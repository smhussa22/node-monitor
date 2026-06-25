#!/bin/bash
# CAN BE RAN WITH ./up.sh to provision the EKS cluster and deploy the node-monitor stack
# expects: eksctl, kubectl, docker, and aws credentials configured
# optional env: REGISTRY=<your-ecr-uri> to override the default local image refs

set -euo pipefail

# navigate to repo root (parent of scripts/)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR/.."

REGISTRY="${REGISTRY:-}"
COLLECTOR_IMAGE="${REGISTRY:+${REGISTRY}/}node-monitor-collector:latest"
SIMULATOR_IMAGE="${REGISTRY:+${REGISTRY}/}node-monitor-simulator:latest"
DASHBOARD_IMAGE="${REGISTRY:+${REGISTRY}/}node-monitor-dashboard:latest"

echo ">>> building container images"
docker build -t "$COLLECTOR_IMAGE" -f cc/Dockerfile cc/
docker build -t "$SIMULATOR_IMAGE" -f python/Dockerfile python/
docker build -t "$DASHBOARD_IMAGE" -f dashboard/Dockerfile dashboard/

# push to a remote registry when REGISTRY is set; skipped for local clusters like minikube/kind
if [ -n "$REGISTRY" ]; then
    echo ">>> pushing images to $REGISTRY"
    docker push "$COLLECTOR_IMAGE"
    docker push "$SIMULATOR_IMAGE"
    docker push "$DASHBOARD_IMAGE"
fi

# create the EKS cluster if it does not already exist
if ! eksctl get cluster --name node-monitor --region us-east-1 >/dev/null 2>&1; then
    echo ">>> creating EKS cluster (this takes ~15 minutes)"
    eksctl create cluster -f k8s/cluster.yaml
else
    echo ">>> EKS cluster already exists, skipping create"
fi

# metrics-server is required for HPA cpu-target scaling but is not bundled with EKS
echo ">>> installing metrics-server"
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

echo ">>> applying manifests"
kubectl apply -f k8s/postgres.yaml
kubectl apply -f k8s/collector-rbac.yaml
kubectl apply -f k8s/collector.yaml
kubectl apply -f k8s/dashboard.yaml
kubectl apply -f k8s/simulator-cisco.yaml
kubectl apply -f k8s/simulator-juniper.yaml
kubectl apply -f k8s/simulator-paloalto.yaml

echo ">>> waiting for collector, dashboard, and postgres to become ready"
kubectl rollout status deployment/collector --timeout=5m
kubectl rollout status deployment/dashboard --timeout=5m
kubectl rollout status statefulset/postgres --timeout=5m

echo ">>> done. inspect with: kubectl get pods,svc,hpa"
