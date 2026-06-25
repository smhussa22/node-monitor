#!/bin/bash
# CAN BE RAN WITH ./up.sh to provision the EKS cluster and deploy the node-monitor stack
# expects: eksctl, kubectl, docker, aws cli, and aws credentials configured
# optional env:
#   REGISTRY=<your-ecr-uri>   override the auto-detected image registry
#   SKIP_PUSH=true             skip the docker push step (useful when images are already in ECR)

set -euo pipefail

# navigate to repo root (parent of scripts/)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR/.."

REGION="${AWS_REGION:-us-east-1}"
CLUSTER_NAME="node-monitor"

# auto-detect ECR registry when REGISTRY isn't explicitly passed in
REGISTRY="${REGISTRY:-}"
if [ -z "$REGISTRY" ] && command -v aws >/dev/null 2>&1; then
    ACCOUNT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)"
    if [ -n "$ACCOUNT" ]; then
        REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
        echo ">>> using auto-detected ECR registry $REGISTRY"
    fi
fi

COLLECTOR_IMAGE="${REGISTRY:+${REGISTRY}/}node-monitor-collector:latest"
SIMULATOR_IMAGE="${REGISTRY:+${REGISTRY}/}node-monitor-simulator:latest"
DASHBOARD_IMAGE="${REGISTRY:+${REGISTRY}/}node-monitor-dashboard:latest"

if [ "${SKIP_PUSH:-false}" != "true" ]; then
    echo ">>> building container images"
    docker build -t "$COLLECTOR_IMAGE" -f cc/Dockerfile cc/
    docker build -t "$SIMULATOR_IMAGE" -f python/Dockerfile python/
    docker build -t "$DASHBOARD_IMAGE" -f dashboard/Dockerfile dashboard/

    if [ -n "$REGISTRY" ]; then
        echo ">>> pushing images to $REGISTRY"
        aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$REGISTRY"
        docker push "$COLLECTOR_IMAGE"
        docker push "$SIMULATOR_IMAGE"
        docker push "$DASHBOARD_IMAGE"
    fi
fi

# create the EKS cluster if it does not already exist
if ! eksctl get cluster --name "$CLUSTER_NAME" --region "$REGION" >/dev/null 2>&1; then
    echo ">>> creating EKS cluster (this takes ~15 minutes)"
    eksctl create cluster -f k8s/cluster.yaml
else
    echo ">>> EKS cluster already exists, skipping create"
fi

# metrics-server is required for HPA cpu-target scaling but is not bundled with EKS
echo ">>> installing metrics-server"
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

# cluster-autoscaler scales nodes when pods are Pending; eksctl already attached the IAM policy to node role
echo ">>> installing cluster-autoscaler"
kubectl apply -f k8s/cluster-autoscaler.yaml

# rewrite image references in our manifests on the fly so they pick up the ECR URI when present
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT
for f in k8s/collector.yaml k8s/dashboard.yaml k8s/simulator-cisco.yaml k8s/simulator-juniper.yaml k8s/simulator-paloalto.yaml; do
    out="$TMP/$(basename "$f")"
    if [ -n "$REGISTRY" ]; then
        sed -e "s|image: node-monitor-collector:latest|image: ${REGISTRY}/node-monitor-collector:latest|g" \
            -e "s|image: node-monitor-simulator:latest|image: ${REGISTRY}/node-monitor-simulator:latest|g" \
            -e "s|image: node-monitor-dashboard:latest|image: ${REGISTRY}/node-monitor-dashboard:latest|g" \
            "$f" > "$out"
    else
        cp "$f" "$out"
    fi
done

echo ">>> applying manifests"
kubectl apply -f k8s/postgres.yaml
kubectl apply -f k8s/collector-rbac.yaml
kubectl apply -f "$TMP/collector.yaml"
kubectl apply -f "$TMP/dashboard.yaml"
kubectl apply -f "$TMP/simulator-cisco.yaml"
kubectl apply -f "$TMP/simulator-juniper.yaml"
kubectl apply -f "$TMP/simulator-paloalto.yaml"

echo ">>> waiting for collector, dashboard, and postgres to become ready"
kubectl rollout status deployment/collector --timeout=5m
kubectl rollout status deployment/dashboard --timeout=5m
kubectl rollout status statefulset/postgres --timeout=5m

# wait briefly for the load balancer hostname; this is async on EKS so it may take 1-2 minutes
echo ">>> waiting up to 3 minutes for the dashboard load balancer URL"
for i in $(seq 1 36); do
    LB_URL="$(kubectl get svc dashboard -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || true)"
    if [ -n "$LB_URL" ]; then
        echo ">>> dashboard URL: http://${LB_URL}"
        break
    fi
    sleep 5
done

echo ">>> done. inspect with: kubectl get pods,svc,hpa,nodes"
