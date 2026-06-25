#!/bin/bash
# CAN BE RAN WITH ./down.sh to tear down the EKS cluster and all node-monitor resources
# expects: eksctl, kubectl, aws credentials configured

set -euo pipefail

# delete the workload first so the LoadBalancer / PVC controllers can release AWS resources cleanly
echo ">>> deleting workload manifests (best effort)"
kubectl delete -f k8s/simulator-cisco.yaml --ignore-not-found
kubectl delete -f k8s/simulator-juniper.yaml --ignore-not-found
kubectl delete -f k8s/simulator-paloalto.yaml --ignore-not-found
kubectl delete -f k8s/dashboard.yaml --ignore-not-found
kubectl delete -f k8s/collector.yaml --ignore-not-found
kubectl delete -f k8s/collector-rbac.yaml --ignore-not-found
kubectl delete -f k8s/postgres.yaml --ignore-not-found

# delete the cluster itself; this also removes the managed node group and detaches EBS volumes
echo ">>> deleting EKS cluster (this takes ~10 minutes)"
eksctl delete cluster --name node-monitor --region us-east-1

echo ">>> done. confirm via: eksctl get cluster --region us-east-1"
