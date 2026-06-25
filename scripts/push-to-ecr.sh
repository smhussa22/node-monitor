#!/bin/bash
# CAN BE RAN WITH ./push-to-ecr.sh to build all three images and push them to ECR.
# expects: aws cli configured, docker, jq (optional). on success prints the REGISTRY env you should pass to up.sh.

set -euo pipefail

# navigate to repo root (parent of scripts/)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR/.."

REGION="${AWS_REGION:-us-east-1}"
REPOS=(node-monitor-collector node-monitor-simulator node-monitor-dashboard)

# verify aws cli is reachable and credentials exist
if ! command -v aws >/dev/null 2>&1; then
    echo "error: aws cli not found. install per https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
    exit 1
fi

ACCOUNT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)"
if [ -z "$ACCOUNT" ]; then
    echo "error: cannot resolve aws account. run 'aws configure' first."
    exit 1
fi

REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
echo ">>> account=${ACCOUNT}  region=${REGION}  registry=${REGISTRY}"

# create each ECR repo if it doesn't already exist; describe-repositories is the idempotent probe
for repo in "${REPOS[@]}"; do
    if ! aws ecr describe-repositories --region "$REGION" --repository-names "$repo" >/dev/null 2>&1; then
        echo ">>> creating ECR repo $repo"
        aws ecr create-repository --region "$REGION" --repository-name "$repo" \
            --image-scanning-configuration scanOnPush=true \
            --image-tag-mutability MUTABLE >/dev/null
    else
        echo ">>> repo $repo already exists"
    fi
done

# authenticate docker against ECR; token lasts 12 hours
echo ">>> logging in to ECR"
aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$REGISTRY"

# build, tag, and push each image. assumes the local *:latest tags already exist or get built first
echo ">>> building images"
docker build -t node-monitor-collector:latest -f cc/Dockerfile cc/
docker build -t node-monitor-simulator:latest -f python/Dockerfile python/
docker build -t node-monitor-dashboard:latest -f dashboard/Dockerfile dashboard/

for repo in "${REPOS[@]}"; do
    echo ">>> pushing $repo"
    docker tag "${repo}:latest" "${REGISTRY}/${repo}:latest"
    docker push "${REGISTRY}/${repo}:latest"
done

echo
echo ">>> done. to deploy, run:"
echo "    REGISTRY=${REGISTRY} ./scripts/up.sh"
