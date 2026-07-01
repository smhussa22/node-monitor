#!/usr/bin/env bash
# verify zero node-monitor AWS resources remain.
# run AFTER scripts/down.sh finishes — checks every resource type that could keep a bill running.
# exits 0 if clean, 1 if any check failed.
#
# usage:  scripts/demos/aws_verify_clean.sh

set -uo pipefail

REGION="${AWS_REGION:-us-east-1}"
CLUSTER="${CLUSTER_NAME:-node-monitor}"
FAILED=0
PASS="OK"
FAIL="STILL RUNNING"

if ! command -v aws >/dev/null 2>&1; then
    echo "error: aws cli not on PATH"
    exit 2
fi

check() {
    local label="$1"
    local result="$2"
    if [ -z "$result" ] || [ "$result" = "None" ] || [ "$result" = "[]" ]; then
        printf "  [%s]   %s\n" "$PASS" "$label"
    else
        printf "  [%s]   %s\n" "$FAIL" "$label"
        echo "$result" | sed 's/^/         /'
        FAILED=1
    fi
}

echo "=== verifying node-monitor AWS resources in $REGION ==="
echo ""

# 1. EKS control plane (~$0.10/hr if alive)
result=$(aws eks list-clusters --region "$REGION" \
    --query "clusters[?contains(@, '$CLUSTER')]" --output text 2>/dev/null)
check "EKS cluster '$CLUSTER'" "$result"

# 2. eksctl creates CloudFormation stacks; if those linger, sub-resources linger
result=$(aws cloudformation list-stacks --region "$REGION" \
    --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE CREATE_IN_PROGRESS \
                         DELETE_FAILED ROLLBACK_COMPLETE \
    --query "StackSummaries[?contains(StackName, 'eksctl-$CLUSTER')].StackName" \
    --output text 2>/dev/null)
check "eksctl CloudFormation stacks" "$result"

# 3. EC2 worker nodes (the biggest cost when running)
result=$(aws ec2 describe-instances --region "$REGION" \
    --filters "Name=tag:eks:cluster-name,Values=$CLUSTER" \
              "Name=instance-state-name,Values=running,pending,stopping" \
    --query "Reservations[].Instances[].InstanceId" --output text 2>/dev/null)
check "EC2 worker nodes" "$result"

# 4. EBS volumes — Postgres PVC + any other PVCs (~$0.10/GB-month)
result=$(aws ec2 describe-volumes --region "$REGION" \
    --filters "Name=tag-key,Values=kubernetes.io/created-for/pvc/name" \
    --query "Volumes[?State!=\`deleted\`].VolumeId" --output text 2>/dev/null)
check "EBS volumes from PVCs" "$result"

# 5. Classic ELBs (~$0.025/hr) — Service type=LoadBalancer creates these on EKS
result=$(aws elb describe-load-balancers --region "$REGION" \
    --query "LoadBalancerDescriptions[?VPCId!=null].LoadBalancerName" --output text 2>/dev/null)
check "Classic ELBs in non-default VPCs" "$result"

# 6. Application/Network LBs (also ~$0.025/hr each)
result=$(aws elbv2 describe-load-balancers --region "$REGION" \
    --query "LoadBalancers[].LoadBalancerName" --output text 2>/dev/null)
check "Application/Network LBs" "$result"

# 7. NAT Gateways (~$0.045/hr each) — eksctl VPC includes these by default
result=$(aws ec2 describe-nat-gateways --region "$REGION" \
    --filter "Name=tag:alpha.eksctl.io/cluster-name,Values=$CLUSTER" \
    --query "NatGateways[?State!='deleted'].NatGatewayId" --output text 2>/dev/null)
check "NAT Gateways for the cluster" "$result"

# 8. VPCs — if the eksctl VPC is still there, NAT gateways + IPs probably are too
result=$(aws ec2 describe-vpcs --region "$REGION" \
    --filters "Name=tag:alpha.eksctl.io/cluster-name,Values=$CLUSTER" \
    --query "Vpcs[].VpcId" --output text 2>/dev/null)
check "VPCs tagged with cluster" "$result"

# 9. Elastic IPs — unattached ones bill ~$0.005/hr each
result=$(aws ec2 describe-addresses --region "$REGION" \
    --query "Addresses[?AssociationId==null].PublicIp" --output text 2>/dev/null)
check "Unattached Elastic IPs (any)" "$result"

echo ""
echo "----------------------------------------------------------------"
if [ "$FAILED" = "0" ]; then
    echo "ALL CLEAN — no node-monitor resources are running. No bill."
    echo ""
    echo "ECR repositories are PRESERVED (negligible cost):"
    aws ecr describe-repositories --region "$REGION" \
        --query "repositories[?starts_with(repositoryName, 'node-monitor')].repositoryName" \
        --output text 2>/dev/null | tr '\t' '\n' | sed 's/^/    /'
    echo ""
    echo "To delete the ECR repos too (optional, save ~$0/month):"
    for r in collector simulator dashboard frr; do
        echo "    aws ecr delete-repository --repository-name node-monitor-$r --force --region $REGION"
    done
    exit 0
else
    echo "SOMETHING STILL RUNNING — review the [STILL RUNNING] rows above."
    echo ""
    echo "Most likely fix: re-run the teardown."
    echo "    ./scripts/down.sh"
    echo "Then re-run this verifier."
    echo ""
    echo "If a resource is stuck, delete it manually via the AWS console:"
    echo "    https://console.aws.amazon.com/cloudformation/home?region=$REGION"
    echo "    https://console.aws.amazon.com/ec2/v2/home?region=$REGION"
    echo "    https://console.aws.amazon.com/vpc/home?region=$REGION"
    exit 1
fi
