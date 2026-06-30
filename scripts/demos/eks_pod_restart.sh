#!/usr/bin/env bash
# the headline EKS demo: kill a simulator pod, watch the runbook execute a REAL pod restart against
# the live K8s API (status=success, response_code=200, NOT dry_run). this is what flips when the
# collector has real in-cluster credentials.
#
# usage:  LB=<hostname> scripts/demos/eks_pod_restart.sh

set -euo pipefail

LB="${LB:-${1:-}}"
if [ -z "$LB" ]; then
    echo "usage: LB=<lb-hostname> scripts/demos/eks_pod_restart.sh"
    exit 1
fi

if ! command -v kubectl >/dev/null; then
    echo "error: kubectl not on PATH. run this from WSL or a Linux shell with kubectl configured."
    exit 1
fi

echo "=== EKS pod restart demo: real K8s API actions (not dry_run) ==="
echo ""

# pick a victim pod
VICTIM=$(kubectl get pods -l app=simulator -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ -z "$VICTIM" ]; then
    echo "error: no simulator pods found. run ./scripts/up.sh first."
    exit 1
fi

echo "Step 1/3 — capturing baseline runbook activity"
BEFORE=$(curl -s --max-time 10 "http://$LB/search?q=action_type=restart_pod+status=success" | grep -c "restart_pod" || true)
echo "  baseline restart_pod success rows visible on /search: $BEFORE"

echo ""
echo "Step 2/3 — deleting pod $VICTIM (triggers device_offline / health_down rules)"
kubectl delete pod "$VICTIM" --grace-period=0 --force 2>&1 | head -1

echo ""
echo "Waiting 90s for: pod re-creation + simulators going offline + alert fire + runbook execution"
sleep 90

echo ""
echo "Step 3/3 — checking for new successful restart_pod actions on the dashboard"
AFTER=$(curl -s --max-time 10 "http://$LB/search?q=action_type=restart_pod+status=success" | grep -c "restart_pod" || true)
echo "  restart_pod success rows visible NOW: $AFTER"
echo "  delta: $((AFTER - BEFORE))"

echo ""
echo "If the delta is > 0, the runbook engine fired a real K8s API DELETE pod call,"
echo "the apiserver returned 200, and the action was logged with status=success — NOT dry_run."
echo ""
echo "Per-action detail (most recent restart_pod attempts):"
kubectl exec postgres-0 -- psql -U nodemonitor -d node_monitor \
    -c "SELECT runbook_name, hostname, action_type, status, response_code FROM actions WHERE action_type='restart_pod' ORDER BY started_at DESC LIMIT 5;" 2>&1 | sed 's/^/  /'
