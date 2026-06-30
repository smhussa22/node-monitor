#!/usr/bin/env bash
# EKS version of the BGP failure demo. kills an FRR pod, watches bgp_peer_down fire on the surviving
# pod, watches the runbook attempt a real K8s restart (NOT dry_run because EKS has real creds), watches
# the killed pod auto-recreate, watches the incident auto-resolve.
#
# usage:  LB=<hostname> scripts/demos/eks_bgp_failure.sh

set -euo pipefail

LB="${LB:-${1:-}}"
if [ -z "$LB" ]; then
    echo "usage: LB=<lb-hostname> scripts/demos/eks_bgp_failure.sh"
    exit 1
fi

if ! command -v kubectl >/dev/null; then
    echo "error: kubectl not on PATH."
    exit 1
fi

echo "=== EKS BGP failure → real K8s remediation → auto-resolution ==="
echo ""

echo "Step 1/4 — confirm BGP is currently up"
FRR1_POD=$(kubectl get pods -l app=frr-router,instance=frr1 -o jsonpath='{.items[0].metadata.name}')
FRR2_POD=$(kubectl get pods -l app=frr-router,instance=frr2 -o jsonpath='{.items[0].metadata.name}')
echo "  frr1 pod: $FRR1_POD"
echo "  frr2 pod: $FRR2_POD"
kubectl exec "$FRR1_POD" -- vtysh -c "show bgp summary" 2>&1 | tail -5 | sed 's/^/  /'

echo ""
echo "Step 2/4 — killing frr2 pod"
kubectl delete pod "$FRR2_POD" --grace-period=5 2>&1 | head -1

echo ""
echo "Waiting 60s for the bgp_peer_down rule (30s sustained) to fire and the runbook to execute..."
sleep 60

echo ""
echo "Step 3/4 — incidents + runbook actions"
echo ""
echo "  --- bgp_peer_down incidents ---"
kubectl exec postgres-0 -- psql -U nodemonitor -d node_monitor \
    -c "SELECT rule_name, hostname, severity, details->>'description' AS detail, (resolved_at IS NOT NULL) AS resolved FROM incidents WHERE rule_name='bgp_peer_down' ORDER BY fired_at DESC LIMIT 3;" 2>&1 | sed 's/^/  /'

echo ""
echo "  --- rb_bgp_peer_down runbook actions ---"
kubectl exec postgres-0 -- psql -U nodemonitor -d node_monitor \
    -c "SELECT runbook_name, action_type, status, response_code FROM actions WHERE rule_name='bgp_peer_down' ORDER BY started_at DESC LIMIT 4;" 2>&1 | sed 's/^/  /'

echo ""
echo "Expected on EKS: restart_pod has status=success and response_code=200"
echo "(In docker-compose this would be dry_run; on EKS the collector has real ServiceAccount creds)"
echo ""

echo "Step 4/4 — verify frr2 pod recreated + incident resolved (wait 90s)"
sleep 90
kubectl get pods -l app=frr-router 2>&1 | sed 's/^/  /'
echo ""
kubectl exec postgres-0 -- psql -U nodemonitor -d node_monitor \
    -c "SELECT rule_name, hostname, fired_at, resolved_at FROM incidents WHERE rule_name='bgp_peer_down' ORDER BY fired_at DESC LIMIT 3;" 2>&1 | sed 's/^/  /'
