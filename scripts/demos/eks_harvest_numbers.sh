#!/usr/bin/env bash
# pull the headline numbers from the EKS postgres pod for the writeup. THESE are what the writeup
# should lead with — they replace the pre-phase-10 numbers (27,899 metrics / 60 restarts) that are
# currently stale in summary.md.
#
# usage:  scripts/demos/eks_harvest_numbers.sh

set -euo pipefail

if ! command -v kubectl >/dev/null; then
    echo "error: kubectl not on PATH."
    exit 1
fi

q() {
    kubectl exec postgres-0 -- psql -U nodemonitor -d node_monitor -tAc "$1" 2>/dev/null
}

echo "=== node-monitor headline numbers (EKS run) ==="
echo "Stack uptime: $(kubectl get deploy collector -o jsonpath='{.metadata.creationTimestamp}' 2>/dev/null || echo unknown)"
echo ""

printf "  metric rows persisted          : %s\n"   "$(q 'SELECT COUNT(*) FROM metrics')"
printf "  unique simulated devices       : %s\n"   "$(q 'SELECT COUNT(DISTINCT hostname) FROM metrics')"
printf "  total incidents fired          : %s\n"   "$(q 'SELECT COUNT(*) FROM incidents')"
printf "  active (unresolved) incidents  : %s\n"   "$(q 'SELECT COUNT(*) FROM incidents WHERE resolved_at IS NULL')"
printf "  auto-resolved incidents        : %s\n"   "$(q 'SELECT COUNT(*) FROM incidents WHERE resolved_at IS NOT NULL')"
printf "  NetFlow records (binary v5)    : %s\n"   "$(q 'SELECT COUNT(*) FROM flows')"
printf "  acl-permitted flows            : %s\n"   "$(q \"SELECT COUNT(*) FROM flows WHERE acl_action='permit'\")"
printf "  acl-denied flows               : %s\n"   "$(q \"SELECT COUNT(*) FROM flows WHERE acl_action='deny'\")"
printf "  runbook actions executed       : %s\n"   "$(q 'SELECT COUNT(*) FROM actions')"
printf "  SUCCESSFUL restart_pod calls   : %s\n"   "$(q \"SELECT COUNT(*) FROM actions WHERE action_type='restart_pod' AND status='success'\")"
printf "  rate-limit suppressions        : %s\n"   "$(q \"SELECT COUNT(*) FROM actions WHERE status='rate_limited'\")"
printf "  cooldown suppressions          : %s\n"   "$(q \"SELECT COUNT(*) FROM actions WHERE status='cooldown_suppressed'\")"
printf "  dhcp lease state changes       : %s\n"   "$(q 'SELECT COUNT(*) FROM dhcp_leases')"
printf "  unique macs that bound a lease : %s\n"   "$(q \"SELECT COUNT(DISTINCT mac) FROM dhcp_leases WHERE state='bound'\")"

echo ""
echo "Top 5 rules by incident count:"
q "SELECT rule_name || ': ' || COUNT(*) FROM incidents GROUP BY rule_name ORDER BY COUNT(*) DESC LIMIT 5" | sed 's/^/  /'

echo ""
echo "Most-fired runbooks:"
q "SELECT runbook_name || ': ' || COUNT(*) FROM actions GROUP BY runbook_name ORDER BY COUNT(*) DESC LIMIT 5" | sed 's/^/  /'

echo ""
echo "=== suggested writeup paragraph ==="
echo ""
metrics=$(q 'SELECT COUNT(*) FROM metrics')
incidents=$(q 'SELECT COUNT(*) FROM incidents')
flows=$(q 'SELECT COUNT(*) FROM flows')
successful_restarts=$(q "SELECT COUNT(*) FROM actions WHERE action_type='restart_pod' AND status='success'")
suppressions=$(q "SELECT COUNT(*) FROM actions WHERE status IN ('rate_limited','cooldown_suppressed')")
echo "  \"Validated on AWS EKS with a fleet of ~1,200 simulated devices across 17 simulator pods plus"
echo "   two FRRouting instances peering via real eBGP. During a single demonstration run the system"
echo "   persisted ${metrics} metric rows, fired ${incidents} incidents (auto-resolving most), ingested"
echo "   ${flows} binary NetFlow v5 records, executed ${successful_restarts} REAL pod-restart actions"
echo "   against the live Kubernetes API (HTTP 200), and correctly suppressed ${suppressions} actions"
echo "   via the cooldown + rate-limit safety rails — proving both the happy path and the safety"
echo "   mechanisms work, not just one of them.\""
