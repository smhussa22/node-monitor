#!/usr/bin/env bash
# pull the headline numbers out of the local postgres for the writeup
#
# usage:  scripts/demos/local_harvest_numbers.sh

set -euo pipefail

if ! docker ps --format '{{.Names}}' | grep -q nm-postgres; then
    echo "error: nm-postgres not running. start the stack first: docker compose up -d"
    exit 1
fi

q() {
    docker exec nm-postgres psql -U nodemonitor -d node_monitor -tAc "$1"
}

echo "=== node-monitor numbers (local docker-compose) ==="
echo ""
printf "  metric rows                    : %s\n"   "$(q 'SELECT COUNT(*) FROM metrics')"
printf "  unique simulated devices       : %s\n"   "$(q 'SELECT COUNT(DISTINCT hostname) FROM metrics')"
printf "  vendor breakdown               : %s\n"   "$(q 'SELECT string_agg(vendor::text || \"=\" || c::text, \", \") FROM (SELECT vendor, COUNT(DISTINCT hostname) AS c FROM metrics GROUP BY vendor) v')"
printf "  total incidents fired          : %s\n"   "$(q 'SELECT COUNT(*) FROM incidents')"
printf "  active incidents               : %s\n"   "$(q 'SELECT COUNT(*) FROM incidents WHERE resolved_at IS NULL')"
printf "  auto-resolved incidents        : %s\n"   "$(q 'SELECT COUNT(*) FROM incidents WHERE resolved_at IS NOT NULL')"
printf "  incidents by rule              : %s\n"   "$(q 'SELECT string_agg(rule_name || \"=\" || c::text, \", \") FROM (SELECT rule_name, COUNT(*) AS c FROM incidents GROUP BY rule_name ORDER BY c DESC LIMIT 5) v')"
printf "  netflow records persisted      : %s\n"   "$(q 'SELECT COUNT(*) FROM flows')"
printf "  flow permits / denies          : %s / %s\n" "$(q \"SELECT COUNT(*) FROM flows WHERE acl_action='permit'\")" "$(q \"SELECT COUNT(*) FROM flows WHERE acl_action='deny'\")"
printf "  runbook actions executed       : %s\n"   "$(q 'SELECT COUNT(*) FROM actions')"
printf "  successful pod restarts        : %s\n"   "$(q \"SELECT COUNT(*) FROM actions WHERE action_type='restart_pod' AND status='success'\")"
printf "  dry-run pod restarts (compose) : %s\n"   "$(q \"SELECT COUNT(*) FROM actions WHERE action_type='restart_pod' AND status='dry_run'\")"
printf "  rate-limit suppressions        : %s\n"   "$(q \"SELECT COUNT(*) FROM actions WHERE status='rate_limited'\")"
printf "  cooldown suppressions          : %s\n"   "$(q \"SELECT COUNT(*) FROM actions WHERE status='cooldown_suppressed'\")"
printf "  dhcp lease state changes       : %s\n"   "$(q 'SELECT COUNT(*) FROM dhcp_leases')"
printf "  unique macs that bound a lease : %s\n"   "$(q \"SELECT COUNT(DISTINCT mac) FROM dhcp_leases WHERE state='bound'\")"

echo ""
echo "These are the local-docker-compose numbers. Run scripts/demos/eks_harvest_numbers.sh"
echo "after the EKS deploy to get the headline numbers for the writeup."
