#!/usr/bin/env bash
# kill nm-frr2 → bgp_peer_down fires on frr1 → runbook executes 3 actions → restore nm-frr2 → incident
# auto-resolves. demonstrates the full failure-detection + remediation + recovery loop.
#
# usage:  scripts/demos/local_bgp_failure.sh

set -euo pipefail

if ! docker ps --format '{{.Names}}' | grep -q nm-frr2; then
    echo "error: nm-frr2 not running. start the stack first: docker compose up -d"
    exit 1
fi

echo "=== BGP failure → detection → remediation → resolution demo ==="
echo ""
echo "Step 1/4 — confirm BGP is currently up between AS 65001 and AS 65002"
docker exec nm-frr1 vtysh -c "show bgp summary" 2>&1 | grep -E "Established|172.20" | head -3 | sed 's/^/  /'

echo ""
echo "Step 2/4 — killing nm-frr2 (real BGP peer drops)"
docker stop nm-frr2 >/dev/null
echo "  → nm-frr2 stopped"

echo ""
echo "Waiting 45s for AlertEngine to evaluate (rule needs 30s sustained window + ~10s tick lag)..."
sleep 45

echo ""
echo "Step 3/4 — incidents fired by bgp_peer_down"
docker exec nm-postgres psql -U nodemonitor -d node_monitor \
    -c "SELECT rule_name, hostname, severity, details->>'description' AS detail FROM incidents WHERE rule_name='bgp_peer_down' ORDER BY fired_at DESC LIMIT 3;" 2>&1 | sed 's/^/  /'

echo ""
echo "Runbook actions taken (rb_bgp_peer_down):"
docker exec nm-postgres psql -U nodemonitor -d node_monitor \
    -c "SELECT runbook_name, action_type, status, response_code FROM actions WHERE rule_name='bgp_peer_down' ORDER BY started_at DESC LIMIT 4;" 2>&1 | sed 's/^/  /'

echo ""
echo "Expected: log_only=success, webhook_notify=success, restart_pod=dry_run"
echo "(restart_pod is dry_run on docker-compose because there are no in-cluster credentials)"
echo ""

echo "Step 4/4 — restoring nm-frr2 to verify auto-resolution"
docker start nm-frr2 >/dev/null
echo "  → nm-frr2 restarted; waiting 90s for BGP to re-establish + AlertEngine to clear the incident..."
sleep 90

docker exec nm-postgres psql -U nodemonitor -d node_monitor \
    -c "SELECT rule_name, hostname, fired_at, resolved_at, (resolved_at IS NOT NULL) AS resolved FROM incidents WHERE rule_name='bgp_peer_down' ORDER BY fired_at DESC LIMIT 3;" 2>&1 | sed 's/^/  /'

echo ""
echo "Expected: most recent row has resolved=t (true)"
