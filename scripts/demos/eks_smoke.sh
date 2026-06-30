#!/usr/bin/env bash
# smoke test every collector JSON endpoint against the EKS LoadBalancer. one row per protocol,
# pass / fail. run AFTER ./scripts/up.sh prints the LB hostname.
#
# usage:  LB=<hostname-from-up.sh> scripts/demos/eks_smoke.sh
#         OR  scripts/demos/eks_smoke.sh <hostname>

set -euo pipefail

LB="${LB:-${1:-}}"
if [ -z "$LB" ]; then
    echo "usage: LB=<lb-hostname> scripts/demos/eks_smoke.sh"
    echo "       (or pass the LB hostname as the first argument)"
    exit 1
fi

PASS="✓"
FAIL="✗"

check() {
    local name="$1"; local url="$2"; local expected="$3"
    local got
    got=$(curl -s --max-time 10 "$url" || true)
    if echo "$got" | grep -qE "$expected"; then
        printf "  %s %-30s %s\n" "$PASS" "$name" "passed"
    else
        printf "  %s %-30s %s\n" "$FAIL" "$name" "FAILED  (url=$url, expected match: $expected)"
    fi
}

echo "=== EKS smoke test against http://$LB ==="
echo ""
check "healthz"          "http://$LB/healthz"                                '"ok":true'
check "readyz (db ping)" "http://$LB/readyz"                                 '"ready":true'
check "acl rules"        "http://$LB/acl/rules"                              '"totals"'
check "dhcp leases"      "http://$LB/dhcp/leases"                            '"pool_in_use"'
check "dns zone"         "http://$LB/dns/zone"                               '"node-monitor.local"'
check "snmp agents"      "http://$LB/snmp/agents"                            '"discovery_mode"'
check "snmp traps"       "http://$LB/snmp/traps"                             '"received"'
check "splunk search"    "http://$LB/search?q=severity=critical"             'kpi-card|hist-chart'
check "network funnel"   "http://$LB/network"                                'DHCP bound'
check "blocked traffic"  "http://$LB/blocked-traffic"                        'top denied'

echo ""
echo "=== SNMP discovery mode ==="
echo "    expected: k8s+static  (real K8s API discovery active)"
echo -n "    actual:   "
curl -s --max-time 10 "http://$LB/snmp/agents" | python -c "import sys,json; print(json.loads(sys.stdin.read()).get('discovery_mode','?'))" 2>/dev/null || echo "ERROR"

echo ""
echo "=== scale check ==="
echo -n "    DHCP leases bound:  "
curl -s --max-time 10 "http://$LB/dhcp/leases" | python -c "import sys,json; print(json.loads(sys.stdin.read())['totals']['pool_in_use'])" 2>/dev/null || echo "ERROR"
echo -n "    DNS zone entries:   "
curl -s --max-time 10 "http://$LB/dns/zone" | python -c "import sys,json; print(len(json.loads(sys.stdin.read())['entries']))" 2>/dev/null || echo "ERROR"
echo -n "    SNMP agents:        "
curl -s --max-time 10 "http://$LB/snmp/agents" | python -c "import sys,json; print(len(json.loads(sys.stdin.read())['agents']))" 2>/dev/null || echo "ERROR"
