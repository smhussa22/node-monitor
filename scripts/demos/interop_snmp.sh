#!/usr/bin/env bash
# real-tool interop: net-snmp (snmpget / snmpwalk / snmpbulkwalk) → our hand-rolled SnmpAgent.
# proves all three v2c query types work and every type tag we emit (Counter32, Gauge32, TimeTicks,
# INTEGER, OCTET STRING, OID) is decoded correctly by an independent reference implementation.
#
# usage:  scripts/demos/interop_snmp.sh

set -euo pipefail

if ! docker ps --format '{{.Names}}' | grep -q simulator-cisco; then
    echo "error: simulator-cisco not running. start the stack first: docker compose up -d"
    exit 1
fi

echo "=== SNMP interop: net-snmp 5.x → our SnmpAgent ==="
echo ""

docker run --rm --network node-monitor_default alpine:latest sh -c "
apk add --quiet net-snmp-tools >/dev/null 2>&1

echo '--- snmpget: single OID query for sysName.0 across all 3 vendor pods ---'
for t in simulator-cisco simulator-juniper simulator-paloalto; do
    printf '%-22s ' \"\$t:\"
    snmpget -v2c -c public -t 3 \$t 1.3.6.1.2.1.1.5.0 2>&1 | tail -1
done

echo ''
echo '--- snmpget: enterprise OID (Gauge32 type tag) ---'
echo '\$ snmpget -v2c -c public simulator-cisco 1.3.6.1.4.1.99999.2.0'
snmpget -v2c -c public -t 3 simulator-cisco 1.3.6.1.4.1.99999.2.0 2>&1 | head -3

echo ''
echo '--- snmpwalk: full system subtree (uses GETNEXT internally) ---'
echo '\$ snmpwalk -v2c -c public simulator-cisco 1.3.6.1.2.1.1'
snmpwalk -v2c -c public -t 3 simulator-cisco 1.3.6.1.2.1.1 2>&1 | head -6

echo ''
echo '--- snmpbulkwalk: ifTable (uses GETBULK with max-repetitions) ---'
echo '\$ snmpbulkwalk -v2c -c public simulator-cisco 1.3.6.1.2.1.2.2'
snmpbulkwalk -v2c -c public -t 3 simulator-cisco 1.3.6.1.2.1.2.2 2>&1 | head -10
echo '(...)'
n=\$(snmpbulkwalk -v2c -c public -t 3 simulator-cisco 1.3.6.1.2.1.2.2 2>&1 | wc -l)
echo \"total OIDs returned: \$n\"
"
