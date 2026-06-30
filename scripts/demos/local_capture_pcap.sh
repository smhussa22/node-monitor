#!/usr/bin/env bash
# capture a pcap of all four protocols (DHCP/DNS/SNMP/NetFlow + traps) over a 60s window. saves to
# capture-fresh.pcap in the repo root. open in Wireshark and the protocol dissectors should light up
# green with zero red warnings.
#
# usage:  scripts/demos/local_capture_pcap.sh [seconds=60]

set -euo pipefail

DURATION="${1:-60}"

if ! docker ps --format '{{.Names}}' | grep -q nm-collector; then
    echo "error: nm-collector not running. start the stack first: docker compose up -d"
    exit 1
fi

echo "=== capturing all-protocols pcap for ${DURATION}s ==="
echo ""
echo "Attaching tcpdump to nm-collector's network namespace so we see all UDP traffic going to /"
echo "from the collector (DHCP, DNS, SNMP queries + traps, NetFlow)."
echo ""

docker rm -f nm-cap 2>/dev/null || true
docker run -d --network container:nm-collector --name nm-cap alpine:latest \
    sh -c "apk add --quiet tcpdump && tcpdump -i any -w /tmp/cap.pcap -U 'port 53 or port 67 or port 68 or port 161 or port 162 or port 2055'" >/dev/null

sleep 5
echo "Generating activity (dig + snmpwalk + scanner injection)..."
docker run --rm --network node-monitor_default alpine:latest sh -c "
apk add --quiet net-snmp-tools bind-tools 2>/dev/null
dig +short @collector A collector.node-monitor.local >/dev/null
dig +short @collector AAAA collector.node-monitor.local >/dev/null
dig +short @collector -x 10.42.0.1 >/dev/null
snmpget -v2c -c public -t 2 simulator-cisco 1.3.6.1.2.1.1.5.0 >/dev/null 2>&1
snmpwalk -v2c -c public -t 2 simulator-cisco 1.3.6.1.2.1.1 >/dev/null 2>&1
snmpbulkwalk -v2c -c public -t 2 simulator-cisco 1.3.6.1.2.1.2.2 >/dev/null 2>&1
" >/dev/null 2>&1

REMAINING=$((DURATION - 5))
echo "Holding capture open for ${REMAINING}s while simulators emit their normal traffic..."
sleep "$REMAINING"

docker exec nm-cap pkill tcpdump 2>/dev/null || true
sleep 1
docker cp nm-cap:/tmp/cap.pcap capture-fresh.pcap
docker rm -f nm-cap >/dev/null

echo ""
echo "=== capture summary ==="
docker run --rm -v "$(pwd)/capture-fresh.pcap:/cap.pcap" alpine:latest sh -c "
apk add --quiet tcpdump >/dev/null 2>&1
for proto_label in 'DNS:port 53' 'DHCP:port 67 or port 68' 'SNMP:port 161' 'SNMP-traps:port 162' 'NetFlow-v5:port 2055'; do
    label=\${proto_label%%:*}
    filter=\${proto_label#*:}
    n=\$(tcpdump -nr /cap.pcap \$filter 2>/dev/null | wc -l)
    printf '  %-15s : %s packets\n' \"\$label\" \"\$n\"
done
" 2>&1

echo ""
echo "Saved: $(pwd)/capture-fresh.pcap"
echo ""
echo "Open in Wireshark:"
echo "  File → Open → C:/Users/faraz/node-monitor/capture-fresh.pcap"
echo "  Filter bar:  bootp  /  dns  /  snmp  /  cflow"
echo "  Click any packet → expand the protocol tree in the lower pane"
echo "  Screenshot anywhere you see decoded fields. Zero red rows = wire format is correct."
