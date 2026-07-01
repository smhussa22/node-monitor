#!/usr/bin/env bash
# capture a pcap of one or all protocols. saves to pcaps/<type>_<YYYY-MM-DD>_<HHMM>.pcap so the
# filename always carries enough metadata to understand what's in it without opening Wireshark.
#
# usage:  scripts/demos/local_capture_pcap.sh [type] [duration_seconds]
#
#   type        one of: all, dhcp, dns, snmp, snmp-bulk, snmp-traps, netflow
#               (default: all)
#   duration    seconds to capture (default: 60)
#
# examples:
#   scripts/demos/local_capture_pcap.sh                       # 60s, all protocols
#   scripts/demos/local_capture_pcap.sh snmp 30               # 30s, only SNMP query traffic
#   scripts/demos/local_capture_pcap.sh snmp-bulk 30          # 30s, includes a triggered GetBulkRequest
#   scripts/demos/local_capture_pcap.sh netflow 90            # 90s, only NetFlow v5

set -euo pipefail

TYPE="${1:-all}"
DURATION="${2:-60}"

# protocol-to-tcpdump-filter map. snmp-bulk and snmp share a filter; the difference is that snmp-bulk
# also triggers an explicit GetBulkRequest from a sidecar so the capture is guaranteed to contain one
case "$TYPE" in
    all)         FILTER="port 53 or port 67 or port 68 or port 161 or port 162 or port 2055"; LABEL="all 5 protocols (DHCP+DNS+SNMP+SNMP-traps+NetFlow)" ;;
    dhcp)        FILTER="port 67 or port 68";    LABEL="DHCP DORA" ;;
    dns)         FILTER="port 53";               LABEL="DNS queries + responses" ;;
    snmp)        FILTER="port 161";              LABEL="SNMP GET/GETNEXT/GetResponse" ;;
    snmp-bulk)   FILTER="port 161";              LABEL="SNMP GetBulkRequest + GetResponse" ;;
    snmp-traps)  FILTER="port 162";              LABEL="SNMP v2 traps (linkUp/linkDown)" ;;
    netflow)     FILTER="port 2055";             LABEL="binary NetFlow v5" ;;
    *)           echo "error: unknown type '$TYPE'. valid: all dhcp dns snmp snmp-bulk snmp-traps netflow"; exit 1 ;;
esac

if ! docker ps --format '{{.Names}}' | grep -q nm-collector; then
    echo "error: nm-collector not running. start the stack first: docker compose up -d"
    exit 1
fi

# resolve the project root so the pcaps/ path is reliable regardless of cwd
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"
PCAP_DIR="$REPO_ROOT/pcaps"
mkdir -p "$PCAP_DIR"

# filename: <type>_<YYYY-MM-DD>_<HHMM>.pcap — date AND time in the name so multiple runs in a day
# don't collide. wireshark also reads per-packet timestamps so you can cross-check
TS="$(date '+%Y-%m-%d_%H%M')"
OUT="$PCAP_DIR/${TYPE}_${TS}.pcap"

echo "=== capturing $LABEL for ${DURATION}s ==="
echo "  filter:  $FILTER"
echo "  output:  pcaps/${TYPE}_${TS}.pcap"
echo ""

# tcpdump runs INSIDE nm-collector's network namespace so it sees all of the collector's traffic.
# capturing from a sidecar attached to a different namespace only catches that sidecar's own packets
docker rm -f nm-cap 2>/dev/null || true
docker run -d --network container:nm-collector --name nm-cap alpine:latest \
    sh -c "apk add --quiet tcpdump && tcpdump -i any -w /tmp/cap.pcap -U '$FILTER'" >/dev/null

sleep 4

# trigger representative traffic so the capture is non-empty even if the simulators are quiet at that
# moment. each protocol gets a tailored kick — snmp-bulk explicitly triggers a GetBulkRequest, etc.
echo "Generating activity to ensure the capture is non-empty..."

# DNS / SNMP triggers run in an alpine sidecar with bind-tools + net-snmp-tools
docker run --rm --network node-monitor_default alpine:latest sh -c "
apk add --quiet net-snmp-tools bind-tools 2>/dev/null
case '$TYPE' in
    all|dns)         dig +short @collector A collector.node-monitor.local >/dev/null; dig +short @collector AAAA collector.node-monitor.local >/dev/null; dig +short @collector -x 10.42.0.1 >/dev/null ;;
esac
case '$TYPE' in
    all|snmp)        snmpget -v2c -c public -t 2 simulator-cisco 1.3.6.1.2.1.1.5.0 >/dev/null 2>&1; snmpwalk -v2c -c public -t 2 simulator-cisco 1.3.6.1.2.1.1 >/dev/null 2>&1 ;;
esac
case '$TYPE' in
    all|snmp-bulk)   snmpbulkwalk -v2c -c public -t 2 simulator-cisco 1.3.6.1.2.1.2.2 >/dev/null 2>&1 ;;
esac
" >/dev/null 2>&1

# DHCP DISCOVER trigger uses scapy — interop_dhcp.sh already proved this DISCOVER
# format elicits an OFFER from our DhcpServer, so we reuse the same recipe to get a
# full DORA exchange visible in the pcap (vs a hand-rolled DISCOVER which the collector
# silently ignores).
if [ "$TYPE" = "all" ] || [ "$TYPE" = "dhcp" ]; then
    docker run --rm --network node-monitor_default python:3.12-slim sh -c "
pip install --quiet --break-system-packages scapy >/dev/null 2>&1
python3 -c '
from scapy.all import BOOTP, DHCP
import socket, random
ip = socket.gethostbyname(\"collector\")
xid = random.getrandbits(32)
mac_bytes = bytes([0x02, 0xde, 0xad, 0xbe, 0xef, random.randint(1, 255)])
discover = (
    BOOTP(op=1, htype=1, hlen=6, xid=xid, chaddr=mac_bytes + b\"\\x00\"*10) /
    DHCP(options=[
        (\"message-type\", \"discover\"),
        (\"hostname\", \"capture-trigger\"),
        (\"param_req_list\", 1, 3, 6, 51, 54),
        \"end\",
    ])
)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((\"0.0.0.0\", 0))
s.settimeout(3)
s.sendto(bytes(discover), (ip, 67))
try:
    s.recvfrom(4096)
except Exception:
    pass
'
" >/dev/null 2>&1 || true
fi

REMAINING=$((DURATION - 4))
[ $REMAINING -gt 0 ] && sleep "$REMAINING"

docker exec nm-cap pkill tcpdump 2>/dev/null || true
sleep 1

# on Windows + Git Bash, the host path is "/c/Users/..." which docker doesn't accept. cygpath
# converts to "C:\Users\..." which docker on Windows DOES accept. on Linux/WSL cygpath isn't
# present and the path is already canonical, so we fall through to the bare path
if command -v cygpath >/dev/null 2>&1; then
    OUT_DOCKER="$(cygpath -w "$OUT")"
else
    OUT_DOCKER="$OUT"
fi

MSYS_NO_PATHCONV=1 docker cp nm-cap:/tmp/cap.pcap "$OUT_DOCKER"
docker rm -f nm-cap >/dev/null

# print packet counts per protocol so you see at a glance what's inside without opening Wireshark
echo ""
echo "=== capture contents ==="
MSYS_NO_PATHCONV=1 docker run --rm -v "${OUT_DOCKER}:/cap.pcap" alpine:latest sh -c "
apk add --quiet tcpdump >/dev/null 2>&1
for proto_label in 'DNS:port 53' 'DHCP:port 67 or port 68' 'SNMP:port 161' 'SNMP-traps:port 162' 'NetFlow-v5:port 2055'; do
    label=\${proto_label%%:*}
    filter=\${proto_label#*:}
    n=\$(tcpdump -nr /cap.pcap \$filter 2>/dev/null | wc -l)
    printf '  %-15s : %s packets\n' \"\$label\" \"\$n\"
done
size=\$(stat -c %s /cap.pcap)
printf '  %-15s : %s bytes\n' 'file size' \"\$size\"
" 2>&1

echo ""
echo "Saved: pcaps/${TYPE}_${TS}.pcap"
echo ""
echo "Open in Wireshark:"
echo "  File -> Open -> C:\\Users\\faraz\\node-monitor\\pcaps\\${TYPE}_${TS}.pcap"
echo "  Filter bar:  bootp  /  dns  /  snmp  /  cflow"
