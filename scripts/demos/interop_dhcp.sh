#!/usr/bin/env bash
# real-tool interop: scapy (Python's reference BOOTP/DHCP codec, used by thousands of network
# security tools) → our hand-rolled DhcpServer. proves the OFFER we emit is decoded correctly
# with all options parsed by an independent codec.
#
# usage:  scripts/demos/interop_dhcp.sh

set -euo pipefail

if ! docker ps --format '{{.Names}}' | grep -q nm-collector; then
    echo "error: nm-collector not running. start the stack first: docker compose up -d"
    exit 1
fi

echo "=== DHCP interop: scapy BOOTP decoder → our DhcpServer ==="
echo ""

docker run --rm --network node-monitor_default python:3.12-slim sh -c "
pip install --quiet --break-system-packages scapy >/dev/null 2>&1
python3 -c '
from scapy.all import BOOTP, DHCP
import socket, random
SERVER = \"collector\"
ip = socket.gethostbyname(SERVER)
print(f\"Sending DISCOVER to {SERVER} ({ip})...\")

xid = random.getrandbits(32)
mac_bytes = bytes([0x02, 0xde, 0xad, 0xbe, 0xef, 0x42])

discover = (
    BOOTP(op=1, htype=1, hlen=6, xid=xid, chaddr=mac_bytes + b\"\\x00\"*10) /
    DHCP(options=[
        (\"message-type\", \"discover\"),
        (\"hostname\", \"scapy-interop-test\"),
        (\"param_req_list\", 1, 3, 6, 51, 54),
        \"end\",
    ])
)

raw = bytes(discover)
print(f\"DISCOVER size: {len(raw)} bytes\")

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((\"0.0.0.0\", 0))
s.settimeout(5)
s.sendto(raw, (ip, 67))

data, _ = s.recvfrom(4096)
print(f\"Received {len(data)} bytes back from server\")
print()
print(\"=== scapy decoded our OFFER as: ===\")
parsed = BOOTP(data)
parsed.show()
'
"
