#!/usr/bin/env bash
# inject 60 binary NetFlow v5 packets from one src across distinct dst ports — the canonical
# horizontal-scan fingerprint. waits for the PortScanRule to fire and prints the resulting incident
#
# usage:  scripts/demos/local_port_scan.sh

set -euo pipefail

echo "=== port scan detection demo ==="
echo ""
echo "Injecting 60 binary NetFlow v5 packets from src=10.42.99.99 across dst_ports 1..60."
echo "All TCP. Same src_ip. This is what a real horizontal scan looks like on the wire."
echo ""

python <<'PY'
import socket, struct, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
boot = int(time.monotonic() * 1000)
for p in range(1, 61):
    now_ms = int(time.monotonic() * 1000) - boot
    header = struct.pack("!HHIIIIBBH", 5, 1, now_ms, int(time.time()), 0, p, 0, 0, 0)
    src = (10 << 24) | (42 << 16) | (99 << 8) | 99   # 10.42.99.99
    dst = (8 << 24) | (8 << 16) | (8 << 8) | 8        # 8.8.8.8
    record = struct.pack("!IIIHHIIIIHHBBBBHHBBH", src, dst, 0, 0, 0, 1, 64, 0, now_ms, 54321, p, 0, 0, 6, 0, 0, 0, 0, 0, 0)
    s.sendto(header + record, ("localhost", 2055))
print("  → 60 packets sent in <100ms")
PY

echo ""
echo "Waiting 15s for the AlertEngine tick (every 10s) to evaluate the rule..."
sleep 15

echo ""
echo "=== incidents fired by port_scan_detected ==="
docker exec nm-postgres psql -U nodemonitor -d node_monitor \
    -c "SELECT rule_name, hostname, severity, details->>'description' AS detail FROM incidents WHERE rule_name='port_scan_detected' ORDER BY fired_at DESC LIMIT 3;" 2>&1 | sed 's/^/  /'

echo ""
echo "Expected: a row with src=10.42.99.99 and description matching '60 distinct dst ports in the last 60s'"
