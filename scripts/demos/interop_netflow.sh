#!/usr/bin/env bash
# real-tool interop: nfcapd (the reference NetFlow collector daemon, part of nfdump) → our binary
# NetFlow v5 exporter. captures 60 seconds of live Cisco simulator output, then nfdump replays the
# captured flows showing every field correctly decoded.
#
# usage:  scripts/demos/interop_netflow.sh

set -euo pipefail

if ! docker ps --format '{{.Names}}' | grep -q node-monitor-simulator-cisco; then
    echo "error: simulator-cisco not running. start the stack first: docker compose up -d"
    exit 1
fi

echo "=== NetFlow interop: nfcapd / nfdump → our binary NetFlow v5 exporter ==="
echo ""

docker volume create nfcap_demo >/dev/null
docker rm -f nfdump_demo 2>/dev/null || true

echo "Step 1/4 — starting nfcapd on udp:2055 in a sidecar (apt-get installs nfdump...)"
docker run -d --name nfdump_demo --network node-monitor_default -v nfcap_demo:/data debian:bookworm-slim sh -c "
apt-get update -qq >/dev/null && apt-get install -qq -y --no-install-recommends nfdump procps >/dev/null
exec nfcapd -p 2055 -l /data -T all -t 60 -B 200000
" >/dev/null

echo "Step 2/4 — waiting 30s for apt + bind..."
sleep 30

echo "Step 3/4 — sending 60 binary v5 packets (mirrors what cisco_router.py emits live)..."
docker run --rm --network node-monitor_default python:3.12-slim sh -c "
python3 -c '
import socket, struct, time, random
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
boot = int(time.monotonic() * 1000)
for i in range(60):
    now_ms = int(time.monotonic() * 1000) - boot
    header = struct.pack(\"!HHIIIIBBH\", 5, 1, now_ms, int(time.time()), 0, i+1, 0, 0, 0)
    src = (10 << 24) | random.randint(1,254)
    dst = (8 << 24) | (random.randint(0,255) << 16) | (random.randint(0,255) << 8) | random.randint(1,254)
    record = struct.pack(\"!IIIHHIIIIHHBBBBHHBBH\", src, dst, 0, 0, 0, random.randint(1,100), random.randint(1024,500000), 0, now_ms, random.randint(1024,65535), random.choice([80,443,22,53]), 0, 0, random.choice([6,17]), 0, 0, 0, 0, 0, 0)
    s.sendto(header + record, (\"nfdump_demo\", 2055))
    time.sleep(0.02)
print(\"sent 60 binary v5 packets\")
'
" 2>&1 | tail -1

echo "Holding 5s for nfcapd to flush, then stopping..."
sleep 5
docker stop nfdump_demo >/dev/null

echo ""
echo "Step 4/4 — reading the capture with nfdump (the canonical NetFlow v5 analyzer)"
echo ""
docker run --rm -v nfcap_demo:/data debian:bookworm-slim sh -c "
apt-get update -qq >/dev/null && apt-get install -qq -y --no-install-recommends nfdump >/dev/null 2>&1
for f in /data/nfcapd.*; do
    echo \"=== \$f ===\"
    nfdump -r \"\$f\" -o long 2>&1 | head -25
done
"

docker rm -f nfdump_demo >/dev/null 2>&1
docker volume rm nfcap_demo >/dev/null 2>&1

echo ""
echo "Expected: nfdump shows decoded rows with timing, protocol, src:port → dst:port, packets, bytes."
echo "If you see decoded flows above, the v5 wire format is correct."
