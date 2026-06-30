#!/usr/bin/env bash
# build + run all five micro / wire benches in a throwaway gcc:14 container. captures clean output
# blocks the writeup can use verbatim.
#
# usage:  scripts/demos/run_benchmarks.sh [sample_size_scale=1]
# scale=1 → defaults (1M ACL, 100k DHCP, 1M DNS, 10k DHCP wire, 100k DNS wire)
# scale=2 → 2x sizes (longer, more stable numbers)

set -euo pipefail

SCALE="${1:-1}"

ACL_N=$((1000000 * SCALE))
DHCP_N=$((100000 * SCALE))
DNS_N=$((1000000 * SCALE))
DHCP_W_N=$((10000 * SCALE))
DNS_W_N=$((100000 * SCALE))

echo "=== node-monitor benchmark suite ==="
echo "Scale: ${SCALE} (acl=${ACL_N} dhcp=${DHCP_N} dns=${DNS_N} dhcp_wire=${DHCP_W_N} dns_wire=${DNS_W_N})"
echo ""
echo "Building binaries in a throwaway gcc:14 container (one-time apt install + cmake)..."

MSYS_NO_PATHCONV=1 docker run --rm \
    -v "/c/Users/faraz/node-monitor/cc:/src" \
    -w /src \
    --entrypoint /bin/bash \
    gcc:14 -lc "
apt-get update -qq >/dev/null
apt-get install -qq -y --no-install-recommends cmake libpq-dev libcurl4-openssl-dev libpq5 libcurl4 >/dev/null 2>&1
cmake -B /tmp/build -DCMAKE_BUILD_TYPE=Release >/dev/null 2>&1
cmake --build /tmp/build --target acl_bench dhcp_bench dns_bench dhcp_bench_wire dns_bench_wire -j >/dev/null 2>&1

echo ''
echo '======================================================================'
echo '=== ACL evaluator (in-process; no wire layer)                      ==='
echo '======================================================================'
/tmp/build/acl_bench ${ACL_N} 2>&1 | tail -12

echo ''
echo '======================================================================'
echo '=== DHCP DORA (in-process; codec + state machine only)             ==='
echo '======================================================================'
/tmp/build/dhcp_bench ${DHCP_N} 2>&1 | tail -10

echo ''
echo '======================================================================'
echo '=== DNS query (in-process; codec + zone lookup only)               ==='
echo '======================================================================'
/tmp/build/dns_bench ${DNS_N} 2>&1 | tail -10

echo ''
echo '======================================================================'
echo '=== DHCP DORA over real UDP (127.0.0.1) — the over-the-wire number ==='
echo '======================================================================'
/tmp/build/dhcp_bench_wire ${DHCP_W_N} 2>&1 | grep -v -E '\\[dhcp\\] (OFFER|ACK)' | tail -12

echo ''
echo '======================================================================'
echo '=== DNS query over real UDP (127.0.0.1) — the over-the-wire number ==='
echo '======================================================================'
/tmp/build/dns_bench_wire ${DNS_W_N} 2>&1 | tail -10
"

echo ""
echo "Lead with the over-the-wire numbers in the writeup. The in-process numbers exist for sizing"
echo "the CPU budget of the codec itself but are 10-30x higher than what real production would see."
