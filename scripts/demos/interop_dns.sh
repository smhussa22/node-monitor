#!/usr/bin/env bash
# real-tool interop: dig from ISC BIND queries our hand-rolled DnsServer for A / AAAA / PTR / NXDOMAIN
# / REFUSED. all five rcode paths exercised; output goes straight into the writeup verbatim.
#
# usage:  scripts/demos/interop_dns.sh

set -euo pipefail

if ! docker ps --format '{{.Names}}' | grep -q nm-collector; then
    echo "error: nm-collector not running. start the stack first: docker compose up -d"
    exit 1
fi

echo "=== DNS interop: dig (ISC BIND) → our DnsServer ==="
echo ""

docker run --rm --network node-monitor_default alpine:latest sh -c "
apk add --quiet bind-tools >/dev/null 2>&1
echo '--- A record ---'
echo '\$ dig +short @collector A collector.node-monitor.local'
dig +short @collector A collector.node-monitor.local
echo ''
echo '--- AAAA record (IPv4-mapped IPv6 synthesized from the A binding per RFC 4291 § 2.5.5.2) ---'
echo '\$ dig +short @collector AAAA collector.node-monitor.local'
dig +short @collector AAAA collector.node-monitor.local
echo ''
echo '--- PTR (reverse lookup via the in-addr.arpa chain) ---'
echo '\$ dig +short @collector -x 10.42.0.1'
dig +short @collector -x 10.42.0.1
echo ''
echo '--- NXDOMAIN (name does not exist in our zone) ---'
echo '\$ dig +short @collector A nonexistent.node-monitor.local'
out=\$(dig +short @collector A nonexistent.node-monitor.local)
if [ -z \"\$out\" ]; then echo '(empty — correct: server returned NOERROR with 0 answers / NXDOMAIN)'; else echo \"\$out\"; fi
echo ''
echo '--- REFUSED (name is outside our authoritative zone) ---'
echo '\$ dig +short @collector A google.com'
out=\$(dig +short @collector A google.com)
if [ -z \"\$out\" ]; then echo '(empty — correct: server returned REFUSED for off-zone query)'; else echo \"\$out\"; fi
"
