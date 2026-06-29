#!/usr/bin/env bash
# wrapper entrypoint for the FRR + bgp_scraper image. order:
#   1. start bgp_scraper in background (it tolerates bgpd not being up yet)
#   2. exec FRR's normal docker-start (watchfrr supervisor) — this becomes pid 1
# the scraper streams BGP peer state to the collector every interval seconds

set -e

# wait briefly so docker logs interleave the banners predictably
sleep 1

echo "[start] launching bgp_scraper sidecar"
python3 /usr/local/bin/bgp_scraper.py &

echo "[start] launching FRR (watchfrr -> zebra + bgpd + staticd + mgmtd)"
if [ -x /usr/lib/frr/docker-start ]; then
    exec /usr/lib/frr/docker-start
else
    echo "[start] /usr/lib/frr/docker-start missing; this image isn't FRR"
    exit 1
fi
