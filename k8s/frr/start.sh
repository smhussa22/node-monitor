#!/usr/bin/env bash
# wrapper entrypoint for the FRR + bgp_scraper image.
#
# templates /etc/frr/frr.conf from /etc/frr/frr.conf.tmpl using env vars so the same image works for
# both docker-compose (static peer IPs) and kubernetes (peer hostnames that resolve via CoreDNS).
# the peer host can be a dotted-quad or a DNS name — getent does the right thing in both cases.
# after templating, starts the bgp_scraper sidecar and hands off to FRR's normal docker-start

set -e

LOCAL_AS="${LOCAL_AS:-65001}"
PEER_AS="${PEER_AS:-65002}"
PEER_HOST="${PEER_HOST:-172.20.0.11}"
PEER_DESC="${PEER_DESC:-peer}"
ADVERTISE_PREFIX="${ADVERTISE_PREFIX:-10.10.10.0/24}"
HOSTNAME_TAG="${FRR_HOSTNAME:-$(hostname)}"

# resolve the peer host into an IP. retry briefly so DNS races at pod start don't fail us.
# getent ahosts returns "<ip> <name>..." lines; take the first IP it gives us
PEER_IP=""
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    PEER_IP="$(getent ahosts "$PEER_HOST" | awk 'NR==1{print $1}')"
    if [ -n "$PEER_IP" ]; then
        echo "[start] resolved peer $PEER_HOST -> $PEER_IP"
        break
    fi
    echo "[start] peer $PEER_HOST unresolved (attempt $attempt); retrying in 2s"
    sleep 2
done
if [ -z "$PEER_IP" ]; then
    echo "[start] FATAL: peer $PEER_HOST never resolved"
    exit 1
fi

# router-id should be the pod's primary ipv4. if ROUTER_ID env override is set we honor it (used by
# docker-compose where the FRR is on a static subnet and the static IP is the obvious router-id);
# otherwise pick the first non-loopback ip we have, which on k8s is the pod IP
ROUTER_ID="${ROUTER_ID:-}"
if [ -z "$ROUTER_ID" ]; then
    ROUTER_ID="$(hostname -i 2>/dev/null | awk '{print $1}')"
fi
echo "[start] router-id = $ROUTER_ID, local-as = $LOCAL_AS, peer = $PEER_IP (AS $PEER_AS)"

# substitute placeholders in the template into the real config
sed -e "s|__HOSTNAME__|$HOSTNAME_TAG|g" \
    -e "s|__LOCAL_AS__|$LOCAL_AS|g" \
    -e "s|__PEER_AS__|$PEER_AS|g" \
    -e "s|__PEER_IP__|$PEER_IP|g" \
    -e "s|__PEER_DESC__|$PEER_DESC|g" \
    -e "s|__ROUTER_ID__|$ROUTER_ID|g" \
    -e "s|__ADVERTISE_PREFIX__|$ADVERTISE_PREFIX|g" \
    /etc/frr/frr.conf.tmpl > /etc/frr/frr.conf

chown frr:frr /etc/frr/frr.conf
chmod 640 /etc/frr/frr.conf

echo "[start] templated /etc/frr/frr.conf:"
sed -e 's/^/  /' /etc/frr/frr.conf

echo "[start] launching bgp_scraper sidecar"
python3 /usr/local/bin/bgp_scraper.py &

echo "[start] launching FRR (watchfrr -> zebra + bgpd + staticd + mgmtd)"
if [ -x /usr/lib/frr/docker-start ]; then
    exec /usr/lib/frr/docker-start
else
    echo "[start] /usr/lib/frr/docker-start missing; this image isn't FRR"
    exit 1
fi
