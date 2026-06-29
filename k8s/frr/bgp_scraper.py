"""
sidecar process that runs INSIDE the FRR container alongside bgpd.

every interval seconds it executes `vtysh -c "show bgp summary json"` locally, parses the result,
and POSTs a metric to the collector's HTTP endpoint. the existing MetricCache + MetricStore +
AlertEngine pipeline picks it up like any other device metric. that way we monitor a real BGP
session without needing FRR's SNMP module (the upstream alpine FRR image does not ship it).

payload shape — flat enough that AlertEngine's ThresholdRule and StateChangeRule can read fields
directly via JSON Pointer:

  {
    "hostname": "frr1",
    "vendor":   "frr-router",
    "cpu":      0.0,
    "memory":   0.0,
    "health_status": "healthy" | "degraded",
    "local_as": 65001,
    "router_id": "172.20.0.10",
    "peers":    [
      { "ip": "172.20.0.11", "remote_as": 65002, "state": "Established", "uptime_s": 137 }
    ],
    "peers_total":       1,
    "peers_established": 1
  }
"""

import json
import os
import socket
import subprocess
import time
from typing import Optional

import urllib.request
import urllib.error


HOSTNAME    = os.environ.get("FRR_HOSTNAME", socket.gethostname())
COLLECTOR   = os.environ.get("COLLECTOR_URL", "http://collector:8000/")
INTERVAL    = float(os.environ.get("BGP_SCRAPE_INTERVAL", "15"))


# run "vtysh -c '<cmd>'" inside this container and return stdout as a string. shell=False on purpose
# so the command list is literal. raises on non-zero exit
def vtysh(cmd: str, timeout: float = 5.0) -> str:

    r = subprocess.run(
        ["/usr/bin/vtysh", "-c", cmd],
        capture_output=True, text=True, timeout=timeout, check=False,
    )
    if r.returncode != 0:
        raise RuntimeError(f"vtysh {cmd!r} failed (rc={r.returncode}): {r.stderr.strip()}")
    return r.stdout


# parse "show bgp summary json" into a flat metric payload. tolerates the JSON output being absent
# or partial (during early startup before bgpd has sessions)
def collect_bgp_state() -> dict:

    raw = vtysh("show bgp summary json")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {}

    # the JSON layout is {"ipv4Unicast": {"as": 65001, "routerId": "...", "peers": {...}, ...}}
    af = parsed.get("ipv4Unicast", {}) if isinstance(parsed, dict) else {}
    local_as  = int(af.get("as", 0))
    router_id = str(af.get("routerId", ""))

    peers = []
    established = 0
    for peer_ip, p in (af.get("peers") or {}).items():
        state = str(p.get("state", "")) or str(p.get("peerState", ""))
        remote_as = int(p.get("remoteAs", 0))
        uptime_s = int(p.get("peerUptimeMsec", 0)) // 1000
        peers.append({
            "ip": peer_ip,
            "remote_as": remote_as,
            "state": state,
            "uptime_s": uptime_s,
        })
        if state == "Established":
            established += 1

    health = "healthy" if peers and established == len(peers) else "degraded"

    return {
        "hostname": HOSTNAME,
        "vendor":   "frr-router",
        "cpu":      0.0,
        "memory":   0.0,
        "health_status": health,
        "local_as": local_as,
        "router_id": router_id,
        "peers":    peers,
        "peers_total":       len(peers),
        "peers_established": established,
    }


# POST the metric payload to the collector's HTTP endpoint. silently tolerates collector unreachable
# so a brief outage doesn't crash the scraper — next interval will retry
def push(metric: dict) -> None:

    body = json.dumps(metric).encode("utf-8")
    req = urllib.request.Request(COLLECTOR, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            r.read()
    except (urllib.error.URLError, OSError) as e:
        print(f"[bgp_scraper] push failed: {e}")


def main() -> None:

    print(f"[bgp_scraper] starting for {HOSTNAME}; pushing to {COLLECTOR} every {INTERVAL}s")
    while True:
        try:
            m = collect_bgp_state()
            push(m)
            est = m["peers_established"]
            total = m["peers_total"]
            print(f"[bgp_scraper] {HOSTNAME} as={m['local_as']} peers={est}/{total} health={m['health_status']}")
        except Exception as e:
            print(f"[bgp_scraper] iteration failed: {e}")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
