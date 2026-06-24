import argparse
import sys
import time
from typing import Optional

import requests


COLLECTOR = "http://localhost:8000"


# post one metric payload; the json column will store whatever fields are present
def post(host: str, vendor: str, cpu: float, memory: float, health: str = "healthy", extra: Optional[dict] = None) -> bool:

    body = {"hostname": host, "vendor": vendor, "cpu": cpu, "memory": memory, "health_status": health, "timestamp": time.time()}
    if extra:
        body.update(extra)
    try:
        r = requests.post(COLLECTOR, json=body, timeout=5)
        return r.status_code == 200
    except requests.RequestException as e:
        print(f"  post failed: {e}")
        return False


# fire-immediately rules ---------------------------------------------------------------

def ips_storm(host: str) -> None:
    print(f"posting {host}: paloalto with ips_alerts=99")
    post(host, "paloalto", 50, 50, extra={"ips_alerts": 99, "blocked_connections": 50, "blocked_urls": 100})
    print("ALERT [critical] rule=ips_storm should fire within 10s (engine evaluates every 10s)")


def health_down(host: str) -> None:
    print(f"posting {host}: any vendor with health_status=down")
    post(host, "cisco", 50, 50, health="down", extra={"bgp_peers": 2, "ospf_neighbors": 2})
    print("ALERT [critical] rule=health_down should fire within 10s")


# sustained-window rules ---------------------------------------------------------------

def hold_condition(host: str, vendor: str, extra: dict, health: str, seconds: int, label: str) -> None:
    print(f"posting {host}: {label} for {seconds}s (every 5s)")
    iterations = seconds // 5 + 2
    for i in range(iterations):
        post(host, vendor, 50, 50, health=health, extra=extra)
        print(f"  post {i+1}/{iterations}")
        time.sleep(5)
    print(f"ALERT for this rule should have fired during the loop and may RESOLVE soon if you stop posting")


def bgp_loss(host: str) -> None:
    hold_condition(host, "cisco", {"bgp_peers": 0, "ospf_neighbors": 3}, "healthy", 70, "cisco bgp_peers=0")


def ospf_loss(host: str) -> None:
    hold_condition(host, "cisco", {"bgp_peers": 2, "ospf_neighbors": 0}, "healthy", 70, "cisco ospf_neighbors=0")


def vpn_partial(host: str) -> None:
    hold_condition(host, "juniper", {"vpn_tunnels_up": 0, "active_firewall_sessions": 2000, "firewall_throughput": 1e6}, "healthy", 70, "juniper vpn_tunnels_up=0")


def firewall_ddos(host: str) -> None:
    hold_condition(host, "paloalto", {"blocked_connections": 200, "ips_alerts": 5, "blocked_urls": 100}, "healthy", 70, "paloalto blocked_connections=200")


def health_degraded(host: str) -> None:
    hold_condition(host, "cisco", {"bgp_peers": 2, "ospf_neighbors": 2}, "degraded", 40, "health_status=degraded")


# rate-of-change rules -----------------------------------------------------------------

def cpu_spike(host: str) -> None:
    print(f"posting {host}: cpu=20 baseline, wait 12s, post cpu=70 (delta=50 over <30s)")
    post(host, "cisco", 20.0, 50.0, extra={"bgp_peers": 2, "ospf_neighbors": 2})
    time.sleep(12)
    post(host, "cisco", 70.0, 50.0, extra={"bgp_peers": 2, "ospf_neighbors": 2})
    print("ALERT [warning] rule=cpu_spike should fire within 10s")


def memory_jump(host: str) -> None:
    print(f"posting {host}: memory=30 baseline, wait 12s, post memory=65 (delta=35 over <60s)")
    post(host, "cisco", 50.0, 30.0, extra={"bgp_peers": 2, "ospf_neighbors": 2})
    time.sleep(12)
    post(host, "cisco", 50.0, 65.0, extra={"bgp_peers": 2, "ospf_neighbors": 2})
    print("ALERT [info] rule=memory_jump should fire within 10s")


def health_flapping(host: str) -> None:
    print(f"posting {host}: 5 health_status flips over ~30s")
    states = ["healthy", "degraded", "healthy", "degraded", "healthy"]
    for i, s in enumerate(states):
        post(host, "cisco", 50.0, 50.0, health=s, extra={"bgp_peers": 2, "ospf_neighbors": 2})
        print(f"  post {i+1}/{len(states)} health_status={s}")
        time.sleep(6)
    print("ALERT [warning] rule=health_flapping should fire within 10s")


# offline rule -------------------------------------------------------------------------

def device_offline(host: str) -> None:
    print(f"posting {host} once, then waiting 70s without further pushes")
    post(host, "cisco", 50.0, 50.0, extra={"bgp_peers": 2, "ospf_neighbors": 2})
    for i in range(7):
        print(f"  waiting... {70 - i*10}s")
        time.sleep(10)
    print("ALERT [critical] rule=device_offline should have fired")


# entrypoint ---------------------------------------------------------------------------

RULES = {
    "ips_storm": ips_storm,
    "health_down": health_down,
    "bgp_loss": bgp_loss,
    "ospf_loss": ospf_loss,
    "vpn_partial": vpn_partial,
    "firewall_ddos": firewall_ddos,
    "health_degraded": health_degraded,
    "cpu_spike": cpu_spike,
    "memory_jump": memory_jump,
    "health_flapping": health_flapping,
    "device_offline": device_offline,
}


def main() -> None:

    global COLLECTOR

    parser = argparse.ArgumentParser(description="manually trigger one of the registered alert rules against a running collector")
    parser.add_argument("rule", choices=sorted(RULES.keys()) + ["list"], help="rule to trigger (or 'list' to print all)")
    parser.add_argument("--host", default=None, help="hostname to use for the simulated device; defaults to test-<rule>")
    parser.add_argument("--collector", default=COLLECTOR, help="collector base url")
    args = parser.parse_args()

    if args.rule == "list":
        for name in sorted(RULES.keys()):
            print(f"  {name}")
        return

    COLLECTOR = args.collector
    host = args.host or f"test-{args.rule}"
    RULES[args.rule](host)


if __name__ == "__main__":
    main()
