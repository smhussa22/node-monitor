import argparse
import os
import signal
import sys
import time
from typing import List, Optional

import random
import time

from simulators.cisco_router import CiscoRouterSimulator
from simulators.dhcp_client import DhcpClient
from simulators.dns_client import DnsClient
from simulators.juniper_srx import JuniperSRXSimulator
from simulators.paloalto import PaloAltoSimulator
from simulators.snmp_agent import SnmpAgent, MibTree, install_baseline


# spin up a configurable number of simulators that push metrics to the c++ collector
def main() -> None:

    parser = argparse.ArgumentParser(description="drive the node-monitor collector with simulated devices")
    parser.add_argument("--count", type=int, default=3, help="number of simulated devices to spin up")
    parser.add_argument("--duration", type=int, default=30, help="seconds to run before stopping; 0 means run forever")
    parser.add_argument("--interval", type=float, default=2.0, help="seconds between exports per device")
    parser.add_argument("--collector", type=str, default="http://localhost:8000", help="collector base url")
    parser.add_argument("--vendor", type=str, default="all", choices=["cisco", "juniper", "paloalto", "all"], help="restrict to a single vendor")
    parser.add_argument("--netflow-host", type=str, default="127.0.0.1", help="udp host for cisco netflow records")
    parser.add_argument("--netflow-port", type=int, default=2055, help="udp port for cisco netflow records")
    parser.add_argument("--hostname-prefix", type=str, default=os.environ.get("POD_NAME", os.environ.get("HOSTNAME", "local")), help="prefix added to each simulated hostname to keep them unique across pods")
    parser.add_argument("--dhcp-server", type=str, default=os.environ.get("DHCP_SERVER", ""), help="dhcp server ip; when set, each simulator does a real DORA exchange before pushing metrics")
    parser.add_argument("--dhcp-port", type=int, default=int(os.environ.get("DHCP_PORT", "67")), help="dhcp server udp port")
    parser.add_argument("--dns-server", type=str, default=os.environ.get("DNS_SERVER", ""), help="dns server ip; when set, each simulator does live A + PTR lookups against our c++ DnsServer after DORA")
    parser.add_argument("--dns-port", type=int, default=int(os.environ.get("DNS_PORT", "53")), help="dns server udp port")
    parser.add_argument("--dns-zone", type=str, default=os.environ.get("DNS_ZONE", "node-monitor.local"), help="zone suffix used for DNS lookups")
    parser.add_argument("--snmp-port", type=int, default=int(os.environ.get("SNMP_PORT", "161")), help="udp port the per-process snmp agent binds; set to 0 to disable")
    parser.add_argument("--snmp-community", type=str, default=os.environ.get("SNMP_COMMUNITY", "public"), help="community string the snmp agent accepts")
    args = parser.parse_args()

    # build the DNS client once and reuse it across simulators; resolve_a / resolve_ptr are stateless
    # so a single client serves the whole pool. None when --dns-server isn't configured
    dns: 'Optional[DnsClient]' = DnsClient(server_ip=args.dns_server, server_port=args.dns_port) if args.dns_server else None

    # restrict the vendor pool when caller pinned to one type
    vendors_all = [
        ("cisco", "router", CiscoRouterSimulator),
        ("juniper", "firewall", JuniperSRXSimulator),
        ("paloalto", "pa", PaloAltoSimulator),
    ]
    vendors = vendors_all if args.vendor == "all" else [v for v in vendors_all if v[0] == args.vendor]

    # build the simulator pool, round-robin across whichever vendors are active. when --dhcp-server is set,
    # each simulator does a real DORA exchange before being constructed and runs a background renewal thread
    sims: List = []
    dhcp_clients: List[DhcpClient] = []
    for i in range(args.count):
        vendor_name, host_prefix, cls = vendors[i % len(vendors)]
        hostname = f"{args.hostname_prefix}-{host_prefix}{i // len(vendors) + 1}"

        assigned_ip = None
        if args.dhcp_server:
            client = DhcpClient(hostname=hostname, server_ip=args.dhcp_server, server_port=args.dhcp_port)
            try:
                lease = client.acquire(timeout_sec=10.0)
                client.start_renewal()
                dhcp_clients.append(client)
                assigned_ip = lease.ip
                print(f"[dhcp] {hostname} bound {lease.ip} mask={lease.mask} gw={lease.gateway} lease={lease.lease_seconds}s")
            except Exception as e:
                print(f"[dhcp] {hostname} acquire failed: {e}; running without an assigned ip")

        # if DNS is configured, exercise the c++ DnsServer with two real queries that prove the dhcp->dns
        # auto-binding works: our own hostname should resolve to the ip dhcp just handed us, and the
        # static "collector" entry should resolve to the configured gateway. silent on failure so a
        # transient dns blip doesn't cascade to simulator startup
        if dns is not None and assigned_ip is not None:
            own_fqdn = f"{hostname}.{args.dns_zone}"
            resolved_self = dns.resolve_a(own_fqdn)
            resolved_collector = dns.resolve_a(f"collector.{args.dns_zone}")
            if resolved_self or resolved_collector:
                print(f"[dns] {hostname} resolved self={resolved_self} collector={resolved_collector}")

        if cls is CiscoRouterSimulator:
            sims.append(cls(hostname=hostname, collector_url=args.collector, netflow_host=args.netflow_host, netflow_port=args.netflow_port, interval_sec=args.interval, assigned_ip=assigned_ip))
        else:
            sims.append(cls(hostname=hostname, collector_url=args.collector, interval_sec=args.interval, assigned_ip=assigned_ip))

    # spin up a single snmp agent for this process; the first simulator's hostname is the device this
    # agent represents. one agent per container because UDP/161 is a single-binding port. other simulators
    # in the same process continue to push metrics via http alongside this snmp path
    snmp_agent: Optional[SnmpAgent] = None
    if args.snmp_port > 0 and sims:
        primary = sims[0]
        primary_vendor = vendors[0 % len(vendors)][0]
        boot_t = time.time()
        mib = MibTree()
        install_baseline(
            mib,
            hostname=getattr(primary, "hostname", "snmp-host"),
            vendor=primary_vendor,
            descr=f"{primary_vendor} simulator v1.0 (node-monitor)",
            boot_time=boot_t,
            get_cpu=lambda: random.uniform(20.0, 85.0),
            get_mem=lambda: random.uniform(35.0, 75.0),
        )
        snmp_agent = SnmpAgent(mib=mib, port=args.snmp_port, community=args.snmp_community)
        snmp_agent.start()
        if snmp_agent.running:
            print(f"[snmp] agent listening udp:{args.snmp_port} community={args.snmp_community} representing {getattr(primary, 'hostname', '?')}")

    # install a SIGINT handler so Ctrl+C and k8s SIGTERM stop every simulator cleanly. RELEASE any dhcp
    # leases on the way out so the server can reclaim ips immediately instead of waiting for expiry
    def shutdown(signum, frame) -> None:
        print(f"\nstopping {len(sims)} simulators...")
        for s in sims:
            s.stop()
        if snmp_agent is not None:
            snmp_agent.stop()
        for c in dhcp_clients:
            try: c.release()
            except Exception: pass
            c.stop()
        sys.exit(0)
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # start all simulators and let them run for the requested duration; 0 means run forever
    print(f"starting {args.count} {args.vendor} simulators pushing to {args.collector} every {args.interval}s (prefix={args.hostname_prefix})")
    for s in sims:
        s.start()

    if args.duration == 0:
        # block forever until a signal arrives
        while True:
            time.sleep(3600)
    else:
        time.sleep(args.duration)

    # stop everything cleanly
    print(f"stopping {len(sims)} simulators...")
    for s in sims:
        s.stop()
    if snmp_agent is not None:
        snmp_agent.stop()
    for c in dhcp_clients:
        try: c.release()
        except Exception: pass
        c.stop()


if __name__ == "__main__":
    main()
