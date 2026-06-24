import argparse
import os
import signal
import sys
import time
from typing import List

from simulators.cisco_router import CiscoRouterSimulator
from simulators.juniper_srx import JuniperSRXSimulator
from simulators.paloalto import PaloAltoSimulator


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
    args = parser.parse_args()

    # restrict the vendor pool when caller pinned to one type
    vendors_all = [
        ("cisco", "router", CiscoRouterSimulator),
        ("juniper", "firewall", JuniperSRXSimulator),
        ("paloalto", "pa", PaloAltoSimulator),
    ]
    vendors = vendors_all if args.vendor == "all" else [v for v in vendors_all if v[0] == args.vendor]

    # build the simulator pool, round-robin across whichever vendors are active
    sims: List = []
    for i in range(args.count):
        vendor_name, host_prefix, cls = vendors[i % len(vendors)]
        hostname = f"{args.hostname_prefix}-{host_prefix}{i // len(vendors) + 1}"
        if cls is CiscoRouterSimulator:
            sims.append(cls(hostname=hostname, collector_url=args.collector, netflow_host=args.netflow_host, netflow_port=args.netflow_port, interval_sec=args.interval))
        else:
            sims.append(cls(hostname=hostname, collector_url=args.collector, interval_sec=args.interval))

    # install a SIGINT handler so Ctrl+C and k8s SIGTERM stop every simulator cleanly
    def shutdown(signum, frame) -> None:
        print(f"\nstopping {len(sims)} simulators...")
        for s in sims:
            s.stop()
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


if __name__ == "__main__":
    main()
