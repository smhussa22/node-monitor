import argparse
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
    parser.add_argument("--duration", type=int, default=30, help="seconds to run before stopping")
    parser.add_argument("--interval", type=float, default=2.0, help="seconds between exports per device")
    parser.add_argument("--collector", type=str, default="http://localhost:8000", help="collector base url")
    args = parser.parse_args()

    # build a round-robin mix of vendors so the cache shows entries from each
    sims: List = []
    vendors = [
        ("cisco", "router",   CiscoRouterSimulator),
        ("juniper", "firewall", JuniperSRXSimulator),
        ("paloalto", "pa",     PaloAltoSimulator),
    ]
    for i in range(args.count):
        vendor_name, host_prefix, cls = vendors[i % len(vendors)]
        hostname = f"{host_prefix}{i // len(vendors) + 1}"
        sims.append(cls(hostname=hostname, collector_url=args.collector, interval_sec=args.interval))

    # install a SIGINT handler so Ctrl+C stops every simulator cleanly
    def shutdown(signum, frame) -> None:
        print(f"\nstopping {len(sims)} simulators...")
        for s in sims:
            s.stop()
        sys.exit(0)
    signal.signal(signal.SIGINT, shutdown)

    # start all simulators and let them run for the requested duration
    print(f"starting {args.count} simulators pushing to {args.collector} every {args.interval}s for {args.duration}s")
    for s in sims:
        s.start()
    time.sleep(args.duration)

    # stop everything cleanly
    print(f"stopping {len(sims)} simulators...")
    for s in sims:
        s.stop()


if __name__ == "__main__":
    main()
