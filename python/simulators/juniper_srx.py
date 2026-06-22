import random
import time
import threading
from dataclasses import dataclass, asdict
from typing import Optional

import requests


# telemetry payload emitted by a simulated juniper srx firewall
@dataclass
class JuniperSRXMetrics:

    hostname: str                # name of the simulated firewall
    vendor: str                  # device vendor identifier; juniper
    cpu: float                   # cpu usage percentage
    memory: float                # memory usage percentage
    active_sessions: int         # current number of active firewall sessions
    vpn_status: dict             # per-tunnel vpn up/down state
    firewall_throughput: float   # current throughput in bytes per second


# simulates a juniper srx firewall that pushes metrics to a collector
class JuniperSRXSimulator:

    def __init__(self, hostname: str, collector_url: str, interval_sec: float = 30.0):

        self.hostname: str = hostname                       # name of the simulated firewall
        self.collector_url: str = collector_url             # http url where metrics are pushed
        self.interval_sec: float = interval_sec             # seconds between export cycles
        self.running: bool = False                          # whether the export loop is active
        self.thread: Optional[threading.Thread] = None      # background export thread

    # begin pushing metrics on a background thread
    def start(self) -> None:

        if self.running: return

        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    # stop pushing metrics and join the background thread
    def stop(self) -> None:

        if not self.running: return

        self.running = False
        if self.thread is not None: self.thread.join()
        self.thread = None

    # build a metrics payload and push it to the collector over http
    def export_metrics(self) -> None:

        # build a fresh metrics snapshot with fluctuating fake values
        metrics = JuniperSRXMetrics(
            hostname=self.hostname,
            vendor="juniper",
            cpu=round(random.uniform(15.0, 80.0), 2),
            memory=round(random.uniform(40.0, 70.0), 2),
            active_sessions=random.randint(1000, 5000),
            vpn_status=self._generate_vpn_status(),
            firewall_throughput=round(random.uniform(1e6, 1e9), 2),
        )

        # post the snapshot to the http collector
        try:
            requests.post(self.collector_url, json=asdict(metrics), timeout=5)
        except requests.RequestException as e:
            print(f"[{self.hostname}] metric export failed: {e}")

    # generate randomized vpn tunnel up/down state
    def _generate_vpn_status(self) -> dict:

        # 90 percent chance each tunnel is up
        return {f"tunnel-{i}": random.random() > 0.1 for i in range(3)}

    # background loop driving metric exports
    def _loop(self) -> None:

        while self.running:
            self.export_metrics()

            # sleep in small chunks so stop() can interrupt the loop quickly
            elapsed: float = 0.0
            while self.running and elapsed < self.interval_sec:
                time.sleep(0.5)
                elapsed += 0.5
