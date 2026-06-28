import random
import time
import threading
from dataclasses import dataclass, asdict
from typing import Optional

import requests


# telemetry payload emitted by a simulated juniper srx firewall
@dataclass
class JuniperSRXMetrics:

    hostname: str                  # name of the simulated firewall
    vendor: str                    # device vendor identifier; juniper
    cpu: float                     # cpu usage percentage
    memory: float                  # memory usage percentage
    active_firewall_sessions: int  # current number of active firewall sessions
    vpn_tunnels_up: int            # count of currently established vpn tunnels
    firewall_throughput: float     # current throughput in bytes per second
    health_status: str             # rolled-up device health: healthy, degraded, or down
    timestamp: float               # epoch seconds when the snapshot was generated
    ip: Optional[str] = None       # ipv4 address acquired via dhcp; None when dhcp wasn't used


# simulates a juniper srx firewall that pushes metrics to a collector
class JuniperSRXSimulator:

    def __init__(self, hostname: str, collector_url: str, interval_sec: float = 30.0, assigned_ip: Optional[str] = None):

        self.hostname: str = hostname                       # name of the simulated firewall
        self.collector_url: str = collector_url             # http url where metrics are pushed
        self.interval_sec: float = interval_sec             # seconds between export cycles
        self.assigned_ip: Optional[str] = assigned_ip       # ip acquired from dhcp; included in metric payload
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
            active_firewall_sessions=random.randint(1000, 5000),
            vpn_tunnels_up=random.randint(0, 5),
            firewall_throughput=round(random.uniform(1e6, 1e9), 2),
            health_status=random.choices(["healthy", "degraded", "down"], weights=[0.85, 0.12, 0.03])[0],
            timestamp=time.time(),
            ip=self.assigned_ip,
        )

        # post the snapshot to the http collector
        try:
            requests.post(self.collector_url, json=asdict(metrics), timeout=5)
        except requests.RequestException as e:
            print(f"[{self.hostname}] metric export failed: {e}")

    # background loop driving metric exports
    def _loop(self) -> None:

        while self.running:
            self.export_metrics()

            # sleep in small chunks so stop() can interrupt the loop quickly
            elapsed: float = 0.0
            while self.running and elapsed < self.interval_sec:
                time.sleep(0.5)
                elapsed += 0.5
