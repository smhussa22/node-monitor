import random
import time
import json
import socket
import threading
from dataclasses import dataclass, asdict
from typing import Optional

import requests


# telemetry payload emitted by a simulated cisco router
@dataclass
class CiscoRouterMetrics:

    hostname: str           # name of the simulated router
    vendor: str             # device vendor identifier; cisco
    cpu: float              # cpu usage percentage
    memory: float           # memory usage percentage
    interface_stats: dict   # per-interface (connection point on router) byte and packet counters
    ospf_neighbors: int     # count of active open shortest path first (ospf) neighbors
    bgp_peers: int          # count of active border gateway protocol (bgp) peers


# simulates a cisco router that pushes metrics and netflow records to a collector
class CiscoRouterSimulator:

    def __init__(self, hostname: str, collector_url: str, netflow_host: str = "127.0.0.1", netflow_port: int = 2055, interval_sec: float = 30.0):

        self.hostname: str = hostname                       # name of the simulated router
        self.collector_url: str = collector_url             # http url where metrics are pushed
        self.netflow_host: str = netflow_host               # host that receives netflow records over udp
        self.netflow_port: int = netflow_port               # udp port that receives netflow records
        self.interval_sec: float = interval_sec             # seconds between export cycles
        self.running: bool = False                          # whether the export loop is active
        self.thread: Optional[threading.Thread] = None      # background export thread
        self.netflow_socket: Optional[socket.socket] = None # udp socket used for netflow exports

    # begin pushing metrics on a background thread
    def start(self) -> None:

        if self.running: return

        self.running = True
        self.netflow_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    # stop pushing metrics and join the background thread
    def stop(self) -> None:

        if not self.running: return

        self.running = False
        if self.thread is not None: self.thread.join()
        if self.netflow_socket is not None: self.netflow_socket.close()
        self.thread = None
        self.netflow_socket = None

    # build a metrics payload and push it to the collector over http
    def export_metrics(self) -> None:

        # build a fresh metrics snapshot with fluctuating fake values
        metrics = CiscoRouterMetrics(
            hostname=self.hostname,
            vendor="cisco",
            cpu=round(random.uniform(20.0, 85.0), 2),
            memory=round(random.uniform(35.0, 75.0), 2),
            interface_stats=self._generate_interface_stats(),
            ospf_neighbors=random.randint(2, 5),
            bgp_peers=random.randint(1, 3),
        )

        # post the snapshot to the http collector
        try:
            requests.post(self.collector_url, json=asdict(metrics), timeout=5)
        except requests.RequestException as e:
            print(f"[{self.hostname}] metric export failed: {e}")

    # build a netflow record and push it to the collector over udp
    def export_netflow(self) -> None:

        if self.netflow_socket is None: return

        # build a randomized flow record
        record = {
            "src": f"10.0.0.{random.randint(1, 254)}",
            "dst": f"8.8.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "bytes": random.randint(1024, 500_000_000),
            "duration": random.randint(1, 60),
            "hostname": self.hostname,
        }

        # send the record to the netflow collector
        try:
            payload = json.dumps(record).encode("utf-8")
            self.netflow_socket.sendto(payload, (self.netflow_host, self.netflow_port))
        except OSError as e:
            print(f"[{self.hostname}] netflow export failed: {e}")

    # generate a small snapshot of per-interface counters
    def _generate_interface_stats(self) -> dict:

        stats: dict = {}
        for i in range(4):
            stats[f"GigabitEthernet0/{i}"] = {
                "rx_bytes": random.randint(10_000, 10_000_000),
                "tx_bytes": random.randint(10_000, 10_000_000),
                "rx_packets": random.randint(100, 100_000),
                "tx_packets": random.randint(100, 100_000),
            }
        return stats

    # background loop driving metric and netflow exports
    def _loop(self) -> None:

        while self.running:
            self.export_metrics()
            self.export_netflow()

            # sleep in small chunks so stop() can interrupt the loop quickly
            elapsed: float = 0.0
            while self.running and elapsed < self.interval_sec:
                time.sleep(0.5)
                elapsed += 0.5
