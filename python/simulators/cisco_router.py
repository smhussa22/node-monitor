import random
import time
import json
import socket
import struct
import threading
from dataclasses import dataclass, asdict
from typing import Optional

import requests


# telemetry payload emitted by a simulated cisco router
@dataclass
class CiscoRouterMetrics:

    hostname: str                  # name of the simulated router
    vendor: str                    # device vendor identifier; cisco
    cpu: float                     # cpu usage percentage
    memory: float                  # memory usage percentage
    interface_stats: dict          # per-interface (connection point on router) byte and packet counters
    ospf_neighbors: int            # count of active open shortest path first (ospf) neighbors
    bgp_peers: int                 # count of active border gateway protocol (bgp) peers
    health_status: str             # rolled-up device health: healthy, degraded, or down
    timestamp: float               # epoch seconds when the snapshot was generated
    ip: Optional[str] = None       # ipv4 address acquired via dhcp; None when dhcp wasn't used


# simulates a cisco router that pushes metrics and netflow records to a collector
class CiscoRouterSimulator:

    def __init__(self, hostname: str, collector_url: str, netflow_host: str = "127.0.0.1", netflow_port: int = 2055, interval_sec: float = 30.0, assigned_ip: Optional[str] = None):

        self.hostname: str = hostname                       # name of the simulated router
        self.collector_url: str = collector_url             # http url where metrics are pushed
        self.netflow_host: str = netflow_host               # host that receives netflow records over udp
        self.netflow_port: int = netflow_port               # udp port that receives netflow records
        self.interval_sec: float = interval_sec             # seconds between export cycles
        self.assigned_ip: Optional[str] = assigned_ip       # ip acquired from dhcp; included in metric payload
        self.running: bool = False                          # whether the export loop is active
        self.thread: Optional[threading.Thread] = None      # background export thread
        self.netflow_socket: Optional[socket.socket] = None # udp socket used for netflow exports
        self.netflow_boot_ms: int = int(time.monotonic() * 1000)  # exporter boot time for the sys_uptime field
        self.netflow_seq: int = 0                           # monotonic flow_sequence; persists across calls

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
            health_status=random.choices(["healthy", "degraded", "down"], weights=[0.85, 0.12, 0.03])[0],
            timestamp=time.time(),
            ip=self.assigned_ip,
        )

        # post the snapshot to the http collector
        try:
            requests.post(self.collector_url, json=asdict(metrics), timeout=5)
        except requests.RequestException as e:
            print(f"[{self.hostname}] metric export failed: {e}")

    # build a real NetFlow v5 datagram and push it to the collector over UDP. wire format per Cisco's
    # original NetFlow v5 spec: 24-byte big-endian header + 48-byte big-endian flow records. one record
    # per datagram is fine for a simulator; real routers batch up to 30 records per datagram
    def export_netflow(self) -> None:

        if self.netflow_socket is None: return

        # pick a randomized 5-tuple with the same port mix and protocol weighting as the json version
        src_a, src_b, src_c, src_d = 10, 0, 0, random.randint(1, 254)
        dst_a, dst_b, dst_c, dst_d = 8, random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 53, 3389, 8080, random.randint(1024, 65535)])
        proto = random.choice([6, 17, 1])   # TCP / UDP / ICMP
        octets = random.randint(1024, 500_000_000) & 0xFFFFFFFF
        packets = random.randint(1, 100)

        # timestamps in the header are seconds + nanos; per-flow first/last are sys_uptime ms relative to boot
        now_ms = int(time.monotonic() * 1000) - self.netflow_boot_ms
        duration_ms = random.randint(1000, 60_000)
        first_ms = max(0, now_ms - duration_ms)
        last_ms = now_ms
        unix_secs = int(time.time())
        unix_nsecs = int((time.time() % 1) * 1_000_000_000)

        self.netflow_seq = (self.netflow_seq + 1) & 0xFFFFFFFF

        # 24-byte header (network byte order). version=5, count=1, then timing + sequence + engine fields
        header = struct.pack(
            "!HHIIIIBBH",
            5,              # version
            1,              # count of records in this datagram
            now_ms,         # sys_uptime
            unix_secs,
            unix_nsecs,
            self.netflow_seq,
            0,              # engine_type
            0,              # engine_id
            0,              # sampling_interval (mode + interval)
        )

        # 48-byte v5 record (network byte order)
        src_addr = (src_a << 24) | (src_b << 16) | (src_c << 8) | src_d
        dst_addr = (dst_a << 24) | (dst_b << 16) | (dst_c << 8) | dst_d
        record = struct.pack(
            "!IIIHHIIIIHHBBBBHHBBH",
            src_addr,       # srcaddr
            dst_addr,       # dstaddr
            0,              # nexthop
            0, 0,           # input, output ifindex
            packets,        # dPkts
            octets,         # dOctets
            first_ms, last_ms,
            src_port, dst_port,
            0,              # pad1
            0,              # tcp_flags
            proto,          # protocol
            0,              # tos
            0, 0,           # src_as, dst_as
            0, 0,           # src_mask, dst_mask
            0,              # pad2
        )

        try:
            self.netflow_socket.sendto(header + record, (self.netflow_host, self.netflow_port))
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
