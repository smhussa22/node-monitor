import random
import time
import threading
from dataclasses import dataclass, asdict
from typing import Optional, List

import requests


# telemetry payload emitted by a simulated palo alto firewall
@dataclass
class PaloAltoMetrics:

    hostname: str                  # name of the simulated firewall
    vendor: str                    # device vendor identifier; paloalto
    cpu: float                     # cpu usage percentage
    memory: float                  # memory usage percentage
    ips_alerts: int                # count of intrusion prevention system alerts
    blocked_connections: int       # count of connections blocked by firewall rules
    url_filtering_stats: dict      # per-category url filter hit counters
    security_events: List[dict]    # recent security event records


# simulates a palo alto firewall that pushes security metrics to a collector
class PaloAltoSimulator:

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
        metrics = PaloAltoMetrics(
            hostname=self.hostname,
            vendor="paloalto",
            cpu=round(random.uniform(20.0, 80.0), 2),
            memory=round(random.uniform(40.0, 75.0), 2),
            ips_alerts=random.randint(0, 50),
            blocked_connections=random.randint(0, 200),
            url_filtering_stats=self._generate_url_filtering_stats(),
            security_events=self._generate_security_events(),
        )

        # post the snapshot to the http collector
        try:
            requests.post(self.collector_url, json=asdict(metrics), timeout=5)
        except requests.RequestException as e:
            print(f"[{self.hostname}] metric export failed: {e}")

    # generate randomized per-category url filter hit counters
    def _generate_url_filtering_stats(self) -> dict:

        categories = ["social-media", "streaming", "malware", "phishing", "business", "news"]
        return {cat: random.randint(0, 500) for cat in categories}

    # generate a small list of fake security events
    def _generate_security_events(self) -> List[dict]:

        event_types = ["malware-detected", "port-scan", "brute-force", "phishing-blocked", "ips-signature-match"]
        severities = ["low", "medium", "high", "critical"]

        # produce 0 to 3 events per export cycle
        events: List[dict] = []
        for _ in range(random.randint(0, 3)):
            events.append({
                "type": random.choice(event_types),
                "severity": random.choice(severities),
                "src_ip": f"192.168.1.{random.randint(1, 254)}",
                "timestamp": time.time(),
            })
        return events

    # background loop driving metric exports
    def _loop(self) -> None:

        while self.running:
            self.export_metrics()

            # sleep in small chunks so stop() can interrupt the loop quickly
            elapsed: float = 0.0
            while self.running and elapsed < self.interval_sec:
                time.sleep(0.5)
                elapsed += 0.5
