# node-monitor demo scripts

Self-contained scripts for the writeup. Each one is independent — run from the repo root.

## Local (docker compose)

All of these run against the local docker-compose stack. Bring it up first:

```bash
docker compose up -d
# wait ~30s for everything to settle
```

| Script | What it demonstrates |
|---|---|
| `local_port_scan.sh` | Injects 60 binary NetFlow v5 packets from one src_ip → `port_scan_detected` fires |
| `local_bgp_failure.sh` | Kills nm-frr2 → `bgp_peer_down` fires → restarts nm-frr2 → incident auto-resolves |
| `local_harvest_numbers.sh` | Prints the headline numbers from the local postgres |
| `local_capture_pcap.sh` | Tcpdumps DHCP/DNS/SNMP/NetFlow traffic to a fresh pcap for Wireshark |

## Third-party tool interop (docker-compose stack must be running)

| Script | What it demonstrates |
|---|---|
| `interop_dns.sh` | `dig` resolving A/AAAA/PTR against our DnsServer |
| `interop_snmp.sh` | `snmpget` + `snmpwalk` + `snmpbulkwalk` against our SnmpAgent |
| `interop_dhcp.sh` | `scapy` decoding a DHCP OFFER from our DhcpServer |
| `interop_netflow.sh` | `nfcapd`/`nfdump` parsing our binary NetFlow v5 output |

## Benchmarks

| Script | What it demonstrates |
|---|---|
| `run_benchmarks.sh` | Builds + runs all five micro/wire benches, prints the results block |

## EKS (requires kubectl + WSL or Linux)

| Script | What it demonstrates |
|---|---|
| `eks_smoke.sh` | Hits every JSON endpoint on the LB — expects `LB=<hostname>` env |
| `eks_pod_restart.sh` | Kills a simulator pod, waits, verifies the runbook executed a real `restart_pod` action with `response_code=200` |
| `eks_bgp_failure.sh` | Same as `local_bgp_failure.sh` but against EKS |
| `eks_harvest_numbers.sh` | Headline numbers from the EKS postgres pod |

---

## How the writeup uses these

Run each one, capture its stdout, paste into the writeup as a code block. The text in each script's stdout is intentionally formatted as a self-contained narrative ("expected:", "actual:", "passed/failed").
