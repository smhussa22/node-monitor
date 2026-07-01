# node-monitor demo scripts

**Recording a video?** Open [`DEMO.md`](./DEMO.md) — scene-by-scene script with windows,
commands, and narration cues.

Everything in this folder is a self-contained script. Each one prints its own
"expected / actual" narrative so the terminal looks good on camera.

## Local-stack demos (docker compose required)

| Script | What it does |
|---|---|
| `interop_dns.sh` | `dig` resolves A / AAAA / PTR / NXDOMAIN / REFUSED against our DnsServer |
| `interop_snmp.sh` | `snmpget` + `snmpwalk` + `snmpbulkwalk` against our SnmpAgent |
| `interop_dhcp.sh` | `scapy` decodes a DHCP OFFER from our DhcpServer (full options) |
| `interop_netflow.sh` | `nfcapd` / `nfdump` parse our binary NetFlow v5 output |
| `local_port_scan.sh` | Injects 60 NetFlow v5 packets → `port_scan_detected` fires |
| `local_bgp_failure.sh` | Kills nm-frr2 → `bgp_peer_down` → runbook → auto-resolve (remediation is dry_run on compose) |
| `local_harvest_numbers.sh` | Headline numbers from local Postgres |
| `local_capture_pcap.sh [type] [seconds]` | Tcpdumps to `pcaps/<type>_<YYYY-MM-DD>_<HHMM>.pcap`. type ∈ {all, dhcp, dns, snmp, snmp-bulk, snmp-traps, netflow} |
| `run_benchmarks.sh` | Builds + runs all five micro/wire benches |

## EKS demos (kubectl required, EKS already deployed)

All take `LB=<dashboard-hostname>` from `kubectl get svc dashboard`.

| Script | What it does |
|---|---|
| `eks_smoke.sh` | Hits every JSON endpoint on the LB |
| `eks_pod_restart.sh` | Kills a sim pod → verifies real `restart_pod` action (`status=success`, `response_code=200`) |
| `eks_bgp_failure.sh` | Same loop as local but with **real** K8s API remediation |
| `eks_harvest_numbers.sh` | Headline numbers + suggested writeup paragraph |

## pcaps

All captures go to `pcaps/` at repo root (git-ignored). Filenames carry protocol +
timestamp so multiple runs don't collide:

```
pcaps/all_2026-06-30_0843.pcap
pcaps/dhcp_2026-06-30_0923.pcap
pcaps/snmp-bulk_2026-06-30_0844.pcap
```

`bootp`, `dns`, `snmp`, `cflow` are the Wireshark filter-bar names for the four
hand-implemented protocols.
