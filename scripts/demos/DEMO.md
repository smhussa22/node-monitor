# node-monitor video demo — unnarrated walkthrough

Just stage directions: which window, what to do, how long to linger. No talking, no captions.

**Target length: ~10 minutes.**

---

## Before recording  (~25 min, off-camera)

```bash
./scripts/push-to-ecr.sh                                                    # ~5 min
SKIP_PUSH=true ./scripts/up.sh                                              # ~15 min
export LB=$(kubectl get svc dashboard -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
curl -s http://$LB/readyz                                                   # expect {"ready":true}
docker compose up -d && sleep 30                                            # local stack for Scene 3
```

**Windows:**
- Terminal — WSL, big font, `$LB` exported
- Browser — `http://$LB`
- Wireshark — `pcaps/all_2026-06-30_0843.pcap` loaded

---

## Scene 1 — Dashboard  (0:00 → 1:35)

**Window:** Browser → `http://$LB`

1. Home / Network funnel — 10s
2. Click **Search** → type `severity=critical` → Enter — 15s
3. Click **Incidents** → scroll slowly — 10s
4. Click **Blocked Traffic** — 10s
5. Navigate to `http://$LB/netflow` — 10s
6. Navigate to `http://$LB/dhcp` — 10s
7. Navigate to `http://$LB/dns` — 10s
8. Navigate to `http://$LB/snmp` — 10s
9. Navigate to `http://$LB/actions` — 10s

---

## Scene 2 — Kubernetes  (1:35 → 2:35)

**Window:** Terminal

```bash
kubectl get nodes
```
*Pause 5s*

```bash
kubectl get pods
```
*Pause 8s*

```bash
kubectl get hpa
```
*Pause 5s*

```bash
kubectl get svc
```
*Pause 5s*

---

## Scene 3 — Protocol interop  (2:35 → 4:50)

**Window:** Terminal

```bash
scripts/demos/interop_dns.sh
scripts/demos/interop_snmp.sh
scripts/demos/interop_dhcp.sh
scripts/demos/interop_netflow.sh
```

Let each one print fully before running the next.

---

## Scene 4 — Wireshark  (4:50 → 5:35)

**Window:** Wireshark

In the filter bar, type each and press Enter, ~10s each:

1. `bootp` → click a DISCOVER packet → expand BOOTP tree
2. `dns` → click a query → expand DNS tree
3. `snmp` → click a GetRequest → expand SNMP tree
4. `cflow` → click any NetFlow packet → expand cflow tree

---

## Scene 5 — Port scan  (5:35 → 6:35)

**Window:** Terminal

```bash
scripts/demos/local_port_scan.sh
```

During the 15s `sleep`, **Alt-Tab to Browser → Incidents**, refresh.

Back to Terminal once script prints the incident row.

---

## Scene 6 — BGP failure + self-healing  (6:35 → 9:20)

**Window:** Terminal (main focus)

```bash
scripts/demos/eks_bgp_failure.sh
```

The script has built-in waits. **Alt-Tab between Terminal and Browser → Incidents** during each wait so the camera sees both.

Stay on Terminal for the final `resolved_at` query at the end.

---

## Scene 7 — Numbers  (9:20 → 10:05)

**Window:** Terminal

```bash
scripts/demos/eks_harvest_numbers.sh
```

Let the camera hold on the suggested paragraph block at the end for ~10s.

---

## Scene 8 — Outro  (10:05 → 10:20)

**Window:** Browser → Search page

Type: `severity=critical AND rule=port_scan_detected` → Enter

Hold ~10s on the results. Stop recording.

---

## After recording

```bash
# 1. capture bench numbers (NOT saved anywhere — required for the writeup)
mkdir -p docs/evidence
scripts/demos/run_benchmarks.sh > docs/evidence/benchmarks.txt 2>&1   # ~5 min, local-only

# 2. kill the AWS bill
./scripts/down.sh                                                     # ~10 min teardown
scripts/demos/aws_verify_clean.sh                                     # exit 0 = no charges
```

Benchmarks are local (gcc:14 container) — they don't need EKS, so it's safe to run them
in parallel with the EKS teardown if you want.

---

## If something breaks mid-recording

| Problem | Fix |
|---|---|
| Dashboard 502 | `kubectl rollout restart deployment/dashboard`, wait 30s |
| Sim pod Pending | `kubectl describe pod <name>` — autoscaler usually adds a node within 2 min |
| BGP doesn't resolve in 90s | Wait 60s more, FRR re-peering can be slow |
| `eks_harvest_numbers` shows blanks | Collector hasn't been running long enough — let it cook 5+ min |

Scenes are independent. Pause, fix, retake from the next scene.

---

## Glossary (reference only, never on camera)

| Acronym | Meaning |
|---|---|
| EKS | AWS-managed Kubernetes |
| EBS | AWS disk storage (used by Postgres) |
| ECR | AWS Docker image registry |
| ELB | AWS load balancer (dashboard URL) |
| HPA | Auto-scales sim pods on CPU |
