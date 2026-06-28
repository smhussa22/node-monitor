import json
import os
import time
from collections import deque
from typing import Any
from urllib.request import urlopen
from urllib.error import URLError

from flask import Flask, Response, jsonify, redirect, render_template, request, stream_with_context

from db import query_all, query_one
from filters import parse_filter, window_interval


# url of the c++ collector's http endpoint; same in docker-compose and k8s because the service is named "collector"
COLLECTOR_URL = os.environ.get("COLLECTOR_URL", "http://collector:8000")


# fetch the live acl rule snapshot from the collector; returns a stable empty payload when the collector
# is unreachable so the dashboard renders cleanly during cold start instead of 500'ing
def fetch_acl_snapshot() -> dict:

    try:
        with urlopen(f"{COLLECTOR_URL}/acl/rules", timeout=2) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (URLError, OSError, ValueError):
        return {"totals": {"evaluations": 0, "permits": 0, "denies": 0, "implicit_denies": 0}, "rules": []}


app = Flask(__name__)


# ---- helpers ------------------------------------------------------------------

# read the global time window from the cookie, defaulting to 1h
def current_window() -> str:

    return request.cookies.get("window", "1h")


# severity badge css class names that match the bootstrap palette
SEVERITY_CLASS = {
    "critical": "bg-danger",
    "warning":  "bg-warning text-dark",
    "info":     "bg-info text-dark",
}

HEALTH_CLASS = {
    "healthy":  "bg-success",
    "degraded": "bg-warning text-dark",
    "down":     "bg-danger",
}


# inject helpers + window selector state into every template
@app.context_processor
def template_globals() -> dict:

    return {
        "current_window": current_window(),
        "severity_class": SEVERITY_CLASS,
        "health_class": HEALTH_CLASS,
        "windows": ["15m", "1h", "6h", "24h"],
    }


# ---- health endpoints ---------------------------------------------------------

# cheap liveness probe — no DB query, just confirms the gunicorn worker is responsive
@app.route("/healthz")
def healthz() -> Response:

    return jsonify({"ok": True})


# readiness probe — confirms the DB connection pool can hand out a working connection
@app.route("/readyz")
def readyz() -> Response:

    try:
        query_one("SELECT 1 AS ok")
        return jsonify({"ready": True})
    except Exception as e:
        return jsonify({"ready": False, "error": str(e)}), 503


# ---- HTML pages ---------------------------------------------------------------

@app.route("/")
def home() -> str:

    window = current_window()
    interval = window_interval(window)

    # count current devices and live alert counts per severity
    by_vendor = query_all(
        "SELECT vendor, COUNT(DISTINCT hostname) AS hosts FROM metrics "
        f"WHERE ts > NOW() - INTERVAL '{interval}' GROUP BY vendor ORDER BY hosts DESC"
    )
    active_alerts = query_all(
        "SELECT severity, COUNT(*) AS n FROM incidents WHERE resolved_at IS NULL GROUP BY severity"
    )
    severity_counts = {row["severity"]: row["n"] for row in active_alerts}
    severity_counts.setdefault("critical", 0)
    severity_counts.setdefault("warning", 0)
    severity_counts.setdefault("info", 0)

    # top-5 noisiest hosts in the chosen window
    noisiest = query_all(
        "SELECT hostname, COUNT(*) AS incidents FROM incidents "
        f"WHERE fired_at > NOW() - INTERVAL '{interval}' "
        "GROUP BY hostname ORDER BY incidents DESC LIMIT 5"
    )

    # top-5 alert-firing rules in the chosen window
    top_rules = query_all(
        "SELECT rule_name, severity, COUNT(*) AS fired FROM incidents "
        f"WHERE fired_at > NOW() - INTERVAL '{interval}' "
        "GROUP BY rule_name, severity ORDER BY fired DESC LIMIT 5"
    )

    # top-5 current CPU consumers; scope to the last 5 minutes so the DISTINCT ON scan stays cheap as the metrics
    # table grows. without this clause the query degrades linearly with corpus size — at 1k devices it's already slow
    top_cpu = query_all(
        "WITH recent AS ("
        "  SELECT hostname, vendor, cpu, memory, ts FROM metrics "
        "  WHERE ts > NOW() - INTERVAL '5 minutes'"
        "), latest AS ("
        "  SELECT DISTINCT ON (hostname) hostname, vendor, cpu, memory, ts "
        "  FROM recent ORDER BY hostname, ts DESC"
        ") "
        "SELECT hostname, vendor, cpu, memory FROM latest "
        "ORDER BY cpu DESC LIMIT 5"
    )

    # overall counters
    summary = query_one(
        "SELECT (SELECT COUNT(*) FROM metrics) AS metric_rows, "
        "       (SELECT COUNT(*) FROM incidents) AS incident_rows, "
        "       (SELECT COUNT(*) FROM flows) AS flow_rows, "
        "       (SELECT COUNT(*) FROM actions) AS action_rows, "
        "       (SELECT MAX(ts) FROM metrics) AS last_metric"
    ) or {}

    return render_template(
        "home.html",
        by_vendor=by_vendor,
        severity_counts=severity_counts,
        noisiest=noisiest,
        top_rules=top_rules,
        top_cpu=top_cpu,
        summary=summary,
    )


@app.route("/devices")
def devices() -> str:

    filter_str = request.args.get("filter")
    where_sql, params = parse_filter(filter_str, "metrics")

    # window to last 15 minutes so DISTINCT ON doesn't scan the entire metrics table at any reasonable corpus size
    sql = (
        "WITH recent AS ("
        "  SELECT hostname, vendor, cpu, memory, ts, payload FROM metrics "
        "  WHERE ts > NOW() - INTERVAL '15 minutes'"
        "), latest AS ("
        "  SELECT DISTINCT ON (hostname) hostname, vendor, cpu, memory, ts, payload "
        "  FROM recent ORDER BY hostname, ts DESC"
        ") "
        f"SELECT hostname, vendor, cpu, memory, ts AS last_seen, "
        "       payload->>'health_status' AS health_status "
        "FROM latest " + (where_sql or "") + " ORDER BY hostname"
    )
    rows = query_all(sql, tuple(params))
    return render_template("devices.html", devices=rows, filter_str=filter_str or "")


@app.route("/devices/<hostname>")
def device_detail(hostname: str) -> str:

    window = current_window()
    interval = window_interval(window)

    latest = query_one(
        "SELECT hostname, vendor, cpu, memory, ts, payload, "
        "       payload->>'health_status' AS health_status "
        "FROM metrics WHERE hostname = %s ORDER BY ts DESC LIMIT 1",
        (hostname,),
    )
    if latest is None:
        return render_template("device_detail.html", hostname=hostname, latest=None, incidents=[])

    incidents = query_all(
        "SELECT rule_name, severity, fired_at, resolved_at, details "
        "FROM incidents WHERE hostname = %s "
        f"AND fired_at > NOW() - INTERVAL '{interval}' "
        "ORDER BY fired_at DESC LIMIT 50",
        (hostname,),
    )

    # use psycopg's native datetime handling via the api endpoint; for template we just need pretty fields
    payload_pretty = json.dumps(latest.get("payload"), indent=2, default=str) if latest else ""

    return render_template(
        "device_detail.html",
        hostname=hostname,
        latest=latest,
        payload_pretty=payload_pretty,
        incidents=incidents,
    )


@app.route("/alerts")
def alerts() -> str:

    filter_str = request.args.get("filter")
    severity = request.args.get("severity")

    # build a flat list of WHERE clauses and bind params, then join with AND; this keeps the SQL readable
    _, parsed_params = parse_filter(filter_str, "incidents")
    clauses: list = []
    params: list = []
    if filter_str:
        # use parse_filter to get the per-clause fragments without its leading WHERE
        fragment_sql, fragment_params = parse_filter(filter_str, "incidents")
        if fragment_sql.startswith("WHERE "):
            clauses.append(fragment_sql[6:])
            params.extend(fragment_params)
    if severity in ("critical", "warning", "info"):
        clauses.append("severity = %s")
        params.append(severity)

    active_clauses = clauses + ["resolved_at IS NULL"]
    active_where = " WHERE " + " AND ".join(active_clauses)
    active = query_all(
        "SELECT rule_name, hostname, severity, fired_at, details FROM incidents"
        + active_where
        + " ORDER BY severity, fired_at DESC LIMIT 200",
        tuple(params),
    )
    recent = query_all(
        "SELECT rule_name, hostname, severity, fired_at, resolved_at, details "
        "FROM incidents WHERE resolved_at IS NOT NULL "
        "ORDER BY resolved_at DESC LIMIT 50"
    )
    return render_template(
        "alerts.html",
        active=active,
        recent=recent,
        filter_str=filter_str or "",
        severity=severity or "",
    )


@app.route("/topology")
def topology() -> str:

    rows = query_all(
        "WITH latest AS ("
        "  SELECT DISTINCT ON (hostname) hostname, vendor, payload->>'health_status' AS health, ts "
        "  FROM metrics ORDER BY hostname, ts DESC"
        ") "
        "SELECT hostname, vendor, "
        "       COALESCE(health, 'unknown') AS health, "
        "       EXTRACT(EPOCH FROM (NOW() - ts))::int AS age_s "
        "FROM latest ORDER BY vendor, hostname"
    )

    # tile color: red if offline (>60s) or health=down, yellow if degraded, green if healthy
    by_vendor: dict[str, list] = {}
    for r in rows:
        effective = r["health"]
        if r["age_s"] is not None and r["age_s"] > 60:
            effective = "offline"
        r["effective_health"] = effective
        by_vendor.setdefault(r["vendor"], []).append(r)

    return render_template("topology.html", by_vendor=by_vendor)


@app.route("/timeline")
def timeline() -> str:

    window = current_window()
    interval = window_interval(window)
    rows = query_all(
        "SELECT rule_name, hostname, severity, "
        "       EXTRACT(EPOCH FROM fired_at)*1000 AS fired_ms, "
        "       EXTRACT(EPOCH FROM COALESCE(resolved_at, NOW()))*1000 AS resolved_ms "
        "FROM incidents "
        f"WHERE fired_at > NOW() - INTERVAL '{interval}' "
        "ORDER BY fired_at"
    )
    incidents_json = json.dumps([
        {
            "rule": r["rule_name"],
            "host": r["hostname"],
            "severity": r["severity"],
            "start": int(r["fired_ms"]),
            "end": int(r["resolved_ms"]),
        }
        for r in rows
    ])
    return render_template("timeline.html", incidents_json=incidents_json, count=len(rows))


@app.route("/live")
def live() -> str:

    return render_template("live.html")


@app.route("/actions")
def actions() -> str:

    window = current_window()
    interval = window_interval(window)
    rows = query_all(
        "SELECT runbook_name, rule_name, hostname, action_type, target, status, started_at, completed_at, error_message, response_code "
        "FROM actions "
        f"WHERE started_at > NOW() - INTERVAL '{interval}' "
        "ORDER BY started_at DESC LIMIT 500"
    )
    by_status = query_all(
        "SELECT status, COUNT(*) AS n FROM actions "
        f"WHERE started_at > NOW() - INTERVAL '{interval}' "
        "GROUP BY status ORDER BY n DESC"
    )
    by_runbook = query_all(
        "SELECT runbook_name, COUNT(*) AS total, "
        "       COUNT(*) FILTER (WHERE status = 'success') AS success, "
        "       COUNT(*) FILTER (WHERE status = 'failed') AS failed, "
        "       COUNT(*) FILTER (WHERE status = 'dry_run') AS dry_run, "
        "       COUNT(*) FILTER (WHERE status = 'cooldown_suppressed') AS cooldown "
        "FROM actions "
        f"WHERE started_at > NOW() - INTERVAL '{interval}' "
        "GROUP BY runbook_name ORDER BY total DESC"
    )
    return render_template("actions.html", actions=rows, by_status=by_status, by_runbook=by_runbook)


@app.route("/blocked-traffic")
def blocked_traffic() -> str:

    window = current_window()
    interval = window_interval(window)

    # live acl rule definitions + per-rule hit counts come from the collector's in-memory engine
    acl = fetch_acl_snapshot()

    # top denied src->dst pairs in the chosen window, straight from the flows table
    top_denied = query_all(
        "SELECT src_ip, dst_ip, dst_port, protocol, COUNT(*) AS flows, SUM(bytes) AS total_bytes "
        "FROM flows "
        f"WHERE received_at > NOW() - INTERVAL '{interval}' AND acl_action = 'deny' "
        "GROUP BY src_ip, dst_ip, dst_port, protocol "
        "ORDER BY flows DESC LIMIT 15"
    )

    # denied flow counts grouped by the rule that matched; NULL acl_rule_id means implicit deny
    denied_by_rule = query_all(
        "SELECT acl_rule_id, COUNT(*) AS flows "
        "FROM flows "
        f"WHERE received_at > NOW() - INTERVAL '{interval}' AND acl_action = 'deny' "
        "GROUP BY acl_rule_id ORDER BY flows DESC"
    )

    # action mix for the donut: permits vs explicit denies vs implicit denies (NULL rule id)
    mix = query_all(
        "SELECT acl_action, "
        "       COUNT(*) FILTER (WHERE acl_rule_id IS NULL) AS implicit, "
        "       COUNT(*) FILTER (WHERE acl_rule_id IS NOT NULL) AS explicit "
        "FROM flows "
        f"WHERE received_at > NOW() - INTERVAL '{interval}' AND acl_action IS NOT NULL "
        "GROUP BY acl_action"
    )

    # build a {rule_id -> description} map so we can label denied_by_rule rows nicely
    rule_labels = {r["id"]: r["description"] for r in acl.get("rules", [])}
    denied_rows = []
    for r in denied_by_rule:
        rid = r.get("acl_rule_id")
        denied_rows.append({
            "rule_id": rid,
            "label": rule_labels.get(rid, "implicit deny") if rid is not None else "implicit deny",
            "flows": int(r["flows"]),
        })

    # turn the mix rows into a single object the chart can consume
    permit_count = 0
    explicit_deny_count = 0
    implicit_deny_count = 0
    for row in mix:
        if row["acl_action"] == "permit":
            permit_count = int(row["explicit"] or 0) + int(row["implicit"] or 0)
        elif row["acl_action"] == "deny":
            explicit_deny_count = int(row["explicit"] or 0)
            implicit_deny_count = int(row["implicit"] or 0)

    mix_json = json.dumps({
        "permit": permit_count,
        "explicit_deny": explicit_deny_count,
        "implicit_deny": implicit_deny_count,
    })

    return render_template(
        "blocked_traffic.html",
        acl=acl,
        top_denied=top_denied,
        denied_rows=denied_rows,
        mix_json=mix_json,
        permit_count=permit_count,
        explicit_deny_count=explicit_deny_count,
        implicit_deny_count=implicit_deny_count,
    )


@app.route("/netflow")
def netflow() -> str:

    window = current_window()
    interval = window_interval(window)

    # top src->dst pairs by total bytes
    top_talkers = query_all(
        "SELECT src_ip, dst_ip, SUM(bytes) AS total_bytes, COUNT(*) AS flows "
        "FROM flows "
        f"WHERE received_at > NOW() - INTERVAL '{interval}' "
        "GROUP BY src_ip, dst_ip ORDER BY total_bytes DESC LIMIT 10"
    )

    # top destination ports by flow count
    top_ports = query_all(
        "SELECT dst_port, COUNT(*) AS flows, SUM(bytes) AS total_bytes "
        "FROM flows "
        f"WHERE received_at > NOW() - INTERVAL '{interval}' AND dst_port IS NOT NULL "
        "GROUP BY dst_port ORDER BY flows DESC LIMIT 10"
    )

    # protocol breakdown for the donut chart
    protocols = query_all(
        "SELECT protocol, COUNT(*) AS flows, SUM(bytes) AS total_bytes "
        "FROM flows "
        f"WHERE received_at > NOW() - INTERVAL '{interval}' "
        "GROUP BY protocol ORDER BY flows DESC"
    )

    total = query_one(
        "SELECT COUNT(*) AS total_flows, SUM(bytes) AS total_bytes "
        "FROM flows "
        f"WHERE received_at > NOW() - INTERVAL '{interval}'"
    ) or {"total_flows": 0, "total_bytes": 0}

    return render_template(
        "netflow.html",
        top_talkers=top_talkers,
        top_ports=top_ports,
        protocols=protocols,
        protocols_json=json.dumps([{"protocol": p["protocol"], "flows": int(p["flows"])} for p in protocols]),
        total=total,
    )


# ---- JSON API -----------------------------------------------------------------

@app.route("/api/acl/rules")
def api_acl_rules() -> Response:

    return jsonify(fetch_acl_snapshot())


@app.route("/api/summary")
def api_summary() -> Response:

    return jsonify(query_one(
        "SELECT (SELECT COUNT(*) FROM metrics) AS metric_rows, "
        "       (SELECT COUNT(*) FROM incidents WHERE resolved_at IS NULL) AS active_alerts, "
        "       (SELECT COUNT(*) FROM flows) AS flow_rows, "
        "       (SELECT MAX(ts) FROM metrics) AS last_metric"
    ) or {})


@app.route("/api/devices/<hostname>/history")
def api_device_history(hostname: str) -> Response:

    window = request.args.get("window", current_window())
    interval = window_interval(window)
    rows = query_all(
        "SELECT EXTRACT(EPOCH FROM ts)*1000 AS ts_ms, cpu, memory "
        "FROM metrics WHERE hostname = %s "
        f"AND ts > NOW() - INTERVAL '{interval}' "
        "ORDER BY ts ASC",
        (hostname,),
    )
    return jsonify([
        {"ts": int(r["ts_ms"]), "cpu": float(r["cpu"]), "memory": float(r["memory"])}
        for r in rows
    ])


@app.route("/api/devices/sparklines")
def api_devices_sparklines() -> Response:

    # one query returns recent cpu samples for every device; the page slices per host client-side
    rows = query_all(
        "SELECT hostname, EXTRACT(EPOCH FROM ts)*1000 AS ts_ms, cpu, memory "
        "FROM metrics WHERE ts > NOW() - INTERVAL '30 minutes' "
        "ORDER BY hostname, ts ASC"
    )
    by_host: dict[str, list] = {}
    for r in rows:
        by_host.setdefault(r["hostname"], []).append([int(r["ts_ms"]), float(r["cpu"]), float(r["memory"])])
    return jsonify(by_host)


@app.route("/api/alerts/active")
def api_alerts_active() -> Response:

    rows = query_all(
        "SELECT rule_name, hostname, severity, fired_at, details "
        "FROM incidents WHERE resolved_at IS NULL ORDER BY severity, fired_at DESC LIMIT 200"
    )
    return jsonify([
        {**r, "fired_at": r["fired_at"].isoformat() if r.get("fired_at") else None}
        for r in rows
    ])


@app.route("/api/live/stream")
def api_live_stream() -> Response:

    # poll the metrics table every second and stream new rows as server-sent events
    def gen():
        last_ts = None
        while True:
            params: tuple = ()
            sql = ("SELECT hostname, vendor, cpu, memory, ts, payload->>'health_status' AS health_status "
                   "FROM metrics ORDER BY ts DESC LIMIT 20")
            if last_ts is not None:
                sql = ("SELECT hostname, vendor, cpu, memory, ts, payload->>'health_status' AS health_status "
                       "FROM metrics WHERE ts > %s ORDER BY ts ASC LIMIT 50")
                params = (last_ts,)
            rows = query_all(sql, params)
            for r in rows:
                ts = r["ts"]
                if ts is not None:
                    last_ts = ts
                payload = {
                    "hostname": r["hostname"],
                    "vendor": r["vendor"],
                    "cpu": float(r["cpu"]),
                    "memory": float(r["memory"]),
                    "ts": ts.isoformat() if ts else None,
                    "health_status": r.get("health_status"),
                }
                yield f"data: {json.dumps(payload)}\n\n"
            time.sleep(1)

    return Response(stream_with_context(gen()), mimetype="text/event-stream")


@app.route("/api/devices/<hostname>/csv")
def api_device_csv(hostname: str) -> Response:

    window = request.args.get("window", current_window())
    interval = window_interval(window)
    rows = query_all(
        "SELECT ts, cpu, memory, payload->>'health_status' AS health_status "
        "FROM metrics WHERE hostname = %s "
        f"AND ts > NOW() - INTERVAL '{interval}' "
        "ORDER BY ts ASC",
        (hostname,),
    )

    def gen():
        yield "ts,cpu,memory,health_status\n"
        for r in rows:
            ts = r["ts"].isoformat() if r["ts"] else ""
            yield f"{ts},{r['cpu']},{r['memory']},{r.get('health_status') or ''}\n"

    return Response(gen(), mimetype="text/csv", headers={
        "Content-Disposition": f'attachment; filename="{hostname}_{window}.csv"'
    })


# ---- window cookie setter -----------------------------------------------------

@app.route("/set-window/<window>")
def set_window(window: str) -> Response:

    target = request.args.get("next", "/")
    resp = redirect(target)
    if window in ("15m", "1h", "6h", "24h"):
        resp.set_cookie("window", window, max_age=60 * 60 * 24 * 30)
    return resp
