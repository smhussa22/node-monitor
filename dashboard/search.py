import re
from typing import List, Optional, Tuple


# per-source whitelist of searchable fields. anything not in this set is dropped from the parsed
# expression rather than spliced into SQL, so the search page never exposes an injection surface
SOURCE_CONFIG: dict = {

    "incidents": {
        "timestamp_col": "fired_at",
        "select_cols": "rule_name, hostname, severity, fired_at, resolved_at, details",
        "text_field":   "rule_name || ' ' || hostname || ' ' || severity || ' ' || COALESCE(details::text, '')",
        "string_fields": {"rule_name", "hostname", "severity"},
        "numeric_fields": set(),
        "special_fields": {"status"},  # active / resolved
    },

    "metrics": {
        "timestamp_col": "ts",
        "select_cols":   "hostname, vendor, cpu, memory, ts, payload->>'health_status' AS health_status",
        "text_field":    "hostname || ' ' || vendor || ' ' || COALESCE(payload::text, '')",
        "string_fields": {"hostname", "vendor"},
        "numeric_fields": {"cpu", "memory"},
        "special_fields": set(),
    },

    "flows": {
        "timestamp_col": "received_at",
        "select_cols":   "src_ip, dst_ip, src_port, dst_port, protocol, bytes, acl_action, acl_rule_id, received_at",
        "text_field":    "src_ip || ' ' || dst_ip || ' ' || protocol || ' ' || COALESCE(acl_action, '')",
        "string_fields": {"src_ip", "dst_ip", "protocol", "acl_action"},
        "numeric_fields": {"src_port", "dst_port", "bytes"},
        "special_fields": set(),
    },

    "actions": {
        "timestamp_col": "started_at",
        "select_cols":   "runbook_name, rule_name, hostname, action_type, target, status, started_at, response_code",
        "text_field":    "runbook_name || ' ' || rule_name || ' ' || hostname || ' ' || action_type || ' ' || target || ' ' || status",
        "string_fields": {"runbook_name", "rule_name", "hostname", "action_type", "status"},
        "numeric_fields": {"response_code"},
        "special_fields": set(),
    },

}


# user-facing window strings -> postgres interval literal AND histogram bucket width
WINDOW_INTERVAL: dict = {
    "15m": ("15 minutes",   "30 seconds"),
    "1h":  ("1 hour",       "1 minute"),
    "6h":  ("6 hours",      "5 minutes"),
    "24h": ("24 hours",     "30 minutes"),
}


# one clause produced by the parser; ready to splice into the WHERE list with bound params
class Clause:

    def __init__(self, sql: str, params: list):

        self.sql: str = sql        # SQL fragment with $1-style placeholders translated to %s by psycopg
        self.params: list = params # bound values in order


# parsed result: source name (which table), the time-window string, the list of clauses, the raw query
class ParsedQuery:

    def __init__(self):

        self.source: str = "incidents"  # which table to search
        self.window: Optional[str] = None  # window override; None means "use the cookie default"
        self.clauses: List[Clause] = []    # WHERE-fragment list
        self.errors: List[str] = []        # parse errors (shown to the user as a warning)


# the tiny SPL-ish parser. tokens are whitespace-separated; supported forms:
#   source=incidents | metrics | flows | actions
#   last=15m | last=1h | ...
#   field=value     field!=value     field:value  (alias for =)
#   field<N         field>N          field<=N     field>=N    (numeric)
#   anything else is a free-text term matched against the source's text_field with ILIKE
def parse(query: str) -> ParsedQuery:

    out = ParsedQuery()
    if not query:
        return out

    # split on whitespace; quoted values like "hello world" survive as one token
    tokens = re.findall(r'"[^"]*"|\S+', query)

    for tok in tokens:

        # source selector
        m = re.match(r"^source\s*=\s*(.+)$", tok)
        if m:
            v = m.group(1).strip().strip('"')
            if v in SOURCE_CONFIG:
                out.source = v
            else:
                out.errors.append(f"unknown source '{v}'")
            continue

        # time window selector
        m = re.match(r"^last\s*=\s*(.+)$", tok)
        if m:
            v = m.group(1).strip().strip('"')
            if v in WINDOW_INTERVAL:
                out.window = v
            else:
                out.errors.append(f"unknown window '{v}' (try 15m/1h/6h/24h)")
            continue

        # field operator value: =, !=, :, <, >, <=, >=
        m = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)(!=|<=|>=|=|:|<|>)("[^"]*"|\S+)$', tok)
        if m:
            key, op, raw_val = m.group(1), m.group(2), m.group(3).strip('"')
            out.clauses.append(_field_clause(out.source, key, op, raw_val, out.errors))
            continue

        # free-text term: wildcard match against the source's text_field
        if tok.strip():
            term = tok.strip().strip('"')
            cfg = SOURCE_CONFIG[out.source]
            out.clauses.append(Clause(f"({cfg['text_field']}) ILIKE %s", [f"%{term}%"]))

    # drop None clauses produced by rejected fields
    out.clauses = [c for c in out.clauses if c is not None]
    return out


# build a single field=value (or other op) clause, validating that the field is allowed for the source
def _field_clause(source: str, key: str, op: str, value: str, errors: list) -> Optional[Clause]:

    cfg = SOURCE_CONFIG.get(source)
    if cfg is None:
        return None

    # special field: incidents.status maps to a different SQL shape
    if key in cfg["special_fields"] and source == "incidents" and key == "status":
        v = value.lower()
        if v == "active":
            return Clause("resolved_at IS NULL", [])
        if v == "resolved":
            return Clause("resolved_at IS NOT NULL", [])
        errors.append(f"status value must be 'active' or 'resolved'")
        return None

    # numeric ops require a numeric field
    if op in ("<", ">", "<=", ">="):
        if key not in cfg["numeric_fields"]:
            errors.append(f"field '{key}' is not numeric")
            return None
        try:
            float(value)
        except ValueError:
            errors.append(f"'{value}' is not a number")
            return None
        return Clause(f"{key} {op} %s", [value])

    # equality / inequality on string fields (numeric fields also work via implicit text cast in pg)
    if key in cfg["string_fields"] or key in cfg["numeric_fields"]:
        sql_op = "!=" if op == "!=" else "="
        return Clause(f"{key}::text {sql_op} %s", [value])

    errors.append(f"unknown field '{key}' for source '{source}'")
    return None


# combine clauses with AND, prepending WHERE if any survived parsing. returns (sql_fragment, params)
def build_where(clauses: List[Clause]) -> Tuple[str, list]:

    if not clauses:
        return "", []
    fragments = [c.sql for c in clauses]
    params: list = []
    for c in clauses:
        params.extend(c.params)
    return "WHERE " + " AND ".join(fragments), params


# return (interval_literal, bucket_width_literal) for a given window string; falls back to '1 hour' / '1 minute'
def window_to_interval_and_bucket(window: Optional[str]) -> Tuple[str, str]:

    return WINDOW_INTERVAL.get(window or "1h", WINDOW_INTERVAL["1h"])
