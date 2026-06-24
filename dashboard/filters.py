import re
from typing import Optional, Tuple


# fields safe to filter on; everything else is rejected so we never expose injection surface
ALLOWED_FIELDS = {
    "metrics": {"hostname", "vendor", "health_status"},
    "incidents": {"hostname", "vendor", "severity", "rule_name", "status"},
}


# parse a simple "key=value AND key=value" expression into a parameterized SQL WHERE fragment
# returns (sql_fragment, params_list); both are empty when filter_str is blank or unparseable
def parse_filter(filter_str: Optional[str], table: str) -> Tuple[str, list]:

    if not filter_str:
        return "", []

    allowed: set = ALLOWED_FIELDS.get(table, set())
    fragments: list = []
    params: list = []

    # split on case-insensitive AND surrounded by whitespace
    parts: list = re.split(r"\s+and\s+", filter_str.strip(), flags=re.IGNORECASE)
    for part in parts:
        # accept key=value, key!=value, and key:value as alternate syntax
        m = re.match(r"^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*(=|!=|:)\s*(.+?)\s*$", part)
        if not m:
            continue
        key: str = m.group(1)
        op: str = m.group(2)
        raw_value: str = m.group(3).strip().strip('"').strip("'")
        if key not in allowed:
            continue

        # status=active and status=resolved are special: they map to resolved_at IS NULL / IS NOT NULL
        if table == "incidents" and key == "status":
            if raw_value.lower() == "active":
                fragments.append("resolved_at IS NULL")
            elif raw_value.lower() == "resolved":
                fragments.append("resolved_at IS NOT NULL")
            continue

        sql_op: str = "!=" if op == "!=" else "="
        fragments.append(f"{key} {sql_op} %s")
        params.append(raw_value)

    if not fragments:
        return "", []
    return "WHERE " + " AND ".join(fragments), params


# translate the user-facing time window strings into postgres INTERVAL literals
WINDOW_TO_INTERVAL = {
    "15m": "15 minutes",
    "1h":  "1 hour",
    "6h":  "6 hours",
    "24h": "24 hours",
}


def window_interval(window: Optional[str]) -> str:

    return WINDOW_TO_INTERVAL.get(window or "1h", "1 hour")
