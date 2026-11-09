"""Each rule's alerts (Rule Monitoring, #68): how many it raised each day, by workflow status.

TIDE didn't read a destination's alerts; alert volume is the main sign of a rule that needs tuning,
and the base for spotting silent rules and spikes. At each sync, for each (SIEM, space) synced, one
paged aggregation through Kibana's alert search (``elastic_helper.fetch_alert_counts``) counts each
rule's alerts per day (UTC) and status over the last ``ALERT_DAYS``. The counts replace that space's
in the client's database (``rule_alert_counts``); whether the read worked is kept per space
(``rule_alert_reads``), so a key that can't read alerts is reported on the destination rather than
failing the sync. A count belongs to a rule by its Kibana id (``kibana.alert.rule.uuid``, the rule's
``raw_data.id``), which tells apart two rules sharing a rule id.
"""
from __future__ import annotations

import logging
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

COUNTS_DDL = """
    CREATE TABLE IF NOT EXISTS rule_alert_counts (
        siem_id   VARCHAR NOT NULL,
        space     VARCHAR NOT NULL,
        rule_uuid VARCHAR NOT NULL,     -- the rule's Kibana id (raw_data.id)
        rule_id   VARCHAR,
        day       DATE NOT NULL,        -- UTC
        status    VARCHAR NOT NULL,     -- open, acknowledged, closed
        alerts    INTEGER NOT NULL,
        PRIMARY KEY (siem_id, space, rule_uuid, day, status)
    )
"""
READS_DDL = """
    CREATE TABLE IF NOT EXISTS rule_alert_reads (
        siem_id VARCHAR NOT NULL,
        space   VARCHAR NOT NULL,
        read_at TIMESTAMP NOT NULL,
        ok      BOOLEAN NOT NULL,
        error   VARCHAR,
        PRIMARY KEY (siem_id, space)
    )
"""

# What the client can set for Rule Monitoring (clients columns), and what applies when it hasn't: noisy
# and silent rules (#68, #69), how long an upstream update may wait unreviewed, and whether expired or
# changed validations are listed (0 off, #77), and how many exception items are too many (#75).
DEFAULTS = {"noisy_per_day": 100, "noisy_share_pct": 50, "silent_enabled_days": 30, "silent_days": 90,
            "upstream_pending_days": 30, "validation_stale": 0, "exceptions_many": 10}
STATUSES = ("open", "acknowledged", "closed")


def today() -> date:
    """The day alerts are counted to: UTC, as their days are."""
    return datetime.now(timezone.utc).date()


def thresholds(db: Any, client_id: Optional[str]) -> Dict[str, int]:
    """The client's Rule Monitoring settings (``DEFAULTS``' keys), each its default where not set, or
    where the column isn't there yet (a database not yet upgraded)."""
    out = dict(DEFAULTS)
    if not (db and client_id):
        return out
    try:
        with db.get_shared_connection() as conn:
            cursor = conn.execute("SELECT * FROM clients WHERE id = ?", [client_id])
            row = cursor.fetchone()
            names = [d[0] for d in cursor.description or []]
    except Exception:   # noqa: BLE001 - no clients table to read
        return out
    for key, value in zip(names, row or ()):
        if key in DEFAULTS and value:
            out[key] = int(value)
    return out


def _tables(conn) -> set:
    return {r[0] for r in conn.execute("SELECT table_name FROM duckdb_tables() WHERE database_name = current_database() "
                                       "AND table_name IN ('rule_alert_counts', 'rule_alert_reads')").fetchall()}


def store(conn, siem_id: str, space: str, result: Dict[str, Any], now: Optional[datetime] = None) -> int:
    """Keep what one space's alert read found (``fetch_alert_counts``): its counts in place of the
    space's last ones, and whether it worked. A failed read keeps the last counts. Returns how many
    alerts were counted."""
    conn.execute(COUNTS_DDL)
    conn.execute(READS_DDL)
    conn.execute("INSERT INTO rule_alert_reads VALUES (?, ?, ?, ?, ?) ON CONFLICT (siem_id, space) DO UPDATE SET "
                 "read_at = EXCLUDED.read_at, ok = EXCLUDED.ok, error = EXCLUDED.error",
                 [siem_id, space, now or datetime.now(), bool(result.get("ok")), None if result.get("ok") else result.get("error")])
    if not result.get("ok"):
        return 0
    merged: Dict[Tuple[str, str, str], List[Any]] = {}       # an alert with no status counts as open
    for uuid, rule_id, day, status, n in result["rows"]:
        if uuid and day and n:
            key = (uuid, day, status if status in STATUSES else "open")
            merged.setdefault(key, [rule_id or None, 0])[1] += int(n)
    conn.execute("DELETE FROM rule_alert_counts WHERE siem_id = ? AND space = ?", [siem_id, space])
    if merged:
        conn.executemany("INSERT INTO rule_alert_counts VALUES (?, ?, ?, ?, ?, ?, ?)",
                         [[siem_id, space, uuid, rid, day, status, n] for (uuid, day, status), (rid, n) in merged.items()])
    return sum(n for _rid, n in merged.values())


def reads(conn) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """Each space's last alert read: ``{(siem_id, space): {ok, error, read_at}}``."""
    if "rule_alert_reads" not in _tables(conn):
        return {}
    return {(r[0], r[1]): {"read_at": r[2], "ok": r[3], "error": r[4] or ""}
            for r in conn.execute("SELECT siem_id, space, read_at, ok, error FROM rule_alert_reads").fetchall()}


def daily(conn, scopes: Iterable[Tuple[str, str]]) -> Dict[Tuple[str, str, str], Dict[date, int]]:
    """Each rule's alerts per day in ``scopes``, every status together: ``{(siem_id, space, rule uuid):
    {day: alerts}}``."""
    scopes = sorted(set(scopes))
    if not scopes or "rule_alert_counts" not in _tables(conn):
        return {}
    out: Dict[Tuple[str, str, str], Dict[date, int]] = {}
    for siem_id, space, uuid, day, n in conn.execute(
            "SELECT siem_id, space, rule_uuid, day, sum(alerts) FROM rule_alert_counts c WHERE EXISTS (SELECT 1 FROM "
            "(SELECT unnest(?::VARCHAR[]) AS s, unnest(?::VARCHAR[]) AS sp) x WHERE x.s = c.siem_id AND x.sp = c.space) "
            "GROUP BY 1, 2, 3, 4", [[s for s, _ in scopes], [sp for _, sp in scopes]]).fetchall():
        out.setdefault((siem_id, space, uuid), {})[day] = int(n)
    return out


def recent(counts: Dict[date, int], days: int, until: date) -> int:
    """Alerts in the ``days`` days up to ``until`` (that day included)."""
    since = until - timedelta(days=days - 1)
    return sum(n for d, n in counts.items() if since <= d <= until)


def per_rule(conn, keys: Iterable[Tuple[str, str, str]], days: int = 7,
             until: Optional[date] = None) -> Dict[Tuple[str, str, str], int]:
    """Alerts each rule (``(rule_id, siem_id, space)``) raised in the last ``days`` days, by its Kibana
    id: for Rule Health's Alerts column and its sort. A rule with none is left out."""
    keys = sorted(set(keys))
    if not keys or "rule_alert_counts" not in _tables(conn):
        return {}
    since = (until or today()) - timedelta(days=days - 1)
    rows = conn.execute(
        "SELECT d.rule_id, d.siem_id, d.space, sum(c.alerts) FROM detection_rules d "
        "JOIN rule_alert_counts c ON c.siem_id = d.siem_id AND c.space = d.space "
        "AND c.rule_uuid = json_extract_string(d.raw_data, '$.id') WHERE c.day >= ? AND EXISTS (SELECT 1 FROM "
        "(SELECT unnest(?::VARCHAR[]) AS k, unnest(?::VARCHAR[]) AS s, unnest(?::VARCHAR[]) AS sp) x "
        "WHERE x.k = d.rule_id AND x.s = d.siem_id AND x.sp = d.space) GROUP BY 1, 2, 3",
        [since, [k[0] for k in keys], [k[1] for k in keys], [k[2] for k in keys]]).fetchall()
    return {(r[0], r[1], r[2]): int(r[3]) for r in rows}


def for_rule(conn, siem_id: str, space: str, uuid: str, days: int = 30,
             until: Optional[date] = None) -> Optional[Dict[str, Any]]:
    """What the rule window's Alerts section shows: each of the last ``days`` days' alerts (``per_day``,
    oldest first, days with none included), the alerts of those days by status, the last
    ``ALERT_DAYS``' total and newest day, and when the space's alerts were last read. None when its
    space's alerts were never read."""
    from app.elastic_helper import ALERT_DAYS
    read = reads(conn).get((siem_id, space))
    if not read:
        return None
    until = until or today()
    since = until - timedelta(days=days - 1)
    rows = conn.execute("SELECT day, status, sum(alerts) FROM rule_alert_counts WHERE siem_id = ? AND space = ? "
                        "AND rule_uuid = ? GROUP BY 1, 2", [siem_id, space, uuid or ""]).fetchall() \
        if "rule_alert_counts" in _tables(conn) else []
    by_day: Dict[date, int] = {}
    by_status = {s: 0 for s in STATUSES}
    for day, status, n in rows:
        by_day[day] = by_day.get(day, 0) + int(n)
        if since <= day <= until:
            by_status[status if status in by_status else "open"] += int(n)
    return {"per_day": [(since + timedelta(days=i), by_day.get(since + timedelta(days=i), 0)) for i in range(days)],
            "by_status": by_status, "days": days, "total": sum(by_day.values()), "total_days": ALERT_DAYS,
            "last_day": max(by_day) if by_day else None, "read": read}
