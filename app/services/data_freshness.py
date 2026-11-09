"""Is the data a rule searches arriving (Rule Monitoring)? The newest event in each index pattern
(#71, ``DataFreshness``), and whether recent events fill the fields rules match on (#72, ``FieldData``,
below).

An index pattern can match indexes and still leave a rule blind: the source behind it stopped sending,
so the rule finds nothing and nothing reports an error. At each sync TIDE asks each SIEM for the newest
event of every index pattern its rules search, by each timestamp field they search by (``@timestamp``,
or a rule's timestamp override), with one ``_msearch`` (``elastic_helper.fetch_newest_events``). The
answer is kept per (SIEM, pattern, field) in the shared database, as the field catalogue keeps mappings:
indexes belong to the SIEM, not to a space or a client.

A pattern is quiet when its newest event was longer before TIDE looked than the client expects new data:
every ``DEFAULT_HOURS`` unless the client sets its own (``clients.data_window_hours``), or the pattern
has a window of its own (``data_windows``, in the client's database), which can also say no new data is
expected (a retired source). A failed check keeps the last answer; a pattern never checked, or matching
no index (the field catalogue's ``no_index``), is never called quiet.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

OK, NO_EVENTS, NO_INDICES = "ok", "no_events", "no_indices"
DEFAULT_HOURS = 24
NOT_EXPECTED = 0            # a pattern's window: no new data expected (a retired source)
MAX_HOURS = 24 * 366

Item = Tuple[str, str]                                  # (index pattern, timestamp field)
Fetcher = Callable[[List[Item]], List[Tuple[str, Any]]]


@dataclass(frozen=True)
class Entry:
    status: str                       # OK, NO_EVENTS or NO_INDICES
    newest_at: Optional[datetime]     # TIDE's local time, as every time it keeps
    checked_at: Optional[datetime]
    last_error: str = ""


class _Asker:
    """What each check of one SIEM's data shares: asking it, keeping what failed apart, and saving.
    ``db=None`` keeps the answers in memory (tests). ``error``: why the last ``ensure`` got no answer
    at all, or couldn't save them, for the sync's failed steps. ``doing`` names what is asked."""
    doing = ""

    def __init__(self, db: Any, siem_id: str):
        self.db, self.siem_id = db, siem_id
        self._entries: Dict[Any, Any] = {}
        self.error: Optional[Exception] = None

    def _ask(self, items: list, fetch: Callable[[list], list], statuses: Tuple[str, ...]):
        """``fetch``'s answer for each of ``items``: ``(answered [(item, status, value)], failed [(item,
        why)])``. A fetch that raises fails every item."""
        try:
            answers = list(fetch(items))
        except Exception as exc:   # noqa: BLE001 - the sync goes on without it
            answers = [("error", f"{type(exc).__name__}: {exc}")] * len(items)
        answered, failed = [], []
        for item, (status, value) in zip(items, answers + [("error", "no answer")] * len(items)):
            if status in statuses:
                answered.append((item, status, value))
            else:
                failed.append((item, str(value or "")[:300]))
        if failed:
            logger.warning("Could not %s: %d of %d searches on SIEM %s failed, first %s: %s",
                           self.doing, len(failed), len(items), self.siem_id, failed[0][0], failed[0][1])
        if failed and not answered:
            self.error = RuntimeError(f"Could not {self.doing}: {failed[0][1]}")
        return answered, failed

    def _save(self, store: Callable[..., None], *args) -> None:
        if not self.db:
            return
        try:
            store(*args)
        except Exception as exc:   # noqa: BLE001 - reported as a failed step of the sync
            logger.warning("Could not save what was found (%s) on SIEM %s", self.doing, self.siem_id, exc_info=True)
            self.error = exc


class DataFreshness(_Asker):
    """The newest events of one SIEM's index patterns."""
    doing = "read the newest events of any index pattern"

    def ensure(self, wanted: Dict[str, Iterable[str]], fetch: Fetcher) -> Dict[str, int]:
        """Ask for the newest event of each pattern by each of its fields (``wanted``), and keep the
        answers. A search that fails keeps the pattern's last answer, noting the error."""
        from app.services.database import utc_to_local
        items = sorted({(p, f) for p, fields in wanted.items() if p for f in fields if f})
        if not items:
            return {"searches": 0, "checked": 0, "failed": 0}
        answered, failed = self._ask(items, fetch, (OK, NO_EVENTS, NO_INDICES))
        now = datetime.now()
        rows = []
        for (pattern, field), status, value in answered:
            newest = utc_to_local(value) if status == OK else None
            rows.append((pattern, field, status, newest))
            self._entries[(pattern, field)] = Entry(status, newest, now)
        self._save(self._store, rows, [(p, f, why) for (p, f), why in failed], now)
        return {"searches": len(items), "checked": len(answered), "failed": len(failed)}

    def _store(self, answered, failed, now: datetime) -> None:
        with self.db.get_shared_connection() as conn:
            if answered:
                conn.executemany(
                    "INSERT INTO siem_data_freshness (siem_id, pattern, field, status, newest_at, checked_at, last_error) "
                    "VALUES (?, ?, ?, ?, ?, ?, NULL) ON CONFLICT (siem_id, pattern, field) DO UPDATE SET "
                    "status = EXCLUDED.status, newest_at = EXCLUDED.newest_at, checked_at = EXCLUDED.checked_at, "
                    "last_error = NULL",
                    [[self.siem_id, p, f, s, n, now] for p, f, s, n in answered])
            if failed:
                conn.executemany("UPDATE siem_data_freshness SET last_error = ? WHERE siem_id = ? AND pattern = ? AND field = ?",
                                 [[e, self.siem_id, p, f] for p, f, e in failed])

    def entries(self, patterns: Iterable[str]) -> Dict[Item, Entry]:
        """What is known of ``patterns``, by (pattern, field); one never checked is left out."""
        patterns = sorted({p for p in patterns if p})
        out = {k: e for k, e in self._entries.items() if k[0] in patterns}
        if not self.db or not patterns:
            return out
        with self.db.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT pattern, field, status, newest_at, checked_at, last_error FROM siem_data_freshness "
                f"WHERE siem_id = ? AND pattern IN ({','.join('?' * len(patterns))})", [self.siem_id, *patterns]).fetchall()
        for pattern, field, status, newest, checked, error in rows:
            out.setdefault((pattern, field), Entry(status, newest, checked, error or ""))
        return out


# ── how long without new data is too long ────────────────────────────────

def default_hours(db: Any, client_id: Optional[str]) -> int:
    """How often the client expects new data in an index pattern, in hours."""
    if not (db and client_id):
        return DEFAULT_HOURS
    try:
        with db.get_shared_connection() as conn:
            row = conn.execute("SELECT data_window_hours FROM clients WHERE id = ?", [client_id]).fetchone()
    except Exception:   # noqa: BLE001 - before the column exists
        return DEFAULT_HOURS
    return int(row[0]) if row and row[0] else DEFAULT_HOURS


def hours_text(hours: int) -> str:
    """A window as the page says it: '24 hours', '7 days', '1 hour'."""
    if hours >= 48 and hours % 24 == 0:
        return f"{hours // 24} days"
    return "1 hour" if hours == 1 else f"{hours} hours"


WINDOW_DDL = """
    CREATE TABLE IF NOT EXISTS data_windows (
        siem_id VARCHAR NOT NULL,
        pattern VARCHAR NOT NULL,
        hours   INTEGER NOT NULL,     -- new events expected every this many hours; 0: none expected (retired)
        note    VARCHAR,
        set_by  VARCHAR,
        set_at  TIMESTAMP,
        PRIMARY KEY (siem_id, pattern)
    )
"""


def windows(conn) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """The index patterns with a window of their own in this client's database, by (siem_id, pattern).
    The table is looked for first, so a client with none never fails a statement (and the transaction
    it may be in)."""
    if not conn.execute("SELECT 1 FROM duckdb_tables() WHERE table_name = 'data_windows' "
                        "AND database_name = current_database()").fetchone():
        return {}
    rows = conn.execute("SELECT siem_id, pattern, hours, note, set_by, set_at FROM data_windows").fetchall()
    return {(r[0], r[1]): {"hours": int(r[2]), "note": r[3] or "", "by": r[4] or "", "at": r[5]} for r in rows}


def set_window(conn, siem_ids: Iterable[str], pattern: str, hours: Optional[int], note: str, actor: str,
               now: Optional[datetime] = None) -> None:
    """Give ``pattern`` on each of ``siem_ids`` its own window (``NOT_EXPECTED``: no new data expected),
    or, with ``hours`` None, take it away so the client's applies."""
    conn.execute(WINDOW_DDL)
    for siem_id in siem_ids:
        conn.execute("DELETE FROM data_windows WHERE siem_id = ? AND pattern = ?", [siem_id, pattern])
        if hours is not None:
            conn.execute("INSERT INTO data_windows VALUES (?, ?, ?, ?, ?, ?)",
                         [siem_id, pattern, int(hours), (note or "").strip()[:1000] or None, actor, now or datetime.now()])


def quiet(entry: Optional[Entry], hours: int) -> Optional[bool]:
    """Whether ``entry`` shows its pattern has gone quiet for a window of ``hours``: True when it had
    no event at all, or its newest was longer before the check than the window; None when it can't
    say (never checked, no index, or no new data expected)."""
    if entry is None or hours == NOT_EXPECTED or entry.status not in (OK, NO_EVENTS):
        return None
    if entry.status == NO_EVENTS:
        return True
    return bool(entry.newest_at and entry.checked_at and entry.checked_at - entry.newest_at > timedelta(hours=hours))


def searched_by(rule: Dict[str, Any]) -> Tuple[str, bool]:
    """The timestamp field a rule searches by, and whether Kibana falls back to @timestamp for events
    without it."""
    override = str(rule.get("timestamp_override") or "").strip()
    if not override or override == "-" or override == "@timestamp":
        return "@timestamp", False
    return override, not rule.get("timestamp_override_fallback_disabled")


def entry_for(entries: Dict[Item, Entry], pattern: str, field: str, fallback: bool) -> Optional[Entry]:
    """What a rule searching ``pattern`` by ``field`` sees: by @timestamp instead where its events lack
    the override and Kibana falls back to it."""
    entry = entries.get((pattern, field))
    if fallback and (entry is None or entry.status == NO_EVENTS):
        return entries.get((pattern, "@timestamp")) or entry
    return entry


def recent_events(entry: Optional[Entry], days: int) -> bool:
    """Whether ``entry`` saw an event in its pattern within ``days`` before TIDE looked."""
    return bool(entry and entry.status == OK and entry.newest_at and entry.checked_at
                and entry.checked_at - entry.newest_at <= timedelta(days=days))


# ── fields recent events don't fill (#72) ────────────────────────────────
# Index templates map nearly every field a source might send, so a field a rule matches on is rarely
# missing from the mappings; what goes wrong is a mapped field no event fills, and the rule can never
# match on it. For each field enabled rules match on that their own index patterns map, TIDE asks
# whether any event of the last FIELD_DATA_DAYS has a value in it (elastic_helper.fetch_field_data),
# keyed by the timestamp field the rules search by. As the field catalogue: asked again after a day,
# or when forced (Sync this rule, a full mapping sync); a failed search keeps the last answer.

HAS_DATA, EMPTY = "has_data", "empty"
FIELD_TTL = timedelta(hours=24)

FieldItem = Tuple[str, str, str]          # (index pattern, timestamp field, field)


@dataclass(frozen=True)
class FieldEntry:
    status: str                       # HAS_DATA, EMPTY or NO_INDICES
    checked_at: Optional[datetime]
    last_error: str = ""


class FieldData(_Asker):
    """Whether recent events fill each field of one SIEM's index patterns that enabled rules match on."""
    doing = "check whether any field has data"

    def ensure(self, wanted: Dict[Tuple[str, str], Iterable[str]], fetch: Callable[[List[FieldItem]], List[Tuple[str, Any]]],
               force: bool = False) -> Dict[str, int]:
        """Ask about each (pattern, timestamp field) and field in ``wanted`` not asked about in the last
        day (all of them with ``force``), and keep the answers."""
        items = sorted({(p, ts, f) for (p, ts), fields in wanted.items() if p and ts for f in fields if f})
        known = {} if force else self.entries({p for p, _t, _f in items})
        now = datetime.now()
        todo = [i for i in items if force or not (known.get(i) and known[i].checked_at
                                                  and now - known[i].checked_at < FIELD_TTL)]
        stats = {"searches": len(items), "cached": len(items) - len(todo), "checked": 0, "failed": 0}
        if not todo:
            return stats
        answered, failed = self._ask(todo, fetch, (HAS_DATA, EMPTY, NO_INDICES))
        for item, status, _value in answered:
            self._entries[item] = FieldEntry(status, now)
        self._save(self._store, [(*item, status) for item, status, _v in answered],
                   [(*item, why) for item, why in failed], now)
        stats["checked"], stats["failed"] = len(answered), len(failed)
        return stats

    def _store(self, answered, failed, now: datetime) -> None:
        with self.db.get_shared_connection() as conn:
            if answered:
                conn.executemany(
                    "INSERT INTO siem_field_data (siem_id, pattern, ts_field, field, status, checked_at, last_error) "
                    "VALUES (?, ?, ?, ?, ?, ?, NULL) ON CONFLICT (siem_id, pattern, ts_field, field) DO UPDATE SET "
                    "status = EXCLUDED.status, checked_at = EXCLUDED.checked_at, last_error = NULL",
                    [[self.siem_id, p, t, f, s, now] for p, t, f, s in answered])
            if failed:
                conn.executemany("UPDATE siem_field_data SET last_error = ? WHERE siem_id = ? AND pattern = ? "
                                 "AND ts_field = ? AND field = ?", [[e, self.siem_id, p, t, f] for p, t, f, e in failed])

    def entries(self, patterns: Iterable[str]) -> Dict[FieldItem, FieldEntry]:
        """What is known of the fields of ``patterns``; one never checked is left out."""
        patterns = sorted({p for p in patterns if p})
        out = {k: e for k, e in self._entries.items() if k[0] in patterns}
        if not self.db or not patterns:
            return out
        with self.db.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT pattern, ts_field, field, status, checked_at, last_error FROM siem_field_data "
                f"WHERE siem_id = ? AND pattern IN ({','.join('?' * len(patterns))})", [self.siem_id, *patterns]).fetchall()
        for pattern, ts, field, status, checked, error in rows:
            out.setdefault((pattern, ts, field), FieldEntry(status, checked, error or ""))
        return out


# ── how late events arrive (#73) ─────────────────────────────────────────
# A rule searches its interval plus some additional look-back, by when each event happened
# (@timestamp). An event reaching Elasticsearch later than that margin is never searched by any run,
# and nothing says so. For each index pattern enabled rules search by @timestamp, TIDE measures how
# late events arrive at each sync: the 95th percentile of event.ingested minus @timestamp over the
# last hour's arrivals (elastic_helper.fetch_ingest_delay). Rules searching by event.ingested aren't
# affected: a late event is found by the next run.

NO_SAMPLE = "no_sample"
INGEST_MIN_SAMPLE = 20      # events measured before a pattern's delay is judged


@dataclass(frozen=True)
class DelayEntry:
    status: str                       # OK, NO_SAMPLE or NO_INDICES
    p95_ms: Optional[int]
    sample: int
    checked_at: Optional[datetime]
    last_error: str = ""


class IngestDelay(_Asker):
    """How late events reach each of one SIEM's index patterns that enabled rules search by @timestamp."""
    doing = "measure how late events arrive in any index pattern"

    def ensure(self, patterns: Iterable[str], fetch: Callable[[List[str]], List[Tuple[str, Any]]]) -> Dict[str, int]:
        """Measure each of ``patterns``, and keep the answers. A search that fails keeps the last one."""
        items = sorted({p for p in patterns if p})
        if not items:
            return {"searches": 0, "checked": 0, "failed": 0}
        answered, failed = self._ask(items, fetch, (OK, NO_SAMPLE, NO_INDICES))
        now = datetime.now()
        rows = []
        for pattern, status, value in answered:
            p95, sample = value if status == OK else (None, 0)
            rows.append((pattern, status, p95, sample))
            self._entries[pattern] = DelayEntry(status, p95, sample, now)
        self._save(self._store, rows, failed, now)
        return {"searches": len(items), "checked": len(answered), "failed": len(failed)}

    def _store(self, answered, failed, now: datetime) -> None:
        with self.db.get_shared_connection() as conn:
            if answered:
                conn.executemany(
                    "INSERT INTO siem_ingest_delay (siem_id, pattern, status, p95_ms, sample, checked_at, last_error) "
                    "VALUES (?, ?, ?, ?, ?, ?, NULL) ON CONFLICT (siem_id, pattern) DO UPDATE SET status = EXCLUDED.status, "
                    "p95_ms = EXCLUDED.p95_ms, sample = EXCLUDED.sample, checked_at = EXCLUDED.checked_at, last_error = NULL",
                    [[self.siem_id, p, s, ms, n, now] for p, s, ms, n in answered])
            if failed:
                conn.executemany("UPDATE siem_ingest_delay SET last_error = ? WHERE siem_id = ? AND pattern = ?",
                                 [[why, self.siem_id, p] for p, why in failed])

    def entries(self, patterns: Iterable[str]) -> Dict[str, DelayEntry]:
        """What is known of ``patterns``; one never measured is left out."""
        patterns = sorted({p for p in patterns if p})
        out = {k: e for k, e in self._entries.items() if k in patterns}
        if not self.db or not patterns:
            return out
        with self.db.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT pattern, status, p95_ms, sample, checked_at, last_error FROM siem_ingest_delay "
                f"WHERE siem_id = ? AND pattern IN ({','.join('?' * len(patterns))})", [self.siem_id, *patterns]).fetchall()
        for pattern, status, p95, sample, checked, error in rows:
            out.setdefault(pattern, DelayEntry(status, p95, int(sample or 0), checked, error or ""))
        return out
