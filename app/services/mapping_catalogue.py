"""Persisted field catalogue: what each SIEM's index patterns actually map.

Checking a rule's fields used to mean asking Elasticsearch about the newest
matching index on every sync. The catalogue stores the answer once per
(SIEM, index pattern) in the shared database, so:

* a normal sync makes no mapping calls for patterns it already knows;
* a pattern is fetched only when it is new, older than ``TTL_S``, or an
  operator asks for a refresh;
* the answer covers every index the pattern matches (``_field_caps``), not just
  the newest one, and includes whether each field is searchable / aggregatable;
* a failed fetch never overwrites a good entry, and a pattern that could not be
  checked is "unknown" (left out of scoring), never "missing".

Scoping is per SIEM (CLAUDE.md section 8): two SIEMs can hold the same pattern
name with different mappings. Spaces do not matter, indexes are not space-scoped.
"""
from __future__ import annotations

import hashlib
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from app.scoring import FOUND, MISSING, UNKNOWN

logger = logging.getLogger(__name__)

TTL_S = 24 * 3600

OK, NO_INDICES = "ok", "no_indices"

# Compact per-field record: [type, aggregatable, searchable, type_conflict]
Fields = Dict[str, List[Any]]
Fetcher = Callable[[str], Tuple[str, Any]]   # pattern -> ("ok", Fields) | ("no_indices", {}) | ("error", message)


class Entry:
    __slots__ = ("status", "fields", "fetched_at", "last_error")

    def __init__(self, status: str, fields: Fields, fetched_at: Optional[datetime], last_error: str = ""):
        self.status, self.fields, self.fetched_at, self.last_error = status, fields, fetched_at, last_error


class MappingCatalogue:
    """Field catalogue for one SIEM. ``db=None`` keeps everything in memory (scripts, tests)."""

    def __init__(self, db: Any, siem_id: str, ttl_s: int = TTL_S):
        self.db, self.siem_id, self.ttl_s = db, siem_id, ttl_s
        self._entries: Dict[str, Entry] = {}

    # ── persistence ──────────────────────────────────────────────────────
    def _load(self, patterns: List[str]) -> None:
        if not self.db or not patterns:
            return
        marks = ",".join("?" * len(patterns))
        with self.db.get_shared_connection() as conn:
            rows = conn.execute(
                "SELECT pattern, status, fields_json, fetched_at, last_error FROM siem_field_catalogue "
                f"WHERE siem_id = ? AND pattern IN ({marks})",
                [self.siem_id, *patterns],
            ).fetchall()
        for pattern, status, fields_json, fetched_at, last_error in rows:
            try:
                fields = json.loads(fields_json) if fields_json else {}
            except ValueError:
                continue                                   # corrupt row: treat as never fetched
            self._entries[pattern] = Entry(status, fields, fetched_at, last_error or "")

    def _store(self, pattern: str, status: str, fields: Fields, now: datetime) -> None:
        if not self.db:
            return
        body = json.dumps(fields, separators=(",", ":"), sort_keys=True)
        with self.db.get_shared_connection() as conn:
            conn.execute(
                "INSERT INTO siem_field_catalogue "
                "(siem_id, pattern, status, fields_json, field_count, fingerprint, fetched_at, last_error) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, NULL) "
                "ON CONFLICT (siem_id, pattern) DO UPDATE SET status = EXCLUDED.status, "
                "fields_json = EXCLUDED.fields_json, field_count = EXCLUDED.field_count, "
                "fingerprint = EXCLUDED.fingerprint, fetched_at = EXCLUDED.fetched_at, last_error = NULL",
                [self.siem_id, pattern, status, body, len(fields), hashlib.sha1(body.encode()).hexdigest(), now],
            )

    def _record_error(self, pattern: str, message: str) -> None:
        if not self.db or pattern not in self._entries:
            return
        with self.db.get_shared_connection() as conn:
            conn.execute(
                "UPDATE siem_field_catalogue SET last_error = ? WHERE siem_id = ? AND pattern = ?",
                [message[:300], self.siem_id, pattern],
            )

    # ── refresh policy ───────────────────────────────────────────────────
    def _is_fresh(self, pattern: str, now: datetime) -> bool:
        entry = self._entries.get(pattern)
        return bool(entry and entry.fetched_at and now - entry.fetched_at < timedelta(seconds=self.ttl_s))

    def ensure(self, patterns: Iterable[str], fetch: Fetcher, force: bool = False, workers: int = 20) -> Dict[str, int]:
        """Make sure every pattern has a usable entry, fetching only what is new, stale or forced."""
        wanted = sorted({p for p in patterns if p})
        self._load([p for p in wanted if p not in self._entries])
        now = datetime.now()
        todo = [p for p in wanted if force or not self._is_fresh(p, now)]
        stats = {"patterns": len(wanted), "cached": len(wanted) - len(todo), "refreshed": 0, "failed": 0}
        if not todo:
            return stats

        with ThreadPoolExecutor(max_workers=min(workers, len(todo))) as pool:
            results = list(pool.map(lambda p: (p, *self._safe_fetch(fetch, p)), todo))
        for pattern, status, payload in results:
            if status == "error":
                stats["failed"] += 1
                self._record_error(pattern, str(payload))
                logger.warning("Mapping catalogue: could not fetch %r for SIEM %s: %s; keeping %s",
                               pattern, self.siem_id, payload,
                               "the previous entry" if pattern in self._entries else "no entry (fields unknown)")
                continue
            previous = self._entries.get(pattern)
            self._store(pattern, status, payload, now)
            self._entries[pattern] = Entry(status, payload, now)
            stats["refreshed"] += 1
            if previous and previous.status == OK:
                self._log_changes(pattern, previous.fields, payload)
        return stats

    @staticmethod
    def _safe_fetch(fetch: Fetcher, pattern: str) -> Tuple[str, Any]:
        try:
            return fetch(pattern)
        except Exception as exc:   # noqa: BLE001 - one bad pattern must not sink the sync
            return "error", f"{type(exc).__name__}: {exc}"

    def _log_changes(self, pattern: str, before: Fields, after: Fields) -> None:
        added, removed = set(after) - set(before), set(before) - set(after)
        retyped = [f for f in set(before) & set(after) if before[f][0] != after[f][0]]
        if added or removed or retyped:
            logger.info("Mapping catalogue: %r on SIEM %s changed: +%d fields, -%d fields, %d type changes",
                        pattern, self.siem_id, len(added), len(removed), len(retyped))

    # ── answers ──────────────────────────────────────────────────────────
    def entry(self, pattern: str) -> Optional[Entry]:
        return self._entries.get(pattern)

    def check(self, indices: Iterable[str], fields: Iterable[str]) -> Tuple[Dict[str, Dict[str, Any]], List[Tuple[str, str, str, str]]]:
        """Facts per field (see ``app.scoring``) and the per-index rows shown in the Rule modal.

        A field is FOUND when any of the rule's indexes has it, MISSING when the
        indexes were checked and none does, UNKNOWN when no index could be checked.
        """
        indices = [i for i in indices if i]
        rows: List[Tuple[str, str, str, str]] = []
        facts: Dict[str, Dict[str, Any]] = {}
        for field in sorted(fields):
            fact = {"state": UNKNOWN, "type": "", "aggregatable": None, "no_index": False}
            checked = empty = 0
            for idx in indices:
                entry = self._entries.get(idx)
                if entry is None:
                    rows.append((idx, field, "?", "unknown"))
                    continue
                checked += 1
                info = entry.fields.get(field)
                if info is not None:
                    rows.append((idx, field, "Yes", str(info[0])))
                    if fact["state"] != FOUND:
                        fact.update(state=FOUND, type=str(info[0]), aggregatable=bool(info[1]))
                else:
                    empty += entry.status == NO_INDICES
                    rows.append((idx, field, "-", "no index" if entry.status == NO_INDICES else "missing"))
                    if fact["state"] == UNKNOWN:
                        fact["state"] = MISSING
            # Missing because every checked pattern matches no indices at all (not because the mapping lacks it).
            fact["no_index"] = fact["state"] == MISSING and empty == checked
            facts[field] = fact
        return facts, rows

    def describe(self, indices: Iterable[str]) -> Dict[str, Any]:
        """For the Rule modal: how fresh the mapping data behind a rule is."""
        self._load([i for i in indices if i and i not in self._entries])
        stamps = [e.fetched_at for i in indices if (e := self._entries.get(i)) and e.fetched_at]
        return {"patterns": len([i for i in indices if i]), "known": len(stamps),
                "oldest": min(stamps) if stamps else None}
