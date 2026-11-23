"""Rule exceptions (Rule Monitoring, #75): the items of the exception lists each rule uses, read at
each sync, kept per destination, and what changed since the last read, recorded in the history of
every rule using the list ("Exception added", "removed", "changed", with who did it in Kibana).

A rule's ``exceptions_list`` names its own list and any shared ones; each is read once per space
per sync (``elastic_helper.fetch_exception_items``), with the space's lists' own details
(``fetch_exception_lists``). A list Kibana didn't give in full keeps its last items. An item past its
``expire_time`` no longer applies, so it isn't counted. Each item and list is also kept as Kibana gave
it (``raw``, ``details``), for the GitLab backup (``kept_lists``, #90).
"""
import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

ITEMS_DDL = """
    CREATE TABLE IF NOT EXISTS rule_exception_items (
        siem_id        VARCHAR NOT NULL,
        space          VARCHAR NOT NULL,
        list_id        VARCHAR NOT NULL,
        namespace_type VARCHAR,
        item_id        VARCHAR NOT NULL,
        name           VARCHAR,
        entries        JSON,
        fingerprint    VARCHAR,
        created_by     VARCHAR,
        created_at     TIMESTAMP,          -- UTC, as Kibana gives it
        updated_by     VARCHAR,
        updated_at     TIMESTAMP,
        expire_time    TIMESTAMP,
        raw            JSON,               -- the item as Kibana gave it
        PRIMARY KEY (siem_id, space, list_id, item_id)
    )
"""
READS_DDL = """
    CREATE TABLE IF NOT EXISTS rule_exception_reads (
        siem_id        VARCHAR NOT NULL,
        space          VARCHAR NOT NULL,
        list_id        VARCHAR NOT NULL,
        read_at        TIMESTAMP NOT NULL,
        ok             BOOLEAN NOT NULL,   -- ever read in full
        namespace_type VARCHAR,
        details        JSON,               -- the list itself, without its items, as Kibana last gave it
        last_ok        BOOLEAN,            -- the last read was in full
        PRIMARY KEY (siem_id, space, list_id)
    )
"""
# Columns added after the tables were first made (6.5.0, #90).
_ADDED = (("rule_exception_items", "raw", "JSON"), ("rule_exception_reads", "namespace_type", "VARCHAR"),
          ("rule_exception_reads", "details", "JSON"), ("rule_exception_reads", "last_ok", "BOOLEAN"))
Key = Tuple[str, str]          # (list_id, namespace_type)
Change = Tuple[str, str, Dict[str, Any], Optional[Dict[str, Any]]]   # (list_id, kind, item, the item before)


def _ensure(conn) -> None:
    conn.execute(ITEMS_DDL)
    conn.execute(READS_DDL)
    for table, column, kind in _ADDED:
        if column not in {r[0] for r in conn.execute(f"DESCRIBE {table}").fetchall()}:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")


def lists_of(exceptions_list) -> List[Key]:
    """The exception lists a rule uses, from its ``exceptions_list`` (a list, or its JSON)."""
    if isinstance(exceptions_list, str):
        try:
            exceptions_list = json.loads(exceptions_list)
        except ValueError:
            return []
    return [(str(e.get("list_id")), str(e.get("namespace_type") or "single"))
            for e in exceptions_list or [] if isinstance(e, dict) and e.get("list_id")]


def space_lists(conn, siem_id: str, space: str) -> Set[Key]:
    """Every exception list the rules of one space use."""
    out: Set[Key] = set()
    for (text,) in conn.execute(
            "SELECT json_extract(raw_data, '$.exceptions_list')::VARCHAR FROM detection_rules "
            "WHERE siem_id = ? AND space = ? AND NOT COALESCE(deprecated, false)", [siem_id, space]).fetchall():
        out.update(lists_of(text))
    return out


def _utc(value) -> Optional[datetime]:
    """Kibana's ISO time as naive UTC."""
    if not value:
        return None
    try:
        when = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return when.astimezone(timezone.utc).replace(tzinfo=None) if when.tzinfo else when


def fingerprint(item: Dict[str, Any]) -> str:
    """What an item excepts, as a hash: its entries, operating systems and expiry (not its name)."""
    what = {"entries": item.get("entries") or [], "os_types": sorted(item.get("os_types") or []),
            "expire_time": item.get("expire_time")}
    return hashlib.sha1(json.dumps(what, sort_keys=True, default=str).encode(), usedforsecurity=False).hexdigest()[:16]  # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1 # a change fingerprint, not for security


def store(conn, siem_id: str, space: str, read: Dict[Key, Optional[List[Dict[str, Any]]]],
          now: Optional[datetime] = None, details: Optional[Dict[Key, Dict[str, Any]]] = None) -> List[Change]:
    """Keep what one space's lists hold (``read``: each list's items, or None when Kibana didn't give
    them all, which keeps the last), and each list's own details from ``details``
    (``fetch_exception_lists``; a list it lacks, or None, keeps its last). Returns what changed in lists
    read before: ``[(list_id, "added" | "removed" | "changed", item, item before or None)]``. A list's
    first read changes nothing."""
    _ensure(conn)
    now = now or datetime.now()
    changes: List[Change] = []
    for (list_id, ns), items in read.items():
        before_read = conn.execute("SELECT ok FROM rule_exception_reads WHERE siem_id = ? AND space = ? AND list_id = ?",
                                   [siem_id, space, list_id]).fetchone()
        about = (details or {}).get((list_id, ns))
        conn.execute("INSERT INTO rule_exception_reads (siem_id, space, list_id, read_at, ok, namespace_type, details, "
                     "last_ok) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (siem_id, space, list_id) "
                     "DO UPDATE SET read_at = EXCLUDED.read_at, ok = EXCLUDED.ok OR rule_exception_reads.ok, "
                     "namespace_type = EXCLUDED.namespace_type, "
                     "details = COALESCE(EXCLUDED.details, rule_exception_reads.details), last_ok = EXCLUDED.last_ok",
                     [siem_id, space, list_id, now, items is not None, ns,
                      json.dumps(about, default=str) if about else None, items is not None])
        if items is None:
            continue
        old = {r[0]: {"item_id": r[0], "name": r[1], "entries": json.loads(r[2] or "[]"), "fingerprint": r[3],
                      "created_by": r[4], "updated_by": r[5]}
               for r in conn.execute("SELECT item_id, name, entries::VARCHAR, fingerprint, created_by, updated_by "
                                     "FROM rule_exception_items WHERE siem_id = ? AND space = ? AND list_id = ?",
                                     [siem_id, space, list_id]).fetchall()}
        new = {str(i.get("item_id") or i.get("id")): i for i in items if i.get("item_id") or i.get("id")}
        if before_read and before_read[0]:
            for item_id, item in new.items():
                if item_id not in old:
                    changes.append((list_id, "added", item, None))
                elif old[item_id]["fingerprint"] != fingerprint(item):
                    changes.append((list_id, "changed", item, old[item_id]))
            changes += [(list_id, "removed", item, item) for item_id, item in old.items() if item_id not in new]
        conn.execute("DELETE FROM rule_exception_items WHERE siem_id = ? AND space = ? AND list_id = ?",
                     [siem_id, space, list_id])
        if new:
            conn.executemany(
                "INSERT INTO rule_exception_items (siem_id, space, list_id, namespace_type, item_id, name, entries, "
                "fingerprint, created_by, created_at, updated_by, updated_at, expire_time, raw) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [
                    [siem_id, space, list_id, ns, item_id, i.get("name") or "", json.dumps(i.get("entries") or []),
                     fingerprint(i), i.get("created_by") or "", _utc(i.get("created_at")), i.get("updated_by") or "",
                     _utc(i.get("updated_at")), _utc(i.get("expire_time")), json.dumps(i, default=str)]
                    for item_id, i in new.items()])
    return changes


def read_lists(db, client_id: str, siem_id: str, space: str, lists: Iterable[Key], kibana_url: str, api_key: str,
               users: Optional[Dict[str, List[str]]] = None) -> List[Change]:
    """Read ``lists`` in one space from Kibana, with the space's lists' details, keep them, and record
    what changed in the history of the rules using each (``users``, as ``record_changes`` takes it).
    Lists not named are left as they are, so a sync of one rule reads only its own. A full sync reads
    every list its space's rules use."""
    from app import elastic_helper
    lists = set(lists)
    failed: Dict[Key, Any] = {}
    read = elastic_helper.fetch_exception_items(kibana_url, api_key, space, lists, failures=failed) if lists else {}
    details = elastic_helper.fetch_exception_lists(kibana_url, api_key, space) if lists else None
    with db.get_connection() as conn:
        changes = store(conn, siem_id, space, read, details=details)
    record_changes(db, client_id, siem_id, space, changes, users)
    if failed:
        raise unread(space, failed)
    return changes


def unread(space: str, failed: Dict[Key, Any]):
    """The error for the lists Kibana didn't give (#116): which, and why, with the first one's code (S403
    when the key can't read them, …). Each keeps its last items; this says so, where a read used to be
    silent."""
    from app import elastic_helper
    from app.services import errors
    ids = sorted(list_id for list_id, _ns in failed)
    first = failed[min(failed)]
    named = ", ".join(ids[:3]) + (f" and {len(ids) - 3} more" if len(ids) > 3 else "")
    return elastic_helper.KibanaError(errors.Failure(
        first.code, f"Kibana didn't give {len(ids)} exception list{'s' if len(ids) != 1 else ''} in space "
                    f"'{space}' ({named}), which keep their last items: {errors.without_code(first, first.code)}"))


_DONE = {"added": "added", "removed": "removed", "changed": "changed"}


def list_users(rules) -> Dict[str, Dict[Key, List[str]]]:
    """Which rules use each list, from rules just read from Kibana (a frame, or records, with
    ``rule_id``, ``space_id`` and ``raw_data``): ``{space: {(list_id, namespace_type): [rule_id]}}``."""
    out: Dict[str, Dict[Key, List[str]]] = {}
    if rules is None:
        return out
    records = rules.to_dict("records") if hasattr(rules, "to_dict") else rules
    for r in records or []:
        raw = r.get("raw_data") if isinstance(r.get("raw_data"), dict) else {}
        for key in lists_of(raw.get("exceptions_list")):
            out.setdefault(str(r.get("space_id") or "default"), {}).setdefault(key, []).append(str(r.get("rule_id")))
    return out


def record_changes(db, client_id: str, siem_id: str, space: str, changes: List["Change"],
                   users: Optional[Dict[str, List[str]]] = None) -> int:
    """Each change, in the history of every rule in the space using its list (``exception_added``,
    ``exception_removed``, ``exception_changed``), by whoever Kibana says made it. ``users``: which rules
    use each list (``{list_id: [rule_id]}``, from the rules just read), else as TIDE has them. Returns
    how many."""
    if not changes:
        return 0
    if users is None:
        users = {}
        with db.get_connection() as conn:
            for rule_id, text in conn.execute(
                    "SELECT rule_id, json_extract(raw_data, '$.exceptions_list')::VARCHAR FROM detection_rules "
                    "WHERE siem_id = ? AND space = ? AND NOT COALESCE(deprecated, false)", [siem_id, space]).fetchall():
                for list_id, _ns in lists_of(text):
                    users.setdefault(list_id, []).append(rule_id)
    n = 0
    for list_id, kind, item, before in changes:
        name = item.get("name") or "unnamed"
        by = (item.get("created_by") if kind == "added" else item.get("updated_by")) or ""
        what = item_text(item)
        # As the rule window's History shows an edit: the exception before and after, in words.
        diff = {"field": f'Exception "{name}"', "before": item_text(before) if before else "-",
                "after": "-" if kind == "removed" else what}
        for rule_id in users.get(list_id, []):
            try:
                db.record_rule_history(rule_id=rule_id, siem_id=siem_id, space=space, client_id=client_id,
                                       action=f"exception_{kind}", actor_name=by or "elastic",
                                       detail={"message": f'Exception "{name}" {_DONE[kind]}' + (f": {what}." if what else "."),
                                               "exception": name, "list_id": list_id, "changed_fields": "exceptions",
                                               "field_diffs": [diff],
                                               "item_id": str(item.get("item_id") or item.get("id") or "")})
                n += 1
            except Exception:
                logger.warning("Could not record an exception change on rule %s", rule_id, exc_info=True)
    return n


# ── what an item says, and whether it is broad ───────────────────────────

_OPS = {"match": "is", "match_any": "is one of", "wildcard": "matches", "exists": "exists", "list": "is in list"}


def entry_text(entry: Dict[str, Any]) -> str:
    """One condition of an item, in words: 'process.name is "x.exe"', 'user.name is not one of a, b'."""
    kind, field = entry.get("type"), entry.get("field") or "?"
    negated = entry.get("operator") == "excluded"
    if kind == "nested":
        return f"{field} {{{' and '.join(entry_text(e) for e in entry.get('entries') or [])}}}"
    if kind == "exists":
        return f"{field} {'does not exist' if negated else 'exists'}"
    op = _OPS.get(kind, kind or "is")
    if negated:
        op = {"is": "is not", "is one of": "is not one of", "matches": "does not match", "is in list": "is not in list"}.get(op, f"not {op}")
    value = entry.get("value")
    if kind == "list":
        value = (entry.get("list") or {}).get("id") or value
    if isinstance(value, list):
        shown = ", ".join(f'"{v}"' for v in value[:5]) + (f" and {len(value) - 5} more" if len(value) > 5 else "")
    else:
        shown = f'"{value}"'
    return f"{field} {op} {shown}"


def item_text(item: Dict[str, Any]) -> str:
    """Every condition of an item: an event is excepted when all of them hold."""
    return " and ".join(entry_text(e) for e in item.get("entries") or [])


_WILDCARD_ONLY = re.compile(r"^[\s*?]+$")


def _broad_entry(entry: Dict[str, Any]) -> bool:
    if entry.get("type") == "nested":
        return bool(entry.get("entries")) and all(_broad_entry(e) for e in entry["entries"])
    return (entry.get("type") == "wildcard" and entry.get("operator", "included") == "included"
            and bool(_WILDCARD_ONLY.match(str(entry.get("value") or ""))))


def broad(item: Dict[str, Any]) -> bool:
    """An item whose every condition is a wildcard-only value (``process.name matches "*"``): it excepts
    every event that has those fields. An item's conditions must all hold, so one such condition
    beside a specific one isn't broad."""
    entries = item.get("entries") or []
    return bool(entries) and all(_broad_entry(e) for e in entries)


def active(item: Dict[str, Any], now_utc: Optional[datetime] = None) -> bool:
    """Whether an item still applies: not past its expiry."""
    expires = item.get("expire_time")
    return not expires or expires > (now_utc or datetime.now(timezone.utc).replace(tzinfo=None))


# ── read back ────────────────────────────────────────────────────────────

def items_by_list(conn, siem_id: str) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
    """A SIEM's kept items, ``{(space, list_id): [item]}``, each with its entries and times (UTC)."""
    try:
        rows = conn.execute("SELECT space, list_id, item_id, name, entries::VARCHAR, created_by, created_at, updated_by, "
                            "updated_at, expire_time FROM rule_exception_items WHERE siem_id = ? ORDER BY name",
                            [siem_id]).fetchall()
    except Exception:          # never read in this tenant yet
        return {}
    out: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for space, list_id, item_id, name, entries, cby, cat, uby, uat, exp in rows:
        out.setdefault((space, list_id), []).append({
            "item_id": item_id, "name": name, "entries": json.loads(entries or "[]"), "created_by": cby,
            "created_at": cat, "updated_by": uby, "updated_at": uat, "expire_time": exp})
    return out


def kept_lists(conn, siem_id: str, space: str) -> Dict[str, Tuple[Dict[str, Any], List[Dict[str, Any]]]]:
    """One space's lists as Kibana last gave them in full, for the GitLab backup (#90):
    ``{list_id: (the list's details, [each item as Kibana gave it])}``. A list whose last read failed,
    whose details Kibana didn't give, or read before TIDE kept these, is left out."""
    try:
        details = {r[0]: json.loads(r[1]) for r in conn.execute(
            "SELECT list_id, details::VARCHAR FROM rule_exception_reads WHERE siem_id = ? AND space = ? AND last_ok "
            "AND details IS NOT NULL", [siem_id, space]).fetchall()}
        rows = conn.execute("SELECT list_id, raw::VARCHAR FROM rule_exception_items WHERE siem_id = ? AND space = ?",
                            [siem_id, space]).fetchall()
    except Exception:          # never read in this tenant yet, or not since TIDE kept these
        return {}
    items: Dict[str, List[Dict[str, Any]]] = {}
    for list_id, raw in rows:
        if list_id in details:
            items.setdefault(list_id, []).append(json.loads(raw) if raw else None)
    return {list_id: (about, items.get(list_id, [])) for list_id, about in details.items()
            if None not in items.get(list_id, [])}


def for_rule(conn, siem_id: str, space: str, exceptions_list) -> Dict[str, Any]:
    """The rule window's Exceptions (#75): ``{lists: [{list_id, namespace_type, label, read, list_items: [item with
    text, broad, active]}], count, read_at}``; ``count`` the items that apply. None-safe."""
    mine = lists_of(exceptions_list)
    if not mine:
        return {"lists": [], "count": 0, "read_at": None}
    if isinstance(exceptions_list, str):
        exceptions_list = json.loads(exceptions_list)
    kinds = {str(e.get("list_id")): e.get("type") for e in exceptions_list or [] if isinstance(e, dict)}
    kept = items_by_list(conn, siem_id)
    try:
        reads = dict(conn.execute("SELECT list_id, read_at FROM rule_exception_reads WHERE siem_id = ? AND space = ?",
                                  [siem_id, space]).fetchall())
    except Exception:
        reads = {}
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    lists = []
    for list_id, ns in mine:
        items = [{**i, "text": item_text(i), "broad": broad(i), "active": active(i, now)}
                 for i in kept.get((space, list_id), [])]
        kind = kinds.get(list_id)
        lists.append({"list_id": list_id, "namespace_type": ns, "list_items": items, "read": list_id in reads,
                      "label": {"rule_default": "Its own exceptions", "endpoint": "Endpoint exceptions"}.get(
                          kind, "Shared exception list")})
    return {"lists": lists, "count": sum(1 for lst in lists for i in lst["list_items"] if i["active"]),
            "read_at": max(reads.values(), default=None)}


def iter_rule_items(lists: Iterable[Key], kept: Dict[Tuple[str, str], List[Dict[str, Any]]], space: str,
                    now_utc: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """The items that apply to a rule using ``lists``, from ``items_by_list``."""
    return [i for list_id, _ns in lists for i in kept.get((space, list_id), []) if active(i, now_utc)]
