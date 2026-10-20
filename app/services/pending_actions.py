"""Changes Kibana made that TIDE couldn't record (#83, #88).

Give it its own rule id, Move (and copy) and Restore in Elastic change Kibana first, then record
the change in TIDE. If TIDE's part fails after Kibana's succeeded, TIDE is left showing the rule as
it was while Kibana has moved on, and trying the action again fails (the original is gone from
Kibana) or, for Restore, does it twice.

So what TIDE still has to do is kept in data/pending_actions.json, outside the client's database
(the failure may be that database: a DuckDB fatal error closes it until TIDE restarts), and is
finished by **Finish in TIDE** (the rule window, and Rule Monitoring's ``change_pending``), by
trying the action again (which then doesn't change Kibana again), and by the next sync that reads
the rule concerned (:func:`finish_for_sync`).

An entry is ``{"kind", "client_id", "siem_id", "space", "rule_id"}`` (the rule as TIDE holds it:
for a move, the source) plus what its kind's ``apply`` needs, and ``error`` and ``at`` once kept.
Each ``apply`` is safe to repeat: what was done before a failure isn't done twice.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

RECORD = "pending_actions.json"
KINDS = ("own_rule_id", "move", "restore")
_KEY = ("kind", "client_id", "siem_id", "space", "rule_id", "copy_id")
_lock = threading.Lock()

Key = Tuple[str, str, str]


# ── the record ───────────────────────────────────────────────────────────

def _path() -> Path:
    from app.config import get_settings
    return Path(get_settings().data_dir) / RECORD


def _load() -> List[Dict[str, Any]]:
    try:
        return json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []


def _save(entries: List[Dict[str, Any]]) -> None:
    path = _path()
    if not entries:
        path.unlink(missing_ok=True)
        return
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(entries, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)


def _same(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    return all((a.get(k) or "") == (b.get(k) or "") for k in _KEY)


def add(entry: Dict[str, Any], error: str) -> None:
    """Keep ``entry`` with the error that stopped it, replacing an earlier one for the same change."""
    entry = {**entry, "error": error, "at": datetime.now().isoformat(timespec="seconds")}
    with _lock:
        _save([e for e in _load() if not _same(e, entry)] + [entry])


def remove(entry: Dict[str, Any]) -> None:
    with _lock:
        _save([e for e in _load() if not _same(e, entry)])


def for_client(client_id: str) -> List[Dict[str, Any]]:
    return [e for e in _load() if e.get("client_id") == client_id]


def for_rule(client_id: str, key: Key) -> List[Dict[str, Any]]:
    """The client's unfinished changes on the rule TIDE holds as ``key`` (rule_id, siem_id, space)."""
    return [e for e in for_client(client_id) if (e["rule_id"], e["siem_id"], e["space"]) == tuple(key)]


def get(client_id: str, kind: str, rule_id: str, siem_id: str, space: str, copy_id: str = "") -> Optional[Dict[str, Any]]:
    want = {"kind": kind, "client_id": client_id, "siem_id": siem_id, "space": space, "rule_id": rule_id,
            "copy_id": copy_id}
    return next((e for e in for_client(client_id) if _same(e, want)), None)


def summary(exc: BaseException) -> str:
    text = str(exc).strip()
    return (text.splitlines()[0] if text else type(exc).__name__)[:300]


# ── what the user reads ──────────────────────────────────────────────────

def describe(entry: Dict[str, Any]) -> str:
    """What Kibana did, for the rule window and Rule Monitoring: 'Kibana moved this rule to Prod'."""
    kind = entry["kind"]
    if kind == "own_rule_id":
        what = f"the custom copy, {entry['name']}," if entry.get("copy_id") else "this rule"
        return f"Kibana gave {what} its own rule id, {entry['new_id']}"
    if kind == "move":
        return f"Kibana {'moved' if entry['delete_source'] else 'copied'} this rule to {entry['target_name']}"
    return f"Kibana restored this rule{' under its own rule id, ' + entry['new_id'] if entry.get('new_id') else ''}"


def pending_message(entry: Dict[str, Any], error: str) -> str:
    """The answer when TIDE's part failed: what Kibana did, why TIDE didn't, and how to finish."""
    where = entry.get("target_name") if entry["kind"] == "move" else "this destination"
    what = describe(entry).replace("this rule", f'"{entry["name"]}"')
    return (f"{what}, but TIDE couldn't record the change ({error}). Finish in TIDE, on the rule, completes it; "
            f"so does the next sync of {where}.")


# ── finishing ────────────────────────────────────────────────────────────

def finish(db, entry: Dict[str, Any], user_id: Optional[str] = None, username: Optional[str] = None,
           refresh: bool = True) -> Tuple[int, str, Key]:
    """Do TIDE's part of ``entry``'s change. On success the record goes (if it was kept) and, with
    ``refresh``, the rule is read again from Kibana: ``(200, message, the rule's key now)``. On
    failure the change is kept with its error: ``(202, what happened and how to finish, the rule's
    key as TIDE holds it)``."""
    entry = {**entry, "user_id": user_id or entry.get("user_id"), "username": username or entry.get("username")}
    try:
        message, key = _APPLY[entry["kind"]](db, entry, refresh)
    except Exception as exc:  # noqa: BLE001 - Kibana has changed: keep what TIDE still has to do
        error = summary(exc)
        logger.exception("%s for rule %s in %s/%s, but TIDE couldn't record it", describe(entry),
                         entry["rule_id"], entry["siem_id"], entry["space"])
        add(entry, error)
        return 202, pending_message(entry, error), (entry["rule_id"], entry["siem_id"], entry["space"])
    remove(entry)
    if refresh and entry["kind"] != "move":         # a move reads its target itself, before linking
        from app.api.rules import sync_single_rule
        try:
            sync_single_rule(db, entry["client_id"], *key, entry.get("user_id"), entry.get("username") or "system")
        except Exception:  # noqa: BLE001 - the next sync reads it instead
            logger.warning("Rule %s: re-reading it from Kibana failed", key[0], exc_info=True)
    return 200, message, key


def finish_for_sync(db, client_id: str, records: Iterable[Dict[str, Any]], stage: str) -> int:
    """At a sync: finish each of the client's pending changes whose rule this sync fetched from
    Kibana. ``before_save`` (own rule id, restore) moves the old row to the rule's new identity
    before saving would add it as a new rule and deprecate the old one; ``after_save`` (move)
    needs the target's row the save just wrote. Returns how many were finished; a failure is kept,
    and noted on the sync."""
    kinds = ("own_rule_id", "restore") if stage == "before_save" else ("move",)
    pending = [e for e in for_client(client_id) if e["kind"] in kinds]
    if not pending:
        return 0
    fetched: Dict[tuple, set] = {}
    for r in records:
        raw = r.get("raw_data") or {}
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except ValueError:
                raw = {}
        fetched.setdefault((r.get("siem_id"), r.get("space") or r.get("space_id") or "default"), set()).add(
            (raw.get("rule_id") if isinstance(raw, dict) else None) or r.get("rule_id"))
    done = 0
    for entry in pending:
        if entry["kind"] == "move":
            where, ids = (entry["target_siem_id"], entry["target_space"]), {entry["target_rule_id"]}
        else:
            where = (entry["siem_id"], entry["space"])
            ids = {entry.get("new_id") or entry.get("saved_id") or entry["rule_id"], entry["rule_id"]}
        if not ids & fetched.get(where, set()):
            continue
        status, message, _key = finish(db, entry, refresh=False)
        if status == 200:
            done += 1
            logger.info("At sync, finished: %s (rule %s)", describe(entry), entry["rule_id"])
        else:
            from app.services import sync_runs
            sync_runs.step_failed("Finishing a change made in Kibana", message)
    return done


# ── each kind's part in TIDE ─────────────────────────────────────────────

def _recorded(db, key: Key, action: str, since: Optional[str] = None, field: str = "", value: str = "") -> bool:
    """Whether the rule's history already has ``action`` (since ``since``, or with ``field`` = ``value``)."""
    sql = "SELECT 1 FROM rule_lifecycle_history WHERE rule_id = ? AND siem_id = ? AND space = ? AND action = ?"
    params: List[Any] = [*key, action]
    if since:
        sql += " AND created_at >= ?"
        params.append(datetime.fromisoformat(since))
    if field:
        sql += f" AND json_extract_string(detail, '$.{field}') = ?"
        params.append(value)
    import duckdb
    try:
        with db.get_connection() as conn:
            return conn.execute(sql + " LIMIT 1", params).fetchone() is not None
    except duckdb.CatalogException:     # no history table yet: nothing recorded
        return False


def _take_new_identity(db, entry: Dict[str, Any], old: Key, new_id: str, object_id: Optional[str]) -> None:
    """Move what TIDE holds for ``old`` to ``new_id`` (rekey_rule), keeping Elastic's rule as its
    upstream. A sync since Kibana's part may hold the rule under ``new_id`` as a fresh row (the same
    Kibana rule: its saved-object id is ``object_id``); the old row, which has the history, links and
    mappings, takes its place. No other row is ever removed."""
    from app.services import rule_origins
    rule_id, siem_id, space = old
    if not db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=entry["client_id"]):
        return                                      # done before
    with db.get_connection() as conn:
        if entry.get("elastic_id") and not rule_origins.get(conn, old):
            rule_origins.record(conn, old, "elastic", entry["elastic_id"], "first_seen",
                                entry.get("username") or "TIDE", version=entry.get("version"))
        if object_id:
            conn.execute("DELETE FROM detection_rules WHERE rule_id = ? AND siem_id = ? AND space = ? "
                         "AND json_extract_string(raw_data, '$.id') = ?", [new_id, siem_id, space, object_id])
    db.rekey_rule(rule_id, new_id, siem_id, space, object_id=object_id)


def own_rule_id_message(entry: Dict[str, Any]) -> str:
    return (f'Gave "{entry["name"]}" its own rule id, {entry["new_id"]}, in place of Elastic\'s '
            f'{entry["elastic_id"]}. Kibana keeps its past alerts and runs with the original. TIDE still shows '
            "Elastic's updates for it.")


def _apply_own_rule_id(db, entry: Dict[str, Any], refresh: bool) -> Tuple[str, Key]:
    """Giving a rule (or, with ``copy_id``, Kibana's custom copy beside it) its own rule id."""
    from app.services import rule_origins
    from app.services.tenant_manager import tenant_context_for
    client_id, siem_id, space = entry["client_id"], entry["siem_id"], entry["space"]
    old, new, by = entry["rule_id"], entry["new_id"], entry.get("username") or "TIDE"
    with tenant_context_for(client_id):
        if entry.get("copy_id"):
            with db.get_connection() as conn:
                recorded = rule_origins.get(conn, (new, siem_id, space))
            if not recorded:
                rule_origins.record_for_client(db, client_id, (new, siem_id, space), "elastic", entry["elastic_id"],
                                               "copied", by, version=entry.get("created_version"))
        else:
            _take_new_identity(db, entry, (old, siem_id, space), new, entry.get("object_id"))
        text = own_rule_id_message(entry)
        if not _recorded(db, (new, siem_id, space), "new_rule_id"):
            db.record_rule_history(rule_id=new, siem_id=siem_id, space=space, client_id=client_id,
                                   action="new_rule_id", actor_user_id=entry.get("user_id"), actor_name=by,
                                   detail={"message": text, "previous_rule_id": entry["elastic_id"]})
            if entry.get("copy_id"):
                db.record_rule_history(rule_id=old, siem_id=siem_id, space=space, client_id=client_id,
                                       action="new_rule_id", actor_user_id=entry.get("user_id"), actor_name=by,
                                       detail={"message": f'Kibana\'s custom copy of this rule, "{entry["name"]}", '
                                                          f"now has its own rule id, {new}."})
    return text, (new, siem_id, space)


def _linked(db, a: Key, b: Key) -> bool:
    links = db.get_rule_links_bulk([a]).get(a, []) or []
    return any(l["rule_id"] == b[0] and l["siem_id"] == b[1] and str(l["space"]).lower() == str(b[2]).lower()
               for l in links)


def _apply_move(db, entry: Dict[str, Any], refresh: bool) -> Tuple[str, Key]:
    """A move (``delete_source``) or copy to another destination, or (``resolution`` "link") a move
    onto the identical rule the target already held."""
    from app.services import rule_origins
    from app.services.tenant_manager import tenant_context_for
    client_id, by, uid = entry["client_id"], entry.get("username") or "TIDE", entry.get("user_id")
    src: Key = (entry["rule_id"], entry["siem_id"], entry["space"])
    tgt: Key = (entry["target_rule_id"], entry["target_siem_id"], entry["target_space"])
    name, target_name, delete = entry["name"], entry["target_name"], entry["delete_source"]
    settle = entry.get("resolution") == "link"
    with tenant_context_for(client_id):
        mode = entry.get("validation_mode") or "keep"
        if mode != "keep" and entry.get("stamp_validation_key"):
            from app.services.database import validation_for
            before = bool(validation_for(db._load_validation_data(), entry["source_validation_key"], name))
            if mode == "stamp" or (mode == "new_only" and not before):
                db.save_validation(entry["stamp_validation_key"], name, by)
        if refresh and not settle:
            # The new copy exists only in Kibana until it is read; a link needs both rows.
            from app.api.rules import sync_single_rule
            try:
                sync_single_rule(db, client_id, *tgt, uid, by)
            except Exception:  # noqa: BLE001
                logger.exception("Move: reading the new copy failed; the link may not be created")
        with db.get_connection() as conn:
            if not rule_origins.get(conn, tgt):
                new_id = bool(entry.get("new_id_used"))
                if (not rule_origins.copy(conn, src, tgt, "copied", by, parent=new_id and not settle)
                        and entry.get("elastic_id") and not settle):
                    rule_origins.record(conn, tgt, "elastic", entry["elastic_id"], "copied", by,
                                        parent=src if new_id else None, version=entry.get("version"))
        if settle and delete:
            db.set_rule_deprecated(*src, True)
            db.remap_rule_references(src[0], tgt[0], client_id, src[1], src[2], tgt[1], tgt[2], actor=by)
            message = (f'{target_name} already had "{name}" unchanged, so it now lives there only: this copy '
                       f"was deleted and its baseline mappings point at {target_name}.")
            resolution = "link"
        elif settle:
            linked = not _linked(db, src, tgt) and db.create_rule_link(*src, *tgt, by)
            message = (f'{target_name} already had "{name}" unchanged; the two are now linked.' if linked
                       else f'{target_name} already had "{name}" unchanged, and the two were already linked.')
            resolution = "link"
        else:
            db.set_rule_deprecated(*src, delete)
            if delete:
                # A true move: baseline references follow the rule to its new home.
                db.remap_rule_references(src[0], tgt[0], client_id, src[1], src[2], tgt[1], tgt[2], actor=by)
                message = f'Moved "{name}" to {target_name}{entry.get("under", "")}.{entry.get("actions_note", "")}'
            else:
                # Both copies stay live: link them, so the rule window shows each from the other.
                message = f'Copied "{name}" to {target_name}{entry.get("under", "")}.{entry.get("actions_note", "")}'
                if not _linked(db, src, tgt) and not db.create_rule_link(*src, *tgt, by):
                    logger.warning("Move: copied '%s' to %s but could not record a link (target not found in "
                                   "detection_rules after sync) -- link the two rows manually.", name, target_name)
                    message += " Could not link it to the source automatically — use Add link in the rule window."
            resolution = "new_id" if entry.get("new_id_used") else ""
        if not _recorded(db, src, "moved", field="target_rule_id", value=tgt[0]):
            db.record_rule_history(
                rule_id=src[0], siem_id=src[1], space=src[2], client_id=client_id, action="moved",
                actor_user_id=uid, actor_name=by,
                detail={"message": message, "target_siem_id": tgt[1], "target_space": tgt[2], "target_rule_id": tgt[0],
                        "delete_source": delete, "resolution": resolution})
    return message, (tgt if delete else src)


def _apply_restore(db, entry: Dict[str, Any], refresh: bool) -> Tuple[str, Key]:
    """Restoring a deprecated rule that Kibana has created again (disabled)."""
    from app.services.tenant_manager import tenant_context_for
    client_id, by = entry["client_id"], entry.get("username") or "TIDE"
    rule_id, siem_id, space = entry["rule_id"], entry["siem_id"], entry["space"]
    new_id, saved_id = entry.get("new_id"), entry.get("saved_id")
    with tenant_context_for(client_id):
        if new_id:
            # Under one of Elastic's rule ids it came back under a new one: everything moves there.
            _take_new_identity(db, entry, (rule_id, siem_id, space), new_id, saved_id)
            db.set_rule_deprecated(new_id, siem_id, space, False)
            key: Key = (new_id, siem_id, space)
        elif entry.get("kibana_rule_id") and entry["kibana_rule_id"] == rule_id:
            db.set_rule_deprecated(rule_id, siem_id, space, False)
            key = (rule_id, siem_id, space)
        elif saved_id and saved_id != rule_id:
            # Keyed by the saved-object id, which Kibana has now issued afresh: keep the old row for
            # history and move baseline links to the new identity.
            db.remap_rule_references(rule_id, saved_id, client_id, siem_id, space, siem_id, space, actor=by)
            key = (saved_id, siem_id, space)
        else:
            db.set_rule_deprecated(rule_id, siem_id, space, False)
            key = (rule_id, siem_id, space)
        history_key = (new_id or rule_id, siem_id, space)
        if not _recorded(db, history_key, "restored", since=entry.get("started")):
            db.record_rule_history(rule_id=history_key[0], siem_id=siem_id, space=space, client_id=client_id,
                                   action="restored", actor_user_id=entry.get("user_id"), actor_name=by,
                                   detail={"message": entry["history_message"], "restored_disabled": True})
    own_id = (" It has its own rule id now, so Kibana can still install Elastic's own rule here; TIDE still shows "
              "Elastic's updates for it." if new_id else "")
    return f'Restored "{entry["name"]}". It was recreated disabled; enable it when you are ready.{own_id}', key


_APPLY = {"own_rule_id": _apply_own_rule_id, "move": _apply_move, "restore": _apply_restore}
