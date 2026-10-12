"""Diagnostics fixes: named repairs for what some checks find, with a preview, a backup and Undo.

A fix only ever changes TIDE's own data (links, baseline rows, rule mappings) in one client's
database -- never a SIEM, never anything typed. Applying one:
  1. the client must allow fixes (clients.diagnostic_fixes, which only a super admin turns on);
  2. the person types the fix's name to confirm what the preview showed;
  3. the client's database file is copied to data/diagnostics-backups/ first (the newest
     BACKUPS_KEPT per client are kept; refused when the disk is short of space);
  4. the change runs in one transaction, never while a sync is running for that client;
  5. it is recorded in diagnostic_runs with the rows it changed, so Undo can put exactly those
     back -- a row-level undo, safer than swapping the database file while TIDE has it open.
"""
from __future__ import annotations

import glob
import json
import logging
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from app.services import diagnostics as dg

logger = logging.getLogger(__name__)

BACKUPS_KEPT = 3
PREVIEW_ROWS = 50


class FixRefused(Exception):
    """A fix that must not run (fixes off, nothing to change, confirmation wrong, no disk space)."""


@dataclass(frozen=True)
class Fix:
    id: str              # also what the person types to confirm
    check_id: str        # the check whose findings it repairs
    label: str           # the button
    does: str            # what it changes, in plain words
    plan: Callable       # (conn, ctx) -> (columns, rows to show, payload for apply)
    apply: Callable      # (conn, ctx, payload, actor) -> undo data (JSON-able)
    undo: Callable       # (conn, ctx, undo data, actor) -> rows put back


# ── helpers ──────────────────────────────────────────────────────────────

def _rows(conn, table: str, where: str, params: list) -> Dict[str, Any]:
    """Whole rows of ``table``, as JSON-able columns + values, so Undo can re-insert them as they were."""
    cur = conn.execute(f"SELECT * FROM {table} WHERE {where}", params)
    cols = [d[0] for d in cur.description]
    return {"table": table, "columns": cols,
            "rows": [[v.isoformat() if hasattr(v, "isoformat") else v for v in r] for r in cur.fetchall()]}


def _reinsert(conn, saved: Dict[str, Any]) -> int:
    if not saved["rows"]:
        return 0
    cols = ", ".join(f'"{c}"' for c in saved["columns"])
    marks = ", ".join("?" for _ in saved["columns"])
    for row in saved["rows"]:
        conn.execute(f"INSERT INTO {saved['table']} ({cols}) VALUES ({marks}) ON CONFLICT DO NOTHING", row)
    return len(saved["rows"])


def _in(ids: List[str]) -> str:
    return ", ".join("?" for _ in ids) or "NULL"


# ── remove links to a rule that is gone ──────────────────────────────────

def _dead_links_plan(conn, ctx):
    if not {"rule_links", "detection_rules"} <= dg._tables(conn):
        return [], [], []
    cols, rows = dg._links_missing_rule(conn, ctx)
    ids = [r[0] for r in conn.execute(
        "SELECT l.id FROM rule_links l WHERE NOT EXISTS (SELECT 1 FROM detection_rules r WHERE r.rule_id = l.rule_a_id "
        "AND r.siem_id = l.siem_a_id AND r.space = l.space_a) OR NOT EXISTS (SELECT 1 FROM detection_rules r "
        "WHERE r.rule_id = l.rule_b_id AND r.siem_id = l.siem_b_id AND r.space = l.space_b)").fetchall()]
    return cols, rows, ids


def _dead_links_apply(conn, ctx, ids, actor):
    saved = _rows(conn, "rule_links", f"id IN ({_in(ids)})", ids)
    conn.execute(f"DELETE FROM rule_links WHERE id IN ({_in(ids)})", ids)
    return [saved]


# ── remove baseline rows left without their baseline ─────────────────────

def _orphans_plan(conn, ctx):
    cols, rows = dg._orphaned_baseline_rows(conn, ctx)
    tables = dg._tables(conn)
    steps = [r[0] for r in conn.execute(
        "SELECT s.id FROM playbook_steps s WHERE NOT EXISTS (SELECT 1 FROM playbooks p WHERE p.id = s.playbook_id)"
    ).fetchall()] if {"playbook_steps", "playbooks"} <= tables else []
    dets = [r[0] for r in conn.execute(
        f"SELECT id FROM step_detections WHERE step_id IN ({_in(steps)}) "
        "OR NOT EXISTS (SELECT 1 FROM playbook_steps s WHERE s.id = step_detections.step_id)", steps
    ).fetchall()] if {"step_detections", "playbook_steps"} <= tables else []
    return cols, rows, {"steps": steps, "detections": dets} if (steps or dets) else []


def _orphans_apply(conn, ctx, plan, actor):
    tables = dg._tables(conn)
    steps, dets = plan["steps"], plan["detections"]
    saved = []
    # Children first; Undo puts them back parents first (the list is reversed there).
    if dets and "applied_detections" in tables:
        saved.append(_rows(conn, "applied_detections", f"detection_id IN ({_in(dets)})", dets))
        conn.execute(f"DELETE FROM applied_detections WHERE detection_id IN ({_in(dets)})", dets)
    if dets:
        saved.append(_rows(conn, "step_detections", f"id IN ({_in(dets)})", dets))
        conn.execute(f"DELETE FROM step_detections WHERE id IN ({_in(dets)})", dets)
    if steps and "step_techniques" in tables:
        saved.append(_rows(conn, "step_techniques", f"step_id IN ({_in(steps)})", steps))
        conn.execute(f"DELETE FROM step_techniques WHERE step_id IN ({_in(steps)})", steps)
    if steps:
        saved.append(_rows(conn, "playbook_steps", f"id IN ({_in(steps)})", steps))
        conn.execute(f"DELETE FROM playbook_steps WHERE id IN ({_in(steps)})", steps)
    return saved


def _reinsert_all(conn, ctx, saved, actor):
    return sum(_reinsert(conn, s) for s in reversed(saved))


# ── relink mappings with exactly one match ───────────────────────────────

def _relink_plan(conn, ctx):
    from app.scripts.relink_rule_mappings import _plan
    if not {"step_detections", "detection_rules"} <= dg._tables(conn):
        return [], [], []
    names = {(sid, sp): name for sid, sp, name in ctx["scopes"]}
    plan = _plan(conn, [(sid, sp) for sid, sp, _ in ctx["scopes"]])
    sure = [p for p in plan if len(p["matches"]) == 1]
    rows = [(p["was"], p["was_at"] if p["was_at"] == "no destination" else names.get(tuple(p["was_at"].split("/", 1)), p["was_at"]),
             p["matches"][0][3], names.get((p["matches"][0][1], p["matches"][0][2]), p["matches"][0][2])) for p in sure]
    payload = [{"id": p["id"], "rule_ref": m[0], "siem_id": m[1], "space": m[2], "note": m[3]}
               for p in sure for m in p["matches"]]
    return ["mapped as", "was at", "relinks to", "at"], rows, payload


def _relink_apply(conn, ctx, payload, actor):
    from app.inventory_engine import relink_step_detection
    before = []
    for p in payload:
        old = conn.execute("SELECT rule_ref, siem_id, space, note FROM step_detections WHERE id = ?", [p["id"]]).fetchone()
        if old and relink_step_detection(p["id"], rule_ref=p["rule_ref"], siem_id=p["siem_id"], space=p["space"],
                                         note=p["note"], actor=actor, client_id=ctx["client_id"], conn=conn):
            before.append({"id": p["id"], "rule_ref": old[0], "siem_id": old[1], "space": old[2], "note": old[3]})
    return before


def _relink_undo(conn, ctx, before, actor):
    from app.inventory_engine import relink_step_detection
    return sum(1 for b in before if relink_step_detection(
        b["id"], rule_ref=b["rule_ref"], siem_id=b["siem_id"], space=b["space"], note=b["note"] or "",
        actor=actor, client_id=ctx["client_id"], conn=conn))


FIXES: List[Fix] = [
    Fix("relink_mappings", "mappings_need_relink", "Relink where there is one match",
        "Points each mapping at the one rule copy its rule ID or name matches at this client's destinations, "
        "keeping where it is applied and its history (each relink is added to the technique's history). "
        "Mappings with no match or several are left for a person to Relink from the technique.",
        _relink_plan, _relink_apply, _relink_undo),
    Fix("remove_dead_links", "links_missing_rule", "Remove these links",
        "Removes each link whose rule (one side or both) TIDE no longer has. The rules themselves are not touched.",
        _dead_links_plan, _dead_links_apply, _reinsert_all),
    Fix("remove_orphan_rows", "orphaned_baseline_rows", "Remove the leftover rows",
        "Removes techniques whose baseline was deleted, with their ATT&CK techniques, rule mappings and where those "
        "were applied, and rule mappings whose technique was deleted. None of them is shown anywhere.",
        _orphans_plan, _orphans_apply, _reinsert_all),
]
FIXES_BY_ID = {f.id: f for f in FIXES}
FIX_FOR_CHECK = {f.check_id: f for f in FIXES}


# ── who may, and the per-client switch ───────────────────────────────────

def fixes_allowed(db) -> Dict[str, bool]:
    """``client_id -> bool``: each client's own Allow diagnostic fixes switch."""
    with db.get_shared_connection() as conn:
        return {cid: bool(on) for cid, on in conn.execute("SELECT id, COALESCE(diagnostic_fixes, false) FROM clients").fetchall()}


def set_fixes_allowed(db, client_id: str, on: bool) -> None:
    with db.get_shared_connection() as conn:
        conn.execute("UPDATE clients SET diagnostic_fixes = ? WHERE id = ?", [bool(on), client_id])


# ── preview / apply / undo ───────────────────────────────────────────────

def _ctx(db, client: Dict) -> Dict[str, Any]:
    scopes = [(s.get("id"), s.get("space") or "default", s.get("name") or s.get("label") or s.get("space"))
              for s in (db.get_client_siems(client["id"]) or [])]
    return {"client_id": client["id"], "scopes": scopes, "data_dir": os.path.dirname(db.db_path)}


def preview(db, fix_id: str, client: Dict) -> Dict[str, Any]:
    """What the fix would change for this client, without changing anything."""
    from app.services.tenant_manager import tenant_context_for
    fix = FIXES_BY_ID[fix_id]
    with tenant_context_for(client["id"]), db.get_connection() as conn:
        cols, rows, payload = dg._rolled_back(conn, fix.plan, _ctx(db, client))
    return {"fix": fix, "client": client, "columns": cols, "rows": rows[:PREVIEW_ROWS],
            "count": len(rows), "changes": bool(payload)}


def _backup(db, client: Dict, conn) -> str:
    """Copy the client's database (and its WAL) aside before a fix. Keeps the newest BACKUPS_KEPT."""
    data_dir = os.path.dirname(db.db_path)
    with db.get_shared_connection() as sconn:
        row = sconn.execute("SELECT db_filename FROM clients WHERE id = ?", [client["id"]]).fetchone()
    if not row or not row[0]:
        raise FixRefused("This client has no database file to back up.")
    src = os.path.join(data_dir, row[0])
    dest_dir = os.path.join(data_dir, "diagnostics-backups")
    os.makedirs(dest_dir, exist_ok=True)
    need = os.path.getsize(src) * 1.5
    if shutil.disk_usage(dest_dir).free < need:
        raise FixRefused(f"Not enough free disk space to back up this client's database first "
                         f"({need / 1073741824:.1f} GB needed). Nothing was changed.")
    conn.execute("CHECKPOINT")
    stem = re.sub(r"[^A-Za-z0-9_-]", "_", row[0].rsplit(".", 1)[0])
    dest = os.path.join(dest_dir, f"{stem}_{datetime.utcnow():%Y%m%dT%H%M%SZ}.duckdb")
    shutil.copy2(src, dest)
    if os.path.exists(src + ".wal"):
        shutil.copy2(src + ".wal", dest + ".wal")
    for old in sorted(glob.glob(os.path.join(dest_dir, f"{stem}_*.duckdb")))[:-BACKUPS_KEPT]:
        for path in (old, old + ".wal"):
            if os.path.exists(path):
                os.remove(path)
    return dest


def _refuse_while_syncing(client: Dict) -> None:
    from app.main import sync_running
    if sync_running(client["id"]):
        raise FixRefused(f"A sync is running for {client['name']}. Try again when it has finished. Nothing was changed.")


def _in_transaction(conn, fn: Callable):
    conn.execute("BEGIN TRANSACTION")
    try:
        out = fn()
        conn.execute("COMMIT")
        return out
    except Exception:
        conn.execute("ROLLBACK")
        raise


def apply(db, fix_id: str, client: Dict, confirm: str, actor) -> Dict[str, Any]:
    """Apply a fix to one client after its preview: refuses unless the client allows fixes and
    ``confirm`` is the fix's name. Backs up, changes in one transaction, records for Undo."""
    from app.config import get_settings
    from app.services.tenant_manager import tenant_context_for
    fix = FIXES_BY_ID[fix_id]
    if not fixes_allowed(db).get(client["id"]):
        raise FixRefused(f"Fixes are off for {client['name']}. A super admin can turn them on under Clients on this page.")
    if (confirm or "").strip() != fix.id:
        raise FixRefused(f"Type {fix.id} to confirm. Nothing was changed.")
    _refuse_while_syncing(client)
    ctx = _ctx(db, client)
    with tenant_context_for(client["id"]), db.get_connection() as conn:
        _cols, rows, payload = fix.plan(conn, ctx)
        if not payload:
            raise FixRefused("There is nothing for this fix to change now. Nothing was changed.")
        backup = _backup(db, client, conn)
        undo_data = _in_transaction(conn, lambda: fix.apply(conn, ctx, payload, actor.username))
    changed = len(rows)
    with db.get_shared_connection() as conn:
        run_id = conn.execute(
            "INSERT INTO diagnostic_runs (fix_id, check_id, client_id, actor_id, actor, tide_version, rows_changed, "
            "backup_path, undo_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
            [fix.id, fix.check_id, client["id"], actor.id, actor.username, get_settings().tide_version, changed,
             backup, json.dumps(undo_data, default=str)],
        ).fetchone()[0]
    return {"run_id": run_id, "fix": fix, "client": client, "changed": changed, "backup": backup}


def undo(db, run_id: str, client: Dict, actor) -> Dict[str, Any]:
    """Put back exactly what a fix changed. Once only; recorded on the fix's row."""
    from app.services.tenant_manager import tenant_context_for
    with db.get_shared_connection() as conn:
        row = conn.execute("SELECT fix_id, client_id, undo_data, undone_at FROM diagnostic_runs WHERE id = ?",
                           [run_id]).fetchone()
    if not row or row[1] != client["id"]:
        raise FixRefused("That fix was not found for this client.")
    if row[3]:
        raise FixRefused("That fix has already been undone.")
    _refuse_while_syncing(client)
    fix = FIXES_BY_ID[row[0]]
    ctx = _ctx(db, client)
    with tenant_context_for(client["id"]), db.get_connection() as conn:
        restored = _in_transaction(conn, lambda: fix.undo(conn, ctx, json.loads(row[2]), actor.username))
    with db.get_shared_connection() as conn:
        conn.execute("UPDATE diagnostic_runs SET undone_at = now(), undone_by = ? WHERE id = ?", [actor.username, run_id])
    return {"run_id": run_id, "fix": fix, "client": client, "restored": restored}


def recent_runs(db, client_ids: List[str], limit: int = 20) -> List[Dict[str, Any]]:
    """The newest fixes on these clients, for the page's Fixes list."""
    if not client_ids:
        return []
    with db.get_shared_connection() as conn:
        names = dict(conn.execute("SELECT id, name FROM clients").fetchall())
        rows = conn.execute(
            f"SELECT id, fix_id, client_id, actor, rows_changed, backup_path, created_at, undone_at, undone_by "
            f"FROM diagnostic_runs WHERE client_id IN ({_in(client_ids)}) ORDER BY created_at DESC LIMIT ?",
            list(client_ids) + [limit],
        ).fetchall()
    return [{
        "id": r[0], "fix": FIXES_BY_ID.get(r[1]), "fix_id": r[1], "client_id": r[2], "client": names.get(r[2], r[2]),
        "actor": r[3], "changed": r[4], "backup": os.path.basename(r[5] or ""), "at": r[6],
        "undone_at": r[7], "undone_by": r[8],
    } for r in rows]
