"""Bulk edit for Rule Health: validate, enable, disable, move or delete many rules at once.

The page keeps the selection in the browser as a list of ``{rule_id, siem_id, space}``. "Select all"
asks ``/ids`` for every rule matching the current filters (not just the loaded page). A confirm dialog
re-checks the selection on the server, and ``/start`` runs it as a background job whose progress the
dialog polls.

Move has no eligibility restriction -- any selected rule can go to any linked destination. The
browser greys buttons out only for "select at least one rule."
"""
from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import time
from html import escape
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

from app.api.deps import ActiveClient, DbDep, RequireUser
from app.models.rules import RuleFilters
from app.services.database import validation_key

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/rules/bulk-edit", tags=["bulk-edit"])

ACTIONS = {
    "validate": "Validate",
    "enable": "Enable",
    "disable": "Disable",
    "move": "Move",
    "delete": "Delete",
}
MAX_ITEMS = 2000

# One job per client, in memory. A job starts on a click and ends on its own.
_EDIT_JOBS: Dict[str, Dict[str, Any]] = {}


def _render(request: Request, template: str, ctx: Dict[str, Any]) -> HTMLResponse:
    return request.app.state.templates.TemplateResponse(request, template, ctx)


def _parse_items(raw: str) -> List[Dict[str, str]]:
    """Selection from the browser: a JSON list of {rule_id, siem_id, space}, de-duplicated."""
    try:
        data = json.loads(raw or "[]")
    except Exception:
        return []
    items, seen = [], set()
    for entry in data if isinstance(data, list) else []:
        if not isinstance(entry, dict) or not entry.get("rule_id"):
            continue
        item = {
            "rule_id": str(entry["rule_id"]),
            "siem_id": str(entry.get("siem_id") or ""),
            "space": str(entry.get("space") or "default"),
        }
        key = (item["rule_id"], item["siem_id"], item["space"])
        if key not in seen:
            seen.add(key)
            items.append(item)
    return items


def _eligibility(action: str, count: int) -> Optional[str]:
    """Why ``action`` cannot run on this many selected rules; None when it can.

    Move has no state to check any more -- any selected rule can go to any linked destination."""
    if not count:
        return "Select at least one rule."
    return None


@router.get("/ids")
def matching_rule_ids(
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    search: Optional[str] = Query(None),
    space: Optional[str] = Query(None),
    enabled: Optional[str] = Query(None),
    state: List[str] = Query([]),
    min_score: Optional[str] = Query(None),
    max_score: Optional[str] = Query(None),
    validated_from: Optional[str] = Query(None),
    validated_to: Optional[str] = Query(None),
):
    """Every rule matching the Rule Health filters (all pages), as selection items."""
    from app.api.rules import _get_filtered_deduped_rules, _parse_date_bound

    def _int(v):
        return int(v) if v and v.strip().lstrip("-").isdigit() else None

    filters = RuleFilters(
        search=search or None,
        space=space or None,
        enabled=None if not enabled else enabled.lower() == "true",
        state=[s for s in state if s],
        min_score=_int(min_score),
        max_score=_int(max_score),
        validated_from=_parse_date_bound(validated_from, end_of_day=False),
        validated_to=_parse_date_bound(validated_to, end_of_day=True),
    )
    rules = _get_filtered_deduped_rules(db, filters, client_id)
    return JSONResponse([
        {
            "rule_id": r.rule_id,
            "siem_id": r.siem_id or "",
            "space": r.space or "default",
        }
        for r in rules
    ])


@router.post("/dialog", response_class=HTMLResponse)
def bulk_edit_dialog(
    request: Request,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    action: str = Form(...),
    items: str = Form("[]"),
):
    """Confirm dialog for ``action`` on the posted selection, with the options that action needs."""
    if action not in ACTIONS:
        return HTMLResponse('<div class="toast toast-danger">Unknown bulk action.</div>', status_code=400)
    job = _EDIT_JOBS.get(client_id)
    if job and job["state"] == "running":
        return _render(request, "components/bulk_edit_dialog.html", {"job": job})
    parsed = _parse_items(items)
    ctx: Dict[str, Any] = {"action": action, "label": ACTIONS[action], "total": len(parsed)}
    if len(parsed) > MAX_ITEMS:
        ctx["error"] = f"That is {len(parsed)} rules. Bulk edit handles up to {MAX_ITEMS} at a time; narrow the filters first."
    else:
        ctx["error"] = _eligibility(action, len(parsed))
    if not ctx["error"] and action == "move":
        destinations = db.get_client_siems(client_id) or []
        if not destinations:
            ctx["error"] = "No SIEM is linked to this client. Link one under Management, then try again."
        ctx["destinations"] = destinations
    client = db.get_client(client_id) or {}
    ctx.update({
        "items_json": json.dumps(parsed),
        "delete_default": bool(client.get("delete_source_after_promotion", True)),
    })
    return _render(request, "components/bulk_edit_dialog.html", ctx)


def _set_enabled_locally(db, rule_id: str, siem_id: str, space: str, enabled: bool) -> None:
    """Reflect an enable/disable in the tenant cache so the grid is right before the next sync."""
    try:
        with db.get_connection() as conn:
            conn.execute(
                "UPDATE detection_rules SET enabled = ? WHERE rule_id = ? AND siem_id = ? AND space = ?",
                [1 if enabled else 0, rule_id, siem_id, space],
            )
    except Exception as exc:  # the next sync corrects it
        logger.warning("bulk edit: local enabled flag not updated for %s: %s", rule_id, exc)


def _apply_one(db, action: str, user_id: str, username: str, client_id: str,
               item: Dict[str, str], opts: Dict[str, Any]):
    """Apply ``action`` to one rule (blocking). Returns ``(status_code, message, rule_name)``; 200 is success.

    Refreshes only the rule(s) this call actually touched — never the whole client — see
    sync_single_rule / CHANGELOG 5.1.2. A bulk run can span hundreds of rules; none of the others
    changed, so nothing else needs re-checking against Elastic.
    """
    from app import elastic_helper
    from app.api.promotion import _move_rule_sync
    from app.api.rules import sync_single_rule

    rule_id, siem_id, space = item["rule_id"], item["siem_id"], item["space"]

    if action == "move":
        # _move_rule_sync syncs the target row itself (it has to, to be able to link to it) --
        # no need to sync it again here.
        status, message, name, _target_rule_id, _target_scope = _move_rule_sync(
            db, user_id, username, client_id, rule_id, siem_id or None, space,
            opts["target_siem_id"], opts["target_space"], opts["delete_source"], opts["validation_mode"],
        )
        return status, message, name

    thresholds = db.get_client_validation_thresholds(client_id)
    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id or None, thresholds=thresholds, client_id=client_id)
    if not rule:
        return 404, "Rule not found.", None

    if action == "validate":
        db.save_validation(validation_key(rule.rule_id, rule.raw_data), rule.name, username)
        if siem_id:
            try:
                reason = f"{username} validated rule"
                db.record_rule_history(
                    rule_id=rule_id, siem_id=siem_id, space=space, client_id=client_id, action="validated",
                    actor_user_id=user_id, actor_name=username, detail={"message": reason, "reason": reason},
                )
            except Exception:
                logger.exception("bulk edit: validation history not written for %s", rule_id)
        return 200, "Validated.", rule.name

    if action == "delete":
        # TIDE-only, like the single-rule Delete from TIDE button: removes the row, does not
        # touch Elastic. If the rule still exists there, the next sync brings it straight back.
        if not siem_id:
            return 400, "Missing SIEM context.", rule.name
        if not db.delete_rule(rule_id, siem_id, space, remove_links=opts.get("remove_links", True)):
            return 404, "Rule not found.", rule.name
        db.record_rule_history(
            rule_id=rule_id, siem_id=siem_id, space=space, client_id=client_id,
            action="deleted", actor_user_id=user_id, actor_name=username,
            detail={"message": "Rule deleted from TIDE (bulk edit)."},
        )
        return 200, "Deleted from TIDE.", rule.name

    # enable / disable
    if not siem_id:
        return 400, "Missing SIEM context.", rule.name
    siem = next((s for s in (db.get_client_siems(client_id) or []) if s.get("id") == siem_id), None)
    if not siem:
        return 404, "SIEM not linked to this client.", rule.name
    turn_on = action == "enable"
    fn = elastic_helper.enable_detection_rule if turn_on else elastic_helper.disable_detection_rule
    # Kibana knows the rule by the id in its own payload, which is not always the id TIDE keys it by
    # (a moved or linked rule). The edit form resolves it the same way.
    payload = rule.raw_data if isinstance(rule.raw_data, dict) else {}
    kibana_rule_id = str(payload.get("rule_id") or payload.get("id") or rule.rule_id)
    ok, message = fn(kibana_rule_id, space=space, kibana_url=siem.get("kibana_url"), api_key=siem.get("api_token_enc"))
    if not ok:
        return 400, str(message), rule.name
    _set_enabled_locally(db, rule_id, siem_id, space, turn_on)
    db.record_rule_history(
        rule_id=rule_id, siem_id=siem_id, space=space, client_id=client_id,
        action="enabled" if turn_on else "disabled",
        actor_user_id=user_id, actor_name=username, detail={"message": message},
    )
    # _set_enabled_locally only flips the enabled column; refresh this one row so its cached
    # score and raw_data agree with the state Elastic now reports.
    sync_single_rule(db, client_id, rule_id, siem_id, space, user_id, username)
    return 200, message, rule.name


async def _run_in_context(fn, *args):
    from app.api.promotion import _run_in_context as run
    return await run(fn, *args)


def _names_for(db, client_id: str, items: List[Dict[str, str]]) -> Dict[tuple, str]:
    """``(rule_id, siem_id, space lower)`` -> rule name for the whole selection in one query, plus
    ``rule_id`` -> name as a fallback when the exact destination no longer matches.

    The progress panel and the per-rule errors are read by a person, so they name the rule.
    Resolving up front means "Working on: …" shows a name while the rule is being processed, not
    only afterwards, and a rule that fails before its name is known still reports as itself.
    """
    from app.services.tenant_manager import tenant_context_for

    if not items:
        return {}
    rule_ids = sorted({i["rule_id"] for i in items})
    placeholders = ",".join("?" for _ in rule_ids)
    try:
        with tenant_context_for(client_id), db.get_connection() as conn:
            rows = conn.execute(
                f"SELECT rule_id, siem_id, space, name FROM detection_rules WHERE rule_id IN ({placeholders})",
                rule_ids,
            ).fetchall()
    except Exception:
        logger.exception("bulk edit: could not resolve rule names for the progress panel")
        return {}
    names: Dict[Any, str] = {}
    for rid, sid, sp, name in rows:
        if name:
            names[(rid, sid or "", str(sp or "default").lower())] = name
            names.setdefault(rid, name)
    return names


def _readable(message: str, item: Dict[str, str], name: str) -> str:
    """Kibana's own error text quotes rule ids; the panel is read by a person, so name the rule."""
    return str(message or "").replace(item["rule_id"], f'"{name}"') if name else str(message or "")


async def _run_job(job: Dict[str, Any], db, user_id: str, username: str, client_id: str,
                   action: str, items: List[Dict[str, str]], opts: Dict[str, Any]) -> None:
    try:
        names = await _run_in_context(_names_for, db, client_id, items)

        def label(item: Dict[str, str]) -> str:
            return (names.get((item["rule_id"], item["siem_id"], item["space"].lower()))
                    or names.get(item["rule_id"]) or "Unnamed rule")

        for item in items:
            if job["cancel"]:
                break
            job["current"] = label(item)
            status, message, name = await _run_in_context(_apply_one, db, action, user_id, username, client_id, item, opts)
            job["current"] = name or label(item)
            job["done"] += 1
            if status == 200:
                job["ok"] += 1
            else:
                job["failed"] += 1
                if len(job["errors"]) < 10:
                    shown = name or label(item)
                    job["errors"].append(f"{shown}: {_readable(message, item, shown)}")
        job["state"] = "cancelled" if job["cancel"] else "done"
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Bulk edit crashed")
        job["state"] = "error"
        job["errors"].append(str(exc))
    finally:
        job["current"] = ""
        # No client-wide sync here: move/enable/disable each refresh exactly the
        # row(s) they touched inside _apply_one (validate never touches Elastic at all).


@router.post("/start", response_class=HTMLResponse)
async def bulk_edit_start(
    request: Request,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    action: str = Form(...),
    items: str = Form("[]"),
    validation: str = Form("keep"),
    delete_source: str = Form(""),
    target_scope: str = Form(""),
    remove_links: str = Form(""),  # an unchecked checkbox sends nothing at all, not "false"
):
    """Re-check the selection, then run ``action`` on it in the background."""
    job = _EDIT_JOBS.get(client_id)
    if job and job["state"] == "running":
        return _render(request, "components/bulk_edit_status.html", {"job": job})
    if action not in ACTIONS:
        return HTMLResponse('<div class="toast toast-danger">Unknown bulk action.</div>', status_code=400)
    parsed = _parse_items(items)
    if not parsed or len(parsed) > MAX_ITEMS:
        return HTMLResponse('<div class="toast toast-danger">Nothing valid to run.</div>', status_code=400)
    why = _eligibility(action, len(parsed))
    if why:
        return HTMLResponse(f'<div class="toast toast-danger">{escape(why)}</div>', status_code=400)

    username = user.name or user.username if user else "Unknown"
    opts: Dict[str, Any] = {
        "delete_source": action == "move" and delete_source.lower() in {"1", "true", "on", "yes"},
        "validation_mode": validation if validation in ("stamp", "keep", "new_only") else "keep",
        "remove_links": remove_links.lower() in {"1", "true", "on", "yes"},
    }
    if action == "move":
        target_siem_id, _, target_space = target_scope.partition("|")
        if not target_siem_id or not target_space:
            return HTMLResponse('<div class="toast toast-danger">Choose a target destination.</div>', status_code=400)
        opts["target_siem_id"], opts["target_space"] = target_siem_id, target_space

    job = {
        "state": "running", "action": action, "label": ACTIONS[action], "total": len(parsed),
        "done": 0, "ok": 0, "failed": 0, "errors": [], "current": "", "cancel": False,
        "started": time.time(),
    }
    _EDIT_JOBS[client_id] = job
    asyncio.get_running_loop().create_task(
        _run_job(job, db, user.id, username, client_id, action, parsed, opts),
        context=contextvars.copy_context(),
    )
    logger.info("Bulk %s started client_id=%s rules=%d opts=%s by %s", action, client_id, len(parsed), opts, username)
    return _render(request, "components/bulk_edit_status.html", {"job": job})


@router.get("/status", response_class=HTMLResponse)
def bulk_edit_status(request: Request, user: RequireUser, client_id: ActiveClient):
    job = _EDIT_JOBS.get(client_id)
    if not job:
        return HTMLResponse("")
    return _render(request, "components/bulk_edit_status.html", {"job": job})


@router.post("/cancel", response_class=HTMLResponse)
def bulk_edit_cancel(request: Request, user: RequireUser, client_id: ActiveClient):
    """Stop after the rule currently being processed."""
    job = _EDIT_JOBS.get(client_id)
    if job and job["state"] == "running":
        job["cancel"] = True
    return _render(request, "components/bulk_edit_status.html", {"job": job or {
        "state": "done", "label": "Bulk edit", "action": "", "total": 0, "done": 0, "ok": 0, "failed": 0,
        "errors": [], "current": "",
    }})
