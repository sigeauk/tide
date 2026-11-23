"""Rule tuning (app.services.rule_tuning): the Rule Tuning page's list, and Record outcome…, Mark as
tuned… and Dismiss…. A dialog opens over the rule's window, and saving brings the window back, saying
what changed, with the rule's card behind it; from the page (``from=page``) saving closes it and the
list refreshes. Reading needs Rule Tuning read, saving its write (main.py's maps).
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional, Tuple

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.api.deps import ActiveClient, DbDep, RequireUser
from app.services import rule_alerts, rule_issues, rule_tuning

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/rule-tuning", tags=["rule-tuning"])

DIALOG = "components/rule_tuning_dialog.html"


def _unknown(what: str, dialog: bool = False) -> HTMLResponse:
    text = f"Could not {what}: that rule is not one of this client's."
    return HTMLResponse(f'<div class="alert alert-danger">{text}</div>' if dialog else f'<p class="inline-error">{text}</p>',
                        status_code=404)


def _rule(db, client_id: str, params) -> Tuple[Optional[Tuple[str, str, str]], Any]:
    """The rule a dialog is for (``rule_id``, ``siem_id``, ``space``), only in one of the client's
    destinations (CLAUDE.md section 6): ``(key, rule)``, or ``(None, None)``."""
    key = tuple(str(params.get(k) or "").strip() for k in ("rule_id", "siem_id", "space"))
    if not all(key) or (key[1], key[2]) not in set(db.get_client_siem_scopes(client_id) or []):
        return None, None
    rule = db.get_rule_by_id(key[0], key[2], siem_id=key[1], client_id=client_id)
    return (key, rule) if rule else (None, None)


def _where(db, client_id: str, key) -> str:
    return next((d.get("name") or d.get("space") for d in db.get_client_siems(client_id) or []
                 if d["id"] == key[1] and str(d.get("space") or "default") == key[2]), key[2])


def _dialog(request: Request, db, client_id: str, mode: str, what: str) -> HTMLResponse:
    key, rule = _rule(db, client_id, request.query_params)
    if not key:
        return _unknown(what, dialog=True)
    ctx: Dict[str, Any] = {"mode": mode, "key": key, "name": rule.name, "where": _where(db, client_id, key),
                           "outcomes": list(rule_tuning.OUTCOMES.values()), "max_alerts": rule_tuning.MAX_ALERTS,
                           "max_note": rule_tuning.MAX_NOTE, "from_page": request.query_params.get("from") == "page"}
    if mode in ("tuned", "dismiss"):
        with db.get_connection() as conn:
            mark = rule_tuning.open_marks(conn, [key]).get(key)
            ctx["changes"] = rule_tuning.changes_since(conn, key, mark["since"]) if mark else []
        if not mark:
            return HTMLResponse('<div class="alert alert-danger">Could not open it: the rule isn\'t marked for '
                                'tuning any more.</div>', status_code=409)
        ctx["mark"] = mark
    return request.app.state.templates.TemplateResponse(request, DIALOG, ctx)


async def _done(request: Request, db, client_id: str, key, user, message: str, form=None) -> HTMLResponse:
    """Find what the change means for Rule Monitoring at once (a mark is listed there), then bring the
    rule's window back, saying so, with its card behind it; from the Rule Tuning page, close the dialog,
    say so and refresh the list."""
    from starlette.concurrency import run_in_threadpool
    from app.api.rules import _modal_with_card_oob
    from app.config import get_settings
    await run_in_threadpool(rule_issues.refresh_tenant, db, client_id, None, [key])
    if form is not None and form.get("from") == "page":
        return HTMLResponse("", headers={"HX-Trigger": json.dumps(
            {"tuningChanged": None, "showToast": {"message": message, "type": "success"}})})
    rule = db.get_rule_by_id(key[0], key[2], siem_id=key[1], client_id=client_id)
    return _modal_with_card_oob(request, db, client_id, rule, key[2], key[1], get_settings(), flash=message, user=user)


def _history(db, client_id: str, key, user, action: str, message: str) -> None:
    try:
        db.record_rule_history(rule_id=key[0], siem_id=key[1], space=key[2], client_id=client_id, action=action,
                               actor_user_id=user.id if user else None, actor_name=user.label if user else "Unknown",
                               detail={"message": message})
    except Exception:
        logger.exception("Rule tuning: History not written for %s", key)


@router.get("/record-form", response_class=HTMLResponse)
def record_form(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """Record outcome…: an outcome, how many alerts, a note, and whether the rule needs tuning."""
    return _dialog(request, db, client_id, "record", "record an outcome")


@router.post("/record", response_class=HTMLResponse)
async def record(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    form = await request.form()
    key, _rule_found = _rule(db, client_id, form)
    if not key:
        return _unknown("record it")
    fields, why = rule_tuning.check(str(form.get("outcome") or ""), form.get("alerts"), form.get("note"))
    if not fields:
        return HTMLResponse(f'<p class="inline-error">Could not record it: {why[0].lower() + why[1:]}</p>', status_code=400)
    outcome, alerts, note = fields
    needs = bool(form.get("needs_tuning"))
    by = user.label if user else "Unknown"
    with db.get_connection() as conn:
        done = rule_tuning.record(conn, key, outcome, alerts, note, needs, by)
    _history(db, client_id, key, user, "marked_for_tuning" if done == "marked" else "outcome_recorded",
             rule_tuning.record_text(outcome, alerts, note, needs))
    logger.info("Rule tuning: %s recorded %s x%d on %s (%s)", by, outcome, alerts, key, done)
    return await _done(request, db, client_id, key, user, {
        "marked": "Outcome recorded, and the rule is marked for tuning.",
        "added": "Outcome recorded, and added to the rule's mark for tuning.",
        "recorded": "Outcome recorded."}[done], form)


@router.get("/tuned-form", response_class=HTMLResponse)
def tuned_form(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """Mark as tuned…: the changes History recorded since the rule was marked, and a note."""
    return _dialog(request, db, client_id, "tuned", "mark it as tuned")


@router.post("/tuned", response_class=HTMLResponse)
async def mark_tuned(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    form = await request.form()
    key, _rule_found = _rule(db, client_id, form)
    if not key:
        return _unknown("mark it as tuned")
    note = str(form.get("note") or "").strip()[:rule_tuning.MAX_NOTE]
    by = user.label if user else "Unknown"
    with db.get_connection() as conn:
        kept = rule_tuning.tuned(conn, key, by, note, limits=rule_alerts.thresholds(db, client_id))
    if not kept:
        return HTMLResponse('<p class="inline-error">Could not mark it as tuned: it isn\'t marked for tuning any '
                            'more.</p>', status_code=409)
    changes = "; ".join(c["text"] for c in kept["changes"])
    _history(db, client_id, key, user, "tuned", "Marked as tuned." + (f" Changes since it was marked: {changes}." if changes
                                                                      else "") + (f" {note}" if note else ""))
    logger.info("Rule tuning: %s marked %s as tuned", by, key)
    return await _done(request, db, client_id, key, user,
                       f"Marked as tuned. Its window shows the effect after {rule_tuning.EFFECT_DAYS} days.", form)


@router.get("/dismiss-form", response_class=HTMLResponse)
def dismiss_form(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """Dismiss…: close the mark with no change, saying why."""
    return _dialog(request, db, client_id, "dismiss", "dismiss it")


@router.post("/dismiss", response_class=HTMLResponse)
async def dismiss(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    form = await request.form()
    key, _rule_found = _rule(db, client_id, form)
    if not key:
        return _unknown("dismiss it")
    note = str(form.get("note") or "").strip()[:rule_tuning.MAX_NOTE]
    if not note:
        return HTMLResponse('<p class="inline-error">Could not dismiss it: say why it needs no change.</p>', status_code=400)
    by = user.label if user else "Unknown"
    with db.get_connection() as conn:
        closed = rule_tuning.close(conn, key, "dismissed", by, note)
    if not closed:
        return HTMLResponse('<p class="inline-error">Could not dismiss it: it isn\'t marked for tuning any more.</p>',
                            status_code=409)
    _history(db, client_id, key, user, "tuning_dismissed", f"Dismissed: no change needed. {note}")
    logger.info("Rule tuning: %s dismissed the mark on %s", by, key)
    return await _done(request, db, client_id, key, user, "Mark dismissed.", form)


# ── the Rule Tuning page ─────────────────────────────────────────────────────────────────────

def page_context(db, client_id: str, params, user=None) -> Dict[str, Any]:
    """The page's filters, their choices and what they show (rule_tuning.page). ``can_tune``: the user may
    mark rules as tuned; ``can_fix``: mute them (who can change Rule Health)."""
    filters = rule_tuning.page_filters(params)
    destinations = db.get_client_siems(client_id) or []
    with db.get_connection() as conn:
        data = rule_tuning.page(conn, destinations, filters, client_id=client_id,
                                limits=rule_alerts.thresholds(db, client_id))
    issues = rule_issues.KNOWN
    return {
        "filters": filters, "filter_defaults": rule_tuning.PAGE_DEFAULTS, **data, "client_siems": destinations,
        "scope_options": [("", "Any")] + [(f"{d['id']}|{d.get('space') or 'default'}", d.get("name") or d.get("space"))
                                          for d in destinations],
        "reason_options": rule_tuning.reason_options(),
        "reason_titles": {k: issues[k].meaning for k, _ in rule_tuning.reason_options()},
        "fixer_options": list(rule_issues.FIXERS.items()), "source_options": list(rule_tuning.SOURCES),
        "show_options": list(rule_tuning.SHOW), "sort_options": list(rule_tuning.SORTS),
        "can_tune": not user or user.can_write("page:rule_tuning"), "can_fix": not user or user.can_write("page:rules"),
        # What every request from the page sends along: the filter bar's fields only.
        "filter_include": ", ".join(f"#rtune-filters [name='{n}']" for n in
                                    ("search", "scope", "issue", "fixer", "source", "show", "sort")),
    }


@router.get("/list", response_class=HTMLResponse)
def tuning_list(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """The list for the filter bar's choices, with the figures (out of band) and the number beside each
    filter choice (``filterCounts``, which app.js puts in the filter bar)."""
    ctx = page_context(db, client_id, request.query_params, user)
    response = request.app.state.templates.TemplateResponse(request, "partials/rule_tuning_list.html", {**ctx, "oob": True})
    response.headers["HX-Trigger"] = json.dumps({"filterCounts": {"issue": ctx["counts"]["reason"], "fixer": ctx["counts"]["fixer"],
                                                                  "source": ctx["counts"]["source"]}})
    return response
