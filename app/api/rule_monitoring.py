"""Rule Monitoring (#67): the rules that need action, grouped by what causes it and who fixes it.

The page (``/rule-monitoring``, main.py) and its list share ``page_context``. What is listed is found
at each sync (``app.services.rule_issues``); this only reads it, for the active client.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.api.deps import ActiveClient, DbDep, RequireUser
from app.services import rule_issues

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/rule-monitoring", tags=["rule-monitoring"])


def filters_from(params) -> Dict[str, Any]:
    """The page's filters from a query string (the page's address, or the filter bar)."""
    def one(name, choices, default):
        value = params.get(name) or default
        return value if value in {c for c, _ in choices} else default

    def many(name, allowed):
        return [v for v in params.getlist(name) if v in allowed]

    return {
        "search": (params.get("search") or "").strip(),
        "scope": params.get("scope") or "",
        "severity": many("severity", {s for s, _ in rule_issues.SEVERITIES}),
        "fixer": many("fixer", set(rule_issues.FIXERS)),
        "issue": many("issue", set(rule_issues.KNOWN)),
        "rules": one("rules", rule_issues.RULES, "enabled"),
        "show": one("show", rule_issues.SHOW, "open"),
        "group": one("group", rule_issues.GROUPS, "issue"),
    }


def page_context(db, client_id: str, params, user=None) -> Dict[str, Any]:
    """The filters, their choices, and what they show; ``can_fix``: the user may acknowledge, sync and
    fix (who can edit Rule Health)."""
    filters = filters_from(params)
    destinations: List[Dict[str, Any]] = db.get_client_siems(client_id) or []
    with db.get_connection() as conn:
        data = rule_issues.view(conn, destinations, filters)
    issues = sorted(rule_issues.KNOWN.values(), key=lambda i: i.title)
    return {
        "filters": filters, **data,
        "client_siems": destinations,
        "scope_options": [("", "All SIEMs")] + [(f"{d['id']}|{d.get('space') or 'default'}", d.get("name") or d.get("space"))
                                                for d in destinations],
        "severity_options": list(rule_issues.SEVERITIES),
        "fixer_options": list(rule_issues.FIXERS.items()),
        "issue_options": [(i.id, i.title) for i in issues],
        "issue_titles": {i.id: i.meaning for i in issues},
        "rules_options": list(rule_issues.RULES),
        "show_options": list(rule_issues.SHOW),
        "group_options": list(rule_issues.GROUPS),
        "stale_days": rule_issues.STALE_DAYS,
        "can_fix": not user or user.can_write("page:rules"),
        # What every request from the page sends along: the filter bar's fields only (a dialog's
        # fields can share their names: Acknowledge's issue, cause).
        "filter_include": ", ".join(f"#rmon-filters [name='{n}']" for n in
                                    ("search", "scope", "severity", "fixer", "issue", "rules", "show", "group")),
    }


@router.get("/list", response_class=HTMLResponse)
def monitoring_list(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """The grouped list for the filter bar's choices, with the stat cards (out of band)."""
    return request.app.state.templates.TemplateResponse(
        request, "partials/rule_monitoring_list.html", {**page_context(db, client_id, request.query_params, user), "oob": True})


def _causes(groups: List[Dict[str, Any]], with_acknowledged: bool = True) -> List[Dict[str, Any]]:
    """Every cause node under ``groups``, in the order shown."""
    out = []
    for node in groups:
        if node["kind"] == "acknowledged" and not with_acknowledged:
            continue
        out += [node] if node["kind"] == "cause" else _causes(node["children"], with_acknowledged)
    return out


def _changed(message: str) -> HTMLResponse:
    """Close the dialog, say what happened, and refresh the list."""
    return HTMLResponse("", headers={"HX-Trigger": json.dumps(
        {"rmonChanged": None, "showToast": {"message": message, "type": "success"}})})


@router.get("/ack-form", response_class=HTMLResponse)
def ack_form(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """The Acknowledge dialog for one cause (on one or more SIEM records of one cluster)."""
    keys = rule_issues.causes_from(request.query_params)
    if not keys:
        return HTMLResponse('<div class="alert alert-danger">Could not acknowledge it: that issue is not known.</div>',
                            status_code=400)
    issue, cause, _s, space = keys[0]
    return request.app.state.templates.TemplateResponse(request, "components/rule_monitoring_ack.html", {
        "issue": issue, "cause": cause, "space": space, "siem_ids": ",".join(k[2] for k in keys),
        "title": rule_issues.KNOWN[issue].title, "label": request.query_params.get("label") or cause})


@router.post("/ack", response_class=HTMLResponse)
async def acknowledge(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """Acknowledge (mute) a cause until it affects more rules than it does now."""
    form = await request.form()
    keys = rule_issues.causes_from(form)
    if not keys:
        return HTMLResponse('<p class="inline-error">Could not acknowledge it: that issue is not known.</p>', status_code=400)
    actor = user.label if user else "Unknown"
    with db.get_connection() as conn:
        for key in keys:
            rule_issues.acknowledge(conn, key, str(form.get("note") or ""), actor)
    logger.info("Rule Monitoring: %s acknowledged %s", actor, keys)
    return _changed("Acknowledged. It comes back if it starts affecting more rules.")


@router.post("/unack", response_class=HTMLResponse)
async def unacknowledge(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """Unmute a cause: it is listed with the rest again."""
    keys = rule_issues.causes_from(await request.form())
    if not keys:
        return HTMLResponse("", status_code=400)
    with db.get_connection() as conn:
        for key in keys:
            rule_issues.unacknowledge(conn, key)
    logger.info("Rule Monitoring: %s unmuted %s", user.label if user else "Unknown", keys)
    return _changed("Unmuted.")


@router.get("/copy", response_class=HTMLResponse)
def copy_markdown(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """Copy for engineers: one cause (issue, cause, siem_id, space), or with ``all`` every cause the
    filter bar shows that isn't acknowledged, as Markdown in a dialog to copy."""
    ctx = page_context(db, client_id, request.query_params, user)
    every = request.query_params.get("all") == "1"
    nodes = _causes(ctx["groups"], with_acknowledged=not every)
    if not every:
        keys = set(rule_issues.causes_from(request.query_params))
        nodes = [n for n in nodes if keys and {(n["issue"], n["cause"], s, n["space"]) for s in n["siem_ids"]} == keys]
    labels = {d["id"]: d.get("label") or d.get("name") or d["id"] for d in ctx["client_siems"]}
    text = rule_issues.markdown(nodes, labels, ctx["now"]) if nodes else ""
    return request.app.state.templates.TemplateResponse(request, "components/rule_monitoring_copy.html", {
        "text": text, "count": len(nodes), "every": every})
