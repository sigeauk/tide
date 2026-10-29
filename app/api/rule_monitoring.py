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
from app.services import gitlab_issues, rule_issues

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
        "fixer": rule_issues.fixer_values(params.getlist("fixer")),
        "issue": many("issue", set(rule_issues.KNOWN)),
        "rules": one("rules", rule_issues.RULES, "enabled"),
        "show": one("show", rule_issues.SHOW, "open"),
        "group": one("group", rule_issues.GROUPS, "issue"),
    }


# A group with more rules than this loads them once it is open and in view (``rows``), so a long list
# doesn't draw thousands of rules nobody opens; smaller groups come with the page and open at once.
INLINE_ROWS = 25


def _mark_lazy(groups: List[Dict[str, Any]]) -> None:
    for node in groups:
        node["lazy"] = not node["children"] and len(node["rows"]) > INLINE_ROWS
        _mark_lazy(node["children"])


def page_context(db, client_id: str, params, user=None) -> Dict[str, Any]:
    """The filters, their choices, and what they show; ``can_fix``: the user may acknowledge, sync and
    fix (who can edit Rule Health)."""
    filters = filters_from(params)
    destinations: List[Dict[str, Any]] = db.get_client_siems(client_id) or []
    with db.get_connection() as conn:
        data = rule_issues.view(conn, destinations, filters, client_id=client_id)
        raised = gitlab_issues.by_cause(conn)
    rule_issues.remember_keys(data["groups"], f"rmon.{filters['group']}")
    _mark_lazy(data["groups"])
    # Each cause shows the GitLab issues raised for it (Raise in GitLab, in Raise issue):
    # open ones, and those closed in the last few days.
    for node in _causes(data["groups"]):
        found = {i["id"]: i for k in _keys([node]) for i in raised.get(k, []) if gitlab_issues.shown(i)}
        node["gitlab_issues"] = sorted(found.values(), key=lambda i: i["created_at"], reverse=True)
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
    """The grouped list for the filter bar's choices, with the stat cards (out of band) and the number
    beside each filter choice (the ``filterCounts`` event, which app.js puts in the filter bar)."""
    ctx = page_context(db, client_id, request.query_params, user)
    response = request.app.state.templates.TemplateResponse(
        request, "partials/rule_monitoring_list.html", {**ctx, "oob": True})
    response.headers["HX-Trigger"] = json.dumps({"filterCounts": ctx["counts"]})
    return response


@router.get("/rows", response_class=HTMLResponse)
def rows(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """A group's own body (a cause's actions and rules, or a rule's findings) when it is first opened:
    ``at`` is the group's ``mem``, with the filter bar's choices, so it lists what the group counted."""
    ctx = page_context(db, client_id, request.query_params, user)
    node = rule_issues.node_at(ctx["groups"], request.query_params.get("at") or "", field="mem")
    return request.app.state.templates.TemplateResponse(
        request, "partials/rule_monitoring_rows.html", {**ctx, "node": node})


def _causes(groups: List[Dict[str, Any]], with_acknowledged: bool = True) -> List[Dict[str, Any]]:
    """Every cause node under ``groups``, in the order shown."""
    out = []
    for node in groups:
        if node["kind"] == "acknowledged" and not with_acknowledged:
            continue
        out += [node] if node["kind"] == "cause" else _causes(node["children"], with_acknowledged)
    return out


def _keys(nodes: List[Dict[str, Any]]) -> List[tuple]:
    """The cause keys (rule_issues.causes_from's) of cause nodes: one per SIEM record."""
    return [(n["issue"], n["cause"], s, n["space"]) for n in nodes for s in n["siem_ids"]]


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


def _selection(db, client_id: str, params, user) -> Dict[str, Any]:
    """What Raise issue (and Raise in GitLab) is for: one cause (issue, cause, siem_id, space);
    one issue as it is listed (``node``: its path, as JSON), every cause of it; or with ``all`` every
    issue the filter bar shows that isn't acknowledged. ``for``: who it is for, where either role may
    fix an issue in it (``rule_issues.audiences``; the first by default). ``params`` is the dialog's
    query string, or the same fields posted back. Returns its cause nodes, their Markdown and the
    page's context."""
    ctx = page_context(db, client_id, params, user)
    every = params.get("all") == "1"
    issue = None
    if every:
        nodes = _causes(ctx["groups"], with_acknowledged=False)
    elif params.get("node"):
        try:
            issue = rule_issues.node_at(ctx["groups"], json.loads(params["node"]))
        except ValueError:
            issue = None
        nodes = _causes([issue]) if issue else []
    else:
        keys = set(rule_issues.causes_from(params))
        nodes = [n for n in _causes(ctx["groups"]) if keys and set(_keys([n])) == keys]
    labels = {d["id"]: d.get("label") or d.get("name") or d["id"] for d in ctx["client_siems"]}
    # Kibana names a field Elasticsearch can't find, not where: the rules' own index patterns say.
    unknown = [(f["rule_id"], f["siem_id"], f["space"]) for n in nodes if n["issue"] == "unknown_field"
               for f in n["rows"] if f["rule_id"]]
    patterns = {}
    if unknown:
        with db.get_connection() as conn:
            patterns = rule_issues.rule_patterns(conn, unknown)
    audiences = rule_issues.audiences(nodes)
    audience = params.get("for") if params.get("for") in audiences else (audiences[0] if audiences else "")
    text = rule_issues.markdown(nodes, labels, ctx["now"], patterns, audience) if nodes else ""
    return {"ctx": ctx, "nodes": nodes, "text": text, "every": every, "issue": issue["label"] if issue else "",
            "causes": len(nodes), "issues": len({n["issue"] for n in nodes}),
            "audiences": [(a, rule_issues.FIXERS[a]) for a in audiences], "audience": audience}


def _title(sel: Dict[str, Any]) -> str:
    """A GitLab issue's title for a selection: the cause's own heading, or what it covers."""
    if sel["every"]:
        return f"Rule Monitoring: {sel['issues']} issues, {sel['causes']} causes"
    if sel["issue"]:
        return f"{sel['issue']}: {sel['causes']} {'cause' if sel['causes'] == 1 else 'causes'}"
    first = next((line for line in sel["text"].splitlines() if line.strip()), "Rule Monitoring")
    return first.lstrip("#").replace("`", "").strip()


def _raised(db, client_id: str, keys: List[tuple]) -> List[Dict[str, Any]]:
    """The issues raised for any of ``keys``, as GitLab has them now (as they were, when GitLab
    doesn't answer); ``usable``: one TIDE can comment on."""
    with db.get_connection() as conn:
        found = gitlab_issues.for_causes(conn, keys)
    reached = gitlab_issues.refresh(db, client_id, found)
    for i in found:
        i["usable"] = i["id"] in reached and i["state"] != "deleted"
    return found


def _footer(user, now) -> str:
    from app.config import get_settings
    who = user.label if user else "TIDE"
    return (f"\n\n---\nRaised from TIDE's Rule Monitoring by {who} on {now:%Y-%m-%d %H:%M}: "
            f"{get_settings().app_url.rstrip('/')}/rule-monitoring")


@router.get("/copy", response_class=HTMLResponse)
def copy_markdown(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """Raise issue: the Markdown in a dialog, to copy (``_selection``); For picks who it is for, and
    opens it again for them. Who can fix (``can_fix``) can also raise it as an issue in one of the
    client's GitLab issues projects, or comment on an issue already raised for it."""
    sel = _selection(db, client_id, request.query_params, user)
    selection = [(k, v) for k, v in request.query_params.multi_items() if k != "for"]
    if sel["audience"]:
        selection.append(("for", sel["audience"]))
    gitlab = {}
    if sel["ctx"]["can_fix"] and sel["nodes"]:
        gitlab = {"projects": gitlab_issues.usable_projects(db, client_id), "raised": _raised(db, client_id, _keys(sel["nodes"])),
                  "title": _title(sel), "labels": "TIDE", "selection": selection}
    return request.app.state.templates.TemplateResponse(request, "components/rule_monitoring_copy.html", {
        **{k: sel[k] for k in ("text", "every", "issue", "causes", "issues", "audiences", "audience")},
        "selection": [(k, v) for k, v in selection if k != "for"], "gitlab": gitlab})


def _gitlab_done(request: Request, html: str, kind: str = "success") -> HTMLResponse:
    """The dialog's GitLab part after raising or commenting: what happened; the list redraws."""
    response = HTMLResponse(f'<div class="rmon-gitlab__result alert alert-{kind}">{html}</div>')
    if kind == "success":
        response.headers["HX-Trigger"] = json.dumps({"rmonChanged": None})
    return response


@router.post("/gitlab-issue", response_class=HTMLResponse)
async def raise_gitlab_issue(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """Raise what Raise issue shows (the posted selection) as an issue in the chosen GitLab
    issues project; TIDE keeps which causes it was raised for (gitlab_issues)."""
    from html import escape
    from starlette.concurrency import run_in_threadpool
    from app.services import gitlab
    form = await request.form()
    sel = await run_in_threadpool(_selection, db, client_id, form, user)
    if not sel["ctx"]["can_fix"]:
        return _gitlab_done(request, "You can't raise issues: it needs the right to change Rule Health.", "danger")
    link = next((p for p in gitlab_issues.usable_projects(db, client_id) if p["id"] == form.get("link_id")), None)
    if not link or not sel["nodes"]:
        return _gitlab_done(request, "Nothing raised: choose one of the client's GitLab issues projects, and "
                                     "something Rule Monitoring still lists.", "danger")
    title = str(form.get("title") or "").strip() or _title(sel)
    labels = [s.strip() for s in str(form.get("labels") or "").split(",") if s.strip()]
    assignee = str(form.get("assignee_id") or "").strip()
    assignee_id = int(assignee) if assignee.isdigit() else None
    try:
        issue = await run_in_threadpool(gitlab.create_issue, link, title,
                                        sel["text"] + _footer(user, sel["ctx"]["now"]), labels, assignee_id)
    except gitlab.GitLabError as exc:
        return _gitlab_done(request, f"Nothing raised. {escape(str(exc))}", "danger")
    with db.get_connection() as conn:
        gitlab_issues.record(conn, link, issue, title, _keys(sel["nodes"]), user.label if user else "TIDE")
    logger.info("Rule Monitoring: %s raised GitLab issue %s#%s for %d cause(s)", user.label if user else "TIDE",
                link["project"], issue["iid"], sel["causes"])
    to = (f", assigned to {escape(issue['assignee_name'] or issue['assignee'])}" if issue.get("assignee")
          else ". GitLab didn't assign it: that person may no longer be able to see the project" if assignee_id else "")
    return _gitlab_done(request, f'Raised <a href="{escape(issue["web_url"] or "")}" target="_blank" rel="noopener">'
                                 f'{escape(link["project"])}#{issue["iid"]}</a>: {escape(title)}{to}.')


@router.get("/gitlab-members", response_class=HTMLResponse)
async def gitlab_members(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """Raise in GitLab's Assign to: the people in the chosen issues project (``link_id``) an issue
    can be assigned to, Nobody first and chosen. For who can fix only."""
    from starlette.concurrency import run_in_threadpool
    from app.services import gitlab
    members, error = [], ""
    link = next((p for p in gitlab_issues.usable_projects(db, client_id)
                 if p["id"] == request.query_params.get("link_id")), None)
    if user and not user.can_write("page:rules"):
        error = "assigning needs the right to change Rule Health."
    elif link:
        try:
            members = await run_in_threadpool(gitlab.project_members, link)
        except gitlab.GitLabError as exc:
            error = str(exc)
    return request.app.state.templates.TemplateResponse(request, "partials/rule_monitoring_assignees.html",
                                                        {"members": members, "error": error})


@router.post("/gitlab-comment", response_class=HTMLResponse)
async def comment_gitlab_issue(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """Comment on an issue already raised for this selection, with what Rule Monitoring finds now."""
    from html import escape
    from starlette.concurrency import run_in_threadpool
    from app.services import gitlab
    form = await request.form()
    sel = await run_in_threadpool(_selection, db, client_id, form, user)
    if not sel["ctx"]["can_fix"]:
        return _gitlab_done(request, "You can't comment on issues: it needs the right to change Rule Health.", "danger")
    with db.get_connection() as conn:
        raised = gitlab_issues.get(conn, str(form.get("raised_id") or ""))
    link = gitlab_issues.project_for(gitlab_issues.usable_projects(db, client_id), raised) if raised else None
    if not raised or not link or not sel["nodes"] or not set(raised["causes"]) & set(_keys(sel["nodes"])):
        return _gitlab_done(request, "No comment added: that issue isn't one raised for this.", "danger")
    text = (f"Still found by TIDE on {sel['ctx']['now']:%Y-%m-%d %H:%M}:\n\n{sel['text']}"
            + _footer(user, sel["ctx"]["now"]))
    try:
        await run_in_threadpool(gitlab.add_comment, link, raised["iid"], text)
    except gitlab.GitLabError as exc:
        return _gitlab_done(request, f"No comment added. {escape(str(exc))}", "danger")
    with db.get_connection() as conn:
        gitlab_issues.commented(conn, raised["id"])
    return _gitlab_done(request, f'Commented on <a href="{escape(raised["web_url"] or "")}" target="_blank" '
                                 f'rel="noopener">{escape(raised["project"])}#{raised["iid"]}</a> with what TIDE finds now.')
