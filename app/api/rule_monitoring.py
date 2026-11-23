"""Rule Monitoring (#67): the rules that need action, grouped by what causes it and who fixes it.

The page (``/rule-monitoring``, main.py) and its list share ``page_context``. What is listed is found
at each sync (``app.services.rule_issues``); this only reads it, for the active client.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.api.deps import ActiveClient, DbDep, RequireUser
from app.services import gitlab_issues, rule_alerts, rule_issues

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/rule-monitoring", tags=["rule-monitoring"])


# The one-choice filters' defaults; the bar's Filters fold counts a choice only when it isn't its default.
DEFAULTS = {"rules": "enabled", "show": "open", "group": "issue"}


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
        "kind": many("kind", {k for k, _ in rule_issues.KINDS}),
        "rules": one("rules", rule_issues.RULES, DEFAULTS["rules"]),
        "show": one("show", rule_issues.SHOW, DEFAULTS["show"]),
        "group": one("group", rule_issues.GROUPS, DEFAULTS["group"]),
    }


# A group with more rules than this loads them once it is open and in view (``rows``), so a long list
# doesn't draw thousands of rules nobody opens; smaller groups come with the page and open at once.
INLINE_ROWS = 25


def _mark_lazy(groups: List[Dict[str, Any]]) -> None:
    for node in groups:
        node["lazy"] = not node["children"] and len(node["rows"]) > INLINE_ROWS
        _mark_lazy(node["children"])


def page_context(db, client_id: str, params, user=None) -> Dict[str, Any]:
    """The filters, their choices, and what they show; ``can_fix``: the user may mute, sync and
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
        "filters": filters, "filter_defaults": DEFAULTS, **data,
        "client_siems": destinations,
        "scope_options": [("", "Any")] + [(f"{d['id']}|{d.get('space') or 'default'}", d.get("name") or d.get("space"))
                                                for d in destinations],
        "severity_options": list(rule_issues.SEVERITIES),
        "kind_options": list(rule_issues.KINDS),
        "fixer_options": list(rule_issues.FIXERS.items()),
        "issue_options": [(i.id, i.title) for i in issues],
        "issue_titles": {i.id: i.meaning for i in issues},
        "rules_options": list(rule_issues.RULES),
        "show_options": list(rule_issues.SHOW),
        "group_options": list(rule_issues.GROUPS),
        "stale_days": rule_issues.STALE_DAYS,
        "can_fix": not user or user.can_write("page:rules"),
        # What every request from the page sends along: the filter bar's fields only (a dialog's
        # fields can share their names: the Mute dialog's issue, cause).
        "filter_include": ", ".join(f"#rmon-filters [name='{n}']" for n in
                                    ("search", "scope", "kind", "severity", "fixer", "issue", "rules", "show", "group")),
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


def _causes(groups: List[Dict[str, Any]], with_muted: bool = True) -> List[Dict[str, Any]]:
    """Every cause node under ``groups``, in the order shown."""
    out = []
    for node in groups:
        if node["kind"] == "muted" and not with_muted:
            continue
        out += [node] if node["kind"] == "cause" else _causes(node["children"], with_muted)
    return out


def _keys(nodes: List[Dict[str, Any]]) -> List[tuple]:
    """The cause keys (rule_issues.causes_from's) of cause nodes: one per SIEM record."""
    return [(n["issue"], n["cause"], s, n["space"]) for n in nodes for s in n["siem_ids"]]


def _changed(message: str, request: Optional[Request] = None, db=None, client_id: str = "",
             form=None) -> HTMLResponse:
    """Close the dialog, say what happened, and refresh the list. Muted or unmuted from a rule's window
    (``X-Return-Modal: rule``, #106): the window again, saying so, with its card behind it."""
    if request is not None and request.headers.get("X-Return-Modal") == "rule" and _rule_of(form or {}):
        rule_id, siem_id, space = _rule_of(form)
        rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)
        if rule is not None:
            from app.api.rules import _modal_with_card_oob
            from app.config import get_settings
            return _modal_with_card_oob(request, db, client_id, rule, space, siem_id, get_settings(), flash=message)
    return HTMLResponse("", headers={"HX-Trigger": json.dumps(
        {"rmonChanged": None, "showToast": {"message": message, "type": "success"}})})


def _cause_of(params) -> List[tuple]:
    """The cause keys a Mute dialog names: ``cause_siem_ids`` (comma-separated, the SIEM records of
    one cluster), with the issue, cause and space."""
    return rule_issues.causes_from({"issue": params.get("issue"), "cause": params.get("cause"),
                                    "space": params.get("space"), "siem_id": params.get("cause_siem_ids")})


@router.get("/mute-form", response_class=HTMLResponse)
def mute_form(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """The Mute dialog. From a rule's row (``rule_id``): this problem on the rule, every problem it has,
    or the problem's cause on every rule it affects; from a cause (``scope=cause``, ``cause_siem_ids``),
    the cause only."""
    p = request.query_params
    rule = None if p.get("scope") == "cause" else rule_issues.mute_from(p)
    keys = (rule_issues.causes_from({**p, "siem_id": rule[1]}) if rule and rule[3] else
            _cause_of(p) if not rule else [])
    if not keys:
        return HTMLResponse('<div class="alert alert-danger">Could not mute it: that rule or issue is not known.</div>',
                            status_code=400)
    with db.get_connection() as conn:
        scope = rule_issues.cause_scope(conn, db.get_client_siems(client_id) or [], keys)
    issue, cause, _s, space = keys[0]
    return request.app.state.templates.TemplateResponse(request, "components/rule_monitoring_mute.html", {
        "issue": issue, "cause": cause, "space": rule[2] if rule else space,
        "cause_siem_ids": ",".join(k[2] for k in scope["keys"]), "rules": scope["rules"], "cause_muted": scope["muted"],
        "title": rule_issues.KNOWN[issue].title, "label": p.get("label") or cause or p.get("where") or "",
        "rule_id": rule[0] if rule else "", "siem_id": rule[1] if rule else "",
        "name": p.get("name") or (rule[0] if rule else ""), "where": p.get("where") or "",
        # From a rule's window (#106): it opens over the window, and muting brings the window back.
        "from_window": p.get("from") == "window"})


@router.post("/mute", response_class=HTMLResponse)
async def mute(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """Mute, as the dialog's ``scope`` says: ``problem``, one rule's problem, or ``rule``, every problem
    it has, until it is unmuted; ``cause``, a cause on every rule it affects, until it affects more."""
    form = await request.form()
    scope, note = form.get("scope") or "problem", str(form.get("note") or "")
    actor = user.label if user else "Unknown"
    if scope == "cause":
        keys = _cause_of(form)
        if not keys:
            return HTMLResponse('<p class="inline-error">Could not mute it: that issue is not known.</p>', status_code=400)
        with db.get_connection() as conn:
            for key in keys:
                rule_issues.mute_cause(conn, key, note, actor)
        logger.info("Rule Monitoring: %s muted the cause %s", actor, keys)
        return _changed("Cause muted. It comes back if it starts affecting more rules.", request, db, client_id, form)
    key = rule_issues.mute_from(form)
    if not key:
        return HTMLResponse('<p class="inline-error">Could not mute it: that rule or issue is not known.</p>', status_code=400)
    with db.get_connection() as conn:
        rule_issues.mute(conn, key, note, actor)
    logger.info("Rule Monitoring: %s muted the rule %s", actor, key)
    return _changed("Rule muted for this problem until you unmute it." if key[3]
                    else "Rule muted for every problem, now and later, until you unmute it.", request, db, client_id, form)


@router.post("/unmute-cause", response_class=HTMLResponse)
async def unmute_cause(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """Unmute a cause: it is listed with the rest again."""
    keys = rule_issues.causes_from(await request.form())
    if not keys:
        return HTMLResponse("", status_code=400)
    with db.get_connection() as conn:
        for key in keys:
            rule_issues.unmute_cause(conn, key)
    logger.info("Rule Monitoring: %s unmuted the cause %s", user.label if user else "Unknown", keys)
    return _changed("Cause unmuted.")


@router.post("/unmute", response_class=HTMLResponse)
async def unmute_rule(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """Unmute a rule's problem (or every problem it has, as it was muted): listed with the rest again."""
    form = await request.form()
    key = rule_issues.mute_from(form)
    if not key:
        return HTMLResponse("", status_code=400)
    with db.get_connection() as conn:
        rule_issues.unmute(conn, key)
    logger.info("Rule Monitoring: %s unmuted the rule %s", user.label if user else "Unknown", key)
    return _changed("Rule unmuted.", request, db, client_id, form)


def _pattern_siems(db, client_id: str, params) -> List[str]:
    """The SIEM records (of the client's) a window dialog's ``cause_siem_ids`` names."""
    linked = {d["id"] for d in db.get_client_siems(client_id) or []}
    return sorted({s.strip() for s in str(params.get("cause_siem_ids") or "").split(",") if s.strip() in linked})


@router.get("/window-form", response_class=HTMLResponse)
def window_form(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """Expect new data every…, on a "No recent events in the index pattern" cause (``pattern``,
    ``cause_siem_ids``): how often new events are expected in the pattern, with its window now."""
    from app.services import data_freshness as df
    p = request.query_params
    pattern, siem_ids = str(p.get("pattern") or ""), _pattern_siems(db, client_id, p)
    if not (pattern and siem_ids):
        return HTMLResponse('<div class="alert alert-danger">Could not open it: that index pattern is not known.</div>',
                            status_code=400)
    with db.get_connection() as conn:
        own = next((w for s in siem_ids if (w := df.windows(conn).get((s, pattern)))), None)
    hours = own["hours"] if own and own["hours"] else df.default_hours(db, client_id)
    days = hours >= 48 and hours % 24 == 0
    return request.app.state.templates.TemplateResponse(request, "components/rule_monitoring_window.html", {
        "pattern": pattern, "cause_siem_ids": ",".join(siem_ids), "label": p.get("label") or pattern, "own": own,
        "default": df.hours_text(df.default_hours(db, client_id)),
        "every": hours // 24 if days else hours, "unit": "days" if days else "hours"})


@router.post("/window", response_class=HTMLResponse)
async def set_window(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """Save how often new events are expected in an index pattern (``expect``: ``client``, ``every``
    with ``every`` and ``unit``, or ``none``), then find what that changes in the client's rules."""
    from starlette.concurrency import run_in_threadpool
    from app.services import data_freshness as df
    form = await request.form()
    pattern, siem_ids = str(form.get("pattern") or ""), _pattern_siems(db, client_id, form)
    if not (pattern and siem_ids):
        return HTMLResponse('<p class="inline-error">Could not save it: that index pattern is not known.</p>', status_code=400)
    expect = form.get("expect") or "client"
    hours = df.NOT_EXPECTED if expect == "none" else None       # None: the client's window
    if expect == "every":
        try:
            hours = int(form.get("every") or 0) * (24 if form.get("unit") == "days" else 1)
        except ValueError:
            hours = 0
        if not 1 <= hours <= df.MAX_HOURS:
            return HTMLResponse('<p class="inline-error">Could not save it: give a number of hours or days, up to a year.</p>',
                                status_code=400)
    actor = user.label if user else "Unknown"
    with db.get_connection() as conn:
        df.set_window(conn, siem_ids, pattern, hours, str(form.get("note") or ""), actor)
    scopes = [(s, sp) for s, sp in db.get_client_siem_scopes(client_id) or [] if s in siem_ids]
    await run_in_threadpool(rule_issues.refresh_tenant, db, client_id, scopes)
    logger.info("Rule Monitoring: %s set new data expected in %s on %s to %s", actor, pattern, siem_ids,
                "the client's" if hours is None else hours)
    return _changed(f"{pattern}: " + (
        f"new data is expected every {df.hours_text(df.default_hours(db, client_id))}, as for the client." if hours is None
        else "no new data is expected, so it isn't listed however long it stays quiet." if hours == df.NOT_EXPECTED
        else f"new data is expected every {df.hours_text(hours)}."))


def _rule_of(params) -> Optional[Tuple[str, str, str]]:
    """The rule Raise issue is for (``rule_id``, ``siem_id``, ``space``: from Rule Health, #106), or None."""
    key = tuple(str(params.get(k) or "").strip() for k in ("rule_id", "siem_id", "space"))
    return key if all(key) else None


def _selection(db, client_id: str, params, user) -> Dict[str, Any]:
    """What Raise issue (and Raise in GitLab) is for: one cause (issue, cause, siem_id, space);
    one issue as it is listed (``node``: its path, as JSON), every cause of it; with ``all`` every
    issue the filter bar shows that isn't muted; or one rule (``rule_id``, ``siem_id``, ``space``, from
    Rule Health): the rule, then each cause it has that isn't muted, with its own finding only.
    ``for``: who it is for, where either role may fix an issue in it (``rule_issues.audiences``; the
    first by default). ``params`` is the dialog's query string, or the same fields posted back. Returns
    its cause nodes, their Markdown and the page's context, and ``rule`` (the rule, or None)."""
    from starlette.datastructures import QueryParams
    rule_key = _rule_of(params)
    ctx = page_context(db, client_id, QueryParams({"rules": "all", "scope": f"{rule_key[1]}|{rule_key[2]}"})
                       if rule_key else params, user)
    every = not rule_key and params.get("all") == "1"
    issue, rule = None, None
    tuning = ""
    if rule_key:
        rule = db.get_rule_by_id(rule_key[0], rule_key[2], siem_id=rule_key[1], client_id=client_id)
        # Its mark for tuning is told in full, with each entry and the outcomes recorded (rule_tuning).
        nodes = [n for n in rule_issues.for_rule(_causes(ctx["groups"], with_muted=False), rule_key)
                 if n["issue"] != "marked_for_tuning"] if rule else []
        if rule:
            from app.services import rule_tuning
            with db.get_connection() as conn:
                tuning = rule_tuning.markdown(conn, rule_key, limits=rule_alerts.thresholds(db, client_id))
    elif every:
        nodes = _causes(ctx["groups"], with_muted=False)
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
    if rule:
        from app.api.rules import _kibana_rule_url
        where = next((d.get("name") or d.get("space") for d in ctx["client_siems"]
                      if d["id"] == rule_key[1] and str(d.get("space") or "default") == rule_key[2]), rule_key[2])
        text = (rule_issues.rule_markdown(rule.name, rule.rule_id, where, _kibana_rule_url(db, rule, client_id),
                                          bool(rule.enabled)) + ("\n" + text if text else "") + ("\n" + tuning if tuning else ""))
    return {"ctx": ctx, "nodes": nodes, "text": text, "every": every, "issue": issue["label"] if issue else "",
            "causes": len(nodes), "issues": len({n["issue"] for n in nodes}),
            "audiences": [(a, rule_issues.FIXERS[a]) for a in audiences], "audience": audience,
            "rule": rule, "rule_key": rule_key if rule else None}


def _about_rule(db, client_id: str, key: Tuple[str, str, str]) -> List[Dict[str, Any]]:
    """The GitLab issues about one rule that Rule Health shows: raised for it, or for a cause it has."""
    with db.get_connection() as conn:
        found = rule_issues.rule_findings(conn, [key])
        return gitlab_issues.about_rules(conn, rule_issues.cause_keys(found, [key])).get(key, [])


def _title(sel: Dict[str, Any]) -> str:
    """A GitLab issue's title for a selection: the rule's name, the cause's own heading, or what it covers."""
    if sel["rule"]:
        return sel["rule"].name
    if sel["every"]:
        return f"Rule Monitoring: {sel['issues']} issues, {sel['causes']} causes"
    if sel["issue"]:
        return f"{sel['issue']}: {sel['causes']} {'cause' if sel['causes'] == 1 else 'causes'}"
    first = next((line for line in sel["text"].splitlines() if line.strip()), "Rule Monitoring")
    return first.lstrip("#").replace("`", "").strip()


def _raised(db, client_id: str, sel: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The issues raised for the selection (for any of its causes, or about its rule), as GitLab has
    them now (as they were, when GitLab doesn't answer); ``usable``: one TIDE can comment on."""
    if sel["rule"]:
        found = _about_rule(db, client_id, sel["rule_key"])
    else:
        with db.get_connection() as conn:
            found = gitlab_issues.for_causes(conn, _keys(sel["nodes"]))
    reached = gitlab_issues.refresh(db, client_id, found)
    for i in found:
        i["usable"] = i["id"] in reached and i["state"] != "deleted"
    return found


def _footer(user, now, sel: Dict[str, Any]) -> str:
    from app.config import get_settings
    who = user.label if user else "TIDE"
    page, path = ("Rule Health", "rules") if sel["rule"] else ("Rule Monitoring", "rule-monitoring")
    return (f"\n\n---\nRaised from TIDE's {page} by {who} on {now:%Y-%m-%d %H:%M}: "
            f"{get_settings().app_url.rstrip('/')}/{path}")


def _note(form) -> str:
    """What the person raising an issue for a rule wrote (#106), to go above what TIDE writes."""
    note = str(form.get("note") or "").strip()
    return f"{note}\n\n" if note else ""


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
    if sel["ctx"]["can_fix"] and (sel["nodes"] or sel["rule"]):
        gitlab = {"projects": gitlab_issues.usable_projects(db, client_id), "raised": _raised(db, client_id, sel),
                  "title": _title(sel), "labels": "TIDE", "selection": selection}
    rule = sel["rule"]
    return request.app.state.templates.TemplateResponse(request, "components/rule_monitoring_copy.html", {
        **{k: sel[k] for k in ("text", "every", "issue", "causes", "issues", "audiences", "audience")},
        "selection": [(k, v) for k, v in selection if k != "for"], "gitlab": gitlab,
        # Raise issue for a rule (#106): from its window (``from=window``) it opens over the window,
        # and Back to rule opens the window again, with what changed.
        "rule": rule, "rule_asked": bool(_rule_of(request.query_params)),
        "from_window": request.query_params.get("from") == "window",
        "back_url": (f"/api/rules/{rule.rule_id}/history-modal?space={sel['rule_key'][2]}&siem_id={sel['rule_key'][1]}"
                     if rule else "")})


def _gitlab_done(request: Request, html: str, kind: str = "success", sel: Optional[Dict[str, Any]] = None,
                 db=None, client_id: str = "") -> HTMLResponse:
    """The dialog's GitLab part after raising or commenting: what happened; the list redraws. For a
    rule (#106), its card or table row behind the dialog too, out of band: the issue pill."""
    extra = ""
    if kind == "success" and sel and sel["rule"]:
        from app.api.rules import card_oob_html
        from app.config import get_settings
        try:
            extra = card_oob_html(request, db, client_id, sel["rule"], get_settings())
        except Exception:  # noqa: BLE001 - the issue is raised; the card catches up when the page reloads
            logger.warning("Could not redraw the rule's card after raising its issue", exc_info=True)
    response = HTMLResponse(f'<div class="rmon-gitlab__result alert alert-{kind}">{html}</div>{extra}')
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
    if not link or not (sel["nodes"] or sel["rule"]):
        return _gitlab_done(request, "Nothing raised: choose one of the client's GitLab issues projects, and "
                                     + ("a rule TIDE still has." if _rule_of(form) else "something Rule Monitoring still lists."),
                            "danger")
    title = str(form.get("title") or "").strip() or _title(sel)
    labels = [s.strip() for s in str(form.get("labels") or "").split(",") if s.strip()]
    assignee = str(form.get("assignee_id") or "").strip()
    assignee_id = int(assignee) if assignee.isdigit() else None
    try:
        issue = await run_in_threadpool(gitlab.create_issue, link, title,
                                        (_note(form) if sel["rule"] else "") + sel["text"] + _footer(user, sel["ctx"]["now"], sel),
                                        labels, assignee_id)
    except gitlab.GitLabError as exc:
        return _gitlab_done(request, f"Nothing raised. {escape(str(exc))}", "danger")
    with db.get_connection() as conn:
        if sel["rule"]:      # a rule's issue is the rule's: Rule Monitoring's causes keep their own (#106)
            gitlab_issues.record(conn, link, issue, title, [], user.label if user else "TIDE", rules=[sel["rule_key"]])
        else:
            gitlab_issues.record(conn, link, issue, title, _keys(sel["nodes"]), user.label if user else "TIDE")
    logger.info("Rule Monitoring: %s raised GitLab issue %s#%s for %s", user.label if user else "TIDE",
                link["project"], issue["iid"], f"the rule {sel['rule_key']}" if sel["rule"] else f"{sel['causes']} cause(s)")
    to = (f", assigned to {escape(issue['assignee_name'] or issue['assignee'])}" if issue.get("assignee")
          else ". GitLab didn't assign it: that person may no longer be able to see the project" if assignee_id else "")
    return _gitlab_done(request, f'Raised <a href="{escape(issue["web_url"] or "")}" target="_blank" rel="noopener">'
                                 f'{escape(link["project"])}#{issue["iid"]}</a>: {escape(title)}{to}.', sel=sel, db=db,
                        client_id=client_id)


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
    about = {i["id"] for i in _about_rule(db, client_id, sel["rule_key"])} if sel["rule"] else set()
    if not raised or not link or not (raised["id"] in about if sel["rule"] else
                                      sel["nodes"] and set(raised["causes"]) & set(_keys(sel["nodes"]))):
        return _gitlab_done(request, "No comment added: that issue isn't one raised for this.", "danger")
    found = "As TIDE finds the rule" if sel["rule"] else "Still found by TIDE"
    text = ((_note(form) if sel["rule"] else "") + f"{found} on {sel['ctx']['now']:%Y-%m-%d %H:%M}:\n\n{sel['text']}"
            + _footer(user, sel["ctx"]["now"], sel))
    try:
        await run_in_threadpool(gitlab.add_comment, link, raised["iid"], text)
    except gitlab.GitLabError as exc:
        return _gitlab_done(request, f"No comment added. {escape(str(exc))}", "danger")
    with db.get_connection() as conn:
        gitlab_issues.commented(conn, raised["id"])
    return _gitlab_done(request, f'Commented on <a href="{escape(raised["web_url"] or "")}" target="_blank" '
                                 f'rel="noopener">{escape(raised["project"])}#{raised["iid"]}</a> with what TIDE finds now.')
