"""
Dashboards: the page's context, each section's figures, and the editor's actions (new, save,
duplicate, set as default, delete, and the preview a section shows while it is edited).

The actions need write access to the Dashboard (page:dashboard). The page itself is /dashboard
and /dashboard/<id> in app/main.py, built by ``page_context``; app/services/dashboards.py holds
the dashboards and what a section may show.
"""
import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response

from app.api.deps import ActiveClient, DbDep, RequireUser, require_write
from app.services import dashboards, past_figures

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"],
                   dependencies=[Depends(require_write("page:dashboard"))])


# ── what a section shows ─────────────────────────────────────────────────────────────────────

def _changes(source: str, days: int, now: dict, then_at) -> dict:
    """``now``'s changes since the end of the day ``days`` ago, from ``then_at(that moment)``. A
    failure leaves the section without them, never without its figures."""
    try:
        return past_figures.changes(source, now, then_at(past_figures.day_end(days)), days)
    except Exception:
        logger.exception("Dashboard section %s: could not work out its figures %d day(s) ago", source, days)
        return {}


def _compute(db, client_id: str, card: dict) -> dict:
    """A section's figures from the database, the same way its page works them out, and, when it
    compares with an earlier day, how much each has changed since (``changes``)."""
    from app import inventory_engine as eng
    source, f = card["source"], card.get("filters") or {}
    days = past_figures.compare_days(card)
    if source == "rule_health":
        from app.api.rules import filtered_rule_metrics
        view = filtered_rule_metrics(db, client_id, f, keep_rules=bool(days))
        if days:
            rules, m = view.pop("rules"), view["metrics"]
            view["changes"] = _changes(source, days, {"total": m.total_rules, "enabled": m.enabled_rules,
                                                      "validated": m.validated_count, "quality": m.avg_score},
                                       lambda at: past_figures.rule_health_then(db, client_id, rules, f.get("space"), at))
        return view
    if source == "rule_monitoring":
        from app.services import rule_issues
        filters = {"show": "open", "group": "issue", **f}
        destinations = db.get_client_siems(client_id) or []
        with db.get_connection() as conn:
            data = rule_issues.view(conn, destinations, filters, client_id=client_id)
            moved = rule_issues.flows(conn, destinations, filters, past_figures.day_end(days)) if days else None
        view = {"metrics": data["metrics"], "filters": filters, "stale_days": rule_issues.STALE_DAYS}
        if moved:
            view["flows"] = past_figures.flow_lines(moved, days)
        return view
    if source == "system":
        system = eng.get_system(f["system_id"], client_id=client_id) if f.get("system_id") else None
        if not system:
            return {"empty": "This system no longer exists." if f.get("system_id") else "No system chosen yet.",
                    "no_link": True}
        data = eng.get_system_steps(system.id, client_id=client_id)
        view = {"default_name": system.name, "totals": data["totals"], "coverage_undefined": data.get("coverage_undefined")}
        if days:
            t, scored = data["totals"], data["totals"]["total"] - data["totals"]["na"]
            now = {"covered": None if view["coverage_undefined"] or not scored else int(round(t["covered"] / scored * 100)),
                   "techniques": t["total"], "no_coverage": t["none"], "known_gaps": t["gap"],
                   "unmapped": t["unmapped"], "not_counted": t["uncounted"]}
            view["changes"] = _changes(source, days, now,
                                       lambda at: past_figures.system_then(db, client_id, system.id, at, now))
        return view
    if source == "threat_landscape":
        from app.main import get_last_sync_time
        return {"metrics": db.get_threat_landscape_metrics(client_id=client_id), "last_sync_time": get_last_sync_time()}
    if source == "baselines":
        view = {"overview": eng.get_baselines_overview(client_id=client_id),
                "rollup": eng.get_system_baselines_rollup(client_id=client_id)}
        if days:
            ru = view["rollup"]
            now = {"rules_mapped": ru["rules_mapped"], "uncovered": ru["red"], "fully_covered": ru["green"]}
            systems = [s.id for s in eng.list_systems(client_id=client_id)]
            view["changes"] = _changes(source, days, now,
                                       lambda at: past_figures.baselines_then(db, client_id, systems, at, now))
        return view
    if source == "asset_inventory":
        return {"stats": eng.get_inventory_stats(client_id=client_id)}
    if source == "cve_overview":
        return {"stats": eng.get_cve_overview_stats(client_id=client_id)}
    if source == "connected_services":
        if not client_id:
            return {"client_siems": [], "client_opencti": [], "client_gitlab": []}
        from app.services.cti_connectors.opencti_taxii import graphql_base
        opencti = [{"label": c.get("label") or "OpenCTI", "url": graphql_base((c.get("config") or {}).get("taxii_root") or ""),
                    "active": bool(c.get("is_active")), "status": c.get("last_status")}
                   for c in db.list_cti_connectors() or []
                   if str(c.get("vendor") or "").lower() == "opencti_taxii"
                   and any(x.get("id") == client_id for x in db.get_cti_connector_clients(c.get("id")) or [])]
        return {"client_siems": db.get_client_siems(client_id),
                "client_opencti": opencti, "client_gitlab": db.list_client_gitlab_projects(client_id)}
    if source == "repositories":
        from app.services import builtin_data
        return {"items": builtin_data.status()}
    return {}


def section_view(db, client_id: str, card: dict, done: Optional[dict] = None) -> dict:
    """What a section shows: its source's figures for its filters, worked out afresh each time so
    a change shows as soon as the page is reloaded, and where its cards go. ``done`` shares the
    figures between sections of one page with the same source, filters and comparison."""
    key = (card["source"], json.dumps(card.get("filters") or {}, sort_keys=True), past_figures.compare_days(card))
    if done is not None and key in done:
        view = dict(done[key])
    else:
        try:
            view = _compute(db, client_id, card)
        except Exception:
            logger.exception("Dashboard section %s for client %s failed", card["source"], client_id)
            view = {"empty": "These figures can't be worked out just now. Reload in a moment.", "no_link": True}
        if done is not None:
            done[key] = dict(view)
    view["link"] = "" if view.get("no_link") else dashboards.link_for(card)
    return view


def _filter_options(db, client_id: str) -> dict:
    """The choices a section's filters offer, as their pages offer them."""
    from app.api.rules import _build_scope_labels, _filter_scope_options
    from app.inventory_engine import list_systems
    scopes, _ = _filter_scope_options(db, client_id)
    labels = _build_scope_labels(db, client_id)
    from app.services import rule_issues
    return {
        "scopes": [(s, labels.get(s, s.split("|")[-1].capitalize())) for s in scopes],
        "systems": [(s.id, s.name) for s in list_systems(client_id=client_id)],
        # Rule Monitoring's choices, as its filter bar offers them.
        "severities": list(rule_issues.SEVERITIES),
        "fixers": list(rule_issues.FIXERS.items()),
        "issues": sorted(((i.id, i.title) for i in rule_issues.KNOWN.values()), key=lambda i: i[1]),
    }


def page_context(db, client_id: str, user, dashboard: dict, editing: bool) -> dict:
    from app.config import get_settings
    cards, done = dashboard["cards"], {}
    ctx = {
        "dashboard": dashboard,
        "dashboards": dashboards.list_dashboards(db, client_id),
        "items": [(c, section_view(db, client_id, c, done) if c["type"] == "section" else {}) for c in cards],
        "sources": dashboards.SOURCES,
        "text_limits": dashboards.TEXT_CARDS,
        "name_limit": dashboards.NAME_LIMIT,
        "search_limit": dashboards.SEARCH_LIMIT,
        "rule_states": dashboards.RULE_STATES,
        "icon_names": dashboards.available_icons(),
        "can_edit": bool(user and user.can_write("page:dashboard")),
        "editing": editing,
        "env": get_settings(),
        "app_settings": db.get_all_settings(),
    }
    if editing:
        ctx["filter_options"] = _filter_options(db, client_id)
        ctx["compare_options"], ctx["compare_notes"] = past_figures.COMPARE, past_figures.NOTES
        ctx["new_cards"] = [("title", {"type": "title", "w": 12, "text": ""}),
                            ("text", {"type": "text", "w": 6, "text": ""})] + \
                           [(f"section:{k}", dashboards.new_section(k)) for k in dashboards.SOURCES]
    return ctx


# ── the editor's actions ─────────────────────────────────────────────────────────────────────

def _go(url: str) -> Response:
    return Response(status_code=204, headers={"HX-Redirect": url})


def _bad(exc: Exception) -> HTTPException:
    return HTTPException(status_code=400, detail=str(exc))


@router.post("/new")
def new_dashboard(db: DbDep, user: RequireUser, client_id: ActiveClient):
    did = dashboards.create(db, client_id, "New dashboard", [], user.username)
    logger.info("Dashboard created: client=%s id=%s by=%s", client_id, did, user.username)
    return _go(f"/dashboard/{did}?edit=1")


@router.post("/{dashboard_id}/save")
def save_dashboard(dashboard_id: str, db: DbDep, user: RequireUser, client_id: ActiveClient,
                   name: str = Form(...), layout: str = Form(...)):
    try:
        found = dashboards.save(db, client_id, dashboard_id, name, json.loads(layout), user.username)
    except (ValueError, TypeError) as exc:
        raise _bad(exc)
    if not found:
        raise HTTPException(status_code=404, detail="That dashboard no longer exists.")
    logger.info("Dashboard saved: client=%s id=%s by=%s", client_id, dashboard_id, user.username)
    return _go(f"/dashboard/{dashboard_id}")


@router.post("/{dashboard_id}/duplicate")
def duplicate_dashboard(dashboard_id: str, db: DbDep, user: RequireUser, client_id: ActiveClient):
    source = dashboards.get(db, client_id, dashboard_id)
    if not source:
        raise HTTPException(status_code=404, detail="That dashboard no longer exists.")
    name = f"Copy of {source['name']}"[:dashboards.NAME_LIMIT]
    did = dashboards.create(db, client_id, name, source["cards"], user.username)
    logger.info("Dashboard duplicated: client=%s from=%s id=%s by=%s", client_id, dashboard_id, did, user.username)
    return _go(f"/dashboard/{did}?edit=1")


@router.post("/{dashboard_id}/default")
def default_dashboard(dashboard_id: str, db: DbDep, user: RequireUser, client_id: ActiveClient):
    if not dashboards.set_default(db, client_id, dashboard_id):
        raise HTTPException(status_code=404, detail="That dashboard no longer exists.")
    logger.info("Dashboard made default: client=%s id=%s by=%s", client_id, dashboard_id, user.username)
    return _go(f"/dashboard/{dashboard_id}")


@router.post("/{dashboard_id}/delete")
def delete_dashboard(dashboard_id: str, db: DbDep, user: RequireUser, client_id: ActiveClient):
    result = dashboards.delete(db, client_id, dashboard_id)
    if result == "default":
        raise HTTPException(status_code=400, detail="The default dashboard can't be deleted. Make another the default first.")
    logger.info("Dashboard deleted: client=%s id=%s result=%s by=%s", client_id, dashboard_id, result, user.username)
    return _go("/dashboard")


@router.post("/preview")
def preview_section(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient,
                    card: str = Form(...)):
    """A section's cards as its settings stand in the editor, before it is saved."""
    try:
        cleaned = dashboards.clean([json.loads(card)])
    except (ValueError, TypeError) as exc:
        raise _bad(exc)
    if not cleaned or cleaned[0]["type"] != "section":
        raise HTTPException(status_code=400, detail="Only a section has a preview.")
    from app.config import get_settings
    return request.app.state.templates.TemplateResponse(request, "partials/dashboard_section.html", {
        "card": cleaned[0], "view": section_view(db, client_id, cleaned[0]),
        "env": get_settings(), "app_settings": db.get_all_settings(),
    })
