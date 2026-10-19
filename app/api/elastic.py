"""
API routes for the Elastic Rules page: Elastic's detection rules, bundled in the
image (app/services/elastic_rules.py), and deploying a rule to a linked destination
(app/services/elastic_deploy.py).
"""

import logging
import re

from fastapi import APIRouter, Request, Query
from fastapi.responses import HTMLResponse

from app.api.deps import CurrentUser, RequireUser, DbDep, ActiveClient
from app.services import elastic_rules as er
from app.services import rule_origins

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/elastic", tags=["elastic"])

_NOT_FOUND = '<div class="empty-state empty-state--fill"><p>{}</p></div>'


def _coverage(db, client_id: str):
    return db.get_all_covered_ttps(client_id=client_id), db.get_ttp_rule_counts(client_id=client_id)


def rules_list_context(db, client_id: str, q: str = "", technique: str = "", platform: str = "",
                       integration: str = "", rule_type: str = "", severity: str = "", status: str = "",
                       selected: str = "", limit: int = 100, offset: int = 0) -> dict:
    """What ``partials/elastic_rules_list.html`` needs; shared with the page route. From ``offset``
    on, only the next rows (the list scrolled to its end)."""
    rules, matching, total = [], 0, 0
    with db.get_shared_connection() as conn:
        if er.index_ready(conn):
            rules, matching = er.search_rules(conn, q=q, technique=technique, platform=platform,
                                              integration=integration, rule_type=rule_type,
                                              severity=severity, status=status, limit=limit, offset=offset)
            total = conn.execute("SELECT COUNT(*) FROM elastic_rules_index").fetchone()[0]
    covered_ttps, ttp_rule_counts = _coverage(db, client_id)
    shown = offset + len(rules)
    return {"rules": rules, "matching": matching, "total_count": total, "selected_id": selected,
            "offset": offset, "next_offset": shown if shown < matching else 0,
            "covered_ttps": covered_ttps, "ttp_rule_counts": ttp_rule_counts,
            "status_labels": dict(er.STATUSES)}


@router.get("/rules", response_class=HTMLResponse)
def search_rules(
    request: Request,
    user: CurrentUser,
    db: DbDep,
    client_id: ActiveClient,
    q: str = Query(""),
    technique: str = Query(""),
    platform: str = Query(""),
    integration: str = Query(""),
    rule_type: str = Query("", alias="type"),
    severity: str = Query(""),
    status: str = Query(""),
    selected: str = Query(""),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """The rule browser's list, filtered; from ``offset`` on, the next rows as it is scrolled."""
    return request.app.state.templates.TemplateResponse(
        request, "partials/elastic_rules_list.html",
        rules_list_context(db, client_id, q, technique, platform, integration, rule_type, severity,
                           status, selected, limit, offset),
    )


@router.get("/rules/{rule_id}", response_class=HTMLResponse)
def rule_detail(request: Request, rule_id: str, user: CurrentUser, db: DbDep, client_id: ActiveClient):
    """One rule: what it detects, its query, ATT&CK techniques, guide and source."""
    from app.api.rules import _render_guide_markdown

    with db.get_shared_connection() as conn:
        rule = er.get_rule(conn, rule_id) if er.index_ready(conn) else None
    if not rule:
        return HTMLResponse(_NOT_FOUND.format("This rule is not in the bundled Elastic rules."), status_code=404)
    body = rule["rule_json"] or {}
    covered_ttps, ttp_rule_counts = _coverage(db, client_id)
    return request.app.state.templates.TemplateResponse(
        request, "partials/elastic_rule_detail.html",
        {
            "rule": rule,
            "body": body,
            "builds": er.stack_builds(rule),
            "deployed": rule_origins.deployed_for_client(db, client_id, "elastic", rule_id),
            "commit": er.commit(),
            "description_html": _render_guide_markdown(rule["description"]),
            "guide_html": _render_guide_markdown(body["note"]) if body.get("note") else "",
            "setup_html": _render_guide_markdown(body["setup"]) if body.get("setup") else "",
            "source": er.source_text(rule["file_path"]),
            "status_labels": dict(er.STATUSES),
            "covered_ttps": covered_ttps,
            "ttp_rule_counts": ttp_rule_counts,
            "can_deploy": rule["status"] != "deprecated" and (not user or user.can_write("page:elastic")),
        },
    )


# A technique window the deploy form returns to on Cancel.
_TECHNIQUE_URL = re.compile(r"^/api/(systems/[\w-]+/steps|baselines/tactics)/[\w-]+$")


@router.get("/rules/{rule_id}/deploy-form", response_class=HTMLResponse)
def deploy_form(request: Request, rule_id: str, user: RequireUser, db: DbDep, client_id: ActiveClient,
                technique_url: str = Query(""), scope_pair: str = Query(""), enabled: str = Query("")):
    """Deploy: the Create Rule form, filled in with Elastic's rule, so it can be changed first.
    Opened from the Elastic Rules page (with its Deploy to / Deploy as settings: ``scope_pair``,
    ``enabled``) or a technique window's Elastic rules (Cancel goes back)."""
    from app.api.rules import _LANGUAGE_TYPES, _build_rule_form_context, _rule_type_label
    from app.services import elastic_deploy

    with db.get_shared_connection() as conn:
        rule = er.get_rule(conn, rule_id) if er.index_ready(conn) else None
    if not rule:
        return HTMLResponse(_NOT_FOUND.format("This rule is not in the bundled Elastic rules."), status_code=404)
    prefill = elastic_deploy.form_prefill(rule)
    if scope_pair and scope_pair in {f"{s['id']}|{s.get('space') or 'default'}" for s in db.get_client_siems(client_id) or []}:
        prefill["scope_pair"] = scope_pair
    prefill["enabled"] = enabled == "true"
    ctx = _build_rule_form_context(db, client_id, user.username, f"/api/elastic/rules/{rule_id}/deploy",
                                   "Deploy rule", "Deploy Elastic rule", prefill=prefill)
    if prefill["type"] not in _LANGUAGE_TYPES:
        label = _rule_type_label(prefill["type"])
        ctx["rule_type_label"] = label
        ctx["type_note"] = (f"This is a {label} rule. Its {label} settings come from Elastic's rule as they are; "
                            "change them in Kibana once it is deployed.")
    ctx["min_stack_version"] = rule.get("min_stack_version") or ""
    if _TECHNIQUE_URL.match(technique_url):
        ctx["cancel_url"] = technique_url
    return request.app.state.templates.TemplateResponse(request, "components/rule_create_form.html", ctx)


@router.post("/rules/{rule_id}/deploy", response_class=HTMLResponse)
async def deploy_rule(request: Request, rule_id: str, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """Deploy the rule, with the changes made in the form, to a linked destination as a new custom
    rule (app/services/elastic_deploy.py). A refusal shows in the form; once deployed, the window
    shows the new rule. Posting only ``scope_pair`` (and optionally ``enabled``) deploys Elastic's
    rule unchanged."""
    from app.api.promotion import _run_in_context
    from app.api.rules import _build_rule_modal_context, _build_technique_groups, _form_error
    from app.services import elastic_deploy

    form = await request.form()
    siem_id, _, space = str(form.get("scope_pair") or "").partition("|")
    if not siem_id or not space:
        return _form_error("Choose a target SIEM and space.")
    with db.get_shared_connection() as conn:
        rule = er.get_rule(conn, rule_id) if er.index_ready(conn) else None
    if not rule:
        return _form_error("This rule is not in the Elastic rules built into TIDE.", 404)
    if "name" in form:
        _, technique_lookup = _build_technique_groups(db)
        payload, problem = elastic_deploy.payload_from_form(rule, form, user.username, technique_lookup)
        if payload is None:
            return _form_error(problem)
    else:
        payload = er.kibana_payload(rule, "", str(form.get("enabled") or "").lower() == "true")
    confirm = str(form.get("confirm_version") or "") == "1"
    actor = user.name or user.username
    status, message, key, ask = await _run_in_context(
        elastic_deploy.deploy, db, client_id, user.id, actor, rule_id, siem_id, space,
        bool(payload.get("enabled")), confirm, payload)
    if status != 200:
        if ask == "version":
            message += " Tick “Deploy even if…” below to deploy it anyway."
        return _form_error(message, status)
    deployed = db.get_rule_by_id(key[0], key[2], siem_id=key[1], client_id=client_id)
    if not deployed:      # deployed, but its sync has not brought it into TIDE yet
        response = HTMLResponse('<div hidden data-start-sync></div>')
    else:
        response = request.app.state.templates.TemplateResponse(
            request, "components/rule_modal.html",
            _build_rule_modal_context(db, client_id, deployed, key[2], key[1], flash=message))
    response.headers["HX-Trigger"] = "refreshRules"
    return response
