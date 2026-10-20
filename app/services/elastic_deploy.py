"""Deploying one of Elastic's bundled rules (app/services/elastic_rules.py) to a linked destination.

The rule is created as a custom rule under a new rule id, not Elastic's own: Kibana installs its
prebuilt rules under Elastic's ids, and a custom rule holding one would stop Kibana installing or
updating that prebuilt rule in the space. The copy's origin (``rule_origins``) keeps Elastic's id
and version, so TIDE still knows which Elastic rule it is.
"""

from __future__ import annotations

import logging
import uuid
from typing import Optional, Tuple

from app import elastic_helper
from app.services import elastic_rules as er
from app.services import rule_origins

logger = logging.getLogger(__name__)

Key = Tuple[str, str, str]


def form_prefill(rule: dict) -> dict:
    """The Create Rule form's values for deploying ``rule`` (an ``elastic_rules.get_rule`` row):
    Elastic's rule as it is, disabled."""
    body = er.kibana_payload(rule, "", enabled=False)
    return {
        "name": body.get("name") or "", "description": body.get("description") or "",
        "query": body.get("query") or "", "language": body.get("language") or "kuery",
        "severity": body.get("severity") or "medium", "author": body.get("author") or [],
        "tags": body.get("tags") or [], "mitre_ids": list(rule.get("techniques") or []),
        "note": body.get("note") or "", "interval": body.get("interval") or "5m",
        "from": body.get("from") or "now-6m", "enabled": False, "type": body.get("type") or "query",
        "risk_score": body.get("risk_score"), "index": body.get("index") or [],
        "timestamp_override": body.get("timestamp_override") or "",
        "highlighted_fields": (body.get("investigation_fields") or {}).get("field_names") or [],
    }


def payload_from_form(rule: dict, form, username: str, technique_lookup: dict) -> Tuple[Optional[dict], str]:
    """Elastic's rule with the user's changes in the Create Rule form: only the fields changed from
    what the form showed are laid over Elastic's payload, so everything the form cannot show (new
    terms, threshold, machine learning and indicator match settings, alert suppression, setup
    guide, ...) stays as Elastic has it. ``(payload, '')``, or ``(None, why)``."""
    from app.api.rules import _rule_form_values, changes_against

    body = er.kibana_payload(rule, "", enabled=False)
    shown = _rule_form_values(None, username, form_prefill(rule))
    changes, removed, problem = changes_against(shown, body.get("type") or "query", form, technique_lookup, username)
    if problem:
        return None, problem
    for key, value in changes.items():
        if key not in ("mitre_ids", "reason"):
            body[key] = value
    for key in removed:
        body.pop(key, None)
    if body.get("type") == "esql":
        body.pop("index", None)
    return body, ""


def destination(db, client_id: str, siem_id: str, space: str) -> Optional[dict]:
    """The tenant's linked destination ``(siem_id, space)``, or None if it is not linked."""
    return next(
        (s for s in (db.get_client_siems(client_id) or [])
         if s.get("id") == siem_id and str(s.get("space") or "default") == space),
        None,
    )


def already_there(db, client_id: str, upstream_id: str, siem_id: str, space: str,
                  kibana_url: str, api_key: str) -> Tuple[str, str]:
    """Whether the destination already holds this Elastic rule: ``(state, what)`` with state
    ``"no"``, ``"yes"`` (``what`` names it) or ``"unknown"`` (its SIEM did not answer)."""
    state, live = elastic_helper.find_rule_in_space(upstream_id, space, kibana_url, api_key)
    if state == "unknown":
        return "unknown", ""
    if state == "found":
        how = " (installed by Kibana as one of Elastic's prebuilt rules)" if rule_origins.is_prebuilt(live) else ""
        return "yes", f'"{live.get("name") or upstream_id}"{how}'
    from app.services.tenant_manager import tenant_context_for
    with tenant_context_for(client_id):
        with db.get_connection() as conn:
            copies = rule_origins.copies_of(conn, "elastic", upstream_id, siem_id, space)
    for copy in copies:
        rule = db.get_rule_by_id(copy["rule_id"], space, siem_id=siem_id, client_id=client_id)
        if rule and not rule.deprecated:
            return "yes", f'"{rule.name}", deployed by TIDE'
    return "no", ""


def _remember_version(db, client_id: str, siem_id: str, running: Optional[str]) -> None:
    """Keep the Elastic version the destination's SIEM runs (as a sync does); never raises."""
    if not running:
        return
    from app.services.tenant_manager import tenant_context_for
    try:
        with tenant_context_for(client_id):
            db.record_siem_version(siem_id, running)
    except Exception:
        logger.warning("Could not store the Elastic version of SIEM %s", siem_id, exc_info=True)


def deploy(db, client_id: str, actor_id: str, actor: str, upstream_id: str, siem_id: str, space: str,
           enabled: bool, confirm_version: bool = False,
           payload: Optional[dict] = None) -> Tuple[int, str, Optional[Key], str]:
    """Deploy bundled Elastic rule ``upstream_id`` to ``(siem_id, space)`` (blocking): Elastic's
    rule as it is, or ``payload`` (``payload_from_form``: it with the user's changes, whose own
    enabled state wins over ``enabled``).

    Returns ``(status, message, key, ask)``: 200 with the new rule's key when deployed. ``ask`` is
    ``"version"`` when the destination runs an older Elastic than the rule needs; deploying anyway
    takes ``confirm_version``.
    """
    with db.get_shared_connection() as conn:
        rule = er.get_rule(conn, upstream_id) if er.index_ready(conn) else None
    if not rule:
        return 404, "This rule is not in the Elastic rules built into TIDE.", None, ""
    if rule["status"] == "deprecated":
        return 400, f'Elastic has deprecated "{rule["name"]}", so it is not deployed.', None, ""
    dest = destination(db, client_id, siem_id, space)
    if not dest:
        return 400, "Choose a destination linked to this client.", None, ""
    url, key = dest.get("kibana_url"), dest.get("api_token_enc")
    if not (url and key):
        return 400, f'{dest.get("name") or space} has no Kibana address or API key configured.', None, ""
    name = dest.get("name") or space

    state, what = already_there(db, client_id, upstream_id, siem_id, space, url, key)
    if state == "unknown":
        return 502, (f"Could not check whether {name} already has this rule: its SIEM did not answer. "
                     "Nothing was deployed."), None, ""
    if state == "yes":
        return 409, f"{name} already has this rule: {what}. Nothing was deployed.", None, ""

    running = elastic_helper.kibana_version(url, key)
    _remember_version(db, client_id, siem_id, running)
    needs = rule.get("min_stack_version")
    if needs and not confirm_version:
        if running and er.version_tuple(running) < er.version_tuple(needs):
            return 409, (f'"{rule["name"]}" needs Elastic {needs} or later and {name} runs {running}. '
                         "Kibana may refuse it or run it without some of its settings."), None, "version"

    new_id = str(uuid.uuid4())
    body = dict(payload) if payload is not None else er.kibana_payload(rule, new_id, enabled)
    body["rule_id"] = new_id
    # Elastic numbers some rules differently for newer Elastic versions: deploy it as the version
    # Elastic ships to an Elastic like this one.
    version = er.version_for(rule.get("version"), rule.get("stack_versions"), running)
    if version is not None:
        body["version"] = version
    enabled = bool(body.get("enabled"))
    ok, message, created_id = elastic_helper.create_rule_as_given(body, space, url, key)
    if not ok:
        return 502, f'Could not deploy "{rule["name"]}": {message}', None, ""
    new_key = (created_id or new_id, siem_id, space)

    from app.api.rules import sync_single_rule
    try:
        sync_single_rule(db, client_id, new_key[0], siem_id, space, actor_id, actor)
    except Exception:
        logger.exception("Post-deploy sync of %s failed", new_key[0])
    rule_origins.record_for_client(db, client_id, new_key, "elastic", upstream_id, "deployed", actor,
                                   version=version)
    version_text = f", version {version}" if version else ""
    db.record_rule_history(
        rule_id=new_key[0], siem_id=siem_id, space=space, client_id=client_id, action="created",
        actor_user_id=actor_id, actor_name=actor,
        detail={"message": f'Deployed from Elastic\'s rule "{rule["name"]}"{version_text}.',
                "rule_name": rule["name"], "upstream_id": upstream_id},
    )
    logger.info("Deployed Elastic rule %s to %s/%s as %s by %s", upstream_id, siem_id, space, new_key[0], actor)
    state_text = "enabled" if enabled else "disabled"
    return 200, f'Deployed "{body.get("name") or rule["name"]}" to {name}, {state_text}.', new_key, ""
