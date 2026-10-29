"""Reviewing an upstream update to a deployed rule and taking it section by section.

A rule that came from Elastic's or the SigmaHQ rules (``rule_origins``) has an update when the
bundled upstream rule changed since it was taken. The review compares the deployed copy with the
upstream rule in Kibana's form (an Elastic rule's payload; a Sigma rule converted again, the way
it was first converted when TIDE knows that) using the same comparison as Compare. The user ticks
the sections to take; only those fields are written, to the rule as Kibana holds it now
(``elastic_helper.apply_rule_changes``), and the rule is then marked as reviewed against that
upstream revision. An Elastic prebuilt rule takes the sections too: Kibana marks it customised.

Elastic sometimes raises a rule's version for a change outside the rule as Kibana holds it (its
build, its integrations' versions). Such an update changes nothing compared, so it is not offered
for review: ``settle_unchanged`` moves the rule to the new version at a sync.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from app.services import rule_origins
from app.services.rule_diff import NOT_TAKEN, build_rule_diff, link_differences, section_changes, sections_text

logger = logging.getLogger(__name__)

Key = Tuple[str, str, str]

# Kibana fills these in when a rule leaves them out; the upstream payload gets the same so a
# default is not shown as a difference.
_KIBANA_DEFAULTS = {"interval": "5m", "from": "now-6m", "max_signals": 100}


def _sigma_payload(upstream_id: str, deployed: Dict[str, Any], options: Dict[str, Any]) -> Tuple[Optional[dict], str]:
    from app import sigma_helper

    rule = sigma_helper.get_rule_by_id(upstream_id)
    if not rule:
        return None, "The Sigma rule is not in the Sigma rules built into this TIDE."
    index = options.get("index_pattern") or ", ".join(deployed.get("index") or [])
    ok, out = sigma_helper.convert_sigma_rule(
        yaml_content=rule.get("_raw_yaml", ""), backend="elasticsearch", pipeline="none",
        output_format="kibana_ndjson", index_pattern=index,
        pipeline_file=options.get("pipeline_file") or "", template_file=options.get("template_file") or "",
    )
    if not ok:
        return None, f"The new Sigma rule could not be converted: {out}"
    try:
        payload = json.loads(out)
    except ValueError:
        payload = next((json.loads(line) for line in str(out).splitlines() if line.strip().startswith("{")), None)
    note = "" if options else ("TIDE does not know how this rule was first converted, so the new version was "
                               "converted with no pipeline: check its field names before taking the query.")
    return payload, note


def upstream_payload(conn, origin: Dict[str, Any], deployed: Dict[str, Any],
                     elastic: Optional[Dict[str, Dict[str, Any]]] = None) -> Tuple[Optional[dict], str]:
    """The upstream rule as it is now, in Kibana's form, under the deployed copy's rule id and on/off
    state: ``(payload, note)``; payload None (with the reason in note) when there is none.
    ``elastic``: the Elastic rules already read (``elastic_rules.get_rules``), for many rules at once."""
    if origin["origin"] == "elastic":
        from app.services import elastic_rules as er
        rule = (elastic.get(origin["upstream_id"]) if elastic is not None
                else er.get_rule(conn, origin["upstream_id"]))
        if not rule:
            return None, "The Elastic rule is not in the Elastic rules built into this TIDE."
        payload = er.kibana_payload(rule, deployed.get("rule_id") or origin["rule_id"], bool(deployed.get("enabled")))
        note = ""
    else:
        options = json.loads(origin.get("convert_options") or "null") or {}
        payload, note = _sigma_payload(origin["upstream_id"], deployed, options)
        if payload is None:
            return None, note
        payload["rule_id"] = deployed.get("rule_id") or origin["rule_id"]
        payload["enabled"] = bool(deployed.get("enabled"))
    for key, value in _KIBANA_DEFAULTS.items():
        payload.setdefault(key, value)
    return payload, note


def _elastic_rules(conn, origins: Dict[Key, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """The Elastic rules ``origins`` came from, read in one query rather than one per rule."""
    from app.services import elastic_rules as er
    return er.get_rules(conn, (o["upstream_id"] for o in origins.values() if o["origin"] == "elastic"))


def settle_unchanged(conn, keys: Optional[List[Key]] = None) -> int:
    """Move every rule (of ``keys``, or all) with an Elastic update that changes nothing compared
    to the new version, so it is not flagged for a review with nothing in it. Sigma updates are
    left to the user: converting each again at every sync is too slow. Needs the tenant DB's pooled
    connection (the reference DB attached). Returns how many were moved."""
    pending = {k: s for k, s in rule_origins.statuses(conn, keys).items()
               if s["state"] == "update" and s["origin"] == "elastic"}
    if not pending:
        return 0
    origins = rule_origins.get_bulk(conn, pending)
    raw = {(r, s, sp): data for r, s, sp, data in conn.execute(
        "WITH k AS (SELECT unnest(?::VARCHAR[]) AS r, unnest(?::VARCHAR[]) AS s, unnest(?::VARCHAR[]) AS sp) "
        "SELECT d.rule_id, d.siem_id, d.space, d.raw_data FROM detection_rules d "
        "JOIN k ON d.rule_id = k.r AND d.siem_id = k.s AND d.space = k.sp",
        [[k[0] for k in pending], [k[1] for k in pending], [k[2] for k in pending]]).fetchall()}
    elastic = _elastic_rules(conn, origins)
    settled = 0
    for key, status in pending.items():
        deployed = json.loads(raw[key]) if isinstance(raw.get(key), str) else raw.get(key)
        if not deployed or key not in origins:
            continue
        payload, _ = upstream_payload(conn, origins[key], deployed, elastic)
        if payload is not None and not build_rule_diff(deployed, payload):
            rule_origins.mark_current(conn, key, version=status.get("to_version"), how="unchanged")
            settled += 1
    if settled:
        logger.info("Moved %d rule(s) to an Elastic version that changes nothing compared", settled)
    return settled


# How a link is confirmed: reviewed against the upstream rule in Compare with Elastic (sections taken,
# or kept as it is), or an update that changed nothing compared.
_REVIEWED = {"updated", "unchanged"}


def link_unconfirmed(status: Optional[Dict[str, Any]], diffs: Optional[List[Dict[str, Any]]]) -> List[str]:
    """The sections in which a custom rule differs from the Elastic rule TIDE links it to (``diffs``,
    this rule against it), while that link hasn't been reviewed: it may be a copy changed on purpose,
    or not that rule at all. Empty for a confirmed link, Elastic's own rules and Sigma's."""
    if (not status or not diffs or status["origin"] != "elastic" or status["prebuilt"]
            or status["state"] not in ("current", "update") or status.get("recorded_how") in _REVIEWED):
        return []
    return link_differences(diffs)


def unconfirmed_links(conn, keys: Optional[List[Key]] = None) -> Dict[Key, Dict[str, Any]]:
    """``link_unconfirmed`` for each custom rule linked to an Elastic rule (of ``keys``, or all):
    ``{key: {"name": Elastic's rule, "sections": [...]}}`` for those that differ. Rule Monitoring's
    elastic_link_differs. Needs the tenant DB's pooled connection (the reference DB attached)."""
    candidates = {k: s for k, s in rule_origins.statuses(conn, keys).items()
                  if s["origin"] == "elastic" and not s["prebuilt"] and s.get("recorded_how") not in _REVIEWED}
    if not candidates:
        return {}
    origins = rule_origins.get_bulk(conn, candidates)
    raw = {(r, s, sp): data for r, s, sp, data in conn.execute(
        "WITH k AS (SELECT unnest(?::VARCHAR[]) AS r, unnest(?::VARCHAR[]) AS s, unnest(?::VARCHAR[]) AS sp) "
        "SELECT d.rule_id, d.siem_id, d.space, d.raw_data FROM detection_rules d "
        "JOIN k ON d.rule_id = k.r AND d.siem_id = k.s AND d.space = k.sp WHERE NOT COALESCE(d.deprecated, false)",
        [[k[0] for k in candidates], [k[1] for k in candidates], [k[2] for k in candidates]]).fetchall()}
    elastic = _elastic_rules(conn, origins)
    out: Dict[Key, Dict[str, Any]] = {}
    for key, status in candidates.items():
        deployed = json.loads(raw[key]) if isinstance(raw.get(key), str) else raw.get(key)
        if not deployed or key not in origins:
            continue
        payload, _ = upstream_payload(conn, origins[key], deployed, elastic)
        sections = link_unconfirmed(status, build_rule_diff(deployed, payload)) if payload else []
        if sections:
            out[key] = {"name": status["name"] or status["upstream_id"], "sections": sections}
    return out


def review(db, client_id: str, key: Key) -> Dict[str, Any]:
    """Everything the update dialog shows: the rule, its upstream status, the upstream payload and
    the differences (``old`` = this rule, ``new`` = upstream), and which sections can be taken."""
    rule = db.get_rule_by_id(key[0], key[2], siem_id=key[1], client_id=client_id)
    out: Dict[str, Any] = {"rule": rule, "status": None, "diffs": None, "note": "", "payload": None, "sections": [],
                           "unconfirmed": []}
    if not rule:
        out["note"] = "This rule is no longer in TIDE."
        return out
    with db.get_connection() as conn:
        origin = rule_origins.get(conn, key)
        status = rule_origins.statuses(conn, [key]).get(key)
        out["status"] = status
        if not origin or not status:
            out["note"] = "TIDE does not know which Elastic or Sigma rule this came from."
            return out
        payload, note = upstream_payload(conn, origin, rule.raw_data or {})
    out.update({"payload": payload, "note": note})
    if payload is not None:
        out["diffs"] = build_rule_diff(rule.raw_data or {}, payload)
        out["sections"] = [d["key"] for d in out["diffs"] if d["key"] not in NOT_TAKEN]
        out["unconfirmed"] = link_unconfirmed(status, out["diffs"])
        out["unconfirmed_text"] = sections_text(out["unconfirmed"])
    return out


def apply(db, client_id: str, key: Key, sections: List[str], actor_id: str, actor: str) -> Tuple[int, str]:
    """Take the chosen sections of the upstream update (none: keep this rule as it is) and mark the
    rule as reviewed against the upstream revision. Returns ``(status, message)``."""
    from app import elastic_helper
    from app.api.rules import sync_single_rule

    info = review(db, client_id, key)
    rule, status, payload = info["rule"], info["status"], info["payload"]
    if not rule or not status:
        return 404, info["note"] or "Rule not found."
    # An Elastic prebuilt rule takes the sections too: Kibana keeps it as Elastic's (same rule id
    # and version number) and marks it customised.
    chosen = [s for s in sections if s in info["sections"]]
    taken = ""
    if chosen:
        if payload is None:
            return 400, info["note"]
        siem = next((s for s in (db.get_client_siems(client_id) or [])
                     if s.get("id") == key[1] and str(s.get("space") or "default") == key[2]), None)
        if not siem:
            return 400, "This rule's destination is no longer linked to this client."
        changes, remove = section_changes(rule.raw_data or {}, payload, chosen)
        outcome, message, _live = elastic_helper.apply_rule_changes(
            rule.rule_id, changes, remove, space=key[2], kibana_url=siem.get("kibana_url"),
            api_key=siem.get("api_token_enc"), cached=rule.raw_data or {},
            on_recreated=db.kibana_recreate_hook(client_id, rule.rule_id, key[1], key[2], actor, actor_id),
        )
        if outcome == "conflict":
            return 409, (f"Someone changed {message} in Kibana since TIDE last synced this rule. Sync it, "
                         "then review the update again.")
        if outcome != "updated":
            return 502, message
        labels = {d["key"]: d["label"] for d in info["diffs"] or []}
        taken = ", ".join(labels.get(s, s) for s in chosen)
    unchanged = info["diffs"] == []
    with db.get_connection() as conn:
        rule_origins.mark_current(conn, key, actor, version=status.get("to_version"),
                                  how="unchanged" if unchanged else "updated")
    version = f" version {status['to_version']}" if status.get("to_version") else ""
    if taken:
        message = f"Merged {taken} from {status['source']}'s{version} into this rule."
    elif unchanged:
        message = (f"Moved this rule to {status['source']}'s{version or ' current rule'}: it changes nothing TIDE "
                   "compares.")
    elif status["state"] == "current":    # Keep the link: a rule that differs from it, reviewed
        message = (f'Kept the link to {status["source"]}\'s "{status["name"]}": TIDE goes on showing its updates '
                   "for this rule.")
    else:
        message = f"Kept this rule as it is; marked as reviewed against {status['source']}'s{version}."
    if taken and status["prebuilt"]:
        message += " Kibana now marks it as customised."
    elif unchanged and status["prebuilt"] and status.get("installed_version"):
        message += (f" Kibana keeps version {status['installed_version']} installed until it installs "
                    "Elastic's update itself.")
    db.record_rule_history(
        rule_id=key[0], siem_id=key[1], space=key[2], client_id=client_id, action="upstream_update",
        actor_user_id=actor_id, actor_name=actor,
        detail={"message": message, "sections": chosen, "upstream_id": status["upstream_id"],
                "to_version": status.get("to_version")},
    )
    if chosen:
        try:
            sync_single_rule(db, client_id, key[0], key[1], key[2], actor_id, actor)
        except Exception:
            logger.exception("Post-update sync of %s failed", key[0])
    else:   # reviewed: a link Rule Monitoring asked to confirm is confirmed (a sync did it above)
        from app.services import rule_issues
        rule_issues.refresh_tenant(db, client_id, rule_keys=[key])
    return 200, message
