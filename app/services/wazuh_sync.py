"""A Wazuh SIEM's rules and alerts, read at a sync (app.services.sync.run_elastic_sync hands each Wazuh
SIEM it syncs to ``fetch``).

Rules are manager-wide: one read serves every agent group linked, and each destination (a group, or
``*`` for every agent) gets its own copy of the rows. A destination holds the rules that carry an ATT&CK
id and every custom rule (``etc/rules``), or every rule when it has **Include every Wazuh rule**
(``client_siem_map.all_rules``): the stock ruleset's thousands of rules without ATT&CK ids would bury
the rest, and couldn't count towards coverage anyway.

The rules come back as the records ``elastic_helper.fetch_detection_rules`` makes, scored by
app.scoring, with each space's diagnostics in the same shape, so the sync saves, reconciles and records
them as it does Kibana's. A read that fails gives no records and no diagnostics, so nothing is removed.
Each destination's alerts are counted for its own agents only: two clients sharing a manager never see
each other's.
"""
import logging
import re
from typing import Dict, Iterable, List, Optional

from app import scoring
from app.services import wazuh

logger = logging.getLogger(__name__)


def is_custom(item: dict) -> bool:
    """A rule a person wrote (``etc/rules``), as opposed to Wazuh's own ruleset (``ruleset/rules``)."""
    return str(item.get("relative_dirname") or "").startswith("etc/")


def held(item: dict) -> bool:
    """Whether a destination without **Include every Wazuh rule** holds this rule."""
    return bool(item.get("mitre")) or is_custom(item)


def tactics_of(mitre_ids: Iterable[str], tactic_of: Dict[str, str]) -> List[str]:
    """The ATT&CK tactics of the techniques: Wazuh's rules name techniques only (its alerts add the
    tactics from ATT&CK, as this does). A sub-technique has its parent's tactics."""
    out = set()
    for mid in mitre_ids:
        for tactic in str(tactic_of.get(mid) or tactic_of.get(mid.split(".")[0]) or "").split(","):
            if tactic.strip():
                out.add(tactic.strip())
    return sorted(out)


def current_ids(ids: Iterable[str], revisions: Optional[Dict[str, str]]) -> tuple:
    """``ids`` as the bundled ATT&CK numbers them now: ``(current ids, {old id: new id} for the ones
    renumbered)``. Wazuh's rules carry the ids of the ATT&CK release they were written for; coverage
    is counted on TIDE's."""
    revisions = revisions or {}
    out, renumbered = [], {}
    for mid in ids:
        new = revisions.get(mid, mid)
        if new != mid:
            renumbered[mid] = new
        if new not in out:
            out.append(new)
    return out, renumbered


def record(item: dict, space: str, weights, tactic_of: Dict[str, str], name_of: Dict[str, str],
           revisions: Optional[Dict[str, str]] = None) -> dict:
    """One rule of the manager's (``GET /rules``) as a scored rule record of the destination ``space``.
    ``revisions`` (database.get_technique_revisions) turns ATT&CK ids a later release renumbered into
    the current ones for ``mitre_ids``; ``raw_data.mitre`` keeps Wazuh's."""
    rid = str(item.get("id"))
    custom = is_custom(item)
    wazuh_ids = list(dict.fromkeys(str(m).strip().upper() for m in item.get("mitre") or [] if str(m).strip()))
    mitre, renumbered = current_ids(wazuh_ids, revisions)
    enabled = str(item.get("status") or "enabled") == "enabled"
    description = str(item.get("description") or "").strip()
    raw = {
        "id": rid,                       # rule_alerts joins a rule's alert counts on raw_data.id
        "type": wazuh.RULE_TYPE, "language": wazuh.RULE_LANGUAGE,
        "name": description or f"Wazuh rule {rid}", "description": description,
        "level": item.get("level"), "groups": list(item.get("groups") or []),
        "compliance": {key: list(item.get(key)) for key, _label in wazuh.COMPLIANCE_KEYS if item.get(key)},
        "mitre": wazuh_ids, "mitre_current": renumbered,
        "filename": item.get("filename"), "relative_dirname": item.get("relative_dirname"),
        "status": item.get("status"), "details": item.get("details") or {}, "custom": custom, "enabled": enabled,
    }
    data = {
        "rule_id": rid, "name": raw["name"], "enabled": enabled, "author_str": "Custom" if custom else "Wazuh",
        "severity": wazuh.severity(item.get("level")), "risk_score": None, "timestamp_override": "-",
        "note_exists": "-", "note": "", "tactics": ",".join(tactics_of(mitre, tactic_of)),
        "techniques": ",".join(f"{m} {name_of.get(m, '')}".strip() for m in mitre),
        "highlighted_str": "-", "highlight_fields": [], "aggregate_fields": [], "search_time": 0,
        "search_times_ms": [], "search_sample": None, "language": wazuh.RULE_LANGUAGE, "indices": [], "fields": [],
        "results": [], "field_facts": {}, "aux_facts": {}, "query": "", "mitre_ids": mitre, "raw_data": raw,
        "space_id": space,
    }
    scoring.score_rule(data, weights)
    data.pop("field_facts", None)
    data.pop("aux_facts", None)
    return data


def fetch(siem: dict, spaces: Iterable[str], all_rules: Iterable[str], weights, tactic_of: Dict[str, str],
          name_of: Dict[str, str], alert_days: int, revisions: Optional[Dict[str, str]] = None) -> dict:
    """The rules and alert counts of one Wazuh SIEM's destinations ``spaces`` (``all_rules``: the ones
    with **Include every Wazuh rule**): ``{"records", "diagnostics": {space: {complete, total,
    returned, rule_ids}}, "dropped": {space: ids}, "alerts": {space: rule_alerts.store's result},
    "error": why the rules couldn't be read}``. A diagnostic's ``rule_ids`` are every rule the manager
    has, so the sync's reconcile marks deprecated only the rules gone from Wazuh; ``dropped`` are the
    ones it has that the destination doesn't hold, which the sync removes."""
    spaces, all_rules = sorted(set(spaces)), set(all_rules)
    s = wazuh.settings(siem)
    out: dict = {"records": [], "diagnostics": {}, "dropped": {}, "alerts": {}, "error": ""}
    missing = wazuh.missing_settings(s)
    if missing:
        out["error"] = f"its {', '.join(missing)} {'is' if len(missing) == 1 else 'are'} not saved"
        return out
    manager = wazuh.Manager.from_settings(s)
    try:
        items = manager.rules()
    except wazuh.WazuhError as exc:
        out["error"] = str(exc)
        return out
    every = {str(i.get("id")) for i in items}
    for space in spaces:
        chosen = items if space in all_rules else [i for i in items if held(i)]
        records = [record(i, space, weights, tactic_of, name_of, revisions) for i in chosen]
        out["records"] += records
        out["diagnostics"][space] = {"complete": True, "total": len(chosen), "returned": len(records),
                                     "rule_ids": every, "duplicates": []}
        out["dropped"][space] = every - {r["rule_id"] for r in records}
    indexer = wazuh.Indexer.from_settings(s)
    for space in spaces:
        try:
            agent_ids = manager.agent_ids(space)
        except wazuh.WazuhError as exc:
            out["alerts"][space] = {"ok": False, "status": exc.status,
                                    "error": f"Could not list the agents of group {space}: {exc}"}
            continue
        out["alerts"][space] = indexer.alert_counts(agent_ids, alert_days)
    return out


# A rule's details that say when it is checked or fires, rather than a field it matches.
_NOT_CONDITIONS = {"if_sid", "if_matched_sid", "if_group", "if_matched_group", "frequency", "timeframe", "ignore",
                   "options", "noalert", "info"}


def window_details(raw: dict) -> dict:
    """What the rule window shows of a Wazuh rule (its raw_data): level, groups, compliance, file, the
    rules or groups it follows, how often it must match, and each field condition."""
    details = raw.get("details") or {}

    def ids(key):
        return [x for x in re.split(r"[\s,]+", str(details.get(key) or "")) if x]

    conditions = []
    for field, value in details.items():
        if field in _NOT_CONDITIONS or field.startswith(("same_", "different_", "not_same_")):
            continue
        if isinstance(value, dict):
            conditions.append({"field": field, "pattern": str(value.get("pattern") or ""),
                               "negate": str(value.get("negate") or "").lower() == "yes", "type": value.get("type") or ""})
        else:
            conditions.append({"field": field, "pattern": str(value), "negate": False, "type": ""})
    compliance = raw.get("compliance") or {}
    return {
        "level": raw.get("level"), "groups": list(raw.get("groups") or []),
        "file": "/".join(p for p in (raw.get("relative_dirname"), raw.get("filename")) if p),
        "compliance": [(label, compliance[key]) for key, label in wazuh.COMPLIANCE_KEYS if compliance.get(key)],
        "parents": ids("if_sid"), "matched_parents": ids("if_matched_sid"),
        "parent_groups": ids("if_group"), "matched_groups": ids("if_matched_group"),
        "frequency": details.get("frequency"), "timeframe": details.get("timeframe"), "ignore": details.get("ignore"),
        "same": [k[len("same_"):].replace("_", " ") for k in details if k.startswith("same_")],
        "options": ids("options"), "conditions": conditions,
        "renumbered": sorted((raw.get("mitre_current") or {}).items()),
    }


def rule_block(xml: str, rule_id: str) -> Optional[str]:
    """The ``<rule id="…">…</rule>`` element of ``rule_id`` in a rule file's text, found by pattern:
    the XML is shown, never parsed."""
    m = re.search(r'<rule\b[^>]*\bid\s*=\s*"' + re.escape(str(rule_id)) + r'"[^>]*>.*?</rule>', xml or "", re.S)
    return m.group(0) if m else None


def rule_xml(siem: dict, raw: dict) -> Optional[str]:
    """The XML file a Wazuh rule is in, for its window; None when the manager can't be read now."""
    s = wazuh.settings(siem)
    if not (raw.get("filename") and s["manager_url"]):
        return None
    try:
        return wazuh.Manager.from_settings(s).rule_file(raw["filename"], raw.get("relative_dirname") or "ruleset/rules")
    except wazuh.WazuhError as exc:
        logger.info("Could not read Wazuh rule file %s: %s", raw.get("filename"), exc)
        return None
