"""
API routes for Detection Rules (Rule Health page).
"""

import json
import re
from datetime import datetime, timedelta
from html import escape
from urllib.parse import quote, unquote

from fastapi import APIRouter, Request, Query, BackgroundTasks, File, Form, UploadFile
from fastapi.responses import HTMLResponse
from starlette.concurrency import run_in_threadpool
from typing import Optional, Any, List, Dict, Tuple

from app.api.deps import DbDep, CurrentUser, RequireUser, SettingsDep, ActiveClient
from app.services.database import validation_key, rule_state
from app.services.rule_origins import is_prebuilt
from app.models.rules import RuleFilters, RuleHealthMetrics, DetectionRule, rule_language_name, rule_type_name

import logging

logger = logging.getLogger(__name__)


def _parse_date_bound(raw_value: Optional[str], end_of_day: bool) -> Optional[datetime]:
    """Parse a ``<input type=date>`` value (``YYYY-MM-DD``) into a bound.

    ``end_of_day`` pushes the bound to 23:59:59.999999 so a "to" date
    filter includes the whole day rather than only midnight.
    """
    if not raw_value:
        return None
    try:
        parsed = datetime.strptime(raw_value.strip()[:10], "%Y-%m-%d")
    except ValueError:
        return None
    if end_of_day:
        parsed = parsed + timedelta(days=1) - timedelta(microseconds=1)
    return parsed


# Table-view column sorts beyond score / validated / name. Each maps to a key builder that
# receives (rule, ctx) where ctx = {"offline": get_offline_scopes(), "siem_label": callable(rule)}.
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_COLUMN_SORTS = {
    "siem": lambda r, c: (c["siem_label"](r) or "").lower(),
    "state": lambda r, c: {"live": 0, "offline": 1, "deprecated": 2}[rule_state(r, c.get("offline") or {})],
    "severity": lambda r, c: _SEVERITY_RANK.get(str(getattr(getattr(r, "severity", None), "value", getattr(r, "severity", "")) or "").lower(), 0),
    "author": lambda r, c: str(getattr(r, "author", "") or "").lower(),
    "alerts": lambda r, c: (c.get("alerts") or {}).get((r.rule_id, r.siem_id, r.space), 0),
    "language": lambda r, c: rule_language_name(r.query_language).lower(),
    "type": lambda r, c: rule_type_name(r.rule_type).lower(),
}


def _resort_rules(rules: list, sort_score: str, sort_validated: str, sort_name: str, sort_by: str,
                  sort_col: str = "", sort_dir: str = "", sort_ctx: Optional[dict] = None) -> list:
    """Re-apply the active sort after any post-fetch substitution.

    ``list_rules`` swaps some rows for their migrated "master" counterpart
    after ``db.get_rules`` already sorted the pre-swap rows — the master can
    carry a different score/validation date/name, silently breaking the
    requested order (e.g. Validate sort). Cheap to redo in Python since the
    page is already fully materialized here.
    """
    legacy_map = {
        "score_asc": ("score", "asc"), "score_desc": ("score", "desc"),
        "validated_asc": ("validated", "asc"), "validated_desc": ("validated", "desc"),
        "name_asc": ("name", "asc"), "name_desc": ("name", "desc"),
    }
    if sort_col in _COLUMN_SORTS and sort_dir in ("asc", "desc"):
        # Table header sort on a column the DB layer cannot order: stable secondary sort by name.
        rules.sort(key=lambda r: str(getattr(r, "name", "") or "").lower())
        ctx = sort_ctx or {"offline": {}, "siem_label": lambda r: ""}
        rules.sort(key=lambda r: _COLUMN_SORTS[sort_col](r, ctx), reverse=(sort_dir == "desc"))
        return rules
    if sort_validated in ("asc", "desc"):
        field, direction = "validated", sort_validated
    elif sort_score in ("asc", "desc"):
        field, direction = "score", sort_score
    elif sort_name in ("asc", "desc"):
        field, direction = "name", sort_name
    else:
        field, direction = legacy_map.get(sort_by, ("score", "desc"))

    reverse = direction == "desc"
    if field == "validated":
        # Never-validated rules have no date: keep them after every dated rule in both directions.
        rules.sort(key=lambda r: str(getattr(r, "name", "") or "").lower())
        rules.sort(key=lambda r: getattr(r, "validation_date", None) or datetime.min, reverse=reverse)
        dated = [r for r in rules if getattr(r, "validation_date", None)]
        rules[:] = dated + [r for r in rules if not getattr(r, "validation_date", None)]
    elif field == "score":
        rules.sort(key=lambda r: int(getattr(r, "score", 0) or 0), reverse=reverse)
    elif field == "name":
        rules.sort(key=lambda r: str(getattr(r, "name", "") or "").lower(), reverse=reverse)
    return rules


def _dedupe_display_rules(db, rules: List["DetectionRule"], client_id: str) -> List["DetectionRule"]:
    """Every stored rule gets its own card now -- linked rules included. This used to collapse a
    linked pair down to one card, picking a "winner" and silently hiding the other; that's gone,
    kept only as a passthrough so callers that filtered/counted through it don't need to change."""
    return rules


def _metrics_from_rules(rules: List["DetectionRule"], all_rules: Optional[List["DetectionRule"]] = None) -> RuleHealthMetrics:
    """Aggregate Rule Health stats from an already-filtered, already-
    deduplicated rule list — i.e. exactly the cards the grid would render
    across every page. Computing stats from raw (pre-dedup) SQL rows
    overcounts any migrated/merged identity, since its staging and
    production copies both independently satisfy the same filters."""
    if not rules:
        return RuleHealthMetrics()

    total_rules = len(rules)
    enabled_rules = sum(1 for r in rules if r.enabled)
    scores = [int(r.score or 0) for r in rules]
    avg_score = round(sum(scores) / total_rules, 1) if scores else 0.0

    rules_by_space: Dict[str, int] = {}
    rules_by_scope: Dict[str, int] = {}
    severity_breakdown: Dict[str, int] = {}
    language_breakdown: Dict[str, int] = {}
    validated_count = 0
    validation_amber_count = 0
    validation_expired_count = 0
    never_validated_count = 0

    # Rules per SIEM count every copy: a promoted rule still lives in its staging SIEM, so the
    # staging count does not drop when a rule is promoted (the grid shows the pair once).
    for r in (all_rules if all_rules is not None else rules):
        if r.deprecated:
            continue
        if r.space:
            rules_by_space[r.space] = rules_by_space.get(r.space, 0) + 1
        if r.siem_id and r.space:
            scope_key = f"{r.siem_id}|{str(r.space).lower()}"
            rules_by_scope[scope_key] = rules_by_scope.get(scope_key, 0) + 1

    for r in rules:
        sev = str(getattr(r.severity, "value", r.severity) or "low").lower()
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
        lang = r.language or "unknown"
        language_breakdown[lang] = language_breakdown.get(lang, 0) + 1
        # "Validated" is deliberately only the currently in-policy
        # ("valid"/green) rows — matching what an operator can actually
        # count on the grid. Amber (due soon) and expired rows had a
        # timestamp too, but folding them into the headline number made
        # it read higher than the visibly-validated card count.
        if r.validation_status == "valid":
            validated_count += 1
        elif r.validation_status == "amber":
            validation_amber_count += 1
        elif r.validation_status == "expired":
            validation_expired_count += 1
        else:
            never_validated_count += 1

    return RuleHealthMetrics(
        total_rules=total_rules,
        enabled_rules=enabled_rules,
        disabled_rules=total_rules - enabled_rules,
        avg_score=avg_score,
        min_score=min(scores) if scores else 0,
        max_score=max(scores) if scores else 0,
        validated_count=validated_count,
        validation_amber_count=validation_amber_count,
        validation_expired_count=validation_expired_count,
        never_validated_count=never_validated_count,
        low_quality_count=sum(1 for s in scores if s < 50),
        high_quality_count=sum(1 for s in scores if s >= 80),
        quality_excellent=sum(1 for s in scores if s >= 80),
        quality_good=sum(1 for s in scores if 70 <= s < 80),
        quality_fair=sum(1 for s in scores if 50 <= s < 70),
        quality_poor=sum(1 for s in scores if s < 50),
        rules_by_space=rules_by_space,
        rules_by_scope=rules_by_scope,
        severity_breakdown=severity_breakdown,
        language_breakdown=language_breakdown,
    )


def _apply_lifecycle_counts(metrics: RuleHealthMetrics, db, client_id: str, rules) -> None:
    """Fill the Linked / Deprecated split on ``metrics`` for ``rules`` (one entry per card the
    grid renders). There is no more Production/Staging/Migrated split -- see rule_links."""
    if not rules:
        return
    links = db.get_rule_links_bulk([(r.rule_id, r.siem_id, r.space) for r in rules])
    offline_scopes = db.get_offline_scopes()
    linked = deprecated = offline = 0
    for r in rules:
        state = rule_state(r, offline_scopes)
        if state == "deprecated":
            deprecated += 1
        elif state == "offline":
            offline += 1
        elif links.get((r.rule_id, r.siem_id, r.space)):
            linked += 1
    metrics.state_linked = linked
    metrics.state_deprecated = deprecated
    metrics.state_offline = offline


def _get_filtered_rules(db, filters: RuleFilters, client_id: str):
    """Every rule matching ``filters`` (unpaginated) as ``(all_rules, deduped)``.

    Every rule is now its own card -- ``deduped`` is kept only so callers that filtered/counted
    through it don't need to change (see ``_dedupe_display_rules``)."""
    all_filters = filters.model_copy(update={"page": 1, "page_size": 1_000_000})
    # Slim: the grid and the metrics read only each rule's Kibana rule_id and language, which are
    # columns of their own, so the rule JSON (tens of MB for a large client) isn't loaded.
    rules, _, _ = db.get_rules(filters=all_filters, client_id=client_id, slim=True)
    return rules, _dedupe_display_rules(db, rules, client_id)


def _get_filtered_deduped_rules(db, filters: RuleFilters, client_id: str) -> List["DetectionRule"]:
    """Every rule matching ``filters``."""
    return _get_filtered_rules(db, filters, client_id)[1]


router = APIRouter(prefix="/api/rules", tags=["rules"])


def rule_dom_id(rule_id, siem_id, space) -> str:
    """The DOM id of one rule's card or row, unique per destination: a rule_id is shared by every
    copy of a rule, so the destination is part of it. Slugified, as it ends up in a CSS selector."""
    def slug(value) -> str:
        return re.sub(r"[^A-Za-z0-9_-]", "_", str(value or ""))
    return f"rule-{slug(rule_id)}--{slug(siem_id)}--{slug(space or 'default')}"


def rule_window(rule_id, siem_id, space) -> dict:
    """What the browser needs to open one rule's window in place of the current one, keeping its
    place in prev/next (app.js tideShowRuleAfterAction): the window's URL and the card's DOM id."""
    space = space or "default"
    url = f"/api/rules/{quote(str(rule_id), safe='')}/history-modal?space={quote(space, safe='')}"
    if siem_id:
        url += f"&siem_id={quote(str(siem_id), safe='')}"
    return {"url": url, "dom_id": rule_dom_id(rule_id, siem_id, space)}

def _tactic_meta(label: str) -> Optional[dict]:
    """The ATT&CK name, id and reference of the tactic a picker group is labelled with, for a
    rule's threat entry; None if it isn't a tactic."""
    from app.attack_tactics import ID_BY_NAME, tactic_name
    name = tactic_name(label)
    if not name:
        return None
    tid = ID_BY_NAME[name]
    return {"name": name, "id": tid, "reference": f"/mitre/tactic?id={tid}"}


def _parse_scope_pair(scope_pair: str) -> tuple[str, str]:
    """Parse `<siem_id>|<space>` from create/edit forms."""
    if not scope_pair or "|" not in scope_pair:
        return "", ""
    siem_id, space = scope_pair.split("|", 1)
    return (siem_id or "").strip(), (space or "").strip() or "default"


def _format_tactic_label(raw_tactic: str) -> str:
    value = (raw_tactic or "other").replace("_", " ").replace("-", " ").strip()
    return value.title() if value else "Other"


def _normalize_author(raw_author: Any) -> str:
    if isinstance(raw_author, list):
        return ", ".join(str(item).strip() for item in raw_author if str(item).strip())
    return str(raw_author or "").strip()


def _split_csv(raw_value: Any) -> list[str]:
    if isinstance(raw_value, list):
        return [str(item).strip() for item in raw_value if str(item).strip()]
    return [part.strip() for part in str(raw_value or "").split(",") if part.strip()]


def _build_technique_groups(db) -> tuple[list[dict], dict[str, dict]]:
    """Tactic -> techniques for the pickers, each technique under every tactic it belongs to;
    and technique id -> its option under its first (primary) tactic."""
    groups: dict[str, list[dict]] = {}
    lookup: dict[str, dict] = {}
    seen: set[tuple[str, str]] = set()
    for item in db.get_mitre_technique_options() or []:
        technique_id = str(item.get("id") or "").strip().upper()
        technique_name = str(item.get("name") or "").strip()
        if not technique_id or not technique_name:
            continue
        tactic = _format_tactic_label(str(item.get("tactic") or ""))
        if (tactic, technique_id) in seen:
            continue
        seen.add((tactic, technique_id))
        option = {
            "id": technique_id,
            "name": technique_name,
            "tactic": tactic,
            "url": item.get("url") or "",
        }
        groups.setdefault(tactic, []).append(option)
        if technique_id not in lookup or tactic == _format_tactic_label(str(item.get("primary_tactic") or "")):
            lookup[technique_id] = option

    ordered = [
        {"tactic": tactic, "options": options}
        for tactic, options in sorted(groups.items(), key=lambda pair: pair[0])
    ]
    return ordered, lookup


def _extract_prefill(raw_prefill: Optional[str]) -> dict:
    if not raw_prefill:
        return {}
    try:
        return json.loads(unquote(raw_prefill))
    except Exception:
        logger.warning("Invalid rule form prefill payload")
        return {}


def _build_threat_entries(mitre_ids: list[str], technique_lookup: dict[str, dict]) -> list[dict]:
    tactic_map: dict[str, dict] = {}
    for technique_id in mitre_ids:
        option = technique_lookup.get(technique_id.upper())
        if not option:
            continue
        tactic_meta = _tactic_meta(option["tactic"])
        if not tactic_meta:
            continue
        tactic = tactic_meta["name"]
        bucket = tactic_map.setdefault(
            tactic,
            {
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "id": tactic_meta["id"],
                    "name": tactic,
                    "reference": tactic_meta["reference"],
                },
                "technique": [],
            },
        )
        technique_entry = {
            "id": option["id"],
            "name": option["name"],
        }
        if option.get("url"):
            technique_entry["reference"] = option["url"]
        bucket["technique"].append(technique_entry)
    return list(tactic_map.values())


def _rule_form_values(rule, username: str = "", prefill: Optional[dict] = None) -> dict:
    raw = (getattr(rule, "raw_data", None) or {}) if rule else {}
    severity = getattr(rule, "severity", "medium") if rule else "medium"
    severity_value = severity
    enabled = getattr(rule, "enabled", True) if rule is not None else True

    prefill = prefill or {}
    if prefill:
        name = str(prefill.get("name") or "").strip()
        description = str(prefill.get("description") or "").strip()
        query = str(prefill.get("query") or "").strip()
        language = str(prefill.get("language") or "kuery").strip().lower()
        severity_value = str(prefill.get("severity") or severity_value).strip().lower()
        author = _normalize_author(prefill.get("author") or raw.get("author") or (getattr(rule, "author", "") if rule else "") or username)
        tags_value = prefill.get("tags") or raw.get("tags") or []
        mitre_ids = [str(item).upper() for item in (prefill.get("mitre_ids") or []) if str(item).strip()]
        note = str(prefill.get("note") or raw.get("note") or "")
        index_value = prefill.get("index") or []
        timestamp_override = str(prefill.get("timestamp_override") or raw.get("timestamp_override") or "event.ingested")
        highlighted_fields = prefill.get("highlighted_fields") or []
        risk_score = prefill.get("risk_score")
        scope_pair = str(prefill.get("scope_pair") or "")
        return {
            "name": name,
            "description": description,
            "scope_pair": scope_pair or (f'{getattr(rule, "siem_id", "")}|{getattr(rule, "space", "default")}' if rule and getattr(rule, "siem_id", None) else ""),
            "language": language,
            "query": query,
            "severity": severity_value,
            "author": author,
            "tags": ", ".join(_split_csv(tags_value)),
            "mitre_ids": mitre_ids,
            "note": note,
            "interval": str(prefill.get("interval") or raw.get("interval") or "5m"),
            "from": str(prefill.get("from") or raw.get("from") or "now-6m"),
            "enabled": bool(prefill.get("enabled", enabled if enabled is not None else True)),
            "type": str(prefill.get("type") or raw.get("type") or "query"),
            "risk_score": str(risk_score if risk_score is not None else prefill.get("risk_score_default") or _severity_to_risk_score(severity_value)),
            "index": ", ".join(_split_csv(index_value)),
            "timestamp_override": timestamp_override,
            "highlighted_fields": ", ".join(_split_csv(highlighted_fields)),
            "reason": str(prefill.get("reason") or ""),
            **_type_setting_values(prefill),
        }

    return {
        "name": getattr(rule, "name", "") if rule else "",
        "scope_pair": f'{getattr(rule, "siem_id", "")}|{getattr(rule, "space", "default")}' if rule and getattr(rule, "siem_id", None) else "",
        "language": str(raw.get("language") or (rule.language if rule else "kuery") or "kuery").lower(),
        "query": str(raw.get("query") or (rule.query if rule else "") or ""),
        "description": str(raw.get("description") or ""),
        "severity": severity_value.lower(),
        "author": _normalize_author(raw.get("author") or (getattr(rule, "author", "") if rule else "") or username),
        "tags": ", ".join(_split_csv(raw.get("tags") or [])),
        "mitre_ids": [str(item).upper() for item in (getattr(rule, "mitre_ids", []) or []) if str(item).strip()],
        "note": str(raw.get("note") or ""),
        "interval": str(raw.get("interval") or "5m"),
        "from": str(raw.get("from") or "now-6m"),
        "enabled": bool(enabled if enabled is not None else True),
        "type": str(raw.get("type") or "query"),
        "risk_score": str(raw.get("risk_score") or _severity_to_risk_score(severity_value.lower())),
        "index": ", ".join(_split_csv(raw.get("index") or [])),
        # Editing shows the rule's own override (blank = none); only a new rule starts on event.ingested.
        "timestamp_override": str(raw.get("timestamp_override") or ("" if rule else "event.ingested")),
        "highlighted_fields": ", ".join(_split_csv(raw.get("investigation_fields", {}).get("field_names", []) if isinstance(raw.get("investigation_fields"), dict) else raw.get("investigation_fields") or [])),
        "reason": "",
        **_data_view_values(raw),
        **_type_setting_values(raw),
    }


def _type_setting_values(source: dict) -> dict:
    """The form's values for the settings only some rule types have (rule_type_settings), from a rule
    or a prefill shaped like one; a new rule starts on Kibana's own defaults. Filters, which the form
    leaves as Kibana has them, come as text to show."""
    from app.services import rule_type_settings as rts
    return {
        "threat_index": ", ".join(_split_csv(source.get("threat_index") or [])),
        "threat_query": str(source.get("threat_query") or rts.INDICATOR_QUERY_DEFAULT),
        "threat_language": str(source.get("threat_language") or "kuery").lower(),
        "threat_mapping": json.dumps(rts.mapping_groups(source.get("threat_mapping"))),
        "threat_indicator_path": str(source.get("threat_indicator_path") or ""),
        **_threshold_values(rts.threshold_parts(source.get("threshold") or {"value": rts.THRESHOLD_DEFAULT})),
        "new_terms_fields": ", ".join(_split_csv(source.get("new_terms_fields") or [])),
        "history_window": rts.history_window(source.get("history_window_start")) or rts.HISTORY_WINDOW_DEFAULT,
        "filters_text": rts.filter_texts(source.get("filters")),
        "threat_filters_text": rts.filter_texts(source.get("threat_filters")),
    }


def _threshold_values(threshold: dict) -> dict:
    """A threshold (rule_type_settings.threshold_parts) as the form's fields: Group by, Threshold, and
    Count's first field and unique values; any further Count settings (Kibana's own form shows one)
    ride along as JSON, kept as they are."""
    counts = threshold.get("cardinality") or []
    first = counts[0] if counts else {"field": "", "value": ""}
    return {
        "threshold_field": ", ".join(threshold.get("field") or []),
        "threshold_value": str(threshold.get("value") if threshold.get("value") not in (None, "") else ""),
        "threshold_cardinality_field": first["field"],
        "threshold_cardinality_value": str(first["value"]),
        "threshold_cardinality_rest": json.dumps(counts[1:]) if len(counts) > 1 else "",
    }


def _data_view_values(raw: dict) -> dict:
    """Whether the rule searches a data view, and its name ("" when TIDE couldn't read it). Kibana
    searches the data view, not index patterns, so the Edit form shows it instead of them."""
    from app.elastic_helper import DATA_VIEW_NOTE
    note = raw.get(DATA_VIEW_NOTE)
    uses = isinstance(note, dict) or bool(raw.get("data_view_id") or raw.get("dataViewId"))
    return {"uses_data_view": uses, "data_view": str(note.get("name") or "") if isinstance(note, dict) else ""}


def _build_rule_form_context(db, client_id: str, username: str, form_action: str, submit_label: str,
                             title: str, rule=None, scope_locked: bool = False,
                             prefill: Optional[dict] = None) -> dict:
    siems = db.get_client_siems(client_id) or []
    technique_groups, technique_lookup = _build_technique_groups(db)
    scope_options = [
        {
            "siem_id": s.get("id"),
            "space": s.get("space") or "default",
            "label": s.get("name") or s.get("label", "SIEM"),
            "default_index": s.get("default_index") or "",
        }
        for s in siems
        if s.get("id") and (s.get("space") is not None)
    ]
    form_values = _rule_form_values(rule, username=username, prefill=prefill)
    # Rule type: a new rule can be any type the form edits. An existing rule (or Elastic's or Sigma's,
    # being deployed) switches only between the types its query language decides, as TIDE always has;
    # any other type keeps its own, as on Kibana's Edit page.
    current = form_values["type"]
    if current not in _LANGUAGE_TYPES:
        type_choices, type_locked = (current,), True
    else:
        type_choices, type_locked = (_LANGUAGE_TYPES if rule or prefill else _LANGUAGE_TYPES + _FORM_TYPES), False
    selected_tactics = []
    for mitre_id in form_values.get("mitre_ids", []):
        option = technique_lookup.get(str(mitre_id).upper())
        if option and option.get("tactic") not in selected_tactics:
            selected_tactics.append(option.get("tactic"))
    return {
        "form_action": form_action,
        "submit_label": submit_label,
        "modal_title": title,
        "scope_options": scope_options,
        "technique_groups": technique_groups,
        "mitre_tactics": [group["tactic"] for group in technique_groups],
        "selected_tactics": selected_tactics,
        "form_values": form_values,
        "mode": "edit" if rule else "create",
        "type_options": [(t, rule_type_name(t), " ".join(_TYPE_LANGUAGES.get(t, _QUERY_LANGUAGES))) for t in type_choices],
        "type_locked": type_locked,
        "type_languages": _TYPE_LANGUAGES.get(current, _QUERY_LANGUAGES),
        # A type whose own settings the form doesn't show: they stay as Kibana has them.
        "rule_type_label": _rule_type_label(current) if current not in _LANGUAGE_TYPES + _FORM_TYPES else "",
        "scope_locked": scope_locked,
        "rule": rule,
        # One of Elastic's prebuilt rules still in Kibana: the form says what saving does to it.
        "prebuilt": bool(rule and not rule.deprecated and is_prebuilt(rule.raw_data)),
        "siem_id": getattr(rule, "siem_id", "") if rule else "",
        "space": getattr(rule, "space", "default") if rule else "default",
        # A converted Sigma rule: Create records it as the rule's origin.
        "sigma_id": "" if rule else str((prefill or {}).get("sigma_id") or ""),
    }


def _severity_to_risk_score(severity: str) -> int:
    return {
        "low": 21,
        "medium": 47,
        "high": 73,
        "critical": 99,
    }.get((severity or "medium").lower(), 47)


# Kibana's detection_engine/rules API validates ``language`` against a
# different enum per rule ``type`` (e.g. the "query" type only accepts
# kuery/lucene) — sending type="query" with language="eql"/"esql" 400s.
_RULE_TYPE_BY_LANGUAGE = {
    "kuery": "query",
    "lucene": "query",
    "eql": "eql",
    "esql": "esql",
}
# The query languages each rule type takes, as the form offers them ("kql" is KQL's legacy name).
_QUERY_LANGUAGES = ("kuery", "kql", "lucene")
_TYPE_LANGUAGES = {"query": _QUERY_LANGUAGES, "eql": ("eql",), "esql": ("esql",)}


def _posted_rule_type(form_data, language: str) -> str:
    """The rule type the form posted: Rule type, when it is one the form edits and takes ``language``;
    else the one the query language decides (a form or a caller that posts no type, or a type the form
    shows but doesn't edit, such as threshold)."""
    posted = str(form_data.get("type") or "").strip()
    if posted in _FORM_TYPES or language in _TYPE_LANGUAGES.get(posted, ()):
        return posted
    return _RULE_TYPE_BY_LANGUAGE.get(language, "query")


def _build_rule_payload(form_data, technique_lookup: dict[str, dict], default_author: str) -> tuple[dict, str, str, list[str]]:
    from app.elastic_helper import normalize_rule_language
    from app.services import rule_type_settings as rts

    rule_name = (form_data.get("name") or "").strip()
    description = (form_data.get("description") or "").strip()
    query = (form_data.get("query") or "").strip()
    language = normalize_rule_language(form_data.get("language") or "kuery")
    severity = (form_data.get("severity") or "medium").strip().lower()
    enabled = str(form_data.get("enabled") or "true").lower() == "true"
    author_value = (form_data.get("author") or "").strip() or default_author
    author_values = _split_csv(author_value)
    if not author_values:
        author_values = _split_csv(default_author)
    if not author_values:
        author_values = ["Unknown"]
    tags = _split_csv(form_data.get("tags") or "")
    note = (form_data.get("note") or "").strip()
    interval = (form_data.get("interval") or "5m").strip() or "5m"
    lookback = (form_data.get("from") or "now-6m").strip() or "now-6m"
    risk_score_raw = (form_data.get("risk_score") or "").strip()
    index_patterns = _split_csv(form_data.get("index") or "")
    timestamp_override = (form_data.get("timestamp_override") or "").strip()   # blank = no override
    highlighted_fields = _split_csv(form_data.get("highlighted_fields") or "")
    reason = (form_data.get("reason") or "").strip()
    raw_mitre_values = (
        form_data.getlist("mitre_ids") if hasattr(form_data, "getlist") else []
    )
    mitre_ids: list[str] = []
    for raw_value in raw_mitre_values:
        mitre_ids.extend(item.upper() for item in _split_csv(raw_value))
    if not mitre_ids:
        mitre_ids = [item.upper() for item in _split_csv(form_data.get("mitre_ids") or "")]
    mitre_ids = list(dict.fromkeys(mitre_ids))

    payload = {
        "name": rule_name,
        "description": description or rule_name,
        "query": query,
        "language": language,
        "severity": severity,
        "risk_score": int(risk_score_raw) if risk_score_raw.isdigit() else _severity_to_risk_score(severity),
        "enabled": enabled,
        "author": author_values,
        "tags": tags,
        "note": note,
        "interval": interval,
        "from": lookback,
        "type": _posted_rule_type(form_data, language),
        "mitre_ids": mitre_ids,
        "index": index_patterns,
    }
    if payload["type"] == "threat_match":
        payload.update({
            "threat_index": _split_csv(form_data.get("threat_index") or ""),
            "threat_query": (form_data.get("threat_query") or "").strip(),
            "threat_language": normalize_rule_language(form_data.get("threat_language") or "kuery"),
            "threat_mapping": rts.mapping_groups(form_data.get("threat_mapping") or ""),
        })
        prefix = (form_data.get("threat_indicator_path") or "").strip()   # blank: Kibana's threat.indicator
        if prefix:
            payload["threat_indicator_path"] = prefix
    elif payload["type"] == "threshold":
        payload["threshold"] = rts.threshold_from_form(
            form_data.get("threshold_field") or "", form_data.get("threshold_value") or "",
            form_data.get("threshold_cardinality_field") or "", form_data.get("threshold_cardinality_value") or "",
            form_data.get("threshold_cardinality_rest") or "")
    elif payload["type"] == "new_terms":
        payload["new_terms_fields"] = _split_csv(form_data.get("new_terms_fields") or "")
        payload["history_window_start"] = rts.history_window_start(form_data.get("history_window") or "")
    if timestamp_override:
        payload["timestamp_override"] = timestamp_override
    if language == "esql":
        # ES|QL rules source their index from the query's FROM clause —
        # Kibana's esql rule schema doesn't accept a separate "index" field.
        payload.pop("index", None)
    if highlighted_fields:
        payload["investigation_fields"] = {"field_names": highlighted_fields}
    if reason:
        payload["reason"] = reason
    threat = _build_threat_entries(mitre_ids, technique_lookup)
    if threat:
        payload["threat"] = threat
    else:
        payload["threat"] = []
    return payload, rule_name, query, mitre_ids


def _as_form(values: dict):
    """Form values (``_rule_form_values``) as the browser would post them."""
    from starlette.datastructures import FormData
    def text(v):
        return ", ".join(v) if isinstance(v, list) else ("true" if v else "false") if isinstance(v, bool) else str(v)
    return FormData([(k, text(v)) for k, v in values.items()])


# Optional fields the Edit form can clear: a field it shows empty that the rule has is removed.
_CLEARABLE = ("timestamp_override", "investigation_fields")
# Rule types whose type follows the query language. Others keep their own type: the form edits the
# settings of those in _FORM_TYPES too (rule_type_settings); of the rest (machine learning, saved
# query) only the common fields, leaving their own settings as Kibana has them.
_LANGUAGE_TYPES = ("query", "eql", "esql")
_FORM_TYPES = ("threshold", "new_terms", "threat_match")


def _form_changes(rule, form, technique_lookup: dict, username: str) -> tuple[dict, tuple, str]:
    """What the user changed in the Edit form: ``(changes, removed, problem)``.

    The form shows every field, filled from TIDE's copy of the rule, and posts every field back.
    Only the fields whose value differs from what the form showed are changes: both sides go
    through the same normalisation (``_build_rule_payload``), so a field the user didn't touch is
    never sent, and Kibana keeps whatever it holds for it. ``problem`` is a sentence for the user
    when the change can't be made.
    """
    raw = getattr(rule, "raw_data", None) or {}
    return changes_against(_rule_form_values(rule, username), str(raw.get("type") or "query"),
                           form, technique_lookup, username)


def changes_against(shown: dict, rule_type: str, form, technique_lookup: dict, username: str) -> tuple[dict, tuple, str]:
    """``_form_changes`` for any rule form: what differs between the values the form was shown
    with (``shown``, as ``_rule_form_values`` gives them) and what it posted, for a rule of
    ``rule_type``. Also used to deploy one of Elastic's rules with the user's changes."""
    before, *_ = _build_rule_payload(_as_form(shown), technique_lookup, username)
    after, *_ = _build_rule_payload(form, technique_lookup, username)
    if not after["name"]:
        return {}, (), "The rule needs a name."

    changes = {}
    for key, value in after.items():
        if key in ("reason", "type", "threat"):
            continue
        if key == "mitre_ids":
            if _canonicalize_id_list(value, uppercase=True) != _canonicalize_id_list(before.get(key), uppercase=True):
                changes["mitre_ids"], changes["threat"] = value, after["threat"]
        elif value != before.get(key):
            changes[key] = value
    removed = tuple(k for k in _CLEARABLE if k in before and k not in after)

    if shown.get("uses_data_view"):
        # Kibana searches the rule's data view, so index patterns are a change only when the user
        # chose Use index patterns instead, and then even when they are the data view's own.
        changes.pop("index", None)
        if str(form.get("use_index_patterns") or "") == "1":
            if not after.get("index"):
                return {}, (), "Give the index patterns to search, or untick Use index patterns instead."
            changes["index"] = after["index"]

    if "language" in changes:
        if rule_type in _LANGUAGE_TYPES:
            changes["type"] = after["type"]
        elif {before.get("language"), after.get("language")} - {"kuery", "lucene"}:
            # Any other type stays itself: its query is KQL or Lucene, as Kibana allows.
            return {}, (), (f"A {_rule_type_label(rule_type)} rule's query is KQL or Lucene. "
                            "Set the language back.")
    if "query" in changes and not changes["query"] and rule_type != "query":
        return {}, (), "The query can't be empty."
    from app.services.rule_type_settings import SETTING_KEYS, settings_problem
    if after["type"] in _FORM_TYPES and ("language" in changes or set(changes) & set(SETTING_KEYS[after["type"]])):
        problem = settings_problem(after)
        if problem:
            return {}, (), problem
    return changes, removed, ""


def _rule_type_label(rule_type: str) -> str:
    return rule_type_name(rule_type, in_sentence=True)


def _form_error(message: str, status_code: int = 400) -> HTMLResponse:
    """A refusal shown inside the open rule form (rule_form.js puts it in ``#rule-form-error``),
    so what the user typed stays where it is."""
    return HTMLResponse(f'<p class="rm-note rm-note--danger" role="alert">{escape(message)}</p>',
                        status_code=status_code)


def _value_for_compare(value: Any) -> str:
    if isinstance(value, list):
        return ",".join(str(v).strip() for v in value if str(v).strip())
    if isinstance(value, dict):
        try:
            return json.dumps(value, sort_keys=True)
        except Exception:
            return str(value)
    return str(value or "").strip()


def _value_for_display(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, list):
        cleaned = [str(v).strip() for v in value if str(v).strip()]
        return ", ".join(cleaned) if cleaned else "-"
    if isinstance(value, dict):
        try:
            return json.dumps(value, sort_keys=True)
        except Exception:
            return str(value)
    text = str(value).strip()
    return text if text else "-"


def _canonicalize_id_list(value: Any, *, uppercase: bool = False) -> list[str]:
    """Normalize list-like values for stable equality checks.

    Handles list inputs and comma-separated strings, trims whitespace,
    optionally uppercases values, de-duplicates case-insensitively, and sorts
    for order-independent comparison.
    """
    if value is None:
        return []

    if isinstance(value, str):
        raw_items = value.split(",")
    elif isinstance(value, (list, tuple, set)):
        raw_items = list(value)
    else:
        raw_items = [value]

    seen: set[str] = set()
    normalized: list[str] = []
    for item in raw_items:
        text = str(item or "").strip()
        if not text:
            continue
        if uppercase:
            text = text.upper()
        marker = text.lower()
        if marker in seen:
            continue
        seen.add(marker)
        normalized.append(text)

    normalized.sort(key=str.lower)
    return normalized


# What the Edit form changes, as the user calls it (History, messages).
_FIELD_LABELS = {
    "name": "name",
    "description": "description",
    "query": "query",
    "language": "language",
    "severity": "severity",
    "risk_score": "risk score",
    "enabled": "enabled",
    "author": "author",
    "tags": "tags",
    "note": "investigation guide",
    "interval": "interval",
    "from": "lookback",
    "index": "index",
    "timestamp_override": "timestamp override",
    "investigation_fields": "custom highlighted fields",
    "mitre_ids": "MITRE techniques",
    "threat_index": "indicator index patterns",
    "threat_query": "indicator index query",
    "threat_language": "indicator query language",
    "threat_mapping": "indicator mapping",
    "threat_indicator_path": "indicator prefix override",
    "threshold": "threshold",
    "new_terms_fields": "new terms fields",
    "history_window_start": "history window",
}


def _summarize_rule_changes(old_payload: dict, new_payload: dict) -> tuple[str, str, list[dict[str, str]]]:
    changed: list[str] = []
    changed_diffs: list[dict[str, str]] = []
    for key, label in _FIELD_LABELS.items():
        if key not in new_payload and key not in old_payload:
            continue

        if key == "threshold":
            from app.services.rule_type_settings import threshold_parts, threshold_text
            if threshold_parts(old_payload.get(key)) != threshold_parts(new_payload.get(key)):
                changed.append(label)
                changed_diffs.append({"field": label, "before": threshold_text(old_payload.get(key)) if old_payload.get(key) else "-",
                                      "after": threshold_text(new_payload.get(key)) if new_payload.get(key) else "-"})
            continue

        if key == "threat_mapping":
            from app.services.rule_type_settings import mapping_groups, mapping_text
            if mapping_groups(old_payload.get(key)) != mapping_groups(new_payload.get(key)):
                changed.append(label)
                changed_diffs.append({"field": label, "before": mapping_text(old_payload.get(key)),
                                      "after": mapping_text(new_payload.get(key))})
            continue

        if key in ("mitre_ids", "investigation_fields"):
            # Compared as id lists: order-free, and highlighted fields' {"field_names": []} is none.
            names = lambda v: v.get("field_names") if isinstance(v, dict) else v
            before_ids = _canonicalize_id_list(names(old_payload.get(key)), uppercase=key == "mitre_ids")
            after_ids = _canonicalize_id_list(names(new_payload.get(key)), uppercase=key == "mitre_ids")
            if before_ids != after_ids:
                changed.append(label)
                changed_diffs.append(
                    {
                        "field": label,
                        "before": ", ".join(before_ids) if before_ids else "-",
                        "after": ", ".join(after_ids) if after_ids else "-",
                    }
                )
            continue

        before = _value_for_compare(old_payload.get(key))
        after = _value_for_compare(new_payload.get(key))
        if before != after:
            changed.append(label)
            changed_diffs.append(
                {
                    "field": label,
                    "before": _value_for_display(old_payload.get(key)),
                    "after": _value_for_display(new_payload.get(key)),
                }
            )

    if not changed:
        return "Updated rule settings.", "-", []

    if len(changed) == 1:
        message = f"Edited '{changed[0]}' field."
    elif len(changed) == 2:
        message = f"Edited '{changed[0]}' and '{changed[1]}' fields."
    else:
        quoted = ", ".join(f"'{name}'" for name in changed[:-1])
        message = f"Edited {quoted}, and '{changed[-1]}' fields."
    return message, ", ".join(changed), changed_diffs


def _build_rule_history_entries(history: list[dict], score_history: list[dict]) -> list[dict]:
    """Build one unified history timeline for the modal accordion."""
    from app.services.database import get_database_service
    aliases = get_database_service().get_actor_aliases() if history else {}

    def _normalize_history_actor(actor_name: Any) -> str:
        # One person reads as one person: username, email or full name all show the username.
        raw_name = str(actor_name or "").strip()
        if not raw_name:
            return "system"
        normalized = " ".join(raw_name.lower().split())
        if normalized in {"elastic", "system"}:
            return normalized
        return aliases.get(normalized, raw_name)

    entries: list[dict] = []

    for event in history:
        action = str(event.get("action") or "").strip().lower()
        category = "validation" if action == "validated" else "edits"
        if action == "validated":
            badge = "Validated"
        elif action == "edited":
            badge = "Edit"
        elif action == "new_rule_id":
            badge = "New rule id"
        elif action:
            badge = action.replace("_", " ").title()
        else:
            badge = "Edit"

        detail = event.get("detail") or {}
        field_diffs = detail.get("field_diffs") or []
        changed_fields = detail.get("changed_fields") or ""
        if (
            action == "edited"
            and detail.get("source") == "elastic_sync"
            and not field_diffs
            and not changed_fields
        ):
            fallback_diffs: list[dict[str, str]] = []
            if detail.get("elastic_timestamp"):
                fallback_diffs.append(
                    {
                        "field": "updated_at",
                        "before": "-",
                        "after": str(detail.get("elastic_timestamp")),
                    }
                )
            if detail.get("kibana_user"):
                fallback_diffs.append(
                    {
                        "field": "updated_by",
                        "before": "-",
                        "after": str(detail.get("kibana_user")),
                    }
                )
            if fallback_diffs:
                field_diffs = fallback_diffs
                changed_fields = ", ".join(item.get("field", "") for item in fallback_diffs if item.get("field"))

        entries.append(
            {
                "kind": category,
                "action": action,
                "badge": badge,
                "actor": _normalize_history_actor(event.get("actor_name")),
                "created_at": event.get("created_at"),
                "message": detail.get("message") or "",
                "reason": detail.get("reason") or "",
                "elastic_timestamp": detail.get("elastic_timestamp") or "",
                "changed_fields": changed_fields,
                "field_diffs": field_diffs,
                "expandable": category == "edits",
            }
        )

    for score_row in score_history:
        score_value = score_row.get("score")
        score_display = "N/A" if score_value is None else str(score_value)
        entries.append(
            {
                "kind": "score",
                "action": "score",
                "badge": f"Score: {score_display}/100",
                "actor": "system",
                "created_at": score_row.get("created_at"),
                "message": "",
                "reason": "",
                "elastic_timestamp": "",
                "changed_fields": "",
                "field_diffs": [],
                "score": score_row,
                "expandable": True,
            }
        )

    def _entry_time(item: dict) -> float:
        created_at = item.get("created_at")
        if not created_at:
            return 0.0
        try:
            return float(created_at.timestamp())
        except Exception:
            return 0.0

    entries.sort(key=_entry_time, reverse=True)
    return entries


def _build_space_labels(db, client_id: str) -> dict:
    """Build space → environment-role label mapping for the active client.

    CLAUDE.md §8.2 guarantee 4: two SIEMs can share a Kibana space-name.
    Keying this dict by ``space`` alone silently overwrites the first SIEM's
    label with the second SIEM's label, so the rule grid badge then shows
    rules from SIEM A under SIEM B's name. We therefore concatenate every
    SIEM/role label that maps to the same space-name into one display string
    (`"SIEM A (Production) / SIEM B (Staging)"`) so no SIEM is hidden. For
    callers that have a rule's ``siem_id`` available (e.g. ``rule_card``),
    the unambiguous lookup is exposed as ``space_labels_by_pair`` keyed by
    ``"<siem_id>|<space>"``.
    """
    try:
        siems = db.get_client_siems(client_id)
    except Exception:
        return {}
    out: dict = {}
    for s in siems or []:
        space = s.get("space")
        if not space:
            continue
        label = s.get("name") or s["label"]
        existing = out.get(space)
        if existing and label not in existing.split(" / "):
            out[space] = f"{existing} / {label}"
        elif not existing:
            out[space] = label
    return out


def _build_space_labels_by_pair(db, client_id: str) -> dict:
    """Unambiguous ``"<siem_id>|<space>"`` → label lookup. Templates that
    have a per-rule ``siem_id`` should prefer this over ``space_labels``."""
    try:
        siems = db.get_client_siems(client_id)
    except Exception:
        return {}
    return {
        f'{s["id"]}|{s["space"]}': s.get("name") or s["label"]
        for s in (siems or [])
        if s.get("id") and s.get("space")
    }


def _build_scope_labels(db, client_id: str) -> dict:
    """``"<siem_id>|<space lower>"`` -> destination name, matching the keys of
    ``RuleHealthMetrics.rules_by_scope`` and the SIEM filter's option values."""
    try:
        siems = db.get_client_siems(client_id)
    except Exception:
        return {}
    return {
        f'{s["id"]}|{str(s["space"]).lower()}': s.get("name") or s["label"]
        for s in (siems or [])
        if s.get("id") and s.get("space")
    }


def _build_space_colors_by_pair(db, client_id: str) -> dict:
    """``"<siem_id>|<space>"`` → the destination's chosen colour (Management → Linked SIEMs),
    for the small colour dot on each rule card's SIEM pill. Absent/empty when a destination has
    no colour set (pre-6.0.0 rows all get one via Migration 67, but stay defensive anyway)."""
    try:
        siems = db.get_client_siems(client_id)
    except Exception:
        return {}
    return {
        f'{s["id"]}|{s["space"]}': s["color"]
        for s in (siems or [])
        if s.get("id") and s.get("space") and s.get("color")
    }


def _build_kibana_urls_by_siem(db, client_id: str) -> dict:
    """``siem_id`` → ``kibana_url`` map for the active client.

    The rule card's "Open in Kibana" link previously composed the URL
    from a global ``env.elastic_url`` setting that was removed in 4.0.10,
    so the button silently anchored to the TIDE host. Each rule carries
    its owning ``siem_id``; the card template uses this dict to resolve
    the right Kibana base URL per row. Returns an empty dict on failure
    — the template falls back to the global env value (and ultimately
    hides the link if neither is set).
    """
    try:
        siems = db.get_client_siems(client_id)
    except Exception:
        return {}
    return {
        s["id"]: s.get("kibana_url") or ""
        for s in (siems or [])
        if s.get("id")
    }


def _resolve_kibana_url(db, rule, client_id: str) -> str:
    """Return the Kibana base URL for a rule's owning SIEM (or '' if none).

    The rule detail modal builds an "Open in Kibana" button. Before this
    helper the template tried to read a non-existent global ``elastic_url``
    setting (removed in 4.0.10), so the link silently anchored to the TIDE
    host instead of Kibana. Now we look the rule's ``siem_id`` up in the
    active client's SIEM map and return the per-SIEM ``kibana_url``. Returns
    an empty string when the rule has no SIEM, when the SIEM is no longer
    assigned to the active tenant, or when the SIEM row carries no Kibana
    URL — the template hides the button in that case.
    """
    siem_id = getattr(rule, "siem_id", None) if rule else None
    if not siem_id or not client_id:
        return ""
    try:
        for s in (db.get_client_siems(client_id) or []):
            if s.get("id") == siem_id:
                return s.get("kibana_url") or ""
    except Exception:
        logger.debug("kibana_url resolution failed for rule siem_id=%s", siem_id)
    return ""


def _filter_scope_options(db, client_id: str):
    """Rule Health's SIEM filter options: ``(scopes, spaces)`` holding rules in this client's
    database, as ``"siem_id|space"`` (space lowercased) and space keys, limited to destinations
    still linked to the client (as _prune_orphan_scopes does for the metrics). The same keys the
    unfiltered metrics' ``rules_by_scope`` / ``rules_by_space`` gave, from one DISTINCT query
    instead of loading every rule."""
    with db.get_connection() as conn:
        try:
            pairs = conn.execute("SELECT DISTINCT siem_id, space FROM detection_rules WHERE space IS NOT NULL").fetchall()
        except Exception:
            return [], []
    holder = RuleHealthMetrics(
        rules_by_space={str(sp): 1 for _, sp in pairs},
        rules_by_scope={f"{sid}|{str(sp).lower()}": 1 for sid, sp in pairs if sid is not None},
    )
    _prune_orphan_scopes(holder, db, client_id)
    return sorted(holder.rules_by_scope), sorted(holder.rules_by_space)


def _prune_orphan_scopes(metrics, db, client_id: str):
    """Strip rule-count buckets for spaces no longer in ``client_siem_map``.

    After a SIEM mapping change (space removed / SIEM repointed) the old
    rows linger in ``detection_rules`` until the next sync cleans them up.
    They show up in the Rule Health metrics card as orphan entries (e.g.
    ``One: 7`` once the ``one`` space was unmapped). The sync path will
    eventually delete them, but in the meantime we hide them from the UI
    so the card reflects the *current* mapping. Mutates ``metrics`` in
    place; safe no-op if the client has no SIEMs.
    """
    try:
        siems = db.get_client_siems(client_id) or []
    except Exception:
        return metrics
    allowed_spaces = {s["space"] for s in siems if s.get("space")}
    allowed_pairs = {
        f'{s["id"]}|{str(s["space"]).lower()}'
        for s in siems
        if s.get("id") and s.get("space")
    }
    if metrics.rules_by_space:
        metrics.rules_by_space = {
            k: v for k, v in metrics.rules_by_space.items() if k in allowed_spaces
        }
    if metrics.rules_by_scope:
        metrics.rules_by_scope = {
            k: v for k, v in metrics.rules_by_scope.items() if k in allowed_pairs
        }
    return metrics


@router.get("", response_class=HTMLResponse)
def list_rules(
    request: Request,
    db: DbDep,
    user: CurrentUser,
    client_id: ActiveClient,
    search: Optional[str] = Query(None),
    space: Optional[str] = Query(None),
    enabled: Optional[str] = Query(None),
    state: list[str] = Query([]),
    linked_to: Optional[str] = Query(None),
    upstream: list[str] = Query([]),
    rule_type: list[str] = Query([]),
    language: list[str] = Query([]),
    min_score: Optional[str] = Query(None),
    max_score: Optional[str] = Query(None),
    validation: list[str] = Query([]),
    validated_from: Optional[str] = Query(None),
    validated_to: Optional[str] = Query(None),
    sort_by: str = Query("score_desc"),
    sort_score: str = Query("desc"),
    sort_validated: str = Query(""),
    sort_name: str = Query(""),
    page: int = Query(1, ge=1),
    page_size: int = Query(24, ge=1, le=100),
    append: bool = Query(False),
    view: str = Query("cards"),
    sort_col: str = Query(""),
    sort_dir: str = Query(""),
):
    """List detection rules with filtering and pagination."""
    try:
        validated_from_dt = _parse_date_bound(validated_from, end_of_day=False)
        validated_to_dt = _parse_date_bound(validated_to, end_of_day=True)
        min_score_int = int(min_score) if min_score and min_score.strip().lstrip('-').isdigit() else None
        max_score_int = int(max_score) if max_score and max_score.strip().lstrip('-').isdigit() else None
        # Tenant isolation is handled by the ActiveClient dep, which pins
        # the request to the tenant's DuckDB file. Detection rules are
        # per-tenant since 4.1.13 — no allowed_scopes filter needed.
        filters = RuleFilters(
            search=search if search else None,
            space=space if space else None,
            enabled=None if not enabled else (enabled.lower() == 'true'),
            state=[s for s in state if s],
            linked_to=linked_to or None,
            upstream=[u for u in upstream if u],
            rule_type=[t for t in rule_type if t],
            language=[l for l in language if l],
            min_score=min_score_int,
            max_score=max_score_int,
            validation=[v for v in validation if v],
            validated_from=validated_from_dt,
            validated_to=validated_to_dt,
            sort_by=sort_by,
            sort_score=sort_score,
            sort_validated=sort_validated,
            sort_name=sort_name,
            page=page,
            page_size=page_size,
        )
        
        # Rule Health is a master-rule view: a tracked staging/production
        # pair renders once using the production copy (falling back to
        # staging if production was deleted). Dedup must happen on the
        # FULL filtered set before pagination — deduping only the current
        # page's slice lets a pair split across two pages render as two
        # separate cards, and makes the pagination total disagree with
        # the stats cards (which are computed the same way).
        all_rules = _get_filtered_deduped_rules(db, filters, client_id)
        sort_ctx = None
        if sort_col in _COLUMN_SORTS:
            _labels_by_pair = _build_space_labels_by_pair(db, client_id)
            _labels = _build_space_labels(db, client_id)
            sort_ctx = {
                "offline": db.get_offline_scopes(),
                "siem_label": lambda r: _labels_by_pair.get(f"{r.siem_id}|{r.space}") or _labels.get(r.space or "default", ""),
            }
            if sort_col == "alerts":       # each rule's alerts in the last 7 days (#68)
                from app.services import rule_alerts
                with db.get_connection() as _conn:
                    sort_ctx["alerts"] = rule_alerts.per_rule(_conn, [(r.rule_id, r.siem_id, r.space) for r in all_rules])
        all_rules = _resort_rules(all_rules, sort_score, sort_validated, sort_name, sort_by, sort_col, sort_dir, sort_ctx)
        if search and search.strip():
            # Search also matches author, rule id and MITRE ids, so a short term (e.g. "111") can hit
            # dozens of rule-id substrings. Show name matches first (exact, then contains); the chosen
            # sort still orders rules within each group (sorted() is stable).
            _q = search.strip().lower()
            all_rules = sorted(
                all_rules,
                key=lambda r: 0 if (r.name or "").lower() == _q else 1 if _q in (r.name or "").lower() else 2,
            )
        total = len(all_rules)
        total_pages = max(1, (total + page_size - 1) // page_size)
        offset = (page - 1) * page_size
        rules = all_rules[offset:offset + page_size]

        card_ctx = build_rule_card_context(db, client_id, rules)
        
        logger.info(f"Fetched {len(rules)} rules (total: {total}, page: {page}/{total_pages})")
        
        templates = request.app.state.templates
        context = {
            "rules": rules,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "search": search or "",
            "space": space or "",
            "enabled": enabled or "",
            "state": [s for s in state if s],
            "linked_to": linked_to or "",
            "upstream": [u for u in upstream if u],
            "rule_type": [t for t in rule_type if t],
            "language": [l for l in language if l],
            "min_score": min_score if min_score is not None else "",
            "max_score": max_score if max_score is not None else "",
            "validation": [v for v in validation if v],
            "validated_from": validated_from or "",
            "validated_to": validated_to or "",
            "sort_by": sort_by,
            "sort_score": sort_score,
            "sort_validated": sort_validated,
            "sort_name": sort_name,
            **card_ctx,
            "append": append,
            "view": view if view in ("cards", "table") else "cards",
            "sort_col": sort_col if sort_col in _COLUMN_SORTS else "",
            "sort_dir": sort_dir if (sort_col in _COLUMN_SORTS and sort_dir in ("asc", "desc")) else "",
        }
        response = templates.TemplateResponse(request, "partials/rules_grid.html", context)
        # Lets the stats cards re-fetch with the same active filters (see
        # #metrics-container in rule_health.html) so they never drift from
        # what the grid is currently showing. Not when the grid loads itself (the page has just
        # drawn the cards, and they refresh on refreshRules of their own): working them and the
        # filter counts out twice made every visit to Rule Health load every rule twice more.
        if not append and request.headers.get("HX-Trigger") != "rules-grid":
            response.headers["HX-Trigger"] = "rulesFiltered"
        return response
    except Exception as e:
        logger.exception(f"Failed to list rules (sort={sort_by}, space={space}): {e}")
        return HTMLResponse('<div class="alert alert-danger">Could not load the rules. Check the server logs for details.</div>')


@router.get("/metrics", response_class=HTMLResponse)
def get_metrics(
    request: Request,
    db: DbDep,
    user: CurrentUser,
    client_id: ActiveClient,
    search: Optional[str] = Query(None),
    space: Optional[str] = Query(None),
    enabled: Optional[str] = Query(None),
    state: list[str] = Query([]),
    linked_to: Optional[str] = Query(None),
    upstream: list[str] = Query([]),
    rule_type: list[str] = Query([]),
    language: list[str] = Query([]),
    min_score: Optional[str] = Query(None),
    max_score: Optional[str] = Query(None),
    validation: list[str] = Query([]),
    validated_from: Optional[str] = Query(None),
    validated_to: Optional[str] = Query(None),
):
    """Get rule health metrics, scoped to the same filters as the rules grid. The number beside each
    filter choice follows the filters too: they come along as the ``filterCounts`` event, by filter
    field (app.js puts them in the filter bar, which isn't redrawn)."""
    params = {
        "search": search, "space": space, "enabled": enabled, "state": state, "linked_to": linked_to,
        "upstream": upstream, "rule_type": rule_type, "language": language, "min_score": min_score,
        "max_score": max_score, "validation": validation, "validated_from": validated_from, "validated_to": validated_to,
    }
    ctx = filtered_rule_metrics(db, client_id, params)
    response = request.app.state.templates.TemplateResponse(request, "partials/metrics_row.html", ctx)
    counts = db.rule_filter_counts(rule_filters_from(params), client_id=client_id)
    response.headers["HX-Trigger"] = json.dumps({"filterCounts": {
        "space": counts["scope"], **{k: counts[k] for k in ("enabled", "state", "linked_to", "upstream", "validation",
                                                             "rule_type", "language")}}})
    return response


def rule_filters_from(params: dict) -> RuleFilters:
    """Rule Health's filters, given as the page takes them (``space`` is "<siem_id>|<space>")."""
    def _int(value):
        value = "" if value is None else str(value)
        return int(value) if value.strip().lstrip('-').isdigit() else None

    enabled = str(params.get("enabled") or "")
    return RuleFilters(
        search=params.get("search") or None,
        space=params.get("space") or None,
        enabled=None if not enabled else (enabled.lower() == 'true'),
        state=[s for s in (params.get("state") or []) if s],
        linked_to=params.get("linked_to") or None,
        upstream=[u for u in (params.get("upstream") or []) if u],
        rule_type=[t for t in (params.get("rule_type") or []) if t],
        language=[l for l in (params.get("language") or []) if l],
        min_score=_int(params.get("min_score")),
        max_score=_int(params.get("max_score")),
        validation=[v for v in (params.get("validation") or []) if v],
        validated_from=_parse_date_bound(params.get("validated_from"), end_of_day=False),
        validated_to=_parse_date_bound(params.get("validated_to"), end_of_day=True),
    )


def filtered_rule_metrics(db, client_id: str, params: dict, keep_rules: bool = False) -> dict:
    """Rule Health's metric strip for these filters (:func:`rule_filters_from`): the context
    partials/metrics_row.html needs. The page's metrics and a Dashboard section built from it both
    come from here, so they always agree. ``keep_rules`` adds the rules counted (``rules``), for a
    section working out the same figures on an earlier day."""
    from app.main import get_last_sync_time

    filters = rule_filters_from(params)

    # Per-tenant since 4.1.13 — tenant context is pinned by the caller.
    # Computed from the deduplicated rule list (matching what the grid
    # renders) rather than raw SQL rows — a migrated/merged identity's
    # staging and production copies both satisfy the same filters, which
    # would otherwise double-count it against the grid's single card.
    all_rules, deduped_rules = _get_filtered_rules(db, filters, client_id)
    metrics = _metrics_from_rules(deduped_rules, all_rules)
    # Hide orphan space buckets (rules whose (siem_id, space) is no
    # longer in client_siem_map after a mapping change).
    _prune_orphan_scopes(metrics, db, client_id)
    _apply_lifecycle_counts(metrics, db, client_id, deduped_rules)
    from app.services import rule_issues
    return {
        "metrics": metrics,
        "last_sync_time": get_last_sync_time(all_rules),
        "last_sync": rule_issues.freshness(db, client_id),
        "space_labels": _build_space_labels(db, client_id),
        "scope_labels": _build_scope_labels(db, client_id),
        **({"rules": deduped_rules} if keep_rules else {}),
    }


@router.post("/{rule_id}/validate", response_class=HTMLResponse)
def validate_rule(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    settings: SettingsDep,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(None),
):
    """Mark a rule as validated by the current user."""
    thresholds = db.get_client_validation_thresholds(client_id)
    rule = db.get_rule_by_id(
        rule_id, space, siem_id=siem_id, thresholds=thresholds, client_id=client_id
    )
    
    if not rule:
        return HTMLResponse('<div class="rm-empty">Rule not found.</div>', status_code=404)
    
    username = user.name or user.username if user else "Unknown"
    db.save_validation(validation_key(rule.rule_id, rule.raw_data), rule.name, username)
    validation_reason = f"{username} validated rule"
    if siem_id:
        try:
            db.record_rule_history(
                rule_id=rule_id,
                siem_id=siem_id,
                space=space,
                client_id=client_id,
                action="validated",
                actor_user_id=user.id,
                actor_name=username,
                detail={"message": validation_reason, "reason": validation_reason},
            )
        except Exception:
            logger.exception("Failed to write validation history for rule %s", rule_id)
    rule = db.get_rule_by_id(
        rule_id, space, siem_id=siem_id, thresholds=thresholds, client_id=client_id
    )
    
    templates = request.app.state.templates

    card_ctx = build_rule_card_context(db, client_id, [rule])

    # Unified Rule modal: re-render the modal and refresh the card behind it
    # out-of-band (its "Validated on" date changes).
    if request.headers.get("X-Return-Modal") == "rule":
        return _modal_with_card_oob(request, db, client_id, rule, space, siem_id, settings, just_validated=True)

    return templates.TemplateResponse(
        request, "components/rule_card.html",
        {"rule": rule, **card_ctx, "env": settings},
    )


@router.post("/{rule_id}/test", response_class=HTMLResponse)
async def test_rule(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    settings: SettingsDep,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(
        None,
        description="SIEM that owns this rule. Required since 4.0.13 for "
                    "unambiguous Kibana selection when multiple SIEMs are "
                    "mapped to the same space name. The legacy fallback "
                    "(first SIEM matching the space) is retained for one "
                    "release with a WARN log + UI banner.",
    ),
):
    """Test a detection rule against live Elasticsearch data via the Kibana Preview API."""
    import asyncio
    
    # Parse lookback from form body (sent via hx-include)
    form = await request.form()
    lookback = str(form.get("test-lookback", "24h"))
    allowed = {"1h", "6h", "24h", "7d", "30d"}
    if lookback not in allowed:
        lookback = "24h"
    
    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)
    if not rule:
        return HTMLResponse(
            '<div class="test-result test-error">Rule not found</div>',
            status_code=404
        )
    
    if not rule.raw_data:
        return HTMLResponse(
            '<div class="test-result test-error">Rule data not available for testing</div>',
            status_code=400
        )
    if rule.raw_data.get("type") == "machine_learning":
        return HTMLResponse(
            '<div class="test-result test-error">A machine learning rule can\'t be tested: it has no query to run.</div>',
            status_code=400
        )

    # Resolve the SIEM for this rule. The PREFERRED path (4.0.13+) is to use
    # the explicit siem_id query param — either passed by the rule modal
    # template (which knows rule.siem_id) or inferred from rule.siem_id below.
    # Falling back to space-only matching is ambiguous when two SIEMs share a
    # Kibana space name (e.g. both expose 'production') and was the root cause
    # of the 4.0.7→4.0.11 Test Rule 401 regression — the first SIEM matching
    # the space won, sending the request to the wrong Kibana with the wrong
    # API key. Until callers all pass siem_id we keep the fallback alive but
    # log loudly so it shows up in support bundles.
    resolved_siem_id = siem_id or getattr(rule, "siem_id", None)
    siem = None
    try:
        client_siems = db.get_client_siems(client_id)
    except Exception:
        client_siems = []
        logger.exception("Failed to load client SIEMs for client %s", client_id)

    if resolved_siem_id:
        for s in client_siems:
            if s.get("id") == resolved_siem_id:
                siem = s
                break
        if siem is None:
            logger.warning(
                "test_rule: rule siem_id=%s is not assigned to active client %s; "
                "refusing to fall back to space-match to avoid leaking across tenants",
                resolved_siem_id, client_id,
            )
            return HTMLResponse(
                '<div class="test-result test-error">'
                f"This rule was synced from a SIEM that is not assigned to the "
                f"current tenant. Re-assign the SIEM in Settings or run a sync "
                f"to refresh."
                '</div>',
                status_code=400,
            )
    else:
        # Fail closed: selecting by space-name is ambiguous when two SIEMs
        # share the same space id. The caller must provide siem_id (or the
        # rule row must carry one) so request routing is deterministic.
        return HTMLResponse(
            '<div class="test-result test-error">'
            "Cannot test rule: SIEM identifier missing for this rule. "
            "Refresh rules and retry, or re-run sync so the rule carries "
            "its source SIEM identity."
            '</div>',
            status_code=400,
        )

    if not siem or not siem.get("kibana_url") or not siem.get("api_token_enc"):
        return HTMLResponse(
            '<div class="test-result test-error">'
            f"No SIEM is assigned to this client for space '{space}'. "
            "Add a SIEM to this tenant in Settings and re-test."
            '</div>',
            status_code=400,
        )

    # Diagnostic context (4.0.13): customer upgraded 4.0.7 -> 4.0.11 and the
    # Test Rule popup started returning 401. The wire-format request is
    # byte-identical to 4.0.7 — only the source of kibana_url / api_key changed
    # (was .env, now siem_inventory). Log enough to compare without leaking
    # the secret: SIEM label, kibana_url, space, env role, key prefix + length.
    _key = siem.get("api_token_enc") or ""
    logger.info(
        "test_rule resolved SIEM client=%s space=%s siem_label=%s siem_id=%s "
        "kibana_url=%s destination=%s api_key_prefix=%s api_key_len=%d es_url=%s",
        client_id, space, siem.get("label"), siem.get("id"),
        siem.get("kibana_url"), siem.get("name"),
        _key[:8] + "..." if _key else "<empty>", len(_key),
        siem.get("elasticsearch_url"),
    )

    try:
        from app.elastic_helper import preview_detection_rule
        loop = asyncio.get_event_loop()
        timing: Dict[str, Any] = {}
        hit_count, samples, error = await loop.run_in_executor(
            None,
            lambda: preview_detection_rule(
                rule.raw_data, space, lookback=lookback,
                kibana_url=siem["kibana_url"],
                api_key=siem["api_token_enc"],
                elasticsearch_url=siem.get("elasticsearch_url"),
                timing=timing,
            )
        )

        # What TIDE already knows about this rule's search time, so the user can see how the test compares.
        recorded: List[int] = []
        try:
            recorded = db.get_rule_search_times(
                _search_time_rule_id(rule), rule.siem_id or resolved_siem_id, rule.space or space,
            )
        except Exception:
            logger.exception("Could not read recorded search times for %s", rule_id)

        templates = request.app.state.templates
        return templates.TemplateResponse(
            request, "components/test_result_popup.html",
            {
                "rule": rule,
                "hit_count": hit_count,
                "samples": samples,
                "error": error,
                "lookback": lookback,
                "space_labels": _build_space_labels(db, client_id),
                "search_ms": timing.get("ms"),
                "search_ms_source": timing.get("source"),
                "recorded_count": len(recorded),
                "recorded_median": int(sorted(recorded)[len(recorded) // 2]) if recorded else None,
                "siem_id": rule.siem_id or resolved_siem_id or "",
                "rule_space": rule.space or space,
            }
        )
    except Exception as e:
        logger.exception(f"Test rule failed for {rule_id}")
        return HTMLResponse(
            f'<div class="test-result test-error">Could not run the test: {str(e)}</div>',
            status_code=500
        )


def _search_time_rule_id(rule) -> str:
    """The id search-time samples are stored under: Kibana's saved-object id, as the sync records them."""
    raw = rule.raw_data if isinstance(getattr(rule, "raw_data", None), dict) else {}
    return str(raw.get("id") or rule.rule_id)


@router.post("/{rule_id}/search-time", response_class=HTMLResponse)
async def record_test_search_time(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(None),
):
    """Keep the search time measured by a Test run: ``mode=add`` joins the rule's average, ``mode=replace``
    makes it the rule's only search time. The rule is re-scored for search time straight away."""
    from datetime import datetime as _dt
    form = await request.form()
    mode = str(form.get("mode") or "add")
    try:
        ms = int(str(form.get("ms") or "0"))
    except ValueError:
        ms = 0
    if mode not in ("add", "replace") or not (0 < ms <= 3_600_000):
        return HTMLResponse('<div class="toast toast-danger" data-click="el.remove">Not a valid search time.</div>', status_code=400)

    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)
    if not rule:
        return HTMLResponse('<div class="toast toast-danger" data-click="el.remove">Rule not found.</div>', status_code=404)
    rule_siem = rule.siem_id or siem_id or ""
    rule_space = rule.space or space
    sample_id = _search_time_rule_id(rule)

    if mode == "replace":
        db.clear_search_time_samples(sample_id, rule_siem, rule_space)
    db.record_search_time_samples([{
        "rule_id": sample_id, "siem_id": rule_siem, "space": rule_space,
        "executed_at": _dt.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "search_ms": ms,
    }])
    samples = db.get_rule_search_times(sample_id, rule_siem, rule_space)
    new_score = db.rescore_rule_search_time(client_id, rule.rule_id, rule_siem, rule_space, samples)

    username = user.name or user.username if user else "Unknown"
    try:
        db.record_rule_history(
            rule_id=rule.rule_id, siem_id=rule_siem, space=rule_space, client_id=client_id,
            action="search_time_recorded", actor_user_id=user.id, actor_name=username,
            detail={"message": f"Search time {ms} ms from a Test run, {'set as the only value' if mode == 'replace' else 'added to the average'}.",
                    "search_ms": ms, "mode": mode},
        )
    except Exception:
        logger.exception("Could not write search-time history for %s", rule_id)

    from html import escape
    what = "is now this rule's search time" if mode == "replace" else "was added to this rule's average"
    tail = (f" The rule now scores {new_score}%." if new_score is not None
            else " Its score will pick this up on the next sync.")
    response = HTMLResponse(
        f'<div class="toast toast-success" data-click="el.remove">{escape(f"{ms} ms {what}.")}{escape(tail)}</div>'
    )
    response.headers["HX-Trigger"] = "refreshRules"
    return response


@router.get("/duplicates", response_class=HTMLResponse)
def find_duplicate_rules(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """Dialog listing rows in the active tenant that are the same real rule stored more than
    once — see ``DatabaseService.find_duplicate_rule_groups`` for how a group is identified."""
    groups = db.find_duplicate_rule_groups()
    return request.app.state.templates.TemplateResponse(
        request, "components/duplicate_rules_dialog.html",
        {"groups": groups, "space_labels": _build_space_labels(db, client_id)},
    )


@router.post("/duplicates/resolve", response_class=HTMLResponse)
async def resolve_duplicate_rules(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """Merge the duplicate groups the operator confirmed (skips any marked 'not a duplicate')."""
    form = await request.form()
    try:
        group_count = int(form.get("group_count") or 0)
    except ValueError:
        group_count = 0

    username = user.name or user.username if user else "Unknown"
    merged_groups = moved_total = deleted_total = 0
    for i in range(group_count):
        if str(form.get(f"skip__{i}") or "").lower() in {"1", "true", "on", "yes"}:
            continue
        siem_id = form.get(f"group_siem__{i}")
        space = form.get(f"group_space__{i}")
        members = form.getlist(f"group_members__{i}")
        keep = form.get(f"keep__{i}")
        if not siem_id or not space or not keep or keep not in members:
            continue
        drop_ids = [m for m in members if m != keep]
        if not drop_ids:
            continue
        result = db.merge_duplicate_rules(keep, siem_id, space, drop_ids)
        if result["deleted"]:
            merged_groups += 1
            moved_total += result["moved_links"]
            deleted_total += result["deleted"]
            logger.info(
                "Merged duplicate rule group (client=%s siem=%s space=%s): kept %s, dropped %s "
                "(%d baseline link(s) moved) by %s",
                client_id, siem_id, space, keep, drop_ids, result["moved_links"], username,
            )

    response = request.app.state.templates.TemplateResponse(
        request, "components/duplicate_rules_dialog.html",
        {"result": {"groups": merged_groups, "moved_links": moved_total, "deleted": deleted_total}},
    )
    response.headers["HX-Trigger"] = "refreshRules"
    return response


_IMPORT_VALIDATION_MAX_BYTES = 5 * 1024 * 1024


@router.post("/import-validation", response_class=HTMLResponse)
async def import_validation_file(
    request: Request,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    file: UploadFile = File(...),
    overwrite: str = Form(""),
    checked_by: str = Form(""),
):
    """Import a ``checkedRule.json``-shaped file into the active client's rule validations.

    Manual, on-demand version of the file TIDE reads automatically once at startup (see the
    README and ``app.services.tenant_manager.import_legacy_validation_file``) — that one is
    untouched. This is for re-applying an old export, or a file recovered after a migration
    issue, without restarting the app.
    """
    def _script(message: str, kind: str = "success") -> HTMLResponse:
        # Closes the dialog (validationImported, rule_health.js), says how it went, refreshes the rules.
        return HTMLResponse("", headers={"HX-Trigger": json.dumps({
            "validationImported": None, "showToast": {"message": message, "type": kind}, "refreshRules": None,
        })})

    raw = await file.read(_IMPORT_VALIDATION_MAX_BYTES + 1)
    if len(raw) > _IMPORT_VALIDATION_MAX_BYTES:
        return _script("File is larger than 5 MB.", "danger")
    try:
        payload = json.loads(raw)
    except Exception as exc:
        return _script(f"Invalid JSON: {exc}", "danger")

    entries = payload.get("rules") if isinstance(payload, dict) else None
    if entries is None and isinstance(payload, dict) and all(isinstance(v, dict) for v in payload.values()):
        entries = payload  # a bare {name: {...}} file, without the "rules" wrapper
    if not isinstance(entries, dict) or not entries:
        return _script(
            'Not a validation file — expected {"rules": {"<rule name>": '
            '{"last_checked_on": "...", "checked_by": "..."}}}.', "danger",
        )

    do_overwrite = overwrite.strip().lower() in {"1", "true", "on", "yes"}
    name_override = checked_by.strip() or None
    result = db.import_validation_entries(entries, overwrite=do_overwrite, checked_by_override=name_override)

    username = user.name or user.username if user else "Unknown"
    logger.info(
        "Validation file imported by %s (client=%s): %d entries, overwrite=%s, checked_by_override=%r -> %s",
        username, client_id, len(entries), do_overwrite, name_override, result,
    )

    parts = [f"{result['added']} added"]
    if result["overwritten"]:
        parts.append(f"{result['overwritten']} overwritten")
    if result["skipped"]:
        parts.append(f"{result['skipped']} skipped (already validated)")
    if result["unmatched"]:
        parts.append(f"{result['unmatched']} not matched to a rule yet")
    if result["invalid"]:
        parts.append(f"{result['invalid']} invalid entries ignored")
    return _script("Validation file imported: " + ", ".join(parts) + ".")


@router.post("/sync", response_class=HTMLResponse)
async def sync_rules(
    request: Request,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    background_tasks: BackgroundTasks,
    settings: SettingsDep,
    force_mapping: bool = Query(False),
    siem_id: Optional[str] = Query(None),
    space: Optional[str] = Query(None),
):
    """Trigger an immediate per-tenant sync of rules from Elastic.

    Always scoped to the active tenant. The cross-tenant ``scope=all``
    fallback was removed in 4.1.13 — detection rules are per-tenant, so a
    sync MUST be scoped to one client.

    ``siem_id``/``space`` (both required together): narrow the sync to one
    of the client's own linked destinations instead of every one — for a
    slow or heavily-loaded Elastic, syncing one destination at a time keeps
    the ask small. Only a destination actually linked to this client is
    accepted, so a stray id can't be used to probe another tenant's SIEM.
    """
    return _start_rule_sync(db, user, client_id, force_mapping, siem_id, space)


@router.post("/sync/retry/{run_id}", response_class=HTMLResponse)
async def retry_rule_sync(request: Request, run_id: str, db: DbDep, user: RequireUser, client_id: ActiveClient):
    """Run a failed, partial or interrupted rule sync again, over the same destination and with
    the same mapping re-check. Anyone who can press Sync can retry; the run must be this client's."""
    from app.services import sync_runs
    run = sync_runs.get(run_id)
    if not run or run["client_id"] != client_id or run["sync_kind"] != "rules":
        return HTMLResponse('<div id="sync-status" class="sync-tracker sync-error"><span>That sync wasn\'t found for this client.</span></div>')
    scope = run.get("scope") or {}
    return _start_rule_sync(db, user, client_id, bool(scope.get("force_mapping")), scope.get("siem_id"),
                            scope.get("space"), retry_of=run_id)


@router.get("/sync/last", response_class=HTMLResponse)
def last_rule_sync(request: Request, user: RequireUser, client_id: ActiveClient):
    """Rule Health's notice when this client's last rule sync failed, partly finished or was
    interrupted: why, and Retry. Empty when it went fine (the Last Synced card says when)."""
    from app.services import sync_runs
    return request.app.state.templates.TemplateResponse(
        request, "partials/rules/last_sync.html", {"run": sync_runs.last_rule_sync(client_id)})


def _start_rule_sync(db, user, client_id: str, force_mapping: bool, siem_id: Optional[str], space: Optional[str],
                     retry_of: Optional[str] = None) -> HTMLResponse:
    """Start a rule sync for the active client and return its live tracker: Rule Health's Sync and
    Retry share it. ``siem_id``/``space`` (both or neither) narrow it to one linked destination."""
    import asyncio
    from app.main import scheduled_sync, _start_sync_job

    dest_name = None
    only_siem_id, only_space = None, None
    if siem_id and space:
        for dest in db.get_client_siems(client_id):
            if dest.get("id") == siem_id and str(dest.get("space") or "").lower() == space.lower():
                only_siem_id, only_space = siem_id, dest.get("space")
                dest_name = dest.get("name") or dest.get("label")
                break
        if only_siem_id is None:
            return HTMLResponse(
                '<div id="sync-status" class="sync-tracker sync-error">'
                '<span>That destination isn\'t linked to this client.</span></div>'
            )

    if dest_name:
        label = f"Initialising full mapping sync for {dest_name}…" if force_mapping else f"Initialising sync for {dest_name}…"
    else:
        label = "Initialising full mapping sync…" if force_mapping else "Initialising sync…"
    job_id = _start_sync_job(client_id, message=label, actor=user.username, retry_of=retry_of,
                             scope={"force_mapping": force_mapping, "siem_id": only_siem_id, "space": only_space,
                                    "destination": dest_name})

    asyncio.create_task(scheduled_sync(force_mapping=force_mapping, client_id=client_id, job_id=job_id,
                                       only_siem_id=only_siem_id, only_space=only_space))

    # Return live sync tracker that polls for status; its "complete" answer (/api/sync/status)
    # refreshes the grid and the metrics (syncComplete, rule_health.js).
    return HTMLResponse(
        '<div id="sync-status"'
        f'     hx-get="/api/sync/status?job_id={job_id}"'
        '     hx-trigger="load, every 1s"'
        '     hx-swap="outerHTML"'
        '     class="sync-tracker sync-running">'
        '    <span class="sync-spinner"></span>'
        '    <span>Sync starting…</span>'
        '</div>'
    )


@router.get("/create-form", response_class=HTMLResponse)
async def get_create_form(
    request: Request,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    prefill: Optional[str] = Query(None),
):
    """Render the create-rule modal form."""
    try:
        templates = request.app.state.templates
        return templates.TemplateResponse(
            request,
            "components/rule_create_form.html",
            _build_rule_form_context(
                db,
                client_id,
                user.username,
                "/api/rules/create",
                "Create Rule",
                "Create Rule",
                prefill=_extract_prefill(prefill),
            ),
        )
    except Exception as e:
        logger.exception("get_create_form failed")
        return HTMLResponse(
            f'<div class="alert alert-danger">Error loading form: {str(e)}</div>',
            status_code=500,
        )


@router.post("/create", response_class=HTMLResponse)
async def create_rule(
    request: Request,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
):
    """Create a detection rule in the selected tenant-scoped SIEM/space."""
    from app import elastic_helper

    try:
        form_data = await request.form()
        scope_pair = (form_data.get("scope_pair") or "").strip()
        siem_id, space = _parse_scope_pair(scope_pair)
        _, technique_lookup = _build_technique_groups(db)
        rule_data, rule_name, query, _ = _build_rule_payload(form_data, technique_lookup, user.username)

        if not rule_name or not query:
            return _form_error("Rule name and query are required.")
        if rule_data["type"] in _FORM_TYPES:
            from app.services.rule_type_settings import settings_problem
            problem = settings_problem(rule_data)
            if problem:
                return _form_error(problem)
        if not siem_id or not space:
            return _form_error("Select a target SIEM/space pair.")

        allowed_pairs = set(db.get_client_siem_scopes(client_id) or [])
        if (siem_id, space) not in allowed_pairs:
            return _form_error("Selected SIEM/space is not assigned to this tenant.", 403)

        siem = next(
            (
                s for s in (db.get_client_siems(client_id) or [])
                if s.get("id") == siem_id and (s.get("space") or "default") == space
            ),
            None,
        )
        if not siem:
            return _form_error("Could not find the SIEM details for that destination.", 404)

        success, message, new_rule_id = await run_in_threadpool(elastic_helper.create_detection_rule,
            rule_data,
            space=space,
            kibana_url=siem.get("kibana_url"),
            api_key=siem.get("api_token_enc"),
        )
        if not success:
            return _form_error(f"Could not create the rule: {message}", 502)

        db.record_rule_history(
            rule_id=new_rule_id,
            siem_id=siem_id,
            space=space,
            client_id=client_id,
            action="created",
            actor_user_id=user.id,
            actor_name=user.username,
            detail={
                "rule_name": rule_name,
                "message": message,
            },
        )
        sigma_id = str(form_data.get("sigma_id") or "").strip()
        if sigma_id and new_rule_id:
            from app.services import rule_origins
            rule_origins.record_for_client(db, client_id, (new_rule_id, siem_id, space), "sigma", sigma_id,
                                           "created", user.username)

        # Sync so the new rule shows up. Rule Health shows the sync's progress; from anywhere else
        # (a technique window's Sigma Convert) the sync just runs.
        return HTMLResponse('<div hidden data-start-sync></div>')
    except Exception as e:
        logger.exception("create_rule failed")
        return _form_error(f"Could not create the rule: {e}", 500)


@router.get("/{rule_id}/history", response_class=HTMLResponse)
def get_rule_history(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: CurrentUser,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(None),
):
    """Render lifecycle timeline for one rule."""
    if not siem_id:
        return HTMLResponse('<div class="rm-empty">Missing SIEM context.</div>', status_code=400)

    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)
    if not rule:
        return HTMLResponse('<div class="rm-empty">Rule not found.</div>', status_code=404)

    history = db.get_rule_history(rule_id, siem_id, space, limit=100)
    score_history = db.get_rule_score_history(rule_id, siem_id, space, limit=50)
    history_entries = _build_rule_history_entries(history, score_history)
    history_users = sorted({entry.get("actor") for entry in history_entries if entry.get("actor")})
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "partials/rule_timeline.html",
        {
            "history": history,
            "history_users": history_users,
            "score_history": score_history,
            "history_entries": history_entries,
        },
    )


def _build_score_chart(score_history: list[dict], events: Optional[list[dict]] = None) -> Optional[dict]:
    """Geometry for the Rule Score-over-time line chart (server-rendered SVG).

    * x-axis is TIME-scaled across the score snapshots and the supplied
      ``events`` (validations / edits), so markers line up with the line.
    * y-axis auto-scales to the data (padded, clamped to 0–100) so small score
      changes are visible instead of a flat line on a 0–100 axis.
    ``score_history`` is newest-first (as returned by the DB layer). Returns
    ``None`` when there is nothing to plot.
    """
    from datetime import datetime as _dt

    samples = [
        (row["created_at"], int(row["score"]))
        for row in reversed(score_history or [])
        if row.get("score") is not None and isinstance(row.get("created_at"), _dt)
    ]
    if not samples:
        return None

    marks = [
        {"ts": e["ts"], "kind": e.get("kind", "edit"), "actor": e.get("actor") or "", "label": e.get("label") or ""}
        for e in (events or [])
        if isinstance(e.get("ts"), _dt)
    ]
    width, height = 340, 190
    pad_l, pad_r, pad_t, pad_b = 34, 14, 14, 34
    plot_w, plot_h = width - pad_l - pad_r, height - pad_t - pad_b

    scores = [s for _, s in samples]
    lo, hi = min(scores), max(scores)
    if hi - lo < 10:                      # flat/near-flat: give the axis some air
        mid = (hi + lo) / 2
        lo, hi = mid - 6, mid + 6
    pad = max(2, (hi - lo) * 0.1)
    y_min, y_max = max(0, int(lo - pad)), min(100, int(hi + pad + 0.999))
    if y_max - y_min < 10:
        y_min, y_max = max(0, y_max - 10), min(100, max(y_max, 10))

    def _y(score: float) -> float:
        return round(pad_t + plot_h * (1 - (score - y_min) / (y_max - y_min)), 1)

    times = [ts for ts, _ in samples] + [m["ts"] for m in marks]
    t0, t1 = min(times), max(times)
    span = (t1 - t0).total_seconds()

    def _x(ts) -> float:
        if span <= 0:
            return round(pad_l + plot_w / 2, 1)
        return round(pad_l + plot_w * ((ts - t0).total_seconds() / span), 1)

    fmt = lambda ts: ts.strftime("%Y-%m-%d %H:%M")
    points = [{"x": _x(ts), "y": _y(s), "score": s, "label": fmt(ts)} for ts, s in samples]
    step = 5 if (y_max - y_min) <= 30 else 10 if (y_max - y_min) <= 60 else 25
    tick_vals = sorted({y_min, y_max, *range(((y_min + step - 1) // step) * step, y_max, step)})
    if len(tick_vals) > 6:
        tick_vals = tick_vals[:: len(tick_vals) // 4 or 1] + [y_max]
    event_marks = [
        {"x": _x(m["ts"]), "kind": m["kind"],
         "label": " · ".join(part for part in (m["label"], m["actor"], fmt(m["ts"])) if part)}
        for m in marks
    ]
    return {
        "width": width,
        "height": height,
        "pad_l": pad_l,
        "plot_right": width - pad_r,
        "plot_top": pad_t,
        "plot_bottom": pad_t + plot_h,
        "points": points,
        "path": " ".join(f'{p["x"]},{p["y"]}' for p in points),
        "ticks": [{"y": _y(v), "label": str(v)} for v in sorted(set(tick_vals))],
        "events": event_marks,
        "first_label": (t0).strftime("%Y-%m-%d"),
        "last_label": (t1).strftime("%Y-%m-%d"),
        "latest": points[-1]["score"],
        "delta": points[-1]["score"] - points[0]["score"] if len(points) > 1 else 0,
        "y_min": y_min,
        "y_max": y_max,
    }


def _bar_chart(points: list, tick_label=None) -> Optional[dict]:
    """Geometry for a bar chart in the rule window (server-rendered SVG, as the score chart): one bar
    per point from the baseline, rounded at its end, a 2px gap between bars, and the axis to a round
    number. ``points`` is ``[(when, value)]``, oldest first; ``tick_label(value, axis_top)`` writes an
    axis value. None when there's none."""
    if not points:
        return None
    width, height, pad_l, pad_r, pad_t, pad_b = 340, 130, 40, 8, 10, 22
    plot_w, plot_h = width - pad_l - pad_r, height - pad_t - pad_b
    top = max(n for _d, n in points)
    nice = 1
    while nice * 10 <= top:
        nice *= 10
    y_max = next(m * nice for m in (1, 2, 5, 10) if m * nice >= max(top, 1))
    slot = plot_w / len(points)
    w = max(1.0, slot - 2)
    bars = []
    for i, (when, n) in enumerate(points):
        h = round(plot_h * n / y_max, 1)
        x, y = round(pad_l + i * slot + 1, 1), round(pad_t + plot_h - h, 1)
        r = min(4, w / 2, h)
        bars.append({"at": when, "value": n, "x": x, "y": y, "w": round(w, 1), "h": h,
                     # Up the left side, round the top corners, down the right: the end away from the baseline.
                     "path": (f"M{x},{pad_t + plot_h} V{y + r} Q{x},{y} {x + r},{y} H{x + w - r} "
                              f"Q{x + w},{y} {x + w},{y + r} V{pad_t + plot_h} Z") if h else ""})
    label = tick_label or (lambda v, _top: f"{v:,}")
    return {"width": width, "height": height, "pad_l": pad_l, "plot_right": width - pad_r, "plot_top": pad_t,
            "plot_bottom": pad_t + plot_h, "bars": bars,
            "ticks": [{"y": round(pad_t + plot_h * (1 - v / y_max), 1), "label": label(v, y_max)}
                      for v in (0, y_max // 2, y_max)],
            "first_label": points[0][0].strftime("%d %b"), "last_label": points[-1][0].strftime("%d %b")}


def _build_alert_chart(per_day: list) -> Optional[dict]:
    """The rule window's alerts-per-day chart (#68): ``per_day`` is ``[(day, alerts)]``, oldest first."""
    chart = _bar_chart(per_day)
    for b in (chart or {}).get("bars", []):
        b["day"], b["alerts"] = b["at"], b["value"]
    return chart


def _exceptions_for(db, rule, siem_id: Optional[str], space: str) -> Optional[dict]:
    """The rule window's Exceptions (#75): the items of the lists the rule uses, as the last sync read
    them. None when it uses none. Never fatal."""
    raw = rule.raw_data if isinstance(rule.raw_data, dict) else {}
    if not raw.get("exceptions_list"):
        return None
    try:
        from app.services import rule_exceptions
        with db.get_connection() as conn:
            return rule_exceptions.for_rule(conn, siem_id or rule.siem_id or "", space or "default", raw["exceptions_list"])
    except Exception:
        logger.warning("Could not read rule %s's exceptions", rule.rule_id, exc_info=True)
        return None


def _search_chart_for(db, rule, siem_id: Optional[str], space: str) -> Optional[dict]:
    """The rule window's search-time chart for ``rule`` at its destination. Never fatal."""
    try:
        raw = rule.raw_data if isinstance(rule.raw_data, dict) else {}
        samples = db.get_rule_search_samples(_search_time_rule_id(rule), siem_id or rule.siem_id or "", space or "default")
        return _build_search_chart(samples, raw.get("interval"))
    except Exception:
        logger.warning("Could not chart rule %s's search times", rule.rule_id, exc_info=True)
        return None


def _build_search_chart(samples: list, interval: Optional[str]) -> Optional[dict]:
    """The rule window's search times (#76): a bar per run TIDE recorded, oldest first, from
    ``samples`` (``[(executed_at ISO in UTC, ms)]``), with the median of the last runs as the score and
    Rule Monitoring take it, and the time between runs. None with no runs."""
    import statistics
    from app.services.rule_issues import SLOW_RUNS, _span
    points = []
    for at, ms in sorted(samples):
        try:
            points.append((datetime.fromisoformat(str(at).replace("Z", "+00:00")), int(ms)))
        except ValueError:
            continue
    chart = _bar_chart(points, lambda v, top: "0" if not v else (f"{v / 1000:g} s" if top >= 1000 else f"{v:,} ms"))
    if chart:
        recent = [ms for _at, ms in points[-SLOW_RUNS:]]
        every = _span(interval)
        chart.update(runs=len(points), median=statistics.median(recent), median_runs=len(recent),
                     share=round(statistics.median(recent) / every / 10) if every else None)
    return chart


def _kibana_rule_url(db, rule, client_id: str) -> str:
    """Deep link to the rule in its owning SIEM's Kibana ('' when unknown)."""
    base = (_resolve_kibana_url(db, rule, client_id) or "").rstrip("/")
    if not base:
        return ""
    space = getattr(rule, "space", None) or "default"
    obj_id = (rule.raw_data or {}).get("id") if getattr(rule, "raw_data", None) else None
    obj_id = obj_id or rule.rule_id
    prefix = "" if str(space).lower() == "default" else f"/s/{space}"
    return f"{base}{prefix}/app/security/rules/id/{obj_id}"


def _as_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _render_guide_markdown(text: str):
    """Tiny, safe Markdown → HTML for Elastic investigation guides.

    Everything is HTML-escaped FIRST; only headings, lists, fenced code, bold,
    inline code and http(s) links are then re-introduced, so rule content can
    never inject markup.
    """
    import re as _re
    from markupsafe import Markup, escape

    def inline(s: str) -> str:
        s = str(escape(s))
        s = _re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        s = _re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
        return _re.sub(
            r"\[([^\]]+)\]\((https?://[^)\s]+)\)",
            r'<a href="\2" target="_blank" rel="noopener noreferrer">\1</a>', s,
        )

    out: list[str] = []
    para: list[str] = []
    list_tag = ""
    in_code = False

    def flush_para():
        if para:
            out.append("<p>" + inline(" ".join(para)) + "</p>")
            para.clear()

    def close_list():
        nonlocal list_tag
        if list_tag:
            out.append(f"</{list_tag}>")
            list_tag = ""

    for line in str(text).splitlines():
        if line.strip().startswith("```"):
            flush_para(); close_list()
            out.append("</code></pre>" if in_code else "<pre><code>")
            in_code = not in_code
            continue
        if in_code:
            out.append(str(escape(line)) + "\n")
            continue
        stripped = line.strip()
        heading = _re.match(r"^#{1,6}\s+(.*)$", stripped)
        bullet = _re.match(r"^[-*]\s+(.*)$", stripped)
        numbered = _re.match(r"^\d+[.)]\s+(.*)$", stripped)
        if not stripped:
            flush_para(); close_list()
        elif heading:
            flush_para(); close_list()
            out.append("<h4>" + inline(heading.group(1)) + "</h4>")
        elif bullet or numbered:
            flush_para()
            tag = "ul" if bullet else "ol"
            if list_tag != tag:
                close_list()
                out.append(f"<{tag}>")
                list_tag = tag
            out.append("<li>" + inline((bullet or numbered).group(1)) + "</li>")
        else:
            close_list()
            para.append(stripped)
    flush_para(); close_list()
    if in_code:
        out.append("</code></pre>")
    return Markup("".join(out))


def _window_type_settings(rule) -> dict:
    """Rule logic's settings beside the query (rule_type_settings.window_settings)."""
    from app.services.rule_type_settings import window_settings
    return window_settings(getattr(rule, "raw_data", None) or {})


def _build_rule_details(rule) -> dict:
    """Human-facing rule facts from the stored Elastic payload (no new data needed)."""
    raw = getattr(rule, "raw_data", None) or {}
    references = [u for u in _as_list(raw.get("references")) if u.lower().startswith(("http://", "https://"))]
    indexes = _as_list(raw.get("index"))
    return {
        "description": str(raw.get("description") or "").strip(),
        "tags": _as_list(raw.get("tags")),
        "interval": str(raw.get("interval") or "").strip(),
        "lookback": str(raw.get("from") or "").strip(),
        "risk_score": raw.get("risk_score"),
        "max_signals": raw.get("max_signals"),
        "indexes": indexes,
        "guide": str(raw.get("note") or "").strip(),
        "guide_html": _render_guide_markdown(str(raw.get("note") or "").strip()) if str(raw.get("note") or "").strip() else "",
        "setup": str(raw.get("setup") or "").strip(),
        "references": references,
        "false_positives": _as_list(raw.get("false_positives")),
    }


def _score_components(rule, weights: Optional[dict] = None) -> tuple[int, list[dict]]:
    """``(scoring version, components)`` for a rule.

    Rules scored since model 2 carry per-component detail (points, whether it applied, a sentence
    about this rule's result). Older rows fall back to the stored columns plus the generic
    description until the next sync re-scores them.
    """
    from app import scoring

    detail = (getattr(rule, "raw_data", None) or {}).get("score_detail")
    if isinstance(detail, dict) and detail.get("components"):
        keys = set(scoring.DEFAULT_WEIGHTS)
        components = [c for c in detail["components"] if c.get("key") in keys]
        if len(components) == len(keys):
            return int(detail.get("version") or 1), components
    weights = scoring.resolve_weights(weights)
    def stored(key: str) -> int:
        if key == "mitre":
            return int(getattr(rule, "score_tactics", 0) or 0) + int(getattr(rule, "score_techniques", 0) or 0)
        column = scoring.COLUMN_FOR.get(key)          # checks added later have no stored column
        return int(getattr(rule, column, 0) or 0) if column else 0
    return 1, [
        {"key": key, "label": label, "group": group, "max": weights[key], "value": stored(key),
         "applicable": True, "how": how, "result": ""}
        for key, label, group, _w, how in scoring.COMPONENTS
    ]


def _build_score_bars(rule) -> list[dict]:
    """Score breakdown as [{title, rows:[{label, value, max, pct, tone, applicable, how, result}]}]."""
    _version, components = _score_components(rule)

    def row(c: dict) -> dict:
        maximum = c.get("max") or 0
        applicable = c.get("applicable", True)
        v = c.get("value") or 0
        counted = applicable and maximum > 0
        pct = max(0, min(100, round(v * 100 / maximum))) if counted else 0
        tone = "muted" if not counted else "success" if pct >= 80 else "warning" if pct >= 50 else "danger"
        return {"label": c.get("label", ""), "value": v, "max": maximum, "pct": pct, "tone": tone,
                "applicable": applicable, "off": maximum <= 0, "how": c.get("how", ""), "result": c.get("result", "")}

    # Only checks that carry points for this client are shown; a check set to 0 is simply not part of the score.
    groups = [("Quality", "quality"), ("Operations", "operations"), ("Meta", "meta")]
    shown = [(title, [row(c) for c in components if c.get("group") == key and (c.get("max") or 0) > 0]) for title, key in groups]
    return [{"title": title, "rows": rows} for title, rows in shown if rows]


def _build_score_meta(rule) -> dict:
    """Scoring-model facts for the breakdown header: version, points in play and what could not be scored."""
    version, components = _score_components(rule)
    counted = [c for c in components if c.get("max", 0) > 0]
    return {"version": version,
            "allocated": sum(int(c.get("max") or 0) for c in counted),
            "possible": sum(int(c.get("max") or 0) for c in counted if c.get("applicable", True)),
            "skipped": [c.get("label", "") for c in counted if not c.get("applicable", True)]}


def build_rule_card_context(db, client_id: str, rules) -> dict:
    """Context ``components/rule_card.html`` / ``rule_row.html`` need — built in one place.

    Used by the Rule Health grid + table, the post-validate refresh and the MITRE
    technique sidebar so every rule renders identically.
    """
    rules = list(rules)
    links = db.get_rule_links_bulk([(r.rule_id, r.siem_id, r.space) for r in rules])
    offline = db.get_offline_scopes()
    states, titles = {}, {}
    for r in rules:
        key = f"{r.rule_id}|{r.siem_id or ''}|{r.space or ''}"
        states[key], titles[key] = _lifecycle(r, links.get((r.rule_id, r.siem_id, r.space)), offline)
    # Whether the Elastic or Sigma rule each came from has a newer version (rule_origins).
    upstream = {f"{k[0]}|{k[1] or ''}|{k[2] or ''}": v
                for k, v in db.upstream_statuses([(r.rule_id, r.siem_id, r.space) for r in rules]).items()}
    # What Rule Monitoring found on each, as its card flags it (rule_issues.card_problems), and its
    # alerts in the last 7 days, for the table's Alerts column (#68).
    problems, alerts_7d = {}, {}
    try:
        from app.services import rule_alerts, rule_issues
        keys = [(r.rule_id, r.siem_id, r.space) for r in rules if r.siem_id]
        with db.get_connection() as conn:
            found = rule_issues.rule_findings(conn, keys)
            alerts = rule_alerts.per_rule(conn, keys)
        for r in rules:
            lifecycle_key = f"{r.rule_id}|{r.siem_id or ''}|{r.space or ''}"
            flagged = rule_issues.card_problems(found.get((r.rule_id, r.siem_id, r.space), []), bool(r.enabled))
            if flagged:
                problems[lifecycle_key] = flagged
            if alerts.get((r.rule_id, r.siem_id, r.space)):
                alerts_7d[lifecycle_key] = alerts[(r.rule_id, r.siem_id, r.space)]
    except Exception:
        logger.warning("Could not read Rule Monitoring's findings for the rule cards", exc_info=True)

    return {
        "space_labels": _build_space_labels(db, client_id),
        "space_labels_by_pair": _build_space_labels_by_pair(db, client_id),
        "space_colors_by_pair": _build_space_colors_by_pair(db, client_id),
        "lifecycle_states": states,
        "lifecycle_titles": titles,
        "upstream_states": upstream,
        "rule_problems": problems,
        "rule_alerts_7d": alerts_7d,
    }


def _lifecycle(rule, linked, offline_scopes) -> tuple[str, str]:
    """The rule's state badge and its hover text: Deprecated, SIEM offline, Linked or none."""
    state = rule_state(rule, offline_scopes)
    if state == "deprecated":
        return "Deprecated", ""
    if state == "offline":
        info = offline_scopes[(rule.siem_id, rule.space)]
        at = info["checked_at"].strftime("%Y-%m-%d %H:%M") if info.get("checked_at") else "the last sync"
        return "SIEM offline", f"SIEM offline: {info['reason']} (checked {at}). Shown from TIDE's last copy."
    return ("Linked" if linked else ""), ""


def _ago(when: Optional[datetime], now: Optional[datetime] = None) -> str:
    """How long before ``now`` ``when`` was: 'just now', '12 min ago', '5 h ago', '3 days ago'."""
    if not when:
        return ""
    seconds = max(0, int(((now or datetime.now()) - when).total_seconds()))
    return ("just now" if seconds < 90 else f"{seconds // 60} min ago" if seconds < 5400
            else f"{round(seconds / 3600)} h ago" if seconds < 172800 else f"{seconds // 86400} days ago")


def _mapping_info(db, siem_id: str, rule) -> dict:
    """How fresh the field-catalogue data behind a rule's mapping check is ('' label when unknown)."""
    from app.services.mapping_catalogue import MappingCatalogue

    indices = sorted({str(row[0]) for row in (getattr(rule, "field_mappings", None) or []) if row})
    if not indices:
        return {}
    try:
        info = MappingCatalogue(db, siem_id).describe(indices)
    except Exception:
        logger.warning("Could not read the field catalogue for rule %s", getattr(rule, "rule_id", "?"), exc_info=True)
        return {}
    return {"label": _ago(info.get("oldest")), "known": info.get("known", 0), "patterns": info.get("patterns", 0)}


def _index_patterns(db, siem_id: str, rule) -> list:
    """Each of the rule's index patterns and whether it matches any index in the SIEM, from the field
    catalogue (#63): the rule's own ``index`` list, else the indexes its field checks used (a data view
    or ES|QL rule). Not checked yet stays unknown, never missing (CLAUDE.md §9)."""
    from app.services.mapping_catalogue import MappingCatalogue

    raw = rule.raw_data if isinstance(rule.raw_data, dict) else {}
    patterns = [str(p) for p in (raw.get("index") or []) if p]
    if not patterns:
        patterns = sorted({str(row[0]) for row in (getattr(rule, "field_mappings", None) or []) if row})
    if not patterns or not siem_id:
        return []
    try:
        return MappingCatalogue(db, siem_id).pattern_states(patterns)
    except Exception:
        logger.warning("Could not read index patterns for rule %s", getattr(rule, "rule_id", "?"), exc_info=True)
        return []


# Kibana's last_execution.status -> what the Last run section says, and its colour.
_RUN_STATUS = {
    "succeeded": ("Succeeded", "success"),
    "warning": ("Warning", "warning"),
    "partial failure": ("Partial failure", "warning"),
    "failed": ("Failed", "danger"),
    "running": ("Running", "muted"),
}


def _last_run(rule) -> Optional[dict]:
    """The rule's last run in Kibana, as TIDE recorded it at its last sync (#63): status, when, Kibana's
    message (why it failed) and timings. None when Kibana has no run for it. Shown in the rule window
    only; it differs per destination, so Compare leaves it out."""
    raw = rule.raw_data if isinstance(rule.raw_data, dict) else {}
    summary = raw.get("execution_summary") if isinstance(raw.get("execution_summary"), dict) else {}
    last = summary.get("last_execution") if isinstance(summary.get("last_execution"), dict) else {}
    if not last:
        return None
    status = str(last.get("status") or "").lower()
    label, tone = _RUN_STATUS.get(status, (status.title() or "Unknown", "muted"))
    when = None
    try:
        when = datetime.fromisoformat(str(last.get("date")).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        pass
    metrics = last.get("metrics") if isinstance(last.get("metrics"), dict) else {}

    def _num(key):
        try:
            value = metrics.get(key)
            return None if value is None else float(value)
        except (TypeError, ValueError):
            return None

    gap = _num("execution_gap_duration_s")
    return {
        "label": label, "tone": tone, "when": when, "message": str(last.get("message") or "").strip(),
        "search_ms": _num("total_search_duration_ms"), "indexing_ms": _num("total_indexing_duration_ms"),
        "gap_s": gap, "gap": _duration(gap) if gap else "", "synced_at": getattr(rule, "last_updated", None),
    }


def _duration(seconds: float) -> str:
    """A length of time as people say it: 45 s, 12 min, 5 h, 3 days."""
    s = int(seconds)
    return (f"{s} s" if s < 90 else f"{round(s / 60)} min" if s < 5400
            else f"{round(s / 3600)} h" if s < 172800 else f"{round(s / 86400)} days")


def _modal_with_card_oob(request, db, client_id: str, rule, space: str, siem_id: Optional[str],
                         settings, **modal_flags) -> HTMLResponse:
    """Re-render the Rule modal and refresh the card (or table row) behind it out-of-band."""
    templates = request.app.state.templates
    card_ctx = build_rule_card_context(db, client_id, [rule])
    modal_ctx = _build_rule_modal_context(db, client_id, rule, space, siem_id, **modal_flags)
    modal_html = templates.get_template("components/rule_modal.html").render({"request": request, **modal_ctx})
    # The item behind the modal is a card, or a table row when the page is in table view
    # (htmx sends the page URL, which carries ``view=table``).
    as_row = "view=table" in request.headers.get("HX-Current-URL", "")
    item_html = templates.get_template(
        "components/rule_row.html" if as_row else "components/rule_card.html"
    ).render({"request": request, "rule": rule, **card_ctx, "env": settings, "oob": True})
    if as_row:
        item_html = f"<template>{item_html}</template>"   # htmx: table rows need a <template> wrapper for OOB
    return HTMLResponse(modal_html + item_html)


def _rule_covers(rule_id, siem_id, space, linked, client_id):
    """The baseline techniques this rule covers (the rule window's Covers panel). Never fatal:
    the rule window must open even if the baseline tables are unreadable."""
    from app.inventory_engine import get_rule_coverage
    try:
        return get_rule_coverage(rule_id, siem_id, space, linked, client_id=client_id)
    except Exception:
        logger.warning("Covers lookup failed for rule %s", rule_id, exc_info=True)
        return []


def _covers_problems(rule_id, siem_id, space, client_id) -> List[str]:
    """Why this rule isn't effective coverage (the Covers panel's note, #79): the open Rule
    Monitoring findings that stop it working. Never fatal."""
    from app.inventory_engine import rule_states
    try:
        key = (rule_id, siem_id or "", space or "default")
        return (rule_states([key], client_id=client_id).get(key) or {}).get("problems", [])
    except Exception:
        logger.warning("Could not tell whether rule %s is effective coverage", rule_id, exc_info=True)
        return []


def _build_rule_modal_context(
    db, client_id: str, rule, space: str, siem_id: Optional[str], just_validated: bool = False,
    flash: str = "",
) -> dict:
    """Everything the unified Rule modal needs: history, score chart, details, logic, links."""
    actual_siem = siem_id or getattr(rule, "siem_id", "") or ""
    history = db.get_rule_history(rule.rule_id, actual_siem, space, limit=100)
    score_history = db.get_rule_score_history(rule.rule_id, actual_siem, space, limit=50)
    all_entries = _build_rule_history_entries(history, score_history)
    # Activity = edits + validations. Score snapshots are plotted in the chart
    # beside it, so they are not repeated as timeline rows.
    entries = [e for e in all_entries if e.get("kind") != "score"]
    chart_events = [
        {"ts": e["created_at"], "kind": "validation" if e.get("kind") == "validation" else "edit",
         "actor": e.get("actor"), "label": e.get("badge") or ("Validated" if e.get("kind") == "validation" else "Edited")}
        for e in entries if e.get("created_at")
    ]
    # Mark where the scoring model changed, so a step in the line reads as "the model changed",
    # not "the rule got worse".
    previous_version = None
    for snap in reversed(score_history):          # history is newest-first
        version = snap.get("scoring_version") or 1
        if previous_version is not None and version != previous_version and snap.get("created_at"):
            chart_events.append({"ts": snap["created_at"], "kind": "scoring", "actor": "",
                                 "label": f"Scoring model v{version}"})
        previous_version = version
    scoring_cfg = db.get_client_scoring(client_id)
    if scoring_cfg.get("custom") and isinstance(scoring_cfg.get("updated_at"), datetime):
        chart_events.append({"ts": scoring_cfg["updated_at"], "kind": "scoring", "actor": scoring_cfg.get("updated_by") or "",
                             "label": "Scoring weights changed"})
    _, technique_lookup = _build_technique_groups(db)
    mitre = []
    for mid in getattr(rule, "mitre_ids", None) or []:
        info = technique_lookup.get(str(mid).upper()) or {}
        mitre.append({"id": str(mid).upper(), "name": info.get("name") or "", "tactic": info.get("tactic") or ""})
    scope_label = (
        _build_space_labels_by_pair(db, client_id).get(f"{actual_siem}|{space}")
        or _build_space_labels(db, client_id).get(space, space.capitalize())
    )
    linked = db.get_rule_links_bulk([(rule.rule_id, actual_siem, space)]).get((rule.rule_id, actual_siem, space), [])
    # Every other linked SIEM+space this client has -- the Move dialog's target picker. Any
    # destination but this rule's own current one. Only what the client-side dialog needs to
    # render and submit a choice -- never api_token_enc or other credential fields.
    move_targets = [
        {"siem_id": s.get("id"), "space": s.get("space"), "name": s.get("name") or s.get("label")}
        for s in (db.get_client_siems(client_id) or [])
        if not (s.get("id") == actual_siem and str(s.get("space") or "default").lower() == str(space).lower())
    ]
    # Add link's destinations: the others, then this rule's own (a duplicate beside it, to Compare and
    # Merge). Coverage gains nothing from a link within one destination (CLAUDE.md section 6).
    own = next(({"siem_id": s.get("id"), "space": s.get("space"), "name": s.get("name") or s.get("label")}
                for s in (db.get_client_siems(client_id) or [])
                if s.get("id") == actual_siem and str(s.get("space") or "default").lower() == str(space).lower()), None)
    link_targets = move_targets + ([own] if own else [])
    from app.services import pending_actions, rule_origins
    key = (rule.rule_id, actual_siem, space)
    # Changes Kibana made but TIDE couldn't record (a new rule id, a move, a restore): Finish in TIDE.
    pending = pending_actions.for_rule(client_id, key)
    own_pending = [e for e in pending if e["kind"] == "own_rule_id"]
    with db.get_connection() as conn:
        upstream = rule_origins.statuses(conn, [key]).get(key)
        # A custom rule under one of Elastic's rule ids can be given its own (promotion.own_rule_id).
        holds_elastic_id = rule_origins.holds_elastic_id(conn, client_id, key, rule)
        # A custom rule linked to an Elastic rule can be unlinked, and is flagged when it doesn't match it.
        origin = rule_origins.get(conn, key)
        can_unlink = not rule.deprecated and not rule_origins.unlink_refused(origin)
        from app.services.rule_diff import sections_text
        from app.services.rule_updates import unconfirmed_links
        link_unconfirmed = (unconfirmed_links(conn, [key]).get(key) or {}).get("sections", []) if can_unlink else []
        unlinked_from = rule_origins.unlinked_name(conn, origin)
        # What Rule Monitoring found on this rule, for its section of that name, and its alerts (#68).
        from app.services import rule_alerts, rule_issues
        monitoring = rule_issues.rule_findings(conn, [key]).get(key, [])
        alerts = rule_alerts.for_rule(conn, actual_siem, space, str((rule.raw_data or {}).get("id") or ""))
    # Custom rules Kibana held beside this one under the same rule id at the last sync (TIDE holds one).
    shared_copies = [c for c in db.shared_rule_id_copies(actual_siem, space, rule.rule_id)
                     if not c.get("prebuilt") and not any(e.get("copy_id") == c.get("id") for e in own_pending)]
    if upstream and upstream["parent"]:
        parent = db.get_rule_by_id(upstream["parent"][0], upstream["parent"][2], siem_id=upstream["parent"][1],
                                   client_id=client_id)
        upstream["parent_name"] = parent.name if parent else ""
    return {
        "upstream": upstream,
        "holds_elastic_id": holds_elastic_id,
        "can_unlink": can_unlink,
        "link_unconfirmed": link_unconfirmed,
        "link_unconfirmed_text": sections_text(link_unconfirmed),
        "unlinked_from": unlinked_from,
        # Link to an Elastic or Sigma rule starts from this rule's name, as a copy's is: without the
        # " [Duplicate]" Kibana's Duplicate adds.
        "upstream_guess": re.sub(r"(\s*\[Duplicate\])+\s*$", "", rule.name or ""),
        "shared_copies": shared_copies,
        "pending_changes": [{**e, "text": pending_actions.describe(e)} for e in pending],
        "monitoring": monitoring,
        "alerts": alerts,
        "alert_chart": _build_alert_chart(alerts["per_day"]) if alerts and alerts["total"] else None,
        "search_chart": _search_chart_for(db, rule, actual_siem, space),
        "exceptions": _exceptions_for(db, rule, actual_siem, space),
        "rule": rule,
        "space": space,
        "siem_id": actual_siem,
        "scope_label": scope_label,
        **dict(zip(("lifecycle_state", "lifecycle_title"), _lifecycle(rule, linked, db.get_offline_scopes()))),
        "linked_rules": linked,
        "covers": _rule_covers(rule.rule_id, actual_siem, space, linked, client_id),
        "covers_problems": _covers_problems(rule.rule_id, actual_siem, space, client_id),
        "move_targets": move_targets,
        "link_targets": link_targets,
        "delete_source_default": bool((db.get_client(client_id) or {}).get("delete_source_after_promotion", True)),
        "history_entries": entries,
        "history_users": sorted({e.get("actor") for e in entries if e.get("actor")}),
        "score_chart": _build_score_chart(score_history, chart_events),
        "score_bars": _build_score_bars(rule),
        "score_meta": _build_score_meta(rule),
        "details": _build_rule_details(rule),
        "type_settings": _window_type_settings(rule),
        "mitre_details": mitre,
        "kibana_rule_url": _kibana_rule_url(db, rule, client_id),
        "just_validated": just_validated,
        "flash": flash,
        "mapping_info": _mapping_info(db, actual_siem, rule),
        "index_patterns": _index_patterns(db, actual_siem, rule),
        "last_run": _last_run(rule),
    }


@router.get("/{rule_id}/history-modal", response_class=HTMLResponse)
def get_rule_history_modal(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: CurrentUser,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(None),
):
    """Unified Rule modal (history + score chart, logic, actions) opened from a rule card."""
    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)
    if not rule:
        return HTMLResponse('<div class="rm-empty">Rule not found.</div>', status_code=404)
    return request.app.state.templates.TemplateResponse(
        request,
        "components/rule_modal.html",
        _build_rule_modal_context(db, client_id, rule, space, siem_id),
    )


@router.get("/field-suggestions", response_class=HTMLResponse)
def field_suggestions(
    db: DbDep,
    user: CurrentUser,
    client_id: ActiveClient,
    scope_pair: str = Query(""),
    patterns: str = Query(""),
):
    """The rule form's field names to suggest (``<option>``s for a ``<datalist>``): the fields TIDE's
    field catalogue holds for these index patterns on the destination's SIEM. Never asks the SIEM: a
    pattern it hasn't checked yet suggests nothing, and any field can still be typed."""
    from app.services.mapping_catalogue import MappingCatalogue
    siem_id, space = _parse_scope_pair(scope_pair)
    if not siem_id or (siem_id, space) not in set(db.get_client_siem_scopes(client_id) or []):
        return HTMLResponse("")
    entries = MappingCatalogue(db, siem_id).entries(_split_csv(patterns)[:20])
    fields = sorted({name for entry in entries.values() for name in entry.fields})[:5000]
    return HTMLResponse("".join(f'<option value="{escape(name)}"></option>' for name in fields))


@router.get("/link-search", response_class=HTMLResponse)
async def search_rule_link_targets(
    request: Request,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    target_name: str = Query(""),
    target_scope: str = Query(""),
    exclude_rule_id: Optional[str] = Query(None),
    exclude_siem_id: Optional[str] = Query(None),
    exclude_space: Optional[str] = Query(None),
):
    """Live search behind the rule modal's "Add link" box: rule names matching ``target_name``
    inside the chosen destination, so linking doesn't require typing an exact, full name from
    memory. Shares the same field name as the Add-link form's text input so one hx-include
    covers both the plain submit and this search.

    ``exclude_*`` identifies the exact row you're linking from -- not just its rule_id, which
    every copy of the same rule shares across destinations by design, so excluding by rule_id
    alone would hide every other copy too.
    """
    from html import escape
    target_siem_id, _, target_space = target_scope.partition("|")
    target_siem_id, target_space = target_siem_id.strip(), target_space.strip()
    q = target_name.strip()
    # The swap is outerHTML (so a click-to-pick result can replace itself and still be
    # re-targetable by the next search), so every branch must return the wrapper div itself,
    # never an empty string -- an empty string would delete the div outright and the next
    # search would have nothing to target.
    if not target_siem_id or not target_space:
        return HTMLResponse('<div class="rm-add-link__results"><p class="rm-empty">Choose a destination first.</p></div>')
    if len(q) < 2:
        return HTMLResponse('<div class="rm-add-link__results"></div>')
    matches = db.search_rule_names(
        target_siem_id, target_space, q,
        exclude_rule_id=exclude_rule_id, exclude_siem_id=exclude_siem_id, exclude_space=exclude_space, limit=8,
    )
    if not matches:
        return HTMLResponse('<div class="rm-add-link__results"><p class="rm-empty">No matching rule in that destination.</p></div>')
    # Each suggestion carries its rule id: names are not unique in a destination, so picking one
    # links that exact rule rather than whatever has the same name.
    items = "".join(
        f'<button type="button" data-click="rule.linkPick" data-name="{escape(m["name"])}" '
        f'data-rule-id="{escape(m["rule_id"])}">{escape(m["name"])}</button>'
        for m in matches
    )
    return HTMLResponse(f'<div class="rm-add-link__results">{items}</div>')


@router.post("/{rule_id}/links", response_class=HTMLResponse)
async def add_rule_link(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(None),
):
    """Manually link this rule to another one in a chosen destination: the rule picked from the
    search (``target_rule_id``), else the one the typed name resolves to there."""
    form = await request.form()
    target_name = str(form.get("target_name") or "").strip()
    target_rule_id = str(form.get("target_rule_id") or "").strip()
    target_siem_id, _, target_space = str(form.get("target_scope") or "").partition("|")
    target_siem_id, target_space = target_siem_id.strip(), target_space.strip()
    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)
    if not rule:
        return HTMLResponse('<div class="rm-empty">Rule not found.</div>', status_code=404)
    flash = ""
    if not (target_name or target_rule_id) or not target_siem_id or not target_space:
        flash = "Choose a target destination and type the rule's name."
    else:
        dest = next(
            (s.get("name") or s.get("label") for s in (db.get_client_siems(client_id) or [])
             if s.get("id") == target_siem_id and str(s.get("space") or "default") == target_space),
            None,
        )
        if not dest:
            flash = "That destination is not linked to this client."
        else:
            # A rule is its id at one SIEM and space (CLAUDE.md section 6): a picked suggestion is
            # looked up exactly there; a typed name is resolved the way the search matched it.
            if target_rule_id:
                picked = db.get_rule_by_id(target_rule_id, target_space, siem_id=target_siem_id, client_id=client_id)
                matches = [picked.rule_id] if picked and not picked.deprecated else []
            else:
                matches = db.rule_ids_named(target_siem_id, target_space, target_name)
            # In the rule's own destination its own name finds itself: never a rule to link to.
            matches = [m for m in matches if (m, target_siem_id, target_space) != (rule_id, siem_id or rule.siem_id, space)]
            label = target_name or "that rule"
            if not matches:
                flash = f'No rule named "{label}" in {dest}. Pick one from the list.'
            elif len(matches) > 1:
                flash = f'{len(matches)} rules in {dest} are named "{label}". Pick one from the list.'
            else:
                username = user.name or user.username if user else "Unknown"
                link_id = db.create_rule_link(
                    rule_id, siem_id, space, matches[0], target_siem_id, target_space, username,
                )
                flash = "Linked." if link_id else "Could not link -- these two are already linked, or one no longer exists."
    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)
    response = request.app.state.templates.TemplateResponse(
        request, "components/rule_modal.html",
        _build_rule_modal_context(db, client_id, rule, space, siem_id, flash=flash),
    )
    response.headers["HX-Trigger"] = "refreshRules"
    return response


@router.delete("/{rule_id}/links/{link_id}", response_class=HTMLResponse)
def remove_rule_link(
    request: Request,
    rule_id: str,
    link_id: str,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(None),
):
    """Remove a link. Neither rule, its history nor its validation is touched."""
    db.delete_rule_link(link_id)
    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)
    if not rule:
        return HTMLResponse('<div class="rm-empty">Rule not found.</div>', status_code=404)
    response = request.app.state.templates.TemplateResponse(
        request, "components/rule_modal.html",
        _build_rule_modal_context(db, client_id, rule, space, siem_id, flash="Link removed."),
    )
    response.headers["HX-Trigger"] = "refreshRules"
    return response


@router.get("/{rule_id}/edit-form", response_class=HTMLResponse)
def get_rule_edit_form(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: CurrentUser,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(None),
):
    """Render full edit form for a rule using the create/edit modal layout."""
    thresholds = db.get_client_validation_thresholds(client_id)
    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, thresholds=thresholds)
    if not rule:
        return HTMLResponse('<div class="rm-empty">Rule not found.</div>', status_code=404)

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "components/rule_create_form.html",
        _build_rule_form_context(
            db,
            client_id,
            user.username,
            f'/api/rules/{rule_id}/edit?space={space}'
            + (f'&siem_id={siem_id or getattr(rule, "siem_id", "")}' if (siem_id or getattr(rule, "siem_id", "")) else ""),
            "Save Changes",
            "Edit Rule",
            rule=rule,
            scope_locked=True,
        ),
    )


@router.post("/{rule_id}/edit", response_class=HTMLResponse)
async def edit_rule(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    settings: SettingsDep,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(None),
):
    """Save the Edit form's changes to the rule in Kibana and record them in its History.

    Only the fields the user changed are sent, onto the rule as Kibana holds it now
    (``_form_changes``, ``elastic_helper.apply_rule_changes``). A refusal is shown inside the
    form, keeping what was typed; success re-opens the rule window, refreshed from Kibana."""
    from app import elastic_helper

    thresholds = db.get_client_validation_thresholds(client_id)
    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, thresholds=thresholds, client_id=client_id)
    if not rule:
        return _form_error("This rule is no longer in TIDE. Close the form and sync the rules.", 404)
    actual_siem_id = siem_id or getattr(rule, "siem_id", None)
    siem = next((s for s in (db.get_client_siems(client_id) or [])
                 if s.get("id") == actual_siem_id and str(s.get("space") or "default") == space), None)
    if not siem:
        return _form_error("This rule's destination is no longer linked to this client.", 404)

    form = await request.form()
    reason = (form.get("reason") or "").strip()
    if not reason:
        return _form_error("Reason for Change is required before saving.")
    _, technique_lookup = _build_technique_groups(db)
    changes, removed, problem = _form_changes(rule, form, technique_lookup, user.username)
    if problem:
        return _form_error(problem)
    if not changes and not removed:
        return _modal_with_card_oob(request, db, client_id, rule, space, actual_siem_id, settings,
                                    flash="Nothing changed, so the rule was not updated.")

    cached = dict(rule.raw_data or {})
    rule_mitre = _canonicalize_id_list(getattr(rule, "mitre_ids", []) or [], uppercase=True)
    kibana_changes = {k: v for k, v in changes.items() if k != "mitre_ids"}   # Kibana takes "threat"
    if rule.deprecated:
        # Kibana no longer has it: change TIDE's copy only.
        before = cached
        payload = {k: v for k, v in {**cached, **changes}.items() if k not in removed}
        if "index" in changes:
            payload.pop(elastic_helper.DATA_VIEW_NOTE, None)
        if not db.update_cached_rule(rule_id, actual_siem_id, space, payload):
            return _form_error("TIDE couldn't save its copy of this rule. Nothing was changed.", 500)
        update_message = "Saved in TIDE only: Kibana no longer has this rule."
    else:
        # Editing changes ONLY this rule, never a linked one: a link means the two are deliberately
        # separate for now. Push a reviewed edit across on purpose with Merge, from Compare.
        elastic_rule_id = str(cached.get("rule_id") or rule_id)
        outcome, message, before = await run_in_threadpool(
            elastic_helper.apply_rule_changes, rule_id=elastic_rule_id, changes=kibana_changes, remove=removed,
            space=space, kibana_url=siem.get("kibana_url"), api_key=siem.get("api_token_enc"), cached=cached,
            on_recreated=db.kibana_recreate_hook(client_id, rule_id, actual_siem_id, space, user.username, user.id),
        )
        if outcome != "updated":
            logger.warning("Rule edit not saved (%s): rule_id=%s siem_id=%s space=%s %s",
                           outcome, rule_id, actual_siem_id, space, message)
        if outcome == "conflict":
            fields = ", ".join(_FIELD_LABELS.get(k, "data view" if k == "data_view_id" else k) for k in message.split(", "))
            await run_in_threadpool(sync_single_rule, db, client_id, rule_id, actual_siem_id, space, user.id, user.username)
            return _form_error(f"Someone changed this rule's {fields} in Kibana since TIDE last synced it, so "
                               "nothing was saved. TIDE has now loaded Kibana's version: go back to the rule, "
                               "check it, and make your change again.", 409)
        if outcome == "missing":
            return _form_error(message + " Use Sync this rule in the rule window to update TIDE.", 404)
        if outcome != "updated":
            return _form_error(message, 502)
        update_message = "Saved to Kibana." + (f" {message}" if message else "")

    before = {**(before or cached), "mitre_ids": rule_mitre}
    data_view = cached.get(elastic_helper.DATA_VIEW_NOTE)
    if "index" in changes and isinstance(data_view, dict):
        before["index"] = f"data view {data_view.get('name')}"   # History: what it searched until now
    after = {k: v for k, v in {**before, **changes}.items() if k not in removed}
    change_message, changed_fields, field_diffs = _summarize_rule_changes(before, after)
    db.record_rule_history(
        rule_id=rule_id, siem_id=actual_siem_id, space=space, client_id=client_id, action="edited",
        actor_user_id=user.id, actor_name=user.username,
        detail={"message": update_message + " " + change_message, "reason": reason,
                "changed_fields": changed_fields, "field_diffs": field_diffs},
    )

    # The rule window stays open on this rule, showing the change (#62): refresh just this rule
    # from Kibana rather than the whole client, then re-render the window and its card behind it.
    status, sync_message = 200, ""
    if not rule.deprecated:
        status, sync_message, _ = await run_in_threadpool(
            sync_single_rule, db, client_id, rule_id, actual_siem_id, space, user.id, user.username,
        )
    refreshed = db.get_rule_by_id(rule_id, space, siem_id=actual_siem_id, thresholds=thresholds, client_id=client_id) or rule
    flash = f"{update_message} Changed: {changed_fields}." if field_diffs else update_message
    if status != 200:
        flash += f" Showing TIDE's copy from before the change: reloading it from Kibana failed ({sync_message})."
    return _modal_with_card_oob(request, db, client_id, refreshed, space, actual_siem_id, settings, flash=flash)


def sync_single_rule(db, client_id: str, rule_id: str, siem_id: Optional[str], space: str,
                     actor_user_id: Optional[str] = None, actor_name: str = "system") -> Tuple[int, str, str]:
    """Re-check ONE rule against its SIEM (blocking). Shared core of the "Sync this rule" button
    and every write action (promote, demote, master push, restore, bulk edit) that used to
    trigger a full client sync just to pick up the one or two rules it actually touched — see
    CHANGELOG 5.1.2. A full mirror sync stays available (the Sync button, and any scheduled run);
    this is for refreshing a known rule without re-fetching and re-scoring the whole space.

    Pulls just that rule, refreshes the field catalogue for its index patterns, re-scores it and
    records the result. A SIEM that cannot be reached changes nothing; only a definite "not
    found" from Kibana marks the rule deprecated.

    Returns ``(status_code, message, action)`` — ``action`` is "synced", "deprecated", or "" on
    failure. 200/202 mean something happened; other codes mean nothing changed.
    """
    from app import elastic_helper
    from app.services.mapping_catalogue import MappingCatalogue

    if not siem_id:
        return 400, "Missing SIEM context.", ""
    if (siem_id, space) not in {(s, sp) for s, sp in (db.get_client_siem_scopes(client_id) or [])}:
        return 404, "SIEM not found.", ""
    # No existing row is not an error here (unlike the "Sync this rule" button, which always has
    # one): a rule TIDE just promoted, restored or pushed as master into this (siem, space) for
    # the first time has no row yet — this call both creates and refreshes.
    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)
    full = db.get_siem_inventory_item(siem_id) or {}
    if not (full.get("kibana_url") and full.get("api_token_enc")):
        return 400, "This SIEM has no Kibana URL or API key configured.", ""

    # fetch_single_rule tries both Kibana's saved-object id and its portable rule_id, so either
    # identity works here. Prefer a cached saved-object id when we have one (faster, unambiguous);
    # otherwise use rule_id as given — for a brand new row that IS the identity that was just used
    # to create it in Kibana.
    elastic_id = str((rule.raw_data or {}).get("id") if rule and rule.raw_data else rule_id)
    # Search-time samples are stored under this SAME saved-object id (see
    # ``_search_time_rule_id``) — filtering by the portable ``rule_id`` here
    # instead silently lost every sample recorded from a manual Test run
    # whenever the two ids differ, resetting "Search time" to n/a on the
    # very next sync even right after recording one.
    history = {(rid, sp): samples for (rid, sid, sp), samples in db.get_search_time_history().items()
               if sid == siem_id and rid == elastic_id}
    from app.services.data_freshness import DataFreshness, FieldData, IngestDelay
    try:
        frame = elastic_helper.fetch_single_rule(
            kibana_url=full["kibana_url"], api_key=full["api_token_enc"], space=space, rule_id=elastic_id,
            catalogue=MappingCatalogue(db, siem_id), elasticsearch_url=full.get("elasticsearch_url"),
            force_catalogue=True, search_time_history=history,
            weights=db.get_client_scoring(client_id)["weights"], freshness=DataFreshness(db, siem_id),
            field_data=FieldData(db, siem_id), ingest_delay=IngestDelay(db, siem_id),
        )
    except Exception as exc:
        logger.exception("Targeted rule sync failed for %s", rule_id)
        return 502, f"Could not reach the SIEM, so nothing was changed: {exc}", ""

    if frame is None or frame.empty:
        if rule:
            db.set_rule_deprecated(rule_id, siem_id, space, True)
            message = "Rule was not found in Elastic and is marked deprecated."
        else:
            message = "Rule was not found in Elastic."
        action = "deprecated"
    else:
        rec = frame.to_dict("records")[0]
        rec["siem_id"] = siem_id
        db.save_audit_results([rec], client_id=client_id, checkpoint=False)
        if isinstance(rec.get("search_sample"), dict):
            db.record_search_time_samples([{**rec["search_sample"], "siem_id": siem_id}])
        db.set_rule_deprecated(rule_id, siem_id, space, False)
        from app.services import rule_origins
        rule_origins.backfill_tenant(db, client_id, keys=[(rule_id, siem_id, space)])
        action = "synced"
        # No score delta here: "before" is this rule's score as of the *start* of this call,
        # which a just-prior action (recording a search time, say) may have already moved —
        # comparing against it can claim "unchanged" for a rule whose score visibly moved this
        # session. The score-over-time chart is the accurate record; this message just confirms
        # the refresh happened.
        message = "Rule refreshed from Elastic and its field mappings re-checked."
        # Its exception lists too, as a full sync reads them (#96), before Rule Monitoring looks at it.
        # A shared list's changes go into the history of every rule using it, as at a full sync.
        try:
            from app.services import rule_exceptions
            raw = rec.get("raw_data")
            raw = json.loads(raw) if isinstance(raw, str) else (raw or {})
            lists = rule_exceptions.lists_of(raw.get("exceptions_list"))
            if lists:
                rule_exceptions.read_lists(db, client_id, siem_id, space, lists, full["kibana_url"], full["api_token_enc"])
        except Exception as exc:
            logger.warning("Could not read the exception lists of rule %s", rule_id, exc_info=True)
            message += f" Could not read its exception lists: {exc}."
    # What needs action on this rule now (Rule Monitoring); a deprecated rule's issues are resolved.
    from app.services import rule_issues
    rule_issues.refresh_tenant(db, client_id, rule_keys=[(rule_id, siem_id, space)])
    db.record_rule_history(
        rule_id=rule_id, siem_id=siem_id, space=space, client_id=client_id,
        action=action, actor_user_id=actor_user_id, actor_name=actor_name,
        detail={"message": message, "targeted": True},
    )
    return 200, message, action


@router.post("/{rule_id}/sync", response_class=HTMLResponse)
def sync_one_rule(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    settings: SettingsDep,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(None),
):
    """Re-check ONE rule against its SIEM without syncing the rest. See ``sync_single_rule``."""
    def reply(message: str, status_code: int = 200, rule=None):
        if rule is not None and request.headers.get("X-Return-Modal") == "rule":
            return _modal_with_card_oob(request, db, client_id, rule, space, siem_id, settings, flash=message)
        tone = "danger" if status_code >= 400 else "success"
        return HTMLResponse(f'<div class="alert alert-{tone}">{message}</div>', status_code=status_code)

    before_rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id) if siem_id else None
    status, message, _action = sync_single_rule(
        db, client_id, rule_id, siem_id, space, actor_user_id=user.id, actor_name=user.username,
    )
    if status != 200:
        return reply(message, status, before_rule)
    refreshed = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id) or before_rule
    return reply(message, 200, refreshed)


@router.post("/{rule_id}/restore", response_class=HTMLResponse)
async def restore_rule(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(None),
):
    """Recreate a deprecated rule in the selected replacement SIEM scope."""
    if not siem_id:
        return HTMLResponse('<div class="rm-empty">Rule not found.</div>', status_code=404)
    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)
    if not rule or not rule.raw_data:
        return HTMLResponse('<div class="rm-empty">Rule data is unavailable.</div>', status_code=404)
    form = await request.form()
    replacement_siem_id, replacement_space = _parse_scope_pair(
        str(form.get("replacement_scope") or "")
    )
    if not replacement_siem_id or not replacement_space:
        return HTMLResponse('<div class="alert alert-danger">Select a Replacement SIEM / space first.</div>', status_code=400)
    target = next(
        (item for item in (db.get_client_siems(client_id) or [])
         if item.get("id") == replacement_siem_id
         and (item.get("space") or "default") == replacement_space),
        None,
    )
    if not target:
        return HTMLResponse('<div class="alert alert-danger">Replacement SIEM / space is not linked to this client.</div>', status_code=400)

    from app import elastic_helper
    full_target = db.get_siem_inventory_item(replacement_siem_id) or target
    success, message, new_rule_id = await run_in_threadpool(elastic_helper.create_detection_rule,
        rule.raw_data,
        space=replacement_space,
        kibana_url=full_target.get("kibana_url") or target.get("kibana_url"),
        api_key=full_target.get("api_token_enc"),
    )
    if not success or not new_rule_id:
        return HTMLResponse(f'<div class="alert alert-danger">Could not restore the rule: {message}</div>', status_code=400)

    # Refresh the tenant cache so the new Elastic ID exists before moving
    # baseline references and recording the migration pair.
    import asyncio
    from app.services.sync import run_elastic_sync
    await asyncio.get_running_loop().run_in_executor(
        None, lambda: run_elastic_sync(client_id)
    )
    db.remap_rule_references(
        rule_id, new_rule_id, client_id,
        siem_id, space,
        replacement_siem_id, replacement_space, actor=user.username,
    )
    # Restore is an identity replacement, not a migration mapping. The new
    # synced row is the sole TIDE record; remove the old SIEM-scope cache row
    # after baseline references have been moved to the recreated ID. Its
    # rule_id is gone for good, so any link it was part of goes with it too.
    db.delete_rule(rule_id, siem_id, space, remove_links=True)
    db.record_rule_history(
        rule_id=new_rule_id, siem_id=replacement_siem_id, space=replacement_space, client_id=client_id,
        action="restored", actor_user_id=user.id, actor_name=user.username,
        detail={
            "message": "Rule recreated in Elastic from a deprecated TIDE copy.",
            "source_rule_id": rule_id,
            "replacement_siem_id": replacement_siem_id,
            "replacement_space": replacement_space,
            "identity_replaced": True,
        },
    )
    return HTMLResponse(
        f'<div class="alert alert-success">Rule recreated in Elastic as {new_rule_id}.</div>'
    )


@router.delete("/{rule_id}", response_class=HTMLResponse)
def delete_rule(
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(None),
    remove_links: bool = Query(True),
    from_elastic: bool = Query(False),
):
    """Delete a rule from TIDE, and with ``from_elastic`` from its SIEM as well.

    TIDE-only is the default and is safe to do casually: a rule still live in Elastic comes
    back on the next sync. ``from_elastic`` deletes it in Elastic first and only then drops
    TIDE's row, so a failed Elastic delete never leaves TIDE believing a live rule is gone.
    ``remove_links`` (default on) also removes any rule_links row this rule was part of, so its
    counterpart doesn't end up pointing at a rule that no longer exists."""
    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id) if siem_id else None
    if not rule:
        return HTMLResponse('<div class="rm-empty">Rule not found.</div>', status_code=404)
    if from_elastic:
        from html import escape
        from app.elastic_helper import delete_detection_rule
        siem = next((s for s in (db.get_client_siems(client_id) or []) if s.get("id") == siem_id), None)
        if not siem:
            return HTMLResponse(
                '<div class="alert alert-danger">This rule\'s SIEM is no longer linked to this client, '
                'so it could not be deleted from Elastic. Nothing was deleted.</div>', status_code=400)
        ok, msg = delete_detection_rule(rule_id, space, siem.get("kibana_url"), siem.get("api_token_enc"))
        if not ok:
            return HTMLResponse(
                f'<div class="alert alert-danger">Elastic refused the delete ({escape(msg[:200])}). '
                'Nothing was deleted, in Elastic or TIDE.</div>', status_code=502)
    if not db.delete_rule(rule_id, siem_id, space, remove_links=remove_links):
        if not from_elastic:
            return HTMLResponse('<div class="rm-empty">Rule not found.</div>', status_code=404)
    message = "Rule deleted from Elastic and TIDE." if from_elastic else "Rule deleted from TIDE."
    db.record_rule_history(
        rule_id=rule_id, siem_id=siem_id, space=space, client_id=client_id,
        action="deleted", actor_user_id=user.id, actor_name=user.username,
        detail={"message": message + ("" if remove_links else " Its links were kept."), "enabled": bool(rule.enabled)},
    )
    # The rule window's Delete (app.js showDeleteRuleDialog) closes the window itself. The grid
    # refreshes so the deleted card disappears without the user having to reload.
    return HTMLResponse("", headers={"HX-Trigger": json.dumps({
        "showToast": {"message": "Rule deleted from TIDE.", "type": "success"}, "refreshRules": None,
    })})


@router.post("/{rule_id}/enable", response_class=HTMLResponse)
async def enable_rule(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(None),
):
    """Enable a detection rule in Kibana and refresh the grid."""
    from app import elastic_helper

    if not siem_id:
        return HTMLResponse('<div class="alert alert-danger">Missing SIEM context.</div>', status_code=400)

    siem = next((s for s in (db.get_client_siems(client_id) or []) if s.get("id") == siem_id), None)
    if not siem:
        return HTMLResponse('<div class="rm-empty">SIEM not found.</div>', status_code=404)

    success, message = await run_in_threadpool(elastic_helper.enable_detection_rule,
        rule_id,
        space=space,
        on_recreated=db.kibana_recreate_hook(client_id, rule_id, siem_id, space, user.username, user.id),
        kibana_url=siem.get("kibana_url"),
        api_key=siem.get("api_token_enc"),
    )
    if not success:
        return HTMLResponse(f'<div class="alert alert-danger">{message}</div>', status_code=400)

    db.record_rule_history(
        rule_id=rule_id,
        siem_id=siem_id,
        space=space,
        client_id=client_id,
        action="enabled",
        actor_user_id=user.id,
        actor_name=user.username,
        detail={"message": message},
    )
    return HTMLResponse("", headers={"HX-Trigger": "refreshRules"})


@router.post("/{rule_id}/disable", response_class=HTMLResponse)
async def disable_rule(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(None),
):
    """Disable a detection rule in Kibana and refresh the grid."""
    from app import elastic_helper

    if not siem_id:
        return HTMLResponse('<div class="alert alert-danger">Missing SIEM context.</div>', status_code=400)

    siem = next((s for s in (db.get_client_siems(client_id) or []) if s.get("id") == siem_id), None)
    if not siem:
        return HTMLResponse('<div class="rm-empty">SIEM not found.</div>', status_code=404)

    success, message = await run_in_threadpool(elastic_helper.disable_detection_rule,
        rule_id,
        space=space,
        on_recreated=db.kibana_recreate_hook(client_id, rule_id, siem_id, space, user.username, user.id),
        kibana_url=siem.get("kibana_url"),
        api_key=siem.get("api_token_enc"),
    )
    if not success:
        return HTMLResponse(f'<div class="alert alert-danger">{message}</div>', status_code=400)

    db.record_rule_history(
        rule_id=rule_id,
        siem_id=siem_id,
        space=space,
        client_id=client_id,
        action="disabled",
        actor_user_id=user.id,
        actor_name=user.username,
        detail={"message": message},
    )
    return HTMLResponse("", headers={"HX-Trigger": "refreshRules"})
