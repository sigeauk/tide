"""
API routes for Detection Rules (Rule Health page).
"""

import json
from datetime import datetime, timedelta
from urllib.parse import unquote

from fastapi import APIRouter, Request, Query, BackgroundTasks
from fastapi.responses import HTMLResponse
from typing import Optional, Any, List, Dict

from app.api.deps import DbDep, CurrentUser, RequireUser, SettingsDep, ActiveClient
from app.models.rules import RuleFilters, RuleHealthMetrics, DetectionRule

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


def _resort_rules(rules: list, sort_score: str, sort_validated: str, sort_name: str, sort_by: str) -> list:
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
        rules.sort(key=lambda r: getattr(r, "validation_date", None) or datetime.min, reverse=reverse)
    elif field == "score":
        rules.sort(key=lambda r: int(getattr(r, "score", 0) or 0), reverse=reverse)
    elif field == "name":
        rules.sort(key=lambda r: str(getattr(r, "name", "") or "").lower(), reverse=reverse)
    return rules


def _pick_display_rule(db, migration: Optional[dict], logical: Optional[dict], identity_key, fallback_rule, client_id: str):
    """Resolve the single row to render for a migrated/merged rule identity.

    Prefers the production/master copy. If that copy is itself deprecated
    (e.g. deleted from production) this MUST fall back to the live staging/
    source copy instead of leaving both rows in the result — the caller only
    calls this once per ``identity_key``, so whatever it returns is the only
    card rendered for this identity. Previously the fallback only happened
    when a master substitution *succeeded*, so a deprecated master left the
    staging row unsubstituted AND still separately iterated into the output,
    showing a "Deprecated" card next to a "Staging" card for the same rule.
    """
    def fetch(rule_id, space, siem_id):
        if not (rule_id and space and siem_id):
            return None
        return db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)

    info = migration or logical or {}
    master = fetch(
        info.get("target_rule_id") or info.get("master_rule_id"),
        info.get("target_space") or info.get("master_space"),
        info.get("target_siem_id") or info.get("master_siem_id"),
    )
    if master and not master.deprecated:
        return master

    if migration:
        source = fetch(migration.get("source_rule_id"), migration.get("source_space"), migration.get("source_siem_id"))
        if source and not source.deprecated:
            return source
    elif logical:
        master_rule_id = info.get("master_rule_id")
        for member in db.get_logical_rule_members(identity_key) or []:
            if member.get("rule_id") == master_rule_id:
                continue
            candidate = fetch(member.get("rule_id"), member.get("space"), member.get("siem_id"))
            if candidate and not candidate.deprecated:
                return candidate

    # Both sides deprecated/unresolvable — show whatever we have.
    return master or fallback_rule


def _dedupe_display_rules(db, rules: List["DetectionRule"], client_id: str) -> List["DetectionRule"]:
    """Collapse migrated/merged identities to the single card Rule Health
    would render for each — one row per (staging, production) pair or
    logical merge group, preferring the production/master copy (see
    ``_pick_display_rule``). Any aggregate computed straight from
    un-deduped rows (e.g. raw SQL counts) double-counts these pairs, since
    both the staging and production copy independently match the same
    filters."""
    display_rules = []
    seen_migrations = set()
    for rule in rules:
        migration = db.get_rule_migration_for_rule(rule.rule_id)
        logical = db.get_logical_rule_identity_for_rule(
            rule.rule_id, rule.siem_id, rule.space
        )
        identity_key = (migration or logical or {}).get("id")
        if identity_key:
            if identity_key in seen_migrations:
                continue
            seen_migrations.add(identity_key)
            display_rules.append(_pick_display_rule(db, migration, logical, identity_key, rule, client_id))
            continue
        display_rules.append(rule)
    return display_rules


def _metrics_from_rules(rules: List["DetectionRule"]) -> RuleHealthMetrics:
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

    for r in rules:
        if r.space:
            rules_by_space[r.space] = rules_by_space.get(r.space, 0) + 1
        if r.siem_id and r.space:
            scope_key = f"{r.siem_id}|{str(r.space).lower()}"
            rules_by_scope[scope_key] = rules_by_scope.get(scope_key, 0) + 1
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


def _get_filtered_deduped_rules(db, filters: RuleFilters, client_id: str) -> List["DetectionRule"]:
    """Fetch every rule matching ``filters`` (unpaginated) and collapse
    migrated/merged identities to one row each — the same rule set the
    grid would render across all of its pages combined."""
    all_filters = filters.model_copy(update={"page": 1, "page_size": 1_000_000})
    rules, _, _ = db.get_rules(filters=all_filters, client_id=client_id)
    db.backfill_unique_rule_migrations(
        db.get_client_siem_scopes(client_id, environment_role="staging"),
        db.get_client_siem_scopes(client_id, environment_role="production"),
    )
    return _dedupe_display_rules(db, rules, client_id)


router = APIRouter(prefix="/api/rules", tags=["rules"])

MITRE_TACTIC_MAP = {
    "Reconnaissance": {"id": "TA0043", "reference": "/mitre/tactic?id=TA0043"},
    "Resource Development": {"id": "TA0042", "reference": "/mitre/tactic?id=TA0042"},
    "Initial Access": {"id": "TA0001", "reference": "/mitre/tactic?id=TA0001"},
    "Execution": {"id": "TA0002", "reference": "/mitre/tactic?id=TA0002"},
    "Persistence": {"id": "TA0003", "reference": "/mitre/tactic?id=TA0003"},
    "Privilege Escalation": {"id": "TA0004", "reference": "/mitre/tactic?id=TA0004"},
    "Defense Evasion": {"id": "TA0005", "reference": "/mitre/tactic?id=TA0005"},
    "Credential Access": {"id": "TA0006", "reference": "/mitre/tactic?id=TA0006"},
    "Discovery": {"id": "TA0007", "reference": "/mitre/tactic?id=TA0007"},
    "Lateral Movement": {"id": "TA0008", "reference": "/mitre/tactic?id=TA0008"},
    "Collection": {"id": "TA0009", "reference": "/mitre/tactic?id=TA0009"},
    "Exfiltration": {"id": "TA0010", "reference": "/mitre/tactic?id=TA0010"},
    "Command And Control": {"id": "TA0011", "reference": "/mitre/tactic?id=TA0011"},
    "Impact": {"id": "TA0040", "reference": "/mitre/tactic?id=TA0040"},
}


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
    groups: dict[str, list[dict]] = {}
    lookup: dict[str, dict] = {}
    for item in db.get_mitre_techniques() or []:
        technique_id = str(item.get("id") or "").strip().upper()
        technique_name = str(item.get("name") or "").strip()
        if not technique_id or not technique_name:
            continue
        tactic = _format_tactic_label(str(item.get("tactic") or ""))
        option = {
            "id": technique_id,
            "name": technique_name,
            "tactic": tactic,
            "url": item.get("url") or "",
        }
        groups.setdefault(tactic, []).append(option)
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
        tactic = option["tactic"]
        tactic_meta = MITRE_TACTIC_MAP.get(tactic)
        if not tactic_meta:
            continue
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
        "timestamp_override": str(raw.get("timestamp_override") or "event.ingested"),
        "highlighted_fields": ", ".join(_split_csv(raw.get("investigation_fields", {}).get("field_names", []) if isinstance(raw.get("investigation_fields"), dict) else raw.get("investigation_fields") or [])),
        "reason": "",
    }


def _build_rule_form_context(db, client_id: str, username: str, form_action: str, submit_label: str,
                             title: str, rule=None, scope_locked: bool = False,
                             prefill: Optional[dict] = None) -> dict:
    siems = db.get_client_siems(client_id) or []
    technique_groups, technique_lookup = _build_technique_groups(db)
    scope_options = [
        {
            "siem_id": s.get("id"),
            "space": s.get("space") or "default",
            "label": f'{s.get("label", "SIEM")} ({(s.get("environment_role") or "staging").title()})',
            "default_index": s.get("default_index") or "",
        }
        for s in siems
        if s.get("id") and (s.get("space") is not None)
    ]
    form_values = _rule_form_values(rule, username=username, prefill=prefill)
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
        "scope_locked": scope_locked,
        "rule": rule,
        "siem_id": getattr(rule, "siem_id", "") if rule else "",
        "space": getattr(rule, "space", "default") if rule else "default",
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


def _build_rule_payload(form_data, technique_lookup: dict[str, dict], default_author: str) -> tuple[dict, str, str, list[str]]:
    from app.elastic_helper import normalize_rule_language

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
    timestamp_override = (form_data.get("timestamp_override") or "event.ingested").strip() or "event.ingested"
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
        # Ignore any submitted "type" (the form carries a stale hidden
        # <input name="type" value="query"> left over from prefill) — the
        # rule type is fully determined by the query language.
        "type": _RULE_TYPE_BY_LANGUAGE.get(language, "query"),
        "mitre_ids": mitre_ids,
        "index": index_patterns,
        "timestamp_override": timestamp_override,
    }
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


def _summarize_rule_changes(old_payload: dict, new_payload: dict) -> tuple[str, str, list[dict[str, str]]]:
    labels = {
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
    }
    changed: list[str] = []
    changed_diffs: list[dict[str, str]] = []
    for key, label in labels.items():
        if key not in new_payload:
            continue

        if key == "mitre_ids":
            before_ids = _canonicalize_id_list(old_payload.get(key), uppercase=True)
            after_ids = _canonicalize_id_list(new_payload.get(key), uppercase=True)
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
    def _normalize_history_actor(actor_name: Any, actor_user_id: Any = None) -> str:
        raw_name = str(actor_name or "").strip()
        if not raw_name:
            return "system"
        normalized = " ".join(raw_name.lower().split())

        # Keep sync actors deterministic and merge known local-user aliases.
        if normalized in {"elastic", "system"}:
            return normalized
        if normalized in {"darral", "darral jukes"}:
            return "darral"

        if actor_user_id and normalized == "darral jukes":
            return "darral"
        return raw_name

    entries: list[dict] = []

    for event in history:
        action = str(event.get("action") or "").strip().lower()
        category = "validation" if action == "validated" else "edits"
        if action == "validated":
            badge = "Validated"
        elif action == "edited":
            badge = "Edit"
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
                "actor": _normalize_history_actor(event.get("actor_name"), event.get("actor_user_id")),
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

    AGENTS.md §8.2 guarantee 4: two SIEMs can share a Kibana space-name.
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
        label = f'{s["label"]} ({s["environment_role"].title()})'
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
        f'{s["id"]}|{s["space"]}': f'{s["label"]} ({s["environment_role"].title()})'
        for s in (siems or [])
        if s.get("id") and s.get("space")
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
    min_score: Optional[str] = Query(None),
    max_score: Optional[str] = Query(None),
    validated_from: Optional[str] = Query(None),
    validated_to: Optional[str] = Query(None),
    sort_by: str = Query("score_desc"),
    sort_score: str = Query("desc"),
    sort_validated: str = Query(""),
    sort_name: str = Query(""),
    page: int = Query(1, ge=1),
    page_size: int = Query(24, ge=1, le=100),
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
            min_score=min_score_int,
            max_score=max_score_int,
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
        all_rules = _resort_rules(all_rules, sort_score, sort_validated, sort_name, sort_by)
        total = len(all_rules)
        total_pages = max(1, (total + page_size - 1) // page_size)
        offset = (page - 1) * page_size
        rules = all_rules[offset:offset + page_size]

        staging_scopes = db.get_client_siem_scopes(client_id, environment_role="staging")
        production_scopes = db.get_client_siem_scopes(client_id, environment_role="production")
        lifecycle_states = {
            f"{rule.rule_id}|{rule.siem_id}|{rule.space}": db.get_rule_lifecycle_state(
                rule.rule_id, staging_scopes, production_scopes
            )
            for rule in rules
        }
        
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
            "min_score": min_score if min_score is not None else "",
            "max_score": max_score if max_score is not None else "",
            "validated_from": validated_from or "",
            "validated_to": validated_to or "",
            "sort_by": sort_by,
            "sort_score": sort_score,
            "sort_validated": sort_validated,
            "sort_name": sort_name,
            "space_labels": _build_space_labels(db, client_id),
            "space_labels_by_pair": _build_space_labels_by_pair(db, client_id),
            "kibana_urls_by_siem": _build_kibana_urls_by_siem(db, client_id),
            "lifecycle_states": lifecycle_states,
        }
        response = templates.TemplateResponse(request, "partials/rules_grid.html", context)
        # Lets the stats cards re-fetch with the same active filters (see
        # #metrics-container in rule_health.html) so they never drift from
        # what the grid is currently showing.
        response.headers["HX-Trigger"] = "rulesFiltered"
        return response
    except Exception as e:
        logger.exception(f"Failed to list rules (sort={sort_by}, space={space}): {e}")
        return HTMLResponse(
            '<div class="empty-state">'
            '<div class="empty-state-title">Error loading rules</div>'
            f'<p class="empty-state-text">An error occurred while loading rules. Check server logs for details.</p>'
            '</div>'
        )


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
    min_score: Optional[str] = Query(None),
    max_score: Optional[str] = Query(None),
    validated_from: Optional[str] = Query(None),
    validated_to: Optional[str] = Query(None),
):
    """Get rule health metrics, scoped to the same filters as the rules grid."""
    from app.main import get_last_sync_time

    min_score_int = int(min_score) if min_score and min_score.strip().lstrip('-').isdigit() else None
    max_score_int = int(max_score) if max_score and max_score.strip().lstrip('-').isdigit() else None
    filters = RuleFilters(
        search=search if search else None,
        space=space if space else None,
        enabled=None if not enabled else (enabled.lower() == 'true'),
        state=[s for s in state if s],
        min_score=min_score_int,
        max_score=max_score_int,
        validated_from=_parse_date_bound(validated_from, end_of_day=False),
        validated_to=_parse_date_bound(validated_to, end_of_day=True),
    )

    # Per-tenant since 4.1.13 — tenant context is pinned by ActiveClient.
    # Computed from the deduplicated rule list (matching what the grid
    # renders) rather than raw SQL rows — a migrated/merged identity's
    # staging and production copies both satisfy the same filters, which
    # would otherwise double-count it against the grid's single card.
    deduped_rules = _get_filtered_deduped_rules(db, filters, client_id)
    metrics = _metrics_from_rules(deduped_rules)
    # Hide orphan space buckets (rules whose (siem_id, space) is no
    # longer in client_siem_map after a mapping change).
    _prune_orphan_scopes(metrics, db, client_id)
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request, "partials/metrics_row.html",
        {
            "metrics": metrics,
            "last_sync_time": get_last_sync_time(),
            "space_labels": _build_space_labels(db, client_id),
            "space_labels_by_pair": _build_space_labels_by_pair(db, client_id),
        },
    )


@router.get("/{rule_id}/detail", response_class=HTMLResponse)
def get_rule_detail(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: CurrentUser,
    settings: SettingsDep,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(
        None,
        description="SIEM that owns this rule. Required for unambiguous "
                    "resolution when multiple SIEMs share a space name. "
                    "Falls back to first space-match (with WARN) if absent.",
    ),
):
    """Get full rule details for modal display."""
    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)
    
    if not rule:
        return HTMLResponse(
            '<div class="modal-overlay" onclick="this.remove()">' 
            '<div class="modal-content" onclick="event.stopPropagation()">' 
            '<p style="color: var(--color-danger);">Rule not found</p>'
            '<button class="btn btn-secondary" onclick="this.closest(\'.modal-overlay\').remove()">Close</button>'
            '</div></div>',
            status_code=404
        )
    
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request, "components/rule_detail_modal.html",
        {
            "rule": rule,
            "env": settings,
            "space_labels": _build_space_labels(db, client_id),
            "kibana_url": _resolve_kibana_url(db, rule, client_id),
        },
    )


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
        return HTMLResponse('<div class="empty-state">Rule not found</div>', status_code=404)
    
    username = user.name or user.username if user else "Unknown"
    db.save_validation(rule.name, username)
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

    _sl = _build_space_labels(db, client_id) if client_id else {}
    staging_scopes = db.get_client_siem_scopes(client_id, environment_role="staging")
    production_scopes = db.get_client_siem_scopes(client_id, environment_role="production")
    lifecycle_states = {
        f"{rule.rule_id}|{rule.siem_id}|{rule.space}": db.get_rule_lifecycle_state(
            rule.rule_id, staging_scopes, production_scopes
        )
    }

    # If called from the modal, re-render the modal instead of the card
    if request.headers.get("X-Return-Modal") == "true":
        return templates.TemplateResponse(
            request, "components/rule_detail_modal.html",
            {
                "rule": rule,
                "env": settings,
                "space_labels": _sl,
                "kibana_url": _resolve_kibana_url(db, rule, client_id),
            },
        )

    return templates.TemplateResponse(
        request, "components/rule_card.html",
        {
            "rule": rule,
            "space_labels": _sl,
            "space_labels_by_pair": _build_space_labels_by_pair(db, client_id),
            "kibana_urls_by_siem": _build_kibana_urls_by_siem(db, client_id),
            "lifecycle_states": lifecycle_states,
            "env": settings,
        }
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
    
    # Resolve the SIEM for this rule. The PREFERRED path (4.0.13+) is to use
    # the explicit siem_id query param — either passed by the rule_detail_modal
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
        "kibana_url=%s env_role=%s api_key_prefix=%s api_key_len=%d es_url=%s",
        client_id, space, siem.get("label"), siem.get("id"),
        siem.get("kibana_url"), siem.get("environment_role"),
        _key[:8] + "..." if _key else "<empty>", len(_key),
        siem.get("elasticsearch_url"),
    )

    try:
        from app.elastic_helper import preview_detection_rule
        loop = asyncio.get_event_loop()
        hit_count, samples, error = await loop.run_in_executor(
            None,
            lambda: preview_detection_rule(
                rule.raw_data, space, lookback=lookback,
                kibana_url=siem["kibana_url"],
                api_key=siem["api_token_enc"],
                elasticsearch_url=siem.get("elasticsearch_url"),
            )
        )
        
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
            }
        )
    except Exception as e:
        logger.exception(f"Test rule failed for {rule_id}")
        return HTMLResponse(
            f'<div class="test-result test-error">Error: {str(e)}</div>',
            status_code=500
        )


@router.post("/sync", response_class=HTMLResponse)
async def sync_rules(
    request: Request,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    background_tasks: BackgroundTasks,
    settings: SettingsDep,
    force_mapping: bool = Query(False),
):
    """Trigger an immediate per-tenant sync of rules from Elastic.

    Always scoped to the active tenant. The cross-tenant ``scope=all``
    fallback was removed in 4.1.13 — detection rules are per-tenant, so a
    sync MUST be scoped to one client.
    """
    import asyncio
    from app.main import scheduled_sync, _sync_status, _update_sync_status
    
    # Reset status and start sync
    _sync_status["started_at"] = None
    _sync_status["finished_at"] = None
    _sync_status["rule_count"] = 0
    label = "Initialising full mapping sync..." if force_mapping else "Initialising sync..."
    _update_sync_status("running", label)
    
    asyncio.create_task(scheduled_sync(force_mapping=force_mapping, client_id=client_id))
    
    # Return live sync tracker that polls for status and refreshes grid on completion
    return HTMLResponse(
        '<div id="sync-status"'
        '     hx-get="/api/sync/status"'
        '     hx-trigger="load, every 1s"'
        '     hx-swap="outerHTML"'
        '     class="sync-tracker sync-running">'
        '    <span class="sync-spinner"></span>'
        '    <span>Sync starting...</span>'
        '</div>'
        '<script>'
        '(function poll(){'
        '  var iv=setInterval(function(){'
        '    var el=document.getElementById("sync-status");'
        '    if(el && el.classList.contains("sync-complete")){'
        '      clearInterval(iv);'
        '      htmx.trigger(document.body,"refreshRules");'
        '      htmx.ajax("GET","/api/rules/metrics",{target:"#metrics-container",swap:"innerHTML"});'
        '    }'
        '  },1000);'
        '})();'
        '</script>'
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
            f'<div class="empty-state-text">Error loading form: {str(e)}</div>',
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
            return HTMLResponse(
                '<div class="empty-state-text">Rule name and query are required.</div>',
                status_code=400,
            )
        if not siem_id or not space:
            return HTMLResponse(
                '<div class="empty-state-text">Select a target SIEM/space pair.</div>',
                status_code=400,
            )

        allowed_pairs = set(db.get_client_siem_scopes(client_id) or [])
        if (siem_id, space) not in allowed_pairs:
            return HTMLResponse(
                '<div class="empty-state-text">Selected SIEM/space is not assigned to this tenant.</div>',
                status_code=403,
            )

        siem = next(
            (
                s for s in (db.get_client_siems(client_id) or [])
                if s.get("id") == siem_id and (s.get("space") or "default") == space
            ),
            None,
        )
        if not siem:
            return HTMLResponse(
                '<div class="empty-state-text">Unable to resolve SIEM credentials for selected pair.</div>',
                status_code=404,
            )

        success, message, new_rule_id = elastic_helper.create_detection_rule(
            rule_data,
            space=space,
            kibana_url=siem.get("kibana_url"),
            api_key=siem.get("api_token_enc"),
        )
        if not success:
            return HTMLResponse(
                f'<div class="empty-state-text">Failed to create rule: {message}</div>',
                status_code=400,
            )

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

        return HTMLResponse(
            '<div></div>'
            '<script>'
            'htmx.ajax("POST","/api/rules/sync",{target:"#sync-status",swap:"outerHTML"});'
            '</script>'
        )
    except Exception as e:
        logger.exception("create_rule failed")
        return HTMLResponse(
            f'<div class="empty-state-text">Error: {str(e)}</div>',
            status_code=500,
        )


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
        return HTMLResponse('<div class="timeline-empty">Missing SIEM context.</div>', status_code=400)

    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)
    if not rule:
        return HTMLResponse('<div class="timeline-empty">Rule not found.</div>', status_code=404)

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
    """Open a focused history modal with edit action when clicking a rule card."""
    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)
    if not rule:
        return HTMLResponse('<div class="timeline-empty">Rule not found.</div>', status_code=404)

    history = db.get_rule_history(rule_id, siem_id or getattr(rule, "siem_id", ""), space, limit=100)
    score_history = db.get_rule_score_history(rule_id, siem_id or getattr(rule, "siem_id", ""), space, limit=50)
    history_entries = _build_rule_history_entries(history, score_history)
    history_users = sorted({entry.get("actor") for entry in history_entries if entry.get("actor")})
    templates = request.app.state.templates
    scope_label = (
        _build_space_labels_by_pair(db, client_id).get(f'{siem_id or getattr(rule, "siem_id", "")}|{space}')
        or _build_space_labels(db, client_id).get(space, space.capitalize())
    )
    return templates.TemplateResponse(
        request,
        "components/rule_history_modal.html",
        {
            "rule": rule,
            "history": history,
            "history_users": history_users,
            "score_history": score_history,
            "history_entries": history_entries,
            "space": space,
            "scope_label": scope_label,
            "siem_id": siem_id or getattr(rule, "siem_id", ""),
        },
    )


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
        return HTMLResponse('<div class="timeline-empty">Rule not found.</div>', status_code=404)

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
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(None),
):
    """Update a rule in Kibana and append lifecycle history."""
    from app import elastic_helper

    thresholds = db.get_client_validation_thresholds(client_id)
    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, thresholds=thresholds)
    if not rule:
        return HTMLResponse('<div class="empty-state-text">Rule not found.</div>', status_code=404)

    actual_siem_id = siem_id or getattr(rule, "siem_id", None)
    if not actual_siem_id:
        return HTMLResponse('<div class="empty-state-text">Missing SIEM context.</div>', status_code=400)

    siem = next((s for s in (db.get_client_siems(client_id) or []) if s.get("id") == actual_siem_id), None)
    if not siem:
        return HTMLResponse('<div class="empty-state-text">SIEM not found.</div>', status_code=404)

    form = await request.form()
    _, technique_lookup = _build_technique_groups(db)
    updated_fields, new_name, _, _ = _build_rule_payload(form, technique_lookup, user.username)
    reason = (form.get("reason") or "").strip()
    if not reason:
        return HTMLResponse(
            '<div class="empty-state-text">Reason for change is required before saving.</div>',
            status_code=400,
        )

    old_payload = dict(rule.raw_data or {})
    # Some historic rule payloads store MITRE only in structured columns, not
    # in raw_data. Backfill for diffing so unchanged MITRE doesn't appear as
    # "- -> Txxxx" on unrelated edits.
    if not old_payload.get("mitre_ids"):
        persisted_mitre_ids = _canonicalize_id_list(
            getattr(rule, "mitre_ids", []) or [],
            uppercase=True,
        )
        if persisted_mitre_ids:
            old_payload["mitre_ids"] = persisted_mitre_ids

    payload = dict(old_payload)
    payload.update(updated_fields)
    if new_name:
        payload["name"] = new_name

    # TIDE may retain a logical/source identity after Elastic generated a new
    # ID during restore or promotion. Kibana updates must use the payload's
    # actual Elastic ID, while TIDE history continues to use rule_id.
    elastic_rule_id = str(old_payload.get("rule_id") or old_payload.get("id") or rule_id)
    migration = db.get_rule_migration_for_rule(rule_id)
    logical = db.get_logical_rule_identity_for_rule(rule_id, actual_siem_id, space)
    if rule.deprecated:
        if not db.update_cached_rule(rule_id, actual_siem_id, space, payload):
            return HTMLResponse('<div class="empty-state-text">TIDE-only rule update failed.</div>', status_code=400)
        update_message = "Deprecated rule updated in TIDE only."
    else:
        update_targets = [(actual_siem_id, space, elastic_rule_id, siem)]
        if migration:
            migration_members = [
                (migration["source_rule_id"], migration["source_siem_id"], migration["source_space"]),
                (migration["target_rule_id"], migration["target_siem_id"], migration["target_space"]),
            ]
            for member_rule_id, member_siem_id, member_space in migration_members:
                if (member_siem_id, member_space) == (actual_siem_id, space):
                    continue
                member_siem = next(
                    (item for item in (db.get_client_siems(client_id) or []) if item.get("id") == member_siem_id),
                    None,
                )
                member_rule = db.get_rule_by_id(
                    member_rule_id, member_space,
                    siem_id=member_siem_id, client_id=client_id,
                )
                if member_siem and member_rule:
                    member_payload = member_rule.raw_data or {}
                    update_targets.append(
                        (member_siem_id, member_space, str(member_payload.get("rule_id") or member_payload.get("id") or member_rule.rule_id), member_siem)
                    )
        elif logical:
            for member in db.get_logical_rule_members(logical["id"]):
                if (member["siem_id"], member["space"]) == (actual_siem_id, space):
                    continue
                member_siem = next(
                    (item for item in (db.get_client_siems(client_id) or []) if item.get("id") == member["siem_id"]),
                    None,
                )
                member_rule = db.get_rule_by_id(
                    member["rule_id"], member["space"],
                    siem_id=member["siem_id"], client_id=client_id,
                )
                if member_siem and member_rule:
                    member_payload = member_rule.raw_data or {}
                    update_targets.append(
                        (member["siem_id"], member["space"], str(member_payload.get("rule_id") or member_payload.get("id") or member_rule.rule_id), member_siem)
                    )
        failures = []
        for target_siem_id, target_space, target_rule_id, target in update_targets:
            success, message = elastic_helper.update_detection_rule(
                rule_id=target_rule_id, rule_data=payload, space=target_space,
                kibana_url=target.get("kibana_url"), api_key=target.get("api_token_enc"),
            )
            if not success:
                logger.error(
                    "Rule edit update failed: rule_id=%s siem_id=%s space=%s "
                    "target_rule_id=%s message=%s",
                    rule_id, target_siem_id, target_space, target_rule_id, message,
                )
                failures.append(f"{target.get('label', target_siem_id)} / {target_space}: {message}")
        if failures:
            return HTMLResponse(
                '<div class="empty-state-text">Rule update was partial. '
                + ' | '.join(failures) + '</div>',
                status_code=409,
            )
        update_message = "Rule updated in all applicable SIEM scopes."

    change_message, changed_fields, field_diffs = _summarize_rule_changes(old_payload, payload)
    db.record_rule_history(
        rule_id=rule_id,
        siem_id=actual_siem_id,
        space=space,
        client_id=client_id,
        action="edited",
        actor_user_id=user.id,
        actor_name=user.username,
        detail={
            "message": update_message + " " + change_message,
            "reason": reason,
            "changed_fields": changed_fields,
            "field_diffs": field_diffs,
        },
    )

    return HTMLResponse(
        '<div></div>'
        '<script>'
        'htmx.ajax("POST","/api/rules/sync",{target:"#sync-status",swap:"outerHTML"});'
        '</script>'
    )


@router.post("/{rule_id}/sync", response_class=HTMLResponse)
def sync_one_rule(
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(None),
):
    """Check one rule directly against its configured SIEM scope."""
    from app import elastic_helper

    if not siem_id:
        return HTMLResponse('<div class="empty-state-text">Missing SIEM context.</div>', status_code=400)
    siem = next((item for item in (db.get_client_siems(client_id) or []) if item.get("id") == siem_id), None)
    if not siem:
        return HTMLResponse('<div class="empty-state-text">SIEM not found.</div>', status_code=404)
    full = db.get_siem_inventory_item(siem_id) or siem
    try:
        frame = elastic_helper.fetch_detection_rules(
            kibana_url=full.get("kibana_url") or siem.get("kibana_url"),
            api_key=full.get("api_token_enc"),
            spaces=[space],
            check_mappings=True,
            known_rule_keys=set(),
            elasticsearch_url=full.get("elasticsearch_url") or siem.get("elasticsearch_url"),
        )
        matches = [] if frame is None or frame.empty else frame[
            frame["rule_id"].astype(str) == str(rule_id)
        ].to_dict("records")
        if matches:
            matches[0]["siem_id"] = siem_id
            db.save_audit_results(matches, client_id=client_id)
            action = "synced"
            message = "Rule found in Elastic and refreshed."
            detail = {"message": message, "targeted": True}
            db.set_rule_deprecated(rule_id, siem_id, space, False)
        else:
            db.set_rule_deprecated(rule_id, siem_id, space, True)
            action = "deprecated"
            message = "Rule was not found in Elastic and is marked deprecated."
            detail = {"message": message, "targeted": True}
        db.record_rule_history(
            rule_id=rule_id, siem_id=siem_id, space=space, client_id=client_id,
            action=action, actor_user_id=user.id, actor_name=user.username,
            detail=detail,
        )
        return HTMLResponse(f'<div class="empty-state-text">{message}</div>')
    except Exception as exc:
        logger.exception("Targeted rule sync failed for %s", rule_id)
        return HTMLResponse(f'<div class="empty-state-text">Targeted sync failed: {exc}</div>', status_code=400)


@router.post("/{rule_id}/archive", response_class=HTMLResponse)
def archive_rule(
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(None),
):
    """Archive a rule in TIDE without changing Elastic."""
    if not siem_id or not db.set_rule_deprecated(rule_id, siem_id, space, True):
        return HTMLResponse('<div class="empty-state-text">Rule not found.</div>', status_code=404)
    db.record_rule_history(
        rule_id=rule_id, siem_id=siem_id, space=space, client_id=client_id,
        action="deprecated", actor_user_id=user.id, actor_name=user.username,
        detail={"message": "Rule archived in TIDE."},
    )
    return HTMLResponse('<div class="empty-state-text">Rule archived in TIDE.</div>')


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
        return HTMLResponse('<div class="empty-state-text">Rule not found.</div>', status_code=404)
    rule = db.get_rule_by_id(rule_id, space, siem_id=siem_id, client_id=client_id)
    if not rule or not rule.raw_data:
        return HTMLResponse('<div class="empty-state-text">Rule data is unavailable.</div>', status_code=404)
    form = await request.form()
    replacement_siem_id, replacement_space = _parse_scope_pair(
        str(form.get("replacement_scope") or "")
    )
    if not replacement_siem_id or not replacement_space:
        return HTMLResponse('<div class="empty-state-text">Select a Replacement SIEM / space first.</div>', status_code=400)
    target = next(
        (item for item in (db.get_client_siems(client_id) or [])
         if item.get("id") == replacement_siem_id
         and (item.get("space") or "default") == replacement_space),
        None,
    )
    if not target:
        return HTMLResponse('<div class="empty-state-text">Replacement SIEM / space is not linked to this client.</div>', status_code=400)

    from app import elastic_helper
    full_target = db.get_siem_inventory_item(replacement_siem_id) or target
    success, message, new_rule_id = elastic_helper.create_detection_rule(
        rule.raw_data,
        space=replacement_space,
        kibana_url=full_target.get("kibana_url") or target.get("kibana_url"),
        api_key=full_target.get("api_token_enc"),
    )
    if not success or not new_rule_id:
        return HTMLResponse(f'<div class="empty-state-text">Restore failed: {message}</div>', status_code=400)

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
        replacement_siem_id, replacement_space,
    )
    # Restore is an identity replacement, not a migration mapping. The new
    # synced row is the sole TIDE record; remove the old SIEM-scope cache row
    # after baseline references have been moved to the recreated ID.
    db.delete_rule(rule_id, siem_id, space)
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
        f'<div class="empty-state-text">Rule recreated in Elastic as {new_rule_id}.</div>'
    )


@router.delete("/{rule_id}", response_class=HTMLResponse)
def delete_rule(
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(None),
):
    """Delete a rule from TIDE only; Elastic is never modified."""
    if not siem_id or not db.delete_rule(rule_id, siem_id, space):
        return HTMLResponse('<div class="empty-state-text">Rule not found.</div>', status_code=404)
    db.record_rule_history(
        rule_id=rule_id, siem_id=siem_id, space=space, client_id=client_id,
        action="deleted", actor_user_id=user.id, actor_name=user.username,
        detail={"message": "Rule deleted from TIDE."},
    )
    return HTMLResponse('<div class="empty-state-text">Rule deleted from TIDE.</div>')


@router.post("/{rule_id}/merge", response_class=HTMLResponse)
async def merge_rule(
    request: Request,
    rule_id: str,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    space: str = Query("default"),
    siem_id: Optional[str] = Query(None),
):
    """Merge two rule IDs into one logical TIDE rule identity."""
    form = await request.form()
    replacement_id = str(form.get("replacement_rule_id") or "").strip()
    replacement_scope = str(form.get("replacement_scope") or "").strip()
    replacement_siem_id, replacement_space = _parse_scope_pair(replacement_scope)
    replacement_siem_id = replacement_siem_id or str(siem_id or "").strip()
    replacement_space = replacement_space if replacement_scope else ""
    if not siem_id or not replacement_id or not replacement_siem_id or not replacement_space:
        return HTMLResponse('<div class="empty-state-text">Replacement rule ID, SIEM, and space are required.</div>', status_code=400)
    logical_id = db.merge_logical_rule_identity(
        rule_id, replacement_id, siem_id, space,
        replacement_siem_id, replacement_space, user.username,
    )
    if not logical_id:
        return HTMLResponse('<div class="empty-state-text">Both rules must exist in their selected SIEM and space.</div>', status_code=400)
    db.record_rule_history(
        rule_id=rule_id, siem_id=siem_id, space=space, client_id=client_id,
        action="merged", actor_user_id=user.id, actor_name=user.username,
        detail={"message": "Rules merged into one logical identity.", "replacement_rule_id": replacement_id, "replacement_siem_id": replacement_siem_id, "replacement_space": replacement_space, "logical_rule_id": logical_id},
    )
    return HTMLResponse(f'<div class="empty-state-text">Rules merged. Baselines now follow {replacement_id}.</div>')


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
        return HTMLResponse('<div class="empty-state-text">Missing SIEM context.</div>', status_code=400)

    siem = next((s for s in (db.get_client_siems(client_id) or []) if s.get("id") == siem_id), None)
    if not siem:
        return HTMLResponse('<div class="empty-state-text">SIEM not found.</div>', status_code=404)

    success, message = elastic_helper.enable_detection_rule(
        rule_id,
        space=space,
        kibana_url=siem.get("kibana_url"),
        api_key=siem.get("api_token_enc"),
    )
    if not success:
        return HTMLResponse(f'<div class="empty-state-text">{message}</div>', status_code=400)

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
    return HTMLResponse('<script>htmx.trigger(document.body,"refreshRules");</script>')


@router.patch("/{rule_id}/disable", response_class=HTMLResponse)
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
        return HTMLResponse('<div class="empty-state-text">Missing SIEM context.</div>', status_code=400)

    siem = next((s for s in (db.get_client_siems(client_id) or []) if s.get("id") == siem_id), None)
    if not siem:
        return HTMLResponse('<div class="empty-state-text">SIEM not found.</div>', status_code=404)

    success, message = elastic_helper.disable_detection_rule(
        rule_id,
        space=space,
        kibana_url=siem.get("kibana_url"),
        api_key=siem.get("api_token_enc"),
    )
    if not success:
        return HTMLResponse(f'<div class="empty-state-text">{message}</div>', status_code=400)

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
    return HTMLResponse('<script>htmx.trigger(document.body,"refreshRules");</script>')
