"""Rule quality scoring (pure functions, no I/O).

A rule can be checked against many things (the components below); a client switches on the ones it cares about. Each check
produces a *fraction* between 0 and 1 (how well the rule does), or "not
applicable" when it cannot be judged (for example search time for a rule that
has never run). Each client decides how many points every check is worth; the
rule's score is a percentage of the points that apply:

    score % = points earned / points that apply x 100

so weights do not need to add up to 100, a check set to 0 is switched off, and a
check that cannot be judged never drags a rule down.

Every component carries a plain-English description of how it is scored (``how``)
and a sentence about this rule's result (``result``) for the Rule modal. The
stored fraction lets a client's rules be re-scored under new weights without
asking the SIEM again (``rescore_detail``).

``SCORING_VERSION`` identifies the scoring model. Bump it whenever a threshold
or a component changes; stored scores and score-history snapshots carry it, so a
step change in scores can be explained by the model rather than by the rule's owners.

Versions
  1  original model (mapping ratio over index x field rows, last-run search time,
     note = exists, query language scored, fixed weights, out of 100 points).
  2  mapping scored per field (found on any of the rule's indexes), unreachable
     indexes left out instead of counted as failures, checks that cannot be
     judged are "not applicable", search time is the median of recent runs, the
     investigation guide is scored on length, fit-for-use type weights
     (aggregatable fields), highlights and the timestamp override are checked
     against the mapping, tactics and techniques are one MITRE check, the query
     language is worth 0 points unless a client turns it on, weights are set per
     client and scores are a percentage of the points allocated.
  3  when a rule's index patterns match no indices at all there is nothing to check
     its mapping, field types or timestamp override against, so those three checks
     earn full marks instead of being failed or left out. They are still failed when
     the indexes exist and lack the field, and left out when the SIEM cannot be reached.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from statistics import median
from typing import Any, Dict, Iterable, List, Optional, Tuple

SCORING_VERSION = 3

# Facts about one field: state is "found" | "missing" | "unknown".
#   found    - present in the mapping of at least one of the rule's indexes
#   missing  - the indexes were checked and none has it
#   unknown  - the indexes could not be checked (SIEM unreachable): never counted against the rule
FOUND, MISSING, UNKNOWN = "found", "missing", "unknown"

FIELD_TYPE_WEIGHTS: Dict[str, float] = {
    "keyword": 1.0, "constant_keyword": 1.0, "alias": 1.0,
    "wildcard": 0.8, "date": 0.8, "date_nanos": 0.8,
    "ip": 0.7, "nested": 0.7, "version": 0.7,
    "object": 0.6, "flattened": 0.6,
    "text": 0.5, "match_only_text": 0.5,
    "integer": 0.5, "long": 0.5, "short": 0.5, "byte": 0.5, "unsigned_long": 0.5,
    "geo_point": 0.5, "ip_range": 0.5, "date_range": 0.5,
    "integer_range": 0.5, "long_range": 0.5, "float_range": 0.5, "double_range": 0.5,
    "float": 0.4, "double": 0.4, "half_float": 0.4, "scaled_float": 0.4, "geo_shape": 0.4,
    "boolean": 0.3,
    "binary": 0.2,
}
UNLISTED_TYPE_WEIGHT = 0.5

SEARCH_TIME_TIERS = ((200, 1.0), (400, 0.8), (1000, 0.6), (2000, 0.4), (2500, 0.2))   # (max ms, fraction)
SEARCH_TIME_SAMPLES = 10

NOTE_TIERS = ((600, 1.0), (300, 0.75), (100, 0.5), (1, 0.25))                           # (min characters, fraction)

MITRE_TACTIC_SHARE, MITRE_TECHNIQUE_SHARE = 0.3, 0.7

DESCRIPTION_TIERS = ((200, 1.0), (100, 0.75), (30, 0.5), (1, 0.25))                     # (min characters, fraction)
FRESHNESS_TIERS = ((90, 1.0), (180, 0.75), (365, 0.5))                                 # (max days since update, fraction)
FRESHNESS_STALE = 0.25
EXECUTION_STATUS = {"succeeded": 1.0, "partial failure": 0.5, "failed": 0.0}

# Query language: 60% detection strength + 40% performance, out of 10. Worth 0 points unless a client turns it on.
LANGUAGE_SCORES = {
    "kuery": (7, 9), "lucene": (6, 9), "eql": (10, 7), "esql": (9, 7), "dsl": (9, 8),
}
LANGUAGE_NAMES = {"kuery": "KQL", "lucene": "Lucene", "eql": "EQL", "esql": "ES|QL", "dsl": "Query DSL"}

# key, label, group, default points, how it is scored
COMPONENTS = (
    ("mapping", "Mapping", "quality", 37,
     "Share of the fields used by the rule that exist in the mapping of its index patterns. A field counts when any "
     "of the rule's indexes has it. Indexes that could not be reached are left out, not counted as failures."),
    ("field_type", "Field type", "quality", 12,
     "How well the mapped field types suit detection: keyword full points, date and wildcard 80%, ip 70%, text and "
     "numbers 50%, boolean 30%. A field the rule groups or suppresses on scores 0 when it cannot be aggregated."),
    ("search_time", "Search time", "quality", 8,
     "Median search time of the rule's last 10 executions: up to 200 ms full points, 400 ms 80%, 1 s 60%, 2 s 40%, "
     "2.5 s 20%, slower 0. Not scored until TIDE has seen the rule run."),
    ("language", "Query language", "quality", 0,
     "Off by default. Scored on the query language: 60% detection strength and 40% performance. "
     "KQL 78%, Lucene 78%, EQL 88%, ES|QL 82%, Query DSL 86%."),
    ("execution", "Last execution", "operations", 0,
     "Result of the rule's last run in Kibana: succeeded full points, partial failure 50%, failed 0. "
     "Not scored when the rule has not run."),
    ("schedule", "Schedule coverage", "operations", 0,
     "Full points when the look-back covers the run interval, so no events fall between runs. A shorter look-back scores in proportion."),
    ("enabled", "Enabled", "operations", 0, "Full points when the rule is enabled in its SIEM."),
    ("freshness", "Freshness", "operations", 0,
     "How recently the rule was last updated in the SIEM: within 90 days full points, 180 days 75%, a year 50%, older 25%."),
    ("note", "Investigation guide", "meta", 15,
     "Scored on length: none 0, under 100 characters 25%, under 300 50%, under 600 75%, 600 or more full points."),
    ("override", "Timestamp override", "meta", 8,
     "Full points when the timestamp override is event.ingested and that field exists in the rule's indexes."),
    ("mitre", "MITRE mapping", "meta", 10,
     "30% for at least one MITRE tactic and 70% for at least one technique."),
    ("author", "Author", "meta", 5, "Full points when an author is set."),
    ("highlights", "Highlighted fields", "meta", 5,
     "Full points when custom highlighted fields are set, scaled by the share that exist in the mapping. "
     "Alert-suppression fields do not count."),
    ("description", "Description", "meta", 0,
     "Scored on length: none 0, under 30 characters 25%, under 100 50%, under 200 75%, 200 or more full points."),
    ("references", "References", "meta", 0, "Full points when the rule links at least one reference URL."),
    ("false_positives", "False positives documented", "meta", 0, "Full points when known false positives are listed."),
    ("tags", "Tags", "meta", 0, "Full points when the rule has at least one tag."),
    ("setup", "Setup guide", "meta", 0, "Full points when the rule has setup instructions."),
    ("suppression", "Alert suppression", "meta", 0,
     "Full points when alert suppression is configured, which cuts down duplicate alerts."),
)
COMPONENT_BY_KEY = {c[0]: c for c in COMPONENTS}
DEFAULT_WEIGHTS: Dict[str, int] = {c[0]: c[3] for c in COMPONENTS}
MAX_WEIGHT = 100

# component key -> stored integer point columns on detection_rules (mitre is split across two)
COLUMN_FOR = {
    "mapping": "score_mapping", "field_type": "score_field_type", "search_time": "score_search_time",
    "language": "score_language", "note": "score_note", "override": "score_override", "author": "score_author", "highlights": "score_highlights",
}
SCORE_COLUMNS = (
    "score", "quality_score", "meta_score", "score_mapping", "score_field_type", "score_search_time",
    "score_language", "score_note", "score_override", "score_tactics", "score_techniques", "score_author",
    "score_highlights",
)


def resolve_weights(weights: Optional[Dict[str, Any]] = None) -> Dict[str, int]:
    """A client's weights with defaults filled in; anything unusable falls back to the default."""
    out = dict(DEFAULT_WEIGHTS)
    for key, value in (weights or {}).items():
        if key in out:
            try:
                out[key] = max(0, min(MAX_WEIGHT, int(value)))
            except (TypeError, ValueError):
                pass
    return out


def parse_weights(raw: Dict[str, Any]) -> Tuple[Optional[Dict[str, int]], str]:
    """Validate submitted weights: whole numbers 0-100 for every check, at least one above 0."""
    weights: Dict[str, int] = {}
    for key, label, *_ in COMPONENTS:
        text = str(raw.get(key, "")).strip()
        if text == "":
            return None, f"Enter a number of points for {label}."
        try:
            value = int(text)
        except ValueError:
            return None, f"{label} must be a whole number."
        if not 0 <= value <= MAX_WEIGHT:
            return None, f"{label} must be between 0 and {MAX_WEIGHT}."
        weights[key] = value
    if not any(weights.values()):
        return None, "At least one check needs points."
    return weights, ""


def facts_from_results(results: Iterable[Any]) -> Dict[str, Dict[str, Any]]:
    """Field facts from stored ``(index, field, exists, type)`` rows (used when no live catalogue data is at hand)."""
    facts: Dict[str, Dict[str, Any]] = {}
    for row in results or []:
        try:
            _idx, field, exists, ftype = row[0], str(row[1]), str(row[2]), str(row[3])
        except (IndexError, TypeError):
            continue
        cur = facts.setdefault(field, {"state": UNKNOWN, "type": "", "aggregatable": None})
        if exists == "Yes":
            cur["state"], cur["type"] = FOUND, cur["type"] or ftype
        elif exists == "-" and cur["state"] != FOUND:
            cur["state"] = MISSING
    return facts


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _names(fields: List[str], limit: int = 4) -> str:
    shown = ", ".join(sorted(fields)[:limit])
    return shown + (f" and {len(fields) - limit} more" if len(fields) > limit else "")


def search_time_fraction(ms: float) -> float:
    for ceiling, fraction in SEARCH_TIME_TIERS:
        if ms <= ceiling:
            return fraction
    return 0.0


def note_fraction(length: int) -> float:
    for minimum, fraction in NOTE_TIERS:
        if length >= minimum:
            return fraction
    return 0.0


_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def _seconds(text: Any) -> Optional[int]:
    """``"5m"`` / ``"now-65m"`` / ``"1h"`` as seconds (None when unreadable)."""
    m = re.fullmatch(r"(?:now-)?(\d+)([smhdw])", str(text or "").strip().lower())
    return int(m.group(1)) * _UNIT_SECONDS[m.group(2)] if m else None


def _days_since(stamp: Any) -> Optional[int]:
    try:
        moment = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - moment).days)


def _points(x: float):
    """One decimal, no trailing ``.0``."""
    x = round(x, 1)
    return int(x) if x == int(x) else x


def _finish(components: List[Dict[str, Any]], weights: Dict[str, int]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Apply weights to component fractions. Returns ``(detail, columns)``."""
    earned = possible = 0.0
    quality = 0.0
    for c in components:
        weight = weights[c["key"]]
        c["max"] = weight
        active = c["fraction"] is not None and weight > 0
        c["applicable"] = c["fraction"] is not None
        c["value"] = _points(c["fraction"] * weight) if active else 0
        if active:
            earned += c["fraction"] * weight
            possible += weight
            if c["group"] == "quality":
                quality += c["fraction"] * weight
    total = round(100 * earned / possible) if possible else 0
    quality_pct = round(100 * quality / possible) if possible else 0

    by_key = {c["key"]: c for c in components}
    columns: Dict[str, Any] = {"score": total, "quality_score": quality_pct, "meta_score": total - quality_pct}
    for key, column in COLUMN_FOR.items():
        columns[column] = int(round(by_key[key]["value"]))
    mitre = by_key["mitre"]
    tactic_points = int(round(mitre["max"] * MITRE_TACTIC_SHARE)) if (mitre["fraction"] or 0) >= MITRE_TACTIC_SHARE else 0
    columns["score_tactics"] = min(tactic_points, int(round(mitre["value"])))
    columns["score_techniques"] = max(0, int(round(mitre["value"])) - columns["score_tactics"])

    detail = {"version": SCORING_VERSION, "earned": _points(earned), "possible": _points(possible),
              "allocated": sum(weights.values()), "components": components}
    return detail, columns


def rescore_detail(detail: Dict[str, Any], weights: Optional[Dict[str, Any]]) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """Re-apply new weights to a stored ``score_detail`` (no SIEM calls).

    Returns ``(detail, columns)``, or ``None`` when the stored detail predates
    per-check fractions and the rule has to be synced again first.
    """
    stored = {c.get("key"): c for c in (detail or {}).get("components", [])}
    if any(key not in stored or "fraction" not in stored[key] for key in DEFAULT_WEIGHTS):
        return None
    components = [dict(stored[key]) for key in DEFAULT_WEIGHTS]      # canonical order, extras (old keys) dropped
    return _finish(components, resolve_weights(weights))


def apply_search_time(detail: Dict[str, Any], samples_ms: Iterable[int],
                      weights: Optional[Dict[str, Any]]) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """Recompute only the search-time check of a stored ``score_detail`` from ``samples_ms`` (newest first).

    Like ``rescore_detail`` it needs no SIEM call, and returns ``None`` when the stored detail predates
    per-check fractions (the rule has to be synced first).
    """
    stored = {c.get("key"): c for c in (detail or {}).get("components", [])}
    if any(key not in stored or "fraction" not in stored[key] for key in DEFAULT_WEIGHTS):
        return None
    components = [dict(stored[key]) for key in DEFAULT_WEIGHTS]
    samples = [int(s) for s in samples_ms if s is not None][:SEARCH_TIME_SAMPLES]
    target = next(c for c in components if c["key"] == "search_time")
    if samples:
        med = median(samples)
        target["fraction"] = search_time_fraction(med)
        target["result"] = f"Median {int(med)} ms over the last {_plural(len(samples), 'run')}."
    else:
        target["fraction"] = None
        target["result"] = "Not scored: TIDE has not seen this rule run yet."
    return _finish(components, resolve_weights(weights))


def score_rule(rule_data: Dict[str, Any], weights: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Score one rule in place and return it.

    Reads from ``rule_data``: ``field_facts`` (query fields), ``aux_facts``
    (highlight / override fields), ``aggregate_fields`` (fields the rule groups
    or suppresses on), ``search_times_ms`` (recent runs), ``note``,
    ``timestamp_override``, ``tactics``, ``techniques``, ``author_str`` and
    ``highlight_fields``. ``weights`` are the client's points per check (defaults
    when omitted). Writes the ``score*`` columns, ``score_detail`` and ``scoring_version``.
    """
    facts = rule_data.get("field_facts")
    if facts is None:
        facts = facts_from_results(rule_data.get("results"))
    aux = rule_data.get("aux_facts") or {}
    aggregate_fields = set(rule_data.get("aggregate_fields") or [])
    out: Dict[str, Dict[str, Any]] = {}

    def put(key: str, fraction: Optional[float], result: str) -> None:
        _k, label, group, _weight, how = COMPONENT_BY_KEY[key]
        out[key] = {"key": key, "label": label, "group": group, "fraction": fraction, "how": how, "result": result}

    # Mapping: per field, found on any index counts.
    found = [f for f, v in facts.items() if v["state"] == FOUND]
    missing = [f for f, v in facts.items() if v["state"] == MISSING]
    unknown = [f for f, v in facts.items() if v["state"] == UNKNOWN]
    known = len(found) + len(missing)
    no_index = [f for f in missing if facts[f].get("no_index")]          # nothing to check against
    really_missing = [f for f in missing if f not in no_index]
    if not facts:
        put("mapping", None, "No fields could be read from the query, so there is nothing to check.")
    elif known == 0:
        put("mapping", None, "Not scored: the rule's indexes could not be checked against the SIEM.")
    else:
        text = f"{len(found)} of {_plural(known, 'field')} found in the mapping"
        if really_missing:
            text += f"; missing: {_names(really_missing)}"
        if no_index:
            text += (f"; {_plural(len(no_index), 'field')} cannot be mapped because the rule's index patterns match no "
                     f"indices in the SIEM, so {'it earns' if len(no_index) == 1 else 'they earn'} full marks")
        if unknown:
            text += f"; {_plural(len(unknown), 'field')} not checked (index unreachable)"
        put("mapping", (len(found) + len(no_index)) / known, text + ".")

    # Field type: fit for use, over the query fields that were found plus any grouping / suppression
    # fields (which live outside the query but must be aggregatable).
    typed = {f: facts[f] for f in found}
    for f in aggregate_fields:
        info = aux.get(f) or facts.get(f)
        if info and info["state"] == FOUND:
            typed.setdefault(f, info)
    if typed:
        weights_by_field, bad_agg = [], []
        for f, info in typed.items():
            if f in aggregate_fields and info.get("aggregatable") is False:
                weights_by_field.append(0.0)
                bad_agg.append(f)
            else:
                weights_by_field.append(FIELD_TYPE_WEIGHTS.get(str(info.get("type") or "").lower(), UNLISTED_TYPE_WEIGHT))
        avg = sum(weights_by_field) / len(weights_by_field)
        text = f"Average type weight {avg:.2f} across {_plural(len(typed), 'field')}"
        if bad_agg:
            text += f"; cannot be aggregated but used for grouping: {_names(bad_agg)}"
        put("field_type", avg, text + ".")
    elif no_index and not found:
        put("field_type", 1.0, "Full marks: the rule's index patterns match no indices in the SIEM, so there are no mapped field types to judge.")
    else:
        put("field_type", None, "Not scored: no mapped fields to assess.")

    # Search time: median of recent executions.
    samples = [int(s) for s in (rule_data.get("search_times_ms") or []) if s is not None][:SEARCH_TIME_SAMPLES]
    if samples:
        med = median(samples)
        put("search_time", search_time_fraction(med), f"Median {int(med)} ms over the last {_plural(len(samples), 'run')}.")
    else:
        put("search_time", None, "Not scored: TIDE has not seen this rule run yet.")

    # Query language (worth 0 points unless a client turns it on).
    lang_key = str(rule_data.get("language") or "kuery").lower()
    if lang_key in LANGUAGE_SCORES:
        detection, performance = LANGUAGE_SCORES[lang_key]
        value = detection * 0.6 + performance * 0.4
        put("language", value / 10, f"{LANGUAGE_NAMES[lang_key]}: detection {detection}, performance {performance} = {value:.1f} out of 10.")
    else:
        put("language", 0.0, f"Unrecognised query language: {lang_key}.")

    # Investigation guide by length.
    note_len = len(str(rule_data.get("note") or "").strip())
    put("note", note_fraction(note_len), f"{note_len} characters." if note_len else "No investigation guide written.")

    # Timestamp override.
    override = str(rule_data.get("timestamp_override") or "-")
    if override == "event.ingested":
        info = aux.get("event.ingested")
        if info and info["state"] == MISSING and info.get("no_index"):
            # The setting is right; there is simply no index to check it against (a lab SIEM, or a
            # pattern for an integration that is not installed). That earns full marks.
            put("override", 1.0, "Set to event.ingested. The rule's index patterns match no indices in the SIEM, so there is nothing to check it against: full marks.")
        elif info and info["state"] == MISSING:
            put("override", 0.0, "Set to event.ingested, but that field is missing from the rule's indexes.")
        else:
            put("override", 1.0, "Set to event.ingested.")
    else:
        put("override", 0.0, "Not set to event.ingested." if override in ("-", "") else f"Set to {override}, not event.ingested.")

    # MITRE mapping.
    has_tactic = bool(rule_data.get("tactics")) and rule_data.get("tactics") != "-"
    has_technique = bool(rule_data.get("techniques")) and rule_data.get("techniques") != "-"
    mitre_text = ("Tactic and technique mapped." if has_tactic and has_technique else "Technique mapped, no tactic." if has_technique
                  else "Tactic mapped, no technique." if has_tactic else "No tactic or technique mapped.")
    put("mitre", (MITRE_TACTIC_SHARE if has_tactic else 0) + (MITRE_TECHNIQUE_SHARE if has_technique else 0), mitre_text)

    author = rule_data.get("author_str")
    has_author = bool(author) and str(author) not in ("-", "[]")
    put("author", 1.0 if has_author else 0.0, "Author set." if has_author else "No author set.")

    # Highlighted fields.
    hl = [str(f) for f in (rule_data.get("highlight_fields") or []) if f]
    if hl:
        gone = [f for f in hl if (aux.get(f) or {}).get("state") == MISSING]
        text = f"{_plural(len(hl), 'highlighted field')}"
        if gone:
            text += f"; missing from the mapping: {_names(gone)}"
        put("highlights", (len(hl) - len(gone)) / len(hl), text + ".")
    else:
        put("highlights", 0.0, "No custom highlighted fields set.")

    raw = rule_data.get("raw_data") if isinstance(rule_data.get("raw_data"), dict) else {}

    # Operations: is the rule healthy in its SIEM?
    last_exec = ((raw.get("execution_summary") or {}).get("last_execution") or {}) if isinstance(raw.get("execution_summary"), dict) else {}
    status = str(last_exec.get("status") or "").lower()
    if status in EXECUTION_STATUS:
        put("execution", EXECUTION_STATUS[status], f"Last run: {status}.")
    else:
        put("execution", None, "Not scored: TIDE has no execution result for this rule.")

    interval, lookback = _seconds(raw.get("interval")), _seconds(raw.get("from"))
    if interval and lookback:
        put("schedule", min(1.0, lookback / interval),
            f"Runs every {raw.get('interval')} and looks back {str(raw.get('from')).replace('now-', '')}"
            + ("." if lookback >= interval else ": events between runs can be missed."))
    else:
        put("schedule", None, "Not scored: the run interval or look-back could not be read.")

    is_enabled = bool(rule_data.get("enabled"))
    put("enabled", 1.0 if is_enabled else 0.0, "Enabled." if is_enabled else "Disabled.")

    age = _days_since(raw.get("updated_at"))
    if age is None:
        put("freshness", None, "Not scored: no last-updated date.")
    else:
        put("freshness", next((f for limit, f in FRESHNESS_TIERS if age <= limit), FRESHNESS_STALE), f"Last updated {age} days ago.")

    # More documentation checks.
    description_len = len(str(raw.get("description") or "").strip())
    put("description", next((f for minimum, f in DESCRIPTION_TIERS if description_len >= minimum), 0.0),
        f"{description_len} characters." if description_len else "No description.")
    refs = [u for u in (raw.get("references") or []) if str(u).lower().startswith(("http://", "https://"))]
    put("references", 1.0 if refs else 0.0, f"{_plural(len(refs), 'reference')}." if refs else "No references.")
    fps = [f for f in (raw.get("false_positives") or []) if str(f).strip()]
    put("false_positives", 1.0 if fps else 0.0, f"{_plural(len(fps), 'false positive')} listed." if fps else "No false positives listed.")
    tags = [t for t in (raw.get("tags") or []) if str(t).strip()]
    put("tags", 1.0 if tags else 0.0, f"{_plural(len(tags), 'tag')}." if tags else "No tags.")
    has_setup = bool(str(raw.get("setup") or "").strip())
    put("setup", 1.0 if has_setup else 0.0, "Setup guide written." if has_setup else "No setup guide.")
    grouped = bool(isinstance(raw.get("alert_suppression"), dict) and raw["alert_suppression"].get("group_by"))
    put("suppression", 1.0 if grouped else 0.0, "Alert suppression configured." if grouped else "No alert suppression.")

    detail, columns = _finish([out[key] for key in DEFAULT_WEIGHTS], resolve_weights(weights))
    rule_data.update(columns)
    rule_data["scoring_version"] = SCORING_VERSION
    rule_data["score_detail"] = detail
    return rule_data
