"""The settings only some Kibana rule types have, as TIDE's rule form edits them and the rule window
shows them: an indicator match rule's indicator index, query and mapping; a threshold rule's
threshold; a new terms rule's fields and history window.

An indicator mapping is Kibana's ``threat_mapping``: groups joined by OR, each a list of entries
joined by AND, each entry a field of the rule's own indexes that matches a field of the indicator
index (``value``). Kibana 9.x can also hold "does not match" entries (``negate``); Kibana 8.19 drops
them (047741/TIDE#91), so the form never makes one, but keeps any a rule has, unchanged.

Kibana's limits, checked on 8.19: a threshold groups by at most 3 fields and is at least 1; a new
terms rule has 1 to 3 fields and a history window in date math (``now-7d``, not ``7d``).
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple

# Each type's own settings, as the form posts them in a rule's payload.
SETTING_KEYS = {
    "threat_match": ("threat_index", "threat_query", "threat_language", "threat_mapping", "threat_indicator_path"),
    "threshold": ("threshold",),
    "new_terms": ("new_terms_fields", "history_window_start"),
}
FIELDS_MAX = 3                       # a threshold's group-by fields, a new terms rule's fields
THRESHOLD_DEFAULT = 100              # Kibana's own form starts a threshold rule on 100
HISTORY_WINDOW_DEFAULT = "7d"        # ... and a new terms rule on the last 7 days
_WINDOW = re.compile(r"^(?:now-)?(\d+)([smhd])$")

# What Kibana's own form starts an indicator match rule with.
INDICATOR_QUERY_DEFAULT = '@timestamp >= "now-30d/d"'
INDICATOR_INDEX_PLACEHOLDER = "logs-ti_*"
INDICATOR_PREFIX_DEFAULT = "threat.indicator"
QUERY_LANGUAGES = ("kuery", "lucene")      # an indicator match rule's, on either index


def mapping_groups(raw: Any) -> List[Dict[str, Any]]:
    """An indicator mapping as Kibana takes it, ``[{"entries": [{"field", "type": "mapping", "value"}]}]``,
    from a rule's ``threat_mapping`` or the form's (JSON text). Blank entries and empty groups are left
    out; an entry Kibana holds as "does not match" keeps ``negate``."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw) if raw.strip() else []
        except ValueError:
            return []
    groups = []
    for group in raw if isinstance(raw, list) else []:
        entries = group.get("entries") if isinstance(group, dict) else group if isinstance(group, list) else []
        kept = []
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            field, value = str(entry.get("field") or "").strip(), str(entry.get("value") or "").strip()
            if not field and not value:
                continue
            item = {"field": field, "type": "mapping", "value": value}
            if entry.get("negate"):
                item["negate"] = True
            kept.append(item)
        if kept:
            groups.append({"entries": kept})
    return groups


def mapping_problem(groups: List[Dict[str, Any]]) -> str:
    """Why Kibana would refuse this mapping, in the form's words; '' when it wouldn't."""
    if not groups:
        return "Add an indicator mapping: a field of your events and the indicator index field it matches."
    for group in groups:
        if any(not e["field"] or not e["value"] for e in group["entries"]):
            return "Each indicator mapping needs both a field and an indicator index field."
        if all(e.get("negate") for e in group["entries"]):
            return "Each group of the indicator mapping needs at least one field that matches."
    return ""


def settings_problem(payload: Dict[str, Any]) -> str:
    """Why a rule's own settings (as the form posts them in its payload) can't be saved, in the form's
    words; '' when they can, or the type has none the form edits."""
    kind = payload.get("type")
    if kind not in SETTING_KEYS:
        return ""
    if payload.get("language") not in QUERY_LANGUAGES:
        return f"{'An' if kind == 'threat_match' else 'A'} {_TYPE_WORDS[kind]} rule's query is KQL or Lucene."
    if kind == "threshold":
        return threshold_problem(payload.get("threshold") or {})
    if kind == "new_terms":
        return new_terms_problem(payload.get("new_terms_fields") or [], payload.get("history_window_start") or "")
    if not payload.get("threat_index"):
        return "Give the indicator index patterns: the indexes holding your indicators, such as logs-ti_*."
    if not str(payload.get("threat_query") or "").strip():
        return "The indicator index query can't be empty. To use every indicator, query *:*."
    if payload.get("threat_language") not in QUERY_LANGUAGES:
        return "The indicator index query is KQL or Lucene."
    return mapping_problem(payload.get("threat_mapping") or [])


_TYPE_WORDS = {"threat_match": "indicator match", "threshold": "threshold", "new_terms": "new terms"}


def _count(value: Any) -> Any:
    """A whole number from the form or Kibana; anything else as it is (for the problem to name)."""
    text = str(value if value is not None else "").strip()
    return int(text) if text.isdigit() else text


def threshold_parts(raw: Any) -> Dict[str, Any]:
    """A threshold as Kibana takes it: ``{"field": [...], "value": n}``, with ``"cardinality":
    [{"field", "value"}]`` when it counts unique values. Kibana may hold one group-by field as a
    string; it is a list here."""
    raw = raw if isinstance(raw, dict) else {}
    fields = raw.get("field") or []
    fields = [fields] if isinstance(fields, str) else fields
    out: Dict[str, Any] = {"field": [str(f).strip() for f in fields if str(f).strip()], "value": _count(raw.get("value"))}
    cardinality = [{"field": str(c.get("field") or "").strip(), "value": _count(c.get("value"))}
                   for c in raw.get("cardinality") or [] if isinstance(c, dict) and (c.get("field") or c.get("value"))]
    if cardinality:
        out["cardinality"] = cardinality
    return out


def threshold_from_form(fields: str, value: str, count_field: str, count_value: str, count_rest: str) -> Dict[str, Any]:
    """The threshold the form posts: Group by (comma-separated), Threshold, and Count's field and unique
    values. ``count_rest`` holds, as JSON, any further Count settings Kibana has that the form doesn't
    show (Kibana's own form shows one): kept as they are."""
    try:
        rest = json.loads(count_rest) if (count_rest or "").strip() else []
    except ValueError:
        rest = []
    count = [{"field": count_field, "value": count_value}] if (count_field or "").strip() or (count_value or "").strip() else []
    return threshold_parts({"field": [f for f in (fields or "").split(",")], "value": value,
                            "cardinality": count + (rest if isinstance(rest, list) else [])})


def threshold_problem(threshold: Dict[str, Any]) -> str:
    if len(threshold.get("field") or []) > FIELDS_MAX:
        return f"Group by takes at most {FIELDS_MAX} fields."
    if not isinstance(threshold.get("value"), int) or threshold["value"] < 1:
        return "The threshold is a whole number, 1 or more."
    for count in threshold.get("cardinality") or []:
        if not count["field"]:
            return "Count needs a field whose unique values to count."
        if not isinstance(count["value"], int) or count["value"] < 1:
            return "Count's unique values is a whole number, 1 or more."
    return ""


def threshold_text(raw: Any) -> str:
    """A threshold on one line, for History and the rule window: "5 or more, grouped by host.name, with
    3 or more unique user.name"."""
    t = threshold_parts(raw)
    text = f"{t['value']} or more"
    if t["field"]:
        text += f", grouped by {', '.join(t['field'])}"
    for count in t.get("cardinality") or []:
        text += f", with {count['value']} or more unique {count['field']}"
    return text


def history_window(start: Any) -> str:
    """A new terms rule's history window as the form shows it: "now-7d" is "7d"."""
    text = str(start or "").strip()
    return text[4:] if text.startswith("now-") else text


def history_window_start(window: str) -> str:
    """The form's history window as Kibana takes it: "7d" (or "now-7d") is "now-7d". Anything else is
    left as it is, for new_terms_problem to refuse."""
    match = _WINDOW.match((window or "").strip())
    return f"now-{match.group(1)}{match.group(2)}" if match and int(match.group(1)) > 0 else (window or "").strip()


def new_terms_problem(fields: List[str], start: str) -> str:
    if not fields:
        return "Give the fields whose new values to alert on: one to three."
    if len(fields) > FIELDS_MAX:
        return f"A new terms rule looks at most {FIELDS_MAX} fields."
    if not re.fullmatch(r"now-[1-9]\d*[smhd]", start or ""):
        return "The history window size is a number and s, m, h or d, such as 7d."
    return ""


def mapping_lines(raw: Any) -> List[List[Tuple[str, str, str]]]:
    """The mapping for reading: groups of ``(field, "matches" | "does not match", indicator field)``."""
    return [[(e["field"], "does not match" if e.get("negate") else "matches", e["value"]) for e in g["entries"]]
            for g in mapping_groups(raw)]


def mapping_text(raw: Any) -> str:
    """The mapping on one line, for History: "a matches b and c matches d; or e matches f"."""
    groups = [" and ".join(f"{f} {op} {v}" for f, op, v in group) for group in mapping_lines(raw)]
    return "; or ".join(groups) or "-"


def filter_texts(filters: Any) -> List[str]:
    """Kibana's filter pills as text ("event.category: threat", "NOT host.name: a or b"), each named by its
    custom label when it has one; a disabled one says so."""
    out = []
    for f in filters if isinstance(filters, list) else []:
        if not isinstance(f, dict):
            continue
        meta = f.get("meta") or {}
        params = meta.get("params")
        kind = meta.get("type")
        if meta.get("alias"):
            text = str(meta["alias"])
        elif kind == "exists":
            text = f"{meta.get('key')}: exists"
        elif kind == "phrases" and isinstance(params, list):
            text = f"{meta.get('key')}: {' or '.join(str(p) for p in params)}"
        elif kind == "range" and isinstance(params, dict):
            bounds = [f"{op} {params[op]}" for op in ("gte", "gt", "lte", "lt") if params.get(op) is not None]
            text = f"{meta.get('key')}: {' and '.join(bounds)}"
        elif isinstance(params, dict) and "query" in params:
            text = f"{meta.get('key')}: {params['query']}"
        elif meta.get("key") and meta.get("value") is not None:
            text = f"{meta['key']}: {meta['value']}"
        else:
            text = json.dumps(f.get("query") or {k: v for k, v in f.items() if k not in ("meta", "$state")},
                              sort_keys=True, ensure_ascii=False)
        if meta.get("negate"):
            text = f"NOT {text}"
        if meta.get("disabled"):
            text += " (disabled)"
        out.append(text)
    return out


def window_settings(raw: Dict[str, Any]) -> Dict[str, Any]:
    """What the rule window's Rule logic shows beside the query: a threshold, new terms or indicator
    match rule's own settings, and the filters any rule has (which TIDE's form leaves as Kibana has them)."""
    raw = raw or {}
    settings: Dict[str, Any] = {"filters": filter_texts(raw.get("filters"))}
    if raw.get("type") == "threshold":
        t = threshold_parts(raw.get("threshold"))
        settings["threshold"] = {"group_by": t["field"], "value": t["value"],
                                 "counts": [(c["field"], c["value"]) for c in t.get("cardinality") or []]}
    if raw.get("type") == "new_terms":
        settings["new_terms"] = {"fields": [str(f) for f in raw.get("new_terms_fields") or []],
                                 "window": history_window(raw.get("history_window_start"))}
    if raw.get("type") == "threat_match":
        settings["indicator"] = {
            "index": [str(i) for i in raw.get("threat_index") or []],
            "query": str(raw.get("threat_query") or ""),
            "language": raw.get("threat_language") or "kuery",
            "mapping": mapping_lines(raw.get("threat_mapping")),
            "filters": filter_texts(raw.get("threat_filters")),
            "prefix": raw.get("threat_indicator_path") or INDICATOR_PREFIX_DEFAULT,
        }
    return settings
