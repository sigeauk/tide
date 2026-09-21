"""Human-readable comparison of two copies of a detection rule (staging vs production).

Only fields an engineer would review are compared; Kibana bookkeeping, execution
results, TIDE scoring, generated exception-list ids and the like are ignored, and
empty values (missing / "" / [] / {}) count as equal.
"""

from __future__ import annotations

import difflib
import json
import re
from typing import Any, Dict, List

# Promotion strips these environment tags, so they never count as a difference.
_ENV_TAGS = {"test", "staging", "production"}

# (key, label, kind) per compared field, in display order.
_FIELDS = [
    ("name", "Name", "scalar"),
    ("description", "Description", "text"),
    ("severity", "Severity", "scalar"),
    ("risk_score", "Risk score", "scalar"),
    ("enabled", "Enabled", "scalar"),
    ("type", "Rule type", "scalar"),
    ("language", "Query language", "scalar"),
    ("query", "Query", "text"),
    ("index", "Index patterns", "list"),
    ("filters", "Filters", "list"),
    ("threat", "MITRE ATT&CK", "list"),
    ("tags", "Tags", "list"),
    ("author", "Author", "list"),
    ("false_positives", "False positives", "list"),
    ("references", "References", "list"),
    ("note", "Investigation guide", "text"),
    ("investigation_fields", "Highlighted fields", "list"),
    ("schedule", "Schedule", "scalar"),
]

_CONTEXT = 2  # unchanged lines kept around a changed line in text diffs


def _empty(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _label(item: Dict[str, Any]) -> str:
    return " ".join(p for p in (item.get("id"), item.get("name")) if p)


def _prune(value: Any) -> Any:
    """Drop None / "" / empty containers recursively (Kibana pads filters with them)."""
    if isinstance(value, dict):
        pruned = {k: _prune(v) for k, v in value.items()}
        return {k: v for k, v in pruned.items() if not _empty(v)}
    if isinstance(value, list):
        return [v for v in (_prune(v) for v in value) if not _empty(v)]
    return value


def _threat_lines(threat: Any) -> List[str]:
    lines: List[str] = []
    for entry in threat if isinstance(threat, list) else []:
        if not isinstance(entry, dict):
            continue
        tactic = _label(entry.get("tactic") or {})
        techniques = entry.get("technique") or []
        if not techniques and tactic:
            lines.append(tactic)
        for tech in techniques:
            path = [p for p in (tactic, _label(tech)) if p]
            lines.append(" › ".join(path))
            for sub in tech.get("subtechnique") or []:
                lines.append(" › ".join(path + [_label(sub)]))
    return lines


def _value(rule: Dict[str, Any], key: str) -> Any:
    if key == "threat":
        return _threat_lines(rule.get("threat"))
    if key == "tags":
        return [t for t in (rule.get("tags") or []) if str(t).lower() not in _ENV_TAGS]
    if key == "filters":
        return [json.dumps(f, sort_keys=True, ensure_ascii=False) for f in _prune(rule.get("filters") or [])]
    if key == "investigation_fields":
        return list((rule.get("investigation_fields") or {}).get("field_names") or [])
    if key == "schedule":
        parts = []
        if rule.get("interval"):
            parts.append(f"every {rule['interval']}")
        if rule.get("from"):
            parts.append(f"looking back to {rule['from']}")
        return ", ".join(parts)
    value = rule.get(key)
    return [str(v) for v in value] if isinstance(value, list) else value


def _words(text: str) -> List[str]:
    return re.findall(r"\s+|\S+", text)


def _inline(old: str, new: str) -> tuple:
    """Word-level segments for a changed line pair: ([(text, changed)], [(text, changed)])."""
    a, b = _words(old), _words(new)
    old_segs, new_segs = [], []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == "equal":
            old_segs.append(("".join(a[i1:i2]), False))
            new_segs.append(("".join(b[j1:j2]), False))
        else:
            if i2 > i1:
                old_segs.append(("".join(a[i1:i2]), True))
            if j2 > j1:
                new_segs.append(("".join(b[j1:j2]), True))
    return old_segs, new_segs


def _gap(count: int) -> Dict[str, Any]:
    return {"type": "gap", "segments": [(f"{count} unchanged line{'s' if count != 1 else ''}", False)]}


def _collapse(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Keep a little context around changed rows and replace long unchanged runs with a gap marker."""
    keep = [False] * len(rows)
    for idx, row in enumerate(rows):
        if row["type"] != "same":
            for k in range(max(0, idx - _CONTEXT), min(len(rows), idx + _CONTEXT + 1)):
                keep[k] = True
    out: List[Dict[str, Any]] = []
    skipped = 0
    for idx, row in enumerate(rows):
        if keep[idx]:
            if skipped:
                out.append(_gap(skipped))
                skipped = 0
            out.append(row)
        else:
            skipped += 1
    if skipped:
        out.append(_gap(skipped))
    return out


def _text_diff(old: str, new: str) -> Dict[str, List[Dict[str, Any]]]:
    """Line diff (staging -> production) as ``{"inline": rows, "side": rows}`` with word highlights.

    Inline rows: ``{type: same|del|add|gap, segments}``. Side rows: ``{type: same|change|gap,
    left, right}`` where left/right are segment lists (or None when that side has no line).
    """
    a, b = (old or "").splitlines(), (new or "").splitlines()
    inline: List[Dict[str, Any]] = []
    side: List[Dict[str, Any]] = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == "equal":
            for line in a[i1:i2]:
                inline.append({"type": "same", "segments": [(line, False)]})
                side.append({"type": "same", "left": [(line, False)], "right": [(line, False)]})
            continue
        olds, news = a[i1:i2], b[j1:j2]
        paired = min(len(olds), len(news))
        pairs = [_inline(olds[k], news[k]) for k in range(paired)]
        left = [p[0] for p in pairs] + [[(line, True)] for line in olds[paired:]]
        right = [p[1] for p in pairs] + [[(line, True)] for line in news[paired:]]
        inline.extend({"type": "del", "segments": segs} for segs in left)
        inline.extend({"type": "add", "segments": segs} for segs in right)
        for k in range(max(len(left), len(right))):
            side.append({
                "type": "change",
                "left": left[k] if k < len(left) else None,
                "right": right[k] if k < len(right) else None,
            })
    return {"inline": _collapse(inline), "side": _collapse(side)}


def _show(value: Any) -> str:
    if _empty(value):
        return "—"
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return str(value)


def build_rule_diff(staging: Dict[str, Any], production: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the reviewable differences between two rule payloads, in display order.

    Each item: ``{key, label, kind}`` plus ``old``/``new`` (scalar), ``added``/``removed``
    (list) or ``inline`` / ``side`` rows (text). ``old`` is the staging value, ``new`` the production one.
    """
    staging, production = staging or {}, production or {}
    changes: List[Dict[str, Any]] = []
    for key, label, kind in _FIELDS:
        old, new = _value(staging, key), _value(production, key)
        if _empty(old) and _empty(new):
            continue
        if kind == "list":
            old_l, new_l = list(old or []), list(new or [])
            removed = [x for x in old_l if x not in new_l]
            added = [x for x in new_l if x not in old_l]
            if removed or added:
                changes.append({"key": key, "label": label, "kind": kind, "added": added, "removed": removed})
        elif kind == "text":
            old_s, new_s = str(old or "").strip(), str(new or "").strip()
            if old_s != new_s:
                changes.append({"key": key, "label": label, "kind": kind, **_text_diff(old_s, new_s)})
        elif old != new:
            changes.append({"key": key, "label": label, "kind": kind, "old": _show(old), "new": _show(new)})
    return changes
