"""Human-readable comparison of two copies of a detection rule (staging vs production).

Only fields an engineer would review are compared; Kibana bookkeeping, execution
results, TIDE scoring, generated exception-list ids and the like are ignored, and
empty values (missing / "" / [] / {}) count as equal.
"""

from __future__ import annotations

import difflib
import json
import re
from typing import Any, Dict, List, Optional

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
    ("setup", "Setup guide", "text"),
    ("investigation_fields", "Highlighted fields", "list"),
    ("schedule", "Schedule", "scalar"),
    ("type_settings", "Rule type settings", "list"),
    ("timestamp_override", "Timestamp override", "scalar"),
    ("alert_suppression", "Alert suppression", "scalar"),
    ("max_signals", "Max alerts per run", "scalar"),
    ("building_block_type", "Building block", "scalar"),
]

# The settings only some rule types have (new terms, threshold, machine learning, indicator match, EQL).
TYPE_KEYS = ("new_terms_fields", "history_window_start", "threshold", "machine_learning_job_id",
             "anomaly_threshold", "threat_index", "threat_query", "threat_mapping", "threat_indicator_path",
             "threat_language", "threat_filters", "event_category_override", "tiebreaker_field",
             "timestamp_field")

# A compared section and the rule fields it stands for, when one side's section is taken (Merge by
# section, an upstream update). A section not listed is the field of the same name.
SECTION_KEYS = {
    "schedule": ("interval", "from"),
    "type": ("type",) + TYPE_KEYS,
    "type_settings": TYPE_KEYS,
}
# Never taken from the other side: each copy keeps its own on/off state.
NOT_TAKEN = {"enabled"}
# Sections a merge can combine rather than take whole: a list's items, ticked one by one (the merged
# list is what both share and what is ticked), or a text, edited in place (``section_changes``).
ITEM_KEYS = ("index", "filters", "threat", "tags", "author", "false_positives", "references",
             "investigation_fields")
TEXT_KEYS = ("query", "description", "note", "setup")
# Kibana refuses a rule without these: an edit may not leave them empty.
_REQUIRED = ("query", "description")

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
    if key == "type_settings":
        return [f"{k}: {json.dumps(_prune(rule[k]), sort_keys=True, ensure_ascii=False)}"
                for k in TYPE_KEYS if not _empty(_prune(rule.get(k)))]
    if key == "alert_suppression":
        value = _prune(rule.get(key))
        return json.dumps(value, sort_keys=True, ensure_ascii=False) if value else None
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


# Text read as one paragraph, whose line breaks mean nothing: compared and shown unwrapped.
_PROSE = {"description"}


def _squash(text: Any) -> str:
    """``text`` with every run of whitespace made one space."""
    return " ".join(str(text).split())


def _trim_lines(text: str) -> str:
    """``text`` without trailing spaces on its lines or blank lines around it."""
    return "\n".join(line.rstrip() for line in text.strip("\n").splitlines()).strip()


def _show(value: Any) -> str:
    if _empty(value):
        return "—"
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return str(value)


# Moving a rule into a destination that already holds its rule id: these never make the two
# different rules (each destination points a rule at its own indices and turns it on or off).
CONFLICT_IGNORED = {"index", "enabled"}


def conflict_differences(ours: Dict[str, Any], theirs: Dict[str, Any]) -> List[Dict[str, Any]]:
    """``build_rule_diff`` without the fields that do not make two copies of a rule different."""
    return [d for d in build_rule_diff(ours, theirs) if d["key"] not in CONFLICT_IGNORED]


# What a rule detects: two rules alike in these raise the same alerts from the same data, whatever
# they are named, described or tagged.
DETECTION_KEYS = {"type", "language", "query", "index", "filters", "type_settings", "timestamp_override"}


def same_detection(diffs: List[Dict[str, Any]]) -> bool:
    """Whether two rules ``build_rule_diff`` compared detect the same thing (Compare with the copy)."""
    return not any(d["key"] in DETECTION_KEYS for d in diffs)


# A rule and the upstream rule it is linked to: a difference here means it may be another detection
# altogether. Index patterns and a timestamp override are each destination's own, like its name.
LINK_KEYS = DETECTION_KEYS - {"index", "timestamp_override"}


def link_differences(diffs: List[Dict[str, Any]]) -> List[str]:
    """The labels of the ``LINK_KEYS`` sections that differ ("Query", "Rule type")."""
    return [d["label"] for d in diffs if d["key"] in LINK_KEYS]


def sections_text(labels: List[str]) -> str:
    """Section labels as words in a sentence: "rule type, query language and query"."""
    words = [str(label).lower() for label in labels]
    return " and ".join([", ".join(words[:-1]), words[-1]]) if len(words) > 1 else "".join(words)


def section_changes(dest: Dict[str, Any], donor: Dict[str, Any], sections,
                    merges: Optional[Dict[str, Any]] = None) -> tuple:
    """``(changes, remove)`` that make ``dest`` take ``donor``'s value for each chosen section, for
    ``elastic_helper.apply_rule_changes``: a field the donor leaves empty is removed from ``dest``.
    Environment tags are each side's own and are kept. ``merges`` (``posted_merges``) combines a
    section instead: a list section's items both sides share plus those ticked, a text section as
    edited. One combined just as the donor has it is taken as the donor holds it."""
    import copy

    dest, donor, merges = dest or {}, donor or {}, merges or {}
    changes: Dict[str, Any] = {}
    remove: List[str] = []

    def put(key: str, value: Any) -> None:
        if _empty(value):
            if key in dest:
                remove.append(key)
        else:
            changes[key] = value

    by_hand = combined_by_hand(dest, donor, merges, sections)
    for section in sections:
        if section in NOT_TAKEN:
            continue
        if section in by_hand and section in TEXT_KEYS:
            put(section, merges[section])
            continue
        if section in by_hand and section in ITEM_KEYS:
            value = _combined(dest, donor, section, merges[section])
            if section == "tags":       # set, as when taken whole: the environment tags stay
                changes["tags"] = value
            else:
                put(section, value)
            continue
        for key in SECTION_KEYS.get(section, (section,)):
            if key == "tags":
                own_env = [t for t in dest.get("tags") or [] if str(t).lower() in _ENV_TAGS]
                changes["tags"] = [t for t in donor.get("tags") or [] if str(t).lower() not in _ENV_TAGS] + own_env
            else:
                put(key, copy.deepcopy(donor.get(key)))
    return changes, tuple(remove)


def _items(rule: Dict[str, Any], key: str) -> List[tuple]:
    """A list section's items as ``(shown, value)``: as the comparison shows it, and as the rule holds it."""
    if key == "filters":
        return [(_squash(json.dumps(p, sort_keys=True, ensure_ascii=False)), f)
                for f, p in ((f, _prune(f)) for f in rule.get("filters") or []) if not _empty(p)]
    return [(_squash(x), x) for x in _value(rule, key) or []]


def _combined(dest: Dict[str, Any], donor: Dict[str, Any], key: str, ticked) -> Any:
    """``key``'s value combined from both sides: the items both share and those ``ticked`` (as
    shown), the donor's first in its order, then ``dest``'s."""
    import copy

    mine, theirs = _items(dest, key), _items(donor, key)
    shared = {s for s, _ in mine} & {s for s, _ in theirs}
    keep = shared | set(ticked or ())
    out, seen = [], set()
    for shown, value in theirs + mine:
        if shown in keep and shown not in seen:
            seen.add(shown)
            out.append(copy.deepcopy(value))
    if key == "threat":
        return _threat_from(out, donor, dest)
    if key == "investigation_fields":
        return {**(donor.get("investigation_fields") or dest.get("investigation_fields") or {}), "field_names": out} if out else None
    if key == "tags":
        return out + [t for t in dest.get("tags") or [] if str(t).lower() in _ENV_TAGS]
    return out


def _threat_from(lines: List[str], *rules: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Kibana's ``threat`` from lines as ``_threat_lines`` makes them ("tactic › technique ›
    sub-technique"), with the tactic, technique and sub-technique objects ``rules`` hold. A
    sub-technique brings its technique, and a technique its tactic."""
    import copy

    entries, techs, subs = {}, {}, {}
    for rule in rules:
        for entry in rule.get("threat") or []:
            if not isinstance(entry, dict):
                continue
            tactic = _squash(_label(entry.get("tactic") or {}))
            entries.setdefault(tactic, entry)
            for tech in entry.get("technique") or []:
                name = _squash(_label(tech))
                techs.setdefault((tactic, name), tech)
                for sub in tech.get("subtechnique") or []:
                    subs.setdefault((tactic, name, _squash(_label(sub))), sub)
    out: Dict[str, Dict[str, Any]] = {}
    for line in lines:
        parts = [_squash(p) for p in line.split(" › ")]
        if parts[0] not in entries:
            continue
        entry = entries[parts[0]]
        made = out.setdefault(parts[0], {**{k: copy.deepcopy(v) for k, v in entry.items() if k != "technique"},
                                         "technique": []})
        if len(parts) < 2 or tuple(parts[:2]) not in techs:
            continue
        tech = next((t for t in made["technique"] if _squash(_label(t)) == parts[1]), None)
        if tech is None:
            tech = {k: copy.deepcopy(v) for k, v in techs[tuple(parts[:2])].items() if k != "subtechnique"}
            made["technique"].append(tech)
        if len(parts) > 2 and tuple(parts[:3]) in subs:
            sub = subs[tuple(parts[:3])]
            if all(_squash(_label(s)) != parts[2] for s in tech.get("subtechnique") or []):
                tech.setdefault("subtechnique", []).append(copy.deepcopy(sub))
    return list(out.values())


def posted_merges(form) -> Dict[str, Any]:
    """The combined sections a comparison's form posted (macros/rule_diff.html): ``{section: the
    ticked items, as shown}`` for a list combined item by item (``merge-items`` names it), and
    ``{section: text}`` for a text edited in place."""
    out: Dict[str, Any] = {}
    for key in form.getlist("merge-items"):
        if key in ITEM_KEYS:
            out[key] = [str(v) for v in form.getlist(f"merge-item-{key}")]
    for key in TEXT_KEYS:
        text = form.get(f"merge-text-{key}")
        if text is not None:
            out[key] = str(text).replace("\r\n", "\n")
    return out


def merge_problem(merges: Dict[str, Any], sections) -> str:
    """Why a merge can't be written, or "": an edit leaving a field Kibana requires empty."""
    labels = {key: label for key, label, _ in _FIELDS}
    for key in _REQUIRED:
        if key in sections and key in merges and not str(merges[key]).strip():
            return f"The merged {labels[key].lower()} is empty: write one, or discard the edit."
    return ""


# A rule that becomes another type takes the new query language and query with it: Kibana refuses
# the one without the others (an EQL query on a custom query rule).
TOGETHER = ("type", "language", "query")


def retyped(diffs: List[Dict[str, Any]]) -> bool:
    """Whether the two rules ``build_rule_diff`` compared are of different types (each has one)."""
    return any(d["key"] == "type" and _show(None) not in (d.get("old"), d.get("new")) for d in diffs)


def together_problem(diffs: List[Dict[str, Any]], sections) -> str:
    """Why the chosen sections can't be merged as they are, or "": when the rule type differs, its
    rule type, query language and query (those that differ) are taken together or not at all."""
    labels = {d["key"]: d["label"] for d in diffs}
    tied = [k for k in TOGETHER if k in labels]
    picked = [k for k in tied if k in sections]
    if not retyped(diffs) or not picked or len(picked) == len(tied):
        return ""
    return (f"The rule type changes, so its {sections_text([labels[k] for k in tied])} go together: "
            "tick all of them, or none.")


def taken_text(diffs: List[Dict[str, Any]], sections, by_hand) -> str:
    """The sections merged, for a message: "Tags, Highlighted fields (combined), Query (edited)"."""
    labels = {d["key"]: d["label"] for d in diffs}
    return ", ".join(labels.get(s, s) + ((" (edited)" if s in TEXT_KEYS else " (combined)") if s in by_hand else "")
                     for s in sections)


def combined_by_hand(dest: Dict[str, Any], donor: Dict[str, Any], merges: Dict[str, Any], sections) -> List[str]:
    """The chosen sections ``merges`` makes other than the donor's: combined or edited, not taken."""
    out = []
    dest, donor = dest or {}, donor or {}
    for key in sections:
        if key not in (merges or {}):
            continue
        if key in TEXT_KEYS and _trim_lines(str(merges[key])) != _trim_lines(str(donor.get(key) or "")):
            out.append(key)
        elif key in ITEM_KEYS:
            theirs = {s for s, _ in _items(donor, key)}
            if ({s for s, _ in _items(dest, key)} & theirs) | set(merges[key]) != theirs:
                out.append(key)
    return out


def build_rule_diff(staging: Dict[str, Any], production: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the reviewable differences between two rule payloads, in display order.

    Each item: ``{key, label, kind, merge}`` plus ``old``/``new`` (scalar), ``added``/``removed``
    and ``both`` (list) or ``inline`` / ``side`` rows and ``old_text``/``new_text``, each side's
    own (text). ``old`` is the staging value, ``new`` the production one. ``merge`` says how a merge
    can combine the section rather than take it whole: "items", "text" or None.
    """
    staging, production = staging or {}, production or {}
    changes: List[Dict[str, Any]] = []
    for key, label, kind in _FIELDS:
        old, new = _value(staging, key), _value(production, key)
        if _empty(old) and _empty(new):
            continue
        # Line breaks and indentation alone never make a difference (Elastic's rule files wrap
        # their text; Kibana's copies of the same rules do not).
        if kind == "list":
            old_l, new_l = [_squash(x) for x in old or []], [_squash(x) for x in new or []]
            removed = [x for x in old_l if x not in new_l]
            added = [x for x in new_l if x not in old_l]
            if removed or added:
                changes.append({"key": key, "label": label, "kind": kind, "added": added, "removed": removed,
                                "both": [x for x in old_l if x in new_l],
                                "merge": "items" if key in ITEM_KEYS else None})
        elif kind == "text":
            old_s, new_s = str(old or ""), str(new or "")
            if _squash(old_s) == _squash(new_s):
                continue
            texts = {"old_text": old_s, "new_text": new_s, "merge": "text" if key in TEXT_KEYS else None}
            if key in _PROSE:
                old_s, new_s = _squash(old_s), _squash(new_s)
            else:
                old_s, new_s = _trim_lines(old_s), _trim_lines(new_s)
            changes.append({"key": key, "label": label, "kind": kind, **_text_diff(old_s, new_s), **texts})
        elif old != new:
            changes.append({"key": key, "label": label, "kind": kind, "old": _show(old), "new": _show(new),
                            "merge": None})
    return changes
