"""Baselines made from a rule library's browser (Create baseline on the Sigma and Elastic pages).

The rules the browser lists for its filters become one baseline technique each, titled and
described as the rule is, with every ATT&CK id it carries and the rule it came from
(``playbook_steps.source_library`` / ``source_rule_id``; inventory_engine.generate_baseline_from_rules).
Deprecated rules are left out, and Sigma's unsupported ones. This module finds those rules and
words what was filtered, for the suggested name and description.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from app import sigma_helper as sigma
from app.services import elastic_rules as er

logger = logging.getLogger(__name__)

LIBRARIES = {"elastic": "Elastic", "sigma": "Sigma"}
# Generating this many techniques or more asks first: each is worked through on every system.
WARN_AT = 100

# Each filter's label, in the order a name reads them: where the rules run and what they read, the
# technique, then the rest.
_LABELS = {
    "elastic": (("platform", "Platform"), ("data_source", "Data source"), ("integration", "Integration"),
                ("technique", "MITRE technique"), ("tactic", "Tactic"), ("type", "Type"), ("severity", "Severity"),
                ("status", "Status"), ("profile", "Profile"), ("noise", "Noise")),
    "sigma": (("product", "Product"), ("category", "Category"), ("service", "Service"),
              ("technique", "MITRE technique"), ("tactic", "Tactic"), ("level", "Level"), ("status", "Status")),
}
_LEFT_OUT = {"sigma": ("deprecated", "unsupported")}
# How a name says a Profile or Noise choice that has no tag.
_NAMED = {("Profile", "None"): "No profile", ("Noise", "Not tagged"): "Noise not tagged"}


def picked(library: str, filters: Optional[Dict[str, Any]]) -> Dict[str, List[str]]:
    """``filters`` as that library's browser takes them (blanks and unknown names left out)."""
    return er.picked(filters) if library == "elastic" else sigma.picked_filters(filters)


def find(library: str, q: str = "", technique: str = "", filters: Optional[Dict[str, Any]] = None,
         conn=None) -> Tuple[List[Dict[str, Any]], int]:
    """The rules a baseline is made from, in the browser's order, as ``{rule_id, title,
    description, techniques, tactics, technique, tactic}``: ``technique`` is the one it is made for
    (main_technique) and ``tactic`` the one the rule puts that technique under. Also how many the
    browser lists that are left out (deprecated, or Sigma's unsupported). ``conn``: a connection
    that reads the reference DB."""
    if library == "elastic":
        rows, left_out = er.rules_for_baseline(conn, q, technique, filters)
        rules = []
        for r in rows:
            main = main_technique(r["techniques"] or [], technique)
            rules.append({"rule_id": r["rule_id"], "title": r["name"], "techniques": r["techniques"] or [],
                          "tactics": r["tactics"] or [], "technique": main,
                          "tactic": r["tactic_of"].get(main) or ((r["tactics"] or [""])[0]),
                          "description": _with_false_positives(r["description"], r["false_positives"])})
        return rules, left_out
    listed = sigma.search_rules(query=q, technique_filter=technique, filters=filters, limit=0)
    kept = [r for r in listed if str(r.get("status") or "").strip().lower() not in _LEFT_OUT["sigma"]]
    attack = _attack_tactics(conn) if conn is not None else {}
    rules = []
    for r in kept:
        techniques, tactics = r.get("_techniques") or [], r.get("_tactics") or []
        main = main_technique(techniques, technique)
        rules.append({"rule_id": str(r.get("id") or ""), "title": r.get("title") or "", "techniques": techniques,
                      "tactics": tactics, "technique": main, "tactic": _sigma_tactic(main, tactics, attack),
                      "description": _with_false_positives(r.get("description"), r.get("falsepositives"))})
    return rules, len(listed) - len(kept)


def main_technique(techniques: List[str], wanted: str = "") -> str:
    """The ATT&CK id a rule's technique is made for: of those matching the browser's technique
    filter (which matches ids starting with it: T1059 finds T1059.001), the first sub-technique,
    else the first; with no filter, the first sub-technique the rule carries, else its first id."""
    ids = [str(t).strip().upper() for t in techniques if str(t).strip()]
    want = re.sub(r"[^A-Z0-9.]", "", (wanted or "").strip().upper())
    if want and want[0].isdigit():
        want = "T" + want
    pool = [t for t in ids if t.startswith(want)] if want else []
    pool = pool or ids
    return next((t for t in pool if "." in t), pool[0] if pool else "")


def _sigma_tactic(technique: str, tactics: List[str], attack: Dict[str, List[str]]) -> str:
    """The tactic a Sigma rule's main technique sits under: of the rule's own tactics, the first
    ATT&CK puts that technique under (Sigma's tags don't pair them), else the rule's first tactic,
    else ATT&CK's first for the technique."""
    from app.attack_tactics import ID_BY_NAME, tactic_name

    under = {ID_BY_NAME.get(tactic_name(t) or t) for t in attack.get(technique, [])}
    own = next((t for t in tactics if ID_BY_NAME.get(tactic_name(t) or t) in under), "")
    return own or (tactics[0] if tactics else (attack.get(technique) or [""])[0])


def _attack_tactics(conn) -> Dict[str, List[str]]:
    """{enterprise technique id: the tactics ATT&CK puts it under} from the reference DB."""
    rows = conn.execute(
        "SELECT upper(tt.technique_id), list(ta.name ORDER BY ta.name) FROM mitre_technique_tactics tt "
        "JOIN mitre_tactics ta ON ta.tactic_id = tt.tactic_id AND ta.domain = tt.domain "
        "WHERE tt.domain = 'enterprise' GROUP BY 1").fetchall()
    return {tid: list(names) for tid, names in rows}


def _with_false_positives(description: Any, false_positives: Any) -> str:
    text = str(description or "").strip()
    fps = [str(f).strip() for f in (false_positives if isinstance(false_positives, list) else [false_positives] if false_positives else [])
           if str(f).strip()]
    if not fps:
        return text
    return "\n\n".join(p for p in (text, f"False positives: {'; '.join(fps)}") if p)


def summary(library: str, q: str, technique: str, filters: Dict[str, List[str]],
            value_labels: Optional[Dict[str, Dict[str, str]]] = None) -> List[Tuple[str, List[str]]]:
    """(label, chosen values as the browser shows them) for each filter in use, the technique and
    the search, in _LABELS' order. ``value_labels``: {filter: {value: label}} where a value isn't
    its own label (Elastic's tag filters, lower case)."""
    labels = value_labels or {}
    out: List[Tuple[str, List[str]]] = []
    for name, label in _LABELS[library]:
        if name == "technique":
            if technique.strip():
                out.append((label, [technique.strip().upper()]))
            continue
        values = filters.get(name) or []
        if values:
            out.append((label, [_label(library, name, v, labels.get(name, {})) for v in values]))
    if q.strip():
        out.append(("Search", [f"“{q.strip()}”"]))
    return out


def _label(library: str, name: str, value: str, labels: Dict[str, str]) -> str:
    if value in labels:
        return labels[value]
    if name in ("platform", "product"):
        return value.replace("_", " ").title()
    if name == "status" and library == "elastic":
        return dict(er.STATUSES).get(value, value)
    if name in ("severity", "level", "status", "type"):
        return value.replace("_", " ").capitalize()
    return value


def suggested_name(library: str, parts: List[Tuple[str, List[str]]]) -> str:
    """A name from what was filtered, in summary's order: "Windows · PowerShell Logs · T1059.001 ·
    High · Production (Elastic)". A value already named is left out (Platform and Integration both
    "windows"), Profile and Noise say which they are ("Low noise"), and a filter with more than
    three choices is shortened."""
    seen, words = set(), []
    for label, values in parts:
        values = [_NAMED.get((label, v), f"{v} {label.lower()}" if label in ("Profile", "Noise") else v) for v in values]
        values = [v for v in values if v.lower() not in seen]
        seen.update(v.lower() for v in values)
        if values:
            words.append(" / ".join(values) if len(values) <= 3 else f"{' / '.join(values[:2])} +{len(values) - 2}")
    name = " · ".join(words) if words else "All rules"
    return f"{name[:150]} ({LIBRARIES[library]})"


def suggested_description(library: str, parts: List[Tuple[str, List[str]]]) -> str:
    what = "; ".join(f"{label}: {', '.join(values)}" for label, values in parts)
    return (f"One technique per {LIBRARIES[library]} rule matching {what}." if what
            else f"One technique per {LIBRARIES[library]} rule.")


def made_from(step, mapped: set, client_id: str) -> Optional[Dict[str, Any]]:
    """The library rule a technique was made from, for its window on a system: its name, where it
    opens on its library page, why it can't be deployed any more (``gone``: deprecated or removed
    upstream; '' when it can), and its copies in this client's linked destinations, each with
    ``mapped`` (one of ``mapped``'s ``(rule_id, siem_id, space)``: mapped to this technique). None
    for a technique not made from one. Never raises: the window still opens."""
    from app.services import rule_origins
    from app.services.database import get_database_service

    library, rule_id = getattr(step, "source_library", ""), getattr(step, "source_rule_id", "")
    if library not in LIBRARIES or not rule_id:
        return None
    db = get_database_service()
    name, gone = "", ""
    try:
        if library == "elastic":
            with db.get_shared_connection() as conn:
                rule = er.get_rule(conn, rule_id) if er.index_ready(conn) else None
            name = (rule or {}).get("name") or ""
            gone = ("Elastic no longer has this rule." if not rule
                    else "Elastic has deprecated this rule." if rule.get("status") == "deprecated" else "")
        else:
            rule = sigma.get_rule_by_id(rule_id)
            status = str((rule or {}).get("status") or "").strip().lower()
            name = (rule or {}).get("title") or ""
            gone = ("SigmaHQ no longer has this rule." if not rule
                    else f"SigmaHQ marks this rule {status}." if status in _LEFT_OUT["sigma"] else "")
    except Exception:
        logger.exception("Could not read %s rule %s", library, rule_id)
    siems = {(s["id"], str(s.get("space") or "default")): s for s in db.get_client_siems(client_id) or []}
    copies = []
    for c in rule_origins.deployed_for_client(db, client_id, library, rule_id):
        dest = (c["siem_id"], str(c.get("space") or "default"))
        if dest in siems:
            copies.append({**c, "space": dest[1], "color": siems[dest].get("color"),
                           "mapped": (c["rule_id"], *dest) in mapped})
    return {"library": library, "label": LIBRARIES[library], "rule_id": rule_id, "name": name or step.title,
            "url": f"/{library}?rule={quote(rule_id)}", "gone": gone, "copies": copies}


def elastic_value_labels(conn) -> Dict[str, Dict[str, str]]:
    """{filter: {value: label}} for Elastic's tag filters, whose values are lower case."""
    facets = er.rule_facets(conn)
    return {"data_source": dict(facets["data_sources"]), "profile": dict(facets["profiles"]),
            "noise": dict(facets["noise"])}
