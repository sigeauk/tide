"""MITRE ATT&CK catalogue pages: one card/table grid and one window for every kind of object.

A kind (groups, software, ...) is a ``KindSpec``: how to list its rows as grid items, what the
table shows, how it sorts, filters and groups, and what the metric strip counts. ``grid()``
applies the filter bar to a kind's items and either pages them (infinite scroll) or groups them
(each group's items fetched when it is opened), so a page never renders the whole catalogue.

Also home to the helpers every MITRE page shares (source filter, the active client's coverage,
detail lookup with fallback to another source), moved out of ``app.main``.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urlencode

logger = logging.getLogger(__name__)

# ── Sources ──────────────────────────────────────────────────────────────────

SOURCE_META: Dict[str, Dict[str, str]] = {
    "all": {"label": "All MITRE ATT&CK Sources", "code": "ALL", "pill_class": "src-opencti"},
    "enterprise": {"label": "MITRE ATT&CK Enterprise", "code": "ENT", "pill_class": "src-enterprise"},
    "mobile": {"label": "MITRE ATT&CK Mobile", "code": "MOB", "pill_class": "src-mobile"},
    "ics": {"label": "MITRE ATT&CK ICS", "code": "ICS", "pill_class": "src-ics"},
    "pre": {"label": "MITRE ATT&CK PRE", "code": "PRE", "pill_class": "src-pre"},
}
SOURCE_ORDER = ["enterprise", "ics", "mobile", "pre"]
SOURCE_OPTIONS = [("all", "All"), ("enterprise", "Enterprise"), ("mobile", "Mobile"), ("ics", "ICS"), ("pre", "PRE")]


def resolve_source(src: str) -> Tuple[str, Dict[str, str]]:
    key = (src or "all").strip().lower()
    if key not in SOURCE_META:
        key = "all"
    return key, SOURCE_META[key]


def source_context(src: str) -> Dict[str, Any]:
    key, meta = resolve_source(src)
    return {
        "source_domain": key,
        "source_label": meta["label"],
        "source_code": meta["code"],
        "source_pill_class": meta["pill_class"],
        "source_meta": SOURCE_META,
        "source_order": SOURCE_ORDER,
        "source_options": SOURCE_OPTIONS,
    }


def active_client_for(request, user, db) -> str:
    """The client whose rules decide coverage: the active-client cookie, else the user's default
    client, else the default client."""
    cid = request.cookies.get("active_client_id")
    if not cid and user:
        with db.get_shared_connection() as conn:
            row = conn.execute(
                "SELECT client_id FROM user_clients WHERE user_id = ? AND is_default = true LIMIT 1",
                [user.id],
            ).fetchone()
            if row:
                cid = row[0]
    return cid or db.get_default_client_id()


def coverage_for(db, cid: Optional[str]) -> Tuple[set, dict]:
    """(technique ids the client's enabled rules cover, rules per technique id). Empty when the
    client's rules cannot be read, so a page still renders."""
    try:
        from app.services.tenant_manager import tenant_context_for
        if cid:
            with tenant_context_for(cid):
                return db.get_all_covered_ttps(client_id=cid), db.get_ttp_rule_counts(client_id=cid)
        return db.get_all_covered_ttps(client_id=cid), db.get_ttp_rule_counts(client_id=cid)
    except Exception:
        return set(), {}


_DETAIL_GETTERS = {
    "tactic": "get_mitre_tactic_detail",
    "technique": "get_mitre_technique_detail",
    "group": "get_mitre_group_detail",
    "software": "get_mitre_software_detail",
    "campaign": "get_mitre_campaign_detail",
    "mitigation": "get_mitre_mitigation_detail",
}


def resolve_detail(db, kind: str, object_id: str, src: str) -> Tuple[str, Optional[dict]]:
    """(source it was found in, detail) -- ``src`` first, then the other sources, so a link from
    one domain to an object that only exists in another still opens it."""
    name = _DETAIL_GETTERS.get(kind)
    if not name:
        return src, None
    getter = getattr(db, name)
    detail = getter(object_id, domain=src)
    if detail:
        return src, detail
    for candidate in ("enterprise", "mobile", "ics", "pre"):
        if candidate != src:
            detail = getter(object_id, domain=candidate)
            if detail:
                return candidate, detail
    return src, None


# ── Item helpers ─────────────────────────────────────────────────────────────

_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_TAG = re.compile(r"<[^>]+>")


def plain_summary(text: Optional[str], limit: int = 240) -> str:
    """A card's one-paragraph summary: ATT&CK markdown without citations, links or tags."""
    t = _CITATION.sub("", text or "")
    t = _MD_LINK.sub(r"\1", t)
    t = _TAG.sub("", t).replace("`", "")
    t = " ".join(t.split())
    if len(t) <= limit:
        return t
    return t[:limit].rsplit(" ", 1)[0] + "…"


def coverage_of(technique_ids: set, covered: set) -> Optional[Dict[str, Any]]:
    """How many of ``technique_ids`` the client's enabled rules cover. None when there are none
    to cover (a check that cannot be judged is not applicable, never zero)."""
    total = len(technique_ids)
    if not total:
        return None
    n = len(technique_ids & covered)
    level = "full" if n == total else ("none" if n == 0 else "partial")
    return {"covered": n, "total": total, "pct": round(100 * n / total), "level": level}


COVERAGE_LEVELS = {"full": "Fully covered", "partial": "Partly covered", "none": "Not covered", "na": "No techniques"}


def _coverage_key(item: dict) -> str:
    return item["coverage"]["level"] if item.get("coverage") else "na"


def dom_id(kind: str, object_id: str) -> str:
    """The card/row id, and the window's data-rule-dom-id (how prev/next finds its place).
    Slugged: ATT&CK ids carry dots (T1059.001) and the id can end up in a CSS selector."""
    return f"mitre-{kind}-" + re.sub(r"[^A-Za-z0-9_-]", "_", object_id or "")


def window_url(kind: str, object_id: str, domain: str) -> str:
    return f"/api/mitre/window/{kind}/{object_id}?{urlencode({'src': domain})}"


_CACHE: Dict[Tuple, Tuple[float, Any]] = {}
_CACHE_TTL = 300


def _cached(key: Tuple, load: Callable[[], Any]) -> Any:
    """ATT&CK reference data only changes on an import, so a page's reads of it are kept for a few
    minutes instead of being queried again for every scroll, filter and group."""
    hit = _CACHE.get(key)
    if hit and time.monotonic() - hit[0] < _CACHE_TTL:
        return hit[1]
    value = load()
    _CACHE[key] = (time.monotonic(), value)
    return value


# ── Kinds ────────────────────────────────────────────────────────────────────

@dataclass
class Filter:
    label: str
    # (value, label), "" = any; or (db, domain) -> that list, for options that depend on the source.
    options: Union[List[Tuple[str, str]], Callable[[Any, str], List[Tuple[str, str]]]]
    match: Callable[[dict, str], bool]

    @property
    def by_source(self) -> bool:
        return callable(self.options)

    def options_for(self, db, domain: str) -> List[Tuple[str, str]]:
        return self.options(db, domain) if callable(self.options) else self.options


@dataclass
class KindSpec:
    key: str                                          # URL segment: /mitre/<key>
    title: str
    subtitle: str
    singular: str
    detail_kind: str                                  # resolve_detail's kind
    active_sub: str
    load: Callable[..., List[dict]]                   # (db, search, domain, covered, counts) -> items
    sorts: Dict[str, Tuple[str, str, Callable[[dict], Any]]]   # key -> (label, default dir, sort key)
    default_sort: str
    columns: List[Tuple[str, str, Optional[str]]]     # (cell key, header, sort key)
    metrics: Callable[[List[dict]], List[dict]]
    window_body: str
    filters: Dict[str, Filter] = field(default_factory=dict)
    # group key -> (label, item -> (group value, group label, order)), or a list of those for an
    # item that belongs to several groups (a technique under two tactics is listed under both).
    groupings: Dict[str, Tuple[str, Callable[[dict], Any]]] = field(default_factory=dict)
    # (db, client_id, detail, covered, counts) -> extra window context
    window_context: Callable[..., dict] = lambda db, client_id, detail, covered, counts: {}


def _technique_ids(db, kind: str, domain: str) -> Dict[str, set]:
    """{object id: its technique ids} for a kind of object (get_mitre_technique_ids_by)."""
    return _cached(("technique_ids", kind, domain), lambda: db.get_mitre_technique_ids_by(kind, domain))


def _plural(n: int, word: str, plural: Optional[str] = None) -> str:
    return f"{n} {word if n == 1 else (plural or word + 's')}"


def _coverage_metrics(items: List[dict], first: dict, second: dict, avg_sub: str) -> List[dict]:
    """The metric strip of a kind scored by coverage_of: its own first two cards, then fully,
    partly and not covered, then the average coverage of those with techniques to cover."""
    levels = {k: 0 for k in COVERAGE_LEVELS}
    for it in items:
        levels[_coverage_key(it)] += 1
    scored = [it["coverage"]["pct"] for it in items if it.get("coverage")]
    avg = round(sum(scored) / len(scored)) if scored else None
    return [
        first,
        second,
        {"value": levels["full"], "label": "Fully covered", "sub": "Every technique has a rule", "icon": "shield-check", "tone": "success" if levels["full"] else ""},
        {"value": levels["partial"], "label": "Partly covered", "sub": "Some techniques have rules", "icon": "shield", "tone": "warning" if levels["partial"] else ""},
        {"value": levels["none"], "label": "Not covered", "sub": "No technique has a rule", "icon": "shield-off", "tone": "danger" if levels["none"] else ""},
        {"value": f"{avg}%" if avg is not None else "—", "label": "Average coverage", "sub": avg_sub, "icon": "target"},
    ]


def _groups_load(db, search, domain, covered, counts) -> List[dict]:
    rows = db.list_mitre_groups(search=search or None, domain=domain)
    tech_ids = _technique_ids(db, "group", domain)
    items = []
    for r in rows:
        gid = (r["id"] or "").upper()
        aliases = [a.strip() for a in (r.get("aliases") or "").split(",") if a.strip() and a.strip() != r["name"]]
        cov = coverage_of(tech_ids.get(gid, set()), covered)
        items.append({
            "id": r["id"],
            "dom_id": dom_id("groups", r["id"]),
            "window_url": window_url("groups", r["id"], domain),
            "name": r["name"],
            "sub": ", ".join(aliases),
            "summary": plain_summary(r.get("description")),
            "sources": r.get("sources") or [],
            "coverage": cov,
            "technique_count": r["technique_count"],
            "associated_count": r["associated_count"],
            "meta": [
                ("crosshair", f"{r['technique_count']} technique{'s' if r['technique_count'] != 1 else ''}", "ATT&CK techniques this group uses"),
            ] + ([("users", f"{r['associated_count']} related", "Associated groups")] if r["associated_count"] else []),
        })
    return items


def _groups_metrics(items: List[dict]) -> List[dict]:
    using = sum(1 for it in items if it.get("coverage"))
    return _coverage_metrics(
        items,
        {"value": len(items), "label": "Groups", "sub": "Matching the filters", "icon": "users"},
        {"value": using, "label": "Using techniques", "sub": "With ATT&CK techniques", "icon": "crosshair"},
        "Across groups using techniques",
    )


def _technique_set_window(db, client_id, detail: dict, covered: set, counts: dict) -> dict:
    """The window of an object scored by coverage_of (a group, software, campaign, mitigation)."""
    ids = {(t.get("id") or "").upper() for t in detail.get("techniques") or [] if t.get("id")}
    return {"coverage": coverage_of(ids, covered), "uncovered_count": len(ids - covered)}


def _coverage_filter() -> Filter:
    return Filter(
        "Coverage",
        [("", "Any"), ("none", "Not covered"), ("partial", "Partly covered"), ("full", "Fully covered"), ("na", "No techniques")],
        lambda item, v: _coverage_key(item) == v,
    )


def _coverage_grouping() -> Tuple[str, Callable[[dict], Tuple[str, str, Any]]]:
    order = {"none": 0, "partial": 1, "full": 2, "na": 3}
    return ("Coverage", lambda it: (_coverage_key(it), COVERAGE_LEVELS[_coverage_key(it)], order[_coverage_key(it)]))


def _coverage_sort(it: dict) -> Tuple:
    c = it.get("coverage")
    # Least covered first; groups with nothing to cover last.
    return (1, 0, "") if not c else (0, c["pct"], it["id"])


# ── Techniques ───────────────────────────────────────────────────────────────

def _tactics(db, domain: str) -> List[dict]:
    """The domain's tactics in kill-chain order."""
    return _cached(("tactics", domain), lambda: db.list_mitre_tactics(domain=domain))


def _tactic_index(db, domain: str) -> Dict[str, Tuple[str, str, int]]:
    """Tactic shortname -> (id, name, kill-chain order), how a technique row names its tactics."""
    index: Dict[str, Tuple[str, str, int]] = {}
    for i, t in enumerate(_tactics(db, domain)):
        index.setdefault(t["shortname"], (t["id"], t["name"], i))
    return index


def _row_tactics(row: dict, index: Dict[str, Tuple[str, str, int]]) -> List[Tuple[str, str, int]]:
    return [index[s.strip()] for s in (row["tactic"] or "").split(",") if s.strip() in index]


def _tactic_options(db, domain: str) -> List[Tuple[str, str]]:
    opts = [("", "Any")]
    for t in _tactics(db, domain):
        codes = "/".join(SOURCE_META.get(s, {}).get("code", s.upper()) for s in t.get("sources") or [])
        opts.append((t["id"], f"{t['name']} ({codes})" if domain == "all" and codes else t["name"]))
    return opts


def technique_coverage(tid: str, subs: List[str], covered: set, counts: dict) -> Dict[str, Any]:
    """A technique is covered when an enabled rule carries its own id. One that is not, but has a
    covered sub-technique, is partly covered: those rules see some ways of doing it, not all."""
    n = counts.get(tid, 0)
    if tid in covered:
        return {"level": "full", "rank": 2, "label": f"{n} rule{'s' if n != 1 else ''}",
                "title": f"{n} enabled rule{'s carry' if n != 1 else ' carries'} {tid}"}
    sub_hit = [s for s in subs if s in covered]
    if sub_hit:
        return {"level": "partial", "rank": 1, "label": f"{len(sub_hit)}/{len(subs)} sub-techniques",
                "title": f"No enabled rule carries {tid} itself; {len(sub_hit)} of its {len(subs)} sub-techniques are covered"}
    return {"level": "none", "rank": 0, "label": "No rule", "title": f"No enabled rule carries {tid}"}


def _technique_rows(db, domain: str) -> List[dict]:
    return _cached(("techniques", domain), lambda: db.list_mitre_techniques(domain=domain))


def _matches(row: dict, needle: str) -> int:
    """Search rank (lower is better), or -1 for no match: id, then name, then description."""
    rid = (row["id"] or "").lower()
    if rid == needle:
        return 0
    if rid.startswith(needle):
        return 1
    if needle in (row["name"] or "").lower():
        return 2
    if needle in (row["description"] or "").lower():
        return 3
    return -1


def _techniques_load(db, search, domain, covered, counts) -> List[dict]:
    rows = _technique_rows(db, domain)
    by_id = {(r["id"] or "").upper(): r for r in rows}
    children: Dict[str, List[str]] = {}
    for r in rows:
        if r["is_subtechnique"] and r["parent_id"]:
            children.setdefault(r["parent_id"].upper(), []).append(r["id"].upper())
    tactic_by_short = _tactic_index(db, domain)

    if search:
        needle = search.strip().lower()
        picked = sorted((r for r in rows if _matches(r, needle) >= 0), key=lambda r: (_matches(r, needle), r["id"]))
        # A matching sub-technique brings its parent along, for context.
        present = {r["id"].upper() for r in picked}
        for r in list(picked):
            pid = (r["parent_id"] or "").upper()
            if pid and pid not in present and pid in by_id:
                picked.append(by_id[pid])
                present.add(pid)
        rows = picked

    items = []
    for r in rows:
        tid = (r["id"] or "").upper()
        tactics = _row_tactics(r, tactic_by_short)
        parent = by_id.get((r["parent_id"] or "").upper()) if r["is_subtechnique"] else None
        subs = children.get(tid, [])
        meta = []
        if parent:
            meta.append(("git-branch", f"Sub-technique of {parent['id']}", parent["name"]))
        elif subs:
            meta.append(("git-branch", f"{len(subs)} sub-technique{'s' if len(subs) != 1 else ''}", "Sub-techniques"))
        meta.append(("users", f"{r['group_count']} group{'s' if r['group_count'] != 1 else ''}", "Groups known to use it"))
        meta.append(("shield", f"{r['mitigation_count']} mitigation{'s' if r['mitigation_count'] != 1 else ''}", "ATT&CK mitigations"))
        items.append({
            "id": r["id"],
            "dom_id": dom_id("technique", r["id"]),
            "window_url": window_url("technique", r["id"], domain),
            "name": r["name"],
            "sub": ", ".join(name for _, name, _ in tactics),
            "summary": plain_summary(r.get("description")),
            "sources": r.get("sources") or [],
            "coverage": technique_coverage(tid, subs, covered, counts),
            "is_sub": r["is_subtechnique"],
            "parent_id": parent["id"] if parent else "",
            "parent_name": parent["name"] if parent else "",
            "tactics": tactics,
            "tactic_ids": {t[0] for t in tactics},
            "type_label": "Sub-technique" if r["is_subtechnique"] else "Technique",
            "group_count": r["group_count"],
            "mitigation_count": r["mitigation_count"],
            "rule_count": counts.get(tid, 0),
            "meta": meta,
        })
    return items


def _techniques_metrics(items: List[dict]) -> List[dict]:
    levels = {"full": 0, "partial": 0, "none": 0}
    for it in items:
        levels[it["coverage"]["level"]] += 1
    subs = sum(1 for it in items if it["is_sub"])
    used_gaps = sum(1 for it in items if it["coverage"]["level"] != "full" and it["group_count"])
    pct = round(100 * levels["full"] / len(items)) if items else None
    return [
        {"value": len(items), "label": "Techniques", "sub": f"{len(items) - subs} techniques, {subs} sub-techniques", "icon": "crosshair"},
        {"value": levels["full"], "label": "Covered", "sub": "An enabled rule carries the id", "icon": "shield-check", "tone": "success" if levels["full"] else ""},
        {"value": levels["partial"], "label": "Through sub-techniques", "sub": "Only some sub-techniques have rules", "icon": "shield", "tone": "warning" if levels["partial"] else ""},
        {"value": levels["none"], "label": "Not covered", "sub": "No enabled rule", "icon": "shield-off", "tone": "danger" if levels["none"] else ""},
        {"value": used_gaps, "label": "Gaps groups use", "sub": "Not fully covered, used by a known group", "icon": "users", "tone": "danger" if used_gaps else ""},
        {"value": f"{pct}%" if pct is not None else "—", "label": "Coverage", "sub": "Of the techniques shown", "icon": "target"},
    ]


def _rule_cards(db, client_id, rules) -> List[dict]:
    """The client's rules as the baseline technique window shows them (window_ui.html: rule_card),
    each at its own (SIEM, space) destination, its ring the rule's own score."""
    from app.inventory_engine import own_score_evidence, rule_card
    dests = {}
    try:
        for d in (db.get_client_siems(client_id) or [] if client_id else []):
            dests[(d.get("id"), d.get("space") or "default")] = {
                "name": d.get("name") or d.get("label") or d.get("space"), "color": d.get("color"),
            }
    except Exception:
        logger.warning("Destination lookup failed for the MITRE technique window", exc_info=True)
    cards = []
    for r in rules:
        card = {
            **rule_card(r, dests.get((r.siem_id, r.space or "default"))),
            "name": r.name, "rule_id": r.rule_id, "siem_id": r.siem_id, "space": r.space, "source": "siem",
        }
        card["evidence"] = own_score_evidence(card)
        cards.append(card)
    return cards


RULES_SHOWN = 50


def technique_rules(db, client_id, tid: str) -> list:
    """The client's rules carrying a technique id, enabled first, then strongest."""
    try:
        rules = db.get_rules_for_technique(tid, enabled_only=False, client_id=client_id)
    except Exception:
        logger.warning("Rules for %s could not be read for the technique window", tid, exc_info=True)
        rules = []
    return sorted(rules, key=lambda r: (not r.enabled, -(r.score or 0), (r.name or "").lower()))


def technique_rule_cards(db, client_id, tid: str, rules: list, offset: int = 0) -> Dict[str, Any]:
    """One batch of Your rules (partials/mitre_rule_cards.html): up to RULES_SHOWN cards from
    ``offset`` on, and where the rest load from."""
    batch = rules[offset:offset + RULES_SHOWN] if offset == 0 else rules[offset:]
    nxt = offset + len(batch)
    return {
        "rule_cards": _rule_cards(db, client_id, batch),
        "rules_total": len(rules),
        "rules_more_url": f"/api/mitre/window/technique/{tid}/rules?offset={nxt}" if nxt < len(rules) else "",
    }


def _techniques_window(db, client_id, detail: dict, covered: set, counts: dict) -> dict:
    tid = (detail.get("id") or "").upper()
    subs = [(s.get("id") or "").upper() for s in detail.get("subtechniques") or []]
    rules = technique_rules(db, client_id, tid)
    try:
        from app import sigma_helper
        sigma_rules = sigma_helper.search_rules(technique_filter=tid, limit=250)
    except Exception:
        sigma_rules = []
    domain = next((s for s in detail.get("sources") or [] if s in SOURCE_ORDER), "enterprise")
    try:
        nist = db.list_nist_capabilities_for_technique(tid, domain=domain)
    except Exception:
        nist = []
    groups = [{"id": p["group_id"], "name": p["group_name"], "use": p["use"], "url": p["url"]}
              for p in detail.get("procedure_examples") or []]
    return {
        "coverage": technique_coverage(tid, subs, covered, counts),
        "rules": rules,
        **technique_rule_cards(db, client_id, tid, rules),
        "enabled_rules": sum(1 for r in rules if r.enabled),
        "sigma_rules": sigma_rules,
        "nist_capabilities": nist,
        "technique_groups": groups,
    }


def _tactic_grouping(it: dict) -> List[Tuple[str, str, Any]]:
    return [(tid, name, order) for tid, name, order in it["tactics"]] or [("none", "No tactic", 999)]


def _parent_grouping(it: dict) -> Tuple[str, str, Any]:
    pid = it["parent_id"] or it["id"]
    name = it["parent_name"] or it["name"]
    return (pid, f"{pid} {name}", pid)


_TECHNIQUE_LEVELS = {"full": "Covered", "partial": "Through sub-techniques", "none": "Not covered"}


# ── Software ─────────────────────────────────────────────────────────────────

def _software_rows(db, domain: str) -> List[dict]:
    return _cached(("software", domain), lambda: db.list_mitre_software(domain=domain))


def _platforms(text: Optional[str]) -> List[str]:
    return [p.strip() for p in (text or "").split(",") if p.strip()]


def _platform_options(db, domain: str) -> List[Tuple[str, str]]:
    names = sorted({p for r in _software_rows(db, domain) for p in _platforms(r["platforms"])}, key=str.lower)
    return [("", "Any")] + [(p, p) for p in names]


def _software_load(db, search, domain, covered, counts) -> List[dict]:
    rows = db.list_mitre_software(search=search, domain=domain) if search else _software_rows(db, domain)
    tech_ids = _technique_ids(db, "software", domain)
    items = []
    for r in rows:
        kind = (r["software_type"] or "").lower()            # malware | tool
        type_label = kind.title() or "Software"
        platforms = _platforms(r["platforms"])
        meta = [("crosshair", _plural(r["technique_count"], "technique"), "ATT&CK techniques it is used for")]
        if r["group_count"]:
            meta.append(("users", f"Used by {_plural(r['group_count'], 'group')}", "Groups known to use it"))
        items.append({
            "id": r["id"],
            "dom_id": dom_id("software", r["id"]),
            "window_url": window_url("software", r["id"], domain),
            "name": r["name"],
            "sub": " · ".join([type_label] + ([", ".join(platforms)] if platforms else [])),
            "summary": plain_summary(r.get("description")),
            "sources": r.get("sources") or [],
            "coverage": coverage_of(tech_ids.get((r["id"] or "").upper(), set()), covered),
            "software_type": kind,
            "type_label": type_label,
            "platforms": platforms,
            "platforms_text": ", ".join(platforms),
            "technique_count": r["technique_count"],
            "group_count": r["group_count"],
            "meta": meta,
        })
    return items


def _software_metrics(items: List[dict]) -> List[dict]:
    malware = sum(1 for it in items if it["software_type"] == "malware")
    used = sum(1 for it in items if it["group_count"])
    return _coverage_metrics(
        items,
        {"value": len(items), "label": "Software", "sub": f"{malware} malware, {_plural(len(items) - malware, 'tool')}", "icon": "package"},
        {"value": used, "label": "Used by groups", "sub": "At least one known group uses it", "icon": "users"},
        "Across software with techniques",
    )


# ── Campaigns ────────────────────────────────────────────────────────────────

_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _month(iso: Optional[str]) -> str:
    """'2022-03-01T05:00:00.000Z' -> 'Mar 2022'."""
    m = re.match(r"(\d{4})-(\d{2})", iso or "")
    return f"{_MONTHS[int(m.group(2)) - 1]} {m.group(1)}" if m and 1 <= int(m.group(2)) <= 12 else ""


def _active_span(first: Optional[str], last: Optional[str]) -> str:
    a, b = _month(first), _month(last)
    if a and b:
        return a if a == b else f"{a} – {b}"
    return a or b


def _campaign_groups(db, domain: str) -> Dict[str, List[Tuple[str, str]]]:
    return _cached(("campaign_groups", domain), lambda: db.get_mitre_campaign_groups(domain))


def _attribution_options(db, domain: str) -> List[Tuple[str, str]]:
    groups = {gid: name for links in _campaign_groups(db, domain).values() for gid, name in links}
    return [("", "Any"), ("none", "Unattributed")] + [
        (gid, f"{name} ({gid})") for gid, name in sorted(groups.items(), key=lambda g: g[1].lower())
    ]


def _campaigns_load(db, search, domain, covered, counts) -> List[dict]:
    rows = db.list_mitre_campaigns(search=search or None, domain=domain)
    tech_ids = _technique_ids(db, "campaign", domain)
    links = _campaign_groups(db, domain)
    items = []
    for r in rows:
        cid = (r["id"] or "").upper()
        groups = links.get(cid, [])
        attributed = ", ".join(name for _, name in groups) or "Unattributed"
        span = _active_span(r["first_seen"], r["last_seen"])
        year = (r["last_seen"] or "")[:4]
        items.append({
            "id": r["id"],
            "dom_id": dom_id("campaigns", r["id"]),
            "window_url": window_url("campaigns", r["id"], domain),
            "name": r["name"],
            "sub": attributed,
            "summary": plain_summary(r.get("description")),
            "sources": r.get("sources") or [],
            "coverage": coverage_of(tech_ids.get(cid, set()), covered),
            "groups": groups,
            "group_ids": {gid for gid, _ in groups},
            "attributed": attributed,
            "span": span or "—",
            "first_seen": (r["first_seen"] or "")[:10],
            "last_seen": (r["last_seen"] or "")[:10],
            "last_year": year if year.isdigit() else "",
            "technique_count": r["technique_count"],
            "meta": [
                ("calendar", span or "Dates unknown", "First to last seen"),
                ("crosshair", _plural(r["technique_count"], "technique"), "ATT&CK techniques used in it"),
            ],
        })
    return items


def _campaigns_metrics(items: List[dict]) -> List[dict]:
    attributed = sum(1 for it in items if it["group_ids"])
    return _coverage_metrics(
        items,
        {"value": len(items), "label": "Campaigns", "sub": "Matching the filters", "icon": "activity"},
        {"value": attributed, "label": "Attributed", "sub": "Linked to a known group", "icon": "users"},
        "Across campaigns using techniques",
    )


def _attribution_grouping(it: dict) -> List[Tuple[str, str, Any]]:
    return [(gid, name, (0, name.lower())) for gid, name in it["groups"]] or [("none", "Unattributed", (1, ""))]


def _year_grouping(it: dict) -> Tuple[str, str, Any]:
    year = it["last_year"]
    return (year, year, -int(year)) if year else ("unknown", "Unknown", 0)


# ── Mitigations ──────────────────────────────────────────────────────────────

def _technique_tactics(db, domain: str) -> Dict[str, List[Tuple[str, str, int]]]:
    """Technique id -> its tactics (id, name, kill-chain order)."""
    def load():
        index = _tactic_index(db, domain)
        return {(r["id"] or "").upper(): _row_tactics(r, index) for r in _technique_rows(db, domain)}
    return _cached(("technique_tactics", domain), load)


def _mitigations_load(db, search, domain, covered, counts) -> List[dict]:
    rows = db.list_mitre_mitigations(search=search or None, domain=domain)
    tech_ids = _technique_ids(db, "mitigation", domain)
    tactics_of = _technique_tactics(db, domain)
    items = []
    for r in rows:
        ids = tech_ids.get((r["id"] or "").upper(), set())
        tactics = sorted({t for tid in ids for t in tactics_of.get(tid, [])}, key=lambda t: t[2])
        items.append({
            "id": r["id"],
            "dom_id": dom_id("mitigations", r["id"]),
            "window_url": window_url("mitigations", r["id"], domain),
            "name": r["name"],
            "sub": ", ".join(name for _, name, _ in tactics),
            "summary": plain_summary(r.get("description")),
            "sources": r.get("sources") or [],
            "coverage": coverage_of(ids, covered),
            "technique_ids": ids,
            "tactics": tactics,
            "tactic_ids": {t[0] for t in tactics},
            "technique_count": r["technique_count"],
            "meta": [
                ("crosshair", _plural(r["technique_count"], "technique"), "ATT&CK techniques it mitigates"),
                ("layers", _plural(len(tactics), "tactic"), "Tactics those techniques serve"),
            ],
        })
    return items


def _mitigations_metrics(items: List[dict]) -> List[dict]:
    addressed = set().union(*(it["technique_ids"] for it in items)) if items else set()
    return _coverage_metrics(
        items,
        {"value": len(items), "label": "Mitigations", "sub": "Matching the filters", "icon": "shield"},
        {"value": len(addressed), "label": "Techniques addressed", "sub": "Mitigated by those shown", "icon": "crosshair"},
        "Of the techniques each mitigates",
    )


def _mitigations_window(db, client_id, detail: dict, covered: set, counts: dict) -> dict:
    """Coverage, each technique with its tactics, and coverage per tactic: which of the techniques
    this control addresses your rules would also detect, and where the gaps sit in the kill chain."""
    ctx = _technique_set_window(db, client_id, detail, covered, counts)
    domain = next((s for s in detail.get("sources") or [] if s in SOURCE_ORDER), "enterprise")
    tactics_of = _technique_tactics(db, domain)
    techniques, by_tactic = [], {}
    for t in detail.get("techniques") or []:
        tid = (t.get("id") or "").upper()
        tactics = tactics_of.get(tid, [])
        techniques.append({**t, "tactic": ", ".join(name for _, name, _ in tactics)})
        for tac in tactics:
            by_tactic.setdefault(tac, set()).add(tid)
    ctx["techniques"] = techniques
    ctx["tactic_coverage"] = [
        {"id": tac[0], "name": tac[1], **coverage_of(ids, covered)}
        for tac, ids in sorted(by_tactic.items(), key=lambda kv: kv[0][2])
    ]
    return ctx


# ── Tactics ──────────────────────────────────────────────────────────────────

def _tactics_load(db, search, domain, covered, counts) -> List[dict]:
    rows = _tactics(db, domain)
    tech_ids = _technique_ids(db, "tactic", domain)
    needle = (search or "").strip().lower()
    items = []
    for order, r in enumerate(rows):
        if needle and not any(needle in (r.get(k) or "").lower() for k in ("id", "name", "shortname", "description")):
            continue
        ids = tech_ids.get((r["id"] or "").upper(), set())
        subs = sum(1 for t in ids if "." in t)
        items.append({
            "id": r["id"],
            "dom_id": dom_id("tactic", r["id"]),
            "window_url": window_url("tactic", r["id"], domain),
            "name": r["name"],
            "sub": "",
            "summary": plain_summary(r.get("description")),
            "sources": r.get("sources") or [],
            "coverage": coverage_of(ids, covered),
            "order": order,
            "technique_ids": ids,
            "technique_count": len(ids) - subs,
            "sub_count": subs,
            "group_count": r["group_count"],
            "meta": [
                ("crosshair", f"{_plural(len(ids) - subs, 'technique')}, {subs} sub", "ATT&CK techniques and sub-techniques under this tactic"),
                ("users", _plural(r["group_count"], "group"), "Groups using its techniques"),
            ],
        })
    return items


def _tactics_metrics(items: List[dict]) -> List[dict]:
    ids = set().union(*(it["technique_ids"] for it in items)) if items else set()
    return _coverage_metrics(
        items,
        {"value": len(items), "label": "Tactics", "sub": "Matching the filters", "icon": "layers"},
        {"value": len(ids), "label": "Techniques", "sub": "Techniques and sub-techniques under them", "icon": "crosshair"},
        "Of each tactic's techniques",
    )


def _source_grouping(it: dict) -> List[Tuple[str, str, Any]]:
    return [(s, SOURCE_META[s]["label"], SOURCE_ORDER.index(s)) for s in it["sources"] if s in SOURCE_ORDER] \
        or [("other", "Other", 99)]


KINDS: Dict[str, KindSpec] = {
    "tactic": KindSpec(
        key="tactic",
        title="Tactics",
        subtitle="The adversary's goals, in kill-chain order, and how much of each one's techniques your enabled rules cover.",
        singular="Tactic",
        detail_kind="tactic",
        active_sub="tactic",
        load=_tactics_load,
        sorts={
            "order": ("Kill chain", "asc", lambda it: it["order"]),
            "id": ("ID", "asc", lambda it: it["id"]),
            "name": ("Name", "asc", lambda it: (it["name"] or "").lower()),
            "techniques": ("Techniques", "desc", lambda it: it["technique_count"]),
            "coverage": ("Coverage", "asc", _coverage_sort),
        },
        default_sort="order",
        columns=[
            ("id", "ID", "id"),
            ("name", "Tactic", "name"),
            ("technique_count", "Techniques", "techniques"),
            ("group_count", "Groups", None),
            ("coverage", "Coverage", "coverage"),
            ("sources", "Source", None),
        ],
        metrics=_tactics_metrics,
        window_body="components/mitre_window_tactic.html",
        filters={"coverage": _coverage_filter()},
        groupings={
            "source": ("Source", _source_grouping),
            "coverage": _coverage_grouping(),
        },
        window_context=_technique_set_window,
    ),
    "groups": KindSpec(
        key="groups",
        title="Groups",
        subtitle="Tracked adversary clusters in ATT&CK, and how much of each one's tradecraft your enabled rules cover.",
        singular="Group",
        detail_kind="group",
        active_sub="groups",
        load=_groups_load,
        sorts={
            "id": ("ID", "asc", lambda it: it["id"]),
            "name": ("Name", "asc", lambda it: (it["name"] or "").lower()),
            "techniques": ("Techniques", "desc", lambda it: it["technique_count"]),
            "coverage": ("Coverage", "asc", _coverage_sort),
        },
        default_sort="name",
        columns=[
            ("id", "ID", "id"),
            ("name", "Group", "name"),
            ("sub", "Also known as", None),
            ("technique_count", "Techniques", "techniques"),
            ("coverage", "Coverage", "coverage"),
            ("sources", "Source", None),
        ],
        metrics=_groups_metrics,
        window_body="components/mitre_window_group.html",
        filters={"coverage": _coverage_filter()},
        groupings={"coverage": _coverage_grouping()},
        window_context=_technique_set_window,
    ),
    "technique": KindSpec(
        key="technique",
        title="Techniques",
        subtitle="How adversaries achieve their goals, and which of them your enabled rules detect.",
        singular="Technique",
        detail_kind="technique",
        active_sub="technique",
        load=_techniques_load,
        sorts={
            "id": ("ID", "asc", lambda it: it["id"]),
            "name": ("Name", "asc", lambda it: (it["name"] or "").lower()),
            "groups": ("Groups using it", "desc", lambda it: it["group_count"]),
            "rules": ("Rules", "desc", lambda it: it["rule_count"]),
            "coverage": ("Coverage", "asc", lambda it: (it["coverage"]["rank"], -it["group_count"], it["id"])),
        },
        default_sort="id",
        columns=[
            ("id", "ID", "id"),
            ("name", "Technique", "name"),
            ("sub", "Tactics", None),
            ("group_count", "Groups", "groups"),
            ("coverage", "Coverage", "coverage"),
            ("sources", "Source", None),
        ],
        metrics=_techniques_metrics,
        window_body="components/mitre_window_technique.html",
        filters={
            "tactic": Filter("Tactic", _tactic_options, lambda it, v: v.upper() in it["tactic_ids"]),
            "type": Filter("Type", [("", "Any"), ("technique", "Techniques"), ("sub", "Sub-techniques")],
                           lambda it, v: it["is_sub"] == (v == "sub")),
            "coverage": Filter("Coverage", [("", "Any")] + list(_TECHNIQUE_LEVELS.items()),
                               lambda it, v: it["coverage"]["level"] == v),
        },
        groupings={
            "tactic": ("Tactic", _tactic_grouping),
            "parent": ("Parent technique", _parent_grouping),
            "coverage": ("Coverage", lambda it: (it["coverage"]["level"], _TECHNIQUE_LEVELS[it["coverage"]["level"]], it["coverage"]["rank"])),
        },
        window_context=_techniques_window,
    ),
    "software": KindSpec(
        key="software",
        title="Software",
        subtitle="Malware and tools adversaries use, and how much of what each one does your enabled rules cover.",
        singular="Software",
        detail_kind="software",
        active_sub="software",
        load=_software_load,
        sorts={
            "id": ("ID", "asc", lambda it: it["id"]),
            "name": ("Name", "asc", lambda it: (it["name"] or "").lower()),
            "techniques": ("Techniques", "desc", lambda it: it["technique_count"]),
            "groups": ("Groups using it", "desc", lambda it: it["group_count"]),
            "coverage": ("Coverage", "asc", _coverage_sort),
        },
        default_sort="name",
        columns=[
            ("id", "ID", "id"),
            ("name", "Software", "name"),
            ("type_label", "Type", None),
            ("platforms_text", "Platforms", None),
            ("technique_count", "Techniques", "techniques"),
            ("coverage", "Coverage", "coverage"),
            ("sources", "Source", None),
        ],
        metrics=_software_metrics,
        window_body="components/mitre_window_software.html",
        filters={
            "type": Filter("Type", [("", "Any"), ("malware", "Malware"), ("tool", "Tool")],
                           lambda it, v: it["software_type"] == v),
            "platform": Filter("Platform", _platform_options, lambda it, v: v in it["platforms"]),
            "coverage": _coverage_filter(),
        },
        groupings={
            "type": ("Type", lambda it: (it["software_type"] or "other", it["type_label"], it["type_label"])),
            "platform": ("Platform", lambda it: [(p, p, (0, p.lower())) for p in it["platforms"]] or [("none", "No platform", (1, ""))]),
            "coverage": _coverage_grouping(),
        },
        window_context=_technique_set_window,
    ),
    "campaigns": KindSpec(
        key="campaigns",
        title="Campaigns",
        subtitle="Intrusion activity over a known period, who it is attributed to, and how much of it your enabled rules cover.",
        singular="Campaign",
        detail_kind="campaign",
        active_sub="campaigns",
        load=_campaigns_load,
        sorts={
            "id": ("ID", "asc", lambda it: it["id"]),
            "name": ("Name", "asc", lambda it: (it["name"] or "").lower()),
            "first_seen": ("First seen", "desc", lambda it: it["first_seen"]),
            "last_seen": ("Last seen", "desc", lambda it: it["last_seen"]),
            "techniques": ("Techniques", "desc", lambda it: it["technique_count"]),
            "coverage": ("Coverage", "asc", _coverage_sort),
        },
        default_sort="last_seen",
        columns=[
            ("id", "ID", "id"),
            ("name", "Campaign", "name"),
            ("attributed", "Attributed to", None),
            ("span", "Active", "last_seen"),
            ("technique_count", "Techniques", "techniques"),
            ("coverage", "Coverage", "coverage"),
            ("sources", "Source", None),
        ],
        metrics=_campaigns_metrics,
        window_body="components/mitre_window_campaign.html",
        filters={
            "attributed": Filter("Attributed to", _attribution_options,
                            lambda it, v: not it["group_ids"] if v == "none" else v in it["group_ids"]),
            "coverage": _coverage_filter(),
        },
        groupings={
            "group": ("Attributed to", _attribution_grouping),
            "year": ("Year last seen", _year_grouping),
            "coverage": _coverage_grouping(),
        },
        window_context=_technique_set_window,
    ),
    "mitigations": KindSpec(
        key="mitigations",
        title="Mitigations",
        subtitle="Security controls that prevent techniques, and how many of the techniques each one addresses your enabled rules also detect.",
        singular="Mitigation",
        detail_kind="mitigation",
        active_sub="mitigations",
        load=_mitigations_load,
        sorts={
            "id": ("ID", "asc", lambda it: it["id"]),
            "name": ("Name", "asc", lambda it: (it["name"] or "").lower()),
            "techniques": ("Techniques", "desc", lambda it: it["technique_count"]),
            "coverage": ("Coverage", "asc", _coverage_sort),
        },
        default_sort="id",
        columns=[
            ("id", "ID", "id"),
            ("name", "Mitigation", "name"),
            ("sub", "Tactics", None),
            ("technique_count", "Techniques", "techniques"),
            ("coverage", "Coverage", "coverage"),
            ("sources", "Source", None),
        ],
        metrics=_mitigations_metrics,
        window_body="components/mitre_window_mitigation.html",
        filters={
            "tactic": Filter("Tactic", _tactic_options, lambda it, v: v.upper() in it["tactic_ids"]),
            "coverage": _coverage_filter(),
        },
        groupings={
            "tactic": ("Tactic", _tactic_grouping),
            "coverage": _coverage_grouping(),
        },
        window_context=_mitigations_window,
    ),
}


# ── The grid ─────────────────────────────────────────────────────────────────

PAGE_SIZE = 48

# The grid's own query parameters. A filter shares the query string, so it cannot take one of
# these names (a campaign filter called "group" read group=none as "unattributed").
GRID_PARAMS = {"q", "src", "sort", "dir", "group", "view", "page", "in_group", "open"}
for _spec in KINDS.values():
    assert not GRID_PARAMS & set(_spec.filters), f"{_spec.key}: filter named like a grid parameter"


def grid(db, spec: KindSpec, params: Dict[str, str], covered: set, counts: dict) -> Dict[str, Any]:
    """Filter, sort, then group or page a kind's items for partials/mitre_grid.html.

    ``params``: q, src, sort, dir, group, view, page, in_group, plus the kind's own filters. With a
    grouping and no ``in_group`` it returns the group heads only; each head's body fetches its own
    items (``in_group``) when opened. An item can be in several groups, and is counted in each.
    Otherwise it returns one page of items and the next page's URL.
    """
    domain, _ = resolve_source(params.get("src") or "enterprise")
    search = (params.get("q") or "").strip()
    items = spec.load(db, search, domain, covered, counts)

    active = {}
    for name, flt in spec.filters.items():
        value = (params.get(name) or "").strip()
        valid = {v for v, _ in flt.options_for(db, domain)}
        if value not in valid and value.upper() in valid:
            value = value.upper()             # ?tactic=ta0006
        if value and value in valid:
            items = [it for it in items if flt.match(it, value)]
            active[name] = value

    sort = params.get("sort") if params.get("sort") in spec.sorts else spec.default_sort
    default_dir = spec.sorts[sort][1]
    direction = params.get("dir") if params.get("dir") in ("asc", "desc") else default_dir
    # Search results keep their relevance order unless a sort was chosen explicitly.
    if not (search and not params.get("sort")):
        items = sorted(items, key=spec.sorts[sort][2], reverse=(direction == "desc"))

    group = params.get("group") if params.get("group") in spec.groupings else ""
    view = "table" if params.get("view") == "table" else "cards"
    state = {"q": search, "src": domain, "sort": sort, "dir": direction, "group": group or "none", "view": view, **active}
    base_url = f"/api/mitre/grid/{spec.key}"

    out: Dict[str, Any] = {
        "spec": spec, "view": view, "sort": sort, "dir": direction, "group": group, "state": state,
        "metrics": spec.metrics(items), "total": len(items),
    }

    in_group = params.get("in_group")
    if group:
        keyfn = spec.groupings[group][1]

        def memberships(it):
            keys = keyfn(it)
            return keys if isinstance(keys, list) else [keys]

    if group and in_group is None:
        heads: Dict[str, Dict[str, Any]] = {}
        for it in items:
            for gkey, glabel, gorder in memberships(it):
                head = heads.setdefault(gkey, {"key": gkey, "label": glabel, "order": gorder, "count": 0})
                head["count"] += 1
        for head in heads.values():
            head["url"] = f"{base_url}?{urlencode({**state, 'in_group': head['key']})}"
        out["groups"] = sorted(heads.values(), key=lambda h: (h["order"], h["label"]))
        out["mode"] = "groups"
        return out

    if group and in_group is not None:
        items = [it for it in items if any(m[0] == in_group for m in memberships(it))]

    try:
        page = max(1, int(params.get("page") or 1))
    except ValueError:
        page = 1
    start = (page - 1) * PAGE_SIZE
    out["items"] = items[start:start + PAGE_SIZE]
    out["page"] = page
    out["mode"] = "append" if page > 1 else ("group_body" if in_group is not None else "flat")
    if start + PAGE_SIZE < len(items):
        nxt = {**state, "page": page + 1}
        if in_group is not None:
            nxt["in_group"] = in_group
        out["next_url"] = f"{base_url}?{urlencode(nxt)}"
    out["shown_total"] = len(items)
    return out
