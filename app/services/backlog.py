"""The Detection Backlog: what to build next, one row per ATT&CK technique.

A row is an ATT&CK technique that some system's baseline techniques carrying it still need covered:
**No coverage**, **Known gap** (Partial coverage among them), or covered only by rules that aren't
effective (**Not effective**). Each baseline technique's status is its own system's
(``inventory_engine.get_system_steps``, as the system's page shows it), so the backlog and each
system's page always agree; the ATT&CK id only groups them, as one rule that detects it can then be
mapped on every system (Map rules by ATT&CK id). A baseline technique with several ATT&CK ids is
under each; one with none is under a row of its own, last.

Rows are ranked by fixed keys, in this order, with no weights:

1. a known gap on it whose Review by date has passed;
2. the highest priority set on one of its baseline techniques;
3. the known exploited CVEs (CISA KEV) on its systems' devices that are exploited through it (the
   bundled KEV-to-ATT&CK mapping, and the techniques added to a CVE in TIDE);
4. how many of the client's threat actors use it (Threat Landscape's: MITRE's and the client's
   OpenCTI's), by its exact id;
5. how many systems it is on;

then by ATT&CK id. **Sort by** can put one of 3 to 5 first instead.

Each row also says which rules are ready: the client's enabled rules that carry it (they may only
need mapping), and Elastic's and SigmaHQ's rules for it that aren't deprecated.
"""
import logging
from collections import Counter
from typing import Any, Dict, Iterable, List, Set, Tuple

logger = logging.getLogger(__name__)

# The system page's Coverage choices that need work, with its labels: Known gap includes Partial
# coverage, and Not effective partly covered ones (inventory_engine.get_system_steps' filter).
STATUSES = (("red", "No coverage"), ("amber", "Known gap"), ("partial", "Partial coverage"),
            ("not_effective", "Not effective"))
SORTS = (("rank", "Most urgent"), ("kev", "KEV CVEs"), ("actors", "Threat actors"), ("systems", "Systems"),
         ("id", "ATT&CK id"))
SORT_TITLES = {
    "rank": "Review due first, then priority, KEV CVEs, threat actors and systems",
    "kev": "Most known exploited CVEs on its systems first",
    "actors": "Used by the most threat actors first",
    "systems": "On the most systems first",
}


def _priority_rank(priority: str) -> int:
    from app.inventory_engine import STEP_PRIORITIES
    keys = [k for k, _ in STEP_PRIORITIES]
    return keys.index(priority) if priority in keys else len(keys)


def needs_work(step: Dict[str, Any]) -> bool:
    """No coverage, a known gap (Partial coverage too), or covered only by rules that aren't effective."""
    return step.get("status") in ("red", "amber") or bool(step.get("not_effective"))


def matches(step: Dict[str, Any], statuses: Iterable[str]) -> bool:
    """Whether a baseline technique is one of the chosen statuses (any of them; none chosen is all)."""
    wanted = list(statuses or ())
    return not wanted or any(step.get("status") == s if s in ("red", "amber") else bool(step.get(s)) for s in wanted)


def _entry_key(step: Dict[str, Any]) -> Tuple:
    """A row's baseline techniques: review due first, then priority, then system and title."""
    return (not step.get("review_due"), _priority_rank(step.get("priority") or ""),
            (step.get("system_name") or "").lower(), (step.get("title") or "").lower())


def build_rows(entries: List[Dict[str, Any]], *, names: Dict[str, Dict[str, str]], actors: Dict[str, int],
               kev: Dict[Tuple[str, str], Set[str]], ready: Dict[str, Dict[str, int]]) -> List[Dict[str, Any]]:
    """One row per ATT&CK id from the baseline techniques that need work (``entries``: system steps,
    each with ``system_id`` and ``system_name``). ``names``: each id's ATT&CK name and tactic;
    ``actors``: how many threat actors use each id; ``kev``: the KEV CVEs per (system, id);
    ``ready``: per id, how many of the client's rules carry it and Elastic and Sigma rules there are."""
    by_tid: Dict[str, List[Dict[str, Any]]] = {}
    for e in entries:
        for tid in e.get("display_technique_ids") or [""]:
            bucket = by_tid.setdefault(tid, [])
            if e not in bucket:
                bucket.append(e)
    rows = []
    for tid, group in by_tid.items():
        group = sorted(group, key=_entry_key)
        systems = {e["system_id"]: e["system_name"] for e in group}
        cves = set().union(*(kev.get((sid, tid), set()) for sid in systems)) if tid else set()
        priorities = [e.get("priority") for e in group if e.get("priority")]
        rows.append({
            "tid": tid, "name": (names.get(tid) or {}).get("name", ""), "tactic": (names.get(tid) or {}).get("tactic", ""),
            "entries": group,
            "systems": len(systems), "system_names": sorted(systems.values(), key=str.lower),
            "due": sum(1 for e in group if e.get("review_due")),
            "priority": min(priorities, key=_priority_rank) if priorities else "",
            "kev": sorted(cves), "actors": actors.get(tid, 0) if tid else 0,
            "ready": ready.get(tid) or {"rules": 0, "elastic": 0, "sigma": 0},
            "counts": {s: sum(1 for e in group if matches(e, [s])) for s, _ in STATUSES},
        })
    return rows


def rank_key(row: Dict[str, Any]) -> Tuple:
    """Most urgent first: review due, priority, KEV CVEs, threat actors, systems, then ATT&CK id
    (the row with none last)."""
    return (not row["due"], _priority_rank(row["priority"]), -len(row["kev"]), -row["actors"], -row["systems"],
            not row["tid"], row["tid"])


def sorted_rows(rows: List[Dict[str, Any]], sort: str = "rank") -> List[Dict[str, Any]]:
    """``rows`` by **Sort by**: one figure first, then the ranking; or by ATT&CK id."""
    first = {"kev": lambda r: -len(r["kev"]), "actors": lambda r: -r["actors"], "systems": lambda r: -r["systems"]}
    if sort == "id":
        return sorted(rows, key=lambda r: (not r["tid"], r["tid"]))
    if sort in first:
        return sorted(rows, key=lambda r: (first[sort](r),) + rank_key(r))
    return sorted(rows, key=rank_key)


def searched(rows: List[Dict[str, Any]], search: str) -> List[Dict[str, Any]]:
    """The rows whose ATT&CK id or name, or one of whose baseline techniques or systems, has ``search``."""
    q = (search or "").strip().lower()
    if not q:
        return rows
    return [r for r in rows if q in r["tid"].lower() or q in r["name"].lower()
            or any(q in (e.get("title") or "").lower() or q in (e.get("system_name") or "").lower() for e in r["entries"])]


def totals(entries: List[Dict[str, Any]], rows: List[Dict[str, Any]]) -> Dict[str, int]:
    """The metric strip, for the whole backlog: the baseline techniques by status (as a system's page
    counts them), the ATT&CK techniques, systems and KEV CVEs, and how many are due for review."""
    from app.inventory_engine import step_totals
    t = step_totals(entries)
    return {"techniques": sum(1 for r in rows if r["tid"]), "unmapped": len(next((r["entries"] for r in rows if not r["tid"]), [])),
            "baseline_techniques": len(entries), "systems": len({e["system_id"] for e in entries}),
            "due": sum(1 for e in entries if e.get("review_due")),
            "none": t["none"], "none_critical": t["none_critical"], "gap": t["gap"], "partial": t["partial"], "not_effective": t["not_effective"],
            "kev": len({c for r in rows for c in r["kev"]})}


# ── what the rows are built from ───────────────────────────────────────────────────────────────

def system_entries(client_id: str) -> Tuple[List[Any], List[Dict[str, Any]], int]:
    """The client's systems, their baseline techniques that need work (each with its system and its
    card's ring: the strongest counted rule's score, for one that has a rule), and how many baseline
    techniques they have in all."""
    from app.inventory_engine import attach_step_evidence, get_system_steps, list_systems
    systems = list_systems(client_id=client_id)
    entries: List[Dict[str, Any]] = []
    total = 0
    for s in systems:
        steps = get_system_steps(s.id, client_id=client_id)["steps"]
        total += len(steps)
        work = [dict(st, system_id=s.id, system_name=s.name, evidence_score=None, evidence_rule="", evidence_how="")
                for st in steps if needs_work(st)]
        ringed = [e for e in work if e.get("partial") or e.get("not_effective")]
        if ringed:
            attach_step_evidence(s.id, ringed, client_id=client_id)
        entries += work
    return systems, entries, total


def kev_by_technique(system_ids: Iterable[str], client_id: str) -> Dict[Tuple[str, str], Set[str]]:
    """``(system_id, ATT&CK id) -> KEV CVE ids`` on the system's devices exploited through it."""
    from app.inventory_engine import cve_technique_ids, get_system_vulnerabilities
    out: Dict[Tuple[str, str], Set[str]] = {}
    for sid in system_ids:
        for match in get_system_vulnerabilities(sid, client_id=client_id) or []:
            for tid in cve_technique_ids(match.cve_id, client_id=client_id):
                out.setdefault((sid, str(tid).strip().upper()), set()).add(match.cve_id)
    return out


def actor_counts(db, client_id: str) -> Dict[str, int]:
    """How many of the client's threat actors use each ATT&CK id."""
    counts: Counter = Counter()
    for actor in db.get_threat_actors(client_id=client_id) or []:
        counts.update({str(t).strip().upper() for t in (actor.ttps or []) if t})
    return dict(counts)


# Each library's rules per ATT&CK id, from the indexes built into TIDE, in one query each: a rule is
# counted for an id when one of its techniques starts with it (the id or a sub-technique of it), as
# the library's page finds rules by technique (elastic_rules.technique_clause).
_ELASTIC_BY_TECHNIQUE = (
    "SELECT t.tid, COUNT(e.rule_id) FROM (SELECT unnest(?::VARCHAR[]) AS tid) t "
    "LEFT JOIN elastic_rules_index e ON e.status <> 'deprecated' "
    "AND (',' || array_to_string(e.techniques, ',')) LIKE '%,' || t.tid || '%' GROUP BY t.tid")
_SIGMA_BY_TECHNIQUE = (
    "SELECT t.tid, COUNT(s.rule_id) FROM (SELECT unnest(?::VARCHAR[]) AS tid) t "
    "LEFT JOIN sigma_rules_index s ON lower(COALESCE(s.status, '')) NOT IN ('deprecated', 'unsupported') "
    "AND (',' || upper(array_to_string(s.techniques, ','))) LIKE '%,' || t.tid || '%' GROUP BY t.tid")


def _library_counts(conn, sql: str, tids: List[str], library: str) -> Dict[str, int]:
    try:
        return {tid: n for tid, n in conn.execute(sql, [tids]).fetchall()}
    except Exception:
        logger.warning("Detection Backlog: %s rules couldn't be counted", library, exc_info=True)
        return {}


def ready_counts(db, client_id: str, tids: Iterable[str]) -> Dict[str, Dict[str, int]]:
    """Per ATT&CK id: the client's enabled rules carrying it (as a technique's "N to consider"), and
    Elastic's and SigmaHQ's rules for it that aren't deprecated (nor, for Sigma, unsupported)."""
    tids = sorted({t for t in tids if t})
    rules = db.get_ttp_rule_counts(client_id=client_id) or {}
    elastic: Dict[str, int] = {}
    sigma: Dict[str, int] = {}
    if tids:
        with db.get_shared_connection() as conn:
            elastic = _library_counts(conn, _ELASTIC_BY_TECHNIQUE, tids, "Elastic")
            sigma = _library_counts(conn, _SIGMA_BY_TECHNIQUE, tids, "Sigma")
    return {t: {"rules": rules.get(t, 0), "elastic": elastic.get(t, 0), "sigma": sigma.get(t, 0)} for t in tids}


def technique_names(tids: Iterable[str]) -> Dict[str, Dict[str, str]]:
    from app.inventory_engine import _technique_names
    return {t["id"]: t for t in _technique_names(sorted({t for t in tids if t}))}


def backlog(db, client_id: str) -> Dict[str, Any]:
    """Every row, unfiltered and unsorted, with the client's systems and the whole backlog's totals."""
    systems, entries, total = system_entries(client_id)
    tids = {t for e in entries for t in (e.get("display_technique_ids") or [])}
    try:
        kev = kev_by_technique(sorted({e["system_id"] for e in entries}), client_id)
    except Exception:
        logger.warning("Detection Backlog: KEV CVEs couldn't be matched to systems", exc_info=True)
        kev = {}
    sources = {"names": technique_names(tids), "actors": actor_counts(db, client_id), "kev": kev,
               "ready": ready_counts(db, client_id, tids)}
    rows = build_rows(entries, **sources)
    return {"systems": systems, "entries": entries, "rows": rows, "sources": sources, "baseline_techniques": total,
            "totals": totals(entries, rows)}


def filters_from(params, systems: List[Any]) -> Dict[str, Any]:
    """The filter bar's choices from a query string (the page's address, or the bar)."""
    ids = {s.id for s in systems}
    sort = params.get("sort") or "rank"
    return {"search": (params.get("search") or "").strip(),
            "system": [v for v in params.getlist("system") if v in ids],
            "status": [v for v in params.getlist("status") if v in dict(STATUSES)],
            "sort": sort if sort in dict(SORTS) else "rank"}


def view(data: Dict[str, Any], filters: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The rows the filters show: built from the chosen systems' baseline techniques of the chosen
    statuses (so a row's figures are theirs), searched, then sorted."""
    rows = data["rows"]
    if filters["system"] or filters["status"]:
        keep = [e for e in data["entries"] if (not filters["system"] or e["system_id"] in filters["system"])
                and matches(e, filters["status"])]
        rows = build_rows(keep, **data["sources"])
    return sorted_rows(searched(rows, filters["search"]), filters["sort"])
