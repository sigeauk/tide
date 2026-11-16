"""The executive briefing of a system's report (Audience: Executive / CISO): what the report's figures
mean for the business, in two or three pages.

Built from the report's own data (``inventory_engine.build_system_report_data``), so the briefing and
the technical report always agree:

- **KPIs:** effective coverage, the threat baselines assessed, the exposure gaps (techniques nothing
  detects) and the device fleet's health (devices with no known exploited vulnerability).
- **Kill-chain coverage:** the techniques by ATT&CK tactic, in kill-chain order.
- **Remediation roadmap:** what would close the gaps. Quick wins first, which need no new engineering
  (rules that exist but don't count, rules in the SIEM carrying a technique's ATT&CK ids that aren't
  mapped, rules that can't work now, accepted gaps due for review), then the detections to build.
  Each says how much coverage it would add; a technique is counted under one action only.
- **Summary:** three or four plain sentences on where the system stands, from these figures.

Deterministic: the same report always says the same thing.
"""
from typing import Any, Dict, Iterable, List, Optional

STRONG, MODERATE = 80, 40
TOP = 3


def _n(n: int, one: str, many: str = "") -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _and(items: Iterable[str]) -> str:
    """"a", "a and b", "a, b and c"."""
    items = [i for i in items if i]
    if len(items) < 2:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _pct(part: int, whole: int) -> Optional[int]:
    return round(part / whole * 100) if whole else None


def _tone(pct: Optional[int]) -> str:
    return "plain" if pct is None else "success" if pct >= STRONG else "warning" if pct >= MODERATE else "danger"


def _scored(report: Dict[str, Any]) -> int:
    t = report["totals"]
    return t["total"] - t["na"]


def _gain(report: Dict[str, Any], base: str, more: int) -> Optional[int]:
    """How many percentage points ``more`` techniques would add to Covered (``base`` covered) or
    Effective (``effective``): None while coverage isn't scored."""
    scored = _scored(report)
    if report["coverage_undefined"] or not scored or not more:
        return None
    now = report["totals"][base]
    return _pct(now + more, scored) - _pct(now, scored)


# ── KPIs ────────────────────────────────────────────────────────────────────────────────────────

def kpis(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Page one's four cards: ``{key, value, label, sub, tone}``."""
    t = report["totals"]
    scored = _scored(report)
    eff = report["effective_pct"]
    high = sum(1 for x in report["techniques"] if x["status"] == "red" and x["priority"] in ("critical", "high"))
    cards = [
        {"key": "effective", "value": "—" if eff is None else f"{eff}%", "label": "Effective coverage", "tone": _tone(eff),
         "sub": "not scored: no SIEM coverage set" if eff is None else f"{t['effective']} of {scored} techniques"},
        {"key": "baselines", "value": str(len(report["baselines"])), "label": "Threat baselines assessed", "tone": "plain",
         "sub": _n(t["total"], "technique")},
        {"key": "exposure", "value": str(t["none"]), "label": "Critical exposure gaps",
         "tone": "danger" if t["none"] else "success",
         "sub": "techniques nothing detects" + (f"; {high} high or critical priority" if high else "")},
    ]
    hosts = report.get("total_hosts") or 0
    if not report.get("include_devices"):
        fleet = {"value": "—", "sub": "devices not included", "tone": "plain"}
    elif not hosts:
        fleet = {"value": "—", "sub": "no devices recorded", "tone": "plain"}
    else:
        clean, risk = report["green_hosts"], report["red_hosts"]
        fleet = {"value": f"{clean}/{hosts}", "tone": "success" if clean == hosts else "danger" if risk else "warning",
                 "sub": "clean: no known exploited vulnerability" if clean == hosts
                 else f"{risk} at risk, {report['amber_hosts']} monitored"}
    return cards + [{"key": "fleet", "label": "Device fleet health", **fleet}]


# ── kill-chain coverage ─────────────────────────────────────────────────────────────────────────

def tactic_rollup(techs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The techniques by ATT&CK tactic, in kill-chain order: how many, by status, and the share
    covered and effectively covered (of those scored, as a baseline's)."""
    from app.inventory_engine import tactic_sort_key
    rows: Dict[str, Dict[str, Any]] = {}
    for x in techs:
        r = rows.setdefault(x["tactic"] or "Other", {"tactic": x["tactic"] or "Other", "total": 0, "covered": 0,
                                                   "effective": 0, "none": 0, "gap": 0, "na": 0})
        r["total"] += 1
        status = x["status"]
        if status == "green":
            r["covered"] += 1
            r["effective"] += 0 if x.get("not_effective") else 1
        elif status == "red":
            r["none"] += 1
        elif status == "amber":
            r["gap"] += 1
        else:
            r["na"] += 1
    for r in rows.values():
        r["coverage_pct"] = _pct(r["covered"], r["total"] - r["na"])
        r["effective_pct"] = _pct(r["effective"], r["total"] - r["na"])
    return sorted(rows.values(), key=lambda r: tactic_sort_key(r["tactic"], "attack"))


# ── remediation roadmap ─────────────────────────────────────────────────────────────────────────

def _effect(report: Dict[str, Any], count: int, measure: str = "covered") -> Dict[str, Any]:
    """An action's ``measure`` (the figure it raises: covered or effective), ``gain`` (by how many
    points, None while not scored) and ``impact`` (the two in words)."""
    gain = _gain(report, measure, count)
    what = "covered" if measure == "covered" else "effectively covered"
    return {"measure": measure, "gain": gain,
            "impact": f"Up to {_n(count, 'more technique')} {what}" + (f" (+{gain} points)" if gain else "")}


def roadmap(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The actions that would close the gaps, quick wins first: ``{kind: quick|engineering, title,
    detail, count, measure, gain, impact}`` (``_effect``; a review raises no figure), and for one that
    covers techniques without new engineering, ``how`` (for the summary). A technique with no coverage
    is counted under the first action that would cover it, so the counts add up."""
    from app.inventory_engine import NOT_COUNTED, NOT_COUNTED_FLAG
    techs = report["techniques"]
    name = report["system"]["name"]
    red = [x for x in techs if x["status"] == "red"]
    taken: set = set()

    def take(rows):
        picked = [x for x in rows if x["step_id"] not in taken]
        taken.update(x["step_id"] for x in picked)
        return picked

    def why(x, keys):
        return any(u["why"] in {NOT_COUNTED[k] for k in keys} for u in x["uncounted_rules"])

    def mapped(keys):
        flags = {NOT_COUNTED_FLAG[k] for k in keys}
        rows = [u for u in report["uncounted_mappings"] if u["why"] in flags]
        return sorted({u["rule"] for u in rows}), sorted({u["destination"] for u in rows})

    actions: List[Dict[str, Any]] = []
    outside = take([x for x in red if why(x, ["destination"])])
    if outside:
        rules, places = mapped(["destination"])
        actions.append({"kind": "quick", "count": len(outside),
                        "title": f"Re-scope {_n(len(rules), 'existing rule')} outside SIEM coverage",
                        "detail": f"{'It is' if len(rules) == 1 else 'They are'} mapped at {_and(places)}, where {name} isn't "
                                  f"measured. Add {'that destination' if len(places) == 1 else 'those destinations'} to the "
                                  "system's SIEM coverage, or map the rules where it is measured.",
                        "how": "bringing existing rules into its SIEM coverage", **_effect(report, len(outside))})
    off = take([x for x in red if why(x, ["disabled", "deprecated"])])
    if off:
        rules, _ = mapped(["disabled", "deprecated"])
        actions.append({"kind": "quick", "count": len(off),
                        "title": f"Re-enable or replace {_n(len(rules), 'disabled or deprecated rule')}",
                        "detail": "Mapped to techniques nothing else covers, but switched off or deprecated in the SIEM.",
                        "how": "re-enabling rules", **_effect(report, len(off))})
    carried = take([x for x in red if not x["mapped_count"] and x.get("suggestion_count")])
    if carried:
        actions.append({"kind": "quick", "count": len(carried),
                        "title": f"Map rules already in the SIEM to {_n(len(carried), 'technique')}",
                        "detail": "Enabled rules in your SIEMs carry their ATT&CK techniques. Check that they fit, then map them.",
                        "how": "mapping rules already in the SIEM", **_effect(report, len(carried))})
    broken = [x for x in techs if x.get("not_effective")]
    if broken:
        rules = sorted({r for x in broken for r in x["not_effective_rule_names"]})
        actions.append({"kind": "quick", "count": len(broken),
                        "title": f"Fix {_n(len(rules), 'rule')} that can't work now",
                        "detail": "Rule Monitoring finds they can't run or can't see their data, so the techniques they cover "
                                  "aren't effectively covered.",
                        **_effect(report, len(broken), "effective")})
    due = [x for x in techs if x.get("review_due")]
    if due:
        actions.append({"kind": "quick", "count": len(due),
                        "title": f"Review {_n(len(due), 'known gap')} past {'its' if len(due) == 1 else 'their'} review date",
                        "detail": "Accepted risks due for a decision: close them, or accept them again with a new date.",
                        "measure": None, "gain": None, "impact": "Keeps accepted risk current"})
    build = [x for x in red if x["step_id"] not in taken]
    if build:
        first = [g["title"] for g in report["priority_gaps"] if g["step_id"] in {x["step_id"] for x in build}][:TOP]
        actions.append({"kind": "engineering", "count": len(build),
                        "title": f"Build detections for {_n(len(build), 'technique')} with no rule",
                        "detail": "Nothing in your SIEMs carries their ATT&CK techniques" + (f". Start with {_and(first)}." if first else "."),
                        **_effect(report, len(build))})
    return actions


# ── summary ─────────────────────────────────────────────────────────────────────────────────────

def summary(report: Dict[str, Any], actions: List[Dict[str, Any]]) -> List[str]:
    """Three or four plain sentences: the posture, the exposure, what would close it, the devices."""
    t = report["totals"]
    name = report["system"]["name"]
    baselines = report["baselines"]
    scored = _scored(report)
    eff = report["effective_pct"]
    out: List[str] = []

    if not t["total"]:
        return [f"No techniques are defined in {name}'s selected baselines yet, so its detection coverage can't be assessed."]
    if eff is None:
        out.append(f"{name}'s detection coverage isn't scored yet: no SIEM coverage destinations are set, so it isn't "
                   f"known which rules protect it.")
    else:
        level = "strong" if eff >= STRONG else "partial" if eff >= MODERATE else "weak"
        named = f" ({_and(b['name'] for b in baselines)})" if len(baselines) <= 3 else ""
        out.append(f"{name}'s detection posture is {level}: {eff}% of the {_n(scored, 'technique')} assessed across "
                   f"{_n(len(baselines), 'threat baseline')}{named} {'is' if scored == 1 else 'are'} covered by detections "
                   f"that work today.")

    if t["none"]:
        top = [g["title"] for g in report["priority_gaps"] if g["status"] == "red"][:TOP]
        blind = [b["name"] for b in baselines if eff is not None and b["totals"]["total"] - b["totals"]["na"]
                 and not b["effective_pct"]]
        lead = f"There is no working detection for {_and(blind)}, and " if blind else ""
        out.append(f"{lead}{_n(t['none'], 'technique')} {'has' if t['none'] == 1 else 'have'} nothing detecting "
                   f"{'it' if t['none'] == 1 else 'them'} at all, including {_and(top)}: that activity would go unnoticed, "
                   "raising the risk of an attacker staying undetected for longer.")
    elif t["gap"]:
        out.append(f"Every technique has coverage or an accepted reason: {_n(t['gap'], 'known gap')} "
                   f"{'is' if t['gap'] == 1 else 'are'} accepted rather than detected.")
    else:
        out.append("Every technique assessed has coverage.")

    wins = [a for a in actions if a.get("how")]
    quick = sum(a["count"] for a in wins)
    build = sum(a["count"] for a in actions if a["kind"] == "engineering")
    if quick:
        gain = _gain(report, "covered", quick)
        rest = f"; the other {_n(build, 'technique')} need new detections" if build else ""
        out.append(f"{_n(quick, 'technique')} could be covered without new engineering, by "
                   f"{_and(a['how'] for a in wins)}{f' (up to +{gain} points)' if gain else ''}{rest}.")
    elif build:
        out.append(f"Closing the gaps needs new detection engineering: {_n(build, 'technique')} "
                   f"{'has' if build == 1 else 'have'} no rule in any SIEM.")

    hosts = report.get("total_hosts") or 0
    if report.get("include_devices") and hosts:
        if not report["total_cves"]:
            out.append(f"{'All ' + _n(hosts, 'device') + ' are' if hosts != 1 else 'Its one device is'} clean of known "
                       "exploited vulnerabilities.")
        elif report["red_hosts"]:
            out.append(f"{report['red_hosts']} of {_n(hosts, 'device')} {'has' if report['red_hosts'] == 1 else 'have'} "
                       f"known exploited vulnerabilities with no detection ({_n(report['total_cves'], 'CVE')} in all).")
        else:
            out.append(f"{_n(report['amber_hosts'], 'device')} {'has' if report['amber_hosts'] == 1 else 'have'} known "
                       "exploited vulnerabilities, each with a detection applied.")
    return out


def brief(report: Dict[str, Any]) -> Dict[str, Any]:
    """Everything the briefing adds to the report's data."""
    actions = roadmap(report)
    return {"kpis": kpis(report), "tactics": tactic_rollup(report["techniques"]), "roadmap": actions,
            "summary": summary(report, actions)}
