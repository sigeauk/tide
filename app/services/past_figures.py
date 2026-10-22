"""Past figures: a Dashboard section's figures as they stood at the end of an earlier day, and how
much each has changed since. Worked out from the history TIDE already keeps (rule history, score
history, validations), never from snapshots, and only for a section that asks for it.

``FIGURES`` names the cards that can show a change, which way is better for each, and the unit the
card shows it in ("%": a change in a percentage reads "10%", the difference between the two). A
card whose earlier value can't be known shows no change.
"""
import json
import logging
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from typing import Dict, List, Optional, Tuple

from app.scoring import SCORING_VERSION
from app.services.database import validation_key

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Figure:
    better: str = "up"      # "up", "down", or "" when neither is better
    digits: int = 0
    unit: str = ""          # after the change and the value then, as the card shows it ("%")


# source -> card -> Figure. A source listed here offers Compare with in the Dashboard editor.
FIGURES: Dict[str, Dict[str, Figure]] = {
    "rule_health": {"total": Figure(better=""), "enabled": Figure(), "validated": Figure(),
                    "quality": Figure(digits=1)},
    "system": {"covered": Figure(unit="%"), "techniques": Figure(better=""),
               "no_coverage": Figure(better="down"), "known_gaps": Figure(better="down"),
               "unmapped": Figure(better="down"), "not_counted": Figure(better="down")},
    "baselines": {"rules_mapped": Figure(), "uncovered": Figure(better="down"), "fully_covered": Figure()},
}
# The filters a comparing section may have. Any other is a filter on something TIDE keeps no
# history of, which would mix today's values with the earlier day's, so the section shows no change.
COMPARE_FILTERS: Dict[str, Tuple[str, ...]] = {"rule_health": ("space",), "system": ("system_id",)}
_COVERAGE_NOTE = "TIDE has the history to work this out from its 6.0 upgrade on, for the systems you have now."
NOTES = {"rule_health": "Total Rules, Enabled, Validated and Avg Quality show how much they have changed "
                        "since then, when the section has no filter other than SIEM.",
         "system": "Each card shows how much it has changed since then. " + _COVERAGE_NOTE,
         "baselines": "Rules Mapped, Uncovered and Fully Covered show how much they have changed since then. "
                      + _COVERAGE_NOTE}
COMPARE = (("", "None"), ("1", "Yesterday"), ("7", "7 days ago"), ("30", "30 days ago"), ("90", "90 days ago"))
PERIODS = {1: "since yesterday", 7: "in 7 days", 30: "in 30 days", 90: "in 90 days"}
# Avg Quality on an earlier day needs that day's scores, from today's scoring model, for most rules.
QUALITY_COVERAGE = 0.9


def compare_days(card: dict) -> int:
    """How many days back a section compares with: 0 when it doesn't, or can't (its source has no
    changes, or it has a filter TIDE can't apply to an earlier day)."""
    source, days = card.get("source"), card.get("compare") or ""
    allowed = COMPARE_FILTERS.get(source, ())
    if source not in FIGURES or not days.isdigit() or int(days) not in PERIODS:
        return 0
    return int(days) if all(k in allowed for k in card.get("filters") or {}) else 0


def day_end(days_ago: int, today: Optional[date] = None) -> datetime:
    """The end of the day ``days_ago`` days before ``today``: midnight after it."""
    return datetime.combine((today or date.today()) - timedelta(days=days_ago - 1), time())


def changes(source: str, now: Dict[str, Optional[float]], then: Dict[str, Optional[float]], days: int,
            today: Optional[date] = None) -> Dict[str, dict]:
    """Each card's change from ``then`` (its value at the end of the day ``days`` ago) to ``now``,
    as the card shows it. A card with no value then is left out."""
    day = (today or date.today()) - timedelta(days=days)
    out = {}
    for key, fig in FIGURES[source].items():
        if now.get(key) is None or then.get(key) is None:
            continue
        delta = round(now[key] - then[key], fig.digits)
        direction = "up" if delta > 0 else "down" if delta < 0 else ""
        if direction:
            text = f"{abs(delta):,.{fig.digits}f}{fig.unit} {PERIODS[days]}"
            tone = "good" if direction == fig.better else "bad" if fig.better else "neutral"
        else:
            text, tone = f"No change {PERIODS[days]}", "neutral"
        out[key] = {"text": text, "direction": direction, "tone": tone,
                    "then": f"{then[key]:,.{fig.digits}f}{fig.unit}", "then_label": f"On {day.day} {day:%b}"}
    return out


def rule_health_then(db, client_id: str, rules: List, scope: Optional[str], at: datetime) -> Dict[str, Optional[float]]:
    """Total Rules, Enabled, Validated and Avg Quality as they stood at ``at``, for the rules a
    Rule Health section counts now (``rules``, filtered to ``scope``, "<siem_id>|<space>", or
    not) that existed then, and those it counted then that have gone since: deleted or, under a
    SIEM filter, deprecated (a SIEM filter counts only what is there now).

    A rule existed once Kibana created it. It was on or off as its recorded changes say (each one
    since undone; a rule deleted since, with none, as its removal recorded it, else off). It was
    validated if its last check by then was within the client's period for its severity (today's
    periods); its score is its last one by then. Avg Quality is None when fewer than 9 in 10 of
    those rules had a score from today's scoring model then: earlier scores came from another
    model, or before TIDE kept score history.
    """
    siem, _, space = (scope or "").partition("|")
    with db.get_connection() as conn:
        created = {(r, s, sp): c for r, s, sp, c in conn.execute(
            "SELECT rule_id, siem_id, space, min(created_at) FROM rule_lifecycle_history "
            "WHERE action = 'created' GROUP BY ALL").fetchall()}
        gone = [k for k in conn.execute(
            "SELECT h.rule_id, h.siem_id, h.space FROM rule_lifecycle_history h WHERE h.action = 'deleted' "
            "AND NOT EXISTS (SELECT 1 FROM detection_rules r "
            "                WHERE r.rule_id = h.rule_id AND r.siem_id = h.siem_id AND r.space = h.space) "
            "GROUP BY ALL HAVING max(h.created_at) > ?", [at]).fetchall()
            if not scope or (k[1] == siem and str(k[2]).lower() == space.lower())]
        retired = [] if not scope else conn.execute(
            "SELECT r.rule_id, r.siem_id, r.space, COALESCE(NULLIF(r.kibana_rule_id, ''), r.rule_id), r.severity, "
            "       COALESCE(CAST(r.enabled AS BOOLEAN), false) "
            "FROM detection_rules r WHERE COALESCE(r.deprecated, false) AND r.siem_id = ? AND LOWER(r.space) = LOWER(?) "
            "  AND (SELECT max(h.created_at) FROM rule_lifecycle_history h WHERE h.rule_id = r.rule_id "
            "       AND h.siem_id = r.siem_id AND h.space = r.space AND h.action IN ('deprecated', 'moved')) > ?",
            [siem, space, at]).fetchall()
        # A check counts for every copy of the rule: validation follows Kibana's own rule id.
        checked = dict(conn.execute(
            "SELECT COALESCE(NULLIF(r.kibana_rule_id, ''), h.rule_id), max(h.created_at) "
            "FROM rule_lifecycle_history h LEFT JOIN detection_rules r "
            "  ON r.rule_id = h.rule_id AND r.siem_id = h.siem_id AND r.space = h.space "
            "WHERE h.action = 'validated' AND h.created_at <= ? GROUP BY 1", [at]).fetchall())
        try:                               # each rule's latest check, imported ones included
            for vkey, when in conn.execute("SELECT rule_id, max(last_checked_on) FROM checkedRule "
                                           "WHERE rule_id IS NOT NULL AND last_checked_on <= ? GROUP BY 1", [at]).fetchall():
                checked[vkey] = max(when, checked.get(vkey, when))
        except Exception:
            logger.debug("No checkedRule table yet", exc_info=True)
        scores = {(r, s, sp): (score, version) for r, s, sp, score, version in conn.execute(
            "SELECT rule_id, siem_id, space, arg_max(score, created_at), arg_max(scoring_version, created_at) "
            "FROM rule_score_history WHERE created_at <= ? GROUP BY ALL", [at]).fetchall()}
        switches = _enabled_changes(conn)

    amber: Dict[str, int] = {}

    def valid(vkey: str, latest: Optional[datetime], severity) -> bool:
        dates = [d for d in (checked.get(vkey), latest) if d is not None and d <= at]
        if not dates:
            return False
        sev = str(getattr(severity, "value", severity) or "low").lower()
        if sev not in amber:
            amber[sev] = db.get_client_validation_thresholds(client_id, severity=sev)[0]
        return (at - max(dates)).days / 7 <= amber[sev]       # as Rule Health ages a check today

    # (key, validation key, latest check, severity, on now): a rule deleted since has no Kibana
    # id, severity or state left to read.
    rows = [((r.rule_id, r.siem_id, r.space), validation_key(r.rule_id, r.raw_data), r.validation_date,
             r.severity, bool(r.enabled)) for r in rules]
    rows += [(key, key[0], None, None, None) for key in gone]
    rows += [((rid, sid, sp), vkey, None, sev, on) for rid, sid, sp, vkey, sev, on in retired]
    then = [row for row in rows if created.get(row[0]) is None or created[row[0]] <= at]
    current = [scores[k][0] for k, *_ in then
               if k in scores and scores[k][1] == SCORING_VERSION and scores[k][0] is not None]
    return {
        "total": len(then),
        "enabled": sum(_was_on(switches.get(k, ()), at, on) for k, _, _, _, on in then),
        "validated": sum(valid(vkey, latest, sev) for _, vkey, latest, sev, _ in then),
        "quality": (round(sum(current) / len(current), 1)
                    if then and len(current) >= QUALITY_COVERAGE * len(then) else None),
    }


def _enabled_changes(conn) -> Dict[Tuple[str, str, str], List[Tuple[datetime, bool, Optional[bool]]]]:
    """Each rule's recorded on/off changes, oldest first, as ``(when, before, after)``: Enable and
    Disable, a sync's before and after, and a removal's last state (``after`` None)."""
    out: Dict[Tuple[str, str, str], list] = {}
    for rid, sid, sp, action, when, detail in conn.execute(
            "SELECT rule_id, siem_id, space, action, created_at, CAST(detail AS VARCHAR) FROM rule_lifecycle_history "
            "WHERE action IN ('enabled', 'disabled') OR CAST(detail AS VARCHAR) LIKE '%\"enabled\"%' "
            "ORDER BY created_at").fetchall():
        if action in ("enabled", "disabled"):
            change = (action == "disabled", action == "enabled")
        else:
            try:
                d = json.loads(detail or "{}")
            except ValueError:
                continue
            diff = next((x for x in d.get("field_diffs") or [] if x.get("field") == "enabled"), None)
            if diff:
                change = (_flag(diff.get("before")), _flag(diff.get("after")))
            elif action == "deleted" and "enabled" in d:
                change = (bool(d["enabled"]), None)
            else:
                continue
        out.setdefault((rid, sid, sp), []).append((when, *change))
    return out


def _flag(text) -> bool:
    """A recorded on/off value ("True", "1", "-" ...) as a bool."""
    return str(text).strip().lower() in ("true", "1", "yes", "on")


def _was_on(changes, at: datetime, now: Optional[bool]) -> bool:
    """Whether a rule was enabled at ``at``: as before its first change since; else as it is now;
    else (a rule gone since) as its last change by then left it, or off."""
    since = [before for when, before, _ in changes if when > at]
    if since:
        return since[0]
    if now is not None:
        return now
    earlier = [after for when, _, after in changes if when <= at and after is not None]
    return earlier[-1] if earlier else False


# ── coverage: a system's techniques on an earlier day ─────────────────────────────────────────

_MARKS = ("gap_added", "gap_removed", "gap_edited", "na_added", "na_removed", "na_edited")


def history_start(db) -> Optional[datetime]:
    """When TIDE began keeping technique history (Migration 70, the 6.0 upgrade, or the install).
    Removals before then were never recorded, so no coverage figure is worked out for earlier."""
    try:
        with db.get_shared_connection(read_only=True) as conn:
            row = conn.execute("SELECT min(applied_at) FROM schema_version WHERE version = 70").fetchone()
        return row[0] if row else None
    except Exception:
        logger.warning("Could not read when technique history began", exc_info=True)
        return None


def _mark_before(event: str, detail: Optional[str]) -> set:
    """A known gap / N/A mark as it was just before ``event`` changed it."""
    kind = "na" if event.startswith("na") else "gap"
    if event.endswith("_added"):
        return set()
    if event.endswith("_edited") and "→" in (detail or ""):      # its type changed: it was the other
        return {"gap" if kind == "na" else "na"}
    return {kind}


def techniques_then(db, client_id: str, system_id: str, moments: List[datetime]) -> Dict[datetime, Optional[List[dict]]]:
    """Each of a system's techniques as it stood at each of ``moments``: ``{step_id, baseline_id,
    status, mapped, uncounted, undefined}`` for every technique the system had then, or None for
    a moment TIDE can't work out (before its technique history began, or when it can't tell which
    destinations the system counted then).

    Replayed from the technique history. A technique existed from when it was added, or its
    baseline applied, until it or its baseline was removed. Today's rule mappings count from when
    each was made, as they are now (rule, destination, where applied); a removed one from its own
    events, while it existed. Known gaps and N/A, non-alerting coverage and the destinations the
    system counts are today's with each change since undone; a removed technique's are replayed
    from its events. Rule links are today's.
    """
    from app.inventory_engine import _technique_status
    start = history_start(db)
    with db.get_connection() as conn:
        def q(sql, *args):
            return conn.execute(sql, list(args)).fetchall()
        live = dict(q("SELECT s.id, s.playbook_id FROM playbook_steps s JOIN playbooks p ON p.id = s.playbook_id "
                      "WHERE p.system_id = ?", system_id))
        baseline_start = dict(q("SELECT playbook_id, applied_at FROM system_baselines WHERE system_id = ?", system_id))
        events = q("SELECT event, step_id, baseline_id, detection_id, rule_id, siem_id, COALESCE(space, 'default'), "
                   "COALESCE(source, 'manual'), detail, created_at FROM technique_events WHERE system_id = ? "
                   "ORDER BY created_at", system_id)
        maps = q("SELECT sd.id, sd.step_id, sd.rule_ref, sd.siem_id, COALESCE(sd.space, 'default'), "
                 "COALESCE(sd.source, 'manual'), COALESCE(sd.created_at, TIMESTAMP '1970-01-01') FROM step_detections sd "
                 "JOIN playbook_steps s ON s.id = sd.step_id JOIN playbooks p ON p.id = s.playbook_id "
                 "WHERE p.system_id = ? AND COALESCE(sd.source, 'manual') <> 'sigma'", system_id)
        applied = {r[0] for r in q("SELECT DISTINCT detection_id FROM applied_detections "
                                   "WHERE (system_id = ? AND host_id IS NULL) "
                                   "   OR host_id IN (SELECT id FROM hosts WHERE system_id = ?)", system_id, system_id)}
        marks: Dict[str, set] = {}
        for step, kind in q("SELECT entity_id, COALESCE(override_type, 'gap') FROM blind_spots "
                            "WHERE entity_type = 'tactic' AND system_id = ?", system_id):
            marks.setdefault(step, set()).add(kind)
        try:
            watched = dict(q("SELECT c.step_id, count(*) FROM step_coverage c JOIN playbook_steps s ON s.id = c.step_id "
                             "JOIN playbooks p ON p.id = s.playbook_id WHERE p.system_id = ? GROUP BY 1", system_id))
        except Exception:
            watched = {}
        counted_now = {(s, sp or "default") for s, sp in
                       q("SELECT siem_id, space FROM system_coverage_destinations WHERE system_id = ?", system_id)}

    # Each technique: its baseline, and when it came and went.
    step_baseline, added, ended, baseline_end = dict(live), {}, {}, {}
    by_step: Dict[str, list] = {}
    siem_events, gone_maps, unmapped, relinked = [], {}, {}, {}
    for event, step, baseline, det, rule, siem, space, source, detail, when in events:
        if step and baseline:
            step_baseline.setdefault(step, baseline)
        if event == "technique_added":
            added.setdefault(step, when)
        elif event == "technique_removed":
            ended[step] = when
        elif event == "baseline_applied":
            baseline_start.setdefault(baseline, when)
        elif event == "baseline_removed":
            baseline_end[baseline] = when
        elif event in ("siem_counted", "siem_uncounted", "siem_coverage"):
            siem_events.append((event, siem, space, detail, when))
        elif event == "rule_mapped" and source != "sigma" and det:
            gone_maps.setdefault(det, (step, rule, siem, space, source, when))
        elif event == "rule_unmapped" and det:
            unmapped[det] = when
        elif event == "rule_relinked" and det:
            relinked[det] = (rule, siem, space)
        if step and (event in _MARKS or event.startswith("coverage_")):
            by_step.setdefault(step, []).append((event, detail, when))
    for step, baseline in step_baseline.items():
        if step not in live and step not in ended and baseline in baseline_end:
            ended[step] = baseline_end[baseline]       # removed with its baseline, before 6.2.4 said so
    window = {step: (added.get(step) or baseline_start.get(step_baseline.get(step)), ended.get(step))
              for step in set(live) | set(ended)}

    # Each mapping: (step, rule, siem, space, source, made, ended, applied).
    mappings = [(step, rule, siem, space, source, made, None, det in applied)
                for det, step, rule, siem, space, source, made in maps]
    live_dets = {m[0] for m in maps}
    for det, (step, rule, siem, space, source, made) in gone_maps.items():
        end = unmapped.get(det) or (window[step][1] if step in window else None)
        if det not in live_dets and step in window and end:
            rule, siem, space = relinked.get(det, (rule, siem, space))
            mappings.append((step, rule, siem, space, source, made, end, True))
    by_step_maps: Dict[str, list] = {}
    for m in mappings:
        by_step_maps.setdefault(m[0], []).append(m)

    anchors = [(m[1], m[2], m[3]) for m in mappings if m[1] and m[2]]
    links = {key: {(e.get("siem_id"), str(e.get("space") or "default")) for e in entries if not e.get("missing")}
             for key, entries in (db.get_rule_links_bulk(anchors) or {}).items()} if anchors else {}
    names = _destination_keys(db, client_id) if any(e[0] == "siem_coverage" for e in siem_events) else {}

    def counted_at(at: datetime) -> Optional[set]:
        counted = set(counted_now)
        for event, siem, space, detail, when in reversed(siem_events):
            if when <= at:
                break
            if event == "siem_counted":
                counted.discard((siem, space))
            elif event == "siem_uncounted":
                counted.add((siem, space))
            else:                          # before 6.2.4: "now counts A, B; stopped counting C", by name
                for part in (detail or "").split("; "):
                    now_counts = part.startswith("now counts ")
                    listed = part[len("now counts " if now_counts else "stopped counting "):]
                    for name in filter(None, listed.split(", ")):
                        if name not in names:
                            return None
                        (counted.discard if now_counts else counted.add)(names[name])
        return counted

    def counts(m, counted: set) -> bool:
        if not counted or m[4] == "manual" or not m[2]:
            return True
        return bool(({(m[2], m[3])} | links.get((m[1], m[2], m[3]), set())) & counted)

    def marks_at(step: str, at: datetime) -> set:
        changes = [(e, d, w) for e, d, w in by_step.get(step, ()) if e in _MARKS]
        if step in live:
            since = [(e, d) for e, d, w in changes if w > at]
            return _mark_before(*since[0]) if since else marks.get(step, set())
        state: set = set()
        for event, _, when in changes:
            if when <= at:
                state = set() if event.endswith("_removed") else {"na" if event.startswith("na") else "gap"}
        return state

    def watched_at(step: str, at: datetime) -> int:
        cov = [(e, w) for e, _, w in by_step.get(step, ()) if e in ("coverage_added", "coverage_removed")]
        if step in live:
            return watched.get(step, 0) - sum(1 if e == "coverage_added" else -1 for e, w in cov if w > at)
        return sum(1 if e == "coverage_added" else -1 for e, w in cov if w <= at)

    out: Dict[datetime, Optional[List[dict]]] = {}
    for at in moments:
        counted = None if start and at < start else counted_at(at)
        if counted is None:
            out[at] = None
            continue
        rows = []
        for step, (began, gone) in window.items():
            if (began is not None and began > at) or (gone is not None and gone <= at):
                continue
            present = [m for m in by_step_maps.get(step, ()) if m[5] <= at and (m[6] is None or m[6] > at)]
            counting = [m for m in present if counts(m, counted)]
            kinds = marks_at(step, at)
            status = _technique_status(any(m[7] for m in counting), "gap" in kinds, "na" in kinds,
                                       watched_at(step, at) > 0)
            rows.append({"step_id": step, "baseline_id": step_baseline.get(step), "status": status,
                         "mapped": len(present), "uncounted": len(present) - len(counting),
                         "undefined": not counted})
        out[at] = rows
    return out


def _destination_keys(db, client_id: str) -> Dict[str, Tuple[str, str]]:
    """A client's destinations by the name TIDE recorded them under, for history written before
    6.2.4 that names them only. A name two destinations share is left out: it can't be told apart."""
    seen: Dict[str, list] = {}
    for d in db.get_client_siems(client_id) or []:
        space = d.get("space") or "default"
        seen.setdefault(d.get("name") or d.get("label") or space, []).append((d.get("id"), space))
    return {name: keys[0] for name, keys in seen.items() if len(keys) == 1}


def coverage_figures(rows: List[dict]) -> Dict[str, Optional[int]]:
    """A system's cards for these techniques, as its page works them out (Covered: of those
    scored, as a whole percentage; None when nothing is scored or no destination is counted)."""
    count = lambda status: sum(1 for r in rows if r["status"] == status)  # noqa: E731
    scored = len(rows) - count("grey")
    undefined = any(r["undefined"] for r in rows)
    return {
        "covered": None if undefined or not scored else int(round(count("green") / scored * 100)),
        "techniques": len(rows), "no_coverage": count("red"), "known_gaps": count("amber"),
        "unmapped": sum(1 for r in rows if not r["mapped"]),
        "not_counted": sum(1 for r in rows if r["uncounted"]),
    }


def system_then(db, client_id: str, system_id: str, at: datetime, now: Dict[str, Optional[int]]) -> Dict[str, Optional[int]]:
    """A System section's cards as they stood at ``at``. Each is left out unless replaying the
    history to now gives today's figure (``now``): a history TIDE can't fully replay shows no
    change rather than a wrong one."""
    moment = datetime.now()
    states = techniques_then(db, client_id, system_id, [at, moment])
    if states[at] is None or states[moment] is None:
        return {}
    then, replayed = coverage_figures(states[at]), coverage_figures(states[moment])
    return {key: value for key, value in then.items() if replayed[key] == now.get(key)}


def weekly_coverage(db, client_id: str, system_id: str, baseline_ids: List[str], weeks: int = 52) -> List[dict]:
    """Each of ``baseline_ids``' techniques by status at the end of each week, back to when the
    technique history began (at most ``weeks``), oldest first and ending now: ``{day, baseline_id,
    green, amber, red, grey, covered}`` (``covered``: a whole percentage of those scored). A week
    TIDE can't work out, or with no destination counted, is left out."""
    start, now = history_start(db), datetime.now()
    moments = [day_end(7 * k) for k in range(weeks - 1, 0, -1)] + [now]
    moments = [m for m in moments if not start or m >= start]
    states = techniques_then(db, client_id, system_id, moments) if moments else {}
    points = []
    for at in moments:
        rows = states[at]
        if rows is None or any(r["undefined"] for r in rows):
            continue
        for baseline in baseline_ids:
            statuses = [r["status"] for r in rows if r["baseline_id"] == baseline]
            if not statuses:
                continue
            n = {s: statuses.count(s) for s in ("green", "amber", "red", "grey")}
            scored = len(statuses) - n["grey"]
            points.append({"day": now.date() if at is now else (at - timedelta(days=1)).date(),
                           "baseline_id": baseline, **n,
                           "covered": int(round(n["green"] / scored * 100)) if scored else 0})
    return points


def baseline_figures(rows: List[dict]) -> Dict[str, int]:
    """The Baselines section's coverage cards for these techniques, by the baseline each belongs
    to, as the Baselines page works them out: rules mapped; baselines with a technique with no
    coverage; baselines with none, no known gap, and something covered."""
    by_baseline: Dict[str, set] = {}
    for r in rows:
        by_baseline.setdefault(r["baseline_id"], set()).add(r["status"])
    return {"rules_mapped": sum(r["mapped"] for r in rows),
            "uncovered": sum(1 for s in by_baseline.values() if "red" in s),
            "fully_covered": sum(1 for s in by_baseline.values() if not s & {"red", "amber"} and "green" in s)}


def baselines_then(db, client_id: str, systems: List[str], at: datetime, now: Dict[str, int]) -> Dict[str, int]:
    """A Baselines section's Rules Mapped, Uncovered and Fully Covered as they stood at ``at``,
    across ``systems`` (those there are now), each replayed as ``techniques_then`` does. Each is
    left out unless replaying to now gives today's figure (``now``)."""
    moment = datetime.now()
    rows: Dict[datetime, list] = {at: [], moment: []}
    for system_id in systems:
        states = techniques_then(db, client_id, system_id, [at, moment])
        if states[at] is None or states[moment] is None:
            return {}
        for when in rows:          # a baseline id is one system's, so the systems' rows add up
            rows[when] += states[when]
    then, replayed = baseline_figures(rows[at]), baseline_figures(rows[moment])
    return {key: value for key, value in then.items() if replayed[key] == now.get(key)}
