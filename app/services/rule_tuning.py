"""Rule tuning: what people record of a rule's alerts, and marking rules for tuning.

An outcome is what one alert, or several, turned out to be (``OUTCOMES``). A person with write on Rule
Tuning records them on a rule with **Record outcome…**: an outcome, how many alerts, a note, and
whether the rule needs tuning. Needs tuning opens the rule's mark, or adds to the one open: a rule has
at most one open mark, made of the entries recorded with Needs tuning since it opened. **Mark as
tuned…** closes it as tuned and keeps the rule's figures at that moment, so the window can show the
effect ``EFFECT_DAYS`` later; **Dismiss…** closes it with nothing changed. Rule Monitoring lists an
open mark as Marked for tuning (``rule_issues``), its cause the mark's main outcome.

Shares are worked out over *judged* alerts (``JUDGED``) in the last ``WINDOW_DAYS``, and shown only
from ``MIN_JUDGED`` of them. Everything is kept in the client's own database, keyed by the rule's
``(rule_id, siem_id, space)`` as every rule's data is.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

from app.services.search_query import SearchQuery

Key = Tuple[str, str, str]          # (rule_id, siem_id, space)

WINDOW_DAYS = 30        # outcomes are counted over this many days
MIN_JUDGED = 10         # a share is shown from this many judged alerts
EFFECT_DAYS = 14        # Mark as tuned compares this many days before and after
MAX_ALERTS = 100_000
MAX_NOTE = 1000


@dataclass(frozen=True)
class Outcome:
    key: str
    label: str
    meaning: str
    counts: str         # "actionable", "not_actionable", "excluded" (left out of the shares) or "missed"
    fixer: str          # who fixes what it calls for: a rule_issues.FIXERS key, or "" (nothing to fix)
    tune: bool          # Needs tuning is ticked by default


OUTCOMES: Dict[str, Outcome] = {o.key: o for o in (
    Outcome("true_positive", "True positive",
            "Malicious or unwanted activity the rule was written to catch.", "actionable", "", False),
    Outcome("benign_true_positive", "Benign true positive",
            "The rule caught what it was written to catch, but the activity was expected or authorised: admin "
            "tools, scanners, backup jobs, a pen test.", "not_actionable", "author", True),
    Outcome("false_positive", "False positive",
            "The rule fired on activity it wasn't meant to catch: its logic is too broad or wrong.",
            "not_actionable", "author", True),
    Outcome("false_positive_data", "False positive (bad data)",
            "The alert came from wrong, incomplete or misparsed data: a parser, a mapping, clock skew.",
            "not_actionable", "engineer", True),
    Outcome("duplicate", "Duplicate", "Another alert or rule had already raised it.", "not_actionable", "author", True),
    Outcome("undetermined", "Undetermined", "It couldn't be decided from the alert and the logs.",
            "excluded", "author", False),
    Outcome("test", "Test", "Raised by a test: a purple team exercise, an atomic test, a validation.",
            "excluded", "", False),
    Outcome("missed", "Missed detection",
            "The rule should have fired and didn't: the activity was found some other way.", "missed", "author", True),
)}
JUDGED = tuple(k for k, o in OUTCOMES.items() if o.counts in ("actionable", "not_actionable"))
NOT_ACTIONABLE = tuple(k for k, o in OUTCOMES.items() if o.counts == "not_actionable")

MARKS_DDL = """
    CREATE TABLE IF NOT EXISTS rule_tuning_marks (
        id           VARCHAR PRIMARY KEY,
        rule_id      VARCHAR NOT NULL,
        siem_id      VARCHAR NOT NULL,
        space        VARCHAR NOT NULL,
        outcome      VARCHAR NOT NULL,     -- a key of OUTCOMES
        alerts       INTEGER NOT NULL DEFAULT 1,
        note         VARCHAR,
        needs_tuning BOOLEAN NOT NULL,     -- part of the rule's mark while closed_at is NULL
        by_name      VARCHAR NOT NULL,     -- the TIDE user's display name
        recorded_at  TIMESTAMP NOT NULL,
        closed_at    TIMESTAMP,
        closed_by    VARCHAR,
        closed_how   VARCHAR,              -- 'tuned' or 'dismissed'
        closed_note  VARCHAR
    )
"""
# One row per mark closed as tuned: the figures before, and once EFFECT_DAYS have passed, after.
EFFECTS_DDL = """
    CREATE TABLE IF NOT EXISTS rule_tuning_effects (
        id                   VARCHAR PRIMARY KEY,
        rule_id              VARCHAR NOT NULL,
        siem_id              VARCHAR NOT NULL,
        space                VARCHAR NOT NULL,
        tuned_at             TIMESTAMP NOT NULL,
        tuned_day            DATE NOT NULL,      -- UTC, as alerts are counted
        tuned_by             VARCHAR NOT NULL,
        note                 VARCHAR,
        outcome              VARCHAR,            -- the mark's main outcome
        changes              VARCHAR,            -- JSON: the History entries named at the time
        alerts_a_day         DOUBLE,             -- the EFFECT_DAYS before; NULL when alerts weren't read
        not_actionable       DOUBLE,             -- over WINDOW_DAYS before; NULL below MIN_JUDGED
        after_alerts_a_day   DOUBLE,             -- the EFFECT_DAYS after, once they have passed
        after_not_actionable DOUBLE,
        after_at             TIMESTAMP
    )
"""


def ensure(conn) -> None:
    conn.execute(MARKS_DDL)
    conn.execute(EFFECTS_DDL)


def _has(conn, table: str) -> bool:
    return bool(conn.execute("SELECT 1 FROM duckdb_tables() WHERE database_name = current_database() "
                             "AND table_name = ?", [table]).fetchone())


def _keys_sql(keys: List[Key], alias: str = "") -> Tuple[str, list]:
    """A filter on ``keys`` as three arrays joined against (thousands of OR terms plan slowly)."""
    a = f"{alias}." if alias else ""
    return (f" AND EXISTS (SELECT 1 FROM (SELECT unnest(?::VARCHAR[]) AS r, unnest(?::VARCHAR[]) AS s, "
            f"unnest(?::VARCHAR[]) AS sp) k WHERE k.r = {a}rule_id AND k.s = {a}siem_id AND k.sp = {a}space)",
            [[k[0] for k in keys], [k[1] for k in keys], [k[2] for k in keys]])


def alerts_text(n: int) -> str:
    return f"{n:,} alert" if n == 1 else f"{n:,} alerts"


# ── recording ────────────────────────────────────────────────────────────────────────────────

def check(outcome: str, alerts: Any, note: Any) -> Tuple[Optional[Tuple[str, int, str]], str]:
    """A Record outcome dialog's fields as stored, ``(outcome, alerts, note)``, or why they can't be."""
    if outcome not in OUTCOMES:
        return None, "Choose an outcome."
    try:
        n = int(str(alerts if alerts not in (None, "") else 1).strip())
    except ValueError:
        n = 0
    if not 1 <= n <= MAX_ALERTS:
        return None, f"Give how many alerts, from 1 to {MAX_ALERTS:,}."
    return (outcome, n, str(note or "").strip()[:MAX_NOTE]), ""


def record(conn, key: Key, outcome: str, alerts: int, note: str, needs_tuning: bool, by: str,
           now: Optional[datetime] = None) -> str:
    """Record an outcome on the rule ``key``: returns ``"marked"`` when it opened the rule's mark,
    ``"added"`` when it added to the one open, ``"recorded"`` when it doesn't need tuning."""
    ensure(conn)
    opened = needs_tuning and not open_marks(conn, [key])
    conn.execute("INSERT INTO rule_tuning_marks (id, rule_id, siem_id, space, outcome, alerts, note, needs_tuning, "
                 "by_name, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                 [str(uuid.uuid4()), *key, outcome, int(alerts), note or None, bool(needs_tuning), by, now or datetime.now()])
    return "marked" if opened else "added" if needs_tuning else "recorded"


def close(conn, key: Key, how: str, by: str, note: str, now: Optional[datetime] = None) -> int:
    """Close the rule's open mark, ``how`` "tuned" or "dismissed". Returns how many entries it held."""
    if not _has(conn, "rule_tuning_marks"):
        return 0
    return len(conn.execute(
        "UPDATE rule_tuning_marks SET closed_at = ?, closed_by = ?, closed_how = ?, closed_note = ? "
        "WHERE rule_id = ? AND siem_id = ? AND space = ? AND needs_tuning AND closed_at IS NULL RETURNING 1",
        [now or datetime.now(), by, how, note or None, *key]).fetchall())


def _entry(row) -> Dict[str, Any]:
    outcome, alerts, note, by, at = row
    o = OUTCOMES.get(outcome)
    return {"outcome": outcome, "label": o.label if o else outcome, "alerts": int(alerts), "note": note or "",
            "by": by, "at": at}


def entry_text(e: Dict[str, Any]) -> str:
    """One entry as a mark's detail and its window name it: who, when, how many alerts, the outcome, the note."""
    note = f': "{e["note"]}"' if e["note"] else ""
    return f"{e['by']}, {e['at']:%d %b}: {alerts_text(e['alerts'])}, {e['label'].lower()}{note}"


def _main(entries: List[Dict[str, Any]]) -> str:
    """A mark's main outcome: the one with most alerts, the latest of those tied."""
    totals: Dict[str, List[Any]] = {}
    for e in entries:
        t = totals.setdefault(e["outcome"], [0, e["at"]])
        t[0] += e["alerts"]
        t[1] = max(t[1], e["at"])
    return max(totals, key=lambda k: (totals[k][0], totals[k][1])) if totals else ""


def open_marks(conn, keys: Optional[Iterable[Key]] = None) -> Dict[Key, Dict[str, Any]]:
    """Each rule's open mark: ``{key: {since, entries (newest first), outcome (its main one), label,
    fixer, alerts}}``, for ``keys`` or every rule."""
    if not _has(conn, "rule_tuning_marks"):
        return {}
    where, params = "", []
    if keys is not None:
        keys = sorted(set(keys))
        if not keys:
            return {}
        where, params = _keys_sql(keys)
    out: Dict[Key, Dict[str, Any]] = {}
    for rule_id, siem_id, space, *rest in conn.execute(
            "SELECT rule_id, siem_id, space, outcome, alerts, note, by_name, recorded_at FROM rule_tuning_marks "
            "WHERE needs_tuning AND closed_at IS NULL" + where + " ORDER BY recorded_at DESC", params).fetchall():
        out.setdefault((rule_id, siem_id, space), {"entries": []})["entries"].append(_entry(rest))
    for mark in out.values():
        main = _main(mark["entries"])
        mark.update(since=min(e["at"] for e in mark["entries"]), outcome=main, label=OUTCOMES[main].label,
                    fixer=OUTCOMES[main].fixer or "author", alerts=sum(e["alerts"] for e in mark["entries"]))
    return out


SHOWN_ENTRIES = 5


def mark_findings(conn, keys: Optional[Iterable[Key]] = None) -> Dict[Key, Tuple[str, str]]:
    """Rule Monitoring's Marked for tuning, one per open mark: ``{key: (cause, detail)}``, the cause
    its main outcome and the detail each entry, newest first."""
    out = {}
    for key, mark in open_marks(conn, keys).items():
        entries = mark["entries"]
        more = len(entries) - SHOWN_ENTRIES
        detail = "; ".join(entry_text(e) for e in entries[:SHOWN_ENTRIES]) + (f"; and {more} more" if more > 0 else "") + "."
        out[key] = (mark["label"], detail)
    return out


def fixer_of_cause(cause: str) -> str:
    """Who fixes a mark whose main outcome is ``cause`` (its label): the engineers for bad data."""
    return "engineer" if cause == OUTCOMES["false_positive_data"].label else "author"


# ── outcomes and shares ──────────────────────────────────────────────────────────────────────

def window(limits: Optional[Dict[str, int]] = None) -> Tuple[int, int]:
    """The client's outcome window in days, and the judged alerts a share needs (``rule_alerts.thresholds``)."""
    limits = limits or {}
    return int(limits.get("outcome_days") or WINDOW_DAYS), int(limits.get("outcome_min") or MIN_JUDGED)


def people(conn, keys: Iterable[Key], since: datetime, until: Optional[datetime] = None) -> Dict[Key, Dict[str, int]]:
    """The outcomes people recorded on each rule from ``since`` (to ``until``): ``{key: {outcome: alerts}}``."""
    keys = sorted(set(keys))
    if not keys or not _has(conn, "rule_tuning_marks"):
        return {}
    where, params = _keys_sql(keys)
    out: Dict[Key, Dict[str, int]] = {}
    for rule_id, siem_id, space, outcome, n in conn.execute(
            "SELECT rule_id, siem_id, space, outcome, sum(alerts) FROM rule_tuning_marks WHERE recorded_at >= ? AND recorded_at <= ?"
            + where + " GROUP BY ALL", [since, until or datetime.max, *params]).fetchall():
        out.setdefault((rule_id, siem_id, space), {})[outcome] = int(n)
    return out


def detail(conn, keys: Iterable[Key], since: datetime, until: Optional[datetime] = None) -> Dict[Key, Dict[str, Any]]:
    """Each rule's outcomes from ``since`` (to ``until``), from Kibana (``rule_outcomes``, by the alerts'
    days) and from people: ``{key: {counts, source, by_source, none, in_closed_case}}``. Kibana's decide
    ``counts`` when the rule has any, else people's do (D10); ``source`` says which ("kibana", "people" or
    ""). ``by_source`` holds each source's own (``kibana_reason``, ``kibana_tag``, ``kibana_case``,
    ``person``); ``none`` the closed alerts with no outcome, ``in_closed_case`` those left open in a closed case."""
    from app.services import rule_outcomes
    keys = sorted(set(keys))
    if not keys:
        return {}
    until = until or datetime.now()
    kibana = rule_outcomes.by_rule(conn, keys, since.date(), until.date())
    person = people(conn, keys, since, until)
    out: Dict[Key, Dict[str, Any]] = {}
    for key in set(kibana) | set(person):
        k = kibana.get(key, {})
        by_source = {s: dict(c) for s, c in k.items() if s in rule_outcomes.KIBANA_SOURCES}
        counts: Dict[str, int] = {}
        for c in by_source.values():
            for o, n in c.items():
                counts[o] = counts.get(o, 0) + n
        if person.get(key):
            by_source["person"] = dict(person[key])
        out[key] = {"counts": counts or dict(person.get(key, {})),
                    "source": "kibana" if counts else "people" if person.get(key) else "",
                    "by_source": by_source, "none": sum(k.get("kibana_none", {}).values()),
                    "in_closed_case": sum(k.get("case_open", {}).values())}
    return out


def outcomes(conn, keys: Iterable[Key], since: datetime, until: Optional[datetime] = None) -> Dict[Key, Dict[str, int]]:
    """Each rule's outcomes from ``since`` (to ``until``), Kibana's or people's as D10 decides (``detail``):
    ``{key: {outcome: alerts}}``."""
    return {k: d["counts"] for k, d in detail(conn, keys, since, until).items() if d["counts"]}


def shares(counts: Dict[str, int], least: int = MIN_JUDGED) -> Dict[str, Any]:
    """What ``counts`` (``{outcome: alerts}``) come to: how many were judged, and from ``least`` of them
    the share not needing action and the share that were true positives (0 to 1), else None."""
    judged = sum(counts.get(k, 0) for k in JUDGED)
    enough = judged >= least
    return {"judged": judged,
            "not_actionable": sum(counts.get(k, 0) for k in NOT_ACTIONABLE) / judged if enough else None,
            "precision": counts.get("true_positive", 0) / judged if enough else None}


def not_actionable(conn, keys: Iterable[Key], now: Optional[datetime] = None,
                   limits: Optional[Dict[str, int]] = None) -> Dict[Key, Dict[str, Any]]:
    """Rule Health's Not actionable column: for each rule with outcomes in the client's window,
    ``{key: {judged, share}}`` (``share`` None below the judged alerts it needs)."""
    days, least = window(limits)
    since = (now or datetime.now()) - timedelta(days=days)
    out = {}
    for key, counts in outcomes(conn, keys, since).items():
        s = shares(counts, least)
        out[key] = {"judged": s["judged"], "share": s["not_actionable"]}
    return out


def cost(alerts_a_day: float, share: Optional[float]) -> float:
    """Alerts a day not needing action: all of them while too few were judged (an unjudged alert costs
    an analyst as much)."""
    return alerts_a_day * (share if share is not None else 1.0)


def _listed(counts: Dict[str, int]) -> List[Tuple[str, str, int]]:
    return [(k, o.label, counts[k]) for k, o in OUTCOMES.items() if counts.get(k)]


def summary(conn, key: Key, now: Optional[datetime] = None, limits: Optional[Dict[str, int]] = None,
            kibana_url: str = "") -> Dict[str, Any]:
    """The rule's outcomes over the client's window: ``{counts: [(key, label, alerts)] in OUTCOMES' order,
    source, sources: [(label, counts)] each source's own, none, judged, not_actionable, precision,
    last_true_positive (a date), cases}``; ``cases`` its latest closed cases, linked to Kibana at ``kibana_url``."""
    from app.services import rule_outcomes
    now = now or datetime.now()
    days, least = window(limits)
    d = detail(conn, [key], now - timedelta(days=days), now).get(key) or {"counts": {}, "source": "", "by_source": {},
                                                                         "none": 0, "in_closed_case": 0}
    last_tp = rule_outcomes.last_true_positive(conn, key)
    if _has(conn, "rule_tuning_marks"):
        row = conn.execute("SELECT max(recorded_at) FROM rule_tuning_marks WHERE outcome = 'true_positive' AND rule_id = ? "
                           "AND siem_id = ? AND space = ?", list(key)).fetchone()
        if row and row[0] and (not last_tp or row[0].date() > last_tp):
            last_tp = row[0].date()
    sources = [(rule_outcomes.SOURCE_LABELS[s], _listed(d["by_source"][s]))
               for s in (*rule_outcomes.KIBANA_SOURCES, "person") if d["by_source"].get(s)]
    return {"counts": _listed(d["counts"]), "source": d["source"], "sources": sources, "none": d["none"],
            **shares(d["counts"], least), "last_true_positive": last_tp, "days": days, "min_judged": least,
            "cases": rule_outcomes.latest_cases(conn, key, kibana_url)}


# ── Mark as tuned, and its effect ─────────────────────────────────────────────────────────────

def changes_since(conn, key: Key, since: datetime) -> List[Dict[str, Any]]:
    """What History recorded on the rule since ``since`` that could have tuned it (edits, exceptions,
    upstream updates merged), each named as Alerts spiked names one: ``[{at, by, text}]``, oldest first."""
    from app.services.rule_issues import _CHANGE_ACTIONS, _change_text, _json
    if not _has(conn, "rule_lifecycle_history"):
        return []
    actions = [a for a in _CHANGE_ACTIONS if a != "created"]
    rows = conn.execute(
        f"SELECT created_at, actor_name, action, detail::VARCHAR FROM rule_lifecycle_history WHERE rule_id = ? "
        f"AND siem_id = ? AND space = ? AND created_at >= ? AND action IN ({', '.join('?' * len(actions))}) "
        f"ORDER BY created_at", [*key, since, *actions]).fetchall()
    return [{"at": at, "by": by or "", "text": _change_text(action, _json(detail, {}) or {})} for at, by, action, detail in rows]


def _uuid(conn, key: Key) -> str:
    row = conn.execute("SELECT json_extract_string(raw_data, '$.id') FROM detection_rules WHERE rule_id = ? "
                       "AND siem_id = ? AND space = ?", list(key)).fetchone()
    return (row[0] if row else "") or ""


def alerts_a_day(conn, key: Key, first: date, days: int) -> Optional[float]:
    """The rule's alerts a day over ``days`` UTC days from ``first``; None when its space's alerts were
    never read."""
    from app.services import rule_alerts
    rule_uuid = _uuid(conn, key)
    if not rule_uuid or not rule_alerts.reads(conn).get((key[1], key[2])):
        return None
    row = conn.execute("SELECT COALESCE(sum(alerts), 0) FROM rule_alert_counts WHERE siem_id = ? AND space = ? "
                       "AND rule_uuid = ? AND day BETWEEN ? AND ?",
                       [key[1], key[2], rule_uuid, first, first + timedelta(days=days - 1)]).fetchone()
    return int(row[0]) / days


def tuned(conn, key: Key, by: str, note: str, now: Optional[datetime] = None,
          limits: Optional[Dict[str, int]] = None) -> Optional[Dict[str, Any]]:
    """Mark as tuned: close the rule's open mark, keeping its figures now (alerts a day over the
    EFFECT_DAYS before, the share not needing action over the WINDOW_DAYS before) and the changes
    History recorded since it opened. Returns what was kept, or None when no mark was open."""
    from app.services import rule_alerts
    now = now or datetime.now()
    mark = open_marks(conn, [key]).get(key)
    if not mark:
        return None
    today = rule_alerts.today()
    changes = changes_since(conn, key, mark["since"])
    days, least = window(limits)
    before = shares(outcomes(conn, [key], now - timedelta(days=days), now).get(key, {}), least)
    row = {"id": str(uuid.uuid4()), "alerts_a_day": alerts_a_day(conn, key, today - timedelta(days=EFFECT_DAYS), EFFECT_DAYS),
           "not_actionable": before["not_actionable"], "changes": changes, "outcome": mark["outcome"]}
    conn.execute("INSERT INTO rule_tuning_effects (id, rule_id, siem_id, space, tuned_at, tuned_day, tuned_by, note, "
                 "outcome, changes, alerts_a_day, not_actionable) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                 [row["id"], *key, now, today, by, note or None, mark["outcome"],
                  json.dumps([{**c, "at": c["at"].isoformat() if c["at"] else None} for c in changes]),
                  row["alerts_a_day"], row["not_actionable"]])
    close(conn, key, "tuned", by, note, now)
    return row


def _after(conn, key: Key, tuned_at: datetime, tuned_day: date) -> Tuple[Optional[float], Optional[float]]:
    after = shares(outcomes(conn, [key], tuned_at, tuned_at + timedelta(days=EFFECT_DAYS)).get(key, {}))
    return alerts_a_day(conn, key, tuned_day + timedelta(days=1), EFFECT_DAYS), after["not_actionable"]


def ready(tuned_day: date, today: date) -> bool:
    """Whether the EFFECT_DAYS after a tuning have all passed (UTC days, as alerts are counted)."""
    return today > tuned_day + timedelta(days=EFFECT_DAYS)


def settle(conn, today: Optional[date] = None) -> int:
    """Keep the figures after each tuning whose EFFECT_DAYS have passed, once: alert counts only go
    back so far. Run as Rule Monitoring refreshes. Returns how many were kept."""
    from app.services import rule_alerts
    if not _has(conn, "rule_tuning_effects"):
        return 0
    today = today or rule_alerts.today()
    done = 0
    for eid, rule_id, siem_id, space, tuned_at, tuned_day in conn.execute(
            "SELECT id, rule_id, siem_id, space, tuned_at, tuned_day FROM rule_tuning_effects "
            "WHERE after_at IS NULL AND tuned_day < ?", [today - timedelta(days=EFFECT_DAYS)]).fetchall():
        a_day, share = _after(conn, (rule_id, siem_id, space), tuned_at, tuned_day)
        conn.execute("UPDATE rule_tuning_effects SET after_alerts_a_day = ?, after_not_actionable = ?, after_at = ? "
                     "WHERE id = ?", [a_day, share, datetime.now(), eid])
        done += 1
    return done


def _change(before: Optional[float], after: Optional[float]) -> Optional[int]:
    """The change from ``before`` to ``after`` in percent, rounded; None when either is unknown or before is 0."""
    if before is None or after is None or not before:
        return None
    return round((after - before) / before * 100)


def past(conn, key: Key, today: Optional[date] = None) -> List[Dict[str, Any]]:
    """The rule's tunings, newest first, each with its effect: ``[{at, by, note, label, changes,
    before, after, change, share_before, share_after, ready, from_day}]``. Figures after are the kept
    ones, else worked out now once the days have passed."""
    from app.services import rule_alerts
    if not _has(conn, "rule_tuning_effects"):
        return []
    today = today or rule_alerts.today()
    out = []
    for (tuned_at, tuned_day, by, note, outcome, changes, a_before, s_before, a_after, s_after,
         after_at) in conn.execute(
            "SELECT tuned_at, tuned_day, tuned_by, note, outcome, changes, alerts_a_day, not_actionable, "
            "after_alerts_a_day, after_not_actionable, after_at FROM rule_tuning_effects WHERE rule_id = ? "
            "AND siem_id = ? AND space = ? ORDER BY tuned_at DESC", list(key)).fetchall():
        is_ready = after_at is not None or ready(tuned_day, today)
        if after_at is None and is_ready:
            a_after, s_after = _after(conn, key, tuned_at, tuned_day)
        try:
            named = json.loads(changes or "[]")
        except ValueError:
            named = []
        out.append({"at": tuned_at, "by": by, "note": note or "", "outcome": outcome,
                    "label": OUTCOMES[outcome].label if outcome in OUTCOMES else "", "changes": named,
                    "before": a_before, "after": a_after if is_ready else None, "change": _change(a_before, a_after) if is_ready else None,
                    "share_before": s_before, "share_after": s_after if is_ready else None, "ready": is_ready,
                    "from_day": tuned_day + timedelta(days=EFFECT_DAYS + 1)})
    return out


NO_EFFECT_SHARE = 0.5      # a tuning helped when what it is judged by fell by at least half
NO_EFFECT_DAYS = 90        # a tuning is judged this long after it (alert counts go back no further)


def judged_change(before: Optional[float], share_before: Optional[float], after: Optional[float],
                  share_after: Optional[float]) -> Optional[Tuple[float, float, str]]:
    """What a tuning is judged by, before and after: alerts a day not needing action where both shares
    are known, else alerts a day. ``(before, after, what)``, or None when it can't be judged."""
    if before is None or after is None:
        return None
    if share_before is not None and share_after is not None:
        return before * share_before, after * share_after, "alerts a day not needing action"
    return before, after, "alerts a day"


def no_effect_findings(conn, keys: Iterable[Key], today: Optional[date] = None) -> Dict[Key, Tuple[str, str]]:
    """Rule Monitoring's Tuning didn't help, for the rules ``keys``: each one's latest tuning, in the last
    NO_EFFECT_DAYS and with its EFFECT_DAYS passed, after which what it is judged by (``judged_change``)
    fell by less than NO_EFFECT_SHARE. Not once the rule is marked for tuning again. ``{key: ("", detail)}``."""
    from app.services import rule_alerts
    keys = sorted(set(keys))
    if not keys or not _has(conn, "rule_tuning_effects"):
        return {}
    today = today or rule_alerts.today()
    where, params = _keys_sql(keys, "e")
    marked = open_marks(conn, keys)
    out: Dict[Key, Tuple[str, str]] = {}
    for rule_id, siem_id, space, tuned_at, tuned_day, by, a_before, s_before, a_after, s_after, after_at in conn.execute(
            "SELECT rule_id, siem_id, space, arg_max(tuned_at, tuned_at), arg_max(tuned_day, tuned_at), "
            "arg_max(tuned_by, tuned_at), arg_max(alerts_a_day, tuned_at), arg_max(not_actionable, tuned_at), "
            "arg_max(after_alerts_a_day, tuned_at), arg_max(after_not_actionable, tuned_at), arg_max(after_at, tuned_at) "
            "FROM rule_tuning_effects e WHERE tuned_day >= ?" + where + " GROUP BY ALL",
            [today - timedelta(days=NO_EFFECT_DAYS), *params]).fetchall():
        key = (rule_id, siem_id, space)
        if not ready(tuned_day, today) or (key in marked and marked[key]["since"] > tuned_at):
            continue
        if after_at is None:
            a_after, s_after = _after(conn, key, tuned_at, tuned_day)
        judged = judged_change(a_before, s_before, a_after, s_after)
        if not judged or not judged[0] or judged[1] <= judged[0] * (1 - NO_EFFECT_SHARE):
            continue
        b, a, what = judged
        change = _change(b, a)
        out[key] = ("", f"Tuned on {tuned_at:%d %b} by {by}: {what} {_per_day(b)} before, {_per_day(a)} in the "
                        f"{EFFECT_DAYS} days after ({change:+d}%), less than half off.")
    return out


# Rule Monitoring's findings from outcomes (5.4), over the client's window from the judged alerts it needs:
# (issue, the outcomes it counts, the client's threshold, its default %). No true positives looks back
# NO_TP_DAYS and needs NO_TP_MIN judged; Often undetermined counts undetermined among every verdict.
SHARE_FINDINGS = (("mostly_false_positives", ("false_positive",), "fp_share_pct", "false positives"),
                  ("bad_data_alerts", ("false_positive_data",), "bad_data_share_pct", "false positives from bad data"),
                  ("mostly_expected", ("benign_true_positive",), "expected_share_pct", "benign true positives"),
                  ("mostly_duplicates", ("duplicate",), "duplicate_share_pct", "duplicates"))
SHARE_DEFAULTS = {"fp_share_pct": 50, "bad_data_share_pct": 25, "expected_share_pct": 80, "duplicate_share_pct": 50}
UNDETERMINED_PCT = 50
NO_TP_DAYS, NO_TP_MIN = 90, 50
OUTCOME_ISSUES = tuple(f[0] for f in SHARE_FINDINGS) + ("often_undetermined", "no_true_positives")


def _from(d: Dict[str, Any]) -> str:
    """Where a rule's counts came from, as a finding's detail ends."""
    from app.services import rule_outcomes
    if d["source"] == "people":
        return "as people recorded them in TIDE"
    names = [rule_outcomes.SOURCE_LABELS[s].lower() for s in rule_outcomes.KIBANA_SOURCES if d["by_source"].get(s)]
    return "from Kibana's " + (", ".join(names[:-1]) + " and " + names[-1] if len(names) > 1 else names[0])


def outcome_findings(conn, keys: Iterable[Key], limits: Optional[Dict[str, int]] = None,
                     now: Optional[datetime] = None) -> Dict[Key, List[Tuple[str, str]]]:
    """Rule Monitoring's findings from what the rules' alerts turned out to be (Kibana's, else people's,
    D10): ``{key: [(issue, detail)]}``. Only one of mostly false positives, expected and duplicates can
    hold at the default thresholds."""
    keys = sorted(set(keys))
    if not keys:
        return {}
    limits = limits or {}
    now = now or datetime.now()
    days, least = window(limits)
    recent = detail(conn, keys, now - timedelta(days=days), now)
    longer = detail(conn, keys, now - timedelta(days=NO_TP_DAYS), now)
    out: Dict[Key, List[Tuple[str, str]]] = {}
    for key, d in recent.items():
        c = d["counts"]
        judged = sum(c.get(k, 0) for k in JUDGED)
        found = []
        if judged >= least:
            for issue, these, setting, words in SHARE_FINDINGS:
                n = sum(c.get(k, 0) for k in these)
                if n and n * 100 >= judged * int(limits.get(setting) or SHARE_DEFAULTS[setting]):
                    found.append((issue, f"{n:,} of {judged:,} judged alerts in {days} days were {words} "
                                         f"({n / judged:.0%}), {_from(d)}."))
        undetermined = c.get("undetermined", 0)
        verdicts = judged + undetermined
        if undetermined and verdicts >= least and undetermined * 100 >= verdicts * UNDETERMINED_PCT:
            found.append(("often_undetermined", f"{undetermined:,} of {verdicts:,} alerts given an outcome in {days} days "
                                                f"were undetermined ({undetermined / verdicts:.0%}), {_from(d)}."))
        if found:
            out[key] = found
    for key, d in longer.items():
        c = d["counts"]
        judged = sum(c.get(k, 0) for k in JUDGED)
        if judged >= NO_TP_MIN and not c.get("true_positive"):
            out.setdefault(key, []).append(("no_true_positives", f"None of its {judged:,} judged alerts in "
                                                                 f"{NO_TP_DAYS} days was a true positive, {_from(d)}."))
    return out


def _per_day(x: float) -> str:
    return f"{x:.1f}" if x < 10 else f"{x:,.0f}"


def dismissed(conn, key: Key) -> List[Dict[str, Any]]:
    """The rule's dismissed marks, newest first: ``[{at, by, note}]``."""
    if not _has(conn, "rule_tuning_marks"):
        return []
    return [{"at": at, "by": by, "note": note or ""} for at, by, note in conn.execute(
        "SELECT closed_at, any_value(closed_by), any_value(closed_note) FROM rule_tuning_marks WHERE rule_id = ? "
        "AND siem_id = ? AND space = ? AND closed_how = 'dismissed' GROUP BY closed_at ORDER BY closed_at DESC",
        list(key)).fetchall()]


# Rule Health's Tuning filter: (value, label).
TUNED_DAYS = 30
FILTER_STATES = (("marked", "Marked for tuning"), ("tuned", f"Tuned in the last {TUNED_DAYS} days"),
                 ("no_outcomes", "No outcomes"))


def filter_states(conn, limits: Optional[Dict[str, int]] = None) -> Dict[str, set]:
    """The rules each Tuning filter choice shows: ``{"marked": {key}, "tuned": {key}, "no_outcomes": {key}}``."""
    return {"marked": set(open_marks(conn)), "tuned": recently_tuned(conn, TUNED_DAYS),
            "no_outcomes": no_outcomes(conn, limits)}


def no_outcomes(conn, limits: Optional[Dict[str, int]] = None, now: Optional[datetime] = None) -> set:
    """The rules with alerts closed in the client's window and no outcome for them, from Kibana or people."""
    from app.services import rule_alerts
    if not (_has(conn, "rule_alert_counts") and _has(conn, "detection_rules")):
        return set()
    days, _least = window(limits)
    closed = {tuple(r) for r in conn.execute(
        "SELECT d.rule_id, d.siem_id, d.space FROM detection_rules d JOIN rule_alert_counts c ON c.siem_id = d.siem_id "
        "AND c.space = d.space AND c.rule_uuid = json_extract_string(d.raw_data, '$.id') WHERE c.status = 'closed' "
        "AND c.day >= ? GROUP BY ALL", [rule_alerts.today() - timedelta(days=days - 1)]).fetchall()}
    return closed - set(outcomes(conn, closed, (now or datetime.now()) - timedelta(days=days))) if closed else set()


def recently_tuned(conn, days: int = 30, now: Optional[datetime] = None) -> set:
    """The rules marked as tuned in the last ``days``, as keys."""
    if not _has(conn, "rule_tuning_effects"):
        return set()
    since = (now or datetime.now()) - timedelta(days=days)
    return {tuple(r) for r in conn.execute("SELECT DISTINCT rule_id, siem_id, space FROM rule_tuning_effects "
                                           "WHERE tuned_at >= ?", [since]).fetchall()}


# ── the Rule Tuning page ─────────────────────────────────────────────────────────────────────

SOURCES = (("people", "People"), ("kibana", "Kibana"), ("tide", "TIDE"))
SHOW = (("open", "Open"), ("tuned", f"Tuned in the last {TUNED_DAYS} days"))
SORTS = (("cost", "Not actionable a day (High → Low)"), ("alerts", "Alerts a day (High → Low)"),
         ("fp", "False positive share (High → Low)"), ("marked", "Marked (Newest first)"))
PAGE_DEFAULTS = {"show": "open", "sort": "cost"}


def reason_options() -> List[Tuple[str, str]]:
    """The Reason filter's choices: Rule Monitoring's tuning issues, by title."""
    from app.services.rule_issues import KNOWN
    return sorted(((i.id, i.title) for i in KNOWN.values() if i.kind == "tuning"), key=lambda o: o[1])


def page_filters(params) -> Dict[str, Any]:
    """The page's filters from a query string (its address, or the filter bar)."""
    from app.services.rule_issues import FIXERS, fixer_values

    def many(name, allowed):
        return [v for v in params.getlist(name) if v in allowed]

    def one(name, choices):
        value = params.get(name) or PAGE_DEFAULTS[name]
        return value if value in {c for c, _ in choices} else PAGE_DEFAULTS[name]

    return {"search": (params.get("search") or "").strip(), "scope": params.get("scope") or "",
            # Reason is sent as ``issue``, as Rule Monitoring's Issue is, so Raise issue for all shown reads it.
            "reason": many("issue", {k for k, _ in reason_options()}),
            "fixer": [f for f in fixer_values(params.getlist("fixer")) if f in FIXERS],
            "source": many("source", {k for k, _ in SOURCES}), "show": one("show", SHOW), "sort": one("sort", SORTS)}


def totals(conn, scopes: Iterable[Tuple[str, str]], since: datetime,
           until: Optional[datetime] = None) -> Tuple[Dict[str, int], int]:
    """The outcomes of every rule of ``scopes`` (its destinations) from ``since``, each rule's from Kibana
    or from people as D10 decides: ``({outcome: alerts}, closed alerts with no outcome)``."""
    from app.services import rule_outcomes
    scopes = sorted(set(scopes))
    if not scopes:
        return {}, 0
    until = until or datetime.now()
    out: Dict[str, int] = {}
    none = 0
    from_kibana = set()
    for (siem_id, space, uuid), by_source in rule_outcomes.scope_totals(conn, scopes, since.date(), until.date()).items():
        none += sum(by_source.get("kibana_none", {}).values())
        for source in rule_outcomes.KIBANA_SOURCES:
            for o, n in by_source.get(source, {}).items():
                out[o] = out.get(o, 0) + n
                from_kibana.add((siem_id, space, uuid))
    if _has(conn, "rule_tuning_marks"):
        for siem_id, space, uuid, o, n in conn.execute(
                "SELECT m.siem_id, m.space, json_extract_string(any_value(d.raw_data), '$.id'), m.outcome, sum(m.alerts) "
                "FROM rule_tuning_marks m LEFT JOIN detection_rules d ON d.rule_id = m.rule_id AND d.siem_id = m.siem_id "
                "AND d.space = m.space WHERE m.recorded_at >= ? AND m.recorded_at <= ? AND EXISTS (SELECT 1 FROM "
                "(SELECT unnest(?::VARCHAR[]) AS s, unnest(?::VARCHAR[]) AS sp) x WHERE x.s = m.siem_id AND x.sp = m.space) "
                "GROUP BY m.rule_id, m.siem_id, m.space, m.outcome",
                [since, until, [s for s, _ in scopes], [sp for _, sp in scopes]]).fetchall():
            if (siem_id, space, uuid or "") not in from_kibana:
                out[o] = out.get(o, 0) + int(n)
    return out, none


def _enrich(conn, rules: Dict[Key, Dict[str, Any]], now: datetime, limits: Optional[Dict[str, int]] = None) -> None:
    """Each rule's alerts a day (the last 7 days), outcomes (the client's window, Kibana's or people's) and
    shares, cost, open mark and open GitLab issues."""
    from app.services import gitlab_issues, rule_alerts, rule_issues
    keys = sorted(rules)
    if not keys:
        return
    days, least = window(limits)
    week = rule_alerts.per_rule(conn, keys, days=7)
    found = detail(conn, keys, now - timedelta(days=days), now)
    marks = open_marks(conn, keys)
    try:
        raised = gitlab_issues.about_rules(conn, rule_issues.cause_keys(rule_issues.rule_findings(conn, keys), keys),
                                           open_only=True)
    except Exception:                       # noqa: BLE001 - a row shows without its issues
        raised = {}
    for key, r in rules.items():
        d = found.get(key) or {"counts": {}, "source": "", "none": 0}
        c = d["counts"]
        s = shares(c, least)
        per_day = week.get(key, 0) / 7
        r.update(per_day=per_day, counts=[(k, o.label, c[k]) for k, o in OUTCOMES.items() if c.get(k)],
                 outcome_source=d["source"], none=d["none"],
                 judged=s["judged"], share=s["not_actionable"], cost=cost(per_day, s["not_actionable"]),
                 fp=(c.get("false_positive", 0) + c.get("false_positive_data", 0)) / s["judged"]
                 if s["not_actionable"] is not None else None,
                 mark=marks.get(key), issues=raised.get(key, []))
        # Who found its reasons: a person's mark; Kibana's outcomes (the outcome findings, D10); TIDE the rest.
        issues = {x["issue"] for x in r.get("reasons", [])}
        from_outcomes = issues & set(OUTCOME_ISSUES)
        r["sources"] = (["people"] if "marked_for_tuning" in issues or (from_outcomes and d["source"] == "people") else []) \
            + (["kibana"] if from_outcomes and d["source"] == "kibana" else []) \
            + (["tide"] if issues - set(OUTCOME_ISSUES) - {"marked_for_tuning"} else [])


def page(conn, destinations: List[Dict[str, Any]], filters: Dict[str, Any], client_id: Optional[str] = None,
         now: Optional[datetime] = None, limits: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    """Everything the Rule Tuning page shows for one client: ``rows`` (one per rule with an open tuning
    finding not muted, or, with Show *tuned*, one per rule tuned lately), sorted as asked; ``counts``
    per filter choice (with the other filters, not its own); ``metrics``, the four figures. A rule's
    reasons are Rule Monitoring's findings of kind tuning: TIDE's on enabled rules, a mark on any.
    ``limits`` are the client's settings (``rule_alerts.thresholds``)."""
    from app.services import rule_alerts, rule_issues
    now = now or datetime.now()
    days, least = window(limits)
    names = {(d["id"], str(d.get("space") or "default")) for d in destinations}
    scope = filters.get("scope") or ""
    data = rule_issues.view(conn, destinations, {"show": "open", "group": "rule", "rules": "all", "kind": ["tuning"],
                                                 "scope": scope}, now=now, client_id=client_id)
    rules: Dict[Key, Dict[str, Any]] = {}
    for f in data["rows"]:
        if not f["rule_id"] or f["ack"] or f["mute"] or not (f["enabled"] or f["issue"] == "marked_for_tuning"):
            continue
        key = (f["rule_id"], f["siem_id"], f["space"])
        r = rules.setdefault(key, {"key": key, "name": f["name"] or f["rule_id"], "destination": f["destination"],
                                   "enabled": f["enabled"], "reasons": [], "since": f["first_seen"]})
        r["reasons"].append({k: f[k] for k in ("issue", "title", "cause", "severity", "fixer", "fixer_label", "detail")})
        if f["first_seen"] and (not r["since"] or f["first_seen"] < r["since"]):
            r["since"] = f["first_seen"]
    _enrich(conn, rules, now, limits)

    tuned_keys = {k for k in recently_tuned(conn, TUNED_DAYS, now) if (k[1], k[2]) in names
                  and (not scope or f"{k[1]}|{k[2]}" == scope)}
    tuned: Dict[Key, Dict[str, Any]] = {}
    if tuned_keys:
        where, params = _keys_sql(sorted(tuned_keys))
        about = {(r, s, sp): n for r, s, sp, n in conn.execute(
            "SELECT rule_id, siem_id, space, name FROM detection_rules WHERE true" + where, params).fetchall()}
        dest = {(d["id"], str(d.get("space") or "default")): d.get("name") or d.get("space") for d in destinations}
        for key in tuned_keys:
            if key in about:
                tuned[key] = {**rules.get(key, {"reasons": [], "sources": [], "since": None}), "key": key,
                              "name": about[key] or key[0], "destination": dest.get((key[1], key[2]))}
        _enrich(conn, tuned, now, limits)
        for key, r in tuned.items():
            r["tuning"] = (past(conn, key) or [None])[0]

    def narrowed(rows: List[Dict[str, Any]], skip: str = "") -> List[Dict[str, Any]]:
        search = SearchQuery(filters.get("search"))
        out = []
        for r in rows:
            if skip != "reason" and filters.get("reason") and not {x["issue"] for x in r["reasons"]} & set(filters["reason"]):
                continue
            if skip != "fixer" and filters.get("fixer") and not {x["fixer"] for x in r["reasons"]} & set(filters["fixer"]):
                continue
            if skip != "source" and filters.get("source") and not set(r["sources"]) & set(filters["source"]):
                continue
            if search and not search.matches(r["name"], r["destination"],
                                             [x[k] for x in r["reasons"] for k in ("title", "cause", "detail")]):
                continue
            out.append(r)
        return out

    every = list((tuned if filters.get("show") == "tuned" else rules).values())
    counts = {"reason": {}, "fixer": {}, "source": {}}
    for field, values in (("reason", lambda r: {x["issue"] for x in r["reasons"]}),
                          ("fixer", lambda r: {x["fixer"] for x in r["reasons"]}), ("source", lambda r: set(r["sources"]))):
        for r in narrowed(every, field):
            for v in values(r):
                counts[field][v] = counts[field].get(v, 0) + 1
    shown = narrowed(every)
    order = {"cost": lambda r: (-r["cost"], r["name"].lower()), "alerts": lambda r: (-r["per_day"], r["name"].lower()),
             "fp": lambda r: (r["fp"] is None, -(r["fp"] or 0), -r["cost"], r["name"].lower()),
             "marked": lambda r: (r["mark"] is None, -(r["mark"]["since"].timestamp() if r["mark"] else 0), r["name"].lower())}
    shown.sort(key=order.get(filters.get("sort"), order["cost"]))

    # The figures, for the filters shown (the open rules: what is shown, unless Show is tuned).
    open_rows = narrowed(list(rules.values()))
    scopes = [k for k in names if not scope or f"{k[0]}|{k[1]}" == scope]
    all_alerts = sum(rule_alerts.recent(days, 7, rule_alerts.today()) for days in rule_alerts.daily(conn, scopes).values())
    client_counts, none = totals(conn, scopes, now - timedelta(days=days), now)
    client = shares(client_counts, least)
    effects = [r["tuning"] for r in tuned.values() if r.get("tuning")]
    saved = sum(t["before"] - t["after"] for t in effects if t["ready"] and t["before"] is not None and t["after"] is not None)
    metrics = {"rules": len(open_rows), "people": sum("people" in r["sources"] for r in open_rows),
               "kibana": sum("kibana" in r["sources"] for r in open_rows),
               "tide": sum("tide" in r["sources"] for r in open_rows),
               "per_day": sum(r["per_day"] for r in open_rows), "all_per_day": all_alerts / 7,
               "not_actionable": client["not_actionable"], "judged": client["judged"], "none": none,
               "tuned": len(tuned), "saved": saved, "ready": sum(1 for t in effects if t["ready"]),
               "days": days, "tuned_days": TUNED_DAYS, "min_judged": least}
    return {"rows": shown, "counts": counts, "metrics": metrics, "now": now}


# ── History, Raise issue ─────────────────────────────────────────────────────────────────────

HISTORY_ACTIONS = {"outcome_recorded": "Outcome recorded", "marked_for_tuning": "Marked for tuning",
                   "tuned": "Tuned", "tuning_dismissed": "Tuning dismissed"}


def record_text(outcome: str, alerts: int, note: str, needs_tuning: bool) -> str:
    """A Record outcome as the rule's History says it."""
    text = f"{alerts_text(alerts)}: {OUTCOMES[outcome].label.lower()}."
    if needs_tuning:
        text += " Needs tuning."
    return text + (f" {note}" if note else "")


def markdown(conn, key: Key, now: Optional[datetime] = None, limits: Optional[Dict[str, int]] = None) -> str:
    """Raise issue for a rule: its open mark's entries and its outcome counts, as tables. Empty when
    it has neither."""
    lines: List[str] = []
    mark = open_marks(conn, [key]).get(key)
    if mark:
        from app.services.rule_issues import KNOWN
        lines += [f"### Marked for tuning: {mark['label']}", "",
                  f"- **Who fixes:** {'Engineer' if mark['fixer'] == 'engineer' else 'Author'}",
                  f"- **Marked since:** {mark['since']:%Y-%m-%d}",
                  f"- **What it means:** {OUTCOMES[mark['outcome']].meaning}",
                  f"- **To fix:** {KNOWN['marked_for_tuning'].check}", "",
                  "| Recorded | By | Outcome | Alerts | Note |", "|---|---|---|---|---|"]
        lines += [f"| {e['at']:%Y-%m-%d} | {_cell(e['by'])} | {e['label']} | {e['alerts']:,} | {_cell(e['note'])} |"
                  for e in mark["entries"]]
        lines.append("")
    s = summary(conn, key, now, limits)
    if s["counts"]:
        where = "from Kibana" if s["source"] == "kibana" else "recorded by people"
        lines += [f"### Outcomes {where}, last {s['days']} days", "", "| Outcome | Alerts |", "|---|---|"]
        lines += [f"| {label} | {n:,} |" for _k, label, n in s["counts"]]
        lines.append("")
        if s["none"]:
            lines += [f"Closed with no outcome: {s['none']:,} alerts.", ""]
        if s["not_actionable"] is not None:
            lines += [f"Not needing action: {s['not_actionable']:.0%} of {s['judged']:,} judged alerts.", ""]
    return "\n".join(lines)


def _cell(text: Any) -> str:
    return str(text or "").replace("|", "\\|").replace("\n", " ")
