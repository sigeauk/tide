"""Rules that need action (Rule Monitoring, #67): what is wrong, who fixes it, and since when.

An issue is one known kind of problem (``KNOWN``) with a cause: what one fix clears, such as an index
pattern, or a field in a data stream. Rules failing for the same cause are one thing to fix, so the
page groups them. ``cause`` is "" when the problem is the rule's own (its query won't parse).

Found at each sync, from what the sync already read (no other calls to Kibana):
- Kibana's last run of each enabled rule (``execution_summary.last_execution``). Its message can hold
  several problems, one per paragraph; each is matched against the known ones, and a paragraph that
  none recognises is ``other``, by Kibana's own words;
- the field catalogue: index patterns matching no index, fields no index has or mapped with
  conflicting types, and the timestamp override field missing. For a rule whose last run Kibana
  already reported on those, Kibana's (more exact) report is used instead;
- TIDE's record of each destination: rules sharing a rule id, custom rules under one of Elastic's
  rule ids, syncs that couldn't read every rule, SIEMs that didn't answer.

Each finding is kept in the client's ``rule_issues`` table with when it was first and last seen and
when it was resolved (gone at a later sync). A destination not synced for ``STALE_DAYS`` (stale data)
is worked out when asked, from when it last synced.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

STALE_DAYS = 7           # a destination not synced for this long is stale (#65)
RESOLVED_DAYS = 14       # resolved issues are kept, and shown as resolved, this long
NEVER_RUN_AFTER = timedelta(hours=1)    # an enabled rule with no run this long after its last change

FIXERS = {"data": "Data / ingest", "author": "Rule author", "platform": "Kibana / platform", "tide": "TIDE"}


@dataclass(frozen=True)
class Issue:
    id: str
    title: str
    fixer: str          # a FIXERS key
    severity: str       # "error" (the rule doesn't do its job) or "warning" (it does, less well)
    level: str          # "rule": found per rule; "destination": one SIEM space as a whole
    meaning: str        # what it means, in plain words
    check: str          # what to check or do


KNOWN: Dict[str, Issue] = {i.id: i for i in (
    Issue("stale_data", "Rule data not synced recently", "tide", "error", "destination",
          "TIDE hasn't read this destination's rules for a while, so its scores, coverage and the issues listed "
          "here may be out of date.",
          "Sync the destination in TIDE. If the sync fails, Diagnostics → Sync activity says why."),
    Issue("no_index", "No index matches the index pattern", "data", "error", "rule",
          "The rule searches an index pattern that matches no index on this SIEM, so it finds nothing there.",
          "Check that the integration or pipeline writing to this index pattern is installed and sending data."),
    Issue("override_missing", "Indexes missing the timestamp override field", "data", "warning", "rule",
          "These indexes don't have the field the rule uses as its timestamp override, usually because the "
          "ingest pipeline that adds it doesn't run for them. Their events can be searched late or missed.",
          "Add the field in the ingest pipeline for these indexes (event.ingested is set by Elastic's default "
          "ingest pipeline), or change the rule's timestamp override."),
    Issue("field_missing", "Field not in the index mappings", "data", "warning", "rule",
          "The rule's query uses a field that none of its indexes map, so it can't match on that field.",
          "Check the data source sends the field (or that its pipeline creates it); if the name is wrong, "
          "correct the rule's query."),
    Issue("field_conflict", "Field mapped with conflicting types", "data", "warning", "rule",
          "The field has different types in different indexes the rule searches, so searches on it can fail "
          "or miss events in some of them.",
          "Map the field with one type in every index (index template or ingest pipeline)."),
    Issue("unknown_field", "Query uses a field Elasticsearch can't find", "author", "error", "rule",
          "Elasticsearch refused the rule's query because a field it names doesn't exist in the indexes.",
          "Check the field name in the query. If it is right, the data doesn't have the field yet."),
    Issue("query_syntax", "Query won't parse", "author", "error", "rule",
          "Kibana can't parse the rule's query, so the rule never runs a search.",
          "Correct the query's syntax; Kibana's message points at where it stopped."),
    Issue("query_invalid", "Query refused by Elasticsearch", "author", "error", "rule",
          "Elasticsearch refused the rule's query (an unknown function, or a query it can't run).",
          "Correct the query; Kibana's message says what Elasticsearch objected to."),
    Issue("privileges", "Missing index privileges", "platform", "warning", "rule",
          "The user whose API key runs the rule may lack read privileges on some of its indexes, or Kibana "
          "couldn't check them.",
          "Check the roles of the user who last saved the rule in Kibana: they need read on its index patterns."),
    Issue("max_alerts", "Reached the maximum alerts per run", "author", "warning", "rule",
          "The rule found more matches than it may turn into alerts in one run, so some weren't raised.",
          "Tune the rule to match less, or raise its maximum alerts per run."),
    Issue("gap", "Runs were missed", "platform", "warning", "rule",
          "Some of the rule's scheduled runs didn't happen, so events in those periods weren't searched.",
          "Check Kibana's task manager capacity; add Kibana instances or lengthen the rule's look-back."),
    Issue("timeout", "Search timed out", "platform", "warning", "rule",
          "The rule's search ran out of time, so its results may be incomplete.",
          "Check Elasticsearch load, or make the query cheaper."),
    Issue("overloaded", "Elasticsearch refused the search (overloaded)", "platform", "warning", "rule",
          "Elasticsearch turned the search away because it was short of memory or busy.",
          "Check the cluster's memory and load (circuit breakers, search queue)."),
    Issue("ml_job", "Machine learning job not running", "platform", "error", "rule",
          "The machine learning job the rule reads from isn't running, so the rule has nothing to alert on.",
          "Start the job in Kibana's Machine Learning, and check its datafeed."),
    Issue("schedule_gap", "Blind windows between runs", "author", "error", "rule",
          "The rule searches back less time than it waits between runs, so part of every interval is never "
          "searched: events there can't raise an alert, and Kibana doesn't report it as missed runs.",
          "Make the rule search back at least its run interval plus a margin: for example, runs every 5 minutes "
          "with 1 minute of additional look-back time (from now-6m)."),
    Issue("short_lookback", "Little or no additional look-back", "author", "warning", "rule",
          "The rule searches back little more than its run interval, so events that reach Elasticsearch late "
          "(normal ingest delay) fall between runs and are missed.",
          "Give the rule at least a minute of additional look-back time, more if its data arrives late, or use "
          "event.ingested as its timestamp override."),
    Issue("never_run", "Enabled but never run", "platform", "warning", "rule",
          "Kibana has no run recorded for this enabled rule.",
          "Check the rule in Kibana and Kibana's task manager."),
    Issue("siem_offline", "SIEM didn't answer at the last sync", "platform", "warning", "destination",
          "TIDE couldn't reach this destination at the last sync, so its rules are shown from TIDE's last copy.",
          "Check the SIEM is up, and its address and API key in Management → SIEMs, then sync again."),
    Issue("sync_incomplete", "Syncs couldn't read every rule", "tide", "warning", "destination",
          "At the last two syncs Kibana returned fewer rules than it said it holds, so rules deleted in Kibana "
          "haven't been marked deprecated here.",
          "Check the SIEM is healthy and look for 'Sync drift' in TIDE's log, then sync again."),
    Issue("sync_step_failed", "A step of the last sync failed", "tide", "warning", "destination",
          "The last sync read the rules, but a step TIDE runs after reading them failed, so what that step keeps "
          "(such as rule history, score history or Rule Monitoring itself) wasn't brought up to date.",
          "Sync again. If the step fails again, Settings → Diagnostics → Sync activity shows its error: report "
          "it with TIDE's log from that time."),
    Issue("shared_rule_id", "Rules sharing a rule id in Kibana", "tide", "warning", "rule",
          "Kibana holds a custom copy beside this prebuilt rule under the same rule id. TIDE shows only one.",
          "Open the rule and use Give the copy its own rule id."),
    Issue("custom_elastic_id", "Custom rule using one of Elastic's rule ids", "tide", "warning", "rule",
          "While it does, Kibana can't install Elastic's own rule in this space.",
          "Open the rule and use Give it its own rule id."),
    Issue("change_pending", "Change not finished in TIDE", "tide", "warning", "rule",
          "Kibana made a change TIDE asked for (giving the rule its own rule id, moving or copying it, or restoring "
          "it), but TIDE couldn't record it, so TIDE still shows the rule as it was before.",
          "Use Finish in TIDE on the rule. The next sync that reads the rule also finishes it."),
    Issue("other", "Other Kibana errors", "platform", "warning", "rule",
          "Kibana reported a problem with the rule's last run that TIDE doesn't recognise.",
          "Read Kibana's message on the rule, in Kibana's rule details or TIDE's rule window."),
)}


# ── Kibana's last-run message ────────────────────────────────────────────

def _list(text: str) -> List[str]:
    try:
        value = json.loads(text)
    except ValueError:
        value = re.findall(r'"([^"]+)"', text)
    return [str(v) for v in value] if isinstance(value, list) else []


def data_stream(index: str) -> str:
    """The data stream (or index) a concrete index belongs to: ``.ds-logs-x-default-2026.08.07-000002``
    is ``logs-x-default``; a rolled-over ``name-000001`` is ``name``."""
    m = re.match(r"^\.ds-(.+)-\d{4}\.\d{2}\.\d{2}-\d{6}$", index)
    return m.group(1) if m else re.sub(r"-\d{6}$", "", index)


def _duration(seconds: float) -> str:
    s = int(seconds)
    return (f"{s} s" if s < 90 else f"{round(s / 60)} min" if s < 5400
            else f"{round(s / 3600)} h" if s < 172800 else f"{round(s / 86400)} days")


MIN_EXTRA_LOOKBACK = 60          # seconds of look-back beyond the run interval below which late events are missed
_SPAN = re.compile(r"(\d+)([smhd])")
_SPAN_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _span(text) -> Optional[int]:
    """Kibana's '5m', '360s', '1h' in seconds; None for anything else."""
    m = _SPAN.fullmatch(str(text or "").strip())
    return int(m.group(1)) * _SPAN_SECONDS[m.group(2)] if m else None


def schedule_findings(interval, lookback_from) -> List[Tuple[str, str, str, str]]:
    """(issue, cause, severity, detail) for a rule's schedule, from its own JSON (#74): it runs every
    ``interval`` and searches back to ``from`` ('now-6m'). Searching back less than the interval leaves
    blind windows between runs; less than a minute more leaves late events unsearched. The cause is
    the schedule, so rules sharing one are fixed together."""
    every = _span(interval)
    m = re.fullmatch(r"now-(\d+[smhd])", str(lookback_from or "").replace(" ", ""))
    back = _span(m.group(1)) if m else None
    if not every or back is None:
        return []
    cause = f"Runs every {interval}, searches from {lookback_from}"
    if back < every:
        return [("schedule_gap", cause, KNOWN["schedule_gap"].severity,
                 f"Runs every {_duration(every)} but searches only the last {_duration(back)}: {_duration(every - back)} "
                 "of each interval is never searched.")]
    if back - every < MIN_EXTRA_LOOKBACK:
        extra = f"only {_duration(back - every)}" if back > every else "no"
        return [("short_lookback", cause, KNOWN["short_lookback"].severity,
                 f"Runs every {_duration(every)} and searches the last {_duration(back)}: {extra} additional look-back, "
                 "so events that reach Elasticsearch later than that are missed.")]
    return []


def _other_cause(part: str) -> str:
    """An unrecognised paragraph, normalised so the same problem on many rules is one cause."""
    line = part.strip().splitlines()[0] if part.strip() else ""
    line = re.sub(r"^An error occurred during rule execution:\s*(message:\s*)?", "", line)
    line = re.sub(r'"[^"]*"|\[[^\]]*\]|\b[0-9a-f]{8}-[0-9a-f-]{27,}\b|\d+(\.\d+)?', "…", line)
    return re.sub(r"\s+", " ", line).strip()[:140] or "No message"


# Each paragraph of Kibana's message is matched against these, in order: (issue, pattern, causes).
# ``causes`` turns the match into the cause(s) it names; None means the rule's own ("").
_MATCHERS: List[Tuple[str, "re.Pattern[str]", Optional[Callable[["re.Match[str]"], List[str]]]]] = [
    ("override_missing", re.compile(r'missing the timestamp override field "([^"]+)":\s*(\[[^\]]*\])'),
     lambda m: sorted({f"{m.group(1)} in {data_stream(i)}" for i in _list(m.group(2))}) or [m.group(1)]),
    ("no_index", re.compile(r"no index matching:?\s*(\[[^\]]*\])"), lambda m: _list(m.group(1))),
    ("no_index", re.compile(r"index_not_found_exception.*?no such index \[([^\]]+)\]", re.S), lambda m: [m.group(1)]),
    ("privileges", re.compile(r"Check privileges failed|required read privileges|missing .{0,40}privileges",
                              re.I), None),
    ("unknown_field", re.compile(r"Unknown column \[([^\]]+)\]"), lambda m: [m.group(1)]),
    ("query_syntax", re.compile(r"Expected .{1,200}? but .{1,60}? found|Failed to parse query|"
                                r"query_shard_exception|kql_syntax", re.I), None),
    ("query_invalid", re.compile(r"verification_exception|parsing_exception|Unknown function", re.I), None),
    ("max_alerts", re.compile(r"maximum alert limit|max_signals", re.I), None),
    ("gap", re.compile(r"were not queried between|missed (\d+ )?schedule|execution gap", re.I), None),
    ("ml_job", re.compile(r"machine learning job.{0,80}(not started|not running|not .{0,20}running)", re.I | re.S), None),
    ("overloaded", re.compile(r"circuit_breaking_exception|Data too large|too_many_requests|es_rejected_execution",
                              re.I), None),
    ("timeout", re.compile(r"timed out|timeout", re.I), None),
]


def kibana_findings(last: Dict[str, Any]) -> List[Tuple[str, str, str, str]]:
    """What Kibana's last run says is wrong: ``[(issue, cause, severity, detail)]``, empty when it
    succeeded. ``detail`` is Kibana's paragraph, as it wrote it."""
    status = str((last or {}).get("status") or "").lower()
    out: List[Tuple[str, str, str, str]] = []
    gap = (last.get("metrics") or {}).get("execution_gap_duration_s") if isinstance(last.get("metrics"), dict) else None
    if gap:
        out.append(("gap", "", KNOWN["gap"].severity, f"{_duration(float(gap))} of scheduled runs were missed."))
    if status in ("", "succeeded", "running"):
        return out
    message = str(last.get("message") or "")
    for part in [p for p in re.split(r"\n\s*\n", message) if p.strip()] or [message]:
        for issue, pattern, causes in _MATCHERS:
            m = pattern.search(part)
            if m:
                for cause in (causes(m) if causes else [""]):
                    out.append((issue, cause, KNOWN[issue].severity, part.strip()))
                break
        else:
            out.append(("other", _other_cause(part), "error" if status == "failed" else "warning", part.strip()))
    return out


# ── the field catalogue ──────────────────────────────────────────────────

def catalogue_findings(rule: Dict[str, Any], entries: Dict[str, Any],
                       kibana_issues: Set[str]) -> List[Tuple[str, str, str, str]]:
    """What the field catalogue says is wrong with a rule's indexes and fields. ``entries`` are the
    catalogue's entries for its patterns (``MappingCatalogue.entries``); a pattern not checked yet is
    unknown, never missing. Index and timestamp findings Kibana already made (``kibana_issues``) are
    not repeated."""
    from app.services.mapping_catalogue import NO_INDICES, OK
    out: List[Tuple[str, str, str, str]] = []
    rows = [r for r in rule.get("results") or [] if isinstance(r, (list, tuple)) and len(r) >= 4]
    patterns = [str(p) for p in rule.get("index") or [] if p] or sorted({str(r[0]) for r in rows})
    # Only when none of its patterns matches an index, as Kibana reports it: a rule listing several
    # integrations' patterns (most of Elastic's do) normally finds only some of them installed.
    checked = [p for p in patterns if p in entries]
    if "no_index" not in kibana_issues and checked and all(entries[p].status == NO_INDICES for p in checked):
        for p in checked:
            out.append(("no_index", p, KNOWN["no_index"].severity, f"{p} matches no index on this SIEM."))
    by_field: Dict[str, List[Tuple[str, str]]] = {}
    for idx, field, has, typ in (tuple(r[:4]) for r in rows):
        by_field.setdefault(str(field), []).append((str(idx), str(has)))
    for field, seen in sorted(by_field.items()):
        if any(has == "Yes" for _, has in seen):
            for idx, has in seen:
                info = (entries.get(idx).fields or {}).get(field) if idx in entries else None
                if has == "Yes" and info and len(info) > 3 and info[3]:
                    out.append(("field_conflict", f"{field} in {idx}", KNOWN["field_conflict"].severity,
                                f"{field} has more than one type across {idx}."))
            continue
        for idx, has in seen:          # no index has it: missing where its pattern has indexes
            if idx in entries and entries[idx].status == OK:
                out.append(("field_missing", f"{field} in {idx}", KNOWN["field_missing"].severity,
                            f"No index matching {idx} maps {field}."))
    override = str(rule.get("timestamp_override") or "")
    if override and override != "-" and "override_missing" not in kibana_issues:
        for p in patterns:
            entry = entries.get(p)
            if entry and entry.status == OK and override not in (entry.fields or {}):
                out.append(("override_missing", f"{override} in {p}", KNOWN["override_missing"].severity,
                            f"No index matching {p} maps {override}, the rule's timestamp override."))
    return out


# ── finding everything ───────────────────────────────────────────────────

Key = Tuple[str, str, str, str, str]          # (issue, cause, siem_id, space, rule_id)
_BATCH = 250                                  # rules read at a time

_RULES_SQL = """
    SELECT rule_id, siem_id, space, COALESCE(enabled, 0) = 1 AS enabled,
           json_extract(raw_data, '$.execution_summary.last_execution')::VARCHAR AS last,
           json_extract(raw_data, '$.index')::VARCHAR AS idx,
           json_extract(raw_data, '$.results')::VARCHAR AS results,
           json_extract_string(raw_data, '$.timestamp_override') AS timestamp_override,
           json_extract_string(raw_data, '$.updated_at') AS updated_at, last_updated,
           json_extract_string(raw_data, '$.interval') AS run_interval,
           json_extract_string(raw_data, '$.from') AS lookback_from
    FROM detection_rules WHERE NOT COALESCE(deprecated, false)
"""


def _json(text, default):
    try:
        return json.loads(text) if text else default
    except ValueError:
        return default


def detect(db, conn, scopes: Optional[Set[Tuple[str, str]]] = None,
           rule_keys: Optional[Set[Tuple[str, str, str]]] = None,
           catalogue_for: Optional[Callable[[str], Any]] = None) -> Dict[Key, Tuple[str, str]]:
    """Every current finding, ``{key: (severity, detail)}``: for the rules and destinations in
    ``scopes`` (all when None), or only the rules ``rule_keys`` (no destination findings then)."""
    from app.services.mapping_catalogue import MappingCatalogue
    from app.services.rule_origins import PREBUILT_SQL
    catalogue_for = catalogue_for or (lambda siem_id: MappingCatalogue(db, siem_id))
    found: Dict[Key, Tuple[str, str]] = {}

    def add(issue, cause, siem_id, space, rule_id, severity, detail):
        found.setdefault((issue, cause, siem_id, space, rule_id), (severity, detail))

    def wanted(siem_id, space, rule_id=None):
        if rule_keys is not None:
            return rule_id is not None and (rule_id, siem_id, space) in rule_keys
        return scopes is None or (siem_id, space) in scopes

    # The rules' JSON is read in batches: all of a large destination's at once can exceed DuckDB's
    # memory limit on the shared connection.
    if rule_keys is not None:
        keys = sorted(rule_keys)
    else:
        keys = [k for k in conn.execute("SELECT rule_id, siem_id, space FROM detection_rules "
                                        "WHERE NOT COALESCE(deprecated, false)").fetchall()
                if scopes is None or (k[1], k[2]) in scopes]
    rules = []
    for at in range(0, len(keys), _BATCH):
        batch = keys[at:at + _BATCH]
        rules += conn.execute(
            _RULES_SQL + " AND EXISTS (SELECT 1 FROM (SELECT unnest(?::VARCHAR[]) AS k, unnest(?::VARCHAR[]) AS s, "
            "unnest(?::VARCHAR[]) AS sp) x WHERE x.k = rule_id AND x.s = siem_id AND x.sp = space)",
            [[k[0] for k in batch], [k[1] for k in batch], [k[2] for k in batch]]).fetchall()
    by_siem: Dict[str, List[tuple]] = {}
    for r in rules:
        by_siem.setdefault(r[1], []).append(r)
    for siem_id, siem_rules in by_siem.items():
        parsed = []
        for (rule_id, _s, space, enabled, last, idx, results, override, updated_at, last_updated,
             run_interval, lookback_from) in siem_rules:
            rule = {"index": _json(idx, []), "results": _json(results, []), "timestamp_override": override}
            parsed.append((rule_id, space, enabled, _json(last, {}), rule, updated_at, last_updated))
            for issue, cause, severity, detail in schedule_findings(run_interval, lookback_from):
                add(issue, cause, siem_id, space, rule_id, severity, detail)
        patterns = {p for *_x, rule, _u, _l in parsed
                    for p in (rule["index"] or [row[0] for row in rule["results"] if isinstance(row, list) and row])}
        try:
            entries = catalogue_for(siem_id).entries([str(p) for p in patterns if p])
        except Exception:
            logger.warning("Could not read the field catalogue of SIEM %s", siem_id, exc_info=True)
            entries = {}
        for rule_id, space, enabled, last, rule, updated_at, last_updated in parsed:
            kibana = kibana_findings(last) if enabled else []
            for issue, cause, severity, detail in kibana:
                add(issue, cause, siem_id, space, rule_id, severity, detail)
            for issue, cause, severity, detail in catalogue_findings(rule, entries, {f[0] for f in kibana}):
                add(issue, cause, siem_id, space, rule_id, severity, detail)
            if enabled and not last:
                changed = _when(updated_at)
                if changed and last_updated and last_updated - changed > NEVER_RUN_AFTER:
                    add("never_run", "", siem_id, space, rule_id, KNOWN["never_run"].severity,
                        f"No run recorded since it was last changed, {changed:%Y-%m-%d %H:%M}.")

    tables = {r[0] for r in conn.execute("SELECT table_name FROM duckdb_tables()").fetchall()}
    # Custom rules under the rule id of one of Elastic's rules (rule_origins.elastic_id_held, in SQL).
    try:
        for rule_id, siem_id, space in conn.execute(
                f"SELECT rule_id, siem_id, space FROM detection_rules WHERE NOT COALESCE(deprecated, false) "
                f"AND NOT {PREBUILT_SQL} AND COALESCE(NULLIF(kibana_rule_id, ''), rule_id) IN "
                f"(SELECT rule_id FROM elastic_rules_index)").fetchall():
            if wanted(siem_id, space, rule_id):
                add("custom_elastic_id", "", siem_id, space, rule_id, KNOWN["custom_elastic_id"].severity,
                    f"Uses Elastic's rule id {rule_id}.")
    except Exception:
        logger.debug("No Elastic rule index to check custom rules against", exc_info=True)
    if "space_fetch_results" in tables:
        for siem_id, space, duplicates in conn.execute(
                "SELECT siem_id, space, arg_max(duplicates, synced_at) FROM space_fetch_results GROUP BY 1, 2").fetchall():
            for dup in _json(duplicates, []):
                if wanted(siem_id, space, dup.get("rule_id")):
                    copies = [r.get("name") or "" for r in dup.get("rules", []) if not r.get("kept")]
                    add("shared_rule_id", "", siem_id, space, dup.get("rule_id"), KNOWN["shared_rule_id"].severity,
                        f"Kibana also holds {len(copies)} custom cop{'y' if len(copies) == 1 else 'ies'} under this rule id.")
        if rule_keys is None:
            for siem_id, space, total, returned, held in conn.execute(
                    "WITH r AS (SELECT *, row_number() OVER (PARTITION BY siem_id, space ORDER BY synced_at DESC) AS n "
                    "FROM space_fetch_results) SELECT siem_id, space, max(CASE WHEN n = 1 THEN kibana_total END), "
                    "max(CASE WHEN n = 1 THEN returned END), max(CASE WHEN n = 1 THEN held_not_returned END) "
                    "FROM r WHERE n <= 2 GROUP BY 1, 2 HAVING count(*) = 2 AND NOT bool_or(complete)").fetchall():
                if wanted(siem_id, space):
                    add("sync_incomplete", "", siem_id, space, "", KNOWN["sync_incomplete"].severity,
                        f"Kibana said it holds {total} rules and returned {returned}; TIDE holds {held} that it "
                        "didn't return.")
    if rule_keys is None and "siem_space_status" in tables:
        for siem_id, space, reason in conn.execute(
                "SELECT siem_id, space, reason FROM siem_space_status WHERE NOT reachable").fetchall():
            if wanted(siem_id, space):
                add("siem_offline", "", siem_id, space, "", KNOWN["siem_offline"].severity, reason or "")
    return found


def _when(value) -> Optional[datetime]:
    from app.services.database import kibana_utc, utc_to_local
    return utc_to_local(kibana_utc(value)) if value else None


# ── keeping them, with their history ─────────────────────────────────────

DDL = """
    CREATE TABLE IF NOT EXISTS rule_issues (
        issue       VARCHAR NOT NULL,
        cause       VARCHAR NOT NULL,
        siem_id     VARCHAR NOT NULL,
        space       VARCHAR NOT NULL,
        rule_id     VARCHAR NOT NULL,     -- '' for a destination as a whole
        severity    VARCHAR,
        detail      VARCHAR,
        first_seen  TIMESTAMP NOT NULL,
        last_seen   TIMESTAMP NOT NULL,
        resolved_at TIMESTAMP,
        PRIMARY KEY (issue, cause, siem_id, space, rule_id)
    )
"""


def refresh(db, conn, scopes: Optional[Set[Tuple[str, str]]] = None,
            rule_keys: Optional[Set[Tuple[str, str, str]]] = None,
            catalogue_for: Optional[Callable[[str], Any]] = None, now: Optional[datetime] = None) -> Dict[str, int]:
    """Record what ``detect`` finds now for ``scopes`` / ``rule_keys``: a new finding is first seen
    now (again, if it had been resolved), one still there is seen now, and an open one in the same
    scope that is gone is resolved now. Resolved ones older than RESOLVED_DAYS are dropped.
    Returns ``{"open", "new", "resolved"}``."""
    import pandas as pd
    now = now or datetime.now()
    conn.execute(DDL)
    found = detect(db, conn, scopes, rule_keys, catalogue_for)
    cols = ["issue", "cause", "siem_id", "space", "rule_id", "severity", "detail"]
    frame = pd.DataFrame([[*k, *v] for k, v in found.items()], columns=cols).astype(object)
    if rule_keys is not None:
        scope_sql = ("EXISTS (SELECT 1 FROM (SELECT unnest(?::VARCHAR[]) AS k, unnest(?::VARCHAR[]) AS s, "
                     "unnest(?::VARCHAR[]) AS sp) x WHERE x.k = r.rule_id AND x.s = r.siem_id AND x.sp = r.space)")
        keys = sorted(rule_keys)
        scope_params = [[k[0] for k in keys], [k[1] for k in keys], [k[2] for k in keys]]
    elif scopes is not None:
        scope_sql = ("EXISTS (SELECT 1 FROM (SELECT unnest(?::VARCHAR[]) AS s, unnest(?::VARCHAR[]) AS sp) x "
                     "WHERE x.s = r.siem_id AND x.sp = r.space)")
        pairs = sorted(scopes)
        scope_params = [[p[0] for p in pairs], [p[1] for p in pairs]]
    else:
        scope_sql, scope_params = "TRUE", []
    same = "r.issue = f.issue AND r.cause = f.cause AND r.siem_id = f.siem_id AND r.space = f.space AND r.rule_id = f.rule_id"
    conn.register("issues_found", frame)
    try:
        new = conn.execute(
            f"SELECT count(*) FROM issues_found f WHERE NOT EXISTS (SELECT 1 FROM rule_issues r WHERE {same} "
            "AND r.resolved_at IS NULL)").fetchone()[0]
        conn.execute(
            f"UPDATE rule_issues r SET severity = f.severity, detail = f.detail, last_seen = ?, "
            f"first_seen = CASE WHEN r.resolved_at IS NULL THEN r.first_seen ELSE ? END, resolved_at = NULL "
            f"FROM issues_found f WHERE {same}", [now, now])
        conn.execute(
            f"INSERT INTO rule_issues SELECT f.*, ?, ?, NULL FROM issues_found f "
            f"WHERE NOT EXISTS (SELECT 1 FROM rule_issues r WHERE {same})", [now, now])
        resolved = conn.execute(
            f"UPDATE rule_issues r SET resolved_at = ? WHERE resolved_at IS NULL AND {scope_sql} "
            f"AND NOT EXISTS (SELECT 1 FROM issues_found f WHERE {same}) RETURNING 1",
            [now, *scope_params]).fetchall()
    finally:
        conn.unregister("issues_found")
    conn.execute("DELETE FROM rule_issues WHERE resolved_at < ?", [now - timedelta(days=RESOLVED_DAYS)])
    return {"open": len(found), "new": new, "resolved": len(resolved)}


def refresh_tenant(db, client_id: str, scopes: Optional[Iterable[Tuple[str, str]]] = None,
                   rule_keys: Optional[Iterable[Tuple[str, str, str]]] = None) -> Optional[Dict[str, int]]:
    """``refresh`` on one client's database after a sync; never raises (a sync must not fail over it)."""
    from app.services import sync_runs
    from app.services.tenant_manager import tenant_context_for
    try:
        with tenant_context_for(client_id), db.get_connection() as conn:
            counts = refresh(db, conn, set(scopes) if scopes is not None else None,
                             set(rule_keys) if rule_keys is not None else None)
        logger.info("Rule issues for client %s: %s", client_id, counts)
        return counts
    except Exception as exc:
        logger.exception("Could not record rule issues for client %s", client_id)
        sync_runs.step_failed("Rule Monitoring", exc)
        return None


# ── stale data, worked out when asked ────────────────────────────────────

def last_synced(conn) -> Dict[Tuple[str, str], datetime]:
    """When each destination's rules were last read from Kibana: its latest recorded fetch, else
    (synced before fetches were recorded) the time most of its rules were last stored."""
    out: Dict[Tuple[str, str], datetime] = {}
    try:
        for siem_id, space, stamp in conn.execute(
                "WITH s AS (SELECT siem_id, space, last_updated, count(*) AS n FROM detection_rules "
                "GROUP BY 1, 2, 3) SELECT siem_id, space, arg_max(last_updated, n) FROM s GROUP BY 1, 2").fetchall():
            out[(siem_id, space)] = stamp
        for siem_id, space, stamp in conn.execute(
                "SELECT siem_id, space, max(synced_at) FROM space_fetch_results GROUP BY 1, 2").fetchall():
            out[(siem_id, space)] = max(stamp, out.get((siem_id, space)) or stamp)
    except Exception:
        logger.debug("No sync record to read yet", exc_info=True)
    return out


def stale(conn, destinations: Iterable[Tuple[str, str]], now: Optional[datetime] = None,
          days: int = STALE_DAYS) -> List[Dict[str, Any]]:
    """The linked destinations not synced for ``days``: ``[{siem_id, space, last_synced, since}]``
    (``last_synced`` None when never synced; ``since`` is when it became stale)."""
    now = now or datetime.now()
    synced = last_synced(conn)
    out = []
    for siem_id, space in destinations:
        when = synced.get((siem_id, space))
        if when is None or now - when > timedelta(days=days):
            out.append({"siem_id": siem_id, "space": space, "last_synced": when,
                        "since": when + timedelta(days=days) if when else None})
    return out


def freshness(db, client_id: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    """The Last Synced card (Rule Health, Rule Monitoring, a Dashboard's Rule Health section):
    ``{"at": newest sync of the client's destinations or None, "stale": how many are stale,
    "days": STALE_DAYS}``. Never raises: a card mustn't break its page."""
    from app.services.tenant_manager import tenant_context_for
    out = {"at": None, "stale": 0, "days": STALE_DAYS}
    try:
        pairs = [(d["id"], str(d.get("space") or "default")) for d in db.get_client_siems(client_id) or []]
        with tenant_context_for(client_id), db.get_connection() as conn:
            synced = last_synced(conn)
            out["at"] = max((synced[p] for p in pairs if synced.get(p)), default=None)
            out["stale"] = len(stale(conn, pairs, now))
    except Exception:
        logger.warning("Could not work out when client %s last synced", client_id, exc_info=True)
    return out


def report_synced(db, client_id: Optional[str], now: Optional[datetime] = None) -> str:
    """An exported report's "Rules last synced" beneath Generated: the newest sync of the client's
    destinations, in UTC as Generated is, and how many are stale. Empty when the client has no
    destinations, so its report has no rules to date."""
    sync = freshness(db, client_id, now) if client_id else {}
    if not sync.get("at") and not sync.get("stale"):
        return ""
    text = f"{sync['at'].astimezone(timezone.utc):%Y-%m-%d %H:%M UTC}" if sync.get("at") else "never"
    if sync.get("stale"):
        n = sync["stale"]
        text += f" ({n} destination{'' if n == 1 else 's'} not synced for {sync.get('days', STALE_DAYS)} days)"
    return text


# ── failed sync steps, worked out when asked (#85) ───────────────────────

def failed_steps(client_id: Optional[str], destinations: Iterable[Tuple[str, str]]) -> List[Dict[str, Any]]:
    """``sync_step_failed`` findings from the client's last finished rule sync (sync_runs
    ``detail.steps_failed``): one per failed step, its cause, and per destination that sync covered
    (a sync of one destination covers only it). Gone once a later sync's steps succeed. Never raises."""
    if not client_id:
        return []
    from app.services import sync_runs
    try:
        run = sync_runs.last_finished_rule_sync(client_id)
    except Exception:
        logger.warning("Could not read the last sync of client %s", client_id, exc_info=True)
        return []
    steps = {s["step"]: s["error"] for s in ((run or {}).get("detail") or {}).get("steps_failed") or []}
    if not steps:
        return []
    scope = run.get("scope") or {}
    covered = [(s, sp) for s, sp in destinations if not scope.get("siem_id")
               or (s == scope["siem_id"] and sp == str(scope.get("space") or "default"))]
    when = run.get("finished_at") or run.get("started_at")
    at = f" at the sync of {when:%Y-%m-%d %H:%M}" if when else ""
    return [{"issue": "sync_step_failed", "cause": step, "siem_id": siem_id, "space": space, "rule_id": "",
             "severity": "warning", "first_seen": when, "resolved_at": None, "name": None, "enabled": True,
             "detail": f"{step} failed{at}: {error}"}
            for step, error in steps.items() for siem_id, space in covered]


def pending_changes(client_id: Optional[str]) -> List[Dict[str, Any]]:
    """``change_pending`` findings: changes Kibana made but TIDE couldn't record (pending_actions,
    #83 and #88), on the rule as TIDE still holds it; ``kind`` and ``copy_id`` are for Finish in TIDE."""
    if not client_id:
        return []
    from app.services import pending_actions
    out = []
    for e in pending_actions.for_client(client_id):
        try:
            since = datetime.fromisoformat(e.get("at") or "")
        except ValueError:
            since = None
        out.append({"issue": "change_pending", "cause": "", "siem_id": e["siem_id"], "space": e["space"],
                    "rule_id": e["rule_id"], "severity": "warning", "first_seen": since, "resolved_at": None,
                    "name": e.get("name"), "enabled": True, "kind": e["kind"], "copy_id": e.get("copy_id") or "",
                    "detail": f"{pending_actions.describe(e)}. TIDE couldn't record that: {e.get('error') or 'unknown error'}."})
    return out


# ── the Rule Monitoring page ─────────────────────────────────────────────

SEVERITIES = (("error", "Error"), ("warning", "Warning"))
GROUPS = (("issue", "Issue"), ("fixer", "Who fixes"), ("destination", "SIEM / destination"), ("rule", "Rule"))
SHOW = (("open", "Open"), ("resolved", "Resolved recently"))
RULES = (("enabled", "Enabled"), ("all", "Include disabled"))
_SEVERITY_ORDER = {"error": 0, "warning": 1}


def _age(since: Optional[datetime], now: datetime) -> str:
    if not since:
        return ""
    days = (now - since).days
    return "under a day" if days < 1 else "1 day" if days == 1 else f"{days} days"


def _item(f: Dict[str, Any]) -> Tuple[str, str, str]:
    """What a finding is about: its rule, or ('', siem_id, space) for a destination as a whole."""
    return (f["rule_id"], f["siem_id"], f["space"])


def view(conn, destinations: List[Dict[str, Any]], filters: Dict[str, Any],
         now: Optional[datetime] = None, client_id: Optional[str] = None) -> Dict[str, Any]:
    """Everything the Rule Monitoring page shows for one client: ``rows`` (each finding, filtered),
    ``groups`` (as ``filters["group"]`` asks), ``metrics``, and ``counts`` per filter choice (before
    the choice's own filter). ``destinations`` are the client's linked ones, ``[{id, space, name}]``;
    findings anywhere else are left out. Stale destinations come in as ``stale_data``, and with
    ``client_id``, steps its last sync failed as ``sync_step_failed``."""
    now = now or datetime.now()
    names = {(d["id"], str(d.get("space") or "default")): d.get("name") or d.get("space") for d in destinations}
    clusters = {d["id"]: cluster_of(d) for d in destinations}
    try:
        stored = conn.execute(
            "SELECT i.issue, i.cause, i.siem_id, i.space, i.rule_id, i.severity, i.detail, i.first_seen, "
            "i.resolved_at, d.name, COALESCE(d.enabled, 0) = 1 FROM rule_issues i LEFT JOIN detection_rules d "
            "ON d.rule_id = i.rule_id AND d.siem_id = i.siem_id AND d.space = i.space").fetchall()
    except Exception:            # no sync since Rule Monitoring came in: nothing recorded yet
        stored = []
    found = [dict(zip(("issue", "cause", "siem_id", "space", "rule_id", "severity", "detail", "first_seen",
                       "resolved_at", "name", "enabled"), r)) for r in stored]
    for s in stale(conn, names, now):
        when = s["last_synced"]
        found.append({"issue": "stale_data", "cause": "", "siem_id": s["siem_id"], "space": s["space"], "rule_id": "",
                      "severity": "error", "first_seen": s["since"], "resolved_at": None, "name": None, "enabled": True,
                      "detail": (f"Last synced {when:%Y-%m-%d %H:%M}, {_age(when, now)} ago." if when
                                 else "Never synced.")})
    found += failed_steps(client_id, names)
    found += pending_changes(client_id)
    copies = _shared_copies(conn)
    for f in found:
        f["destination"] = names.get((f["siem_id"], f["space"]))
        known = KNOWN.get(f["issue"], KNOWN["other"])
        f.update(title=known.title, fixer=known.fixer, fixer_label=FIXERS[known.fixer], age=_age(f["first_seen"], now),
                 copies=copies.get(_item(f), []) if f["issue"] == "shared_rule_id" else [],
                 cluster=clusters.get(f["siem_id"], f["siem_id"]))
    every = [f for f in found if f["destination"] is not None]
    all_rules = (filters.get("rules") or "enabled") == "all"
    scope = filters.get("scope") or ""

    def shown(show: str) -> List[Dict[str, Any]]:
        """Open or resolved findings, on enabled rules unless disabled ones are asked for (TIDE's own
        problems, rule ids, matter whether the rule is on or not)."""
        return [f for f in every if (f["resolved_at"] is None) == (show == "open")
                and (all_rules or not f["rule_id"] or f["enabled"] or f["fixer"] == "tide")]

    def narrowed(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """The filter bar's other choices."""
        if scope:
            rows = [f for f in rows if f"{f['siem_id']}|{f['space']}" == scope]
        for field in ("severity", "fixer", "issue"):
            wanted = set(filters.get(field) or [])
            if wanted:
                rows = [f for f in rows if f[field] in wanted]
        search = str(filters.get("search") or "").strip().lower()
        if search:
            rows = [f for f in rows if any(search in str(f.get(k) or "").lower()
                                           for k in ("name", "cause", "detail", "title", "destination"))]
        return rows

    def tally(rows, field) -> Dict[str, int]:
        out: Dict[str, Set] = {}
        for f in rows:
            out.setdefault(field(f), set()).add(_item(f))
        return {k: len(v) for k, v in out.items()}

    # An acknowledged cause stays muted until it affects more rules than when it was acknowledged.
    acks, counts_now = _acks(conn), _open_counts(conn)
    for f in every:
        ack = acks.get(_cause_key(f))
        if ack and f["resolved_at"] is None:
            current = counts_now.get(_cause_key(f), 0) if f["issue"] != "stale_data" else 1
            f["ack"] = ack if current <= ack["rules"] else None
            f["ack_lapsed"] = None if current <= ack["rules"] else {**ack, "now": current}
        else:
            f["ack"] = f["ack_lapsed"] = None

    show = filters.get("show") or "open"
    before = shown(show)
    counts = {"severity": tally(before, lambda f: f["severity"]), "fixer": tally(before, lambda f: f["fixer"]),
              "issue": tally(before, lambda f: f["issue"]), "scope": tally(before, lambda f: f"{f['siem_id']}|{f['space']}")}
    found = narrowed(before)
    group = filters.get("group") or "issue"
    open_rows = found if show == "open" else narrowed(shown("open"))
    muted = [f for f in open_rows if f["ack"]]
    metrics = _metrics(conn, [f for f in open_rows if not f["ack"]], narrowed(shown("resolved")), names, scope,
                       all_rules, now)
    metrics["acknowledged"] = len({_fix_key(f) for f in muted})
    if show == "open":
        groups = _group([f for f in found if not f["ack"]], group)
        if muted:
            groups.append(_node("acknowledged", "acknowledged", "Acknowledged", muted, children=_group(muted, group)))
    else:
        groups = _group(found, group)
    return {"rows": found, "groups": groups, "metrics": metrics, "counts": counts, "now": now}


def _shared_copies(conn) -> Dict[Tuple[str, str, str], List[Dict[str, Any]]]:
    """For each rule TIDE holds whose rule id Kibana also gave to a custom copy (at the latest sync),
    those copies: ``{(rule_id, siem_id, space): [{id, name}]}`` (Give the copy its own rule id)."""
    out: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    try:
        rows = conn.execute("SELECT siem_id, space, arg_max(duplicates, synced_at) FROM space_fetch_results "
                            "GROUP BY 1, 2").fetchall()
    except Exception:
        return out
    for siem_id, space, duplicates in rows:
        for dup in _json(duplicates, []):
            out[(dup.get("rule_id"), siem_id, space)] = [{"id": r.get("id"), "name": r.get("name")}
                                                        for r in dup.get("rules", [])
                                                        if not r.get("kept") and not r.get("prebuilt")]
    return out


def _cause_key(f: Dict[str, Any]) -> Tuple[str, str, str, str]:
    """A cause on one SIEM record (what is acknowledged): the issue and its cause on a SIEM, or a
    problem without a cause per destination."""
    return (f["issue"], f["cause"], f["siem_id"], "" if f["cause"] else f["space"])


def cluster_of(siem: Dict[str, Any]) -> str:
    """The cluster behind a SIEM record: its Elasticsearch address, else its Kibana's. Two SIEM
    records can point at one cluster (a SIEM linked twice); its indexes, and their fixes, are one."""
    url = str(siem.get("elasticsearch_url") or siem.get("kibana_url") or "").strip().rstrip("/").lower()
    return url or str(siem.get("id"))


def _fix_key(f: Dict[str, Any]) -> Tuple[str, str, str, str]:
    """One thing to fix: a named cause (an index pattern, a field) once per cluster, whichever SIEM
    records point at it; a problem without a cause per destination."""
    return (f["issue"], f["cause"], f.get("cluster") or f["siem_id"], "" if f["cause"] else f"{f['siem_id']}|{f['space']}")


# ── acknowledging a cause ────────────────────────────────────────────────

ACK_DDL = """
    CREATE TABLE IF NOT EXISTS rule_issue_acks (
        issue         VARCHAR NOT NULL,
        cause         VARCHAR NOT NULL,
        siem_id       VARCHAR NOT NULL,
        space         VARCHAR NOT NULL,    -- '' when the cause names what it is (a pattern, a field)
        note          VARCHAR,
        acked_by      VARCHAR,
        acked_at      TIMESTAMP NOT NULL,
        rules_at_ack  INTEGER NOT NULL,    -- what it affected then: more since brings it back
        PRIMARY KEY (issue, cause, siem_id, space)
    )
"""


def _acks(conn) -> Dict[Tuple[str, str, str, str], Dict[str, Any]]:
    try:
        rows = conn.execute("SELECT issue, cause, siem_id, space, note, acked_by, acked_at, rules_at_ack "
                            "FROM rule_issue_acks").fetchall()
    except Exception:            # nothing acknowledged yet
        return {}
    return {tuple(r[:4]): {"note": r[4], "by": r[5], "at": r[6], "rules": r[7]} for r in rows}


def _open_counts(conn) -> Dict[Tuple[str, str, str, str], int]:
    """How many rules (or whole destinations) each open cause affects now, enabled or not."""
    out: Dict[Tuple[str, str, str, str], Set] = {}
    try:
        for issue, cause, siem_id, space, rule_id in conn.execute(
                "SELECT issue, cause, siem_id, space, rule_id FROM rule_issues WHERE resolved_at IS NULL").fetchall():
            f = {"issue": issue, "cause": cause, "siem_id": siem_id, "space": space, "rule_id": rule_id}
            out.setdefault(_cause_key(f), set()).add(_item(f))
    except Exception:
        pass
    return {k: len(v) for k, v in out.items()}


def acknowledge(conn, key: Tuple[str, str, str, str], note: str, actor: str,
                now: Optional[datetime] = None) -> int:
    """Acknowledge (mute) one cause until it affects more rules than it does now. Returns that number."""
    conn.execute(ACK_DDL)
    rules = _open_counts(conn).get(tuple(key), 1)
    conn.execute("INSERT OR REPLACE INTO rule_issue_acks VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                 [*key, (note or "").strip()[:1000], actor, now or datetime.now(), rules])
    return rules


def unacknowledge(conn, key: Tuple[str, str, str, str]) -> None:
    conn.execute(ACK_DDL)
    conn.execute("DELETE FROM rule_issue_acks WHERE issue = ? AND cause = ? AND siem_id = ? AND space = ?", list(key))


def causes_from(params) -> List[Tuple[str, str, str, str]]:
    """A cause's keys from a request: issue, cause, siem_id and space (space only for a cause-less
    one). ``siem_id`` can name several SIEM records, comma-separated: one cause on one cluster."""
    issue, cause = params.get("issue") or "", params.get("cause") or ""
    siem_ids = [s for s in str(params.get("siem_id") or "").split(",") if s.strip()]
    if issue not in KNOWN or not siem_ids:
        return []
    return [(issue, cause, s.strip(), "" if cause else (params.get("space") or "")) for s in siem_ids]


# ── Copy for engineers ───────────────────────────────────────────────────

def _md(text: Any) -> str:
    """Text safe in a Markdown table cell or line."""
    return re.sub(r"\s+", " ", str(text or "")).replace("|", "\\|").strip()


def markdown(nodes: List[Dict[str, Any]], siem_labels: Dict[str, str], now: datetime) -> str:
    """Causes as Markdown for a ticket or a chat: ``nodes`` are cause nodes (``view`` groups)."""
    parts = []
    for node in nodes:
        rows = node["rows"]
        first = rows[0]
        known = KNOWN.get(first["issue"], KNOWN["other"])
        siem = ", ".join(siem_labels.get(s, s) for s in node.get("siem_ids") or [first["siem_id"]])
        title = (f"### {known.title}: `{node['cause']}` on {siem}" if node.get("cause")
                 else f"### {known.title}: {node['where']}")
        rules = [f for f in rows if f["rule_id"]]
        disabled = sum(1 for f in rules if not f["enabled"])
        since = node["first_seen"]
        lines = [title,
                 f"- **Who fixes:** {FIXERS[known.fixer]} · **Severity:** {node['severity'].title()}",
                 f"- **Failing since:** {since:%Y-%m-%d} ({_age(since, now)})" if since else "- **Failing since:** unknown",
                 f"- **Rules affected:** {len(rules)}" + (f" ({disabled} disabled)" if disabled else "")
                 if rules else "- **Affects:** the whole destination",
                 f"- **What it means:** {_md(known.meaning)}",
                 f"- **To fix:** {_md(known.check)}"]
        detail = next((f["detail"] for f in rows if f["detail"]), "")
        if detail:
            lines.append(f"- **{'Kibana says' if first['issue'] not in _TIDE_FOUND else 'Found'}:** {_md(detail)[:600]}")
        if node.get("ack"):
            a = node["ack"]
            lines.append(f"- **Acknowledged:** by {_md(a['by'])} on {a['at']:%Y-%m-%d}" + (f": {_md(a['note'])}" if a["note"] else ""))
        if rules:
            lines += ["", "| Rule | Destination | State | Since |", "|---|---|---|---|"]
            lines += [f"| {_md(f['name'] or f['rule_id'])} | {_md(f['destination'])} | "
                      f"{'Enabled' if f['enabled'] else 'Disabled'} | {f['first_seen']:%Y-%m-%d} |"
                      for f in sorted(rules, key=lambda f: str(f["name"] or "").lower()) if f["first_seen"]]
        parts.append("\n".join(lines))
    return "\n\n".join(parts) + "\n"


# Issues TIDE finds itself (its message is TIDE's, not Kibana's).
_TIDE_FOUND = {"stale_data", "field_missing", "field_conflict", "never_run", "siem_offline", "sync_incomplete",
               "sync_step_failed", "shared_rule_id", "custom_elastic_id", "change_pending", "schedule_gap",
               "short_lookback"}


def _metrics(conn, open_rows, resolved_rows, names, scope: str, all_rules: bool, now: datetime) -> Dict[str, Any]:
    """Rule Monitoring's stat cards, for the filters shown (always of what is open, whichever Show
    is chosen)."""
    worst: Dict[Tuple[str, str, str], str] = {}
    since: Dict[Tuple[str, str, str], datetime] = {}       # when each rule's first open problem began
    for f in open_rows:
        if _item(f) not in worst or _SEVERITY_ORDER[f["severity"]] < _SEVERITY_ORDER[worst[_item(f)]]:
            worst[_item(f)] = f["severity"]
        if f["first_seen"]:
            since[_item(f)] = min(since.get(_item(f), f["first_seen"]), f["first_seen"])
    week = now - timedelta(days=7)
    by_fixer: Dict[str, Set] = {k: set() for k in FIXERS}
    for f in open_rows:
        by_fixer[f["fixer"]].add(_fix_key(f))
    pairs = [k for k in names if not scope or f"{k[0]}|{k[1]}" == scope]
    rules_total = 0
    if pairs:
        rules_total = conn.execute(
            "SELECT count(*) FROM detection_rules WHERE NOT COALESCE(deprecated, false) "
            f"{'' if all_rules else 'AND COALESCE(enabled, 0) = 1 '}"
            "AND EXISTS (SELECT 1 FROM (SELECT unnest(?::VARCHAR[]) AS s, unnest(?::VARCHAR[]) AS sp) x "
            "WHERE x.s = siem_id AND x.sp = space)", [[p[0] for p in pairs], [p[1] for p in pairs]]).fetchone()[0]
    # When Rule Monitoring began recording these destinations: until a week of history, every problem
    # it has found looks new, so the cards don't say how many are.
    tracked_since = None
    if pairs:
        try:
            tracked_since = conn.execute(
                "SELECT min(first_seen) FROM rule_issues WHERE EXISTS (SELECT 1 FROM (SELECT unnest(?::VARCHAR[]) AS s, "
                "unnest(?::VARCHAR[]) AS sp) x WHERE x.s = siem_id AND x.sp = space)",
                [[p[0] for p in pairs], [p[1] for p in pairs]]).fetchone()[0]
        except Exception:       # no sync since Rule Monitoring came in
            tracked_since = None
    synced = last_synced(conn)
    return {
        "rules": len({i for i in worst if i[0]}),
        "rules_enabled": len({_item(f) for f in open_rows if f["rule_id"] and f["enabled"]}),
        "rules_total": rules_total,
        "errors": sum(1 for s in worst.values() if s == "error"),
        "warnings": sum(1 for s in worst.values() if s == "warning"),
        "new_errors": sum(1 for i, s in worst.items() if s == "error" and since.get(i, now) >= week),
        "new_warnings": sum(1 for i, s in worst.items() if s == "warning" and since.get(i, now) >= week),
        "tracked_since": tracked_since,
        "new_known": tracked_since is None or tracked_since <= week,
        "causes": len({_fix_key(f) for f in open_rows}),
        "by_fixer": {k: len(v) for k, v in by_fixer.items()},
        "resolved": len({_fix_key(f) for f in resolved_rows}),
        "stale": len({_item(f) for f in open_rows if f["issue"] == "stale_data"}),
        "last_synced": max((synced[k] for k in pairs if synced.get(k)), default=None),
    }


def _node(kind: str, key: Any, label: str, rows: List[Dict[str, Any]], **extra) -> Dict[str, Any]:
    items = {_item(f) for f in rows}
    firsts = [f["first_seen"] for f in rows if f["first_seen"]]
    return {"kind": kind, "key": key, "label": label, "rows": rows, "count": len(items),
            "rules": len({i for i in items if i[0]}),
            "severity": min((f["severity"] for f in rows), key=_SEVERITY_ORDER.get, default="warning"),
            "first_seen": min(firsts) if firsts else None, "children": [], **extra}


def _ordered(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Errors first, then what affects the most, then by name."""
    return sorted(nodes, key=lambda n: (_SEVERITY_ORDER[n["severity"]], -n["count"], str(n["label"]).lower()))


def _split(rows, by: Callable[[Dict[str, Any]], Any]) -> Dict[Any, List[Dict[str, Any]]]:
    out: Dict[Any, List[Dict[str, Any]]] = {}
    for f in rows:
        out.setdefault(by(f), []).append(f)
    return out


def _causes(rows) -> List[Dict[str, Any]]:
    """An issue's findings by cause: a named cause on one SIEM (a pattern, a field), or, for a
    problem with no cause of its own, the destination."""
    nodes = []
    for key, part in _split(rows, _fix_key).items():
        cause = key[1]
        where = ", ".join(sorted({f["destination"] for f in part}))
        siem_ids = sorted({f["siem_id"] for f in part})
        acked = [f for f in part if f.get("ack")]
        lapsed = [f for f in part if f.get("ack_lapsed")]
        nodes.append(_node("cause", key, cause or where, part, cause=cause, where=where,
                           issue=part[0]["issue"], siem_id=siem_ids[0], siem_ids=siem_ids,
                           space="" if cause else part[0]["space"],
                           ack=acked[0]["ack"] if acked else None,
                           ack_lapsed=lapsed[0]["ack_lapsed"] if lapsed else None,
                           rule_keys=[{"rule_id": f["rule_id"], "siem_id": f["siem_id"], "space": f["space"]}
                                      for f in part if f["rule_id"]]))
    return _ordered(nodes)


def _issues(rows) -> List[Dict[str, Any]]:
    nodes = []
    for issue, part in _split(rows, lambda f: f["issue"]).items():
        known = KNOWN.get(issue, KNOWN["other"])
        node = _node("issue", issue, known.title, part, fixer=FIXERS[known.fixer], meaning=known.meaning,
                     check=known.check)
        node["children"] = _causes(part)
        nodes.append(node)
    return _ordered(nodes)


def _group(rows: List[Dict[str, Any]], group: str) -> List[Dict[str, Any]]:
    """issue → cause → rules (the default); who fixes → issue → cause → rules; destination →
    issue → cause → rules; or rule → its findings."""
    if group in ("fixer", "destination"):
        by = (lambda f: f["fixer"]) if group == "fixer" else (lambda f: (f["siem_id"], f["space"]))
        nodes = []
        for key, part in _split(rows, by).items():
            node = _node(group, key, FIXERS[key] if group == "fixer" else part[0]["destination"], part)
            node["children"] = _issues(part)
            nodes.append(node)
        return _ordered(nodes)
    if group == "rule":
        return _ordered([
            _node("rule" if rule_id else "destination", (rule_id, siem_id, space),
                  (part[0]["name"] or rule_id) if rule_id else part[0]["destination"], part,
                  where=part[0]["destination"], rule_id=rule_id, siem_id=siem_id, space=space)
            for (rule_id, siem_id, space), part in _split(rows, _item).items()])
    return _issues(rows)
