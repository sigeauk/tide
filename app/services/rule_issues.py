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
- the newest event in each index pattern (``data_freshness``, a search a sync adds): a pattern with no
  new events for longer than the client expects; whether recent events fill the fields rules match
  on (``FieldData``, checked daily): a mapped field no event of the last 7 days has a value in; and how
  late events arrive (``IngestDelay``): later than a rule looks back beyond its interval;
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
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

STALE_DAYS = 7           # a destination not synced for this long is stale (#65)
RESOLVED_DAYS = 14       # resolved issues are kept, and shown as resolved, this long
NEVER_RUN_AFTER = timedelta(hours=1)    # an enabled rule with no run this long after its last change

# Who fixes an issue: the engineers who run the SIEM (its indexes, pipelines, Kibana and cluster), the
# rule's author, or TIDE. Before 6.3.2 Engineer was two, "data" and "platform": saved dashboards and
# bookmarks may still name them.
FIXERS = {"engineer": "Engineer", "author": "Author", "tide": "TIDE"}
_FIXERS_BEFORE = {"data": "engineer", "platform": "engineer"}


def fixer_values(values) -> List[str]:
    """Who fixes choices as the filter reads them: the known ones, an old one as the role it is now."""
    out: List[str] = []
    for v in values or []:
        v = _FIXERS_BEFORE.get(str(v), str(v))
        if v in FIXERS and v not in out:
            out.append(v)
    return out


@dataclass(frozen=True)
class Issue:
    id: str
    title: str
    fixer: str          # a FIXERS key
    severity: str       # "error" (the rule doesn't do its job), "warning" (it does, less well) or "info" (worth knowing)
    level: str          # "rule": found per rule; "destination": one SIEM space as a whole
    meaning: str        # what it means, in plain words
    check: str          # what to check or do


KNOWN: Dict[str, Issue] = {i.id: i for i in (
    Issue("stale_data", "Rule data not synced recently", "tide", "error", "destination",
          "TIDE hasn't read this destination's rules for a while, so its scores, coverage and the issues listed "
          "here may be out of date.",
          "Sync the destination in TIDE. If the sync fails, Diagnostics → Sync activity says why."),
    Issue("no_index", "No index matches the index pattern", "engineer", "error", "rule",
          "The rule searches an index pattern that matches no index on this SIEM, so it finds nothing there.",
          "Check that the integration or pipeline writing to this index pattern is installed and sending data."),
    Issue("no_recent_data", "No recent events in the index pattern", "engineer", "error", "rule",
          "The index pattern has indexes, but no new event has reached them for longer than new data is expected, "
          "so the rule can't alert on that source. It is an error where none of the rule's index patterns has "
          "recent events, as the rule can't raise alerts at all, and a warning where its other patterns still do.",
          "Check the integration, agent or pipeline that sends this data. If the source sends only now and then, "
          "or is retired, use Expect new data every… on the cause."),
    Issue("override_missing", "Indexes missing the timestamp override field", "engineer", "warning", "rule",
          "These indexes don't have the field the rule uses as its timestamp override, usually because the "
          "ingest pipeline that adds it doesn't run for them. Their events can be searched late or missed.",
          "Add the field in the ingest pipeline for these indexes (event.ingested is set by Elastic's default "
          "ingest pipeline), or change the rule's timestamp override."),
    Issue("field_missing", "Field not in the index mappings", "engineer", "warning", "rule",
          "The rule's query uses a field that none of its indexes map, so it can't match on that field.",
          "Check the data source sends the field (or that its pipeline creates it); if the name is wrong, "
          "correct the rule's query."),
    Issue("field_conflict", "Field mapped with conflicting types", "engineer", "warning", "rule",
          "The field has different types in different indexes the rule searches, so searches on it can fail "
          "or miss events in some of them.",
          "Map the field with one type in every index (index template or ingest pipeline)."),
    Issue("field_empty", "Field mapped but has no data", "engineer", "warning", "rule",
          "The indexes map the field the rule matches on, and have recent events, but none of the last 7 days' "
          "events has a value in it, so the rule can't match on it. Index templates map many fields whether or not "
          "the source sends them.",
          "Check the data source sends the field, or that its ingest pipeline fills it; if the rule should match on "
          "another field, correct its query."),
    Issue("unknown_field", "Query uses a field Elasticsearch can't find", "author", "error", "rule",
          "Elasticsearch refused the rule's query because a field it names doesn't exist in the indexes.",
          "Check the field name in the query. If it is right, the data doesn't have the field yet."),
    Issue("query_syntax", "Query won't parse", "author", "error", "rule",
          "Kibana can't parse the rule's query, so the rule never runs a search.",
          "Correct the query's syntax; Kibana's message points at where it stopped."),
    Issue("query_invalid", "Query refused by Elasticsearch", "author", "error", "rule",
          "Elasticsearch refused the rule's query (an unknown function, or a query it can't run).",
          "Correct the query; Kibana's message says what Elasticsearch objected to."),
    Issue("privileges", "Missing index privileges", "engineer", "warning", "rule",
          "The user whose API key runs the rule may lack read privileges on some of its indexes, or Kibana "
          "couldn't check them.",
          "Check the roles of the user who last saved the rule in Kibana: they need read on its index patterns."),
    Issue("max_alerts", "Reached the maximum alerts per run", "author", "warning", "rule",
          "The rule found more matches than it may turn into alerts in one run, so some weren't raised.",
          "Tune the rule to match less, or raise its maximum alerts per run."),
    Issue("gap", "Runs were missed", "engineer", "warning", "rule",
          "Some of the rule's scheduled runs didn't happen, so events in those periods weren't searched.",
          "Check Kibana's task manager capacity; add Kibana instances or lengthen the rule's look-back."),
    Issue("timeout", "Search timed out", "engineer", "warning", "rule",
          "The rule's search ran out of time, so its results may be incomplete.",
          "Check Elasticsearch load, or make the query cheaper."),
    Issue("slow", "Searches getting slow", "author", "warning", "rule",
          "The rule's searches take a large share of the time between its runs, or have more than doubled "
          "in two weeks. Kibana misses runs once a search takes longer than that: this is the warning before.",
          "Make the query cheaper: narrow its index patterns, avoid leading wildcards and regular expressions, "
          "or filter on keyword fields first. Or run it less often."),
    Issue("overloaded", "Elasticsearch refused the search (overloaded)", "engineer", "warning", "rule",
          "Elasticsearch turned the search away because it was short of memory or busy.",
          "Check the cluster's memory and load (circuit breakers, search queue)."),
    Issue("ml_job", "Machine learning job not running", "engineer", "error", "rule",
          "The machine learning job the rule reads from isn't running, so the rule has nothing to alert on.",
          "Start the job in Kibana's Machine Learning, and check its datafeed."),
    Issue("schedule_gap", "Blind windows between runs", "author", "error", "rule",
          "The rule searches back less time than it waits between runs, so part of every interval is never "
          "searched: events there can't raise an alert, and Kibana doesn't report it as missed runs.",
          "Make the rule search back at least its run interval plus a margin: for example, runs every 5 minutes "
          "with 1 minute of additional look-back time (from now-6m)."),
    Issue("short_lookback", "Little or no additional look-back", "author", "warning", "rule",
          "The rule searches back little more than its run interval, by the time each event happened, so events "
          "that reach Elasticsearch late (normal ingest delay) fall between runs and are missed. A rule that "
          "uses event.ingested as its timestamp override isn't listed: the next run finds a late event.",
          "Give the rule at least a minute of additional look-back time, more if its data arrives late, or use "
          "event.ingested as its timestamp override."),
    Issue("ingest_late", "Events arrive later than the rule looks back", "engineer", "warning", "rule",
          "Events reach this index pattern later than the rule looks back beyond its run interval, by when each "
          "happened, so the late ones fall between runs and are never searched. Measured at each sync on the last "
          "hour's events (event.ingested against @timestamp); rules that search by event.ingested aren't affected.",
          "Find what holds events up between the source and Elasticsearch (agents, queues, pipelines). In the rules, "
          "use event.ingested as the timestamp override, or give them more additional look-back time than the delay."),
    Issue("noisy", "Too many alerts", "author", "warning", "rule",
          "The rule raises more alerts than analysts can look at: on average more a day than the client allows, or "
          "most of its space's alerts. Alerts like these are usually false positives that bury the true ones.",
          "Tune the rule: add exceptions for known-good activity, narrow its query, or group its alerts (alert "
          "suppression). The client's thresholds are on its page."),
    Issue("silent", "No alerts for a long time", "author", "warning", "rule",
          "The rule has been enabled a long while and raised no alert in the time the client allows. It may be "
          "right (the attack hasn't happened), or quietly broken: a query that can't match, or data it never gets. "
          "Where none of its data arrives any more, or a field it matches on is empty, that is listed instead.",
          "Check it can still fire: Validate it, or Test it against recent data, or run an atomic test. A rule meant "
          "to be rare can be muted."),
    Issue("alert_spike", "Alerts spiked", "author", "warning", "rule",
          "The rule raised far more alerts in a day than it usually does. A rise like this usually follows a change: "
          "an edit, a new data source, or an exception removed. The change TIDE recorded just before it is named.",
          "Look at the change named, and at the new alerts in Kibana: tune the rule if they are false positives."),
    Issue("alerts_unreadable", "Alerts couldn't be read", "engineer", "warning", "destination",
          "TIDE couldn't read this space's alerts at the last sync, so it can't tell which rules are noisy or silent here.",
          "Give the SIEM's API key read access to the space's alerts index (.alerts-security.alerts-<space>), then "
          "sync again."),
    Issue("never_run", "Enabled but never run", "engineer", "warning", "rule",
          "Kibana has no run recorded for this enabled rule.",
          "Check the rule in Kibana and Kibana's task manager."),
    Issue("siem_offline", "SIEM didn't answer at the last sync", "engineer", "warning", "destination",
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
          "Kibana holds a custom copy beside this rule under the same rule id, usually beside one of Elastic's "
          "prebuilt rules. TIDE shows only one of them; the row names the other. The two are usually the same "
          "detection, so with both enabled each alert is raised twice.",
          "Use Compare with the copy, on the rule's row or in its window, then choose: delete the copy, keep both (the "
          "copy gets a rule id of its own), or keep both and disable the rule TIDE shows."),
    Issue("custom_elastic_id", "Custom rule using one of Elastic's rule ids", "tide", "warning", "rule",
          "While it does, Kibana can't install Elastic's own rule in this space.",
          "Open the rule and use Give it its own rule id."),
    Issue("elastic_link_differs", "Linked to an Elastic rule it doesn't match", "tide", "warning", "rule",
          "TIDE links this custom rule to one of Elastic's rules, by its rule id or because it was copied from it, "
          "but its rule type, query or filters differ from Elastic's. It may be a copy changed on purpose, or not "
          "Elastic's rule at all; either way TIDE shows Elastic's updates for it.",
          "Use Compare with Elastic, on the rule's row or in its window, then keep the link (a copy you changed on "
          "purpose) or unlink it from Elastic (your own rule)."),
    Issue("exceptions_many", "Many exceptions", "author", "warning", "rule",
          "The rule has more exception items than the client allows (its own list and the shared lists it "
          "uses). Each is reasonable on its own; together they can mute the rule without anyone noticing.",
          "Review its Exceptions: remove those no longer needed, merge overlapping ones, or narrow the rule's "
          "query so fewer are needed. The client sets how many are too many on its page."),
    Issue("exception_broad", "Exception matches almost anything", "author", "warning", "rule",
          "An exception item whose every condition is a wildcard-only value (such as process.name matches \"*\") "
          "excepts every event that has those fields, so the rule raises almost nothing.",
          "Narrow the exception to the activity it was meant for, or remove it."),
    Issue("exception_recent", "Exception added recently", "author", "info", "rule",
          "An exception item was added to a list the rule uses in the last 7 days. Worth a look: it may "
          "except more than intended.",
          "Check the exception in the rule's Exceptions section, and its history."),
    Issue("duplicate_query", "Same detection deployed twice", "author", "warning", "rule",
          "Two or more enabled rules in this space search the same index patterns with the same query (and, for "
          "a threshold, new terms or indicator match rule, the same settings), under different names or rule "
          "ids: a re-import, or one copy from Sigma and one from Elastic. Every event alerts once per copy, and "
          "tuning one leaves the other as it was.",
          "Keep one: disable or delete the others, or change one so it finds something different. A copy kept "
          "on purpose can be linked to the other (Add link in its window), and isn't listed then."),
    Issue("upstream_update_pending", "Upstream update not reviewed", "author", "warning", "rule",
          "Elastic or SigmaHQ updated the rule this one came from a while ago, and the update hasn't been reviewed. "
          "Upstream fixes (fewer false positives, new fields, broader matching) don't reach your copy until then.",
          "Open the rule and use Review update in its Upstream section: take the sections you want, or keep it as "
          "it is. The client sets how long an update may wait on its page."),
    Issue("prebuilt_updates", "Elastic's prebuilt rules have updates", "engineer", "info", "destination",
          "Elastic has newer versions of prebuilt rules installed in this space, and has had them longer than the "
          "client allows. Kibana installs them itself, all at once, so they are one finding here rather than one "
          "for each rule.",
          "In Kibana, open Rules → Rule updates and update them (an air-gapped Kibana needs Elastic's newer prebuilt "
          "rules package first). Rule Health's Upstream filter, Elastic update available, lists them; Review update "
          "in a rule's window takes only the sections you choose into it."),
    Issue("upstream_deprecated", "Retired upstream", "author", "warning", "rule",
          "Elastic or SigmaHQ has deprecated the rule this one came from: they no longer maintain it, usually "
          "because a better rule replaces it or it caught too little.",
          "Find what replaces it in the Elastic or Sigma rules, deploy that, and retire this rule once it is "
          "covered; or keep it, knowing no more updates will come."),
    Issue("validation_stale", "Validation expired or out of date", "author", "info", "rule",
          "The rule's validation has expired under the client's validation policy, or the rule was edited since "
          "it was last validated, so no one has confirmed it still catches what it should. Listed only when "
          "the client turns it on.",
          "Validate the rule: run it against test data or an atomic test, then mark it validated in its window."),
    Issue("change_pending", "Change not finished in TIDE", "tide", "warning", "rule",
          "Kibana made a change TIDE asked for (giving the rule its own rule id, moving or copying it, or restoring "
          "it), but TIDE couldn't record it, so TIDE still shows the rule as it was before.",
          "Use Finish in TIDE on the rule. The next sync that reads the rule also finishes it."),
    Issue("backup_overwritten", "Backup changed in GitLab", "tide", "warning", "rule",
          "Someone changed or removed this rule's file in the client's GitLab backup project. Kibana holds the rule, "
          "so TIDE's backup put Kibana's version back; the change is still in the project's history.",
          "If the change was meant for the rule, make it in Kibana or in the rule's window in TIDE. Otherwise nothing "
          "is needed: this goes after 7 days."),
    Issue("other", "Other Kibana errors", "engineer", "warning", "rule",
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


def schedule_findings(interval, lookback_from, timestamp_override=None) -> List[Tuple[str, str, str, str]]:
    """(issue, cause, severity, detail) for a rule's schedule, from its own JSON (#74): it runs every
    ``interval`` and searches back to ``from`` ('now-6m': the whole window, Kibana's additional
    look-back is what it adds to the interval). Searching back less than the interval leaves blind
    windows between runs; less than a minute more leaves late events unsearched, unless the rule
    searches by event.ingested: a late event is then found by the next run. The cause is the
    schedule, so rules sharing one are fixed together."""
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
    if back - every < MIN_EXTRA_LOOKBACK and str(timestamp_override or "") != "event.ingested":
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


def freshness_findings(rule: Dict[str, Any], entries: Dict[Tuple[str, str], Any],
                       hours_for: Callable[[str], int]) -> List[Tuple[str, str, str, str]]:
    """The index patterns a rule searches that have gone quiet (#71): ``entries`` are the newest events
    of its SIEM's patterns (``DataFreshness.entries``), ``hours_for`` how often new data is expected in a
    pattern. An error when none of the patterns it can be judged on has recent events (the rule can't
    raise alerts), a warning when some still do. A pattern never checked, matching no index (that is
    ``no_index``) or with no new data expected isn't judged."""
    from app.services import data_freshness as df
    rows = [r for r in rule.get("results") or [] if isinstance(r, (list, tuple)) and r]
    patterns = [str(p) for p in rule.get("index") or [] if p] or sorted({str(r[0]) for r in rows})
    field, fallback = df.searched_by(rule)
    judged = []
    for p in dict.fromkeys(p for p in patterns if not p.startswith(("-", "_"))):
        entry, hours = df.entry_for(entries, p, field, fallback), hours_for(p)
        state = df.quiet(entry, hours)
        if state is not None:
            judged.append((p, state, entry, hours))
    quiet = [j for j in judged if j[1]]
    if not quiet:
        return []
    blind = len(quiet) == len(judged)
    then = ("None of the rule's index patterns has recent events, so it can't raise alerts." if blind
            else "The rule's other index patterns still have recent events.")
    out = []
    for p, _q, entry, hours in quiet:
        by = f" by {field}" if field != "@timestamp" and entries.get((p, field)) is entry else ""
        if entry.status == df.NO_EVENTS:
            seen = f"No event{by} in its indexes when TIDE looked, on {entry.checked_at:%Y-%m-%d %H:%M}."
        else:
            seen = (f"Newest event{by} {entry.newest_at:%Y-%m-%d %H:%M}, "
                    f"{_duration((entry.checked_at - entry.newest_at).total_seconds())} before TIDE looked, "
                    f"where new data is expected every {df.hours_text(hours)}.")
        out.append(("no_recent_data", p, "error" if blind else "warning", f"{seen} {then}"))
    return out


def alert_findings(counts: Dict[Any, int], space_counts: Dict[Any, int], limits: Dict[str, int],
                   until: Any) -> List[Tuple[str, str, str, str]]:
    """What an enabled rule's alerts say (#68): ``counts`` are its alerts per day (``rule_alerts.daily``),
    ``space_counts`` its space's, ``limits`` the client's thresholds (``rule_alerts.thresholds``),
    ``until`` the last day counted. Noisy when it averages more alerts a day over the last 7 days than
    the client allows, or makes more than its share of a space that has that many."""
    from app.services import rule_alerts
    week, space_week = rule_alerts.recent(counts, 7, until), rule_alerts.recent(space_counts, 7, until)
    per_day, space_per_day = week / 7, space_week / 7
    share = week / space_week * 100 if space_week else 0
    if per_day > limits["noisy_per_day"] or (space_per_day > limits["noisy_per_day"] and share > limits["noisy_share_pct"]):
        return [("noisy", "", KNOWN["noisy"].severity,
                 f"Averaged {per_day:,.0f} alerts a day over the last 7 days ({week:,} in all), {share:.0f}% of its "
                 f"space's alerts.")]
    return []


def silent_findings(counts: Dict[Any, int], enabled_since: Optional[datetime], limits: Dict[str, int],
                    until: Any, now: datetime) -> List[Tuple[str, str, str, str]]:
    """An enabled rule that has raised no alert for a long while (#69): enabled since ``enabled_since``
    at least ``silent_enabled_days``, and no alert in the last ``silent_days`` (at most what TIDE
    counts back). Only where its space's alerts were read, and none of its data problems is known
    (the caller leaves those out)."""
    from app.elastic_helper import ALERT_DAYS
    from app.services import rule_alerts
    days = min(limits["silent_days"], ALERT_DAYS)
    if not enabled_since or now - enabled_since < timedelta(days=limits["silent_enabled_days"]):
        return []
    if rule_alerts.recent(counts, days, until):
        return []
    last = max(counts) if counts else None
    return [("silent", "", KNOWN["silent"].severity,
             f"No alerts in the last {days} days{f' (the last on {last:%d %b %Y})' if last else ''}, though enabled "
             f"since {enabled_since:%d %b %Y}. Check it can still fire: Validate it, or Test it against recent data.")]


SPIKE_TIMES, SPIKE_MIN, SPIKE_BASE_DAYS = 3, 50, 14     # a spike: over 3x its median day of the 14 before, and 50+


def _change_text(action: str, detail: Dict[str, Any]) -> str:
    """A history entry as the cause of a spike: what was done to the rule."""
    fields = ", ".join(f.strip() for f in str(detail.get("changed_fields") or "").split(",") if f.strip())
    exception = f'the exception "{detail["exception"]}"' if detail.get("exception") else "an exception"
    return {"edited": f"edited its {fields}" if fields else "edited it", "enabled": "enabled it",
            "created": "created it", "restored": "restored it", "upstream_update": "merged an update into it",
            "moved": "moved it here", "new_rule_id": "gave it a rule id of its own",
            "exception_added": f"added {exception}", "exception_removed": f"removed {exception}",
            "exception_changed": f"changed {exception}"}.get(action, action.replace("_", " "))


def spike_findings(counts: Dict[Any, int], changes: List[Tuple[datetime, str, str, Dict[str, Any]]],
                   until: Any) -> List[Tuple[str, str, str, str]]:
    """A day (today or yesterday, UTC) with over ``SPIKE_TIMES`` the rule's median day of the
    ``SPIKE_BASE_DAYS`` before it, and at least ``SPIKE_MIN`` alerts (#70). ``changes`` are its history
    entries, ``(when, action, actor, detail)``: the latest before the end of that day, within the days
    looked back on, is named."""
    import statistics
    best = None
    for day in (until, until - timedelta(days=1)):
        n = counts.get(day, 0)
        base = statistics.median(counts.get(day - timedelta(days=i), 0) for i in range(1, SPIKE_BASE_DAYS + 1))
        if n >= SPIKE_MIN and n > SPIKE_TIMES * base and (best is None or n > best[1]):
            best = (day, n, base)
    if not best:
        return []
    from app.services.database import utc_to_local
    day, n, base = best
    # The days are UTC; history keeps local time.
    end = utc_to_local(datetime.combine(day + timedelta(days=1), datetime.min.time()))
    start = utc_to_local(datetime.combine(day - timedelta(days=SPIKE_BASE_DAYS), datetime.min.time()))
    before = [c for c in changes if start <= c[0] < end]
    rose = f"Alerts rose from about {base:,.0f} a day to {n:,} on {day:%d %b}"
    if before:
        when, action, actor, detail = max(before, key=lambda c: c[0])
        why = f", after {actor or 'someone'} {_change_text(action, detail)} on {when:%d %b}."
    else:
        why = ", with no change to the rule recorded in the two weeks before: its data may have changed."
    return [("alert_spike", "", KNOWN["alert_spike"].severity, rose + why)]


# Slow searches (#76): the median of the last SLOW_RUNS (as the score's search-time check takes it) at
# SLOW_SHARE of the interval or more; or, at SLOW_FLOOR_MS or more, over SLOW_TIMES the median of the
# runs before SLOW_DAYS ago. Each needs SLOW_MIN runs.
SLOW_RUNS, SLOW_SHARE, SLOW_TIMES, SLOW_DAYS, SLOW_FLOOR_MS, SLOW_MIN = 10, 0.5, 2, 14, 1000, 3


def _ms(ms: float) -> str:
    return f"{ms / 1000:.1f} s" if ms >= 1000 else f"{ms:.0f} ms"


def slow_findings(samples: List[Tuple[str, int]], interval, now: datetime) -> List[Tuple[str, str, str, str]]:
    """A rule whose searches are getting slow (#76), from its recorded search times (``samples``:
    ``(executed_at ISO in UTC, ms)``, any order): their recent median a large share of its run
    ``interval``, or more than doubled over two weeks."""
    import statistics
    runs = sorted(samples, reverse=True)
    recent = [ms for _at, ms in runs[:SLOW_RUNS]]
    if len(recent) < SLOW_MIN:
        return []
    med = statistics.median(recent)
    every = _span(interval)
    n = len(recent)
    if every and med >= SLOW_SHARE * every * 1000:
        return [("slow", "", KNOWN["slow"].severity,
                 f"Its searches take {_ms(med)} (the median of its last {n} runs), {med / every / 10:.0f}% of the "
                 f"{_duration(every)} between runs. Kibana misses runs once a search takes longer than that.")]
    cutoff = (now - timedelta(days=SLOW_DAYS)).strftime("%Y-%m-%dT%H:%M:%S")
    newer = [ms for at, ms in runs if at >= cutoff][:SLOW_RUNS]
    older = [ms for at, ms in runs if at < cutoff][:SLOW_RUNS]
    if len(newer) >= SLOW_MIN and len(older) >= SLOW_MIN:
        now_med, then_med = statistics.median(newer), statistics.median(older)
        if now_med >= SLOW_FLOOR_MS and now_med > SLOW_TIMES * then_med:
            return [("slow", "", KNOWN["slow"].severity,
                     f"Its searches have slowed from {_ms(then_med)} to {_ms(now_med)} (medians) in the last "
                     f"{SLOW_DAYS} days{f', {now_med / every / 10:.0f}% of the {_duration(every)} between runs' if every else ''}.")]
    return []


EXCEPTION_RECENT_DAYS = 7      # an exception item added in this many days is listed for information (#75)


def exception_findings(items: List[Dict[str, Any]], lists: int, limits: Dict[str, int],
                       now_utc: datetime) -> List[Tuple[str, str, str, str]]:
    """A rule's exceptions (#75), from the items that apply to it (``rule_exceptions.iter_rule_items``)
    across ``lists`` lists: more than the client's ``exceptions_many``; each broad item; each added
    in the last ``EXCEPTION_RECENT_DAYS`` (times UTC, as Kibana gives them). The cause of a broad or
    recent item is its name, so a shared list's item is one thing to fix on every rule using it."""
    from app.services import rule_exceptions
    out: List[Tuple[str, str, str, str]] = []
    n, limit = len(items), limits["exceptions_many"]
    if n > limit:
        across = f" across {lists} lists" if lists > 1 else ""
        out.append(("exceptions_many", "", KNOWN["exceptions_many"].severity,
                    f"Has {n} exception items{across}, more than the client's {limit}. Each is reasonable on its "
                    "own; together they can mute the rule."))
    for item in items:
        name = item.get("name") or item.get("item_id") or "unnamed"
        text = rule_exceptions.item_text(item)
        if rule_exceptions.broad(item):
            out.append(("exception_broad", name, KNOWN["exception_broad"].severity,
                        f'Exception "{name}" excepts every event where {text}.'))
        added, by = item.get("created_at"), item.get("created_by")
        if added and now_utc - added <= timedelta(days=EXCEPTION_RECENT_DAYS):
            who = f"by {by} " if by else ""
            out.append(("exception_recent", name, KNOWN["exception_recent"].severity,
                        f"Added {who}on {added:%d %b %Y}: {text}."))
    return out


def _as_day(value) -> Optional[Any]:
    """A date from a date, a datetime or ISO text; None for anything else."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.date()
    if hasattr(value, "year") and hasattr(value, "month"):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")[:19]).date()
    except ValueError:
        try:
            return datetime.strptime(str(value)[:10], "%Y-%m-%d").date()
        except ValueError:
            return None


def upstream_findings(status: Dict[str, Any], limits: Dict[str, int], today) -> List[Tuple[str, str, str, str]]:
    """Upstream drift (#77) from a rule's upstream status (``rule_origins.statuses``): the rule it came
    from retired by Elastic or SigmaHQ, or updated and not reviewed for the client's
    ``upstream_pending_days``. A rule linked by hand, still to be compared, isn't a known update."""
    if status.get("state") == "retired":
        return [("upstream_deprecated", "", KNOWN["upstream_deprecated"].severity, status["title"])]
    if status.get("state") != "update" or status.get("recorded_how") == "linked":
        return []
    since = _as_day(status.get("to_date"))
    if since and (today - since).days < limits["upstream_pending_days"]:
        return []
    if status.get("prebuilt"):
        # One of Elastic's prebuilt rules: Kibana updates them together, so detect counts them once per
        # destination (#95) rather than listing each.
        return [("prebuilt_updates", "", KNOWN["prebuilt_updates"].severity, status["title"])]
    return [("upstream_update_pending", "", KNOWN["upstream_update_pending"].severity,
             status["title"] + (f" Updated {since:%d %b %Y}, not reviewed since." if since else ""))]


def prebuilt_text(rules: List[Tuple[bool, str]], days: int, shown: int = 5) -> str:
    """What a destination's prebuilt updates finding says (#95), from its rules (``(enabled, name)``): how
    many, how many are enabled, and the first few by name, enabled ones first."""
    n, on = len(rules), sum(1 for enabled, _name in rules if enabled)
    names = [name for _on, name in sorted(rules, key=lambda r: (not r[0], r[1].lower()))]
    listed = ", ".join(f'"{name}"' for name in names[:shown]) + (f" and {n - shown} more" if n > shown else "")
    return (f"{n} prebuilt rule{'s' if n != 1 else ''} installed here ({on} enabled) {'has' if n == 1 else 'have'} had "
            f"a newer version from Elastic for {days} days or more: {listed}.")


# Recorded changes that leave what a rule does as it was: switching it on or off, and Kibana's own
# bookkeeping of who changed it when.
_NOT_EDITS = {"enabled", "updated_at", "updated_by", "revision"}


def _real_edit(detail: Dict[str, Any]) -> bool:
    """A recorded edit that changed the rule itself, not only switched it on or off or Kibana's
    record of when it was changed."""
    fields = {f.strip() for f in str(detail.get("changed_fields") or "").split(",") if f.strip()}
    return not fields or bool(fields - _NOT_EDITS)


def validation_findings(checked: Optional[datetime], expired_weeks: int, severity: str,
                        changes: List[Tuple[datetime, str, str, Dict[str, Any]]], now: datetime) -> List[Tuple[str, str, str, str]]:
    """A rule's validation gone stale (#77, when the client turns it on): never validated, expired under
    the client's validation policy (``expired_weeks`` for its ``severity``), or edited since
    (``changes``, its history: an edit or a merged upstream update after ``checked``)."""
    sev = KNOWN["validation_stale"].severity
    if not checked:
        return [("validation_stale", "", sev, "Never validated.")]
    weeks = (now - checked).days / 7
    if weeks > expired_weeks:
        return [("validation_stale", "", sev,
                 f"Last validated {checked:%d %b %Y}, {int(weeks)} weeks ago: the client's policy expires a "
                 f"{severity} rule's validation after {expired_weeks} weeks.")]
    later = [c for c in changes if c[0] > checked and c[1] in ("edited", "upstream_update") and _real_edit(c[3])]
    if later:
        when, action, actor, detail = max(later, key=lambda c: c[0])
        return [("validation_stale", "", sev,
                 f"Edited since it was last validated on {checked:%d %b %Y}: {actor or 'someone'} "
                 f"{_change_text(action, detail)} on {when:%d %b %Y}.")]
    return []


def ingest_findings(rule: Dict[str, Any], delays: Dict[str, Any]) -> List[Tuple[str, str, str, str]]:
    """The index patterns a rule searches whose events arrive later than it looks back beyond its run
    interval (#73): ``delays`` are ``IngestDelay.entries`` of its SIEM, judged where at least
    ``INGEST_MIN_SAMPLE`` events were measured. Only a rule searching by @timestamp: one searching by
    event.ingested finds a late event at its next run, and one by another field can't be measured.
    ``rule`` has its ``interval`` and ``from``."""
    from app.services import data_freshness as df
    override = str(rule.get("timestamp_override") or "").strip()
    every = _span(rule.get("interval"))
    m = re.fullmatch(r"now-(\d+[smhd])", str(rule.get("from") or "").replace(" ", ""))
    back = _span(m.group(1)) if m else None
    if (override and override not in ("-", "@timestamp")) or not every or back is None:
        return []
    extra = max(0, back - every)
    rows = [r for r in rule.get("results") or [] if isinstance(r, (list, tuple)) and r]
    patterns = [str(p) for p in rule.get("index") or [] if p] or sorted({str(r[0]) for r in rows})
    out = []
    for p in dict.fromkeys(p for p in patterns if not p.startswith(("-", "_"))):
        e = delays.get(p)
        if e and e.status == df.OK and e.sample >= df.INGEST_MIN_SAMPLE and e.p95_ms / 1000 > extra:
            looks = f"looks back {_duration(extra)} beyond" if extra else "doesn't look back beyond"
            out.append(("ingest_late", p, KNOWN["ingest_late"].severity,
                        f"95% of the last hour's events reached {p} within {_duration(e.p95_ms / 1000)}. The rule {looks} "
                        f"its {_duration(every)} run interval, so events arriving later than that are never searched."))
    return out


def field_data_findings(rule: Dict[str, Any], newest: Dict[Tuple[str, str], Any],
                        fields: Dict[Tuple[str, str, str], Any]) -> List[Tuple[str, str, str, str]]:
    """Fields a rule matches on that its index patterns map but no recent event fills (#72). A field is
    judged in each of the rule's own patterns that had events by the field the rule searches by in the
    last FIELD_DATA_DAYS (a quiet one is ``no_recent_data``'s), and reported, per pattern, only where
    none of those has a value in it, as ``field_missing`` is only where no index maps it. ``newest``
    and ``fields`` are ``DataFreshness.entries`` and ``FieldData.entries`` of its SIEM."""
    from app.elastic_helper import FIELD_DATA_DAYS
    from app.services import data_freshness as df
    own = {str(p) for p in rule.get("index") or [] if p}
    rows = [r for r in rule.get("results") or [] if isinstance(r, (list, tuple)) and len(r) >= 3]
    override = str(rule.get("timestamp_override") or "").strip()
    ts = override if override and override not in ("-", "@timestamp") else "@timestamp"
    by_field: Dict[str, List[str]] = {}
    for idx, field, has, *_x in rows:
        if has == "Yes" and (not own or str(idx) in own):
            by_field.setdefault(str(field), []).append(str(idx))
    out = []
    for field, patterns in sorted(by_field.items()):
        judged = [(p, fields[(p, ts, field)].status) for p in dict.fromkeys(patterns)
                  if df.recent_events(newest.get((p, ts)), FIELD_DATA_DAYS) and (p, ts, field) in fields
                  and fields[(p, ts, field)].status in (df.HAS_DATA, df.EMPTY)]
        if judged and all(status == df.EMPTY for _p, status in judged):
            for p, _s in judged:
                out.append(("field_empty", f"{field} in {p}", KNOWN["field_empty"].severity,
                            f"None of the events in {p} from the last {FIELD_DATA_DAYS} days has a value in {field}, "
                            f"though {p} has recent events."))
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
           json_extract_string(raw_data, '$.from') AS lookback_from,
           COALESCE(TRY_CAST(json_extract(raw_data, '$.timestamp_override_fallback_disabled') AS BOOLEAN), false)
               AS fallback_disabled,
           json_extract_string(raw_data, '$.id') AS kibana_id,
           json_extract_string(raw_data, '$.created_at') AS kibana_created,
           lower(COALESCE(json_extract_string(raw_data, '$.severity'), 'low')) AS rule_severity,
           COALESCE(json_extract_string(raw_data, '$.rule_id'), rule_id) AS validation_key,
           COALESCE(json_extract_string(raw_data, '$.name'), '') AS rule_name,
           json_extract(raw_data, '$.exceptions_list')::VARCHAR AS exceptions_list
    FROM detection_rules WHERE NOT COALESCE(deprecated, false)
"""

# Changes to a rule a spike can follow, and those that switch it on (#69, #70).
_CHANGE_ACTIONS = ("created", "edited", "enabled", "restored", "upstream_update", "moved", "new_rule_id",
                   "exception_added", "exception_removed", "exception_changed")
_SWITCHED_ON = ("enabled", "restored", "new_rule_id")
# Problems that already explain a rule raising no alerts: its data, its query, its job, its runs.
# No recent events only as an error (none of its patterns has any): with some still sending, it can fire.
_EXPLAINS_SILENCE = {"no_index", "no_recent_data", "field_missing", "field_empty", "query_syntax", "query_invalid",
                     "unknown_field", "ml_job", "never_run"}
_EXPLAINS_ONLY_AS_ERROR = {"no_recent_data"}


def _explains_silence(issues: Dict[str, Set[str]]) -> bool:
    """Whether one of a rule's issues found so far (``{issue: {severity}}``) explains it raising no alerts."""
    return any(i in _EXPLAINS_SILENCE and (i not in _EXPLAINS_ONLY_AS_ERROR or "error" in severities)
               for i, severities in issues.items())


def _rule_history(conn, siem_id: str, days: int = 120) -> Dict[Tuple[str, str], List[Tuple[datetime, str, str, Dict[str, Any]]]]:
    """Each of a SIEM's rules' recent changes, ``{(rule_id, space): [(when, action, actor, detail)]}``."""
    if not conn.execute("SELECT 1 FROM duckdb_tables() WHERE table_name = 'rule_lifecycle_history' "
                        "AND database_name = current_database()").fetchone():
        return {}
    out: Dict[Tuple[str, str], List[Tuple[datetime, str, str, Dict[str, Any]]]] = {}
    for rule_id, space, action, actor, detail, when in conn.execute(
            f"SELECT rule_id, space, action, actor_name, detail::VARCHAR, created_at FROM rule_lifecycle_history "
            f"WHERE siem_id = ? AND created_at >= now() - INTERVAL {int(days)} DAY "
            f"AND action IN ({', '.join('?' * len(_CHANGE_ACTIONS))})", [siem_id, *_CHANGE_ACTIONS]).fetchall():
        out.setdefault((rule_id, space), []).append((when, action, actor or "", _json(detail, {}) or {}))
    return out


# Duplicate detections (#78): what decides which events a rule matches, beside its type, language,
# query and index patterns. Exceptions, schedule, severity and name don't.
_MATCH_FIELDS = ("data_view_id", "filters", "saved_id", "threshold", "new_terms_fields", "history_window_start",
                 "threat_index", "threat_query", "threat_mapping", "threat_language", "machine_learning_job_id",
                 "anomaly_threshold", "event_category_override", "tiebreaker_field", "timestamp_field")
_DUPLICATE_SQL = (
    "SELECT rule_id, space, name, json_extract_string(raw_data, '$.type'), json_extract_string(raw_data, '$.language'), "
    "json_extract_string(raw_data, '$.query'), json_extract(raw_data, '$.index')::VARCHAR, "
    + ", ".join(f"json_extract(raw_data, '$.{f}')::VARCHAR" for f in _MATCH_FIELDS)
    + " FROM detection_rules WHERE siem_id = ? AND COALESCE(enabled, 0) = 1 AND NOT COALESCE(deprecated, false)")


def _norm_json(text) -> Any:
    """A JSON value as compared: parsed, with objects' keys sorted; text as it is."""
    try:
        return json.dumps(json.loads(text), sort_keys=True) if text not in (None, "", "null") else None
    except (TypeError, ValueError):
        return str(text)


def duplicate_findings(rows: List[tuple], links: Set[frozenset]) -> Dict[Tuple[str, str], Tuple[str, str]]:
    """Enabled rules in one space that match the same events (#78): the same type, language, query
    (whitespace aside), index patterns (in any order) and the settings that decide what matches
    (``_MATCH_FIELDS``). ``rows`` are ``_DUPLICATE_SQL``'s; ``links`` the rule links, as frozensets of two
    ``(rule_id, space)``. A group whose rules are all linked to each other is kept on purpose (a copy
    linked when it was made, or given its own rule id), and isn't listed. ``{(rule_id, space): (cause,
    detail)}``: the cause is the query, so the copies are one thing to fix."""
    groups: Dict[Tuple[Any, ...], List[Tuple[str, str, str]]] = {}
    for rule_id, space, name, rtype, language, query, index, *match in rows:
        q = re.sub(r"\s+", " ", str(query or "")).strip()
        idx = tuple(sorted(str(i) for i in (_json(index, []) or []) if i))
        settings = tuple(_norm_json(m) for m in match)
        if not q and not any(settings):
            continue                      # nothing to say what it matches: not compared
        groups.setdefault((space, rtype or "", language or "", q, idx, settings), []).append((rule_id, space, name or rule_id))
    out: Dict[Tuple[str, str], Tuple[str, str]] = {}
    causes: Dict[Tuple[str, str], int] = {}
    for (space, rtype, language, q, idx, _s), members in groups.items():
        if len(members) < 2 or _all_linked([(r, s) for r, s, _n in members], links):
            continue
        shown = q if len(q) <= 100 else q[:99] + "…"
        cause = f"{language or rtype}: {shown}" + (f" on {', '.join(idx)}" if idx else "")
        n = causes[(space, cause)] = causes.get((space, cause), 0) + 1
        cause += f" ({n})" if n > 1 else ""         # two queries that read the same when shortened
        for rule_id, _sp, name in members:
            others = [f'"{o}"' for r, _x, o in members if r != rule_id]
            listed = ", ".join(others[:3]) + (f" and {len(others) - 3} more" if len(others) > 3 else "")
            out[(rule_id, space)] = (cause, f"Matches the same events as {listed}: each event alerts "
                                            f"{len(members)} times, once per copy.")
    return out


def _all_linked(members: List[Tuple[str, str]], links: Set[frozenset]) -> bool:
    """Whether rule links join every one of ``members`` to the others (one linked group)."""
    seen, todo = {members[0]}, [members[0]]
    while todo:
        a = todo.pop()
        for b in members:
            if b not in seen and frozenset((a, b)) in links:
                seen.add(b)
                todo.append(b)
    return len(seen) == len(members)


def _space_links(conn, siem_id: str) -> Set[frozenset]:
    """The rule links between two rules in one space of a SIEM, as frozensets of ``(rule_id, space)``."""
    try:
        rows = conn.execute("SELECT rule_a_id, space_a, rule_b_id, space_b FROM rule_links "
                            "WHERE siem_a_id = ? AND siem_b_id = ? AND space_a = space_b", [siem_id, siem_id]).fetchall()
    except Exception:            # no links table in this tenant yet
        return set()
    return {frozenset(((a, sa), (b, sb))) for a, sa, b, sb in rows}


def _search_samples(conn, siem_id: str) -> Dict[Tuple[str, str], List[Tuple[str, int]]]:
    """Each of a SIEM's rules' recorded search times (#76), ``{(Kibana id, space): [(executed_at, ms)]}``:
    the sync keeps them under the rule's Kibana saved-object id."""
    if not conn.execute("SELECT 1 FROM duckdb_tables() WHERE table_name = 'rule_search_time_samples' "
                        "AND database_name = current_database()").fetchone():
        return {}
    out: Dict[Tuple[str, str], List[Tuple[str, int]]] = {}
    for kibana_id, space, at, ms in conn.execute(
            "SELECT rule_id, space, executed_at, search_ms FROM rule_search_time_samples WHERE siem_id = ?",
            [siem_id]).fetchall():
        out.setdefault((kibana_id, space), []).append((str(at), int(ms)))
    return out


def _validations(conn) -> Dict[str, datetime]:
    """When each rule was last validated (#77), by its validation key, or by name for a record not
    bound to one yet (``database.validation_for``)."""
    try:
        rows = conn.execute("SELECT rule_id, rule_name, last_checked_on FROM checkedRule "
                            "WHERE last_checked_on IS NOT NULL").fetchall()
    except Exception:            # nothing validated in this tenant yet
        return {}
    out: Dict[str, datetime] = {}
    for rule_id, name, when in rows:
        when = when if isinstance(when, datetime) else _as_datetime(when)
        if when:
            out[str(rule_id or name)] = when
    return out


def _as_datetime(value) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "")[:19])
    except ValueError:
        return None


def _expired_weeks(db, client_id: Optional[str]) -> Callable[[str], int]:
    """The weeks after which the client's validation policy expires a rule of a severity (master
    cadence, or by criticality), as Rule Health shows it; TIDE's default without a client."""
    from app.config import get_settings
    cache: Dict[str, int] = {}

    def weeks(severity: str) -> int:
        if severity not in cache:
            try:
                cache[severity] = int(db.get_client_validation_thresholds(client_id, severity=severity)[1]) \
                    if db is not None and client_id else int(get_settings().rule_validation_expired_weeks)
            except Exception:
                cache[severity] = int(get_settings().rule_validation_expired_weeks)
        return cache[severity]
    return weeks


def _enabled_since(created: Optional[str], changes: List[Tuple[datetime, str, str, Dict[str, Any]]]) -> Optional[datetime]:
    """When a rule was last switched on, from its history (enabled, restored, re-created, or an edit
    of ``enabled``), else when Kibana created it."""
    on = [when for when, action, _a, detail in changes if action in _SWITCHED_ON
          or (action == "edited" and "enabled" in str(detail.get("changed_fields") or ""))]
    return max(on) if on else _when(created)


def _json(text, default):
    try:
        return json.loads(text) if text else default
    except ValueError:
        return default


def _among(keys: List[Tuple[str, str, str]]) -> Tuple[str, List[List[str]]]:
    """A condition (" AND …") and its parameters picking the detection_rules rows ``keys`` name."""
    return (" AND EXISTS (SELECT 1 FROM (SELECT unnest(?::VARCHAR[]) AS k, unnest(?::VARCHAR[]) AS s, "
            "unnest(?::VARCHAR[]) AS sp) x WHERE x.k = rule_id AND x.s = siem_id AND x.sp = space)",
            [[k[0] for k in keys], [k[1] for k in keys], [k[2] for k in keys]])


def rule_patterns(conn, keys: Iterable[Tuple[str, str, str]]) -> Dict[Tuple[str, str, str], List[str]]:
    """The index patterns each rule searches, as ``detect`` reads them: its own, else those its fields
    were checked in (an ES|QL rule's FROM). ``{(rule_id, siem_id, space): [pattern]}``."""
    keys = sorted(set(keys))
    out: Dict[Tuple[str, str, str], List[str]] = {}
    for at in range(0, len(keys), _BATCH):
        where, params = _among(keys[at:at + _BATCH])
        for rule_id, siem_id, space, idx, results in conn.execute(
                "SELECT rule_id, siem_id, space, json_extract(raw_data, '$.index')::VARCHAR, "
                "json_extract(raw_data, '$.results')::VARCHAR FROM detection_rules WHERE true" + where, params).fetchall():
            rows = [r for r in _json(results, []) or [] if isinstance(r, list) and r]
            out[(rule_id, siem_id, space)] = ([str(p) for p in _json(idx, []) or [] if p]
                                              or sorted({str(r[0]) for r in rows}))
    return out


def detect(db, conn, scopes: Optional[Set[Tuple[str, str]]] = None,
           rule_keys: Optional[Set[Tuple[str, str, str]]] = None,
           catalogue_for: Optional[Callable[[str], Any]] = None,
           freshness_for: Optional[Callable[[str], Any]] = None,
           client_id: Optional[str] = None,
           field_data_for: Optional[Callable[[str], Any]] = None,
           delay_for: Optional[Callable[[str], Any]] = None) -> Dict[Key, Tuple[str, str]]:
    """Every current finding, ``{key: (severity, detail)}``: for the rules and destinations in
    ``scopes`` (all when None), or only the rules ``rule_keys`` (no destination findings then).
    ``client_id`` says how often the client expects new data (``data_freshness.default_hours``)."""
    from app.services import data_freshness
    from app.services.mapping_catalogue import MappingCatalogue
    from app.services.rule_origins import PREBUILT_SQL
    catalogue_for = catalogue_for or (lambda siem_id: MappingCatalogue(db, siem_id))
    freshness_for = freshness_for or (lambda siem_id: data_freshness.DataFreshness(db, siem_id))
    field_data_for = field_data_for or (lambda siem_id: data_freshness.FieldData(db, siem_id))
    delay_for = delay_for or (lambda siem_id: data_freshness.IngestDelay(db, siem_id))
    default_hours = data_freshness.default_hours(db, client_id)
    windows = data_freshness.windows(conn)
    from app.services import rule_alerts
    limits, until, alert_reads = rule_alerts.thresholds(db, client_id), rule_alerts.today(), rule_alerts.reads(conn)
    validations = _validations(conn) if limits.get("validation_stale") else {}
    expired_weeks = _expired_weeks(db, client_id)
    found: Dict[Key, Tuple[str, str]] = {}
    rule_found: Dict[Tuple[str, str, str], Dict[str, Set[str]]] = {}     # each rule's issues so far, by severity

    def add(issue, cause, siem_id, space, rule_id, severity, detail):
        found.setdefault((issue, cause, siem_id, space, rule_id), (severity, detail))
        rule_found.setdefault((siem_id, space, rule_id), {}).setdefault(issue, set()).add(severity)

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
        where, params = _among(keys[at:at + _BATCH])
        rules += conn.execute(_RULES_SQL + where, params).fetchall()
    by_siem: Dict[str, List[tuple]] = {}
    for r in rules:
        by_siem.setdefault(r[1], []).append(r)
    for siem_id, siem_rules in by_siem.items():
        parsed = []
        for (rule_id, _s, space, enabled, last, idx, results, override, updated_at, last_updated,
             run_interval, lookback_from, fallback_disabled, kibana_id, kibana_created, rule_severity, validation_key,
             rule_name, exceptions_list) in siem_rules:
            rule = {"index": _json(idx, []), "results": _json(results, []), "timestamp_override": override,
                    "timestamp_override_fallback_disabled": bool(fallback_disabled),
                    "interval": run_interval, "from": lookback_from, "kibana_id": kibana_id or "",
                    "created": kibana_created, "severity": rule_severity, "validation_key": validation_key,
                    "name": rule_name, "exceptions": exceptions_list}
            parsed.append((rule_id, space, enabled, _json(last, {}), rule, updated_at, last_updated))
            for issue, cause, severity, detail in schedule_findings(run_interval, lookback_from, override):
                add(issue, cause, siem_id, space, rule_id, severity, detail)
        # Its own patterns and every pattern its lines name (an indicator match rule's indicator indexes).
        patterns = {p for *_x, rule, _u, _l in parsed
                    for p in list(rule["index"] or []) + [row[0] for row in rule["results"] if isinstance(row, list) and row]}
        try:
            entries = catalogue_for(siem_id).entries([str(p) for p in patterns if p])
        except Exception:
            logger.warning("Could not read the field catalogue of SIEM %s", siem_id, exc_info=True)
            entries = {}
        try:
            newest = freshness_for(siem_id).entries([str(p) for p in patterns if p])
        except Exception:
            logger.warning("Could not read the newest events of SIEM %s", siem_id, exc_info=True)
            newest = {}
        try:
            filled = field_data_for(siem_id).entries([str(p) for p in patterns if p])
        except Exception:
            logger.warning("Could not read which fields have data on SIEM %s", siem_id, exc_info=True)
            filled = {}
        try:
            delays = delay_for(siem_id).entries([str(p) for p in patterns if p])
        except Exception:
            logger.warning("Could not read how late events arrive on SIEM %s", siem_id, exc_info=True)
            delays = {}
        # Each rule's alerts per day, and each space's (#68); its recent changes (#69, #70).
        alerts = rule_alerts.daily(conn, {(siem_id, sp) for _r, sp, *_x in parsed})
        history = _rule_history(conn, siem_id)
        searches = _search_samples(conn, siem_id)      # each rule's search times (#76)
        utc_now = datetime.now(timezone.utc).replace(tzinfo=None)
        from app.services import rule_exceptions
        exception_items = rule_exceptions.items_by_list(conn, siem_id)    # the exception lists' items (#75)
        # The same detection deployed twice in one space (#78), over every enabled rule in it.
        try:
            spaces = {sp for _r, sp, *_x in parsed}
            copies = duplicate_findings([r for r in conn.execute(_DUPLICATE_SQL, [siem_id]).fetchall() if r[1] in spaces],
                                        _space_links(conn, siem_id))
            for (rule_id, space), (cause, detail) in copies.items():
                if wanted(siem_id, space, rule_id):
                    add("duplicate_query", cause, siem_id, space, rule_id, KNOWN["duplicate_query"].severity, detail)
        except Exception:
            logger.warning("Could not look for duplicate rules on SIEM %s", siem_id, exc_info=True)
        space_alerts: Dict[str, Dict[Any, int]] = {}
        for (_s, sp, _u), days in alerts.items():
            total = space_alerts.setdefault(sp, {})
            for day, n in days.items():
                total[day] = total.get(day, 0) + n

        def hours_for(pattern: str, siem_id: str = siem_id) -> int:
            own = windows.get((siem_id, pattern))
            return own["hours"] if own else default_hours

        for rule_id, space, enabled, last, rule, updated_at, last_updated in parsed:
            kibana = kibana_findings(last) if enabled else []
            for issue, cause, severity, detail in kibana:
                add(issue, cause, siem_id, space, rule_id, severity, detail)
            for issue, cause, severity, detail in catalogue_findings(rule, entries, {f[0] for f in kibana}):
                add(issue, cause, siem_id, space, rule_id, severity, detail)
            for issue, cause, severity, detail in freshness_findings(rule, newest, hours_for):
                add(issue, cause, siem_id, space, rule_id, severity, detail)
            for issue, cause, severity, detail in field_data_findings(rule, newest, filled):
                add(issue, cause, siem_id, space, rule_id, severity, detail)
            for issue, cause, severity, detail in ingest_findings(rule, delays):
                add(issue, cause, siem_id, space, rule_id, severity, detail)
            if enabled:
                for issue, cause, severity, detail in slow_findings(searches.get((rule["kibana_id"], space), []),
                                                                    rule["interval"], utc_now):
                    add(issue, cause, siem_id, space, rule_id, severity, detail)
            lists = rule_exceptions.lists_of(rule["exceptions"])
            if lists:
                for issue, cause, severity, detail in exception_findings(
                        rule_exceptions.iter_rule_items(lists, exception_items, space, utc_now), len(lists), limits, utc_now):
                    add(issue, cause, siem_id, space, rule_id, severity, detail)
            if enabled and limits.get("validation_stale"):     # #77, when the client turns it on
                checked = validations.get(str(rule["validation_key"])) or validations.get(rule["name"])
                for issue, cause, severity, detail in validation_findings(
                        checked, expired_weeks(rule["severity"]), rule["severity"],
                        history.get((rule_id, space), []), datetime.now()):
                    add(issue, cause, siem_id, space, rule_id, severity, detail)
            if enabled and not last:
                changed = _when(updated_at)
                if changed and last_updated and last_updated - changed > NEVER_RUN_AFTER:
                    add("never_run", "", siem_id, space, rule_id, KNOWN["never_run"].severity,
                        f"No run recorded since it was last changed, {changed:%Y-%m-%d %H:%M}.")
            # Its alerts (#68, #69, #70), where its space's were read: noisy, a spike, or silent unless a
            # problem found above already explains it.
            if enabled and (alert_reads.get((siem_id, space)) or {}).get("ok"):
                counts = alerts.get((siem_id, space, rule["kibana_id"]), {})
                changes = history.get((rule_id, space), [])
                explained = _explains_silence(rule_found.get((siem_id, space, rule_id), {}))
                for issue, cause, severity, detail in (
                        alert_findings(counts, space_alerts.get(space, {}), limits, until)
                        + spike_findings(counts, changes, until)
                        + ([] if explained else silent_findings(counts, _enabled_since(rule["created"], changes),
                                                                 limits, until, datetime.now()))):
                    add(issue, cause, siem_id, space, rule_id, severity, detail)

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
    # Custom rules linked to an Elastic rule they don't match, until the link is reviewed (rule_updates).
    try:
        from app.services.rule_diff import sections_text
        from app.services.rule_updates import unconfirmed_links
        links = unconfirmed_links(conn, sorted(rule_keys) if rule_keys is not None else None)
        for (rule_id, siem_id, space), link in links.items():
            if wanted(siem_id, space, rule_id):
                what = sections_text(link["sections"])
                add("elastic_link_differs", "", siem_id, space, rule_id, KNOWN["elastic_link_differs"].severity,
                    f"Its {what} {'differs' if len(link['sections']) == 1 else 'differ'} from Elastic's \"{link['name']}\".")
    except Exception:
        logger.warning("Could not check custom rules against the Elastic rules they are linked to", exc_info=True)
    # Upstream drift (#77): the Elastic or Sigma rule a rule came from retired, or updated and not
    # reviewed for the client's days. Elastic's prebuilt rules with updates are one finding per destination
    # (#95), found by a look at the whole destination: a refresh of a few rules leaves it as it was.
    try:
        from app.services import rule_origins
        keys = [(r[0], r[1], r[2]) for r in rules]
        about = {(r[0], r[1], r[2]): (bool(r[3]), r[17] or r[0]) for r in rules}     # enabled, name
        today = datetime.now().date()
        prebuilt: Dict[Tuple[str, str], List[Tuple[bool, str]]] = {}
        for (rule_id, siem_id, space), status in (rule_origins.statuses(conn, keys) if keys else {}).items():
            if wanted(siem_id, space, rule_id):
                for issue, cause, severity, detail in upstream_findings(status, limits, today):
                    if issue == "prebuilt_updates":
                        prebuilt.setdefault((siem_id, space), []).append(
                            about.get((rule_id, siem_id, space), (False, rule_id)))
                    else:
                        add(issue, cause, siem_id, space, rule_id, severity, detail)
        if rule_keys is None:
            for (siem_id, space), them in prebuilt.items():
                add("prebuilt_updates", "", siem_id, space, "", KNOWN["prebuilt_updates"].severity,
                    prebuilt_text(them, limits["upstream_pending_days"]))
    except Exception:
        logger.warning("Could not check rules against the Elastic and Sigma rules they came from", exc_info=True)
    if "space_fetch_results" in tables:
        for siem_id, space, duplicates in conn.execute(
                "SELECT siem_id, space, arg_max(duplicates, synced_at) FROM space_fetch_results GROUP BY 1, 2").fetchall():
            for dup in _json(duplicates, []):
                if wanted(siem_id, space, dup.get("rule_id")):
                    copies = ", ".join(f'"{r.get("name") or ""}"' for r in dup.get("rules", []) if not r.get("kept"))
                    add("shared_rule_id", "", siem_id, space, dup.get("rule_id"), KNOWN["shared_rule_id"].severity,
                        f"Kibana also holds {copies} under this rule id; TIDE shows only this one.")
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
    # Backed-up rule files changed in GitLab, which the backup put back to Kibana's (gitlab_backup).
    if "gitlab_backup_files" in tables:
        from app.services.gitlab_backup import OVERWRITE_DAYS
        for rule_id, siem_id, space, by, commit in conn.execute(
                "SELECT rule_id, siem_id, space, overwritten_by, overwritten_commit FROM gitlab_backup_files "
                f"WHERE rule_id IS NOT NULL AND overwritten_at >= now() - INTERVAL {int(OVERWRITE_DAYS)} DAY").fetchall():
            if wanted(siem_id, space, rule_id):
                who = f" by {by}" if by else ""
                where = f" in commit {commit}" if commit else ""
                add("backup_overwritten", "", siem_id, space, rule_id, KNOWN["backup_overwritten"].severity,
                    f"Its backup file was changed in GitLab{who}{where}; TIDE put Kibana's version back.")
    if rule_keys is None and "siem_space_status" in tables:
        for siem_id, space, reason in conn.execute(
                "SELECT siem_id, space, reason FROM siem_space_status WHERE NOT reachable").fetchall():
            if wanted(siem_id, space):
                add("siem_offline", "", siem_id, space, "", KNOWN["siem_offline"].severity, reason or "")
    # A space whose alerts the SIEM's key couldn't read at the last sync (#68).
    if rule_keys is None:
        for (siem_id, space), read in rule_alerts.reads(conn).items():
            if not read["ok"] and wanted(siem_id, space):
                add("alerts_unreadable", "", siem_id, space, "", KNOWN["alerts_unreadable"].severity,
                    f"Kibana didn't give its alerts at the last sync: {read['error'] or 'no answer'}.")
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

# Each time a finding began and was fixed, for the Dashboard's Compare with: how many began and how
# many were fixed in a period (``flows``). rule_issues holds one row per finding, reused when it comes
# back, and drops fixed ones after RESOLVED_DAYS; this keeps every occurrence HISTORY_DAYS after it
# was fixed. Per destination: when TIDE first looked at it (what it found then was there already, so
# isn't new), and, for one it already watched when this history began (6.3.2, from what rule_issues
# held), when the history is complete from (RESOLVED_DAYS before that).
HISTORY_DAYS = 100       # the Dashboard compares with up to 90 days ago
HISTORY_DDL = (
    """CREATE TABLE IF NOT EXISTS rule_issue_history (
        issue       VARCHAR NOT NULL,
        cause       VARCHAR NOT NULL,
        siem_id     VARCHAR NOT NULL,
        space       VARCHAR NOT NULL,
        rule_id     VARCHAR NOT NULL,
        severity    VARCHAR,
        opened_at   TIMESTAMP NOT NULL,
        resolved_at TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS rule_issue_watched (
        siem_id       VARCHAR NOT NULL,
        space         VARCHAR NOT NULL,
        first_at      TIMESTAMP NOT NULL,
        complete_from TIMESTAMP,
        PRIMARY KEY (siem_id, space)
    )""",
)


def _ensure_history(conn, now: datetime) -> None:
    """The history tables. The first time, begun from what rule_issues holds: its open findings from
    when each began, the ones fixed in the last RESOLVED_DAYS, and each destination as first seen."""
    had = {r[0] for r in conn.execute("SELECT table_name FROM duckdb_tables() "
                                      "WHERE database_name = current_database()").fetchall()}
    for ddl in HISTORY_DDL:
        conn.execute(ddl)
    if "rule_issue_history" in had:
        return
    conn.execute("INSERT INTO rule_issue_history SELECT issue, cause, siem_id, space, rule_id, severity, "
                 "first_seen, resolved_at FROM rule_issues")
    kept_from = now - timedelta(days=RESOLVED_DAYS)
    conn.execute("INSERT INTO rule_issue_watched SELECT siem_id, space, min(first_seen), "
                 "CASE WHEN min(first_seen) < ? THEN ?::TIMESTAMP END FROM rule_issues GROUP BY 1, 2",
                 [kept_from, kept_from])


# One client's refreshes run one at a time (#93). A sync's refresh of every destination and a rule
# action's refresh of one rule (a save, Sync this rule, Expect new data every…) can otherwise run at
# once on two pooled connections: both find the same new finding, the second insert fails on the
# primary key, and the sync's whole refresh is lost until the next sync. Keyed by the database file,
# so every connection to one client's database shares a lock and other clients never wait.
_REFRESH_LOCKS: Dict[str, threading.Lock] = {}
_REFRESH_LOCKS_GUARD = threading.Lock()
REFRESH_WAIT_S = 120.0       # how long a refresh waits for another of the same client's to finish


def _database_of(conn) -> str:
    """The database ``conn`` is on: its file; an in-memory one is its own."""
    try:
        row = conn.execute("SELECT path FROM duckdb_databases() WHERE database_name = current_database()").fetchone()
    except Exception:            # noqa: BLE001 - only the lock's key; an own lock is safe
        row = None
    return row[0] if row and row[0] else f"memory:{id(conn)}"


def _refresh_lock(database: str) -> threading.Lock:
    with _REFRESH_LOCKS_GUARD:
        return _REFRESH_LOCKS.setdefault(database, threading.Lock())


def refresh(db, conn, scopes: Optional[Set[Tuple[str, str]]] = None,
            rule_keys: Optional[Set[Tuple[str, str, str]]] = None,
            catalogue_for: Optional[Callable[[str], Any]] = None, now: Optional[datetime] = None,
            freshness_for: Optional[Callable[[str], Any]] = None, client_id: Optional[str] = None,
            field_data_for: Optional[Callable[[str], Any]] = None,
            delay_for: Optional[Callable[[str], Any]] = None) -> Dict[str, int]:
    """Record what ``detect`` finds now for ``scopes`` / ``rule_keys`` (``_refresh``), once any other
    refresh of the same client's database has finished (``REFRESH_WAIT_S`` at most; longer raises).
    A refresh that still meets a conflict in DuckDB is tried once more: what it records is worked out
    again from what is stored. Returns ``{"open", "new", "resolved"}``."""
    import duckdb
    lock = _refresh_lock(_database_of(conn))
    if not lock.acquire(timeout=REFRESH_WAIT_S):
        raise RuntimeError(f"Another Rule Monitoring refresh of this client took over {REFRESH_WAIT_S:.0f} s")
    try:
        args = (db, conn, scopes, rule_keys, catalogue_for, now or datetime.now(), freshness_for, client_id, field_data_for,
                delay_for)
        try:
            return _refresh(*args)
        except (duckdb.ConstraintException, duckdb.TransactionException) as exc:
            logger.warning("Rule Monitoring refresh met a conflict, trying once more: %s", exc)
            return _refresh(*args)
    finally:
        lock.release()


def _refresh(db, conn, scopes: Optional[Set[Tuple[str, str]]] = None,
             rule_keys: Optional[Set[Tuple[str, str, str]]] = None,
             catalogue_for: Optional[Callable[[str], Any]] = None, now: Optional[datetime] = None,
             freshness_for: Optional[Callable[[str], Any]] = None, client_id: Optional[str] = None,
             field_data_for: Optional[Callable[[str], Any]] = None,
             delay_for: Optional[Callable[[str], Any]] = None) -> Dict[str, int]:
    """Record what ``detect`` finds now for ``scopes`` / ``rule_keys``: a new finding is first seen
    now (again, if it had been resolved), one still there is seen now, and an open one in the same
    scope that is gone is resolved now. Resolved ones older than RESOLVED_DAYS are dropped. Each
    occurrence is also kept in rule_issue_history, HISTORY_DAYS after it was fixed, and a destination
    looked at for the first time is noted in rule_issue_watched. Returns ``{"open", "new", "resolved"}``."""
    import pandas as pd
    now = now or datetime.now()
    conn.execute(DDL)
    _ensure_history(conn, now)
    found = detect(db, conn, scopes, rule_keys, catalogue_for, freshness_for, client_id, field_data_for, delay_for)
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
        # The history: an occurrence begins with each finding that isn't open there, and ends when it is gone.
        conn.execute(
            "INSERT INTO rule_issue_history SELECT f.issue, f.cause, f.siem_id, f.space, f.rule_id, f.severity, ?, NULL "
            f"FROM issues_found f WHERE NOT EXISTS (SELECT 1 FROM rule_issue_history r WHERE {same} "
            "AND r.resolved_at IS NULL)", [now])
        conn.execute(
            f"UPDATE rule_issue_history r SET resolved_at = ? WHERE resolved_at IS NULL AND {scope_sql} "
            f"AND NOT EXISTS (SELECT 1 FROM issues_found f WHERE {same})", [now, *scope_params])
    finally:
        conn.unregister("issues_found")
    # A destination looked at for the first time: what is found there now was there already.
    looked = (set(scopes) if scopes is not None else {(k[1], k[2]) for k in rule_keys} if rule_keys is not None
              else set(conn.execute("SELECT DISTINCT siem_id, space FROM detection_rules").fetchall()))
    looked |= {(k[2], k[3]) for k in found}
    if looked:
        pairs = sorted(looked)
        conn.execute("INSERT INTO rule_issue_watched SELECT s, sp, ?, NULL FROM (SELECT unnest(?::VARCHAR[]) AS s, "
                     "unnest(?::VARCHAR[]) AS sp) x WHERE NOT EXISTS (SELECT 1 FROM rule_issue_watched w "
                     "WHERE w.siem_id = x.s AND w.space = x.sp)", [now, [p[0] for p in pairs], [p[1] for p in pairs]])
    conn.execute("DELETE FROM rule_issues WHERE resolved_at < ?", [now - timedelta(days=RESOLVED_DAYS)])
    conn.execute("DELETE FROM rule_issue_history WHERE resolved_at < ?", [now - timedelta(days=HISTORY_DAYS)])
    return {"open": len(found), "new": new, "resolved": len(resolved)}


def refresh_tenant(db, client_id: str, scopes: Optional[Iterable[Tuple[str, str]]] = None,
                   rule_keys: Optional[Iterable[Tuple[str, str, str]]] = None) -> Optional[Dict[str, int]]:
    """``refresh`` on one client's database after a sync; never raises (a sync must not fail over it)."""
    from app.services import sync_runs
    from app.services.tenant_manager import tenant_context_for
    try:
        with tenant_context_for(client_id), db.get_connection() as conn:
            counts = refresh(db, conn, set(scopes) if scopes is not None else None,
                             set(rule_keys) if rule_keys is not None else None, client_id=client_id)
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


def report_rule_health(conn, rules: Dict[Tuple[str, str, str], str], dest_names: Dict[Tuple[str, str], str],
                       now: Optional[datetime] = None) -> Dict[str, Any]:
    """A report's Rule health section (#80): the open Rule Monitoring findings on the rules the report
    counts (``rules``: ``{(rule_id, siem_id, space): name}``), grouped by what is wrong, worst first,
    with who fixes each. Muted ones are held back, as on the page, and counted. ``{rules, flagged,
    errors, warnings, muted, groups: [{issue, title, severity, fixer_label, count, rules: [{name,
    destination, cause, severity}]}]}``: ``errors`` the rules with an error, ``warnings`` those with
    warnings at worst, ``info`` those with only information. Never raises: a report mustn't fail for it."""
    out: Dict[str, Any] = {"rules": len(rules), "flagged": 0, "errors": 0, "warnings": 0, "info": 0, "muted": 0,
                           "groups": []}
    try:
        found = rule_findings(conn, rules.keys(), now) if rules else {}
    except Exception:
        logger.warning("Could not read Rule Monitoring's findings for a report", exc_info=True)
        found, out["unavailable"] = {}, True
    rank = lambda s: _SEVERITY_ORDER.get(s, 3)  # noqa: E731
    groups: Dict[str, Dict[str, Any]] = {}
    worst: Dict[Tuple[str, str, str], str] = {}
    for key, findings in found.items():
        for f in findings:
            if f["muted"]:
                out["muted"] += 1
                continue
            g = groups.setdefault(f["issue"], {"issue": f["issue"], "title": f["title"], "severity": f["severity"],
                                               "fixer_label": f["fixer_label"], "rules": []})
            g["severity"] = min(g["severity"], f["severity"], key=rank)
            g["rules"].append({"name": rules[key], "destination": dest_names.get((key[1], key[2])) or key[2],
                               "cause": f["cause"], "severity": f["severity"]})
            worst[key] = min(worst.get(key, f["severity"]), f["severity"], key=rank)
    for g in groups.values():
        g["rules"].sort(key=lambda r: (rank(r["severity"]), r["name"].lower(), r["destination"], r["cause"]))
        g["count"] = len({(r["name"], r["destination"]) for r in g["rules"]})
    out.update(flagged=len(worst), errors=sum(1 for s in worst.values() if s == "error"),
               warnings=sum(1 for s in worst.values() if s == "warning"),
               info=sum(1 for s in worst.values() if s == "info"),
               groups=sorted(groups.values(), key=lambda g: (rank(g["severity"]), -g["count"], g["title"])))
    out["summary"] = report_rule_health_summary(out)
    return out


def report_rule_health_summary(health: Dict[str, Any]) -> str:
    """The Rule health section's one line: how many of the rules counted have open findings."""
    n = health["rules"]
    if health.get("unavailable"):
        return "Rule Monitoring's findings couldn't be read, so they aren't shown."
    if not n:
        return "This report counts no rules."
    rules = f"{n} rule{'' if n == 1 else 's'} this report counts"
    if not health["flagged"]:
        text = f"None of the {rules} has an open Rule Monitoring finding." if n > 1 else \
            "The rule this report counts has no open Rule Monitoring finding."
    elif n == 1:
        text = "The rule this report counts has open Rule Monitoring findings, " + \
            ("with an error." if health["errors"] else "warnings only." if health["warnings"] else "information only.")
    else:
        parts = [f"{health['errors']} with an error" if health["errors"] else "",
                 f"{health['warnings']} with warnings only" if health["warnings"] else "",
                 f"{health.get('info', 0)} with information only" if health.get("info") else ""]
        who = f"All {rules}" if health["flagged"] == n else \
            f"{health['flagged']} of the {rules}"
        text = f"{who} {'has' if health['flagged'] == 1 else 'have'} open Rule Monitoring findings: " \
               f"{', '.join(p for p in parts if p)}."
    if health["muted"]:
        text += f" {health['muted']} muted finding{'' if health['muted'] == 1 else 's'} not shown."
    return text


def report_rule_health_markdown(health: Dict[str, Any], synced: str, technical: bool) -> List[str]:
    """The Rule health section as Markdown lines, for the system and threat reports' Markdown export."""
    lines = ["## Rule Health", "", health["summary"]]
    if synced:
        lines += ["", f"**Rules last synced:** {synced}"]
    lines.append("")
    if health["groups"]:
        lines += ["| What's wrong | Severity | Who fixes | Rules |", "|---|---|---|---|"]
        for g in health["groups"]:
            if technical:
                names = "; ".join(f"{r['name']} ({r['destination']}{', ' + r['cause'] if r['cause'] else ''})"
                                  for r in g["rules"]).replace("|", "\\|")
            else:
                names = str(g["count"])
            lines.append(f"| {g['title']} | {g['severity'].title()} | {g['fixer_label']} | {names} |")
        lines.append("")
    return lines


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

SEVERITIES = (("error", "Error"), ("warning", "Warning"), ("info", "Info"))
GROUPS = (("issue", "Issue"), ("fixer", "Who fixes"), ("destination", "SIEM / destination"), ("rule", "Rule"))
SHOW = (("open", "Open"), ("resolved", "Resolved recently"))
RULES = (("enabled", "Enabled"), ("all", "Include disabled"))
_SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}


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
    ``groups`` (as ``filters["group"]`` asks), ``metrics``, and ``counts`` per filter choice (with
    every other filter, not its own). ``destinations`` are the client's linked ones, ``[{id, space, name}]``;
    findings anywhere else are left out. Stale destinations come in as ``stale_data``, and with
    ``client_id``, steps its last sync failed as ``sync_step_failed``."""
    now = now or datetime.now()
    filters = {**filters, "fixer": fixer_values(filters.get("fixer"))}
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
    linked = _linked_to_elastic(conn, [_item(f) for f in found if f["issue"] == "custom_elastic_id"])
    for f in found:
        f["destination"] = names.get((f["siem_id"], f["space"]))
        known = KNOWN.get(f["issue"], KNOWN["other"])
        # sort_name: as a rule's row shows it, its name or, for a rule TIDE no longer holds, its rule id.
        f.update(title=known.title, fixer=known.fixer, fixer_label=FIXERS[known.fixer], age=_age(f["first_seen"], now),
                 sort_name=str(f["name"] or f["rule_id"] or "").lower(),
                 copies=copies.get(_item(f), []) if f["issue"] == "shared_rule_id" else [],
                 unlinkable=f["issue"] == "custom_elastic_id" and _item(f) in linked,
                 cluster=clusters.get(f["siem_id"], f["siem_id"]))
    every = [f for f in found if f["destination"] is not None]
    all_rules = (filters.get("rules") or "enabled") == "all"
    scope = filters.get("scope") or ""

    def shown(show: str) -> List[Dict[str, Any]]:
        """Open or resolved findings, on enabled rules unless disabled ones are asked for (TIDE's own
        problems, rule ids, matter whether the rule is on or not)."""
        return [f for f in every if (f["resolved_at"] is None) == (show == "open")
                and (all_rules or not f["rule_id"] or f["enabled"] or f["fixer"] == "tide")]

    def narrowed(rows: List[Dict[str, Any]], skip: str = "") -> List[Dict[str, Any]]:
        """The filter bar's other choices, all but ``skip`` (a filter's counts leave out its own choice)."""
        if scope and skip != "scope":
            rows = [f for f in rows if f"{f['siem_id']}|{f['space']}" == scope]
        for field in ("severity", "fixer", "issue"):
            wanted = set(filters.get(field) or [])
            if wanted and field != skip:
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

    # A muted cause (``ack``, stored as an acknowledgement) stays muted until it affects more rules than
    # when it was muted; a muted rule (``mute``: one problem of it, or every one) until it is unmuted. A
    # row can be both. ``ack_siem_ids``: the SIEM records its cause is muted on, for Unmute cause on the row.
    acks, counts_now, mutes = _acks(conn), _open_counts(conn), _mutes(conn)
    siems_of: Dict[str, List[str]] = {}
    for siem_id, cluster in clusters.items():
        siems_of.setdefault(cluster, []).append(siem_id)
    for f in every:
        ack = acks.get(_cause_key(f))
        if ack and f["resolved_at"] is None:
            current = counts_now.get(_cause_key(f), 0) if f["issue"] != "stale_data" else 1
            f["ack"] = ack if current <= ack["rules"] else None
            f["ack_lapsed"] = None if current <= ack["rules"] else {**ack, "now": current}
        else:
            f["ack"] = f["ack_lapsed"] = None
        f["ack_siem_ids"] = (sorted(s for s in siems_of.get(f["cluster"], [f["siem_id"]])
                                    if (f["issue"], f["cause"], s, "") in acks) if f["cause"] else [f["siem_id"]]
                             ) if f["ack"] else []
        f["mute"] = _muted(mutes, f) if f["resolved_at"] is None else None

    show = filters.get("show") or "open"
    before = shown(show)
    # Each choice's count is what the list holds once it is picked, with the other filters as they are.
    counts = {field: tally(narrowed(before, field), key) for field, key in (
        ("severity", lambda f: f["severity"]), ("fixer", lambda f: f["fixer"]), ("issue", lambda f: f["issue"]),
        ("scope", lambda f: f"{f['siem_id']}|{f['space']}"))}
    found = narrowed(before)
    group = filters.get("group") or "issue"
    open_rows = found if show == "open" else narrowed(shown("open"))
    muted = [f for f in open_rows if f["ack"] or f["mute"]]
    metrics = _metrics(conn, [f for f in open_rows if not (f["ack"] or f["mute"])], narrowed(shown("resolved")),
                       names, scope, all_rules, now)
    metrics["muted_causes"] = len({_fix_key(f) for f in muted if f["ack"]})
    metrics["muted_rules"] = len({_item(f) for f in muted if f["mute"]})
    if show == "open":
        groups = _group([f for f in found if not (f["ack"] or f["mute"])], group)
        if muted:
            groups.append(_node("muted", "muted", "Muted", muted, children=_group(muted, group, ("muted",))))
    else:
        groups = _group(found, group)
    return {"rows": found, "groups": groups, "metrics": metrics, "counts": counts, "now": now}


def rule_findings(conn, keys: Iterable[Tuple[str, str, str]],
                  now: Optional[datetime] = None) -> Dict[Tuple[str, str, str], List[Dict[str, Any]]]:
    """Each rule's open findings as Rule Monitoring lists them, for Rule Health's cards and the rule
    window: ``{(rule_id, siem_id, space): [{issue, title, fixer, fixer_label, severity, cause, detail,
    first_seen, age, muted}]}``, unmuted first, errors first. ``muted`` is what holds one back, as on the
    page: the rule muted (``what`` "rule"), or its cause, while that affects no more rules than when it
    was muted (``what`` "cause"); else None. Findings about a whole destination (data not synced, a SIEM
    that didn't answer) aren't a rule's own, and aren't listed."""
    keys = sorted(set(keys))
    now = now or datetime.now()
    rows = []
    try:
        for at in range(0, len(keys), _BATCH):
            where, params = _among(keys[at:at + _BATCH])
            rows += conn.execute("SELECT issue, cause, siem_id, space, rule_id, severity, detail, first_seen "
                                 "FROM rule_issues WHERE resolved_at IS NULL AND rule_id <> ''" + where, params).fetchall()
    except Exception:            # no sync since Rule Monitoring came in: nothing recorded yet
        return {}
    acks = _acks(conn)
    mutes, counts = _mutes(conn), _open_counts(conn) if acks else {}
    out: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for issue, cause, siem_id, space, rule_id, severity, detail, first_seen in rows:
        f = {"issue": issue, "cause": cause, "siem_id": siem_id, "space": space, "rule_id": rule_id,
             "severity": severity, "detail": detail, "first_seen": first_seen}
        known = KNOWN.get(issue, KNOWN["other"])
        ack = acks.get(_cause_key(f))
        if ack and counts.get(_cause_key(f), 0) > ack["rules"]:
            ack = None                   # the cause affects more rules than when it was muted: it's back
        mute = _muted(mutes, f)
        f.update(title=known.title, fixer=known.fixer, fixer_label=FIXERS[known.fixer], age=_age(first_seen, now),
                 muted={**mute, "what": "rule"} if mute else {**ack, "what": "cause"} if ack else None)
        out.setdefault((rule_id, siem_id, space), []).append(f)
    for found in out.values():
        found.sort(key=lambda f: (f["muted"] is not None, _SEVERITY_ORDER.get(f["severity"], 2), f["title"], f["cause"]))
    return out


def card_problems(found: List[Dict[str, Any]], enabled: bool) -> Optional[Dict[str, Any]]:
    """What a rule's card flags of its findings (``rule_findings``): every one not muted.
    ``{severity, count, disabled, lines}``, or None. ``severity`` is the worst of those the page lists
    by default -- on an enabled rule, or TIDE's own (its rule id) on any rule, which matter either way
    -- or "muted" when a disabled rule has only others: they would stop it working only if it were
    switched on, so its card shows them in grey."""
    shown = [f for f in found if not f["muted"]]
    if not shown:
        return None
    live = [f for f in shown if enabled or f["fixer"] == "tide"]
    severity = min((f["severity"] for f in live), key=lambda s: _SEVERITY_ORDER.get(s, 3)) if live else "muted"
    return {"severity": severity, "count": len(shown), "disabled": not enabled,
            "lines": [f"{f['severity'].title()}: {f['title']}" + (f" ({f['cause']})" if f["cause"] else "") for f in shown]}


FLOW_CARDS = ("rules", "errors", "warnings", "info", "causes")
_FLOW_OF = {"error": "errors", "warning": "warnings", "info": "info"}     # a severity's Compare with card


def flows(conn, destinations: List[Dict[str, Any]], filters: Dict[str, Any], start: datetime,
          now: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
    """How many began and how many were fixed after ``start`` (the Dashboard's Compare with), from the
    history of what syncs found, for the filters as ``view`` reads them (not Search): for each of
    ``FLOW_CARDS`` ``{"new", "fixed"}``, and ``since`` when the history is complete only from later
    than ``start`` (then both count from ``since``). A rule (or destination) is new with an error when
    one begins and fixed when it has none left; a cause, when it is found and when it is gone. What
    TIDE found when it first looked at a destination was there already, so isn't new. Problems worked
    out when asked (stale data, a failed sync step, a change TIDE didn't finish) have no history and
    aren't counted, nor are causes or rules muted now. None before the first sync that
    keeps history."""
    now = now or datetime.now()
    try:
        watched = {(s, sp): (first, complete) for s, sp, first, complete in conn.execute(
            "SELECT siem_id, space, first_at, complete_from FROM rule_issue_watched").fetchall()}
        stored = conn.execute(
            "SELECT h.issue, h.cause, h.siem_id, h.space, h.rule_id, h.severity, h.opened_at, h.resolved_at, "
            "COALESCE(d.enabled, 0) = 1 FROM rule_issue_history h LEFT JOIN detection_rules d "
            "ON d.rule_id = h.rule_id AND d.siem_id = h.siem_id AND d.space = h.space "
            "WHERE h.resolved_at IS NULL OR h.resolved_at > ?", [start]).fetchall()
    except Exception:          # no sync since the history came in
        return None
    names = {(d["id"], str(d.get("space") or "default")) for d in destinations}
    clusters = {d["id"]: cluster_of(d) for d in destinations}
    scope = filters.get("scope") or ""
    in_scope = {k for k in names if not scope or f"{k[0]}|{k[1]}" == scope}
    complete = [watched[k][1] for k in in_scope if k in watched and watched[k][1]]
    since = max(complete) if complete and max(complete) > start else None
    start = since or start
    all_rules = (filters.get("rules") or "enabled") == "all"
    wanted = {"severity": set(filters.get("severity") or []), "fixer": set(fixer_values(filters.get("fixer"))),
              "issue": set(filters.get("issue") or [])}
    acks, counts_now, mutes = _acks(conn), _open_counts(conn), _mutes(conn)
    spans: Dict[str, Dict[Any, List[Tuple[datetime, Optional[datetime], datetime]]]] = {k: {} for k in FLOW_CARDS}
    for issue, cause, s, sp, rule_id, severity, opened, resolved, enabled in stored:
        if (s, sp) not in in_scope or (s, sp) not in watched:
            continue
        f = {"issue": issue, "cause": cause, "siem_id": s, "space": sp, "rule_id": rule_id, "severity": severity,
             "fixer": KNOWN.get(issue, KNOWN["other"]).fixer, "cluster": clusters.get(s, s)}
        if any(v and f[k] not in v for k, v in wanted.items()):
            continue
        if not (all_rules or not rule_id or enabled or f["fixer"] == "tide"):
            continue
        ack = acks.get(_cause_key(f))
        if (ack and counts_now.get(_cause_key(f), 0) <= ack["rules"]) or _muted(mutes, f):
            continue
        span = (opened, resolved, watched[(s, sp)][0])
        if rule_id:
            spans["rules"].setdefault(_item(f), []).append(span)
        if severity in _FLOW_OF:
            spans[_FLOW_OF[severity]].setdefault(_item(f), []).append(span)
        spans["causes"].setdefault(_fix_key(f), []).append(span)
    out: Dict[str, Any] = {card: _moves(by_unit, start, now) for card, by_unit in spans.items()}
    out["since"] = since
    return out


def _moves(by_unit: Dict[Any, List[Tuple[datetime, Optional[datetime], datetime]]], start: datetime,
           now: datetime) -> Dict[str, int]:
    """How many units began after ``start`` and how many were fixed: each unit's spans
    ``(opened, resolved, first looked at)`` joined where they meet, so a rule fixed of one problem as
    another began was never fixed; it began when a joined span starts after ``start`` and after TIDE
    first looked, and was fixed when one ends after ``start``."""
    new = fixed = 0
    for spans in by_unit.values():
        joined: List[List[Any]] = []
        for opened, resolved, first in sorted(spans, key=lambda x: x[0]):
            end = resolved or datetime.max
            if joined and opened <= joined[-1][1]:
                joined[-1][1] = max(joined[-1][1], end)
            else:
                joined.append([opened, end, first])
        new += any(start < a <= now and a > first for a, _e, first in joined)
        fixed += any(start < e <= now for _a, e, _f in joined)
    return {"new": new, "fixed": fixed}


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


def _linked_to_elastic(conn, keys: List[Tuple[str, str, str]]) -> Set[Tuple[str, str, str]]:
    """Of ``keys``, the rules linked to one of Elastic's rules that can be unlinked from it
    (rule_origins.unlink_refused)."""
    if not keys:
        return set()
    from app.services import rule_origins
    try:
        origins = rule_origins.get_bulk(conn, keys)
    except Exception:
        logger.debug("Could not read rule origins", exc_info=True)
        return set()
    return {k for k, row in origins.items() if not rule_origins.unlink_refused(row)}


def _cause_key(f: Dict[str, Any]) -> Tuple[str, str, str, str]:
    """A cause on one SIEM record (what Mute cause mutes): the issue and its cause on a SIEM, or a
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


# ── muting a cause ───────────────────────────────────────────────────────
# Stored as an acknowledgement (rule_issue_acks), its name before 6.3.3.

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
    except Exception:            # no cause muted yet
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


def mute_cause(conn, key: Tuple[str, str, str, str], note: str, actor: str,
               now: Optional[datetime] = None) -> int:
    """Mute one cause until it affects more rules than it does now. Returns that number."""
    conn.execute(ACK_DDL)
    rules = _open_counts(conn).get(tuple(key), 1)
    conn.execute("INSERT OR REPLACE INTO rule_issue_acks VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                 [*key, (note or "").strip()[:1000], actor, now or datetime.now(), rules])
    return rules


def unmute_cause(conn, key: Tuple[str, str, str, str]) -> None:
    conn.execute(ACK_DDL)
    conn.execute("DELETE FROM rule_issue_acks WHERE issue = ? AND cause = ? AND siem_id = ? AND space = ?", list(key))


def cause_scope(conn, destinations: List[Dict[str, Any]], keys: List[Tuple[str, str, str, str]]) -> Dict[str, Any]:
    """What muting a cause (``keys``, causes_from's) holds back: ``keys``, ``rules``, how many rules it
    affects now, disabled ones too (more brings it back), and ``muted``, whether it is muted now. From
    a rule's row ``keys`` is the rule's SIEM record only: a named cause takes in the other SIEM records
    of its cluster it is open on, as its group on the page does."""
    counts, acks = _open_counts(conn), _acks(conn)
    if len(keys) == 1 and keys[0][1]:
        issue, cause, siem_id, _ = keys[0]
        clusters = {d["id"]: cluster_of(d) for d in destinations}
        home = clusters.get(siem_id, siem_id)
        keys = [k for k in ((issue, cause, s, "") for s in sorted({s for s, c in clusters.items() if c == home} | {siem_id}))
                if counts.get(k) or k[2] == siem_id]
    held = [k for k in keys if k in acks and counts.get(k, 0) <= acks[k]["rules"]]
    return {"keys": keys, "rules": sum(counts.get(k, 0) for k in keys), "muted": bool(keys) and len(held) == len(keys)}


# ── muting a rule ────────────────────────────────────────────────────────
# One rule's problem, or every problem it has now and later (issue and cause ''), muted until it is
# unmuted: unlike a cause, it doesn't come back by affecting more rules.

MUTE_DDL = """
    CREATE TABLE IF NOT EXISTS rule_issue_mutes (
        rule_id   VARCHAR NOT NULL,
        siem_id   VARCHAR NOT NULL,
        space     VARCHAR NOT NULL,
        issue     VARCHAR NOT NULL,    -- '' with cause '': every problem the rule has
        cause     VARCHAR NOT NULL,
        note      VARCHAR,
        muted_by  VARCHAR,
        muted_at  TIMESTAMP NOT NULL,
        PRIMARY KEY (rule_id, siem_id, space, issue, cause)
    )
"""


def _mutes(conn) -> Dict[Tuple[str, str, str, str, str], Dict[str, Any]]:
    try:
        rows = conn.execute("SELECT rule_id, siem_id, space, issue, cause, note, muted_by, muted_at "
                            "FROM rule_issue_mutes").fetchall()
    except Exception:            # nothing muted yet
        return {}
    return {tuple(r[:5]): {"issue": r[3], "cause": r[4], "note": r[5], "by": r[6], "at": r[7]} for r in rows}


def _muted(mutes, f: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The mute that holds ``f`` back: its own problem's, else its rule's for every problem."""
    rule = (f["rule_id"], f["siem_id"], f["space"])
    return mutes.get((*rule, f["issue"], f["cause"] or "")) or mutes.get((*rule, "", "")) if f["rule_id"] else None


def mute(conn, key: Tuple[str, str, str, str, str], note: str, actor: str, now: Optional[datetime] = None) -> None:
    """Mute one rule's problem (``key``: rule_id, siem_id, space, issue, cause), or every problem it
    has (issue and cause '')."""
    conn.execute(MUTE_DDL)
    conn.execute("INSERT OR REPLACE INTO rule_issue_mutes VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                 [*key, (note or "").strip()[:1000], actor, now or datetime.now()])


def unmute(conn, key: Tuple[str, str, str, str, str]) -> None:
    conn.execute(MUTE_DDL)
    conn.execute("DELETE FROM rule_issue_mutes WHERE rule_id = ? AND siem_id = ? AND space = ? AND issue = ? "
                 "AND cause = ?", list(key))


def mute_from(params) -> Optional[Tuple[str, str, str, str, str]]:
    """A rule mute's key from a request: the rule (rule_id, siem_id, space), and its problem (issue,
    cause), or every problem it has when ``scope`` is ``rule`` or there is no issue."""
    rule = tuple(str(params.get(k) or "").strip() for k in ("rule_id", "siem_id", "space"))
    issue = str(params.get("issue") or "")
    if not all(rule) or (issue and issue not in KNOWN):
        return None
    if params.get("scope") == "rule" or not issue:
        return (*rule, "", "")
    return (*rule, issue, str(params.get("cause") or ""))


def causes_from(params) -> List[Tuple[str, str, str, str]]:
    """A cause's keys from a request: issue, cause, siem_id and space (space only for a cause-less
    one). ``siem_id`` can name several SIEM records, comma-separated: one cause on one cluster."""
    issue, cause = params.get("issue") or "", params.get("cause") or ""
    siem_ids = [s for s in str(params.get("siem_id") or "").split(",") if s.strip()]
    if issue not in KNOWN or not siem_ids:
        return []
    return [(issue, cause, s.strip(), "" if cause else (params.get("space") or "")) for s in siem_ids]


# ── Raise issue ───────────────────────────────────────────────────

def _md(text: Any) -> str:
    """Text safe in a Markdown table cell or line."""
    return re.sub(r"\s+", " ", str(text or "")).replace("|", "\\|").strip()


# What an issue hands over depends on who it is for. For the engineer, an index or field problem is the
# fix itself: each index, the field it lacks, on which SIEM, with how many rules it holds back. Where
# the rule may be the one at fault instead (``_EITHER_SIDE``), it can be for the author: the rules, with
# the fields each uses. Every other issue is a table of its rules (or destinations), with what was found.
_FIELD_ISSUES = {"field_missing", "field_conflict", "override_missing", "unknown_field", "field_empty"}   # cause: a field
_PATTERN_ISSUES = {"no_index", "no_recent_data", "ingest_late"}                                       # cause: an index pattern
# issue: (who else may fix it, when, what each of them does)
_EITHER_SIDE = {
    "field_empty": ("author", "if the rule should match on another field", {
        "engineer": "Check the data source sends each field to its index, or that the index's ingest pipeline fills it: "
                    "the indexes map it, but no recent event has a value in it.",
        "author": "Check each rule matches on the field its data really fills, and correct its query if not."}),
    "field_missing": ("author", "if a field name is wrong", {
        "engineer": "Check the data source sends each field to its index, or that the index's ingest pipeline creates it.",
        "author": "Check each rule's query for a field name that is wrong, and correct it. If the names are right, "
                  "the data doesn't have these fields yet."}),
    "override_missing": ("author", "if the rule's timestamp override is wrong", {
        "engineer": "Add the field in the ingest pipeline for these indexes (event.ingested is set by Elastic's default "
                    "ingest pipeline).",
        "author": "Change each rule's timestamp override to a field its indexes have."}),
    "unknown_field": ("engineer", "if the field name is right", {
        "engineer": "Check the data source sends the field to the indexes the rules search, or that their ingest "
                    "pipeline creates it.",
        "author": "Check the field name in each rule's query, and correct it if it is wrong."}),
}


def audiences(nodes: List[Dict[str, Any]]) -> List[str]:
    """Who Raise issue can be for, when ``nodes`` hold an issue either role may fix: the first
    such issue's own fixer first. Empty when each issue has one."""
    out: List[str] = []
    for node in nodes:
        if node["issue"] in _EITHER_SIDE:
            for role in (KNOWN[node["issue"]].fixer, _EITHER_SIDE[node["issue"]][0]):
                if role not in out:
                    out.append(role)
    return out


def _cut(text: Any, size: int = 300) -> str:
    """``_md`` text, no longer than ``size``."""
    text = _md(text)
    return text if len(text) <= size else text[:size - 1].rstrip() + "…"


def _code(text: Any) -> str:
    """``_md`` text as inline code (a field, an index, a pattern), so it reads as typed."""
    text = _md(text).replace("`", "")
    return f"`{text}`" if text else "—"


# A column with one value on every row is said once, above the table, by these names. Since and State
# are said already (Failing since; Rules affected, with how many are disabled), so they just go.
_ONCE = {"SIEM": "SIEM", "Destination": "Destination", "Index": "Index", "Index pattern": "Index pattern",
         "Field": "Field", "Fields": "Fields", "Timestamp override": "Timestamp override",
         "What was found": "Found", "Since": "", "State": ""}


def _table(head: List[str], rows: List[List[str]], said: Set[str]) -> Tuple[List[str], List[str]]:
    """``rows`` (cells as Markdown) as a table under ``head``, and the lines saying a column that is the
    same on every row of two or more instead: ``(lines, table)``. A value the heading names (``said``)
    isn't said again."""
    once, keep = [], []
    for i, name in enumerate(head):
        values = {r[i] for r in rows}
        if len(rows) > 1 and len(values) == 1 and name in _ONCE:
            value = values.pop()
            if _ONCE[name] and value != "—" and value.strip("`") not in said:
                once.append(f"- **{_ONCE[name]}:** {value}")
            continue
        keep.append(i)
    return once, (["| " + " | ".join(head[i] for i in keep) + " |", "|" + "---|" * len(keep)]
                  + ["| " + " | ".join(r[i] for i in keep) + " |" for r in rows])


def _merged(rows: List[List[str]], at: int) -> List[List[str]]:
    """Rows alike but for column ``at`` (one rule's copies in several destinations) as one, naming each."""
    out: Dict[Tuple[str, ...], List[str]] = {}
    for r in rows:
        key = tuple(c for i, c in enumerate(r) if i != at)
        if key in out:
            out[key][at] += ", " + r[at]
        else:
            out[key] = list(r)
    return list(out.values())


def _first_sentence(text: Any) -> str:
    """What a finding says of its cause, without what it says of the rule (``freshness_findings``)."""
    text = str(text or "").strip()
    end = text.find(". ")
    return text[:end + 1] if end >= 0 else text


def _field_index(cause: str) -> Tuple[str, str]:
    """A field issue's cause, "<field> in <index>", as (field, index); the index is "" when it names none."""
    field, _, index = cause.partition(" in ")
    return field, index


def _state(f: Dict[str, Any]) -> str:
    return "Enabled" if f["enabled"] else "Disabled"


def _since(when: Optional[datetime]) -> str:
    return f"{when:%Y-%m-%d}" if when else "—"


def _rules_count(rules: Dict[Tuple[str, str, str], Dict[str, Any]]) -> str:
    disabled = sum(1 for f in rules.values() if not f["enabled"])
    return f"{len(rules)}" + (f" ({disabled} disabled)" if disabled else "")


def _by_rule(rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(rows, key=lambda f: (str(f["name"] or f["rule_id"]).lower(), str(f["destination"])))


def _fixes(issue: str, nodes: List[Dict[str, Any]], labels: Dict[str, str],
           patterns: Dict[Tuple[str, str, str], List[str]]) -> Tuple[List[str], List[List[str]]]:
    """The engineer's table: a row per index and field (or per index pattern) on each SIEM, by index,
    field and SIEM, with how many rules it holds back and since when. A cause listed in several groups
    is one row."""
    slots: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for node in nodes:
        siem = ", ".join(sorted(labels.get(s, s) for s in node["siem_ids"]))
        for f in node["rows"]:
            if issue in _PATTERN_ISSUES:
                places = [("", node["cause"])]
            elif issue == "unknown_field":           # Kibana names the field; the rule names where it searched
                places = [(node["cause"], p) for p in patterns.get(_item(f)) or [""]]
            else:
                places = [_field_index(node["cause"])]
            for field, index in places:
                slot = slots.setdefault((field, index, siem), {"rules": {}, "since": None, "seen": ""})
                if f["rule_id"]:
                    slot["rules"][_item(f)] = f
                if f["first_seen"] and (slot["since"] is None or f["first_seen"] < slot["since"]):
                    slot["since"] = f["first_seen"]
                slot["seen"] = slot["seen"] or _first_sentence(f["detail"])
    ordered = sorted(slots.items(), key=lambda kv: (kv[0][1].lower(), kv[0][0].lower(), kv[0][2].lower()))
    if issue == "no_index":
        return ["Index pattern", "SIEM", "Rules", "Since"], [
            [_code(index), _md(siem), _rules_count(s["rules"]), _since(s["since"])]
            for (_field, index, siem), s in ordered]
    if issue == "no_recent_data":           # how many of its rules see no recent data at all
        return ["Index pattern", "SIEM", "Rules", "Can't alert", "Since", "What was found"], [
            [_code(index), _md(siem), _rules_count(s["rules"]),
             str(sum(1 for f in s["rules"].values() if f["severity"] == "error")), _since(s["since"]), _cut(s["seen"])]
            for (_field, index, siem), s in ordered]
    if issue == "ingest_late":              # how late its events arrive
        return ["Index pattern", "SIEM", "Rules", "Since", "What was found"], [
            [_code(index), _md(siem), _rules_count(s["rules"]), _since(s["since"]), _cut(s["seen"])]
            for (_field, index, siem), s in ordered]
    return (["Index pattern" if issue == "unknown_field" else "Index",
             "Timestamp override" if issue == "override_missing" else "Field", "SIEM", "Rules", "Since"], [
        [_code(index), _code(field), _md(siem), _rules_count(s["rules"]), _since(s["since"])]
        for (field, index, siem), s in ordered])


def _rules_using(issue: str, nodes: List[Dict[str, Any]]) -> Tuple[List[str], List[List[str]]]:
    """The author's table, for an issue either role may fix: each rule and the fields it uses."""
    by_rule: Dict[Tuple[str, str, str], Tuple[Dict[str, Any], Set[str]]] = {}
    for node in nodes:
        field = node["cause"] if issue == "unknown_field" else _field_index(node["cause"])[0]
        for f in node["rows"]:
            if f["rule_id"]:
                by_rule.setdefault(_item(f), (f, set()))[1].add(field)
    head = ["Rule", "Destination", "State", "Timestamp override" if issue == "override_missing" else "Fields"]
    return head, _merged([[_md(f["name"] or f["rule_id"]), _md(f["destination"]), _state(f),
                           ", ".join(_code(x) for x in sorted(by_rule[_item(f)][1]))]
                          for f in _by_rule(f for f, _n in by_rule.values())], 1)


def _found(nodes: List[Dict[str, Any]]) -> Tuple[List[str], List[List[str]]]:
    """Every other issue's table: each rule, or whole destination, with what was found on it (a
    query's error is each rule's own)."""
    rows = [f for node in nodes for f in node["rows"]]
    if not any(f["rule_id"] for f in rows):
        return ["Destination", "Since", "What was found"], [
            [_md(f["destination"]), _since(f["first_seen"]), _cut(f["detail"])]
            for f in sorted(rows, key=lambda f: str(f["destination"]).lower())]
    return ["Rule", "Destination", "State", "Since", "What was found"], _merged([
        [_md(f["name"] or f["rule_id"]), _md(f["destination"]), _state(f), _since(f["first_seen"]), _cut(f["detail"])]
        for f in _by_rule(f for f in rows if f["rule_id"])], 1)


def _issue_markdown(issue: str, nodes: List[Dict[str, Any]], labels: Dict[str, str], now: datetime,
                    patterns: Dict[Tuple[str, str, str], List[str]], audience: str) -> str:
    """One issue's causes: what it is, who fixes it, and the table the one it is for needs."""
    known = KNOWN.get(issue, KNOWN["other"])
    rows = [f for node in nodes for f in node["rows"]]
    rules = {_item(f): f for f in rows if f["rule_id"]}
    firsts = [n["first_seen"] for n in nodes if n["first_seen"]]
    since = min(firsts) if firsts else None
    said: Set[str] = set()
    if len(nodes) == 1:
        node = nodes[0]
        siem = ", ".join(labels.get(s, s) for s in node["siem_ids"])
        title = f"### {known.title}: `{node['cause']}` on {siem}" if node["cause"] else f"### {known.title}: {node['where']}"
        said = {_md(node["cause"] or node["where"]), _md(siem), _md(", ".join(sorted(labels.get(s, s) for s in node["siem_ids"])))}
    else:
        title = f"### {known.title}"
    either = _EITHER_SIDE.get(issue)
    role = audience if either and audience in (known.fixer, either[0]) else known.fixer
    who = (f"{FIXERS[known.fixer]}, or {FIXERS[either[0]]} {either[1]}" if either and role == known.fixer
           else f"{FIXERS[role]} {either[1]}, or else {FIXERS[known.fixer]}" if either else FIXERS[known.fixer])
    places = {(f["siem_id"], f["space"]) for f in rows}
    affects = (f"- **Rules affected:** {_rules_count(rules)}" if rules
               else "- **Affects:** the whole destination" if len(places) == 1
               else f"- **Affects:** {len(places)} destinations, as a whole")
    if either and role == "author":
        head, cells = _rules_using(issue, nodes)
    elif issue in _PATTERN_ISSUES or issue in _FIELD_ISSUES:
        head, cells = _fixes(issue, nodes, labels, patterns)
    else:
        head, cells = _found(nodes)
    once, table = _table(head, cells, said)
    lines = [title,
             f"- **Who fixes:** {who} · **Severity:** {min((n['severity'] for n in nodes), key=_SEVERITY_ORDER.get).title()}",
             f"- **Failing since:** {since:%Y-%m-%d} ({_age(since, now)})" if since else "- **Failing since:** unknown",
             affects, *once,
             f"- **What it means:** {_md(known.meaning)}",
             f"- **To fix:** {_md(either[2][role] if either else known.check)}"]
    for node in nodes:
        if node.get("ack"):
            a = node["ack"]
            what = f"`{node['cause'] or node['where']}` " if len(nodes) > 1 else ""
            lines.append(f"- **Muted:** {what}by {_md(a['by'])} on {a['at']:%Y-%m-%d}"
                         + (f": {_md(a['note'])}" if a["note"] else ""))
    return "\n".join(lines + [""] + table)


def markdown(nodes: List[Dict[str, Any]], siem_labels: Dict[str, str], now: datetime,
             patterns: Optional[Dict[Tuple[str, str, str], List[str]]] = None, audience: str = "") -> str:
    """Causes as Markdown for a ticket or a chat, one section per issue in the order given: ``nodes``
    are cause nodes (``view`` groups); ``patterns`` the index patterns of the rules a field
    Elasticsearch can't find is on (``rule_patterns``); ``audience`` who it is for, a FIXERS key, for
    an issue either role may fix (``audiences``; otherwise each issue's own fixer)."""
    by_issue: Dict[str, List[Dict[str, Any]]] = {}
    for node in nodes:
        by_issue.setdefault(node["issue"], []).append(node)
    return "\n\n".join(_issue_markdown(issue, part, siem_labels, now, patterns or {}, audience)
                       for issue, part in by_issue.items()) + "\n"


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
        "info": sum(1 for s in worst.values() if s == "info"),
        "new_errors": sum(1 for i, s in worst.items() if s == "error" and since.get(i, now) >= week),
        "new_warnings": sum(1 for i, s in worst.items() if s == "warning" and since.get(i, now) >= week),
        "new_info": sum(1 for i, s in worst.items() if s == "info" and since.get(i, now) >= week),
        "tracked_since": tracked_since,
        "new_known": tracked_since is None or tracked_since <= week,
        "causes": len({_fix_key(f) for f in open_rows}),
        "by_fixer": {k: len(v) for k, v in by_fixer.items()},
        "resolved": len({_fix_key(f) for f in resolved_rows}),
        "resolved_rules": len({_item(f) for f in resolved_rows if f["rule_id"]}),
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


def _issues(rows, within: Tuple[str, ...] = ()) -> List[Dict[str, Any]]:
    """An issue node's ``path`` is where it is listed (the groups it is in, then its issue), so Copy
    for engineers can find it again (``node_at``)."""
    nodes = []
    for issue, part in _split(rows, lambda f: f["issue"]).items():
        known = KNOWN.get(issue, KNOWN["other"])
        node = _node("issue", issue, known.title, part, fixer=FIXERS[known.fixer], meaning=known.meaning,
                     check=known.check, path=[*within, issue])
        node["children"] = _causes(part)
        nodes.append(node)
    return _ordered(nodes)


def node_at(groups: List[Dict[str, Any]], path: Any, field: str = "path") -> Optional[Dict[str, Any]]:
    """The issue node listed at ``path`` (its ``path``), or the group whose ``field`` is ``path``; None
    when there is none."""
    for node in groups:
        if node.get(field) == path:
            return node
        found = node_at(node["children"], path, field)
        if found:
            return found
    return None


def remember_keys(groups: List[Dict[str, Any]], trail: str) -> None:
    """Each group's ``mem``: the groups it is in, then its own kind and key. The list remembers a group
    open or closed by it (data-remember), and finds the group again by it when it is opened."""
    for node in groups:
        key = node["key"]
        node["mem"] = f"{trail}/{node['kind']}:{key if isinstance(key, str) else '|'.join(map(str, key))}"
        remember_keys(node["children"], node["mem"])


def _group(rows: List[Dict[str, Any]], group: str, within: Tuple[str, ...] = ()) -> List[Dict[str, Any]]:
    """issue → cause → rules (the default); who fixes → issue → cause → rules; destination →
    issue → cause → rules; or rule → its findings."""
    if group in ("fixer", "destination"):
        by = (lambda f: f["fixer"]) if group == "fixer" else (lambda f: (f["siem_id"], f["space"]))
        nodes = []
        for key, part in _split(rows, by).items():
            node = _node(group, key, FIXERS[key] if group == "fixer" else part[0]["destination"], part)
            node["children"] = _issues(part, (*within, key if group == "fixer" else "|".join(key)))
            nodes.append(node)
        return _ordered(nodes)
    if group == "rule":
        return _ordered([
            _node("rule" if rule_id else "destination", (rule_id, siem_id, space),
                  (part[0]["name"] or rule_id) if rule_id else part[0]["destination"], part,
                  where=part[0]["destination"], rule_id=rule_id, siem_id=siem_id, space=space)
            for (rule_id, siem_id, space), part in _split(rows, _item).items()])
    return _issues(rows, within)
