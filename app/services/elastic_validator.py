"""Elastic's own rule validator in TIDE (#7): the checks Elastic runs on its prebuilt rules, run on the
client's custom rules.

It is Elastic's detection-rules package, installed in the image in a Python environment of its own
(``PYTHON``): it pins packages TIDE ships newer versions of. ``elastic_validator_runner.py`` runs in it,
one process per check; this module starts it and keeps what it found.

What it says about a rule's query (``problems``, as the runner gives them):
- an error: Elastic can't parse the query, or a value doesn't fit its field's type. Rule form Save,
  Sigma Deploy and Elastic Deploy don't write a rule with one when the client stops them (``stops``,
  its page's switch; off by default), else they name it and write the rule (``verdict``);
- a warning: a field in none of Elastic's schemas and not in the rule's indexes (TIDE's field
  catalogue). Shown, and the save goes ahead.
Elastic's conventions for its own repository aren't checked (see the runner).

At each sync, and on Sync this rule, the destination's custom rules are checked (``check_synced``) when
what is checked changed since (``fingerprint``: the query and what it searches, the catalogue's fields
for its patterns, the destination's Elastic version, Elastic's validator), and the result is kept in the
client's ``rule_elastic_checks`` for Rule Monitoring (``rule_issues.elastic_findings``). Elastic's prebuilt
rules aren't checked: Elastic checked them. In an image without the validator nothing is checked or said.
"""
from __future__ import annotations

import glob
import hashlib
import json
import logging
import os
import subprocess  # nosec B404 # runs Elastic's validator, a fixed script, in the image's own venv
import time
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

PYTHON = "/opt/elastic-venv/bin/python"
RUNNER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "elastic_validator_runner.py")
FORM_TIMEOUT_S = 60          # one rule, before writing it
SYNC_TIMEOUT_S = 600         # one batch at a sync
BATCH = 500                  # rules per runner at a sync
STACK_TTL_S = 3600           # how long a SIEM's Elastic version is taken as known

# The fields of a rule its check depends on, as Kibana holds them (the runner reads these and no more).
CHECKED = ("type", "language", "query", "index", "related_integrations", "timestamp_override",
           "event_category_override", "tiebreaker_field", "timestamp_field", "threshold", "new_terms",
           "new_terms_fields", "history_window_start", "threat_index", "threat_query", "threat_mapping",
           "threat_language", "threat_indicator_path", "threat_filters")
# Fields an Edit form change touches that change what is checked.
QUERY_KEYS = ("type", "language", "query", "index", "data_view_id", "event_category_override", "tiebreaker_field",
              "timestamp_field", "threshold", "new_terms_fields", "history_window_start", "threat_index",
              "threat_query", "threat_mapping", "threat_language")

DDL = """
    CREATE TABLE IF NOT EXISTS rule_elastic_checks (
        rule_id     VARCHAR NOT NULL,
        siem_id     VARCHAR NOT NULL,
        space       VARCHAR NOT NULL,
        fingerprint VARCHAR NOT NULL,
        checked_at  TIMESTAMP NOT NULL,
        problems    JSON,
        PRIMARY KEY (rule_id, siem_id, space)
    )
"""


def available() -> bool:
    """Whether this image has Elastic's validator."""
    return os.path.exists(PYTHON) and os.path.exists(RUNNER)


def version() -> str:
    """Elastic's validator as built into the image: detection-rules' version and the commit it came from."""
    try:
        with open(os.path.join(os.path.dirname(os.path.dirname(PYTHON)), ".tide-commit"), encoding="utf-8") as fh:
            commit = fh.read().split()[0][:12]
    except (OSError, IndexError):
        commit = ""
    found = glob.glob(os.path.join(os.path.dirname(os.path.dirname(PYTHON)), "lib", "python*", "site-packages",
                                   "detection_rules-*.dist-info"))
    pkg = os.path.basename(found[0])[len("detection_rules-"):-len(".dist-info")] if found else ""
    return f"{pkg} {commit}".strip()


def run(rules: Dict[str, Dict[str, Any]], fields: Dict[str, Dict[str, str]], stack: Optional[str],
        timeout: int = SYNC_TIMEOUT_S) -> Optional[Dict[str, List[Dict[str, Any]]]]:
    """Elastic's problems with each of ``rules`` (``{key: rule as Kibana holds it}``), given the fields
    the client's indexes have (``{pattern: {field: type}}``) and the destination's Elastic version:
    ``{key: [problem]}``. None when it isn't in this image or didn't answer, which is logged."""
    if not available() or not rules:
        return {} if available() else None
    request = {"rules": {k: {f: r.get(f) for f in CHECKED if r.get(f) not in (None, "", [])} for k, r in rules.items()},
               "fields": fields, "stack": stack}
    started = time.perf_counter()
    try:
        done = subprocess.run([PYTHON, "-I", RUNNER], input=json.dumps(request, default=str), capture_output=True,  # nosec B603 # a fixed command, the rules go in on stdin
                              text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("Elastic's validator didn't answer for %d rules: %s", len(rules), exc)
        return None
    for line in (done.stderr or "").splitlines()[-20:]:
        logger.info(line[:500])
    if done.returncode != 0:
        logger.warning("Elastic's validator failed (exit %s) for %d rules", done.returncode, len(rules))
        return None
    try:
        results = json.loads(done.stdout or "{}").get("results") or {}
    except ValueError:
        logger.warning("Elastic's validator gave an answer TIDE can't read")
        return None
    logger.info(f"[perf] Elastic's validator: {len(rules)} rules in {(time.perf_counter() - started) * 1000:.0f}ms")
    return {k: list(v or []) for k, v in results.items()}


# ── what it needs: the client's fields, the destination's version ───────

def fields_for(db, siem_id: str, patterns: Iterable[str]) -> Dict[str, Dict[str, str]]:
    """The fields TIDE's field catalogue holds for ``patterns`` on a SIEM: ``{pattern: {field: type}}``."""
    from app.services.mapping_catalogue import OK, MappingCatalogue
    patterns = [str(p) for p in dict.fromkeys(patterns) if p]
    if not patterns:
        return {}
    try:
        entries = MappingCatalogue(db, siem_id).entries(patterns)
    except Exception:  # noqa: BLE001 - checked against Elastic's schemas alone then
        logger.warning("Could not read the field catalogue of SIEM %s for Elastic's validator", siem_id, exc_info=True)
        return {}
    return {p: {f: str((info or ["keyword"])[0]) for f, info in (e.fields or {}).items()}
            for p, e in entries.items() if e.status == OK}


_stacks: Dict[str, Tuple[float, Optional[str]]] = {}


def stack_of(siem: Dict[str, Any]) -> Optional[str]:
    """A SIEM's Elastic version ("8.19.11"), asked of Kibana at most once an hour; None if unknown."""
    from app import elastic_helper
    url, key = str(siem.get("kibana_url") or ""), siem.get("api_token_enc") or ""
    if not url:
        return None
    at, known = _stacks.get(url, (0.0, None))
    if time.monotonic() - at < STACK_TTL_S:
        return known
    found = elastic_helper.kibana_version(url, key)
    _stacks[url] = (time.monotonic(), found)
    return found


def _patterns(rule: Dict[str, Any]) -> List[str]:
    return [str(p) for p in (rule.get("index") or []) + (rule.get("threat_index") or []) if p]


# ── before writing a rule ───────────────────────────────────────────────

def check_rule(db, siem: Dict[str, Any], rule: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """Elastic's problems with one rule about to be written to the SIEM ``siem`` (``{"id", "kibana_url",
    "api_token_enc"}``): ``[problem]``, or None when it wasn't checked."""
    if not available():
        return None
    found = run({"rule": rule}, fields_for(db, siem.get("id") or "", _patterns(rule)), stack_of(siem), FORM_TIMEOUT_S)
    return None if found is None else found.get("rule", [])


def touches_query(changes: Dict[str, Any]) -> bool:
    """Whether an edit changes what Elastic checks: an edit that doesn't is never stopped by it."""
    return any(k in changes for k in QUERY_KEYS)


def blocking(problems: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    return [p for p in problems or [] if p.get("kind") == "error"]


def warnings(problems: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    return [p for p in problems or [] if p.get("kind") == "warning"]


def _at(problem: Dict[str, Any]) -> str:
    line, column = int(problem.get("line") or 0), int(problem.get("column") or 0)
    return f" at line {line}, column {column}" if line and column else f" at line {line}" if line else ""


def describe(problem: Dict[str, Any]) -> str:
    """One problem in words, for the rule form and Rule Monitoring."""
    message = str(problem.get("message") or "").strip().rstrip(".")
    if problem.get("kind") == "warning":
        field = problem.get("field") or "A field"
        return (f"{field} is in none of Elastic's schemas (ECS, its integrations' and Endpoint's), and TIDE hasn't "
                "seen it in the rule's indexes.")
    if problem.get("what") == "syntax":
        return f"Elastic can't parse the query{_at(problem)}: {message}."
    return f"Elastic finds a value or comparison that doesn't fit its field{_at(problem)}: {message}."


def stops(db, client_id: str) -> bool:
    """Whether the client stops a save or deploy whose query Elastic's validator refuses (its page's
    Stop saves Elastic's validator refuses; off unless ticked). Otherwise the error is named, as a warning."""
    try:
        return bool((db.get_client(client_id) or {}).get("elastic_blocks"))
    except Exception:  # noqa: BLE001 - unreadable: only warn
        return False


def form_error(problems: List[Dict[str, Any]], doing: str) -> str:
    """Why a save or deploy was stopped: "Could not <doing>: …"."""
    return f"Could not {doing}: {describe(problems[0])} Correct the query and try again."


def form_note(problems: Optional[List[Dict[str, Any]]]) -> str:
    """What a save or deploy that went ahead adds about what Elastic found: "" when nothing."""
    note = ""
    errors = blocking(problems)
    if errors:
        note += f" {describe(errors[0])} It was written anyway: correct the query."
    found = warnings(problems)
    fields = [p.get("field") for p in found if p.get("field")]
    if len(fields) == 1:
        note += f" {describe(found[0])} Check its name."
    elif fields:
        shown = ", ".join(fields[:5]) + (f" and {len(fields) - 5} more" if len(fields) > 5 else "")
        note += (f" {shown} are in none of Elastic's schemas, and TIDE hasn't seen them in the rule's indexes. "
                 "Check their names.")
    return note


def verdict(problems: Optional[List[Dict[str, Any]]], stop: bool, doing: str) -> Tuple[Optional[str], str]:
    """``(why the save is stopped, or None; what a save that goes ahead adds to its message)``: an error
    stops it only when the client says so (``stops``)."""
    if stop and blocking(problems):
        return form_error(blocking(problems), doing), ""
    return None, form_note(problems)


# ── at a sync ───────────────────────────────────────────────────────────

def ensure(conn) -> None:
    conn.execute(DDL)


def fingerprint(rule: Dict[str, Any], fields: Dict[str, Dict[str, str]], stack: Optional[str], made_by: str) -> str:
    """What a rule's check depends on, as a hash: when it changes, the rule is checked again."""
    body = json.dumps({"rule": {k: rule.get(k) for k in CHECKED}, "stack": stack, "by": made_by,
                       "fields": {p: sorted((fields.get(p) or {}).items()) for p in _patterns(rule)}},
                      sort_keys=True, default=str)
    return hashlib.sha256(body.encode()).hexdigest()[:32]


_RULES_SQL = """
    SELECT rule_id, space, raw_data FROM detection_rules
    WHERE siem_id = ? AND NOT COALESCE(deprecated, false) AND NOT {prebuilt}
"""


def check_synced(db, client_id: str, scopes: Iterable[Tuple[str, str]],
                 rule_keys: Optional[Set[Tuple[str, str, str]]] = None) -> Dict[str, int]:
    """Check the custom rules of the destinations ``scopes`` (``(siem_id, space)``), or only the rules
    ``rule_keys``, whose fingerprint changed, and keep what Elastic found. Needs the client's database
    context. ``{"rules", "checked", "problems"}``; nothing is done without the validator."""
    from app.services.rule_origins import PREBUILT_SQL
    stats = {"rules": 0, "checked": 0, "problems": 0}
    if not available():
        return stats
    made_by = version()
    by_siem: Dict[str, Set[str]] = {}
    for siem_id, space in scopes:
        by_siem.setdefault(siem_id, set()).add(str(space or "default"))
    for siem_id, spaces in by_siem.items():
        siem = db.get_siem_inventory_item(siem_id) or {}
        with db.get_connection() as conn:
            ensure(conn)
            rows = [(r[0], r[1], r[2]) for r in conn.execute(_RULES_SQL.format(prebuilt=PREBUILT_SQL), [siem_id]).fetchall()
                    if r[1] in spaces and (rule_keys is None or (r[0], siem_id, r[1]) in rule_keys)]
            kept = {(r[0], r[1]): r[2] for r in conn.execute(
                "SELECT rule_id, space, fingerprint FROM rule_elastic_checks WHERE siem_id = ?", [siem_id]).fetchall()}
        rules = {}
        for rule_id, space, raw in rows:
            try:
                rules[(rule_id, space)] = json.loads(raw) if isinstance(raw, str) else (raw or {})
            except ValueError:
                continue
        stats["rules"] += len(rules)
        fields = fields_for(db, siem_id, {p for r in rules.values() for p in _patterns(r)})
        stack = stack_of(siem) if rules else None
        prints = {k: fingerprint(r, fields, stack, made_by) for k, r in rules.items()}
        due = [k for k in rules if kept.get(k) != prints[k]]
        for at in range(0, len(due), BATCH):
            part = due[at:at + BATCH]
            found = run({f"{k[0]}\x1f{k[1]}": rules[k] for k in part}, fields, stack)
            if found is None:
                break                        # not checked: tried again at the next sync
            now = datetime.now()
            with db.get_connection() as conn:
                for k in part:
                    problems = found.get(f"{k[0]}\x1f{k[1]}", [])
                    stats["problems"] += len(problems)
                    conn.execute("INSERT INTO rule_elastic_checks VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT "
                                 "(rule_id, siem_id, space) DO UPDATE SET fingerprint = EXCLUDED.fingerprint, "
                                 "checked_at = EXCLUDED.checked_at, problems = EXCLUDED.problems",
                                 [k[0], siem_id, k[1], prints[k], now, json.dumps(problems)])
            stats["checked"] += len(part)
        if rule_keys is None:
            with db.get_connection() as conn:       # rules no longer there, or now prebuilt
                for (rule_id, space) in set(kept) - set(rules):
                    if space in spaces:
                        conn.execute("DELETE FROM rule_elastic_checks WHERE rule_id = ? AND siem_id = ? AND space = ?",
                                     [rule_id, siem_id, space])
    return stats


def problems_by_rule(conn, siem_id: str) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
    """What Elastic found in each of a SIEM's rules at its last check: ``{(rule_id, space): [problem]}``."""
    try:
        rows = conn.execute("SELECT rule_id, space, problems::VARCHAR FROM rule_elastic_checks WHERE siem_id = ? "
                            "AND json_array_length(problems) > 0", [siem_id]).fetchall()
    except Exception:          # never checked in this tenant
        return {}
    return {(r[0], r[1]): json.loads(r[2] or "[]") for r in rows}
