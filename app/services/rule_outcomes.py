"""Outcomes from Kibana (rule tuning): what a rule's closed alerts turned out to be, as Elastic holds it.

At each sync, for each Kibana space synced, TIDE reads the space's closed Security cases of the last
``ALERT_DAYS`` (``elastic_helper.fetch_closed_cases``) and then runs one paged aggregation over its alerts
(``elastic_helper.fetch_alert_outcomes``). A script in that search gives each alert one outcome key, in the
order R28 sets: its closing reason (9.6), else its first outcome tag, else its case. Here those keys are
mapped onto ``rule_tuning.OUTCOMES`` with the client's mappings (``mapping``) and kept per rule, day,
source and outcome in place of the space's last ones (``rule_outcome_counts``), as alert counts are.

Mappings are per client, one set for all its destinations. A value maps to an outcome by the
client's choice, else by its name (``ALIASES``: *TP*, *False Positive*, *Benign True Positive*…), else it
is ignored. Values are compared without regard to case, spaces or punctuation (``norm``).

A case's outcome counts only when the client says where its case tool leaves it (``case_field``: the
case's tags, its category or one of its custom fields), and only for a case whose alerts all come from one
rule. An alert's own reason or tag wins over its case's outcome. TIDE keeps no case title,
description, comment or name: only counts, and each rule's latest closed cases (id, outcome, when)
for the link back.
"""
from __future__ import annotations

import json
import logging
from datetime import date, datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

Key = Tuple[str, str, str]          # (rule_id, siem_id, space)

COUNTS_DDL = """
    CREATE TABLE IF NOT EXISTS rule_outcome_counts (
        siem_id   VARCHAR NOT NULL,
        space     VARCHAR NOT NULL,
        rule_uuid VARCHAR NOT NULL,     -- kibana.alert.rule.uuid, as rule_alert_counts keys it
        day       DATE NOT NULL,        -- the alert's day, UTC
        source    VARCHAR NOT NULL,     -- kibana_reason, kibana_tag, kibana_case, kibana_none (closed, no
                                        -- outcome) or case_open (open or acknowledged in a closed case)
        outcome   VARCHAR NOT NULL,     -- a key of rule_tuning.OUTCOMES, or 'none'
        alerts    INTEGER NOT NULL,
        PRIMARY KEY (siem_id, space, rule_uuid, day, source, outcome)
    )
"""
CASES_DDL = """
    CREATE TABLE IF NOT EXISTS rule_outcome_cases (
        siem_id   VARCHAR NOT NULL,
        space     VARCHAR NOT NULL,
        rule_uuid VARCHAR NOT NULL,
        case_id   VARCHAR NOT NULL,
        outcome   VARCHAR,              -- the case's mapped outcome, when the client takes one from cases
        closed_at TIMESTAMP,
        alerts    INTEGER NOT NULL,     -- this rule's alerts in the case
        mixed     BOOLEAN NOT NULL,     -- it holds other rules' alerts too, so its outcome doesn't count
        PRIMARY KEY (siem_id, space, rule_uuid, case_id)
    )
"""
READS_DDL = """
    CREATE TABLE IF NOT EXISTS rule_outcome_reads (
        siem_id       VARCHAR NOT NULL,
        space         VARCHAR NOT NULL,
        read_at       TIMESTAMP NOT NULL,
        ok            BOOLEAN NOT NULL,     -- the alerts' outcomes were read
        error         VARCHAR,
        cases_ok      BOOLEAN NOT NULL,     -- the closed cases were read
        cases_error   VARCHAR,
        tag_values    VARCHAR,              -- JSON {tag: closed alerts}
        case_values   VARCHAR,              -- JSON {field: {value: cases}}
        reason_values VARCHAR,              -- JSON {closing reason: closed alerts} (9.6)
        case_fields   VARCHAR,              -- JSON {custom field key: its label}
        PRIMARY KEY (siem_id, space)
    )
"""

KIBANA_SOURCES = ("kibana_reason", "kibana_tag", "kibana_case")
SOURCE_LABELS = {"kibana_reason": "Closing reasons", "kibana_tag": "Alert tags", "kibana_case": "Cases",
                 "person": "People"}
LATEST_CASES = 5
MAX_VALUES = 50          # values kept per field found, for the mappings
MAX_VALUE_LEN = 60       # longer values are free text, not an outcome: not kept

# What a value is taken to mean when the client hasn't mapped it (``norm``'d): Kibana's default alert tags,
# True Positive and Benign True Positive, and the short forms case tools use (TP, FP, BTP).
ALIASES = {
    "tp": "true_positive", "truepositive": "true_positive",
    "btp": "benign_true_positive", "benigntruepositive": "benign_true_positive", "benignpositive": "benign_true_positive",
    "fp": "false_positive", "falsepositive": "false_positive",
    "falsepositivebaddata": "false_positive_data", "baddata": "false_positive_data",
    "duplicate": "duplicate", "dup": "duplicate",
    "undetermined": "undetermined", "inconclusive": "undetermined",
    "test": "test",
}
IGNORE = "ignore"
CASE_FIELDS = (("tags", "Case tags"), ("category", "Case category"))


def norm(value: Any) -> str:
    """A value as mappings compare it: lower case, letters and digits only (the alert search's script
    does the same)."""
    return "".join(ch for ch in str(value or "").lower() if ch.isalnum())


def choices(chosen: Dict[str, str]) -> Dict[str, str]:
    """The client's choices (``{value as found: outcome or IGNORE}``) keyed by ``norm``."""
    return {norm(k): v for k, v in chosen.items()}


def map_value(value: Any, chosen: Dict[str, str]) -> Optional[str]:
    """The outcome ``value`` maps to: the client's choice (``chosen``), else its name, else None (ignored)."""
    n = norm(value)
    picked = choices(chosen)
    if n in picked:
        return None if picked[n] == IGNORE else picked[n]
    return ALIASES.get(n)


def outcome_keys(chosen: Dict[str, str]) -> List[str]:
    """The ``norm``'d values that map to an outcome: what the alert search's script looks for."""
    picked = choices(chosen)
    return sorted({n for n in ALIASES if picked.get(n) != IGNORE} | {n for n, o in picked.items() if o != IGNORE})


# ── the client's mappings ────────────────────────────────────────────────────────────────────

EMPTY = {"tags": {}, "case_field": "", "case": {}, "reasons": {}}


def parse(raw: Any) -> Dict[str, Any]:
    """A stored mapping, with every part there: ``{tags, case_field, case, reasons}``."""
    from app.services.rule_tuning import OUTCOMES
    try:
        data = json.loads(raw) if isinstance(raw, str) and raw else (raw or {})
    except ValueError:
        data = {}
    out = {"tags": {}, "case": {}, "reasons": {}, "case_field": str(data.get("case_field") or "")}
    for part in ("tags", "case", "reasons"):
        for value, outcome in (data.get(part) or {}).items():
            value = str(value).strip()
            if norm(value) and (outcome == IGNORE or outcome in OUTCOMES) and outcome != "missed":
                out[part][value] = outcome
    return out


def mapping(db: Any, client_id: Optional[str]) -> Dict[str, Any]:
    """The client's mappings (``parse``); none chosen where it has none, or the column isn't there yet."""
    if not (db and client_id):
        return parse(None)
    try:
        with db.get_shared_connection() as conn:
            row = conn.execute("SELECT outcome_mapping FROM clients WHERE id = ?", [client_id]).fetchone()
    except Exception:          # noqa: BLE001 - a database not yet upgraded: nothing chosen
        return parse(None)
    return parse(row[0] if row else None)


def save_mapping(db: Any, client_id: str, data: Dict[str, Any]) -> None:
    db.update_client(client_id, outcome_mapping=json.dumps(parse(data)))


def script_params(chosen: Dict[str, Any], cases: Dict[str, Any]) -> Dict[str, Any]:
    """What the alert search's script needs: the outcome tags and reasons it looks for, and each closed
    case's closing time (epoch ms), so an alert in several takes the latest closed."""
    closed = {}
    for cid, c in ((cases or {}).get("cases") or {}).items():
        when = _parse_time(c.get("closed_at"))
        if when:
            closed[cid] = int(when.timestamp() * 1000)
    return {"tags": outcome_keys(chosen["tags"]), "reasons": outcome_keys(chosen["reasons"]), "closed": closed}


def _parse_time(value: Any) -> Optional[datetime]:
    """A Kibana time (ISO, UTC) as naive UTC."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def case_value(case: Dict[str, Any], field: str, chosen: Dict[str, str]) -> Optional[str]:
    """What the case says in ``field`` (``tags``, ``category`` or ``field:<key>``): for tags, the first that
    maps to an outcome."""
    if field == "tags":
        tags = [t for t in case.get("tags") or [] if t]
        return next((t for t in tags if map_value(t, chosen)), tags[0] if tags else None)
    if field == "category":
        return case.get("category") or None
    if field.startswith("field:"):
        value = (case.get("fields") or {}).get(field[6:])
        return None if value in (None, "") else str(value)
    return None


# ── one space's read ─────────────────────────────────────────────────────────────────────────

def ensure(conn) -> None:
    conn.execute(COUNTS_DDL)
    conn.execute(CASES_DDL)
    conn.execute(READS_DDL)


def _split(key: str) -> Tuple[str, str, str]:
    """An outcome key from the search's script, ``kind:value|case``, as ``(kind, value, case)``."""
    head, _sep, case = key.rpartition("|")
    kind, _sep, value = head.partition(":")
    return kind, value, case


def _values_found(cases: Dict[str, Any]) -> Dict[str, Dict[str, int]]:
    """How many closed cases hold each value, in each field a case tool could leave an outcome in."""
    out: Dict[str, Dict[str, int]] = {}

    def count(field, value):
        value = str(value or "").strip()
        if value and len(value) <= MAX_VALUE_LEN:
            out.setdefault(field, {})[value] = out.setdefault(field, {}).get(value, 0) + 1

    for c in cases.values():
        for t in c.get("tags") or []:
            count("tags", t)
        count("category", c.get("category"))
        for key, value in (c.get("fields") or {}).items():
            if isinstance(value, str):
                count(f"field:{key}", value)
    return {f: dict(sorted(v.items(), key=lambda kv: -kv[1])[:MAX_VALUES]) for f, v in out.items()}


def store(conn, siem_id: str, space: str, result: Dict[str, Any], cases: Dict[str, Any],
          chosen: Dict[str, Any], now: Optional[datetime] = None) -> Dict[str, int]:
    """Keep what one space's outcome read found (``fetch_alert_outcomes``, after ``fetch_closed_cases``):
    its outcome counts in place of the space's last ones, each rule's latest closed cases, the values
    found, and whether both reads worked. A failed outcome read keeps the last counts; so does a failed
    cases read while the client takes an outcome from cases. Returns ``{source: alerts}`` counted."""
    ensure(conn)
    cases = cases or {}
    cases_ok = bool(cases.get("ok"))
    closed = cases.get("cases") or {} if cases_ok else {}
    field = chosen.get("case_field") or ""
    ok = bool(result.get("ok"))
    last = conn.execute("SELECT tag_values, case_values, reason_values, case_fields FROM rule_outcome_reads "
                        "WHERE siem_id = ? AND space = ?", [siem_id, space]).fetchone()
    tag_values = result.get("tags") if ok else None
    reason_values = result.get("reasons") if ok else None
    case_values = _values_found(closed) if cases_ok else None
    case_fields = cases.get("fields") if cases_ok else None
    conn.execute(
        "INSERT INTO rule_outcome_reads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (siem_id, space) DO UPDATE SET "
        "read_at = EXCLUDED.read_at, ok = EXCLUDED.ok, error = EXCLUDED.error, cases_ok = EXCLUDED.cases_ok, "
        "cases_error = EXCLUDED.cases_error, tag_values = EXCLUDED.tag_values, case_values = EXCLUDED.case_values, "
        "reason_values = EXCLUDED.reason_values, case_fields = EXCLUDED.case_fields",
        [siem_id, space, now or datetime.now(), ok, None if ok else result.get("error"), cases_ok,
         None if cases_ok else cases.get("error"),
         json.dumps(tag_values) if tag_values is not None else (last[0] if last else None),
         json.dumps(case_values) if case_values is not None else (last[1] if last else None),
         json.dumps(reason_values) if reason_values is not None else (last[2] if last else None),
         json.dumps(case_fields) if case_fields is not None else (last[3] if last else None)])
    if not ok or (not cases_ok and field):
        return {}

    rows = [(str(u), str(d), str(k), int(n)) for u, d, k, n in result.get("rows") or [] if u and d and n]
    rules_of: Dict[str, set] = {}                 # the rules each case holds alerts of
    for uuid, _day, key, _n in rows:
        case = _split(key)[2]
        if case:
            rules_of.setdefault(case, set()).add(uuid)
    case_outcome = {cid: map_value(case_value(c, field, chosen["case"]), chosen["case"]) if field else None
                    for cid, c in closed.items()}

    counts: Dict[Tuple[str, str, str, str], int] = {}
    in_case: Dict[Tuple[str, str], int] = {}
    for uuid, day, key, n in rows:
        kind, value, case = _split(key)
        if case and case in closed:
            in_case[(uuid, case)] = in_case.get((uuid, case), 0) + n
        if kind == "o":
            if case and case in closed:
                source, outcome = "case_open", "none"
            else:
                continue
        elif kind == "r" and map_value(value, chosen["reasons"]):
            source, outcome = "kibana_reason", map_value(value, chosen["reasons"])
        elif kind == "t" and map_value(value, chosen["tags"]):
            source, outcome = "kibana_tag", map_value(value, chosen["tags"])
        elif case and case_outcome.get(case) and len(rules_of.get(case, ())) == 1:
            source, outcome = "kibana_case", case_outcome[case]
        else:
            source, outcome = "kibana_none", "none"
        k = (uuid, day, source, outcome)
        counts[k] = counts.get(k, 0) + n
    conn.execute("DELETE FROM rule_outcome_counts WHERE siem_id = ? AND space = ?", [siem_id, space])
    if counts:
        conn.executemany("INSERT INTO rule_outcome_counts VALUES (?, ?, ?, ?, ?, ?, ?)",
                         [[siem_id, space, u, d, s, o, n] for (u, d, s, o), n in counts.items()])
    if cases_ok:
        latest: Dict[str, List[Tuple[str, int]]] = {}
        for (uuid, case), n in in_case.items():
            latest.setdefault(uuid, []).append((case, n))
        conn.execute("DELETE FROM rule_outcome_cases WHERE siem_id = ? AND space = ?", [siem_id, space])
        keep = []
        for uuid, held in latest.items():
            held.sort(key=lambda cn: _parse_time(closed[cn[0]].get("closed_at")) or datetime.min, reverse=True)
            keep += [[siem_id, space, uuid, case, case_outcome.get(case), _parse_time(closed[case].get("closed_at")), n,
                      len(rules_of.get(case, ())) > 1] for case, n in held[:LATEST_CASES]]
        if keep:
            conn.executemany("INSERT INTO rule_outcome_cases VALUES (?, ?, ?, ?, ?, ?, ?, ?)", keep)
    out: Dict[str, int] = {}
    for (_u, _d, source, _o), n in counts.items():
        out[source] = out.get(source, 0) + n
    return out


# ── reading them back ────────────────────────────────────────────────────────────────────────

def _has(conn, table: str) -> bool:
    return bool(conn.execute("SELECT 1 FROM duckdb_tables() WHERE database_name = current_database() "
                             "AND table_name = ?", [table]).fetchone())


_JOIN = ("FROM detection_rules d JOIN rule_outcome_counts c ON c.siem_id = d.siem_id AND c.space = d.space "
         "AND c.rule_uuid = json_extract_string(d.raw_data, '$.id') ")


def _keys_sql(keys: List[Key]) -> Tuple[str, list]:
    return (" AND EXISTS (SELECT 1 FROM (SELECT unnest(?::VARCHAR[]) AS r, unnest(?::VARCHAR[]) AS s, "
            "unnest(?::VARCHAR[]) AS sp) k WHERE k.r = d.rule_id AND k.s = d.siem_id AND k.sp = d.space)",
            [[k[0] for k in keys], [k[1] for k in keys], [k[2] for k in keys]])


def by_rule(conn, keys: Iterable[Key], first: date, last: date) -> Dict[Key, Dict[str, Dict[str, int]]]:
    """Each rule's Kibana outcomes of the days ``first`` to ``last``: ``{key: {source: {outcome: alerts}}}``,
    with ``kibana_none`` (closed with no outcome) and ``case_open`` among the sources."""
    keys = sorted(set(keys))
    if not keys or not _has(conn, "rule_outcome_counts"):
        return {}
    where, params = _keys_sql(keys)
    out: Dict[Key, Dict[str, Dict[str, int]]] = {}
    for rule_id, siem_id, space, source, outcome, n in conn.execute(
            "SELECT d.rule_id, d.siem_id, d.space, c.source, c.outcome, sum(c.alerts) " + _JOIN
            + "WHERE c.day BETWEEN ? AND ?" + where + " GROUP BY ALL", [first, last, *params]).fetchall():
        out.setdefault((rule_id, siem_id, space), {}).setdefault(source, {})[outcome] = int(n)
    return out


def scope_totals(conn, scopes: Iterable[Tuple[str, str]], first: date, last: date) -> Dict[Tuple[str, str, str], Dict[str, Dict[str, int]]]:
    """Every rule's Kibana outcomes in ``scopes`` of the days ``first`` to ``last``, by its Kibana id:
    ``{(siem_id, space, rule uuid): {source: {outcome: alerts}}}``."""
    scopes = sorted(set(scopes))
    if not scopes or not _has(conn, "rule_outcome_counts"):
        return {}
    out: Dict[Tuple[str, str, str], Dict[str, Dict[str, int]]] = {}
    for siem_id, space, uuid, source, outcome, n in conn.execute(
            "SELECT siem_id, space, rule_uuid, source, outcome, sum(alerts) FROM rule_outcome_counts c WHERE day BETWEEN ? AND ? "
            "AND EXISTS (SELECT 1 FROM (SELECT unnest(?::VARCHAR[]) AS s, unnest(?::VARCHAR[]) AS sp) x "
            "WHERE x.s = c.siem_id AND x.sp = c.space) GROUP BY ALL",
            [first, last, [s for s, _ in scopes], [sp for _, sp in scopes]]).fetchall():
        out.setdefault((siem_id, space, uuid), {}).setdefault(source, {})[outcome] = int(n)
    return out


def last_true_positive(conn, key: Key) -> Optional[date]:
    """The newest day an alert of the rule closed as a true positive, by Kibana's outcomes."""
    if not _has(conn, "rule_outcome_counts"):
        return None
    where, params = _keys_sql([key])
    row = conn.execute("SELECT max(c.day) " + _JOIN + "WHERE c.outcome = 'true_positive' AND c.source IN "
                       "('kibana_reason', 'kibana_tag', 'kibana_case')" + where, params).fetchone()
    return row[0] if row else None


def latest_cases(conn, key: Key, kibana_url: str = "") -> List[Dict[str, Any]]:
    """The rule's latest closed cases (at most ``LATEST_CASES``), newest first: ``[{id, outcome, label,
    closed_at, alerts, mixed, url}]``, ``url`` the case in Kibana when its address is known."""
    from app.services.rule_tuning import OUTCOMES
    if not _has(conn, "rule_outcome_cases"):
        return []
    rows = conn.execute(
        "SELECT o.case_id, o.outcome, o.closed_at, o.alerts, o.mixed FROM detection_rules d JOIN rule_outcome_cases o "
        "ON o.siem_id = d.siem_id AND o.space = d.space AND o.rule_uuid = json_extract_string(d.raw_data, '$.id') "
        "WHERE d.rule_id = ? AND d.siem_id = ? AND d.space = ? ORDER BY o.closed_at DESC NULLS LAST", list(key)).fetchall()
    base = (kibana_url or "").rstrip("/")
    space = key[2]
    prefix = f"{base}/s/{space}"
    return [{"id": cid, "outcome": outcome, "label": OUTCOMES[outcome].label if outcome in OUTCOMES else "",
             "closed_at": closed_at, "alerts": int(n), "mixed": bool(mixed),
             "url": f"{prefix}/app/security/cases/{cid}" if base else ""} for cid, outcome, closed_at, n, mixed in rows]


def reads(conn) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """Each space's last outcome read: ``{(siem_id, space): {read_at, ok, error, cases_ok, cases_error,
    tags, cases, reasons, fields}}``, the last four the values found."""
    if not _has(conn, "rule_outcome_reads"):
        return {}

    def load(raw):
        try:
            return json.loads(raw) if raw else {}
        except ValueError:
            return {}

    return {(r[0], r[1]): {"read_at": r[2], "ok": r[3], "error": r[4] or "", "cases_ok": r[5], "cases_error": r[6] or "",
                           "tags": load(r[7]), "cases": load(r[8]), "reasons": load(r[9]), "fields": load(r[10])}
            for r in conn.execute("SELECT siem_id, space, read_at, ok, error, cases_ok, cases_error, tag_values, "
                                  "case_values, reason_values, case_fields FROM rule_outcome_reads").fetchall()}


def found(conn, scopes: Iterable[Tuple[str, str]]) -> Dict[str, Any]:
    """The values found in ``scopes``' last reads, added up, for the client's mappings: ``{tags, cases
    ({field: {value: cases}}), reasons, fields ({key: label}), read (any read yet), cases_read}``."""
    scopes = set(scopes)
    out = {"tags": {}, "cases": {}, "reasons": {}, "fields": {}, "read": False, "cases_read": False}
    for scope, read in reads(conn).items():
        if scope not in scopes:
            continue
        out["read"] = out["read"] or bool(read["ok"])
        out["cases_read"] = out["cases_read"] or bool(read["cases_ok"])
        for part in ("tags", "reasons"):
            for value, n in (read[part] or {}).items():
                out[part][value] = out[part].get(value, 0) + int(n)
        for field, values in (read["cases"] or {}).items():
            for value, n in values.items():
                out["cases"].setdefault(field, {})[value] = out["cases"].get(field, {}).get(value, 0) + int(n)
        out["fields"].update(read["fields"] or {})
    return out
