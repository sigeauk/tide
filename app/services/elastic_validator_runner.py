"""Elastic's own rule validator (its detection-rules package), as TIDE runs it (#7).

TIDE runs this file in the Python environment detection-rules is installed in, ``/opt/elastic-venv``:
a separate one, as detection-rules pins packages TIDE ships newer versions of. So it imports only the
standard library and detection-rules, never TIDE's code. ``app.services.elastic_validator`` starts
it and reads its answer.

In (stdin, JSON): ``{"rules": {key: a rule as Kibana holds it}, "fields": {index pattern: {field:
type}}, "stack": "8.19.0" or null}``. ``fields`` are the fields the client's indexes have (TIDE's
field catalogue); ``stack`` is the destination's Elastic version.

Out (stdout, JSON): ``{"version": detection-rules', "results": {key: [problem]}}``; a problem is
``{"kind": "error" | "warning", "what": "syntax" | "type" | "field", "field", "message", "line",
"column"}`` (line and column from 1, 0 when Elastic didn't say).
- an error: Elastic can't parse the query, or a value doesn't fit its field's type;
- a warning: a field in none of Elastic's schemas (ECS, its integrations', Endpoint's) and not in
  ``fields``. Elastic stops at the first; each is accepted in turn to find the next.

Only the query is checked: Elastic's conventions for its own repository (UUID rule ids, tags, notes,
building-block timing, version and revision, threat links) aren't faults in a customer's rules. A
rule type Elastic doesn't check (machine learning) has no problems.

``--self-test`` checks it tells a good query from a broken one and an unknown field, and exits 1 if
not: the image build runs it, so a change in Elastic's code fails the build rather than ship broken.
"""
import json
import os
import re
import sys

# Elastic's repository conventions, off before detection-rules reads them at import.
for _flag in ("DR_BYPASS_NOTE_VALIDATION_AND_PARSE", "DR_BYPASS_TAGS_VALIDATION", "DR_BYPASS_TIMELINE_TEMPLATE_VALIDATION",
              "DR_BYPASS_BBR_LOOKBACK_VALIDATION", "DR_BYPASS_ESQL_METADATA_VALIDATION", "DR_BYPASS_ESQL_KEEP_VALIDATION"):
    os.environ[_flag] = "1"

import marshmallow  # noqa: E402
from detection_rules import ecs  # noqa: E402

# The client's fields, and unknown fields accepted to find the next. Elastic caches its schemas, so
# this is in place before any rule is checked, and its caches are cleared when it changes.
FIELDS = {}
_elastic_non_ecs = ecs.get_non_ecs_schema


def _non_ecs_with_client():
    combined = {pattern: dict(fields) for pattern, fields in _elastic_non_ecs().items()}
    for pattern, fields in FIELDS.items():
        combined.setdefault(pattern, {}).update(fields)
    return combined


ecs.get_non_ecs_schema = _non_ecs_with_client

from detection_rules import utils as _dr_utils  # noqa: E402
from detection_rules.integrations import load_integrations_manifests  # noqa: E402
from detection_rules.rule import RULES_CONFIG, TOMLRuleContents  # noqa: E402
from detection_rules.schemas import load_stack_schema_map  # noqa: E402
from detection_rules.utils import clear_caches  # noqa: E402


def _fields_changed():
    """``FIELDS`` changed: forget only the schemas built from it, keeping the costly ones (Elastic's
    integration schemas) loaded."""
    for made in (ecs.get_index_schema, ecs.get_custom_index_schema, ecs.get_kql_schema, ecs.get_eql_schema,
                 ecs.get_all_flattened_schema):
        getattr(made, "clear", lambda: None)()
    _dr_utils._cache_generation += 1          # Elastic's per-object memos

# Kibana takes AND, OR and NOT in any case; Elastic's own repository wants them lower case.
object.__setattr__(RULES_CONFIG, "normalize_kql_keywords", True)


def stack_key(version):
    """The entry of Elastic's schema map for an Elastic version: the newest at or below it (8.19.11 ->
    8.19.0), the oldest for one older than all, None when there is no version."""
    def parts(text):
        return tuple(int(p) for p in re.findall(r"\d+", str(text))[:3]) or (0,)
    if not version:
        return None
    keys = sorted(load_stack_schema_map(), key=parts)
    below = [k for k in keys if parts(k)[:2] <= parts(version)[:2]]
    return (below or keys)[-1] if keys else None


# The errors that are about the query, by class name: KQL's, EQL's, and ES|QL's (its parser's, and
# detection-rules' own wrappers of them). An unknown index in an ES|QL FROM isn't one: Elastic just
# doesn't know its fields.
_QUERY_ERROR_MODULES = ("kql", "eql", "esql", "detection_rules.esql_errors")
_FIELD_ERRORS = ("EqlSchemaError", "EsqlSchemaError")
_SYNTAX_ERRORS = ("EqlSyntaxError", "EsqlSyntaxError")
_NOT_PROBLEMS = ("EsqlUnknownIndexError",)


def _about_query(exc):
    return any(type(exc).__module__ == m or type(exc).__module__.startswith(m + ".") for m in _QUERY_ERROR_MODULES)

MAX_FIELDS = 10          # unknown fields listed per rule
ANY_UUID = "00000000-0000-4000-8000-000000000000"

# What a rule's query is checked with, by rule type: Kibana's own fields, as it holds them.
_COMMON = ("name", "description", "risk_score", "severity", "type", "language", "query", "index", "from", "interval",
           "related_integrations", "timestamp_override", "event_category_override", "tiebreaker_field",
           "timestamp_field")
_BY_TYPE = {
    "query": (), "eql": (), "esql": (),
    "threshold": ("threshold",),
    "new_terms": ("new_terms", "new_terms_fields", "history_window_start"),
    "threat_match": ("threat_index", "threat_query", "threat_mapping", "threat_language", "threat_indicator_path",
                     "threat_filters"),
}


def _shape(rule):
    """The rule as Elastic checks it, or None for a type it doesn't check."""
    kind = str(rule.get("type") or "query")
    if kind not in _BY_TYPE or not rule.get("query"):
        return None
    data = {k: rule[k] for k in _COMMON + _BY_TYPE[kind] if rule.get(k) not in (None, "", [])}
    if kind == "esql":
        data.pop("index", None)         # its FROM names its indexes
    data.setdefault("risk_score", 21)
    data.setdefault("severity", "low")
    data.setdefault("related_integrations", [])
    # What Elastic holds its own rules to and the query doesn't depend on (its name pattern, rule id).
    data.update({"name": "Rule Checked By TIDE", "description": "Checked by TIDE.", "rule_id": ANY_UUID,
                 "author": ["TIDE"], "license": "Elastic License v2"})
    return data


_DATA_STREAM = re.compile(r"^(?:logs|metrics)-([a-z0-9_]+)(?:[.*-]|$)")


def _packages(data):
    """The Elastic integrations whose schemas the query is checked against: those Kibana lists for the
    rule, and those whose data streams its index patterns name (logs-endpoint.events.process-* is
    Endpoint's), as Elastic does for an ES|QL rule's FROM. A copy of one of Elastic's rules made
    without its integrations is checked as Elastic checks the original."""
    out = [r["package"] for r in data.get("related_integrations") or [] if isinstance(r, dict) and r.get("package")]
    known = load_integrations_manifests()
    for pattern in data.get("index") or []:
        m = _DATA_STREAM.match(str(pattern))
        if m and m.group(1) in known and m.group(1) not in out:
            out.append(m.group(1))
    return out


def _meta(data, stack):
    meta = {"creation_date": "2026/01/01", "updated_date": "2026/01/01", "maturity": "production",
            "integration": _packages(data)}
    if stack:
        meta["min_stack_version"] = stack
    return meta


_AT = re.compile(r"line:(\d+),column:(\d+)")


def _where(exc):
    """Where Elastic points (line and column from 1; 0 when it doesn't say), and its caret's width."""
    if isinstance(getattr(exc, "line", None), int) and isinstance(getattr(exc, "column", None), int):
        return exc.line, exc.column, len(str(getattr(exc, "caret", "") or "").strip())
    m = _AT.search(str(exc))
    if not m:
        return None, None, 0
    caret = next((ln for ln in str(exc).splitlines() if ln.strip() and set(ln.strip()) == {"^"}), "")
    return int(m.group(1)) - 1, int(m.group(2)), len(caret.strip())


def _field(query, line, column, width):
    """The field Elastic's caret is under in the query."""
    try:
        text = query.splitlines()[min(line, len(query.splitlines()) - 1)]
        return re.sub(r"^\W+|\W+$", "", text[column:column + max(width, 1)]) or None
    except Exception:  # noqa: BLE001 - not every error points at a field
        return None


def _message(exc):
    """Elastic's message, without its "Error at line…" and the query it repeats."""
    text = str(getattr(exc, "error_msg", "") or "").strip()
    if not text:
        lines = [ln.strip() for ln in str(exc).strip().splitlines() if ln.strip()]
        lines = lines[1:] if lines and _AT.search(lines[0]) else lines
        text = lines[0] if lines else type(exc).__name__
    return text[:300]


def _problem(exc, query):
    """What one of Elastic's errors says, as a problem; None when it isn't one."""
    name = type(exc).__name__
    if name in _NOT_PROBLEMS:
        return None
    line, column, width = _where(exc)
    message = _message(exc)
    base = {"line": line + 1 if line is not None else 0, "column": column + 1 if column is not None else 0,
            "message": message, "field": None}
    if (name == "KqlParseError" and message == "Unknown field") or name in _FIELD_ERRORS:
        named = re.search(r"'([^']+)'", message)          # ES|QL names it: Unknown field 'x'
        return {**base, "kind": "warning", "what": "field",
                "field": named.group(1) if named else _field(query, line, column, width) if line is not None else None}
    if name in _SYNTAX_ERRORS or (name == "KqlParseError" and message in ("Invalid syntax", "Unexpected EOF",
                                                                         "No query provided")):
        return {**base, "kind": "error", "what": "syntax"}
    return {**base, "kind": "error", "what": "type",
            "field": _field(query, line, column, width) if line is not None else None}


def check(rule, stack=None):
    """Every problem Elastic finds in one rule's query (``[problem]``)."""
    data = _shape(rule)
    if data is None:
        return []
    accepted = []                       # (pattern, field) taken in to look further, undone after
    try:
        return _check(rule, data, _meta(data, stack), accepted)
    finally:
        if accepted:
            for pattern, field in accepted:
                FIELDS.get(pattern, {}).pop(field, None)
            _fields_changed()


def _check(rule, data, meta, accepted):
    problems = []
    query = str(data.get("query") or "")
    for _ in range(MAX_FIELDS + 1):
        try:
            TOMLRuleContents.from_dict({"metadata": meta, "rule": data, "transforms": None}, unknown=marshmallow.EXCLUDE)
            return problems
        except marshmallow.ValidationError as exc:
            # Elastic's own schema refused the rule's shape, not its query: not one of the problems TIDE lists.
            print(f"elastic_validator: {rule.get('name')!r} not checked: {str(exc.messages)[:300]}", file=sys.stderr)
            return problems
        except Exception as exc:  # noqa: BLE001 - sorted by what it is about below
            if not _about_query(exc):
                raise
            found = _problem(exc, query)
        if found is None:
            return problems
        if found["what"] != "field" and found["field"] in {f for _p, f in accepted}:
            return problems          # about a field taken in to look further, whose type was only a guess
        problems.append(found)
        if found["what"] != "field" or not found["field"] or str(rule.get("type")) == "esql":
            return problems
        taken = len(accepted)
        for pattern in data.get("index") or []:
            if found["field"] not in FIELDS.get(pattern, {}):
                FIELDS.setdefault(pattern, {})[found["field"]] = "keyword"
                accepted.append((pattern, found["field"]))
        if len(accepted) == taken:
            return problems          # nowhere to take it in: Elastic would stop at it again
        _fields_changed()
    return problems


def run(request):
    """``request`` as the module docstring says; the answer to print."""
    from importlib.metadata import version
    FIELDS.clear()
    for pattern, fields in (request.get("fields") or {}).items():
        FIELDS[pattern] = {str(f): str(t) for f, t in (fields or {}).items()}
    clear_caches()
    stack = stack_key(request.get("stack"))
    results = {}
    for key, rule in (request.get("rules") or {}).items():
        try:
            results[key] = check(rule, stack)
        except Exception as exc:  # noqa: BLE001 - one rule Elastic's code trips over doesn't stop the rest
            print(f"elastic_validator: {rule.get('name')!r} not checked: {type(exc).__name__}: {exc}"[:400], file=sys.stderr)
            results[key] = []
    return {"version": version("detection-rules"), "results": results}


def self_test():
    """True when Elastic's code tells a good query from a broken one and an unknown field, in KQL and EQL."""
    base = {"name": "TIDE self-test", "description": "x", "risk_score": 21, "severity": "low", "index": ["logs-*"],
            "from": "now-6m", "interval": "5m"}
    kql = {**base, "type": "query", "language": "kuery"}
    eql = {**base, "type": "eql", "language": "eql"}
    esql = {**base, "type": "esql", "language": "esql"}
    cases = {
        "good": ({**kql, "query": 'process.name : "cmd.exe"'}, []),
        "syntax": ({**kql, "query": 'process.name : ("cmd.exe"'}, ["error"]),
        "type": ({**kql, "query": 'process.pid : "not a number"'}, ["error"]),
        "fields": ({**kql, "query": 'tide.no_such_field : "x" and tide.nor_this : "y"'}, ["warning", "warning"]),
        "client": ({**kql, "query": 'tide.client_field : "x"'}, []),
        "eql": ({**eql, "query": 'process where process.name == "cmd.exe"'}, []),
        "eql_field": ({**eql, "query": 'process where tide.no_such_field == "x"'}, ["warning"]),
        "eql_fields": ({**eql, "query": 'process where tide.no_such_field == "x" and tide.nor_this == "y"'},
                       ["warning", "warning"]),
        "endpoint": ({**eql, "index": ["logs-endpoint.events.process*"],
                      "query": 'process where process.Ext.effective_parent.executable : "/tmp/*"'}, []),
        "eql_type": ({**eql, "query": 'process where process.pid == "abc"'}, ["error"]),
        "esql": ({**esql, "query": 'from logs-* | where process.name == "cmd.exe"'}, []),
        "esql_syntax": ({**esql, "query": "from logs-* | wher x"}, ["error"]),
    }
    answer = run({"rules": {k: rule for k, (rule, _) in cases.items()}, "fields": {"logs-*": {"tide.client_field": "keyword"}}})
    got = {k: [p["kind"] for p in answer["results"].get(k, [])] for k in cases}
    ok = all(got[k] == want for k, (_r, want) in cases.items())
    print(f"elastic_validator self-test ({answer['version']}): {'ok' if ok else 'FAILED'} {json.dumps(got)}",
          file=sys.stderr)
    return ok


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(0 if self_test() else 1)
    json.dump(run(json.load(sys.stdin)), sys.stdout)
