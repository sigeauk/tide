import requests
import os
import pandas as pd
import urllib3
import re
import json
import time as _time
import threading as _threading
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Tuple, Optional, Dict, Any
from dotenv import load_dotenv
try:
    # Works when caller put /app/app on sys.path (legacy sync entrypoint
    # in app/services/sync.py does this before `import elastic_helper`).
    from log import log_debug, log_error, log_info
except ModuleNotFoundError:
    # Works when caller imported via the package path
    # (`from app.elastic_helper import ...`) — e.g. test_rule, promotion,
    # management. Without this fallback, a uvicorn hot-reload that
    # re-executes this module before sync.py has run leaves test_rule
    # raising `ModuleNotFoundError: No module named 'log'` → HTTP 500.
    from app.log import log_debug, log_error, log_info

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

# --- Module-level sync diagnostics ---
# Populated by ``fetch_detection_rules`` on every call. Keyed by an opaque
# token returned alongside the DataFrame via the ``last_sync_diagnostics``
# dict (keyed by ``id(returned_dataframe)`` since DataFrames are not
# hashable). The sync orchestrator reads this to decide whether the
# subtractive-delete pass is safe for each (siem_id, space) pair.
#
# Shape: ``{ <call_token>: { <space>: {"total": int, "fetched": int,
#                                       "complete": bool,
#                                       "rule_ids": set[str]} } }``
last_sync_diagnostics: dict = {}
_diag_lock = _threading.Lock()


# --- TEST CONNECTION ---

def test_elastic_connection(kibana_url: str, api_key: str, timeout: int = 10):
    """
    Test connectivity to a Kibana instance.
    Returns (ok: bool, detail: str).
    """
    url = kibana_url.rstrip("/") + "/api/status"
    headers = {
        "kbn-xsrf": "true",
        "Authorization": f"ApiKey {api_key}",
    }
    try:
        resp = requests.get(url, headers=headers, verify=False, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            version = data.get("version", {}).get("number", "unknown")
            status = data.get("status", {}).get("overall", {}).get("level", "unknown")
            return True, f"Kibana {version} ({status})"
        elif resp.status_code == 401:
            return False, "Authentication failed (401)"
        else:
            return False, f"HTTP {resp.status_code}"
    except requests.exceptions.ConnectTimeout:
        return False, "Connection timed out"
    except requests.exceptions.ConnectionError:
        return False, "Connection refused"
    except Exception as exc:
        return False, str(exc)[:120]


def test_elastic_connection_full(
    kibana_url: str,
    api_key: str,
    timeout: int = 10,
):
    """Three-tier connectivity / privilege test against a single Kibana.

    Each check is independent and recorded so the operator sees exactly
    which capability is missing rather than a single pass/fail. Returns::

        {
            "ok": bool,                          # all three checks passed
            "spaces": [...],                     # populated by check 2 on success
            "checks": [
                {
                    "name": "kibana_status" | "spaces" | "detection_rules",
                    "endpoint": "/api/...",
                    "ok": bool,
                    "status_code": int | None,    # None on network error
                    "detail": str,                # short human message
                    "body_excerpt": str | None,   # first 200 chars of response on fail
                },
                ...
            ],
        }

    No retries, no fallbacks — each check is one HTTP request so the result
    panel reflects exactly what the next sync request would see. Token and
    URL are NOT logged anywhere; only the redacted ``len/first/last`` shape
    if logging is enabled by the caller.
    """
    base = (kibana_url or "").rstrip("/")
    headers = {
        "kbn-xsrf": "true",
        "Authorization": f"ApiKey {api_key or ''}",
        "Content-Type": "application/json",
    }
    result: dict = {"ok": False, "spaces": [], "checks": []}

    def _record(name, endpoint, ok, status_code, detail, body_excerpt=None):
        result["checks"].append({
            "name": name,
            "endpoint": endpoint,
            "ok": bool(ok),
            "status_code": status_code,
            "detail": detail,
            "body_excerpt": body_excerpt,
        })

    def _do(method, path):
        url = f"{base}{path}"
        try:
            r = requests.request(
                method, url, headers=headers, verify=False, timeout=timeout
            )
            return r, None
        except requests.exceptions.ConnectTimeout:
            return None, "Connection timed out"
        except requests.exceptions.ConnectionError as e:
            return None, f"Connection refused ({type(e).__name__})"
        except Exception as e:
            return None, f"{type(e).__name__}: {str(e)[:140]}"

    # ── Check 1: Kibana reachable + token format valid ────────────────
    r, err = _do("GET", "/api/status")
    if err:
        _record("kibana_status", "/api/status", False, None, err)
        return result
    if r.status_code == 200:
        try:
            data = r.json()
            version = data.get("version", {}).get("number", "unknown")
            status = data.get("status", {}).get("overall", {}).get("level", "unknown")
            _record(
                "kibana_status", "/api/status", True, 200,
                f"Kibana {version} ({status})",
            )
        except Exception:
            _record(
                "kibana_status", "/api/status", True, 200,
                "Reachable (non-JSON status response)",
            )
    else:
        body = (r.text or "")[:200]
        if r.status_code in (401, 403):
            detail = (
                f"HTTP {r.status_code} — token rejected by Kibana. "
                f"Common causes: token revoked, wrong tenant, or pasted with "
                f"'ApiKey ' prefix."
            )
        else:
            detail = f"HTTP {r.status_code}"
        _record("kibana_status", "/api/status", False, r.status_code, detail, body)
        return result

    # ── Check 2: spaces privilege ─────────────────────────────────────
    r, err = _do("GET", "/api/spaces/space")
    if err:
        _record("spaces", "/api/spaces/space", False, None, err)
    elif r.status_code == 200:
        try:
            spaces = [s.get("id") for s in r.json() if isinstance(s, dict) and s.get("id")]
        except Exception:
            spaces = []
        result["spaces"] = spaces
        _record(
            "spaces", "/api/spaces/space", True, 200,
            f"Found {len(spaces)} space(s): {', '.join(spaces[:6])}"
            + ("…" if len(spaces) > 6 else ""),
        )
    else:
        body = (r.text or "")[:200]
        detail = f"HTTP {r.status_code} — token lacks 'kibana_spaces_all' / 'spaces:read'"
        _record("spaces", "/api/spaces/space", False, r.status_code, detail, body)

    # ── Check 3: detection-engine read privilege per known space ─────
    spaces_to_check = result["spaces"] or ["default"]
    de_failures = []
    de_successes = []
    for sp in spaces_to_check[:5]:  # cap to keep panel readable
        path = f"/s/{sp}/api/detection_engine/rules/_find?per_page=1&page=1"
        r, err = _do("GET", path)
        if err:
            de_failures.append(f"{sp}: {err}")
            continue
        if r.status_code == 200:
            try:
                total = r.json().get("total", "?")
            except Exception:
                total = "?"
            de_successes.append(f"{sp} ({total} rules)")
        else:
            body_hint = ""
            try:
                jb = r.json()
                if isinstance(jb, dict):
                    body_hint = jb.get("message") or jb.get("error") or ""
            except Exception:
                pass
            de_failures.append(
                f"{sp}: HTTP {r.status_code}"
                + (f" — {body_hint[:80]}" if body_hint else "")
            )
    if de_failures and not de_successes:
        _record(
            "detection_rules",
            "/s/<space>/api/detection_engine/rules/_find",
            False, None,
            "All spaces failed: " + "; ".join(de_failures[:3]),
            "; ".join(de_failures)[:200],
        )
    elif de_failures:
        _record(
            "detection_rules",
            "/s/<space>/api/detection_engine/rules/_find",
            True, 200,
            "OK on: " + ", ".join(de_successes)
            + " | failed on: " + "; ".join(de_failures[:2]),
        )
    else:
        _record(
            "detection_rules",
            "/s/<space>/api/detection_engine/rules/_find",
            True, 200,
            "OK on: " + ", ".join(de_successes),
        )

    result["ok"] = all(c["ok"] for c in result["checks"])
    return result


# --- CONFIG ---
IGNORED_INDICES = {
    "_id", "_index", "_score", "_version", "_source", "alert", "event", 
    "host", "source", "destination", "user", "process", "file", "metadata"
}

# ES|QL grammar tokens — Elastic 8.19 reference:
#   https://www.elastic.co/guide/en/elasticsearch/reference/8.19/esql-commands.html
# This is a *grammar/function* registry, NOT a field exclusion list. It holds
# source/processing commands plus the names of built-in scalar/aggregate
# functions so the field extractor can distinguish identifiers used as field
# references from identifiers used as language tokens. Update on Kibana minor
# upgrades only.
ESQL_COMMANDS = {
    # Source commands
    "from", "row", "show",
    # Processing commands
    "where", "keep", "sort", "limit", "eval", "dissect", "grok",
    "rename", "stats", "mv_expand", "drop", "enrich", "lookup",
}

ESQL_FUNCTIONS = {
    # Aggregations
    "count", "count_distinct", "avg", "max", "min", "sum", "median",
    "median_absolute_deviation", "percentile", "values", "top", "st_centroid_agg",
    # Multi-value
    "mv_avg", "mv_concat", "mv_count", "mv_dedupe", "mv_first", "mv_last",
    "mv_max", "mv_median", "mv_min", "mv_slice", "mv_sort", "mv_sum", "mv_zip",
    # String
    "concat", "length", "substring", "split", "starts_with", "ends_with",
    "like", "rlike", "to_lower", "to_upper", "trim", "ltrim", "rtrim",
    "replace", "left", "right", "locate", "repeat", "reverse",
    # Date/time
    "now", "date_diff", "date_extract", "date_format", "date_parse", "date_trunc",
    "bucket", "auto_bucket",
    # Conditional / null
    "case", "coalesce", "greatest", "least", "is_null", "is_not_null",
    # Type conversion
    "to_string", "to_int", "to_integer", "to_long", "to_double", "to_datetime",
    "to_ip", "to_boolean", "to_version", "to_cartesianpoint", "to_cartesianshape",
    "to_geopoint", "to_geoshape", "to_unsigned_long",
    # Math
    "abs", "acos", "asin", "atan", "atan2", "ceil", "cos", "cosh", "e", "exp",
    "floor", "log", "log10", "pi", "pow", "round", "signum", "sin", "sinh",
    "sqrt", "tan", "tanh", "tau",
    # IP / spatial
    "cidr_match", "ip_prefix",
    "st_contains", "st_disjoint", "st_intersects", "st_within",
    "st_x", "st_y", "st_distance",
}

ESQL_RESERVED = {
    "and", "or", "not", "true", "false", "null", "in", "as", "by", "with", "on",
    "asc", "desc", "nulls", "first", "last", "is",
}

# ES|QL time-span literals (``30 minutes``) and ``::type`` casts are grammar, not field names.
_ESQL_TIME_LITERAL_RE = re.compile(
    r"\b\d+\s*(?:milliseconds?|seconds?|minutes?|hours?|days?|weeks?|months?|quarters?|years?)\b", re.IGNORECASE)
_ESQL_CAST_RE = re.compile(r"::\s*[A-Za-z_]\w*")

# Backwards-compat alias (kept for any external importers).
ESQL_KEYWORDS = ESQL_COMMANDS | ESQL_FUNCTIONS | ESQL_RESERVED

MOVING_TAGS = {"test", "staging", "production"}

# Identifier shape used everywhere a field/alias name is expected.
_IDENT_RE = re.compile(r"[A-Za-z_@][A-Za-z0-9_@.\-]*")

# ==========================================
# --- 1. PARSERS ---
# ==========================================

def _string_end(text: str, i: int, triple: bool = True) -> int:
    """Index just past the string literal that opens at ``text[i]`` (a quote character).

    Understands ES|QL / EQL raw strings (triple-quoted, no escapes, may contain
    quotes and pipes) and ordinary quoted strings with backslash escapes. An
    unterminated string runs to the end of the text. Shared by the string
    masker, the comment stripper and the ES|QL pipe splitter so they can never
    disagree about where a string ends.
    """
    n = len(text)
    q = text[i]
    if triple and q == '"' and text.startswith('"""', i):
        j = text.find('"""', i + 3)
        return n if j == -1 else j + 3
    j = i + 1
    while j < n:
        c = text[j]
        if c == '\\' and j + 1 < n:
            j += 2
            continue
        if c == q:
            return j + 1
        j += 1
    return n


def _strip_string_literals(text: str, quotes=('"', "'"), triple: bool = True) -> str:
    """Replace quoted literals with whitespace so the regex pass below cannot
    mistake string contents for field identifiers. Length is preserved.

    ``quotes`` are the characters that open/close a string in the language:
    KQL and Lucene only use ``"`` (an apostrophe in an unquoted value such as
    ``O'Brien`` is just a character) and have no raw-string syntax
    (``triple=False``); ES|QL/EQL callers keep the defaults."""
    if not text:
        return text
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in quotes:
            end = _string_end(text, i, triple and ch == '"')
            out.append(' ' * (end - i))
            i = end
        else:
            out.append(ch)
            i += 1
    return ''.join(out)


def _split_esql_pipes(query: str):
    """Split an ES|QL query on top-level ``|`` characters, ignoring any pipes
    inside quoted string literals (including triple-quoted raw strings). Returns the
    list of stage strings (stripped, empties dropped)."""
    if not query:
        return []
    stages = []
    buf = []
    i = 0
    n = len(query)
    while i < n:
        ch = query[i]
        if ch in ('"', "'"):
            end = _string_end(query, i)
            buf.append(query[i:end])
            i = end
            continue
        if ch == '|':
            stages.append(''.join(buf).strip())
            buf = []
        else:
            buf.append(ch)
        i += 1
    if buf:
        stages.append(''.join(buf).strip())
    return [s for s in stages if s]


def _candidate_idents(text: str):
    """Yield identifier-shaped tokens from ``text`` excluding those that are
    pure numbers, ES|QL grammar/function names, or boolean/null literals."""
    if not text:
        return []
    cleaned = _ESQL_CAST_RE.sub(' ', _ESQL_TIME_LITERAL_RE.sub(' ', _strip_string_literals(text)))
    out = []
    # A reserved word used as ONE SEGMENT of a dotted name is backtick-quoted in place:
    # ``source.`as`.organization.name`` is the field ``source.as.organization.name``.
    cleaned = re.sub(r"(?<=\.)`(\w+)`|`(\w+)`(?=\.)", lambda m: m.group(1) or m.group(2), cleaned)
    # Backtick-quoted names are how ES|QL spells fields containing special characters
    # (``kubernetes.audit.annotations.authorization_k8s_io/decision``): one field, not several tokens.
    for m in re.finditer(r'`([^`]+)`', cleaned):
        quoted = m.group(1).strip()
        if quoted and not quoted.startswith('_'):
            out.append(quoted)
    cleaned = re.sub(r'`[^`]*`', ' ', cleaned)
    for m in _IDENT_RE.finditer(cleaned):
        tok = m.group(0).rstrip('.-')      # a trailing '.' is sentence/statement punctuation, never part of a field name
        if not tok:
            continue
        # ``source.*`` / ``*_suffix`` are wildcard PATTERNS (KEEP/DROP), not fields.
        if cleaned[m.end():m.end() + 1] == '*' or (m.start() > 0 and cleaned[m.start() - 1] == '*'):
            continue
        # A name directly followed by '(' is a function call (KQL(), match(), space(), mv_contains() ...),
        # whether or not it is in the known-function list.
        if re.match(r'\s*\(', cleaned[m.end():]):
            continue
        low = tok.lower()
        if low in ESQL_RESERVED or low in ESQL_COMMANDS or low in ESQL_FUNCTIONS:
            continue
        # Elasticsearch reserves leading-underscore names for metadata
        # fields (_id, _index, _version, _score, _source, _seq_no,
        # _primary_term, _routing, _ignored). They never appear in user
        # mappings, so they must not enter the validator set — whether
        # they were declared via ``FROM <idx> METADATA …`` or referenced
        # bare in another query language.
        if tok.startswith('_'):
            continue
        out.append(tok)
    return out


def _extract_dissect_grok_aliases(pattern: str):
    """Extract emitted alias names from a Dissect/Grok pattern string.

    Dissect uses ``%{name}`` / ``%{name->}`` / ``%{+name}`` / ``%{?name}``.
    Grok uses ``%{SYNTAX:name}`` / ``%{SYNTAX:name:type}``. The ``?`` prefix
    in Dissect denotes a skip-key (not emitted) so we drop those.
    """
    if not pattern:
        return set()
    aliases = set()
    for m in re.finditer(r'%\{([^}]+)\}', pattern):
        body = m.group(1).strip()
        # Grok form SYNTAX:name[:type]
        if ':' in body:
            parts = body.split(':')
            if len(parts) >= 2 and parts[1]:
                name = parts[1].strip()
                if name and not name.startswith('?'):
                    aliases.add(name.lstrip('+'))
            continue
        # Dissect form: name, name->, +name, ?name
        name = body.strip()
        if name.startswith('?'):
            continue
        name = name.lstrip('+').rstrip('->').strip()
        if name:
            aliases.add(name)
    return aliases


def strip_query_comments(query):
    """Strip ``//`` line comments and ``/* */`` block comments from a query string.

    Analysts sometimes annotate KQL/EQL/ES|QL rule queries with comments.
    Left unstripped, the comment text gets tokenized by the field extractors
    below and mistaken for field references, corrupting the mapping score.
    Comment markers found inside quoted strings are left untouched.
    """
    if not query:
        return query
    out = []
    i = 0
    n = len(query)
    while i < n:
        ch = query[i]
        if ch in ('"', "'"):
            end = _string_end(query, i)          # comment markers inside strings are data
            out.append(query[i:end])
            i = end
            continue
        if ch == '/' and i + 1 < n and query[i + 1] == '/':
            while i < n and query[i] not in ('\n', '\r'):
                i += 1
            continue
        if ch == '/' and i + 1 < n and query[i + 1] == '*':
            end = query.find('*/', i + 2)
            i = end + 2 if end != -1 else n
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


# A field reference: optional leading ``@`` (``@timestamp``), then an identifier that may contain
# dots and hyphens. Digit-leading tokens (``4688``, ``2020-01-01T00``) can never be fields.
_FIELD_NAME = r'@?[A-Za-z_][\w.\-]*'
# KQL / Lucene field names may also contain '/' (``kubernetes.audit.annotations.authorization_k8s_io/decision``).
_KQL_FIELD_NAME = r'@?[A-Za-z_][\w.\-/]*'
_KQL_KEYWORDS = {"and", "or", "not", "true", "false", "in", "by", "from", "where", "to"}


def _mask_query_literals(query: str, quotes=('"',)) -> str:
    """Blank string literals and Lucene ``/regex/`` values.

    Everything between quotes is data, not field names: ``"C:\\Windows\\*"``,
    ``"http://host:8080"`` and ``"12:30:00"`` all contain ``word:`` sequences that a
    field regex would happily report as fields (``C``, ``http``, ``12``...). Each
    phantom field is a guaranteed mapping miss on every index, dragging the
    mapping score down. This is structural (what is inside quotes), not a
    hardcoded exclusion list of field names.
    """
    masked = _strip_string_literals(query, quotes=quotes, triple=False)
    # Lucene regex value: field:/.../  (body may contain ':' and other operators)
    return re.sub(r'(?<=:)\s*/(?:\\.|[^/\\\n])*/', lambda m: ' ' * len(m.group(0)), masked)


def extract_kuery_lucene(query):
    """Field names referenced by a KQL or Lucene query (string contents excluded)."""
    if not query: return set()
    query = strip_query_comments(query)
    masked = _mask_query_literals(query, quotes=('"',))
    fields_colon = re.findall(r'(?<![\w.@])(' + _KQL_FIELD_NAME + r')\s*:(?!:)', masked)
    fields_compare = re.findall(r'(?<![\w.@])(' + _KQL_FIELD_NAME + r')\s*(?:==|!=|<=|>=|<|>)', masked)
    fields = set(fields_colon + fields_compare)
    # Lucene existence syntax: ``_exists_:field`` — the argument is the field, ``_exists_`` is grammar.
    fields.update(re.findall(r'\b_(?:exists|missing)_\s*:\s*(' + _KQL_FIELD_NAME + r')', masked))
    fields = {f for f in fields if f.lower() not in ("_exists_", "_missing_")}
    return {f for f in fields if f.lower() not in _KQL_KEYWORDS and not f[0].isdigit()}


def extract_filter_fields(filters):
    """Extract field names from a Kibana detection-rule ``filters`` array.

    UI-built rules (no top-level ``query`` string, only Kibana filter pills)
    carry their selection criteria in ``rule.filters`` — an array of objects
    shaped roughly like::

        {"meta": {"key": "host.name", "type": "phrase", ...},
         "query": {"match_phrase": {"host.name": "foo"}}}

    The mapping validator needs those field names exactly the same way it
    needs fields parsed out of a KQL/Lucene/EQL/ES|QL string, otherwise
    filter-only rules silently score 0% mapping coverage and can fail the
    field-mapping pass entirely (the rule named ``'host rules '`` is the
    canonical repro). This helper walks both ``meta.key`` and the
    Elasticsearch DSL ``query`` body (recursing through ``bool.{must,
    should,must_not,filter}``) and returns the union of referenced field
    names. Per CLAUDE.md it adds no hardcoded field exclusion lists —
    grammar/operator keys (``bool``, ``minimum_should_match`` …) are
    skipped, everything else discovered dynamically is treated as a field.
    """
    if not filters or not isinstance(filters, (list, tuple)):
        return set()

    # DSL container keys that are NOT field names. Anything not in this set
    # at a leaf-clause level is treated as a field name.
    _dsl_containers = {
        "bool", "must", "should", "must_not", "filter",
        "minimum_should_match", "boost", "_name",
    }
    # Leaf clauses whose immediate child key IS the field name.
    _field_keyed_clauses = {
        "match", "match_phrase", "match_phrase_prefix", "term", "terms",
        "terms_set", "range", "wildcard", "prefix", "regexp", "fuzzy",
        "span_term", "exists",
    }

    out: set = set()

    def _walk_query(node):
        if isinstance(node, dict):
            for k, v in node.items():
                kl = str(k).lower()
                if kl == "exists" and isinstance(v, dict) and v.get("field"):
                    out.add(str(v["field"]))
                    continue
                if kl in _field_keyed_clauses and isinstance(v, dict):
                    for field_name in v.keys():
                        if field_name and not str(field_name).startswith("_"):
                            out.add(str(field_name))
                    continue
                if kl in _dsl_containers or kl == "query":
                    _walk_query(v)
                    continue
                # Unknown structural key — recurse defensively so we don't
                # miss nested clauses inside vendor extensions.
                if isinstance(v, (dict, list)):
                    _walk_query(v)
        elif isinstance(node, list):
            for item in node:
                _walk_query(item)

    for f in filters:
        if not isinstance(f, dict):
            continue
        meta = f.get("meta") or {}
        if isinstance(meta, dict):
            key = meta.get("key")
            if key:
                out.add(str(key))
            # Some filter exports stash the field under ``params.field``.
            params = meta.get("params")
            if isinstance(params, dict):
                pfield = params.get("field")
                if pfield:
                    out.add(str(pfield))
        q = f.get("query")
        if q is not None:
            _walk_query(q)

    # Filter out anything that is clearly not an index field name
    # (empty strings, leading underscores like ``_source``).
    return {name for name in out if name and not name.startswith("_")}


def normalize_rule_language(language):
    """Normalize Elastic rule language aliases used across sync/preview paths.

    Kibana Detection Engine query rules use ``language: kuery`` in the rules
    API, but some upstream/export paths may still present ``kql``. Treat both
    as the same query language so mapping extraction and scoring remain stable.
    """
    lang = str(language or "kuery").strip().lower()
    if lang == "kql":
        return "kuery"
    return lang


def extract_esql(query):
    """Extract index-resolvable field names from an ES|QL query.

    Walks the pipe stages in order, maintaining two sets:
      * ``emitted`` — names introduced inside the query (EVAL aliases, STATS
        outputs, RENAME targets, DISSECT/GROK capture names, ENRICH WITH
        aliases, ROW assignments). These are *ephemeral* — they do not exist
        in any index mapping and must be filtered out before the mapping
        validator scores the rule.
      * ``referenced`` — names read from the document stream (WHERE/SORT/KEEP
        operands, RHS of EVAL/STATS, RENAME source, ENRICH match field).

    The returned set is ``referenced − emitted − grammar/function tokens``.

    See CLAUDE.md (no hardcoded field exclusion lists). The filter set is
    grammar tokens only; field names are still discovered dynamically.
    """
    if not query:
        return set()

    query = strip_query_comments(query)

    emitted: set = set()
    referenced: set = set()

    for raw_stage in _split_esql_pipes(query):
        stage = raw_stage.strip()
        if not stage:
            continue
        # Identify the leading command keyword (case-insensitive).
        m = re.match(r'\s*([A-Za-z_]+)\b\s*(.*)', stage, re.DOTALL)
        if not m:
            continue
        cmd = m.group(1).lower()
        body = m.group(2)

        if cmd == 'from':
            # Index pattern stage — handled by get_esql_index. The optional
            # ``METADATA _id, _version, _index, …`` suffix declares ES
            # metadata fields as available in the query stream. Record them
            # as emitted so any downstream WHERE/KEEP/SORT reference is not
            # treated as a missing index field.
            mmeta = re.search(r'\bMETADATA\b\s*(.+)$', body, re.IGNORECASE | re.DOTALL)
            if mmeta:
                for part in _split_top_level_commas(mmeta.group(1)):
                    name = part.strip().rstrip(',').strip()
                    if name:
                        emitted.add(name)
            continue
        if cmd == 'show':
            continue
        if cmd == 'limit':
            continue

        if cmd in ('where', 'sort'):
            referenced.update(_candidate_idents(body))
            continue

        if cmd in ('keep', 'drop', 'mv_expand'):
            # KEEP/DROP take a comma-separated field list; aliases in KEEP
            # have the form ``new = old`` — emit new, reference old.
            for part in body.split(','):
                part = part.strip()
                if not part:
                    continue
                if '=' in part:
                    lhs, rhs = part.split('=', 1)
                    lhs = lhs.strip()
                    if lhs:
                        emitted.add(lhs)
                    referenced.update(_candidate_idents(rhs))
                else:
                    referenced.update(_candidate_idents(part))
            continue

        if cmd in ('eval', 'row'):
            # ``EVAL alias = expr [, alias2 = expr2 ...]``.
            # Split on top-level commas (no parens; safe-enough for ES|QL EVAL
            # which doesn't allow nested commas outside function args — we
            # tokenise each chunk anyway so any over-split is harmless).
            for chunk in _split_top_level_commas(body):
                if '=' in chunk:
                    lhs, rhs = chunk.split('=', 1)
                    alias = lhs.strip()
                    if alias:
                        emitted.add(alias)
                    # RHS field references — but tokens that match a
                    # previously-emitted alias must NOT propagate as
                    # referenced (they are not in the index mapping).
                    for tok in _candidate_idents(rhs):
                        if tok not in emitted:
                            referenced.add(tok)
                else:
                    # ROW with bare literal — nothing to emit/reference.
                    continue
            continue

        if cmd == 'stats':
            # ``STATS [alias =] agg(field) [, ...] [BY group_field [, ...]]``.
            by_split = re.split(r'\bBY\b', body, maxsplit=1, flags=re.IGNORECASE)
            agg_part = by_split[0]
            by_part = by_split[1] if len(by_split) > 1 else ''
            for chunk in _split_top_level_commas(agg_part):
                if '=' in chunk:
                    lhs, rhs = chunk.split('=', 1)
                    alias = lhs.strip()
                    if alias:
                        emitted.add(alias)
                    for tok in _candidate_idents(rhs):
                        if tok not in emitted:
                            referenced.add(tok)
                else:
                    for tok in _candidate_idents(chunk):
                        if tok not in emitted:
                            referenced.add(tok)
            for chunk in _split_top_level_commas(by_part):
                if '=' in chunk:
                    lhs, rhs = chunk.split('=', 1)
                    alias = lhs.strip()
                    if alias:
                        emitted.add(alias)
                    for tok in _candidate_idents(rhs):
                        if tok not in emitted:
                            referenced.add(tok)
                else:
                    for tok in _candidate_idents(chunk):
                        if tok not in emitted:
                            referenced.add(tok)
            continue

        if cmd == 'rename':
            # ``RENAME old AS new [, ...]``.
            for chunk in _split_top_level_commas(body):
                pair = re.split(r'\bAS\b', chunk, maxsplit=1, flags=re.IGNORECASE)
                if len(pair) == 2:
                    src = pair[0].strip()
                    dst = pair[1].strip()
                    if src and src not in emitted:
                        referenced.add(src)
                    if dst:
                        emitted.add(dst)
            continue

        if cmd == 'dissect':
            # ``DISSECT input_field "pattern" [APPEND_SEPARATOR=...]``.
            # First identifier = source field; quoted string = pattern.
            src_match = _IDENT_RE.search(body)
            if src_match:
                src = src_match.group(0)
                if src not in emitted:
                    referenced.add(src)
            pat_match = re.search(r'"([^"]*)"', body)
            if pat_match:
                emitted.update(_extract_dissect_grok_aliases(pat_match.group(1)))
            continue

        if cmd == 'grok':
            src_match = _IDENT_RE.search(body)
            if src_match:
                src = src_match.group(0)
                if src not in emitted:
                    referenced.add(src)
            pat_match = re.search(r'"([^"]*)"', body)
            if pat_match:
                emitted.update(_extract_dissect_grok_aliases(pat_match.group(1)))
            continue

        if cmd == 'enrich':
            # ``ENRICH policy [ON match_field] [WITH new = enrich_field, ...]``.
            on_split = re.split(r'\bON\b', body, maxsplit=1, flags=re.IGNORECASE)
            with_split = re.split(r'\bWITH\b', body, maxsplit=1, flags=re.IGNORECASE)
            if len(on_split) == 2:
                # Skip the policy name (first ident in the segment after ON).
                tail = on_split[1]
                # Stop at WITH if present.
                tail = re.split(r'\bWITH\b', tail, maxsplit=1, flags=re.IGNORECASE)[0]
                m = _IDENT_RE.search(tail)
                if m:
                    src = m.group(0)
                    if src not in emitted:
                        referenced.add(src)
            if len(with_split) == 2:
                for chunk in _split_top_level_commas(with_split[1]):
                    if '=' in chunk:
                        lhs, _rhs = chunk.split('=', 1)
                        alias = lhs.strip()
                        if alias:
                            emitted.add(alias)
                    else:
                        # Bare ``WITH enrich_field`` — Elastic emits it under
                        # its own name, which we still cannot validate against
                        # the source index, so treat it as emitted.
                        m = _IDENT_RE.search(chunk)
                        if m:
                            emitted.add(m.group(0))
            continue

        # Unknown command (future Kibana version) — be permissive: collect
        # candidate idents but do NOT emit anything, so we err on the side of
        # validating rather than silently dropping fields.
        referenced.update(_candidate_idents(body))

    # Final scrub: anything emitted is always removed from the validator set.
    fields = {f for f in referenced if f and f not in emitted and not f[0].isdigit()}
    return fields


def _split_top_level_commas(text: str):
    """Split ``text`` on commas that are not nested inside ``(...)`` or string
    literals. Returns a list of stripped chunks (empty chunks dropped)."""
    out = []
    buf = []
    depth = 0
    in_str = None
    for ch in text or '':
        if in_str:
            buf.append(ch)
            if ch == in_str:
                in_str = None
            continue
        if ch in ('"', "'"):
            in_str = ch
            buf.append(ch)
            continue
        if ch == '(':
            depth += 1
            buf.append(ch)
        elif ch == ')':
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch == ',' and depth == 0:
            chunk = ''.join(buf).strip()
            if chunk:
                out.append(chunk)
            buf = []
        else:
            buf.append(ch)
    chunk = ''.join(buf).strip()
    if chunk:
        out.append(chunk)
    return out


# EQL functions whose arguments can be field references (grammar, not field names).
_EQL_FUNCTIONS = (
    "add", "arrayContains", "arrayCount", "arraySearch", "between", "cidrMatch", "concat", "divide",
    "endsWith", "indexOf", "length", "match", "modulo", "multiply", "number", "startsWith", "string",
    "stringContains", "substring", "subtract", "toString", "wildcard",
)
_EQL_KEYWORDS = {
    "and", "or", "not", "true", "false", "null", "in", "like", "regex", "by", "where", "sequence",
    "sample", "join", "until", "with", "runs", "maxspan", "of", "child", "descendant", "any",
    "process", "file", "network", "registry", "dns", "library", "driver", "image",
}


def _balanced_args(text: str, open_idx: int) -> str:
    """Text inside the parenthesis that opens at ``open_idx`` (up to its matching close)."""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i]
    return text[open_idx + 1:]


def extract_eql(query):
    """Returns ``(fields, event_categories)`` for an EQL query (string contents excluded)."""
    if not query: return set(), []
    query = strip_query_comments(query)
    masked = _strip_string_literals(query)          # EQL strings: double or single quotes
    event_cats = re.findall(r'\b([a-zA-Z0-9_\-]+)\s+where\b', masked, re.IGNORECASE)
    ident = r'\??(' + _FIELD_NAME + r')'          # ``?field`` marks an optional field
    fields = set(re.findall(r'(?<![\w.@])' + ident + r'\s*(?:==|!=|<=|>=|<|>|:|(?:in|like|regex)~?(?![\w.]))', masked))
    # sequence / join / sample keys:  ``sequence by host.id, user.name [ ... ]``
    for m in re.finditer(r'\bby\s+(' + ident + r'(?:\s*,\s*' + ident + r')*)', masked):
        fields.update(re.findall(_FIELD_NAME, m.group(1).replace('?', '')))
    # field arguments of EQL functions:  wildcard(process.executable, "..."), length(process.args) ...
    for m in re.finditer(r'(?<![\w.])(?:' + '|'.join(_EQL_FUNCTIONS) + r')~?\s*\(', masked, re.IGNORECASE):
        inner = _balanced_args(masked, m.end() - 1)
        for tok in re.finditer(r'(?<![\w.@])\??(' + _FIELD_NAME + r')(\s*~?\s*\()?', inner):
            if not tok.group(2):                    # a name followed by '(' is a nested function, not a field
                fields.add(tok.group(1))
    clean_fields = {f for f in fields if f.lower() not in _EQL_KEYWORDS and not f[0].isdigit()}
    return clean_fields, event_cats


def get_esql_index(query):
    if not query: return []
    query = strip_query_comments(query)
    match = re.search(r'(?:^|\|\s*)\s*FROM\s+(.*?)(?=\s*\||$|\n)', query, re.IGNORECASE)
    if not match: return []
    raw_indices_str = match.group(1).strip()
    parts = re.split(r'[,\s]+', raw_indices_str)
    indices = []
    for part in parts:
        clean_part = re.sub(r'["\']', '', part).strip()
        if not clean_part: continue
        if clean_part.lower() in ESQL_KEYWORDS: break
        if any(char in clean_part for char in ['=', '>', '<', '(', ')']): break
        if clean_part.lower() not in IGNORED_INDICES:
            indices.append(clean_part)
    return indices


def get_data_view_indices(session, base_url, space, rule):
    """Resolve index patterns from Kibana data view metadata for rules that do not carry `index`."""
    data_view_id = rule.get("data_view_id") or rule.get("dataViewId")
    if not data_view_id:
        return []

    if isinstance(data_view_id, list):
        data_view_id = data_view_id[0] if data_view_id else None
    if not data_view_id:
        return []

    # Always use /s/{space}/api/... -- see _space_api_prefix and
    # fetch_detection_rules for the full rationale (4.1.14 fix). Do NOT
    # special-case the literal 'default' here.
    endpoint = f"{base_url}/s/{space}/api/data_views/data_view/{data_view_id}"

    try:
        res = session.get(endpoint, timeout=10)
        if res.status_code != 200:
            log_debug(f"Data view lookup failed for rule '{rule.get('name', '-')}' ({data_view_id}) in space '{space}': {res.status_code}")
            return []

        data = res.json() if res.text else {}
        dv = data.get("data_view", {}) if isinstance(data, dict) else {}
        title = dv.get("title") or ""
        if not title:
            return []

        indices = [p.strip() for p in str(title).split(',') if p and p.strip()]
        if indices:
            log_debug(f"Resolved data view indices for rule '{rule.get('name', '-')}' in space '{space}': {indices}")
        return indices
    except Exception as e:
        log_debug(f"Data view lookup exception for rule '{rule.get('name', '-')}' ({data_view_id}): {e}")
        return []

# ==========================================
# --- 2. INDEX MAPPINGS ---
# ==========================================

def flatten_properties(props, prefix=""):
    """Recursively flattens the Elasticsearch mapping properties."""
    fields = {}
    for k, v in props.items():
        field_name = f"{prefix}.{k}" if prefix else k
        if "properties" in v:
            fields.update(flatten_properties(v["properties"], field_name))
        else:
            fields[field_name] = v.get("type", "unknown")
    return fields


def _es_get(session, base_url, es_direct_url, path, timeout=60):
    """GET an Elasticsearch path directly, or through the Kibana console proxy."""
    if es_direct_url:
        return session.get(f"{es_direct_url}{path}", verify=False, timeout=timeout)
    return session.post(f"{base_url}/api/console/proxy", params={"path": path, "method": "GET"},
                        verify=False, timeout=timeout)


def fetch_field_caps(session, base_url, pattern, es_direct_url=None):
    """Ask the SIEM what an index pattern maps, in ONE call covering every matching index.

    Returns ``("ok", fields)``, ``("no_indices", {})`` when the pattern matches nothing,
    or ``("error", message)`` when the SIEM could not answer. ``fields`` maps a field name
    to ``[type, aggregatable, searchable, type_conflict]``. Used by the field catalogue
    (``app.services.mapping_catalogue``), which decides when to call it.
    """
    from urllib.parse import quote
    path = f"/{quote(pattern, safe='*,-:.')}/_field_caps"
    query = "?fields=*&ignore_unavailable=true&allow_no_indices=true"
    res = None
    # ``filters`` (skip metadata / object parents) needs Elasticsearch 7.13+; retry without it on a 400.
    for extra in ("&filters=-metadata,-parent", ""):
        res = _es_get(session, base_url, es_direct_url, path + query + extra)
        if res.status_code != 400:
            break
    if res.status_code == 404:
        return "no_indices", {}
    if res.status_code != 200:
        return "error", f"HTTP {res.status_code}"
    data = res.json() or {}
    if not data.get("indices"):
        return "no_indices", {}
    fields = {}
    for name, by_type in (data.get("fields") or {}).items():
        types = {t: i for t, i in (by_type or {}).items() if t != "unmapped" and not (i or {}).get("metadata_field")}
        if not types:
            continue
        primary = "keyword" if "keyword" in types else sorted(types)[0]
        infos = list(types.values())
        fields[name] = [
            primary,
            int(all(i.get("aggregatable") for i in infos)),
            int(all(i.get("searchable") for i in infos)),
            int(len(types) > 1),
        ]
    return "ok", fields


def make_field_caps_fetcher(session, base_url, es_direct_url=None):
    """A ``pattern -> (status, fields)`` callable for ``MappingCatalogue.ensure``."""
    return lambda pattern: fetch_field_caps(session, base_url, pattern, es_direct_url)


# ==========================================
# --- 3. SCORING & FETCH ---
# ==========================================

def calculate_score(rule_data, weights=None):
    """Score one rule. The model and its version live in ``app.scoring``; ``weights`` are the client's points per check."""
    from app.scoring import score_rule
    return score_rule(rule_data, weights)


def _new_session(api_key):
    """Requests session for one SIEM's Kibana, sized for the parallel lookups below."""
    # NOTE (4.1.14 Fix 15): Do NOT add `Connection: close` here. Combined with a large thread pool it
    # caused TCP port exhaustion against the default urllib3 pool of 10, surfacing as
    # `urllib3.connectionpool is full` and SSL `Max retries exceeded` redirect storms. The
    # HTTPAdapter below sizes the pool to absorb the parallelism instead.
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=25, pool_maxsize=25, max_retries=3)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.headers.update({
        "kbn-xsrf": "true",
        "Authorization": f"ApiKey {api_key}",
        "Content-Type": "application/json",
    })
    session.verify = False
    return session


def _process_rules(session, base_url, all_rules, check_mappings=True, catalogue=None,
                   elasticsearch_url=None, force_catalogue=False, search_time_history=None, weights=None):
    """Turn raw Kibana rule payloads into scored rows.

    Field checks read the SIEM's field catalogue; the SIEM is only asked about index
    patterns the catalogue does not know yet, that are older than its refresh window, or
    when ``force_catalogue`` is set. ``search_time_history`` maps ``(rule_id, space)`` to
    ``[(executed_at, ms), ...]`` (this SIEM's recent runs) for the search-time median.
    """
    from app.services.mapping_catalogue import MappingCatalogue
    if check_mappings and catalogue is None:
        catalogue = MappingCatalogue(None, "")
    search_time_history = search_time_history or {}

    # --- Batch data view resolution: resolve all data-view rules in parallel ---
    dv_tasks = []
    for i, r in enumerate(all_rules):
        has_explicit_index = r.get('index') and len(r.get('index', [])) > 0
        if not has_explicit_index and (r.get('data_view_id') or r.get('dataViewId')):
            dv_tasks.append((i, r.get('space_id', 'default'), r))

    dv_results = {}
    if dv_tasks:
        workers = min(10, len(dv_tasks))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(get_data_view_indices, session, base_url, space, rule): idx
                for idx, space, rule in dv_tasks
            }
            for fut in as_completed(futures):
                rule_idx = futures[fut]
                try:
                    dv_results[rule_idx] = fut.result()
                except Exception:
                    dv_results[rule_idx] = []
        log_info(f"[perf] Resolved {len(dv_tasks)} data view lookups in parallel")

    rule_meta_list = []
    wanted_patterns = set()
    for i, r in enumerate(all_rules):
        query = r.get('query', '')
        language = normalize_rule_language(r.get('language', 'kuery'))
        # Last execution: its search duration feeds the search-time median.
        sample = None
        try:
            last_exec = (r.get('execution_summary', {}) or {}).get('last_execution', {}) or {}
            ms = int((last_exec.get('metrics', {}) or {}).get('total_search_duration_ms', 0) or 0)
            if ms > 0 and last_exec.get('date'):
                sample = {"rule_id": r.get('id') or r.get('rule_id'), "space": r.get('space_id', 'default'),
                          "executed_at": str(last_exec['date']), "search_ms": ms}
        except Exception:
            sample = None
        indices = r.get('index', []) or []
        resolved_from_data_view = False
        if not indices:
            # Use pre-resolved data view indices (fetched in parallel above)
            indices = dv_results.get(i, [])
            if indices:
                resolved_from_data_view = True
        if language == "esql":
            esql_indices = get_esql_index(query)
            if esql_indices:
                indices = esql_indices

        clean_indices = [str(i).strip() for i in indices if i and str(i).strip().lower() not in IGNORED_INDICES]

        # Convert data-view-backed rules to concrete index patterns at pull
        # time. ``data_view_id`` is a Kibana-space-scoped object — copying
        # a rule that still carries one into another space (promotion)
        # references a data view that doesn't exist there, and the rule
        # fails to run. Persisting resolved ``index`` onto the raw payload
        # here means every downstream consumer (mapping, promotion,
        # preview) sees a portable index list instead of a dangling
        # data_view_id.
        if resolved_from_data_view and clean_indices:
            r['index'] = clean_indices
            r.pop('data_view_id', None)
            r.pop('dataViewId', None)

        fields = set()
        if check_mappings:
            if language in ["kuery", "lucene"]:
                fields = extract_kuery_lucene(query)
            elif language == "esql":
                fields = extract_esql(query)
            elif language == "eql":
                fields = extract_eql(query)[0]

            # UI-built rules can have an empty ``query`` and put every
            # selection criterion into ``filters`` (the rule named
            # ``'host rules '`` is the canonical repro — see CHANGELOG
            # 4.1.18). Always union filter-derived fields into the
            # mapping set, regardless of query language, so those rules
            # are validated the same way as standard query rules.
            filter_fields = extract_filter_fields(r.get("filters"))
            if filter_fields:
                fields = fields | filter_fields
            wanted_patterns.update(
                p for p in clean_indices if not p.startswith(('_', '-')) and p.lower() not in IGNORED_INDICES
            )

        rule_meta_list.append({"raw": r, "fields": fields, "indices": clean_indices, "sample": sample})

    if check_mappings and wanted_patterns:
        stats = catalogue.ensure(wanted_patterns, make_field_caps_fetcher(session, base_url, elasticsearch_url),
                                 force=force_catalogue)
        log_info(f"[perf] Field catalogue: {stats['cached']} cached, {stats['refreshed']} fetched, "
                 f"{stats['failed']} failed of {stats['patterns']} index patterns")

    processed_rules = []
    for meta in rule_meta_list:
        r = meta["raw"]
        rule_language = normalize_rule_language(r.get('language', 'kuery'))
        space_id = r.get('space_id', 'default')

        # Fields the rule groups, suppresses or highlights on live outside its query but still have to exist.
        suppression = r.get('alert_suppression', {})
        aggregate_fields = list(suppression.get('group_by', []) or []) if isinstance(suppression, dict) else []
        threshold = r.get('threshold')
        if isinstance(threshold, dict):
            tf = threshold.get('field')
            aggregate_fields += [tf] if isinstance(tf, str) else list(tf or [])
        new_terms = r.get('new_terms_fields')
        if isinstance(new_terms, list):
            aggregate_fields += new_terms
        aggregate_fields = [str(f) for f in aggregate_fields if f]

        # Extract investigation/highlighted fields (alert suppression is NOT a highlight).
        investigation_fields_obj = r.get('investigation_fields', {})
        investigation_fields = (investigation_fields_obj.get('field_names', []) or []
                                if isinstance(investigation_fields_obj, dict) else [])
        highlighted_str = ",".join(investigation_fields) if investigation_fields else "-"

        results, field_facts, aux_facts = [], None, {}
        if check_mappings:
            field_facts, results = catalogue.check(meta["indices"], meta["fields"])
            aux = set(aggregate_fields) | {str(f) for f in investigation_fields}
            if r.get('timestamp_override') == 'event.ingested':
                aux.add('event.ingested')
            aux_facts, _ = catalogue.check(meta["indices"], aux - set(meta["fields"]))
            aux_facts.update({f: v for f, v in field_facts.items() if f in aux})

        # Search-time median: this run plus the recent runs TIDE has already recorded.
        key = ((r.get('id') or r.get('rule_id')), space_id)
        runs = dict(search_time_history.get(key, []))
        if meta["sample"]:
            runs.setdefault(meta["sample"]["executed_at"], meta["sample"]["search_ms"])
        search_times = [ms for _, ms in sorted(runs.items(), reverse=True)]

        threats = r.get('threat', [])
        mitre_ids = []
        tactics = []
        techniques = []
        if isinstance(threats, list):
            for t in threats:
                if not isinstance(t, dict):
                    continue
                if 'tactic' in t:
                    tactics.append(t['tactic'].get('name', ''))
                for tech in t.get('technique', []):
                    if tech.get('id'):
                        mitre_ids.append(tech.get('id'))
                    techniques.append(f"{tech.get('id')} {tech.get('name')}")

        rule_data = {
            "rule_id": r.get('rule_id'),
            "name": r.get('name'),
            "enabled": r.get('enabled'),
            "author_str": str(r.get('author', [])),
            "severity": r.get('severity'),
            "risk_score": r.get('risk_score'),
            "timestamp_override": r.get('timestamp_override', "-"),
            "note_exists": "Yes" if r.get('note') else "-",
            "note": r.get('note', ''),
            "tactics": ",".join(tactics),
            "techniques": ",".join(techniques),
            "highlighted_str": highlighted_str,
            "highlight_fields": list(investigation_fields),
            "aggregate_fields": aggregate_fields,
            "search_time": search_times[0] if search_times else 0,
            "search_times_ms": search_times,
            "search_sample": meta["sample"],
            "language": rule_language,
            "indices": meta["indices"],
            "fields": list(meta["fields"]),
            "results": results,
            "field_facts": field_facts,
            "aux_facts": aux_facts,
            "query": r.get('query', ''),
            "mitre_ids": list(set(mitre_ids)),
            "raw_data": r,
            "space_id": space_id,
        }
        calculate_score(rule_data, weights)
        rule_data.pop("field_facts", None)
        rule_data.pop("aux_facts", None)
        processed_rules.append(rule_data)
    return processed_rules


def fetch_single_rule(kibana_url, api_key, space, rule_id, catalogue=None, elasticsearch_url=None,
                      force_catalogue=True, search_time_history=None, weights=None):
    """Fetch and score ONE rule from its SIEM, without listing the space.

    Returns a one-row DataFrame, or ``None`` when Kibana says the rule does not exist.
    Raises on any network or HTTP failure so an outage is never mistaken for a deleted rule.
    """
    base_url = kibana_url.rstrip('/')
    session = _new_session(api_key)
    endpoint = f"{base_url}/s/{space}/api/detection_engine/rules"
    rule = None
    for param in ("id", "rule_id"):
        res = session.get(endpoint, params={param: rule_id}, timeout=60)
        if res.status_code == 200:
            rule = res.json()
            break
        if res.status_code != 404:
            raise RuntimeError(f"Kibana returned HTTP {res.status_code} for space '{space}'")
    if not isinstance(rule, dict) or not rule:
        return None
    rule['space_id'] = rule.get('space_id') or space
    rows = _process_rules(session, base_url, [rule], True, catalogue, elasticsearch_url,
                          force_catalogue, search_time_history, weights)
    return pd.DataFrame(rows)


def fetch_detection_rules(kibana_url, api_key, spaces, check_mappings=True, catalogue=None,
                          elasticsearch_url=None, force_catalogue=False, search_time_history=None,
                          weights=None):
    """Fetch detection rules from a single SIEM's Kibana instance.

    All connection parameters are mandatory and resolved per-tenant from
    ``siem_inventory`` / ``client_siem_map``.

    Args:
        kibana_url: Base Kibana URL for this SIEM (from ``siem_inventory.kibana_url``).
        api_key: Kibana API key (from ``siem_inventory.api_token_enc``).
        spaces: List of Kibana spaces to fetch rules from for this SIEM.
        check_mappings: When True, check the rules' fields against the SIEM's field catalogue.
        catalogue: ``MappingCatalogue`` for this SIEM (default: an in-memory one).
        elasticsearch_url: Optional direct Elasticsearch URL (from
            ``siem_inventory.elasticsearch_url``) used to bypass the Kibana
            console proxy when fetching index mappings.
        force_catalogue: Refresh every index pattern in the catalogue, not just new or stale ones.
        search_time_history: ``{(rule_id, space): [(executed_at, ms), ...]}`` recent runs for the
            search-time median.
        weights: the client's points per scoring check (defaults when omitted).
    """
    if not kibana_url or not api_key:
        log_error("fetch_detection_rules: kibana_url and api_key are required")
        return pd.DataFrame()

    base_url = kibana_url.rstrip('/')
    session = _new_session(api_key)

    spaces = [s.strip() for s in (spaces or []) if s and s.strip()]
    if not spaces:
        spaces = ['default']

    all_rules = []

    # Per-call diagnostics: { space: {"total": int, "fetched": int,
    # "complete": bool, "rule_ids": set[str]} }. Stashed on the module so the
    # sync orchestrator can decide whether the subtractive-delete pass is safe
    # to run. See app/services/sync.py for the consumer.
    diagnostics: dict = {}

    PAGE_SIZE = 100           # Lowered from 1000 (Kibana documented max) to
                              # keep per-page response construction well under
                              # the 60s timeout on slow / large-rule-set
                              # Kibanas. More pages, but each page completes
                              # before the proxy / Kibana stalls.
    MAX_PAGE_RETRIES = 3
    BACKOFF_S = (0.5, 1.0, 2.0)

    try:
        # Loop through each Kibana space
        for space in spaces:
            page = 1
            space_rules: list = []
            seen_ids: set = set()      # distinct rule_ids collected so far, across all pages
            advertised_total: int = -1  # -1 = unknown until first response
            hit_empty_page = False     # Kibana itself said "no more" — the only definitive end
            page_fetch_failed = False  # True only if an HTTP/network error
                                       # actually broke pagination. Distinct
                                       # from "Kibana said total=N but only N-k
                                       # rules came back across successful
                                       # pages" — the latter is a benign
                                       # count drift (rules deleted between
                                       # pages, RBAC filtering, stale total)
                                       # and must not block reconciliation.
            failure_reason: str = ""   # populated when page_fetch_failed/-1
            failure_endpoint: str = ""

            while True:
                # Always use /s/{space}/api/... for every space, including
                # 'default'. Vanilla Kibana accepts both /api/... and
                # /s/default/api/... at the application layer, but reverse
                # proxies / nginx ingresses fronting Kibana commonly route on
                # the /s/<space>/ prefix and 404 the bare /api/... form.
                # `test_elastic_connection_full` (the working test-button
                # path) always uses /s/<space>/...; aligning sync onto the
                # same shape eliminates the test-vs-sync divergence that
                # caused 4.1.13's `0/0 rules` regression for default-only
                # SIEMs. Do NOT special-case the literal string 'default'
                # here -- CLAUDE.md §8.3 anti-pattern.
                endpoint = f"{base_url}/s/{space}/api/detection_engine/rules/_find"
                if page == 1:
                    # Permanent visible proof of the URL being hit per
                    # (siem, space). One line per space per sync; matches
                    # the dry-run output from `diag_sync` section 9.
                    log_debug(
                        f"[sync url] GET {endpoint} (space={space!r})"
                    )

                # Per-page retry with exponential backoff for transient 5xx /
                # network errors. Fatal errors (4xx other than 429) break out
                # immediately so the per-space drift counter sees the gap.
                attempt = 0
                res = None
                last_err = None
                while attempt < MAX_PAGE_RETRIES:
                    try:
                        res = session.get(
                            endpoint,
                            params={"page": page, "per_page": PAGE_SIZE},
                            timeout=60,
                        )
                        if res.status_code == 200:
                            break
                        if res.status_code in (429,) or 500 <= res.status_code < 600:
                            last_err = f"HTTP {res.status_code}"
                            attempt += 1
                            if attempt < MAX_PAGE_RETRIES:
                                _time.sleep(BACKOFF_S[attempt - 1])
                                continue
                        # Non-retryable
                        body_snip = ""
                        try:
                            body_snip = (res.text or "")[:200].replace("\n", " ")
                        except Exception:
                            body_snip = ""
                        failure_reason = (
                            f"HTTP {res.status_code} (non-retryable)"
                            + (f" body=\"{body_snip}\"" if body_snip else "")
                        )
                        failure_endpoint = endpoint
                        log_error(
                            f"Failed to fetch from space '{space}' page {page}: "
                            f"{failure_reason} url={endpoint}"
                        )
                        page_fetch_failed = True
                        break
                    except (requests.exceptions.ConnectionError,
                            requests.exceptions.Timeout) as e:
                        # Capture the exact exception class + full message so
                        # the operator can tell `ReadTimeout` from
                        # `ConnectTimeout` from `RemoteDisconnected` from
                        # `ProtocolError` etc. Truncating to 120 chars (the
                        # pre-4.1.14 behaviour) hid all of that under a
                        # generic "network error" banner.
                        import traceback as _tb
                        last_err = f"{type(e).__name__}: {str(e)}"
                        log_debug(
                            f"[sync exc] space={space!r} page={page} "
                            f"attempt={attempt + 1}/{MAX_PAGE_RETRIES} "
                            f"endpoint={endpoint}\n{_tb.format_exc()}"
                        )
                        attempt += 1
                        if attempt < MAX_PAGE_RETRIES:
                            _time.sleep(BACKOFF_S[attempt - 1])
                            continue
                        log_error(
                            f"Network error fetching space '{space}' page {page} "
                            f"after {MAX_PAGE_RETRIES} attempts: {last_err} url={endpoint}"
                        )
                        failure_reason = f"network: {last_err}"
                        failure_endpoint = endpoint
                        res = None
                        page_fetch_failed = True
                        break

                if res is None or res.status_code != 200:
                    # Page failed — bail out of this space; diagnostics will
                    # show fetched < total and the orchestrator will skip the
                    # subtractive-delete pass for this (siem, space).
                    break

                data = res.json()
                rules = data.get('data', []) or []
                if advertised_total < 0:
                    try:
                        advertised_total = int(data.get('total', len(rules)))
                    except (TypeError, ValueError):
                        advertised_total = len(rules)

                # Add space identifier to each rule if not already present
                for rule in rules:
                    if 'space_id' not in rule or not rule['space_id']:
                        rule['space_id'] = space

                space_rules.extend(rules)
                for rule in rules:
                    rid = rule.get('rule_id')
                    if rid:
                        seen_ids.add(rid)

                if not rules:
                    # Kibana itself says there is nothing more — the only fully trustworthy end
                    # of results, regardless of what ``total`` claimed.
                    hit_empty_page = True
                    break
                # Stop once the DISTINCT rule count reaches the advertised total, not the raw row
                # count. A real production bug (large rule sets, e.g. 500 rules over 5 pages of
                # 100): if Kibana's paging returns the same rule on two pages while a different
                # rule falls through the gap between them, the raw row count reaches ``total`` one
                # page early, before the actual missing rule was ever fetched — and TIDE would
                # deprecate a rule that is genuinely still in Kibana. Continuing until the DISTINCT
                # count catches up gives that rule a real chance to show up on a later page.
                if advertised_total >= 0 and len(seen_ids) >= advertised_total:
                    break
                # Safety cap so a ``total`` that never converges (a Kibana bug, or rules being
                # created faster than pages are fetched) cannot loop forever: allow some slack
                # beyond what the advertised total should need, then give up and mark incomplete.
                if page > (advertised_total // PAGE_SIZE + 1) + 5:
                    break
                page += 1

            fetched = len(space_rules)
            distinct_ids = seen_ids

            # ``space_rules`` can still hold the same rule twice (it appeared on two pages — see
            # the loop above). Collapse that before it is fed into scoring/history as if it were
            # two separate rules.
            if len(distinct_ids) < len(space_rules):
                seen: set = set()
                deduped = []
                for r in space_rules:
                    rid = r.get('rule_id')
                    if rid and rid in seen:
                        continue
                    if rid:
                        seen.add(rid)
                    deduped.append(r)
                space_rules = deduped

            # A fetch is "complete" — safe for the subtractive-delete pass below to trust — only
            # when every page returned 200 AND the distinct rule count reached what Kibana itself
            # advertised on page 1. Ending on an empty page short of that total looks identical
            # whether Kibana's total was simply stale, or a page-boundary duplicate masked a rule
            # that was skipped — those cannot be told apart from the response alone, so both are
            # treated as incomplete. The cost of that is a genuinely-deleted rule takes one more
            # sync to be marked deprecated; the alternative is wrongly deprecating a rule that is
            # still live in Kibana, which is what this fix is for (500 rules over 5 pages of 100 is
            # enough for a duplicate on one page to push a real rule past where pagination stops).
            if page_fetch_failed or advertised_total < 0:
                total = advertised_total if advertised_total >= 0 else fetched
                complete = False
                # If we exited the retry loop without ever recording a reason
                # (defensive — shouldn't happen) at least say so.
                reason = failure_reason or "unknown (no successful page)"
                ep = failure_endpoint or endpoint
                log_error(
                    f"Sync drift: space '{space}' fetched {fetched}/{total} rules "
                    f"— {reason} — endpoint={ep}. Subtractive delete skipped "
                    f"for this space. Run `docker exec tide-app python -m "
                    f"app.scripts.diag_sync` for a full credential/connectivity "
                    f"breakdown."
                )
            elif len(distinct_ids) >= advertised_total:
                total = advertised_total
                complete = True
                if fetched > len(distinct_ids):
                    log_info(
                        f"Space '{space}': fetched {len(distinct_ids)} distinct rule(s) of "
                        f"advertised total {total} ({fetched - len(distinct_ids)} duplicate row(s) "
                        f"across page boundaries, collapsed)."
                    )
                else:
                    log_info(f"Space '{space}': fetched {len(distinct_ids)}/{total} rules")
            else:
                total = advertised_total
                complete = False
                stop_reason = (
                    "Kibana returned an empty page" if hit_empty_page
                    else f"gave up after {page} page(s) without converging"
                )
                log_error(
                    f"Sync drift: space '{space}' — only {len(distinct_ids)} distinct rule(s) "
                    f"found (advertised total {total}); every page returned HTTP 200 so this is "
                    f"not a connectivity error — {stop_reason}. Either Kibana's advertised total "
                    f"was stale, or a duplicate on one page masked a rule skipped on another; the "
                    f"two look identical from here, so subtractive delete is skipped for this "
                    f"space to avoid wrongly deprecating a rule that is still live. A rule "
                    f"genuinely deleted in Kibana will be marked deprecated on a later sync that "
                    f"does converge. Re-run sync, or validate/sync the specific rule directly if "
                    f"this space keeps triggering it."
                )

            diagnostics[space] = {
                "total": total,
                "fetched": fetched,
                "complete": complete,
                "rule_ids": distinct_ids,
            }
            all_rules.extend(space_rules)

        processed_rules = _process_rules(session, base_url, all_rules, check_mappings, catalogue,
                                         elasticsearch_url, force_catalogue, search_time_history, weights)
        df = pd.DataFrame(processed_rules)
        # Stash per-space diagnostics so the orchestrator can scope its
        # subtractive-delete pass to fully-fetched (siem, space) pairs.
        with _diag_lock:
            last_sync_diagnostics[id(df)] = diagnostics
            # Also publish under a stable per-(kibana_url, spaces) key so
            # callers that don't preserve the DataFrame identity can look it
            # up. The DataFrame-id key is preferred when available.
            last_sync_diagnostics[(base_url, tuple(sorted(spaces)))] = diagnostics
        return df

    except Exception as e:
        log_error(f"Sync Failure: {e}")
        with _diag_lock:
            last_sync_diagnostics[(base_url, tuple(sorted(spaces)))] = diagnostics
        return pd.DataFrame()


# ==========================================
# --- 5. PROMOTION FUNCTIONS ---
# ==========================================

def _space_api_prefix(base_url: str, space: str) -> str:
    """Build the correct Kibana API URL prefix for a space.

    Always emits ``{base_url}/s/{space}`` for every space, including
    ``default``. See the matching comment in ``fetch_detection_rules`` for
    the full rationale (4.1.14 fix): vanilla Kibana accepts both forms but
    reverse-proxy ingresses commonly only honour the ``/s/<space>/`` prefix,
    so aligning every URL builder onto the prefixed shape matches the
    working ``test_elastic_connection_full`` path and eliminates the
    test-vs-sync divergence.

    Empty/None ``space`` is a config bug (the link-to-tenant UI rejects
    empty space); guarded so we don't silently emit ``/s//api/...`` and
    return ``base_url`` with an error log so the operator sees it.
    """
    if not space:
        log_error(
            f"_space_api_prefix called with empty space (base_url={base_url!r}). "
            "This indicates a missing client_siem_map.space entry; falling back "
            "to {base_url} but the call will likely 404."
        )
        return f"{base_url}"
    return f"{base_url}/s/{space}"


def _make_session(api_key: str) -> "requests.Session":
    """Build a requests session with the given API key.

    Mounts a sized HTTPAdapter (same pattern as ``fetch_detection_rules`` —
    see 4.1.14 Fix 15) so that SSL certificate verification is properly
    suppressed for self-signed / private-CA Kibana endpoints and the
    connection pool is not exhausted during multi-step promotion operations
    (exception-list copy, target verify GET, source DELETE).  Without this
    adapter the default urllib3 pool raises ``SSL: CERTIFICATE_VERIFY_FAILED``
    on non-public CAs even when ``session.verify = False`` is set, because
    urllib3 rebuilds the SSL context on each new connection without honouring
    the session-level flag.
    """
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=10, pool_maxsize=10, max_retries=3,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "kbn-xsrf": "true",
        "Content-Type": "application/json",
        "Authorization": f"ApiKey {api_key}",
    })
    session.verify = False
    return session


def _fetch_preview_alerts(session, base_url, space, preview_id, es_direct_url=None):
    """
    Fetch alerts from the temporary preview index after Kibana's Preview API (8.7+).
    Returns (hit_count, alerts_list, error_or_None).
    Retries briefly because Kibana writes alerts asynchronously after returning the previewId.

    ``es_direct_url`` is resolved per-tenant from ``siem_inventory.elasticsearch_url``;
    the global ``ELASTICSEARCH_URL`` env-var fallback was removed in 4.0.10.
    """
    import time as _time

    index = f".preview.alerts-security.alerts-{space}"
    search_body = {
        "query": {
            "bool": {
                "should": [
                    {"term": {"kibana.alert.rule.preview_id": preview_id}},
                    {"term": {"kibana.alert.rule.uuid": preview_id}},
                ],
                "minimum_should_match": 1,
            }
        },
        "size": 3,
        "sort": [{"@timestamp": {"order": "desc"}}],
    }
    search_params = {"track_total_hits": "true"}

    # Retry up to 3 times with a short delay — Kibana writes alerts asynchronously
    for attempt in range(3):
        try:
            if es_direct_url:
                url = f"{es_direct_url}/{index}/_search"
                resp = session.post(url, json=search_body, params=search_params, verify=False, timeout=15)
            else:
                path = f"/{index}/_search?track_total_hits=true"
                proxy_url = f"{base_url}/api/console/proxy"
                resp = session.post(proxy_url, json=search_body, params={"path": path, "method": "POST"}, verify=False, timeout=15)

            if resp.status_code == 200:
                result = resp.json()
                total = result.get("hits", {}).get("total", {})
                hit_count = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
                hits = result.get("hits", {}).get("hits", [])
                if hit_count > 0 or attempt == 2:
                    return hit_count, hits, None
                # No hits yet — wait briefly for Kibana to finish writing
                _time.sleep(1)
            elif resp.status_code == 404:
                # Index doesn't exist yet — Kibana hasn't created it; wait and retry
                if attempt < 2:
                    _time.sleep(1)
                    continue
                return 0, [], None
            else:
                msg = f"Alert search failed ({resp.status_code}): {resp.text[:300]}"
                log_error(f"Preview alerts search failed ({resp.status_code}): {resp.text[:300]}")
                return 0, [], msg
        except Exception as e:
            log_error(f"Failed to fetch preview alerts: {e}")
            return 0, [], f"Failed to fetch preview alerts: {e}"
    return 0, [], None


def preview_detection_rule(rule_data, space="default", lookback="24h",
                           kibana_url=None, api_key=None, elasticsearch_url=None, timing=None):
    """
    Test a detection rule against live Elasticsearch data using the Kibana Preview API.
    Returns (hit_count, sample_results, error) tuple.

    Pass a dict as ``timing`` to also get how long the run took: ``timing["ms"]`` is the duration Kibana
    reports for the preview execution (or, when it reports none, the wall-clock time of the request) and
    ``timing["source"]`` says which ("kibana" or "request").

    ``kibana_url``, ``api_key`` and (optionally) ``elasticsearch_url`` are
    resolved per-tenant from ``siem_inventory`` / ``client_siem_map`` by the
    caller. The legacy global ``ELASTIC_URL`` / ``ELASTIC_API_KEY`` /
    ``ELASTICSEARCH_URL`` env-var fallbacks were removed in 4.0.10.
    """
    if not kibana_url or not api_key:
        return 0, [], (
            "No SIEM connection resolved for this rule's space. Ensure the active "
            "client has a SIEM assigned in Settings covering this space."
        )
    session, base_url = _make_session(api_key), kibana_url

    if space.lower() == "default":
        endpoint = f"{base_url}/api/detection_engine/rules/preview"
    else:
        endpoint = f"{base_url}/s/{space}/api/detection_engine/rules/preview"
    
    # Build the preview payload based on rule language
    language = normalize_rule_language(rule_data.get("language", "kuery"))
    query = rule_data.get("query", "")
    rule_type = rule_data.get("type", "query")
    
    # Map language to the correct type field for the preview API
    type_map = {
        "kuery": "query",
        "lucene": "query",
        "eql": "eql",
        "esql": "esql",
    }
    preview_type = type_map.get(language, rule_type)
    
    # Resolve index patterns — rules using data views may have an empty index list
    indices = rule_data.get("index") or []
    if not indices and (rule_data.get("data_view_id") or rule_data.get("dataViewId")):
        indices = get_data_view_indices(session, base_url, space, rule_data)

    # Build the payload the Preview API requires (name, description, risk_score are mandatory)
    payload = {
        "type": preview_type,
        "query": query,
        "language": language,
        "index": indices,
        "name": rule_data.get("name", "TIDE Preview"),
        "description": rule_data.get("description", "Preview test from TIDE"),
        "risk_score": rule_data.get("risk_score", 21),
        "severity": rule_data.get("severity", "low"),
        "interval": "5m",
        "from": f"now-{lookback}",
        "invocationCount": 1,
        "timeframeEnd": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    }

    # Include filters if present (many rules depend on these for matching)
    filters = rule_data.get("filters")
    if filters:
        payload["filters"] = filters

    # Forward the rule's timestamp_override (and its fallback flag) so the
    # Preview API uses the same timestamp source the production rule does.
    # Without this, Elastic defaults to ``@timestamp`` and rejects rules whose
    # source index uses a non-standard timestamp field (e.g.
    # ``kibana_sample_data_flights`` exposes ``timestamp``). The rule object
    # already encodes both fields when configured in Kibana \u2014 we just have to
    # propagate them.
    if rule_data.get("timestamp_override"):
        payload["timestamp_override"] = rule_data["timestamp_override"]
        if "timestamp_override_fallback_disabled" in rule_data:
            payload["timestamp_override_fallback_disabled"] = rule_data[
                "timestamp_override_fallback_disabled"
            ]
    # For EQL, include event_category_override if present
    if language == "eql":
        if rule_data.get("event_category_override"):
            payload["event_category_override"] = rule_data["event_category_override"]
    
    # For threshold rules
    if rule_data.get("threshold"):
        payload["threshold"] = rule_data["threshold"]
        payload["type"] = "threshold"

    # For threat_match (indicator) rules
    if rule_type == "threat_match":
        payload["type"] = "threat_match"
        for field in ("threat_query", "threat_mapping", "threat_index", "threat_language"):
            if rule_data.get(field):
                payload[field] = rule_data[field]

    # For new_terms rules
    if rule_type == "new_terms":
        payload["type"] = "new_terms"
        if rule_data.get("new_terms_fields"):
            payload["new_terms_fields"] = rule_data["new_terms_fields"]
        if rule_data.get("history_window_start"):
            payload["history_window_start"] = rule_data["history_window_start"]
    
    try:
        import time as _time
        _t0 = _time.monotonic()
        response = session.post(endpoint, json=payload, timeout=30)
        _wall_ms = int((_time.monotonic() - _t0) * 1000)

        if response.status_code != 200:
            error_text = response.text[:500]
            log_error(f"Preview API error ({response.status_code}): {error_text}")
            if response.status_code in (401, 403):
                # Diagnostic dump (4.0.13): log endpoint, request-id, response
                # headers and the auth header prefix actually sent so we can
                # confirm the on-the-wire request matches what worked in 4.0.7.
                _sent_auth = session.headers.get("Authorization", "<missing>")
                _auth_prefix = (_sent_auth[:14] + "...") if _sent_auth else "<empty>"
                _resp_headers = {
                    k: v for k, v in response.headers.items()
                    if k.lower() in (
                        "www-authenticate", "x-elastic-product",
                        "x-found-handling-cluster", "x-found-handling-instance",
                        "kbn-name", "kbn-license-sig", "x-kibana-request-id",
                    )
                }
                log_error(
                    f"Preview API {response.status_code} diagnostics: "
                    f"endpoint={endpoint} space={space} "
                    f"auth_header_prefix={_auth_prefix} resp_headers={_resp_headers}"
                )
                return 0, [], (
                    f"Kibana rejected the API key for the Detection Engine preview "
                    f"endpoint (HTTP {response.status_code}). Note: Management \u2192 "
                    f"Test Connection only proves /api/status — the preview endpoint "
                    f"requires Security \u2192 Detection rules privileges on space "
                    f"'{space}'. Likely causes: API key rotated/revoked in Kibana, "
                    f"the role behind the key lost Detection-rule privileges, the "
                    f"space '{space}' was renamed/removed, or the active client's "
                    f"SIEM mapping no longer covers this space. Check tide-app logs "
                    f"for the matching 'test_rule resolved SIEM ...' line to see what "
                    f"was sent. Raw response: {error_text}"
                )
            return 0, [], f"Preview API returned {response.status_code}: {error_text}"

        data = response.json()
        
        # The preview API returns logs with alerts
        logs = data.get("logs", [])
        alerts = []

        # Collect preview execution warnings and errors to surface to the user
        preview_warnings = []
        for entry in logs:
            for err in entry.get("errors", []):
                log_error(f"Preview execution error: {err}")
                preview_warnings.append(f"Error: {str(err)[:200]}")
            for warn in entry.get("warnings", []):
                preview_warnings.append(str(warn)[:200])

        if timing is not None:
            reported = 0
            for entry in logs:
                try:
                    reported += int(entry.get("duration") or 0)
                except (TypeError, ValueError):
                    pass
            timing["ms"] = reported if reported > 0 else max(_wall_ms, 1)
            timing["source"] = "kibana" if reported > 0 else "request"

        # Check if the preview was aborted
        if data.get("isAborted"):
            return 0, [], "Preview was aborted by Kibana (query may be too expensive or timed out)."
        
        # Extract alerts from the preview response
        if "previewId" in data:
            # Newer API (8.7+): alerts stored in a temporary index, not in the response body.
            # We must query .preview.alerts-security.alerts-<space> to get the actual results.
            preview_id = data["previewId"]
            hit_count, alerts, fetch_error = _fetch_preview_alerts(
                session, base_url, space, preview_id, es_direct_url=elasticsearch_url
            )
            if fetch_error:
                return 0, [], fetch_error
        else:
            # Direct response format (older Kibana versions)
            hit_count = len(data.get("alerts", []))
            alerts = data.get("alerts", [])[:3]
        
        # Simplify sample results for display
        sample_results = []
        for alert in alerts:
            source = alert.get("_source", alert)
            sample_results.append({
                "timestamp": source.get("@timestamp", source.get("event", {}).get("created", "-")),
                "host": source.get("host", {}).get("name", source.get("host.name", "-")) if isinstance(source.get("host"), dict) else source.get("host.name", "-"),
                "message": (source.get("message", source.get("rule", {}).get("description", "-")) or "-")[:200],
            })
        
        # Surface warnings when there are 0 hits (explains WHY there are no results)
        warning_msg = None
        if hit_count == 0 and preview_warnings:
            warning_msg = " | ".join(preview_warnings[:3])
        
        return hit_count, sample_results, warning_msg
        
    except requests.exceptions.Timeout:
        return 0, [], "Preview API request timed out"
    except Exception as e:
        log_error(f"Preview rule failed: {e}")
        return 0, [], str(e)


def get_exception_list(list_id, source_space, session, base_url):
    """Get exception list details from source space. Caller must supply session
    and base_url resolved from the per-tenant ``siem_inventory`` row."""
    prefix = _space_api_prefix(base_url, source_space)
    url = f"{prefix}/api/exception_lists/items/_find?list_id={list_id}"
    
    response = session.get(url)
    if response.status_code == 200:
        data = response.json().get("data", [])
        return data[0] if data else None
    
    log_error(f"Failed to get exception list {list_id}: {response.status_code}")
    return None


def get_exception_list_entries(list_id, source_space, session, base_url):
    """Get all entries from an exception list. Caller must supply session and
    base_url resolved from the per-tenant ``siem_inventory`` row."""
    prefix = _space_api_prefix(base_url, source_space)
    url = f"{prefix}/api/exception_lists/items/_find?list_id={list_id}"
    
    response = session.get(url)
    if response.status_code == 200:
        return response.json().get("data", [])
    
    log_error(f"Failed to get exception entries for {list_id}: {response.status_code}")
    return []


def create_exception_list_in_target(exc_object, target_space, rule_name, session, base_url):
    """Create a new exception list in the target space. Caller must supply
    session and base_url resolved from the per-tenant ``siem_inventory`` row."""
    exc_object = exc_object.copy()
    # Remove read-only fields
    for readonly in ["_version", "version", "created_at", "created_by", "updated_at", "updated_by", "tie_breaker_id", "meta"]:
        exc_object.pop(readonly, None)
    
    # Generate new IDs
    exc_object["list_id"] = str(uuid.uuid4())
    exc_object["id"] = str(uuid.uuid4())
    exc_object["name"] = f"Exception for rule - {rule_name}"
    exc_object["type"] = "rule_default"
    exc_object["namespace_type"] = "single"
    
    prefix = _space_api_prefix(base_url, target_space)
    url = f"{prefix}/api/exception_lists"
    response = session.post(url, json=exc_object)
    
    if response.status_code in (200, 201):
        log_info(f"Created exception list for {rule_name}")
        return response.json()
    
    log_error(f"Failed to create exception list for {rule_name}: {response.status_code}")
    return None


def create_exception_entry_in_target(exc_entry, list_id, target_space, session, base_url):
    """Create an exception entry in the target list. Caller must supply session
    and base_url resolved from the per-tenant ``siem_inventory`` row."""
    exc_entry = exc_entry.copy()
    exc_entry["list_id"] = list_id
    exc_entry["namespace_type"] = "single"
    exc_entry["item_id"] = str(uuid.uuid4())
    
    # Remove read-only fields
    for readonly in ["id", "_version", "created_at", "created_by", "updated_at", "updated_by", "tie_breaker_id", "meta"]:
        exc_entry.pop(readonly, None)
    
    prefix = _space_api_prefix(base_url, target_space)
    url = f"{prefix}/api/exception_lists/items"
    response = session.post(url, json=exc_entry)
    
    if response.status_code in (200, 201):
        return response.json()
    
    log_error(f"Failed to create exception entry in {target_space}: {response.status_code}")
    return None


def create_exception_list_for_rule(exc_object, rule_name, source_space, target_space,
                                   source_session=None, source_base_url=None,
                                   target_session=None, target_base_url=None):
    """Create a full exception list with entries for a rule"""
    old_list_id = exc_object.get("list_id")
    log_info(f"Creating exception list for {rule_name} in {target_space}")
    
    created = create_exception_list_in_target(exc_object, target_space, rule_name,
                                               session=target_session, base_url=target_base_url)
    if not created:
        log_error(f"Exception list for {rule_name} not created")
        return None
    
    # Copy all entries from the old list
    items = get_exception_list_entries(old_list_id, source_space,
                                       session=source_session, base_url=source_base_url)
    for item in items:
        create_exception_entry_in_target(item, created["list_id"], target_space,
                                          session=target_session, base_url=target_base_url)
    
    return {
        "id": created["id"],
        "list_id": created["list_id"],
        "type": created["type"],
        "namespace_type": "single"
    }


def create_detection_rule(
    rule_data: dict,
    space: str = "default",
    kibana_url: str = None,
    api_key: str = None,
) -> Tuple[bool, str, Optional[str]]:
    """Create a new detection rule in Kibana.
    
    Args:
        rule_data: Rule object with name, query, language, enabled, etc.
        space: Target Kibana space
        kibana_url: Base Kibana URL
        api_key: Kibana API key
    
    Returns: (success, message, rule_id)
    """
    if not (kibana_url and api_key):
        return False, "Missing kibana_url or api_key", None
    
    session = _make_session(api_key)
    base_url = kibana_url.rstrip("/")
    
    # Remove read-only fields
    rule = rule_data.copy()
    for readonly in ["id", "rule_id", "_version", "created_at", "created_by", "updated_at", "updated_by"]:
        rule.pop(readonly, None)
    
    # Ensure required fields
    if not rule.get("name") or not rule.get("query"):
        return False, "Rule must have name and query", None
    
    prefix = _space_api_prefix(base_url, space)
    url = f"{prefix}/api/detection_engine/rules"
    
    try:
        response = session.post(url, json=rule)
        if response.status_code not in (200, 201):
            error_msg = f"HTTP {response.status_code}: {response.text[:200]}"
            log_error(f"Failed to create rule: {error_msg}")
            return False, error_msg, None
        
        data = response.json()
        new_rule_id = data.get("rule_id") or data.get("id")
        log_info(f"Created rule '{rule.get('name')}' with ID {new_rule_id} in {space}")
        return True, f"Created rule '{rule.get('name')}'", new_rule_id
    except Exception as e:
        log_error(f"Create rule failed: {e}")
        return False, str(e), None


def update_detection_rule(
    rule_id: str,
    rule_data: dict,
    space: str = "default",
    kibana_url: str = None,
    api_key: str = None,
) -> Tuple[bool, str]:
    """Update an existing detection rule in Kibana.
    
    Args:
        rule_id: Kibana rule ID to update
        rule_data: Updated rule object
        space: Target Kibana space
        kibana_url: Base Kibana URL
        api_key: Kibana API key
    
    Returns: (success, message)
    """
    if not (kibana_url and api_key):
        return False, "Missing kibana_url or api_key"
    
    session = _make_session(api_key)
    base_url = kibana_url.rstrip("/")
    
    # Prepare update (preserve rule_id and id fields)
    rule = rule_data.copy()
    rule["rule_id"] = rule_id
    for readonly in ["id", "_version", "created_at", "created_by", "updated_by"]:
        rule.pop(readonly, None)
    
    prefix = _space_api_prefix(base_url, space)
    url = f"{prefix}/api/detection_engine/rules"
    
    try:
        response = session.put(url, json=rule)
        if response.status_code not in (200, 201):
            error_msg = f"HTTP {response.status_code}: {response.text[:200]}"
            log_error(f"Failed to update rule: {error_msg}")
            return False, error_msg
        
        log_info(f"Updated rule {rule_id} in {space}")
        return True, f"Updated rule '{rule.get('name', rule_id)}'"
    except Exception as e:
        log_error(f"Update rule failed: {e}")
        return False, str(e)


def restore_detection_rule(
    rule_data: dict,
    space: str = "default",
    kibana_url: str = None,
    api_key: str = None,
) -> Tuple[bool, str, Optional[str]]:
    """Recreate a rule that was deleted from Kibana, from the copy TIDE kept.

    The rule keeps its ``rule_id`` so anything that refers to it (baselines, history) still lines up.
    It is created DISABLED: it was removed on purpose (usually by a promotion) and switching it on
    could double-alert next to its production twin. If Kibana already has a rule with that
    ``rule_id`` nothing is created and that rule is reported instead.

    Returns: (success, message, kibana_saved_object_id)
    """
    import copy
    if not (kibana_url and api_key):
        return False, "Missing kibana_url or api_key", None
    rule = copy.deepcopy(rule_data or {})
    if not rule.get("name") or not (rule.get("query") is not None or rule.get("type") in ("machine_learning", "threat_match")):
        return False, "Stored rule data is incomplete (no name or query), so it cannot be recreated.", None
    for readonly in ("id", "_version", "created_at", "created_by", "updated_at", "updated_by", "execution_summary"):
        rule.pop(readonly, None)
    rule["enabled"] = False

    session = _make_session(api_key)
    prefix = _space_api_prefix(kibana_url.rstrip("/"), space)
    url = f"{prefix}/api/detection_engine/rules"
    try:
        response = session.post(url, json=rule)
        if response.status_code == 409 and rule.get("rule_id"):
            existing = session.get(url, params={"rule_id": rule["rule_id"]})
            if existing.status_code == 200:
                saved = (existing.json() or {}).get("id")
                return True, f"'{rule.get('name')}' already exists in {space}; nothing to recreate", saved
        if response.status_code not in (200, 201):
            error_msg = f"HTTP {response.status_code}: {response.text[:200]}"
            log_error(f"Failed to restore rule: {error_msg}")
            return False, error_msg, None
        saved = (response.json() or {}).get("id")
        log_info(f"Restored rule '{rule.get('name')}' in {space} (disabled)")
        return True, f"Recreated '{rule.get('name')}' in {space}, disabled", saved
    except Exception as e:
        log_error(f"Restore rule failed: {e}")
        return False, str(e), None


def enable_detection_rule(
    rule_id: str,
    space: str = "default",
    kibana_url: str = None,
    api_key: str = None,
) -> Tuple[bool, str]:
    """Enable a detection rule in Kibana.
    
    Returns: (success, message)
    """
    if not (kibana_url and api_key):
        return False, "Missing kibana_url or api_key"
    
    session = _make_session(api_key)
    base_url = kibana_url.rstrip("/")
    prefix = _space_api_prefix(base_url, space)
    
    # First get the rule to preserve all its data
    get_url = f"{prefix}/api/detection_engine/rules?rule_id={rule_id}"
    try:
        get_resp = session.get(get_url)
        if get_resp.status_code != 200:
            return False, f"Could not fetch rule: HTTP {get_resp.status_code}"
        
        rule_data = get_resp.json()
        rule_data["enabled"] = True
        return update_detection_rule(rule_id, rule_data, space, base_url, api_key)
    except Exception as e:
        log_error(f"Enable rule failed: {e}")
        return False, str(e)


def disable_detection_rule(
    rule_id: str,
    space: str = "default",
    kibana_url: str = None,
    api_key: str = None,
) -> Tuple[bool, str]:
    """Disable a detection rule in Kibana.
    
    Returns: (success, message)
    """
    if not (kibana_url and api_key):
        return False, "Missing kibana_url or api_key"
    
    session = _make_session(api_key)
    base_url = kibana_url.rstrip("/")
    prefix = _space_api_prefix(base_url, space)
    
    # First get the rule to preserve all its data
    get_url = f"{prefix}/api/detection_engine/rules?rule_id={rule_id}"
    try:
        get_resp = session.get(get_url)
        if get_resp.status_code != 200:
            return False, f"Could not fetch rule: HTTP {get_resp.status_code}"
        
        rule_data = get_resp.json()
        rule_data["enabled"] = False
        return update_detection_rule(rule_id, rule_data, space, base_url, api_key)
    except Exception as e:
        log_error(f"Disable rule failed: {e}")
        return False, str(e)


def promote_rule_to_production(rule_data, source_space="staging", target_space="production",
                               source_kibana_url=None, source_api_key=None,
                               target_kibana_url=None, target_api_key=None,
                               delete_source=True):
    """
    Promote a rule from source space to target space, potentially across different SIEMs.

    Source/target ``kibana_url`` and ``api_key`` are resolved per-tenant from
    ``siem_inventory`` / ``client_siem_map`` by the caller. The legacy global
    ``ELASTIC_URL`` / ``ELASTIC_API_KEY`` env-var fallbacks were removed in 4.0.10
    — both sides MUST be supplied.

    Returns: (success: bool, message: str)
    """
    if not (source_kibana_url and source_api_key):
        return False, "Promotion requires source SIEM kibana_url + api_key (none resolved)."
    if not (target_kibana_url and target_api_key):
        return False, "Promotion requires target SIEM kibana_url + api_key (none resolved)."

    src_session = _make_session(source_api_key)
    src_base = source_kibana_url.rstrip("/")
    tgt_session = _make_session(target_api_key)
    tgt_base = target_kibana_url.rstrip("/")
    
    rule = rule_data.copy()
    # Kibana payloads use ``id`` as the live Elastic identity. TIDE's
    # logical/source ``rule_id`` may differ after restore or migration.
    source_elastic_id = rule.get("id")
    source_rule_id = rule.get("rule_id")
    rule_id = source_rule_id or source_elastic_id
    rule_name = rule.get("name")
    
    log_info(f"Promoting rule '{rule_name}' from {source_space}@{src_base} to {target_space}@{tgt_base}")
    
    # Remove space tags from the rule (staging, production, test)
    for tag in MOVING_TAGS:
        if tag in rule.get("tags", []):
            rule["tags"].remove(tag)
    
    # Remove fields that should not be copied
    rule.pop("id", None)
    rule.pop("execution_summary", None)
    
    # Does the target space already have this rule? A single targeted lookup by the rule's own
    # (portable) rule_id — the field Elastic itself treats as unique per space — rather than
    # paging through the whole target space to answer one yes/no question. Fetching every rule
    # in the target just to check one is both slow on a large ruleset and carries the same
    # pagination-drift risk fixed elsewhere in sync (a rule genuinely present can still be
    # missed by a paged listing); a direct lookup by id has neither problem. This also means a
    # retry after a partially completed promotion updates the existing copy instead of creating
    # a duplicate.
    tgt_prefix = _space_api_prefix(tgt_base, target_space)
    target_existing_id = None
    if rule_id:
        lookup_resp = tgt_session.get(
            f"{tgt_prefix}/api/detection_engine/rules", params={"rule_id": rule_id},
        )
        if lookup_resp.status_code == 200:
            found = lookup_resp.json() or {}
            target_existing_id = found.get("rule_id") or found.get("id") or rule_id
    if target_existing_id is None:
        # A real Elastic rule always has a rule_id, so this only fires when the source payload
        # was missing one — match by exact name as a last resort. This is a single-page scan,
        # not authoritative on a target space with more rules than fit in one page; it exists
        # only to cover that edge case, not as the primary existence check above.
        find_resp = tgt_session.get(
            f"{tgt_prefix}/api/detection_engine/rules/_find",
            params={"search": rule_name, "per_page": 100},
        )
        if find_resp.status_code == 200:
            exact = next(
                (item for item in (find_resp.json().get("data", []) or [])
                 if item.get("name") == rule_name),
                None,
            )
            if exact:
                target_existing_id = exact.get("rule_id") or exact.get("id")
    
    # Handle exception lists
    if rule.get("exceptions_list"):
        exceptions = rule.get("exceptions_list", [])
        log_debug(f"Rule has {len(exceptions)} exception list(s)")
        
        new_exceptions = []
        for exception in exceptions:
            exception_list_id = exception.get("list_id")
            exc_obj = get_exception_list(exception_list_id, source_space,
                                          session=src_session, base_url=src_base)
            
            if exc_obj is not None:
                new_exc = create_exception_list_for_rule(
                    exc_obj, rule_name, source_space, target_space,
                    source_session=src_session, source_base_url=src_base,
                    target_session=tgt_session, target_base_url=tgt_base,
                )
                if new_exc:
                    new_exceptions.append(new_exc)
        
        if new_exceptions:
            rule["exceptions_list"] = new_exceptions
    
    # ── CREATE / UPDATE in target ──
    tgt_prefix = _space_api_prefix(tgt_base, target_space)
    url = f"{tgt_prefix}/api/detection_engine/rules"
    
    if target_existing_id:
        rule["rule_id"] = target_existing_id
        response = tgt_session.put(url, json=rule)
        action = "Updated"
    else:
        response = tgt_session.post(url, json=rule)
        action = "Created"
    
    if response.status_code not in (200, 201):
        error_msg = f"Failed to {action.lower()} rule in {target_space}: {response.status_code} - {response.text}"
        log_error(error_msg)
        return False, error_msg
    
    try:
        response_rule = response.json() or {}
    except Exception:
        response_rule = {}
    target_rule_id = response_rule.get("rule_id") or response_rule.get("id") or rule_id
    # TIDE keys a rule by Kibana's saved-object ``id`` (``rule_id`` is the same in every space),
    # so that is the identity the caller must record for the copy.
    target_saved_id = response_rule.get("id") or target_rule_id
    log_info(f"{action} rule '{rule_name}' in {target_space} as {target_rule_id}")

    # Copy-only promotion is non-destructive by contract. Kibana can take a
    # moment to expose a newly-created rule through its lookup endpoint, but
    # the successful create response is sufficient to retain the source and
    # let the next tenant sync reconcile the destination copy.
    if not delete_source:
        return True, f"Successfully {action.lower()} rule in {target_space}; source retained", target_saved_id
    
    # ── Verify the rule actually exists in the target before deleting from source ──
    verify_prefix = _space_api_prefix(tgt_base, target_space)
    verify_url = f"{verify_prefix}/api/detection_engine/rules?rule_id={target_rule_id}"
    verify_resp = tgt_session.get(verify_url)
    if verify_resp.status_code != 200:
        # Kibana versions differ on the single-rule GET endpoint after a
        # cross-space create. Use _find as the authoritative confirmation,
        # matching the exact rule name and accepting either returned ID key.
        find_resp = tgt_session.get(
            f"{verify_prefix}/api/detection_engine/rules/_find",
            params={"search": rule_name, "per_page": 100},
        )
        if find_resp.status_code == 200:
            candidates = find_resp.json().get("data", []) or []
            match = next(
                (item for item in candidates if item.get("name") == rule_name),
                None,
            )
            if match and (match.get("rule_id") or match.get("id")):
                target_rule_id = match.get("rule_id") or match.get("id")
                target_saved_id = match.get("id") or target_saved_id
                verify_resp = type("Verification", (), {"status_code": 200})()
    if verify_resp.status_code != 200:
        error_msg = (
            f"Rule appeared to be {action.lower()} in {target_space} but verification "
            f"failed ({verify_resp.status_code}). Source rule NOT deleted to prevent data loss."
        )
        log_error(error_msg)
        return False, error_msg
    
    # ── DELETE from source ──
    src_prefix = _space_api_prefix(src_base, source_space)
    source_query_key = "rule_id" if source_rule_id else "id"
    source_query_value = source_rule_id or source_elastic_id
    delete_url = f"{src_prefix}/api/detection_engine/rules?{source_query_key}={source_query_value}"
    delete_response = src_session.delete(delete_url)
    
    if delete_response.status_code not in (200, 204):
        warning_msg = f"Rule promoted but failed to delete from {source_space}: {delete_response.status_code}"
        log_error(warning_msg)
        return True, f"{action} in {target_space}, but failed to remove from {source_space}", target_saved_id
    
    log_info(f"Deleted rule '{rule_name}' from {source_space}")
    return True, f"Successfully {action.lower()} rule in {target_space} and removed from {source_space}", target_saved_id