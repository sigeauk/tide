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
from dotenv import load_dotenv
from log import log_debug, log_error, log_info

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
    "asc", "desc", "nulls", "first", "last",
}

# Backwards-compat alias (kept for any external importers).
ESQL_KEYWORDS = ESQL_COMMANDS | ESQL_FUNCTIONS | ESQL_RESERVED

MOVING_TAGS = {"test", "staging", "production"}

# Identifier shape used everywhere a field/alias name is expected.
_IDENT_RE = re.compile(r"[A-Za-z_@][A-Za-z0-9_@.\-]*")

# ==========================================
# --- 1. PARSERS ---
# ==========================================

def _strip_string_literals(text: str) -> str:
    """Replace ``"..."`` and ``'...'`` literals with whitespace so the regex
    pass below cannot mistake string contents for field identifiers. Length is
    preserved so any positional logic stays intact (none today, but cheap)."""
    if not text:
        return text
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in ('"', "'"):
            quote = ch
            out.append(' ')
            i += 1
            while i < n and text[i] != quote:
                # honour simple backslash escapes
                if text[i] == '\\' and i + 1 < n:
                    out.append('  ')
                    i += 2
                    continue
                out.append(' ')
                i += 1
            if i < n:
                out.append(' ')
                i += 1
        else:
            out.append(ch)
            i += 1
    return ''.join(out)


def _split_esql_pipes(query: str):
    """Split an ES|QL query on top-level ``|`` characters, ignoring any pipes
    inside quoted string literals. Returns the list of stage strings (stripped,
    empties dropped)."""
    if not query:
        return []
    stages = []
    buf = []
    in_str = None
    i = 0
    n = len(query)
    while i < n:
        ch = query[i]
        if in_str:
            buf.append(ch)
            if ch == '\\' and i + 1 < n:
                buf.append(query[i + 1])
                i += 2
                continue
            if ch == in_str:
                in_str = None
        elif ch in ('"', "'"):
            in_str = ch
            buf.append(ch)
        elif ch == '|':
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
    cleaned = _strip_string_literals(text)
    out = []
    for tok in _IDENT_RE.findall(cleaned):
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
        # tokens that look like commands followed by `(` are functions we
        # haven't registered yet — skip when they precede `(` in the source.
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


def extract_kuery_lucene(query):
    if not query: return set()
    fields_colon = re.findall(r'\b([\w.\-]+)\s*:', query)
    fields_compare = re.findall(r'\b([a-zA-Z_][\w.\-]*)\s*(?:==|!=|<=|>=|<|>)\s*', query)
    keywords = {"and", "or", "not", "true", "false", "in", "by", "from", "where"}
    fields = set(fields_colon + fields_compare)
    return {f for f in fields if f.lower() not in keywords and not f[0].isdigit()}


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

    See AGENTS.md (no hardcoded field exclusion lists). The filter set is
    grammar tokens only; field names are still discovered dynamically.
    """
    if not query:
        return set()

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


def extract_eql(query):
    if not query: return set(), []
    event_cats = re.findall(r'\b([a-zA-Z0-9_\-]+)\s+where\b', query, re.IGNORECASE)
    fields = re.findall(r'\b([a-zA-Z0-9_\-\.]+)\s*(?:==|!=|<=|>=|<|>|:|in\b)', query)
    func_fields = re.findall(r'\b(?:length|concat|indexOf|stringContains)\s*\(\s*([a-zA-Z0-9_\-\.]+)', query, re.IGNORECASE)
    keywords = {
        "and", "or", "not", "true", "false", "in", "by", "where", 
        "process", "file", "network", "registry", "sequence", "descendant", "child", "of"
    }
    all_fields = set(fields + func_fields)
    clean_fields = {f for f in all_fields if f.lower() not in keywords and not f[0].isdigit()}
    return clean_fields, event_cats

def get_esql_index(query):
    if not query: return []
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

    if str(space).lower() == "default":
        endpoint = f"{base_url}/api/data_views/data_view/{data_view_id}"
    else:
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

def resolve_latest_index(session, base_url, pattern, direct_es=None):
    # 1. If the pattern is already concrete, return it
    if "*" not in pattern:
        return pattern

    # 2. STRATEGY A: _cat/indices (Sorts by date)
    try:
        path = f"/_cat/indices/{pattern}?s=creation.date:desc&h=index&format=json"
        if direct_es:
            res = session.get(f"{direct_es}{path}", verify=False, timeout=5)
        else:
            proxy_url = f"{base_url}/api/console/proxy"
            res = session.post(proxy_url, params={"path": path, "method": "GET"}, verify=False, timeout=5)
        
        if res.status_code == 200:
            indices = res.json()
            if indices and isinstance(indices, list) and len(indices) > 0:
                return indices[0].get('index')
    except: pass 

    # 3. STRATEGY B: _resolve/index
    try:
        resolve_path = f"/_resolve/index/{pattern}"
        if direct_es:
            res = session.get(f"{direct_es}{resolve_path}", verify=False, timeout=5)
        else:
            proxy_url = f"{base_url}/api/console/proxy"
            res = session.post(proxy_url, params={"path": resolve_path, "method": "GET"}, verify=False, timeout=5)

        if res.status_code == 200:
            data = res.json()
            candidates = data.get('indices', []) + data.get('data_streams', []) + data.get('aliases', [])
            if candidates: return candidates[0].get('name')
    except: pass

    # 4. STRATEGY C: "DUMMY STACK" FALLBACK (The Fix)
    # If API resolution failed, we guess the name based on your seeder logic.
    # Pattern: logs-endpoint.events.process* -> logs-endpoint.events.process-default
    
    # Remove the * and trailing characters, then append -default
    clean_base = pattern.replace('*', '').rstrip('-.') 
    guess_index = f"{clean_base}-default"
    
    return guess_index

# ==========================================
# --- 2. MAPPING LOGIC (FULL FETCH) ---
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


# Module-level TTL cache for resolved per-pattern field mappings. Keyed by
# ``(es_direct_url or base_url, pattern)`` so two SIEMs pointing at different
# clusters never share a cache entry. TTL is short (5 min) so a mapping change
# in Elastic surfaces on the next sync; ``force_mapping=True`` upstream
# bypasses the cache by clearing entries via ``invalidate_mapping_cache``.
_MAPPING_CACHE_TTL_S = 300
_mapping_cache: dict = {}
_mapping_cache_lock = _threading.Lock()


def invalidate_mapping_cache():
    """Drop every entry from the per-pattern mapping cache. Called by the
    sync orchestrator when ``force_mapping=True`` so a forced re-check
    actually re-hits Elastic."""
    with _mapping_cache_lock:
        _mapping_cache.clear()


def _cached_mapping_get(cache_key):
    with _mapping_cache_lock:
        entry = _mapping_cache.get(cache_key)
        if not entry:
            return None
        ts, value = entry
        if (_time.time() - ts) > _MAPPING_CACHE_TTL_S:
            _mapping_cache.pop(cache_key, None)
            return None
        return value


def _cached_mapping_put(cache_key, value):
    with _mapping_cache_lock:
        _mapping_cache[cache_key] = (_time.time(), value)


def get_batch_mappings(session, base_url, index_field_map, es_direct_url=None):
    """Fetch field mappings for a batch of index patterns.

    ``es_direct_url`` (optional) bypasses the Kibana console proxy and queries
    Elasticsearch directly. It is resolved per-tenant from
    ``siem_inventory.elasticsearch_url`` by callers — the global
    ``ELASTICSEARCH_URL`` env var fallback was removed in 4.0.10.

    Performance:
      * Per-pattern TTL cache (5 min) avoids re-hitting Elastic when the same
        pattern is requested by another rule on the same sync run, or by a
        re-trigger inside the TTL window.
      * Uses ``GET <index>/_mapping/field/<csv>`` so only the fields we care
        about come back over the wire (10–100× smaller payload than the full
        ``_mapping`` for `logs-*`-shaped indices).
    """
    global_cache = {}

    unique_patterns = [i for i in index_field_map.keys() if i]
    valid_patterns = [
        p for p in unique_patterns
        if p and not p.startswith('_') and p.lower() not in IGNORED_INDICES
    ]

    cluster_key = (es_direct_url or base_url).rstrip('/')

    def _fetch_mapping_for_pattern(pattern):
        """Fetch and validate field mappings for a single index pattern."""
        fields_to_check = sorted(index_field_map.get(pattern, set()))
        if not fields_to_check:
            return pattern, {}

        # Cache key includes the requested fields so a subsequent caller
        # asking for a SUPERSET of fields will still trigger a refetch (and
        # populate the larger entry). For the common case of identical
        # field-sets this is a clean hit.
        cache_key = (cluster_key, pattern, tuple(fields_to_check))
        cached = _cached_mapping_get(cache_key)
        if cached is not None:
            log_debug(f"   [cache hit] {pattern} ({len(cached)}/{len(fields_to_check)} fields)")
            return pattern, cached

        target_index = resolve_latest_index(session, base_url, pattern, es_direct_url)
        # Use the field-filtered mapping endpoint (Elastic 7.x+).
        # Handles dotted paths transparently — ES returns one object per
        # leaf with ``mapping[<leaf-name>].type``.
        fields_csv = ",".join(fields_to_check)

        try:
            if es_direct_url:
                full_url = (
                    f"{es_direct_url}/{target_index}/_mapping/field/{fields_csv}"
                )
                response = session.get(
                    full_url,
                    params={"ignore_unavailable": "true",
                            "allow_no_indices": "true",
                            "include_defaults": "false"},
                    verify=False,
                    timeout=30,
                )
            else:
                path = (
                    f"/{target_index}/_mapping/field/{fields_csv}"
                    f"?ignore_unavailable=true&allow_no_indices=true"
                )
                proxy_url = f"{base_url}/api/console/proxy"
                response = session.post(
                    proxy_url,
                    params={"path": path, "method": "GET"},
                    verify=False,
                    timeout=30,
                )

            found_mappings = {}

            if response.status_code == 200:
                data = response.json() or {}
                # Response shape:
                #   { "<concrete-index>": { "mappings": {
                #       "<dotted.field.name>": {
                #           "full_name": "...",
                #           "mapping": { "<leaf>": { "type": "..." } } } } } }
                for concrete_index, index_data in data.items():
                    fmap = (index_data or {}).get('mappings', {}) or {}
                    for full_name, info in fmap.items():
                        leaves = (info or {}).get('mapping', {}) or {}
                        if not leaves:
                            continue
                        # Pick the first leaf — for non-multi-field types
                        # there's exactly one entry keyed by the field's
                        # short name.
                        leaf = next(iter(leaves.values()), {}) or {}
                        ftype = leaf.get('type', 'unknown')
                        # Prefer the ``full_name`` Elastic returns (handles
                        # the dotted vs. nested ambiguity); fall back to the
                        # outer key.
                        canonical = (info or {}).get('full_name') or full_name
                        # Only record fields the caller actually asked for.
                        if canonical in fields_to_check:
                            found_mappings[canonical] = ftype

            elif response.status_code == 404:
                log_debug(f"   Index not found (404): {target_index}")
            else:
                log_error(f"   Failed mapping fetch for {pattern}: {response.status_code}")

            _cached_mapping_put(cache_key, found_mappings)
            return pattern, found_mappings

        except Exception as e:
            log_error(f"   Exception for {pattern}: {e}")
            return pattern, {}

    # Fetch all index mappings in parallel (requests.Session is thread-safe for reads)
    workers = min(20, len(valid_patterns)) if valid_patterns else 1
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_fetch_mapping_for_pattern, p): p for p in valid_patterns}
        for fut in as_completed(futures):
            try:
                pattern, mappings = fut.result()
                global_cache[pattern] = mappings
            except Exception as e:
                pattern = futures[fut]
                log_error(f"   Thread exception for {pattern}: {e}")
                global_cache[pattern] = {}

    return global_cache

# ==========================================
# --- 3. SCORING & FETCH ---
# ==========================================

def calculate_score(rule_data):
    """Calculate rule quality score matching rules.py logic."""
    score = 0
    quality_score = 0
    meta_score = 0
    results = rule_data.get('results', [])
    
    # Data Quality Scores
    
    # Mapping score (max 20)
    score_mapping = 0
    if results:
        valid_lines = len([r for r in results if r[2] == "Yes"])
        score_mapping = (valid_lines / len(results)) * 20
        score += score_mapping
        quality_score += score_mapping

    # Field type score (max 11)
    score_field_type = 0
    field_type_scores = {
        "keyword": 1,
        "wildcard": 0.8,
        "boolean": 0.3,
        "integer": 0.5,
        "long": 0.5,
        "float": 0.4,
        "double": 0.4,
        "text": 0.5,
        "ip": 0.7,
        "date": 0.8,
        "object": 0.6,
        "nested": 0.7,
        "geo_point": 0.5,
        "geo_shape": 0.4
    }
    if results:
        valid_types = sum(field_type_scores.get(str(r[3]), 0) for r in results)
        score_field_type = (valid_types / len(results)) * 11
        score += score_field_type
        quality_score += score_field_type

    # Search time score (max 10)
    search_time = rule_data.get('search_time', 0)
    score_search_time = 0
    if search_time == 0:
        score_search_time = 0  # Rule hasn't run yet
    elif search_time <= 200:
        score_search_time = 10
    elif search_time <= 400:
        score_search_time = 8
    elif search_time <= 1000:
        score_search_time = 6
    elif search_time <= 2000:
        score_search_time = 4
    elif search_time <= 2500:
        score_search_time = 2
    score += score_search_time
    quality_score += score_search_time
    
    # Language score (max ~9) - detection * 0.6 + performance * 0.4
    language_scores = {
        "kuery": {"detection": 7, "performance": 9},
        "lucene": {"detection": 6, "performance": 9},
        "eql": {"detection": 10, "performance": 7},
        "esql": {"detection": 9, "performance": 7},
        "dsl": {"detection": 9, "performance": 8},
    }
    lang = rule_data.get('language', 'kuery').lower()
    lang_score = language_scores.get(lang, {"detection": 0, "performance": 0})
    score_language = round(lang_score['detection'] * 0.6 + lang_score['performance'] * 0.4, 4)
    score += score_language
    quality_score += score_language

    # META Data Scores
    
    # Note score (max 20)
    score_note = 20 if rule_data.get('note_exists') == "Yes" else 0
    score += score_note
    meta_score += score_note

    # Timestamp override score (max 5)
    score_override = 5 if rule_data.get('timestamp_override') == "event.ingested" else 0
    score += score_override
    meta_score += score_override

    # Tactics score (max 3)
    score_tactics = 3 if (rule_data.get('tactics') and rule_data.get('tactics') != "-") else 0
    score += score_tactics
    meta_score += score_tactics

    # Techniques score (max 7)
    score_techniques = 7 if (rule_data.get('techniques') and rule_data.get('techniques') != "-") else 0
    score += score_techniques
    meta_score += score_techniques
    
    # Author score (max 5)
    score_author = 5 if (rule_data.get('author_str') and rule_data.get('author_str') != "-") else 0
    score += score_author
    meta_score += score_author

    # Highlights score (max 10)
    score_highlights = 10 if (rule_data.get('highlighted_str') and rule_data.get('highlighted_str') != "-") else 0
    score += score_highlights
    meta_score += score_highlights

    # Update rule_data with all scores
    rule_data.update({
        'score': int(round(score, 0)),
        'quality_score': int(round(quality_score, 0)),
        'meta_score': int(round(meta_score, 0)),
        'score_mapping': int(round(score_mapping, 0)),
        'score_field_type': int(round(score_field_type, 0)),
        'score_search_time': int(score_search_time),
        'score_language': int(round(score_language, 0)),
        'score_note': int(score_note),
        'score_override': int(score_override),
        'score_tactics': int(score_tactics),
        'score_techniques': int(score_techniques),
        'score_author': int(score_author),
        'score_highlights': int(score_highlights)
    })
    return rule_data

def fetch_detection_rules(kibana_url, api_key, spaces, check_mappings=True,
                          known_rule_keys=None, elasticsearch_url=None):
    """Fetch detection rules from a single SIEM's Kibana instance.

    All connection parameters are now mandatory and resolved per-tenant from
    ``siem_inventory`` / ``client_siem_map``. The legacy ``ELASTIC_URL`` /
    ``ELASTIC_API_KEY`` / ``KIBANA_SPACES`` env-var fallbacks were removed in
    4.0.10 — every call site must pass real values.

    Args:
        kibana_url: Base Kibana URL for this SIEM (from ``siem_inventory.kibana_url``).
        api_key: Kibana API key (from ``siem_inventory.api_token_enc``).
        spaces: List of Kibana spaces to fetch rules from for this SIEM.
        check_mappings: When True, validate field mappings against ES.
        known_rule_keys: ``(rule_id, space)`` tuples already in DB — mapping is
            skipped for these (lazy mapping).
        elasticsearch_url: Optional direct Elasticsearch URL (from
            ``siem_inventory.elasticsearch_url``) used to bypass the Kibana
            console proxy when fetching index mappings.
    """
    if not kibana_url or not api_key:
        log_error("fetch_detection_rules: kibana_url and api_key are required")
        return pd.DataFrame()
    if known_rule_keys is None:
        known_rule_keys = set()

    base_url = kibana_url.rstrip('/')
    headers = {"kbn-xsrf": "true", "Authorization": f"ApiKey {api_key}", "Content-Type": "application/json"}
    session = requests.Session()
    session.headers.update(headers)
    session.verify = False

    spaces = [s.strip() for s in (spaces or []) if s and s.strip()]
    if not spaces:
        spaces = ['default']

    all_rules = []

    # Per-call diagnostics: { space: {"total": int, "fetched": int,
    # "complete": bool, "rule_ids": set[str]} }. Stashed on the module so the
    # sync orchestrator can decide whether the subtractive-delete pass is safe
    # to run. See app/services/sync.py for the consumer.
    diagnostics: dict = {}

    PAGE_SIZE = 1000          # Kibana _find documented max
    MAX_PAGE_RETRIES = 3
    BACKOFF_S = (0.5, 1.0, 2.0)

    try:
        # Loop through each Kibana space
        for space in spaces:
            page = 1
            space_rules: list = []
            advertised_total: int = -1  # -1 = unknown until first response
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
                # Construct URL with space prefix if not 'default'
                if space.lower() == 'default':
                    endpoint = f"{base_url}/api/detection_engine/rules/_find"
                else:
                    endpoint = f"{base_url}/s/{space}/api/detection_engine/rules/_find"

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
                            timeout=30,
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
                        last_err = str(e)[:120]
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

                # Termination: either we've collected the advertised total or
                # the API returned an empty page (defensive against a bad
                # ``total``). Note we no longer rely on ``len(rules) <
                # PAGE_SIZE`` because Kibana can occasionally return a short
                # page mid-stream (e.g. when filters change between pages).
                if advertised_total >= 0 and len(space_rules) >= advertised_total:
                    break
                if not rules:
                    break
                page += 1

            fetched = len(space_rules)
            # Three outcomes:
            #  1. page_fetch_failed       — real drift, preserve existing rows.
            #  2. advertised_total < 0    — no successful page at all, treat as failure.
            #  3. fetched < advertised_total but every page returned 200 —
            #     Kibana's total was stale or filtered. Reconcile is safe;
            #     the rules we got back are the authoritative current set.
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
            else:
                total = advertised_total
                complete = True  # all pages OK — treat result set as authoritative
                if fetched < advertised_total:
                    log_info(
                        f"Space '{space}': fetched {fetched}/{total} rules "
                        f"(Kibana over-reported total; reconciling against "
                        f"actual returned set)."
                    )
                else:
                    log_info(f"Space '{space}': fetched {fetched}/{total} rules")

            diagnostics[space] = {
                "total": total,
                "fetched": fetched,
                "complete": complete,
                "rule_ids": {r.get('rule_id') for r in space_rules if r.get('rule_id')},
            }
            all_rules.extend(space_rules)

        rule_meta_list = []
        index_request_map = defaultdict(set)
        skipped_mapping_count = 0

        # --- Batch data view resolution: resolve all data-view rules in parallel ---
        dv_tasks = []
        for i, r in enumerate(all_rules):
            has_explicit_index = r.get('index') and len(r.get('index', [])) > 0
            if not has_explicit_index and (r.get('data_view_id') or r.get('dataViewId')):
                dv_tasks.append((i, r.get('space_id', 'default'), r))

        if dv_tasks:
            dv_results = {}
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
        else:
            dv_results = {}

        for i, r in enumerate(all_rules):
            query = r.get('query', '')
            language = r.get('language', 'kuery')
            # Use last execution metrics for dynamic search-time scoring
            search_time = 0
            try:
                exec_summary = r.get('execution_summary', {}) or {}
                last_exec = exec_summary.get('last_execution', {}) or {}
                metrics = last_exec.get('metrics', {}) or {}
                search_time = int(metrics.get('total_search_duration_ms', 0) or 0)
            except Exception:
                search_time = 0
            indices = r.get('index', []) or []
            if not indices:
                # Use pre-resolved data view indices (fetched in parallel above)
                indices = dv_results.get(i, [])
            if language == "esql":
                esql_indices = get_esql_index(query)
                if esql_indices: indices = esql_indices

            clean_indices = [str(i).strip() for i in indices if i and str(i).strip().lower() not in IGNORED_INDICES]

            # Lazy Mapping: skip mapping check for rules already in DB
            rule_key = (r.get('rule_id'), r.get('space_id', 'default'))
            needs_mapping = check_mappings and rule_key not in known_rule_keys

            fields = set()
            if needs_mapping:
                if language in ["kuery", "lucene"]: fields = extract_kuery_lucene(query)
                elif language == "esql": fields = extract_esql(query)
                elif language == "eql": fields = extract_eql(query)[0]

                for idx in clean_indices: index_request_map[idx].update(fields)
            else:
                if check_mappings:
                    skipped_mapping_count += 1

            rule_meta_list.append({
                "raw": r,
                "fields": fields,
                "indices": clean_indices,
                "needs_mapping": needs_mapping,
                "search_time": search_time,
            })

        if skipped_mapping_count:
            log_info(f"[perf] Lazy mapping: skipped {skipped_mapping_count}/{len(all_rules)} rules (already in DB)")

        mapping_cache = {}
        if check_mappings and index_request_map:
            mapping_cache = get_batch_mappings(session, base_url, index_request_map,
                                              es_direct_url=elasticsearch_url)
        
        processed_rules = []
        for meta in rule_meta_list:
            r = meta["raw"]
            results = []
            if check_mappings:
                for idx in meta["indices"]:
                    idx_mappings = mapping_cache.get(idx, {})
                    for f in meta["fields"]:
                        if not idx_mappings: exists, f_type = "?", "unknown"
                        elif f in idx_mappings: exists, f_type = "Yes", idx_mappings.get(f)
                        else: exists, f_type = "-", "missing"
                        results.append((str(idx), str(f), str(exists), str(f_type)))

            # Simplified extraction for brevity
            threats = r.get('threat', [])
            mitre_ids = []
            tactics = []
            techniques = []
            if isinstance(threats, list):
                for t in threats:
                    if not isinstance(t, dict): continue
                    if 'tactic' in t: tactics.append(t['tactic'].get('name', ''))
                    for tech in t.get('technique', []):
                         if tech.get('id'): mitre_ids.append(tech.get('id'))
                         techniques.append(f"{tech.get('id')} {tech.get('name')}")
            
            # Extract investigation/highlighted fields
            investigation_fields_obj = r.get('investigation_fields', {})
            if isinstance(investigation_fields_obj, dict):
                investigation_fields = investigation_fields_obj.get('field_names', [])
            else:
                investigation_fields = []
            if not investigation_fields:
                # Try alert_suppression.group_by as fallback
                alert_suppression = r.get('alert_suppression', {})
                if isinstance(alert_suppression, dict):
                    investigation_fields = alert_suppression.get('group_by', [])
            highlighted_str = ",".join(investigation_fields) if investigation_fields else "-"
            
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
                "search_time": meta.get("search_time", 0), "language": r.get('language', 'kuery'),
                "indices": meta["indices"],
                "fields": list(meta["fields"]),
                "results": results, "query": r.get('query', ''),
                "mitre_ids": list(set(mitre_ids)),
                "raw_data": r,
                "space_id": r.get('space_id', 'default')
            }
            processed_rules.append(calculate_score(rule_data))

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
    
    Kibana's default space has NO /s/default/ prefix — it's just /api/...
    Named spaces use /s/{space}/api/...
    """
    if not space or space.lower() == "default":
        return f"{base_url}"
    return f"{base_url}/s/{space}"


def _make_session(api_key: str) -> "requests.Session":
    """Build a requests session with the given API key."""
    session = requests.Session()
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
                           kibana_url=None, api_key=None, elasticsearch_url=None):
    """
    Test a detection rule against live Elasticsearch data using the Kibana Preview API.
    Returns (hit_count, sample_results, error) tuple.

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
    language = rule_data.get("language", "kuery")
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
        response = session.post(endpoint, json=payload, timeout=30)

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


def get_space_rule_ids(space, session, base_url):
    """Get all rule_ids from a space. Caller must supply session and base_url
    resolved from the per-tenant ``siem_inventory`` row."""
    prefix = _space_api_prefix(base_url, space)
    url = f"{prefix}/api/detection_engine/rules/_find"
    all_rules = []
    per_page = 100
    page = 1
    
    while True:
        params = {"per_page": per_page, "page": page}
        response = session.get(url, params=params)
        
        if response.status_code != 200:
            log_error(f"Failed to get rules from {space}: {response.status_code} {response.text}")
            return set()
        
        data = response.json()
        rules = data.get("data", [])
        all_rules.extend(rules)
        
        if len(rules) < per_page:
            break
        page += 1
    
    return {rule["rule_id"] for rule in all_rules}


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


def promote_rule_to_production(rule_data, source_space="staging", target_space="production",
                               source_kibana_url=None, source_api_key=None,
                               target_kibana_url=None, target_api_key=None):
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
    rule_id = rule.get("rule_id")
    rule_name = rule.get("name")
    
    log_info(f"Promoting rule '{rule_name}' from {source_space}@{src_base} to {target_space}@{tgt_base}")
    
    # Remove space tags from the rule (staging, production, test)
    for tag in MOVING_TAGS:
        if tag in rule.get("tags", []):
            rule["tags"].remove(tag)
    
    # Remove fields that should not be copied
    rule.pop("id", None)
    rule.pop("execution_summary", None)
    
    # Get existing rule IDs in target space
    existing_ids = get_space_rule_ids(target_space, session=tgt_session, base_url=tgt_base)
    
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
    
    if rule_id in existing_ids:
        response = tgt_session.put(url, json=rule)
        action = "Updated"
    else:
        response = tgt_session.post(url, json=rule)
        action = "Created"
    
    if response.status_code not in (200, 201):
        error_msg = f"Failed to {action.lower()} rule in {target_space}: {response.status_code} - {response.text}"
        log_error(error_msg)
        return False, error_msg
    
    log_info(f"{action} rule '{rule_name}' in {target_space}")
    
    # ── Verify the rule actually exists in the target before deleting from source ──
    verify_prefix = _space_api_prefix(tgt_base, target_space)
    verify_url = f"{verify_prefix}/api/detection_engine/rules?rule_id={rule_id}"
    verify_resp = tgt_session.get(verify_url)
    if verify_resp.status_code != 200:
        error_msg = (
            f"Rule appeared to be {action.lower()} in {target_space} but verification "
            f"failed ({verify_resp.status_code}). Source rule NOT deleted to prevent data loss."
        )
        log_error(error_msg)
        return False, error_msg
    
    # ── DELETE from source ──
    src_prefix = _space_api_prefix(src_base, source_space)
    delete_url = f"{src_prefix}/api/detection_engine/rules?rule_id={rule_id}"
    delete_response = src_session.delete(delete_url)
    
    if delete_response.status_code not in (200, 204):
        warning_msg = f"Rule promoted but failed to delete from {source_space}: {delete_response.status_code}"
        log_error(warning_msg)
        return True, f"{action} in {target_space}, but failed to remove from {source_space}"
    
    log_info(f"Deleted rule '{rule_name}' from {source_space}")
    return True, f"Successfully {action.lower()} rule in {target_space} and removed from {source_space}"