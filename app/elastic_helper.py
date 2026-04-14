import requests
import os
import pandas as pd
import urllib3
import re
import json
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from dotenv import load_dotenv
from log import log_debug, log_error, log_info

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()


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

ESQL_KEYWORDS = {
    "where", "keep", "sort", "limit", "eval", "dissect", "grok", 
    "rename", "row", "stats", "mv_expand", "drop", "enrich"
}

MOVING_TAGS = {"test", "staging", "production"}

# ==========================================
# --- 1. PARSERS ---
# ==========================================

def extract_kuery_lucene(query):
    if not query: return set()
    fields_colon = re.findall(r'\b([\w.\-]+)\s*:', query)
    fields_compare = re.findall(r'\b([a-zA-Z_][\w.\-]*)\s*(?:==|!=|<=|>=|<|>)\s*', query)
    keywords = {"and", "or", "not", "true", "false", "in", "by", "from", "where"}
    fields = set(fields_colon + fields_compare)
    return {f for f in fields if f.lower() not in keywords and not f[0].isdigit()}

def extract_esql(query):
    if not query: return set()
    comparison_fields = re.findall(r'\b([a-zA-Z0-9_\-\.]+)\s*(?:==|!=|<=|>=|<|>)\s*', query)
    command_args = re.findall(r'(?:KEEP|SORT|DROP|MV_EXPAND|BY)\s+([a-zA-Z0-9_\-\.,\s]+)(?:\||$)', query, re.IGNORECASE)
    explicit_fields = []
    for arg_str in command_args:
        explicit_fields.extend([f.strip() for f in arg_str.split(',') if f.strip()])
    eval_fields = re.findall(r'EVAL\s+\w+\s*=\s*([a-zA-Z0-9_\-\.]+)', query, re.IGNORECASE)
    keywords = {"and", "or", "not", "true", "false", "in", "by", "from", "where", "limit", "keep", "sort", "eval", "dissect"}
    all_found = set(comparison_fields + explicit_fields + eval_fields)
    return {f for f in all_found if f.lower() not in keywords and not f[0].isdigit()}

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

def get_batch_mappings(session, base_url, index_field_map):
    es_direct_url = os.getenv("ELASTICSEARCH_URL")
    global_cache = {}

    unique_patterns = [i for i in index_field_map.keys() if i]
    valid_patterns = [
        p for p in unique_patterns
        if p and not p.startswith('_') and p.lower() not in IGNORED_INDICES
    ]

    def _fetch_mapping_for_pattern(pattern):
        """Fetch and validate field mappings for a single index pattern."""
        fields_to_check = list(index_field_map.get(pattern, set()))
        if not fields_to_check:
            return pattern, {}

        target_index = resolve_latest_index(session, base_url, pattern, es_direct_url)

        try:
            path = f"/{target_index}/_mapping?ignore_unavailable=true&allow_no_indices=true"

            if es_direct_url:
                full_url = f"{es_direct_url}/{target_index}/_mapping"
                response = session.get(full_url, params={"ignore_unavailable": "true", "allow_no_indices": "true"}, verify=False, timeout=30)
            else:
                proxy_url = f"{base_url}/api/console/proxy"
                response = session.post(proxy_url, params={"path": path, "method": "GET"}, verify=False, timeout=30)

            found_mappings = {}

            if response.status_code == 200:
                data = response.json()

                all_index_fields = {}
                for concrete_index, index_data in data.items():
                    props = index_data.get('mappings', {}).get('properties', {})
                    if props:
                        all_index_fields.update(flatten_properties(props))

                for f in fields_to_check:
                    if f in all_index_fields:
                        found_mappings[f] = all_index_fields[f]

            elif response.status_code == 404:
                log_debug(f"   Index not found (404): {target_index}")
            else:
                log_error(f"   Failed mapping fetch for {pattern}: {response.status_code}")

            return pattern, found_mappings

        except Exception as e:
            log_error(f"   Exception for {pattern}: {e}")
            return pattern, {}

    # Fetch all index mappings in parallel (requests.Session is thread-safe for reads)
    workers = min(10, len(valid_patterns)) if valid_patterns else 1
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

def fetch_detection_rules(url_override=None, key_override=None, check_mappings=True, known_rule_keys=None):
    """
    Fetch detection rules from Kibana spaces.
    known_rule_keys: set of (rule_id, space) tuples already in DB - skip mapping for these.
    """
    if known_rule_keys is None:
        known_rule_keys = set()
    base_url = url_override or os.getenv("ELASTIC_URL")
    api_key = key_override or os.getenv("ELASTIC_API_KEY")
    kibana_spaces_raw = os.getenv("KIBANA_SPACES", "default")

    if not base_url or not api_key: return pd.DataFrame()

    base_url = base_url.rstrip('/')
    headers = {"kbn-xsrf": "true", "Authorization": f"ApiKey {api_key}", "Content-Type": "application/json"}
    session = requests.Session()
    session.headers.update(headers)
    session.verify = False

    # Parse comma-separated Kibana spaces
    spaces = [s.strip() for s in kibana_spaces_raw.split(',') if s.strip()]
    if not spaces:
        spaces = ['default']
    
    all_rules = []
    
    try:
        # Loop through each Kibana space
        for space in spaces:
            page = 1
            space_rules_count = 0
            
            while True:
                # Construct URL with space prefix if not 'default'
                if space.lower() == 'default':
                    endpoint = f"{base_url}/api/detection_engine/rules/_find"
                else:
                    endpoint = f"{base_url}/s/{space}/api/detection_engine/rules/_find"
                
                res = session.get(endpoint, params={"page": page, "per_page": 100})
                if res.status_code != 200:
                    log_debug(f"Failed to fetch from space '{space}' page {page}: {res.status_code}")
                    break
                data = res.json()
                rules = data.get('data', [])
                
                # Add space identifier to each rule if not already present
                for rule in rules:
                    if 'space_id' not in rule or not rule['space_id']:
                        rule['space_id'] = space
                
                all_rules.extend(rules)
                space_rules_count += len(rules)
                
                if len(rules) < 100: break
                page += 1

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
            mapping_cache = get_batch_mappings(session, base_url, index_request_map)
        
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

        return pd.DataFrame(processed_rules)

    except Exception as e:
        log_error(f"Sync Failure: {e}")
        return pd.DataFrame()


# ==========================================
# --- 5. PROMOTION FUNCTIONS ---
# ==========================================

def get_promotion_session():
    """Get a session configured for Elastic API calls"""
    base_url = os.getenv("ELASTIC_URL")
    api_key = os.getenv("ELASTIC_API_KEY")
    
    session = requests.Session()
    session.headers.update({
        "kbn-xsrf": "true",
        "Content-Type": "application/json",
        "Authorization": f"ApiKey {api_key}"
    })
    session.verify = False
    return session, base_url


def _fetch_preview_alerts(session, base_url, space, preview_id):
    """
    Fetch alerts from the temporary preview index after Kibana's Preview API (8.7+).
    Returns (hit_count, alerts_list, error_or_None).
    Retries briefly because Kibana writes alerts asynchronously after returning the previewId.
    """
    import time as _time

    es_direct_url = os.getenv("ELASTICSEARCH_URL")
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


def preview_detection_rule(rule_data, space="default", lookback="24h"):
    """
    Test a detection rule against live Elasticsearch data using the Kibana Preview API.
    Returns (hit_count, sample_results, error) tuple.
    """
    session, base_url = get_promotion_session()
    
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
            hit_count, alerts, fetch_error = _fetch_preview_alerts(session, base_url, space, preview_id)
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


def get_space_rule_ids(space):
    """Get all rule_ids from a space"""
    session, base_url = get_promotion_session()
    url = f"{base_url}/s/{space}/api/detection_engine/rules/_find"
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


def get_exception_list(list_id, source_space):
    """Get exception list details from source space"""
    session, base_url = get_promotion_session()
    url = f"{base_url}/s/{source_space}/api/exception_lists/items/_find?list_id={list_id}"
    
    response = session.get(url)
    if response.status_code == 200:
        data = response.json().get("data", [])
        return data[0] if data else None
    
    log_error(f"Failed to get exception list {list_id}: {response.status_code}")
    return None


def get_exception_list_entries(list_id, source_space):
    """Get all entries from an exception list"""
    session, base_url = get_promotion_session()
    url = f"{base_url}/s/{source_space}/api/exception_lists/items/_find?list_id={list_id}"
    
    response = session.get(url)
    if response.status_code == 200:
        return response.json().get("data", [])
    
    log_error(f"Failed to get exception entries for {list_id}: {response.status_code}")
    return []


def create_exception_list_in_target(exc_object, target_space, rule_name):
    """Create a new exception list in the target space"""
    session, base_url = get_promotion_session()
    
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
    
    url = f"{base_url}/s/{target_space}/api/exception_lists"
    response = session.post(url, json=exc_object)
    
    if response.status_code in (200, 201):
        log_info(f"Created exception list for {rule_name}")
        return response.json()
    
    log_error(f"Failed to create exception list for {rule_name}: {response.status_code}")
    return None


def create_exception_entry_in_target(exc_entry, list_id, target_space):
    """Create an exception entry in the target list"""
    session, base_url = get_promotion_session()
    
    exc_entry = exc_entry.copy()
    exc_entry["list_id"] = list_id
    exc_entry["namespace_type"] = "single"
    exc_entry["item_id"] = str(uuid.uuid4())
    
    # Remove read-only fields
    for readonly in ["id", "_version", "created_at", "created_by", "updated_at", "updated_by", "tie_breaker_id", "meta"]:
        exc_entry.pop(readonly, None)
    
    url = f"{base_url}/s/{target_space}/api/exception_lists/items"
    response = session.post(url, json=exc_entry)
    
    if response.status_code in (200, 201):
        return response.json()
    
    log_error(f"Failed to create exception entry in {target_space}: {response.status_code}")
    return None


def create_exception_list_for_rule(exc_object, rule_name, source_space, target_space):
    """Create a full exception list with entries for a rule"""
    old_list_id = exc_object.get("list_id")
    log_info(f"Creating exception list for {rule_name} in {target_space}")
    
    created = create_exception_list_in_target(exc_object, target_space, rule_name)
    if not created:
        log_error(f"Exception list for {rule_name} not created")
        return None
    
    # Copy all entries from the old list
    items = get_exception_list_entries(old_list_id, source_space)
    for item in items:
        create_exception_entry_in_target(item, created["list_id"], target_space)
    
    return {
        "id": created["id"],
        "list_id": created["list_id"],
        "type": created["type"],
        "namespace_type": "single"
    }


def promote_rule_to_production(rule_data, source_space="staging", target_space="production"):
    """
    Promote a rule from source space to target space.
    Handles exceptions, creates/updates the rule, and deletes from source.
    
    Returns: (success: bool, message: str)
    """
    session, base_url = get_promotion_session()
    
    rule = rule_data.copy()
    rule_id = rule.get("rule_id")
    rule_name = rule.get("name")
    rule_tags = set(rule.get("tags", []))
    
    log_info(f"Promoting rule '{rule_name}' from {source_space} to {target_space}")
    
    # Remove space tags from the rule (staging, production, test)
    for tag in MOVING_TAGS:
        if tag in rule.get("tags", []):
            rule["tags"].remove(tag)
    
    # Remove fields that should not be copied
    rule.pop("id", None)
    rule.pop("execution_summary", None)
    
    # Get existing rule IDs in target space
    existing_ids = get_space_rule_ids(target_space)
    
    # Handle exception lists
    if rule.get("exceptions_list"):
        exceptions = rule.get("exceptions_list", [])
        log_debug(f"Rule has {len(exceptions)} exception list(s)")
        
        new_exceptions = []
        for exception in exceptions:
            exception_list_id = exception.get("list_id")
            exc_obj = get_exception_list(exception_list_id, source_space)
            
            if exc_obj is not None:
                new_exc = create_exception_list_for_rule(exc_obj, rule_name, source_space, target_space)
                if new_exc:
                    new_exceptions.append(new_exc)
        
        if new_exceptions:
            rule["exceptions_list"] = new_exceptions
    
    # Create or update rule in target space
    url = f"{base_url}/s/{target_space}/api/detection_engine/rules"
    
    if rule_id in existing_ids:
        # Update existing rule (PUT)
        response = session.put(url, json=rule)
        action = "Updated"
    else:
        # Create new rule (POST)
        response = session.post(url, json=rule)
        action = "Created"
    
    if response.status_code not in (200, 201):
        error_msg = f"Failed to {action.lower()} rule in {target_space}: {response.status_code} - {response.text}"
        log_error(error_msg)
        return False, error_msg
    
    log_info(f"{action} rule '{rule_name}' in {target_space}")
    
    # Delete rule from source space
    delete_url = f"{base_url}/s/{source_space}/api/detection_engine/rules?rule_id={rule_id}"
    delete_response = session.delete(delete_url)
    
    if delete_response.status_code not in (200, 204):
        warning_msg = f"Rule promoted but failed to delete from {source_space}: {delete_response.status_code}"
        log_error(warning_msg)
        return True, f"{action} in {target_space}, but failed to remove from {source_space}"
    
    log_info(f"Deleted rule '{rule_name}' from {source_space}")
    return True, f"Successfully {action.lower()} rule in {target_space} and removed from {source_space}"