import os
import yaml
import re
import uuid
import logging
import json
from typing import List, Dict, Optional, Tuple
from dotenv import load_dotenv

load_dotenv()

# Configure logging
logger = logging.getLogger(__name__)

def log_info(msg): logger.info(msg)
def log_error(msg): logger.error(msg)
def log_debug(msg): logger.debug(msg)

# ─── Airgap fix: point pySigma at the local MITRE ATT&CK JSON ─────────
# Must run BEFORE any sigma.backends.elasticsearch import, because those
# modules trigger a lazy download of enterprise-attack.json via urllib.
MITRE_LOCAL_PATH = os.getenv(
    "MITRE_ATTACK_PATH", "/opt/repos/mitre/enterprise-attack.json"
)
if os.path.exists(MITRE_LOCAL_PATH):
    try:
        from sigma.data import mitre_attack as _mitre_mod
        _mitre_mod.set_url(MITRE_LOCAL_PATH)
        log_info(f"[SIGMA] Using local MITRE ATT&CK data: {MITRE_LOCAL_PATH}")
    except Exception as _e:
        log_error(f"[SIGMA] Failed to configure local MITRE data: {_e}")
else:
    log_info(f"[SIGMA] Local MITRE file not found at {MITRE_LOCAL_PATH}, "
             "pySigma will attempt a remote fetch (requires internet).")

# Sigma repository paths - check /opt/repos first (Docker), then fallback locations
SIGMA_REPO_PATH = os.getenv('SIGMA_REPO_PATH', '/opt/repos/sigma')

# Pipeline storage — inside the already-mounted data volume, so saved pipelines
# survive container restarts without requiring an extra volume mount.
# Default resolves to /app/data/sigma_pipelines/ (alongside tide.duckdb).
PIPELINE_DIR: str = os.path.join(
    os.path.dirname(os.getenv("DB_PATH", "/app/data/tide.duckdb")),
    "sigma_pipelines",
)

# Template storage for query post-processing pipelines (pySigma template type).
TEMPLATE_DIR: str = os.path.join(
    os.path.dirname(os.getenv("DB_PATH", "/app/data/tide.duckdb")),
    "sigma_templates",
)

# Cache for loaded rules
_rules_cache: Optional[List[Dict]] = None

# Whether backends have been warmed up
_backends_warmed: bool = False


def warm_up_backends() -> None:
    """
    Pre-import all Sigma backends & pipelines at startup so the first
    user conversion doesn't pay a multi-second cold-start penalty.
    Also instantiates each backend once to trigger any internal class-level
    initialisation (e.g. MITRE ATT&CK taxonomy loading).
    """
    global _backends_warmed
    if _backends_warmed:
        return

    log_info("[SIGMA] Warming up backends and pipelines …")

    # -- Backends --
    backend_classes = []
    try:
        from sigma.rule import SigmaRule  # noqa: F401
        from sigma.collection import SigmaCollection  # noqa: F401
        log_info("[SIGMA]   ✓ sigma.rule / sigma.collection")
    except Exception as e:
        log_error(f"[SIGMA]   ✗ sigma core: {e}")

    try:
        from sigma.backends.elasticsearch import LuceneBackend, EqlBackend, ESQLBackend
        backend_classes.extend([LuceneBackend, EqlBackend, ESQLBackend])
        log_info("[SIGMA]   ✓ elasticsearch backends (Lucene, EQL, ES|QL)")
    except Exception as e:
        log_error(f"[SIGMA]   ✗ elasticsearch backends: {e}")

    try:
        from sigma.backends.splunk import SplunkBackend
        backend_classes.append(SplunkBackend)
        log_info("[SIGMA]   ✓ splunk backend")
    except Exception as e:
        log_error(f"[SIGMA]   ✗ splunk backend: {e}")

    try:
        try:
            from sigma.backends.microsoft365defender import Microsoft365DefenderBackend  # noqa: F401
        except ImportError:
            from sigma.backends.microsoft365defender import KustoBackend  # noqa: F401
        log_info("[SIGMA]   ✓ microsoft365defender backend")
    except Exception as e:
        log_error(f"[SIGMA]   ✗ microsoft365defender backend: {e}")

    # Instantiate each backend once (forces class-level setup)
    for cls in backend_classes:
        try:
            cls()
        except Exception:
            pass  # some may require a pipeline — that's fine

    # -- Pipelines --
    try:
        from sigma.pipelines.sysmon import sysmon_pipeline  # noqa: F401
        log_info("[SIGMA]   ✓ sysmon pipeline")
    except Exception as e:
        log_error(f"[SIGMA]   ✗ sysmon pipeline: {e}")

    try:
        try:
            from sigma.pipelines.windows import windows_logsource_pipeline  # noqa: F401
        except ImportError:
            from sigma.pipelines.windows import windows_pipeline  # noqa: F401
        from sigma.pipelines.windows import windows_audit_pipeline  # noqa: F401
        log_info("[SIGMA]   ✓ windows pipelines")
    except Exception as e:
        log_error(f"[SIGMA]   ✗ windows pipelines: {e}")

    try:
        from sigma.pipelines.elasticsearch import ecs_windows  # noqa: F401
        log_info("[SIGMA]   ✓ ecs_windows pipeline")
    except Exception as e:
        log_error(f"[SIGMA]   ✗ ecs_windows pipeline: {e}")

    _backends_warmed = True
    log_info("[SIGMA] Backend warm-up complete")


def ensure_sigma_repo() -> str:
    """Find the local Sigma rules directory. No internet access — repo is baked into the Docker image."""
    # Check possible locations in order of preference
    possible_paths = [
        '/opt/repos/sigma',           # Docker build location
        '/app/repos/sigma',           # Alternative Docker location
        os.path.join(os.getcwd(), 'repos', 'sigma'),  # Local dev
    ]
    
    for repo_path in possible_paths:
        rules_path = os.path.join(repo_path, 'rules')
        if os.path.exists(rules_path):
            log_info(f"[SIGMA] Found rules at: {rules_path}")
            return rules_path
    
    log_error(f"[SIGMA] No Sigma rules found in any of: {possible_paths}")
    # Return default path even if it doesn't exist
    return os.path.join(SIGMA_REPO_PATH, 'rules')


def get_sigma_rules_path() -> str:
    """Get the path to sigma rules directory."""
    return ensure_sigma_repo()


def load_sigma_rule(file_path: str) -> Optional[Dict]:
    """Load a single Sigma rule from a YAML file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            rule = yaml.safe_load(content)
            if rule and isinstance(rule, dict):
                rule['_file_path'] = file_path
                rule['_raw_yaml'] = content
                return rule
    except Exception as e:
        log_error(f"Error loading {file_path}: {e}")
    return None


def extract_mitre_techniques(rule: Dict) -> List[str]:
    """Extract MITRE ATT&CK technique IDs from a Sigma rule."""
    techniques = []
    tags = rule.get('tags', []) or []
    if tags:
        for tag in tags:
            if isinstance(tag, str):
                # Match patterns like attack.t1059, attack.t1059.001, attack.T1059
                match = re.search(r'attack\.t(\d+(?:\.\d+)?)', tag, re.IGNORECASE)
                if match:
                    # Format as T1234 or T1234.001
                    tech_num = match.group(1)
                    techniques.append(f"T{tech_num}")
    return list(set(techniques))


# Canonical mapping of Sigma tag slugs → human-readable MITRE tactic names
_TACTIC_TAG_MAP = {
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command_and_control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "resource_development": "Resource Development",
    "reconnaissance": "Reconnaissance",
}


def extract_mitre_tactics(rule: Dict) -> List[str]:
    """Extract MITRE ATT&CK tactic names from a Sigma rule's tags.

    Tags like ``attack.initial_access`` are mapped via *_TACTIC_TAG_MAP*
    to human-readable names (e.g. "Initial Access").
    """
    tactics: list[str] = []
    for tag in (rule.get("tags") or []):
        if not isinstance(tag, str) or not tag.startswith("attack."):
            continue
        slug = tag[len("attack."):]
        tactic = _TACTIC_TAG_MAP.get(slug)
        if tactic:
            tactics.append(tactic)
    return list(dict.fromkeys(tactics))  # dedupe, preserve order


def index_sigma_rules() -> int:
    """Populate the *sigma_rules_index* table in the **shared** DB.

    Uses the in-memory rules cache (must be loaded first via
    ``load_all_rules()``).  Strategy is TRUNCATE → INSERT so the index
    always mirrors the baked-in SigmaHQ repo.

    Returns the number of rows inserted.
    """
    from datetime import datetime as _dt
    from app.services.database import get_database_service

    rules = load_all_rules()
    if not rules:
        log_error("[SIGMA-INDEX] No rules in cache – skipping index")
        return 0

    db = get_database_service()
    now = _dt.utcnow()
    rows = []
    for rule in rules:
        rule_id = rule.get("id")
        if not rule_id:
            continue
        ls = rule.get("logsource") or {}
        product  = (ls.get("product") or "").strip().lower() or None
        category = (ls.get("category") or "").strip().lower() or None
        service  = (ls.get("service") or "").strip().lower() or None
        techniques = extract_mitre_techniques(rule) or []
        tactics    = extract_mitre_tactics(rule) or []
        rows.append((
            str(rule_id),
            rule.get("title", ""),
            (rule.get("level") or "").lower(),
            (rule.get("status") or "").lower(),
            product,
            category,
            service,
            techniques,
            tactics,
            rule.get("_file_path", ""),
            now,
        ))

    with db.get_shared_connection() as conn:
        conn.execute("DELETE FROM sigma_rules_index")
        conn.executemany(
            """INSERT INTO sigma_rules_index
               (rule_id, title, level, status, product, category,
                service, techniques, tactics, file_path, indexed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )

    log_info(f"[SIGMA-INDEX] Indexed {len(rows)} rules into sigma_rules_index")
    return len(rows)


def load_all_rules(force_reload: bool = False) -> List[Dict]:
    """Load all Sigma rules from the repository."""
    global _rules_cache
    
    if _rules_cache is not None and not force_reload:
        return _rules_cache
    
    rules = []
    rules_path = get_sigma_rules_path()
    
    if not os.path.exists(rules_path):
        log_error(f"Sigma rules path not found: {rules_path}")
        return rules
    
    # Walk through all YAML files in the rules directory
    for root, dirs, files in os.walk(rules_path):
        for file in files:
            if file.endswith(('.yml', '.yaml')):
                file_path = os.path.join(root, file)
                rule = load_sigma_rule(file_path)
                if rule:
                    # Add extracted metadata
                    rule['_techniques'] = extract_mitre_techniques(rule)
                    rule['_category'] = os.path.relpath(root, rules_path).split(os.sep)[0] if root != rules_path else 'root'
                    rules.append(rule)
    
    _rules_cache = rules
    log_info(f"Loaded {len(rules)} Sigma rules")
    return rules


def search_rules(
    query: str = "",
    technique_filter: str = "",
    category_filter: str = "",
    level_filter: str = "",
    limit: int = 100
) -> List[Dict]:
    """Search Sigma rules by various criteria."""
    rules = load_all_rules()
    results = []
    
    query_lower = query.lower().strip()
    # Normalize technique filter - remove T prefix if present for flexible matching
    technique_filter = technique_filter.upper().strip()
    if technique_filter.startswith('T'):
        technique_filter_num = technique_filter[1:]  # Just the number part
    else:
        technique_filter_num = technique_filter
    
    for rule in rules:
        # Filter by search query (title, description, name)
        if query_lower:
            title = str(rule.get('title', '')).lower()
            description = str(rule.get('description', '')).lower()
            name = str(rule.get('name', '')).lower()
            rule_id = str(rule.get('id', '')).lower()
            # Also search in tags
            tags_str = ' '.join(str(t) for t in (rule.get('tags', []) or [])).lower()
            
            if not any(query_lower in field for field in [title, description, name, rule_id, tags_str]):
                continue
        
        # Filter by MITRE technique
        if technique_filter:
            techniques = rule.get('_techniques', [])
            # Also check raw tags for technique patterns
            raw_tags = [str(t).lower() for t in (rule.get('tags', []) or [])]
            
            # Check extracted techniques
            technique_match = any(technique_filter in t or technique_filter_num in t for t in techniques)
            # Also check raw tags for t1234 patterns
            tag_match = any(f't{technique_filter_num}' in tag for tag in raw_tags)
            
            if not technique_match and not tag_match:
                continue
        
        # Filter by category (windows, linux, etc.)
        if category_filter:
            if rule.get('_category', '').lower() != category_filter.lower():
                continue
        
        # Filter by level (critical, high, medium, low, informational)
        if level_filter:
            if rule.get('level', '').lower() != level_filter.lower():
                continue
        
        results.append(rule)
        
        if len(results) >= limit:
            break
    
    return results


def get_rule_categories() -> List[str]:
    """Get all unique rule categories."""
    rules = load_all_rules()
    categories = set()
    for rule in rules:
        cat = rule.get('_category', '')
        if cat:
            categories.add(cat)
    return sorted(list(categories))


def get_rule_levels() -> List[str]:
    """Get all unique rule levels."""
    return ['critical', 'high', 'medium', 'low', 'informational']


def get_available_backends() -> Dict[str, str]:
    """Get available pySigma backends."""
    backends = {
        'elasticsearch': 'Elasticsearch (Lucene)',
        'eql': 'Elasticsearch (EQL)',
        'esql': 'Elasticsearch (ES|QL)',
        'splunk': 'Splunk SPL',
        'microsoft365defender': 'Microsoft 365 Defender (KQL)',
    }
    return backends


def get_output_formats(backend: str) -> Dict[str, str]:
    """Get available output formats for a specific backend."""
    # Note: Order matters - first item is default
    formats = {
        'elasticsearch': {
            'kibana_ndjson': 'Kibana Detection Rule',
            'default': 'Default Query',
            'dsl_lucene': 'DSL Query (Lucene)',
        },
        'eql': {
            'default': 'Default Query',
            'eqlapi': 'EQL API Format',
        },
        'esql': {
            'default': 'Default Query',
        },
        'splunk': {
            'default': 'Default Query',
            'savedsearches': 'savedsearches.conf',
            'data_model': 'Data Model Query',
        },
        'microsoft365defender': {
            'default': 'Default Query',
        },
    }
    return formats.get(backend, {'default': 'Default Query'})


def get_available_pipelines() -> Dict[str, str]:
    """Get available pySigma pipelines."""
    pipelines = {
        'none': 'No Pipeline',
        'sysmon': 'Sysmon',
        'windows': 'Windows',
        'windows-audit': 'Windows Audit',
        'ecs_windows': 'ECS Windows',
    }
    return pipelines


def convert_sigma_rule(
    yaml_content: str,
    backend: str = 'elasticsearch',
    pipeline: str = 'none',
    output_format: str = 'default',
    index_pattern: str = '',
    custom_pipeline_yaml: str = '',
    pipeline_file: str = '',
    template_file: str = '',
) -> Tuple[bool, str]:
    """
        Convert a Sigma rule using the in-process pySigma API.

        Uses the pySigma Python API exclusively (never sigma-cli subprocess)
        to guarantee air-gapped compatibility.  The module-level
        ``mitre_attack.set_url()`` call points pySigma at the bundled
        MITRE ATT&CK JSON; a sigma-cli subprocess would bypass that
        and attempt a network fetch, breaking air-gapped deployments.

        Note: For Elasticsearch detection-rule output, UI format
        ``kibana_ndjson`` is mapped to native pySigma backend format
        ``siem_rule_ndjson``.

    Returns:
        (True, result_string)  on success
        (False, error_string)  on failure
    """

    # Resolve saved processing pipelines.
    pipeline_disk_paths: List[str] = []
    if pipeline_file and pipeline_file.strip():
        for fname in [f.strip() for f in pipeline_file.split(',') if f.strip()]:
            safe = os.path.basename(fname)
            full = os.path.join(PIPELINE_DIR, safe)
            if not os.path.isfile(full):
                return False, f"Pipeline file not found: {fname}"
            pipeline_disk_paths.append(full)

    # Parse explicit index pattern into backend-option list.
    explicit_indices = _dedupe_keep_order(
        [p.strip() for p in str(index_pattern or '').split(',') if p.strip()]
    )

    # Resolve saved template pipelines (postprocessing template type).
    template_disk_paths: List[str] = []
    if template_file and template_file.strip():
        for fname in [f.strip() for f in template_file.split(',') if f.strip()]:
            safe = os.path.basename(fname)
            full = os.path.join(TEMPLATE_DIR, safe)
            if not os.path.isfile(full):
                return False, f"Template file not found: {fname}"
            template_disk_paths.append(full)

    # Alias UI format to native backend format.
    selected_output_format = output_format
    if backend == 'elasticsearch' and output_format == 'kibana_ndjson':
        selected_output_format = 'default' if template_disk_paths else 'siem_rule_ndjson'

    try:
        from sigma.rule import SigmaRule
        from sigma.collection import SigmaCollection
        from sigma.processing.pipeline import ProcessingPipeline

        rule = SigmaRule.from_yaml(yaml_content)
        collection = SigmaCollection([rule])

        # ── Assemble the processing pipeline ──────────────────────────
        pipeline_parts: List[ProcessingPipeline] = []

        # 1) Built-in named pipeline
        if pipeline and pipeline != 'none':
            if pipeline == 'sysmon':
                from sigma.pipelines.sysmon import sysmon_pipeline
                pipeline_parts.append(sysmon_pipeline())
            elif pipeline == 'windows':
                try:
                    from sigma.pipelines.windows import windows_logsource_pipeline
                    pipeline_parts.append(windows_logsource_pipeline())
                except ImportError:
                    from sigma.pipelines.windows import windows_pipeline
                    pipeline_parts.append(windows_pipeline())
            elif pipeline == 'windows-audit':
                from sigma.pipelines.windows import windows_audit_pipeline
                pipeline_parts.append(windows_audit_pipeline())
            elif pipeline == 'ecs_windows':
                try:
                    from sigma.pipelines.elasticsearch import ecs_windows
                    pipeline_parts.append(ecs_windows())
                except ImportError:
                    pass

        # 2) Saved pipeline files from disk
        for disk_path in pipeline_disk_paths:
            with open(disk_path, 'r', encoding='utf-8') as f:
                pipeline_parts.append(ProcessingPipeline.from_yaml(f.read()))

        # 3) Saved template files (with optional index override)
        for disk_path in template_disk_paths:
            with open(disk_path, 'r', encoding='utf-8') as f:
                tpl_yaml = f.read()
            if explicit_indices:
                tpl_data = yaml.safe_load(tpl_yaml) or {}
                vars_obj = tpl_data.get('vars') if isinstance(tpl_data.get('vars'), dict) else {}
                vars_obj['index_names'] = explicit_indices
                tpl_data['vars'] = vars_obj
                tpl_yaml = yaml.dump(tpl_data, default_flow_style=False, sort_keys=False)
            pipeline_parts.append(ProcessingPipeline.from_yaml(tpl_yaml))

        # 4) Ad-hoc pipeline YAML (upload / paste)
        if custom_pipeline_yaml and custom_pipeline_yaml.strip():
            pipeline_parts.append(ProcessingPipeline.from_yaml(custom_pipeline_yaml))

        # Merge all pipeline parts into a single pipeline (or None).
        processing_pipeline = None
        if pipeline_parts:
            processing_pipeline = pipeline_parts[0]
            for extra in pipeline_parts[1:]:
                processing_pipeline += extra

        # ── Backend factory ───────────────────────────────────────────
        bk_kwargs: Dict = {}
        if processing_pipeline:
            bk_kwargs['processing_pipeline'] = processing_pipeline

        if backend == 'elasticsearch' and selected_output_format in ('siem_rule', 'siem_rule_ndjson'):
            bk_kwargs['index_names'] = explicit_indices or _dedupe_keep_order(get_elastic_indices())

        if backend == 'elasticsearch':
            from sigma.backends.elasticsearch import LuceneBackend
            sigma_backend = LuceneBackend(**bk_kwargs)
        elif backend == 'eql':
            from sigma.backends.elasticsearch import EqlBackend
            sigma_backend = EqlBackend(**bk_kwargs)
        elif backend == 'esql':
            from sigma.backends.elasticsearch import ESQLBackend
            sigma_backend = ESQLBackend(**bk_kwargs)
        elif backend == 'splunk':
            from sigma.backends.splunk import SplunkBackend
            sigma_backend = SplunkBackend(**bk_kwargs)
        elif backend == 'microsoft365defender':
            try:
                from sigma.backends.microsoft365defender import Microsoft365DefenderBackend
                sigma_backend = Microsoft365DefenderBackend(**bk_kwargs)
            except ImportError:
                from sigma.backends.microsoft365defender import KustoBackend
                sigma_backend = KustoBackend(**bk_kwargs)
        else:
            return False, f"Unknown backend: {backend}"

        if selected_output_format and selected_output_format != 'default':
            try:
                result = sigma_backend.convert(collection, selected_output_format)
            except TypeError:
                result = sigma_backend.convert(collection)
        else:
            result = sigma_backend.convert(collection)

        if isinstance(result, list):
            parts = [json.dumps(r) if isinstance(r, dict) else str(r) for r in result]
            return True, '\n'.join(parts)
        if isinstance(result, dict):
            return True, json.dumps(result)
        return True, str(result)

    except Exception as exc:
        return False, f"Conversion error: {str(exc)}"


def validate_sigma_rule(yaml_content: str) -> Tuple[bool, str]:
    """Validate a Sigma rule YAML."""
    try:
        from sigma.rule import SigmaRule
        rule = SigmaRule.from_yaml(yaml_content)
        return True, f"Valid Sigma rule: {rule.title}"
    except Exception as e:
        return False, f"Invalid Sigma rule: {str(e)}"


def get_kibana_spaces() -> List[str]:
    """Get Kibana spaces from environment."""
    spaces_str = os.getenv('KIBANA_SPACES', 'staging, production')
    return [s.strip() for s in spaces_str.split(',') if s.strip()]


def get_elastic_indices() -> List[str]:
    """Get Elasticsearch index patterns from ELASTIC_INDICES env var."""
    indices_str = os.getenv('ELASTIC_INDICES', 'logs-*, winlogbeat-*, filebeat-*')
    return [s.strip() for s in indices_str.split(',') if s.strip()]


def _dedupe_keep_order(values: List[str]) -> List[str]:
    """Return a de-duplicated list while preserving first-seen order."""
    out: List[str] = []
    seen = set()
    for v in values:
        sv = str(v).strip()
        if not sv or sv in seen:
            continue
        seen.add(sv)
        out.append(sv)
    return out


def _get_pipeline_index_mode(data: Dict, transformations: Optional[List[Dict]] = None) -> str:
    """
    Resolve pipeline index merge mode.

    Supported values: append (default), overwrite.
    Accepted keys for compatibility:
      - index_mode
      - x_tide_index_mode
      - x-tide-index-mode
    """
    raw_mode = (
        data.get('index_mode')
        or data.get('x_tide_index_mode')
        or data.get('x-tide-index-mode')
        or ''
    )
    mode = str(raw_mode).strip().lower()
    if mode in ('append', 'overwrite'):
        return mode

    # Parser-safe fallback: infer from add_condition transformation metadata
    # using either explicit custom keys or id naming conventions.
    for t in transformations or []:
        if t.get('type') != 'add_condition':
            continue
        t_mode = str(
            t.get('tide_index_mode')
            or t.get('x_tide_index_mode')
            or t.get('x-tide-index-mode')
            or ''
        ).strip().lower()
        if t_mode in ('append', 'overwrite'):
            return t_mode

        t_id = str(t.get('id') or '').strip().lower()
        if 'overwrite' in t_id:
            return 'overwrite'

    return 'append'




def _extract_indices_from_pipeline_yaml(yaml_content: str) -> List[str]:
    """
    Read a Sigma ProcessingPipeline YAML and return every _index value found
    in add_condition transformations.
    """
    try:
        data = yaml.safe_load(yaml_content) or {}
        indices: List[str] = []
        for t in data.get('transformations', []):
            if t.get('type') == 'add_condition':
                idx = (t.get('conditions') or {}).get('_index')
                if isinstance(idx, list):
                    indices.extend(str(i) for i in idx)
                elif isinstance(idx, str):
                    indices.append(idx)
        return indices
    except Exception:
        return []


def _extract_and_strip_index_from_pipeline(pipeline_yaml: str) -> Tuple[List[str], str, str]:
    """
    Structured (no-regex) extraction of _index values from a pipeline YAML.

    Reads every ``add_condition`` transformation, collects ``_index`` values,
    and returns a copy of the pipeline YAML with those transformations removed.
    The cleaned YAML is safe to pass to `LuceneBackend` for Kibana Detection
    Rule conversion — the ``_index`` will NOT appear in the query string, so
    no regex post-processing is required.

    Also resolves the pipeline merge mode for index handling:
      - append: add discovered indices to the running list (default)
      - overwrite: replace the running list with discovered indices

    Returns:
        (index_list, cleaned_pipeline_yaml, index_mode)
    """
    try:
        data = yaml.safe_load(pipeline_yaml) or {}
        transformations = data.get('transformations', [])
        mode = _get_pipeline_index_mode(data, transformations)
        indices: List[str] = []
        kept = []
        for t in transformations:
            if t.get('type') == 'add_condition':
                idx = (t.get('conditions') or {}).get('_index')
                if idx is not None:
                    if isinstance(idx, list):
                        indices.extend(str(v) for v in idx)
                    else:
                        indices.append(str(idx))
                    continue  # drop this transformation from the clean pipeline
            kept.append(t)
        clean_data = {**data, 'transformations': kept}
        return _dedupe_keep_order(indices), yaml.dump(clean_data, default_flow_style=False), mode
    except Exception:
        return [], pipeline_yaml, 'append'


def _merge_pipeline_indices(pipeline_yamls: List[str]) -> Tuple[List[str], List[str]]:
    """
    Merge index filters from multiple pipeline YAMLs in user-selected order.

    Merge rules:
      - append: extend current list
      - overwrite: replace current list

    Returns:
        (merged_indices, cleaned_pipeline_yamls)
    """
    merged: List[str] = []
    stripped_list: List[str] = []

    for pl_yaml in pipeline_yamls:
        pl_indices, stripped, mode = _extract_and_strip_index_from_pipeline(pl_yaml)
        stripped_list.append(stripped)

        if mode == 'overwrite':
            merged = _dedupe_keep_order(pl_indices)
        else:
            merged = _dedupe_keep_order(merged + pl_indices)

    return merged, stripped_list


# ─── Saved Pipeline File Management ───────────────────────────────────────────

def ensure_pipeline_dir() -> str:
    """Create the pipeline storage directory if it does not exist."""
    os.makedirs(PIPELINE_DIR, exist_ok=True)
    return PIPELINE_DIR


def ensure_template_dir() -> str:
    """Create the template storage directory if it does not exist."""
    os.makedirs(TEMPLATE_DIR, exist_ok=True)
    return TEMPLATE_DIR


def list_saved_pipelines() -> List[Dict]:
    """
    Return metadata for all .yml/.yaml files in PIPELINE_DIR.
    Each entry: {filename, name (stem), display (title-cased stem)}.
    """
    ensure_pipeline_dir()
    results: List[Dict] = []
    try:
        for fname in sorted(os.listdir(PIPELINE_DIR)):
            if fname.endswith(('.yml', '.yaml')):
                stem = os.path.splitext(fname)[0]
                results.append({
                    "filename": fname,
                    "name":     stem,
                    "display":  stem.replace('-', ' ').replace('_', ' ').title(),
                })
    except Exception as _e:
        log_error(f"[SIGMA] Failed to list saved pipelines: {_e}")
    return results


def list_saved_templates() -> List[Dict]:
    """
    Return metadata for all .yml/.yaml files in TEMPLATE_DIR.
    Each entry: {filename, name (stem), display (title-cased stem)}.
    """
    ensure_template_dir()
    results: List[Dict] = []
    try:
        for fname in sorted(os.listdir(TEMPLATE_DIR)):
            if fname.endswith(('.yml', '.yaml')):
                stem = os.path.splitext(fname)[0]
                results.append({
                    "filename": fname,
                    "name": stem,
                    "display": stem.replace('-', ' ').replace('_', ' ').title(),
                })
    except Exception as _e:
        log_error(f"[SIGMA] Failed to list saved templates: {_e}")
    return results


def read_pipeline_file(filename: str) -> Optional[str]:
    """Read a saved pipeline YAML by filename. Returns None if not found."""
    ensure_pipeline_dir()
    safe = os.path.basename(filename)  # prevent path traversal
    path = os.path.join(PIPELINE_DIR, safe)
    if not os.path.isfile(path):
        log_error(f"[SIGMA] Pipeline file not found: {safe}")
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as _e:
        log_error(f"[SIGMA] Failed to read pipeline file {safe}: {_e}")
        return None


def read_template_file(filename: str) -> Optional[str]:
    """Read a saved template YAML by filename. Returns None if not found."""
    ensure_template_dir()
    safe = os.path.basename(filename)
    path = os.path.join(TEMPLATE_DIR, safe)
    if not os.path.isfile(path):
        log_error(f"[SIGMA] Template file not found: {safe}")
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as _e:
        log_error(f"[SIGMA] Failed to read template file {safe}: {_e}")
        return None


def validate_pipeline_yaml(content: str) -> Tuple[bool, str]:
    """
    Dry-run parse a Sigma ProcessingPipeline YAML.
    Returns (True, info_message) or (False, error_message).
    """
    try:
        from sigma.processing.pipeline import ProcessingPipeline as _PP
        pl = _PP.from_yaml(content)
        item_count = len(pl.items) if hasattr(pl, 'items') else '?'
        log_info(f"[SIGMA] Pipeline validation OK — {item_count} items")
        return True, f"Valid pipeline ({item_count} processing item(s))"
    except Exception as _e:
        return False, f"Invalid pipeline YAML: {_e}"


def write_pipeline_file(filename: str, content: str) -> Tuple[bool, str]:
    """
    Validate then save a pipeline YAML to PIPELINE_DIR.
    Ensures the filename has a .yml extension.
    Returns (True, saved_filename) or (False, error_message).
    """
    ok, msg = validate_pipeline_yaml(content)
    if not ok:
        return False, msg
    ensure_pipeline_dir()
    safe = os.path.basename(filename)
    if not safe.endswith(('.yml', '.yaml')):
        safe += '.yml'
    path = os.path.join(PIPELINE_DIR, safe)
    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        log_info(f"[SIGMA] Saved pipeline file: {safe}")
        return True, safe
    except Exception as _e:
        log_error(f"[SIGMA] Failed to save pipeline file {safe}: {_e}")
        return False, str(_e)


def write_template_file(filename: str, content: str) -> Tuple[bool, str]:
    """
    Validate then save a template pipeline YAML to TEMPLATE_DIR.
    Template pipelines are standard ProcessingPipeline YAML files and should
    include a postprocessing section with one or more template items.
    """
    ok, msg = validate_pipeline_yaml(content)
    if not ok:
        return False, msg

    try:
        data = yaml.safe_load(content) or {}
    except Exception as _e:
        return False, f"Invalid template YAML: {_e}"

    post = data.get('postprocessing')
    if not isinstance(post, list) or not post:
        return False, "Template YAML must include a non-empty postprocessing list"

    ensure_template_dir()
    safe = os.path.basename(filename)
    if not safe.endswith(('.yml', '.yaml')):
        safe += '.yml'
    path = os.path.join(TEMPLATE_DIR, safe)
    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        log_info(f"[SIGMA] Saved template file: {safe}")
        return True, safe
    except Exception as _e:
        log_error(f"[SIGMA] Failed to save template file {safe}: {_e}")
        return False, str(_e)


def delete_pipeline_file(filename: str) -> Tuple[bool, str]:
    """
    Delete a saved pipeline YAML by filename.
    Returns (True, filename) or (False, error_message).
    """
    ensure_pipeline_dir()
    safe = os.path.basename(filename)
    path = os.path.join(PIPELINE_DIR, safe)
    if not os.path.isfile(path):
        return False, f"Pipeline not found: {safe}"
    try:
        os.remove(path)
        log_info(f"[SIGMA] Deleted pipeline file: {safe}")
        return True, safe
    except Exception as _e:
        log_error(f"[SIGMA] Failed to delete pipeline file {safe}: {_e}")
        return False, str(_e)


def delete_template_file(filename: str) -> Tuple[bool, str]:
    """
    Delete a saved template YAML by filename.
    Returns (True, filename) or (False, error_message).
    """
    ensure_template_dir()
    safe = os.path.basename(filename)
    path = os.path.join(TEMPLATE_DIR, safe)
    if not os.path.isfile(path):
        return False, f"Template not found: {safe}"
    try:
        os.remove(path)
        log_info(f"[SIGMA] Deleted template file: {safe}")
        return True, safe
    except Exception as _e:
        log_error(f"[SIGMA] Failed to delete template file {safe}: {_e}")
        return False, str(_e)


def build_detection_rule_dict(
    sigma_rule_obj: Dict,
    query: str,
    rule_indices: List[str],
    username: str = '',
) -> Dict:
    """
    Build an Elastic Detection Rule payload dict from a parsed Sigma rule.

    This is the single source of truth for rule serialisation — used by both
    ``convert_sigma_rule`` (kibana_ndjson export/display) and
    ``send_rule_to_siem`` (API deploy).  Keeping one path guarantees that
    the rule the user previews is byte-identical to the rule sent to Elastic.

    Args:
        sigma_rule_obj: Parsed Sigma YAML as a dict
        query: Lucene query string (already transformed, _index stripped)
        rule_indices: Index patterns for the detection rule
        username: Author to stamp on the rule

    Returns:
        Dict ready for ``json.dumps`` or Kibana Detection Rules API POST/PUT
    """
    rule_id = sigma_rule_obj.get('id', str(uuid.uuid4()))
    title = sigma_rule_obj.get('title', 'Untitled Sigma Rule')
    description = sigma_rule_obj.get('description', '')
    level = sigma_rule_obj.get('level', 'medium')

    if not title.upper().startswith('SIGMA'):
        title = f"SIGMA - {title}"

    severity_map = {
        'critical': 'critical', 'high': 'high',
        'medium': 'medium', 'low': 'low', 'informational': 'low',
    }
    risk_map = {'critical': 99, 'high': 73, 'medium': 47, 'low': 21}
    severity = severity_map.get(level, 'medium')
    risk_score = risk_map.get(severity, 47)

    tags = sigma_rule_obj.get('tags', []) or []
    tags = [str(t) for t in tags] if isinstance(tags, list) else []
    if 'Sigma' not in tags:
        tags.append('Sigma')

    payload: Dict = {
        "rule_id": rule_id,
        "name": title,
        "description": description or f"Sigma rule: {title}",
        "severity": severity,
        "risk_score": risk_score,
        "tags": tags,
        "enabled": False,
        "type": "query",
        "query": query,
        "language": "lucene",
        "index": rule_indices,
        "from": "now-6m",
        "to": "now",
        "interval": "5m",
        "actions": [],
        "author": [username] if username else [sigma_rule_obj.get('author', 'Sigma')],
        "license": sigma_rule_obj.get('license', 'DRL'),
        "false_positives": sigma_rule_obj.get('falsepositives', []) or [],
        "references": sigma_rule_obj.get('references', []) or [],
        "max_signals": 100,
        "threat": [],
    }

    tactic_map = {
        'reconnaissance': {'id': 'TA0043', 'name': 'Reconnaissance'},
        'resource_development': {'id': 'TA0042', 'name': 'Resource Development'},
        'resource-development': {'id': 'TA0042', 'name': 'Resource Development'},
        'initial_access': {'id': 'TA0001', 'name': 'Initial Access'},
        'initial-access': {'id': 'TA0001', 'name': 'Initial Access'},
        'execution': {'id': 'TA0002', 'name': 'Execution'},
        'persistence': {'id': 'TA0003', 'name': 'Persistence'},
        'privilege_escalation': {'id': 'TA0004', 'name': 'Privilege Escalation'},
        'privilege-escalation': {'id': 'TA0004', 'name': 'Privilege Escalation'},
        'defense_evasion': {'id': 'TA0005', 'name': 'Defense Evasion'},
        'defense-evasion': {'id': 'TA0005', 'name': 'Defense Evasion'},
        'credential_access': {'id': 'TA0006', 'name': 'Credential Access'},
        'credential-access': {'id': 'TA0006', 'name': 'Credential Access'},
        'discovery': {'id': 'TA0007', 'name': 'Discovery'},
        'lateral_movement': {'id': 'TA0008', 'name': 'Lateral Movement'},
        'lateral-movement': {'id': 'TA0008', 'name': 'Lateral Movement'},
        'collection': {'id': 'TA0009', 'name': 'Collection'},
        'command_and_control': {'id': 'TA0011', 'name': 'Command and Control'},
        'command-and-control': {'id': 'TA0011', 'name': 'Command and Control'},
        'exfiltration': {'id': 'TA0010', 'name': 'Exfiltration'},
        'impact': {'id': 'TA0040', 'name': 'Impact'},
    }

    tactics_found: list = []
    techniques_found: list = []
    for tag in tags:
        if not isinstance(tag, str):
            continue
        tag_lower = tag.lower()
        if tag_lower.startswith('attack.t'):
            m = re.search(r'attack\.t(\d+(?:\.\d+)?)', tag, re.IGNORECASE)
            if m:
                tech_id = f"T{m.group(1).upper()}"
                if tech_id not in techniques_found:
                    techniques_found.append(tech_id)
        elif tag_lower.startswith('attack.'):
            tname = tag_lower.replace('attack.', '')
            if tname in tactic_map and tactic_map[tname] not in tactics_found:
                tactics_found.append(tactic_map[tname])

    for tactic in tactics_found:
        threat_entry: Dict = {
            "framework": "MITRE ATT&CK",
            "tactic": {
                "id": tactic['id'],
                "name": tactic['name'],
                "reference": f"https://attack.mitre.org/tactics/{tactic['id']}/",
            },
            "technique": [
                {
                    "id": tid,
                    "name": tid,
                    "reference": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
                }
                for tid in techniques_found
            ],
        }
        if threat_entry["technique"]:
            payload["threat"].append(threat_entry)

    if techniques_found and not tactics_found:
        for tid in techniques_found:
            payload["threat"].append({
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "id": "TA0002", "name": "Execution",
                    "reference": "https://attack.mitre.org/tactics/TA0002/",
                },
                "technique": [{
                    "id": tid, "name": tid,
                    "reference": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
                }],
            })

    return payload


def send_rule_to_siem(
    yaml_content: str,
    space: str,
    enabled: bool = False,
    index_pattern: Optional[str] = None,
    pipeline_file: str = '',
    template_file: str = '',
    username: str = '',
) -> Tuple[bool, str]:
    """
    Send a Sigma rule to Kibana/Elasticsearch SIEM via the Detection Rules API.

    Unified path: internally calls ``convert_sigma_rule`` with
    ``output_format='kibana_ndjson'`` so preview and deploy are guaranteed to
    produce identical output — no split-brain, no duplicated logic.

    Args:
        yaml_content: Original Sigma rule YAML
        space: Kibana space to deploy to (e.g. ``staging``, ``production``)
        enabled: Whether to enable the rule immediately after creation/update
        index_pattern: Comma-separated index patterns (overrides pipeline)
        pipeline_file: Comma-separated filenames of saved pipelines in PIPELINE_DIR
        username: Username of the deploying user (added to ``author`` field)

    Returns:
        Tuple of (success: bool, message: str)
    """
    import requests

    # ── Re-convert using the exact same code path as the UI preview ────────
    ok, json_str = convert_sigma_rule(
        yaml_content=yaml_content,
        backend='elasticsearch',
        pipeline='none',
        output_format='kibana_ndjson',
        index_pattern=index_pattern or '',
        pipeline_file=pipeline_file,
        template_file=template_file,
    )
    if not ok:
        return False, f"Conversion failed before deploy: {json_str}"

    try:
        payload = json.loads(json_str)
    except json.JSONDecodeError:
        # siem_rule_ndjson can be returned as newline-delimited JSON.
        parsed = None
        for line in [ln.strip() for ln in str(json_str).splitlines() if ln.strip()]:
            try:
                candidate = json.loads(line)
                if isinstance(candidate, dict):
                    parsed = candidate
                    break
            except json.JSONDecodeError:
                continue
        if parsed is None:
            return False, "Failed to parse conversion result as JSON/NDJSON"
        payload = parsed

    # Apply deploy-time overrides
    payload['enabled'] = enabled
    if username:
        payload['author'] = [username]

    title = payload.get('name', 'Unknown Rule')
    rule_id = payload.get('rule_id', '')

    kibana_url = os.getenv('ELASTIC_URL', '')
    api_key = os.getenv('ELASTIC_API_KEY', '')
    if not kibana_url or not api_key:
        return False, "Missing ELASTIC_URL or ELASTIC_API_KEY in environment"

    headers = {
        "kbn-xsrf": "true",
        "Content-Type": "application/json",
        "Authorization": f"ApiKey {api_key}",
    }
    url = f"{kibana_url}/s/{space}/api/detection_engine/rules"

    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        check_response = requests.get(
            f"{url}?rule_id={rule_id}",
            headers=headers,
            verify=False,
            timeout=30,
        )

        if check_response.status_code == 200:
            response = requests.put(
                url, json=payload, headers=headers, verify=False, timeout=30
            )
            action = "updated"
        else:
            response = requests.post(
                url, json=payload, headers=headers, verify=False, timeout=30
            )
            action = "created"
            if response.status_code == 409:
                response = requests.put(
                    url, json=payload, headers=headers, verify=False, timeout=30
                )
                action = "updated"

        if response.status_code in [200, 201]:
            return True, f"Rule '{title}' {action} in {space} space!"
        return False, f"Failed to {action} rule: {response.status_code} - {response.text}"

    except requests.exceptions.RequestException as exc:
        return False, f"Connection error: {exc}"


def get_rule_by_id(rule_id: str) -> Optional[Dict]:
    """Get a specific rule by its ID."""
    rules = load_all_rules()
    for rule in rules:
        if rule.get('id') == rule_id:
            return rule
    return None


def get_all_techniques() -> List[str]:
    """Get all unique MITRE techniques from loaded rules."""
    rules = load_all_rules()
    techniques = set()
    for rule in rules:
        for t in rule.get('_techniques', []):
            techniques.add(t)
    return sorted(list(techniques))
