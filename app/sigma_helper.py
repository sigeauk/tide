import os
import yaml
import re
import subprocess
import uuid
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from log import log_info, log_error, log_debug
from dotenv import load_dotenv

load_dotenv()

# Sigma repository paths - check /opt/repos first (Docker), then fallback locations
SIGMA_REPO_PATH = os.getenv('SIGMA_REPO_PATH', '/opt/repos/sigma')
SIGMA_REPO_URL = os.getenv('SIGMA_REPO_URL', 'https://github.com/SigmaHQ/sigma.git')

# Cache for loaded rules
_rules_cache: Optional[List[Dict]] = None
_repo_initialized: bool = False


def ensure_sigma_repo() -> str:
    """Ensure Sigma repo exists, clone if needed. Returns path to rules."""
    global _repo_initialized
    
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
    
    # No repo found - try to clone
    if not _repo_initialized:
        _repo_initialized = True
        clone_path = '/opt/repos/sigma' if os.path.exists('/opt') else os.path.join(os.getcwd(), 'repos', 'sigma')
        
        try:
            log_info(f"[SIGMA] Cloning Sigma repo to {clone_path}...")
            os.makedirs(os.path.dirname(clone_path), exist_ok=True)
            subprocess.run(
                ['git', 'clone', '--depth', '1', SIGMA_REPO_URL, clone_path],
                check=True,
                capture_output=True,
                timeout=300
            )
            rules_path = os.path.join(clone_path, 'rules')
            if os.path.exists(rules_path):
                log_info(f"[SIGMA] Successfully cloned repo, rules at: {rules_path}")
                return rules_path
        except Exception as e:
            log_error(f"[SIGMA] Failed to clone repo: {e}")
    
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
    formats = {
        'elasticsearch': {
            'default': 'Default Query',
            'kibana_ndjson': 'Kibana NDJSON',
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
    output_format: str = 'default'
) -> Tuple[bool, str]:
    """
    Convert a Sigma rule to a target query language.
    
    Args:
        yaml_content: The Sigma rule YAML content
        backend: Target backend (elasticsearch, splunk, etc.)
        pipeline: Processing pipeline to use
        output_format: Output format for the backend
    
    Returns:
        Tuple of (success: bool, result: str)
    """
    try:
        from sigma.rule import SigmaRule
        from sigma.collection import SigmaCollection
        
        # Parse the Sigma rule
        rule = SigmaRule.from_yaml(yaml_content)
        collection = SigmaCollection([rule])
        
        # Get the appropriate backend
        if backend == 'elasticsearch':
            from sigma.backends.elasticsearch import LuceneBackend
            sigma_backend = LuceneBackend()
        elif backend == 'eql':
            from sigma.backends.elasticsearch import EqlBackend
            sigma_backend = EqlBackend()
        elif backend == 'esql':
            from sigma.backends.elasticsearch import ESQLBackend
            sigma_backend = ESQLBackend()
        elif backend == 'splunk':
            from sigma.backends.splunk import SplunkBackend
            sigma_backend = SplunkBackend()
        elif backend == 'microsoft365defender':
            from sigma.backends.microsoft365defender import Microsoft365DefenderBackend
            sigma_backend = Microsoft365DefenderBackend()
        else:
            return False, f"Unknown backend: {backend}"
        
        # Apply pipeline if specified
        processing_pipeline = None
        if pipeline and pipeline != 'none':
            if pipeline == 'sysmon':
                from sigma.pipelines.sysmon import sysmon_pipeline
                processing_pipeline = sysmon_pipeline()
            elif pipeline == 'windows':
                from sigma.pipelines.windows import windows_pipeline
                processing_pipeline = windows_pipeline()
            elif pipeline == 'windows-audit':
                from sigma.pipelines.windows import windows_audit_pipeline
                processing_pipeline = windows_audit_pipeline()
            elif pipeline == 'ecs_windows':
                try:
                    from sigma.pipelines.elasticsearch import ecs_windows
                    processing_pipeline = ecs_windows()
                except ImportError:
                    pass
        
        # Apply pipeline to backend if available
        if processing_pipeline:
            sigma_backend = sigma_backend.__class__(processing_pipeline=processing_pipeline)
        
        # Convert the rule with specified format
        if output_format and output_format != 'default':
            try:
                result = sigma_backend.convert(collection, output_format)
            except TypeError:
                # Some backends don't support output_format parameter
                result = sigma_backend.convert(collection)
        else:
            result = sigma_backend.convert(collection)
        
        if isinstance(result, list):
            result = '\n\n'.join(str(r) for r in result)
        
        return True, str(result)
        
    except Exception as e:
        return False, f"Conversion error: {str(e)}"


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


def send_rule_to_siem(
    yaml_content: str,
    query: str,
    space: str,
    enabled: bool = False
) -> Tuple[bool, str]:
    """
    Send a converted Sigma rule to Kibana/Elasticsearch SIEM.
    
    Args:
        yaml_content: Original Sigma rule YAML
        query: Converted query string
        space: Kibana space to send to
        enabled: Whether to enable the rule
    
    Returns:
        Tuple of (success: bool, message: str)
    """
    import requests
    import yaml as pyyaml
    
    # Get Elastic/Kibana config
    kibana_url = os.getenv('ELASTIC_URL', '')
    api_key = os.getenv('ELASTIC_API_KEY', '')
    
    if not kibana_url or not api_key:
        return False, "Missing ELASTIC_URL or ELASTIC_API_KEY in environment"
    
    # Parse the Sigma rule to extract metadata
    try:
        sigma_rule = pyyaml.safe_load(yaml_content)
    except Exception as e:
        return False, f"Failed to parse Sigma YAML: {e}"
    
    # Build the Kibana detection rule payload
    rule_id = sigma_rule.get('id', str(uuid.uuid4()))
    title = sigma_rule.get('title', 'Untitled Sigma Rule')
    description = sigma_rule.get('description', '')
    level = sigma_rule.get('level', 'medium')
    
    # Prefix title with SIGMA - for easy identification in SIEM
    if not title.upper().startswith('SIGMA'):
        title = f"SIGMA - {title}"
    
    # Map Sigma severity to Kibana severity
    severity_map = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'informational': 'low'
    }
    severity = severity_map.get(level, 'medium')
    
    # Map severity to risk score
    risk_map = {
        'critical': 99,
        'high': 73,
        'medium': 47,
        'low': 21
    }
    risk_score = risk_map.get(severity, 47)
    
    # Extract tags
    tags = sigma_rule.get('tags', []) or []
    if isinstance(tags, list):
        tags = [str(t) for t in tags]
    else:
        tags = []
    
    # Add Sigma tag
    if 'Sigma' not in tags:
        tags.append('Sigma')
    
    # Build the rule payload
    payload = {
        "rule_id": rule_id,
        "name": title,
        "description": description or f"Sigma rule: {title}",
        "severity": severity,
        "risk_score": risk_score,
        "tags": tags,
        "enabled": enabled,
        "type": "query",
        "query": query,
        "language": "lucene",
        "index": ["logs-*", "winlogbeat-*", "filebeat-*"],
        "from": "now-6m",
        "to": "now",
        "interval": "5m",
        "actions": [],
        "author": [sigma_rule.get('author', 'Sigma')],
        "license": sigma_rule.get('license', 'DRL'),
        "false_positives": sigma_rule.get('falsepositives', []) or [],
        "references": sigma_rule.get('references', []) or [],
        "max_signals": 100,
        "threat": []
    }
    
    # Build MITRE threat mapping
    for tag in tags:
        if isinstance(tag, str) and tag.startswith('attack.t'):
            # Extract technique ID
            import re
            match = re.search(r'attack\.t(\d+(?:\.\d+)?)', tag, re.IGNORECASE)
            if match:
                tech_id = f"T{match.group(1)}"
                payload["threat"].append({
                    "framework": "MITRE ATT&CK",
                    "tactic": {
                        "id": "TA0001",  # Default tactic
                        "name": "Unknown",
                        "reference": "https://attack.mitre.org/tactics/TA0001/"
                    },
                    "technique": [{
                        "id": tech_id,
                        "name": title,
                        "reference": f"https://attack.mitre.org/techniques/{tech_id}/"
                    }]
                })
    
    # Send to Kibana
    headers = {
        "kbn-xsrf": "true",
        "Content-Type": "application/json",
        "Authorization": f"ApiKey {api_key}"
    }
    
    url = f"{kibana_url}/s/{space}/api/detection_engine/rules"
    
    try:
        # Suppress SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # First check if rule already exists by fetching it
        check_response = requests.get(
            f"{url}?rule_id={rule_id}",
            headers=headers,
            verify=False,
            timeout=30
        )
        
        rule_exists = check_response.status_code == 200
        
        if rule_exists:
            # Update existing rule with PUT
            response = requests.put(
                url,
                json=payload,
                headers=headers,
                verify=False,
                timeout=30
            )
            if response.status_code in [200, 201]:
                return True, f"✅ Rule '{title}' updated in {space} space!"
            else:
                return False, f"Failed to update rule: {response.status_code} - {response.text}"
        else:
            # Create new rule with POST
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                verify=False,
                timeout=30
            )
            if response.status_code in [200, 201]:
                return True, f"✅ Rule '{title}' created in {space} space successfully!"
            elif response.status_code == 409:
                # Rule already exists (conflict), try update
                response = requests.put(
                    url,
                    json=payload,
                    headers=headers,
                    verify=False,
                    timeout=30
                )
                if response.status_code in [200, 201]:
                    return True, f"✅ Rule '{title}' updated in {space} space!"
                else:
                    return False, f"Failed to update rule: {response.status_code} - {response.text}"
            else:
                return False, f"Failed to create rule: {response.status_code} - {response.text}"
            
    except requests.exceptions.RequestException as e:
        return False, f"Connection error: {str(e)}"


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
