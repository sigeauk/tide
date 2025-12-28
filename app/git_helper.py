import requests
import yaml
import pandas as pd
import base64
import os
import uuid
from log import log_info, log_error

# --- SCORING (Simplified version of elastic_helper) ---
def calculate_basic_score(rule):
    score = 0
    # 1. Metadata check
    if rule.get('description'): score += 20
    if rule.get('severity'): score += 10
    if rule.get('author'): score += 10
    
    # 2. Logic check
    query = rule.get('query', '') or rule.get('detection', '')
    if query: score += 30
    
    # 3. Threat mapping
    if rule.get('tags') or rule.get('mitre'): score += 20
    
    return min(score, 100)

def fetch_rules(url=None, token=None, project_id=None, branch="main"):
    """
    Fetches rules from a GitLab Repository (Recursive Tree Search).
    """
    base_url = url or os.getenv("GITLAB_URL")
    api_token = token or os.getenv("GITLAB_TOKEN")
    
    # Try to extract project ID from URL if not explicitly provided
    # (Simplified logic, usually better to set GITLAB_PROJECT_ID env var)
    if not project_id:
        project_id = os.getenv("GITLAB_PROJECT_ID")

    if not base_url or not api_token or not project_id:
        log_error("Missing GitLab Config (URL, Token, or Project ID)")
        return pd.DataFrame()

    headers = {"PRIVATE-TOKEN": api_token}
    
    # 1. Get File Tree
    tree_url = f"{base_url.rstrip('/')}/api/v4/projects/{project_id}/repository/tree"
    params = {"recursive": True, "ref": branch, "per_page": 100}
    
    try:
        log_info(f"Scanning GitLab Project {project_id}...")
        res = requests.get(tree_url, headers=headers, params=params, verify=False, timeout=20)
        res.raise_for_status()
        files = res.json()
    except Exception as e:
        log_error(f"GitLab Tree Fetch Failed: {e}")
        return pd.DataFrame()

    parsed_rules = []

    # 2. Iterate and Fetch Rule Content
    for f in files:
        # Look for YAML files in a 'rules' directory or similar
        if f['type'] == 'blob' and (f['path'].endswith('.yml') or f['path'].endswith('.yaml')):
            try:
                # Fetch raw file content
                raw_url = f"{base_url.rstrip('/')}/api/v4/projects/{project_id}/repository/files/{f['path'].replace('/', '%2F')}/raw"
                file_res = requests.get(raw_url, headers=headers, params={"ref": branch}, verify=False)
                
                if file_res.status_code == 200:
                    rule_content = yaml.safe_load(file_res.text)
                    
                    # Basic Validation: Is it a rule?
                    if not isinstance(rule_content, dict): continue
                    
                    # Map to TIDE Schema
                    rule_id = rule_content.get('id') or str(uuid.uuid4())
                    name = rule_content.get('title') or rule_content.get('name') or f['name']
                    
                    # Extract TTPs from tags (e.g., "attack.t1059")
                    tags = rule_content.get('tags', [])
                    mitre_ids = [t.split('.')[-1].upper() for t in tags if 'attack.t' in t]

                    rule_obj = {
                        "rule_id": rule_id,
                        "name": name,
                        "description": rule_content.get('description'),
                        "author_str": rule_content.get('author', 'Unknown'),
                        "severity": rule_content.get('status', 'low'), # Sigma uses status/level
                        "enabled": True,
                        "query": rule_content.get('detection', 'See YAML'),
                        "language": "sigma" if "detection" in rule_content else "yaml",
                        "mitre_ids": mitre_ids,
                        "tactics": "Unknown", # Would need mapping logic
                        "techniques": ", ".join(mitre_ids),
                        "raw_data": rule_content
                    }
                    
                    # Calculate Score
                    rule_obj['score'] = calculate_basic_score(rule_obj)
                    rule_obj['quality_score'] = rule_obj['score'] # Simplified
                    rule_obj['meta_score'] = rule_obj['score'] # Simplified
                    
                    parsed_rules.append(rule_obj)

            except Exception as e:
                log_error(f"Failed to parse {f['path']}: {e}")

    log_info(f"Fetched {len(parsed_rules)} rules from GitLab.")
    return pd.DataFrame(parsed_rules)