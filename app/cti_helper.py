import requests
import os
import json
import pandas as pd
import re
from log import log_info, log_error, log_debug

# --- ISO COUNTRY MAPPING ---
ISO_MAP = {
    "RU": "ru", "RUSSIA": "ru", "RUSSIAN": "ru", "USSR": "ru",
    "TURLA": "ru", "VENOMOUS BEAR": "ru", "WATERBUG": "ru", "IRON HUNTER": "ru",
    "APT28": "ru", "FANCY BEAR": "ru", "APT29": "ru", "COZY BEAR": "ru",
    "NOBELIUM": "ru", "SANDWORM": "ru", "DRAGONFLY": "ru", "WIZARD SPIDER": "ru",
    "GAMAREDON": "ru", "PRIMITIVE BEAR": "ru",
    
    "CN": "cn", "CHINA": "cn", "CHINESE": "cn", "PRC": "cn",
    "APT41": "cn", "WICKED PANDA": "cn", "APT40": "cn", "MUSTANG PANDA": "cn",
    "HAFNIUM": "cn", "APT31": "cn", "APT10": "cn", "STONE PANDA": "cn",
    "APT27": "cn", "EMISSARY PANDA": "cn", "WINNTI": "cn",
    "VOLT TYPHOON": "cn", "BRONZE SILHOUETTE": "cn", "MALLARDSPIDER": "cn",
    
    "KP": "kp", "NORTH KOREA": "kp", "DPRK": "kp", "PYONGYANG": "kp",
    "LAZARUS": "kp", "HIDDEN COBRA": "kp", "KIMSUKY": "kp", "VELVET CHOLLIMA": "kp",
    "ANDARIEL": "kp", "SILENT CHOLLIMA": "kp", "ONYX SLEET": "kp", "PLUTONIUM": "kp",
    "APT37": "kp", "RICOCHET CHOLLIMA": "kp", "SCARCRUFT": "kp", "INKYSQUID": "kp",
    
    "IR": "ir", "IRAN": "ir", "IRANIAN": "ir",
    "APT33": "ir", "ELFIN": "ir", "APT34": "ir", "OILRIG": "ir",
    "MUDDYWATER": "ir", "APT35": "ir", "CHARMING KITTEN": "ir",
    
    "VN": "vn", "VIETNAM": "vn", "OCEANLOTUS": "vn", "APT32": "vn",
    "IN": "in", "INDIA": "in", "SIDEWINDER": "in", "PATCHWORK": "in",
    "PK": "pk", "PAKISTAN": "pk", "TRANSPARENT TRIBE": "pk",
    "IL": "il", "ISRAEL": "il", "UNIT 8200": "il",
    "KR": "kr", "SOUTH KOREA": "kr", "DARKHOTEL": "kr",

    "US": "us", "USA": "us", "EQUATION GROUP": "us", "UNC3658": "us",
    "SCATTERED SPIDER": "us", "OCTO TEMPEST": "us", "0KTAPUS": "us",
}

def get_iso_code(text):
    if not text: return None
    text_search = str(text).upper()
    sorted_keywords = sorted(ISO_MAP.keys(), key=len, reverse=True)
    for keyword in sorted_keywords:
        pattern = r'\b' + re.escape(keyword) + r'\b'
        if re.search(pattern, text_search):
            return ISO_MAP[keyword]
    return None

# --- MITRE / STIX FETCHERS ---

def fetch_stix_data(source=None):
    """
    Fetches STIX data from a local file only (no URL support).
    Handles files that may contain multiple JSON objects or have extra data.
    """
    if not source or not os.path.isfile(source):
        log_error(f"Invalid or missing file path: {source}")
        return None
    try:
        with open(source, "r", encoding="utf-8") as f:
            content = f.read().strip()
            
        # Try to parse as single JSON first
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            if "Extra data" in str(e):
                # File might contain multiple JSON objects - try to parse the first one
                log_debug(f"File contains extra data, attempting to parse first JSON object from {source}")
                try:
                    # Find the end of the first JSON object
                    brace_count = 0
                    in_string = False
                    escape_next = False
                    end_pos = 0
                    
                    for i, char in enumerate(content):
                        if escape_next:
                            escape_next = False
                            continue
                        
                        if char == '\\':
                            escape_next = True
                            continue
                        
                        if char == '"' and not escape_next:
                            in_string = not in_string
                            continue
                        
                        if not in_string:
                            if char == '{':
                                brace_count += 1
                            elif char == '}':
                                brace_count -= 1
                                if brace_count == 0:
                                    end_pos = i + 1
                                    break
                    
                    if end_pos > 0:
                        first_json = content[:end_pos].strip()
                        return json.loads(first_json)
                    else:
                        raise e
                except:
                    log_error(f"Failed to parse first JSON object from {source}: {e}")
                    return None
            else:
                raise e
                
    except json.JSONDecodeError as e:
        log_error(f"Failed to parse JSON from file {source}: {e}")
        return None
    except Exception as e:
        log_error(f"Failed to load STIX data from file {source}: {e}")
        return None

def process_stix_bundle(bundle_data, source_name="unknown"):
    """
    Parses STIX bundle to extract Actors AND their TTPs via relationships.
    Adds a 'source' field based on the filename.
    """
    if not bundle_data or 'objects' not in bundle_data:
        return pd.DataFrame()

    technique_map = {} 
    actor_map = {}
    relationships = []

    for obj in bundle_data['objects']:
        obj_type = obj.get('type')
        obj_id = obj.get('id')

        if obj_type == 'attack-pattern':
            mitre_id = None
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    mitre_id = ref.get('external_id')
                    break
            if mitre_id:
                technique_map[obj_id] = mitre_id

        elif obj_type == 'intrusion-set':
            actor_map[obj_id] = {
                "name": obj.get('name'),
                "description": obj.get('description', ''),
                "aliases": ", ".join(obj.get('aliases', [])),
                "origin": get_iso_code(obj.get('description', '')) or get_iso_code(obj.get('name', '')), 
                "ttps": [], 
                "source": f"MITRE: {source_name}",  # Added source field
                "id": obj_id
            }

        elif obj_type == 'relationship' and obj.get('relationship_type') == 'uses':
            relationships.append(obj)

    # Link Actors to Techniques via Relationships
    for rel in relationships:
        source = rel.get('source_ref')
        target = rel.get('target_ref')

        if source in actor_map and target in technique_map:
            t_code = technique_map[target]
            if t_code not in actor_map[source]['ttps']:
                actor_map[source]['ttps'].append(t_code)

    return pd.DataFrame(list(actor_map.values()))

def process_mitre_definitions(bundle_data):
    """
    Extracts technique definitions. 
    Maintains RAW slug format (e.g. 'defense-evasion') so UI maps work correctly.
    """
    definitions = []
    if not bundle_data or 'objects' not in bundle_data:
        return pd.DataFrame()
        
    for obj in bundle_data['objects']:
        if obj.get('type') == 'attack-pattern':
            mitre_id = ""
            for ext_ref in obj.get('external_references', []):
                if ext_ref.get('source_name') == 'mitre-attack':
                    mitre_id = ext_ref.get('external_id')
                    break
            
            if mitre_id:
                # Get raw tactic slug (e.g., 'defense-evasion')
                # We do NOT convert to Title Case here, because heatmap.py expects the slug.
                raw_tactic = 'unknown'
                if obj.get('kill_chain_phases'):
                    raw_tactic = obj.get('kill_chain_phases')[0].get('phase_name', 'unknown')

                definitions.append({
                    "technique_id": mitre_id,
                    "technique_name": obj.get('name'),
                    "tactic": raw_tactic, 
                    "url": f"https://attack.mitre.org/techniques/{mitre_id}"
                })
                
    return pd.DataFrame(definitions)

def get_threat_landscape(api_url, api_token):
    """
    Fetches Intrusion Sets and their TTPs from OpenCTI via GraphQL.
    Returns a DataFrame compatible with database.save_threat_data().
    """
    if not api_url or not api_token:
        log_error("OpenCTI Config missing")
        return pd.DataFrame()

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    # Query for Actors AND their 'uses' relationships to Attack Patterns
    query = """
    query ThreatActors {
      intrusionSets(first: 200) {
        edges {
          node {
            name
            description
            aliases
            stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Attack-Pattern"]
              first: 100
            ) {
              edges {
                node {
                  to {
                    ... on AttackPattern {
                      x_mitre_id
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    """

    try:
        log_info(f"Connecting to OpenCTI at {api_url}...")
        response = requests.post(f"{api_url}/graphql", json={'query': query}, headers=headers, timeout=30)
        
        if response.status_code != 200:
            log_error(f"OpenCTI API Error {response.status_code}: {response.text}")
            return pd.DataFrame()

        data = response.json()
        if "errors" in data:
            log_error(f"GraphQL Error: {data['errors']}")
            return pd.DataFrame()

        actors = []
        # Parse the nested GraphQL response
        edges = data.get("data", {}).get("intrusionSets", {}).get("edges", [])
        
        for edge in edges:
            node = edge.get("node", {})
            name = node.get("name")
            desc = node.get("description") or ""
            aliases = ", ".join(node.get("aliases") or [])
            
            # Extract TTPs from nested relationships
            ttps = []
            rel_edges = node.get("stixCoreRelationships", {}).get("edges", [])
            for rel in rel_edges:
                target = rel.get("node", {}).get("to", {})
                mitre_id = target.get("x_mitre_id")
                if mitre_id:
                    ttps.append(mitre_id)

            actors.append({
                "name": name,
                "description": desc,
                "aliases": aliases,
                "origin": get_iso_code(desc) or get_iso_code(name) or "unknown",
                "ttps": list(set(ttps)), # Unique IDs
                "ttp_count": len(set(ttps)),
                "source": "OpenCTI"
            })

        log_info(f"✅ Fetched {len(actors)} Threat Actors from OpenCTI")
        return pd.DataFrame(actors)

    except Exception as e:
        log_error(f"OpenCTI Sync Failed: {e}")
        return pd.DataFrame()