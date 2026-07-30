import requests
import os
import json
import pandas as pd
import re
from log import log_info, log_error, log_debug

MITRE_REF_SOURCES = {
    "mitre-attack",
    "mitre-attack-mobile",
    "mitre-attack-ics",
    "mitre-mobile-attack",
    "mitre-ics-attack",
}

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


def _mitre_external_id(stix_obj, prefix):
    """Return first MITRE external_id that starts with prefix."""
    for ref in stix_obj.get("external_references", []) or []:
        source_name = (ref.get("source_name") or "").lower()
        external_id = (ref.get("external_id") or "").strip().upper()
        if source_name in MITRE_REF_SOURCES and external_id.startswith(prefix):
            return external_id
    return None


def _mitre_ref_url(stix_obj):
    """Return first MITRE URL from external references."""
    for ref in stix_obj.get("external_references", []) or []:
        source_name = (ref.get("source_name") or "").lower()
        url = (ref.get("url") or "").strip()
        if source_name in MITRE_REF_SOURCES and url:
            return url
    return ""

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
    knowledge = process_mitre_knowledge(bundle_data)
    techniques = knowledge.get("techniques", pd.DataFrame())
    if techniques.empty:
        return pd.DataFrame()
    return techniques[["technique_id", "technique_name", "tactic", "url"]].copy()


def process_mitre_knowledge(bundle_data, source_name="unknown"):
    """Extract MITRE entities and edges required for offline ATT&CK pages."""
    if not bundle_data or "objects" not in bundle_data:
        return {
            "techniques": pd.DataFrame(),
            "tactics": pd.DataFrame(),
            "groups": pd.DataFrame(),
            "mitigations": pd.DataFrame(),
            "software": pd.DataFrame(),
            "campaigns": pd.DataFrame(),
            "group_techniques": pd.DataFrame(),
            "group_software": pd.DataFrame(),
            "technique_tactics": pd.DataFrame(),
            "technique_mitigations": pd.DataFrame(),
            "software_techniques": pd.DataFrame(),
            "campaign_techniques": pd.DataFrame(),
            "campaign_software": pd.DataFrame(),
            "campaign_groups": pd.DataFrame(),
        }

    domain = str(source_name or "unknown").strip().lower()
    objects = bundle_data.get("objects") or []

    tactics_by_stix = {}
    tactics_by_shortname = {}
    techniques_by_stix = {}
    groups_by_stix = {}
    mitigations_by_stix = {}
    software_by_stix = {}
    campaigns_by_stix = {}
    relationships = []

    for obj in objects:
        obj_type = obj.get("type")
        obj_id = obj.get("id")
        if not obj_id:
            continue
        if obj.get("revoked") is True or obj.get("x_mitre_deprecated") is True:
            continue

        if obj_type == "x-mitre-tactic":
            tactic_id = _mitre_external_id(obj, "TA")
            shortname = (obj.get("x_mitre_shortname") or "").strip().lower()
            if tactic_id:
                tactic_row = {
                    "stix_id": obj_id,
                    "tactic_id": tactic_id,
                    "name": obj.get("name") or tactic_id,
                    "shortname": shortname,
                    "description": obj.get("description") or "",
                    "domain": domain,
                    "url": f"/mitre/tactic?id={tactic_id}",
                }
                tactics_by_stix[obj_id] = tactic_row
                if shortname:
                    tactics_by_shortname[shortname] = tactic_row

        elif obj_type == "attack-pattern":
            technique_id = _mitre_external_id(obj, "T")
            if technique_id:
                kill_chain_phases = [
                    (phase.get("phase_name") or "").strip().lower()
                    for phase in (obj.get("kill_chain_phases") or [])
                    if (phase.get("kill_chain_name") or "").strip().lower() == "mitre-attack"
                ]
                techniques_by_stix[obj_id] = {
                    "stix_id": obj_id,
                    "technique_id": technique_id,
                    "technique_name": obj.get("name") or technique_id,
                    "description": obj.get("description") or "",
                    "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
                    "kill_chain_phases": kill_chain_phases,
                    "domain": domain,
                    "url": f"/mitre/technique/{technique_id}",
                }

        elif obj_type == "intrusion-set":
            group_id = _mitre_external_id(obj, "G")
            if group_id:
                groups_by_stix[obj_id] = {
                    "stix_id": obj_id,
                    "group_id": group_id,
                    "name": obj.get("name") or group_id,
                    "aliases": ", ".join(obj.get("aliases", []) or []),
                    "description": obj.get("description") or "",
                    "domain": domain,
                    "url": f"/mitre/groups/{group_id}",
                }

        elif obj_type == "course-of-action":
            mitigation_id = _mitre_external_id(obj, "M")
            if mitigation_id:
                mitigations_by_stix[obj_id] = {
                    "stix_id": obj_id,
                    "mitigation_id": mitigation_id,
                    "name": obj.get("name") or mitigation_id,
                    "description": obj.get("description") or "",
                    "domain": domain,
                    "url": _mitre_ref_url(obj),
                }

        elif obj_type in {"malware", "tool"}:
            software_id = _mitre_external_id(obj, "S")
            if software_id:
                software_by_stix[obj_id] = {
                    "stix_id": obj_id,
                    "software_id": software_id,
                    "name": obj.get("name") or software_id,
                    "description": obj.get("description") or "",
                    "software_type": str(obj_type or "").upper(),
                    "platforms": ", ".join(obj.get("x_mitre_platforms", []) or []),
                    "domain": domain,
                    "url": f"/mitre/software/{software_id}",
                }

        elif obj_type == "campaign":
            campaign_id = _mitre_external_id(obj, "C")
            if campaign_id:
                campaigns_by_stix[obj_id] = {
                    "stix_id": obj_id,
                    "campaign_id": campaign_id,
                    "name": obj.get("name") or campaign_id,
                    "description": obj.get("description") or "",
                    "first_seen": (obj.get("first_seen") or ""),
                    "last_seen": (obj.get("last_seen") or ""),
                    "domain": domain,
                    "url": f"/mitre/campaigns/{campaign_id}",
                }

        elif obj_type == "relationship":
            relationships.append(obj)

    technique_tactics = []
    for technique in techniques_by_stix.values():
        for shortname in technique.get("kill_chain_phases", []):
            tactic = tactics_by_shortname.get(shortname)
            if not tactic:
                continue
            technique_tactics.append({
                "technique_stix_id": technique["stix_id"],
                "tactic_stix_id": tactic["stix_id"],
                "technique_id": technique["technique_id"],
                "tactic_id": tactic["tactic_id"],
                "domain": domain,
            })

    group_techniques = []
    group_software = []
    technique_mitigations = []
    software_techniques = []
    campaign_techniques = []
    campaign_software = []
    campaign_groups = []
    group_associations = []
    for rel in relationships:
        rel_type = (rel.get("relationship_type") or "").strip().lower()
        source_ref = rel.get("source_ref")
        target_ref = rel.get("target_ref")
        rel_desc = (rel.get("description") or "").strip()
        if rel_type == "uses" and source_ref in groups_by_stix and target_ref in techniques_by_stix:
            group = groups_by_stix[source_ref]
            technique = techniques_by_stix[target_ref]
            group_techniques.append({
                "group_stix_id": group["stix_id"],
                "technique_stix_id": technique["stix_id"],
                "group_id": group["group_id"],
                "technique_id": technique["technique_id"],
                "domain": domain,
                "use_description": rel_desc,
            })
        elif rel_type == "uses" and source_ref in groups_by_stix and target_ref in software_by_stix:
            group = groups_by_stix[source_ref]
            software = software_by_stix[target_ref]
            group_software.append({
                "group_stix_id": group["stix_id"],
                "software_stix_id": software["stix_id"],
                "group_id": group["group_id"],
                "software_id": software["software_id"],
                "domain": domain,
                "use_description": rel_desc,
            })
        elif rel_type == "mitigates" and source_ref in mitigations_by_stix and target_ref in techniques_by_stix:
            mitigation = mitigations_by_stix[source_ref]
            technique = techniques_by_stix[target_ref]
            technique_mitigations.append({
                "technique_stix_id": technique["stix_id"],
                "mitigation_stix_id": mitigation["stix_id"],
                "technique_id": technique["technique_id"],
                "mitigation_id": mitigation["mitigation_id"],
                "domain": domain,
            })
        elif rel_type == "uses" and source_ref in software_by_stix and target_ref in techniques_by_stix:
            software = software_by_stix[source_ref]
            technique = techniques_by_stix[target_ref]
            software_techniques.append({
                "software_stix_id": software["stix_id"],
                "technique_stix_id": technique["stix_id"],
                "software_id": software["software_id"],
                "technique_id": technique["technique_id"],
                "domain": domain,
                "use_description": rel_desc,
            })
        elif rel_type == "uses" and source_ref in campaigns_by_stix and target_ref in techniques_by_stix:
            campaign = campaigns_by_stix[source_ref]
            technique = techniques_by_stix[target_ref]
            campaign_techniques.append({
                "campaign_stix_id": campaign["stix_id"],
                "technique_stix_id": technique["stix_id"],
                "campaign_id": campaign["campaign_id"],
                "technique_id": technique["technique_id"],
                "domain": domain,
                "use_description": rel_desc,
            })
        elif rel_type == "uses" and source_ref in campaigns_by_stix and target_ref in software_by_stix:
            campaign = campaigns_by_stix[source_ref]
            software = software_by_stix[target_ref]
            campaign_software.append({
                "campaign_stix_id": campaign["stix_id"],
                "software_stix_id": software["stix_id"],
                "campaign_id": campaign["campaign_id"],
                "software_id": software["software_id"],
                "domain": domain,
                "use_description": rel_desc,
            })
        elif rel_type in {"attributed-to", "uses"} and source_ref in campaigns_by_stix and target_ref in groups_by_stix:
            campaign = campaigns_by_stix[source_ref]
            group = groups_by_stix[target_ref]
            campaign_groups.append({
                "campaign_stix_id": campaign["stix_id"],
                "group_stix_id": group["stix_id"],
                "campaign_id": campaign["campaign_id"],
                "group_id": group["group_id"],
                "domain": domain,
                "description": rel_desc,
            })
        elif rel_type in {"related-to", "attributed-to"} and source_ref in groups_by_stix and target_ref in groups_by_stix:
            src_group = groups_by_stix[source_ref]
            dst_group = groups_by_stix[target_ref]
            group_associations.append({
                "group_stix_id": src_group["stix_id"],
                "associated_group_stix_id": dst_group["stix_id"],
                "group_id": src_group["group_id"],
                "associated_group_id": dst_group["group_id"],
                "domain": domain,
                "description": rel_desc,
            })

    techniques_rows = []
    for technique in techniques_by_stix.values():
        tactics = technique.get("kill_chain_phases") or []
        primary_tactic = tactics[0] if tactics else "unknown"
        techniques_rows.append({
            "stix_id": technique["stix_id"],
            "technique_id": technique["technique_id"],
            "technique_name": technique["technique_name"],
            "description": technique["description"],
            "is_subtechnique": technique["is_subtechnique"],
            "tactic": primary_tactic,
            "domain": domain,
            "url": technique["url"],
        })

    return {
        "techniques": pd.DataFrame(techniques_rows),
        "tactics": pd.DataFrame(list(tactics_by_stix.values())),
        "groups": pd.DataFrame(list(groups_by_stix.values())),
        "mitigations": pd.DataFrame(list(mitigations_by_stix.values())),
        "software": pd.DataFrame(list(software_by_stix.values())),
        "campaigns": pd.DataFrame(list(campaigns_by_stix.values())),
        "group_techniques": pd.DataFrame(group_techniques),
        "group_software": pd.DataFrame(group_software),
        "technique_tactics": pd.DataFrame(technique_tactics),
        "technique_mitigations": pd.DataFrame(technique_mitigations),
        "software_techniques": pd.DataFrame(software_techniques),
        "campaign_techniques": pd.DataFrame(campaign_techniques),
        "campaign_software": pd.DataFrame(campaign_software),
        "campaign_groups": pd.DataFrame(campaign_groups),
        "group_associations": pd.DataFrame(group_associations),
    }

def get_threat_landscape(api_url, api_token):
    """
    Fetches Intrusion Sets and their TTPs from OpenCTI via GraphQL.
    Paginates through all results.
    Returns a DataFrame compatible with database.save_threat_data().
    """
    if not api_url or not api_token:
        log_error("OpenCTI Config missing")
        return pd.DataFrame()

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    # Paginated query for Actors AND their 'uses' relationships to Attack Patterns
    query = """
    query ThreatActors($cursor: ID, $count: Int!) {
      intrusionSets(first: $count, after: $cursor) {
        edges {
          node {
            name
            description
            aliases
            stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Attack-Pattern"]
              first: 500
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
          cursor
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
    """

    try:
        base_url = api_url.rstrip('/')
        log_info(f"Connecting to OpenCTI at {base_url}...")
        
        actors = []
        cursor = None
        page_size = 200
        
        while True:
            variables = {"count": page_size, "cursor": cursor}
            response = requests.post(
                f"{base_url}/graphql",
                json={'query': query, 'variables': variables},
                headers=headers,
                timeout=60
            )
            
            if response.status_code != 200:
                log_error(f"OpenCTI API Error {response.status_code}: {response.text}")
                break

            data = response.json()
            if "errors" in data:
                log_error(f"GraphQL Error: {data['errors']}")
                break

            intrusion_data = data.get("data", {}).get("intrusionSets", {})
            edges = intrusion_data.get("edges", [])
            
            if not edges:
                break
            
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
                    "ttps": list(set(ttps)),
                    "ttp_count": len(set(ttps)),
                    "source": "OCTI"
                })
            
            # Check for next page
            page_info = intrusion_data.get("pageInfo", {})
            if page_info.get("hasNextPage") and page_info.get("endCursor"):
                cursor = page_info["endCursor"]
                log_debug(f"  Fetched {len(actors)} actors so far, getting next page...")
            else:
                break

        log_info(f"Fetched {len(actors)} Threat Actors from OpenCTI")
        return pd.DataFrame(actors)

    except Exception as e:
        log_error(f"OpenCTI Sync Failed: {e}")
        return pd.DataFrame()