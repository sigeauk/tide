"""
inventory_engine.py - Asset Inventory & CVE Mapping Engine (Phase 2: Enterprise)
"""
from __future__ import annotations
import json, logging, os, re, shutil, xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple
import threading
from app.config import get_settings
from app.models.inventory import (
    AffectedHost, CveMatch, CveOverviewStats, Host, HostCreate, HostSummary,
    HostUpdate, InventoryStats, MitreTechnique, SoftwareCreate, SoftwareInventory,
    SoftwareUpdate, System, SystemCreate, SystemSummary, SystemUpdate, VulnDetection,
)
logger = logging.getLogger(__name__)

def _get_conn():
    from app.services.database import get_database_service
    return get_database_service().get_connection()

def _row_to_system(r):
    return System(id=r[0], name=r[1], description=r[2], created_at=r[3], updated_at=r[4],
                  classification=r[5] if len(r) > 5 else None)

def _row_to_host(r):
    return Host(id=r[0], system_id=r[1], name=r[2], ip_address=r[3],
                os=r[4], hardware_vendor=r[5], model=r[6], source=r[7], created_at=r[8])

def _row_to_software(r):
    return SoftwareInventory(id=r[0], host_id=r[1], system_id=r[2], name=r[3],
                             version=r[4], vendor=r[5], cpe=r[6], source=r[7], created_at=r[8])

def _load_cisa_kev():
    settings = get_settings()
    for path in [settings.cisa_kev_override_path, settings.cisa_kev_path]:
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                    return data.get("vulnerabilities", data if isinstance(data, list) else [])
            except Exception as exc:
                logger.warning(f"Failed to load CISA KEV from {path}: {exc}")
    logger.warning("No CISA KEV file available.")
    return []

_mitre_cve_map_cache: Optional[Dict] = None
_mitre_cve_map_loaded: bool = False

def _load_mitre_cve_map():
    global _mitre_cve_map_cache, _mitre_cve_map_loaded
    if _mitre_cve_map_loaded:
        return _mitre_cve_map_cache or {}
    for p in ["/app/data/attack-to-cve.json", "/opt/repos/mappings/attack-to-cve.json"]:
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as fh:
                    raw = json.load(fh)
                if not raw:
                    _mitre_cve_map_loaded = True
                    _mitre_cve_map_cache = {}
                    return {}
                first_key = next(iter(raw))
                if first_key.upper().startswith("CVE-"):
                    _mitre_cve_map_cache = {k.upper(): v for k, v in raw.items()}
                else:
                    inverted = {}
                    for tid, cve_list in raw.items():
                        for cve_id in cve_list:
                            inverted.setdefault(cve_id.upper(), [])
                            if tid not in inverted[cve_id.upper()]:
                                inverted[cve_id.upper()].append(tid)
                    _mitre_cve_map_cache = inverted
                _mitre_cve_map_loaded = True
                return _mitre_cve_map_cache
            except Exception as exc:
                logger.warning(f"Failed to load MITRE CVE map from {p}: {exc}")
                _mitre_cve_map_loaded = True   # don't retry on every call
                _mitre_cve_map_cache = {}
                return {}
    _mitre_cve_map_loaded = True
    _mitre_cve_map_cache = {}
    return {}

_TECHNIQUE_NAMES = {
    "T1190": "Exploit Public-Facing Application", "T1059": "Command and Scripting Interpreter",
    "T1059.007": "JavaScript", "T1499": "Endpoint Denial of Service",
    "T1499.004": "Application or System Exploitation", "T1558": "Steal or Forge Kerberos Tickets",
    "T1558.003": "Kerberoasting", "T1110": "Brute Force",
    "T1203": "Exploitation for Client Execution", "T1068": "Exploitation for Privilege Escalation",
    "T1210": "Exploitation of Remote Services", "T1133": "External Remote Services",
    "T1505.003": "Web Shell",
}

def _get_covered_techniques(technique_ids):
    coverage = {}
    try:
        with _get_conn() as conn:
            for t_id in technique_ids:
                row = conn.execute(
                    "SELECT COUNT(*) FROM detection_rules WHERE list_contains(mitre_ids, ?)",
                    [t_id]).fetchone()
                coverage[t_id] = int(row[0]) if row else 0
    except Exception as exc:
        logger.warning(f"Failed to query MITRE coverage: {exc}")
        coverage = {t: 0 for t in technique_ids}
    return coverage

def get_cve_techniques(cve_id):
    mitre_map = _load_mitre_cve_map()
    technique_ids = list(mitre_map.get(cve_id.upper(), []))
    # Merge manual DB overrides
    override_ids = get_cve_technique_overrides(cve_id)
    for t in override_ids:
        if t not in technique_ids:
            technique_ids.append(t)
    if not technique_ids:
        return []
    coverage = _get_covered_techniques(technique_ids)
    return [MitreTechnique(technique_id=t_id, name=_TECHNIQUE_NAMES.get(t_id, ""),
                           has_detection=coverage.get(t_id, 0) > 0, rule_count=coverage.get(t_id, 0))
            for t_id in technique_ids]

# --- MITRE Technique Overrides (manual per-CVE additions) ---

def get_cve_technique_overrides(cve_id: str) -> List[str]:
    """Return list of manually added technique IDs for a CVE."""
    try:
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT technique_id FROM cve_technique_overrides WHERE cve_id = ? ORDER BY technique_id",
                [cve_id.upper()]).fetchall()
        return [r[0] for r in rows]
    except Exception as exc:
        logger.warning(f"get_cve_technique_overrides failed: {exc}")
        return []

def add_cve_technique_override(cve_id: str, technique_id: str) -> bool:
    """Add a technique ID override for a CVE. Returns True if inserted."""
    try:
        with _get_conn() as conn:
            conn.execute(
                "INSERT INTO cve_technique_overrides (cve_id, technique_id) VALUES (?, ?) ON CONFLICT DO NOTHING",
                [cve_id.upper(), technique_id.upper()])
        return True
    except Exception as exc:
        logger.warning(f"add_cve_technique_override failed: {exc}")
        return False

def remove_cve_technique_override(cve_id: str, technique_id: str) -> bool:
    """Remove a technique ID override for a CVE. Returns True if deleted."""
    try:
        with _get_conn() as conn:
            before = conn.execute(
                "SELECT COUNT(*) FROM cve_technique_overrides WHERE cve_id = ? AND technique_id = ?",
                [cve_id.upper(), technique_id.upper()]).fetchone()[0]
            conn.execute(
                "DELETE FROM cve_technique_overrides WHERE cve_id = ? AND technique_id = ?",
                [cve_id.upper(), technique_id.upper()])
        return bool(before)
    except Exception as exc:
        logger.warning(f"remove_cve_technique_override failed: {exc}")
        return False

# --- System CRUD ---
def list_systems():
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, name, description, created_at, updated_at, classification FROM systems ORDER BY name"
        ).fetchall()
    return [_row_to_system(r) for r in rows]

def get_system(system_id):
    with _get_conn() as conn:
        r = conn.execute(
            "SELECT id, name, description, created_at, updated_at, classification FROM systems WHERE id = ?",
            [system_id]).fetchone()
    return _row_to_system(r) if r else None

def add_system(data):
    with _get_conn() as conn:
        row = conn.execute(
            "INSERT INTO systems (name, description, classification) VALUES (?, ?, ?) RETURNING id, name, description, created_at, updated_at, classification",
            [data.name, data.description, getattr(data, 'classification', None)]).fetchone()
    return _row_to_system(row)

def edit_system(system_id, data):
    current = get_system(system_id)
    if not current:
        return None
    name = data.name if data.name is not None else current.name
    desc = data.description if data.description is not None else current.description
    classification = data.classification if data.classification is not None else current.classification
    with _get_conn() as conn:
        row = conn.execute(
            "UPDATE systems SET name = ?, description = ?, classification = ?, updated_at = now() WHERE id = ? RETURNING id, name, description, created_at, updated_at, classification",
            [name, desc, classification, system_id]).fetchone()
    return _row_to_system(row) if row else None

def delete_system(system_id):
    with _get_conn() as conn:
        before = conn.execute("SELECT COUNT(*) FROM systems WHERE id = ?", [system_id]).fetchone()[0]
        if before == 0:
            return False
        host_ids = [r[0] for r in conn.execute("SELECT id FROM hosts WHERE system_id = ?", [system_id]).fetchall()]
        for h_id in host_ids:
            conn.execute("DELETE FROM software_inventory WHERE host_id = ?", [h_id])
        conn.execute("DELETE FROM software_inventory WHERE system_id = ?", [system_id])
        conn.execute("DELETE FROM hosts WHERE system_id = ?", [system_id])
        conn.execute("DELETE FROM systems WHERE id = ?", [system_id])
    return True

# --- Host CRUD ---
def list_hosts(system_id):
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, system_id, name, ip_address, os, hardware_vendor, model, source, created_at FROM hosts WHERE system_id = ? ORDER BY name",
            [system_id]).fetchall()
    return [_row_to_host(r) for r in rows]

def get_host(host_id):
    with _get_conn() as conn:
        r = conn.execute(
            "SELECT id, system_id, name, ip_address, os, hardware_vendor, model, source, created_at FROM hosts WHERE id = ?",
            [host_id]).fetchone()
    return _row_to_host(r) if r else None

def add_host(system_id, data):
    with _get_conn() as conn:
        row = conn.execute(
            "INSERT INTO hosts (system_id, name, ip_address, os, hardware_vendor, model, source) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id, system_id, name, ip_address, os, hardware_vendor, model, source, created_at",
            [system_id, data.name, data.ip_address, data.os, data.hardware_vendor, data.model, data.source]).fetchone()
    return _row_to_host(row)

def edit_host(host_id, data: HostUpdate):
    current = get_host(host_id)
    if not current:
        return None
    name = data.name if data.name is not None else current.name
    ip  = data.ip_address if data.ip_address is not None else current.ip_address
    os_ = data.os if data.os is not None else current.os
    hv  = data.hardware_vendor if data.hardware_vendor is not None else current.hardware_vendor
    mod = data.model if data.model is not None else current.model
    with _get_conn() as conn:
        row = conn.execute(
            "UPDATE hosts SET name=?, ip_address=?, os=?, hardware_vendor=?, model=? WHERE id=? "
            "RETURNING id, system_id, name, ip_address, os, hardware_vendor, model, source, created_at",
            [name, ip, os_, hv, mod, host_id]).fetchone()
    return _row_to_host(row) if row else None

def delete_host(host_id):
    with _get_conn() as conn:
        before = conn.execute("SELECT COUNT(*) FROM hosts WHERE id = ?", [host_id]).fetchone()[0]
        if before == 0:
            return False
        conn.execute("DELETE FROM software_inventory WHERE host_id = ?", [host_id])
        conn.execute("DELETE FROM hosts WHERE id = ?", [host_id])
    return True

# --- Software CRUD ---
def list_host_software(host_id):
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, host_id, system_id, name, version, vendor, cpe, source, created_at FROM software_inventory WHERE host_id = ? ORDER BY name",
            [host_id]).fetchall()
    return [_row_to_software(r) for r in rows]

def add_host_software(host_id, system_id, data):
    with _get_conn() as conn:
        row = conn.execute(
            "INSERT INTO software_inventory (host_id, system_id, name, version, vendor, cpe, source) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id, host_id, system_id, name, version, vendor, cpe, source, created_at",
            [host_id, system_id, data.name, data.version, data.vendor, data.cpe, data.source]).fetchone()
    return _row_to_software(row)

def list_software(system_id):
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, host_id, system_id, name, version, vendor, cpe, source, created_at FROM software_inventory WHERE system_id = ? ORDER BY name",
            [system_id]).fetchall()
    return [_row_to_software(r) for r in rows]

def add_software(system_id, data):
    with _get_conn() as conn:
        row = conn.execute(
            "INSERT INTO software_inventory (system_id, name, version, vendor, cpe, source) VALUES (?, ?, ?, ?, ?, ?) RETURNING id, host_id, system_id, name, version, vendor, cpe, source, created_at",
            [system_id, data.name, data.version, data.vendor, data.cpe, data.source]).fetchone()
    return _row_to_software(row)

def get_software(software_id):
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT id, host_id, system_id, name, version, vendor, cpe, source, created_at FROM software_inventory WHERE id = ?",
            [software_id]).fetchone()
    return _row_to_software(row) if row else None

def edit_software(software_id, data: SoftwareUpdate):
    current = get_software(software_id)
    if not current:
        return None
    name    = data.name    if data.name    is not None else current.name
    version = data.version if data.version is not None else current.version
    vendor  = data.vendor  if data.vendor  is not None else current.vendor
    cpe     = data.cpe     if data.cpe     is not None else current.cpe
    with _get_conn() as conn:
        row = conn.execute(
            "UPDATE software_inventory SET name=?, version=?, vendor=?, cpe=? WHERE id=? "
            "RETURNING id, host_id, system_id, name, version, vendor, cpe, source, created_at",
            [name, version, vendor, cpe, software_id]).fetchone()
    return _row_to_software(row) if row else None

def delete_software(software_id):
    with _get_conn() as conn:
        before = conn.execute("SELECT COUNT(*) FROM software_inventory WHERE id = ?", [software_id]).fetchone()[0]
        conn.execute("DELETE FROM software_inventory WHERE id = ?", [software_id])
    return before > 0

# --- Nessus Parser ---
def parse_nessus_xml(xml_bytes, system_id):
    warnings = []
    hosts_created = 0
    software_inserted = 0
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML: {exc}") from exc
    for report_host in root.iter("ReportHost"):
        host_name = report_host.get("name", "unknown")
        ip_address = None
        os_name = None
        for prop in report_host.iter("HostProperties"):
            for tag in prop.iter("tag"):
                tag_name = tag.get("name", "")
                if tag_name == "host-ip":
                    ip_address = tag.text
                elif tag_name in ("operating-system", "os"):
                    os_name = tag.text
        try:
            host = add_host(system_id, HostCreate(name=host_name, ip_address=ip_address, os=os_name, source="nessus"))
            hosts_created += 1
        except Exception as exc:
            msg = f"Failed to create host {host_name!r}: {exc}"
            logger.warning(msg); warnings.append(msg); continue
        existing = set()
        for item in report_host.iter("ReportItem"):
            cpe_values = [el.text.strip() for el in item.iter("cpe") if el.text]
            software_name = None
            software_version = None
            vendor = None
            for cpe in cpe_values:
                parts = cpe.split(":")
                if len(parts) >= 4:
                    vendor = parts[2].replace("_", " ").title() if parts[2] else None
                    software_name = parts[3].replace("_", " ").title() if parts[3] else None
                    software_version = parts[4] if len(parts) >= 5 else None
                    break
            if not software_name:
                po = (item.findtext("plugin_output") or "").strip()
                nm = re.search(r"(?:Product|Application|Software)\s*:\s*(.+)", po, re.IGNORECASE)
                vm = re.search(r"(?:Version|Ver)\s*:\s*([\d][^\s]*)", po, re.IGNORECASE)
                if nm: software_name = nm.group(1).strip()
                if vm: software_version = vm.group(1).strip()
            if not software_name:
                pn = item.get("pluginName", "")
                if pn and "?" not in pn:
                    software_name = pn.strip()
            if not software_name:
                continue
            key = (software_name.lower(), (software_version or "").lower())
            if key in existing:
                continue
            existing.add(key)
            try:
                add_host_software(host.id, system_id, SoftwareCreate(
                    name=software_name, version=software_version,
                    vendor=vendor, cpe=cpe_values[0] if cpe_values else None, source="nessus"))
                software_inserted += 1
            except Exception as exc:
                msg = f"Failed to insert {software_name!r} on {host_name!r}: {exc}"
                logger.warning(msg); warnings.append(msg)
    logger.info(f"Nessus: {hosts_created} hosts, {software_inserted} software, {len(warnings)} warnings")
    return hosts_created, software_inserted, warnings

# --- CVE Matching ---
_CVE_RANSOMWARE_YES = {"known", "yes", "true"}

def _kev_to_cve_match(kev, affected_hosts=None, matched_software=None, techniques=None,
                       detection=None, system_detections=None, threat_actors=None):
    """Build a CveMatch from a raw KEV dict."""
    ransomware_raw = (kev.get("knownRansomwareCampaignUse") or "").lower()
    return CveMatch(
        cve_id=kev.get("cveID", ""),
        vendor_project=kev.get("vendorProject", ""),
        product=kev.get("product", ""),
        vulnerability_name=kev.get("vulnerabilityName", ""),
        short_description=kev.get("shortDescription", ""),
        date_added=kev.get("dateAdded", ""),
        due_date=kev.get("dueDate", ""),
        known_ransomware=ransomware_raw in _CVE_RANSOMWARE_YES,
        notes=kev.get("notes"),
        matched_software=matched_software or [],
        affected_hosts=affected_hosts or [],
        techniques=techniques or [],
        threat_actors=threat_actors or [],
        detection=detection,
        system_detections=system_detections or {},
    )


_octi_warmup_started: bool = False
_octi_warmup_lock = threading.Lock()


def _ensure_opencti_index_warm() -> bool:
    """
    Return True if the OpenCTI bulk index is already cached.
    If not, start a one-shot background thread to warm it and return False
    so the caller can skip the enrichment for this request.
    """
    from app.version_gate import fetch_opencti_vuln_index, _octi_bulk_cache
    global _octi_warmup_started
    if _octi_bulk_cache is not None:
        return True
    with _octi_warmup_lock:
        if not _octi_warmup_started:
            _octi_warmup_started = True
            t = threading.Thread(target=fetch_opencti_vuln_index, daemon=True, name="octi-warmup")
            t.start()
            logger.info("[opencti-index] Background warm-up started")
    return False


def _match_software_against_opencti(
    software_list: list,
    host_sw_cpes: List[str],
) -> Dict[str, Dict]:
    """
    Match host software CPEs against the OpenCTI vulnerability index using strict
    CPE identity (part/vendor/product) matching.

    Returns {cve_id: {description, cvss_score, actors, matched_software}} for
    every CVE in OpenCTI whose affected-software CPEs identity-match at least
    one host CPE. Version filtering is applied where OpenCTI provides version data.

    This is intentionally separate from _match_software_against_kev so the KEV
    overview page is unaffected.
    """
    from app.version_gate import fetch_opencti_vuln_index, Cpe, _evaluate_opencti_ranges

    if not _ensure_opencti_index_warm():
        return {}   # cache still warming in background — skip enrichment this request

    index = fetch_opencti_vuln_index()
    if not index or not host_sw_cpes:
        return {}

    # Parse host CPEs once and map cpe_str -> software names (a CPE may appear once)
    host_parsed: List[tuple] = [(Cpe.parse(c), c) for c in host_sw_cpes if c]
    cpe_to_sw: Dict[str, List[str]] = {}
    for sw in software_list:
        if sw.cpe:
            cpe_to_sw.setdefault(sw.cpe, []).append(sw.name)

    results: Dict[str, Dict] = {}
    for cve_id, vuln in index.items():
        cpe_ranges = vuln.get("cpe_ranges", [])
        if not cpe_ranges:
            continue

        # Use the existing CPE-identity + version-range evaluator
        match_result = _evaluate_opencti_ranges(cpe_ranges, host_sw_cpes)
        if match_result is not True:
            continue

        # Identify which software names contributed to the match
        matched_names: List[str] = []
        for r in cpe_ranges:
            nvd_cpe = Cpe.parse(r.get("cpe23Uri", ""))
            for hcpe, hcpe_str in host_parsed:
                if nvd_cpe.identity_matches(hcpe):
                    for name in cpe_to_sw.get(hcpe_str, []):
                        if name not in matched_names:
                            matched_names.append(name)

        if matched_names:
            results[cve_id] = {
                "description": vuln.get("description", ""),
                "cvss_score": vuln.get("cvss_score"),
                "actors": vuln.get("actors", []),
                "matched_software": matched_names,
            }

    logger.debug("[opencti-match] %d CVEs matched via CPE identity", len(results))
    return results

def _match_software_against_kev(
    software_list,
    kev_entries,
    host_os: str = "",
    apply_version_gate: bool = True,
) -> Dict[str, List[str]]:
    """
    Returns {cve_id: matched_software_names} for software that matches KEV entries.

    When apply_version_gate=True (default) and host_os is provided, Windows OS-level
    CVEs that do not affect the host's specific build number are suppressed to
    eliminate false positives caused by simple keyword matching.
    """
    from app.version_gate import should_include_match

    matches: Dict[str, List[str]] = {}
    # Collect all CPEs from this host's software list once for the version gate
    host_sw_cpes: List[str] = [sw.cpe for sw in software_list if sw.cpe]

    for kev in kev_entries:
        cve_id = kev.get("cveID", "")
        vendor_proj = (kev.get("vendorProject") or "").lower()
        product = (kev.get("product") or "").lower()
        notes = (kev.get("notes") or "").lower()
        for sw in software_list:
            sw_cpe = (sw.cpe or "").lower()
            sw_vendor = (sw.vendor or "").lower()
            sw_name = sw.name.lower()
            matched = ((sw_cpe and sw_cpe in notes) or
                       (sw_vendor and sw_vendor in vendor_proj) or
                       (product and (product in sw_name or sw_name in product)))
            if not matched:
                continue

            # Version gate: suppress CVEs whose version ranges don't cover this build
            if apply_version_gate and cve_id:
                matched_cpe = [sw.cpe] if sw.cpe else []
                if not should_include_match(
                    cve_id, kev, matched_cpe, host_sw_cpes
                ):
                    continue

            if cve_id not in matches:
                matches[cve_id] = [sw.name]
            elif sw.name not in matches[cve_id]:
                matches[cve_id].append(sw.name)
    return matches

def get_host_vulnerabilities(host_id):
    host = get_host(host_id)
    if not host:
        return []
    software = list_host_software(host_id)
    if not software:
        return []

    detections = list_cve_detections()
    host_sw_cpes: List[str] = [sw.cpe for sw in software if sw.cpe]

    # --- KEV keyword matching (existing) ---
    kev = _load_cisa_kev()
    kev_by_id = {k.get("cveID", ""): k for k in (kev or [])}
    matched_map: Dict[str, List[str]] = {}
    if kev:
        matched_map = _match_software_against_kev(software, kev, host_os=host.os or "")

    # --- OpenCTI CPE identity matching (enrichment) ---
    octi_map = _match_software_against_opencti(software, host_sw_cpes)

    # Merge: collect all CVE IDs from both sources
    all_cve_ids = set(matched_map) | set(octi_map)
    out = []
    for cve_id in all_cve_ids:
        kev_entry = kev_by_id.get(cve_id, {})
        octi_vuln = octi_map.get(cve_id, {})
        actors = octi_vuln.get("actors", [])
        cve_dets = detections.get(cve_id, {})
        any_det = next(iter(cve_dets.values()), None)

        # Merge software name lists from both sources
        kev_sw = matched_map.get(cve_id, [])
        octi_sw = octi_vuln.get("matched_software", [])
        sw_names = list(dict.fromkeys(kev_sw + [n for n in octi_sw if n not in kev_sw]))

        if kev_entry:
            # CVE is in CISA KEV — use KEV metadata, enrich with OpenCTI actors
            out.append(_kev_to_cve_match(
                kev_entry,
                matched_software=sw_names,
                techniques=get_cve_techniques(cve_id) if cve_id in matched_map else [],
                detection=any_det,
                system_detections=cve_dets,
                threat_actors=actors,
            ))
        else:
            # CVE is in OpenCTI but not in CISA KEV — synthesise a CveMatch
            desc = octi_vuln.get("description", "")
            out.append(CveMatch(
                cve_id=cve_id,
                vendor_project="OpenCTI",
                product=", ".join(sw_names) or "Unknown",
                vulnerability_name=desc[:120] if desc else cve_id,
                short_description=desc,
                date_added="",
                due_date="",
                known_ransomware=False,
                matched_software=sw_names,
                threat_actors=actors,
                detection=any_det,
                system_detections=cve_dets,
            ))

    return sorted(out, key=lambda m: (m.date_added or "0"), reverse=True)

def get_system_vulnerabilities(system_id):
    system = get_system(system_id)
    if not system:
        return []
    kev = _load_cisa_kev()
    kev_by_id = {k.get("cveID", ""): k for k in (kev or [])}
    detections = list_cve_detections()
    combined_sw: Dict[str, List[str]] = {}          # cve_id -> sw names
    combined_hosts: Dict[str, List[AffectedHost]] = {}
    combined_actors: Dict[str, List[str]] = {}      # cve_id -> actor names

    for host in list_hosts(system_id):
        software = list_host_software(host.id)
        if not software:
            continue
        host_sw_cpes: List[str] = [sw.cpe for sw in software if sw.cpe]
        ah = AffectedHost(host_id=host.id, name=host.name, ip_address=host.ip_address,
                          system_id=system.id, system_name=system.name)

        # KEV keyword matches for this host
        kev_matches: Dict[str, List[str]] = {}
        if kev:
            kev_matches = _match_software_against_kev(software, kev, host_os=host.os or "")

        # OpenCTI CPE-identity matches for this host
        octi_matches = _match_software_against_opencti(software, host_sw_cpes)

        for cve_id in set(kev_matches) | set(octi_matches):
            sw_names = list(dict.fromkeys(
                kev_matches.get(cve_id, []) +
                [n for n in octi_matches.get(cve_id, {}).get("matched_software", [])
                 if n not in kev_matches.get(cve_id, [])]
            ))
            actors = octi_matches.get(cve_id, {}).get("actors", [])

            if cve_id not in combined_hosts:
                combined_hosts[cve_id] = [ah]
                combined_sw[cve_id] = sw_names
                combined_actors[cve_id] = actors
            else:
                if not any(a.host_id == host.id for a in combined_hosts[cve_id]):
                    combined_hosts[cve_id].append(ah)
                for sn in sw_names:
                    if sn not in combined_sw[cve_id]:
                        combined_sw[cve_id].append(sn)
                for ac in actors:
                    if ac not in combined_actors[cve_id]:
                        combined_actors[cve_id].append(ac)

    out = []
    for cve_id, hosts_list in combined_hosts.items():
        kev_entry = kev_by_id.get(cve_id, {})
        octi_desc = ""
        cve_dets = detections.get(cve_id, {})
        any_det = next(iter(cve_dets.values()), None)
        actors = combined_actors.get(cve_id, [])

        if kev_entry:
            out.append(_kev_to_cve_match(
                kev_entry,
                affected_hosts=hosts_list,
                matched_software=combined_sw.get(cve_id, []),
                detection=any_det,
                system_detections=cve_dets,
                threat_actors=actors,
            ))
        else:
            # OpenCTI-only CVE
            sw_names = combined_sw.get(cve_id, [])
            out.append(CveMatch(
                cve_id=cve_id,
                vendor_project="OpenCTI",
                product=", ".join(sw_names) or "Unknown",
                vulnerability_name=cve_id,
                short_description="",
                date_added="",
                due_date="",
                known_ransomware=False,
                matched_software=sw_names,
                affected_hosts=hosts_list,
                threat_actors=actors,
                detection=any_det,
                system_detections=cve_dets,
            ))

    return sorted(out, key=lambda m: (m.date_added or "0"), reverse=True)

def get_all_cve_overview():
    """Return all KEV entries. Matched entries (with affected hosts) come first."""
    kev_entries = _load_cisa_kev()
    if not kev_entries:
        return []
    detections = list_cve_detections()
    # Build map: cve_id -> List[AffectedHost]
    affected_by_cve: Dict[str, List[AffectedHost]] = {}
    for system in list_systems():
        for host in list_hosts(system.id):
            software = list_host_software(host.id)
            if not software:
                continue
            matches = _match_software_against_kev(software, kev_entries, host_os=host.os or "")
            ah = AffectedHost(host_id=host.id, name=host.name, ip_address=host.ip_address,
                              system_id=system.id, system_name=system.name)
            for cve_id in matches:
                affected_by_cve.setdefault(cve_id, [])
                if not any(a.host_id == host.id for a in affected_by_cve[cve_id]):
                    affected_by_cve[cve_id].append(ah)
    matched_rows, unmatched_rows = [], []
    for kev in kev_entries:
        cve_id = kev.get("cveID", "")
        hosts = affected_by_cve.get(cve_id, [])
        cve_dets = detections.get(cve_id, {})
        any_det = next(iter(cve_dets.values()), None)
        row = _kev_to_cve_match(kev, affected_hosts=hosts, detection=any_det, system_detections=cve_dets)
        if hosts:
            matched_rows.append(row)
        else:
            unmatched_rows.append(row)
    matched_rows.sort(key=lambda m: m.date_added, reverse=True)
    unmatched_rows.sort(key=lambda m: m.date_added, reverse=True)
    return matched_rows + unmatched_rows

def get_cve_detail(cve_id):
    kev_entries = _load_cisa_kev()
    kev_entry = next((k for k in kev_entries if k.get("cveID", "").upper() == cve_id.upper()), None)
    if not kev_entry:
        return None
    detections = list_cve_detections()
    all_affected: List[AffectedHost] = []
    matched_sw: List[str] = []
    for system in list_systems():
        for host in list_hosts(system.id):
            software = list_host_software(host.id)
            matches = _match_software_against_kev(software, kev_entries, host_os=host.os or "")
            if cve_id.upper() in {k.upper() for k in matches}:
                match_key = next(k for k in matches if k.upper() == cve_id.upper())
                if not any(a.host_id == host.id for a in all_affected):
                    all_affected.append(AffectedHost(
                        host_id=host.id, name=host.name, ip_address=host.ip_address,
                        system_id=system.id, system_name=system.name))
                for sw_name in matches[match_key]:
                    if sw_name not in matched_sw:
                        matched_sw.append(sw_name)
    return _kev_to_cve_match(kev_entry, affected_hosts=all_affected,
                             matched_software=matched_sw,
                             techniques=get_cve_techniques(cve_id),
                             detection=next(iter(detections.get(cve_id.upper(), {}).values()), None),
                             system_detections=detections.get(cve_id.upper(), {}))

# --- Summaries ---
def get_system_summaries():
    summaries = []
    for system in list_systems():
        hosts = list_hosts(system.id)
        vulns = get_system_vulnerabilities(system.id)
        sw_count = sum(len(list_host_software(h.id)) for h in hosts)
        summaries.append(SystemSummary(
            system=system, host_count=len(hosts), vuln_count=len(vulns), software_count=sw_count))
    return summaries

def get_host_summaries(system_id):
    summaries = []
    for host in list_hosts(system_id):
        software = list_host_software(host.id)
        vulns = get_host_vulnerabilities(host.id)
        summaries.append(HostSummary(host=host, software_count=len(software), vuln_count=len(vulns)))
    return summaries

# --- Stats for Dashboard ---
def get_inventory_stats() -> InventoryStats:
    """Fast aggregated stats for dashboard widget."""
    try:
        with _get_conn() as conn:
            env_count = conn.execute("SELECT COUNT(*) FROM systems").fetchone()[0]
            host_count = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
            sw_count = conn.execute("SELECT COUNT(*) FROM software_inventory WHERE host_id IS NOT NULL").fetchone()[0]
            last_scan_row = conn.execute(
                "SELECT MAX(created_at) FROM hosts").fetchone()
            last_scan = str(last_scan_row[0])[:10] if last_scan_row and last_scan_row[0] else None
    except Exception as exc:
        logger.warning(f"get_inventory_stats DB error: {exc}")
        return InventoryStats()
    # CVE matching is expensive — use overview to count affected hosts
    kev = _load_cisa_kev()
    if not kev:
        return InventoryStats(environment_count=env_count, host_count=host_count,
                              software_count=sw_count, last_scan=last_scan)
    affected_hosts_set: set = set()
    matched_cves: set = set()
    for system in list_systems():
        for host in list_hosts(system.id):
            sw = list_host_software(host.id)
            if not sw:
                continue
            m = _match_software_against_kev(sw, kev, host_os=host.os or "")
            if m:
                affected_hosts_set.add(host.id)
                matched_cves.update(m.keys())
    return InventoryStats(
        environment_count=env_count, host_count=host_count, software_count=sw_count,
        unique_vuln_count=len(matched_cves), affected_host_count=len(affected_hosts_set),
        last_scan=last_scan,
    )

def get_cve_overview_stats() -> CveOverviewStats:
    """Stats for the CVE Overview header cards."""
    kev = _load_cisa_kev()
    total_kev = len(kev)
    if not total_kev:
        return CveOverviewStats()
    # Count ransomware
    ransomware_count = sum(1 for k in kev
                          if (k.get("knownRansomwareCampaignUse") or "").lower() in _CVE_RANSOMWARE_YES)
    # Build affected host set
    affected_cves: set = set()
    affected_hosts_set: set = set()
    for system in list_systems():
        for host in list_hosts(system.id):
            sw = list_host_software(host.id)
            if not sw:
                continue
            m = _match_software_against_kev(sw, kev, host_os=host.os or "")
            if m:
                affected_hosts_set.add(host.id)
                affected_cves.update(m.keys())
    detections = list_cve_detections()
    detected_count = len(detections)
    ransomware_cves = {k.get("cveID", "") for k in kev
                      if (k.get("knownRansomwareCampaignUse") or "").lower() in _CVE_RANSOMWARE_YES}
    ransomware_undetected = len(ransomware_cves - set(detections.keys()))
    return CveOverviewStats(
        total_kev=total_kev, matched_count=len(affected_cves),
        affected_hosts=len(affected_hosts_set), ransomware_count=ransomware_count,
        detected_count=detected_count, ransomware_undetected=ransomware_undetected,
    )

# --- Detection CRUD ---
def list_cve_detections() -> Dict[str, Dict[str, VulnDetection]]:
    """Returns {cve_id: {system_id: VulnDetection}} for all asserted detections."""
    try:
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT cve_id, system_id, note, rule_ref, created_at FROM vuln_detections"
            ).fetchall()
        result: Dict[str, Dict[str, VulnDetection]] = {}
        for r in rows:
            cve_id, sys_id = r[0], r[1]
            result.setdefault(cve_id, {})[sys_id] = VulnDetection(
                cve_id=cve_id, system_id=sys_id, note=r[2], rule_ref=r[3], created_at=r[4])
        return result
    except Exception as exc:
        logger.warning(f"list_cve_detections error: {exc}")
        return {}

def get_cve_detection(cve_id: str, system_id: str = '') -> Optional[VulnDetection]:
    try:
        with _get_conn() as conn:
            r = conn.execute(
                "SELECT cve_id, system_id, note, rule_ref, created_at FROM vuln_detections WHERE cve_id = ? AND system_id = ?",
                [cve_id.upper(), system_id]).fetchone()
        return VulnDetection(cve_id=r[0], system_id=r[1], note=r[2], rule_ref=r[3], created_at=r[4]) if r else None
    except Exception as exc:
        logger.warning(f"get_cve_detection error: {exc}")
        return None

def mark_cve_detected(cve_id: str, system_id: str = '', note: Optional[str] = None, rule_ref: Optional[str] = None) -> VulnDetection:
    cve_id = cve_id.upper()
    with _get_conn() as conn:
        conn.execute("""
            INSERT INTO vuln_detections (cve_id, system_id, note, rule_ref)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (cve_id, system_id) DO UPDATE SET note=excluded.note, rule_ref=excluded.rule_ref
        """, [cve_id, system_id, note, rule_ref])
    return get_cve_detection(cve_id, system_id)

def unmark_cve_detected(cve_id: str, system_id: str = '') -> bool:
    cve_id = cve_id.upper()
    with _get_conn() as conn:
        before = conn.execute(
            "SELECT COUNT(*) FROM vuln_detections WHERE cve_id = ? AND system_id = ?",
            [cve_id, system_id]).fetchone()[0]
        conn.execute("DELETE FROM vuln_detections WHERE cve_id = ? AND system_id = ?", [cve_id, system_id])
    return before > 0

def get_rules_for_cve_techniques(cve_id: str) -> Dict[str, list]:
    """Returns {technique_id: [DetectionRule]} for all techniques mapped to this CVE."""
    from app.services.database import get_database_service
    db = get_database_service()
    techniques = get_cve_techniques(cve_id)
    result: Dict[str, list] = {}
    for t in techniques:
        rules = db.get_rules_for_technique(t.technique_id, enabled_only=False)
        if rules:
            result[t.technique_id] = rules
    return result

# --- CISA Feed ---
def save_mitre_cve_map(json_bytes: bytes) -> int:
    """Validate and persist a CVE→ATT&CK mapping file. Returns entry count."""
    try:
        data = json.loads(json_bytes)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("Mapping file must be a JSON object.")
    path = "/app/data/attack-to-cve.json"
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        shutil.move(tmp, path)
    except Exception as exc:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise RuntimeError(f"Failed to save mapping file: {exc}") from exc
    logger.info(f"MITRE CVE mapping updated: {len(data)} entries written to {path}")
    return len(data)

def ingest_cisa_feed(json_bytes):
    settings = get_settings()
    override_path = settings.cisa_kev_override_path
    try:
        data = json.loads(json_bytes)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc
    vulns = data.get("vulnerabilities", data if isinstance(data, list) else None)
    if vulns is None:
        raise ValueError("JSON must contain a vulnerabilities array or be a top-level array.")
    count = len(vulns)
    override_dir = os.path.dirname(override_path)
    if override_dir:
        os.makedirs(override_dir, exist_ok=True)
    tmp = override_path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        shutil.move(tmp, override_path)
    except Exception as exc:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise RuntimeError(f"Failed to persist CISA KEV override: {exc}") from exc
    logger.info(f"CISA KEV override written: {count} entries to {override_path}")
    return count
