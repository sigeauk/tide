"""
inventory_engine.py - Asset Inventory & CVE Mapping Engine (Phase 2: Enterprise)
"""
from __future__ import annotations
import json, logging, os, re, shutil, xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple
import threading
from app.config import get_settings
from app.models.inventory import (
    AffectedHost, AppliedDetection, Baseline, BaselineCreate, BaselineTactic, BlindSpot, Classification, CveMatch,
    CveOverviewStats, Host, HostCreate, HostSummary, HostUpdate, InventoryStats, MitreTechnique, SoftwareCreate,
    SoftwareInventory, SoftwareUpdate, System, SystemBaseline, SystemCreate, SystemSummary, SystemUpdate,
    TacticDetection, TacticTechnique, VulnDetection,
    # backward compat aliases
    Playbook, PlaybookCreate, PlaybookStep, StepDetection, StepTechnique,
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

_cisa_kev_cache: Optional[list] = None
_cisa_kev_mtime: Optional[float] = None
_cisa_kev_path_used: Optional[str] = None

def _load_cisa_kev():
    global _cisa_kev_cache, _cisa_kev_mtime, _cisa_kev_path_used
    settings = get_settings()
    for path in [settings.cisa_kev_override_path, settings.cisa_kev_path]:
        if path and os.path.exists(path):
            try:
                mtime = os.path.getmtime(path)
                if _cisa_kev_cache is not None and _cisa_kev_path_used == path and _cisa_kev_mtime == mtime:
                    return _cisa_kev_cache
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                    result = data.get("vulnerabilities", data if isinstance(data, list) else [])
                    _cisa_kev_cache = result
                    _cisa_kev_mtime = mtime
                    _cisa_kev_path_used = path
                    return result
            except Exception as exc:
                logger.warning(f"Failed to load CISA KEV from {path}: {exc}")
    logger.warning("No CISA KEV file available.")
    return []


def _list_all_hosts_by_system() -> Dict[str, List]:
    """Load all hosts grouped by system_id in one query."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, system_id, name, ip_address, os, hardware_vendor, model, source, created_at FROM hosts ORDER BY name"
        ).fetchall()
    result: Dict[str, list] = {}
    for r in rows:
        h = _row_to_host(r)
        result.setdefault(h.system_id, []).append(h)
    return result


def _list_all_software_by_host() -> Dict[str, List]:
    """Load all software grouped by host_id in one query."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, host_id, system_id, name, version, vendor, cpe, source, created_at "
            "FROM software_inventory WHERE host_id IS NOT NULL ORDER BY name"
        ).fetchall()
    result: Dict[str, list] = {}
    for r in rows:
        sw = _row_to_software(r)
        result.setdefault(sw.host_id, []).append(sw)
    return result

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

# --- Classification CRUD ---
def list_classifications() -> List[Classification]:
    with _get_conn() as conn:
        rows = conn.execute("SELECT id, name, color FROM classifications ORDER BY name").fetchall()
    return [Classification(id=r[0], name=r[1], color=r[2]) for r in rows]

def get_classification_color(name: Optional[str]) -> Optional[str]:
    """Return the hex colour for a classification name, or None."""
    if not name:
        return None
    with _get_conn() as conn:
        r = conn.execute("SELECT color FROM classifications WHERE name = ?", [name]).fetchone()
    return r[0] if r else None

def add_classification(name: str, color: str = "#6b7280") -> Classification:
    with _get_conn() as conn:
        row = conn.execute(
            "INSERT INTO classifications (name, color) VALUES (?, ?) RETURNING id, name, color",
            [name.strip(), color.strip()]).fetchone()
    return Classification(id=row[0], name=row[1], color=row[2])

def delete_classification(cls_id: str) -> bool:
    with _get_conn() as conn:
        before = conn.execute("SELECT COUNT(*) FROM classifications WHERE id = ?", [cls_id]).fetchone()[0]
        if before == 0:
            return False
        # Clear classification from any systems using it
        row = conn.execute("SELECT name FROM classifications WHERE id = ?", [cls_id]).fetchone()
        if row:
            conn.execute("UPDATE systems SET classification = NULL WHERE classification = ?", [row[0]])
        conn.execute("DELETE FROM classifications WHERE id = ?", [cls_id])
    return True

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
            # Only import items that have a CPE or an explicit software name
            # from plugin_output. Do NOT fall back to pluginName — those are
            # audit/info plugin titles (e.g. "Microsoft Windows SMB Shares
            # Enumeration") and are not actual software.
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
                       detections=None, threat_actors=None):
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
        detections=detections or [],
    )


_octi_warmup_started: bool = False
_octi_warmup_lock = threading.Lock()


def _ensure_opencti_index_warm() -> bool:
    """
    Return True if the OpenCTI bulk index is already cached.
    If not, start a one-shot background thread to warm it and return False
    so the caller can skip the enrichment for this request.
    """
    from app.engine.sync_manager import fetch_opencti_vuln_index, _octi_bulk_cache
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
    from app.engine.sync_manager import fetch_opencti_vuln_index, evaluate_opencti_ranges
    from app.engine.cpe_validator import Cpe

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
        match_result = evaluate_opencti_ranges(cpe_ranges, host_sw_cpes)
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
    from app.engine.cpe_validator import should_include_match, Cpe

    matches: Dict[str, List[str]] = {}
    # Only software WITH a CPE can participate in matching — items without a
    # CPE have no verifiable identity and would cause massive false positives.
    sw_with_cpe = [sw for sw in software_list if sw.cpe]
    if not sw_with_cpe:
        return matches
    host_sw_cpes: List[str] = [sw.cpe for sw in sw_with_cpe]

    # Pre-parse CPEs once to avoid repeated parsing in the inner loop
    sw_parsed = []
    for sw in sw_with_cpe:
        cpe_obj = Cpe.parse(sw.cpe)
        sw_parsed.append((sw, sw.cpe.lower(),
                          (cpe_obj.vendor or "").lower() if cpe_obj else "",
                          (cpe_obj.product or "").lower() if cpe_obj else ""))

    for kev in kev_entries:
        cve_id = kev.get("cveID", "")
        vendor_proj = (kev.get("vendorProject") or "").lower()
        product = (kev.get("product") or "").lower()
        notes = (kev.get("notes") or "").lower()
        for sw, sw_cpe_lower, cpe_vendor, cpe_product in sw_parsed:
            # Match via CPE string appearing in KEV notes
            cpe_in_notes = sw_cpe_lower in notes
            # Match via CPE vendor+product identity against KEV vendor/product
            identity_match = (cpe_vendor and cpe_vendor == vendor_proj and
                              cpe_product and cpe_product == product)
            if not (cpe_in_notes or identity_match):
                continue

            # Version gate: suppress CVEs whose version ranges don't cover this build
            if apply_version_gate and cve_id:
                if not should_include_match(cve_id, kev, [sw.cpe], host_sw_cpes):
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
    applied_map = _load_applied_detections()
    # Enrich detections with applied_to so templates can check per-host coverage
    for dets in detections.values():
        _enrich_detections_with_applied(dets, applied_map)
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
        cve_dets = detections.get(cve_id, [])

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
                detections=cve_dets,
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
                detections=cve_dets,
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
    all_software = _list_all_software_by_host()

    for host in list_hosts(system_id):
        software = all_software.get(host.id, list_host_software(host.id))
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
        cve_dets = detections.get(cve_id, [])
        actors = combined_actors.get(cve_id, [])

        if kev_entry:
            out.append(_kev_to_cve_match(
                kev_entry,
                affected_hosts=hosts_list,
                matched_software=combined_sw.get(cve_id, []),
                detections=cve_dets,
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
                detections=cve_dets,
            ))

    return sorted(out, key=lambda m: (m.date_added or "0"), reverse=True)

def get_all_cve_overview():
    """Return all KEV entries. Matched entries (with affected hosts) come first."""
    kev_entries = _load_cisa_kev()
    if not kev_entries:
        return []
    detections = list_cve_detections()
    applied_map = _load_applied_detections()
    systems = list_systems()
    all_hosts = _list_all_hosts_by_system()
    all_software = _list_all_software_by_host()
    # Enrich detections with applied_to
    for cve_id_key, dets in detections.items():
        _enrich_detections_with_applied(dets, applied_map)
    # Load all CVE blind spots once
    all_blind_spots = _load_all_blind_spots("cve")
    # Build map: cve_id -> List[AffectedHost]
    affected_by_cve: Dict[str, List[AffectedHost]] = {}
    for system in systems:
        for host in all_hosts.get(system.id, []):
            software = all_software.get(host.id, [])
            if not software:
                continue
            matches = _match_software_against_kev(software, kev_entries, host_os=host.os or "")
            for cve_id in matches:
                cve_dets = detections.get(cve_id, [])
                cve_bs = all_blind_spots.get(cve_id, [])
                status, rule_names = _compute_coverage_status(host.id, system.id, cve_dets, applied_map, cve_bs)
                ah = AffectedHost(host_id=host.id, name=host.name, ip_address=host.ip_address,
                                  system_id=system.id, system_name=system.name,
                                  coverage_status=status,
                                  applied_rule_names=rule_names)
                affected_by_cve.setdefault(cve_id, [])
                if not any(a.host_id == host.id for a in affected_by_cve[cve_id]):
                    affected_by_cve[cve_id].append(ah)
    matched_rows, unmatched_rows = [], []
    for kev in kev_entries:
        cve_id = kev.get("cveID", "")
        hosts = affected_by_cve.get(cve_id, [])
        cve_dets = detections.get(cve_id, [])
        row = _kev_to_cve_match(kev, affected_hosts=hosts, detections=cve_dets)
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
    applied_map = _load_applied_detections()
    cve_dets = detections.get(cve_id.upper(), [])
    _enrich_detections_with_applied(cve_dets, applied_map)
    cve_blind_spots = get_blind_spots("cve", cve_id.upper())
    all_affected: List[AffectedHost] = []
    matched_sw: List[str] = []
    all_hosts = _list_all_hosts_by_system()
    all_software = _list_all_software_by_host()
    for system in list_systems():
        for host in all_hosts.get(system.id, []):
            software = all_software.get(host.id, [])
            matches = _match_software_against_kev(software, kev_entries, host_os=host.os or "")
            if cve_id.upper() in {k.upper() for k in matches}:
                match_key = next(k for k in matches if k.upper() == cve_id.upper())
                if not any(a.host_id == host.id for a in all_affected):
                    status, rule_names = _compute_coverage_status(host.id, system.id, cve_dets, applied_map, cve_blind_spots)
                    all_affected.append(AffectedHost(
                        host_id=host.id, name=host.name, ip_address=host.ip_address,
                        system_id=system.id, system_name=system.name,
                        coverage_status=status,
                        software_count=len(software),
                        source=host.source,
                        applied_rule_names=rule_names))
                for sw_name in matches[match_key]:
                    if sw_name not in matched_sw:
                        matched_sw.append(sw_name)
    return _kev_to_cve_match(kev_entry, affected_hosts=all_affected,
                             matched_software=matched_sw,
                             techniques=get_cve_techniques(cve_id),
                             detections=cve_dets)

# --- Summaries ---
def get_system_summaries():
    systems = list_systems()
    if not systems:
        return []
    all_hosts = _list_all_hosts_by_system()
    all_software = _list_all_software_by_host()
    kev = _load_cisa_kev()
    detections = list_cve_detections()
    applied_map = _load_applied_detections()
    # Preload baseline assignment counts per system
    baseline_counts: dict[str, int] = {}
    baseline_step_totals: dict[str, int] = {}
    baseline_step_covered: dict[str, int] = {}
    try:
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT system_id, COUNT(*) FROM system_baselines GROUP BY system_id"
            ).fetchall()
            step_rows = conn.execute(
                "SELECT sb.system_id, COUNT(ps.id) "
                "FROM system_baselines sb "
                "JOIN playbook_steps ps ON ps.playbook_id = sb.playbook_id "
                "GROUP BY sb.system_id"
            ).fetchall()
            covered_rows = conn.execute(
                "SELECT sb.system_id, COUNT(DISTINCT sd.step_id) "
                "FROM system_baselines sb "
                "JOIN playbook_steps ps ON ps.playbook_id = sb.playbook_id "
                "JOIN step_detections sd ON sd.step_id = ps.id "
                "LEFT JOIN hosts h ON h.system_id = sb.system_id "
                "JOIN applied_detections ad ON ad.detection_id = sd.id "
                "  AND (ad.system_id = sb.system_id OR ad.host_id = h.id) "
                "GROUP BY sb.system_id"
            ).fetchall()
        baseline_counts = {str(system_id): int(cnt) for system_id, cnt in rows}
        baseline_step_totals = {str(system_id): int(cnt) for system_id, cnt in step_rows}
        baseline_step_covered = {str(system_id): int(cnt) for system_id, cnt in covered_rows}
    except Exception:
        baseline_counts = {}
        baseline_step_totals = {}
        baseline_step_covered = {}
    summaries = []
    for system in systems:
        hosts = all_hosts.get(system.id, [])
        sw_count = sum(len(all_software.get(h.id, [])) for h in hosts)
        # Count unique CVEs affecting this system with one pass
        vuln_cves: set = set()
        # Track per-host vuln/detected counts for worst-case RAG
        has_red = False
        has_amber = False
        for host in hosts:
            software = all_software.get(host.id, [])
            if not software:
                continue
            host_vulns: set = set()
            if kev:
                m = _match_software_against_kev(software, kev, host_os=host.os or "")
                host_vulns.update(m.keys())
                vuln_cves.update(m.keys())
            host_sw_cpes = [sw.cpe for sw in software if sw.cpe]
            octi = _match_software_against_opencti(software, host_sw_cpes)
            host_vulns.update(octi.keys())
            vuln_cves.update(octi.keys())
            if host_vulns:
                # Check if all CVEs on this host have an applied detection
                host_detected = 0
                for cve_id in host_vulns:
                    for det in detections.get(cve_id, []):
                        if any(ad.host_id == host.id or ad.system_id == system.id for ad in applied_map.get(det.id, [])):
                            host_detected += 1
                            break
                if host_detected >= len(host_vulns):
                    has_amber = True
                else:
                    has_red = True
        if has_red:
            worst_status = "red"
        elif has_amber:
            worst_status = "amber"
        else:
            worst_status = "green"
        total_steps = baseline_step_totals.get(str(system.id), 0)
        covered_steps = baseline_step_covered.get(str(system.id), 0)
        baseline_coverage_pct = int(round((covered_steps / total_steps) * 100)) if total_steps > 0 else 0
        summaries.append(SystemSummary(
            system=system, host_count=len(hosts), vuln_count=len(vuln_cves),
            software_count=sw_count,
            baseline_count=baseline_counts.get(str(system.id), 0),
            baseline_coverage_pct=baseline_coverage_pct,
            worst_status=worst_status))
    return summaries

def get_host_summaries(system_id):
    hosts = list_hosts(system_id)
    if not hosts:
        return []
    all_software = _list_all_software_by_host()
    kev = _load_cisa_kev()
    detections = list_cve_detections()
    applied_map = _load_applied_detections()
    summaries = []
    for host in hosts:
        software = all_software.get(host.id, [])
        vuln_count = 0
        detected_count = 0
        if software:
            vuln_cves: set = set()
            if kev:
                m = _match_software_against_kev(software, kev, host_os=host.os or "")
                vuln_cves.update(m.keys())
            host_sw_cpes = [sw.cpe for sw in software if sw.cpe]
            octi = _match_software_against_opencti(software, host_sw_cpes)
            vuln_cves.update(octi.keys())
            vuln_count = len(vuln_cves)
            # Only count as detected if a detection is actually applied to this host or its system
            for cve_id in vuln_cves:
                for det in detections.get(cve_id, []):
                    if any(ad.host_id == host.id or ad.system_id == system_id for ad in applied_map.get(det.id, [])):
                        detected_count += 1
                        break
        sw_names = [sw.name for sw in software] if software else []
        summaries.append(HostSummary(host=host, software_count=len(software), vuln_count=vuln_count,
                                     detected_count=detected_count, software_names=sw_names))
    return summaries

# --- Stats for Dashboard ---
def get_inventory_stats() -> InventoryStats:
    """Fast aggregated stats for dashboard widget."""
    try:
        with _get_conn() as conn:
            env_count = conn.execute("SELECT COUNT(*) FROM systems").fetchone()[0]
            host_count = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
            sw_count = conn.execute("SELECT COUNT(*) FROM software_inventory WHERE host_id IS NOT NULL").fetchone()[0]
            baseline_count = conn.execute("SELECT COUNT(*) FROM playbooks").fetchone()[0]
            baseline_assignment_count = conn.execute("SELECT COUNT(*) FROM system_baselines").fetchone()[0]
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
                              software_count=sw_count,
                              baseline_count=baseline_count,
                              baseline_assignment_count=baseline_assignment_count,
                              last_scan=last_scan)
    affected_hosts_set: set = set()
    matched_cves: set = set()
    all_hosts = _list_all_hosts_by_system()
    all_software = _list_all_software_by_host()
    for system in list_systems():
        for host in all_hosts.get(system.id, []):
            sw = all_software.get(host.id, [])
            if not sw:
                continue
            m = _match_software_against_kev(sw, kev, host_os=host.os or "")
            if m:
                affected_hosts_set.add(host.id)
                matched_cves.update(m.keys())
    return InventoryStats(
        environment_count=env_count, host_count=host_count, software_count=sw_count,
        unique_vuln_count=len(matched_cves), affected_host_count=len(affected_hosts_set),
        baseline_count=baseline_count, baseline_assignment_count=baseline_assignment_count,
        last_scan=last_scan,
    )

def get_cve_overview_stats(cves=None) -> CveOverviewStats:
    """Stats for the CVE Overview header cards.
    If *cves* (output of get_all_cve_overview) is passed, derive stats from it
    to avoid recomputing the expensive host/software matching.
    """
    kev = _load_cisa_kev()
    total_kev = len(kev)
    if not total_kev:
        return CveOverviewStats()
    # Count ransomware
    ransomware_count = sum(1 for k in kev
                          if (k.get("knownRansomwareCampaignUse") or "").lower() in _CVE_RANSOMWARE_YES)

    if cves is not None:
        # Derive from pre-computed overview data
        affected_cves: set = set()
        affected_hosts_set: set = set()
        for c in cves:
            if c.affected_hosts:
                affected_cves.add(c.cve_id)
                for h in c.affected_hosts:
                    affected_hosts_set.add(h.host_id)
    else:
        # Fallback: compute from scratch with batch loading
        affected_cves = set()
        affected_hosts_set = set()
        all_hosts = _list_all_hosts_by_system()
        all_software = _list_all_software_by_host()
        for system in list_systems():
            for host in all_hosts.get(system.id, []):
                sw = all_software.get(host.id, [])
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
def list_cve_detections() -> Dict[str, List[VulnDetection]]:
    """Returns {cve_id: [VulnDetection, ...]} for all recorded detection rules."""
    try:
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT id, cve_id, rule_ref, note, source, created_at FROM vuln_detections"
            ).fetchall()
        result: Dict[str, List[VulnDetection]] = {}
        for r in rows:
            det = VulnDetection(id=r[0], cve_id=r[1], rule_ref=_resolve_rule_ref(r[2]), note=r[3], source=r[4], created_at=r[5])
            result.setdefault(r[1], []).append(det)
        return result
    except Exception as exc:
        logger.warning(f"list_cve_detections error: {exc}")
        return {}

def get_cve_detections(cve_id: str) -> List[VulnDetection]:
    """Return all detection entries for a given CVE."""
    try:
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT id, cve_id, rule_ref, note, source, created_at FROM vuln_detections WHERE cve_id = ? ORDER BY created_at",
                [cve_id.upper()]).fetchall()
        return [VulnDetection(id=r[0], cve_id=r[1], rule_ref=_resolve_rule_ref(r[2]), note=r[3], source=r[4], created_at=r[5]) for r in rows]
    except Exception as exc:
        logger.warning(f"get_cve_detections error: {exc}")
        return []

def add_cve_detection(cve_id: str, rule_ref: Optional[str] = None, note: Optional[str] = None, source: str = "manual") -> Optional[VulnDetection]:
    """Add a new detection entry for a CVE. Returns the created entry."""
    cve_id = cve_id.upper()
    with _get_conn() as conn:
        row = conn.execute(
            "INSERT INTO vuln_detections (cve_id, rule_ref, note, source) VALUES (?, ?, ?, ?) RETURNING id, cve_id, rule_ref, note, source, created_at",
            [cve_id, rule_ref, note, source]).fetchone()
    if row:
        return VulnDetection(id=row[0], cve_id=row[1], rule_ref=row[2], note=row[3], source=row[4], created_at=row[5])
    return None

def remove_cve_detection(detection_id: str) -> bool:
    """Remove a single detection entry by its ID."""
    with _get_conn() as conn:
        before = conn.execute("SELECT COUNT(*) FROM vuln_detections WHERE id = ?", [detection_id]).fetchone()[0]
        conn.execute("DELETE FROM vuln_detections WHERE id = ?", [detection_id])
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


def get_all_siem_rules() -> list:
    """Return a lightweight list of ALL SIEM rules [{rule_id, name}] for dropdowns."""
    from app.services.database import get_database_service
    db = get_database_service()
    with db.get_connection() as conn:
        rows = conn.execute(
            "SELECT rule_id, name FROM detection_rules ORDER BY name"
        ).fetchall()
    return [{"rule_id": r[0], "name": r[1]} for r in rows]


# --- Tier 3: Applied Detection CRUD ---

def apply_detection(detection_id: str, system_id: Optional[str] = None, host_id: Optional[str] = None) -> Optional[AppliedDetection]:
    """Apply a detection rule to a system or individual host (Tier 3).
    When system_id is given, creates per-host rows for every host in that system
    so that coverage can be managed individually per host."""
    if not system_id and not host_id:
        return None
    last: Optional[AppliedDetection] = None
    with _get_conn() as conn:
        if host_id:
            dup = conn.execute(
                "SELECT id FROM applied_detections WHERE detection_id = ? AND host_id = ?",
                [detection_id, host_id]).fetchone()
            if dup:
                return AppliedDetection(id=dup[0], detection_id=detection_id, host_id=host_id)
            row = conn.execute(
                "INSERT INTO applied_detections (detection_id, system_id, host_id) VALUES (?, NULL, ?) RETURNING id, detection_id, system_id, host_id, applied_at",
                [detection_id, host_id]).fetchone()
            if row:
                return AppliedDetection(id=row[0], detection_id=row[1], system_id=row[2], host_id=row[3], applied_at=row[4])
        elif system_id:
            # Remove any old system-level row (system_id set, host_id NULL)
            conn.execute(
                "DELETE FROM applied_detections WHERE detection_id = ? AND system_id = ? AND host_id IS NULL",
                [detection_id, system_id])
            # Expand to per-host rows so each host can be managed individually
            host_rows = conn.execute(
                "SELECT id FROM hosts WHERE system_id = ?", [system_id]
            ).fetchall()
            if not host_rows:
                # No hosts in system — store a system-level row so coverage is tracked.
                # Will be expanded to per-host rows when hosts are later added.
                dup = conn.execute(
                    "SELECT id FROM applied_detections WHERE detection_id = ? AND system_id = ? AND host_id IS NULL",
                    [detection_id, system_id]).fetchone()
                if not dup:
                    row = conn.execute(
                        "INSERT INTO applied_detections (detection_id, system_id, host_id) VALUES (?, ?, NULL) RETURNING id, detection_id, system_id, host_id, applied_at",
                        [detection_id, system_id]).fetchone()
                    if row:
                        last = AppliedDetection(id=row[0], detection_id=row[1], system_id=row[2], host_id=row[3], applied_at=row[4])
                else:
                    last = AppliedDetection(id=dup[0], detection_id=detection_id, system_id=system_id)
            else:
                for (hid,) in host_rows:
                    dup = conn.execute(
                        "SELECT id FROM applied_detections WHERE detection_id = ? AND host_id = ?",
                        [detection_id, hid]).fetchone()
                    if dup:
                        last = AppliedDetection(id=dup[0], detection_id=detection_id, host_id=hid)
                        continue
                    row = conn.execute(
                        "INSERT INTO applied_detections (detection_id, system_id, host_id) VALUES (?, NULL, ?) RETURNING id, detection_id, system_id, host_id, applied_at",
                        [detection_id, hid]).fetchone()
                    if row:
                        last = AppliedDetection(id=row[0], detection_id=row[1], system_id=row[2], host_id=row[3], applied_at=row[4])
    return last


def remove_applied_detection(applied_id: str) -> bool:
    """Remove an applied detection entry by its ID."""
    with _get_conn() as conn:
        before = conn.execute("SELECT COUNT(*) FROM applied_detections WHERE id = ?", [applied_id]).fetchone()[0]
        conn.execute("DELETE FROM applied_detections WHERE id = ?", [applied_id])
    return before > 0


def remove_detection_for_system(detection_id: str, system_id: str) -> int:
    """Remove applied detection rows for all hosts in a system (and any system-level row). Returns count removed."""
    with _get_conn() as conn:
        count = 0
        host_ids = [r[0] for r in conn.execute(
            "SELECT id FROM hosts WHERE system_id = ?", [system_id]).fetchall()]
        if host_ids:
            placeholders = ",".join("?" for _ in host_ids)
            count += conn.execute(
                f"DELETE FROM applied_detections WHERE detection_id = ? AND host_id IN ({placeholders})",
                [detection_id] + host_ids).rowcount
        # Also remove system-level row (used when system has no hosts)
        count += conn.execute(
            "DELETE FROM applied_detections WHERE detection_id = ? AND system_id = ? AND host_id IS NULL",
            [detection_id, system_id]).rowcount
    return count


def _load_applied_detections() -> Dict[str, List[AppliedDetection]]:
    """Load all applied detections keyed by detection_id for fast lookup.
    Migrates any legacy system-level rows (system_id set, host_id NULL) to per-host rows."""
    try:
        with _get_conn() as conn:
            # Migrate legacy system-level rows to per-host rows
            legacy = conn.execute(
                "SELECT id, detection_id, system_id FROM applied_detections WHERE system_id IS NOT NULL AND host_id IS NULL"
            ).fetchall()
            for leg_id, det_id, sys_id in legacy:
                host_ids = [r[0] for r in conn.execute(
                    "SELECT id FROM hosts WHERE system_id = ?", [sys_id]).fetchall()]
                if not host_ids:
                    continue  # Keep system-level row when system has no hosts
                for hid in host_ids:
                    dup = conn.execute(
                        "SELECT id FROM applied_detections WHERE detection_id = ? AND host_id = ?",
                        [det_id, hid]).fetchone()
                    if not dup:
                        conn.execute(
                            "INSERT INTO applied_detections (detection_id, system_id, host_id) VALUES (?, NULL, ?)",
                            [det_id, hid])
                conn.execute("DELETE FROM applied_detections WHERE id = ?", [leg_id])

            rows = conn.execute(
                "SELECT id, detection_id, system_id, host_id, applied_at FROM applied_detections"
            ).fetchall()
        result: Dict[str, List[AppliedDetection]] = {}
        for r in rows:
            ad = AppliedDetection(id=r[0], detection_id=r[1], system_id=r[2], host_id=r[3], applied_at=r[4])
            result.setdefault(r[1], []).append(ad)
        return result
    except Exception as exc:
        logger.warning(f"_load_applied_detections error: {exc}")
        return {}


def _compute_coverage_status(host_id: str, system_id: str,
                             cve_detections: List[VulnDetection],
                             applied_map: Dict[str, List[AppliedDetection]],
                             blind_spots: Optional[List[BlindSpot]] = None) -> Tuple[str, List[str]]:
    """Compute traffic-light status for a host against a CVE's detections.
    Returns (status, rule_names) where status is 'red'|'amber'|'grey' and rule_names are applied rule labels."""
    # Check for blind spots first
    if blind_spots:
        for bs in blind_spots:
            if bs.host_id == host_id:
                return "grey", []
    if not cve_detections:
        return "red", []
    applied_names: List[str] = []
    for det in cve_detections:
        for ad in applied_map.get(det.id, []):
            if ad.host_id == host_id:
                label = _resolve_rule_ref(det.rule_ref) or det.note or "Rule"
                if label not in applied_names:
                    applied_names.append(label)
    if applied_names:
        return "amber", applied_names
    return "red", []


def _resolve_rule_ref(rule_ref: Optional[str]) -> Optional[str]:
    """If rule_ref looks like a UUID/rule_id, look up the human-readable name
    from detection_rules. Otherwise return as-is."""
    if not rule_ref:
        return None
    # Quick heuristic: UUIDs are 32+ hex chars with dashes
    stripped = rule_ref.replace("-", "")
    if len(stripped) >= 32 and all(c in '0123456789abcdefABCDEF' for c in stripped):
        try:
            with _get_conn() as conn:
                row = conn.execute(
                    "SELECT name FROM detection_rules WHERE rule_id = ?", [rule_ref]
                ).fetchone()
            if row and row[0]:
                return row[0]
        except Exception:
            pass
    return rule_ref


def _enrich_detections_with_applied(detections: List[VulnDetection],
                                    applied_map: Dict[str, List[AppliedDetection]]) -> List[VulnDetection]:
    """Attach applied_to entries to each VulnDetection."""
    for det in detections:
        det.applied_to = applied_map.get(det.id, [])
    return detections


def _load_all_blind_spots(entity_type: str) -> Dict[str, List[BlindSpot]]:
    """Load all blind spots of a given type, grouped by entity_id."""
    try:
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT id, entity_type, entity_id, system_id, host_id, reason, created_by, created_at, "
                "COALESCE(override_type, 'gap') "
                "FROM blind_spots WHERE entity_type = ?",
                [entity_type],
            ).fetchall()
        result: Dict[str, List[BlindSpot]] = {}
        for r in rows:
            bs = BlindSpot(id=r[0], entity_type=r[1], entity_id=r[2], system_id=r[3],
                           host_id=r[4], reason=r[5], created_by=r[6], created_at=r[7],
                           override_type=r[8])
            result.setdefault(r[2], []).append(bs)
        return result
    except Exception:
        return {}

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
    # Invalidate memory cache so next load picks up the new file
    global _cisa_kev_cache, _cisa_kev_mtime, _cisa_kev_path_used
    _cisa_kev_cache = None
    _cisa_kev_mtime = None
    _cisa_kev_path_used = None
    return count


# ---------------------------------------------------------------------------
# Report Data Builders
# ---------------------------------------------------------------------------

def build_system_report_data(system_id: str) -> Optional[Dict]:
    """Build all data needed for System detail reports (CISO + Technical)."""
    system = get_system(system_id)
    if not system:
        return None

    kev = _load_cisa_kev()
    kev_by_id = {k.get("cveID", ""): k for k in (kev or [])}
    detections = list_cve_detections()
    applied_map = _load_applied_detections()
    for dets in detections.values():
        _enrich_detections_with_applied(dets, applied_map)

    all_software = _list_all_software_by_host()
    hosts = list_hosts(system_id)

    # Load all CVE blind spots once
    all_blind_spots = _load_all_blind_spots("cve")

    # Build per-host vulnerability data with full RAG status
    host_rows: List[Dict] = []
    all_cves: Dict[str, Dict] = {}  # cve_id -> {kev_entry, hosts: [...], detections, techniques}

    for host in hosts:
        software = all_software.get(host.id, [])
        host_cves: List[Dict] = []
        if software and kev:
            matches = _match_software_against_kev(software, kev, host_os=host.os or "")
            for cve_id, sw_names in matches.items():
                cve_dets = detections.get(cve_id, [])
                cve_bs = all_blind_spots.get(cve_id, [])
                status, rule_names = _compute_coverage_status(host.id, system_id, cve_dets, applied_map, cve_bs)
                host_cves.append({
                    "cve_id": cve_id,
                    "status": status,
                    "rule_names": rule_names,
                    "sw_names": sw_names,
                })
                if cve_id not in all_cves:
                    kev_entry = kev_by_id.get(cve_id, {})
                    techniques = get_cve_techniques(cve_id)
                    all_cves[cve_id] = {
                        "cve_id": cve_id,
                        "vulnerability_name": kev_entry.get("vulnerabilityName", cve_id),
                        "vendor_project": kev_entry.get("vendorProject", ""),
                        "product": kev_entry.get("product", ""),
                        "short_description": kev_entry.get("shortDescription", ""),
                        "known_ransomware": (kev_entry.get("knownRansomwareCampaignUse", "") or "").lower() in ("known", "yes"),
                        "date_added": kev_entry.get("dateAdded", ""),
                        "techniques": [{"id": t.technique_id, "name": t.name, "has_detection": t.has_detection} for t in techniques],
                        "detections": [{"rule_ref": d.rule_ref, "note": d.note, "source": d.source} for d in cve_dets],
                        "hosts_red": [],
                        "hosts_amber": [],
                        "hosts_grey": [],
                    }
                if status == "red":
                    all_cves[cve_id]["hosts_red"].append({"name": host.name, "ip": host.ip_address or ""})
                elif status == "grey":
                    all_cves[cve_id]["hosts_grey"].append({
                        "name": host.name, "ip": host.ip_address or "",
                        "reason": next((bs.reason for bs in cve_bs if bs.host_id == host.id), ""),
                    })
                else:
                    all_cves[cve_id]["hosts_amber"].append({
                        "name": host.name, "ip": host.ip_address or "", "rule_names": rule_names,
                    })

        red_count = sum(1 for c in host_cves if c["status"] == "red")
        amber_count = sum(1 for c in host_cves if c["status"] == "amber")
        grey_count = sum(1 for c in host_cves if c["status"] == "grey")
        if not host_cves:
            rag = "green"
        elif red_count == 0 and grey_count == 0:
            rag = "amber"
        elif red_count == 0:
            rag = "grey"
        else:
            rag = "red"

        host_rows.append({
            "name": host.name,
            "ip": host.ip_address or "",
            "os": host.os or "",
            "rag": rag,
            "cve_count": len(host_cves),
            "red_count": red_count,
            "amber_count": amber_count,
            "grey_count": grey_count,
            "cves": host_cves,
        })

    # Metrics
    total_hosts = len(hosts)
    total_cves = len(all_cves)
    red_hosts = sum(1 for h in host_rows if h["rag"] == "red")
    amber_hosts = sum(1 for h in host_rows if h["rag"] == "amber")
    green_hosts = sum(1 for h in host_rows if h["rag"] == "green")
    grey_hosts = sum(1 for h in host_rows if h["rag"] == "grey")
    total_red_pairs = sum(len(c["hosts_red"]) for c in all_cves.values())
    total_amber_pairs = sum(len(c["hosts_amber"]) for c in all_cves.values())
    total_grey_pairs = sum(len(c["hosts_grey"]) for c in all_cves.values())

    # Top 5 critical CVEs by number of at-risk hosts
    sorted_cves = sorted(all_cves.values(), key=lambda c: len(c["hosts_red"]), reverse=True)
    top5 = sorted_cves[:5]

    return {
        "system": {"name": system.name, "description": system.description or "", "classification": system.classification or ""},
        "generated_at": __import__("datetime").datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "total_hosts": total_hosts,
        "total_cves": total_cves,
        "red_hosts": red_hosts,
        "amber_hosts": amber_hosts,
        "green_hosts": green_hosts,
        "grey_hosts": grey_hosts,
        "total_red_pairs": total_red_pairs,
        "total_amber_pairs": total_amber_pairs,
        "total_grey_pairs": total_grey_pairs,
        "coverage_ratio": round(total_amber_pairs / (total_amber_pairs + total_red_pairs) * 100) if (total_amber_pairs + total_red_pairs) else 100,
        "top5_cves": top5,
        "host_rows": host_rows,
        "all_cves": sorted_cves,
        "baselines": get_system_baselines(system_id),
        "snapshots": get_baseline_snapshots(system_id),
    }


def build_cve_report_data(cve_id: str, search_filter: str = "") -> Optional[Dict]:
    """Build all data needed for the CVE Audit Report."""
    kev_entries = _load_cisa_kev()
    kev_entry = next((k for k in kev_entries if k.get("cveID", "").upper() == cve_id.upper()), None)
    if not kev_entry:
        return None

    detections_map = list_cve_detections()
    applied_map = _load_applied_detections()
    cve_dets = detections_map.get(cve_id.upper(), [])
    _enrich_detections_with_applied(cve_dets, applied_map)

    techniques = get_cve_techniques(cve_id)
    technique_rules = get_rules_for_cve_techniques(cve_id)
    cve_blind_spots = get_blind_spots("cve", cve_id.upper())

    # Build affected systems/hosts matrix
    all_hosts_by_sys = _list_all_hosts_by_system()
    all_software = _list_all_software_by_host()
    systems_map: Dict[str, Dict] = {}

    for system in list_systems():
        for host in all_hosts_by_sys.get(system.id, []):
            # Apply search filter
            if search_filter:
                q = search_filter.lower()
                if q not in host.name.lower() and q not in (host.ip_address or "").lower():
                    continue
            software = all_software.get(host.id, [])
            if not software:
                continue
            matches = _match_software_against_kev(software, kev_entries, host_os=host.os or "")
            if cve_id.upper() not in {k.upper() for k in matches}:
                continue
            status, rule_names = _compute_coverage_status(host.id, system.id, cve_dets, applied_map, cve_blind_spots)
            bs_reason = next((bs.reason for bs in cve_blind_spots if bs.host_id == host.id), "")
            if system.id not in systems_map:
                systems_map[system.id] = {
                    "system_name": system.name,
                    "system_id": system.id,
                    "hosts": [],
                }
            systems_map[system.id]["hosts"].append({
                "name": host.name,
                "ip": host.ip_address or "",
                "os": host.os or "",
                "status": status,
                "rule_names": rule_names,
                "blind_spot_reason": bs_reason,
            })

    grouped_systems = sorted(systems_map.values(), key=lambda s: s["system_name"])

    total_hosts = sum(len(s["hosts"]) for s in grouped_systems)
    red_count = sum(1 for s in grouped_systems for h in s["hosts"] if h["status"] == "red")
    amber_count = sum(1 for s in grouped_systems for h in s["hosts"] if h["status"] == "amber")
    grey_count = sum(1 for s in grouped_systems for h in s["hosts"] if h["status"] == "grey")

    kev_ransomware = (kev_entry.get("knownRansomwareCampaignUse", "") or "").lower() in ("known", "yes")

    return {
        "cve_id": cve_id.upper(),
        "vulnerability_name": kev_entry.get("vulnerabilityName", cve_id),
        "vendor_project": kev_entry.get("vendorProject", ""),
        "product": kev_entry.get("product", ""),
        "short_description": kev_entry.get("shortDescription", ""),
        "date_added": kev_entry.get("dateAdded", ""),
        "due_date": kev_entry.get("dueDate", ""),
        "known_ransomware": kev_ransomware,
        "notes": kev_entry.get("notes", ""),
        "is_kev": True,
        "techniques": [{"id": t.technique_id, "name": t.name, "has_detection": t.has_detection, "rule_count": t.rule_count} for t in techniques],
        "detections": [{"rule_ref": d.rule_ref, "note": d.note, "source": d.source} for d in cve_dets],
        "technique_rules": {tid: [{"name": r.name, "severity": getattr(r, "severity", "")} for r in rules] for tid, rules in technique_rules.items()},
        "grouped_systems": grouped_systems,
        "total_systems": len(grouped_systems),
        "total_hosts": total_hosts,
        "red_count": red_count,
        "amber_count": amber_count,
        "grey_count": grey_count,
        "generated_at": __import__("datetime").datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    }


def build_baseline_report_data(baseline_id: str) -> Optional[Dict]:
    """Build all data needed for a Baseline Assurance Report.

    Collects the baseline definition, all applied systems, and per-system
    step-level RAG coverage.
    """
    playbook = get_playbook(baseline_id)
    if not playbook:
        return None

    # Per-step per-system RAG coverage
    step_coverage = get_baseline_step_coverage(baseline_id)

    # Collect applied systems with IDs
    with _get_conn() as conn:
        sys_rows = conn.execute(
            "SELECT sb.system_id, s.name FROM system_baselines sb "
            "JOIN systems s ON s.id = sb.system_id WHERE sb.playbook_id = ? ORDER BY s.name",
            [baseline_id],
        ).fetchall()
    system_ids = [r[0] for r in sys_rows]
    system_names = {r[0]: r[1] for r in sys_rows}

    # Build per-system summary with step-level detail
    systems = []
    for sys_id in system_ids:
        sys_name = system_names[sys_id]
        covered = 0
        gap = 0
        red = 0
        na = 0
        step_details = []
        for step in playbook.tactics:
            cov_entries = step_coverage.get(step.id, [])
            entry = next((e for e in cov_entries if e["system_id"] == sys_id), None)
            status = entry["status"] if entry else "red"
            if status == "green":
                covered += 1
            elif status == "amber":
                gap += 1
            elif status == "grey":
                na += 1
            else:
                red += 1
            step_details.append({
                "step_id": step.id,
                "step_number": step.step_number,
                "title": step.title,
                "tactic": step.tactic,
                "status": status,
                "applied_dets": [],
                "blind_spot_reason": "",
            })
        total = len(playbook.tactics)
        effective = total - na
        pct = round(covered / effective * 100) if effective else (100 if total else 0)
        systems.append({
            "system_id": sys_id,
            "system_name": sys_name,
            "coverage_pct": pct,
            "covered_steps": covered,
            "gap_steps": gap,
            "red_steps": red,
            "na_steps": na,
            "tactics": step_details,
        })

    # Enrich step details with applied_dets using get_system_baselines data
    # This is slightly expensive but gives full detail for each system
    for sys_info in systems:
        sb_list = get_system_baselines(sys_info["system_id"])
        matching = next((sb for sb in sb_list if sb["playbook_id"] == baseline_id), None)
        if matching:
            for step_detail in sys_info["tactics"]:
                matching_step = next(
                    (t for t in matching["tactics"] if t["step_id"] == step_detail["step_id"]), None
                )
                if matching_step:
                    step_detail["applied_dets"] = matching_step.get("applied_dets", [])
                    step_detail["blind_spot_reason"] = matching_step.get("blind_spot_reason", "")

    # Aggregate metrics
    total_techniques = sum(len(step.techniques) for step in playbook.tactics)
    total_detections = sum(len(step.detections) for step in playbook.tactics)
    avg_coverage = round(sum(s["coverage_pct"] for s in systems) / len(systems)) if systems else 0

    # Build steps list for template
    steps = []
    for step in playbook.tactics:
        steps.append({
            "step_number": step.step_number,
            "title": step.title,
            "tactic": step.tactic,
            "techniques": [
                {"technique_id": t.technique_id, "has_detection": False}
                for t in step.techniques
            ],
            "detections": [
                {"rule_ref": d.rule_ref, "note": d.note}
                for d in step.detections
            ],
        })

    return {
        "baseline_id": baseline_id,
        "baseline_name": playbook.name,
        "description": playbook.description or "",
        "total_systems": len(systems),
        "total_steps": len(playbook.tactics),
        "total_techniques": total_techniques,
        "total_detections": total_detections,
        "avg_coverage": avg_coverage,
        "steps": steps,
        "systems": systems,
        "generated_at": __import__("datetime").datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    }


# ---------------------------------------------------------------------------
# Baselines — Engine
# ---------------------------------------------------------------------------

def list_playbooks() -> List[Playbook]:
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, name, description, created_at, updated_at FROM playbooks ORDER BY name"
        ).fetchall()
    result = []
    for r in rows:
        pb = Playbook(id=r[0], name=r[1], description=r[2] or "", created_at=r[3], updated_at=r[4])
        pb.tactics = _get_playbook_steps(r[0])
        result.append(pb)
    return result


def get_baseline_step_coverage(baseline_id: str) -> Dict[str, List[Dict]]:
    """Compute per-step per-system RAG status for a single baseline.

    Returns {step_id: [{system_id, system_name, status}, ...]} where
    status is one of 'green', 'amber', 'red', 'grey'.
    """
    with _get_conn() as conn:
        # Applied systems
        sys_rows = conn.execute(
            "SELECT sb.system_id, s.name FROM system_baselines sb "
            "JOIN systems s ON s.id = sb.system_id WHERE sb.playbook_id = ? ORDER BY s.name",
            [baseline_id],
        ).fetchall()
        if not sys_rows:
            return {}
        system_ids = [r[0] for r in sys_rows]
        system_names = {r[0]: r[1] for r in sys_rows}

        # Steps for this baseline
        steps = conn.execute(
            "SELECT id FROM playbook_steps WHERE playbook_id = ?", [baseline_id]
        ).fetchall()
        step_ids = [r[0] for r in steps]
        if not step_ids:
            return {}

        sp = ",".join("?" for _ in step_ids)

        # Step detection IDs per step
        sd_rows = conn.execute(
            f"SELECT step_id, id FROM step_detections WHERE step_id IN ({sp})", step_ids
        ).fetchall()
        step_det_ids: Dict[str, set] = {}
        for sid, det_id in sd_rows:
            step_det_ids.setdefault(sid, set()).add(det_id)

        # Collect all step_detection IDs across all steps
        all_step_det_ids = set()
        for dids in step_det_ids.values():
            all_step_det_ids |= dids

        # Blind spots for tactic entity_type
        bs_rows = conn.execute(
            f"SELECT entity_id, system_id, COALESCE(override_type, 'gap') FROM blind_spots "
            f"WHERE entity_type = 'tactic' AND entity_id IN ({sp})", step_ids
        ).fetchall()
        step_gap: Dict[str, set] = {}
        step_na: Dict[str, set] = {}
        for eid, sid, otype in bs_rows:
            if otype == "na":
                step_na.setdefault(eid, set()).add(sid)
            else:
                step_gap.setdefault(eid, set()).add(sid)

        # Hosts per system + applied rules per system
        sid_ph = ",".join("?" for _ in system_ids)
        host_rows = conn.execute(
            f"SELECT id, system_id FROM hosts WHERE system_id IN ({sid_ph})", system_ids
        ).fetchall()
        sys_hosts: Dict[str, list] = {}
        all_host_ids = []
        for hid, sid in host_rows:
            sys_hosts.setdefault(sid, []).append(hid)
            all_host_ids.append(hid)

        # Which step_detections are applied to which hosts?
        # Maps: system_id -> set of step_detection_ids that are applied to at least one host
        system_applied_det_ids: Dict[str, set] = {s: set() for s in system_ids}
        if all_host_ids and all_step_det_ids:
            hp = ",".join("?" for _ in all_host_ids)
            dp = ",".join("?" for _ in all_step_det_ids)
            ad_rows = conn.execute(
                f"SELECT host_id, detection_id FROM applied_detections "
                f"WHERE host_id IN ({hp}) AND detection_id IN ({dp})",
                list(all_host_ids) + list(all_step_det_ids),
            ).fetchall()
            # Build host->system reverse map
            host_to_sys: Dict[str, str] = {}
            for hid, sid in host_rows:
                host_to_sys[hid] = sid
            for hid, did in ad_rows:
                sid = host_to_sys.get(hid)
                if sid:
                    system_applied_det_ids[sid].add(did)

    # Build per-step coverage
    result: Dict[str, List[Dict]] = {}
    for step_id in step_ids:
        det_ids = step_det_ids.get(step_id, set())
        gap_sys = step_gap.get(step_id, set())
        na_sys = step_na.get(step_id, set())
        entries = []
        for sys_id in system_ids:
            # Green = at least one of this step's detections has been applied to a host in this system
            if det_ids and (det_ids & system_applied_det_ids.get(sys_id, set())):
                status = "green"
            elif sys_id in na_sys:
                status = "grey"
            elif sys_id in gap_sys:
                status = "amber"
            else:
                status = "red"
            entries.append({"system_id": sys_id, "system_name": system_names[sys_id], "status": status})
        result[step_id] = entries
    return result


def get_baselines_overview() -> List[Dict]:
    """Efficient overview of all baselines for the listing page.

    Returns a list of dicts with:
      id, name, description, step_count, detection_count,
      system_count, worst_status ('green'|'amber'|'red'|'grey'|None)
    Uses a single DB connection for all queries.
    """
    with _get_conn() as conn:
        # All playbooks
        pbs = conn.execute(
            "SELECT id, name, description FROM playbooks ORDER BY name"
        ).fetchall()
        if not pbs:
            return []
        pb_ids = [r[0] for r in pbs]
        placeholders = ",".join("?" for _ in pb_ids)

        # Step counts per playbook
        step_rows = conn.execute(
            f"SELECT playbook_id, COUNT(*) FROM playbook_steps WHERE playbook_id IN ({placeholders}) GROUP BY playbook_id",
            pb_ids,
        ).fetchall()
        step_counts = dict(step_rows)

        # Tactic counts per playbook (distinct tactics)
        tactic_rows = conn.execute(
            f"SELECT playbook_id, COUNT(DISTINCT COALESCE(NULLIF(tactic,''),'Other')) "
            f"FROM playbook_steps WHERE playbook_id IN ({placeholders}) GROUP BY playbook_id",
            pb_ids,
        ).fetchall()
        tactic_counts = dict(tactic_rows)

        # Detection counts per playbook (via step_detections)
        det_rows = conn.execute(
            f"SELECT ps.playbook_id, COUNT(DISTINCT sd.id) "
            f"FROM playbook_steps ps JOIN step_detections sd ON sd.step_id = ps.id "
            f"WHERE ps.playbook_id IN ({placeholders}) GROUP BY ps.playbook_id",
            pb_ids,
        ).fetchall()
        det_counts = dict(det_rows)

        # System counts per playbook
        sys_rows = conn.execute(
            f"SELECT playbook_id, COUNT(DISTINCT system_id) FROM system_baselines "
            f"WHERE playbook_id IN ({placeholders}) GROUP BY playbook_id",
            pb_ids,
        ).fetchall()
        sys_counts = dict(sys_rows)

        # Compute worst-case RAG per playbook for baselines with applied systems
        # Load all step IDs per playbook
        all_steps = conn.execute(
            f"SELECT id, playbook_id FROM playbook_steps WHERE playbook_id IN ({placeholders})",
            pb_ids,
        ).fetchall()
        step_to_pb = {r[0]: r[1] for r in all_steps}
        all_step_ids = list(step_to_pb.keys())

        # Load detection IDs per step (for applied_detections matching)
        step_det_id_sets = {}
        all_step_det_ids_flat = set()
        if all_step_ids:
            sp = ",".join("?" for _ in all_step_ids)
            sd_rows = conn.execute(
                f"SELECT step_id, id FROM step_detections WHERE step_id IN ({sp})",
                all_step_ids,
            ).fetchall()
            for sid, det_id in sd_rows:
                step_det_id_sets.setdefault(sid, set()).add(det_id)
                all_step_det_ids_flat.add(det_id)

        # Load blind spots for tactics (with override_type)
        bs_rows = conn.execute(
            "SELECT entity_id, system_id, COALESCE(override_type, 'gap') FROM blind_spots WHERE entity_type = 'tactic'"
        ).fetchall()
        step_blind_spots = {}      # step_id -> set(system_id) for gap
        step_na_spots = {}         # step_id -> set(system_id) for na
        for eid, sid, otype in bs_rows:
            if otype == "na":
                step_na_spots.setdefault(eid, set()).add(sid)
            else:
                step_blind_spots.setdefault(eid, set()).add(sid)

        # Load all system_baselines
        sb_rows = conn.execute(
            f"SELECT playbook_id, system_id FROM system_baselines WHERE playbook_id IN ({placeholders})",
            pb_ids,
        ).fetchall()
        pb_systems = {}
        for pbid, sid in sb_rows:
            pb_systems.setdefault(pbid, set()).add(sid)

        # Load hosts per system and applied rules per system (for systems in baselines)
        all_system_ids = set()
        for sids in pb_systems.values():
            all_system_ids |= sids

        # Build set of applied step_detection IDs per system
        system_applied_det_ids = {}
        if all_system_ids:
            sid_list = list(all_system_ids)
            sp = ",".join("?" for _ in sid_list)
            # Batch: get all hosts for all relevant systems in one query
            all_host_rows = conn.execute(
                f"SELECT id, system_id FROM hosts WHERE system_id IN ({sp})", sid_list,
            ).fetchall()
            sys_hosts = {}
            all_host_ids = []
            for hid, sid in all_host_rows:
                sys_hosts.setdefault(sid, []).append(hid)
                all_host_ids.append(hid)

            # Batch: get applied_detections that match our step_detection IDs
            host_applied_dets = {}  # host_id -> set(detection_id)
            if all_host_ids and all_step_det_ids_flat:
                hp = ",".join("?" for _ in all_host_ids)
                dp = ",".join("?" for _ in all_step_det_ids_flat)
                ad_rows = conn.execute(
                    f"SELECT host_id, detection_id FROM applied_detections "
                    f"WHERE host_id IN ({hp}) AND detection_id IN ({dp})",
                    all_host_ids + list(all_step_det_ids_flat),
                ).fetchall()
                for hid, did in ad_rows:
                    host_applied_dets.setdefault(hid, set()).add(did)

            for sid in all_system_ids:
                det_ids_for_sys = set()
                for hid in sys_hosts.get(sid, []):
                    det_ids_for_sys |= host_applied_dets.get(hid, set())
                system_applied_det_ids[sid] = det_ids_for_sys
        else:
            for sid in all_system_ids:
                system_applied_det_ids[sid] = set()

    # Compute worst status per playbook
    # Priority: red > amber > grey > green
    STATUS_PRIORITY = {"red": 0, "amber": 1, "grey": 2, "green": 3}

    results = []
    for pb_id, pb_name, pb_desc in pbs:
        system_ids = pb_systems.get(pb_id, set())
        step_ids_for_pb = [sid for sid, pid in step_to_pb.items() if pid == pb_id]
        worst = "green"

        if system_ids and step_ids_for_pb:
            for step_id in step_ids_for_pb:
                det_ids = step_det_id_sets.get(step_id, set())
                bs_systems = step_blind_spots.get(step_id, set())
                na_systems = step_na_spots.get(step_id, set())
                for sys_id in system_ids:
                    if det_ids and (det_ids & system_applied_det_ids.get(sys_id, set())):
                        status = "green"
                    elif sys_id in na_systems:
                        status = "grey"
                    elif sys_id in bs_systems:
                        status = "amber"
                    else:
                        status = "red"
                    if STATUS_PRIORITY.get(status, 4) < STATUS_PRIORITY.get(worst, 4):
                        worst = status
                    if worst == "red":
                        break
                if worst == "red":
                    break
        elif not system_ids:
            worst = None  # Not applied to any system

        results.append({
            "id": pb_id,
            "name": pb_name,
            "description": pb_desc or "",
            "step_count": step_counts.get(pb_id, 0),
            "tactic_count": tactic_counts.get(pb_id, 0),
            "detection_count": det_counts.get(pb_id, 0),
            "system_count": sys_counts.get(pb_id, 0),
            "worst_status": worst,
        })
    return results


def get_playbook_header(playbook_id: str) -> Optional[Playbook]:
    """Lightweight playbook fetch — no steps loaded. For breadcrumbs etc."""
    with _get_conn() as conn:
        r = conn.execute(
            "SELECT id, name, description, created_at, updated_at FROM playbooks WHERE id = ?",
            [playbook_id],
        ).fetchone()
    if not r:
        return None
    return Playbook(id=r[0], name=r[1], description=r[2] or "", created_at=r[3], updated_at=r[4])


def get_playbook(playbook_id: str) -> Optional[Playbook]:
    with _get_conn() as conn:
        r = conn.execute(
            "SELECT id, name, description, created_at, updated_at FROM playbooks WHERE id = ?",
            [playbook_id],
        ).fetchone()
    if not r:
        return None
    pb = Playbook(id=r[0], name=r[1], description=r[2] or "", created_at=r[3], updated_at=r[4])
    pb.tactics = _get_playbook_steps(playbook_id)
    return pb


def _get_playbook_steps(playbook_id: str) -> List[PlaybookStep]:
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, playbook_id, step_number, title, technique_id, required_rule, description, tactic "
            "FROM playbook_steps WHERE playbook_id = ? ORDER BY step_number",
            [playbook_id],
        ).fetchall()
        if not rows:
            return []

        step_ids = [r[0] for r in rows]
        sp = ",".join("?" for _ in step_ids)

        # Batch: all techniques for all steps
        tech_rows = conn.execute(
            f"SELECT id, step_id, technique_id FROM step_techniques WHERE step_id IN ({sp}) ORDER BY technique_id",
            step_ids,
        ).fetchall()
        step_techs = {}
        for tid, sid, techid in tech_rows:
            step_techs.setdefault(sid, []).append(StepTechnique(id=tid, step_id=sid, technique_id=techid))

        # Batch: all detections for all steps
        det_rows = conn.execute(
            f"SELECT id, step_id, rule_ref, note, source FROM step_detections WHERE step_id IN ({sp}) ORDER BY rule_ref",
            step_ids,
        ).fetchall()
        step_dets = {}
        for did, sid, rref, note, source in det_rows:
            step_dets.setdefault(sid, []).append(
                StepDetection(id=did, step_id=sid, rule_ref=rref or "", note=note or "", source=source or "manual")
            )

    steps = []
    for r in rows:
        step_id = r[0]
        step = PlaybookStep(
            id=step_id, playbook_id=r[1], step_number=r[2], title=r[3],
            technique_id=r[4] or "", required_rule=r[5] or "", description=r[6] or "",
            tactic=r[7] or "",
        )
        step.techniques = step_techs.get(step_id, [])
        step.detections = step_dets.get(step_id, [])
        steps.append(step)
    return steps


def _get_step_techniques(step_id: str) -> List[StepTechnique]:
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, step_id, technique_id FROM step_techniques WHERE step_id = ? ORDER BY technique_id",
            [step_id],
        ).fetchall()
    return [StepTechnique(id=r[0], step_id=r[1], technique_id=r[2]) for r in rows]


def _get_step_detections(step_id: str) -> List[StepDetection]:
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, step_id, rule_ref, note, source FROM step_detections WHERE step_id = ? ORDER BY rule_ref",
            [step_id],
        ).fetchall()
    return [StepDetection(id=r[0], step_id=r[1], rule_ref=r[2] or "", note=r[3] or "", source=r[4] or "manual") for r in rows]


def create_playbook(name: str, description: str = "") -> Playbook:
    with _get_conn() as conn:
        r = conn.execute(
            "INSERT INTO playbooks (name, description) VALUES (?, ?) RETURNING id, name, description, created_at, updated_at",
            [name, description],
        ).fetchone()
    return Playbook(id=r[0], name=r[1], description=r[2] or "", created_at=r[3], updated_at=r[4])


def update_playbook(playbook_id: str, name: str = None, description: str = None) -> Optional[Playbook]:
    """Update editable fields on a playbook (baseline)."""
    with _get_conn() as conn:
        sets, vals = [], []
        if name is not None:
            sets.append("name = ?"); vals.append(name)
        if description is not None:
            sets.append("description = ?"); vals.append(description)
        if sets:
            vals.append(playbook_id)
            conn.execute(f"UPDATE playbooks SET {', '.join(sets)} WHERE id = ?", vals)
    return get_playbook(playbook_id)


def generate_baseline_from_actor(
    actor_name: str,
    ttps: list,
    technique_tactic_map: dict,
    technique_name_map: dict,
    baseline_name: str = "",
    description: str = "",
) -> Playbook:
    """Create a Baseline Playbook from a Threat Actor's MITRE technique set.

    Uses a single DB connection for the entire operation to avoid
    per-step connection overhead.
    """
    from app.api.heatmap import get_tactic_display

    name = baseline_name.strip() if baseline_name.strip() else f"{actor_name} Baseline"
    desc = description.strip() if description.strip() else f"Auto-generated from {actor_name} threat profile ({len(ttps)} techniques)."

    sorted_ttps = sorted(set(t.strip().upper() for t in ttps if t.strip()))

    with _get_conn() as conn:
        # Create playbook
        pb_row = conn.execute(
            "INSERT INTO playbooks (name, description) VALUES (?, ?) "
            "RETURNING id, name, description, created_at, updated_at",
            [name, desc],
        ).fetchone()
        playbook = Playbook(id=pb_row[0], name=pb_row[1], description=pb_row[2] or "",
                            created_at=pb_row[3], updated_at=pb_row[4])

        # Insert all steps + junction rows in the same connection
        for idx, tech_id in enumerate(sorted_ttps, start=1):
            raw_tactic = technique_tactic_map.get(tech_id, "")
            tactic_display = get_tactic_display(raw_tactic)
            tech_name = technique_name_map.get(tech_id, tech_id)
            title = f"{tech_id} — {tech_name}" if tech_name != tech_id else tech_id
            tactic_val = tactic_display if tactic_display != "Other" else ""

            step_row = conn.execute(
                "INSERT INTO playbook_steps (playbook_id, step_number, title, technique_id, required_rule, description, tactic) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
                [playbook.id, idx, title, tech_id, "", "", tactic_val],
            ).fetchone()
            step_id = step_row[0]

            conn.execute(
                "INSERT INTO step_techniques (step_id, technique_id) VALUES (?, ?)",
                [step_id, tech_id],
            )

    return playbook


def delete_playbook(playbook_id: str) -> bool:
    with _get_conn() as conn:
        conn.execute("DELETE FROM playbook_steps WHERE playbook_id = ?", [playbook_id])
        conn.execute("DELETE FROM system_baselines WHERE playbook_id = ?", [playbook_id])
        cnt = conn.execute("DELETE FROM playbooks WHERE id = ?", [playbook_id]).rowcount
    return cnt > 0


def add_playbook_step(playbook_id: str, step_number: int, title: str,
                      technique_id: str = "", required_rule: str = "",
                      description: str = "", tactic: str = "") -> PlaybookStep:
    with _get_conn() as conn:
        r = conn.execute(
            "INSERT INTO playbook_steps (playbook_id, step_number, title, technique_id, required_rule, description, tactic) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id, playbook_id, step_number, title, technique_id, required_rule, description, tactic",
            [playbook_id, step_number, title, technique_id, required_rule, description, tactic],
        ).fetchone()
    step = PlaybookStep(id=r[0], playbook_id=r[1], step_number=r[2], title=r[3],
                        technique_id=r[4] or "", required_rule=r[5] or "", description=r[6] or "",
                        tactic=r[7] or "")
    # Auto-populate junction tables from legacy single fields
    if technique_id.strip():
        add_step_technique(step.id, technique_id.strip())
        step.techniques = _get_step_techniques(step.id)
    return step


def delete_playbook_step(step_id: str) -> bool:
    with _get_conn() as conn:
        conn.execute("DELETE FROM step_techniques WHERE step_id = ?", [step_id])
        conn.execute("DELETE FROM step_detections WHERE step_id = ?", [step_id])
        cnt = conn.execute("DELETE FROM playbook_steps WHERE id = ?", [step_id]).rowcount
    return cnt > 0


def apply_baseline(system_id: str, playbook_id: str) -> SystemBaseline:
    with _get_conn() as conn:
        dup = conn.execute(
            "SELECT id FROM system_baselines WHERE system_id = ? AND playbook_id = ?",
            [system_id, playbook_id],
        ).fetchone()
        if dup:
            return SystemBaseline(id=dup[0], system_id=system_id, playbook_id=playbook_id)
        r = conn.execute(
            "INSERT INTO system_baselines (system_id, playbook_id) VALUES (?, ?) "
            "RETURNING id, system_id, playbook_id, applied_at",
            [system_id, playbook_id],
        ).fetchone()
    return SystemBaseline(id=r[0], system_id=r[1], playbook_id=r[2], applied_at=r[3])


def remove_baseline(system_id: str, playbook_id: str) -> bool:
    with _get_conn() as conn:
        cnt = conn.execute(
            "DELETE FROM system_baselines WHERE system_id = ? AND playbook_id = ?",
            [system_id, playbook_id],
        ).rowcount
    return cnt > 0


def get_system_baselines(system_id: str) -> List[Dict]:
    """Return playbooks applied to a system with step-level RAG coverage."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT sb.id, sb.playbook_id, sb.applied_at, p.name, p.description "
            "FROM system_baselines sb JOIN playbooks p ON p.id = sb.playbook_id "
            "WHERE sb.system_id = ? ORDER BY p.name",
            [system_id],
        ).fetchall()

    # Get applied detections for this system's hosts (by step_detection ID)
    hosts = list_hosts(system_id)
    host_ids = {h.id for h in hosts}

    # Build set of step_detection IDs that have been applied to at least one host
    applied_step_det_ids: set = set()
    if host_ids:
        with _get_conn() as conn2:
            hp = ",".join("?" for _ in host_ids)
            ad_rows = conn2.execute(
                f"SELECT DISTINCT detection_id FROM applied_detections WHERE host_id IN ({hp})",
                list(host_ids),
            ).fetchall()
            applied_step_det_ids = {r[0] for r in ad_rows}

    # Also include system-level applied detections (for systems with no hosts)
    with _get_conn() as conn2:
        sys_ad = conn2.execute(
            "SELECT DISTINCT detection_id FROM applied_detections WHERE system_id = ? AND host_id IS NULL",
            [system_id],
        ).fetchall()
        applied_step_det_ids |= {r[0] for r in sys_ad}

    # Load blind spots for all tactics in one pass
    all_step_blind_spots = _load_all_blind_spots("tactic")

    # Load per-technique coverage data (from Sigma/SIEM rules) once
    try:
        from app.services.database import get_database_service
        _db = get_database_service()
        covered_ttps = _db.get_all_covered_ttps()
        ttp_rule_counts = _db.get_ttp_rule_counts()
    except Exception:
        covered_ttps = set()
        ttp_rule_counts = {}

    # Batch lookup: rule name -> (rule_id, space) for clickable rule badges
    rule_name_lookup: Dict[str, Dict] = {}
    try:
        with _get_conn() as conn:
            rrows = conn.execute(
                "SELECT rule_id, name, space FROM detection_rules ORDER BY name"
            ).fetchall()
        for rid, rname, rspace in rrows:
            rule_name_lookup[rname] = {"rule_id": rid, "space": rspace or "default"}
    except Exception:
        pass

    result = []
    for sb_id, pb_id, applied_at, pb_name, pb_desc in rows:
        steps = _get_playbook_steps(pb_id)
        step_results = []
        covered = 0
        gap_count = 0
        na_count = 0
        for step in steps:
            # Check blind spots — distinguish gap vs na
            step_bs = all_step_blind_spots.get(step.id, [])
            sys_blind_spots = [bs for bs in step_bs if bs.system_id == system_id]
            has_na = any(bs.override_type == "na" for bs in sys_blind_spots)
            has_gap = any(bs.override_type == "gap" for bs in sys_blind_spots)
            bs_reason = next((bs.reason for bs in sys_blind_spots), "")

            # Check if any detection for this step is applied to a host on this system
            step_det_ids = {d.id for d in step.detections}
            is_applied = bool(step_det_ids & applied_step_det_ids) if step_det_ids else False

            # 4-tier: green > grey > amber > red
            if is_applied:
                status = "green"
                covered += 1
            elif has_na:
                status = "grey"
                na_count += 1
            elif has_gap:
                status = "amber"
                gap_count += 1
            else:
                status = "red"

            # Split detections into applied/unapplied for this system
            step_applied = []
            step_unapplied = []
            for d in step.detections:
                label = d.rule_ref or d.note or "Rule"
                rule_info = rule_name_lookup.get(label) or rule_name_lookup.get(d.rule_ref or "")
                entry = {"id": d.id, "rule_ref": d.rule_ref, "note": d.note, "label": label,
                         "rule_id": rule_info["rule_id"] if rule_info else None,
                         "space": rule_info["space"] if rule_info else None}
                if d.id in applied_step_det_ids:
                    step_applied.append(entry)
                else:
                    step_unapplied.append(entry)

            step_results.append({
                "step_id": step.id,
                "step_number": step.step_number,
                "title": step.title,
                "tactic": step.tactic,
                "technique_id": step.technique_id,
                "description": step.description,
                "status": status,
                "blind_spot_reason": bs_reason,
                "override_type": "na" if has_na else ("gap" if has_gap else ""),
                "techniques": [
                    {
                        "technique_id": t.technique_id,
                        "has_detection": t.technique_id.upper() in covered_ttps,
                        "rule_count": ttp_rule_counts.get(t.technique_id.upper(), 0),
                    }
                    for t in step.techniques
                ],
                "detections": [{"id": d.id, "rule_ref": d.rule_ref, "note": d.note} for d in step.detections],
                "applied_dets": step_applied,
                "unapplied_dets": step_unapplied,
            })
        total = len(steps)
        # New math: Green / (Total - Grey) * 100
        effective_total = total - na_count
        pct = round(covered / effective_total * 100) if effective_total else (100 if total else 0)
        result.append({
            "baseline_id": sb_id,
            "playbook_id": pb_id,
            "playbook_name": pb_name,
            "playbook_description": pb_desc or "",
            "applied_at": applied_at,
            "tactics": step_results,
            "total_steps": total,
            "covered_steps": covered,
            "gap_steps": gap_count,
            "na_steps": na_count,
            "coverage_pct": pct,
        })
    return result


def _get_all_rule_names() -> Dict[str, str]:
    """Return {rule_name_lower: rule_id} for all detection rules."""
    try:
        with _get_conn() as conn:
            rows = conn.execute("SELECT rule_id, name FROM detection_rules").fetchall()
        return {r[1].lower(): r[0] for r in rows if r[1]}
    except Exception:
        return {}


def _get_applied_rule_names_for_hosts(host_ids: set) -> set:
    """Return a set of lowercased rule names / rule_refs applied to any of the given hosts."""
    if not host_ids:
        return set()
    try:
        with _get_conn() as conn:
            # Get detection_ids with at least one applied_detection for these hosts
            placeholders = ",".join("?" for _ in host_ids)
            applied_det_ids = conn.execute(
                f"SELECT DISTINCT detection_id FROM applied_detections WHERE host_id IN ({placeholders})",
                list(host_ids),
            ).fetchall()
            det_ids = [r[0] for r in applied_det_ids]
            if not det_ids:
                return set()
            # Get vuln_detection rule_refs and notes for these detection IDs
            placeholders2 = ",".join("?" for _ in det_ids)
            vuln_rows = conn.execute(
                f"SELECT rule_ref, note FROM vuln_detections WHERE id IN ({placeholders2})",
                det_ids,
            ).fetchall()
            names = set()
            for rule_ref, note in vuln_rows:
                if rule_ref:
                    names.add(rule_ref.lower())
                    resolved = _resolve_rule_ref(rule_ref)
                    if resolved:
                        names.add(resolved.lower())
                if note:
                    names.add(note.lower())
            # Also pull in detection_rules names from the applied chain
            dr_rows = conn.execute(
                "SELECT DISTINCT dr.name FROM detection_rules dr "
                "JOIN vuln_detections vd ON vd.rule_ref = dr.rule_id "
                f"WHERE vd.id IN ({placeholders2})",
                det_ids,
            ).fetchall()
            for (name,) in dr_rows:
                if name:
                    names.add(name.lower())
            # Also check step_detections (tactic detections applied to hosts)
            step_rows = conn.execute(
                f"SELECT rule_ref, note FROM step_detections WHERE id IN ({placeholders2})",
                det_ids,
            ).fetchall()
            for rule_ref, note in step_rows:
                if rule_ref:
                    names.add(rule_ref.lower())
                    resolved = _resolve_rule_ref(rule_ref)
                    if resolved:
                        names.add(resolved.lower())
                if note:
                    names.add(note.lower())
        return names
    except Exception as exc:
        logger.warning(f"_get_applied_rule_names_for_hosts error: {exc}")
        return set()


def seed_default_playbooks():
    """Seed the two default playbooks if they don't already exist."""
    existing = list_playbooks()
    existing_names = {p.name for p in existing}

    if "Insider Threat (Data Exfiltration)" not in existing_names:
        pb = create_playbook("Insider Threat (Data Exfiltration)",
                             "Detect and respond to insider threat data exfiltration scenarios.")
        add_playbook_step(pb.id, 1, "Unauthorized Hardware Attachment", "T1200", "USB_Storage_Detected",
                          "Detect unauthorized USB or hardware device connections.", tactic="Initial Access")
        add_playbook_step(pb.id, 2, "Privilege Escalation via Auth Account", "T1078", "Admin_Logon_Anomaly",
                          "Detect anomalous admin logon events.", tactic="Privilege Escalation")
        add_playbook_step(pb.id, 3, "Data Compressed for Exfiltration", "T1560", "Archive_Tool_Execution",
                          "Detect execution of archive/compression tools.", tactic="Collection")
        add_playbook_step(pb.id, 4, "Data Transfer to External Device", "T1052", "Large_File_Copy_USB",
                          "Detect large file transfers to removable media.", tactic="Exfiltration")
        logger.info("Seeded default playbook: Insider Threat (Data Exfiltration)")

    if "Ransomware Precursor (Lateral Movement)" not in existing_names:
        pb = create_playbook("Ransomware Precursor (Lateral Movement)",
                             "Detect early indicators of ransomware lateral movement chains.")
        add_playbook_step(pb.id, 1, "Internal Net Service Scanning", "T1046", "Internal_Port_Scan_Detected",
                          "Detect internal network service scanning activity.", tactic="Discovery")
        add_playbook_step(pb.id, 2, "Lateral Movement via SMB/RPC", "T1021.002", "PsExec_Lateral_Movement",
                          "Detect lateral movement using PsExec or SMB/RPC services.", tactic="Lateral Movement")
        add_playbook_step(pb.id, 3, "Credential Dumping", "T1003", "LSASS_Memory_Access",
                          "Detect LSASS memory access for credential harvesting.", tactic="Credential Access")
        add_playbook_step(pb.id, 4, "Delete Backups / Inhibit Recovery", "T1490", "VSSAdmin_Shadow_Delete",
                          "Detect backup deletion via VSSAdmin or similar tools.", tactic="Impact")
        logger.info("Seeded default playbook: Ransomware Precursor (Lateral Movement)")

    # Backfill tactics on existing steps that are missing them
    _backfill_step_tactics()


def _backfill_step_tactics():
    """Assign tactics to existing playbook steps that have technique_id but no tactic."""
    # Map technique prefixes to tactics based on known MITRE mappings
    _TECHNIQUE_TACTIC_MAP = {
        "T1200": "Initial Access", "T1078": "Privilege Escalation",
        "T1560": "Collection", "T1052": "Exfiltration",
        "T1046": "Discovery", "T1021": "Lateral Movement",
        "T1003": "Credential Access", "T1490": "Impact",
        "T1190": "Initial Access", "T1566": "Initial Access",
        "T1059": "Execution", "T1053": "Execution",
        "T1547": "Persistence", "T1098": "Persistence",
        "T1548": "Privilege Escalation", "T1134": "Privilege Escalation",
        "T1070": "Defense Evasion", "T1027": "Defense Evasion",
        "T1110": "Credential Access", "T1558": "Credential Access",
        "T1083": "Discovery", "T1018": "Discovery",
        "T1071": "Command and Control", "T1105": "Command and Control",
        "T1048": "Exfiltration", "T1041": "Exfiltration",
    }
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, technique_id FROM playbook_steps WHERE (tactic IS NULL OR tactic = '') AND technique_id != ''"
        ).fetchall()
        for step_id, tech_id in rows:
            base_tech = tech_id.split(".")[0] if tech_id else ""
            tactic = _TECHNIQUE_TACTIC_MAP.get(tech_id, _TECHNIQUE_TACTIC_MAP.get(base_tech, "Other"))
            conn.execute("UPDATE playbook_steps SET tactic = ? WHERE id = ?", [tactic, step_id])
        if rows:
            logger.info(f"Backfilled tactics on {len(rows)} playbook steps")


# ---------------------------------------------------------------------------
# Step-level CRUD (multi-technique, multi-detection)
# ---------------------------------------------------------------------------

def add_step_technique(step_id: str, technique_id: str) -> StepTechnique:
    with _get_conn() as conn:
        dup = conn.execute(
            "SELECT id FROM step_techniques WHERE step_id = ? AND technique_id = ?",
            [step_id, technique_id],
        ).fetchone()
        if dup:
            return StepTechnique(id=dup[0], step_id=step_id, technique_id=technique_id)
        r = conn.execute(
            "INSERT INTO step_techniques (step_id, technique_id) VALUES (?, ?) RETURNING id",
            [step_id, technique_id],
        ).fetchone()
    return StepTechnique(id=r[0], step_id=step_id, technique_id=technique_id)


def remove_step_technique(technique_row_id: str) -> bool:
    with _get_conn() as conn:
        cnt = conn.execute("DELETE FROM step_techniques WHERE id = ?", [technique_row_id]).rowcount
    return cnt > 0


def update_step_technique(technique_row_id: str, technique_id: str) -> Optional[StepTechnique]:
    with _get_conn() as conn:
        r = conn.execute(
            "UPDATE step_techniques SET technique_id = ? WHERE id = ? RETURNING id, step_id, technique_id",
            [technique_id, technique_row_id],
        ).fetchone()
    if not r:
        return None
    return StepTechnique(id=r[0], step_id=r[1], technique_id=r[2])


def add_step_detection(step_id: str, rule_ref: str, note: str = "", source: str = "manual") -> StepDetection:
    with _get_conn() as conn:
        r = conn.execute(
            "INSERT INTO step_detections (step_id, rule_ref, note, source) VALUES (?, ?, ?, ?) "
            "RETURNING id, step_id, rule_ref, note, source",
            [step_id, rule_ref, note, source],
        ).fetchone()
    return StepDetection(id=r[0], step_id=r[1], rule_ref=r[2] or "", note=r[3] or "", source=r[4] or "manual")


def remove_step_detection(detection_row_id: str) -> bool:
    with _get_conn() as conn:
        cnt = conn.execute("DELETE FROM step_detections WHERE id = ?", [detection_row_id]).rowcount
    return cnt > 0


def update_playbook_step(step_id: str, title: str = None, tactic: str = None,
                         description: str = None, step_number: int = None) -> Optional[PlaybookStep]:
    """Update editable fields on a playbook step."""
    with _get_conn() as conn:
        row = conn.execute("SELECT playbook_id FROM playbook_steps WHERE id = ?", [step_id]).fetchone()
        if not row:
            return None
        sets, vals = [], []
        if title is not None:
            sets.append("title = ?"); vals.append(title)
        if tactic is not None:
            sets.append("tactic = ?"); vals.append(tactic)
        if description is not None:
            sets.append("description = ?"); vals.append(description)
        if step_number is not None:
            sets.append("step_number = ?"); vals.append(step_number)
        if sets:
            vals.append(step_id)
            conn.execute(f"UPDATE playbook_steps SET {', '.join(sets)} WHERE id = ?", vals)
    return get_playbook_step(step_id)


def get_playbook_step(step_id: str) -> Optional[PlaybookStep]:
    """Get a single step with its techniques and detections."""
    with _get_conn() as conn:
        r = conn.execute(
            "SELECT id, playbook_id, step_number, title, technique_id, required_rule, description, tactic "
            "FROM playbook_steps WHERE id = ?",
            [step_id],
        ).fetchone()
    if not r:
        return None
    step = PlaybookStep(
        id=r[0], playbook_id=r[1], step_number=r[2], title=r[3],
        technique_id=r[4] or "", required_rule=r[5] or "", description=r[6] or "",
        tactic=r[7] or "",
    )
    step.techniques = _get_step_techniques(step_id)
    step.detections = _get_step_detections(step_id)
    return step


def get_step_affected_systems(step_id: str) -> List[Dict]:
    """Get systems where the baseline containing this tactic is applied, with per-system RAG status.
    4-tier RAG logic:
      GREEN = detection rule applied (covered)
      AMBER = user explicitly marked as known gap (override_type='gap')
      GREY  = user explicitly marked as N/A (override_type='na')
      RED   = no action taken (default)
    Also returns per-system applied_dets / unapplied_dets for the apply-to-system UI."""
    step = get_playbook_step(step_id)
    if not step:
        return []
    # Find which systems have this playbook applied
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT sb.system_id, s.name FROM system_baselines sb "
            "JOIN systems s ON s.id = sb.system_id "
            "WHERE sb.playbook_id = ? ORDER BY s.name",
            [step.playbook_id],
        ).fetchall()
    if not rows:
        return []

    # Gather all detection rule refs for this step
    det_rule_refs = {d.rule_ref.lower() for d in step.detections if d.rule_ref}

    # Pre-load applied_detections for this step's detection IDs
    det_ids = [d.id for d in step.detections]
    applied_host_map: Dict[str, set] = {}  # {detection_id: set(host_id)}
    applied_sys_map: Dict[str, set] = {}   # {detection_id: set(system_id)} for system-level rows
    if det_ids:
        with _get_conn() as conn:
            ph = ",".join("?" for _ in det_ids)
            ad_rows = conn.execute(
                f"SELECT detection_id, host_id, system_id FROM applied_detections WHERE detection_id IN ({ph})",
                det_ids,
            ).fetchall()
        for det_id, host_id, sys_id in ad_rows:
            if host_id:
                applied_host_map.setdefault(det_id, set()).add(host_id)
            elif sys_id:
                applied_sys_map.setdefault(det_id, set()).add(sys_id)

    # Load blind spots for this tactic
    blind_spots = get_blind_spots("tactic", step_id)

    result = []
    for system_id, system_name in rows:
        # Fetch system description
        sys_obj = get_system(system_id)
        system_description = sys_obj.description if sys_obj else ""
        hosts = list_hosts(system_id)
        host_ids = {h.id for h in hosts}

        # Check direct application: detection applied to at least one host in system,
        # or applied at system level (for systems with no hosts)
        sys_applied = []
        sys_unapplied = []
        for d in step.detections:
            det_hosts = applied_host_map.get(d.id, set())
            det_systems = applied_sys_map.get(d.id, set())
            if (host_ids and (det_hosts & host_ids)) or (system_id in det_systems):
                sys_applied.append({"id": d.id, "label": d.rule_ref or d.note or "Rule"})
            else:
                sys_unapplied.append({"id": d.id, "label": d.rule_ref or d.note or "Rule"})

        # Check for blind spot on this system — distinguish gap vs na
        sys_blind_spots = [bs for bs in blind_spots if bs.system_id == system_id]
        has_na = any(bs.override_type == "na" for bs in sys_blind_spots)
        has_gap = any(bs.override_type == "gap" for bs in sys_blind_spots)
        bs_reason = next((bs.reason for bs in sys_blind_spots), "")

        # 4-tier status: green > grey > amber > red
        if sys_applied:
            status = "green"
        elif has_na:
            status = "grey"
        elif has_gap:
            status = "amber"
        else:
            status = "red"

        result.append({
            "system_id": system_id,
            "system_name": system_name,
            "system_description": system_description or "",
            "host_count": len(hosts),
            "status": status,
            "blind_spot_reason": bs_reason,
            "override_type": "na" if has_na else ("gap" if has_gap else ""),
            "matched_rules": [],
            "applied_dets": sys_applied,
            "unapplied_dets": sys_unapplied,
        })
    return result


# ---------------------------------------------------------------------------
# Negative Coverage / Known Blind Spots
# ---------------------------------------------------------------------------

def add_blind_spot(entity_type: str, entity_id: str, reason: str,
                   system_id: str = None, host_id: str = None,
                   created_by: str = "", override_type: str = "gap") -> BlindSpot:
    """Record a known blind spot (negative coverage).
    override_type: 'gap' (amber/known gap) or 'na' (grey/not applicable)."""
    if override_type not in ("gap", "na"):
        override_type = "gap"
    with _get_conn() as conn:
        r = conn.execute(
            "INSERT INTO blind_spots (entity_type, entity_id, system_id, host_id, reason, created_by, override_type) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id, entity_type, entity_id, system_id, host_id, reason, created_by, created_at, override_type",
            [entity_type, entity_id, system_id, host_id, reason, created_by, override_type],
        ).fetchone()
    return BlindSpot(id=r[0], entity_type=r[1], entity_id=r[2], system_id=r[3],
                     host_id=r[4], reason=r[5], created_by=r[6], created_at=r[7],
                     override_type=r[8] if r[8] else "gap")


def remove_blind_spot(blind_spot_id: str) -> bool:
    with _get_conn() as conn:
        cnt = conn.execute("DELETE FROM blind_spots WHERE id = ?", [blind_spot_id]).rowcount
    return cnt > 0


def get_blind_spots(entity_type: str, entity_id: str) -> List[BlindSpot]:
    """Get all blind spots for a given entity (CVE or step)."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, entity_type, entity_id, system_id, host_id, reason, created_by, created_at, "
            "COALESCE(override_type, 'gap') "
            "FROM blind_spots WHERE entity_type = ? AND entity_id = ? ORDER BY created_at",
            [entity_type, entity_id],
        ).fetchall()
    return [BlindSpot(id=r[0], entity_type=r[1], entity_id=r[2], system_id=r[3],
                      host_id=r[4], reason=r[5], created_by=r[6], created_at=r[7],
                      override_type=r[8]) for r in rows]


def get_blind_spots_for_system(system_id: str) -> List[BlindSpot]:
    """Get all blind spots affecting a system (by system_id or by host_id belonging to system)."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, entity_type, entity_id, system_id, host_id, reason, created_by, created_at, "
            "COALESCE(override_type, 'gap') "
            "FROM blind_spots WHERE system_id = ? ORDER BY created_at",
            [system_id],
        ).fetchall()
        host_rows = conn.execute(
            "SELECT bs.id, bs.entity_type, bs.entity_id, bs.system_id, bs.host_id, bs.reason, bs.created_by, bs.created_at, "
            "COALESCE(bs.override_type, 'gap') "
            "FROM blind_spots bs JOIN hosts h ON h.id = bs.host_id WHERE h.system_id = ? ORDER BY bs.created_at",
            [system_id],
        ).fetchall()
    all_rows = {r[0]: r for r in rows}
    for r in host_rows:
        all_rows[r[0]] = r
    return [BlindSpot(id=r[0], entity_type=r[1], entity_id=r[2], system_id=r[3],
                      host_id=r[4], reason=r[5], created_by=r[6], created_at=r[7],
                      override_type=r[8]) for r in all_rows.values()]


# ---------------------------------------------------------------------------
# Baseline Snapshots
# ---------------------------------------------------------------------------

def create_baseline_snapshot(
    system_id: str, baseline_id: str, label: str, captured_by: str,
    captured_at=None,
) -> Dict:
    """Capture a point-in-time snapshot of baseline coverage for a system."""
    import uuid
    from datetime import datetime as _dt

    # Calculate current coverage for this baseline
    all_baselines = get_system_baselines(system_id)
    bl = next((b for b in all_baselines if b["playbook_id"] == baseline_id), None)
    if not bl:
        return None

    snap_id = str(uuid.uuid4())
    ts = captured_at or _dt.utcnow()

    count_green = bl["covered_steps"]
    count_amber = bl.get("gap_steps", 0)
    count_grey = bl.get("na_steps", 0)
    count_red = bl["total_steps"] - count_green - count_amber - count_grey
    score_pct = float(bl["coverage_pct"])

    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO system_baseline_snapshots "
            "(id, system_id, baseline_id, captured_at, captured_by, label, "
            "score_percentage, count_green, count_amber, count_red, count_grey) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [snap_id, system_id, baseline_id, ts, captured_by, label,
             score_pct, count_green, count_amber, count_red, count_grey],
        )

    return {
        "id": snap_id, "system_id": system_id, "baseline_id": baseline_id,
        "captured_at": ts, "captured_by": captured_by, "label": label,
        "score_percentage": score_pct,
        "count_green": count_green, "count_amber": count_amber,
        "count_red": count_red, "count_grey": count_grey,
    }


def create_all_baseline_snapshots(
    system_id: str, label: str, captured_by: str, captured_at=None,
) -> List[Dict]:
    """Snapshot all baselines applied to a system with a shared timestamp."""
    from datetime import datetime as _dt

    ts = captured_at or _dt.utcnow()
    all_baselines = get_system_baselines(system_id)
    results = []
    for bl in all_baselines:
        snap = create_baseline_snapshot(
            system_id, bl["playbook_id"], label, captured_by, captured_at=ts,
        )
        if snap:
            results.append(snap)
    return results


def get_baseline_snapshots(system_id: str) -> List[Dict]:
    """Return all snapshots for a system, newest first, with baseline names."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT s.id, s.system_id, s.baseline_id, s.captured_at, s.captured_by, "
            "s.label, s.score_percentage, s.count_green, s.count_amber, "
            "s.count_red, s.count_grey, p.name "
            "FROM system_baseline_snapshots s "
            "LEFT JOIN playbooks p ON p.id = s.baseline_id "
            "WHERE s.system_id = ? ORDER BY s.captured_at DESC",
            [system_id],
        ).fetchall()
    return [
        {
            "id": r[0], "system_id": r[1], "baseline_id": r[2],
            "captured_at": r[3], "captured_by": r[4], "label": r[5],
            "score_percentage": r[6], "count_green": r[7], "count_amber": r[8],
            "count_red": r[9], "count_grey": r[10],
            "baseline_name": r[11] or "Deleted Baseline",
        }
        for r in rows
    ]


def delete_baseline_snapshot(snapshot_id: str) -> bool:
    """Delete a single snapshot."""
    with _get_conn() as conn:
        cnt = conn.execute(
            "DELETE FROM system_baseline_snapshots WHERE id = ?", [snapshot_id],
        ).rowcount
    return cnt > 0
