"""
inventory_engine.py - Asset Inventory & CVE Mapping Engine (Phase 2: Enterprise)
"""
from __future__ import annotations
import json, logging, os, re, shutil, xml.etree.ElementTree as ET
from datetime import date, datetime
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
# A rule id (Kibana saved-object id) rather than a name, in an older mapping's rule_ref.
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

def _get_conn():
    from app.services.database import get_database_service
    return get_database_service().get_connection()


def _cf(alias: str = "", client_id: str = None) -> tuple[str, list]:
    """Build a client_id filter clause. Returns (sql_fragment, params).
    alias: table alias prefix (e.g. 's.' or '' for no alias).
    In multi-DB mode (tenant context active), returns empty clause
    because the database IS the tenant scope — no filtering needed.
    If client_id is None, returns empty clause (no filter)."""
    from app.services.tenant_manager import get_tenant_db_path
    if get_tenant_db_path() is not None:
        return ("", [])
    if client_id is None:
        return ("", [])
    col = f"{alias}client_id" if alias else "client_id"
    return (f" AND {col} = ?", [client_id])

def _row_to_system(r):
    return System(id=r[0], name=r[1], description=r[2], created_at=r[3], updated_at=r[4],
                  classification=r[5] if len(r) > 5 else None)

def _row_to_host(r):
    return Host(id=r[0], system_id=r[1], name=r[2], ip_address=r[3],
                os=r[4], hardware_vendor=r[5], model=r[6], source=r[7], created_at=r[8])

def _row_to_software(r):
    return SoftwareInventory(id=r[0], host_id=r[1], system_id=r[2], name=r[3],
                             version=r[4], vendor=r[5], cpe=r[6], source=r[7], created_at=r[8])


def normalize_technique_id(value: str) -> str:
    """Normalize free-form technique input into a MITRE technique ID when possible."""
    raw = (value or "").strip()
    if not raw:
        return ""

    # Accept legacy UI labels but persist only clean technique IDs.
    raw = re.sub(r"^legacy\s+technique\s*:\s*", "", raw, flags=re.IGNORECASE)
    raw = raw.replace("`", "").strip()

    match = re.search(r"\b(T\d{4}(?:\.\d{3})?)\b", raw, flags=re.IGNORECASE)
    if match:
        return match.group(1).upper()

    return ""


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


def _list_all_hosts_by_system(client_id: str = None) -> Dict[str, List]:
    """Load all hosts grouped by system_id in one query."""
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, system_id, name, ip_address, os, hardware_vendor, model, source, created_at FROM hosts WHERE 1=1" + frag + " ORDER BY name",
            params,
        ).fetchall()
    result: Dict[str, list] = {}
    for r in rows:
        h = _row_to_host(r)
        result.setdefault(h.system_id, []).append(h)
    return result


def _list_all_software_by_host(client_id: str = None) -> Dict[str, List]:
    """Load all software grouped by host_id in one query."""
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, host_id, system_id, name, version, vendor, cpe, source, created_at "
            "FROM software_inventory WHERE host_id IS NOT NULL" + frag + " ORDER BY name",
            params,
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
    for p in [
        "/app/data/attack-to-cve.json",
        "/opt/repos/mappings/kev-07.28.2025_attack-16.1-enterprise.json",
        "/opt/repos/mappings/attack-to-cve.json",
    ]:
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as fh:
                    raw = json.load(fh)
                if not raw:
                    _mitre_cve_map_loaded = True
                    _mitre_cve_map_cache = {}
                    return {}
                if isinstance(raw, dict) and "mapping_objects" in raw:
                    inverted = {}
                    for item in raw.get("mapping_objects") or []:
                        if not isinstance(item, dict):
                            continue
                        cve_id = (item.get("capability_id") or "").strip().upper()
                        technique_id = (item.get("attack_object_id") or "").strip().upper()
                        if not cve_id or not cve_id.startswith("CVE-") or not technique_id:
                            continue
                        inverted.setdefault(cve_id, [])
                        if technique_id not in inverted[cve_id]:
                            inverted[cve_id].append(technique_id)
                    _mitre_cve_map_cache = inverted
                else:
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

def _get_covered_techniques(technique_ids, client_id: str = None):
    coverage = {}
    frag, params = _cf("", client_id)
    try:
        with _get_conn() as conn:
            for t_id in technique_ids:
                row = conn.execute(
                    "SELECT COUNT(*) FROM detection_rules WHERE list_contains(mitre_ids, ?)" + frag,
                    [t_id] + params).fetchone()
                coverage[t_id] = int(row[0]) if row else 0
    except Exception as exc:
        logger.warning(f"Failed to query MITRE coverage: {exc}")
        coverage = {t: 0 for t in technique_ids}
    return coverage

def get_cve_techniques(cve_id, client_id: str = None):
    mitre_map = _load_mitre_cve_map()
    technique_ids = list(mitre_map.get(cve_id.upper(), []))
    # Merge manual DB overrides
    override_ids = get_cve_technique_overrides(cve_id, client_id=client_id)
    for t in override_ids:
        if t not in technique_ids:
            technique_ids.append(t)
    if not technique_ids:
        return []
    coverage = _get_covered_techniques(technique_ids, client_id=client_id)
    return [MitreTechnique(technique_id=t_id, name=_TECHNIQUE_NAMES.get(t_id, ""),
                           has_detection=coverage.get(t_id, 0) > 0, rule_count=coverage.get(t_id, 0))
            for t_id in technique_ids]

# --- MITRE Technique Overrides (manual per-CVE additions) ---

def get_cve_technique_overrides(cve_id: str, client_id: str = None) -> List[str]:
    """Return list of manually added technique IDs for a CVE."""
    frag, params = _cf("", client_id)
    try:
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT technique_id FROM cve_technique_overrides WHERE cve_id = ?" + frag + " ORDER BY technique_id",
                [cve_id.upper()] + params).fetchall()
        return [r[0] for r in rows]
    except Exception as exc:
        logger.warning(f"get_cve_technique_overrides failed: {exc}")
        return []

def add_cve_technique_override(cve_id: str, technique_id: str, client_id: str = None) -> bool:
    """Add a technique ID override for a CVE. Returns True if inserted."""
    try:
        with _get_conn() as conn:
            if client_id:
                conn.execute(
                    "INSERT INTO cve_technique_overrides (cve_id, technique_id, client_id) VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
                    [cve_id.upper(), technique_id.upper(), client_id])
            else:
                conn.execute(
                    "INSERT INTO cve_technique_overrides (cve_id, technique_id) VALUES (?, ?) ON CONFLICT DO NOTHING",
                    [cve_id.upper(), technique_id.upper()])
        return True
    except Exception as exc:
        logger.warning(f"add_cve_technique_override failed: {exc}")
        return False

def remove_cve_technique_override(cve_id: str, technique_id: str, client_id: str = None) -> bool:
    """Remove a technique ID override for a CVE. Returns True if deleted."""
    frag, params = _cf("", client_id)
    try:
        with _get_conn() as conn:
            before = conn.execute(
                "SELECT COUNT(*) FROM cve_technique_overrides WHERE cve_id = ? AND technique_id = ?" + frag,
                [cve_id.upper(), technique_id.upper()] + params).fetchone()[0]
            conn.execute(
                "DELETE FROM cve_technique_overrides WHERE cve_id = ? AND technique_id = ?" + frag,
                [cve_id.upper(), technique_id.upper()] + params)
        return bool(before)
    except Exception as exc:
        logger.warning(f"remove_cve_technique_override failed: {exc}")
        return False

# --- Classification CRUD ---
def list_classifications(client_id: str = None) -> List[Classification]:
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        rows = conn.execute("SELECT id, name, color FROM classifications WHERE 1=1" + frag + " ORDER BY name", params).fetchall()
    return [Classification(id=r[0], name=r[1], color=r[2]) for r in rows]

def get_classification_color(name: Optional[str], client_id: str = None) -> Optional[str]:
    """Return the hex colour for a classification name, or None."""
    if not name:
        return None
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        r = conn.execute("SELECT color FROM classifications WHERE name = ?" + frag, [name] + params).fetchone()
    return r[0] if r else None

def add_classification(name: str, color: str = "#6b7280", client_id: str = None) -> Classification:
    with _get_conn() as conn:
        if client_id:
            row = conn.execute(
                "INSERT INTO classifications (name, color, client_id) VALUES (?, ?, ?) RETURNING id, name, color",
                [name.strip(), color.strip(), client_id]).fetchone()
        else:
            row = conn.execute(
                "INSERT INTO classifications (name, color) VALUES (?, ?) RETURNING id, name, color",
                [name.strip(), color.strip()]).fetchone()
    return Classification(id=row[0], name=row[1], color=row[2])

def delete_classification(cls_id: str, client_id: str = None) -> bool:
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        before = conn.execute("SELECT COUNT(*) FROM classifications WHERE id = ?" + frag, [cls_id] + params).fetchone()[0]
        if before == 0:
            return False
        # Clear classification from any systems using it
        row = conn.execute("SELECT name FROM classifications WHERE id = ?" + frag, [cls_id] + params).fetchone()
        if row:
            conn.execute("UPDATE systems SET classification = NULL WHERE classification = ?" + frag, [row[0]] + params)
        conn.execute("DELETE FROM classifications WHERE id = ?" + frag, [cls_id] + params)
    return True

# --- System CRUD ---
def list_systems(client_id: str = None):
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, name, description, created_at, updated_at, classification FROM systems WHERE 1=1" + frag + " ORDER BY name",
            params,
        ).fetchall()
    return [_row_to_system(r) for r in rows]


def count_systems(client_id: str = None) -> int:
    """Lightweight COUNT(*) for the systems table, scoped to the tenant context.

    Avoids materialising full `System` rows + their child queries when a caller
    only needs the cardinality (e.g. badge counts on the Management hub).
    """
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM systems WHERE 1=1" + frag,
            params,
        ).fetchone()
    return int(row[0]) if row else 0

def _cascade_system_client(conn, system_id: str, new_client_id: str):
    """Cascade client_id change to all child tables of a system."""
    child_tables_with_system_id = [
        "hosts", "software_inventory", "applied_detections",
        "blind_spots", "system_baselines", "system_baseline_snapshots",
    ]
    for table in child_tables_with_system_id:
        conn.execute(f"UPDATE {table} SET client_id = ? WHERE system_id = ?",
                     [new_client_id, system_id])
    # Also update host-linked rows in tables that use host_id instead of system_id
    host_ids = [r[0] for r in conn.execute(
        "SELECT id FROM hosts WHERE system_id = ?", [system_id]).fetchall()]
    if host_ids:
        ph = ",".join("?" for _ in host_ids)
        # software_inventory, applied_detections, blind_spots can link via host_id
        for table in ["software_inventory", "applied_detections", "blind_spots"]:
            conn.execute(
                f"UPDATE {table} SET client_id = ? WHERE host_id IN ({ph})",
                [new_client_id] + host_ids)


def assign_system_to_client(system_id: str, client_id: str) -> bool:
    with _get_conn() as conn:
        r = conn.execute("SELECT id, client_id FROM systems WHERE id = ?", [system_id]).fetchone()
        if not r:
            return False
        conn.execute("UPDATE systems SET client_id = ? WHERE id = ?", [client_id, system_id])
        _cascade_system_client(conn, system_id, client_id)
    return True

def unassign_system_from_client(system_id: str, client_id: str, default_client_id: str = None) -> bool:
    with _get_conn() as conn:
        r = conn.execute("SELECT id FROM systems WHERE id = ? AND client_id = ?", [system_id, client_id]).fetchone()
        if not r:
            return False
        target_client = default_client_id or client_id
        conn.execute("UPDATE systems SET client_id = ? WHERE id = ?", [target_client, system_id])
        _cascade_system_client(conn, system_id, target_client)
    return True


def move_system_check(system_id: str, source_client_id: str, target_client_id: str) -> Optional[Dict]:
    """Pre-flight check for moving a system between clients.
    Returns dependency summary dict or None if system not found."""
    from app.services.database import get_database_service
    from app.services.tenant_manager import tenant_context_for, is_multi_db_mode
    db = get_database_service()

    if is_multi_db_mode():
        with tenant_context_for(source_client_id):
            return _move_system_check_inner(system_id, source_client_id, target_client_id, db)
    else:
        return _move_system_check_inner(system_id, source_client_id, target_client_id, db)


def _move_system_check_inner(system_id, source_client_id, target_client_id, db):
    with _get_conn() as conn:
        sys_row = conn.execute(
            "SELECT id, name FROM systems WHERE id = ? AND client_id = ?",
            [system_id, source_client_id]).fetchone()
        if not sys_row:
            return None

        baselines = conn.execute(
            "SELECT sb.playbook_id, p.name FROM system_baselines sb "
            "JOIN playbooks p ON p.id = sb.playbook_id "
            "WHERE sb.system_id = ?", [system_id]).fetchall()

        host_count = conn.execute(
            "SELECT COUNT(*) FROM hosts WHERE system_id = ?", [system_id]).fetchone()[0]
        software_count = conn.execute(
            "SELECT COUNT(*) FROM software_inventory WHERE system_id = ?", [system_id]).fetchone()[0]

        applied_count = conn.execute(
            "SELECT COUNT(*) FROM applied_detections WHERE system_id = ?", [system_id]).fetchone()[0]

    # SIEM compatibility check: are the source and target clients mapped to
    # any of the SAME (siem_id, space) production pair? Composite key is
    # mandatory — two clients pointing at SIEM_A 'default' and SIEM_B
    # 'default' are NOT compatible even though their space names match
    # (CLAUDE.md §8.2 g4).
    source_scopes = set(db.get_client_siem_scopes(source_client_id, "production"))
    target_scopes = set(db.get_client_siem_scopes(target_client_id, "production"))
    shared_scopes = source_scopes & target_scopes
    siem_compatible = bool(shared_scopes)

    return {
        "system_id": system_id,
        "system_name": sys_row[1],
        "baselines": [{"id": b[0], "name": b[1]} for b in baselines],
        "host_count": host_count,
        "software_count": software_count,
        "applied_detections_count": applied_count,
        "siem_compatible": siem_compatible,
        "source_spaces": sorted({sp for _, sp in source_scopes}),
        "target_spaces": sorted({sp for _, sp in target_scopes}),
        "shared_spaces": sorted({sp for _, sp in shared_scopes}),
    }


def _cross_db_copy(src, tgt, table: str, where: str, params: list,
                   new_client_id: str = None) -> int:
    """Copy rows from *src* to *tgt* DuckDB connections.

    If *new_client_id* is provided and the table has a ``client_id``
    column, all copied rows have their ``client_id`` replaced.
    Returns the number of rows copied.
    """
    cols = [c[0] for c in src.execute(f"DESCRIBE {table}").fetchall()]
    rows = src.execute(
        f"SELECT {', '.join(cols)} FROM {table} WHERE {where}", params
    ).fetchall()
    if not rows:
        return 0
    ci_idx = cols.index("client_id") if ("client_id" in cols and new_client_id) else None
    placeholders = ", ".join("?" for _ in cols)
    col_list = ", ".join(cols)
    for row in rows:
        values = list(row)
        if ci_idx is not None:
            values[ci_idx] = new_client_id
        tgt.execute(f"INSERT INTO {table} ({col_list}) VALUES ({placeholders})", values)
    return len(rows)


def move_system_to_client(
    system_id: str,
    source_client_id: str,
    target_client_id: str,
) -> Dict:
    """Move a system between clients with SIEM-aware rule coverage handling. Its baselines are
    its own, so they always go with it.

    In multi-DB mode, physically copies data from the source tenant DB to
    the target tenant DB and deletes from source.
    Returns result dict with move status and what was affected.
    """
    from app.services.tenant_manager import is_multi_db_mode

    check = move_system_check(system_id, source_client_id, target_client_id)
    if check is None:
        raise ValueError("System not found or not owned by source client.")

    if is_multi_db_mode():
        return _move_system_multi_db(system_id, source_client_id, target_client_id, check)
    return _move_system_single_db(system_id, source_client_id, target_client_id, check)


def _move_system_single_db(system_id, source_client_id, target_client_id, check):
    """Legacy single-DB move: UPDATE client_id on all related rows."""
    coverage_reset = False
    reset_count = 0

    with _get_conn() as conn:
        if not check["siem_compatible"]:
            reset_count = conn.execute(
                "SELECT COUNT(*) FROM applied_detections WHERE system_id = ?",
                [system_id]).fetchone()[0]
            conn.execute(
                "DELETE FROM applied_detections WHERE system_id = ?",
                [system_id])
            host_ids = [r[0] for r in conn.execute(
                "SELECT id FROM hosts WHERE system_id = ?", [system_id]).fetchall()]
            if host_ids:
                ph = ",".join("?" for _ in host_ids)
                reset_count += conn.execute(
                    f"SELECT COUNT(*) FROM applied_detections WHERE host_id IN ({ph})",
                    host_ids).fetchone()[0]
                conn.execute(
                    f"DELETE FROM applied_detections WHERE host_id IN ({ph})",
                    host_ids)
            coverage_reset = True

        conn.execute("UPDATE systems SET client_id = ? WHERE id = ?",
                     [target_client_id, system_id])
        _cascade_system_client(conn, system_id, target_client_id)
        conn.execute("UPDATE playbooks SET client_id = ? WHERE system_id = ?",
                     [target_client_id, system_id])
        moved_baselines = check["baselines"]

    logger.info(
        f"System {system_id} moved from {source_client_id} to {target_client_id} "
        f"(coverage_reset={coverage_reset}, baselines_moved={len(moved_baselines)})"
    )
    return {
        "moved": True, "system_id": system_id,
        "system_name": check["system_name"],
        "target_client_id": target_client_id,
        "coverage_reset": coverage_reset,
        "applied_detections_removed": reset_count,
        "baselines_moved": moved_baselines,
        "host_count": check["host_count"],
        "software_count": check["software_count"],
    }


def _move_system_multi_db(system_id, source_client_id, target_client_id, check):
    """Multi-DB move: copy rows from source tenant DB to target, then delete."""
    import duckdb
    from app.services.tenant_manager import resolve_tenant_db_path
    from app.config import get_settings

    settings = get_settings()
    src_path = resolve_tenant_db_path(source_client_id, settings.data_dir)
    tgt_path = resolve_tenant_db_path(target_client_id, settings.data_dir)
    if not src_path or not tgt_path:
        raise ValueError("Both clients must have tenant databases for cross-DB move.")

    siem_compatible = check["siem_compatible"]
    reset_count = 0

    src = duckdb.connect(src_path)
    tgt = duckdb.connect(tgt_path)
    try:
        # Gather host IDs for this system
        host_ids = [r[0] for r in src.execute(
            "SELECT id FROM hosts WHERE system_id = ?", [system_id]).fetchall()]
        host_ph = ",".join("?" for _ in host_ids) if host_ids else None

        # ── Helper to build combined system_id + host_id WHERE clause ──
        def _sys_host_where():
            w = "system_id = ?"
            p = [system_id]
            if host_ids:
                w += f" OR host_id IN ({host_ph})"
                p += host_ids
            return w, p

        # ── Copy to target ──
        _cross_db_copy(src, tgt, "systems", "id = ?", [system_id], target_client_id)
        _cross_db_copy(src, tgt, "hosts", "system_id = ?", [system_id], target_client_id)

        sw_w, sw_p = _sys_host_where()
        _cross_db_copy(src, tgt, "software_inventory", sw_w, sw_p, target_client_id)
        _cross_db_copy(src, tgt, "blind_spots", sw_w, sw_p, target_client_id)

        if siem_compatible:
            _cross_db_copy(src, tgt, "applied_detections", sw_w, sw_p, target_client_id)
        else:
            reset_count = src.execute(
                f"SELECT COUNT(*) FROM applied_detections WHERE {sw_w}", sw_p
            ).fetchone()[0]

        # The system's own baselines, with their techniques, mappings and history
        _cross_db_copy(src, tgt, "playbooks", "system_id = ?", [system_id], target_client_id)
        _cross_db_copy(src, tgt, "system_baselines", "system_id = ?", [system_id], target_client_id)
        _cross_db_copy(src, tgt, "system_baseline_snapshots", "system_id = ?", [system_id], target_client_id)
        _cross_db_copy(src, tgt, "technique_events", "system_id = ?", [system_id], target_client_id)
        steps_of = "SELECT s.id FROM playbook_steps s JOIN playbooks p ON p.id = s.playbook_id WHERE p.system_id = ?"
        _cross_db_copy(src, tgt, "playbook_steps", "playbook_id IN (SELECT id FROM playbooks WHERE system_id = ?)", [system_id])
        _cross_db_copy(src, tgt, "step_techniques", f"step_id IN ({steps_of})", [system_id])
        _cross_db_copy(src, tgt, "step_detections", f"step_id IN ({steps_of})", [system_id])
        _cross_db_copy(src, tgt, "step_sigma_dismissals", "system_id = ?", [system_id], target_client_id)
        from app.services.database import DatabaseService
        for c in (src, tgt):
            c.execute(DatabaseService.STEP_COVERAGE_DDL)
        _cross_db_copy(src, tgt, "step_coverage", f"step_id IN ({steps_of})", [system_id])
        moved_baselines = check["baselines"]
        for (pb_id,) in src.execute("SELECT id FROM playbooks WHERE system_id = ?", [system_id]).fetchall():
            _delete_playbook_rows(src, pb_id)
        src.execute("DELETE FROM system_baselines WHERE system_id = ?", [system_id])
        src.execute("DELETE FROM system_baseline_snapshots WHERE system_id = ?", [system_id])
        src.execute("DELETE FROM technique_events WHERE system_id = ?", [system_id])

        # ── Delete system data from source (reverse FK order) ──
        ad_w, ad_p = _sys_host_where()
        src.execute(f"DELETE FROM applied_detections WHERE {ad_w}", ad_p)
        src.execute(f"DELETE FROM blind_spots WHERE {sw_w}", sw_p)
        src.execute(f"DELETE FROM software_inventory WHERE {sw_w}", sw_p)
        src.execute("DELETE FROM hosts WHERE system_id = ?", [system_id])
        src.execute("DELETE FROM systems WHERE id = ?", [system_id])

    finally:
        src.close()
        tgt.close()

    logger.info(
        f"System {system_id} moved cross-DB from {source_client_id} to "
        f"{target_client_id} (siem_reset={not siem_compatible}, "
        f"baselines_moved={len(moved_baselines)})"
    )
    return {
        "moved": True, "system_id": system_id,
        "system_name": check["system_name"],
        "target_client_id": target_client_id,
        "coverage_reset": not siem_compatible,
        "applied_detections_removed": reset_count,
        "baselines_moved": moved_baselines,
        "host_count": check["host_count"],
        "software_count": check["software_count"],
    }

def get_system(system_id, client_id: str = None):
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        r = conn.execute(
            "SELECT id, name, description, created_at, updated_at, classification FROM systems WHERE id = ?" + frag,
            [system_id] + params).fetchone()
    return _row_to_system(r) if r else None

def add_system(data, client_id: str = None):
    with _get_conn() as conn:
        if client_id:
            row = conn.execute(
                "INSERT INTO systems (name, description, classification, client_id) VALUES (?, ?, ?, ?) "
                "RETURNING id, name, description, created_at, updated_at, classification",
                [data.name, data.description, getattr(data, 'classification', None), client_id]).fetchone()
        else:
            row = conn.execute(
                "INSERT INTO systems (name, description, classification) VALUES (?, ?, ?) RETURNING id, name, description, created_at, updated_at, classification",
                [data.name, data.description, getattr(data, 'classification', None)]).fetchone()
    return _row_to_system(row)

def edit_system(system_id, data, client_id: str = None):
    current = get_system(system_id, client_id=client_id)
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

def delete_system(system_id, client_id: str = None):
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        before = conn.execute("SELECT COUNT(*) FROM systems WHERE id = ?" + frag, [system_id] + params).fetchone()[0]
        if before == 0:
            return False
        host_ids = [r[0] for r in conn.execute("SELECT id FROM hosts WHERE system_id = ?" + frag, [system_id] + params).fetchall()]
        for h_id in host_ids:
            conn.execute("DELETE FROM software_inventory WHERE host_id = ?", [h_id])
        conn.execute("DELETE FROM software_inventory WHERE system_id = ?", [system_id])
        conn.execute("DELETE FROM hosts WHERE system_id = ?", [system_id])
        for (pb_id,) in conn.execute("SELECT id FROM playbooks WHERE system_id = ?", [system_id]).fetchall():
            _delete_playbook_rows(conn, pb_id)
        conn.execute("DELETE FROM system_baselines WHERE system_id = ?", [system_id])
        conn.execute("DELETE FROM system_coverage_destinations WHERE system_id = ?", [system_id])
        if host_ids:
            hph = ",".join("?" for _ in host_ids)
            conn.execute(f"DELETE FROM applied_detections WHERE host_id IN ({hph})", host_ids)
            conn.execute(f"DELETE FROM blind_spots WHERE host_id IN ({hph})", host_ids)
        conn.execute("DELETE FROM applied_detections WHERE system_id = ?", [system_id])
        conn.execute("DELETE FROM blind_spots WHERE system_id = ?", [system_id])
        conn.execute("DELETE FROM technique_events WHERE system_id = ?", [system_id])
        conn.execute("DELETE FROM systems WHERE id = ?", [system_id])
    return True

# --- Host CRUD ---
def list_hosts(system_id, client_id: str = None):
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, system_id, name, ip_address, os, hardware_vendor, model, source, created_at FROM hosts WHERE system_id = ?" + frag + " ORDER BY name",
            [system_id] + params).fetchall()
    return [_row_to_host(r) for r in rows]

def get_host(host_id, client_id: str = None):
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        r = conn.execute(
            "SELECT id, system_id, name, ip_address, os, hardware_vendor, model, source, created_at FROM hosts WHERE id = ?" + frag,
            [host_id] + params).fetchone()
    return _row_to_host(r) if r else None

def add_host(system_id, data, client_id: str = None):
    with _get_conn() as conn:
        if client_id:
            row = conn.execute(
                "INSERT INTO hosts (system_id, name, ip_address, os, hardware_vendor, model, source, client_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id, system_id, name, ip_address, os, hardware_vendor, model, source, created_at",
                [system_id, data.name, data.ip_address, data.os, data.hardware_vendor, data.model, data.source, client_id]).fetchone()
        else:
            row = conn.execute(
                "INSERT INTO hosts (system_id, name, ip_address, os, hardware_vendor, model, source) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id, system_id, name, ip_address, os, hardware_vendor, model, source, created_at",
                [system_id, data.name, data.ip_address, data.os, data.hardware_vendor, data.model, data.source]).fetchone()
    return _row_to_host(row)

def edit_host(host_id, data: HostUpdate, client_id: str = None):
    current = get_host(host_id, client_id=client_id)
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

def delete_host(host_id, client_id: str = None):
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        before = conn.execute("SELECT COUNT(*) FROM hosts WHERE id = ?" + frag, [host_id] + params).fetchone()[0]
        if before == 0:
            return False
        conn.execute("DELETE FROM software_inventory WHERE host_id = ?", [host_id])
        conn.execute("DELETE FROM hosts WHERE id = ?", [host_id])
    return True

# --- Software CRUD ---
def list_host_software(host_id, client_id: str = None):
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, host_id, system_id, name, version, vendor, cpe, source, created_at FROM software_inventory WHERE host_id = ?" + frag + " ORDER BY name",
            [host_id] + params).fetchall()
    return [_row_to_software(r) for r in rows]

def add_host_software(host_id, system_id, data, client_id: str = None):
    with _get_conn() as conn:
        if client_id:
            row = conn.execute(
                "INSERT INTO software_inventory (host_id, system_id, name, version, vendor, cpe, source, client_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id, host_id, system_id, name, version, vendor, cpe, source, created_at",
                [host_id, system_id, data.name, data.version, data.vendor, data.cpe, data.source, client_id]).fetchone()
        else:
            row = conn.execute(
                "INSERT INTO software_inventory (host_id, system_id, name, version, vendor, cpe, source) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id, host_id, system_id, name, version, vendor, cpe, source, created_at",
                [host_id, system_id, data.name, data.version, data.vendor, data.cpe, data.source]).fetchone()
    return _row_to_software(row)

def list_software(system_id, client_id: str = None):
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, host_id, system_id, name, version, vendor, cpe, source, created_at FROM software_inventory WHERE system_id = ?" + frag + " ORDER BY name",
            [system_id] + params).fetchall()
    return [_row_to_software(r) for r in rows]

def add_software(system_id, data, client_id: str = None):
    with _get_conn() as conn:
        if client_id:
            row = conn.execute(
                "INSERT INTO software_inventory (system_id, name, version, vendor, cpe, source, client_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id, host_id, system_id, name, version, vendor, cpe, source, created_at",
                [system_id, data.name, data.version, data.vendor, data.cpe, data.source, client_id]).fetchone()
        else:
            row = conn.execute(
                "INSERT INTO software_inventory (system_id, name, version, vendor, cpe, source) VALUES (?, ?, ?, ?, ?, ?) RETURNING id, host_id, system_id, name, version, vendor, cpe, source, created_at",
                [system_id, data.name, data.version, data.vendor, data.cpe, data.source]).fetchone()
    return _row_to_software(row)

def get_software(software_id, client_id: str = None):
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT id, host_id, system_id, name, version, vendor, cpe, source, created_at FROM software_inventory WHERE id = ?" + frag,
            [software_id] + params).fetchone()
    return _row_to_software(row) if row else None

def edit_software(software_id, data: SoftwareUpdate, client_id: str = None):
    current = get_software(software_id, client_id=client_id)
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

def delete_software(software_id, client_id: str = None):
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        before = conn.execute("SELECT COUNT(*) FROM software_inventory WHERE id = ?" + frag, [software_id] + params).fetchone()[0]
        conn.execute("DELETE FROM software_inventory WHERE id = ?", [software_id])
    return before > 0

# --- Nessus Parser ---
def parse_nessus_xml(xml_bytes, system_id, client_id: str = None):
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
            host = add_host(system_id, HostCreate(name=host_name, ip_address=ip_address, os=os_name, source="nessus"), client_id=client_id)
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
                    vendor=vendor, cpe=cpe_values[0] if cpe_values else None, source="nessus"), client_id=client_id)
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


_octi_warmup_started: Dict[str, bool] = {}
_octi_warmup_lock = threading.Lock()


def _ensure_opencti_index_warm(client_id: str) -> bool:
    """
    Return True if the OpenCTI bulk index for ``client_id`` is already cached.
    If not, start a one-shot background thread to warm it and return False
    so the caller can skip the enrichment for this request.

    The cache is keyed by client_id because OpenCTI is a per-tenant integration
    (configured via ``client_opencti_map``/``opencti_inventory``). A global
    cache would leak one tenant's threat intel across tenants.
    """
    from app.engine.sync_manager import fetch_opencti_vuln_index, _octi_bulk_cache
    if not client_id:
        return False
    if isinstance(_octi_bulk_cache, dict) and _octi_bulk_cache.get(client_id) is not None:
        return True
    with _octi_warmup_lock:
        if not _octi_warmup_started.get(client_id):
            _octi_warmup_started[client_id] = True
            t = threading.Thread(
                target=fetch_opencti_vuln_index,
                args=(client_id,),
                daemon=True,
                name=f"octi-warmup-{client_id[:8]}",
            )
            t.start()
            logger.info("[opencti-index] Background warm-up started for client %s", client_id)
    return False


def _match_software_against_opencti(
    software_list: list,
    host_sw_cpes: List[str],
    client_id: Optional[str] = None,
) -> Dict[str, Dict]:
    """
    Match host software CPEs against the active client's OpenCTI vulnerability
    index using strict CPE identity (part/vendor/product) matching.

    OpenCTI is per-tenant: without a ``client_id`` — or when the client has no
    OpenCTI assigned — this returns an empty map so no cross-tenant data is
    exposed.

    Returns {cve_id: {description, cvss_score, actors, matched_software}}.
    """
    from app.engine.sync_manager import fetch_opencti_vuln_index, evaluate_opencti_ranges
    from app.engine.cpe_validator import Cpe

    if not client_id:
        return {}

    if not _ensure_opencti_index_warm(client_id):
        return {}   # cache still warming in background — skip enrichment this request

    index = fetch_opencti_vuln_index(client_id)
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

def get_host_vulnerabilities(host_id, client_id: str = None):
    host = get_host(host_id, client_id=client_id)
    if not host:
        return []
    software = list_host_software(host_id, client_id=client_id)
    if not software:
        return []

    detections = list_cve_detections(client_id=client_id)
    applied_map = _load_applied_detections(client_id=client_id)
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

    # --- OpenCTI CPE identity matching (enrichment, per-tenant) ---
    octi_map = _match_software_against_opencti(software, host_sw_cpes, client_id=client_id)

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
                techniques=get_cve_techniques(cve_id, client_id=client_id) if cve_id in matched_map else [],
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

def get_system_vulnerabilities(system_id, client_id: str = None):
    system = get_system(system_id, client_id=client_id)
    if not system:
        return []
    kev = _load_cisa_kev()
    kev_by_id = {k.get("cveID", ""): k for k in (kev or [])}
    detections = list_cve_detections(client_id=client_id)
    combined_sw: Dict[str, List[str]] = {}          # cve_id -> sw names
    combined_hosts: Dict[str, List[AffectedHost]] = {}
    combined_actors: Dict[str, List[str]] = {}      # cve_id -> actor names
    all_software = _list_all_software_by_host(client_id=client_id)

    for host in list_hosts(system_id, client_id=client_id):
        software = all_software.get(host.id, list_host_software(host.id, client_id=client_id))
        if not software:
            continue
        host_sw_cpes: List[str] = [sw.cpe for sw in software if sw.cpe]
        ah = AffectedHost(host_id=host.id, name=host.name, ip_address=host.ip_address,
                          system_id=system.id, system_name=system.name)

        # KEV keyword matches for this host
        kev_matches: Dict[str, List[str]] = {}
        if kev:
            kev_matches = _match_software_against_kev(software, kev, host_os=host.os or "")

        # OpenCTI CPE-identity matches for this host (per-tenant)
        octi_matches = _match_software_against_opencti(software, host_sw_cpes, client_id=client_id)

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

def get_all_cve_overview(client_id: str = None):
    """Return all KEV entries. Matched entries (with affected hosts) come first."""
    kev_entries = _load_cisa_kev()
    if not kev_entries:
        return []
    detections = list_cve_detections(client_id=client_id)
    applied_map = _load_applied_detections(client_id=client_id)
    systems = list_systems(client_id=client_id)
    all_hosts = _list_all_hosts_by_system(client_id=client_id)
    all_software = _list_all_software_by_host(client_id=client_id)
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

def get_cve_detail(cve_id, client_id: str = None):
    kev_entries = _load_cisa_kev()
    kev_entry = next((k for k in kev_entries if k.get("cveID", "").upper() == cve_id.upper()), None)
    if not kev_entry:
        return None
    detections = list_cve_detections(client_id=client_id)
    applied_map = _load_applied_detections(client_id=client_id)
    cve_dets = detections.get(cve_id.upper(), [])
    _enrich_detections_with_applied(cve_dets, applied_map)
    cve_blind_spots = get_blind_spots("cve", cve_id.upper(), client_id=client_id)
    all_affected: List[AffectedHost] = []
    matched_sw: List[str] = []
    all_hosts = _list_all_hosts_by_system(client_id=client_id)
    all_software = _list_all_software_by_host(client_id=client_id)
    for system in list_systems(client_id=client_id):
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
                             techniques=get_cve_techniques(cve_id, client_id=client_id),
                             detections=cve_dets)

# --- Summaries ---
def get_system_summaries(client_id: str = None):
    systems = list_systems(client_id=client_id)
    if not systems:
        return []
    all_hosts = _list_all_hosts_by_system(client_id=client_id)
    all_software = _list_all_software_by_host(client_id=client_id)
    kev = _load_cisa_kev()
    detections = list_cve_detections(client_id=client_id)
    applied_map = _load_applied_detections(client_id=client_id)
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
        # Keep systems list baseline expansions visually consistent with the
        # system detail assurance-baseline cards by including step-level
        # detection metadata (pill coloring + detection counts).
        system_baselines = get_system_baselines(system.id, include_detection_details=True, client_id=client_id)
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
            octi = _match_software_against_opencti(software, host_sw_cpes, client_id=client_id)
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
            baselines=system_baselines,
            worst_status=worst_status))
    return summaries

def get_host_summaries(system_id, client_id: str = None):
    hosts = list_hosts(system_id, client_id=client_id)
    if not hosts:
        return []
    all_software = _list_all_software_by_host(client_id=client_id)
    kev = _load_cisa_kev()
    detections = list_cve_detections(client_id=client_id)
    applied_map = _load_applied_detections(client_id=client_id)
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
            octi = _match_software_against_opencti(software, host_sw_cpes, client_id=client_id)
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
def get_inventory_stats(client_id: str = None) -> InventoryStats:
    """Fast aggregated stats for dashboard widget."""
    frag, params = _cf("", client_id)
    try:
        with _get_conn() as conn:
            env_count = conn.execute("SELECT COUNT(*) FROM systems WHERE 1=1" + frag, params).fetchone()[0]
            host_count = conn.execute("SELECT COUNT(*) FROM hosts WHERE 1=1" + frag, params).fetchone()[0]
            sw_count = conn.execute("SELECT COUNT(*) FROM software_inventory WHERE host_id IS NOT NULL" + frag, params).fetchone()[0]
            baseline_count = conn.execute("SELECT COUNT(*) FROM playbooks WHERE 1=1" + frag, params).fetchone()[0]
            baseline_assignment_count = conn.execute("SELECT COUNT(*) FROM system_baselines WHERE 1=1" + frag, params).fetchone()[0]
            last_scan_row = conn.execute(
                "SELECT MAX(created_at) FROM hosts WHERE 1=1" + frag, params).fetchone()
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
    all_hosts = _list_all_hosts_by_system(client_id=client_id)
    all_software = _list_all_software_by_host(client_id=client_id)
    for system in list_systems(client_id=client_id):
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

def get_cve_overview_stats(cves=None, client_id: str = None) -> CveOverviewStats:
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
        all_hosts = _list_all_hosts_by_system(client_id=client_id)
        all_software = _list_all_software_by_host(client_id=client_id)
        for system in list_systems(client_id=client_id):
            for host in all_hosts.get(system.id, []):
                sw = all_software.get(host.id, [])
                if not sw:
                    continue
                m = _match_software_against_kev(sw, kev, host_os=host.os or "")
                if m:
                    affected_hosts_set.add(host.id)
                    affected_cves.update(m.keys())

    detections = list_cve_detections(client_id=client_id)
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
def list_cve_detections(client_id: str = None) -> Dict[str, List[VulnDetection]]:
    """Returns {cve_id: [VulnDetection, ...]} for all recorded detection rules."""
    frag, params = _cf("", client_id)
    try:
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT id, cve_id, rule_ref, note, source, created_at FROM vuln_detections WHERE 1=1" + frag,
                params,
            ).fetchall()
        result: Dict[str, List[VulnDetection]] = {}
        for r in rows:
            det = VulnDetection(id=r[0], cve_id=r[1], rule_ref=_resolve_rule_ref(r[2]), note=r[3], source=r[4], created_at=r[5])
            result.setdefault(r[1], []).append(det)
        return result
    except Exception as exc:
        logger.warning(f"list_cve_detections error: {exc}")
        return {}

def get_cve_detections(cve_id: str, client_id: str = None) -> List[VulnDetection]:
    """Return all detection entries for a given CVE."""
    frag, params = _cf("", client_id)
    try:
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT id, cve_id, rule_ref, note, source, created_at FROM vuln_detections WHERE cve_id = ?" + frag + " ORDER BY created_at",
                [cve_id.upper()] + params).fetchall()
        return [VulnDetection(id=r[0], cve_id=r[1], rule_ref=_resolve_rule_ref(r[2]), note=r[3], source=r[4], created_at=r[5]) for r in rows]
    except Exception as exc:
        logger.warning(f"get_cve_detections error: {exc}")
        return []

def add_cve_detection(cve_id: str, rule_ref: Optional[str] = None, note: Optional[str] = None, source: str = "manual", client_id: str = None) -> Optional[VulnDetection]:
    """Add a new detection entry for a CVE. Returns the created entry."""
    cve_id = cve_id.upper()
    with _get_conn() as conn:
        if client_id:
            row = conn.execute(
                "INSERT INTO vuln_detections (cve_id, rule_ref, note, source, client_id) VALUES (?, ?, ?, ?, ?) RETURNING id, cve_id, rule_ref, note, source, created_at",
                [cve_id, rule_ref, note, source, client_id]).fetchone()
        else:
            row = conn.execute(
                "INSERT INTO vuln_detections (cve_id, rule_ref, note, source) VALUES (?, ?, ?, ?) RETURNING id, cve_id, rule_ref, note, source, created_at",
                [cve_id, rule_ref, note, source]).fetchone()
    if row:
        return VulnDetection(id=row[0], cve_id=row[1], rule_ref=row[2], note=row[3], source=row[4], created_at=row[5])
    return None

def remove_cve_detection(detection_id: str, client_id: str = None) -> bool:
    """Remove a single detection entry by its ID."""
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        before = conn.execute("SELECT COUNT(*) FROM vuln_detections WHERE id = ?" + frag, [detection_id] + params).fetchone()[0]
        conn.execute("DELETE FROM vuln_detections WHERE id = ?" + frag, [detection_id] + params)
    return before > 0

def get_rules_for_cve_techniques(cve_id: str, client_id: str = None) -> Dict[str, list]:
    """Returns {technique_id: [DetectionRule]} for all techniques mapped to this CVE."""
    from app.services.database import get_database_service
    db = get_database_service()
    techniques = get_cve_techniques(cve_id, client_id=client_id)
    result: Dict[str, list] = {}
    for t in techniques:
        rules = db.get_rules_for_technique(t.technique_id, enabled_only=False, client_id=client_id)
        if rules:
            result[t.technique_id] = rules
    return result


def get_all_siem_rules(client_id: str = None) -> list:
    """Return a list of ALL SIEM rules [{rule_id, name, mitre_ids, severity, enabled}] for dropdowns.

    NOTE (4.1.0): Migration 37 made `detection_rules` per-tenant-scoped — the
    shared schema no longer carries a `client_id` column. Calling `_cf()` here
    against a non-multi-DB deployment would produce `WHERE client_id=?` against
    a column that doesn't exist (BinderException). The table is already tenant-
    scoped (either by tenant DB routing or by being empty in pre-migration
    deployments), so we skip the filter unconditionally."""
    from app.services.database import get_database_service
    db = get_database_service()
    with db.get_connection() as conn:
        rows = conn.execute(
            "SELECT rule_id, name, mitre_ids, severity, enabled, siem_id, space, deprecated "
            "FROM detection_rules ORDER BY name"
        ).fetchall()
        # Each row is one rule at one destination, and the same rule at two destinations is two
        # genuinely different choices to map -- so they must be distinguishable in the picker,
        # by the destination's own name, not collapsed into identical-looking duplicates.
        dest_names = {}
        if client_id:
            try:
                for d in (db.get_client_siems(client_id) or []):
                    dest_names[(d.get("id"), str(d.get("space") or "default"))] = (
                        d.get("name") or d.get("label") or d.get("space")
                    )
            except Exception:
                logger.warning("Destination names unavailable for the rule picker", exc_info=True)
    out = []
    for rid, name, mitre, sev, enabled, siem_id, space, deprecated in rows:
        space = space or "default"
        out.append({
            "rule_id": rid, "name": name, "mitre_ids": mitre or [], "severity": sev or "",
            "enabled": bool(enabled), "siem_id": siem_id, "space": space,
            "deprecated": bool(deprecated),
            "destination": dest_names.get((siem_id, space)) or space,
        })
    return out


# --- Tier 3: Applied Detection CRUD ---

def apply_detection(detection_id: str, system_id: Optional[str] = None, host_id: Optional[str] = None, client_id: str = None) -> Optional[AppliedDetection]:
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
            if client_id:
                row = conn.execute(
                    "INSERT INTO applied_detections (detection_id, system_id, host_id, client_id) VALUES (?, NULL, ?, ?) RETURNING id, detection_id, system_id, host_id, applied_at",
                    [detection_id, host_id, client_id]).fetchone()
            else:
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
                    if client_id:
                        row = conn.execute(
                            "INSERT INTO applied_detections (detection_id, system_id, host_id, client_id) VALUES (?, ?, NULL, ?) RETURNING id, detection_id, system_id, host_id, applied_at",
                            [detection_id, system_id, client_id]).fetchone()
                    else:
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
                    if client_id:
                        row = conn.execute(
                            "INSERT INTO applied_detections (detection_id, system_id, host_id, client_id) VALUES (?, NULL, ?, ?) RETURNING id, detection_id, system_id, host_id, applied_at",
                            [detection_id, hid, client_id]).fetchone()
                    else:
                        row = conn.execute(
                            "INSERT INTO applied_detections (detection_id, system_id, host_id) VALUES (?, NULL, ?) RETURNING id, detection_id, system_id, host_id, applied_at",
                            [detection_id, hid]).fetchone()
                    if row:
                        last = AppliedDetection(id=row[0], detection_id=row[1], system_id=row[2], host_id=row[3], applied_at=row[4])
    return last


def remove_applied_detection(applied_id: str, client_id: str = None) -> bool:
    """Remove an applied detection entry by its ID."""
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        before = conn.execute("SELECT COUNT(*) FROM applied_detections WHERE id = ?" + frag, [applied_id] + params).fetchone()[0]
        conn.execute("DELETE FROM applied_detections WHERE id = ?" + frag, [applied_id] + params)
    return before > 0


def remove_detection_for_system(detection_id: str, system_id: str, client_id: str = None) -> int:
    """Remove applied detection rows for all hosts in a system (and any system-level row). Returns count removed."""
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        # Verify system ownership when client_id is provided
        if client_id:
            owner = conn.execute("SELECT client_id FROM systems WHERE id = ?", [system_id]).fetchone()
            if not owner or owner[0] != client_id:
                return 0
        count = 0
        host_ids = [r[0] for r in conn.execute(
            "SELECT id FROM hosts WHERE system_id = ?", [system_id]).fetchall()]
        if host_ids:
            placeholders = ",".join("?" for _ in host_ids)
            count += conn.execute(
                f"DELETE FROM applied_detections WHERE detection_id = ? AND host_id IN ({placeholders})" + frag,
                [detection_id] + host_ids + params).rowcount
        # Also remove system-level row (used when system has no hosts)
        count += conn.execute(
            "DELETE FROM applied_detections WHERE detection_id = ? AND system_id = ? AND host_id IS NULL" + frag,
            [detection_id, system_id] + params).rowcount
    return count


def _load_applied_detections(client_id: str = None) -> Dict[str, List[AppliedDetection]]:
    """Load all applied detections keyed by detection_id for fast lookup.
    Migrates any legacy system-level rows (system_id set, host_id NULL) to per-host rows."""
    frag, params = _cf("", client_id)
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
                "SELECT id, detection_id, system_id, host_id, applied_at FROM applied_detections WHERE 1=1" + frag,
                params).fetchall()
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
    from detection_rules. Otherwise return as-is.

    Orphan handling (4.1.14): when a rule_ref looks like a rule UUID but no
    matching ``detection_rules`` row exists in the active tenant DB, we now
    return ``"⚠ Detached: <short_uuid>"`` instead of the bare UUID. This
    happens when the operator removes a SIEM mapping (or moves a SIEM to a
    different space) and the orphan-sweep in
    ``app/services/sync.py:run_elastic_sync`` has cleaned up the
    ``detection_rules`` rows. The mapping in ``step_detections`` /
    ``vuln_detections`` is intentionally preserved (no FK cascade — see
    schema in ``app/services/tenant_manager.py``) so the operator's hours of
    baseline-mapping work survive a temporary sync regression or a deliberate
    promote-to-staging move. The "Detached" prefix tells them the link still
    exists but the source rule is currently absent from production rules,
    while keeping the short UUID for debugging.
    """
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
            # UUID-shaped but not present in the tenant's detection_rules —
            # mark as Detached so the operator can distinguish "rule
            # temporarily missing" from "free-text rule reference".
            return f"⚠ Detached: {rule_ref[:8]}"
        except Exception:
            pass
    return rule_ref


def _enrich_detections_with_applied(detections: List[VulnDetection],
                                    applied_map: Dict[str, List[AppliedDetection]]) -> List[VulnDetection]:
    """Attach applied_to entries to each VulnDetection."""
    for det in detections:
        det.applied_to = applied_map.get(det.id, [])
    return detections


def _bs_cols(alias: str = "") -> str:
    """The blind_spots columns every reader selects, in the order ``_bs_from_row`` reads them."""
    p = f"{alias}." if alias else ""
    return (f"{p}id, {p}entity_type, {p}entity_id, {p}system_id, {p}host_id, {p}reason, {p}created_by, "
            f"{p}created_at, COALESCE({p}override_type, 'gap'), {p}review_by, {p}updated_at, {p}updated_by")


def _bs_from_row(r) -> BlindSpot:
    return BlindSpot(id=r[0], entity_type=r[1], entity_id=r[2], system_id=r[3], host_id=r[4],
                     reason=r[5], created_by=r[6] or "", created_at=r[7], override_type=r[8] or "gap",
                     review_by=r[9], updated_at=r[10], updated_by=r[11] or "")


def _load_all_blind_spots(entity_type: str, client_id: str = None) -> Dict[str, List[BlindSpot]]:
    """Load all blind spots of a given type, grouped by entity_id."""
    frag, params = _cf("", client_id)
    try:
        with _get_conn() as conn:
            rows = conn.execute(
                f"SELECT {_bs_cols()} FROM blind_spots WHERE entity_type = ?" + frag,
                [entity_type] + params,
            ).fetchall()
        result: Dict[str, List[BlindSpot]] = {}
        for r in rows:
            result.setdefault(r[2], []).append(_bs_from_row(r))
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

def _build_baseline_heatmap(baselines: List[Dict], client_id: str = None) -> Dict:
    """Build MITRE ATT&CK heatmap matrix from baseline coverage data.

    Returns dict with: matrix, active_tactics, metrics, narrative.
    """
    try:
        from app.services.report_generator import TACTIC_ORDER
    except Exception:
        TACTIC_ORDER = [
            "Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Command and Control", "Exfiltration", "Impact",
            "Reconnaissance", "Resource Dev", "Other",
        ]

    try:
        from app.services.database import get_database_service
        _db = get_database_service()
        ttp_names = _db.get_technique_names()
        ttp_rule_counts = _db.get_ttp_rule_counts(client_id=client_id)
    except Exception:
        ttp_names = {}
        ttp_rule_counts = {}

    _STATUS_PRIORITY = {"green": 0, "grey": 1, "amber": 2, "red": 3}
    _STATUS_MAP = {"green": "covered", "grey": "na", "amber": "known-gap", "red": "gap"}

    # Aggregate: (tactic, technique_id) → best status + metadata
    cells: Dict[tuple, Dict] = {}

    for bl in baselines:
        for step in bl.get("tactics", []):
            tid = (step.get("technique_id") or "").strip().upper()
            tactic = step.get("tactic") or ""
            if not tid or not tactic:
                continue

            key = (tactic, tid)
            curr_status = step.get("status", "red")
            rule_names = [
                d.get("rule_ref") or d.get("note", "")
                for d in step.get("applied_dets", [])
                if d.get("rule_ref") or d.get("note")
            ]

            existing = cells.get(key)
            if existing is None or _STATUS_PRIORITY.get(curr_status, 3) < _STATUS_PRIORITY.get(existing["baseline_status"], 3):
                cells[key] = {
                    "id": tid,
                    "name": ttp_names.get(tid, tid),
                    "tactic": tactic,
                    "status": _STATUS_MAP.get(curr_status, "gap"),
                    "baseline_status": curr_status,
                    "rule_count": ttp_rule_counts.get(tid, 0),
                    "rule_names": rule_names,
                }

    # Organize into matrix by tactic
    matrix: Dict[str, list] = {t: [] for t in TACTIC_ORDER}
    for (_tactic, _tid), cell_data in cells.items():
        target = _tactic if _tactic in matrix else "Other"
        matrix[target].append(cell_data)

    for t in matrix:
        matrix[t].sort(key=lambda c: c["id"])

    active_tactics = [t for t in TACTIC_ORDER if matrix.get(t)]

    # Metrics
    total_techniques = len(cells)
    covered_count = sum(1 for c in cells.values() if c["baseline_status"] == "green")
    na_count = sum(1 for c in cells.values() if c["baseline_status"] == "grey")
    gap_count = total_techniques - covered_count - na_count
    effective_total = total_techniques - na_count
    coverage_pct = round(covered_count / effective_total * 100) if effective_total else (100 if total_techniques else 0)

    # Count tactics with at least one covered technique
    monitored_tactics = len([t for t in active_tactics if any(c["baseline_status"] == "green" for c in matrix[t])])

    if coverage_pct >= 75:
        narrative = (
            f"Detection coverage is robust. "
            f"{monitored_tactics} tactics and {covered_count} techniques are actively monitored, "
            f"covering {coverage_pct}% of defined threat profiles."
        )
    elif coverage_pct >= 40:
        narrative = (
            f"Coverage is moderate at {coverage_pct}%. "
            f"Priority visibility gaps exist in specific tactics that require mitigation."
        )
    else:
        narrative = (
            f"Critical visibility gaps detected. "
            f"Environment lacks sufficient telemetry for the majority of applied threat baselines "
            f"({coverage_pct}% coverage)."
        )

    return {
        "matrix": matrix,
        "active_tactics": active_tactics,
        "total_techniques": total_techniques,
        "covered_techniques": covered_count,
        "gap_techniques": gap_count,
        "na_techniques": na_count,
        "coverage_pct": coverage_pct,
        "narrative": narrative,
    }


def build_system_report_data(system_id: str, include_devices: bool = True, client_id: str = None) -> Optional[Dict]:
    """Build all data needed for System detail reports (CISO + Technical).
    
    Args:
        system_id: System ID to build report for
        include_devices: If False, excludes all device/host-specific tables and metrics
    """
    system = get_system(system_id, client_id=client_id)
    if not system:
        return None

    kev = _load_cisa_kev()
    kev_by_id = {k.get("cveID", ""): k for k in (kev or [])}
    detections = list_cve_detections(client_id=client_id)
    applied_map = _load_applied_detections(client_id=client_id)
    for dets in detections.values():
        _enrich_detections_with_applied(dets, applied_map)

    all_software = _list_all_software_by_host(client_id=client_id)
    hosts = list_hosts(system_id, client_id=client_id)

    # Load all CVE blind spots once
    all_blind_spots = _load_all_blind_spots("cve", client_id=client_id)

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

    # When include_devices is False, exclude all device-specific data from the report
    baselines = get_system_baselines(system_id)
    snapshots = get_baseline_snapshots(system_id)
    try:
        heatmap = _build_baseline_heatmap(baselines, client_id=client_id)
    except Exception as _e:
        import logging as _log
        _log.getLogger(__name__).warning(f"Baseline heatmap build failed: {_e}")
        heatmap = {
            "matrix": {}, "active_tactics": [],
            "total_techniques": 0, "covered_techniques": 0,
            "gap_techniques": 0, "na_techniques": 0,
            "coverage_pct": 0, "narrative": "",
        }

    if not include_devices:
        return {
            "system": {"name": system.name, "description": system.description or "", "classification": system.classification or ""},
            "generated_at": __import__("datetime").datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            "total_hosts": 0,  # Hide device count
            "total_cves": 0,   # Hide CVE count (it would show exposed systems without remediation)
            "red_hosts": 0,
            "amber_hosts": 0,
            "green_hosts": 0,
            "grey_hosts": 0,
            "total_red_pairs": 0,
            "total_amber_pairs": 0,
            "total_grey_pairs": 0,
            "coverage_ratio": 100,  # No device-specific coverage metrics
            "top5_cves": [],       # Exclude device-specific CVE breakdown
            "host_rows": [],       # Exclude all host-specific tables
            "all_cves": [],        # Exclude device-specific CVE details
            "baselines": baselines,
            "snapshots": snapshots,
            "baseline_matrix": heatmap["matrix"],
            "baseline_active_tactics": heatmap["active_tactics"],
            "baseline_narrative": heatmap["narrative"],
            "bl_total_techniques": heatmap["total_techniques"],
            "bl_covered_techniques": heatmap["covered_techniques"],
            "bl_gap_techniques": heatmap["gap_techniques"],
            "bl_na_techniques": heatmap["na_techniques"],
            "bl_coverage_pct": heatmap["coverage_pct"],
        }
    
    # Full report when include_devices is True
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
        "baselines": baselines,
        "snapshots": snapshots,
        "baseline_matrix": heatmap["matrix"],
        "baseline_active_tactics": heatmap["active_tactics"],
        "baseline_narrative": heatmap["narrative"],
        "bl_total_techniques": heatmap["total_techniques"],
        "bl_covered_techniques": heatmap["covered_techniques"],
        "bl_gap_techniques": heatmap["gap_techniques"],
        "bl_na_techniques": heatmap["na_techniques"],
        "bl_coverage_pct": heatmap["coverage_pct"],
    }


def build_cve_report_data(cve_id: str, search_filter: str = "", client_id: str = None) -> Optional[Dict]:
    """Build all data needed for the CVE Audit Report."""
    kev_entries = _load_cisa_kev()
    kev_entry = next((k for k in kev_entries if k.get("cveID", "").upper() == cve_id.upper()), None)
    if not kev_entry:
        return None

    detections_map = list_cve_detections(client_id=client_id)
    applied_map = _load_applied_detections(client_id=client_id)
    cve_dets = detections_map.get(cve_id.upper(), [])
    _enrich_detections_with_applied(cve_dets, applied_map)

    techniques = get_cve_techniques(cve_id, client_id=client_id)
    technique_rules = get_rules_for_cve_techniques(cve_id, client_id=client_id)
    cve_blind_spots = get_blind_spots("cve", cve_id.upper(), client_id=client_id)

    # Build affected systems/hosts matrix
    all_hosts_by_sys = _list_all_hosts_by_system(client_id=client_id)
    all_software = _list_all_software_by_host(client_id=client_id)
    systems_map: Dict[str, Dict] = {}

    for system in list_systems(client_id=client_id):
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


def build_baseline_report_data(baseline_id: str, client_id: str = None) -> Optional[Dict]:
    """Build the data for a template's report: its definition only. A template carries no
    coverage and has no link to the systems it was applied to -- each system's report covers
    its own copy."""
    playbook = get_playbook(baseline_id, client_id=client_id)
    if not playbook:
        return None
    total_techniques = sum(len(step.techniques) for step in playbook.tactics)

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
        "total_steps": len(playbook.tactics),
        "total_techniques": total_techniques,
        "steps": steps,
        "generated_at": __import__("datetime").datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    }


# ---------------------------------------------------------------------------
# Baselines — Engine
# ---------------------------------------------------------------------------

def list_playbooks(client_id: str = None) -> List[Playbook]:
    """Every template. A system's own copies are reached through that system."""
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, name, description, created_at, updated_at FROM playbooks WHERE system_id IS NULL"
            + frag + " ORDER BY name",
            params,
        ).fetchall()
    result = []
    for r in rows:
        pb = Playbook(id=r[0], name=r[1], description=r[2] or "", created_at=r[3], updated_at=r[4])
        pb.tactics = _get_playbook_steps(r[0])
        result.append(pb)
    return result


def count_playbooks(client_id: str = None) -> int:
    """Lightweight COUNT(*) of templates.

    Used by the Management hub badge count to avoid the per-playbook
    `_get_playbook_steps` fan-out triggered by `list_playbooks`.
    """
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM playbooks WHERE system_id IS NULL" + frag,
            params,
        ).fetchone()
    return int(row[0]) if row else 0

def assign_baseline_to_client(baseline_id: str, client_id: str) -> bool:
    with _get_conn() as conn:
        r = conn.execute("SELECT id, client_id FROM playbooks WHERE id = ?", [baseline_id]).fetchone()
        if not r:
            return False
        conn.execute("UPDATE playbooks SET client_id = ? WHERE id = ?", [client_id, baseline_id])
        # Cascade to system_baselines linking this playbook
        conn.execute("UPDATE system_baselines SET client_id = ? WHERE playbook_id = ?",
                     [client_id, baseline_id])
    return True

def unassign_baseline_from_client(baseline_id: str, client_id: str, default_client_id: str = None) -> bool:
    with _get_conn() as conn:
        r = conn.execute("SELECT id FROM playbooks WHERE id = ? AND client_id = ?", [baseline_id, client_id]).fetchone()
        if not r:
            return False
        target_client = default_client_id or client_id
        conn.execute("UPDATE playbooks SET client_id = ? WHERE id = ?", [target_client, baseline_id])
        conn.execute("UPDATE system_baselines SET client_id = ? WHERE playbook_id = ?",
                     [target_client, baseline_id])
    return True


def get_baselines_overview(client_id: str = None) -> List[Dict]:
    """Every template, for the Baselines page and the dashboard: its techniques and tactics.

    A template carries no coverage and knows nothing of the systems it was applied to -- their
    copies have no link back. How systems are covered is :func:`get_system_baselines_rollup`."""
    frag, fparams = _cf("", client_id)
    with _get_conn() as conn:
        pbs = conn.execute(
            "SELECT id, name, description FROM playbooks WHERE system_id IS NULL" + frag + " ORDER BY name",
            fparams,
        ).fetchall()
        steps = conn.execute(
            "SELECT s.playbook_id, s.technique_id, COALESCE(NULLIF(s.tactic, ''), 'Other'), "
            "(SELECT COUNT(*) FROM step_techniques t WHERE t.step_id = s.id) FROM playbook_steps s"
        ).fetchall()

    step_count: Dict[str, int] = {}
    technique_count: Dict[str, int] = {}
    tactics: Dict[str, set] = {}
    for pb_id, tech, tactic, n_tech in steps:
        step_count[pb_id] = step_count.get(pb_id, 0) + 1
        technique_count[pb_id] = technique_count.get(pb_id, 0) + (n_tech or (1 if (tech or "").strip() else 0))
        tactics.setdefault(pb_id, set()).add(tactic)
    return [{
        "id": pb_id,
        "name": name,
        "description": desc or "",
        "step_count": step_count.get(pb_id, 0),
        "technique_count": technique_count.get(pb_id, 0),
        "tactic_count": len(tactics.get(pb_id, ())),
    } for pb_id, name, desc in pbs]


def count_system_baselines(client_id: str = None) -> int:
    """How many baselines systems have of their own (each applied template is one copy)."""
    frag, fparams = _cf("p.", client_id)
    with _get_conn() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM playbooks p JOIN systems s ON s.id = p.system_id WHERE 1=1" + frag, fparams,
        ).fetchone()[0]


def get_system_baselines_rollup(client_id: str = None) -> Dict[str, int]:
    """Every system's own baselines, scored exactly as each system's page scores them: how many
    there are, rules mapped across them, and how many have an uncovered technique (red) or are
    fully covered (green). For the dashboard and the Baselines page."""
    frag, fparams = _cf("p.", client_id)
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT p.system_id, p.id FROM playbooks p JOIN systems s ON s.id = p.system_id "
            "WHERE p.system_id IS NOT NULL" + frag,
            fparams,
        ).fetchall()
    by_system: Dict[str, List[str]] = {}
    for sys_id, pb_id in rows:
        by_system.setdefault(sys_id, []).append(pb_id)
    out = {"baselines": 0, "rules_mapped": 0, "red": 0, "green": 0}
    for sys_id, ids in by_system.items():
        for b in get_system_baselines(sys_id, playbook_ids=ids, include_detection_details=False, client_id=client_id):
            red = b["total_steps"] - b["covered_steps"] - b["gap_steps"] - b["na_steps"]
            out["baselines"] += 1
            out["rules_mapped"] += sum(t["mapped_count"] for t in b["tactics"])
            out["red"] += 1 if red else 0
            out["green"] += 1 if not red and not b["gap_steps"] and b["covered_steps"] else 0
    return out


def get_playbook_header(playbook_id: str, client_id: str = None) -> Optional[Playbook]:
    """Lightweight playbook fetch — no steps loaded. For breadcrumbs etc."""
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        r = conn.execute(
            "SELECT id, name, description, created_at, updated_at, system_id "
            "FROM playbooks WHERE id = ?" + frag,
            [playbook_id] + params,
        ).fetchone()
    if not r:
        return None
    return Playbook(id=r[0], name=r[1], description=r[2] or "", created_at=r[3], updated_at=r[4],
                    system_id=r[5])


def get_playbook(playbook_id: str, client_id: str = None) -> Optional[Playbook]:
    pb = get_playbook_header(playbook_id, client_id=client_id)
    if pb:
        pb.tactics = _get_playbook_steps(playbook_id)
    return pb


def get_template(playbook_id: str, client_id: str = None) -> Optional[Playbook]:
    """A template with its techniques, or None -- including for a system's own copy, which is
    only ever reached through its system."""
    pb = get_playbook(playbook_id, client_id=client_id)
    return pb if pb and not pb.system_id else None


def _step_system_id(conn, step_id: str) -> Optional[str]:
    """The system a step's baseline belongs to; None for a template's step (or no such step)."""
    row = conn.execute(
        "SELECT p.system_id FROM playbook_steps s JOIN playbooks p ON p.id = s.playbook_id WHERE s.id = ?",
        [step_id],
    ).fetchone()
    return row[0] if row else None


def _get_playbook_steps(playbook_id: str) -> List[PlaybookStep]:
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, playbook_id, step_number, title, technique_id, required_rule, description, tactic, "
            "priority, category "
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
            f"SELECT id, step_id, rule_ref, note, source, siem_id, space, created_at, created_by "
            f"FROM step_detections WHERE step_id IN ({sp}) ORDER BY rule_ref",
            step_ids,
        ).fetchall()
        step_dets = {}
        for did, sid, rref, note, source, dsiem, dspace, made_at, made_by in det_rows:
            step_dets.setdefault(sid, []).append(
                StepDetection(id=did, step_id=sid, rule_ref=rref or "", note=note or "",
                              source=source or "manual", siem_id=dsiem, space=dspace,
                              created_at=made_at, created_by=made_by)
            )

    steps = []
    for r in rows:
        step_id = r[0]
        step = PlaybookStep(
            id=step_id, playbook_id=r[1], step_number=r[2], title=r[3],
            technique_id=r[4] or "", required_rule=r[5] or "", description=r[6] or "",
            tactic=r[7] or "", **_risk_fields(r[8:10]),
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
            "SELECT id, step_id, rule_ref, note, source, siem_id, space, created_at, created_by "
            "FROM step_detections WHERE step_id = ? ORDER BY rule_ref",
            [step_id],
        ).fetchall()
    return [
        StepDetection(id=r[0], step_id=r[1], rule_ref=r[2] or "", note=r[3] or "",
                      source=r[4] or "manual", siem_id=r[5], space=r[6],
                      created_at=r[7], created_by=r[8])
        for r in rows
    ]


def create_playbook(name: str, description: str = "", client_id: str = None) -> Playbook:
    with _get_conn() as conn:
        if client_id:
            r = conn.execute(
                "INSERT INTO playbooks (name, description, client_id) VALUES (?, ?, ?) RETURNING id, name, description, created_at, updated_at",
                [name, description, client_id],
            ).fetchone()
        else:
            r = conn.execute(
                "INSERT INTO playbooks (name, description) VALUES (?, ?) RETURNING id, name, description, created_at, updated_at",
                [name, description],
            ).fetchone()
    return Playbook(id=r[0], name=r[1], description=r[2] or "", created_at=r[3], updated_at=r[4])


def update_playbook(playbook_id: str, name: str = None, description: str = None, client_id: str = None) -> Optional[Playbook]:
    """Update editable fields on a playbook (baseline)."""
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        sets, vals = [], []
        if name is not None:
            sets.append("name = ?"); vals.append(name)
        if description is not None:
            sets.append("description = ?"); vals.append(description)
        if sets:
            vals.append(playbook_id)
            conn.execute(f"UPDATE playbooks SET {', '.join(sets)} WHERE id = ?" + frag, vals + params)
    return get_playbook(playbook_id, client_id=client_id)


def generate_baseline_from_actor(
    actor_name: str,
    ttps: list,
    technique_tactic_map: dict,
    technique_name_map: dict,
    technique_description_map: Optional[Dict[str, str]] = None,
    baseline_name: str = "",
    description: str = "",
    client_id: str = None,
) -> Playbook:
    """Create a Baseline Playbook from a Threat Actor's MITRE technique set.

    Uses a single DB connection for the entire operation to avoid
    per-step connection overhead.
    """
    from app.api.heatmap import get_tactic_display

    name = baseline_name.strip() if baseline_name.strip() else f"{actor_name} Baseline"
    desc = description.strip() if description.strip() else f"Auto-generated from {actor_name} threat profile ({len(ttps)} techniques)."
    technique_description_map = technique_description_map or {}

    sorted_ttps = sorted(set(t.strip().upper() for t in ttps if t.strip()))

    with _get_conn() as conn:
        # Create playbook
        if client_id:
            pb_row = conn.execute(
                "INSERT INTO playbooks (name, description, client_id) VALUES (?, ?, ?) "
                "RETURNING id, name, description, created_at, updated_at",
                [name, desc, client_id],
            ).fetchone()
        else:
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
            step_description = (technique_description_map.get(tech_id) or "").strip()

            step_row = conn.execute(
                "INSERT INTO playbook_steps (playbook_id, step_number, title, technique_id, required_rule, description, tactic) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
                [playbook.id, idx, title, tech_id, "", step_description, tactic_val],
            ).fetchone()
            step_id = step_row[0]

            conn.execute(
                "INSERT INTO step_techniques (step_id, technique_id) VALUES (?, ?)",
                [step_id, tech_id],
            )

    return playbook


def _delete_steps(conn, step_ids: List[str]) -> int:
    """Delete steps and everything recorded on them: ATT&CK techniques, rule mappings (and where
    they were applied), known gaps and N/A, and history. Returns the number of steps deleted."""
    if not step_ids:
        return 0
    ph = ",".join("?" for _ in step_ids)
    conn.execute(
        f"DELETE FROM applied_detections WHERE detection_id IN (SELECT id FROM step_detections WHERE step_id IN ({ph}))",
        step_ids,
    )
    conn.execute(f"DELETE FROM step_detections WHERE step_id IN ({ph})", step_ids)
    conn.execute(f"DELETE FROM step_techniques WHERE step_id IN ({ph})", step_ids)
    conn.execute(f"DELETE FROM technique_events WHERE step_id IN ({ph})", step_ids)
    conn.execute(f"DELETE FROM step_sigma_dismissals WHERE step_id IN ({ph})", step_ids)
    conn.execute(f"DELETE FROM blind_spots WHERE entity_type = 'tactic' AND entity_id IN ({ph})", step_ids)
    from app.services.database import DatabaseService
    conn.execute(DatabaseService.STEP_COVERAGE_DDL)
    conn.execute(f"DELETE FROM step_coverage WHERE step_id IN ({ph})", step_ids)
    return conn.execute(f"DELETE FROM playbook_steps WHERE id IN ({ph})", step_ids).rowcount


def _delete_playbook_rows(conn, playbook_id: str) -> int:
    step_ids = [r[0] for r in conn.execute(
        "SELECT id FROM playbook_steps WHERE playbook_id = ?", [playbook_id]
    ).fetchall()]
    _delete_steps(conn, step_ids)
    conn.execute("DELETE FROM system_baselines WHERE playbook_id = ?", [playbook_id])
    conn.execute("DELETE FROM system_baseline_snapshots WHERE baseline_id = ?", [playbook_id])
    return conn.execute("DELETE FROM playbooks WHERE id = ?", [playbook_id]).rowcount


def delete_playbook(playbook_id: str, client_id: str = None) -> bool:
    """Delete a template, or a system's copy with everything recorded on it. Deleting a template
    leaves the systems' copies of it alone: they belong to those systems."""
    with _get_conn() as conn:
        if client_id:
            owner = conn.execute("SELECT client_id FROM playbooks WHERE id = ?", [playbook_id]).fetchone()
            if not owner or owner[0] != client_id:
                return False
        return _delete_playbook_rows(conn, playbook_id) > 0


def _copy_playbook(src, tgt, playbook_id: str, *, name: str, client_id: str,
                   system_id: str = None) -> Tuple[str, int]:
    """Copy a baseline's techniques into a new baseline with fresh ids. Rule mappings, gaps and
    history are never copied -- they describe one system. ``src`` and ``tgt`` may be the same
    connection. Returns (new baseline id, number of techniques).

    With ``system_id`` the copy is that system's own and keeps nothing of the template but each
    technique's title, ATT&CK techniques (its tactic follows the first) and description -- no
    link back to the template, no Sigma suggestions (the technique window suggests those from
    its ATT&CK ids), no required rule. A template copied to another client keeps everything."""
    import uuid
    new_id = str(uuid.uuid4())
    desc = src.execute("SELECT description FROM playbooks WHERE id = ?", [playbook_id]).fetchone()
    tgt.execute(
        "INSERT INTO playbooks (id, name, description, client_id, system_id) VALUES (?, ?, ?, ?, ?)",
        [new_id, name, (desc[0] if desc else "") or "", client_id, system_id],
    )
    steps = src.execute(
        "SELECT id, step_number, title, technique_id, required_rule, description, tactic "
        "FROM playbook_steps WHERE playbook_id = ?",
        [playbook_id],
    ).fetchall()
    for step in steps:
        new_step = str(uuid.uuid4())
        _sid, number, title, technique_id, required_rule, step_desc, tactic = step
        tgt.execute(
            "INSERT INTO playbook_steps (id, playbook_id, step_number, title, technique_id, required_rule, "
            "description, tactic) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [new_step, new_id, number, title, technique_id, "" if system_id else required_rule, step_desc, tactic],
        )
        for (tech,) in src.execute("SELECT technique_id FROM step_techniques WHERE step_id = ?", [step[0]]).fetchall():
            tgt.execute("INSERT INTO step_techniques (step_id, technique_id) VALUES (?, ?)", [new_step, tech])
        if system_id:
            continue
        for ref, note in src.execute(
            "SELECT rule_ref, note FROM step_detections WHERE step_id = ? AND source = 'sigma'", [step[0]]
        ).fetchall():
            tgt.execute(
                "INSERT INTO step_detections (step_id, rule_ref, note, source, created_at) "
                "VALUES (?, ?, ?, 'sigma', CURRENT_TIMESTAMP)",
                [new_step, ref, note],
            )
    return new_id, len(steps)


def add_playbook_step(playbook_id: str, step_number: int, title: str,
                      technique_id: str = "", required_rule: str = "",
                      description: str = "", tactic: str = "", client_id: str = None) -> PlaybookStep:
    normalized_technique_id = normalize_technique_id(technique_id)
    with _get_conn() as conn:
        r = conn.execute(
            "INSERT INTO playbook_steps (playbook_id, step_number, title, technique_id, required_rule, description, tactic) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id, playbook_id, step_number, title, technique_id, required_rule, description, tactic",
            [playbook_id, step_number, title, normalized_technique_id, required_rule, description, tactic],
        ).fetchone()
    step = PlaybookStep(id=r[0], playbook_id=r[1], step_number=r[2], title=r[3],
                        technique_id=r[4] or "", required_rule=r[5] or "", description=r[6] or "",
                        tactic=r[7] or "")
    # Auto-populate junction tables from legacy single fields
    if normalized_technique_id:
        add_step_technique(step.id, normalized_technique_id)
        step.techniques = _get_step_techniques(step.id)
    return step


def delete_playbook_step(step_id: str, client_id: str = None) -> bool:
    with _get_conn() as conn:
        return _delete_steps(conn, [step_id]) > 0


def _unique_baseline_name(conn, system_id: str, name: str) -> str:
    """``name``, or ``name (copy)``, ``name (copy) (copy)``… -- whichever this system does not
    already have. A template can be applied to one system more than once."""
    taken = {r[0] for r in conn.execute("SELECT name FROM playbooks WHERE system_id = ?", [system_id]).fetchall()}
    while name in taken:
        name = f"{name} (copy)"
    return name


def apply_baseline(system_id: str, playbook_id: str, client_id: str = None) -> SystemBaseline:
    """Give a system its own copy of a template. From then on the copy is the system's alone,
    with no link back: its techniques, mappings and gaps never touch the template or any other
    system, and changing the template never reaches it. Applying the same template again makes
    another copy, named "<name> (copy)"."""
    with _get_conn() as conn:
        # Validate same-client ownership when client_id is provided
        if client_id:
            sys_client = conn.execute("SELECT client_id FROM systems WHERE id = ?", [system_id]).fetchone()
            pb_client = conn.execute("SELECT client_id FROM playbooks WHERE id = ?", [playbook_id]).fetchone()
            if not sys_client or sys_client[0] != client_id:
                raise ValueError(f"System {system_id} does not belong to active client")
            if not pb_client or pb_client[0] != client_id:
                raise ValueError(f"Baseline {playbook_id} does not belong to active client")
        template = conn.execute("SELECT name, system_id FROM playbooks WHERE id = ?", [playbook_id]).fetchone()
        if not template or template[1]:
            raise ValueError("Only a baseline template can be applied to a system")
        copy_id, _ = _copy_playbook(conn, conn, playbook_id, client_id=client_id, system_id=system_id,
                                    name=_unique_baseline_name(conn, system_id, template[0]))
        r = conn.execute(
            "INSERT INTO system_baselines (system_id, playbook_id, client_id) VALUES (?, ?, ?) "
            "RETURNING id, system_id, playbook_id, applied_at",
            [system_id, copy_id, client_id],
        ).fetchone()
    return SystemBaseline(id=r[0], system_id=r[1], playbook_id=r[2], applied_at=r[3])


def create_system_baseline(system_id: str, name: str, description: str = "",
                           client_id: str = None) -> SystemBaseline:
    """Start an empty baseline that belongs to this system alone, with no template behind it.
    A name the system already has becomes "<name> (copy)"."""
    import uuid
    with _get_conn() as conn:
        if client_id:
            owner = conn.execute("SELECT client_id FROM systems WHERE id = ?", [system_id]).fetchone()
            if not owner or owner[0] != client_id:
                raise ValueError(f"System {system_id} does not belong to active client")
        name = _unique_baseline_name(conn, system_id, name)
        pb_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO playbooks (id, name, description, client_id, system_id) VALUES (?, ?, ?, ?, ?)",
            [pb_id, name, description, client_id, system_id],
        )
        r = conn.execute(
            "INSERT INTO system_baselines (system_id, playbook_id, client_id) VALUES (?, ?, ?) "
            "RETURNING id, system_id, playbook_id, applied_at",
            [system_id, pb_id, client_id],
        ).fetchone()
    return SystemBaseline(id=r[0], system_id=r[1], playbook_id=r[2], applied_at=r[3])


def remove_baseline(system_id: str, playbook_id: str, client_id: str = None) -> bool:
    """Remove a system's own baseline, and with it the rule mappings, known gaps and history
    recorded on it. The template it came from is untouched."""
    with _get_conn() as conn:
        if client_id:
            sys_client = conn.execute("SELECT client_id FROM systems WHERE id = ?", [system_id]).fetchone()
            if not sys_client or sys_client[0] != client_id:
                raise ValueError(f"System {system_id} does not belong to active client")
        owner = conn.execute("SELECT system_id FROM playbooks WHERE id = ?", [playbook_id]).fetchone()
        if not owner or owner[0] != system_id:
            raise ValueError("That baseline does not belong to this system")
        return _delete_playbook_rows(conn, playbook_id) > 0


def get_system_coverage_destinations(system_id: str, client_id: str = None) -> List[Tuple[str, str]]:
    """The ``(siem_id, space)`` destinations whose rules count toward this system's coverage.

    Per system, not per tenant: a system is watched by whichever SIEM+space actually watches it.
    An empty list means nobody has answered the question for this system yet -- callers must
    treat that as *undefined*, never as "nothing counts", or an unanswered question reads as a
    total failure of coverage.
    """
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT siem_id, space FROM system_coverage_destinations WHERE system_id = ?",
            [system_id],
        ).fetchall()
    return [(r[0], r[1] or "default") for r in rows]


def set_system_coverage_destinations(system_id: str, scopes: List[Tuple[str, str]],
                                     client_id: str = None, actor: str = None) -> int:
    """Replace this system's counted destinations with ``scopes``. Returns how many are counted."""
    before = set(get_system_coverage_destinations(system_id, client_id=client_id))
    after = {(s, sp or "default") for s, sp in scopes if s}
    with _get_conn() as conn:
        conn.execute("DELETE FROM system_coverage_destinations WHERE system_id = ?", [system_id])
        for siem_id, space in sorted(after):
            conn.execute(
                "INSERT INTO system_coverage_destinations (system_id, siem_id, space, client_id, created_by) "
                "VALUES (?, ?, ?, ?, ?)",
                [system_id, siem_id, space, client_id, actor],
            )
        if before != after:
            name = lambda sc: _destination_name(sc[0], sc[1], client_id) or sc[1]  # noqa: E731
            parts = []
            if after - before:
                parts.append("now counts " + ", ".join(sorted(name(x) for x in after - before)))
            if before - after:
                parts.append("stopped counting " + ", ".join(sorted(name(x) for x in before - after)))
            _record_technique_event(
                conn, "siem_coverage", system_id=system_id, detail="; ".join(parts),
                actor=actor, client_id=client_id,
            )
    return len(after)


def _counted_scope_resolver(system_id: str, steps_detections, client_id: str = None):
    """Build ``(detection) -> bool`` for "does this mapping count toward this system?".

    A mapping names one destination, but the same detection may have been copied to others --
    that is what Move-as-copy does, and ``rule_links`` records it. So the anchor destination the
    user picked AND every destination it is linked to are considered; if any of them is one this
    system counts, the mapping counts.

    Returns ``(counts_fn, counted_scopes, undefined)``. ``undefined`` is True when the system has
    no answer recorded at all, in which case ``counts_fn`` passes everything through -- coverage
    is unchanged until somebody says what counts.
    """
    counted = {(s, sp) for s, sp in get_system_coverage_destinations(system_id, client_id=client_id)}
    if not counted:
        return (lambda _d: True), counted, True

    anchors = [
        (d.rule_ref, d.siem_id, d.space or "default")
        for d in steps_detections
        if getattr(d, "siem_id", None) and d.rule_ref
    ]
    linked_map: Dict[Tuple[str, str, str], set] = {}
    if anchors:
        try:
            from app.services.database import get_database_service
            links = get_database_service().get_rule_links_bulk(anchors)
            for key, entries in (links or {}).items():
                linked_map[key] = {
                    (e.get("siem_id"), str(e.get("space") or "default"))
                    for e in entries if not e.get("missing")
                }
        except Exception:
            logger.warning("Rule links unavailable while scoring coverage; using anchors only", exc_info=True)

    def counts(d) -> bool:
        source = (getattr(d, "source", None) or "manual")
        if source == "manual":
            return True   # a human assertion of coverage, not a SIEM rule -- no destination to check
        anchor_siem = getattr(d, "siem_id", None)
        if not anchor_siem:
            return True   # unresolved mapping: flagged for relinking, not silently failed
        anchor_space = d.space or "default"
        scopes = {(anchor_siem, anchor_space)}
        scopes |= linked_map.get((d.rule_ref, anchor_siem, anchor_space), set())
        return bool(scopes & counted)

    return counts, counted, False


def _applied_detection_ids(system_id: str, client_id: str = None) -> set:
    """Detection ids applied to this system, whether pinned to its hosts or to the system."""
    host_ids = [h.id for h in list_hosts(system_id, client_id=client_id)]
    applied = set()
    with _get_conn() as conn:
        if host_ids:
            hp = ",".join("?" for _ in host_ids)
            applied |= {
                r[0] for r in conn.execute(
                    f"SELECT DISTINCT detection_id FROM applied_detections WHERE host_id IN ({hp})",
                    host_ids,
                ).fetchall()
            }
        applied |= {
            r[0] for r in conn.execute(
                "SELECT DISTINCT detection_id FROM applied_detections "
                "WHERE system_id = ? AND host_id IS NULL",
                [system_id],
            ).fetchall()
        }
    return applied


def get_step_detail_for_system(step_id: str, system_id: str, client_id: str = None) -> Optional[Dict]:
    """Everything the step window needs, for ONE step on ONE system.

    Every step belongs to one system's own baseline; a step of another system (or of a template)
    is not found here, so no system's window can ever show another's techniques.
    """
    with _get_conn() as conn:
        if _step_system_id(conn, step_id) != system_id:
            return None
    step = get_playbook_step(step_id, client_id=client_id)
    if not step:
        return None

    counts_toward_coverage, counted_scopes, coverage_undefined = _counted_scope_resolver(
        system_id, step.detections, client_id=client_id,
    )
    applied_ids = _applied_detection_ids(system_id, client_id=client_id)

    bs = [b for b in get_blind_spots("tactic", step_id, client_id=client_id) if b.system_id == system_id]
    has_na = any(b.override_type == "na" for b in bs)
    has_gap = any(b.override_type == "gap" for b in bs)

    # What a rule looks like right now, per destination -- the mapping names one, so look it up
    # by (rule_id, siem_id, space) and never by rule_id alone.
    rules_now: Dict[Tuple[str, str, str], object] = {}
    dest_names: Dict[Tuple[str, str], Dict] = {}
    try:
        from app.services.database import get_database_service
        _db = get_database_service()
        for d in step.detections:
            if d.siem_id and d.rule_ref and (d.source or "manual") != "sigma":
                key = (d.rule_ref, d.siem_id, d.space or "default")
                if key not in rules_now:
                    rules_now[key] = _db.get_rule_by_id(d.rule_ref, key[2], siem_id=d.siem_id, client_id=client_id)
        for d in (_db.get_client_siems(client_id) or [] if client_id else []):
            dest_names[(d.get("id"), d.get("space") or "default")] = {
                "name": d.get("name") or d.get("label") or d.get("space"), "color": d.get("color"),
            }
    except Exception:
        logger.warning("Rule/destination lookup failed for the step window", exc_info=True)

    detections = []
    for d in step.detections:
        source = d.source or "manual"
        rule = rules_now.get((d.rule_ref, d.siem_id, d.space or "default")) if d.siem_id else None
        dest = dest_names.get((d.siem_id, d.space or "default")) if d.siem_id else None
        detections.append({
            "id": d.id,
            "source": source,
            "rule_ref": d.rule_ref,
            "note": d.note,
            "rule_id": d.rule_ref if rule else None,
            "name": (rule.name if rule else None) or d.note or d.rule_ref,
            "enabled": rule.enabled if rule else None,
            "score": rule.score if rule else None,
            "deprecated": bool(rule and rule.deprecated),
            "validation_status": rule.validation_status if rule else None,
            "validation_date": rule.validation_date if rule else None,
            "validated_by": rule.validated_by if rule else None,
            "telemetry": _rule_telemetry(rule) if rule else None,
            "siem_id": d.siem_id,
            "space": d.space,
            "destination": (dest or {}).get("name"),
            "destination_color": (dest or {}).get("color"),
            # Mapped but pointing at a rule TIDE can't find, or at a destination this system
            # isn't measured on: both are worth saying out loud rather than hiding.
            "unresolved": source == "siem" and not rule,
            "unresolved_reason": (
                "" if source != "siem" or rule else
                "This mapping predates destination tracking, so it does not say which SIEM its rule is in."
                if not d.siem_id else
                f"The rule is no longer at {(dest or {}).get('name') or d.space or 'its destination'}: "
                "it was moved, renamed in the SIEM or deleted."
            ),
            # What Relink searches for: the rule's name (older mappings stored it as the rule id).
            "relink_query": d.note or ("" if _UUID_RE.match(d.rule_ref or "") else d.rule_ref),
            "counts": counts_toward_coverage(d),
            "applied": d.id in applied_ids,
            "created_at": d.created_at,
            "created_by": d.created_by,
        })

    # Sigma entries are suggestions carried over from the template, not detection: they are listed
    # apart and never count.
    live = [x for x in detections if x["source"] != "sigma"]
    for x in live:
        x["evidence"] = _evidence(x)
    sigma_refs = [x for x in detections if x["source"] == "sigma"]
    is_applied = any(x["applied"] and x["counts"] for x in live)
    watched = get_step_coverage([step_id]).get(step_id, [])
    status = _technique_status(is_applied, has_gap, has_na, bool(watched))

    technique_ids = []
    for t in step.techniques:
        tid = normalize_technique_id(t.technique_id)
        if tid and tid not in technique_ids:
            technique_ids.append(tid)
    primary = normalize_technique_id(step.technique_id)
    if primary and primary not in technique_ids:
        technique_ids.append(primary)

    history = get_technique_history(step_id, system_id, client_id=client_id)

    # The header ring: the strongest rule actually protecting this system, from the scores
    # app/scoring.py already gave each rule. Only a covered technique has one -- a known gap or
    # N/A is decided by the mark, so a rule score there would contradict the status.
    protecting = [x for x in live if x["counts"] and x["applied"] and x["score"] is not None]
    best = max(protecting, key=lambda x: x["score"]) if status == "green" and protecting else None

    mark = bs[0] if bs else None
    system = get_system(system_id, client_id=client_id)
    return {
        "step": step,
        "system_id": system_id,
        "system_name": system.name if system else "",
        "as_of": datetime.now(),
        "status": status,
        "blind_spot_reason": next((b.reason for b in bs), ""),
        "override_type": "na" if has_na else ("gap" if has_gap else ""),
        "technique_ids": technique_ids,
        "techniques": _technique_names(technique_ids, canonical_tactic(step.tactic) if step.tactic else ""),
        # Covered only by a dashboard, report or log: watched, but nothing alerts.
        "non_alerting": status == "green" and not is_applied,
        # Dashboards, reports and logs watching it (non-alerting coverage).
        "watched": watched,
        "risk_labels": {"priority": dict(STEP_PRIORITIES), "category": dict(STEP_CATEGORIES),
                        "coverage_kind": dict(COVERAGE_KINDS)},
        "detections": live,
        "sigma_refs": sigma_refs,
        "mapped_count": len(live),
        "uncounted_count": sum(1 for x in live if not x["counts"]),
        "coverage_undefined": coverage_undefined,
        "counted_destinations": sorted(counted_scopes),
        "tactic": canonical_tactic(step.tactic),
        "baseline_name": _playbook_name(step.playbook_id),
        # This system's known gap / N/A, with what is needed to remove it.
        "blind_spots": [
            {"id": b.id, "reason": b.reason, "override_type": b.override_type or "gap",
             "created_by": b.created_by, "created_at": b.created_at,
             "review_by": b.review_by, "review_due": b.review_due,
             "updated_by": b.updated_by, "updated_at": b.updated_at}
            for b in bs
        ],
        "review_due": bool(mark and mark.review_due),
        "evidence_score": best["score"] if best else None,
        "evidence_rule": best["name"] if best else "",
        # Newest first, as Recent activity is in the rule window.
        "history": history,
        "history_users": sorted({h["actor"] for h in history if h["actor"]}),
    }


def _rule_telemetry(rule) -> Dict:
    """Where a rule reads from and whether its fields exist there (the rule's own index patterns
    and the field-mapping check sync stored with it). A '?' is unknown, never missing (§9)."""
    raw = rule.raw_data if isinstance(rule.raw_data, dict) else {}
    index = raw.get("index") or []
    indexes = [str(i) for i in (index if isinstance(index, list) else [index]) if i]
    ok = missing = unknown = 0
    missing_fields = []
    for row in rule.field_mappings or []:
        if not isinstance(row, (list, tuple)) or len(row) < 3:
            continue
        if row[2] in ("Yes", True):
            ok += 1
        elif row[2] == "?":
            unknown += 1
        else:
            missing += 1
            missing_fields.append(f"{row[1]} ({row[0]})")
    return {"indexes": indexes, "ok": ok, "missing": missing, "unknown": unknown,
            "missing_fields": missing_fields}


def _evidence(x: Dict) -> Dict:
    """How far one mapped rule is evidence for this technique on this system, for the score ring
    on its card: the rule's own score (app/scoring.py) when it counts and is applied here, else
    n/a with the reason -- never a zero that reads as a bad rule."""
    where = f" at {x['destination']}" if x["destination"] else ""
    if x["unresolved"]:
        why = f"Needs relinking. {x['unresolved_reason']}"
    elif x["source"] == "manual":
        why = "Recorded by hand, not a SIEM rule, so it has no score."
    elif not x["rule_id"]:
        why = "This rule is no longer in TIDE."
    elif not x["counts"]:
        why = f"Mapped{where}, which this system is not measured on."
    elif not x["applied"]:
        why = "Mapped, but not applied to this system."
    else:
        why = f"Applied to this system{where}. Its rule score is {x['score']}%."
    scored = x["score"] is not None and x["counts"] and x["applied"] and not x["unresolved"]
    pct = max(0, min(100, int(x["score"] or 0))) if scored else 0
    tone = "muted" if not scored else "success" if pct >= 80 else "warning" if pct >= 50 else "danger"
    if x["validation_status"] == "expired":
        why += " Its validation has expired."
    elif x["validation_status"] == "never":
        why += " It has never been validated."
    return {"pct": pct, "tone": tone, "applicable": scored, "how": why}


STEP_PRIORITIES = [("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low")]
STEP_CATEGORIES = [
    ("identity", "Identity"), ("endpoint", "Endpoint"), ("network", "Network"),
    ("cloud_saas", "Cloud & SaaS"), ("container", "Container"), ("impex", "IMPEX (Import/Export)"),
    ("email", "Email"), ("secops", "SecOps"), ("ot_ics", "OT/ICS"),
]
# Non-alerting coverage a technique can have on a system, besides mapped rules: each is watched,
# but nothing alerts -- a person has to look. Any one of them makes the technique covered.
COVERAGE_KINDS = [("dashboard", "Dashboard"), ("report", "Report"), ("log", "Log")]


def _risk_fields(values) -> Dict[str, str]:
    return {k: (v or "") for k, v in zip(("priority", "category"), values)}


def _technique_status(covered: bool, has_gap: bool, has_na: bool, non_alerting: bool = False) -> str:
    """A technique shows its lowest setting. Not applicable wins -- a rule there doesn't apply,
    but the mark says the risk was considered, and it is left out of the score. A known gap
    wins over a mapped rule: the rule is on record, but the gap is what is true. Then covered
    -- by a counted rule, or by a dashboard, report or log (non-alerting) -- then nothing."""
    if has_na:
        return "grey"
    if has_gap:
        return "amber"
    return "green" if covered or non_alerting else "red"


def update_step_risks(step_id: str, system_id: str, *, priority: str, category: str,
                      actor: str = None, client_id: str = None) -> None:
    """Save a system technique's priority and category, recorded in its history."""
    priority = priority if priority in dict(STEP_PRIORITIES) else ""
    category = category if category in dict(STEP_CATEGORIES) else ""
    before = get_playbook_step(step_id)
    if not before:
        raise ValueError("Technique not found")
    labels = {**dict(STEP_PRIORITIES), **dict(STEP_CATEGORIES), "": "not set"}
    changed = [f"{name} {labels.get(old, old)} → {labels.get(new, new)}" for name, old, new in (
        ("priority", before.priority, priority), ("category", before.category, category),
    ) if old != new]
    with _get_conn() as conn:
        conn.execute("UPDATE playbook_steps SET priority = ?, category = ? WHERE id = ?", [priority, category, step_id])
        if changed:
            _record_technique_event(conn, "risks_edited", step_id=step_id, system_id=system_id,
                                    detail="Changed " + "; ".join(changed), actor=actor, client_id=client_id)


def get_step_coverage(step_ids: List[str]) -> Dict[str, List[Dict]]:
    """``step_id`` -> its dashboards, reports and logs, oldest first. Empty for a tenant DB that
    has not got the table yet."""
    if not step_ids:
        return {}
    ph = ",".join("?" for _ in step_ids)
    out: Dict[str, List[Dict]] = {}
    with _get_conn() as conn:
        try:
            rows = conn.execute(
                f"SELECT id, step_id, kind, title, url, rationale, created_by, created_at FROM step_coverage "
                f"WHERE step_id IN ({ph}) ORDER BY created_at, title", list(step_ids),
            ).fetchall()
        except Exception:
            return {}
    labels = dict(COVERAGE_KINDS)
    for cid, sid, kind, title, url, why, by, at in rows:
        out.setdefault(sid, []).append({"id": cid, "kind": kind, "kind_label": labels.get(kind, kind), "title": title,
                                        "url": url or "", "rationale": why or "", "created_by": by, "created_at": at})
    return out


def _coverage_fields(kind: str, title: str, url: str, rationale: str) -> Tuple[str, str, str]:
    """A dashboard, report or log's title, link and rationale, cleaned. It needs a title; the
    link is optional and must be a web address."""
    title, url, rationale = (title or "").strip(), (url or "").strip(), (rationale or "").strip()
    if kind not in dict(COVERAGE_KINDS):
        raise ValueError("Choose a dashboard, report or log.")
    if not title:
        raise ValueError("Give it a title, so it can be told apart from the others.")
    if url and not re.match(r"^https?://", url, re.I):
        raise ValueError("The link must be a web address starting http:// or https://.")
    return title, url, rationale


def add_step_coverage(step_id: str, system_id: str, *, kind: str, title: str, url: str = "", rationale: str = "",
                      actor: str = None, client_id: str = None) -> None:
    """Record a dashboard, report or log watching this technique on this system."""
    title, url, rationale = _coverage_fields(kind, title, url, rationale)
    from app.services.database import DatabaseService
    with _get_conn() as conn:
        conn.execute(DatabaseService.STEP_COVERAGE_DDL)
        conn.execute(
            "INSERT INTO step_coverage (step_id, system_id, kind, title, url, rationale, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [step_id, system_id, kind, title, url, rationale, actor],
        )
        _record_technique_event(conn, "coverage_added", step_id=step_id, system_id=system_id,
                                detail=f"{dict(COVERAGE_KINDS)[kind]}: {title}", reason=rationale or None,
                                actor=actor, client_id=client_id)


def update_step_coverage(coverage_id: str, step_id: str, system_id: str, *, kind: str, title: str, url: str = "",
                         rationale: str = "", actor: str = None, client_id: str = None) -> bool:
    """Change one dashboard, report or log on this technique on this system, recording what
    changed. False if it is not on this technique."""
    title, url, rationale = _coverage_fields(kind, title, url, rationale)
    labels = dict(COVERAGE_KINDS)
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT kind, title, url, rationale FROM step_coverage WHERE id = ? AND step_id = ? AND system_id = ?",
            [coverage_id, step_id, system_id],
        ).fetchone()
        if not row:
            return False
        changed = [name for name, old, new in (
            ("type", row[0], kind), ("title", row[1], title), ("link", row[2] or "", url), ("rationale", row[3] or "", rationale),
        ) if old != new]
        if not changed:
            return True
        conn.execute("UPDATE step_coverage SET kind = ?, title = ?, url = ?, rationale = ? WHERE id = ?",
                     [kind, title, url, rationale, coverage_id])
        _record_technique_event(conn, "coverage_edited", step_id=step_id, system_id=system_id,
                                detail=f"{labels[kind]}: {title} (changed {', '.join(changed)})",
                                reason=rationale or None, actor=actor, client_id=client_id)
    return True


def remove_step_coverage(coverage_id: str, step_id: str, system_id: str, actor: str = None,
                         client_id: str = None) -> bool:
    """Remove one dashboard, report or log from this technique on this system."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT kind, title FROM step_coverage WHERE id = ? AND step_id = ? AND system_id = ?",
            [coverage_id, step_id, system_id],
        ).fetchone()
        if not row:
            return False
        conn.execute("DELETE FROM step_coverage WHERE id = ?", [coverage_id])
        _record_technique_event(conn, "coverage_removed", step_id=step_id, system_id=system_id,
                                detail=f"{dict(COVERAGE_KINDS).get(row[0], row[0])}: {row[1]}",
                                actor=actor, client_id=client_id)
    return True


def _technique_names(technique_ids: List[str], prefer_tactic: str = "") -> List[Dict]:
    """``[{id, name, tactic}]`` for ATT&CK ids, in the order given, for pills with names. A
    technique under several tactics shows ``prefer_tactic`` (the one it was picked under) when
    that is one of them, else its first."""
    if not technique_ids:
        return []
    found: Dict[str, Tuple[str, str]] = {}
    tactics: Dict[str, set] = {}
    try:
        ph = ",".join("?" for _ in technique_ids)
        with _get_conn() as conn:
            for tid, name, tactic in conn.execute(
                f"SELECT id, name, tactic FROM mitre_techniques WHERE id IN ({ph})", technique_ids,
            ).fetchall():
                found[str(tid).upper()] = (name or "", canonical_tactic(tactic) if tactic else "")
            if prefer_tactic:
                for tid, short in conn.execute(
                    "SELECT mt.id, t.shortname FROM mitre_techniques mt "
                    "JOIN mitre_technique_tactics mtt ON mtt.technique_stix_id = mt.stix_id AND LOWER(mtt.domain) = LOWER(mt.domain) "
                    "JOIN mitre_tactics t ON t.stix_id = mtt.tactic_stix_id AND LOWER(t.domain) = LOWER(mtt.domain) "
                    f"WHERE mt.id IN ({ph})", technique_ids,
                ).fetchall():
                    tactics.setdefault(str(tid).upper(), set()).add(canonical_tactic(short))
    except Exception:
        logger.warning("ATT&CK names unavailable for %s", technique_ids, exc_info=True)

    def tactic_of(t: str) -> str:
        return prefer_tactic if prefer_tactic in tactics.get(t, ()) else found.get(t, ("", ""))[1]
    return [{"id": t, "name": found.get(t, ("", ""))[0], "tactic": tactic_of(t)} for t in technique_ids]


def _playbook_name(playbook_id: Optional[str]) -> str:
    if not playbook_id:
        return ""
    with _get_conn() as conn:
        row = conn.execute("SELECT name FROM playbooks WHERE id = ?", [playbook_id]).fetchone()
    return row[0] if row else ""


def get_rule_coverage(rule_id: str, siem_id: str, space: str, linked: List[Dict] = None,
                      client_id: str = None) -> List[Dict]:
    """The baseline techniques this rule covers, grouped by baseline, for the rule window.

    A mapping names the destination that was picked; a rule copied onward by Move still covers
    it (coverage follows ``rule_links``), so mappings made to a linked copy are included and
    marked with the destination they were made at. A mapping recorded before destinations were
    tracked, against this rule id, is included too, flagged as needing relinking.

    ``linked`` is the rule window's own ``get_rule_links_bulk`` entry for this rule.
    """
    anchors = [(rule_id, siem_id, space or "default", None)]
    for l in linked or []:
        if not l.get("missing"):
            anchors.append((l["rule_id"], l["siem_id"], l.get("space") or "default", l.get("destination_name")))
    pred = " OR ".join("(sd.rule_ref = ? AND sd.siem_id = ? AND sd.space = ?)" for _ in anchors)
    params = [v for a in anchors for v in a[:3]]
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT sd.step_id, sd.rule_ref, sd.siem_id, sd.space, ps.title, ps.tactic, ps.step_number, "
            "ps.playbook_id, p.name FROM step_detections sd "
            "JOIN playbook_steps ps ON ps.id = sd.step_id JOIN playbooks p ON p.id = ps.playbook_id "
            f"WHERE {pred} OR (sd.rule_ref = ? AND sd.siem_id IS NULL)",
            params + [rule_id],
        ).fetchall()
        playbook_ids = sorted({r[7] for r in rows})
        systems: Dict[str, List[Dict]] = {}
        if playbook_ids:
            ph = ",".join("?" for _ in playbook_ids)
            for pb_id, sys_id, sys_name in conn.execute(
                "SELECT sb.playbook_id, s.id, s.name FROM system_baselines sb "
                f"JOIN systems s ON s.id = sb.system_id WHERE sb.playbook_id IN ({ph}) ORDER BY s.name",
                playbook_ids,
            ).fetchall():
                systems.setdefault(pb_id, []).append({"id": sys_id, "name": sys_name})

    via = {(a[0], a[1], a[2]): a[3] for a in anchors}
    baselines: Dict[str, Dict] = {}
    for step_id, ref, sid, sp, title, tactic, number, pb_id, pb_name in rows:
        b = baselines.setdefault(pb_id, {"id": pb_id, "name": pb_name, "systems": systems.get(pb_id, []),
                                         "techniques": {}})
        entry = {
            "step_id": step_id, "title": title, "tactic": canonical_tactic(tactic),
            "step_number": number or 0,
            "via": via.get((ref, sid, sp or "default")) if sid else None,
            "needs_relinking": not sid,
        }
        seen = b["techniques"].get(step_id)
        # One row per technique; a direct mapping beats one made through a link or a legacy one.
        if not seen or (seen["via"] or seen["needs_relinking"]) and not (entry["via"] or entry["needs_relinking"]):
            b["techniques"][step_id] = entry
    out = []
    for b in sorted(baselines.values(), key=lambda x: (x["name"] or "").lower()):
        b["techniques"] = sorted(b["techniques"].values(), key=lambda t: (t["step_number"], t["title"] or ""))
        out.append(b)
    return out


def attack_plain_text(text: Optional[str]) -> str:
    """ATT&CK's STIX description as readable prose: markdown links become their text, and the
    "(Citation: ...)" markers -- references into a bibliography TIDE doesn't show -- are dropped."""
    import re
    out = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text or "")
    out = re.sub(r"\(Citation:[^)]*\)", "", out)
    out = re.sub(r"<code>(.*?)</code>", r"\1", out)
    return re.sub(r"[ \t]{2,}", " ", out).replace(" .", ".").strip()


_TACTIC_ALIASES = {
    "resource dev": "Resource Development", "c2": "Command and Control",
    "command & control": "Command and Control", "privesc": "Privilege Escalation",
    "recon": "Reconnaissance", "exfil": "Exfiltration",
}


def canonical_tactic(raw: Optional[str]) -> str:
    """A baseline step's free-text tactic as the ATT&CK tactic it means, or "Other".

    Steps are typed by hand and imported from several places, so the same tactic turns up as
    "Resource Dev", "resource-development" or blank. Grouping and ATT&CK ordering need one name.
    """
    from app.models.inventory import MITRE_TACTICS
    text = " ".join((raw or "").replace("-", " ").replace("_", " ").split()).lower()
    if not text:
        return "Other"
    for t in MITRE_TACTICS:
        if t.lower() == text:
            return t
    raw = raw.strip()
    # An ATT&CK shortname this list doesn't know yet ("stealth", "defense-impairment") reads as
    # a name; anything typed with capitals is kept as typed.
    return _TACTIC_ALIASES.get(text) or (text.title() if raw == raw.lower() else raw)


def tactic_sort_key(tactic: str, mode: str = "attack"):
    """ATT&CK kill-chain order (unknown tactics after the fourteen, A-Z, then Other), or plain A-Z."""
    from app.models.inventory import MITRE_TACTICS
    if mode == "alpha":
        return (0, tactic.lower())
    known = MITRE_TACTICS[:-1]            # "Other" always sorts last
    if tactic in known:
        return (known.index(tactic), "")
    return (len(known) + (1 if tactic == "Other" else 0), tactic.lower())


def group_system_steps(steps: List[Dict], group_by: List[str], tactic_sort: str = "attack") -> List[Dict]:
    """Nest already-sorted steps into collapsible groups: by baseline, by tactic, or tactics
    within each baseline. Each group carries its own covered/scored counts. Step order inside a
    group is preserved, so the chosen sort still applies within it."""
    def counts(rows):
        scored = [r for r in rows if r["status"] != "grey"]
        covered = sum(1 for r in scored if r["status"] == "green")
        return {"total": len(rows), "scored": len(scored), "covered": covered,
                "pct": round(covered / len(scored) * 100) if scored else None}

    def by(rows, field, order_key):
        buckets: Dict[str, List[Dict]] = {}
        labels: Dict[str, str] = {}
        for r in rows:
            k = r[field]
            buckets.setdefault(k, []).append(r)
            labels[k] = r["baseline_name"] if field == "baseline_id" else r["tactic"]
        keys = sorted(buckets, key=lambda k: order_key(labels[k]))
        kind = "baseline" if field == "baseline_id" else "tactic"
        return [{"key": k, "kind": kind, "label": labels[k], "steps": buckets[k], **counts(buckets[k])} for k in keys]

    by_tactic = lambda rows: by(rows, "tactic", lambda t: tactic_sort_key(t, tactic_sort))  # noqa: E731
    if "baseline" in group_by:
        groups = by(steps, "baseline_id", lambda n: (n or "").lower())
        if "tactic" in group_by:
            for g in groups:
                g["groups"] = by_tactic(g["steps"])
        return groups
    if "tactic" in group_by:
        return by_tactic(steps)
    return []


def get_system_steps(system_id: str, client_id: str = None, search: str = "", tactic=None,
                     status: str = "", mapping: str = "", baseline_id: str = "",
                     tactic_sort: str = "attack", sort_name: str = "") -> Dict:
    """Every step across this system's baselines, flattened and filtered, plus its own totals.

    Flat rather than nested baseline > tactic > step: the question a system's owner asks is
    "where are my gaps", which is a property of steps, and three levels of accordion between
    them and the answer is what the old page made them click through.

    ``baseline_id`` is a filter, and leaves the totals whole.
    """
    baselines = get_system_baselines(system_id, client_id=client_id)
    steps, tactics, baseline_names = [], [], []
    for bl in baselines:
        if bl["playbook_name"] not in baseline_names:
            baseline_names.append(bl["playbook_name"])
        for st in bl["tactics"]:
            row = dict(st)
            row["baseline_id"] = bl["playbook_id"]
            row["baseline_name"] = bl["playbook_name"]
            row["coverage_undefined"] = bl.get("coverage_undefined", False)
            row["tactic"] = canonical_tactic(row.get("tactic"))
            steps.append(row)
            if row["tactic"] not in tactics:
                tactics.append(row["tactic"])

    totals = {
        "total": len(steps),
        "covered": sum(1 for s in steps if s["status"] == "green"),
        "gap": sum(1 for s in steps if s["status"] == "amber"),
        "na": sum(1 for s in steps if s["status"] == "grey"),
        "none": sum(1 for s in steps if s["status"] == "red"),
        "unmapped": sum(1 for s in steps if not s.get("mapped_count")),
        "uncounted": sum(1 for s in steps if s.get("uncounted_count")),
    }

    q = (search or "").strip().lower()
    if q:
        steps = [
            s for s in steps
            if q in (s.get("title") or "").lower()
            or q in (s.get("description") or "").lower()
            or any(q in (t or "").lower() for t in (s.get("display_technique_ids") or []))
        ]
    wanted = {tactic} if isinstance(tactic, str) else set(tactic or [])
    wanted.discard("")
    if wanted:
        steps = [s for s in steps if s["tactic"] in wanted]
    if status:
        steps = [s for s in steps if s["status"] == status]
    if baseline_id:
        steps = [s for s in steps if s["baseline_id"] == baseline_id]
    if mapping == "unmapped":
        steps = [s for s in steps if not s.get("mapped_count")]
    elif mapping == "mapped":
        steps = [s for s in steps if s.get("mapped_count")]
    elif mapping == "uncounted":
        steps = [s for s in steps if s.get("uncounted_count")]

    # Tactic first (kill-chain order by default -- an attack tree reads in sequence), then name
    # if asked, else the baseline's own step order. Stable sorts, applied innermost first.
    steps.sort(key=lambda s: ((s.get("baseline_name") or "").lower(), s.get("step_number") or 0))
    if sort_name in ("asc", "desc"):
        steps.sort(key=lambda s: (s.get("title") or "").lower(), reverse=sort_name == "desc")
    if tactic_sort in ("attack", "alpha"):
        steps.sort(key=lambda s: tactic_sort_key(s["tactic"], tactic_sort))
    tactics.sort(key=lambda t: tactic_sort_key(t, "attack"))
    return {
        "steps": steps, "totals": totals, "tactics": tactics,
        "baselines": [{"id": b["playbook_id"], "name": b["playbook_name"]} for b in baselines],
        "coverage_undefined": all(b.get("coverage_undefined") for b in baselines) if baselines else False,
    }


def get_system_baselines(
    system_id: str,
    playbook_ids: Optional[List[str]] = None,
    include_detection_details: bool = True,
    client_id: str = None,
) -> List[Dict]:
    """Return playbooks applied to a system with step-level RAG coverage."""
    query = (
        "SELECT sb.id, sb.playbook_id, sb.applied_at, p.name, p.description "
        "FROM system_baselines sb JOIN playbooks p ON p.id = sb.playbook_id "
        "WHERE sb.system_id = ?"
    )
    params: List[str] = [system_id]
    if client_id:
        query += " AND p.client_id = ?"
        params.append(client_id)
    if playbook_ids:
        placeholders = ",".join("?" for _ in playbook_ids)
        query += f" AND sb.playbook_id IN ({placeholders})"
        params.extend(playbook_ids)
    query += " ORDER BY p.name"

    with _get_conn() as conn:
        rows = conn.execute(query, params).fetchall()

    # Get applied detections for this system's hosts (by step_detection ID)
    hosts = list_hosts(system_id, client_id=client_id)
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

    # Load per-technique coverage data only when rich detection details are requested.
    if include_detection_details:
        try:
            from app.services.database import get_database_service
            _db = get_database_service()
            covered_ttps = _db.get_all_covered_ttps(client_id=client_id)
            ttp_rule_counts = _db.get_ttp_rule_counts(client_id=client_id)
        except Exception:
            covered_ttps = set()
            ttp_rule_counts = {}
    else:
        covered_ttps = set()
        ttp_rule_counts = {}

    # Batch lookup: rule name -> (rule_id, space) for clickable rule badges
    rule_name_lookup: Dict[str, Dict] = {}
    if include_detection_details:
        try:
            with _get_conn() as conn:
                rrows = conn.execute(
                    "SELECT rule_id, name, space, raw_data FROM detection_rules ORDER BY name"
                ).fetchall()
            for rid, rname, rspace, raw_data in rrows:
                info = {"rule_id": rid, "name": rname or rid, "space": rspace or "default"}
                if rname:
                    rule_name_lookup[rname] = info
                if rid:
                    rule_name_lookup[rid] = info
                try:
                    raw = json.loads(raw_data) if isinstance(raw_data, str) and raw_data.strip() else (raw_data or {})
                    raw_id = str(raw.get("id") or "").strip() if isinstance(raw, dict) else ""
                    if raw_id:
                        rule_name_lookup[raw_id] = info
                except Exception:
                    pass
        except Exception:
            pass

    # Which destinations count toward THIS system, resolved once for every step below.
    _all_steps_by_pb = {row[1]: _get_playbook_steps(row[1]) for row in rows}
    _all_dets = [d for sts in _all_steps_by_pb.values() for st in sts for d in st.detections]
    # Dashboards, reports and logs watching each step (non-alerting coverage), in one query.
    _watched = get_step_coverage([st.id for sts in _all_steps_by_pb.values() for st in sts])
    counts_toward_coverage, counted_scopes, coverage_undefined = _counted_scope_resolver(
        system_id, _all_dets, client_id=client_id,
    )

    result = []
    for sb_id, pb_id, applied_at, pb_name, pb_desc in rows:
        steps = _all_steps_by_pb[pb_id]
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
            review_by = min((bs.review_by for bs in sys_blind_spots if bs.review_by), default=None)

            # A detection counts for this step only if it is applied to a host on this system AND
            # its rule lives somewhere this system is actually graded on (§4.3). A rule sitting
            # only in staging protects nothing, so it must not read as covered here.
            step_det_ids = {
                d.id for d in step.detections
                if (d.source or 'manual') != 'sigma' and counts_toward_coverage(d)
            }
            is_applied = bool(step_det_ids & applied_step_det_ids) if step_det_ids else False
            # Mapped but not counted: there IS a rule for this step, it just isn't anywhere this
            # system is graded on. Shown distinctly rather than as "nothing here".
            uncounted_count = sum(
                1 for d in step.detections
                if (d.source or 'manual') != 'sigma' and not counts_toward_coverage(d)
            )
            # How many rules are mapped to *this step* -- every one of them, counted or not, so
            # the card can say "2 rules, 1 not counted" rather than quietly showing 1. Deliberately
            # separate from the per-technique rule counts below, which are tenant-wide ("some rule
            # somewhere carries this tag") and were being rendered on step cards as if they meant
            # the same thing.
            mapped_count = len(step_det_ids) + uncounted_count

            status = _technique_status(is_applied, has_gap, has_na, bool(_watched.get(step.id)))
            if status == "green":
                covered += 1
            elif status == "grey":
                na_count += 1
            elif status == "amber":
                gap_count += 1

            # Build normalized tagged techniques for display/heatmap consumers.
            normalized_tagged = []
            for t in step.techniques:
                tid = normalize_technique_id(t.technique_id)
                if tid and tid not in normalized_tagged:
                    normalized_tagged.append(tid)
            primary_tid = normalize_technique_id(step.technique_id)
            if primary_tid and primary_tid not in normalized_tagged:
                normalized_tagged.append(primary_tid)

            # Split detections into applied/unapplied for this system
            step_applied = []
            step_unapplied = []
            if include_detection_details:
                for d in step.detections:
                    if (d.source or "manual") == "sigma":
                        continue  # sigma rules are not appliable
                    label = d.rule_ref or d.note or "Rule"
                    rule_info = rule_name_lookup.get(label) or rule_name_lookup.get(d.rule_ref or "")
                    display_label = rule_info.get("name") if rule_info else label
                    entry = {"id": d.id, "rule_ref": d.rule_ref, "note": d.note, "label": label,
                             "display_label": display_label,
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
                "tactic": (step.tactic or "Other"),
                "technique_id": normalize_technique_id(step.technique_id),
                "display_technique_ids": normalized_tagged,
                "display_technique": normalized_tagged[0] if normalized_tagged else "",
                "description": step.description,
                "status": status,
                # Covered only by a dashboard, report or log: watched, but nothing alerts.
                "non_alerting": status == "green" and not is_applied,
                "priority": step.priority,
                "category": step.category,
                "blind_spot_reason": bs_reason,
                "override_type": "na" if has_na else ("gap" if has_gap else ""),
                "review_by": review_by,
                "review_due": bool(review_by and review_by <= date.today()),
                "mapped_count": mapped_count,
                "uncounted_count": uncounted_count,
                # Tenant-wide: how many rules anywhere carry this step's techniques. A prompt to go
                # looking, never a statement about this step. `rule_count`/`has_detection` below are
                # the same number per technique and are named for the technique, not the step.
                "suggestion_count": max(
                    [ttp_rule_counts.get(tid.upper(), 0) for tid in normalized_tagged] or [0]
                ),
                "techniques": [
                    {
                        "technique_id": normalize_technique_id(t.technique_id),
                        "has_detection": normalize_technique_id(t.technique_id).upper() in covered_ttps,
                        "rule_count": ttp_rule_counts.get(normalize_technique_id(t.technique_id).upper(), 0),
                    }
                    for t in step.techniques
                    if normalize_technique_id(t.technique_id)
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
            # True when nobody has said which destinations count for this system. The percentage
            # is still computed, but callers must present it as unanswered rather than as a score:
            # an unanswered question is not a gap.
            "coverage_undefined": coverage_undefined,
            "counted_destinations": sorted(counted_scopes),
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

def add_step_technique(step_id: str, technique_id: str, client_id: str = None) -> StepTechnique:
    normalized_technique_id = normalize_technique_id(technique_id)
    if not normalized_technique_id:
        raise ValueError("technique_id is required")

    with _get_conn() as conn:
        dup = conn.execute(
            "SELECT id FROM step_techniques WHERE step_id = ? AND technique_id = ?",
            [step_id, normalized_technique_id],
        ).fetchone()
        if dup:
            return StepTechnique(id=dup[0], step_id=step_id, technique_id=normalized_technique_id)
        r = conn.execute(
            "INSERT INTO step_techniques (step_id, technique_id) VALUES (?, ?) RETURNING id",
            [step_id, normalized_technique_id],
        ).fetchone()
    return StepTechnique(id=r[0], step_id=step_id, technique_id=normalized_technique_id)


def _destination_name(siem_id: Optional[str], space: Optional[str], client_id: Optional[str]) -> Optional[str]:
    if not siem_id:
        return None
    try:
        from app.services.database import get_database_service
        for d in get_database_service().get_client_siems(client_id) or [] if client_id else []:
            if d.get("id") == siem_id and (d.get("space") or "default") == (space or "default"):
                return d.get("name") or d.get("label") or space
    except Exception:
        logger.warning("Destination name unavailable for %s/%s", siem_id, space, exc_info=True)
    return space


def _record_technique_event(conn, event: str, *, step_id: str = None, system_id: str = None,
                            detection_id: str = None, rule_id: str = None, siem_id: str = None,
                            space: str = None, source: str = None, reason: str = None,
                            detail: str = None, actor: str = None, client_id: str = None) -> None:
    """Append one row to the technique history. Rule name, destination and score are captured
    as they are now, so the history still reads correctly after a rename, move or rescore. A
    step's event is filed under the system that owns the step; a template's steps have no history.

    Never raises: history is a record of the change, not a condition of it.
    """
    try:
        if step_id and not system_id:
            system_id = _step_system_id(conn, step_id)
            if not system_id:
                return
        rule_name, score = None, None
        if rule_id:
            if siem_id:
                row = conn.execute(
                    "SELECT name, score FROM detection_rules WHERE rule_id = ? AND siem_id = ? AND space = ?",
                    [rule_id, siem_id, space or "default"],
                ).fetchone()
            else:
                row = None
            rule_name, score = (row[0], row[1]) if row else (None, None)
        conn.execute(
            "INSERT INTO technique_events (event, step_id, system_id, detection_id, rule_id, siem_id, "
            "space, rule_name, destination, score, source, reason, detail, actor, client_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [event, step_id, system_id, detection_id, rule_id, siem_id, space,
             rule_name or detail if event in ("rule_mapped", "rule_unmapped") else rule_name,
             _destination_name(siem_id, space, client_id), score, source, reason,
             None if event in ("rule_mapped", "rule_unmapped") else detail, actor, client_id],
        )
    except Exception:
        logger.warning("Could not record technique event %s for step %s", event, step_id, exc_info=True)


_EVENT_KIND = {
    "rule_mapped": "rules", "rule_unmapped": "rules", "rule_relinked": "rules", "coverage_added": "rules", "coverage_edited": "rules", "coverage_removed": "rules",
    "gap_added": "gaps", "gap_removed": "gaps", "na_added": "gaps", "na_removed": "gaps",
    "gap_edited": "gaps", "na_edited": "gaps",
    "sigma_dismissed": "technique", "sigma_restored": "technique",
    "technique_added": "technique", "technique_edited": "technique", "risks_edited": "technique",
    "siem_coverage": "coverage",
}


def get_technique_history(step_id: str, system_id: str, client_id: str = None) -> List[Dict]:
    """Everything that changed this technique on this system, newest first: rules mapped and
    removed, known gaps and N/A, edits to the technique itself, and the system's SIEM coverage
    changes (which can move every technique)."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, event, step_id, system_id, rule_id, siem_id, space, rule_name, destination, "
            "score, source, reason, detail, actor, source_ref, created_at FROM technique_events "
            "WHERE system_id = ? AND (step_id = ? OR (step_id IS NULL AND event = 'siem_coverage')) "
            "ORDER BY created_at DESC",
            [system_id, step_id],
        ).fetchall()
    cols = ["id", "event", "step_id", "system_id", "rule_id", "siem_id", "space", "rule_name",
            "destination", "score", "source", "reason", "detail", "actor", "source_ref", "created_at"]
    out = []
    for r in rows:
        e = dict(zip(cols, r))
        e["kind"] = _EVENT_KIND.get(e["event"], "other")
        e["system_scoped"] = e["system_id"] is not None
        e["reconstructed"] = e["source_ref"] is not None
        out.append(e)
    return out


def add_step_detection(step_id: str, rule_ref: str, note: str = "", source: str = "manual",
                       client_id: str = None, siem_id: str = None, space: str = None,
                       created_by: str = None) -> StepDetection:
    """Map a rule to a step.

    ``siem_id``/``space`` record which destination's copy was picked. They are the caller's to
    supply and are stored exactly as given -- resolving the mapping onward to the rule's other
    destinations is a read-time concern (``rule_links``), deliberately not baked in here, so the
    stored row always says what the person actually chose.
    """
    with _get_conn() as conn:
        logical_row = conn.execute(
            "SELECT id FROM logical_rule_identities WHERE canonical_rule_id = ? "
            "ORDER BY created_at LIMIT 1",
            [rule_ref],
        ).fetchone()
        logical_rule_id = logical_row[0] if logical_row else None
        r = conn.execute(
            "INSERT INTO step_detections (step_id, rule_ref, logical_rule_id, note, source, "
            "siem_id, space, created_at, created_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?) "
            "RETURNING id, step_id, rule_ref, note, source, siem_id, space, created_at, created_by",
            [step_id, rule_ref, logical_rule_id, note, source, siem_id, space, created_by],
        ).fetchone()
        _record_technique_event(
            conn, "rule_mapped", step_id=step_id, detection_id=r[0], rule_id=rule_ref,
            siem_id=siem_id, space=space, source=source, detail=note or rule_ref,
            actor=created_by, client_id=client_id,
        )
    return StepDetection(id=r[0], step_id=r[1], rule_ref=r[2] or "", note=r[3] or "",
                         source=r[4] or "manual", siem_id=r[5], space=r[6],
                         created_at=r[7], created_by=r[8])


def relink_step_detection(detection_row_id: str, *, rule_ref: str, siem_id: str, space: str, note: str = "",
                          actor: str = None, client_id: str = None, conn=None) -> bool:
    """Point an existing rule mapping at a rule copy that exists, keeping the mapping itself (its
    id, so where it is applied, and its history). For a mapping whose rule TIDE can no longer find
    at the destination it names -- one made before destinations were recorded, one that stored
    the rule's name, or one whose rule has moved. ``conn`` lets a repair script pass its own
    connection to a tenant DB. False if the mapping does not exist."""
    def _relink(c) -> bool:
        old = c.execute("SELECT step_id, rule_ref, siem_id, space, note FROM step_detections WHERE id = ?",
                        [detection_row_id]).fetchone()
        if not old:
            return False
        logical = c.execute("SELECT id FROM logical_rule_identities WHERE canonical_rule_id = ? ORDER BY created_at LIMIT 1",
                            [rule_ref]).fetchone()
        c.execute("UPDATE step_detections SET rule_ref = ?, siem_id = ?, space = ?, note = ?, logical_rule_id = ? WHERE id = ?",
                  [rule_ref, siem_id, space, note or old[4], logical[0] if logical else None, detection_row_id])
        was = old[4] or old[1]
        was_at = _destination_name(old[2], old[3], client_id) if old[2] else "no destination recorded"
        _record_technique_event(c, "rule_relinked", step_id=old[0], detection_id=detection_row_id, rule_id=rule_ref,
                                siem_id=siem_id, space=space, source="siem", detail=f"was {was} ({was_at})",
                                actor=actor, client_id=client_id)
        return True
    if conn is not None:
        return _relink(conn)
    with _get_conn() as c:
        return _relink(c)


def remove_step_detection(detection_row_id: str, client_id: str = None, actor: str = None) -> bool:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT step_id, rule_ref, siem_id, space, source, note FROM step_detections WHERE id = ?",
            [detection_row_id],
        ).fetchone()
        cnt = conn.execute("DELETE FROM step_detections WHERE id = ?", [detection_row_id]).rowcount
        conn.execute("DELETE FROM applied_detections WHERE detection_id = ?", [detection_row_id])
        if row and cnt:
            _record_technique_event(
                conn, "rule_unmapped", step_id=row[0], detection_id=detection_row_id, rule_id=row[1],
                siem_id=row[2], space=row[3], source=row[4], detail=row[5] or row[1],
                actor=actor, client_id=client_id,
            )
    return cnt > 0


def parse_technique_ids(raw: str) -> List[str]:
    """ATT&CK ids typed as free text ("T1003, t1059.001 T1078"): normalised, de-duplicated and
    kept in the order given. Anything that is not a technique id is ignored."""
    out: List[str] = []
    for part in re.split(r"[\s,;]+", raw or ""):
        tid = normalize_technique_id(part)
        if tid and tid not in out:
            out.append(tid)
    return out


def get_step_owner(step_id: str) -> Optional[Dict]:
    """Which baseline a step is in: ``{playbook_id, system_id, client_id}``, where system_id is
    None for a template's step. None if there is no such step."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT p.id, p.system_id, p.client_id FROM playbook_steps s "
            "JOIN playbooks p ON p.id = s.playbook_id WHERE s.id = ?",
            [step_id],
        ).fetchone()
    return {"playbook_id": row[0], "system_id": row[1], "client_id": row[2]} if row else None


def _set_step_techniques(conn, step_id: str, technique_ids: List[str]) -> None:
    conn.execute("DELETE FROM step_techniques WHERE step_id = ?", [step_id])
    for tid in technique_ids:
        conn.execute("INSERT INTO step_techniques (step_id, technique_id) VALUES (?, ?)", [step_id, tid])
    conn.execute("UPDATE playbook_steps SET technique_id = ? WHERE id = ?",
                 [technique_ids[0] if technique_ids else "", step_id])


def add_technique(playbook_id: str, *, title: str, tactic: str = "", description: str = "",
                  technique_ids: List[str] = (), actor: str = None, client_id: str = None) -> PlaybookStep:
    """Add a technique at the end of a template, or of a system's own baseline (where it is
    recorded in the technique's history)."""
    with _get_conn() as conn:
        number = conn.execute(
            "SELECT COALESCE(MAX(step_number), 0) + 1 FROM playbook_steps WHERE playbook_id = ?", [playbook_id],
        ).fetchone()[0]
        step_id = conn.execute(
            "INSERT INTO playbook_steps (playbook_id, step_number, title, technique_id, required_rule, description, tactic) "
            "VALUES (?, ?, ?, '', '', ?, ?) RETURNING id",
            [playbook_id, number, title, description, tactic],
        ).fetchone()[0]
        _set_step_techniques(conn, step_id, list(technique_ids))
        _record_technique_event(conn, "technique_added", step_id=step_id, detail=title,
                                actor=actor, client_id=client_id)
    return get_playbook_step(step_id)


def update_technique(step_id: str, *, title: str, tactic: str, description: str,
                     technique_ids: List[str], actor: str = None, client_id: str = None) -> Optional[PlaybookStep]:
    """Edit a technique's title, tactic, description and ATT&CK ids. On a system's own baseline
    the edit is recorded in the technique's history, naming what changed."""
    before = get_playbook_step(step_id)
    if not before:
        return None
    old_ids = [t.technique_id for t in before.techniques] or ([before.technique_id] if before.technique_id else [])
    changed = [label for label, old, new in (
        ("title", before.title, title),
        # "execution" from a Sigma rule and "Execution" from the form are the same tactic
        ("tactic", canonical_tactic(before.tactic) if before.tactic else "", canonical_tactic(tactic) if tactic else ""),
        ("description", before.description, description), ("ATT&CK", old_ids, list(technique_ids)),
    ) if old != new]
    with _get_conn() as conn:
        conn.execute("UPDATE playbook_steps SET title = ?, tactic = ?, description = ? WHERE id = ?",
                     [title, tactic, description, step_id])
        _set_step_techniques(conn, step_id, list(technique_ids))
        if changed:
            _record_technique_event(conn, "technique_edited", step_id=step_id,
                                    detail="Changed " + ", ".join(changed), actor=actor, client_id=client_id)
    return get_playbook_step(step_id)


def get_playbook_step(step_id: str, client_id: str = None) -> Optional[PlaybookStep]:
    """Get a single step with its techniques and detections.
    client_id accepted for API compatibility; steps are scoped via their parent playbook."""
    with _get_conn() as conn:
        r = conn.execute(
            "SELECT id, playbook_id, step_number, title, technique_id, required_rule, description, tactic, "
            "priority, category "
            "FROM playbook_steps WHERE id = ?",
            [step_id],
        ).fetchone()
    if not r:
        return None
    step = PlaybookStep(
        id=r[0], playbook_id=r[1], step_number=r[2], title=r[3],
        technique_id=r[4] or "", required_rule=r[5] or "", description=r[6] or "",
        tactic=r[7] or "", **_risk_fields(r[8:10]),
    )
    step.techniques = _get_step_techniques(step_id)
    step.detections = _get_step_detections(step_id)
    return step


# ---------------------------------------------------------------------------
# Negative Coverage / Known Blind Spots
# ---------------------------------------------------------------------------

def add_blind_spot(entity_type: str, entity_id: str, reason: str,
                   system_id: str = None, host_id: str = None,
                   created_by: str = "", override_type: str = "gap",
                   client_id: str = None, review_by: Optional[date] = None) -> BlindSpot:
    """Record a known blind spot (negative coverage).
    override_type: 'gap' (amber/known gap) or 'na' (grey/not applicable).
    review_by: when the mark should be looked at again (None = no date)."""
    if override_type not in ("gap", "na"):
        override_type = "gap"
    cols = ["entity_type", "entity_id", "system_id", "host_id", "reason", "created_by", "override_type", "review_by"]
    vals = [entity_type, entity_id, system_id, host_id, reason, created_by, override_type, review_by]
    if client_id:
        cols.append("client_id")
        vals.append(client_id)
    with _get_conn() as conn:
        r = conn.execute(
            f"INSERT INTO blind_spots ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)}) "
            f"RETURNING {_bs_cols()}",
            vals,
        ).fetchone()
        if entity_type == "tactic":
            _record_technique_event(
                conn, "na_added" if override_type == "na" else "gap_added", step_id=entity_id,
                system_id=system_id, reason=reason, detail=_review_note(review_by),
                actor=created_by or None, client_id=client_id,
            )
    return _bs_from_row(r)


def _review_note(review_by: Optional[date]) -> Optional[str]:
    return f"Review by {review_by.isoformat()}" if review_by else None


def update_blind_spot(blind_spot_id: str, reason: str, override_type: str,
                      review_by: Optional[date] = None, actor: str = None,
                      client_id: str = None) -> Optional[BlindSpot]:
    """Edit a known gap / N/A mark in place: its type, reason and review date. The history
    records what it was changed from, so the previous reasoning is never lost."""
    if override_type not in ("gap", "na"):
        override_type = "gap"
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        before = conn.execute(
            f"SELECT {_bs_cols()} FROM blind_spots WHERE id = ?" + frag, [blind_spot_id] + params,
        ).fetchone()
        if not before:
            return None
        old = _bs_from_row(before)
        r = conn.execute(
            "UPDATE blind_spots SET reason = ?, override_type = ?, review_by = ?, "
            "updated_at = now(), updated_by = ? WHERE id = ?" + frag + f" RETURNING {_bs_cols()}",
            [reason, override_type, review_by, actor or "", blind_spot_id] + params,
        ).fetchone()
        new = _bs_from_row(r)
        if old.entity_type == "tactic":
            label = {"gap": "Known gap", "na": "Not applicable"}
            changes = []
            if old.override_type != new.override_type:
                changes.append(f"{label[old.override_type]} → {label[new.override_type]}")
            if old.reason != new.reason:
                changes.append(f"was: {old.reason}")
            if old.review_by != new.review_by:
                changes.append(_review_note(new.review_by) or "Review date cleared")
            if changes:
                _record_technique_event(
                    conn, "na_edited" if new.override_type == "na" else "gap_edited",
                    step_id=old.entity_id, system_id=old.system_id, reason=new.reason,
                    detail="; ".join(changes), actor=actor, client_id=client_id,
                )
    return new


def remove_blind_spot(blind_spot_id: str, client_id: str = None, actor: str = None) -> bool:
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT entity_type, entity_id, system_id, reason, COALESCE(override_type, 'gap') "
            "FROM blind_spots WHERE id = ?" + frag, [blind_spot_id] + params,
        ).fetchone()
        cnt = conn.execute("DELETE FROM blind_spots WHERE id = ?" + frag, [blind_spot_id] + params).rowcount
        if row and cnt and row[0] == "tactic":
            _record_technique_event(
                conn, "na_removed" if row[4] == "na" else "gap_removed", step_id=row[1],
                system_id=row[2], reason=row[3], actor=actor, client_id=client_id,
            )
    return cnt > 0


def get_blind_spots(entity_type: str, entity_id: str, client_id: str = None) -> List[BlindSpot]:
    """Get all blind spots for a given entity (CVE or step)."""
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        rows = conn.execute(
            f"SELECT {_bs_cols()} FROM blind_spots WHERE entity_type = ? AND entity_id = ?" + frag
            + " ORDER BY created_at",
            [entity_type, entity_id] + params,
        ).fetchall()
    return [_bs_from_row(r) for r in rows]


def get_blind_spots_for_system(system_id: str) -> List[BlindSpot]:
    """Get all blind spots affecting a system (by system_id or by host_id belonging to system)."""
    with _get_conn() as conn:
        rows = conn.execute(
            f"SELECT {_bs_cols()} FROM blind_spots WHERE system_id = ? ORDER BY created_at",
            [system_id],
        ).fetchall()
        host_rows = conn.execute(
            f"SELECT {_bs_cols('bs')} FROM blind_spots bs JOIN hosts h ON h.id = bs.host_id "
            "WHERE h.system_id = ? ORDER BY bs.created_at",
            [system_id],
        ).fetchall()
    all_rows = {r[0]: r for r in rows}
    for r in host_rows:
        all_rows[r[0]] = r
    return [_bs_from_row(r) for r in all_rows.values()]


# ---------------------------------------------------------------------------
# Baseline Snapshots
# ---------------------------------------------------------------------------

def create_baseline_snapshot(
    system_id: str, baseline_id: str, label: str, captured_by: str,
    captured_at=None, client_id: str = None,
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
        if client_id:
            conn.execute(
                "INSERT INTO system_baseline_snapshots "
                "(id, system_id, baseline_id, captured_at, captured_by, label, "
                "score_percentage, count_green, count_amber, count_red, count_grey, client_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [snap_id, system_id, baseline_id, ts, captured_by, label,
                 score_pct, count_green, count_amber, count_red, count_grey, client_id],
            )
        else:
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
    system_id: str, label: str, captured_by: str, captured_at=None, client_id: str = None,
) -> List[Dict]:
    """Snapshot all baselines applied to a system with a shared timestamp."""
    from datetime import datetime as _dt

    ts = captured_at or _dt.utcnow()
    all_baselines = get_system_baselines(system_id, client_id=client_id)
    results = []
    for bl in all_baselines:
        snap = create_baseline_snapshot(
            system_id, bl["playbook_id"], label, captured_by, captured_at=ts, client_id=client_id,
        )
        if snap:
            results.append(snap)
    return results


def get_baseline_snapshots(system_id: str, client_id: str = None) -> List[Dict]:
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


def delete_baseline_snapshot(snapshot_id: str, client_id: str = None) -> bool:
    """Delete a single snapshot."""
    frag, params = _cf("", client_id)
    with _get_conn() as conn:
        cnt = conn.execute(
            "DELETE FROM system_baseline_snapshots WHERE id = ?" + frag, [snapshot_id] + params,
        ).rowcount
    return cnt > 0


# ---------------------------------------------------------------------------
# Cross-Tenant Baseline Cloning
# ---------------------------------------------------------------------------

def clone_baseline_cross_tenant(
    source_client_id: str,
    target_client_id: str,
    baseline_id: str,
) -> Dict:
    """Clone a baseline (playbook + steps + techniques + detections) from one
    tenant's database into another.  All rows receive fresh UUIDs so the
    clone is completely independent of the source.

    Returns a dict with the new playbook id and name.
    """
    import uuid
    import duckdb
    from app.services.tenant_manager import resolve_tenant_db_path, is_multi_db_mode
    from app.config import get_settings

    if source_client_id == target_client_id:
        raise ValueError("Source and target clients must be different.")

    settings = get_settings()
    multi_db = is_multi_db_mode()

    if multi_db:
        src_path = resolve_tenant_db_path(source_client_id, settings.data_dir)
        tgt_path = resolve_tenant_db_path(target_client_id, settings.data_dir)
        if not src_path or not tgt_path:
            raise ValueError("Both clients must have tenant databases.")
        src = duckdb.connect(src_path)
        tgt = duckdb.connect(tgt_path)
    else:
        # Single DB — use a single shared connection
        src = _get_conn().__enter__()
        tgt = src

    try:
        result = _clone_baseline_inner(src, tgt, baseline_id, target_client_id)
    finally:
        if multi_db:
            src.close()
            tgt.close()
        else:
            src.__exit__(None, None, None)

    logger.info(
        f"Baseline cloned from client {source_client_id} to "
        f"{target_client_id} as '{result['name']}' (new id={result['id']})"
    )
    return result


def _clone_baseline_inner(src, tgt, baseline_id: str, target_client_id: str) -> Dict:
    """Core cloning logic shared by both single-DB and multi-DB paths. Only a template can be
    cloned; a system's own copy belongs to that system."""
    pb = src.execute(
        "SELECT name FROM playbooks WHERE id = ? AND system_id IS NULL",
        [baseline_id],
    ).fetchone()
    if not pb:
        raise ValueError("Baseline not found in source tenant.")
    clone_name = f"{pb[0]} (clone)"
    new_pb_id, steps = _copy_playbook(src, tgt, baseline_id, name=clone_name, client_id=target_client_id)
    return {"id": new_pb_id, "name": clone_name, "steps": steps}
