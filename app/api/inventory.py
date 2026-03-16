"""
API routes for the Asset Inventory / CVE Mapping module (Phase 2: Enterprise).

Page routes (HTML):
  GET  /systems                    Systems dashboard
  GET  /systems/{id}               System detail (devices list)
  GET  /hosts/{host_id}            Device detail (packages + CVE matches)
  GET  /cve-overview               Global CVE overview (all KEV, stats, import)
  GET  /cve/{cve_id}               CVE detail with MITRE techniques + detection

API routes (HTMX / JSON):
  POST   /api/inventory/systems              Create system
  PUT    /api/inventory/systems/{id}         Update system
  DELETE /api/inventory/systems/{id}         Delete system
  POST   /api/inventory/systems/{id}/hosts   Create device in system
  DELETE /api/inventory/hosts/{id}           Delete device
  POST   /api/inventory/systems/{id}/nessus-upload  Upload Nessus XML
  POST   /api/inventory/nessus-upload        Upload Nessus XML (with system_id query param)
  POST   /api/inventory/hosts/{id}/software  Add package to device
  DELETE /api/inventory/software/{sw_id}     Delete package

  GET    /api/inventory/hosts/{id}/cve-matches     CVE matches for device (partial)
  GET    /api/inventory/cve-overview-partial        KEV table (HTMX reload)
  POST   /api/inventory/feed/cisa                   Ingest CISA KEV blob (file upload)
  GET    /api/inventory/cve/{cve_id}/detect          Get detection for a CVE
  POST   /api/inventory/cve/{cve_id}/detect          Mark CVE as detected
  DELETE /api/inventory/cve/{cve_id}/detect          Unmark detection
  GET    /api/inventory/inventory-stats-partial      Dashboard stats partial (inventory)
  GET    /api/inventory/cve-stats-partial            Dashboard stats partial (CVE overview)
"""

from __future__ import annotations
import logging
from typing import Optional
from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, Response
from app.api.deps import CurrentUser, RequireUser
from app.inventory_engine import (
    add_classification, add_cve_technique_override, add_host, add_host_software,
    add_software, add_system,
    add_cve_detection, remove_cve_detection, get_cve_detections,
    apply_detection, remove_applied_detection, remove_detection_for_system,
    delete_classification, delete_host, delete_software, delete_system,
    edit_host, edit_software, edit_system,
    get_all_cve_overview, get_classification_color, get_cve_detail, get_cve_overview_stats,
    get_host, get_host_summaries, get_host_vulnerabilities,
    get_inventory_stats, get_software, get_system, get_system_summaries,
    get_system_vulnerabilities, get_rules_for_cve_techniques, get_all_siem_rules,
    ingest_cisa_feed, list_classifications, list_host_software, list_hosts, list_software,
    list_systems, parse_nessus_xml, remove_cve_technique_override,
    save_mitre_cve_map,
    build_system_report_data, build_cve_report_data,
    # Baselines
    list_playbooks, get_playbook, get_playbook_header, get_baselines_overview,
    create_playbook, delete_playbook, update_playbook,
    add_playbook_step, delete_playbook_step,
    apply_baseline, remove_baseline, get_system_baselines,
    # Tactic-level CRUD
    add_step_technique, remove_step_technique, update_step_technique,
    add_step_detection, remove_step_detection,
    update_playbook_step, get_playbook_step, get_step_affected_systems,
    get_baseline_step_coverage,
    # Blind Spots
    add_blind_spot, remove_blind_spot, get_blind_spots,
)
from app.models.inventory import HostCreate, HostUpdate, SoftwareCreate, SoftwareUpdate, SystemCreate, SystemUpdate, MITRE_TACTICS

logger = logging.getLogger(__name__)
router = APIRouter(tags=["inventory"])


def _templates(request: Request):
    return request.app.state.templates


def _render(name: str, request: Request, ctx: dict):
    from app.config import get_settings
    settings = get_settings()
    base = {
        "request": request,
        "brand_hue": settings.brand_hue,
        "cache_bust": settings.tide_version,
        "settings": settings,
    }
    base.update(ctx)
    return _templates(request).TemplateResponse(name, base)


def _get_conn_inline():
    from app.services.database import get_database_service
    return get_database_service().get_connection()


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------

@router.get("/systems", response_class=HTMLResponse)
def page_systems(request: Request, user: CurrentUser):
    summaries = get_system_summaries()
    systems = [s.system for s in summaries]  # for Nessus modal dropdown
    return _render("pages/systems.html", request, {
        "active_page": "systems", "summaries": summaries, "systems": systems, "user": user,
        "classifications": list_classifications(), "clf_colors": _clf_color_map(),
    })


@router.get("/systems/{system_id}", response_class=HTMLResponse)
def page_system_detail(request: Request, system_id: str, user: CurrentUser):
    from app.services.report_generator import CLASSIFICATION_OPTIONS
    system = get_system(system_id)
    if not system:
        raise HTTPException(status_code=404, detail="System not found")
    host_summaries = get_host_summaries(system_id)
    baselines = get_system_baselines(system_id)
    all_baselines = list_playbooks()
    return _render("pages/system_detail.html", request, {
        "active_page": "systems", "system": system,
        "host_summaries": host_summaries, "user": user,
        "classifications": list_classifications(), "clf_colors": _clf_color_map(),
        "classification_options": CLASSIFICATION_OPTIONS,
        "baselines": baselines, "playbooks": all_baselines,
    })


@router.get("/hosts/{host_id}", response_class=HTMLResponse)
def page_host_detail(request: Request, host_id: str, user: CurrentUser):
    host = get_host(host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    system = get_system(host.system_id)
    software = list_host_software(host_id)
    vulns = get_host_vulnerabilities(host_id)
    clf_color = get_classification_color(system.classification) if system and system.classification else None
    return _render("pages/host_detail.html", request, {
        "active_page": "systems", "host": host, "system": system,
        "software": software, "vulns": vulns, "user": user,
        "clf_color": clf_color,
    })


@router.get("/cve-overview", response_class=HTMLResponse)
def page_cve_overview(request: Request, user: CurrentUser):
    cves = get_all_cve_overview()
    stats = get_cve_overview_stats(cves=cves)
    return _render("pages/cve_overview.html", request, {
        "active_page": "cve_overview", "cves": cves,
        "matched_count": stats.matched_count,
        "stats": stats, "user": user,
    })


@router.get("/cve/{cve_id}", response_class=HTMLResponse)
def page_cve_detail(request: Request, cve_id: str, user: CurrentUser):
    from app.inventory_engine import get_cve_techniques
    from app.services.report_generator import CLASSIFICATION_OPTIONS
    cve = get_cve_detail(cve_id)
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    technique_rules = get_rules_for_cve_techniques(cve_id)
    techniques = get_cve_techniques(cve_id)
    # Group affected hosts by system for the template
    systems_map: dict = {}
    for h in cve.affected_hosts:
        if h.system_id not in systems_map:
            systems_map[h.system_id] = {"system_id": h.system_id, "system_name": h.system_name, "hosts": []}
        systems_map[h.system_id]["hosts"].append(h)
    grouped_systems = sorted(systems_map.values(), key=lambda s: s["system_name"])
    # Get all systems for "apply to system" dropdown
    all_systems = list_systems()
    cve_blind_spots = get_blind_spots("cve", cve_id)
    return _render("pages/cve_detail.html", request, {
        "active_page": "cve_overview", "cve": cve, "user": user,
        "cve_id": cve.cve_id,
        "techniques": techniques,
        "detections": cve.detections,
        "technique_rules": technique_rules,
        "all_siem_rules": get_all_siem_rules(),
        "grouped_systems": grouped_systems,
        "all_systems": all_systems,
        "classification_options": CLASSIFICATION_OPTIONS,
        "blind_spots": cve_blind_spots,
    })


# ---------------------------------------------------------------------------
# CVE MITRE Technique Override API
# ---------------------------------------------------------------------------

@router.post("/api/inventory/cve/{cve_id}/techniques", response_class=HTMLResponse)
async def api_add_cve_technique(request: Request, cve_id: str, user: RequireUser):
    """Add a manual MITRE technique override for a CVE. Re-renders the MITRE section."""
    from app.inventory_engine import get_cve_techniques
    form = await request.form()
    technique_id = (form.get("technique_id") or "").strip().upper()
    if not technique_id:
        raise HTTPException(status_code=422, detail="technique_id is required")
    add_cve_technique_override(cve_id, technique_id)
    cve = get_cve_detail(cve_id)
    technique_rules = get_rules_for_cve_techniques(cve_id)
    techniques = get_cve_techniques(cve_id)
    return _render("partials/cve_mitre_section.html", request, {
        "cve": cve, "cve_id": cve_id,
        "techniques": techniques,
        "technique_rules": technique_rules, "user": user,
    })


@router.delete("/api/inventory/cve/{cve_id}/techniques/{technique_id}", response_class=HTMLResponse)
async def api_remove_cve_technique(request: Request, cve_id: str, technique_id: str, user: RequireUser):
    """Remove a manual MITRE technique override for a CVE. Re-renders the MITRE section."""
    from app.inventory_engine import get_cve_techniques
    remove_cve_technique_override(cve_id, technique_id)
    cve = get_cve_detail(cve_id)
    technique_rules = get_rules_for_cve_techniques(cve_id)
    techniques = get_cve_techniques(cve_id)
    return _render("partials/cve_mitre_section.html", request, {
        "cve": cve, "cve_id": cve_id,
        "techniques": techniques,
        "technique_rules": technique_rules, "user": user,
    })


# ---------------------------------------------------------------------------
# Classification API
# ---------------------------------------------------------------------------

def _clf_color_map() -> dict:
    """Return {name: color} dict for all classifications."""
    return {c.name: c.color for c in list_classifications()}


@router.get("/api/inventory/classifications", response_class=HTMLResponse)
def api_list_classifications(request: Request, user: CurrentUser):
    return _render("partials/classification_list.html", request, {
        "classifications": list_classifications(), "user": user,
    })


@router.post("/api/inventory/classifications", response_class=HTMLResponse)
async def api_add_classification(request: Request, user: RequireUser):
    form = await request.form()
    name = (form.get("name") or "").strip()
    color = (form.get("color") or "#6b7280").strip()
    if not name:
        raise HTTPException(status_code=422, detail="Name is required")
    try:
        add_classification(name, color)
    except Exception:
        raise HTTPException(status_code=409, detail="Classification already exists")
    return _render("partials/classification_list.html", request, {
        "classifications": list_classifications(), "user": user,
    })


@router.delete("/api/inventory/classifications/{cls_id}", response_class=HTMLResponse)
def api_delete_classification(request: Request, cls_id: str, user: RequireUser):
    ok = delete_classification(cls_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Classification not found")
    return _render("partials/classification_list.html", request, {
        "classifications": list_classifications(), "user": user,
    })


# ---------------------------------------------------------------------------
# System API
# ---------------------------------------------------------------------------

@router.post("/api/inventory/systems", response_class=HTMLResponse)
async def api_create_system(request: Request, user: RequireUser):
    form = await request.form()
    data = SystemCreate(
        name=(form.get("name") or "").strip(),
        description=form.get("description") or None,
        classification=form.get("classification") or None,
    )
    if not data.name:
        raise HTTPException(status_code=422, detail="Name is required")
    system = add_system(data)
    summaries = get_system_summaries()
    systems = [s.system for s in summaries]
    return _render("partials/system_cards.html", request, {
        "summaries": summaries, "systems": systems, "user": user,
        "clf_colors": _clf_color_map(),
        "toast": f"System '{system.name}' created.",
    })


@router.put("/api/inventory/systems/{system_id}", response_class=HTMLResponse)
async def api_update_system(request: Request, system_id: str, user: RequireUser):
    form = await request.form()
    data = SystemUpdate(
        name=form.get("name") or None,
        description=form.get("description") or None,
        classification=form.get("classification") or None,
    )
    system = edit_system(system_id, data)
    if not system:
        raise HTTPException(status_code=404, detail="System not found")
    summaries = get_system_summaries()
    systems = [s.system for s in summaries]
    return _render("partials/system_cards.html", request, {
        "summaries": summaries, "systems": systems, "user": user,
        "clf_colors": _clf_color_map(),
    })


@router.delete("/api/inventory/systems/{system_id}", response_class=HTMLResponse)
def api_delete_system(request: Request, system_id: str, user: RequireUser):
    ok = delete_system(system_id)
    if not ok:
        raise HTTPException(status_code=404, detail="System not found")
    summaries = get_system_summaries()
    systems = [s.system for s in summaries]
    return _render("partials/system_cards.html", request, {
        "summaries": summaries, "systems": systems, "user": user,
        "clf_colors": _clf_color_map(),
        "toast": "System deleted.",
    })


# ---------------------------------------------------------------------------
# Device API
# ---------------------------------------------------------------------------

@router.post("/api/inventory/systems/{system_id}/hosts", response_class=HTMLResponse)
async def api_create_host(request: Request, system_id: str, user: RequireUser):
    if not get_system(system_id):
        raise HTTPException(status_code=404, detail="System not found")
    form = await request.form()
    data = HostCreate(
        name=(form.get("name") or "").strip(),
        ip_address=form.get("ip_address") or None,
        os=form.get("os") or None,
        hardware_vendor=form.get("hardware_vendor") or None,
        model=form.get("model") or None,
        source="manual",
    )
    if not data.name:
        raise HTTPException(status_code=422, detail="Device name is required")
    add_host(system_id, data)
    host_summaries = get_host_summaries(system_id)
    sys = get_system(system_id)
    return _render("partials/host_list.html", request, {
        "system_id": system_id, "host_summaries": host_summaries, "user": user,
        "sys_classification": sys.classification if sys else None,
        "sys_clf_color": get_classification_color(sys.classification) if sys and sys.classification else None,
    })


@router.put("/api/inventory/hosts/{host_id}", response_class=HTMLResponse)
async def api_update_host(request: Request, host_id: str, user: RequireUser):
    """Edit device name, IP, OS etc.  Returns the device detail header partial."""
    form = await request.form()
    data = HostUpdate(
        name=(form.get("name") or "").strip() or None,
        ip_address=form.get("ip_address") or None,
        os=form.get("os") or None,
        hardware_vendor=form.get("hardware_vendor") or None,
        model=form.get("model") or None,
    )
    host = edit_host(host_id, data)
    if not host:
        raise HTTPException(status_code=404, detail="Device not found")
    system = get_system(host.system_id)
    software = list_host_software(host_id)
    vulns = get_host_vulnerabilities(host_id)
    clf_color = get_classification_color(system.classification) if system and system.classification else None
    return _render("partials/host_header.html", request, {
        "host": host, "system": system, "software": software, "vulns": vulns, "user": user,
        "clf_color": clf_color,
    })


@router.delete("/api/inventory/hosts/{host_id}", response_class=HTMLResponse)
def api_delete_host(
    request: Request, host_id: str, user: RequireUser,
    system_id: str = Query(...),
):
    ok = delete_host(host_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Device not found")
    host_summaries = get_host_summaries(system_id)
    sys = get_system(system_id)
    return _render("partials/host_list.html", request, {
        "system_id": system_id, "host_summaries": host_summaries, "user": user,
        "sys_classification": sys.classification if sys else None,
        "sys_clf_color": get_classification_color(sys.classification) if sys and sys.classification else None,
    })


# ---------------------------------------------------------------------------
# Nessus Upload (per-system endpoint)
# ---------------------------------------------------------------------------

@router.post("/api/inventory/systems/{system_id}/nessus-upload", response_class=HTMLResponse)
async def api_nessus_upload_by_system(
    request: Request, system_id: str, user: RequireUser,
    file: UploadFile = File(...),
):
    if not get_system(system_id):
        raise HTTPException(status_code=404, detail="System not found")
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    filename = file.filename or ""
    if not (filename.endswith(".nessus") or filename.endswith(".xml")):
        raise HTTPException(status_code=422, detail="File must be .nessus or .xml")
    try:
        hosts_created, records_inserted, warnings = parse_nessus_xml(content, system_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    host_summaries = get_host_summaries(system_id)
    sys_obj = get_system(system_id)
    return _render("partials/host_list.html", request, {
        "system_id": system_id, "host_summaries": host_summaries, "user": user,
        "nessus_hosts": hosts_created, "nessus_records": records_inserted,
        "nessus_warnings": warnings,
        "sys_classification": sys_obj.classification if sys_obj else None,
        "sys_clf_color": get_classification_color(sys_obj.classification) if sys_obj and sys_obj.classification else None,
    })


@router.post("/api/inventory/nessus-upload", response_class=HTMLResponse)
async def api_nessus_upload_global(
    request: Request, user: RequireUser,
    file: UploadFile = File(...),
    system_id: str = Form(...),
    new_env_name: Optional[str] = Form(None),
):
    """Global Nessus upload: user selects the system from the modal.
    Passing system_id='__new__' creates a new system using new_env_name."""
    if system_id == "__new__":
        env_name = (new_env_name or "").strip()
        if not env_name:
            raise HTTPException(status_code=422, detail="System name is required when creating a new one")
        new_sys = add_system(SystemCreate(name=env_name))
        system = new_sys
    else:
        system = get_system(system_id)
        if not system:
            raise HTTPException(status_code=404, detail="System not found")
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    filename = file.filename or ""
    if not (filename.endswith(".nessus") or filename.endswith(".xml")):
        raise HTTPException(status_code=422, detail="File must be .nessus or .xml")
    try:
        hosts_created, records_inserted, warnings = parse_nessus_xml(content, system.id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    summaries = get_system_summaries()
    systems = [s.system for s in summaries]
    return _render("partials/system_cards.html", request, {
        "summaries": summaries, "systems": systems, "user": user,
        "clf_colors": _clf_color_map(),
        "toast": (f"Nessus import complete: {hosts_created} device(s), "
                  f"{records_inserted} package record(s) added to {system.name}."),
    })


# ---------------------------------------------------------------------------
# Device Packages API
# ---------------------------------------------------------------------------

@router.post("/api/inventory/hosts/{host_id}/software", response_class=HTMLResponse)
async def api_add_host_software(request: Request, host_id: str, user: RequireUser):
    host = get_host(host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Device not found")
    form = await request.form()
    data = SoftwareCreate(
        name=(form.get("name") or "").strip(),
        version=form.get("version") or None,
        vendor=form.get("vendor") or None,
        cpe=form.get("cpe") or None,
        source="manual",
    )
    if not data.name:
        raise HTTPException(status_code=422, detail="Package name is required")
    add_host_software(host_id, host.system_id, data)
    software = list_host_software(host_id)
    vulns = get_host_vulnerabilities(host_id)
    return _render("partials/host_software.html", request, {
        "host": host, "software": software, "vulns": vulns, "user": user,
    })


@router.put("/api/inventory/software/{software_id}", response_class=HTMLResponse)
async def api_update_software(
    request: Request, software_id: str, user: RequireUser,
    host_id: str = Query(None),
):
    """Edit a software record (name, version, vendor, CPE)."""
    form = await request.form()
    data = SoftwareUpdate(
        name=(form.get("name") or "").strip() or None,
        version=form.get("version") or None,
        vendor=form.get("vendor") or None,
        cpe=form.get("cpe") or None,
    )
    sw = edit_software(software_id, data)
    if not sw:
        raise HTTPException(status_code=404, detail="Software not found")
    h_id = host_id or sw.host_id
    if h_id:
        host = get_host(h_id)
        software = list_host_software(h_id)
        vulns = get_host_vulnerabilities(h_id)
        return _render("partials/host_software.html", request, {
            "host": host, "software": software, "vulns": vulns, "user": user,
        })
    return _render("partials/host_software.html", request, {"software": [], "user": user})


@router.delete("/api/inventory/software/{software_id}", response_class=HTMLResponse)
def api_delete_software(
    request: Request, software_id: str, user: RequireUser,
    host_id: str = Query(None), system_id: str = Query(None),
):
    delete_software(software_id)
    if host_id:
        host = get_host(host_id)
        software = list_host_software(host_id)
        vulns = get_host_vulnerabilities(host_id)
        return _render("partials/host_software.html", request, {
            "host": host, "software": software, "vulns": vulns, "user": user,
        })
    software = list_software(system_id) if system_id else []
    vulns = get_system_vulnerabilities(system_id) if system_id else []
    return _render("partials/software_list.html", request, {
        "system_id": system_id, "software": software, "vulns": vulns, "user": user,
    })


# ---------------------------------------------------------------------------
# CVE Partials
# ---------------------------------------------------------------------------

@router.get("/api/inventory/hosts/{host_id}/cve-matches", response_class=HTMLResponse)
def api_host_cve_matches(request: Request, host_id: str, user: CurrentUser):
    host = get_host(host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    vulns = get_host_vulnerabilities(host_id)
    return _render("partials/host_cve_matches.html", request, {
        "host": host, "vulns": vulns, "user": user,
    })


@router.get("/api/inventory/cve-overview-partial", response_class=HTMLResponse)
def api_cve_overview_partial(request: Request, user: CurrentUser):
    from app.inventory_engine import list_systems
    cves = get_all_cve_overview()
    matched_count = sum(1 for c in cves if c.affected_hosts)
    systems = list_systems()
    return _render("partials/cve_overview_table.html", request, {
        "cves": cves, "matched_count": matched_count, "user": user,
        "systems": systems,
    })


# ---------------------------------------------------------------------------
# CVE Detection (add / remove detection entries)
# ---------------------------------------------------------------------------

@router.post("/api/inventory/cve/{cve_id}/detect", response_class=HTMLResponse)
async def api_add_detection(request: Request, cve_id: str, user: RequireUser):
    """Add a new detection entry for a CVE."""
    form = await request.form()
    rule_ref = (form.get("rule_ref") or "").strip() or None
    note = (form.get("note") or "").strip() or None
    source = (form.get("source") or "manual").strip()
    if not rule_ref and not note:
        raise HTTPException(status_code=422, detail="rule_ref or note is required")
    add_cve_detection(cve_id, rule_ref=rule_ref, note=note, source=source)
    detections = get_cve_detections(cve_id)
    technique_rules = get_rules_for_cve_techniques(cve_id)
    return _render("partials/cve_detection_badge.html", request, {
        "cve_id": cve_id.upper(),
        "detections": detections,
        "technique_rules": technique_rules,
        "all_siem_rules": get_all_siem_rules(),
        "user": user,
    })


@router.delete("/api/inventory/cve/{cve_id}/detect/{detection_id}", response_class=HTMLResponse)
async def api_remove_detection(request: Request, cve_id: str, detection_id: str, user: RequireUser):
    """Remove a single detection entry by its ID."""
    remove_cve_detection(detection_id)
    detections = get_cve_detections(cve_id)
    technique_rules = get_rules_for_cve_techniques(cve_id)
    return _render("partials/cve_detection_badge.html", request, {
        "cve_id": cve_id.upper(),
        "detections": detections,
        "technique_rules": technique_rules,
        "all_siem_rules": get_all_siem_rules(),
        "user": user,
    })


# ---------------------------------------------------------------------------
# CVE Detection Application (Tier 3: apply / unapply to systems or hosts)
# ---------------------------------------------------------------------------

@router.post("/api/inventory/cve/{cve_id}/detect/{detection_id}/apply", response_class=HTMLResponse)
async def api_apply_detection(request: Request, cve_id: str, detection_id: str, user: RequireUser):
    """Apply a detection rule to a system or host. Re-renders the affected hosts section."""
    form = await request.form()
    system_id = (form.get("system_id") or "").strip() or None
    host_id = (form.get("host_id") or "").strip() or None
    if not system_id and not host_id:
        raise HTTPException(status_code=422, detail="system_id or host_id is required")
    apply_detection(detection_id, system_id=system_id, host_id=host_id)
    return _render_cve_affected_section(request, cve_id, user)


@router.delete("/api/inventory/applied-detection/{applied_id}", response_class=HTMLResponse)
async def api_remove_applied_detection(request: Request, applied_id: str, user: RequireUser,
                                       cve_id: str = Query(...)):
    """Remove an applied detection. Re-renders the affected hosts section."""
    remove_applied_detection(applied_id)
    return _render_cve_affected_section(request, cve_id, user)


@router.delete("/api/inventory/cve/{cve_id}/detect/{detection_id}/apply-system/{system_id}", response_class=HTMLResponse)
async def api_remove_detection_for_system(request: Request, cve_id: str, detection_id: str, system_id: str, user: RequireUser):
    """Remove an applied detection from all hosts in a system."""
    remove_detection_for_system(detection_id, system_id)
    return _render_cve_affected_section(request, cve_id, user)


def _render_cve_affected_section(request: Request, cve_id: str, user):
    """Helper: re-render the affected devices section for a CVE."""
    cve = get_cve_detail(cve_id)
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    systems_map: dict = {}
    for h in cve.affected_hosts:
        if h.system_id not in systems_map:
            systems_map[h.system_id] = {"system_id": h.system_id, "system_name": h.system_name, "hosts": []}
        systems_map[h.system_id]["hosts"].append(h)
    grouped_systems = sorted(systems_map.values(), key=lambda s: s["system_name"])
    return _render("partials/cve_affected_hosts.html", request, {
        "cve": cve, "cve_id": cve.cve_id,
        "detections": cve.detections,
        "grouped_systems": grouped_systems,
        "user": user,
    })


# ---------------------------------------------------------------------------
# Dashboard Stats Partials
# ---------------------------------------------------------------------------

@router.get("/api/inventory/inventory-stats-partial", response_class=HTMLResponse)
def api_inventory_stats(request: Request, user: CurrentUser):
    stats = get_inventory_stats()
    return _render("partials/inventory_metrics.html", request, {
        "stats": stats, "user": user,
    })


@router.get("/api/inventory/cve-stats-partial", response_class=HTMLResponse)
def api_cve_stats(request: Request, user: CurrentUser):
    stats = get_cve_overview_stats()
    return _render("partials/cve_metrics.html", request, {
        "stats": stats, "user": user,
    })


# ---------------------------------------------------------------------------
# CISA KEV Feed Ingest
# ---------------------------------------------------------------------------

@router.delete("/api/inventory/feed/cisa", response_class=HTMLResponse)
async def api_reset_kev_override(request: Request, user: RequireUser):
    """Delete the KEV override file so the system/dockerfile KEV is used instead."""
    from app.config import get_settings
    import os
    settings = get_settings()
    path = settings.cisa_kev_override_path
    removed = False
    if path and os.path.exists(path):
        os.remove(path)
        removed = True
    cves = get_all_cve_overview()
    stats = get_cve_overview_stats(cves=cves)
    return _render("partials/cve_overview_table.html", request, {
        "cves": cves, "matched_count": stats.matched_count,
        "stats": stats, "user": user,
        "toast": "KEV override removed — using system catalogue." if removed else "No override file found.",
    })

@router.post("/api/inventory/feed/cisa", response_class=HTMLResponse)
async def api_ingest_cisa(
    request: Request, user: RequireUser,
    file: Optional[UploadFile] = File(None),
):
    if file:
        raw = await file.read()
    else:
        raw = await request.body()
    if not raw:
        raise HTTPException(status_code=400, detail="No data received")
    try:
        count = ingest_cisa_feed(raw)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    cves = get_all_cve_overview()
    stats = get_cve_overview_stats(cves=cves)
    return _render("partials/cve_overview_table.html", request, {
        "cves": cves, "matched_count": stats.matched_count,
        "stats": stats, "user": user,
        "toast": f"CISA KEV feed ingested: {count} vulnerabilities loaded.",
    })


# ---------------------------------------------------------------------------
# MITRE CVE Mapping Upload (airgap-safe: file stored locally)
# ---------------------------------------------------------------------------

@router.post("/api/inventory/feed/mitre-mapping", response_class=HTMLResponse)
async def api_upload_mitre_mapping(
    request: Request, user: RequireUser,
    file: Optional[UploadFile] = File(None),
):
    """Upload a CVE→ATT&CK mapping JSON file (airgap-safe offline update).
    Accepted formats:
      {\"CVE-xxxx-yyyy\": [\"T1190\", ...], ...}   — CVE-keyed
      {\"T1190\": [\"CVE-xxxx-yyyy\", ...], ...}   — technique-keyed (auto-inverted)
    """
    if file:
        raw = await file.read()
    else:
        raw = await request.body()
    if not raw:
        raise HTTPException(status_code=400, detail="No data received")
    try:
        count = save_mitre_cve_map(raw)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return HTMLResponse(
        f"<div class='alert alert-success' style='margin-top:0.5rem;'>"
        f"Mapping updated: {count} entries saved. Reloading page to apply…"
        f"<script>setTimeout(()=>window.location.reload(),1500)</script></div>"
    )


# ---------------------------------------------------------------------------
# Baselines — Page + API routes
# ---------------------------------------------------------------------------

@router.get("/baselines", response_class=HTMLResponse)
def page_baselines(request: Request, user: CurrentUser):
    baselines = get_baselines_overview()
    return _render("pages/baselines.html", request, {
        "active_page": "baselines", "baselines": baselines, "user": user,
    })


@router.get("/baselines/{baseline_id}", response_class=HTMLResponse)
def page_baseline_detail(request: Request, baseline_id: str, user: CurrentUser):
    pb = get_playbook(baseline_id)
    if not pb:
        raise HTTPException(status_code=404, detail="Baseline not found")
    # Group tactics by MITRE tactic
    tactic_groups = {}
    for t in pb.tactics:
        tac = t.tactic or "Other"
        tactic_groups.setdefault(tac, []).append(t)
    # Systems applied to this baseline
    with _get_conn_inline() as conn:
        sys_rows = conn.execute(
            "SELECT sb.system_id, s.name FROM system_baselines sb "
            "JOIN systems s ON s.id = sb.system_id WHERE sb.playbook_id = ? ORDER BY s.name",
            [baseline_id],
        ).fetchall()
    applied_systems = [{"system_id": r[0], "system_name": r[1]} for r in sys_rows]
    all_systems = list_systems()
    step_coverage = get_baseline_step_coverage(baseline_id)
    return _render("pages/baseline_detail.html", request, {
        "active_page": "baselines", "baseline": pb, "user": user,
        "mitre_tactics": MITRE_TACTICS,
        "tactic_groups": tactic_groups,
        "applied_systems": applied_systems,
        "all_systems": all_systems,
        "step_coverage": step_coverage,
    })


@router.post("/api/baselines", response_class=HTMLResponse)
def api_create_baseline(
    request: Request, user: RequireUser,
    name: str = Form(...), description: str = Form(""),
):
    create_playbook(name, description)
    baselines = get_baselines_overview()
    return _render("partials/baselines_list.html", request, {"baselines": baselines})


@router.delete("/api/baselines/{baseline_id}", response_class=HTMLResponse)
def api_delete_baseline(request: Request, baseline_id: str, user: RequireUser):
    delete_playbook(baseline_id)
    baselines = get_baselines_overview()
    return _render("partials/baselines_list.html", request, {"baselines": baselines})


@router.put("/api/baselines/{baseline_id}", response_class=HTMLResponse)
def api_update_baseline(
    request: Request, baseline_id: str, user: RequireUser,
    name: str = Form(...), description: str = Form(""),
):
    update_playbook(baseline_id, name=name, description=description)
    resp = HTMLResponse("")
    resp.headers["HX-Redirect"] = f"/baselines/{baseline_id}"
    return resp


@router.post("/api/baselines/{baseline_id}/tactics", response_class=HTMLResponse)
def api_add_tactic(
    request: Request, baseline_id: str, user: RequireUser,
    title: str = Form(...), step_number: int = Form(0),
    technique_id: str = Form(""),
    description: str = Form(""), tactic: str = Form(""),
):
    if step_number < 1:
        pb = get_playbook(baseline_id)
        step_number = (len(pb.tactics) + 1) if pb else 1
    add_playbook_step(baseline_id, step_number, title, technique_id, "", description, tactic=tactic or None)
    pb = get_playbook(baseline_id)
    return _render("partials/baseline_tactics.html", request, {"baseline": pb})


@router.delete("/api/baselines/tactics/{tactic_id}", response_class=HTMLResponse)
def api_delete_tactic(request: Request, tactic_id: str, playbook_id: str = Query(...), user: RequireUser = None):
    delete_playbook_step(tactic_id)
    if request.headers.get("HX-Target") == "body":
        resp = HTMLResponse("")
        resp.headers["HX-Redirect"] = f"/baselines/{playbook_id}"
        return resp
    pb = get_playbook(playbook_id)
    return _render("partials/baseline_tactics.html", request, {"baseline": pb})


@router.post("/api/baselines/{baseline_id}/apply/{system_id}", response_class=HTMLResponse)
def api_apply_baseline(request: Request, baseline_id: str, system_id: str, user: RequireUser):
    apply_baseline(system_id, baseline_id)
    if request.headers.get("HX-Target") == "baseline-coverage":
        baselines = get_system_baselines(system_id)
        playbooks = list_playbooks()
        return _render("partials/baseline_coverage.html", request, {
            "baselines": baselines, "system_id": system_id, "playbooks": playbooks,
        })
    resp = HTMLResponse("")
    resp.headers["HX-Redirect"] = f"/baselines/{baseline_id}"
    return resp


@router.delete("/api/baselines/{baseline_id}/apply/{system_id}", response_class=HTMLResponse)
def api_remove_baseline(request: Request, baseline_id: str, system_id: str, user: RequireUser):
    remove_baseline(system_id, baseline_id)
    if request.headers.get("HX-Target") == "baseline-coverage":
        baselines = get_system_baselines(system_id)
        playbooks = list_playbooks()
        return _render("partials/baseline_coverage.html", request, {
            "baselines": baselines, "system_id": system_id, "playbooks": playbooks,
        })
    resp = HTMLResponse("")
    resp.headers["HX-Redirect"] = f"/baselines/{baseline_id}"
    return resp


@router.get("/api/baselines/system/{system_id}/coverage", response_class=HTMLResponse)
def api_system_baseline_coverage(request: Request, system_id: str, user: CurrentUser):
    baselines = get_system_baselines(system_id)
    playbooks = list_playbooks()
    return _render("partials/baseline_coverage.html", request, {
        "baselines": baselines, "system_id": system_id, "playbooks": playbooks,
    })


# ---------------------------------------------------------------------------
# Tactic Detail Page + Tactic-level CRUD
# ---------------------------------------------------------------------------

def _build_technique_rules(step):
    """Build technique_id -> {has_detection, rule_count, rules} map for pills and dropdown."""
    from app.services.database import get_database_service
    db = get_database_service()
    covered_ttps = db.get_all_covered_ttps()
    technique_rules = {}
    for t in step.techniques:
        tid = t.technique_id.upper()
        rules = db.get_rules_for_technique(tid, enabled_only=False)
        technique_rules[tid] = {
            "has_detection": tid in covered_ttps,
            "rule_count": len(rules),
            "rules": rules,
        }
    return technique_rules


@router.get("/baselines/{baseline_id}/tactics/{tactic_id}", response_class=HTMLResponse)
def page_tactic_detail(request: Request, baseline_id: str, tactic_id: str, user: CurrentUser):
    pb = get_playbook_header(baseline_id)
    if not pb:
        raise HTTPException(status_code=404, detail="Baseline not found")
    step = get_playbook_step(tactic_id)
    if not step:
        raise HTTPException(status_code=404, detail="Tactic not found")
    affected_systems = get_step_affected_systems(tactic_id)
    blind_spots = get_blind_spots("tactic", tactic_id)
    all_siem_rules = get_all_siem_rules()

    technique_rules = _build_technique_rules(step)

    return _render("pages/tactic_detail.html", request, {
        "active_page": "baselines", "baseline": pb, "tactic": step,
        "step": step,  # alias for partials that still reference step
        "step_id": tactic_id,  # needed by tactic_affected_systems.html partial
        "playbook": pb,  # alias for breadcrumb compat
        "affected_systems": affected_systems, "blind_spots": blind_spots,
        "all_siem_rules": all_siem_rules,
        "technique_rules": technique_rules,
        "mitre_tactics": MITRE_TACTICS,
        "user": user,
    })


@router.put("/api/baselines/tactics/{tactic_id}", response_class=HTMLResponse)
def api_update_tactic(
    request: Request, tactic_id: str, user: RequireUser,
    title: str = Form(None), tactic: str = Form(None),
    description: str = Form(None), step_number: int = Form(None),
):
    step = update_playbook_step(tactic_id, title=title, tactic=tactic,
                                description=description, step_number=step_number)
    if not step:
        raise HTTPException(status_code=404)
    resp = HTMLResponse("")
    resp.headers["HX-Redirect"] = f"/baselines/{step.playbook_id}/tactics/{tactic_id}"
    return resp


@router.post("/api/baselines/tactics/{tactic_id}/techniques", response_class=HTMLResponse)
def api_add_tactic_technique(
    request: Request, tactic_id: str, user: RequireUser,
    technique_id: str = Form(...),
):
    add_step_technique(tactic_id, technique_id)
    step = get_playbook_step(tactic_id)
    resp = _render("partials/tactic_mitre_section.html", request, {
        "step": step, "technique_rules": _build_technique_rules(step),
    })
    resp.headers["HX-Trigger"] = "stepUpdated"
    return resp


@router.delete("/api/baselines/tactics/{tactic_id}/techniques/{technique_row_id}", response_class=HTMLResponse)
def api_remove_tactic_technique(
    request: Request, tactic_id: str, technique_row_id: str, user: RequireUser,
):
    remove_step_technique(technique_row_id)
    step = get_playbook_step(tactic_id)
    resp = _render("partials/tactic_mitre_section.html", request, {
        "step": step, "technique_rules": _build_technique_rules(step),
    })
    resp.headers["HX-Trigger"] = "stepUpdated"
    return resp


@router.put("/api/baselines/tactics/{tactic_id}/techniques/{technique_row_id}", response_class=HTMLResponse)
def api_update_tactic_technique(
    request: Request, tactic_id: str, technique_row_id: str, user: RequireUser,
    technique_id: str = Form(...),
):
    update_step_technique(technique_row_id, technique_id)
    step = get_playbook_step(tactic_id)
    resp = _render("partials/tactic_mitre_section.html", request, {
        "step": step, "technique_rules": _build_technique_rules(step),
    })
    resp.headers["HX-Trigger"] = "stepUpdated"
    return resp


@router.post("/api/baselines/tactics/{tactic_id}/detections", response_class=HTMLResponse)
def api_add_tactic_detection(
    request: Request, tactic_id: str, user: RequireUser,
    rule_ref: str = Form(""), note: str = Form(""), source: str = Form("manual"),
):
    add_step_detection(tactic_id, rule_ref, note, source)
    step = get_playbook_step(tactic_id)
    all_siem_rules = get_all_siem_rules()
    resp = _render("partials/tactic_detection_section.html", request, {
        "step": step, "all_siem_rules": all_siem_rules,
        "technique_rules": _build_technique_rules(step),
    })
    resp.headers["HX-Trigger"] = "stepUpdated"
    return resp


@router.delete("/api/baselines/tactics/detections/{detection_row_id}", response_class=HTMLResponse)
def api_remove_tactic_detection(
    request: Request, detection_row_id: str, step_id: str = Query(...), user: RequireUser = None,
):
    remove_step_detection(detection_row_id)
    step = get_playbook_step(step_id)
    all_siem_rules = get_all_siem_rules()
    resp = _render("partials/tactic_detection_section.html", request, {
        "step": step, "all_siem_rules": all_siem_rules,
        "technique_rules": _build_technique_rules(step),
    })
    resp.headers["HX-Trigger"] = "stepUpdated"
    return resp


@router.get("/api/baselines/tactics/{tactic_id}/affected-systems", response_class=HTMLResponse)
def api_tactic_affected_systems(request: Request, tactic_id: str, user: CurrentUser):
    return _render_tactic_affected_section(request, tactic_id)


@router.get("/api/baselines/tactics/{tactic_id}/detections", response_class=HTMLResponse)
def api_tactic_detections(request: Request, tactic_id: str, user: CurrentUser):
    step = get_playbook_step(tactic_id)
    all_siem_rules = get_all_siem_rules()
    return _render("partials/tactic_detection_section.html", request, {
        "step": step, "all_siem_rules": all_siem_rules,
        "technique_rules": _build_technique_rules(step),
    })


@router.post("/api/baselines/tactics/{tactic_id}/detections/{detection_id}/apply", response_class=HTMLResponse)
async def api_apply_step_detection(request: Request, tactic_id: str, detection_id: str, user: RequireUser):
    """Apply a tactic detection rule to all hosts in a system."""
    form = await request.form()
    system_id = (form.get("system_id") or "").strip()
    if not system_id:
        raise HTTPException(status_code=422, detail="system_id is required")
    apply_detection(detection_id, system_id=system_id)
    # Return appropriate partial based on caller context
    hx_target = request.headers.get("HX-Target", "")
    if hx_target == "baseline-coverage":
        return _render_system_baseline_coverage(request, system_id)
    return _render_tactic_affected_section(request, tactic_id)


@router.delete("/api/baselines/tactics/{tactic_id}/detections/{detection_id}/apply-system/{system_id}", response_class=HTMLResponse)
def api_remove_step_detection_for_system(request: Request, tactic_id: str, detection_id: str, system_id: str, user: RequireUser):
    """Remove a tactic detection from all hosts in a system."""
    remove_detection_for_system(detection_id, system_id)
    hx_target = request.headers.get("HX-Target", "")
    if hx_target == "baseline-coverage":
        return _render_system_baseline_coverage(request, system_id)
    return _render_tactic_affected_section(request, tactic_id)


def _render_tactic_affected_section(request: Request, tactic_id: str):
    """Helper: re-render the Applied Systems section for a tactic."""
    affected = get_step_affected_systems(tactic_id)
    blind_spots = get_blind_spots("tactic", tactic_id)
    return _render("partials/tactic_affected_systems.html", request, {
        "step_id": tactic_id, "affected_systems": affected, "blind_spots": blind_spots,
    })


def _render_system_baseline_coverage(request: Request, system_id: str):
    """Helper: re-render the baseline coverage section for a system."""
    baselines = get_system_baselines(system_id)
    playbooks = list_playbooks()
    return _render("partials/baseline_coverage.html", request, {
        "baselines": baselines, "system_id": system_id, "playbooks": playbooks,
    })


# ---------------------------------------------------------------------------
# Blind Spot CRUD
# ---------------------------------------------------------------------------

@router.post("/api/blind-spots", response_class=HTMLResponse)
def api_add_blind_spot(
    request: Request, user: RequireUser,
    entity_type: str = Form(...), entity_id: str = Form(...),
    reason: str = Form(...),
    system_id: str = Form(None), host_id: str = Form(None),
    redirect_target: str = Form(""),
    override_type: str = Form("gap"),
):
    username = user.username if user else ""
    add_blind_spot(entity_type, entity_id, reason,
                   system_id=system_id or None, host_id=host_id or None,
                   created_by=username, override_type=override_type or "gap")
    # Return the appropriate partial based on context
    if entity_type == "cve" and entity_id:
        cve = get_cve_detail(entity_id)
        if cve:
            grouped = _group_affected_by_system(cve)
            detections_map = list_cve_detections()
            applied_map = _load_applied_detections()
            cve_dets = detections_map.get(entity_id.upper(), [])
            _enrich_detections_with_applied(cve_dets, applied_map)
            cve_blind_spots = get_blind_spots("cve", entity_id)
            return _render("partials/cve_affected_hosts.html", request, {
                "cve": cve, "cve_id": entity_id,
                "grouped_systems": grouped, "detections": cve_dets,
                "blind_spots": cve_blind_spots,
            })
    if entity_type == "tactic" and entity_id:
        hx_target = request.headers.get("HX-Target", "")
        if hx_target == "baseline-coverage" and system_id:
            return _render_system_baseline_coverage(request, system_id)
        return _render_tactic_affected_section(request, entity_id)
    return HTMLResponse("")


@router.delete("/api/blind-spots/{blind_spot_id}", response_class=HTMLResponse)
def api_remove_blind_spot(
    request: Request, blind_spot_id: str, user: RequireUser,
    entity_type: str = Query(""), entity_id: str = Query(""),
):
    remove_blind_spot(blind_spot_id)
    if entity_type == "cve" and entity_id:
        cve = get_cve_detail(entity_id)
        if cve:
            grouped = _group_affected_by_system(cve)
            detections_map = list_cve_detections()
            applied_map = _load_applied_detections()
            cve_dets = detections_map.get(entity_id.upper(), [])
            _enrich_detections_with_applied(cve_dets, applied_map)
            cve_blind_spots = get_blind_spots("cve", entity_id)
            return _render("partials/cve_affected_hosts.html", request, {
                "cve": cve, "cve_id": entity_id,
                "grouped_systems": grouped, "detections": cve_dets,
                "blind_spots": cve_blind_spots,
            })
    if entity_type == "tactic" and entity_id:
        return _render_tactic_affected_section(request, entity_id)
    return HTMLResponse("")


def _group_affected_by_system(cve):
    """Group affected hosts by system for the affected hosts partial."""
    systems_map = {}
    for h in (cve.affected_hosts or []):
        if h.system_id not in systems_map:
            systems_map[h.system_id] = {
                "system_id": h.system_id,
                "system_name": h.system_name,
                "hosts": [],
            }
        systems_map[h.system_id]["hosts"].append(h)
    return sorted(systems_map.values(), key=lambda s: s["system_name"])


# ---------------------------------------------------------------------------
# Report Generation Endpoints
# ---------------------------------------------------------------------------

@router.get("/api/inventory/systems/{system_id}/report")
def api_system_report(
    request: Request, system_id: str, user: CurrentUser,
    mode: str = Query("executive", pattern="^(executive|technical)$"),
    format: str = Query("pdf", pattern="^(pdf|markdown)$"),
    classification: str = Query("Official"),
):
    """Generate a System report — CISO Executive Summary or Technical Deep Dive."""
    import os
    from datetime import datetime
    from app.services.report_generator import CLASSIFICATION_OPTIONS

    if classification not in CLASSIFICATION_OPTIONS:
        classification = CLASSIFICATION_OPTIONS[0]

    report_data = build_system_report_data(system_id)
    if not report_data:
        raise HTTPException(status_code=404, detail="System not found")

    report_data["mode"] = mode
    report_data["classification"] = classification

    safe_name = report_data["system"]["name"].replace(" ", "-").replace("/", "-")[:30]
    level_tag = "Technical" if mode == "technical" else "Executive"
    date_str = datetime.utcnow().strftime("%Y%m%d")

    if format == "markdown":
        md = _generate_system_markdown(report_data, classification)
        filename = f"TIDE_SystemReport_{level_tag}_{safe_name}_{date_str}.md"
        content = md.encode("utf-8")
        return Response(
            content=content,
            media_type="text/markdown; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(content)),
            },
        )

    # PDF via WeasyPrint
    templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
    try:
        from weasyprint import HTML as WeasyprintHTML
        from jinja2 import Environment, FileSystemLoader
        env = Environment(loader=FileSystemLoader(templates_dir), autoescape=True)
        template = env.get_template("report/system_report.html")
        html_str = template.render(report=report_data)
        pdf_bytes = WeasyprintHTML(string=html_str).write_pdf()
    except ImportError:
        logger.error("WeasyPrint is not installed in this environment")
        raise HTTPException(status_code=500, detail="PDF generation requires WeasyPrint. Check server installation.")
    except Exception as exc:
        logger.exception(f"PDF generation failed: {exc}")
        raise HTTPException(status_code=500, detail="PDF generation failed. Check server logs.")

    filename = f"TIDE_SystemReport_{level_tag}_{safe_name}_{date_str}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )


@router.get("/api/inventory/cve/{cve_id}/report")
def api_cve_report(
    request: Request, cve_id: str, user: CurrentUser,
    format: str = Query("pdf", pattern="^(pdf|markdown)$"),
    classification: str = Query("Official"),
    search: str = Query(""),
):
    """Generate a CVE Vulnerability Impact Audit Report."""
    import os
    from datetime import datetime
    from app.services.report_generator import CLASSIFICATION_OPTIONS

    if classification not in CLASSIFICATION_OPTIONS:
        classification = CLASSIFICATION_OPTIONS[0]

    report_data = build_cve_report_data(cve_id, search_filter=search)
    if not report_data:
        raise HTTPException(status_code=404, detail="CVE not found")

    report_data["classification"] = classification

    safe_cve = cve_id.replace("/", "-")
    date_str = datetime.utcnow().strftime("%Y%m%d")

    if format == "markdown":
        md = _generate_cve_markdown(report_data, classification)
        filename = f"TIDE_CVE_Audit_{safe_cve}_{date_str}.md"
        content = md.encode("utf-8")
        return Response(
            content=content,
            media_type="text/markdown; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(content)),
            },
        )

    # PDF via WeasyPrint
    templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
    try:
        from weasyprint import HTML as WeasyprintHTML
        from jinja2 import Environment, FileSystemLoader
        env = Environment(loader=FileSystemLoader(templates_dir), autoescape=True)
        template = env.get_template("report/cve_report.html")
        html_str = template.render(report=report_data)
        pdf_bytes = WeasyprintHTML(string=html_str).write_pdf()
    except ImportError:
        logger.error("WeasyPrint is not installed in this environment")
        raise HTTPException(status_code=500, detail="PDF generation requires WeasyPrint. Check server installation.")
    except Exception as exc:
        logger.exception(f"PDF generation failed: {exc}")
        raise HTTPException(status_code=500, detail="PDF generation failed. Check server logs.")

    filename = f"TIDE_CVE_Audit_{safe_cve}_{date_str}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )


# ---------------------------------------------------------------------------
# Markdown generation helpers
# ---------------------------------------------------------------------------

def _generate_system_markdown(data: dict, classification: str) -> str:
    """Generate a Markdown system report."""
    mode = data.get("mode", "executive")
    sys = data["system"]
    lines = [
        f"<!-- {classification} -->",
        "",
        f"# {sys['name']} — {'Technical Deep Dive' if mode == 'technical' else 'CISO Executive Summary'}",
        "",
        f"**Classification:** {classification}",
        f"**Generated:** {data['generated_at']}",
        f"**Audience:** {'Technical / Engineer' if mode == 'technical' else 'Executive / CISO'}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total Devices | {data['total_hosts']} |",
        f"| Unique CVEs | {data['total_cves']} |",
        f"| At Risk (Red) | {data['red_hosts']} |",
        f"| Monitored (Amber) | {data['amber_hosts']} |",
        f"| Blind Spots (Grey) | {data.get('grey_hosts', 0)} |",
        f"| Clean (Green) | {data['green_hosts']} |",
        f"| Coverage Ratio | {data['coverage_ratio']}% |",
        "",
    ]

    # Top 5 CVEs
    if data.get("top5_cves"):
        lines += [
            "## Top 5 Critical CVEs",
            "",
            "| CVE ID | Vulnerability | At Risk | Monitored | Blind Spots | Ransomware |",
            "|--------|---------------|---------|-----------|-------------|------------|",
        ]
        for cve in data["top5_cves"]:
            rw = "Yes" if cve.get("known_ransomware") else "No"
            lines.append(
                f"| {cve['cve_id']} | {cve['vulnerability_name'][:60]} | "
                f"{len(cve.get('hosts_red', []))} | {len(cve.get('hosts_amber', []))} | "
                f"{len(cve.get('hosts_grey', []))} | {rw} |"
            )
        lines.append("")

    # Device Status
    lines += [
        "## Device Status Summary",
        "",
        "| Device | IP | OS | Status | CVEs | At Risk | Monitored |",
        "|--------|----|----|--------|------|---------|-----------|",
    ]
    for h in data.get("host_rows", []):
        status = {"green": "Clean", "amber": "Monitored", "red": "At Risk", "grey": "Blind Spot"}.get(h["rag"], h["rag"])
        lines.append(
            f"| {h['name']} | {h['ip']} | {h['os'][:30]} | {status} | "
            f"{h['cve_count']} | {h['red_count']} | {h['amber_count']} |"
        )
    lines.append("")

    # Baseline Coverage
    baselines = data.get("baselines", [])
    if baselines:
        lines += [
            "## Baseline Coverage",
            "",
            "| Playbook | Steps | Covered | Gaps | Coverage |",
            "|----------|-------|---------|------|----------|",
        ]
        for bl in baselines:
            gaps = bl["total_steps"] - bl["covered_steps"]
            lines.append(
                f"| {bl['playbook_name']} | {bl['total_steps']} | "
                f"{bl['covered_steps']} | {gaps} | {bl['coverage_pct']}% |"
            )
        lines.append("")

    # Technical detail
    if mode == "technical":
        # Baseline gap analysis
        if baselines:
            lines += ["## Baseline Gap Analysis", ""]
            for bl in baselines:
                lines.append(f"### {bl['playbook_name']}")
                if bl.get("playbook_description"):
                    lines.append(f"_{bl['playbook_description']}_")
                lines.append("")
                lines.append("| Step | Title | Technique | Required Rule | Status |")
                lines.append("|------|-------|-----------|---------------|--------|")
                for step in bl.get("tactics", []):
                    if step["status"] == "grey":
                        status = "Blind Spot"
                    elif step["status"] == "amber":
                        status = "Covered"
                    else:
                        status = "**Missing**"
                    det_display = ", ".join(d["rule_ref"] for d in step.get("detections", []) if d.get("rule_ref")) or "—"
                    lines.append(
                        f"| {step['step_number']} | {step['title']} | "
                        f"`{step['technique_id'] or '—'}` | `{det_display}` | {status} |"
                    )
                lines.append("")

        if data.get("all_cves"):
            lines += ["## CVE Breakdown (Technical Detail)", ""]
            for cve in data["all_cves"]:
                lines.append(f"### {cve['cve_id']}")
                lines.append(f"_{cve.get('vulnerability_name', '')}_")
                lines.append("")
                if cve.get("techniques"):
                    lines.append("**MITRE Techniques:** " + ", ".join(
                        f"`{t['id']}`" for t in cve["techniques"]
                    ))
                    lines.append("")
                lines.append("| Host | IP | Status | Active Rules |")
                lines.append("|------|----|--------|-------------|")
                for h in cve.get("hosts_red", []):
                    lines.append(f"| {h['name']} | {h['ip']} | At Risk | — |")
                for h in cve.get("hosts_amber", []):
                    rules = ", ".join(h.get("rule_names", [])) or "—"
                    lines.append(f"| {h['name']} | {h['ip']} | Monitored | {rules} |")
                for h in cve.get("hosts_grey", []):
                    reason = h.get("blind_spot_reason", "")[:40] or "—"
                    lines.append(f"| {h['name']} | {h['ip']} | Blind Spot | {reason} |")
                lines.append("")

    lines += [
        "---",
        f"*{classification} — Report generated by TIDE — Threat Intelligence Detection Engineering*",
    ]
    return "\n".join(lines)


def _generate_cve_markdown(data: dict, classification: str) -> str:
    """Generate a Markdown CVE audit report."""
    lines = [
        f"<!-- {classification} -->",
        "",
        f"# {data['cve_id']} — CVE Vulnerability Impact Audit",
        "",
        f"**Classification:** {classification}",
        f"**Generated:** {data['generated_at']}",
        f"**Vulnerability:** {data.get('vulnerability_name', '')}",
        "",
        "---",
        "",
        "## Impact Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Affected Systems | {data['total_systems']} |",
        f"| Affected Hosts | {data['total_hosts']} |",
        f"| At Risk Hosts | {data['red_count']} |",
        f"| Monitored Hosts | {data['amber_count']} |",
        f"| Blind Spot Hosts | {data.get('grey_count', 0)} |",
        f"| Detection Rules | {len(data.get('detections', []))} |",
        f"| MITRE Techniques | {len(data.get('techniques', []))} |",
        "",
    ]

    # Info
    lines += [
        "## CVE Details",
        "",
        f"- **Vendor / Product:** {data.get('vendor_project', '')} / {data.get('product', '')}",
        f"- **Date Added:** {data.get('date_added', '')}",
        f"- **Due Date:** {data.get('due_date', '')}",
        f"- **Ransomware:** {'Yes' if data.get('known_ransomware') else 'No'}",
    ]
    if data.get("short_description"):
        lines.append(f"- **Description:** {data['short_description']}")
    if data.get("notes"):
        lines.append(f"- **Required Action:** {data['notes']}")
    lines.append("")

    # MITRE Techniques
    if data.get("techniques"):
        lines += [
            "## MITRE ATT&CK Techniques",
            "",
            "| Technique | Name | Detection | Rule Count |",
            "|-----------|------|-----------|------------|",
        ]
        for t in data["techniques"]:
            status = "Covered" if t.get("has_detection") else "Gap"
            lines.append(f"| `{t['id']}` | {t.get('name', '—')} | {status} | {t.get('rule_count', 0)} |")
        lines.append("")

    # Detection Rules
    if data.get("detections"):
        lines += [
            "## Applied Detection Rules",
            "",
            "| Rule / Reference | Note | Source |",
            "|-----------------|------|--------|",
        ]
        for d in data["detections"]:
            lines.append(f"| {d.get('rule_ref', '—')} | {d.get('note', '—')} | {d.get('source', '—')} |")
        lines.append("")

    # Impact Matrix
    if data.get("grouped_systems"):
        lines += ["## Impact Matrix — Affected Systems & Hosts", ""]
        for sys in data["grouped_systems"]:
            lines.append(f"### {sys['system_name']}")
            lines.append("")
            lines.append("| Hostname | IP | OS | Status | Active Rules |")
            lines.append("|----------|----|----|--------|-------------|")
            for h in sys["hosts"]:
                if h.get("status") == "grey":
                    status = "Blind Spot"
                elif h.get("status") == "red":
                    status = "At Risk"
                else:
                    status = "Monitored"
                rules = ", ".join(h.get("rule_names", [])) or "—"
                lines.append(f"| {h['name']} | {h['ip']} | {h.get('os', '')[:25]} | {status} | {rules} |")
            lines.append("")

    lines += [
        "---",
        f"*{classification} — Report generated by TIDE — Threat Intelligence Detection Engineering*",
    ]
    return "\n".join(lines)
