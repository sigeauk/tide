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
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from app.api.deps import ActiveClient, CurrentUser, RequireUser
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
    build_system_report_data, build_cve_report_data, build_baseline_report_data,
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
    normalize_technique_id,
    # Blind Spots
    add_blind_spot, remove_blind_spot, get_blind_spots,
    # Baseline Snapshots
    create_baseline_snapshot, create_all_baseline_snapshots,
    get_baseline_snapshots, delete_baseline_snapshot,
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
        "brand_hue": settings.brand_hue,
        "cache_bust": settings.tide_version,
        "settings": settings,
    }
    base.update(ctx)

    # Inject active client info for client switcher component
    if "active_client" not in base:
        try:
            from app.services.database import get_database_service
            _db = get_database_service()
            _user = base.get("user")

            _cid = request.cookies.get("active_client_id")
            if not _cid and _user:
                with _db.get_connection() as conn:
                    row = conn.execute(
                        "SELECT client_id FROM user_clients WHERE user_id = ? AND is_default = true LIMIT 1",
                        [_user.id],
                    ).fetchone()
                    if row:
                        _cid = row[0]
            if not _cid:
                with _db.get_connection() as conn:
                    row = conn.execute(
                        "SELECT id FROM clients WHERE is_default = true LIMIT 1",
                    ).fetchone()
                    if row:
                        _cid = row[0]

            base["active_client"] = _db.get_client(_cid) if _cid else None

            if _user and hasattr(_user, "is_admin") and _user.is_admin():
                base["user_clients"] = _db.list_clients()
            elif _user:
                _ids = _db.get_user_client_ids(_user.id)
                base["user_clients"] = [c for c in (_db.get_client(i) for i in _ids) if c]
            else:
                base["user_clients"] = []
        except Exception:
            base["active_client"] = None
            base["user_clients"] = []

    return _templates(request).TemplateResponse(request, name, base)


def _get_conn_inline():
    from app.services.database import get_database_service
    return get_database_service().get_connection()


def _gone_redirect(request: Request, fallback_url: str = "/") -> Response:
    """Return a redirect instead of a hard 404 when a resource is not found
    in the current tenant's DB (e.g. after a client switch).
    Handles both HTMX partial requests and full-page loads."""
    if request.headers.get("HX-Request"):
        return HTMLResponse(content="", headers={"HX-Redirect": fallback_url})
    return RedirectResponse(url=fallback_url, status_code=302)


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------

@router.get("/systems", response_class=HTMLResponse)
def page_systems(request: Request, user: CurrentUser, client_id: ActiveClient):
    summaries = get_system_summaries(client_id=client_id)
    systems = [s.system for s in summaries]  # for Nessus modal dropdown
    return _render("pages/systems.html", request, {
        "active_page": "systems", "summaries": summaries, "systems": systems, "user": user,
        "classifications": list_classifications(client_id=client_id), "clf_colors": _clf_color_map(client_id=client_id),
    })


@router.get("/systems/{system_id}", response_class=HTMLResponse)
def page_system_detail(request: Request, system_id: str, user: CurrentUser, client_id: ActiveClient):
    from app.services.report_generator import CLASSIFICATION_OPTIONS
    system = get_system(system_id, client_id=client_id)
    if not system:
        return _gone_redirect(request, "/systems")
    host_summaries = get_host_summaries(system_id, client_id=client_id)
    baselines = get_system_baselines(system_id, client_id=client_id)
    all_baselines = list_playbooks(client_id=client_id)
    return _render("pages/system_detail.html", request, {
        "active_page": "systems", "system": system,
        "host_summaries": host_summaries, "user": user,
        "classifications": list_classifications(client_id=client_id), "clf_colors": _clf_color_map(client_id=client_id),
        "classification_options": CLASSIFICATION_OPTIONS,
        "baselines": baselines, "playbooks": all_baselines,
    })


@router.get("/hosts/{host_id}", response_class=HTMLResponse)
def page_host_detail(request: Request, host_id: str, user: CurrentUser, client_id: ActiveClient):
    host = get_host(host_id, client_id=client_id)
    if not host:
        return _gone_redirect(request, "/systems")
    system = get_system(host.system_id, client_id=client_id)
    software = list_host_software(host_id, client_id=client_id)
    vulns = get_host_vulnerabilities(host_id, client_id=client_id)
    clf_color = get_classification_color(system.classification, client_id=client_id) if system and system.classification else None
    return _render("pages/host_detail.html", request, {
        "active_page": "systems", "host": host, "system": system,
        "software": software, "vulns": vulns, "user": user,
        "clf_color": clf_color,
    })


@router.get("/cve-overview", response_class=HTMLResponse)
def page_cve_overview(request: Request, user: CurrentUser, client_id: ActiveClient):
    cves = get_all_cve_overview(client_id=client_id)
    stats = get_cve_overview_stats(cves=cves, client_id=client_id)
    return _render("pages/cve_overview.html", request, {
        "active_page": "cve_overview", "cves": cves,
        "matched_count": stats.matched_count,
        "stats": stats, "user": user,
    })


@router.get("/cve/{cve_id}", response_class=HTMLResponse)
def page_cve_detail(request: Request, cve_id: str, user: CurrentUser, client_id: ActiveClient):
    from app.inventory_engine import get_cve_techniques
    from app.services.report_generator import CLASSIFICATION_OPTIONS
    cve = get_cve_detail(cve_id, client_id=client_id)
    if not cve:
        return _gone_redirect(request, "/cve-overview")
    technique_rules = get_rules_for_cve_techniques(cve_id, client_id=client_id)
    techniques = get_cve_techniques(cve_id, client_id=client_id)
    # Group affected hosts by system for the template
    systems_map: dict = {}
    for h in cve.affected_hosts:
        if h.system_id not in systems_map:
            systems_map[h.system_id] = {"system_id": h.system_id, "system_name": h.system_name, "hosts": []}
        systems_map[h.system_id]["hosts"].append(h)
    grouped_systems = sorted(systems_map.values(), key=lambda s: s["system_name"])
    # Get all systems for "apply to system" dropdown
    all_systems = list_systems(client_id=client_id)
    cve_blind_spots = get_blind_spots("cve", cve_id, client_id=client_id)
    return _render("pages/cve_detail.html", request, {
        "active_page": "cve_overview", "cve": cve, "user": user,
        "cve_id": cve.cve_id,
        "techniques": techniques,
        "detections": cve.detections,
        "technique_rules": technique_rules,
        "all_siem_rules": get_all_siem_rules(client_id=client_id),
        "grouped_systems": grouped_systems,
        "all_systems": all_systems,
        "classification_options": CLASSIFICATION_OPTIONS,
        "blind_spots": cve_blind_spots,
    })


# ---------------------------------------------------------------------------
# CVE MITRE Technique Override API
# ---------------------------------------------------------------------------

@router.post("/api/inventory/cve/{cve_id}/techniques", response_class=HTMLResponse)
async def api_add_cve_technique(request: Request, cve_id: str, user: RequireUser, client_id: ActiveClient):
    """Add a manual MITRE technique override for a CVE. Re-renders the MITRE section."""
    from app.inventory_engine import get_cve_techniques
    form = await request.form()
    technique_id = (form.get("technique_id") or "").strip().upper()
    if not technique_id:
        raise HTTPException(status_code=422, detail="technique_id is required")
    add_cve_technique_override(cve_id, technique_id, client_id=client_id)
    cve = get_cve_detail(cve_id, client_id=client_id)
    technique_rules = get_rules_for_cve_techniques(cve_id, client_id=client_id)
    techniques = get_cve_techniques(cve_id, client_id=client_id)
    return _render("partials/cve_mitre_section.html", request, {
        "cve": cve, "cve_id": cve_id,
        "techniques": techniques,
        "technique_rules": technique_rules, "user": user,
    })


@router.delete("/api/inventory/cve/{cve_id}/techniques/{technique_id}", response_class=HTMLResponse)
async def api_remove_cve_technique(request: Request, cve_id: str, technique_id: str, user: RequireUser, client_id: ActiveClient):
    """Remove a manual MITRE technique override for a CVE. Re-renders the MITRE section."""
    from app.inventory_engine import get_cve_techniques
    remove_cve_technique_override(cve_id, technique_id, client_id=client_id)
    cve = get_cve_detail(cve_id, client_id=client_id)
    technique_rules = get_rules_for_cve_techniques(cve_id, client_id=client_id)
    techniques = get_cve_techniques(cve_id, client_id=client_id)
    return _render("partials/cve_mitre_section.html", request, {
        "cve": cve, "cve_id": cve_id,
        "techniques": techniques,
        "technique_rules": technique_rules, "user": user,
    })


# ---------------------------------------------------------------------------
# Classification API
# ---------------------------------------------------------------------------

def _clf_color_map(client_id: str = None) -> dict:
    """Return {name: color} dict for all classifications."""
    return {c.name: c.color for c in list_classifications(client_id=client_id)}


@router.get("/api/inventory/classifications", response_class=HTMLResponse)
def api_list_classifications(request: Request, user: CurrentUser, client_id: ActiveClient):
    return _render("partials/classification_list.html", request, {
        "classifications": list_classifications(client_id=client_id), "user": user,
    })


@router.post("/api/inventory/classifications", response_class=HTMLResponse)
async def api_add_classification(request: Request, user: RequireUser, client_id: ActiveClient):
    form = await request.form()
    name = (form.get("name") or "").strip()
    color = (form.get("color") or "#6b7280").strip()
    if not name:
        raise HTTPException(status_code=422, detail="Name is required")
    try:
        add_classification(name, color, client_id=client_id)
    except Exception:
        raise HTTPException(status_code=409, detail="Classification already exists")
    return _render("partials/classification_list.html", request, {
        "classifications": list_classifications(client_id=client_id), "user": user,
    })


@router.delete("/api/inventory/classifications/{cls_id}", response_class=HTMLResponse)
def api_delete_classification(request: Request, cls_id: str, user: RequireUser, client_id: ActiveClient):
    ok = delete_classification(cls_id, client_id=client_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Classification not found")
    return _render("partials/classification_list.html", request, {
        "classifications": list_classifications(client_id=client_id), "user": user,
    })


# ---------------------------------------------------------------------------
# System API
# ---------------------------------------------------------------------------

@router.post("/api/inventory/systems", response_class=HTMLResponse)
async def api_create_system(request: Request, user: RequireUser, client_id: ActiveClient):
    form = await request.form()
    data = SystemCreate(
        name=(form.get("name") or "").strip(),
        description=form.get("description") or None,
        classification=form.get("classification") or None,
    )
    if not data.name:
        raise HTTPException(status_code=422, detail="Name is required")
    system = add_system(data, client_id=client_id)
    summaries = get_system_summaries(client_id=client_id)
    systems = [s.system for s in summaries]
    return _render("partials/system_cards.html", request, {
        "summaries": summaries, "systems": systems, "user": user,
        "clf_colors": _clf_color_map(client_id=client_id),
        "toast": f"System '{system.name}' created.",
    })


@router.put("/api/inventory/systems/{system_id}", response_class=HTMLResponse)
async def api_update_system(request: Request, system_id: str, user: RequireUser, client_id: ActiveClient):
    form = await request.form()
    data = SystemUpdate(
        name=form.get("name") or None,
        description=form.get("description") or None,
        classification=form.get("classification") or None,
    )
    system = edit_system(system_id, data, client_id=client_id)
    if not system:
        raise HTTPException(status_code=404, detail="System not found")
    summaries = get_system_summaries(client_id=client_id)
    systems = [s.system for s in summaries]
    return _render("partials/system_cards.html", request, {
        "summaries": summaries, "systems": systems, "user": user,
        "clf_colors": _clf_color_map(client_id=client_id),
    })


@router.delete("/api/inventory/systems/{system_id}", response_class=HTMLResponse)
def api_delete_system(request: Request, system_id: str, user: RequireUser, client_id: ActiveClient):
    ok = delete_system(system_id, client_id=client_id)
    if not ok:
        raise HTTPException(status_code=404, detail="System not found")
    summaries = get_system_summaries(client_id=client_id)
    systems = [s.system for s in summaries]
    return _render("partials/system_cards.html", request, {
        "summaries": summaries, "systems": systems, "user": user,
        "clf_colors": _clf_color_map(client_id=client_id),
        "toast": "System deleted.",
    })


# ---------------------------------------------------------------------------
# Device API
# ---------------------------------------------------------------------------

@router.post("/api/inventory/systems/{system_id}/hosts", response_class=HTMLResponse)
async def api_create_host(request: Request, system_id: str, user: RequireUser, client_id: ActiveClient):
    if not get_system(system_id, client_id=client_id):
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
    add_host(system_id, data, client_id=client_id)
    host_summaries = get_host_summaries(system_id, client_id=client_id)
    sys = get_system(system_id, client_id=client_id)
    return _render("partials/host_list.html", request, {
        "system_id": system_id, "host_summaries": host_summaries, "user": user,
        "sys_classification": sys.classification if sys else None,
        "sys_clf_color": get_classification_color(sys.classification, client_id=client_id) if sys and sys.classification else None,
    })


@router.put("/api/inventory/hosts/{host_id}", response_class=HTMLResponse)
async def api_update_host(request: Request, host_id: str, user: RequireUser, client_id: ActiveClient):
    """Edit device name, IP, OS etc.  Returns the device detail header partial."""
    form = await request.form()
    data = HostUpdate(
        name=(form.get("name") or "").strip() or None,
        ip_address=form.get("ip_address") or None,
        os=form.get("os") or None,
        hardware_vendor=form.get("hardware_vendor") or None,
        model=form.get("model") or None,
    )
    host = edit_host(host_id, data, client_id=client_id)
    if not host:
        raise HTTPException(status_code=404, detail="Device not found")
    system = get_system(host.system_id, client_id=client_id)
    software = list_host_software(host_id, client_id=client_id)
    vulns = get_host_vulnerabilities(host_id, client_id=client_id)
    clf_color = get_classification_color(system.classification, client_id=client_id) if system and system.classification else None
    return _render("partials/host_header.html", request, {
        "host": host, "system": system, "software": software, "vulns": vulns, "user": user,
        "clf_color": clf_color,
    })


@router.delete("/api/inventory/hosts/{host_id}", response_class=HTMLResponse)
def api_delete_host(
    request: Request, host_id: str, user: RequireUser, client_id: ActiveClient,
    system_id: str = Query(...),
):
    ok = delete_host(host_id, client_id=client_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Device not found")
    host_summaries = get_host_summaries(system_id, client_id=client_id)
    sys = get_system(system_id, client_id=client_id)
    return _render("partials/host_list.html", request, {
        "system_id": system_id, "host_summaries": host_summaries, "user": user,
        "sys_classification": sys.classification if sys else None,
        "sys_clf_color": get_classification_color(sys.classification, client_id=client_id) if sys and sys.classification else None,
    })


# ---------------------------------------------------------------------------
# Nessus Upload (per-system endpoint)
# ---------------------------------------------------------------------------

@router.post("/api/inventory/systems/{system_id}/nessus-upload", response_class=HTMLResponse)
async def api_nessus_upload_by_system(
    request: Request, system_id: str, user: RequireUser, client_id: ActiveClient,
    file: UploadFile = File(...),
):
    if not get_system(system_id, client_id=client_id):
        raise HTTPException(status_code=404, detail="System not found")
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    filename = file.filename or ""
    if not (filename.endswith(".nessus") or filename.endswith(".xml")):
        raise HTTPException(status_code=422, detail="File must be .nessus or .xml")
    try:
        hosts_created, records_inserted, warnings = parse_nessus_xml(content, system_id, client_id=client_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    host_summaries = get_host_summaries(system_id, client_id=client_id)
    sys_obj = get_system(system_id, client_id=client_id)
    return _render("partials/host_list.html", request, {
        "system_id": system_id, "host_summaries": host_summaries, "user": user,
        "nessus_hosts": hosts_created, "nessus_records": records_inserted,
        "nessus_warnings": warnings,
        "sys_classification": sys_obj.classification if sys_obj else None,
        "sys_clf_color": get_classification_color(sys_obj.classification, client_id=client_id) if sys_obj and sys_obj.classification else None,
    })


@router.post("/api/inventory/nessus-upload", response_class=HTMLResponse)
async def api_nessus_upload_global(
    request: Request, user: RequireUser, client_id: ActiveClient,
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
        new_sys = add_system(SystemCreate(name=env_name), client_id=client_id)
        system = new_sys
    else:
        system = get_system(system_id, client_id=client_id)
        if not system:
            raise HTTPException(status_code=404, detail="System not found")
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    filename = file.filename or ""
    if not (filename.endswith(".nessus") or filename.endswith(".xml")):
        raise HTTPException(status_code=422, detail="File must be .nessus or .xml")
    try:
        hosts_created, records_inserted, warnings = parse_nessus_xml(content, system.id, client_id=client_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    summaries = get_system_summaries(client_id=client_id)
    systems = [s.system for s in summaries]
    return _render("partials/system_cards.html", request, {
        "summaries": summaries, "systems": systems, "user": user,
        "clf_colors": _clf_color_map(client_id=client_id),
        "toast": (f"Nessus import complete: {hosts_created} device(s), "
                  f"{records_inserted} package record(s) added to {system.name}."),
    })


# ---------------------------------------------------------------------------
# Device Packages API
# ---------------------------------------------------------------------------

@router.post("/api/inventory/hosts/{host_id}/software", response_class=HTMLResponse)
async def api_add_host_software(request: Request, host_id: str, user: RequireUser, client_id: ActiveClient):
    host = get_host(host_id, client_id=client_id)
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
    add_host_software(host_id, host.system_id, data, client_id=client_id)
    software = list_host_software(host_id, client_id=client_id)
    vulns = get_host_vulnerabilities(host_id, client_id=client_id)
    return _render("partials/host_software.html", request, {
        "host": host, "software": software, "vulns": vulns, "user": user,
    })


@router.put("/api/inventory/software/{software_id}", response_class=HTMLResponse)
async def api_update_software(
    request: Request, software_id: str, user: RequireUser, client_id: ActiveClient,
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
    sw = edit_software(software_id, data, client_id=client_id)
    if not sw:
        raise HTTPException(status_code=404, detail="Software not found")
    h_id = host_id or sw.host_id
    if h_id:
        host = get_host(h_id, client_id=client_id)
        software = list_host_software(h_id, client_id=client_id)
        vulns = get_host_vulnerabilities(h_id, client_id=client_id)
        return _render("partials/host_software.html", request, {
            "host": host, "software": software, "vulns": vulns, "user": user,
        })
    return _render("partials/host_software.html", request, {"software": [], "user": user})


@router.delete("/api/inventory/software/{software_id}", response_class=HTMLResponse)
def api_delete_software(
    request: Request, software_id: str, user: RequireUser, client_id: ActiveClient,
    host_id: str = Query(None), system_id: str = Query(None),
):
    delete_software(software_id, client_id=client_id)
    if host_id:
        host = get_host(host_id, client_id=client_id)
        software = list_host_software(host_id, client_id=client_id)
        vulns = get_host_vulnerabilities(host_id, client_id=client_id)
        return _render("partials/host_software.html", request, {
            "host": host, "software": software, "vulns": vulns, "user": user,
        })
    software = list_software(system_id, client_id=client_id) if system_id else []
    vulns = get_system_vulnerabilities(system_id, client_id=client_id) if system_id else []
    return _render("partials/software_list.html", request, {
        "system_id": system_id, "software": software, "vulns": vulns, "user": user,
    })


# ---------------------------------------------------------------------------
# CVE Partials
# ---------------------------------------------------------------------------

@router.get("/api/inventory/hosts/{host_id}/cve-matches", response_class=HTMLResponse)
def api_host_cve_matches(request: Request, host_id: str, user: CurrentUser, client_id: ActiveClient):
    host = get_host(host_id, client_id=client_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    vulns = get_host_vulnerabilities(host_id, client_id=client_id)
    return _render("partials/host_cve_matches.html", request, {
        "host": host, "vulns": vulns, "user": user,
    })


@router.get("/api/inventory/cve-overview-partial", response_class=HTMLResponse)
def api_cve_overview_partial(request: Request, user: CurrentUser, client_id: ActiveClient):
    from app.inventory_engine import list_systems
    cves = get_all_cve_overview(client_id=client_id)
    matched_count = sum(1 for c in cves if c.affected_hosts)
    systems = list_systems(client_id=client_id)
    return _render("partials/cve_overview_table.html", request, {
        "cves": cves, "matched_count": matched_count, "user": user,
        "systems": systems,
    })


# ---------------------------------------------------------------------------
# CVE Detection (add / remove detection entries)
# ---------------------------------------------------------------------------

@router.post("/api/inventory/cve/{cve_id}/detect", response_class=HTMLResponse)
async def api_add_detection(request: Request, cve_id: str, user: RequireUser, client_id: ActiveClient):
    """Add a new detection entry for a CVE."""
    form = await request.form()
    rule_ref = (form.get("rule_ref") or "").strip() or None
    note = (form.get("note") or "").strip() or None
    source = (form.get("source") or "manual").strip()
    if not rule_ref and not note:
        raise HTTPException(status_code=422, detail="rule_ref or note is required")
    add_cve_detection(cve_id, rule_ref=rule_ref, note=note, source=source, client_id=client_id)
    detections = get_cve_detections(cve_id, client_id=client_id)
    technique_rules = get_rules_for_cve_techniques(cve_id, client_id=client_id)
    return _render("partials/cve_detection_badge.html", request, {
        "cve_id": cve_id.upper(),
        "detections": detections,
        "technique_rules": technique_rules,
        "all_siem_rules": get_all_siem_rules(client_id=client_id),
        "user": user,
    })


@router.delete("/api/inventory/cve/{cve_id}/detect/{detection_id}", response_class=HTMLResponse)
async def api_remove_detection(request: Request, cve_id: str, detection_id: str, user: RequireUser, client_id: ActiveClient):
    """Remove a single detection entry by its ID."""
    remove_cve_detection(detection_id, client_id=client_id)
    detections = get_cve_detections(cve_id, client_id=client_id)
    technique_rules = get_rules_for_cve_techniques(cve_id, client_id=client_id)
    return _render("partials/cve_detection_badge.html", request, {
        "cve_id": cve_id.upper(),
        "detections": detections,
        "technique_rules": technique_rules,
        "all_siem_rules": get_all_siem_rules(client_id=client_id),
        "user": user,
    })


# ---------------------------------------------------------------------------
# CVE Detection Application (Tier 3: apply / unapply to systems or hosts)
# ---------------------------------------------------------------------------

@router.post("/api/inventory/cve/{cve_id}/detect/{detection_id}/apply", response_class=HTMLResponse)
async def api_apply_detection(request: Request, cve_id: str, detection_id: str, user: RequireUser, client_id: ActiveClient):
    """Apply a detection rule to a system or host. Re-renders the affected hosts section."""
    form = await request.form()
    system_id = (form.get("system_id") or "").strip() or None
    host_id = (form.get("host_id") or "").strip() or None
    if not system_id and not host_id:
        raise HTTPException(status_code=422, detail="system_id or host_id is required")
    apply_detection(detection_id, system_id=system_id, host_id=host_id, client_id=client_id)
    return _render_cve_affected_section(request, cve_id, user, client_id=client_id)


@router.delete("/api/inventory/applied-detection/{applied_id}", response_class=HTMLResponse)
async def api_remove_applied_detection(request: Request, applied_id: str, user: RequireUser, client_id: ActiveClient,
                                       cve_id: str = Query(...)):
    """Remove an applied detection. Re-renders the affected hosts section."""
    remove_applied_detection(applied_id, client_id=client_id)
    return _render_cve_affected_section(request, cve_id, user, client_id=client_id)


@router.delete("/api/inventory/cve/{cve_id}/detect/{detection_id}/apply-system/{system_id}", response_class=HTMLResponse)
async def api_remove_detection_for_system(request: Request, cve_id: str, detection_id: str, system_id: str, user: RequireUser, client_id: ActiveClient):
    """Remove an applied detection from all hosts in a system."""
    remove_detection_for_system(detection_id, system_id, client_id=client_id)
    return _render_cve_affected_section(request, cve_id, user, client_id=client_id)


def _render_cve_affected_section(request: Request, cve_id: str, user, client_id: str = None):
    """Helper: re-render the affected devices section for a CVE."""
    cve = get_cve_detail(cve_id, client_id=client_id)
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
def api_inventory_stats(request: Request, user: CurrentUser, client_id: ActiveClient):
    stats = get_inventory_stats(client_id=client_id)
    return _render("partials/inventory_metrics.html", request, {
        "stats": stats, "user": user,
    })


@router.get("/api/inventory/cve-stats-partial", response_class=HTMLResponse)
def api_cve_stats(request: Request, user: CurrentUser, client_id: ActiveClient):
    stats = get_cve_overview_stats(client_id=client_id)
    return _render("partials/cve_metrics.html", request, {
        "stats": stats, "user": user,
    })


# ---------------------------------------------------------------------------
# CISA KEV Feed Ingest
# ---------------------------------------------------------------------------

@router.delete("/api/inventory/feed/cisa", response_class=HTMLResponse)
async def api_reset_kev_override(request: Request, user: RequireUser, client_id: ActiveClient):
    """Delete the KEV override file so the system/dockerfile KEV is used instead."""
    from app.config import get_settings
    import os
    settings = get_settings()
    path = settings.cisa_kev_override_path
    removed = False
    if path and os.path.exists(path):
        os.remove(path)
        removed = True
    cves = get_all_cve_overview(client_id=client_id)
    stats = get_cve_overview_stats(cves=cves, client_id=client_id)
    return _render("partials/cve_overview_table.html", request, {
        "cves": cves, "matched_count": stats.matched_count,
        "stats": stats, "user": user,
        "toast": "KEV override removed — using system catalogue." if removed else "No override file found.",
    })

@router.post("/api/inventory/feed/cisa", response_class=HTMLResponse)
async def api_ingest_cisa(
    request: Request, user: RequireUser, client_id: ActiveClient,
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
    cves = get_all_cve_overview(client_id=client_id)
    stats = get_cve_overview_stats(cves=cves, client_id=client_id)
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
    request: Request, user: RequireUser, client_id: ActiveClient,
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
def page_baselines(request: Request, user: CurrentUser, client_id: ActiveClient):
    baselines = get_baselines_overview(client_id=client_id)
    return _render("pages/baselines.html", request, {
        "active_page": "baselines", "baselines": baselines, "user": user,
    })


@router.get("/baselines/{baseline_id}", response_class=HTMLResponse)
def page_baseline_detail(request: Request, baseline_id: str, user: CurrentUser, client_id: ActiveClient):
    pb = get_playbook(baseline_id, client_id=client_id)
    if not pb:
        return _gone_redirect(request, "/baselines")
    # Group tactics by MITRE tactic
    tactic_groups = {}
    for t in pb.tactics:
        tac = t.tactic or "Other"
        tactic_groups.setdefault(tac, []).append(t)
    # Systems applied to this baseline (scoped to active client)
    with _get_conn_inline() as conn:
        sys_rows = conn.execute(
            "SELECT sb.system_id, s.name FROM system_baselines sb "
            "JOIN systems s ON s.id = sb.system_id "
            "WHERE sb.playbook_id = ? AND s.client_id = ? ORDER BY s.name",
            [baseline_id, client_id],
        ).fetchall()
    applied_systems = [{"system_id": r[0], "system_name": r[1]} for r in sys_rows]
    all_systems = list_systems(client_id=client_id)
    step_coverage = get_baseline_step_coverage(baseline_id, client_id=client_id)
    # Per-technique coverage for pill coloring
    from app.services.database import get_database_service as _get_db
    _db = _get_db()
    covered_ttps = _db.get_all_covered_ttps(client_id=client_id)
    ttp_rule_counts = _db.get_ttp_rule_counts(client_id=client_id)
    return _render("pages/baseline_detail.html", request, {
        "active_page": "baselines", "baseline": pb, "user": user,
        "mitre_tactics": MITRE_TACTICS,
        "tactic_groups": tactic_groups,
        "applied_systems": applied_systems,
        "all_systems": all_systems,
        "step_coverage": step_coverage,
        "covered_ttps": covered_ttps,
        "ttp_rule_counts": ttp_rule_counts,
    })


# ---------------------------------------------------------------------------
# Dynamic Baseline Generator — Phase 3 (Questionnaire) + Phase 4 (Engine)
# ---------------------------------------------------------------------------

# Severity / status filters applied to every sigma_rules_index query.
_SIGMA_LEVEL_FILTER = "level IN ('critical', 'high', 'medium')"
_SIGMA_STATUS_FILTER = "(status IS NULL OR status NOT IN ('deprecated', 'unsupported'))"

# SQL expressions for the "Primary Technology" abstraction.
# tech = the top-level technology the user selects (e.g. "windows", "proxy").
# gkey = the sub-grouping used to split one tech into modular baselines.
_TECH_COL = "COALESCE(product, category)"
_GROUP_COL = ("CASE WHEN product IS NOT NULL "
              "THEN COALESCE(service, category) ELSE service END")

# Curated UI bucket definitions — order is display order.
_UI_BUCKETS: list[tuple[str, set[str]]] = [
    ("Endpoints", {"windows", "linux", "macos"}),
    ("Cloud & Identity", {
        "aws", "azure", "gcp", "m365", "google_workspace",
        "okta", "onelogin", "github", "bitbucket",
    }),
    ("Network & Security", {
        "cisco", "fortigate", "paloalto", "firewall",
        "proxy", "dns", "zeek", "antivirus",
    }),
]


def _sigma_tech_catalog() -> dict[str, list[dict]]:
    """Return a curated Service Catalog of primary technologies for the UI.

    Each rule is assigned to exactly one *tech* via ``COALESCE(product,
    category)``.  The resulting tech names are then sorted into predefined
    UI buckets (Endpoints, Cloud & Identity, Network & Security) with
    everything else falling into "Other Applications".
    """
    from app.services.database import get_database_service
    db = get_database_service()
    with db.get_shared_connection() as conn:
        rows = conn.execute(f"""
            SELECT {_TECH_COL} AS tech, COUNT(rule_id) AS cnt
            FROM sigma_rules_index
            WHERE {_TECH_COL} IS NOT NULL
              AND {_SIGMA_LEVEL_FILTER}
              AND {_SIGMA_STATUS_FILTER}
            GROUP BY tech
            ORDER BY tech
        """).fetchall()

    buckets: dict[str, list[dict]] = {name: [] for name, _ in _UI_BUCKETS}
    buckets["Other Applications"] = []

    for tech, cnt in rows:
        item = {
            "tech": tech,
            "label": tech.replace("_", " ").title(),
            "count": cnt,
        }
        placed = False
        for bucket_name, members in _UI_BUCKETS:
            if tech in members:
                buckets[bucket_name].append(item)
                placed = True
                break
        if not placed:
            buckets["Other Applications"].append(item)

    return {k: v for k, v in buckets.items() if v}


@router.get("/api/baselines/generate-form", response_class=HTMLResponse)
def api_generate_baselines_form(
    request: Request, user: CurrentUser, client_id: ActiveClient,
    system_id: str = Query(...),
):
    """Return the Generate Baselines modal HTML with dynamic tech checkboxes."""
    system = get_system(system_id, client_id=client_id)
    if not system:
        return HTMLResponse("<p style='color:var(--color-danger)'>System not found.</p>")

    catalog = _sigma_tech_catalog()
    total = sum(item["count"] for items in catalog.values() for item in items)

    return _render("partials/generate_baselines_modal.html", request, {
        "system_id": system_id,
        "system_name": system.name,
        "catalog": catalog,
        "rule_count": total,
    })


def _build_baseline_groups(
    selections: list[str], client_id: str,
) -> list[dict]:
    """Query sigma_rules_index and group matching rules into baseline buckets.

    *selections* contains ``COALESCE(product, category)`` tech names from
    the form checkboxes.  The query fans each tech out into sub-groups via
    ``CASE WHEN product IS NOT NULL THEN COALESCE(service, category)
    ELSE service END`` so that e.g. "windows" yields ~20 modular baselines
    (one per event type / service).

    Each group dict includes an ``exists`` flag (True when a playbook with
    that name is already present).  The UI shows existing baselines
    unchecked by default so the user can choose to re-create them.

    Returns ``groups`` — a flat list of baseline group dicts.
    """
    if not selections:
        return []

    from app.services.database import get_database_service
    db = get_database_service()

    placeholders = ", ".join(["?"] * len(selections))
    with db.get_shared_connection() as conn:
        rows = conn.execute(f"""
            SELECT {_TECH_COL}  AS tech,
                   {_GROUP_COL} AS gkey,
                   COUNT(*)     AS cnt
            FROM sigma_rules_index
            WHERE {_TECH_COL} IN ({placeholders})
              AND {_SIGMA_LEVEL_FILTER}
              AND {_SIGMA_STATUS_FILTER}
            GROUP BY tech, gkey
            ORDER BY tech, gkey
        """, selections).fetchall()

    existing_names = {p.name for p in list_playbooks(client_id=client_id)}
    groups: list[dict] = []
    for tech, gkey, cnt in rows:
        tech_label = tech.replace("_", " ").title()
        if gkey:
            name = f"{tech_label} {gkey.replace('_', ' ').title()} Detection Baseline"
        else:
            name = f"{tech_label} Detection Baseline"
        groups.append({
            "name": name, "count": cnt,
            "tech": tech, "grouping_key": gkey,
            "exists": name in existing_names,
        })
    return groups


@router.post("/api/baselines/generate-preview", response_class=HTMLResponse)
async def api_generate_baselines_preview(
    request: Request, user: RequireUser, client_id: ActiveClient,
):
    """Return a preview of what baselines will be created."""
    form = await request.form()
    system_id = form.get("system_id", "")
    techs = form.getlist("techs")
    groups = _build_baseline_groups(techs, client_id)
    new_groups = [g for g in groups if not g["exists"]]
    existing_groups = [g for g in groups if g["exists"]]
    total_rules = sum(g["count"] for g in new_groups)
    return _render("partials/generate_baselines_preview.html", request, {
        "groups": groups,
        "new_groups": new_groups,
        "existing_groups": existing_groups,
        "total_rules": total_rules,
        "system_id": system_id,
    })


def _generate_baselines_from_sigma(
    system_id: str,
    groups: list[dict],
    client_id: str,
) -> int:
    """Phase 4 baseline engine — create playbooks from Sigma rule groups.

    For each group (tech + sub-grouping combination):
      1. Create a Playbook with a description summarising the scope.
      2. Query sigma_rules_index for matching rule_ids using the same
         ``_TECH_COL`` / ``_GROUP_COL`` expressions as the preview.
      3. For each rule, load the YAML file via sigma_helper, extract
         description / falsepositives / techniques / tactics.
      4. Create a PlaybookStep per rule with step_detections and
         step_techniques populated.
      5. Apply the new baseline to the triggering system_id.

    Returns the number of baselines created.
    """
    from app.sigma_helper import load_sigma_rule, extract_mitre_techniques, extract_mitre_tactics
    from app.services.database import get_database_service
    db = get_database_service()

    created = 0
    for group in groups:
        tech = group["tech"]
        gkey = group["grouping_key"]
        baseline_name = group["name"]

        # Fetch matching rule rows — identical predicates to _build_baseline_groups
        with db.get_shared_connection() as conn:
            if gkey is not None:
                rule_rows = conn.execute(f"""
                    SELECT rule_id, title, file_path, techniques, tactics
                    FROM sigma_rules_index
                    WHERE {_TECH_COL} = ?
                      AND ({_GROUP_COL}) = ?
                      AND {_SIGMA_LEVEL_FILTER}
                      AND {_SIGMA_STATUS_FILTER}
                    ORDER BY title
                """, [tech, gkey]).fetchall()
            else:
                rule_rows = conn.execute(f"""
                    SELECT rule_id, title, file_path, techniques, tactics
                    FROM sigma_rules_index
                    WHERE {_TECH_COL} = ?
                      AND ({_GROUP_COL}) IS NULL
                      AND {_SIGMA_LEVEL_FILTER}
                      AND {_SIGMA_STATUS_FILTER}
                    ORDER BY title
                """, [tech]).fetchall()

        if not rule_rows:
            continue

        # Create the playbook in the tenant DB
        scope = gkey.replace("_", " ").title() if gkey else "General"
        description = (
            f"Auto-generated detection baseline for {tech.replace('_', ' ').title()} "
            f"({scope}) — {len(rule_rows)} Sigma rules covering "
            f"severity levels critical/high/medium."
        )
        pb = create_playbook(baseline_name, description, client_id=client_id)

        # Create one PlaybookStep per Sigma rule
        for step_num, (rule_id, title, file_path, idx_techniques, idx_tactics) in enumerate(rule_rows, 1):
            rule_yaml = load_sigma_rule(file_path) if file_path else None

            if rule_yaml:
                rule_desc = rule_yaml.get("description", "") or ""
                fps = rule_yaml.get("falsepositives") or []
                if fps:
                    fp_text = "; ".join(str(fp) for fp in fps)
                    rule_desc = f"{rule_desc}\n\nFalse Positives: {fp_text}" if rule_desc else f"False Positives: {fp_text}"
                techniques = extract_mitre_techniques(rule_yaml)
                tactics = extract_mitre_tactics(rule_yaml)
            else:
                rule_desc = ""
                techniques = list(idx_techniques) if idx_techniques else []
                tactics = list(idx_tactics) if idx_tactics else []

            primary_technique = techniques[0] if techniques else ""
            primary_tactic = tactics[0] if tactics else ""

            step = add_playbook_step(
                pb.id,
                step_num,
                title or f"Rule {rule_id}",
                technique_id=primary_technique,
                required_rule=rule_id,
                description=rule_desc.strip(),
                tactic=primary_tactic,
                client_id=client_id,
            )

            for extra_tech in techniques[1:]:
                try:
                    add_step_technique(step.id, extra_tech, client_id=client_id)
                except Exception:
                    pass

            # Sigma rules are tracked as step_detections with source="sigma"
            # so they appear in the detection list, but only SIEM/manual
            # detections can be applied to systems for coverage (green).
            add_step_detection(
                step.id,
                rule_ref=title or rule_id,
                note=f"Sigma rule {rule_id}",
                source="sigma",
                client_id=client_id,
            )

        try:
            apply_baseline(system_id, pb.id, client_id=client_id)
        except Exception as e:
            logger.warning(f"[GENERATE] Could not apply baseline {baseline_name}: {e}")

        created += 1
        logger.info(f"[GENERATE] Created baseline '{baseline_name}' ({len(rule_rows)} rules)")

    return created


@router.post("/api/baselines/generate", response_class=HTMLResponse)
async def api_generate_baselines(
    request: Request, user: RequireUser, client_id: ActiveClient,
):
    """Execute baseline generation from selected technologies.

    Reads *techs* (primary technology names), builds baseline groups,
    filters to only the baselines the user selected in the preview,
    calls the engine, and returns the refreshed baseline coverage partial.
    """
    form = await request.form()
    system_id = form.get("system_id", "")
    techs = form.getlist("techs")
    selected_indices = set(form.getlist("selected_baselines"))
    system = get_system(system_id, client_id=client_id)
    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    groups = _build_baseline_groups(techs, client_id)

    # If the user explicitly selected baselines in the preview, only
    # generate those.  Otherwise fall back to all non-existing groups.
    if selected_indices:
        groups = [g for i, g in enumerate(groups) if str(i) in selected_indices]
    else:
        groups = [g for g in groups if not g["exists"]]

    if groups:
        created = _generate_baselines_from_sigma(system_id, groups, client_id)
        logger.info(
            f"[GENERATE] Created {created} baselines "
            f"({sum(g['count'] for g in groups)} rules) for system {system_id}"
        )
    else:
        logger.warning(f"[GENERATE] No new baselines to create for {techs}")

    # Re-render baseline coverage
    return _render_system_baseline_coverage(request, system_id, client_id)


@router.post("/api/baselines", response_class=HTMLResponse)
def api_create_baseline(
    request: Request, user: RequireUser, client_id: ActiveClient,
    name: str = Form(...), description: str = Form(""),
):
    create_playbook(name, description, client_id=client_id)
    baselines = get_baselines_overview(client_id=client_id)
    return _render("partials/baselines_list.html", request, {"baselines": baselines})


@router.post("/api/baselines/import", response_class=HTMLResponse)
async def api_import_baseline(
    request: Request, user: RequireUser, client_id: ActiveClient,
    file: UploadFile = File(...),
    name: str = Form(""),
    description: str = Form(""),
    baseline_id: str = Form(""),
):
    """Import a baseline from a CSV or Excel file.

    Expected columns (case-insensitive, flexible naming):
      Title | Tactic (Kill Chain Phase) | Technique (MITRE ID) | Description
    """
    import csv
    import io
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    filename = (file.filename or "").lower()

    # --- Parse rows from CSV or Excel ---
    if filename.endswith((".xlsx", ".xls")):
        try:
            import openpyxl
            wb = openpyxl.load_workbook(io.BytesIO(content), read_only=True, data_only=True)
            ws = wb.active
            rows_iter = ws.iter_rows(values_only=True)
            raw_headers = next(rows_iter, None)
            if not raw_headers:
                raise HTTPException(status_code=422, detail="Excel file has no header row")
            headers = [str(h).strip().lower() if h else "" for h in raw_headers]
            data_rows = [
                {headers[i]: (str(cell).strip() if cell is not None else "")
                 for i, cell in enumerate(row) if i < len(headers)}
                for row in rows_iter
            ]
            wb.close()
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"Failed to parse Excel file: {exc}")
    elif filename.endswith(".csv"):
        try:
            text = content.decode("utf-8-sig")
            reader = csv.DictReader(io.StringIO(text))
            headers = [h.strip().lower() for h in (reader.fieldnames or [])]
            reader.fieldnames = headers
            data_rows = [{k: (v.strip() if v else "") for k, v in row.items()} for row in reader]
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"Failed to parse CSV file: {exc}")
    else:
        raise HTTPException(status_code=422, detail="File must be .csv, .xlsx, or .xls")

    if not data_rows:
        raise HTTPException(status_code=422, detail="File contains no data rows")

    # --- Map flexible column names to canonical fields ---
    def _find_col(candidates):
        for c in candidates:
            if c in headers:
                return c
        return None

    col_title = _find_col(["title", "name", "technique name", "technique_name"])
    col_tactic = _find_col(["tactic", "kill chain phase", "kill chain", "phase",
                            "kill_chain_phase", "mitre tactic", "mitre_tactic"])
    col_tech = _find_col(["technique", "technique id", "technique_id", "mitre id",
                          "mitre_id", "mitre technique", "mitre_technique", "att&ck id"])
    col_desc = _find_col(["description", "desc", "details", "notes", "note"])

    if not col_title and not col_tech:
        raise HTTPException(
            status_code=422,
            detail="Could not find a 'Title' or 'Technique' column. "
                   "Expected headers like: Title, Tactic, Technique, Description",
        )

    # --- Create or select baseline ---
    if baseline_id.strip():
        pb = get_playbook(baseline_id.strip(), client_id=client_id)
        if not pb:
            raise HTTPException(status_code=404, detail="Baseline not found")
        start_idx = len(pb.tactics) + 1
    else:
        if not name.strip():
            raise HTTPException(status_code=422, detail="Baseline name is required when creating a new baseline")
        pb = create_playbook(name.strip(), description.strip(), client_id=client_id)
        start_idx = 1

    from app.models.inventory import MITRE_TACTICS
    tactic_lookup = {t.lower(): t for t in MITRE_TACTICS}
    tactic_order = {t.lower(): i for i, t in enumerate(MITRE_TACTICS)}

    # Parse all valid rows first
    parsed_rows = []
    for row in data_rows:
        title = row.get(col_title, "") if col_title else ""
        technique_id = row.get(col_tech, "") if col_tech else ""
        raw_tactic = row.get(col_tactic, "") if col_tactic else ""
        desc = row.get(col_desc, "") if col_desc else ""

        # Skip completely empty rows
        if not title and not technique_id:
            continue

        # Fall back: use technique ID as title if title is blank
        if not title:
            title = technique_id

        # Infer and normalize MITRE technique tags from either Technique column or title text.
        if not technique_id and title:
            technique_id = title
        technique_id = normalize_technique_id(technique_id)

        # Normalise tactic name to canonical casing
        tactic_val = tactic_lookup.get(raw_tactic.lower(), raw_tactic) if raw_tactic else ""

        parsed_rows.append((title, technique_id, tactic_val, desc))

    # Sort by kill chain phase order so step_numbers follow MITRE ordering
    parsed_rows.sort(key=lambda r: tactic_order.get(r[2].lower(), 999))

    imported = 0
    for idx, (title, technique_id, tactic_val, desc) in enumerate(parsed_rows, start=start_idx):
        add_playbook_step(pb.id, idx, title, technique_id, "", desc, tactic=tactic_val or None, client_id=client_id)
        imported += 1

    if imported == 0:
        if not baseline_id.strip():
            delete_playbook(pb.id, client_id=client_id)
        raise HTTPException(status_code=422, detail="No valid rows found in file")

    # If imported into an existing baseline, redirect back to its detail page
    if baseline_id.strip():
        resp = HTMLResponse("")
        resp.headers["HX-Redirect"] = f"/baselines/{pb.id}"
        return resp

    baselines = get_baselines_overview(client_id=client_id)
    resp = _render("partials/baselines_list.html", request, {"baselines": baselines})
    resp.headers["HX-Trigger"] = "showToast"
    return resp


@router.delete("/api/baselines/{baseline_id}", response_class=HTMLResponse)
def api_delete_baseline(request: Request, baseline_id: str, user: RequireUser, client_id: ActiveClient):
    delete_playbook(baseline_id, client_id=client_id)
    baselines = get_baselines_overview(client_id=client_id)
    return _render("partials/baselines_list.html", request, {"baselines": baselines})


@router.put("/api/baselines/{baseline_id}", response_class=HTMLResponse)
def api_update_baseline(
    request: Request, baseline_id: str, user: RequireUser, client_id: ActiveClient,
    name: str = Form(...), description: str = Form(""),
    system_id: str = Form(""),
):
    update_playbook(baseline_id, name=name, description=description, client_id=client_id)
    if system_id:
        baselines = get_system_baselines(system_id, client_id=client_id)
        playbooks = list_playbooks(client_id=client_id)
        return _render("partials/baseline_coverage.html", request, {
            "baselines": baselines, "system_id": system_id, "playbooks": playbooks,
        })
    resp = HTMLResponse("")
    resp.headers["HX-Redirect"] = f"/baselines/{baseline_id}"
    return resp


@router.post("/api/baselines/{baseline_id}/tactics", response_class=HTMLResponse)
def api_add_tactic(
    request: Request, baseline_id: str, user: RequireUser, client_id: ActiveClient,
    title: str = Form(...), step_number: int = Form(0),
    technique_id: str = Form(""),
    description: str = Form(""), tactic: str = Form(""),
):
    if step_number < 1:
        pb = get_playbook(baseline_id, client_id=client_id)
        step_number = (len(pb.tactics) + 1) if pb else 1
    add_playbook_step(baseline_id, step_number, title, technique_id, "", description, tactic=tactic or None, client_id=client_id)
    pb = get_playbook(baseline_id, client_id=client_id)
    from app.services.database import get_database_service as _get_db
    _db = _get_db()
    return _render("partials/baseline_tactics.html", request, {
        "baseline": pb,
        "covered_ttps": _db.get_all_covered_ttps(client_id=client_id),
        "ttp_rule_counts": _db.get_ttp_rule_counts(client_id=client_id),
    })


@router.delete("/api/baselines/tactics/{tactic_id}", response_class=HTMLResponse)
def api_delete_tactic(request: Request, tactic_id: str, playbook_id: str = Query(...), user: RequireUser = None, client_id: ActiveClient = None):
    delete_playbook_step(tactic_id, client_id=client_id)
    # When hx-target="body", HTMX does not send the HX-Target header (body has no id).
    # An empty or absent HX-Target means we came from the tactic detail page and should
    # navigate back to the baseline list rather than returning a bare partial.
    hx_target = request.headers.get("HX-Target", "")
    if not hx_target or hx_target == "body":
        resp = HTMLResponse("")
        resp.headers["HX-Redirect"] = f"/baselines/{playbook_id}"
        return resp
    pb = get_playbook(playbook_id, client_id=client_id)
    from app.services.database import get_database_service as _get_db
    _db = _get_db()
    return _render("partials/baseline_tactics.html", request, {
        "baseline": pb,
        "covered_ttps": _db.get_all_covered_ttps(client_id=client_id),
        "ttp_rule_counts": _db.get_ttp_rule_counts(client_id=client_id),
    })


@router.post("/api/baselines/{baseline_id}/apply/{system_id}", response_class=HTMLResponse)
def api_apply_baseline(request: Request, baseline_id: str, system_id: str, user: RequireUser, client_id: ActiveClient):
    try:
        apply_baseline(system_id, baseline_id, client_id=client_id)
    except ValueError as e:
        return HTMLResponse(str(e), status_code=400)
    if request.headers.get("HX-Target") == "baseline-coverage":
        baselines = get_system_baselines(system_id, client_id=client_id)
        playbooks = list_playbooks(client_id=client_id)
        return _render("partials/baseline_coverage.html", request, {
            "baselines": baselines, "system_id": system_id, "playbooks": playbooks,
        })
    resp = HTMLResponse("")
    resp.headers["HX-Redirect"] = f"/baselines/{baseline_id}"
    return resp


@router.delete("/api/baselines/{baseline_id}/apply/{system_id}", response_class=HTMLResponse)
def api_remove_baseline(request: Request, baseline_id: str, system_id: str, user: RequireUser, client_id: ActiveClient):
    try:
        remove_baseline(system_id, baseline_id, client_id=client_id)
    except ValueError as e:
        return HTMLResponse(str(e), status_code=400)
    if request.headers.get("HX-Target") == "baseline-coverage":
        baselines = get_system_baselines(system_id, client_id=client_id)
        playbooks = list_playbooks(client_id=client_id)
        return _render("partials/baseline_coverage.html", request, {
            "baselines": baselines, "system_id": system_id, "playbooks": playbooks,
        })
    resp = HTMLResponse("")
    resp.headers["HX-Redirect"] = f"/baselines/{baseline_id}"
    return resp


@router.get("/api/baselines/system/{system_id}/coverage", response_class=HTMLResponse)
def api_system_baseline_coverage(request: Request, system_id: str, user: CurrentUser, client_id: ActiveClient):
    baselines = get_system_baselines(system_id, client_id=client_id)
    playbooks = list_playbooks(client_id=client_id)
    return _render("partials/baseline_coverage.html", request, {
        "baselines": baselines, "system_id": system_id, "playbooks": playbooks,
    })


# ---------------------------------------------------------------------------
# Baseline Snapshot Routes
# ---------------------------------------------------------------------------

@router.post("/api/baselines/system/{system_id}/snapshot", response_class=HTMLResponse)
def api_snapshot_baseline(
    request: Request, system_id: str, user: RequireUser, client_id: ActiveClient,
    baseline_id: str = Form(...), label: str = Form(""),
    captured_date: str = Form(""),
):
    """Capture a single baseline snapshot."""
    from datetime import datetime as _dt
    ts = _dt.strptime(captured_date, "%Y-%m-%d") if captured_date else None
    create_baseline_snapshot(system_id, baseline_id, label, user.username, captured_at=ts, client_id=client_id)
    snapshots = get_baseline_snapshots(system_id, client_id=client_id)
    baselines = get_system_baselines(system_id, client_id=client_id)
    return _render("partials/audit_history.html", request, {
        "snapshots": snapshots, "system_id": system_id, "baselines": baselines,
    })


@router.post("/api/baselines/system/{system_id}/snapshot-all", response_class=HTMLResponse)
def api_snapshot_all_baselines(
    request: Request, system_id: str, user: RequireUser, client_id: ActiveClient,
    label: str = Form(""),
    captured_date: str = Form(""),
):
    """Snapshot all applied baselines at once."""
    from datetime import datetime as _dt
    ts = _dt.strptime(captured_date, "%Y-%m-%d") if captured_date else None
    create_all_baseline_snapshots(system_id, label, user.username, captured_at=ts, client_id=client_id)
    snapshots = get_baseline_snapshots(system_id, client_id=client_id)
    baselines = get_system_baselines(system_id, client_id=client_id)
    return _render("partials/audit_history.html", request, {
        "snapshots": snapshots, "system_id": system_id, "baselines": baselines,
    })


@router.delete("/api/baselines/snapshots/{snapshot_id}", response_class=HTMLResponse)
def api_delete_snapshot(
    request: Request, snapshot_id: str, user: RequireUser, client_id: ActiveClient,
    system_id: str = Query(...),
):
    """Delete a snapshot."""
    delete_baseline_snapshot(snapshot_id, client_id=client_id)
    snapshots = get_baseline_snapshots(system_id, client_id=client_id)
    baselines = get_system_baselines(system_id, client_id=client_id)
    return _render("partials/audit_history.html", request, {
        "snapshots": snapshots, "system_id": system_id, "baselines": baselines,
    })


@router.get("/api/baselines/system/{system_id}/audit-history", response_class=HTMLResponse)
def api_audit_history(request: Request, system_id: str, user: CurrentUser, client_id: ActiveClient):
    """Get audit history partial."""
    snapshots = get_baseline_snapshots(system_id, client_id=client_id)
    baselines = get_system_baselines(system_id, client_id=client_id)
    return _render("partials/audit_history.html", request, {
        "snapshots": snapshots, "system_id": system_id, "baselines": baselines,
    })


# ---------------------------------------------------------------------------
# Tactic Detail Page + Tactic-level CRUD
# ---------------------------------------------------------------------------

def _build_technique_rules(step, client_id: str = None):
    """Build technique_id -> {has_detection, rule_count, rules} map for pills and dropdown."""
    from app.services.database import get_database_service
    db = get_database_service()
    covered_ttps = db.get_all_covered_ttps(client_id=client_id)
    technique_rules = {}
    for t in step.techniques:
        tid = t.technique_id.upper()
        rules = db.get_rules_for_technique(tid, enabled_only=False, client_id=client_id)
        technique_rules[tid] = {
            "has_detection": tid in covered_ttps,
            "rule_count": len(rules),
            "rules": rules,
        }
    return technique_rules


@router.get("/baselines/{baseline_id}/tactics/{tactic_id}", response_class=HTMLResponse)
def page_tactic_detail(request: Request, baseline_id: str, tactic_id: str, user: CurrentUser, client_id: ActiveClient):
    pb = get_playbook_header(baseline_id, client_id=client_id)
    if not pb:
        return _gone_redirect(request, "/baselines")
    step = get_playbook_step(tactic_id, client_id=client_id)
    if not step:
        return _gone_redirect(request, f"/baselines/{baseline_id}")
    affected_systems = get_step_affected_systems(tactic_id, client_id=client_id)
    blind_spots = get_blind_spots("tactic", tactic_id, client_id=client_id)
    all_siem_rules = get_all_siem_rules(client_id=client_id)

    technique_rules = _build_technique_rules(step, client_id=client_id)

    # Sigma convert context — only when sigma detections exist on this step
    sigma_ctx: dict = {}
    sigma_dets = [d for d in step.detections if (d.source or "manual") == "sigma"]
    if sigma_dets:
        from app import sigma_helper as sigma_mod
        from app.services.database import get_database_service
        _db = get_database_service()
        sigma_ctx["backends"] = sigma_mod.get_available_backends()
        sigma_ctx["pipelines"] = sigma_mod.get_available_pipelines()
        sigma_ctx["formats"] = sigma_mod.get_output_formats("elasticsearch")
        sigma_ctx["pipeline_files"] = sigma_mod.list_saved_pipelines()
        sigma_ctx["template_files"] = sigma_mod.list_saved_templates()
        # Build deploy targets from client's linked SIEMs
        client_siems = _db.get_client_siems(client_id) if client_id else []
        deploy_targets = []
        for s in client_siems:
            if s.get("space"):
                deploy_targets.append({
                    "space": s["space"],
                    "label": f'{s["label"]} ({s["environment_role"].title()})',
                    "environment_role": s["environment_role"],
                })
        sigma_ctx["deploy_targets"] = deploy_targets
        # Resolve sigma rule UUIDs for all sigma detections
        all_rules_cache = None  # lazy-load for legacy title lookups
        sigma_rule_ids = []
        sigma_rule_map = {}  # id → title for selector display
        for det in sigma_dets:
            ref = det.rule_ref or ""
            if not ref:
                continue
            # Try as UUID first
            rule_data = sigma_mod.get_rule_by_id(ref)
            if rule_data:
                sigma_rule_ids.append(ref)
                sigma_rule_map[ref] = rule_data.get("title", ref)
            else:
                # Legacy: stored as title — search all rules for matching title
                if all_rules_cache is None:
                    all_rules_cache = sigma_mod.load_all_rules()
                for r in all_rules_cache:
                    if r.get("title") == ref:
                        rid = r.get("id", "")
                        if rid:
                            sigma_rule_ids.append(rid)
                            sigma_rule_map[rid] = ref
                        break
        # Deduplicate while preserving order
        seen = set()
        unique_ids = []
        for rid in sigma_rule_ids:
            if rid not in seen:
                seen.add(rid)
                unique_ids.append(rid)
        sigma_ctx["sigma_rule_ids"] = unique_ids
        sigma_ctx["sigma_rule_map"] = sigma_rule_map

    return _render("pages/tactic_detail.html", request, {
        "active_page": "baselines", "baseline": pb, "tactic": step,
        "step": step,  # alias for partials that still reference step
        "step_id": tactic_id,  # needed by tactic_affected_systems.html partial
        "playbook": pb,  # alias for breadcrumb compat
        "affected_systems": affected_systems, "blind_spots": blind_spots,
        "all_siem_rules": all_siem_rules,
        "technique_rules": technique_rules,
        "rule_name_lookup": _build_rule_name_lookup(client_id),
        "mitre_tactics": MITRE_TACTICS,
        "user": user,
        **sigma_ctx,
    })


@router.put("/api/baselines/tactics/{tactic_id}", response_class=HTMLResponse)
def api_update_tactic(
    request: Request, tactic_id: str, user: RequireUser, client_id: ActiveClient,
    title: str = Form(None), tactic: str = Form(None),
    description: str = Form(None), step_number: int = Form(None),
):
    step = update_playbook_step(tactic_id, title=title, tactic=tactic,
                                description=description, step_number=step_number, client_id=client_id)
    if not step:
        raise HTTPException(status_code=404)
    resp = HTMLResponse("")
    resp.headers["HX-Redirect"] = f"/baselines/{step.playbook_id}/tactics/{tactic_id}"
    return resp


@router.post("/api/baselines/tactics/{tactic_id}/techniques", response_class=HTMLResponse)
def api_add_tactic_technique(
    request: Request, tactic_id: str, user: RequireUser, client_id: ActiveClient,
    technique_id: str = Form(...),
):
    try:
        add_step_technique(tactic_id, technique_id, client_id=client_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    step = get_playbook_step(tactic_id, client_id=client_id)
    resp = _render("partials/tactic_mitre_section.html", request, {
        "step": step, "technique_rules": _build_technique_rules(step, client_id=client_id),
    })
    resp.headers["HX-Trigger"] = "stepUpdated"
    return resp


@router.delete("/api/baselines/tactics/{tactic_id}/techniques/{technique_row_id}", response_class=HTMLResponse)
def api_remove_tactic_technique(
    request: Request, tactic_id: str, technique_row_id: str, user: RequireUser, client_id: ActiveClient,
):
    remove_step_technique(technique_row_id, client_id=client_id)
    step = get_playbook_step(tactic_id, client_id=client_id)
    resp = _render("partials/tactic_mitre_section.html", request, {
        "step": step, "technique_rules": _build_technique_rules(step, client_id=client_id),
    })
    resp.headers["HX-Trigger"] = "stepUpdated"
    return resp


@router.put("/api/baselines/tactics/{tactic_id}/techniques/{technique_row_id}", response_class=HTMLResponse)
def api_update_tactic_technique(
    request: Request, tactic_id: str, technique_row_id: str, user: RequireUser, client_id: ActiveClient,
    technique_id: str = Form(...),
):
    try:
        update_step_technique(technique_row_id, technique_id, client_id=client_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    step = get_playbook_step(tactic_id, client_id=client_id)
    resp = _render("partials/tactic_mitre_section.html", request, {
        "step": step, "technique_rules": _build_technique_rules(step, client_id=client_id),
    })
    resp.headers["HX-Trigger"] = "stepUpdated"
    return resp


def _build_rule_name_lookup(client_id: str = None) -> dict:
    """Build rule_name -> {rule_id, space} lookup for clickable rule names.

    NOTE (4.1.0): Migration 37 made `detection_rules` per-tenant-scoped — the
    shared schema no longer carries a `client_id` column. The table is already
    tenant-scoped (by tenant DB routing) so we skip the legacy
    `WHERE client_id = ?` filter that would BinderException against the
    current schema."""
    with _get_conn_inline() as conn:
        rows = conn.execute(
            "SELECT rule_id, name, space FROM detection_rules"
        ).fetchall()
    return {r[1]: {"rule_id": r[0], "space": r[2] or "default"} for r in rows}


def _render_detection_section(request, step, client_id=None):
    """Render tactic_detection_section.html with all required context."""
    return _render("partials/tactic_detection_section.html", request, {
        "step": step,
        "rule_name_lookup": _build_rule_name_lookup(client_id),
    })


@router.post("/api/baselines/tactics/{tactic_id}/detections", response_class=HTMLResponse)
def api_add_tactic_detection(
    request: Request, tactic_id: str, user: RequireUser, client_id: ActiveClient,
    rule_ref: str = Form(""), note: str = Form(""), source: str = Form("manual"),
):
    add_step_detection(tactic_id, rule_ref, note, source, client_id=client_id)
    step = get_playbook_step(tactic_id, client_id=client_id)
    resp = _render_detection_section(request, step, client_id=client_id)
    resp.headers["HX-Trigger"] = "stepUpdated"
    return resp


@router.delete("/api/baselines/tactics/detections/{detection_row_id}", response_class=HTMLResponse)
def api_remove_tactic_detection(
    request: Request, detection_row_id: str, step_id: str = Query(...), user: RequireUser = None, client_id: ActiveClient = None,
):
    remove_step_detection(detection_row_id, client_id=client_id)
    step = get_playbook_step(step_id, client_id=client_id)
    resp = _render_detection_section(request, step, client_id=client_id)
    resp.headers["HX-Trigger"] = "stepUpdated"
    return resp


@router.get("/api/baselines/tactics/{tactic_id}/sigma-rules", response_class=HTMLResponse)
def api_search_sigma_rules_for_step(
    request: Request, tactic_id: str, user: CurrentUser, client_id: ActiveClient,
    q: str = Query(""),
):
    """Return sigma rules matching the techniques on this step, as HTML options."""
    from app import sigma_helper as sigma_mod
    step = get_playbook_step(tactic_id, client_id=client_id)
    if not step:
        return HTMLResponse("")
    # Collect all technique IDs mapped on this step
    technique_ids = [t.technique_id.upper() for t in step.techniques]
    if step.technique_id and step.technique_id.upper() not in technique_ids:
        technique_ids.append(step.technique_id.upper())
    if not technique_ids:
        return _render("partials/sigma_rule_options.html", request, {"sigma_results": [], "query": q})
    # Search sigma rules for each technique and de-duplicate
    seen = set()
    sigma_results = []
    for tid in technique_ids:
        matches = sigma_mod.search_rules(query=q, technique_filter=tid, limit=50)
        for r in matches:
            rid = r.get("id", "")
            if rid and rid not in seen:
                seen.add(rid)
                sigma_results.append(r)
    # Sort by title
    sigma_results.sort(key=lambda r: r.get("title", ""))
    return _render("partials/sigma_rule_options.html", request, {
        "sigma_results": sigma_results[:100],
        "query": q,
    })


@router.get("/api/baselines/tactics/{tactic_id}/siem-rules", response_class=HTMLResponse)
def api_search_siem_rules_for_step(
    request: Request, tactic_id: str, user: CurrentUser, client_id: ActiveClient,
    q: str = Query(""),
):
    """Return SIEM rules as HTML options, mapped-to-technique rules first, then all."""
    from app.services.database import get_database_service
    db = get_database_service()
    step = get_playbook_step(tactic_id, client_id=client_id)
    if not step:
        return HTMLResponse("")
    # Collect technique IDs on this step
    technique_ids = [t.technique_id.upper() for t in step.techniques]
    if step.technique_id and step.technique_id.upper() not in technique_ids:
        technique_ids.append(step.technique_id.upper())
    # Get mapped rules (rules that cover this step's techniques)
    mapped = []
    mapped_ids = set()
    for tid in technique_ids:
        for r in db.get_rules_for_technique(tid, enabled_only=False, client_id=client_id):
            if r.rule_id not in mapped_ids:
                mapped_ids.add(r.rule_id)
                mapped.append(r)
    # Get all SIEM rules
    all_rules = get_all_siem_rules(client_id=client_id)
    # Apply search filter
    q_lower = q.strip().lower()
    if q_lower:
        mapped = [r for r in mapped if q_lower in r.name.lower()]
        all_rules = [r for r in all_rules if q_lower in r["name"].lower()]
    # Sort
    mapped.sort(key=lambda r: r.name)
    all_rules.sort(key=lambda r: r["name"])
    return _render("partials/siem_rule_options.html", request, {
        "mapped_rules": mapped[:50],
        "all_rules": all_rules[:100],
        "query": q,
        "mapped_ids": mapped_ids,
    })


@router.get("/api/baselines/tactics/{tactic_id}/affected-systems", response_class=HTMLResponse)
def api_tactic_affected_systems(request: Request, tactic_id: str, user: CurrentUser, client_id: ActiveClient):
    return _render_tactic_affected_section(request, tactic_id, client_id=client_id)


@router.get("/api/baselines/tactics/{tactic_id}/detections", response_class=HTMLResponse)
def api_tactic_detections(request: Request, tactic_id: str, user: CurrentUser, client_id: ActiveClient):
    step = get_playbook_step(tactic_id, client_id=client_id)
    return _render_detection_section(request, step, client_id=client_id)


@router.post("/api/baselines/tactics/{tactic_id}/detections/{detection_id}/apply", response_class=HTMLResponse)
async def api_apply_step_detection(request: Request, tactic_id: str, detection_id: str, user: RequireUser, client_id: ActiveClient):
    """Apply a tactic detection rule to all hosts in a system."""
    # Block sigma-sourced detections — only SIEM/manual rules can be applied
    step = get_playbook_step(tactic_id, client_id=client_id)
    if step:
        det = next((d for d in step.detections if d.id == detection_id), None)
        if det and (det.source or "manual") == "sigma":
            raise HTTPException(status_code=422, detail="Sigma rules cannot be applied directly — convert & deploy first")
    form = await request.form()
    system_id = (form.get("system_id") or "").strip()
    if not system_id:
        raise HTTPException(status_code=422, detail="system_id is required")
    apply_detection(detection_id, system_id=system_id, client_id=client_id)
    # Return appropriate partial based on caller context
    hx_target = request.headers.get("HX-Target", "")
    if hx_target == "baseline-coverage":
        return _render_system_baseline_coverage(request, system_id, client_id=client_id)
    return _render_tactic_affected_section(request, tactic_id, client_id=client_id)


@router.delete("/api/baselines/tactics/{tactic_id}/detections/{detection_id}/apply-system/{system_id}", response_class=HTMLResponse)
def api_remove_step_detection_for_system(request: Request, tactic_id: str, detection_id: str, system_id: str, user: RequireUser, client_id: ActiveClient):
    """Remove a tactic detection from all hosts in a system."""
    remove_detection_for_system(detection_id, system_id, client_id=client_id)
    hx_target = request.headers.get("HX-Target", "")
    if hx_target == "baseline-coverage":
        return _render_system_baseline_coverage(request, system_id, client_id=client_id)
    return _render_tactic_affected_section(request, tactic_id, client_id=client_id)


def _render_tactic_affected_section(request: Request, tactic_id: str, client_id: str = None):
    """Helper: re-render the Applied Systems section for a tactic."""
    affected = get_step_affected_systems(tactic_id, client_id=client_id)
    blind_spots = get_blind_spots("tactic", tactic_id, client_id=client_id)
    return _render("partials/tactic_affected_systems.html", request, {
        "step_id": tactic_id, "affected_systems": affected, "blind_spots": blind_spots,
    })


def _render_system_baseline_coverage(request: Request, system_id: str, client_id: str = None):
    """Helper: re-render the baseline coverage section for a system."""
    baselines = get_system_baselines(system_id, client_id=client_id)
    playbooks = list_playbooks(client_id=client_id)
    return _render("partials/baseline_coverage.html", request, {
        "baselines": baselines, "system_id": system_id, "playbooks": playbooks,
    })


# ---------------------------------------------------------------------------
# Blind Spot CRUD
# ---------------------------------------------------------------------------

@router.post("/api/blind-spots", response_class=HTMLResponse)
def api_add_blind_spot(
    request: Request, user: RequireUser, client_id: ActiveClient,
    entity_type: str = Form(...), entity_id: str = Form(...),
    reason: str = Form(...),
    system_id: str = Form(None), host_id: str = Form(None),
    redirect_target: str = Form(""),
    override_type: str = Form("gap"),
):
    username = user.username if user else ""
    add_blind_spot(entity_type, entity_id, reason,
                   system_id=system_id or None, host_id=host_id or None,
                   created_by=username, override_type=override_type or "gap",
                   client_id=client_id)
    # Return the appropriate partial based on context
    if entity_type == "cve" and entity_id:
        cve = get_cve_detail(entity_id, client_id=client_id)
        if cve:
            grouped = _group_affected_by_system(cve)
            detections_map = list_cve_detections(client_id=client_id)
            applied_map = _load_applied_detections(client_id=client_id)
            cve_dets = detections_map.get(entity_id.upper(), [])
            _enrich_detections_with_applied(cve_dets, applied_map)
            cve_blind_spots = get_blind_spots("cve", entity_id, client_id=client_id)
            return _render("partials/cve_affected_hosts.html", request, {
                "cve": cve, "cve_id": entity_id,
                "grouped_systems": grouped, "detections": cve_dets,
                "blind_spots": cve_blind_spots,
            })
    if entity_type == "tactic" and entity_id:
        hx_target = request.headers.get("HX-Target", "")
        if hx_target == "baseline-coverage" and system_id:
            return _render_system_baseline_coverage(request, system_id, client_id=client_id)
        return _render_tactic_affected_section(request, entity_id, client_id=client_id)
    return HTMLResponse("")


@router.delete("/api/blind-spots/{blind_spot_id}", response_class=HTMLResponse)
def api_remove_blind_spot(
    request: Request, blind_spot_id: str, user: RequireUser, client_id: ActiveClient,
    entity_type: str = Query(""), entity_id: str = Query(""),
):
    remove_blind_spot(blind_spot_id, client_id=client_id)
    if entity_type == "cve" and entity_id:
        cve = get_cve_detail(entity_id, client_id=client_id)
        if cve:
            grouped = _group_affected_by_system(cve)
            detections_map = list_cve_detections(client_id=client_id)
            applied_map = _load_applied_detections(client_id=client_id)
            cve_dets = detections_map.get(entity_id.upper(), [])
            _enrich_detections_with_applied(cve_dets, applied_map)
            cve_blind_spots = get_blind_spots("cve", entity_id, client_id=client_id)
            return _render("partials/cve_affected_hosts.html", request, {
                "cve": cve, "cve_id": entity_id,
                "grouped_systems": grouped, "detections": cve_dets,
                "blind_spots": cve_blind_spots,
            })
    if entity_type == "tactic" and entity_id:
        return _render_tactic_affected_section(request, entity_id, client_id=client_id)
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
    request: Request, system_id: str, user: CurrentUser, client_id: ActiveClient,
    mode: str = Query("executive", pattern="^(executive|technical)$"),
    format: str = Query("pdf", pattern="^(pdf|markdown)$"),
    classification: str = Query("Official"),
    include_devices: str = Query("1"),
    include_baselines: str = Query("1"),
):
    """Generate a System report — CISO Executive Summary or Technical Deep Dive."""
    import os
    from datetime import datetime
    from app.services.report_generator import CLASSIFICATION_OPTIONS

    if classification not in CLASSIFICATION_OPTIONS:
        classification = CLASSIFICATION_OPTIONS[0]

    # Parse query parameters
    include_devices_flag = include_devices == "1"
    include_baselines_flag = include_baselines == "1"
    
    report_data = build_system_report_data(system_id, include_devices=include_devices_flag, client_id=client_id)
    if not report_data:
        raise HTTPException(status_code=404, detail="System not found")

    report_data["mode"] = mode
    report_data["classification"] = classification
    report_data["include_devices"] = include_devices_flag
    report_data["include_baselines"] = include_baselines_flag

    safe_name = report_data["system"]["name"].replace(" ", "_").replace("/", "_")[:30]
    level_tag = "ciso" if mode == "executive" else "technical"
    date_str = datetime.utcnow().strftime("%Y%m%d")

    if format == "markdown":
        md = _generate_system_markdown(report_data, classification)
        filename = f"{date_str}-{safe_name}-{level_tag}.md"
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

    filename = f"{date_str}-{safe_name}-{level_tag}.pdf"
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
    request: Request, cve_id: str, user: CurrentUser, client_id: ActiveClient,
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

    report_data = build_cve_report_data(cve_id, search_filter=search, client_id=client_id)
    if not report_data:
        raise HTTPException(status_code=404, detail="CVE not found")

    report_data["classification"] = classification

    safe_cve = cve_id.replace("/", "_")
    date_str = datetime.utcnow().strftime("%Y%m%d")

    if format == "markdown":
        md = _generate_cve_markdown(report_data, classification)
        filename = f"{date_str}-{safe_cve}-audit.md"
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

    filename = f"{date_str}-{safe_cve}-audit.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )


@router.get("/api/baselines/{baseline_id}/report")
def api_baseline_report(
    request: Request, baseline_id: str, user: CurrentUser, client_id: ActiveClient,
    mode: str = Query("executive", pattern="^(executive|technical)$"),
    format: str = Query("pdf", pattern="^(pdf|markdown)$"),
    classification: str = Query("Official"),
):
    """Generate a Baseline Assurance Report — PDF or Markdown."""
    import os
    from datetime import datetime
    from app.services.report_generator import CLASSIFICATION_OPTIONS

    if classification not in CLASSIFICATION_OPTIONS:
        classification = CLASSIFICATION_OPTIONS[0]

    report_data = build_baseline_report_data(baseline_id, client_id=client_id)
    if not report_data:
        raise HTTPException(status_code=404, detail="Baseline not found")

    report_data["classification"] = classification
    report_data["audience_level"] = "CISO" if mode == "executive" else "Technical"

    safe_name = report_data["baseline_name"].replace(" ", "_").replace("/", "_")[:30]
    level_tag = "ciso" if mode == "executive" else "technical"
    date_str = datetime.utcnow().strftime("%Y%m%d")

    if format == "markdown":
        md = _generate_baseline_markdown(report_data, classification)
        filename = f"{date_str}-{safe_name}-{level_tag}.md"
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
        template = env.get_template("report/baseline_report.html")
        html_str = template.render(report=report_data)
        pdf_bytes = WeasyprintHTML(string=html_str).write_pdf()
    except ImportError:
        logger.error("WeasyPrint is not installed in this environment")
        raise HTTPException(status_code=500, detail="PDF generation requires WeasyPrint. Check server installation.")
    except Exception as exc:
        logger.exception(f"PDF generation failed: {exc}")
        raise HTTPException(status_code=500, detail="PDF generation failed. Check server logs.")

    filename = f"{date_str}-{safe_name}-{level_tag}.pdf"
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
    ]
    
    # Add device stats only if include_devices is True
    if data.get("include_devices"):
        lines += [
            f"| Total Devices | {data['total_hosts']} |",
            f"| Unique CVEs | {data['total_cves']} |",
            f"| At Risk (Red) | {data['red_hosts']} |",
            f"| Monitored (Amber) | {data['amber_hosts']} |",
            f"| Blind Spots (Grey) | {data.get('grey_hosts', 0)} |",
            f"| Clean (Green) | {data['green_hosts']} |",
            f"| Coverage Ratio | {data['coverage_ratio']}% |",
        ]
    
    lines.append("")

    # Top 5 CVEs (only if include_devices is True)
    if data.get("top5_cves") and data.get("include_devices"):
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

    # Device Status (only if include_devices is True)
    if data.get("include_devices"):
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
        # Baseline gap analysis (grouped by tactic)
        if baselines:
            lines += ["## Baseline Gap Analysis", ""]
            for bl in baselines:
                lines.append(f"### {bl['playbook_name']}")
                if bl.get("playbook_description"):
                    lines.append(f"_{bl['playbook_description']}_")
                lines.append("")
                
                # Group steps by tactic
                tactics_grouped = {}
                for step in bl.get("tactics", []):
                    tactic = step.get("tactic") or "Unassigned"
                    if tactic not in tactics_grouped:
                        tactics_grouped[tactic] = []
                    tactics_grouped[tactic].append(step)
                
                # Render each tactic with its steps
                for tactic in sorted(tactics_grouped.keys()):
                    lines.append(f"#### {tactic}")
                    lines.append("")
                    lines.append("| Step | Title | Technique | Applied Rules | Status |")
                    lines.append("|------|-------|-----------|----------------|--------|")
                    for step in tactics_grouped[tactic]:
                        # Determine status display
                        if step["status"] == "grey":
                            status = "N/A"
                        elif step["status"] == "green":
                            status = "Detected"
                        elif step["status"] == "amber":
                            status = "Known Gap"
                        else:
                            status = "Missing"
                        
                        # Get applied detections (rules that are actually in place)
                        applied_rules = step.get("applied_dets", [])
                        applied_display = ", ".join(
                            d.get('rule_ref') or d.get('note') or 'Rule'
                            for d in applied_rules
                        ) if applied_rules else "—"
                        
                        lines.append(
                            f"| {step['step_number']} | {step['title']} | "
                            f"{step['technique_id'] or '—'} | {applied_display} | {status} |"
                        )
                    lines.append("")

        if data.get("all_cves") and data.get("include_devices"):
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


def _generate_baseline_markdown(data: dict, classification: str) -> str:
    """Generate a Markdown baseline assurance report."""
    audience = data.get("audience_level", "Technical")
    lines = [
        f"<!-- {classification} -->",
        "",
        f"# {data['baseline_name']} — Baseline Assurance Report",
        "",
        f"**Classification:** {classification}",
        f"**Generated:** {data['generated_at']}",
        f"**Audience:** {audience}",
        "",
    ]
    if data.get("description"):
        lines += [f"> {data['description']}", ""]

    lines += [
        "---",
        "",
        "## Executive Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Applied Systems | {data['total_systems']} |",
        f"| Tactic Steps | {data['total_steps']} |",
        f"| Mapped Techniques | {data['total_techniques']} |",
        f"| Average Coverage | {data['avg_coverage']}% |",
        f"| Detection Rules | {data['total_detections']} |",
        "",
    ]

    if data.get("steps"):
        lines += [
            "## Baseline Definition — Tactic Steps",
            "",
            "| # | Title | Tactic | Techniques | Detections |",
            "|---|-------|--------|------------|------------|",
        ]
        for s in data["steps"]:
            techs = ", ".join(f"`{t['technique_id']}`" for t in s.get("techniques", [])) or "—"
            dets = ", ".join(d.get("rule_ref") or d.get("note", "—") for d in s.get("detections", [])) or "None"
            lines.append(f"| {s['step_number']} | {s['title']} | {s.get('tactic', '—')} | {techs} | {dets} |")
        lines.append("")

    if data.get("systems"):
        lines += [
            "## System Compliance Matrix",
            "",
            "| System | Coverage | Green | Amber | Red | N/A |",
            "|--------|----------|-------|-------|-----|-----|",
        ]
        for sys in data["systems"]:
            lines.append(
                f"| {sys['system_name']} | {sys['coverage_pct']}% | "
                f"{sys['covered_steps']} | {sys['gap_steps']} | "
                f"{sys['red_steps']} | {sys['na_steps']} |"
            )
        lines.append("")

        if audience != "CISO":
            lines += ["## Per-System Coverage Detail", ""]
            for sys in data["systems"]:
                lines.append(f"### {sys['system_name']} ({sys['coverage_pct']}%)")
                lines.append("")
                lines.append("| # | Step | Tactic | Status | Applied Detections |")
                lines.append("|---|------|--------|--------|--------------------|")
                for t in sys.get("tactics", []):
                    status = {"green": "Covered", "amber": "Known Gap", "grey": "N/A", "red": "Missing"}.get(t["status"], t["status"])
                    dets = ", ".join(d.get("label", d.get("rule_ref", "—")) for d in t.get("applied_dets", [])) or "—"
                    lines.append(f"| {t['step_number']} | {t['title']} | {t.get('tactic', '—')} | {status} | {dets} |")
                lines.append("")

    lines += [
        "---",
        f"*{classification} — Report generated by TIDE — Threat Intelligence Detection Engineering*",
    ]
    return "\n".join(lines)
