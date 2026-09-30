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
import json
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import quote
from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from app.api.deps import ActiveClient, CurrentUser, RequireUser
from app.inventory_engine import (
    get_system_steps,
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
    list_playbooks, get_playbook, get_template, get_baselines_overview, count_system_baselines,
    create_playbook, delete_playbook, update_playbook,
    add_playbook_step, delete_playbook_step,
    apply_baseline, remove_baseline, get_system_baselines, create_system_baseline,
    # Techniques (steps)
    add_step_technique, add_step_detection, relink_step_detection, remove_step_detection,
    get_playbook_step, get_step_owner, add_technique, update_technique, parse_technique_ids,
    canonical_tactic,
    normalize_technique_id,
    # Blind Spots
    add_blind_spot, remove_blind_spot, get_blind_spots, update_blind_spot,
    list_cve_detections, _load_applied_detections, _enrich_detections_with_applied,
    # Baseline Snapshots
    create_baseline_snapshot, create_all_baseline_snapshots,
    get_baseline_snapshots, delete_baseline_snapshot,
)
from app.models.inventory import HostCreate, HostUpdate, SoftwareCreate, SoftwareUpdate, SystemCreate, SystemUpdate, MITRE_TACTICS, PlaybookStep
from app.services.database import get_database_service

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
                with _db.get_shared_connection() as conn:
                    row = conn.execute(
                        "SELECT client_id FROM user_clients WHERE user_id = ? AND is_default = true LIMIT 1",
                        [_user.id],
                    ).fetchone()
                    if row:
                        _cid = row[0]
            if not _cid:
                with _db.get_shared_connection() as conn:
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
    return _render("pages/inventory/systems.html", request, {
        "active_page": "systems", "summaries": summaries, "systems": systems, "user": user,
        "classifications": list_classifications(client_id=client_id), "clf_colors": _clf_color_map(client_id=client_id),
    })


_STEP_VIEWS = ("cards", "table")
_TACTIC_SORTS = ("attack", "alpha", "off")


def _step_grid_filters(request: Request) -> Dict[str, Any]:
    """The system page's technique filters, read from the query string. Shared by the page (so a
    reload or a shared link restores the same view) and the grid endpoint (so they never drift)."""
    q = request.query_params
    tactic_sort = q.get("tactic_sort", "")
    view = q.get("view", "")
    return {
        "search": q.get("search", ""),
        "tactic": [t for t in q.getlist("tactic") if t],
        # Empty means "not chosen in the URL": the page fills it from the browser's remembered
        # choice before the grid first loads, and the grid endpoint falls back to the default.
        "tactic_sort": tactic_sort if tactic_sort in _TACTIC_SORTS else "",
        "sort_name": q.get("sort_name", "") if q.get("sort_name") in ("asc", "desc") else "",
        "status": q.get("status", ""),
        "mapping": q.get("mapping", ""),
        "baseline_id": q.get("baseline_id", ""),
        "group": [g for g in q.getlist("group") if g in ("baseline", "tactic", "none")],
        "view": view if view in _STEP_VIEWS else "",
        "technique": q.get("technique", ""),
    }


def _system_baseline_or_none(system_id: str, baseline_id: str, client_id: str):
    """One of this system's own baselines (its copy of a template, or one it started), else None.
    A template, or another system's baseline, is never managed through this system."""
    pb = get_playbook(baseline_id, client_id=client_id) if baseline_id else None
    return pb if pb and pb.system_id == system_id else None


def _system_page(request: Request, system, user, client_id: str):
    """The system page, where all of its baselines are managed."""
    from app.services.report_generator import CLASSIFICATION_OPTIONS
    return _render("pages/inventory/system_detail.html", request, {
        "active_page": "systems", "system": system, "system_id": system.id,
        "host_summaries": get_host_summaries(system.id, client_id=client_id), "user": user,
        "classifications": list_classifications(client_id=client_id), "clf_colors": _clf_color_map(client_id=client_id),
        "classification_options": CLASSIFICATION_OPTIONS,
        "filters": _step_grid_filters(request),
        # Rollups for the metric strip, and the tactic/baseline lists for the filters; the grid
        # loads over htmx with the filters applied.
        **get_system_steps(system.id, client_id=client_id),
    })


@router.get("/systems/{system_id}", response_class=HTMLResponse)
def page_system_detail(request: Request, system_id: str, user: CurrentUser, client_id: ActiveClient):
    system = get_system(system_id, client_id=client_id)
    if not system:
        return _gone_redirect(request, "/systems")
    return _system_page(request, system, user, client_id)


@router.get("/systems/{system_id}/baselines/{baseline_id}")
def page_system_baseline(system_id: str, baseline_id: str, user: CurrentUser):
    """Old address of a page that no longer exists: a system's baselines are managed on the
    system page. Kept so bookmarks land there, filtered to that baseline."""
    return RedirectResponse(url=f"/systems/{system_id}?baseline_id={quote(baseline_id)}", status_code=301)


@router.get("/hosts/{host_id}", response_class=HTMLResponse)
def page_host_detail(request: Request, host_id: str, user: CurrentUser, client_id: ActiveClient):
    host = get_host(host_id, client_id=client_id)
    if not host:
        return _gone_redirect(request, "/systems")
    system = get_system(host.system_id, client_id=client_id)
    software = list_host_software(host_id, client_id=client_id)
    vulns = get_host_vulnerabilities(host_id, client_id=client_id)
    clf_color = get_classification_color(system.classification, client_id=client_id) if system and system.classification else None
    return _render("pages/inventory/host_detail.html", request, {
        "active_page": "systems", "host": host, "system": system,
        "software": software, "vulns": vulns, "user": user,
        "clf_color": clf_color,
    })


@router.get("/cve-overview", response_class=HTMLResponse)
def page_cve_overview(request: Request, user: CurrentUser, client_id: ActiveClient):
    cves = get_all_cve_overview(client_id=client_id)
    stats = get_cve_overview_stats(cves=cves, client_id=client_id)
    return _render("pages/inventory/cve_overview.html", request, {
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
    return _render("pages/inventory/cve_detail.html", request, {
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
    """The templates, shown the way a system's page shows its baselines: every template's
    techniques in one grid, with the same search, filters, grouping and technique window --
    without coverage, which a template only has once applied to a system."""
    from app.inventory_engine import get_template_steps
    return _render("pages/inventory/baselines.html", request, {
        "active_page": "baselines", "user": user, "filters": _step_grid_filters(request),
        "system_baselines": count_system_baselines(client_id=client_id),
        **get_template_steps(client_id=client_id),
    })


@router.get("/baselines/{baseline_id}")
def page_baseline_detail(baseline_id: str, user: CurrentUser):
    """Old address of a template's page: templates are on the Baselines page. Kept so bookmarks
    land there, filtered to that template. Temporary (307), like the MITRE pages' old addresses,
    so a browser never caches where it goes."""
    return RedirectResponse(url=f"/baselines?baseline_id={quote(baseline_id)}&group=baseline", status_code=307)


@router.get("/api/baselines/steps", response_class=HTMLResponse)
def api_template_steps_grid(request: Request, user: CurrentUser, client_id: ActiveClient):
    """The templates' filtered, sorted and optionally grouped technique grid (or table). Grouped
    by baseline, a template with no techniques yet still shows, so it can be managed."""
    from app.inventory_engine import get_template_steps, group_system_steps
    f = _step_grid_filters(request)
    tactic_sort = f["tactic_sort"] or "attack"
    data = get_template_steps(client_id=client_id, search=f["search"], tactic=f["tactic"],
                              baseline_id=f["baseline_id"], tactic_sort=tactic_sort, sort_name=f["sort_name"])
    groups = group_system_steps(data["steps"], f["group"], tactic_sort)
    narrowed = f["search"] or f["tactic"]
    if "baseline" in f["group"] and not narrowed:
        shown = {g["key"] for g in groups}
        groups += [{"key": b["id"], "kind": "baseline", "label": b["name"], "steps": [], "groups": [], "total": 0}
                   for b in data["baselines"]
                   if b["id"] not in shown and (not f["baseline_id"] or b["id"] == f["baseline_id"])]
        groups.sort(key=lambda g: (g["label"] or "").lower())
    return _render("partials/system_steps_grid.html", request, {
        **data, "template": True, "groups": groups, "view": f["view"] or "cards",
        "tactic_sort": tactic_sort, "sort_name": f["sort_name"],
    })


@router.get("/api/baselines/steps-metrics", response_class=HTMLResponse)
def api_template_steps_metrics(request: Request, user: CurrentUser, client_id: ActiveClient):
    """The Baselines page's metric strip: whole-set totals, never the filtered grid's."""
    from app.inventory_engine import get_template_steps
    return _render("partials/template_steps_metrics.html", request, {
        **get_template_steps(client_id=client_id), "system_baselines": count_system_baselines(client_id=client_id),
    })


@router.get("/api/baselines/{baseline_id}/manage", response_class=HTMLResponse)
def api_template_manage(request: Request, baseline_id: str, user: CurrentUser, client_id: ActiveClient):
    """One template's window: rename it, apply it to a system, import techniques into it,
    export it, or delete it."""
    pb = get_template(baseline_id, client_id=client_id)
    if not pb:
        raise HTTPException(status_code=404, detail="Baseline not found")
    # Applying changes a system, so it is offered only to those who may edit systems.
    can_apply = user is None or user.can_write("page:systems")
    return _render("partials/template_manage_dialog.html", request, {
        "baseline": pb, "systems": list_systems(client_id=client_id) if can_apply else [],
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


def _sigma_index_exists() -> bool:
    """Return True when sigma_rules_index is available in the active DB."""
    from app.services.database import get_database_service
    db = get_database_service()
    with db.get_shared_connection() as conn:
        row = conn.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'main' AND table_name = 'sigma_rules_index'"
        ).fetchone()
    return bool(row)


def _sigma_tech_catalog() -> dict[str, list[dict]]:
    """Return a curated Service Catalog of primary technologies for the UI.

    Each rule is assigned to exactly one *tech* via ``COALESCE(product,
    category)``.  The resulting tech names are then sorted into predefined
    UI buckets (Endpoints, Cloud & Identity, Network & Security) with
    everything else falling into "Other Applications".
    """
    if not _sigma_index_exists():
        logger.info("Baseline generator: sigma_rules_index missing for active DB; returning empty catalog")
        return {}

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
    selections: list[str], client_id: str, system_id: str,
) -> list[dict]:
    """Query sigma_rules_index and group matching rules into baseline buckets.

    *selections* contains ``COALESCE(product, category)`` tech names from
    the form checkboxes.  The query fans each tech out into sub-groups via
    ``CASE WHEN product IS NOT NULL THEN COALESCE(service, category)
    ELSE service END`` so that e.g. "windows" yields ~20 modular baselines
    (one per event type / service).

    Each group dict includes an ``exists`` flag (True when this system already
    has a baseline with that name).  The UI shows those unchecked by default;
    generating one again adds a second, named "<name> (copy)".

    Returns ``groups`` — a flat list of baseline group dicts.
    """
    if not selections or not _sigma_index_exists():
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

    existing_names = {b["playbook_name"] for b in get_system_baselines(system_id, include_detection_details=False, client_id=client_id)}
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
    groups = _build_baseline_groups(techs, client_id, system_id)
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
    """Create baselines of this system's own from Sigma rule groups -- no template behind them.

    For each group (tech + sub-grouping combination):
      1. Start an empty baseline on the system, with a description summarising the scope.
      2. Query sigma_rules_index for matching rule_ids using the same
         ``_TECH_COL`` / ``_GROUP_COL`` expressions as the preview.
      3. For each rule, load the YAML file via sigma_helper, extract
         description / falsepositives / techniques / tactics.
      4. Add one technique per rule: its title, ATT&CK techniques and description only. The
         technique window suggests Sigma rules from those ATT&CK ids.

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
        with db.get_shared_connection() as conn:
            if gkey:
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

        scope = gkey.replace("_", " ").title() if gkey else "General"
        description = (
            f"Auto-generated detection baseline for {tech.replace('_', ' ').title()} "
            f"({scope}) — {len(rule_rows)} Sigma rules covering "
            f"severity levels critical/high/medium."
        )
        baseline = create_system_baseline(system_id, baseline_name, description, client_id=client_id)

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
                baseline.playbook_id,
                step_num,
                title or f"Rule {rule_id}",
                technique_id=primary_technique,
                description=rule_desc.strip(),
                tactic=primary_tactic,
                client_id=client_id,
            )

            for extra_tech in techniques[1:]:
                try:
                    add_step_technique(step.id, extra_tech, client_id=client_id)
                except Exception:
                    pass

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

    groups = _build_baseline_groups(techs, client_id, system_id)

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
    """A new, empty template: the Baselines page reloads showing it, ready for its techniques."""
    pb = create_playbook(name, description, client_id=client_id)
    resp = HTMLResponse("")
    resp.headers["HX-Redirect"] = f"/baselines?baseline_id={quote(pb.id)}&group=baseline"
    return resp


def _decode_rule_raw_data(raw_data):
    if isinstance(raw_data, dict):
        return raw_data
    if isinstance(raw_data, str) and raw_data.strip():
        try:
            return json.loads(raw_data)
        except Exception:
            return {}
    return {}


def _rule_saved_object_id(rule_payload: dict) -> str:
    raw_data = _decode_rule_raw_data(rule_payload.get("raw_data"))
    return str(rule_payload.get("id") or raw_data.get("id") or "").strip()


def _rule_reference_keys(rule_payload: dict) -> set[str]:
    raw_data = _decode_rule_raw_data(rule_payload.get("raw_data"))
    keys = {
        str(rule_payload.get("id") or "").strip(),
        str(rule_payload.get("rule_id") or "").strip(),
        str(rule_payload.get("source_rule_id") or "").strip(),
    }
    if isinstance(raw_data, dict):
        keys.add(str(raw_data.get("id") or "").strip())
        keys.add(str(raw_data.get("rule_id") or "").strip())
        params = raw_data.get("params") if isinstance(raw_data.get("params"), dict) else {}
        keys.add(str(params.get("rule_id") or "").strip())
    return {key for key in keys if key}


def _rule_export_payloads_for_refs(conn, refs: set[str]) -> dict:
    wanted = {str(ref).strip() for ref in refs if str(ref or "").strip()}
    if not wanted:
        return {}
    rows = conn.execute("SELECT * FROM detection_rules ORDER BY siem_id, space, name").fetchall()
    columns = [item[0] for item in conn.description]
    found = {}
    seen_rules = set()
    for row in rows:
        payload = dict(zip(columns, row))
        matched_refs = wanted.intersection(_rule_reference_keys(payload))
        if not matched_refs:
            continue
        rule_key = (payload.get("rule_id"), payload.get("siem_id"), payload.get("space"))
        if rule_key in seen_rules:
            continue
        seen_rules.add(rule_key)
        for ref in matched_refs:
            found[ref] = payload
    return found


def _baseline_export_payload(baseline_id: str, client_id: str, include_rules: bool = True) -> dict:
    baseline = get_playbook(baseline_id, client_id=client_id)
    if not baseline:
        raise HTTPException(status_code=404, detail="Baseline not found")
    refs = set()
    steps = []
    for step in baseline.tactics or []:
        detections = [
            {"rule_ref": det.rule_ref, "note": det.note, "source": det.source}
            for det in (step.detections or [])
        ]
        refs.update(det["rule_ref"] for det in detections if det["rule_ref"])
        steps.append({
            "step_number": step.step_number,
            "title": step.title,
            "technique_id": step.technique_id,
            "required_rule": step.required_rule,
            "tactic": step.tactic,
            "description": step.description,
            "techniques": [tech.technique_id for tech in (step.techniques or [])],
            "detections": detections,
        })
    rules = []
    rules_by_ref = {}
    if include_rules:
        db = get_database_service()
        with db.get_connection() as conn:
            rules_by_ref = _rule_export_payloads_for_refs(conn, refs)
            for ref in sorted(refs):
                rule_payload = rules_by_ref.get(ref)
                if rule_payload:
                    rules.append(rule_payload)
    for step in steps:
        for detection in step.get("detections") or []:
            rule_payload = rules_by_ref.get(detection.get("rule_ref")) or {}
            display_name = rule_payload.get("name") or detection.get("note")
            if display_name:
                detection["display_name"] = display_name
    return {
        "tide_export_version": 1,
        "export_type": "baseline",
        "baseline_id": baseline.id,
        "baseline": {"name": baseline.name, "description": baseline.description},
        "steps": steps,
        "rules": rules,
    }


def _ensure_baseline_import_schema(client_id: str) -> None:
    db = get_database_service()
    with db.get_connection() as conn:
        try:
            conn.execute("ALTER TABLE step_detections ADD COLUMN IF NOT EXISTS logical_rule_id VARCHAR")
        except Exception:
            logger.debug("step_detections logical identity column repair failed for %s", client_id, exc_info=True)


def _import_name(source_name: str, existing_names: set[str]) -> str:
    return f"{source_name} (copy)" if source_name in existing_names else source_name


@router.get("/api/baselines/{baseline_id}/export.json")
def export_baseline_json(
    baseline_id: str,
    client_id: ActiveClient,
    include_rules: bool = Query(True),
):
    payload = _baseline_export_payload(baseline_id, client_id, include_rules=include_rules)
    payload["include_rules"] = include_rules
    return Response(
        content=json.dumps(payload, default=str, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="baseline-{baseline_id}.json"'},
    )


@router.post("/api/baselines/import.json")
async def import_baseline_json(
    request: Request,
    user: RequireUser,
    client_id: ActiveClient,
    file: UploadFile = File(...),
    include_rules: bool = Form(False),
    conflict: str = Form("create"),
    target_baseline_id: str = Form(""),
):
    try:
        payload = json.loads((await file.read()).decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid JSON export: {exc}")
    if payload.get("tide_export_version") != 1 or payload.get("export_type") != "baseline":
        raise HTTPException(status_code=422, detail="Unsupported TIDE baseline export")
    _ensure_baseline_import_schema(client_id)
    baseline_name = str((payload.get("baseline") or {}).get("name") or "Imported baseline")
    existing = [item for item in (get_baselines_overview(client_id=client_id) or []) if item.get("name") == baseline_name]
    if existing and conflict == "prompt":
        return JSONResponse(
            {"status": "conflict", "existing_id": existing[0].get("id"), "existing_name": baseline_name},
            status_code=409,
        )
    if conflict == "override" and target_baseline_id:
        # The current import remains copy-first; the target ID is returned so
        # the operator can explicitly choose the existing baseline in the UI.
        logger.info("Baseline import requested override for target %s", target_baseline_id)
    source_rules = payload.get("rules") or [] if include_rules else []
    db = get_database_service()
    imported_ids = {}
    logical_sources = []
    with db.get_connection() as conn:
        for source in source_rules:
            original_id = str(source.get("rule_id") or source.get("source_rule_id") or "").strip()
            if not original_id:
                continue
            # Preserve the source Elastic ID across installations. The
            # logical TIDE identity layer handles later merges to a new ID.
            imported_id = original_id
            imported_ids[original_id] = original_id
            saved_object_id = _rule_saved_object_id(source)
            if saved_object_id:
                imported_ids[saved_object_id] = imported_id
            logical_sources.append((original_id, source.get("siem_id") or "imported", source.get("space") or ""))
            raw_data = source.get("raw_data") or {}
            if not isinstance(raw_data, str):
                raw_data = json.dumps(raw_data, default=str)
            conn.execute(
                """INSERT INTO detection_rules (
                    rule_id, siem_id, name, severity, author, enabled, space,
                    score, quality_score, meta_score, score_mapping, score_field_type,
                    score_search_time, score_language, score_note, score_override,
                    score_tactics, score_techniques, score_author, score_highlights,
                    last_updated, mitre_ids, raw_data, client_id, deprecated, source_rule_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, true, ?)
                ON CONFLICT (rule_id, siem_id, space) DO UPDATE SET
                    name = EXCLUDED.name, severity = EXCLUDED.severity,
                    author = EXCLUDED.author, enabled = EXCLUDED.enabled,
                    raw_data = EXCLUDED.raw_data, mitre_ids = EXCLUDED.mitre_ids,
                    deprecated = true, source_rule_id = EXCLUDED.source_rule_id
                """,
                [
                    imported_id, source.get("siem_id") or "imported", source.get("name") or original_id,
                    source.get("severity") or "low", source.get("author") or "Unknown",
                    int(bool(source.get("enabled", True))), source.get("space") or "",
                    source.get("score") or 0, source.get("quality_score") or 0, source.get("meta_score") or 0,
                    source.get("score_mapping") or 0, source.get("score_field_type") or 0,
                    source.get("score_search_time") or 0, source.get("score_language") or 0,
                    source.get("score_note") or 0, source.get("score_override") or 0,
                    source.get("score_tactics") or 0, source.get("score_techniques") or 0,
                    source.get("score_author") or 0, source.get("score_highlights") or 0,
                    source.get("last_updated"), source.get("mitre_ids") or [], raw_data,
                    client_id, original_id,
                ],
            )
    for original_id, source_siem_id, source_space in logical_sources:
        db.ensure_logical_rule_identity(
            original_id, original_id, source_siem_id, source_space
        )
    baseline_info = payload.get("baseline") or {}
    if conflict == "override" and target_baseline_id:
        baseline = get_template(target_baseline_id, client_id=client_id)
        if not baseline:
            raise HTTPException(status_code=404, detail="Target baseline not found")
        with db.get_connection() as conn:
            step_ids = [row[0] for row in conn.execute(
                "SELECT id FROM playbook_steps WHERE playbook_id = ?", [baseline.id]
            ).fetchall()]
            if step_ids:
                placeholders = ",".join("?" for _ in step_ids)
                conn.execute(f"DELETE FROM step_detections WHERE step_id IN ({placeholders})", step_ids)
                conn.execute(f"DELETE FROM step_techniques WHERE step_id IN ({placeholders})", step_ids)
                conn.execute("DELETE FROM playbook_steps WHERE playbook_id = ?", [baseline.id])
            conn.execute(
                "UPDATE playbooks SET name = ?, description = ?, updated_at = now() WHERE id = ?",
                [baseline_info.get("name") or baseline.name, baseline_info.get("description") or "", baseline.id],
            )
    else:
        existing_names = {item.get("name") for item in (get_baselines_overview(client_id=client_id) or [])}
        imported_name = _import_name(baseline_info.get("name") or "Imported baseline", existing_names)
        baseline = create_playbook(
            imported_name,
            baseline_info.get("description") or "",
            client_id=client_id,
        )
    for step_data in payload.get("steps") or []:
        step = add_playbook_step(
            baseline.id,
            int(step_data.get("step_number") or 1),
            step_data.get("title") or "Imported step",
            technique_id=step_data.get("technique_id") or "",
            required_rule=imported_ids.get(step_data.get("required_rule") or "", ""),
            description=step_data.get("description") or "",
            tactic=step_data.get("tactic") or "",
            client_id=client_id,
        )
        for technique_id in step_data.get("techniques") or []:
            add_step_technique(step.id, technique_id, client_id=client_id)
        # A template carries Sigma suggestions only; rule mappings are made on a system.
        for detection in step_data.get("detections") or []:
            if (detection.get("source") or "manual") != "sigma":
                continue
            add_step_detection(
                step.id,
                imported_ids.get(detection.get("rule_ref"), detection.get("rule_ref") or ""),
                note=detection.get("display_name") or detection.get("note") or "",
                source="sigma",
                client_id=client_id,
            )
    return {"status": "ok", "baseline_id": baseline.id, "imported_rules": len(imported_ids)}


@router.get("/api/systems/export.json")
def export_system_configuration(
    client_id: ActiveClient,
    include_baselines: bool = Query(True),
    include_rules: bool = Query(True),
    include_devices: bool = Query(False),
    system_ids: Optional[List[str]] = Query(None),
):
    """Export selected tenant systems, baselines, rules, and devices."""
    db = get_database_service()
    with db.get_connection() as conn:
        selected_ids = [value for value in (system_ids or []) if value]
        system_filter = ""
        system_params = []
        if selected_ids:
            placeholders = ",".join("?" for _ in selected_ids)
            system_filter = f" WHERE id IN ({placeholders})"
            system_params = selected_ids
        baseline_ids = []
        assignments = [
            {"system_id": row[0], "playbook_id": row[1], "applied_at": row[2]}
            for row in conn.execute(
                "SELECT system_id, playbook_id, applied_at FROM system_baselines"
                + (f" WHERE system_id IN ({','.join('?' for _ in selected_ids)})" if selected_ids else ""),
                system_params,
            ).fetchall()
        ]
        if include_baselines:
            baseline_ids = sorted({row["playbook_id"] for row in assignments})
        system_rows = conn.execute("SELECT * FROM systems ORDER BY name").fetchall()
        system_columns = [item[0] for item in conn.description]
        systems = [dict(zip(system_columns, row)) for row in system_rows]
        if selected_ids:
            systems = [system for system in systems if system.get("id") in selected_ids]
        if include_devices:
            for system in systems:
                hosts = conn.execute(
                    "SELECT id, name, ip_address, os, hardware_vendor, model, source "
                    "FROM hosts WHERE system_id = ? ORDER BY name",
                    [system["id"]],
                ).fetchall()
                system["hosts"] = []
                for host in hosts:
                    host_data = dict(zip(
                        ["id", "name", "ip_address", "os", "hardware_vendor", "model", "source"],
                        host,
                    ))
                    software = conn.execute(
                        "SELECT name, version, vendor, cpe, source FROM software_inventory "
                        "WHERE host_id = ? ORDER BY name",
                        [host_data["id"]],
                    ).fetchall()
                    host_data["software"] = [
                        dict(zip(["name", "version", "vendor", "cpe", "source"], item))
                        for item in software
                    ]
                    system["hosts"].append(host_data)
    baselines = (
        [_baseline_export_payload(item, client_id, include_rules=include_rules) for item in baseline_ids]
        if include_baselines else []
    )
    return Response(
        content=json.dumps({
            "tide_export_version": 1,
            "export_type": "system",
            "include_baselines": include_baselines,
            "include_rules": include_rules,
            "include_devices": include_devices,
            "systems": systems,
            "assignments": assignments,
            "baselines": baselines,
        }, default=str, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="tide-system-export.json"'},
    )


async def _import_baseline_payload(payload: dict, client_id: str, system_id: str = None) -> str:
    """Create an imported baseline and return its new ID: a template, or -- given ``system_id``
    -- that system's own baseline, with its rule mappings applied to it. A template carries
    techniques and Sigma suggestions only, so any other mappings in the file are left out."""
    _ensure_baseline_import_schema(client_id)
    source_rules = payload.get("rules") or []
    db = get_database_service()
    imported_ids = {}
    logical_sources = []
    with db.get_connection() as conn:
        for source in source_rules:
            original_id = str(source.get("rule_id") or source.get("source_rule_id") or "").strip()
            if not original_id:
                continue
            imported_id = original_id
            imported_ids[original_id] = original_id
            saved_object_id = _rule_saved_object_id(source)
            if saved_object_id:
                imported_ids[saved_object_id] = imported_id
            logical_sources.append((original_id, source.get("siem_id") or "imported", source.get("space") or ""))
            raw_data = source.get("raw_data") or {}
            if not isinstance(raw_data, str):
                raw_data = json.dumps(raw_data, default=str)
            conn.execute(
                """INSERT INTO detection_rules (
                    rule_id, siem_id, name, severity, author, enabled, space,
                    score, quality_score, meta_score, score_mapping, score_field_type,
                    score_search_time, score_language, score_note, score_override,
                    score_tactics, score_techniques, score_author, score_highlights,
                    last_updated, mitre_ids, raw_data, client_id, deprecated, source_rule_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, true, ?)
                ON CONFLICT (rule_id, siem_id, space) DO UPDATE SET
                    name = EXCLUDED.name, severity = EXCLUDED.severity,
                    author = EXCLUDED.author, enabled = EXCLUDED.enabled,
                    raw_data = EXCLUDED.raw_data, mitre_ids = EXCLUDED.mitre_ids,
                    deprecated = true, source_rule_id = EXCLUDED.source_rule_id
                """,
                [
                    imported_id, source.get("siem_id") or "imported", source.get("name") or original_id,
                    source.get("severity") or "low", source.get("author") or "Unknown",
                    int(bool(source.get("enabled", True))), source.get("space") or "",
                    source.get("score") or 0, source.get("quality_score") or 0, source.get("meta_score") or 0,
                    source.get("score_mapping") or 0, source.get("score_field_type") or 0,
                    source.get("score_search_time") or 0, source.get("score_language") or 0,
                    source.get("score_note") or 0, source.get("score_override") or 0,
                    source.get("score_tactics") or 0, source.get("score_techniques") or 0,
                    source.get("score_author") or 0, source.get("score_highlights") or 0,
                    source.get("last_updated"), source.get("mitre_ids") or [], raw_data,
                    client_id, original_id,
                ],
            )
    for original_id, source_siem_id, source_space in logical_sources:
        db.ensure_logical_rule_identity(
            original_id, original_id, source_siem_id, source_space
        )
    baseline_info = payload.get("baseline") or {}
    imported_name = baseline_info.get("name") or "Imported baseline"
    if not system_id:
        existing_names = {item.get("name") for item in (get_baselines_overview(client_id=client_id) or [])}
        imported_name = _import_name(imported_name, existing_names)
    baseline = create_playbook(
        imported_name,
        baseline_info.get("description") or "",
        client_id=client_id,
    )
    if system_id:
        with db.get_connection() as conn:
            conn.execute("UPDATE playbooks SET system_id = ? WHERE id = ?", [system_id, baseline.id])
            conn.execute("INSERT INTO system_baselines (system_id, playbook_id, client_id) VALUES (?, ?, ?)",
                         [system_id, baseline.id, client_id])
    for step_data in payload.get("steps") or []:
        step = add_playbook_step(
            baseline.id,
            int(step_data.get("step_number") or 1),
            step_data.get("title") or "Imported step",
            technique_id=step_data.get("technique_id") or "",
            required_rule=imported_ids.get(step_data.get("required_rule") or "", ""),
            description=step_data.get("description") or "",
            tactic=step_data.get("tactic") or "",
            client_id=client_id,
        )
        for technique_id in step_data.get("techniques") or []:
            add_step_technique(step.id, technique_id, client_id=client_id)
        for detection in step_data.get("detections") or []:
            source = detection.get("source") or "manual"
            if source != "sigma" and not system_id:
                continue
            det = add_step_detection(
                step.id,
                imported_ids.get(detection.get("rule_ref"), detection.get("rule_ref") or ""),
                note=detection.get("display_name") or detection.get("note") or "",
                source=source,
                client_id=client_id,
            )
            if source != "sigma":
                apply_detection(det.id, system_id=system_id, client_id=client_id)
    return baseline.id


@router.post("/api/systems/import.json")
async def import_system_configuration(
    user: RequireUser,
    client_id: ActiveClient,
    file: UploadFile = File(...),
    include_baselines: bool = Form(True),
    include_rules: bool = Form(True),
    include_devices: bool = Form(False),
    conflict: str = Form("create"),
):
    """Import a system export as copies in the active tenant."""
    try:
        payload = json.loads((await file.read()).decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid JSON export: {exc}")
    if payload.get("tide_export_version") != 1 or payload.get("export_type") != "system":
        raise HTTPException(status_code=422, detail="Unsupported TIDE system export")
    existing_system_names = {
        item.system.name for item in (get_system_summaries(client_id=client_id) or [])
    }
    incoming_names = [str(item.get("name") or "Imported system") for item in payload.get("systems") or []]
    conflicts = [name for name in incoming_names if name in existing_system_names]
    if conflicts and conflict == "prompt":
        return JSONResponse(
            {"status": "conflict", "names": conflicts},
            status_code=409,
        )

    system_ids = {}
    existing_systems = {
        summary.system.name: summary.system
        for summary in (get_system_summaries(client_id=client_id) or [])
    }
    for source in payload.get("systems") or []:
        source_name = str(source.get("name") or "Imported system")
        existing_system = existing_systems.get(source_name) if conflict == "override" else None
        if existing_system:
            created = edit_system(
                existing_system.id,
                SystemUpdate(
                    name=source_name,
                    description=source.get("description") or "",
                    classification=source.get("classification"),
                ),
                client_id=client_id,
            )
        else:
            created_name = _import_name(source_name, set(existing_systems))
            created = add_system(
                SystemCreate(
                    name=created_name,
                    description=source.get("description") or "",
                    classification=source.get("classification"),
                ),
                client_id=client_id,
            )
        system_ids[source.get("id")] = created.id
        if include_devices:
            for host in source.get("hosts") or []:
                imported_host = add_host(
                    created.id,
                    HostCreate(
                        name=host.get("name") or "Imported host",
                        ip_address=host.get("ip_address"),
                        os=host.get("os"),
                        hardware_vendor=host.get("hardware_vendor"),
                        model=host.get("model"),
                        source=host.get("source") or "manual",
                    ),
                    client_id=client_id,
                )
                for software in host.get("software") or []:
                    add_host_software(
                        imported_host.id,
                        created.id,
                        SoftwareCreate(
                            name=software.get("name") or "Imported software",
                            version=software.get("version"),
                            vendor=software.get("vendor"),
                            cpe=software.get("cpe"),
                            source=software.get("source") or "manual",
                        ),
                        client_id=client_id,
                    )

    # Each system gets its own baseline. A file exported before baselines belonged to systems
    # can list one baseline against several systems; each of them gets a full copy.
    payloads = {b.get("baseline_id"): b for b in payload.get("baselines") or []} if include_baselines else {}
    assignments_created = 0
    for assignment in payload.get("assignments") or [] if include_baselines else []:
        new_system_id = system_ids.get(assignment.get("system_id"))
        baseline_payload = payloads.get(assignment.get("playbook_id"))
        if not new_system_id or not baseline_payload:
            continue
        await _import_baseline_payload(
            baseline_payload if include_rules else {**baseline_payload, "rules": []},
            client_id, system_id=new_system_id,
        )
        assignments_created += 1
    return {
        "status": "ok",
        "systems": len(system_ids),
        "baselines": assignments_created,
        "assignments": assignments_created,
    }


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

    # The Baselines page, showing the template the techniques went into.
    resp = HTMLResponse("")
    resp.headers["HX-Redirect"] = f"/baselines?baseline_id={quote(pb.id)}&group=baseline"
    return resp


@router.delete("/api/baselines/{baseline_id}", response_class=HTMLResponse)
def api_delete_baseline(request: Request, baseline_id: str, user: RequireUser, client_id: ActiveClient):
    """Delete a template. Systems keep their own copies of it."""
    if not get_template(baseline_id, client_id=client_id):
        raise HTTPException(status_code=404, detail="Baseline not found")
    delete_playbook(baseline_id, client_id=client_id)
    resp = HTMLResponse("")
    resp.headers["HX-Redirect"] = "/baselines"
    return resp


@router.put("/api/baselines/{baseline_id}", response_class=HTMLResponse)
def api_update_baseline(
    request: Request, baseline_id: str, user: RequireUser, client_id: ActiveClient,
    name: str = Form(...), description: str = Form(""),
):
    if not get_template(baseline_id, client_id=client_id):
        raise HTTPException(status_code=404, detail="Baseline not found")
    update_playbook(baseline_id, name=name, description=description, client_id=client_id)
    # Reload the Baselines page as it was (its filters are in the address bar), so the new name
    # shows in the grid and the filter bar alike.
    resp = HTMLResponse("")
    resp.headers["HX-Refresh"] = "true"
    return resp


def _template_step_or_404(step_id: str, client_id: str) -> Dict[str, Any]:
    """The owner of a template's step. A system's step is edited from its system, never here."""
    owner = get_step_owner(step_id)
    if not owner or owner["system_id"] or owner["client_id"] != client_id:
        raise HTTPException(status_code=404, detail="Technique not found")
    return owner


def _technique_fields(title: str, tactic: str, description: str, technique_ids: str,
                      current_tactic: str = "") -> Dict[str, Any]:
    """The form's fields, cleaned. The tactic is the first ATT&CK row's (the picker sends it);
    with no rows at all, a technique keeps the tactic it had."""
    title = (title or "").strip()
    if not title:
        raise HTTPException(status_code=422, detail="A technique needs a title")
    tactic = (tactic or "").strip()
    return {"title": title, "tactic": canonical_tactic(tactic) if tactic else (current_tactic or ""),
            "description": (description or "").strip(), "technique_ids": parse_technique_ids(technique_ids)}


def _technique_picker_context(step=None) -> Dict[str, Any]:
    """What components/technique_form.html needs for its tactic -> technique rows (the same
    picker as the rule form), with the step's current ATT&CK ids preselected."""
    from app.api.rules import _build_technique_groups
    groups, _ = _build_technique_groups(get_database_service())
    for g in groups:
        g["tactic"] = canonical_tactic(g["tactic"])
    selected = []
    if step:
        selected = [t.technique_id for t in step.techniques] or ([step.technique_id] if step.technique_id else [])
    return {"technique_groups": groups, "selected_ids": selected}


def _actor(user) -> Optional[str]:
    return user.username if user else None


# ── A template's techniques, on the Baselines page: the same window as a system's technique,
# without Coverage or History (a template has neither until it is applied to a system). ──

def _template_window(request: Request, step_id: str, client_id: str, changed: bool = False):
    """The template technique window; ``changed`` tells the page to refresh its grid."""
    from app.inventory_engine import get_template_step_detail
    detail = get_template_step_detail(step_id, client_id=client_id)
    if not detail:
        return HTMLResponse('<div class="empty-state-text">This technique no longer exists.</div>', status_code=404)
    resp = _render("components/template_step_modal.html", request, {"detail": detail})
    if changed:
        resp.headers["HX-Trigger"] = "stepsChanged"
    return resp


@router.get("/api/baselines/techniques-new", response_class=HTMLResponse)
def api_new_template_technique_form(request: Request, user: CurrentUser, client_id: ActiveClient,
                                    baseline_id: str = Query("")):
    """The template technique window, blank, for a new technique in one of the templates."""
    templates = [{"id": b["id"], "name": b["name"]} for b in get_baselines_overview(client_id=client_id)]
    if not templates:
        raise HTTPException(status_code=404, detail="Create a template first")
    return _blank_technique_window(
        request, "components/template_step_modal.html", "/api/baselines/techniques", templates, baseline_id,
        "Added to this template only. Systems that already use it keep their own copy.")


@router.post("/api/baselines/techniques", response_class=HTMLResponse)
def api_add_template_technique(
    request: Request, user: RequireUser, client_id: ActiveClient,
    playbook_id: str = Form(...), title: str = Form(...), technique_ids: str = Form(""),
    description: str = Form(""), tactic: str = Form(""),
):
    """Add a technique to a template, then open it."""
    if not get_template(playbook_id, client_id=client_id):
        raise HTTPException(status_code=404, detail="Baseline not found")
    step = add_technique(playbook_id, **_technique_fields(title, tactic, description, technique_ids),
                         actor=_actor(user), client_id=client_id)
    return _template_window(request, step.id, client_id, changed=True)


@router.get("/api/baselines/tactics/{tactic_id}", response_class=HTMLResponse)
def api_template_technique_window(request: Request, tactic_id: str, user: CurrentUser, client_id: ActiveClient):
    """One template technique, in its window."""
    _template_step_or_404(tactic_id, client_id)
    return _template_window(request, tactic_id, client_id)


@router.get("/api/baselines/tactics/{tactic_id}/edit", response_class=HTMLResponse)
def api_edit_tactic_form(request: Request, tactic_id: str, user: CurrentUser, client_id: ActiveClient,
                         part: str = Query("")):
    """Edit a template technique in place, in its window: ``part`` 'description' (title and
    description) or 'mitre' (ATT&CK techniques). Save or Cancel returns the window."""
    _template_step_or_404(tactic_id, client_id)
    step = get_playbook_step(tactic_id)
    return _render("components/technique_form.html", request, {
        "step": step, **_technique_picker_context(step),
        "part": part if part in ("description", "mitre") else "",
        "action": f"/api/baselines/tactics/{tactic_id}", "method": "put", "target": "#modal-container",
        "cancel": f"/api/baselines/tactics/{tactic_id}",
        "note": "Changes this template only. Systems that already use it keep their own copy.",
    })


@router.put("/api/baselines/tactics/{tactic_id}", response_class=HTMLResponse)
def api_update_tactic(
    request: Request, tactic_id: str, user: RequireUser, client_id: ActiveClient,
    title: str = Form(...), tactic: str = Form(""), description: str = Form(""),
    technique_ids: str = Form(""),
):
    _template_step_or_404(tactic_id, client_id)
    current = get_playbook_step(tactic_id)
    update_technique(tactic_id, **_technique_fields(title, tactic, description, technique_ids, current.tactic),
                     actor=_actor(user), client_id=client_id)
    return _template_window(request, tactic_id, client_id, changed=True)


@router.put("/api/baselines/tactics/{tactic_id}/risks", response_class=HTMLResponse)
def api_template_technique_risks(
    request: Request, tactic_id: str, user: RequireUser, client_id: ActiveClient,
    priority: str = Form(""), category: str = Form(""),
):
    """A template technique's priority and category: copied to each system it is applied to."""
    from app.inventory_engine import update_step_risks
    _template_step_or_404(tactic_id, client_id)
    update_step_risks(tactic_id, None, priority=priority, category=category, actor=_actor(user), client_id=client_id)
    return _template_window(request, tactic_id, client_id, changed=True)


@router.delete("/api/baselines/tactics/{tactic_id}", response_class=HTMLResponse)
def api_delete_tactic(request: Request, tactic_id: str, user: RequireUser, client_id: ActiveClient):
    """Delete a technique from a template. Systems keep their own copies of it."""
    _template_step_or_404(tactic_id, client_id)
    delete_playbook_step(tactic_id, client_id=client_id)
    resp = HTMLResponse("")
    resp.headers["HX-Trigger"] = "stepsChanged"
    return resp


@router.get("/api/baselines/tactics/{tactic_id}/sigma", response_class=HTMLResponse)
def api_template_technique_sigma(request: Request, tactic_id: str, user: CurrentUser, client_id: ActiveClient,
                                 q: str = Query("")):
    _template_step_or_404(tactic_id, client_id)
    return _sigma_suggestions(request, tactic_id, q, f"/api/baselines/tactics/{tactic_id}")


@router.get("/api/baselines/tactics/{tactic_id}/sigma/convert", response_class=HTMLResponse)
def api_template_sigma_convert_form(request: Request, tactic_id: str, user: CurrentUser, client_id: ActiveClient,
                                    sigma_id: str = Query(...)):
    _template_step_or_404(tactic_id, client_id)
    return _sigma_convert_form(request, client_id, sigma_id, f"/api/baselines/tactics/{tactic_id}", template=True)


@router.post("/api/baselines/tactics/{tactic_id}/sigma/convert", response_class=HTMLResponse)
def api_template_sigma_convert(request: Request, tactic_id: str, user: RequireUser, client_id: ActiveClient,
                               sigma_id: str = Form(...), pipeline: str = Form("none")):
    _template_step_or_404(tactic_id, client_id)
    return _sigma_convert(request, user, client_id, sigma_id, pipeline, f"/api/baselines/tactics/{tactic_id}",
                          template=True)


@router.post("/api/baselines/{baseline_id}/apply/{system_id}", response_class=HTMLResponse)
def api_apply_baseline(request: Request, baseline_id: str, system_id: str, user: RequireUser, client_id: ActiveClient):
    try:
        copy = apply_baseline(system_id, baseline_id, client_id=client_id)
    except ValueError as e:
        return HTMLResponse(str(e), status_code=400)
    if request.query_params.get("return") == "system-dialog":
        resp = _baselines_dialog(request, system_id, client_id)
        resp.headers["HX-Trigger"] = "stepsChanged"
        return resp
    # From the template's page: show the system with its new copy.
    resp = HTMLResponse("")
    resp.headers["HX-Redirect"] = f"/systems/{system_id}?baseline_id={copy.playbook_id}"
    return resp


@router.delete("/api/baselines/{baseline_id}/apply/{system_id}", response_class=HTMLResponse)
def api_remove_baseline(request: Request, baseline_id: str, system_id: str, user: RequireUser, client_id: ActiveClient):
    """Remove a system's own baseline (``baseline_id`` is the system's copy, not the template)."""
    try:
        remove_baseline(system_id, baseline_id, client_id=client_id)
    except ValueError as e:
        return HTMLResponse(str(e), status_code=400)
    resp = _baselines_dialog(request, system_id, client_id)
    resp.headers["HX-Trigger"] = "stepsChanged"
    return resp


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


def _system_step_or_404(system_id: str, step_id: str, client_id: str) -> None:
    """A step may only be changed through the system whose baseline it is in."""
    owner = get_step_owner(step_id)
    if not get_system(system_id, client_id=client_id) or not owner or owner["system_id"] != system_id:
        raise HTTPException(status_code=404, detail="Technique not found on this system")


@router.post("/api/baselines/tactics/{tactic_id}/detections", response_class=HTMLResponse)
def api_add_tactic_detection(
    request: Request, tactic_id: str, user: RequireUser, client_id: ActiveClient,
    rule_ref: str = Form(""), note: str = Form(""), source: str = Form("manual"),
    system_id: str = Form(...), rule_scope: str = Form(""), replace_id: str = Form(""),
):
    """Map a rule to one of a system's techniques, from its technique window. With
    ``replace_id`` (Relink on a mapping whose rule TIDE can't find), that mapping is pointed at
    the chosen rule instead, keeping its id and history."""
    _system_step_or_404(system_id, tactic_id, client_id)
    # The SIEM picker posts "<siem_id>|<space>" alongside the rule id, so the mapping records
    # which destination's copy was chosen. Manual and Sigma entries have no destination.
    scope_siem, _, scope_space = (rule_scope or "").partition("|")
    scope_siem, scope_space = scope_siem.strip() or None, scope_space.strip() or None
    if replace_id:
        if replace_id not in {d.id for d in get_playbook_step(tactic_id, client_id=client_id).detections}:
            raise HTTPException(status_code=404, detail="Mapping not found on this technique")
        if not (rule_ref and scope_siem):
            raise HTTPException(status_code=422, detail="Relinking needs a rule picked from the SIEM")
        relink_step_detection(replace_id, rule_ref=rule_ref, siem_id=scope_siem, space=scope_space, note=note,
                              actor=_actor(user), client_id=client_id)
        det_id = replace_id
    else:
        det = add_step_detection(
            tactic_id, rule_ref, note, source, client_id=client_id,
            siem_id=scope_siem, space=scope_space, created_by=_actor(user),
        )
        det_id = det.id if det else None
    # The technique is this system's own, so mapping a rule to it applies it here. Sigma rules
    # can't be applied directly (they need converting and deploying first).
    if det_id and (source or "manual") != "sigma":
        apply_detection(det_id, system_id=system_id, client_id=client_id)
    resp = _step_modal_response(request, system_id, tactic_id, client_id)
    resp.headers["HX-Trigger"] = "stepsChanged"
    return resp


@router.delete("/api/baselines/tactics/detections/{detection_row_id}", response_class=HTMLResponse)
def api_remove_tactic_detection(
    request: Request, detection_row_id: str, user: RequireUser, client_id: ActiveClient,
    step_id: str = Query(...), system_id: str = Query(...),
):
    _system_step_or_404(system_id, step_id, client_id)
    step = get_playbook_step(step_id, client_id=client_id)
    if detection_row_id not in {d.id for d in step.detections}:
        raise HTTPException(status_code=404, detail="Mapping not found on this technique")
    remove_step_detection(detection_row_id, client_id=client_id, actor=_actor(user))
    resp = _step_modal_response(request, system_id, step_id, client_id)
    resp.headers["HX-Trigger"] = "stepsChanged"
    return resp


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
    # Rules whose tags match this step's techniques, suggested first. Keyed by destination as
    # well as rule id: the same rule in staging and in production are two different things to
    # map, so neither may hide the other from the list below.
    def scope_of(rule) -> str:
        return f"{getattr(rule, 'siem_id', None) or ''}|{getattr(rule, 'space', None) or 'default'}"

    mapped = []
    mapped_scopes = set()
    for tid in technique_ids:
        for r in db.get_rules_for_technique(tid, enabled_only=False, client_id=client_id):
            key = (r.rule_id, scope_of(r))
            if key not in mapped_scopes:
                mapped_scopes.add(key)
                mapped.append(r)
    all_rules = get_all_siem_rules(client_id=client_id)
    q_lower = q.strip().lower()
    if q_lower:
        mapped = [r for r in mapped if q_lower in r.name.lower()]
        all_rules = [r for r in all_rules if q_lower in r["name"].lower()]
    mapped.sort(key=lambda r: (r.name or "", scope_of(r)))
    all_rules.sort(key=lambda r: (r["name"] or "", r.get("destination") or ""))
    # "All" leaves out only the copies listed above it: a tagged rule past the first 50 must still
    # be offered somewhere, or it cannot be picked at all.
    mapped = mapped[:50]
    shown = {f"{r.rule_id}|{scope_of(r)}" for r in mapped}
    all_rules = [r for r in all_rules
                 if f"{r['rule_id']}|{r.get('siem_id') or ''}|{r.get('space') or 'default'}" not in shown]

    destinations = db.get_client_siems(client_id) or []
    dest_key = lambda d: f"{d.get('id')}|{d.get('space') or 'default'}"  # noqa: E731
    return _render("partials/siem_rule_options.html", request, {
        "mapped_rules": mapped,
        "all_rules": all_rules[:100],
        "query": q,
        "dest_names": {dest_key(d): (d.get("name") or d.get("label") or d.get("space")) for d in destinations},
        "dest_colors": {dest_key(d): d.get("color") for d in destinations},
    })


def _system_not_found(system_id: str, client_id: str) -> Optional[HTMLResponse]:
    """A 404 unless ``system_id`` is a system of the active client, else None.

    Every system-scoped endpoint checks this before reading anything keyed by the id: a row can
    reference a system that is not this tenant's (old data predating apply-time ownership checks
    does exactly that), and nothing may be served for a system the active client does not own.
    """
    if get_system(system_id, client_id=client_id):
        return None
    return HTMLResponse('<div class="empty-state-text">This system no longer exists.</div>', status_code=404)


def _coverage_destination_context(system_id: str, client_id: str = None) -> Dict[str, Any]:
    """Every destination this client has linked, each flagged with whether this SYSTEM counts it."""
    from app.inventory_engine import get_system_coverage_destinations
    from app.services.database import get_database_service as _db_svc

    counted = {(s, sp) for s, sp in get_system_coverage_destinations(system_id, client_id=client_id)}
    options = []
    for d in (_db_svc().get_client_siems(client_id) or [] if client_id else []):
        space = d.get("space") or "default"
        options.append({
            "siem_id": d.get("id"), "space": space,
            "name": d.get("name") or d.get("label") or space,
            "color": d.get("color"),
            "counted": (d.get("id"), space) in counted,
        })
    options.sort(key=lambda o: (o["name"] or "").lower())
    return {"coverage_destinations": options, "counted_total": sum(1 for o in options if o["counted"])}


def _render_system_baseline_coverage(request: Request, system_id: str, client_id: str = None):
    """Tell the system page its techniques changed. The page's metric strip and technique grid
    each refetch themselves on ``stepsChanged`` with whatever filters are active, so a caller
    never has to know, or reset, the view the user is looking at."""
    resp = HTMLResponse("")
    resp.headers["HX-Trigger"] = "stepsChanged"
    return resp


def _step_modal_response(request: Request, system_id: str, step_id: str, client_id: str,
                         coverage_error: Optional[Dict[str, str]] = None):
    """Render the step window, or a graceful note when the step is gone."""
    from app.inventory_engine import get_step_detail_for_system

    missing = _system_not_found(system_id, client_id)
    if missing:
        return missing
    detail = get_step_detail_for_system(step_id, system_id, client_id=client_id)
    if not detail:
        return HTMLResponse('<div class="empty-state-text">This technique no longer exists.</div>', status_code=404)
    return _render("components/step_modal.html", request, {
        "detail": detail, "system_id": system_id, "coverage_error": coverage_error,
    })


@router.get("/api/systems/{system_id}/steps/{step_id}", response_class=HTMLResponse)
def api_system_step_modal(
    request: Request, system_id: str, step_id: str, user: CurrentUser, client_id: ActiveClient,
):
    """One baseline step, as seen from one system."""
    return _step_modal_response(request, system_id, step_id, client_id)


def _technique_form(request: Request, system_id: str, step, part: str = ""):
    """Edit a system's technique in place: the form replaces its window's Description
    (``part='description'``: title and description) or MITRE ATT&CK (``part='mitre'``) body;
    Save or Cancel returns the window."""
    return _render("components/technique_form.html", request, {
        "step": step, "target": "#modal-container", **_technique_picker_context(step),
        "action": f"/api/systems/{system_id}/steps/{step.id}", "method": "put",
        "part": part if part in ("description", "mitre") else "",
        "cancel": f"/api/systems/{system_id}/steps/{step.id}",
        "note": "Changes this system only. The template and other systems are not affected.",
    })


def _blank_technique_window(request: Request, template_name: str, create_url: str,
                            baselines: List[Dict[str, str]], selected: str, note: str, **context):
    """The technique window, blank (Add technique, or "+" beside its < >): every section shows,
    empty, and the only thing asked for is the title, in Description. Create makes the technique
    and the window becomes its own. ``selected`` preselects the baseline ("+" adds another to
    the same one)."""
    from app.inventory_engine import COVERAGE_KINDS, STEP_CATEGORIES, STEP_PRIORITIES
    blank = {
        "step": PlaybookStep(id="", playbook_id=selected), "status": None, "tactic": "",
        "risk_labels": {"priority": dict(STEP_PRIORITIES), "category": dict(STEP_CATEGORIES),
                        "coverage_kind": dict(COVERAGE_KINDS)},
        "blind_spots": [], "detections": [], "watched": [], "mapped_count": 0, "evidence_score": None,
        "technique_ids": [], "techniques": [], "history": [], "history_users": [],
        "baseline_id": selected, "baseline_name": "",
    }
    return _render(template_name, request, {
        **context, "detail": blank,
        "new": {"create_url": create_url, "baselines": baselines, "selected": selected, "note": note},
    })


@router.get("/api/systems/{system_id}/steps/{step_id}/sigma", response_class=HTMLResponse)
def api_system_technique_sigma(request: Request, system_id: str, step_id: str, user: CurrentUser, client_id: ActiveClient,
                               q: str = Query("")):
    """Sigma rules for a system's technique (see _sigma_suggestions)."""
    _system_step_or_404(system_id, step_id, client_id)
    return _sigma_suggestions(request, step_id, q, f"/api/systems/{system_id}/steps/{step_id}")


def _sigma_suggestions(request: Request, step_id: str, q: str, technique_url: str):
    """Sigma rules suggested for a technique from its ATT&CK techniques (or, with none, its
    tactic), or, with ``q``, any SigmaHQ rule matching it. Potential rules -- never coverage.
    ``technique_url`` is the technique window's own address (a system's or a template's)."""
    from app import sigma_helper as sigma_mod
    step = get_playbook_step(step_id)
    ids = [t.technique_id for t in step.techniques] or ([step.technique_id] if step.technique_id else [])
    q = q.strip()
    if q:
        matches = sigma_mod.search_rules(query=q, limit=50)
    else:
        matches = []
        for tid in ids:
            matches += sigma_mod.search_rules(technique_filter=tid, limit=25)
        if not ids and step.tactic:
            slug = canonical_tactic(step.tactic).lower().replace(" ", "-")
            matches = sigma_mod.search_rules(query=f"attack.{slug}", limit=25)
    rules, seen = [], set()
    for r in matches:
        if r.get("id") and r["id"] not in seen:
            seen.add(r["id"])
            rules.append(r)
    return _render("partials/technique_sigma.html", request, {
        "rules": rules[:50 if q else 25], "query": q, "technique_ids": ids,
        "tactic": canonical_tactic(step.tactic) if step.tactic else "",
        "technique_url": technique_url,
    })


@router.put("/api/systems/{system_id}/steps/{step_id}/risks", response_class=HTMLResponse)
def api_system_technique_risks(
    request: Request, system_id: str, step_id: str, user: RequireUser, client_id: ActiveClient,
    priority: str = Form(""), category: str = Form(""),
):
    """Save a technique's priority and category on this system, then return its window."""
    from app.inventory_engine import update_step_risks
    _system_step_or_404(system_id, step_id, client_id)
    update_step_risks(step_id, system_id, priority=priority, category=category, actor=_actor(user), client_id=client_id)
    resp = _step_modal_response(request, system_id, step_id, client_id)
    resp.headers["HX-Trigger"] = "stepsChanged"
    return resp


@router.post("/api/systems/{system_id}/steps/{step_id}/coverage", response_class=HTMLResponse)
def api_add_technique_coverage(
    request: Request, system_id: str, step_id: str, user: RequireUser, client_id: ActiveClient,
    kind: str = Form(...), title: str = Form(""), url: str = Form(""), rationale: str = Form(""),
):
    """Record a dashboard, report or log watching this technique on this system (non-alerting
    coverage), from Add coverage. A refused entry comes back with the form open and the reason."""
    from app.inventory_engine import add_step_coverage
    _system_step_or_404(system_id, step_id, client_id)
    try:
        add_step_coverage(step_id, system_id, kind=kind, title=title, url=url, rationale=rationale,
                          actor=_actor(user), client_id=client_id)
    except ValueError as exc:
        return _step_modal_response(request, system_id, step_id, client_id,
                                    coverage_error={"message": str(exc), "kind": kind, "title": title,
                                                    "url": url, "rationale": rationale})
    resp = _step_modal_response(request, system_id, step_id, client_id)
    resp.headers["HX-Trigger"] = "stepsChanged"
    return resp


@router.put("/api/systems/{system_id}/steps/{step_id}/coverage/{coverage_id}", response_class=HTMLResponse)
def api_update_technique_coverage(
    request: Request, system_id: str, step_id: str, coverage_id: str, user: RequireUser, client_id: ActiveClient,
    kind: str = Form(...), title: str = Form(""), url: str = Form(""), rationale: str = Form(""),
):
    """Change one dashboard, report or log on this technique on this system. A refused change
    comes back with that card's form open and the reason."""
    from app.inventory_engine import update_step_coverage
    _system_step_or_404(system_id, step_id, client_id)
    try:
        found = update_step_coverage(coverage_id, step_id, system_id, kind=kind, title=title, url=url,
                                     rationale=rationale, actor=_actor(user), client_id=client_id)
    except ValueError as exc:
        return _step_modal_response(request, system_id, step_id, client_id,
                                    coverage_error={"id": coverage_id, "message": str(exc), "kind": kind,
                                                    "title": title, "url": url, "rationale": rationale})
    if not found:
        raise HTTPException(status_code=404, detail="Coverage not found on this technique")
    resp = _step_modal_response(request, system_id, step_id, client_id)
    resp.headers["HX-Trigger"] = "stepsChanged"
    return resp


@router.delete("/api/systems/{system_id}/steps/{step_id}/coverage/{coverage_id}", response_class=HTMLResponse)
def api_remove_technique_coverage(
    request: Request, system_id: str, step_id: str, coverage_id: str, user: RequireUser, client_id: ActiveClient,
):
    """Remove one dashboard, report or log from this technique on this system."""
    from app.inventory_engine import remove_step_coverage
    _system_step_or_404(system_id, step_id, client_id)
    if not remove_step_coverage(coverage_id, step_id, system_id, actor=_actor(user), client_id=client_id):
        raise HTTPException(status_code=404, detail="Coverage not found on this technique")
    resp = _step_modal_response(request, system_id, step_id, client_id)
    resp.headers["HX-Trigger"] = "stepsChanged"
    return resp


def _client_pipelines(client_id: str) -> List[Dict[str, str]]:
    """Pipelines a conversion can use here: pySigma's built-ins, then the saved pipeline files
    assigned to this client (Management → Sigma assets)."""
    from app import sigma_helper as sigma_mod
    from app.services.database import get_database_service
    out = [{"value": k, "label": v} for k, v in sigma_mod.get_available_pipelines().items()]
    try:
        assigned = get_database_service().list_sigma_asset_assignments("pipeline")
    except Exception:
        assigned = {}
    for p in sigma_mod.list_saved_pipelines():
        fname = p.get("filename") or ""
        if fname and any(c.get("id") == client_id for c in assigned.get(fname, [])):
            out.append({"value": f"file:{fname}", "label": p.get("display") or p.get("name") or fname})
    return out


@router.get("/api/systems/{system_id}/steps/{step_id}/sigma/convert", response_class=HTMLResponse)
def api_technique_sigma_convert_form(
    request: Request, system_id: str, step_id: str, user: CurrentUser, client_id: ActiveClient,
    sigma_id: str = Query(...),
):
    """Convert a suggested Sigma rule: choose the pipeline, then the Create Rule form opens."""
    _system_step_or_404(system_id, step_id, client_id)
    return _sigma_convert_form(request, client_id, sigma_id, f"/api/systems/{system_id}/steps/{step_id}")


def _sigma_convert_form(request: Request, client_id: str, sigma_id: str, technique_url: str, template: bool = False):
    from app import sigma_helper as sigma_mod
    rule = sigma_mod.get_rule_by_id(sigma_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Sigma rule not found")
    return _render("partials/technique_sigma_convert.html", request, {
        "rule": rule, "technique_url": technique_url, "template": template, "pipelines": _client_pipelines(client_id),
    })


@router.post("/api/systems/{system_id}/steps/{step_id}/sigma/convert", response_class=HTMLResponse)
def api_technique_sigma_convert(
    request: Request, system_id: str, step_id: str, user: RequireUser, client_id: ActiveClient,
    sigma_id: str = Form(...), pipeline: str = Form("none"),
):
    """Convert a system technique's Sigma rule (see _sigma_convert)."""
    _system_step_or_404(system_id, step_id, client_id)
    return _sigma_convert(request, user, client_id, sigma_id, pipeline, f"/api/systems/{system_id}/steps/{step_id}")


def _sigma_convert(request: Request, user, client_id: str, sigma_id: str, pipeline: str, technique_url: str,
                   template: bool = False):
    """Convert the Sigma rule (Elastic, Lucene) and open the Create Rule form filled in with it.
    Creating the rule does not map it anywhere: mapping it to a technique is a separate step."""
    import yaml
    from app import sigma_helper as sigma_mod
    from app.api.rules import _build_rule_form_context
    from app.api.sigma import rule_form_prefill
    from app.services.database import get_database_service
    rule = sigma_mod.get_rule_by_id(sigma_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Sigma rule not found")
    allowed = {p["value"] for p in _client_pipelines(client_id)}
    pipeline = pipeline if pipeline in allowed else "none"
    raw_yaml = rule.get("_raw_yaml", "")
    ok, query = sigma_mod.convert_sigma_rule(
        yaml_content=raw_yaml, backend="elasticsearch",
        pipeline="none" if pipeline.startswith("file:") else pipeline,
        pipeline_file=pipeline[5:] if pipeline.startswith("file:") else "",
    )
    if not ok:
        return _render("partials/technique_sigma_convert.html", request, {
            "rule": rule, "technique_url": technique_url, "template": template,
            "pipelines": _client_pipelines(client_id), "selected": pipeline, "error": query,
        })
    prefill = rule_form_prefill(yaml.safe_load(raw_yaml) or {}, query, "elasticsearch", "", user.username or "")
    return _templates(request).TemplateResponse(
        request, "components/rule_create_form.html",
        _build_rule_form_context(get_database_service(), client_id, user.username, "/api/rules/create",
                                 "Create Rule", "Create Rule", prefill=prefill),
    )


@router.get("/api/systems/{system_id}/steps-new", response_class=HTMLResponse)
def api_system_technique_new(request: Request, system_id: str, user: CurrentUser, client_id: ActiveClient,
                             baseline_id: str = Query("")):
    """The technique window, blank, for a new technique in one of this system's baselines."""
    missing = _system_not_found(system_id, client_id)
    if missing:
        return missing
    baselines = [{"id": b["playbook_id"], "name": b["playbook_name"]}
                 for b in get_system_baselines(system_id, include_detection_details=False, client_id=client_id)]
    if not baselines:
        raise HTTPException(status_code=404, detail="Apply or add a baseline to this system first")
    return _blank_technique_window(
        request, "components/step_modal.html", f"/api/systems/{system_id}/steps", baselines, baseline_id,
        "Added to this system's baseline only. The template it came from is not changed.", system_id=system_id)


@router.post("/api/systems/{system_id}/steps", response_class=HTMLResponse)
def api_system_technique_add(
    request: Request, system_id: str, user: RequireUser, client_id: ActiveClient,
    playbook_id: str = Form(...), title: str = Form(...), tactic: str = Form(""),
    description: str = Form(""), technique_ids: str = Form(""),
):
    """Add a technique to one of this system's baselines, then open it."""
    missing = _system_not_found(system_id, client_id)
    if missing:
        return missing
    if not _system_baseline_or_none(system_id, playbook_id, client_id):
        raise HTTPException(status_code=404, detail="Baseline not found on this system")
    step = add_technique(playbook_id, **_technique_fields(title, tactic, description, technique_ids),
                         actor=_actor(user), client_id=client_id)
    resp = _step_modal_response(request, system_id, step.id, client_id)
    resp.headers["HX-Trigger"] = "stepsChanged"
    return resp


@router.get("/api/systems/{system_id}/steps/{step_id}/edit", response_class=HTMLResponse)
def api_system_technique_edit(request: Request, system_id: str, step_id: str, user: CurrentUser, client_id: ActiveClient,
                              part: str = Query("")):
    _system_step_or_404(system_id, step_id, client_id)
    return _technique_form(request, system_id, get_playbook_step(step_id), part=part)


@router.put("/api/systems/{system_id}/steps/{step_id}", response_class=HTMLResponse)
def api_system_technique_update(
    request: Request, system_id: str, step_id: str, user: RequireUser, client_id: ActiveClient,
    title: str = Form(...), tactic: str = Form(""), description: str = Form(""),
    technique_ids: str = Form(""),
):
    _system_step_or_404(system_id, step_id, client_id)
    current = get_playbook_step(step_id)
    update_technique(step_id, **_technique_fields(title, tactic, description, technique_ids, current.tactic),
                     actor=_actor(user), client_id=client_id)
    resp = _step_modal_response(request, system_id, step_id, client_id)
    resp.headers["HX-Trigger"] = "stepsChanged"
    return resp


@router.delete("/api/systems/{system_id}/steps/{step_id}", response_class=HTMLResponse)
def api_system_technique_remove(request: Request, system_id: str, step_id: str, user: RequireUser, client_id: ActiveClient):
    """Remove a technique from this system's baseline, with its mappings, gaps and history."""
    _system_step_or_404(system_id, step_id, client_id)
    delete_playbook_step(step_id, client_id=client_id)
    resp = HTMLResponse("")
    resp.headers["HX-Trigger"] = "stepsChanged"
    return resp


@router.get("/api/systems/{system_id}/steps", response_class=HTMLResponse)
def api_system_steps_grid(
    request: Request, system_id: str, user: CurrentUser, client_id: ActiveClient,
):
    """The filtered, sorted and optionally grouped technique grid (or table) for one system."""
    from app.inventory_engine import get_system_steps, group_system_steps

    missing = _system_not_found(system_id, client_id)
    if missing:
        return missing
    f = _step_grid_filters(request)
    tactic_sort = f["tactic_sort"] or "attack"
    data = get_system_steps(
        system_id, client_id=client_id, search=f["search"], tactic=f["tactic"],
        status=f["status"], mapping=f["mapping"], baseline_id=f["baseline_id"],
        tactic_sort=tactic_sort, sort_name=f["sort_name"],
    )
    return _render("partials/system_steps_grid.html", request, {
        "system_id": system_id, **data,
        "groups": group_system_steps(data["steps"], f["group"], tactic_sort),
        "view": f["view"] or "cards",
        "tactic_sort": tactic_sort, "sort_name": f["sort_name"],
    })


@router.get("/api/systems/{system_id}/steps-metrics", response_class=HTMLResponse)
def api_system_steps_metrics(
    request: Request, system_id: str, user: CurrentUser, client_id: ActiveClient,
):
    """Whole-baseline rollups for the metric strip -- never the filtered page's counts."""
    from app.inventory_engine import get_system_steps

    missing = _system_not_found(system_id, client_id)
    if missing:
        return missing
    data = get_system_steps(system_id, client_id=client_id)
    return _render("partials/system_steps_metrics.html", request, {
        "system_id": system_id, **data,
    })


@router.post("/api/systems/{system_id}/coverage-destinations", response_class=HTMLResponse)
async def api_set_coverage_destinations(
    request: Request, system_id: str, user: RequireUser, client_id: ActiveClient,
):
    """Set which destinations count toward this system's coverage.

    Ticking nothing is allowed and means "not answered yet", which reads as undefined rather
    than as 0% -- see get_system_baselines.
    """
    from app.inventory_engine import set_system_coverage_destinations

    missing = _system_not_found(system_id, client_id)
    if missing:
        return missing
    form = await request.form()
    allowed = {
        (d.get("id"), d.get("space") or "default")
        for d in (get_database_service().get_client_siems(client_id) or [])
    }
    scopes = []
    for raw in form.getlist("scope"):
        siem_id, _, space = str(raw or "").partition("|")
        pair = (siem_id.strip(), space.strip() or "default")
        if pair[0] and pair in allowed:   # never store a destination this client isn't linked to
            scopes.append(pair)
    set_system_coverage_destinations(
        system_id, scopes, client_id=client_id,
        actor=_actor(user),
    )
    resp = _render("partials/system_siem_coverage_dialog.html", request, {
        "system_id": system_id, "saved": True, **_coverage_destination_context(system_id, client_id),
    })
    resp.headers["HX-Trigger"] = "stepsChanged"
    return resp


@router.get("/api/systems/{system_id}/siem-coverage", response_class=HTMLResponse)
def api_siem_coverage_dialog(request: Request, system_id: str, user: CurrentUser, client_id: ActiveClient):
    """Which SIEM destinations count toward this system's coverage."""
    missing = _system_not_found(system_id, client_id)
    if missing:
        return missing
    return _render("partials/system_siem_coverage_dialog.html", request, {
        "system_id": system_id, **_coverage_destination_context(system_id, client_id),
    })


def _baselines_dialog(request: Request, system_id: str, client_id: str):
    """Manage baselines: this system's own (edit, remove), every template (apply, again if need
    be: a second copy is named "<name> (copy)"), and starting an empty one."""
    return _render("partials/system_baselines_dialog.html", request, {
        "system_id": system_id,
        "applied": get_system_baselines(system_id, include_detection_details=False, client_id=client_id),
        "available": list_playbooks(client_id=client_id),
    })


@router.post("/api/systems/{system_id}/baselines", response_class=HTMLResponse)
def api_system_baseline_create(
    request: Request, system_id: str, user: RequireUser, client_id: ActiveClient,
    name: str = Form(...), description: str = Form(""),
):
    """Start an empty baseline of this system's own, from the Manage baselines window."""
    missing = _system_not_found(system_id, client_id)
    if missing:
        return missing
    if not name.strip():
        raise HTTPException(status_code=422, detail="A baseline needs a name")
    create_system_baseline(system_id, name.strip(), description.strip(), client_id=client_id)
    resp = _baselines_dialog(request, system_id, client_id)
    resp.headers["HX-Trigger"] = "stepsChanged"
    return resp


@router.get("/api/systems/{system_id}/baselines/{baseline_id}/edit", response_class=HTMLResponse)
def api_system_baseline_edit_form(request: Request, system_id: str, baseline_id: str, user: CurrentUser, client_id: ActiveClient):
    """Rename or re-describe one of this system's own baselines (a window)."""
    missing = _system_not_found(system_id, client_id)
    if missing:
        return missing
    baseline = _system_baseline_or_none(system_id, baseline_id, client_id)
    if not baseline:
        raise HTTPException(status_code=404, detail="Baseline not found on this system")
    return _render("partials/system_baseline_edit_dialog.html", request, {
        "system": get_system(system_id, client_id=client_id), "baseline": baseline,
    })


@router.put("/api/systems/{system_id}/baselines/{baseline_id}", response_class=HTMLResponse)
def api_system_baseline_update(
    request: Request, system_id: str, baseline_id: str, user: RequireUser, client_id: ActiveClient,
    name: str = Form(...), description: str = Form(""),
):
    """Rename this system's own baseline, then return to Manage baselines. Only this system's
    baseline changes; templates and other systems keep their own name and description."""
    missing = _system_not_found(system_id, client_id)
    if missing:
        return missing
    if not _system_baseline_or_none(system_id, baseline_id, client_id):
        raise HTTPException(status_code=404, detail="Baseline not found on this system")
    if not name.strip():
        raise HTTPException(status_code=422, detail="A baseline needs a name")
    update_playbook(baseline_id, name=name.strip(), description=description.strip(), client_id=client_id)
    resp = _baselines_dialog(request, system_id, client_id)
    resp.headers["HX-Trigger"] = "stepsChanged"
    return resp


@router.get("/api/systems/{system_id}/baselines-dialog", response_class=HTMLResponse)
def api_system_baselines_dialog(request: Request, system_id: str, user: CurrentUser, client_id: ActiveClient):
    """Apply a baseline to this system, or remove one."""
    missing = _system_not_found(system_id, client_id)
    if missing:
        return missing
    return _baselines_dialog(request, system_id, client_id)


# ---------------------------------------------------------------------------
# Blind Spot CRUD
# ---------------------------------------------------------------------------

def _review_date(value: str):
    """A known gap's review date from a form field: '' is no date; anything unparsable is a 400."""
    from datetime import date
    if not (value or "").strip():
        return None
    try:
        return date.fromisoformat(value.strip())
    except ValueError:
        raise HTTPException(status_code=400, detail="Review date must be a date (YYYY-MM-DD)")


@router.post("/api/blind-spots", response_class=HTMLResponse)
def api_add_blind_spot(
    request: Request, user: RequireUser, client_id: ActiveClient,
    entity_type: str = Form(...), entity_id: str = Form(...),
    reason: str = Form(...),
    system_id: str = Form(None), host_id: str = Form(None),
    redirect_target: str = Form(""),
    override_type: str = Form("gap"),
    review_by: str = Form(""),
):
    if entity_type == "tactic":
        # A technique's gap or N/A belongs to the system whose baseline the technique is in.
        _system_step_or_404(system_id or "", entity_id, client_id)
    username = user.username if user else ""
    add_blind_spot(entity_type, entity_id, reason,
                   system_id=system_id or None, host_id=host_id or None,
                   created_by=username, override_type=override_type or "gap",
                   client_id=client_id, review_by=_review_date(review_by))
    if entity_type == "tactic":
        resp = _step_modal_response(request, system_id, entity_id, client_id)
        resp.headers["HX-Trigger"] = "stepsChanged"
        return resp
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
    return HTMLResponse("")


@router.put("/api/blind-spots/{blind_spot_id}", response_class=HTMLResponse)
def api_edit_blind_spot(
    request: Request, blind_spot_id: str, user: RequireUser, client_id: ActiveClient,
    entity_id: str = Form(...), system_id: str = Form(...),
    reason: str = Form(...), override_type: str = Form("gap"), review_by: str = Form(""),
):
    """Edit a technique's known gap / N/A on one system in place; the history keeps the old one."""
    _system_step_or_404(system_id, entity_id, client_id)
    owned = {b.id for b in get_blind_spots("tactic", entity_id, client_id=client_id) if b.system_id == system_id}
    if blind_spot_id not in owned:
        raise HTTPException(status_code=404, detail="Mark not found on this technique")
    update_blind_spot(blind_spot_id, reason.strip(), override_type, review_by=_review_date(review_by),
                      actor=_actor(user), client_id=client_id)
    resp = _step_modal_response(request, system_id, entity_id, client_id)
    resp.headers["HX-Trigger"] = "stepsChanged"
    return resp


@router.delete("/api/blind-spots/{blind_spot_id}", response_class=HTMLResponse)
def api_remove_blind_spot(
    request: Request, blind_spot_id: str, user: RequireUser, client_id: ActiveClient,
    entity_type: str = Query(""), entity_id: str = Query(""),
    system_id: str = Query(""),
):
    if entity_type == "tactic":
        _system_step_or_404(system_id, entity_id, client_id)
    remove_blind_spot(blind_spot_id, client_id=client_id,
                      actor=_actor(user))
    if entity_type == "tactic":
        resp = _step_modal_response(request, system_id, entity_id, client_id)
        resp.headers["HX-Trigger"] = "stepsChanged"
        return resp
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
            "| Baseline | Techniques | Covered | Gaps | Coverage |",
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
                    lines.append("| # | Technique | ATT&CK | Applied Rules | Status |")
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
        f"| Techniques | {data['total_steps']} |",
        f"| Mapped ATT&CK Techniques | {data['total_techniques']} |",
        "",
        "A template carries no coverage: each system it is applied to gets its own copy, "
        "and that system's report shows how its copy is covered.",
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

    lines += [
        "---",
        f"*{classification} — Report generated by TIDE — Threat Intelligence Detection Engineering*",
    ]
    return "\n".join(lines)
