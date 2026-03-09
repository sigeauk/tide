"""
API routes for the Asset Inventory / CVE Mapping module (Phase 2: Enterprise).

Page routes (HTML):
  GET  /systems                    Environments dashboard
  GET  /systems/{id}               Environment detail (hosts list)
  GET  /hosts/{host_id}            Host detail (software + CVE matches)
  GET  /cve-overview               Global CVE overview (all KEV, stats, import)
  GET  /cve/{cve_id}               CVE detail with MITRE techniques + detection

API routes (HTMX / JSON):
  POST   /api/inventory/systems              Create environment
  PUT    /api/inventory/systems/{id}         Update environment
  DELETE /api/inventory/systems/{id}         Delete environment
  POST   /api/inventory/systems/{id}/hosts   Create host in environment
  DELETE /api/inventory/hosts/{id}           Delete host
  POST   /api/inventory/systems/{id}/nessus-upload  Upload Nessus XML
  POST   /api/inventory/nessus-upload        Upload Nessus XML (with system_id query param)
  POST   /api/inventory/hosts/{id}/software  Add software to host
  DELETE /api/inventory/software/{sw_id}     Delete software

  GET    /api/inventory/hosts/{id}/cve-matches     CVE matches for host (partial)
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
from fastapi.responses import HTMLResponse
from app.api.deps import CurrentUser, RequireUser
from app.inventory_engine import (
    add_cve_technique_override, add_host, add_host_software, add_software, add_system,
    delete_host, delete_software, delete_system, edit_host, edit_software, edit_system,
    get_all_cve_overview, get_cve_detail, get_cve_overview_stats,
    get_host, get_host_summaries, get_host_vulnerabilities,
    get_inventory_stats, get_software, get_system, get_system_summaries,
    get_system_vulnerabilities, get_cve_detection, get_rules_for_cve_techniques,
    ingest_cisa_feed, list_host_software, list_hosts, list_software,
    list_systems, mark_cve_detected, parse_nessus_xml, remove_cve_technique_override,
    save_mitre_cve_map, unmark_cve_detected,
)
from app.models.inventory import HostCreate, HostUpdate, SoftwareCreate, SoftwareUpdate, SystemCreate, SystemUpdate

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


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------

@router.get("/systems", response_class=HTMLResponse)
def page_systems(request: Request, user: CurrentUser):
    summaries = get_system_summaries()
    systems = [s.system for s in summaries]  # for Nessus modal dropdown
    return _render("pages/systems.html", request, {
        "active_page": "systems", "summaries": summaries, "systems": systems, "user": user,
    })


@router.get("/systems/{system_id}", response_class=HTMLResponse)
def page_system_detail(request: Request, system_id: str, user: CurrentUser):
    system = get_system(system_id)
    if not system:
        raise HTTPException(status_code=404, detail="System not found")
    host_summaries = get_host_summaries(system_id)
    return _render("pages/system_detail.html", request, {
        "active_page": "systems", "system": system,
        "host_summaries": host_summaries, "user": user,
    })


@router.get("/hosts/{host_id}", response_class=HTMLResponse)
def page_host_detail(request: Request, host_id: str, user: CurrentUser):
    host = get_host(host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    system = get_system(host.system_id)
    software = list_host_software(host_id)
    vulns = get_host_vulnerabilities(host_id)
    return _render("pages/host_detail.html", request, {
        "active_page": "systems", "host": host, "system": system,
        "software": software, "vulns": vulns, "user": user,
    })


@router.get("/cve-overview", response_class=HTMLResponse)
def page_cve_overview(request: Request, user: CurrentUser):
    cves = get_all_cve_overview()
    stats = get_cve_overview_stats()
    return _render("pages/cve_overview.html", request, {
        "active_page": "cve_overview", "cves": cves,
        "matched_count": stats.matched_count,
        "stats": stats, "user": user,
    })


@router.get("/cve/{cve_id}", response_class=HTMLResponse)
def page_cve_detail(request: Request, cve_id: str, user: CurrentUser):
    from app.inventory_engine import get_cve_techniques
    cve = get_cve_detail(cve_id)
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found in CISA KEV")
    technique_rules = get_rules_for_cve_techniques(cve_id)
    techniques = get_cve_techniques(cve_id)
    # Unique systems from affected hosts (for per-system detection UI)
    affected_systems: dict = {}
    for h in cve.affected_hosts:
        if h.system_id not in affected_systems:
            affected_systems[h.system_id] = h.system_name or h.system_id
    return _render("pages/cve_detail.html", request, {
        "active_page": "cve_overview", "cve": cve, "user": user,
        "cve_id": cve.cve_id,
        "techniques": techniques,
        "system_detections": cve.system_detections,
        "affected_systems": affected_systems,
        "technique_rules": technique_rules,
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
        "toast": f"Environment '{system.name}' created.",
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
        "toast": "Environment deleted.",
    })


# ---------------------------------------------------------------------------
# Host API
# ---------------------------------------------------------------------------

@router.post("/api/inventory/systems/{system_id}/hosts", response_class=HTMLResponse)
async def api_create_host(request: Request, system_id: str, user: RequireUser):
    if not get_system(system_id):
        raise HTTPException(status_code=404, detail="Environment not found")
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
        raise HTTPException(status_code=422, detail="Host name is required")
    add_host(system_id, data)
    host_summaries = get_host_summaries(system_id)
    return _render("partials/host_list.html", request, {
        "system_id": system_id, "host_summaries": host_summaries, "user": user,
    })


@router.put("/api/inventory/hosts/{host_id}", response_class=HTMLResponse)
async def api_update_host(request: Request, host_id: str, user: RequireUser):
    """Edit host name, IP, OS etc.  Returns the host detail header partial."""
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
        raise HTTPException(status_code=404, detail="Host not found")
    system = get_system(host.system_id)
    software = list_host_software(host_id)
    vulns = get_host_vulnerabilities(host_id)
    return _render("partials/host_header.html", request, {
        "host": host, "system": system, "software": software, "vulns": vulns, "user": user,
    })


@router.delete("/api/inventory/hosts/{host_id}", response_class=HTMLResponse)
def api_delete_host(
    request: Request, host_id: str, user: RequireUser,
    system_id: str = Query(...),
):
    ok = delete_host(host_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Host not found")
    host_summaries = get_host_summaries(system_id)
    return _render("partials/host_list.html", request, {
        "system_id": system_id, "host_summaries": host_summaries, "user": user,
    })


# ---------------------------------------------------------------------------
# Nessus Upload (per-environment endpoint)
# ---------------------------------------------------------------------------

@router.post("/api/inventory/systems/{system_id}/nessus-upload", response_class=HTMLResponse)
async def api_nessus_upload_by_system(
    request: Request, system_id: str, user: RequireUser,
    file: UploadFile = File(...),
):
    if not get_system(system_id):
        raise HTTPException(status_code=404, detail="Environment not found")
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
    return _render("partials/host_list.html", request, {
        "system_id": system_id, "host_summaries": host_summaries, "user": user,
        "nessus_hosts": hosts_created, "nessus_records": records_inserted,
        "nessus_warnings": warnings,
    })


@router.post("/api/inventory/nessus-upload", response_class=HTMLResponse)
async def api_nessus_upload_global(
    request: Request, user: RequireUser,
    file: UploadFile = File(...),
    system_id: str = Form(...),
    new_env_name: Optional[str] = Form(None),
):
    """Global Nessus upload: user selects the environment from the modal.
    Passing system_id='__new__' creates a new environment using new_env_name."""
    if system_id == "__new__":
        env_name = (new_env_name or "").strip()
        if not env_name:
            raise HTTPException(status_code=422, detail="Environment name is required when creating a new one")
        new_sys = add_system(SystemCreate(name=env_name))
        system = new_sys
    else:
        system = get_system(system_id)
        if not system:
            raise HTTPException(status_code=404, detail="Environment not found")
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
        "toast": (f"Nessus import complete: {hosts_created} host(s), "
                  f"{records_inserted} software record(s) added to {system.name}."),
    })


# ---------------------------------------------------------------------------
# Host Software API
# ---------------------------------------------------------------------------

@router.post("/api/inventory/hosts/{host_id}/software", response_class=HTMLResponse)
async def api_add_host_software(request: Request, host_id: str, user: RequireUser):
    host = get_host(host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    form = await request.form()
    data = SoftwareCreate(
        name=(form.get("name") or "").strip(),
        version=form.get("version") or None,
        vendor=form.get("vendor") or None,
        cpe=form.get("cpe") or None,
        source="manual",
    )
    if not data.name:
        raise HTTPException(status_code=422, detail="Software name is required")
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
# CVE Detection (mark/unmark)
# ---------------------------------------------------------------------------

@router.post("/api/inventory/cve/{cve_id}/detect", response_class=HTMLResponse)
async def api_mark_detected(request: Request, cve_id: str, user: RequireUser):
    form = await request.form()
    system_id = (form.get("system_id") or "").strip()
    note = (form.get("note") or "").strip() or None
    rule_ref = (form.get("rule_ref") or "").strip() or None
    mark_cve_detected(cve_id, system_id=system_id, note=note, rule_ref=rule_ref)
    # Re-fetch the full CVE to rebuild the badge
    cve = get_cve_detail(cve_id)
    affected_systems = {h.system_id: (h.system_name or h.system_id) for h in (cve.affected_hosts if cve else [])}
    technique_rules = get_rules_for_cve_techniques(cve_id)
    return _render("partials/cve_detection_badge.html", request, {
        "cve_id": cve_id.upper(),
        "system_detections": cve.system_detections if cve else {},
        "affected_systems": affected_systems,
        "technique_rules": technique_rules,
        "user": user,
    })


@router.post("/api/inventory/cve/{cve_id}/detect/append-rule", response_class=HTMLResponse)
async def api_append_rule(request: Request, cve_id: str, user: RequireUser):
    """Append a new rule reference to an existing detection (comma-separated)."""
    form = await request.form()
    system_id = (form.get("system_id") or "").strip()
    existing = (form.get("existing_rule_ref") or "").strip()
    new_rule = (form.get("new_rule_ref") or "").strip()
    if not new_rule:
        raise HTTPException(status_code=400, detail="new_rule_ref is required")
    # Build combined rule_ref, avoiding duplicates
    parts = [r.strip() for r in existing.split(",") if r.strip()] if existing else []
    if new_rule not in parts:
        parts.append(new_rule)
    combined = ", ".join(parts)
    # Preserve existing note
    current = get_cve_detection(cve_id, system_id=system_id)
    mark_cve_detected(cve_id, system_id=system_id,
                      note=current.note if current else None,
                      rule_ref=combined)
    cve = get_cve_detail(cve_id)
    affected_systems = {h.system_id: (h.system_name or h.system_id) for h in (cve.affected_hosts if cve else [])}
    technique_rules = get_rules_for_cve_techniques(cve_id)
    return _render("partials/cve_detection_badge.html", request, {
        "cve_id": cve_id.upper(),
        "system_detections": cve.system_detections if cve else {},
        "affected_systems": affected_systems,
        "technique_rules": technique_rules,
        "user": user,
    })


@router.delete("/api/inventory/cve/{cve_id}/detect", response_class=HTMLResponse)
async def api_unmark_detected(request: Request, cve_id: str, user: RequireUser,
                               system_id: str = Query("")):
    unmark_cve_detected(cve_id, system_id=system_id)
    cve = get_cve_detail(cve_id)
    affected_systems = {h.system_id: (h.system_name or h.system_id) for h in (cve.affected_hosts if cve else [])}
    technique_rules = get_rules_for_cve_techniques(cve_id)
    return _render("partials/cve_detection_badge.html", request, {
        "cve_id": cve_id.upper(),
        "system_detections": cve.system_detections if cve else {},
        "affected_systems": affected_systems,
        "technique_rules": technique_rules,
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
    stats = get_cve_overview_stats()
    cves = get_all_cve_overview()
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
    stats = get_cve_overview_stats()
    cves = get_all_cve_overview()
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
