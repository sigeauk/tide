"""
API routes for Heatmap (MITRE ATT&CK coverage matrix).
Returns HTML partials for HTMX swapping.
Export endpoints return downloadable PDF or Markdown files.
"""

from fastapi import APIRouter, Request, Query, HTTPException, Form
from fastapi.responses import HTMLResponse, Response, RedirectResponse
from typing import List, Optional, Set, Dict
import io
import os
import time

from app.api.deps import ActiveClient, DbDep, CurrentUser
from app.models.threats import HeatmapCell, HeatmapData, CoverageStatus

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/heatmap", tags=["heatmap"])

# Cache system baseline heatmap source data briefly to speed up rapid filter toggles.
_SYSTEM_HEATMAP_CACHE: Dict[str, tuple[float, List[Dict]]] = {}
_SYSTEM_HEATMAP_CACHE_TTL = 20.0

# Tactic order for consistent display — single source of truth
from app.services.report_generator import TACTIC_ORDER

# Map STIX slugs to display titles
SLUG_TO_TITLE = {
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Dev",
}


def get_tactic_display(raw_tactic: str) -> str:
    """Convert tactic slug to display name."""
    if not raw_tactic:
        return "Other"
    return SLUG_TO_TITLE.get(raw_tactic.lower(), "Other")


@router.get("/matrix", response_class=HTMLResponse)
def get_heatmap_matrix(
    request: Request,
    db: DbDep,
    user: CurrentUser, client_id: ActiveClient,
    actors: List[str] = Query(default=[]),
    show_defense: bool = Query(False),
    source_filter: List[str] = Query(default=[], description="Filter actors by data source(s). Empty = all sources."),
):
    """
    Generate MITRE ATT&CK heatmap matrix for selected actors.
    Returns HTML partial for HTMX swap.
    """
    # Get data from database
    all_actors = db.get_threat_actors()
    covered_ttps = db.get_all_covered_ttps(client_id=client_id)
    ttp_rule_counts = db.get_ttp_rule_counts(client_id=client_id)
    ttp_map = db.get_technique_map()
    ttp_names = db.get_technique_names()
    
    # Filter to selected actors
    selected_actors = [a for a in all_actors if a.name in actors]

    # Apply source filter — only retain actors whose source list overlaps with the selected filters
    # Both the filter values and the actor's raw sources are normalised before comparison
    # so that e.g. "Enterprise" (display) matches DB values "enterprise" or "mitre:enterprise".
    _SOURCE_NORM = {
        "enterprise": "enterprise",
        "mitre:enterprise": "enterprise",
        "mitre-enterprise": "enterprise",
        "mobile": "mobile",
        "mitre:mobile": "mobile",
        "ics": "ics",
        "mitre:ics": "ics",
        "opencti": "opencti",
        "open-cti": "opencti",
        "octi": "opencti",
    }

    def _norm(s: str) -> str:
        key = s.strip().lower()
        return _SOURCE_NORM.get(key, key)

    if source_filter:
        norm_filters = {_norm(s) for s in source_filter if s.strip()}
        selected_actors = [
            a for a in selected_actors
            if norm_filters & {_norm(s) for s in (a.source or [])}
        ]
    
    # Build relevant TTPs set and actor mapping
    relevant_ttps: Set[str] = set()
    actor_ttp_map: Dict[str, List[str]] = {}
    
    for actor in selected_actors:
        for ttp in actor.ttps:
            ttp_id = str(ttp).strip().upper()
            relevant_ttps.add(ttp_id)
            if ttp_id not in actor_ttp_map:
                actor_ttp_map[ttp_id] = []
            actor_ttp_map[ttp_id].append(actor.name)
    
    # Build display TTPs
    display_ttps = relevant_ttps.copy()
    if show_defense:
        display_ttps.update(covered_ttps)
    
    # Build matrix data
    matrix_data: Dict[str, List[HeatmapCell]] = {t: [] for t in TACTIC_ORDER}
    
    for ttp_id in display_ttps:
        is_relevant = ttp_id in relevant_ttps
        is_covered = ttp_id in covered_ttps
        
        # Determine status
        if is_relevant and not is_covered:
            status = CoverageStatus.GAP
        elif is_relevant and is_covered:
            status = CoverageStatus.COVERED
        else:
            status = CoverageStatus.DEFENSE
        
        # Get technique info
        tech_name = ttp_names.get(ttp_id, ttp_names.get(ttp_id.upper(), "Unknown"))
        raw_tactic = ttp_map.get(ttp_id.upper(), ttp_map.get(ttp_id, ""))
        tactic = get_tactic_display(raw_tactic)
        
        if tactic not in matrix_data:
            tactic = "Other"
        
        cell = HeatmapCell(
            id=ttp_id,
            name=tech_name,
            tactic=raw_tactic,
            status=status,
            actors=actor_ttp_map.get(ttp_id, []),
            rule_count=ttp_rule_counts.get(ttp_id, 0),
        )
        matrix_data[tactic].append(cell)
    
    # Filter out empty tactics
    active_tactics = [t for t in TACTIC_ORDER if matrix_data[t]]
    
    # Calculate metrics
    gap_count = sum(1 for t in relevant_ttps if t not in covered_ttps)
    covered_count = len(relevant_ttps) - gap_count
    coverage_pct = int((covered_count / len(relevant_ttps) * 100)) if relevant_ttps else 0
    defense_count = len(covered_ttps - relevant_ttps) if show_defense else 0
    
    heatmap_data = HeatmapData(
        tactics=active_tactics,
        matrix=matrix_data,
        selected_actors=[a.name for a in selected_actors],
        total_ttps=len(relevant_ttps),
        gap_count=gap_count,
        covered_count=covered_count,
        defense_count=defense_count,
        coverage_pct=coverage_pct,
    )
    
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "partials/heatmap_matrix.html",
        {
            "data": heatmap_data,
        }
    )


@router.get("/actors", response_class=HTMLResponse)
def search_actors(
    request: Request,
    db: DbDep,
    user: CurrentUser, client_id: ActiveClient,
    actor_search: Optional[str] = Query(None),
):
    """
    Search threat actors by name or alias.
    Returns HTML options for actor select.
    """
    actors = db.get_threat_actors()
    
    if actor_search:
        search_lower = actor_search.lower()
        actors = [
            a for a in actors
            if search_lower in a.name.lower() or 
               (a.aliases and search_lower in a.aliases.lower())
        ]
    
    # Build options HTML
    options_html = ""
    for actor in actors:
        options_html += f'<option value="{actor.name}">{actor.name} ({actor.ttp_count} TTPs)</option>\n'
    
    return HTMLResponse(options_html)


@router.get("/technique/{technique_id}", response_class=HTMLResponse)
def get_technique_detail(
    request: Request,
    technique_id: str,
    db: DbDep,
    user: CurrentUser, client_id: ActiveClient,
    search: Optional[str] = Query(None),
):
    """
    Get technique detail slide-over panel.
    Returns HTML partial for slide-over display.
    
    Args:
        technique_id: MITRE technique ID
        search: Optional search filter to apply to rules (matches name, author, rule_id, mitre_ids)
    """
    ttp_names = db.get_technique_names()
    ttp_map = db.get_technique_map()
    covered_ttps = db.get_all_covered_ttps(client_id=client_id)
    
    ttp_upper = technique_id.upper()
    name = ttp_names.get(ttp_upper, "Unknown Technique")
    raw_tactic = ttp_map.get(ttp_upper, "")
    tactic = get_tactic_display(raw_tactic)
    is_covered = ttp_upper in covered_ttps
    
    # Get ALL rules (including disabled) so users see coverage gaps clearly
    rules = db.get_rules_for_technique(technique_id, search=search, enabled_only=False, client_id=client_id)
    has_rules = len(rules) > 0
    
    # Build technique object for template
    from app.models.threats import MITRETechnique
    technique = MITRETechnique(
        id=ttp_upper,
        name=name,
        tactic=raw_tactic,
        url=f"https://attack.mitre.org/techniques/{ttp_upper.replace('.', '/')}"
    )
    
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "partials/technique_detail.html",
        {
            "technique": technique,
            "tactic": tactic,
            "is_covered": is_covered,
            "has_rules": has_rules,
            "rule_count": len([r for r in rules if r.enabled]),
            "actors": [],  # TODO: Get actors using this TTP
            "search": search or "",  # Pass search to template for rules endpoint
        }
    )


@router.get("/technique/{technique_id}/rules", response_class=HTMLResponse)
def get_technique_rules(
    request: Request,
    technique_id: str,
    db: DbDep,
    user: CurrentUser, client_id: ActiveClient,
    search: Optional[str] = Query(None),
):
    """
    Get detection rules for a specific technique.
    Returns HTML partial for rules list.
    
    Args:
        technique_id: MITRE technique ID
        search: Optional search filter to apply to rules (matches name, author, rule_id, mitre_ids)
    """
    # Get ALL rules for this technique (including disabled)
    rules = db.get_rules_for_technique(technique_id, search=search, enabled_only=False, client_id=client_id)

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "partials/technique_rules.html",
        {
            "rules": rules,
        }
    )


# ─── REPORT EXPORT ────────────────────────────────────────────────────────────

@router.get("/export")
def export_threat_report(
    request: Request,
    db: DbDep,
    user: CurrentUser, client_id: ActiveClient,
    actors: List[str] = Query(default=[]),
    format: str = Query("pdf", pattern="^(pdf|markdown)$"),
    show_defense: bool = Query(False),
    audience_level: str = Query("executive", pattern="^(executive|technical)$"),
    classification: str = Query("Official"),
):
    """
    Generate and download a Threat Coverage Report for selected actors.

    Formats
    -------
    pdf      — Professional A4 PDF rendered by WeasyPrint (CSS Grid matrix +
               executive summary + per-tactic detail tables).
    markdown — Plain-text Markdown report (no extra dependencies).

    Audience levels
    ---------------
    executive — Title page + exec summary + actor profiles + MITRE matrix.
    technical — All executive content + granular tactic/rule tables + Sigma
                opportunity listings for each GAP technique.

    The endpoint is synchronous and runs inside FastAPI's threadpool, so
    WeasyPrint's blocking PDF generation does not stall the event loop.
    """
    if not actors:
        raise HTTPException(
            status_code=400,
            detail="No actors selected. Pass ?actors=ActorName one or more times.",
        )

    from app.services.report_generator import (
        CLASSIFICATION_OPTIONS,
        build_report_data,
        generate_markdown,
        generate_pdf_bytes,
    )

    # Validate classification against the server-side list
    if classification not in CLASSIFICATION_OPTIONS:
        classification = CLASSIFICATION_OPTIONS[0]

    report_data = build_report_data(
        db,
        actors,
        show_defense=show_defense,
        audience_level=audience_level,
        classification=classification,
        client_id=client_id,
    )
    if report_data is None:
        raise HTTPException(
            status_code=404,
            detail="None of the requested actors were found in the database.",
        )

    # ── Sanitise actor names for filename ────────────────────────────────
    safe_actors = "_".join(
        a.replace(" ", "_").replace("/", "_")[:20]
        for a in actors[:3]
    )
    if len(actors) > 3:
        safe_actors += f"_and_{len(actors) - 3}_more"

    from datetime import datetime
    date_str    = datetime.utcnow().strftime("%Y%m%d")
    level_tag   = "ciso" if audience_level == "executive" else "technical"

    if format == "markdown":
        md_text = generate_markdown(report_data)
        filename = f"{date_str}-{safe_actors}-{level_tag}.md"
        return Response(
            content=md_text.encode("utf-8"),
            media_type="text/markdown; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(md_text.encode("utf-8"))),
            },
        )

    # ── PDF (default) ─────────────────────────────────────────────────────
    templates_dir = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "templates"
    )
    try:
        pdf_bytes = generate_pdf_bytes(report_data, templates_dir)
    except RuntimeError as exc:
        logger.error(f"PDF generation failed: {exc}")
        raise HTTPException(status_code=500, detail=str(exc))
    except Exception as exc:
        logger.exception(f"Unexpected error during PDF generation: {exc}")
        raise HTTPException(
            status_code=500,
            detail="PDF generation failed. Check server logs for details.",
        )

    filename = f"{date_str}-{safe_actors}-{level_tag}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )


# ---------------------------------------------------------------------------
# Generate Assurance Baseline from Threat Actor(s)
# ---------------------------------------------------------------------------

@router.post("/generate-baseline")
def generate_baseline_from_heatmap(
    request: Request,
    db: DbDep,
    user: CurrentUser, client_id: ActiveClient,
    actor_names: str = Form(...),
    baseline_name: str = Form(""),
    description: str = Form(""),
):
    """Create a Baseline from one or more Threat Actors' MITRE techniques."""
    from app.inventory_engine import generate_baseline_from_actor

    names = [n.strip() for n in actor_names.split(",") if n.strip()]
    if not names:
        raise HTTPException(status_code=400, detail="No actor names provided")

    all_actors = db.get_threat_actors()
    selected = [a for a in all_actors if a.name in names]
    if not selected:
        raise HTTPException(status_code=404, detail="No matching actors found")

    # Merge TTPs from all selected actors
    merged_ttps = []
    for actor in selected:
        merged_ttps.extend(actor.ttps)

    technique_tactic_map = db.get_technique_map()
    technique_name_map = db.get_technique_names()

    display_name = names[0] if len(names) == 1 else f"{len(names)} Actors"

    baseline = generate_baseline_from_actor(
        actor_name=display_name,
        ttps=merged_ttps,
        technique_tactic_map=technique_tactic_map,
        technique_name_map=technique_name_map,
        baseline_name=baseline_name,
        description=description,
        client_id=client_id,
    )

    return RedirectResponse(url=f"/baselines/{baseline.id}", status_code=303)


# ─── SYSTEM BASELINE HEATMAP ─────────────────────────────────────────────────

@router.get("/system/{system_id}/matrix", response_class=HTMLResponse)
def get_system_heatmap_matrix(
    request: Request,
    system_id: str,
    db: DbDep,
    user: CurrentUser, client_id: ActiveClient,
    baseline_ids: List[str] = Query(default=[]),
):
    """
    Generate a MITRE ATT&CK heatmap for a specific system's baseline techniques.
    Colours reflect per-system coverage status (green/amber/red/grey).
    Optionally filter by specific baseline_ids.
    """
    from app.inventory_engine import get_system_baselines, normalize_technique_id

    cache_key = str(system_id)
    now = time.time()
    cached = _SYSTEM_HEATMAP_CACHE.get(cache_key)
    if cached and (now - cached[0]) < _SYSTEM_HEATMAP_CACHE_TTL:
        all_baselines = cached[1]
    else:
        all_baselines = get_system_baselines(
            system_id,
            include_detection_details=False,
            client_id=client_id,
        )
        _SYSTEM_HEATMAP_CACHE[cache_key] = (now, all_baselines)

    baselines = all_baselines
    if baseline_ids:
        selected = set(baseline_ids)
        baselines = [bl for bl in all_baselines if bl.get("playbook_id") in selected]
    if not baselines:
        templates = request.app.state.templates
        return templates.TemplateResponse(
            request,
            "partials/heatmap_matrix.html",
            {
                "data": HeatmapData(
                    tactics=[], matrix={},
                    selected_actors=[], total_ttps=0,
                    gap_count=0, covered_count=0,
                    defense_count=0, coverage_pct=0,
                ),
            },
        )

    # Status to CSS class mapping for system baseline heatmap
    STATUS_CSS = {
        "green": "status-covered",
        "amber": "status-amber",
        "red": "status-gap",
        "grey": "status-na",
    }

    STATUS_TOOLTIP = {
        "green": "COVERED",
        "amber": "KNOWN GAP",
        "red": "MISSING",
        "grey": "N/A",
    }

    # Build matrix from baseline steps
    matrix_data: Dict[str, List] = {t: [] for t in TACTIC_ORDER}
    matrix_entries: List[dict] = []

    canonical_tactics = {t.lower(): t for t in TACTIC_ORDER}

    def _fallback_other_label(raw_tactic: str) -> str:
        label = (raw_tactic or "").strip()
        if not label:
            return "OTHER"
        if label.lower() in canonical_tactics:
            return "OTHER"
        return label.upper()

    for bl in baselines:
        for step in bl.get("tactics", []):
            status = step.get("status", "red")
            title = step.get("title", "")
            raw_step_tactic = (step.get("tactic") or "").strip()
            step_uses_other_bucket = (
                not raw_step_tactic
                or raw_step_tactic == "Other"
                or raw_step_tactic not in matrix_data
            )

            tagged_ids = []
            for tagged in step.get("techniques", []):
                tid = normalize_technique_id(str(tagged.get("technique_id") or ""))
                if tid:
                    tagged_ids.append(tid)

            primary_tid = normalize_technique_id(step.get("technique_id") or "")
            if primary_tid:
                tagged_ids.append(primary_tid)

            # System heatmap mirrors the baseline breakdown: one card per step.
            tech_ids = list(dict.fromkeys(tagged_ids))
            display_technique = tech_ids[0] if tech_ids else _fallback_other_label(raw_step_tactic)
            display_tactic = "Other" if step_uses_other_bucket else raw_step_tactic
            matrix_entries.append({
                "tech_id": display_technique,
                "title": title,
                "tactic": display_tactic,
                "status": status,
                "baseline": bl["playbook_name"],
                "step_id": step.get("step_id", ""),
                "all_techniques": tech_ids,
            })

    # Build HeatmapCell-like dicts for the template
    # We use a simple namespace object so the template can access .css_class and .tooltip
    class _Cell:
        """Lightweight cell for system heatmap rendering."""
        __slots__ = ("id", "name", "tactic", "css_class", "tooltip", "rule_count")
        def __init__(self, tech_id, name, tactic, css_class, tooltip, rule_count=0):
            self.id = tech_id
            self.name = name
            self.tactic = tactic
            self.css_class = css_class
            self.tooltip = tooltip
            self.rule_count = rule_count

    for entry in matrix_entries:
        tactic = entry["tactic"]
        cell = _Cell(
            tech_id=entry["tech_id"],
            name=entry["title"],
            tactic=tactic,
            css_class=STATUS_CSS.get(entry["status"], "status-gap"),
            tooltip=(
                f'{entry["tech_id"]}: {entry["title"] or "Untitled"} | '
                f'{STATUS_TOOLTIP.get(entry["status"], "MISSING")} | '
                f'Baseline: {entry["baseline"]}'
                + (
                    f' | Tagged: {", ".join(entry["all_techniques"])}'
                    if entry.get("all_techniques")
                    else ""
                )
            ),
        )
        matrix_data[tactic].append(cell)

    # Sort cells within each tactic by technique ID
    for tactic in matrix_data:
        matrix_data[tactic].sort(key=lambda c: (c.id, c.name))

    active_tactics = [t for t in TACTIC_ORDER if matrix_data[t]]

    # Compute metrics
    total = len(matrix_entries)
    green_count = sum(1 for e in matrix_entries if e["status"] == "green")
    amber_count = sum(1 for e in matrix_entries if e["status"] == "amber")
    red_count = sum(1 for e in matrix_entries if e["status"] == "red")
    grey_count = sum(1 for e in matrix_entries if e["status"] == "grey")
    effective = total - grey_count
    pct = int(green_count / effective * 100) if effective else 0

    # Build a simple data object the template can consume
    class _HeatmapData:
        __slots__ = ("tactics", "matrix", "selected_actors", "total_ttps",
                     "gap_count", "covered_count", "defense_count", "coverage_pct")
        def __init__(self, **kw):
            for k, v in kw.items():
                setattr(self, k, v)
        def get(self, key, default=None):
            return getattr(self, key, default)

    data = _HeatmapData(
        tactics=active_tactics,
        matrix=matrix_data,
        selected_actors=[],  # empty to suppress OOB actor-centric metrics
        total_ttps=total,
        gap_count=red_count,
        covered_count=green_count,
        defense_count=grey_count,
        coverage_pct=pct,
    )

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "partials/heatmap_matrix.html",
        {"data": data},
    )
