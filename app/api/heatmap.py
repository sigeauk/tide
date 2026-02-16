"""
API routes for Heatmap (MITRE ATT&CK coverage matrix).
Returns HTML partials for HTMX swapping.
"""

from fastapi import APIRouter, Request, Query
from fastapi.responses import HTMLResponse
from typing import List, Optional, Set, Dict

from app.api.deps import DbDep, CurrentUser
from app.models.threats import HeatmapCell, HeatmapData, CoverageStatus

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/heatmap", tags=["heatmap"])

# Tactic order for consistent display
TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact"
]

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
    user: CurrentUser,
    actors: List[str] = Query(default=[]),
    show_defense: bool = Query(False),
):
    """
    Generate MITRE ATT&CK heatmap matrix for selected actors.
    Returns HTML partial for HTMX swap.
    """
    # Get data from database
    all_actors = db.get_threat_actors()
    covered_ttps = db.get_all_covered_ttps()
    ttp_rule_counts = db.get_ttp_rule_counts()
    ttp_map = db.get_technique_map()
    ttp_names = db.get_technique_names()
    
    # Filter to selected actors
    selected_actors = [a for a in all_actors if a.name in actors]
    
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
    matrix_data: Dict[str, List[HeatmapCell]] = {t: [] for t in TACTIC_ORDER + ["Other"]}
    
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
    active_tactics = [t for t in TACTIC_ORDER + ["Other"] if matrix_data[t]]
    
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
        "partials/heatmap_matrix.html",
        {
            "request": request,
            "data": heatmap_data,
        }
    )


@router.get("/actors", response_class=HTMLResponse)
def search_actors(
    request: Request,
    db: DbDep,
    user: CurrentUser,
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
    user: CurrentUser,
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
    covered_ttps = db.get_all_covered_ttps()
    
    ttp_upper = technique_id.upper()
    name = ttp_names.get(ttp_upper, "Unknown Technique")
    raw_tactic = ttp_map.get(ttp_upper, "")
    tactic = get_tactic_display(raw_tactic)
    is_covered = ttp_upper in covered_ttps
    
    # Get rules covering this technique with optional search filter
    rules = db.get_rules_for_technique(technique_id, search=search)
    
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
        "partials/technique_detail.html",
        {
            "request": request,
            "technique": technique,
            "tactic": tactic,
            "is_covered": is_covered,
            "rule_count": len(rules),
            "actors": [],  # TODO: Get actors using this TTP
            "search": search or "",  # Pass search to template for rules endpoint
        }
    )


@router.get("/technique/{technique_id}/rules", response_class=HTMLResponse)
def get_technique_rules(
    request: Request,
    technique_id: str,
    db: DbDep,
    user: CurrentUser,
    search: Optional[str] = Query(None),
):
    """
    Get detection rules for a specific technique.
    Returns HTML partial for rules list.
    
    Args:
        technique_id: MITRE technique ID
        search: Optional search filter to apply to rules (matches name, author, rule_id, mitre_ids)
    """
    rules = db.get_rules_for_technique(technique_id, search=search)
    
    templates = request.app.state.templates
    return templates.TemplateResponse(
        "partials/technique_rules.html",
        {
            "request": request,
            "rules": rules,
        }
    )
