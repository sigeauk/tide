"""
API routes for Threat Landscape page.
"""

from fastapi import APIRouter, Request, Query, BackgroundTasks
from fastapi.responses import HTMLResponse
from typing import Optional, List
from dataclasses import dataclass
import re

from app.api.deps import DbDep, CurrentUser, RequireUser, SettingsDep

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/threats", tags=["threats"])

# --- ISO COUNTRY MAPPING (for flag SVGs) ---
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
    "VOLT TYPHOON": "cn", "BRONZE SILHOUETTE": "cn",
    
    "KP": "kp", "NORTH KOREA": "kp", "DPRK": "kp", "PYONGYANG": "kp",
    "LAZARUS": "kp", "HIDDEN COBRA": "kp", "KIMSUKY": "kp", "VELVET CHOLLIMA": "kp",
    "ANDARIEL": "kp", "SILENT CHOLLIMA": "kp", "ONYX SLEET": "kp", "PLUTONIUM": "kp",
    "APT37": "kp", "RICOCHET CHOLLIMA": "kp", "SCARCRUFT": "kp",
    
    "IR": "ir", "IRAN": "ir", "IRANIAN": "ir",
    "APT33": "ir", "ELFIN": "ir", "APT34": "ir", "OILRIG": "ir",
    "MUDDYWATER": "ir", "APT35": "ir", "CHARMING KITTEN": "ir",
    
    "VN": "vn", "VIETNAM": "vn", "OCEANLOTUS": "vn", "APT32": "vn",
    "IN": "in", "INDIA": "in", "SIDEWINDER": "in", "PATCHWORK": "in",
    "PK": "pk", "PAKISTAN": "pk", "TRANSPARENT TRIBE": "pk",
    "IL": "il", "ISRAEL": "il", "UNIT 8200": "il",
    "KR": "kr", "SOUTH KOREA": "kr", "DARKHOTEL": "kr",
    "US": "us", "USA": "us", "EQUATION GROUP": "us",
    "SCATTERED SPIDER": "us", "OCTO TEMPEST": "us", "0KTAPUS": "us",
    "UA": "ua", "UKRAINE": "ua", "UKRAINIAN": "ua",
    "TR": "tr", "TURKEY": "tr", "TURKISH": "tr",
    "BR": "br", "BRAZIL": "br", "BRAZILIAN": "br",
    "NG": "ng", "NIGERIA": "ng", "NIGERIAN": "ng",
    "GB": "gb", "UK": "gb", "UNITED KINGDOM": "gb", "BRITAIN": "gb",
    "FR": "fr", "FRANCE": "fr", "FRENCH": "fr",
    "DE": "de", "GERMANY": "de", "GERMAN": "de",
}


def get_iso_code(text: str) -> Optional[str]:
    """Get ISO country code from text (name, origin, description)."""
    if not text:
        return None
    text_search = str(text).upper()
    sorted_keywords = sorted(ISO_MAP.keys(), key=len, reverse=True)
    for keyword in sorted_keywords:
        pattern = r'\b' + re.escape(keyword) + r'\b'
        if re.search(pattern, text_search):
            return ISO_MAP[keyword]
    return None


@dataclass
class TTPWithCoverage:
    """TTP with coverage status and rule count for display."""
    id: str
    covered: bool
    rule_count: int = 0


@dataclass
class ActorWithCoverage:
    """Threat actor with calculated coverage for display."""
    name: str
    description: Optional[str]
    aliases: Optional[str]
    origin: Optional[str]
    source: List[str]
    ttp_count: int
    ttps: List[str]
    covered_count: int
    coverage_pct: int
    ttps_with_coverage: List[TTPWithCoverage]
    iso_code: Optional[str] = None  # For flag SVG path


@router.get("", response_class=HTMLResponse)
def list_threats(
    request: Request,
    db: DbDep,
    user: CurrentUser,
    search: Optional[str] = Query(None),
    origin: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    sort_by: str = Query("ttp_desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(24, ge=1, le=100),
):
    """List threat actors with filtering and pagination."""
    try:
        # Get all actors
        actors = db.get_threat_actors()
        
        # Get covered TTPs and rule counts in production
        covered_ttps = db.get_covered_ttps_by_space("production")
        technique_rule_counts = db.get_technique_rule_counts("production")
    except Exception as e:
        # Fallback if database not ready
        actors = []
        covered_ttps = set()
        technique_rule_counts = {}
    
    # Apply text/origin/source filters FIRST on lightweight actor objects
    # before computing coverage (which is more expensive per actor)
    if search:
        search_lower = search.lower()
        actors = [
            a for a in actors
            if search_lower in a.name.lower() or
               (a.aliases and search_lower in a.aliases.lower()) or
               (a.description and search_lower in a.description.lower())
        ]
    
    if origin:
        actors = [
            a for a in actors
            if a.origin and origin.lower() in a.origin.lower()
        ]
    
    if source:
        actors = [
            a for a in actors
            if source in a.source
        ]
    
    # Calculate coverage only for filtered actors
    actors_with_coverage = []
    for actor in actors:
        actor_ttps = {str(t).strip().upper() for t in actor.ttps}
        covered_count = len(actor_ttps.intersection(covered_ttps))
        coverage_pct = int((covered_count / len(actor_ttps) * 100)) if actor_ttps else 0
        
        # Build TTPs with coverage status and rule count, sorted (covered first, then gaps)
        ttps_with_coverage = []
        for ttp in sorted(actor.ttps):
            ttp_upper = str(ttp).strip().upper()
            ttps_with_coverage.append(TTPWithCoverage(
                id=ttp_upper,
                covered=ttp_upper in covered_ttps,
                rule_count=technique_rule_counts.get(ttp_upper, 0)
            ))
        
        # Sort: covered first, then gaps
        ttps_with_coverage.sort(key=lambda x: (not x.covered, x.id))
        
        # Get ISO code from origin, name, or description
        text_to_check = f"{actor.origin or ''} {actor.name} {actor.description or ''}"
        iso_code = get_iso_code(text_to_check)
        
        actors_with_coverage.append(ActorWithCoverage(
            name=actor.name,
            description=actor.description,
            aliases=actor.aliases,
            origin=actor.origin,
            source=actor.source,
            ttp_count=actor.ttp_count,
            ttps=actor.ttps,
            covered_count=covered_count,
            coverage_pct=coverage_pct,
            ttps_with_coverage=ttps_with_coverage,
            iso_code=iso_code,
        ))
    
    # Apply sorting
    sort_map = {
        "ttp_desc": lambda x: -x.ttp_count,
        "ttp_asc": lambda x: x.ttp_count,
        "name_asc": lambda x: x.name.lower(),
        "coverage_desc": lambda x: -x.coverage_pct,
        "coverage_asc": lambda x: x.coverage_pct,
    }
    sort_fn = sort_map.get(sort_by, lambda x: -x.ttp_count)
    actors_with_coverage.sort(key=sort_fn)
    
    # Pagination
    total = len(actors_with_coverage)
    total_pages = max(1, (total + page_size - 1) // page_size)
    offset = (page - 1) * page_size
    paginated_actors = actors_with_coverage[offset:offset + page_size]
    
    logger.info(f"Fetched {len(paginated_actors)} actors (total: {total}, page: {page}/{total_pages})")
    
    templates = request.app.state.templates
    context = {
        "request": request,
        "actors": paginated_actors,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "search": search or "",
        "origin": origin or "",
        "source": source or "",
        "sort_by": sort_by,
    }
    return templates.TemplateResponse("partials/threats_grid.html", context)


@router.get("/metrics", response_class=HTMLResponse)
def get_threat_metrics(
    request: Request,
    db: DbDep,
    user: CurrentUser,
):
    """Get threat landscape metrics."""
    from app.main import get_last_sync_time
    metrics = db.get_threat_landscape_metrics()
    templates = request.app.state.templates
    return templates.TemplateResponse(
        "partials/threat_metrics.html",
        {"request": request, "metrics": metrics, "last_sync_time": get_last_sync_time()}
    )


@router.post("/sync", response_class=HTMLResponse)
async def sync_threats(
    request: Request,
    db: DbDep,
    user: RequireUser,
    background_tasks: BackgroundTasks,
    settings: SettingsDep,
):
    """Trigger a sync of threat intel from MITRE ATT&CK files and OpenCTI."""
    import asyncio
    from app.services.sync import run_mitre_sync
    
    try:
        loop = asyncio.get_event_loop()
        count = await loop.run_in_executor(None, run_mitre_sync)
        
        if count > 0:
            return HTMLResponse(
                f'<div class="toast toast-success" onclick="this.remove()">'
                f'Synced {count} threat actors from MITRE ATT&CK and OpenCTI.'
                f'</div>'
            )
        elif count == 0:
            return HTMLResponse(
                '<div class="toast toast-warning" onclick="this.remove()">'
                'No threat data found. Check /opt/repos/mitre directory and OpenCTI connection.'
                '</div>'
            )
        else:
            return HTMLResponse(
                '<div class="toast toast-error" onclick="this.remove()">'
                'MITRE sync failed. Check logs for details.'
                '</div>'
            )
    except Exception as e:
        return HTMLResponse(
            f'<div class="toast toast-error" onclick="this.remove()">'
            f'Sync error: {str(e)}'
            f'</div>'
        )
