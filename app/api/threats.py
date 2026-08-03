"""
API routes for Threat Landscape page.
"""

from fastapi import APIRouter, Request, Query, BackgroundTasks
from fastapi.responses import HTMLResponse
from typing import Optional, List, Any
from dataclasses import dataclass
import re
import json

from app.api.deps import DbDep, CurrentUser, RequireUser, SettingsDep, ActiveClient

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/threats", tags=["threats"])


def _build_threat_sync_toast(result: Any) -> tuple[str, str]:
    """Return ``(toast_class, message)`` for a threat sync result payload."""
    if isinstance(result, int):
        result = {
            "status": "success" if result > 0 else ("failed" if result < 0 else "partial"),
            "total": max(result, 0),
            "mitre_count": 0,
            "octi_count": 0,
            "warnings": [],
            "errors": [],
            "error": None,
        }

    status = (result or {}).get("status", "failed")
    total = int((result or {}).get("total", 0) or 0)
    mitre = int((result or {}).get("mitre_count", 0) or 0)
    octi = int((result or {}).get("octi_count", 0) or 0)
    errs = (result or {}).get("errors", []) or []
    warns = (result or {}).get("warnings", []) or []

    if status == "success":
        toast_class = "toast-success"
        msg = (f"Synced {total} threat actors "
               f"({mitre} MITRE + {octi} CTI connector actors).")
        if warns:
            msg += f" {len(warns)} warning(s) - see logs."
        return toast_class, msg

    if status == "partial":
        toast_class = "toast-warning"
        first = errs[0] if errs else "see logs"
        more = f" (+{len(errs) - 1} more)" if len(errs) > 1 else ""
        msg = (
            f"Partial sync: {total} actors loaded ({mitre} MITRE + {octi} "
            f"CTI connector actors) but {len(errs)} source(s) failed. First error: "
            f"{first}{more}"
        )
        return toast_class, msg

    toast_class = "toast-error"
    top = (result or {}).get("error")
    if top:
        msg = f"MITRE sync failed: {top}"
    elif errs:
        msg = f"MITRE sync failed: {errs[0]}"
    else:
        msg = (
            "No threat data found. Check /opt/repos/mitre and linked "
            "CTI connectors in Management."
        )
    return toast_class, msg

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
    group_url: Optional[str] = None


@router.get("", response_class=HTMLResponse)
def list_threats(
    request: Request,
    db: DbDep,
    user: CurrentUser,
    client_id: ActiveClient,
    search: Optional[str] = Query(None),
    origin: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    sort_by: str = Query("ttp_desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(24, ge=1, le=100),
):
    """List threat actors with filtering and pagination."""
    try:
        # Get all actors visible to the active tenant (OpenCTI-only actors are
        # hidden when this client has no OpenCTI link — see DB layer).
        actors = db.get_threat_actors(client_id=client_id)

        # Get covered TTPs and rule counts scoped to active client
        covered_ttps = db.get_all_covered_ttps(client_id=client_id)
        technique_rule_counts = db.get_ttp_rule_counts(client_id=client_id)
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

    # Best-effort MITRE group URL resolution so actor titles can deep-link
    # to group detail pages when the actor maps to a known ATT&CK group.
    group_lookup = {}
    try:
        for grp in db.list_mitre_groups(domain="enterprise"):
            gid = (grp.get("id") or "").strip().upper()
            if not gid:
                continue
            group_url = f"/mitre/groups/{gid}"

            name_key = (grp.get("name") or "").strip().lower()
            if name_key and name_key not in group_lookup:
                group_lookup[name_key] = group_url

            aliases_raw = grp.get("aliases") or ""
            for alias in str(aliases_raw).split(","):
                alias_key = alias.strip().lower()
                if alias_key and alias_key not in group_lookup:
                    group_lookup[alias_key] = group_url
    except Exception:
        group_lookup = {}

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

        # Resolve actor title link to MITRE group detail by matching actor
        # canonical name and aliases to the MITRE groups catalog.
        group_url = None
        actor_keys = [(actor.name or "").strip().lower()]
        if actor.aliases:
            actor_keys.extend(
                [a.strip().lower() for a in str(actor.aliases).split(",") if a.strip()]
            )
        for key in actor_keys:
            hit = group_lookup.get(key)
            if hit:
                group_url = hit
                break
        
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
            group_url=group_url,
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
    return templates.TemplateResponse(request, "partials/threats_grid.html", context)


@router.get("/metrics", response_class=HTMLResponse)
def get_threat_metrics(
    request: Request,
    db: DbDep,
    user: CurrentUser,
    client_id: ActiveClient,
):
    """Get threat landscape metrics scoped to active client.

    4.1.7 Phase C: wrap the metrics fetch so a transient failure during a
    concurrent sync degrades to an empty render instead of 500-ing the
    HTMX swap (which would leave the dashboard tile broken until reload).
    """
    from app.main import get_last_sync_time
    from app.models.threats import ThreatLandscapeMetrics
    try:
        metrics = db.get_threat_landscape_metrics(client_id=client_id)
    except Exception:
        import logging as _lg
        _lg.getLogger(__name__).exception(
            "get_threat_metrics: metrics fetch failed (client=%s); "
            "rendering empty.", client_id,
        )
        metrics = ThreatLandscapeMetrics()
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request, "partials/threat_metrics.html",
        {"metrics": metrics, "last_sync_time": get_last_sync_time()}
    )


@router.post("/sync", response_class=HTMLResponse)
async def sync_threats(
    request: Request,
    db: DbDep,
    user: RequireUser,
    client_id: ActiveClient,
    background_tasks: BackgroundTasks,
    settings: SettingsDep,
):
    """Trigger a background Threat Landscape sync and return a polling badge.

    The previous implementation waited for the full sync in-request, which
    can exceed reverse-proxy timeouts on large CTI connector pulls and return
    504 even when the backend work continues. This endpoint now mirrors the
    connector sync job pattern: submit quickly, poll job status via HTMX.
    """
    from app.services.sync import run_mitre_sync
    from app.services import cti_jobs

    job_id = cti_jobs.submit(
        kind="threat-sync",
        runner=lambda: run_mitre_sync(client_id),
        label="Threat Landscape",
        client_id=client_id,
    )

    return HTMLResponse(
        f'<span id="threat-sync-job-{job_id}" class="badge badge-info" '
        f'hx-get="/api/threats/sync/jobs/{job_id}" '
        f'hx-trigger="every 2s" '
        f'hx-swap="outerHTML">Sync running...</span>'
    )


@router.get("/sync/jobs/{job_id}", response_class=HTMLResponse)
def sync_threats_job_status(job_id: str, user: RequireUser):
    """HTMX polling target for Threat Landscape sync jobs."""
    import html as _html
    from app.services import cti_jobs

    target_id = f"threat-sync-job-{_html.escape(job_id)}"
    job = cti_jobs.get(job_id)
    if job is None:
        return HTMLResponse(
            '<div class="toast toast-warning" onclick="this.remove()">'
            'Threat sync job is no longer tracked. Please run Sync again.</div>'
        )

    status = job.get("status")
    if status in (cti_jobs.JOB_STATUS_PENDING, cti_jobs.JOB_STATUS_RUNNING):
        return HTMLResponse(
            f'<span id="{target_id}" class="badge badge-info" '
            f'hx-get="/api/threats/sync/jobs/{job_id}" '
            f'hx-trigger="every 2s" '
            f'hx-swap="outerHTML">Sync running...</span>'
        )

    if status == cti_jobs.JOB_STATUS_SUCCESS:
        result = job.get("summary") or {}
    else:
        result = {
            "status": "failed",
            "error": job.get("error") or "Unknown job failure",
            "errors": [job.get("error") or "Unknown job failure"],
            "warnings": [],
            "total": 0,
            "mitre_count": 0,
            "octi_count": 0,
        }

    toast_class, msg = _build_threat_sync_toast(result)
    headers = {}
    sync_status = (result or {}).get("status")
    if sync_status in ("success", "partial"):
        headers["HX-Trigger"] = json.dumps({"refreshThreats": True})

    return HTMLResponse(
        f'<div class="toast {toast_class}" onclick="this.remove()">'
        f'{_html.escape(msg)}'
        f'</div>',
        headers=headers,
    )
