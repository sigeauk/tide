"""
API routes for Threat Landscape page.
"""

from fastapi import APIRouter, Request, Query, BackgroundTasks
from fastapi.responses import HTMLResponse
from types import SimpleNamespace
from typing import Optional, List, Any
from urllib.parse import urlencode
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


# Longest keyword first (the most specific wins), each compiled once. The substring test in
# get_iso_code skips the regex for keywords a text can't contain: a page of actors used to run
# tens of thousands of regex searches.
_ISO_PATTERNS = [(k, re.compile(r'\b' + re.escape(k) + r'\b')) for k in sorted(ISO_MAP, key=len, reverse=True)]


def get_iso_code(text: str) -> Optional[str]:
    """Get ISO country code from text (name, origin, description)."""
    if not text:
        return None
    text_search = str(text).upper()
    for keyword, pattern in _ISO_PATTERNS:
        if keyword in text_search and pattern.search(text_search):
            return ISO_MAP[keyword]
    return None


# A threat actor on Threat Landscape is shown as an ATT&CK group is on the MITRE Groups page: the
# same card (components/mitre_card.html), grid and window (components/mitre_window.html), with the
# actor's own techniques (OpenCTI's merged onto MITRE's).
ACTOR_SPEC = SimpleNamespace(key="actor", title="Threat actors", singular="Threat actor",
                             window_body="components/mitre_window_actor.html")
# An actor's sources as source pills: an ATT&CK domain as on the MITRE pages, OpenCTI as CTI, any
# other connector by its own name.
_MITRE_SOURCE = re.compile(r"^MITRE:\s*(\w+)$", re.I)
_OPENCTI = {"octi", "opencti", "stix"}


def _actor_sources(sources) -> List[str]:
    out = []
    for src in sources or []:
        text = str(src).strip()
        m = _MITRE_SOURCE.match(text)
        key = m.group(1).lower() if m else ("OpenCTI" if text.lower() in _OPENCTI else text)
        if key and key not in out:
            out.append(key)
    return out


def _source_meta() -> dict:
    from app.services import mitre_catalog as catalog
    return {**catalog.SOURCE_META, "OpenCTI": {"label": "OpenCTI", "code": "CTI", "pill_class": "src-opencti"}}


def _group_ids(db) -> dict:
    """ATT&CK Enterprise groups by lower-case name and alias -> group id: an actor of the same name
    (or alias) is that group."""
    lookup = {}
    try:
        for grp in db.list_mitre_groups(domain="enterprise"):
            gid = (grp.get("id") or "").strip().upper()
            if not gid:
                continue
            for key in [grp.get("name") or ""] + str(grp.get("aliases") or "").split(","):
                key = key.strip().lower()
                if key and key not in lookup:
                    lookup[key] = gid
    except Exception:
        logger.warning("ATT&CK groups unavailable for Threat Landscape", exc_info=True)
    return lookup


def _actor_group(actor, groups: dict) -> str:
    keys = [actor.name or ""] + str(actor.aliases or "").split(",")
    return next((groups[k.strip().lower()] for k in keys if k.strip().lower() in groups), "")


def _ttps(actor) -> set:
    return {str(t).strip().upper() for t in actor.ttps or [] if str(t).strip()}


def actor_item(actor, covered: set) -> dict:
    """An actor as a card (components/mitre_card.html): flag, aliases, sources, coverage of its
    techniques by the client's enabled rules, and its counts."""
    from app.services import mitre_catalog as catalog
    ttps = _ttps(actor)
    aliases = [a.strip() for a in str(actor.aliases or "").split(",") if a.strip() and a.strip() != actor.name]
    meta = [("crosshair", f"{len(ttps)} technique{'s' if len(ttps) != 1 else ''}", "ATT&CK techniques this actor uses")]
    return {
        "id": "",
        "dom_id": catalog.dom_id("actor", actor.name),
        "window_url": f"/api/threats/window?{urlencode({'name': actor.name})}",
        "name": actor.name,
        "flag": get_iso_code(f"{actor.origin or ''} {actor.name} {actor.description or ''}"),
        "sub": ", ".join(aliases),
        "sources": _actor_sources(actor.source),
        "coverage": catalog.coverage_of(ttps, covered),
        "ttp_count": len(ttps),
        "meta": meta,
    }


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
):
    """The actors as cards, one page at a time: the next loads as the end of the grid scrolls into
    view, as on the MITRE pages."""
    from app.services import mitre_catalog as catalog
    try:
        # OpenCTI-only actors are hidden when this client has no OpenCTI link (see the DB layer).
        actors = db.get_threat_actors(client_id=client_id)
    except Exception:
        logger.warning("Threat actors unavailable", exc_info=True)
        actors = []
    covered, _counts = catalog.coverage_for(db, client_id)

    if search:
        needle = search.lower()
        actors = [a for a in actors if needle in a.name.lower() or needle in (a.aliases or "").lower()
                  or needle in (a.description or "").lower()]
    if origin:
        actors = [a for a in actors if a.origin and origin.lower() in a.origin.lower()]
    if source:
        actors = [a for a in actors if source in a.source]

    items = [actor_item(a, covered) for a in actors]

    def pct(it):
        return it["coverage"]["pct"] if it["coverage"] else 0

    sort_map = {
        "ttp_desc": (lambda it: it["ttp_count"], True),
        "ttp_asc": (lambda it: it["ttp_count"], False),
        "name_asc": (lambda it: it["name"].lower(), False),
        "coverage_desc": (pct, True),
        "coverage_asc": (pct, False),
    }
    key, reverse = sort_map.get(sort_by, sort_map["ttp_desc"])
    items.sort(key=key, reverse=reverse)

    start = (page - 1) * catalog.PAGE_SIZE
    params = {"search": search or "", "origin": origin or "", "source": source or "", "sort_by": sort_by}
    more = start + catalog.PAGE_SIZE < len(items)
    return request.app.state.templates.TemplateResponse(request, "partials/threats_grid.html", {
        "items": items[start:start + catalog.PAGE_SIZE], "total": len(items), "page": page,
        "next_url": f"/api/threats?{urlencode({**params, 'page': page + 1})}" if more else "",
        "spec": ACTOR_SPEC, "source_meta": _source_meta(), "filtered": bool(search or origin or source),
    })


@router.get("/window", response_class=HTMLResponse)
def actor_window(request: Request, db: DbDep, user: CurrentUser, client_id: ActiveClient, name: str = Query(...)):
    """One threat actor's window, built as an ATT&CK group's: its details and the ATT&CK group it
    is, coverage, description and techniques; "…" › Create baseline."""
    from app.services import mitre_catalog as catalog
    actor = next((a for a in db.get_threat_actors(client_id=client_id) if a.name == name), None)
    if not actor:
        return HTMLResponse(f"No threat actor named {name}.", status_code=404)
    covered, counts = catalog.coverage_for(db, client_id)
    ttps = sorted(_ttps(actor))
    names, tactics = db.get_technique_names(), db.get_technique_map()
    tactic_names = {short: name for short, (_id, name, _order) in catalog._tactic_index(db, "enterprise").items()}
    item = actor_item(actor, covered)
    gid = _actor_group(actor, _group_ids(db))
    group = None
    if gid:
        found = db.get_mitre_group_detail(gid, domain="enterprise") or {}
        group = {"id": gid, "name": found.get("name") or gid}
    ctx = {
        "spec": ACTOR_SPEC,
        "detail": {
            "id": "", "name": actor.name, "flag": item["flag"], "description": actor.description,
            # OpenCTI gives a country's code: shown as one (KP), anything longer as it is
            "aliases": item["sub"], "origin": (actor.origin.upper() if len(actor.origin) <= 3 else actor.origin)
                                               if actor.origin else "",
            "sources": item["sources"],
            "techniques": [{"id": t, "name": names.get(t, ""),
                            "tactic": ", ".join(tactic_names.get(x.strip(), x.strip()) for x in (tactics.get(t) or "").split(",") if x.strip())}
                           for t in ttps],
            "group": group,
        },
        "dom_id": item["dom_id"],
        "coverage": item["coverage"],
        "uncovered_count": len(set(ttps) - covered),
        "covered_ttps": covered,
        "ttp_rule_counts": counts,
        "window_kinds": list(catalog.KINDS),
        **catalog.source_context("enterprise"),
        "source_meta": _source_meta(),
    }
    if ttps and (user is None or user.can_write("page:baselines")):
        ctx.update(baseline_from=len(ttps), baseline_url="/api/heatmap/generate-baseline",
                   baseline_fields=[("actor_names", actor.name), ("actor_group_ids", gid)])
    return request.app.state.templates.TemplateResponse(request, "components/mitre_window.html", ctx)


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
        actor=getattr(user, "username", None),
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
            '<div class="toast toast-warning" data-click="el.remove">'
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
        f'<div class="toast {toast_class}" data-click="el.remove">'
        f'{_html.escape(msg)}'
        f'</div>',
        headers=headers,
    )
