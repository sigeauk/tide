"""API routes for offline MITRE ATT&CK knowledge-base data: JSON, plus the catalogue pages' grid
and window partials (app/services/mitre_catalog.py)."""

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from typing import Optional

from app.api.deps import ActiveClient, DbDep, CurrentUser
from app.services import mitre_catalog as catalog

router = APIRouter(prefix="/api/mitre", tags=["mitre"])


@router.get("/grid/{kind}", response_class=HTMLResponse)
def mitre_grid(kind: str, request: Request, db: DbDep, user: CurrentUser, client_id: ActiveClient):
    """A catalogue page's grid: cards or table, one page of it, or its group heads (the filter
    bar's inputs arrive as query parameters). Also swaps the metric strip out of band."""
    spec = catalog.KINDS.get(kind)
    if not spec:
        return HTMLResponse("Unknown MITRE catalogue.", status_code=404)
    covered, counts = catalog.coverage_for(db, client_id)
    ctx = catalog.grid(db, spec, dict(request.query_params), covered, counts)
    ctx.update(catalog.source_context(ctx["state"]["src"]))
    return request.app.state.templates.TemplateResponse(request, "partials/mitre_grid.html", ctx)


@router.get("/window/{kind}/{object_id}", response_class=HTMLResponse)
def mitre_window(kind: str, object_id: str, request: Request, db: DbDep, user: CurrentUser,
                 client_id: ActiveClient, src: str = "enterprise"):
    """One ATT&CK object's window, over its catalogue page (or any page)."""
    spec = catalog.KINDS.get(kind)
    if not spec:
        return HTMLResponse("Unknown MITRE catalogue.", status_code=404)
    src_key, _ = catalog.resolve_source(src)
    found_src, detail = catalog.resolve_detail(db, spec.detail_kind, object_id, src_key)
    if not detail:
        return HTMLResponse(f"No MITRE {spec.singular.lower()} found for {object_id}.", status_code=404)
    covered, counts = catalog.coverage_for(db, client_id)
    ctx = {
        "spec": spec,
        "detail": detail,
        "dom_id": catalog.dom_id(spec.key, detail["id"]),
        "covered_ttps": covered,
        "ttp_rule_counts": counts,
        "window_kinds": list(catalog.KINDS),
        **spec.window_context(db, client_id, detail, covered, counts),
        **catalog.source_context(found_src),
    }
    return request.app.state.templates.TemplateResponse(request, "components/mitre_window.html", ctx)


@router.get("/window/technique/{technique_id}/rules", response_class=HTMLResponse)
def mitre_technique_rules(technique_id: str, request: Request, db: DbDep, user: CurrentUser,
                          client_id: ActiveClient, offset: int = Query(0, ge=0)):
    """The rest of a technique window's Your rules, from ``offset`` on (its Show all button)."""
    tid = technique_id.strip().upper()
    rules = catalog.technique_rules(db, client_id, tid)
    ctx = catalog.technique_rule_cards(db, client_id, tid, rules, offset)
    return request.app.state.templates.TemplateResponse(request, "partials/mitre_rule_cards.html", ctx)


@router.get("", response_class=JSONResponse)
def mitre_overview(db: DbDep, user: CurrentUser):
    return db.get_mitre_overview()


@router.get("/tactic", response_class=JSONResponse)
def mitre_tactics(
    db: DbDep,
    user: CurrentUser,
    id: Optional[str] = Query(default=None),
):
    if id:
        detail = db.get_mitre_tactic_detail(id)
        if not detail:
            return JSONResponse({"detail": "Tactic not found"}, status_code=404)
        return detail
    return {"items": db.list_mitre_tactics()}


@router.get("/technique", response_class=JSONResponse)
def mitre_techniques(
    db: DbDep,
    user: CurrentUser,
    q: Optional[str] = Query(default=None),
    tactic: Optional[str] = Query(default=None),
):
    return {"items": db.list_mitre_techniques(search=q, tactic_id=tactic)}


@router.get("/technique/{technique_id}", response_class=JSONResponse)
def mitre_technique_detail(technique_id: str, db: DbDep, user: CurrentUser):
    detail = db.get_mitre_technique_detail(technique_id)
    if not detail:
        return JSONResponse({"detail": "Technique not found"}, status_code=404)
    return detail


@router.get("/groups", response_class=JSONResponse)
def mitre_groups(
    db: DbDep,
    user: CurrentUser,
    q: Optional[str] = Query(default=None),
):
    return {"items": db.list_mitre_groups(search=q)}


@router.get("/groups/{group_id}", response_class=JSONResponse)
def mitre_group_detail(group_id: str, db: DbDep, user: CurrentUser):
    detail = db.get_mitre_group_detail(group_id)
    if not detail:
        return JSONResponse({"detail": "Group not found"}, status_code=404)
    return detail
