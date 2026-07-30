"""API routes for offline MITRE ATT&CK knowledge-base data."""

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from typing import Optional

from app.api.deps import DbDep, CurrentUser

router = APIRouter(prefix="/api/mitre", tags=["mitre"])


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
