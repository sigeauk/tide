"""
Dashboard layout: save or reset the active client's layout, or the user's own copy of it.

Both need write access to the Dashboard (page:dashboard). The page itself is /dashboard in
app/main.py; app/services/dashboard_layout.py holds the layouts.
"""
import json
import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Response

from app.api.deps import ActiveClient, DbDep, RequireUser, require_write
from app.services import dashboard_layout as layouts

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"],
                   dependencies=[Depends(require_write("page:dashboard"))])


def _owner(scope: str, user) -> str:
    if scope == "client":
        return layouts.CLIENT
    if scope == "mine":
        return layouts.user_owner(user.id)
    raise HTTPException(status_code=400, detail="scope must be 'mine' or 'client'")


def _back_to_dashboard() -> Response:
    return Response(status_code=204, headers={"HX-Redirect": "/dashboard"})


@router.post("/layout")
def save_layout(db: DbDep, user: RequireUser, client_id: ActiveClient,
                scope: str = Form(...), layout: str = Form(...)):
    owner = _owner(scope, user)
    try:
        cards = layouts.clean(json.loads(layout))
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    layouts.save(db, client_id, owner, cards, user.username)
    logger.info("Dashboard layout saved: client=%s owner=%s cards=%d by=%s",
                client_id, owner, len(cards), user.username)
    return _back_to_dashboard()


@router.post("/layout/reset")
def reset_layout(db: DbDep, user: RequireUser, client_id: ActiveClient, scope: str = Form(...)):
    owner = _owner(scope, user)
    layouts.reset(db, client_id, owner)
    logger.info("Dashboard layout reset: client=%s owner=%s by=%s", client_id, owner, user.username)
    return _back_to_dashboard()
