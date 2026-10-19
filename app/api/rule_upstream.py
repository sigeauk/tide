"""
API routes for reviewing an upstream update to a rule that came from Elastic's or the Sigma rules
built into TIDE (app/services/rule_updates.py): the comparison dialog, and taking the ticked
sections (or none, keeping the rule as it is) to mark the update reviewed.
"""

import logging
from html import escape

from fastapi import APIRouter, Request, Query
from fastapi.responses import HTMLResponse

from app.api.deps import CurrentUser, RequireUser, DbDep, ActiveClient
from app.services import rule_updates

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/rules", tags=["rules"])


def _in_scope(db, client_id: str, siem_id: str, space: str) -> bool:
    return (siem_id, space) in set(db.get_client_siem_scopes(client_id) or [])


@router.get("/{rule_id}/upstream", response_class=HTMLResponse)
def review_update(request: Request, rule_id: str, db: DbDep, user: CurrentUser, client_id: ActiveClient,
                  siem_id: str = Query(...), space: str = Query("default")):
    """The update dialog: this rule beside its upstream rule as it is now, a tick per differing section."""
    if not _in_scope(db, client_id, siem_id, space):
        return HTMLResponse('<div class="rm-empty">Rule not found.</div>', status_code=404)
    info = rule_updates.review(db, client_id, (rule_id, siem_id, space))
    dest_name = next((s.get("name") for s in db.get_client_siems(client_id) or []
                      if s.get("id") == siem_id and str(s.get("space") or "default") == space), space)
    return request.app.state.templates.TemplateResponse(
        request, "components/rule_update_diff.html",
        {**info, "siem_id": siem_id, "space": space, "dest_name": dest_name,
         "can_apply": not user or user.can_write("page:rules")},
    )


@router.post("/{rule_id}/upstream", response_class=HTMLResponse)
async def apply_update(request: Request, rule_id: str, db: DbDep, user: RequireUser, client_id: ActiveClient,
                       siem_id: str = Query(...), space: str = Query("default")):
    """Take the ticked sections of the upstream update (none: keep the rule as it is) and mark the
    update reviewed. The outcome shows in the dialog."""
    from app.api.promotion import _run_in_context
    from app.api.rules import rule_window

    if not _in_scope(db, client_id, siem_id, space):
        return HTMLResponse('<div class="alert alert-danger">Rule not found.</div>')
    form = await request.form()
    sections = [str(s) for s in form.getlist("section")] if form.get("take") == "sections" else []
    actor = user.name or user.username
    status, message = await _run_in_context(
        rule_updates.apply, db, client_id, (rule_id, siem_id, space), sections, user.id, actor)
    if status != 200:
        return HTMLResponse(f'<div class="alert alert-danger">{escape(message)}</div>')
    window = rule_window(rule_id, siem_id, space)
    response = HTMLResponse(
        f'<div class="alert alert-success"><p>{escape(message)}</p>'
        f'<button name="Back To Rule" type="button" class="btn btn-secondary btn-sm" '
        f'hx-get="{escape(window["url"])}" hx-target="#modal-container" hx-swap="innerHTML">Back to rule</button></div>'
    )
    response.headers["HX-Trigger"] = "refreshRules"
    return response
