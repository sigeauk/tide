"""Diagnostics page: a snapshot, read-only checks and look-ups.

  GET /diagnostics                  the page: snapshot, the checks ready to run, look-ups
  GET /api/diagnostics/run          run one check or all of them, for one client or every client
  GET /api/diagnostics/lookup       everything TIDE holds for a rule, user or destination
  GET/POST /api/diagnostics/fix/... preview, apply and undo a fix (app.services.diagnostic_fixes)
  POST /api/diagnostics/clients/{id}/fixes   a client's Allow diagnostic fixes switch (super admins)
  POST /api/diagnostics/access      grant or revoke Platform Admin or Support (super admins)

Who sees what (``_scope``):
  - a super admin: every client, the TIDE setup checks, user look-ups and Access;
  - a user with the SUPPORT role on the active client: that client only -- its checks, its rule
    and destination look-ups, its own log errors and its fixes when allowed. Nothing about other
    clients or users.

Checks and look-ups never change data (app.services.diagnostics). Everything is audit-logged.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

from fastapi import APIRouter, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.api.deps import ActiveClient, CurrentUser, DbDep, RequireUser
from app.services import diagnostics

logger = logging.getLogger(__name__)
router = APIRouter(tags=["diagnostics"])


@dataclass
class Scope:
    clients: List[Dict]      # the clients this user may diagnose
    full: bool               # a super admin: also TIDE setup checks, user look-ups, the whole log

    @property
    def checks(self):
        return [c for c in diagnostics.CHECKS if self.full or c.scope == "client"]

    @property
    def lookup_kinds(self):
        return [k for k in diagnostics.LOOKUP_KINDS if self.full or k != "user"]


def _scope(db, user, active_client: Optional[str]) -> Optional[Scope]:
    """What this user may see on Diagnostics, or None for nothing."""
    if not user:
        return None
    clients = sorted(db.list_clients(), key=lambda c: (c.get("name") or "").lower())
    if user.is_superadmin:
        return Scope(clients, True)
    if active_client and user.is_support(active_client):
        return Scope([c for c in clients if c["id"] == active_client], False)
    return None


def _fix_context(db, scope: Scope) -> Dict:
    """What the page needs to offer fixes: each check's fix, each client's switch, recent fixes."""
    from app.services import diagnostic_fixes as fx
    allowed = fx.fixes_allowed(db)
    ids = [c["id"] for c in scope.clients]
    return {"fixes": fx.FIX_FOR_CHECK, "fix_ok": {cid: allowed.get(cid, False) for cid in ids},
            "runs": fx.recent_runs(db, ids)}


def _required(db, user, active_client) -> Scope:
    scope = _scope(db, user, active_client)
    if scope is None:
        raise HTTPException(status_code=403, detail="Diagnostics needs Platform Admin, or Support on this client.")
    return scope


@router.get("/diagnostics", response_class=HTMLResponse)
def page_diagnostics(request: Request, db: DbDep, user: CurrentUser, client_id: ActiveClient):
    scope = _scope(db, user, client_id)
    if scope is None:
        return RedirectResponse(url="/", status_code=302)   # as Management does for non-admins
    return request.app.state.render_template("pages/admin/diagnostics.html", request, {
        "user": user, "active_page": "diagnostics", "full": scope.full,
        "snap": diagnostics.snapshot(db, scope.clients, full=scope.full),
        "checks": scope.checks, "clients": scope.clients, "lookup_kinds": scope.lookup_kinds,
        **_fix_context(db, scope), **(_access_context(db, user, scope) if scope.full else {}),
        "sync_runs": _sync_activity(scope), "active_client": client_id,
    })


def _sync_activity(scope: Scope, limit: int = 50) -> List[Dict]:
    """Recent rule and CTI sync runs in this scope, newest first, each named by its client. A super
    admin also sees scheduled connector syncs, which span clients."""
    from app.services import sync_runs
    names = {c["id"]: c["name"] for c in scope.clients}
    runs = sync_runs.recent(None if scope.full else list(names), include_unscoped=scope.full, limit=limit)
    for r in runs:
        r["client"] = names.get(r["client_id"], "—" if not r["client_id"] else r["client_id"])
    return runs


def _access_context(db, user, scope: Scope, result: Optional[Dict] = None) -> Dict:
    from app.services import diagnostic_access as access
    return {"h": access.holders(db), "actions": access.ACTIONS, "me": user.id, "result": result,
            "clients": scope.clients}


@router.post("/api/diagnostics/access", response_class=HTMLResponse)
def change_access(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient,
                  action: str = Form(...), username: str = Form(""), client: str = Form("")):
    """Grant or revoke Platform Admin or Support by username. Super admins only; never your own
    Platform Admin. Re-renders the Access section with the outcome."""
    from app.services import diagnostic_access as access
    scope = _required(db, user, client_id)
    if not scope.full:
        raise HTTPException(status_code=403, detail="Only a super admin can change Platform Admin or Support.")
    ok, message = access.change(db, user, action, username, client)
    return request.app.state.templates.TemplateResponse(
        request, "partials/diagnostics_access.html",
        _access_context(db, user, scope, {"ok": ok, "message": message}))


@router.get("/api/diagnostics/lookup", response_class=HTMLResponse)
def lookup_diagnostics(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient,
                       kind: str = Query("rule"), q: str = Query("")):
    """Everything TIDE holds for the rules, users or destinations matching ``q``, in the clients
    this user may diagnose."""
    from app.services.log_context import audit_log
    scope = _required(db, user, client_id)
    if kind not in scope.lookup_kinds:
        return HTMLResponse('<p class="text-muted">That look-up is not available to you.</p>', status_code=403)
    found = diagnostics.lookup(db, kind, q, scope.clients)
    audit_log("diagnostics_lookup", actor_id=user.id, actor_username=user.username, kind=kind, query=q.strip()[:100],
              clients=[c["id"] for c in scope.clients], results=sum(len(g["entries"]) for g in found["groups"]))
    return request.app.state.templates.TemplateResponse(request, "partials/diagnostics_lookup.html", {"found": found})


def _scoped_client(scope: Scope, client_id: str) -> Dict:
    client = next((c for c in scope.clients if c["id"] == client_id), None)
    if client is None:
        raise HTTPException(status_code=403, detail="That client is not one you can diagnose.")
    return client


def _fix_panel(request: Request, **ctx):
    return request.app.state.templates.TemplateResponse(request, "partials/diagnostics_fix.html", ctx)


@router.get("/api/diagnostics/fix/preview", response_class=HTMLResponse)
def preview_fix(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient,
                fix: str = Query(...), client: str = Query(...)):
    """What a fix would change for one client, and the box to confirm it. Changes nothing."""
    from app.services import diagnostic_fixes as fx
    scope = _required(db, user, client_id)
    target = _scoped_client(scope, client)
    if fix not in fx.FIXES_BY_ID:
        return HTMLResponse('<p class="text-muted">Unknown fix.</p>', status_code=404)
    return _fix_panel(request, mode="preview", p=fx.preview(db, fix, target),
                      allowed=fx.fixes_allowed(db).get(target["id"], False))


@router.post("/api/diagnostics/fix/apply", response_class=HTMLResponse)
def apply_fix(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient,
              fix_id: str = Form(..., alias="fix"), target_id: str = Form(..., alias="client"),
              confirm: str = Form("")):
    """Apply a fix to one client: the client must allow fixes and the person must type its name."""
    from app.services import diagnostic_fixes as fx
    from app.services.log_context import audit_log
    scope = _required(db, user, client_id)
    target = _scoped_client(scope, target_id)
    if fix_id not in fx.FIXES_BY_ID:
        return HTMLResponse('<p class="text-muted">Unknown fix.</p>', status_code=404)
    try:
        done = fx.apply(db, fix_id, target, confirm, user)
    except fx.FixRefused as exc:
        return _fix_panel(request, mode="refused", message=str(exc), p=fx.preview(db, fix_id, target),
                          allowed=fx.fixes_allowed(db).get(target["id"], False))
    audit_log("diagnostics_fix", actor_id=user.id, actor_username=user.username, fix=fix_id,
              client=target["id"], rows=done["changed"], run_id=done["run_id"], backup=done["backup"])
    return _fix_panel(request, mode="done", done=done)


@router.post("/api/diagnostics/fix/undo/{run_id}", response_class=HTMLResponse)
def undo_fix(request: Request, run_id: str, db: DbDep, user: RequireUser, client_id: ActiveClient,
             client: str = Query(...)):
    """Put back exactly what a fix changed."""
    from app.services import diagnostic_fixes as fx
    from app.services.log_context import audit_log
    scope = _required(db, user, client_id)
    target = _scoped_client(scope, client)
    try:
        done = fx.undo(db, run_id, target, user)
    except fx.FixRefused as exc:
        return _fix_panel(request, mode="refused", message=str(exc))
    audit_log("diagnostics_fix_undo", actor_id=user.id, actor_username=user.username, fix=done["fix"].id,
              client=target["id"], rows=done["restored"], run_id=run_id)
    return _fix_panel(request, mode="undone", done=done)


@router.post("/api/diagnostics/clients/{target_id}/fixes", response_class=HTMLResponse)
def set_client_fixes(request: Request, target_id: str, db: DbDep, user: RequireUser, on: str = Form("")):
    """Turn a client's Allow diagnostic fixes switch on or off. Super admins only."""
    from app.services import diagnostic_fixes as fx
    from app.services.log_context import audit_log
    if not user.is_superadmin:
        raise HTTPException(status_code=403, detail="Only a super admin can allow or stop fixes for a client.")
    client = next((c for c in db.list_clients() if c["id"] == target_id), None)
    if client is None:
        raise HTTPException(status_code=404, detail="Unknown client.")
    on = on in ("1", "true", "on")
    fx.set_fixes_allowed(db, target_id, on)
    audit_log("diagnostics_fixes_allowed", actor_id=user.id, actor_username=user.username, client=target_id, on=on)
    return request.app.state.templates.TemplateResponse(request, "partials/diagnostics_fix_switch.html", {
        "c": client, "on": on, "full": True,
    })


@router.get("/api/diagnostics/run", response_class=HTMLResponse)
def run_diagnostics(request: Request, db: DbDep, user: RequireUser, client_id: ActiveClient,
                    check: str = Query("all"), client: str = Query("all")):
    from app.services.log_context import audit_log
    scope = _required(db, user, client_id)
    allowed = {c.id: c for c in scope.checks}
    ids = list(allowed) if check == "all" else [check]
    if not all(i in allowed for i in ids):
        return HTMLResponse('<p class="text-muted">Unknown check.</p>', status_code=404)
    clients = scope.clients if client in ("", "all") else [c for c in scope.clients if c["id"] == client]
    if not clients:
        return HTMLResponse('<p class="text-muted">Unknown client.</p>', status_code=404)
    results = diagnostics.run_checks(db, ids, clients)
    findings = sum(r["count"] for r in results["install"] + [x for c in results["clients"] for x in c["results"]]
                   if r["status"] not in ("ok", "listing", "failed"))
    audit_log("diagnostics_run", actor_id=user.id, actor_username=user.username,
              checks=ids, clients=[c["id"] for c in clients], findings=findings)
    return request.app.state.templates.TemplateResponse(request, "partials/diagnostics_checks.html", {
        "checks": scope.checks, "outcomes": diagnostics.by_check(results), **_fix_context(db, scope),
        "single": allowed[check] if check != "all" else None,
    })
