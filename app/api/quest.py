"""
4.1.0 P6 — Coverage Quest API + page routes (redesign).

Plan §6 (`.github/plan.md`): the quest is a **way to complete a baseline**.
Entry is from a baseline detail page; the user picks a system to harden;
the quest then walks the baseline's MITRE techniques sequentially with
clear Tactic → Technique → Procedure framing, an "existing coverage"
panel and a link out to the existing tactic-detail editor for adding
new detections. End-of-quest returns to the baseline page (updates
persist via the underlying playbook_steps / step_detections tables).

Routes:
    POST /api/quest/start                       -- (baseline_id, system_id) → /quest/{id}
    GET  /quest/{id}                            -- walker (uses current cursor or first)
    GET  /quest/{id}/technique/{technique_id}   -- walker pinned to a specific technique
    POST /api/quest/{id}/complete/{tech}        -- mark covered, advance cursor
    POST /api/quest/{id}/end                    -- abandon, back to baseline
    GET  /api/quest/active                      -- JSON summary for tray

Legacy redirects (308):
    /quest/{id}/baseline      → /quest/{id}
    /quest/{id}/cover/{tech}  → /quest/{id}/technique/{tech}
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from app.api.deps import ActiveClient, RequireUser
from app.services import quest as quest_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["quest"])


# ── Helpers ─────────────────────────────────────────────────────────

def _set_cookie(response: Response, quest_id: str) -> None:
    """Apply the signed quest cookie. Mirrors the auth cookie's flags."""
    from app.config import get_settings
    settings = get_settings()
    response.set_cookie(
        key=quest_service.QUEST_COOKIE,
        value=quest_service.encode_quest_cookie(quest_id),
        httponly=True,
        samesite="lax",
        secure=settings.app_url.startswith("https://"),
        max_age=86400 * 30,  # 30 days; row status enforces real lifetime
        path="/",
    )


def _clear_cookie(response: Response) -> None:
    response.delete_cookie(quest_service.QUEST_COOKIE, path="/")


def _hx_redirect(request: Request, target: str) -> Response:
    """HTMX-aware redirect: real navigation when issued from `hx-post`,
    plain 303 otherwise."""
    if request.headers.get("HX-Request"):
        resp = HTMLResponse(content="", status_code=200)
        resp.headers["HX-Redirect"] = target
        return resp
    return RedirectResponse(url=target, status_code=303)


def _require_owned_quest(quest_id: str, user) -> dict:
    q = quest_service.get_quest(quest_id)
    if q is None:
        raise HTTPException(404, "quest not found")
    if q["user_id"] != user.id:
        raise HTTPException(403, "not your quest")
    return q


# ── Start ───────────────────────────────────────────────────────────

@router.post("/api/quest/start", response_class=HTMLResponse)
def api_start_quest(
    request: Request,
    user: RequireUser,
    client_id: ActiveClient,
    baseline_id: str = Form(...),
    system_id: Optional[str] = Form(None),
):
    """Begin a quest scoped to (baseline, system). Idempotent: if the
    user already has an active quest for the same triple, redirects to it
    instead of creating a duplicate.

    If *system_id* is omitted (e.g. baseline has no applied systems and
    the user clicked Start without picking one), redirect to the
    baseline page with a query flag so the launcher can prompt for a
    system before retrying."""
    from app.services.database import get_database_service
    with get_database_service().get_connection() as c:
        if not c.execute(
            "SELECT 1 FROM playbooks WHERE id=?", [baseline_id],
        ).fetchone():
            raise HTTPException(404, "baseline not found in this tenant")

    system_id = (system_id or "").strip() or None
    if not system_id:
        # No system chosen — bounce back with a flag so the launcher
        # forces the user to pick one (handled by template ?need_system=1).
        target = f"/baselines/{baseline_id}?need_system=1"
        return _hx_redirect(request, target)

    with get_database_service().get_connection() as c:
        if not c.execute(
            "SELECT 1 FROM systems WHERE id=?", [system_id],
        ).fetchone():
            raise HTTPException(404, "system not found in this tenant")

    # Auto-apply the baseline to the chosen system if not already applied.
    # This means the user can quest-launch a fresh (baseline, system) pair
    # without first clicking through the baseline-detail "Apply system"
    # picker — the quest IS the application.
    try:
        from app.inventory_engine import apply_baseline
        apply_baseline(system_id, baseline_id, client_id=client_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "quest_start_apply_baseline_failed baseline_id=%s system_id=%s err=%s",
            baseline_id, system_id, exc,
        )

    existing = quest_service.find_active_for_triple(user.id, baseline_id, system_id)
    if existing:
        quest_id = existing["id"]
    else:
        quest_id = quest_service.start_quest(
            user_id=user.id, baseline_id=baseline_id, system_id=system_id,
        )

    target = f"/quest/{quest_id}"
    resp = _hx_redirect(request, target)
    _set_cookie(resp, quest_id)
    return resp


# ── Walker page ─────────────────────────────────────────────────────

def _render_walker(
    request: Request, user, quest: dict, technique_id: Optional[str] = None,
) -> Response:
    """Shared renderer for `/quest/{id}` and `/quest/{id}/technique/{t}`.
    Picks the requested technique, falls back to the cursor, then to the
    first uncovered, then to the first technique on the baseline."""
    techniques = quest_service.list_baseline_techniques(quest.get("baseline_id") or "")
    if not techniques:
        # Empty baseline — back to the baseline page so the user can add steps.
        return _hx_redirect(request, f"/baselines/{quest.get('baseline_id') or ''}")

    valid_ids = [t["technique_id"] for t in techniques]

    # Resolve which technique to focus on.
    target_tech = None
    if technique_id and technique_id in valid_ids:
        target_tech = technique_id
    elif quest.get("current_technique_id") in valid_ids:
        target_tech = quest["current_technique_id"]
    else:
        target_tech = quest_service.next_uncovered(quest) or techniques[0]["technique_id"]

    # Persist cursor if changed.
    if quest.get("current_technique_id") != target_tech:
        quest = quest_service.update_quest(quest["id"], current_technique_id=target_tech)

    # Real coverage from step_detections — drives strip pills + counter so
    # state matches the baseline page exactly.
    coverage_map = quest_service.baseline_coverage_map(quest["baseline_id"])

    # Locate current technique + neighbours.
    idx = next((i for i, t in enumerate(techniques) if t["technique_id"] == target_tech), 0)
    current = techniques[idx]
    prev_tech = techniques[idx - 1]["technique_id"] if idx > 0 else None
    next_tech = techniques[idx + 1]["technique_id"] if idx < len(techniques) - 1 else None

    # Decorate techniques with covered flag (data-driven).
    for t in techniques:
        t["covered"] = coverage_map.get(t["technique_id"], 0) > 0
        t["detection_count"] = coverage_map.get(t["technique_id"], 0)

    # Group techniques by tactic in MITRE_TACTICS order so the strip
    # mirrors the heatmap page layout (kill-chain left → right).
    from app.models.inventory import MITRE_TACTICS
    tactic_order = list(MITRE_TACTICS) + ["Other"]
    grouped: dict[str, list[dict]] = {tac: [] for tac in tactic_order}
    for t in techniques:
        tac = t["tactic"] if t["tactic"] in grouped else "Other"
        grouped[tac].append(t)
    grouped_columns = [
        (tac, items) for tac, items in grouped.items() if items
    ]

    # Existing coverage on this (baseline, system, technique) triple.
    coverage = quest_service.existing_coverage(
        quest["baseline_id"], quest["system_id"], target_tech,
    )

    summary = quest_service.quest_summary(quest)
    covered_count = sum(1 for t in techniques if t["covered"])

    return request.app.state.templates.TemplateResponse(
        request,
        "pages/quest.html",
        {
            "request": request,
            "user": user,
            "active_page": "quest",
            "quest": summary,
            "techniques": techniques,
            "grouped_columns": grouped_columns,
            "current": current,
            "current_index": idx,
            "prev_tech": prev_tech,
            "next_tech": next_tech,
            "coverage": coverage,
            "completed_count": covered_count,
            "current_covered": current["covered"],
        },
    )


@router.get("/quest/{quest_id}", response_class=HTMLResponse)
def page_quest(
    request: Request, quest_id: str, user: RequireUser, client_id: ActiveClient,
):
    q = _require_owned_quest(quest_id, user)
    return _render_walker(request, user, q)


@router.get("/quest/{quest_id}/technique/{technique_id}", response_class=HTMLResponse)
def page_quest_technique(
    request: Request, quest_id: str, technique_id: str,
    user: RequireUser, client_id: ActiveClient,
):
    q = _require_owned_quest(quest_id, user)
    return _render_walker(request, user, q, technique_id=technique_id)


# ── Mutations ───────────────────────────────────────────────────────

@router.post("/api/quest/{quest_id}/complete/{technique_id}", response_class=HTMLResponse)
def api_complete_technique(
    request: Request, quest_id: str, technique_id: str,
    user: RequireUser, client_id: ActiveClient,
):
    """Mark *technique_id* covered and advance to the next uncovered.
    On full completion: flip status to ``completed`` and redirect to the
    baseline detail page (so updates persist visibly) and clear cookie."""
    q = _require_owned_quest(quest_id, user)
    q = quest_service.mark_technique_complete(quest_id, technique_id)

    next_tech = quest_service.next_uncovered(q) if q else None
    if next_tech:
        quest_service.update_quest(quest_id, current_technique_id=next_tech)
        target = f"/quest/{quest_id}/technique/{next_tech}"
        resp = _hx_redirect(request, target)
        return resp

    # Done.
    quest_service.end_quest(quest_id, status="completed")
    target = f"/baselines/{q['baseline_id']}" if q and q.get("baseline_id") else "/baselines"
    resp = _hx_redirect(request, target)
    _clear_cookie(resp)
    return resp


@router.post("/api/quest/{quest_id}/end", response_class=HTMLResponse)
def api_end_quest(
    request: Request, quest_id: str, user: RequireUser, client_id: ActiveClient,
):
    """Abandon the quest. Returns the user to the baseline page (updates
    they made during the quest persist via the underlying tables)."""
    q = _require_owned_quest(quest_id, user)
    quest_service.end_quest(quest_id, status="abandoned")
    target = f"/baselines/{q['baseline_id']}" if q.get("baseline_id") else "/baselines"
    resp = _hx_redirect(request, target)
    _clear_cookie(resp)
    return resp


@router.get("/api/quest/active")
def api_active_quest(user: RequireUser, client_id: ActiveClient):
    """JSON summary of the user's current active quest, or ``{active: false}``."""
    q = quest_service.get_active_quest_for_user(user.id)
    if not q:
        return {"active": False}
    summary = quest_service.quest_summary(q)
    summary["active"] = True
    summary.pop("created_at", None)
    summary.pop("updated_at", None)
    return summary


# ── Legacy redirects (308) ──────────────────────────────────────────
# Old URLs from the pre-redesign flow keep working for one release so
# bookmarks / open tabs don't 404. Remove in 4.2.0.

@router.get("/quest/{quest_id}/baseline")
def legacy_baseline_picker(quest_id: str):
    return RedirectResponse(url=f"/quest/{quest_id}", status_code=308)


@router.get("/quest/{quest_id}/cover/{technique_id}")
def legacy_cover_page(quest_id: str, technique_id: str):
    return RedirectResponse(
        url=f"/quest/{quest_id}/technique/{technique_id}", status_code=308,
    )
