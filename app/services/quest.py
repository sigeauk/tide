"""
4.1.0 P6 — Coverage Quest persistence and lifecycle.

Plan §6 (`.github/plan.md`): the user-facing journey "Threat → Pick system
+ baseline → Cover techniques → Convert rule → Deploy → See it green" is
currently a sequence of disconnected pages with state living only in
modal `<input>` fields. A page reload mid-flow loses the context and the
user starts over. This module persists that journey in a `quests` table
(per-tenant) with a signed cookie pointer (``tide_quest_id``) so the
server is the source of truth and any browser tab can rejoin the active
quest.

Storage: `quests` lives in the tenant DB (every entity it references —
threat actor, system, baseline — is tenant-scoped, and the isolation
contract from §2 means we should never carry quest state in the shared
DB). Schema is created on demand via :func:`_ensure_quests_table` so we
don't need a SCHEMA_VERSION bump for the shared DB or a migration on
every existing tenant DB.

Cookie: signed with the existing ``settings.session_secret`` via
``itsdangerous`` (same primitive as the auth session cookie). Lifetime
matches the session cookie — abandoning a quest just clears it.

Status values:
    * ``active``    — in progress, target of the cookie
    * ``completed`` — every required technique covered (terminal)
    * ``abandoned`` — user explicitly ended (terminal)

Concurrency: each user has at most one ``active`` quest at a time.
``start_quest`` moves any prior ``active`` row for the same user to
``abandoned`` first, so a stale cookie can't resurrect a half-finished
journey behind the scenes.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

from itsdangerous import URLSafeSerializer

logger = logging.getLogger(__name__)

# Cookie name kept short — visible in DevTools.
QUEST_COOKIE = "tide_quest_id"

# We track per-tenant-DB whether we've already created the table this
# process so the IF NOT EXISTS check isn't issued on every API call.
_schema_checked: set = set()


# ── Cookie helpers ───────────────────────────────────────────────────

def _signer():
    """Build a URLSafeSerializer keyed off the app session secret. We
    use the un-timed variant because the cookie is just a pointer at a
    server-side row — expiry is enforced by the row's ``status`` field
    and the cookie's own ``Max-Age`` set by the caller."""
    from app.config import get_settings
    return URLSafeSerializer(get_settings().session_secret, salt="tide-quest")


def encode_quest_cookie(quest_id: str) -> str:
    """Sign a quest_id for the ``tide_quest_id`` cookie value."""
    return _signer().dumps(quest_id)


def decode_quest_cookie(value: str) -> Optional[str]:
    """Return the embedded quest_id or None if the signature is bad."""
    try:
        return _signer().loads(value)
    except Exception:
        return None


def get_quest_id_from_request(request) -> Optional[str]:
    """Read + validate the ``tide_quest_id`` cookie. Returns None when
    missing or tampered."""
    raw = request.cookies.get(QUEST_COOKIE)
    if not raw:
        return None
    return decode_quest_cookie(raw)


# ── Schema ───────────────────────────────────────────────────────────

def _ensure_quests_table(conn) -> None:
    """Create the `quests` table on the connection's DB if it doesn't
    exist. Cheap (one CREATE TABLE IF NOT EXISTS per process per
    db_path) — guarded by `_schema_checked` so we only pay it once."""
    db_id = id(conn)  # poor proxy; the per-tenant-path cache below is the real key
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS quests (
            id VARCHAR PRIMARY KEY DEFAULT (uuid()),
            user_id VARCHAR NOT NULL,
            threat_actor_id VARCHAR,
            system_id VARCHAR,
            baseline_id VARCHAR,
            current_technique_id VARCHAR,
            completed_technique_ids VARCHAR[],
            status VARCHAR DEFAULT 'active',
            created_at TIMESTAMP DEFAULT now(),
            updated_at TIMESTAMP DEFAULT now()
        )
        """
    )


@contextmanager
def _conn():
    """Yield a tenant-scoped DB connection with the quests table ready.
    All quest helpers use this so callers don't have to remember the
    schema-on-demand step."""
    from app.services.database import get_database_service
    from app.services.tenant_manager import get_tenant_db_path

    db = get_database_service()
    path = get_tenant_db_path() or "shared"
    with db.get_connection() as c:
        if path not in _schema_checked:
            _ensure_quests_table(c)
            _schema_checked.add(path)
        yield c


# ── Row helpers ──────────────────────────────────────────────────────

_COLS = (
    "id", "user_id", "threat_actor_id", "system_id", "baseline_id",
    "current_technique_id", "completed_technique_ids", "status",
    "created_at", "updated_at",
)


def _row_to_dict(row) -> Dict[str, Any]:
    if row is None:
        return None
    return dict(zip(_COLS, row))


# ── CRUD ─────────────────────────────────────────────────────────────

def start_quest(
    user_id: str,
    baseline_id: str,
    system_id: str,
    threat_actor_id: Optional[str] = None,
) -> str:
    """Create a new active quest for *user_id* scoped to a (baseline, system)
    pair. Abandons any prior active quest the same user holds
    (one-active-per-user invariant). Returns the new quest_id."""
    with _conn() as c:
        c.execute(
            "UPDATE quests SET status='abandoned', updated_at=now() "
            "WHERE user_id=? AND status='active'",
            [user_id],
        )
        row = c.execute(
            "INSERT INTO quests (user_id, threat_actor_id, baseline_id, system_id, "
            "completed_technique_ids) VALUES (?, ?, ?, ?, []) RETURNING id",
            [user_id, threat_actor_id, baseline_id, system_id],
        ).fetchone()
    quest_id = row[0]
    logger.info(
        "quest_started quest_id=%s user_id=%s baseline_id=%s system_id=%s",
        quest_id, user_id, baseline_id, system_id,
    )
    return quest_id


def find_active_for_triple(
    user_id: str, baseline_id: str, system_id: str,
) -> Optional[Dict[str, Any]]:
    """Return the user's active quest matching this (baseline, system) pair,
    if any. Used by the baseline-detail Start button to flip to "Resume" and
    by /api/quest/start to be idempotent on accidental double-clicks."""
    with _conn() as c:
        row = c.execute(
            f"SELECT {', '.join(_COLS)} FROM quests "
            "WHERE user_id=? AND baseline_id=? AND system_id=? AND status='active' "
            "ORDER BY updated_at DESC LIMIT 1",
            [user_id, baseline_id, system_id],
        ).fetchone()
    return _row_to_dict(row)


def get_quest(quest_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a quest by id from the active tenant DB. Returns None if
    not found in this tenant — the caller should treat that as 404."""
    with _conn() as c:
        row = c.execute(
            f"SELECT {', '.join(_COLS)} FROM quests WHERE id=?",
            [quest_id],
        ).fetchone()
    return _row_to_dict(row)


def get_active_quest_for_user(user_id: str) -> Optional[Dict[str, Any]]:
    """Return the user's currently-active quest in this tenant, if any.
    Used by the breadcrumb tray and the `g q` keyboard shortcut."""
    with _conn() as c:
        row = c.execute(
            f"SELECT {', '.join(_COLS)} FROM quests "
            "WHERE user_id=? AND status='active' "
            "ORDER BY updated_at DESC LIMIT 1",
            [user_id],
        ).fetchone()
    return _row_to_dict(row)


def update_quest(quest_id: str, **fields) -> Optional[Dict[str, Any]]:
    """Patch the listed fields. Silently ignores unknown keys to keep
    the API call sites uncluttered."""
    allowed = {
        "system_id", "baseline_id", "current_technique_id",
        "completed_technique_ids", "status", "threat_actor_id",
    }
    sets, params = [], []
    for k, v in fields.items():
        if k not in allowed:
            continue
        sets.append(f"{k}=?")
        params.append(v)
    if not sets:
        return get_quest(quest_id)
    sets.append("updated_at=now()")
    params.append(quest_id)
    with _conn() as c:
        c.execute(f"UPDATE quests SET {', '.join(sets)} WHERE id=?", params)
    return get_quest(quest_id)


def mark_technique_complete(quest_id: str, technique_id: str) -> Optional[Dict[str, Any]]:
    """Append *technique_id* to ``completed_technique_ids`` (idempotent)
    and clear ``current_technique_id`` if it matches. The caller chooses
    the next ``current_technique_id`` so this helper stays decision-free."""
    q = get_quest(quest_id)
    if q is None:
        return None
    completed = list(q.get("completed_technique_ids") or [])
    if technique_id not in completed:
        completed.append(technique_id)
    fields: Dict[str, Any] = {"completed_technique_ids": completed}
    if q.get("current_technique_id") == technique_id:
        fields["current_technique_id"] = None
    return update_quest(quest_id, **fields)


def end_quest(quest_id: str, status: str = "abandoned") -> Optional[Dict[str, Any]]:
    """Move the quest to a terminal status (``abandoned`` or
    ``completed``). Subsequent reads still return the row so the user
    can see what they did, but the cookie should be cleared by the
    caller so it stops surfacing in the tray."""
    if status not in ("abandoned", "completed"):
        raise ValueError(f"invalid quest status: {status}")
    return update_quest(quest_id, status=status)


# ── Convenience used by the breadcrumb / tray ──────────────────────

def quest_summary(quest: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve referenced names so the tray template doesn't have to
    issue its own queries. Returns a dict with ``actor_name``,
    ``system_name``, ``baseline_name`` (each may be None) plus the raw
    quest fields."""
    out = dict(quest)
    out["actor_name"] = None
    out["system_name"] = None
    out["baseline_name"] = None

    with _conn() as c:
        if quest.get("threat_actor_id"):
            try:
                # threat_actors.name is the primary key in the tenant
                # schema, so the stored "id" is actually the name.
                row = c.execute(
                    "SELECT name FROM threat_actors WHERE name=?",
                    [quest["threat_actor_id"]],
                ).fetchone()
                if row:
                    out["actor_name"] = row[0]
            except Exception:
                pass
        if quest.get("system_id"):
            try:
                row = c.execute(
                    "SELECT name FROM systems WHERE id=?",
                    [quest["system_id"]],
                ).fetchone()
                if row:
                    out["system_name"] = row[0]
            except Exception:
                pass
        if quest.get("baseline_id"):
            try:
                row = c.execute(
                    "SELECT name FROM playbooks WHERE id=?",
                    [quest["baseline_id"]],
                ).fetchone()
                if row:
                    out["baseline_name"] = row[0]
            except Exception:
                pass
    # Progress counters (covered / total) so the tray + walker header
    # don't have to re-query the baseline_steps table for the strip.
    completed = quest.get("completed_technique_ids") or []
    out["covered_count"] = len(completed)
    out["technique_total"] = 0
    if quest.get("baseline_id"):
        try:
            with _conn() as c:
                row = c.execute(
                    "SELECT COUNT(*) FROM playbook_steps "
                    "WHERE playbook_id=? AND technique_id IS NOT NULL "
                    "AND technique_id != ''",
                    [quest["baseline_id"]],
                ).fetchone()
                if row:
                    out["technique_total"] = int(row[0])
        except Exception:
            pass
    return out


# ── Walker helpers (Phase 6 redesign) ───────────────────────────────

def list_baseline_techniques(baseline_id: str) -> List[Dict[str, Any]]:
    """Return ordered techniques on the baseline with tactic/name/description
    for the walker. Empty list if baseline has no MITRE-tagged steps."""
    with _conn() as c:
        rows = c.execute(
            "SELECT ps.id, ps.step_number, ps.technique_id, ps.tactic, "
            "       ps.title, ps.description, mt.name "
            "FROM playbook_steps ps "
            "LEFT JOIN mitre_techniques mt ON mt.id = ps.technique_id "
            "WHERE ps.playbook_id=? "
            "  AND ps.technique_id IS NOT NULL AND ps.technique_id != '' "
            "ORDER BY ps.step_number",
            [baseline_id],
        ).fetchall()
    out = []
    for r in rows:
        out.append({
            "step_id": r[0],
            "step_number": r[1],
            "technique_id": r[2],
            "tactic": r[3] or "Other",
            "title": r[4] or "",
            "description": r[5] or "",
            "technique_name": r[6] or r[4] or r[2],
        })
    return out


def existing_coverage(
    baseline_id: str, system_id: str, technique_id: str,
) -> List[Dict[str, Any]]:
    """Return the step_detections rows currently attached to the baseline
    step that maps to *technique_id*. The system_id parameter is kept for
    future system-scoped filtering — today every step detection covers the
    technique on every system the baseline is applied to. Drives the
    walker's "you already have N detections here" panel."""
    with _conn() as c:
        try:
            rows = c.execute(
                "SELECT sd.id, sd.rule_ref, sd.note, sd.source "
                "FROM playbook_steps ps "
                "JOIN step_detections sd ON sd.step_id = ps.id "
                "WHERE ps.playbook_id = ? AND ps.technique_id = ? "
                "ORDER BY sd.source, sd.rule_ref",
                [baseline_id, technique_id],
            ).fetchall()
        except Exception:
            return []
    return [
        {"detection_id": r[0], "rule_ref": r[1], "note": r[2], "source": r[3] or "manual"}
        for r in rows
    ]


def baseline_coverage_map(baseline_id: str) -> Dict[str, int]:
    """Return ``{technique_id: detection_count}`` for every MITRE-tagged
    step on *baseline_id*. One query — used by the walker's technique
    strip + header counter so coverage state matches the baseline page
    exactly (a rule attached anywhere shows here, and vice-versa)."""
    out: Dict[str, int] = {}
    with _conn() as c:
        try:
            rows = c.execute(
                "SELECT ps.technique_id, COUNT(sd.id) "
                "FROM playbook_steps ps "
                "LEFT JOIN step_detections sd ON sd.step_id = ps.id "
                "WHERE ps.playbook_id = ? "
                "  AND ps.technique_id IS NOT NULL AND ps.technique_id != '' "
                "GROUP BY ps.technique_id",
                [baseline_id],
            ).fetchall()
        except Exception:
            return out
    for tid, cnt in rows:
        out[tid] = int(cnt or 0)
    return out


def next_uncovered(quest: Dict[str, Any]) -> Optional[str]:
    """Return the next technique_id on the baseline that has no detections
    attached AND isn't in the quest's manually-marked completed set, in
    step order. Coverage is derived from real ``step_detections`` rows so
    it stays in sync with the baseline page — adding a rule there marks
    it covered here, and vice-versa. ``None`` when every technique is
    covered."""
    if not quest.get("baseline_id"):
        return None
    completed = set(quest.get("completed_technique_ids") or [])
    cov = baseline_coverage_map(quest["baseline_id"])
    for t in list_baseline_techniques(quest["baseline_id"]):
        tid = t["technique_id"]
        if cov.get(tid, 0) > 0:
            continue
        if tid in completed:
            continue
        return tid
    return None
