"""Diagnostics built-in actions: grant or revoke Platform Admin and Support, by username.

Super admins only (the route checks). The same rules as Management -> Users' Platform Admin toggle:
nobody changes their own Platform Admin flag, and every change is audit-logged. Support is per client;
granting it also adds the user to that client, since they couldn't open it otherwise. Revoking Support
leaves the user's other roles and their membership of the client as they were.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from app.services.database import SUPPORT_ROLE

logger = logging.getLogger(__name__)

ACTIONS = {
    "grant_admin": "Grant Platform Admin",
    "revoke_admin": "Revoke Platform Admin",
    "grant_support": "Grant Support",
    "revoke_support": "Revoke Support",
}


def holders(db) -> Dict[str, List[Dict[str, Any]]]:
    """Who has Platform Admin, and who has Support on which client."""
    with db.get_shared_connection() as conn:
        admins = conn.execute(
            "SELECT id, username, auth_provider, is_active FROM users WHERE is_superadmin ORDER BY lower(username)"
        ).fetchall()
        support = conn.execute(
            "SELECT u.id, u.username, u.auth_provider, u.is_active, c.id, c.name FROM user_roles ur "
            "JOIN roles r ON r.id = ur.role_id JOIN users u ON u.id = ur.user_id JOIN clients c ON c.id = ur.client_id "
            "WHERE r.name = ? ORDER BY lower(c.name), lower(u.username)", [SUPPORT_ROLE]
        ).fetchall()
    return {
        "admins": [{"id": r[0], "username": r[1], "provider": r[2] or "local", "active": r[3] is not False} for r in admins],
        "support": [{"id": r[0], "username": r[1], "provider": r[2] or "local", "active": r[3] is not False,
                     "client_id": r[4], "client": r[5]} for r in support],
    }


def change(db, actor, action: str, username: str, client_id: str = "") -> Tuple[bool, str]:
    """Apply one action. Returns ``(changed, message)``; nothing changes unless ``changed``."""
    from app.services.log_context import audit_log
    if action not in ACTIONS:
        return False, "Unknown action."
    username = (username or "").strip()
    target = db.get_user_by_username(username) if username else None
    if not target:
        return False, f"There is no user named '{username}'." if username else "Enter a username."
    name = target.get("username") or username
    active = target.get("is_active", True) is not False
    granting = action.startswith("grant")
    if granting and not active:
        return False, f"{name} is deactivated. Reactivate them in Management → Users first."

    if action.endswith("_admin"):
        if target["id"] == actor.id:
            return False, "You cannot change your own Platform Admin."
        if bool(target.get("is_superadmin")) == granting:
            return False, f"{name} {'already has' if granting else 'does not have'} Platform Admin."
        db.set_user_superadmin(target["id"], granting)
        audit_log("superadmin_grant" if granting else "superadmin_revoke", actor_id=actor.id,
                  actor_username=actor.username, target_id=target["id"], target_username=name, via="diagnostics")
        logger.warning("Platform-admin %s %s (%s) by %s from Diagnostics",
                       "granted to" if granting else "revoked from", name, target["id"], actor.username)
        return True, f"Platform Admin {'granted to' if granting else 'revoked from'} {name}."

    client = next((c for c in db.list_clients() if c["id"] == client_id), None)
    if not client:
        return False, "Choose the client."
    roles = db.get_user_roles(target["id"], client_id=client_id)
    if (SUPPORT_ROLE in roles) == granting:
        return False, f"{name} {'already has' if granting else 'does not have'} Support on {client['name']}."
    added = ""
    if granting:
        if client_id not in db.get_user_client_ids(target["id"]):
            db.assign_user_to_client(target["id"], client_id)
            added = f", and added them to {client['name']}"
        new_roles = roles + [SUPPORT_ROLE]
    else:
        new_roles = [r for r in roles if r != SUPPORT_ROLE]
    db.set_user_roles(target["id"], new_roles, client_id=client_id, grant_support=True)
    audit_log("support_grant" if granting else "support_revoke", actor_id=actor.id, actor_username=actor.username,
              target_id=target["id"], target_username=name, client=client_id, added_to_client=bool(added))
    logger.warning("Support %s %s on client %s by %s", "granted to" if granting else "revoked from",
                   name, client_id, actor.username)
    return True, f"Support on {client['name']} {'granted to' if granting else 'revoked from'} {name}{added}."
