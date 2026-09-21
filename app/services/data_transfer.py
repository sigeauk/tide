"""Portable export / import of TIDE-owned data (Management -> Data).

Supplements copying ``data/`` (see README "Moving to new hardware"): the JSON
produced here is independent of the DuckDB file format and of the host, and can
restore a single tenant or the user directory into another TIDE install.

Tenant data
    Rules and their metadata (scores, validation history, migrations, logical
    identities), baselines with their techniques and rule mappings, systems and
    the rest of the tenant database. Threat actors (re-synced from CTI),
    SIEM inventory / mapping and ``app_settings`` (may hold credentials) are
    deliberately not exported.

Users (optional, superadmin)
    Users, their per-tenant roles, tenant assignments and role permissions,
    keyed by username / role name / tenant slug so they survive new IDs. No
    password hashes and no Keycloak IDs: SSO users are re-linked by username or
    email at their first login against the new Keycloak, and local users must
    have a password set again.

The functions here take open DuckDB connections and do no request handling, so
they can be tested against throwaway databases.
"""
from __future__ import annotations

import json
import logging
from datetime import date, datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

FORMAT_VERSION = 1

# Import order matters only loosely (DuckDB enforces few FKs here) but parents
# come first so a partial failure leaves a coherent picture.
TENANT_TABLES: List[str] = [
    "detection_rules",
    "logical_rule_identities",
    "logical_rule_members",
    "rule_migrations",
    "rule_lifecycle_history",
    "rule_score_history",
    "rule_search_time_samples",
    "checkedRule",
    "playbooks",
    "playbook_steps",
    "step_techniques",
    "step_detections",
    "systems",
    "hosts",
    "software_inventory",
    "system_baselines",
    "system_baseline_snapshots",
    "applied_detections",
    "blind_spots",
    "classifications",
    "quests",
    "vuln_detections",
    "cve_technique_overrides",
]


def _json_default(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat(sep=" ") if isinstance(value, datetime) else value.isoformat()
    return str(value)


def dumps(payload: dict) -> str:
    return json.dumps(payload, default=_json_default, indent=1)


def _existing_tables(conn) -> set:
    return {r[0] for r in conn.execute(
        "SELECT table_name FROM duckdb_tables() WHERE schema_name = 'main'").fetchall()}


def _columns(conn, table: str) -> List[tuple]:
    """[(name, type)] in table order."""
    return [(r[0], r[1]) for r in conn.execute(
        "SELECT column_name, data_type FROM duckdb_columns() "
        "WHERE schema_name = 'main' AND table_name = ? ORDER BY column_index", [table]).fetchall()]


def _has_unique_key(conn, table: str) -> bool:
    return bool(conn.execute(
        "SELECT 1 FROM duckdb_constraints() WHERE schema_name = 'main' AND table_name = ? "
        "AND constraint_type IN ('PRIMARY KEY', 'UNIQUE') LIMIT 1", [table]).fetchone())


# ── Tenant data ──────────────────────────────────────────────────────────────

def export_tenant(conn) -> Dict[str, dict]:
    """Return ``{table: {"columns": [...], "rows": [[...], ...]}}`` for every exportable table present."""
    present = _existing_tables(conn)
    out: Dict[str, dict] = {}
    for table in TENANT_TABLES:
        if table not in present:
            continue
        cols = [name for name, _ in _columns(conn, table)]
        rows = conn.execute(f'SELECT * FROM "{table}"').fetchall()
        out[table] = {"columns": cols, "rows": [list(r) for r in rows]}
    return out


def import_tenant(conn, tables: Dict[str, dict], client_id: Optional[str] = None) -> Dict[str, dict]:
    """Merge exported tenant tables into ``conn``. Never overwrites or deletes.

    * Tables with a primary/unique key: existing keys are kept, new rows added.
    * Tables without one (score history, samples, checkedRule): only filled when
      the target table is empty, otherwise skipped, since a merge would duplicate.
    * Baselines whose name already exists are not duplicated by name.
    * A ``client_id`` column is rewritten to ``client_id`` (the target tenant).
    * Columns unknown to the target schema are ignored, so an export from a newer
      or older TIDE version still loads what it can.

    Returns per-table ``{"added": n, "skipped": n, "note": str}``.
    """
    present = _existing_tables(conn)
    summary: Dict[str, dict] = {}
    # A baseline whose name already exists in the target (e.g. the two default
    # baselines every new tenant is seeded with) is not imported a second time:
    # its steps are skipped and references to it are pointed at the existing one.
    pb_remap: Dict[str, str] = {}      # exported playbook id -> existing playbook id
    skip_steps: set = set()            # exported step ids belonging to skipped playbooks
    if "playbooks" in present and (tables.get("playbooks") or {}).get("rows"):
        block = tables["playbooks"]
        cols = block.get("columns") or []
        if "id" in cols and "name" in cols:
            existing = {r[0]: r[1] for r in conn.execute("SELECT name, id FROM playbooks").fetchall()}
            for row in block["rows"]:
                rid, rname = row[cols.index("id")], row[cols.index("name")]
                if rname in existing and existing[rname] != rid:
                    pb_remap[rid] = existing[rname]
    if pb_remap and (tables.get("playbook_steps") or {}).get("rows"):
        cols = tables["playbook_steps"].get("columns") or []
        if "id" in cols and "playbook_id" in cols:
            for row in tables["playbook_steps"]["rows"]:
                if row[cols.index("playbook_id")] in pb_remap:
                    skip_steps.add(row[cols.index("id")])
    # (table, column) -> rows to drop / values to rewrite
    drop_where = {("playbooks", "id"): set(pb_remap), ("playbook_steps", "playbook_id"): set(pb_remap),
                  ("step_techniques", "step_id"): skip_steps, ("step_detections", "step_id"): skip_steps}
    remap_cols = {("system_baselines", "playbook_id"): pb_remap, ("system_baseline_snapshots", "baseline_id"): pb_remap}

    for table in TENANT_TABLES:
        block = tables.get(table)
        if not block:
            continue
        if table not in present:
            summary[table] = {"added": 0, "skipped": len(block.get("rows", [])), "note": "table not in target"}
            continue
        target_cols = [name for name, _ in _columns(conn, table)]
        src_cols = block.get("columns") or []
        use = [c for c in src_cols if c in target_cols]
        rows = block.get("rows") or []
        if not use or not rows:
            summary[table] = {"added": 0, "skipped": 0, "note": ""}
            continue
        keyed = _has_unique_key(conn, table)
        if not keyed and conn.execute(f'SELECT 1 FROM "{table}" LIMIT 1').fetchone():
            summary[table] = {"added": 0, "skipped": len(rows), "note": "target has rows, no key to merge on"}
            continue
        idx = [src_cols.index(c) for c in use]
        cid_pos = use.index("client_id") if (client_id and "client_id" in use) else None
        collist = ", ".join(f'"{c}"' for c in use)
        marks = ", ".join("?" for _ in use)
        sql = f'INSERT INTO "{table}" ({collist}) VALUES ({marks})'
        if keyed:
            sql += " ON CONFLICT DO NOTHING RETURNING 1"
        added = 0
        dropped = 0
        drops = [(use.index(c), ids) for (t, c), ids in drop_where.items() if t == table and c in use and ids]
        remaps = [(use.index(c), m) for (t, c), m in remap_cols.items() if t == table and c in use and m]
        for row in rows:
            values = [row[i] for i in idx]
            if any(values[pos] in ids for pos, ids in drops):
                dropped += 1
                continue
            for pos, mapping in remaps:
                values[pos] = mapping.get(values[pos], values[pos])
            if cid_pos is not None:
                values[cid_pos] = client_id
            cur = conn.execute(sql, values)
            added += len(cur.fetchall()) if keyed else 1
        note = f"{dropped} already present by name" if dropped else ""
        summary[table] = {"added": added, "skipped": len(rows) - added, "note": note}
    return summary


# ── Users ────────────────────────────────────────────────────────────────────

_USER_FIELDS = ["username", "email", "full_name", "auth_provider", "is_active", "is_superadmin"]


def export_users(conn) -> dict:
    """Users + tenant roles/assignments/permissions, keyed by names and slugs (no secrets)."""
    slug = {r[0]: r[1] for r in conn.execute("SELECT id, slug FROM clients").fetchall()}
    role = {r[0]: r[1] for r in conn.execute("SELECT id, name FROM roles").fetchall()}
    users = []
    for uid, *vals in conn.execute(
            f"SELECT id, {', '.join(_USER_FIELDS)} FROM users ORDER BY username").fetchall():
        entry = dict(zip(_USER_FIELDS, vals))
        entry["tenants"] = [
            {"tenant": slug.get(cid), "is_default": bool(is_def)}
            for cid, is_def in conn.execute(
                "SELECT client_id, is_default FROM user_clients WHERE user_id = ?", [uid]).fetchall()
            if slug.get(cid)
        ]
        entry["roles"] = [
            {"tenant": slug.get(cid), "role": role.get(rid)}
            for cid, rid in conn.execute(
                "SELECT client_id, role_id FROM user_roles WHERE user_id = ?", [uid]).fetchall()
            if role.get(rid)
        ]
        users.append(entry)
    permissions = [
        {"tenant": slug.get(cid), "role": role.get(rid), "resource": res,
         "can_read": bool(r), "can_write": bool(w)}
        for rid, cid, res, r, w in conn.execute(
            "SELECT role_id, client_id, resource, can_read, can_write FROM role_permissions").fetchall()
        if role.get(rid)
    ]
    return {"users": users, "role_permissions": permissions}


def import_users(conn, payload: dict, tenant_map: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Add users missing from the target (matched by username). Existing users are left untouched.

    ``tenant_map`` maps an exported tenant slug to the target client id, so the
    assignments of the tenant just imported follow it even when the client was
    created under a different slug."""
    slug_to_id = {r[0]: r[1] for r in conn.execute("SELECT slug, id FROM clients").fetchall()}
    slug_to_id.update({k: v for k, v in (tenant_map or {}).items() if k and v})
    role_to_id = {r[0]: r[1] for r in conn.execute("SELECT name, id FROM roles").fetchall()}
    added, existing, no_password = [], [], 0
    for entry in payload.get("users") or []:
        username = (entry.get("username") or "").strip()
        if not username:
            continue
        if conn.execute("SELECT 1 FROM users WHERE LOWER(username) = LOWER(?)", [username]).fetchone():
            existing.append(username)
            continue
        provider = (entry.get("auth_provider") or "local").lower()
        conn.execute(
            "INSERT INTO users (username, email, full_name, auth_provider, is_active, is_superadmin, "
            "change_on_next_login) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [username, entry.get("email"), entry.get("full_name"), provider,
             bool(entry.get("is_active", True)), bool(entry.get("is_superadmin", False)),
             provider == "local"],
        )
        uid = conn.execute("SELECT id FROM users WHERE username = ?", [username]).fetchone()[0]
        if provider == "local":
            no_password += 1
        for t in entry.get("tenants") or []:
            cid = slug_to_id.get(t.get("tenant"))
            if cid:
                conn.execute(
                    "INSERT INTO user_clients (user_id, client_id, is_default) VALUES (?, ?, ?) "
                    "ON CONFLICT DO NOTHING", [uid, cid, bool(t.get("is_default"))])
        for r in entry.get("roles") or []:
            cid, rid = slug_to_id.get(r.get("tenant")), role_to_id.get(r.get("role"))
            if cid and rid:
                conn.execute(
                    "INSERT INTO user_roles (user_id, client_id, role_id) VALUES (?, ?, ?) "
                    "ON CONFLICT DO NOTHING", [uid, cid, rid])
        added.append(username)
    perms_added = 0
    for p in payload.get("role_permissions") or []:
        cid, rid = slug_to_id.get(p.get("tenant")), role_to_id.get(p.get("role"))
        if not (cid and rid and p.get("resource")):
            continue
        if conn.execute(
                "SELECT 1 FROM role_permissions WHERE role_id = ? AND client_id = ? AND resource = ?",
                [rid, cid, p["resource"]]).fetchone():
            continue
        conn.execute(
            "INSERT INTO role_permissions (role_id, client_id, resource, can_read, can_write) "
            "VALUES (?, ?, ?, ?, ?)",
            [rid, cid, p["resource"], bool(p.get("can_read")), bool(p.get("can_write"))])
        perms_added += 1
    return {"added": added, "existing": existing, "local_without_password": no_password,
            "permissions_added": perms_added}


# ── Envelope ────────────────────────────────────────────────────────────────

def build_export(tenant_slug: str, tenant_tables: Optional[dict], users: Optional[dict],
                 tide_version: str = "") -> dict:
    payload: Dict[str, Any] = {
        "tide_export_version": FORMAT_VERSION,
        "export_type": "data",
        "tide_version": tide_version,
        "exported_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "tenant": tenant_slug,
    }
    if tenant_tables is not None:
        payload["tenant_data"] = tenant_tables
    if users is not None:
        payload["user_data"] = users
    return payload


def validate_envelope(payload: Any) -> Optional[str]:
    """Return an error message when ``payload`` is not a TIDE data export, else None."""
    if not isinstance(payload, dict) or payload.get("export_type") != "data":
        return "This is not a TIDE data export."
    if int(payload.get("tide_export_version", 0) or 0) > FORMAT_VERSION:
        return "This export was made by a newer TIDE version."
    return None
