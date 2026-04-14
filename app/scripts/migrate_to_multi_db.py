#!/usr/bin/env python3
"""
migrate_to_multi_db.py — One-time migration to split a single-DB TIDE
deployment into the database-per-tenant model.

For each client in the shared DB that does NOT yet have a `db_filename`:
  1. Creates a dedicated `{slug}_{short_id}.duckdb` file.
  2. Copies all tenant-scoped rows (filtered by client_id) into it.
  3. Copies shared reference tables (mitre_techniques, threat_actors, etc.).
  4. Registers the filename on `clients.db_filename`.

The shared DB is NOT modified (existing rows are preserved for backward
compatibility).  Running this script is idempotent — clients that already
have a `db_filename` are skipped.

Usage (inside the tide-app container):
    python -m app.scripts.migrate_to_multi_db
"""

import duckdb
import logging
import os
import sys

# Allow running as `python -m app.scripts.migrate_to_multi_db`
_this = os.path.dirname(os.path.abspath(__file__))
_app_dir = os.path.dirname(_this)
_project_root = os.path.dirname(_app_dir)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from app.config import get_settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("migrate_to_multi_db")

# Tables whose rows are scoped to a client_id
TENANT_TABLES = [
    "systems",
    "hosts",
    "software_inventory",
    "detection_rules",
    "playbooks",
    "system_baselines",
    "system_baseline_snapshots",
    "vuln_detections",
    "applied_detections",
    "cve_technique_overrides",
    "classifications",
    "blind_spots",
    "app_settings",
]

# Tables without client_id that are per-tenant by foreign key
# (playbook_steps → playbooks, step_techniques/step_detections → playbook_steps)
FK_TENANT_TABLES = [
    ("playbook_steps", "playbook_id", "playbooks"),
    ("step_techniques", "step_id", "playbook_steps"),
    ("step_detections", "step_id", "playbook_steps"),
]

# Reference tables copied as-is from shared → tenant (read replicas)
REFERENCE_TABLES = [
    "mitre_techniques",
    "threat_actors",
    "siem_inventory",
    "client_siem_map",
]


def migrate(dry_run: bool = False):
    settings = get_settings()
    shared_db_path = settings.db_path
    data_dir = settings.data_dir

    if not os.path.exists(shared_db_path):
        logger.error(f"Shared DB not found: {shared_db_path}")
        return

    conn = duckdb.connect(shared_db_path)

    # Ensure db_filename column exists (migration 29)
    cols = conn.execute("DESCRIBE clients").fetchall()
    col_names = {c[0] for c in cols}
    if "db_filename" not in col_names:
        logger.info("Adding db_filename column to clients...")
        conn.execute("ALTER TABLE clients ADD COLUMN db_filename VARCHAR")

    # Get clients that need migration
    clients = conn.execute(
        "SELECT id, name, slug FROM clients WHERE db_filename IS NULL"
    ).fetchall()

    if not clients:
        logger.info("All clients already have tenant databases. Nothing to migrate.")
        conn.close()
        return

    logger.info(f"Found {len(clients)} client(s) to migrate: {[c[1] for c in clients]}")

    # Get available tables in shared DB
    existing_tables = {
        t[0]
        for t in conn.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'"
        ).fetchall()
    }

    for client_id, client_name, slug in clients:
        short_id = client_id[:8]
        db_filename = f"{slug}_{short_id}.duckdb"
        tenant_path = os.path.join(data_dir, db_filename)

        if os.path.exists(tenant_path):
            logger.warning(f"  Tenant DB already exists: {tenant_path} — skipping")
            continue

        logger.info(f"  Migrating '{client_name}' → {db_filename}")

        if dry_run:
            for tbl in TENANT_TABLES:
                if tbl not in existing_tables:
                    continue
                count = conn.execute(
                    f"SELECT COUNT(*) FROM {tbl} WHERE client_id = ?", [client_id]
                ).fetchone()[0]
                logger.info(f"    {tbl}: {count} rows")
            continue

        # Create tenant DB with schema
        from app.services.tenant_manager import _create_tenant_schema

        tconn = duckdb.connect(tenant_path)
        _create_tenant_schema(tconn)

        # Copy tenant-scoped rows
        for tbl in TENANT_TABLES:
            if tbl not in existing_tables:
                logger.info(f"    {tbl}: not in shared DB, skipping")
                continue
            try:
                # Get column names from tenant DB
                tenant_cols = {
                    c[0] for c in tconn.execute(f"DESCRIBE {tbl}").fetchall()
                }
                shared_cols = {
                    c[0] for c in conn.execute(f"DESCRIBE {tbl}").fetchall()
                }
                common_cols = sorted(tenant_cols & shared_cols)
                col_list = ", ".join(common_cols)

                # Export from shared, import to tenant
                rows = conn.execute(
                    f"SELECT {col_list} FROM {tbl} WHERE client_id = ?",
                    [client_id],
                ).fetchall()

                if rows:
                    # Clear any seeded defaults first (e.g. classifications)
                    tconn.execute(f"DELETE FROM {tbl}")
                    placeholders = ", ".join("?" for _ in common_cols)
                    tconn.executemany(
                        f"INSERT INTO {tbl} ({col_list}) VALUES ({placeholders})",
                        rows,
                    )
                logger.info(f"    {tbl}: {len(rows)} rows")
            except Exception as e:
                logger.warning(f"    {tbl}: migration failed — {e}")

        # Copy FK-linked tables (steps, techniques, detections)
        for tbl, fk_col, parent_tbl in FK_TENANT_TABLES:
            if tbl not in existing_tables:
                continue
            try:
                # Get parent IDs that belong to this client
                parent_ids = tconn.execute(
                    f"SELECT id FROM {parent_tbl}"
                ).fetchall()
                if not parent_ids:
                    logger.info(f"    {tbl}: 0 rows (no parent rows)")
                    continue

                id_list = [r[0] for r in parent_ids]
                placeholders = ", ".join("?" for _ in id_list)

                tenant_cols = {
                    c[0] for c in tconn.execute(f"DESCRIBE {tbl}").fetchall()
                }
                shared_cols = {
                    c[0] for c in conn.execute(f"DESCRIBE {tbl}").fetchall()
                }
                common_cols = sorted(tenant_cols & shared_cols)
                col_list = ", ".join(common_cols)

                rows = conn.execute(
                    f"SELECT {col_list} FROM {tbl} WHERE {fk_col} IN ({placeholders})",
                    id_list,
                ).fetchall()

                if rows:
                    val_placeholders = ", ".join("?" for _ in common_cols)
                    tconn.executemany(
                        f"INSERT INTO {tbl} ({col_list}) VALUES ({val_placeholders})",
                        rows,
                    )
                logger.info(f"    {tbl}: {len(rows)} rows")
            except Exception as e:
                logger.warning(f"    {tbl}: migration failed — {e}")

        # Copy reference tables (without ATTACH — DuckDB can't attach the
        # same file twice in one process, and `conn` already holds it)
        for ref_tbl in REFERENCE_TABLES:
            if ref_tbl not in existing_tables:
                continue
            try:
                # Read from shared via conn
                ref_cols_shared = [
                    c[0] for c in conn.execute(f"DESCRIBE {ref_tbl}").fetchall()
                ]
                ref_cols_tenant = [
                    c[0] for c in tconn.execute(f"DESCRIBE {ref_tbl}").fetchall()
                ]
                common = sorted(set(ref_cols_shared) & set(ref_cols_tenant))
                col_list = ", ".join(common)

                rows = conn.execute(f"SELECT {col_list} FROM {ref_tbl}").fetchall()
                tconn.execute(f"DELETE FROM {ref_tbl}")
                if rows:
                    placeholders = ", ".join("?" for _ in common)
                    tconn.executemany(
                        f"INSERT INTO {ref_tbl} ({col_list}) VALUES ({placeholders})",
                        rows,
                    )
                logger.info(f"    {ref_tbl} (ref): {len(rows)} rows")
            except Exception as e:
                logger.warning(f"    {ref_tbl} (ref): sync failed — {e}")

        # Copy checkedRule if it exists
        if "checkedRule" in existing_tables:
            try:
                rows = conn.execute("SELECT * FROM checkedRule").fetchall()
                if rows:
                    tconn.executemany(
                        "INSERT INTO checkedRule VALUES (?, ?, ?)", rows
                    )
                logger.info(f"    checkedRule: {len(rows)} rows")
            except Exception as e:
                logger.warning(f"    checkedRule: {e}")

        tconn.close()

        # Register in shared DB
        conn.execute(
            "UPDATE clients SET db_filename = ? WHERE id = ?",
            [db_filename, client_id],
        )
        logger.info(f"  ✓ Tenant DB created: {db_filename}")

    conn.close()
    logger.info("Migration complete.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Migrate TIDE to database-per-tenant")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be migrated without making changes",
    )
    args = parser.parse_args()
    migrate(dry_run=args.dry_run)
