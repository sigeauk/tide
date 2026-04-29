"""Manual schema migration entrypoint.

Migrations also run automatically at app startup. This script lets operators
run them on demand (e.g. inside an offline maintenance window) and reports
the before/after schema version plus a short summary for any migration that
has notable side effects.

Usage::

    docker compose exec tide python -m app.scripts.migrate

Exits 0 on success, 1 on any failure.
"""
from __future__ import annotations

import logging
import sys


def _current_schema_version(db) -> int:
    """Best-effort read of the persisted schema_version, 0 if absent."""
    try:
        with db.get_connection() as conn:
            row = conn.execute(
                "SELECT MAX(version) FROM schema_version"
            ).fetchone()
            return int(row[0]) if row and row[0] is not None else 0
    except Exception:
        return 0


def _detection_rules_count(db) -> int:
    try:
        with db.get_connection() as conn:
            return int(conn.execute(
                "SELECT COUNT(*) FROM detection_rules"
            ).fetchone()[0])
    except Exception:
        return -1


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    log = logging.getLogger("migrate")

    # Lazy import so this script can be invoked without the full app stack
    # initialised (e.g. inside a rescue shell).
    from app.services.database import get_database_service, SCHEMA_VERSION

    db = get_database_service()
    before = _current_schema_version(db)
    log.info("Schema version (before): v%d", before)
    log.info("Code expects:           v%d", SCHEMA_VERSION)

    if before >= SCHEMA_VERSION:
        log.info("No pending migrations.")
        return 0

    rules_before = _detection_rules_count(db)

    try:
        # ``get_database_service()`` already runs migrations as a side effect
        # on construction, but call the migration entrypoint explicitly so an
        # operator running this script after a partial init still completes
        # the upgrade.
        with db.get_connection() as conn:
            db._run_migrations(conn)
    except Exception:
        log.exception("Migration failed")
        return 1

    after = _current_schema_version(db)
    rules_after = _detection_rules_count(db)
    log.info("Schema version (after):  v%d", after)

    # Migration 37 (4.0.13) wipes detection_rules. Surface this loudly so the
    # operator knows to trigger a sync before users notice empty rule grids.
    if before < 37 <= after:
        log.warning(
            "Migration 37 wiped detection_rules (was %d rows, now %d). "
            "Trigger a sync from the UI (Settings \u2192 Sync, or POST "
            "/api/admin/sync) to repopulate with siem_id correctly assigned.",
            rules_before, rules_after,
        )

    log.info("Migrations complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
