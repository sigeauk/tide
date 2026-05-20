"""Repair script: clean OpenCTI-only rows out of the SHARED threat_actors table.

Background
----------
Before 4.1.5 / 4.1.19 the OpenCTI sync writer could land rows in the shared
``tide.duckdb`` ``threat_actors`` table when called without an active tenant
context. Because every tenant reads shared first and then merges its own
per-tenant rows, those legacy OCTI rows leaked into every tenant's Threat
Landscape regardless of whether the tenant had an OpenCTI link.

This one-off cleanup:

1. Finds rows in SHARED ``threat_actors`` whose ``source`` array is
   "OCTI-only" (no MITRE marker) and deletes them. They came from a
   historical bug; the canonical home for OpenCTI rows is now the
   per-tenant DB, so removing them in shared cannot cause data loss for
   linked tenants.
2. For rows where ``source`` is a mixed ``["MITRE: ...", "OCTI"]`` array,
   strips the ``OCTI`` element while preserving the MITRE marker so the
   row continues to show up in the MITRE baseline.

Run inside the running container (so the connection is brokered through
the same pool the app uses):

    docker exec tide-app python -m app.scripts.repair_octi_source_markers

Pass ``--dry-run`` to print the planned changes without committing.
"""
from __future__ import annotations

import argparse
import logging
import sys
from typing import List

from app.services.database import get_database_service

logger = logging.getLogger("repair_octi_source_markers")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def _is_octi_only(source: List[str]) -> bool:
    if not source:
        return False
    return all((s or "").strip().upper() == "OCTI" for s in source)


def _has_octi(source: List[str]) -> bool:
    return any((s or "").strip().upper() == "OCTI" for s in (source or []))


def _strip_octi(source: List[str]) -> List[str]:
    return [s for s in (source or []) if (s or "").strip().upper() != "OCTI"]


def run(dry_run: bool = False) -> int:
    db = get_database_service()
    delete_names: List[str] = []
    update_rows: List[tuple] = []
    with db.get_shared_connection() as conn:
        rows = conn.execute(
            "SELECT name, source FROM threat_actors"
        ).fetchall()
        for name, source in rows:
            source_list = list(source) if source is not None else []
            if _is_octi_only(source_list):
                delete_names.append(name)
            elif _has_octi(source_list):
                update_rows.append((name, _strip_octi(source_list)))

        logger.info(
            "shared threat_actors scanned: %d rows, %d OCTI-only to delete, "
            "%d mixed to strip", len(rows), len(delete_names), len(update_rows),
        )

        if dry_run:
            for n in delete_names[:20]:
                logger.info("  DRY DELETE: %s", n)
            for n, s in update_rows[:20]:
                logger.info("  DRY UPDATE: %s -> %s", n, s)
            return 0

        for name in delete_names:
            conn.execute("DELETE FROM threat_actors WHERE name = ?", [name])
        for name, new_source in update_rows:
            conn.execute(
                "UPDATE threat_actors SET source = ? WHERE name = ?",
                [new_source, name],
            )

    logger.info(
        "repair complete: deleted=%d, updated=%d",
        len(delete_names), len(update_rows),
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                        help="Print planned changes without modifying the DB.")
    args = parser.parse_args()
    return run(dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
