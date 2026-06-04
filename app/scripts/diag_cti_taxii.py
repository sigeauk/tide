"""Quick standalone TAXII 2.1 cursor inspector.

Usage (always in-container per AGENTS.md §3):

    docker exec tide-app python -m app.scripts.diag_cti_taxii
    docker exec tide-app python -m app.scripts.diag_cti_taxii --connector <id>

Reports the persisted ``cti_taxii_cursors`` rows captured by the
generic TAXII client (``app.services.cti_fetchers.taxii21``). Use this
to confirm a connector is actually progressing its delta watermark
after each operator-triggered sync.

Reads from a temporary snapshot of the shared DB, so it is safe to run
while the live TIDE process holds the DuckDB writer lock. Pure read —
never mutates anything.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from typing import Dict, Tuple


def _snapshot(db_path: str) -> Tuple[str, str]:
    snap_dir = tempfile.mkdtemp(prefix="diag_taxii_")
    snap = os.path.join(snap_dir, "snap.duckdb")
    shutil.copy2(db_path, snap)
    wal = db_path + ".wal"
    if os.path.exists(wal):
        shutil.copy2(wal, snap + ".wal")
    return snap, snap_dir


def main() -> int:
    parser = argparse.ArgumentParser(prog="diag_cti_taxii")
    parser.add_argument(
        "--connector", default=None,
        help="Restrict output to one connector id (UUID).",
    )
    args = parser.parse_args()

    db_path = os.environ.get("TIDE_DB_PATH", "/app/data/tide.duckdb")
    if not os.path.exists(db_path):
        print(f"ERROR: shared DB not found at {db_path}")
        return 2

    try:
        import duckdb
    except Exception as exc:
        print(f"ERROR: duckdb import failed: {exc}")
        return 2

    snap_dir = None
    conn = None
    try:
        snap, snap_dir = _snapshot(db_path)
        conn = duckdb.connect(snap, read_only=True)
    except Exception as exc:
        print(f"ERROR: snapshot of {db_path} failed: {exc}")
        if snap_dir:
            shutil.rmtree(snap_dir, ignore_errors=True)
        return 2

    try:
        tables = {r[0] for r in conn.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema='main'"
        ).fetchall()}
        if "cti_taxii_cursors" not in tables:
            print("cti_taxii_cursors table not present "
                  "(schema < v49 — no TAXII connectors run yet).")
            return 0

        if args.connector:
            rows = conn.execute(
                "SELECT connector_id, api_root, collection_id, "
                "added_after, last_run_at FROM cti_taxii_cursors "
                "WHERE connector_id = ? "
                "ORDER BY last_run_at DESC NULLS LAST",
                [args.connector],
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT connector_id, api_root, collection_id, "
                "added_after, last_run_at FROM cti_taxii_cursors "
                "ORDER BY last_run_at DESC NULLS LAST"
            ).fetchall()

        label_by_id: Dict[str, str] = {}
        if "cti_connectors" in tables:
            try:
                for cid, vendor, label in conn.execute(
                    "SELECT id, vendor, label FROM cti_connectors"
                ).fetchall():
                    label_by_id[cid] = f"{vendor}/{label}"
            except Exception:
                pass

        if not rows:
            print("No TAXII cursors recorded.")
            return 0

        print(f"TAXII 2.1 cursor rows: {len(rows)}")
        print("-" * 78)
        for connector_id, api_root, coll, added_after, last_run in rows:
            label = label_by_id.get(connector_id, connector_id[:8])
            print(f"connector  : {label}")
            print(f"  api_root : {api_root}")
            print(f"  collect. : {coll}")
            print(f"  cursor   : {added_after}")
            print(f"  last_run : {last_run}")
            print()
        return 0
    finally:
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass
        if snap_dir:
            shutil.rmtree(snap_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
