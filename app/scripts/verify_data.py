"""Check a TIDE data folder before and after moving it to new hardware.

Run with the app stopped, so every database is cleanly checkpointed:

    docker compose down
    docker compose run --rm --no-deps tide-app python -m app.scripts.verify_data --write

Copy ``data/`` to the new host (with the same TIDE version), then there:

    docker compose run --rm --no-deps tide-app python -m app.scripts.verify_data --check

``--write`` records a SHA-256 and per-table row counts for every database in
``data/move-manifest.json``. ``--check`` fails if any file differs from that
manifest, a database has an unflushed ``.wal`` file, a tenant database listed in
``clients`` is missing, or a ``.duckdb`` file is not referenced by any tenant.
Without a flag it only reports. Delete the manifest once the move is verified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

import duckdb

MANIFEST = "move-manifest.json"


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _row_counts(path: str) -> dict:
    conn = duckdb.connect(path, read_only=True)
    try:
        tables = [r[0] for r in conn.execute(
            "SELECT table_name FROM duckdb_tables() WHERE schema_name = 'main' ORDER BY 1").fetchall()]
        return {t: conn.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0] for t in tables}
    finally:
        conn.close()


def _referenced(data_dir: str) -> tuple[set, set]:
    """Return (tenant files listed in clients, files derived from them)."""
    shared = os.path.join(data_dir, "tide.duckdb")
    conn = duckdb.connect(shared, read_only=True)
    try:
        listed = {r[0] for r in conn.execute(
            "SELECT db_filename FROM clients WHERE db_filename IS NOT NULL").fetchall()}
    finally:
        conn.close()
    return listed, {"cti_" + name for name in listed}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="record the manifest")
    mode.add_argument("--check", action="store_true", help="compare against the manifest")
    ap.add_argument("--data-dir", default=os.getenv("DATA_DIR", "/app/data"))
    args = ap.parse_args()
    data_dir = args.data_dir

    problems: list[str] = []
    dbs = sorted(f for f in os.listdir(data_dir) if f.endswith(".duckdb"))
    if "tide.duckdb" not in dbs:
        print(f"ERROR: {data_dir}/tide.duckdb not found")
        return 2

    for wal in sorted(f for f in os.listdir(data_dir) if f.endswith(".wal")):
        problems.append(f"{wal}: unflushed WAL; stop the app cleanly (docker compose down) and try again")

    listed, cti = _referenced(data_dir)
    for name in sorted(listed):
        if name not in dbs:
            problems.append(f"{name}: listed in clients but missing from {data_dir}")
    for name in dbs:
        if name != "tide.duckdb" and name not in listed and name not in cti:
            problems.append(f"{name}: not referenced by any tenant (safe to remove if unused)")

    current = {}
    for name in dbs:
        path = os.path.join(data_dir, name)
        try:
            current[name] = {"sha256": _sha256(path), "bytes": os.path.getsize(path), "tables": _row_counts(path)}
        except Exception as exc:
            problems.append(f"{name}: cannot be opened ({exc})")

    for name, info in current.items():
        print(f"{name}: {info['bytes'] / 1024 / 1024:,.1f} MB, {len(info['tables'])} tables, "
              f"{sum(info['tables'].values()):,} rows")

    manifest_path = os.path.join(data_dir, MANIFEST)
    if args.write:
        if problems:
            print("\nNot written: fix these first")
        else:
            with open(manifest_path, "w", encoding="utf-8") as fh:
                json.dump(current, fh, indent=2)
            print(f"\nWrote {manifest_path}")
    elif args.check:
        if not os.path.exists(manifest_path):
            problems.append(f"{MANIFEST} not found; run --write on the old host and copy it with data/")
        else:
            with open(manifest_path, encoding="utf-8") as fh:
                expected = json.load(fh)
            for name, exp in expected.items():
                got = current.get(name)
                if got is None:
                    problems.append(f"{name}: missing")
                elif got["sha256"] != exp["sha256"]:
                    diff = [t for t in exp["tables"] if got["tables"].get(t) != exp["tables"][t]]
                    problems.append(f"{name}: file differs from the manifest (tables with different counts: {diff or 'none'})")
            for name in current.keys() - expected.keys():
                problems.append(f"{name}: not in the manifest")

    print()
    for p in problems:
        print("PROBLEM:", p)
    if not problems:
        print("OK")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
