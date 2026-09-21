"""Compact a bloated DuckDB file (reclaim free blocks).

DuckDB never shrinks a database file: repeated DELETE + INSERT (every rule
sync) leaves most blocks free, so a tenant DB can be ~1 GB for ~60 MB of
live data. This rewrites the database into a fresh file and swaps it in.

    # 1. STOP the app first — DuckDB allows only one process on a file:
    docker compose stop tide-app
    # 2. Dry run (default): reports live vs file size, changes nothing:
    docker compose run --rm --no-deps tide-app python -m app.scripts.compact_duckdb /app/data/primary_bc9c913e.duckdb
    # 3. Apply (keeps the original as <file>.pre-compact-<timestamp>):
    docker compose run --rm --no-deps tide-app python -m app.scripts.compact_duckdb /app/data/primary_bc9c913e.duckdb --apply
    docker compose up -d

Safety: the new file is verified table-by-table (row counts) before the
swap; the original and its WAL are kept next to it as a backup.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import time

import duckdb


def _mb(n: float) -> str:
    return f"{n / 1024 / 1024:,.0f} MB"


def compact(path: str, apply: bool) -> int:
    if not os.path.exists(path):
        print(f"ERROR: {path} not found")
        return 2
    tmp = path + ".compact"
    if os.path.exists(tmp):
        os.remove(tmp)

    size_before = os.path.getsize(path)
    con = duckdb.connect(":memory:")
    con.execute(f"ATTACH '{path}' AS old (READ_ONLY)")
    used, total = con.execute(
        "SELECT used_blocks * block_size, total_blocks * block_size FROM pragma_database_size() WHERE database_name = 'old'"
    ).fetchone()
    print(f"{path}\n  file: {_mb(size_before)}   live data: {_mb(used)}   reclaimable: {_mb(max(0, total - used))}")
    if not apply:
        print("Dry run — pass --apply (with the app stopped) to compact.")
        return 0

    t = time.time()
    con.execute(f"ATTACH '{tmp}' AS new")
    con.execute("COPY FROM DATABASE old TO new")
    tables = [r[0] for r in con.execute(
        "SELECT table_name FROM duckdb_tables() WHERE database_name = 'old'").fetchall()]
    bad = []
    for name in tables:
        a = con.execute(f'SELECT count(*) FROM old."{name}"').fetchone()[0]
        b = con.execute(f'SELECT count(*) FROM new."{name}"').fetchone()[0]
        if a != b:
            bad.append((name, a, b))
    idx_old = con.execute("SELECT count(*) FROM duckdb_indexes() WHERE database_name = 'old'").fetchone()[0]
    idx_new = con.execute("SELECT count(*) FROM duckdb_indexes() WHERE database_name = 'new'").fetchone()[0]
    con.execute("DETACH new")
    con.execute("DETACH old")
    con.close()
    if bad or idx_old != idx_new:
        print(f"ABORT: verification failed (row-count mismatches: {bad}; indexes {idx_old} -> {idx_new}). Original untouched.")
        os.remove(tmp)
        return 1

    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = f"{path}.pre-compact-{stamp}"
    os.replace(path, backup)
    if os.path.exists(path + ".wal"):
        os.replace(path + ".wal", backup + ".wal")
    os.replace(tmp, path)
    print(f"Done in {time.time() - t:.0f}s: {_mb(size_before)} -> {_mb(os.path.getsize(path))}  "
          f"({len(tables)} tables verified, {idx_new} indexes). Backup: {backup}")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", help="DuckDB file, e.g. /app/data/primary_<id>.duckdb")
    ap.add_argument("--apply", action="store_true", help="actually compact (default is a dry run)")
    args = ap.parse_args()
    sys.exit(compact(args.path, args.apply))
