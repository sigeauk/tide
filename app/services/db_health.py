"""Are a database's indexes whole? (Diagnostics → Database health, #86.)

DuckDB raises a fatal error on any delete or update of a row that one of the table's indexes is
missing, as on the lab's primary tenant on 2026-10-20 (startup now rebuilds the rule history
indexes; primary keys can't be rebuilt that way). Nothing reads an index's completeness directly,
so this deletes every row of each table with an index or key, and commits, on a copy of the file:
the commit has DuckDB find every row in every index. The copy is thrown away; the live file is
only read.

The copy is tested in a separate process (``python -m app.services.db_health <copy>``): such a
commit can end the process outright, and a fatal error closes the copy for the rest of the process,
so after one the next process goes on from the following table.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Tuple

TIMEOUT = 600       # seconds one testing process may take


def check_file(path: str) -> List[Tuple[str, int, str]]:
    """``[(table, rows, problem)]`` for the tables of the database at ``path`` whose indexes are
    missing rows (or that couldn't be tested). Empty when every index is whole."""
    tmp = tempfile.mkdtemp(prefix="tide-db-health-")
    try:
        copy = os.path.join(tmp, "copy.duckdb")
        shutil.copyfile(path, copy)
        if os.path.exists(path + ".wal"):
            shutil.copyfile(path + ".wal", copy + ".wal")
        problems: List[Tuple[str, int, str]] = []
        tested: List[str] = []
        root = str(Path(__file__).resolve().parents[2])
        while True:
            before = len(tested)
            proc = subprocess.run([sys.executable, "-m", "app.services.db_health", copy, *tested],
                                  capture_output=True, text=True, timeout=TIMEOUT, cwd=root,
                                  env={**os.environ, "PYTHONPATH": root})
            current, done = None, False
            for line in proc.stdout.splitlines():
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                if "start" in msg:
                    current = msg["start"]
                elif "table" in msg:
                    tested.append(msg["table"])
                    current = None
                    if not msg["ok"]:
                        problems.append((msg["table"], msg["rows"], msg["error"]))
                elif "done" in msg:
                    done = True
                elif "unreadable" in msg:
                    return [("(the copy)", 0, f"The copy couldn't be opened ({msg['unreadable']}); "
                                              "TIDE may have been writing to it. Run the check again.")]
            if done:
                return problems
            if current is not None:     # the process ended inside this table's commit
                tested.append(current)
                problems.append((current, 0, "Committing a delete ended the process (DuckDB aborted): an index "
                                             "is missing rows, or the table is damaged."))
            elif proc.returncode != 3 or len(tested) == before:
                # 3: a fatal error, already reported; anything else, or no progress: stop here
                return problems + [("(the check)", 0,
                                    f"Testing stopped: {proc.stderr.strip()[-200:] or f'exit {proc.returncode}'}")]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _test(copy: str, skip: set) -> None:
    """In the testing process: one JSON line per table (``start``, then the result), then ``done``.
    Exits without checkpointing, so nothing is written back but the copy's WAL."""
    import duckdb
    try:
        conn = duckdb.connect(copy, config={"checkpoint_threshold": "1TB"})
        conn.execute("PRAGMA disable_checkpoint_on_shutdown")
        tables = [r[0] for r in conn.execute("""
            SELECT DISTINCT table_name FROM (
                SELECT table_name FROM duckdb_indexes() WHERE database_name = current_database()
                UNION ALL
                SELECT table_name FROM duckdb_constraints() WHERE database_name = current_database()
                AND constraint_type IN ('PRIMARY KEY', 'UNIQUE')) ORDER BY 1""").fetchall()]
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"unreadable": str(exc).splitlines()[0][:200]}), flush=True)
        os._exit(0)
    for table in tables:
        if table in skip:
            continue
        print(json.dumps({"start": table}), flush=True)
        rows = 0
        try:
            rows = conn.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
            conn.execute("BEGIN")
            conn.execute(f'DELETE FROM "{table}"')
            conn.execute("COMMIT")
            print(json.dumps({"table": table, "rows": rows, "ok": True}), flush=True)
        except Exception as exc:  # noqa: BLE001
            print(json.dumps({"table": table, "rows": rows, "ok": False,
                              "error": str(exc).splitlines()[0][:300]}), flush=True)
            if isinstance(exc, (duckdb.FatalException, duckdb.InternalException)):
                os._exit(3)     # the copy is closed for this process; the next goes on from here
            try:
                conn.execute("ROLLBACK")
            except Exception:  # noqa: BLE001
                pass
    print(json.dumps({"done": True}), flush=True)
    os._exit(0)


if __name__ == "__main__":
    _test(sys.argv[1], set(sys.argv[2:]))
