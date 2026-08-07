"""One-time cleanup: remove sequential duplicate score snapshots.

Deletes rows in ``rule_score_history`` where all score fields are identical to
the immediately preceding snapshot for the same
(rule_id, siem_id, space, client_id) timeline.
"""

from __future__ import annotations

import glob
import os
from typing import List

import duckdb

SCORE_COLUMNS: List[str] = [
    "score",
    "quality_score",
    "meta_score",
    "score_mapping",
    "score_field_type",
    "score_search_time",
    "score_language",
    "score_note",
    "score_override",
    "score_tactics",
    "score_techniques",
    "score_author",
    "score_highlights",
]


def _has_table(conn: duckdb.DuckDBPyConnection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ?",
        [table_name],
    ).fetchone()
    return bool(row and row[0])


def dedupe_file(db_path: str) -> int:
    conn = duckdb.connect(db_path)
    try:
        if not _has_table(conn, "rule_score_history"):
            return 0

        lag_exprs = [
            (
                f"LAG({col}) OVER (PARTITION BY rule_id, siem_id, space, client_id "
                f"ORDER BY created_at, id) AS prev_{col}"
            )
            for col in SCORE_COLUMNS
        ]
        comparisons = [
            f"{col} IS NOT DISTINCT FROM prev_{col}" for col in SCORE_COLUMNS
        ]

        sql = f"""
        WITH ranked AS (
            SELECT
                id,
                {", ".join(SCORE_COLUMNS)},
                {", ".join(lag_exprs)}
            FROM rule_score_history
        ),
        dupes AS (
            SELECT id
            FROM ranked
            WHERE {' AND '.join(comparisons)}
        )
        DELETE FROM rule_score_history
        WHERE id IN (SELECT id FROM dupes)
        """

        before = conn.execute("SELECT COUNT(*) FROM rule_score_history").fetchone()[0]
        conn.execute(sql)
        after = conn.execute("SELECT COUNT(*) FROM rule_score_history").fetchone()[0]
        deleted = int(before - after)
        if deleted:
            conn.execute("CHECKPOINT")
        return deleted
    finally:
        conn.close()


def main() -> None:
    db_paths = sorted(glob.glob("/app/data/*.duckdb"))
    total_deleted = 0
    touched = 0

    print("[score-dedupe] scanning tenant databases...")
    for db_path in db_paths:
        try:
            deleted = dedupe_file(db_path)
            if deleted:
                touched += 1
                total_deleted += deleted
                print(f"[score-dedupe] {os.path.basename(db_path)}: deleted {deleted}")
        except Exception as exc:
            print(f"[score-dedupe] {os.path.basename(db_path)}: skipped ({exc})")

    print(f"[score-dedupe] done: touched={touched}, deleted={total_deleted}")


if __name__ == "__main__":
    main()
