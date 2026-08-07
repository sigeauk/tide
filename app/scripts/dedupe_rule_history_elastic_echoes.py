"""One-time cleanup: remove elastic sync edit echoes after local rule edits.

Deletes ``rule_lifecycle_history`` rows where an ``elastic`` ``edited`` event
with ``detail.source == 'elastic_sync'`` immediately follows a recent local
``edited`` event for the same (rule_id, siem_id, space, client_id) timeline
and its field diffs are a subset of the local edit.
"""

from __future__ import annotations

import glob
import json
import os
from collections import defaultdict
from datetime import datetime
from typing import Any, DefaultDict, Dict, List, Tuple

import duckdb

MAX_ECHO_WINDOW_SECONDS = 120


def _ensure_rule_lifecycle_history_indexes(conn: duckdb.DuckDBPyConnection) -> None:
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_rule_lifecycle_rule "
        "ON rule_lifecycle_history (rule_id, siem_id, space, client_id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_rule_lifecycle_created "
        "ON rule_lifecycle_history (created_at DESC)"
    )


def _has_table(conn: duckdb.DuckDBPyConnection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ?",
        [table_name],
    ).fetchone()
    return bool(row and row[0])


def _parse_detail(raw_value: Any) -> Dict[str, Any]:
    if isinstance(raw_value, dict):
        return raw_value
    if not raw_value:
        return {}
    try:
        parsed = json.loads(raw_value)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _coerce_ts(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def _value_text(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, list):
        cleaned = [str(item).strip() for item in value if str(item).strip()]
        return ", ".join(cleaned) if cleaned else "-"
    if isinstance(value, dict):
        try:
            return json.dumps(value, sort_keys=True)
        except Exception:
            return str(value)
    text = str(value).strip()
    return text if text else "-"


def _field_diff_map(field_diffs: Any) -> Dict[str, Tuple[str, str]]:
    out: Dict[str, Tuple[str, str]] = {}
    if not isinstance(field_diffs, list):
        return out
    for diff in field_diffs:
        if not isinstance(diff, dict):
            continue
        field_name = str(diff.get("field") or "").strip().lower()
        if not field_name:
            continue
        out[field_name] = (
            _value_text(diff.get("before")),
            _value_text(diff.get("after")),
        )
    return out


def _matches_local_echo(
    elastic_row: Dict[str, Any],
    local_row: Dict[str, Any],
) -> bool:
    elastic_ts = _coerce_ts(elastic_row.get("created_at"))
    local_ts = _coerce_ts(local_row.get("created_at"))
    if not elastic_ts or not local_ts:
        return False

    delta = (local_ts - elastic_ts).total_seconds()
    if delta < 0 or delta > MAX_ECHO_WINDOW_SECONDS:
        return False

    elastic_detail = _parse_detail(elastic_row.get("detail"))
    elastic_map = _field_diff_map(elastic_detail.get("field_diffs"))
    elastic_changed_fields = {
        part.strip().lower()
        for part in str(elastic_detail.get("changed_fields") or "").split(",")
        if part.strip()
    }

    local_detail = _parse_detail(local_row.get("detail"))
    local_map = _field_diff_map(local_detail.get("field_diffs"))
    if elastic_map and local_map:
        if all(local_map.get(name) == values for name, values in elastic_map.items()):
            return True

    local_changed_fields = {
        part.strip().lower()
        for part in str(local_detail.get("changed_fields") or "").split(",")
        if part.strip()
    }
    if elastic_changed_fields and local_changed_fields:
        if elastic_changed_fields.issubset(local_changed_fields):
            return True

    if delta <= 5:
        return True

    return False


def dedupe_file(db_path: str) -> int:
    conn = duckdb.connect(db_path)
    try:
        if not _has_table(conn, "rule_lifecycle_history"):
            return 0

        rows = conn.execute(
            """
            SELECT
                id,
                rule_id,
                siem_id,
                space,
                client_id,
                actor_name,
                detail,
                created_at
            FROM rule_lifecycle_history
            WHERE action = 'edited'
            ORDER BY rule_id, siem_id, space, client_id, created_at, id
            """
        ).fetchall()

        timeline_by_key: DefaultDict[
            Tuple[str, str, str, str], List[Dict[str, Any]]
        ] = defaultdict(list)
        delete_ids: List[str] = []

        for row in rows:
            row_dict = {
                "id": row[0],
                "rule_id": row[1],
                "siem_id": row[2],
                "space": row[3],
                "client_id": row[4],
                "actor_name": row[5],
                "detail": row[6],
                "created_at": row[7],
            }
            key = (row[1], row[2], row[3], row[4])
            timeline_by_key[key].append(row_dict)

        for timeline in timeline_by_key.values():
            for index, row_dict in enumerate(timeline):
                actor_name = str(row_dict.get("actor_name") or "").strip().lower()
                detail = _parse_detail(row_dict.get("detail"))
                source = str(detail.get("source") or "").strip().lower()
                if actor_name != "elastic" or source != "elastic_sync":
                    continue

                elastic_ts = _coerce_ts(row_dict.get("created_at"))
                if not elastic_ts:
                    continue

                for next_row in timeline[index + 1 :]:
                    next_ts = _coerce_ts(next_row.get("created_at"))
                    if not next_ts:
                        continue
                    if (next_ts - elastic_ts).total_seconds() > MAX_ECHO_WINDOW_SECONDS:
                        break

                    next_actor = str(next_row.get("actor_name") or "").strip().lower()
                    next_detail = _parse_detail(next_row.get("detail"))
                    next_source = str(next_detail.get("source") or "").strip().lower()
                    if next_actor == "elastic" or next_source == "elastic_sync":
                        continue

                    if _matches_local_echo(row_dict, next_row):
                        delete_ids.append(str(row_dict.get("id")))
                        break

        if not delete_ids:
            return 0

        delete_id_sql = ", ".join("?" for _ in delete_ids)
        conn.execute("DROP TABLE IF EXISTS rule_lifecycle_history_survivors")
        conn.execute(
            f"""
            CREATE TABLE rule_lifecycle_history_survivors AS
            SELECT *
            FROM rule_lifecycle_history
            WHERE id NOT IN ({delete_id_sql})
            """,
            delete_ids,
        )
        conn.execute("DROP TABLE rule_lifecycle_history")
        conn.execute(
            """
            CREATE TABLE rule_lifecycle_history (
                id VARCHAR PRIMARY KEY DEFAULT (uuid()::VARCHAR),
                rule_id VARCHAR NOT NULL,
                siem_id VARCHAR NOT NULL,
                space VARCHAR NOT NULL,
                client_id VARCHAR NOT NULL,
                action VARCHAR NOT NULL,
                actor_user_id VARCHAR,
                actor_name VARCHAR,
                detail JSON,
                created_at TIMESTAMP DEFAULT now()
            )
            """
        )
        conn.execute(
            """
            INSERT INTO rule_lifecycle_history
            SELECT * FROM rule_lifecycle_history_survivors
            """
        )
        conn.execute("DROP TABLE rule_lifecycle_history_survivors")
        _ensure_rule_lifecycle_history_indexes(conn)
        conn.execute("FORCE CHECKPOINT")
        return len(delete_ids)
    finally:
        conn.close()


def main() -> None:
    db_paths = sorted(glob.glob("/app/data/*.duckdb"))
    total_deleted = 0
    touched = 0

    print("[history-dedupe] scanning tenant databases...")
    for db_path in db_paths:
        try:
            deleted = dedupe_file(db_path)
            if deleted:
                touched += 1
                total_deleted += deleted
                print(f"[history-dedupe] {os.path.basename(db_path)}: deleted {deleted}")
        except Exception as exc:
            print(f"[history-dedupe] {os.path.basename(db_path)}: skipped ({exc})")

    print(f"[history-dedupe] done: touched={touched}, deleted={total_deleted}")


if __name__ == "__main__":
    main()