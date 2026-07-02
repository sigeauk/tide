"""Backfill ``rule_score_history`` from historical rule log files.

Reads JSONL files under ``/app/data/log/rules/<SIEM_LABEL>/`` and writes score
snapshots into each tenant DB for linked ``(siem_id, space)`` mappings.

Usage:
    docker exec tide-app python -m app.scripts.backfill_rule_score_history
    docker exec tide-app python -m app.scripts.backfill_rule_score_history --dry-run
"""

from __future__ import annotations

import argparse
import json
import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import duckdb

from app.services.database import get_database_service
from app.services.tenant_manager import tenant_context_for

logger = logging.getLogger(__name__)


def _parse_ts(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except Exception:
        return None


def _norm_space(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text or "default"


def _load_pair_map(db) -> tuple[dict[str, list[str]], dict[tuple[str, str], list[str]]]:
    """Build lookup maps from shared DB.

    Returns:
        - label_to_siem_ids: SIEM label -> [siem_id...]
        - pair_to_clients: (siem_id, space) -> [client_id...]
    """
    label_to_siem_ids: dict[str, list[str]] = defaultdict(list)
    pair_to_clients: dict[tuple[str, str], list[str]] = defaultdict(list)

    with db.get_shared_connection() as conn:
        rows = conn.execute(
            "SELECT s.id, s.label, m.client_id, "
            "LOWER(COALESCE(NULLIF(TRIM(m.space), ''), 'default')) AS space "
            "FROM siem_inventory s "
            "JOIN client_siem_map m ON m.siem_id = s.id"
        ).fetchall()

    for siem_id, label, client_id, space in rows:
        if siem_id and label:
            if siem_id not in label_to_siem_ids[label]:
                label_to_siem_ids[label].append(siem_id)
        if siem_id and client_id:
            key = (str(siem_id), str(space or "default"))
            if client_id not in pair_to_clients[key]:
                pair_to_clients[key].append(str(client_id))

    return label_to_siem_ids, pair_to_clients


def _snapshot_payload(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "score": entry.get("score"),
        "quality_score": entry.get("quality_score"),
        "meta_score": entry.get("meta_score"),
        "score_mapping": entry.get("score_mapping"),
        "score_field_type": entry.get("score_field_type"),
        "score_search_time": entry.get("score_search_time"),
        "score_language": entry.get("score_language"),
        "score_note": entry.get("score_note"),
        "score_override": entry.get("score_override"),
        "score_tactics": entry.get("score_tactics"),
        "score_techniques": entry.get("score_techniques"),
        "score_author": entry.get("score_author"),
        "score_highlights": entry.get("score_highlights"),
    }


def _row_exists(db, rule_id: str, siem_id: str, space: str, ts: datetime) -> bool:
    with db.get_connection() as conn:
        db._ensure_rule_score_history_table(conn)
        row = conn.execute(
            "SELECT 1 FROM rule_score_history "
            "WHERE rule_id = ? AND siem_id = ? AND LOWER(space) = ? AND created_at = ? "
            "LIMIT 1",
            [rule_id, siem_id, space, ts],
        ).fetchone()
    return bool(row)


def _rule_present(db, rule_id: str, siem_id: str, space: str) -> bool:
    with db.get_connection() as conn:
        try:
            row = conn.execute(
                "SELECT 1 FROM detection_rules "
                "WHERE rule_id = ? AND siem_id = ? AND LOWER(space) = ? LIMIT 1",
                [rule_id, siem_id, space],
            ).fetchone()
        except duckdb.Error as exc:
            # Some tenant DBs may be provisioned without rule tables yet.
            if "detection_rules" in str(exc):
                return False
            raise
    return bool(row)


def run_backfill(log_root: Path, dry_run: bool = False) -> int:
    db = get_database_service()
    label_to_siem_ids, pair_to_clients = _load_pair_map(db)

    inserted = 0
    inspected = 0

    files = sorted(log_root.glob("*/*-rules.log"))
    if not files:
        logger.warning("No rule log files found under %s", log_root)
        return 0

    logger.info("Scanning %d rule log files", len(files))

    for file_path in files:
        siem_label = file_path.parent.name
        siem_ids = label_to_siem_ids.get(siem_label, [])
        if not siem_ids:
            logger.debug("Skipping %s: SIEM label '%s' not mapped", file_path, siem_label)
            continue

        for line_no, raw_line in enumerate(file_path.read_text(encoding="utf-8").splitlines(), start=1):
            text = raw_line.strip()
            if not text:
                continue
            try:
                entry = json.loads(text)
            except json.JSONDecodeError:
                logger.warning("Skipping invalid JSON line %s:%d", file_path, line_no)
                continue

            inspected += 1
            rule_id = str(entry.get("rule_id") or "").strip()
            space = _norm_space(entry.get("space"))
            ts = _parse_ts(entry.get("date"))
            if not rule_id or ts is None:
                continue

            payload = _snapshot_payload(entry)

            for siem_id in siem_ids:
                clients = pair_to_clients.get((siem_id, space), [])
                if not clients:
                    continue
                for client_id in clients:
                    with tenant_context_for(client_id):
                        if not _rule_present(db, rule_id, siem_id, space):
                            continue
                        if _row_exists(db, rule_id, siem_id, space, ts):
                            continue
                        if dry_run:
                            inserted += 1
                            continue
                        db.record_rule_score_snapshot(
                            rule_id=rule_id,
                            siem_id=siem_id,
                            space=space,
                            client_id=client_id,
                            rule_data=payload,
                            created_at=ts,
                        )
                        inserted += 1

    logger.info(
        "Score history backfill complete: inspected=%d inserted=%d dry_run=%s",
        inspected,
        inserted,
        dry_run,
    )
    return inserted


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill rule score history from log files")
    parser.add_argument(
        "--log-root",
        default="/app/data/log/rules",
        help="Root folder containing SIEM subfolders and *-rules.log files",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Calculate inserts without writing to rule_score_history",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log_root = Path(args.log_root)
    if not log_root.exists():
        logger.error("Log root does not exist: %s", log_root)
        return 1

    run_backfill(log_root=log_root, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
