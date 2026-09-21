"""Repair rule lifecycle history written by older syncs.

Two defects are cleaned up (both only touch rows written by Elastic sync,
``actor_name = 'elastic'`` — never operator actions):

1. Fake edits: syncs used to record "MITRE techniques changed" whenever
   Elastic returned the same technique IDs in a different order.
2. Mis-keyed rows: the initial bootstrap keyed events by Kibana's ``rule_id``
   instead of the stored saved-object id, so they never matched any rule
   card. The next sync re-creates them under the correct id.

    docker compose stop tide-app
    docker compose run --rm --no-deps tide-app python -m app.scripts.repair_rule_history /app/data/primary_<id>.duckdb
    docker compose run --rm --no-deps tide-app python -m app.scripts.repair_rule_history /app/data/primary_<id>.duckdb --apply
    docker compose up -d

Dry run is the default. Take a copy of the DB file before ``--apply``.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import duckdb


def _is_fake_reorder(detail_json: str) -> bool:
    try:
        d = json.loads(detail_json or "{}")
    except Exception:
        return False
    if d.get("source") != "elastic_sync":
        return False
    diffs = d.get("field_diffs") or []
    if len(diffs) != 1 or diffs[0].get("field") != "MITRE techniques":
        return False
    norm = lambda s: sorted(x.strip() for x in str(s or "").split(",") if x.strip())
    return norm(diffs[0].get("before")) == norm(diffs[0].get("after"))


def repair(path: str, apply: bool) -> int:
    if not os.path.exists(path):
        print(f"ERROR: {path} not found")
        return 2
    con = duckdb.connect(path, read_only=not apply)
    tables = {r[0] for r in con.execute("SHOW TABLES").fetchall()}
    if "rule_lifecycle_history" not in tables or "detection_rules" not in tables:
        print("Nothing to do: rule_lifecycle_history / detection_rules not present.")
        return 0

    fake = [
        rid for rid, detail in con.execute(
            "SELECT id, detail FROM rule_lifecycle_history WHERE action = 'edited' AND actor_name = 'elastic'"
        ).fetchall() if _is_fake_reorder(detail)
    ]
    mis_keyed = [
        r[0] for r in con.execute(
            """
            SELECT h.id FROM rule_lifecycle_history h
            WHERE h.actor_name = 'elastic' AND h.action IN ('created', 'edited')
              AND NOT EXISTS (SELECT 1 FROM detection_rules d
                              WHERE d.rule_id = h.rule_id AND d.siem_id = h.siem_id AND d.space = h.space)
              AND EXISTS (SELECT 1 FROM detection_rules d
                          WHERE json_extract_string(d.raw_data, '$.rule_id') = h.rule_id
                            AND d.siem_id = h.siem_id AND d.space = h.space)
            """
        ).fetchall()
    ]
    total = con.execute("SELECT count(*) FROM rule_lifecycle_history").fetchone()[0]
    ids = sorted(set(fake) | set(mis_keyed))
    print(f"{path}\n  history rows: {total}\n  fake MITRE-reorder edits: {len(fake)}\n"
          f"  mis-keyed Elastic rows:   {len(mis_keyed)}\n  total to delete:          {len(ids)}")
    if not apply:
        print("Dry run — pass --apply (app stopped, DB backed up) to delete.")
        return 0
    # DuckDB cannot reliably DELETE from a table whose non-unique ART indexes
    # hold many duplicate keys ("Failed to delete all rows from index"), so
    # drop the secondary indexes for the delete and recreate them after.
    con.execute("DROP INDEX IF EXISTS idx_rule_lifecycle_rule")
    con.execute("DROP INDEX IF EXISTS idx_rule_lifecycle_created")
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        con.execute(f"DELETE FROM rule_lifecycle_history WHERE id IN ({', '.join(['?'] * len(chunk))})", chunk)
    con.execute("CREATE INDEX IF NOT EXISTS idx_rule_lifecycle_rule ON rule_lifecycle_history (rule_id, siem_id, space, client_id)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_rule_lifecycle_created ON rule_lifecycle_history (created_at DESC)")
    con.execute("CHECKPOINT")
    after = con.execute("SELECT count(*) FROM rule_lifecycle_history").fetchone()[0]
    print(f"Deleted {total - after} rows; {after} remain. Run a sync to re-create Elastic history under the correct ids.")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    sys.exit(repair(args.path, args.apply))
