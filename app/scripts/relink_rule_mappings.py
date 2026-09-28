"""Relink baseline rule mappings whose rule TIDE can no longer find where the mapping says.

A mapping names one copy of a rule: (rule id, SIEM, space). Older mappings may name no SIEM
(made before destinations were recorded), may hold the rule's name instead of its id, or may name
a space the rule has since left. The technique window flags those as **Needs relinking**.

This fixes the ones with exactly one answer: the rule id -- or, failing that, the rule name
the mapping holds -- matches exactly one rule copy at the destinations the client has linked.
Ambiguous or unmatched mappings are listed and left for a person to Relink from the window.
Each fix keeps the mapping (so where it is applied and its history) and adds a "Rule relinked"
history entry saying what it pointed at before.

    docker compose stop tide-app
    docker compose run --rm --no-deps tide-app python -m app.scripts.relink_rule_mappings
    docker compose run --rm --no-deps tide-app python -m app.scripts.relink_rule_mappings --apply
    docker compose up -d

Dry run is the default. Take a copy of the data folder before ``--apply``.
"""
from __future__ import annotations

import argparse
import os
import sys

import duckdb

from app.config import get_settings


def _tenant_path(data_dir: str, client_id: str, slug: str, db_filename: str):
    for name in (db_filename, f"{slug}_{client_id[:8]}.duckdb", f"dc_{client_id[:8]}.duckdb",
                 f"primary_{client_id[:8]}.duckdb"):
        if name and os.path.exists(os.path.join(data_dir, name)):
            return os.path.join(data_dir, name)
    return None


def _plan(con, dests):
    """Each SIEM mapping whose rule copy is missing, with its unique match (or why there is none)."""
    if not dests:
        return []
    scope = " OR ".join("(siem_id = ? AND COALESCE(space, 'default') = ?)" for _ in dests)
    scope_args = [v for d in dests for v in d]
    out = []
    for det_id, rule_ref, note, siem_id, space in con.execute(
        "SELECT id, rule_ref, note, siem_id, space FROM step_detections WHERE COALESCE(source, 'manual') = 'siem'"
    ).fetchall():
        if siem_id and con.execute(
            "SELECT 1 FROM detection_rules WHERE rule_id = ? AND siem_id = ? AND COALESCE(space, 'default') = ?",
            [rule_ref, siem_id, space or "default"],
        ).fetchone():
            continue
        found = []
        for column, values in (("rule_id", [rule_ref]), ("name", [v for v in (rule_ref, note) if v])):
            if not values:
                continue
            found = con.execute(
                f"SELECT DISTINCT rule_id, siem_id, COALESCE(space, 'default'), name FROM detection_rules "
                f"WHERE {column} IN ({', '.join('?' for _ in values)}) AND ({scope})",
                values + scope_args,
            ).fetchall()
            if found:
                break
        out.append({"id": det_id, "was": note or rule_ref, "was_at": f"{siem_id}/{space}" if siem_id else "no destination",
                    "matches": found})
    return out


def run(apply: bool) -> int:
    settings = get_settings()
    data_dir = os.path.dirname(settings.db_path)
    shared = duckdb.connect(settings.db_path, read_only=True)
    clients = shared.execute("SELECT id, name, slug, db_filename FROM clients ORDER BY name").fetchall()
    dests = {}
    for cid, siem_id, space in shared.execute("SELECT client_id, siem_id, COALESCE(space, 'default') FROM client_siem_map").fetchall():
        dests.setdefault(cid, []).append((siem_id, space))
    shared.close()   # the history entry looks up destination names through the app's own connection

    from app.inventory_engine import relink_step_detection

    fixed = left = 0
    for cid, name, slug, db_filename in clients:
        path = _tenant_path(data_dir, cid, slug, db_filename)
        if not path:
            continue
        con = duckdb.connect(path, read_only=not apply)
        try:
            tables = {r[0] for r in con.execute("SHOW TABLES").fetchall()}
            if not {"step_detections", "detection_rules"} <= tables:
                continue
            plan = _plan(con, dests.get(cid, []))
            if plan:
                print(f"\n{name} ({os.path.basename(path)}): {len(plan)} mapping(s) need relinking")
            for p in plan:
                if len(p["matches"]) == 1:
                    rule_id, siem_id, space, rule_name = p["matches"][0]
                    print(f"  RELINK  {p['was']} ({p['was_at']}) -> {rule_name} ({siem_id}/{space})")
                    if apply:
                        relink_step_detection(p["id"], rule_ref=rule_id, siem_id=siem_id, space=space, note=rule_name,
                                              actor="relink_rule_mappings", client_id=cid, conn=con)
                    fixed += 1
                else:
                    why = f"{len(p['matches'])} possible rules" if p["matches"] else "no matching rule at its client's destinations"
                    print(f"  LEAVE   {p['was']} ({p['was_at']}): {why}")
                    left += 1
        finally:
            con.close()
    verb = "Relinked" if apply else "Would relink"
    print(f"\n{verb} {fixed}; {left} left for a person to Relink from the technique window.")
    if fixed and not apply:
        print("Dry run: nothing was changed. Run again with --apply.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--apply", action="store_true", help="write the fixes (default: dry run)")
    sys.exit(run(parser.parse_args().apply))
