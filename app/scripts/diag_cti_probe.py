"""Per-connection probe: hit each GraphQL connection individually with
a small page_size and report HTTP status, error payload (if any),
node count, and pageInfo. Reveals exactly which connection is slow
or errors out.
"""
from __future__ import annotations

import logging
import os
import shutil
import sys
import tempfile
import time
import traceback

import duckdb
import requests


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    db_path = os.environ.get("TIDE_DB_PATH", "/app/data/tide.duckdb")
    snap_dir = tempfile.mkdtemp(prefix="diag_cti_probe_")
    snap_path = os.path.join(snap_dir, "snap.duckdb")
    shutil.copy2(db_path, snap_path)
    wal = db_path + ".wal"
    if os.path.exists(wal):
        shutil.copy2(wal, snap_path + ".wal")

    conn = duckdb.connect(snap_path, read_only=True)
    row = conn.execute(
        "SELECT url, token_enc FROM opencti_inventory "
        "WHERE COALESCE(is_active, TRUE) = TRUE LIMIT 1"
    ).fetchone()
    if not row:
        print("no active opencti_inventory rows")
        return 0
    url, token = row
    base = url.rstrip("/") + "/graphql"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    print(f"target: {base}")

    queries = {
        "intrusionSets": "query($c:Int!){ intrusionSets(first:$c){ edges{ node{ standard_id name } } pageInfo{ hasNextPage endCursor } } }",
        "threatActors": "query($c:Int!){ threatActors(first:$c){ edges{ node{ standard_id name } } pageInfo{ hasNextPage endCursor } } }",
        "reports": "query($c:Int!){ reports(first:$c){ edges{ node{ standard_id name } } pageInfo{ hasNextPage endCursor } } }",
        "indicators": "query($c:Int!){ indicators(first:$c){ edges{ node{ standard_id pattern } } pageInfo{ hasNextPage endCursor } } }",
        "me": "{ me { name user_email } }",
    }

    for label, q in queries.items():
        print()
        print(f"--- {label} ---")
        t0 = time.time()
        try:
            r = requests.post(
                base,
                json={"query": q, "variables": {"c": 5}},
                headers=headers,
                timeout=(10, 30),
            )
            elapsed = time.time() - t0
            print(f"HTTP {r.status_code}  elapsed={elapsed:.2f}s")
            try:
                j = r.json()
            except Exception:
                print(f"non-json body[:200]: {r.text[:200]!r}")
                continue
            if "errors" in j:
                print(f"GraphQL errors: {j['errors']}")
            data = (j.get("data") or {}).get(label)
            if data:
                edges = data.get("edges") or []
                pi = data.get("pageInfo") or {}
                print(f"edges_in_page={len(edges)}  hasNextPage={pi.get('hasNextPage')}  endCursor={'set' if pi.get('endCursor') else 'none'}")
                if edges:
                    print(f"first node: {edges[0].get('node')}")
            elif label == "me":
                print(f"me data: {j.get('data')}")
            else:
                print(f"data: {j.get('data')}")
        except Exception:
            print(f"REQUEST RAISED after {time.time()-t0:.2f}s:")
            traceback.print_exc()
    return 0


if __name__ == "__main__":
    sys.exit(main())
