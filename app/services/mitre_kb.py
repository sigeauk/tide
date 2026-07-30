"""Build-time style MITRE KB loader.

Loads ATT&CK STIX files from /opt/repos/mitre into local DuckDB tables at
application startup. This path is intentionally decoupled from runtime threat
sync actions so operators can refresh other data without rewriting MITRE KB.
"""

from __future__ import annotations

import hashlib
import os
import sys
from typing import Dict, Any

from app.services.database import get_database_service

import logging

logger = logging.getLogger(__name__)


def _mitre_source_digest(mitre_dir: str) -> str:
    h = hashlib.sha256()
    files = sorted(
        f for f in os.listdir(mitre_dir)
        if f.endswith("-attack.json") and os.path.isfile(os.path.join(mitre_dir, f))
    )
    for name in files:
        p = os.path.join(mitre_dir, name)
        st = os.stat(p)
        h.update(name.encode("utf-8"))
        h.update(str(st.st_size).encode("ascii"))
        h.update(str(st.st_mtime_ns).encode("ascii"))
    return h.hexdigest()


def load_mitre_kb_from_files(force: bool = False, mitre_dir: str = "/opt/repos/mitre") -> Dict[str, Any]:
    """Load MITRE KB entities from local ATT&CK JSON files when sources change."""
    out: Dict[str, Any] = {
        "updated": False,
        "processed_files": 0,
        "errors": [],
        "reason": "",
    }

    if not os.path.isdir(mitre_dir):
        out["reason"] = f"MITRE directory missing: {mitre_dir}"
        return out

    files = sorted(
        f for f in os.listdir(mitre_dir)
        if f.endswith("-attack.json") and os.path.isfile(os.path.join(mitre_dir, f))
    )
    if not files:
        out["reason"] = "No MITRE ATT&CK JSON files found."
        return out

    # TIDE MITRE pages currently target enterprise ATT&CK parity.
    if "enterprise-attack.json" in files:
        files = ["enterprise-attack.json"]

    digest = _mitre_source_digest(mitre_dir)
    db = get_database_service()

    with db.get_shared_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mitre_kb_state (
                key VARCHAR PRIMARY KEY,
                value VARCHAR,
                updated_at TIMESTAMP DEFAULT now()
            )
            """
        )
        row = conn.execute(
            "SELECT value FROM mitre_kb_state WHERE key = 'source_digest'"
        ).fetchone()
        previous = row[0] if row else ""

        # If core MITRE tables are empty, force a reload even when source
        # digest matches. This recovers from previous failed load attempts.
        has_rows = int(conn.execute("SELECT COUNT(*) FROM mitre_techniques").fetchone()[0] or 0) > 0

    if (not force) and previous == digest and has_rows:
        out["reason"] = "MITRE sources unchanged; skipped reload."
        return out

    app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if app_dir not in sys.path:
        sys.path.insert(0, app_dir)

    import cti_helper
    from app.database import save_mitre_knowledge

    with db.get_shared_connection() as conn:
        for table in (
            "mitre_campaign_software",
            "mitre_campaign_techniques",
            "mitre_campaign_groups",
            "mitre_software_techniques",
            "mitre_group_software",
            "mitre_group_associations",
            "mitre_technique_mitigations",
            "mitre_group_techniques",
            "mitre_technique_tactics",
            "mitre_campaigns",
            "mitre_software",
            "mitre_mitigations",
            "mitre_groups",
            "mitre_tactics",
            "mitre_techniques",
        ):
            conn.execute(f"DELETE FROM {table}")

    for file_name in files:
        short_name = file_name.replace("-attack.json", "")
        file_path = os.path.join(mitre_dir, file_name)
        try:
            bundle = cti_helper.fetch_stix_data(file_path)
            if not bundle:
                out["errors"].append(f"{file_name}: no data")
                continue
            knowledge = cti_helper.process_mitre_knowledge(bundle, source_name=short_name)
            save_mitre_knowledge(knowledge, domain=short_name)
            out["processed_files"] += 1
        except Exception as exc:
            msg = f"{file_name}: {exc}"
            logger.error("MITRE KB load failed for %s", file_name, exc_info=True)
            out["errors"].append(msg)

    if out["errors"]:
        out["updated"] = False
        out["reason"] = "MITRE KB load encountered errors; digest not advanced."
        return out

    with db.get_shared_connection() as conn:
        conn.execute(
            """
            INSERT INTO mitre_kb_state (key, value, updated_at)
            VALUES ('source_digest', ?, now())
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
            """,
            [digest],
        )

    out["updated"] = True
    out["reason"] = "MITRE KB reloaded from local ATT&CK files."
    return out
