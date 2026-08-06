"""Build-time loader for offline NIST 800-53 mappings."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
from typing import Any, Dict

import pandas as pd

from app.services.database import get_database_service

logger = logging.getLogger(__name__)


_NIST_FILES = [
    "nist_800_53-rev5_attack-16.1-enterprise.json",
]


def _slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (value or "").strip().lower()).strip("-") or "item"


def _nist_source_digest(mappings_dir: str) -> str:
    h = hashlib.sha256()
    for name in sorted(_NIST_FILES):
        path = os.path.join(mappings_dir, name)
        if not os.path.isfile(path):
            continue
        st = os.stat(path)
        h.update(name.encode("utf-8"))
        h.update(str(st.st_size).encode("ascii"))
        h.update(str(st.st_mtime_ns).encode("ascii"))
    return h.hexdigest()


def _parse_nist_mapping(bundle: Dict[str, Any], source_name: str) -> Dict[str, Any]:
    metadata = bundle.get("metadata") or {}
    capability_groups = metadata.get("capability_groups") or {}

    group_rows = []
    for index, (group_code, group_name) in enumerate(capability_groups.items()):
        group_rows.append(
            {
                "group_code": (group_code or "").strip().upper(),
                "group_name": (group_name or group_code or "").strip(),
                "attack_version": (metadata.get("attack_version") or "").strip(),
                "framework_version": (metadata.get("mapping_framework_version") or "").strip(),
                "url": f"/mitre/nist/{(group_code or '').strip().upper()}",
                "sort_index": index,
            }
        )

    capability_rows = []
    for item in bundle.get("mapping_objects") or []:
        if not isinstance(item, dict):
            continue
        capability_description = (item.get("capability_description") or "").strip()
        attack_object_id = (item.get("attack_object_id") or "").strip().upper()
        capability_group = (item.get("capability_group") or "").strip().upper()
        if not capability_description or not attack_object_id or not capability_group:
            continue
        capability_id = (item.get("capability_id") or "").strip()
        capability_slug = _slugify(capability_description if capability_description else capability_id or attack_object_id)
        capability_rows.append(
            {
                "capability_group": capability_group,
                "group_name": (capability_groups.get(capability_group) or capability_group).strip(),
                "capability_id": capability_id,
                "capability_slug": capability_slug,
                "capability_description": capability_description,
                "comments": (item.get("comments") or "").strip(),
                "mapping_type": (item.get("mapping_type") or "").strip(),
                "attack_object_id": attack_object_id,
                "attack_object_name": (item.get("attack_object_name") or "").strip(),
                "status": (item.get("status") or "").strip(),
                "url": f"/mitre/nist/{capability_group}/{capability_slug}",
            }
        )

    return {
        "capability_groups": group_rows,
        "capabilities": capability_rows,
        "metadata": metadata,
        "source_name": source_name,
    }


def load_nist_kb_from_files(force: bool = False, mappings_dir: str = "/opt/repos/mappings") -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "updated": False,
        "processed_files": 0,
        "errors": [],
        "reason": "",
    }

    if not os.path.isdir(mappings_dir):
        out["reason"] = f"Mappings directory missing: {mappings_dir}"
        return out

    files = [name for name in _NIST_FILES if os.path.isfile(os.path.join(mappings_dir, name))]
    if not files:
        out["reason"] = "No NIST mappings files found."
        return out

    digest = _nist_source_digest(mappings_dir)
    db = get_database_service()

    app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if app_dir not in sys.path:
        sys.path.insert(0, app_dir)

    from app.database import _ensure_nist_kb_schema, save_nist_knowledge

    with db.get_shared_connection() as conn:
        _ensure_nist_kb_schema(conn)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS nist_kb_state (
                key VARCHAR PRIMARY KEY,
                value VARCHAR,
                updated_at TIMESTAMP DEFAULT now()
            )
            """
        )
        row = conn.execute("SELECT value FROM nist_kb_state WHERE key = 'source_digest'").fetchone()
        previous = row[0] if row else ""
        has_rows = int(conn.execute("SELECT COUNT(*) FROM nist_capabilities").fetchone()[0] or 0) > 0

    if (not force) and previous == digest and has_rows:
        out["reason"] = "NIST sources unchanged; skipped reload."
        return out

    with db.get_shared_connection() as conn:
        _ensure_nist_kb_schema(conn)
        conn.execute("DELETE FROM nist_capabilities")
        conn.execute("DELETE FROM nist_capability_groups")

    for file_name in files:
        file_path = os.path.join(mappings_dir, file_name)
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                bundle = json.load(handle)
            knowledge = _parse_nist_mapping(bundle, source_name=file_name)
            knowledge["capability_groups"] = pd.DataFrame(knowledge.get("capability_groups") or [])
            knowledge["capabilities"] = pd.DataFrame(knowledge.get("capabilities") or [])
            save_nist_knowledge(knowledge, domain="enterprise")
            out["processed_files"] += 1
        except Exception as exc:
            logger.error("NIST KB load failed for %s", file_name, exc_info=True)
            out["errors"].append(f"{file_name}: {exc}")

    if out["errors"]:
        out["reason"] = "NIST KB load encountered errors; digest not advanced."
        return out

    with db.get_shared_connection() as conn:
        conn.execute(
            """
            INSERT INTO nist_kb_state (key, value, updated_at)
            VALUES ('source_digest', ?, now())
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
            """,
            [digest],
        )

    out["updated"] = True
    out["reason"] = "NIST KB reloaded from local mappings-explorer files."
    return out