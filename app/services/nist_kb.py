"""NIST 800-53 mapping loader for the reference database (see ``reference_db``)."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
from typing import Any, Dict, List

import pandas as pd

logger = logging.getLogger(__name__)


_NIST_FILES = [
    "nist_800_53-rev5_attack-16.1-enterprise.json",
]


def _slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (value or "").strip().lower()).strip("-") or "item"


def source_digest(mappings_dir: str) -> str:
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


def load(mappings_dir: str) -> List[str]:
    """Load the NIST mapping files into the database ``app.database`` points at.
    Returns error strings."""
    errors: List[str] = []
    app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if app_dir not in sys.path:
        sys.path.insert(0, app_dir)

    from app.database import save_nist_knowledge

    for file_name in (n for n in _NIST_FILES if os.path.isfile(os.path.join(mappings_dir, n))):
        try:
            with open(os.path.join(mappings_dir, file_name), "r", encoding="utf-8") as handle:
                bundle = json.load(handle)
            knowledge = _parse_nist_mapping(bundle, source_name=file_name)
            knowledge["capability_groups"] = pd.DataFrame(knowledge.get("capability_groups") or [])
            knowledge["capabilities"] = pd.DataFrame(knowledge.get("capabilities") or [])
            save_nist_knowledge(knowledge, domain="enterprise")
        except Exception as exc:
            logger.error("NIST KB load failed for %s", file_name, exc_info=True)
            errors.append(f"{file_name}: {exc}")
    return errors
