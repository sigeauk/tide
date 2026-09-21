"""MITRE ATT&CK loader for the reference database.

Parses the STIX bundles baked into the image (/opt/repos/mitre) into the
tables of ``reference.duckdb``. Called by ``reference_db.ensure_reference_db``.
"""

from __future__ import annotations

import hashlib
import logging
import os
import sys
from typing import List

logger = logging.getLogger(__name__)


def _files(mitre_dir: str) -> List[str]:
    return sorted(
        f for f in os.listdir(mitre_dir)
        if f.endswith("-attack.json") and os.path.isfile(os.path.join(mitre_dir, f))
    )


def source_digest(mitre_dir: str) -> str:
    h = hashlib.sha256()
    for name in _files(mitre_dir):
        st = os.stat(os.path.join(mitre_dir, name))
        h.update(name.encode("utf-8"))
        h.update(str(st.st_size).encode("ascii"))
        h.update(str(st.st_mtime_ns).encode("ascii"))
    return h.hexdigest()


def load(mitre_dir: str) -> List[str]:
    """Load every ATT&CK domain file into the database ``app.database`` points
    at. Domains are kept apart by the ``domain`` column. Returns error strings."""
    errors: List[str] = []
    app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if app_dir not in sys.path:
        sys.path.insert(0, app_dir)

    import cti_helper
    from app.database import save_mitre_knowledge

    for file_name in _files(mitre_dir):
        short_name = file_name.replace("-attack.json", "")
        try:
            bundle = cti_helper.fetch_stix_data(os.path.join(mitre_dir, file_name))
            if not bundle:
                errors.append(f"{file_name}: no data")
                continue
            knowledge = cti_helper.process_mitre_knowledge(bundle, source_name=short_name)
            save_mitre_knowledge(knowledge, domain=short_name)
        except Exception as exc:
            logger.error("MITRE KB load failed for %s", file_name, exc_info=True)
            errors.append(f"{file_name}: {exc}")
    return errors
