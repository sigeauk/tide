"""STIX-folder egress driver.

Writes the per-tenant indicator set as a single STIX 2.1 bundle JSON
file into ``target.folder_path``. The filename is timestamped so each
run produces a fresh artifact; downstream consumers should treat the
folder as an append-only drop zone.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Optional

from ._common import _empty_summary, _load_indicators
from ._stix_bundle import build_bundle, write_bundle

logger = logging.getLogger(__name__)


def run(client_id: str, target: Dict[str, Any], *,
        now: Optional[datetime] = None) -> Dict[str, Any]:
    """Export indicators as a STIX bundle dropped to ``folder_path``.

    Returns the standard summary dict extended with
    ``bundle_path`` (the file written) and ``bundle_objects``
    (object count in the bundle).
    """
    summary = _empty_summary(target)
    summary.update({"bundle_path": None, "bundle_objects": 0})

    folder = target.get("folder_path")
    if not folder:
        summary["errors"].append(
            "stix_folder target requires folder_path to be set"
        )
        return summary

    indicators = _load_indicators(
        client_id, tlp_ceiling=target.get("tlp_ceiling") or "amber",
    )
    summary["read"] = len(indicators)
    if not indicators:
        return summary

    bundle = build_bundle(
        indicators,
        source_label=str(target.get("label") or target.get("id") or "tide"),
    )
    stamp = (now or datetime.utcnow()).strftime("%Y%m%dT%H%M%SZ")
    filename = f"tide-cti-{client_id}-{stamp}.json"
    try:
        path = write_bundle(bundle, folder, filename=filename)
    except OSError as exc:
        msg = f"stix_folder write failed ({folder}): {exc}"
        logger.error(msg, exc_info=True)
        summary["errors"].append(msg)
        summary["failures"] = len(indicators)
        return summary
    summary["bundle_path"] = path
    summary["bundle_objects"] = len(bundle.get("objects") or [])
    return summary


__all__ = ["run"]
