"""Diode egress driver.

Writes the per-tenant indicator set as a STIX 2.1 bundle into a
diode-side outbox folder. The right-of-diode ingestor (step I in
PLAN_CTI.md) is responsible for picking the bundle up from the
mirrored receive folder; here we only produce the artifact.

``target.diode_endpoint`` overrides the default outbox path
(``data/diode_outbox/<client_id>/``) and is interpreted as a local
filesystem path inside the TIDE container — the diode itself owns
the off-host transport.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any, Dict, Optional

from ._common import _empty_summary, _load_indicators
from ._stix_bundle import build_bundle, write_bundle

logger = logging.getLogger(__name__)


_DEFAULT_OUTBOX_ROOT = "data/diode_outbox"


def _resolve_outbox(target: Dict[str, Any], client_id: str) -> str:
    """Pick the directory the bundle is dropped into.

    Operator-set ``diode_endpoint`` wins; otherwise we fall back to
    ``data/diode_outbox/<client_id>/`` relative to the working dir so
    a fresh deployment has a sane default without configuration.
    """
    explicit = target.get("diode_endpoint")
    if explicit:
        return explicit
    return os.path.join(_DEFAULT_OUTBOX_ROOT, client_id)


def run(client_id: str, target: Dict[str, Any], *,
        now: Optional[datetime] = None) -> Dict[str, Any]:
    """Export indicators as a STIX bundle into the diode outbox.

    Returns the standard summary dict extended with
    ``bundle_path`` and ``bundle_objects``.
    """
    summary = _empty_summary(target)
    summary.update({"bundle_path": None, "bundle_objects": 0})

    indicators = _load_indicators(
        client_id, tlp_ceiling=target.get("tlp_ceiling") or "amber",
    )
    summary["read"] = len(indicators)
    if not indicators:
        return summary

    outbox = _resolve_outbox(target, client_id)
    bundle = build_bundle(
        indicators,
        source_label=str(target.get("label") or target.get("id") or "tide"),
    )
    stamp = (now or datetime.utcnow()).strftime("%Y%m%dT%H%M%SZ")
    filename = f"tide-cti-{client_id}-{stamp}.diode.json"
    try:
        path = write_bundle(bundle, outbox, filename=filename)
    except OSError as exc:
        msg = f"diode write failed ({outbox}): {exc}"
        logger.error(msg, exc_info=True)
        summary["errors"].append(msg)
        summary["failures"] = len(indicators)
        return summary
    summary["bundle_path"] = path
    summary["bundle_objects"] = len(bundle.get("objects") or [])
    return summary


__all__ = ["run"]
