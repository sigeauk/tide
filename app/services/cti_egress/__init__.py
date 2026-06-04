"""CTI egress facade.

Public entry points:

* :func:`export_cti_for_target` — run one egress target.
* :func:`export_cti_for_client` — run every active target on a tenant.

Both dispatch on ``target["kind"]`` into a driver module:

================  ================================================
``kind``          driver
================  ================================================
``elastic``       :mod:`app.services.cti_egress.elastic` (default)
``stix_folder``   :mod:`app.services.cti_egress.stix_folder`
``diode``         :mod:`app.services.cti_egress.diode`
================  ================================================

The aggregated summary returned by :func:`export_cti_for_client`
carries kind-agnostic counters (``read``, ``filtered``, ``failures``)
plus the union of the kind-specific keys, so a mixed deployment can
still be inspected with a single template loop.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Optional

import requests

# Re-exported so tests can do ``patch.object(cti_egress.cti_database, ...)``.
from app.services import cti_database  # noqa: F401  (re-export)

from ._common import (
    BATCH_SIZE,
    HISTORY_PREFIX,
    LATEST_INDEX,
    _load_targets,
)
from . import diode, elastic, stix_folder

logger = logging.getLogger(__name__)


_DRIVERS = {
    "elastic": elastic.run,
    "stix_folder": stix_folder.run,
    "diode": diode.run,
}


# Aggregated counter keys produced by *any* driver. The aggregator
# below sums whichever keys are present per target, so adding a key
# to a driver doesn't require a code change here.
_AGGREGATE_KEYS = (
    "read", "filtered", "failures",
    # elastic
    "batches", "latest_indexed", "history_created", "history_duplicates",
    # stix_folder / diode
    "bundle_objects",
)


def export_cti_for_target(client_id: str, target: Dict[str, Any], *,
                          session: Optional[requests.Session] = None,
                          batch_size: int = BATCH_SIZE,
                          now: Optional[datetime] = None,
                          ) -> Dict[str, Any]:
    """Export ``client_id``'s indicators to one egress target.

    ``target`` is a row from ``cti_egress_targets`` (see
    :func:`_load_targets`). Dispatch is on ``target["kind"]``;
    unknown / missing kinds fall through to ``elastic`` for backward
    compatibility with v1 targets.

    Kind-specific keyword arguments (``session``, ``batch_size``,
    ``now``) are forwarded only when the driver accepts them; the
    file-drop drivers ignore ``session`` and ``batch_size``.
    """
    kind = (target.get("kind") or "elastic").strip().lower()
    driver = _DRIVERS.get(kind, elastic.run)
    if kind == "elastic":
        return driver(
            client_id, target,
            session=session, batch_size=batch_size, now=now,
        )
    # File-drop drivers take only ``now``.
    return driver(client_id, target, now=now)


def export_cti_for_client(client_id: str, *,
                          target_id: Optional[str] = None,
                          session: Optional[requests.Session] = None,
                          now: Optional[datetime] = None,
                          ) -> Dict[str, Any]:
    """Export indicators for every active egress target on this tenant.

    If ``target_id`` is given, only that one target is exported. The
    per-target counters are returned under ``per_target`` alongside
    an aggregated top-level summary. The aggregate keys are the union
    of every driver's counter keys; absent keys are treated as zero.
    """
    targets = _load_targets(client_id, target_id=target_id)
    overall: Dict[str, Any] = {
        "client_id": client_id,
        "targets": len(targets),
        "errors": [],
        "per_target": [],
    }
    for k in _AGGREGATE_KEYS:
        overall[k] = 0
    if not targets:
        return overall
    for t in targets:
        result = export_cti_for_target(
            client_id, t, session=session, now=now,
        )
        for k in _AGGREGATE_KEYS:
            overall[k] += int(result.get(k, 0) or 0)
        overall["errors"].extend(result.get("errors", []))
        overall["per_target"].append(result)
    return overall


__all__ = [
    "BATCH_SIZE",
    "HISTORY_PREFIX",
    "LATEST_INDEX",
    "cti_database",
    "export_cti_for_client",
    "export_cti_for_target",
]
