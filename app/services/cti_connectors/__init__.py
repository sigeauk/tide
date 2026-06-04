"""Registry of CTI connector vendors (step F).

Vendor modules register themselves by being imported here. Consumers
use :func:`get` / :func:`all_vendors` rather than importing vendor
modules directly so the API/UI can stay schema-driven.
"""

from __future__ import annotations

from typing import Dict, List

from ._base import ConnectorFetcher, ConnectorVendor, FieldSpec, SyncResult
# NOTE: the legacy OpenCTI GraphQL vendor module (``cti_connectors.opencti``)
# was deleted in 5.0.0. Actors, indicators, reports and relationships
# now flow exclusively through the TAXII 2.1 connector
# (``opencti_taxii``).
from . import opencti_taxii as _opencti_taxii
from . import mandiant_taxii as _mandiant_taxii
from . import crowdstrike_taxii as _crowdstrike_taxii
from . import mitre_attack as _mitre_attack
from . import greynoise as _greynoise

__all__ = [
    "ConnectorFetcher", "ConnectorVendor", "FieldSpec", "SyncResult",
    "get", "all_vendors", "register",
]


_REGISTRY: Dict[str, ConnectorVendor] = {}


def register(vendor: ConnectorVendor) -> None:
    _REGISTRY[vendor.name] = vendor


def get(name: str) -> ConnectorVendor:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"Unknown connector vendor: {name!r}")


def all_vendors() -> List[ConnectorVendor]:
    return sorted(_REGISTRY.values(), key=lambda v: v.label.lower())


# ── Built-in vendors ────────────────────────────────────────────────
register(_opencti_taxii.VENDOR)
register(_mandiant_taxii.VENDOR)
register(_crowdstrike_taxii.VENDOR)
register(_mitre_attack.VENDOR)
register(_greynoise.VENDOR)
