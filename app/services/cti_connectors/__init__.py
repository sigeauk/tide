"""Registry of CTI connector vendors.

Vendor modules register themselves by being imported here. Consumers
use :func:`get` / :func:`all_vendors` rather than importing vendor
modules directly so the API/UI can stay schema-driven.

Since 6.3.0 the only vendor is OpenCTI, Threat Landscape's source of
intrusion sets; the TAXII feeds (Mandiant, CrowdStrike, GreyNoise, MITRE
ATT&CK) went with the CTI pages they fed.
"""

from __future__ import annotations

from typing import Dict, List

from ._base import ConnectorVendor, FieldSpec
from . import opencti_taxii as _opencti_taxii

__all__ = [
    "ConnectorVendor", "FieldSpec",
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
