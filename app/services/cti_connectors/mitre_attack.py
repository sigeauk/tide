"""MITRE ATT&CK TAXII 2.1 connector.

ATT&CK is treated as a **static structural framework**, not a
high-frequency CTI feed:

* TAXII root is hard-pinned to ``https://attack-taxii.mitre.org/api/v21/``
  (the MITRE-hosted TAXII 2.1 service) so operators can't accidentally
  point this connector at the wrong server.
* Authentication is anonymous.
* Cursor handling is **disabled** (``use_cursor=False``) \u2014 ATT&CK
  matrix updates are quarterly and operators sync on-demand. Pulling
  the full bundle each run is cheap relative to the lookup tables it
  populates downstream (intrusion-sets, malware, course-of-action,
  attack-pattern relationships).

The collections served by attack-taxii.mitre.org are the three ATT&CK
domains: Enterprise, Mobile, ICS. An empty collection list
auto-discovers all three.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ._base import ConnectorVendor, FieldSpec, SyncResult
from app.services.cti_fetchers.taxii21 import (
    TaxiiVendorProfile, run_taxii_sync, test_taxii_connection,
)


MITRE_TAXII_ROOT = "https://attack-taxii.mitre.org/api/v21/"


FIELDS: List[FieldSpec] = [
    FieldSpec(
        key="collections", label="Collection IDs (comma-separated)",
        type="text", default="",
        help="Leave blank to pull all three ATT&CK domains "
             "(Enterprise, Mobile, ICS). Provide explicit collection "
             "IDs to restrict the run.",
    ),
    FieldSpec(
        key="page_size", label="Page Size",
        type="number", default=1000,
    ),
    FieldSpec(
        key="max_objects_per_collection",
        label="Max objects per collection per run",
        type="number", default=0,
        help="Safety cap. 0 = no cap.",
    ),
]


def _profile_from_config(cfg: Dict[str, Any]) -> TaxiiVendorProfile:
    raw_cols = (cfg.get("collections") or "").strip()
    cols = [c.strip() for c in raw_cols.split(",") if c.strip()]
    return TaxiiVendorProfile(
        name="mitre_attack",
        api_root=MITRE_TAXII_ROOT,
        collections=cols,
        auth_mode="none",
        page_size=int(cfg.get("page_size") or 1000),
        verify_tls=True,
        max_objects_per_collection=int(
            cfg.get("max_objects_per_collection") or 0
        ),
        # ATT&CK is a structural framework, not a delta-driven feed.
        # Skip the cursor so every operator-triggered sync re-pulls the
        # whole bundle and refreshes the relationship graph in place.
        use_cursor=False,
    )


def sync(connector: Dict[str, Any],
         linked_clients: List[Dict[str, Any]]) -> SyncResult:
    cfg = connector.get("config") or {}
    return run_taxii_sync(connector, linked_clients,
                          _profile_from_config(cfg))


def test_connection(connector: Dict[str, Any]) -> Dict[str, Any]:
    cfg = connector.get("config") or {}
    return test_taxii_connection(_profile_from_config(cfg))


VENDOR = ConnectorVendor(
    name="mitre_attack",
    label="MITRE ATT&CK (TAXII 2.1)",
    icon="mitre",
    kind_default="cti",
    fields=FIELDS,
    fetcher=sync,
    tester=test_connection,
)
