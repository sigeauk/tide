"""Mandiant TAXII 2.1 connector.

Counterpart to :mod:`app.services.cti_connectors.mandiant` (the
Advantage v4 REST connector). This module wires Mandiant's TAXII 2.1
feed into the generic engine in
:mod:`app.services.cti_fetchers.taxii21` so operators who prefer
standards-based ingest can use TAXII alongside the REST path.

Mandiant's TAXII 2 service uses HTTP Basic auth with the operator's
v4 ``key id`` / ``key secret`` pair, and emits STIX objects carrying
``x_mandiant_*`` custom properties. The generic TAXII engine ingests
STIX as plain dicts, so those custom properties pass through to
:func:`cti_ingest.ingest_stix_bundle` unchanged \u2014 no strict validation
to crash on extra fields.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ._base import ConnectorVendor, FieldSpec, SyncResult
from app.services.cti_fetchers.taxii21 import (
    TaxiiVendorProfile, run_taxii_sync, test_taxii_connection,
)


FIELDS: List[FieldSpec] = [
    FieldSpec(
        key="taxii_root", label="TAXII 2.1 API Root", type="url",
        required=True,
        default="https://api.intelligence.mandiant.com/v4/taxii2/",
        help="Mandiant TAXII 2.1 API root. Override only for regional "
             "or tenant-specific endpoints.",
    ),
    FieldSpec(
        key="api_v4_key_id", label="API v4 Key ID",
        type="text", required=True,
        help="Mandiant Advantage v4 public key (used as the HTTP "
             "Basic auth username).",
    ),
    FieldSpec(
        key="api_v4_key_secret", label="API v4 Key Secret",
        type="password", required=True, secret=True,
        help="Mandiant Advantage v4 private key (HTTP Basic password).",
    ),
    FieldSpec(
        key="collections", label="Collection IDs (comma-separated)",
        type="text", default="",
        help="Leave blank to auto-discover every collection on the "
             "API root. Provide explicit IDs to pin the connector to "
             "the subset your subscription covers (indicators, "
             "reports, actors, malware, \u2026).",
    ),
    FieldSpec(
        key="page_size", label="Page Size",
        type="number", default=1000,
        help="STIX objects per TAXII page (Mandiant caps lower than "
             "this on some collections).",
    ),
    FieldSpec(
        key="verify_tls", label="Verify TLS",
        type="bool", default=True,
    ),
    FieldSpec(
        key="max_objects_per_collection",
        label="Max objects per collection per run",
        type="number", default=0,
        help="Safety cap. 0 = no cap (rely on the cursor for delta).",
    ),
    FieldSpec(
        key="from_date", label="Start From (ISO 8601 UTC)",
        type="text", default="",
        help="One-shot ``added_after`` seed used when no cursor exists "
             "yet (e.g. 2024-01-01T00:00:00Z). Ignored once a cursor "
             "is persisted in cti_taxii_cursors.",
    ),
]


def _profile_from_config(cfg: Dict[str, Any]) -> TaxiiVendorProfile:
    raw_cols = (cfg.get("collections") or "").strip()
    cols = [c.strip() for c in raw_cols.split(",") if c.strip()]
    return TaxiiVendorProfile(
        name="mandiant_taxii",
        api_root=(cfg.get("taxii_root") or "").strip(),
        collections=cols,
        auth_mode="basic",
        auth_username=(cfg.get("api_v4_key_id") or "").strip() or None,
        auth_password=(cfg.get("api_v4_key_secret") or "").strip() or None,
        page_size=int(cfg.get("page_size") or 1000),
        verify_tls=bool(cfg.get("verify_tls", True)),
        max_objects_per_collection=int(
            cfg.get("max_objects_per_collection") or 0
        ),
        initial_added_after=(cfg.get("from_date") or "").strip() or None,
        use_cursor=True,
    )


def sync(connector: Dict[str, Any],
         linked_clients: List[Dict[str, Any]]) -> SyncResult:
    cfg = connector.get("config") or {}
    label = connector.get("label") or connector.get("id", "?")
    if (not cfg.get("taxii_root")
            or not cfg.get("api_v4_key_id")
            or not cfg.get("api_v4_key_secret")):
        return SyncResult(
            errors=[f"Mandiant TAXII connector {label!r}: missing "
                    "taxii_root, api_v4_key_id or api_v4_key_secret"],
        )
    return run_taxii_sync(connector, linked_clients,
                          _profile_from_config(cfg))


def test_connection(connector: Dict[str, Any]) -> Dict[str, Any]:
    cfg = connector.get("config") or {}
    return test_taxii_connection(_profile_from_config(cfg))


VENDOR = ConnectorVendor(
    name="mandiant_taxii",
    label="Mandiant Advantage (TAXII 2.1)",
    icon="mandiant",
    kind_default="cti",
    fields=FIELDS,
    fetcher=sync,
    tester=test_connection,
)
