"""OpenCTI TAXII 2.1 connector — first vendor entry for the new engine.

This is the TAXII counterpart to the existing
:mod:`app.services.cti_connectors.opencti_taxii` connector (TAXII 2.1).
Operators can run both side-by-side: keep the GraphQL one for actor
sync (which mirrors the legacy Threat Landscape flow), and add this
TAXII one for high-volume indicator + relationship pulls with proper
delta cursors.

Pulls from the OpenCTI TAXII 2.1 root at
``https://<host>/taxii2/<root>/`` — typically ``/taxii2/root/`` on a
default OpenCTI deployment.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from ._base import ConnectorVendor, FieldSpec, SyncResult
from app.services.cti_fetchers.taxii21 import (
    TaxiiVendorProfile, run_taxii_sync, test_taxii_connection,
)


# OpenCTI's "Data sharing" UI hands operators URLs like
#   http://host/taxii2/root/collections/<uuid>/objects/
# instead of the bare API root. Detect that shape so the connector
# accepts either form: the regex captures the API root prefix and the
# embedded collection id, which is then auto-pinned.
_COLLECTION_OBJECTS_RE = re.compile(
    r"^(?P<root>.+?/)collections/(?P<cid>[0-9a-fA-F-]{36})(?:/objects)?/?$"
)


def _normalise_root(raw_root: str,
                    explicit_cols: List[str]) -> Tuple[str, List[str]]:
    """Return ``(api_root, collections)`` tolerating either UI form.

    OpenCTI shows per-collection objects URLs in its UI; pasting those
    into the TAXII API Root field is the most common operator mistake.
    When detected, strip the collection suffix to recover the root and
    pin the connector to that collection id (unless the operator
    already provided an explicit collections list).
    """
    root = (raw_root or "").strip()
    if not root:
        return "", explicit_cols
    if not root.endswith("/"):
        root = root + "/"
    m = _COLLECTION_OBJECTS_RE.match(root)
    if m:
        api_root = m.group("root")
        cid = m.group("cid")
        cols = explicit_cols or [cid]
        return api_root, cols
    return root, explicit_cols


FIELDS: List[FieldSpec] = [
    FieldSpec(
        key="taxii_root", label="TAXII 2.1 API Root", type="url",
        required=True,
        default="https://opencti.example.com/taxii2/root/",
        help="Full TAXII 2.1 API root URL, e.g. "
             "https://opencti.example.com/taxii2/root/. "
             "If you paste a per-collection URL of the form "
             "/collections/<uuid>/objects/ (OpenCTI's Data sharing "
             "default) the connector strips it and pins to that "
             "collection automatically.",
    ),
    FieldSpec(
        key="token", label="OpenCTI API Token",
        type="password", required=True, secret=True,
        help="Bearer token of an OpenCTI user with read access to the "
             "exposed TAXII collections.",
    ),
    FieldSpec(
        key="collections", label="Collection IDs (comma-separated)",
        type="text", default="",
        help="Leave blank to auto-discover every collection on the "
             "API root. Provide explicit IDs to pin the connector to "
             "a subset.",
    ),
    FieldSpec(
        key="page_size", label="Page Size",
        type="number", default=1000,
        help="STIX objects per TAXII page (server may cap lower).",
    ),
    FieldSpec(
        key="verify_tls", label="Verify TLS",
        type="bool", default=True,
        help="Disable only for lab instances with self-signed certs.",
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
        help="One-shot ``added_after`` seed used when this connector "
             "has no cursor yet (e.g. 2024-01-01T00:00:00Z). Leave "
             "blank to start at the server default (typically 'now'). "
             "Ignored once a cursor is persisted in cti_taxii_cursors.",
    ),
]


def _profile_from_config(cfg: Dict[str, Any]) -> TaxiiVendorProfile:
    raw_cols = (cfg.get("collections") or "").strip()
    explicit_cols = [c.strip() for c in raw_cols.split(",") if c.strip()]
    api_root, cols = _normalise_root(cfg.get("taxii_root") or "", explicit_cols)
    return TaxiiVendorProfile(
        name="opencti_taxii",
        api_root=api_root,
        collections=cols,
        auth_mode="bearer",
        auth_token=(cfg.get("token") or "").strip() or None,
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
    if not cfg.get("taxii_root") or not cfg.get("token"):
        return SyncResult(
            errors=[f"OpenCTI TAXII connector {label!r}: "
                    "missing taxii_root or token"],
        )
    return run_taxii_sync(connector, linked_clients,
                          _profile_from_config(cfg))


def test_connection(connector: Dict[str, Any]) -> Dict[str, Any]:
    """Used by the Management → Connectors Test button."""
    cfg = connector.get("config") or {}
    return test_taxii_connection(_profile_from_config(cfg))


VENDOR = ConnectorVendor(
    name="opencti_taxii",
    label="OpenCTI (TAXII 2.1)",
    icon="opencti",
    kind_default="cti",
    fields=FIELDS,
    fetcher=sync,
    tester=test_connection,
)
