"""GreyNoise TAXII 2.1 connector.

GreyNoise emits STIX bundles whose primary SCO is ``ipv4-addr``, and
attaches their proprietary tag taxonomy (e.g. ``mirai``, ``tor``,
``scanner``) via custom ``x_greynoise_*`` properties. We map that
custom taxonomy onto a standard STIX surface so downstream UI / RBAC
that filters on ``labels`` keeps working:

* ``x_greynoise_tags`` (list)  \u2192 appended to the object's STIX
  ``labels`` list with a ``greynoise:`` prefix so they're traceable.
* ``classification``           \u2192 appended as ``greynoise:<value>``.

The raw ``x_greynoise_*`` properties are left intact so anyone
querying ``raw_stix`` later can recover the original payload.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ._base import ConnectorVendor, FieldSpec, SyncResult
from app.services.cti_fetchers.taxii21 import (
    TaxiiVendorProfile, run_taxii_sync, test_taxii_connection,
)


FIELDS: List[FieldSpec] = [
    FieldSpec(
        key="taxii_root", label="TAXII 2.1 API Root", type="url",
        required=True,
        default="https://api.greynoise.io/v3/taxii2/",
        help="GreyNoise TAXII 2.1 API root.",
    ),
    FieldSpec(
        key="api_key", label="API Key",
        type="password", required=True, secret=True,
        help="GreyNoise API key. Sent in the ``key`` header.",
    ),
    FieldSpec(
        key="collections", label="Collection IDs (comma-separated)",
        type="text", default="",
        help="Leave blank to auto-discover (typically ``noise``, "
             "``riot``).",
    ),
    FieldSpec(
        key="page_size", label="Page Size",
        type="number", default=1000,
    ),
    FieldSpec(
        key="verify_tls", label="Verify TLS",
        type="bool", default=True,
    ),
    FieldSpec(
        key="max_objects_per_collection",
        label="Max objects per collection per run",
        type="number", default=0,
    ),
    FieldSpec(
        key="from_date", label="Start From (ISO 8601 UTC)",
        type="text", default="",
        help="One-shot ``added_after`` seed used when no cursor exists "
             "yet (e.g. 2024-01-01T00:00:00Z). Ignored once a cursor "
             "is persisted in cti_taxii_cursors.",
    ),
]


def _greynoise_transform(obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Map ``x_greynoise_*`` custom properties onto STIX ``labels``.

    Only touches objects that carry GreyNoise-specific properties so
    standard STIX SDOs (marking-definition, identity, \u2026) pass through
    untouched. The original ``x_greynoise_*`` keys are preserved on
    the dict so the raw STIX captured by ``cti_ingest`` keeps full
    vendor fidelity.
    """
    if not isinstance(obj, dict):
        return obj
    tags = obj.get("x_greynoise_tags")
    classification = obj.get("x_greynoise_classification") or obj.get(
        "classification"
    )
    if not tags and not classification:
        return obj

    labels = list(obj.get("labels") or [])
    if isinstance(tags, list):
        for t in tags:
            if not t:
                continue
            tag = f"greynoise:{str(t).strip().lower()}"
            if tag not in labels:
                labels.append(tag)
    if classification:
        tag = f"greynoise:{str(classification).strip().lower()}"
        if tag not in labels:
            labels.append(tag)
    if labels:
        obj["labels"] = labels
    return obj


def _profile_from_config(cfg: Dict[str, Any]) -> TaxiiVendorProfile:
    raw_cols = (cfg.get("collections") or "").strip()
    cols = [c.strip() for c in raw_cols.split(",") if c.strip()]
    return TaxiiVendorProfile(
        name="greynoise",
        api_root=(cfg.get("taxii_root") or "").strip(),
        collections=cols,
        auth_mode="apikey_header",
        auth_token=(cfg.get("api_key") or "").strip() or None,
        auth_header_name="key",
        page_size=int(cfg.get("page_size") or 1000),
        verify_tls=bool(cfg.get("verify_tls", True)),
        max_objects_per_collection=int(
            cfg.get("max_objects_per_collection") or 0
        ),
        initial_added_after=(cfg.get("from_date") or "").strip() or None,
        use_cursor=True,
        transform_object=_greynoise_transform,
    )


def sync(connector: Dict[str, Any],
         linked_clients: List[Dict[str, Any]]) -> SyncResult:
    cfg = connector.get("config") or {}
    label = connector.get("label") or connector.get("id", "?")
    if not cfg.get("taxii_root") or not cfg.get("api_key"):
        return SyncResult(
            errors=[f"GreyNoise connector {label!r}: missing taxii_root "
                    "or api_key"],
        )
    return run_taxii_sync(connector, linked_clients,
                          _profile_from_config(cfg))


def test_connection(connector: Dict[str, Any]) -> Dict[str, Any]:
    cfg = connector.get("config") or {}
    return test_taxii_connection(_profile_from_config(cfg))


VENDOR = ConnectorVendor(
    name="greynoise",
    label="GreyNoise (TAXII 2.1)",
    icon="greynoise",
    kind_default="cti",
    fields=FIELDS,
    fetcher=sync,
    tester=test_connection,
)
