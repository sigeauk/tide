"""Centralised Kibana space resolution for TIDE (4.1.7 Phase B).

Both the Elastic sync orchestrator (``app.services.sync.run_elastic_sync``)
and the Management API (``app.api.management._list_kibana_spaces``) need to
answer the same question — *what spaces does this SIEM legitimately have?* —
but were doing it through different code paths with subtly different
fallbacks. The result was a class of bug where a freshly-added standalone
SIEM showed 10+ spaces in Test Connection but an empty dropdown on the
link-to-tenant form, because nothing in the sync path was populating the
persistent ``siem_kibana_spaces`` cache (Migration 41) that the dropdown
falls back to.

This module is the single source of truth for the resolution ladder:

    1. ``client_siem_map`` (operator-declared, authoritative for sync attribution)
    2. ``siem_kibana_spaces`` persistent cache (last successful Test Connection)
    3. Live ``GET /api/spaces/space`` against Kibana (and persist on success)

Side-effect free except for ``save_siem_spaces`` on a successful live call,
which is the whole point — the next caller (UI dropdown, sync, diagnostics)
gets to see what we just discovered without a dedicated refresh click.
"""

from __future__ import annotations

import logging
from typing import Optional, Tuple, Set

import requests as _requests
import urllib3 as _urllib3

_urllib3.disable_warnings(_urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


# Reason codes returned alongside the resolved spaces. Stable strings so log
# greps and the diag_sync verdict block can branch on them without parsing
# free-form English.
REASON_CLIENT_MAP = "client_map"           # spaces came from client_siem_map
REASON_PERSISTED = "persisted_cache"       # spaces came from siem_kibana_spaces
REASON_LIVE = "live_discovery"             # spaces fetched live from Kibana
REASON_NO_CREDS = "no_credentials"         # SIEM record missing url or token
REASON_LIVE_FAILED = "live_failed"         # Kibana returned non-200 / network error
REASON_NO_SPACES = "no_spaces_found"       # Kibana returned an empty space list


def _live_lookup(kibana_url: str, api_token: str,
                 timeout: float = 10.0) -> Optional[Set[str]]:
    """Issue a single ``GET /api/spaces/space`` and return the set of space
    ids, or ``None`` if Kibana refused / was unreachable. Caller decides
    whether to fall back further.
    """
    url = (kibana_url or "").rstrip("/")
    if not url or not api_token:
        return None
    try:
        r = _requests.get(
            f"{url}/api/spaces/space",
            headers={
                "kbn-xsrf": "true",
                "Authorization": f"ApiKey {api_token}",
                "Content-Type": "application/json",
            },
            verify=False,
            timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001 — network/SSL/anything
        logger.warning(
            "space_resolver: live lookup raised %s: %s", type(exc).__name__, exc
        )
        return None
    if r.status_code != 200:
        logger.warning(
            "space_resolver: GET /api/spaces/space returned HTTP %s (body=%r)",
            r.status_code, r.text[:200],
        )
        return None
    try:
        data = r.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning("space_resolver: response was not JSON: %s", exc)
        return None
    return {
        s.get("id") for s in data
        if isinstance(s, dict) and s.get("id")
    }


def resolve_spaces(
    db,
    siem_id: str,
    *,
    kibana_url: Optional[str] = None,
    api_token: Optional[str] = None,
    allow_live: bool = True,
) -> Tuple[Set[str], str]:
    """Resolve the set of Kibana spaces for a SIEM via the legacy ladder.

    Backward-compat wrapper retained for existing call sites that still need
    the old semantics (client mapping first, then discoverable spaces).

    On a successful live discovery, the result is persisted via
    ``db.save_siem_spaces`` so the next reader (UI dropdown, sync, diag_sync)
    sees the discovery without a separate refresh.
    """
    # ── 1. client_siem_map (operator-declared) ─────────────────────────────
    try:
        mapped = set(db.get_siem_spaces(siem_id) or [])
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "space_resolver(%s): get_siem_spaces failed: %r", siem_id, exc
        )
        mapped = set()
    if mapped:
        return mapped, REASON_CLIENT_MAP

    return resolve_discoverable_spaces(
        db,
        siem_id,
        kibana_url=kibana_url,
        api_token=api_token,
        allow_live=allow_live,
    )


def resolve_discoverable_spaces(
    db,
    siem_id: str,
    *,
    kibana_url: Optional[str] = None,
    api_token: Optional[str] = None,
    allow_live: bool = True,
) -> Tuple[Set[str], str]:
    """Resolve spaces this SIEM can actually serve (cache/live), excluding
    client_siem_map.

    Use this for operator validation ("does this space exist on the SIEM?")
    and picker population. It intentionally does *not* treat current
    client mappings as authoritative capability discovery, because mappings
    are usually incomplete while onboarding new tenants.
    """

    # ── 1. siem_kibana_spaces persistent cache (Migration 41) ──────────────
    try:
        persisted = set(db.get_siem_spaces_cached(siem_id) or [])
    except Exception as exc:  # noqa: BLE001
        logger.debug(
            "space_resolver(%s): get_siem_spaces_cached failed: %r",
            siem_id, exc,
        )
        persisted = set()

    # ── 2. Live Kibana discovery (and persist) ─────────────────────────────
    if allow_live:
        # Pull credentials from the SIEM record if the caller didn't provide
        # them. Sync supplies these directly to avoid a second DB hit.
        if kibana_url is None or api_token is None:
            try:
                row = db.get_siem_inventory_item(siem_id) or {}
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "space_resolver(%s): inventory lookup failed: %r",
                    siem_id, exc,
                )
                row = {}
            kibana_url = kibana_url or row.get("kibana_url")
            api_token = api_token or row.get("api_token_enc")

        if not kibana_url or not api_token:
            if persisted:
                return persisted, REASON_PERSISTED
            return set(), REASON_NO_CREDS

        live = _live_lookup(kibana_url, api_token)
        if live is None:
            # Live failed — return persisted if we have it, otherwise an
            # explicit failure reason.
            if persisted:
                return persisted, REASON_PERSISTED
            return set(), REASON_LIVE_FAILED
        if not live:
            return set(), REASON_NO_SPACES

        # Best-effort persist so the next caller benefits.
        try:
            db.save_siem_spaces(siem_id, sorted(live))
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "space_resolver(%s): save_siem_spaces failed: %r",
                siem_id, exc,
            )
        return live, REASON_LIVE

    if persisted:
        return persisted, REASON_PERSISTED
    return set(), REASON_NO_CREDS


def resolve_mapped_spaces(db, siem_id: str) -> Tuple[Set[str], str]:
    """Return spaces declared in client_siem_map for this SIEM.

    This is for attribution logic where operator mapping is the source of
    truth; do not use it for capability validation.
    """
    try:
        mapped = set(db.get_siem_spaces(siem_id) or [])
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "space_resolver(%s): get_siem_spaces failed: %r", siem_id, exc
        )
        mapped = set()
    if mapped:
        return mapped, REASON_CLIENT_MAP
    return set(), REASON_NO_SPACES
