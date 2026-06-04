"""Generic TAXII 2.1 client (step T1 of the CTI refactor).

One engine for every TAXII 2.1 feed (OpenCTI, Mandiant, CrowdStrike,
MITRE ATT&CK, GreyNoise, …). Vendor modules under
``app.services.cti_connectors`` declare a :class:`TaxiiVendorProfile`
and call :func:`run_taxii_sync`; this module owns the HTTP plumbing,
pagination, cursor handling, and bundle assembly. Writes are delegated
to :func:`app.services.cti_ingest.ingest_stix_bundle` so every TAXII
source goes through the same dedup + provenance code path as the
legacy OpenCTI GraphQL fetcher.

Hard rules enforced here (see ``PLAN_CTI.md`` + ``AGENTS.md``):

* Synchronous façade — ``run_taxii_sync`` is a plain function so it
  fits the :class:`ConnectorFetcher` protocol used by the existing
  HTMX endpoints. The async fan-out across collections lives behind
  ``asyncio.run`` and never escapes this module.
* No Pydantic / stix2-validator. STIX objects are dicts and pass
  through ``cti_ingest`` unchanged so vendor ``x_*`` custom properties
  (Mandiant / CrowdStrike) do not trip strict validation.
* Cursor I/O is behind a small ABC (:class:`CursorStore`). T1 ships
  the in-memory implementation only; T2 will plug the DuckDB-backed
  store into the registry without touching this file.
* No background ticker — every call is operator-triggered.
"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

import httpx

# NOTE: ``SyncResult`` is imported lazily inside ``run_taxii_sync`` to
# avoid a circular import. ``cti_connectors/__init__.py`` imports the
# vendor modules (which import this module), so a top-level import of
# ``cti_connectors._base`` here would trigger the package init and
# deadlock with ``TaxiiVendorProfile`` not yet defined.

logger = logging.getLogger(__name__)


# ── Public dataclasses ──────────────────────────────────────────────


AuthMode = str  # one of: "bearer", "basic", "apikey_header", "none"


@dataclass(frozen=True)
class TaxiiVendorProfile:
    """How one vendor talks TAXII 2.1.

    Vendor modules build this from the connector ``config`` row.
    """

    name: str                       # e.g. "opencti_taxii"
    api_root: str                   # https://host/taxii2/<root>/
    collections: List[str]          # collection ids to poll; [] = all
    auth_mode: AuthMode = "bearer"
    auth_token: Optional[str] = None
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    auth_header_name: Optional[str] = None   # for "apikey_header"
    page_size: int = 1000
    verify_tls: bool = True
    request_timeout: float = 60.0
    # If False, the engine ignores any stored cursor and always pulls
    # the full collection (used by MITRE ATT&CK).
    use_cursor: bool = True
    # Hard cap on objects per (collection, run); 0 = no cap.
    max_objects_per_collection: int = 0
    # One-shot ``added_after`` seed used when no cursor exists yet for
    # a (connector_id, api_root, collection_id) tuple. Operator-set
    # via the per-vendor "Start From" field so a fresh connector can
    # backfill history instead of starting at "now". Ignored once a
    # cursor lands in ``cti_taxii_cursors``.
    initial_added_after: Optional[str] = None
    # Optional per-object post-processor (vendor mapping hook). Runs
    # on every STIX object before the bundle is handed to
    # ``cti_ingest``. Must return the object (modified or not) or
    # ``None`` to drop it.
    transform_object: Optional[Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]] = None


@dataclass
class CollectionResult:
    collection_id: str
    objects: List[Dict[str, Any]] = field(default_factory=list)
    next_cursor: Optional[str] = None       # X-TAXII-Date-Added-Last
    error: Optional[str] = None
    pages: int = 0
    elapsed_s: float = 0.0


# ── Cursor store ABC ────────────────────────────────────────────────


class CursorStore(ABC):
    """Persistence boundary for the ``added_after`` watermark.

    T2 implements a DuckDB-backed subclass that writes to
    ``cti_taxii_cursors`` in the shared ``tide.duckdb``.
    """

    @abstractmethod
    def get(self, connector_id: str, api_root: str,
            collection_id: str) -> Optional[str]: ...

    @abstractmethod
    def set(self, connector_id: str, api_root: str,
            collection_id: str, cursor: str) -> None: ...


class InMemoryCursorStore(CursorStore):
    """Default cursor store. Cleared on process restart."""

    def __init__(self) -> None:
        self._d: Dict[Tuple[str, str, str], str] = {}

    def get(self, connector_id: str, api_root: str,
            collection_id: str) -> Optional[str]:
        return self._d.get((connector_id, api_root, collection_id))

    def set(self, connector_id: str, api_root: str,
            collection_id: str, cursor: str) -> None:
        self._d[(connector_id, api_root, collection_id)] = cursor


_DEFAULT_CURSOR_STORE: CursorStore = InMemoryCursorStore()


def set_default_cursor_store(store: CursorStore) -> None:
    """Replace the process-wide cursor store (called by T2 wiring)."""
    global _DEFAULT_CURSOR_STORE
    _DEFAULT_CURSOR_STORE = store


def get_default_cursor_store() -> CursorStore:
    return _DEFAULT_CURSOR_STORE


class DuckDBCursorStore(CursorStore):
    """Persistent cursor store backed by ``cti_taxii_cursors`` (mig. 49).

    Lazy ``DatabaseService`` import so test code and tools that drive
    the TAXII engine without the full app can stick to the in-memory
    default.
    """

    def get(self, connector_id: str, api_root: str,
            collection_id: str) -> Optional[str]:
        from app.services.database import get_database_service
        try:
            return get_database_service().get_taxii_cursor(
                connector_id, api_root, collection_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("DuckDBCursorStore.get failed: %s", exc)
            return None

    def set(self, connector_id: str, api_root: str,
            collection_id: str, cursor: str) -> None:
        from app.services.database import get_database_service
        try:
            get_database_service().set_taxii_cursor(
                connector_id, api_root, collection_id, cursor,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("DuckDBCursorStore.set failed: %s", exc)


# ── HTTP helpers ────────────────────────────────────────────────────


_TAXII_ACCEPT = "application/taxii+json;version=2.1"
_STIX_ACCEPT = "application/stix+json;version=2.1, application/taxii+json;version=2.1"


def _auth_headers(profile: TaxiiVendorProfile) -> Dict[str, str]:
    h: Dict[str, str] = {}
    if profile.auth_mode == "bearer" and profile.auth_token:
        h["Authorization"] = f"Bearer {profile.auth_token}"
    elif profile.auth_mode == "apikey_header" and profile.auth_token:
        name = profile.auth_header_name or "X-Api-Key"
        h[name] = profile.auth_token
    # "basic" handled by httpx auth=
    return h


def _basic_auth(profile: TaxiiVendorProfile) -> Optional[Tuple[str, str]]:
    if profile.auth_mode == "basic":
        return (profile.auth_username or "", profile.auth_password or "")
    return None


async def _resolve_api_root(client: httpx.AsyncClient,
                            profile: TaxiiVendorProfile) -> str:
    """Return the working TAXII 2.1 API root.

    Some vendors (notably CrowdStrike Falcon Intel) publish the
    *discovery* URL — e.g. ``/intel/taxii2/`` — but the actual API
    root is announced by the ``api_roots`` field of that discovery
    response (typically ``/intel/taxii2/<root>/``). Operators commonly
    paste the discovery URL into the connector form, so we transparently
    follow the announced root before any collection-level call.
    """
    root = profile.api_root.rstrip("/") + "/"
    headers = {"Accept": _TAXII_ACCEPT, **_auth_headers(profile)}
    auth = _basic_auth(profile)
    try:
        resp = await client.get(
            root, headers=headers, auth=auth,
            timeout=profile.request_timeout,
        )
        if 200 <= resp.status_code < 300:
            try:
                payload = resp.json() or {}
            except Exception:
                payload = {}
            api_roots = (
                payload.get("api_roots")
                if isinstance(payload, dict) else None
            )
            if isinstance(api_roots, list) and api_roots:
                announced = (api_roots[0] or "").strip()
                if announced:
                    if not announced.endswith("/"):
                        announced += "/"
                    if announced != root:
                        logger.info(
                            "TAXII %s: following discovery api_roots[0]=%s "
                            "(configured root was %s)",
                            profile.name, announced, root,
                        )
                    return announced
    except httpx.HTTPError:
        # Non-fatal: vendors that expose /collections/ directly will
        # also reject /, so fall through and use the configured root.
        pass
    return root


async def _discover_collections(client: httpx.AsyncClient,
                                profile: TaxiiVendorProfile) -> List[str]:
    """Return the explicit list (if configured) or hit /collections/."""
    if profile.collections:
        return list(profile.collections)
    url = profile.api_root.rstrip("/") + "/collections/"
    resp = await client.get(
        url,
        headers={"Accept": _TAXII_ACCEPT, **_auth_headers(profile)},
        auth=_basic_auth(profile),
        timeout=profile.request_timeout,
    )
    resp.raise_for_status()
    payload = resp.json() or {}
    return [c["id"] for c in payload.get("collections", []) if c.get("id")]


async def _poll_collection(client: httpx.AsyncClient,
                           profile: TaxiiVendorProfile,
                           collection_id: str,
                           added_after: Optional[str]) -> CollectionResult:
    """Page through one TAXII 2.1 collection.

    Honours ``X-TAXII-Date-Added-Last`` as the cursor watermark, and
    walks the ``next`` query parameter for in-collection pagination.
    """
    started = time.monotonic()
    out = CollectionResult(collection_id=collection_id)
    base = f"{profile.api_root.rstrip('/')}/collections/{collection_id}/objects/"
    next_token: Optional[str] = None
    latest_added: Optional[str] = added_after

    headers = {"Accept": _STIX_ACCEPT, **_auth_headers(profile)}
    auth = _basic_auth(profile)

    while True:
        params: Dict[str, Any] = {"limit": profile.page_size}
        if added_after:
            params["added_after"] = added_after
        if next_token:
            params["next"] = next_token

        try:
            resp = await client.get(
                base, params=params, headers=headers, auth=auth,
                timeout=profile.request_timeout,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            out.error = f"GET {base}: {exc}"
            logger.error("TAXII poll failed for %s: %s", collection_id, exc)
            break

        # X-TAXII-Date-Added-Last → next cursor. Header name is
        # case-insensitive in httpx; the spec uses the dashed form.
        header_added = (
            resp.headers.get("X-TAXII-Date-Added-Last")
            or resp.headers.get("x-taxii-date-added-last")
        )
        if header_added:
            latest_added = header_added

        body = resp.json() or {}
        objs = body.get("objects") or []
        if profile.transform_object:
            shaped: List[Dict[str, Any]] = []
            for o in objs:
                try:
                    r = profile.transform_object(o)
                except Exception as exc:  # noqa: BLE001 - vendor hook safety
                    logger.warning(
                        "transform_object raised on %s: %s",
                        o.get("id"), exc,
                    )
                    continue
                if r is not None:
                    shaped.append(r)
            objs = shaped

        out.objects.extend(objs)
        out.pages += 1
        # Per-page INFO so the operator can watch a long backfill tick
        # by in the container logs (`docker compose logs -f tide-app`).
        # OpenCTI tenants with millions of objects regularly take
        # minutes per collection; without this the only signal was
        # the per-collection summary line emitted at the end of the
        # whole pull, which makes "is it still working?" impossible to
        # answer from outside the process.
        logger.info(
            "TAXII page profile=%s collection=%s page=%d "
            "size=%d running_total=%d cursor=%s",
            profile.name, collection_id, out.pages, len(objs),
            len(out.objects), latest_added or "(none)",
        )

        if (profile.max_objects_per_collection
                and len(out.objects) >= profile.max_objects_per_collection):
            out.objects = out.objects[:profile.max_objects_per_collection]
            break

        more = bool(body.get("more"))
        next_token = body.get("next") if more else None
        if not next_token:
            break

    out.elapsed_s = round(time.monotonic() - started, 3)
    out.next_cursor = latest_added
    return out


async def _run_async(profile: TaxiiVendorProfile,
                     connector_id: str,
                     cursor_store: CursorStore) -> List[CollectionResult]:
    limits = httpx.Limits(max_connections=10, max_keepalive_connections=10)
    async with httpx.AsyncClient(verify=profile.verify_tls,
                                 limits=limits) as client:
        try:
            resolved_root = await _resolve_api_root(client, profile)
            if (resolved_root and
                    resolved_root.rstrip("/") != profile.api_root.rstrip("/")):
                profile = replace(profile, api_root=resolved_root)
        except Exception as exc:  # noqa: BLE001
            logger.debug("TAXII api_root resolution skipped: %s", exc)
        try:
            collections = await _discover_collections(client, profile)
        except httpx.HTTPError as exc:
            logger.error("TAXII collection discovery failed for %s: %s",
                         profile.api_root, exc)
            return [CollectionResult(collection_id="<discovery>",
                                     error=f"discovery: {exc}")]

        async def _one(cid: str) -> CollectionResult:
            cursor = (cursor_store.get(connector_id, profile.api_root, cid)
                      if profile.use_cursor else None)
            if not cursor and profile.initial_added_after:
                cursor = profile.initial_added_after
                logger.info(
                    "TAXII %s collection=%s seeding cursor from "
                    "profile.initial_added_after=%s",
                    profile.name, cid, cursor,
                )
            res = await _poll_collection(client, profile, cid, cursor)
            if profile.use_cursor and res.next_cursor and not res.error:
                try:
                    cursor_store.set(connector_id, profile.api_root,
                                     cid, res.next_cursor)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "cursor_store.set failed for %s/%s: %s",
                        connector_id, cid, exc,
                    )
            return res

        return await asyncio.gather(*(_one(c) for c in collections))


# ── Public entry point ──────────────────────────────────────────────


def run_taxii_sync(
    connector: Dict[str, Any],
    linked_clients: List[Dict[str, Any]],
    profile: TaxiiVendorProfile,
    *,
    cursor_store: Optional[CursorStore] = None,
) -> SyncResult:
    """Poll every collection on ``profile`` and ingest into each tenant.

    One TAXII pull, ingest fan-out per tenant — matching the OpenCTI
    GraphQL connector's contract. Errors are accumulated, not raised,
    so a single collection failure does not abort the whole run.
    """
    from app.services.cti_connectors._base import SyncResult  # local import; see top-of-file note
    from app.services import cti_ingest
    from app.services.tenant_manager import tenant_context_for

    label = connector.get("label") or connector.get("id", "?")
    connector_id = str(connector.get("id") or "")
    store = cursor_store or _DEFAULT_CURSOR_STORE

    if not linked_clients:
        return SyncResult(
            errors=[f"TAXII connector {label!r}: no clients linked"],
        )

    try:
        results = asyncio.run(_run_async(profile, connector_id, store))
    except RuntimeError as exc:
        # Defensive: covers the rare case where the caller is already
        # inside an event loop (shouldn't happen — connectors are
        # invoked via a thread executor from FastAPI — but raising
        # here would crash the sync button). Fall back to a fresh loop.
        if "asyncio.run() cannot be called" in str(exc):
            loop = asyncio.new_event_loop()
            try:
                results = loop.run_until_complete(
                    _run_async(profile, connector_id, store)
                )
            finally:
                loop.close()
        else:
            raise

    errors: List[str] = []
    all_objects: List[Dict[str, Any]] = []
    # Per-STIX-type tally across every polled collection. Operators
    # commonly compare the connector's reported "indicators ingested"
    # count against the upstream vendor's dashboard total ("OpenCTI
    # says 2.58M indicators, why did TIDE only get 1363?"); the gap
    # is almost always because the upstream TAXII export filters by
    # TLP / collection / connector permissions, or because most
    # objects in the bundle are non-indicator SDOs (relationships,
    # malware, reports, attack-patterns). Logging the per-type tally
    # here lets the operator see at a glance which of those caused
    # the gap without trawling DEBUG logs.
    type_tally: Dict[str, int] = {}
    for r in results:
        if r.error:
            errors.append(f"{label}/{r.collection_id}: {r.error}")
        all_objects.extend(r.objects)
        per_type: Dict[str, int] = {}
        for o in r.objects:
            t = (o.get("type") or "unknown")
            per_type[t] = per_type.get(t, 0) + 1
            type_tally[t] = type_tally.get(t, 0) + 1
        logger.info(
            "TAXII %s collection=%s pages=%d objects=%d "
            "indicators=%d relationships=%d attack-patterns=%d "
            "intrusion-sets=%d threat-actors=%d reports=%d "
            "elapsed=%.3fs",
            label, r.collection_id, r.pages, len(r.objects),
            per_type.get("indicator", 0),
            per_type.get("relationship", 0),
            per_type.get("attack-pattern", 0),
            per_type.get("intrusion-set", 0),
            per_type.get("threat-actor", 0),
            per_type.get("report", 0),
            r.elapsed_s,
        )
    if type_tally:
        logger.info(
            "TAXII %s total objects=%d by-type=%s",
            label, sum(type_tally.values()),
            ", ".join(
                f"{k}={v}" for k, v
                in sorted(type_tally.items(), key=lambda kv: -kv[1])
            ),
        )

    if not all_objects:
        return SyncResult(
            tenants=0,
            errors=errors,
            upstream_types=type_tally,
            per_tenant=[{"collections": [
                {"id": r.collection_id, "objects": len(r.objects),
                 "pages": r.pages, "error": r.error}
                for r in results
            ]}],
        )

    bundle = {"type": "bundle", "id": f"bundle--taxii-{connector_id}",
              "objects": all_objects}
    source_id = f"connector:{connector_id}"

    totals: Dict[str, int] = {
        k: 0 for k in (
            "indicators_new", "indicators_merged", "indicators_review",
            "actors", "reports", "intrusion_sets",
            "relationships", "skipped",
        )
    }
    per_tenant: List[Dict[str, Any]] = []

    for client in linked_clients:
        cid = client.get("id")
        try:
            with tenant_context_for(cid):
                counters = cti_ingest.ingest_stix_bundle(
                    cid, bundle, source_id=source_id, bundle_id=bundle["id"],
                )
        except Exception as exc:  # noqa: BLE001
            msg = (f"TAXII ingest failed for "
                   f"{client.get('name', cid)} via {label!r}: {exc}")
            logger.error(msg, exc_info=True)
            errors.append(msg)
            continue
        for k in totals:
            totals[k] += int(counters.get(k, 0) or 0)
        per_tenant.append({
            "client_id": cid,
            "client_name": client.get("name"),
            **counters,
        })

    return SyncResult(
        tenants=len(per_tenant),
        errors=errors,
        per_tenant=per_tenant,
        upstream_types=type_tally,
        **totals,
    )


# ── Convenience for "Test connection" buttons ──────────────────────


def test_taxii_connection(profile: TaxiiVendorProfile) -> Dict[str, Any]:
    """Probe the TAXII root and return a summary dict.

    Always performs at least one upstream HTTP call so the tester
    surfaces real auth / network failures rather than echoing the
    pre-pinned collection list back to the operator.

    Strategy:
    * Always GET ``<api_root>/collections/`` first when reachable to
      validate the root + credentials. Some servers (notably some
      OpenCTI deployments) deny that endpoint to per-collection
      tokens, so a 401/403 there falls through to a per-collection
      probe when ``profile.collections`` is pinned.
    * If pinned collections are provided, GET
      ``<api_root>/collections/<id>/`` for the first one as a final
      validation step.
    """
    async def _probe_root(client: httpx.AsyncClient) -> Tuple[bool, List[str], Optional[str]]:
        url = profile.api_root.rstrip("/") + "/collections/"
        try:
            resp = await client.get(
                url,
                headers={"Accept": _TAXII_ACCEPT, **_auth_headers(profile)},
                auth=_basic_auth(profile),
                timeout=profile.request_timeout,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            return False, [], f"GET {url}: {exc}"
        payload = resp.json() or {}
        ids = [c["id"] for c in payload.get("collections", []) if c.get("id")]
        return True, ids, None

    async def _probe_collection(client: httpx.AsyncClient, cid: str) -> Tuple[bool, Optional[str], Optional[dict]]:
        url = profile.api_root.rstrip("/") + f"/collections/{cid}/"
        try:
            resp = await client.get(
                url,
                headers={"Accept": _TAXII_ACCEPT, **_auth_headers(profile)},
                auth=_basic_auth(profile),
                timeout=profile.request_timeout,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            return False, f"GET {url}: {exc}", None
        try:
            meta = resp.json() or {}
        except Exception:
            meta = {}
        return True, None, meta

    async def _probe_objects(client: httpx.AsyncClient, cid: str) -> Tuple[bool, Optional[str], Optional[int]]:
        """Hit the ``objects/`` endpoint with limit=1 to confirm read
        access. Returns the upstream HTTP status (or None on transport
        failure) so the operator can tell ``403 Forbidden`` apart from
        a DNS/TLS error.
        """
        url = profile.api_root.rstrip("/") + f"/collections/{cid}/objects/?limit=1"
        try:
            resp = await client.get(
                url,
                headers={"Accept": _TAXII_ACCEPT, **_auth_headers(profile)},
                auth=_basic_auth(profile),
                timeout=profile.request_timeout,
            )
        except httpx.HTTPError as exc:
            return False, f"GET {url}: {exc}", None
        if 200 <= resp.status_code < 300:
            return True, None, resp.status_code
        body = ""
        try:
            body = (resp.text or "")[:200]
        except Exception:
            pass
        return False, (
            f"GET {url} returned HTTP {resp.status_code}"
            + (f" — {body}" if body else "")
        ), resp.status_code

    async def _go() -> Dict[str, Any]:
        nonlocal profile
        async with httpx.AsyncClient(verify=profile.verify_tls) as client:
            try:
                resolved_root = await _resolve_api_root(client, profile)
                if (resolved_root and
                        resolved_root.rstrip("/") != profile.api_root.rstrip("/")):
                    profile = replace(profile, api_root=resolved_root)
            except Exception:
                pass
            root_ok, discovered, root_err = await _probe_root(client)
            # Build the list of collection ids we are going to probe.
            # Pinned wins; otherwise fall back to whatever discovery
            # returned. If neither is available, surface the root error.
            cids = list(profile.collections) if profile.collections else list(discovered)
            if not cids:
                if root_ok:
                    return {
                        "ok": False,
                        "error": (
                            "TAXII root reachable but exposes no "
                            "collections. Pin a collection ID on the "
                            "connector or grant the token access to at "
                            "least one collection."
                        ),
                        "collections": [],
                    }
                return {"ok": False, "error": root_err, "collections": []}

            readable: list[str] = []
            unreadable: list[str] = []
            errors: list[str] = []
            for cid in cids:
                col_ok, col_err, meta = await _probe_collection(client, cid)
                if not col_ok:
                    errors.append(f"{cid}: {col_err}")
                    continue
                # Collections list ``can_read`` per the TAXII 2.1 spec
                # (§5.2). When it is explicitly ``false`` the server is
                # telling us this is a write-only collection (a push
                # destination), so don't bother hitting objects/.
                can_read = meta.get("can_read", True) if meta else True
                if can_read is False:
                    title = (meta or {}).get("title") or cid
                    unreadable.append(
                        f"{cid} ({title}): can_read=false — "
                        f"this is a write-only collection (push target), "
                        f"not a source TIDE can pull from"
                    )
                    continue
                # Final proof: actually ask for an object. This catches
                # OpenCTI-style policies where can_read is true but the
                # user lacks the per-collection read role.
                obj_ok, obj_err, _status = await _probe_objects(client, cid)
                if obj_ok:
                    readable.append(cid)
                else:
                    unreadable.append(f"{cid}: {obj_err}")

            if readable:
                return {
                    "ok": True,
                    "collections": readable,
                    "unreadable": unreadable,
                    "root_probe": "ok" if root_ok else f"skipped ({root_err})",
                }
            return {
                "ok": False,
                "error": (
                    "No TAXII collection is readable with the supplied "
                    "credentials. "
                    + ("; ".join(unreadable + errors))[:400]
                ),
                "collections": [],
                "unreadable": unreadable,
                "root_probe": "ok" if root_ok else root_err,
            }

    try:
        return asyncio.run(_go())
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "collections": []}
