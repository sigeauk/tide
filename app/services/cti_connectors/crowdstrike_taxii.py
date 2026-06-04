"""CrowdStrike Falcon Intelligence connector.

CrowdStrike does **not** publish a public TAXII 2.1 server on
``api.crowdstrike.com`` — Falcon Intel is exposed exclusively over
the OAuth2 REST API (``/intel/queries/...`` + ``/intel/combined/...``).
This module:

* exchanges the operator-supplied client_id/client_secret for a Falcon
  bearer token (OAuth2 client-credentials),
* pulls indicators, actors and reports via the REST API,
* normalises each payload into STIX 2.1 SDOs so the shared
  :func:`app.services.cti_ingest.ingest_stix_bundle` pipeline can write
  them into every linked tenant's CTI database,
* exposes :func:`download_report_pdf` for the report viewer so attached
  PDFs render inline via ``/intel/entities/report-files/v1``.

The module name is kept as ``crowdstrike_taxii`` for backwards
compatibility with existing ``cti_connectors`` rows.
"""

from __future__ import annotations

import logging
import time
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ._base import ConnectorVendor, FieldSpec, SyncResult

logger = logging.getLogger(__name__)


FIELDS: List[FieldSpec] = [
    FieldSpec(
        key="api_base_url", label="Falcon API Base URL", type="url",
        required=True, default="https://api.crowdstrike.com",
        help="Region-specific Falcon API URL "
             "(us-1: api.crowdstrike.com, us-2: api.us-2.crowdstrike.com, "
             "eu-1: api.eu-1.crowdstrike.com, "
             "gov-1: api.laggar.gcw.crowdstrike.com).",
    ),
    FieldSpec(
        key="client_id", label="API Client ID",
        type="text", required=True,
    ),
    FieldSpec(
        key="client_secret", label="API Client Secret",
        type="password", required=True, secret=True,
    ),
    FieldSpec(
        key="page_size", label="Page size",
        type="number", default=500,
        help="Items per Falcon REST page (max 5000).",
    ),
    FieldSpec(
        key="max_per_kind",
        label="Max objects per kind per run",
        type="number", default=0,
        help="Hard cap per kind (indicators/actors/reports). "
             "0 = no cap; recommended for first backfill against a "
             "tenant with millions of indicators.",
    ),
    FieldSpec(
        key="from_date", label="Start From (ISO 8601 UTC)",
        type="text", default="",
        help="Optional epoch floor applied to the global indicator "
             "top-up via Falcon's filterable ``last_updated`` column "
             "(e.g. 2025-01-01T00:00:00Z). Leave blank to skip the "
             "global pull entirely — per-report indicators are always "
             "fetched regardless.",
    ),
    FieldSpec(
        key="verify_tls", label="Verify TLS",
        type="bool", default=True,
    ),
]


def _get_falcon_token(api_base: str, client_id: str,
                      client_secret: str) -> str:
    """OAuth2 client-credentials \u2192 bearer token.

    Falcon requires ``grant_type=client_credentials`` in the form body
    plus a form-encoded ``Content-Type``. Omitting either yields an
    opaque ``400 invalid_request`` that previously surfaced to
    operators with no actionable detail, so any non-2xx body is now
    bubbled up to the Connectors UI.
    """
    import requests
    resp = requests.post(
        f"{api_base.rstrip('/')}/oauth2/token",
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials",
        },
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout=30,
    )
    if resp.status_code >= 400:
        body = ""
        try:
            body = (resp.text or "")[:300]
        except Exception:
            pass
        raise RuntimeError(
            f"Falcon /oauth2/token returned HTTP {resp.status_code}"
            + (f" \u2014 {body}" if body else "")
        )
    tok = resp.json().get("access_token")
    if not tok:
        raise RuntimeError(
            "CrowdStrike token endpoint returned no access_token"
        )
    return tok


def download_report_pdf(cfg: Dict[str, Any],
                        report_id: str) -> Optional[Tuple[bytes, str, str]]:
    """Fetch a Falcon Intel report PDF via the report-files endpoint.

    Returns ``(bytes, mime_type, filename)`` on success, ``None`` if the
    connector config is incomplete. ``report_id`` accepts both the
    numeric Falcon report id (``x_crowdstrike_id``) and the CSA-style
    slug from ``external_references[].external_id``.
    """
    import requests
    api_base = (cfg.get("api_base_url") or "").strip()
    client_id = (cfg.get("client_id") or "").strip()
    client_secret = (cfg.get("client_secret") or "").strip()
    if not (api_base and client_id and client_secret and report_id):
        return None
    token = _get_falcon_token(api_base, client_id, client_secret)
    url = f"{api_base.rstrip('/')}/intel/entities/report-files/v1"
    resp = requests.get(
        url,
        params={"id": str(report_id)},
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/pdf",
        },
        timeout=60,
        verify=bool(cfg.get("verify_tls", True)),
    )
    if resp.status_code >= 400:
        body = ""
        try:
            body = (resp.text or "")[:300]
        except Exception:
            pass
        raise RuntimeError(
            f"Falcon report-files returned HTTP {resp.status_code} "
            f"for id={report_id}"
            + (f" \u2014 {body}" if body else "")
        )
    mime = (
        resp.headers.get("Content-Type", "application/pdf")
        .split(";")[0].strip() or "application/pdf"
    )
    return resp.content, mime, f"{report_id}.pdf"


# ── REST helpers ────────────────────────────────────────────────────


_NS = _uuid.uuid5(_uuid.NAMESPACE_URL, "https://falcon.crowdstrike.com/intel")


def _stix_uuid(kind: str, key: str) -> str:
    return str(_uuid.uuid5(_NS, f"{kind}:{key}"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ts_to_iso(ts: Any) -> Optional[str]:
    if ts in (None, "", 0):
        return None
    try:
        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(
                int(ts), tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
        return str(ts)
    except Exception:
        return None


def _confidence(level: Optional[str]) -> int:
    return {
        "high": 90, "medium": 65, "low": 35, "unverified": 10,
    }.get((level or "").lower(), 50)


_PATTERN_FOR = {
    "domain": lambda v: f"[domain-name:value = '{v}']",
    "url": lambda v: f"[url:value = '{v}']",
    "ip_address": lambda v: f"[ipv4-addr:value = '{v}']",
    "ipv4": lambda v: f"[ipv4-addr:value = '{v}']",
    "ipv6": lambda v: f"[ipv6-addr:value = '{v}']",
    "hash_md5": lambda v: f"[file:hashes.MD5 = '{v}']",
    "hash_sha1": lambda v: f"[file:hashes.'SHA-1' = '{v}']",
    "hash_sha256": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
    "email_address": lambda v: f"[email-addr:value = '{v}']",
    "email_subject": lambda v: f"[email-message:subject = '{v}']",
    "username": lambda v: f"[user-account:user_id = '{v}']",
    "file_name": lambda v: f"[file:name = '{v}']",
    "registry": lambda v: f"[windows-registry-key:key = '{v}']",
    "mutex_name": lambda v: f"[mutex:name = '{v}']",
    "campaign_id": lambda v: f"[x-crowdstrike-campaign:id = '{v}']",
}


def _falcon_session(cfg: Dict[str, Any]) -> Tuple[Any, str]:
    """Return (requests.Session pre-loaded with Falcon bearer auth, api_base)."""
    import requests
    api_base = (cfg.get("api_base_url") or "").strip().rstrip("/")
    token = _get_falcon_token(
        api_base,
        (cfg.get("client_id") or "").strip(),
        (cfg.get("client_secret") or "").strip(),
    )
    s = requests.Session()
    s.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": "TIDE-Falcon-Intel-Connector",
    })
    s.verify = bool(cfg.get("verify_tls", True))
    return s, api_base


def _falcon_paged(session, url: str, *, base_params: Dict[str, Any],
                  limit: int, max_total: int) -> List[Dict[str, Any]]:
    """Page through a Falcon ``/intel/combined/...`` endpoint.

    Falcon paginates with ``offset``/``limit`` and reports total in
    ``meta.pagination.total``. Retries 429/5xx with simple backoff.
    """
    out: List[Dict[str, Any]] = []
    offset = 0
    # Falcon rejects requests where ``limit + offset >= 50000``.
    # Keep each page request under that hard ceiling.
    falcon_window_max = 49999
    while True:
        page_limit = min(limit, falcon_window_max - offset)
        if page_limit <= 0:
            logger.warning(
                "CrowdStrike pagination window exhausted for %s "
                "(offset=%d, fetched=%d)",
                url, offset, len(out),
            )
            break
        params = dict(base_params)
        params.update({"limit": page_limit, "offset": offset})
        for attempt in range(4):
            r = session.get(url, params=params, timeout=60)
            if r.status_code == 429 or r.status_code >= 500:
                time.sleep(min(2 ** attempt, 8))
                continue
            break
        if r.status_code >= 400:
            raise RuntimeError(
                f"Falcon GET {url} HTTP {r.status_code}: "
                f"{(r.text or '')[:300]}"
            )
        body = r.json() or {}
        resources = body.get("resources") or []
        if not resources:
            break
        out.extend(resources)
        meta = (body.get("meta") or {}).get("pagination") or {}
        total = int(meta.get("total") or 0)
        offset += len(resources)
        if max_total and len(out) >= max_total:
            return out[:max_total]
        if offset >= total:
            break
    return out


# ── STIX transformers ───────────────────────────────────────────────


def _actor_stix_id(slug_or_id: Any) -> str:
    return f"intrusion-set--{_stix_uuid('actor', str(slug_or_id))}"


def _report_stix_id(slug_or_id: Any) -> str:
    return f"report--{_stix_uuid('report', str(slug_or_id))}"


def _indicator_stix_id(falcon_id: str) -> str:
    return f"indicator--{_stix_uuid('indicator', falcon_id)}"


def _to_stix_actor(actor: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    name = (actor.get("name") or "").strip()
    slug = (actor.get("slug") or "").strip()
    aid = actor.get("id")
    key = slug or str(aid or name)
    if not key:
        return None
    aliases: List[str] = []
    for entry in actor.get("known_as_list") or []:
        if isinstance(entry, dict) and entry.get("name"):
            aliases.append(entry["name"])
    if isinstance(actor.get("known_as"), str):
        aliases.extend(
            x.strip() for x in actor["known_as"].split(",") if x.strip()
        )
    created = _ts_to_iso(actor.get("created_date")) or _now_iso()
    return {
        "type": "intrusion-set",
        "spec_version": "2.1",
        "id": _actor_stix_id(key),
        "name": name or slug or f"falcon-actor-{aid}",
        "aliases": aliases or None,
        "description": actor.get("short_description")
                       or actor.get("description") or "",
        "created": created,
        "modified": _ts_to_iso(actor.get("last_modified_date")) or created,
        "labels": ["crowdstrike"],
        "x_crowdstrike_id": aid,
        "x_crowdstrike_slug": slug,
        "external_references": [{
            "source_name": "CrowdStrike",
            "external_id": slug,
            "url": actor.get("url")
                   or f"https://falcon.crowdstrike.com/intelligence/actors/{slug}",
        }] if slug else [],
    }


def _to_stix_report(report: Dict[str, Any],
                    object_refs: List[str]) -> Optional[Dict[str, Any]]:
    rid = report.get("id")
    slug = (report.get("slug") or "").strip()
    key = slug or str(rid)
    if not key:
        return None
    created = _ts_to_iso(report.get("created_date")) or _now_iso()
    published = (_ts_to_iso(report.get("publish_date"))
                 or _ts_to_iso(report.get("created_date"))
                 or created)
    name = report.get("name") or slug or f"falcon-report-{rid}"
    # STIX 2.1 requires object_refs to be non-empty. When we have no
    # cross-references yet, point the report at itself via a synthetic
    # marker so the SDO is spec-compliant.
    refs = list(dict.fromkeys(object_refs)) or [_actor_stix_id(f"self:{key}")]
    return {
        "type": "report",
        "spec_version": "2.1",
        "id": _report_stix_id(key),
        "name": name,
        "description": report.get("description")
                       or report.get("short_description") or "",
        "published": published,
        "created": created,
        "modified": _ts_to_iso(report.get("last_modified_date")) or created,
        "labels": ["crowdstrike"],
        "object_refs": refs,
        "x_crowdstrike_id": rid,
        "x_crowdstrike_slug": slug,
        "external_references": [{
            "source_name": "CrowdStrike",
            "external_id": slug,
            "url": report.get("url")
                   or f"https://falcon.crowdstrike.com/intelligence/reports/{slug}",
        }] if slug else [],
    }


def _to_stix_indicator(ind: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    itype = (ind.get("type") or "").lower().strip()
    value = ind.get("indicator")
    if not itype or value in (None, ""):
        return None
    pattern_fn = _PATTERN_FOR.get(itype)
    if not pattern_fn:
        return None
    fid = str(ind.get("id") or f"{itype}-{value}")
    pub_iso = (_ts_to_iso(ind.get("published_date"))
               or _ts_to_iso(ind.get("last_updated"))
               or _now_iso())
    labels = ["crowdstrike", itype]
    for m in ind.get("malware_families") or []:
        if m:
            labels.append(f"malware:{m}")
    for a in ind.get("actors") or []:
        if a:
            labels.append(f"actor:{a}")
    kill_chain = [
        {"kill_chain_name": "crowdstrike", "phase_name": k}
        for k in (ind.get("kill_chains") or []) if k
    ]
    reports = [str(r).strip() for r in (ind.get("reports") or []) if r]
    actors = [str(a).strip() for a in (ind.get("actors") or []) if a]
    pattern = pattern_fn(str(value).replace("'", "\\'"))
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _indicator_stix_id(fid),
        "created": pub_iso,
        "modified": _ts_to_iso(ind.get("last_updated")) or pub_iso,
        "valid_from": pub_iso,
        "name": f"CrowdStrike {itype} {value}",
        "pattern_type": "stix",
        "pattern": pattern,
        "labels": labels,
        "confidence": _confidence(ind.get("malicious_confidence")),
        "kill_chain_phases": kill_chain,
        "x_crowdstrike_id": fid,
        # Keep vendor linkage fields so the UI can resolve report
        # associations from stored raw_stix even when relationship edges
        # are sparse in legacy tenants.
        "x_crowdstrike_reports": reports,
        "x_crowdstrike_actors": actors,
    }


# ── Sync orchestrator ───────────────────────────────────────────────


def _build_bundle(cfg: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """Pull indicators/actors/reports and assemble a STIX bundle."""
    session, api_base = _falcon_session(cfg)
    page_size = max(1, min(int(cfg.get("page_size") or 500), 5000))
    # Accept the legacy field name ``max_objects_per_collection`` (used
    # while the connector still pretended to be TAXII 2.1) so existing
    # connector rows keep their saved cap after upgrade.
    cap_per_kind = int(
        cfg.get("max_per_kind")
        or cfg.get("max_objects_per_collection")
        or 0
    )
    from_date = (cfg.get("from_date") or "").strip()
    logger.info(
        "CrowdStrike: starting bundle build "
        "(page_size=%d, cap_per_kind=%s, from_date=%s)",
        page_size, cap_per_kind or "unlimited", from_date or "<none>",
    )

    # Falcon ``_marker`` is an opaque continuation cursor, NOT a
    # filterable date field — ``filter=_marker:>='2026-01-01...'`` is
    # accepted but always returns 0 rows. The real filterable date
    # column is ``last_updated`` (epoch seconds), so translate the
    # operator-supplied ISO date into that.
    from_epoch: Optional[int] = None
    if from_date:
        try:
            ts = from_date.replace("Z", "+00:00")
            from_epoch = int(datetime.fromisoformat(ts).timestamp())
        except Exception:
            logger.warning(
                "CrowdStrike: ignoring unparseable from_date=%r", from_date,
            )

    # Pull newest-first so a bounded Falcon pagination window still
    # contains current report-linked IOCs (e.g. latest CSA reports).
    ind_base_params: Dict[str, Any] = {
        "sort": "last_updated.desc",
        # Falcon omits ``reports`` unless include_relations=true.
        # Without this, report-linked indicator wiring stays empty.
        "include_relations": "true",
    }
    if from_epoch:
        ind_base_params["filter"] = f"last_updated:>={from_epoch}"

    actors = _falcon_paged(
        session, f"{api_base}/intel/combined/actors/v1",
        base_params={"sort": "last_modified_date.asc"},
        limit=page_size, max_total=cap_per_kind,
    )
    logger.info("CrowdStrike: fetched %d actors", len(actors))

    report_base_params: Dict[str, Any] = {"sort": "last_modified_date.desc"}
    if from_epoch:
        report_base_params["filter"] = f"last_modified_date:>={from_epoch}"
    reports = _falcon_paged(
        session, f"{api_base}/intel/combined/reports/v1",
        base_params=report_base_params,
        limit=page_size, max_total=cap_per_kind,
    )
    logger.info("CrowdStrike: fetched %d reports", len(reports))

    # 5.0.0: single bulk indicator fetch. Each Falcon indicator carries
    # ``reports[]`` and ``actors[]`` arrays, so one paginated call gives
    # us everything we need to wire indicators to their reports — the
    # earlier per-report scan was 1,296 sequential API calls which
    # exhausted Falcon's rate limit. ``reports:!''`` restricts the
    # response to IOCs that are attached to at least one report so we
    # don't drag in the bulk-feed corpus (Falcon's full indicator set
    # is 300M+ rows).
    ind_base_params["filter"] = (
        f"({ind_base_params['filter']})+reports:!''"
        if ind_base_params.get("filter")
        else "reports:!''"
    )
    indicators = _falcon_paged(
        session, f"{api_base}/intel/combined/indicators/v1",
        base_params=ind_base_params,
        limit=page_size, max_total=cap_per_kind,
    )
    logger.info(
        "CrowdStrike: fetched %d report-linked indicators", len(indicators),
    )

    actor_slug_to_id: Dict[str, str] = {}
    actor_objects: List[Dict[str, Any]] = []
    for a in actors:
        obj = _to_stix_actor(a)
        if not obj:
            continue
        actor_objects.append(obj)
        slug = (a.get("slug") or "").strip()
        if slug:
            actor_slug_to_id[slug.lower()] = obj["id"]
            actor_slug_to_id[(a.get("name") or "").lower()] = obj["id"]

    report_slug_to_id: Dict[str, str] = {}
    report_refs: Dict[str, List[str]] = {}
    report_actor_relationships: List[Dict[str, Any]] = []
    seen_report_actor: set[tuple[str, str]] = set()
    for r in reports:
        slug = (r.get("slug") or "").strip()
        rid = r.get("id")
        key = slug or str(rid or "")
        if not key:
            continue
        sid = _report_stix_id(key)
        rep_created = _ts_to_iso(r.get("created_date")) or _now_iso()
        rep_modified = _ts_to_iso(r.get("last_modified_date")) or rep_created
        if slug:
            report_slug_to_id[slug.lower()] = sid
        report_slug_to_id[str(rid).lower()] = sid
        # seed object_refs with the actors named on this report
        refs: List[str] = []
        for entry in r.get("actors") or []:
            if not isinstance(entry, dict):
                continue
            sslug = (entry.get("slug") or "").lower()
            sname = (entry.get("name") or "").lower()
            aid = actor_slug_to_id.get(sslug) or actor_slug_to_id.get(sname)
            if aid:
                refs.append(aid)
                edge = (sid, aid)
                if edge not in seen_report_actor:
                    seen_report_actor.add(edge)
                    report_actor_relationships.append({
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": (
                            "relationship--"
                            f"{_stix_uuid('rel-rep-actor', sid + aid)}"
                        ),
                        "created": rep_created,
                        "modified": rep_modified,
                        "relationship_type": "attributed-to",
                        "source_ref": sid,
                        "target_ref": aid,
                    })
        report_refs[sid] = refs

    indicator_objects: List[Dict[str, Any]] = []
    relationships: List[Dict[str, Any]] = list(report_actor_relationships)
    for ind in indicators:
        obj = _to_stix_indicator(ind)
        if not obj:
            continue
        indicator_objects.append(obj)
        # indicator → intrusion-set (indicates)
        for a in ind.get("actors") or []:
            if not a:
                continue
            aid = actor_slug_to_id.get(str(a).lower())
            if not aid:
                continue
            relationships.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{_stix_uuid('rel-ind-actor', obj['id'] + aid)}",
                "created": obj["created"],
                "modified": obj["modified"],
                "relationship_type": "indicates",
                "source_ref": obj["id"],
                "target_ref": aid,
            })
        # add indicator to any matching report.object_refs and emit an
        # explicit ``refers-to`` relationship SDO so cti_ingest writes
        # an edge into ``cti_relationships`` (the report viewer queries
        # that edge table, not ``object_refs``).
        for r in ind.get("reports") or []:
            if not r:
                continue
            rid = report_slug_to_id.get(str(r).lower())
            if not rid:
                continue
            report_refs.setdefault(rid, []).append(obj["id"])
            relationships.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{_stix_uuid('rel-rep-ind', rid + obj['id'])}",
                "created": obj["created"],
                "modified": obj["modified"],
                "relationship_type": "refers-to",
                "source_ref": rid,
                "target_ref": obj["id"],
            })

    report_objects: List[Dict[str, Any]] = []
    for r in reports:
        slug = (r.get("slug") or "").strip()
        key = slug or str(r.get("id") or "")
        if not key:
            continue
        sid = _report_stix_id(key)
        obj = _to_stix_report(r, report_refs.get(sid, []))
        if obj:
            report_objects.append(obj)

    all_objects = (
        actor_objects + report_objects + indicator_objects + relationships
    )
    type_tally: Dict[str, int] = {}
    for o in all_objects:
        t = o.get("type") or "unknown"
        type_tally[t] = type_tally.get(t, 0) + 1

    bundle = {
        "type": "bundle",
        "id": f"bundle--{_uuid.uuid4()}",
        "objects": all_objects,
    }
    return bundle, type_tally


def sync(connector: Dict[str, Any],
         linked_clients: List[Dict[str, Any]]) -> SyncResult:
    from app.services import cti_ingest
    from app.services.tenant_manager import tenant_context_for

    cfg = connector.get("config") or {}
    label = connector.get("label") or connector.get("id", "?")
    connector_id = str(connector.get("id") or "")
    missing = [k for k in ("api_base_url", "client_id", "client_secret")
               if not cfg.get(k)]
    if missing:
        return SyncResult(
            errors=[f"CrowdStrike connector {label!r}: missing "
                    f"{', '.join(missing)}"],
        )
    if not linked_clients:
        return SyncResult(
            errors=[f"CrowdStrike connector {label!r}: no clients linked"],
        )

    try:
        bundle, type_tally = _build_bundle(cfg)
    except Exception as exc:
        msg = f"CrowdStrike connector {label!r}: fetch failed: {exc}"
        logger.error(msg, exc_info=True)
        return SyncResult(errors=[msg])

    if not bundle["objects"]:
        return SyncResult(
            tenants=0,
            upstream_types=type_tally,
            errors=[f"CrowdStrike connector {label!r}: upstream returned "
                    f"no usable objects"],
        )

    source_id = f"connector:{connector_id}"
    totals: Dict[str, int] = {
        k: 0 for k in (
            "indicators_new", "indicators_merged", "indicators_review",
            "actors", "reports", "intrusion_sets",
            "relationships", "skipped",
        )
    }
    per_tenant: List[Dict[str, Any]] = []
    errors: List[str] = []
    for client in linked_clients:
        cid = client.get("id")
        try:
            with tenant_context_for(cid):
                counters = cti_ingest.ingest_stix_bundle(
                    cid, bundle, source_id=source_id, bundle_id=bundle["id"],
                )
        except Exception as exc:
            msg = (f"CrowdStrike ingest failed for "
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


def test_connection(connector: Dict[str, Any]) -> Dict[str, Any]:
    """Hit a cheap Falcon Intel endpoint to validate creds + scope."""
    import requests
    cfg = connector.get("config") or {}
    api_base = (cfg.get("api_base_url") or "").strip().rstrip("/")
    try:
        token = _get_falcon_token(
            api_base,
            (cfg.get("client_id") or "").strip(),
            (cfg.get("client_secret") or "").strip(),
        )
    except Exception as exc:
        return {"ok": False, "error": f"token exchange failed: {exc}",
                "collections": []}

    headers = {"Authorization": f"Bearer {token}",
               "Accept": "application/json"}
    readable: List[str] = []
    unreadable: List[str] = []
    for kind, path in (("indicators", "/intel/queries/indicators/v1"),
                       ("actors", "/intel/queries/actors/v1"),
                       ("reports", "/intel/queries/reports/v1")):
        try:
            r = requests.get(
                f"{api_base}{path}", params={"limit": 1},
                headers=headers, timeout=30,
                verify=bool(cfg.get("verify_tls", True)),
            )
        except Exception as exc:
            unreadable.append(f"{kind}: {exc}")
            continue
        if 200 <= r.status_code < 300:
            readable.append(kind)
        else:
            body = (r.text or "")[:200]
            unreadable.append(
                f"{kind}: HTTP {r.status_code}"
                + (f" \u2014 {body}" if body else "")
            )

    if readable:
        return {
            "ok": True,
            "collections": readable,
            "unreadable": unreadable,
        }
    return {
        "ok": False,
        "error": (
            "Falcon credentials authenticate, but none of the Falcon "
            "Intelligence read scopes are granted. Enable the API "
            "client's Intel:read scope and retry. "
            + "; ".join(unreadable)[:400]
        ),
        "collections": [],
        "unreadable": unreadable,
    }


VENDOR = ConnectorVendor(
    name="crowdstrike_taxii",
    label="CrowdStrike Falcon Intelligence",
    icon="crowdstrike",
    kind_default="cti",
    fields=FIELDS,
    fetcher=sync,
    tester=test_connection,
)
