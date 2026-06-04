"""CTI read surface — `/cti/...` (step E of PLAN_CTI.md).

This module owns the operator-facing browse + drill-down pages for the
per-tenant CTI database: indicators, actors and reports, each with a
cross-link panel driven by the ``cti_relationships`` edge table.

Design notes
------------

* **TLP scoping.** Indicator queries pass every ``tlp`` column through
  :func:`app.api.cti_deps.tlp_filter_clause`, which is bound to the
  operator's Keycloak ``tide_tlp_max`` claim via the
  :data:`TlpScopeDep` dependency. Actors carry no TLP and are always
  visible. Reports do not currently carry a ``tlp`` column (schema v3)
  so the report list is unfiltered today; a future schema bump will
  carry through the report-level marking. Cross-link panels that hang
  off a report still scope the indicator side by the operator ceiling,
  so a ``red`` indicator never surfaces just because it was referenced
  by a wide-distribution report.

* **Query helpers vs. routes.** The pure-SQL ``query_*`` helpers take a
  raw DuckDB connection so the smoke test can drive them against an
  in-memory database without spinning up FastAPI. The route handlers
  open the per-tenant CTI DB via :func:`open_cti_db` and delegate.

* **Templates.** Pages live under ``app/templates/pages/cti/``. The
  router exposes ``request.app.state.templates`` (the shared
  ``Jinja2Templates`` instance configured in ``app/main.py``) so we
  pick up brand_hue / cache_bust / active_client without re-deriving
  them here.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from app.api.cti_deps import (
    TlpScope,
    TlpScopeDep,
    filter_rows_by_tlp,
    tlp_filter_clause,
)
from app.api.deps import ActiveClient, RequireUser, RequireAdmin, DbDep
from app.services.cti_database import open_cti_db

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cti", tags=["cti"])


# ── Query helpers (pure SQL, take a connection) ──────────────────────


_INDICATOR_COLS = (
    "id", "pattern_type", "observable_value", "pattern",
    "valid_from", "valid_until", "tlp", "confidence",
    "source_id", "first_seen", "last_seen",
    "kill_chain", "mitre_techniques", "needs_review",
)


def _row_to_dict(cols: tuple[str, ...], row: tuple) -> dict:
    return {c: row[i] for i, c in enumerate(cols)}


def query_indicators(
    conn,
    scope: TlpScope,
    *,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    """List indicators visible under ``scope``.

    Sorted most-recently-seen first. ``search`` does a case-insensitive
    substring match against ``observable_value`` and ``pattern_type``.
    """
    clause, params = tlp_filter_clause(scope)
    sql = (
        f"SELECT {', '.join(_INDICATOR_COLS)} FROM cti_indicators "
        f"WHERE {clause}"
    )
    if search:
        sql += " AND (observable_value ILIKE ? OR pattern_type ILIKE ?)"
        like = f"%{search}%"
        params.extend([like, like])
    sql += " ORDER BY last_seen DESC NULLS LAST, id LIMIT ? OFFSET ?"
    params.extend([int(limit), int(offset)])
    rows = conn.execute(sql, params).fetchall()
    return [_row_to_dict(_INDICATOR_COLS, r) for r in rows]


def query_indicator(
    conn,
    scope: TlpScope,
    indicator_id: str,
) -> Optional[dict]:
    """Fetch one indicator + its related actors + related reports.

    Returns ``None`` if the indicator does not exist *or* is hidden by
    the operator's TLP ceiling. The two outcomes look identical to the
    caller on purpose: we do not want to leak the existence of a row
    the operator cannot see.
    """
    clause, params = tlp_filter_clause(scope)
    sql = (
        f"SELECT {', '.join(_INDICATOR_COLS)} FROM cti_indicators "
        f"WHERE id = ? AND {clause}"
    )
    row = conn.execute(sql, [indicator_id, *params]).fetchone()
    if not row:
        return None
    out = _row_to_dict(_INDICATOR_COLS, row)

    # Related actors via the ``indicates`` edge.
    actor_rows = conn.execute(
        "SELECT a.stix_type, a.name, a.origin, a.description "
        "FROM cti_relationships r "
        "JOIN cti_actors a "
        "  ON a.stix_type = r.dst_type AND a.name = r.dst_id "
        "WHERE r.src_type = 'indicator' AND r.src_id = ? "
        "  AND r.rel_type = 'indicates' "
        "  AND r.dst_type IN ('intrusion-set', 'threat-actor') "
        "ORDER BY a.name",
        [indicator_id],
    ).fetchall()
    out["related_actors"] = [
        {"stix_type": r[0], "name": r[1], "origin": r[2], "description": r[3]}
        for r in actor_rows
    ]

    # Related reports via ``refers-to`` (report → indicator). Reports
    # carry no TLP today, so we return all of them.
    report_rows = conn.execute(
        "SELECT rep.id, rep.name, rep.published "
        "FROM cti_relationships r "
        "JOIN cti_reports rep ON rep.id = r.src_id "
        "WHERE r.src_type = 'report' AND r.dst_type = 'indicator' "
        "  AND r.dst_id = ? "
        "ORDER BY rep.published DESC NULLS LAST, rep.id",
        [indicator_id],
    ).fetchall()
    out["related_reports"] = [
        {"id": r[0], "name": r[1], "published": r[2]} for r in report_rows
    ]
    return out


_ACTOR_COLS = (
    "stix_type", "name", "aliases", "description", "origin",
    "first_seen", "last_seen", "source_id",
)


def query_actors(
    conn,
    *,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    """List actors. Actors carry no TLP marking so ``scope`` is not consulted."""
    sql = (
        f"SELECT {', '.join(_ACTOR_COLS)} FROM cti_actors"
    )
    params: list = []
    if search:
        sql += " WHERE (name ILIKE ? OR description ILIKE ?)"
        like = f"%{search}%"
        params.extend([like, like])
    sql += " ORDER BY name LIMIT ? OFFSET ?"
    params.extend([int(limit), int(offset)])
    rows = conn.execute(sql, params).fetchall()
    return [_row_to_dict(_ACTOR_COLS, r) for r in rows]


def query_actor(
    conn,
    scope: TlpScope,
    name: str,
    *,
    stix_type: Optional[str] = None,
) -> Optional[dict]:
    """Fetch one actor + related indicators (TLP-filtered) + related reports.

    ``stix_type`` is optional. If omitted we pick the first match on
    name (intrusion-set wins lexicographically); callers that care
    should pass it explicitly.
    """
    if stix_type:
        row = conn.execute(
            f"SELECT {', '.join(_ACTOR_COLS)} FROM cti_actors "
            f"WHERE stix_type = ? AND name = ?",
            [stix_type, name],
        ).fetchone()
    else:
        row = conn.execute(
            f"SELECT {', '.join(_ACTOR_COLS)} FROM cti_actors "
            f"WHERE name = ? ORDER BY stix_type LIMIT 1",
            [name],
        ).fetchone()
    if not row:
        return None
    out = _row_to_dict(_ACTOR_COLS, row)
    actor_type = out["stix_type"]
    actor_name = out["name"]
    actor_stix_id = ""
    try:
        stix_row = conn.execute(
            "SELECT stix_id FROM cti_actors WHERE stix_type = ? AND name = ? "
            "LIMIT 1",
            [actor_type, actor_name],
        ).fetchone()
        actor_stix_id = str(stix_row[0] or "") if stix_row else ""
    except Exception:
        actor_stix_id = ""

    # Related indicators via the ``indicates`` edge (indicator → actor),
    # scoped by the operator's TLP ceiling.
    ind_clause, ind_params = tlp_filter_clause(
        TlpScope(scope.ceiling), column="i.tlp",
    )
    ind_rows = conn.execute(
        "SELECT i.id, i.pattern_type, i.observable_value, i.tlp, "
        "       i.confidence, i.last_seen "
        "FROM cti_relationships r "
        "JOIN cti_indicators i ON i.id = r.src_id "
        "WHERE r.src_type = 'indicator' AND r.rel_type = 'indicates' "
        "  AND r.dst_type = ? AND r.dst_id = ? "
        f"  AND {ind_clause} "
        "ORDER BY i.last_seen DESC NULLS LAST, i.id",
        [actor_type, actor_name, *ind_params],
    ).fetchall()
    out["related_indicators"] = [
        {
            "id": r[0],
            "pattern_type": r[1],
            "observable_value": r[2],
            "tlp": r[3],
            "confidence": r[4],
            "last_seen": r[5],
        }
        for r in ind_rows
    ]

    # Related reports: union explicit edges from ``cti_relationships``
    # with report.raw_stix.object_refs fallback so Falcon/OpenCTI report
    # pages and actor pages stay symmetric even when ingest did not emit
    # a report->actor relationship SDO.
    report_sql = (
        "SELECT DISTINCT rep.id, rep.name, rep.published "
        "FROM cti_reports rep "
        "WHERE ("
        "  EXISTS ("
        "    SELECT 1 FROM cti_relationships r "
        "    WHERE r.src_type = 'report' AND r.src_id = rep.id "
        "      AND r.dst_type = ? AND (r.dst_id = ? OR r.dst_id = ?)"
        "  )"
    )
    report_params: list = [actor_type, actor_name, actor_stix_id]
    if actor_stix_id:
        report_sql += " OR rep.raw_stix ILIKE ?"
        report_params.append(f'%"{actor_stix_id}"%')
    report_sql += ") ORDER BY rep.published DESC NULLS LAST, rep.id"
    report_rows = conn.execute(report_sql, report_params).fetchall()
    out["related_reports"] = [
        {"id": r[0], "name": r[1], "published": r[2]} for r in report_rows
    ]
    return out


_REPORT_COLS = (
    "id", "name", "description", "published", "labels", "source_id",
)


def query_reports(
    conn,
    *,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    """List reports. ``cti_reports`` has no TLP column in schema v3."""
    sql = (
        f"SELECT {', '.join(_REPORT_COLS)} FROM cti_reports"
    )
    params: list = []
    if search:
        sql += " WHERE (name ILIKE ? OR description ILIKE ?)"
        like = f"%{search}%"
        params.extend([like, like])
    sql += " ORDER BY published DESC NULLS LAST, id LIMIT ? OFFSET ?"
    params.extend([int(limit), int(offset)])
    rows = conn.execute(sql, params).fetchall()
    return [_row_to_dict(_REPORT_COLS, r) for r in rows]


def _source_connector_id(source_id: Optional[str]) -> Optional[str]:
    sid = (source_id or "").strip()
    if not sid.startswith("connector:"):
        return None
    cid = sid.split(":", 1)[1].strip()
    return cid or None


def _opencti_base_from_taxii_root(taxii_root: str) -> str:
    """Derive OpenCTI base URL from a TAXII root URL."""
    from urllib.parse import urlsplit, urlunsplit

    root = (taxii_root or "").strip()
    if not root:
        return ""
    parts = urlsplit(root)
    path = parts.path or "/"
    marker = "/taxii2/"
    if marker in path:
        path = path.split(marker, 1)[0] or "/"
    if not path.endswith("/"):
        path += "/"
    return urlunsplit((parts.scheme, parts.netloc, path.rstrip("/"), "", ""))


def _opencti_graphql_from_taxii_root(taxii_root: str) -> str:
    base = _opencti_base_from_taxii_root(taxii_root)
    if not base:
        return ""
    return base.rstrip("/") + "/graphql"


def _normalise_opencti_file_entry(item: dict) -> dict:
    meta = item.get("metaData") if isinstance(item.get("metaData"), dict) else {}
    mime = (
        item.get("mime_type")
        or item.get("mimeType")
        or item.get("mimetype")
        or meta.get("mimetype")
        or "application/octet-stream"
    )
    return {
        "id": item.get("id") or item.get("file_id") or "",
        "name": item.get("name") or item.get("filename") or "attachment",
        "mime_type": mime,
        "data": item.get("data") or "",
    }


def _extract_opencti_files(payload: Any) -> list[dict]:
    """Best-effort extraction of OpenCTI file entries from GraphQL payload."""
    import json as _json

    out: list[dict] = []

    def _add_many(vals: list[Any]) -> None:
        for v in vals:
            if isinstance(v, dict):
                out.append(_normalise_opencti_file_entry(v))

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            if "x_opencti_files" in node:
                raw = node.get("x_opencti_files")
                if isinstance(raw, str):
                    try:
                        raw = _json.loads(raw)
                    except Exception:
                        raw = []
                if isinstance(raw, list):
                    _add_many(raw)
            if "importFiles" in node and isinstance(node.get("importFiles"), dict):
                edges = node["importFiles"].get("edges") or []
                for e in edges:
                    n = (e or {}).get("node") if isinstance(e, dict) else None
                    if isinstance(n, dict):
                        out.append(_normalise_opencti_file_entry(n))
            for v in node.values():
                _walk(v)
        elif isinstance(node, list):
            for v in node:
                _walk(v)

    _walk(payload)

    dedup: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for f in out:
        key = ((f.get("id") or "").strip(), (f.get("name") or "").strip())
        if key in seen:
            continue
        seen.add(key)
        dedup.append(f)
    return dedup


def _fetch_opencti_report_files_live(
    db,
    source_id: Optional[str],
    report_id: str,
    report_name: Optional[str] = None,
) -> list[dict]:
    """Query OpenCTI GraphQL for report files when TAXII payload omits them."""
    import requests

    cid = _source_connector_id(source_id)
    if not cid:
        return []
    try:
        connector = db.get_cti_connector(cid)
    except Exception:
        return []
    if not connector or connector.get("vendor") != "opencti_taxii":
        return []
    cfg = connector.get("config") or {}
    token = (cfg.get("token") or "").strip()
    gql = _opencti_graphql_from_taxii_root(cfg.get("taxii_root") or "")
    if not token or not gql:
        return []

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    queries: list[tuple[str, dict]] = [
        (
            """
            query($id:String!) {
              stixCoreObject(id:$id) {
                ... on Report {
                  x_opencti_files
                  importFiles(first: 50) {
                    edges { node { id name mimeType mimetype } }
                  }
                }
              }
            }
            """,
            {"id": report_id},
        ),
        (
            """
            query($search:String!) {
              reports(search:$search, first: 5) {
                edges {
                  node {
                    standard_id
                    name
                    x_opencti_files
                    importFiles(first: 50) {
                      edges { node { id name mimeType mimetype } }
                    }
                  }
                }
              }
            }
            """,
            {"search": report_name or report_id},
        ),
    ]

    for query, variables in queries:
        try:
            resp = requests.post(
                gql,
                json={"query": query, "variables": variables},
                headers=headers,
                timeout=(8, 20),
            )
            if resp.status_code != 200:
                continue
            payload = resp.json()
            if payload.get("errors"):
                continue
            files = _extract_opencti_files(payload.get("data") or {})
            if files:
                return files
        except Exception:
            logger.debug("OpenCTI live file lookup failed for %s", report_id)
            continue
    return []


def _crowdstrike_report_ids(raw_stix: dict) -> list[str]:
    """Return CrowdStrike report identifiers usable against the Falcon
    report-files endpoint. Prefers ``x_crowdstrike_id`` (numeric), then
    falls back to CSA-style slugs in ``external_references``.
    """
    out: list[str] = []
    if not isinstance(raw_stix, dict):
        return out
    cs_id = (
        raw_stix.get("x_crowdstrike_id")
        or raw_stix.get("x_crowdstrike_report_id")
    )
    if cs_id not in (None, ""):
        out.append(str(cs_id))
    for ref in raw_stix.get("external_references") or []:
        if not isinstance(ref, dict):
            continue
        src = (ref.get("source_name") or "").lower()
        ext = (ref.get("external_id") or "").strip()
        if not ext:
            continue
        cs_slug = ext.upper().startswith(
            ("CSA-", "CSIT-", "CSWR-", "CSIR-", "CSMR-", "CSDR-")
        )
        if "crowdstrike" in src or "falcon" in src or cs_slug:
            if ext not in out:
                out.append(ext)
    return out


def _crowdstrike_connector_config(db, source_id: Optional[str]) -> Optional[dict]:
    """Return the CrowdStrike connector ``config`` dict for ``source_id``,
    or ``None`` if the source did not originate from a CrowdStrike connector.
    """
    cid = _source_connector_id(source_id)
    if not cid:
        return None
    try:
        connector = db.get_cti_connector(cid)
    except Exception:
        return None
    if not connector or connector.get("vendor") != "crowdstrike_taxii":
        return None
    return connector.get("config") or {}


def _fetch_crowdstrike_report_indicator_stix_ids_live(
    db,
    source_id: Optional[str],
    raw_stix: dict,
    *,
    max_ids: int = 3000,
) -> list[str]:
    """Best-effort Falcon lookup for indicators linked to one report.

    Returns indicator STIX ids (``indicator--...``) derived from Falcon's
    indicator ids, so callers can join back onto local ``cti_indicators``.
    Only used when local relationship/object-ref wiring is empty.
    """
    import requests
    from app.services.cti_connectors import crowdstrike_taxii as cs

    cfg = _crowdstrike_connector_config(db, source_id)
    if not cfg:
        return []
    api_base = (cfg.get("api_base_url") or "").strip().rstrip("/")
    client_id = (cfg.get("client_id") or "").strip()
    client_secret = (cfg.get("client_secret") or "").strip()
    if not (api_base and client_id and client_secret):
        return []

    tokens = _crowdstrike_report_ids(raw_stix)
    if not tokens:
        return []

    try:
        token = cs._get_falcon_token(api_base, client_id, client_secret)
    except Exception:
        return []

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    out: list[str] = []
    seen: set[str] = set()

    # Prefer slug-like tokens first (CSA-..., CSWR-...) then numeric ids.
    ordered = sorted(tokens, key=lambda t: t.isdigit())
    for report_token in ordered:
        offset = 0
        page_limit = 500
        while len(out) < max_ids:
            filt = f"reports:'{report_token}'"
            params = {
                "limit": page_limit,
                "offset": offset,
                "sort": "last_updated.desc",
                "filter": filt,
                "include_relations": "true",
            }
            try:
                resp = requests.get(
                    f"{api_base}/intel/combined/indicators/v1",
                    headers=headers,
                    params=params,
                    timeout=45,
                    verify=bool(cfg.get("verify_tls", True)),
                )
            except Exception:
                break
            if resp.status_code != 200:
                break
            body = resp.json() or {}
            rows = body.get("resources") or []
            if not rows:
                break
            for ind in rows:
                falcon_id = str(ind.get("id") or "").strip()
                if not falcon_id:
                    continue
                sid = cs._indicator_stix_id(falcon_id)
                if sid in seen:
                    continue
                seen.add(sid)
                out.append(sid)
                if len(out) >= max_ids:
                    break
            offset += len(rows)
            if len(rows) < page_limit:
                break
        if out:
            # One token hit is enough; don't fan out extra calls.
            break
    return out


def _download_opencti_file_live(
    db,
    source_id: Optional[str],
    file_id: str,
) -> tuple[bytes, str] | tuple[None, None]:
    """Download one OpenCTI file by id via the storage endpoint."""
    import base64
    import requests

    cid = _source_connector_id(source_id)
    if not cid or not file_id:
        return (None, None)
    try:
        connector = db.get_cti_connector(cid)
    except Exception:
        return (None, None)
    if not connector or connector.get("vendor") != "opencti_taxii":
        return (None, None)
    cfg = connector.get("config") or {}
    token = (cfg.get("token") or "").strip()
    base = _opencti_base_from_taxii_root(cfg.get("taxii_root") or "")
    if not token or not base:
        return (None, None)

    headers = {"Authorization": f"Bearer {token}"}
    candidates = [
        f"{base.rstrip('/')}/storage/get/{file_id}",
        f"{base.rstrip('/')}/storage/get/{file_id}?download=true",
    ]
    for url in candidates:
        try:
            resp = requests.get(url, headers=headers, timeout=(8, 30))
            if resp.status_code != 200:
                continue
            ctype = (resp.headers.get("Content-Type") or "").lower()
            if "application/json" in ctype:
                try:
                    j = resp.json() or {}
                    b64 = j.get("data") or ""
                    if b64:
                        return (base64.b64decode(b64), j.get("mime_type") or "application/octet-stream")
                except Exception:
                    continue
            return (resp.content, resp.headers.get("Content-Type") or "application/octet-stream")
        except Exception:
            continue
    return (None, None)


def query_report(
    conn,
    scope: TlpScope,
    report_id: str,
    db=None,
) -> Optional[dict]:
    """Fetch one report + related indicators (TLP-filtered) + related actors."""
    row = conn.execute(
        f"SELECT {', '.join(_REPORT_COLS)} FROM cti_reports WHERE id = ?",
        [report_id],
    ).fetchone()
    if not row:
        return None
    out = _row_to_dict(_REPORT_COLS, row)

    # Indicators this report refers to, TLP-scoped. Two sources:
    #   1. ``cti_relationships`` (preferred — what OpenCTI ingest wires
    #      from STIX ``relationship`` SDOs).
    #   2. The report's own ``raw_stix.object_refs`` (what
    #      CrowdStrike's bundle always carries, even when no separate
    #      ``relationship`` SDO was emitted or written).
    # 5.0.x: we union the two so a report renders its IOCs as long as
    # *either* path resolved during ingest. Match indicators by
    # ``stix_id`` (raw STIX identifier) OR ``id`` (the legacy md5 key
    # the per-tenant store uses); OpenCTI feeds populate the former,
    # CrowdStrike's deterministic STIX ids populate both.
    raw_object_refs: list[str] = []
    raw_blob: dict = {}
    try:
        raw_row = conn.execute(
            "SELECT raw_stix FROM cti_reports WHERE id = ?", [report_id],
        ).fetchone()
        if raw_row and raw_row[0]:
            import json as _json
            _blob = _json.loads(raw_row[0]) or {}
            raw_blob = _blob
            raw_object_refs = [
                str(x) for x in (_blob.get("object_refs") or []) if x
            ]
    except Exception:
        raw_object_refs = []
        raw_blob = {}
    ref_indicator_ids = [r for r in raw_object_refs if r.startswith("indicator--")]
    ref_actor_ids = [
        r for r in raw_object_refs
        if r.startswith("intrusion-set--") or r.startswith("threat-actor--")
    ]

    ind_clause, ind_params = tlp_filter_clause(scope, column="i.tlp")
    placeholders = ",".join("?" * len(ref_indicator_ids)) if ref_indicator_ids else None
    # Fallback: many CrowdStrike indicator rows carry linked report ids
    # only inside indicator.raw_stix (e.g. ``reports`` arrays) without a
    # corresponding relationship SDO/object_ref edge. Match by known
    # report tokens so the report page can render related IOCs from
    # already-ingested data.
    report_tokens: list[str] = [report_id]
    for key in ("x_crowdstrike_id", "x_crowdstrike_slug"):
        val = raw_blob.get(key)
        if val not in (None, ""):
            report_tokens.append(str(val))
    for ref in (raw_blob.get("external_references") or []):
        if not isinstance(ref, dict):
            continue
        ext = ref.get("external_id")
        if ext not in (None, ""):
            report_tokens.append(str(ext))
    seen_tokens: set[str] = set()
    dedup_tokens: list[str] = []
    for tok in report_tokens:
        t = tok.strip()
        if not t or t in seen_tokens:
            continue
        seen_tokens.add(t)
        dedup_tokens.append(t)
    raw_link_join = ""
    raw_link_params: list[str] = []
    if dedup_tokens:
        raw_link_join = " OR (" + " OR ".join("i.raw_stix ILIKE ?" for _ in dedup_tokens) + ")"
        raw_link_params = [f'%"{t}"%' for t in dedup_tokens]
    object_refs_join = (
        f" OR i.stix_id IN ({placeholders}) OR i.id IN ({placeholders})"
        if placeholders else ""
    )
    extra_params = (ref_indicator_ids + ref_indicator_ids) if ref_indicator_ids else []
    ind_rows = conn.execute(
        "SELECT DISTINCT i.id, i.pattern_type, i.observable_value, i.tlp, "
        "       i.confidence, i.last_seen "
        "FROM cti_indicators i "
        "WHERE ("
        "    EXISTS ("
        "      SELECT 1 FROM cti_relationships r "
        "      WHERE r.src_type='report' AND r.src_id = ? "
        "        AND r.dst_type='indicator' AND r.dst_id = i.id"
        "    )"
        f"    {object_refs_join}"
        f"    {raw_link_join}"
        ") "
        f"  AND {ind_clause} "
        "ORDER BY i.last_seen DESC NULLS LAST, i.id",
        [report_id, *extra_params, *raw_link_params, *ind_params],
    ).fetchall()
    out["related_indicators"] = [
        {
            "id": r[0],
            "pattern_type": r[1],
            "observable_value": r[2],
            "tlp": r[3],
            "confidence": r[4],
            "last_seen": r[5],
        }
        for r in ind_rows
    ]

    # Last-resort CrowdStrike lookup: when local ingest has the report
    # and indicators but no join edges yet, ask Falcon for this report's
    # indicator ids and resolve those ids against local cti_indicators.
    if not out["related_indicators"] and db is not None:
        try:
            live_ids = _fetch_crowdstrike_report_indicator_stix_ids_live(
                db, out.get("source_id"), raw_blob,
            )
            if live_ids:
                ph = ",".join("?" * len(live_ids))
                live_rows = conn.execute(
                    "SELECT DISTINCT i.id, i.pattern_type, i.observable_value, i.tlp, "
                    "       i.confidence, i.last_seen "
                    "FROM cti_indicators i "
                    f"WHERE (i.id IN ({ph}) OR i.stix_id IN ({ph})) "
                    f"  AND {ind_clause} "
                    "ORDER BY i.last_seen DESC NULLS LAST, i.id",
                    [*live_ids, *live_ids, *ind_params],
                ).fetchall()
                out["related_indicators"] = [
                    {
                        "id": r[0],
                        "pattern_type": r[1],
                        "observable_value": r[2],
                        "tlp": r[3],
                        "confidence": r[4],
                        "last_seen": r[5],
                    }
                    for r in live_rows
                ]
        except Exception:
            logger.debug(
                "CrowdStrike live indicator fallback failed for report %s",
                report_id,
            )

    # Actors named by this report. Same union strategy: prefer
    # cti_relationships, fall back on the report's object_refs which
    # CrowdStrike populates directly with intrusion-set STIX ids.
    actor_placeholders = ",".join("?" * len(ref_actor_ids)) if ref_actor_ids else None
    actor_object_refs_join = (
        f" OR a.stix_id IN ({actor_placeholders})"
        if actor_placeholders else ""
    )
    actor_extra = ref_actor_ids if ref_actor_ids else []
    actor_rows = conn.execute(
        "SELECT DISTINCT a.stix_type, a.name, a.origin "
        "FROM cti_actors a "
        "WHERE ("
        "    EXISTS ("
        "      SELECT 1 FROM cti_relationships r "
        "      WHERE r.src_type='report' AND r.src_id = ? "
        "        AND r.dst_type IN ('intrusion-set','threat-actor') "
        "        AND (r.dst_id = a.name OR r.dst_id = a.stix_id)"
        "    )"
        f"    {actor_object_refs_join}"
        ") "
        "ORDER BY a.name",
        [report_id, *actor_extra],
    ).fetchall()
    out["related_actors"] = [
        {"stix_type": r[0], "name": r[1], "origin": r[2]} for r in actor_rows
    ]

    # 5.0.x — surface STIX external_references from raw_stix. This
    # column is not part of the normalised schema (it's a vendor-specific
    # blob) so we parse them on demand from the JSON payload the ingest
    # writer already persists. Quiet try/except: a malformed raw_stix
    # should never break the page render.
    external_refs: list[dict] = []
    attachments: list[dict] = []
    try:
        raw_row = conn.execute(
            "SELECT raw_stix FROM cti_reports WHERE id = ?", [report_id],
        ).fetchone()
        if raw_row and raw_row[0]:
            import json as _json
            blob = _json.loads(raw_row[0])
            for ref in (blob.get("external_references") or []):
                if not isinstance(ref, dict):
                    continue
                external_refs.append({
                    "source_name": ref.get("source_name") or "",
                    "url": ref.get("url") or "",
                    "description": ref.get("description") or "",
                    "external_id": ref.get("external_id") or "",
                })
            for idx, f in enumerate(blob.get("x_opencti_files") or []):
                if not isinstance(f, dict):
                    continue
                attachments.append({
                    "index": idx,
                    "name": f.get("name") or f"attachment-{idx}",
                    "mime_type": f.get("mime_type") or "application/octet-stream",
                    "has_data": bool(f.get("data")),
                })
    except Exception:
        logger.exception("Failed to parse raw_stix for report %s", report_id)
    # OpenCTI TAXII commonly omits file blobs from report objects.
    # 5.0.x: we no longer fall back to a live OpenCTI GraphQL fetch on
    # render — those calls were the dominant cause of 30-40s page hangs
    # when the OpenCTI host was unreachable or slow. Operators that need
    # OpenCTI-hosted file metadata should ingest it during sync rather
    # than re-query it per pageview.
    # CrowdStrike reports never carry the PDF bytes inline — Falcon
    # serves them via /intel/entities/report-files/v1. Surface a single
    # synthetic attachment entry so the report page exposes a viewer;
    # the actual bytes are fetched lazily in report_attachment().
    if not attachments and db is not None:
        try:
            cs_cfg = _crowdstrike_connector_config(db, out.get("source_id"))
            if cs_cfg:
                blob_for_ids: dict = {}
                try:
                    import json as _json
                    raw_row = conn.execute(
                        "SELECT raw_stix FROM cti_reports WHERE id = ?",
                        [report_id],
                    ).fetchone()
                    if raw_row and raw_row[0]:
                        blob_for_ids = _json.loads(raw_row[0]) or {}
                except Exception:
                    blob_for_ids = {}
                cs_ids = _crowdstrike_report_ids(blob_for_ids)
                if cs_ids:
                    attachments.append({
                        "index": 0,
                        "name": f"{cs_ids[0]}.pdf",
                        "mime_type": "application/pdf",
                        "has_data": True,
                    })
        except Exception:
            logger.debug("CrowdStrike attachment synth failed for %s", report_id)
    out["external_references"] = external_refs
    out["attachments"] = attachments

    return out


# ── Page routes ──────────────────────────────────────────────────────


def _render(request: Request, name: str, ctx: dict) -> HTMLResponse:
    """Render a page template using the shared Jinja2 instance.

    Prefers ``app.state.render_template`` (set in :mod:`app.main`) so the
    rendered page picks up ``active_client``, ``user_clients`` and
    ``space_labels`` for the sidebar / client switcher. Falls back to a
    direct TemplateResponse for unit-test contexts where the helper is
    not installed.
    """
    render = getattr(request.app.state, "render_template", None)
    if render is not None:
        return render(name, request, ctx)
    templates = request.app.state.templates
    return templates.TemplateResponse(request, name, ctx)


def _resolve_source_labels(db, rows: Iterable[dict]) -> dict[str, str]:
    """Map ingest ``source_id`` strings to human-friendly connector labels.

    Rows ingested via the OpenCTI / multi-vendor connector path store
    ``source_id = "connector:<uuid>"`` (see
    :mod:`app.services.cti_connectors.opencti_taxii`). Showing the raw UUID in
    the indicators / reports tables is unreadable. We collect every
    distinct ``source_id`` once per page render, parse the connector UUIDs
    out, and look up the friendly ``label`` from the global
    ``cti_connectors`` table via :meth:`DatabaseService.get_cti_connector`.
    Unknown or non-connector source_ids fall through to the raw value so
    legacy ingest paths (e.g. ``"OCTI"``) still render readably.
    """
    out: dict[str, str] = {}
    for row in rows or ():
        sid = (row.get("source_id") or "").strip()
        if not sid or sid in out:
            continue
        if sid.startswith("connector:"):
            cid = sid.split(":", 1)[1].strip()
            conn = None
            if cid:
                try:
                    conn = db.get_cti_connector(cid)
                except Exception:
                    logger.debug("connector lookup failed for source_id=%s", sid)
            if conn:
                # Prefer the operator-supplied label; fall back to the
                # vendor name so the UI never has to render the raw UUID.
                label = (conn.get("label") or conn.get("vendor") or "").strip()
                if label:
                    out[sid] = label
                    continue
            # Unknown / orphaned connector: hide the UUID. After the
            # 5.0.0 GraphQL retirement the most common cause is that
            # the operator deleted a connector and the indicator rows
            # it ingested still carry its UUID. Surface a stable
            # "Retired connector" label so the UI never shows a UUID.
            out[sid] = "Retired connector"
            continue
        if sid.startswith("opencti:"):
            # Legacy GraphQL ingest path (pre-5.0.0) wrote
            # ``source_id = f"opencti:{opencti_inventory.id}"``. The
            # source tables are gone post-migration 50, so we can no
            # longer resolve the original instance label — just show
            # the operator that this row came from the retired path.
            out[sid] = "OpenCTI (legacy)"
            continue
        out[sid] = sid
    return out


@router.get("/indicators", response_class=HTMLResponse, name="cti_indicators")
def indicators_page(
    request: Request,
    user: RequireUser,
    client_id: ActiveClient,
    scope: TlpScopeDep,
    db: DbDep,
    search: Optional[str] = Query(None),
    pattern_type: Optional[str] = Query(None),
    tlp: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
):
    offset = (page - 1) * page_size
    with open_cti_db(client_id) as conn:
        clause, base_params = tlp_filter_clause(scope)

        # Whole-tenant rollups (independent of pagination + column
        # filters) so the metric strip and the filter dropdowns reflect
        # what is *available* under the operator's TLP ceiling, not
        # just what survived the current filter combo.
        type_rows = conn.execute(
            f"SELECT COALESCE(pattern_type, 'unknown') AS pt, COUNT(*) "
            f"FROM cti_indicators WHERE {clause} GROUP BY pt ORDER BY 2 DESC",
            list(base_params),
        ).fetchall()
        tlp_rows = conn.execute(
            f"SELECT COALESCE(tlp, 'unlabelled') AS t, COUNT(*) "
            f"FROM cti_indicators WHERE {clause} GROUP BY t ORDER BY 2 DESC",
            list(base_params),
        ).fetchall()
        source_rows = conn.execute(
            f"SELECT DISTINCT source_id FROM cti_indicators "
            f"WHERE {clause} AND source_id IS NOT NULL AND source_id <> '' "
            f"ORDER BY source_id",
            list(base_params),
        ).fetchall()

        # Listing query with the new per-column filters applied.
        where = [clause]
        params = list(base_params)
        if search:
            where.append("(observable_value ILIKE ? OR pattern_type ILIKE ?)")
            like = f"%{search}%"
            params.extend([like, like])
        if pattern_type:
            where.append("pattern_type = ?")
            params.append(pattern_type)
        if tlp:
            where.append("COALESCE(tlp, 'unlabelled') = ?")
            params.append(tlp)
        if source:
            where.append("source_id = ?")
            params.append(source)
        sql = (
            f"SELECT {', '.join(_INDICATOR_COLS)} FROM cti_indicators "
            f"WHERE {' AND '.join(where)} "
            f"ORDER BY last_seen DESC NULLS LAST, id LIMIT ? OFFSET ?"
        )
        params.extend([int(page_size), int(offset)])
        rows = conn.execute(sql, params).fetchall()
        indicators = [_row_to_dict(_INDICATOR_COLS, r) for r in rows]

    type_counts = [(r[0], int(r[1])) for r in type_rows]
    tlp_counts = [(r[0], int(r[1])) for r in tlp_rows]
    sources_all = [r[0] for r in source_rows]
    total_indicators = sum(c for _, c in type_counts)
    label_input = list(indicators) + [{"source_id": s} for s in sources_all]
    source_labels = _resolve_source_labels(db, label_input)
    return _render(
        request,
        "pages/cti/indicators.html",
        {
            "user": user,
            "active_page": "cti",
            "active_sub": "indicators",
            "indicators": indicators,
            "source_labels": source_labels,
            "type_counts": type_counts,
            "tlp_counts": tlp_counts,
            "pattern_types": [t for t, _ in type_counts],
            "tlp_values": [t for t, _ in tlp_counts],
            "sources": sources_all,
            "selected_pattern_type": pattern_type or "",
            "selected_tlp": tlp or "",
            "selected_source": source or "",
            "total_indicators": total_indicators,
            "search": search or "",
            "page": page,
            "page_size": page_size,
            "tlp_ceiling": scope.ceiling,
        },
    )


@router.get(
    "/indicators/{indicator_id:path}",
    response_class=HTMLResponse,
    name="cti_indicator_detail",
)
def indicator_detail_page(
    request: Request,
    indicator_id: str,
    user: RequireUser,
    client_id: ActiveClient,
    scope: TlpScopeDep,
    db: DbDep,
):
    with open_cti_db(client_id) as conn:
        indicator = query_indicator(conn, scope, indicator_id)
    if indicator is None:
        # 404 whether the row genuinely does not exist or the TLP
        # ceiling hides it — see ``query_indicator`` rationale.
        raise HTTPException(status_code=404, detail="Indicator not found")
    source_labels = _resolve_source_labels(db, [indicator])
    return _render(
        request,
        "pages/cti/indicator_detail.html",
        {
            "user": user,
            "active_page": "cti",
            "active_sub": "indicators",
            "indicator": indicator,
            "source_labels": source_labels,
            "tlp_ceiling": scope.ceiling,
        },
    )


@router.get("/actors", response_class=HTMLResponse, name="cti_actors")
def actors_page(
    request: Request,
    user: RequireUser,
    client_id: ActiveClient,
    scope: TlpScopeDep,
    db: DbDep,
    search: Optional[str] = Query(None),
    stix_type: Optional[str] = Query(None),
    origin: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
):
    offset = (page - 1) * page_size
    with open_cti_db(client_id) as conn:
        # Whole-tenant rollups for the metrics strip (independent of
        # pagination so the cards reflect total holdings, not the
        # current page).
        total_actors = conn.execute(
            "SELECT COUNT(*) FROM cti_actors"
        ).fetchone()[0]
        type_rows = conn.execute(
            "SELECT stix_type, COUNT(*) FROM cti_actors "
            "GROUP BY stix_type ORDER BY 2 DESC"
        ).fetchall()
        origins_all = [
            r[0] for r in conn.execute(
                "SELECT DISTINCT origin FROM cti_actors "
                "WHERE origin IS NOT NULL AND origin <> '' "
                "ORDER BY origin"
            ).fetchall()
        ]
        sources_all = [
            r[0] for r in conn.execute(
                "SELECT DISTINCT source_id FROM cti_actors "
                "WHERE source_id IS NOT NULL AND source_id <> '' "
                "ORDER BY source_id"
            ).fetchall()
        ]
        with_aliases = conn.execute(
            "SELECT COUNT(*) FROM cti_actors "
            "WHERE aliases IS NOT NULL AND length(aliases) > 0"
        ).fetchone()[0]
        linked_actors = conn.execute(
            "SELECT COUNT(DISTINCT a.name) FROM cti_actors a "
            "JOIN cti_relationships r "
            "  ON r.dst_type = a.stix_type AND r.dst_id = a.name "
            "WHERE r.src_type = 'indicator' "
            "  AND r.rel_type = 'indicates'"
        ).fetchone()[0]

        # Build the filtered listing in-line so we can honour the new
        # column-header filters without bloating the query helper
        # signature (the helper still drives the smoke test).
        where = []
        params: list = []
        if search:
            where.append("(name ILIKE ? OR description ILIKE ?)")
            like = f"%{search}%"
            params.extend([like, like])
        if stix_type:
            where.append("stix_type = ?")
            params.append(stix_type)
        if origin:
            where.append("origin = ?")
            params.append(origin)
        if source:
            where.append("source_id = ?")
            params.append(source)
        sql = f"SELECT {', '.join(_ACTOR_COLS)} FROM cti_actors"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY name LIMIT ? OFFSET ?"
        params.extend([int(page_size), int(offset)])
        rows = conn.execute(sql, params).fetchall()
        actors = [_row_to_dict(_ACTOR_COLS, r) for r in rows]

    # Source labels span both the visible rows and the filter dropdown
    # so the operator never sees a raw connector UUID anywhere.
    label_rows = list(actors) + [{"source_id": s} for s in sources_all]
    source_labels = _resolve_source_labels(db, label_rows)
    type_counts = [(r[0], int(r[1])) for r in type_rows]
    intrusion_sets = next(
        (n for t, n in type_counts if t == "intrusion-set"), 0
    )
    threat_actors = next(
        (n for t, n in type_counts if t == "threat-actor"), 0
    )
    return _render(
        request,
        "pages/cti/actors.html",
        {
            "user": user,
            "active_page": "cti",
            "active_sub": "actors",
            "actors": actors,
            "source_labels": source_labels,
            "search": search or "",
            "selected_stix_type": stix_type or "",
            "selected_origin": origin or "",
            "selected_source": source or "",
            "stix_types": [t for t, _ in type_counts],
            "origins": origins_all,
            "sources": sources_all,
            "metrics": {
                "total": total_actors,
                "intrusion_sets": intrusion_sets,
                "threat_actors": threat_actors,
                "origins": len(origins_all),
                "with_aliases": with_aliases,
                "linked": linked_actors,
            },
            "page": page,
            "page_size": page_size,
            "tlp_ceiling": scope.ceiling,
        },
    )


@router.get(
    "/actors/{name:path}",
    response_class=HTMLResponse,
    name="cti_actor_detail",
)
def actor_detail_page(
    request: Request,
    name: str,
    user: RequireUser,
    client_id: ActiveClient,
    scope: TlpScopeDep,
    db: DbDep,
    stix_type: Optional[str] = Query(None),
):
    with open_cti_db(client_id) as conn:
        actor = query_actor(conn, scope, name, stix_type=stix_type)
    if actor is None:
        raise HTTPException(status_code=404, detail="Actor not found")
    source_labels = _resolve_source_labels(db, [actor])
    return _render(
        request,
        "pages/cti/actor_detail.html",
        {
            "user": user,
            "active_page": "cti",
            "active_sub": "actors",
            "actor": actor,
            "source_labels": source_labels,
            "tlp_ceiling": scope.ceiling,
        },
    )


@router.get("/reports", response_class=HTMLResponse, name="cti_reports")
def reports_page(
    request: Request,
    user: RequireUser,
    client_id: ActiveClient,
    scope: TlpScopeDep,
    db: DbDep,
    search: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    label: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
):
    offset = (page - 1) * page_size
    with open_cti_db(client_id) as conn:
        # Whole-tenant rollups for the metric strip.
        total_reports = conn.execute(
            "SELECT COUNT(*) FROM cti_reports"
        ).fetchone()[0]
        with_description = conn.execute(
            "SELECT COUNT(*) FROM cti_reports "
            "WHERE description IS NOT NULL AND description <> ''"
        ).fetchone()[0]
        recent_30d = conn.execute(
            "SELECT COUNT(*) FROM cti_reports "
            "WHERE published IS NOT NULL "
            "  AND TRY_CAST(published AS TIMESTAMP) >= now() - INTERVAL 30 DAY"
        ).fetchone()[0]
        sources_all = [
            r[0] for r in conn.execute(
                "SELECT DISTINCT source_id FROM cti_reports "
                "WHERE source_id IS NOT NULL AND source_id <> '' "
                "ORDER BY source_id"
            ).fetchall()
        ]
        # Flatten the LIST(VARCHAR) labels column for a distinct count
        # and a filter dropdown of the top labels seen across the tenant.
        label_rows = conn.execute(
            "SELECT lbl, COUNT(*) FROM ("
            "  SELECT UNNEST(labels) AS lbl FROM cti_reports "
            "  WHERE labels IS NOT NULL"
            ") WHERE lbl IS NOT NULL AND lbl <> '' "
            "GROUP BY lbl ORDER BY 2 DESC, lbl LIMIT 100"
        ).fetchall()
        all_labels = [r[0] for r in label_rows]
        linked_indicators = conn.execute(
            "SELECT COUNT(DISTINCT src_id) FROM cti_relationships "
            "WHERE src_type = 'report' AND dst_type = 'indicator'"
        ).fetchone()[0]
        linked_actors = conn.execute(
            "SELECT COUNT(DISTINCT src_id) FROM cti_relationships "
            "WHERE src_type = 'report' "
            "  AND dst_type IN ('intrusion-set', 'threat-actor')"
        ).fetchone()[0]

        where = []
        params: list = []
        if search:
            where.append("(name ILIKE ? OR description ILIKE ?)")
            like = f"%{search}%"
            params.extend([like, like])
        if source:
            where.append("source_id = ?")
            params.append(source)
        if label:
            where.append("list_contains(labels, ?)")
            params.append(label)
        sql = f"SELECT {', '.join(_REPORT_COLS)} FROM cti_reports"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY published DESC NULLS LAST, id LIMIT ? OFFSET ?"
        params.extend([int(page_size), int(offset)])
        rows = conn.execute(sql, params).fetchall()
        reports = [_row_to_dict(_REPORT_COLS, r) for r in rows]

    label_input_rows = list(reports) + [{"source_id": s} for s in sources_all]
    source_labels = _resolve_source_labels(db, label_input_rows)
    return _render(
        request,
        "pages/cti/reports.html",
        {
            "user": user,
            "active_page": "cti",
            "active_sub": "reports",
            "reports": reports,
            "source_labels": source_labels,
            "search": search or "",
            "selected_source": source or "",
            "selected_label": label or "",
            "sources": sources_all,
            "all_labels": all_labels,
            "metrics": {
                "total": total_reports,
                "sources": len(sources_all),
                "labels": len(all_labels),
                "with_description": with_description,
                "recent_30d": recent_30d,
                "linked_indicators": linked_indicators,
                "linked_actors": linked_actors,
            },
            "page": page,
            "page_size": page_size,
            "tlp_ceiling": scope.ceiling,
        },
    )


@router.get(
    "/reports/{report_id}",
    response_class=HTMLResponse,
    name="cti_report_detail",
)
def report_detail_page(
    request: Request,
    report_id: str,
    user: RequireUser,
    client_id: ActiveClient,
    scope: TlpScopeDep,
    db: DbDep,
):
    with open_cti_db(client_id) as conn:
        report = query_report(conn, scope, report_id, db=db)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    source_labels = _resolve_source_labels(db, [report])
    return _render(
        request,
        "pages/cti/report_detail.html",
        {
            "user": user,
            "active_page": "cti",
            "active_sub": "reports",
            "report": report,
            "source_labels": source_labels,
            "tlp_ceiling": scope.ceiling,
        },
    )


# ────────────────────────────────────────────────────────────────────
# Report attachment download — decodes the base64 file blobs OpenCTI
# embeds inside ``raw_stix.x_opencti_files`` and streams them back to
# the browser with the right MIME type so PDFs render inline in the
# browser's native viewer and other types prompt a save. No PDF.js
# bundle required — every supported browser (Chrome / Edge / Firefox /
# Safari) ships a built-in PDF viewer.
# ────────────────────────────────────────────────────────────────────


@router.get(
    "/reports/{report_id}/attachments/{idx}",
    name="cti_report_attachment",
)
def report_attachment(
    report_id: str,
    idx: int,
    user: RequireUser,
    client_id: ActiveClient,
    db: DbDep,
):
    """Stream an attachment from a report's raw_stix.x_opencti_files."""
    from fastapi.responses import Response
    import base64
    import json as _json

    with open_cti_db(client_id) as conn:
        row = conn.execute(
            "SELECT source_id, raw_stix, pdf_blob, pdf_mime, pdf_filename "
            "FROM cti_reports WHERE id = ?",
            [report_id],
        ).fetchone()
    if not row or not row[1]:
        raise HTTPException(status_code=404, detail="Report not found")
    source_id = row[0]
    # 5.0.0: serve the cached blob if we already have it. Caching every
    # attachment fetch means a re-render of the same report doesn't hit
    # Falcon / OpenCTI again, which was triggering rate limits and
    # multi-minute waits per page load.
    cached_blob, cached_mime, cached_name = row[2], row[3], row[4]
    if cached_blob is not None and idx == 0:
        safe_name = (cached_name or f"{report_id}.pdf").replace('"', "")
        return Response(
            content=bytes(cached_blob),
            media_type=cached_mime or "application/pdf",
            headers={
                "Content-Disposition": f'inline; filename="{safe_name}"',
                "X-Content-Type-Options": "nosniff",
            },
        )
    try:
        blob = _json.loads(row[1])
    except Exception:
        raise HTTPException(status_code=404, detail="Report payload unreadable")
    files = blob.get("x_opencti_files") or []
    # 5.0.x: do not perform live OpenCTI GraphQL fetches during render.
    # We only use file metadata already present in raw_stix.
    # CrowdStrike fallback: no inline files, fetch the PDF live from
    # Falcon's report-files endpoint using whatever id we can extract.
    if (not files or idx >= len(files)) and source_id:
        cs_cfg = _crowdstrike_connector_config(db, source_id)
        if cs_cfg:
            from app.services.cti_connectors.crowdstrike_taxii import (
                download_report_pdf,
            )
            last_err: Exception | None = None
            for rid in _crowdstrike_report_ids(blob):
                try:
                    result = download_report_pdf(cs_cfg, rid)
                except Exception as exc:  # noqa: BLE001
                    last_err = exc
                    continue
                if result is None:
                    continue
                data, mime, filename = result
                safe_name = filename.replace('"', "")
                # Persist the bytes for future requests so we never hit
                # Falcon for the same PDF twice.
                try:
                    with open_cti_db(client_id) as wconn:
                        wconn.execute(
                            "UPDATE cti_reports SET "
                            "pdf_blob = ?, pdf_mime = ?, pdf_filename = ?, "
                            "pdf_fetched_at = CURRENT_TIMESTAMP "
                            "WHERE id = ?",
                            [data, mime, filename, report_id],
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Failed to cache PDF for %s: %s", report_id, exc,
                    )
                return Response(
                    content=data,
                    media_type=mime,
                    headers={
                        "Content-Disposition": f'inline; filename="{safe_name}"',
                        "X-Content-Type-Options": "nosniff",
                    },
                )
            if last_err is not None:
                logger.warning(
                    "CrowdStrike report-files download failed for %s: %s",
                    report_id, last_err,
                )
    if idx < 0 or idx >= len(files):
        raise HTTPException(status_code=404, detail="Attachment not found")
    f = files[idx]
    if not isinstance(f, dict):
        raise HTTPException(status_code=404, detail="Attachment has no data")

    data: bytes | None = None
    mime = f.get("mime_type") or f.get("mimeType") or "application/octet-stream"
    if f.get("data"):
        try:
            data = base64.b64decode(f["data"])
        except Exception:
            raise HTTPException(status_code=400, detail="Attachment is not valid base64")
    else:
        file_id = f.get("id") or f.get("file_id")
        if file_id:
            data, live_mime = _download_opencti_file_live(db, source_id, file_id)
            if live_mime:
                mime = live_mime
    if not data:
        raise HTTPException(status_code=404, detail="Attachment has no data")

    name = f.get("name") or f"attachment-{idx}"
    safe_name = name.replace('"', "")
    return Response(
        content=data,
        media_type=mime,
        headers={
            "Content-Disposition": f'inline; filename="{safe_name}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


# ────────────────────────────────────────────────────────────────────
# Per-page sync + counts (consistent action cluster: Check connection
# · Sync · Last sync). Each /cti/{kind}/sync iterates the new
# ``cti_connectors`` framework — every connector linked to the active
# tenant is run end-to-end (a TAXII 2.1 pull is collection-level and
# can't be filtered per-SDO on the wire, so the page-specific button
# is now just a friendly trigger that surfaces the slice of the
# resulting SyncResult relevant to that page).
# ────────────────────────────────────────────────────────────────────


def _esc(s: object) -> str:
    import html as _h
    return _h.escape(str(s or ""))


def _render_job_fragment(job: dict, kind_label: str) -> str:
    """Return the HTMX fragment that represents ``job`` at its current state.

    Running jobs re-emit a span that polls itself every 2 s; terminal
    jobs render a final badge that breaks the polling loop (no
    ``hx-trigger`` on the outermost element). The outer element id
    stays stable across polls so HTMX's ``outerHTML`` swap finds the
    same anchor.
    """
    job_id = job.get("id") or ""
    status = job.get("status") or ""
    label = job.get("label") or ""
    target_id = f"cti-sync-job-{job_id}"
    poll_attrs = (
        f'id="{target_id}" '
        f'hx-get="/cti/sync/jobs/{job_id}?kind={_esc(kind_label)}" '
        f'hx-trigger="every 2s" '
        f'hx-swap="outerHTML"'
    )

    if status in ("pending", "running"):
        body = (
            f'<span {poll_attrs} class="badge badge-info">'
            f'\u2026 syncing {_esc(label) or kind_label}</span>'
        )
        return body

    if status == "failed":
        err = job.get("error") or "unknown error"
        return (
            f'<span id="{target_id}" class="badge badge-danger">'
            f'Sync failed \u2014 {_esc(err[:200])}</span>'
        )

    # Success.
    summary = job.get("summary") or {}
    if not isinstance(summary, dict):
        summary = {}

    def _i(key: str) -> int:
        try:
            return int(summary.get(key, 0) or 0)
        except Exception:
            return 0

    err_count = len(summary.get("errors") or [])
    cls = "badge-success" if err_count == 0 else "badge-warning"
    if kind_label == "indicators":
        body = (
            f"+{_i('indicators_new')} new / "
            f"~{_i('indicators_merged')} merged / "
            f"?{_i('indicators_review')} review"
        )
    elif kind_label == "actors":
        body = f"{_i('intrusion_sets') + _i('actors')} actor(s)"
    elif kind_label == "reports":
        body = f"{_i('reports')} report(s)"
    else:
        body = "synced"
    err_suffix = f" &middot; {err_count} error(s)" if err_count else ""
    return (
        f'<span id="{target_id}" class="badge {cls}">'
        f'{body}{err_suffix}</span>'
    )


def _build_kind_runner(client_id: str, kind_label: str):
    """Return a zero-arg callable that performs the per-tenant sync.

    Captured by the job thread; the closure deliberately re-resolves
    the connector list at run-time (not submit-time) so an operator
    who links/unlinks a connector between clicking Sync and the job
    starting still gets the up-to-date fan-out.
    """
    def _runner():
        from app.services.database import get_database_service
        from app.services.cti_connectors import get as get_vendor

        db = get_database_service()
        linked_connectors: list[dict] = []
        for conn_row in db.list_cti_connectors(only_active=True) or []:
            members = db.get_cti_connector_clients(conn_row["id"]) or []
            if any((m.get("id") == client_id) for m in members):
                linked_connectors.append(conn_row)

        totals: dict[str, Any] = {
            "indicators_new": 0, "indicators_merged": 0,
            "indicators_review": 0, "intrusion_sets": 0,
            "actors": 0, "reports": 0, "relationships": 0,
            "connectors": 0, "errors": [],
        }
        if not linked_connectors:
            totals["errors"].append(
                "No CTI connector linked to this client"
            )
            return totals

        for conn_row in linked_connectors:
            vendor = get_vendor(conn_row.get("vendor") or "")
            if vendor is None or vendor.fetcher is None:
                totals["errors"].append(
                    f"{conn_row.get('label') or conn_row.get('id')}: "
                    f"vendor '{conn_row.get('vendor')}' is not registered"
                )
                continue
            single_client = [
                m for m in (db.get_cti_connector_clients(conn_row["id"]) or [])
                if m.get("id") == client_id
            ]
            try:
                result = vendor.fetcher(conn_row, single_client)
            except Exception as exc:
                logger.error(
                    "CTI connector sync failed (%s, %s): %s",
                    kind_label, conn_row.get("id"), exc, exc_info=True,
                )
                totals["errors"].append(
                    f"{conn_row.get('label')}: {exc}"
                )
                continue
            totals["connectors"] += 1
            summary = (
                result.as_dict() if hasattr(result, "as_dict")
                else (result or {})
            )
            for k in (
                "indicators_new", "indicators_merged", "indicators_review",
                "intrusion_sets", "actors", "reports", "relationships",
            ):
                totals[k] += int(summary.get(k, 0) or 0)
            totals["errors"].extend(summary.get("errors", []) or [])
        return totals

    return _runner


def _start_sync_job(
    client_id: str,
    kind_label: str,
) -> HTMLResponse:
    """Submit a background sync job and return the polling fragment.

    Replaces the synchronous per-page fan-out so the operator's HTMX
    request returns immediately and the badge polls itself for the
    terminal state. Heavy fetchers (OpenCTI bundles north of a million
    objects) no longer hold a worker thread for the duration of the
    pull and can't be killed by an upstream nginx timeout.
    """
    from app.services import cti_jobs

    runner = _build_kind_runner(client_id, kind_label)
    job_id = cti_jobs.submit(
        kind=kind_label, runner=runner, label=kind_label, client_id=client_id,
    )
    job = cti_jobs.get(job_id) or {"id": job_id, "status": "pending"}
    return HTMLResponse(_render_job_fragment(job, kind_label))


@router.post("/indicators/sync", response_class=HTMLResponse, name="cti_indicators_sync")
def cti_indicators_sync(
    request: Request,
    user: RequireAdmin,
    client_id: ActiveClient,
):
    return _start_sync_job(client_id, "indicators")


@router.post("/actors/sync", response_class=HTMLResponse, name="cti_actors_sync")
def cti_actors_sync(
    request: Request,
    user: RequireAdmin,
    client_id: ActiveClient,
):
    return _start_sync_job(client_id, "actors")


@router.post("/reports/sync", response_class=HTMLResponse, name="cti_reports_sync")
def cti_reports_sync(
    request: Request,
    user: RequireAdmin,
    client_id: ActiveClient,
):
    return _start_sync_job(client_id, "reports")


@router.get(
    "/sync/jobs/{job_id}",
    response_class=HTMLResponse,
    name="cti_sync_job_status",
)
def cti_sync_job_status(
    request: Request,
    job_id: str,
    user: RequireUser,
    kind: str = Query("", max_length=32),
):
    """HTMX polling target for an in-flight CTI sync job.

    Returns the same fragment shape as :func:`_start_sync_job`: a
    self-polling span while the job is in flight, or a terminal badge
    once it succeeds or fails. The ``kind`` query parameter is
    optional and only changes how the terminal summary string is
    formatted; the underlying job status is authoritative.
    """
    from app.services import cti_jobs

    job = cti_jobs.get(job_id)
    if job is None:
        # Job evicted from the retention window (or never existed).
        # Render a terminal fragment so the polling loop ends.
        return HTMLResponse(
            f'<span id="cti-sync-job-{_esc(job_id)}" class="badge badge-warning">'
            f'Job no longer tracked &mdash; refresh the page to see current state.'
            f'</span>'
        )
    return HTMLResponse(_render_job_fragment(job, kind or job.get("kind") or ""))


@router.get("/counts", response_class=HTMLResponse, name="cti_counts")
def cti_counts(
    request: Request,
    user: RequireUser,
    client_id: ActiveClient,
):
    """Report the per-kind counts currently stored for this tenant.

    The pre-5.0.0 implementation called the OpenCTI GraphQL ``fetch_counts``
    helper to show *upstream* totals on the Check Connection button.
    With GraphQL retired we report the LOCAL counts the operator just
    pulled — that's the number that actually matters for the surface
    they're looking at, and it works for every TAXII vendor.
    """
    from app.services.database import get_database_service
    from app.services import cti_database as _cti_db

    db = get_database_service()
    linked = []
    for conn_row in db.list_cti_connectors(only_active=True) or []:
        members = db.get_cti_connector_clients(conn_row["id"]) or []
        if any((m.get("id") == client_id) for m in members):
            linked.append(conn_row)
    if not linked:
        return HTMLResponse(
            '<span class="text-secondary">No CTI connector linked.</span>'
        )
    try:
        stats = _cti_db.cti_db_stats(client_id) or {}
        ind_n = stats.get("indicators")
        act_n = stats.get("actors")
        rep_n = stats.get("reports")
    except Exception as exc:
        logger.warning("cti_counts read failed for %s: %s", client_id, exc)
        return HTMLResponse(
            f'<span class="badge badge-warning">Counts unavailable: '
            f'{_esc(str(exc)[:120])}</span>'
        )

    def _fmt(n: Optional[int]) -> str:
        return f"{n:,}" if n is not None else "n/a"

    names = ", ".join(_esc(c.get("label") or c.get("vendor")) for c in linked)
    return HTMLResponse(
        f'<span class="badge badge-info" title="{names}">'
        f'actors {_fmt(act_n)} &middot; '
        f'indicators {_fmt(ind_n)} &middot; '
        f'reports {_fmt(rep_n)}'
        f'</span>'
    )



__all__ = [
    "router",
    "query_indicators",
    "query_indicator",
    "query_actors",
    "query_actor",
    "query_reports",
    "query_report",
]
