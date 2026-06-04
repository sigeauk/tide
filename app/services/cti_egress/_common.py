"""Shared helpers for the CTI egress drivers.

Anything reused by more than one driver lives here so the driver
modules stay focused on their wire format / transport.

The constants and functions in this module are intentionally
module-private (leading underscore) — drivers reach in directly because
they're part of the same package. External callers should go through
:mod:`app.services.cti_egress` (the package facade).
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.services import cti_database
from app.services.database import get_database_service

logger = logging.getLogger(__name__)

# Index names. The "latest" index is a single rollover-style snapshot
# of every active indicator; the dated indices are the audit trail.
LATEST_INDEX = "logs-ti_tide_latest"
HISTORY_PREFIX = "logs-ti_tide.indicator-"

# TLP ordering (lower = more restrictive). An indicator is exported
# only if ``tlp_rank(indicator) <= tlp_rank(target.tlp_ceiling)``.
# ``None`` / unknown TLP is treated as ``amber`` so unlabelled
# indicators don't accidentally leave the tenant via a ``green``
# ceiling.
_TLP_ORDER = {"clear": 4, "white": 4, "green": 3, "amber": 2, "red": 1}

# Per-_bulk request indicator count. Each indicator produces TWO bulk
# action+source lines (one for ``_latest``, one for the dated index)
# so the wire-level batch size is 4 * BATCH_SIZE NDJSON lines.
BATCH_SIZE = 500


def _tlp_rank(tlp: Optional[str]) -> int:
    """Map a TLP string to a numeric rank (higher = less restrictive)."""
    if not tlp:
        return _TLP_ORDER["amber"]
    return _TLP_ORDER.get(str(tlp).strip().lower(), _TLP_ORDER["amber"])


def _doc_id(pattern_type: str, observable_value: str) -> str:
    """Deterministic ``_id`` for upsert behaviour across re-exports."""
    h = hashlib.md5()
    h.update(f"{pattern_type}|{observable_value}".encode("utf-8"))
    return h.hexdigest()


def _iso(value: Any) -> Optional[str]:
    """Return an ISO-8601 UTC string for a DuckDB timestamp / None."""
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return (
            value.astimezone(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
    if isinstance(value, str):
        return value
    return str(value)


def _history_index_for(now: Optional[datetime] = None) -> str:
    """Daily history index name ``logs-ti_tide.indicator-YYYY.MM.DD``."""
    when = (now or datetime.utcnow()).date()
    return f"{HISTORY_PREFIX}{when:%Y.%m.%d}"


def _build_doc(row: Dict[str, Any], client_id: str,
               target_label: str, target_id: str) -> Dict[str, Any]:
    """Build the ECS-leaning JSON document for one indicator row.

    Shared between drivers so the on-wire shape is consistent whether
    the indicator lands in Elasticsearch, a STIX bundle on disk, or a
    diode outbox.
    """
    now_iso = _iso(datetime.utcnow())
    actors = row.get("actors") or []
    kill_chain = row.get("kill_chain")
    if isinstance(kill_chain, str):
        try:
            kill_chain = json.loads(kill_chain) if kill_chain else None
        except json.JSONDecodeError:
            kill_chain = None
    raw_stix = row.get("raw_stix")
    if isinstance(raw_stix, str):
        try:
            raw_stix = json.loads(raw_stix) if raw_stix else None
        except json.JSONDecodeError:
            raw_stix = None

    doc: Dict[str, Any] = {
        "@timestamp": now_iso,
        "event": {
            "kind": "enrichment",
            "category": ["threat"],
            "type": ["indicator"],
            "module": "tide_cti",
            "dataset": "tide.cti.indicator",
            "ingested": now_iso,
        },
        "tide": {
            "client_id": client_id,
            "egress_target_id": target_id,
            "egress_target_label": target_label,
            "indicator_id": row.get("id"),
            "needs_review": bool(row.get("needs_review")),
            "source_id": row.get("source_id"),
        },
        "threat": {
            "indicator": {
                "type": row.get("pattern_type"),
                "ioc_value": row.get("observable_value"),
                "pattern": row.get("pattern"),
                "confidence": row.get("confidence"),
                "first_seen": _iso(row.get("first_seen")),
                "last_seen": _iso(row.get("last_seen")),
                "modified_at": _iso(row.get("last_seen")),
                "marking": {"tlp": row.get("tlp")},
            },
        },
    }

    valid_from = _iso(row.get("valid_from"))
    valid_until = _iso(row.get("valid_until"))
    if valid_from:
        doc["threat"]["indicator"]["valid_from"] = valid_from
    if valid_until:
        doc["threat"]["indicator"]["valid_until"] = valid_until

    if actors:
        doc["threat"]["group"] = [{"name": a} for a in actors]
    if kill_chain:
        doc["threat"]["indicator"]["kill_chain_phases"] = kill_chain
    mitre = row.get("mitre_techniques") or []
    if mitre:
        doc["threat"]["technique"] = [{"id": t} for t in mitre]
        doc["tide"]["mitre_techniques"] = list(mitre)
    if raw_stix:
        doc["stix"] = raw_stix
    return doc


def _load_indicators(client_id: str, *,
                     tlp_ceiling: str = "amber",
                     include_review: bool = False) -> List[Dict[str, Any]]:
    """Return the indicators to export for one tenant.

    ``needs_review`` rows are excluded by default so we never ship a
    half-resolved indicator. The TLP ceiling is applied in Python so
    the rank ordering lives in one place. Actor names are aggregated
    from ``cti_relationships`` (``indicator --indicates--> actor``)
    introduced in schema v3.
    """
    sql = (
        "SELECT i.id, i.pattern_type, i.observable_value, i.pattern, "
        "i.valid_from, i.valid_until, i.tlp, i.confidence, i.source_id, "
        "i.first_seen, i.last_seen, i.kill_chain, i.mitre_techniques, "
        "i.raw_stix, i.needs_review, "
        "COALESCE(list(r.dst_id) FILTER (WHERE r.dst_id IS NOT NULL), "
        "         []) AS actors "
        "FROM cti_indicators i "
        "LEFT JOIN cti_relationships r "
        "  ON r.src_type = 'indicator' "
        " AND r.src_id   = i.id "
        " AND r.rel_type = 'indicates' "
        " AND r.dst_type IN ('intrusion-set','threat-actor') "
        "GROUP BY i.id, i.pattern_type, i.observable_value, i.pattern, "
        "         i.valid_from, i.valid_until, i.tlp, i.confidence, "
        "         i.source_id, i.first_seen, i.last_seen, i.kill_chain, "
        "         i.mitre_techniques, i.raw_stix, i.needs_review "
        "ORDER BY i.last_seen DESC"
    )
    cols = ["id", "pattern_type", "observable_value", "pattern",
            "valid_from", "valid_until", "tlp", "confidence", "source_id",
            "first_seen", "last_seen", "kill_chain", "mitre_techniques",
            "raw_stix", "needs_review", "actors"]
    ceiling = _tlp_rank(tlp_ceiling)
    out: List[Dict[str, Any]] = []
    with cti_database.open_cti_db(client_id) as conn:
        rows = conn.execute(sql).fetchall()
    for r in rows:
        d = dict(zip(cols, r))
        if not include_review and d.get("needs_review"):
            continue
        if _tlp_rank(d.get("tlp")) < ceiling:
            continue
        out.append(d)
    return out


def _resolve_siem(siem_id: str) -> Optional[Dict[str, Any]]:
    """Look up a ``siem_inventory`` row by id."""
    if not siem_id:
        return None
    with get_database_service().get_shared_connection() as conn:
        row = conn.execute(
            "SELECT id, label, elasticsearch_url, kibana_url, "
            "api_token_enc, is_active "
            "FROM siem_inventory WHERE id = ?",
            [siem_id],
        ).fetchone()
    if not row:
        return None
    return {
        "id": row[0], "label": row[1],
        "elasticsearch_url": row[2], "kibana_url": row[3],
        "api_token_enc": row[4], "is_active": row[5],
    }


def _load_targets(client_id: str,
                  target_id: Optional[str] = None,
                  ) -> List[Dict[str, Any]]:
    """Return active egress targets for ``client_id`` (optionally one).

    Includes the v2 ``kind`` discriminator plus the kind-specific
    config columns (``folder_path``, ``diode_endpoint``) so the
    dispatcher in :func:`app.services.cti_egress.export_cti_for_target`
    can route without a second query.
    """
    with cti_database.open_cti_db(client_id) as conn:
        sql = (
            "SELECT id, label, kind, siem_id, index_pattern, latest_index, "
            "api_key_enc, folder_path, diode_endpoint, tlp_ceiling, "
            "is_active "
            "FROM cti_egress_targets WHERE COALESCE(is_active, TRUE) = TRUE"
        )
        params: List[Any] = []
        if target_id:
            sql += " AND id = ?"
            params.append(target_id)
        rows = conn.execute(sql, params).fetchall()
    cols = ["id", "label", "kind", "siem_id", "index_pattern",
            "latest_index", "api_key_enc", "folder_path",
            "diode_endpoint", "tlp_ceiling", "is_active"]
    return [dict(zip(cols, r)) for r in rows]


def _empty_summary(target: Dict[str, Any]) -> Dict[str, Any]:
    """Base counter dict every driver returns (driver-specific keys
    added by the driver). ``read`` / ``filtered`` / ``failures`` /
    ``errors`` are universal."""
    return {
        "target_id": target.get("id"),
        "target_label": target.get("label"),
        "kind": (target.get("kind") or "elastic"),
        "read": 0,
        "filtered": 0,
        "failures": 0,
        "errors": [],
    }
