"""Elasticsearch ``_bulk`` egress driver.

Ships one indexing op into ``logs-ti_tide_latest`` and one append-only
``create`` op into ``logs-ti_tide.indicator-YYYY.MM.DD`` per indicator.
Deterministic ``_id`` (md5 of ``pattern_type|observable_value``) means
re-running the export is idempotent: the latest index is overwritten
in place, the dated history index 409s on same-day re-export.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

import requests

from ._common import (
    BATCH_SIZE,
    HISTORY_PREFIX,
    LATEST_INDEX,
    _build_doc,
    _doc_id,
    _empty_summary,
    _history_index_for,
    _load_indicators,
    _resolve_siem,
)

logger = logging.getLogger(__name__)


def _bulk_lines(docs: Iterable[Tuple[str, Dict[str, Any]]],
                history_index: str) -> Iterator[str]:
    """Yield NDJSON lines for the ``_bulk`` request (2 ops per doc)."""
    for doc_id, doc in docs:
        yield json.dumps({"index": {"_index": LATEST_INDEX, "_id": doc_id}},
                         separators=(",", ":"))
        yield json.dumps(doc, separators=(",", ":"), default=str)
        yield json.dumps({"create": {"_index": history_index, "_id": doc_id}},
                         separators=(",", ":"))
        yield json.dumps(doc, separators=(",", ":"), default=str)


def _post_bulk(session: requests.Session, es_url: str, api_token: str,
               ndjson_body: str, *,
               timeout: Tuple[float, float] = (10.0, 60.0),
               ) -> Dict[str, Any]:
    """POST a single ``_bulk`` request; raise on non-200."""
    resp = session.post(
        f"{es_url.rstrip('/')}/_bulk",
        data=ndjson_body,
        headers={
            "Authorization": f"ApiKey {api_token}",
            "Content-Type": "application/x-ndjson",
        },
        timeout=timeout,
    )
    if resp.status_code != 200:
        raise RuntimeError(
            f"Elasticsearch _bulk HTTP {resp.status_code}: {resp.text[:300]}"
        )
    return resp.json()


def _count_bulk_outcomes(bulk_response: Dict[str, Any]) -> Dict[str, int]:
    """Reduce a ``_bulk`` response into counters per outcome."""
    out = {
        "latest_indexed": 0,
        "history_created": 0,
        "history_duplicates": 0,
        "failures": 0,
    }
    items = bulk_response.get("items") or []
    for item in items:
        if "index" in item:
            sub = item["index"]
            status = sub.get("status", 0)
            if 200 <= status < 300:
                out["latest_indexed"] += 1
            else:
                out["failures"] += 1
        elif "create" in item:
            sub = item["create"]
            status = sub.get("status", 0)
            if 200 <= status < 300:
                out["history_created"] += 1
            elif status == 409:
                out["history_duplicates"] += 1
            else:
                out["failures"] += 1
    return out


def _flush(session: requests.Session, es_url: str, api_token: str,
           batch: List[Tuple[str, Dict[str, Any]]],
           history_index: str, summary: Dict[str, Any]) -> None:
    """Send one batch and fold its counters into ``summary``."""
    body = "\n".join(_bulk_lines(batch, history_index)) + "\n"
    try:
        resp = _post_bulk(session, es_url, api_token, body)
    except Exception as exc:
        msg = f"_bulk failed (batch={len(batch)}): {exc}"
        logger.error(msg, exc_info=True)
        summary["errors"].append(msg)
        summary["failures"] += len(batch) * 2
        return
    summary["batches"] += 1
    counters = _count_bulk_outcomes(resp)
    for k, v in counters.items():
        summary[k] = summary.get(k, 0) + v


def run(client_id: str, target: Dict[str, Any], *,
        session: Optional[requests.Session] = None,
        batch_size: int = BATCH_SIZE,
        now: Optional[datetime] = None) -> Dict[str, Any]:
    """Export indicators to Elasticsearch ``_bulk``.

    Resolves ``target.siem_id`` against ``siem_inventory`` for the ES
    URL and falls back from ``target.api_key_enc`` to the SIEM-level
    token. Returns the standard summary dict extended with the
    elastic-specific counters (``batches``, ``latest_indexed``,
    ``history_created``, ``history_duplicates``).
    """
    summary = _empty_summary(target)
    summary.update({
        "batches": 0,
        "latest_indexed": 0,
        "history_created": 0,
        "history_duplicates": 0,
    })

    siem = _resolve_siem(target.get("siem_id"))
    if not siem:
        summary["errors"].append(
            f"siem_id={target.get('siem_id')} not found in siem_inventory"
        )
        return summary
    es_url = siem.get("elasticsearch_url")
    if not es_url:
        summary["errors"].append(
            f"siem '{siem.get('label')}' has no elasticsearch_url; "
            "_bulk requires direct ES, Kibana proxy is not supported"
        )
        return summary
    api_token = target.get("api_key_enc") or siem.get("api_token_enc")
    if not api_token:
        summary["errors"].append(
            f"no api token available (neither target.api_key_enc nor "
            f"siem '{siem.get('label')}'.api_token_enc set)"
        )
        return summary

    indicators = _load_indicators(
        client_id, tlp_ceiling=target.get("tlp_ceiling") or "amber",
    )
    summary["read"] = len(indicators)
    if not indicators:
        return summary

    history_index = _history_index_for(now)
    own_session = session is None
    if own_session:
        session = requests.Session()

    try:
        batch: List[Tuple[str, Dict[str, Any]]] = []
        for ind in indicators:
            pt = ind.get("pattern_type")
            ov = ind.get("observable_value")
            if not pt or not ov:
                summary["filtered"] += 1
                continue
            doc_id = _doc_id(pt, ov)
            doc = _build_doc(
                ind, client_id,
                target_label=target.get("label", ""),
                target_id=target.get("id", ""),
            )
            batch.append((doc_id, doc))
            if len(batch) >= batch_size:
                _flush(session, es_url, api_token, batch,
                       history_index, summary)
                batch = []
        if batch:
            _flush(session, es_url, api_token, batch,
                   history_index, summary)
    finally:
        if own_session:
            session.close()
    return summary


# Public re-exports for tests / callers that patch these helpers.
__all__ = [
    "HISTORY_PREFIX",
    "LATEST_INDEX",
    "_bulk_lines",
    "_count_bulk_outcomes",
    "_flush",
    "_post_bulk",
    "run",
]
