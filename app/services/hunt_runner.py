"""Running a hunting query against one of the tenant's SIEMs: the Hunting page's Run.

Elastic's hunting queries are run as they are written: ES|QL through Elasticsearch's ``_query``
API, EQL through ``_eql/search`` on an index pattern. SigmaHQ's threat-hunting rules are converted
to ES|QL first, with a pySigma pipeline and an index pattern. Osquery SQL runs on hosts, not the
SIEM, so it is not run. Only bundled queries are run (never query text sent by the browser), over
an optional time range, and only the first rows come back.

Elasticsearch is reached directly when the SIEM has an Elasticsearch URL, else through Kibana's
console proxy (as the field checks and the rule Test do).
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# (value, label): how far back a run looks. "" runs the query over whatever time it says itself.
LOOKBACKS = (("", "As the query says"), ("1h", "Last hour"), ("24h", "Last 24 hours"),
             ("7d", "Last 7 days"), ("30d", "Last 30 days"))
MAX_ROWS = 50
# ES|QL column types shown right-aligned, as numbers
_NUMERIC = {"long", "integer", "double", "float", "unsigned_long", "half_float", "scaled_float", "short", "byte",
            "counter_long", "counter_integer", "counter_double"}
DEFAULT_INDEX = "logs-*"
_INDEX_OK = re.compile(r"^[A-Za-z0-9*_.,:\-]+$")
# EQL results: the fields shown for each event (those that are empty in every row are left out).
_EVENT_FIELDS = ("@timestamp", "host.name", "user.name", "event.action", "process.name",
                 "process.command_line", "file.path", "destination.ip")


def query_kind(query: str) -> str:
    """``esql``, ``eql`` or ``osquery`` (Osquery SQL, which is not run against the SIEM)."""
    text = (query or "").lstrip()
    if re.match(r"(?i)(from|row|show)\b", text):
        return "esql"
    if re.match(r"(?i)(select|with)\b", text):
        return "osquery"
    return "eql"


def clean_index(index: str) -> str:
    """The index pattern a run may use: letters, digits, ``*_.,:-`` only; else the default."""
    index = (index or "").strip().replace(" ", "")
    return index if index and _INDEX_OK.match(index) else DEFAULT_INDEX


def sigma_esql(raw_yaml: str, pipeline: str, index: str) -> Tuple[bool, str]:
    """A Sigma rule converted to ES|QL with ``pipeline``, reading ``index`` (pySigma writes
    ``from *``)."""
    from app import sigma_helper

    if pipeline not in sigma_helper.get_available_pipelines():
        pipeline = "none"
    ok, query = sigma_helper.convert_sigma_rule(raw_yaml, backend="esql", pipeline=pipeline,
                                                output_format="default")
    if not ok:
        return False, query
    return True, re.sub(r"^\s*from\s+\*", f"from {clean_index(index)}", query, count=1, flags=re.IGNORECASE)


def default_pipeline(platform: str) -> str:
    """The pipeline a Sigma hunting rule is converted with unless another is picked."""
    return "ecs_windows" if (platform or "").lower() == "windows" else "none"


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)
    text = str(value)
    return text if len(text) <= 300 else text[:300] + "…"


def _flat(source: Dict[str, Any], dotted: str) -> Any:
    if dotted in source:
        return source[dotted]
    node: Any = source
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _time_filter(lookback: str) -> Optional[Dict[str, Any]]:
    return {"range": {"@timestamp": {"gte": f"now-{lookback}", "lte": "now"}}} if lookback else None


def _error_text(resp) -> str:
    try:
        err = (resp.json() or {}).get("error")
        if isinstance(err, dict):
            reason = err.get("reason") or err.get("type") or ""
            cause = ((err.get("root_cause") or [{}])[0] or {}).get("reason") or ""
            return (reason if not cause or cause in reason else f"{reason}: {cause}")[:500]
        if err:
            return str(err)[:500]
    except ValueError:
        pass
    return (resp.text or "")[:500]


def run(siem: Dict[str, Any], query: str, kind: str, lookback: str = "", index: str = "") -> Dict[str, Any]:
    """Run ``query`` on ``siem`` (a ``get_client_siems`` row). Returns ``{ok, error, note, columns,
    numeric, rows, total, at_least, ms}``: ``numeric`` which columns hold numbers, ``rows`` the first
    ``MAX_ROWS`` as lists of strings, ``total`` how
    many there were (``at_least`` when Elasticsearch stopped counting); ``note`` why there was
    nothing to search (no index matches the query's)."""
    from app import elastic_helper

    out: Dict[str, Any] = {"ok": False, "error": "", "note": "", "columns": [], "numeric": [], "rows": [],
                           "total": 0, "at_least": False, "ms": 0}
    if kind == "osquery":
        out["error"] = "This is an Osquery query: it runs on your hosts (Osquery Manager), not against the SIEM."
        return out
    kibana, key = siem.get("kibana_url"), siem.get("api_token_enc")
    if not (kibana and key):
        out["error"] = f'{siem.get("label") or "This SIEM"} has no Kibana address or API key configured.'
        return out
    lookback = lookback if lookback in dict(LOOKBACKS) else ""
    session = elastic_helper._make_session(key, kibana)
    es_url = siem.get("elasticsearch_url") or None
    started = time.monotonic()
    try:
        if kind == "esql":
            body: Dict[str, Any] = {"query": query}
            if _time_filter(lookback):
                body["filter"] = _time_filter(lookback)
            resp = elastic_helper._es_post(session, kibana, es_url, "/_query", body, timeout=120)
        else:
            body = {"query": query, "size": MAX_ROWS}
            if _time_filter(lookback):
                body["filter"] = _time_filter(lookback)
            resp = elastic_helper._es_post(session, kibana, es_url,
                                           f"/{clean_index(index)}/_eql/search?allow_no_indices=true", body,
                                           timeout=120)
    except Exception as exc:
        logger.warning("Hunting query run on SIEM %s failed: %s", siem.get("id"), exc)
        out["error"] = f"The SIEM did not answer: {exc}"
        return out
    out["ms"] = int((time.monotonic() - started) * 1000)
    if resp.status_code != 200:
        text = _error_text(resp)
        missing = re.search(r"Unknown index \[([^\]]+)\]", text)
        if missing:     # not an error: this SIEM simply holds no such data
            out.update(ok=True, note=f"No index on this SIEM matches {missing.group(1)}, so there was nothing to search.")
            return out
        out["error"] = f"Elasticsearch refused the query ({resp.status_code}): {text}"
        return out
    data = resp.json() or {}
    if kind == "esql":
        out["columns"] = [c.get("name", "") for c in data.get("columns") or []]
        out["numeric"] = [c.get("type") in _NUMERIC for c in data.get("columns") or []]
        values = data.get("values") or []
        out["total"] = len(values)
        out["at_least"] = len(values) >= 1000     # ES|QL's default LIMIT
        out["rows"] = [[_cell(v) for v in row] for row in values[:MAX_ROWS]]
    else:
        hits = data.get("hits") or {}
        total = hits.get("total") or {}
        events = list(hits.get("events") or [])
        for seq in hits.get("sequences") or []:
            events.extend(seq.get("events") or [])
        sources = [e.get("_source") or {} for e in events[:MAX_ROWS]]
        columns = [f for f in _EVENT_FIELDS if any(_flat(s, f) not in (None, "") for s in sources)]
        out["columns"] = columns
        out["numeric"] = [False] * len(columns)
        out["rows"] = [[_cell(_flat(s, f)) for f in columns] for s in sources]
        out["total"] = int(total.get("value", len(events))) if isinstance(total, dict) else len(events)
        out["at_least"] = isinstance(total, dict) and total.get("relation") == "gte"
    out["ok"] = True
    return out


def destinations_for(db, client_id: str) -> List[Dict[str, Any]]:
    """The tenant's destinations a hunt can run on and be saved to: ``{value ("<siem_id>|<space>"),
    label, siem_id, space, index}``. A run uses the destination's SIEM (Elasticsearch has no spaces);
    Save to Kibana its space."""
    out = []
    for s in db.get_client_siems(client_id) or []:
        if s.get("siem_type", "elastic") not in ("elastic", "elasticsearch", None, ""):
            continue
        space = str(s.get("space") or "default")
        out.append({"value": f"{s['id']}|{space}", "label": s.get("name") or space, "siem_id": s["id"],
                    "space": space, "index": str(s.get("default_index") or "")})
    return sorted(out, key=lambda d: d["label"].lower())


def destination(db, client_id: str, value: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """``(siem row, space)`` for a ``destinations_for`` value, if it is one of the tenant's."""
    siem_id, _, space = (value or "").partition("|")
    for s in db.get_client_siems(client_id) or []:
        if s.get("id") == siem_id and str(s.get("space") or "default") == space:
            return s, space
    return None, ""


def saved_search_id(source: str, hunt_id: str, query_no: int) -> str:
    """The Kibana saved search a hunt query is saved as: the same id each time, so saving it again
    replaces it rather than adding another."""
    return re.sub(r"[^A-Za-z0-9_-]", "-", f"tide-hunt-{source}-{hunt_id}-{query_no}")


def save_search(siem: Dict[str, Any], space: str, saved_id: str, title: str, description: str,
                query: str, lookback: str = "") -> Dict[str, Any]:
    """Save an ES|QL ``query`` as a Discover saved search in ``space`` of ``siem``'s Kibana, under
    ``saved_id`` (replacing one saved before), with the time range when ``lookback`` gives one.
    Returns ``{ok, error, replaced, url}`` (``url`` opens it in Discover)."""
    from app import elastic_helper

    out: Dict[str, Any] = {"ok": False, "error": "", "replaced": False, "url": ""}
    kibana, key = siem.get("kibana_url"), siem.get("api_token_enc")
    if not (kibana and key):
        out["error"] = f'{siem.get("label") or "This SIEM"} has no Kibana address or API key configured.'
        return out
    lookback = lookback if lookback in dict(LOOKBACKS) else ""
    prefix = elastic_helper._space_api_prefix(kibana.rstrip("/"), space)
    url = f"{prefix}/api/saved_objects/search/{saved_id}"
    attributes: Dict[str, Any] = {
        "title": title[:250], "description": (description or "")[:2000],
        "columns": [], "sort": [], "grid": {}, "hideChart": False, "isTextBasedQuery": True,
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"esql": query}, "filter": []})},
        "timeRestore": bool(lookback),
    }
    if lookback:
        attributes["timeRange"] = {"from": f"now-{lookback}", "to": "now"}
    session = elastic_helper._make_session(key, kibana)
    try:
        out["replaced"] = session.get(url, timeout=30).status_code == 200
        resp = session.post(url, params={"overwrite": "true"}, json={"attributes": attributes}, timeout=60)
    except Exception as exc:
        logger.warning("Saving hunting query %s to SIEM %s failed: %s", saved_id, siem.get("id"), exc)
        out["error"] = f"Kibana did not answer: {exc}"
        return out
    if resp.status_code not in (200, 201):
        out["error"] = f"Kibana refused to save it ({resp.status_code}): {_error_text(resp)}"
        if resp.status_code == 403:
            out["error"] += " The API key needs Discover access in this space."
        return out
    # The browser link, like the rule window's View in Kibana (no /s/ for the default space)
    browse = kibana.rstrip("/") + ("" if space.lower() == "default" else f"/s/{space}")
    out.update(ok=True, url=f"{browse}/app/discover#/view/{saved_id}")
    return out
