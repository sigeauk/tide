"""TIDE's Content-Security-Policy (#89 R3): what a browser may load and run on TIDE's pages.

Scripts only from TIDE's own files: no inline script, no eval (so no htmx ``hx-on``; see app.js's
``data-request-*`` / ``data-done-*``). Styles from TIDE's own files, and in ``style`` attributes
(``style-src-attr 'unsafe-inline'``, a decision of the owner's: the inline-style lint keeps shrinking
them). Images from TIDE and ``data:``; fonts, connections and frames from TIDE; no plugins; forms post
to TIDE, or on to the Keycloak TIDE signs in with (sign-out is a form that redirects there); only TIDE
may frame its pages.

Browsers enforce it (``MODE``, from ``CSP_MODE`` in .env). ``CSP_MODE=report-only`` sends it as
``Content-Security-Policy-Report-Only`` instead, for an install where it stops something working: then
nothing is blocked. Either way browsers report each thing it blocks, or would block, to ``REPORT_PATH``.
``record`` keeps one row per distinct violation (``csp_violations`` in the shared database, made by
migration 104; at most ``MAX_KEPT``) and logs each the first time; Diagnostics lists them.
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)


def _mode() -> str:
    """CSP_MODE: "report-only" only reports; anything else enforces, as TIDE does by default."""
    from app.config import get_settings
    value = str(get_settings().csp_mode or "").strip().lower()
    if value and value not in ("enforce", "report-only"):
        logger.warning(f"CSP_MODE={value!r} is neither enforce nor report-only: the Content-Security-Policy is enforced")
    return "report-only" if value == "report-only" else "enforce"


MODE = _mode()
REPORT_PATH = "/csp-report"
MAX_BODY = 64 * 1024           # a report larger than this isn't read
MAX_KEPT = 500                 # distinct violations kept; more are counted, not kept
WRITE_EVERY_S = 60             # a violation seen again updates its row at most this often

DDL = """
    CREATE TABLE IF NOT EXISTS csp_violations (
        key         VARCHAR PRIMARY KEY,
        directive   VARCHAR,
        blocked     VARCHAR,
        page        VARCHAR,
        source      VARCHAR,
        sample      VARCHAR,
        first_seen  TIMESTAMP NOT NULL,
        last_seen   TIMESTAMP NOT NULL,
        count       BIGINT NOT NULL
    )
"""


def _origin(url: str) -> str:
    parts = urlsplit(str(url or ""))
    return f"{parts.scheme}://{parts.netloc}" if parts.scheme in ("http", "https") and parts.netloc else ""


def policy(keycloak_url: str = "") -> str:
    """The policy, as the header's value. ``keycloak_url``: the address sign-out sends browsers to."""
    sign_out = _origin(keycloak_url)
    directives = [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "style-src-attr 'unsafe-inline'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'" + (f" {sign_out}" if sign_out else ""),
        f"report-uri {REPORT_PATH}",
    ]
    if MODE == "enforce":
        directives.insert(-1, "frame-ancestors 'self'")    # ignored, with a console warning, in report-only
    return "; ".join(directives)


def header_name() -> str:
    return "Content-Security-Policy" if MODE == "enforce" else "Content-Security-Policy-Report-Only"


# ── the reports ─────────────────────────────────────────────────────────

_lock = threading.Lock()
_seen: Dict[str, Dict[str, Any]] = {}     # key -> {"count", "written" (count written), "at" (last write)}
_dropped = {"count": 0}


def _blocked(value: str) -> str:
    """Where what was blocked came from: "inline", "eval", "data", or an origin (never a full URL, which
    may carry a query)."""
    value = str(value or "").strip()
    if value in ("inline", "eval", "data", "blob", "self", "wasm-eval", "trusted-types-policy", "trusted-types-sink"):
        return value
    return _origin(value) or (value.split(":", 1)[0] if ":" in value else value)[:100]


def _path(url: str) -> str:
    return (urlsplit(str(url or "")).path or "/")[:200]


def parse(body: bytes) -> List[Dict[str, str]]:
    """The violations in a report as a browser sends it: ``report-uri``'s ``{"csp-report": {...}}``, or the
    Reporting API's ``[{"type": "csp-violation", "body": {...}}]``."""
    try:
        data = json.loads(body.decode("utf-8")) if body else None
    except (UnicodeDecodeError, ValueError):
        return []
    found = []
    reports = [data.get("csp-report")] if isinstance(data, dict) else \
        [r.get("body") for r in data if isinstance(r, dict) and r.get("type") == "csp-violation"] if isinstance(data, list) else []
    for r in reports:
        if not isinstance(r, dict):
            continue
        directive = str(r.get("effective-directive") or r.get("effectiveDirective") or r.get("violated-directive") or "")
        found.append({
            "directive": directive.split()[0][:60] if directive else "",
            "blocked": _blocked(r.get("blocked-uri") or r.get("blockedURL") or ""),
            "page": _path(r.get("document-uri") or r.get("documentURL") or ""),
            "source": f"{_path(r.get('source-file') or r.get('sourceFile') or '')}:{r.get('line-number') or r.get('lineNumber') or ''}"
                      if (r.get("source-file") or r.get("sourceFile")) else "",
            "sample": str(r.get("script-sample") or r.get("sample") or "")[:120],
        })
    return found


def record(db, violations: List[Dict[str, str]], now: Optional[datetime] = None) -> int:
    """Keep each violation (one row per directive, blocked source, page and place), logging each the
    first time. Returns how many were new."""
    now = now or datetime.now()
    new = 0
    for v in violations:
        key = "|".join((v["directive"], v["blocked"], v["page"], v["source"]))[:500]
        with _lock:
            seen = _seen.get(key)
            if seen is None and len(_seen) >= MAX_KEPT:
                _dropped["count"] += 1
                continue
            seen = _seen.setdefault(key, {"count": 0, "written": 0, "at": 0.0})
            seen["count"] += 1
            first = seen["count"] == 1
            due = first or (now.timestamp() - seen["at"] >= WRITE_EVERY_S)
            if due:
                seen["at"], add = now.timestamp(), seen["count"] - seen["written"]
                seen["written"] = seen["count"]
        if first:
            new += 1
            logger.warning(f"Content-Security-Policy ({MODE}): {v['directive']} "
                           f"{'blocked' if MODE == 'enforce' else 'would block'} {v['blocked'] or 'something'} "
                           f"on {v['page']}{' at ' + v['source'] if v['source'] else ''}"
                           f"{' (' + v['sample'] + ')' if v['sample'] else ''}")
        if due:
            try:
                with db.get_shared_connection() as conn:
                    conn.execute(
                        "INSERT INTO csp_violations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (key) DO UPDATE SET "
                        "last_seen = EXCLUDED.last_seen, count = csp_violations.count + EXCLUDED.count",
                        [key, v["directive"], v["blocked"], v["page"], v["source"], v["sample"], now, now, add])
            except Exception:  # noqa: BLE001 - a report is never worth failing over
                logger.debug("Could not keep a Content-Security-Policy report", exc_info=True)
    return new


def violations(conn, limit: int = 200) -> List[Dict[str, Any]]:
    """What the policy blocked (or would block, report-only), most seen first, for Diagnostics."""
    try:
        rows = conn.execute("SELECT directive, blocked, page, source, sample, first_seen, last_seen, count "
                            "FROM csp_violations ORDER BY count DESC, last_seen DESC LIMIT ?", [limit]).fetchall()
    except Exception:  # noqa: BLE001 - shown as none
        return []
    names = ("directive", "blocked", "page", "source", "sample", "first_seen", "last_seen", "count")
    return [dict(zip(names, r)) for r in rows]


def kept(conn) -> Dict[str, int]:
    """How many kinds of violation are kept, and how many reports of them."""
    try:
        kinds, times = conn.execute("SELECT count(*), coalesce(sum(count), 0) FROM csp_violations").fetchone()
    except Exception:  # noqa: BLE001 - no table yet: none
        return {"kinds": 0, "times": 0}
    return {"kinds": int(kinds), "times": int(times)}


def forget(conn) -> Dict[str, int]:
    """Clear what was kept (Diagnostics' Clear this list, once a release fixes what was reported): a browser
    reports anything still blocked again. Returns what was cleared."""
    cleared = kept(conn)
    conn.execute("DELETE FROM csp_violations")
    with _lock:
        _seen.clear()
        _dropped["count"] = 0
    return cleared
