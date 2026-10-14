"""Dashboards: a client's named dashboards, what each one shows, and which one each user last opened.

A dashboard is a list of cards, each ``{"type": ..., "w": ...}``: a title or text block (plus
``text``), or a section (``type`` "section", plus ``source``, ``name``, ``metrics`` and
``filters``) showing chosen metric cards from one source. A source mirrors a page's metric strip
(Rule Health, a system, Threat Landscape, ...): its cards and, where the page's cards follow its
filters, those filters. Any source can be added any number of times. ``w`` is the card's width in
twelfths of the page.

Dashboards belong to the client and live in its own database, made on first use. The client's
earlier layouts become dashboards then: its own layout (or TIDE's default) as "Overview", the
client's default, and each user's own layout as "<user>'s dashboard". Text is stored as typed and
escaped when the page shows it.
"""
import json
import logging
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, urlencode

from app.services.tenant_manager import tenant_context_for

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Source:
    label: str
    icon: str
    metrics: Tuple[Tuple[str, str], ...]     # (key, card label), in the page's order
    filters: Tuple[str, ...] = ()            # the page's filters its cards follow
    page: str = ""                           # where a card goes; "" = its cards are not links


RULE_STATES = (("live", "Live"), ("offline", "SIEM offline"), ("deprecated", "Deprecated"))

SOURCES: Dict[str, Source] = {
    "rule_health": Source("Rule Health", "shield-check", (
        ("total", "Total Rules"), ("enabled", "Enabled"), ("validated", "Validated"),
        ("quality", "Avg Quality"), ("severity", "Severity"), ("last_synced", "Last Synced"),
    ), ("space", "enabled", "state", "min_score", "max_score", "validated_from", "validated_to", "search"), "/rules"),
    "system": Source("System", "server", (
        ("covered", "Covered"), ("techniques", "Techniques"), ("no_coverage", "No coverage"),
        ("known_gaps", "Known gaps"), ("unmapped", "Unmapped"), ("not_counted", "Not counted"),
    ), ("system_id",), "/systems"),
    "threat_landscape": Source("Threat Landscape", "target", (
        ("actors", "Tracked Actors"), ("ttps", "Unique TTPs"), ("coverage", "Global Coverage"),
        ("gaps", "Coverage Gaps"), ("fully_covered", "Fully Covered"), ("last_synced", "Last Synced"),
    ), (), "/threats"),
    "baselines": Source("Baselines", "shield", (
        ("templates", "Templates"), ("techniques", "Techniques Defined"), ("system_baselines", "System Baselines"),
        ("rules_mapped", "Rules Mapped"), ("uncovered", "Uncovered"), ("fully_covered", "Fully Covered"),
    ), (), "/baselines"),
    "asset_inventory": Source("Asset Inventory", "server", (
        ("systems", "Systems"), ("devices", "Devices"), ("packages", "Packages"),
        ("cve_matches", "CVE Matches"), ("affected_devices", "Affected Devices"), ("baseline_assignments", "Baseline Assignments"),
    ), (), "/systems"),
    "cve_overview": Source("CVE Overview", "shield-alert", (
        ("total", "Total CVEs"), ("matched", "CVEs Matched"), ("affected_devices", "Affected Devices"),
        ("ransomware", "Ransomware CVEs"), ("detected", "Detected"), ("ransom_undetected", "Ransom Undetected"),
    ), (), "/cve-overview"),
    "connected_services": Source("Connected Services", "settings", (
        ("siems", "SIEMs"), ("opencti", "OpenCTI"), ("gitlab", "GitLab"), ("logging", "Logging"),
    )),
    "repositories": Source("Repositories", "github", (
        ("mitre_enterprise", "MITRE Enterprise ATT&CK"), ("mitre_mobile", "MITRE Mobile ATT&CK"),
        ("mitre_ics", "MITRE ICS ATT&CK"), ("mitre_pre", "MITRE PRE-ATT&CK"),
        ("sigma", "Sigma Rules"), ("elastic", "Elastic Detection Rules"),
    )),
}
TEXT_CARDS = {"title": 120, "text": 2000}      # type -> most characters
NAME_LIMIT = 80                                # a section's or a dashboard's name
WIDTHS = (3, 4, 6, 8, 9, 12)
DEFAULT_WIDTH = {"text": 6}
MAX_CARDS = 60
SEARCH_LIMIT = 200

DEFAULT_NAME = "Overview"
DEFAULT_LAYOUT = [{"type": "section", "source": s, "w": 12, "name": "",
                   "metrics": [k for k, _ in SOURCES[s].metrics], "filters": {}}
                  for s in ("rule_health", "threat_landscape", "baselines", "connected_services",
                            "repositories", "asset_inventory", "cve_overview")]


def new_section(source: str) -> dict:
    """A section as Add puts it on a dashboard: every card, no filters, and no name of its own, so
    it is headed by its source (a System section by the system's name) until it is given one."""
    return {"type": "section", "source": source, "w": 12, "name": "",
            "metrics": [k for k, _ in SOURCES[source].metrics], "filters": {}}


def _one_line(text, limit: int, what: str) -> str:
    if text is None:
        return ""
    if not isinstance(text, str):
        raise ValueError(f"{what} must be text.")
    text = " ".join(text.split())
    if len(text) > limit:
        raise ValueError(f"{what} can be at most {limit} characters.")
    return text


def _clean_filters(source: str, raw) -> dict:
    """Only the source's own filters, each in the form its page takes; empty ones are dropped."""
    raw = raw if isinstance(raw, dict) else {}
    allowed, out = SOURCES[source].filters, {}
    for key in allowed:
        value = raw.get(key)
        if value in (None, "", []):
            continue
        if key == "state":
            states = [value] if isinstance(value, str) else value if isinstance(value, list) else []
            picked = [s for s, _ in RULE_STATES if s in states]
            if picked:
                out[key] = picked
        elif key == "enabled":
            if value in ("true", "false"):
                out[key] = value
        elif key in ("min_score", "max_score"):
            try:
                out[key] = max(0, min(100, int(value)))
            except (TypeError, ValueError):
                raise ValueError("A score must be a number from 0 to 100.")
        elif key in ("validated_from", "validated_to"):
            try:
                out[key] = date.fromisoformat(str(value)).isoformat()
            except ValueError:
                raise ValueError("A validation date must be a date (YYYY-MM-DD).")
        elif key == "search":
            text = _one_line(value, SEARCH_LIMIT, "A search")
            if text:
                out[key] = text
        elif key in ("space", "system_id"):
            if not isinstance(value, str) or len(value) > 300:
                raise ValueError("A destination or system is not recognised.")
            out[key] = value
    return out


def clean(cards) -> List[dict]:
    """A layout as it may be stored. Cards of a type TIDE no longer has and empty titles and text
    blocks are dropped; a width snaps to the nearest one offered; a section keeps only its
    source's cards and filters. A section saved before dashboards ({"type": "rule_health"})
    becomes the same section with every card. Raises ValueError when ``cards`` is not a layout
    or a text is too long."""
    if not isinstance(cards, list) or len(cards) > MAX_CARDS:
        raise ValueError(f"A dashboard is a list of at most {MAX_CARDS} cards.")
    out = []
    for card in cards:
        if not isinstance(card, dict):
            raise ValueError("Each card must be an object.")
        kind = card.get("type")
        if kind in SOURCES:                      # a section as layouts stored it before 6.1.2
            card = {**new_section(kind), "w": card.get("w")}
            kind = "section"
        try:
            w = int(card.get("w") or DEFAULT_WIDTH.get(kind, 12))
        except (TypeError, ValueError):
            w = 12
        w = min(WIDTHS, key=lambda x: (abs(x - w), -x))
        if kind == "section":
            source = card.get("source")
            if source not in SOURCES:
                continue
            keys = [k for k, _ in SOURCES[source].metrics]
            chosen = card.get("metrics") if isinstance(card.get("metrics"), list) else keys
            out.append({
                "type": "section", "source": source, "w": w,
                "name": _one_line(card.get("name"), NAME_LIMIT, "A section's name"),
                "metrics": [k for k in keys if k in chosen] or keys,
                "filters": _clean_filters(source, card.get("filters")),
            })
        elif kind in TEXT_CARDS:
            text = card.get("text")
            if not isinstance(text, str):
                raise ValueError("A title or text block's text must be a string.")
            text = text.replace("\r\n", "\n").strip()
            if kind == "title":
                text = " ".join(text.split())
            if len(text) > TEXT_CARDS[kind]:
                raise ValueError(f"A {'title' if kind == 'title' else 'text block'} can be at most "
                                 f"{TEXT_CARDS[kind]} characters.")
            if text:
                out.append({"type": kind, "w": w, "text": text})
    return out


def clean_name(name) -> str:
    name = _one_line(name, NAME_LIMIT, "A dashboard's name")
    if not name:
        raise ValueError("A dashboard needs a name.")
    return name


def link_for(card: dict) -> str:
    """Where a section's cards go: its page, with the section's filters applied. "" when its
    cards are not links (Connected Services, Repositories) or a system is not chosen yet."""
    source = SOURCES[card["source"]]
    filters = card.get("filters") or {}
    if card["source"] == "system":
        return f"/systems/{quote(filters['system_id'])}" if filters.get("system_id") else ""
    if not source.page:
        return ""
    query = urlencode({k: v for k, v in filters.items() if k in source.filters}, doseq=True)
    return f"{source.page}?{query}" if query else source.page


# ── storage ──────────────────────────────────────────────────────────────────────────────────

def _ensure_tables(conn) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS dashboards (
            id VARCHAR PRIMARY KEY,
            name VARCHAR NOT NULL,
            layout_json VARCHAR NOT NULL,
            is_default BOOLEAN DEFAULT false,
            created_at TIMESTAMP DEFAULT now(),
            created_by VARCHAR,
            updated_at TIMESTAMP DEFAULT now(),
            updated_by VARCHAR
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS dashboard_choices (
            user_id VARCHAR PRIMARY KEY,
            dashboard_id VARCHAR NOT NULL,
            updated_at TIMESTAMP DEFAULT now()
        )
    """)


def _usernames(db, user_ids: List[str]) -> Dict[str, str]:
    if not user_ids:
        return {}
    marks = ", ".join("?" for _ in user_ids)
    try:
        with db.get_shared_connection() as conn:
            rows = conn.execute(f"SELECT id, username FROM users WHERE id IN ({marks})", user_ids).fetchall()
        return {str(r[0]): r[1] for r in rows}
    except Exception as exc:
        logger.warning("Dashboards: could not read usernames for earlier layouts: %s", exc)
        return {}


def _seed(db, conn, client_id: str) -> None:
    """A client's first dashboards, from the layouts it had before dashboards (once: only while it
    has none). Fixed ids, so two requests doing this at once insert each one only once."""
    if conn.execute("SELECT count(*) FROM dashboards").fetchone()[0]:
        return
    layouts = {}
    has_old = conn.execute("SELECT count(*) FROM information_schema.tables "
                           "WHERE table_name = 'dashboard_layouts'").fetchone()[0]
    if has_old:
        for owner, raw in conn.execute("SELECT owner, layout_json FROM dashboard_layouts").fetchall():
            try:
                layouts[owner] = clean(json.loads(raw))
            except (ValueError, TypeError) as exc:
                logger.warning("Dashboards: client %s layout %s unreadable, not carried over: %s", client_id, owner, exc)
    rows = [("overview", DEFAULT_NAME, layouts.get("client", DEFAULT_LAYOUT), True)]
    users = sorted(o.split(":", 1)[1] for o in layouts if o.startswith("user:"))
    names = _usernames(db, users)
    for uid in users:
        rows.append((f"user-{uid}", f"{names.get(uid, 'A user')}'s dashboard", layouts[f"user:{uid}"], False))
    for did, name, cards, is_default in rows:
        conn.execute("INSERT INTO dashboards (id, name, layout_json, is_default, created_by, updated_by) "
                     "VALUES (?, ?, ?, ?, 'TIDE', 'TIDE') ON CONFLICT (id) DO NOTHING",
                     [did, name, json.dumps(cards), is_default])
    logger.info("Dashboards: client %s set up with %d dashboard(s) from its earlier layouts", client_id, len(rows))


@contextmanager
def _conn(db, client_id: str):
    """The client's database, with the dashboard tables ready."""
    with tenant_context_for(client_id), db.get_connection() as conn:
        _ensure_tables(conn)
        _seed(db, conn, client_id)
        yield conn


def _row(r) -> dict:
    try:
        cards = clean(json.loads(r[2]))
    except (ValueError, TypeError) as exc:
        logger.warning("Dashboard %s is unreadable, shown empty: %s", r[0], exc)
        cards = []
    return {"id": r[0], "name": r[1], "cards": cards, "is_default": bool(r[3])}


_COLS = "id, name, layout_json, is_default"


def list_dashboards(db, client_id: str) -> List[dict]:
    """The client's dashboards, the default first, then by name (without their cards)."""
    with _conn(db, client_id) as conn:
        rows = conn.execute("SELECT id, name, is_default FROM dashboards "
                            "ORDER BY is_default DESC, lower(name), id").fetchall()
    return [{"id": r[0], "name": r[1], "is_default": bool(r[2])} for r in rows]


def get(db, client_id: str, dashboard_id: str) -> Optional[dict]:
    with _conn(db, client_id) as conn:
        r = conn.execute(f"SELECT {_COLS} FROM dashboards WHERE id = ?", [dashboard_id]).fetchone()
    return _row(r) if r else None


def resolve(db, client_id: str, user_id, dashboard_id: Optional[str] = None) -> Optional[dict]:
    """The dashboard to show: the one asked for, else the one this user last opened, else the
    client's default. None only when the one asked for doesn't exist."""
    with _conn(db, client_id) as conn:
        if dashboard_id:
            r = conn.execute(f"SELECT {_COLS} FROM dashboards WHERE id = ?", [dashboard_id]).fetchone()
            return _row(r) if r else None
        r = conn.execute(f"SELECT {_COLS} FROM dashboards d JOIN dashboard_choices c ON c.dashboard_id = d.id "
                         "WHERE c.user_id = ?", [str(user_id)]).fetchone() if user_id else None
        r = r or conn.execute(f"SELECT {_COLS} FROM dashboards ORDER BY is_default DESC, lower(name), id LIMIT 1").fetchone()
    return _row(r) if r else None


def remember(db, client_id: str, user_id, dashboard_id: str) -> None:
    """The dashboard ``user_id`` opened last, shown to them next time they open the Dashboard."""
    if not user_id:
        return
    with _conn(db, client_id) as conn:
        conn.execute("INSERT INTO dashboard_choices (user_id, dashboard_id, updated_at) VALUES (?, ?, now()) "
                     "ON CONFLICT (user_id) DO UPDATE SET dashboard_id = excluded.dashboard_id, updated_at = now()",
                     [str(user_id), dashboard_id])


def create(db, client_id: str, name: str, cards: List[dict], actor: str) -> str:
    did = uuid.uuid4().hex[:12]
    with _conn(db, client_id) as conn:
        conn.execute("INSERT INTO dashboards (id, name, layout_json, is_default, created_by, updated_by) "
                     "VALUES (?, ?, ?, false, ?, ?)", [did, clean_name(name), json.dumps(clean(cards)), actor, actor])
    return did


def save(db, client_id: str, dashboard_id: str, name: str, cards: List[dict], actor: str) -> bool:
    with _conn(db, client_id) as conn:
        found = conn.execute("SELECT 1 FROM dashboards WHERE id = ?", [dashboard_id]).fetchone()
        if found:
            conn.execute("UPDATE dashboards SET name = ?, layout_json = ?, updated_at = now(), updated_by = ? WHERE id = ?",
                         [clean_name(name), json.dumps(clean(cards)), actor, dashboard_id])
    return bool(found)


def set_default(db, client_id: str, dashboard_id: str) -> bool:
    with _conn(db, client_id) as conn:
        if not conn.execute("SELECT 1 FROM dashboards WHERE id = ?", [dashboard_id]).fetchone():
            return False
        conn.execute("UPDATE dashboards SET is_default = (id = ?)", [dashboard_id])
    return True


def delete(db, client_id: str, dashboard_id: str) -> str:
    """'deleted', 'default' (the default can't be deleted) or 'missing'."""
    with _conn(db, client_id) as conn:
        r = conn.execute("SELECT is_default FROM dashboards WHERE id = ?", [dashboard_id]).fetchone()
        if not r:
            return "missing"
        if r[0]:
            return "default"
        conn.execute("DELETE FROM dashboard_choices WHERE dashboard_id = ?", [dashboard_id])
        conn.execute("DELETE FROM dashboards WHERE id = ?", [dashboard_id])
    return "deleted"
