"""Dashboard layouts: which cards the Dashboard shows, in what order and how wide.

A layout is a list of cards, each ``{"type": ..., "w": ...}`` plus ``text`` for a title or text
block. ``w`` is the card's width in twelfths of the page. Layouts live in the client's own
database: the client's layout (owner ``client``) and any user's own copy (owner ``user:<id>``). A
user sees their own copy, else the client's, else ``DEFAULT_LAYOUT``. Text is stored as typed and
escaped when the page shows it.
"""
import json
import logging
from typing import List, Optional, Tuple

from app.services.tenant_manager import tenant_context_for

logger = logging.getLogger(__name__)

# The Dashboard's sections, in their default order: type -> (heading, icon). Each shows at most once.
SECTION_CARDS = {
    "rule_health": ("Rule Health", "shield-check"),
    "promotion": ("Promotion", "circle-arrow-up"),
    "threat_landscape": ("Threat Landscape", "target"),
    "baselines": ("Baselines", "shield"),
    "connected_services": ("Connected Services", "settings"),
    "repositories": ("Repositories", "github"),
    "asset_inventory": ("Asset Inventory", "server"),
    "cve_overview": ("CVE Overview", "shield-alert"),
}
TEXT_CARDS = {"title": 120, "text": 2000}      # type -> most characters
WIDTHS = (3, 4, 6, 8, 9, 12)
DEFAULT_WIDTH = {"text": 6}
MAX_CARDS = 60

DEFAULT_LAYOUT = [{"type": t, "w": 12} for t in SECTION_CARDS]

CLIENT = "client"


def user_owner(user_id) -> str:
    return f"user:{user_id}"


def clean(cards) -> List[dict]:
    """A layout as it may be stored. Cards of a type TIDE no longer has, a second copy of a
    section, and empty titles and text blocks are dropped; a width snaps to the nearest one
    offered. Raises ValueError when ``cards`` is not a layout or a text is too long."""
    if not isinstance(cards, list) or len(cards) > MAX_CARDS:
        raise ValueError(f"A layout is a list of at most {MAX_CARDS} cards.")
    out, seen = [], set()
    for card in cards:
        if not isinstance(card, dict):
            raise ValueError("Each card must be an object.")
        kind = card.get("type")
        try:
            w = int(card.get("w") or DEFAULT_WIDTH.get(kind, 12))
        except (TypeError, ValueError):
            w = 12
        w = min(WIDTHS, key=lambda x: (abs(x - w), -x))
        if kind in SECTION_CARDS:
            if kind not in seen:
                seen.add(kind)
                out.append({"type": kind, "w": w})
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


def _ensure_table(conn) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS dashboard_layouts (
            owner VARCHAR PRIMARY KEY,
            layout_json VARCHAR NOT NULL,
            updated_at TIMESTAMP DEFAULT now(),
            updated_by VARCHAR
        )
    """)


def _read(db, client_id: str, owners: List[str]) -> dict:
    with tenant_context_for(client_id), db.get_connection() as conn:
        _ensure_table(conn)
        marks = ", ".join("?" for _ in owners)
        rows = conn.execute(f"SELECT owner, layout_json FROM dashboard_layouts WHERE owner IN ({marks})",
                            owners).fetchall()
    out = {}
    for owner, raw in rows:
        try:
            out[owner] = clean(json.loads(raw))
        except (ValueError, TypeError) as exc:
            logger.warning("Dashboard layout %s for client %s is unreadable, ignored: %s", owner, client_id, exc)
    return out


def load(db, client_id: str, user_id) -> Tuple[List[dict], str, set]:
    """The layout ``user_id`` sees on ``client_id``, where it came from ('user', 'client' or
    'default'), and which of the two stored layouts exist ({'user', 'client'})."""
    mine = user_owner(user_id)
    found = _read(db, client_id, [mine, CLIENT]) if client_id else {}
    stored = {"user" if o == mine else "client" for o in found}
    if mine in found:
        return found[mine], "user", stored
    if CLIENT in found:
        return found[CLIENT], "client", stored
    return [dict(c) for c in DEFAULT_LAYOUT], "default", stored


def load_for_edit(db, client_id: str, user_id, scope: str) -> List[dict]:
    """What the editor starts from: the layout being edited, else what it would replace (a user's
    first copy starts from the client's layout, the client's first from the default)."""
    if scope == "client":
        found = _read(db, client_id, [CLIENT])
        return found.get(CLIENT) or [dict(c) for c in DEFAULT_LAYOUT]
    return load(db, client_id, user_id)[0]


def save(db, client_id: str, owner: str, cards: List[dict], actor: str) -> None:
    with tenant_context_for(client_id), db.get_connection() as conn:
        _ensure_table(conn)
        conn.execute(
            "INSERT INTO dashboard_layouts (owner, layout_json, updated_at, updated_by) VALUES (?, ?, now(), ?) "
            "ON CONFLICT (owner) DO UPDATE SET layout_json = excluded.layout_json, "
            "updated_at = excluded.updated_at, updated_by = excluded.updated_by",
            [owner, json.dumps(cards), actor],
        )


def reset(db, client_id: str, owner: str) -> None:
    with tenant_context_for(client_id), db.get_connection() as conn:
        _ensure_table(conn)
        conn.execute("DELETE FROM dashboard_layouts WHERE owner = ?", [owner])
