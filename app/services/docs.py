"""TIDE's guide and its changelog, rendered for Settings & Administration.

Documentation is the README plus the documents in docs/, a page each (PAGES). Changelog is the
CHANGELOG's entries for the running major version (every 6.x.x release while on 6), newest first,
so release notes are written once, in the CHANGELOG. All of them ship in the image beside the app
(/app) and are TIDE's own text, so their HTML is rendered as written. Links between them
(docs/API.md, ../README.md, CHANGELOG.md, with any #section) are pointed at their pages here.
Rendering is cached until a file or the version changes.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional

import markdown

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[2]
CHANGELOG_PATH = ROOT / "CHANGELOG.md"


class Page(NamedTuple):
    slug: str              # its address under /settings/docs ("" for the README)
    title: str
    path: Optional[Path]   # None for the Changelog, which is built from the CHANGELOG


# Documentation's pages, in its tab order.
PAGES: List[Page] = [
    Page("", "Overview", ROOT / "README.md"),
    Page("configuration", "Configuration", ROOT / "docs" / "CONFIGURATION.md"),
    Page("operations", "Operations", ROOT / "docs" / "OPERATIONS.md"),
    Page("api", "External Query API", ROOT / "docs" / "API.md"),
]
PAGES_BY_SLUG = {p.slug: p for p in PAGES}
CHANGELOG = Page("changelog", "Changelog", None)   # its own tab, /settings/changelog
# A link to one of these files, from the README or from docs/, goes to its page.
_FILE_URLS = {"README": "/settings/docs", "CONFIGURATION": "/settings/docs/configuration",
              "OPERATIONS": "/settings/docs/operations", "API": "/settings/docs/api",
              "CHANGELOG": "/settings/changelog"}
_DOC_LINK = re.compile(r'href="(?:\.\./)?(?:docs/)?(README|CHANGELOG|CONFIGURATION|OPERATIONS|API)\.md(#[^"]*)?"')

_RELEASE = re.compile(r"^## \[(\d+)\.(\d+)\.(\d+)\]\s*-?\s*(.*)$")
_cache: Dict[str, tuple] = {}


def _mtime(path: Optional[Path]) -> Optional[float]:
    try:
        return path.stat().st_mtime if path else None
    except OSError:
        return None


def whats_new(changelog: str, major: str) -> str:
    """Markdown for "What's new in TIDE <major>": that major's CHANGELOG entries, as written.
    Each release becomes an h2 and its Added / Changed / Fixed an h3. The CHANGELOG nests
    bullets two spaces deep; Python-Markdown needs four."""
    releases: List[List[str]] = []
    current: Optional[List[str]] = None
    for line in changelog.splitlines():
        m = _RELEASE.match(line)
        if m:
            current = None
            if m.group(1) == major:
                when = m.group(4).strip()
                when = "not released yet" if not when or when.lower() == "unreleased" else when
                current = [f"## {m.group(1)}.{m.group(2)}.{m.group(3)} ({when})", ""]
                releases.append(current)
        elif line.startswith("## "):
            current = None
        elif current is not None:
            current.append(line)
    body = "\n".join("\n".join(r).rstrip() + "\n" for r in releases)
    body = re.sub(r"^( +)(?=[-*] |\d+\. )", lambda m: m.group(1) * 2, body, flags=re.M)
    intro = (f"Every change in TIDE {major}, newest release first, from TIDE's release notes "
             "(`CHANGELOG.md`, which also lists earlier versions).")
    return f"# What's new in TIDE {major}\n\n{intro}\n\n{body or 'No release notes yet.'}"


def _contents(tokens: List[Dict]) -> List[Dict]:
    """The sections (h2) for the contents list, each with its subsections (h3) as ``children``.
    The h1 is the page's own title, so it is left out; any h2 under it is lifted up."""
    out: List[Dict] = []
    for t in tokens:
        if t["level"] == 1:
            out.extend(_contents(t.get("children", [])))
        elif t["level"] == 2:
            out.append({"id": t["id"], "name": t["name"],
                        "children": [{"id": c["id"], "name": c["name"]} for c in t.get("children", []) if c["level"] == 3]})
    return out


def _link(match: re.Match) -> str:
    name = match.group(1)
    anchor = "" if name == "CHANGELOG" else (match.group(2) or "")   # the CHANGELOG's own sections aren't on the page
    return f'href="{_FILE_URLS[name]}{anchor}"'


def page(slug: str, version: str) -> Optional[Dict]:
    """``{"html", "contents", "title", "slug"}`` for a page of the guide, or for the Changelog
    (slug "changelog"); None when there is no such page or its file isn't in this installation."""
    p = CHANGELOG if slug == CHANGELOG.slug else PAGES_BY_SLUG.get(slug)
    if p is None:
        return None
    source = p.path or CHANGELOG_PATH
    key = (_mtime(source), version)
    if key[0] is None:
        return None
    if _cache.get(slug, (None,))[0] != key:
        text = source.read_text(encoding="utf-8")
        if p.path is None:
            text = whats_new(text, version.split(".")[0])
        md = markdown.Markdown(extensions=["tables", "fenced_code", "sane_lists", "toc"])
        html = _DOC_LINK.sub(_link, md.convert(text))
        _cache[slug] = (key, {"html": html, "contents": _contents(md.toc_tokens), "title": p.title, "slug": slug})
        logger.info("Rendered Documentation page %r (%d sections)", p.title, len(_cache[slug][1]["contents"]))
    return _cache[slug][1]
