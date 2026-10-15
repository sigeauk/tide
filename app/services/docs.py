"""The README, rendered for Settings & Administration -> Documentation, with what's new.

README.md and CHANGELOG.md ship in the image beside the app (/app) and are TIDE's own text, so
their HTML is rendered as written. Between the README's whats-new markers (a pointer to the
CHANGELOG, for readers of the file itself) go the CHANGELOG's entries for the running major version
("What's new in TIDE 6": every 6.x.x release, newest first), so release notes are written once, in
the CHANGELOG. Rendering is cached until either file or the version changes.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional

import markdown

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[2]
README_PATH = ROOT / "README.md"
CHANGELOG_PATH = ROOT / "CHANGELOG.md"
WHATS_NEW = re.compile(r"<!-- whats-new -->.*?<!-- /whats-new -->", re.S)

_RELEASE = re.compile(r"^## \[(\d+)\.(\d+)\.(\d+)\]\s*-?\s*(.*)$")
_cache: Dict[str, object] = {"key": None, "doc": None}


def _mtime(path: Path) -> Optional[float]:
    try:
        return path.stat().st_mtime
    except OSError:
        return None


def whats_new(changelog: str, major: str) -> str:
    """Markdown for "What's new in TIDE <major>": that major's CHANGELOG entries, as written.
    Each release becomes an h3 and its Added / Changed / Fixed an h4. The CHANGELOG nests
    bullets two spaces deep; Python-Markdown needs four."""
    releases: List[str] = []
    current: Optional[List[str]] = None
    for line in changelog.splitlines():
        m = _RELEASE.match(line)
        if m:
            current = None
            if m.group(1) == major:
                when = m.group(4).strip()
                when = "not released yet" if not when or when.lower() == "unreleased" else when
                current = [f"### {m.group(1)}.{m.group(2)}.{m.group(3)} ({when})", ""]
                releases.append(current)
        elif line.startswith("## "):
            current = None
        elif current is not None:
            current.append("#" + line if line.startswith("### ") else line)
    if not releases:
        return ""
    body = "\n".join("\n".join(r).rstrip() + "\n" for r in releases)
    body = re.sub(r"^( +)(?=[-*] |\d+\. )", lambda m: m.group(1) * 2, body, flags=re.M)
    return (f"## What's new in TIDE {major}\n\n"
            f"Every change in TIDE {major}, newest release first, from TIDE's release notes "
            f"(`CHANGELOG.md`, which also lists earlier versions).\n\n{body}")


def _contents(tokens: List[Dict], depth: int = 3) -> List[Dict]:
    """The headings to ``depth`` (h2 and h3 by default), flattened for the contents list.
    The h1 is the page's own title, so it is left out."""
    out: List[Dict] = []
    for t in tokens:
        if 2 <= t["level"] <= depth:
            out.append({"id": t["id"], "name": t["name"], "level": t["level"]})
        out.extend(_contents(t.get("children", []), depth))
    return out


def readme(version: str) -> Optional[Dict]:
    """``{"html", "contents"}`` for the README with what's new in ``version``'s major, or None
    when the README isn't there."""
    key = (_mtime(README_PATH), _mtime(CHANGELOG_PATH), version)
    if key[0] is None:
        return None
    if _cache["key"] != key:
        text = README_PATH.read_text(encoding="utf-8")
        news = whats_new(CHANGELOG_PATH.read_text(encoding="utf-8"), version.split(".")[0]) if key[1] else ""
        text = WHATS_NEW.sub(lambda _: news, text)
        md = markdown.Markdown(extensions=["tables", "fenced_code", "sane_lists", "toc"])
        html = md.convert(text)
        _cache.update(key=key, doc={"html": html, "contents": _contents(md.toc_tokens)})
        logger.info("Rendered README.md and CHANGELOG.md for Documentation (%d headings)", len(_cache["doc"]["contents"]))
    return _cache["doc"]
