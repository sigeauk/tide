"""TIDE's guide and its changelog, rendered for Settings & Administration.

The guide is the README plus the documents in docs/, a page each (PAGES), grouped by who reads
them (GROUPS: about TIDE, using TIDE, detection engineering, administration, reference). Documentation opens
on a landing page of those groups; each page sits in one sidebar beside its sections, and
search_index() lets the sidebar's search find any section of any page. A page with no file yet
is listed as coming. Changelog is the CHANGELOG's entries for the running major version (every
6.x.x release while on 6), newest first, so release notes are written once, in the CHANGELOG. All
of them ship in the image beside the app (/app) and are TIDE's own text, so their HTML is rendered
as written. Links between them (docs/API.md, ../README.md, CHANGELOG.md, with any #section) are
pointed at their pages here. Rendering is cached until a file or the version changes.

A page may lay out a part in HTML (TIDE at a glance does, with TIDE's own cards, metric cards and
tags); an icon there is written ``<tide-icon name="…" size="…"></tide-icon>`` and drawn as TIDE's
own SVG (app.services.icons), never a character or an image. ``<tide-figures source="…"
metrics="…"></tide-figures>`` is the reader's own figures, a Dashboard section's cards for the
active client, drawn each time the page is shown (``live``), not cached with the page.
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
    slug: str              # its address under /settings/docs
    title: str
    path: Optional[Path]   # None for the Changelog (built from the CHANGELOG) and a page still to come
    group: str = ""        # GROUPS key
    summary: str = ""      # one line on the landing page


# Who reads what: (key, heading, icon, what it covers), in the sidebar's (and landing page's) order.
GROUPS = [
    ("about", "About TIDE", "lightbulb", "Why TIDE is needed and what it achieves for your team, with your own figures."),
    ("use", "Using TIDE", "monitor", "Working with systems, baselines, coverage and threat intelligence day to day."),
    ("engineer", "Detection engineering", "shield-check", "Your rules: their health, editing, moving and merging, and Elastic's and the Sigma rules."),
    ("admin", "Administration", "settings", "Installing TIDE, setting up clients, configuring and running it."),
    ("reference", "Reference", "code", "Connecting other tools to TIDE."),
]
DOCS = ROOT / "docs"
# The guide's pages, by group, in the sidebar's order.
PAGES: List[Page] = [
    Page("at-a-glance", "TIDE at a glance", DOCS / "AT_A_GLANCE.md", "about", "What TIDE does for your team, with your own figures, and how to get the most from it."),
    Page("getting-started", "Getting started", DOCS / "GETTING_STARTED.md", "use", "Signing in, choosing a client, and the controls every page shares."),
    Page("systems", "Systems & baselines", DOCS / "SYSTEMS.md", "use", "Systems, baselines and their techniques, coverage, risks, devices and CVEs."),
    Page("threats", "Threat intelligence", DOCS / "THREATS.md", "use", "Threat Landscape, the Heatmap and the MITRE pages."),
    Page("rules", "Rules", DOCS / "RULES.md", "engineer", "Rule Health, the rule window, Move, Compare and Merge, and upstream updates."),
    Page("libraries", "Sigma, Elastic & Hunting", DOCS / "LIBRARIES.md", "engineer", "Converting and deploying Elastic's and the Sigma rules, and running hunts."),
    Page("install", "Installing TIDE", ROOT / "README.md", "admin", "What TIDE needs, and installing it."),
    Page("clients", "Setting up clients", DOCS / "CLIENTS.md", "admin", "Clients, their SIEMs, users, scoring and threat feeds."),
    Page("configuration", "Configuration", DOCS / "CONFIGURATION.md", "admin", "Settings, certificates, single sign-on, users and roles."),
    Page("operations", "Operations", DOCS / "OPERATIONS.md", "admin", "Syncing, backups and upgrades, moving hosts, disk space, Diagnostics."),
    Page("api", "External Query API", DOCS / "API.md", "reference", "Querying a client's data from other tools."),
]
PAGES_BY_SLUG = {p.slug: p for p in PAGES}
CHANGELOG = Page("changelog", "Changelog", None)   # its own tab, /settings/changelog
# A link to one of these files, from the README or from docs/, goes to its page.
_FILE_URLS = {"README": "/settings/docs/install", "CONFIGURATION": "/settings/docs/configuration",
              "OPERATIONS": "/settings/docs/operations", "API": "/settings/docs/api",
              "GETTING_STARTED": "/settings/docs/getting-started", "SYSTEMS": "/settings/docs/systems",
              "THREATS": "/settings/docs/threats", "RULES": "/settings/docs/rules",
              "LIBRARIES": "/settings/docs/libraries", "CLIENTS": "/settings/docs/clients",
              "AT_A_GLANCE": "/settings/docs/at-a-glance",
              "CHANGELOG": "/settings/changelog"}
_DOC_LINK = re.compile(r'href="(?:\.\./)?(?:docs/)?(' + "|".join(_FILE_URLS) + r')\.md(#[^"]*)?"')


def nav() -> List[Dict]:
    """The guide's groups with their pages, in the sidebar's order."""
    return [{"key": k, "title": t, "icon": i, "about": a, "pages": [p for p in PAGES if p.group == k]}
            for k, t, i, a in GROUPS]


_ICON = re.compile(r'<tide-icon name="([a-z0-9-]+)"(?: size="(\d+)")?\s*>\s*</tide-icon>')
_FIGURES = re.compile(r'<tide-figures source="([a-z_]+)" metrics="([a-z_,]+)"\s*>\s*</tide-figures>')
_OWN_NAV = re.compile(r'<p><a href="/settings/docs/install">[^<]*Back to the README</a></p>\s*|<p><strong>Contents:</strong>.*?</p>\s*(?:<hr\s*/?>\s*)?', re.S)
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


def _icon(match: re.Match) -> str:
    from app.services import icons
    return icons.icon(match.group(1), match.group(2) or "16")


def live(doc: Dict, draw) -> Dict:
    """``doc`` with its ``<tide-figures>`` drawn by ``draw(source, metrics)`` (HTML, or "" to leave
    them out: no client, or a page the reader may not open)."""
    if "<tide-figures" not in doc["html"]:
        return doc
    return {**doc, "html": _FIGURES.sub(lambda m: draw(m.group(1), m.group(2).split(",")) or "", doc["html"])}


def page(slug: str, version: str) -> Optional[Dict]:
    """``{"html", "contents", "title", "slug"}`` for a page of the guide, or for the Changelog
    (slug "changelog"); None when there is no such page or its file isn't in this installation."""
    p = CHANGELOG if slug == CHANGELOG.slug else PAGES_BY_SLUG.get(slug)
    if p is None or (p is not CHANGELOG and p.path is None):     # no such page, or one still to come
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
        html = _ICON.sub(_icon, html)
        # The sidebar is the way round the guide in TIDE: a document's own "Back to the README"
        # and "Contents:" lines (for reading the files elsewhere) are left out here.
        html = _OWN_NAV.sub("", html)
        _cache[slug] = (key, {"html": html, "contents": _contents(md.toc_tokens), "title": p.title, "slug": slug})
        logger.info("Rendered Documentation page %r (%d sections)", p.title, len(_cache[slug][1]["contents"]))
    return _cache[slug][1]


_SECTION = re.compile(r'<h([123]) id="([^"]+)">(.*?)</h[123]>', re.S)
_TAG = re.compile(r"<[^>]+>")

# Each page's ? (macros/help.html): the guide's (page, section) on that page, by the page's name.
HELP = {
    "dashboard": ("getting-started", "dashboards"),
    "systems": ("systems", "the-systems-page"),
    "system": ("systems", "a-systems-page"),
    "baselines": ("systems", "baseline-templates"),
    "cves": ("systems", "devices-and-cves"),
    "rule-health": ("rules", "rule-health"),
    "rule-monitoring": ("rules", "rule-monitoring"),
    "sigma": ("libraries", "sigma-rules"),
    "elastic": ("libraries", "elastic-rules"),
    "hunting": ("libraries", "hunting"),
    "threat-landscape": ("threats", "threat-landscape"),
    "heatmap": ("threats", "heatmap"),
    "mitre": ("threats", "the-mitre-pages"),
    "nist": ("threats", "nist-800-53"),
    "clients": ("clients", "the-order-to-set-things-up"),
    "client": ("clients", "link-destinations-to-a-client"),
}


def help_section(topic: str, version: str) -> Optional[Dict]:
    """``{"title", "html", "page", "url"}``: the guide's section for a page's ? (HELP), up to the
    next heading of its level or above, with its links to the rest of the page made whole."""
    slug, sid = HELP.get(topic, (None, None))
    doc = page(slug, version) if slug else None
    if not doc:
        return None
    html = doc["html"]
    marks = list(_SECTION.finditer(html))
    at = next((i for i, m in enumerate(marks) if m.group(2) == sid), None)
    if at is None:
        return None
    level = int(marks[at].group(1))
    end = next((m.start() for m in marks[at + 1:] if int(m.group(1)) <= level), len(html))
    body = html[marks[at].end():end].replace('href="#', f'href="/settings/docs/{slug}#')
    title = re.sub(r"\s+", " ", _TAG.sub("", marks[at].group(3))).strip()
    return {"title": title, "html": body, "page": doc["title"], "url": f"/settings/docs/{slug}#{sid}"}


def search_index(version: str) -> List[Dict]:
    """Every section of every written page, for the sidebar's search: ``{slug, page, section, id,
    text}`` (text: the section's words, tags stripped)."""
    out: List[Dict] = []
    for p in PAGES:
        doc = page(p.slug, version) if p.path else None
        if not doc:
            continue
        html = doc["html"]
        marks = list(_SECTION.finditer(html))
        for i, m in enumerate(marks):
            body = html[m.end():marks[i + 1].start() if i + 1 < len(marks) else len(html)]
            text = re.sub(r"\s+", " ", _TAG.sub(" ", body)).strip()
            title = re.sub(r"\s+", " ", _TAG.sub("", m.group(3))).strip()
            out.append({"slug": p.slug, "page": p.title, "section": title, "id": "" if m.group(1) == "1" else m.group(2),
                        "text": text})
    return out
