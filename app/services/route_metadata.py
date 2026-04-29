"""
4.1.0 P5 — Breadcrumb registry and per-request crumb resolution.

The Plan §5 design: every page declares its breadcrumb trail in ONE
place (this module), keyed by the FastAPI route path. The
``RequestContextMiddleware`` in ``log_context.py`` calls
:func:`resolve_crumbs` for each request and stashes the result on
``request.state.crumbs``; ``app.main.create_app`` exposes a
``crumbs`` Jinja global that pulls from there. Templates render via the
``components/ui/breadcrumb.html`` macro.

Why a static registry instead of decorators on every endpoint:
  * Breadcrumbs describe *navigation*, not *handler logic* — they belong
    near the routing config, not scattered across handler bodies.
  * Detail pages need to interpolate a dynamic title (e.g.
    "Baselines › <name>"). Handlers can override per-request via
    ``set_crumbs(request, [...])`` for that case; the static fallback
    still kicks in if the handler forgets.
  * No FastAPI dep on the registry — keeps the audit story for P2 simple
    (this module never touches DB).

Crumb shape: ``(label: str, href: str | None)``. Trailing crumb's href
should be None so the renderer styles it as the current page.
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

# (label, href). href=None ⇒ current page (rendered without anchor).
Crumb = Tuple[str, Optional[str]]


# Static path → crumb-trail registry. Keep alphabetical inside each
# section so adding new pages stays low-conflict.
_HOME: Crumb = ("Home", "/")

_REGISTRY: dict = {
    "/":               [("Home", None)],
    "/dashboard":      [_HOME, ("Dashboard", None)],
    "/heatmap":        [_HOME, ("Heatmap", None)],
    "/threats":        [_HOME, ("Threats", None)],
    "/rules":          [_HOME, ("Rules", None)],
    "/promotion":      [_HOME, ("Promotion", None)],
    "/sigma":          [_HOME, ("Sigma Library", None)],
    "/attack-tree":    [_HOME, ("Attack Tree", None)],
    "/baselines":      [_HOME, ("Baselines", None)],
    "/systems":        [_HOME, ("Systems", None)],
    "/cve-overview":   [_HOME, ("CVE Catalogue", None)],
    "/clients":        [_HOME, ("Clients", None)],
    "/management":     [_HOME, ("Management", None)],
    "/settings":       [_HOME, ("Settings", None)],
    "/preferences":    [_HOME, ("Preferences", None)],
    "/presentation":   [_HOME, ("Presentation", None)],
}

# Path-prefix fallbacks for parametric routes are intentionally NOT
# defined: detail pages render their own breadcrumb via the
# `breadcrumb(items=...)` macro so they can interpolate the entity
# name. base.html only auto-renders for static-mapped routes, so the
# detail page's inline breadcrumb is the sole source of truth and we
# avoid double-rendering.


def resolve_crumbs(path: str) -> List[Crumb]:
    """Return the static crumb trail for *path*, or [] if unmapped."""
    return list(_REGISTRY.get(path, []))


def set_crumbs(request, crumbs: Sequence[Crumb]) -> None:
    """Override the static trail for the current request. Handlers call
    this when they need to interpolate a dynamic label, e.g.::

        set_crumbs(request, [
            ("Home", "/"),
            ("Baselines", "/baselines"),
            (baseline.name, None),
        ])

    Safe to call from anywhere that holds the FastAPI ``Request`` object.
    """
    request.state.crumbs = list(crumbs)


def get_crumbs(request) -> List[Crumb]:
    """Read crumbs for the current request: handler override → static
    registry → empty. Called by the Jinja ``crumbs`` global."""
    override = getattr(request.state, "crumbs", None)
    if override is not None:
        return override
    return resolve_crumbs(request.url.path)
