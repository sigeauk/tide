"""TIDE's icons for HTML built in Python (a few routes build theirs as strings), from the same
macros the templates use (macros/icons.html, macros/modal.html), so an icon is drawn one way
everywhere. Scripts get the same icons from TIDE.icon() (app.js)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

_TEMPLATES = Path(__file__).resolve().parents[1] / "templates"


@lru_cache(maxsize=1)
def _env() -> Environment:
    return Environment(loader=FileSystemLoader(str(_TEMPLATES)), autoescape=True)


def icon(name: str, size: str = "16", cls: str = "") -> str:
    """An icon's SVG, as ``{{ icon(name, size, cls) }}`` gives it."""
    return str(_env().get_template("macros/icons.html").module.icon(name, size, cls)).strip()


def close_button(attrs: str, label: str = "Close") -> str:
    """A dialog's close X, as ``{{ close_button(attrs) }}`` gives it."""
    return str(_env().get_template("macros/modal.html").module.close_button(attrs, label)).strip()


def icon_text(name: str, text: str, size: str = "16") -> str:
    """An icon then its words, as ``{{ icon_text(name, text, size) }}`` gives it."""
    return str(_env().get_template("macros/icons.html").module.icon_text(name, text, size)).strip()


def empty_state(icon_name: str, title: str, text: str = "") -> str:
    """A list or tab with nothing to show, as ``{% call empty_state(icon_name) %}`` draws it: what is
    missing, then (optionally) what to do. ``title`` and ``text`` are escaped."""
    from markupsafe import escape
    body = f'<p class="empty-state-title">{escape(title)}</p>' + (f"<p>{escape(text)}</p>" if text else "")
    tpl = _env().from_string('{% from "macros/modal.html" import empty_state %}'
                             '{% call empty_state(n) %}{{ body | safe }}{% endcall %}')
    return tpl.render(n=icon_name, body=body).strip()
