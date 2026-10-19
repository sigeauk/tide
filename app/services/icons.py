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
