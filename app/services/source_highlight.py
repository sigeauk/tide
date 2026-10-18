"""Syntax colouring for a rule file's source on the library pages (the ``highlight_source`` Jinja
filter): TOML for Elastic's rules and hunting queries, YAML for Sigma's rules. Line by line, with
the query display's colour classes (``hl-field`` keys, ``hl-str`` strings, ``hl-kw`` TOML tables,
``hl-num`` numbers and booleans, ``hl-comment`` comments); multi-line strings and YAML block text
are coloured as strings throughout."""

from __future__ import annotations

import re
from typing import List

from markupsafe import Markup, escape

_TABLE = re.compile(r"^\s*\[\[?[^\]]+\]\]?\s*$")
_TOML_KEY = re.compile(r"^(\s*)([A-Za-z0-9_\-.]+|\"[^\"]*\")(\s*=\s*)(.*)$")
_YAML_KEY = re.compile(r"^(\s*(?:-\s+)?)([^\s#'\"\-][^:#]*?|\"[^\"]*\"|'[^']*')(\s*:)(?=\s|$)(.*)$")
_YAML_ITEM = re.compile(r"^(\s*-\s+)(.*)$")
_TOKEN = re.compile(
    r"(\"(?:[^\"\\]|\\.)*\"?|'[^']*'?)"                       # a string (to the end of the line if open)
    r"|((?:^|(?<=\s))#.*$)"                                    # a comment
    r"|(?<![\w.-])(true|false|null|True|False|-?\d+(?:\.\d+)?)(?![\w.-])"   # a number or boolean
)


def _span(cls: str, text: str) -> str:
    return f'<span class="hl-{cls}">{escape(text)}</span>' if text else ""


def _value(text: str) -> str:
    """A value's strings, numbers, booleans and trailing comment."""
    out: List[str] = []
    pos = 0
    for match in _TOKEN.finditer(text):
        out.append(str(escape(text[pos:match.start()])))
        string, comment, scalar = match.groups()
        out.append(_span("str", string) if string else _span("comment", comment) if comment else _span("num", scalar))
        pos = match.end()
    out.append(str(escape(text[pos:])))
    return "".join(out)


def _toml(lines: List[str]) -> List[str]:
    out: List[str] = []
    closing = ""       # the delimiter of the multi-line string the line is in, if any
    for line in lines:
        if closing:
            out.append(_span("str", line))
            if closing in line:
                closing = ""
            continue
        if _TABLE.match(line):
            out.append(_span("kw", line))
            continue
        if line.lstrip().startswith("#"):
            out.append(_span("comment", line))
            continue
        key = _TOML_KEY.match(line)
        if not key:
            out.append(_value(line))
            continue
        indent, name, eq, value = key.groups()
        for delim in ('"""', "'''"):
            if value.lstrip().startswith(delim) and value.count(delim) == 1:
                closing = delim
                break
        out.append(str(escape(indent)) + _span("field", name) + _span("op", eq)
                   + (_span("str", value) if closing else _value(value)))
    return out


def _yaml(lines: List[str]) -> List[str]:
    out: List[str] = []
    block = -1         # the indent of the key whose block text (| or >) the lines are in, if any
    for line in lines:
        indent = len(line) - len(line.lstrip())
        if block >= 0:
            if not line.strip() or indent > block:
                out.append(_span("str", line))
                continue
            block = -1
        if line.lstrip().startswith("#"):
            out.append(_span("comment", line))
            continue
        key = _YAML_KEY.match(line)
        if key:
            lead, name, colon, value = key.groups()
            if re.match(r"^\s*[|>][-+0-9]*\s*(#.*)?$", value):
                block = indent
            out.append(str(escape(lead)) + _span("field", name) + _span("op", colon) + _value(value))
            continue
        item = _YAML_ITEM.match(line)
        if item:
            out.append(str(escape(item.group(1))) + _value(item.group(2)))
            continue
        out.append(_value(line))
    return out


def highlight(source: str, language: str) -> Markup:
    """``source`` as HTML with its syntax coloured; ``language`` is ``toml`` or ``yaml`` (anything
    else is returned escaped, uncoloured)."""
    if not source:
        return Markup("")
    lines = str(source).split("\n")
    lang = (language or "").lower()
    if lang == "toml":
        return Markup("\n".join(_toml(lines)))
    if lang in ("yaml", "yml"):
        return Markup("\n".join(_yaml(lines)))
    return Markup(escape(source))
