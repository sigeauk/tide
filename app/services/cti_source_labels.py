"""Central display-label helpers for ``threat_actors.source`` values.

The ``source`` column on ``threat_actors`` stores raw strings written by
the various ingest paths:

- MITRE STIX loader writes ``"MITRE: enterprise"``, ``"MITRE: mobile"``,
  ``"MITRE: ics"``, ``"MITRE: pre"`` (see ``cti_helper.process_stix_bundle``).
- OpenCTI sync writes ``"OCTI"``.
- Older imports may have written ``"opencti"``, ``"open-cti"``,
  ``"mitre:enterprise"`` (no space), ``"mitre-enterprise"``, etc.

The Threat Landscape and Heatmap source filters historically did their
own normalisation inline, which drifted between pages and silently failed
for case variants (e.g. the template only matched the literal ``"OCTI"``).
This module is the single source of truth so the filter dropdown shows
the same human-friendly labels everywhere.

The filter VALUE sent to ``/api/threats`` must remain the raw DB string,
because ``api/threats.list_threats`` filters with ``source in a.source``
against the literal list contents. The helper therefore returns
``(raw_value, display_label)`` pairs so the template can render
``<option value="{{ raw }}">{{ label }}</option>``.
"""
from __future__ import annotations

from typing import Iterable, List, Tuple

# Lowercased canonical forms -> display label.
_DISPLAY_MAP = {
    "octi": "OpenCTI",
    "opencti": "OpenCTI",
    "open-cti": "OpenCTI",
    "mitre": "MITRE",
    "mitre:enterprise": "MITRE Enterprise",
    "mitre: enterprise": "MITRE Enterprise",
    "mitre-enterprise": "MITRE Enterprise",
    "mitre:mobile": "MITRE Mobile",
    "mitre: mobile": "MITRE Mobile",
    "mitre-mobile": "MITRE Mobile",
    "mitre:ics": "MITRE ICS",
    "mitre: ics": "MITRE ICS",
    "mitre-ics": "MITRE ICS",
    "mitre:pre": "MITRE PRE",
    "mitre: pre": "MITRE PRE",
    "mitre-pre": "MITRE PRE",
    "enterprise": "MITRE Enterprise",
    "mobile": "MITRE Mobile",
    "ics": "MITRE ICS",
    "pre": "MITRE PRE",
}


def display_label(raw: str) -> str:
    """Return the human-friendly label for a raw ``source`` string.

    Unknown values are returned title-cased so they still render cleanly
    in the dropdown (e.g. a future ``"abuse-ch"`` becomes ``"Abuse-Ch"``)
    without requiring a code change to ship.
    """
    if not raw:
        return ""
    key = raw.strip().lower()
    if key in _DISPLAY_MAP:
        return _DISPLAY_MAP[key]
    # Fallback: keep MITRE-style prefixes recognisable; otherwise title-case.
    if key.startswith("mitre"):
        return raw.strip()
    return raw.strip().title()


def filter_options(raw_sources: Iterable[str]) -> List[Tuple[str, str]]:
    """Build the ``[(value, label), ...]`` list for the source dropdown.

    Sorted by label so OpenCTI / MITRE families group naturally.
    Duplicate labels collapse to the first raw value seen, so when the DB
    contains both ``"OCTI"`` and a legacy ``"opencti"`` row the dropdown
    shows a single ``"OpenCTI"`` entry. The filter value sent to the API
    is the canonical raw string DuckDB actually holds, so the
    ``source in a.source`` check in ``api/threats.list_threats`` still
    matches.
    """
    seen: dict[str, str] = {}
    for raw in raw_sources:
        if not raw:
            continue
        label = display_label(raw)
        if label not in seen:
            seen[label] = raw
    return sorted(((raw, label) for label, raw in seen.items()),
                  key=lambda pair: pair[1].lower())
