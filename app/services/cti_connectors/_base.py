"""Base types for the CTI Connectors framework.

Each vendor module declares a :class:`ConnectorVendor` describing how its
vendor-specific config is rendered and validated, and how its Test button
probes it. The :mod:`app.services.cti_connectors` package exposes a small
registry on top of these so the API/UI can be schema-driven.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass(frozen=True)
class FieldSpec:
    """Declarative description of one vendor-specific config field.

    Rendered automatically by the connectors HTMX form. Generic fields
    (label, is_active) live on the ``cti_connectors`` row itself and are
    NOT declared here.
    """

    key: str
    label: str
    type: str = "text"          # text | password | url | number | bool | select | textarea
    required: bool = False
    default: Any = None
    secret: bool = False         # mask in UI + redact in logs
    help: Optional[str] = None
    options: Optional[List[str]] = None  # for type=select


@dataclass(frozen=True)
class ConnectorVendor:
    """Metadata + behaviour for one vendor."""

    name: str               # registry key, lowercase (e.g. "opencti_taxii")
    label: str              # human-readable
    icon: Optional[str] = None
    fields: List[FieldSpec] = field(default_factory=list)
    # Optional probe callable used by the "Test connection" button.
    # Receives the full connector row dict (``config`` already
    # deserialised) and returns a dict at minimum containing
    # ``{"ok": bool, "error"?: str, "message"?: str}``. When ``None`` the
    # management endpoint falls back to a generic "no probe" message.
    tester: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None

    def field_keys(self) -> List[str]:
        return [f.key for f in self.fields]
