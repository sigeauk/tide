"""Base types for the generic CTI Connectors framework (step F).

Each vendor module (``opencti.py``, ``mandiant.py``, ``crowdstrike.py``,
...) declares a :class:`ConnectorVendor` describing how its
vendor-specific config is rendered, validated, and run. The
:mod:`app.services.cti_connectors` package exposes a small registry on
top of these so the API/UI can be schema-driven.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Protocol


@dataclass(frozen=True)
class FieldSpec:
    """Declarative description of one vendor-specific config field.

    Rendered automatically by the connectors HTMX form. Generic fields
    (label, kind, duration_period, confidence_floor,
    marking_definition) live on the ``cti_connectors`` row itself and
    are NOT declared here.
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
class SyncResult:
    """Aggregate counters returned by :meth:`ConnectorFetcher.sync`."""

    tenants: int = 0
    indicators_new: int = 0
    indicators_merged: int = 0
    indicators_review: int = 0
    actors: int = 0
    reports: int = 0
    intrusion_sets: int = 0
    relationships: int = 0
    skipped: int = 0
    errors: List[str] = field(default_factory=list)
    per_tenant: List[Dict[str, Any]] = field(default_factory=list)
    # Per-STIX-type tally of objects the upstream returned in this
    # run, before per-tenant ingest. Lets the UI/diag_sync surface
    # the volume gap between "upstream sent N objects" and "TIDE
    # ingested M indicators" (e.g. upstream may send 2.58M objects
    # of which only 1363 are indicator SDOs).
    upstream_types: Dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "tenants": self.tenants,
            "indicators_new": self.indicators_new,
            "indicators_merged": self.indicators_merged,
            "indicators_review": self.indicators_review,
            "actors": self.actors,
            "reports": self.reports,
            "intrusion_sets": self.intrusion_sets,
            "relationships": self.relationships,
            "skipped": self.skipped,
            "errors": list(self.errors),
            "per_tenant": list(self.per_tenant),
            "upstream_types": dict(self.upstream_types),
        }


class ConnectorFetcher(Protocol):
    """Callable that runs one connector against its linked tenants.

    ``connector`` is the row dict from
    :func:`DatabaseService.get_cti_connector` (``config`` already
    deserialised). ``linked_clients`` is the list of client dicts from
    :func:`DatabaseService.get_cti_connector_clients`.
    """

    def __call__(
        self,
        connector: Dict[str, Any],
        linked_clients: List[Dict[str, Any]],
    ) -> SyncResult: ...


@dataclass(frozen=True)
class ConnectorVendor:
    """Metadata + behaviour for one vendor (e.g. opencti, mandiant)."""

    name: str               # registry key, lowercase (e.g. "opencti")
    label: str              # human-readable
    icon: Optional[str] = None
    kind_default: str = "cti"   # cti | actors | both
    fields: List[FieldSpec] = field(default_factory=list)
    fetcher: Optional[ConnectorFetcher] = None
    # Optional probe callable used by the "Test connection" button.
    # Receives the full connector row dict (``config`` already
    # deserialised) and returns a dict at minimum containing
    # ``{"ok": bool, "error"?: str, ...}``. When ``None`` the
    # management endpoint falls back to a generic "no probe" message.
    tester: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None

    def field_keys(self) -> List[str]:
        return [f.key for f in self.fields]
