"""
platform_graph.py — Hierarchical Platform → Device → Component Model

Defines the recursive "Platform" structure and provides database CRUD for
managing the hierarchy.  Every entity in the graph carries a CPE 2.3 string
that ties it into the CPE-to-CVE matching engine.

Hierarchy
---------
  PLATFORM   — a collection of Devices (e.g. "Production Network")
  DEVICE     — a collection of Hardware and Software Components
  COMPONENT  — a HW or SW entity with a unique CPE 2.3 string

Persistence is handled via DuckDB tables created by migration 11 in
``services/database.py``.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from app.engine.cpe_validator import Cpe

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ComponentType(str, Enum):
    HARDWARE = "h"
    SOFTWARE = "a"
    OS       = "o"


# ---------------------------------------------------------------------------
# Dataclasses (in-memory graph nodes)
# ---------------------------------------------------------------------------

@dataclass
class Component:
    """A hardware or software component attached to a Device."""
    id: Optional[str] = None
    device_id: Optional[str] = None
    component_type: ComponentType = ComponentType.SOFTWARE
    name: str = ""
    version: Optional[str] = None
    vendor: Optional[str] = None
    cpe: Optional[str] = None
    source: str = "manual"
    created_at: Optional[datetime] = None

    # Lazy-parsed CPE object (cached)
    _parsed_cpe: Optional[Cpe] = field(default=None, repr=False, compare=False)

    @property
    def parsed_cpe(self) -> Optional[Cpe]:
        if self._parsed_cpe is None and self.cpe:
            self._parsed_cpe = Cpe.parse(self.cpe)
        return self._parsed_cpe

    def collect_cpes(self) -> List[str]:
        """Return a list containing this component's CPE (if any)."""
        return [self.cpe] if self.cpe else []


@dataclass
class Device:
    """A physical or virtual device within a Platform."""
    id: Optional[str] = None
    platform_id: Optional[str] = None
    name: str = ""
    device_type: str = ""          # free-form ("server", "workstation", "switch")
    cpe: Optional[str] = None      # device-level CPE (e.g. hardware CPE)
    components: List[Component] = field(default_factory=list)
    created_at: Optional[datetime] = None

    def collect_cpes(self) -> List[str]:
        """Aggregate CPEs: device CPE + all component CPEs."""
        cpes: List[str] = []
        if self.cpe:
            cpes.append(self.cpe)
        for comp in self.components:
            cpes.extend(comp.collect_cpes())
        return cpes

    def add_component(self, comp: Component) -> None:
        comp.device_id = self.id
        self.components.append(comp)


@dataclass
class Platform:
    """
    A named collection of Devices — the root of the hierarchy.

    Maps 1:1 to the existing concept of a "System" / "Environment" in
    the inventory engine, but adds recursive CPE aggregation.
    """
    id: Optional[str] = None
    name: str = ""
    description: Optional[str] = None
    classification: Optional[str] = None
    devices: List[Device] = field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def collect_cpes(self) -> List[str]:
        """Recursively collect every CPE string in the platform tree."""
        cpes: List[str] = []
        for device in self.devices:
            cpes.extend(device.collect_cpes())
        return cpes

    def add_device(self, device: Device) -> None:
        device.platform_id = self.id
        self.devices.append(device)


# ---------------------------------------------------------------------------
# Database helpers  (thin wrappers — mirror existing inventory_engine style)
# ---------------------------------------------------------------------------

def _get_conn():
    from app.services.database import get_database_service
    return get_database_service().get_connection()


# ---- Platform (maps to 'systems' table for backward compat) ----

def list_platforms() -> List[Platform]:
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, name, description, created_at, updated_at, classification "
            "FROM systems ORDER BY name"
        ).fetchall()
    return [
        Platform(id=r[0], name=r[1], description=r[2],
                 created_at=r[3], updated_at=r[4],
                 classification=r[5] if len(r) > 5 else None)
        for r in rows
    ]


def get_platform(platform_id: str) -> Optional[Platform]:
    with _get_conn() as conn:
        r = conn.execute(
            "SELECT id, name, description, created_at, updated_at, classification "
            "FROM systems WHERE id = ?", [platform_id]
        ).fetchone()
    if not r:
        return None
    return Platform(id=r[0], name=r[1], description=r[2],
                    created_at=r[3], updated_at=r[4],
                    classification=r[5] if len(r) > 5 else None)


def create_platform(name: str, description: str = "",
                    classification: str = None) -> Platform:
    with _get_conn() as conn:
        r = conn.execute(
            "INSERT INTO systems (name, description, classification) "
            "VALUES (?, ?, ?) "
            "RETURNING id, name, description, created_at, updated_at, classification",
            [name, description, classification],
        ).fetchone()
    return Platform(id=r[0], name=r[1], description=r[2],
                    created_at=r[3], updated_at=r[4],
                    classification=r[5] if len(r) > 5 else None)


def delete_platform(platform_id: str) -> bool:
    with _get_conn() as conn:
        exists = conn.execute(
            "SELECT 1 FROM systems WHERE id = ?", [platform_id]
        ).fetchone()
        if not exists:
            return False
        # Cascade: components → devices → platform
        device_ids = [
            r[0] for r in
            conn.execute("SELECT id FROM hosts WHERE system_id = ?", [platform_id]).fetchall()
        ]
        for did in device_ids:
            conn.execute("DELETE FROM software_inventory WHERE host_id = ?", [did])
        conn.execute("DELETE FROM software_inventory WHERE system_id = ?", [platform_id])
        conn.execute("DELETE FROM hosts WHERE system_id = ?", [platform_id])
        conn.execute("DELETE FROM systems WHERE id = ?", [platform_id])
    return True


# ---- Device (maps to 'hosts' table for backward compat) ----

def list_devices(platform_id: str) -> List[Device]:
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, system_id, name, ip_address, os, hardware_vendor, model, source, created_at "
            "FROM hosts WHERE system_id = ? ORDER BY name",
            [platform_id],
        ).fetchall()
    return [
        Device(id=r[0], platform_id=r[1], name=r[2],
               device_type=r[7] or "",  # source doubles as type for now
               cpe=None,               # host-level CPE not stored in legacy schema
               created_at=r[8])
        for r in rows
    ]


def get_device(device_id: str) -> Optional[Device]:
    with _get_conn() as conn:
        r = conn.execute(
            "SELECT id, system_id, name, ip_address, os, hardware_vendor, model, source, created_at "
            "FROM hosts WHERE id = ?", [device_id]
        ).fetchone()
    if not r:
        return None
    return Device(id=r[0], platform_id=r[1], name=r[2],
                  device_type=r[7] or "", created_at=r[8])


def get_device_with_components(device_id: str) -> Optional[Device]:
    """Load a Device and eagerly populate its Component list."""
    device = get_device(device_id)
    if not device:
        return None
    device.components = list_components(device_id)
    return device


def create_device(platform_id: str, name: str, device_type: str = "",
                  ip_address: str = None, os_name: str = None,
                  hardware_vendor: str = None, model: str = None,
                  cpe: str = None, source: str = "manual") -> Device:
    with _get_conn() as conn:
        r = conn.execute(
            "INSERT INTO hosts (system_id, name, ip_address, os, hardware_vendor, model, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "RETURNING id, system_id, name, ip_address, os, hardware_vendor, model, source, created_at",
            [platform_id, name, ip_address, os_name, hardware_vendor, model, source],
        ).fetchone()
    return Device(id=r[0], platform_id=r[1], name=r[2],
                  device_type=source, cpe=cpe, created_at=r[8])


def delete_device(device_id: str) -> bool:
    with _get_conn() as conn:
        exists = conn.execute("SELECT 1 FROM hosts WHERE id = ?", [device_id]).fetchone()
        if not exists:
            return False
        conn.execute("DELETE FROM software_inventory WHERE host_id = ?", [device_id])
        conn.execute("DELETE FROM hosts WHERE id = ?", [device_id])
    return True


# ---- Component (maps to 'software_inventory' table) ----

def list_components(device_id: str) -> List[Component]:
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, host_id, system_id, name, version, vendor, cpe, source, created_at "
            "FROM software_inventory WHERE host_id = ? ORDER BY name",
            [device_id],
        ).fetchall()
    return [
        Component(
            id=r[0], device_id=r[1],
            component_type=_infer_component_type(r[6]),
            name=r[3], version=r[4], vendor=r[5],
            cpe=r[6], source=r[7], created_at=r[8],
        )
        for r in rows
    ]


def add_component(device_id: str, system_id: str,
                  name: str, version: str = None,
                  vendor: str = None, cpe: str = None,
                  source: str = "manual",
                  component_type: ComponentType = ComponentType.SOFTWARE) -> Component:
    with _get_conn() as conn:
        r = conn.execute(
            "INSERT INTO software_inventory "
            "(host_id, system_id, name, version, vendor, cpe, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "RETURNING id, host_id, system_id, name, version, vendor, cpe, source, created_at",
            [device_id, system_id, name, version, vendor, cpe, source],
        ).fetchone()
    return Component(
        id=r[0], device_id=r[1],
        component_type=component_type,
        name=r[3], version=r[4], vendor=r[5],
        cpe=r[6], source=r[7], created_at=r[8],
    )


def delete_component(component_id: str) -> bool:
    with _get_conn() as conn:
        before = conn.execute(
            "SELECT COUNT(*) FROM software_inventory WHERE id = ?", [component_id]
        ).fetchone()[0]
        conn.execute("DELETE FROM software_inventory WHERE id = ?", [component_id])
    return before > 0


# ---------------------------------------------------------------------------
# Full graph loader (Platform → Devices → Components)
# ---------------------------------------------------------------------------

def load_platform_graph(platform_id: str) -> Optional[Platform]:
    """
    Load a complete Platform object with its Device and Component trees.

    This is the primary entry-point for the sync engine: it provides
    a single object whose ``collect_cpes()`` method yields every CPE
    registered under the platform.
    """
    platform = get_platform(platform_id)
    if not platform:
        return None
    platform.devices = list_devices(platform_id)
    for device in platform.devices:
        device.components = list_components(device.id)
    return platform


def load_all_platform_graphs() -> List[Platform]:
    """Load every Platform with full Device + Component trees."""
    return [load_platform_graph(p.id) for p in list_platforms()]


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _infer_component_type(cpe_str: Optional[str]) -> ComponentType:
    """Derive the component type from the ``part`` field of a CPE string."""
    if not cpe_str:
        return ComponentType.SOFTWARE
    parsed = Cpe.parse(cpe_str)
    mapping = {"h": ComponentType.HARDWARE, "o": ComponentType.OS, "a": ComponentType.SOFTWARE}
    return mapping.get(parsed.part, ComponentType.SOFTWARE)


def collect_device_cpes(device_id: str) -> List[str]:
    """Quick helper: return all CPE strings for a device without building the full graph."""
    components = list_components(device_id)
    return [c.cpe for c in components if c.cpe]


def collect_platform_cpes(platform_id: str) -> List[str]:
    """Quick helper: return all CPE strings across the entire platform."""
    cpes: List[str] = []
    for device in list_devices(platform_id):
        cpes.extend(collect_device_cpes(device.id))
    return cpes
