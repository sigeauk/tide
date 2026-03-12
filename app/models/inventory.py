"""
Pydantic models for the Asset Inventory / CVE mapping feature.

Architecture:
  System   = Enterprise Environment (e.g. "Company A", "Client Network 1")
  Host     = Individual machine within an environment (e.g. DC-PROD-01)
  Software = Installed package attached to a specific Host
"""

from pydantic import BaseModel, Field
from typing import Dict, Optional, List
from datetime import datetime


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

class Classification(BaseModel):
    id: Optional[str] = None
    name: str
    color: str = "#6b7280"


# ---------------------------------------------------------------------------
# System (Enterprise Environment)
# ---------------------------------------------------------------------------

class System(BaseModel):
    """An Enterprise Environment container (e.g. a client, site, or network segment)."""
    id: Optional[str] = None
    name: str
    description: Optional[str] = None
    classification: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class SystemCreate(BaseModel):
    name: str
    description: Optional[str] = None
    classification: Optional[str] = None


class SystemUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    classification: Optional[str] = None


# ---------------------------------------------------------------------------
# Host (Individual Machine)
# ---------------------------------------------------------------------------

class Host(BaseModel):
    """A single physical or virtual host within a System/Environment."""
    id: Optional[str] = None
    system_id: str
    name: str                           # hostname, e.g. DC-PROD-01
    ip_address: Optional[str] = None
    os: Optional[str] = None
    hardware_vendor: Optional[str] = None
    model: Optional[str] = None
    source: str = "manual"              # "manual" | "nessus"
    created_at: Optional[datetime] = None


class HostCreate(BaseModel):
    name: str
    ip_address: Optional[str] = None
    os: Optional[str] = None
    hardware_vendor: Optional[str] = None
    model: Optional[str] = None
    source: str = "manual"


class HostSummary(BaseModel):
    """Host with aggregated vulnerability status for the environment detail view."""
    host: Host
    software_count: int
    vuln_count: int
    detected_count: int = 0             # CVEs that have at least one detection rule
    software_names: List[str] = Field(default_factory=list)  # for context-aware search


# ---------------------------------------------------------------------------
# Software Inventory (attached to Host)
# ---------------------------------------------------------------------------

class SoftwareInventory(BaseModel):
    """A software package installed on a given host."""
    id: Optional[str] = None
    host_id: Optional[str] = None
    system_id: Optional[str] = None     # legacy field, kept for backward compat
    name: str
    version: Optional[str] = None
    vendor: Optional[str] = None
    cpe: Optional[str] = None
    source: str = "manual"              # "manual" | "nessus" | "opencti"
    created_at: Optional[datetime] = None


class SoftwareCreate(BaseModel):
    name: str
    version: Optional[str] = None
    vendor: Optional[str] = None
    cpe: Optional[str] = None
    source: str = "manual"


class HostUpdate(BaseModel):
    name: Optional[str] = None
    ip_address: Optional[str] = None
    os: Optional[str] = None
    hardware_vendor: Optional[str] = None
    model: Optional[str] = None


class SoftwareUpdate(BaseModel):
    name: Optional[str] = None
    version: Optional[str] = None
    vendor: Optional[str] = None
    cpe: Optional[str] = None


# ---------------------------------------------------------------------------
# CISA KEV & CVE Matching
# ---------------------------------------------------------------------------

class CisaKevEntry(BaseModel):
    """A single entry from the CISA Known Exploited Vulnerabilities catalogue."""
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str = ""
    required_action: str = ""
    due_date: str
    known_ransomware_campaign_use: str = "Unknown"
    notes: Optional[str] = None


class MitreTechnique(BaseModel):
    """A MITRE ATT&CK technique linked to a CVE."""
    technique_id: str                   # e.g. T1190
    name: str = ""
    has_detection: bool = False         # True if we have a Sigma rule for this technique
    rule_count: int = 0


class AffectedHost(BaseModel):
    """A host that has been matched against a CVE in the KEV catalogue."""
    host_id: str
    name: str
    ip_address: Optional[str] = None
    system_id: str
    system_name: str
    coverage_status: str = "red"        # 'green' | 'red' | 'amber'
    software_count: int = 0
    source: str = "manual"
    applied_rule_names: List[str] = Field(default_factory=list)  # rule names providing coverage

    @property
    def display_label(self) -> str:
        return f"{self.name} ({self.system_name})"


class AppliedDetection(BaseModel):
    """Tier 3: A detection rule applied to a specific system or host."""
    id: Optional[str] = None
    detection_id: str
    system_id: Optional[str] = None
    host_id: Optional[str] = None
    applied_at: Optional[datetime] = None


class VulnDetection(BaseModel):
    """A detection rule recorded against a CVE (does not imply coverage)."""
    id: Optional[str] = None
    cve_id: str
    rule_ref: Optional[str] = None      # e.g. Sigma rule title or ID
    note: Optional[str] = None          # free-text note about the detection
    source: str = "manual"               # "manual" | "technique"
    created_at: Optional[datetime] = None
    applied_to: List["AppliedDetection"] = Field(default_factory=list)  # Tier 3 applications


class CveMatch(BaseModel):
    """
    A CVE entry from the CISA KEV.
    In overview mode: always present (all KEV), affected_hosts lists matched hosts.
    In host mode: only entries matching the host's software.
    """
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    short_description: str = ""
    date_added: str
    due_date: str
    known_ransomware: bool
    notes: Optional[str] = None
    matched_software: List[str] = Field(default_factory=list)
    affected_hosts: List["AffectedHost"] = Field(default_factory=list)
    techniques: List[MitreTechnique] = Field(default_factory=list)
    threat_actors: List[str] = Field(default_factory=list)          # actor names from OpenCTI
    detections: List["VulnDetection"] = Field(default_factory=list)     # detection rules recorded


class InventoryStats(BaseModel):
    """Aggregated statistics for the asset inventory dashboard widget."""
    environment_count: int = 0
    host_count: int = 0
    software_count: int = 0
    unique_vuln_count: int = 0          # distinct CVE IDs matched across all hosts
    affected_host_count: int = 0        # hosts with at least one KEV match
    last_scan: Optional[str] = None     # ISO date of most recently added host


class CveOverviewStats(BaseModel):
    """Aggregated stats shown in the CVE Overview header cards."""
    total_kev: int = 0
    matched_count: int = 0             # KEV entries with >= 1 affected host
    affected_hosts: int = 0            # distinct hosts with any match
    ransomware_count: int = 0          # KEV entries flagged as ransomware
    detected_count: int = 0            # CVEs with a VulnDetection entry
    ransomware_undetected: int = 0     # ransomware CVEs with no detection


# ---------------------------------------------------------------------------
# System Summary (dashboard cards)
# ---------------------------------------------------------------------------

class SystemSummary(BaseModel):
    """System with aggregated host/vulnerability counts for the dashboard."""
    system: System
    host_count: int
    vuln_count: int
    software_count: int = 0
    worst_status: str = "green"         # 'green' | 'amber' | 'red' (worst-case RAG across all hosts)


# ---------------------------------------------------------------------------
# Hierarchical Platform Model (CPE-to-CVE Engine)
# ---------------------------------------------------------------------------

class ComponentModel(BaseModel):
    """A hardware or software component attached to a Device."""
    id: Optional[str] = None
    device_id: Optional[str] = None
    component_type: str = "a"           # "h" (HW), "a" (SW), "o" (OS)
    name: str
    version: Optional[str] = None
    vendor: Optional[str] = None
    cpe: Optional[str] = None
    source: str = "manual"
    created_at: Optional[datetime] = None


class ComponentCreate(BaseModel):
    name: str
    version: Optional[str] = None
    vendor: Optional[str] = None
    cpe: Optional[str] = None
    source: str = "manual"
    component_type: str = "a"


class DeviceModel(BaseModel):
    """A physical or virtual device within a Platform."""
    id: Optional[str] = None
    platform_id: Optional[str] = None
    name: str
    device_type: str = ""
    cpe: Optional[str] = None
    components: List[ComponentModel] = Field(default_factory=list)
    created_at: Optional[datetime] = None


class DeviceCreate(BaseModel):
    name: str
    device_type: str = ""
    ip_address: Optional[str] = None
    os: Optional[str] = None
    hardware_vendor: Optional[str] = None
    model: Optional[str] = None
    cpe: Optional[str] = None
    source: str = "manual"


class PlatformModel(BaseModel):
    """
    A named collection of Devices — the root of the hierarchy.
    Maps to the existing System / Environment concept.
    """
    id: Optional[str] = None
    name: str
    description: Optional[str] = None
    classification: Optional[str] = None
    devices: List[DeviceModel] = Field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class PlatformCreate(BaseModel):
    name: str
    description: Optional[str] = None
    classification: Optional[str] = None
