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

    @property
    def display_label(self) -> str:
        return f"{self.name} ({self.system_name})"


class VulnDetection(BaseModel):
    """Marks a CVE as having a detection in place (manually asserted)."""
    cve_id: str
    system_id: str = ""                 # empty = applies to all systems
    note: Optional[str] = None          # free-text note about the detection
    rule_ref: Optional[str] = None      # e.g. Sigma rule title or ID
    created_at: Optional[datetime] = None


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
    detection: Optional["VulnDetection"] = None        # any detection exists (for overview badge)
    system_detections: Dict[str, "VulnDetection"] = Field(default_factory=dict)  # system_id -> detection


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
