"""
Pydantic models for Threat Intelligence and MITRE ATT&CK data.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from datetime import datetime
from enum import Enum


class CoverageStatus(str, Enum):
    """TTP coverage status for heatmap."""
    GAP = "gap"           # Adversary uses, no detection
    COVERED = "covered"   # Adversary uses, detection exists
    DEFENSE = "defense"   # Detection exists, adversary doesn't use (defense in depth)


class MITRETechnique(BaseModel):
    """MITRE ATT&CK Technique."""
    id: str  # e.g., T1078
    name: str
    tactic: str  # e.g., "initial-access"
    url: Optional[str] = None
    
    @property
    def tactic_display(self) -> str:
        """Convert tactic slug to display name."""
        mapping = {
            "initial-access": "Initial Access",
            "execution": "Execution",
            "persistence": "Persistence",
            "privilege-escalation": "Privilege Escalation",
            "defense-evasion": "Defense Evasion",
            "credential-access": "Credential Access",
            "discovery": "Discovery",
            "lateral-movement": "Lateral Movement",
            "collection": "Collection",
            "command-and-control": "Command and Control",
            "exfiltration": "Exfiltration",
            "impact": "Impact",
            "reconnaissance": "Reconnaissance",
            "resource-development": "Resource Development",
        }
        return mapping.get(self.tactic.lower(), self.tactic)


class ThreatActor(BaseModel):
    """Threat actor from CTI sources."""
    name: str
    description: Optional[str] = None
    ttps: List[str] = Field(default_factory=list)
    ttp_count: int = 0
    aliases: Optional[str] = None
    origin: Optional[str] = None  # Country/region
    source: List[str] = Field(default_factory=list)  # Data sources (OpenCTI, etc.)
    last_updated: Optional[datetime] = None
    
    @property
    def alias_list(self) -> List[str]:
        """Parse aliases string into list."""
        if not self.aliases:
            return []
        return [a.strip() for a in self.aliases.split(",")]


class HeatmapCell(BaseModel):
    """Single cell in the MITRE ATT&CK heatmap."""
    id: str  # Technique ID (e.g., T1078)
    name: str  # Technique name
    tactic: str  # Tactic slug
    status: CoverageStatus
    actors: List[str] = Field(default_factory=list)  # Actors using this TTP
    rule_count: int = 0  # Number of detection rules covering this technique
    
    @property
    def css_class(self) -> str:
        """CSS class for styling."""
        return f"status-{self.status.value}"
    
    @property
    def tooltip(self) -> str:
        """Tooltip text for cell."""
        status_text = {
            CoverageStatus.GAP: "CRITICAL GAP: No rules found",
            CoverageStatus.COVERED: "COVERED: Rules exist",
            CoverageStatus.DEFENSE: "Defense in Depth",
        }
        actors_str = ", ".join(self.actors) if self.actors else "N/A"
        return f"{self.name} | {status_text[self.status]} | Used by: {actors_str}"


class HeatmapData(BaseModel):
    """Complete heatmap data for rendering."""
    tactics: List[str]  # Ordered tactic names
    matrix: Dict[str, List[HeatmapCell]]  # Tactic -> cells mapping
    
    # Metrics
    selected_actors: List[str]
    total_ttps: int
    gap_count: int
    covered_count: int
    defense_count: int
    coverage_pct: int


class ThreatLandscapeMetrics(BaseModel):
    """Aggregated threat landscape statistics."""
    total_actors: int = 0
    total_ttps: int = 0  # Sum of all TTPs
    unique_ttps: int = 0
    avg_ttps_per_actor: float = 0.0
    
    # Coverage
    covered_ttps: int = 0
    uncovered_ttps: int = 0
    global_coverage_pct: float = 0.0
    
    # Breakdowns
    origin_breakdown: Dict[str, int] = Field(default_factory=dict)
    source_breakdown: Dict[str, int] = Field(default_factory=dict)
    
    # Actor coverage tiers
    fully_covered_actors: int = 0
    partially_covered_actors: int = 0
    uncovered_actors: int = 0
