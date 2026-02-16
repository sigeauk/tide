"""
Pydantic models for Detection Rules and Rule Health metrics.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    """Rule severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleLanguage(str, Enum):
    """Detection rule query languages."""
    KUERY = "kuery"
    KQL = "kql"
    EQL = "eql"
    ESQL = "esql"
    LUCENE = "lucene"


class ValidationRecord(BaseModel):
    """Record of rule validation by an analyst."""
    rule_name: str
    checked_by: str
    last_checked_on: datetime
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.strftime("%Y-%m-%dT%H:%M:%SZ")
        }


class DetectionRule(BaseModel):
    """Detection rule from Elastic Security."""
    rule_id: str
    name: str
    severity: Severity = Severity.LOW
    author: str = "Unknown"
    enabled: bool = True
    space: str = "default"
    
    # Quality scores
    score: int = Field(default=0, ge=0, le=100)
    quality_score: int = 0
    meta_score: int = 0
    
    # Component scores
    score_mapping: int = Field(default=0, ge=0, le=20)
    score_field_type: int = Field(default=0, ge=0, le=11)
    score_search_time: int = Field(default=0, ge=0, le=10)
    score_language: int = Field(default=0, ge=0, le=9)
    score_note: int = Field(default=0, ge=0, le=20)
    score_override: int = Field(default=0, ge=0, le=5)
    score_tactics: int = Field(default=0, ge=0, le=3)
    score_techniques: int = Field(default=0, ge=0, le=7)
    score_author: int = Field(default=0, ge=0, le=5)
    score_highlights: int = Field(default=0, ge=0, le=10)
    
    # Metadata
    mitre_ids: List[str] = Field(default_factory=list)
    last_updated: Optional[datetime] = None
    raw_data: Optional[Dict[str, Any]] = None
    
    # Computed fields (set during retrieval)
    validation_date: Optional[datetime] = None
    validated_by: Optional[str] = None
    validation_status: str = "never"  # never, valid, expired
    
    @property
    def language(self) -> str:
        """Extract language from raw_data."""
        if self.raw_data:
            return self.raw_data.get("language", "kuery")
        return "kuery"
    
    @property
    def query(self) -> str:
        """Extract query from raw_data."""
        if self.raw_data:
            return self.raw_data.get("query", "")
        return ""
    
    @property
    def field_mappings(self) -> List[Dict[str, Any]]:
        """Extract field mapping results from raw_data."""
        if self.raw_data:
            return self.raw_data.get("results", [])
        return []
    
    def score_color(self) -> str:
        """CSS color class based on score."""
        if self.score >= 80:
            return "success"
        elif self.score >= 50:
            return "warning"
        return "danger"


class RuleHealthMetrics(BaseModel):
    """Aggregated rule health statistics."""
    total_rules: int = 0
    enabled_rules: int = 0
    disabled_rules: int = 0
    
    avg_score: float = 0.0
    min_score: int = 0
    max_score: int = 0
    
    validated_count: int = 0
    validation_expired_count: int = 0
    never_validated_count: int = 0
    
    low_quality_count: int = 0   # score < 50
    high_quality_count: int = 0  # score >= 80
    
    # Quality brackets
    quality_excellent: int = 0   # score >= 80
    quality_good: int = 0       # 70-79
    quality_fair: int = 0       # 50-69
    quality_poor: int = 0       # < 50
    
    rules_by_space: Dict[str, int] = Field(default_factory=dict)
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    language_breakdown: Dict[str, int] = Field(default_factory=dict)


class RuleFilters(BaseModel):
    """Filters for rule listing endpoint."""
    search: Optional[str] = None
    space: Optional[str] = None
    enabled: Optional[bool] = None
    severity: Optional[Severity] = None
    min_score: Optional[int] = None
    max_score: Optional[int] = None
    sort_by: str = "score_asc"  # score_asc, score_desc, validated_asc, validated_desc, name_asc
    page: int = 1
    page_size: int = 24


class RuleListResponse(BaseModel):
    """Paginated rule list response."""
    rules: List[DetectionRule]
    total: int
    page: int
    page_size: int
    total_pages: int
    last_sync: str
