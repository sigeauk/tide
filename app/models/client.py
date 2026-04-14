"""
Pydantic models for multi-tenant Client management and SIEM Inventory.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Literal
from datetime import datetime


class Client(BaseModel):
    """A tenant / client organization."""
    id: str
    name: str
    slug: str
    description: Optional[str] = None
    is_default: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class ClientCreate(BaseModel):
    """Create a new client."""
    name: str = Field(..., min_length=1, max_length=200)
    slug: str = Field(..., min_length=1, max_length=50, pattern=r"^[a-z0-9][a-z0-9\-]*$")
    description: Optional[str] = None


class ClientUpdate(BaseModel):
    """Update an existing client."""
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = None


# --- SIEM Inventory (centralized, shared across clients) ---

class SIEMInventoryItem(BaseModel):
    """A centralized SIEM object from the inventory."""
    id: str
    label: str
    siem_type: str
    elasticsearch_url: Optional[str] = None
    kibana_url: Optional[str] = None
    extra_config: Optional[dict] = None
    is_active: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class SIEMInventoryCreate(BaseModel):
    """Create a SIEM in the centralized inventory."""
    siem_type: str = Field(..., pattern=r"^(elastic|splunk|sentinel)$")
    label: str = Field(..., min_length=1, max_length=200)
    elasticsearch_url: Optional[str] = None
    kibana_url: Optional[str] = None
    api_token: Optional[str] = None
    extra_config: Optional[dict] = None


class SIEMInventoryUpdate(BaseModel):
    """Update a SIEM in the inventory."""
    label: Optional[str] = None
    elasticsearch_url: Optional[str] = None
    kibana_url: Optional[str] = None
    api_token: Optional[str] = None
    extra_config: Optional[dict] = None
    is_active: Optional[bool] = None


# --- Client-SIEM mapping with environment role ---

class ClientSIEMLink(BaseModel):
    """A client's link to a SIEM with environment role and space."""
    siem_id: str
    environment_role: Literal["production", "staging"] = "production"
    space: Optional[str] = None


class ClientSIEMLinkFull(BaseModel):
    """Full SIEM info as linked to a client, including environment context."""
    id: str
    label: str
    siem_type: str
    elasticsearch_url: Optional[str] = None
    kibana_url: Optional[str] = None
    environment_role: str = "production"
    space: Optional[str] = None
    is_active: bool = True
    created_at: Optional[datetime] = None


# --- Legacy per-client SIEM config (kept for backward compat) ---

class SIEMConfig(BaseModel):
    """Per-client SIEM connection configuration."""
    id: str
    client_id: str
    siem_type: str  # 'elastic', 'splunk', 'sentinel'
    label: str
    base_url: Optional[str] = None
    space_list: Optional[str] = None
    extra_config: Optional[dict] = None
    is_active: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class SIEMConfigCreate(BaseModel):
    """Create a SIEM connection for a client."""
    siem_type: str = Field(..., pattern=r"^(elastic|splunk|sentinel)$")
    label: str = Field(..., min_length=1, max_length=200)
    base_url: Optional[str] = None
    api_token: Optional[str] = None  # Plaintext — encrypted before storage
    space_list: Optional[str] = None
    extra_config: Optional[dict] = None


class SIEMConfigUpdate(BaseModel):
    """Update a SIEM connection."""
    label: Optional[str] = None
    base_url: Optional[str] = None
    api_token: Optional[str] = None
    space_list: Optional[str] = None
    extra_config: Optional[dict] = None
    is_active: Optional[bool] = None


class UserClientAssignment(BaseModel):
    """Assign a user to a client."""
    user_id: str
    is_default: bool = False


class ClientSwitchResponse(BaseModel):
    """Response after switching active client."""
    client_id: str
    client_name: str
