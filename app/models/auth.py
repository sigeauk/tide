"""
Pydantic models for Authentication and User data.
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class TokenData(BaseModel):
    """Decoded JWT token data."""
    sub: str  # Subject (user ID)
    exp: Optional[int] = None  # Expiration timestamp
    iat: Optional[int] = None  # Issued at timestamp
    iss: Optional[str] = None  # Issuer
    aud: Optional[str] = None  # Audience
    
    # Keycloak-specific claims
    preferred_username: Optional[str] = None
    email: Optional[str] = None
    email_verified: bool = False
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    
    # Roles and groups
    realm_access: Optional[dict] = None
    resource_access: Optional[dict] = None
    groups: List[str] = Field(default_factory=list)
    
    @property
    def roles(self) -> List[str]:
        """Extract realm roles from token."""
        if self.realm_access:
            return self.realm_access.get("roles", [])
        return []
    
    def has_role(self, role: str) -> bool:
        """Check if user has a specific role."""
        return role in self.roles


class User(BaseModel):
    """Application user model."""
    id: str  # Keycloak subject ID
    username: str
    email: Optional[str] = None
    name: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    groups: List[str] = Field(default_factory=list)
    
    # Session info
    authenticated_at: Optional[datetime] = None
    
    @classmethod
    def from_token(cls, token: TokenData) -> "User":
        """Create User from decoded JWT token."""
        return cls(
            id=token.sub,
            username=token.preferred_username or token.sub,
            email=token.email,
            name=token.name,
            roles=token.roles,
            groups=token.groups,
            authenticated_at=datetime.now()
        )
    
    @classmethod
    def dev_user(cls) -> "User":
        """Create mock user for local development."""
        return cls(
            id="dev-user-001",
            username="developer",
            email="dev@localhost",
            name="Local Developer",
            roles=["admin", "user"],
            groups=["/admins", "/developers"],
            authenticated_at=datetime.now()
        )
    
    def is_admin(self) -> bool:
        """Check if user has admin role."""
        return "admin" in self.roles


class AuthState(BaseModel):
    """Authentication state for templates."""
    is_authenticated: bool = False
    user: Optional[User] = None
    login_url: Optional[str] = None
    logout_url: Optional[str] = None
