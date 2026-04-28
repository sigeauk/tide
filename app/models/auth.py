"""
Pydantic models for Authentication and User data.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict
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
    id: str  # Internal DB user ID
    username: str
    email: Optional[str] = None
    name: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    groups: List[str] = Field(default_factory=list)
    auth_provider: str = "keycloak"  # 'keycloak' or 'local'
    is_active: bool = True
    is_superadmin: bool = False  # Maps from Keycloak `superadmin` group; bypasses tenant role checks.
    permissions: Dict[str, Dict[str, bool]] = Field(default_factory=dict)

    # Multi-tenant fields
    clients: List[str] = Field(default_factory=list)  # Assigned client IDs
    active_client_id: Optional[str] = None  # Currently selected client
    # Per-tenant role membership: {client_id: [role_name, ...]}.
    # `roles` reflects the *active* tenant only; this map is the source of truth.
    client_roles: Dict[str, List[str]] = Field(default_factory=dict)

    # Session info
    authenticated_at: Optional[datetime] = None
    
    @classmethod
    def from_token(cls, token: TokenData, db_user: dict = None, db_roles: List[str] = None,
                   client_roles: Dict[str, List[str]] = None) -> "User":
        """Create User from decoded JWT token, enriched with DB data."""
        if db_user:
            return cls(
                id=db_user["id"],
                username=db_user.get("username") or token.preferred_username or token.sub,
                email=db_user.get("email") or token.email,
                name=db_user.get("full_name") or token.name,
                roles=db_roles or [],
                groups=token.groups,
                auth_provider="keycloak",
                is_active=db_user.get("is_active", True),
                is_superadmin=bool(db_user.get("is_superadmin", False)),
                client_roles=client_roles or {},
                authenticated_at=datetime.now(),
            )
        return cls(
            id=token.sub,
            username=token.preferred_username or token.sub,
            email=token.email,
            name=token.name,
            roles=token.roles,
            groups=token.groups,
            auth_provider="keycloak",
            authenticated_at=datetime.now(),
        )

    @classmethod
    def from_db(cls, db_user: dict, db_roles: List[str] = None,
                client_roles: Dict[str, List[str]] = None) -> "User":
        """Create User from database row."""
        return cls(
            id=db_user["id"],
            username=db_user["username"],
            email=db_user.get("email"),
            name=db_user.get("full_name"),
            roles=db_roles or [],
            auth_provider=db_user.get("auth_provider", "local"),
            is_active=db_user.get("is_active", True),
            is_superadmin=bool(db_user.get("is_superadmin", False)),
            client_roles=client_roles or {},
            authenticated_at=datetime.now(),
        )
    
    @classmethod
    def dev_user(cls, client_ids: List[str] = None) -> "User":
        """Create mock user for local development."""
        return cls(
            id="dev-user-001",
            username="developer",
            email="dev@localhost",
            name="Local Developer",
            roles=["ADMIN", "ANALYST", "ENGINEER"],
            groups=["/admins", "/developers"],
            auth_provider="local",
            is_superadmin=True,
            clients=client_ids or [],
            active_client_id=(client_ids[0] if client_ids else None),
            authenticated_at=datetime.now()
        )

    def is_admin(self, client_id: Optional[str] = None) -> bool:
        """Check if the user has admin powers.

        - Superadmins always return True.
        - With `client_id`: only True when ADMIN role is assigned in that tenant.
        - Without `client_id`: True when ADMIN is assigned in ANY tenant the user
          can see (used by management routes that gate on "can the user reach
          the management panel at all"). Per-tenant write checks must always
          pass an explicit `client_id`.
        """
        if self.is_superadmin:
            return True
        if client_id is not None:
            roles = self.client_roles.get(client_id, [])
            return any(r.upper() == "ADMIN" for r in roles)
        # Either the active tenant's roles (loaded into self.roles) or any tenant.
        if any(r.upper() == "ADMIN" for r in self.roles):
            return True
        for roles in self.client_roles.values():
            if any(r.upper() == "ADMIN" for r in roles):
                return True
        return False

    def has_role(self, role: str) -> bool:
        """Check if user has a specific role in the active tenant (case-insensitive)."""
        return role.upper() in [r.upper() for r in self.roles]

    def can_read(self, resource: str) -> bool:
        """Check if user can read a resource based on permissions.

        Bypass only for super-admins and tenant-ADMINs of the *active* tenant
        \u2014 a DC-only admin must NOT see Marvel-only sidebar items just because
        they hold ADMIN somewhere.
        """
        if self.is_superadmin:
            return True
        if self.active_client_id and self.is_admin(self.active_client_id):
            return True
        perm = self.permissions.get(resource)
        return perm.get("can_read", False) if perm else False

    def can_write(self, resource: str) -> bool:
        """Check if user can write a resource based on permissions (active tenant)."""
        if self.is_superadmin:
            return True
        if self.active_client_id and self.is_admin(self.active_client_id):
            return True
        perm = self.permissions.get(resource)
        return perm.get("can_write", False) if perm else False


class AuthState(BaseModel):
    """Authentication state for templates."""
    is_authenticated: bool = False
    user: Optional[User] = None
    login_url: Optional[str] = None
    logout_url: Optional[str] = None
