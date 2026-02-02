"""
Configuration module for TIDE FastAPI application.
Uses Pydantic Settings for type-safe environment variable loading.
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from functools import lru_cache
from typing import Optional, List
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # --- APPLICATION ---
    tide_version: str = Field(default="2.0.0", alias="TIDE_VERSION")
    app_url: str = Field(default="http://localhost:8000", alias="APP_URL")
    sync_interval_minutes: int = Field(default=60, alias="SYNC_INTERVAL_MINUTES")
    debug: bool = Field(default=False, alias="DEBUG")
    
    # --- BRAND CUSTOMIZATION ---
    # Change this value (0-360) to restyle the entire app
    # 0=Red, 30=Orange, 145=Green, 220=Blue (default), 280=Purple
    brand_hue: int = Field(default=220, alias="BRAND_HUE", ge=0, le=360)
    
    # --- AUTHENTICATION ---
    auth_disabled: bool = Field(default=False, alias="AUTH_DISABLED")
    keycloak_url: str = Field(default="http://localhost:8080", alias="KEYCLOAK_URL")
    keycloak_internal_url: Optional[str] = Field(default=None, alias="KEYCLOAK_INTERNAL_URL")
    keycloak_realm: str = Field(default="tide", alias="KEYCLOAK_REALM")
    keycloak_client_id: str = Field(default="tide-app", alias="KEYCLOAK_CLIENT_ID")
    keycloak_client_secret: str = Field(default="", alias="KEYCLOAK_CLIENT_SECRET")
    jwt_algorithm: str = Field(default="RS256", alias="JWT_ALGORITHM")
    
    # --- DATABASE ---
    db_path: str = Field(default="/app/data/tide.duckdb", alias="DB_PATH")
    trigger_dir: str = Field(default="/app/data/triggers", alias="TRIGGER_DIR")
    validation_file: str = Field(default="/app/data/checkedRule.json", alias="VALIDATION_FILE")
    
    # --- ELASTICSEARCH ---
    elasticsearch_url: str = Field(default="http://elasticsearch:9200", alias="ELASTICSEARCH_URL")
    elastic_url: str = Field(default="http://kibana:5601", alias="ELASTIC_URL")
    elastic_api_key: str = Field(default="", alias="ELASTIC_API_KEY")
    kibana_spaces: str = Field(default="production, staging", alias="KIBANA_SPACES")
    
    # --- OPENCTI ---
    opencti_url: str = Field(default="http://opencti:8080", alias="OPENCTI_URL")
    opencti_token: str = Field(default="", alias="OPENCTI_TOKEN")
    
    # --- GITLAB ---
    gitlab_url: str = Field(default="http://gitlab:8929/", alias="GITLAB_URL")
    gitlab_token: str = Field(default="", alias="GITLAB_TOKEN")
    
    # --- MITRE DATA SOURCES ---
    mitre_source: str = Field(
        default="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        alias="MITRE_SOURCE"
    )
    sigma_repo_path: str = Field(default="/opt/repos/sigma", alias="SIGMA_REPO_PATH")
    mitre_repo_path: str = Field(default="/opt/repos/mitre", alias="MITRE_REPO_PATH")
    
    @property
    def keycloak_internal(self) -> str:
        """Returns internal Keycloak URL for backend calls."""
        return self.keycloak_internal_url or self.keycloak_url
    
    @property
    def oidc_issuer(self) -> str:
        """OIDC issuer URL for token validation."""
        return f"{self.keycloak_internal}/realms/{self.keycloak_realm}"
    
    @property
    def oidc_jwks_url(self) -> str:
        """JWKS URL for public key retrieval."""
        return f"{self.oidc_issuer}/protocol/openid-connect/certs"
    
    @property
    def oidc_token_url(self) -> str:
        """Token endpoint for code exchange."""
        return f"{self.oidc_issuer}/protocol/openid-connect/token"
    
    @property
    def oidc_auth_url(self) -> str:
        """Authorization endpoint (browser-facing, uses external URL)."""
        return f"{self.keycloak_url}/realms/{self.keycloak_realm}/protocol/openid-connect/auth"
    
    @property
    def oidc_logout_url(self) -> str:
        """Logout endpoint (browser-facing)."""
        return f"{self.keycloak_url}/realms/{self.keycloak_realm}/protocol/openid-connect/logout"
    
    @property
    def kibana_space_list(self) -> List[str]:
        """Parse comma-separated Kibana spaces."""
        return [s.strip() for s in self.kibana_spaces.split(",") if s.strip()]
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"  # Ignore extra env vars


@lru_cache()
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
