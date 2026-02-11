"""
Configuration module for TIDE FastAPI application.
Uses Pydantic Settings for type-safe environment variable loading.
"""

from pydantic_settings import BaseSettings
from pydantic import Field, field_validator, model_validator
from functools import lru_cache
from typing import Optional, List
from pathlib import Path
import os


def _read_version_file() -> Optional[str]:
    """
    Read version from VERSION file. Checked in order:
    1. /app/VERSION (Docker production path)
    2. ./VERSION (relative to working directory)
    3. VERSION file next to this config.py
    """
    search_paths = [
        Path("/app/VERSION"),
        Path("VERSION"),
        Path(__file__).parent.parent / "VERSION",
    ]
    for path in search_paths:
        if path.exists():
            try:
                return path.read_text().strip()
            except Exception:
                continue
    return None


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # --- APPLICATION ---
    # Version is loaded from VERSION file first, .env second, default third
    tide_version: str = Field(default="0.0.0", alias="TIDE_VERSION")
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
    mitre_mobile_source: str = Field(
        default="https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
        alias="MITRE_MOBILE_SOURCE"
    )
    mitre_ics_source: str = Field(
        default="https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
        alias="MITRE_ICS_SOURCE"
    )
    mitre_pre_source: str = Field(
        default="https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json",
        alias="MITRE_PRE_SOURCE"
    )
    sigma_repo_url: str = Field(default="https://github.com/SigmaHQ/sigma.git", alias="SIGMA_REPO_URL")
    elastic_repo_url: str = Field(default="https://github.com/elastic/detection-rules.git", alias="ELASTIC_REPO_URL")
    sigma_repo_path: str = Field(default="/opt/repos/sigma", alias="SIGMA_REPO_PATH")
    elastic_repo_path: str = Field(default="/opt/repos/elastic-detection-rules", alias="ELASTIC_REPO_PATH")
    mitre_repo_path: str = Field(default="/opt/repos/mitre", alias="MITRE_REPO_PATH")
    
    # --- RULE LOGGING ---
    # Host path from .env (displayed on settings page for SIEM agent reference)
    rule_log_host_path: str = Field(default="/app/data/log/rules", alias="RULE_LOG_PATH")
    
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
    
    @model_validator(mode='after')
    def override_version_from_file(self) -> 'Settings':
        """
        Override tide_version with VERSION file if it exists.
        VERSION file takes priority over .env to ensure version is baked into Docker image.
        """
        file_version = _read_version_file()
        if file_version:
            object.__setattr__(self, 'tide_version', file_version)
        return self
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"  # Ignore extra env vars


@lru_cache()
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
