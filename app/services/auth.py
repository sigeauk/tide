"""
Authentication service for TIDE - Keycloak OIDC integration.
Supports stateless JWT validation with optional dev mode bypass.
"""

import httpx
import jwt
from jwt import PyJWKClient
from datetime import datetime
from typing import Optional
from urllib.parse import urlencode
from functools import lru_cache

from app.config import get_settings
from app.models.auth import User, TokenData

import logging

logger = logging.getLogger(__name__)


class AuthService:
    """
    Authentication service handling Keycloak OIDC.
    Validates JWTs using Keycloak's JWKS endpoint.
    """
    
    def __init__(self):
        self.settings = get_settings()
        self._jwks_client: Optional[PyJWKClient] = None
    
    @property
    def auth_disabled(self) -> bool:
        """Check if auth is disabled for development."""
        return self.settings.auth_disabled
    
    @property
    def jwks_client(self) -> PyJWKClient:
        """Lazy-loaded JWKS client for public key retrieval."""
        if self._jwks_client is None:
            self._jwks_client = PyJWKClient(
                self.settings.oidc_jwks_url,
                cache_keys=True,
                lifespan=3600  # Cache keys for 1 hour
            )
        return self._jwks_client
    
    def get_login_url(self, redirect_uri: str, state: str = "") -> str:
        """Generate Keycloak authorization URL."""
        params = {
            "client_id": self.settings.keycloak_client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
        }
        return f"{self.settings.oidc_auth_url}?{urlencode(params)}"
    
    def get_logout_url(self, redirect_uri: str) -> str:
        """Generate Keycloak logout URL."""
        params = {
            "client_id": self.settings.keycloak_client_id,
            "post_logout_redirect_uri": redirect_uri,
        }
        return f"{self.settings.oidc_logout_url}?{urlencode(params)}"
    
    async def exchange_code(self, code: str, redirect_uri: str) -> Optional[dict]:
        """Exchange authorization code for tokens."""
        data = {
            "grant_type": "authorization_code",
            "client_id": self.settings.keycloak_client_id,
            "client_secret": self.settings.keycloak_client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    self.settings.oidc_token_url,
                    data=data,
                    timeout=10.0
                )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPError as e:
                logger.error(f"Token exchange failed: {e}")
                return None
    
    async def refresh_token(self, refresh_token: str) -> Optional[dict]:
        """Refresh access token using refresh token."""
        data = {
            "grant_type": "refresh_token",
            "client_id": self.settings.keycloak_client_id,
            "client_secret": self.settings.keycloak_client_secret,
            "refresh_token": refresh_token,
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    self.settings.oidc_token_url,
                    data=data,
                    timeout=10.0
                )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPError as e:
                logger.error(f"Token refresh failed: {e}")
                return None
    
    def validate_token(self, token: str) -> Optional[TokenData]:
        """
        Validate JWT token and return decoded data.
        Uses Keycloak's JWKS for signature verification.
        """
        try:
            # Get the signing key from JWKS
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)
            
            # Decode and verify the token
            # Note: Keycloak tokens may have 'account' as audience or use azp (authorized party)
            # We verify the azp claim matches our client_id instead of aud
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=[self.settings.jwt_algorithm],
                issuer=self.settings.oidc_issuer,
                options={
                    "verify_exp": True,
                    "verify_aud": False,  # Keycloak uses azp instead of aud for client verification
                    "verify_iss": True,
                }
            )
            
            # Verify authorized party (azp) matches our client
            azp = payload.get("azp")
            if azp and azp != self.settings.keycloak_client_id:
                logger.warning(f"Token azp '{azp}' doesn't match client_id '{self.settings.keycloak_client_id}'")
                return None
            
            return TokenData(**payload)
        
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return None
    
    def get_user_from_token(self, token: str) -> Optional[User]:
        """Validate token and return User model."""
        token_data = self.validate_token(token)
        if token_data:
            return User.from_token(token_data)
        return None
    
    def get_dev_user(self) -> User:
        """Get mock user for development mode."""
        return User.dev_user()


# Singleton accessor
@lru_cache()
def get_auth_service() -> AuthService:
    """Get the auth service singleton."""
    return AuthService()
