"""
Authentication service for TIDE - Keycloak OIDC integration.
Supports stateless JWT validation with optional dev mode bypass.
"""

import httpx
import jwt
import ssl as _ssl
from jwt import PyJWKClient
from datetime import datetime
from typing import Optional
from urllib.parse import urlencode
from functools import lru_cache
from pathlib import Path

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
    
    def _build_ssl_context(self) -> _ssl.SSLContext:
        """
        Build an ssl.SSLContext that honours SSL_VERIFY / CA_CERT_PATH.
        Used by PyJWKClient (urllib) which needs a native SSLContext.
        """
        if not self.settings.ssl_verify:
            # Disable verification entirely
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            return ctx
        # Explicit CA_CERT_PATH
        if self.settings.ca_cert_path and Path(self.settings.ca_cert_path).exists():
            return _ssl.create_default_context(cafile=self.settings.ca_cert_path)
        # Merged bundle created by entrypoint
        bundle = Path("/app/certs/ca-bundle.crt")
        if bundle.exists() and bundle.stat().st_size > 0:
            return _ssl.create_default_context(cafile=str(bundle))
        return _ssl.create_default_context()
    
    @property
    def jwks_client(self) -> PyJWKClient:
        """Lazy-loaded JWKS client for public key retrieval."""
        if self._jwks_client is None:
            self._jwks_client = PyJWKClient(
                self.settings.oidc_jwks_url,
                cache_keys=True,
                lifespan=3600,  # Cache keys for 1 hour
                ssl_context=self._build_ssl_context(),
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
        
        token_url = self.settings.oidc_token_url
        logger.info(f"Exchanging auth code at: {token_url}")
        logger.debug(f"Exchange data: client_id={data['client_id']}, redirect_uri={redirect_uri}")
        
        async with httpx.AsyncClient(verify=self.settings.ssl_context) as client:
            try:
                response = await client.post(
                    token_url,
                    data=data,
                    timeout=10.0
                )
                response.raise_for_status()
                logger.info("Token exchange successful")
                return response.json()
            except httpx.HTTPStatusError as e:
                logger.error(f"Token exchange HTTP error: {e.response.status_code}")
                logger.error(f"Response body: {e.response.text}")
                return None
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
        
        async with httpx.AsyncClient(verify=self.settings.ssl_context) as client:
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
        import time
        try:
            logger.debug(f"Validating token, expected issuer: {self.settings.oidc_issuer}")
            
            # First, decode without verification to check expiration time
            try:
                unverified = jwt.decode(token, options={"verify_signature": False})
                exp_time = unverified.get("exp", 0)
                current_time = int(time.time())
                time_left = exp_time - current_time
                username = unverified.get("preferred_username", "unknown")
                
                if time_left < 0:
                    logger.warning(f"Token for {username} expired {abs(time_left)}s ago")
                elif time_left < 60:
                    logger.warning(f"Token for {username} expires in {time_left}s (nearly expired)")
                elif time_left < 300:
                    logger.debug(f"Token for {username} expires in {time_left}s")
            except Exception as e:
                logger.debug(f"Could not pre-decode token: {e}")
            
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
            
            logger.info(f"Token validated successfully for user: {payload.get('preferred_username', 'unknown')}")
            
            # Verify authorized party (azp) matches our client
            azp = payload.get("azp")
            if azp and azp != self.settings.keycloak_client_id:
                logger.warning(f"Token azp '{azp}' doesn't match client_id '{self.settings.keycloak_client_id}'")
                return None
            
            return TokenData(**payload)
        
        except jwt.ExpiredSignatureError:
            logger.error("Token validation failed: Token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.error(f"Token validation failed - Invalid token: {e}")
            return None
        except Exception as e:
            logger.error(f"Token validation error: {type(e).__name__}: {e}")
            return None
    
    def get_user_from_token(self, token: str) -> Optional[User]:
        """Validate token and return User model."""
        token_data = self.validate_token(token)
        if token_data:
            return User.from_token(token_data)
        return None
    
    def token_expires_soon(self, token: str, threshold_seconds: int = 60) -> bool:
        """
        Check if token expires within threshold_seconds.
        Returns True if token will expire soon (should proactively refresh).
        """
        import time
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
            exp_time = unverified.get("exp", 0)
            current_time = int(time.time())
            time_left = exp_time - current_time
            return time_left > 0 and time_left < threshold_seconds
        except Exception:
            return False
    
    def get_dev_user(self) -> User:
        """Get mock user for development mode."""
        return User.dev_user()


# Singleton accessor
@lru_cache()
def get_auth_service() -> AuthService:
    """Get the auth service singleton."""
    return AuthService()
