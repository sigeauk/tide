"""
Authentication service for TIDE - Hybrid Keycloak OIDC + Local DB auth.
Supports stateless JWT validation with optional dev mode bypass,
plus local username/password authentication with signed session tokens.
"""

import bcrypt
import httpx
import jwt
import ssl as _ssl
import time
from jwt import PyJWKClient
from datetime import datetime
from typing import Optional, Union, Dict, List
from urllib.parse import urlencode
from functools import lru_cache
from itsdangerous import URLSafeTimedSerializer

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
        Build an ssl.SSLContext that honours SSL_VERIFY.
        
        When running in Docker the entrypoint installs CA certs into the
        system trust store, so the default context trusts them automatically.
        """
        if not self.settings.ssl_verify:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            return ctx
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
        """Validate Keycloak JWT and return User model with JIT provisioning."""
        token_data = self.validate_token(token)
        if not token_data:
            return None
        # JIT provision: sync the Keycloak user into the local DB
        try:
            from app.services.database import get_database_service
            db = get_database_service()
            db_user = db.jit_provision_keycloak_user(
                keycloak_id=token_data.sub,
                username=token_data.preferred_username or token_data.sub,
                email=token_data.email,
                full_name=token_data.name,
            )
            if db_user and not db_user.get("is_active", True):
                logger.warning(f"Keycloak user {token_data.preferred_username} is deactivated in TIDE")
                return None
            db_roles = db.get_user_roles(db_user["id"]) if db_user else []
            user = User.from_token(token_data, db_user=db_user, db_roles=db_roles)
            if db_user:
                user.permissions = db.get_user_permissions(db_user["id"])
            return user
        except Exception as e:
            logger.warning(f"JIT provisioning failed, falling back to token-only user: {e}")
            return User.from_token(token_data)
    
    def token_expires_soon(self, token: str, threshold_seconds: int = 60) -> bool:
        """
        Check if token expires within threshold_seconds.
        Returns True if token will expire soon (should proactively refresh).
        """
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
            exp_time = unverified.get("exp", 0)
            current_time = int(time.time())
            time_left = exp_time - current_time
            return time_left > 0 and time_left < threshold_seconds
        except Exception:
            return False
    
    # --- Local (DB) Authentication ---

    def _get_signer(self) -> URLSafeTimedSerializer:
        return URLSafeTimedSerializer(self.settings.session_secret)

    def _password_grant_clients(self) -> List[Dict[str, str]]:
        clients: List[Dict[str, str]] = []

        preferred_client_id = self.settings.keycloak_password_grant_client_id.strip()
        preferred_client_secret = self.settings.keycloak_password_grant_client_secret.strip()
        if preferred_client_id:
            clients.append(
                {
                    "client_id": preferred_client_id,
                    "client_secret": preferred_client_secret,
                }
            )

        browser_client_id = self.settings.keycloak_client_id.strip()
        browser_client_secret = self.settings.keycloak_client_secret.strip()
        if browser_client_id and all(c["client_id"] != browser_client_id for c in clients):
            clients.append(
                {
                    "client_id": browser_client_id,
                    "client_secret": browser_client_secret,
                }
            )

        return clients

    def _authenticate_via_keycloak(self, username: str, password: str) -> Optional[dict]:
        """Authenticate credentials against Keycloak using a password-grant capable client.
        Returns the token payload on success, None on failure."""
        try:
            with httpx.Client(verify=self.settings.ssl_context, timeout=10.0) as client:
                for client_cfg in self._password_grant_clients():
                    data = {
                        "grant_type": "password",
                        "client_id": client_cfg["client_id"],
                        "username": username,
                        "password": password,
                        "scope": "openid email profile",
                    }
                    if client_cfg.get("client_secret"):
                        data["client_secret"] = client_cfg["client_secret"]

                    response = client.post(self.settings.oidc_token_url, data=data)
                    if response.status_code == 200:
                        logger.info(
                            "Keycloak password grant auth succeeded for '%s' via client '%s'",
                            username,
                            client_cfg["client_id"],
                        )
                        return response.json()

                    error = ""
                    error_description = response.text
                    try:
                        body = response.json()
                        error = body.get("error", "")
                        error_description = body.get("error_description", error_description)
                    except ValueError:
                        body = {}

                    logger.warning(
                        "Keycloak password grant auth failed for '%s' via client '%s': %s %s",
                        username,
                        client_cfg["client_id"],
                        response.status_code,
                        error_description,
                    )

                    if response.status_code == 400 and error == "unauthorized_client":
                        continue

                    break
        except Exception as e:
            logger.error(f"Keycloak password grant auth error for '{username}': {e}")

        return None

    def _token_data_from_password_grant(self, tokens: dict) -> Optional[TokenData]:
        """Extract user claims from a successful password grant response."""
        raw_token = tokens.get("id_token") or tokens.get("access_token")
        if not raw_token:
            logger.warning("Password grant response did not include an ID or access token")
            return None

        try:
            payload = jwt.decode(
                raw_token,
                options={
                    "verify_signature": False,
                    "verify_aud": False,
                    "verify_exp": False,
                    "verify_iss": False,
                },
            )
            return TokenData(**payload)
        except Exception as e:
            logger.error(f"Failed to decode password grant token claims: {e}")
            return None

    def authenticate_local(self, username: str, password: str) -> Union[User, str, None]:
        """Authenticate a local user against bcrypt password hash in DB.
        Falls back to Keycloak ROPC for SSO-provisioned users.
        Returns User on success, None on failure."""
        from app.services.database import get_database_service
        db = get_database_service()
        db_user = db.get_user_by_username(username)
        if db_user and not db_user.get("is_active", True):
            logger.warning(f"Local login failed: user '{username}' is deactivated")
            return None

        provider = (db_user.get("auth_provider") or "local").lower() if db_user else ""
        stored_hash = db_user.get("password_hash") if db_user else None
        # Any account with a local hash can always use local credential validation,
        # regardless of whether it was originally provisioned by SSO.
        if stored_hash:
            if not bcrypt.checkpw(password.encode(), stored_hash.encode()):
                logger.warning(f"Local login failed: bad password for '{username}'")
                return None
            db.update_user(db_user["id"], last_login=datetime.now())
            db_roles = db.get_user_roles(db_user["id"])
            logger.info(f"Local login successful for '{username}' (provider={provider}) with roles {db_roles}")
            user = User.from_db(db_user, db_roles)
            user.permissions = db.get_user_permissions(db_user["id"])
            return user

        # No local hash available: SSO-capable accounts can try Keycloak password grant fallback.
        can_try_sso = False
        if db_user:
            can_try_sso = provider in {"keycloak", "hybrid"} and bool(db_user.get("keycloak_id"))
        else:
            # Allow local-form login for SSO users that only exist in Keycloak; the DB row will be JIT-created.
            can_try_sso = True

        if can_try_sso:
            tokens = self._authenticate_via_keycloak(username, password)
            if tokens:
                if not db_user:
                    token_data = self._token_data_from_password_grant(tokens)
                    if not token_data:
                        return None
                    db_user = db.jit_provision_keycloak_user(
                        keycloak_id=token_data.sub,
                        username=token_data.preferred_username or username,
                        email=token_data.email,
                        full_name=token_data.name,
                    )

                db.update_user(db_user["id"], last_login=datetime.now())
                db_roles = db.get_user_roles(db_user["id"])
                logger.info(f"SSO user '{username}' authenticated via Keycloak password grant")
                user = User.from_db(db_user, db_roles)
                user.permissions = db.get_user_permissions(db_user["id"])
                return user

        if not db_user:
            logger.warning(f"Local login failed: unknown user '{username}'")
            return None

        logger.warning(f"Local login failed: user '{username}' has no local password hash")
        return None

    def create_session_token(self, user_id: str) -> str:
        """Create a signed session token for local auth."""
        return self._get_signer().dumps({"uid": user_id})

    def get_user_from_session(self, token: str, max_age: int = 86400) -> Optional[User]:
        """Validate a local session token and return User."""
        try:
            data = self._get_signer().loads(token, max_age=max_age)
            user_id = data.get("uid")
            if not user_id:
                return None
            from app.services.database import get_database_service
            db = get_database_service()
            db_user = db.get_user_by_id(user_id)
            if not db_user or not db_user.get("is_active", True):
                return None
            db_roles = db.get_user_roles(db_user["id"])
            user = User.from_db(db_user, db_roles)
            user.permissions = db.get_user_permissions(db_user["id"])
            return user
        except Exception:
            return None
    
    def get_dev_user(self) -> User:
        """Get mock user for development mode."""
        return User.dev_user()


# Singleton accessor
@lru_cache()
def get_auth_service() -> AuthService:
    """Get the auth service singleton."""
    return AuthService()
