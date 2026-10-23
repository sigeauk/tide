"""The Keycloak TIDE signs people in with.

Since 6.3.0 it is the Keycloak integration (Settings → Management → Integrations): the
``keycloak_inventory`` row marked ``used_for_signin``, managed in TIDE. The first time TIDE starts
with Keycloak settings in .env and no Keycloak integration to sign in with, :func:`import_from_env`
makes one from them; after that .env's Keycloak lines are not read, and Diagnostics says when they
differ (:func:`env_differences`). With no such row (no Keycloak set up, or its integration deleted)
sign-in uses .env's settings, as before 6.3.0.

:func:`current` is read on every sign-in and token check, so it is cached in the process (TIDE runs
one worker); every change to a Keycloak integration calls :func:`invalidate`.
"""
from __future__ import annotations

import logging
import ssl
import threading
from dataclasses import dataclass
from typing import List, Optional, Tuple

from app.config import Settings, get_settings

logger = logging.getLogger(__name__)

# The .env settings the Keycloak integration replaces: Settings field -> KeycloakConfig field.
ENV_FIELDS = {
    "keycloak_url": "url",
    "keycloak_internal_url": "internal_url",
    "keycloak_realm": "realm",
    "keycloak_client_id": "client_id",
    "keycloak_client_secret": "client_secret",
    "keycloak_password_grant_client_id": "pg_client_id",
    "keycloak_password_grant_client_secret": "pg_client_secret",
}
SECRETS = {"client_secret", "pg_client_secret"}


@dataclass(frozen=True)
class KeycloakConfig:
    url: str                 # the address browsers are sent to
    internal_url: str        # the address TIDE itself calls; '' means url
    realm: str
    client_id: str
    client_secret: str
    pg_client_id: str        # the client the sign-in form's password grant tries first
    pg_client_secret: str
    verify_tls: bool
    source: str              # "tide" (the integration) or "env"

    @property
    def internal(self) -> str:
        return (self.internal_url or self.url).rstrip("/")

    @property
    def issuer(self) -> str:
        return f"{self.internal}/realms/{self.realm}"

    @property
    def jwks_url(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/certs"

    @property
    def token_url(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/token"

    @property
    def auth_url(self) -> str:
        """Browser-facing, so on the external address."""
        return f"{self.url.rstrip('/')}/realms/{self.realm}/protocol/openid-connect/auth"

    @property
    def logout_url(self) -> str:
        return f"{self.url.rstrip('/')}/realms/{self.realm}/protocol/openid-connect/logout"

    def ssl_context(self) -> ssl.SSLContext:
        """For httpx and the JWKS client: the system trust store (with the CA certificates the
        entrypoint installs), or no verification when Verify TLS certificate is off."""
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx


def from_env(settings: Optional[Settings] = None) -> KeycloakConfig:
    s = settings or get_settings()
    return KeycloakConfig(
        url=s.keycloak_url, internal_url=s.keycloak_internal_url or "", realm=s.keycloak_realm,
        client_id=s.keycloak_client_id, client_secret=s.keycloak_client_secret,
        pg_client_id=s.keycloak_password_grant_client_id, pg_client_secret=s.keycloak_password_grant_client_secret,
        verify_tls=s.ssl_verify, source="env",
    )


def from_row(row: dict) -> KeycloakConfig:
    """A ``keycloak_inventory`` row (secrets already revealed) as sign-in settings."""
    return KeycloakConfig(
        url=row.get("url") or "", internal_url=row.get("internal_url") or "", realm=row.get("realm") or "master",
        client_id=row.get("client_id_enc") or "", client_secret=row.get("client_secret_enc") or "",
        pg_client_id=row.get("pg_client_id") or "", pg_client_secret=row.get("pg_client_secret_enc") or "",
        verify_tls=bool(row.get("tls_verify")), source="tide",
    )


_lock = threading.Lock()
_cached: Optional[KeycloakConfig] = None


def current() -> KeycloakConfig:
    """The Keycloak sign-in uses now: the integration's, else .env's."""
    global _cached
    with _lock:
        if _cached is not None:
            return _cached
    try:
        from app.services.database import get_database_service
        row = get_database_service().get_signin_keycloak()
    except Exception as exc:                # not cached, so the integration is read again next time
        logger.warning("Could not read the Keycloak integration; signing in with .env's Keycloak settings: %s", exc)
        return from_env()
    cfg = from_row(row) if row else from_env()
    with _lock:
        _cached = cfg
    return cfg


def invalidate() -> None:
    """Read the sign-in Keycloak again at its next use (after a Keycloak integration changes)."""
    global _cached
    with _lock:
        _cached = None


def env_has_keycloak(settings: Optional[Settings] = None) -> bool:
    """Whether .env (or the container's environment) sets KEYCLOAK_URL, rather than TIDE's default."""
    return "keycloak_url" in (settings or get_settings()).model_fields_set


def import_from_env(db) -> Optional[str]:
    """At startup: when .env has Keycloak settings and no Keycloak integration is the one TIDE signs
    in with, make it one from them, so sign-in carries on as before and is managed in TIDE from
    now on. A Keycloak integration recorded before 6.3.0 for the same address and realm becomes
    it; otherwise a new one is made. Returns the integration's id, or None when nothing was done."""
    s = get_settings()
    if not env_has_keycloak(s) or db.get_signin_keycloak():
        return None
    env = from_env(s)
    values = dict(url=env.url, realm=env.realm, client_id_enc=env.client_id or None,
                  client_secret_enc=env.client_secret or None, tls_verify=env.verify_tls,
                  internal_url=env.internal_url or None, pg_client_id=env.pg_client_id or None)
    same = next((k for k in db.list_keycloak_inventory()
                 if (k.get("url") or "").rstrip("/") == env.url.rstrip("/") and k.get("realm") == env.realm), None)
    if same:
        db.update_keycloak_inventory_item(same["id"], used_for_signin=True,
                                          pg_client_secret_enc=env.pg_client_secret or None, **values)
        kc_id = same["id"]
    else:
        kc_id = db.create_keycloak_inventory_item(label="Keycloak", used_for_signin=True,
                                                  pg_client_secret=env.pg_client_secret or None, **values)["id"]
    invalidate()
    logger.info("Keycloak: sign-in now uses the Keycloak integration, made from .env's Keycloak settings; "
                ".env's Keycloak lines are no longer read (manage it in Settings → Management → Integrations).")
    return kc_id


def env_differences(settings: Optional[Settings] = None) -> List[Tuple[str, str, str]]:
    """``(.env line, in .env, in TIDE)`` for each Keycloak line .env still has that differs from the
    Keycloak integration TIDE signs in with; secrets are only said to differ. Empty when sign-in
    uses .env."""
    s = settings or get_settings()
    cfg = current()
    if cfg.source != "tide":
        return []
    env = from_env(s)
    rows = []
    for setting, attr in ENV_FIELDS.items():
        if setting not in s.model_fields_set:
            continue
        a, b = getattr(env, attr) or "", getattr(cfg, attr) or ""
        if attr in ("url", "internal_url"):
            a, b = a.rstrip("/"), b.rstrip("/")
        if a == b:
            continue
        line = Settings.model_fields[setting].alias
        rows.append((line, "(set)" if attr in SECRETS and a else a or "(empty)",
                     "(differs)" if attr in SECRETS and b else b or "(empty)"))
    return rows
