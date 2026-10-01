"""Per-integration TLS certificate verification.

Every integration (SIEM, GitLab, Keycloak, CTI connector) has its own "Verify TLS certificate"
setting, off by default: TIDE is built to run standalone against self-signed certificates. When it
is on, the certificate is checked against the system trust store, which includes any CA
certificate mounted into /usr/local/share/ca-certificates (see entrypoint.sh).

The Kibana and Elasticsearch helpers are called with a URL and an API key from many places, so a
SIEM's setting is looked up by the URL being called (``siem_verify``) rather than passed down
every call chain.
"""
import logging
import os
import threading
import time
from urllib.parse import urlsplit

import requests

logger = logging.getLogger(__name__)

CA_BUNDLE = os.environ.get("REQUESTS_CA_BUNDLE") or "/etc/ssl/certs/ca-certificates.crt"
_TTL_SECONDS = 30

_lock = threading.Lock()
_siem_origins: dict = {}
_loaded_at = 0.0


def verify_arg(enabled) -> "str | bool":
    """The ``verify`` argument for requests / httpx: the trust store when on, False when off."""
    return CA_BUNDLE if enabled else False


def _origin(url: str) -> str:
    parts = urlsplit((url or "").strip())
    if not parts.hostname:
        return ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return f"{parts.scheme.lower()}://{parts.hostname.lower()}:{port}"


def invalidate() -> None:
    """Forget the cached SIEM settings (call after a SIEM is added, edited or removed)."""
    global _loaded_at
    _loaded_at = 0.0


SIEM_TLS_QUERY = "SELECT kibana_url, elasticsearch_url, base_url, coalesce(tls_verify, false) FROM siem_inventory"


def _load_siem_origins() -> dict:
    from app.services.database import get_database_service
    with get_database_service().get_shared_connection() as conn:
        return siem_origins(conn.execute(SIEM_TLS_QUERY).fetchall())


def siem_origins(rows) -> dict:
    """{origin: verify} from (kibana_url, elasticsearch_url, base_url, tls_verify) rows."""
    origins: dict = {}
    for *urls, verify in rows:
        for url in urls:
            origin = _origin(url)
            if origin:
                # Two SIEM entries on one host that disagree: verify.
                origins[origin] = origins.get(origin, False) or bool(verify)
    return origins


def siem_verify(url: str) -> "str | bool":
    """``verify`` for a call to a SIEM's Kibana or Elasticsearch URL, from that SIEM's setting.
    A URL no SIEM entry owns is not verified, the same as the default."""
    global _siem_origins, _loaded_at
    with _lock:
        if time.monotonic() - _loaded_at > _TTL_SECONDS:
            try:
                _siem_origins = _load_siem_origins()
            except Exception as exc:  # noqa: BLE001 - keep the last known settings
                logger.warning("Could not read SIEM TLS settings: %s", exc)
            _loaded_at = time.monotonic()
        return verify_arg(_siem_origins.get(_origin(url), False))


class Session(requests.Session):
    """A requests session whose ``verify`` is honoured. Plain requests lets REQUESTS_CA_BUNDLE
    (set by entrypoint.sh) override ``session.verify = False`` whenever a call names no verify."""

    def request(self, method, url, *args, **kwargs):
        if kwargs.get("verify") is None:
            kwargs["verify"] = self.verify
        return super().request(method, url, *args, **kwargs)
