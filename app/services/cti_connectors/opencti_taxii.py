"""OpenCTI connector: Threat Landscape's link to an OpenCTI instance.

The threat sync (:mod:`app.services.sync`) reads the intrusion sets of each
active OpenCTI connector linked to the client through OpenCTI's GraphQL API
(:func:`app.cti_helper.get_threat_landscape`) into that client's own database.
GraphQL rather than TAXII 2.1: it can read, and later write, more than a TAXII
collection shares. A connector holds the
address, the API token and whether to verify TLS. The address may be
OpenCTI's own or the TAXII 2.1 root it shows (``.../taxii2/root/``), which
connectors made before 6.3.0 hold; :func:`graphql_base` works out the
GraphQL address from either. The vendor keeps the name ``opencti_taxii`` so
those connectors keep working.
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlsplit, urlunsplit

import requests

from ._base import ConnectorVendor, FieldSpec


FIELDS: List[FieldSpec] = [
    FieldSpec(
        key="taxii_root", label="OpenCTI address", type="url",
        required=True,
        default="https://opencti.example.com/",
        help="For example https://opencti.example.com/. The TAXII 2.1 "
             "root OpenCTI shows, such as "
             "https://opencti.example.com/taxii2/root/, also works.",
    ),
    FieldSpec(
        key="token", label="OpenCTI API Token",
        type="password", required=True, secret=True,
        help="Bearer token of an OpenCTI user who can read intrusion sets.",
    ),
    FieldSpec(
        key="verify_tls", label="Verify TLS certificate",
        type="bool", default=False,
        help="Leave off for a self-signed certificate.",
    ),
]


def graphql_base(address: str) -> str:
    """OpenCTI's base URL (``<base>/graphql`` is its API) from its address or a TAXII root."""
    root = (address or "").strip()
    if not root:
        return ""
    parts = urlsplit(root)
    path = parts.path or "/"
    marker = "/taxii2/"
    if marker in path:
        path = path.split(marker, 1)[0] or "/"
    if not path.endswith("/"):
        path += "/"
    base = urlunsplit((parts.scheme, parts.netloc, path.rstrip("/"), "", ""))
    return base.rstrip("/")


def test_connection(connector: Dict[str, Any]) -> Dict[str, Any]:
    """Used by the Management → Connectors Test button: asks OpenCTI's GraphQL API for its
    version with the connector's token, as the threat sync would connect."""
    from app.services import tls

    cfg = connector.get("config") or {}
    base = graphql_base(cfg.get("taxii_root") or "")
    token = (cfg.get("token") or "").strip()
    if not (base and token):
        return {"ok": False, "error": "The OpenCTI address and API token are required."}
    try:
        resp = requests.post(
            f"{base}/graphql",
            json={"query": "{ about { version } }"},
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=20,
            verify=tls.verify_arg(cfg.get("verify_tls")),
        )
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)[:200]}
    if resp.status_code != 200:
        return {"ok": False, "error": f"OpenCTI answered HTTP {resp.status_code} at {base}/graphql"}
    try:
        data = resp.json()
    except ValueError:
        return {"ok": False, "error": f"{base}/graphql did not answer with JSON; is this OpenCTI?"}
    if data.get("errors"):
        return {"ok": False, "error": str(data["errors"][0].get("message") or data["errors"][0])[:200]}
    version = ((data.get("data") or {}).get("about") or {}).get("version")
    return {"ok": True, "message": f"OpenCTI {version}" if version else "connection ok"}


VENDOR = ConnectorVendor(
    name="opencti_taxii",
    label="OpenCTI",
    icon="opencti",
    fields=FIELDS,
    tester=test_connection,
)
