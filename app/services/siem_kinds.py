"""What kind of SIEM a ``siem_inventory`` row (or a destination from ``get_client_siems``) is.

Kibana's features work on Elastic SIEMs only: sync's Kibana reads, deploying, Move and Copy, editing,
exceptions, the field catalogue and the GitLab rule backup. A Wazuh SIEM is read from its own API and
indexer (app.services.wazuh) and never written to. Splunk and Sentinel can be registered, but nothing
reads them yet.
"""

WAZUH = "wazuh"
_ELASTIC = ("elastic", "elasticsearch", "", None)


def is_elastic(siem) -> bool:
    return (siem or {}).get("siem_type") in _ELASTIC


def is_wazuh(siem) -> bool:
    return (siem or {}).get("siem_type") == WAZUH


def elastic_only(destinations) -> list:
    """The Elastic ones of ``destinations``: the targets Kibana's features may offer."""
    return [d for d in destinations or [] if is_elastic(d)]
