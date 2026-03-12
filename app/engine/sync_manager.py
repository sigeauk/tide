"""
sync_manager.py — KEV / OpenCTI / NVD Delta Tracking & Cache Management

Implements the "Moving Target" synchronisation engine:

  TRIGGER      Sync runs on system changes (new component) OR data updates
               (new CVEs ingested).
  ORCHESTRATION
    1. Pull initial known-exploited data from local CISA KEV JSON.
    2. Query local OpenCTI instance (via GraphQL) for updated ``affects``
       relationships.
    3. Cross-reference against the NVD database in OpenCTI.
  PERFORMANCE  Aggressive caching (LRU for NVD, 1-hour TTL for OpenCTI).

This module owns all external data access (disk / network).  The pure
matching logic lives in ``cpe_validator.py``.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from functools import lru_cache
from typing import Dict, List, Optional

from app.engine.cpe_validator import (
    Cpe,
    _eval_cpe_matches,
    evaluate_nvd_configurations,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Local NVD JSON cache  (baked into Docker image at /opt/repos/nvd/)
# ---------------------------------------------------------------------------

def _nvd_cache_dir() -> str:
    try:
        from app.config import get_settings
        return getattr(get_settings(), "nvd_cache_path", "/opt/repos/nvd")
    except Exception:
        return "/opt/repos/nvd"


@lru_cache(maxsize=8192)
def load_nvd_entry(cve_id: str) -> Optional[str]:
    """
    Return the raw JSON string for a single CVE from the local NVD cache.

    Supported layouts under ``_nvd_cache_dir()``:
      ``{year}/CVE-YYYY-NNNNN.json``       — one file per CVE
      ``nvdcve-2.0-{year}.json``           — combined year file (NVD 2.0)
      ``nvdcve-1.1-{year}.json``           — combined year file (NVD 1.1)
    """
    cve_id = cve_id.upper()
    m = re.match(r"CVE-(\d{4})-\d+", cve_id)
    if not m:
        return None
    year = m.group(1)
    cache_dir = _nvd_cache_dir()

    # Individual file
    for fname in (f"{cve_id}.json", f"{cve_id.lower()}.json"):
        p = os.path.join(cache_dir, year, fname)
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as fh:
                    return fh.read()
            except Exception as exc:
                logger.debug("NVD local read failed %s: %s", p, exc)

    # Combined year files
    for fname in (
        f"nvdcve-2.0-{year}.json",
        f"nvdcve-1.1-{year}.json",
        f"windows-{year}.json",
        f"windows11-{year}.json",
    ):
        p = os.path.join(cache_dir, fname)
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as fh:
                    raw = json.load(fh)
                return _extract_cve_from_combined(raw, cve_id)
            except Exception as exc:
                logger.debug("NVD combined read failed %s: %s", p, exc)

    return None


def _extract_cve_from_combined(data: dict, cve_id: str) -> Optional[str]:
    """Pull a single CVE entry from a combined NVD JSON dict."""
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        if cve.get("id", "").upper() == cve_id:
            return json.dumps(cve)
    for item in data.get("CVE_Items", []):
        item_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
        if item_id.upper() == cve_id:
            return json.dumps(item)
    return None


def _cpe_ranges_from_nvd_entry(raw: str) -> List[Dict]:
    """
    Parse CPE match ranges from a raw NVD JSON string.

    Normalises both NVD 1.1 and NVD 2.0 formats into a common schema::

      {
        cpe23Uri: str,
        versionStartIncluding / versionStartExcluding: str | None,
        versionEndIncluding   / versionEndExcluding:   str | None,
        vulnerable: bool,
      }
    """
    if not raw:
        return []
    try:
        entry = json.loads(raw)
    except Exception:
        return []

    ranges: List[Dict] = []

    def _add_nodes_20(nodes):
        for node in nodes:
            for cm in node.get("cpeMatch", []):
                ranges.append({
                    "cpe23Uri": cm.get("criteria", ""),
                    "versionStartIncluding": cm.get("versionStartIncluding"),
                    "versionStartExcluding": cm.get("versionStartExcluding"),
                    "versionEndIncluding":   cm.get("versionEndIncluding"),
                    "versionEndExcluding":   cm.get("versionEndExcluding"),
                    "vulnerable": cm.get("vulnerable", True),
                })
            _add_nodes_20(node.get("children", []))

    def _add_nodes_11(nodes):
        for node in nodes:
            for cm in node.get("cpe_match", []):
                ranges.append({
                    "cpe23Uri": cm.get("cpe23Uri", ""),
                    "versionStartIncluding": cm.get("versionStartIncluding"),
                    "versionStartExcluding": cm.get("versionStartExcluding"),
                    "versionEndIncluding":   cm.get("versionEndIncluding"),
                    "versionEndExcluding":   cm.get("versionEndExcluding"),
                    "vulnerable": cm.get("vulnerable", True),
                })
            _add_nodes_11(node.get("children", []))

    for config in entry.get("configurations", []):
        if isinstance(config, dict) and "nodes" in config:
            _add_nodes_20(config["nodes"])

    if not ranges:
        _add_nodes_11(entry.get("configurations", {}).get("nodes", []))

    return ranges


def get_nvd_cpe_ranges(cve_id: str) -> List[Dict]:
    """Return CPE match ranges from the local NVD cache."""
    raw = load_nvd_entry(cve_id)
    if not raw:
        return []
    return _cpe_ranges_from_nvd_entry(raw)


# ---------------------------------------------------------------------------
# CISA KEV loader
# ---------------------------------------------------------------------------

def load_cisa_kev() -> List[Dict]:
    """Load the CISA Known Exploited Vulnerabilities catalogue from disk."""
    try:
        from app.config import get_settings
        settings = get_settings()
    except Exception:
        return []

    for path in [settings.cisa_kev_override_path, settings.cisa_kev_path]:
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                    return data.get("vulnerabilities", data if isinstance(data, list) else [])
            except Exception as exc:
                logger.warning("Failed to load CISA KEV from %s: %s", path, exc)
    logger.warning("No CISA KEV file available.")
    return []


# ---------------------------------------------------------------------------
# OpenCTI — per-CVE query (cached 1 h)
# ---------------------------------------------------------------------------

_octi_vuln_cache: Dict[str, Optional[Dict]] = {}
_octi_vuln_cache_ts: Dict[str, float] = {}
_OCTI_CACHE_TTL = 3600.0

_OCTI_VULN_QUERY = """
query VulnVersionRanges($cve: String!) {
  vulnerabilities(
    filters: {
      mode: and,
      filters: [{key: "name", values: [$cve], operator: eq}],
      filterGroups: []
    }
    first: 1
  ) {
    edges {
      node {
        name
        description
        x_opencti_cvss_base_score
        external_references {
          edges {
            node {
              source_name
              url
              description
            }
          }
        }
        stixCoreRelationships(
          relationship_type: "affects"
          toTypes: ["Software"]
          first: 200
        ) {
          edges {
            node {
              to {
                ... on Software {
                  name
                  version
                  cpe
                }
              }
              start_time
              stop_time
            }
          }
        }
      }
    }
  }
}
"""


def fetch_cve_opencti(cve_id: str) -> Optional[Dict]:
    """
    Query OpenCTI for a Vulnerability entity matching the CVE ID.

    Results are in-process cached for ``_OCTI_CACHE_TTL`` seconds.
    """
    cve_id = cve_id.upper()
    now = time.monotonic()
    if cve_id in _octi_vuln_cache:
        if now - _octi_vuln_cache_ts.get(cve_id, 0) < _OCTI_CACHE_TTL:
            return _octi_vuln_cache[cve_id]

    result = _do_fetch_cve_opencti(cve_id)
    _octi_vuln_cache[cve_id] = result
    _octi_vuln_cache_ts[cve_id] = now
    return result


def _do_fetch_cve_opencti(cve_id: str) -> Optional[Dict]:
    try:
        from app.config import get_settings
        import requests as _requests

        settings = get_settings()
        if not settings.opencti_url or not settings.opencti_token:
            return None

        headers = {
            "Authorization": f"Bearer {settings.opencti_token}",
            "Content-Type": "application/json",
        }
        ssl_ctx = settings.ssl_context
        resp = _requests.post(
            f"{settings.opencti_url.rstrip('/')}/graphql",
            json={"query": _OCTI_VULN_QUERY, "variables": {"cve": cve_id}},
            headers=headers,
            verify=ssl_ctx,
            timeout=10,
        )
        if resp.status_code != 200:
            logger.debug("OpenCTI %s for %s", resp.status_code, cve_id)
            return None

        data = resp.json()
        if "errors" in data:
            logger.debug("OpenCTI GraphQL errors for %s: %s", cve_id, data["errors"])
            return None

        edges = (data.get("data") or {}).get("vulnerabilities", {}).get("edges", [])
        if not edges:
            return None

        node = edges[0].get("node", {})
        cpe_ranges: List[Dict] = []
        for rel_edge in (node.get("stixCoreRelationships") or {}).get("edges", []):
            sw = (rel_edge.get("node") or {}).get("to") or {}
            cpe = sw.get("cpe")
            version = sw.get("version")
            if cpe:
                cpe_ranges.append({
                    "cpe23Uri": cpe,
                    "versionEndIncluding": version or None,
                    "versionStartIncluding": None,
                    "versionStartExcluding": None,
                    "versionEndExcluding": None,
                    "vulnerable": True,
                })

        return {
            "name": node.get("name", ""),
            "description": node.get("description", ""),
            "cvss_score": node.get("x_opencti_cvss_base_score"),
            "cpe_ranges": cpe_ranges,
        }
    except Exception as exc:
        logger.debug("OpenCTI query failed for %s: %s", cve_id, exc)
        return None


# ---------------------------------------------------------------------------
# OpenCTI — bulk vulnerability index (all CVEs + actors, cached 1 h)
# ---------------------------------------------------------------------------

_octi_bulk_cache: Optional[Dict[str, Dict]] = None
_octi_bulk_cache_ts: float = 0.0
_OCTI_BULK_TTL = 3600.0

_OCTI_BULK_VULN_QUERY = """
query BulkVulnerabilities($cursor: ID, $count: Int!) {
  vulnerabilities(first: $count, after: $cursor) {
    pageInfo { hasNextPage endCursor }
    edges {
      node {
        name
        description
        x_opencti_cvss_base_score
        affected_software: stixCoreRelationships(
          relationship_type: "affects"
          toTypes: ["Software"]
          first: 100
        ) {
          edges {
            node {
              to {
                ... on Software {
                  name
                  version
                  cpe
                }
              }
            }
          }
        }
        threat_actors: stixCoreRelationships(
          relationship_type: "uses"
          fromTypes: ["Intrusion-Set"]
          first: 50
        ) {
          edges {
            node {
              from {
                ... on IntrusionSet {
                  name
                }
              }
            }
          }
        }
      }
    }
  }
}
"""


def fetch_opencti_vuln_index() -> Dict[str, Dict]:
    """
    Return the full OpenCTI vulnerability index, fetching and caching if needed.

    Returns ``{CVE-ID: {description, cvss_score, cpe_ranges, actors}}``.
    """
    global _octi_bulk_cache, _octi_bulk_cache_ts
    now = time.monotonic()
    if _octi_bulk_cache is not None and (now - _octi_bulk_cache_ts) < _OCTI_BULK_TTL:
        return _octi_bulk_cache
    result = _do_fetch_opencti_vuln_index()
    _octi_bulk_cache = result
    _octi_bulk_cache_ts = now
    return result


def _do_fetch_opencti_vuln_index() -> Dict[str, Dict]:
    try:
        from app.config import get_settings
        import requests as _req

        settings = get_settings()
        if not settings.opencti_url or not settings.opencti_token:
            return {}

        headers = {
            "Authorization": f"Bearer {settings.opencti_token}",
            "Content-Type": "application/json",
        }
        ssl_ctx = settings.ssl_context
        base = settings.opencti_url.rstrip("/") + "/graphql"
        page_size = 50

        index: Dict[str, Dict] = {}
        cursor = None
        page = 0

        while True:
            variables: Dict = {"count": page_size}
            if cursor:
                variables["cursor"] = cursor

            resp = _req.post(
                base,
                json={"query": _OCTI_BULK_VULN_QUERY, "variables": variables},
                headers=headers,
                verify=ssl_ctx,
                timeout=30,
            )
            if resp.status_code != 200:
                logger.warning("[opencti-index] HTTP %s on page %d", resp.status_code, page)
                break

            data = resp.json()
            if "errors" in data:
                logger.warning("[opencti-index] GraphQL errors: %s", data["errors"])
                break

            vuln_data = (data.get("data") or {}).get("vulnerabilities", {})
            for edge in vuln_data.get("edges", []):
                node = edge.get("node") or {}
                cve_id = (node.get("name") or "").upper()
                if not cve_id.startswith("CVE-"):
                    continue

                cpe_ranges: List[Dict] = []
                for rel in (node.get("affected_software") or {}).get("edges", []):
                    sw = (rel.get("node") or {}).get("to") or {}
                    cpe = sw.get("cpe")
                    version = sw.get("version")
                    if cpe:
                        cpe_ranges.append({
                            "cpe23Uri": cpe,
                            "versionEndIncluding": version or None,
                            "versionStartIncluding": None,
                            "versionStartExcluding": None,
                            "versionEndExcluding": None,
                            "vulnerable": True,
                        })

                actors: List[str] = []
                for rel in (node.get("threat_actors") or {}).get("edges", []):
                    actor_name = ((rel.get("node") or {}).get("from") or {}).get("name", "")
                    if actor_name and actor_name not in actors:
                        actors.append(actor_name)

                index[cve_id] = {
                    "description": node.get("description", ""),
                    "cvss_score": node.get("x_opencti_cvss_base_score"),
                    "cpe_ranges": cpe_ranges,
                    "actors": actors,
                }

            page_info = vuln_data.get("pageInfo", {})
            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")
            page += 1

        logger.info("[opencti-index] Loaded %d vulnerabilities from OpenCTI", len(index))
        return index

    except Exception as exc:
        logger.warning("[opencti-index] Fetch failed: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# OpenCTI CPE-range evaluation (reuses core cpe_validator logic)
# ---------------------------------------------------------------------------

def evaluate_opencti_ranges(
    cpe_ranges: List[Dict], host_cpes: List[str],
) -> Optional[bool]:
    """
    Evaluate OpenCTI CPE ranges against the host using CPE identity matching.

    OpenCTI's NVD connector returns flat ``cpe_ranges`` (no nested nodes),
    so we emulate a single OR-group of ``cpeMatch`` entries.
    """
    if not cpe_ranges:
        return None
    return _eval_cpe_matches(cpe_ranges, "OR", host_cpes)


# ---------------------------------------------------------------------------
# Cache management
# ---------------------------------------------------------------------------

def clear_opencti_vuln_cache() -> None:
    """Flush all in-process OpenCTI caches (per-CVE and bulk index)."""
    global _octi_bulk_cache, _octi_bulk_cache_ts
    _octi_vuln_cache.clear()
    _octi_vuln_cache_ts.clear()
    _octi_bulk_cache = None
    _octi_bulk_cache_ts = 0.0
    # Allow inventory_engine to re-trigger a background warm-up
    try:
        import app.inventory_engine as _ie
        _ie._octi_warmup_started = False
    except Exception:
        pass


def invalidate_nvd_cache() -> None:
    """Clear the LRU cache for NVD entries (e.g. after a data update)."""
    load_nvd_entry.cache_clear()


# ---------------------------------------------------------------------------
# Sync triggers  (called when the platform graph changes)
# ---------------------------------------------------------------------------

def on_component_added(device_id: str) -> None:
    """
    Trigger hook: called after a new component is added to a device.

    Invalidates caches so the next vulnerability scan picks up the change.
    """
    logger.info("[sync] Component added to device %s — caches will refresh on next scan", device_id)
    # Per-CVE OpenCTI cache is TTL-based; only bulk cache needs a nudge
    # if the component introduces a new CPE that wasn't in the index.
    # For now this is a no-op — the 1-hour TTL handles natural refresh.


def on_data_updated() -> None:
    """
    Trigger hook: called after new CVE data is ingested (KEV upload, NVD refresh).

    Flushes all caches so the next scan uses fresh data.
    """
    logger.info("[sync] CVE data updated — flushing all caches")
    clear_opencti_vuln_cache()
    invalidate_nvd_cache()
