"""
sync_manager.py — KEV / NVD Delta Tracking & Cache Management

Implements the "Moving Target" synchronisation engine:

  TRIGGER      Sync runs on system changes (new component) OR data updates
               (new CVEs ingested).
  ORCHESTRATION
    1. Pull initial known-exploited data from local CISA KEV JSON.
    2. Cross-reference against the local NVD JSON for CPE version ranges.
  PERFORMANCE  LRU caching for NVD.

This module owns all external data access (disk).  The pure matching logic
lives in ``cpe_validator.py``. (OpenCTI vulnerability lookups were removed in
6.3.1: nothing gave them an OpenCTI to ask.)
"""
from __future__ import annotations

import json
import logging
import os
import re
from functools import lru_cache
from typing import Dict, List, Optional

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
    # Nothing to flush: the NVD cache is keyed by CVE, not by device.


def on_data_updated() -> None:
    """
    Trigger hook: called after new CVE data is ingested (KEV upload, NVD refresh).

    Flushes all caches so the next scan uses fresh data.
    """
    logger.info("[sync] CVE data updated — flushing all caches")
    invalidate_nvd_cache()
