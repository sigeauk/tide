"""
version_gate.py — CPE-Identity & Version-Range CVE Filtering

Prevents false-positive vulnerability alerts by performing strict CPE 2.3
identity matching (part/vendor/product) between the host's software CPEs and
NVD configuration entries, then mathematically comparing version ranges using
``packaging.version.Version``.

Design principles
-----------------
* **No string heuristics** — "microsoft", "windows", etc. are NOT special-cased.
  A Windows CVE is treated identically to a Linux or Chrome CPE.
* **CPE identity gate first** — a CVE only applies if at least one host CPE
  shares the same ``part``, ``vendor``, and ``product`` as an NVD ``cpeMatch``
  entry that is marked ``vulnerable:true``.
* **Mathematical version bounds** — ``packaging.version.Version`` is used for
  all comparisons directly. No normalisation is applied. If the CPE emits
  ``26100.7840`` and NVD stores ``10.0.26100.7840``, they are different values
  and will not match. The ingestion pipeline must provide accurate CPEs.
* **Recursive NVD node evaluation** — NVD ``configurations`` can contain nested
  AND/OR logic; the engine evaluates the full tree before deciding.

Priority ladder:
  1. Local NVD JSON  — /opt/repos/nvd/ baked into image at build time
  2. OpenCTI live    — NVD-connector-backed Vulnerability objects (cached 1 h)
  3. Default         — include (fail-safe: over-report rather than miss)
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Dict, List, Optional

try:
    from packaging.version import Version, InvalidVersion
except ImportError as _pkg_err:  # pragma: no cover
    raise ImportError(
        "The 'packaging' library is required for version-range comparison. "
        "Add 'packaging>=23.0' to requirements.txt."
    ) from _pkg_err

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CPE constants and version regexes
# ---------------------------------------------------------------------------

# Wildcard / any / not-applicable sentinels in CPE
_CPE_ANY = frozenset({"*", "-", "", "ANY", "NA"})


# ---------------------------------------------------------------------------
# CPE 2.3 parser
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Cpe:
    """Parsed representation of a CPE 2.3 or CPE 2.2 URI."""
    part: str       # "o", "a", "h", or ""
    vendor: str
    product: str
    version: str    # raw version string from CPE; may be "*", "-", or "22h2"
    update: str
    edition: str
    raw: str        # original unparsed string

    # Derived version (None if the version field is a named token, wildcard,
    # or otherwise unparseable as a dotted-numeric version).
    parsed_version: Optional[Version] = field(default=None, compare=False, hash=False)

    @staticmethod
    def parse(cpe_str: str) -> "Cpe":
        """Parse a CPE 2.2 or CPE 2.3 string into a Cpe object."""
        if not cpe_str:
            return Cpe("", "", "", "*", "*", "*", cpe_str, None)

        if cpe_str.startswith("cpe:2.3:"):
            # cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:...
            parts = cpe_str.split(":")
            # indices: [0]="cpe" [1]="2.3" [2]=part [3]=vendor [4]=product [5]=version ...

            def _f(idx: int) -> str:
                return parts[idx] if idx < len(parts) else "*"

            part    = _f(2).lower()
            vendor  = _f(3).lower().replace("\\", "")
            product = _f(4).lower().replace("\\", "")
            version = _f(5)
            update  = _f(6)
            edition = _f(7)

        elif cpe_str.startswith("cpe:/"):
            # cpe:/<part>:<vendor>:<product>:<version>:<update>:<edition>
            body = cpe_str[5:]   # strip "cpe:/"
            parts = body.split(":")

            def _f(idx: int) -> str:
                return parts[idx] if idx < len(parts) else "*"

            raw_part = _f(0)
            part    = raw_part.split("/")[0].lower() if "/" in raw_part else raw_part.lower()
            vendor  = _f(1).lower().replace("\\", "")
            product = _f(2).lower().replace("\\", "")
            version = _f(3)
            update  = _f(4)
            edition = _f(5)

        else:
            # Unknown format — best-effort split
            parts = cpe_str.split(":")
            part    = parts[2].lower() if len(parts) > 2 else ""
            vendor  = parts[3].lower() if len(parts) > 3 else ""
            product = parts[4].lower() if len(parts) > 4 else ""
            version = parts[5] if len(parts) > 5 else "*"
            update  = parts[6] if len(parts) > 6 else "*"
            edition = parts[7] if len(parts) > 7 else "*"

        pv = _parse_version(version)
        return Cpe(
            part=part,
            vendor=vendor,
            product=product,
            version=version,
            update=update,
            edition=edition,
            raw=cpe_str,
            parsed_version=pv,
        )

    def identity_matches(self, other: "Cpe") -> bool:
        """
        Return True if part, vendor, and product are equal.

        Wildcards ("*", "-") in either CPE count as "any", so NVD entries
        with part="*" still match against host CPEs.
        """
        def _match(a: str, b: str) -> bool:
            return (a in _CPE_ANY or b in _CPE_ANY) or (a == b)

        return (
            _match(self.part, other.part)
            and _match(self.vendor, other.vendor)
            and _match(self.product, other.product)
        )


# ---------------------------------------------------------------------------
# Version parsing helpers
# ---------------------------------------------------------------------------

def _parse_version(ver_str: str) -> Optional[Version]:
    """
    Parse a version string into a packaging.version.Version.

    No normalisation is applied. The version string is passed directly to
    ``packaging.version.Version``. If it is a CPE wildcard or packaging
    rejects it, ``None`` is returned — the caller treats a missing version
    as "unbounded on that side" (fail-safe include).
    """
    if not ver_str:
        return None
    s = ver_str.strip()
    if s in _CPE_ANY:
        return None
    try:
        return Version(s)
    except InvalidVersion:
        return None


def _host_cpe_version(host_cpes: List[str], nvd_cpe: Cpe) -> Optional[Version]:
    """
    Find the host CPE that identity-matches the NVD CPE and return its version.

    Returns None if no host CPE matches the product or if the matching CPE
    carries an unparseable version (caller treats as "version unknown -> include").
    """
    for raw in host_cpes:
        hcpe = Cpe.parse(raw)
        if nvd_cpe.identity_matches(hcpe):
            if hcpe.parsed_version is not None:
                return hcpe.parsed_version
    return None


# ---------------------------------------------------------------------------
# Local NVD JSON cache (baked into Docker image at build time)
# ---------------------------------------------------------------------------

def _nvd_cache_dir() -> str:
    try:
        from app.config import get_settings
        return getattr(get_settings(), "nvd_cache_path", "/opt/repos/nvd")
    except Exception:
        return "/opt/repos/nvd"


@lru_cache(maxsize=8192)
def _load_nvd_entry(cve_id: str) -> Optional[str]:
    """
    Return the raw JSON string for a single CVE from the local NVD cache, or None.
    Results are lru_cached to avoid repeated disk reads.

    Supported layouts under _nvd_cache_dir():
      {year}/CVE-YYYY-NNNNN.json          — one file per CVE (NVD 2.0 API export)
      nvdcve-2.0-{year}.json              — combined year file (NVD 2.0)
      nvdcve-1.1-{year}.json              — combined year file (NVD 1.1 legacy)
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
                logger.debug(f"NVD local read failed {p}: {exc}")

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
                logger.debug(f"NVD combined read failed {p}: {exc}")

    return None


def _extract_cve_from_combined(data: dict, cve_id: str) -> Optional[str]:
    """Pull a single CVE entry from a combined NVD JSON dict."""
    # NVD 2.0
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        if cve.get("id", "").upper() == cve_id:
            return json.dumps(cve)
    # NVD 1.1
    for item in data.get("CVE_Items", []):
        item_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
        if item_id.upper() == cve_id:
            return json.dumps(item)
    return None


def _cpe_ranges_from_nvd_entry(raw: str) -> List[Dict]:
    """
    Parse CPE match ranges from a raw NVD JSON string.
    Normalises both NVD 1.1 and NVD 2.0 formats into a common schema:
      {
        cpe23Uri: str,
        versionStartIncluding: str | None,
        versionStartExcluding: str | None,
        versionEndIncluding:   str | None,
        versionEndExcluding:   str | None,
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

    # NVD 2.0: entry["configurations"][*]["nodes"]
    for config in entry.get("configurations", []):
        if isinstance(config, dict) and "nodes" in config:
            _add_nodes_20(config["nodes"])

    # NVD 1.1: entry["configurations"]["nodes"]
    if not ranges:
        _add_nodes_11(entry.get("configurations", {}).get("nodes", []))

    return ranges


def get_nvd_cpe_ranges(cve_id: str) -> List[Dict]:
    """Return CPE match ranges from the local NVD cache. Empty list if unavailable."""
    raw = _load_nvd_entry(cve_id)
    if not raw:
        return []
    return _cpe_ranges_from_nvd_entry(raw)


# ---------------------------------------------------------------------------
# Recursive NVD configuration tree evaluator
# ---------------------------------------------------------------------------

def _evaluate_nvd_configurations(entry: dict, host_cpes: List[str]) -> Optional[bool]:
    """
    Recursively evaluate the NVD ``configurations`` tree against the host's CPEs.

    Returns:
      True  — host satisfies at least one vulnerable AND-group -> flag the CVE
      False — configurations exist but no AND-group is satisfied -> suppress
      None  — no relevant CPE data found for this host -> fall through
    """
    configs = entry.get("configurations", [])

    # NVD 2.0: list of {"nodes": [...], "operator": "AND"|"OR", ...}
    if isinstance(configs, list) and configs:
        return _eval_config_list_20(configs, host_cpes)

    # NVD 1.1: {"nodes": [...]}
    if isinstance(configs, dict):
        nodes = configs.get("nodes", [])
        if nodes:
            return _eval_nodes(nodes, "OR", host_cpes)

    return None


def _eval_config_list_20(configs: list, host_cpes: List[str]) -> Optional[bool]:
    """
    Evaluate a NVD 2.0 top-level configurations list.

    Each item is an independent configuration group (OR-combined at the top level).
    Within a group, ``operator`` specifies how nodes are combined (AND/OR).
    """
    any_relevant = False
    for config in configs:
        nodes = config.get("nodes", [])
        if not nodes:
            continue
        operator = config.get("operator", "OR").upper()
        result = _eval_nodes(nodes, operator, host_cpes)
        if result is None:
            continue
        any_relevant = True
        if result:
            return True

    return False if any_relevant else None


def _eval_nodes(nodes: list, operator: str, host_cpes: List[str]) -> Optional[bool]:
    """
    Evaluate a list of NVD nodes combined by ``operator`` (AND or OR).

    Each node may contain:
      - ``cpeMatch`` (NVD 2.0) or ``cpe_match`` (NVD 1.1) entries
      - ``children`` nested nodes (evaluated recursively)
      - ``operator`` that applies to items within this node

    AND: ALL nodes must be satisfied (e.g. "running on Windows" AND "app installed")
    OR:  ANY node satisfying is sufficient
    """
    if not nodes:
        return None

    results: List[Optional[bool]] = []
    for node in nodes:
        node_op = node.get("operator", "OR").upper()
        cpe_matches = node.get("cpeMatch") or node.get("cpe_match") or []
        children = node.get("children", [])

        node_result: Optional[bool] = None

        if cpe_matches:
            node_result = _eval_cpe_matches(cpe_matches, node_op, host_cpes)

        if children:
            child_result = _eval_nodes(children, node_op, host_cpes)
            if node_result is None:
                node_result = child_result
            elif child_result is not None:
                if node_op == "AND":
                    node_result = node_result and child_result
                else:
                    node_result = node_result or child_result

        results.append(node_result)

    if operator == "AND":
        return _combine_and(results)
    return _combine_or(results)


def _eval_cpe_matches(
    cpe_matches: list,
    operator: str,
    host_cpes: List[str],
) -> Optional[bool]:
    """
    Evaluate a list of cpeMatch entries against the host CPE list.

    For each entry:
      1. Parse the NVD CPE into a Cpe object.
      2. Find the host CPE whose identity (part/vendor/product) matches.
      3. Compare the host version against the NVD version bounds.

    Non-vulnerable context entries (e.g. OS platform node in an app CVE) are
    evaluated as "host has this product" (True) so AND-node logic works.
    """
    results: List[Optional[bool]] = []

    for cm in cpe_matches:
        nvd_cpe_str = cm.get("criteria") or cm.get("cpe23Uri") or ""
        if not nvd_cpe_str:
            continue

        nvd_cpe = Cpe.parse(nvd_cpe_str)
        ver_si = cm.get("versionStartIncluding")
        ver_se = cm.get("versionStartExcluding")
        ver_ei = cm.get("versionEndIncluding")
        ver_ee = cm.get("versionEndExcluding")

        # Identity-match: find a host CPE with same part/vendor/product
        host_version = _host_cpe_version(host_cpes, nvd_cpe)

        if host_version is None:
            # Host does not have this product — not relevant to this node
            results.append(None)
            continue

        # Host has this product — check version bounds
        in_range = _version_in_range(host_version, ver_si, ver_se, ver_ei, ver_ee)

        vulnerable = cm.get("vulnerable", True)
        if vulnerable:
            results.append(in_range)
        else:
            # Context / platform node: satisfied as long as host has the product
            results.append(True)

    if operator == "AND":
        return _combine_and(results)
    return _combine_or(results)


def _version_in_range(
    host_version: Version,
    ver_si: Optional[str],
    ver_se: Optional[str],
    ver_ei: Optional[str],
    ver_ee: Optional[str],
) -> bool:
    """
    Return True if host_version falls within the version range defined by the bounds.

    Missing bounds are treated as unbounded on that side.
    Unparseable bounds (named tokens like "22h2") are also treated as unbounded
    (fail-safe: include rather than incorrectly suppress).
    """
    has_any_bound = any((ver_si, ver_se, ver_ei, ver_ee))
    if not has_any_bound:
        # No version bounds -> applies to ALL versions of this product
        return True

    in_range = True

    if ver_si:
        start = _parse_version(ver_si)
        if start is not None and host_version < start:
            in_range = False

    if ver_se and in_range:
        start = _parse_version(ver_se)
        if start is not None and host_version <= start:
            in_range = False

    if ver_ei and in_range:
        end = _parse_version(ver_ei)
        if end is not None and host_version > end:
            # Host version is strictly newer than the last-affected version -> patched
            in_range = False

    if ver_ee and in_range:
        end = _parse_version(ver_ee)
        if end is not None and host_version >= end:
            in_range = False

    return in_range


def _combine_and(results: List[Optional[bool]]) -> Optional[bool]:
    """
    AND-combine Optional[bool] with strict product-presence semantics.

    In an AND node, every sub-node must be satisfied:
      - False   => product present but version out of range  (not satisfied)
      - None    => product not found on this host            (not satisfied)
      - True    => product present and in vulnerable range   (satisfied)

    Special case: if ALL results are None, the entire AND group had no
    relevant CPE data for this host -> fall through (include conservatively).
    """
    if not results or all(r is None for r in results):
        return None  # no CPE data relevant to this host
    # Any non-True (False or None) breaks the AND
    for r in results:
        if r is not True:
            return False
    return True


def _combine_or(results: List[Optional[bool]]) -> Optional[bool]:
    """OR-combine Optional[bool]: any True -> True; all None -> None; else False."""
    has_false = False
    for r in results:
        if r is True:
            return True
        if r is False:
            has_false = True
    return False if has_false else None


# ---------------------------------------------------------------------------
# OpenCTI vulnerability query (live, cached 1 hour)
# ---------------------------------------------------------------------------

_octi_vuln_cache: Dict[str, Optional[Dict]] = {}
_octi_vuln_cache_ts: Dict[str, float] = {}
_OCTI_CACHE_TTL = 3600.0  # seconds

# ---------------------------------------------------------------------------
# OpenCTI bulk vulnerability index (all CVEs + actors, cached 1 hour)
# ---------------------------------------------------------------------------

_octi_bulk_cache: Optional[Dict[str, Dict]] = None
_octi_bulk_cache_ts: float = 0.0
_OCTI_BULK_TTL = 3600.0

# Fetches every Vulnerability node with its affected-Software CPEs and the
# Intrusion-Sets that "use" it. Uses GraphQL aliases to request both
# relationship types from the same node in a single round-trip per page.
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

    Returns a dict keyed by upper-case CVE ID:
      {
        "CVE-YYYY-NNNNN": {
          "description": str,
          "cvss_score":  float | None,
          "cpe_ranges":  List[Dict],   # same schema as NVD cpeMatch ranges
          "actors":      List[str],    # intrusion-set names that "use" this CVE
        },
        ...
      }
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
        page_size = 50  # keep response size manageable

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

                # Affected-software CPEs → cpe_ranges list
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

                # Intrusion-Set (actor) names
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

    Returns a dict with:
      name, description, cvss_score, cpe_ranges (list of CPE match dicts)
    or None if not found / unreachable.

    Results are in-process cached for _OCTI_CACHE_TTL to avoid thrashing
    during a single vulnerability-matching cycle.
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
            logger.debug(f"OpenCTI {resp.status_code} for {cve_id}")
            return None

        data = resp.json()
        if "errors" in data:
            logger.debug(f"OpenCTI GraphQL errors for {cve_id}: {data['errors']}")
            return None

        edges = (data.get("data") or {}).get("vulnerabilities", {}).get("edges", [])
        if not edges:
            return None

        node = edges[0].get("node", {})

        # Build CPE ranges from "affects" relationships (NVD connector may populate these)
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
        logger.debug(f"OpenCTI query failed for {cve_id}: {exc}")
        return None


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


# ---------------------------------------------------------------------------
# OpenCTI CPE-range evaluation (reuses core logic)
# ---------------------------------------------------------------------------

def _evaluate_opencti_ranges(cpe_ranges: List[Dict], host_cpes: List[str]) -> Optional[bool]:
    """
    Evaluate OpenCTI CPE ranges against the host using CPE identity matching.

    OpenCTI's NVD connector returns flat cpe_ranges (no nested nodes), so
    we emulate a single OR-group of cpeMatch entries.
    """
    if not cpe_ranges:
        return None
    return _eval_cpe_matches(cpe_ranges, "OR", host_cpes)


# ---------------------------------------------------------------------------
# Main gate function
# ---------------------------------------------------------------------------

def should_include_match(
    cve_id: str,
    kev_entry: Dict,
    matched_sw_cpes: List[str],
    host_sw_cpes: List[str],
) -> bool:
    """
    CPE Identity Version Gate — return True if the CVE should be reported.

    Pipeline (fail-safe — include whenever data is insufficient):
      1. Use host_sw_cpes directly as the CPE list. If empty, include.
      2. NVD local JSON — recursive CPE-identity + version-range evaluation.
      3. OpenCTI live   — secondary source using same CPE evaluation.
      4. Default        — include (never suppress without proof).

    This function is a "dumb calculator". It contains zero string heuristics,
    zero OS knowledge, and zero version normalisation. CPE versions are
    compared exactly as provided. The ingestion pipeline is responsible for
    emitting CPEs whose version fields match the NVD data format.
    """
    # Step 1: Use the software CPE list directly — no OS string augmentation
    host_cpes: List[str] = [c for c in (host_sw_cpes or []) if c]

    if not host_cpes:
        # No CPE data available — include conservatively
        logger.debug("[vgate] %s: no host CPEs — including conservatively", cve_id)
        return True

    # Step 2: Local NVD JSON — authoritative
    raw = _load_nvd_entry(cve_id)
    if raw:
        try:
            entry = json.loads(raw)
        except Exception:
            entry = {}

        result = _evaluate_nvd_configurations(entry, host_cpes)
        if result is not None:
            if not result:
                logger.debug(
                    "[vgate] %s: NVD local -> NOT affected (host_cpes=%s)",
                    cve_id, host_cpes,
                )
            return result

    # Step 3: OpenCTI live query
    octi = fetch_cve_opencti(cve_id)
    if octi and octi.get("cpe_ranges"):
        result = _evaluate_opencti_ranges(octi["cpe_ranges"], host_cpes)
        if result is not None:
            if not result:
                logger.debug(
                    "[vgate] %s: OpenCTI -> NOT affected (host_cpes=%s)",
                    cve_id, host_cpes,
                )
            return result

    # Step 4: Default — include (no definitive data confirms it's patched)
    return True
