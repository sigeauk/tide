"""
cpe_validator.py — Strict CPE 2.3 Identity Matching & Version Arithmetic

Design principles (inherited from the original version_gate.py):
  * **No string heuristics** — zero references to specific OS names, hardware
    brands, or software vendors.  A CPE is an opaque data object.
  * **CPE identity gate first** — Part, Vendor, Product must match exactly
    (wildcards treated as "any").
  * **Mathematical version bounds** — ``packaging.version.Version`` is used
    directly.  If a version string is non-numeric / unparseable, ``None`` is
    returned (no guessing).
  * **Recursive NVD node evaluation** — NVD ``configurations`` can contain
    nested AND/OR logic; the engine evaluates the full tree.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    from packaging.version import Version, InvalidVersion
except ImportError as _pkg_err:  # pragma: no cover
    raise ImportError(
        "The 'packaging' library is required.  "
        "Add 'packaging>=23.0' to requirements.txt."
    ) from _pkg_err

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CPE constants
# ---------------------------------------------------------------------------
_CPE_ANY = frozenset({"*", "-", "", "ANY", "NA"})


# ---------------------------------------------------------------------------
# CPE 2.3 dataclass + parser
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Cpe:
    """Parsed representation of a CPE 2.3 or CPE 2.2 URI."""

    part: str           # "o", "a", "h", or ""
    vendor: str
    product: str
    version: str        # raw version string ("*" / "-" / "22h2" / "10.0.1")
    update: str
    edition: str
    raw: str            # original unparsed string

    parsed_version: Optional[Version] = field(
        default=None, compare=False, hash=False,
    )

    # ---- construction ----

    @staticmethod
    def parse(cpe_str: str) -> "Cpe":
        """Parse a CPE 2.2 or CPE 2.3 string into a ``Cpe`` object."""
        if not cpe_str:
            return Cpe("", "", "", "*", "*", "*", cpe_str, None)

        if cpe_str.startswith("cpe:2.3:"):
            parts = cpe_str.split(":")

            def _f(idx: int) -> str:
                return parts[idx] if idx < len(parts) else "*"

            part    = _f(2).lower()
            vendor  = _f(3).lower().replace("\\", "")
            product = _f(4).lower().replace("\\", "")
            version = _f(5)
            update  = _f(6)
            edition = _f(7)

        elif cpe_str.startswith("cpe:/"):
            body = cpe_str[5:]
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
            parts = cpe_str.split(":")
            part    = parts[2].lower() if len(parts) > 2 else ""
            vendor  = parts[3].lower() if len(parts) > 3 else ""
            product = parts[4].lower() if len(parts) > 4 else ""
            version = parts[5] if len(parts) > 5 else "*"
            update  = parts[6] if len(parts) > 6 else "*"
            edition = parts[7] if len(parts) > 7 else "*"

        pv = parse_version(version)
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

    # ---- identity match ----

    def identity_matches(self, other: "Cpe") -> bool:
        """
        Return True when Part, Vendor, and Product are equal.

        Wildcards (``*``, ``-``) in either CPE count as "any".
        """
        def _eq(a: str, b: str) -> bool:
            return (a in _CPE_ANY or b in _CPE_ANY) or (a == b)

        return (
            _eq(self.part, other.part)
            and _eq(self.vendor, other.vendor)
            and _eq(self.product, other.product)
        )


# ---------------------------------------------------------------------------
# Version parsing (no normalisation, no guessing)
# ---------------------------------------------------------------------------

def parse_version(ver_str: str) -> Optional[Version]:
    """Parse *ver_str* into ``packaging.version.Version``, or ``None``."""
    if not ver_str:
        return None
    s = ver_str.strip()
    if s in _CPE_ANY:
        return None
    try:
        return Version(s)
    except InvalidVersion:
        return None


# ---------------------------------------------------------------------------
# Host-CPE lookup helper
# ---------------------------------------------------------------------------

def _host_cpe_version(host_cpes: List[str], nvd_cpe: Cpe) -> Optional[Version]:
    """Return the parsed version from the first host CPE that identity-matches *nvd_cpe*."""
    for raw in host_cpes:
        hcpe = Cpe.parse(raw)
        if nvd_cpe.identity_matches(hcpe) and hcpe.parsed_version is not None:
            return hcpe.parsed_version
    return None


# ---------------------------------------------------------------------------
# Version-range comparison
# ---------------------------------------------------------------------------

def version_in_range(
    host_version: Version,
    ver_si: Optional[str],
    ver_se: Optional[str],
    ver_ei: Optional[str],
    ver_ee: Optional[str],
) -> bool:
    """
    Return True if *host_version* falls within the specified bounds.

    Missing bounds → unbounded on that side.
    Unparseable bounds → treated as unbounded (fail-safe: include).
    """
    if not any((ver_si, ver_se, ver_ei, ver_ee)):
        return True  # No bounds → all versions affected

    in_range = True

    if ver_si:
        start = parse_version(ver_si)
        if start is not None and host_version < start:
            in_range = False

    if ver_se and in_range:
        start = parse_version(ver_se)
        if start is not None and host_version <= start:
            in_range = False

    if ver_ei and in_range:
        end = parse_version(ver_ei)
        if end is not None and host_version > end:
            in_range = False

    if ver_ee and in_range:
        end = parse_version(ver_ee)
        if end is not None and host_version >= end:
            in_range = False

    return in_range


# ---------------------------------------------------------------------------
# Recursive NVD configuration tree evaluator
# ---------------------------------------------------------------------------

def evaluate_nvd_configurations(
    entry: dict, host_cpes: List[str],
) -> Optional[bool]:
    """
    Recursively evaluate the NVD ``configurations`` tree against *host_cpes*.

    Returns:
      True  — host satisfies at least one vulnerable group → flag the CVE
      False — configurations exist but none satisfied → suppress
      None  — no relevant CPE data for this host → fall through
    """
    configs = entry.get("configurations", [])

    if isinstance(configs, list) and configs:
        return _eval_config_list_20(configs, host_cpes)

    if isinstance(configs, dict):
        nodes = configs.get("nodes", [])
        if nodes:
            return _eval_nodes(nodes, "OR", host_cpes)

    return None


def _eval_config_list_20(
    configs: list, host_cpes: List[str],
) -> Optional[bool]:
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


def _eval_nodes(
    nodes: list, operator: str, host_cpes: List[str],
) -> Optional[bool]:
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
    results: List[Optional[bool]] = []

    for cm in cpe_matches:
        nvd_cpe_str = cm.get("criteria") or cm.get("cpe23Uri") or ""
        if not nvd_cpe_str:
            continue

        nvd_cpe = Cpe.parse(nvd_cpe_str)
        host_version = _host_cpe_version(host_cpes, nvd_cpe)

        if host_version is None:
            results.append(None)
            continue

        in_range = version_in_range(
            host_version,
            cm.get("versionStartIncluding"),
            cm.get("versionStartExcluding"),
            cm.get("versionEndIncluding"),
            cm.get("versionEndExcluding"),
        )

        if cm.get("vulnerable", True):
            results.append(in_range)
        else:
            results.append(True)

    if operator == "AND":
        return _combine_and(results)
    return _combine_or(results)


# ---------------------------------------------------------------------------
# Boolean combinators (three-valued: True / False / None)
# ---------------------------------------------------------------------------

def _combine_and(results: List[Optional[bool]]) -> Optional[bool]:
    """
    AND-combine with product-presence semantics.

    All None → None (no relevant CPE data).
    Any non-True → False.
    """
    if not results or all(r is None for r in results):
        return None
    for r in results:
        if r is not True:
            return False
    return True


def _combine_or(results: List[Optional[bool]]) -> Optional[bool]:
    """OR-combine: any True → True; all None → None; else False."""
    has_false = False
    for r in results:
        if r is True:
            return True
        if r is False:
            has_false = True
    return False if has_false else None


# ---------------------------------------------------------------------------
# Top-level gate (called from sync_manager or inventory_engine)
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
      1. Collect host CPEs.  If empty → include.
      2. NVD local JSON → recursive CPE-identity + version-range evaluation.
      3. OpenCTI live → secondary source using same CPE evaluation.
      4. Default → include (never suppress without proof).

    Zero string heuristics.  Zero OS knowledge.  Zero version normalisation.
    """
    # Lazy import to break circular dependency with sync_manager
    from app.engine.sync_manager import (
        load_nvd_entry,
        fetch_cve_opencti,
        evaluate_opencti_ranges,
    )

    host_cpes: List[str] = [c for c in (host_sw_cpes or []) if c]
    if not host_cpes:
        logger.debug("[vgate] %s: no host CPEs — including conservatively", cve_id)
        return True

    # Step 2: Local NVD JSON
    raw = load_nvd_entry(cve_id)
    if raw:
        try:
            entry = json.loads(raw)
        except Exception:
            entry = {}
        result = evaluate_nvd_configurations(entry, host_cpes)
        if result is not None:
            if not result:
                logger.debug("[vgate] %s: NVD local → NOT affected", cve_id)
            return result

    # Step 3: OpenCTI live
    octi = fetch_cve_opencti(cve_id)
    if octi and octi.get("cpe_ranges"):
        result = evaluate_opencti_ranges(octi["cpe_ranges"], host_cpes)
        if result is not None:
            if not result:
                logger.debug("[vgate] %s: OpenCTI → NOT affected", cve_id)
            return result

    # Step 4: Default — include
    return True
