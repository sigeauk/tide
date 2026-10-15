"""The reference data bundled in the TIDE image: ATT&CK (four domains), the Sigma rules, the CISA
KEV catalogue and the ATT&CK mappings (KEV -> ATT&CK, NIST 800-53 -> ATT&CK). For each: whether it
is there, and what it says about itself (its version or date, and when it was fetched into the
image), for the Dashboard's Built-in data section.

What a file says about itself is read once per file version (path and modified time), so a new
image or an override file shows at once and nothing is re-read otherwise.
"""
import json
import logging
import os
import re
from datetime import datetime, timezone
from functools import lru_cache
from typing import List, Optional

from app.config import get_settings

logger = logging.getLogger(__name__)

NIST_FILE = "nist_800_53-rev5_attack-16.1-enterprise.json"      # as app/services/nist_kb.py reads it

# key -> name, in the order the section shows them
ITEMS = (
    ("mitre_enterprise", "MITRE Enterprise ATT&CK"),
    ("mitre_mobile", "MITRE Mobile ATT&CK"),
    ("mitre_ics", "MITRE ICS ATT&CK"),
    ("sigma", "Sigma Rules"),
    ("cisa_kev", "CISA KEV catalogue"),
    ("attack_cve", "ATT&CK to CVE mapping"),
    ("nist", "NIST 800-53 to ATT&CK mapping"),
)


def _path(key: str) -> str:
    s = get_settings()
    if key.startswith("mitre_"):
        return os.path.join(s.mitre_repo_path, f"{key[len('mitre_'):]}-attack.json")
    if key == "sigma":
        return os.path.join(s.sigma_repo_path, "rules")
    if key == "cisa_kev":
        override = s.cisa_kev_override_path
        return override if override and os.path.isfile(override) else s.cisa_kev_path
    if key == "attack_cve":
        return s.mitre_cve_path
    return os.path.join(os.path.dirname(s.mitre_cve_path), NIST_FILE)


def _iso(us_date: Optional[str]) -> str:
    """A mapping file's 'MM/DD/YYYY' as YYYY-MM-DD; anything else as it is."""
    try:
        return datetime.strptime(us_date or "", "%m/%d/%Y").date().isoformat()
    except ValueError:
        return us_date or "unknown"


@lru_cache(maxsize=32)
def _detail(key: str, path: str, mtime: float) -> str:
    """What the file says about itself (``mtime`` keys the cache to this version of it)."""
    try:
        if key.startswith("mitre_"):
            with open(path, encoding="utf-8") as fh:
                dates = re.findall(r'"modified":\s*"(\d{4}-\d{2}-\d{2})', fh.read())
            return f"ATT&CK data updated {max(dates)}" if dates else "ATT&CK data"
        if key == "sigma":
            count = sum(1 for _, _, files in os.walk(path) for f in files if f.endswith((".yml", ".yaml")))
            return f"{count:,} rules"
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if key == "cisa_kev":
            return f"Catalogue {data.get('catalogVersion', 'unknown')}, {data.get('count', len(data.get('vulnerabilities', []))):,} vulnerabilities"
        meta = data.get("metadata") or {}
        framework = "KEV" if key == "attack_cve" else "NIST 800-53"
        version = meta.get("mapping_framework_version") or ""
        version = _iso(version) if "/" in version else version
        return (f"{framework} {version} mapped to ATT&CK {meta.get('attack_version') or 'unknown'}, "
                f"updated {_iso(meta.get('last_update'))}")
    except Exception as exc:                 # unreadable: say so rather than fail the section
        logger.warning("Built-in data %s at %s could not be read: %s", key, path, exc)
        return "Present, but could not be read"


def status() -> List[dict]:
    """Each item: key, name, whether it is there, and its tip."""
    s = get_settings()
    out = []
    for key, name in ITEMS:
        path = _path(key)
        present = os.path.isdir(path) if key == "sigma" else os.path.isfile(path)
        if not present:
            tip = "Not found in this image"
        else:
            mtime = os.path.getmtime(path)
            fetched = datetime.fromtimestamp(mtime, tz=timezone.utc).date().isoformat()
            where = (f"Loaded from {path}, {fetched}" if key == "cisa_kev" and path == s.cisa_kev_override_path
                     else f"Bundled in the TIDE image, fetched {fetched}")
            tip = f"{_detail(key, path, mtime)}. {where}."
        out.append({"key": key, "name": name, "present": present, "tip": tip})
    return out
