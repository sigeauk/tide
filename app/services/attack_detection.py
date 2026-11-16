"""How MITRE ATT&CK says to detect a technique, and the log sources a system's baseline techniques need.

The data is ATT&CK's own, bundled in reference.duckdb (cti_helper.DETECTION_KEYS): each technique has a
detection strategy, made of analytics, one per platform, each naming the log sources it reads (with the
channel: an event code, or what to look for) and what to tune. The MITRE technique window shows a
technique's strategy; the baseline technique window and a system's Log sources section narrow it to the
system's platforms.

A system's platforms are those its devices' operating systems show, and any a person adds in Edit system
(``systems.platforms``): no device shows a SaaS, a cloud or an identity provider. TIDE only suggests here;
nothing is a coverage decision, and nothing says whether the logs are collected (that needs the SIEM).
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from typing import Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

# ATT&CK's platforms a system can have, in the order TIDE lists them. ATT&CK's PRE (reconnaissance seen
# from outside) and ICS's "None" aren't a system's.
PLATFORMS = ("Windows", "Linux", "macOS", "ESXi", "Network Devices", "Containers", "IaaS", "SaaS",
             "Office Suite", "Identity Provider", "Embedded", "Android", "iOS")
_DOMAINS = ("enterprise", "ics", "mobile")

# A device's operating system, as typed, read from Wazuh or named by an OS CPE, to an ATT&CK platform.
# First match wins: Cisco IOS is a network device, not Apple's iOS (which is matched by its own casing).
_OS_PLATFORMS = (
    ("Network Devices", re.compile(r"cisco|\bios[ -]?x[er]\b|\bnx-?os\b|junos|fortios|fortigate|pan-?os|"
                                   r"palo ?alto|arista|routeros|mikrotik|sonicos|aruba ?os|vyos|edgeos", re.I)),
    ("ESXi", re.compile(r"\besxi?\b", re.I)),
    ("Windows", re.compile(r"\bwin(dows)?\b|\bwin ?(xp|vista|7|8|10|11|20\d\d)\b", re.I)),
    ("macOS", re.compile(r"\bmac ?os\b|\bos ?x\b|darwin|macintosh", re.I)),
    ("iOS", re.compile(r"\biOS\b|iphone|ipad")),
    ("Android", re.compile(r"android", re.I)),
    ("Linux", re.compile(r"linux|ubuntu|debian|cent ?os|red ?hat|\brhel\b|fedora|suse|\bsles\b|almalinux|"
                         r"rocky|oracle ?linux|amazon ?linux|kali|alpine|raspbian|photon ?os", re.I)),
)


def device_platform(os_text: Optional[str]) -> str:
    """The ATT&CK platform an operating system's name shows, '' when TIDE can't tell."""
    text = (os_text or "").replace("_", " ")
    for platform, pattern in _OS_PLATFORMS:
        if pattern.search(text):
            return platform
    return ""


def _cpe_os(cpe: str) -> str:
    """The vendor and product of an operating-system CPE (cpe:2.3:o:vendor:product:…), '' otherwise."""
    parts = (cpe or "").split(":")
    return f"{parts[3]} {parts[4]}" if len(parts) > 4 and parts[2] == "o" else ""


def _platform_list(text: Optional[str]) -> List[str]:
    return [p.strip() for p in (text or "").split(",") if p.strip()]


# ── Strategies ────────────────────────────────────────────────────────────────

def strategies(conn, technique_ids: Iterable[str], domain: str = "") -> Dict[str, List[dict]]:
    """Each technique's detection strategies (ATT&CK gives one), keyed by the id asked for:
    ``{id, name, analytics: [{platforms, description, log_sources: [{name, channel, component}],
    tuning: [{field, description}]}]}``. ``domain`` narrows to one ATT&CK domain; without it a
    technique's first domain (enterprise, ICS, mobile) is used. An id ATT&CK renumbered gets the
    strategy of the technique it became."""
    wanted = [t for t in dict.fromkeys((t or "").strip().upper() for t in technique_ids) if t]
    if not wanted:
        return {}
    try:
        return _strategies(conn, wanted, domain)
    except Exception:
        logger.warning("ATT&CK detection strategies could not be read", exc_info=True)
        return {}


def _strategies(conn, wanted: List[str], domain: str) -> Dict[str, List[dict]]:
    holes = ", ".join("?" for _ in wanted)
    renamed = dict(conn.execute(
        f"SELECT old_id, MIN(new_id) FROM mitre_technique_revisions WHERE old_id IN ({holes}) GROUP BY old_id",
        wanted).fetchall())
    asked = {tid: renamed.get(tid, tid) for tid in wanted}
    ids = sorted(set(asked.values()))
    rows = conn.execute(
        f"SELECT st.technique_id, s.strategy_id, s.name, s.domain FROM mitre_strategy_techniques st "
        f"JOIN mitre_detection_strategies s ON s.strategy_id = st.strategy_id AND s.domain = st.domain "
        f"WHERE st.technique_id IN ({', '.join('?' for _ in ids)})" + (" AND st.domain = ?" if domain else "")
        + " ORDER BY s.strategy_id", ids + ([domain] if domain else [])).fetchall()
    first_domain: Dict[str, str] = {}
    for tid, _sid, _name, dom in sorted(rows, key=lambda r: _DOMAINS.index(r[3]) if r[3] in _DOMAINS else 9):
        first_domain.setdefault(tid, dom)
    found: Dict[str, List[dict]] = {}
    for tid, sid, name, dom in rows:
        if dom == first_domain[tid]:
            found.setdefault(tid, []).append({"id": sid, "name": name, "domain": dom, "analytics": []})
    keys = {(s["id"], s["domain"]): s for group in found.values() for s in group}
    if keys:
        _add_analytics(conn, keys)
    return {tid: found[real] for tid, real in asked.items() if real in found}


def _add_analytics(conn, strategies_by_key: Dict[tuple, dict]) -> None:
    pairs = list(strategies_by_key)
    where = " OR ".join("(a.strategy_id = ? AND a.domain = ?)" for _ in pairs)
    params = [v for pair in pairs for v in pair]
    analytics = conn.execute(
        f"SELECT a.strategy_id, a.domain, a.analytic_id, a.platforms, a.description FROM mitre_analytics a "
        f"WHERE {where} ORDER BY a.strategy_id, a.position", params).fetchall()
    by_id: Dict[tuple, dict] = {}
    for sid, dom, aid, platforms, description in analytics:
        a = {"platforms": _platform_list(platforms), "description": description or "", "log_sources": [],
             "tuning": []}
        strategies_by_key[(sid, dom)]["analytics"].append(a)
        by_id.setdefault((aid, dom), a)
    if not by_id:
        return
    where = " OR ".join("(x.analytic_id = ? AND x.domain = ?)" for _ in by_id)
    params = [v for pair in by_id for v in pair]
    for aid, dom, name, channel, component in conn.execute(
            f"SELECT x.analytic_id, x.domain, x.log_source, x.channel, c.name FROM mitre_analytic_log_sources x "
            f"LEFT JOIN mitre_data_components c ON c.component_id = x.component_id AND c.domain = x.domain "
            f"WHERE {where} ORDER BY x.analytic_id, x.position", params).fetchall():
        by_id[(aid, dom)]["log_sources"].append({"name": name, "channel": channel or "", "component": component or ""})
    for aid, dom, field, description in conn.execute(
            f"SELECT x.analytic_id, x.domain, x.field, x.description FROM mitre_analytic_tuning x "
            f"WHERE {where} ORDER BY x.analytic_id, x.position", params).fetchall():
        by_id[(aid, dom)]["tuning"].append({"field": field, "description": description or ""})


def for_platforms(found: Dict[str, List[dict]], platforms: List[str]) -> List[dict]:
    """The strategies of ``found`` (strategies()), in technique order, each with its analytics split into
    those for the system's ``platforms`` (``analytics``) and the rest (``other``). With no platforms
    known, every analytic is the system's."""
    out = []
    mine = set(platforms)
    for tid, group in found.items():
        for s in group:
            on, other = [], []
            for a in s["analytics"]:
                (on if not mine or mine & set(a["platforms"]) else other).append(a)
            out.append({**s, "technique_id": tid, "analytics": on, "other": other})
    return out


# ── A system's platforms and log sources ─────────────────────────────────────

def system_platforms(conn, system_id: str) -> Dict[str, object]:
    """The system's platforms: ``platforms`` [{name, devices, device_names, added}] in PLATFORMS order,
    ``names`` the same as a list, ``from_devices`` those its devices show, and ``unplaced`` the names of
    devices whose operating system TIDE can't place."""
    added = conn.execute("SELECT platforms FROM systems WHERE id = ?", [system_id]).fetchone()
    added = [p for p in (added[0] if added and added[0] else []) if p in PLATFORMS]
    hosts = conn.execute("SELECT id, name, os FROM hosts WHERE system_id = ? ORDER BY name", [system_id]).fetchall()
    os_cpes: Dict[str, List[str]] = {}
    if hosts:
        for host_id, cpe in conn.execute(
                "SELECT host_id, cpe FROM software_inventory WHERE system_id = ? AND cpe LIKE 'cpe:2.3:o:%' "
                "AND host_id IS NOT NULL", [system_id]).fetchall():
            os_cpes.setdefault(host_id, []).append(_cpe_os(cpe))
    devices: Dict[str, List[str]] = {}
    unplaced = []
    for host_id, name, os_text in hosts:
        platform = device_platform(os_text) or next(
            (p for p in map(device_platform, os_cpes.get(host_id, [])) if p), "")
        if platform:
            devices.setdefault(platform, []).append(name)
        else:
            unplaced.append(name)
    platforms = [{"name": p, "devices": len(devices.get(p, [])), "device_names": devices.get(p, []),
                  "added": p in added} for p in PLATFORMS if p in devices or p in added]
    return {"platforms": platforms, "names": [p["name"] for p in platforms],
            "from_devices": [p for p in PLATFORMS if p in devices], "unplaced": unplaced}


_EVENT_CODES = re.compile(r"^\s*EventCode\s*=\s*([\d,\s]+)$", re.I)


def _channels(channels: Counter) -> List[str]:
    """A log source's channels, most used first, Windows event codes merged into one line."""
    codes, others = set(), Counter()
    for channel, n in channels.items():
        m = _EVENT_CODES.match(channel)
        if m:
            codes.update(int(c) for c in re.findall(r"\d+", m.group(1)))
        elif channel:
            others[channel] += n
    out = [f"EventCode={', '.join(str(c) for c in sorted(codes))}"] if codes else []
    return out + [c for c, _n in others.most_common()]


def system_log_sources(conn, system_id: str, steps: List[dict]) -> Dict[str, object]:
    """The log sources ATT&CK's analytics read for the system's baseline techniques (``steps``, rows of
    inventory_engine.get_system_steps), on its platforms: ``sources`` [{name, platforms, channels,
    steps: [{step_id, title}]}], most techniques first, and the counts behind them: ``considered``
    (techniques marked N/A are left out), ``with_analytics``, ``without_analytics`` (ATT&CK ids but
    no analytic on these platforms) and ``no_ids`` (no ATT&CK technique at all)."""
    platforms = system_platforms(conn, system_id)
    mine = set(platforms["names"])
    considered = [s for s in steps if s.get("status") != "grey"]
    found = strategies(conn, [t for s in considered for t in s.get("display_technique_ids") or []]) if mine else {}
    sources: Dict[str, dict] = {}
    with_analytics = 0
    for step in considered:
        hit = False
        for tid in step.get("display_technique_ids") or []:
            for strategy in found.get(tid.upper(), []):
                for a in strategy["analytics"]:
                    on = mine & set(a["platforms"])
                    if not on:
                        continue
                    hit = True
                    for ls in a["log_sources"]:
                        row = sources.setdefault(ls["name"], {"name": ls["name"], "platforms": set(),
                                                              "channels": Counter(), "steps": {}})
                        row["platforms"] |= on
                        row["channels"][ls["channel"]] += 1
                        row["steps"].setdefault(step["step_id"], step.get("title") or "")
        with_analytics += hit
    rows = [{"name": r["name"], "platforms": [p for p in PLATFORMS if p in r["platforms"]],
             "channels": _channels(r["channels"]),
             "steps": [{"step_id": k, "title": v} for k, v in sorted(r["steps"].items(), key=lambda kv: kv[1].lower())]}
            for r in sources.values()]
    rows.sort(key=lambda r: (-len(r["steps"]), r["name"].lower()))
    no_ids = sum(1 for s in considered if not s.get("display_technique_ids"))
    return {**platforms, "sources": rows, "considered": len(considered), "with_analytics": with_analytics,
            "no_ids": no_ids, "without_analytics": len(considered) - with_analytics - no_ids if mine else 0}
