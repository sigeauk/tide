"""Wazuh agents as a system's devices, with their vulnerabilities and alerts (Wazuh_integration.md phase 3).

A system says which of the client's Wazuh destinations supply its devices (**Wazuh agents…** on its page:
``system_wazuh_agents``, one row per destination, with an optional name pattern). At each sync, and when
that is saved, the destination's agents that match become the system's hosts (``source = 'wazuh'``; the
agent behind each is in ``host_agents``, so a renamed agent stays the same device).
Agents no longer matching are removed, their findings with them; manual and Nessus devices are never
touched. The manager's own agent (000) is nobody's device.

Each Wazuh host keeps its agent's facts (``host_agents``), Wazuh's own vulnerability findings
(``host_vulnerabilities``: what ``wazuh-states-vulnerabilities-*`` holds now; a finding gone from it after
a complete read is ``resolved_at``, the only record Wazuh gives that something was fixed) and its alerts
per day (``host_alert_counts``). A read that fails changes nothing.

A finding whose CVE is in CISA's KEV catalogue is *Known exploited*, and joins the CVE pages and the
device's CVE matches beside the matches made from its packages (``kev_matches_by_host``).

Each device's SCA results (its CIS benchmark policies and their checks) are kept too, and a baseline
technique can name hardening checks, shown beside its coverage (the SCA section below).
"""
from __future__ import annotations

import fnmatch
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

SOURCE = "wazuh"
DDL = (
    """CREATE TABLE IF NOT EXISTS system_wazuh_agents (
        system_id VARCHAR NOT NULL, siem_id VARCHAR NOT NULL, space VARCHAR NOT NULL,
        name_pattern VARCHAR, PRIMARY KEY (system_id, siem_id, space))""",
    """CREATE TABLE IF NOT EXISTS host_agents (
        host_id VARCHAR PRIMARY KEY, siem_id VARCHAR NOT NULL, space VARCHAR NOT NULL, agent_id VARCHAR NOT NULL,
        status VARCHAR, last_seen TIMESTAMP, version VARCHAR, groups VARCHAR[], synced_at TIMESTAMP)""",
    """CREATE TABLE IF NOT EXISTS host_vulnerabilities (
        host_id VARCHAR NOT NULL, cve_id VARCHAR NOT NULL, package VARCHAR NOT NULL, version VARCHAR,
        severity VARCHAR, cvss DOUBLE, cvss_version VARCHAR, detected_at TIMESTAMP, published_at TIMESTAMP,
        reference VARCHAR, description VARCHAR, condition VARCHAR, source VARCHAR,
        first_seen TIMESTAMP NOT NULL, last_seen TIMESTAMP NOT NULL, resolved_at TIMESTAMP,
        PRIMARY KEY (host_id, cve_id, package))""",
    """CREATE TABLE IF NOT EXISTS host_alert_counts (
        host_id VARCHAR NOT NULL, day DATE NOT NULL, alerts INTEGER NOT NULL, PRIMARY KEY (host_id, day))""",
    # Every agent of a destination as of its last complete read, a device of a system or not: Rule
    # Monitoring's Wazuh agents disconnected (phase 5, D13) looks at the whole group.
    """CREATE TABLE IF NOT EXISTS wazuh_agents (
        siem_id VARCHAR NOT NULL, space VARCHAR NOT NULL, agent_id VARCHAR NOT NULL, name VARCHAR, status VARCHAR,
        last_seen TIMESTAMP, synced_at TIMESTAMP, PRIMARY KEY (siem_id, space, agent_id))""",
    # How each destination's last read of agents, findings and SCA went: Wazuh read incomplete (D13).
    """CREATE TABLE IF NOT EXISTS wazuh_destination_reads (
        siem_id VARCHAR NOT NULL, space VARCHAR NOT NULL, read_at TIMESTAMP NOT NULL, agents INTEGER,
        error VARCHAR, PRIMARY KEY (siem_id, space))""",
)
SEVERITIES = ("Critical", "High", "Medium", "Low")
ALERT_DAYS = 90


def ensure(conn) -> None:
    for stmt in DDL:
        conn.execute(stmt)


def _tables(conn) -> Set[str]:
    return {r[0] for r in conn.execute("SELECT table_name FROM duckdb_tables()").fetchall()}


# ── A system's Wazuh agents setting ───────────────────────────────────────────

def system_sources(conn, system_id: str) -> Dict[Tuple[str, str], str]:
    """``{(siem_id, space): name pattern}`` of the destinations whose agents are this system's devices."""
    if "system_wazuh_agents" not in _tables(conn):
        return {}
    return {(r[0], r[1]): r[2] or "" for r in conn.execute(
        "SELECT siem_id, space, name_pattern FROM system_wazuh_agents WHERE system_id = ?", [system_id]).fetchall()}


def save_system_sources(conn, system_id: str, sources: Dict[Tuple[str, str], str]) -> Set[Tuple[str, str]]:
    """Replace the system's setting. Returns the destinations dropped, whose Wazuh devices go with them."""
    ensure(conn)
    before = set(system_sources(conn, system_id))
    conn.execute("DELETE FROM system_wazuh_agents WHERE system_id = ?", [system_id])
    for (siem_id, space), pattern in sources.items():
        conn.execute("INSERT INTO system_wazuh_agents VALUES (?, ?, ?, ?)",
                     [system_id, siem_id, space, (pattern or "").strip() or None])
    dropped = before - set(sources)
    for siem_id, space in dropped:
        _remove_hosts(conn, system_id, siem_id, space, keep_agent_ids=set())
    return dropped


def systems_for(conn, siem_id: str, space: str) -> List[Tuple[str, str]]:
    """``[(system_id, pattern)]`` of the systems that take this destination's agents."""
    if "system_wazuh_agents" not in _tables(conn):
        return []
    return [(r[0], r[1] or "") for r in conn.execute(
        "SELECT system_id, name_pattern FROM system_wazuh_agents WHERE siem_id = ? AND space = ?",
        [siem_id, space]).fetchall()]


def matches(agent: dict, pattern: str) -> bool:
    """Whether an agent's name fits ``pattern`` (a glob, case-insensitive; blank fits every agent)."""
    return not pattern or fnmatch.fnmatch(str(agent.get("name") or "").lower(), pattern.lower())


# ── Refreshing from Wazuh ─────────────────────────────────────────────────────

def _when(value) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _remove_hosts(conn, system_id: str, siem_id: str, space: str, keep_agent_ids: Set[str]) -> int:
    """Remove the system's Wazuh devices from this destination whose agents aren't in ``keep_agent_ids``."""
    gone = [r[0] for r in conn.execute(
        "SELECT h.id FROM hosts h JOIN host_agents a ON a.host_id = h.id WHERE h.system_id = ? AND a.siem_id = ? "
        "AND a.space = ? AND NOT list_contains(?::VARCHAR[], a.agent_id)",
        [system_id, siem_id, space, sorted(keep_agent_ids)]).fetchall()]
    for host_id in gone:
        for table in ("host_vulnerabilities", "host_alert_counts", "host_agents", "software_inventory",
                      "host_sca_policies", "host_sca_checks", "host_sca_history"):
            conn.execute(f"DELETE FROM {table} WHERE host_id = ?", [host_id])
        conn.execute("DELETE FROM hosts WHERE id = ?", [host_id])
    return len(gone)


def _store_agents(conn, siem_id: str, space: str, agents: List[dict], now: datetime) -> None:
    """The destination's agents as read now, in place of the last read's."""
    conn.execute("DELETE FROM wazuh_agents WHERE siem_id = ? AND space = ?", [siem_id, space])
    rows = [[siem_id, space, str(a["id"]), a.get("name") or str(a["id"]), a.get("status"),
             _when(a.get("lastKeepAlive")), now] for a in agents if a.get("id")]
    if rows:
        conn.executemany("INSERT INTO wazuh_agents VALUES (?, ?, ?, ?, ?, ?, ?)", rows)


def _record_read(conn, siem_id: str, space: str, now: datetime, agents: Optional[int], error: str) -> None:
    conn.execute("INSERT INTO wazuh_destination_reads VALUES (?, ?, ?, ?, ?) ON CONFLICT (siem_id, space) DO UPDATE SET "
                 "read_at = EXCLUDED.read_at, agents = EXCLUDED.agents, error = EXCLUDED.error",
                 [siem_id, space, now, agents, error or None])


def _upsert_host(conn, system_id: str, client_id: str, siem_id: str, space: str, agent: dict, now: datetime) -> str:
    agent_id = str(agent["id"])
    os_info = agent.get("os") or {}
    os_text = " ".join(p for p in (os_info.get("name"), os_info.get("version")) if p) or None
    row = conn.execute(
        "SELECT h.id FROM hosts h JOIN host_agents a ON a.host_id = h.id WHERE h.system_id = ? AND a.siem_id = ? "
        "AND a.space = ? AND a.agent_id = ?", [system_id, siem_id, space, agent_id]).fetchone()
    if row:
        host_id = row[0]
        conn.execute("UPDATE hosts SET name = ?, ip_address = ?, os = ? WHERE id = ?",
                     [agent.get("name") or agent_id, agent.get("ip"), os_text, host_id])
    else:
        host_id = conn.execute(
            "INSERT INTO hosts (system_id, name, ip_address, os, source, client_id) VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
            [system_id, agent.get("name") or agent_id, agent.get("ip"), os_text, SOURCE, client_id],
        ).fetchone()[0]
    conn.execute(
        "INSERT INTO host_agents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (host_id) DO UPDATE SET status = "
        "EXCLUDED.status, last_seen = EXCLUDED.last_seen, version = EXCLUDED.version, groups = EXCLUDED.groups, "
        "synced_at = EXCLUDED.synced_at",
        [host_id, siem_id, space, agent_id, agent.get("status"), _when(agent.get("lastKeepAlive")),
         agent.get("version"), list(agent.get("group") or []), now])
    return host_id


def _store_vulnerabilities(conn, host_id: str, docs: List[dict], now: datetime) -> None:
    """This host's findings as Wazuh has them now; the ones it no longer has are resolved."""
    present: Set[Tuple[str, str]] = set()
    for d in docs:
        v, pkg, scanner = d.get("vulnerability") or {}, d.get("package") or {}, d.get("scanner") or {}
        cve, package = str(v.get("id") or "").upper(), str(pkg.get("name") or "")
        if not cve or not package:
            continue
        present.add((cve, package))
        score = v.get("score") or {}
        conn.execute(
            "INSERT INTO host_vulnerabilities VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL) "
            "ON CONFLICT (host_id, cve_id, package) DO UPDATE SET version = EXCLUDED.version, severity = "
            "EXCLUDED.severity, cvss = EXCLUDED.cvss, cvss_version = EXCLUDED.cvss_version, detected_at = "
            "EXCLUDED.detected_at, published_at = EXCLUDED.published_at, reference = EXCLUDED.reference, "
            "description = EXCLUDED.description, condition = EXCLUDED.condition, source = EXCLUDED.source, "
            "last_seen = EXCLUDED.last_seen, resolved_at = NULL",
            [host_id, cve, package, pkg.get("version"), (v.get("severity") or "").title() or None,
             score.get("base"), score.get("version"), _when(v.get("detected_at")), _when(v.get("published_at")),
             str(v.get("reference") or "")[:2000] or None, str(v.get("description") or "")[:2000] or None,
             scanner.get("condition"), scanner.get("source"), now, now])
    conn.execute(
        "UPDATE host_vulnerabilities SET resolved_at = ? WHERE host_id = ? AND resolved_at IS NULL AND NOT EXISTS ("
        "SELECT 1 FROM (SELECT unnest(?::VARCHAR[]) AS c, unnest(?::VARCHAR[]) AS p) x "
        "WHERE x.c = host_vulnerabilities.cve_id AND x.p = host_vulnerabilities.package)",
        [now, host_id, [c for c, _p in present], [p for _c, p in present]])


def refresh_destination(db, client_id: str, siem_id: str, space: str, manager, indexer,
                        systems: Optional[Iterable[Tuple[str, str]]] = None) -> Dict[str, Any]:
    """Read one destination's agents (kept for Rule Monitoring whether or not a system takes them), and
    for each system that takes them (``systems``, or every one that does) make, update and remove its
    Wazuh devices, then read their vulnerabilities, alerts and SCA.
    ``{"hosts", "removed", "vulnerabilities", "sca_checks", "error"}``; on an error nothing was changed,
    except that a step after the agents (vulnerabilities, alerts, SCA) may have failed on its own, named in
    ``error``. How the read went is recorded for the destination (``destination_reads``), unless
    ``systems`` names the systems (a save of **Wazuh agents…**, not a sync).
    Uses the tenant's connection, so the caller has set its context."""
    from app.services import wazuh
    out: Dict[str, Any] = {"hosts": 0, "removed": 0, "vulnerabilities": 0, "sca_checks": 0, "error": ""}
    now = datetime.now()
    with db.get_connection() as conn:
        ensure(conn)
        takers = list(systems) if systems is not None else systems_for(conn, siem_id, space)
    try:
        agents = manager.agents(space)
    except wazuh.WazuhError as exc:
        out["error"] = f"Could not list the agents of {space}: {exc}"
        if systems is None:
            with db.get_connection() as conn:
                _record_read(conn, siem_id, space, now, None, out["error"])
        return out
    if systems is None:
        with db.get_connection() as conn:
            _store_agents(conn, siem_id, space, agents, now)
    out.update(_refresh_devices(db, client_id, siem_id, space, agents, takers, indexer, manager, now))
    if systems is None:
        with db.get_connection() as conn:
            _record_read(conn, siem_id, space, now, len(agents), out["error"])
    return out


def _refresh_devices(db, client_id: str, siem_id: str, space: str, agents: List[dict],
                     takers: List[Tuple[str, str]], indexer, manager, now: datetime) -> Dict[str, Any]:
    """The devices part of ``refresh_destination``: the systems' Wazuh devices from ``agents``, their
    findings, alerts and SCA."""
    from app.services import wazuh
    out: Dict[str, Any] = {"hosts": 0, "removed": 0, "vulnerabilities": 0, "sca_checks": 0, "error": ""}
    if not takers:
        return out
    host_agents: Dict[str, str] = {}            # host id -> agent id
    with db.get_connection() as conn:
        for system_id, pattern in takers:
            mine = [a for a in agents if matches(a, pattern)]
            for a in mine:
                host_agents[_upsert_host(conn, system_id, client_id, siem_id, space, a, now)] = str(a["id"])
            out["removed"] += _remove_hosts(conn, system_id, siem_id, space, {str(a["id"]) for a in mine})
    out["hosts"] = len(host_agents)
    agent_ids = sorted(set(host_agents.values()))
    try:
        docs = indexer.vulnerabilities(agent_ids)
    except wazuh.WazuhError as exc:
        out["error"] = f"Could not read the vulnerabilities of {space}: {exc}"
        docs = None
    if docs is not None:
        by_agent: Dict[str, List[dict]] = {}
        for d in docs:
            by_agent.setdefault(str((d.get("agent") or {}).get("id") or ""), []).append(d)
        with db.get_connection() as conn:
            for host_id, agent_id in host_agents.items():
                _store_vulnerabilities(conn, host_id, by_agent.get(agent_id, []), now)
        out["vulnerabilities"] = len(docs)
    try:
        counts = indexer.agent_alert_counts(agent_ids, ALERT_DAYS)
    except wazuh.WazuhError as exc:
        out["error"] = out["error"] or f"Could not count the alerts of {space}'s agents: {exc}"
        return out
    with db.get_connection() as conn:
        for host_id, agent_id in host_agents.items():
            conn.execute("DELETE FROM host_alert_counts WHERE host_id = ?", [host_id])
            rows = [[host_id, day, n] for (aid, day), n in counts.items() if aid == agent_id and day and n]
            if rows:
                conn.executemany("INSERT INTO host_alert_counts VALUES (?, ?, ?)", rows)
    out["sca_checks"], sca_error = refresh_sca(db, host_agents, manager, now)
    out["error"] = out["error"] or sca_error
    return out


def refresh_system(db, client_id: str, system_id: str) -> List[str]:
    """Read the system's Wazuh devices now, from each destination it takes them from (after **Wazuh
    agents…** is saved). Returns the problems met, one line each."""
    from app.services import wazuh
    problems = []
    with db.get_connection() as conn:
        sources = system_sources(conn, system_id)
    for (siem_id, space), pattern in sources.items():
        siem = db.get_siem_inventory_item(siem_id)
        if not siem or siem.get("siem_type") != SOURCE:
            continue
        s = wazuh.settings(siem)
        result = refresh_destination(db, client_id, siem_id, space, wazuh.Manager.from_settings(s),
                                     wazuh.Indexer.from_settings(s), [(system_id, pattern)])
        if result["error"]:
            problems.append(result["error"])
    return problems


# ── Reading, for the pages ────────────────────────────────────────────────────

def host_counts(conn, host_ids: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    """Each Wazuh host's agent status and current vulnerabilities by severity: ``{host_id: {status,
    last_seen, agent_id, by_severity: {Critical: n, …}, total, kev}}``. Hosts without an agent are absent."""
    host_ids = sorted(set(host_ids))
    if not host_ids or "host_agents" not in _tables(conn):
        return {}
    from app.inventory_engine import _load_cisa_kev
    kev = {k.get("cveID", "").upper() for k in (_load_cisa_kev() or [])}
    out: Dict[str, Dict[str, Any]] = {}
    for host_id, agent_id, status, last_seen in conn.execute(
            "SELECT host_id, agent_id, status, last_seen FROM host_agents WHERE list_contains(?::VARCHAR[], host_id)",
            [host_ids]).fetchall():
        out[host_id] = {"agent_id": agent_id, "status": status or "", "last_seen": last_seen,
                        "by_severity": {s: 0 for s in SEVERITIES}, "total": 0, "kev": 0}
    for host_id, severity, cve, n in conn.execute(
            "SELECT host_id, severity, cve_id, count(*) FROM host_vulnerabilities WHERE resolved_at IS NULL "
            "AND list_contains(?::VARCHAR[], host_id) GROUP BY 1, 2, 3", [host_ids]).fetchall():
        h = out.get(host_id)
        if h is None:
            continue
        h["by_severity"][severity if severity in SEVERITIES else "Low"] += n
        h["total"] += n
        h["kev"] += n if cve in kev else 0
    return out


def host_vulnerabilities(conn, host_id: str, with_resolved: bool = False) -> List[Dict[str, Any]]:
    """A Wazuh host's findings, Known exploited first, then by severity and CVSS."""
    if "host_vulnerabilities" not in _tables(conn):
        return []
    from app.inventory_engine import _load_cisa_kev
    kev = {k.get("cveID", "").upper() for k in (_load_cisa_kev() or [])}
    cols = ["cve_id", "package", "version", "severity", "cvss", "cvss_version", "detected_at", "published_at",
            "reference", "description", "condition", "source", "first_seen", "last_seen", "resolved_at"]
    rows = conn.execute(f"SELECT {', '.join(cols)} FROM host_vulnerabilities WHERE host_id = ?"
                        + ("" if with_resolved else " AND resolved_at IS NULL"), [host_id]).fetchall()
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    out = [dict(zip(cols, r), kev=r[0] in kev, references=[u for u in str(r[8] or "").split(",") if u.strip()])
           for r in rows]
    out.sort(key=lambda v: (v["resolved_at"] is not None, not v["kev"], rank.get(v["severity"], 9), -(v["cvss"] or 0), v["cve_id"]))
    return out


def host_alerts(conn, host_id: str, days: int = 30) -> Dict[str, Any]:
    """``{total, days}`` of a Wazuh host's alerts over the last ``days``, as of the last sync."""
    if "host_alert_counts" not in _tables(conn):
        return {"total": 0, "days": days}
    total = conn.execute("SELECT COALESCE(sum(alerts), 0) FROM host_alert_counts WHERE host_id = ? "
                         "AND day >= current_date - ?", [host_id, days]).fetchone()[0]
    return {"total": int(total), "days": days}


def kev_matches_by_host(conn) -> Dict[str, Dict[str, List[str]]]:
    """``{host_id: {cve_id: [packages]}}`` for every current finding whose CVE is in CISA's KEV catalogue:
    what the CVE pages add to the matches made from devices' packages."""
    if "host_vulnerabilities" not in _tables(conn):
        return {}
    from app.inventory_engine import _load_cisa_kev
    kev = {k.get("cveID", "").upper() for k in (_load_cisa_kev() or [])}
    if not kev:
        return {}
    out: Dict[str, Dict[str, List[str]]] = {}
    for host_id, cve, package in conn.execute(
            "SELECT host_id, cve_id, package FROM host_vulnerabilities WHERE resolved_at IS NULL").fetchall():
        if cve in kev:
            out.setdefault(host_id, {}).setdefault(cve, []).append(package)
    return out


# ── A destination's agents and reads, for Rule Monitoring (phase 5, D13) ─────

def destination_reads(conn) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """How each Wazuh destination's last read of agents, findings and SCA went: ``{(siem_id, space):
    {read_at, agents, error}}``; an ``error`` names the first step that failed."""
    if "wazuh_destination_reads" not in _tables(conn):
        return {}
    return {(r[0], r[1]): {"read_at": r[2], "agents": r[3], "error": r[4] or ""} for r in
            conn.execute("SELECT siem_id, space, read_at, agents, error FROM wazuh_destination_reads").fetchall()}


def disconnected_agents(conn, siem_id: str, space: str, hours: int,
                        now: Optional[datetime] = None) -> Dict[str, Any]:
    """The destination's agents not seen within ``hours`` (their last keep-alive, in UTC), as of the last
    complete read: ``{"total", "gone": [{agent_id, name, status, last_seen}]}``."""
    out: Dict[str, Any] = {"total": 0, "gone": []}
    if "wazuh_agents" not in _tables(conn):
        return out
    cutoff = (now or datetime.now(timezone.utc).replace(tzinfo=None)) - timedelta(hours=hours)
    for agent_id, name, status, last_seen in conn.execute(
            "SELECT agent_id, name, status, last_seen FROM wazuh_agents WHERE siem_id = ? AND space = ? "
            "ORDER BY last_seen NULLS FIRST, name", [siem_id, space]).fetchall():
        out["total"] += 1
        if last_seen is None or last_seen < cutoff:
            out["gone"].append({"agent_id": agent_id, "name": name, "status": status or "", "last_seen": last_seen})
    return out


# ── A system's Wazuh figures, for its cards and its report (phase 5, D14, D15) ─

def _system_wazuh_hosts(conn, system_id: str) -> List[str]:
    if "host_agents" not in _tables(conn):
        return []
    return [r[0] for r in conn.execute("SELECT h.id FROM hosts h JOIN host_agents a ON a.host_id = h.id "
                                       "WHERE h.system_id = ?", [system_id]).fetchall()]


def system_figures(conn, system_id: str) -> Optional[Dict[str, Any]]:
    """A system's Vulnerabilities and Hardening cards, over its Wazuh devices: ``{devices, vulnerabilities,
    by_severity, kev, affected, hardening (the average policy score, None without SCA), policies,
    hardened}``; None when the system has no Wazuh device."""
    hosts = _system_wazuh_hosts(conn, system_id)
    if not hosts:
        return None
    counts = host_counts(conn, hosts)
    out = {"devices": len(hosts), "vulnerabilities": sum(c["total"] for c in counts.values()),
           "by_severity": {s: sum(c["by_severity"][s] for c in counts.values()) for s in SEVERITIES},
           "kev": sum(c["kev"] for c in counts.values()), "affected": sum(1 for c in counts.values() if c["total"]),
           "hardening": None, "policies": 0, "hardened": 0}
    if "host_sca_policies" in _tables(conn):
        avg, hardened, policies = conn.execute(
            "SELECT avg(score), count(DISTINCT host_id), count(DISTINCT policy_id) FROM host_sca_policies "
            "WHERE list_contains(?::VARCHAR[], host_id)", [hosts]).fetchone()
        out.update(hardening=None if avg is None else int(round(avg)), hardened=hardened, policies=policies)
    return out


def system_figures_at(conn, system_id: str, at: datetime) -> Dict[str, Optional[int]]:
    """The two cards as they stood at ``at``, from TIDE's own records: the findings it held then that
    weren't yet resolved, and each policy's last score recorded by then. A card with no record by then is
    left out."""
    hosts = _system_wazuh_hosts(conn, system_id)
    out: Dict[str, Optional[int]] = {}
    if not hosts:
        return out
    first = conn.execute("SELECT min(first_seen) FROM host_vulnerabilities WHERE list_contains(?::VARCHAR[], host_id)",
                         [hosts]).fetchone()[0]
    if first is not None and first <= at:
        out["vulnerabilities"] = conn.execute(
            "SELECT count(*) FROM host_vulnerabilities WHERE list_contains(?::VARCHAR[], host_id) AND first_seen <= ? "
            "AND (resolved_at IS NULL OR resolved_at > ?)", [hosts, at, at]).fetchone()[0]
    if "host_sca_history" in _tables(conn):
        avg = conn.execute(
            "SELECT avg(score) FROM (SELECT arg_max(score, recorded_at) AS score FROM host_sca_history "
            "WHERE list_contains(?::VARCHAR[], host_id) AND recorded_at <= ? GROUP BY host_id, policy_id)",
            [hosts, at]).fetchone()[0]
        if avg is not None:
            out["hardening"] = int(round(avg))
    return out


def system_vulnerability_report(conn, system_id: str, shown: int = 10) -> Optional[Dict[str, Any]]:
    """The report's Vulnerabilities section: the system's Wazuh devices with their agent status and findings
    by severity, and the CVEs on most devices (``top``: cve_id, severity, cvss, devices, kev, packages).
    None when the system has no Wazuh device."""
    hosts = _system_wazuh_hosts(conn, system_id)
    if not hosts:
        return None
    figures = system_figures(conn, system_id) or {}
    counts = host_counts(conn, hosts)
    from app.inventory_engine import _load_cisa_kev
    kev = {k.get("cveID", "").upper() for k in (_load_cisa_kev() or [])}
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    devices = []
    for host_id, name, ip, os_text in conn.execute(
            "SELECT id, name, ip_address, os FROM hosts WHERE list_contains(?::VARCHAR[], id) ORDER BY name", [hosts]).fetchall():
        c = counts.get(host_id) or {}
        devices.append({"name": name, "ip": ip or "", "os": os_text or "", "status": c.get("status") or "",
                        "last_seen": c.get("last_seen"), "total": c.get("total", 0), "kev": c.get("kev", 0),
                        "by_severity": c.get("by_severity") or {s: 0 for s in SEVERITIES}})
    top = []
    for cve, severity, cvss, n, packages in conn.execute(
            "SELECT cve_id, arg_max(severity, COALESCE(cvss, 0)), max(cvss), count(DISTINCT host_id), "
            "list_sort(list_distinct(list(package))) FROM host_vulnerabilities WHERE resolved_at IS NULL "
            "AND list_contains(?::VARCHAR[], host_id) GROUP BY cve_id", [hosts]).fetchall():
        top.append({"cve_id": cve, "severity": severity or "", "cvss": cvss, "devices": n, "kev": cve in kev,
                    "packages": list(packages or [])})
    top.sort(key=lambda v: (not v["kev"], -v["devices"], rank.get(v["severity"], 9), -(v["cvss"] or 0), v["cve_id"]))
    return {**figures, "devices_list": devices, "top": top[:shown], "distinct": len(top)}


# ── SCA / CIS: hardening (phase 4) ────────────────────────────────────────────
# A device's SCA policies (score, passed / failed / not applicable) and their checks, as Wazuh last ran
# them. The checks are read again only when a policy's end_scan changed: one API call per device per
# policy otherwise. A baseline technique can name hardening checks (``step_hardening``, D6): shown
# beside its coverage as mitigation, with how many of the system's devices pass, never counted as coverage.

SCA_DDL = (
    """CREATE TABLE IF NOT EXISTS host_sca_policies (
        host_id VARCHAR NOT NULL, policy_id VARCHAR NOT NULL, name VARCHAR, passed INTEGER, failed INTEGER,
        not_applicable INTEGER, total INTEGER, score INTEGER, end_scan TIMESTAMP, synced_at TIMESTAMP,
        PRIMARY KEY (host_id, policy_id))""",
    """CREATE TABLE IF NOT EXISTS host_sca_checks (
        host_id VARCHAR NOT NULL, policy_id VARCHAR NOT NULL, check_id VARCHAR NOT NULL, title VARCHAR,
        result VARCHAR, cis_ids VARCHAR[], technique_ids VARCHAR[], rationale VARCHAR, remediation VARCHAR,
        PRIMARY KEY (host_id, policy_id, check_id))""",
    """CREATE TABLE IF NOT EXISTS step_hardening (
        id VARCHAR PRIMARY KEY DEFAULT (uuid()), step_id VARCHAR NOT NULL, system_id VARCHAR NOT NULL,
        policy_id VARCHAR NOT NULL, check_id VARCHAR NOT NULL, title VARCHAR, cis_ids VARCHAR[], note VARCHAR,
        created_at TIMESTAMP DEFAULT now(), created_by VARCHAR)""",
    # Each policy's score as TIDE recorded it after each new scan: the Dashboard's Hardening card compares
    # with an earlier day from this (phase 5, D15).
    """CREATE TABLE IF NOT EXISTS host_sca_history (
        host_id VARCHAR NOT NULL, policy_id VARCHAR NOT NULL, recorded_at TIMESTAMP NOT NULL, end_scan TIMESTAMP,
        score INTEGER, PRIMARY KEY (host_id, policy_id, recorded_at))""",
)
DDL = DDL + SCA_DDL
RESULTS = ("passed", "failed", "not applicable")


def _ids(value) -> List[str]:
    return [x.strip() for x in str(value or "").split(",") if x.strip()]


def _compliance(check: dict, key: str) -> List[str]:
    out: List[str] = []
    for item in check.get("compliance") or []:
        if item.get("key") == key:
            out += _ids(item.get("value"))
    return out


def _store_sca(conn, host_id: str, manager, agent_id: str, now: datetime) -> Tuple[int, int]:
    """One device's SCA: every policy's summary, and the checks of the policies whose scan is new.
    ``(policies, checks read)``; raises WazuhError when the manager won't answer."""
    policies = manager.sca(agent_id)
    known = {r[0]: r[1] for r in conn.execute(
        "SELECT policy_id, end_scan FROM host_sca_policies WHERE host_id = ?", [host_id]).fetchall()}
    seen, checks_read = set(), 0
    for p in policies:
        pid = str(p.get("policy_id") or "")
        if not pid:
            continue
        seen.add(pid)
        end_scan = _when(p.get("end_scan"))
        conn.execute(
            "INSERT INTO host_sca_policies VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (host_id, policy_id) DO UPDATE SET "
            "name = EXCLUDED.name, passed = EXCLUDED.passed, failed = EXCLUDED.failed, not_applicable = "
            "EXCLUDED.not_applicable, total = EXCLUDED.total, score = EXCLUDED.score, end_scan = EXCLUDED.end_scan, "
            "synced_at = EXCLUDED.synced_at",
            [host_id, pid, p.get("name"), p.get("pass"), p.get("fail"), p.get("invalid"), p.get("total_checks"),
             p.get("score"), end_scan, now])
        have = conn.execute("SELECT count(*) FROM host_sca_checks WHERE host_id = ? AND policy_id = ?",
                            [host_id, pid]).fetchone()[0]
        recorded = conn.execute("SELECT count(*) FROM host_sca_history WHERE host_id = ? AND policy_id = ?",
                                [host_id, pid]).fetchone()[0]
        if pid not in known or known[pid] != end_scan or not recorded:
            conn.execute("INSERT INTO host_sca_history VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
                         [host_id, pid, now, end_scan, p.get("score")])
        if pid in known and known[pid] == end_scan and have:
            continue                                # the same scan as last time: its checks stand
        checks = manager.sca_checks(agent_id, pid)
        conn.execute("DELETE FROM host_sca_checks WHERE host_id = ? AND policy_id = ?", [host_id, pid])
        conn.executemany(
            "INSERT INTO host_sca_checks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [[host_id, pid, str(c.get("id")), c.get("title"), str(c.get("result") or "").lower(),
              _compliance(c, "cis"), [t.upper() for t in _compliance(c, "mitre_techniques")],
              str(c.get("rationale") or "")[:2000] or None, str(c.get("remediation") or "")[:4000] or None]
             for c in checks if c.get("id") is not None])
        checks_read += len(checks)
    for pid in set(known) - seen:              # a policy the agent no longer runs
        for table in ("host_sca_checks", "host_sca_policies", "host_sca_history"):
            conn.execute(f"DELETE FROM {table} WHERE host_id = ? AND policy_id = ?", [host_id, pid])
    return len(seen), checks_read


def refresh_sca(db, host_agents: Dict[str, str], manager, now: datetime) -> Tuple[int, str]:
    """SCA for each ``{host_id: agent_id}``: ``(checks read, error)``. A device whose read fails keeps what
    it had; the first problem is returned."""
    from app.services import wazuh
    read, error = 0, ""
    for host_id, agent_id in host_agents.items():
        try:
            with db.get_connection() as conn:
                _p, n = _store_sca(conn, host_id, manager, agent_id, now)
                read += n
        except wazuh.WazuhError as exc:
            error = error or f"Could not read the SCA results of agent {agent_id}: {exc}"
    return read, error


def host_hardening(conn, host_id: str) -> List[Dict[str, Any]]:
    """A device's policies, each with its failing checks (CIS ids, title, remediation), best score first."""
    if "host_sca_policies" not in _tables(conn):
        return []
    cols = ["policy_id", "name", "passed", "failed", "not_applicable", "total", "score", "end_scan"]
    out = []
    for r in conn.execute(f"SELECT {', '.join(cols)} FROM host_sca_policies WHERE host_id = ? ORDER BY score DESC, name",
                          [host_id]).fetchall():
        p = dict(zip(cols, r))
        p["failing"] = [dict(zip(("check_id", "title", "cis_ids", "technique_ids", "remediation", "rationale"), c))
                        for c in conn.execute(
                            "SELECT check_id, title, cis_ids, technique_ids, remediation, rationale FROM host_sca_checks "
                            "WHERE host_id = ? AND policy_id = ? AND result = 'failed' ORDER BY list_sort(cis_ids), title",
                            [host_id, r[0]]).fetchall()]
        out.append(p)
    return out


def system_hardening(conn, system_id: str, shown: int = 10) -> List[Dict[str, Any]]:
    """A system's hardening by policy, over its Wazuh devices: how many run it, the average score, the
    device with the lowest score, and the checks most devices fail (``failing``: check_id, title, cis_ids,
    devices failing, devices with the policy)."""
    if "host_sca_policies" not in _tables(conn):
        return []
    out = []
    for policy_id, name, devices, avg, worst_score, worst in conn.execute(
            "SELECT p.policy_id, max(p.name), count(*), round(avg(p.score)), min(p.score), "
            "arg_min(h.name, p.score) FROM host_sca_policies p JOIN hosts h ON h.id = p.host_id "
            "WHERE h.system_id = ? GROUP BY p.policy_id ORDER BY 2", [system_id]).fetchall():
        failing = [{"check_id": c[0], "title": c[1], "cis_ids": list(c[2] or []), "failing": c[3], "devices": devices}
                   for c in conn.execute(
                       "SELECT c.check_id, max(c.title), max(c.cis_ids), count(*) FROM host_sca_checks c "
                       "JOIN hosts h ON h.id = c.host_id WHERE h.system_id = ? AND c.policy_id = ? AND c.result = 'failed' "
                       "GROUP BY c.check_id ORDER BY count(*) DESC, list_sort(max(c.cis_ids)) LIMIT ?",
                       [system_id, policy_id, shown]).fetchall()]
        total_failing = conn.execute(
            "SELECT count(DISTINCT c.check_id) FROM host_sca_checks c JOIN hosts h ON h.id = c.host_id "
            "WHERE h.system_id = ? AND c.policy_id = ? AND c.result = 'failed'", [system_id, policy_id]).fetchone()[0]
        out.append({"policy_id": policy_id, "name": name, "devices": devices, "avg_score": int(avg or 0),
                    "worst_score": worst_score, "worst": worst, "failing": failing, "total_failing": total_failing})
    return out


# ── A baseline technique's hardening checks (D6) ─────────────────────────────

def _check_states(conn, system_id: str, keys: Iterable[Tuple[str, str]]) -> Dict[Tuple[str, str], Dict[str, int]]:
    """``{(policy_id, check_id): {passed, failed, not_applicable, devices}}`` over the system's devices."""
    keys = sorted(set(keys))
    out = {k: {"passed": 0, "failed": 0, "not_applicable": 0, "devices": 0} for k in keys}
    if not keys or "host_sca_checks" not in _tables(conn):
        return out
    for pid, chk, result, n in conn.execute(
            "SELECT c.policy_id, c.check_id, c.result, count(*) FROM host_sca_checks c JOIN hosts h ON h.id = c.host_id "
            "WHERE h.system_id = ? AND EXISTS (SELECT 1 FROM (SELECT unnest(?::VARCHAR[]) AS p, unnest(?::VARCHAR[]) AS k) x "
            "WHERE x.p = c.policy_id AND x.k = c.check_id) GROUP BY 1, 2, 3",
            [system_id, [k[0] for k in keys], [k[1] for k in keys]]).fetchall():
        st = out[(pid, chk)]
        st[result.replace(" ", "_") if result in RESULTS else "not_applicable"] += n
        st["devices"] += n
    return out


def step_hardening(conn, step_ids: Iterable[str], system_id: str) -> Dict[str, List[Dict[str, Any]]]:
    """``{step_id: [checks]}``: each technique's hardening checks on this system, with how the system's
    devices stand on each (``passed`` of ``devices``)."""
    step_ids = sorted(set(step_ids))
    if not step_ids or "step_hardening" not in _tables(conn):
        return {}
    rows = conn.execute(
        "SELECT id, step_id, policy_id, check_id, title, cis_ids, note, created_at, created_by FROM step_hardening "
        "WHERE system_id = ? AND list_contains(?::VARCHAR[], step_id) ORDER BY created_at", [system_id, step_ids]).fetchall()
    states = _check_states(conn, system_id, [(r[2], r[3]) for r in rows])
    out: Dict[str, List[Dict[str, Any]]] = {}
    for rid, step_id, pid, chk, title, cis, note, created_at, created_by in rows:
        out.setdefault(step_id, []).append({"id": rid, "policy_id": pid, "check_id": chk, "title": title or chk,
                                            "cis_ids": list(cis or []), "note": note or "", "created_at": created_at,
                                            "created_by": created_by, **states[(pid, chk)]})
    return out


def _cis_key(item: Dict[str, Any]):
    first = (item["cis_ids"] or ["~"])[0]
    return ([int(x) if x.isdigit() else x for x in first.split(".")], item["title"])


def offered_checks(conn, system_id: str, technique_ids: Iterable[str], q: str = "", limit: int = 50) -> Dict[str, list]:
    """The checks a technique can name: ``suggested``, those on the system's devices whose Wazuh
    ``mitre_techniques`` include one of its ATT&CK ids; ``others``, the rest matching ``q`` (a CIS id or words
    of the title). Each with its policy, CIS ids and how the devices stand."""
    if "host_sca_checks" not in _tables(conn):
        return {"suggested": [], "others": []}
    ids = sorted({str(t).upper() for t in technique_ids if t})
    rows = conn.execute(
        "SELECT c.policy_id, c.check_id, max(c.title), max(c.cis_ids), max(p.name), "
        "bool_or(list_has_any(c.technique_ids, ?::VARCHAR[])) FROM host_sca_checks c JOIN hosts h ON h.id = c.host_id "
        "JOIN host_sca_policies p ON p.host_id = c.host_id AND p.policy_id = c.policy_id "
        "WHERE h.system_id = ? GROUP BY 1, 2", [ids, system_id]).fetchall()
    words = q.strip().lower()
    suggested, others = [], []
    for pid, chk, title, cis, policy, hit in rows:
        item = {"policy_id": pid, "check_id": chk, "title": title or chk, "cis_ids": list(cis or []), "policy": policy or pid}
        text = f"{title or ''} {' '.join(cis or [])} {chk}".lower()
        if hit and (not words or words in text):
            suggested.append(item)
        elif words and words in text:
            others.append(item)
    suggested.sort(key=_cis_key)
    others.sort(key=_cis_key)
    shown = suggested[:limit] + others[:limit]
    states = _check_states(conn, system_id, [(i["policy_id"], i["check_id"]) for i in shown])
    for i in shown:
        i.update(states[(i["policy_id"], i["check_id"])])
    return {"suggested": suggested[:limit], "others": others[:limit]}


def add_step_hardening(conn, step_id: str, system_id: str, policy_id: str, check_id: str, note: str = "",
                       actor: str = None) -> Optional[Dict[str, Any]]:
    """Name one of the system's devices' checks on a technique. None when the check isn't on any of its
    devices, or is already named; else the row (with the check's title and CIS ids as they are now)."""
    ensure(conn)
    row = conn.execute(
        "SELECT max(c.title), max(c.cis_ids) FROM host_sca_checks c JOIN hosts h ON h.id = c.host_id "
        "WHERE h.system_id = ? AND c.policy_id = ? AND c.check_id = ?", [system_id, policy_id, check_id]).fetchone()
    if not row or row[0] is None:
        return None
    if conn.execute("SELECT 1 FROM step_hardening WHERE step_id = ? AND system_id = ? AND policy_id = ? AND check_id = ?",
                    [step_id, system_id, policy_id, check_id]).fetchone():
        return None
    rid = conn.execute(
        "INSERT INTO step_hardening (step_id, system_id, policy_id, check_id, title, cis_ids, note, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
        [step_id, system_id, policy_id, check_id, row[0], list(row[1] or []), (note or "").strip() or None, actor]).fetchone()[0]
    return {"id": rid, "title": row[0], "cis_ids": list(row[1] or [])}


def remove_step_hardening(conn, hardening_id: str, step_id: str, system_id: str) -> Optional[Dict[str, Any]]:
    """Remove one named check; the row as it was, or None when it isn't on this technique on this system."""
    if "step_hardening" not in _tables(conn):
        return None
    row = conn.execute("SELECT policy_id, check_id, title, cis_ids FROM step_hardening WHERE id = ? AND step_id = ? "
                       "AND system_id = ?", [hardening_id, step_id, system_id]).fetchone()
    if not row:
        return None
    conn.execute("DELETE FROM step_hardening WHERE id = ?", [hardening_id])
    return {"policy_id": row[0], "check_id": row[1], "title": row[2], "cis_ids": list(row[3] or [])}
