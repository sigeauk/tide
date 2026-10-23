"""Diagnostics: the snapshot and read-only checks behind the superadmin Diagnostics page.

A check is reviewed code, not typed SQL: it reads through the app's own connection (the app
holds DuckDB's single writer, so nothing else can open the file) inside a transaction that is
always rolled back, so a check can never change data. Each says what it found in plain words,
what it means and what to do. Columns whose names look like secrets are never shown.

Install checks read the shared database; client checks read one client's database.
"""
from __future__ import annotations

import json
import logging
import os
import re
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple

from app.services.rule_issues import STALE_DAYS

logger = logging.getLogger(__name__)

SAMPLE_ROWS = 25
_SECRET_COLUMN = re.compile(r"token|secret|password|passwd|api_key|apikey|_enc$|credential", re.I)


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    scope: str               # "install" | "client"
    severity: str            # how serious a finding is: "error" | "warning" | "info"
    meaning: str             # what a finding means, in plain words
    advice: str              # what to do about it
    run: Callable[..., Tuple[List[str], List[tuple]]]   # (conn, ctx) -> (columns, rows)
    listing: bool = False    # rows are information to read, not problems to fix
    on_demand: bool = False  # slow (copies files): its own Run only, not Run all checks


def _tables(conn) -> set:
    return {r[0] for r in conn.execute("SHOW TABLES").fetchall()}


def _query(sql: str, needs: Tuple[str, ...] = ()) -> Callable:
    """A check that is one SELECT. ``needs`` names the tables it reads: without them there is
    nothing to check, which is not a finding."""
    def run(conn, ctx):
        if needs and not set(needs) <= _tables(conn):
            return [], []
        cur = conn.execute(sql)
        return [d[0] for d in cur.description], cur.fetchall()
    return run


# ── install checks (shared database) ─────────────────────────────────────

def _schema_behind(conn, ctx):
    from app.services.database import SCHEMA_VERSION
    db_version = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] or 0
    rows = [(db_version, SCHEMA_VERSION)] if db_version < SCHEMA_VERSION else []
    return ["database schema", "this release expects"], rows


def _missing_tenant_db(conn, ctx):
    if "clients" not in _tables(conn):
        return [], []
    rows = [
        (name, fname) for name, fname in conn.execute(
            "SELECT name, db_filename FROM clients WHERE db_filename IS NOT NULL ORDER BY name").fetchall()
        if not os.path.exists(os.path.join(ctx["data_dir"], fname))
    ]
    return ["client", "database file"], rows


# ── client checks (one client's database) ────────────────────────────────

def _scoped(sql_template: str, needs: Tuple[str, ...]) -> Callable:
    """A client check about the client's linked destinations: ``{scopes}`` becomes a VALUES list
    of its (siem_id, space, name) pairs, so results name the destination as the client does."""
    def run(conn, ctx):
        scopes = ctx["scopes"]
        if not scopes or not set(needs) <= _tables(conn):
            return [], []
        values = ", ".join("(?, ?, ?)" for _ in scopes)
        params = [v for s in scopes for v in s]
        cur = conn.execute(sql_template.format(scopes=f"(VALUES {values}) AS d(siem_id, space, destination)"), params)
        return [d[0] for d in cur.description], cur.fetchall()
    return run


def _shared_rule_ids(conn, ctx):
    """Rule ids Kibana held on more than one rule at each destination's latest sync."""
    names = {(siem_id, space): name for siem_id, space, name in ctx["scopes"]}
    if not names or "space_fetch_results" not in _tables(conn):
        return [], []
    rows = []
    for siem_id, space, duplicates in conn.execute(
            "SELECT siem_id, space, arg_max(duplicates, synced_at) FROM space_fetch_results "
            "GROUP BY 1, 2 ORDER BY 1, 2").fetchall():
        if (siem_id, space) not in names:
            continue
        for dup in json.loads(duplicates or "[]"):
            rows += [(names[(siem_id, space)], dup["rule_id"], r.get("name") or "",
                      "Elastic prebuilt" if r.get("prebuilt") else "Custom", str(r.get("created_at") or "")[:10],
                      "yes" if r.get("kept") else "no") for r in dup["rules"]]
    return ["destination", "rule id", "rule", "kind", "created", "the one TIDE holds"], rows


def _stale_destinations(conn, ctx):
    """Linked destinations last synced more than STALE_DAYS ago: the Last Synced card's stale count.
    One never synced holds no rules, so it is under destination_no_rules instead."""
    from app.services import rule_issues
    names = {(siem_id, space): name for siem_id, space, name in ctx["scopes"]}
    if not names or "detection_rules" not in _tables(conn):
        return [], []
    now = datetime.now()
    rows = sorted((names[(s["siem_id"], s["space"])], s["space"], s["last_synced"].strftime("%Y-%m-%d %H:%M"),
                   (now - s["last_synced"]).days)
                  for s in rule_issues.stale(conn, list(names), now) if s["last_synced"])
    return ["destination", "space", "last synced", "days ago"], rows


def _custom_under_elastic_id(conn, ctx):
    """Custom rules held under the rule id of one of the Elastic rules built into TIDE (attached
    from the reference database)."""
    from app.services.rule_origins import PREBUILT_SQL
    scopes = ctx["scopes"]
    if not scopes or "detection_rules" not in _tables(conn):
        return [], []
    values = ", ".join("(?, ?, ?)" for _ in scopes)
    try:
        cur = conn.execute(
            f"SELECT d.destination, r.name, r.rule_id FROM detection_rules r "
            f"JOIN (VALUES {values}) AS d(siem_id, space, destination) ON d.siem_id = r.siem_id AND d.space = r.space "
            f"WHERE NOT COALESCE(r.deprecated, false) AND NOT {PREBUILT_SQL} "
            f"AND COALESCE(NULLIF(r.kibana_rule_id, ''), r.rule_id) IN (SELECT rule_id FROM elastic_rules_index) "
            f"ORDER BY 1, 2", [v for s in scopes for v in s])
    except Exception:       # no Elastic rule index (a reference DB from before it), or an old rule table
        return [], []
    return [d[0] for d in cur.description], cur.fetchall()


def _rules_column_drift(conn, ctx):
    from app.services.sync import _TENANT_DETECTION_RULES_COLUMNS
    if "detection_rules" not in _tables(conn):
        return [], []
    have = {r[1] for r in conn.execute("PRAGMA table_info('detection_rules')").fetchall()}
    return ["missing column", "type"], [(c, t) for c, t in _TENANT_DETECTION_RULES_COLUMNS if c not in have]


def _links_missing_rule(conn, ctx):
    """Links with a side TIDE no longer has: the rule that remains (by name, at its destination)
    and where the missing copy was. Both sides gone is still listed, by id."""
    if not {"rule_links", "detection_rules"} <= _tables(conn):
        return [], []
    names = {(sid, sp): name for sid, sp, name in ctx.get("scopes", [])}

    def dest(key):
        return names.get(key) or f"{key[1]} (not linked)"

    rows = conn.execute(
        "SELECT ra.name, l.siem_a_id, l.space_a, l.rule_a_id, rb.name, l.siem_b_id, l.space_b, l.rule_b_id "
        "FROM rule_links l "
        "LEFT JOIN detection_rules ra ON ra.rule_id = l.rule_a_id AND ra.siem_id = l.siem_a_id AND ra.space = l.space_a "
        "LEFT JOIN detection_rules rb ON rb.rule_id = l.rule_b_id AND rb.siem_id = l.siem_b_id AND rb.space = l.space_b "
        "WHERE ra.rule_id IS NULL OR rb.rule_id IS NULL"
    ).fetchall()
    out = []
    for name_a, siem_a, space_a, id_a, name_b, siem_b, space_b, id_b in rows:
        kept, gone = ((name_a, siem_a, space_a, id_a), (name_b, siem_b, space_b, id_b)) if name_a \
            else ((name_b, siem_b, space_b, id_b), (name_a, siem_a, space_a, id_a))
        out.append((
            kept[0] or f"(gone too) {kept[3]}", dest((kept[1], kept[2])), dest((gone[1], gone[2])), gone[3],
        ))
    return ["rule", "destination", "missing copy was at", "missing rule id"], sorted(out)


def _mappings_need_relink(conn, ctx):
    """Mappings whose rule TIDE can't find where the mapping says, named by the system they are on.
    Each system has its own copy of a baseline, so the same baseline and technique on two systems
    are two mappings: relinking one leaves the other listed. A baseline technique's window flags
    exactly these as Needs relinking (same match: rule id, SIEM and space)."""
    if not {"step_detections", "playbook_steps", "playbooks", "detection_rules"} <= _tables(conn):
        return [], []
    names = {(sid, sp): name for sid, sp, name in ctx.get("scopes", [])}
    owned = "system_id" in {r[1] for r in conn.execute("PRAGMA table_info('playbooks')").fetchall()}
    systems = "LEFT JOIN systems sy ON sy.id = p.system_id" if owned and "systems" in _tables(conn) else ""
    rows = conn.execute(
        f"SELECT {'sy.name' if systems else 'NULL'}, {'p.system_id' if owned else 'NULL'}, p.name, s.title, "
        "COALESCE(NULLIF(d.note, ''), d.rule_ref), "
        "d.siem_id, d.space FROM step_detections d "
        f"JOIN playbook_steps s ON s.id = d.step_id JOIN playbooks p ON p.id = s.playbook_id {systems} "
        "WHERE COALESCE(d.source, 'manual') = 'siem' AND (d.siem_id IS NULL OR NOT EXISTS ("
        "SELECT 1 FROM detection_rules r WHERE r.rule_id = d.rule_ref AND r.siem_id = d.siem_id "
        "AND r.space = COALESCE(d.space, 'default')))"
    ).fetchall()
    out = []
    for system, system_id, baseline, technique, rule, siem_id, space in rows:
        where = ("no destination recorded" if not siem_id
                 else names.get((siem_id, space or "default")) or f"{space or 'default'} (not linked)")
        out.append((system or ("a template" if not system_id else "a deleted system"), baseline, technique, rule, where))
    return ["system", "baseline", "technique", "rule", "mapped at"], sorted(out)


def _orphaned_baseline_rows(conn, ctx):
    tables = _tables(conn)
    rows = []
    if {"playbook_steps", "playbooks"} <= tables:
        rows += conn.execute(
            "SELECT 'technique' AS kind, s.title AS name, s.playbook_id AS missing_parent FROM playbook_steps s "
            "WHERE NOT EXISTS (SELECT 1 FROM playbooks p WHERE p.id = s.playbook_id)").fetchall()
    if {"step_detections", "playbook_steps"} <= tables:
        rows += conn.execute(
            "SELECT 'rule mapping', COALESCE(NULLIF(d.note, ''), d.rule_ref), d.step_id FROM step_detections d "
            "WHERE NOT EXISTS (SELECT 1 FROM playbook_steps s WHERE s.id = d.step_id)").fetchall()
    return ["kind", "name", "missing parent"], rows


# Set by app.main at startup to its background_services(): the running app is the only process
# that knows whether its schedulers are alive. Unset (a script, a test), the check finds nothing.
background_status: Optional[Callable[[], list]] = None


def _background_services_down(conn, ctx):
    if background_status is None:
        return [], []
    rows = [(name, detail, consequence) for name, running, detail, consequence in background_status() if not running]
    return ["service", "state", "what stops"], rows


def _keycloak_env_differs(conn, ctx):
    from app.services import keycloak_config
    return [".env line", "in .env", "in TIDE"], keycloak_config.env_differences()


def _database_health(conn, ctx):
    """The tables of this connection's database whose indexes are missing rows, tested on a copy
    (db_health)."""
    from app.services import db_health
    path = conn.execute("SELECT path FROM duckdb_databases() WHERE database_name = current_database()").fetchone()[0]
    return ["table", "rows", "problem"], db_health.check_file(path)


_HEALTH_MEANING = ("Tables whose indexes are missing rows. DuckDB stops a database at the next delete or update "
                   "of such a row, and that client's pages then fail until TIDE restarts. The check copies the "
                   "database and tests every table on the copy, so it takes a while on a large database; "
                   "Run all checks leaves it out.")
_HEALTH_ADVICE = ("Restart TIDE: it rebuilds the rule history indexes as it starts. If a table is still listed, "
                  "stop TIDE and restore the database from a backup (Settings → Management → Backups), which "
                  "rebuilds every index, or report it with this list.")


def _database_fatal(conn, ctx):
    """The last DuckDB fatal error, when it was in the last 7 days, and any file still unavailable
    after one (db_fatal)."""
    from app.services import db_fatal
    rows, shown = [], set()
    record = db_fatal.last()
    try:
        recent = record and datetime.now() - datetime.fromisoformat(record.get("at") or "") < timedelta(days=7)
    except ValueError:
        recent = False
    for rec in ([record] if recent else []) + list(db_fatal.unavailable().values()):
        key = (rec.get("at"), rec.get("db"))
        if key in shown:
            continue
        shown.add(key)
        still = rec.get("db") in db_fatal.unavailable()
        rows.append((rec.get("at"), os.path.basename(rec.get("db") or ""), rec.get("error") or "",
                     "unavailable until TIDE restarts" if still
                     else "restarted TIDE" if rec.get("restarted") else "left it unavailable until a restart"))
    return ["when", "database", "error", "what TIDE did"], rows


CHECKS: List[Check] = [
    Check(
        "background_services", "Background services not running", "install", "error",
        "TIDE's background service, the schedule for rule-log export and backups, is not running. "
        "Pages still work, but what it does on its own has stopped.",
        "Restart TIDE. If it still isn't running, the log at startup says why "
        "('Background service not running', and the error before it).",
        _background_services_down,
    ),
    Check(
        "keycloak_env_differs", "Keycloak settings in .env that TIDE no longer reads", "install", "warning",
        "TIDE signs people in with its Keycloak integration, made from .env's Keycloak settings the first "
        "time TIDE 6.3.0 started; .env's Keycloak lines are not read after that. These lines differ from "
        "the integration, so a change made in .env (for example by a deployment that writes it) has not "
        "taken effect.",
        "Make the change in the Keycloak integration (Settings → Management → Integrations), then remove "
        "the Keycloak lines from .env or make them match.",
        _keycloak_env_differs,
    ),
    Check(
        "database_fatal", "A database stopped after a DuckDB fatal error", "install", "error",
        "DuckDB stopped one of TIDE's databases after a fatal error (in the last 7 days), which makes that "
        "client's pages fail until TIDE restarts. TIDE restarts itself once for it, and the restart repairs "
        "the rule history indexes; a second fatal error on the same file within 10 minutes leaves the file "
        "unavailable instead, so the other clients keep working.",
        "If TIDE restarted and the client's pages work, nothing more is needed. If the file is unavailable, "
        "restart TIDE (docker compose restart tide-app); if the error comes back, back up the data folder "
        "and report the error shown here.",
        _database_fatal,
    ),
    Check("shared_database_health", "TIDE's own database: indexes missing rows", "install", "error",
          _HEALTH_MEANING, _HEALTH_ADVICE, _database_health, on_demand=True),
    Check(
        "schema_behind", "Database schema older than this release", "install", "error",
        "TIDE upgraded but the shared database was not migrated, so pages that need newer tables or "
        "columns can fail.",
        "Restart TIDE so it runs its migrations, then check the log for 'Migrations complete'.",
        _schema_behind,
    ),
    Check(
        "missing_tenant_db", "Clients whose database file is missing", "install", "error",
        "TIDE has a client whose data file is not in the data folder; that client's pages show nothing.",
        "Restore the file from a backup, or remove the client in Management if it is no longer used.",
        _missing_tenant_db,
    ),
    Check(
        "unknown_siem", "Destinations linked to a SIEM that no longer exists", "install", "error",
        "A client still has a destination on a SIEM that was deleted, so its sync and Move cannot reach it.",
        "In Management → Clients, remove the destination from the client, or add the SIEM back.",
        _query("SELECT c.name AS client, m.name AS destination, m.space, m.siem_id FROM client_siem_map m "
               "JOIN clients c ON c.id = m.client_id "
               "WHERE NOT EXISTS (SELECT 1 FROM siem_inventory s WHERE s.id = m.siem_id) ORDER BY 1, 2",
               needs=("client_siem_map", "clients", "siem_inventory")),
    ),
    Check(
        "space_whitespace", "Destination spaces with spaces around them", "install", "warning",
        "A linked Kibana space has a space at its start or end. The rule search trims it but sync and "
        "Add link do not, so rules can appear in search and still not be found there.",
        "In Management → Clients, remove the destination and link it again with the space typed exactly.",
        _query("SELECT c.name AS client, m.name AS destination, '\"' || m.space || '\"' AS space FROM client_siem_map m "
               "JOIN clients c ON c.id = m.client_id WHERE m.space <> trim(m.space) ORDER BY 1, 2",
               needs=("client_siem_map", "clients")),
    ),
    Check(
        "super_admins", "Who is a super admin", "install", "info",
        "Users with Platform Admin: they see every client and can change every setting.",
        "Grant or revoke it with Platform Admin in Management → Users.",
        _query("SELECT username, COALESCE(email, '') AS email, auth_provider AS sign_in, "
               "CASE WHEN is_active THEN 'yes' ELSE 'no' END AS active, last_login FROM users "
               "WHERE is_superadmin ORDER BY username", needs=("users",)),
        listing=True,
    ),
    Check(
        "rules_column_drift", "Rule table missing columns", "client", "error",
        "This client's rule table lacks columns this release writes, so sync fails or drops data.",
        "Restart TIDE (the rule table is repaired at start-up and on sync), then run Sync for the client.",
        _rules_column_drift,
    ),
    Check("database_health", "Client database: indexes missing rows", "client", "error",
          _HEALTH_MEANING, _HEALTH_ADVICE, _database_health, on_demand=True),
    Check(
        "destination_offline", "Destinations TIDE could not reach at the last sync", "client", "warning",
        "The last sync could not reach this SIEM space; its rules are shown from TIDE's last copy.",
        "Check the SIEM is up and its address and API key in Management → SIEMs, then Sync again.",
        _scoped("SELECT d.destination, d.space, s.reason, s.checked_at FROM {scopes} "
                "JOIN siem_space_status s ON s.siem_id = d.siem_id AND s.space = d.space "
                "WHERE NOT s.reachable ORDER BY 1", needs=("siem_space_status",)),
    ),
    Check(
        "destination_stale", f"Destinations not synced for {STALE_DAYS} days", "client", "warning",
        f"TIDE hasn't read this destination's rules from Kibana for more than {STALE_DAYS} days. Its rules, "
        "scores and coverage, Rule Monitoring and exported reports are as of that sync, so they may no longer "
        "match Kibana. Rule Health's Last Synced card shows it in red.",
        "Use Sync in Rule Health's ⋮ menu. If the SIEM can't be reached, the destination is listed under "
        "Destinations TIDE could not reach at the last sync.",
        _stale_destinations,
    ),
    Check(
        "sync_drift_repeated", "Destinations whose last two syncs could not read every rule", "client", "warning",
        "At its last two syncs, Kibana returned fewer rules for this destination than it said it holds, so TIDE "
        "did not mark the rules deleted in Kibana as deprecated there. TIDE still counts them, including as "
        "coverage. The last column is how many rules TIDE holds that Kibana did not return.",
        "Check the SIEM is healthy and look for 'Sync drift' in the log, then Sync again. To clear one rule "
        "you know was deleted, open it and use Sync this rule: it is marked deprecated and keeps its history.",
        _scoped("WITH r AS (SELECT *, row_number() OVER (PARTITION BY siem_id, space ORDER BY synced_at DESC) AS n "
                "FROM space_fetch_results) "
                "SELECT d.destination, d.space, max(r.synced_at) AS last_sync, "
                "max(CASE WHEN r.n = 1 THEN r.kibana_total END) AS kibana_total, "
                "max(CASE WHEN r.n = 1 THEN r.returned END) AS returned, "
                "max(CASE WHEN r.n = 1 THEN r.held_not_returned END) AS held_not_returned "
                "FROM r JOIN {scopes} ON d.siem_id = r.siem_id AND d.space = r.space WHERE r.n <= 2 "
                "GROUP BY d.destination, d.space HAVING count(*) = 2 AND NOT bool_or(r.complete) ORDER BY 1",
                needs=("space_fetch_results",)),
    ),
    Check(
        "kibana_shared_rule_id", "Rules sharing a rule id in Kibana", "client", "warning",
        "Kibana holds two rules under the same rule id in this destination, usually a copy made under one of "
        "Elastic's rule ids and Elastic's own prebuilt rule installed there later. TIDE holds one rule per "
        "rule id, so the other is not shown, scored or counted.",
        "In Rule Monitoring, use Compare with the copy on the rule (or Compare them one by one), then choose: "
        "delete the copy, keep both (the copy gets a rule id of its own), or keep both and disable the rule TIDE shows.",
        _shared_rule_ids,
    ),
    Check(
        "custom_rule_elastic_id", "Custom rules using one of Elastic's rule ids", "client", "warning",
        "A custom rule (usually one moved, copied or restored by an earlier TIDE) uses the rule id of one of "
        "Elastic's prebuilt rules. While it does, Kibana can't install Elastic's own rule in that space, or "
        "installs it beside this one under the same rule id.",
        "Open the rule in Rule Health and use Give it its own rule id in its Upstream section. TIDE keeps its "
        "history, links and mappings, and still shows Elastic's updates for it.",
        _custom_under_elastic_id,
    ),
    Check(
        "destination_no_rules", "Linked destinations with no rules", "client", "warning",
        "TIDE holds no rules for this destination. It may not have been synced yet, or its space may be "
        "mistyped so sync finds nothing.",
        "Sync the client. If it stays empty, check the space name matches the Kibana space ID.",
        _scoped("SELECT d.destination, d.space FROM {scopes} WHERE NOT EXISTS (SELECT 1 FROM detection_rules r "
                "WHERE r.siem_id = d.siem_id AND r.space = d.space) ORDER BY 1", needs=("detection_rules",)),
    ),
    Check(
        "rules_unlinked_destination", "Rules held for destinations the client no longer links", "client", "info",
        "TIDE still holds rules from a SIEM space that is no longer linked to this client. They are not "
        "shown on its pages and do not count toward coverage.",
        "Nothing is needed; they are left from an earlier link. Link the destination again if it should count.",
        _scoped("SELECT r.siem_id, r.space, COUNT(*) AS rules FROM detection_rules r "
                "WHERE NOT EXISTS (SELECT 1 FROM {scopes} WHERE d.siem_id = r.siem_id AND d.space = r.space) "
                "GROUP BY 1, 2 ORDER BY 3 DESC", needs=("detection_rules",)),
    ),
    Check(
        "mappings_need_relink", "Rule mappings that need relinking", "client", "warning",
        "A baseline technique is mapped to a rule TIDE can no longer find where the mapping says (moved, "
        "renamed in the SIEM, deleted, or mapped before destinations were recorded). It does not count. "
        "Each system has its own copy of a baseline, so the same technique on another system is listed "
        "until it is relinked there too.",
        "Open the technique on the system named, and use Relink on the mapping, or remove it.",
        _mappings_need_relink,
    ),
    Check(
        "links_missing_rule", "Rule links to a rule that is gone", "client", "info",
        "One side of a rule link no longer exists in TIDE. The rule window shows it as 'Deleted rule'.",
        "Remove the link from the rule's Linked panel if the copy is not coming back.",
        _links_missing_rule,
    ),
    Check(
        "rule_name_whitespace", "Rule names with spaces around them", "client", "info",
        "A rule's name in the SIEM starts or ends with a space. Before 6.0.2, Add link could not link to "
        "these rules.",
        "Rename the rule in Kibana without the extra space, then use Sync this rule in TIDE.",
        _scoped("SELECT d.destination, '\"' || r.name || '\"' AS name FROM detection_rules r JOIN {scopes} "
                "ON d.siem_id = r.siem_id AND d.space = r.space WHERE r.name <> trim(r.name) ORDER BY 1, 2",
                needs=("detection_rules",)),
    ),
    Check(
        "duplicate_rule_names", "Rule names used more than once in a destination", "client", "info",
        "Two or more rules in one destination share a name, so a name alone does not say which rule is meant.",
        "Rename one of them in Kibana if they are different rules; pick from the list when linking.",
        _scoped("SELECT d.destination, r.name, COUNT(*) AS rules FROM detection_rules r JOIN {scopes} "
                "ON d.siem_id = r.siem_id AND d.space = r.space WHERE NOT r.deprecated "
                "GROUP BY 1, 2 HAVING COUNT(*) > 1 ORDER BY 3 DESC, 1, 2", needs=("detection_rules",)),
    ),
    Check(
        "orphaned_baseline_rows", "Baseline rows left without their baseline", "client", "warning",
        "Techniques or rule mappings whose baseline or technique was deleted are still stored. They are "
        "not shown anywhere.",
        "Nothing breaks; a later release can remove them. Report it if the count keeps growing.",
        _orphaned_baseline_rows,
    ),
]
CHECKS_BY_ID = {c.id: c for c in CHECKS}


def _redact(columns: List[str], rows: List[tuple]) -> List[tuple]:
    hidden = [i for i, c in enumerate(columns) if _SECRET_COLUMN.search(c or "")]
    if not hidden:
        return rows
    return [tuple("••••" if i in hidden else v for i, v in enumerate(r)) for r in rows]


def _rolled_back(conn, fn: Callable, ctx: Dict) -> Tuple[List[str], List[tuple]]:
    """Run ``fn`` in a transaction that is always rolled back: a check can never change data."""
    conn.execute("BEGIN TRANSACTION")
    try:
        return fn(conn, ctx)
    finally:
        conn.execute("ROLLBACK")


def _result(check: Check, columns: List[str], rows: List[tuple], error: str = "") -> Dict[str, Any]:
    if error:
        status = "failed"
    elif check.listing:
        status = "listing"
    else:
        status = check.severity if rows else "ok"
    return {
        "id": check.id, "title": check.title, "scope": check.scope, "severity": check.severity,
        "meaning": check.meaning, "advice": check.advice, "listing": check.listing,
        "status": status, "count": len(rows), "columns": columns,
        "rows": _redact(columns, rows[:SAMPLE_ROWS]), "truncated": len(rows) > SAMPLE_ROWS, "error": error,
    }


def run_checks(db, check_ids: List[str], clients: List[Dict]) -> Dict[str, Any]:
    """Run the named checks: install checks once, client checks for each of ``clients``.
    Returns ``{"install": [result], "clients": [{"client": {...}, "results": [result]}]}``."""
    from app.services.tenant_manager import tenant_context_for
    chosen = [CHECKS_BY_ID[i] for i in check_ids if i in CHECKS_BY_ID]
    data_dir = os.path.dirname(db.db_path)
    out: Dict[str, Any] = {"install": [], "clients": []}

    def one(check, conn, ctx):
        try:
            cols, rows = _rolled_back(conn, check.run, ctx)
            return _result(check, cols, rows)
        except Exception as exc:
            logger.warning("Diagnostics check %s failed", check.id, exc_info=True)
            return _result(check, [], [], error=str(exc).splitlines()[0][:300])

    install = [c for c in chosen if c.scope == "install"]
    if install:
        with db.get_shared_connection() as conn:
            out["install"] = [one(c, conn, {"data_dir": data_dir}) for c in install]

    client_checks = [c for c in chosen if c.scope == "client"]
    for client in clients if client_checks else []:
        scopes = [(s.get("id"), s.get("space") or "default", s.get("name") or s.get("label") or s.get("space"))
                  for s in (db.get_client_siems(client["id"]) or [])]
        ctx = {"data_dir": data_dir, "client_id": client["id"], "scopes": scopes}
        try:
            with tenant_context_for(client["id"]), db.get_connection() as conn:
                results = [one(c, conn, ctx) for c in client_checks]
        except Exception as exc:
            logger.warning("Diagnostics could not open %s's database", client.get("name"), exc_info=True)
            results = [_result(c, [], [], error=f"Could not open this client's database: {exc}") for c in client_checks]
        out["clients"].append({"client": client, "results": results})
    return out


# ── look-ups: everything TIDE holds for one named thing ──────────────────

LOOKUP_KINDS = ("rule", "user", "destination")
LOOKUP_LIMIT = 20
_HIDDEN = {" ": "⍽", "​": "∅", "﻿": "∅", "\t": "⇥", "\r": "↵", "\n": "↵"}


def reveal(value: Optional[str]) -> Dict[str, Any]:
    """A stored string as it really is: quoted, with spaces at its ends and invisible characters
    shown as marks. ``odd`` is True when it holds any of them -- the kind of difference that makes
    two names look the same on screen and not match."""
    if value is None:
        return {"text": "—", "odd": False}
    core = value.strip(" ")
    lead, trail = len(value) - len(value.lstrip(" ")), len(value) - len(value.rstrip(" "))
    core = re.sub(r" {2,}", lambda m: "·" * len(m.group()), core)    # doubled spaces inside a name
    shown = "".join(_HIDDEN.get(ch, ch) for ch in core)
    text = "·" * lead + shown + "·" * trail
    odd = bool(lead or trail) or any(ch in _HIDDEN for ch in value) or "  " in value
    return {"text": f"“{text}”", "odd": odd}


def _rule_lookup(conn, q: str, scopes: List[Tuple[str, str, str]]) -> List[Dict[str, Any]]:
    tables = _tables(conn)
    if "detection_rules" not in tables:
        return []
    names = {(sid, sp): name for sid, sp, name in scopes}

    def dest(siem_id, space):
        return names.get((siem_id, space)) or f"{space} (not linked)"

    rows = conn.execute(
        "SELECT rule_id, siem_id, space, name, enabled, deprecated, score, last_updated FROM detection_rules "
        "WHERE name ILIKE ? OR rule_id = ? ORDER BY lower(trim(name)), siem_id, space LIMIT ?",
        [f"%{q}%", q, LOOKUP_LIMIT + 1],
    ).fetchall()
    out = []
    for rule_id, siem_id, space, name, enabled, deprecated, score, last in rows[:LOOKUP_LIMIT]:
        links, mapped = [], []
        if "rule_links" in tables:
            for oid, osiem, ospace in conn.execute(
                "SELECT rule_b_id, siem_b_id, space_b FROM rule_links WHERE rule_a_id = ? AND siem_a_id = ? AND space_a = ? "
                "UNION ALL SELECT rule_a_id, siem_a_id, space_a FROM rule_links WHERE rule_b_id = ? AND siem_b_id = ? AND space_b = ?",
                [rule_id, siem_id, space] * 2,
            ).fetchall():
                other = conn.execute("SELECT name FROM detection_rules WHERE rule_id = ? AND siem_id = ? AND space = ?",
                                     [oid, osiem, ospace]).fetchone()
                links.append(f"{other[0]} at {dest(osiem, ospace)}" if other else f"gone ({oid}) at {dest(osiem, ospace)}")
        if {"step_detections", "playbook_steps", "playbooks"} <= tables:
            mapped = [f"{b} › {t}" for b, t in conn.execute(
                "SELECT p.name, s.title FROM step_detections d JOIN playbook_steps s ON s.id = d.step_id "
                "JOIN playbooks p ON p.id = s.playbook_id WHERE d.rule_ref = ? AND d.siem_id = ? "
                "AND COALESCE(d.space, 'default') = ? ORDER BY 1, 2", [rule_id, siem_id, space]).fetchall()]
        out.append({
            "name": reveal(name), "rule_id": rule_id, "destination": dest(siem_id, space), "space": reveal(space),
            "enabled": bool(enabled), "deprecated": bool(deprecated), "score": score, "last_updated": last,
            "links": links, "mapped": mapped,
        })
    return out + ([{"more": True}] if len(rows) > LOOKUP_LIMIT else [])


def lookup(db, kind: str, q: str, clients: List[Dict]) -> Dict[str, Any]:
    """Everything TIDE holds for rules, users or destinations matching ``q`` (part of a name,
    username, email or space, or an exact rule id). Read-only, like the checks."""
    from app.services.tenant_manager import tenant_context_for
    q = (q or "").strip()
    out: Dict[str, Any] = {"kind": kind, "q": q, "groups": [], "more": False}
    if kind not in LOOKUP_KINDS or len(q) < 2:
        return out

    if kind == "user":
        def users(conn, ctx):
            rows = conn.execute(
                "SELECT id, username, email, full_name, auth_provider, is_active, is_superadmin, keycloak_id IS NOT NULL, "
                "last_login, created_at FROM users WHERE username ILIKE ? OR email ILIKE ? OR full_name ILIKE ? "
                "ORDER BY username LIMIT ?", [f"%{q}%"] * 3 + [LOOKUP_LIMIT + 1]).fetchall()
            client_names = dict(conn.execute("SELECT id, name FROM clients").fetchall())
            found = []
            for uid, uname, email, full, provider, active, superadmin, sso_linked, last, created in rows[:LOOKUP_LIMIT]:
                roles: Dict[str, List[str]] = {}
                for cid, role in conn.execute(
                    "SELECT ur.client_id, r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id "
                    "WHERE ur.user_id = ? ORDER BY r.name", [uid]).fetchall():
                    roles.setdefault(cid, []).append(role)
                assigned = conn.execute("SELECT client_id, is_default FROM user_clients WHERE user_id = ?", [uid]).fetchall()
                found.append({
                    "username": reveal(uname), "email": email or "", "full_name": full or "",
                    "provider": provider or "local", "sso_linked": bool(sso_linked), "active": bool(active),
                    "superadmin": bool(superadmin), "last_login": last, "created_at": created,
                    "clients": [{"name": client_names.get(cid, cid), "default": bool(default),
                                 "roles": roles.get(cid, [])} for cid, default in sorted(
                                     assigned, key=lambda a: client_names.get(a[0], a[0]).lower())],
                })
            return found, len(rows) > LOOKUP_LIMIT
        with db.get_shared_connection() as conn:
            found, more = _rolled_back(conn, users, {})
        out["groups"] = [{"name": "", "entries": found}]
        out["more"] = more
        return out

    for client in clients:
        siems = db.get_client_siems(client["id"]) or []
        scopes = [(s.get("id"), s.get("space") or "default", s.get("name") or s.get("label") or s.get("space"))
                  for s in siems]
        try:
            with tenant_context_for(client["id"]), db.get_connection() as conn:
                if kind == "rule":
                    items = _rolled_back(conn, lambda c, ctx: _rule_lookup(c, q, scopes), {})
                else:
                    wanted = [s for s in siems if q.lower() in (s.get("name") or "").lower()
                              or q.lower() in (s.get("space") or "").lower()]

                    def dests(c, ctx):
                        tables = _tables(c)
                        rows = []
                        for s in wanted:
                            key = [s.get("id"), s.get("space") or "default"]
                            rules = c.execute(
                                "SELECT COUNT(*), COUNT(*) FILTER (WHERE deprecated), MAX(last_updated) FROM detection_rules "
                                "WHERE siem_id = ? AND space = ?", key).fetchone() if "detection_rules" in tables else (0, 0, None)
                            status = c.execute(
                                "SELECT reachable, reason, checked_at FROM siem_space_status WHERE siem_id = ? AND space = ?",
                                key).fetchone() if "siem_space_status" in tables else None
                            rows.append({
                                "name": reveal(s.get("name")), "siem": s.get("label") or "", "siem_id": s.get("id"),
                                "space": reveal(s.get("space")), "rules": rules[0], "deprecated": rules[1],
                                "last_rule_change": rules[2],
                                "reachable": status[0] if status else None, "reason": (status[1] or "") if status else "",
                                "checked_at": status[2] if status else None,
                            })
                        return rows
                    items = _rolled_back(conn, dests, {})
        except Exception as exc:
            logger.warning("Diagnostics look-up could not read %s", client.get("name"), exc_info=True)
            items = [{"error": str(exc).splitlines()[0][:300]}]
        more = bool(items and items[-1].get("more"))
        items = [i for i in items if not i.get("more")]
        out["more"] = out["more"] or more
        if items:
            out["groups"].append({"name": client.get("name") or client["id"], "entries": items, "more": more})
    return out


_RANK = {"ok": 0, "listing": 1, "info": 2, "warning": 3, "error": 4}


def by_check(results: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """``run_checks`` output regrouped per check, for one row per check on the page:
    ``{check_id: {status (worst), count, affected, failed, clean: [names], parts: [{name, result}]}}``.
    An install check has one part with no name; a client check has one per client."""
    out: Dict[str, Dict[str, Any]] = {}
    for r in results["install"]:
        out[r["id"]] = {"parts": [{"name": "", "client_id": None, "result": r}]}
    for c in results["clients"]:
        for r in c["results"]:
            out.setdefault(r["id"], {"parts": []})["parts"].append(
                {"name": c["client"]["name"], "client_id": c["client"].get("id"), "result": r})
    for o in out.values():
        rs = [p["result"] for p in o["parts"]]
        ran = [r["status"] for r in rs if r["status"] != "failed"]
        o["failed"] = len(rs) - len(ran)
        # Findings decide the status; a part that could not run never reads as "no problems".
        status = max(ran, key=_RANK.get) if ran else "failed"
        o["status"] = "failed" if o["failed"] and status == "ok" else status
        o["count"] = sum(r["count"] for r in rs if r["status"] != "failed")
        o["affected"] = sum(1 for r in rs if r["count"])
        o["clean"] = [p["name"] for p in o["parts"] if p["result"]["status"] == "ok" and p["name"]]
    return out


# ── snapshot ─────────────────────────────────────────────────────────────

def recent_errors(log_path: Optional[str] = None, limit: int = 10, hours: int = 24,
                  client_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """The newest ERROR lines in TIDE's log, and how many there were in the last ``hours``.
    With ``client_ids``, only lines recorded against one of those clients (each line carries the
    request's client), so one client's view never shows another's errors."""
    log_path = log_path if log_path is not None else os.getenv("TIDE_LOG_FILE", "/app/data/log/tide.log")
    if not log_path or not os.path.exists(log_path):
        return {"available": False, "count": 0, "entries": []}
    since = datetime.utcnow() - timedelta(hours=hours)
    newest: deque = deque(maxlen=limit)
    count = 0
    with open(log_path, "rb") as fh:
        fh.seek(max(0, os.path.getsize(log_path) - 4 * 1024 * 1024))   # the last 4 MB is plenty
        for raw in fh:
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if str(rec.get("level", "")).upper() not in ("ERROR", "CRITICAL"):
                continue
            if client_ids is not None and rec.get("client_id") not in client_ids:
                continue
            try:
                at = datetime.strptime(str(rec.get("ts", ""))[:19], "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                at = None
            if at and at >= since:
                count += 1
            newest.append({"at": at, "logger": rec.get("logger", ""), "route": rec.get("route", ""),
                           "message": str(rec.get("msg", ""))[:300]})
    return {"available": True, "count": count, "entries": list(reversed(newest)), "hours": hours}


def snapshot(db, clients: List[Dict], full: bool = True) -> Dict[str, Any]:
    """The install at a glance: versions, super admins, and each client's destinations -- rules
    held, when they last changed and whether the SIEM answered at the last sync. Without ``full``
    (a Support user) it leaves out the super-admin count and keeps only these clients' log errors."""
    from app.config import get_settings
    from app.services.database import SCHEMA_VERSION
    from app.services.tenant_manager import tenant_context_for

    data_dir = os.path.dirname(db.db_path)
    with db.get_shared_connection() as conn:
        db_schema = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] or 0
        supers = conn.execute("SELECT COUNT(*) FROM users WHERE is_superadmin AND is_active").fetchone()[0]
        filenames = dict(conn.execute("SELECT id, db_filename FROM clients").fetchall())

    out_clients = []
    for client in clients:
        siems = db.get_client_siems(client["id"]) or []
        fname = filenames.get(client["id"])
        path = os.path.join(data_dir, fname) if fname else None
        destinations = []
        try:
            with tenant_context_for(client["id"]), db.get_connection() as conn:
                tables = _tables(conn)
                counts = {
                    (sid, sp): (n, last) for sid, sp, n, last in conn.execute(
                        "SELECT siem_id, space, COUNT(*), MAX(last_updated) FROM detection_rules GROUP BY 1, 2"
                    ).fetchall()
                } if "detection_rules" in tables else {}
                status = {
                    (sid, sp): (ok, reason, at) for sid, sp, ok, reason, at in conn.execute(
                        "SELECT siem_id, space, reachable, reason, checked_at FROM siem_space_status"
                    ).fetchall()
                } if "siem_space_status" in tables else {}
        except Exception:
            logger.warning("Diagnostics snapshot could not read %s", client.get("name"), exc_info=True)
            counts, status = {}, {}
        for s in siems:
            key = (s.get("id"), s.get("space") or "default")
            rules, last = counts.get(key, (0, None))
            reachable, reason, checked = status.get(key, (None, None, None))
            destinations.append({
                "name": s.get("name") or s.get("space"), "siem": s.get("label") or "", "space": key[1],
                "color": s.get("color"), "rules": rules, "last_rule_change": last,
                "reachable": reachable, "reason": reason or "", "checked_at": checked,
            })
        out_clients.append({
            "id": client["id"], "name": client.get("name") or client["id"],
            "db_size": os.path.getsize(path) if path and os.path.exists(path) else None,
            "destinations": destinations,
        })
    return {
        "version": get_settings().tide_version, "schema": {"database": db_schema, "release": SCHEMA_VERSION},
        "super_admins": supers if full else None, "clients": out_clients,
        "errors": recent_errors(client_ids=None if full else [c["id"] for c in clients]),
    }
