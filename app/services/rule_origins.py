"""Where a rule came from: Elastic's detection rules or the SigmaHQ rules, both bundled in the
image, and which revision of the upstream rule it was taken from.

One row per rule copy, keyed like ``detection_rules`` by ``(rule_id, siem_id, space)``, in the
tenant's ``rule_origins`` table:

- ``origin``: ``elastic`` or ``sigma``. A rule with no row is the tenant's own, and so is one with
  ``none``: unlinked by the user (``recorded_how`` ``unlinked``, ``upstream_id`` what it was linked
  to), which keeps a sync from linking it again by its rule id.
- ``upstream_id``: the Elastic ``rule_id`` or Sigma ``id`` it came from. A copy made under a new
  rule id keeps its upstream id here, so it is still recognised.
- ``upstream_version`` / ``upstream_hash`` / ``upstream_date``: the upstream rule as it was when
  this copy was taken (Elastic's version; a fingerprint of the rule; its own last-change date).
- ``prebuilt``: installed by Kibana's own prebuilt rules, not by TIDE. Its version is Kibana's,
  read from the rule itself.
- ``parent_*``: the copy it was made from, when it was given a new rule id.
- ``recorded_how``: ``deployed`` (from TIDE's Sigma or Elastic page), ``created`` (Create Rule from
  a Sigma conversion), ``copied`` (Move/copy), ``updated`` (an upstream update reviewed, all of it
  or some sections taken), ``unchanged`` (an Elastic update that changes nothing compared, moved
  to by TIDE at a sync or by the user), ``first_seen`` (found at a sync; its revision is taken as
  the bundled one at that time), or ``matched`` (a rule converted from Sigma before origins were recorded,
  found by its Sigma title and tags; only the day it was made is known).
- ``convert_options``: how a Sigma rule was converted (JSON: pipeline, template, index pattern), so
  an upstream update can be converted the same way.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

DDL = """
    CREATE TABLE IF NOT EXISTS rule_origins (
        rule_id          VARCHAR NOT NULL,
        siem_id          VARCHAR NOT NULL,
        space            VARCHAR NOT NULL,
        origin           VARCHAR NOT NULL,
        upstream_id      VARCHAR NOT NULL,
        upstream_version INTEGER,
        upstream_hash    VARCHAR,
        upstream_date    DATE,
        prebuilt         BOOLEAN DEFAULT false,
        parent_rule_id   VARCHAR,
        parent_siem_id   VARCHAR,
        parent_space     VARCHAR,
        recorded_how     VARCHAR,
        recorded_by      VARCHAR,
        recorded_at      TIMESTAMP DEFAULT now(),
        convert_options  VARCHAR,
        PRIMARY KEY (rule_id, siem_id, space)
    )
"""

_COLS = ("rule_id", "siem_id", "space", "origin", "upstream_id", "upstream_version", "upstream_hash",
         "upstream_date", "prebuilt", "parent_rule_id", "parent_siem_id", "parent_space",
         "recorded_how", "recorded_by", "convert_options")

Key = Tuple[str, str, str]

_ready: set = set()     # database files whose rule_origins table is current, this process


def ensure(conn) -> None:
    """Create ``rule_origins`` (and any column added since) once per database file per process."""
    path = conn.execute(
        "SELECT path FROM duckdb_databases() WHERE database_name = current_database()").fetchone()
    key = path[0] if path else None
    if key and key in _ready:
        return
    conn.execute(DDL)
    conn.execute("ALTER TABLE rule_origins ADD COLUMN IF NOT EXISTS convert_options VARCHAR")
    if key:
        _ready.add(key)


def _write(conn, values: Dict[str, Any]) -> None:
    conn.execute(
        f"INSERT OR REPLACE INTO rule_origins ({', '.join(_COLS)}) VALUES ({', '.join('?' * len(_COLS))})",
        [values.get(c) for c in _COLS],
    )


def _rows(cursor) -> List[Dict[str, Any]]:
    cols = [d[0] for d in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


def upstream(conn, origin: str, upstream_id: str) -> Optional[Dict[str, Any]]:
    """The bundled rule ``upstream_id`` as it is now: ``{version, hash, date, name, status}``, or
    None when it is not in this image (or the reference DB predates the index)."""
    sql = {
        "elastic": "SELECT version, content_hash AS hash, updated AS date, name, status "
                   "FROM elastic_rules_index WHERE rule_id = ?",
        "sigma": "SELECT NULL AS version, content_hash AS hash, modified AS date, title AS name, status "
                 "FROM sigma_rules_index WHERE rule_id = ?",
    }.get(origin)
    if not sql or not upstream_id:
        return None
    try:
        rows = _rows(conn.execute(sql, [upstream_id]))
    except Exception as exc:
        logger.warning("Upstream %s rule lookup failed: %s", origin, exc)
        return None
    return rows[0] if rows else None


def record(conn, key: Key, origin: str, upstream_id: str, how: str, actor: str = "",
           parent: Optional[Key] = None, prebuilt: bool = False,
           version: Optional[int] = None, convert_options: Optional[dict] = None) -> None:
    """Record (or replace) where the rule at ``key`` came from, taking the upstream revision from
    the bundled rule as it is now. ``version`` overrides it (a prebuilt rule's installed version)."""
    ensure(conn)
    now = upstream(conn, origin, upstream_id) or {}
    values = dict(zip(("rule_id", "siem_id", "space"), key))
    values.update({
        "origin": origin, "upstream_id": upstream_id,
        "upstream_version": version if version is not None else now.get("version"),
        "upstream_hash": None if prebuilt else now.get("hash"),
        "upstream_date": None if prebuilt else now.get("date"),
        "prebuilt": prebuilt,
        "parent_rule_id": parent[0] if parent else None,
        "parent_siem_id": parent[1] if parent else None,
        "parent_space": parent[2] if parent else None,
        "recorded_how": how, "recorded_by": actor or "TIDE",
        "convert_options": json.dumps(convert_options) if convert_options else None,
    })
    _write(conn, values)


def get(conn, key: Key) -> Optional[Dict[str, Any]]:
    ensure(conn)
    rows = _rows(conn.execute(
        "SELECT * FROM rule_origins WHERE rule_id = ? AND siem_id = ? AND space = ?", list(key)))
    return rows[0] if rows else None


def mark_current(conn, key: Key, actor: str = "", version: Optional[int] = None, how: str = "updated") -> bool:
    """Re-stamp ``key`` as taken from the bundled upstream revision as it is now (an update reviewed:
    all, some or none of it taken), keeping everything else about its origin. ``version`` is the
    upstream version reviewed when it is not the bundled rule's own (Elastic's build for the rule's
    SIEM's Elastic version). ``how`` is ``unchanged`` when the update changed nothing compared.
    False if it has none."""
    row = get(conn, key)
    if not row:
        return False
    now = upstream(conn, row["origin"], row["upstream_id"]) or {}
    row.update({"upstream_version": version if version is not None else now.get("version", row["upstream_version"]),
                "upstream_hash": None if row["prebuilt"] else now.get("hash", row["upstream_hash"]),
                "upstream_date": None if row["prebuilt"] else now.get("date", row["upstream_date"]),
                "recorded_how": how, "recorded_by": actor or "TIDE"})
    _write(conn, row)
    return True


def copy(conn, source: Key, target: Key, how: str, actor: str = "", parent: bool = False) -> bool:
    """Give ``target`` the same origin and upstream revision as ``source`` (a moved or copied rule).
    ``parent`` records ``source`` as the copy it was made from. False if ``source`` has no origin.
    The copy is never prebuilt: TIDE creates it, so Kibana holds it as a custom rule. A copy of a
    prebuilt rule keeps the version Kibana had installed, which its updates are compared with."""
    values = get(conn, source)
    if not values:
        return False
    values.update(dict(zip(("rule_id", "siem_id", "space"), target)))
    values.update({"recorded_how": how, "recorded_by": actor or "TIDE", "prebuilt": False})
    if parent:
        values.update(dict(zip(("parent_rule_id", "parent_siem_id", "parent_space"), source)))
    _write(conn, values)
    return True


def unlink_refused(row: Optional[Dict[str, Any]]) -> Optional[str]:
    """Why a rule (``row`` its origin) can't be unlinked from an Elastic rule, or None when it can: it
    must be linked to one, and not be Elastic's own rule installed by Kibana."""
    if not row or row.get("origin") != "elastic":
        return "This rule isn't linked to one of Elastic's rules."
    if row.get("prebuilt"):
        return "This is Elastic's own rule, installed by Kibana."
    return None


def unlink(db, client_id: str, key: Key, user_id: Optional[str], actor: str) -> Tuple[int, str]:
    """Unlink from Elastic: the rule stops tracking the Elastic rule TIDE linked it to (wrongly, or it
    has gone its own way) and is the tenant's own from then on, even under that rule's id: its row
    becomes ``none``, which a sync never links again. Nothing changes in Kibana. Returns ``(status,
    message)``."""
    from app.services.tenant_manager import tenant_context_for
    if not db.get_rule_by_id(key[0], key[2], siem_id=key[1], client_id=client_id):
        return 404, "Rule not found."
    with tenant_context_for(client_id), db.get_connection() as conn:
        row = get(conn, key)
        refused = unlink_refused(row)
        if refused:
            return 400, refused
        name = (upstream(conn, "elastic", row["upstream_id"]) or {}).get("name") or row["upstream_id"]
        _write(conn, {"rule_id": key[0], "siem_id": key[1], "space": key[2], "origin": "none",
                      "upstream_id": row["upstream_id"], "recorded_how": "unlinked", "recorded_by": actor or "TIDE"})
    message = f'Unlinked from Elastic\'s "{name}": TIDE no longer shows its updates for this rule.'
    db.record_rule_history(rule_id=key[0], siem_id=key[1], space=key[2], client_id=client_id, action="unlinked",
                           actor_user_id=user_id, actor_name=actor,
                           detail={"message": message, "upstream_id": row["upstream_id"]})
    from app.services import rule_issues
    rule_issues.refresh_tenant(db, client_id, rule_keys=[key])
    return 200, message


def get_bulk(conn, keys: Iterable[Key]) -> Dict[Key, Dict[str, Any]]:
    """Origin rows for the given rule keys (those that have one)."""
    keys = list({(str(r), str(s), str(sp)) for r, s, sp in keys})
    if not keys:
        return {}
    ensure(conn)
    # The keys go in as three arrays (as get_rule_links_bulk does), not one OR term per key.
    rows = _rows(conn.execute(
        "WITH k AS (SELECT unnest(?::VARCHAR[]) AS r, unnest(?::VARCHAR[]) AS s, unnest(?::VARCHAR[]) AS sp) "
        "SELECT o.* FROM rule_origins o JOIN k ON o.rule_id = k.r AND o.siem_id = k.s AND o.space = k.sp",
        [[k[0] for k in keys], [k[1] for k in keys], [k[2] for k in keys]],
    ))
    return {(r["rule_id"], r["siem_id"], r["space"]): r for r in rows}


def copies_of(conn, origin: str, upstream_id: str, siem_id: str, space: str) -> List[Dict[str, Any]]:
    """Rules in one destination that came from the same upstream rule."""
    ensure(conn)
    return _rows(conn.execute(
        "SELECT * FROM rule_origins WHERE origin = ? AND upstream_id = ? AND siem_id = ? AND space = ?",
        [origin, upstream_id, siem_id, space]))


def is_prebuilt(rule: Optional[Dict[str, Any]]) -> bool:
    """Whether Kibana installed the rule (as Kibana returns it) as one of Elastic's prebuilt rules:
    ``rule_source.type`` external since Elastic 8.16, ``immutable`` before."""
    rule = rule or {}
    return bool(rule.get("immutable") or (rule.get("rule_source") or {}).get("type") == "external")


def elastic_id_held(conn, rule: Optional[Dict[str, Any]], rule_id: str) -> Optional[str]:
    """The Elastic rule id the rule (as Kibana returns it) is held under, when it is one: it is a
    prebuilt rule, or a custom rule under the id of one of the Elastic rules built into TIDE. A copy
    of such a rule is made under a new rule id, so it never stops Kibana installing Elastic's rule."""
    held = str((rule or {}).get("rule_id") or rule_id or "")
    return held if held and (is_prebuilt(rule) or upstream(conn, "elastic", held)) else None


def holds_elastic_id(conn, client_id: str, key: Key, rule) -> bool:
    """Whether ``rule`` (TIDE's row at ``key``) is a custom rule under one of Elastic's rule ids, so it
    can be given its own (promotion.own_rule_id): not deprecated, not Elastic's prebuilt rule, and
    not already given one in Kibana with TIDE's part still to finish (pending_actions)."""
    from app.services import pending_actions
    raw = rule.raw_data or {}
    if rule.deprecated or is_prebuilt(raw):
        return False
    if any(e["kind"] == "own_rule_id" and not e.get("copy_id") for e in pending_actions.for_rule(client_id, key)):
        return False
    return bool(elastic_id_held(conn, raw, key[0]))


# ``is_prebuilt`` on detection_rules.raw_data.
PREBUILT_SQL = ("(COALESCE(TRY_CAST(json_extract_string(raw_data, '$.immutable') AS BOOLEAN), false) "
                "OR COALESCE(json_extract_string(raw_data, '$.rule_source.type') = 'external', false))")

# A rule's portable id and whether Kibana installed it as one of Elastic's prebuilt rules.
_SYNCED = f"""
    SELECT rule_id, siem_id, space,
           COALESCE(NULLIF(kibana_rule_id, ''), rule_id) AS portable,
           {PREBUILT_SQL} AS prebuilt,
           TRY_CAST(json_extract_string(raw_data, '$.version') AS INTEGER) AS installed_version
    FROM detection_rules
"""
_NO_ORIGIN = ("NOT EXISTS (SELECT 1 FROM rule_origins o WHERE o.rule_id = d.rule_id "
              "AND o.siem_id = d.siem_id AND o.space = d.space)")


def backfill(conn) -> int:
    """Record the origin of synced rules that have none yet, matched by their portable rule id:
    Elastic's prebuilt rules (by how Kibana installed them), copies under an Elastic or Sigma rule's
    own id. Their upstream revision is taken as the bundled one now (``first_seen``), except a copy
    that carries an older Elastic version than the bundled one (copied from an older prebuilt rule),
    which is known by that version. Needs the tenant DB's pooled connection (the reference DB
    attached). Returns how many were added."""
    ensure(conn)
    tables = {r[0] for r in conn.execute("SELECT table_name FROM duckdb_tables()").fetchall()}
    if "detection_rules" not in tables:
        return 0
    before = conn.execute("SELECT COUNT(*) FROM rule_origins").fetchone()[0]
    # A rule recorded as prebuilt that Kibana now holds as a custom rule (a copy TIDE made before
    # 6.2.2 kept its source's flag) is known by its version like any other copy.
    conn.execute(f"""
        UPDATE rule_origins o SET prebuilt = false FROM ({_SYNCED}) d
        WHERE o.rule_id = d.rule_id AND o.siem_id = d.siem_id AND o.space = d.space
          AND COALESCE(o.prebuilt, false) AND NOT d.prebuilt
    """)
    if "elastic_rules_index" in tables:
        conn.execute(f"""
            INSERT INTO rule_origins (rule_id, siem_id, space, origin, upstream_id, upstream_version,
                                      upstream_hash, upstream_date, prebuilt, recorded_how, recorded_by)
            SELECT d.rule_id, d.siem_id, d.space, 'elastic', d.portable,
                   CASE WHEN d.prebuilt OR d.installed_version < e.version THEN d.installed_version ELSE e.version END,
                   CASE WHEN d.prebuilt OR d.installed_version < e.version THEN NULL ELSE e.content_hash END,
                   CASE WHEN d.prebuilt OR d.installed_version < e.version THEN NULL ELSE e.updated END,
                   d.prebuilt, 'first_seen', 'TIDE'
            FROM ({_SYNCED}) d LEFT JOIN elastic_rules_index e ON e.rule_id = d.portable
            WHERE (d.prebuilt OR e.rule_id IS NOT NULL) AND {_NO_ORIGIN}
        """)
        # A copy of an Elastic rule taken as the bundled revision when first seen, though it carries
        # an older Elastic version (made from an older prebuilt rule): compare it by version.
        conn.execute(f"""
            UPDATE rule_origins o SET upstream_version = d.installed_version, upstream_hash = NULL,
                   upstream_date = NULL
            FROM ({_SYNCED}) d
            WHERE o.rule_id = d.rule_id AND o.siem_id = d.siem_id AND o.space = d.space
              AND o.origin = 'elastic' AND NOT COALESCE(o.prebuilt, false) AND o.recorded_how = 'first_seen'
              AND o.upstream_hash IS NOT NULL AND d.installed_version < o.upstream_version
        """)
    sigma_cols = {r[0] for r in conn.execute(
        "SELECT column_name FROM duckdb_columns() WHERE table_name = 'sigma_rules_index'").fetchall()}
    if "content_hash" in sigma_cols:
        conn.execute(f"""
            INSERT INTO rule_origins (rule_id, siem_id, space, origin, upstream_id, upstream_hash,
                                      upstream_date, prebuilt, recorded_how, recorded_by)
            SELECT d.rule_id, d.siem_id, d.space, 'sigma', s.rule_id, s.content_hash, s.modified,
                   false, 'first_seen', 'TIDE'
            FROM ({_SYNCED}) d JOIN sigma_rules_index s ON s.rule_id = d.portable
            WHERE {_NO_ORIGIN}
        """)
        # Rules converted from Sigma before TIDE recorded origins: Kibana gave them ids of their
        # own, so they are known by the Sigma title they kept, with Sigma's ATT&CK tags. Which
        # revision they were made from is not known, only when they were made (upstream_date).
        conn.execute(f"""
            INSERT INTO rule_origins (rule_id, siem_id, space, origin, upstream_id, upstream_date,
                                      prebuilt, recorded_how, recorded_by)
            SELECT d.rule_id, d.siem_id, d.space, 'sigma', s.rule_id,
                   TRY_CAST(left(json_extract_string(d.raw_data, '$.created_at'), 10) AS DATE),
                   false, 'matched', 'TIDE'
            FROM detection_rules d
            JOIN (SELECT rule_id, title FROM sigma_rules_index
                  QUALIFY count(*) OVER (PARTITION BY lower(trim(title))) = 1) s
              ON lower(trim(s.title)) = lower(trim(d.name))
            WHERE json_extract_string(d.raw_data, '$.tags') ILIKE '%"attack.%' AND {_NO_ORIGIN}
        """)
    return conn.execute("SELECT COUNT(*) FROM rule_origins").fetchone()[0] - before


# ── Is there a newer upstream version? ─────────────────────────────────────────────────────────

# State -> its label, shown after the source ("Elastic · Deprecated"). "own" (no origin) is a
# filter choice only.
STATES = {
    "update": "Update available",
    "current": "Up to date",
    "retired": "Deprecated",
    "removed": "No longer in TIDE",
}
# Rule Health's Upstream filter: an update or a deprecation names its source (filter_value).
FILTER_STATES = (("update_elastic", "Elastic update available"), ("update_sigma", "Sigma update available"),
                 ("current", "Up to date"), ("retired_elastic", "Deprecated by Elastic"),
                 ("retired_sigma", "Deprecated by Sigma"), ("removed", "No longer in TIDE's Elastic or Sigma rules"),
                 ("own", "Your own rules"))
# Values saved in links and dashboards before the filter named the source (6.2.2).
_LEGACY_FILTER = {"update": ("update_elastic", "update_sigma"), "retired": ("retired_elastic", "retired_sigma")}


def filter_value(status: Optional[Dict[str, Any]]) -> str:
    """The Upstream filter's value for a rule's upstream status (``statuses``); "own" for none."""
    if not status:
        return "own"
    return f"{status['state']}_{status['origin']}" if status["state"] in ("update", "retired") else status["state"]


def filter_values(values: Iterable[str]) -> List[str]:
    """The Upstream filter's chosen values, with any saved before 6.2.2 read as their new ones."""
    out: List[str] = []
    for value in values:
        for v in _LEGACY_FILTER.get(value, (value,)):
            if v and v not in out:
                out.append(v)
    return out

_STATUS_SQL = """
    SELECT o.rule_id, o.siem_id, o.space, o.origin, o.upstream_id, o.upstream_version, o.upstream_hash,
           o.upstream_date, o.prebuilt, o.parent_rule_id, o.parent_siem_id, o.parent_space,
           o.recorded_how, o.recorded_by, o.recorded_at,
           TRY_CAST(json_extract_string(d.raw_data, '$.version') AS INTEGER) AS installed_version,
           e.version AS e_version, e.stack_versions AS e_stacks, e.content_hash AS e_hash,
           e.status AS e_status, e.name AS e_name,
           e.updated AS e_date, s.content_hash AS s_hash, s.status AS s_status, s.title AS s_name,
           s.modified AS s_date
    FROM (SELECT * FROM rule_origins WHERE origin IN ('elastic', 'sigma')) o
    LEFT JOIN detection_rules d ON d.rule_id = o.rule_id AND d.siem_id = o.siem_id AND d.space = o.space
    LEFT JOIN elastic_rules_index e ON o.origin = 'elastic' AND e.rule_id = o.upstream_id
    LEFT JOIN sigma_rules_index s ON o.origin = 'sigma' AND s.rule_id = o.upstream_id
"""


def _siem_versions(conn) -> Dict[str, str]:
    """The Elastic version each SIEM ran when last synced (``DatabaseService.record_siem_version``)."""
    try:
        return dict(conn.execute("SELECT siem_id, version FROM siem_versions").fetchall())
    except Exception:
        return {}


def _status(row: Dict[str, Any], running: Optional[str] = None) -> Dict[str, Any]:
    """One origin row's upstream status: its state against the bundled rule, and what to say.
    ``running`` is the Elastic version of the rule's SIEM: Elastic numbers some rules differently
    for newer Elastic versions."""
    from app.services.elastic_rules import version_for

    elastic = row["origin"] == "elastic"
    source = "Elastic" if elastic else "Sigma"
    name = row["e_name"] if elastic else row["s_name"]
    to_version = version_for(row["e_version"], row.get("e_stacks"), running) if elastic else None
    # A prebuilt rule is known by the version Kibana installed, or the one reviewed in TIDE since
    # (sections taken into it leave Kibana's version number as it was).
    from_version = (max(row["installed_version"] or 0, row["upstream_version"] or 0) or None) if row["prebuilt"] \
        else row["upstream_version"]
    to_date = row["e_date"] if elastic else row["s_date"]
    if name is None:
        state = "removed"
        title = f"The {source} rule it came from is not in the {source} rules built into this TIDE."
    elif (row["e_status"] if elastic else row["s_status"]) == "deprecated":
        state = "retired"
        title = f'{source} has deprecated "{name}".'
    elif row["prebuilt"]:
        state = "update" if (from_version or 0) < (to_version or 0) else "current"
        installed = row["installed_version"]
        if state == "update":
            title = (f"Elastic's version {to_version} is newer than the installed {installed}. Review update takes "
                     "the sections you choose into it; Kibana also offers its own update (Rules → Rule updates) "
                     "once it has Elastic's newer rules.")
        elif installed and from_version and installed < from_version and row["recorded_how"] == "unchanged":
            title = (f"Elastic's version {from_version} changes nothing TIDE compares, so there is nothing to "
                     f"review; Kibana still has version {installed} installed.")
        elif installed and from_version and installed < from_version:
            title = (f"Reviewed against Elastic's version {from_version} in TIDE; Kibana still has version "
                     f"{installed} installed.")
        else:
            title = f"Elastic's version {to_version} is installed, the latest built into TIDE."
    else:
        current_hash = row["e_hash"] if elastic else row["s_hash"]
        if row["upstream_hash"]:
            state = "update" if current_hash != row["upstream_hash"] else "current"
        elif elastic:   # known only by the Elastic version it carries (a copy of an older prebuilt rule)
            state = "update" if (from_version or 0) < (to_version or 0) else "current"
        else:   # matched by its Sigma title, known only by when it was made
            state = "update" if to_date and row["upstream_date"] and to_date > row["upstream_date"] else "current"
        if state == "update":
            change = (f"version {from_version} → {to_version}" if elastic and from_version and to_version
                      and from_version != to_version else f"changed {to_date}" if to_date else "changed")
            title = f'{source} updated "{name}" since it was taken: {change}.'
        else:   # the upstream rule is unchanged, not this one: rule_updates.unconfirmed_links compares them
            title = f'{source} hasn\'t changed "{name}" since it was taken' + (f" (version {to_version})." if to_version else ".")
    return {
        "state": state, "label": STATES[state], "title": title, "source": source, "origin": row["origin"],
        "upstream_id": row["upstream_id"], "name": name, "prebuilt": bool(row["prebuilt"]),
        "from_version": from_version, "to_version": to_version, "installed_version": row["installed_version"],
        "from_date": row["upstream_date"], "to_date": to_date,
        "parent": ((row["parent_rule_id"], row["parent_siem_id"], row["parent_space"])
                   if row["parent_rule_id"] else None),
        "recorded_how": row["recorded_how"], "recorded_by": row["recorded_by"], "recorded_at": row["recorded_at"],
    }


def statuses(conn, keys: Optional[Iterable[Key]] = None) -> Dict[Key, Dict[str, Any]]:
    """The upstream status of each rule with an origin (of ``keys``, or all). Empty when the
    reference DB cannot answer (an image built before the indexes)."""
    ensure(conn)
    sql, params = _STATUS_SQL, []
    if keys is not None:
        keys = list({(str(r), str(s), str(sp)) for r, s, sp in keys})
        if not keys:
            return {}
        sql = ("WITH k AS (SELECT unnest(?::VARCHAR[]) AS r, unnest(?::VARCHAR[]) AS s, unnest(?::VARCHAR[]) AS sp) "
               + sql + " JOIN k ON o.rule_id = k.r AND o.siem_id = k.s AND o.space = k.sp")
        params = [[k[0] for k in keys], [k[1] for k in keys], [k[2] for k in keys]]
    try:
        rows = _rows(conn.execute(sql, params))
    except Exception as exc:
        logger.warning("Upstream status unavailable: %s", exc)
        return {}
    running = _siem_versions(conn)
    return {(r["rule_id"], r["siem_id"], r["space"]): _status(r, running.get(r["siem_id"])) for r in rows}


def deployments(conn, upstream_id: str, origin: str = "elastic") -> List[Dict[str, Any]]:
    """Where the tenant has the Elastic or Sigma rule ``upstream_id`` now: copies recorded as made
    from it (for Elastic, Kibana's prebuilt install too), and any rule still carrying its id. Each
    row is a ``detection_rules`` key with its name, whether it is enabled and its upstream
    ``status``. Rules not found at the last sync are left out."""
    ensure(conn)
    try:
        rows = _rows(conn.execute("""
            SELECT d.rule_id, d.siem_id, d.space, d.name, COALESCE(d.enabled, 0) = 1 AS enabled
            FROM detection_rules d
            LEFT JOIN rule_origins o ON o.rule_id = d.rule_id AND o.siem_id = d.siem_id AND o.space = d.space
            WHERE NOT COALESCE(d.deprecated, false)
              AND ((o.origin = ? AND o.upstream_id = ?)
                   OR (o.rule_id IS NULL AND COALESCE(NULLIF(d.kibana_rule_id, ''), d.rule_id) = ?))
            ORDER BY d.space, d.name
        """, [origin, upstream_id, upstream_id]))
    except Exception as exc:      # a tenant that has never synced has no detection_rules
        logger.debug("No deployments of %s: %s", upstream_id, exc)
        return []
    found = statuses(conn, [(r["rule_id"], r["siem_id"], r["space"]) for r in rows])
    for row in rows:
        row["status"] = found.get((row["rule_id"], row["siem_id"], row["space"]))
    return rows


def deployed_for_client(db, client_id: str, origin: str, upstream_id: str) -> List[Dict[str, Any]]:
    """``deployments`` in the active tenant, each named by its destination (``destination``), for a
    library page's In your SIEMs. Never raises: the rule is still worth reading."""
    try:
        with db.get_connection() as conn:
            rows = deployments(conn, upstream_id, origin)
        names = {(s["id"], str(s.get("space") or "default")): s.get("name") or s.get("space")
                 for s in db.get_client_siems(client_id) or []}
    except Exception:
        logger.exception("Could not find where %s rule %s is deployed", origin, upstream_id)
        return []
    for row in rows:
        row["destination"] = names.get((row["siem_id"], row["space"]), row["space"])
    return rows


def record_for_client(db, client_id: str, key: Key, origin: str, upstream_id: str, how: str,
                      actor: str = "", **kwargs) -> bool:
    """``record`` on one tenant's DB, only when ``upstream_id`` is a bundled rule (a Sigma rule
    pasted with an id of its own is the tenant's). Never raises: the deploy already happened."""
    from app.services.tenant_manager import tenant_context_for
    if not upstream_id:
        return False
    try:
        with tenant_context_for(client_id):
            with db.get_connection() as conn:
                if not upstream(conn, origin, upstream_id):
                    return False
                record(conn, key, origin, upstream_id, how, actor, **kwargs)
                return True
    except Exception:
        logger.exception("Could not record the origin of %s", key)
        return False


def backfill_tenant(db, client_id: str, keys: Optional[Iterable[Key]] = None) -> int:
    """``backfill`` on one tenant's DB, then ``rule_updates.settle_unchanged`` (of ``keys``, or
    all), so a sync never flags an Elastic update that changes nothing. Returns how many origins
    were added; never raises (a sync must not fail over it)."""
    from app.services import rule_updates, sync_runs
    from app.services.tenant_manager import tenant_context_for
    try:
        with tenant_context_for(client_id):
            with db.get_connection() as conn:
                added = backfill(conn)
                try:
                    rule_updates.settle_unchanged(conn, keys)
                except Exception as exc:
                    logger.exception("Settling unchanged Elastic updates failed for client %s", client_id)
                    sync_runs.step_failed("Elastic updates check", exc)
                return added
    except Exception as exc:
        logger.exception("Rule origin backfill failed for client %s", client_id)
        sync_runs.step_failed("Rule origins", exc)
        return 0
