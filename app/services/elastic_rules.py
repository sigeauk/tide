"""Elastic's detection rules and hunting queries, bundled in the TIDE image like the SigmaHQ rules.

The image holds a sparse copy of github.com/elastic/detection-rules (main) at ``/opt/repos/elastic``:
``rules/`` (with ``_deprecated/``), ``rules_building_block/``, ``hunting/``, and the version lock and
deprecation list from ``detection_rules/etc``. ``build_index(conn)`` reads them into
``elastic_rules_index`` and ``elastic_hunts_index`` when the reference DB is built; everything else
here reads those two tables (attached read-only as ``ref`` on every pooled connection).

Hunting queries are kept for searching and reading only; they are not detection rules.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tomllib
from datetime import date, datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from app.config import get_settings

logger = logging.getLogger(__name__)

RULE_DIRS = ("rules", "rules_building_block")
HUNTING_DIR = "hunting"
LOCK_FILE = os.path.join("detection_rules", "etc", "version.lock.json")
DEPRECATED_FILE = os.path.join("detection_rules", "etc", "deprecated_rules.json")
COMMIT_FILE = ".tide-commit"

# (value, label) for the Status filter and pill, in list order.
STATUSES = (("production", "Production"), ("building_block", "Building block"), ("deprecated", "Deprecated"))
SEVERITIES = ("critical", "high", "medium", "low")

RULES_DDL = """
    CREATE TABLE IF NOT EXISTS elastic_rules_index (
        rule_id            VARCHAR PRIMARY KEY,
        name               VARCHAR,
        description        VARCHAR,
        rule_type          VARCHAR,
        language           VARCHAR,
        severity           VARCHAR,
        risk_score         INTEGER,
        status             VARCHAR,
        platform           VARCHAR,
        integrations       VARCHAR[],
        techniques         VARCHAR[],
        tactics            VARCHAR[],
        tags               VARCHAR[],
        version            INTEGER,
        stack_versions     JSON,
        stack_changes      JSON,
        min_stack_version  VARCHAR,
        created            DATE,
        updated            DATE,
        deprecated_on      DATE,
        deprecated_reason  VARCHAR,
        content_hash       VARCHAR,
        file_path          VARCHAR,
        rule_json          JSON,
        metadata_json      JSON,
        indexed_at         TIMESTAMP
    )
"""

HUNTS_DDL = """
    CREATE TABLE IF NOT EXISTS elastic_hunts_index (
        hunt_id       VARCHAR PRIMARY KEY,
        name          VARCHAR,
        description   VARCHAR,
        platform      VARCHAR,
        integrations  VARCHAR[],
        languages     VARCHAR[],
        techniques    VARCHAR[],
        notes         VARCHAR[],
        queries       VARCHAR[],
        refs          VARCHAR[],
        author        VARCHAR,
        license       VARCHAR,
        content_hash  VARCHAR,
        file_path     VARCHAR,
        indexed_at    TIMESTAMP
    )
"""

_RULE_COLS = ("rule_id", "name", "description", "rule_type", "language", "severity", "risk_score",
              "status", "platform", "integrations", "techniques", "tactics", "tags", "version",
              "stack_versions", "stack_changes", "min_stack_version", "created", "updated", "deprecated_on",
              "deprecated_reason", "content_hash", "file_path", "rule_json", "metadata_json", "indexed_at")
_HUNT_COLS = ("hunt_id", "name", "description", "platform", "integrations", "languages", "techniques",
              "notes", "queries", "refs", "author", "license", "content_hash", "file_path", "indexed_at")
_LIST_COLS = {"integrations", "techniques", "tactics", "tags", "languages", "notes", "queries", "refs"}
_JSON_COLS = {"stack_versions", "stack_changes", "rule_json", "metadata_json"}


def repo_path() -> str:
    return get_settings().elastic_rules_repo_path


def available(root: Optional[str] = None) -> bool:
    return os.path.isdir(os.path.join(root or repo_path(), "rules"))


def toml_files(root: str, sub: str):
    for dirpath, _dirs, files in os.walk(os.path.join(root, sub)):
        for name in sorted(files):
            if name.endswith(".toml"):
                yield os.path.join(dirpath, name)


def source_digest(root: str) -> str:
    """Fingerprint of the bundled files: their count, total size and newest change."""
    count = size = newest = 0
    paths = [p for sub in RULE_DIRS + (HUNTING_DIR,) for p in toml_files(root, sub)]
    paths += [os.path.join(root, rel) for rel in (LOCK_FILE, DEPRECATED_FILE, COMMIT_FILE)]
    for path in paths:
        if os.path.isfile(path):
            st = os.stat(path)
            count += 1
            size += st.st_size
            newest = max(newest, st.st_mtime_ns)
    return hashlib.sha256(f"{count}:{size}:{newest}".encode("ascii")).hexdigest()


def commit(root: Optional[str] = None) -> Dict[str, str]:
    """The detection-rules commit bundled in the image: ``{"sha", "date"}`` (date YYYY-MM-DD), or blanks."""
    try:
        with open(os.path.join(root or repo_path(), COMMIT_FILE), encoding="utf-8") as fh:
            sha, _, when = fh.read().strip().partition(" ")
        return {"sha": sha, "date": when[:10]}
    except OSError:
        return {"sha": "", "date": ""}


def _load_json(path: str) -> Dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        logger.warning("Elastic rules: could not read %s: %s", path, exc)
        return {}


def _date(value: Any) -> Optional[date]:
    """detection-rules dates are ``YYYY/MM/DD``."""
    try:
        return datetime.strptime(str(value), "%Y/%m/%d").date()
    except (TypeError, ValueError):
        return None


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v not in (None, "")]
    return [str(value)]


def attack_ids(threat: Any) -> Tuple[List[str], List[str]]:
    """``(technique ids, tactic names)`` from a rule's ATT&CK ``threat`` list."""
    from app.attack_tactics import NAME_BY_ID

    techniques: List[str] = []
    tactics: List[str] = []
    for entry in threat if isinstance(threat, list) else []:
        if not isinstance(entry, dict) or entry.get("framework", "MITRE ATT&CK") != "MITRE ATT&CK":
            continue
        tactic = entry.get("tactic") or {}
        name = NAME_BY_ID.get(str(tactic.get("id") or ""), tactic.get("name"))
        if name and name not in tactics:
            tactics.append(name)
        for tech in entry.get("technique") or []:
            ids = [tech.get("id")] + [sub.get("id") for sub in tech.get("subtechnique") or []]
            for tid in ids:
                if tid and tid not in techniques:
                    techniques.append(str(tid))
    return techniques, tactics


def _platform(parts: List[str], rule: Dict[str, Any], integrations: List[str]) -> str:
    """Where a rule belongs: its folder under ``rules/`` (the integration's, under
    ``integrations/``), or, for building blocks and deprecated rules, its OS tag or first integration."""
    if parts[0] == "rules" and len(parts) > 1 and parts[1] != "_deprecated":
        return parts[2] if parts[1] == "integrations" and len(parts) > 2 else parts[1]
    for tag in rule.get("tags") or []:
        if str(tag).startswith("OS: "):
            return str(tag)[4:].strip().lower()
    return integrations[0] if integrations else "other"


def content_hash(rule: Dict[str, Any]) -> str:
    """A rule's fingerprint: changes whenever anything in its ``[rule]`` table does."""
    return hashlib.sha256(json.dumps(rule, sort_keys=True, default=str).encode("utf-8")).hexdigest()


# Fields whose line breaks and indentation are part of the value; Elastic's packaging leaves them be.
_KEEP_WHITESPACE = {"query", "threat_query", "note", "setup"}
_PLACEHOLDER = re.compile(r"\$(osquery|investigate)_(\d+)\b")
_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")


def _unwrap(text: str) -> str:
    """A TOML string as Elastic's packaging gives it to Kibana: its wrapped lines joined into one."""
    return " ".join(line.strip() for line in text.strip().splitlines())


def _setup_from_note(body: Dict[str, Any]) -> None:
    """Older rules keep their setup steps under a ``## Setup`` heading in the investigation guide;
    Elastic's packaging moves them into ``setup`` (up to the next heading)."""
    note = body.get("note") or ""
    if body.get("setup") or not note:
        return
    lines = note.splitlines()
    for idx, line in enumerate(lines):
        match = _HEADING.match(line)
        if not match or "Setup" not in match.group(2):
            continue
        steps = []
        for nxt in lines[idx + 1:]:
            heading = _HEADING.match(nxt)
            if heading and len(heading.group(1)) >= 2:
                break
            steps.append(nxt)
        setup = "\n".join(steps).strip()
        if setup:
            body["setup"] = setup
            body["note"] = note.replace("## Setup\n\n", "").replace(setup, "").strip()
        return


def _fill_placeholders(text: str, transform: Dict[str, Any]) -> str:
    """``$osquery_0`` / ``$investigate_0`` in a guide, filled from the rule's ``[transform]`` table as
    Elastic's packaging does (the Osquery and Timeline buttons Kibana shows in the guide)."""
    def plugin(match):
        entries = transform.get(match.group(1)) or []
        idx = int(match.group(2))
        if idx >= len(entries):
            return match.group(0)
        return f"!{{{match.group(1)}{json.dumps(entries[idx], sort_keys=True, separators=(',', ':'))}}}"
    return _PLACEHOLDER.sub(plugin, text)


def packaged(doc: Dict[str, Any]) -> Dict[str, Any]:
    """A rule TOML's ``[rule]`` table as Elastic packages it for Kibana's prebuilt rules: wrapped
    text joined, an old-style setup section moved out of the guide, and the guide's placeholders
    filled. What TIDE shows, deploys and compares a deployed rule with."""
    import copy

    body = copy.deepcopy(doc.get("rule") or {})
    for key, value in body.items():
        if key in _KEEP_WHITESPACE:
            continue
        if isinstance(value, str):
            body[key] = _unwrap(value)
        elif isinstance(value, list) and all(isinstance(v, str) for v in value):
            body[key] = [_unwrap(v) for v in value]
    _setup_from_note(body)
    transform = doc.get("transform") or {}
    if transform and body.get("note"):
        body["note"] = _fill_placeholders(body["note"], transform)
    return body


def _parse_rule(root: str, path: str, lock: Dict[str, Any], deprecated: Dict[str, Any], now: datetime):
    with open(path, "rb") as fh:
        doc = tomllib.load(fh)
    rule = doc.get("rule") or {}
    meta = doc.get("metadata") or {}
    body = packaged(doc)
    rule_id = str(rule.get("rule_id") or "")
    if not rule_id:
        return None
    rel = os.path.relpath(path, root).replace(os.sep, "/")
    integrations = _as_list(meta.get("integration"))
    techniques, tactics = attack_ids(rule.get("threat"))
    locked = lock.get(rule_id) or {}
    retired = deprecated.get(rule_id) or {}
    if meta.get("maturity") == "deprecated":
        status = "deprecated"
    elif rule.get("building_block_type"):
        status = "building_block"
    else:
        status = "production"
    # Elastic builds some rules again for newer Elastic versions, under another version number
    # (version.lock.json's stack_emit): which version, and what that build changes.
    stack_versions = {stack: v.get("version") for stack, v in (locked.get("stack_emit") or {}).items()}
    stack_changes = {stack: list(v.get("transforms") or []) for stack, v in (locked.get("stack_emit") or {}).items()}
    return {
        "rule_id": rule_id,
        "name": str(rule.get("name") or ""),
        "description": str(body.get("description") or "").strip(),
        "rule_type": str(rule.get("type") or ""),
        "language": rule.get("language") or ("machine learning" if rule.get("type") == "machine_learning" else ""),
        "severity": str(rule.get("severity") or "").lower(),
        "risk_score": rule.get("risk_score"),
        "status": status,
        "platform": _platform(rel.split("/")[:-1], rule, integrations),
        "integrations": integrations,
        "techniques": techniques,
        "tactics": tactics,
        "tags": _as_list(rule.get("tags")),
        "version": locked.get("version"),
        "stack_versions": json.dumps(stack_versions),
        "stack_changes": json.dumps(stack_changes),
        "min_stack_version": meta.get("min_stack_version"),
        "created": _date(meta.get("creation_date")),
        "updated": _date(meta.get("updated_date")),
        "deprecated_on": _date(meta.get("deprecation_date") or retired.get("deprecation_date")),
        "deprecated_reason": meta.get("deprecated_reason") or retired.get("deprecated_reason"),
        # Fingerprinted as Elastic wrote it; kept as Elastic packages it for Kibana.
        "content_hash": content_hash(rule),
        "file_path": rel,
        "rule_json": json.dumps(body, default=str),
        "metadata_json": json.dumps(meta, default=str),
        "indexed_at": now,
    }


def _parse_hunt(root: str, path: str, now: datetime):
    with open(path, "rb") as fh:
        hunt = (tomllib.load(fh) or {}).get("hunt") or {}
    hunt_id = str(hunt.get("uuid") or "")
    if not hunt_id:
        return None
    rel = os.path.relpath(path, root).replace(os.sep, "/")
    parts = rel.split("/")
    return {
        "hunt_id": hunt_id,
        "name": str(hunt.get("name") or ""),
        "description": str(hunt.get("description") or "").strip(),
        "platform": parts[1] if len(parts) > 2 else "other",
        "integrations": _as_list(hunt.get("integration")),
        "languages": _as_list(hunt.get("language")),
        "techniques": _as_list(hunt.get("mitre")),
        "notes": _as_list(hunt.get("notes")),
        "queries": [q.strip() for q in _as_list(hunt.get("query"))],
        "refs": _as_list(hunt.get("references")),
        "author": ", ".join(_as_list(hunt.get("author"))),
        "license": str(hunt.get("license") or ""),
        "content_hash": content_hash(hunt),
        "file_path": rel,
        "indexed_at": now,
    }


def _load(conn, table: str, cols: Tuple[str, ...], rows: List[Dict[str, Any]]) -> None:
    import pandas as pd

    conn.execute(f"DELETE FROM {table}")
    if not rows:
        return
    # dtype=object keeps None as NULL (a float column would turn a missing version into NaN).
    frame = pd.DataFrame([[r[c] for c in cols] for r in rows], columns=list(cols), dtype=object)
    select = ", ".join(
        f"CAST({c} AS VARCHAR[])" if c in _LIST_COLS else f"CAST({c} AS JSON)" if c in _JSON_COLS else c
        for c in cols
    )
    conn.register(f"{table}_src", frame)
    try:
        conn.execute(f"INSERT INTO {table} ({', '.join(cols)}) SELECT {select} FROM {table}_src")
    finally:
        conn.unregister(f"{table}_src")


def build_index(conn, root: Optional[str] = None) -> Dict[str, int]:
    """Fill ``elastic_rules_index`` and ``elastic_hunts_index`` on *conn* (the reference DB being
    built) from the bundled repository. Returns ``{"rules": n, "hunts": n, "errors": n}``; a file that
    cannot be parsed is logged and skipped."""
    root = root or repo_path()
    conn.execute(RULES_DDL)
    conn.execute(HUNTS_DDL)
    lock = _load_json(os.path.join(root, LOCK_FILE))
    deprecated = _load_json(os.path.join(root, DEPRECATED_FILE))
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    rules: Dict[str, Dict[str, Any]] = {}
    hunts: Dict[str, Dict[str, Any]] = {}
    errors = 0
    for sub in RULE_DIRS:
        for path in toml_files(root, sub):
            try:
                row = _parse_rule(root, path, lock, deprecated, now)
            except Exception as exc:
                errors += 1
                logger.warning("Elastic rules: skipped %s: %s", path, exc)
                continue
            if row:
                rules[row["rule_id"]] = row
    for path in toml_files(root, HUNTING_DIR):
        try:
            row = _parse_hunt(root, path, now)
        except Exception as exc:
            errors += 1
            logger.warning("Elastic hunting: skipped %s: %s", path, exc)
            continue
        if row:
            hunts[row["hunt_id"]] = row
    _load(conn, "elastic_rules_index", _RULE_COLS, list(rules.values()))
    _load(conn, "elastic_hunts_index", _HUNT_COLS, list(hunts.values()))
    logger.info("Elastic rules: indexed %d rules and %d hunting queries (%d skipped)",
                len(rules), len(hunts), errors)
    return {"rules": len(rules), "hunts": len(hunts), "errors": errors}


# ── Reading the index ──────────────────────────────────────────────────────────────────────────

def technique_clause(column: str, technique: str, params: List[Any]) -> str:
    """Matches technique ids that start with what was typed: ``T10`` finds T1003, T1059 and
    T1078; ``T1059`` finds T1059 and its sub-techniques; the T may be left out."""
    import re

    tid = re.sub(r"[^A-Z0-9.]", "", technique.strip().upper())
    if tid and tid[0].isdigit():
        tid = "T" + tid
    params.append(f"%,{tid}%")
    return f"((',' || array_to_string({column}, ',')) LIKE ?)"


def rows_as_dicts(cursor) -> List[Dict[str, Any]]:
    cols = [d[0] for d in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


_STATUS_ORDER = "CASE status WHEN 'production' THEN 0 WHEN 'building_block' THEN 1 ELSE 2 END"


def search_rules(conn, q: str = "", technique: str = "", platform: str = "", integration: str = "",
                 rule_type: str = "", severity: str = "", status: str = "",
                 limit: int = 200, deployable: bool = False, offset: int = 0) -> Tuple[List[Dict[str, Any]], int]:
    """Rules matching every given filter, production first then by name (``limit`` of them from
    ``offset`` on), and how many match. ``deployable`` leaves out deprecated rules (suggestions)."""
    where: List[str] = ["status <> 'deprecated'"] if deployable else []
    params: List[Any] = []
    if q.strip():
        like = f"%{q.strip()}%"
        where.append("(name ILIKE ? OR description ILIKE ? OR rule_id ILIKE ? "
                     "OR array_to_string(tags, ' ') ILIKE ? OR array_to_string(techniques, ' ') ILIKE ?)")
        params += [like] * 5
    if technique.strip():
        where.append(technique_clause("techniques", technique, params))
    for column, value in (("platform", platform), ("rule_type", rule_type), ("severity", severity),
                          ("status", status)):
        if value:
            where.append(f"{column} = ?")
            params.append(value)
    if integration:
        where.append("list_contains(integrations, ?)")
        params.append(integration)
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM elastic_rules_index {clause}", params).fetchone()[0]
    rows = rows_as_dicts(conn.execute(
        f"SELECT rule_id, name, description, severity, rule_type, status, platform, techniques "
        f"FROM elastic_rules_index {clause} ORDER BY {_STATUS_ORDER}, lower(name), rule_id LIMIT ? OFFSET ?",
        params + [int(limit), max(0, int(offset))],
    ))
    return rows, total


def rule_facets(conn) -> Dict[str, Any]:
    """The values each list filter offers, and the overall counts."""
    def distinct(sql: str) -> List[str]:
        return [r[0] for r in conn.execute(sql).fetchall() if r[0]]

    return {
        "platforms": distinct("SELECT DISTINCT platform FROM elastic_rules_index ORDER BY 1"),
        "integrations": distinct(
            "SELECT DISTINCT unnest(integrations) AS i FROM elastic_rules_index ORDER BY 1"),
        "types": distinct("SELECT DISTINCT rule_type FROM elastic_rules_index ORDER BY 1"),
        "rule_count": conn.execute("SELECT COUNT(*) FROM elastic_rules_index").fetchone()[0],
        "hunt_count": conn.execute("SELECT COUNT(*) FROM elastic_hunts_index").fetchone()[0],
    }


def _decode(row: Dict[str, Any], *json_cols: str) -> Dict[str, Any]:
    for col in json_cols:
        value = row.get(col)
        if isinstance(value, str):
            try:
                row[col] = json.loads(value)
            except ValueError:
                row[col] = {}
    return row


def get_rule(conn, rule_id: str) -> Optional[Dict[str, Any]]:
    """One rule with its ``rule_json`` / ``metadata_json`` / ``stack_versions`` / ``stack_changes`` decoded."""
    return get_rules(conn, [rule_id]).get(rule_id)


def get_rules(conn, rule_ids: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    """``get_rule`` for many rules in one query (each is a scan of the index): ``{rule_id: rule}``."""
    ids = sorted({str(r) for r in rule_ids if r})
    if not ids:
        return {}
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows_as_dicts(conn.execute(
            "SELECT * FROM elastic_rules_index WHERE rule_id IN (SELECT unnest(?::VARCHAR[]))", [ids])):
        out.setdefault(row["rule_id"], _decode(row, "rule_json", "metadata_json", "stack_versions", "stack_changes"))
    return out


def search_hunts(conn, q: str = "", technique: str = "", platform: str = "",
                 limit: int = 200) -> Tuple[List[Dict[str, Any]], int]:
    where: List[str] = []
    params: List[Any] = []
    if q.strip():
        like = f"%{q.strip()}%"
        where.append("(name ILIKE ? OR description ILIKE ? OR hunt_id ILIKE ? "
                     "OR array_to_string(queries, ' ') ILIKE ? OR array_to_string(techniques, ' ') ILIKE ?)")
        params += [like] * 5
    if technique.strip():
        where.append(technique_clause("techniques", technique, params))
    if platform:
        where.append("platform = ?")
        params.append(platform)
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM elastic_hunts_index {clause}", params).fetchone()[0]
    rows = rows_as_dicts(conn.execute(
        f"SELECT hunt_id, name, platform, languages, techniques FROM elastic_hunts_index {clause} "
        f"ORDER BY lower(name) LIMIT ?",
        params + [int(limit)],
    ))
    return rows, total


def hunt_platforms(conn) -> List[str]:
    return [r[0] for r in conn.execute(
        "SELECT DISTINCT platform FROM elastic_hunts_index ORDER BY 1").fetchall() if r[0]]


def get_hunt(conn, hunt_id: str) -> Optional[Dict[str, Any]]:
    rows = rows_as_dicts(conn.execute("SELECT * FROM elastic_hunts_index WHERE hunt_id = ?", [hunt_id]))
    return rows[0] if rows else None


def source_text(file_path: str) -> str:
    """The TOML a rule or hunting query was read from, or '' if it is not in this image."""
    root = os.path.realpath(repo_path())
    path = os.path.realpath(os.path.join(root, file_path or ""))
    if not file_path or not path.startswith(root + os.sep) or not path.endswith(".toml"):
        return ""
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


# Tables only detection-rules' own TOML has (its build turns them into API fields or drops them).
_TOML_ONLY = ("threat_mappings",)


def kibana_payload(rule: Dict[str, Any], rule_id: str, enabled: bool) -> Dict[str, Any]:
    """The Kibana create payload for an indexed rule (``get_rule``), under ``rule_id``."""
    import copy

    body = copy.deepcopy(rule.get("rule_json") or {})
    for key in _TOML_ONLY:
        body.pop(key, None)
    new_terms = body.pop("new_terms", None)
    if isinstance(new_terms, dict):
        # [rule.new_terms] holds the API's new_terms_fields and history_window_start
        body["new_terms_fields"] = list(new_terms.get("value") or [])
        window = (new_terms.get("history_window_start") or [{}])[0] or {}
        if window.get("value"):
            body["history_window_start"] = window["value"]
    body["rule_id"] = rule_id
    body["enabled"] = bool(enabled)
    if rule.get("version"):
        body["version"] = int(rule["version"])
    return body


def version_tuple(version: Any) -> Tuple[int, ...]:
    """``"8.19.11"`` -> ``(8, 19, 11)``; anything unreadable -> ``()``."""
    parts = []
    for part in str(version or "").split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


def version_for(rule_version: Optional[int], stack_versions: Any, running: Optional[str]) -> Optional[int]:
    """The version Elastic ships a rule as on Elastic ``running`` ("9.5.1"): the one it builds for
    the newest Elastic version at or below it (``stack_versions``, ``{"9.5": 418}``), else the rule's
    own ``rule_version``, which is also the answer when ``running`` is unknown."""
    if isinstance(stack_versions, str):
        try:
            stack_versions = json.loads(stack_versions)
        except ValueError:
            stack_versions = {}
    run = version_tuple(running)
    best = None
    for stack, version in (stack_versions or {}).items():
        built_for = version_tuple(stack)
        if run and built_for and built_for <= run and version is not None and (best is None or built_for > best[0]):
            best = (built_for, int(version))
    return best[1] if best else rule_version


# What Elastic's build for a newer Elastic version changes (version.lock.json transform names).
_STACK_CHANGES = {
    "mitre_attack_v19": "its ATT&CK techniques mapped to ATT&CK v19",
    "related_integrations_gte": "its integrations' versions given as minimums",
}


def stack_builds(rule: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Elastic's builds of ``rule`` (a ``get_rule`` row) for newer Elastic versions, oldest first:
    ``{stack, version, changes}`` with ``changes`` in words."""
    changes = rule.get("stack_changes") or {}
    builds = []
    for stack, version in sorted((rule.get("stack_versions") or {}).items(), key=lambda kv: version_tuple(kv[0])):
        if version is None:
            continue
        builds.append({"stack": stack, "version": version,
                       "changes": [_STACK_CHANGES.get(t, t.replace("_", " ")) for t in changes.get(stack) or []]})
    return builds


def index_ready(conn) -> bool:
    """Whether this connection can see the Elastic index (the reference DB was built with it)."""
    return bool(conn.execute(
        "SELECT 1 FROM duckdb_tables() WHERE table_name = 'elastic_rules_index' LIMIT 1").fetchone())
