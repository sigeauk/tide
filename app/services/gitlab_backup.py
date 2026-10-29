"""Rule backup to the client's GitLab backup project (6.3.1).

Kibana is the truth: the backup mirrors it, one way. After each sync (``after_sync``, for the
destinations it covered) and on Back up now (``start``), TIDE writes every rule each destination
holds, Elastic's prebuilt rules too, and the exception lists they use, into the backup project
linked on the client's page (``client_gitlab_projects`` used for ``backup``), unless its backups are
paused (``backup_paused``). Destinations it is set not to back up (``backup_skip``) are left out,
and their folders left as they were:

    <folder>/README.md                                 what is where, by rule name (RULES.md with no folder)
    <folder>/<destination>/rules/<rule_id>.json        the rule as Kibana holds it
    <folder>/<destination>/exceptions/<list_id>.json   an exception list and its items

A rule is TIDE's copy from the last sync (``detection_rules.raw_data``) without TIDE's own keys and
without the fields that change when nothing about the rule has (``VOLATILE``); keys are sorted, so a
file changes only when the rule does. Files are named by rule id, so a renamed rule keeps its file;
a renamed destination moves its folder, and a rule given its own rule id (rule history
``new_rule_id``) moves its file, each keeping its history.

What GitLab holds is read each time (``gitlab.tree``: each file's blob id, git's own fingerprint of
its content, which ``blob_id`` works out the same way), and only the difference is committed, in
parts of ``CHUNK_ACTIONS`` files, each commit marked ``[skip ci]``. TIDE manages its files only:
the rules and exceptions folders of the destinations backed up, and the README. A file there that
changed since TIDE wrote it (``gitlab_backup_files``, in the client's database) is put back to
Kibana's version, and the overwrite is kept (who changed it, in which commit) for Rule Monitoring's
``backup_overwritten`` finding; git's history keeps the change. A destination TIDE holds no rules
for (never synced) is left as it is, so an empty TIDE never empties a backup.
"""

from __future__ import annotations

import hashlib
import json
import logging
import posixpath
import re
import threading
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from app.services import gitlab

logger = logging.getLogger(__name__)

# Rule fields that change when nothing about the rule has (Kibana's bookkeeping, run results), and
# the keys TIDE adds to its copy.
VOLATILE = ("updated_at", "revision", "execution_summary")
TIDE_KEYS = ("results", "search_time", "score_detail")
ITEM_VOLATILE = ("_version", "tie_breaker_id", "updated_at")
CHUNK_ACTIONS = 200
OVERWRITE_DAYS = 7          # how long Rule Monitoring shows an overwrite
KEEP_RUNS = 50

DDL = (
    """CREATE TABLE IF NOT EXISTS gitlab_backup_files (
        path               VARCHAR PRIMARY KEY,
        link_id            VARCHAR,
        blob               VARCHAR NOT NULL,
        kind               VARCHAR NOT NULL,
        rule_id            VARCHAR,
        siem_id            VARCHAR,
        space              VARCHAR,
        commit_id          VARCHAR,
        written_at         TIMESTAMP DEFAULT now(),
        overwritten_at     TIMESTAMP,
        overwritten_by     VARCHAR,
        overwritten_commit VARCHAR,
        overwritten_url    VARCHAR
    )""",
    """CREATE TABLE IF NOT EXISTS gitlab_backup_runs (
        id          VARCHAR PRIMARY KEY DEFAULT (gen_random_uuid()::VARCHAR),
        link_id     VARCHAR NOT NULL,
        trigger     VARCHAR NOT NULL,
        started_at  TIMESTAMP DEFAULT now(),
        finished_at TIMESTAMP,
        status      VARCHAR,
        message     VARCHAR,
        commit_url  VARCHAR,
        added       INTEGER DEFAULT 0,
        changed     INTEGER DEFAULT 0,
        deleted     INTEGER DEFAULT 0,
        overwritten INTEGER DEFAULT 0
    )""",
)

_locks: Dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def ensure(conn) -> None:
    for ddl in DDL:
        conn.execute(ddl)
    if "link_id" not in {r[0] for r in conn.execute("DESCRIBE gitlab_backup_files").fetchall()}:
        conn.execute("ALTER TABLE gitlab_backup_files ADD COLUMN link_id VARCHAR")


def blob_id(data: bytes) -> str:
    """Git's blob id of ``data``: what GitLab's file list says a file is."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def _dump(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n"


def rule_json(raw: Dict[str, Any]) -> str:
    """A rule's file: as Kibana holds it, without TIDE's keys or the fields that change on their own."""
    rule = {k: v for k, v in (raw or {}).items() if k not in VOLATILE and k not in TIDE_KEYS}
    if rule.get("type") == "machine_learning" and not rule.get("query"):
        rule.pop("query", None)         # TIDE's copy gives a query-less rule an empty one
    return _dump(rule)


def exception_json(meta: Dict[str, Any], items: List[Dict[str, Any]]) -> str:
    """An exception list's file: the list, then its items in item id order."""
    clean = lambda d: {k: v for k, v in (d or {}).items() if k not in ITEM_VOLATILE}  # noqa: E731
    return _dump({"list": clean(meta),
                  "items": sorted((clean(i) for i in items or []), key=lambda i: str(i.get("item_id") or ""))})


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(text or "").lower()).strip("-") or "destination"


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(name or "")).strip("._") or "unnamed"


def destination_dirs(destinations: List[Dict[str, Any]]) -> Dict[Tuple[str, str], str]:
    """Each destination's folder: its name; two with the same name are told apart by their space."""
    names: Dict[str, int] = {}
    for d in destinations:
        names[slug(d.get("name") or d.get("space"))] = names.get(slug(d.get("name") or d.get("space")), 0) + 1
    out, used = {}, set()
    for d in destinations:
        key = (d["id"], str(d.get("space") or "default"))
        base = slug(d.get("name") or d.get("space"))
        folder = base if names[base] == 1 else f"{base}-{slug(key[1])}"
        n, candidate = 2, folder
        while candidate in used:
            candidate, n = f"{folder}-{n}", n + 1
        used.add(candidate)
        out[key] = candidate
    return out


def usable(link: Dict[str, Any]) -> bool:
    """Its last Test found it usable for backup."""
    return bool(link.get("backup") and link.get("project_id") and link.get("last_status") in ("ok", "warn"))


def backup_link(db, client_id: str) -> Optional[Dict[str, Any]]:
    """The client's backup project, with its token, when it is usable and its backups aren't paused."""
    for p in db.list_client_gitlab_projects(client_id):
        if usable(p) and not p["backup_paused"]:
            return db.get_client_gitlab_project(client_id, p["id"], with_token=True)
    return None


def running(link_id: str) -> bool:
    lock = _locks.get(link_id)
    return bool(lock and lock.locked())


def last_run(conn, link_id: str) -> Optional[Dict[str, Any]]:
    ensure(conn)
    cur = conn.execute("SELECT * FROM gitlab_backup_runs WHERE link_id = ? ORDER BY started_at DESC LIMIT 1", [link_id])
    row = cur.fetchone()
    return dict(zip([d[0] for d in cur.description], row)) if row else None


# ── what the backup should hold ──────────────────────────────────────────

def _rules(conn, siem_id: str, space: str) -> List[Dict[str, Any]]:
    out = []
    for rule_id, name, enabled, raw in conn.execute(
            "SELECT rule_id, name, enabled, raw_data FROM detection_rules WHERE siem_id = ? AND space = ? "
            "AND NOT COALESCE(deprecated, false) ORDER BY lower(name)", [siem_id, space]).fetchall():
        try:
            data = json.loads(raw) if isinstance(raw, str) else (raw or {})
        except ValueError:
            data = {}
        out.append({"rule_id": rule_id, "name": name, "enabled": bool(enabled), "raw": data})
    return out


def _exception_lists(dest: Dict[str, Any], rules: List[Dict[str, Any]]) -> Tuple[Dict[str, str], List[str]]:
    """``({list_id: file}, list ids Kibana didn't give)`` for the lists the destination's rules use."""
    from app import elastic_helper
    wanted: Dict[str, str] = {}
    for r in rules:
        for ref in r["raw"].get("exceptions_list") or []:
            if ref.get("list_id"):
                wanted.setdefault(ref["list_id"], ref.get("namespace_type") or "single")
    if not wanted:
        return {}, []
    session = elastic_helper._make_session(dest.get("api_token_enc") or "", dest.get("kibana_url") or "")
    base, space = (dest.get("kibana_url") or "").rstrip("/"), str(dest.get("space") or "default")
    files, missing = {}, []
    for list_id, namespace in sorted(wanted.items()):
        try:
            meta = elastic_helper.get_exception_list(list_id, space, session, base, namespace_type=namespace)
            items = elastic_helper.get_exception_list_entries(list_id, space, session, base, namespace_type=namespace) \
                if meta else None
        except Exception:  # noqa: BLE001 - Kibana didn't answer: keep what the backup has
            logger.warning("Backup: exception list %s not read from %s", list_id, dest.get("name"), exc_info=True)
            meta = items = None
        if meta is None or items is None:
            missing.append(list_id)
        else:
            files[list_id] = exception_json(meta, items)
    return files, missing


def _renamed(conn) -> Dict[Tuple[str, str, str], str]:
    """``(rule id, siem_id, space)`` -> the rule id it had before, for rules given their own rule id."""
    if not conn.execute("SELECT 1 FROM duckdb_tables() WHERE table_name = 'rule_lifecycle_history' "
                        "AND database_name = current_database()").fetchone():
        return {}
    rows = conn.execute("SELECT rule_id, siem_id, space, json_extract_string(detail, '$.previous_rule_id') "
                        "FROM rule_lifecycle_history WHERE action = 'new_rule_id'").fetchall()
    return {(r[0], r[1], str(r[2] or "default")): r[3] for r in rows if r[3] and r[3] != r[0]}


def _readme(destinations: List[Dict[str, Any]], dirs: Dict[Tuple[str, str], str],
            rules_by_dest: Dict[Tuple[str, str], List[Dict[str, Any]]], skip: Set[Tuple[str, str]]) -> str:
    lines = ["# Detection rule backup", "",
             "Written by TIDE from Kibana after each sync: Kibana holds the rules, this is their copy. Don't edit "
             "these files: TIDE puts Kibana's version back at its next backup (git keeps every change).", ""]
    skipped = [d.get("name") or str(d.get("space") or "default") for d in destinations
               if (d["id"], str(d.get("space") or "default")) in skip]
    if skipped:
        lines += [f"Not backed up, as chosen in TIDE: {', '.join(skipped)}. A folder written for one before is left "
                  "as it was then.", ""]
    for d in destinations:
        key = (d["id"], str(d.get("space") or "default"))
        rules = rules_by_dest.get(key)
        if rules is None or key in skip:
            continue
        lines += [f"## {d.get('name') or key[1]}", "",
                  f"SIEM {d.get('label') or key[0]}, Kibana space `{key[1]}`: {len(rules)} rules.", "",
                  "| Rule | Enabled | Type | File |", "|---|---|---|---|"]
        for r in rules:
            name = str(r["name"] or r["rule_id"]).replace("|", "\\|")
            lines.append(f"| {name} | {'yes' if r['enabled'] else 'no'} | {r['raw'].get('type') or ''} | "
                         f"[{r['rule_id']}]({dirs[key]}/rules/{_safe(r['rule_id'])}.json) |")
        lines.append("")
    return "\n".join(lines)


# ── one backup ───────────────────────────────────────────────────────────

def _record_run(conn, run_id: str, **fields) -> None:
    sets = ", ".join(f"{k} = ?" for k in fields)
    conn.execute(f"UPDATE gitlab_backup_runs SET {sets} WHERE id = ?", [*fields.values(), run_id])


def run(db, client_id: str, link: Dict[str, Any], destinations: Optional[Iterable[Tuple[str, str]]] = None,
        trigger: str = "manual") -> Dict[str, Any]:
    """Back up the client's destinations (``destinations``: (siem_id, space) pairs; all when None) to
    the backup project ``link``. Needs the client's database context. Returns ``{"status": "done" |
    "nothing" | "failed" | "running", "message", "commit_url", "added", "changed", "deleted",
    "overwritten"}``; never raises for GitLab or Kibana refusing."""
    lock = _lock(link["id"])
    if not lock.acquire(blocking=False):
        return {"status": "running", "message": "A backup to this project is already running."}
    try:
        return _run_held(db, client_id, link, destinations, trigger)
    finally:
        lock.release()


def _lock(link_id: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(link_id, threading.Lock())


def _run_held(db, client_id: str, link: Dict[str, Any], destinations, trigger: str) -> Dict[str, Any]:
    """``run`` with the project's lock already held: the backup, kept as one of its runs."""
    with db.get_connection() as conn:
        ensure(conn)
        run_id = conn.execute("INSERT INTO gitlab_backup_runs (link_id, trigger) VALUES (?, ?) RETURNING id",
                              [link["id"], trigger]).fetchone()[0]
    try:
        result = _backup(db, client_id, link, set(destinations) if destinations is not None else None)
    except gitlab.GitLabError as exc:
        result = {"status": "failed", "message": str(exc)}
    except Exception as exc:  # noqa: BLE001 - kept on the run; the sync carries on
        logger.exception("Backup to GitLab failed for client %s", client_id)
        result = {"status": "failed", "message": f"{type(exc).__name__}: {str(exc)[:200]}"}
    with db.get_connection() as conn:
        _record_run(conn, run_id, finished_at=datetime.now(), status=result["status"],
                    message=result.get("message", "")[:2000], commit_url=result.get("commit_url"),
                    **{k: result.get(k, 0) for k in ("added", "changed", "deleted", "overwritten")})
        conn.execute("DELETE FROM gitlab_backup_runs WHERE link_id = ? AND id NOT IN (SELECT id FROM "
                     "gitlab_backup_runs WHERE link_id = ? ORDER BY started_at DESC LIMIT ?)",
                     [link["id"], link["id"], KEEP_RUNS])
    return result


def _backup(db, client_id: str, link: Dict[str, Any], chosen: Optional[Set[Tuple[str, str]]]) -> Dict[str, Any]:
    project = gitlab.project_info(link)
    branch = link.get("branch") or gitlab.DEFAULT_BRANCH
    base = f"{link['folder'].strip('/')}/" if link.get("folder") else ""
    # In its own folder the index is the folder's README (GitLab shows it there); at the top of the
    # project it is RULES.md, never the project's own README.
    readme_path = f"{base}README.md" if base else "RULES.md"
    # A branch not there yet is made from the default branch: what that holds is what it starts with.
    start = None
    if not project.get("empty_repo") and not gitlab.branch_exists(link, branch):
        start = project.get("default_branch")
    ref = start or branch
    all_dests = db.get_client_siems(client_id) or []
    dirs = destination_dirs(all_dests)
    keys = [(d["id"], str(d.get("space") or "default")) for d in all_dests]
    skip = set(link.get("skip") or ())
    backed = [k for k in keys if k not in skip and (chosen is None or k in chosen)]

    # What it should hold: every rule and exception list of the destinations backed up. What TIDE
    # wrote to another project (the backup moved) says nothing about this one.
    with db.get_connection() as conn:
        rules_by_dest = {k: _rules(conn, *k) for k in keys}
        conn.execute("DELETE FROM gitlab_backup_files WHERE link_id IS DISTINCT FROM ?", [link["id"]])
        state = {r[0]: {"blob": r[1], "siem_id": r[2], "space": r[3]} for r in conn.execute(
            "SELECT path, blob, siem_id, space FROM gitlab_backup_files").fetchall()}
        renamed = _renamed(conn)
    desired: Dict[str, Tuple[str, Dict[str, Any]]] = {}
    keep: Set[str] = set()
    notes: List[str] = []
    roots: Set[str] = set()
    for d, key in zip(all_dests, keys):
        if key not in backed:
            continue
        rules = rules_by_dest[key]
        if not rules:
            notes.append(f"{d.get('name') or key[1]}: TIDE holds no rules for it yet (sync it first), so its backup "
                         "was left as it is.")
            continue
        folder = f"{base}{dirs[key]}"
        roots.add(folder)
        for r in rules:
            desired[f"{folder}/rules/{_safe(r['rule_id'])}.json"] = (
                rule_json(r["raw"]), {"kind": "rule", "rule_id": r["rule_id"], "siem_id": key[0], "space": key[1],
                                      "name": r["name"], "by": r["raw"].get("updated_by")})
        lists, missing = _exception_lists(d, rules)
        for list_id, text in lists.items():
            desired[f"{folder}/exceptions/{_safe(list_id)}.json"] = (
                text, {"kind": "exception", "siem_id": key[0], "space": key[1], "name": list_id})
        for list_id in missing:
            keep.add(f"{folder}/exceptions/{_safe(list_id)}.json")
        if missing:
            notes.append(f"{d.get('name') or key[1]}: Kibana didn't give exception list(s) {', '.join(missing)}, "
                         "so their files were left as they were.")
    desired[readme_path] = (_readme(all_dests, dirs, rules_by_dest, skip), {"kind": "readme", "name": "README"})
    # Folders TIDE wrote before for these destinations (a destination renamed), or, backing up all,
    # for destinations no longer linked: what is there goes, or moves. A destination not backed up
    # is still linked, so its folder is never one of them.
    for path, row in state.items():
        top = path[len(base):].split("/", 1)[0] if path.startswith(base) else None
        if top and path != readme_path and (chosen is None and (row["siem_id"], row["space"]) not in keys
                                            or (row["siem_id"], row["space"]) in backed and
                                            rules_by_dest.get((row["siem_id"], row["space"]))):
            roots.add(f"{base}{top}")

    # What GitLab holds now.
    held: Dict[str, str] = {}
    if not project.get("empty_repo"):
        for root in sorted(roots):
            held.update(gitlab.tree(link, root, ref))
        top_files = gitlab.tree(link, base.rstrip("/"), ref, recursive=False)
        if readme_path in top_files:
            held[readme_path] = top_files[readme_path]

    def managed(path: str) -> bool:
        if not any(path.startswith(f"{root}/") for root in roots):
            return False
        rest = path.split("/")[-2:]
        return len(rest) == 2 and rest[0] in ("rules", "exceptions") and rest[1].endswith(".json")

    creates, updates, deletes, overwritten = {}, {}, {}, []
    settled = {}        # GitLab already holds what Kibana does, but TIDE has no (or an old) record of it
    for path, (text, meta) in desired.items():
        want = blob_id(text.encode("utf-8"))
        have = held.get(path)
        if have == want:
            if (state.get(path) or {}).get("blob") != want:
                settled[path] = (text, meta)
            continue
        (updates if have else creates)[path] = (text, meta, want)
        if path in state and have != state[path]["blob"]:
            overwritten.append(path)
    for path, have in held.items():
        if path not in desired and path not in keep and managed(path):
            deletes[path] = have
            if path in state and have != state[path]["blob"]:
                overwritten.append(path)
    # A rule given its own rule id moves to its new file, and a file whose folder moved (the
    # destination renamed) moves with it.
    moves = {}
    for path in list(creates):
        meta = creates[path][1]
        before = renamed.get((meta.get("rule_id"), meta.get("siem_id"), meta.get("space")))
        old = before and f"{posixpath.dirname(path)}/{_safe(before)}.json"
        if old and old in deletes:
            moves[path] = (old, *creates.pop(path))
            deletes.pop(old)
    by_name = {}
    for old in deletes:
        by_name.setdefault(posixpath.basename(old), []).append(old)
    for path in list(creates):
        olds = by_name.get(posixpath.basename(path)) or []
        if olds:
            old = olds.pop(0)
            moves[path] = (old, *creates.pop(path))
            deletes.pop(old)
    gone_from_state = [p for p in state if p not in held and p not in desired and managed(p)]
    if not (creates or updates or deletes or moves):
        with db.get_connection() as conn:
            _remember(conn, link["id"], settled, {}, gone_from_state, None)
        return {"status": "nothing", "message": " ".join(["The backup already matches Kibana."] + notes),
                "added": 0, "changed": 0, "deleted": 0, "overwritten": 0}

    # Who changed what TIDE puts back.
    outside = {}
    for path in overwritten:
        change = gitlab.last_change(link, path, ref) if path in held else None
        outside[path] = change or {}

    actions = ([{"action": "create", "file_path": p, "content": t} for p, (t, _m, _w) in creates.items()]
               + [{"action": "update", "file_path": p, "content": t} for p, (t, _m, _w) in updates.items()]
               + [{"action": "move", "file_path": p, "previous_path": o, "content": t} for p, (o, t, _m, _w) in moves.items()]
               + [{"action": "delete", "file_path": p} for p in deletes])
    names = sorted({d.get("name") or k[1] for d, k in zip(all_dests, keys) if k in backed})
    chunks = [actions[i:i + CHUNK_ACTIONS] for i in range(0, len(actions), CHUNK_ACTIONS)]
    last = None
    for n, chunk in enumerate(chunks, 1):
        message = _message(names, creates, updates, moves, deletes, outside, chunk, n, len(chunks))
        last = gitlab.commit(link, branch, message, chunk, start_branch=start if n == 1 else None)
        done = {a["file_path"] for a in chunk}
        with db.get_connection() as conn:
            _remember(conn, link["id"], {p: desired[p] for p in done if p in desired},
                      {p: outside.get(p) for p in overwritten if p in done},
                      [a["file_path"] for a in chunk if a["action"] == "delete"]
                      + [a["previous_path"] for a in chunk if a["action"] == "move"], last)
    with db.get_connection() as conn:
        _remember(conn, link["id"], settled, {}, gone_from_state, None)
    added, changed, deleted = len(creates), len(updates) + len(moves), len(deletes)
    summary = (f"Backed up to {link['project']}: {added} added, {changed} changed, {deleted} removed"
               f"{f', {len(overwritten)} changed in GitLab put back to Kibana' if overwritten else ''}"
               f"{f' ({len(chunks)} commits)' if len(chunks) > 1 else ''}.")
    return {"status": "done", "message": " ".join([summary] + notes), "commit_url": last and last.get("web_url"),
            "added": added, "changed": changed, "deleted": deleted, "overwritten": len(overwritten)}


def _message(names, creates, updates, moves, deletes, outside, chunk, n, total) -> str:
    """A commit's message: what changed, by whom in Kibana, and what was put back; ``[skip ci]`` so
    the project's pipelines don't run on a backup."""
    paths = {a["file_path"] for a in chunk}
    count = lambda d: sum(1 for p in d if p in paths)  # noqa: E731
    head = (f"TIDE backup of {', '.join(names) or 'rules'}: {count(creates)} added, {count(updates) + count(moves)} changed, "
            f"{count(deletes)} removed{f' (part {n} of {total})' if total > 1 else ''} [skip ci]")
    body = []
    for label, group in (("Added", creates), ("Changed", updates)):
        for p in sorted(x for x in group if x in paths):
            meta = group[p][1]
            if meta["kind"] == "readme":
                continue
            by = f", last changed in Kibana by {meta['by']}" if meta.get("by") and label == "Changed" else ""
            body.append(f"{label}: {meta['name']} ({p}){by}")
    for p in sorted(x for x in moves if x in paths):
        old, _text, meta, _want = moves[p]
        what = "Moved" if posixpath.basename(old) == posixpath.basename(p) else "Rule id changed"
        body.append(f"{what}: {meta['name']} ({old} -> {p})")
    for p in sorted(x for x in deletes if x in paths):
        body.append(f"Removed: {p}")
    for p in sorted(x for x in outside if x in paths):
        change = outside[p]
        who = f" by {change['author']} in {change['short_id']}" if change.get("short_id") else ""
        body.append(f"Put back Kibana's version of {p}, changed in GitLab{who}")
    if len(body) > 300:
        body = body[:300] + [f"...and {len(body) - 300} more"]
    return head + ("\n\n" + "\n".join(body) if body else "")


def _remember(conn, link_id: str, files: Dict[str, Tuple[str, Dict[str, Any]]],
              outside: Dict[str, Optional[Dict[str, Any]]], gone: List[str], commit: Optional[Dict[str, Any]]) -> None:
    """Keep what TIDE wrote to the project ``link_id`` (each file's blob), the overwrites, and forget
    files no longer there."""
    ensure(conn)
    for path, (text, meta) in files.items():
        change = outside.get(path)
        conn.execute(
            "INSERT INTO gitlab_backup_files (path, link_id, blob, kind, rule_id, siem_id, space, commit_id, written_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, now()) ON CONFLICT (path) DO UPDATE SET link_id = excluded.link_id, "
            "blob = excluded.blob, kind = excluded.kind, rule_id = excluded.rule_id, siem_id = excluded.siem_id, "
            "space = excluded.space, commit_id = COALESCE(excluded.commit_id, gitlab_backup_files.commit_id), "
            "written_at = excluded.written_at",
            [path, link_id, blob_id(text.encode("utf-8")), meta["kind"], meta.get("rule_id"), meta.get("siem_id"),
             meta.get("space"), (commit or {}).get("id")])
        if change is not None:
            conn.execute("UPDATE gitlab_backup_files SET overwritten_at = now(), overwritten_by = ?, "
                         "overwritten_commit = ?, overwritten_url = ? WHERE path = ?",
                         [change.get("author"), change.get("short_id"), change.get("web_url"), path])
    for path in gone:
        conn.execute("DELETE FROM gitlab_backup_files WHERE path = ?", [path])


# ── when it runs ─────────────────────────────────────────────────────────

def after_sync(db, client_id: str, scopes: Iterable[Tuple[str, str]]) -> Optional[Dict[str, Any]]:
    """At the end of a sync, in the client's context: back up the destinations it covered, when the
    client has a usable backup project whose backups aren't paused. Returns the run's result, or
    None (no backup project, paused, or it covered only destinations the project doesn't back up)."""
    link = backup_link(db, client_id)
    scopes = [s for s in scopes if s not in (link or {}).get("skip", ())]
    if not link or not scopes:
        return None
    return run(db, client_id, link, destinations=scopes, trigger="sync")


def start(db, client_id: str, link: Dict[str, Any]) -> bool:
    """Back up now, in the background (every destination). It counts as running from the moment this
    returns True; False when one is already running."""
    from app.services.tenant_manager import tenant_context_for
    lock = _lock(link["id"])
    if not lock.acquire(blocking=False):
        return False

    def work():
        try:
            with tenant_context_for(client_id):
                _run_held(db, client_id, link, None, "manual")
        finally:
            lock.release()
    threading.Thread(target=work, name=f"gitlab-backup-{link['id'][:8]}", daemon=True).start()
    return True
