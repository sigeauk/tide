"""The GitLab issues TIDE raised from Rule Monitoring (6.3.1) and for single rules (#106), kept in the
client's own database.

Each row is one issue in one of the client's issues projects (``client_gitlab_projects``, by
``link_id``), with the Rule Monitoring causes it was raised for (``causes``: JSON list of
``[issue, cause, siem_id, space]``, as ``rule_issues.causes_from`` reads them), or the rules it was
raised for from Rule Health (``rules``: JSON list of ``[rule_id, siem_id, space]``). Rule Monitoring
shows an issue on each of its causes, and Rule Health on each rule it is about (its own, or a cause
the rule has: ``about_rules``), while it is open and for ``SHOW_CLOSED_DAYS`` after it closes
(``shown``); raising one of them again offers to comment on it instead.

``state`` (``opened``, ``closed``, or ``deleted`` once GitLab no longer has it), ``closed_at`` (when
it closed, or when TIDE found it gone) and its assignee are GitLab's when TIDE last looked:
``refresh`` asks again, after each sync (``after_sync``, for the issues still shown), after Sync this
rule (``after_rule_sync``, for the issues about it) and when Raise issue lists them.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

Key = Tuple[str, str, str, str]
RuleKey = Tuple[str, str, str]
SHOW_CLOSED_DAYS = 7

DDL = """
    CREATE TABLE IF NOT EXISTS gitlab_issues (
        id          VARCHAR PRIMARY KEY DEFAULT (gen_random_uuid()::VARCHAR),
        link_id     VARCHAR NOT NULL,
        project     VARCHAR NOT NULL,
        iid         INTEGER NOT NULL,
        web_url     VARCHAR,
        title       VARCHAR,
        causes      VARCHAR NOT NULL,
        state       VARCHAR,
        created_by  VARCHAR,
        created_at  TIMESTAMP DEFAULT now(),
        commented_at TIMESTAMP,
        checked_at  TIMESTAMP,
        closed_at   TIMESTAMP,
        assignee    VARCHAR,
        assignee_name VARCHAR,
        rules       VARCHAR
    )
"""
_ADDED = (("closed_at", "TIMESTAMP"), ("assignee", "VARCHAR"), ("assignee_name", "VARCHAR"), ("rules", "VARCHAR"))

_COLS = ("id", "link_id", "project", "iid", "web_url", "title", "causes", "state", "created_by", "created_at",
         "commented_at", "checked_at", "closed_at", "assignee", "assignee_name", "rules")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def ensure(conn) -> None:
    conn.execute(DDL)
    have = {r[0] for r in conn.execute("DESCRIBE gitlab_issues").fetchall()}
    for column, kind in _ADDED:
        if column not in have:
            conn.execute(f"ALTER TABLE gitlab_issues ADD COLUMN {column} {kind}")


def _rows(conn, sql: str, params: list) -> List[Dict[str, Any]]:
    ensure(conn)
    out = []
    for row in conn.execute(sql, params).fetchall():
        item = dict(zip(_COLS, row))
        item["causes"] = [tuple(k) for k in json.loads(item["causes"] or "[]")]
        item["rules"] = [tuple(k) for k in json.loads(item["rules"] or "[]")]
        out.append(item)
    return out


def record(conn, link: Dict[str, Any], issue: Dict[str, Any], title: str, causes: Iterable[Key], actor: str,
           rules: Iterable[RuleKey] = ()) -> str:
    """Keep an issue just raised (gitlab.create_issue's answer), for ``causes`` (Rule Monitoring) or
    ``rules`` (raised for single rules from Rule Health); returns its row id."""
    ensure(conn)
    return conn.execute(
        "INSERT INTO gitlab_issues (link_id, project, iid, web_url, title, causes, state, created_by, checked_at, "
        "assignee, assignee_name, rules) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
        [link["id"], link["project"], issue["iid"], issue.get("web_url"), title,
         json.dumps(sorted(list(k) for k in set(causes))), issue.get("state") or "opened", actor, _utcnow(),
         issue.get("assignee"), issue.get("assignee_name"),
         json.dumps(sorted(list(k) for k in set(rules)))]).fetchone()[0]


def get(conn, row_id: str) -> Dict[str, Any] | None:
    rows = _rows(conn, f"SELECT {', '.join(_COLS)} FROM gitlab_issues WHERE id = ?", [row_id])
    return rows[0] if rows else None


def every(conn) -> List[Dict[str, Any]]:
    """Every issue TIDE raised for this client, newest first."""
    return _rows(conn, f"SELECT {', '.join(_COLS)} FROM gitlab_issues ORDER BY created_at DESC", [])


def for_causes(conn, causes: Iterable[Key]) -> List[Dict[str, Any]]:
    """The issues raised for any of ``causes``, newest first."""
    wanted = set(causes)
    return [i for i in every(conn) if wanted & set(i["causes"])]


def by_cause(conn) -> Dict[Key, List[Dict[str, Any]]]:
    """Each cause key -> the issues raised for it, newest first."""
    out: Dict[Key, List[Dict[str, Any]]] = {}
    for item in every(conn):
        for key in item["causes"]:
            out.setdefault(key, []).append(item)
    return out


def about_rules(conn, causes_by_rule: Dict[RuleKey, Iterable[Key]], now: Optional[datetime] = None,
                open_only: bool = False) -> Dict[RuleKey, List[Dict[str, Any]]]:
    """The issues about each rule that Rule Health shows: those raised for the rule itself, and those
    raised for a cause it has (``causes_by_rule``: each rule's cause keys, from its findings), each with
    ``for_rule`` (raised for the rule, not a cause). The rule window lists those ``shown`` (open, and
    closed in the last week); its card, ``open_only``. Newest first; rules with none left out."""
    out: Dict[RuleKey, List[Dict[str, Any]]] = {}
    issues = [i for i in every(conn) if (i["state"] == "opened" if open_only else shown(i, now))]
    if not issues:
        return out
    for rule, causes in causes_by_rule.items():
        mine = set(causes)
        found = [{**i, "for_rule": rule in i["rules"]} for i in issues if rule in i["rules"] or mine & set(i["causes"])]
        if found:
            out[rule] = found
    return out


def shown(issue: Dict[str, Any], now: Optional[datetime] = None) -> bool:
    """Rule Monitoring shows an issue on its causes while it is open, and for SHOW_CLOSED_DAYS after."""
    if issue.get("state") == "opened":
        return True
    since = issue.get("closed_at") or issue.get("checked_at") or issue.get("created_at")
    return bool(since and since >= (now or _utcnow()) - timedelta(days=SHOW_CLOSED_DAYS))


def commented(conn, row_id: str) -> None:
    conn.execute("UPDATE gitlab_issues SET commented_at = now() WHERE id = ?", [row_id])


def set_now(conn, issues: List[Dict[str, Any]], now: Dict[int, Dict[str, Any]]) -> None:
    """Keep what GitLab says of ``issues`` now (``now``: gitlab.issues_now of their project). One it
    no longer has is ``deleted``, closed when TIDE first found it gone. ``issues`` take the new values."""
    checked = _utcnow()
    for item in issues:
        found = now.get(item["iid"])
        if found:
            item.update(state=found["state"], closed_at=found["closed_at"] if found["state"] != "opened" else None,
                        assignee=found["assignee"], assignee_name=found["assignee_name"])
        elif item.get("state") != "deleted":
            item.update(state="deleted", closed_at=checked)
        item["checked_at"] = checked
        conn.execute("UPDATE gitlab_issues SET state = ?, closed_at = ?, assignee = ?, assignee_name = ?, checked_at = ? "
                     "WHERE id = ?", [item["state"], item.get("closed_at"), item.get("assignee"),
                                      item.get("assignee_name"), checked, item["id"]])


# ── the client's issues projects, and asking GitLab ───────────────────────

def usable_projects(db, client_id: str) -> List[Dict[str, Any]]:
    """The client's issues projects TIDE can use (its last Test didn't fail), with their tokens."""
    return [db.get_client_gitlab_project(client_id, p["id"], with_token=True)
            for p in db.list_client_gitlab_projects(client_id)
            if p["issues"] and p["project_id"] and p["last_status"] in ("ok", "warn")]


def project_for(projects: List[Dict[str, Any]], raised: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The issues project (of ``projects``) an issue was raised in: the link it was raised through,
    or, once that is gone (unlinked, or linked again, say as the backup project too), the one with
    the same path."""
    return (next((p for p in projects if p["id"] == raised["link_id"]), None)
            or next((p for p in projects if str(p["project"]).lower() == str(raised["project"]).lower()), None))


def refresh(db, client_id: str, issues: List[Dict[str, Any]],
            projects: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Dict[str, Any]]:
    """Ask GitLab about ``issues`` (one request per project) and keep what it says; ``issues`` take
    the new values. A project GitLab doesn't answer for keeps what TIDE had. Returns row id -> its
    project, for the issues that still have one (those TIDE can comment on)."""
    from app.services import gitlab
    projects = usable_projects(db, client_id) if projects is None else projects
    groups: Dict[str, Tuple[Dict[str, Any], List[Dict[str, Any]]]] = {}
    found: Dict[str, Dict[str, Any]] = {}
    for item in issues:
        link = project_for(projects, item)
        if link:
            groups.setdefault(link["id"], (link, []))[1].append(item)
            found[item["id"]] = link
    for link, mine in groups.values():
        try:
            now = gitlab.issues_now(link, [i["iid"] for i in mine])
        except gitlab.GitLabError as exc:
            logger.info("GitLab issues of %s not read: %s", link.get("project"), exc)
            continue
        with db.get_connection() as conn:
            set_now(conn, mine, now)
    return found


def after_rule_sync(db, client_id: str, rules: Iterable[RuleKey]) -> None:
    """After Sync this rule (or anything that syncs a few rules, such as bulk edit's Sync): the state now
    of the issues about them that Rule Health shows (``about_rules``: raised for them, or for a cause they
    have), so one closed in GitLab shows closed. Quiet when GitLab doesn't answer, as after a sync."""
    from app.services import rule_issues
    from app.services.tenant_manager import tenant_context_for
    rules = list(rules)
    with tenant_context_for(client_id):
        with db.get_connection() as conn:
            found = rule_issues.rule_findings(conn, rules)
            issues = {i["id"]: i for about in about_rules(conn, rule_issues.cause_keys(found, rules)).values()
                      for i in about}
        if issues:
            refresh(db, client_id, list(issues.values()))


def after_sync(db, client_id: str) -> None:
    """At the end of a sync, in the client's context: the state now of the issues Rule Monitoring
    still shows. Quiet when GitLab doesn't answer: the issues keep what TIDE had."""
    with db.get_connection() as conn:
        issues = [i for i in every(conn) if shown(i)]
    if issues:
        refresh(db, client_id, issues)
