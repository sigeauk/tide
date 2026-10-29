"""GitLab: the projects a client uses, each through its own access token (6.3.1).

A GitLab instance is an integration (Settings → Management → Integrations: its address and
Verify TLS certificate). A client's admins link that instance's projects on the client's page
(``client_gitlab_projects``), each used for one or both of these (``uses``):

- ``backup``: where the client's rules are backed up. One per client.
- ``issues``: where issues raised from Rule Monitoring go. Any number, for example one for
  engineers and one for analysts.

Each project has its own token, usually a project access token (its bot user is the project's
service account), so TIDE sees only that project: one client's work can't reach another
client's project. ``check`` tests a project the way TIDE will use it. It changes nothing in GitLab.
"""

from __future__ import annotations

import logging
import re
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests

from app.services import tls

logger = logging.getLogger(__name__)

PURPOSES = {"backup": "Rule backup", "issues": "Issues"}
DEFAULT_BRANCH = "main"
EXPIRY_WARNING_DAYS = 14     # GitLab's own default for a new token is 30 days: not yet a warning
ROLES = {5: "Minimal access", 10: "Guest", 15: "Planner", 20: "Reporter", 30: "Developer", 40: "Maintainer",
         50: "Owner"}
# The least role each purpose needs: backing up commits files; an issue's labels are kept only for a
# role that can manage issues (Planner and up).
NEEDS = {"backup": 30, "issues": 15}
TIMEOUT = 15


def uses(link: Dict[str, Any]) -> List[str]:
    """What a project is used for, in ``PURPOSES`` order: its ``purpose`` holds them comma-separated."""
    held = str(link.get("purpose") or "").split(",")
    return [p for p in PURPOSES if p in held]


def _session(link: Dict[str, Any]) -> requests.Session:
    session = requests.Session()
    session.headers["PRIVATE-TOKEN"] = link.get("token") or ""
    session.verify = tls.verify_arg(link.get("tls_verify"))
    return session


def _api(link: Dict[str, Any], path: str) -> str:
    return f"{(link.get('gitlab_url') or '').rstrip('/')}/api/v4{path}"


class GitLabError(Exception):
    """GitLab refused or didn't answer; the message says why, for the user."""


# GitLab's own limit on an issue's description and a comment, in characters.
MAX_TEXT = 1_000_000


def _why(resp: requests.Response, what: str) -> str:
    if resp.status_code == 401:
        return "GitLab didn't accept the project's access token: Test the project on the client's page."
    if resp.status_code == 403:
        return f"The project's access token isn't allowed to {what}: its role is too low."
    if resp.status_code == 404:
        return "GitLab no longer has that project, or the token can no longer see it."
    try:
        body = resp.json() or {}
        detail = body.get("message") or body.get("error") or ""
    except ValueError:
        detail = ""
    return f"GitLab couldn't {what} (HTTP {resp.status_code}{': ' + str(detail)[:200] if detail else ''})."


def _send(link: Dict[str, Any], method: str, path: str, what: str, timeout: int = TIMEOUT, **kwargs) -> requests.Response:
    try:
        resp = getattr(_session(link), method)(_api(link, path), timeout=timeout, **kwargs)
    except requests.RequestException as exc:
        raise GitLabError(tls.describe_error(exc) or f"GitLab didn't answer: {str(exc)[:200]}") from exc
    if resp.status_code not in (200, 201):
        raise GitLabError(_why(resp, what))
    return resp


def _clip(text: str) -> str:
    return text if len(text) <= MAX_TEXT else text[:MAX_TEXT - 80] + "\n\n…cut short: GitLab takes no more. TIDE has the rest."


def _issue(issue: Dict[str, Any]) -> Dict[str, Any]:
    """What TIDE keeps of an issue: ``state``, ``closed_at`` (UTC), and its first assignee
    (``assignee``, the username, and ``assignee_name``)."""
    who = (issue.get("assignees") or [issue.get("assignee")] or [None])[0] or {}
    return {"iid": issue.get("iid"), "web_url": issue.get("web_url"), "state": issue.get("state") or "opened",
            "closed_at": _when(issue.get("closed_at")), "assignee": who.get("username"), "assignee_name": who.get("name")}


def create_issue(link: Dict[str, Any], title: str, description: str, labels: list,
                 assignee_id: Optional[int] = None) -> Dict[str, Any]:
    """Open an issue in the link's project, assigned to the member ``assignee_id`` when given:
    ``_issue`` of it. GitLab makes any label the project doesn't have yet, and leaves out an
    assignee who can't be assigned. Raises GitLabError."""
    body = {"title": title[:255], "description": _clip(description), "labels": ",".join(labels)}
    if assignee_id:
        body["assignee_ids"] = [int(assignee_id)]
    return _issue(_send(link, "post", f"/projects/{link['project_id']}/issues", "open an issue", json=body).json() or {})


def add_comment(link: Dict[str, Any], iid: int, text: str) -> None:
    """Comment on issue ``iid`` of the link's project. Raises GitLabError."""
    _send(link, "post", f"/projects/{link['project_id']}/issues/{int(iid)}/notes", "comment on the issue",
          json={"body": _clip(text)})


def issues_now(link: Dict[str, Any], iids: list) -> Dict[int, Dict[str, Any]]:
    """Issues ``iids`` of the link's project as they are now (``_issue``); those GitLab no longer
    has are left out. Quick to give up: it's only to show them. Raises GitLabError."""
    out: Dict[int, Dict[str, Any]] = {}
    iids = sorted({int(i) for i in iids})
    for start in range(0, len(iids), 100):
        query = "&".join(f"iids[]={i}" for i in iids[start:start + 100])
        issues = _send(link, "get", f"/projects/{link['project_id']}/issues?{query}&per_page=100", "read its issues",
                       timeout=5).json()
        out.update({i.get("iid"): _issue(i) for i in issues or []})
    return out


# A token's own account, or another bot: never someone to assign an issue to.
_BOT = re.compile(r"^(project|group)_\d+_bot|^service_account", re.IGNORECASE)


def project_members(link: Dict[str, Any], limit: int = 500) -> List[Dict[str, Any]]:
    """The people an issue in the link's project can be assigned to: its active members, inherited
    ones too, Guest or above, without bots. ``[{"id", "username", "name"}]`` by name. Raises
    GitLabError."""
    people: Dict[int, Dict[str, Any]] = {}
    page = "1"
    while page and len(people) < limit:
        resp = _send(link, "get", f"/projects/{link['project_id']}/members/all?per_page=100&page={page}",
                     "list its members", timeout=5)
        for m in resp.json() or []:
            if (m.get("state") or "active") == "active" and not m.get("bot") and not _BOT.match(m.get("username") or "") \
                    and (m.get("access_level") or 0) >= 10:
                people[m["id"]] = {"id": m["id"], "username": m.get("username"), "name": m.get("name") or m.get("username")}
        page = (getattr(resp, "headers", None) or {}).get("X-Next-Page")
    return sorted(people.values(), key=lambda p: str(p["name"]).lower())


# ── the backup project's repository (app.services.gitlab_backup) ──────────

def project_info(link: Dict[str, Any]) -> Dict[str, Any]:
    """The project as the link's token sees it: ``default_branch``, ``empty_repo``. Raises GitLabError."""
    return _send(link, "get", f"/projects/{link['project_id']}", "read the project").json() or {}


def branch_exists(link: Dict[str, Any], branch: str) -> bool:
    try:
        resp = _session(link).get(_api(link, f"/projects/{link['project_id']}/repository/branches/{quote(branch, safe='')}"),
                                  timeout=TIMEOUT)
    except requests.RequestException as exc:
        raise GitLabError(tls.describe_error(exc) or f"GitLab didn't answer: {str(exc)[:200]}") from exc
    if resp.status_code == 404:
        return False
    if resp.status_code != 200:
        raise GitLabError(_why(resp, "read the branch"))
    return True


def tree(link: Dict[str, Any], path: str, ref: str, recursive: bool = True) -> Dict[str, str]:
    """Every file under ``path`` on branch ``ref``: ``{file path: blob id}`` (git's content
    fingerprint, which ``gitlab_backup.blob_id`` works out the same way). Empty when the branch or
    the folder isn't there. Raises GitLabError."""
    params = f"ref={quote(ref, safe='')}&recursive={'true' if recursive else 'false'}&per_page=100&pagination=keyset"
    url = _api(link, f"/projects/{link['project_id']}/repository/tree?{params}"
                     f"{'&path=' + quote(path, safe='') if path else ''}")
    session, files = _session(link), {}
    while url:
        try:
            resp = session.get(url, timeout=TIMEOUT)
        except requests.RequestException as exc:
            raise GitLabError(tls.describe_error(exc) or f"GitLab didn't answer: {str(exc)[:200]}") from exc
        if resp.status_code == 404:
            return files
        if resp.status_code != 200:
            raise GitLabError(_why(resp, "list the project's files"))
        files.update({e["path"]: e["id"] for e in resp.json() or [] if e.get("type") == "blob"})
        url = (resp.links.get("next") or {}).get("url")
    return files


def commit(link: Dict[str, Any], branch: str, message: str, actions: list, start_branch: Optional[str] = None) -> Dict[str, Any]:
    """One commit of ``actions`` (create / update / delete / move) on ``branch``; ``start_branch``
    makes ``branch`` from it first. ``{"id", "short_id", "web_url"}``. Raises GitLabError."""
    body = {"branch": branch, "commit_message": message, "actions": actions}
    if start_branch:
        body["start_branch"] = start_branch
    result = _send(link, "post", f"/projects/{link['project_id']}/repository/commits", "commit to the project",
                   timeout=120, json=body).json() or {}
    return {"id": result.get("id"), "short_id": result.get("short_id"), "web_url": result.get("web_url")}


def last_change(link: Dict[str, Any], path: str, ref: str) -> Optional[Dict[str, Any]]:
    """The last commit on ``ref`` to change ``path``: ``{"id", "short_id", "author", "web_url"}``, or None."""
    try:
        resp = _send(link, "get", f"/projects/{link['project_id']}/repository/commits?ref_name={quote(ref, safe='')}"
                                  f"&path={quote(path, safe='')}&per_page=1", "read the file's history")
    except GitLabError:
        return None
    found = (resp.json() or [None])[0]
    return {"id": found.get("id"), "short_id": found.get("short_id"), "author": found.get("author_name"),
            "web_url": found.get("web_url")} if found else None


def _expiry(value: Optional[str]) -> Optional[date]:
    try:
        return date.fromisoformat(str(value)[:10]) if value else None
    except ValueError:
        return None


def _when(value: Optional[str]) -> Optional[datetime]:
    """A GitLab time (ISO 8601) as UTC without its zone, as TIDE keeps times."""
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00")) if value else None
    except ValueError:
        return None
    return moment.astimezone(timezone.utc).replace(tzinfo=None) if moment and moment.tzinfo else moment


def _visible(link: Dict[str, Any], session: requests.Session, limit: int = 10) -> str:
    """For a project the token can't see: the projects it can (a project access token sees only its
    own), so a token made in another project, or a path typed differently, shows at once."""
    try:
        resp = session.get(_api(link, f"/projects?membership=true&simple=true&per_page={limit}"), timeout=TIMEOUT)
        paths = [p.get("path_with_namespace") for p in (resp.json() or []) if p.get("path_with_namespace")] \
            if resp.status_code == 200 else None
    except (requests.RequestException, ValueError):
        paths = None
    if paths:
        return f"It can see: {', '.join(paths)}{' and more' if len(paths) == limit else ''}."
    if paths == []:
        # Usually a service account's (or a person's) token whose account was never added to the
        # project; a project access token is a member of its project from the start.
        try:
            resp = session.get(_api(link, "/user"), timeout=TIMEOUT)
            who = (resp.json() or {}).get("username") if resp.status_code == 200 else None
        except (requests.RequestException, ValueError):
            who = None
        account = f"its account, {who}," if who else "its account"
        return (f"It can't see any project: {account} isn't a member of one. Add it to the project (Manage → Members) "
                "with the role it needs, or make a project access token in the project instead (Settings → Access tokens).")
    return "Check the path, and that the token was made in this project."


def check(link: Dict[str, Any], today: Optional[date] = None) -> Dict[str, Any]:
    """Test one project link (``list_client_gitlab_projects`` row with ``token``) as TIDE will use it.

    Returns ``{"status", "message", "project", "project_id", "project_url", "token_expires_at"}``.
    ``status`` is ``ok``, ``warn`` (it works, but something needs attention: a token expiring soon,
    a project anyone can see) or ``fail`` (TIDE can't use it). ``project`` is the path as GitLab
    spells it."""
    today = today or datetime.now(timezone.utc).date()
    used = uses(link) or ["issues"]
    backup = "backup" in used
    out: Dict[str, Any] = {"status": "ok", "message": "", "project": link.get("project"), "project_id": None,
                           "project_url": None, "token_expires_at": None}
    fails, warns, notes = [], [], []

    def done() -> Dict[str, Any]:
        out["status"] = "fail" if fails else "warn" if warns else "ok"
        out["message"] = " ".join(fails or (warns + notes))
        return out

    if not link.get("gitlab_url"):
        fails.append("Its GitLab integration no longer exists.")
        return done()
    if not link.get("token"):
        fails.append("It has no access token.")
        return done()
    session = _session(link)
    try:
        # The token: GitLab answers for any personal, project or group access token.
        resp = session.get(_api(link, "/personal_access_tokens/self"), timeout=TIMEOUT)
        if resp.status_code == 401:
            fails.append("GitLab didn't accept the access token: it may be mistyped, expired or revoked.")
            return done()
        if resp.status_code == 200:
            token = resp.json() or {}
            scopes = token.get("scopes") or []
            if "api" not in scopes:
                fails.append(f"The access token needs the api scope; it has {', '.join(scopes) or 'none'}.")
            expires = _expiry(token.get("expires_at"))
            out["token_expires_at"] = expires
            if expires and expires <= today:
                fails.append(f"The access token expired on {expires.isoformat()}.")
            elif expires and (expires - today).days <= EXPIRY_WARNING_DAYS:
                warns.append(f"The access token expires on {expires.isoformat()}: make a new one before then.")

        # The project, as this token sees it: a project access token sees its own project only.
        resp = session.get(_api(link, f"/projects/{quote(str(link.get('project') or ''), safe='')}"), timeout=TIMEOUT)
        if resp.status_code in (401, 403):
            fails.append("GitLab didn't accept the access token for this project.")
            return done()
        if resp.status_code == 404:
            fails.append(f"GitLab has no project {link.get('project')} that this token can see. {_visible(link, session)}")
            return done()
        if resp.status_code != 200:
            fails.append(f"GitLab answered HTTP {resp.status_code} for the project.")
            return done()
        project = resp.json() or {}
        out.update(project=project.get("path_with_namespace") or link.get("project"), project_id=project.get("id"),
                   project_url=project.get("web_url"))
        if fails:
            return done()
        if project.get("archived"):
            fails.append("The project is archived, so nothing can be written to it.")
        perms = project.get("permissions") or {}
        level = max((perms.get(k) or {}).get("access_level") or 0 for k in ("project_access", "group_access"))
        role = ROLES.get(level, "no role")
        if level < max(NEEDS[u] for u in used):
            fails.append(f"The token's account is {role} in this project; "
                         f"{'backing up rules needs Developer' if backup else 'issues need Planner'} "
                         "or above.")
        visibility = project.get("visibility") or "private"
        if visibility != "private":
            what = "every rule's logic" if backup else "these issues"
            warns.append(f"The project is {visibility}, so anyone who can see it can read {what}. Make it private.")

        if backup and not fails:
            branch = link.get("branch") or DEFAULT_BRANCH
            if project.get("empty_repo"):
                notes.append(f"The project is empty: TIDE will create {branch} with its first backup.")
            else:
                resp = session.get(_api(link, f"/projects/{project.get('id')}/repository/branches/{quote(branch, safe='')}"),
                                   timeout=TIMEOUT)
                if resp.status_code == 404:
                    notes.append(f"It has no {branch} branch yet: TIDE will create it from "
                                 f"{project.get('default_branch') or 'the default branch'}.")
                elif resp.status_code == 200 and not (resp.json() or {}).get("can_push"):
                    fails.append(f"{branch} is protected and the token's account can't push to it: allow it under "
                                 "Settings → Repository → Protected branches, or give it the Maintainer role.")
        if "issues" in used:
            if project.get("issues_access_level") == "disabled" or project.get("issues_enabled") is False:
                fails.append("Issues are turned off in this project (Settings → General → Visibility).")

        if not fails:
            where = f", branch {link.get('branch') or DEFAULT_BRANCH}" if backup else ""
            notes.insert(0, f"Ready: {out['project']}{where}, as {role}.")
        return done()
    except requests.RequestException as exc:
        logger.warning("GitLab project test for %s failed: %s", link.get("project"), exc)
        fails.append(tls.describe_error(exc) or f"GitLab didn't answer: {str(exc)[:200]}")
        return done()
