"""Wazuh, read-only: its manager's API and its indexer.

A Wazuh SIEM is a ``siem_inventory`` row with ``siem_type = 'wazuh'``. Its Kibana and Elasticsearch
columns stay empty, so nothing that calls Kibana ever reaches it. Its settings are in ``extra_config``:

    manager_url, api_user        the manager's API (``https://manager:55000``); the API password is the
                                 row's ``api_token_enc``, sealed like every SIEM's token
    indexer_url, indexer_user,   the indexer (``https://indexer:9200``), with its password sealed by
    indexer_password_enc         app.services.credentials

TIDE only reads. It needs an API user allowed ``rules:read``, ``agent:read``, ``group:read`` and
``sca:read``, and an indexer user allowed to read ``wazuh-alerts-*`` and
``wazuh-states-vulnerabilities-*`` (docs/CONFIGURATION.md). A client's Wazuh destination is the
manager and one of its agent groups, or ``*`` for all its agents.

Every request passes ``verify`` itself (tls.Session): requests lets the container's
REQUESTS_CA_BUNDLE override a session's own setting.
"""
import json
import logging
import re
import time
from typing import Optional

import requests

from app.services import credentials, errors, tls

logger = logging.getLogger(__name__)

ALL_AGENTS = "*"
MANAGER_AGENT = "000"            # the manager's own agent: not a device of anyone's
ALERTS_INDEX = "wazuh-alerts-*"
VULNERABILITIES_INDEX = "wazuh-states-vulnerabilities-*"
MIN_VERSION = (4, 8)
FIRST_UNSUPPORTED_MAJOR = 5
PAGE_SIZE = 500
RULES_PAGE_SIZE = 10000         # the API takes up to 100,000; 4.14's stock ruleset is about 4,500 rules
ALERT_BUCKETS = 1000            # composite buckets a page
ALERT_PAGES = 500
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 30

RULE_TYPE, RULE_LANGUAGE = "wazuh", "wazuh_xml"     # detection_rules.rule_type / rule_language
# A rule's level as a severity, in the Wazuh dashboard's bands: 0-6 low, 7-11 medium, 12-14 high, 15 critical.
LEVEL_BANDS = ((15, "critical"), (12, "high"), (7, "medium"), (0, "low"))
COMPLIANCE_KEYS = (("pci_dss", "PCI DSS"), ("gdpr", "GDPR"), ("hipaa", "HIPAA"), ("nist_800_53", "NIST 800-53"),
                   ("tsc", "TSC"), ("gpg13", "GPG13"))


def severity(level) -> str:
    try:
        level = int(level)
    except (TypeError, ValueError):
        return "low"
    return next(name for floor, name in LEVEL_BANDS if level >= floor)


class WazuhError(errors.FailureError):
    """A Wazuh request that didn't succeed: ``why``, a reason a person can act on, and its error code
    (``code``: the failure's, else by the answer's ``status``, else S502)."""

    def __init__(self, reason: str, status: Optional[int] = None):
        self.status = status
        super().__init__(reason if isinstance(reason, errors.Failure)
                         else errors.Failure(errors.answer_code("S", status or 0), reason))


def _extra(value) -> dict:
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value) if value else {}
    except (TypeError, ValueError):
        return {}


def addresses(siem: dict) -> dict:
    """A Wazuh SIEM row's addresses and users, without its passwords (for cards and lists)."""
    extra = _extra(siem.get("extra_config"))
    return {"manager_url": (extra.get("manager_url") or "").rstrip("/"), "api_user": extra.get("api_user") or "",
            "indexer_url": (extra.get("indexer_url") or "").rstrip("/"), "indexer_user": extra.get("indexer_user") or ""}


def settings(siem: dict) -> dict:
    """A Wazuh SIEM row's connection settings, passwords in the clear (the database layer has already
    revealed the row's ``api_token_enc``)."""
    extra = _extra(siem.get("extra_config"))
    return dict(addresses(siem), api_password=siem.get("api_token_enc") or "",
                indexer_password=credentials.reveal_or_none(extra.get("indexer_password_enc")) or "",
                verify=tls.verify_arg(siem.get("tls_verify")))


def stored_config(manager_url: str, api_user: str, indexer_url: str, indexer_user: str,
                  indexer_password: str, previous=None) -> dict:
    """The ``extra_config`` to save. The indexer password is sealed, and kept from ``previous`` (the
    row's current ``extra_config``) when none is given."""
    sealed = credentials.seal(indexer_password) if indexer_password else _extra(previous).get("indexer_password_enc")
    return {"manager_url": manager_url.strip().rstrip("/"), "api_user": api_user.strip(),
            "indexer_url": indexer_url.strip().rstrip("/"), "indexer_user": indexer_user.strip(),
            "indexer_password_enc": sealed}


def _failure(exc: Exception, what: str) -> errors.Failure:
    """Why a request to ``what`` raised, with its code (S495 certificate, S503 not reached, S504 slow)."""
    return errors.connection_failure("S", what, exc)


def _api_reason(resp) -> str:
    try:
        body = resp.json()
        detail = body.get("detail") or body.get("title") or ""
    except ValueError:
        detail = ""
    return f"HTTP {resp.status_code}" + (f": {detail}" if detail else "")


class Manager:
    """The manager's API, signed in as TIDE's read-only user. Its token (15 minutes, by default) is
    asked for on first use, and again once when the manager answers 401 because it expired."""

    def __init__(self, url: str, user: str, password: str, verify):
        self.url = (url or "").rstrip("/")
        self._auth = (user, password)
        self._session = tls.Session()
        self._session.verify = verify
        self._token = None

    @classmethod
    def from_settings(cls, s: dict) -> "Manager":
        return cls(s["manager_url"], s["api_user"], s["api_password"], s["verify"])

    def sign_in(self) -> None:
        try:
            resp = self._session.post(f"{self.url}/security/user/authenticate", params={"raw": "true"},
                                      auth=self._auth, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
        except requests.RequestException as exc:
            raise WazuhError(_failure(exc, "The Wazuh manager")) from exc
        if resp.status_code == 401:
            raise WazuhError("The API user or password is wrong", 401)
        if resp.status_code != 200 or not resp.text.strip():
            raise WazuhError(f"The Wazuh manager refused to sign in ({_api_reason(resp)})", resp.status_code)
        self._token = resp.text.strip()

    def _request(self, path: str, params: Optional[dict]):
        """GET ``path``: anything but 200 raises WazuhError with the manager's reason."""
        for attempt in (1, 2):
            if not self._token:
                self.sign_in()
            try:
                resp = self._session.get(f"{self.url}{path}", params=params or None,
                                         headers={"Authorization": f"Bearer {self._token}"},
                                         timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
            except requests.RequestException as exc:
                raise WazuhError(_failure(exc, "The Wazuh manager")) from exc
            if resp.status_code == 401 and attempt == 1:
                self._token = None
                continue
            break
        if resp.status_code != 200:
            raise WazuhError(_api_reason(resp), resp.status_code)
        return resp

    def get(self, path: str, **params) -> dict:
        """``path``'s JSON."""
        resp = self._request(path, params)
        try:
            return resp.json()
        except ValueError as exc:
            raise WazuhError("The Wazuh manager's answer wasn't JSON", resp.status_code) from exc

    def items(self, path: str, page_size: int = 0, **params) -> list:
        """Every ``affected_items`` of a list endpoint, a page at a time. All of them or WazuhError:
        a list cut short must never pass for the whole (a sync removes what it doesn't list)."""
        out: list = []
        while True:
            data = self.get(path, offset=len(out), limit=page_size or PAGE_SIZE, **params).get("data") or {}
            page = data.get("affected_items") or []
            total = int(data.get("total_affected_items") or 0)
            out += page
            if len(out) >= total:
                return out
            if not page:
                raise WazuhError(f"The Wazuh manager listed {len(out)} of {total} from {path}")

    def version(self) -> str:
        return str((self.get("/").get("data") or {}).get("api_version") or "")

    def groups(self) -> list:
        return sorted((g["name"] for g in self.items("/groups") if g.get("name")), key=str.lower)

    def rules(self) -> list:
        """Every rule the manager has, enabled or not (one page holds a stock ruleset)."""
        return self.items("/rules", page_size=RULES_PAGE_SIZE)

    def agent_ids(self, group: str) -> Optional[list]:
        """The ids of a destination's agents: ``group``'s, or None for ``*`` (every agent, the manager
        included)."""
        if group == ALL_AGENTS:
            return None
        return sorted(str(a["id"]) for a in self.items("/agents", group=group, select="id") if a.get("id"))

    def agents(self, group: str) -> list:
        """A destination's agents in full (id, name, ip, os, group, status, lastKeepAlive, version): the
        group's, or every agent but the manager itself (agent 000) for ``*``."""
        params = {} if group == ALL_AGENTS else {"group": group}
        return [a for a in self.items("/agents", **params) if str(a.get("id") or "") not in ("", MANAGER_AGENT)]

    def sca(self, agent_id: str) -> list:
        """An agent's SCA policies (``GET /sca/{agent}``): policy_id, name, pass, fail, invalid, total_checks,
        score, end_scan."""
        return self.items(f"/sca/{agent_id}")

    def sca_checks(self, agent_id: str, policy_id: str) -> list:
        """Every check of one policy on one agent: id, title, result (passed / failed / not applicable),
        rationale, remediation, compliance (a list of {key, value}: cis, mitre_techniques, …)."""
        return self.items(f"/sca/{agent_id}/checks/{policy_id}")

    def rule_file(self, filename: str, relative_dirname: str) -> str:
        """A rule file's XML, as Wazuh has it (``relative_dirname``: ``ruleset/rules`` or ``etc/rules``)."""
        return self._request(f"/rules/files/{filename}", {"raw": "true", "relative_dirname": relative_dirname}).text


class Indexer:
    """The indexer (OpenSearch), signed in as TIDE's read-only indexer user."""

    def __init__(self, url: str, user: str, password: str, verify):
        self.url = (url or "").rstrip("/")
        self._session = tls.Session()
        self._session.verify = verify
        self._session.auth = (user, password)

    @classmethod
    def from_settings(cls, s: dict) -> "Indexer":
        return cls(s["indexer_url"], s["indexer_user"], s["indexer_password"], s["verify"])

    def search(self, index: str, body: dict) -> dict:
        try:
            resp = self._session.post(f"{self.url}/{index}/_search", json=body,
                                      timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
        except requests.RequestException as exc:
            raise WazuhError(_failure(exc, "The Wazuh indexer")) from exc
        if resp.status_code == 401:
            raise WazuhError("The indexer user or password is wrong", 401)
        if resp.status_code == 403:
            raise WazuhError(f"The indexer user can't read {index}: give its role read on {index}", 403)
        if resp.status_code != 200:
            raise WazuhError(f"The Wazuh indexer answered HTTP {resp.status_code}", resp.status_code)
        return resp.json()

    def vulnerabilities(self, agent_ids: list) -> list:
        """Every current vulnerability document of ``agent_ids``' agents (``wazuh-states-vulnerabilities-*``
        holds what is vulnerable now; a fixed CVE leaves it). All of them or WazuhError: a partial read
        must never resolve anything."""
        if not agent_ids:
            return []
        docs, after = [], None
        for _page in range(ALERT_PAGES):
            body = {"size": ALERT_BUCKETS, "sort": [{"_id": "asc"}], "query": {"terms": {"agent.id": list(agent_ids)}},
                    **({"search_after": after} if after else {})}
            hits = (self.search(VULNERABILITIES_INDEX, body).get("hits") or {}).get("hits") or []
            docs += [h.get("_source") or {} for h in hits]
            if len(hits) < ALERT_BUCKETS:
                return docs
            after = hits[-1].get("sort")
        raise WazuhError(f"The Wazuh indexer holds more vulnerabilities than TIDE reads ({len(docs)}+)")

    def agent_alert_counts(self, agent_ids: list, days: int) -> dict:
        """Each agent's alerts per day (UTC) over the last ``days``: ``{(agent id, day): alerts}``."""
        out: dict = {}
        if not agent_ids:
            return out
        composite = {"size": ALERT_BUCKETS, "sources": [
            {"agent": {"terms": {"field": "agent.id"}}},
            {"day": {"date_histogram": {"field": "timestamp", "calendar_interval": "day", "format": "yyyy-MM-dd"}}}]}
        query = {"bool": {"filter": [{"range": {"timestamp": {"gte": f"now-{int(days)}d/d"}}},
                                     {"terms": {"agent.id": list(agent_ids)}}]}}
        for _page in range(ALERT_PAGES):
            found = self.search(ALERTS_INDEX, {"size": 0, "track_total_hits": False, "query": query,
                                               "aggs": {"counts": {"composite": composite}}})
            agg = (found.get("aggregations") or {}).get("counts") or {}
            for b in agg.get("buckets") or []:
                k = b.get("key") or {}
                out[(str(k.get("agent") or ""), str(k.get("day") or ""))] = int(b.get("doc_count") or 0)
            if not agg.get("after_key") or len(agg.get("buckets") or []) < ALERT_BUCKETS:
                return out
            composite["after"] = agg["after_key"]
        return out

    def alert_counts(self, agent_ids: Optional[list], days: int) -> dict:
        """Each rule's alerts per day (UTC) over the last ``days``, from ``agent_ids``' agents (None: every
        agent), in rule_alerts.store's shape: ``{"ok": True, "rows": [(rule id, rule id, day, "open",
        alerts)]}`` or ``{"ok": False, "error": why}``. Wazuh alerts have no workflow status: all are open.
        A composite aggregation, read ``ALERT_BUCKETS`` at a time, as Kibana's are."""
        if agent_ids is not None and not agent_ids:
            return {"ok": True, "rows": []}
        filters = [{"range": {"timestamp": {"gte": f"now-{int(days)}d/d"}}}]
        if agent_ids is not None:
            filters.append({"terms": {"agent.id": list(agent_ids)}})
        composite = {"size": ALERT_BUCKETS, "sources": [
            {"rule_id": {"terms": {"field": "rule.id"}}},
            {"day": {"date_histogram": {"field": "timestamp", "calendar_interval": "day", "format": "yyyy-MM-dd"}}}]}
        rows = []
        try:
            for _page in range(ALERT_PAGES):
                found = self.search(ALERTS_INDEX, {"size": 0, "track_total_hits": False,
                                                   "query": {"bool": {"filter": filters}},
                                                   "aggs": {"counts": {"composite": composite}}})
                agg = (found.get("aggregations") or {}).get("counts") or {}
                for b in agg.get("buckets") or []:
                    k = b.get("key") or {}
                    rid = str(k.get("rule_id") or "")
                    rows.append((rid, rid, str(k.get("day") or ""), "open", int(b.get("doc_count") or 0)))
                if not agg.get("after_key") or len(agg.get("buckets") or []) < ALERT_BUCKETS:
                    return {"ok": True, "rows": rows}
                composite["after"] = agg["after_key"]
        except WazuhError as exc:
            return {"ok": False, "status": exc.status, "error": str(exc)}
        return {"ok": True, "rows": rows, "truncated": True}


def parse_version(text: str) -> tuple:
    return tuple(int(n) for n in re.findall(r"\d+", (text or "").split("-")[0])[:3])


def version_problem(text: str) -> Optional[str]:
    """Why TIDE can't read this Wazuh version, or None when it can."""
    v = parse_version(text)
    if not v:
        return f"Could not read the Wazuh version from {text!r}"
    if v[:2] < MIN_VERSION:
        return f"Wazuh {text} is older than 4.8, the first version TIDE reads: upgrade Wazuh"
    if v[0] >= FIRST_UNSUPPORTED_MAJOR:
        return f"Wazuh {text} isn't supported yet: TIDE reads Wazuh 4.8 to 4.x"
    return None


SETTINGS_NAMES = (("manager_url", "manager API URL"), ("api_user", "API user"), ("api_password", "API password"),
                  ("indexer_url", "indexer URL"), ("indexer_user", "indexer user"),
                  ("indexer_password", "indexer password"))


def missing_settings(s: dict) -> list:
    return [name for key, name in SETTINGS_NAMES if not s.get(key)]


def test_connection(s: dict) -> dict:
    """Every check TIDE's reads depend on, each recorded on its own: sign in, the version, each API
    permission, each index. The same shape as the Elastic test
    (elastic_helper.test_elastic_connection_full), with the manager's agent groups, and ``*`` for all
    agents, as its ``spaces``."""
    result: dict = {"ok": False, "spaces": [], "spaces_label": "Agent groups", "version": "", "checks": []}

    def record(name, endpoint, ok, detail, status_code=None, started=None, code=None):
        result["checks"].append({
            "name": name, "endpoint": endpoint, "ok": bool(ok), "status_code": status_code, "detail": str(detail),
            "code": str(code) if code else None, "body_excerpt": None,
            "elapsed_ms": int((time.monotonic() - started) * 1000) if started is not None else None,
        })

    missing = missing_settings(s)
    if missing:
        record("settings", "", False, "Enter the " + ", ".join(missing))
        return result

    manager = Manager.from_settings(s)
    started = time.monotonic()
    try:
        manager.sign_in()
    except WazuhError as exc:
        record("sign_in", "/security/user/authenticate", False, str(exc), exc.status, started, exc.code)
    else:
        record("sign_in", "/security/user/authenticate", True, f"Signed in as {s['api_user']}", 200, started)
        _manager_checks(manager, record, result)

    indexer = Indexer.from_settings(s)
    for name, index, what in (("alerts_index", ALERTS_INDEX, "alerts"),
                              ("vulnerabilities_index", VULNERABILITIES_INDEX, "vulnerabilities")):
        started = time.monotonic()
        try:
            found = indexer.search(index, {"size": 0, "track_total_hits": True})
        except WazuhError as exc:
            record(name, f"/{index}/_search", False, str(exc), exc.status, started, exc.code)
            continue
        total = ((found.get("hits") or {}).get("total") or {}).get("value") or 0
        record(name, f"/{index}/_search", True, f"Reads {what} ({total:,})" if total else f"Reads {index}: no {what} yet",
               200, started)

    result["ok"] = all(c["ok"] for c in result["checks"])
    return result


def _manager_checks(manager: Manager, record, result: dict) -> None:
    started = time.monotonic()
    try:
        version = manager.version()
    except WazuhError as exc:
        record("version", "/", False, str(exc), exc.status, started, exc.code)
    else:
        problem = version_problem(version)
        result["version"] = version
        record("version", "/", not problem, problem or f"Wazuh {version}", 200, started)

    def permission(name, path, what, grant, success, **params):
        started = time.monotonic()
        try:
            data = manager.get(path, **params).get("data") or {}
        except WazuhError as exc:
            detail = errors.with_code(f"The API user can't read {what}: allow it {grant}", exc.code)                 if exc.status == 403 else str(exc)
            record(name, path, False, detail, exc.status, started, exc.code)
            return None
        record(name, path, True, success(data), 200, started)
        return data

    count = lambda data: int(data.get("total_affected_items") or 0)  # noqa: E731
    permission("rules", "/rules", "rules", "rules:read on rule:file:*", lambda d: f"Reads {count(d):,} rules", limit=1)
    agents = permission("agents", "/agents", "agents", "agent:read on agent:id:*",
                        lambda d: f"Reads {count(d):,} agents (the manager is agent 000)", limit=1)

    started = time.monotonic()
    try:
        groups = manager.groups()
    except WazuhError as exc:
        detail = (errors.with_code("The API user can't read agent groups: allow it group:read on group:id:*", exc.code)
                  if exc.status == 403 else str(exc))
        record("groups", "/groups", False, detail, exc.status, started, exc.code)
    else:
        result["spaces"] = [ALL_AGENTS] + groups
        record("groups", "/groups", True, f"Reads {len(groups)} agent group{'s' if len(groups) != 1 else ''}",
               200, started)

    first = ((agents or {}).get("affected_items") or [{}])[0].get("id")
    if not first:
        record("sca", "/sca/{agent}", False, "Not checked: the API user can't read any agent, so TIDE can't try "
               "reading SCA results")
        return
    permission("sca", f"/sca/{first}", "SCA results", "sca:read on agent:id:*",
               lambda d: f"Reads SCA results (agent {first}: {count(d)} polic{'ies' if count(d) != 1 else 'y'})",
               limit=1)


def agent_groups(siem: dict) -> Optional[list]:
    """The destinations a Wazuh SIEM offers: ``*`` (all agents), then its agent groups. None when the
    manager can't be read now."""
    s = settings(siem)
    if not (s["manager_url"] and s["api_user"] and s["api_password"]):
        return None
    try:
        return [ALL_AGENTS] + Manager.from_settings(s).groups()
    except WazuhError as exc:
        logger.info("Could not list the agent groups of Wazuh SIEM %s: %s", siem.get("id"), exc)
        return None
