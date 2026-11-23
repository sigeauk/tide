"""Home: what needs the person signed in, on the active client, as five lists.

Each list comes from the code its own page uses, so Home and that page always agree:

- **Rule Monitoring:** the open problems by kind, errors first (``rule_issues.view`` grouped by issue,
  leaving out what is muted), how many rules need action by their worst problem, and how many began
  and stopped needing it in the last ``DAYS`` days (``rule_issues.flows``, as the Dashboard compares).
- **Rules to tune:** Rule Tuning's first rows, costliest first: alerts a day not needing action
  (``rule_tuning.page``).
- **Known gaps to review:** every known gap and Not applicable mark on a system's baseline technique
  whose Review by date has passed or comes within ``REVIEW_AHEAD`` days, soonest first.
- **Validations lapsing:** enabled rules whose validation has expired or is due soon, expired first
  and then the oldest check, with how many were validated and how many lapsed in the last ``DAYS``
  days (``past_figures.validation_flow``).
- **GitLab issues:** the open issues TIDE raised for the client's rules, newest first.

Each shows its first ``SHOWN`` and links to where the rest are. A list is worked out only for someone
who can open its page, and one that can't be worked out says so without stopping the others.
"""
import logging
from datetime import date, datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlencode

logger = logging.getLogger(__name__)

DAYS = 7
SHOWN = 5
REVIEW_AHEAD = 14
LAPSING = ("expired", "amber")
FAILED = "Could not work out this list: reload the page in a moment."


def _rule_url(rule_id: str, siem_id: str, space: str) -> str:
    """A rule's window, as its card opens it."""
    return f"/api/rules/{rule_id}/history-modal?" + urlencode({"space": space or "default", "siem_id": siem_id or ""})


# ── Rule Monitoring ──────────────────────────────────────────────────────────────────────────

def _counted(n: int, one: str) -> str:
    return f"{n} {one}" if n == 1 else f"{n} {one}s"


def _facts(group: Dict[str, Any], now: datetime) -> str:
    """A kind of problem's line: how many rules (and destinations) have it, and for how long."""
    from app.services.rule_issues import _age
    parts = [_counted(n, one) for n, one in ((group["rules"], "rule"), (group["count"] - group["rules"], "destination")) if n]
    age = _age(group["first_seen"], now)
    return " · ".join(parts + ([f"for {age}"] if age else []))


def monitoring_list(data: Dict[str, Any], moved: Optional[Dict[str, Any]], now: datetime) -> Dict[str, Any]:
    """Rule Monitoring's card from ``rule_issues.view`` (``data``) and ``rule_issues.flows`` (``moved``)."""
    from app.services import past_figures
    m = data["metrics"]
    kinds = [g for g in data["groups"] if g["kind"] == "issue"]          # Muted is a group of its own
    return {
        "count": m["rules"],
        "severities": [(s, m[k]) for s, k in (("error", "errors"), ("warning", "warnings"), ("info", "info")) if m[k]],
        "flow": past_figures.flow_lines(moved, DAYS)["rules"] if moved else None,
        "rows": [{"title": g["label"], "severity": g["severity"], "facts": _facts(g, now),
                   "url": "/rule-monitoring?" + urlencode({"issue": g["key"]})} for g in kinds[:SHOWN]],
        "more": max(0, len(kinds) - SHOWN),
        "url": "/rule-monitoring",
    }


def monitoring(db, client_id: str, now: datetime) -> Dict[str, Any]:
    from app.services import past_figures, rule_issues
    filters = {"show": "open", "group": "issue"}
    destinations = db.get_client_siems(client_id) or []
    with db.get_connection() as conn:
        data = rule_issues.view(conn, destinations, filters, now=now, client_id=client_id)
        moved = rule_issues.flows(conn, destinations, filters, past_figures.day_end(DAYS, now.date()), now=now)
    return {**monitoring_list(data, moved, now), "linked": bool(destinations)}


# ── Rules to tune ────────────────────────────────────────────────────────────────────────────

def tuning_list(rows: List[Dict[str, Any]], now: datetime) -> Dict[str, Any]:
    """Rule Tuning's first rows (``rule_tuning.page``, costliest first), each with its alerts a day, the
    share not needing action, its reasons, and new when its first reason began in the last ``DAYS``."""
    items = [{"name": r["name"], "destination": r["destination"], "per_day": r["per_day"], "share": r["share"],
              "reasons": [x["title"] + (f": {x['cause']}" if x["issue"] == "marked_for_tuning" and x["cause"] else "")
                          for x in r["reasons"]],
              "new": bool(r["since"] and r["since"] >= now - timedelta(days=DAYS)), "url": _rule_url(*r["key"])}
             for r in rows[:SHOWN]]
    return {"count": len(rows), "rows": items, "more": max(0, len(rows) - SHOWN), "url": "/rule-tuning"}


def tuning(db, client_id: str, now: datetime) -> Dict[str, Any]:
    from starlette.datastructures import QueryParams
    from app.services import rule_alerts, rule_tuning
    destinations = db.get_client_siems(client_id) or []
    with db.get_connection() as conn:
        data = rule_tuning.page(conn, destinations, rule_tuning.page_filters(QueryParams("")), client_id=client_id, now=now,
                                limits=rule_alerts.thresholds(db, client_id))
    return {**tuning_list(data["rows"], now), "linked": bool(destinations)}


# ── Known gaps to review ─────────────────────────────────────────────────────────────────────

def review_list(conn, today: date, client_filter: Tuple[str, list] = ("", [])) -> Dict[str, Any]:
    """The marks on baseline techniques to review by ``today`` + REVIEW_AHEAD days, soonest first.
    ``client_filter`` is ``inventory_engine._cf("b.", client_id)``: empty in a client's own database."""
    frag, params = client_filter
    rows = conn.execute(
        "SELECT b.system_id, sy.name, b.entity_id, s.title, COALESCE(b.override_type, 'gap'), b.reason, b.review_by "
        "FROM blind_spots b JOIN playbook_steps s ON s.id = b.entity_id JOIN systems sy ON sy.id = b.system_id "
        "WHERE b.entity_type = 'tactic' AND b.review_by IS NOT NULL AND b.review_by <= ?" + frag
        + " ORDER BY b.review_by, lower(sy.name), lower(s.title)",
        [today + timedelta(days=REVIEW_AHEAD)] + params).fetchall()
    items = [{"system_id": sid, "system": sname, "step_id": step_id, "title": title, "kind": kind,
              "reason": reason, "review_by": by, "due": by <= today,
              "url": f"/api/systems/{sid}/steps/{step_id}"}
             for sid, sname, step_id, title, kind, reason, by in rows]
    return {"count": len(items), "due": sum(i["due"] for i in items), "rows": items[:SHOWN],
            "more": max(0, len(items) - SHOWN), "url": "/systems"}


def reviews(db, client_id: str, now: datetime) -> Dict[str, Any]:
    from app.inventory_engine import _cf
    with db.get_connection() as conn:
        return review_list(conn, now.date(), _cf("b.", client_id))


# ── Validations lapsing ──────────────────────────────────────────────────────────────────────

def validation_list(rules: List[Any], names: Dict[Tuple[str, str], str], flow: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The rules (enabled, as Rule Health deduplicates them) whose validation has expired or is due
    soon: expired first, then the oldest check. ``names``: each destination's name."""
    lapsing = sorted((r for r in rules if r.validation_status in LAPSING),
                     key=lambda r: (r.validation_status != "expired", r.validation_date or datetime.min, (r.name or "").lower()))
    items = [{"name": r.name or r.rule_id, "status": r.validation_status, "checked": r.validation_date,
              "destination": names.get((r.siem_id, r.space or "default"), r.space),
              "url": _rule_url(r.rule_id, r.siem_id, r.space)} for r in lapsing[:SHOWN]]
    query = urlencode([("enabled", "true"), ("validation", "expired"), ("validation", "amber"), ("sort_validated", "asc")])
    return {"count": len(lapsing), "expired": sum(r.validation_status == "expired" for r in lapsing),
            "soon": sum(r.validation_status == "amber" for r in lapsing), "flow": flow,
            "rows": items, "more": max(0, len(lapsing) - SHOWN), "url": f"/rules?{query}"}


def validations(db, client_id: str, now: datetime) -> Dict[str, Any]:
    from app.api.rules import _get_filtered_rules, rule_filters_from
    from app.services import past_figures
    _all, rules = _get_filtered_rules(db, rule_filters_from({"enabled": "true"}), client_id)
    names = {(d["id"], str(d.get("space") or "default")): d.get("name") or d.get("space")
             for d in db.get_client_siems(client_id) or []}
    try:
        flow = past_figures.validation_flow(db, client_id, rules, DAYS, now=now)
    except Exception:
        logger.exception("Home: could not work out validations in %d days for client %s", DAYS, client_id)
        flow = None
    return validation_list(rules, names, flow)


# ── GitLab issues ────────────────────────────────────────────────────────────────────────────

def issue_list(issues: List[Dict[str, Any]], rule_names: Dict[Tuple[str, str, str], str]) -> Dict[str, Any]:
    """The open ones of ``gitlab_issues.every`` (newest first), each with what it is about: the rule it
    was raised for (``rule_names``: each rule's name), or the Rule Monitoring problem."""
    from app.services.rule_issues import KNOWN
    opened = [i for i in issues if i.get("state") == "opened"]
    items = []
    for i in opened[:SHOWN]:
        rules = [k for k in i["rules"] if k in rule_names]
        about = (rule_names[rules[0]] + (f" and {len(rules) - 1} more" if len(rules) > 1 else "")) if rules else ""
        if not about and i["causes"]:
            about = KNOWN[i["causes"][0][0]].title if i["causes"][0][0] in KNOWN else ""
        items.append({**i, "about": about, "for_rule": bool(rules),
                      "rule_url": _rule_url(*rules[0]) if len(rules) == 1 else ""})
    projects = {i["web_url"].rsplit("/", 1)[0] for i in opened if i.get("web_url")}
    return {"count": len(opened), "rows": items, "more": max(0, len(opened) - SHOWN),
            "url": projects.pop() if len(projects) == 1 else ""}


def issues(db, client_id: str, now: datetime) -> Dict[str, Any]:
    from app.services import gitlab_issues
    with db.get_connection() as conn:
        every = gitlab_issues.every(conn)
        wanted = {k for i in every if i.get("state") == "opened" for k in i["rules"]}
        names = {}
        if wanted:
            keys = sorted(wanted)
            names = {(r, s, sp): n for r, s, sp, n in conn.execute(
                "SELECT rule_id, siem_id, space, name FROM detection_rules WHERE EXISTS (SELECT 1 FROM (SELECT "
                "unnest(?::VARCHAR[]) AS r, unnest(?::VARCHAR[]) AS s, unnest(?::VARCHAR[]) AS sp) x "
                "WHERE x.r = rule_id AND x.s = siem_id AND x.sp = space)",
                [[k[0] for k in keys], [k[1] for k in keys], [k[2] for k in keys]]).fetchall()}
    linked = bool(db.list_client_gitlab_projects(client_id))
    return {**issue_list(every, names), "linked": linked}


# ── the page ─────────────────────────────────────────────────────────────────────────────────

# (key, the page whose permission shows it, what works it out), in the page's order.
LISTS: Tuple[Tuple[str, str, Callable], ...] = (
    ("monitoring", "page:rules", monitoring),
    ("tuning", "page:rule_tuning", tuning),
    ("reviews", "page:systems", reviews),
    ("validations", "page:rules", validations),
    ("issues", "page:rules", issues),
)


def page_context(db, client_id: Optional[str], user, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Each list this user may see on ``client_id``, by key; a list that can't be worked out is
    ``{"failed": FAILED}``. None of them without a client."""
    now = now or datetime.now()
    lists: Dict[str, Any] = {}
    if not client_id:
        return {"lists": lists, "days": DAYS, "review_ahead": REVIEW_AHEAD}
    for key, resource, build in LISTS:
        if user is not None and not user.can_read(resource):
            continue
        try:
            lists[key] = build(db, client_id, now)
        except Exception:
            logger.exception("Home: could not work out %s for client %s", key, client_id)
            lists[key] = {"failed": FAILED}
    return {"lists": lists, "days": DAYS, "review_ahead": REVIEW_AHEAD}
