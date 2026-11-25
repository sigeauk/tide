"""Simulations (#118, app.services.sim): the Simulations page, where a Sim Admin starts a simulation on
one of the client's SIEMs (with players, or none yet), follows it, adds players while it runs and ends
it (page:simulations), and the Simulation page, where the
players chosen for it answer its questions (page:simulation; each call also checks the person is one of
its players). Reading needs read and changing needs write on each (main.py's maps).

A simulation runs on the SIEM of one of the client's destinations, in a space of its own that is never a
destination (CLAUDE.md section 6): the SIEM is chosen by its id among the client's, never by a space.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from app.api.deps import ActiveClient, DbDep, RequireUser
from app.services import siem_kinds
from app.services.ttl_cache import TTLCache
from app.services.sim import client, game, packs, rules, simulation

logger = logging.getLogger(__name__)

router = APIRouter(tags=["simulations"])

DETAIL = "partials/simulation_detail.html"
LIST = "partials/simulation_list.html"
PLAY = "partials/simulation_play.html"
QUESTION = "partials/simulation_question.html"
BOARD = "partials/simulation_board.html"
DASHBOARD = "partials/simulation_dashboard.html"
ANSWERS_TAB = "partials/simulation_answers.html"
TAB = "partials/simulation_tab.html"
PLAYERS = "partials/simulation_players_dialog.html"
LIVE = "partials/simulation_live.html"
SCENARIO_DIALOG = "partials/simulation_scenario_dialog.html"
NEW_PARTS = "partials/simulation_new_parts.html"
STATES = {"setting_up": "Setting up", "replaying": "Replaying", "playing": "Playing", "ending": "Ending",
          "ended": "Ended", "cleaning_up": "Cleaning up", "failed": "Failed"}
ANSWERS = {"right": "Right", "wrong": "Not right: try again.", "solved": "You've answered it already.",
           "too_fast": "Wait a moment between answers.", "closed": "This simulation isn't taking answers.",
           "not_yet": "It's still setting up: answers open when the replay starts.",
           "not_player": "You aren't one of this simulation's players.", "unknown": "There is no such question."}


def _store(db, client_id: str) -> simulation.TenantStore:
    return simulation.TenantStore(db, client_id)


def _who(user) -> tuple[str, str]:
    """A user as a simulation keeps them: (TIDE user id, their name now)."""
    if user is None:
        return "dev-user-001", "Local Developer"
    return str(user.id), str(getattr(user, "label", None) or user.name or user.username)


def _client_users(db, client_id: str) -> list[dict]:
    """The client's users who can be chosen to play, by name."""
    return sorted(db.get_client_users(client_id) or [], key=lambda u: (u.get("full_name") or u["username"]).lower())


def _people(db, client_id: str, chosen) -> list[tuple[str, str]]:
    """The client's users among the ids ticked, as a simulation keeps its players: (id, name). An id
    that isn't one of the client's users is left out."""
    chosen = {str(u) for u in chosen}
    return [(u["id"], u.get("full_name") or u["username"]) for u in db.get_client_users(client_id) or []
            if u["id"] in chosen]


def _actor(user) -> Optional[str]:
    """Who TIDE's history names for what a simulation sets up and removes in the client."""
    return user.username if user else None


def siems(db) -> List[Dict[str, str]]:
    """The Elastic SIEMs in TIDE's inventory a simulation can run on: active, with both addresses and a
    key. Any of them, as the client's Integrations can link any (the simulation's new space becomes
    the client's destination)."""
    out = []
    for d in db.list_siem_inventory() or []:
        if d.get("is_active") is False or not siem_kinds.is_elastic(d) or not (d.get("elasticsearch_url") and d.get("kibana_url")):
            continue
        if not (db.get_siem_inventory_item(d["id"]) or {}).get("api_token_enc"):
            continue
        out.append({"id": d["id"], "label": str(d.get("label") or d["id"]),
                    "kibana_url": str(d.get("kibana_url") or "").rstrip("/")})
    return sorted(out, key=lambda s: s["label"].lower())


def scenarios() -> List[Dict[str, Any]]:
    """The scenarios a simulation can play, with what a Sim Admin chooses between."""
    out = []
    for sc in packs.catalogue().values():
        if not sc.ready:
            continue
        try:
            questions, rule_count = len(game.questions(sc)), len(rules.specs(sc))
        except packs.PackError as exc:
            logger.warning("Scenario %s left out: %s", sc.id, exc)
            continue
        out.append({"id": sc.id, "label": sc.label, "levels": sc.levels(), "checked": sc.checked_at,
                    "events": {lv: sc.window_events(lv) for lv in sc.levels()}, "questions": questions,
                    "rules": rule_count})
    return out


def _names() -> Dict[str, str]:
    return {sc.id: sc.label for sc in packs.catalogue().values()}


def _kibana_link(db, client_id: str, sim: dict) -> str:
    """Its space's alerts in Kibana, while the space is there (until a clean-up deletes it)."""
    url = ((db.get_siem_inventory_item(sim["siem_id"]) or {}).get("kibana_url") or "").rstrip("/")
    deleted = ((sim.get("cleanup") or {}).get("space") or {}).get("ok")
    return f"{url}/s/{sim['space']}/app/security/alerts" if url and not deleted else ""


def for_namespace(text: str, namespace: str) -> str:
    """A write-up's searches, written for the scenarios' own data streams (logs-…-botes), for a
    simulation's (logs-…-<namespace>)."""
    return re.sub(r"\blogs-([\w.*]+)-botes\b", lambda m: f"logs-{m.group(1)}-{namespace}", text)


def player_writeup(text: str, namespace: str) -> str:
    """A write-up as a player sees it once answered: for their simulation's data, without the notes
    on TIDE's own rules (for the Sim Admin)."""
    kept = [p for p in re.split(r"\n\s*\n", text) if not p.lstrip().startswith("**With TIDE:**")]
    return for_namespace("\n\n".join(kept), namespace)


def answer_parts(writeup: str) -> Dict[str, str]:
    """A write-up as the Answers tab and a player's answered question show it (#126): its ``title`` (its
    "### N." heading), its ``answer`` (the "**Answer: …**" line, set apart from the searches), and the
    ``rest``: how to find it, its searches and, for the Sim Admin, the notes on TIDE's rules. ``answer_md``
    is the answer as the box shows it: the value in bold, then what the line adds after it ("(6.17)",
    ", looked up at 16:48:12")."""
    lines = writeup.strip().splitlines()
    title = lines.pop(0)[4:].strip() if lines and lines[0].startswith("### ") else ""
    text = "\n".join(lines)
    m = re.search(r"^\*\*Answer:\s*(.+?)\*\*(.*)$", text, re.M)
    if not m:
        return {"title": title, "answer": "", "answer_md": "", "rest": text.strip()}
    value, more = m.group(1).strip(), m.group(2).rstrip()
    value = value[:-1] if value.endswith(".") else value      # "**Answer: 23.22.63.114.** It is also…"
    return {"title": title, "answer": value, "answer_md": f"**{value}**{more}",
            "rest": (text[:m.start()] + text[m.end():]).strip()}


def saved_searches(writeup: str) -> List[tuple]:
    """The searches in a question's write-up a Sim Admin can save in Kibana (#126): ``[(language,
    search)]``, its KQL and ES|QL ones. Discover can't save an EQL search."""
    return [(lang, body.strip()) for lang, body in re.findall(r"^```(esql|kql)\n(.*?)^```", writeup, re.M | re.S)]


# ── The Simulations page (Sim Admins) ──────────────────────────────────────────────────────────

TABS = ("run", "dashboard", "answers")


def page_context(db, client_id: str, user, tab: str = "") -> Dict[str, Any]:
    store = _store(db, client_id)
    sims = simulation.list_all(store)
    return {"siems": siems(db), "scenarios": scenarios(), "noise_levels": packs.NOISE_LEVELS,
            "users": _client_users(db, client_id),
            "sims": sims, "names": _names(), "states": STATES,
            "can_run": user is None or user.can_write("page:simulations"),
            "selected": None, "tab": tab if tab in TABS else "run", "focus": _focus(sims)}


def _focus(sims: list) -> Optional[str]:
    """The simulation the Dashboard and Answers open on: one still running, else the latest."""
    live = [s for s in sims if s["state"] in (*simulation.ACTIVE, *simulation.OPEN) and not s["interrupted"]]
    return (live or sims or [{"id": None}])[0]["id"]


def _live(sim: dict) -> bool:
    """Still changing (setting up, replaying, played or ending): its parts are asked for again."""
    return sim["state"] in (*simulation.ACTIVE, *simulation.OPEN) and not sim["interrupted"]


def _questions(sim: dict, shown: list) -> list:
    """Each of the simulation's scenarios whose questions are shown (``shown``, simulation.question_scenarios),
    with its questions, each with its write-up for its own data (``answer_parts``) and how many of its
    searches can be saved in Kibana."""
    out = []
    for sid in shown:
        try:
            sc = packs.scenario(sid)
            items = []
            for q in game.questions(sc):
                text = for_namespace(q.writeup, sim["namespace"])
                items.append((q, answer_parts(text), len(saved_searches(text))))
            out.append((sc, items))
        except packs.PackError:
            continue
    return out


# ── One simulation, as the Run tab shows it ────────────────────────────────────────────────────

PART_NAMES = {"logs": "its logs", "rules": "its rules", "tide": "set up in TIDE", "questions": "its questions"}
PART_ITEMS = {   # a row's ⋮, for a part not done when it was added: (its label, icon, what it asks first)
    "rules": ("Make its rules", "shield", "Make {name}'s rules in the simulation's space? Where it is set up in TIDE, "
                                          "they are mapped onto its systems."),
    "tide": ("Set it up in TIDE", "monitor", "Set {name} up in TIDE: its baseline, systems and threat actor, with its "
                                             "rules in the space mapped?"),
    "questions": ("Show its questions", "book-open", "Show {name}'s questions to the players? They can't be hidden again."),
}


def _nth(n: int) -> str:
    return f"{n}{'th' if 10 <= n % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')}"


def _and(items: list) -> str:
    return " and ".join([", ".join(items[:-1]), items[-1]] if len(items) > 1 else items)


def _question_count(sc: Optional[packs.Scenario]) -> int:
    try:
        return len(game.questions(sc)) if sc else 0
    except packs.PackError:
        return 0


def _rows(sim: dict, parts: list, reps: list, rule_rows: list, objs: list, names: dict) -> list:
    """Each scenario as the Scenarios table shows it: what was made for it, its replays not yet finished
    (how far each has got, or what a queued one waits for), what its last finished replay did, and the
    parts it can still be given."""
    unfinished = [r for r in reps if r["state"] in simulation.WAITING]
    out = []
    for p in parts:
        sid = p["scenario"]
        try:
            sc = packs.scenario(sid)
        except packs.PackError:
            sc = None
        asked = _question_count(sc)
        mine = [r for r in reps if r["scenario"] in (sid, "")]          # "": an older simulation's, of every scenario
        live = []
        for r in mine:
            if r["state"] not in simulation.WAITING:
                continue
            total = sc.window_events(r["noise"]) if sc else None
            sent = int((r["progress"] or {}).get("sent") or 0)
            before = [names.get(x["scenario"], x["scenario"]) for x in unfinished if x["n"] < r["n"]] if r["after"] else []
            live.append({**r, "sent": sent, "total": total, "pct": min(100, sent * 100 // total) if total else None,
                         "again": f" for the {_nth(r['pass'])} time" if (r["pass"] or 1) > 1 else "",
                         "waits_for_rules": r["state"] == simulation.QUEUED and p["state"] == "setting_up",
                         "before": list(dict.fromkeys(before)),
                         "original": ((r["progress"] or {}).get("original_time") or "")[11:16]})
        done = [r for r in mine if r["state"] not in simulation.WAITING]
        made_in_tide = [o for o in objs if o.get("scenario") == sid and o["kind"] in client.IN_TIDE]
        systems = sum(1 for o in made_in_tide if o["kind"] == client.SYSTEM)
        rule_count = sum(1 for r in rule_rows if r["scenario"] == sid and r["state"] == "created")
        made = []
        if p["rules"]:
            made.append(f"{rule_count} rule{'' if rule_count == 1 else 's'}")
        if p["tide"]:
            made.append(f"baseline and {systems} system{'' if systems == 1 else 's'} in TIDE" if made_in_tide else "set up in TIDE")
        if p["questions"] and asked:
            made.append(f"{asked} questions")
        out.append({"part": p, "scenario": sc, "label": names.get(sid, sid), "made": made, "live": live,
                    "summary": _summary([r for r in done if r["state"] != simulation.CANCELLED] or done),
                    "missing": [k for k in ("rules", "tide", "questions") if not p[k] and (k != "questions" or asked)]})
    return out


def _summary(done: list) -> tuple[str, str]:
    """(what a scenario's finished replays did, its text class): the last, and how many were replayed."""
    if not done:
        return "Not replayed", "text-secondary"
    last, times = done[-1], sum(1 for r in done if r["state"] == simulation.REPLAYED)
    sent = int((last["progress"] or {}).get("sent") or 0)
    at = f" at {last['finished_at']:%H:%M}" if last.get("finished_at") else ""
    if last["state"] == simulation.FAILED:
        return f"Could not replay it: {last['error'] or 'no reason given'}", "text-danger"
    if last["state"] == simulation.CANCELLED:
        return "Its replay was cancelled", "text-secondary"
    if last["state"] == simulation.STOPPED:
        return f"Stopped{at}, after {sent:,} events", "text-secondary"
    return (f"Replayed{'' if times == 1 else f' {times} times'}: {sent:,} events, the last done{at}", "")


def _activity(sim: dict, parts: list, reps: list, players: list, objs: list, names: dict, limit: int = 50) -> list:
    """What happened in the simulation, newest first: its start, each scenario added with its parts, each
    replay asked for, started (when it waited) and finished, each player added, each problem met, its end."""
    events: list = []

    def add(at, text: str, warn: bool = False) -> None:
        if at:
            events.append((at, len(events), text, warn))

    def name(sid: str) -> str:
        return names.get(sid, sid) if sid else "Every scenario"

    add(sim["created_at"], f"{sim['created_by']} started it")
    for p in parts:
        asked = [PART_NAMES[k] for k in ("rules", "tide", "questions", "logs") if p[k]]
        add(p["added_at"], f"{p['added_by']} added {name(p['scenario'])}: {_and(asked) if asked else 'nothing yet'}")
    for pl in players:
        add(pl.get("added_at"), f"{pl.get('added_by') or 'Someone'} added {pl['name']} as a player")
    for r in reps:
        waited = r["started_at"] is None or (r["requested_at"] and (r["started_at"] - r["requested_at"]).total_seconds() > 2)
        again = f", for the {_nth(r['pass'])} time" if (r["pass"] or 1) > 1 else ""
        add(r["requested_at"], f"{r['requested_by']} asked to replay {name(r['scenario'])}'s logs"
                               f"{', after the replays before them' if r['after'] and waited else ''}")
        if r["started_at"] and waited:
            add(r["started_at"], f"{name(r['scenario'])}'s logs replaying{again}")
        sent = int((r["progress"] or {}).get("sent") or 0)
        add(r["finished_at"], {
            simulation.REPLAYED: f"{name(r['scenario'])}'s logs replayed{again}: {sent:,} events",
            simulation.STOPPED: f"{name(r['scenario'])}'s replay stopped, after {sent:,} events",
            simulation.CANCELLED: f"{name(r['scenario'])}'s replay cancelled",
            simulation.FAILED: f"Could not replay {name(r['scenario'])}'s logs: {r['error'] or 'no reason given'}",
        }.get(r["state"], ""), warn=r["state"] == simulation.FAILED)
    for o in objs:
        if o["kind"] == client.PROBLEM:
            add(o.get("made_at"), f"{o['name']}: {o['note']}", warn=True)
    add(sim["ended_at"], f"{sim['ended_by'] or 'Someone'} ended it")
    events.sort(key=lambda e: (e[0], e[1]), reverse=True)
    return [{"at": at, "text": text, "warn": warn} for at, _, text, warn in events[:limit]]


def _cleanup_lines(sim: dict, status: dict) -> list:
    """What a clean-up removed, kept or couldn't remove, part by part, once one has run."""
    report = sim.get("cleanup") or {}
    if not report:
        return []
    out = []
    for part, label, steps in (("tide", "What it set up in TIDE", ("tide",)), ("space", "its space", ("destination", "space", "alerts")),
                               ("data", "its logs", ("data",))):
        st = status[part]
        if st == "failed":
            why = next((report[s]["error"] for s in steps if report.get(s) and not report[s]["ok"]), "no reason given")
            out.append(f"{label}: not removed: {why}")
        elif st != "none":
            out.append(f"{label}: {'removed' if st == 'done' else 'kept'}")
    return out


def _panel(db, client_id: str, sim: dict, user) -> Dict[str, Any]:
    """A simulation's panel: its figures, its scenarios and their replays, its activity, what it set up
    in TIDE, the board and its rules; ``poll``, how often it asks for itself again (every 3 s while
    something is under way, 15 s while it runs), and ``version``, its shape (what it offers), which
    simulation_live compares to draw it again in full only when that changed."""
    store, sim_id, names = _store(db, client_id), sim["id"], _names()
    parts, reps = simulation.scenario_parts(store, sim_id), simulation.replays(store, sim_id)
    objs, rule_rows, players = client.objects(store, sim_id), simulation.rule_results(store, sim_id), simulation.players(store, sim_id)
    can_run, kibana = user is None or user.can_write("page:simulations"), _kibana_link(db, client_id, sim)
    busy = not sim["interrupted"] and (sim["state"] in simulation.ACTIVE
                                        or any(p["state"] == "setting_up" for p in parts)
                                        or any(r["state"] in simulation.WAITING for r in reps))
    opened = sim["state"] in simulation.OPEN and not sim["interrupted"]
    cleanup = simulation.cleanup_status(sim, objs)
    shape = [sim["state"], sim["interrupted"], sim["cleaned"], sim["cleanup_failed"], bool(kibana), can_run, cleanup,
             [(p["scenario"], p["logs"], p["rules"], p["tide"], p["questions"], p["state"], p["interrupted"]) for p in parts]]
    figures = [r["progress"] or {} for r in reps]
    return {"sim": sim, "names": names, "states": STATES, "players": players, "board": simulation.board(store, sim_id),
            "rules": rule_rows, "in_tide": [o for o in objs if o["kind"] in (*client.IN_TIDE, client.PROBLEM)],
            "rows": _rows(sim, parts, reps, rule_rows, objs, names),
            "activity": _activity(sim, parts, reps, players, objs, names),
            "sent": sum(int(f.get("sent") or 0) for f in figures), "refused": sum(int(f.get("refused") or 0) for f in figures),
            "first_refusal": next((f["first_refusal"] for f in figures if f.get("first_refusal")), ""),
            "kibana": kibana, "can_run": can_run, "running": simulation.running(sim), "opened": opened, "cleanup": cleanup,
            "cleanup_lines": _cleanup_lines(sim, cleanup),
            "part_items": PART_ITEMS, "poll": "3s" if busy else ("15s" if opened else None),
            "version": hashlib.sha256(json.dumps(shape, default=str).encode()).hexdigest()[:12]}


def _detail(request: Request, db, client_id: str, sim_id: str, user, note: str = "", error: str = "",
            status_code: int = 200) -> HTMLResponse:
    sim = simulation.get(_store(db, client_id), sim_id)
    if sim is None:
        return HTMLResponse('<div class="alert alert-danger">Could not open it: there is no such simulation.</div>',
                            status_code=404)
    ctx = {**_panel(db, client_id, sim, user), "note": note, "error": error}
    return request.app.state.templates.TemplateResponse(request, DETAIL, ctx, status_code=status_code)


# ── The Dashboard and Answers tabs ─────────────────────────────────────────────────────────────

SERIES = 8          # .sim-series-1 … 8 in style.css: the colours a player's line can have


def _nice(raw: float) -> int:
    for step in (5, 10, 25, 50, 100, 200, 250, 500, 1000, 2000, 2500, 5000):
        if raw <= step:
            return step
    return int(math.ceil(raw / 5000) * 5000)


def score_chart(tl: dict, width: int = 640, height: int = 240) -> Optional[dict]:
    """The Dashboard's scores over time, as SVG geometry: a step line per player (their score holds until
    a solve or a hint changes it), a dot with a hover tip at each change, and the players' names at the
    lines' ends when there are four or fewer. At most SERIES players are drawn, in name order, each in
    their own colour; the board lists everyone."""
    players = [p for p in tl["players"]][:SERIES]
    if not players or tl["start"] is None:
        return None
    direct = len(players) <= 4
    pad_l, pad_r, pad_t, pad_b = 40, (110 if direct else 14), 12, 22
    plot_w, plot_h = width - pad_l - pad_r, height - pad_t - pad_b
    t0, t1 = tl["start"], tl["end"]
    span = max((t1 - t0).total_seconds(), 1.0)
    values = [s for p in players for _, s in p["points"]]
    step = _nice((max(100, *values) - min(0, *values)) / 4)
    lo, hi = int(math.floor(min(0, *values) / step) * step), int(math.ceil(max(100, *values) / step) * step)

    def x(t) -> float:
        return round(pad_l + max(0.0, (t - t0).total_seconds()) / span * plot_w, 1)

    def y(v) -> float:
        return round(pad_t + (hi - v) / (hi - lo) * plot_h, 1)

    lines = []
    for i, p in enumerate(players):
        path, dots, prev = [], [], None
        for t, s in p["points"]:
            if prev is not None:
                path.append(f"{x(t)},{y(prev)}")
                dots.append({"x": x(t), "y": y(s), "tip": f"{p['name']}: {s} points at {t:%H:%M:%S}"})
            path.append(f"{x(t)},{y(s)}")
            prev = s
        path.append(f"{x(t1)},{y(prev)}")
        lines.append({"name": p["name"], "series": i + 1, "path": " ".join(path), "dots": dots, "score": p["score"],
                      "label_y": y(prev)})
    if direct:                                  # keep the end labels apart
        ordered = sorted(lines, key=lambda line: line["label_y"])
        for a, b in zip(ordered, ordered[1:]):
            b["label_y"] = max(b["label_y"], a["label_y"] + 12)
    return {"width": width, "height": height, "pad_l": pad_l, "plot_right": pad_l + plot_w, "plot_top": pad_t,
            "plot_bottom": pad_t + plot_h, "zero_y": y(0), "lines": lines, "direct": direct,
            "ticks": [{"y": y(v), "label": v} for v in range(lo, hi + 1, step)],
            "first_label": f"{t0:%H:%M}", "last_label": f"{t1:%H:%M}", "more": len(tl["players"]) - len(players)}


def _sim_or_404(db, client_id: str, sim_id: str):
    sim = simulation.get(_store(db, client_id), sim_id)
    if sim is None:
        raise HTTPException(status_code=404, detail="There is no such simulation.")
    return sim


# Before the routes by a simulation's id, which would take "tab" for one.
@router.get("/api/simulations/tab/{part}", response_class=HTMLResponse)
def simulations_tab(part: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    """The Dashboard or Answers tab drawn again when a simulation starts, ends, is cleaned up or cleared
    (simulationsChanged), on the one running, else the latest: a new one shows without reloading."""
    if part not in ("dashboard", "answers"):
        raise HTTPException(status_code=404, detail="There is no such tab.")
    sims = simulation.list_all(_store(db, client_id))
    return request.app.state.templates.TemplateResponse(request, TAB, {
        "part": part, "sims": sims, "focus": _focus(sims), "names": _names(), "states": STATES})


@router.get("/api/simulations/{sim_id}/dashboard", response_class=HTMLResponse)
def simulation_dashboard(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    """The Dashboard tab for one simulation: its figures, its scores over time, the board, how each
    question went and its rules' alerts. Asked for again every 15 s while it runs."""
    sim = _sim_or_404(db, client_id, sim_id)
    return _dashboard(request, _store(db, client_id), sim, None, f"/api/simulations/{sim_id}/dashboard", "#sim-dashboard")


def _dashboard(request: Request, store, sim: dict, me: Optional[str], poll_url: str, target: str) -> HTMLResponse:
    """A simulation's dashboard: the Sim Admin's (me None, with its rules) or a player's (me: them)."""
    sim_id = sim["id"]
    board = simulation.board(store, sim_id)
    stats = simulation.question_stats(store, sim_id)
    items = [(sc, q, stats.get(q.key, {})) for sc, qs in _questions(sim, simulation.question_scenarios(store, sim)) for q, *_ in qs]
    return request.app.state.templates.TemplateResponse(request, DASHBOARD, {
        "sim": sim, "names": _names(), "states": STATES, "board": board, "me": me, "player": me is not None,
        "items": items, "chart": score_chart(simulation.timeline(store, sim_id)), "live": _live(sim),
        "poll_url": poll_url, "target": target,
        "players": len(board), "solves": sum(b["solved"] for b in board),
        "hints": sum(s.get("hints", 0) for s in stats.values()),
        "rules": simulation.rule_results(store, sim_id) if me is None else []})


@router.get("/api/simulations/{sim_id}/answers", response_class=HTMLResponse)
def simulation_answers(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    """The Answers tab for one simulation: its questions, each with its answer and how to find it in its
    own data, and the notes on its rules (for the Sim Admin)."""
    sim = _sim_or_404(db, client_id, sim_id)
    return request.app.state.templates.TemplateResponse(request, ANSWERS_TAB, {
        "sim": sim, "questions": _questions(sim, simulation.question_scenarios(_store(db, client_id), sim)), "can_save": _can_save(sim, user)})


def _can_save(sim: dict, user) -> bool:
    """Save in Kibana (#126): who can run simulations, while the simulation's space is there."""
    return ((user is None or user.can_write("page:simulations")) and not sim["cleaned"]
            and sim["state"] not in ("setting_up", "cleaning_up", "failed"))


@router.post("/api/simulations/{sim_id}/saved-searches", response_class=HTMLResponse)
async def save_question_searches(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    """Save in Kibana (#126): a question's KQL and ES|QL searches as saved searches in the simulation's
    space, on its Simulation logs data view and its time so far, so Discover opens on them there. Saving
    again replaces them; cleaning the simulation up deletes them with its space."""
    from html import escape
    from starlette.concurrency import run_in_threadpool
    from app.services.sim.replay import ElasticError
    sim = _sim_or_404(db, client_id, sim_id)
    if not _can_save(sim, None) or (user is not None and not user.can_write("page:simulations")):
        why = ("it needs the right to run simulations" if user is not None and not user.can_write("page:simulations")
               else "the simulation has no space in Kibana now")
        return HTMLResponse(f'<div class="alert alert-danger">Could not save them: {why}.</div>')
    form = await request.form()
    scenario, n = str(form.get("scenario") or ""), str(form.get("n") or "")
    question = None
    if scenario in sim["scenarios"]:
        try:
            question = next((q for q in game.questions(packs.scenario(scenario)) if str(q.n) == n), None)
        except packs.PackError:
            question = None
    if question is None:
        return HTMLResponse('<div class="alert alert-danger">Could not save them: there is no such question.</div>')
    text = for_namespace(question.writeup, sim["namespace"])
    searches = saved_searches(text)
    if not searches:
        return HTMLResponse('<div class="alert alert-danger">Could not save them: this question has no KQL or ES|QL search.</div>')
    title = answer_parts(text)["title"] or f"Question {question.n}"
    try:
        siem = simulation.siem_for(db, sim["siem_id"])
        saved = await run_in_threadpool(simulation.save_searches, siem, sim, scenario, question.n, title, searches)
    except (simulation.SimError, ElasticError) as exc:
        return HTMLResponse(f'<div class="alert alert-danger">Could not save them: {escape(str(exc))}</div>')
    base = ((db.get_siem_inventory_item(sim["siem_id"]) or {}).get("kibana_url") or "").rstrip("/")
    links = ", ".join(f'<a href="{escape(base)}/s/{escape(sim["space"])}/app/discover#/view/{escape(oid)}" '
                      f'target="_blank" rel="noopener">{escape(name)}</a>' for name, oid in saved)
    logger.info("Simulation %s: %s saved %d search(es) of %s question %s in Kibana", sim_id, _who(user)[1],
                len(saved), scenario, question.n)
    return HTMLResponse(f'<div class="alert alert-success">Saved in Discover, in the simulation\'s space: {links}.</div>')


def _list(request: Request, db, client_id: str) -> HTMLResponse:
    return request.app.state.templates.TemplateResponse(request, LIST, {
        "sims": simulation.list_all(_store(db, client_id)), "names": _names(), "states": STATES, "oob": True})


@router.get("/api/simulations/list", response_class=HTMLResponse)
def simulations_list(request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    return _list(request, db, client_id)


@router.post("/api/simulations/start", response_class=HTMLResponse)
async def start_simulation(request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    """Start a simulation with one scenario (``scenario``; a script may send several as ``scenarios``) and
    the parts ticked for it."""
    form = await request.form()
    parts = _parts(form)
    try:
        siem = simulation.siem_for(db, str(form.get("siem_id") or ""))
        chosen = form.getlist("scenario") or form.getlist("scenarios")
        sim_id = simulation.start(_store(db, client_id), siem, [str(s) for s in chosen],
                                  str(form.get("noise") or "quiet"), float(form.get("speed") or 10),
                                  _people(db, client_id, form.getlist("players")), _who(user)[1], actor=_actor(user),
                                  parts=parts)
    except (simulation.SimError, ValueError) as exc:
        # A refusal is shown where the simulation would have opened: htmx swaps only a 2xx, and a 4xx
        # would leave just app.js's "Could not complete that" toast, without the reason.
        return HTMLResponse(f'<div class="alert alert-danger">Could not start it: {exc}</div>')
    response = _detail(request, db, client_id, sim_id, user, note=f"Started: setting up its space, then {_doing(parts)}.")
    response.headers["HX-Trigger"] = "simulationsChanged"
    _players_changed(client_id)
    return response


def _parts(form) -> simulation.Parts:
    """The parts ticked on a form (its ``parts`` boxes, under ``parts_given``); a form without them (a
    script's) asks for all of them."""
    if not form.get("parts_given"):
        return simulation.Parts()
    ticked = {str(p) for p in form.getlist("parts")}
    return simulation.Parts(**{k: k in ticked for k in ("logs", "rules", "tide", "questions")})


def _doing(parts: simulation.Parts) -> str:
    """What a scenario's parts do, as a note says it."""
    steps = [text for on, text in ((parts.rules, "making its rules"), (parts.tide, "setting it up in TIDE"),
                                   (parts.questions, "showing its questions"), (parts.logs, "replaying its logs")) if on]
    return _and(steps) if steps else "nothing more"


@router.get("/api/simulations/{sim_id}/live", response_class=HTMLResponse)
def simulation_live(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser, v: str = ""):
    """What changed in a simulation's panel since it was drawn as ``v`` (its version): its figures, each
    scenario's replays, its activity, what it set up in TIDE, the board and its rules, swapped out of
    band, so a menu or dialog open on it stays open. When what it offers changed (its state, a scenario
    added), the whole panel instead (HX-Reswap), and the list hears of it."""
    sim = simulation.get(_store(db, client_id), sim_id)
    if sim is None:
        return HTMLResponse('<div class="alert alert-danger">Could not show it: it has been cleared.</div>',
                            headers={"HX-Reswap": "innerHTML"})
    ctx = _panel(db, client_id, sim, user)
    if ctx["version"] == v:
        return request.app.state.templates.TemplateResponse(request, LIVE, ctx)
    response = request.app.state.templates.TemplateResponse(request, DETAIL, {**ctx, "note": "", "error": ""})
    response.headers.update({"HX-Reswap": "innerHTML", "HX-Trigger": "simulationsChanged"})
    return response


@router.get("/api/simulations/{sim_id}", response_class=HTMLResponse)
def simulation_detail(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    return _detail(request, db, client_id, sim_id, user)


def _act(request: Request, db, client_id: str, sim_id: str, user, what: str, note: str, act) -> HTMLResponse:
    """Do something to a simulation (act(store, siem, sim): end it, clean it up, stop or cancel a replay, give a
    scenario a part), then show it with a note, or why not ("Could not <what>: <why>")."""
    store = _store(db, client_id)
    sim = simulation.get(store, sim_id)
    try:
        if sim is None:
            raise simulation.SimError("there is no such simulation")
        act(store, simulation.siem_for(db, sim["siem_id"]), sim)
    except simulation.SimError as exc:
        return _detail(request, db, client_id, sim_id, user, error=f"Could not {what}: {exc}") \
            if sim else HTMLResponse(f'<div class="alert alert-danger">Could not {what}: {exc}.</div>', status_code=404)
    response = _detail(request, db, client_id, sim_id, user, note=note)
    response.headers["HX-Trigger"] = "simulationsChanged"
    _players_changed(client_id)
    return response


@router.post("/api/simulations/{sim_id}/end", response_class=HTMLResponse)
def end_simulation(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    """Stop it: the replay and the answering end, its rules' alerts are counted; its space stays."""
    return _act(request, db, client_id, sim_id, user, "end it", "Ending: stopping its replays and counting each rule's alerts.",
                lambda store, siem, sim: simulation.end(store, siem, sim["id"], _who(user)[1]))


# ── Its scenarios and replays ──────────────────────────────────────────────────────────────────

def _scenario_dialog(request: Request, db, client_id: str, sim: dict, user, scenario: str = "", error: str = "",
                     form: Optional[dict] = None) -> HTMLResponse:
    """Add scenario (no ``scenario``: those not in it yet, with the parts to tick) or Replay again (one of
    its scenarios: the noise level, speed and when). In #modal-container, so the panel's refresh leaves
    it open. When something replays or is queued, it asks when: now, alongside it, or after."""
    store = _store(db, client_id)
    reps = simulation.replays(store, sim["id"])
    last = next((r for r in reversed(reps) if r["scenario"] == scenario), None) if scenario else None
    choices = [s for s in scenarios() if (s["id"] == scenario if scenario else s["id"] not in sim["scenarios"])]
    defaults = {"noise": (last or {}).get("noise") or sim["noise"], "speed": (last or {}).get("speed", sim["speed"])}
    return request.app.state.templates.TemplateResponse(request, SCENARIO_DIALOG, {
        "sim": sim, "scenario": scenario, "label": _names().get(scenario, scenario), "choices": choices,
        "noise_levels": packs.NOISE_LEVELS, "form": {**defaults, **(form or {})}, "error": error,
        "when": any(r["state"] in simulation.WAITING for r in reps),
        "opened": sim["state"] in simulation.OPEN and not sim["interrupted"],
        "can_run": user is None or user.can_write("page:simulations")})


def _refused(response: HTMLResponse) -> HTMLResponse:
    """A dialog drawn again with why it was refused, in #modal-container rather than the panel."""
    response.headers.update({"HX-Retarget": "#modal-container", "HX-Reswap": "innerHTML"})
    return response


def _done(response: HTMLResponse) -> HTMLResponse:
    """The panel drawn again after a dialog's action: the dialog closes, and the list hears of it."""
    response.headers.update({"HX-Trigger-After-Swap": "tideCloseModal", "HX-Trigger": "simulationsChanged"})
    return response


@router.get("/api/simulations/{sim_id}/add-scenario", response_class=HTMLResponse)
def add_scenario_dialog(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    return _scenario_dialog(request, db, client_id, _sim_or_404(db, client_id, sim_id), user)


@router.post("/api/simulations/{sim_id}/scenarios", response_class=HTMLResponse)
async def add_simulation_scenario(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    """Add scenario: the one chosen, doing the parts ticked; its replay now or after those under way."""
    sim = _sim_or_404(db, client_id, sim_id)
    form = await request.form()
    scenario, parts = str(form.get("scenario") or ""), _parts(form)
    kept = {"scenario": scenario, "parts": [str(p) for p in form.getlist("parts")], "noise": str(form.get("noise") or ""),
            "speed": form.get("speed") or "", "when": str(form.get("when") or "now")}
    try:
        if not scenario:
            raise simulation.SimError("choose a scenario.")
        simulation.add_scenario(_store(db, client_id), simulation.siem_for(db, sim["siem_id"]), sim_id, scenario, parts,
                                str(form.get("noise") or "quiet"), float(form.get("speed") or 10), _who(user)[1],
                                after=kept["when"] == "after", actor=_actor(user))
    except (simulation.SimError, ValueError) as exc:
        return _refused(_scenario_dialog(request, db, client_id, sim, user, error=f"Could not add it: {exc}", form=kept))
    logger.info("Simulation %s: %s added scenario %s (%s)", sim_id, _who(user)[1], scenario, parts)
    return _done(_detail(request, db, client_id, sim_id, user,
                         note=f"Added {_names().get(scenario, scenario)}: {_doing(parts)}."))


@router.get("/api/simulations/{sim_id}/scenarios/{scenario}/replay", response_class=HTMLResponse)
def replay_scenario_dialog(sim_id: str, scenario: str, request: Request, db: DbDep, client_id: ActiveClient,
                           user: RequireUser):
    sim = _sim_or_404(db, client_id, sim_id)
    if scenario not in sim["scenarios"]:
        raise HTTPException(status_code=404, detail="It has no such scenario.")
    return _scenario_dialog(request, db, client_id, sim, user, scenario=scenario)


@router.post("/api/simulations/{sim_id}/scenarios/{scenario}/replay", response_class=HTMLResponse)
async def replay_simulation_scenario(sim_id: str, scenario: str, request: Request, db: DbDep, client_id: ActiveClient,
                                     user: RequireUser):
    """Replay again: a scenario's logs sent again, stamped now, as its next pass, so rules made or fixed
    since see them; now, alongside any replay, or after those under way."""
    sim = _sim_or_404(db, client_id, sim_id)
    form = await request.form()
    after = str(form.get("when") or "now") == "after"
    kept = {"noise": str(form.get("noise") or ""), "speed": form.get("speed") or "", "when": "after" if after else "now"}
    try:
        simulation.replay_scenario(_store(db, client_id), simulation.siem_for(db, sim["siem_id"]), sim_id, scenario,
                                   str(form.get("noise") or "quiet"), float(form.get("speed") or 10), _who(user)[1],
                                   after=after)
    except (simulation.SimError, ValueError) as exc:
        return _refused(_scenario_dialog(request, db, client_id, sim, user, scenario=scenario,
                                         error=f"Could not replay it: {exc}", form=kept))
    name = _names().get(scenario, scenario)
    return _done(_detail(request, db, client_id, sim_id, user,
                         note=f"Queued {name}'s logs, after the replays before them." if after
                         else f"Replaying {name}'s logs again: rules made or fixed since will see them."))


@router.post("/api/simulations/{sim_id}/scenarios/{scenario}/parts", response_class=HTMLResponse)
async def add_simulation_parts(sim_id: str, scenario: str, request: Request, db: DbDep, client_id: ActiveClient,
                               user: RequireUser):
    """A part a scenario wasn't given when it was added (a row's ⋮): its rules, its set-up in TIDE or its
    questions."""
    part = str((await request.form()).get("part") or "")
    if part not in PART_ITEMS:
        raise HTTPException(status_code=404, detail="There is no such part.")
    name = _names().get(scenario, scenario)
    notes = {"rules": f"Making {name}'s rules in its space, and mapping them onto its set-up in TIDE if it has one.",
             "tide": f"Setting {name} up in TIDE.", "questions": f"{name}'s questions are shown to the players."}
    return _act(request, db, client_id, sim_id, user, f"give {name} that", notes[part],
                lambda store, siem, sim: simulation.add_parts(store, siem, sim["id"], scenario, actor=_actor(user),
                                                              **{part: True}))


@router.post("/api/simulations/{sim_id}/replays/{n}/stop", response_class=HTMLResponse)
def stop_simulation_replay(sim_id: str, n: int, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    """Stop a replay that is running; what it sent stays, and those queued after it may start."""
    return _act(request, db, client_id, sim_id, user, "stop the replay", "Stopping the replay: what it sent stays.",
                lambda store, siem, sim: simulation.stop_replay(store, siem, sim["id"], n))


@router.post("/api/simulations/{sim_id}/replays/{n}/cancel", response_class=HTMLResponse)
def cancel_simulation_replay(sim_id: str, n: int, request: Request, db: DbDep, client_id: ActiveClient,
                             user: RequireUser):
    """Take a queued replay out of the queue."""
    return _act(request, db, client_id, sim_id, user, "cancel the replay", "Took the replay out of the queue.",
                lambda store, siem, sim: simulation.cancel_replay(store, siem, sim["id"], n))


def _players_dialog(request: Request, db, client_id: str, sim: dict, user, error: str = "") -> HTMLResponse:
    playing = {p["user_id"] for p in simulation.players(_store(db, client_id), sim["id"])}
    return request.app.state.templates.TemplateResponse(request, PLAYERS, {
        "sim": sim, "users": [u for u in _client_users(db, client_id) if u["id"] not in playing],
        "running": simulation.running(sim), "can_run": user is None or user.can_write("page:simulations"), "error": error})


@router.get("/api/simulations/{sim_id}/players", response_class=HTMLResponse)
def add_players_dialog(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    """Add players: the client's users who aren't playing it yet, to tick. A dialog in #modal-container,
    so the simulation's own refresh (every 3 s while it sets up or replays) leaves it open."""
    return _players_dialog(request, db, client_id, _sim_or_404(db, client_id, sim_id), user)


@router.post("/api/simulations/{sim_id}/players", response_class=HTMLResponse)
async def add_simulation_players(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    """Add the users ticked as players while it runs: the simulation is drawn again with a note, the
    dialog closes, and their sidebars show Simulation at once. None ticked: the dialog says so."""
    sim = _sim_or_404(db, client_id, sim_id)
    people = _people(db, client_id, (await request.form()).getlist("players"))
    if not people:
        response = _players_dialog(request, db, client_id, sim, user, error="Tick at least one user to add.")
        response.headers.update({"HX-Retarget": "#modal-container", "HX-Reswap": "innerHTML"})
        return response
    try:
        added = simulation.add_players(_store(db, client_id), sim_id, people, by=_who(user)[1])
    except simulation.SimError as exc:
        response = _detail(request, db, client_id, sim_id, user, error=f"Could not add players: {exc}")
    else:
        who = " and ".join([", ".join(added[:-1]), added[-1]] if len(added) > 1 else added)
        response = _detail(request, db, client_id, sim_id, user,
                           note=f"Added {who}: Simulation is in their sidebar now." if added
                           else "They are playing it already.")
        logger.info("Simulation %s: %s added %d player(s)", sim_id, _who(user)[1], len(added))
        _players_changed(client_id)
    response.headers["HX-Trigger-After-Swap"] = "tideCloseModal"
    return response


CLEAN_UP_DIALOG = "partials/simulation_cleanup_dialog.html"
CLEAN_LABELS = {"tide": "what it set up in TIDE", "space": "its space", "data": "its logs"}


def _cleanup_dialog(request: Request, db, client_id: str, sim: dict, user, error: str = "") -> HTMLResponse:
    """Clean up: its three parts (what it set up in TIDE, its space, its logs), each ticked while it is
    left (or failed), or saying it was removed. In #modal-container, as the panel's other dialogs."""
    store = _store(db, client_id)
    return request.app.state.templates.TemplateResponse(request, CLEAN_UP_DIALOG, {
        "sim": sim, "status": simulation.cleanup_status(sim, client.objects(store, sim["id"])), "error": error,
        "ended": sim["state"] == "ended" or (sim["state"] == "cleaning_up" and sim["interrupted"]),
        "can_run": user is None or user.can_write("page:simulations")})


@router.get("/api/simulations/{sim_id}/clean-up", response_class=HTMLResponse)
def clean_up_dialog(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    return _cleanup_dialog(request, db, client_id, _sim_or_404(db, client_id, sim_id), user)


@router.post("/api/simulations/{sim_id}/clean-up", response_class=HTMLResponse)
async def clean_up_simulation(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    """Clean up the parts ticked (``parts`` under ``parts_given``; all of them, from a script): what it set
    up in TIDE, its space on the SIEM (with its destination in TIDE), its logs on the SIEM."""
    sim = _sim_or_404(db, client_id, sim_id)
    form = await request.form()
    parts = tuple(str(p) for p in form.getlist("parts")) if form.get("parts_given") else simulation.CLEAN_PARTS
    try:
        if not parts:
            raise simulation.SimError("tick what to clean up.")
        simulation.clean_up(_store(db, client_id), simulation.siem_for(db, sim["siem_id"]), sim_id, actor=_actor(user),
                            parts=parts)
    except simulation.SimError as exc:
        return _refused(_cleanup_dialog(request, db, client_id, sim, user, error=f"Could not clean it up: {exc}"))
    what = _and([CLEAN_LABELS[p] for p in simulation.CLEAN_PARTS if p in parts])
    return _done(_detail(request, db, client_id, sim_id, user, note=f"Cleaning up {what}."))


@router.post("/api/simulations/{sim_id}/clear", response_class=HTMLResponse)
def clear_simulation(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    try:
        simulation.clear(_store(db, client_id), sim_id)
    except simulation.SimError as exc:
        return _detail(request, db, client_id, sim_id, user, error=f"Could not clear it: {exc}")
    response = HTMLResponse('<div class="alert alert-success">Its results are cleared.</div>')
    response.headers["HX-Trigger"] = "simulationsChanged"
    return response


# ── The Simulation page (players) ──────────────────────────────────────────────────────────────

def _story(sc: packs.Scenario) -> str:
    """What questions.md tells players before its questions."""
    text = sc.path("questions.md").read_text(encoding="utf-8") if sc.path("questions.md").is_file() else ""
    body = text.split("\n", 1)[1] if text.startswith("#") else text
    return re.split(r"^\d+\. ", body, maxsplit=1, flags=re.M)[0].strip()


def _play(db, client_id: str, sim: dict, user_id: str) -> Dict[str, Any]:
    store = _store(db, client_id)
    mine = simulation.progress_for(store, sim["id"], user_id)
    parts = []
    for sid in simulation.question_scenarios(store, sim):
        try:
            sc = packs.scenario(sid)
        except packs.PackError:
            continue
        parts.append({"scenario": sc, "story": for_namespace(_story(sc), sim["namespace"]),
                      "questions": [{"q": q, "mine": mine.get(q.key, {}),
                                     "parts": answer_parts(player_writeup(q.writeup, sim["namespace"]))}
                                    for q in game.questions(sc)]})
    return {"sim": sim, "parts": parts, "board": simulation.board(store, sim["id"]), "me": user_id,
            "kibana": _kibana_link(db, client_id, sim), "states": STATES}


def player_context(db, client_id: str, user) -> Dict[str, Any]:
    """The simulations this user is a player in that haven't ended (setting up included, so it shows
    from the start), each as they play it."""
    uid = _who(user)[0]
    store = _store(db, client_id)
    games = [_play(db, client_id, s, uid) for s in simulation.list_all(store)
             if s["state"] in simulation.SHOWN and not s["interrupted"]
             and any(p["user_id"] == uid for p in simulation.players(store, s["id"]))]
    return {"games": games, "states": STATES}


_PLAYING = TTLCache(ttl_seconds=20, maxsize=512)


def _players_changed(client_id: str) -> None:
    """A simulation of the client started or ended: its players' sidebars ask again at once."""
    _PLAYING.invalidate_prefix(lambda key: key[0] == client_id)


def playing_cached(db, client_id: Optional[str], user) -> bool:
    """playing(), remembered 20 s per client and user, as every page's sidebar asks."""
    if not client_id or user is None:
        return False
    return bool(_PLAYING.get_or_compute((client_id, str(user.id)), lambda: playing(db, client_id, user)))


def playing(db, client_id: Optional[str], user) -> bool:
    """Whether the user is a player in one of the client's open simulations (the sidebar's Simulation)."""
    if not client_id:
        return False
    try:
        return bool(player_context(db, client_id, user)["games"])
    except Exception:  # noqa: BLE001 - the sidebar never fails over it
        return False


def _question(request: Request, db, client_id: str, sim_id: str, scenario: str, n: int, user,
              result: Optional[dict] = None) -> HTMLResponse:
    sim = simulation.get(_store(db, client_id), sim_id)
    uid = _who(user)[0]
    if sim is None:
        return HTMLResponse('<p class="inline-error">Could not answer it: there is no such simulation.</p>', status_code=404)
    play = _play(db, client_id, sim, uid)
    item = next((q for part in play["parts"] for q in part["questions"]
                 if q["q"].scenario == scenario and q["q"].n == n), None)
    if item is None:
        return HTMLResponse('<p class="inline-error">Could not answer it: there is no such question.</p>', status_code=404)
    message = ANSWERS.get((result or {}).get("result", ""), "")
    if result and result.get("result") == "hint":
        message = f"Hint taken, for {result['cost']} points."
    elif result and result.get("result") == "none":
        message = "There are no more hints."
    response = request.app.state.templates.TemplateResponse(request, QUESTION, {
        "sim": sim, "item": item, "message": message, "ok": bool(result and result.get("result") in ("right", "hint"))})
    if result and result.get("result") == "right":
        response.headers["HX-Trigger"] = "boardChanged"
    return response


@router.post("/api/simulation/{sim_id}/answer", response_class=HTMLResponse)
async def answer_question(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    form = await request.form()
    scenario, n = str(form.get("scenario") or ""), int(form.get("n") or 0)
    result = simulation.answer(_store(db, client_id), sim_id, _who(user)[0], scenario, n, str(form.get("answer") or ""))
    return _question(request, db, client_id, sim_id, scenario, n, user, result)


@router.post("/api/simulation/{sim_id}/hint", response_class=HTMLResponse)
async def take_hint(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    form = await request.form()
    scenario, n = str(form.get("scenario") or ""), int(form.get("n") or 0)
    result = simulation.take_hint(_store(db, client_id), sim_id, _who(user)[0], scenario, n)
    return _question(request, db, client_id, sim_id, scenario, n, user, result)


def _playing(store, sim_id: str, uid: str, what: str):
    """(the simulation, None) when the user plays it and it hasn't ended, else (None, the response to give)."""
    sim = simulation.get(store, sim_id)
    if sim is None or sim["state"] not in simulation.SHOWN or sim["interrupted"]:
        # It ended (or was cleared) while the page was open: back to Simulation, which goes Home when
        # nothing is left to play. Not a 403, which app.js would take for a lapsed sign-in.
        return None, HTMLResponse("", headers={"HX-Redirect": "/simulation"})
    if not any(p["user_id"] == uid for p in simulation.players(store, sim_id)):
        return None, HTMLResponse(f'<p class="inline-error">Could not show {what}: you aren\'t one of its players.</p>',
                                  status_code=403)
    return sim, None


@router.get("/api/simulation/{sim_id}/board", response_class=HTMLResponse)
def simulation_board(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    store, uid = _store(db, client_id), _who(user)[0]
    sim, refused = _playing(store, sim_id, uid, "the board")
    if refused:
        return refused
    if request.query_params.get("setting_up") and sim["state"] != "setting_up":
        # The page was opened while it was setting up: show it again now the answers are open.
        return HTMLResponse("", headers={"HX-Refresh": "true"})
    return request.app.state.templates.TemplateResponse(
        request, BOARD, {"board": simulation.board(store, sim_id), "me": uid})


@router.get("/api/simulation/{sim_id}/parts", response_class=HTMLResponse)
def simulation_new_parts(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser,
                         have: str = ""):
    """A player's page asking every 15 s for scenarios whose questions were shown since it was drawn
    (``have``: those it shows): each is appended to it out of band, marked new, with the board if it had
    none, so an answer being typed stays; nothing when none is new."""
    store, uid = _store(db, client_id), _who(user)[0]
    sim, refused = _playing(store, sim_id, uid, "its questions")
    if refused:
        return refused
    seen = {x for x in have.split(",") if x}
    play = _play(db, client_id, sim, uid)
    new = [part for part in play["parts"] if part["scenario"].id not in seen]
    if not new:
        return HTMLResponse("")
    had_board = any(part["questions"] for part in play["parts"] if part["scenario"].id in seen)
    return request.app.state.templates.TemplateResponse(request, NEW_PARTS, {
        "sim": sim, "new": new, "parts": play["parts"], "board": play["board"], "me": uid, "had_board": had_board})


@router.get("/api/simulation/{sim_id}/dashboard", response_class=HTMLResponse)
def player_dashboard(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    """A player's Dashboard tab: the simulation's scores over time, the board (them in bold) and how
    each question went, without the rules. Asked for again every 15 s while it is open."""
    store, uid = _store(db, client_id), _who(user)[0]
    sim, refused = _playing(store, sim_id, uid, "the dashboard")
    return refused or _dashboard(request, store, sim, uid, f"/api/simulation/{sim_id}/dashboard",
                                 f"#sim-dashboard-{sim_id}")
