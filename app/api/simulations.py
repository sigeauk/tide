"""Simulations (#118, app.services.sim): the Simulations page, where a Sim Admin starts a simulation on
one of the client's SIEMs, follows it and ends it (page:simulations), and the Simulation page, where the
players chosen for it answer its questions (page:simulation; each call also checks the person is one of
its players). Reading needs read and changing needs write on each (main.py's maps).

A simulation runs on the SIEM of one of the client's destinations, in a space of its own that is never a
destination (CLAUDE.md section 6): the SIEM is chosen by its id among the client's, never by a space.
"""
from __future__ import annotations

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
    """Its space's alerts in Kibana, while the space is there (until it is cleaned up)."""
    url = ((db.get_siem_inventory_item(sim["siem_id"]) or {}).get("kibana_url") or "").rstrip("/")
    return f"{url}/s/{sim['space']}/app/security/alerts" if url and not sim.get("cleaned") else ""


def for_namespace(text: str, namespace: str) -> str:
    """A write-up's searches, written for the scenarios' own data streams (logs-…-botes), for a
    simulation's (logs-…-<namespace>)."""
    return re.sub(r"\blogs-([\w.*]+)-botes\b", lambda m: f"logs-{m.group(1)}-{namespace}", text)


def player_writeup(text: str, namespace: str) -> str:
    """A write-up as a player sees it once answered: for their simulation's data, without the notes
    on TIDE's own rules (for the Sim Admin)."""
    kept = [p for p in re.split(r"\n\s*\n", text) if not p.lstrip().startswith("**With TIDE:**")]
    return for_namespace("\n\n".join(kept), namespace)


# ── The Simulations page (Sim Admins) ──────────────────────────────────────────────────────────

TABS = ("run", "dashboard", "answers")


def page_context(db, client_id: str, user, tab: str = "") -> Dict[str, Any]:
    store = _store(db, client_id)
    sims = simulation.list_all(store)
    return {"siems": siems(db), "scenarios": scenarios(), "noise_levels": packs.NOISE_LEVELS,
            "users": sorted(db.get_client_users(client_id) or [], key=lambda u: (u.get("full_name") or u["username"]).lower()),
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


def _questions(sim: dict) -> list:
    """Each of the simulation's scenarios with its questions and their write-ups, for its own data."""
    out = []
    for sid in sim["scenarios"]:
        try:
            sc = packs.scenario(sid)
            out.append((sc, [(q, for_namespace(q.writeup, sim["namespace"])) for q in game.questions(sc)]))
        except packs.PackError:
            continue
    return out


def _detail(request: Request, db, client_id: str, sim_id: str, user, note: str = "", error: str = "",
            status_code: int = 200) -> HTMLResponse:
    store = _store(db, client_id)
    sim = simulation.get(store, sim_id)
    if sim is None:
        return HTMLResponse('<div class="alert alert-danger">Could not open it: there is no such simulation.</div>',
                            status_code=404)
    ctx = {"sim": sim, "names": _names(), "states": STATES, "players": simulation.players(store, sim_id),
           "board": simulation.board(store, sim_id), "rules": simulation.rule_results(store, sim_id),
           "in_tide": [o for o in client.objects(store, sim_id) if o["kind"] in (*client.IN_TIDE, client.PROBLEM)],
           "kibana": _kibana_link(db, client_id, sim), "note": note, "error": error,
           "can_run": user is None or user.can_write("page:simulations"), "active": sim["state"] in simulation.ACTIVE
           and not sim["interrupted"]}
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
    items = [(sc, q, stats.get(q.key, {})) for sc, qs in _questions(sim) for q, _ in qs]
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
    return request.app.state.templates.TemplateResponse(request, ANSWERS_TAB, {"sim": sim, "questions": _questions(sim)})


def _list(request: Request, db, client_id: str) -> HTMLResponse:
    return request.app.state.templates.TemplateResponse(request, LIST, {
        "sims": simulation.list_all(_store(db, client_id)), "names": _names(), "states": STATES, "oob": True})


@router.get("/api/simulations/list", response_class=HTMLResponse)
def simulations_list(request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    return _list(request, db, client_id)


@router.post("/api/simulations/start", response_class=HTMLResponse)
async def start_simulation(request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    form = await request.form()
    try:
        siem = simulation.siem_for(db, str(form.get("siem_id") or ""))
        chosen = {str(u) for u in form.getlist("players")}
        people = [(u["id"], u.get("full_name") or u["username"]) for u in db.get_client_users(client_id) or []
                  if u["id"] in chosen]
        sim_id = simulation.start(_store(db, client_id), siem, [str(s) for s in form.getlist("scenarios")],
                                  str(form.get("noise") or "quiet"), float(form.get("speed") or 10), people,
                                  _who(user)[1], actor=_actor(user))
    except (simulation.SimError, ValueError) as exc:
        # A refusal is shown where the simulation would have opened: htmx swaps only a 2xx, and a 4xx
        # would leave just app.js's "Could not complete that" toast, without the reason.
        return HTMLResponse(f'<div class="alert alert-danger">Could not start it: {exc}</div>')
    response = _detail(request, db, client_id, sim_id, user, note="Started: setting up its space, then replaying.")
    response.headers["HX-Trigger"] = "simulationsChanged"
    _players_changed(client_id)
    return response


@router.get("/api/simulations/{sim_id}", response_class=HTMLResponse)
def simulation_detail(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    return _detail(request, db, client_id, sim_id, user)


def _act(request: Request, db, client_id: str, sim_id: str, user, what: str, note: str, act) -> HTMLResponse:
    """End or clean up a simulation (act(store, siem, sim)), then show it with a note, or why not."""
    store = _store(db, client_id)
    sim = simulation.get(store, sim_id)
    try:
        if sim is None:
            raise simulation.SimError("there is no such simulation")
        act(store, simulation.siem_for(db, sim["siem_id"]), sim)
    except simulation.SimError as exc:
        return _detail(request, db, client_id, sim_id, user, error=f"Could not {what} it: {exc}") \
            if sim else HTMLResponse(f'<div class="alert alert-danger">Could not {what} it: {exc}.</div>', status_code=404)
    response = _detail(request, db, client_id, sim_id, user, note=note)
    response.headers["HX-Trigger"] = "simulationsChanged"
    _players_changed(client_id)
    return response


@router.post("/api/simulations/{sim_id}/end", response_class=HTMLResponse)
def end_simulation(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    """Stop it: the replay and the answering end, its rules' alerts are counted; its space stays."""
    return _act(request, db, client_id, sim_id, user, "end", "Ending: stopping the replay and counting each rule's alerts.",
                lambda store, siem, sim: simulation.end(store, siem, sim["id"], _who(user)[1]))


@router.post("/api/simulations/{sim_id}/clean-up", response_class=HTMLResponse)
def clean_up_simulation(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    """Remove what it set up in TIDE and delete what it made on the SIEM (its space among it)."""
    return _act(request, db, client_id, sim_id, user, "clean up",
                "Cleaning up: removing what it set up in TIDE, then deleting its space, data and alerts.",
                lambda store, siem, sim: simulation.clean_up(store, siem, sim["id"], actor=_actor(user)))


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
    for sid in sim["scenarios"]:
        try:
            sc = packs.scenario(sid)
        except packs.PackError:
            continue
        parts.append({"scenario": sc, "story": for_namespace(_story(sc), sim["namespace"]),
                      "questions": [{"q": q, "mine": mine.get(q.key, {}),
                                     "writeup": player_writeup(q.writeup, sim["namespace"])}
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


@router.get("/api/simulation/{sim_id}/dashboard", response_class=HTMLResponse)
def player_dashboard(sim_id: str, request: Request, db: DbDep, client_id: ActiveClient, user: RequireUser):
    """A player's Dashboard tab: the simulation's scores over time, the board (them in bold) and how
    each question went, without the rules. Asked for again every 15 s while it is open."""
    store, uid = _store(db, client_id), _who(user)[0]
    sim, refused = _playing(store, sim_id, uid, "the dashboard")
    return refused or _dashboard(request, store, sim, uid, f"/api/simulation/{sim_id}/dashboard",
                                 f"#sim-dashboard-{sim_id}")
