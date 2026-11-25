"""A simulation: one Kibana space on one of TIDE's SIEMs, where a Sim Admin runs scenarios for the
players they choose, from start to end.

Start (start()): on an Elastic SIEM in TIDE's inventory (the client needn't have it as a destination),
TIDE makes the space sim-<id>, its data view and index template, then sets up the scenarios chosen
and queues their replays, one after the other, in a thread the start begins; the pages read its
progress. It may start with no players: add_players() adds them while it runs.

A scenario's parts (Parts): what adding it does, as the Sim Admin ticks it. Make its rules (rules.py)
in the space; set it up in the client's TIDE (client.py: the space linked to the client as a
destination and synced, its baseline, systems and threat actor, its rules mapped); show its questions
to the players; replay its logs into the namespace sim<id> (replay.py). add_scenario() adds another
while it runs; add_parts() does later what wasn't done. A rule two scenarios share is made once.

Replays (replay_scenario()): each sends one scenario's logs, stamped as they are sent, as that
scenario's next pass. One starts now, alongside any other, or after every replay asked for before it;
either waits for its scenario's rules to be made first. stop_replay() stops one, cancel_replay() takes
one out of the queue. Once one is in, the client's TIDE is synced again, so the rules' field checks
see the data.

End (end()): its replays stop, those queued are cancelled, the players stop answering, and each
rule's alerts are counted; the space, its data and rules stay, and so does what it set up in TIDE.
Clean up (clean_up()): what it set up in TIDE is removed (its systems, baselines, destination and
rules), and the space, its data streams, its template and its alerts are deleted; each removal is
recorded, and one that fails can be tried again by cleaning up again. The results stay in the
client's database until a Sim Admin clears them (clear(), once it is cleaned up).

States: setting_up (its space and first scenarios), replaying (a replay running or queued), playing,
ending, ended, cleaning_up, failed. A simulation shown as setting_up, replaying, ending or cleaning_up
with nothing running behind it was cut off by a restart: it is reported as interrupted; ending (or
cleaning up) it again carries on. One simulation at a time sets up, replays or cleans up on a SIEM.

Everything is kept in the client's own database (Store), with the players by their TIDE user ids.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from app.elastic_helper import esql_data_view  # noqa: F401  (simulation.esql_data_view, as before)
from app.services.sim import client, game, kibana, packs, replay, rules

logger = logging.getLogger(__name__)

ACTIVE = ("setting_up", "replaying", "ending", "cleaning_up")
OPEN = ("replaying", "playing")          # players may answer
SHOWN = ("setting_up", *OPEN)            # players see it (Simulation in their sidebar) from the start
MIN_SECONDS_BETWEEN_ANSWERS = 2
MAX_ANSWER = 200
MAX_SPEED = 1000

DDL = (
    """CREATE TABLE IF NOT EXISTS simulations (
        id          VARCHAR PRIMARY KEY,
        siem_id     VARCHAR NOT NULL,
        space       VARCHAR NOT NULL,      -- its own Kibana space on siem_id, linked to the client while it runs
        namespace   VARCHAR NOT NULL,      -- its data streams: logs-*-<namespace>
        scenarios   VARCHAR NOT NULL,      -- JSON: the scenario ids, in the order they were added
        noise       VARCHAR NOT NULL,      -- the first scenarios' noise level and speed
        speed       DOUBLE NOT NULL,
        state       VARCHAR NOT NULL,
        error       VARCHAR,
        progress    VARCHAR,               -- JSON: the latest replay's summary
        cleanup     VARCHAR,               -- JSON: what the end removed, or why it couldn't
        created_by  VARCHAR NOT NULL,
        created_at  TIMESTAMP NOT NULL,
        replayed_at TIMESTAMP,
        ended_by    VARCHAR,
        ended_at    TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS simulation_players (
        sim_id  VARCHAR NOT NULL,
        user_id VARCHAR NOT NULL,          -- the TIDE user
        name    VARCHAR NOT NULL,          -- their name when chosen
        PRIMARY KEY (sim_id, user_id)      -- and added_by, added_at (COLUMNS_ADDED)
    )""",
    """CREATE TABLE IF NOT EXISTS simulation_answers (
        sim_id   VARCHAR NOT NULL,
        user_id  VARCHAR NOT NULL,
        scenario VARCHAR NOT NULL,
        n        INTEGER NOT NULL,
        answer   VARCHAR NOT NULL,
        correct  BOOLEAN NOT NULL,
        answered_at TIMESTAMP NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS simulation_solves (
        sim_id   VARCHAR NOT NULL,
        user_id  VARCHAR NOT NULL,
        scenario VARCHAR NOT NULL,
        n        INTEGER NOT NULL,
        points   INTEGER NOT NULL,
        solved_at TIMESTAMP NOT NULL,
        PRIMARY KEY (sim_id, user_id, scenario, n)
    )""",
    """CREATE TABLE IF NOT EXISTS simulation_hints (
        sim_id   VARCHAR NOT NULL,
        user_id  VARCHAR NOT NULL,
        scenario VARCHAR NOT NULL,
        n        INTEGER NOT NULL,
        idx      INTEGER NOT NULL,         -- which of the question's hints, from 0
        cost     INTEGER NOT NULL,
        taken_at TIMESTAMP NOT NULL,
        PRIMARY KEY (sim_id, user_id, scenario, n, idx)
    )""",
    """CREATE TABLE IF NOT EXISTS simulation_rules (
        sim_id   VARCHAR NOT NULL,
        scenario VARCHAR NOT NULL,
        rule_id  VARCHAR NOT NULL,
        siem_id  VARCHAR NOT NULL,
        space    VARCHAR NOT NULL,
        name     VARCHAR NOT NULL,
        state    VARCHAR NOT NULL,         -- created, or failed (note says why)
        note     VARCHAR,
        alerts   INTEGER,                  -- counted when it ended; NULL until then, or if it couldn't be
        PRIMARY KEY (sim_id, rule_id)
    )""",
    """CREATE TABLE IF NOT EXISTS simulation_objects (
        sim_id    VARCHAR NOT NULL,
        kind      VARCHAR NOT NULL,        -- destination, baseline, system, problem; siem_space, siem_data (client.py)
        object_id VARCHAR NOT NULL,        -- its id in TIDE; a destination's is "<siem_id>|<space>"
        name      VARCHAR NOT NULL,        -- as made (a problem: what couldn't be done)
        state     VARCHAR NOT NULL,        -- made, removed, or failed (a problem)
        note      VARCHAR,                 -- a problem's reason
        made_at   TIMESTAMP NOT NULL       -- and scenario, the one it was made for (COLUMNS_ADDED)
    )""",
    """CREATE TABLE IF NOT EXISTS simulation_parts (
        sim_id    VARCHAR NOT NULL,
        scenario  VARCHAR NOT NULL,
        logs      BOOLEAN NOT NULL,        -- its logs replayed when it was added
        rules     BOOLEAN NOT NULL,        -- its rules made in the space
        tide      BOOLEAN NOT NULL,        -- set up in the client's TIDE
        questions BOOLEAN NOT NULL,        -- shown to the players
        state     VARCHAR NOT NULL,        -- setting_up (its rules and set-up), ready
        added_by  VARCHAR NOT NULL,
        added_at  TIMESTAMP NOT NULL,
        PRIMARY KEY (sim_id, scenario)
    )""",
    """CREATE TABLE IF NOT EXISTS simulation_replays (
        sim_id       VARCHAR NOT NULL,
        n            INTEGER NOT NULL,     -- its order in the simulation, from 1
        scenario     VARCHAR NOT NULL,
        noise        VARCHAR NOT NULL,
        speed        DOUBLE NOT NULL,
        after        BOOLEAN NOT NULL,     -- waits for every replay asked for before it
        state        VARCHAR NOT NULL,     -- queued, replaying, replayed, stopped, failed, cancelled
        pass         INTEGER,              -- which time the scenario's logs are sent (botes.replay.loop)
        run_id       VARCHAR,              -- botes.replay.run_id
        progress     VARCHAR,              -- JSON: its summary (replay.Progress)
        error        VARCHAR,
        requested_by VARCHAR NOT NULL,
        requested_at TIMESTAMP NOT NULL,
        started_at   TIMESTAMP,
        finished_at  TIMESTAMP,
        PRIMARY KEY (sim_id, n)
    )""",
)
# Columns added to tables a simulation made before they had them.
COLUMNS_ADDED = (("simulation_players", "added_by", "VARCHAR"), ("simulation_players", "added_at", "TIMESTAMP"),
                 ("simulation_objects", "scenario", "VARCHAR"))
TABLES = ("simulations", "simulation_players", "simulation_answers", "simulation_solves", "simulation_hints",
          "simulation_rules", "simulation_objects", "simulation_parts", "simulation_replays")


class SimError(ValueError):
    """A simulation that can't be started, answered or ended as asked; the message says why."""


def ensure(conn) -> None:
    for ddl in DDL:
        conn.execute(ddl)
    have = set(conn.execute("SELECT table_name, column_name FROM duckdb_columns() WHERE database_name = current_database() "
                            "AND schema_name = 'main' AND table_name IN ('simulation_players', 'simulation_objects')").fetchall())
    for table, column, kind in COLUMNS_ADDED:
        if (table, column) not in have:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {kind}")   # nosec B608 # COLUMNS_ADDED is fixed


class TenantStore:
    """A client's own database, as the app opens it."""

    def __init__(self, db, client_id: str):
        self.db, self.client_id = db, client_id

    @contextmanager
    def connect(self):
        from app.services.tenant_manager import tenant_context_for
        with tenant_context_for(self.client_id), self.db.get_connection() as conn:
            ensure(conn)
            yield conn

    # The simulation in the client's TIDE (client.py). A test's store stands in for these.
    def set_up_client(self, sim_id: str, siem_id: str, space: str, namespace: str, scenario: packs.Scenario,
                      actor: Optional[str], *, rules: bool, tide: bool, made: set, in_space: set) -> None:
        from app.services.sim import client
        client.set_up(self, sim_id, siem_id, space, namespace, scenario, actor, rules=rules, tide=tide, made=made,
                      in_space=in_space)

    def resync_client(self, sim_id: str) -> None:
        from app.services.sim import client
        client.resync(self, sim_id)

    def remove_from_client(self, sim_id: str, actor: Optional[str], kinds: Optional[set] = None) -> list:
        from app.services.sim import client
        return client.remove(self, sim_id, actor, kinds=kinds)


@dataclass
class Siem:
    """The SIEM a simulation runs on, with the credentials TIDE holds for it."""
    id: str
    label: str
    es_url: str
    kibana_url: str
    es_session: Any
    kibana_session: Any

    def es(self) -> replay.Elastic:
        return replay.Elastic(self.es_session, self.es_url, timeout=120)

    def kibana(self) -> kibana.Kibana:
        return kibana.Kibana(self.kibana_session, self.kibana_url)


def siem_for(db, siem_id: str) -> Siem:
    """A SIEM from TIDE's inventory (the client needn't have it as a destination: the simulation's
    space becomes one), with its stored credentials; a SimError when there is no such SIEM, it isn't
    Elastic, or it lacks an address or a key."""
    from app import elastic_helper
    from app.services import siem_kinds
    if not siem_id:
        raise SimError("Choose a SIEM.")
    row = db.get_siem_inventory_item(siem_id)
    if row is None or row.get("is_active") is False:
        raise SimError("There is no such SIEM in TIDE.")
    if not siem_kinds.is_elastic(row):
        raise SimError(f"{row.get('label')} isn't an Elastic SIEM: simulations replay into Elasticsearch.")
    es_url, kibana_url, key = row.get("elasticsearch_url"), row.get("kibana_url"), row.get("api_token_enc")
    if not (es_url and kibana_url and key):
        raise SimError(f"{row.get('label')} needs its Elasticsearch URL, its Kibana URL and an API key.")
    return Siem(siem_id, str(row.get("label") or siem_id), es_url, kibana_url,
                elastic_helper._make_session(key, es_url), elastic_helper._make_session(key, kibana_url))


# ── The threads ────────────────────────────────────────────────────────────────────────────────

_LOCK = threading.Lock()          # _WORK
_KICK = threading.Lock()          # which replays start, and the simulation's state, decided one at a time
_SET_UP: dict[str, threading.Lock] = {}     # sim id -> its scenarios' set-ups, one at a time


@dataclass
class _Work:
    """What runs for one simulation in this process: its threads (set-ups, replays, the end or the clean
    up) and the replays running, so End can stop them. It goes when its last thread finishes."""
    siem: Siem
    threads: set = field(default_factory=set)
    replays: dict = field(default_factory=dict)       # replay n -> replay.Replay, while it runs
    ending: bool = False


_WORK: dict[str, _Work] = {}


def _now() -> datetime:
    return datetime.now()


def _set(store, sim_id: str, only_if: Optional[tuple] = None, **values) -> None:
    cols = ", ".join(f"{k} = ?" for k in values)
    sql = f"UPDATE simulations SET {cols} WHERE id = ?"   # nosec B608 # the columns are this module's own
    params = [*values.values(), sim_id]
    if only_if:
        sql += f" AND state IN ({', '.join('?' for _ in only_if)})"
        params += list(only_if)
    with store.connect() as conn:
        conn.execute(sql, params)


def _spawn(sim_id: str, siem: Siem, target, *args, ending: bool = False) -> None:
    th = threading.Thread(target=_thread, args=(sim_id, target, *args), name=f"sim-{sim_id}", daemon=True)
    with _LOCK:
        w = _WORK.setdefault(sim_id, _Work(siem))
        w.threads.add(th)
        w.ending = w.ending or ending
    th.start()


def _thread(sim_id: str, target, *args) -> None:
    try:
        target(*args)
    finally:
        with _LOCK:
            w = _WORK.get(sim_id)
            if w:
                w.threads.discard(threading.current_thread())
                if not w.threads:
                    del _WORK[sim_id]


def _live(sim_id: str) -> bool:
    with _LOCK:
        return sim_id in _WORK


def _ending(sim_id: str) -> bool:
    with _LOCK:
        w = _WORK.get(sim_id)
        return bool(w and w.ending)


def _busy_elsewhere(siem: Siem, sim_id: Optional[str] = None) -> None:
    """One simulation at a time sets up, replays or cleans up on a SIEM: a SimError when another is."""
    with _LOCK:
        if any(w.siem.id == siem.id for sid, w in _WORK.items() if sid != sim_id):
            raise SimError(f"Another simulation is setting up, replaying or cleaning up on {siem.label}: "
                           f"wait for it to finish.")


def _register(sim_id: str, n: int, rp: replay.Replay) -> bool:
    """Hand a replay to end(); False when the simulation is being ended (don't start it)."""
    with _LOCK:
        w = _WORK.get(sim_id)
        if not w or w.ending:
            return False
        w.replays[n] = rp
        return True


def _unregister(sim_id: str, n: int) -> None:
    with _LOCK:
        w = _WORK.get(sim_id)
        if w:
            w.replays.pop(n, None)


def wait(sim_id: str, timeout: float = 600) -> None:
    """Wait until nothing runs for a simulation (for tests and scripts): its set-ups, its replays,
    including those that start meanwhile, and its end or clean up."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with _LOCK:
            w = _WORK.get(sim_id)
            threads = [t for t in (w.threads if w else ()) if t is not threading.current_thread()]
        if not threads:
            return
        for t in threads:
            t.join(max(0.0, deadline - time.monotonic()))


# ── Start ──────────────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Parts:
    """What adding a scenario does: replay its logs, make its rules in the space, set it up in the
    client's TIDE (its baseline, systems and threat actor, its rules mapped) and show its questions to
    the players. All of it, unless the Sim Admin unticks some."""
    logs: bool = True
    rules: bool = True
    tide: bool = True
    questions: bool = True

    def any(self) -> bool:
        return self.logs or self.rules or self.tide or self.questions


def _scenarios(scenario_ids: list[str]) -> list[packs.Scenario]:
    try:
        return [packs.scenario(s) for s in dict.fromkeys(scenario_ids)]
    except packs.PackError as exc:
        raise SimError(str(exc)) from None


def _replayable(scenarios: list[packs.Scenario], noise: str, speed: float) -> None:
    for sc in scenarios:
        if not sc.ready:
            raise SimError(f"{sc.label} has no logs, so it can't be replayed.")
        if noise not in sc.levels():
            raise SimError(f"{sc.label} can't be replayed at noise {noise}.")
    if not 0 <= float(speed) <= MAX_SPEED:
        raise SimError(f"The speed is 0 (as fast as allowed) to {MAX_SPEED}.")


def start(store, siem: Siem, scenario_ids: list[str], noise: str, speed: float,
          players: list[tuple[str, str]], by: str, max_eps: float = replay.MAX_EPS,
          actor: Optional[str] = None, parts: Parts = Parts()) -> str:
    """Start a simulation: checks what was asked, records it, and begins its set-up in a thread: its
    space, then each scenario with ``parts``, then their replays, one after the other. Returns its id.
    ``by`` is the Sim Admin's name as shown; ``actor`` their username, for TIDE's history of what the
    simulation sets up in the client. Players may be none: add_players() adds them while it runs."""
    if not scenario_ids:
        raise SimError("Pick at least one scenario.")
    scenarios = _scenarios(scenario_ids)
    if not parts.any():
        raise SimError("Tick at least one thing for its scenario to do.")
    if parts.logs:
        _replayable(scenarios, noise, speed)
    players = list(dict(players).items())
    _busy_elsewhere(siem)
    sim_id = uuid.uuid4().hex[:8]
    space, namespace, now = f"sim-{sim_id}", f"sim{sim_id}", _now()
    with store.connect() as conn:
        conn.execute("INSERT INTO simulations (id, siem_id, space, namespace, scenarios, noise, speed, state, "
                     "created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'setting_up', ?, ?)",
                     [sim_id, siem.id, space, namespace, json.dumps([sc.id for sc in scenarios]), noise,
                      float(speed), by, now])
        conn.executemany("INSERT INTO simulation_parts (sim_id, scenario, logs, rules, tide, questions, state, "
                         "added_by, added_at) VALUES (?, ?, ?, ?, ?, ?, 'setting_up', ?, ?)",
                         [[sim_id, sc.id, parts.logs, parts.rules, parts.tide, parts.questions, by, now]
                          for sc in scenarios])
        if players:
            conn.executemany("INSERT INTO simulation_players (sim_id, user_id, name, added_by, added_at) "
                             "VALUES (?, ?, ?, ?, ?)", [[sim_id, uid, name, by, now] for uid, name in players])
    _spawn(sim_id, siem, _run, store, siem, sim_id, scenarios, parts, noise, float(speed), float(max_eps), by, actor)
    return sim_id


def _run(store, siem: Siem, sim_id: str, scenarios: list[packs.Scenario], parts: Parts, noise: str,
         speed: float, max_eps: float, by: str, actor: Optional[str] = None) -> None:
    space, namespace = f"sim-{sim_id}", f"sim{sim_id}"
    try:
        kb, es = siem.kibana(), siem.es()
        if kb.space_exists(space):
            raise SimError(f"{siem.label} already has a space {space}.")
        titles = ", ".join(sc.label for sc in scenarios)
        kb.create_space(space, f"Simulation: {titles}"[:1024],
                        f"Made by TIDE for simulation {sim_id}, and deleted when it is cleaned up.")
        client.made_on_siem(store, sim_id, client.SIEM_SPACE, space)
        replay.install_template(es, namespace=namespace)
        client.made_on_siem(store, sim_id, client.SIEM_DATA, namespace)
        # The data streams first, empty, so the data view has their fields (@timestamp) from the start:
        # made on a pattern that matched nothing, Discover would show no histogram until reloaded.
        if parts.logs:
            replay.make_streams(es, replay.plan(scenarios, noise), namespace)
        kb.create_data_view(space, f"logs-*-{namespace}", "Simulation logs")
        for sc in scenarios:
            if _ending(sim_id):
                return                                     # ended while it was setting up
            _set_up(store, siem, sim_id, sc, parts.rules, parts.tide, actor)
        if _ending(sim_id):
            return
        if parts.logs:
            for sc in scenarios:
                _queue(store, sim_id, sc.id, noise, speed, after=True, by=by)
        _set(store, sim_id, only_if=("setting_up",), state="replaying" if parts.logs else "playing")
        _kick(store, siem, sim_id, max_eps)
    except Exception as exc:  # noqa: BLE001 - recorded on the simulation; ending and cleaning it up removes what it made
        logger.exception("Simulation %s failed", sim_id)
        _set(store, sim_id, only_if=("setting_up", "replaying"), state="failed", error=str(exc)[:500])


# ── A scenario's parts ─────────────────────────────────────────────────────────────────────────

def _set_up(store, siem: Siem, sim_id: str, sc: packs.Scenario, make_rules: bool, tide: bool,
            actor: Optional[str]) -> None:
    """Make a scenario's rules in the space and set it up in the client's TIDE, as asked, one scenario
    at a time; its part is ready once done, whatever failed (each problem is recorded and shown)."""
    with _LOCK:
        lock = _SET_UP.setdefault(sim_id, threading.Lock())
    with lock:
        try:
            sim = get(store, sim_id)
            made = _make_rules(store, siem, sim, sc) if make_rules else set()
            if make_rules or tide:
                in_space = {r["rule_id"] for r in rule_results(store, sim_id) if r["state"] == "created"}
                try:
                    store.set_up_client(sim_id, siem.id, sim["space"], sim["namespace"], sc, actor,
                                        rules=make_rules, tide=tide, made=made, in_space=in_space)
                except Exception:  # noqa: BLE001 - its own problems are recorded; the exercise goes on in Kibana
                    logger.exception("Simulation %s: could not set %s up in the client's TIDE", sim_id, sc.id)
        finally:
            with store.connect() as conn:
                conn.execute("UPDATE simulation_parts SET state = 'ready' WHERE sim_id = ? AND scenario = ?", [sim_id, sc.id])


def _make_rules(store, siem: Siem, sim: dict, sc: packs.Scenario) -> set:
    """Make a scenario's rules in the simulation's space and record each: the ids of those made. A rule
    an earlier scenario brought (two scenarios can share one of Elastic's) is there already: it is
    made once, and counts for both."""
    try:
        specs = rules.specs(sc)
    except packs.PackError as exc:
        client.problem(store, sim["id"], f"{sc.label}: could not read its rules", exc, sc.id)
        return set()
    held = {r["rule_id"] for r in rule_results(store, sim["id"])}
    kb, made, rows = siem.kibana(), set(), []
    for spec in specs:
        if spec.kibana_id in held:
            continue
        held.add(spec.kibana_id)
        state, note = "created", None
        try:
            kb.create_rule(sim["space"], rules.body(spec, sim["namespace"]))
        except replay.ElasticError as exc:
            if exc.status != 409:                          # 409: it is in the space already
                state, note = "failed", str(exc)[:500]
        except packs.PackError as exc:
            state, note = "failed", str(exc)[:500]
        if state == "created":
            made.add(spec.kibana_id)
        rows.append([sim["id"], sc.id, spec.kibana_id, siem.id, sim["space"], spec.name, state, note])
    if rows:
        with store.connect() as conn:
            conn.executemany("INSERT INTO simulation_rules (sim_id, scenario, rule_id, siem_id, space, name, state, "
                             "note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
    return made


def _open(sim: dict) -> dict:
    """A simulation that takes more scenarios and replays: once its first scenarios are set up (their
    own replays queued first), until it ends."""
    if sim["state"] == "setting_up" and not sim["interrupted"]:
        raise SimError("it is still setting up its first scenarios: wait a moment.")
    if sim["state"] not in OPEN or sim["interrupted"]:
        raise SimError("it isn't running.")
    return sim


def add_scenario(store, siem: Siem, sim_id: str, scenario_id: str, parts: Parts, noise: str, speed: float,
                 by: str, *, after: bool = False, actor: Optional[str] = None,
                 max_eps: float = replay.MAX_EPS) -> None:
    """Add a scenario to a running simulation, doing ``parts``: its rules and its set-up in TIDE in a
    thread, its questions shown at once, and its logs replayed once its rules are in: now, alongside
    any other replay, or ``after`` those asked for before it."""
    sim = _open(_check(get(store, sim_id), siem))
    sc = _scenarios([scenario_id])[0]
    if sc.id in sim["scenarios"]:
        raise SimError(f"{sc.label} is in it already: replay its logs again, or do what wasn't done, from its row.")
    if not parts.any():
        raise SimError("tick at least one thing for it to do.")
    if parts.logs:
        _replayable([sc], noise, speed)
    _busy_elsewhere(siem, sim_id)
    set_up = parts.rules or parts.tide
    with store.connect() as conn:
        conn.execute("INSERT INTO simulation_parts (sim_id, scenario, logs, rules, tide, questions, state, added_by, "
                     "added_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     [sim_id, sc.id, parts.logs, parts.rules, parts.tide, parts.questions,
                      "setting_up" if set_up else "ready", by, _now()])
        conn.execute("UPDATE simulations SET scenarios = ? WHERE id = ?", [json.dumps([*sim["scenarios"], sc.id]), sim_id])
    if parts.logs:
        _queue(store, sim_id, sc.id, noise, speed, after=after, by=by)
    if set_up:
        _spawn(sim_id, siem, _set_up_then_kick, store, siem, sim_id, sc, parts.rules, parts.tide, actor, max_eps)
    _kick(store, siem, sim_id, max_eps)


def add_parts(store, siem: Siem, sim_id: str, scenario_id: str, *, rules: bool = False, tide: bool = False,
              questions: bool = False, actor: Optional[str] = None, max_eps: float = replay.MAX_EPS) -> None:
    """Do for a scenario already in the simulation what wasn't done when it was added: make its rules
    (mapped onto its TIDE set-up, if it has one), set it up in TIDE, or show its questions."""
    _open(_check(get(store, sim_id), siem))
    part = next((p for p in scenario_parts(store, sim_id) if p["scenario"] == scenario_id), None)
    if part is None:
        raise SimError("it has no such scenario.")
    if part["state"] == "setting_up":
        raise SimError("its set-up is still under way.")
    new_rules, new_tide = rules and not part["rules"], tide and not part["tide"]
    new_questions = questions and not part["questions"]
    if not (new_rules or new_tide or new_questions):
        raise SimError("that is done already.")
    if new_rules or new_tide:
        _busy_elsewhere(siem, sim_id)
    with store.connect() as conn:
        conn.execute("UPDATE simulation_parts SET rules = rules OR ?, tide = tide OR ?, questions = questions OR ?, "
                     "state = ? WHERE sim_id = ? AND scenario = ?",
                     [new_rules, new_tide, new_questions, "setting_up" if new_rules or new_tide else "ready",
                      sim_id, scenario_id])
    if new_rules or new_tide:
        _spawn(sim_id, siem, _set_up_then_kick, store, siem, sim_id, packs.scenario(scenario_id), new_rules,
               new_tide, actor, max_eps)


def _set_up_then_kick(store, siem: Siem, sim_id: str, sc: packs.Scenario, make_rules: bool, tide: bool,
                      actor: Optional[str], max_eps: float) -> None:
    try:
        _set_up(store, siem, sim_id, sc, make_rules, tide, actor)
    finally:
        _kick(store, siem, sim_id, max_eps)               # its replay waited for its rules


# ── Replays ────────────────────────────────────────────────────────────────────────────────────

QUEUED, REPLAYING, REPLAYED, STOPPED, FAILED, CANCELLED = "queued", "replaying", "replayed", "stopped", "failed", "cancelled"
WAITING = (QUEUED, REPLAYING)                              # not finished


def _queue(store, sim_id: str, scenario: str, noise: str, speed: float, *, after: bool, by: str) -> int:
    with _KICK, store.connect() as conn:
        n = conn.execute("SELECT coalesce(max(n), 0) + 1 FROM simulation_replays WHERE sim_id = ?", [sim_id]).fetchone()[0]
        conn.execute("INSERT INTO simulation_replays (sim_id, n, scenario, noise, speed, after, state, requested_by, "
                     "requested_at) VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?)",
                     [sim_id, n, scenario, noise, float(speed), bool(after), by, _now()])
    return int(n)


def replay_scenario(store, siem: Siem, sim_id: str, scenario_id: str, noise: str, speed: float, by: str, *,
                    after: bool = False, max_eps: float = replay.MAX_EPS) -> int:
    """Replay a scenario's logs again, stamped as they are sent, as its next pass: now, alongside any
    other replay, or ``after`` those asked for before it. Returns the replay's number."""
    sim = _open(_check(get(store, sim_id), siem))
    if scenario_id not in sim["scenarios"]:
        raise SimError("it has no such scenario.")
    _replayable(_scenarios([scenario_id]), noise, speed)
    _busy_elsewhere(siem, sim_id)
    n = _queue(store, sim_id, scenario_id, noise, speed, after=after, by=by)
    _kick(store, siem, sim_id, max_eps)
    return n


def stop_replay(store, siem: Siem, sim_id: str, n: int) -> None:
    """Stop a replay that is running; what it sent stays."""
    _check(get(store, sim_id), siem)
    with _LOCK:
        w = _WORK.get(sim_id)
        rp = w.replays.get(n) if w else None
    if rp is None:
        raise SimError("that replay isn't running.")
    rp.stop()


def cancel_replay(store, siem: Siem, sim_id: str, n: int, max_eps: float = replay.MAX_EPS) -> None:
    """Take a queued replay out of the queue; those after it may then start."""
    _check(get(store, sim_id), siem)
    with _KICK, store.connect() as conn:
        done = conn.execute("UPDATE simulation_replays SET state = 'cancelled', finished_at = ? WHERE sim_id = ? "
                            "AND n = ? AND state = 'queued' RETURNING n", [_now(), sim_id, n]).fetchone()
    if not done:
        raise SimError("that replay isn't queued.")
    _kick(store, siem, sim_id, max_eps)


def _kick(store, siem: Siem, sim_id: str, max_eps: float) -> None:
    """Start each queued replay that may start now, and set the simulation replaying or playing. A
    replay waits for its scenario's set-up (its rules must be in to see it); one asked to come after
    also waits for every replay asked for before it to finish."""
    with _KICK:
        rows = replays(store, sim_id)
        if not _ending(sim_id):
            setting_up = {p["scenario"] for p in scenario_parts(store, sim_id) if p["state"] == "setting_up"}
            for r in rows:
                if r["state"] != QUEUED or r["scenario"] in setting_up:
                    continue
                if r["after"] and any(x["n"] < r["n"] and x["state"] in WAITING for x in rows):
                    continue
                r["state"] = REPLAYING
                r["pass"] = 1 + sum(1 for x in rows if x["scenario"] == r["scenario"] and x["pass"] and x is not r)
                with store.connect() as conn:
                    conn.execute("UPDATE simulation_replays SET state = 'replaying', pass = ?, started_at = ? "
                                 "WHERE sim_id = ? AND n = ? AND state = 'queued'", [r["pass"], _now(), sim_id, r["n"]])
                _spawn(sim_id, siem, _replay, store, siem, sim_id, dict(r), max_eps)
        waiting = any(r["state"] in WAITING for r in rows)
        _set(store, sim_id, only_if=("replaying", "playing"), state="replaying" if waiting else "playing")


def _progress(store, sim_id: str, n: int, pass_n: int, summary: dict) -> None:
    """A replay's progress; the simulation's own figures are the latest replay's."""
    with store.connect() as conn:
        conn.execute("UPDATE simulation_replays SET progress = ? WHERE sim_id = ? AND n = ?", [json.dumps(summary), sim_id, n])
        latest = conn.execute("SELECT max(n) FROM simulation_replays WHERE sim_id = ? AND started_at IS NOT NULL",
                              [sim_id]).fetchone()[0]
        if latest == n:
            conn.execute("UPDATE simulations SET progress = ? WHERE id = ?", [json.dumps({**summary, "pass": pass_n}), sim_id])


def _set_replay(store, sim_id: str, n: int, **values) -> None:
    cols = ", ".join(f"{k} = ?" for k in values)
    with store.connect() as conn:
        conn.execute(f"UPDATE simulation_replays SET {cols} WHERE sim_id = ? AND n = ?",   # nosec B608 # the columns are this module's own
                     [*values.values(), sim_id, n])


def _replay(store, siem: Siem, sim_id: str, r: dict, max_eps: float) -> None:
    n = r["n"]
    try:
        sim = get(store, sim_id)
        es = siem.es()
        segments = replay.plan([packs.scenario(r["scenario"])], r["noise"])
        replay.make_streams(es, segments, sim["namespace"])
        rp = replay.Replay(es, segments, namespace=sim["namespace"], speed=r["speed"], max_eps=max_eps, loop=r["pass"],
                           on_progress=lambda s: _progress(store, sim_id, n, r["pass"], s))
        if not _register(sim_id, n, rp):
            _set_replay(store, sim_id, n, state=CANCELLED, finished_at=_now())    # ended before it began
            return
        _set_replay(store, sim_id, n, run_id=rp.run_id)
        summary = rp.run()
        _progress(store, sim_id, n, r["pass"], summary)
        _set_replay(store, sim_id, n, state=STOPPED if summary.get("stopped") else REPLAYED, finished_at=_now())
        _set(store, sim_id, replayed_at=_now())
        if not summary.get("stopped"):
            try:
                store.resync_client(sim_id)
            except Exception:  # noqa: BLE001 - the rules' field checks catch up at the next sync
                logger.exception("Simulation %s: could not sync its rules again", sim_id)
    except Exception as exc:  # noqa: BLE001 - the simulation goes on; its page says why the replay stopped
        logger.exception("Simulation %s: could not replay %s", sim_id, r["scenario"])
        _set_replay(store, sim_id, n, state=FAILED, error=str(exc)[:500], finished_at=_now())
    finally:
        _unregister(sim_id, n)
        _kick(store, siem, sim_id, max_eps)


# ── End, clean up and clear ────────────────────────────────────────────────────────────────────

def _check(sim: Optional[dict], siem: Siem) -> dict:
    if sim is None:
        raise SimError("There is no such simulation.")
    if sim["siem_id"] != siem.id:
        raise SimError("That isn't the SIEM this simulation ran on.")
    return sim


def end(store, siem: Siem, sim_id: str, by: str) -> None:
    """End a simulation: stop its replays (and its set-up, if it is still setting up), cancel those
    queued, stop the players' answering, and count each rule's alerts, in a thread. Its space, data,
    rules and alerts stay on the SIEM, and what it set up stays in the client's TIDE, until it is
    cleaned up (clean_up())."""
    sim = _check(get(store, sim_id), siem)
    if sim["state"] == "ending" and not sim["interrupted"]:
        return
    if sim["state"] in ("ended", "cleaning_up"):
        raise SimError("It has ended already.")
    _set(store, sim_id, state="ending", ended_by=by)
    with _LOCK:
        w = _WORK.get(sim_id)
        previous = list(w.threads) if w else []
        if w:
            w.ending = True                                # a set-up still running starts no replay
            for rp in w.replays.values():
                rp.stop()
    with _KICK, store.connect() as conn:
        conn.execute("UPDATE simulation_replays SET state = 'cancelled', finished_at = ? WHERE sim_id = ? "
                     "AND state = 'queued'", [_now(), sim_id])
    _spawn(sim_id, siem, _stop, store, siem, sim, previous, ending=True)


def _stop(store, siem: Siem, sim: dict, previous: list) -> None:
    sim_id, space = sim["id"], sim["space"]
    for th in previous:
        th.join(600)                  # its set-ups (a sync among them) and replays, stopping
    with store.connect() as conn:     # any a restart cut off
        conn.execute("UPDATE simulation_replays SET state = 'stopped', finished_at = ? WHERE sim_id = ? "
                     "AND state IN ('queued', 'replaying')", [_now(), sim_id])
    kb = siem.kibana()
    try:
        counts = kb.alert_counts(space) if kb.space_exists(space) else None
        if counts is not None:
            with store.connect() as conn:
                for rid, n in counts.items():
                    conn.execute("UPDATE simulation_rules SET alerts = ? WHERE sim_id = ? AND rule_id = ?", [n, sim_id, rid])
                conn.execute("UPDATE simulation_rules SET alerts = 0 WHERE sim_id = ? AND state = 'created' "
                             "AND alerts IS NULL", [sim_id])
    except replay.ElasticError as exc:
        logger.warning("Simulation %s: could not count its rules' alerts: %s", sim_id, exc)
    _set(store, sim_id, state="ended", ended_at=_now())


CLEAN_PARTS = ("tide", "space", "data")     # what a clean-up removes: what it set up in TIDE, its space, its logs
CLEAN_STEPS = {"tide": ("tide",), "space": ("space", "alerts"), "data": ("data",)}


def cleanup_status(sim: dict, objs: list) -> dict[str, str]:
    """Each part of a simulation's clean-up (CLEAN_PARTS): ``none`` (it made nothing of it), ``left``,
    ``done`` or ``failed`` (the last try's reason is in its cleanup report). ``tide``: what it set up in
    the client's TIDE (its destination with its rules, baselines, systems, threat actors); ``space``: its
    Kibana space, with its rules, data view and saved searches, and its alerts; ``data``: its logs and
    their template. ``objs``: client.objects, which also says what it made on the SIEM."""
    report, made = sim.get("cleanup") or {}, {o["kind"] for o in objs}
    out = {}
    for part, steps in CLEAN_STEPS.items():
        tried = [report[s] for s in steps if report.get(s)]
        if part == "tide":
            set_up = any(o["kind"] in client.IN_TIDE and o["state"] == "made" for o in objs)
            out[part] = ("failed" if tried and not tried[0]["ok"] else "left" if set_up or not tried else "done")
        elif (client.SIEM_SPACE if part == "space" else client.SIEM_DATA) not in made:
            out[part] = "none"              # a set-up that failed early made nothing there
        else:
            out[part] = ("failed" if any(not r["ok"] for r in tried) else "done" if len(tried) == len(steps) else "left")
    return out


def clean_up(store, siem: Siem, sim_id: str, actor: Optional[str] = None, parts: tuple = CLEAN_PARTS) -> None:
    """Clean up an ended simulation, in a thread, as much of it as ``parts`` asks (CLEAN_PARTS, all of it
    unless told): remove what it set up in the client's TIDE (its systems, baselines, threat actors, and
    its destination with its rules); delete its space (with its rules and data view) and its alerts;
    delete its data streams and template. A destination can't outlive its space: deleting the space
    removes the destination from TIDE too, while its baselines and systems stay. Each removal is
    recorded; cleaning up again does what is left, or failed."""
    sim = _check(get(store, sim_id), siem)
    if sim["state"] == "cleaning_up" and not sim["interrupted"]:
        return
    if sim["state"] not in ("ended", "cleaning_up"):
        raise SimError("End it first.")
    status = cleanup_status(sim, client.objects(store, sim_id))
    todo = tuple(p for p in CLEAN_PARTS if p in parts and status[p] in ("left", "failed"))
    if not todo:
        raise SimError("It has been cleaned up: nothing it made is left." if sim["cleaned"]
                       else "That has been cleaned up already.")
    _set(store, sim_id, state="cleaning_up")
    _spawn(sim_id, siem, _clean, store, siem, sim, actor, todo, ending=True)


def _clean(store, siem: Siem, sim: dict, actor: Optional[str] = None, todo: tuple = CLEAN_PARTS) -> None:
    sim_id, space, namespace = sim["id"], sim["space"], sim["namespace"]
    kb, es = siem.kibana(), siem.es()
    report: dict[str, Any] = {k: v for k, v in (sim["cleanup"] or {}).items() if k not in ("failed", "left")}

    def from_tide(kinds: Optional[set] = None):
        try:
            return store.remove_from_client(sim_id, actor, kinds=kinds)
        except ValueError:
            raise
        except Exception as exc:  # noqa: BLE001 - reported like the SIEM's steps; cleaning up again retries
            raise ValueError(str(exc)) from exc

    steps = []
    if "tide" in todo:
        steps.append(("tide", from_tide))
    if "space" in todo:
        if "tide" not in todo:              # a destination can't outlive its space
            steps.append(("destination", lambda: from_tide({client.DESTINATION})))
        steps += [("space", lambda: kb.delete_space(space) or space), ("alerts", lambda: kibana.remove_alerts(es, space))]
    if "data" in todo:
        steps.append(("data", lambda: replay.remove_data(es, namespace)))
    blocked = ""
    for name, step in steps:
        if blocked and name in ("space", "alerts"):
            report[name] = {"ok": False, "error": blocked}
            continue
        try:
            report[name] = {"ok": True, "removed": step()}
        except (replay.ElasticError, ValueError) as exc:
            report[name] = {"ok": False, "error": str(exc)[:300]}
            if name == "destination":
                blocked = f"its destination couldn't be removed from TIDE first: {exc}"[:300]
    status = cleanup_status({**sim, "cleanup": report}, client.objects(store, sim_id))
    report["failed"] = any(st == "failed" for st in status.values())
    report["left"] = [p for p, st in status.items() if st in ("left", "failed")]
    _set(store, sim_id, state="ended", cleanup=json.dumps(report))


def clear(store, sim_id: str) -> None:
    """Delete a cleaned-up simulation's results from TIDE."""
    sim = get(store, sim_id)
    if sim is None:
        raise SimError("There is no such simulation.")
    if sim["state"] != "ended" or not sim["cleaned"]:
        raise SimError("Clean it up first, so nothing it made is left in TIDE or on the SIEM.")
    with store.connect() as conn:
        for table in TABLES:
            column = "id" if table == "simulations" else "sim_id"
            conn.execute(f"DELETE FROM {table} WHERE {column} = ?", [sim_id])   # nosec B608 # TABLES is fixed
    with _LOCK:
        _SET_UP.pop(sim_id, None)


# ── Saved searches (#126) ──────────────────────────────────────────────────────────────────────

SEARCH_LABELS = {"kql": "KQL", "esql": "ES|QL"}
SINCE_MARGIN = timedelta(minutes=5)       # a saved search opens a little before the simulation began


def search_saving(sim: dict, scenario: str, n: int, title: str, searches: list, view_id: str) -> list:
    """What save_searches saves: ``[(object id, attributes, references)]``, one for each of a question's
    searches (``[(language, search)]``, KQL and ES|QL), named after its question and language, opening on
    the simulation's time so far (its events are stamped as they are replayed). A KQL search is on the
    space's Simulation logs data view (``view_id``); an ES|QL one names its own data streams."""
    since = sim["created_at"] if isinstance(sim["created_at"], datetime) else datetime.fromisoformat(str(sim["created_at"]))
    time_range = {"from": (since - SINCE_MARGIN).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"), "to": "now"}
    totals = {lang: sum(1 for x, _ in searches if x == lang) for lang, _ in searches}
    seen: dict = {}
    out = []
    for i, (lang, query) in enumerate(searches, 1):
        seen[lang] = seen.get(lang, 0) + 1
        label = SEARCH_LABELS[lang] + (f" {seen[lang]}" if totals[lang] > 1 else "")
        attributes = {"title": f"{title} ({label})", "description": f"Made by TIDE for simulation {sim['id']}.",
                      "columns": [], "sort": [["@timestamp", "desc"]] if lang == "kql" else [], "grid": {},
                      "hideChart": False, "isTextBasedQuery": lang == "esql", "timeRestore": True,
                      "timeRange": time_range, "refreshInterval": {"pause": True, "value": 60000}}
        if lang == "kql":
            source = {"query": {"query": query, "language": "kuery"}, "filter": [],
                      "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"}
            references = [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": view_id}]
        else:
            # Discover keeps an ES|QL search's data view in it, made from the query's FROM as Discover makes
            # it, and reads it on opening: without it, "Cannot read properties of undefined (reading 'id')".
            source, references = {"query": {"esql": query}, "filter": [], "index": esql_data_view(query)}, []
        attributes["kibanaSavedObjectMeta"] = {"searchSourceJSON": json.dumps(source)}
        object_id = re.sub(r"[^a-z0-9-]+", "-", f"tide-{sim['id']}-{scenario}-q{n}-{i}".lower())
        out.append((object_id, attributes, references))
    return out


def save_searches(siem: Siem, sim: dict, scenario: str, n: int, title: str, searches: list) -> list:
    """Save a question's searches in the simulation's space (search_saving): ``[(name, saved object
    id)]``. Saving them again replaces them; cleaning the simulation up deletes them with its space."""
    kb = siem.kibana()
    view_id = ""
    if any(lang == "kql" for lang, _ in searches):
        view_id = kb.data_view_id(sim["space"], f"logs-*-{sim['namespace']}")
        if not view_id:
            raise SimError("its space has no Simulation logs data view.")
    return [(attributes["title"], kb.save_search(sim["space"], object_id, attributes, references))
            for object_id, attributes, references in search_saving(sim, scenario, n, title, searches, view_id)]


# ── Reading ────────────────────────────────────────────────────────────────────────────────────

COLUMNS = ("id", "siem_id", "space", "namespace", "scenarios", "noise", "speed", "state", "error", "progress",
           "cleanup", "created_by", "created_at", "replayed_at", "ended_by", "ended_at")
PART_COLUMNS = ("scenario", "logs", "rules", "tide", "questions", "state", "added_by", "added_at")
REPLAY_COLUMNS = ("n", "scenario", "noise", "speed", "after", "state", "pass", "run_id", "progress", "error",
                  "requested_by", "requested_at", "started_at", "finished_at")


def _row(r) -> dict:
    d = dict(zip(COLUMNS, r))
    d["scenarios"] = json.loads(d["scenarios"] or "[]")
    d["progress"] = json.loads(d["progress"]) if d["progress"] else None
    d["cleanup"] = json.loads(d["cleanup"]) if d["cleanup"] else None
    d["interrupted"] = d["state"] in ACTIVE and not _live(d["id"])
    d["cleanup_failed"] = bool(d["cleanup"] and d["cleanup"].get("failed"))
    # Cleaned: nothing it made is left (a clean-up of only some of it leaves the rest in "left").
    d["cleaned"] = bool(d["cleanup"]) and not d["cleanup_failed"] and not d["cleanup"].get("left")
    return d


def get(store, sim_id: str) -> Optional[dict]:
    with store.connect() as conn:
        r = conn.execute(f"SELECT {', '.join(COLUMNS)} FROM simulations WHERE id = ?", [sim_id]).fetchone()   # nosec B608 # fixed columns
    return _row(r) if r else None


def list_all(store) -> list[dict]:
    with store.connect() as conn:
        rows = conn.execute(f"SELECT {', '.join(COLUMNS)} FROM simulations ORDER BY created_at DESC").fetchall()   # nosec B608 # fixed columns
    return [_row(r) for r in rows]


def scenario_parts(store, sim_id: str) -> list[dict]:
    """Each scenario in the simulation, in the order added, with what was asked of it (logs, rules, tide,
    questions) and its state: setting_up (its rules and set-up under way; ``interrupted`` when a restart
    cut that off) or ready. In a simulation from before scenarios had parts, each did all of it."""
    sim = get(store, sim_id)
    if sim is None:
        return []
    with store.connect() as conn:
        rows = [dict(zip(PART_COLUMNS, r)) for r in conn.execute(
            f"SELECT {', '.join(PART_COLUMNS)} FROM simulation_parts WHERE sim_id = ?", [sim_id]).fetchall()]   # nosec B608 # fixed columns
    if not rows:
        rows = [{"scenario": s, "logs": True, "rules": True, "tide": True, "questions": True, "state": "ready",
                 "added_by": sim["created_by"], "added_at": sim["created_at"]} for s in sim["scenarios"]]
    live, order = _live(sim_id), {s: i for i, s in enumerate(sim["scenarios"])}
    for p in rows:
        p["interrupted"] = p["state"] == "setting_up" and not live
    return sorted(rows, key=lambda p: order.get(p["scenario"], len(order)))


def replays(store, sim_id: str) -> list[dict]:
    """The simulation's replays, in the order asked for: each one scenario's logs, queued, replaying,
    replayed, stopped, failed or cancelled, with its pass (which time that scenario's logs were sent)
    and progress. A simulation from before replays were kept one by one has one per pass, each of every
    scenario (its scenario '')."""
    with store.connect() as conn:
        rows = [dict(zip(REPLAY_COLUMNS, r)) for r in conn.execute(
            f"SELECT {', '.join(REPLAY_COLUMNS)} FROM simulation_replays WHERE sim_id = ? ORDER BY n", [sim_id]).fetchall()]   # nosec B608 # fixed columns
    for r in rows:
        r["progress"] = json.loads(r["progress"]) if r["progress"] else None
    if rows:
        return rows
    sim = get(store, sim_id)
    p = (sim or {}).get("progress")
    if not p:
        return []
    last = int(p.get("pass") or 1)
    return [{"n": i, "scenario": "", "noise": sim["noise"], "speed": sim["speed"], "after": i > 1,
             "state": STOPPED if i == last and p.get("stopped") else REPLAYED, "pass": i, "run_id": None,
             "progress": p if i == last else None, "error": sim["error"] if i == last else None,
             "requested_by": sim["created_by"], "requested_at": sim["created_at"] if i == 1 else None,
             "started_at": sim["created_at"] if i == 1 else None,
             "finished_at": sim["replayed_at"] if i == last else None} for i in range(1, last + 1)]


def players(store, sim_id: str) -> list[dict]:
    with store.connect() as conn:
        return [{"user_id": u, "name": n, "added_by": b, "added_at": a} for u, n, b, a in conn.execute(
            "SELECT user_id, name, added_by, added_at FROM simulation_players WHERE sim_id = ? ORDER BY name",
            [sim_id]).fetchall()]


def rule_results(store, sim_id: str) -> list[dict]:
    with store.connect() as conn:
        cols = ("scenario", "rule_id", "siem_id", "space", "name", "state", "note", "alerts")
        return [dict(zip(cols, r)) for r in conn.execute(
            f"SELECT {', '.join(cols)} FROM simulation_rules WHERE sim_id = ? ORDER BY scenario, name", [sim_id]).fetchall()]   # nosec B608 # fixed columns


# ── Playing ────────────────────────────────────────────────────────────────────────────────────

def question_scenarios(store, sim: dict) -> list[str]:
    """The scenarios whose questions the players see, in the order they were added."""
    return [p["scenario"] for p in scenario_parts(store, sim["id"]) if p["questions"]]


def _question(shown: list[str], scenario: str, n: int) -> Optional[game.Question]:
    if scenario not in shown:
        return None
    try:
        return next((q for q in game.questions(packs.scenario(scenario)) if q.n == n), None)
    except packs.PackError:
        return None


def _may_play(conn, sim: Optional[dict], user_id: str) -> Optional[str]:
    """Why this user can't play this simulation now, or None."""
    if sim is None:
        return "unknown"
    if sim["state"] == "setting_up" and not sim["interrupted"]:
        return "not_yet"
    if sim["state"] not in OPEN or sim["interrupted"]:
        return "closed"
    if not conn.execute("SELECT 1 FROM simulation_players WHERE sim_id = ? AND user_id = ?", [sim["id"], user_id]).fetchone():
        return "not_player"
    return None


def running(sim: dict) -> bool:
    """It sets up, replays or plays, and wasn't cut off by a restart: players can be added."""
    return sim["state"] in SHOWN and not sim["interrupted"]


def add_players(store, sim_id: str, people: list[tuple[str, str]], by: str = "") -> list[str]:
    """Add players (``[(TIDE user id, name)]``) to a simulation while it sets up, replays or plays: the
    names of those added, leaving out anyone playing it already. They answer from then on, as the
    players chosen at the start do. ``by``: who added them, as shown."""
    sim = get(store, sim_id)
    if sim is None:
        raise SimError("there is no such simulation.")
    if not running(sim):
        raise SimError("players can be added only while it sets up, replays or plays.")
    with store.connect() as conn:
        have = {u for (u,) in conn.execute("SELECT user_id FROM simulation_players WHERE sim_id = ?", [sim_id]).fetchall()}
        new = [(uid, name) for uid, name in dict(people).items() if uid not in have]
        if new:
            now = _now()
            conn.executemany("INSERT INTO simulation_players (sim_id, user_id, name, added_by, added_at) "
                             "VALUES (?, ?, ?, ?, ?)", [[sim_id, uid, name, by, now] for uid, name in new])
    return [name for _, name in new]


def answer(store, sim_id: str, user_id: str, scenario: str, n: int, text: str) -> dict:
    """One player's answer to one question: {"result": right | wrong | solved | too_fast | not_yet (it is
    setting up) | closed | not_player | unknown}, with the points and the write-up when right."""
    sim = get(store, sim_id)
    shown = question_scenarios(store, sim) if sim else []
    with store.connect() as conn:
        why = _may_play(conn, sim, user_id)
        if why:
            return {"result": why}
        q = _question(shown, scenario, n)
        if q is None:
            return {"result": "unknown"}
        if conn.execute("SELECT 1 FROM simulation_solves WHERE sim_id = ? AND user_id = ? AND scenario = ? AND n = ?",
                        [sim_id, user_id, scenario, n]).fetchone():
            return {"result": "solved"}
        last = conn.execute("SELECT max(answered_at) FROM simulation_answers WHERE sim_id = ? AND user_id = ?",
                            [sim_id, user_id]).fetchone()[0]
        now = _now()
        if last and (now - last).total_seconds() < MIN_SECONDS_BETWEEN_ANSWERS:
            return {"result": "too_fast"}
        right = game.is_right(q.rule, text)
        conn.execute("INSERT INTO simulation_answers (sim_id, user_id, scenario, n, answer, correct, answered_at) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?)", [sim_id, user_id, scenario, n, str(text)[:MAX_ANSWER], right, now])
        if right:
            conn.execute("INSERT INTO simulation_solves (sim_id, user_id, scenario, n, points, solved_at) VALUES (?, ?, ?, ?, ?, ?)",
                         [sim_id, user_id, scenario, n, q.points, now])
    return {"result": "right", "points": q.points, "writeup": q.writeup} if right else {"result": "wrong"}


def take_hint(store, sim_id: str, user_id: str, scenario: str, n: int) -> dict:
    """The next hint of a question, at its cost: {"result": hint | none | solved | not_yet | closed |
    not_player | unknown, "hint", "cost"}."""
    sim = get(store, sim_id)
    shown = question_scenarios(store, sim) if sim else []
    with store.connect() as conn:
        why = _may_play(conn, sim, user_id)
        if why:
            return {"result": why}
        q = _question(shown, scenario, n)
        if q is None:
            return {"result": "unknown"}
        if conn.execute("SELECT 1 FROM simulation_solves WHERE sim_id = ? AND user_id = ? AND scenario = ? AND n = ?",
                        [sim_id, user_id, scenario, n]).fetchone():
            return {"result": "solved"}
        taken = conn.execute("SELECT count(*) FROM simulation_hints WHERE sim_id = ? AND user_id = ? AND scenario = ? "
                             "AND n = ?", [sim_id, user_id, scenario, n]).fetchone()[0]
        if taken >= len(q.hints):
            return {"result": "none"}
        conn.execute("INSERT INTO simulation_hints (sim_id, user_id, scenario, n, idx, cost, taken_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     [sim_id, user_id, scenario, n, taken, q.hint_cost(), _now()])
    return {"result": "hint", "hint": q.hints[taken], "cost": q.hint_cost()}


def board(store, sim_id: str) -> list[dict]:
    """Each player's score (points solved less hints taken), solves and hints, best first; a tie goes
    to whoever got there first."""
    with store.connect() as conn:
        rows = conn.execute(
            "SELECT p.user_id, p.name, "
            "  coalesce((SELECT sum(points) FROM simulation_solves s WHERE s.sim_id = p.sim_id AND s.user_id = p.user_id), 0), "
            "  (SELECT count(*) FROM simulation_solves s WHERE s.sim_id = p.sim_id AND s.user_id = p.user_id), "
            "  coalesce((SELECT sum(cost) FROM simulation_hints h WHERE h.sim_id = p.sim_id AND h.user_id = p.user_id), 0), "
            "  (SELECT max(solved_at) FROM simulation_solves s WHERE s.sim_id = p.sim_id AND s.user_id = p.user_id) "
            "FROM simulation_players p WHERE p.sim_id = ?", [sim_id]).fetchall()
    out = [{"user_id": u, "name": nm, "score": int(pts) - int(cost), "solved": int(solved), "hint_cost": int(cost),
            "last": last} for u, nm, pts, solved, cost, last in rows]
    out.sort(key=lambda r: (-r["score"], r["last"] or datetime.max, r["name"].lower()))
    for i, r in enumerate(out, 1):
        r["rank"] = i
    return out


def timeline(store, sim_id: str) -> dict:
    """Each player's score over time, as the board counts it (points solved less hints taken): from the
    start, every solve and hint, to the end (or now). The players in name order, so a player keeps
    their place (and colour) whatever their rank."""
    sim = get(store, sim_id)
    if sim is None:
        return {"start": None, "end": None, "players": []}
    with store.connect() as conn:
        people = conn.execute("SELECT user_id, name FROM simulation_players WHERE sim_id = ? ORDER BY lower(name)",
                              [sim_id]).fetchall()
        events = conn.execute(
            "SELECT user_id, solved_at, points FROM simulation_solves WHERE sim_id = ? "
            "UNION ALL SELECT user_id, taken_at, -cost FROM simulation_hints WHERE sim_id = ? ORDER BY 2",
            [sim_id, sim_id]).fetchall()
    start = sim["created_at"]
    end = sim["ended_at"] or _now()
    players = []
    for uid, name in people:
        score, points = 0, [(start, 0)]
        for who, at, change in events:
            if who == uid:
                score += int(change)
                points.append((at, score))
        players.append({"user_id": uid, "name": name, "points": points, "score": score})
    return {"start": start, "end": max([end, *[at for _, at, _ in events]]), "players": players}


def question_stats(store, sim_id: str) -> dict[str, dict]:
    """Per question ("scenario:n"): how many players solved it, who first and when, the hints taken and
    the wrong answers given, so the hardest show."""
    with store.connect() as conn:
        out: dict[str, dict] = {}
        for sc, n, solved, first_at in conn.execute(
                "SELECT scenario, n, count(*), min(solved_at) FROM simulation_solves WHERE sim_id = ? GROUP BY 1, 2",
                [sim_id]).fetchall():
            who = conn.execute("SELECT p.name FROM simulation_solves s JOIN simulation_players p ON p.sim_id = s.sim_id "
                               "AND p.user_id = s.user_id WHERE s.sim_id = ? AND s.scenario = ? AND s.n = ? "
                               "ORDER BY s.solved_at LIMIT 1", [sim_id, sc, n]).fetchone()
            out[f"{sc}:{n}"] = {"solved": int(solved), "first": who[0] if who else None, "first_at": first_at}
        for sc, n, hints in conn.execute("SELECT scenario, n, count(*) FROM simulation_hints WHERE sim_id = ? "
                                         "GROUP BY 1, 2", [sim_id]).fetchall():
            out.setdefault(f"{sc}:{n}", {"solved": 0})["hints"] = int(hints)
        for sc, n, wrong in conn.execute("SELECT scenario, n, count(*) FROM simulation_answers WHERE sim_id = ? "
                                         "AND NOT correct GROUP BY 1, 2", [sim_id]).fetchall():
            out.setdefault(f"{sc}:{n}", {"solved": 0})["wrong"] = int(wrong)
    return out


def progress_for(store, sim_id: str, user_id: str) -> dict:
    """One player's state: {question key: {"solved": points or None, "hints": [hint text taken]}}."""
    sim = get(store, sim_id)
    if sim is None:
        return {}
    with store.connect() as conn:
        solved = {f"{s}:{n}": p for s, n, p in conn.execute(
            "SELECT scenario, n, points FROM simulation_solves WHERE sim_id = ? AND user_id = ?", [sim_id, user_id]).fetchall()}
        hints: dict[str, int] = {}
        for s, n, c in conn.execute("SELECT scenario, n, count(*) FROM simulation_hints WHERE sim_id = ? AND user_id = ? "
                                    "GROUP BY scenario, n", [sim_id, user_id]).fetchall():
            hints[f"{s}:{n}"] = int(c)
    out = {}
    for sid in question_scenarios(store, sim):
        for q in game.questions(packs.scenario(sid)):
            out[q.key] = {"solved": solved.get(q.key), "hints": q.hints[:hints.get(q.key, 0)]}
    return out
