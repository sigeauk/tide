"""A simulation: one run of one or more scenarios in a client's SIEM, played by the players a Sim Admin
chose, from start to end.

Start (start()): on an Elastic SIEM in TIDE's inventory (the client needn't have it as a destination),
TIDE makes the space sim-<id>, its data view and index template, and the scenarios' rules (rules.py).
It then links the space to the client as a destination and sets the scenarios up in the client's TIDE
(client.py: the rules synced in, each scenario's baseline and systems, the rules mapped), and replays
the scenarios into the namespace sim<id> (replay.py). That runs in a thread the start begins, as a
sync does; the pages read its progress. Once the replay is done the players go on answering.
Replay data (replay_data()): once the replay is done, its data can be sent again, stamped now, as the
next pass; it is replaying again meanwhile, then playing.
End (end()): the replay stops if it hasn't finished, the players stop answering, and each rule's
alerts are counted; the space, its data and rules stay, and so does what it set up in TIDE. Clean up
(clean_up()): what it set up in TIDE is removed (its systems, baselines, destination and rules), and
the space, its data streams, its template and its alerts are deleted; each removal is recorded, and
one that fails can be tried again by cleaning up again. The results stay in the client's database
until a Sim Admin clears them (clear(), once it is cleaned up).

States: setting_up, replaying, playing (the replay done), ending, ended, cleaning_up, failed. A
simulation shown as setting_up, replaying, ending or cleaning_up with no thread behind it was cut off by
a restart: it is reported as interrupted; ending (or cleaning up) it again carries on. One simulation
at a time sets up, replays or cleans up on a SIEM.

Everything is kept in the client's own database (Store), with the players by their TIDE user ids.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

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
        scenarios   VARCHAR NOT NULL,      -- JSON: the scenario ids, in replay order
        noise       VARCHAR NOT NULL,
        speed       DOUBLE NOT NULL,
        state       VARCHAR NOT NULL,
        error       VARCHAR,
        progress    VARCHAR,               -- JSON: the replay's summary
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
        PRIMARY KEY (sim_id, user_id)
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
        made_at   TIMESTAMP NOT NULL
    )""",
)
TABLES = ("simulations", "simulation_players", "simulation_answers", "simulation_solves", "simulation_hints",
          "simulation_rules", "simulation_objects")


class SimError(ValueError):
    """A simulation that can't be started, answered or ended as asked; the message says why."""


def ensure(conn) -> None:
    for ddl in DDL:
        conn.execute(ddl)


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
    def set_up_client(self, sim_id: str, siem_id: str, space: str, namespace: str, scenarios: list,
                      actor: Optional[str]) -> None:
        from app.services.sim import client
        client.set_up(self, sim_id, siem_id, space, namespace, scenarios, actor)

    def resync_client(self, sim_id: str) -> None:
        from app.services.sim import client
        client.resync(self, sim_id)

    def remove_from_client(self, sim_id: str, actor: Optional[str]) -> list:
        from app.services.sim import client
        return client.remove(self, sim_id, actor)


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

_LOCK = threading.Lock()
_WORKERS: dict[str, dict] = {}      # sim id -> {"siem_id", "thread", "replay", "ending"}


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


def _spawn(sim_id: str, siem_id: str, target, *args) -> None:
    th = threading.Thread(target=target, args=(*args,), name=f"sim-{sim_id}", daemon=True)
    with _LOCK:
        _WORKERS[sim_id] = {"siem_id": siem_id, "thread": th, "replay": None, "ending": False}
    th.start()


def _done(sim_id: str) -> None:
    """A simulation's thread is finishing: its entry goes, unless an end has replaced it."""
    with _LOCK:
        w = _WORKERS.get(sim_id)
        if w and w["thread"] is threading.current_thread():
            del _WORKERS[sim_id]


def _register(sim_id: str, rp: replay.Replay) -> bool:
    """Hand the replay to end(); False when the simulation is already being ended (don't start it)."""
    with _LOCK:
        w = _WORKERS.get(sim_id)
        if not w or w["ending"] or w["thread"] is not threading.current_thread():
            return False
        w["replay"] = rp
        return True


def wait(sim_id: str, timeout: float = 600) -> None:
    """Wait for a simulation's thread to finish (for tests and scripts)."""
    with _LOCK:
        w = _WORKERS.get(sim_id)
    if w:
        w["thread"].join(timeout)


# ── Start ──────────────────────────────────────────────────────────────────────────────────────

def start(store, siem: Siem, scenario_ids: list[str], noise: str, speed: float,
          players: list[tuple[str, str]], by: str, max_eps: float = replay.MAX_EPS,
          actor: Optional[str] = None) -> str:
    """Start a simulation: checks what was asked, records it, and begins its set-up and replay in a
    thread. Returns its id. ``by`` is the Sim Admin's name as shown; ``actor`` their username, for
    TIDE's history of what the simulation sets up in the client."""
    if not scenario_ids:
        raise SimError("Pick at least one scenario.")
    try:
        scenarios = [packs.scenario(s) for s in dict.fromkeys(scenario_ids)]
    except packs.PackError as exc:
        raise SimError(str(exc)) from None
    for sc in scenarios:
        if not sc.ready:
            raise SimError(f"{sc.label} has no logs, so it can't be replayed.")
        if noise not in sc.levels():
            raise SimError(f"{sc.label} can't be replayed at noise {noise}.")
    if not 0 <= float(speed) <= MAX_SPEED:
        raise SimError(f"The speed is 0 (as fast as allowed) to {MAX_SPEED}.")
    players = list(dict(players).items())
    if not players:
        raise SimError("Pick at least one player.")
    with _LOCK:
        if any(w["siem_id"] == siem.id for w in _WORKERS.values()):
            raise SimError(f"Another simulation is setting up, replaying or cleaning up on {siem.label}: "
                           f"wait for it to finish.")
    sim_id = uuid.uuid4().hex[:8]
    space, namespace = f"sim-{sim_id}", f"sim{sim_id}"
    with store.connect() as conn:
        conn.execute("INSERT INTO simulations (id, siem_id, space, namespace, scenarios, noise, speed, state, "
                     "created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'setting_up', ?, ?)",
                     [sim_id, siem.id, space, namespace, json.dumps([sc.id for sc in scenarios]), noise,
                      float(speed), by, _now()])
        conn.executemany("INSERT INTO simulation_players (sim_id, user_id, name) VALUES (?, ?, ?)",
                         [[sim_id, uid, name] for uid, name in players])
    _spawn(sim_id, siem.id, _run, store, siem, sim_id, scenarios, noise, float(speed), float(max_eps), actor)
    return sim_id


def _ending(sim_id: str) -> bool:
    with _LOCK:
        w = _WORKERS.get(sim_id)
        return bool(w and w["ending"])


# ── Replay data ────────────────────────────────────────────────────────────────────────────────

def replay_data(store, siem: Siem, sim_id: str, max_eps: float = replay.MAX_EPS) -> None:
    """Send a playing simulation's data again (Replay data, #127): the same scenarios at the same noise
    level and speed, stamped now, as a new run (botes.replay.run_id) and the next pass
    (botes.replay.loop), in a thread. Rules made or fixed since the last pass see it, because a rule
    only looks a few minutes back; the players go on answering; the client's TIDE is synced again
    once it is in, as after the first pass."""
    sim = _check(get(store, sim_id), siem)
    if sim["state"] != "playing":
        raise SimError("its data can be sent again once its replay is done, until it ends")
    try:
        scenarios = [packs.scenario(s) for s in sim["scenarios"]]
    except packs.PackError as exc:
        raise SimError(str(exc)) from None
    with _LOCK:
        if any(w["siem_id"] == siem.id for w in _WORKERS.values()):
            raise SimError(f"another simulation is setting up, replaying or cleaning up on {siem.label}: "
                           f"wait for it to finish")
    _set(store, sim_id, only_if=("playing",), state="replaying", error=None)
    if (get(store, sim_id) or {}).get("state") != "replaying":
        raise SimError("it was ended meanwhile")
    _spawn(sim_id, siem.id, _again, store, siem, sim, scenarios, float(max_eps))


def _again(store, siem: Siem, sim: dict, scenarios: list[packs.Scenario], max_eps: float) -> None:
    sim_id = sim["id"]
    n = int((sim["progress"] or {}).get("pass") or 1) + 1
    try:
        rp = replay.Replay(siem.es(), replay.plan(scenarios, sim["noise"]), namespace=sim["namespace"],
                           speed=sim["speed"], max_eps=max_eps, loop=n,
                           on_progress=lambda s: _set(store, sim_id, progress=json.dumps({**s, "pass": n})))
        if not _register(sim_id, rp):
            return                                         # ended before it began
        summary = rp.run()
        _set(store, sim_id, progress=json.dumps({**summary, "pass": n}), replayed_at=_now())
        if not summary.get("stopped"):
            try:
                store.resync_client(sim_id)
            except Exception:  # noqa: BLE001 - the rules' field checks catch up at the next sync
                logger.exception("Simulation %s: could not sync its rules again", sim_id)
        _set(store, sim_id, only_if=("replaying",), state="playing")
    except Exception as exc:  # noqa: BLE001 - the simulation goes on; its page says why the pass stopped
        logger.exception("Simulation %s: could not send its data again", sim_id)
        _set(store, sim_id, only_if=("replaying",), state="playing", error=str(exc)[:500])
    finally:
        _done(sim_id)


def _run(store, siem: Siem, sim_id: str, scenarios: list[packs.Scenario], noise: str, speed: float,
         max_eps: float, actor: Optional[str] = None) -> None:
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
        segments = replay.plan(scenarios, noise)
        # The data streams first, empty, so the data view has their fields (@timestamp) from the start:
        # made on a pattern that matched nothing, Discover would show no histogram until reloaded.
        replay.make_streams(es, segments, namespace)
        kb.create_data_view(space, f"logs-*-{namespace}", "Simulation logs")
        made = []
        for sc in scenarios:
            for spec in rules.specs(sc):
                try:
                    kb.create_rule(space, rules.body(spec, namespace))
                    made.append([sim_id, sc.id, spec.kibana_id, siem.id, space, spec.name, "created", None])
                except (packs.PackError, replay.ElasticError) as exc:
                    made.append([sim_id, sc.id, spec.kibana_id, siem.id, space, spec.name, "failed", str(exc)[:500]])
        if made:
            with store.connect() as conn:
                conn.executemany("INSERT INTO simulation_rules (sim_id, scenario, rule_id, siem_id, space, name, "
                                 "state, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", made)
        if not _ending(sim_id):
            try:
                store.set_up_client(sim_id, siem.id, space, namespace, scenarios, actor)
            except Exception:  # noqa: BLE001 - its own problems are recorded; the exercise goes on in Kibana
                logger.exception("Simulation %s: could not set it up in the client's TIDE", sim_id)
        rp = replay.Replay(es, segments, namespace=namespace, speed=speed, max_eps=max_eps,
                           on_progress=lambda s: _set(store, sim_id, progress=json.dumps(s)))
        if not _register(sim_id, rp):
            return                                         # ended while it was setting up
        _set(store, sim_id, only_if=("setting_up",), state="replaying")
        summary = rp.run()
        _set(store, sim_id, progress=json.dumps(summary), replayed_at=_now())
        if not summary.get("stopped"):
            try:
                store.resync_client(sim_id)
            except Exception:  # noqa: BLE001 - the rules' field checks catch up at the next sync
                logger.exception("Simulation %s: could not sync its rules again", sim_id)
        _set(store, sim_id, only_if=("replaying",), state="playing")
    except Exception as exc:  # noqa: BLE001 - recorded on the simulation; ending and cleaning it up removes what it made
        logger.exception("Simulation %s failed", sim_id)
        _set(store, sim_id, only_if=("setting_up", "replaying"), state="failed", error=str(exc)[:500])
    finally:
        _done(sim_id)


# ── End, clean up and clear ────────────────────────────────────────────────────────────────────

def _check(sim: Optional[dict], siem: Siem) -> dict:
    if sim is None:
        raise SimError("There is no such simulation.")
    if sim["siem_id"] != siem.id:
        raise SimError("That isn't the SIEM this simulation ran on.")
    return sim


def end(store, siem: Siem, sim_id: str, by: str) -> None:
    """End a simulation: stop its replay (and its set-up, if it is still setting up) and the players'
    answering, and count each rule's alerts, in a thread. Its space, data, rules and alerts stay on the
    SIEM, and what it set up stays in the client's TIDE, until it is cleaned up (clean_up())."""
    sim = _check(get(store, sim_id), siem)
    if sim["state"] == "ending" and not sim["interrupted"]:
        return
    if sim["state"] in ("ended", "cleaning_up"):
        raise SimError("It has ended already.")
    _set(store, sim_id, state="ending", ended_by=by)
    with _LOCK:
        w = _WORKERS.get(sim_id)
        if w:
            w["ending"] = True                             # a set-up still running won't start its replay
            if w["replay"]:
                w["replay"].stop()
        previous = w["thread"] if w else None
        th = threading.Thread(target=_stop, args=(store, siem, sim, previous), name=f"sim-end-{sim_id}", daemon=True)
        _WORKERS[sim_id] = {"siem_id": siem.id, "thread": th, "replay": None, "ending": True}
    th.start()


def _stop(store, siem: Siem, sim: dict, previous: Optional[threading.Thread]) -> None:
    sim_id, space = sim["id"], sim["space"]
    try:
        if previous is not None:
            previous.join(600)        # the set-up (a sync among it) or replay, stopping
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
    finally:
        _done(sim_id)


def clean_up(store, siem: Siem, sim_id: str, actor: Optional[str] = None) -> None:
    """Clean up an ended simulation, in a thread: remove what it set up in the client's TIDE (its
    systems, baselines, and its destination with its rules), then delete its space (with its rules and
    data view), its data streams and template, and its alerts. Each removal is recorded; cleaning up
    again retries any that failed."""
    sim = _check(get(store, sim_id), siem)
    if sim["state"] == "cleaning_up" and not sim["interrupted"]:
        return
    if sim["state"] not in ("ended", "cleaning_up"):
        raise SimError("End it first.")
    if sim["cleaned"]:
        raise SimError("It has been cleaned up: nothing it made is left.")
    _set(store, sim_id, state="cleaning_up")
    with _LOCK:
        th = threading.Thread(target=_clean, args=(store, siem, sim, actor), name=f"sim-clean-{sim_id}", daemon=True)
        _WORKERS[sim_id] = {"siem_id": siem.id, "thread": th, "replay": None, "ending": True}
    th.start()


def _clean(store, siem: Siem, sim: dict, actor: Optional[str] = None) -> None:
    sim_id, space, namespace = sim["id"], sim["space"], sim["namespace"]
    kb, es = siem.kibana(), siem.es()
    report: dict[str, Any] = {}

    def from_tide():
        try:
            return store.remove_from_client(sim_id, actor)
        except ValueError:
            raise
        except Exception as exc:  # noqa: BLE001 - reported like the SIEM's steps; ending again retries
            raise ValueError(str(exc)) from exc

    # Only what it made on the SIEM: a set-up that failed early (a key without the privileges, say)
    # left nothing there, and deleting it would be refused for the same reason.
    made = {o["kind"] for o in client.objects(store, sim_id)}
    steps = [("tide", from_tide)]
    if client.SIEM_SPACE in made:
        steps += [("space", lambda: kb.delete_space(space) or space),
                  ("alerts", lambda: kibana.remove_alerts(es, space))]
    if client.SIEM_DATA in made:
        steps.append(("data", lambda: replay.remove_data(es, namespace)))
    failed = False
    for name, step in steps:
        try:
            report[name] = {"ok": True, "removed": step()}
        except (replay.ElasticError, ValueError) as exc:
            report[name] = {"ok": False, "error": str(exc)[:300]}
            failed = True
    report["failed"] = failed
    try:
        _set(store, sim_id, state="ended", cleanup=json.dumps(report))
    finally:
        _done(sim_id)


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


# ── Saved searches (#126) ──────────────────────────────────────────────────────────────────────

SEARCH_LABELS = {"kql": "KQL", "esql": "ES|QL"}
SINCE_MARGIN = timedelta(minutes=5)       # a saved search opens a little before the simulation began


def esql_data_view(query: str) -> dict:
    """The ad hoc data view Discover makes for an ES|QL query, as it keeps it in a saved search: on the
    query's FROM sources (joined by commas), with @timestamp as its time field, and the id Discover gives
    it (the SHA-256 of "esql-" and that pattern)."""
    import hashlib
    m = re.match(r"(?is)\s*FROM\s+([^|]+?)(\s+METADATA[^|]*)?\s*(\||$)", query)
    pattern = ",".join(s.strip() for s in m.group(1).split(",")) if m else ""
    return {"id": hashlib.sha256(f"esql-{pattern}".encode()).hexdigest(), "title": pattern, "name": pattern,
            "timeFieldName": "@timestamp", "type": "esql", "sourceFilters": [], "fieldFormats": {},
            "runtimeFieldMap": {}, "allowNoIndex": False, "allowHidden": False}


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


def _row(r) -> dict:
    d = dict(zip(COLUMNS, r))
    d["scenarios"] = json.loads(d["scenarios"] or "[]")
    d["progress"] = json.loads(d["progress"]) if d["progress"] else None
    d["cleanup"] = json.loads(d["cleanup"]) if d["cleanup"] else None
    with _LOCK:
        live = d["id"] in _WORKERS
    d["interrupted"] = d["state"] in ACTIVE and not live
    d["cleanup_failed"] = bool(d["cleanup"] and d["cleanup"].get("failed"))
    d["cleaned"] = bool(d["cleanup"]) and not d["cleanup_failed"]
    return d


def get(store, sim_id: str) -> Optional[dict]:
    with store.connect() as conn:
        r = conn.execute(f"SELECT {', '.join(COLUMNS)} FROM simulations WHERE id = ?", [sim_id]).fetchone()   # nosec B608 # fixed columns
    return _row(r) if r else None


def list_all(store) -> list[dict]:
    with store.connect() as conn:
        rows = conn.execute(f"SELECT {', '.join(COLUMNS)} FROM simulations ORDER BY created_at DESC").fetchall()   # nosec B608 # fixed columns
    return [_row(r) for r in rows]


def players(store, sim_id: str) -> list[dict]:
    with store.connect() as conn:
        return [{"user_id": u, "name": n} for u, n in conn.execute(
            "SELECT user_id, name FROM simulation_players WHERE sim_id = ? ORDER BY name", [sim_id]).fetchall()]


def rule_results(store, sim_id: str) -> list[dict]:
    with store.connect() as conn:
        cols = ("scenario", "rule_id", "siem_id", "space", "name", "state", "note", "alerts")
        return [dict(zip(cols, r)) for r in conn.execute(
            f"SELECT {', '.join(cols)} FROM simulation_rules WHERE sim_id = ? ORDER BY scenario, name", [sim_id]).fetchall()]   # nosec B608 # fixed columns


# ── Playing ────────────────────────────────────────────────────────────────────────────────────

def _question(sim: dict, scenario: str, n: int) -> Optional[game.Question]:
    if scenario not in sim["scenarios"]:
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


def answer(store, sim_id: str, user_id: str, scenario: str, n: int, text: str) -> dict:
    """One player's answer to one question: {"result": right | wrong | solved | too_fast | not_yet (it is
    setting up) | closed | not_player | unknown}, with the points and the write-up when right."""
    sim = get(store, sim_id)
    with store.connect() as conn:
        why = _may_play(conn, sim, user_id)
        if why:
            return {"result": why}
        q = _question(sim, scenario, n)
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
    with store.connect() as conn:
        why = _may_play(conn, sim, user_id)
        if why:
            return {"result": why}
        q = _question(sim, scenario, n)
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
    for sid in sim["scenarios"]:
        for q in game.questions(packs.scenario(sid)):
            out[q.key] = {"solved": solved.get(q.key), "hints": q.hints[:hints.get(q.key, 0)]}
    return out
