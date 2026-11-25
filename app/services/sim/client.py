"""A simulation in its client's TIDE (#118): what its scenarios set up there, and what its clean-up
removes.

The first scenario that makes rules or is set up in TIDE links the simulation's space to the client as
a destination, "Simulation <id>" (one (SIEM, space) pair, CLAUDE.md section 6); each one after syncs
it again, so the rules made in the space are the client's rules like any other destination's until it
is cleaned up (the end keeps them). A scenario that only replays its logs adds nothing to the client.
Each of Elastic's rules has its origin recorded, as TIDE's Deploy records its copies'.

A scenario set up in TIDE: its tide.toml gives the attack as a baseline and the systems it hit. The
baseline is made with its techniques; each system is made with its devices, the baseline applied, and
the simulation's destination as its coverage; each of its rules in the space is mapped to the
technique its `covers` names, as a SIEM rule (so a disabled or broken one counts as it would on a
client's own SIEM), and the known gaps are recorded (with a review date review_days after the start,
where tide.toml gives one). Its rules made later are mapped onto its systems then. Where tide.toml
names the scenario's attacker ([threat_actor]), it is a threat actor on the client's Threat Landscape,
using the baseline's techniques, its source SIMULATION. After each replay the destination is synced
again with its field lists read afresh, so the rules' field checks see the data.

Each thing made is recorded in simulation_objects, and the clean-up removes exactly those: the
systems (with everything on them) and threat actors, the baselines, then the destination with its rules. What it made on
the SIEM (its space, its data's template) is recorded there too (made_on_siem), so the clean-up deletes
only that. A problem stops only its own step, is recorded, and is shown on the simulation; the replay
goes on regardless. Everything is done as the Sim Admin who started (or cleaned up) it, so TIDE's
history shows it as their work.
"""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta
from typing import Optional

from app.services.sim import packs, rules

logger = logging.getLogger(__name__)

DESTINATION, BASELINE, SYSTEM, ACTOR, PROBLEM = "destination", "baseline", "system", "actor", "problem"
IN_TIDE = (DESTINATION, BASELINE, SYSTEM, ACTOR)
# A threat actor's source when a simulation made it (threat_actors.source): shown on Threat Landscape as
# SIM, and left alone by the OpenCTI sync, which clears the client's OpenCTI actors.
SIMULATION = "Simulation"
# What the simulation made on the SIEM, so a clean-up deletes only that (simulation.py).
SIEM_SPACE, SIEM_DATA = "siem_space", "siem_data"


def label(sim_id: str) -> str:
    """How the things a simulation makes are named: "imreallynotbatman.com (sim 597b7902)"."""
    return f"sim {sim_id}"


def _record(store, sim_id: str, kind: str, object_id: str, name: str, note: Optional[str] = None,
            scenario: Optional[str] = None) -> None:
    with store.connect() as conn:
        conn.execute("INSERT INTO simulation_objects (sim_id, kind, object_id, name, state, note, made_at, scenario) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                     [sim_id, kind, object_id, name, "failed" if kind == PROBLEM else "made", note, datetime.now(),
                      scenario])


def made_on_siem(store, sim_id: str, kind: str, name: str) -> None:
    """Record that the simulation made its space (SIEM_SPACE) or its data's template (SIEM_DATA)."""
    _record(store, sim_id, kind, name, name)


def objects(store, sim_id: str) -> list[dict]:
    """What a simulation made in its client's TIDE, and the problems it met, in the order they came,
    each with the scenario it was for (None: the simulation's own, such as its destination)."""
    cols = ("kind", "object_id", "name", "state", "note", "made_at", "scenario")
    with store.connect() as conn:
        return [dict(zip(cols, r)) for r in conn.execute(
            f"SELECT {', '.join(cols)} FROM simulation_objects WHERE sim_id = ? ORDER BY made_at",   # nosec B608 # fixed columns
            [sim_id]).fetchall()]


def problem(store, sim_id: str, what: str, exc: Exception, scenario: Optional[str] = None) -> None:
    """Record what couldn't be done, and why; the simulation shows it, and goes on."""
    logger.warning("Simulation %s: %s: %s", sim_id, what, exc)
    _record(store, sim_id, PROBLEM, "", what, str(exc)[:500], scenario)


def _linked(store, sim_id: str) -> bool:
    return any(o["kind"] == DESTINATION and o["state"] == "made" for o in objects(store, sim_id))


def _sync(store, siem_id: str, space: str, force_mapping: bool = False) -> None:
    from app.services.sync import run_elastic_sync
    run_elastic_sync(client_id=store.client_id, force_mapping=force_mapping, only_siem_id=siem_id, only_space=space)


def _record_origins(store, sim_id: str, siem_id: str, space: str, scenarios: list[packs.Scenario],
                    actor: Optional[str]) -> None:
    """Record where each of Elastic's rules in the space came from, as TIDE's Deploy does for its copy:
    under an id of its own (rules.RuleSpec.kibana_id), TIDE knows it by its origin, so Elastic's later
    updates show for it and it isn't taken for a custom rule using Elastic's id."""
    from app.services import rule_origins
    for sc in scenarios:
        try:
            specs = [sp for sp in rules.specs(sc) if sp.source == "elastic"]
        except packs.PackError:
            continue                    # the space has none of its rules: the start said why
        for sp in specs:
            if not rule_origins.record_for_client(store.db, store.client_id, (sp.kibana_id, siem_id, space), "elastic",
                                                  sp.rule_id, "deployed", actor or rules.AUTHOR):
                logger.warning("Simulation %s: no origin recorded for Elastic's rule %s", sim_id, sp.rule_id)


def _forget_origins(store, siem_id: str, space: str) -> None:
    """The origins recorded for the space's rules, which unlinking it (deleting its rules) leaves."""
    from app.services import rule_origins
    from app.services.tenant_manager import tenant_context_for
    with tenant_context_for(store.client_id), store.db.get_connection() as conn:
        rule_origins.ensure(conn)
        conn.execute("DELETE FROM rule_origins WHERE siem_id = ? AND space = ?", [siem_id, space])


# ── Set up ─────────────────────────────────────────────────────────────────────────────────────

def set_up(store, sim_id: str, siem_id: str, space: str, namespace: str, sc: packs.Scenario,
           actor: Optional[str], *, rules: bool, tide: bool, made: set, in_space: set) -> None:
    """One scenario's part in the client's TIDE, once its rules are in the space. Links the space to
    the client, if no scenario has yet, and syncs it. With ``rules`` (its rules were just made, ids
    ``made``): records the origins of Elastic's, and maps them onto the systems an earlier set-up made
    for it. With ``tide``: makes its baseline, systems and threat actor, mapping its rules in the space
    (``in_space``, every rule there by its id, one another scenario brought among them)."""
    if not (rules or tide):
        return
    if not _linked(store, sim_id):
        name = f"Simulation {sim_id}"
        try:
            store.db.link_client_siem(store.client_id, siem_id, name=name, space=space,
                                      default_index=f"logs-*-{namespace}")
            _record(store, sim_id, DESTINATION, f"{siem_id}|{space}", name)
        except Exception as exc:  # noqa: BLE001 - recorded and shown; the replay goes on
            problem(store, sim_id, "Could not link its space to the client", exc)
            return
    try:
        _sync(store, siem_id, space)
    except Exception as exc:  # noqa: BLE001
        problem(store, sim_id, f"{sc.label}: could not sync its rules into TIDE", exc, sc.id)
    if rules:
        _record_origins(store, sim_id, siem_id, space, [sc], actor)
    from app.services.tenant_manager import tenant_context_for
    with tenant_context_for(store.client_id):
        if tide:
            try:
                spec = packs.read_tide(sc)
            except packs.PackError as exc:
                problem(store, sim_id, f"{sc.label}: could not read what to set up in TIDE", exc, sc.id)
                return
            if spec:
                _scenario(store, sim_id, sc, spec, siem_id, space, actor, in_space)
        elif made:
            _map_later(store, sim_id, sc, siem_id, space, actor, made)


def _scenario(store, sim_id: str, sc: packs.Scenario, spec: dict, siem_id: str, space: str,
              actor: Optional[str], in_space: set) -> None:
    from app import inventory_engine as engine
    from app.models.inventory import HostCreate, SystemCreate
    cid, tag = store.client_id, label(sim_id)
    b = spec.get("baseline") or {}
    try:
        pb = engine.create_playbook(f"{b.get('name') or sc.label} ({tag})", b.get("description", ""), client_id=cid)
        _record(store, sim_id, BASELINE, pb.id, pb.name, scenario=sc.id)
        for n, t in enumerate(b.get("technique", []), start=1):
            ids = [str(x) for x in t.get("techniques", [])]
            step = engine.add_playbook_step(pb.id, n, t["title"], technique_id=ids[0] if ids else "",
                                            description=t.get("description", ""), tactic=t.get("tactic", ""),
                                            client_id=cid)
            for tid in ids[1:]:
                engine.add_step_technique(step.id, tid, client_id=cid)
            engine.update_step_risks(step.id, None, priority=t.get("priority", ""), category=t.get("category", ""),
                                     actor=actor, client_id=cid)
    except Exception as exc:  # noqa: BLE001
        problem(store, sim_id, f"{sc.label}: could not make its baseline", exc, sc.id)
        return
    if spec.get("threat_actor"):
        _threat_actor(store, sim_id, sc, spec, tag)
    for s in spec.get("system", []):
        try:
            system = engine.add_system(SystemCreate(name=f"{s['name']} ({tag})", description=s.get("description")),
                                       client_id=cid)
            _record(store, sim_id, SYSTEM, system.id, system.name, scenario=sc.id)
            for h in s.get("hosts", []):
                engine.add_host(system.id, HostCreate(name=h["name"], ip_address=h.get("ip"), os=h.get("os")),
                                client_id=cid)
            copy = engine.apply_baseline(system.id, pb.id, client_id=cid, actor=actor)
            engine.set_system_coverage_destinations(system.id, [(siem_id, space)], client_id=cid, actor=actor)
            steps = {st.title: st.id for st in (engine.get_playbook(copy.playbook_id, client_id=cid).tactics or [])}
        except Exception as exc:  # noqa: BLE001
            problem(store, sim_id, f"{sc.label}: could not make the system {s.get('name')}", exc, sc.id)
            continue
        _map(store, sim_id, sc, system.id, system.name, steps, siem_id, space, actor, in_space)
        for gap in spec.get("known_gap", []):
            try:
                if gap["technique"] not in steps:
                    raise ValueError(f"the baseline has no technique '{gap['technique']}'")
                days = gap.get("review_days")
                engine.add_blind_spot("tactic", steps[gap["technique"]], gap["reason"], system_id=system.id,
                                      created_by=actor or "", override_type="gap", client_id=cid,
                                      review_by=date.today() + timedelta(days=days) if days else None)
            except Exception as exc:  # noqa: BLE001
                problem(store, sim_id, f"{sc.label}: could not record the known gap '{gap.get('technique')}'", exc, sc.id)


def _map(store, sim_id: str, sc: packs.Scenario, system_id: str, system_name: str, steps: dict, siem_id: str,
         space: str, actor: Optional[str], rule_ids: set) -> None:
    """Map each of the scenario's rules among ``rule_ids`` (those in the space) to the technique its
    `covers` names on a system (``steps``: the system's techniques by title). A rule not in the space
    (its rules weren't made, or one couldn't be) isn't mapped."""
    from app import inventory_engine as engine
    for rule in rules.specs(sc):
        if rule.kibana_id not in rule_ids:
            continue
        covers = rule.entry.get("covers")
        try:
            if covers not in steps:
                raise ValueError(f"the baseline has no technique '{covers}'")
            # As a SIEM rule, as TIDE's own window maps one: its state counts (a disabled or
            # broken rule doesn't cover the technique, or isn't effective).
            det = engine.add_step_detection(steps[covers], rule.kibana_id, source="siem", client_id=store.client_id,
                                            siem_id=siem_id, space=space, created_by=actor)
            if det:
                engine.apply_detection(det.id, system_id=system_id, client_id=store.client_id)
        except Exception as exc:  # noqa: BLE001
            problem(store, sim_id, f"{sc.label}: could not map '{rule.name}' on {system_name}", exc, sc.id)


def _map_later(store, sim_id: str, sc: packs.Scenario, siem_id: str, space: str, actor: Optional[str],
               made: set) -> None:
    """Rules made after the scenario was set up in TIDE: mapped onto the systems that set-up made, on
    the baseline applied to each. Called in the client's tenant context."""
    from app import inventory_engine as engine
    cid = store.client_id
    for o in objects(store, sim_id):
        if o["kind"] != SYSTEM or o["state"] != "made" or o["scenario"] != sc.id:
            continue
        try:
            steps = {st.title: st.id for b in engine.get_system_baselines(o["object_id"], include_detection_details=False,
                                                                           client_id=cid)
                     for st in (engine.get_playbook(b["playbook_id"], client_id=cid).tactics or [])}
        except Exception as exc:  # noqa: BLE001
            problem(store, sim_id, f"{sc.label}: could not read the techniques of {o['name']}", exc, sc.id)
            continue
        _map(store, sim_id, sc, o["object_id"], o["name"], steps, siem_id, space, actor, made)


def _threat_actor(store, sim_id: str, sc: packs.Scenario, spec: dict, tag: str) -> None:
    """The scenario's attacker as a threat actor on the client's Threat Landscape: its techniques the
    baseline's, so it opens straight onto the attack. Called in the client's tenant context."""
    actor = spec["threat_actor"]
    name = f"{actor['name']} ({tag})"
    ttps = sorted({str(t) for step in (spec.get("baseline") or {}).get("technique", []) for t in step.get("techniques", [])})
    try:
        with store.db.get_connection() as conn:
            conn.execute("INSERT INTO threat_actors (name, description, ttps, ttp_count, aliases, origin, source, last_updated) "
                         "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                         [name, actor.get("description") or None, ttps, len(ttps), actor.get("aliases") or None,
                          actor.get("origin") or None, [SIMULATION], datetime.now()])
        _record(store, sim_id, ACTOR, name, name, scenario=sc.id)
    except Exception as exc:  # noqa: BLE001
        problem(store, sim_id, f"{sc.label}: could not add its threat actor", exc, sc.id)


def resync(store, sim_id: str) -> None:
    """Sync the simulation's destination again once a replay's data is in, with the field lists read
    afresh (force_mapping): its data streams were made empty before the data, so the lists the set-up's
    sync kept would leave its rules' fields "not in the index mappings", and the rules not effective."""
    for o in objects(store, sim_id):
        if o["kind"] == DESTINATION and o["state"] == "made":
            siem_id, _, space = o["object_id"].partition("|")
            try:
                _sync(store, siem_id, space, force_mapping=True)
            except Exception as exc:  # noqa: BLE001
                problem(store, sim_id, "Could not sync its rules again after the replay", exc)


# ── Remove ─────────────────────────────────────────────────────────────────────────────────────

def remove(store, sim_id: str, actor: Optional[str], kinds: Optional[set] = None) -> list[str]:
    """Remove what the simulation made in its client's TIDE: its systems and threat actors, its
    baselines, then its destination with its rules (only those of ``kinds``, if given: a clean-up of
    its space alone removes its destination). Each one removed is marked, so cleaning up again retries
    only what failed. Returns what went; a ValueError says what couldn't."""
    from app import inventory_engine as engine
    from app.services.tenant_manager import tenant_context_for
    order = {SYSTEM: 0, ACTOR: 0, BASELINE: 1, DESTINATION: 2}
    todo = sorted((o for o in objects(store, sim_id) if o["state"] == "made" and o["kind"] in order
                   and (kinds is None or o["kind"] in kinds)),
                  key=lambda o: order[o["kind"]])
    removed, failed = [], []
    for o in todo:
        try:
            if o["kind"] == DESTINATION:
                siem_id, _, space = o["object_id"].partition("|")
                store.db.unlink_destination(store.client_id, siem_id, space=space, actor=actor)
                _forget_origins(store, siem_id, space)
            else:
                with tenant_context_for(store.client_id):
                    if o["kind"] == SYSTEM:
                        engine.delete_system(o["object_id"], client_id=store.client_id)
                    elif o["kind"] == ACTOR:       # only the one it made: a simulation's, by its name
                        with store.db.get_connection() as conn:
                            conn.execute("DELETE FROM threat_actors WHERE name = ? AND list_contains(source, ?)",
                                         [o["object_id"], SIMULATION])
                    else:
                        engine.delete_playbook(o["object_id"], client_id=store.client_id, actor=actor)
            with store.connect() as conn:
                conn.execute("UPDATE simulation_objects SET state = 'removed' WHERE sim_id = ? AND kind = ? "
                             "AND object_id = ?", [sim_id, o["kind"], o["object_id"]])
            removed.append(o["name"])
        except Exception as exc:  # noqa: BLE001 - reported; ending again retries it
            logger.warning("Simulation %s: could not remove %s %s: %s", sim_id, o["kind"], o["name"], exc)
            failed.append(f"{o['name']}: {exc}")
    if failed:
        raise ValueError("; ".join(failed)[:300])
    return removed
