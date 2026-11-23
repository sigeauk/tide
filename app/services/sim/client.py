"""A simulation in its client's TIDE (#118): what a start sets up there, and what its clean-up removes.

The simulation's space is linked to the client as a destination, "Simulation <id>" (one (SIEM, space)
pair, CLAUDE.md section 6), and that destination is synced, so the scenarios' rules are the client's
rules like any other destination's until it is cleaned up (the end keeps them). Each scenario's tide.toml gives the attack as a
baseline and the systems it hit: the baseline is made with its techniques; each system is made with
its devices, the baseline applied, and the simulation's destination as its coverage; every rule in
rules.toml is mapped to the technique its `covers` names, and the known gaps are recorded. After the
replay the destination is synced again, so the rules' field checks see the data.

Each thing made is recorded in simulation_objects, and the clean-up removes exactly those: the
systems (with everything on them), the baselines, then the destination with its rules. What it made on
the SIEM (its space, its data's template) is recorded there too (made_on_siem), so the clean-up deletes
only that. A problem stops only its own step, is recorded, and is shown on the simulation; the replay
goes on regardless. Everything is done as the Sim Admin who started (or cleaned up) it, so TIDE's
history shows it as their work.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from app.services.sim import packs, rules

logger = logging.getLogger(__name__)

DESTINATION, BASELINE, SYSTEM, PROBLEM = "destination", "baseline", "system", "problem"
IN_TIDE = (DESTINATION, BASELINE, SYSTEM)
# What the simulation made on the SIEM, so a clean-up deletes only that (simulation.py).
SIEM_SPACE, SIEM_DATA = "siem_space", "siem_data"


def label(sim_id: str) -> str:
    """How the things a simulation makes are named: "imreallynotbatman.com (sim 597b7902)"."""
    return f"sim {sim_id}"


def _record(store, sim_id: str, kind: str, object_id: str, name: str, note: Optional[str] = None) -> None:
    with store.connect() as conn:
        conn.execute("INSERT INTO simulation_objects (sim_id, kind, object_id, name, state, note, made_at) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?)",
                     [sim_id, kind, object_id, name, "failed" if kind == PROBLEM else "made", note, datetime.now()])


def made_on_siem(store, sim_id: str, kind: str, name: str) -> None:
    """Record that the simulation made its space (SIEM_SPACE) or its data's template (SIEM_DATA)."""
    _record(store, sim_id, kind, name, name)


def objects(store, sim_id: str) -> list[dict]:
    """What a simulation made in its client's TIDE, and the problems it met, in the order they came."""
    cols = ("kind", "object_id", "name", "state", "note")
    with store.connect() as conn:
        return [dict(zip(cols, r)) for r in conn.execute(
            f"SELECT {', '.join(cols)} FROM simulation_objects WHERE sim_id = ? ORDER BY made_at",   # nosec B608 # fixed columns
            [sim_id]).fetchall()]


def _problem(store, sim_id: str, what: str, exc: Exception) -> None:
    logger.warning("Simulation %s: %s: %s", sim_id, what, exc)
    _record(store, sim_id, PROBLEM, "", what, str(exc)[:500])


def _sync(store, siem_id: str, space: str) -> None:
    from app.services.sync import run_elastic_sync
    run_elastic_sync(client_id=store.client_id, only_siem_id=siem_id, only_space=space)


# ── Set up ─────────────────────────────────────────────────────────────────────────────────────

def set_up(store, sim_id: str, siem_id: str, space: str, namespace: str,
           scenarios: list[packs.Scenario], actor: Optional[str]) -> None:
    """Link the simulation's space to the client, sync its rules in, and make each scenario's baseline
    and systems. Its rules must already be in the space."""
    name = f"Simulation {sim_id}"
    try:
        store.db.link_client_siem(store.client_id, siem_id, name=name, space=space,
                                  default_index=f"logs-*-{namespace}")
        _record(store, sim_id, DESTINATION, f"{siem_id}|{space}", name)
    except Exception as exc:  # noqa: BLE001 - recorded and shown; the replay goes on
        _problem(store, sim_id, "Could not link its space to the client", exc)
        return
    try:
        _sync(store, siem_id, space)
    except Exception as exc:  # noqa: BLE001
        _problem(store, sim_id, "Could not sync its rules into TIDE", exc)
    from app.services.tenant_manager import tenant_context_for
    with tenant_context_for(store.client_id):
        for sc in scenarios:
            try:
                spec = packs.read_tide(sc)
            except packs.PackError as exc:
                _problem(store, sim_id, f"{sc.label}: could not read what to set up in TIDE", exc)
                continue
            if spec:
                _scenario(store, sim_id, sc, spec, siem_id, space, actor)


def _scenario(store, sim_id: str, sc: packs.Scenario, spec: dict, siem_id: str, space: str,
              actor: Optional[str]) -> None:
    from app import inventory_engine as engine
    from app.models.inventory import HostCreate, SystemCreate
    cid, tag = store.client_id, label(sim_id)
    b = spec.get("baseline") or {}
    try:
        pb = engine.create_playbook(f"{b.get('name') or sc.label} ({tag})", b.get("description", ""), client_id=cid)
        _record(store, sim_id, BASELINE, pb.id, pb.name)
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
        _problem(store, sim_id, f"{sc.label}: could not make its baseline", exc)
        return
    for s in spec.get("system", []):
        try:
            system = engine.add_system(SystemCreate(name=f"{s['name']} ({tag})", description=s.get("description")),
                                       client_id=cid)
            _record(store, sim_id, SYSTEM, system.id, system.name)
            for h in s.get("hosts", []):
                engine.add_host(system.id, HostCreate(name=h["name"], ip_address=h.get("ip"), os=h.get("os")),
                                client_id=cid)
            copy = engine.apply_baseline(system.id, pb.id, client_id=cid, actor=actor)
            engine.set_system_coverage_destinations(system.id, [(siem_id, space)], client_id=cid, actor=actor)
            steps = {st.title: st.id for st in (engine.get_playbook(copy.playbook_id, client_id=cid).tactics or [])}
        except Exception as exc:  # noqa: BLE001
            _problem(store, sim_id, f"{sc.label}: could not make the system {s.get('name')}", exc)
            continue
        for rule in rules.specs(sc):
            covers = rule.entry.get("covers")
            try:
                if covers not in steps:
                    raise ValueError(f"the baseline has no technique '{covers}'")
                det = engine.add_step_detection(steps[covers], rule.rule_id, source="manual", client_id=cid,
                                                siem_id=siem_id, space=space, created_by=actor)
                if det:
                    engine.apply_detection(det.id, system_id=system.id, client_id=cid)
            except Exception as exc:  # noqa: BLE001
                _problem(store, sim_id, f"{sc.label}: could not map '{rule.name}' on {system.name}", exc)
        for gap in spec.get("known_gap", []):
            try:
                if gap["technique"] not in steps:
                    raise ValueError(f"the baseline has no technique '{gap['technique']}'")
                engine.add_blind_spot("tactic", steps[gap["technique"]], gap["reason"], system_id=system.id,
                                      created_by=actor or "", override_type="gap", client_id=cid)
            except Exception as exc:  # noqa: BLE001
                _problem(store, sim_id, f"{sc.label}: could not record the known gap '{gap.get('technique')}'", exc)


def resync(store, sim_id: str) -> None:
    """Sync the simulation's destination again, once its data is in (the rules' field checks)."""
    for o in objects(store, sim_id):
        if o["kind"] == DESTINATION and o["state"] == "made":
            siem_id, _, space = o["object_id"].partition("|")
            try:
                _sync(store, siem_id, space)
            except Exception as exc:  # noqa: BLE001
                _problem(store, sim_id, "Could not sync its rules again after the replay", exc)


# ── Remove ─────────────────────────────────────────────────────────────────────────────────────

def remove(store, sim_id: str, actor: Optional[str]) -> list[str]:
    """Remove what the simulation made in its client's TIDE: its systems, its baselines, then its
    destination with its rules. Each one removed is marked, so cleaning up again retries only what
    failed. Returns what went; a ValueError says what couldn't."""
    from app import inventory_engine as engine
    from app.services.tenant_manager import tenant_context_for
    order = {SYSTEM: 0, BASELINE: 1, DESTINATION: 2}
    todo = sorted((o for o in objects(store, sim_id) if o["state"] == "made" and o["kind"] in order),
                  key=lambda o: order[o["kind"]])
    removed, failed = [], []
    for o in todo:
        try:
            if o["kind"] == DESTINATION:
                siem_id, _, space = o["object_id"].partition("|")
                store.db.unlink_destination(store.client_id, siem_id, space=space, actor=actor)
            else:
                with tenant_context_for(store.client_id):
                    if o["kind"] == SYSTEM:
                        engine.delete_system(o["object_id"], client_id=store.client_id)
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
