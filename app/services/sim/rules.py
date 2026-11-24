"""A scenario's detection rules (its rules.toml), as the Kibana rules a simulation runs in its space.

Each rule's index patterns are narrowed to the simulation's own data streams, so it searches nothing
else on the SIEM: a pattern for Elastic's logs-* data streams keeps its dataset and takes the
simulation's namespace (logs-iis.access-* becomes logs-iis.access-<namespace>), and any other pattern
(winlogbeat-*, an exact index) is dropped. A rule left with no pattern isn't run. The rules are
enabled and run every minute over the last six, so they see every event a replay sends, unless
rules.toml says otherwise (enabled, interval, from: the demo starts some rules broken). They are
authored AUTHOR.

Sources:
  custom   the rule in full in rules.toml
  elastic  one of Elastic's prebuilt rules, by its rule_id, from the detection-rules copy in the image
  sigma    a Sigma rule, by its id, from the Sigma repository in the image, converted with a pipeline
           from sim/sigma/ (pipeline = "ecs.yml", the default)
A Sigma or custom rule keeps its rules.toml rule_id in the simulation's space. An Elastic rule takes an
id of its own there, the same in every simulation (RuleSpec.kibana_id), as TIDE's Deploy gives a copy
one: under Elastic's id Kibana couldn't install Elastic's own rule in the space, and TIDE would flag
it. The simulation records the copy's origin in its client's TIDE instead (client.py).
"""

from __future__ import annotations

import os
import re
import tomllib
import uuid
from dataclasses import dataclass
from functools import lru_cache

from app.attack_tactics import ID_BY_NAME, tactic_entry, technique_entries
from app.services.sim import packs

AUTHOR = "TIDE Simulations"
TAG = "TIDE Simulation"
INTERVAL, LOOK_BACK = "1m", "now-6m"     # each rule runs every minute, over the last six
TYPES = {"query": "kuery", "threshold": "kuery", "eql": "eql"}
SEVERITIES = ("low", "medium", "high", "critical")
SOURCES = ("custom", "elastic", "sigma")
INTERVAL_RX, FROM_RX = re.compile(r"[1-9][0-9]*[smh]"), re.compile(r"now-[1-9][0-9]*[smh]")
_ELASTIC_IDS = uuid.uuid5(uuid.NAMESPACE_URL, "tide-simulations:elastic-rules")
PIPELINES = packs.SIM_DIR / "sigma"
DEFAULT_PIPELINE = "ecs.yml"


@dataclass
class RuleSpec:
    """One entry of a scenario's rules.toml."""
    rule_id: str
    name: str
    source: str
    entry: dict

    @property
    def kibana_id(self) -> str:
        """Its rule id in the simulation's space: an Elastic rule's own, derived from Elastic's so it is
        the same in every simulation; any other rule's rules.toml rule_id."""
        return str(uuid.uuid5(_ELASTIC_IDS, self.rule_id)) if self.source == "elastic" else self.rule_id


def specs(sc: packs.Scenario) -> list[RuleSpec]:
    """A scenario's rule set ([] without a rules.toml), or a PackError saying what is wrong with it."""
    path = sc.path("rules.toml")
    if not path.is_file():
        return []
    where = packs._shown(path)
    try:
        entries = tomllib.loads(path.read_text(encoding="utf-8")).get("rule", [])
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise packs.PackError(f"{where}: {exc}") from None
    out, seen = [], set()
    for i, e in enumerate(entries if isinstance(entries, list) else [], 1):
        rid = e.get("rule_id") if isinstance(e, dict) else None
        if not isinstance(rid, str) or not re.fullmatch(r"[0-9a-f-]{36}", rid):
            raise packs.PackError(f"{where}: rule {i} needs rule_id, a UUID")
        if rid in seen:
            raise packs.PackError(f"{where}: rule_id {rid} is there twice")
        seen.add(rid)
        source = e.get("source")
        if source not in SOURCES:
            raise packs.PackError(f"{where}: rule {i}'s source is one of {', '.join(SOURCES)}, not '{source}'")
        if source == "sigma" and not (PIPELINES / os.path.basename(str(e.get("pipeline", DEFAULT_PIPELINE)))).is_file():
            raise packs.PackError(f"{where}: rule {i}'s pipeline isn't in sim/sigma/")
        if "enabled" in e and not isinstance(e["enabled"], bool):
            raise packs.PackError(f"{where}: rule {i}'s enabled is true or false")
        if "interval" in e and not INTERVAL_RX.fullmatch(str(e["interval"])):
            raise packs.PackError(f'{where}: rule {i}\'s interval is a number of s, m or h, such as "5m"')
        if "from" in e and not FROM_RX.fullmatch(str(e["from"])):
            raise packs.PackError(f'{where}: rule {i}\'s from is now- and a number of s, m or h, such as "now-6m"')
        out.append(RuleSpec(rid, str(e.get("name", "")), source, e))
    return out


def scope(patterns: list[str], namespace: str) -> list[str]:
    """Index patterns narrowed to a namespace's data streams: logs-<dataset>-<anything> becomes
    logs-<dataset>-<namespace>; a pattern that isn't for logs-* data streams is dropped."""
    out = []
    for p in patterns:
        p = p.strip()
        if not p.startswith("logs-") or p.startswith("-"):
            continue
        if p.count("-") >= 2:                  # logs-<dataset>-<namespace>: the namespace is the last part
            scoped = p.rsplit("-", 1)[0] + f"-{namespace}"
        elif p.endswith("*"):                  # logs-* or logs-windows.*: the dataset part runs on
            scoped = p + f"-{namespace}"
        else:
            scoped = None
        if scoped and scoped not in out:
            out.append(scoped)
    return out


def body(spec: RuleSpec, namespace: str) -> dict:
    """The Kibana rule for a spec, under its kibana_id, its index patterns narrowed to the namespace,
    enabled and run every minute over the last six unless rules.toml says otherwise; a PackError when
    it can't be run (not found, no pattern left, or a field it needs)."""
    rule = {"custom": _custom, "elastic": _elastic, "sigma": _sigma}[spec.source](spec, namespace)
    where = f"rule {spec.name or spec.rule_id}"
    if rule.get("type") not in TYPES:
        raise packs.PackError(f"{where}: a {rule.get('type')} rule can't be run in a simulation")
    for key in ("data_view_id", "output_index", "id", "immutable", "rule_source", "created_at", "updated_at",
                "created_by", "updated_by", "revision", "execution_summary"):
        rule.pop(key, None)
    rule["index"] = scope(list(rule.get("index") or []), namespace)
    if not rule["index"]:
        raise packs.PackError(f"{where}: none of its index patterns is for logs-* data streams")
    tags = [str(t) for t in rule.get("tags") or [] if t != TAG]
    e = spec.entry
    rule.update(rule_id=spec.kibana_id, enabled=bool(e.get("enabled", True)), interval=str(e.get("interval", INTERVAL)),
                actions=[], exceptions_list=[], author=[AUTHOR], tags=[*tags, TAG])
    rule["from"] = str(e.get("from", LOOK_BACK))
    return rule


@lru_cache(maxsize=1)
def _elastic_files() -> dict[str, str]:
    """{rule_id: its TOML} for Elastic's prebuilt rules in the image."""
    from app.services import elastic_rules
    root, out = elastic_rules.repo_path(), {}
    for sub in ("rules", "rules_building_block"):
        for path in elastic_rules.toml_files(root, sub):
            with open(path, encoding="utf-8", errors="replace") as fh:
                m = re.search(r'^rule_id = "([0-9a-f-]+)"', fh.read(), re.M)
            if m:
                out.setdefault(m.group(1), path)
    return out


def _elastic(spec: RuleSpec, namespace: str) -> dict:
    from app.services import elastic_rules
    path = _elastic_files().get(spec.rule_id)
    if not path:
        raise packs.PackError(f"Elastic's rule {spec.rule_id} ({spec.name}) isn't in this image's detection rules")
    with open(path, "rb") as fh:
        doc = tomllib.load(fh)
    return elastic_rules.kibana_payload({"rule_json": elastic_rules.packaged(doc)}, spec.rule_id, True)


@lru_cache(maxsize=1)
def _sigma_files() -> dict[str, str]:
    """{id: its YAML} for the Sigma rules in the image."""
    from app.config import get_settings
    root, out = get_settings().sigma_repo_path, {}
    for top in ("rules", "rules-emerging-threats", "rules-threat-hunting", "rules-compliance", "rules-dfir"):
        for dirpath, _dirs, files in os.walk(os.path.join(root, top)):
            for name in files:
                if name.endswith((".yml", ".yaml")):
                    path = os.path.join(dirpath, name)
                    with open(path, encoding="utf-8", errors="replace") as fh:
                        m = re.search(r"^id:\s*([0-9a-f-]{36})\s*$", fh.read(4096), re.M)
                    if m:
                        out.setdefault(m.group(1), path)
    return out


def _sigma(spec: RuleSpec, namespace: str) -> dict:
    from app import sigma_helper
    path = _sigma_files().get(spec.rule_id)
    if not path:
        raise packs.PackError(f"The Sigma rule {spec.rule_id} ({spec.name}) isn't in this image's Sigma rules")
    pipeline = PIPELINES / os.path.basename(str(spec.entry.get("pipeline", DEFAULT_PIPELINE)))
    with open(path, encoding="utf-8") as fh:
        yaml = fh.read()
    rule, why = sigma_helper.deploy_payload(yaml, True, f"logs-*-{namespace}",
                                            custom_pipeline_yaml=pipeline.read_text(encoding="utf-8"))
    if rule is None:
        raise packs.PackError(f"The Sigma rule {spec.name or spec.rule_id} couldn't be converted: {why}")
    return rule


def _custom(spec: RuleSpec, namespace: str) -> dict:
    e, where = spec.entry, f"rule {spec.name or spec.rule_id}"
    kind = e.get("type")
    if kind not in TYPES:
        raise packs.PackError(f"{where}: type is one of {', '.join(TYPES)}")
    index = scope(list(e.get("index", [])), namespace)
    if not index:
        raise packs.PackError(f"{where}: none of its index patterns is for logs-* data streams")
    severity = e.get("severity", "medium")
    if severity not in SEVERITIES:
        raise packs.PackError(f"{where}: severity is one of {', '.join(SEVERITIES)}")
    rule = {
        "rule_id": spec.rule_id, "name": spec.name, "description": str(e.get("description", spec.name)),
        "type": kind, "language": e.get("language", TYPES[kind]), "query": str(e.get("query", "")),
        "index": index, "severity": severity, "risk_score": int(e.get("risk_score", 47)),
        "enabled": True, "interval": INTERVAL, "from": LOOK_BACK, "max_signals": 100,
        "author": [AUTHOR], "tags": [*[str(t) for t in e.get("tags", [])], TAG], "threat": [],
    }
    if not rule["query"]:
        raise packs.PackError(f"{where}: it has no query")
    if kind == "threshold":
        fields = e.get("threshold_field", [])
        rule["threshold"] = {"field": [fields] if isinstance(fields, str) else list(fields),
                             "value": int(e.get("threshold_value", 1))}
    techniques, tactic = list(e.get("techniques", [])), e.get("tactic")
    if techniques:
        tid = ID_BY_NAME.get(tactic or "")
        if not tid:
            raise packs.PackError(f"{where}: its tactic '{tactic}' isn't an ATT&CK tactic")
        rule["threat"] = [{"framework": "MITRE ATT&CK", "tactic": tactic_entry(tid, tactic),
                           "technique": technique_entries(techniques)}]
        rule["tags"].append(f"Tactic: {tactic}")
    return rule
