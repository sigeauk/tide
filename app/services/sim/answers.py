"""Checking a scenario's answers in a replay: every search in its answers.md runs, and each answer must
be in what its searches find.

For each question, every ES|QL, KQL and EQL block in its "### N." section of answers.md is run on that
scenario's events alone (botes.scenario), in one replay (botes.replay.run_id) or a private index. A
block passes if it runs and finds something. The question passes if its answer, as answer_key.toml
accepts it, shows up in what its blocks found: one of its accepted values, every part of a several-part
answer, or one of its numbers. A question whose answer is reasoning rather than data (data_check =
false) only needs its blocks to run. KQL runs through ES|QL's KQL() function.

The answers' searches are written for the namespace AUTHORED_NAMESPACE (FROM logs-iis.access-botes);
Target reads them for a simulation's own namespace, or for a private index. check_fresh() replays a
scenario into a private index at full speed, checks it, and deletes the index.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field

from app.services.sim import packs, replay

AUTHORED_NAMESPACE = "botes"      # the namespace the answers' searches name
KQL_ROWS = 50                     # documents fetched for a KQL block, to look for the answer in
CELLS = 200                       # rows of an ES|QL result looked through


def sections(text: str) -> dict[int, list[tuple[str, str]]]:
    """{question: [(language, block), ...]} from an answers.md's '### N.' sections."""
    out: dict[int, list[tuple[str, str]]] = {}
    for m in re.finditer(r"^### (\d+)\..*?(?=^### |^## |^---\s*$|\Z)", text, re.M | re.S):
        out[int(m.group(1))] = [(lang, body.strip()) for lang, body in
                                re.findall(r"^```(esql|kql|eql)\n(.*?)^```", m.group(0), re.M | re.S)]
    return out


def answer_found(rule: dict, cells: list) -> bool:
    text = " | ".join(re.sub(r"\s+", " ", str(c)).lower() for c in cells if c is not None)
    if rule.get("accept") and any(str(a).lower() in text for a in rule["accept"]):
        return True
    if rule.get("contains") and all(str(c).lower() in text for c in rule["contains"]):
        return True
    if rule.get("contains_any") and any(str(c).lower() in text for c in rule["contains_any"]):
        return True
    if rule.get("numbers"):
        tol = float(rule.get("tolerance", 0)) + 1e-9
        for c in cells:
            if isinstance(c, bool):
                continue
            try:
                v = float(str(c).replace(",", "")) if not isinstance(c, (int, float)) else float(c)
            except ValueError:
                continue
            if any(abs(v - float(x)) <= tol for x in rule["numbers"]):
                return True
    return False


class Target:
    """Where a scenario's searches run: its events in a namespace's data streams (one replay of them),
    or in a private index."""

    def __init__(self, scenario: str, *, namespace: str = AUTHORED_NAMESPACE, index: str | None = None,
                 run_id: str | None = None):
        self.scenario, self.namespace, self.index, self.run_id = scenario, namespace, index, run_id

    @property
    def everything(self) -> str:
        return self.index or f"logs-*-{self.namespace}"

    def source(self, name: str) -> str:
        """A data stream as the answers name it (logs-<dataset>-botes), in this target's namespace."""
        m = re.fullmatch(rf"logs-(.+)-{AUTHORED_NAMESPACE}", name)
        return f"logs-{m.group(1)}-{self.namespace}" if m else name

    def esql(self, query: str) -> str:
        m = re.match(r"(?is)FROM\s+([^|]+?)(\s+METADATA[^|]*)?(\||$)", query)
        if not m:
            return query
        sources = [s.strip() for s in m.group(1).split(",")]
        rest = query[m.end(1):]
        conds = []
        if self.index:
            datasets = [d.group(1) for s in sources if s != f"logs-*-{AUTHORED_NAMESPACE}"
                        and (d := re.fullmatch(rf"logs-(.+)-{AUTHORED_NAMESPACE}", s))]
            if datasets:
                conds.append(" OR ".join(f'event.dataset == "{d}"' for d in datasets))
            head = f"FROM {self.index}"
        else:
            head = "FROM " + ", ".join(self.source(s) for s in sources)
        if self.run_id:
            conds.append(f'botes.replay.run_id == "{self.run_id}"')
        conds.append(f'botes.scenario == "{self.scenario}"')
        return head + "".join(f" | WHERE {c}" for c in conds) + (" " + rest.lstrip() if rest.strip() else "")

    def kql(self, kql: str) -> str:
        esc = kql.replace("\\", "\\\\").replace('"', '\\"')
        run = (f' AND botes.replay.run_id == "{self.run_id}"' if self.run_id else "") + \
            f' AND botes.scenario == "{self.scenario}"'
        return f'FROM {self.everything} | WHERE KQL("{esc}"){run} | DROP event.original | LIMIT {KQL_ROWS}'

    def eql_filter(self) -> dict:
        terms = [{"term": {"botes.scenario": self.scenario}}]
        if self.run_id:
            terms.append({"term": {"botes.replay.run_id": self.run_id}})
        return {"bool": {"filter": terms}}


def run_block(es: replay.Elastic, target: Target, lang: str, block: str) -> tuple[list, int, str | None]:
    """(every cell found, how many rows, why it failed or None)."""
    try:
        if lang == "eql":
            r = es.call("POST", f"/{target.everything}/_eql/search", "run an EQL search",
                        json_body={"query": block, "size": 10, "filter": target.eql_filter()})
            hits = r.get("hits", {})
            found = hits.get("sequences") or hits.get("events") or []
            cells = []
            for item in found:
                for ev in item.get("events", [item]):
                    src = ev.get("_source", {})
                    proc = src.get("process", {})
                    cells += [proc.get("name"), proc.get("pid"), proc.get("command_line"),
                              src.get("host", {}).get("name")]
            return cells, len(found), None
        query = target.kql(block) if lang == "kql" else target.esql(block)
        try:
            r = es.call("POST", "/_query", "run an ES|QL search", json_body={"query": query}, params={"format": "json"})
        except replay.ElasticError as exc:
            if lang != "kql" or "event.original" not in str(exc):
                raise
            r = es.call("POST", "/_query", "run an ES|QL search",       # a slim replay has no raw events to drop
                        json_body={"query": query.replace(" | DROP event.original", "")}, params={"format": "json"})
        rows = r.get("values", [])
        return [c for row in rows[:CELLS] for c in row], len(rows), None
    except replay.ElasticError as exc:
        return [], 0, exc.reason or str(exc)


@dataclass
class Result:
    n: int
    searches: int
    problems: list[str] = field(default_factory=list)
    reasoning: bool = False           # data_check = false: only the searches are checked

    @property
    def passed(self) -> bool:
        return not self.problems


def check(es: replay.Elastic, sc: packs.Scenario, target: Target, only: list[int] | None = None) -> list[Result]:
    """Each question's result in this target, in order."""
    afile = sc.path("answers.md")
    blocks = sections(afile.read_text(encoding="utf-8")) if afile.is_file() else {}
    key = packs.read_key(sc)
    results = []
    for n in sorted(only or set(blocks) | set(key)):
        entry = key.get(n, {})
        rule = {k: v for k, v in entry.items() if k in ("accept", "contains", "contains_any", "numbers", "tolerance")}
        res = Result(n, len(blocks.get(n, [])), reasoning=not entry.get("data_check", True))
        cells_all = []
        for i, (lang, block) in enumerate(blocks.get(n, []), 1):
            cells, rows, err = run_block(es, target, lang, block)
            if err:
                res.problems.append(f"search {i} ({lang}) failed: {err[:200]}")
            elif rows == 0:
                res.problems.append(f"search {i} ({lang}) found nothing")
            cells_all += cells
        if not blocks.get(n):
            res.problems.append("no searches in its write-up")
        if not res.reasoning and rule and not answer_found(rule, cells_all):
            res.problems.append("its answer isn't in what the searches found")
        results.append(res)
    return results


def check_fresh(es: replay.Elastic, sc: packs.Scenario, noise: str, prefix: str = "tide-sim-check") -> list[Result]:
    """Replay a scenario at full speed into a private index (prefix-<random>), check its answers there,
    and delete the index, however the check ends."""
    index = f"{prefix}-{uuid.uuid4().hex[:8]}"
    try:
        replay.install_template(es, index=index)
        rp = replay.Replay(es, replay.plan([sc], noise), index=index, speed=0, max_eps=3000, workers=3)
        summary = rp.run()
        if summary["refused"]:
            raise replay.ElasticError(f"replay {sc.id} for its check", None,
                                      f"{summary['refused']:,} events refused: {summary['first_refusal']}")
        es.call("POST", f"/{index}/_refresh", f"refresh {index}")
        return check(es, sc, Target(sc.id, index=index))
    finally:
        replay.remove_index(es, index)
