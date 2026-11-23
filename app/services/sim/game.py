"""A scenario's questions as a game: the questions with their points and hints, and whether an answer
is right by the scenario's answer key (answer_key.toml).

An answer is compared lower-case, with quotes, backticks and extra spaces taken out. It is right if:
    accept        it is one of these exactly
    contains      it holds every one of these (an answer in several parts)
    contains_any  it holds one of these
    numbers       its first number is one of these (commas ignored), within tolerance
Each hint costs a quarter of the question's points (at least 1) when taken, solved or not. Who
answered what is kept by the simulation; this module only knows the questions and the rules.
Standard library only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.services.sim import packs

DEFAULT_POINTS = 100


@dataclass
class Question:
    scenario: str
    n: int                    # its number in its scenario
    text: str                 # as questions.md has it (Markdown)
    points: int
    hints: list[str]
    rule: dict                # accept, contains, contains_any, numbers, tolerance
    writeup: str              # its "### N." section of answers.md (Markdown)

    @property
    def key(self) -> str:
        return f"{self.scenario}:{self.n}"

    def hint_cost(self) -> int:
        return max(1, round(self.points / 4))


def questions(sc: packs.Scenario) -> list[Question]:
    """A scenario's questions, in order: each numbered line of questions.md that its answer key has an
    entry for, with that entry's points, hints and rule, and its write-up from answers.md. A PackError
    when its answer key can't be read."""
    qfile = sc.path("questions.md")
    if not qfile.is_file():
        return []
    key = packs.read_key(sc)
    afile = sc.path("answers.md")
    atext = afile.read_text(encoding="utf-8") if afile.is_file() else ""
    writeups = {int(m.group(1)): m.group(0).strip() for m in
                re.finditer(r"^### (\d+)\..*?(?=^### |^## |^---\s*$|\Z)", atext, re.M | re.S)}
    out = []
    for m in re.finditer(r"^(\d+)\. (.+)$", qfile.read_text(encoding="utf-8"), re.M):
        n = int(m.group(1))
        k = key.get(n)
        if not k:
            continue
        rule = {x: k[x] for x in ("accept", "contains", "contains_any", "numbers", "tolerance") if x in k}
        out.append(Question(sc.id, n, m.group(2).strip(), int(k.get("points", DEFAULT_POINTS)),
                            [str(h) for h in k.get("hints", [])], rule, writeups.get(n, "")))
    return out


def normalise(text: str) -> str:
    text = re.sub(r"[`\"'“”‘’]", "", str(text).lower())
    return re.sub(r"\s+", " ", text).strip().strip(".,;:").strip()


def first_number(text: str) -> float | None:
    m = re.search(r"-?\d[\d,]*(?:\.\d+)?", text)
    if not m:
        return None
    try:
        return float(m.group().replace(",", ""))
    except ValueError:
        return None


def is_right(rule: dict, given: str) -> bool:
    g = normalise(given)
    if not g:
        return False
    if any(g == normalise(a) for a in rule.get("accept", [])):
        return True
    if rule.get("contains") and all(normalise(c) in g for c in rule["contains"]):
        return True
    if any(normalise(c) in g for c in rule.get("contains_any", [])):
        return True
    if rule.get("numbers"):
        num = first_number(given)
        tol = float(rule.get("tolerance", 0))
        if num is not None and any(abs(num - float(x)) <= tol + 1e-9 for x in rule["numbers"]):
            return True
    return False
