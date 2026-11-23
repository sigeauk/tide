"""The simulations' scenarios and noise packs, read from sim/ (built into the image at /app/sim).

    sim/scenarios/<id>/scenario.toml       what it is and when it happened
    sim/scenarios/<id>/manifest.json       each log file's source, format, events and times
    sim/scenarios/<id>/logs/*.ndjson.gz    the attack: one file per source, oldest event first
    sim/scenarios/<id>/noise/*.ndjson.gz   the scenario's routine events, sent at noise normal and busy
    sim/scenarios/<id>/questions.md        the questions, numbered from 1
    sim/scenarios/<id>/answers.md          each answer's write-up (its "### N." section), with the searches
    sim/scenarios/<id>/answer_key.toml     points, the answers each question accepts, and hints
    sim/scenarios/<id>/rules.toml          the detection rules a simulation runs (rules.py)
    sim/scenarios/<id>/tide.toml           what it sets up in its client's TIDE (client.py)
    sim/scenarios/intro.md, searches.md    what players read first, and how to read the searches
    sim/noise/<id>/                        a noise pack: noise.toml, logs/, manifest.json

A folder is a scenario when it has a scenario.toml; its name is the scenario's id. The catalogue is
in time order, and leaves out a folder it can't read, saying why, so one broken scenario can't stop
the others. Noise comes at three levels: quiet sends the window's logs/; normal adds the scenario's
own routine events (noise/); busy also sends the lead either side of the window and lays the
scenario's noise packs over it (routine traffic from the same network at another time, each event
moved by the gap between the pack's start and the scenario's span). A noise pack fits only
scenarios from its environment. Standard library only.
"""

from __future__ import annotations

import gzip
import json
import re
import tomllib
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.services.sim import ecs

SIM_DIR = Path(__file__).resolve().parents[3] / "sim"
SCENARIOS_DIR = SIM_DIR / "scenarios"
NOISE_DIR = SIM_DIR / "noise"
NOISE_LEVELS = ("quiet", "normal", "busy")


class PackError(ValueError):
    """A scenario or noise pack that can't be read, or isn't there."""


def _shown(path: Path) -> str:
    """A path as it is in TIDE's repository: sim/scenarios/<id>/..."""
    try:
        return "sim/" + str(path.relative_to(SIM_DIR)).replace("\\", "/")
    except ValueError:
        return str(path)


@dataclass
class LogFile:
    path: Path
    part: str                 # "logs" (the attack) or "noise" (routine events)
    source: str               # the dataset key in ecs.DATASETS
    format: str               # "splunk-export", "ecs" or "suricata-eve"
    events: int
    first: str | None
    last: str | None
    clock_offset: timedelta = timedelta(0)     # added to each event's time; a noise pack's moves it
    in_window: int | None = None               # how many of its events fall in the scenario's window

    @property
    def size(self) -> int:
        return self.path.stat().st_size if self.path.is_file() else 0


def read_pack_file(f: LogFile, start: datetime | None = None, end: datetime | None = None):
    """(event time, dataset key, line) for a pack file's events in [start, end), in the file's order
    (oldest first), each time moved by the file's clock offset."""
    with gzip.open(f.path, "rb") as fh:
        for line in fh:
            line = line.rstrip(b"\r\n")
            if not line.strip():
                continue
            t = ecs.line_time(line)
            if t is None:
                continue
            t += f.clock_offset
            if (start and t < start) or (end and t >= end):
                continue
            yield t, f.source, line


def _time(value, where: str) -> datetime:
    t = ecs.parse_time(str(value)) if value else None
    if not t:
        raise PackError(f"{where}: '{value}' isn't a time (ISO 8601, UTC, such as 2016-08-10T21:35:00Z)")
    return t


def _window(value, where: str) -> tuple[datetime, datetime]:
    if not isinstance(value, list) or len(value) != 2:
        raise PackError(f"{where}: window is [start, end], two times")
    start, end = _time(value[0], where), _time(value[1], where)
    if end <= start:
        raise PackError(f"{where}: the window ends before it starts")
    return start, end


def _files(folder: Path, data: dict, part: str | None, where: str) -> list[LogFile]:
    """The log files a manifest.json lists (part None: as each entry's path says)."""
    try:
        return [LogFile(folder / f["file"], part or f["file"].split("/", 1)[0], f["source"],
                        f.get("format", "splunk-export"), int(f.get("events", 0)), f.get("first"), f.get("last"),
                        timedelta(seconds=float(f.get("clock_offset_seconds", 0))), f.get("in_window"))
                for f in data.get("files", [])]
    except (ValueError, KeyError, TypeError) as exc:
        raise PackError(f"{where}: {exc}") from None


def _manifest(folder: Path) -> dict | None:
    path = folder / "manifest.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PackError(f"{_shown(path)}: {exc}") from None


def _toml(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise PackError(f"{_shown(path)}: {exc}") from None


# ── Noise packs ────────────────────────────────────────────────────────────────────────────────

@dataclass
class NoisePack:
    """Routine traffic from one network at one time, laid over a scenario's span at noise busy."""
    id: str
    dir: Path
    title: str
    environment: str          # whose network: it fits only scenarios from the same one
    source: str
    licence: str
    window: tuple[datetime, datetime]          # what it holds, in original time
    files: list[LogFile] = field(default_factory=list)

    @property
    def length(self) -> timedelta:
        return self.window[1] - self.window[0]

    @property
    def ready(self) -> bool:
        return bool(self.files) and all(f.path.is_file() for f in self.files)

    def events(self) -> int:
        return sum(f.events for f in self.files)


def load_noise(folder: Path) -> NoisePack:
    where = _shown(folder / "noise.toml")
    meta = _toml(folder / "noise.toml")
    missing = [k for k in ("title", "environment", "window") if k not in meta]
    if missing:
        raise PackError(f"{where} needs {', '.join(missing)}")
    np = NoisePack(folder.name, folder, str(meta["title"]), str(meta["environment"]), str(meta.get("source", "")),
                   str(meta.get("licence", "")), _window(meta["window"], where))
    data = _manifest(folder)
    if data is not None:
        np.files = _files(folder, data, "noise", _shown(folder / "manifest.json"))
    return np


def noise_catalogue(folder: Path | None = None, problems: dict[str, str] | None = None) -> dict[str, NoisePack]:
    """Every noise pack that can be read, by id; why the others can't in problems, when given."""
    folder = NOISE_DIR if folder is None else folder
    out: dict[str, NoisePack] = {}
    for d in sorted(folder.iterdir()) if folder.is_dir() else []:
        if d.is_dir() and (d / "noise.toml").is_file():
            try:
                out[d.name] = load_noise(d)
            except PackError as exc:
                if problems is not None:
                    problems[d.name] = str(exc)
    return out


def attacker_hits(np: NoisePack, attacker: list[str]) -> dict[str, dict[str, int]]:
    """{file: {indicator: events}} for each of the attacker's indicators (an address, a domain, a hash, a
    file name) found in a noise pack's events, compared case-insensitively. Empty when there are none."""
    needles = {a: a.lower().encode() for a in attacker if a.strip()}
    hits: dict[str, dict[str, int]] = {}
    for f in np.files:
        with gzip.open(f.path, "rb") as fh:
            for line in fh:
                low = line.lower()
                for a, n in needles.items():
                    if n in low:
                        by = hits.setdefault(f.path.name, {})
                        by[a] = by.get(a, 0) + 1
    return hits


# ── Scenarios ──────────────────────────────────────────────────────────────────────────────────

@dataclass
class Scenario:
    id: str
    dir: Path
    title: str                # short, for lists: "Web defacement"
    date: str                 # as people say it: "10 August 2016"
    environment: str          # whose network: noise packs fit only scenarios from the same one
    source: str               # where the logs came from
    licence: str
    window: tuple[datetime, datetime] | None   # the attack, in original time
    lead: timedelta           # kept either side of the window in the pack
    checked_at: list[str] = field(default_factory=list)   # noise levels its answers have been checked at
    files: list[LogFile] = field(default_factory=list)
    noise_packs: list[str] = field(default_factory=list)  # shared noise packs laid over it at noise busy
    attacker: list[str] = field(default_factory=list)     # the attacker's indicators: never in the noise

    @property
    def label(self) -> str:
        return f"{self.title} ({self.date})"

    @property
    def span(self) -> tuple[datetime, datetime] | None:
        """What the pack holds: the window, with the lead either side."""
        return (self.window[0] - self.lead, self.window[1] + self.lead) if self.window else None

    @property
    def ready(self) -> bool:
        """Its logs are there, so it can be replayed."""
        return bool(self.files) and self.window is not None and all(f.path.is_file() for f in self.files)

    def path(self, name: str) -> Path:
        return self.dir / name

    def files_for(self, noise: str, keys: list[str] | None = None) -> list[LogFile]:
        """Its own files a replay at this noise level sends: logs/, and noise/ unless quiet."""
        return [f for f in self.files if (f.part == "logs" or noise != "quiet") and (keys is None or f.source in keys)]

    def noise_files(self, keys: list[str] | None = None) -> list[LogFile]:
        """Its noise packs' files, each moved onto its timeline: a pack's first moment is the start of its
        span. A PackError if a pack isn't there, has no logs, or is from another environment."""
        if not self.noise_packs:
            return []
        found = noise_catalogue()
        out = []
        for pid in self.noise_packs:
            np = found.get(pid)
            if np is None:
                raise PackError(f"{self.id}'s noise pack '{pid}' isn't in {_shown(NOISE_DIR / pid)}")
            if np.environment != self.environment:
                raise PackError(f"{self.id} is from {self.environment}, but noise pack '{pid}' is from "
                                f"{np.environment}: its hosts and users wouldn't be there")
            if not np.ready:
                raise PackError(f"noise pack '{pid}' has no logs")
            shift = self.span[0] - np.window[0]
            out += [replace(f, clock_offset=f.clock_offset + shift, in_window=None)
                    for f in np.files if keys is None or f.source in keys]
        return out

    def replay(self, noise: str, keys: list[str] | None = None) -> tuple[datetime, datetime, list[LogFile]]:
        """(start, end, files) of a replay at this noise level, in original time: the window and its own
        files; at busy, the span (the window with its lead) and its noise packs too."""
        if noise not in NOISE_LEVELS:
            raise PackError(f"The noise level is one of {', '.join(NOISE_LEVELS)}, not '{noise}'")
        if noise != "busy":
            return self.window[0], self.window[1], self.files_for(noise, keys)
        start, end = self.span
        return start, end, self.files_for("normal", keys) + self.noise_files(keys)

    def levels(self) -> list[str]:
        """The noise levels it can be replayed at: busy only when its noise packs are there."""
        try:
            self.noise_files()
        except PackError:
            return ["quiet", "normal"]
        return list(NOISE_LEVELS)

    def window_events(self, noise: str = "quiet") -> int | None:
        """How many events a replay at this noise level sends (None when it can't be told: busy without
        its noise packs, or with one longer than its span)."""
        if noise == "busy":
            try:
                extra = self.noise_files()
            except PackError:
                return None
            span = self.span[1] - self.span[0]
            if any(p.length > span for p in noise_catalogue().values() if p.id in self.noise_packs):
                return None
            return sum(f.events for f in self.files) + sum(f.events for f in extra)
        counts = [f.in_window for f in self.files_for(noise)]
        return None if any(c is None for c in counts) else sum(counts)

    def size(self) -> int:
        return sum(f.size for f in self.files)


def _names(meta: dict, name: str, where: str) -> list[str]:
    value = meta.get(name, [])
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
        raise PackError(f'{where}: {name} is a list of names, such as {name} = ["..."]')
    return list(value)


def parse_duration(text: str) -> timedelta:
    m = re.fullmatch(r"\s*(\d+)\s*([dhms])\s*", str(text))
    if not m:
        raise PackError(f"'{text}' isn't a time such as 30m, 2h or 1d")
    unit = {"d": "days", "h": "hours", "m": "minutes", "s": "seconds"}[m.group(2)]
    return timedelta(**{unit: int(m.group(1))})


def load(folder: Path) -> Scenario:
    where = _shown(folder / "scenario.toml")
    meta = _toml(folder / "scenario.toml")
    missing = [k for k in ("title", "date") if k not in meta]
    if missing:
        raise PackError(f"{where} needs {', '.join(missing)}")
    data = _manifest(folder)
    window = meta.get("window")
    if window is None and data and data.get("window"):
        window = _window(data["window"], _shown(folder / "manifest.json"))
    elif window is not None:
        window = _window(window, where)
    checked = meta.get("checked_at", [])
    if not isinstance(checked, list) or any(c not in NOISE_LEVELS for c in checked):
        raise PackError(f"{where}: checked_at is a list of noise levels: {', '.join(NOISE_LEVELS)}")
    sc = Scenario(folder.name, folder, str(meta["title"]), str(meta["date"]), str(meta.get("environment", folder.name)),
                  str(meta.get("source", "")), str(meta.get("licence", "")), window,
                  parse_duration(meta.get("lead", "0m")), [c for c in NOISE_LEVELS if c in checked],
                  noise_packs=_names(meta, "noise_packs", where), attacker=_names(meta, "attacker", where))
    if data is not None:
        sc.files = _files(folder, data, None, _shown(folder / "manifest.json"))
    return sc


def catalogue(folder: Path | None = None, problems: dict[str, str] | None = None) -> dict[str, Scenario]:
    """Every scenario that can be read, by id, in time order; why the others can't in problems, when given."""
    folder = SCENARIOS_DIR if folder is None else folder
    found = []
    for d in sorted(folder.iterdir()) if folder.is_dir() else []:
        if d.is_dir() and (d / "scenario.toml").is_file():
            try:
                found.append(load(d))
            except PackError as exc:
                if problems is not None:
                    problems[d.name] = str(exc)
    never = datetime.max.replace(tzinfo=timezone.utc)
    return {s.id: s for s in sorted(found, key=lambda s: (s.window[0] if s.window else never, s.id))}


def scenario(name: str, folder: Path | None = None) -> Scenario:
    """One scenario by id, or a PackError saying why it can't be had."""
    folder = SCENARIOS_DIR if folder is None else folder
    if re.fullmatch(r"[\w.-]+", name) and (folder / name / "scenario.toml").is_file():
        return load(folder / name)
    problems: dict[str, str] = {}
    names = [*catalogue(folder, problems), *problems]
    raise PackError(f"There is no scenario '{name}'. Choose from: {', '.join(sorted(names)) or 'none'}")


def read_key(sc: Scenario) -> dict[int, dict]:
    """A scenario's answer_key.toml by question number ({} when it has none), or a PackError saying
    what is wrong with it."""
    path = sc.path("answer_key.toml")
    if not path.is_file():
        return {}
    where = _shown(path)
    entries = _toml(path).get("question", [])
    if not isinstance(entries, list):
        raise PackError(f"{where}: each question is a [[question]] table")
    key: dict[int, dict] = {}
    for i, q in enumerate(entries, 1):
        n = q.get("n") if isinstance(q, dict) else None
        if not isinstance(n, int) or isinstance(n, bool) or n < 1:
            raise PackError(f"{where}: question entry {i} needs n = its number in questions.md")
        if n in key:
            raise PackError(f"{where}: question {n} is there twice")
        for name in ("accept", "contains", "contains_any", "numbers", "hints"):
            if name in q and not isinstance(q[name], list):
                raise PackError(f'{where}: question {n}\'s {name} is a list, such as {name} = ["..."]')
        if any(not isinstance(x, (int, float)) or isinstance(x, bool) for x in q.get("numbers", [])):
            raise PackError(f"{where}: question {n}'s numbers are numbers, such as numbers = [3]")
        for name in ("points", "tolerance"):
            if name in q and (not isinstance(q[name], (int, float)) or isinstance(q[name], bool)):
                raise PackError(f"{where}: question {n}'s {name} is a number")
        key[n] = q
    return key


def read_tide(sc: Scenario) -> dict:
    """What a simulation of the scenario sets up in its client's TIDE (tide.toml: its baseline, the
    systems it hit, its known gaps), {} when it has none, or a PackError saying what is wrong."""
    path = sc.path("tide.toml")
    if not path.is_file():
        return {}
    where, data = _shown(path), _toml(path)
    baseline = data.get("baseline")
    if not isinstance(baseline, dict) or not baseline.get("name"):
        raise PackError(f"{where}: needs a [baseline] with its name")
    titles = set()
    for i, t in enumerate(baseline.get("technique", []), 1):
        if not isinstance(t, dict) or not t.get("title"):
            raise PackError(f"{where}: technique {i} needs its title")
        if not isinstance(t.get("techniques", []), list):
            raise PackError(f'{where}: technique "{t["title"]}"\'s techniques is a list, such as ["T1190"]')
        titles.add(t["title"])
    for s in data.get("system", []):
        if not isinstance(s, dict) or not s.get("name") or not all(
                isinstance(h, dict) and h.get("name") for h in s.get("hosts", [])):
            raise PackError(f"{where}: each [[system]] needs its name, and each of its hosts a name")
    for g in data.get("known_gap", []):
        if not isinstance(g, dict) or g.get("technique") not in titles or not g.get("reason"):
            raise PackError(f"{where}: each [[known_gap]] names one of the baseline's techniques, with a reason")
    return data
