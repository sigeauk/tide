"""Replaying a scenario into a SIEM's Elasticsearch as if it were happening now.

A replay reads a scenario's log files (packs.Scenario.replay: its window, or at noise busy its span with
its noise packs), merges their events in time order, maps each to ECS (ecs.map_event) and sends them
with the Bulk API, paced to the original timing at `speed` times faster (at most `max_eps` events a
second; a gap longer than `max_gap` seconds is cut short). Each event's @timestamp and event.ingested
are the moment it is sent, so detection rules that look at the last few minutes fire; the time it
really happened is kept in original_timestamp, and the scenario and the replay in botes.scenario and
botes.replay.run_id.

Events go to data streams logs-<dataset>-<namespace> (a simulation's own namespace), or to one index
for a private check. An index template (ecs.index_template) types them; its retention deletes what is
older, so a replay that is never cleared away still goes. A replay is started by a person and runs in
the thread that calls run(); stop() ends it early.
"""

from __future__ import annotations

import heapq
import json
import queue
import re
import threading
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from app.services.sim import ecs, packs

RETENTION = "7d"            # replayed data older than this is deleted by its data streams
MAX_EPS = 2000              # events a second a replay sends at most, unless told otherwise
TEMPLATE_PRIORITY = 250     # above Elastic's own logs-*-* template
NAMESPACE_RX = re.compile(r"[a-z0-9_]{1,40}")     # a data stream namespace may hold no "-"


class ElasticError(RuntimeError):
    """A call Elasticsearch refused, or that never reached it."""

    def __init__(self, what: str, status: int | None = None, reason: str = ""):
        self.status, self.reason = status, reason
        super().__init__(f"Could not {what}: {reason or 'no answer'}" + (f" ({status})" if status else ""))


class Elastic:
    """A SIEM's Elasticsearch, reached directly at its URL with a session that carries its credentials
    (an Authorization header) and its TLS settings (app.services.tls.Session)."""

    def __init__(self, session, url: str, timeout: float = 60):
        self.session, self.url, self.timeout = session, url.rstrip("/"), timeout

    def call(self, method: str, path: str, what: str, *, json_body=None, ndjson: bytes | None = None,
             params: dict | None = None, ok: tuple = (200, 201)) -> dict:
        """The JSON answer to one call, or an ElasticError saying why it failed."""
        headers = {"Content-Type": "application/x-ndjson"} if ndjson is not None else None
        try:
            r = self.session.request(method, self.url + path, json=json_body, data=ndjson, params=params,
                                     headers=headers, timeout=self.timeout)
        except Exception as exc:  # noqa: BLE001 - any transport failure is "never reached it"
            raise ElasticError(what, None, str(exc)) from None
        try:
            body = r.json() if r.content else {}
        except ValueError:
            body = {}
        if r.status_code not in ok:
            err = body.get("error") if isinstance(body, dict) else None
            reason = (err.get("reason") if isinstance(err, dict) else err) or r.reason
            raise ElasticError(what, r.status_code, str(reason))
        return body


def template_name(target: str) -> str:
    """The index template for a namespace's data streams, or for one index."""
    return f"tide-sim-{target}"


def install_template(es: Elastic, *, namespace: str | None = None, index: str | None = None,
                     retention: str = RETENTION) -> str:
    """Install the component template and the index template for a namespace's data streams (deleting
    what is older than retention) or for one index; returns the index template's name."""
    if bool(namespace) == bool(index):
        raise ValueError("A template is for a namespace or for one index: give one")
    pattern = index or f"logs-*-{namespace}"
    name = template_name(index or namespace)
    es.call("PUT", f"/_component_template/{ecs.COMPONENT}", "install the simulation mappings",
            json_body=ecs.component_template())
    es.call("PUT", f"/_index_template/{name}", f"install the index template for {pattern}",
            json_body=ecs.index_template(pattern, data_stream=bool(namespace), priority=TEMPLATE_PRIORITY,
                                         retention=retention if namespace else None))
    return name


def make_streams(es: Elastic, segments: list["Segment"], namespace: str) -> list[str]:
    """Make, empty, each data stream a replay of these segments writes to, before it sends anything,
    so a data view on them has their fields (@timestamp among them) from the start. Kibana finds no
    fields for a pattern that matches no index, and a Discover opened then shows no histogram until it
    is reloaded. One that is there already is left as it is. Returns the streams' names."""
    names = sorted({f"logs-{ecs.dataset(f.source).ds}-{namespace}" for seg in segments for f in seg.files})
    for name in names:
        try:
            es.call("PUT", f"/_data_stream/{name}", f"make the data stream {name}")
        except ElasticError as exc:
            if exc.status != 400 or "already exists" not in exc.reason:
                raise
    return names


def remove_data(es: Elastic, namespace: str) -> list[str]:
    """Delete a namespace's data streams and its index template; returns the streams deleted."""
    if not NAMESPACE_RX.fullmatch(namespace or ""):
        raise ValueError(f"'{namespace}' isn't a namespace (lower-case letters, digits and _)")
    pattern = f"logs-*-{namespace}"
    body = es.call("GET", f"/_data_stream/{pattern}", f"list {pattern}", ok=(200, 404))
    streams = [d["name"] for d in body.get("data_streams", [])]
    if streams:
        es.call("DELETE", f"/_data_stream/{','.join(streams)}", f"delete {pattern}")
    es.call("DELETE", f"/_index_template/{template_name(namespace)}", f"delete the index template for {pattern}",
            ok=(200, 404))
    return streams


def remove_index(es: Elastic, index: str) -> None:
    """Delete one index made for a private check, by its exact name, and its template."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", index or ""):
        raise ValueError(f"'{index}' isn't one index's name")
    es.call("DELETE", f"/{index}", f"delete {index}", ok=(200, 404))
    es.call("DELETE", f"/_index_template/{template_name(index)}", f"delete the index template for {index}",
            ok=(200, 404))


# ── The replay ─────────────────────────────────────────────────────────────────────────────────

@dataclass
class Segment:
    """One scenario's stretch of original time and the files it is read from."""
    scenario: str
    start: datetime
    end: datetime
    files: list[packs.LogFile]


def plan(scenarios: list[packs.Scenario], noise: str, keys: list[str] | None = None) -> list[Segment]:
    """The segments a replay of these scenarios at this noise level sends, in order."""
    out = []
    for sc in scenarios:
        if not sc.ready:
            raise packs.PackError(f"{sc.id} has no logs")
        start, end, files = sc.replay(noise, keys)
        out.append(Segment(sc.id, start, end, files))
    return out


def events(segments: list[Segment]):
    """(original time, dataset key, line, scenario) for every event, segment after segment, in time order."""
    for seg in segments:
        streams = [packs.read_pack_file(f, seg.start, seg.end) for f in seg.files]
        for t, key, line in heapq.merge(*streams, key=lambda item: item[0]):
            yield t, key, line, seg.scenario


def count(segments: list[Segment]) -> Counter:
    """How many events a replay of these segments sends, by dataset key, without sending any."""
    return Counter(key for _, key, _, _ in events(segments))


@dataclass
class Progress:
    sent: Counter = field(default_factory=Counter)        # by dataset key
    refused: Counter = field(default_factory=Counter)     # by index
    first_refusal: str = ""
    original_time: datetime | None = None                 # how far through the original it has come
    started: float = field(default_factory=time.monotonic)
    finished: bool = False
    stopped: bool = False

    @property
    def total(self) -> int:
        return sum(self.sent.values())

    def summary(self) -> dict:
        elapsed = time.monotonic() - self.started
        return {"sent": self.total, "by_source": dict(self.sent), "refused": sum(self.refused.values()),
                "first_refusal": self.first_refusal, "rate": round(self.total / elapsed) if elapsed else 0,
                "original_time": ecs.iso(self.original_time) if self.original_time else None,
                "finished": self.finished, "stopped": self.stopped}


class Replay:
    """One replay: run() sends it (blocking), stop() ends it early, progress says how far it is."""

    def __init__(self, es: Elastic, segments: list[Segment], *, namespace: str | None = None,
                 index: str | None = None, speed: float = 10.0, max_eps: float = MAX_EPS, max_gap: float = 5.0,
                 batch_size: int = 500, workers: int = 2, slim: bool = False, loop: int = 1,
                 on_progress: Callable[[dict], None] | None = None):
        if bool(namespace) == bool(index):
            raise ValueError("A replay goes to a namespace's data streams or to one index: give one")
        if namespace and not NAMESPACE_RX.fullmatch(namespace):
            raise ValueError(f"'{namespace}' isn't a namespace (lower-case letters, digits and _)")
        self.es, self.segments, self.namespace, self.index = es, segments, namespace, index
        self.speed, self.max_eps, self.max_gap = speed, max_eps, max_gap
        self.batch_size, self.workers, self.slim, self.on_progress = batch_size, max(workers, 1), slim, on_progress
        self.run_id = uuid.uuid4().hex[:8]
        self.loop = loop                    # which pass of the same data this is (a simulation's Replay data)
        self.progress = Progress()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._outbox: queue.Queue = queue.Queue(maxsize=self.workers * 2)
        self._threads: list[threading.Thread] = []

    def stop(self) -> None:
        self._stop.set()

    def target(self, ds: ecs.Dataset) -> str:
        return self.index or f"logs-{ds.ds}-{self.namespace}"

    def document(self, t: datetime, key: str, record: dict, now: datetime, scenario: str) -> dict:
        ds = ecs.dataset(key)
        doc = ecs.map_event(key, record, keep_original=not self.slim)
        stamp = ecs.iso(now)
        doc["@timestamp"] = stamp
        doc["original_timestamp"] = ecs.iso(t)
        event = doc.setdefault("event", {})
        event["ingested"] = stamp
        event["dataset"] = ds.ds
        if ecs.is_ecs(record):
            event.setdefault("module", ds.module)   # an imported ECS document keeps its own
        else:
            event["module"] = ds.module
        doc["botes"]["replay"] = {"run_id": self.run_id, "loop": self.loop}
        doc["botes"]["scenario"] = scenario
        if self.namespace:
            doc["data_stream"] = {"type": "logs", "dataset": ds.ds, "namespace": self.namespace}
        return doc

    # ── Sending ────────────────────────────────────────────────────────────────────────────────

    def _bulk(self, batch: list[tuple[str, dict]]) -> None:
        """Send one batch. Events Elasticsearch is too busy for (429) are sent again, up to 8 times,
        2 s doubling to 30 s, so a busy cluster slows the replay rather than losing events."""
        op = "index" if self.index else "create"
        wait = 2.0
        for attempt in range(9):
            body = b"".join(json.dumps({op: {"_index": idx}}).encode() + b"\n"
                            + json.dumps(doc, separators=(",", ":"), default=str).encode() + b"\n"
                            for idx, doc in batch)
            try:
                r = self.es.call("POST", "/_bulk", "send events", ndjson=body, ok=(200,))
            except ElasticError as exc:
                if exc.status in (429, 503) and attempt < 8:
                    time.sleep(wait)
                    wait = min(wait * 2, 30)
                    continue
                self._refuse([(idx, str(exc)) for idx, _ in batch])
                return
            again, refused = [], []
            for (idx, doc), item in zip(batch, r.get("items", [])):
                result = next(iter(item.values()))
                if result.get("status", 200) == 429:
                    again.append((idx, doc))
                elif result.get("error"):
                    refused.append((idx, json.dumps(result["error"])[:400]))
            self._refuse(refused)
            if not again:
                return
            batch = again
            if attempt < 8:
                time.sleep(wait)
                wait = min(wait * 2, 30)
        self._refuse([(idx, "Elasticsearch stayed too busy (429)") for idx, _ in batch])

    def _refuse(self, refused: list[tuple[str, str]]) -> None:
        if refused:
            with self._lock:
                for idx, why in refused:
                    self.progress.refused[idx] += 1
                    self.progress.first_refusal = self.progress.first_refusal or why

    def _sender(self) -> None:
        while True:
            batch = self._outbox.get()
            if batch is None:
                return
            self._bulk(batch)

    def _flush(self, batch: list) -> None:
        """Hand a batch to the senders (waits when they are all busy, so a slow cluster slows the replay)."""
        if not batch:
            return
        if not self._threads:
            self._threads = [threading.Thread(target=self._sender, name=f"sim-send-{self.run_id}", daemon=True)
                             for _ in range(self.workers)]
            for th in self._threads:
                th.start()
        self._outbox.put(list(batch))
        batch.clear()

    def _drain(self) -> None:
        for _ in self._threads:
            self._outbox.put(None)
        for th in self._threads:
            th.join()
        self._threads = []

    def _report(self) -> None:
        if self.on_progress:
            try:
                self.on_progress(self.progress.summary())
            except Exception:  # noqa: BLE001 - a progress listener never stops a replay
                pass

    def run(self) -> dict:
        """Send the replay, paced; returns its summary (progress.summary())."""
        wall0, virt, prev = time.monotonic(), 0.0, None
        min_step = 1 / self.max_eps if self.max_eps else 0.0
        batch: list[tuple[str, dict]] = []
        last_flush = last_report = time.monotonic()
        try:
            for t, key, line, scenario in events(self.segments):
                if self._stop.is_set():
                    self.progress.stopped = True
                    break
                if prev is not None:
                    gap = (t - prev).total_seconds() / self.speed if self.speed > 0 else 0.0
                    virt += max(min(max(gap, 0.0), self.max_gap), min_step)
                prev = t
                delay = wall0 + virt - time.monotonic()
                if delay > 0.05:
                    self._flush(batch)
                    last_flush = time.monotonic()
                    delay = wall0 + virt - time.monotonic()
                    if delay > 0 and self._stop.wait(delay):
                        self.progress.stopped = True
                        break
                try:
                    record = ecs.unwrap(line)
                except ValueError:
                    continue
                batch.append((self.target(ecs.dataset(key)), self.document(t, key, record, datetime.now(timezone.utc),
                                                                            scenario)))
                self.progress.sent[key] += 1
                self.progress.original_time = t
                now = time.monotonic()
                if len(batch) >= self.batch_size or now - last_flush >= 1.0:
                    self._flush(batch)
                    last_flush = now
                if now - last_report >= 2.0:
                    last_report = now
                    self._report()
            self._flush(batch)
        finally:
            self._drain()
            self.progress.finished = True
            self._report()
        return self.progress.summary()
