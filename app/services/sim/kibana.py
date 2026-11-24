"""The Kibana calls a simulation makes in its own space: making and deleting the space, its data view,
its rules, and how many alerts each rule raised.

A simulation's space is never one of a client's destinations (CLAUDE.md section 6): TIDE makes it on
the SIEM of a destination the Sim Admin picked, keeps it in the simulation's own record, and deletes it
when the simulation ends. Deleting a space deletes what it holds (its rules and data view); the alerts
its rules raised are in Elasticsearch, and go with remove_alerts().
"""

from __future__ import annotations

from app.services.sim.replay import ElasticError


class Kibana:
    """A SIEM's Kibana, with a session that carries its credentials, kbn-xsrf and its TLS settings
    (elastic_helper._make_session)."""

    def __init__(self, session, url: str, timeout: float = 60):
        self.session, self.url, self.timeout = session, url.rstrip("/"), timeout

    def call(self, method: str, path: str, what: str, *, json_body=None, ok: tuple = (200,)) -> dict:
        try:
            r = self.session.request(method, self.url + path, json=json_body, timeout=self.timeout)
        except Exception as exc:  # noqa: BLE001 - any transport failure is "never reached it"
            raise ElasticError(what, None, str(exc)) from None
        try:
            body = r.json() if r.content else {}
        except ValueError:
            body = {}
        if r.status_code not in ok:
            reason = body.get("message") or body.get("error") if isinstance(body, dict) else None
            raise ElasticError(what, r.status_code, str(reason or r.reason))
        return body if isinstance(body, dict) else {"items": body}

    # ── The space ──────────────────────────────────────────────────────────────────────────────

    def space_exists(self, space: str) -> bool:
        try:
            self.call("GET", f"/api/spaces/space/{space}", f"look for space {space}")
            return True
        except ElasticError as exc:
            if exc.status == 404:
                return False
            raise

    def create_space(self, space: str, name: str, description: str) -> None:
        self.call("POST", "/api/spaces/space", f"make space {space}",
                  json_body={"id": space, "name": name, "description": description})

    def delete_space(self, space: str) -> None:
        self.call("DELETE", f"/api/spaces/space/{space}", f"delete space {space}", ok=(200, 204, 404))

    def create_data_view(self, space: str, pattern: str, name: str) -> str:
        body = self.call("POST", f"/s/{space}/api/data_views/data_view", f"make the data view in {space}",
                         json_body={"data_view": {"title": pattern, "name": name, "timeFieldName": "@timestamp"},
                                    "override": True})
        return (body.get("data_view") or {}).get("id", "")

    def data_view_id(self, space: str, title: str) -> str:
        """The id of the space's data view on ``title`` (its index pattern); '' when it has none."""
        body = self.call("GET", f"/s/{space}/api/data_views", f"read the data views of {space}")
        return next((str(d.get("id")) for d in body.get("data_view") or [] if d.get("title") == title), "")

    # ── Saved searches (#126) ──────────────────────────────────────────────────────────────────

    def save_search(self, space: str, object_id: str, attributes: dict, references: list) -> str:
        """Save a Discover search in the space as ``object_id``, replacing one saved as it before; its id."""
        body = self.call("POST", f"/s/{space}/api/saved_objects/search/{object_id}?overwrite=true",
                         f"save the search '{attributes.get('title')}'",
                         json_body={"attributes": attributes, "references": references})
        return str(body.get("id") or object_id)

    # ── Its rules and their alerts ─────────────────────────────────────────────────────────────

    def create_rule(self, space: str, rule: dict) -> str:
        """Create a detection rule in the space exactly as given; returns its Kibana id."""
        body = self.call("POST", f"/s/{space}/api/detection_engine/rules", f"create rule '{rule.get('name')}'",
                         json_body=rule)
        return str(body.get("id", ""))

    def alert_counts(self, space: str) -> dict[str, int]:
        """{rule_id: alerts} for the rules in the space that raised any."""
        body = self.call("POST", f"/s/{space}/api/detection_engine/signals/search", f"count the alerts in {space}",
                         json_body={"size": 0, "track_total_hits": False, "query": {"match_all": {}},
                                    "aggs": {"rules": {"terms": {"field": "kibana.alert.rule.rule_id", "size": 500}}}})
        buckets = ((body.get("aggregations") or {}).get("rules") or {}).get("buckets") or []
        return {str(b.get("key")): int(b.get("doc_count") or 0) for b in buckets}


def remove_alerts(es, space: str) -> list[str]:
    """Delete the indexes holding a space's alerts (and its rule previews'), by their exact names, as
    Elasticsearch deletes no index by a pattern; returns those deleted."""
    gone = []
    for alias in (f".alerts-security.alerts-{space}", f".preview.alerts-security.alerts-{space}"):
        found = es.call("GET", f"/_alias/{alias}", f"find {alias}", ok=(200, 404), params={"expand_wildcards": "all"})
        for index in (k for k in found if k not in ("error", "status")):
            es.call("DELETE", f"/{index}", f"delete {index}", ok=(200, 404), params={"expand_wildcards": "all"})
            gone.append(index)
    return gone
