"""
STIX → per-tenant CTI ingest writer.

Single entry point :func:`ingest_stix_bundle`. Called by the Phase 1
OpenCTI GraphQL fetcher and (Phase 2) the diode file ingestor. Both
paths must produce identical rows for the same bundle — that is why
all parsing + write logic lives here, not in the fetchers.

Dedup contract — Plan Phase 1 §5 / answer Q8:
    * Two STIX indicators are *the same* when they share
      ``(pattern_type, observable_value)`` exactly.
    * Canonical row = oldest ``valid_from``.
    * Subsequent duplicates fold into the canonical row:
        - ``last_seen`` bumped to ``now()``
        - ``mitre_techniques`` list unioned
        - ``confidence`` raised to the max of the two
        - ``valid_until`` extended to the later of the two
        - Provenance row inserted, ``was_canonical=FALSE``
    * Multi-value STIX patterns (anything not a simple equality on a
      single observable property) cannot be safely deduped; the row is
      stored with ``needs_review=TRUE`` and the operator surface flags
      it for manual merging.

Everything writes through :func:`app.services.cti_database.open_cti_db`,
so the connection-pool single-writer guarantee covers concurrent UI
sync clicks racing with read requests.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from app.services.cti_database import open_cti_db

logger = logging.getLogger(__name__)


# ── STIX pattern parsing ─────────────────────────────────────────────

# Matches a simple STIX 2.x equality comparison:
#   [file:hashes.'SHA-256' = 'abc...']  → ("file", "abc...")
#   [ipv4-addr:value = '1.2.3.4']       → ("ipv4-addr", "1.2.3.4")
#   [domain-name:value = 'evil.test']   → ("domain-name", "evil.test")
#
# The two captures are the SCO type (used as our ``pattern_type``) and
# the literal value (used as our ``observable_value``). Anything else —
# multi-property patterns, ``IN``, ``LIKE``, ``MATCHES``, OR/AND
# combinations — falls through to the multi-value branch.
_SIMPLE_EQ = re.compile(
    r"""\[\s*
        ([a-zA-Z][\w-]*) :          # SCO type
        [^=]+? \s* = \s*            # property + '='
        ['"](.+?)['"]               # quoted literal value
        \s*\]$""",
    re.VERBOSE,
)

# Best-effort fallback: grab the *leading* SCO type from any STIX
# pattern shape (multi-property, OR/AND combinations, LIKE/MATCHES,
# IN-list, parenthesised). Used when ``_SIMPLE_EQ`` rejects a pattern
# so the row still lands with a real ``pattern_type`` instead of the
# old ``"_review"`` sentinel.
_LEAD_SCO = re.compile(r"\[\s*([a-zA-Z][\w-]*)\s*:")

# Cap the observable_value we store for complex patterns. The column
# participates in the dedup key, so we want it deterministic without
# bloating the row when OpenCTI ships pathological multi-hundred-byte
# patterns. 512 chars is well above every real-world OpenCTI emission.
_PATTERN_VALUE_CAP = 512


def _parse_pattern(pattern: str) -> tuple[Optional[str], Optional[str], bool]:
    """Return ``(pattern_type, observable_value, needs_review)``.

    Two shapes:

    * Simple equality (``[ipv4-addr:value = '1.2.3.4']``) — returns the
      SCO type as ``pattern_type``, the literal value as
      ``observable_value``, and ``needs_review=False``.
    * Anything else (multi-property AND/OR, LIKE/MATCHES, IN-lists,
      parenthesised compositions) — best-effort: extract the *leading*
      SCO type for ``pattern_type`` and store the raw pattern
      (truncated) as ``observable_value``. ``needs_review=True`` so the
      operator queue still flags it, but the row carries a real
      ``pattern_type`` instead of the legacy ``"_review"`` sentinel
      (removed in 5.0.x — see CTI surface notes).

    Returns ``(None, None, True)`` only when the pattern is empty or
    truly unparseable (no SCO type discoverable at all); callers treat
    that as ``skipped``.
    """
    if not pattern:
        return None, None, True
    raw = pattern.strip()
    m = _SIMPLE_EQ.match(raw)
    if m:
        sco_type = m.group(1).strip().lower()
        value = m.group(2).strip()
        if sco_type and value:
            return sco_type, value, False
    # Fallback: extract the leading SCO type so the row still has a
    # meaningful ``pattern_type``. ``observable_value`` carries the
    # truncated raw pattern so the operator can see exactly what came
    # in without diving into ``raw_stix``.
    lead = _LEAD_SCO.search(raw)
    if not lead:
        return None, None, True
    sco_type = lead.group(1).strip().lower()
    if not sco_type:
        return None, None, True
    value = raw[:_PATTERN_VALUE_CAP]
    return sco_type, value, True


# ── Misc helpers ─────────────────────────────────────────────────────

def _now() -> datetime:
    # tz-naive UTC. DuckDB's TIMESTAMP column is itself naive, and
    # mixing aware + naive datetimes blows up at comparison time when
    # we read a stored value back to widen ``valid_until`` on merge.
    return datetime.utcnow()


def _parse_ts(value: Any) -> Optional[datetime]:
    """Parse a STIX timestamp string into a tz-naive UTC ``datetime``.

    Returns ``None`` on failure. We deliberately strip the tzinfo so
    the value matches DuckDB's TIMESTAMP-on-read behaviour.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    # STIX uses ISO-8601 with trailing 'Z'; Python's fromisoformat
    # accepts +00:00 but not 'Z' until 3.11 — guard both.
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(s)
    except Exception:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _tlp_from_object_refs(stix_obj: dict, marking_index: dict[str, str]) -> Optional[str]:
    """Resolve a STIX TLP marking from an indicator's ``object_marking_refs``.

    ``marking_index`` maps marking-definition id → tlp label
    (``"white"|"green"|"amber"|"red"``). Built once per bundle by the
    caller.
    """
    refs = stix_obj.get("object_marking_refs") or []
    for ref in refs:
        tlp = marking_index.get(ref)
        if tlp:
            return tlp
    return None


def _build_marking_index(objects: Iterable[dict]) -> dict[str, str]:
    """Pre-scan the bundle to map marking-definition id → tlp label."""
    out: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") != "marking-definition":
            continue
        definition_type = (obj.get("definition_type") or "").lower()
        if definition_type != "tlp":
            continue
        label = (obj.get("definition") or {}).get("tlp")
        oid = obj.get("id")
        if oid and label:
            out[oid] = label.strip().lower()
    return out


def _extract_mitre_techniques(stix_obj: dict) -> list[str]:
    """Pull ATT&CK technique IDs from ``external_references`` and
    ``kill_chain_phases``. Returns sorted, deduped, uppercased list."""
    found: set[str] = set()
    for ref in stix_obj.get("external_references") or []:
        if (ref.get("source_name") or "").lower() not in {
            "mitre-attack",
            "mitre-att&ck",
            "mitre-attack-ics",
            "mitre-attack-mobile",
        }:
            continue
        ext_id = ref.get("external_id")
        if ext_id and re.fullmatch(r"T\d{4}(\.\d{3})?", ext_id.upper()):
            found.add(ext_id.upper())
    for phase in stix_obj.get("kill_chain_phases") or []:
        if (phase.get("kill_chain_name") or "").lower() != "mitre-attack":
            continue
        name = (phase.get("phase_name") or "").upper()
        if re.fullmatch(r"T\d{4}(\.\d{3})?", name):
            found.add(name)
    return sorted(found)


# ── Public API ───────────────────────────────────────────────────────

def ingest_stix_bundle(
    client_id: str,
    bundle: dict,
    source_id: str,
    bundle_id: Optional[str] = None,
    *,
    slug: Optional[str] = None,
) -> dict:
    """Ingest a STIX 2.x bundle into the tenant's CTI DB.

    Parameters
    ----------
    client_id:
        Owning tenant. Required.
    bundle:
        Parsed STIX 2.x bundle (``{"type":"bundle","objects":[...]}``).
        Accepts a bare list of objects too.
    source_id:
        Identifier of the originating source (e.g. the
        ``opencti_inventory.id`` row, or ``"diode:<filename>"`` for
        Phase 2). Stored on every indicator and provenance row so we
        can attribute facts back to a feed.
    bundle_id:
        Optional bundle identifier — STIX's own ``id``, the OpenCTI
        export job id, or the diode bundle filename. Used by the
        provenance ledger; generated on the fly when omitted.
    slug:
        Forwarded to :func:`open_cti_db` so a known slug skips the
        tenant_manager / shared-DB lookup.

    Returns
    -------
    dict
        Summary counters — keys: ``indicators_new``, ``indicators_merged``,
        ``indicators_review``, ``indicators_revoked``, ``stale_skipped``,
        ``actors``, ``reports``, ``relationships``, ``intrusion_sets``
        (kept for back-compat — counts the subset of actors with
        ``stix_type='intrusion-set'``), ``skipped``.
    """
    if not client_id:
        raise ValueError("client_id is required")
    if not source_id:
        raise ValueError("source_id is required")
    bundle_id = bundle_id or f"adhoc-{uuid.uuid4()}"

    if isinstance(bundle, list):
        objects = bundle
    elif isinstance(bundle, dict):
        objects = bundle.get("objects") or []
    else:
        raise TypeError("bundle must be a dict or list of STIX objects")

    marking_index = _build_marking_index(objects)

    counters = {
        "indicators_new": 0,
        "indicators_merged": 0,
        "indicators_review": 0,
        "indicators_revoked": 0,
        "actors": 0,
        "reports": 0,
        "intrusion_sets": 0,  # subset of actors; preserved for callers
        "relationships": 0,
        "skipped": 0,
        "stale_skipped": 0,
    }

    # Pre-sort indicators by valid_from so the canonical-row rule
    # ("oldest valid_from wins") is naturally satisfied: the first time
    # we see a (pattern_type, observable_value) pair we set
    # ``valid_from`` to the bundle's value; later duplicates only widen
    # ``valid_until`` and union the technique list.
    indicators = [
        o for o in objects if o.get("type") == "indicator"
    ]
    indicators.sort(
        key=lambda o: (_parse_ts(o.get("valid_from")) or _now())
    )
    intrusion_sets = [
        o for o in objects if o.get("type") == "intrusion-set"
    ]
    threat_actors = [
        o for o in objects if o.get("type") == "threat-actor"
    ]
    reports = [
        o for o in objects if o.get("type") == "report"
    ]
    relationships = [
        o for o in objects if o.get("type") == "relationship"
    ]
    # Attack-patterns are projected straight into the relationship index
    # under their MITRE ATT&CK T-ID (e.g. ``T1059.001``) so a
    # ``(intrusion-set --uses--> attack-pattern)`` STIX edge lands in
    # ``cti_relationships`` as ``("intrusion-set","APT29","uses",
    # "attack-pattern","T1059.001")``. The Threat Landscape projection
    # at the end of this function joins on those rows to rebuild each
    # actor's TTP list from STIX data alone — no GraphQL call needed.
    attack_patterns = [
        o for o in objects if o.get("type") == "attack-pattern"
    ]

    # Build STIX-id → (entity_type, natural_key) for everything written
    # in this bundle so the relationship pass can resolve endpoints
    # without extra round-trips. ``natural_key`` matches the row's
    # business key: indicator row-id, actor name, report id.
    stix_to_row: dict[str, str] = {}
    stix_index: dict[str, tuple[str, str]] = {}

    with open_cti_db(client_id, slug) as conn:
        # All writes inside a single transaction so a partial failure
        # leaves the CTI DB untouched. The pool's single-writer slot
        # already serialises against other writers.
        conn.execute("BEGIN")
        try:
            for ind in indicators:
                outcome = _upsert_indicator(
                    conn, ind, source_id, bundle_id, marking_index
                )
                if outcome is None:
                    counters["skipped"] += 1
                    continue
                row_id, status, needs_review = outcome
                sid = ind.get("id")
                if sid:
                    stix_to_row[sid] = row_id
                    stix_index[sid] = ("indicator", row_id)
                if status == "new":
                    counters["indicators_new"] += 1
                elif status == "merged":
                    counters["indicators_merged"] += 1
                elif status == "stale":
                    counters["stale_skipped"] += 1
                elif status == "revoked":
                    counters["indicators_revoked"] += 1
                if needs_review:
                    counters["indicators_review"] += 1

            for actor in intrusion_sets:
                sid = actor.get("id")
                name = (actor.get("name") or "").strip()
                # Always register the stix_id so downstream relationships
                # can resolve even when the actor row was already current.
                if sid and name:
                    stix_index[sid] = ("intrusion-set", name)
                if _upsert_actor(conn, actor, "intrusion-set", source_id):
                    counters["actors"] += 1
                    counters["intrusion_sets"] += 1

            for actor in threat_actors:
                sid = actor.get("id")
                name = (actor.get("name") or "").strip()
                if sid and name:
                    stix_index[sid] = ("threat-actor", name)
                if _upsert_actor(conn, actor, "threat-actor", source_id):
                    counters["actors"] += 1

            for rpt in reports:
                sid = rpt.get("id")
                if sid:
                    stix_index[sid] = ("report", sid)
                if _upsert_report(conn, rpt, source_id):
                    counters["reports"] += 1

            # Attack-patterns: extract the MITRE T-ID from the STIX
            # external_references block and register the STIX id in
            # ``stix_index`` so subsequent ``uses`` relationships from
            # actors can resolve. We don't write attack-patterns into
            # their own table — the MITRE technique catalogue already
            # lives in shared ``threat_actors``-adjacent storage, and
            # carrying duplicate definitions per tenant would only add
            # drift.
            for ap in attack_patterns:
                t_id = None
                for ref in ap.get("external_references") or []:
                    if (ref.get("source_name") or "").lower() == "mitre-attack":
                        t_id = (ref.get("external_id") or "").strip().upper()
                        if t_id:
                            break
                sid = ap.get("id")
                if sid and t_id:
                    stix_index[sid] = ("attack-pattern", t_id)

            for rel in relationships:
                if _wire_relationship(conn, rel, stix_index, source_id):
                    counters["relationships"] += 1

            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:  # pragma: no cover
                pass
            raise

    logger.info(
        "cti_ingest: client=%s source=%s bundle=%s %s",
        client_id, source_id, bundle_id, counters,
    )

    # ── Threat Landscape projection ──────────────────────────────────
    # Replay the per-tenant ``cti_actors`` + ``cti_relationships``
    # tables into the shared/tenant ``threat_actors`` table so the
    # /threats and /heatmap pages render exclusively from STIX data.
    # Best-effort: a projection failure must NOT roll back the bundle
    # ingest above. The projection itself is idempotent — the existing
    # ``save_octi_threat_actors_to_active_db`` upserts by canonical
    # name and unions the source markers, so re-running this after
    # every bundle converges without duplicating rows.
    try:
        # 5.0.0: projection is idempotent and cheap (~ms for hundreds
        # of actors) so run it every ingest, including no-op resyncs
        # where counters are all zero. Without this, a fresh tenant
        # never sees its threat actors after the very first bundle
        # arrives, because the next sync's counters are zero and the
        # projection gate would skip.
        _project_actors_to_threat_landscape(
            client_id, slug, source_id=source_id,
        )
    except Exception as exc:  # pragma: no cover
        logger.warning(
            "cti_ingest: threat_actors projection skipped for "
            "client=%s: %s",
            client_id, exc,
        )

    return counters


def _project_actors_to_threat_landscape(
    client_id: str,
    slug: Optional[str] = None,
    *,
    source_id: Optional[str] = None,
) -> int:
    """Project ``cti_actors`` + ``cti_relationships`` → ``threat_actors``.

    Rebuilds the tenant's threat-landscape view from STIX data only,
    so the Threat Landscape, Heatmap and threat-detail pages no
    longer depend on the legacy OpenCTI GraphQL pull. The projection
    re-uses the existing :py:meth:`Database.save_octi_threat_actors_to_active_db`
    writer so alias-aware merge, source-union and MITRE-canonical-name
    resolution all stay in one place.

    The ``source_id`` carried into ``ingest_stix_bundle`` (typically
    ``"connector:<uuid>"``) is resolved to the connector's
    operator-supplied label so the Threat Landscape source pill shows
    the friendly name instead of a generic ``"STIX"`` marker. Falls
    back to ``"STIX"`` when the source cannot be resolved.

    Returns the number of actor rows projected.
    """
    import pandas as pd
    from app.services.database import get_database_service
    from app.services.tenant_manager import tenant_context_for

    _db = get_database_service()

    # Resolve the ingest source_id to a friendly connector label so the
    # Threat Landscape source pill matches what the rest of the CTI
    # surface shows (see ``cti.py::_resolve_source_labels``).
    source_marker = "STIX"
    if source_id and source_id.startswith("connector:"):
        cid = source_id.split(":", 1)[1].strip()
        if cid:
            try:
                conn = _db.get_cti_connector(cid)
                if conn:
                    label = (conn.get("label") or conn.get("vendor") or "").strip()
                    if label:
                        source_marker = label
            except Exception:
                logger.debug(
                    "connector label lookup failed for source_id=%s",
                    source_id,
                )
    elif source_id:
        source_marker = source_id

    with open_cti_db(client_id, slug) as conn:
        actors = conn.execute(
            "SELECT name, description, aliases, origin, stix_type "
            "FROM cti_actors"
        ).fetchall()
        if not actors:
            return 0
        # Pull every actor → attack-pattern uses-edge. ``dst_id`` is
        # the MITRE T-ID (we projected it from external_references at
        # ingest time), so no further lookup is needed.
        edges = conn.execute(
            "SELECT src_id, dst_id FROM cti_relationships "
            "WHERE rel_type = 'uses' "
            "AND dst_type = 'attack-pattern'"
        ).fetchall()

    ttps_by_actor: dict[str, set[str]] = {}
    for actor_name, t_id in edges:
        if not actor_name or not t_id:
            continue
        ttps_by_actor.setdefault(actor_name, set()).add(t_id.upper())

    rows = []
    for name, description, aliases, origin, stix_type in actors:
        if hasattr(aliases, "tolist"):
            aliases = aliases.tolist()
        if isinstance(aliases, list):
            aliases_str = ", ".join(a for a in aliases if a) or None
        else:
            aliases_str = aliases or None
        ttps = sorted(ttps_by_actor.get(name, set()))
        rows.append({
            "name": name,
            "description": description,
            "aliases": aliases_str,
            "origin": origin,
            "ttps": ttps,
            "ttp_count": len(ttps),
            # Tag the projection with the connector's friendly label
            # (resolved above from the ingest ``source_id``) so the
            # Threat Landscape source pill carries the same label as
            # the rest of the CTI surface. Falls back to ``"STIX"``
            # when the source is unknown / not a connector ingest.
            "source": [source_marker],
        })

    if not rows:
        return 0

    df = pd.DataFrame(rows)
    with tenant_context_for(client_id):
        return _db.save_octi_threat_actors_to_active_db(df)


# ── Indicator upsert ─────────────────────────────────────────────────

def _upsert_indicator(
    conn,
    ind: dict,
    source_id: str,
    bundle_id: str,
    marking_index: dict[str, str],
) -> Optional[tuple[str, str, bool]]:
    """Upsert one indicator with strict STIX 2.1 version control.

    Returns ``(row_id, status, needs_review)`` where ``status`` is:

      * ``"new"``     — first sighting, row inserted.
      * ``"merged"``  — incoming ``modified`` strictly newer than stored
        (or stored is NULL); row updated and provenance recorded.
      * ``"stale"``   — incoming ``modified`` <= stored; no write.
      * ``"revoked"`` — incoming has ``revoked: true``; row deleted from
        the active latest state (per STIX 2.1 §3.5 the revoked SDO must
        not feed downstream consumers).

    Returns ``None`` if the object is unusable (no pattern, etc.).
    """
    pattern = ind.get("pattern")
    pattern_type, observable_value, needs_review = _parse_pattern(pattern)
    # Truly unparseable (no pattern at all, or no SCO type anywhere in
    # the string) — surface as ``skipped`` rather than inventing a
    # fake ``pattern_type``. The legacy ``"_review"`` sentinel is gone
    # (5.0.x) so complex-but-typed patterns now land with the leading
    # SCO type and ``needs_review=True``.
    if pattern_type is None or observable_value is None:
        return None

    stix_id = ind.get("id")
    incoming_modified = _parse_ts(ind.get("modified")) or _parse_ts(
        ind.get("created"))
    revoked = bool(ind.get("revoked"))

    existing = conn.execute(
        "SELECT id, valid_from, valid_until, confidence, "
        "mitre_techniques, stix_modified "
        "FROM cti_indicators "
        "WHERE pattern_type = ? AND observable_value = ?",
        [pattern_type, observable_value],
    ).fetchone()

    # Revoked: drop the active row if we hold one; never insert a fresh
    # revoked indicator. Provenance is left intact so the audit trail
    # survives.
    if revoked:
        if existing is None:
            return None
        row_id = existing[0]
        conn.execute(
            "DELETE FROM cti_indicators WHERE id = ?", [row_id],
        )
        _record_provenance(conn, row_id, source_id, bundle_id, False)
        return row_id, "revoked", needs_review

    valid_from = _parse_ts(ind.get("valid_from"))
    valid_until = _parse_ts(ind.get("valid_until"))
    tlp = _tlp_from_object_refs(ind, marking_index)
    confidence = ind.get("confidence")
    if not isinstance(confidence, int):
        confidence = None
    techniques = _extract_mitre_techniques(ind)
    kill_chain = ind.get("kill_chain_phases") or None
    raw_stix = ind

    if existing is None:
        row_id = ind.get("id") or f"indicator-{uuid.uuid4()}"
        conn.execute(
            "INSERT INTO cti_indicators ("
            "id, pattern_type, observable_value, pattern, valid_from, "
            "valid_until, tlp, confidence, source_id, first_seen, "
            "last_seen, kill_chain, mitre_techniques, raw_stix, "
            "needs_review, stix_id, stix_modified"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                row_id, pattern_type, observable_value, pattern, valid_from,
                valid_until, tlp, confidence, source_id, _now(),
                _now(), json.dumps(kill_chain) if kill_chain else None,
                techniques, json.dumps(raw_stix), needs_review,
                stix_id, incoming_modified,
            ],
        )
        _record_provenance(conn, row_id, source_id, bundle_id, True)
        return row_id, "new", needs_review

    # STIX 2.1 freshness gate: only merge when the incoming object is
    # strictly newer than what we hold. NULL stored ``stix_modified``
    # (legacy rows ingested before v4) is treated as "older than
    # anything" so the next sync upgrades the row in place.
    row_id = existing[0]
    stored_modified = existing[5]
    if (
        incoming_modified is not None
        and stored_modified is not None
        and incoming_modified <= stored_modified
    ):
        return row_id, "stale", needs_review

    existing_techniques = existing[4] or []
    if hasattr(existing_techniques, "tolist"):
        existing_techniques = existing_techniques.tolist()
    merged_techniques = sorted(set(existing_techniques) | set(techniques))
    existing_confidence = existing[3]
    new_confidence = existing_confidence
    if confidence is not None:
        new_confidence = max(existing_confidence or 0, confidence)
    existing_valid_until = existing[2]
    new_valid_until = existing_valid_until
    if valid_until is not None and (
        existing_valid_until is None or valid_until > existing_valid_until
    ):
        new_valid_until = valid_until

    conn.execute(
        "UPDATE cti_indicators SET "
        "last_seen = ?, "
        "valid_until = ?, "
        "confidence = ?, "
        "mitre_techniques = ?, "
        "stix_id = COALESCE(?, stix_id), "
        "stix_modified = ?, "
        "raw_stix = ? "
        "WHERE id = ?",
        [_now(), new_valid_until, new_confidence, merged_techniques,
         stix_id, incoming_modified, json.dumps(raw_stix), row_id],
    )
    _record_provenance(conn, row_id, source_id, bundle_id, False)
    return row_id, "merged", needs_review


def _record_provenance(
    conn,
    indicator_id: str,
    source_id: str,
    bundle_id: str,
    was_canonical: bool,
) -> None:
    conn.execute(
        "INSERT INTO cti_provenance ("
        "indicator_id, source_id, bundle_id, ingested_at, was_canonical"
        ") VALUES (?, ?, ?, ?, ?)",
        [indicator_id, source_id, bundle_id, _now(), was_canonical],
    )


# ── Actor / report / relationship upserts (v2 tables) ────────────────

def _upsert_actor(conn, actor: dict, stix_type: str, source_id: str) -> bool:
    """Upsert a threat-actor or intrusion-set row into ``cti_actors``.

    ``stix_type`` is the discriminator on the composite PK
    ``(stix_type, name)`` so threat-actors and intrusion-sets with
    colliding names coexist cleanly.
    """
    name = (actor.get("name") or "").strip()
    if not name:
        return False
    aliases = actor.get("aliases") or []
    if not isinstance(aliases, list):
        aliases = []
    description = actor.get("description") or None
    origin = None
    first_seen = _parse_ts(actor.get("first_seen") or actor.get("created"))
    last_seen = _parse_ts(actor.get("last_seen") or actor.get("modified"))
    stix_id = actor.get("id")
    incoming_modified = _parse_ts(actor.get("modified")) or _parse_ts(
        actor.get("created"))

    existing = conn.execute(
        "SELECT aliases, description, first_seen, last_seen, stix_modified "
        "FROM cti_actors WHERE stix_type = ? AND name = ?",
        [stix_type, name],
    ).fetchone()

    if existing is None:
        conn.execute(
            "INSERT INTO cti_actors ("
            "  stix_type, name, aliases, description, origin, "
            "  first_seen, last_seen, source_id, raw_stix, "
            "  stix_id, stix_modified"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                stix_type, name, aliases, description, origin,
                first_seen, last_seen, source_id, json.dumps(actor),
                stix_id, incoming_modified,
            ],
        )
        return True

    # STIX 2.1 freshness gate — see ``_upsert_indicator`` for the
    # NULL-stored-modified rationale.
    stored_modified = existing[4]
    if (
        incoming_modified is not None
        and stored_modified is not None
        and incoming_modified <= stored_modified
    ):
        return False

    existing_aliases = existing[0] or []
    if hasattr(existing_aliases, "tolist"):
        existing_aliases = existing_aliases.tolist()
    merged_aliases = sorted({*existing_aliases, *aliases})
    new_description = description or existing[1]
    new_first_seen = existing[2]
    if first_seen and (new_first_seen is None or first_seen < new_first_seen):
        new_first_seen = first_seen
    new_last_seen = existing[3]
    if last_seen and (new_last_seen is None or last_seen > new_last_seen):
        new_last_seen = last_seen

    conn.execute(
        "UPDATE cti_actors SET "
        "aliases = ?, description = ?, first_seen = ?, last_seen = ?, "
        "raw_stix = ?, stix_id = COALESCE(?, stix_id), "
        "stix_modified = ? "
        "WHERE stix_type = ? AND name = ?",
        [
            merged_aliases, new_description, new_first_seen, new_last_seen,
            json.dumps(actor), stix_id, incoming_modified,
            stix_type, name,
        ],
    )
    return True


def _upsert_report(conn, report: dict, source_id: str) -> bool:
    """Upsert a STIX report row. Keyed on the STIX ``id``."""
    sid = report.get("id")
    if not sid:
        return False
    name = (report.get("name") or "").strip() or None
    description = report.get("description") or None
    published = _parse_ts(report.get("published") or report.get("created"))
    labels = report.get("labels") or []
    if not isinstance(labels, list):
        labels = []
    incoming_modified = _parse_ts(report.get("modified")) or _parse_ts(
        report.get("created"))

    existing = conn.execute(
        "SELECT stix_modified FROM cti_reports WHERE id = ?", [sid],
    ).fetchone()
    if existing is None:
        conn.execute(
            "INSERT INTO cti_reports ("
            "  id, name, description, published, labels, source_id, "
            "  raw_stix, stix_modified"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [sid, name, description, published, labels,
             source_id, json.dumps(report), incoming_modified],
        )
        return True
    stored_modified = existing[0]
    if (
        incoming_modified is not None
        and stored_modified is not None
        and incoming_modified <= stored_modified
    ):
        return False
    conn.execute(
        "UPDATE cti_reports SET "
        "name = COALESCE(?, name), "
        "description = COALESCE(?, description), "
        "published = COALESCE(?, published), "
        "labels = ?, raw_stix = ?, stix_modified = ? WHERE id = ?",
        [name, description, published, labels, json.dumps(report),
         incoming_modified, sid],
    )
    return True


def _wire_relationship(
    conn,
    rel: dict,
    stix_index: dict[str, tuple[str, str]],
    source_id: str,
) -> bool:
    """Persist a STIX relationship into ``cti_relationships``.

    Both endpoints must resolve via ``stix_index`` — i.e. the source and
    target objects must have been written earlier in this same bundle.
    That gate keeps the edge table free of dangling references.
    """
    rel_type = (rel.get("relationship_type") or "").strip().lower()
    source_ref = rel.get("source_ref")
    target_ref = rel.get("target_ref")
    if not rel_type or not source_ref or not target_ref:
        return False
    src = stix_index.get(source_ref)
    dst = stix_index.get(target_ref)
    if not src or not dst:
        return False
    src_type, src_id = src
    dst_type, dst_id = dst

    rel_id = rel.get("id") or (
        f"relationship--{src_id}|{rel_type}|{dst_id}"
    )
    conn.execute(
        "INSERT INTO cti_relationships ("
        "  id, src_type, src_id, rel_type, dst_type, dst_id, "
        "  source_id, raw_stix"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (src_type, src_id, rel_type, dst_type, dst_id) "
        "DO NOTHING",
        [rel_id, src_type, src_id, rel_type, dst_type, dst_id,
         source_id, json.dumps(rel)],
    )
    return True
