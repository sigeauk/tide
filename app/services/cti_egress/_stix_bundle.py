"""Shared STIX bundle serialiser used by the file-drop egress drivers.

The bundle contains one STIX ``indicator`` SDO per indicator row plus
the actor ``threat-actor`` / ``intrusion-set`` SDOs referenced by them
and the ``indicates`` relationship SROs that tie them together. The
exact shape is intentionally minimal — diode-side ingesters parse
STIX 2.1 bundles, so we ship the canonical fields and nothing else.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from ._common import _iso


def _stix_id(prefix: str, seed: str) -> str:
    """Deterministic STIX 2.1 id (``<type>--<uuidv5>``)."""
    ns = uuid.UUID("00000000-0000-0000-0000-000000000000")
    return f"{prefix}--{uuid.uuid5(ns, seed)}"


def build_bundle(indicators: List[Dict[str, Any]], *,
                 source_label: str) -> Dict[str, Any]:
    """Serialise indicators into a STIX 2.1 bundle dict.

    ``source_label`` is embedded in each SDO's ``created_by_ref`` proxy
    via a synthetic ``identity`` SDO so downstream ingesters can
    attribute the bundle back to TIDE.
    """
    now = _iso(datetime.now(timezone.utc))
    identity_id = _stix_id("identity", f"tide|{source_label}")
    objects: List[Dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": f"TIDE — {source_label}",
            "identity_class": "system",
        },
    ]

    actor_ids: Dict[str, str] = {}
    for ind in indicators:
        ind_id = ind.get("id") or _stix_id(
            "indicator",
            f"{ind.get('pattern_type','')}|"
            f"{ind.get('observable_value','')}",
        )
        ind_sdo: Dict[str, Any] = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": _iso(ind.get("first_seen")) or now,
            "modified": _iso(ind.get("last_seen")) or now,
            "created_by_ref": identity_id,
            "pattern_type": ind.get("pattern_type") or "stix",
            "pattern": ind.get("pattern") or "",
            "valid_from": _iso(ind.get("valid_from")) or now,
        }
        if ind.get("valid_until"):
            ind_sdo["valid_until"] = _iso(ind.get("valid_until"))
        if ind.get("confidence") is not None:
            ind_sdo["confidence"] = ind.get("confidence")
        if ind.get("tlp"):
            ind_sdo["x_tide_tlp"] = ind.get("tlp")
        objects.append(ind_sdo)

        for actor_name in (ind.get("actors") or []):
            if actor_name not in actor_ids:
                actor_ids[actor_name] = _stix_id(
                    "intrusion-set", f"actor|{actor_name}",
                )
                objects.append({
                    "type": "intrusion-set",
                    "spec_version": "2.1",
                    "id": actor_ids[actor_name],
                    "created": now,
                    "modified": now,
                    "created_by_ref": identity_id,
                    "name": actor_name,
                })
            rel_id = _stix_id(
                "relationship",
                f"{ind_id}|indicates|{actor_ids[actor_name]}",
            )
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": now,
                "modified": now,
                "created_by_ref": identity_id,
                "relationship_type": "indicates",
                "source_ref": ind_id,
                "target_ref": actor_ids[actor_name],
            })

    return {
        "type": "bundle",
        "id": _stix_id("bundle", f"{source_label}|{now}"),
        "objects": objects,
    }


def write_bundle(bundle: Dict[str, Any], folder: str, *,
                 filename: str) -> str:
    """Write ``bundle`` as JSON to ``folder/filename``; return path."""
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, filename)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, separators=(",", ":"))
    return path
