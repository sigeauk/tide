"""One-off: inspect CTI report wiring."""
from app.services.connection_pool import get_pool


def main():
    pool = get_pool()
    # Find tenant DB matching cti_primary_b7a7d4a1.duckdb
    with pool.acquire("/app/data/cti_primary_b7a7d4a1.duckdb") as c:
        print("actors:", c.execute("select count(*) from cti_actors").fetchone())
        print("with stix_id:", c.execute("select count(*) from cti_actors where stix_id is not null").fetchone())
        for r in c.execute(
            "select stix_type, name, stix_id from cti_actors where stix_id is not null limit 5"
        ).fetchall():
            print(" ", r)
        target = "intrusion-set--a174671f-a9d6-5de5-b9f7-b429207a7c9f"
        print("lookup", target)
        print(c.execute(
            "select stix_type, name, stix_id from cti_actors where stix_id = ?",
            [target],
        ).fetchone())
        print("partial a174671f:")
        for r in c.execute(
            "select stix_type, name, stix_id from cti_actors where stix_id like '%a174671f%'"
        ).fetchall():
            print(" ", r)
        # Find reports whose object_refs hits an actor we have
        import json as _json
        hits = 0
        miss = 0
        sample_hit = None
        sample_actor_ids = {r[0] for r in c.execute(
            "select stix_id from cti_actors where stix_id is not null"
        ).fetchall()}
        for rid, raw in c.execute(
            "select id, raw_stix from cti_reports where raw_stix is not null"
        ).fetchall():
            try:
                blob = _json.loads(raw)
            except Exception:
                continue
            refs = blob.get("object_refs") or []
            if any(r in sample_actor_ids for r in refs):
                hits += 1
                if sample_hit is None:
                    sample_hit = (rid, [r for r in refs if r in sample_actor_ids][:3])
            else:
                miss += 1
        print(f"reports with linkable actors: {hits} (no match: {miss})")
        print("sample hit:", sample_hit)
        # Inspect the two reports involved in the slow request
        for probe in [
            "report--eecd09ea-9376-5518-add0-3b64cc0ac799",
            "report--88e0f3cf-bb6d-5386-9bee-5b8e36e7693d",
        ]:
            row = c.execute(
                "select source_id, length(raw_stix), pdf_blob is not null from cti_reports where id=?",
                [probe],
            ).fetchone()
            print(probe, "->", row)
            raw = c.execute(
                "select raw_stix from cti_reports where id=?", [probe]
            ).fetchone()
            if raw and raw[0]:
                b = _json.loads(raw[0])
                refs = b.get("object_refs") or []
                print(
                    "  refs:", len(refs),
                    "ind:", sum(1 for r in refs if r.startswith("indicator--")),
                    "act:", sum(1 for r in refs if r.startswith("intrusion-set--") or r.startswith("threat-actor--")),
                )
                # show first 5 actor refs and whether they exist in cti_actors
                arefs = [r for r in refs if r.startswith("intrusion-set--") or r.startswith("threat-actor--")][:5]
                for ar in arefs:
                    found = c.execute(
                        "select name from cti_actors where stix_id=?", [ar]
                    ).fetchone()
                    print("    ", ar, "->", found)


if __name__ == "__main__":
    main()
