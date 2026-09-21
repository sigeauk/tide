"""TIDE diagnostic: sync chain, schema, and the state of the whole standalone app.

Run from inside the container:

    docker exec tide-app python -m app.scripts.diag_sync            # everything
    docker exec tide-app python -m app.scripts.diag_sync --state    # state sections only (14-19), no Kibana calls

Designed for a standalone system: it needs no internet, only the local files and databases
(and, in the full run, the local Kibana / Elasticsearch / Keycloak). It never writes to a live
database: each one is read from a private snapshot copy. Secrets are never printed (tokens are
redacted to ``len=N first=AAAA last=BBBB``), so the output is safe to paste into a support channel.
Findings are marked [OK] / [INFO] / [WARN] / [FAIL] and repeated in the summary at the end; the
exit code is 1 when there is a FAIL.

Sync chain (``env -> DB -> SIEM record -> Kibana mapping -> rule cache``):
   1. Container env vars (legacy ELASTIC_URL / ELASTIC_API_KEY)
   2. Shared DB state (siem_inventory, clients, client_siem_map)
   3. Live Kibana auth check, plus per-(siem, space) probe vs client_siem_map
   4. Per-tenant DB state + detection_rules column-diff per tenant
   5. Schema / migration state (current vs expected, leftover legacy columns)
   6. Recent ERROR / WARN log tail
   7. Elasticsearch reachability
   8. Verdict naming the failing link and the next action
   9. Dry run of the sync URLs (no network)
  10. Per-client live sync trace (fetch only, no DB writes)
  11. Per-tenant OpenCTI link state
  12. Per-tenant CTI DB state
  13. TAXII delta cursors

State of the app (``--state`` runs only these):
  14. App & host: version, libraries, uptime, memory, disk, auth / debug / default-secret warnings
  15. Database files: size, space in use vs empty (compaction advice), WAL, table row counts,
      leftover backup and quarantined-WAL files
  16. Rules & scoring per tenant: rule counts by SIEM / space / language, sync age, score model
      versions and distribution, weakest checks, weights, history size and orphans
  17. Sync history, SIEM connection tests, field catalogue, reference tables, CTI connectors
  18. Users, tenants, Keycloak reachability
  19. Bundled reference data (Sigma, Elastic rules, MITRE, CISA, NVD) present and consistent
"""
from __future__ import annotations

import os
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _redact(value: str | None) -> str:
    if not value:
        return "<EMPTY>"
    v = str(value)
    return f"len={len(v)} first={v[:6]!r} last={v[-4:]!r}"


def _line(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def _check_env() -> dict:
    _line("1. Container environment variables")
    keys = [
        "ELASTIC_URL",
        "ELASTIC_API_KEY",
        "KIBANA_SPACES",
        "ELASTICSEARCH_URL",
        "TIDE_SECRET_KEY",
        "TIDE_FERNET_KEY",
        "TIDE_ISOLATION_STRICT",
        "TIDE_AUTH_DISABLED",
        "AUTH_DISABLED",
    ]
    found = {}
    for k in keys:
        v = os.environ.get(k)
        found[k] = v
        if "KEY" in k or "TOKEN" in k or "SECRET" in k:
            print(f"  {k:24s} = {_redact(v)}")
        else:
            print(f"  {k:24s} = {v!r}")
    if found.get("ELASTIC_URL") or found.get("ELASTIC_API_KEY"):
        print("  ! ELASTIC_URL / ELASTIC_API_KEY env vars are set. On 4.1.x")
        print("    these are IGNORED — sync uses siem_inventory + client_siem_map.")
        print("    The env vars only do anything on 4.0.x. Delete them to")
        print("    avoid future confusion (they are not the source of any")
        print("    sync behaviour you are seeing on this build).")
    else:
        print("  (no legacy env-var auth set — normal for 4.0.13+ / 4.1.x)")
    return found


def _check_db() -> dict:
    _line("2. Database state")
    info: dict = {"db_read_ok": False}
    db_path = os.environ.get("TIDE_DB_PATH", "/app/data/tide.duckdb")
    info["db_path"] = db_path
    if not os.path.exists(db_path):
        print(f"  shared DB file not found at {db_path}")
        info["db_read_error"] = f"missing file {db_path}"
        return info
    # DuckDB refuses concurrent open even for read-only when another process
    # holds the file. Try snapshot to /tmp first, fall back to a snapshot in
    # the DB's own directory (handles /tmp out-of-space — [Errno 28]), then
    # finally fall back to opening the live file read-only (works on newer
    # DuckDB builds when the writer has checkpointed).
    import shutil
    import tempfile
    snap_dir = None
    snap_path = None
    snapshot_err = None
    for tmp_root in (None, os.path.dirname(db_path)):
        try:
            snap_dir = tempfile.mkdtemp(prefix="diag_db_", dir=tmp_root)
            snap_path = os.path.join(snap_dir, "snap.duckdb")
            shutil.copy2(db_path, snap_path)
            wal = db_path + ".wal"
            if os.path.exists(wal):
                shutil.copy2(wal, snap_path + ".wal")
            snapshot_err = None
            break
        except OSError as exc:
            snapshot_err = exc
            if snap_dir:
                shutil.rmtree(snap_dir, ignore_errors=True)
                snap_dir = None
            # errno 28 (ENOSPC) on /tmp is the common failure mode in
            # constrained containers; the loop's second pass uses the data
            # dir which usually has room.
            continue
        except Exception as exc:
            snapshot_err = exc
            break
    if snapshot_err is not None and snap_path is None:
        errno_part = f" [Errno {snapshot_err.errno}]" if hasattr(snapshot_err, "errno") and snapshot_err.errno else ""
        print(f"  could not snapshot DB{errno_part}: {snapshot_err}")
        if hasattr(snapshot_err, "errno") and snapshot_err.errno == 28:
            print("  -> ENOSPC: /tmp and the DB directory are both out of")
            print("     disk. Free space (df -h /tmp /app/data) or set TMPDIR")
            print("     to a partition that has room, then re-run.")
        info["db_read_error"] = f"snapshot failed: {snapshot_err}"
    import duckdb
    c = None
    if snap_path is not None:
        try:
            c = duckdb.connect(snap_path)
        except Exception as exc:
            print(f"  cannot open DB snapshot: {exc}; trying live file...")
            info["db_read_error"] = f"snapshot open failed: {exc}"
    if c is None:
        try:
            c = duckdb.connect(db_path, read_only=True)
            print("  (read live DB file directly — snapshot was unavailable)")
        except Exception as exc:
            print(f"  cannot open live DB either: {exc}")
            print("  -> downstream sections (4, 5, 7) will say 'skipped:")
            print("     section 2 could not read the shared DB'.")
            info["db_read_error"] = f"live open failed: {exc}"
            return info
    try:
        tables = [r[0] for r in c.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema='main' ORDER BY table_name"
        ).fetchall()]
        print(f"  shared DB ({db_path}): {len(tables)} tables")
        print(f"  has_siem_inventory: {'siem_inventory' in tables}")
        print(f"  has_client_siem_map: {'client_siem_map' in tables}")
        print(f"  has_clients: {'clients' in tables}")
        print(f"  has_detection_rules: {'detection_rules' in tables}")

        try:
            ver = c.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
            print(f"  schema_version: {ver}")
            info["schema_version"] = ver
        except Exception:
            print("  schema_version: <missing> (very old DB or fresh)")
            info["schema_version"] = None

        if "detection_rules" in tables:
            rc = c.execute("SELECT COUNT(*) FROM detection_rules").fetchone()[0]
            print(f"  detection_rules row count: {rc}")
            info["detection_rules_count"] = rc

        if "siem_inventory" in tables:
            # Detect leftover legacy columns from before Migration 38. The
            # columns SHOULD be gone; if PRAGMA still returns them the
            # migration's DROP COLUMN was rejected (very old DuckDB).
            try:
                cols = c.execute(
                    "PRAGMA table_info('siem_inventory')"
                ).fetchall()
                col_names = {row[1] for row in cols}
                legacy = [n for n in ("production_space", "staging_space")
                          if n in col_names]
                if legacy:
                    info["siem_inventory_legacy_cols"] = legacy
            except Exception:
                pass

            rows = c.execute(
                "SELECT id, label, kibana_url, elasticsearch_url, "
                "api_token_enc, is_active FROM siem_inventory"
            ).fetchall()
            info["siems"] = []
            if not rows:
                print("  siem_inventory: <EMPTY> -- no SIEMs configured")
            for sid, label, kurl, eurl, tok, active in rows:
                print(f"  SIEM {sid[:8]} '{label}' active={active}")
                print(f"     kibana_url        = {kurl!r}")
                print(f"     elasticsearch_url = {eurl!r}")
                print(f"     api_token         = {_redact(tok)}")
                info["siems"].append(
                    {"id": sid, "label": label, "kibana_url": kurl,
                     "elasticsearch_url": eurl, "api_token": tok,
                     "is_active": active}
                )

        if "clients" in tables:
            try:
                clients = c.execute(
                    "SELECT id, name, db_filename FROM clients"
                ).fetchall()
            except Exception:
                # Pre-4.1.x clients table has no db_filename column.
                clients = [(r[0], r[1], None) for r in c.execute(
                    "SELECT id, name FROM clients"
                ).fetchall()]
            info["clients"] = clients
            print(f"  clients: {len(clients)}")
            for cid, name, fn in clients:
                print(f"     {cid[:8]} '{name}' db_filename={fn!r}")

        if "client_siem_map" in tables:
            try:
                maps = c.execute(
                    "SELECT client_id, siem_id, environment_role, space "
                    "FROM client_siem_map"
                ).fetchall()
            except Exception:
                maps = c.execute(
                    "SELECT client_id, siem_id, NULL, NULL "
                    "FROM client_siem_map"
                ).fetchall()
            info["mappings"] = maps
            print(f"  client_siem_map rows: {len(maps)}")
            for cid, sid, role, space in maps:
                print(f"     client={cid[:8]} siem={sid[:8]} "
                      f"role={role!r} space={space!r}")
        info["db_read_ok"] = True
    except Exception as exc:
        print(f"  ERROR reading shared DB: {exc}")
        info["db_read_error"] = str(exc)
    finally:
        try:
            c.close()
        except Exception:
            pass
        if snap_dir:
            try:
                import shutil as _sh
                _sh.rmtree(snap_dir, ignore_errors=True)
            except Exception:
                pass
    return info


def _check_kibana(siems: list, env: dict, mappings: list = None) -> None:
    """Hit each SIEM endpoint with the actual stored token. No TIDE wrappers,
    just raw requests so the result reflects only credentials + network.

    When ``mappings`` (rows from ``client_siem_map``) is provided, also probe
    each (siem, space) pair that the sync orchestrator will actually use \u2014
    this catches the very common misconfiguration where ``space`` was set to
    the role name (e.g. literal string ``"production"``) instead of an actual
    Kibana space name.
    """
    _line("3. Live Kibana auth check")
    import requests

    targets = []
    # DB-driven SIEMs (4.0.13+ / 4.1.x)
    for s in siems:
        if not s.get("kibana_url") or not s.get("api_token"):
            continue
        targets.append((
            f"siem_inventory/{s['label']}",
            s["kibana_url"],
            s["api_token"],
            s.get("id"),
        ))
    # Env-var fallback (4.0.x)
    if env.get("ELASTIC_URL") and env.get("ELASTIC_API_KEY"):
        targets.append((
            "env(ELASTIC_URL+ELASTIC_API_KEY)",
            env["ELASTIC_URL"],
            env["ELASTIC_API_KEY"],
            None,
        ))
    if not targets:
        print("  no targets to test (no SIEMs in DB, no env vars). "
              "Either add a SIEM via Management UI or set ELASTIC_URL + "
              "ELASTIC_API_KEY in the container env.")
        return

    # Per-SIEM cache of {space_name: True} as discovered by /api/spaces/space
    real_spaces_per_siem: dict = {}

    for label, url, token, siem_id in targets:
        url = url.rstrip("/")
        # 4.1.14 Fix 15: route through /s/default/ to match the standardised
        # URL shape used by the production app (post-4.1.14). Hitting bare
        # /api/detection_engine/... triggers proxy 404s / redirects on
        # reverse-proxied Kibana ingresses, which historically made Section 3
        # report a connection failure even when sync worked fine.
        endpoint = f"{url}/s/default/api/detection_engine/rules/_find?per_page=1"
        print(f"  -> {label}")
        print(f"     URL: {endpoint}")
        print(f"     Auth: ApiKey {_redact(token)}")
        try:
            r = requests.get(
                endpoint,
                headers={
                    "kbn-xsrf": "true",
                    "Authorization": f"ApiKey {token}",
                    "Content-Type": "application/json",
                },
                verify=False,
                timeout=15,
            )
            print(f"     HTTP {r.status_code}")
            body = r.text[:300].replace("\n", " ")
            print(f"     body: {body}")
            if r.status_code == 200:
                try:
                    total = r.json().get("total")
                    print(f"     OK -- Kibana reports {total} rules in "
                          f"default-space scope.")
                except Exception:
                    print("     OK -- but response wasn't JSON.")
            elif r.status_code == 401:
                print("     401 -- Kibana rejected the API key.")
                # Active probe: if the stored token has surrounding whitespace
                # or quotes, retry stripped — if THAT works the cause is
                # definitively a bad value in siem_inventory.api_token_enc.
                stripped = (token or "").strip().strip('"').strip("'")
                if stripped and stripped != token:
                    try:
                        r2 = requests.get(
                            endpoint,
                            headers={
                                "kbn-xsrf": "true",
                                "Authorization": f"ApiKey {stripped}",
                            },
                            verify=False, timeout=15,
                        )
                        if r2.status_code == 200:
                            print("     >>> RETRY WITH STRIPPED TOKEN -> HTTP 200.")
                            print("         CAUSE: stored token has whitespace/quotes.")
                            print("         FIX: edit the SIEM in Management UI and")
                            print("              re-paste the API key (no quotes,")
                            print("              no surrounding spaces).")
                        else:
                            print(f"     (retry with stripped token also got HTTP {r2.status_code})")
                    except Exception:
                        pass
                else:
                    print("     (token has no surrounding whitespace/quotes")
                    print("      — not a copy/paste artefact.)")
                print("     If the same key works via curl from the SAME container")
                print("     (`docker exec tide-app curl -kv -H 'Authorization:")
                print("     ApiKey <key>' <url>`), the most likely remaining causes are:")
                print("        a) Key revoked/rotated in Kibana since it was stored")
                print("           (the curl test you ran was with a DIFFERENT key).")
                print("        b) URL points to Elasticsearch (port 9200) instead of")
                print("           Kibana (5601). Check the kibana_url printed above.")
                print("        c) Kibana behind a reverse proxy that strips the")
                print("           Authorization header on this code path but not on")
                print("           the curl path (different vhost / location block).")
            elif r.status_code in (403,):
                print("     403 -- Key valid but lacks required Kibana "
                      "privileges. Need 'detections:read' (Detection Engine).")
            elif r.status_code == 404:
                print("     404 -- URL is reachable but path missing. "
                      "Probably hitting Elasticsearch instead of Kibana, "
                      "or wrong base path.")
            else:
                print(f"     HTTP {r.status_code} -- unexpected.")
        except requests.exceptions.SSLError as e:
            print(f"     SSL ERROR: {e}")
            print("     fix: either deploy the CA into the container or "
                  "set requests verify=False (TIDE already does this).")
        except requests.exceptions.ConnectionError as e:
            print(f"     CONNECTION ERROR: {e}")
            print("     fix: check the container can reach the host:port. "
                  "Try: docker exec tide-app curl -kv <url>")
        except Exception as e:
            print(f"     ERROR: {type(e).__name__}: {e}")
            continue

        # Now ask Kibana what spaces actually exist on this instance, so the
        # next section can validate the configured space names.
        try:
            sp = requests.get(
                f"{url}/api/spaces/space",
                headers={
                    "kbn-xsrf": "true",
                    "Authorization": f"ApiKey {token}",
                    "Content-Type": "application/json",
                },
                verify=False,
                timeout=15,
            )
            if sp.status_code == 200:
                try:
                    space_list = [s.get("id") for s in sp.json() if s.get("id")]
                except Exception:
                    space_list = []
                real_spaces_per_siem[siem_id] = set(space_list)
                print(f"     Kibana spaces on this instance: "
                      f"{sorted(space_list) or '<none returned>'}")
            else:
                print(f"     /api/spaces/space returned HTTP {sp.status_code} "
                      f"-- can't validate configured space names.")
        except Exception as e:
            print(f"     /api/spaces/space failed: "
                  f"{type(e).__name__}: {e}")

    # ---- 3b. Per-(siem, space) probe against client_siem_map ---------------
    if mappings:
        print("")
        print("  Per-mapping space check (client_siem_map):")
        siem_lookup = {s.get("id"): s for s in siems}
        for cid, sid, role, space in mappings:
            siem = siem_lookup.get(sid)
            if not siem or not siem.get("kibana_url") or not siem.get("api_token"):
                print(f"     client={cid[:8]} siem={sid[:8]} role={role!r} "
                      f"space={space!r}  -- siem record missing or no token, "
                      f"skipped.")
                continue
            real_spaces = real_spaces_per_siem.get(sid)
            if real_spaces is not None and space not in real_spaces:
                print(f"     client={cid[:8]} siem={sid[:8]} role={role!r} "
                      f"space={space!r}  X NOT a real Kibana space on "
                      f"'{siem.get('label')}'. Real spaces: "
                      f"{sorted(real_spaces)}. This mapping will produce "
                      f"'Sync drift 0/0' on every sync. Fix: edit the "
                      f"mapping in the Management UI and set the space to "
                      f"one of the real values above (or 'default').")
                continue
            # Probe live to be sure
            url = siem["kibana_url"].rstrip("/")
            if (space or "default").lower() == "default":
                ep = f"{url}/api/detection_engine/rules/_find?per_page=1"
            else:
                ep = f"{url}/s/{space}/api/detection_engine/rules/_find?per_page=1"
            try:
                r = requests.get(
                    ep,
                    headers={
                        "kbn-xsrf": "true",
                        "Authorization": f"ApiKey {siem['api_token']}",
                    },
                    verify=False,
                    timeout=15,
                )
                tag = "OK" if r.status_code == 200 else f"HTTP {r.status_code}"
                extra = ""
                if r.status_code == 200:
                    try:
                        extra = f" (Kibana total={r.json().get('total')})"
                    except Exception:
                        pass
                print(f"     client={cid[:8]} siem={sid[:8]} role={role!r} "
                      f"space={space!r}  {tag}{extra}  url={ep}")
            except Exception as e:
                print(f"     client={cid[:8]} siem={sid[:8]} role={role!r} "
                      f"space={space!r}  ERROR: {type(e).__name__}: {e}")


# Canonical detection_rules columns expected in the TENANT DB (26 columns).
# Mirrors _TENANT_DETECTION_RULES_COLUMNS in app/services/sync.py — keep in sync.
_TENANT_DR_COLS = (
    "rule_id", "siem_id", "name", "severity", "author", "enabled", "space",
    "score", "quality_score", "meta_score",
    "score_mapping", "score_field_type", "score_search_time",
    "score_language", "score_note", "score_override",
    "score_tactics", "score_techniques", "score_author", "score_highlights",
    "last_updated", "mitre_ids", "raw_data",
    "client_id", "deprecated", "source_rule_id",
)

# Canonical detection_rules columns expected in the SHARED DB (23 columns —
# no client_id; that column lives only on tenant copies).
_SHARED_DR_COLS = tuple(c for c in _TENANT_DR_COLS if c != "client_id")


def _check_dr_columns(conn, table_ref: str, canonical: tuple, label: str) -> list[str]:
    """Compare actual detection_rules columns against canonical.
    Prints findings, returns list of missing column names."""
    try:
        rows = conn.execute(f"DESCRIBE {table_ref}").fetchall()
        actual = [r[0] for r in rows]
    except Exception as exc:
        print(f"  {label}: could not DESCRIBE {table_ref}: {exc}")
        return []

    actual_set = set(actual)
    canonical_set = set(canonical)
    missing = [c for c in canonical if c not in actual_set]
    extra   = sorted(actual_set - canonical_set)

    status = "OK" if not missing else "X SCHEMA MISMATCH"
    print(f"  {label}: {table_ref} — {len(actual)} columns  [{status}]")
    if missing:
        print(f"     MISSING ({len(missing)}): {missing}")
        if "client_id" in missing:
            print("     ^ This is the direct cause of:")
            print(f"       'table detection_rules has {len(actual)} columns")
            print(f"        but {len(canonical)} values were supplied'")
            print("       Fix: docker compose up -d --build  (startup repairs")
            print("       all tenant DBs automatically in 4.1.8+).")
        if "siem_id" in missing:
            print("     ^ siem_id missing = pre-4.0.13 schema. Table will be")
            print("       rebuilt from scratch on next startup (safe — cache only).")
    if extra:
        print(f"     EXTRA columns (harmless): {extra}")
    return missing


def _check_tenant_dbs(info: dict) -> None:
    _line("4. Per-tenant DB state (4.1.x only)")
    if not info.get("db_read_ok"):
        print("  skipped: section 2 could not read the shared DB")
        print(f"  ({info.get('db_read_error', 'unknown error')})")
        return
    data_dir = os.environ.get("TIDE_DATA_DIR", "/app/data")
    if not os.path.isdir(data_dir):
        print(f"  data_dir {data_dir} not found.")
        return
    print(f"  data_dir: {data_dir}")
    clients = info.get("clients") or []
    if not clients or all(fn is None for _c, _n, fn in clients):
        print("  no per-tenant DB filenames recorded (4.0.x or pre-4.1 client schema).")
        return

    import duckdb
    import shutil
    import tempfile
    for cid, name, fn in clients:
        if not fn:
            print(f"  client {cid[:8]} '{name}' has NO db_filename - "
                  f"per-tenant DB never provisioned.")
            continue
        path = os.path.join(data_dir, fn)
        if not os.path.exists(path):
            print(f"  client {cid[:8]} '{name}' db_filename={fn} but "
                  f"file MISSING at {path}")
            continue
        snap_dir = tempfile.mkdtemp(prefix="diag_tenant_")
        snap = os.path.join(snap_dir, "t.duckdb")
        try:
            shutil.copy2(path, snap)
            wal = path + ".wal"
            if os.path.exists(wal):
                shutil.copy2(wal, snap + ".wal")
            t = duckdb.connect(snap)
            try:
                rc = t.execute("SELECT COUNT(*) FROM detection_rules").fetchone()[0]
            except Exception:
                rc = "<table missing>"
            try:
                cm = t.execute("SELECT COUNT(*) FROM client_siem_map").fetchone()[0]
            except Exception:
                cm = "<table missing>"
            print(f"  client {cid[:8]} '{name}': "
                  f"detection_rules={rc} client_siem_map={cm} ({fn})")
            # Column-diff check against canonical tenant schema.
            if rc != "<table missing>":
                _check_dr_columns(
                    t, "detection_rules", _TENANT_DR_COLS,
                    f"    tenant {cid[:8]} '{name}'",
                )
            t.close()
        except Exception as exc:
            print(f"  client {cid[:8]} '{name}' DB ERROR: {exc}")
        finally:
            shutil.rmtree(snap_dir, ignore_errors=True)


def _verdict(env: dict, info: dict) -> None:
    _line("8. Verdict")
    siems = info.get("siems") or []
    has_db_creds = any(s.get("kibana_url") and s.get("api_token") for s in siems)
    has_env_creds = bool(env.get("ELASTIC_URL")) and bool(env.get("ELASTIC_API_KEY"))
    rules = info.get("detection_rules_count", 0)

    if not has_db_creds and not has_env_creds:
        print("  X No credentials anywhere. Add a SIEM in Management UI "
              "(4.0.13+) or set ELASTIC_URL + ELASTIC_API_KEY env vars (4.0.x).")
        return
    if rules == 0:
        print("  - Shared detection_rules cache is empty. Click Sync in the "
              "UI to populate it.")
    if has_db_creds and has_env_creds:
        print("  ! Both DB SIEM and env-var creds are set. The DB SIEM wins "
              "on 4.0.13+; the env vars are ignored. If you intended to use "
              "env vars, delete the SIEM from Management UI.")
    if rules > 0 and info.get("clients"):
        print("  + Shared rules present. If a tenant has 0 rules in step 4, "
              "they have no client_siem_map row OR the SIEM mapping points "
              "to a (siem_id, space) pair with no rules in the shared cache.")
    print("  Re-run this script after any config change to confirm the fix.")


def _check_migrations(info: dict) -> None:
    _line("5. Schema / migration state + shared detection_rules columns")
    if not info.get("db_read_ok"):
        print("  skipped: section 2 could not read the shared DB")
        print(f"  ({info.get('db_read_error', 'unknown error')})")
        return
    try:
        from app.services.database import SCHEMA_VERSION as expected
    except Exception:
        expected = None          # never guess: a stale hard-coded number gives a false verdict
    sv = info.get("schema_version")
    print(f"  expected schema_version: {expected}")
    print(f"  actual schema_version:   {sv}")
    if expected is None:
        print("  ! could not import the app's SCHEMA_VERSION, so the comparison was skipped.")
    elif sv is None:
        print("  ! schema_version table missing. Either pre-Migration-1 DB or "
              "the migrations runner failed. Check tide-app startup logs for "
              "'Migrations complete'.")
    elif sv < expected:
        print(f"  X DB is {expected - sv} migration(s) behind. Restart the "
              f"container so the migrations runner advances it. Most common "
              f"cause: a migration raised mid-run, see logs for "
              f"'Migration {sv + 1} failed'.")
    elif sv > expected:
        print(f"  ! DB schema_version ({sv}) is ahead of this app build "
              f"({expected}). Image rolled back without DB rollback. Either "
              f"redeploy the matching app version or accept that newer columns "
              f"may be ignored.")
    else:
        print("  + schema is current.")

    # Migration 38 specific check: production_space / staging_space columns
    # should be gone. If they're still there the upgrade was incomplete.
    bad_cols = info.get("siem_inventory_legacy_cols") or []
    if bad_cols:
        print(f"  X siem_inventory still has legacy columns {bad_cols}. "
              f"Migration 38 partially failed (DROP COLUMN refused). The app "
              f"will ignore them but the DB carries dead data. Inspect with: "
              f"docker exec tide-app python -c \"import duckdb; "
              f"print(duckdb.connect('/app/data/tide.duckdb', read_only=True)"
              f".execute('PRAGMA table_info(siem_inventory)').fetchall())\"")

    # ── Shared DB: detection_rules column-diff (skipped post-4.1.13) ──────────────
    # Since 4.1.13 (Migration 45) `detection_rules` exists ONLY in tenant
    # DBs. Confirm the shared DB does NOT carry the table; presence here
    # would be a real regression worth flagging. Tenant column-diff still
    # runs in section 4 (`_check_tenant_dbs`).
    db_path = os.environ.get("TIDE_DB_PATH", "/app/data/tide.duckdb")
    import shutil, tempfile, duckdb as _ddb
    snap_dir2 = None
    try:
        snap_dir2 = tempfile.mkdtemp(prefix="diag_schema_")
        snap2 = os.path.join(snap_dir2, "s.duckdb")
        shutil.copy2(db_path, snap2)
        wal2 = db_path + ".wal"
        if os.path.exists(wal2):
            shutil.copy2(wal2, snap2 + ".wal")
        conn2 = _ddb.connect(snap2)
        try:
            tables = [r[0] for r in conn2.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'main'"
            ).fetchall()]
            if "detection_rules" in tables:
                print("  X shared DB still carries `detection_rules` table. "
                      "Since 4.1.13 (Migration 45) this table is supposed to "
                      "live ONLY in tenant DBs. Presence here means "
                      "Migration 45 did not run — inspect schema_version and "
                      "the migrations log.")
                _check_dr_columns(
                    conn2, "detection_rules", _SHARED_DR_COLS, "  shared DB"
                )
            else:
                print("  + shared DB: detection_rules absent (expected since "
                      "4.1.13 Migration 45 — rules are per-tenant). Per-tenant "
                      "column-diff is in section 4.")
        finally:
            conn2.close()
    except Exception as exc:
        print(f"  shared DB column-diff skipped: {exc}")
    finally:
        if snap_dir2:
            shutil.rmtree(snap_dir2, ignore_errors=True)


def _check_logs() -> None:
    _line("6. Recent ERROR / WARN log tail")
    # Honour the same env override the app uses (see configure_logging in
    # app/services/log_context.py). Fall through to the historical defaults
    # so older deployments that ship a custom path keep working.
    env_path = os.environ.get("TIDE_LOG_FILE")
    log_paths: list[str] = []
    if env_path:
        log_paths.append(env_path)
    log_paths.extend([
        "/app/data/log/tide.log",
        "/app/data/log/app.log",
        "/var/log/tide-app.log",
    ])
    # Include rotated siblings (tide.log.1, tide.log.2…) so we still have
    # something to show right after a rotation.
    expanded: list[str] = []
    seen: set[str] = set()
    import glob
    for p in log_paths:
        for match in [p] + sorted(glob.glob(p + ".*")):
            if match in seen:
                continue
            seen.add(match)
            expanded.append(match)

    needles = ("ERROR", "WARN", "Traceback", "Sync drift",
               "auth-banner", "isolation_violation")
    found_any = False
    matched_any = False
    import collections
    import datetime as _dt
    for p in expanded:
        if not os.path.exists(p):
            continue
        found_any = True
        try:
            st = os.stat(p)
            size_kb = st.st_size / 1024.0
            mtime = _dt.datetime.fromtimestamp(st.st_mtime).isoformat(
                timespec="seconds"
            )
            print(f"  -- {p} (size={size_kb:.1f} KB, mtime={mtime}) --")
        except Exception:
            print(f"  -- {p} --")
        try:
            tail = collections.deque(maxlen=40)
            recent = collections.deque(maxlen=10)
            with open(p, "r", errors="replace") as f:
                for line in f:
                    recent.append(line.rstrip())
                    if any(t in line for t in needles):
                        tail.append(line.rstrip())
            if tail:
                matched_any = True
                print(f"     [last {len(tail)} ERROR/WARN lines]")
                for line in tail:
                    print(f"     {line}")
            else:
                print("     (no ERROR/WARN lines in this file — last 5 lines:)")
                for line in list(recent)[-5:]:
                    print(f"     {line}")
        except Exception as exc:
            print(f"     could not read: {exc}")

    if not found_any:
        print("  no log files found.")
        print("  Looked at:")
        for p in expanded:
            print(f"     - {p}")
        print("  Enable on-disk logs by leaving TIDE_LOG_FILE at its default")
        print("  ('/app/data/log/tide.log'). The app writes a rotating file")
        print("  there as of 4.1.7; older builds only logged to stdout, in")
        print("  which case use:")
        print("     docker logs --tail 200 tide-app | "
              "grep -E 'ERROR|WARN|drift|auth-banner'")
    elif not matched_any:
        print("  (no ERROR/WARN matches across the files above — last lines")
        print("  shown per-file. If you expect errors, check the live stream:")
        print("     docker logs --tail 200 tide-app | "
              "grep -E 'ERROR|WARN|drift|auth-banner')")


def _check_elasticsearch(siems: list) -> None:
    """Probe the elasticsearch_url (port 9200) on each SIEM. Sync only uses
    Kibana, but the operator very often configures the wrong port (9200 for
    kibana_url) and the symptom is identical to a 401 \u2014 differentiating the
    two saves a lot of guesswork."""
    _line("7. Elasticsearch reachability check (port 9200, info-only)")
    import requests
    if not siems:
        print("  no SIEMs to test (either none configured, or section 2")
        print("  could not read the shared DB — see section 2).")
        return
    for s in siems:
        url = (s.get("elasticsearch_url") or "").rstrip("/")
        token = s.get("api_token")
        if not url:
            print(f"  SIEM '{s.get('label')}': elasticsearch_url not set "
                  f"(only Kibana required for sync \u2014 informational).")
            continue
        print(f"  -> {s.get('label')}: GET {url}/_cluster/health")
        try:
            r = requests.get(
                f"{url}/_cluster/health",
                headers=({"Authorization": f"ApiKey {token}"} if token else {}),
                verify=False,
                timeout=10,
            )
            print(f"     HTTP {r.status_code}")
            body = r.text[:200].replace("\n", " ")
            print(f"     body: {body}")
            if r.status_code == 200:
                try:
                    j = r.json()
                    print(f"     status={j.get('status')!r} "
                          f"nodes={j.get('number_of_nodes')!r}")
                except Exception:
                    pass
        except Exception as exc:
            print(f"     ERROR: {type(exc).__name__}: {exc}")


def _check_dry_run_urls(info: dict) -> None:
    """Section 9: Dry Run Sync URL Construction.

    For every (client, siem, space) row in client_siem_map joined to
    siem_inventory, print the EXACT HTTP method, fully-qualified URL, and
    redacted headers that the sync would send to fetch detection rules.

    Pure string construction — makes ZERO network calls. The live probe is
    section 10 (`_check_live_sync_trace`). The point of this section is to
    prove what the app is sending, divorced from network behaviour, so a
    URL-builder regression (e.g. the 4.1.13 `default`-space stripping bug)
    is visible from the operator's first run.

    Uses the same `f"{base_url}/s/{space}/api/detection_engine/rules/_find"`
    formula as `fetch_detection_rules` (post-4.1.14). Flags `[WARN]` if any
    constructed URL contains the legacy bare `/api/detection_engine/...`
    shape — that would mean the special-case has crept back in.
    """
    _line("9. Dry Run Sync URL Construction")
    siems = {s["id"]: s for s in (info.get("siems") or [])}
    clients = {c[0]: c[1] for c in (info.get("clients") or [])}
    mappings = info.get("mappings") or []
    if not mappings:
        print("  no client_siem_map rows; nothing to construct.")
        return
    if not siems:
        print("  no siem_inventory rows; cannot resolve base URLs.")
        return

    legacy_shape_seen = False
    printed = 0
    for client_id, siem_id, role, space in mappings:
        siem = siems.get(siem_id)
        client_name = clients.get(client_id, "<unknown>")
        if not siem:
            print(f"  [client={client_name!r}] [siem={siem_id[:8]}] "
                  f"[space={space!r}] [role={role!r}] -- SKIP: "
                  "siem_id not found in siem_inventory")
            continue
        base_url = (siem.get("kibana_url") or "").rstrip("/")
        if not base_url:
            print(f"  [client={client_name!r}] [siem={siem.get('label')!r}] "
                  f"[space={space!r}] [role={role!r}] -- SKIP: "
                  "siem_inventory.kibana_url is empty")
            continue
        # Mirror the post-4.1.14 fetch_detection_rules URL shape exactly.
        # Empty-space guard mirrors _space_api_prefix.
        if not space:
            url = f"{base_url}/api/detection_engine/rules/_find"
        else:
            url = f"{base_url}/s/{space}/api/detection_engine/rules/_find"
        # Detect the legacy bare-/api/ shape that 4.1.13 produced for the
        # `default` space. If we ever see it again the [WARN] line below
        # tells the operator the regression is back.
        if "/s/" not in url and "/api/detection_engine/" in url:
            legacy_shape_seen = True
        token = siem.get("api_token") or ""
        headers = {
            "kbn-xsrf": "true",
            "Content-Type": "application/json",
            "Authorization": f"ApiKey {_redact(token)}",
        }
        print(
            f"  [client={client_name!r}] [siem={siem.get('label')!r}] "
            f"[space={space!r}] [role={role!r}]"
        )
        print(f"     METHOD : GET")
        print(f"     URL    : {url}")
        print(f"     HEADERS: {headers}")
        printed += 1

    if printed == 0:
        print("  no dry-run lines emitted (all rows skipped above).")
        return
    if legacy_shape_seen:
        print()
        print("  [WARN] one or more URLs above use the bare /api/... shape "
              "WITHOUT a /s/<space>/ prefix. This is the 4.1.13 regression "
              "and means a URL builder is special-casing 'default' again. "
              "Check fetch_detection_rules and _space_api_prefix in "
              "app/elastic_helper.py.")
    else:
        print()
        print(f"  [OK] {printed} URL(s) constructed; all use the "
              "/s/<space>/api/... shape that matches the working "
              "test-connection path.")


def _check_live_sync_trace(info: dict) -> None:
    """Section 10: per-client live sync trace.

    Runs through every step of ``run_elastic_sync`` for each client,
    printing exactly what happens at each decision point WITHOUT modifying
    the database.  This shows you precisely where the pipeline stalls.

    Uses snapshot-based DB reads (like sections 2-5) so the running app's
    write lock on tide.duckdb does not block the diagnostic.
    """
    _line("10. Live sync trace (per-client, read-only)")

    if not info.get("db_read_ok"):
        print("  skipped: section 2 could not read shared DB")
        return

    clients   = info.get("clients")   or []
    siems_raw = info.get("siems")     or []
    mappings  = info.get("mappings")  or []

    if not clients:
        print("  no clients found — nothing to trace")
        return

    import sys, os, shutil, tempfile
    try:
        import requests as _req
        import duckdb as _ddb
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError as exc:
        print(f"  required library not available: {exc}")
        return

    # Build lookup structures from the snapshot data already gathered
    siems_by_id = {s["id"]: s for s in siems_raw}

    # (client_id → [(siem_id, space)]) — from the already-read mappings
    scopes_by_client: dict = {}
    for cid, sid, _role, space in mappings:
        sp = (space or "default").strip().lower() or "default"
        scopes_by_client.setdefault(cid, []).append((sid, sp))

    # Re-open a snapshot to get the encrypted tokens (section 2 stores them)
    # — they were already read into info["siems"] but let's confirm they match
    db_path   = os.environ.get("TIDE_DB_PATH", "/app/data/tide.duckdb")
    data_dir  = os.path.dirname(db_path)

    app_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
    if app_dir not in sys.path:
        sys.path.insert(0, app_dir)

    for cid, name, db_filename in clients:
        print(f"\n  --- Client: '{name}' ({cid[:8]}...) ---")

        # ── Step 1: (siem_id, space) pairs ────────────────────────────────
        pairs = scopes_by_client.get(cid, [])
        print(f"    client_siem_map pairs → {pairs}")
        if not pairs:
            print("    [STOP] No client_siem_map rows for this client.")
            print("           Fix: add a SIEM mapping via Management → Link SIEM to Client.")
            continue

        # ── Step 2: tenant DB path ─────────────────────────────────────────
        if not db_filename:
            print("    [STOP] clients.db_filename is NULL — tenant DB not created.")
            print("           Fix: recreate tenant via Management page.")
            continue
        tenant_path = os.path.join(data_dir, db_filename)
        print(f"    tenant DB path → {tenant_path}")
        if not os.path.exists(tenant_path):
            print("    [WARN] Tenant DB file does not exist on disk yet.")
            print("           It will be created on first successful sync.")

        # ── Step 3: per-SIEM trace ─────────────────────────────────────────
        client_scope: dict = {}
        for sid, sp in pairs:
            client_scope.setdefault(sid, set()).add(sp)

        any_fail = False
        for siem_id, spaces in client_scope.items():
            siem = siems_by_id.get(siem_id)
            if not siem:
                print(f"\n    SIEM {siem_id[:8]} — [STOP] not found in siem_inventory")
                any_fail = True
                continue

            kurl  = (siem.get("kibana_url") or "").rstrip("/")
            token = siem.get("api_token") or ""
            label = siem.get("label", "?")
            active = siem.get("is_active", False)
            spaces_sorted = sorted(spaces)

            print(f"\n    SIEM '{label}' ({siem_id[:8]})")
            print(f"      is_active  = {active}")
            print(f"      kibana_url = {kurl!r}")
            print(f"      api_token  = {_redact(token)}")
            print(f"      spaces     = {spaces_sorted}")

            if not active:
                print("      [STOP] SIEM is inactive — sync skips inactive SIEMs.")
                print("             Fix: enable SIEM in Management → SIEMs.")
                any_fail = True
                continue
            if not kurl:
                print("      [STOP] kibana_url is empty.")
                any_fail = True
                continue
            if not token:
                print("      [STOP] api_token is empty — no credential.")
                any_fail = True
                continue

            # ── Step 3a: per-space HTTP probe ──────────────────────────────
            for space in spaces_sorted:
                if space.lower() == "default":
                    ep = f"{kurl}/api/detection_engine/rules/_find?page=1&per_page=5"
                else:
                    ep = f"{kurl}/s/{space}/api/detection_engine/rules/_find?page=1&per_page=5"
                print(f"      space '{space}' → {ep}")
                try:
                    r = _req.get(
                        ep,
                        headers={
                            "kbn-xsrf": "true",
                            "Authorization": f"ApiKey {token}",
                        },
                        verify=False, timeout=15,
                    )
                    if r.status_code == 200:
                        try:
                            j = r.json()
                            total = j.get("total", "?")
                            sample = [rr.get("name") for rr in (j.get("data") or [])[:3]]
                            print(f"        HTTP 200  Kibana total={total}  sample={sample}")
                            if total == 0:
                                print("        [WARN] Kibana says 0 rules — space empty or API key")
                                print("               lacks 'detections:read' privilege.")
                        except Exception:
                            print(f"        HTTP 200 (body not JSON): {r.text[:120]}")
                    elif r.status_code == 404 and space.lower() != "default":
                        print(f"        HTTP 404 — space '{space}' may not exist on this Kibana.")
                        try:
                            sp_r = _req.get(
                                f"{kurl}/api/spaces/space",
                                headers={"kbn-xsrf": "true", "Authorization": f"ApiKey {token}"},
                                verify=False, timeout=10,
                            )
                            if sp_r.status_code == 200:
                                real = sorted(s.get("id") for s in sp_r.json() if s.get("id"))
                                print(f"        Real spaces on this Kibana: {real}")
                                print(f"        [FIX] Update the mapping to use one of: {real}")
                        except Exception:
                            pass
                        any_fail = True
                    else:
                        print(f"        HTTP {r.status_code}: {r.text[:200]}")
                        any_fail = True
                except Exception as exc:
                    print(f"        [ERROR] {type(exc).__name__}: {exc}")
                    any_fail = True

            # ── Step 3b: fetch_detection_rules (no DB write, no field mapping) ──
            print(f"\n      fetch_detection_rules (check_mappings=False) ...")
            orig_cwd = os.getcwd()
            siem_df = None
            try:
                os.chdir(app_dir)
                import elastic_helper
                siem_df = elastic_helper.fetch_detection_rules(
                    kibana_url=kurl,
                    api_key=token,
                    spaces=spaces_sorted,
                    check_mappings=False,
                    elasticsearch_url=siem.get("elasticsearch_url"),
                )
            except Exception as exc:
                print(f"      [FAIL] fetch_detection_rules: {type(exc).__name__}: {exc}")
                any_fail = True
                continue
            finally:
                try:
                    os.chdir(orig_cwd)
                except Exception:
                    pass

            if siem_df is None or siem_df.empty:
                print("      [FAIL] fetch_detection_rules returned empty DataFrame.")
                print("             Kibana HTTP probe above shows the connection works;")
                print("             check for exceptions inside elastic_helper logged to tide.log.")
                any_fail = True
                continue

            print(f"      DataFrame rows: {len(siem_df)}")
            if "space_id" in siem_df.columns:
                sc = siem_df["space_id"].fillna("default").value_counts().to_dict()
                print(f"      rows per space_id: {sc}")
            else:
                print("      [WARN] 'space_id' column absent — rules will all land in space='default'.")

            cols = list(siem_df.columns)
            print(f"      DataFrame columns ({len(cols)}): {cols}")
            for must in ("rule_id", "space_id"):
                if must not in cols:
                    print(f"      [WARN] Missing expected column '{must}' — save_audit_results may drop rows.")
            # siem_id is absent here by design — sync.py stamps it after
            # fetch_detection_rules returns.  If it were present that would
            # indicate a regression in elastic_helper.
            if "siem_id" in cols:
                print("      [WARN] 'siem_id' present in DataFrame — elastic_helper now stamps it,")
                print("             which may conflict with the stamp in sync.py. Check for duplicates.")

        # ── Step 4: tenant DB current state ───────────────────────────────
        if os.path.exists(tenant_path):
            try:
                snap_dir = tempfile.mkdtemp(prefix="diag_t_")
                snap     = os.path.join(snap_dir, "t.duckdb")
                shutil.copy2(tenant_path, snap)
                tc = _ddb.connect(snap)
                try:
                    before = tc.execute("SELECT COUNT(*) FROM detection_rules").fetchone()[0]
                    sp_rows = tc.execute(
                        "SELECT space, siem_id, COUNT(*) c FROM detection_rules "
                        "GROUP BY space, siem_id ORDER BY space, siem_id"
                    ).fetchall()
                finally:
                    tc.close()
                shutil.rmtree(snap_dir, ignore_errors=True)
                print(f"\n    tenant DB ({db_filename}): {before} detection_rules rows")
                for sp, sid, cnt in sp_rows:
                    print(f"      space='{sp}' siem={sid[:8] if sid else 'NULL'}: {cnt} rows")
                if before == 0:
                    print("    [WARN] Tenant DB has 0 rules — sync has not yet written successfully.")
            except Exception as exc:
                print(f"\n    [FAIL] could not snapshot tenant DB: {exc}")

        if not any_fail:
            print(f"\n    [OK] All pipeline steps passed for '{name}'.")
            print(f"         Rules appear to reach save_audit_results.")
            print(f"         If the UI still shows 0 rules, check:")
            print(f"           a) Active client cookie set to {cid}")
            print(f"           b) /api/rules?... query includes the correct space filter")
            print(f"           c) Recent sync log lines in tide.log (section 6 above)")
        else:
            print(f"\n    [FAIL] Pipeline broken for '{name}' — fix items marked [STOP]/[FAIL] above.")


def _check_opencti_tenants(info: dict) -> None:
    """11. Per-tenant OpenCTI link state + threat_actors source split.

    Designed to catch the 4.1.x leak where OpenCTI-sourced rows ended up
    in the shared ``threat_actors`` table (because the sync writer ran
    without a tenant context) and consequently appeared in every tenant's
    Threat Landscape view. Also flags tenants whose only mapped OpenCTI
    instance has been deactivated, which is what made
    ``_client_has_opencti`` return True for tenants that no longer have an
    active link before the 4.1.19 fix.
    """
    _line("11. Per-tenant OpenCTI link state")
    if not info.get("db_read_ok"):
        print("  skipped: section 2 could not read the shared DB")
        return
    db_path = os.environ.get("TIDE_DB_PATH", "/app/data/tide.duckdb")
    data_dir = os.environ.get("TIDE_DATA_DIR", "/app/data")
    import duckdb
    import shutil
    import tempfile

    def _snapshot_open(path: str):
        snap_dir = tempfile.mkdtemp(prefix="diag_octi_")
        snap = os.path.join(snap_dir, "snap.duckdb")
        shutil.copy2(path, snap)
        wal = path + ".wal"
        if os.path.exists(wal):
            shutil.copy2(wal, snap + ".wal")
        return duckdb.connect(snap), snap_dir

    # Shared side: opencti_inventory, client_opencti_map, threat_actors.
    try:
        c, snap_dir = _snapshot_open(db_path)
    except Exception as exc:
        print(f"  could not snapshot shared DB: {exc}")
        return
    try:
        tables = {r[0] for r in c.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema='main'"
        ).fetchall()}
        if "opencti_inventory" not in tables:
            print("  opencti_inventory table missing -- OpenCTI feature not "
                  "yet provisioned on this DB.")
            return
        inv = c.execute(
            "SELECT id, label, COALESCE(is_active, TRUE) FROM opencti_inventory"
        ).fetchall()
        print(f"  opencti_inventory: {len(inv)} instance(s)")
        for oid, label, active in inv:
            print(f"     {oid[:8]} '{label}' active={active}")

        if "client_opencti_map" in tables:
            maps = c.execute(
                "SELECT m.client_id, m.opencti_id, "
                "COALESCE(o.is_active, TRUE) AS active, o.label "
                "FROM client_opencti_map m "
                "LEFT JOIN opencti_inventory o ON o.id = m.opencti_id"
            ).fetchall()
            print(f"  client_opencti_map rows: {len(maps)}")
            for cid, oid, active, lbl in maps:
                marker = "" if active else "  [STALE: instance is_active=FALSE]"
                print(f"     client={cid[:8]} opencti={oid[:8]} '{lbl}' "
                      f"active={active}{marker}")

        # Shared threat_actors source distribution.
        if "threat_actors" in tables:
            try:
                total = c.execute(
                    "SELECT COUNT(*) FROM threat_actors"
                ).fetchone()[0]
                # DuckDB rejects unnest() alongside GROUP BY in the same
                # SELECT; wrap it in a subquery instead.
                src_rows = c.execute(
                    "SELECT s, COUNT(*) FROM ("
                    "  SELECT unnest(source) AS s FROM threat_actors "
                    "  WHERE source IS NOT NULL"
                    ") GROUP BY s ORDER BY 2 DESC"
                ).fetchall()
                # OCTI-only = source array has at least one element and no
                # element starts with 'mitre' (case-insensitive).
                octi_only = c.execute(
                    "SELECT COUNT(*) FROM ("
                    "  SELECT name, list_filter(source, "
                    "    x -> LOWER(x) LIKE 'mitre%') AS mitre_tags, "
                    "    source "
                    "  FROM threat_actors WHERE source IS NOT NULL "
                    "    AND len(source) > 0"
                    ") WHERE len(mitre_tags) = 0 "
                    "  AND list_contains(list_transform(source, "
                    "    x -> UPPER(x)), 'OCTI')"
                ).fetchone()[0]
                print(f"  SHARED threat_actors: total={total}, "
                      f"OCTI-only (no MITRE marker) rows={octi_only}")
                if octi_only > 0:
                    print("    [LEAK] OCTI-only rows in shared DB leak into "
                          "every tenant's Threat Landscape. Run "
                          "`docker exec tide-app python -m "
                          "app.scripts.repair_octi_source_markers` to clean.")
                for s, n in src_rows[:10]:
                    print(f"     source={s!r}: {n}")
            except Exception as exc:
                print(f"  shared threat_actors source query failed: {exc}")
    finally:
        try:
            c.close()
        except Exception:
            pass
        shutil.rmtree(snap_dir, ignore_errors=True)

    # Per-tenant side: open each tenant snapshot and report actor counts +
    # whether OCTI rows live in the tenant DB (the post-4.1.5 contract).
    clients = info.get("clients") or []
    for cid, name, fn in clients:
        if not fn:
            continue
        path = os.path.join(data_dir, fn)
        if not os.path.exists(path):
            continue
        try:
            tc, tsnap = _snapshot_open(path)
        except Exception as exc:
            print(f"  tenant {cid[:8]} '{name}': snapshot failed: {exc}")
            continue
        try:
            try:
                total = tc.execute(
                    "SELECT COUNT(*) FROM threat_actors"
                ).fetchone()[0]
                octi = tc.execute(
                    "SELECT COUNT(*) FROM threat_actors "
                    "WHERE source IS NOT NULL "
                    "AND list_contains("
                    "  list_transform(source, x -> UPPER(x)), 'OCTI'"
                    ")"
                ).fetchone()[0]
                print(f"  tenant {cid[:8]} '{name}': "
                      f"threat_actors={total} (OCTI={octi})")
            except Exception:
                print(f"  tenant {cid[:8]} '{name}': threat_actors table missing")
        finally:
            try:
                tc.close()
            except Exception:
                pass
            shutil.rmtree(tsnap, ignore_errors=True)


def _check_cti_dbs(info: dict) -> None:
    """Section 12 — per-tenant CTI DB state (Native CTI Engine, Phase 1).

    Reports whether each tenant has a ``cti_<slug>_<short_id>.duckdb``
    file alongside its rule DB, what schema version it is on, and the
    row counts for the core CTI tables. Pure read; never creates files.
    """
    _line("12. Per-tenant CTI DB state (Native CTI Engine)")
    if not info.get("db_read_ok"):
        print("  skipped: section 2 could not read the shared DB")
        return
    clients = info.get("clients") or []
    if not clients:
        print("  no clients registered.")
        return
    try:
        from app.services.cti_database import cti_db_stats
    except Exception as exc:
        print(f"  cti_database import failed: {exc}")
        return
    any_present = False
    for cid, name, _fn in clients:
        try:
            stats = cti_db_stats(cid)
        except Exception as exc:
            print(f"  tenant {cid[:8]} '{name}': stats failed: {exc}")
            continue
        if not stats.get("exists"):
            print(f"  tenant {cid[:8]} '{name}': no CTI DB yet "
                  f"(would create at {stats['path']})")
            continue
        any_present = True
        print(
            f"  tenant {cid[:8]} '{name}': schema_v{stats['schema_version']} "
            f"indicators={stats['indicators']} "
            f"actors={stats.get('actors', 0)} "
            f"reports={stats.get('reports', 0)} "
            f"relationships={stats.get('relationships', 0)} "
            f"egress_targets={stats['egress_targets']}"
        )
    if not any_present:
        print("  (no tenant has run a CTI sync yet)")


def _check_taxii_cursors(info: dict) -> None:
    """Section 13 — TAXII 2.1 delta-cursor state.

    Reports per-(connector, api_root, collection) ``added_after``
    watermarks captured from upstream ``X-TAXII-Date-Added-Last``
    response headers. Built by the generic TAXII client and used to
    make repeat syncs delta-only. A connector with no cursor row means
    "never synced via TAXII yet".

    Opens its own read-only snapshot of the shared DB so it never has
    to fight the live writer for the file lock.
    """
    _line("13. TAXII 2.1 delta cursors")
    if not info.get("db_read_ok"):
        print("  skipped: section 2 could not read the shared DB")
        return
    db_path = info.get("db_path") or "/app/data/tide.duckdb"
    if not os.path.exists(db_path):
        print(f"  skipped: shared DB missing at {db_path}")
        return
    import shutil
    import tempfile
    import duckdb as _ddb
    snap_dir = None
    try:
        snap_dir = tempfile.mkdtemp(prefix="diag_taxii_")
        snap = os.path.join(snap_dir, "snap.duckdb")
        shutil.copy2(db_path, snap)
        wal = db_path + ".wal"
        if os.path.exists(wal):
            shutil.copy2(wal, snap + ".wal")
        c = _ddb.connect(snap)
    except Exception as exc:
        print(f"  could not snapshot shared DB: {exc}")
        if snap_dir:
            shutil.rmtree(snap_dir, ignore_errors=True)
        return
    try:
        tables = {r[0] for r in c.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema='main'"
        ).fetchall()}
        if "cti_taxii_cursors" not in tables:
            print("  cti_taxii_cursors table not present "
                  "(schema < v49 — no TAXII connectors run yet).")
            return
        rows = c.execute(
            "SELECT connector_id, api_root, collection_id, "
            "added_after, last_run_at FROM cti_taxii_cursors "
            "ORDER BY last_run_at DESC NULLS LAST"
        ).fetchall()
        if not rows:
            print("  no TAXII cursors recorded yet.")
            return
        label_by_id: dict[str, str] = {}
        if "cti_connectors" in tables:
            try:
                for cid, vendor, label in c.execute(
                    "SELECT id, vendor, label FROM cti_connectors"
                ).fetchall():
                    label_by_id[cid] = f"{vendor}/{label}"
            except Exception:
                pass
        for connector_id, api_root, coll, added_after, last_run in rows:
            label = label_by_id.get(connector_id, connector_id[:8])
            print(
                f"  {label} root={api_root} "
                f"collection={coll} "
                f"added_after={added_after} "
                f"last_run={last_run}"
            )
    except Exception as exc:
        print(f"  ERROR reading cursors: {exc}")
    finally:
        try:
            c.close()
        except Exception:
            pass
        if snap_dir:
            shutil.rmtree(snap_dir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════════
# State sections 14-19 (troubleshooting snapshot of the whole standalone app)
# ═══════════════════════════════════════════════════════════════════════════
# These read local files and the local databases only. They never call the
# internet, Kibana or Elasticsearch, and never write to a live database:
# every database is read from a private snapshot copy (DuckDB allows only one
# process on a file, and the app holds it). Findings are collected and repeated
# in the summary at the end.

_FINDINGS: list[tuple[str, str]] = []
_SNAPS: dict[str, tuple] = {}


def _emit(level: str, msg: str) -> None:
    print(f"  [{level:<4}] {msg}")
    if level in ("WARN", "FAIL"):
        _FINDINGS.append((level, msg))


def _ok(msg: str) -> None:
    _emit("OK", msg)


def _info(msg: str) -> None:
    _emit("INFO", msg)


def _warn(msg: str) -> None:
    _emit("WARN", msg)


def _fail(msg: str) -> None:
    _emit("FAIL", msg)


def _human(n: float) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def _data_dir() -> str:
    return os.environ.get("TIDE_DATA_DIR", "/app/data")


def _shared_path() -> str:
    return os.environ.get("TIDE_DB_PATH", os.path.join(_data_dir(), "tide.duckdb"))


def _settings():
    try:
        from app.config import get_settings
        return get_settings()
    except Exception:
        return None


def _cleanup_snapshots() -> None:
    import shutil
    for conn, snap_dir in list(_SNAPS.values()):
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass
        if snap_dir:
            shutil.rmtree(snap_dir, ignore_errors=True)
    _SNAPS.clear()


def _snapshot(path: str):
    """One private, writable copy of a database file per run (cached). None if unavailable.

    Opened read-write on purpose: a database with a pending WAL needs to replay it, which a
    read-only open cannot do. The copy is private, so the live file is never touched.
    """
    import shutil
    import tempfile
    if path in _SNAPS:
        return _SNAPS[path][0]
    if not os.path.exists(path):
        return None
    import duckdb
    size = os.path.getsize(path)
    if size > 200 * 1024 * 1024:
        print(f"  (copying {_human(size)} snapshot of {os.path.basename(path)} ...)")
    last_err = None
    for root in (None, os.path.dirname(path)):
        snap_dir = None
        try:
            snap_dir = tempfile.mkdtemp(prefix="diag_state_", dir=root)
            snap = os.path.join(snap_dir, "snap.duckdb")
            shutil.copy2(path, snap)
            if os.path.exists(path + ".wal"):
                shutil.copy2(path + ".wal", snap + ".wal")
            conn = duckdb.connect(snap)
            _SNAPS[path] = (conn, snap_dir)
            return conn
        except Exception as exc:                      # noqa: BLE001 - try the next location, then report
            last_err = exc
            if snap_dir:
                shutil.rmtree(snap_dir, ignore_errors=True)
    _fail(f"cannot read {os.path.basename(path)}: {last_err}")
    _SNAPS[path] = (None, None)
    return None


def _rows(conn, sql: str, params=None):
    try:
        return conn.execute(sql, params or []).fetchall()
    except Exception:
        return None


def _one(conn, sql: str, params=None):
    r = _rows(conn, sql, params)
    return r[0][0] if r else None


def _tables(conn) -> list[str]:
    return [r[0] for r in (_rows(conn, "SELECT table_name FROM information_schema.tables "
                                       "WHERE table_schema='main' ORDER BY 1") or [])]


def _age(ts) -> str:
    """'3 h ago' for a datetime / ISO string, '?' when unreadable."""
    from datetime import datetime, timezone
    try:
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if ts.tzinfo is not None:
            ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
        secs = max(0, int((datetime.now(timezone.utc).replace(tzinfo=None) - ts).total_seconds()))
    except Exception:
        return "?"
    if secs < 90:
        return "just now"
    if secs < 5400:
        return f"{secs // 60} min ago"
    if secs < 172800:
        return f"{secs // 3600} h ago"
    return f"{secs // 86400} days ago"


def _wrap(items: list[str], indent: str = "    ", width: int = 100) -> None:
    line = indent
    for item in items:
        if len(line) + len(item) + 2 > width and line.strip():
            print(line.rstrip(", "))
            line = indent
        line += item + ", "
    if line.strip():
        print(line.rstrip(", "))


def _clients(shared) -> list[tuple]:
    return _rows(shared, "SELECT id, name, db_filename FROM clients ORDER BY name") or []


def _tenant_conn(cid_row):
    cid, name, fn = cid_row
    if not fn:
        return None
    return _snapshot(os.path.join(_data_dir(), fn))


def _check_app_host() -> None:
    _line("14. App & host state")
    import platform
    import shutil
    from datetime import datetime, timezone
    try:
        with open("/app/VERSION") as f:
            file_version = f.read().strip()
    except Exception:
        file_version = "<unknown>"
    st = _settings()
    print(f"  version file      : {file_version}")
    if st is not None and getattr(st, "tide_version", file_version) != file_version:
        _warn(f"settings report version {st.tide_version} but the VERSION file says {file_version}")
    print(f"  python            : {platform.python_version()} on {platform.platform()}")
    try:
        import importlib.metadata as md
        libs = []
        for lib in ("duckdb", "fastapi", "uvicorn", "jinja2", "pandas", "requests"):
            try:
                libs.append(f"{lib} {md.version(lib)}")
            except Exception:
                libs.append(f"{lib} ?")
        print(f"  libraries         : {', '.join(libs)}")
    except Exception:
        pass

    # process / container uptime (PID 1 start time)
    try:
        with open("/proc/1/stat") as f:
            fields = f.read().rsplit(")", 1)[1].split()
        ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
        with open("/proc/stat") as f:
            btime = next(int(l.split()[1]) for l in f if l.startswith("btime"))
        started = datetime.fromtimestamp(btime + int(fields[19]) / ticks, timezone.utc).replace(tzinfo=None)
        print(f"  app process start : {started:%Y-%m-%d %H:%M} UTC ({_age(started)})")
    except Exception:
        print("  app process start : <unavailable>")

    # memory (cgroup v2, then v1)
    used = limit = None
    for used_p, limit_p in (("/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory.max"),
                            ("/sys/fs/cgroup/memory/memory.usage_in_bytes", "/sys/fs/cgroup/memory/memory.limit_in_bytes")):
        try:
            used = int(open(used_p).read().strip())
            raw = open(limit_p).read().strip()
            limit = int(raw) if raw.isdigit() and int(raw) < 1 << 60 else None
            break
        except Exception:
            continue
    if used is not None:
        text = f"memory            : {_human(used)} used" + (f" of {_human(limit)} limit" if limit else " (no container limit)")
        print("  " + text)
        if limit and used / limit > 0.85:
            _warn(f"container memory is {used * 100 // limit}% of its limit")
    print(f"  cpus              : {os.cpu_count()}")

    data_dir = _data_dir()
    try:
        du = shutil.disk_usage(data_dir)
        pct = du.used * 100 // du.total
        print(f"  data disk         : {_human(du.free)} free of {_human(du.total)} ({pct}% used) at {data_dir}")
        if du.free < 2 * 1024 ** 3 or du.free / du.total < 0.05:
            _warn(f"only {_human(du.free)} free on the data disk; DuckDB checkpoints and snapshots need headroom")
    except Exception as exc:
        print(f"  data disk         : <unavailable: {exc}>")

    # configuration that changes how the app behaves (values of secrets are never printed)
    if st is not None:
        if getattr(st, "auth_disabled", False):
            _warn("AUTH_DISABLED is true: authentication is OFF (fine for tests, never for a live system)")
        else:
            _ok("authentication is enabled")
        if getattr(st, "debug", False):
            _warn("debug mode is on")
        if str(getattr(st, "session_secret", "")).startswith("change-me"):
            _warn("session_secret is still the placeholder; set a random SESSION_SECRET")
        if str(getattr(st, "bootstrap_admin_password", "")) in ("TIDEadmin", "admin", ""):
            _warn("the bootstrap admin password is still the default; change it or remove the bootstrap admin")
        if not getattr(st, "ssl_verify", True):
            _info("TLS verification for outbound calls is off (ssl_verify=false)")
        print(f"  app url           : {getattr(st, 'app_url', '?')}")
    for key in ("TIDE_ISOLATION_STRICT", "TIDE_LOG_LEVEL", "TIDE_LOG_FILE"):
        if os.environ.get(key):
            print(f"  {key:<18}: {os.environ[key]}")

    log_dir = os.path.join(data_dir, "log")
    log_file = os.environ.get("TIDE_LOG_FILE") or os.path.join(log_dir, "tide.log")
    if os.path.exists(log_file):
        size = os.path.getsize(log_file)
        print(f"  app log           : {log_file} ({_human(size)}, last written {_age(datetime.fromtimestamp(os.path.getmtime(log_file), timezone.utc))})")
        if size > 500 * 1024 * 1024:
            _warn(f"the app log is {_human(size)}; check log rotation")
    else:
        print(f"  app log           : {log_file} (not found)")


def _check_database_files() -> None:
    _line("15. Database files")
    data_dir = _data_dir()
    if not os.path.isdir(data_dir):
        _fail(f"data directory {data_dir} not found")
        return
    shared_path = _shared_path()
    shared = _snapshot(shared_path)
    tenant_files = {}
    cti_like = set()
    if shared is not None:
        for cid, name, fn in _clients(shared):
            if fn:
                tenant_files[os.path.join(data_dir, fn)] = f"tenant '{name}'"
                cti_like.add(os.path.join(data_dir, f"cti_{fn}"))
    files = sorted(f for f in os.listdir(data_dir) if f.endswith(".duckdb"))
    if not files:
        _fail("no .duckdb files found in the data directory")
    for f in files:
        path = os.path.join(data_dir, f)
        kind = ("shared" if os.path.abspath(path) == os.path.abspath(shared_path)
                else tenant_files.get(path) or ("CTI" if f.startswith("cti_") else "unrecognised"))
        size = os.path.getsize(path)
        wal = os.path.getsize(path + ".wal") if os.path.exists(path + ".wal") else 0
        print(f"\n  {f}   [{kind}]   file {_human(size)}" + (f", WAL {_human(wal)}" if wal else ""))
        if wal > 64 * 1024 * 1024:
            _warn(f"{f}: WAL is {_human(wal)}; the app has not checkpointed (was it stopped uncleanly?)")
        conn = _snapshot(path)
        if conn is None:
            continue
        sizes = _rows(conn, "PRAGMA database_size")
        if sizes:
            _n, _sz, block, total, used, free, *_rest = sizes[0]
            live = used * block
            reclaim = min(free * block, max(0, size - live))
            free_pct = reclaim * 100 // size if size else 0
            print(f"    in use {_human(live)}, empty space inside the file {_human(reclaim)} ({free_pct}%)")
            if size > 200 * 1024 * 1024 and free_pct >= 35:
                _warn(f"{f}: {free_pct}% of the {_human(size)} file is empty space. Compaction would reclaim about "
                      f"{_human(reclaim)} (stop tide-app, then run python -m app.scripts.compact_duckdb {path} --apply)")
        tables = _tables(conn)
        counts = {}
        for t in tables:
            n = _one(conn, f'SELECT count(*) FROM "{t}"')
            counts[t] = n if n is not None else -1
        filled = sorted(((t, n) for t, n in counts.items() if n > 0), key=lambda x: -x[1])
        empty = [t for t, n in counts.items() if n == 0]
        print(f"    {len(tables)} tables, {len(filled)} with data:")
        _wrap([f"{t}={n:,}" for t, n in filled])
        if empty:
            print(f"    empty: {', '.join(empty)[:300]}")

    # leftovers that take space or record past trouble
    leftovers = [f for f in sorted(os.listdir(data_dir))
                 if any(m in f for m in (".pre-", "backup", ".bak", ".corrupt-"))]
    print()
    if leftovers:
        total = sum(os.path.getsize(os.path.join(data_dir, f)) for f in leftovers)
        print("  backups and quarantined files:")
        for f in leftovers:
            print(f"    {_human(os.path.getsize(os.path.join(data_dir, f))):>9}  {f}")
        corrupt = [f for f in leftovers if ".corrupt-" in f]
        if corrupt:
            _warn(f"{len(corrupt)} quarantined WAL file(s) ({', '.join(corrupt)}): the database was stopped uncleanly at some point")
        if total > 500 * 1024 * 1024:
            _warn(f"{_human(total)} of backup files sit in the data directory; delete the ones you no longer need")
    else:
        _ok("no leftover backup or quarantined files")


def _check_rules_state() -> None:
    _line("16. Rules & scoring state (per tenant)")
    import json
    shared = _snapshot(_shared_path())
    if shared is None:
        _fail("shared database unreadable; cannot list tenants")
        return
    try:
        from app import scoring
        current_keys = set(scoring.DEFAULT_WEIGHTS)
        model_version = scoring.SCORING_VERSION
    except Exception:
        current_keys, model_version = set(), None
    siem_labels = {r[0]: r[1] for r in (_rows(shared, "SELECT id, label FROM siem_inventory") or [])}
    weights = {r[0]: r for r in (_rows(shared, "SELECT client_id, weights_json, updated_at, updated_by FROM client_scoring_weights") or [])}

    for row in _clients(shared):
        cid, name, fn = row
        print(f"\n  tenant '{name}' ({cid[:8]})")
        conn = _tenant_conn(row)
        if conn is None:
            _warn(f"tenant '{name}' has no readable database" + ("" if fn else " (db_filename not set)"))
            continue
        if "detection_rules" not in _tables(conn):
            _warn(f"tenant '{name}': no detection_rules table")
            continue
        total = _one(conn, "SELECT count(*) FROM detection_rules") or 0
        enabled = _one(conn, "SELECT count(*) FROM detection_rules WHERE enabled = 1") or 0
        deprecated = _one(conn, "SELECT count(*) FROM detection_rules WHERE deprecated") or 0
        print(f"    rules: {total:,} ({enabled:,} enabled, {total - enabled:,} disabled, {deprecated:,} marked deprecated)")
        if total == 0:
            _info(f"tenant '{name}' has no rules cached; run a sync if it should have some")
            continue
        for siem_id, space, n, en in _rows(conn, "SELECT siem_id, space, count(*), sum(CASE WHEN enabled=1 THEN 1 ELSE 0 END) "
                                                 "FROM detection_rules GROUP BY 1, 2 ORDER BY 3 DESC") or []:
            print(f"      {siem_labels.get(siem_id, siem_id[:8])} / {space}: {n:,} rules ({en or 0:,} enabled)")
        langs = _rows(conn, "SELECT coalesce(json_extract_string(raw_data, '$.language'), '?'), count(*) FROM detection_rules GROUP BY 1 ORDER BY 2 DESC") or []
        print("    languages: " + ", ".join(f"{l}={n:,}" for l, n in langs))

        newest, oldest = _one(conn, "SELECT max(last_updated) FROM detection_rules"), _one(conn, "SELECT min(last_updated) FROM detection_rules")
        print(f"    last synced: {newest} ({_age(newest)}); oldest rule row {_age(oldest)}")
        if newest and _age(newest).endswith("days ago") and int(_age(newest).split()[0]) >= 7:
            _warn(f"tenant '{name}': rules were last synced {_age(newest)}")

        # scoring: model version, distribution, weakest checks
        detail_rows = _rows(conn, "SELECT score, raw_data->'score_detail', coalesce(deprecated, false) FROM detection_rules") or []
        versions, buckets, scores = {}, [0] * 5, []
        comp_fracs: dict[str, list] = {}
        comp_na: dict[str, int] = {}
        comp_label: dict[str, str] = {}
        no_detail = stale_keys = no_detail_deprecated = 0
        for score, detail, is_deprecated in detail_rows:
            scores.append(score or 0)
            buckets[min(4, (score or 0) // 20)] += 1
            try:
                d = json.loads(detail) if isinstance(detail, str) else detail
            except Exception:
                d = None
            if not d or not d.get("components"):
                if is_deprecated:
                    no_detail_deprecated += 1
                else:
                    no_detail += 1
                continue
            versions[d.get("version", 1)] = versions.get(d.get("version", 1), 0) + 1
            keys = {c.get("key") for c in d["components"]}
            if current_keys and not current_keys <= keys:
                stale_keys += 1
            for c in d["components"]:
                k = c.get("key")
                comp_label[k] = c.get("label", k)
                if not c.get("max"):
                    continue
                if c.get("fraction") is None:
                    comp_na[k] = comp_na.get(k, 0) + 1
                else:
                    comp_fracs.setdefault(k, []).append(c["fraction"])
        avg = sum(scores) / len(scores) if scores else 0
        print(f"    score: average {avg:.0f}%; " + ", ".join(f"{i * 20}-{i * 20 + 19 if i < 4 else 100}%={n}" for i, n in enumerate(buckets)))
        print("    scoring model: " + (", ".join(f"v{v}={n:,}" for v, n in sorted(versions.items())) or "none stored")
              + (f" (current is v{model_version})" if model_version else ""))
        if no_detail:
            _warn(f"tenant '{name}': {no_detail:,} rules have no score detail (scored before model v2); run a sync")
        if no_detail_deprecated:
            _info(f"tenant '{name}': {no_detail_deprecated:,} deprecated rule(s) keep their old score (deprecated rules are not re-scored)")
        if stale_keys:
            _warn(f"tenant '{name}': {stale_keys:,} rules were scored before the current set of checks existed; they pick up new weights at the next sync")
        old_versions = [v for v in versions if model_version and v < model_version]
        if old_versions:
            _warn(f"tenant '{name}': some rules still carry an older scoring model ({old_versions}); run a sync")
        if comp_fracs:
            print("    checks with points (average result over rules that could be judged):")
            for k, fr in sorted(comp_fracs.items(), key=lambda kv: sum(kv[1]) / len(kv[1])):
                na = comp_na.get(k, 0)
                print(f"      {comp_label[k]:<22} {sum(fr) / len(fr) * 100:5.0f}%   " + (f"n/a for {na:,} rules" if na else ""))
            for k, na in comp_na.items():
                if k == "mapping" and na:
                    _warn(f"tenant '{name}': {na:,} rules could not be mapping-checked (no fields extracted or the SIEM was unreachable)")

        w = weights.get(cid)
        if w:
            try:
                custom = json.loads(w[1])
                changed = {k: v for k, v in custom.items() if scoring.DEFAULT_WEIGHTS.get(k) != v}
                print(f"    scoring weights: custom, set {_age(w[2])} by {w[3] or '?'}; differs from default: "
                      + (", ".join(f"{k}={v}" for k, v in changed.items()) or "nothing (same as default)"))
            except Exception:
                print("    scoring weights: custom (unreadable)")
        else:
            print("    scoring weights: defaults")

        # history and derived tables
        tabs = set(_tables(conn))
        if "rule_score_history" in tabs:
            n = _one(conn, "SELECT count(*) FROM rule_score_history") or 0
            latest = _one(conn, "SELECT max(created_at) FROM rule_score_history")
            per_rule = n / total if total else 0
            orphans = _one(conn, "SELECT count(*) FROM rule_score_history h WHERE NOT EXISTS (SELECT 1 FROM detection_rules r "
                                 "WHERE r.rule_id = h.rule_id AND r.siem_id = h.siem_id AND r.space = h.space)") or 0
            print(f"    score history: {n:,} snapshots ({per_rule:.0f} per rule), latest {_age(latest)}")
            if per_rule > 40:
                _warn(f"tenant '{name}': score history averages {per_rule:.0f} snapshots per rule (file bloat; dedupe_rule_score_history can trim it)")
            if orphans:
                _warn(f"tenant '{name}': {orphans:,} score-history rows belong to rules that no longer exist")
        if "rule_lifecycle_history" in tabs:
            n = _one(conn, "SELECT count(*) FROM rule_lifecycle_history") or 0
            latest = _one(conn, "SELECT max(created_at) FROM rule_lifecycle_history")
            print(f"    lifecycle history: {n:,} events, latest {_age(latest)}")
        if "rule_search_time_samples" in tabs:
            n = _one(conn, "SELECT count(*) FROM rule_search_time_samples") or 0
            print(f"    search-time samples: {n:,}" + ("" if n else " (no rule execution durations seen yet: search time is n/a)"))
        if "checkedRule" in tabs:
            print(f"    validated rules: {_one(conn, 'SELECT count(*) FROM checkedRule') or 0:,}")
        if "rule_migrations" in tabs:
            print(f"    rule migrations (staging -> production links): {_one(conn, 'SELECT count(*) FROM rule_migrations') or 0:,}")
        dupes = _one(conn, "SELECT count(*) FROM (SELECT 1 FROM detection_rules GROUP BY siem_id, space, name HAVING count(*) > 1)") or 0
        if dupes:
            _warn(f"tenant '{name}': {dupes:,} rule name(s) appear more than once in the same SIEM/space")


def _check_sync_reference_state() -> None:
    _line("17. Sync, SIEM links, field catalogue & reference tables")
    shared = _snapshot(_shared_path())
    if shared is None:
        _fail("shared database unreadable")
        return
    tabs = set(_tables(shared))

    if "sync_history" in tabs:
        print("  recorded background syncs (reference data; rule syncs are timed in section 16):")
        rows = _rows(shared, "SELECT sync_kind, status, started_at, duration_ms, total_count, error FROM sync_history ORDER BY started_at DESC LIMIT 5") or []
        for kind, status, started, ms, count, error in rows:
            print(f"    {started}  {kind:<14} {status:<10} {(ms or 0) / 1000:5.1f}s  {count if count is not None else '-'} items"
                  + (f"  error: {str(error)[:100]}" if error else ""))
        if not rows:
            _info("no sync has been recorded yet")
        elif str(rows[0][1]).lower() not in ("ok", "success", "succeeded", "completed", "complete"):
            _warn(f"the latest recorded sync ended with status '{rows[0][1]}'" + (f": {str(rows[0][5])[:120]}" if rows[0][5] else ""))
    else:
        print("  (no sync_history table)")

    print("\n  SIEMs and their last connection test:")
    labels = {}
    for sid, label, kind, active, tstatus, tat, tmsg in _rows(
            shared, "SELECT id, label, siem_type, is_active, last_test_status, last_test_at, last_test_message FROM siem_inventory") or []:
        labels[sid] = label
        good = str(tstatus or "").lower() in ("ok", "pass", "passed", "success", "succeeded")
        print(f"    {label} ({kind}) active={active} last test: {tstatus or 'never'} {(_age(tat) if tat else '')}"
              + (f" - {str(tmsg)[:80]}" if tmsg and not good else ""))
        if active and tstatus and not good:
            _warn(f"SIEM '{label}': the last connection test reported '{tstatus}'")
        elif active and not tstatus:
            _info(f"SIEM '{label}' has never had a connection test (Management > SIEMs > Test)")

    if "siem_field_catalogue" in tabs:
        print("\n  field catalogue (index mappings remembered per SIEM):")
        cat = _rows(shared, "SELECT siem_id, count(*), sum(CASE WHEN status='ok' THEN 1 ELSE 0 END), sum(CASE WHEN status='no_indices' THEN 1 ELSE 0 END), "
                            "sum(field_count), min(fetched_at), max(fetched_at), "
                            "sum(CASE WHEN fetched_at < now() - INTERVAL 24 HOUR THEN 1 ELSE 0 END), "
                            "sum(CASE WHEN last_error IS NOT NULL THEN 1 ELSE 0 END) FROM siem_field_catalogue GROUP BY 1") or []
        if not cat:
            _info("the field catalogue is empty; it fills on the next sync")
        for sid, n, ok, empty, fields, oldest, newest, stale, errs in cat:
            print(f"    {labels.get(sid, sid[:8])}: {n} index patterns ({ok} mapped, {empty} match no indices), "
                  f"{fields or 0:,} fields, refreshed {_age(newest)} (oldest {_age(oldest)})")
            if stale:
                _info(f"catalogue for '{labels.get(sid, sid[:8])}': {stale} pattern(s) are older than 24 h and refresh at the next sync")
            if errs:
                _warn(f"catalogue for '{labels.get(sid, sid[:8])}': {errs} pattern(s) could not be refreshed (the previous entry is kept)")
                for pat, msg in _rows(shared, "SELECT pattern, last_error FROM siem_field_catalogue WHERE siem_id = ? AND last_error IS NOT NULL LIMIT 5", [sid]) or []:
                    print(f"      {pat}: {str(msg)[:100]}")
            if n and empty * 2 > n:
                _info(f"{empty} of {n} index patterns match no indices in '{labels.get(sid, sid[:8])}', so rules using only those "
                      f"score 0 for mapping (normal for a lab without data)")
            if empty:
                print("      patterns matching no indices: " + ", ".join(
                    r[0] for r in _rows(shared, "SELECT pattern FROM siem_field_catalogue WHERE siem_id = ? AND status='no_indices' ORDER BY 1 LIMIT 8", [sid]) or []))

    print("\n  reference data (reference.duckdb, built into the image):")
    st = _settings()
    ref_path = getattr(st, "reference_db_path", "/opt/reference/reference.duckdb") if st else "/opt/reference/reference.duckdb"
    if not os.path.exists(ref_path):
        _fail(f"{ref_path} is missing; ATT&CK, NIST and Sigma data are unavailable (check startup logs)")
    else:
        import duckdb
        ref = duckdb.connect(ref_path, read_only=True)
        try:
            for t in ("mitre_techniques", "mitre_groups", "nist_capabilities", "sigma_rules_index"):
                n = _one(ref, f'SELECT count(*) FROM "{t}"')
                print(f"    {t}: {'<missing>' if n is None else f'{n:,}'}")
                if not n:
                    _warn(f"{t} is empty; bundled reference data did not load (check startup logs)")
            built = _one(ref, "SELECT max(updated_at) FROM reference_meta")
            print(f"    built {_age(built) if built else '?'}")
        finally:
            ref.close()
    legacy = [t for t in ("mitre_techniques", "mitre_groups", "nist_capabilities", "sigma_rules_index") if t in tabs]
    if legacy:
        _warn(f"shared DB still holds legacy copies of {', '.join(legacy)}; they are dropped on the next start")

    if "cti_connectors" in tabs:
        rows = _rows(shared, "SELECT vendor, label, is_active, last_status, last_run_at FROM cti_connectors") or []
        print(f"\n  CTI connectors: {len(rows)}")
        for vendor, label, active, status, last in rows:
            print(f"    {vendor}/{label} active={active} last run {_age(last) if last else 'never'} status={status or '-'}")
            if active and status and str(status).lower() not in ("ok", "success", "succeeded"):
                _warn(f"CTI connector {vendor}/{label}: last status '{status}'")


def _check_users_tenants() -> None:
    _line("18. Users, tenants & authentication")
    import socket
    from urllib.parse import urlparse
    shared = _snapshot(_shared_path())
    if shared is None:
        _fail("shared database unreadable")
        return
    total = _one(shared, "SELECT count(*) FROM users") or 0
    active = _one(shared, "SELECT count(*) FROM users WHERE is_active") or 0
    admins = _one(shared, "SELECT count(*) FROM users WHERE is_superadmin") or 0
    never = _one(shared, "SELECT count(*) FROM users WHERE last_login IS NULL") or 0
    providers = _rows(shared, "SELECT coalesce(auth_provider, '?'), count(*) FROM users GROUP BY 1 ORDER BY 2 DESC") or []
    last = _one(shared, "SELECT max(last_login) FROM users")
    print(f"  users: {total} ({active} active, {admins} superadmin, {never} never signed in); last sign-in {_age(last) if last else 'never'}")
    print("  sign-in method: " + ", ".join(f"{p}={n}" for p, n in providers))
    if admins == 0:
        _warn("no superadmin exists; nobody can manage tenants or SIEMs")
    if active == 0:
        _fail("no active users")

    print("\n  tenants:")
    for cid, name, fn in _clients(shared):
        users = _one(shared, "SELECT count(*) FROM user_clients WHERE client_id = ?", [cid]) or 0
        links = _one(shared, "SELECT count(*) FROM client_siem_map WHERE client_id = ?", [cid]) or 0
        exists = bool(fn) and os.path.exists(os.path.join(_data_dir(), fn))
        print(f"    {name} ({cid[:8]}): {users} users, {links} SIEM link(s), database {'present' if exists else 'MISSING'}")
        if not exists:
            _fail(f"tenant '{name}' has no database file ({fn or 'db_filename not set'})")
        if links == 0:
            _info(f"tenant '{name}' has no SIEM linked, so it cannot sync rules")
        if users == 0:
            _info(f"tenant '{name}' has no users assigned")
    print(f"\n  roles: {_one(shared, 'SELECT count(*) FROM roles') or 0}, role permission rows: {_one(shared, 'SELECT count(*) FROM role_permissions') or 0}")

    st = _settings()
    kc_users = sum(n for p, n in providers if "keycloak" in str(p).lower() or "sso" in str(p).lower())
    if st is not None and getattr(st, "keycloak_url", ""):
        parsed = urlparse(st.keycloak_url)
        host, port = parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            with socket.create_connection((host, port), timeout=3):
                _ok(f"Keycloak reachable at {host}:{port}")
        except Exception as exc:
            (_warn if kc_users else _info)(f"Keycloak not reachable at {host}:{port} ({type(exc).__name__}); "
                                            + ("SSO users cannot sign in, local-password users still can" if kc_users else "only matters if SSO is used"))


def _count_files(root: str, suffix: str, limit: int = 100000) -> int:
    n = 0
    for _dir, _dirs, files in os.walk(root):
        n += sum(1 for f in files if f.endswith(suffix))
        if n > limit:
            break
    return n


def _check_bundled_data() -> None:
    _line("19. Bundled reference data (standalone: nothing here is downloaded at run time)")
    st = _settings()
    if st is None:
        _fail("settings could not be loaded")
        return
    shared = _snapshot(_shared_path())
    for label, attr, suffix in (("Sigma rules", "sigma_repo_path", ".yml"), ("MITRE ATT&CK", "mitre_repo_path", ".json"),
                                ("CISA KEV", "cisa_kev_path", None), ("ATT&CK-to-CVE mapping", "mitre_cve_path", None),
                                ("NVD cache", "nvd_cache_path", None)):
        path = getattr(st, attr, None)
        if not path or not os.path.exists(path):
            _warn(f"{label}: {path or 'no path configured'} not found")
            continue
        if os.path.isdir(path):
            # the Sigma search index is built from <repo>/rules only
            count_root = os.path.join(path, "rules") if attr == "sigma_repo_path" and os.path.isdir(os.path.join(path, "rules")) else path
            n = _count_files(count_root, suffix) if suffix else sum(len(f) for _d, _s, f in os.walk(path))
            where = "in rules/" if count_root != path else "in total"
            kind = f"{suffix} " if suffix else ""
            print(f"  {label:<24} {path}  ({n:,} {kind}files {where})")
            if n == 0:
                (_info if attr == "nvd_cache_path" else _warn)(
                    f"{label}: {path} exists but holds no data files" + (" (CVE data is not preloaded in this image)" if attr == "nvd_cache_path" else ""))
            if attr == "sigma_repo_path" and shared is not None:
                indexed = _one(shared, "SELECT count(*) FROM sigma_rules_index")
                if indexed is not None:
                    print(f"  {'':<24} search index holds {indexed:,} rules")
                    if n and indexed and abs(indexed - n) > max(50, n // 10):
                        _warn(f"the Sigma index ({indexed:,}) and the Sigma files ({n:,}) differ a lot; the index may need rebuilding")
        else:
            print(f"  {label:<24} {path}  ({_human(os.path.getsize(path))})")
    data_dir = _data_dir()
    for sub in ("sigma_pipelines", "sigma_templates"):
        p = os.path.join(data_dir, sub)
        if os.path.isdir(p):
            print(f"  {sub:<24} {p}  ({len(os.listdir(p))} files)")


def _print_summary() -> int:
    _line("Summary of findings")
    fails = [m for lvl, m in _FINDINGS if lvl == "FAIL"]
    warns = [m for lvl, m in _FINDINGS if lvl == "WARN"]
    if not fails and not warns:
        print("  Nothing needs attention.")
        return 0
    for m in fails:
        print(f"  [FAIL] {m}")
    for m in warns:
        print(f"  [WARN] {m}")
    print(f"\n  {len(fails)} failure(s), {len(warns)} warning(s).")
    return 1 if fails else 0


class _Tee:
    """Pass output through unchanged while noting [FAIL] / [STOP] / [WARN] lines for the final summary."""

    def __init__(self, real):
        self.real, self.buf = real, ""

    def write(self, text):
        self.real.write(text)
        self.buf += text
        while "\n" in self.buf:
            line, self.buf = self.buf.split("\n", 1)
            for marker, level in (("[FAIL]", "FAIL"), ("[STOP]", "FAIL"), ("[WARN]", "WARN")):
                if marker in line:
                    _FINDINGS.append((level, line.split(marker, 1)[1].strip() or line.strip()))
                    break
        return len(text)

    def flush(self):
        self.real.flush()

    def __getattr__(self, name):
        return getattr(self.real, name)


STATE_SECTIONS = (_check_app_host, _check_database_files, _check_rules_state,
                  _check_sync_reference_state, _check_users_tenants, _check_bundled_data)


def main(argv: list[str] | None = None) -> int:
    import argparse
    import atexit
    parser = argparse.ArgumentParser(description="TIDE diagnostic (run inside the container; no internet needed).")
    parser.add_argument("--state", action="store_true",
                        help="only the state sections 14-19 (app, databases, rules, scoring, users, bundled data); "
                             "makes no calls to Kibana or Elasticsearch")
    args = parser.parse_args(argv)
    atexit.register(_cleanup_snapshots)

    print("TIDE comprehensive diagnostic" + (" (state sections only)" if args.state else ""))
    print("=============================")
    try:
        with open("/app/VERSION") as f:
            print(f"VERSION: {f.read().strip()}")
    except Exception:
        print("VERSION: <unknown>")

    if not args.state:
        real_stdout = sys.stdout
        sys.stdout = _Tee(real_stdout)                 # so the summary also lists findings from sections 1-13
        try:
            env = _check_env()
            info = _check_db()
            _check_kibana(info.get("siems") or [], env, info.get("mappings") or [])
            _check_tenant_dbs(info)
            _check_migrations(info)
            _check_logs()
            _check_elasticsearch(info.get("siems") or [])
            _verdict(env, info)
            _check_dry_run_urls(info)
            _check_live_sync_trace(info)
            _check_opencti_tenants(info)
            _check_cti_dbs(info)
            _check_taxii_cursors(info)
        finally:
            sys.stdout = real_stdout
    for section in STATE_SECTIONS:
        try:
            section()
        except Exception as exc:                       # noqa: BLE001 - one broken section must not hide the rest
            _fail(f"section {section.__name__} crashed: {type(exc).__name__}: {exc}")
    return _print_summary()


if __name__ == "__main__":
    sys.exit(main())
