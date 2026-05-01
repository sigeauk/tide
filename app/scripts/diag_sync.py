"""End-to-end TIDE sync + auth + schema + log diagnostic.

Run from inside the container, no arguments needed:

    docker exec tide-app python -m app.scripts.diag_sync

Reports, in plain English, exactly which link in the
``env -> DB -> SIEM record -> Kibana mapping -> rule cache`` chain is broken
and what to do about it. Eight numbered sections \u2014 every one is safe to paste
back into a support channel; tokens and secrets are redacted to
``len=N first=AAAA last=BBBB`` form.

Sections:
  1. Container env vars (looking for ELASTIC_URL/ELASTIC_API_KEY legacy auth)
  2. Shared DB state (siem_inventory, clients, client_siem_map, detection_rules)
  3. Live Kibana auth check, plus per-(siem, space) probe vs client_siem_map
  4. Per-tenant DB row counts (4.1.x only)
  5. Schema / migration state (current vs expected, leftover legacy columns)
  6. Recent ERROR / WARN log tail (when log files are mounted)
  7. Elasticsearch reachability (port 9200, info-only)
  8. Verdict block naming the failing link and the next action

Designed to handle TIDE 4.0.x (env-var driven), 4.0.13+ (siem_inventory) and
4.1.x (per-tenant DB) without needing to know which version is running.
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
            c = duckdb.connect(snap_path, read_only=True)
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
        endpoint = f"{url}/api/detection_engine/rules/_find?per_page=1"
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
            t = duckdb.connect(snap, read_only=True)
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
    _line("5. Schema / migration state")
    if not info.get("db_read_ok"):
        print("  skipped: section 2 could not read the shared DB")
        print(f"  ({info.get('db_read_error', 'unknown error')})")
        return
    try:
        from app.services.database import SCHEMA_VERSION as expected
    except Exception:
        expected = 40  # fallback; bump when SCHEMA_VERSION changes (see app/services/database.py)
    sv = info.get("schema_version")
    print(f"  expected schema_version: {expected}")
    print(f"  actual schema_version:   {sv}")
    if sv is None:
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


def _check_logs() -> None:
    _line("6. Recent ERROR / WARN log tail")
    log_paths = [
        "/app/data/log/tide.log",
        "/app/data/log/app.log",
        "/var/log/tide-app.log",
    ]
    found_any = False
    for p in log_paths:
        if not os.path.exists(p):
            continue
        found_any = True
        print(f"  -- {p} (last 40 ERROR/WARN lines) --")
        try:
            import collections
            tail = collections.deque(maxlen=40)
            with open(p, "r", errors="replace") as f:
                for line in f:
                    if any(t in line for t in ("ERROR", "WARN", "Traceback",
                                               "Sync drift", "auth-banner",
                                               "isolation_violation")):
                        tail.append(line.rstrip())
            for line in tail:
                print(f"     {line}")
            if not tail:
                print("     (no ERROR/WARN lines in this file)")
        except Exception as exc:
            print(f"     could not read: {exc}")
    if not found_any:
        print("  no log files found at the usual paths. App logs to stdout "
              "and is captured by docker; see them with:")
        print("     docker logs --tail 200 tide-app | grep -E 'ERROR|WARN|drift|auth-banner'")


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


def main() -> int:
    print("TIDE comprehensive diagnostic")
    print("=============================")
    try:
        with open("/app/VERSION") as f:
            print(f"VERSION: {f.read().strip()}")
    except Exception:
        print("VERSION: <unknown>")

    env = _check_env()
    info = _check_db()
    _check_kibana(info.get("siems") or [], env, info.get("mappings") or [])
    _check_tenant_dbs(info)
    _check_migrations(info)
    _check_logs()
    _check_elasticsearch(info.get("siems") or [])
    _verdict(env, info)
    return 0


if __name__ == "__main__":
    sys.exit(main())
