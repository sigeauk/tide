# Operations

How TIDE runs day to day, and how to look after it: syncing, CTI feeds, how coverage is worked out, backups and upgrades, moving to new hardware, disk space, and what to do when something goes wrong.

[← Back to the README](../README.md)

**Contents:** [How TIDE runs](#how-tide-runs) · [What runs on its own](#what-runs-on-its-own) · [Syncing rules](#syncing-rules) · [CTI feeds](#cti-feeds) · [Rule-log export](#rule-log-export) · [How coverage is worked out](#how-coverage-is-worked-out) · [Backups and upgrades](#backups-and-upgrades) · [Moving to new hardware](#moving-to-new-hardware) · [Reclaiming disk space](#reclaiming-disk-space) · [Diagnostics](#diagnostics) · [Troubleshooting](#troubleshooting)

---

## How TIDE runs

TIDE is two containers, started by `docker-compose.yml`:

| Container | What it does |
|-----------|--------------|
| `tide-nginx` | Serves TIDE over HTTPS on port 443 with your certificate. |
| `tide-app` | The application. It keeps all its data in the `data/` folder on the host. |

### Where your data lives

Everything TIDE keeps is in `data/`, next to `docker-compose.yml`:

| In `data/` | What it holds |
|------------|---------------|
| `tide.duckdb` | Users, roles, clients, and SIEM and integration settings. |
| `credentials.key` | The key that encrypts the SIEM, connector, GitLab and Keycloak credentials TIDE stores. Created on the first start. **Without it, those credentials must be entered again.** |
| `<client>_<id>.duckdb` | One database per client: its rules, scores, validations, systems and baselines. |
| `cti_<client>_<id>.duckdb` | One CTI database per client. |
| `sigma_pipelines/`, `sigma_templates/` | Your Sigma conversion pipelines and templates. |
| `log/` | TIDE's log, and the rule-log exports. |
| `diagnostics-backups/` | A copy of a client's database taken before each Diagnostics fix (the last three). |

ATT&CK, NIST 800-53, the SigmaHQ rules and Elastic's detection rules and hunting queries are built into the image, not kept in `data/`. They update when you upgrade TIDE.

---

## What runs on its own

| What | When | Where |
|------|------|-------|
| Rule sync from your SIEMs | Only when someone clicks **Sync** | Rule Health |
| CTI connectors | When someone clicks Sync, and on the connector's **Auto-sync interval** if it has one | Management → Integrations → Connectors, and the CTI pages |
| Threat Landscape actors | Only when someone clicks **Sync Threats** | Threat Landscape |
| Rule-log export | Daily, at each SIEM's scheduled time, if turned on | Management → Integrations → SIEMs → Rule Logging |
| Backups | Daily, at the scheduled time, if turned on | Management → Backups |
| CVE data (CISA KEV) | Only when someone imports a file | CVE Overview → Actions → Import CVE |
| Coverage and heatmaps | Worked out each time a page opens | — |

Nothing else runs in the background. A rule sync is always started by a person, for one client at a time.

---

## Syncing rules

In **Rule Health**, the **⋮** menu holds the sync options for the client you have selected:

- **Sync** reads the rules from every destination (a SIEM and one of its spaces) linked to the client. Hover over it to sync one destination only.
- **Sync with mappings** does the same, and also asks each SIEM again which fields its indexes have. Use it after changing index mappings. A normal sync only rechecks index patterns not checked in the last 24 hours.

You can leave the page while a sync runs. The **Last Synced** card shows when the client's rules were last synced. A sync that didn't finish cleanly is shown under the page title:

| Result | What it means |
|--------|---------------|
| **Done** | Every destination answered and its rules were read. |
| **Partly done** | Some destinations didn't answer; the result names them. Their rules keep their last state and show **SIEM offline**. |
| **Failed** | The sync stopped with an error, shown with the reason. |
| **Interrupted** | TIDE restarted while the sync ran. |

For anything but **Done**, **Retry** runs the same sync again over the same destinations. Every sync is also listed in **Diagnostics → Sync activity** for 90 days.

---

## CTI feeds

A connector is one CTI feed (OpenCTI, Mandiant, CrowdStrike or another TAXII source). A super admin adds it once in **Management → Integrations → Connectors**; each client that should receive it links it from the client's page (**Linked CTI Connectors → Edit**). Each client's CTI is kept in its own database.

- **Manual or scheduled.** A connector's **Auto-sync interval** is **Off** (it syncs only when someone clicks Sync) or every 15 minutes, hour, 6 hours or 24 hours. A scheduled sync does exactly what clicking Sync does.
- **Connection status.** A connector shows **Active** when its last connection test passed, **Failed** when it didn't (hover for the reason), or **Untested**. The arrow button on its card tests it again.
- **Syncing from the CTI pages.** **Sync indicators**, **Sync actors** and **Sync reports** run every connector linked to the selected client. While it runs the badge says *syncing*; afterwards it shows what came in, turns amber with a count of errors (hover to read them), or red with the reason it failed.

The **CTI Indicators**, **Actors** and **Reports** pages list what your feeds supplied. **Threat Landscape** combines ATT&CK's actors with your feeds' and shows how much of each one's techniques your rules cover; **Create Baseline** turns an actor's techniques into a baseline.

---

## Rule-log export

Each SIEM can write a daily file of its rules' scores for your log platform to collect. Turn it on in **Management → Integrations → SIEMs → Rule Logging**: choose the spaces, the time (server time) and how many days of files to keep.

Files are written to `data/log/rules/<SIEM>/<date>-<space>-rules.log`, one JSON line per rule, and copied to the folder `RULE_LOG_PATH` names if it is set (see [Configuration](CONFIGURATION.md#optional)).

---

## How coverage is worked out

**Which rules count for a system.** A rule lives in one destination: a SIEM and one of its spaces. Each system chooses which of its client's destinations count toward its coverage (its **SIEM coverage**), usually the production ones. A rule mapped to a baseline technique covers it on that system only if the rule, or a linked copy of it, is in a counted destination; otherwise the mapping is kept but shows **Not counted**. A system with no SIEM coverage chosen isn't scored.

**Each system has its own copy of a baseline.** Applying a baseline template to a system copies it. Changing one system's copy, including mapping or relinking a rule, never changes the template or another system's copy.

| Figure | When it's worked out |
|--------|----------------------|
| Rule scores | At each rule sync, and when a client changes its scoring points. Each rule's score history is kept. |
| Baseline and system coverage | Each time a page opens, from the mapped rules and each system's SIEM coverage. |
| ATT&CK coverage (heatmap, MITRE pages) | Each time a page opens: a technique is covered when an enabled rule carries it. |

---

## Backups and upgrades

### Scheduled backups

Turn them on in **Settings → Management → Backups** (super admins): tick **Back up every day at**, choose the time (server time) and how many backups to keep, and **Save**. **Back up now** makes one straight away.

- Each backup is a folder, `tide-backup-<date>-<time>`, in the folder `BACKUP_PATH` names (default `backups/` next to `docker-compose.yml`). Put it on another disk if you can (see [Configuration](CONFIGURATION.md#optional)).
- It holds a copy of every database, `credentials.key` and your Sigma pipelines and templates. TIDE keeps running while it's made.
- Copies hold only live data, so a backup is usually far smaller than `data/` (database files never shrink on their own).
- Older backups beyond the number you keep are removed. A backup refuses to start when the disk lacks room, and the Backups panel shows the last result and why it failed.
- A backup contains every client's data and the key to the stored credentials: protect the folder as you would `data/`.

Keep a copy of `.env` and `certs/` somewhere safe as well; they aren't in the backup.

### Restore a backup

On the host, in TIDE's folder, with the name of the backup to restore (the Backups panel shows these commands for the newest one):

```bash
docker compose stop tide-app
old=data-before-restore-$(date +%Y%m%d-%H%M%S) && mkdir "$old" && mv data/*.duckdb* data/credentials.key "$old"/
cp -a backups/<backup>/. data/ && rm data/manifest.json
docker compose start tide-app
```

Your current databases are moved to a `data-before-restore-<date>` folder, not deleted; remove it once TIDE runs normally. Restore into the same TIDE version, or restore an older backup into a newer TIDE, which upgrades the databases as it starts. If `BACKUP_PATH` is set, use that folder instead of `backups/`.

### Back up by hand

Without the scheduled backups, stop TIDE and copy `data/`:

```bash
docker compose stop
cp -a data/ /backup/tide-data-$(date +%F)/
docker compose up -d
```

**`data/credentials.key` must always be backed up with the databases**, or the stored SIEM and connector credentials can't be read after a restore.

### Upgrade

Read the release's notes in the [Changelog](../CHANGELOG.md) first: some releases ask you to do something before or after upgrading.

1. Back up: **Back up now** in Management → Backups, or by hand as above.
2. Set `TIDE_VERSION` in `.env` to the new release, and get its image: `docker compose pull`, or `docker load` as in the [Quick start](../README.md#2-get-the-images).
3. Start it, and watch it upgrade:

```bash
docker compose up -d
docker compose logs -f tide-app
```

TIDE upgrades its databases as it starts; the log says `Migrations complete` when it's done.

4. Review rule updates. Each release brings Elastic's rules and the Sigma rules as they were when it was built. In **Rule Health**, set the **Upstream** filter to **Update available** to see your rules whose Elastic or Sigma original has changed since, and open each one: **Upstream → Review update** shows the changes section by section, so you take only what you want. Kibana updates Elastic's prebuilt rules itself (Rules → Rule updates).

---

## Moving to new hardware

### Copy everything

The simplest move. Both hosts must run the same TIDE version.

1. Stop TIDE on both hosts: `docker compose stop`.
2. Copy the whole `data/` folder (including `credentials.key`), `.env` and `certs/` to the new host.
3. Start TIDE on the new host: `docker compose up -d`.

This moves every client, user and integration setting exactly as it was.

### Export and import

Use this to move some clients rather than all, or to move to a host running a newer TIDE (a file from a newer TIDE can't be imported into an older one). It's in **Settings → Management → Data export & import** (super admins).

1. Install TIDE on the new host with its own `.env` and `certs/`, and sign in as a super admin.
2. On the old host, export each client. Tick **Include users, tenant roles and permissions** on one of them. Each export is a JSON file of rules with their history and validation, baselines with their rule mappings, and systems. No passwords, API keys or Keycloak IDs are included.
3. On the new host, add the SIEMs and Keycloak again (their connection details are not exported), then import each file. Choose **+ Create a new client** for a new client, and tick **Also import users** where the file has them.
4. Link each client's destinations again (the same SIEM and space as before), then sync each client's rules.

Importing adds and never deletes: existing rows are kept, and a baseline whose name already exists isn't duplicated. Imported TIDE accounts have no password until one is set. Single sign-on users sign in as before once they exist in the new Keycloak realm with the same username or email.

---

## Reclaiming disk space

A database file never shrinks on its own: syncs rewrite rows and leave free space behind. To see how much each file could shrink, run:

```bash
docker exec tide-app python -m app.scripts.diag_sync --state
```

Its **Files** section lists each file's empty space and the command to reclaim it. Compacting needs TIDE stopped, because only one process may open a database at a time:

```bash
docker compose stop tide-app

# Dry run: reports the size and how much would be reclaimed; changes nothing
docker compose run --rm --no-deps tide-app python -m app.scripts.compact_duckdb /app/data/<file>.duckdb

# Compact it
docker compose run --rm --no-deps tide-app python -m app.scripts.compact_duckdb /app/data/<file>.duckdb --apply

docker compose up -d
```

The file is rewritten and checked table by table before it replaces the original; if any check fails, the original is left untouched. The original is kept beside it as `<file>.duckdb.pre-compact-<timestamp>`: delete it once TIDE runs normally.

---

## Diagnostics

**Settings → Diagnostics** is for super admins, and for people with the **Support** role on a client (who see that client only).

- **Snapshot:** the TIDE version, database schema, clients and their destinations (with whether each SIEM answered at the last sync), and recent errors from the log.
- **Checks:** **Run all checks**, or one, for every client or one. Each finding says what it means and what to do. Checks only read data.
- **Look up:** everything TIDE holds for one rule, user or destination, with names and spaces shown exactly as stored, so stray spaces or invisible characters are marked.
- **Sync activity:** every rule and CTI sync for the last 90 days, with **Retry**.
- **Fixes:** some checks offer a fix. Fixes are off for every client until a super admin turns on **Allow diagnostic fixes** for it. A fix shows what it will change first, copies the client's database to `data/diagnostics-backups/` before changing anything, and can be undone.
- **Access:** who has Platform Admin and who has Support on each client (super admins only).

Every check, look-up, fix and access change is recorded in the audit log.

---

## Troubleshooting

| What you see | What to do |
|--------------|------------|
| A rule sync **Failed** or **Partly done** | Read the reason under Rule Health's title. Usually a SIEM was unreachable or refused its API key: check it with **Test Connection** in Management → Integrations → SIEMs, then click **Retry**. |
| A rule sync shows **Interrupted** | TIDE restarted during it. Click **Retry**. |
| Rules show **SIEM offline** | That destination didn't answer at the last sync. Fix the connection, then sync that destination. |
| A connector shows **Failed**, or a CTI sync badge is red | Hover for the reason, fix the address, credentials or certificate in the connector's form, test it with the arrow button, then sync again. |
| A certificate is refused | See [When a certificate is refused](CONFIGURATION.md#when-a-certificate-is-refused). |
| Scheduled connectors, rule-log exports or backups stopped | A background service isn't running; Diagnostics shows it. Restart TIDE: `docker compose restart tide-app`. |
| A backup failed | Management → Backups shows why. Usually the disk is short of space: free some, or keep fewer backups. |
| TIDE doesn't come up after a restart | Run `docker compose logs -f tide-app`. A large client database can make the first start after an upgrade slow; wait for `Application startup complete`. |
| Anything else | Open **Diagnostics** and click **Run all checks**. |

### Logs

TIDE's log is `data/log/tide.log`; `docker compose logs -f tide-app` shows it live. Each sync writes one entry when it starts and one when it ends, with the same result and reason shown on screen.

For a read-only summary of TIDE's databases, safe to run while TIDE is in use:

```bash
docker exec tide-app python -m app.scripts.diag_sync --state
```
