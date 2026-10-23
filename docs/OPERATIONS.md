# Operations

How TIDE runs day to day, and how to look after it: syncing, OpenCTI, how coverage is worked out, backups and upgrades, moving to new hardware, disk space, and what to do when something goes wrong.

[← Back to the README](../README.md)

**Contents:** [How TIDE runs](#how-tide-runs) · [What runs on its own](#what-runs-on-its-own) · [Syncing rules](#syncing-rules) · [OpenCTI connectors](#opencti-connectors) · [Rule-log export](#rule-log-export) · [How coverage is worked out](#how-coverage-is-worked-out) · [Backups and upgrades](#backups-and-upgrades) · [Moving to new hardware](#moving-to-new-hardware) · [Reclaiming disk space](#reclaiming-disk-space) · [Diagnostics](#diagnostics) · [Troubleshooting](#troubleshooting)

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
| `sigma_pipelines/`, `sigma_templates/` | Your Sigma conversion pipelines and templates. |
| `log/` | TIDE's log, and the rule-log exports. |
| `diagnostics-backups/` | A copy of a client's database taken before each Diagnostics fix (the last three). |

ATT&CK, NIST 800-53, the SigmaHQ rules and Elastic's detection rules and hunting queries are built into the image, not kept in `data/`. They update when you upgrade TIDE.

---

## What runs on its own

| What | When | Where |
|------|------|-------|
| Rule sync from your SIEMs | Only when someone clicks **Sync** | Rule Health |
| Threat Landscape actors | Only when someone clicks **Sync Threats** | Threat Landscape |
| Rule-log export | Daily, at each SIEM's scheduled time, if turned on | Management → Integrations, a SIEM's card → Rule Logging |
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
| **Done, steps failed** | The rules were read, but a step TIDE runs afterwards failed, such as cleaning up score history; the result names it, and Rule Monitoring lists it until a sync's steps succeed. |
| **Partly done** | Some destinations didn't answer; the result names them. Their rules keep their last state and show **SIEM offline**. |
| **Failed** | The sync stopped with an error, shown with the reason. |
| **Interrupted** | TIDE restarted while the sync ran. |

For anything but **Done**, **Retry** runs the same sync again over the same destinations. Every sync is also listed in **Diagnostics → Sync activity** for 90 days.

A rule deleted in Kibana is marked **Deprecated** at the next sync, keeping its history, links and mappings. TIDE does this only when Kibana returned every rule it says the space holds, so a sync cut short never deprecates a rule that still exists. Two Diagnostics checks show when that keeps happening:

- **Destinations whose last two syncs could not read every rule**: TIDE still counts rules there that may have been deleted in Kibana. To clear one you know was deleted, open it and use **Sync this rule**.
- **Rules sharing a rule id in Kibana**: Kibana holds two rules under one rule id, usually a copy and Elastic's own prebuilt rule. TIDE holds one of them; delete the one you don't need in Kibana.

Syncs run when someone starts one. TIDE's figures for a destination are as of its last sync, so **Destinations not synced for 7 days** lists those that have fallen behind, with when each was last synced. Rule Health's **Last Synced** card counts them in red, and reports say when the rules were last synced.

---

## OpenCTI connectors

A connector links TIDE to an OpenCTI. A super admin adds it once in **Management → Integrations** (**Add integration** → **OpenCTI**), with OpenCTI's address and an API token; each client that should use it links it from the client's page (**Linked CTI Connectors → Edit**). **Sync Threats** on **Threat Landscape** then adds the intrusion sets of the client's OpenCTI to ATT&CK's actors and shows how much of each one's techniques your rules cover; **Create Baseline** turns an actor's techniques into a baseline.

- **Connection status.** A connector shows **Active** when its last connection test passed, **Failed** when it didn't (hover for the reason), or **Untested**. The arrow button on its card asks OpenCTI for its version, as a sync would connect.

---

## Rule-log export

Each SIEM can write a daily file of its rules' scores for your log platform to collect. Turn it on in **Management → Integrations**, on the SIEM's card, under **Rule Logging**: choose the spaces, the time (server time) and how many days of files to keep.

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

- Each backup is a folder named for when it was made and the TIDE version that made it, `tide-backup-<date>-<time>-v<version>` (for example `tide-backup-20261020-181056-v6.2.3`), in the folder `BACKUP_PATH` names (default `backups/` next to `docker-compose.yml`). Put it on another disk if you can (see [Configuration](CONFIGURATION.md#optional)). Backups made before 6.2.3 have no version in their name; the Backups panel's **TIDE** column shows it.
- It holds a copy of every database, `credentials.key` and your Sigma pipelines and templates. TIDE keeps running while it's made.
- Copies hold only live data, so a backup is usually far smaller than `data/` (database files never shrink on their own).
- Older backups beyond the number you keep are removed. A backup refuses to start when the disk lacks room, and the Backups panel shows the last result and why it failed.
- A backup contains every client's data and the key to the stored credentials: protect the folder as you would `data/`.

Keep a copy of `.env` and `certs/` somewhere safe as well; they aren't in the backup.

### Back up by hand

Without the scheduled backups, copy `data/` yourself, on the host in TIDE's folder. As with a restore, each command is one way to carry out its step. If a command says `Permission denied`, run it with `sudo`.

1. **Stop TIDE.** Then nothing writes to its databases while they're copied, so the copy is whole.

    `docker compose stop tide-app`

2. **Copy `data/`** into a folder named with today's date and the TIDE version, such as `/backup/tide-data-2026-10-20-v6.2.3`. Put it on another disk if you can.

    `cp -a data/ "/backup/tide-data-$(date +%F)-v$(sed -n 's/^TIDE_VERSION=//p' .env)/"`

    `cp -a` copies the folder and everything in it, keeping the files' dates and permissions. The name is built as the command runs: `$(date +%F)` is today's date, such as `2026-10-20`, and `$(sed -n 's/^TIDE_VERSION=//p' .env)` is the version in `.env`: `sed` finds the line that starts with `TIDE_VERSION=` and prints what follows it (`-n` prints nothing else). Unlike the restore's `sed -i`, this only reads `.env`. `/backup/` is an example: use the folder you keep backups in. If `.env` says `latest`, or your deployment keeps the version somewhere else, type the version number into the name instead, so you know which version made the copy.

3. **Start TIDE** again.

    `docker compose up -d tide-app`

**`data/credentials.key` must always be backed up with the databases**, or the stored SIEM and connector credentials can't be read after a restore. A copy of `data/` includes it.

### Restore a backup

A backup holds TIDE's data. The TIDE version that runs it is set separately, by `TIDE_VERSION` in `.env`, so when you restore you also choose the version:

- **The version that made the backup** (the version at the end of its name) puts TIDE back exactly as it was. Use it to go back after an upgrade that went wrong.
- **A newer version** upgrades the restored databases as it starts. For example: you run 6.5.1 and back up, then upgrade to 6.5.2, which breaks something. When 6.5.3 is out, upgrade to it and restore the 6.5.1 backup into it; the version doesn't change during the restore.
- **Never an older version** than the one that made the backup: an older TIDE can't read a newer TIDE's databases.

In **Settings → Management → Backups**, **Restore steps** on a backup's row shows these steps with that backup's name and version filled in. Run them on the host, in TIDE's folder. Each command is one way to carry out its step: do each step however suits how you run TIDE. If a command says `Permission denied`, run it with `sudo` (TIDE writes the files in `data/` as root).

1. **Stop TIDE.** Then nothing writes to its databases while they're replaced. The container is kept, only stopped, and nginx keeps running.

    `docker compose stop tide-app`

2. **Set the TIDE version, only to change it.** Skip this step to restore into the version TIDE runs now. To go back to the version that made the backup, set `TIDE_VERSION` in `.env` to that version: edit the file (for example `nano .env`), or run

    `sed -i 's/^TIDE_VERSION=.*/TIDE_VERSION=<version>/' .env`

    which rewrites the line that starts with `TIDE_VERSION=` (`-i` changes the file itself; `s/old/new/` replaces the matched line). `grep ^TIDE_VERSION .env` shows the version set. If `.env` is written by your deployment, for example an Ansible playbook, set the version there instead: a change made on the host is overwritten at the next deployment. That version's image must be on the host, or Docker must be able to pull it; without internet access, `docker load` it first, as in the [Quick start](../README.md#2-get-the-images).

3. **Set your current data aside.** Every database and `credentials.key` move to a new folder named for this moment, such as `data-before-restore-20261020-183000`. Nothing is deleted, and the rest of `data/`, such as logs and the backup schedule, stays as it is.

    `old=data-before-restore-$(date +%Y%m%d-%H%M%S) && mkdir "$old" && mv data/*.duckdb* data/credentials.key "$old"/`

    `old=…` names the folder, `mkdir` creates it, and `mv` moves the files (each `.duckdb` file and its `.wal`). `&&` runs each part only if the one before it worked.

4. **Copy the backup in.** Everything in the backup's folder is copied into `data/`, keeping the files' dates and permissions (`-a`), then the copied `manifest.json`, which only describes the backup, is deleted. The Sigma pipelines and templates are replaced by the backup's copies; any added since stay. The backup itself isn't changed, so you can restore it again. If `BACKUP_PATH` is set, copy from that folder instead of `backups/`; for a copy made by hand, copy from it (it has no `manifest.json` to delete).

    `cp -a backups/<backup>/. data/ && rm data/manifest.json`

5. **Start TIDE.** TIDE's container is created from `docker-compose.yml` and `.env`, so it runs the version `.env` names, on the restored data; a newer version than the backup's upgrades the databases as it starts. `-d` leaves it running in the background. If your deployment starts TIDE, run it instead.

    `docker compose up -d tide-app`

6. **Check it.** Watch TIDE start (Ctrl+C stops showing the log, not TIDE). When the log says `Application startup complete`, sign in, check your clients are there, and sync each client's rules: what was changed in TIDE after the backup was made is lost, but what TIDE changed in Kibana since is still there. Remove the `data-before-restore-…` folder once TIDE runs normally.

    `docker compose logs -f tide-app`

### Upgrade

Read the release's notes in the [Changelog](../CHANGELOG.md) first: some releases ask you to do something before or after upgrading.

1. **Back up.** **Back up now** in Management → Backups, or by hand as above. Keep that backup until the new version runs well. If it doesn't, restore the backup into the version that made it, or into a later release once there is one (see [Restore a backup](#restore-a-backup)).

2. **Set the new version.** Set `TIDE_VERSION` in `.env` to the new release: edit the file (for example `nano .env`), or run the command below, which rewrites the line that starts with `TIDE_VERSION=`. If `.env` is written by your deployment, for example an Ansible playbook, set the version there instead: a change made on the host is overwritten at the next deployment.

    `sed -i 's/^TIDE_VERSION=.*/TIDE_VERSION=<version>/' .env`

3. **Get its image.** With internet access, `docker compose pull` downloads it; without, `docker load` it as in the [Quick start](../README.md#2-get-the-images).

    `docker compose pull`

4. **Start it.** TIDE's container is created again with the new version, and TIDE upgrades its databases as it starts. If your deployment starts TIDE, run it instead.

    `docker compose up -d`

5. **Watch it upgrade.** When the release changes the databases, the log says `Migrations complete` once they're upgraded; `Application startup complete` says TIDE is ready (Ctrl+C stops showing the log, not TIDE).

    `docker compose logs -f tide-app`

6. **Review rule updates.** Each release brings Elastic's rules and the Sigma rules as they were when it was built. In **Rule Health**, set the **Upstream** filter to **Elastic update available** and **Sigma update available** to see your rules whose Elastic or Sigma original has changed since, and open each one: **Upstream → Review update** shows the changes section by section, so you take only what you want. Kibana updates Elastic's prebuilt rules itself (Rules → Rule updates).

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

**Settings → Diagnostics** is for super admins, and for people with the **Support** role on a client (who see that client only). Click a section's heading to fold it away.

- **Snapshot:** the TIDE version, database schema, clients and their destinations (with whether each SIEM answered at the last sync), and recent errors from the log.
- **Checks:** **Run all checks**, or one, for every client or one. Each finding says what it means and what to do. Checks only read data. The two database health checks (a client's database, and TIDE's own) copy the database and test every table's indexes on the copy, so they take a while on a large database and run only on their own **Run**.
- **Look up:** everything TIDE holds for one rule, user or destination, with names and spaces shown exactly as stored, so stray spaces or invisible characters are marked.
- **Sync activity:** every rule and Threat Landscape sync for the last 90 days, with **Retry**.
- **Fixes:** some checks offer a fix. Fixes are off for every client until a super admin turns on **Allow diagnostic fixes** for it. A fix shows what it will change first, copies the client's database to `data/diagnostics-backups/` before changing anything, and can be undone.
- **Access:** who has Platform Admin and who has Support on each client (super admins only).
- **Query:** run a read-only SQL statement against TIDE's own database or a client's, and save the ones you use again (super admins only). It runs on a copy of the database, so it never changes or holds up the live one.

Every check, look-up, fix and access change is recorded in the audit log.

---

## Troubleshooting

| What you see | What to do |
|--------------|------------|
| A rule sync **Failed** or **Partly done** | Read the reason under Rule Health's title. Usually a SIEM was unreachable or refused its API key: check it with **Test Connection** in the SIEM's dialog in Management → Integrations, then click **Retry**. |
| A rule sync shows **Interrupted** | TIDE restarted during it. Click **Retry**. |
| A rule sync shows **Done, steps failed** | The rules were read, but a step afterwards failed; the result says which and why. Click **Retry**. If it fails again, report the error from **Diagnostics → Sync activity** with TIDE's log from that time. |
| Diagnostics shows **A database stopped after a DuckDB fatal error** | DuckDB stopped a client's database, so TIDE restarted itself, which repairs the rule history indexes. If that client's pages work, nothing more is needed. If they say its database stopped, a second error came within 10 minutes and TIDE didn't restart again: restart it with `docker compose restart tide-app`, and if it happens again, back up the data folder and report the error. |
| Rules show **SIEM offline** | That destination didn't answer at the last sync. Fix the connection, then sync that destination. |
| A connector shows **Failed**, or **Sync Threats** reports an OpenCTI error | Hover for the reason, fix the address, token or certificate in the connector's form, test it with the arrow button, then click **Sync Threats** again. |
| A certificate is refused | See [When a certificate is refused](CONFIGURATION.md#when-a-certificate-is-refused). |
| Scheduled rule-log exports or backups stopped | A background service isn't running; Diagnostics shows it. Restart TIDE: `docker compose restart tide-app`. |
| A backup failed | Management → Backups shows why. Usually the disk is short of space: free some, or keep fewer backups. |
| TIDE doesn't come up after a restart | Run `docker compose logs -f tide-app`. A large client database can make the first start after an upgrade slow; wait for `Application startup complete`. |
| Anything else | Open **Diagnostics** and click **Run all checks**. |

### Logs

TIDE's log is `data/log/tide.log`; `docker compose logs -f tide-app` shows it live. Each sync writes one entry when it starts and one when it ends, with the same result and reason shown on screen.

For a read-only summary of TIDE's databases, safe to run while TIDE is in use:

```bash
docker exec tide-app python -m app.scripts.diag_sync --state
```
