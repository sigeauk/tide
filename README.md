# Threat Informed Detection Engine (TIDE)

TIDE is a **standalone, containerised platform** for detection engineering. It brings your SIEM's detection rules, MITRE ATT&CK, CTI feeds and your systems together, so you can see which threats your rules cover, where the gaps are, and how good each rule is. A person makes every coverage decision, and every decision is recorded and can be reversed. It runs without internet access.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                         NGINX                               │
│                  (TLS termination, port 443)                │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                        FASTAPI                              │
│          (server-rendered pages + HTMX, port 8000)          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                        DUCKDB                               │
│   tide.duckdb: users, clients, SIEMs and other settings     │
│   one database per client: rules, systems, baselines, CTI   │
│   reference.duckdb (in the image): ATT&CK, NIST, Sigma      │
└─────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| **Reverse proxy** | Nginx | TLS termination, static files, compression |
| **Backend** | FastAPI (Python) | Pages, HTMX partials, the external query API, sync jobs |
| **Database** | DuckDB | Embedded; one file per client keeps each client's data separate |
| **Frontend** | HTMX + Jinja2 | Server-rendered HTML with partial updates; no single-page app |
| **Styling** | CSS custom properties | One stylesheet; dark and light themes (see [Design System](#design-system)) |
| **Auth** | Local accounts, Keycloak (optional) | OIDC single sign-on; per-client roles |
| **Bundled data** | MITRE ATT&CK, NIST 800-53, SigmaHQ | Built into the image, no download at runtime |

---

## Key Features

TIDE is multi-tenant: each **client** has its own data, users and roles, and its own **destinations** (a SIEM and one of its Kibana spaces) that its rules come from.

### Dashboard
- The selected client's figures at a glance, on as many named dashboards as it needs; one is the default, and each person sees the one they opened last.
- A dashboard is made of sections. Each shows the figures from one page (Rule Health, a system, Threat Landscape, Baselines, Asset Inventory or CVE Overview), or the state of the connected services and repositories. Add a section as often as you like, choose which figures it shows, and filter it as its page is filtered: Rule Health by SIEM, status, state, score, validation date and search, and a system's section by system.
- Clicking a figure opens its page, filtered the same way, to see what is behind it.

### Systems, Baselines and Risks
- **Systems**: the environments you defend, with their devices and software (add them by hand, or import a Nessus scan), their CVEs, and the baselines applied to them.
- **Baselines**: templates of the ATT&CK techniques a system should detect. Create them by hand, import them, generate them from a system's software, or make them from a threat actor or a MITRE group, software or campaign.
- For each baseline technique on a system: map the rules that detect it, or record a known gap or N/A. Coverage is shown per system, with snapshots kept for audit.
- **CVE Overview**: CISA KEV entries, matched against your systems' software.
- System reports, executive or technical, as PDF or Markdown.

### Rules
- **Rule Health**: every rule from the client's destinations, with a quality score, validation state and the baseline techniques it covers. Each client chooses how many points each scoring check is worth (Management → client → Rule scoring); a score is the percentage of the applicable points a rule earns.
- **Validation**: record when a rule was last checked, by hand or by importing a validation file. Rules turn amber and then expired after a number of weeks the client sets per severity.
- **Move and copy** a rule between the client's destinations, compare linked copies, and merge one into the other. Create rules, edit them, enable or disable them in bulk, and find duplicates.
- **Sigma**: browse the bundled SigmaHQ rules by ATT&CK technique, convert them to Elastic queries (KQL, Lucene, EQL, ES|QL) with your own pipelines and templates, and deploy them to a destination.

### Threats
- **Threat Landscape**: threat actors from ATT&CK and your CTI feeds, with how much of each one's techniques your enabled rules cover.
- **Heatmap**: selected actors' techniques by ATT&CK tactic, coloured by coverage; export it as a report.
- **MITRE**: browse ATT&CK's tactics, techniques, groups, software, campaigns and mitigations, and NIST 800-53 controls, with your coverage of each.

### CTI
- **Indicators, Actors and Reports** from your CTI feeds (OpenCTI, Mandiant, CrowdStrike and other TAXII sources), kept per client. Indicators can be sent to a SIEM as egress targets.

### Administration
- **Management** (super admins): clients, users and roles, SIEMs, CTI connectors, GitLab and Keycloak instances, Sigma pipelines and templates, classifications, data export and import, and a read-only query tool.
- **Diagnostics** (super admins and Support): checks for known problems, sync history, look-ups and access.
- **Settings**: your profile and API keys; client admins manage their client's users here.

---

## Deployment Models

### Client Deployment Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT ENVIRONMENT                       │
│                                                             │
│  ┌─────────────────┐          ┌─────────────────┐           │
│  │  TIDE Container │ ◀─────▶ │  Elastic SIEM   │           │
│  │                 │  Sync    │  (Detections)   │           │
│  └─────────────────┘          └─────────────────┘           │
│           ▲                                                 │
│           │ CTI                                             │
│           │                                                 │
│  ┌─────────────────┐                                        │
│  │    CTI feeds    │                                        │
│  │  (OpenCTI, …)   │                                        │
│  └─────────────────┘                                        │
└─────────────────────────────────────────────────────────────┘
```

**Key Points:**
- The Docker image is **`sigeauk/tide`**, one tag per release.
- TIDE reads and writes detection rules in your **Elastic** SIEMs (Kibana). Splunk and Sentinel SIEMs can be recorded but don't sync yet.
- GitLab instances can be recorded and linked to clients; publishing reports to them is planned.
- No outbound internet access is needed once the images are on the host.

---

## Installation

### Prerequisites

- A Linux host with Docker and Docker Compose v2 or later.
- A TLS certificate and key for the address users will open TIDE at.
- For each SIEM: its Elasticsearch and Kibana URLs and an API key that can read detection rules (and write them, if you move or deploy rules from TIDE).
- Optional: a Keycloak realm for single sign-on, and CTI feeds (OpenCTI, Mandiant, CrowdStrike and others).

TIDE needs no internet access once its images are on the host. SIEMs, CTI connectors and GitLab are set up in TIDE itself, not in `.env`.

### Install

1. **Get the files.** Put `docker-compose.yml`, `.env.example` and the `nginx/` folder in one directory on the host, for example `/opt/tide`.
2. **Get the images.** With internet access, `docker compose pull`. Without it, save the images on a connected machine, copy the file across, and load it:
   ```bash
   # connected machine
   docker save sigeauk/tide:<version> nginx:alpine | gzip > tide-images.tar.gz
   # TIDE host
   docker load < tide-images.tar.gz
   ```
3. **Add certificates** to a `certs/` folder next to `docker-compose.yml`:
   - `server.crt` and `server.key`: the certificate nginx presents to users' browsers.
   - `ca.crt`: your internal CA, which TIDE then trusts when it connects to your SIEMs, Keycloak, GitLab and CTI feeds (see [TLS certificates](#tls-certificates)). It must exist; if you have no internal CA, copy `server.crt` to `ca.crt`.
4. **Create `.env`:** `cp .env.example .env`, then set at least:
   - `TIDE_VERSION`: the release to run, for example `6.1.0`.
   - `APP_URL`: the address users open TIDE at, for example `https://tide.example.local`.
   - `SESSION_SECRET`: a long random string. TIDE won't start without it. `.env.example` shows two ways to make one offline.
   - `BOOTSTRAP_ADMIN_USERNAME` and `BOOTSTRAP_ADMIN_PASSWORD`: the first administrator account. They are used once, on first start; if not set, the account is `admin` / `TIDEadmin`.
5. **Start TIDE:** `docker compose up -d`. `docker compose ps` shows `tide-app` as healthy within a minute. The first start takes longer while TIDE builds its databases.

### First sign-in and setup

1. Open `APP_URL` and sign in with the bootstrap account. Change its password straight away in **Settings → Profile**.
2. **Add your SIEMs:** Management → Integrations → SIEMs → New SIEM. Use **Test Connection** before saving.
3. **Create a client** for each team or customer whose data must stay separate: Management → Tenants & Users → Clients → New Client. A **Primary Client** already exists and can be used for the first one.
4. **Link destinations to the client.** Open the client, then **Linked SIEMs → Edit → Add SIEM**. Pick the SIEM and one of its Kibana spaces, give the destination a name (for example "Prod"), and click **Link SIEM**. Add one destination for each SIEM and space whose rules this client should see.
5. **Add users.** Create local users or assign single sign-on users to the client, with their roles, in Management → Tenants & Users → Users, or in the client's **Assigned Users**. Client admins can do the same for their own client in Settings → Users.
6. **Load the rules:** switch to the client, open **Rule Health**, and click **⋮ → Sync**. See [Syncing rules](#syncing-rules).
7. **Optional:**
   - CTI: add connectors in Management → Integrations → Connectors, then link them to the client from the client page (**Linked CTI Connectors → Edit**). See [CTI connectors](#cti-connectors).
   - Single sign-on: set the `KEYCLOAK_*` values in `.env` (see below) and run `docker compose up -d` again.
   - Rule-log export: see [Rule-log export](#rule-log-export).

### Upgrading

1. Back up: `docker compose stop`, then copy the `data/` folder.
2. Set `TIDE_VERSION` in `.env` to the new release and get its image (`docker compose pull`, or `docker load` as above).
3. `docker compose up -d`. TIDE upgrades its databases as it starts; the log says `Migrations complete` when it's done.

---

## Configuration

### Environment variables

Set in `.env` (start from `.env.example`). Changes apply after `docker compose up -d`.

| Variable | What it does | Required |
|----------|--------------|----------|
| `TIDE_VERSION` | The TIDE image tag to run | ✅ |
| `APP_URL` | The address users open TIDE at. Single sign-on returns users here, and cookies are marked secure when it starts with `https://` | ✅ |
| `SESSION_SECRET` | Random secret that signs local sign-in sessions. TIDE won't start without one. Changing it signs out everyone using a local account | ✅ |
| `BOOTSTRAP_ADMIN_USERNAME`, `BOOTSTRAP_ADMIN_PASSWORD` | The first administrator, created on the first start only | First start |
| `KEYCLOAK_URL` | Keycloak's address as users' browsers reach it | For SSO |
| `KEYCLOAK_INTERNAL_URL` | Keycloak's address as the TIDE container reaches it, if different | ❌ |
| `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET` | The realm and the TIDE client in it | For SSO |
| `SSL_VERIFY` | Whether TIDE checks Keycloak's certificate when signing users in (default `true`) | ❌ |
| `AUTH_DISABLED` | `true` turns sign-in off entirely. For isolated testing only, never on a live install | ❌ |
| `RULE_LOG_PATH` | Another host folder that gets a copy of each rule-log export (they are always written to `data/log/rules/`) | ❌ |
| `ELASTIC_APM_*` | Send TIDE's own performance traces to Elastic APM. `.env.example` turns this on: set `ELASTIC_APM_ENABLED=false` if you have no APM server | ❌ |

SIEMs, CTI connectors and GitLab are not set in `.env`: add them in Management → Integrations, where each has its own URL, key and **Verify TLS certificate** setting.

### TLS certificates

Each integration in Management (every SIEM, GitLab and Keycloak entry, and every CTI connector) has its own **Verify TLS certificate** box. It is off by default, because TIDE usually runs standalone against self-signed certificates. When it is ticked, the integration's certificate must come from a public CA or from your own CA: save that CA certificate as `certs/ca.crt`, which `docker-compose.yml` installs into the container when it starts. Use **Test Connection** on the form to check a setting before saving it.

TIDE checks certificates strictly, as current browsers do. Test Connection says why a certificate was refused, and what to do:

- **Not signed by a CA TIDE trusts:** install the CA certificate as above.
- **The CA certificate lacks extensions** (for example "CA cert does not include key usage extension"): the CA was made without the fields TLS now requires. Reissue it with `basicConstraints = critical, CA:TRUE` and `keyUsage = critical, keyCertSign, cRLSign`, then reissue the server certificate from it.
- **Does not name this host:** the server certificate must list the exact host name (or IP address) in the integration's URL under Subject Alternative Name.
- **Outside its validity dates:** renew the certificate.

`SSL_VERIFY` in `.env` controls only TIDE's own Keycloak sign-in.

---

## Running TIDE day to day

### What runs on its own, and what you start

| What | When it runs | Where |
|------|--------------|-------|
| Rule sync from your SIEMs | Only when someone clicks Sync | Rule Health |
| CTI connectors | When someone clicks Sync, and also on the connector's **Auto-sync interval** if it has one | Management → Integrations → Connectors; CTI Indicators, Actors and Reports |
| Threat Landscape actors | Only when someone clicks **Sync Threats** | Threat Landscape |
| Rule-log export | Daily, at each SIEM's scheduled time, if turned on | Management → Integrations → SIEMs → Rule Logging |
| CVE data (CISA KEV) | Only when someone imports a file | CVE Overview → Actions → Import CVE |
| Coverage and heatmaps | Worked out from your rules and baselines each time a page opens | – |

Nothing else runs in the background. A rule sync is always started by a person, for one client at a time.

### Syncing rules

Rule Health → **⋮** opens the sync options for the client you have selected:

- **Sync** reads the rules from every destination (SIEM and space) linked to the client. Hover over it to sync a single destination instead.
- **Sync with mappings** does the same, and also asks each SIEM again which fields its index patterns have. Use it after changing index mappings in the SIEM. A normal sync asks only about patterns it hasn't checked in the last 24 hours.

The page shows progress while the sync runs, and you can leave the page; it carries on. The **Last Synced** card shows when the client's rules were last synced. A sync that didn't finish cleanly is shown under the page title, with how it ended (all results are also listed in **Diagnostics → Sync activity**):

| Result | Meaning |
|--------|---------|
| **Done** | Every destination answered and its rules were read. |
| **Partly done** | Some destinations didn't answer; the result names them. Rules from those destinations keep their last synced state and show **SIEM offline**. |
| **Failed** | The sync stopped with an error; the reason is shown. |
| **Interrupted** | TIDE restarted while the sync ran. Anything after the restart wasn't synced. |

For a sync that failed, partly finished or was interrupted, **Retry** runs the same sync again over the same destinations.

### CTI connectors

A connector is one CTI feed (OpenCTI, Mandiant, CrowdStrike and others), added once in Management → Integrations → Connectors and linked to each client that should receive it (client page → **Linked CTI Connectors → Edit**). Each client's CTI data is kept in its own database.

- **Manual or scheduled.** A connector's **Auto-sync interval** is either **Off** (it syncs only when someone clicks Sync; its card says *manual only*) or every 15 minutes, hour, 6 hours or 24 hours (its card says, for example, *auto · every 6h*). A scheduled sync does exactly what clicking Sync does.
- **Connection status.** A connector's card shows **Active** when its last connection test passed, **Failed** when it didn't (hover for the reason), or **Untested**. The arrow button on the card tests it again.
- **Syncing from the CTI pages.** **Sync indicators**, **Sync actors** and **Sync reports** run every connector linked to the selected client, then report what that page received. A connector's feed arrives as a whole, so any of the three fetches everything; the buttons differ only in what they count. Client admins can sync. While a sync runs its badge says *syncing*; when it ends the badge shows what came in (for indicators: new / merged / for review), turns amber with the number of errors (hover to read them), or red with the reason it failed. If the error is *No CTI connector linked to this client*, link one from the client page.
- **Sync history.** Every sync, by a person or on schedule, is recorded with its result. Super admins and Support see them in **Diagnostics → Sync activity**.

### The CTI pages

- **CTI Reports**: the intelligence reports your feeds publish. A report lists the actors it names and the indicators it references, with its attachments and external references.
- **CTI Actors**: the threat actors and intrusion sets from your feeds, with the indicators attributed to each and the reports that mention it.
- **CTI Indicators**: IP addresses, domains, URLs and file hashes, with their TLP marking, related actors and the reports that reference them.
- **Threat Landscape**: threat actors from MITRE ATT&CK and your linked connectors, with how much of each one's techniques your enabled rules cover. **Sync Threats** refreshes the list. An actor's **Create Baseline** turns its techniques into a baseline. The MITRE Groups, Software and Campaigns pages do the same with **Create baseline**.

Each list has a search box and filters, which carry across pages.

### Rule-log export

Each SIEM can write a daily export of its rules' scores, for your SIEM or log platform to collect. Turn it on in Management → Integrations → SIEMs, in that SIEM's **Rule Logging**: choose the spaces, the time (HH:MM, server time) and how many days of files to keep. Files are written to `data/log/rules/<SIEM>/<date>-<space>-rules.log`, one JSON line per rule, and copied to the folder `RULE_LOG_PATH` names, if it's set to another one.

### When something goes wrong

| What you see | What to do |
|--------------|------------|
| A rule sync **Failed** or is **Partly done** | Read the reason under Rule Health's title (or in Diagnostics → Sync activity). Most often a SIEM was unreachable or refused the API key: check it with **Test Connection** in Management → Integrations → SIEMs, then click **Retry**. |
| A rule sync shows **Interrupted** | TIDE restarted during it. Click **Retry**. |
| Rules show **SIEM offline** | That destination didn't answer at the last sync. Fix the connection, then sync that destination. |
| A connector shows **Failed**, or a CTI sync badge is red | Hover for the reason, fix the URL, credentials or certificate in the connector's edit form, test it with the arrow button on its card, then sync again. A scheduled connector tries again at its next interval on its own. |
| A certificate is refused | See [TLS certificates](#tls-certificates). |
| Scheduled connectors or rule-log exports stopped happening | One of TIDE's background services isn't running. TIDE says so in its log when it starts, and Diagnostics shows it. Restart TIDE: `docker compose restart tide-app`. |
| Anything else | Super admins and Support: open **Diagnostics** and click **Run all checks**. Each finding says what it means and what to do. |

**Logs.** TIDE's log is `data/log/tide.log` on the host (`docker compose logs -f tide-app` shows it live). Each sync writes one entry when it starts and one when it ends, with its result and the same reason shown on screen, so a failure seen in the UI can be found in the log. `docker exec tide-app python -m app.scripts.diag_sync --state` prints a read-only summary of TIDE's databases, safe to run while TIDE is in use.

---

## Design System

All colours, surfaces, spacing and type sizes are CSS custom properties defined once at the top of `app/static/css/style.css` (`:root`). The dark theme is the default; the light theme overrides the same properties under `body.light`. Each person picks a theme in **Preferences**, and it is remembered in their browser.

| Token group | Examples | Use |
|-------------|----------|-----|
| Brand | `--color-primary`, `--color-secondary` | Links, primary buttons, focus |
| Surfaces | `--color-bg-base` → `--color-bg-layer-5` | Five elevation layers, darkest furthest back |
| Text | `--color-text`, `--color-text-secondary`, `--color-text-muted` | Text hierarchy |
| Status | `--color-success`, `--color-warning`, `--color-danger` | Coverage, validation and sync states |
| Type | `--ff`, `--h1`…, `--p` | The system font stack and the type scale (14 px body) |

Change a token there and every page follows.

---

## Data Persistence

### Persistent Data (Survives Updates)

Located in `/app/data/` (volume mounted):

| File | Purpose |
|------|---------|
| `tide.duckdb` | Users, roles, clients, SIEM and integration settings |
| `credentials.key` | The key that encrypts the SIEM, connector, GitLab and Keycloak credentials TIDE stores. Created on first start. Back it up with the rest of `data/`: without it those credentials must be entered again |
| `<client>_<id>.duckdb` | One database per client: rules, scores, validations, systems, baselines |
| `cti_<client>_<id>.duckdb` | One CTI database per client |
| `sigma_pipelines/`, `sigma_templates/` | Your Sigma pipelines and templates |
| `log/` | Application log and rule-log exports |
| `diagnostics-backups/` | A copy of a client's database taken before each Diagnostics fix (the last three) |

ATT&CK, NIST 800-53 and the Sigma index are built into the image (`/opt/reference/reference.duckdb`) and are not part of `data/`.

### Moving to new hardware

Use Management (superadmin) > Data export & import.

1. Install TIDE on the new host with its own `.env` and `certs/`, and sign in as a superadmin.
2. On the old host, export each tenant (tick "Include users, tenant roles and permissions" on one of them). Each export downloads as a JSON file: rules with metadata, validation and history, migrations, baselines with their rule mappings, and systems. No passwords, API keys or Keycloak IDs are included.
3. On the new host, add the SIEMs (Management > SIEMs) and Keycloak, since connection details and API keys are not exported. Then import each file, choosing "+ Create a new client" for a new tenant, and tick "Also import users" where the file has them.
4. Link each client's destinations again (the same SIEM and space as before), then sync each client's rules.

Import merges: existing rows are kept, nothing is deleted, baselines with a name that already exists are not duplicated, and score-history tables are only filled when empty. Imported local users have no password until one is set.

Rows keep their SIEM IDs. If a SIEM has a different ID on the new host, rules re-sync from it and baseline links (by rule ID) still resolve, but the per-SIEM rule rows from the file won't match.

Copying the whole `data/` folder to an identical TIDE version also works, and additionally carries SIEM and Keycloak settings, with `credentials.key` to read their stored credentials. Stop TIDE on both hosts first. It moves every tenant, including leftover files from deleted clients.

**Single sign-on users and a new Keycloak.** Users come across with the export (or a copied `data/`), but a new realm issues new Keycloak IDs. At first login TIDE matches the user by Keycloak ID, then by username, then by email, and re-links accounts marked keycloak/hybrid, keeping their roles and tenants. So users only need to exist in the new realm with the same username or email. Local-only accounts are never auto-linked to SSO. The superadmin flag comes across with the user too.

**Sessions.** A local sign-in lasts 24 hours. Signing out ends all of that person's local sessions, in every browser, and so does changing their password, an admin resetting it, or deactivating their account. Single sign-on sessions end through Keycloak when you sign out.

**Superadmins and Keycloak.** Membership of the Keycloak `superadmin` group makes a user a TIDE superadmin only when TIDE first creates their account. After that, the flag belongs to TIDE: grant or revoke it with **Platform Admin** in Management → Users. Adding someone to the Keycloak group later, or removing them from it, no longer changes their TIDE access.

**Roles on each client.** A user can hold several roles on a client (Admin, Analyst, Engineer, Support) and different roles on different clients. On each client, a user can do whatever any of their roles there allows. **Support** opens **Diagnostics** for that client only. Only super admins can grant or remove it, in Management → Users or Diagnostics → Access, which also grants and revokes Platform Admin. Diagnostics fixes change a client's data only when a super admin has turned on **Allow diagnostic fixes** for that client. Before each fix, TIDE copies that client's database to `data/diagnostics-backups/` and keeps the last three copies.

**Which rules count for a system.** A rule belongs to one destination: a SIEM and one of its spaces. Each system chooses which of its client's destinations count toward its coverage (the system's **SIEM coverage**), typically the production ones. A rule mapped to a baseline technique covers it on that system only if the rule is at a counted destination, or a linked copy of it is. Otherwise the mapping is kept but marked *Not counted*. A system with no SIEM coverage chosen isn't scored. Moving a rule to another destination updates the mappings that pointed at it.

### Reclaiming disk space

A database file never shrinks on its own. Every rule sync rewrites rows, and a sync also deletes the score history of rules that no longer exist, so over time much of a file can be empty space. To find out how much, run `docker exec tide-app python -m app.scripts.diag_sync --state`: its Files section shows each file's empty space and the command to reclaim it.

To compact a file, stop TIDE, because only one process may open a database at a time:

```bash
docker compose stop tide-app
# Dry run: reports the file size and how much would be reclaimed, and changes nothing
docker compose run --rm --no-deps tide-app python -m app.scripts.compact_duckdb /app/data/<file>.duckdb
# Compact it
docker compose run --rm --no-deps tide-app python -m app.scripts.compact_duckdb /app/data/<file>.duckdb --apply
docker compose up -d
```

The file is rewritten into a new one and checked table by table (row counts and indexes) before it replaces the original. If any check fails, the original is left untouched. The original is kept next to it as `<file>.duckdb.pre-compact-<timestamp>`: delete it once TIDE runs normally.

### Calculated data

| Data | When it's worked out |
|------|----------------------|
| Rule scores | At each rule sync, and when a client changes its scoring points. Each rule's score history is kept |
| Baseline and system coverage | When a page opens, from the mapped rules and each system's SIEM coverage |
| ATT&CK coverage (heatmap, MITRE pages) | When a page opens: a technique is covered when an enabled rule carries it |

---

## External Query API (Sidecar)

TIDE exposes a read-only SQL query endpoint that lets external applications (SOAR, dashboards, custom scripts) pull data directly from TIDE tenant databases over HTTPS.

Since v4, each client (tenant) has its own isolated database. API keys inherit the tenant access of the user who created them — if you can see tenants A and B in the UI, your API key can query both.

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/external/clients` | List tenants accessible to your API key |
| `POST` | `/api/external/query` | Execute a read-only SQL query against a tenant database |

### Authentication

Every request must include an API key in the `X-TIDE-API-KEY` header. Keys are created in the TIDE UI under **Settings → API Key Management**. Only the SHA-256 hash of the key is stored — the raw key is shown once at creation time.

The API key inherits the tenant access of its creator: to give it more tenants, assign the owning user to those clients in Management. A key stops working while its owner is deactivated. Each user sees and revokes their own keys; a client admin also those of users they manage, and a super admin all of them.

### Tenant Selection

Queries run against a specific tenant database. You specify which tenant via the `client_id` field in the request body:

| Scenario | Behaviour |
|----------|-----------|
| User has **one** tenant | `client_id` is **optional** — auto-resolved |
| User has **multiple** tenants | `client_id` is **required** — use `GET /api/external/clients` to discover IDs |
| `client_id` not in user's access | **403 Forbidden** |

### Security Constraints

| Rule | Detail |
|------|--------|
| **SELECT only** | The SQL must be a single statement starting with `SELECT` or `WITH` (CTEs are allowed) |
| **Keyword blocklist** | `DROP`, `DELETE`, `INSERT`, `UPDATE`, `ALTER`, `CREATE`, `REPLACE`, `TRUNCATE`, `ATTACH`, `DETACH`, `COPY`, `EXPORT`, `IMPORT`, `INSTALL`, `LOAD`, `CALL`, `PRAGMA`, `GRANT`, `REVOKE`, `SET` and DuckDB's file-reading functions (`read_csv`, `read_parquet`, `read_json`, `glob` and similar) are all rejected |
| **Own tables only** | The query is parsed by DuckDB before it runs and may read only the tenant database's own tables and views (and its CTEs). A file path used as a table, another database, and table functions other than `range`, `generate_series` and `unnest` are rejected |
| **Max length** | 4 000 characters |
| **Tenant isolation** | Each query runs against a physically separate DuckDB file — no cross-tenant data leakage |

### Available Tables

The tenant's own tables. The most useful:

| Table | Description |
|-------|-------------|
| `detection_rules` | Synced rules: `rule_id`, `siem_id`, `space`, `name`, `severity`, `enabled`, `score` and its parts, `mitre_ids`, `raw_data` |
| `rule_score_history` | Each rule's score over time |
| `checkedRule` | Rule validations: when and by whom |
| `rule_links` | Linked copies of a rule in other destinations |
| `threat_actors` | The client's threat actors from its CTI feeds: `name`, `aliases`, `origin`, `ttps`, `ttp_count` |
| `systems`, `hosts`, `software_inventory` | Systems, their devices, and installed software (CPE 2.3) |
| `vuln_detections` | CVEs matched to software |
| `playbooks`, `playbook_steps`, `step_techniques` | Baselines, their techniques, and the ATT&CK ids on each |
| `step_detections`, `applied_detections` | Rules mapped to baseline techniques, and where they apply |
| `blind_spots` | Known gaps and N/A marks |
| `system_baselines`, `system_coverage_destinations` | Baselines applied to systems, and which destinations count for each system |
| `system_baseline_snapshots` | Point-in-time coverage captures |

ATT&CK reference data (`mitre_techniques` and similar) is not in the tenant database and can't be queried. Nor can the SIEM connection settings TIDE keeps there for its own use.

### Request Format

**Single-tenant user (client_id optional):**

```json
{
  "sql": "SELECT rule_id, name, severity, score FROM detection_rules ORDER BY score DESC LIMIT 10"
}
```

**Multi-tenant user (client_id required):**

Replace `<TENANT_CLIENT_ID>` with the full UUID returned by `GET /api/external/clients`. The `id` field is the **complete UUID** (e.g. `1b650e71-db8e-4de4-852a-d67cada3fed7`) — do **not** abbreviate it, the API string-compares the value against `user_clients.client_id` and any truncation returns `403 Forbidden`.

```json
{
  "sql": "SELECT rule_id, name, severity, score FROM detection_rules ORDER BY score DESC LIMIT 10",
  "client_id": "<TENANT_CLIENT_ID>"
}
```

### Response Format

```json
{
  "columns": ["rule_id", "name", "severity", "space", "score"],
  "rows": [
    {
      "rule_id": "abc-123-def",
      "name": "Webshell Tool Reconnaissance Activity",
      "severity": "high",
      "space": "production",
      "score": 95
    }
  ],
  "row_count": 1
}
```

### curl Examples

> ⚠️ **Replace `your-tide-host` with the actual hostname of your TIDE deployment** (e.g. `tide.example.local`, or `tide` if it resolves on your network). Leaving the literal placeholder will cause curl to fail with `Could not resolve host` (exit code 6) and return no output.
>
> Replace `YOUR_KEY_HERE` with the API key shown once at creation time in **Settings → API Key Management**.
>
> Add `-k` if your TIDE instance uses a self-signed certificate.

**Step 1 — Discover your tenants:**

```bash
curl -s https://your-tide-host/api/external/clients \
  -H "X-TIDE-API-KEY: YOUR_KEY_HERE"
```

```json
{
  "clients": [
    {"id": "1b650e71-db8e-4de4-852a-d67cada3fed7", "name": "Primary Client", "slug": "primary"},
    {"id": "8bab9263-2c1b-4b0f-9288-407729eef30d", "name": "DC",             "slug": "dc"}
  ]
}
```

> **Use the full `id` UUID verbatim** as `client_id` in subsequent `POST /api/external/query` calls. Truncated values (e.g. `8bab9263-...`) are not pattern-matched by the API and will return `403 Forbidden`.

**Step 2 — Query a tenant (single-tenant users can omit client_id):**

**Count all detection rules:**

```bash
curl -s -X POST https://your-tide-host/api/external/query \
  -H "Content-Type: application/json" \
  -H "X-TIDE-API-KEY: YOUR_KEY_HERE" \
  -d '{"sql": "SELECT COUNT(*) AS total_rules FROM detection_rules"}'
```

```json
{"columns":["total_rules"],"rows":[{"total_rules":239}],"row_count":1}
```

**Query a specific tenant:**

Replace `<TENANT_CLIENT_ID>` with a full UUID from `GET /api/external/clients`. The example below uses the `DC` tenant from the previous response.

```bash
curl -s -X POST https://your-tide-host/api/external/query \
  -H "Content-Type: application/json" \
  -H "X-TIDE-API-KEY: YOUR_KEY_HERE" \
  -d '{"sql": "SELECT rule_id, name, severity, score FROM detection_rules WHERE score IS NOT NULL ORDER BY score DESC LIMIT 5", "client_id": "<TENANT_CLIENT_ID>"}'
```

```json
{
  "columns": ["rule_id", "name", "severity", "score"],
  "rows": [
    {"rule_id": "a1b2c3", "name": "Credential Dumping via LSASS", "severity": "critical", "score": 98},
    {"rule_id": "d4e5f6", "name": "Suspicious PowerShell Execution", "severity": "high", "score": 92}
  ],
  "row_count": 2
}
```

**Get threat actors with their TTP count:**

```bash
curl -s -X POST https://your-tide-host/api/external/query \
  -H "Content-Type: application/json" \
  -H "X-TIDE-API-KEY: YOUR_KEY_HERE" \
  -d '{"sql": "SELECT name, origin, ttp_count FROM threat_actors ORDER BY ttp_count DESC LIMIT 5"}'
```

**Coverage summary using a CTE:**

```bash
curl -s -X POST https://your-tide-host/api/external/query \
  -H "Content-Type: application/json" \
  -H "X-TIDE-API-KEY: YOUR_KEY_HERE" \
  -d '{"sql": "WITH summary AS (SELECT space, COUNT(*) AS rules, AVG(score) AS avg_score FROM detection_rules GROUP BY space) SELECT * FROM summary ORDER BY avg_score DESC"}'
```

```json
{
  "columns": ["space", "rules", "avg_score"],
  "rows": [
    {"space": "production", "rules": 180, "avg_score": 72.4},
    {"space": "staging", "rules": 59, "avg_score": 65.1}
  ],
  "row_count": 2
}
```

### Fully-Worked End-to-End Example

This is what a real working session looks like. The hostname (`tide.example.local`), the API key, and the `client_id` UUID are **all** filled in with realistic values — copy this pattern and substitute your own hostname, key, and tenant ID.

**1. List tenants:**

```bash
curl -s -k https://tide.example.local/api/external/clients \
  -H "X-TIDE-API-KEY: 2Ln5RLGZ6gFqsTB75_LdrmnRkkAY8KLorKuJV7jn6Sg"
```

```json
{"clients":[
  {"id":"1b650e71-db8e-4de4-852a-d67cada3fed7","name":"Primary Client","slug":"primary"},
  {"id":"8bab9263-2c1b-4b0f-9288-407729eef30d","name":"DC","slug":"dc"},
  {"id":"c59b8726-cd15-40ad-b5bd-fe2da6f3fae7","name":"Marvel","slug":"marvel"}
]}
```

**2. Query the `Marvel` tenant using its full UUID:**

```bash
curl -s -k -X POST https://tide.example.local/api/external/query \
  -H "Content-Type: application/json" \
  -H "X-TIDE-API-KEY: 2Ln5RLGZ6gFqsTB75_LdrmnRkkAY8KLorKuJV7jn6Sg" \
  -d '{"sql": "SELECT rule_id, name, severity, score FROM detection_rules WHERE score IS NOT NULL ORDER BY score DESC LIMIT 5", "client_id": "c59b8726-cd15-40ad-b5bd-fe2da6f3fae7"}'
```

```json
{
  "columns": ["rule_id","name","severity","score"],
  "rows": [
    {"rule_id":"a1b2c3","name":"Credential Dumping via LSASS","severity":"critical","score":98},
    {"rule_id":"d4e5f6","name":"Suspicious PowerShell Execution","severity":"high","score":92}
  ],
  "row_count": 2
}
```

### Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| curl exits with code **6** (`Could not resolve host`) and no JSON | URL still contains the literal `your-tide-host` placeholder | Replace `your-tide-host` with your real TIDE hostname |
| curl exits with code **60** (SSL certificate problem) | Self-signed cert on TIDE | Add `-k` to the curl command |
| `401 Unauthorized` | Missing/invalid `X-TIDE-API-KEY` header | Re-generate the key in **Settings → API Key Management** |
| `403 Forbidden` on a query | `client_id` truncated, mistyped, or not assigned to your user | Use the exact full UUID from `GET /api/external/clients` |
| `400 Bad Request` mentioning a keyword | SQL contains a blocked keyword (`DROP`, `INSERT`, `PRAGMA`, etc.) | Rewrite as a `SELECT`/`WITH` query only |

### Migration from v3 API

If you were using the external query API before v4:

| Before (v3) | After (v4) |
|-------------|-----------|
| Queries ran against shared `tide.duckdb` with auto-filtered views | Queries run against isolated tenant databases |
| `client_id` was implicit (tied to the `api_keys` table) | `client_id` is explicit in the request body (or auto-resolved for single-tenant users) |
| No tenant discovery endpoint | Use `GET /api/external/clients` to list your tenants |

**For single-tenant users, the API is backward compatible — existing scripts will work without changes.** Multi-tenant users need to add the `client_id` field to their requests.
---

## Project Structure

```
📂 TIDE/
├── 📂 app/
│   ├── 📂 api/           # FastAPI route handlers (pages' partials, the external API)
│   ├── 📂 engine/        # CVE, KEV and CPE matching
│   ├── 📂 models/        # Pydantic schemas
│   ├── 📂 services/      # Database, sync, CTI connectors, reports, diagnostics
│   ├── 📂 scripts/       # Operator tools (diag_sync, compact_duckdb)
│   ├── 📂 templates/     # Jinja2 HTML templates
│   ├── 📂 static/        # CSS, JS, icons
│   └── main.py           # FastAPI entry point
├── 📂 data/              # Persistent database files (a volume)
├── 📂 nginx/             # Nginx configuration
├── docker-compose.yml    # Production orchestration
└── .env.example          # Environment template
```

---

## Contributing

Report problems and suggestions through your TIDE support contact.

---