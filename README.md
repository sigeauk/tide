# Threat Informed Detection Engine (TIDE)

TIDE shows which threats your SIEM's detection rules cover, where the gaps are, and how good each rule is. It brings your detection rules, MITRE ATT&CK, your CTI feeds and the systems you defend into one place, and a person makes and records every coverage decision. It runs as two Docker containers and needs no internet access once installed.

> **Inside TIDE:** this guide and the documents it links to are under your name at the bottom of the sidebar → **Settings → Documentation**, and the release notes under **Settings → Changelog**.

---

## Key features

- **Rule Health:** every detection rule from your SIEMs, scored for quality, with when it was last validated and which baseline techniques it covers. Move, copy, compare and edit rules across SIEM spaces.
- **Systems and baselines:** describe the environments you defend and the ATT&CK techniques each should detect, map rules to those techniques, and record known gaps. Coverage is worked out per system and exported as PDF or Markdown reports.
- **Threat landscape:** threat actors from ATT&CK and your CTI feeds, with how much of each one's behaviour your rules cover, plus heatmaps and the full ATT&CK and NIST 800-53 catalogues.
- **CTI:** indicators, actors and reports from OpenCTI, Mandiant, CrowdStrike and other TAXII feeds.
- **Multi-tenancy:** each client (team or customer) has its own database, users, roles and SIEM destinations. Nothing is shared between clients.
- **Dashboards and diagnostics:** dashboards built from the figures you choose, and built-in checks that find known problems and say how to fix them.
- **Offline by design:** ATT&CK, NIST 800-53, SigmaHQ, Elastic's detection rules and the CISA KEV catalogue are built into the image.

---

## Before you start

You need:

- A Linux host with **Docker** and **Docker Compose v2**.
- A **TLS certificate and key** for the address people will open TIDE at.
- For each SIEM: its Elasticsearch and Kibana addresses, and an **API key** that can read detection rules (and write them, if you will move or deploy rules from TIDE).
- Optional: a **Keycloak** realm for single sign-on, and **CTI feeds**.

---

## Quick start

These steps take a new host to a working TIDE. Run the commands in the folder you install TIDE into, for example `/opt/tide`.

### 1. Get the files

Copy `docker-compose.yml`, `.env.example` and the `nginx/` folder from this repository into the install folder.

### 2. Get the images

With internet access:

```bash
docker compose pull
```

Without it, save the images on a connected machine, copy the file across, and load it on the TIDE host:

```bash
# On the connected machine (use the release you want, for example 6.1.4)
docker save sigeauk/tide:<version> nginx:alpine | gzip > tide-images.tar.gz

# On the TIDE host
docker load < tide-images.tar.gz
```

### 3. Add your certificates

Create a `certs/` folder next to `docker-compose.yml` with three files:

| File | What it is |
|------|------------|
| `server.crt`, `server.key` | The certificate and key people's browsers see when they open TIDE. |
| `ca.crt` | Your organisation's CA certificate. TIDE trusts it when connecting to your SIEMs, Keycloak and CTI feeds. If you have no internal CA, copy `server.crt` to `ca.crt`; the file must exist. |

See [Certificates](docs/CONFIGURATION.md#certificates) for how strictly TIDE checks them.

### 4. Create your settings file

```bash
cp .env.example .env
```

Edit `.env` and set at least:

| Setting | Example | What it is |
|---------|---------|------------|
| `TIDE_VERSION` | `6.1.4` | The TIDE release to run. |
| `APP_URL` | `https://tide.example.local` | The address people open TIDE at. |
| `SESSION_SECRET` | *(a long random string)* | Signs sign-in sessions. TIDE won't start without it. Make one with `openssl rand -base64 48`. |
| `BOOTSTRAP_ADMIN_USERNAME`, `BOOTSTRAP_ADMIN_PASSWORD` | `admin`, *(a strong password)* | The first administrator, created on the first start only. |

If you have no Elastic APM server, also set `ELASTIC_APM_ENABLED=false`. Every setting is described in [Configuration](docs/CONFIGURATION.md).

### 5. Start TIDE

```bash
docker compose up -d
docker compose ps
```

`tide-app` shows as **healthy** within a minute or two; the first start takes longer while TIDE builds its databases. Then open `APP_URL` in a browser.

### 6. First sign-in

1. Sign in with the administrator from step 4, then change its password: your name at the bottom of the sidebar → **Settings → Profile & Preferences → Sign-in**.
2. **Add a SIEM:** Settings → Management → Integrations → SIEMs → **New SIEM**. Use **Test Connection** before saving.
3. **Set up a client:** a **Primary Client** already exists. Add more under Management → Tenants & Users → Clients for each team or customer whose data must stay separate.
4. **Link destinations:** open the client → **Linked SIEMs → Edit → Add SIEM**. Pick the SIEM and one of its Kibana spaces and give it a name such as "Prod". Add one for each space whose rules the client should see.
5. **Add people:** create users, or assign single sign-on users, with their roles, in Management → Tenants & Users → Users.
6. **Load the rules:** switch to the client, open **Rule Health** and choose **⋮ → Sync**.
7. **Turn on backups:** Settings → Management → **Backups** → tick **Back up every day at** and **Save**.

TIDE is ready. [Operations](docs/OPERATIONS.md) explains what to do next: syncing, CTI feeds, coverage and backups.

---

## Documentation

In TIDE, the whole guide is under **Settings → Documentation**, with a search.

| Document | Read it for |
|----------|-------------|
| [TIDE at a glance](docs/AT_A_GLANCE.md) | What TIDE does for your team, with your own figures in TIDE, and how to get the most from it. |
| [Getting started](docs/GETTING_STARTED.md) | Finding your way around: signing in, choosing a client, filters, windows, dashboards and your profile. |
| [Systems & baselines](docs/SYSTEMS.md) | Systems, baseline templates and their techniques, mapping rules, known gaps, risks, devices and CVEs. |
| [Threat intelligence](docs/THREATS.md) | Threat Landscape, the Heatmap, the MITRE pages and CTI, and making baselines from threats. |
| [Rules](docs/RULES.md) | Rule Health, the rule window, editing, validating, moving and merging rules, and Elastic and Sigma updates. |
| [Sigma, Elastic & Hunting](docs/LIBRARIES.md) | Converting Sigma rules, deploying Elastic's rules, and running hunts. |
| [Setting up clients](docs/CLIENTS.md) | SIEMs, clients, destinations, users and roles, validation, scoring and threat feeds. |
| [Configuration](docs/CONFIGURATION.md) | Every `.env` setting, certificates and how strictly they are checked, single sign-on with Keycloak, users and roles. |
| [Operations](docs/OPERATIONS.md) | How TIDE runs day to day: syncing rules and CTI, how coverage is worked out, backups and upgrades, moving hosts, reclaiming disk space, Diagnostics and troubleshooting. |
| [External Query API](docs/API.md) | Reading TIDE's data from other tools over HTTPS: API keys, endpoints, what queries may do, and examples. |
| [Changelog](CHANGELOG.md) | What changed in each release. |

---

## Support

Report problems and suggestions through your TIDE support contact. Super admins can run **Settings → Diagnostics → Run all checks** first: each finding says what it means and what to do.
