# Configuration

How to configure TIDE: the settings in `.env`, the certificates in `certs/`, single sign-on with Keycloak, and users and roles.

[← Back to the README](../README.md)

**Contents:** [Settings (`.env`)](#settings-env) · [Certificates](#certificates) · [Single sign-on with Keycloak](#single-sign-on-with-keycloak) · [Users, roles and sign-in](#users-roles-and-sign-in) · [Integrations](#integrations)

---

## Settings (`.env`)

TIDE reads its settings from `.env`, next to `docker-compose.yml`. Start from `.env.example`. After changing a setting, apply it with:

```bash
docker compose up -d
```

### Required

| Setting | What it does |
|---------|--------------|
| `TIDE_VERSION` | The TIDE image tag to run, for example `6.1.4`. |
| `APP_URL` | The address people open TIDE at, for example `https://tide.example.local`. Single sign-on returns people here after they sign in, and sign-in cookies are marked secure when it starts with `https://`. |
| `SESSION_SECRET` | A long random string that signs sign-in sessions. TIDE will not start without it. Changing it signs out everyone using a TIDE account. Make one offline with `openssl rand -base64 48`. |

### First start

| Setting | What it does |
|---------|--------------|
| `BOOTSTRAP_ADMIN_USERNAME`, `BOOTSTRAP_ADMIN_PASSWORD` | The first administrator, created only when TIDE starts with no users at all. If not set, the account is `admin` / `TIDEadmin`: change that password straight after signing in. |

### Single sign-on

Only needed if you use Keycloak. See [Single sign-on with Keycloak](#single-sign-on-with-keycloak). These lines are read once: the first time TIDE starts with them set, it makes them the **Keycloak** integration, and after that you manage Keycloak in TIDE and the lines are not read. Diagnostics says if they still differ from the integration.

| Setting | What it does |
|---------|--------------|
| `KEYCLOAK_URL` | Keycloak's address as people's browsers reach it. |
| `KEYCLOAK_INTERNAL_URL` | Keycloak's address as the TIDE container reaches it, if different (for example a Docker service name). |
| `KEYCLOAK_REALM` | The realm TIDE signs people in with. Default `tide`. |
| `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET` | The TIDE client in that realm and its secret. Default client `tide-app`. |
| `KEYCLOAK_PASSWORD_GRANT_CLIENT_ID`, `KEYCLOAK_PASSWORD_GRANT_CLIENT_SECRET` | Optional. A Keycloak client that lets people type their single sign-on password into TIDE's own sign-in form. Without it, TIDE tries the client above. |
| `SSL_VERIFY` | Whether TIDE checks Keycloak's certificate when signing people in, until Keycloak is an integration (then its **Verify TLS certificate** box does). Default `true`. |

### Optional

| Setting | What it does |
|---------|--------------|
| `BACKUP_PATH` | The host folder backups are saved in (default `backups/` next to `docker-compose.yml`). Another disk is better: a backup on the same disk as `data/` won't survive that disk failing. See [Scheduled backups](OPERATIONS.md#scheduled-backups). |
| `RULE_LOG_PATH` | A host folder that receives a copy of each daily rule-log export. They are always written to `data/log/rules/` as well. See [Rule-log export](OPERATIONS.md#rule-log-export). |
| `ELASTIC_APM_ENABLED` and the other `ELASTIC_APM_*` settings | Send TIDE's own performance traces to an Elastic APM server. `.env.example` turns this on; set `ELASTIC_APM_ENABLED=false` if you have no APM server. |
| `AUTH_DISABLED` | `true` turns sign-in off entirely. Only for isolated testing; never on a live install. |

Your SIEMs, OpenCTI, GitLab and Keycloak instances are not set in `.env`. They are added in TIDE itself: see [Integrations](#integrations).

---

## Certificates

TIDE uses three files in the `certs/` folder next to `docker-compose.yml`:

| File | Used for |
|------|----------|
| `server.crt`, `server.key` | The certificate and key the `tide-nginx` container presents to browsers on port 443. Use a certificate whose name matches `APP_URL`. |
| `ca.crt` | Your organisation's CA certificate, which TIDE trusts for its outgoing connections. It must exist: if you have no internal CA, copy `server.crt` to `ca.crt`. |

### Checking your integrations' certificates

Every SIEM, OpenCTI connector, GitLab and Keycloak entry in TIDE has its own **Verify TLS certificate** box.

- **Off (the default):** TIDE connects without checking the certificate. This suits a standalone network with self-signed certificates.
- **On:** the integration's certificate must come from a public CA or from the CA in `certs/ca.crt`.

Use **Test Connection** on the integration's form to try a setting before saving it.

### When a certificate is refused

TIDE checks certificates as strictly as current browsers do. **Test Connection** says why a certificate was refused:

| Message | What to do |
|---------|------------|
| Not signed by a CA TIDE trusts | Save the CA that signed it as `certs/ca.crt`, then run `docker compose up -d`. |
| The CA certificate lacks extensions (for example *CA cert does not include key usage extension*) | Your CA was created without fields that TLS now requires. Reissue it with `basicConstraints = critical, CA:TRUE` and `keyUsage = critical, keyCertSign, cRLSign`, then reissue the server certificate from it. |
| Does not name this host | The server certificate must list the exact host name (or IP address) used in the integration's URL under *Subject Alternative Name*. |
| Outside its validity dates | Renew the certificate. |

`SSL_VERIFY` in `.env` covers only Keycloak sign-in from `.env`, not your integrations. Once Keycloak is an integration, its own box applies.

---

## Single sign-on with Keycloak

TIDE always has its own accounts. Keycloak adds single sign-on alongside them: the sign-in page then offers **Sign in with SSO**.

### 1. Create the client in Keycloak

In your realm, create an **OpenID Connect** client for TIDE:

| Keycloak setting | Value |
|------------------|-------|
| Client ID | `tide-app` (or your own, set as `KEYCLOAK_CLIENT_ID`) |
| Client authentication | **On** (a confidential client). Copy its secret into `KEYCLOAK_CLIENT_SECRET`. |
| Standard flow | **On** |
| Valid redirect URIs | `<APP_URL>/auth/callback`, for example `https://tide.example.local/auth/callback` |
| Valid post logout redirect URIs | `<APP_URL>/login*` |
| Web origins | `<APP_URL>` |
| Direct access grants | Optional. Turn on to let people sign in with their Keycloak password through TIDE's own sign-in form. |

### 2. Send group membership in the token

Add a **Group Membership** mapper to the client (token claim name `groups`), so TIDE can see each person's groups.

### 3. Tell TIDE about Keycloak

In **Settings → Management → Integrations**, click **Add integration** and choose **Keycloak**. Enter its **Address** (as people's browsers reach it), the **Internal address** if the TIDE container reaches it at a different one, the **Realm**, the **Client ID** and the **Client secret**, and a **Password-grant client** if people should type their Keycloak password into TIDE's own sign-in form. Saving checks that the realm answers, so a mistake can't stop everyone signing in.

Or set `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID` and `KEYCLOAK_CLIENT_SECRET` in `.env` (and `KEYCLOAK_INTERNAL_URL` if the container reaches Keycloak at a different address), then run `docker compose up -d`: the first start makes them the Keycloak integration, first in the list, and from then on you manage it in TIDE.

There is one Keycloak integration, the one TIDE signs people in with. If you delete it, sign-in uses the Keycloak settings in `.env` again, and the next start makes the integration from them again.

### How TIDE treats single sign-on users

- **First sign-in creates the account.** TIDE gives the person a role on the Primary Client from their Keycloak groups or realm roles: a group or role named `admin`, `engineer` or `analyst` (or the plural) gives that role; otherwise they become an Analyst.
- **Platform Admin.** Membership of a Keycloak group named `superadmin` makes someone a TIDE super admin, but only when their account is first created. After that, roles and Platform Admin are managed in TIDE (Management → Users), and Keycloak changes don't alter them.
- **Matching existing accounts.** A person is matched to an existing TIDE account by their Keycloak ID, then username, then email. Accounts that are only TIDE accounts are never linked to single sign-on automatically.

---

## Users, roles and sign-in

### Roles on each client

Each person can hold one or more roles on each client, and different roles on different clients. On a client, a person can do whatever any of their roles there allows.

| Role | Typically |
|------|-----------|
| **Admin** | Manages the client: its users, roles, destinations and settings. |
| **Analyst** | Works with rules, baselines, systems and threats. |
| **Engineer** | Reads dashboards, coverage and reports. |
| **Support** | Opens **Diagnostics** for that client only. Granted and removed by super admins only. |

What each role may read and change is set per client in its **Role Templates**, on the client's page in Management.

### Platform Admin (super admin)

Super admins see every client and every setting, and set up the integrations every client uses. Grant or revoke it with **Platform Admin** in Management → Users, or in Diagnostics → Access. You can't change your own.

### Sessions

- A sign-in with a TIDE account lasts 24 hours.
- Signing out ends all of that person's TIDE sessions, in every browser. So does changing their password, an admin resetting it, or deactivating their account.
- Single sign-on sessions end through Keycloak when the person signs out.

### API keys

Each person creates their own API keys for the [External Query API](API.md) in **Settings → Profile & Preferences → API Key Management**. A key can read the clients its owner belongs to, and stops working while its owner is deactivated.

---

## Integrations

Integrations are added in TIDE. Super admins add them under **Settings → Management → Integrations** with **Add integration**, choosing what to add, and each has its own address, credentials and **Verify TLS certificate** setting. The list shows every integration, the Keycloak TIDE signs in with first; **Group by** → **Type** puts them in a group for each kind:

| Integration | Group | Used for |
|-------------|-------|----------|
| **SIEM** (Elastic) | SIEMs | Reading and writing detection rules. Splunk and Sentinel SIEMs can be recorded but don't sync yet. |
| **OpenCTI** | Threat intel | The threat actors (intrusion sets) Threat Landscape adds to ATT&CK's. |
| **GitLab** | Source control | The GitLab whose projects clients link, for rule backup and issues (see [Link GitLab projects](CLIENTS.md#link-gitlab-projects)). It has no token of its own: each project has its own. |
| **Keycloak** | Identity | Single sign-on: TIDE signs people in with it (see [Single sign-on with Keycloak](#single-sign-on-with-keycloak)). There is one. |

A client's admins then link the SIEM spaces and connectors their client should use from the client's page. Credentials are stored encrypted with the key in `data/credentials.key`; see [Backups](OPERATIONS.md#backups-and-upgrades).
