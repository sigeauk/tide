# Threat Informed Detection Engine (TIDE)

TIDE is a **standalone, containerized platform** for Detection Engineering lifecycle management. It provides a "Human-in-the-Loop" interface for managing detection rules, analyzing threat coverage, and automating security workflows.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                         NGINX                               │
│              (Reverse Proxy + SSL Termination)              │
│                      Port 80/443                            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                        FASTAPI                              │
│                (REST API + HTMX Endpoints)                  │
│                       Port 8000                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                        DUCKDB                               │
│              (Embedded Analytics Database)                  │
│                   /app/data/tide.duckdb                     │
└─────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| **Reverse Proxy** | Nginx | SSL termination, static assets, rate limiting |
| **Backend** | FastAPI (Python) | REST API, HTMX partials, business logic |
| **Database** | DuckDB | Embedded analytics DB, zero external dependencies |
| **Frontend** | HTMX + Jinja2 | Server-rendered HTML with dynamic updates |
| **Styling** | Custom Semantic CSS | Hex-based design system (GitHub dark theme palette) |
| **Auth** | Keycloak (optional) | OIDC SSO for enterprise deployments |

---

## Key Features
### Dashboard
- Real-time metrics for rule counts, quality scores, and validation status
- Quick overview of detection engineering program health
- Kibana space breakdown (Staging, Production)

### Threat Landscape
- Threat actor tracking from OpenCTI
- Dynamic TTP coverage calculation per actor
- Country attribution with visual flags
- Global coverage metrics

### Rule Promotion
- Staging → Production workflow
- Quality gates before promotion
- Rule details modal with MITRE mappings

### Rule Health
- Scoring engine (0-100) based on:
  - **Quality Score (50 pts)**: Field mappings, query language, search time
  - **Meta Score (50 pts)**: Investigation guides, MITRE mappings, author
- 12-week validation cycle tracking
- Visual traffic light system

### MITRE ATT&CK Heatmap
- Interactive technique coverage visualization
- Gap analysis across tactics
- Coverage percentages per tactic

### Sigma Conversion
- Convert Sigma rules to Elastic formats
- Multi-format output: KQL, Lucene, EQL, ES|QL

---

## Deployment Models

### Client Deployment Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT ENVIRONMENT                       │
│                                                             │
│  ┌─────────────────┐          ┌─────────────────┐           │
│  │  TIDE Container │ ◀─────▶ │  Elastic SIEM   │           │
│  │ (GitHub Image)  │  Sync    │  (Detections)   │           │
│  └─────────────────┘          └─────────────────┘           │
│           │                                                 │
│           │ Reports                                         │
│           ▼                                                 │
│  ┌─────────────────┐                                        │
│  │  Internal GitLab│  ◀── Reports dispatched here          │
│  │  (Client-owned) │                                        │
│  └─────────────────┘                                        │
└─────────────────────────────────────────────────────────────┘
```

**Key Points:**
- Docker images are pulled from **GitHub Container Registry**
- TIDE syncs detection rules from the client's **Elastic SIEM**
- Reports are dispatched to the client's **internal GitLab** (not GitHub)
- No outbound internet required after initial container pull

---

## Installation

### Prerequisites

- Docker & Docker Compose v2+
- Access to Elastic Security (Kibana) with API key
- (Optional) OpenCTI instance for threat intelligence
- (Optional) Internal GitLab for report dispatching

### Quick Start (Development)

```bash
# Clone the repository
git clone https://github.com/sigeauk/tide.git`
cd tide
```
```bash
# Create environment file
cp .env.example .env
```
```bash
# Configure minimum required settings
nano .env
```
```bash
# Start TIDE
docker compose up --build -d
```
```bash
# Access the UI
open http://localhost:8000
```


### Production Deployment (Nginx + SSL)

```bash
# Configure SSL certificates in nginx/
# Update docker-compose.yml with production settings
docker compose up -d
```

### Air-Gapped Deployment

```bash
# On connected machine - save images
docker save tide:latest | gzip > tide.tar.gz
```
```bash
# Transfer to air-gapped system
# On air-gapped machine
docker load < tide.tar.gz
docker compose up -d
```

---

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

```env
# Required - Elastic Security
ELASTIC_URL="https://kibana.yourdomain.local:5601"
ELASTICSEARCH_URL="https://elasticsearch.yourdomain.local:9200"
ELASTIC_API_KEY="your-api-key"

# Optional - Authentication
AUTH_DISABLED=false
KEYCLOAK_URL="http://keycloak:8080"

# Optional - Threat Intelligence
OPENCTI_URL="https://opencti.yourdomain.local:8080"
OPENCTI_TOKEN="your-token"

# Optional - Report Dispatching
GITLAB_URL="https://gitlab.internal.local/"
GITLAB_TOKEN="your-token"
```

### Configuration Reference

| Variable | Description | Required |
|----------|-------------|----------|
| `ELASTIC_URL` | Kibana URL | ✅ |
| `ELASTICSEARCH_URL` | Elasticsearch URL | ✅ |
| `ELASTIC_API_KEY` | API key with detection rules access | ✅ |
| `KIBANA_SPACES` | Comma-separated spaces (e.g., `production,staging`) | ❌ |
| `AUTH_DISABLED` | Set `true` to bypass Keycloak | ❌ |
| `OPENCTI_URL` | OpenCTI platform URL | ❌ |
| `GITLAB_URL` | Internal GitLab for reports | ❌ |
| `SYNC_INTERVAL_MINUTES` | Background sync interval (default: 60) | ❌ |

---

## Design System

| Principle | Implementation |
|-----------|----------------|
| **HSL Variable Engine** | Base hue: 220 (Blue), Chroma: 0.05 |
| **4-Layer Elevation** | Layer 0→3: 10%→28% lightness |
| **Depth Simulation** | Border-top highlights 15-20% lighter |
| **Typography** | 14px base, Manrope font, 100%/75%/60% lightness hierarchy |
| **Semantic Pills** | Severity (Critical→Low), MITRE status (covered/gap/defense) |
| **Glow Effects** | Pill shadows matching status colors |

Theme uses a static hex-based palette defined in `style.css` CSS variables.
Light/dark mode is toggled via the `body.light` class.

---

## Data Persistence

### Persistent Data (Survives Updates)

Located in `/app/data/` (volume mounted):

| File | Purpose |
|------|---------|
| `tide.duckdb` | Rule cache, coverage calculations |
| `checkedRule.json` | Analyst validation records |
| `triggers/*` | Sync state files |

### Transient Data (Recalculated)

| Data | Calculation |
|------|-------------|
| Quality Scores | Live from rule metadata |
| Coverage % | Live from enabled rules vs MITRE |
| Meta Scores | Live from rule completeness |

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

Every request must include an API key in the `X-TIDE-API-KEY` header. Keys are created in the TIDE UI under **Settings → Profile → API Key Management**. Only the SHA-256 hash of the key is stored — the raw key is shown once at creation time.

The API key inherits the tenant access of its creator via the `user_clients` table. To grant an API key access to additional tenants, assign the owning user to those clients in the Management Hub.

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
| **SELECT only** | The SQL must start with `SELECT` or `WITH` (CTEs are allowed) |
| **Keyword blocklist** | `DROP`, `DELETE`, `INSERT`, `UPDATE`, `ALTER`, `CREATE`, `REPLACE`, `TRUNCATE`, `ATTACH`, `DETACH`, `COPY`, `EXPORT`, `IMPORT`, `INSTALL`, `LOAD`, `CALL`, `PRAGMA`, `GRANT`, `REVOKE`, `SET` are all rejected |
| **Max length** | 4 000 characters |
| **Read-only DB** | Tenant database is opened in read-only mode — writes are impossible even if SQL validation were bypassed |
| **Tenant isolation** | Each query runs against a physically separate DuckDB file — no cross-tenant data leakage |

### Available Tables

| Table | Description |
|-------|-------------|
| `detection_rules` | Synced detection rules (rule_id, name, severity, space, score, quality_score, etc.) |
| `threat_actors` | Threat actors with TTPs, aliases, and origin |
| `mitre_techniques` | Full MITRE ATT&CK technique library |
| `systems` | Top-level environments / systems |
| `hosts` | Devices within a system |
| `software_inventory` | Installed packages with CPE 2.3 strings |
| `vuln_detections` | CVE-to-rule mappings |
| `applied_detections` | Active detections per system/host |
| `blind_spots` | Accepted risk / known gaps |
| `playbooks` | Baseline definitions |
| `playbook_steps` | Tactics within a baseline |
| `step_techniques` | Techniques per tactic |
| `step_detections` | Detection rules per tactic |
| `system_baselines` | Baselines applied to systems |
| `system_baseline_snapshots` | Point-in-time audit captures |
| `classifications` | Classification labels |
| `app_settings` | Application settings (key/value) |

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
> Replace `YOUR_KEY_HERE` with the API key shown once at creation time in **Settings → Profile → API Key Management**.
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
| `401 Unauthorized` | Missing/invalid `X-TIDE-API-KEY` header | Re-generate the key in **Settings → Profile → API Key Management** |
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
│   ├── 📂 api/           # FastAPI route handlers
│   ├── 📂 models/        # Pydantic schemas
│   ├── 📂 services/      # Business logic layer
│   ├── 📂 templates/     # Jinja2 HTML templates
│   ├── 📂 static/        # CSS, JS, icons
│   └── main.py           # FastAPI entry point
├── 📂 data/              # Persistent database files
├── 📂 nginx/             # Nginx configuration
├── docker-compose.yml    # Production orchestration
├── .env.example          # Environment template
└── DOCS_ARCHITECTURE.md  # Detailed architecture docs
```

See [DOCS_ARCHITECTURE.md](DOCS_ARCHITECTURE.md) for complete documentation.

---

## Contributing

Contributions welcome! Please read the architecture documentation and submit PRs to the `develop` branch.

---