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
| **Styling** | Tailwind CSS v4 | HSL Variable Engine (hue: 220, 4-layer elevation) |
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

## Design System (Sajid-Style HSL)

| Principle | Implementation |
|-----------|----------------|
| **HSL Variable Engine** | Base hue: 220 (Blue), Chroma: 0.05 |
| **4-Layer Elevation** | Layer 0→3: 10%→28% lightness |
| **Depth Simulation** | Border-top highlights 15-20% lighter |
| **Typography** | 14px base, Manrope font, 100%/75%/60% lightness hierarchy |
| **Semantic Pills** | Severity (Critical→Low), MITRE status (covered/gap/defense) |
| **Glow Effects** | Pill shadows matching status colors |

Customize theme by changing `--brand-hue` in CSS:
- `0` = Red
- `30` = Orange  
- `145` = Green
- `220` = Blue (default)
- `264` = Purple

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

## License

See [LICENSE](LICENSE) for details.

---

## Support

For issues and feature requests, use the GitHub issue tracker.