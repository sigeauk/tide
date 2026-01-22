# Threat Informed Detection Engine (TIDE)

![TIDE](./app/static/TIDE.png)

TIDE is a modular threat intelligence and detection platform designed to streamline the management, analysis, and automation of threat data. It integrates with Elasticsearch, GitLab, and Sigma rules to provide a robust solution for security teams.

---

## 🚀 Features

### 📊 Dashboard
- **Real-time Metrics**: View total rules, average quality scores, validation status, and coverage statistics
- **Quick Overview**: At-a-glance health of your detection engineering program
- **Space Breakdown**: See rules distributed across Kibana spaces (Staging, Production, etc.)

### 🌊 Threat Landscape
- **Actor Tracking**: Syncs Intrusion Sets/Threat Actors from OpenCTI
- **Coverage Calculation**: Dynamically calculates TTP coverage per actor based on enabled rules
- **Country Attribution**: Visual country flags for threat actor origin
- **Global Metrics**: View total TTP coverage across the entire estate

### 🚀 Rule Promotion
- **Staging → Production Workflow**: Promote validated rules from staging to production Kibana spaces
- **Quality Gates**: View quality and meta scores before promotion
- **Rule Details Modal**: 
  - MITRE ATT&CK hierarchy (Tactics → Techniques)
  - Investigation guides
  - Highlighted fields
  - Timestamp override configuration
  - Author attribution

### 🩺 Rule Health
- **Scoring Engine**: Automatically rates rules (0-100) based on:
  - **Quality Score (50 pts)**: Field mappings, field types, search time, query language
  - **Meta Score (50 pts)**: Investigation guide, timestamp override, MITRE mappings, author, highlighted fields
- **Review Lifecycle**: Track when a rule was last validated and by whom
- **Visual Indicators**: Traffic light system for quality and overdue badges (12-week validation cycle)
- **Card View**: Beautiful rule cards with severity, MITRE techniques, and validation status

### 🗺️ MITRE ATT&CK Heatmap
- **Visual Coverage**: Interactive heatmap showing technique coverage across the MITRE ATT&CK matrix
- **Gap Analysis**: Identify uncovered techniques at a glance
- **Tactic Breakdown**: Coverage percentages per tactic

### 📊 Presentation Mode
- **Executive Dashboards**: Clean visualizations for stakeholder presentations
- **Exportable Metrics**: Key statistics ready for reporting

### 🎯 Attack Tree Integration
- **Campaign Tracking**: Manage and visualize purple team exercises and attack scenarios using the Attack Tree module.
- **Coverage Validation**: Map detection rules to adversary emulation results

### 🔄 SIGMA Conversion
- **Rule Conversion**: Convert SIGMA rules to Elastic query formats
- **Multi-format Support**: Output to KQL, Lucene, EQL, or ES|QL

### ⚙️ Settings
- **Sync Controls**: Manual sync triggers for rules and threat intelligence
- **Configuration Management**: View and update integration settings
- **License Management**: Built-in license validation

---


- **Frontend (UI)**: Streamlit on Port 8501 - Visualizes data and captures analyst actions
- **Backend (Worker)**: Python Scheduler - Syncs data from APIs, calculates scores, runs heavy logic
- **Authentication**: Keycloak OIDC - Enterprise SSO with local bypass mode for development
- **Database**: DuckDB (`tide.duckdb`) - Fast analytical queries for dashboards
- **Source of Truth**:
  - *Detection Logic*: Elastic Security API
  - *Threat Intelligence*: OpenCTI API
  - *Human Context*: `checkedRule.json` (Git-managed validation records)

---

## 🛠️ Installation

### Prerequisites

- Docker & Docker Compose v2+
- Access to Elastic Security (Kibana) with API key
- (Optional) OpenCTI instance for threat intelligence
- (Optional) GitLab for GitOps workflow

### Quick Start (Development Mode)

1. **Clone the repository**
   ```bash
   git clone https://github.com/sigeauk/tide.git
   cd tide
   ```

2. **Create environment file**
   ```bash
   cp env-sample .env
   ```

3. **Configure `.env`** (minimum required):
   ```env
   # Elastic Security (Required)
   ELASTIC_URL="http://your-kibana:5601"
   ELASTICSEARCH_URL="http://your-elasticsearch:9200"
   ELASTIC_API_KEY="your-api-key-here"
   
   # Disable auth for local development
   AUTH_DISABLED=true
   ```

4. **Start TIDE**
   ```bash
   docker compose up --build -d
   ```

5. **Access the UI**
   - TIDE: http://localhost:8501

---

## 🔐 Standalone System Setup (Air-Gapped / Production)

For deploying TIDE on an isolated network with full authentication:

### 1. Pre-requisites on Standalone System

Ensure Docker images are available (transfer via portable media if air-gapped):
```bash
# On connected system, save images
docker save tide-ui:1.1.0 tide-worker:1.1.0 | gzip > tide-images.tar.gz

# On standalone system, load images
docker load < tide-images.tar.gz
```

### 2. Configure Environment Variables

Create `.env` with full configuration:

```env
# ===== Elastic Security =====
ELASTIC_URL="https://kibana.yourdomain.local:5601"
ELASTICSEARCH_URL="https://elasticsearch.yourdomain.local:9200"
ELASTIC_API_KEY="your-elastic-api-key"

# ===== OpenCTI (Optional) =====
OPENCTI_URL="https://opencti.yourdomain.local:8080"
OPENCTI_TOKEN="your-opencti-token"

# ===== GitLab (Optional) =====
GITLAB_URL="https://gitlab.yourdomain.local/"
GITLAB_TOKEN="your-gitlab-token"

# ===== Sync Settings =====
SYNC_INTERVAL_MINUTES=60
TIDE_VERSION="1.1.1"

# ===== MITRE ATT&CK Sources =====
# For air-gapped: host these files locally
MITRE_SOURCE="https://your-local-server/enterprise-attack.json"
MITRE_MOBILE_SOURCE="https://your-local-server/mobile-attack.json"
MITRE_ICS_SOURCE="https://your-local-server/ics-attack.json"

# ===== Authentication (Keycloak) =====
AUTH_DISABLED=false
KEYCLOAK_URL="http://keycloak.yourdomain.local:8080"
KEYCLOAK_INTERNAL_URL="http://keycloak:8080"  # Docker internal
KEYCLOAK_REALM="tide"
KEYCLOAK_CLIENT_ID="tide-app"
KEYCLOAK_CLIENT_SECRET="your-client-secret"
APP_URL="https://tide.yourdomain.local:8501"
```

### 3. Configure Keycloak

1. **Access Keycloak Admin Console**: http://localhost:8080
   - Default credentials: `admin` / `admin`

2. **Create a Realm**:
   - Click "Create Realm"
   - Name: `tide`
   - Click "Create"

3. **Create a Client**:
   - Go to Clients → Create Client
   - Client ID: `tide-app`
   - Client authentication: ON
   - Valid redirect URIs: `http://localhost:8501/*` (or your production URL)
   - Web origins: `http://localhost:8501`

4. **Get Client Secret**:
   - Go to Clients → tide-app → Credentials
   - Copy the Client Secret to your `.env`

5. **Create Users**:
   - Go to Users → Add User
   - Set username, email, first/last name
   - Go to Credentials tab → Set Password

### 4. Deploy

```bash
# Build and start all services
docker compose up --build -d

# Check status
docker compose ps
```

### 5. Verify Installation

1. Navigate to http://localhost:8501 (or your configured URL)
2. You should be redirected to Keycloak login
3. Login with your created user
4. Verify the Dashboard loads with your Elastic rules

---

## 📁 Project Structure

```
📂 TIDE/
├── 📂 app/
│   ├── 📂 static/           # Images, flags, and icons
│   ├── 📂 pages/            # Streamlit pages
│   │   ├── 1_Dashboard.py
│   │   ├── 2_Threat_Landscape.py
│   │   ├── 3_Promotion.py
│   │   ├── 4_Rule_health.py
│   │   ├── 5_Heatmap.py
│   │   ├── 6_Pressentation.py
│   │   ├── 7_Attack_Tree.py
│   │   ├── 8_Sigma_Convert.py
│   │   └── 9_Settings.py
│   ├── 📂 static/           # Flags and icons
│   ├── auth.py              # Keycloak OIDC authentication
│   ├── cti_helper.py        # OpenCTI integration
│   ├── database.py          # DuckDB operations
│   ├── elastic_helper.py    # Elastic Security API
│   ├── git_helper.py        # GitLab integration
│   ├── Home.py              # Main entry point
│   ├── license_mgr.py       # License management
│   ├── log.py               # Logging utilities
│   ├── sigma_helper.py      # import and convert Sigma rules
│   ├── styles.py            # Global CSS styles
│   └── worker.py            # Background sync worker
├── docker-compose.yml       # Container orchestration
├── dockerfile               # Container build instructions
├── env-sample               # Example environment fileconfiguration
├── README.md                # This file
└── requirements.txt         # Python dependencies
```

---

## 🔧 Configuration Reference

| Variable | Description | Required |
|----------|-------------|----------|
| `ELASTIC_URL` | Kibana URL | ✅ |
| `ELASTICSEARCH_URL` | Elasticsearch URL | ✅ |
| `ELASTIC_API_KEY` | Elastic API key with detection rules access | ✅ |
| `OPENCTI_URL` | OpenCTI platform URL | ❌ |
| `OPENCTI_TOKEN` | OpenCTI API token | ❌ |
| `GITLAB_URL` | GitLab instance URL | ❌ |
| `GITLAB_TOKEN` | GitLab personal access token | ❌ |
| `SYNC_INTERVAL_MINUTES` | Background sync interval (default: 60) | ❌ |
| `AUTH_DISABLED` | Set `true` to bypass Keycloak auth | ❌ |
| `KEYCLOAK_URL` | Keycloak server URL (browser access) | ❌ |
| `KEYCLOAK_INTERNAL_URL` | Keycloak URL from Docker network | ❌ |
| `KEYCLOAK_REALM` | Keycloak realm name | ❌ |
| `KEYCLOAK_CLIENT_ID` | OIDC client ID | ❌ |
| `KEYCLOAK_CLIENT_SECRET` | OIDC client secret | ❌ |
| `APP_URL` | TIDE application URL for redirects | ❌ |

---

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to the `develop` branch.

---

## 📄 License

See [LICENSE](LICENSE) for details.

---

## 📞 Support

For issues and feature requests, please use the GitHub issue tracker.

---