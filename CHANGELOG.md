# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.5] - 2026-02-11

### Added
- Icon paths for github and git-branch. 

### Added
- text highlighting to logging.

## [2.1.4] - 2026-02-11

### FIX
- CSS fix on setting -integration. 

### Added
- text highlighting to logging.

## [2.1.3] - 2026-02-10

### ADDED
- Added logging

## [2.1.2] - 2026-02-09

### FIXED
- Update the OpenCTI integration, to map correctly with Mitre Actors.

## [2.1.1] - 2026-02-05

### Changed
- Update CSS backend.

## [2.1.0] - 2026-02-05

### SECURITY
- Image vulnerability fix

### Fixed
- Logout via Keycloak. Users would stay logged in.
- Sidebar links not always working.
- sync to staging space only from promotion page.

## [2.0.7] - 2026-02-04

### Fixed
- Sigma syntax highlighting after HTMX navigation (no longer requires hard refresh)
- Search filter on Rule Health page now applies correctly to SQL query

### Changed
- Updated README and banner


## [2.0.6] - 2026-02-03

### Fixed
- Keycloak authentication token refresh (phantom login page issue)
- App now uses hostname for internal service communication

### Security
- Automatic token refresh using refresh_token cookie
- Proactive token refresh before expiration


## [2.0.5] - 2026-02-02

### Changed
- Updated `.env.example` with latest configuration options


## [2.0.4] - 2026-02-02

### Fixed
- Minor UI box styling improvements


## [2.0.3] - 2026-02-02

### Fixed
- MITRE pill styling consistency across all pages
- Dashboard crash from null reference
- Rule editor UI controls restoration

### Changed
- Home page revamped to app overview with polished icons
- Summary cards standardized across Promotion and Dashboard pages
- Sidebar navigation reordered


## [2.0.2] - 2026-02-01

### Fixed
- Threats and Heatmap page restoration
- Rule editor UI controls repair

### Removed
- Attack Tree and Presentation pages from sidebar
- Legacy Streamlit files and configuration


## [2.0.1] - 2026-01-31

### Added
- UI symmetry enforcement in rule editor (mirror layout)
- Architecture documentation (`DOCS_ARCHITECTURE.md`)
- HSL/Depth-based design system

### Fixed
- Page refresh issues on navigation

### Changed
- Complete UI refactor using HSL color system with depth-based elevation


## [2.0.0] - 2026-01-28

### ⚠️ BREAKING CHANGE: Complete Architecture Migration

**Migrated from Streamlit to FastAPI + HTMX stack**

This release represents a complete rewrite of the application frontend and backend.

### Added
- **FastAPI backend** with async request handling
- **HTMX-powered frontend** for seamless partial page updates
- **Jinja2 templating** with component-based architecture
- **Keycloak OIDC integration** for enterprise authentication
- **Sigma rule converter** with CodeMirror YAML editor
- **Rule Promotion workflow** page
- **User preferences** page
- **Nginx reverse proxy** with HTTPS termination
- **DuckDB** database for fast analytics
- Sidebar navigation with hover popups
- MITRE ATT&CK heatmap with technique details
- Rule cards with detailed modal views

### Changed
- Frontend: Streamlit → FastAPI + HTMX + Tailwind CSS
- Database: SQLite → DuckDB
- Auth: Basic auth → Keycloak OIDC with JWT
- Deployment: Single container → Docker Compose with Nginx

### Removed
- All Streamlit dependencies and pages
- Legacy Python-based UI components


## [1.2.4] - 2026-01-25

### Changed
- Updated `sync.py` and `release.py` scripts


## [1.2.3]

### Changed
- Updated README
    - Removed icons


## [1.2.2]

### Added
- Add description to each page. 

### Fixed
- Title uniformity


## [1.2.0]

### Added
- Search for Threat actors by aliases

### Fixed
- Author not displaying on some cards
- Pills on rule health now full width


## [1.1.6]

### Fixed
- Author not displaying on some cards
- Pills on rule health now full width


## [1.1.0] - 2026-01-20

### Added
- Clear Database table

### Changed
- Elastic Primary key from `rule_id` → `rule_id, space`

### Fixed
- Import detection rules, after primary key conflict


## [1.0.1] - 2026-01-19

### Changed
- Styling changes

### Fixed
- Source of Threat Intel for OpenCTI
- Primary Key for Elastic Detections


## [1.0.0] - 2025-12-01

### Added
- Initial release
