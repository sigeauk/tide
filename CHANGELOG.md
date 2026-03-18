# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.3.7] - 2026-03-18

### Added
- **Elastic Rule Testing:** Ability to test the rule against the elastic indices.
- **Elastic Rule Syncing:**  Users can now sync rules with and without mapping the rule. Increased full sync speed.

### Fixed
- **Elastic Rule Dataviews:** Updating to get rule mappings from rules that used `dataviews` as well as `indices`.
- **Rule Promotion:** On rule promotion, if the rule was successfully moved, it is moved in the database, without the need to sync all Elastic rules.

## [3.3.6] - 2026-03-17

### Added
- **Metric to systems:** added system page stats on baselines

## [3.3.5] - 2026-03-17

### Added
- **Audit Snapshots:** New point-in-time snapshot feature for Assurance Baselines. Users can freeze current coverage metrics (score, green/amber/red/grey counts) per baseline or across all applied baselines at once, with a custom label and optional date. Snapshots are stored in the new `system_baseline_snapshots` table (Migration 19).
- **Audit History Tab:** Added "Audit History" sub-tab on the System Details page showing a searchable, sortable table of all captured snapshots with date, baseline name, label, captured-by user, score badge, and per-status counts.
- **Snapshot Trend Chart (PDF Report):** System Reports now include a "Section 5b — Baseline Coverage Trend" with an inline SVG line chart plotting score over time per baseline, plus a data table of all snapshots.
- **Edit Baseline Inline:** The "Edit Baseline" option in the per-baseline Options dropdown now opens an inline modal (name + description) directly on the System Details page instead of navigating to the Baseline Details page.
- **Rule Health: Test Rule Function:** Added a "Test Rule" action in the rule detail modal using Kibana Preview API support with selectable lookback window and result popup.

### Changed
- **Assurance Baselines Card:** Restructured as a collapsible card with expand/collapse chevron matching the Devices card pattern. "Snapshot All" button moved to the card header alongside the chevron.
- **Audit History Table:** Swapped "Label" and "Baseline" column order so Baseline appears first for quicker scanning.
- **Snapshot Modal:** Added a date picker field ("Date") so users can back-date or forward-date snapshots; defaults to today when left blank.

### Fixed
- **Rule Mapping Logic:** Fixed lazy-mapping edge cases by preserving/restoring prior mapping results for skipped rules and adding data-view index resolution for rules without explicit `index` arrays.
- **Search Time Scoring Logic:** Fixed sync scoring to carry per-rule search duration from execution metadata into rule scoring (`score_search_time`) instead of stale or unset values.

## [3.3.4] - 2026-03-14

### Added
- **Baselines: Multi-Select System Filter:** Added a "Filter by System" multi-select dropdown to the Baseline Details page. Users can select one or more applied systems to dynamically recalculate technique coverage status and rollup counters in real time. Defaults to all systems when no filter is active.
- **Baselines: Technique Coverage Cards:** Replaced flat technique rows with elevated cards featuring a thick left-border coloured by worst-case RAG status (Red/Amber/Green/Grey) across the filtered systems. Technique titles inherit the same status colour.
- **Baselines: Coverage Rollup Counters:** Each technique card now displays compact per-status numerical counters on the right side (e.g., `🟢 1 🔴 2`). Only non-zero statuses are shown. Hovering a counter reveals a tooltip listing the specific system names in that state. Counters dynamically update when the system filter changes.

### Changed
- **Baselines: Consolidated Action Dropdown:** Removed standalone "Log Known Gap" and "Mark N/A" buttons from the technique detail (Applied Systems) view and the system baseline coverage list. Both actions are now permanent static options inside the existing rule-selection `<select>` dropdown, separated by an `<optgroup>` divider. When selected, the same modal popup is triggered to collect the reason string.

---

## [3.3.3] - 2026-03-13

### Added
- **Assurance Baselines:** New top-level module under "Risk & Assurance" for threat modeling. Users can build scenario-based attack trees (Playbooks) using MITRE Tactics and Techniques, map them to detection rules, and apply them to systems to view an automated gap analysis.
- **Reporting Engine (System & CVE):** Added dual-mode "Generate Report" functionality to the System Details page (CISO Executive Summary and Technical Deep Dive). Added "Generate CVE Audit Report" to the CVE details page to export an impact matrix mapping systems, hosts, and active detection rules.
- **Negative Coverage (Known Blind Spots):** Introduced a 4th status tier (Grey) for documented gaps. Users can now log an "Accepted Risk" or "Blind Spot" (with a mandatory reason string) on CVEs and Baseline steps where detection isn't possible, filtering them out of actionable 'Red' metrics.
- **Threat-Informed Defense Automation:** Added a "Create Assurance Baseline" action on Heatmap and Threat Actor pages. This automatically generates a Baseline Playbook populated with the exact MITRE techniques associated with the OpenCTI actor data.
- **Rule Attribution:** CVE Details, Baseline Details, and generated reports now explicitly name the specific detection rule (e.g., Sigma/YARA rule name) that is providing the 'Monitored' (Amber) coverage.

### Changed
- **UI: Navigation Restructure:** Overhauled the monolithic sidebar into an OpenCTI-style hierarchical accordion. Pages are now nested under collapsible parent groups: 'Risk & Assurance', 'Rules', and 'Threats', utilizing the primary accent color for active states.
- **UI: Baseline UI Parity:** Completely redesigned the Baselines interface to mirror the CVE architecture. Baseline details are now grouped by MITRE Tactic, and step details utilize the identical 50/50 MITRE/Rules split view found on CVE pages.
- **UI: App-Wide CSS Elevation:** Implemented a new 5-tier progressive CSS background variable system (`--bg-base` through `--bg-level-4`) to fix flat UI hierarchy. Nested elements (like technique cards inside tactic containers) now correctly display progressive visual depth.
- **UI: Badge Decluttering:** Condensed Tactic, Technique, and Detection badges on Baseline pages to display only an icon and numerical count to save horizontal space. Full descriptions are now accessible via hover tooltip.
- **System Details Logic:** Vulnerability status now strictly follows a "Worst Case" RAG color logic. A system card shows Red if any identified CVE on any host lacks an active detection rule; Amber if all CVEs are monitored; Green if clean.
- **Host Details UX:** Linked the dual-list interface. Selecting a specific package now instantly filters/highlights the adjacent list to show only the CVEs affecting that specific software component.
- **CVE Details Logic:** Expanded rule application hierarchy. Users can now apply a detection rule to an entire system globally, and specifically override/remove that rule from a single host within the system.

### Fixed
- **System Details: Search & Sort:** Fixed the search function to accurately filter the system view by Host Name, IP Address, or Package Name. Implemented column sorting (A-Z, Highest CVE count, Most Critical status).
- **Host Details: Search:** Added missing search bar and filtering options to the Host page package list.
- **CVE Overview: Rule Count Visibility:** Fixed an issue where rule counts ("X Rules Available") displayed universally. Counts now only render if the CVE is relevant to the inventoried infrastructure (matches a CPE in the database).
- **CVE Details: Affected Devices:** Added search and filtering to the affected devices table by Hostname or IP.
- **MITRE Integration:** Fixed the MITRE pill popup across the app; the associated rule name is now a clickable link that successfully routes to the specific Rule Health/Details page.
- **Baselines: Rule Application:** Fixed a CRUD bug where users were unable to apply a detection rule directly to a system from within the Baseline Technique/Step details page. 
- **Baselines: Required Rules Logic:** Removed the rigid "Required Rule" constraint from the database schema, allowing for standard, flexible Technique-to-Rule mapping identical to CVEs.

---

## [3.3.2] - 2026-03-11


### Added
- **Inventory: Classification on System Detail Header** — The system detail page header now displays the classification pill (with colour) below the system name, matching the treatment already present on host cards and the host detail header.
- **Test: Nessus Scan Files** — Two new test scan files: `test/scan_modern.xml` (Windows Server 2022, Ubuntu 22.04, RHEL 9, Win 11 workstation, Cisco IOS XE) and `test/scan_legacy.xml` (Windows Server 2008 R2, Windows XP, CentOS 7, FortiOS, Server 2012 R2) for import and CVE mapping testing.

### Changed
- **UI: Consistent Terminology** — Renamed user-facing labels throughout all templates and API messages: "Environments" → "Systems", "Hosts" → "Devices", "Software" / "Installed Software" → "Packages". Internal variable names, routes, CSS classes, and database columns are unchanged. GitLab Staging/Production references now use "Space" instead of "Environment".

### Fixed
- **CVE: Detection Badge False Positive** — Fixed the CVE detail page showing both "No Matches" and "Detection In Place" simultaneously. The detection badge now requires affected hosts to be present before displaying.
- **CVE: Overview Coverage Filter** — Fixed the CVE overview filter returning 0 results when filtering by "Detected". Global detections (system_id='') were not being matched against system-specific detection lookups.
- **Inventory: Classification Icon Gap** — Added missing `lock` and `tag` SVG paths to the icon macro. Classification pills were rendering an empty icon wrapper (visible gap) because these icons were not in the dictionary.

### Added
- **Inventory: Custom Classifications** — New `classifications` database table (migration 11) with name and colour fields. Seeded with four defaults: Official (green), Confidential (amber), Secret (red), Top Secret (dark red). Users can add and delete custom classifications from the new "Manage Classifications" modal on the Environments page, each with a user-selected colour.
- **Inventory: Classification Colour Coding** — Classification pills on system cards, host cards, and the host detail header now display with the classification's assigned colour (tinted background, coloured text and border) instead of monochrome grey.
- **Inventory: Host Classification Inheritance** — Hosts inherit their parent system's classification. The classification pill is shown on every host card in the host list and on the host detail page header. No classification tag on software items.
- **API: Classification CRUD** — `GET/POST /api/inventory/classifications`, `DELETE /api/inventory/classifications/{id}`. Deleting a classification clears it from all systems that use it.

### Changed
- **Inventory: Dynamic Classification Selects** — The Add and Edit Environment modals now populate classification options dynamically from the database instead of hardcoded values.

### Fixed
- **Inventory: Nessus Parser — Junk Software Entries** — Removed the `pluginName` fallback that treated every Nessus audit/info plugin title (e.g. "Microsoft Windows SMB Shares Enumeration") as an installed software item. Software entries are now only created when `<cpe>` elements exist or when `plugin_output` contains an explicit Product/Application/Software pattern.
- **Inventory: KEV Matching False Positives** — Rewrote `_match_software_against_kev()` to require a CPE on the software item and use CPE vendor+product identity matching instead of loose keyword substring matching. Eliminates false positives such as KEV product "Windows" matching every plugin name containing "Windows".
- **Inventory: Multi-Select Dropdown CSS** — Added missing `.hidden { display: none !important; }` class and `.filter-multi` / `.filter-multi__dropdown` styles so the system and coverage filter dropdowns on the CVE Overview page toggle and render correctly.
- **Inventory: Edit Environment — Classification** — Added the Classification `<select>` dropdown to the Edit Environment modal, matching the field already present in the Add Environment form. Pre-selects the current value.

### Changed
- **Inventory: KEV Matching Performance** — CPE parsing is now performed once per software item outside the inner KEV loop, reducing redundant string splitting in the O(S×K) matching pass.

## [3.3.1] - 2026-03-10

### Added
- **Inventory: CVE Overview — Coverage Colour Coding** — CVE cards now display a colour-coded left border based on detection coverage status: green (detected), amber (partial), red (no cover), blue (unaffected).
- **Inventory: CVE Overview — Multi-Select Filters** — Added multi-select dropdown filters for System and Coverage status on the CVE Overview toolbar, replacing basic single-select.
- **Inventory: CVE Overview — Default Sort** — CVE Overview now defaults to sorting by CVE ID descending (newest first).
- **NVD Fetch Script** — New `scripts/fetch_nvd_windows.py` utility to download per-year Windows CVE data from the NVD 2.0 API during Docker image builds.

### Changed
- **Engine Refactor** — Replaced monolithic `version_gate.py` with a modular `app/engine/` package containing `cpe_validator.py`, `platform_graph.py`, and `sync_manager.py`. All imports updated throughout the codebase.
- **Inventory: Batch Loading Performance** — Replaced per-host and per-system database queries with batch-loading helpers (`_list_all_hosts_by_system()`, `_list_all_software_by_host()`), eliminating N+1 query bottlenecks on summary and overview pages.
- **Inventory: KEV File Caching** — CISA KEV JSON is now cached in memory with mtime-based invalidation, avoiding repeated file reads on every page load.

## [3.3.0] - 2026-03-09

### Added
- **Inventory: System Classification** — New `classification` field on Environment (System) records. Displayed as a pill on the system card and editable from the Add/Edit Environment modal. Database schema migration 9.
- **Inventory: System Cards Redesign** — Replaced the flat environment table with a responsive 3-column card grid (`system_cards.html`). Each card shows name (accent colour), classification pill, description, host/CVE counts, and a delete action.
- **Inventory: CVE Overview Card Layout** — Replaced the CVE overview flat table with horizontal card rows (`cve_overview_table.html`). Includes sort controls (CVE ID, Name, Vendor, Date Added, Due Date, Match status), free-text search, matched-only filter, and per-system filter dropdown.
- **Inventory: CVE Overview Detection Pill** — Matched CVEs without any detection now display a styled **"No Cover"** danger pill instead of a bare `—` dash.
- **Inventory: Host List Card Grid** — Replaced the host table on the System Detail page with a responsive card grid (`host_list.html`). Each card shows hostname (accent, links to host), IP, OS, software count, KEV badge, source, and delete.
- **Inventory: Host KEV Matches Cards** — Replaced the KEV matches table on the Host Detail page with compact mini-cards (`host_cve_matches.html`). Cards are colour-coded: green left border = detection in place, red = no detection on a ransomware CVE. Includes an inline colour key legend.
- **Inventory: CVE Detail – MITRE ATT&CK Manual Edit** — New `cve_technique_overrides` DB table (migration 10) and `cve_mitre_section.html` partial allow analysts to manually add or remove MITRE ATT&CK technique IDs for any CVE. Changes are persisted and merged with the MITRE→CVE JSON feed. API endpoints: `POST /api/inventory/cve/{cve_id}/techniques`, `DELETE /api/inventory/cve/{cve_id}/techniques/{technique_id}`.
- **Inventory: CVE Detail – Affected Hosts Cards** — Replaced flat danger-badge host list on CVE Detail with accent-coloured mini-cards (`aff-host-card`). Cards show green/red left border and host name colour based on whether the host's environment has a detection mapped. Includes a colour key.
- **CSS Design System: New Classes** — Added `.host-card-grid`, `.host-card`, `.cve-mini-card`, `.det-color-key`, `.section-title`, `.aff-host-grid`, `.aff-host-card` to support the new card layouts.

### Changed
- **Inventory: Rule Name Display** — Detection rows (`_det_system_row.html`) now resolve rule IDs to human-readable names using `technique_rules` context. Multiple rules shown as individual chips.
- **Inventory: Detection Row – System Name** — System name label in each detection row is now rendered in the primary accent colour (`--color-primary`) instead of muted grey.
- **Inventory: Detection Row – Edit Button** — Removed icon from the "Edit" button in detection rows for a cleaner, text-only control.
- **Inventory: Detection Row – Card Style** — Removed the green background and border from detection row cards. Green colouring is now limited to the rule name chips only, reducing visual noise.
- **Inventory: CVE Detail – Section Ordering** — Reordered cards: Info → MITRE ATT&CK → Detection Status → Affected Hosts (MITRE now appears first, above detection).
- **Inventory: CVE Detail – Section Titles** — Section headings ("Detection Status", "Affected Hosts", "MITRE ATT&CK Techniques") now use the `.section-title` CSS class (accent colour, no icon).
- **Inventory: CVE Detail – CVE ID Title** — The page `<h1>` CVE ID is now rendered in `--color-primary` accent colour.
- **Inventory: Host Header – Stat Cards** — Replaced raw inline-styled div+span stat blocks with `.metric-card` / `.metric-value` / `.metric-label` CSS classes for design-system compliance.
- **Inventory: Section Headings Consistency** — Applied `.section-title` to section headings on System Detail (Hosts) and Host Detail (Installed Software, KEV Matches).

## [3.2.0] - 2026-03-06

### Added
- Added the sigma pipeline capability.

## [3.1.0] - 2026-03-03

### Added
- **Threat Report Export:** New "Export Report" button group on the Heatmap page lets analysts download a professional report for the currently selected threat actors in two formats:
  - **PDF** — A4 multi-page document rendered entirely server-side using [WeasyPrint](https://weasyprint.org/) (no browser or network calls). Includes:
    - Cover page with actor pills and generation timestamp.
    - Executive Summary with six top-line stat cards: actors analysed, total adversary TTPs, detection coverage %, covered TTPs, critical gaps, and mapped Elastic rules.
    - Visual MITRE ATT&CK matrix rendered as a CSS Grid across a landscape page, colour-coded red/green/blue (GAP / COVERED / DEFENSE IN DEPTH) matching the live heatmap.
    - Detailed per-tactic tables with columns: Technique ID, Technique Name, Status badge, Source (Enterprise / ICS / OpenCTI), and the specific names of every Elastic rule providing coverage.
  - **Markdown** — Plain-text `.md` report with the same structure; no additional dependencies required.
- **`app/services/report_generator.py`:** New service module containing `build_report_data()`, `generate_markdown()`, and `generate_pdf_bytes()`. Performs a single batch SQL query to fetch rule names for all displayed TTPs, infers MITRE matrix source (ICS vs. Enterprise) from technique ID namespace, and flags OpenCTI-sourced intel.
- **`app/templates/report/threat_report.html`:** Self-contained Jinja2 PDF template with fully inlined CSS. Uses Liberation Sans system font (bundled in Docker image). No external URLs — safe for fully airgapped deployments.
- **`GET /api/heatmap/export`:** New FastAPI endpoint accepting `actors[]`, `format` (`pdf`|`markdown`), and `show_defense` query parameters. Returns a `Content-Disposition: attachment` response; blocking WeasyPrint call runs in FastAPI's thread pool.

### Changed
- **`requirements.txt`:** Added `weasyprint>=62.0`.
- **`dockerfile`:** Builder stage now installs `libpango1.0-dev`, `libcairo2-dev`, `libgdk-pixbuf2.0-dev`, `libffi-dev`. Production stage now installs `libpango-1.0-0`, `libpangocairo-1.0-0`, `libcairo2`, `libgdk-pixbuf2.0-0`, `libffi8`, `fonts-liberation`.
- **`app/api/heatmap.py`:** Imports extended (`HTTPException`, `Response`, `io`, `os`) to support the export endpoint.
- **`app/templates/pages/heatmap.html`:** Added "Export Report" filter-group containing PDF and Markdown download buttons. Added `exportReport(format)` JavaScript function that collects the current actor selection and triggers a browser download without leaving the heatmap page.

## [3.0.3] - 2026-03-02

### Fixed
- Refractor CSS

## [3.0.2] - 2026-03-01

## Fixed
- **Kibana icon:** added the `shield-check` as the kibana icon. 

## [3.0.1] - 2026-03-01

### Added
- **Space-Aware Deep Links:** Rule cards and detail modals now include a "Kibana" button that links directly to the rule in the correct Kibana space (`/s/{space}/app/security/rules/id/{id}`). The default space omits the `/s/default/` prefix.
- **Subtractive Sync:** Spaces configured in `KIBANA_SPACES` that return zero rules from Elastic now have their stale/ghost rules automatically purged from the local database during sync.

### Fixed
- **Kibana Deep Link IDs:** Kibana URLs now use the Elastic saved-object `id` instead of the internal `rule_id`. Previously links pointed to non-existent rules (e.g. "Abnormally Large DNS Response" linked to `rule_id` instead of the saved-object `id`).
- **Sigma Page:** CodeMirror editor (rule.yml panel) now loads reliably on HTMX navigation without requiring a hard refresh. Added dynamic script loading fallback via `createElement('script')` to work around `head-support` extension's unreliable `createContextualFragment` execution of `<script defer>` tags.
- **MITRE Heatmap Spinner:** Fixed the loading spinner on the technique detail panel so only the icon rotates — previously the entire container (icon + "Loading rules…" text) was spinning due to a CSS class conflict between `style.css` and `heatmap.css`.

## [3.0.0] - 2026-02-28

### Changed
- Moved docker `047741/tide-core` -> `sigeauk/tide`

## [2.4.2] - 2026-02-27

### Changed
- Changed CSS

### Added
- High quality .svg images

## [2.4.1] - 2026-02-18

### Fixed
- **SSL/CA Trust:** Resolved certificate verification failures when connecting to internal infrastructure (Keycloak, Elasticsearch, OpenCTI, GitLab). The `ssl_context` in `config.py` now uses the system trust store populated by the entrypoint, ensuring volume-mounted CA certificates are trusted by all Python HTTP clients.

### Changed
- Cleaned up `docker-compose.yml` and `.env.example` for production readiness.
- Moved `build` configuration to `docker-compose.override.yml` (development only); production users only need the image, `docker-compose.yml`, and `.env`.
- Static assets now use a named Docker volume shared between app and nginx containers, removing the need for a local source tree.
- CA certificates are volume-mounted and installed at container startup via `entrypoint.sh`.

## [2.4.0] - 2026-02-18

### Added
- Added `nano` and `jq` to the Docker image.

## [2.3.7] - 2026-02-17

### Fixed
- Rule log mapping.

## [2.3.6] - 2026-02-16

### Added 
- Improve page loading.
- Increase favicon size. 

### Changed
- Update pySigma backend/pipeline in requirements.txt

## [2.3.5] - 2026-02-16

### Fixed
- **UI Responsiveness:** Resolved significant lag during page navigation and data loading by refactoring the internal execution model to prevent event-loop blocking.
- **Sigma Converter:** Fixed "temperamental" loading of the rule editor and syntax highlighter; improved initialization reliability across HTMX swaps.
- **Cold Starts:** Eliminated the multi-second delay when first accessing Sigma conversion tools after system idle time.

### Optimized
- **Database I/O:** - Reduced disk write overhead by removing redundant `CHECKPOINT` commands from read operations.
    - Improved memory efficiency by narrowing data fetching to required columns only (`SELECT *` reduction).
- **Backend Concurrency:** Migrated heavy I/O operations to a managed threadpool, allowing the server to handle multiple concurrent HTMX requests without freezing.
- **Engine Warm-up:** Implemented a startup "priming" routine that pre-loads Sigma rules, backends, and pipelines into memory.
- **Asset Caching:** Switched to version-based cache busting for local JS/CSS files to ensure instant UI loads while maintaining update integrity.

### Changed
- Updated `base.html` to use non-blocking deferred script loading.
- Refactored `main.py` lifespan to handle proactive dependency initialization.

## [2.3.1] - 2026-02-13

### CHANGE  
- Clean up of .env

## [2.3.0] - 2026-02-12

### CHANGE
- Change NGINX to use port 443 from legacy 8501 port.
- No internet connection required

### Added
- Add low severity to the metric count.
- entrypoint.sh 

## [2.2.0] - 2026-02-12

### FIX
- Upadate with trust of infra certs

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
