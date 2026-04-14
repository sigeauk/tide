# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.0]

### Added
- **Management Hub (`/management`):** New top-level admin-only area with a tabbed interface consolidating Clients, SIEMs, Users, and Permissions management into a single page.
- **Move System workflow:** "Move" button on client system cards opens a modal to move a system to another client. Pre-flight dependency check (`move-check` endpoint) shows affected baselines, host/software counts, and SIEM compatibility. When the target client has different production SIEM spaces, `applied_detections` are reset to prevent stale rule coverage.
- **Move System engine functions:** `move_system_check()` and `move_system_to_client()` in `inventory_engine.py` handle SIEM space comparison, applied detection cleanup, and optional baseline migration.
- **Cross-DB Move System workflow:** `move_system_to_client()` detects multi-DB mode and dispatches to `_move_system_multi_db()`, which physically copies rows (systems, hosts, software_inventory, blind_spots, applied_detections, playbooks, system_baselines, system_baseline_snapshots, playbook_steps, step_techniques, step_detections) from the source tenant DB to the target tenant DB, then deletes from source. SIEM-aware: if the target has different production spaces, applied_detections are not copied and coverage is reset. Baseline migration is optional. The shared DB is updated for consistency after the cross-tenant transfer.
- **`_cross_db_copy()` helper:** Generic row-copy function between DuckDB connections with automatic `client_id` replacement on copied rows.
- **`tenant_context_for(client_id)` context manager:** Temporarily sets the active tenant DB path via `contextvars` and restores the previous context on exit. Used by management routes and move system pre-flight checks to query the correct tenant DB without full request-scoped dependency injection.
- **Graceful resource-not-found redirects:** `_gone_redirect()` helper in `inventory.py` returns an `HX-Redirect` header for HTMX requests or a 302 `RedirectResponse` for full-page loads. Applied to system detail, host detail, CVE detail, baseline detail, and tactic detail pages — prevents hard 404s when a resource belongs to a different tenant.
- **Database-per-tenant architecture:** Each client now gets a dedicated DuckDB file (`{slug}_{shortid}.duckdb`) instead of sharing a single database with row-level `client_id` filtering. Guarantees zero cross-tenant data leakage at the storage layer and eliminates DuckDB's single-writer concurrency bottleneck.
- **Tenant connection manager (`tenant_manager.py`):** Context-aware connection routing using Python `contextvars`. `get_connection()` automatically routes to the active tenant's DB; `get_shared_connection()` always returns the shared DB for auth, RBAC, and client management.
- **Reference data sync:** `mitre_techniques`, `threat_actors`, `siem_inventory`, and `client_siem_map` are synced as physical copies from the shared DB into each tenant DB on startup and after MITRE/SIEM changes, so tenant queries work without cross-DB ATTACH.
- **Detection rule distribution:** After each Elastic sync, `_distribute_rules_to_tenants()` copies detection rules into each tenant DB filtered by the client's linked SIEM spaces.
- **Migration script (`migrate_to_multi_db.py`):** One-time utility to split an existing single-DB deployment into per-tenant databases. Supports `--dry-run`. Copies all tenant-scoped tables, FK-linked tables, and reference data.
- **External query tenant scoping:** `/api/external/query` now enforces tenant isolation via temporary DuckDB views that shadow all tenant-scoped tables, filtered by the API key's owning `client_id`. Explicit `main.*` schema references are rejected.
- **Playwright multi-tenancy E2E suite:** Five test scripts in `test/playwright/scripts/multi_tenancy/`: cross-tenant URL guard, system card navigation, move system flow, SIEM reset on move, and API cross-tenant guard.
- **SIEM Inventory:** Centralized SIEM management with CRUD for SIEM objects (Elastic, Splunk, Sentinel). SIEMs have label, type, separate Elasticsearch URL and Kibana URL fields, and API key. A single SIEM can be linked to multiple clients with different environment roles.
- **Environment Role model:** Each client-SIEM link now carries an `environment_role` ('production' or 'staging') and a single `space` field. A SIEM can serve as 'production' for one client and 'staging' for another. Production SIEMs drive dashboard/heatmap coverage; staging SIEMs drive promotion workflows.
- **Test Connection:** "Test Connection" button in the SIEM modal calls Kibana `/api/status` to verify connectivity and reports Kibana version and health.
- **Client-SIEM linking with environment context:** Link form now includes Environment Role selector (Production/Staging) and Space input. Unlink is role-specific.
- **Client-aware detection queries:** All coverage queries (`get_all_covered_ttps`, `get_ttp_rule_counts`, `get_rules_for_technique`, `get_sigma_coverage_data`, `get_threat_landscape_metrics`) accept optional `client_id` to scope results to rules deployed in that client's production SIEM spaces.
- **Client-specific query methods:** New `get_client_siem_spaces()`, `get_covered_ttps_for_client()`, `get_technique_rule_counts_for_client()`, `get_rules_for_client()` methods for direct client-scoped queries.
- **Manage Assets page:** Client detail page (`/clients/{id}`) now shows Systems, Baselines, Linked SIEMs, and Assigned Users with counts in the stats strip. "View Details" button renamed to "Manage Assets".
- **User client assignment checklist:** "Manage Clients" action on the Users tab opens a checklist of all clients, updating the `user_clients` join table directly.
- **DB Migration 26:** Created `siem_inventory` table and `client_siem_map` join table. Migrated existing `client_siem_configs` data into the new inventory. Added `page:management` permission resource for ADMIN role.
- **DB Migration 27:** Added `elasticsearch_url`, `kibana_url`, `production_space`, `staging_space` columns to `siem_inventory`. Migrated `base_url` → `kibana_url` and split `space_list` into production/staging fields.
- **DB Migration 28:** Added `environment_role` and `space` columns to `client_siem_map`. Rebuilt table with composite PK `(client_id, siem_id, environment_role)`. Split dual-space SIEM configs into separate production/staging rows. Added `client_id` column to all tenant-scoped tables (systems, hosts, playbooks, etc.).
- **DB Migration 29:** Added `db_filename VARCHAR` column to `clients` table for tracking tenant DB filenames.
- **Management API router (`/api/management/`):** Tab partial endpoints, SIEM CRUD, test-connection, client-SIEM linking, and user-client assignment endpoints.
- **Playwright tenant audit:** New `test/playwright/scripts/tenant_audit.js` automates cross-tenant validation (batman/DC zero-rule check, ironman/Marvel rule visibility, privilege escalation guard, active_client_id cookie on login).
- **Playwright refactor audit:** New `test/playwright/scripts/v4_refactor_audit.js` — 53-check comprehensive audit covering full-site page crawl, sync count leak, sigma deploy scoping, SIEM terminology, baseline isolation, systems isolation, CVE pages, management access, and cross-tenant API guards.

### Changed
- **~40 shared-only methods** in `database.py` switched from `get_connection()` to `get_shared_connection()` (user CRUD, role/permission CRUD, client CRUD, API key management, SIEM inventory/config operations).
- **`inventory_engine._cf()`** returns no-op filter `("", [])` when a tenant context is active, since the DB is already tenant-scoped.
- **`deps.get_active_client()`** now resolves the tenant DB path and sets the tenant context via `contextvars` for the duration of each request.
- **App startup** now calls `refresh_tenant_cache()` and `sync_shared_data()` to initialize multi-DB routing.
- **Tenant switcher redirect:** Client switcher component (`client_switcher.html`) now redirects to `/` (dashboard) after switching tenants instead of reloading the current page, preventing 404s on resource-detail pages that belong to the previous tenant.
- **Management partials tenant context:** `_render_client_systems_partial()` and `_render_client_baselines_partial()` now wrap inventory queries in `tenant_context_for(client_id)` to read from the correct tenant DB in multi-DB mode.
- **Client detail page tenant context:** `client_detail_page()` wraps system and baseline listing in `tenant_context_for(client_id)` for correct multi-DB routing.
- **`_init_db()` uses shared connection:** `DatabaseService._init_db()` now uses `get_shared_connection()` instead of `get_connection()`, ensuring migrations always target the shared DB even when a tenant context is active.
- **Sidebar navigation:** Replaced "Clients" link with "Management" link pointing to the new hub.
- **Settings page:** Fully removed Users and Permissions tabs (previously showed redirect buttons). These are now exclusively in the Management Hub.
- **HTMX navigation:** Management Hub tabs use native `hx-get` on tab buttons targeting `#management-content` — no page reloads. Tab state preserved in URL via `?tab=` query param across client switches.
- **SIEM cards:** SIEMs render as cards (matching Systems page pattern) showing Elasticsearch URL and Kibana URL. Production/staging space display removed from SIEM inventory cards (space is now per client-SIEM link).
- **Client SIEM partial:** Updated `client_siems.html` to display Environment Role badge (Production/Staging) and Kibana Space per linked SIEM instead of dual production_space/staging_space fields.
- **Space → SIEM terminology:** Renamed "Space" filter labels to "SIEM" on Rule Health and Sigma pages. Default dropdown option is now "All SIEMs". SIEM card detail uses "Kibana Space" for the Elastic space field.
- **Sigma deploy targets:** Deploy dropdown on the Sigma page now uses `deploy_targets` (client-scoped SIEM list with labelled environment role) instead of the global `spaces` variable.
- **Heatmap client-awareness:** `get_heatmap_matrix`, `get_technique_detail`, `get_technique_rules`, and report export now pass `client_id` to all coverage queries, ensuring heatmap shows only rules visible to the active client's production SIEM spaces.
- **Sigma search client-awareness:** Added `client_id: ActiveClient` parameter to sigma rule search endpoint for client-scoped coverage pills.
- **Inventory engine client-awareness:** `get_system_baselines`, `build_system_report_data`, `_build_baseline_heatmap`, `get_rules_for_cve_techniques`, and `_build_technique_rules` now thread `client_id` through to all coverage queries.
- **Report generator client-awareness:** `build_report_data` accepts optional `client_id` and scopes coverage/rule-count queries accordingly.
- **Modal consistency:** Client and SIEM modals use `modal-overlay` → `modal-content modal-sm` → `modal-header` pattern matching the Systems page.
- **PATH_RESOURCE_MAP & API_WRITE_RESOURCE_MAP:** Added `/management` and `/api/management` entries for permission enforcement.
- **Pydantic models:** Removed `production_space`/`staging_space` from `SIEMInventoryItem`, `SIEMInventoryCreate`, `SIEMInventoryUpdate`. Added `ClientSIEMLink` and `ClientSIEMLinkFull` models.
- **Architectural reset & instruction hardening:** Purged host-side `node_modules/`, `package.json`, and `package-lock.json` that were erroneously committed. Added Node/NPM artifacts to `.gitignore` and removed them from git tracking. Hardened `copilot-instructions.md` HARD STOPS with explicit `npm install`/`npx` host ban, shell discipline rule, zero-host-dependency mandate, and mandatory `--rm` flag for Playwright containers.
- **Management card modals:** Extracted system and baseline modals from HTMX swap zones (`client_systems.html`, `client_baselines.html`) into `client_detail.html`, preventing modal destruction on every HTMX swap. Replaced fragile `setTimeout(hide, 100)` with `hx-on::before-request` for immediate modal close. Added `hx-swap-oob="true"` for server-side modal option updates.
- **Baseline report scoping:** `build_baseline_report_data()` now passes `client_id` to `get_baseline_step_coverage()` and filters the `system_baselines` JOIN by client, preventing cross-tenant system names from appearing in reports.
- **Rule Health isolation:** Rule Health page (`/rules`) and `/api/rules` now scope detection rules to the active client's linked SIEM spaces via `allowed_spaces` on `RuleFilters`. Clients with 0 SIEMs correctly see 0 rules, 0% coverage.
- **Rule metrics isolation:** `get_rule_health_metrics()` now accepts optional `allowed_spaces` to restrict aggregations to tenant-visible rules only.
- **Space filter isolation:** `get_unique_spaces()` now accepts optional `allowed_spaces` to restrict the space dropdown to tenant-visible spaces only.
- **Login default client:** `local_login()` now sets `active_client_id` cookie to the user's default (or only assigned) client, preventing all users from landing on the system default "Primary Client."
- **User deletion pipeline:** `delete_user()` now also deletes from `user_clients` before removing `user_roles` and the user record, preventing orphaned foreign key rows.
- **Threat Landscape isolation:** `list_threats()` and `get_threat_metrics()` now accept `ActiveClient` and scope covered-TTP / rule-count queries to the active client's production SIEM spaces. Clients with 0 SIEMs correctly see 0% coverage across all actors.
- **Dashboard metrics isolation:** `get_dashboard_metrics()` now accepts optional `client_id` to scope rule health, promotion, and threat landscape metrics to the active client's SIEM spaces.
- **Baseline assignment validation:** `apply_baseline()` and `remove_baseline()` now accept `client_id` and validate same-client ownership of both system and playbook before INSERT/DELETE, preventing cross-tenant baseline manipulation.
- **Baseline queries:** `get_system_baselines()` now filters joined playbooks by `client_id` when provided, preventing cross-client baseline visibility.
- **Asset reassignment checks:** `assign_system_to_client()` and `assign_baseline_to_client()` now reject reassignment if the asset already belongs to a different client.
- **API key cleanup:** `delete_user()` now nullifies `api_keys.created_by_user_id` before cascading deletes, preventing orphaned foreign key references.
- **Sync status privacy:** Sync status banner no longer exposes the global rule count ("Synced 245 rules from Elastic"). Now shows "Sync complete" and dispatches a `refreshRules` event to reload scoped metrics.
- **Sigma deployment scoping:** `/sigma` page deploy dropdown now shows only the active client's linked SIEMs (e.g. "DC (Production)") instead of every Kibana space from the environment variable. The deploy endpoint validates the target space belongs to the client.
- **Sigma spaces API visibility:** `GET /api/sigma/spaces` now returns only the active client's linked SIEM spaces instead of all configured spaces.
- **Baseline detail isolation:** Baseline detail page systems list and step-coverage RAG matrix now filter by `client_id`, preventing systems from other clients appearing in the "Apply to system" dropdown or coverage grid.
- **Management Add System responses:** Assigning a system to a client no longer exposes UUIDs in error toasts. Returns a clear "System not found." message when the system does not exist.

## [3.4.8] - 2026-04-06

### Added
- **Profile self-service endpoints (local-only):** Added `POST /api/settings/profile/email` and `POST /api/settings/profile/password` so local accounts can update their own email and password with server-side validation.
- **Admin reset flow flag:** Added `change_on_next_login` support on users (DB migration 23) and wired Admin reset to set this flag (default `true`) for local accounts.
- **API key ownership metadata:** Added `api_keys.created_by_user_id` (DB migration 24) so API key lifecycle actions can enforce owner/admin authorization.

### Changed
- **Settings tab refactor:** Renamed the `API Keys` settings tab to `Profile`, moved it to first position, and consolidated profile content to include both API key management and local account email/password controls.
- **Permissions resource rename:** Renamed settings permission resource `tab:apikeys` to `tab:profile` (DB migration 23), and updated permissions matrix ordering to display `Profile` first under Settings Tabs.
- **Profile permission defaults:** Ensured ANALYST and ENGINEER have read/write permissions for `tab:profile` by default.
- **API write authorization granularity:** Updated middleware write checks so `/api/settings/profile*` and `/api/settings/api-keys*` authorize against `tab:profile` permissions rather than only `page:settings` write.
- **API key list scoping:** Non-admin users now see only their own API keys in Profile; admins continue to see all keys.
- **Auth local fallback clarity:** Local credential validation is now explicitly applied to any account with a local password hash, including SSO-origin users.

### Fixed
- **Local login after SSO activity:** Fixed auth fallback so stale/invalid Keycloak token state no longer blocks valid local-session access.
- **SSO/local account collision:** Hardened JIT Keycloak provisioning to avoid auto-upgrading/linking local-only users by username/email, preventing local account provider corruption after SSO sign-in.
- **Local login cookie state:** Local sign-in now clears Keycloak auth cookies on success to reduce stale SSO cookie interference with local sessions.
- **API key revocation security:** Revocation now enforces `owner OR ADMIN` authorization; ANALYST/ENGINEER users cannot revoke keys owned by other users.
- **SSO credentials in local form:** Fixed SSO-to-local credential fallback to use a password-grant capable Keycloak client instead of the browser OIDC client, allowing SSO-origin users without a TIDE `password_hash` to authenticate via the local login form.

## [3.4.7] - 2026-04-04

### Added
- **Hybrid Authentication:** TIDE now supports both Keycloak OIDC (SSO) and local username/password login. Users can sign in with either method from the same login page.
- **Local Auth with bcrypt:** Secure password-based login using bcrypt hashing and signed session cookies (`itsdangerous`). Passwords require a minimum of 8 characters.
- **Just-In-Time (JIT) Provisioning:** Keycloak SSO users are automatically synced to the local `users` table on first login, with email, name, and `keycloak_id` claims persisted.
- **Role-Based Access Control (RBAC):** New `roles` and `user_roles` tables with three seeded roles: ADMIN, ANALYST, ENGINEER. Role checks available via `require_role()` dependency and `user.has_role()` / `user.is_admin()` helpers.
- **User Management UI (Settings → Users):** Admin-only tab on the Settings page to list all users, view auth source (Local/SSO), assign/revoke roles, toggle active status, create local users, and delete accounts.
- **Bootstrap Admin:** On first startup with an empty database, a default `admin` user (password: `admin`) with ADMIN role is created automatically.
- **DB Migrations 21–22:** Created `users`, `roles`, `user_roles`, and `role_permissions` tables with proper schema for hybrid auth and RBAC.
- **SESSION_SECRET config:** New `SESSION_SECRET` environment variable for signing local session tokens.
- **Page & Tab RBAC Permissions:** New `role_permissions` table (DB migration 22) with per-role read/write controls for every page and settings tab. Default permissions seeded for ADMIN (full access), ANALYST (pages R+W, settings read-only), and ENGINEER (read-only).
- **Permissions Admin UI:** New "Permissions" tab on the Settings page (admin-only) with a matrix of checkboxes to toggle read/write access per role and resource, powered by HTMX.
- **Permissions API:** `GET /api/settings/permissions` returns the permissions matrix HTML; `POST /api/settings/permissions` toggles individual permission flags.
- **Middleware Permission Enforcement:** `AuthMiddleware` now checks page-level read permissions and API write permissions against the user's role-based access before allowing requests through.
- **Sidebar Permission Guards:** Navigation items are hidden when the user lacks read access to the corresponding page resource.
- **Permission Helpers:** `require_read()` and `require_write()` dependency factories in `deps.py`; `can_read()` and `can_write()` methods on the `User` model.

### Changed
- **Login Page:** Redesigned to show both local login form and SSO button with a divider.
- **Auth Middleware:** Now checks `session_token` cookie (local auth) in addition to `access_token` (Keycloak JWT), enabling seamless hybrid auth.
- **Logout:** Intelligently routes through Keycloak logout only if user had an SSO session; local-only users redirect straight to the login page. All auth cookies (`access_token`, `refresh_token`, `session_token`) are cleared.
- **User Model:** Extended with `auth_provider`, `is_active`, `has_role()`, and `from_db()` class method. Dev user now uses uppercase role names (ADMIN, ANALYST, ENGINEER).
- **ADMIN excluded from Permissions matrix:** The ADMIN role always has full access and is no longer shown in the Permissions UI, preventing accidental lockouts.

### Fixed
- **SSO last_login tracking:** `jit_provision_keycloak_user()` now updates `last_login` on every SSO sign-in, so the Users table no longer shows "Never" for SSO accounts.
- **SSO local login via Keycloak ROPC:** SSO-provisioned users can now sign in through the local login form using their Keycloak password. The auth service falls back to Keycloak's Resource Owner Password Credentials grant when the user has no local password hash.
- **JIT account linking:** When an SSO user signs in and a matching local username already exists, the accounts are linked (keycloak_id set, auth_provider upgraded to hybrid) instead of creating a duplicate.
- **Settings tab fallback:** `switchTab` JS now falls back to the first visible tab when the saved tab is hidden by permissions.

## [3.4.6] - 2026-04-04

### Update
- **Internal Changes:** Changes not released. 

## [3.4.5] - 2026-03-30

### Changed
- **Sigma Converter - deterministic multi-pipeline index merge:** Added ordered index merge semantics for custom pipeline chains. Pipelines now merge index targets in selection order with support for append behavior and explicit overwrite markers.
- **Sigma Converter - fallback behavior without sigma-cli:** When sigma-cli is unavailable, kibana_ndjson conversion still applies merged pipeline index scopes so selected pipeline order remains effective for rule index output.

### Fixed
- **Sigma Pipeline Manager - auth/session save failure path:** Hardened custom pipeline fetch/save/load/delete flows to handle auth-expiry responses cleanly instead of silently failing on non-JSON login payloads.
- **Auth Middleware - API response contract:** Unauthenticated `/api/*` requests now return structured `401` JSON responses instead of login-page redirects, preventing JSON parsing failures in frontend API clients.
- **Sigma Page - custom pipeline refresh auth handling:** Added auth-aware response handling for custom pipeline list refresh on the Sigma converter page.

### Added
- **Sigma Validation Tests:** Added container-run validation scripts for saved-pipeline API CRUD and ordered append/overwrite index logic verification.

## [3.4.4] - 2026-03-30

### Changed
- **Baselines - Technique tag normalization:** Baseline import and tactic technique CRUD now normalize MITRE technique IDs from free-form values (including legacy-labeled input), so instruction-set content is stored as standard tagged techniques.
- **Baselines - Legacy technique label removed:** Removed the "Legacy technique" display block from tactic MITRE mapping UI so only standard technique tags are shown.
- **System Heatmap - step-level baseline rendering:** System baseline heatmap now renders one card per baseline step, using the step's displayed technique label and the step's own tactic bucket so matrix totals match the baseline breakdown.
- **System Baseline cards - technique label source:** Expanded baseline rows now display technique labels from normalized tagged techniques (`step_techniques`) instead of legacy single-field values.

### Fixed
- **System Heatmap - Tagged technique synchronization:** System baseline heatmap now builds from both primary step technique and multi-technique tags, ensuring baseline techniques are reflected correctly when filtering by baseline.
- **System Baselines UI - Bulk expand/collapse controls:** Added separate Expand All and Collapse All controls for top-level baselines and tactic groups in the System Baseline coverage panel.
- **ystem Heatmap - baseline filter undercount:** Filtering to a baseline such as `secret system cyab` now preserves the full set of baseline steps instead of collapsing or overcounting cards through technique remapping.
- **System Heatmap - filter responsiveness:** Added short TTL cache for system heatmap baseline source data and a lighter baseline load path for heatmap calls, improving repeated filter-toggle latency.
- **System Heatmap - traceability for duplicate technique tags:** Aggregation now preserves contributing step titles per technique in tooltip metadata so entries like `Title 14` tagged with `T1200` remain discoverable in the matrix tooltip metadata.
- **System Heatmap - custom tactic buckets route to Other:** System baseline heatmap now keeps steps tagged under non-canonical tactic labels such as `Other`, `priv esc`, and `prililege escalation` in the `Other` column instead of remapping their MITRE techniques back into canonical ATT&CK tactic columns.
- **System Baselines - preserve raw tactic breakdowns:** System baseline coverage data now keeps the original step tactic labels for the top-level breakdown instead of normalizing typo or alias variants into canonical tactic names.

## [3.4.3] - 2026-03-27

### Fixed
- **Rule Health - KQL mapping extraction for comparison operators:** Updated KQL/Lucene field extraction to detect comparison expressions (`==`, `!=`, `<=`, `>=`, `<`, `>`) in addition to `field:value` syntax. This fixes false 0/20 mapping scores for rules such as `score <= 25` where the field was previously not detected.
- **Test Rule - Preview result correlation for Kibana 8.19:** Updated preview alert lookup to support both `kibana.alert.rule.preview_id` and `kibana.alert.rule.uuid` so preview hits are correctly returned instead of false 0-hit results.

## [3.4.2] - 2026-03-26

### Added
- **External Query API (Sidecar):** New `POST /api/external/query` endpoint enables external applications to run read-only SQL against TIDE's DuckDB. Authenticated via `X-TIDE-API-KEY` header with SHA-256 hashed keys stored in the database. SQL validation rejects all non-SELECT statements (DROP, DELETE, INSERT, UPDATE, INSTALL, etc.). Returns clean JSON with `columns`, `rows`, and `row_count`.
- **API Key Management (Settings):** New "API Keys" tab on the Settings page. Create labelled API keys (raw key shown once, only the SHA-256 hash is stored), view key metadata (label, created date, last used), and revoke keys. Each key's `last_used_at` is updated on every successful query.
- **DB Migration 20:** Created `api_keys` table for external API key storage.
- **External API In-App Docs (Settings):** Added External Query API guidance directly inside the API Keys tab, including endpoint/header contract, SQL security constraints, commonly queried table names, cURL examples, and sample success/error responses for quick handoff to external teams.

### Fixed
- **Rule Health — Pydantic score constraints silently drop rules:** Removed `ge`/`le` Field constraints from all 11 score fields in `DetectionRule`. Sub-scores that exceed the expected range (e.g. `score_field_type=12` when `le=11`) caused Pydantic to reject the entire rule silently — the model never constructed, and the rule vanished from the grid. Bounds are now enforced at scoring time only, not at read time.
- **Rule Health — COALESCE-based sort for NULL scores:** Replaced `ORDER BY score ASC NULLS LAST` with `ORDER BY COALESCE(score, 0) ASC, name ASC` across all sort modes. The previous fallback `sort_map.get(sort_by, "score ASC")` used bare `score ASC` without any NULL handling, causing NULL-scored rules to cluster on page 1 and trigger downstream conversion failures.
- **Rule Health — pd.NA handling in `_safe_int` and new `_safe_str`:** Enhanced `_safe_int` to detect `pd.NA` (newer DuckDB/pandas versions) via `pd.isna()` instead of `isinstance(float) and math.isnan()`. Added `_safe_str` helper for string fields where `pd.NA` raises `TypeError` on the `or` operator.
- **Rule Health — API error resilience:** Wrapped the `list_rules` endpoint in `try/except` to return an HTML error div instead of a silent HTTP 500. Previously, one conversion failure caused HTMX to leave the page in a permanent "Loading…" state with no feedback.
- **Test Rule — silent 0 results when preview has warnings:** Preview API warnings (e.g. "no matching index found") and execution errors were only logged server-side — the user saw "0 Documents Matched" with no explanation. Warnings and errors from the Kibana preview logs are now surfaced to the UI when hit count is 0.
- **Test Rule — `_fetch_preview_alerts` errors hidden:** Auth failures, HTTP errors, and exceptions in the alert-fetch step returned `(0, [])` silently. Now returns the actual error message so the UI can display it.
- **Test Rule — `isAborted` not checked:** Preview API responses with `isAborted: true` (query too expensive / timed out) were treated as 0 results. Now returns an explicit error message.
- **Test Rule — `datetime.now()` used instead of UTC:** The `timeframeEnd` timestamp used local time with a hardcoded "Z" (UTC) suffix. On containers with a non-UTC timezone this shifts the preview window. Now uses `datetime.now(timezone.utc)`.
- **Test Rule — `match` query for preview_id:** Changed to `term` query for exact keyword matching on `kibana.alert.rule.preview_id`.
- **Test Rule — missing `filters` in preview payload:** Rules with Kibana filters (4 of 239 rules locally) had those filters silently dropped from the preview, potentially altering match behaviour.
- **Test Rule — missing fields for special rule types:** `threat_match` rules now include `threat_query`, `threat_mapping`, `threat_index`, and `threat_language`. `new_terms` rules now include `new_terms_fields` and `history_window_start`.

## [3.4.1]- 2026-03-24

### Fixed
- **Rule Health — "All Spaces" empty grid:** Rules failed to display when viewing all spaces with the default sort (Score Low → High). Root cause: DuckDB NULL columns become `NaN` in pandas, but `dict.get('score', 0)` returns `NaN` (not `0`) because the key exists — Pydantic then rejects `NaN` as an `int`, crashing the entire response silently. Fixed with null-safe `_safe_int()` and `_safe_dt()` helpers across all numeric and timestamp fields in `_row_to_rule`.
- **Rule Health — NULL score sorting:** Added `NULLS LAST` to all `ORDER BY` clauses so rules with NULL scores no longer land on page 1 of the default "Score Low → High" sort.
- **Rule Health — single bad rule crashes grid:** Wrapped the `_row_to_rule` conversion loop in per-rule `try/except` with logging. One corrupt row no longer kills the entire `/api/rules` response — it is skipped and logged as a warning with the rule ID and space.
- **Rule Health — NaT timestamp crash:** `last_updated` NULL values from DuckDB arrive as `pd.NaT` (not `None`), which Pydantic rejects for `Optional[datetime]`. Added `_safe_dt()` to convert `NaT` → `None`.
- **Rule Health — mitre_ids NULL elements:** Filtered out `None`/empty entries from `mitre_ids` arrays that can appear from DuckDB NULL array elements.
- **Test Rule — always 0 results:** The Kibana Preview API (8.7+) returns a `previewId` immediately but writes alerts to the `.preview.alerts-*` index asynchronously. The follow-up search was racing against Kibana and finding 0 docs. Added a retry loop (up to 3 attempts with 1s delay) and 404 handling for when the preview index hasn't been created yet.
- **Test Rule — empty index for data view rules:** Rules using Kibana data views instead of explicit index patterns sent an empty `index: []` to the Preview API, producing no results. Now resolves data view indices before calling the Preview API.

## [3.4.0] - 2026-03-23

### Fixed
- **Starlette 1.0 compatibility:** Updated all `TemplateResponse` calls across `main.py`, `heatmap.py`, `rules.py`, `promotion.py`, `sigma.py`, `threats.py`, and `inventory.py` to use the new `TemplateResponse(request, name, context)` signature — the old positional API was removed in Starlette 1.0.
- **Jinja2 template caching:** Added `_NoCache` shim to prevent `TypeError: unhashable type: 'dict'` when Jinja2 tries to hash template globals as cache keys.
- **Dockerfile:** Downgraded Python base image from 3.14 to 3.13 for broader package compatibility.
- **System Report cover:** Removed duplicate classification badge (was showing both report classification and system classification separately).
- **System Report export modal:** Classification dropdown now pre-populates from the system's own classification level.

### Enhanced
- **System Report executive summary:** Added narrative paragraph that interprets the scores — describes coverage ratio as strong/moderate/low with contextual recommendations, device counts, and blind spot notes.
- **Baseline Report executive summary:** Added narrative paragraph summarising baseline scope, system count, and coverage assessment with actionable guidance based on the average coverage score.

## [3.3.14] - 2026-03-23

### Fixed
- **Startup:** `markdown` package import no longer crashes the app if the package is missing — falls back to plain text rendering with line breaks.
- **Reports:** `_build_baseline_heatmap` no longer crashes system report generation if the `report_generator` import or technique DB queries fail — returns empty heatmap gracefully.
- **Heatmap:** Unified TACTIC_ORDER to single source of truth (`report_generator.py`). Previously `heatmap.py` defined its own 12-item list missing Reconnaissance, Resource Dev, and Other — causing inconsistent tactic rendering between heatmap page and baseline reports.

## [3.3.13] - 2026-03-23

### Changed
- **Sync Performance:** Parallelized Elasticsearch index mapping fetches (`get_batch_mappings`) using ThreadPoolExecutor (up to 10 concurrent). Previously fetched sequentially — one HTTP round-trip per index pattern.
- **Sync Performance:** Parallelized Kibana data view resolution for rules without explicit index patterns. Previously resolved one-by-one inside the rule loop.
- **CSS:** Added missing badge classes (`badge-primary`, `badge-green`, `badge-red`, `badge-amber`, `badge-info`, `badge-purple`, `badge-default`) to the main stylesheet — previously only defined inline in PDF report templates.
- **CSS:** Added card utility classes (`card-padded`, `card-padded-sm`, `card-padded-lg`, `card-flush`, `card-mb`, `card-mt`, `card-center`) replacing inline padding/margin styles across 11 page and partial templates.
- **CSS:** Defined legacy variable aliases (`--bg-secondary`, `--bg-tertiary`, `--border-color`, `--text-primary`, `--text-secondary`) in `:root` so inline modal styles resolve to the design system correctly.
- **CSS:** Added `--color-muted`, `--color-danger-rgb`, `--color-success-rgb` variables.

## [3.3.12] - 2026-03-23

### Fixed
- **CSS**: update css.

## [3.3.11] - 2026-03-23

### Fixed
- **Baselines:** Implemented Markdown and multi-line support for Baseline descriptions.

### Added
- **Systems:** Added interactive MITRE ATT&CK® Heatmap to System Detail pages with Baseline-specific filtering.


## [3.3.10] - 2026-03-19

### Added
- **Baselines:** Implemented Markdown and multi-line support for Baseline descriptions.

## [3.3.9] - 2026-03-19

### Changed
- **Baselines:** Optimized Baselines dashboard layout to 6-card grid (merged Uncovered + Fully Covered into Coverage Status).
- **Baselines:** Restored missing iconography for Baseline Definitions.
- **Baselines:** Standardized Baseline metadata pills for improved readability (compact inline string).
- **Audit History:** Refactored Audit History to support Baseline grouping and card-based snapshot views.

## [3.3.8] - 2026-03-18

### Added
- **Baselines:** Import Baseline from CSV or Excel (.xlsx/.xls). Accepts columns: Title, Tactic (Kill Chain Phase), Technique (MITRE ID), Description. Flexible column name matching (case-insensitive). New "Import" button on the Baselines page.
- **Baselines:** Kill chain phase groups are now collapsible on both the baseline detail page and the system baseline coverage view.
- **Baselines:** Imported baselines are now sorted by MITRE kill chain phase order.

## [3.3.7] - 2026-03-18


### Fixed
- **Reporting:** Removed dark background on cover for 'printability'.
- **Reporting:** Broke techniques down by tactic.
- **Baselines:** Deleting a tactic from the tactic detail page now correctly redirects to the baseline list instead of rendering a bare partial (header/sidebar missing). Root cause: HTMX does not send the `HX-Target` header when the target is `<body>` (which has no `id`); the server-side check was updated to treat an absent/empty `HX-Target` as a redirect signal.
- **Baselines / System page:** Intermittent 405 errors when submitting the Known Gap or N/A override modal. Added `method="post"` native fallback to the blind-spot forms in `baseline_coverage.html` and `tactic_affected_systems.html` so the browser falls back to POST (not GET) if HTMX binding is absent at submit time.
- **Baselines / System page:** Same `method="post"` fallback added to the Add Technique forms in `baseline_detail.html` (add-tactic modal) and `tactic_mitre_section.html` to prevent 405 errors if HTMX has not yet bound the form (e.g. long-lived page session).

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
