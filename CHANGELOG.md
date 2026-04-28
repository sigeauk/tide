# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.11]

### Added
- **Per-tenant Role Templates on the Client Detail page (`app/templates/pages/client_detail.html`):** New collapsible "Role Templates" section appears at the bottom of every client page. The body lazy-loads via `hx-get="/api/management/clients/{cid}/permissions"` (`get_client_permissions`) and renders the same role × resource matrix as before, but every checkbox toggle posts to `update_client_permission()` (`POST /api/management/clients/{cid}/permissions`) and writes through `db.set_permission(role_id, resource, can_read, can_write, client_id=cid)` so permission changes are scoped to *this* tenant only. ADMIN role rows are intentionally excluded (and the endpoint silently rejects edits to ADMIN to preserve full access). The previous global "Role Templates" section has been removed from the Management page.
- **Inline "Remove" button on every assigned-user row (`app/templates/partials/client_users.html`):** Each row in the Assigned Users panel now has a small ghost-danger Remove button next to the role select. Clicking it fires `hx-delete="/api/management/clients/{cid}/users/{uid}"` against the existing `remove_user_from_client_detail` endpoint (with an `hx-confirm` prompt). The Edit-Users modal still has the same Remove buttons for batch operations.
- **DB Migration 35 — Tenant-scoped permissions matrix:** `role_permissions` is rebuilt with a new `client_id VARCHAR` column and `UNIQUE(role_id, client_id, resource)`. Every legacy global row is fanned out into one row per existing tenant via a `CROSS JOIN clients` so existing role permissions continue to apply unchanged. New clients created after this migration receive a copy of the default client's matrix automatically (`create_client` now seeds `role_permissions` from the default tenant, falling back to any other tenant if no default exists).
- **`db.get_permissions_matrix(client_id=None)`, `db.set_permission(..., client_id=None)` and `db.get_user_permissions(user_id, client_id)` now accept a tenant id:** When supplied, all three operate strictly against that tenant's row set (no NULL-row fallback). Legacy callers that omit `client_id` continue to read/write NULL rows so existing tooling does not break, but the runtime permission lookup performed in `get_active_client` always passes the active tenant — meaning a user's effective permissions are always tenant-scoped after this release.

### Changed
- **Management > Users tab no longer shows the per-row Roles column or the role checkboxes in the Add User form (`app/api/management.py`):** Roles are now assigned per-tenant from the Client Detail page, so `_render_users_tab()` drops the Roles `<th>` plus the inline `hx-post="/api/management/users/{u.id}/roles"` form, and the Add User form drops the `new_roles` checklist. `mgmt_create_user()` no longer reads `form.getlist("new_roles")` and the toast directs the operator to set the role from the client detail page.
- **Per-tenant role assignment from the Client Detail page (`app/templates/partials/client_users.html`):** The "Assigned Users" panel now renders a role `<select>` next to every assigned user that pre-selects their current role for *this* tenant (resolved via `db.get_user_roles(uid, client_id=client.id)`). Changing the dropdown fires `hx-put="/api/management/clients/{cid}/users/{uid}/role"` against the new `update_client_user_role()` endpoint, which calls `db.set_user_roles(uid, [role], client_id=cid)` so the change is scoped to the active client only — granting `darral` the ENGINEER role in DC no longer cascades into Marvel. The "Assign User" form gained a matching role `<select>` (defaulting to `ANALYST`) so a freshly-assigned user lands on the client with their tenant role already set in a single round-trip.
- **`POST /api/management/clients/{client_id}/users` accepts an optional `role` form field:** `assign_user_to_client()` (`app/api/management.py`) now reads `form.get("role")` and, when present, calls `db.set_user_roles(user_id, [role_name], client_id=client_id)` after the existing `db.assign_user_to_client()` call.
- **`db.get_user_permissions(user_id, client_id=None)` overload (`app/services/database.py`):** Adds an optional `client_id` parameter that is forwarded to the existing tenant-aware `get_user_roles(user_id, client_id=...)` call. When supplied, only the user's roles in that tenant contribute to the resulting `{resource: {can_read, can_write}}` map. The legacy `client_id=None` behaviour (merge across every tenant the user belongs to) is preserved verbatim so existing callers in `app/services/auth.py` (4 sites) continue to work.

### Changed
- **`get_active_client` (`app/api/deps.py`) refreshes `user.permissions` per active tenant:** After resolving the active client and refreshing `user.roles`, the dep now also calls `db.get_user_permissions(user.id, client_id=client_id)` and assigns the result to `user.permissions`. Super-admins keep an empty map because their bypass lives in `User.can_read` / `User.can_write`. The combined effect is that the sidebar (which already gates with `user.can_read('page:X')`) now reflects the *active* tenant's role permissions only — a tenant ADMIN in DC who is an ANALYST in Marvel sees the full nav while in DC and the ANALYST-restricted nav while in Marvel.
- **`User.can_read` / `User.can_write` (`app/models/auth.py`) gate on the active tenant:** The previous bypass `if self.is_admin(): return True` returned True for ADMIN-in-any-tenant, which leaked write capabilities across tenants. Both helpers now bypass only for `is_superadmin` or `is_admin(self.active_client_id)` so a DC-only admin no longer auto-passes write checks for resources scoped to Marvel.
- **`/management?tab=permissions` legacy URL falls back to the Clients tab:** The Permissions sub-tab no longer exists; the route handler in `app/main.py` (`management_page`) has been updated so any legacy bookmark that requested `?tab=permissions` lands on the default Clients sub-tab (the matrix itself is reachable a click away in the new Role Templates section).
- **`_render_client_users_partial` (`app/api/management.py`) now passes `all_roles` to the template** and pre-decorates each `client_users` entry with `_current_role` so the per-row dropdown can render without the template doing N queries. The same enrichment is performed inline in `client_detail_page()` (`app/main.py`) for the initial server-side render.
- **Keycloak group → TIDE role passthrough:** Login (both the OIDC redirect path and the local-form Resource-Owner-Password-Credentials fallback) now inspects the access-token's `groups` and `realm_access.roles` claims and maps them to one of the three built-in TIDE roles (`ADMIN`, `ENGINEER`, `ANALYST`) using a highest-priority-wins rule (ADMIN > ENGINEER > ANALYST). Both singular and plural names match (`admin`/`admins`, `engineer`/`engineers`, `analyst`/`analysts`) and Keycloak group paths like `/admins` are stripped before comparison. Implemented in `AuthService._map_kc_token_to_role()` (`app/services/auth.py`); the resolved role is passed into `DatabaseService.jit_provision_keycloak_user(..., kc_role=...)` which calls the new `_sync_kc_role_to_primary()` helper. KC role sync is **scoped to the Primary (default) Client only** — if a TIDE admin manually grants a user a different role in DC or Marvel, that mapping is preserved across logins. New users land in the Primary Client with their mapped role (defaulting to `ANALYST` when no group claim matches).
- **Keycloak `superadmin` group → platform super-admin:** A new boolean column `users.is_superadmin` (default `false`) is set/cleared on every login from the presence of the `superadmin` group/role claim. Super-admins bypass the per-tenant access checks in `get_active_client()` (they can switch into any client) and in `clients.list_clients`/`get_client`/`switch_client`. The bootstrap `admin` account is migrated to `is_superadmin=true` so existing deployments retain their full management reach. New `RequireSuperadmin` FastAPI dependency in `app/api/deps.py` and `DatabaseService.set_user_superadmin()` helper.
- **Tenant-scoped roles:** `user_roles` now carries a `client_id` column with PK `(user_id, client_id, role_id)` — an ADMIN in DC is no longer automatically an ADMIN in Marvel. `DatabaseService.get_user_roles(user_id, client_id=None)` and the new `get_user_role_map(user_id) -> {client_id: [roles]}` expose per-tenant memberships; `set_user_roles(user_id, role_names, client_id=None)` accepts an explicit tenant (legacy `client_id=None` callers replace roles across every client the user is assigned to, preserving prior behaviour). `User` gained `client_roles: Dict[str, List[str]]`; `is_admin()` returns True for super-admins, for ADMIN-in-the-given-tenant, or — when called without an argument — for ADMIN in *any* assigned tenant (used to gate management-panel entry).
- **Per-tenant role refresh inside `get_active_client`:** Once the active client is resolved, `user.active_client_id` is set and `user.roles` is replaced with that tenant's role list (or `["ADMIN"]` for super-admins) so all downstream `user.has_role()` / `user.is_admin()` checks reason about the active tenant.
- **Offline-fallback bcrypt cache for SSO users:** When a Keycloak-provisioned user (no local `password_hash`) successfully signs in via the local-form ROPC path, `AuthService.authenticate_local()` now hashes the just-validated password with bcrypt and writes it to `users.password_hash`. Subsequent logins succeed against the local hash even when Keycloak is offline, fixing the previously-broken assumption that one successful SSO login made the credentials available offline. The hash is only written after Keycloak has confirmed the credentials are valid.

- **Management hub is now tenant-scoped for non-super-admin admins:** `tab_clients`, `tab_siems`, `tab_users` (`app/api/management.py`) all take an `ActiveClient` dependency. A DC admin signed into DC sees only the DC tenant card, only the SIEMs linked to their tenants, and only the users that share at least one tenant with them — no Marvel data leaks into the panel. Super-admins continue to see every tenant. The user-list role badges are loaded for the active client only via `db.get_user_roles(uid, client_id=active)`.
- **`POST /api/management/users` writes to the active tenant only:** Newly-created local users are assigned to the *active* client (set as `is_default=true`) and their roles are stored in `user_roles` against that client only. Previously the legacy `set_user_roles(uid, roles)` call wrote a global mapping that bled into every tenant the user later joined.
- **`POST /api/management/users/{user_id}/roles` is gated per tenant:** Non-super-admin admins may only edit roles for users that share an admin-tenant with them, and only against a client they administer. Returns a toast and a 200-with-warning response otherwise.
- **`GET /api/clients`:** "Admins see all" now means **super-admins** see all; a tenant ADMIN sees only the clients they belong to via `user_clients`. `POST /api/clients` and `DELETE /api/clients/{id}` are restricted to super-admins via the new `RequireSuperadmin` dependency. `PUT /api/clients/{id}` accepts super-admins or the tenant's own ADMIN role. `POST /api/clients/switch` lets super-admins hop into any tenant; everyone else is constrained to their `user_clients` list.
- **`get_active_client` access check:** Super-admin bypass replaces the previous "any admin" bypass — a DC admin can no longer access Marvel data by setting `X-Client-ID: <marvel-uuid>`.
- **`User` model — `is_admin()` accepts an optional `client_id`:** Routes that need to assert "is the user the admin of *this* tenant" can call `user.is_admin(client_id=...)`; existing parameter-less calls retain their meaning ("admin somewhere"). New `User.is_superadmin` boolean.
- **`User.dev_user()` (auth-disabled mode) is now flagged `is_superadmin=true`** so AUTH_DISABLED runs continue to see every tenant under the new tighter rules.

### Fixed
- **Could not log in once Keycloak was offline (root cause):** `AuthService.authenticate_local()` only succeeded against `users.password_hash`; SSO-provisioned users (created via `auth_provider="keycloak"`) had a NULL hash and the path fell through to `_authenticate_via_keycloak()`, which raises a connection error the moment Keycloak is unreachable. The new offline-fallback bcrypt backfill (above) materialises a local hash on every successful ROPC login, restoring the operator-expected behaviour where local creds keep working after the first SSO sign-in.
- **DB Migration 34 — Tenant-scoped roles + super-admin foundation:** Adds `users.is_superadmin BOOLEAN DEFAULT false`; rebuilds `user_roles` with `(user_id, client_id, role_id)` as the primary key and backfills every existing global role into one row per (user, client) the user is currently assigned to (falling back to the default client when the user has no `user_clients` rows). Promotes any pre-existing local `admin` account to `is_superadmin=true` so the bootstrap user keeps full management access through the migration. The fresh-install bootstrap path (`_ensure_users_table`) now writes `is_superadmin=true` and a `(user_id, client_id, role_id)` row directly.
- **Elastic/Kibana connection no longer falls back to global `.env` (`app/services/sync.py`, `app/elastic_helper.py`, `app/sigma_helper.py`, `app/api/sigma.py`, `app/api/rules.py`, `app/config.py`, `app/services/database.py`):** The 4.0.7/4.0.9 migration left several call sites still resolving `ELASTIC_URL` / `ELASTIC_API_KEY` / `ELASTICSEARCH_URL` via `os.getenv()`, so after the env keys were removed from `.env` the scheduled sync, Sigma deploy, exception/promotion fallbacks, and direct-ES mapping queries silently broke (or, worse, hit whatever URL the env vars had previously pointed at).
  - **`run_elastic_sync()` is now per-SIEM:** Iterates `db.list_siem_inventory()` (active rows only) and calls `elastic_helper.fetch_detection_rules(kibana_url=..., api_key=..., spaces=..., elasticsearch_url=...)` once per SIEM, threading each SIEM's own `kibana_url`, `api_token_enc`, declared spaces (resolved via the new `db.get_siem_spaces(siem_id)` helper, falling back to `production_space`/`staging_space` when no client mapping exists yet), and `elasticsearch_url`. Frames are concatenated and saved with the existing subtractive-sync logic. The old "no SIEM mappings → fall back to `KIBANA_SPACES`" code path is gone.
  - **`elastic_helper.fetch_detection_rules` signature changed:** `kibana_url` and `api_key` are now required positional/keyword arguments (no env fallback); `spaces` replaces `spaces_override`; new optional `elasticsearch_url` is forwarded to `get_batch_mappings()` for the direct-ES bypass on field mapping fetches.
  - **`elastic_helper.preview_detection_rule` requires `kibana_url` + `api_key`:** Returns a clean toast error when missing instead of silently falling through to env vars. Now also accepts an optional `elasticsearch_url` that is threaded into `_fetch_preview_alerts` (replacing its `os.getenv("ELASTICSEARCH_URL")` lookup), so the preview-alerts query honours the per-tenant direct-ES URL.
  - **`elastic_helper.get_promotion_session()` removed entirely.** Every promotion helper (`get_space_rule_ids`, `get_exception_list`, `get_exception_list_entries`, `create_exception_list_in_target`, `create_exception_entry_in_target`, `promote_rule_to_production`) now requires its caller to supply `session` and `base_url` resolved from `siem_inventory` — the implicit `session=None` env-fallback branch has been deleted from all six. `promote_rule_to_production` raises a clean error when source/target SIEM creds are missing.
  - **`sigma_helper.send_rule_to_siem` requires `kibana_url` + `api_key`:** The `os.getenv('ELASTIC_URL'/'ELASTIC_API_KEY')` block is gone. Returns a clean error string when missing.
  - **`POST /api/sigma/deploy` (`app/api/sigma.py`) resolves the SIEM per-tenant:** Iterates `db.get_client_siems(client_id)` and matches by `space` to find the right `kibana_url` + `api_token_enc`, mirroring the pattern already used by `POST /api/rules/{rule_id}/test`. Returns a 400 toast when the active client has no SIEM linked for the requested space.
  - **`POST /api/rules/{rule_id}/test` now also threads `elasticsearch_url`** through to `preview_detection_rule()` so the preview-alerts index search uses the per-tenant direct-ES URL.
  - **`app/config.py` drops the dead `elasticsearch_url` / `elastic_url` / `elastic_api_key` fields.** They were unused after the call-site refactor; keeping them as `Settings` aliases would invite regressions where new code re-reads the global value instead of resolving per-tenant.
  - **New `db.get_siem_spaces(siem_id) -> List[str]`** returns the distinct Kibana spaces mapped to a single SIEM via `client_siem_map` (NULL/empty → `default`). Used by the per-SIEM sync loop.
  - Verified end-to-end inside `tide-app` with `ELASTIC_URL` / `ELASTIC_API_KEY` / `ELASTICSEARCH_URL` / `KIBANA_SPACES` stripped from the process environment: `run_elastic_sync()` returned 15 rules from the configured SIEM, `preview_detection_rule()` and `send_rule_to_siem()` returned clean error strings (no AttributeError) when called with empty creds, and `Settings` no longer exposes the dropped fields.

## [4.0.9]

### Fixed
- **External Query API — `README.md` examples returned `403 Forbidden` for multi-tenant API keys:** The documented `curl` payloads embedded `client_id` values as truncated UUIDs (`"client_id": "8bab9263-..."`, `"client_id": "1b650e71-..."`) inside fully-quoted JSON `-d` blocks. The ellipsis was not placeholder syntax — it was sent on the wire as a literal string, which `external_query()` in `app/api/external_sharing.py` correctly rejects via the `target_client_id not in allowed_client_ids` membership check (HTTP 403, `"API key does not have access to the requested tenant."`). The 4.0.7 fix to `validate_api_key_full()` did not change the request schema; the schema has been correct since 4.0.3 when `client_id` was first introduced as a request body field. No code change required — the FastAPI route, `QueryRequest` Pydantic model, and `validate_api_key_full()` ownership resolution all behave as designed. README updated to use a clearly-marked `<TENANT_CLIENT_ID>` placeholder (mirroring the existing `YOUR_KEY_HERE` convention), to print full UUIDs in the `GET /api/external/clients` sample response, and to call out that the API performs an exact string match against `user_clients.client_id` so any abbreviation returns 403. Validated end-to-end through the public nginx 443 ingress using an ephemeral `curlimages/curl` container on the host network: `GET /api/external/clients` → 200 with three tenants, `POST /api/external/query` with truncated UUID → 403, `POST /api/external/query` with full UUID → 200.

## [4.0.8]

### Added
- **Management Hub Phase 3 — Sigma Assets section is functional:** Replaces the Phase-2 placeholder with a two-pane editor for both pipelines (`./data/sigma_pipelines/`) and templates (`./data/sigma_templates/`). Each pane mounts a CodeMirror YAML editor (loaded via `{% block head %}` in `templates/pages/management.html`) and reuses the existing `/api/sigma/saved-pipelines` + `/api/sigma/saved-templates` CRUD endpoints. Editor JS is initialised lazily on first `<details>` toggle and refreshes CodeMirror on subsequent opens to avoid the zero-height bug.
- **Sigma Asset → Tenant assignment ("force-assign-on-save"):** Each editor exposes an `Assign tenants…` button that opens a modal listing all clients via `GET /api/clients`. Selection is persisted via three new endpoints in `app/api/sigma.py` — `GET /api/sigma/assignments/{asset_type}`, `GET /api/sigma/assignments/{asset_type}/{filename}`, and `PUT /api/sigma/assignments/{asset_type}/{filename}` — which call `db.list_sigma_asset_assignments()`, `db.get_sigma_asset_clients()`, and `db.set_sigma_asset_assignments()` respectively. Empty `client_ids` lists are rejected with HTTP 422 so an asset cannot be left orphaned. Tenant chips render next to each editor and refresh after every save/load. Deleting a saved pipeline or template now also calls `db.delete_sigma_asset_assignments()` to clear the assignment rows.
- **Management Hub Phase 3 — Classifications section is functional:** Replaces the Phase-2 placeholder with an inline create form (name + colour) wired to the existing `POST /api/inventory/classifications` endpoint and a `#clf-list` HTMX container that auto-loads `GET /api/inventory/classifications`. The container ID matches the hardcoded `hx-target="#clf-list"` on the delete buttons rendered by `partials/classification_list.html`, so delete-swaps continue to work.
- **Management Hub Phase 3 — per-SIEM Rule Logging on every SIEM card:** Each SIEM card in the Management hub now renders a Rule Logging `<details>` block (helper `_siem_logging_block_html()` in `app/api/management.py`) with a status pill ("Logging On" / "Logging Off") and a form for `enabled`, `target_space` (a `<select>` populated from the SIEM's `production_space` / `staging_space`, falling back to a freeform `<input>` when neither is configured), `schedule` (HH:MM), and `retention_days` (1–365). Form submissions hit the new `POST /api/management/siems/{siem_id}/logging` endpoint, which persists the configuration via `db.update_siem_logging_config()`, calls `reschedule_rule_log_job()` from `app.main` (lazy import to avoid a circular dependency), and re-renders the SIEMs sub-tab partial.
- **`test/verify_management_phase3.py`:** Authenticated container-side verification script that asserts the Management page renders the Sigma Assets section, pipeline/template editors, Classifications `#clf-list` container, CodeMirror imports and tenant assignment modal; that the SIEMs tab partial includes the Rule Logging block; that Settings is trimmed to Profile only (no Sigma / Logging / Classifications tabs, no CodeMirror); and that the new Sigma assignment endpoints accept valid payloads, reject empty `client_ids` with 422, and round-trip an assignment.

### Changed
- **`app/services/rule_logger.run_rule_log_export()` is now per-SIEM:** Previously the export was driven by the global `app_settings.rule_log_enabled` / `rule_log_schedule` / `rule_log_retention_days` keys. The export now calls `db.list_logging_enabled_siems()` first; when one or more SIEMs have `log_enabled=true`, each SIEM gets its own subdirectory (`{base}/{safe_label}/`, where `safe_label` keeps `[a-zA-Z0-9-_.]` and replaces other characters with `_`), uses its own `log_retention_days` value, and runs `cleanup_old_logs()` per directory. The legacy global path is preserved as a fallback when no SIEMs have logging enabled, so existing single-SIEM deployments keep working without reconfiguration.
- **`app/templates/pages/settings.html` trimmed to Profile only (777 → 137 lines):** The Logging, Integrations, Sigma, and Classifications tabs and panels (and ~280 lines of CodeMirror pipeline/template editor JavaScript) have been removed. CodeMirror CSS/JS imports were dropped from `{% block head %}`. The page header now links users to `/management` for tenant, SIEM, logging, Sigma asset, and classification administration. Profile + API-key management is unchanged.
- **Management Hub — per-card persistent status pill:** Every SIEM, Threat Intel, GitLab, and Keycloak card now renders a `status-pill` (Active / Failed / Untested) sourced from the persisted `last_test_status` / `last_test_at` / `last_test_message` columns added in Migration 33. The pill carries a `title` tooltip showing the timestamp and last error message.
- **Management Hub — per-card Test Connection button:** Each inventory card has its own Test button that POSTs to a unified `POST /api/management/{kind}/{item_id}/test` endpoint and OOB-swaps the refreshed status pill back into place. Supports `siems`, `opencti`, `gitlab`, and `keycloak` via a single `_run_inventory_test()` dispatcher. The legacy modal Test buttons (SIEM / OpenCTI / Keycloak) now also persist their result through `db.update_inventory_test_status()` when called against an existing item.
- **Management Hub — clickable tenant chips:** Linked clients on each inventory card render as `tenant-chip` pills that link to `/clients/{id}` in a new tab (deduplicated via a `seen` set). The Keycloak singleton renders a single dashed `tenant-chip--all` "All tenants" pill instead of a full client list.
- **GitLab — live Test Connection:** The new unified test endpoint performs a real `GET {url}/api/v4/version` with a `PRIVATE-TOKEN` header for GitLab cards, persisting the result to `last_test_status`.
- **Shared management helpers (`app/api/management.py`):** New `_KIND_TO_INVENTORY` dict, `_status_pill_html()`, `_tenant_chips_html()`, `_test_button_html()`, `_fetch_inventory_item()`, and `_run_inventory_test()` consolidate inventory-card rendering and live-test logic so the four renderers stay in lock-step.
- **CSS — Management hub component classes (`app/static/css/style.css`):** New `.mgmt-section` / `.mgmt-section__summary|title|hint|body` rules (with rotating `::before` chevron via `[open]`), nested `.mgmt-subsection*` variant, `.settings-tabs--inline` modifier (preserves Tenants & Users sub-tabs), `.tenant-chip` + `.tenant-chip--all` (dashed singleton), and `.status-pill` + `.status-pill--ok|fail|unknown` + `.status-dot` (oklch greens/reds matching the dashboard integration-card palette).
- **DB Migration 33 — Management Hub consolidation foundation:** Adds `last_test_status` / `last_test_at` / `last_test_message` columns to all four inventory tables (`siem_inventory`, `opencti_inventory`, `gitlab_inventory`, `keycloak_inventory`) so the per-instance Test-Connection result persists across page loads and reboots. Adds `log_enabled` / `log_target_space` / `log_schedule` / `log_retention_days` columns to `siem_inventory` so rule-score logging is configured **per SIEM** rather than globally per client. Adds new `sigma_asset_assignments(asset_type, filename, client_id)` table for tenant-scoping Sigma pipeline/template YAML files. Best-effort migrates existing `app_settings.rule_log_enabled` / `rule_log_schedule` / `rule_log_retention_days` rows onto each tenant's first production-role SIEM (`log_target_space` is left NULL so the operator must explicitly pick production vs staging space) and deletes the legacy keys.
- **`DatabaseService.update_inventory_test_status(kind, item_id, status, message)`:** Persists the result of a Test-Connection click for any of `siems` / `opencti` / `gitlab` / `keycloak` so the status badge survives reload.
- **`DatabaseService.update_siem_logging_config(siem_id, ...)` and `list_logging_enabled_siems()`:** Drive per-SIEM rule-score export configuration and enumeration for `services/rule_logger.py`.
- **`DatabaseService.list_sigma_asset_assignments` / `get_sigma_asset_clients` / `set_sigma_asset_assignments` / `delete_sigma_asset_assignments` / `list_sigma_assets_for_client`:** Tenant-assignment CRUD for Sigma pipeline and template YAML files (force-assign-on-save).
- **`list_siem_inventory` / `list_opencti_inventory` / `list_gitlab_inventory` / `list_keycloak_inventory` now select the test-status and (for SIEM) logging columns** so templates can render badges and configuration without a second query.
- **Management Hub — Threat Intel tab:** New "Threat Intel" tab in the Management panel for registering OpenCTI instances. Instances are stored in a new `opencti_inventory` table with encrypted tokens and linked to clients via `client_opencti_map`. Full CRUD via `POST/PUT/DELETE /api/management/opencti` routes.
- **Management Hub — GitLab tab:** New "GitLab" tab in the Management panel (marked "Planned") for pre-registering GitLab instances for future report-push workflows. Stored in `gitlab_inventory` / `client_gitlab_map` tables.
- **Management Hub — Keycloak tab:** New "Keycloak" tab in the Management panel for registering Keycloak SSO instances. Stores URL, realm, client ID, and client secret (encrypted) in a new `keycloak_inventory` table. Full CRUD via `POST/PUT/DELETE /api/management/keycloak` routes.
- **DB Migration 31:** Adds `opencti_inventory`, `client_opencti_map`, `gitlab_inventory`, and `client_gitlab_map` tables.
- **DB Migration 32:** Adds `keycloak_inventory` table for Keycloak SSO instance registration.
- **Configurable bootstrap admin credentials:** The default `admin`/`admin` account created on first run now reads from `BOOTSTRAP_ADMIN_USERNAME` / `BOOTSTRAP_ADMIN_PASSWORD` environment variables (set in `docker-compose.yml`). Defaults remain `admin`/`admin` if not overridden.
- **OpenCTI — Test Connection button:** New "Test Connection" button in the OpenCTI create/edit modal that POSTs to `POST /api/management/opencti/test-connection`. Uses the stored token when the field is left blank (edit mode). Shows connection status badge inline.
- **Client Detail — Linked Threat Intel section:** New collapsible "Linked Threat Intel (OpenCTI)" section on the client detail page. Allows linking and unlinking OpenCTI instances to a client, following the same pattern as the Linked SIEMs section.

### Changed
- **Management Hub — removed top-level tab strip and "Added {date}" lines:** The seven-tab strip in `templates/pages/management.html` is gone; the surviving Clients / Users / Permissions inline tabs now live inside the Tenants & Users `<details>` section. Inventory cards no longer render the `Added {date}` row — that information moved into the status-pill tooltip.
- **`/management` route tab whitelist (`app/main.py`):** Narrowed to `("clients", "users", "permissions")`. Legacy values (`integrations`, `sigma`, `classifications`, `logging`, `threat-intel`, `gitlab`, `keycloak`) fall back to `clients`; the integration sub-sections are now reached through the collapsible UI rather than `?tab=`.
- **HTMX swap targets retargeted (`app/templates/pages/management.html`):** All four integration delete buttons and the four modal submit JS handlers (`submitSiemForm`, `submitOpenCTIForm`, `submitGitLabForm`, `submitKeycloakForm`) now swap into `#mgmt-sub-{siems|opencti|gitlab|keycloak}` with a `|| document.getElementById('management-content')` fallback. `testKeycloakConnection()` now sends the `keycloak_id` form field so persistent test-status writes can resolve the row.
- **`services/sync.py` — OpenCTI DB-first:** `run_mitre_sync()` now queries `opencti_inventory` (active instances) before falling back to the legacy `OPENCTI_URL`/`OPENCTI_TOKEN` environment variables. Supports syncing multiple OpenCTI instances in a single pass.
- **`.env.example` cleanup:** Removed deprecated variables that are now managed in-app or at build time: `TIDE_VERSION`, `ELASTICSEARCH_URL`, `ELASTIC_URL`, `ELASTIC_API_KEY`, `KIBANA_SPACES`, `OPENCTI_URL`, `OPENCTI_TOKEN`, `GITLAB_URL`, `GITLAB_TOKEN`, `MITRE_SOURCE`, `MITRE_MOBILE_SOURCE`, `MITRE_ICS_SOURCE`, `MITRE_PRE_SOURCE`, `SIGMA_SOURCE`, and `RULE_LOG_PATH`. Added commented example for bootstrap admin overrides.
- **Settings — Integrations tab:** Removed stale Elasticsearch/OpenCTI status rows. Replaced with a link to the Management Hub where integrations are now configured. Updated "Host Log Path" description to reference `docker-compose.yml` volume mount instead of `.env`.
- **`docker-compose.yml`:** Added `BOOTSTRAP_ADMIN_USERNAME` and `BOOTSTRAP_ADMIN_PASSWORD` environment variables to the `tide-app` service.

### Fixed
- **Test Connection — status pill never updated (Keycloak / OpenCTI / GitLab / SIEM):** `DatabaseService.update_inventory_test_status()` only accepted `status="success"|"fail"` but every caller (legacy modal endpoints and the new unified `POST /api/management/{kind}/{item_id}/test`) passes `"pass"`, so the `UPDATE` was silently rejected and the per-card pill stayed on "Untested" even after a successful test. The validator now accepts `"pass"|"fail"` (and maps legacy `"success"` → `"pass"`) so the pill correctly swaps to Active / Failed with the timestamp and last message.
- **OpenCTI — "Token not set" badge shown after saving a token:** `list_opencti_inventory()` was not selecting `token_enc`, so the management hub always showed "✗ not set" even after a token was saved. Now selects `token_enc` in the query so the badge reflects actual state.
- **OpenCTI — Token not persisted on edit:** `update_opencti` route was reading both `token_enc` (not present in form) and `token` but the second assignment was overwriting the first with an empty value, effectively clearing the token on save. Fixed to read `token` only and skip the update if blank (keep-existing semantics).
- **SIEM — Test Connection uses blank token in edit mode:** When editing an existing SIEM the token field is intentionally blank ("Leave blank to keep existing"). `testSiemConnection()` now sends the `siem_id` alongside the form data, and the backend falls back to the stored `api_token_enc` when the token field is empty. Both the JS and the `POST /api/management/siems/test-connection` handler were updated.
- **Management Hub tab whitelist:** Direct URL navigation to `/management?tab=threat-intel`, `/management?tab=gitlab`, and `/management?tab=keycloak` no longer redirects to the Clients tab. The tab whitelist in `main.py` now includes these three values.
- **Keycloak — Test Connection button:** New "Test Connection" button in the Keycloak create/edit modal that POSTs to `POST /api/management/keycloak/test-connection`. Hits the OIDC discovery endpoint (`{url}/realms/{realm}/.well-known/openid-configuration`) and shows a connection status badge inline.
- **Management Hub — icon macro refactor:** All Management tab buttons now use the `icon()` Jinja macro from `macros/icons.html` instead of inline SVG paths. SIEM tab uses `shield-check`, Threat Intel uses `target` (concentric circles, matching the sidebar), GitLab uses `gitlab`, Keycloak uses the new `key` icon. Added `key` icon entry to `macros/icons.html`.
- **Sidebar hidden for unauthenticated users:** `base.html` now conditionally renders the sidebar only when `user` is set. When no user is present (login page, logout redirect), the layout adds a `no-sidebar` CSS class that removes the left margin, so the login page no longer exposes page names or tenant context from the navigation.
- **Rule Health → Test Rule built `None/api/...` URL after env-to-UI migration:** `elastic_helper.preview_detection_rule()` resolved its Kibana base URL via `get_promotion_session()`, which read `ELASTIC_URL`/`ELASTIC_API_KEY` from the environment. After those variables were removed from `.env` (now managed per-tenant in `siem_inventory`), the base URL became the literal string `None` and preview POSTs 404'd. `preview_detection_rule()` now accepts explicit `kibana_url` + `api_key` arguments and returns a clear error when neither can be resolved. `POST /api/rules/{rule_id}/test` in `api/rules.py` now resolves the target SIEM from `client_siem_map` by matching the rule's Kibana space (via `db.get_client_siems(client_id)`) and passes the SIEM's `kibana_url` and decrypted `api_token_enc` through — mirroring the promote-rule path. Returns a 400 toast when the active client has no SIEM linked for the rule's space.
- **OpenCTI enrichment leaked across tenants:** `engine/sync_manager.fetch_opencti_vuln_index()` used a single process-wide `_octi_bulk_cache` populated from `settings.opencti_url` / `settings.opencti_token`, so the first tenant whose request warmed the cache exposed its entire OpenCTI vulnerability index to every other tenant — including clients with no OpenCTI linked. `_octi_bulk_cache` and `_octi_bulk_cache_ts` are now `Dict[str, ...]` keyed by `client_id`. `fetch_opencti_vuln_index(client_id)` and `_do_fetch_opencti_vuln_index(client_id)` read per-tenant credentials from a new `db.get_client_opencti_config(client_id)` helper (resolves `client_opencti_map` → `opencti_inventory`) and return an empty index when the client has no OpenCTI assigned. `inventory_engine._ensure_opencti_index_warm(client_id)`, `_match_software_against_opencti(..., client_id=...)`, and the `_octi_warmup_started` flag are all now per-tenant; all four call sites in `inventory_engine.py` thread `client_id` through. `clear_opencti_vuln_cache()` flushes the per-tenant dicts.

## [4.0.7] - 2026-04-23

### Fixed
- **External API: authenticated tenant listing worked but queries returned 401/404:** `validate_api_key_full` in `database.py` returned `None` for any key whose `created_by_user_id` was `NULL`, causing `POST /api/external/query` to reject valid keys even when `GET /api/external/clients` succeeded (which uses the same validation path). The `GET /api/external/clients` route succeeds if any clients are resolved but `POST /api/external/query` performs an additional ownership check that triggered the `None` early-return. Verified correct end-to-end behaviour via `test/test_external_api.py` (16 assertions covering auth, multi-tenant routing, SQL injection blocking, and CTE queries).

### Added
- **`test/test_external_api.py`:** End-to-end test script for the external query sidecar API. Covers API key creation and validation, tenant discovery (`GET /api/external/clients`), parameterised query execution (`POST /api/external/query`), multi-tenant `client_id` enforcement, DML/injection blocking (DROP, DELETE, INSERT, INSTALL), CTE SELECT support, and cleanup.

## [4.0.6] - 2026-04-16

### Fixed
- **Sigma conversion broken in air-gapped environments:** `convert_sigma_rule()` preferred `sigma-cli` as a subprocess, which spawned a separate Python process that never inherited the module-level `mitre_attack.set_url()` pointing at the bundled MITRE ATT&CK JSON. The subprocess attempted to download ~45 MB from GitHub, causing a 30-second timeout and `"Conversion timed out"` error on every convert. Replaced the sigma-cli subprocess path entirely with the in-process pySigma API, which respects `set_url()` and works fully offline. Also enhanced the pySigma path to natively support file-based processing pipelines and templates (previously only available via sigma-cli) using `ProcessingPipeline.from_yaml()`.
- **Create Baseline from Threat Actor(s) broken since v4.0.0:** `generate_baseline_from_actor()` in `inventory_engine.py` did not accept the `client_id` parameter passed by the `POST /api/heatmap/generate-baseline` route, causing a `TypeError` at runtime. Added `client_id` to the function signature and included it in the `INSERT INTO playbooks` statement, consistent with `create_playbook()`.

## [4.0.5] - 2026-04-16

### Fixed
- **CRITICAL: Cross-SIEM promotion now works correctly:** Previously, promoting a rule between staging and production SIEMs on **different Elastic instances** would silently fail — the rule was deleted from the source SIEM but never created on the target, causing data loss. The promotion engine now resolves per-SIEM connection details (`kibana_url`, `api_token_enc`) from `siem_inventory` for both source and target independently, building separate HTTP sessions for each.
- **Promotion verifies target before deleting source:** After creating/updating a rule in the target space, the engine now performs a GET verification to confirm the rule actually exists before deleting it from the source. If verification fails, the source rule is preserved and the error is reported.
- **Kibana default space URL handling in promotion:** Kibana's built-in "default" space uses `/api/...` URLs (no `/s/default/` prefix). All promotion helper functions now use `_space_api_prefix()` to produce the correct URL pattern for both default and named spaces.
- **NULL space normalization to "default":** Empty or NULL space values in `client_siem_map` caused production SIEMs to be invisible to sync and promotion. All layers (`link_siem_to_client`, `link_client_siem`, `get_client_siem_spaces`, `get_client_siems`, `_distribute_rules_to_tenants`) now normalize empty/NULL space to `"default"`.
- **Sync now uses SIEM inventory spaces instead of legacy `KIBANA_SPACES` env var:** `run_elastic_sync()` queries all distinct spaces from `client_siem_map` via `get_all_sync_spaces()` and passes them to `fetch_detection_rules()`. The `.env` `KIBANA_SPACES` variable is no longer required for sync.
- **Management Hub user actions (roles, delete, toggle-active, create) now work correctly:** All interactive user management elements in the Management Hub had conflicting HTMX attributes — both a mutation verb (`hx-post`/`hx-delete`) and an `hx-get` to refresh the tab on the same element. HTMX only supports one verb attribute per element, so the `hx-get` silently overrode the mutation, causing role saves to revert, user deletions to fail, and toggle-active to have no effect. Fixed by adding dedicated management-specific endpoints (`/api/management/users/*`) and removing the conflicting `hx-get` attributes.

### Changed
- **Linked SIEMs UI: production first, colored rule counts:** On the client detail page, linked SIEMs are now sorted by `environment_role` (production before staging). Enabled rule counts display in green, disabled in muted grey.


## [4.0.4] - 2026-04-16

### Fixed
- **Promotion and Rule Health pages now use `environment_role` instead of hardcoded space names:** Previously, the Promotion page hardcoded `"staging"` and `"production"` as literal Kibana space names. Clients whose SIEM inventory maps environment roles to different space names (e.g., Production role → `staging` space) would see incorrect rule counts and broken promotion workflows. All promotion API endpoints, the page handler, and the database metrics query now resolve actual Kibana spaces from `client_siem_map.environment_role`.
- **All UI surfaces now display environment role labels instead of raw Kibana space names:** Rule cards, rule detail modals, test result popups, metrics rows, the dashboard integration cards, and the Rule Health SIEM dropdown all resolve space names through `space_labels` (built from `client_siem_map`) to show friendly labels like "Elastic (Production)" instead of the literal Kibana space name. Kibana deep-links still use the actual space name in the URL.

## [4.0.3] - 2026-04-16

### Fixed
- **External query API broken with multi-tenant DBs:** `POST /api/external/query` was creating TEMP views against the shared DB which no longer contains tenant data in v4. Rewrote to resolve the API key owner's accessible tenants via `user_clients`, then open the target tenant DB directly in read-only mode. Added `client_id` field to the query request body (optional when the user has one tenant, required for multi-tenant users).

### Added
- **`GET /api/external/clients` endpoint:** New endpoint for API key holders to discover which tenants they can query. Returns client IDs, names, and slugs. Authenticated via `X-TIDE-API-KEY` header.
- **`validate_api_key_full()` database method:** Returns the API key owner's user ID and full list of accessible clients (from `user_clients`), replacing the legacy `client_id`-on-`api_keys`-table approach.

## [4.0.2] - 2026-04-15

### Added
- **`sigma_rules_index` table (Migration 30):** New shared-DB table indexes every SigmaHQ rule's `logsource` metadata (`product`, `category`, `service`), severity level, status, MITRE techniques and tactics. Three covering indexes on `product`, `service`, and `category` for fast grouping queries.
- **`index_sigma_rules()` startup sync:** On each app start, all loaded Sigma rules are bulk-indexed into `sigma_rules_index` (TRUNCATE + INSERT) so the Generate Baselines UI always reflects the current rule set.
- **Generate Baselines button:** New "Generate Baselines" button on the system detail page (left of "Snapshot All") opens an HTMX modal for the tech-stack questionnaire workflow.
- **Product-First Tech Stack Questionnaire:** "Primary Technology" abstraction via `COALESCE(product, category)` maps every Sigma rule to a single tech name. Curated UI buckets (Endpoints, Cloud & Identity, Network & Security, Other Applications) present one checkbox per technology with exact rule counts. Eliminates the 50+ redundant Windows category headers from the original `category → product` grouping.
- **Generate Preview endpoint (`POST /api/baselines/generate-preview`):** Queries `sigma_rules_index` using surgical `COALESCE(product, category)` matching with sub-group fan-out via `CASE WHEN product IS NOT NULL THEN COALESCE(service, category) ELSE service END`. Selecting "Windows" correctly previews 59 modular baselines across all event types. Button shows "Generate N Baselines (X Rules)".
- **Baseline Generation Engine (`POST /api/baselines/generate`):** For each baseline group, creates a Playbook in the tenant DB, loads full YAML from SigmaHQ files to extract `description`, `falsepositives`, techniques, and tactics. Creates one PlaybookStep per Sigma rule with populated `step_techniques` and `step_detections` (source: `sigma`). Auto-applies generated baselines to the triggering system.
- **+ Add Sigma Rule button:** New amber-styled "+ Add Sigma Rule" button on the tactic detail page. Opens a search dropdown that filters SigmaHQ rules by the techniques mapped on the current tactic. Selecting a rule adds it as a `source=sigma` detection. Endpoint: `GET /api/baselines/tactics/{id}/sigma-rules`.
- **Sigma rule search dropdown:** `sigma_rule_options.html` partial renders searchable sigma rule results with rule title, MITRE technique pills, and severity badge. De-duplicates results across multiple mapped techniques.
- **Three color-coded Add Detection buttons:** Replaced the single "Add Detection Rule" form with three separate buttons — green "+ Add SIEM Rule" (searchable dropdown via HTMX), blue "+ Add Manual Rule" (text inputs), amber "+ Add Sigma Rule" (searchable dropdown). Each button opens its own color-matched panel.
- **SIEM rule search endpoint:** `GET /api/baselines/tactics/{id}/siem-rules` returns a searchable list of SIEM rules, grouping "Mapped to techniques on this step" first. `siem_rule_options.html` partial shows MITRE pills, severity badge, and enabled status.
- **Sigma rule selector in Convert & Deploy:** When multiple sigma detections exist on a tactic, a dropdown lets the user choose which sigma rule to load into the CodeMirror editor. Backend resolves all sigma detection rule_refs to UUIDs.
- **Clickable SIEM rule names:** SIEM detection rule names in the tactic detection section are now clickable, opening the rule detail/logic modal. Uses `rule_name_lookup` to resolve rule names to rule IDs.

### Changed
- **Clickable MITRE technique pills:** Pills on baseline coverage and baseline tactics pages are now clickable — opening the technique detail slide panel. Added `event.stopPropagation()` to prevent click-through on parent cards.
- **Coverage-colored MITRE pills on baselines:** Technique pills on baseline coverage (system page) and baseline tactics (baseline detail page) now reflect actual detection coverage — green with rule count when covered, red when a gap. Previously all pills were neutral blue regardless of coverage status.
- **SIEM rule dropdown enrichment:** The "All SIEM Rules" section in the search dropdown now shows MITRE technique pills, severity badge, and enabled/disabled status (was: name only). Consistent with the sigma rule dropdown format.
- **Slide panel on baseline detail page:** Added `#slide-panel-container` so technique pills on the baseline detail page open the technique detail modal (was: silently failing).
- **Baseline & coverage card title order:** Technique pills now appear *after* the tactic name (was: technique ID first, then name). Uses the standard `mitre_pill` component for consistent pill formatting across baseline coverage and baseline tactics views.
- **Detection rule color-coding by source:** Tactic detection section now renders SIEM rules with green border, Manual additions with blue (app accent) border and "MANUAL" badge, and Sigma rules with amber border. Previously SIEM and Manual rules shared the same green style.
- **Markdown description rendering:** Tactic detail page descriptions now render Markdown (bold, italic, code, line breaks) via the `| md` Jinja filter instead of raw plain text.

### Fixed
- **Technique coverage count mismatch:** `get_rules_for_technique()` now uses case-insensitive `UPPER()` matching on `mitre_ids` (via unnest + compare), consistent with the aggregation query in `get_ttp_rule_counts()`. Previously, `list_contains()` performed case-sensitive matching, causing techniques like T1203 to show "1 rule" in the coverage count but 0 rules in the detail view.

## [4.0.1] - 2026-04-15

### Fixed
- **500 on tactic edit:** `update_playbook_step()` did not accept the `client_id` keyword argument passed by the API route, causing a `TypeError` on every PUT to `/api/baselines/tactics/{id}`.
- **500 on CISA KEV upload:** `ingest_cisa_feed()` was called with an unsupported `client_id` kwarg (global data, not tenant-scoped).
- **500 on MITRE CVE map upload:** `save_mitre_cve_map()` was called with an unsupported `client_id` kwarg (global data, not tenant-scoped).
- **Blind-spot applied detections not tenant-scoped:** `_load_applied_detections()` calls in `api_add_blind_spot` and `api_remove_blind_spot` now pass `client_id` for correct multi-tenant filtering.

## [4.0.0] - 2026-04-14

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
