# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [5.0.3] - Unreleased

### Added

- **CTI page permissions in Role Templates.** Role Templates now include separate read/write controls for CTI Indicators, CTI Actors, and CTI Reports so tenant admins can grant CTI access at page level.

- **Per-linked-SIEM default index setting.** Each linked SIEM row on the client detail page now supports a default index pattern, and that value pre-populates new rule creation flows.

- **Rule score history backfill utility.** A standalone script is now available under `app/scripts` to import historical rule score snapshots from rule log files into the in-app score history timeline.

### Changed

- **Score history layout is more compact and easier to scan.** The rule history score view now shows Overall on the left with Meta and Quality as two compact lines on the right.

- **Core page shells are aligned to the Systems layout.** Rule Health, Promotion, Sigma, Threat Landscape, and Heatmap now use a consistent header structure with actions aligned in the top-right action cluster.

- **Rule Health sorting is expanded for analyst workflow.** Sort options now include criticality, score, and validation date ordering.

### Fixed

- **Rule history no longer repeats the reason text.** Edit history now shows what changed separately from the operator-entered reason.

- **Sigma rule author prefill now includes the current operator.** Author values are normalized as comma-separated entries so converted Sigma rules carry both source and operator attribution cleanly.

- **Edit validation now flags missing change reason near Save.** When reason is required but missing, the form now surfaces a clear message next to the Save button and opens the section that needs attention.

## [5.0.2] - 2026-07-01

### Added

- **Criticality-aware rule validation.** Tenants can now switch between the legacy master cadence and a criticality-aware mode with per-severity amber and expired thresholds. The Rule Health validation badges now respect the active tenant mode when calculating status.

- **Rule edit reasons are required.** Editing a rule now requires a reason before the change is pushed to Elastic. Rule validation auto-fills the audit reason as the validating user's name plus "validated rule".

- **Rule history now shows table and score views.** The rule history modal now defaults to a table layout, keeps the activity-feed view available, and adds a dated score history table populated from sync snapshots.

- **Sigma conversion can open the shared rule modal.** Converted Sigma output can now launch the shared rule form prefilled with the converted rule fields so operators can review and edit before deploying.

- **Rule form includes the Elastic fields operators asked for.** The shared rule modal now exposes description, index patterns, timestamp override, investigation fields, risk score, and a clearer MITRE ATT&CK selector, with the UI label changed from Notes to Investigation Guide.

- **Rule Creation and Editing.** Operators can now create new detection rules directly from the Rule Health page without leaving TIDE. A **Create Rule** button opens a modal form where operators can define the query, language (KQL, EQL, ES|QL, Lucene), severity, author, MITRE ATT&CK IDs, tags, and deployment space. Rules are created in Kibana and synced back on the next auto-discovery.

- **Enable/Disable controls on rule cards.** Each rule card now displays an **Enable** or **Disable** button (depending on current status) for immediate status toggling in Kibana without leaving the Rule Health grid. The rule card updates instantly to reflect the new state.

- **Full audit trail for rule lifecycle events.** Every rule creation, edit, enable/disable, and validation is recorded with a timestamp, actor name, and contextual detail (reason, before/after values). The audit log persists in the per-tenant DuckDB and is immutable — a complete forensic record of who changed what and when.

- **Timeline view for rule audit history.** The rule detail modal now shows a **Lifecycle** section with a chronological timeline of all events tied to that rule. Events are color-coded by action type (created, enabled, disabled, edited, validated, promoted) for quick visual scanning.

- **Bootstrap history from Elastic metadata on first sync.** When a rule is synced from Kibana for the first time, TIDE extracts the `created_by` and `created_at` metadata from the Elastic response and records an initial "created" event. All future edits, promotions, and validations append to this immutable record.

### Changed

- **Tenant validation settings now support mode switching.** The client detail page now lets operators choose between master cadence and criticality-based validation thresholds, with per-severity week overrides saved on the tenant record.

- **Detection rule CRUD now tenant-scoped via composite key.** All rule operations (read, create, update, delete, enable/disable) enforce the (siem_id, space) composite key pair to guarantee tenant isolation. A rule synced from SIEM A in space "production" is distinct from SIEM B's rule in the same space-name.

- **Rule form UX now mirrors analyst workflow.** The create/edit modal now starts with all sections collapsed, moves Index Patterns into Define Rule above Query, renames Investigation Fields to Custom Highlighted Fields, and replaces the large MITRE multi-select with tactic-first technique rows that support adding multiple selections.

- **Rule form defaults and MITRE spacing refined.** The Create Rule section now opens by default while the other sections remain collapsed, and the Add technique control spacing is tuned to match the expected ATT&CK entry flow.

- **Sigma convert workspace now focuses on browser + YAML editing.** The Sigma page now presents Rule Browser and rule.yml side by side and removes the legacy visible query output panel from the operator flow.

- **Sigma workbench now uses fixed-open equal panels.** Rule Browser is permanently expanded, sized to match the rule.yml panel, and conversion responses now use a hidden swap target that reliably opens the shared Create Rule modal.

- **Sigma panel parity and browser fill corrected.** The Rule Browser and rule.yml panes now render at equal width, and the rules list now fills the left pane height instead of leaving a large empty block under the list.


## [5.0.1] - 2026-06-08

### Added
- **Docker Overview.** Add docker overview form `README.md` into dockerhub on build. 

## [5.0.0] - 2026-06-04

This is a major release introducing full Cyber Threat Intelligence (CTI) ingest and management. TIDE can now connect to multiple CTI sources — **OpenCTI**, **Mandiant Advantage**, **CrowdStrike Falcon Intelligence**, **MITRE ATT&CK** and **GreyNoise** — through a unified Connectors surface on the Management hub. All feeds use delta-aware polling so repeat syncs only fetch what has changed since the last run. The Threat Landscape, Heatmap, and rule coverage pages now draw from ingested STIX 2.1 data directly, with no dependency on the legacy OpenCTI GraphQL connector, which has been retired in this release.

### Added

- **CTI Connectors hub.** A new **Connectors** section in Management lets operators add, edit, test and delete CTI sources. Each connector card shows its current sync status, last-run result, and which tenants it is linked to. Supported vendors: OpenCTI (TAXII 2.1), Mandiant Advantage, CrowdStrike Falcon Intelligence, MITRE ATT&CK and GreyNoise.

- **Import Connectors.** The Connectors hub has an **Import** button that accepts a single connector or a batch in JSON format, so operators can pre-populate connectors from a saved configuration rather than entering each one manually. Partially valid imports are reported cleanly — valid entries are created and skipped entries are listed.

- **Auto-sync scheduler.** Each connector has an **Auto-sync interval** dropdown (Off / 15 min / 1 hour / 6 hours / 24 hours). Enabled connectors sync on schedule without operator intervention; the card badge updates live after each run. Set to **Off** to keep a connector strictly manual.

- **CTI sync runs in the background.** Clicking **Sync** on any CTI page or connector card returns immediately. A live status badge polls for the result and settles into a green / amber / red summary when the job completes. Long-running backfills no longer time out or block the operator's browser session.

- **Delta-aware polling with persistent cursors.** TIDE records a per-collection watermark after each sync. The next run — whether manual or scheduled — resumes from that point, so only new and updated objects are fetched. MITRE ATT&CK is always pulled in full since it is a structural framework rather than a live feed.

- **"Start From" date on TAXII connectors.** Each connector has an optional **Start From** date (ISO 8601). For a brand-new connector with no history, this seeds the initial backfill window instead of starting from "now". Once a real cursor is recorded the field is ignored.

- **STIX 2.1 ingest with version control.** Re-ingesting an unchanged object is a no-op and does not count against sync totals. Objects marked `revoked` in the upstream feed are automatically retired from the active CTI surface. TLP markings are normalised to `clear / green / amber / red` on ingest.

- **Per-tenant CTI data store.** Each tenant's indicators, actors, reports and relationships are stored in a dedicated per-tenant CTI database, keeping holdings fully isolated between tenants. The database is created automatically on first use.

- **In-browser CTI report viewer.** The CTI Reports page now renders attached PDFs inline using the browser's built-in viewer. Attached images display directly; other file types offer an **Open in new tab** link. Operators can read a full Mandiant or OpenCTI threat report without leaving TIDE. CrowdStrike report PDFs are cached locally after the first fetch so repeated views do not call out to Falcon.

- **CrowdStrike Falcon Intelligence connector.** CrowdStrike indicator, actor and report data is pulled via the Falcon Intel REST API using the operator's OAuth2 client credentials. Indicators, actors and their relationships to reports are all ingested in a single efficient call rather than one request per report.

- **Per-tenant Linked CTI Connectors on the client detail page.** A **Linked CTI Connectors** section on the client detail page lets operators link and unlink CTI sources for that tenant, using the same pattern as the existing Linked SIEMs section. The client metric strip's Threat Intel tile now counts linked CTI connectors.

- **CTI Egress to Elasticsearch.** Each tenant can have one or more **CTI Egress Targets** pointing at an Elasticsearch instance. On each run, indicators are written to a current-state index (`logs-ti_tide_latest`) and a daily history index. A TLP ceiling on each target prevents indicators above the configured marking from leaving TIDE. Egress targets are managed from the client detail page, with a per-target API key override if the destination uses different credentials to the main SIEM.

- **Threat Landscape projection from STIX.** Actor-to-technique relationships from ingested CTI feeds are projected directly onto the Threat Landscape and Heatmap pages at ingest time. The Threat Landscape no longer requires an active OpenCTI connection and a missing or expired token can no longer cause a sync failure.

- **TAXII discovery auto-resolve.** Operators can paste either a discovery URL or a direct API root URL into the connector form — TIDE follows the standard TAXII discovery hop automatically. OpenCTI "Data sharing" collection URLs are also handled: TIDE strips the collection suffix and auto-pins the connector to the embedded collection ID.

- **Connector Test button probes the upstream feed.** The **Test** button on each connector card performs a real HTTP probe — verifying credentials, reachability and collection access — and reports the outcome. The discovered collection count is shown on success; the upstream error is shown on failure.

- **Per-sync object type breakdown.** Each sync result includes a count by STIX object type (`indicators`, `reports`, `attack-patterns`, `relationships`, etc.) so operators can see the shape of what was fetched and diagnose gaps between the upstream feed count and what landed in TIDE.

- **Per-tenant rule validation thresholds.** The amber and expired validation thresholds that drive the rule validation badge can now be overridden per tenant from the client detail page. A blank value inherits the global defaults; a positive integer pins that tenant to its own review cadence.

- **Configurable global rule validation windows.** Two new environment variables — `RULE_VALIDATION_AMBER_WEEKS` (default `8`) and `RULE_VALIDATION_EXPIRED_WEEKS` (default `26`) — replace the previous hard-coded 12-week cliff that jumped straight from valid to expired. Rules now progress through valid → amber → expired, and rules that have never been reviewed show a neutral "never" state.

- **"Open in Kibana" links on rule cards now resolve correctly.** The button on each Rule Health card and on the rule detail modal now opens the correct Kibana instance for the rule's owning SIEM. It was previously anchored to a global setting that was removed in an earlier release.

### Changed

- **Connectors hub replaces the legacy Threat Intel tab.** All CTI source management is now under Management → Connectors. The legacy Threat Intel tab has been retired; existing OpenCTI instances are migrated to the new Connectors store automatically on upgrade.

- **CTI list pages redesigned.** The Indicators, Actors and Reports pages use a slim card layout consistent with the rest of TIDE. Indicators lead with a summary strip showing per-type totals (IPv4, URL, domain, file hash, etc.). Actors and Reports lead with a six-card metric strip and expose column-level dropdown filters in addition to free-text search. The source column on all three pages shows the connector's friendly label instead of an internal ID.

- **CTI detail pages use the standard TIDE card theme.** Actor, indicator and report detail pages use the same layout as the rest of TIDE and no longer expose raw internal IDs in the page body.

- **Threat Landscape and Heatmap source labels.** The source pill on actor rows now shows the connector's friendly label (e.g. "Mandiant Advantage") so operators can tell feeds apart at a glance.

- **CTI counts use local data.** The CTI counts displayed on list pages are now read from the per-tenant CTI store rather than issuing a live query to the upstream source on every page load.

- **Sync logs show per-page progress.** Each page fetched from a TAXII collection now emits a progress line in the container logs (`page=N size=… running_total=… cursor=…`) so operators can confirm a large backfill is still running without waiting for the final summary.

- **Check connection button consolidated to the Connectors hub.** Connectivity testing for CTI sources is now available only in Management → Connectors where the **Test** button probes the live TAXII root. The button has been removed from the individual CTI list pages.

### Removed

- **Legacy OpenCTI GraphQL connector.** The OpenCTI GraphQL connector and all supporting code have been removed. All CTI sources — including OpenCTI — are now managed through the TAXII 2.1 connector framework. Any data ingested by the legacy connector is cleaned up automatically on first startup after upgrade.

## [4.1.19] - 2026-05-20

### Fixed

- **Threat Landscape no longer shows OpenCTI actors to tenants that aren't linked to OpenCTI.** Previously, OpenCTI-sourced threat actors written during an earlier sync could appear in every tenant's Threat Landscape and Heatmap pages even after the OpenCTI link was removed. The OpenCTI writer now refuses to fall back to the shared database when no tenant context is active, the link check honours an instance's active/inactive state, and merging an OpenCTI actor whose name collides with a MITRE actor (e.g. APT28, Lazarus) preserves the MITRE marker so the row keeps showing up in the MITRE baseline.
- **Threat Landscape "Source" filter now shows OpenCTI for linked tenants.** The dropdown previously dropped or mis-rendered OpenCTI and the MITRE matrix sources (Enterprise / Mobile / ICS / PRE) because each page normalised the source label slightly differently. Both the Threat Landscape and Heatmap dropdowns now use a single shared display layer, so the option labels are consistent and OpenCTI appears for any tenant with an active OpenCTI link.
- **`diag_sync` adds an OpenCTI section.** A new section 11 reports, per tenant, whether the OpenCTI link is healthy or stale and whether OCTI rows are leaking into the shared database. When a leak is detected the report points operators at a new repair command (`docker exec tide-app python -m app.scripts.repair_octi_source_markers`) that strips OCTI markers from the shared `threat_actors` table without touching any per-tenant data.
- **OpenCTI threat actors now sync into tenant databases.** Two compounding bugs were silently dropping every fetched OpenCTI actor on every sync. First, tenant databases created by earlier 4.1.x builds had a `threat_actors` table without a primary key on the actor name, which made the OpenCTI upsert fail with a "not referenced by a UNIQUE/PRIMARY KEY CONSTRAINT" binder error. Second, the post-sync "shared data → tenant" mirror was issuing `CREATE OR REPLACE TABLE tenant.threat_actors AS SELECT * FROM shared.threat_actors` on every sync, which dropped the primary key (CTAS does not carry constraints) and replaced any per-tenant OpenCTI rows with the shared MITRE-only contents. The mirror now leaves `threat_actors` alone (it was already documented as excluded in the function's own docstring), and tenant databases that were already missing the primary key are repaired automatically on first access after upgrade. The repair runs once per tenant database per process, preserves all existing rows, and logs a single warning per database when it fires.

## [4.1.18] - 2026-05-18

### Fixed

- **Field mapping now works for rules built entirely from Kibana filter pills.** Rules created in the Kibana UI without a KQL/Lucene query previously scored 0% mapping coverage because only the query text was being inspected. Field names are now also extracted from the rule's filters and validated against the index mapping, so these rules are scored the same as standard query rules. Mixed rules (query + filters) and rules with empty filters are handled cleanly; preview and promotion are unaffected.

## [4.1.16] - 2026-05-07

### Fixed

- **Unlinking a SIEM from a tenant now clears its rules immediately.** Previously, rules from a removed SIEM continued to show on the tenant's Rule Health page until the next sync. The unlink action now sweeps those rules from the tenant's database right away, while leaving rules from any other SIEM (or other role on the same SIEM) untouched.

## [4.1.15] - 2026-05-07

### Fixed

- **Elastic sync no longer overwhelms the connection pool.** A defensive change in 4.1.14 was causing sync to open too many short-lived connections in parallel, producing connection-pool warnings and intermittent SSL failures against Kibana proxies. Connection handling was retuned so syncs run smoothly even on busy stacks.
- **Connection diagnostic and section numbering corrected in `diag_sync`.** The diagnostic's Kibana auth check now uses the same URL shape as the live sync (so it stops false-reporting failures on reverse-proxied stacks), and a duplicate section number was fixed for easier triage.

## [4.1.14] - 2026-05-07

### Fixed

- **Sync now reliably returns rules from every SIEM/space pair.** Some reverse-proxied Kibana deployments were returning generic "network error" or "0/0 rules" banners during sync. URL construction was aligned across all sync, promotion, and data-view paths to use the standard `/s/<space>/api/...` form that proxies require, and the failure message now includes the underlying cause so operators can act on it.
- **Stale "ghost" rules left behind after a SIEM/space mapping change are now cleaned up automatically.** When a SIEM or space was unmapped from a tenant, rules previously fetched under the old pairing could linger in the tenant's database indefinitely. Sync now sweeps these orphan pairings on each run, and the Rule Health metrics card hides them in the meantime.
- **Baseline mappings are protected from rule churn.** Baseline and applied-detection mappings have no cascade to the underlying rule rows, so temporarily moving a rule between staging and production (or upstream Kibana edits) cannot silently destroy a tenant's coverage work.
- **Detached rule references are now labelled clearly.** When a rule is missing from the production set but its baseline reference still exists, the reference is shown as "Detached" with a short identifier instead of a bare 36-character UUID.
- **Test Rule button no longer fails after a hot-reload.** Clicking Test Rule shortly after a code reload could return HTTP 500 due to an import path issue. The button now works reliably under both dev and production deployments.
- **Scheduled rule-log export no longer crashes after the per-tenant database move.** The background export job was failing every minute on stacks upgraded to 4.1.13. It now correctly reads each tenant's database and writes a deduplicated log per SIEM/space.

### Added

- **`diag_sync` dry-run sync URL preview.** A new diagnostic section prints the exact URL the app would call to fetch rules for every mapped client/SIEM/space — without making the request — so operators can paste a clean trace to support.
- **Two Query Manager presets** showing rule counts per SIEM/space/role and the top 10 production-vs-staging rules.

## [4.1.13] - 2026-05-06

### Changed

- **Detection rules are now stored per tenant.** Each tenant's database now owns its own copy of `detection_rules`, removing a class of cross-tenant collision bugs and unblocking deployments where multiple tenants legitimately map to the same SIEM/space pair. Sync runs only when an operator clicks **Sync** on the Rules or Promotion page, or after a successful promote/deploy — there is no longer a global background sync ticking across all tenants.

## [4.1.12] - 2026-05-06

### Fixed

- **Sigma rule deployment now works for every mapped SIEM/space, not just the first one.** Deploying a Sigma rule could return "SIEM/space mismatch" whenever a SIEM was linked to a tenant under more than one space (e.g. both staging and production). All combinations now deploy correctly.
- **Sigma Convert page target selector now defaults to a sensible value.** The deploy-target dropdown could render blank, causing form submissions to fail. It now picks a default in priority order (production → staging → first available) and shows a clear placeholder when nothing is configured.
- **Threat Landscape coverage no longer leaks rules from other SIEMs.** When two SIEMs shared a Kibana space name, the Threats page could inflate a tenant's coverage with rules it did not own. Coverage is now strictly scoped to the tenant's mapped SIEM/space pairs.
- **A single SIEM may now legitimately expose the same rule in more than one space.** Operators routing one SIEM as both staging and production through different spaces no longer hit duplicate-key errors during sync, and the Rule Health and Promotion pages render correctly.
- **Promotion page no longer crashes after upgrade.** A leftover reference to old space-only variables produced a 500 on `/promotion`; the page renders normally again.
- **Manual Sync now syncs only the active tenant.** Pressing Sync from a tenant page used to fetch rules for every space mapped to that SIEM across *all* tenants. It now fetches only the active tenant's mappings; an explicit `?scope=all` option remains for cross-tenant reconciles.
- **Rule visibility, promotion, and dashboard metrics no longer leak across SIEMs that share a Kibana space name.** Tenants mapped to two different SIEMs that both expose a space called `default` (or any other shared name) now see only rules from the SIEMs they actually own.

## [4.1.11] - 2026-05-06

### Fixed

- **The "Add SIEM to client" space picker now shows only spaces from the selected SIEM.** When a tenant was linked to multiple SIEMs, the picker mixed spaces from all of them, leading to invalid links and partial syncs. Each SIEM's picker is now scoped to that SIEM and shows per-space rule counts so operators can pick the right one with confidence.
- **Rule grid badges now show the correct SIEM/role even when two SIEMs share a space name.** Rules from one SIEM could render with another SIEM's label in the rule list and Kibana deep-link. Labels are now resolved by the rule's owning SIEM and never collide.

## [4.1.10] - 2026-05-05

### Fixed

- **SIEM / space / role domain rules locked.** Documented the data model in `AGENTS.md` after a series of regressions and added a required pre-flight check for future changes to this area.
- **Spurious "tenant isolation" warnings on Rule and Promotion pages removed.** Several pages were logging false-positive isolation errors even when responses were correct. Lookups were moved to the right database scope and tenant context is now activated earlier in the request, eliminating the noise (and the risk of a real failure under strict mode).
- **KQL-aliased rules are scored correctly.** Rules using `language: "kql"` (an alias for `kuery`) were skipped by the field-mapping check and flagged with a generic red "Field Mapping Issues" warning. They are now scored the same as Kuery rules.
- **Outbound SIEM requests fail closed when the target is ambiguous.** Removed legacy "first SIEM matching this space" fallbacks in Test Rule, Sigma deploy, and Promotion. When a SIEM is missing or doesn't match the chosen space, the action is blocked with a clear message instead of silently targeting the wrong SIEM.
- **Linked-SIEM cards no longer show another SIEM's rule count when two SIEMs share a space name.** Each card now shows its own count.

## [4.1.9] - 2026-05-05

### Fixed

- **`diag_sync` now detects the most common post-upgrade failure.** The diagnostic compares actual rule-table columns against the canonical schema and, when it finds a mismatch, names the missing column and points the operator at `docker compose up -d --build`.
- **Kibana spaces literally named `production` or `staging` can be linked again.** Earlier releases incorrectly rejected those names assuming they were operator confusion with the environment-role dropdown. They are valid Kibana space names and are now accepted everywhere (picker, save handler, and persistent caches). If a previous release rewrote any of these mappings to `default`, re-link the affected tenants from Settings → Clients.

## [4.1.8] - 2026-05-05

### Fixed

- **Sync no longer fails with a "23 columns but 24 values" error.** Tenants with older database files were silently rejecting every rule insert during sync, leaving the Rule grid empty. Tenant schemas are now repaired automatically at startup and on every distribution — the fix is a single `docker compose up -d --build` followed by a Sync from the UI. Existing baselines, manual rules, and mappings are preserved.

### Added

- **Query Manager templates and a SIEM URL backfill.** Operators can now save named queries in Management → Query, and legacy SIEM records with a missing `base_url` are filled in from `kibana_url` so older diagnostics report cleanly.

### Fixed

- **Query Manager built-in SIEM presets updated to the current schema.** A few presets referenced columns that no longer exist; they have been corrected.

## [4.1.7] - 2026-05-04

### Added

- **More reliable Kibana space discovery.** A new shared resolver consults the tenant mapping, the persistent cache, and (when allowed) a live Kibana lookup, then writes any newly-discovered spaces back so the next reader sees them. The Add-SIEM and link-to-tenant pickers now populate consistently even on standalone deployments.
- **On-disk rotating log file.** App logs are now written to `/app/data/log/tide.log` (10 MB × 5 backups by default) in addition to stdout, so operators can read history from inside the container without `docker logs` access. Configurable via `TIDE_LOG_FILE`, `TIDE_LOG_FILE_MAX_BYTES`, and `TIDE_LOG_FILE_BACKUPS`.
- **Threat-sync toasts now reflect reality.** Threat sync reports success, partial success (with a preview of the first error), or failure — replacing the previous "always green" toast that hid partial failures.
- **Sync history audit trail.** Every Elastic and threat sync is recorded with status, duration, totals, and error details, surfaced through two new Query Manager presets and queryable for triage.
- **Read-only Query tab in the Management Hub.** Super-admins can inspect the shared catalog and any tenant database directly from the UI with strict guardrails: only `SELECT` / `SHOW` / `DESCRIBE` etc. are allowed, a row cap is enforced, and queries run against a snapshot copy so the live database is never contended.
- **`migration-check` skill** documenting the prerequisite checklist for safe schema changes.

### Changed

- **Threat sync isolates each MITRE domain.** A bad bundle in one MITRE matrix no longer aborts the others.
- **Space resolution split into two clear intents** ("what's discoverable on this SIEM" vs. "what's operator-declared for this tenant") so pickers and sync use the right source.

### Fixed

- **"Space does not exist" rejections when linking SIEMs to tenants.** A valid Kibana space could be incorrectly rejected during onboarding; validation now accepts any space the SIEM actually exposes.
- **Threat Landscape no longer 500s while a sync is in progress.** The page degrades to an inline banner instead of an error screen if metrics aren't ready yet.
- **`diag_sync` log section finds the rotating log file** and falls back gracefully when no log file exists yet.

## [4.1.6] - 2026-05-02

### Security

- **Management → SIEMs is now restricted to platform admins.** Previously any tenant admin could view and edit every other tenant's stored API token. Tenant admins keep their per-tenant linking ability from Settings → Clients but no longer see the global SIEM inventory or its tokens.

### Added

- **Persistent Kibana spaces cache.** Spaces discovered during Test Connection are remembered across restarts, so the link-to-tenant picker is never silently empty after a reboot.
- **Platform-admin toggle in Management → Users.** Granting or revoking platform-admin is now a one-click action (with confirm), audit-logged, and never available for self-revoke.

### Fixed

- **Editing a SIEM's API token actually saves it.** The Edit-SIEM form was silently discarding the new token field; the only previous remediation was to delete and recreate the SIEM. Token edits now persist correctly.
- **API tokens pasted with hidden whitespace or an `ApiKey ` prefix are normalised.** Common copy-paste mistakes (leading prefix, trailing newline, internal whitespace) that silently broke every sync are now stripped or rejected with a helpful toast.

### Added

- **Three-tier Test Connection for SIEMs.** Test Connection now runs three independent checks per click — status, spaces, and rule-find — and renders a per-check breakdown panel with the underlying HTTP error if any tier fails, so a green pill genuinely means "sync will work" instead of "the URL is reachable."

## [4.1.5] - 2026-05-02

### Added

- **Per-tenant OpenCTI isolation.** Threat-actor data ingested from a tenant's OpenCTI instance is now stored in that tenant's database and is no longer mirrored across other tenants. Existing cross-tenant data left over from previous releases is cleared automatically on first boot; re-run OpenCTI sync per tenant from Management to repopulate.

### Fixed

- **Threat Landscape cards and the Source filter now show real data again.** A stale internal whitelist was hiding every MITRE row for tenants without an OpenCTI link. Cards now show the correct numbers and the Source filter lists all four MITRE matrices.
- **New Kibana spaces appear in pickers without waiting for a sync.** The Add-SIEM autocomplete and SIEM Logging picker now union live-Kibana spaces with the database state, so newly-created spaces are available immediately.
- **MITRE Pre/ICS/Mobile actors are visible again.** A source-tag mismatch was filtering out three of the four MITRE matrices for tenants without OpenCTI; all four now display.
- **Role names rejected as Kibana space inputs.** Typing `production` or `staging` into the *space* field — when intended as a role — is now blocked at the form with an explanatory toast.
- **Autocomplete no longer suggests bad space values.** Previously a polluted entry could be re-suggested to the next operator, perpetuating the same mistake.
- **SIEM Logging picker no longer 500s.** A broken reference in the per-space tag rendering crashed the SIEMs tab; the picker renders correctly again.

## [4.1.4] - 2026-05-02

### Removed

- **The `production_space` and `staging_space` columns on the SIEM record.** These predated multi-tenant routing and disagreed with the per-tenant model. Existing values are migrated into the tenant mapping table on upgrade, after which `client_siem_map` is the single source of truth for which space TIDE pulls rules from for a given tenant.
- **Sync fallback to the SIEM's own production/staging columns.** SIEMs with no tenant mapping are skipped with a clear log line directing the operator to link them in Management.

### Added

- **Live Kibana space lookup with form-side validation.** Linking a SIEM to a tenant now validates the chosen space against the SIEM's real spaces and rejects unknown values with a helpful toast — catching the single most common 4.1.x sync failure (typing the role name into the space field).
- **Startup space-validity walk.** On boot, every tenant/SIEM/space mapping is checked against the real Kibana spaces and any bad mappings are logged with the list of valid options.
- **Expanded `diag_sync`.** New sections cover schema/migration state, the recent ERROR/WARN log tail, and Elasticsearch reachability, so a single command tells the operator what's wrong end-to-end.

### Fixed

- **Rules added to a baseline through the Coverage Quest now update the baseline page immediately.** The Quest was correctly writing the attachment, but the baseline page's coverage colouring ignored it. Coverage now reflects Quest-added detections without a second sync.
- **Coverage Quest now also applies the chosen rule to the quest's target system.** Previously the technique pill went green on the baseline while the per-system RAG dot stayed red. The Quest now performs both the attach and the apply in one click (except for Sigma rules, which still need convert+deploy first).

## [4.1.3] - 2026-04-30

### Removed

- **The "Action required after upgrade" banner.** It pointed at a non-existent settings page; the Rules page and Dashboard already direct operators to Sync.

### Added

- **`diag_sync` — end-to-end sync diagnostic.** Run `docker exec tide-app python -m app.scripts.diag_sync` to walk the full env → database → SIEM → Kibana chain and get a verdict that names the failing link and the next action. Token values are redacted.
- **Startup auth-source banner.** On boot the app logs, in plain English, which credentials it will use on the next sync (per-SIEM rows, env-var fallback, rule counts), so operators no longer have to guess where sync is picking up its config.

### Fixed

- **"Sync drift" no longer false-fires on healthy syncs.** A short-fetch caused by Kibana's approximate `total` was being treated as a failure and the subtractive-delete pass was suppressed (so deleted rules stayed in TIDE forever). The drift check now fires only when a page-fetch genuinely failed, and when it does the message includes the underlying cause and a pointer to `diag_sync`.
- **Linking or unlinking a SIEM now updates the tenant immediately.** The operator-expected "remove the SIEM, re-add it, sync should fix it" workflow now works without waiting for the next scheduled sync.
- **"Resync required" banner no longer false-fires for unmapped tenants.** Tenants with no SIEM mapping no longer see the amber upgrade banner; the per-tenant verdict is cached independently so one tenant's state cannot poison another's.

## [4.1.2] - 2026-04-30

### Changed

- **Total Rules card splits SIEM/space pairs onto separate lines** for easier scanning.
- **Test Rule now honours a rule's custom timestamp field.** Rules using a `timestamp_override` (e.g. the `timestamp` field on the bundled flights dataset) returned 0 hits in the preview popup because the preview ignored the override. Hit counts now match what the production rule actually finds.
- **ES|QL rules no longer get a 0% mapping score for fields they define themselves.** The ES|QL parser now tracks query-defined columns (`EVAL`, `STATS … BY`, `RENAME`, `KEEP`/`DROP`, `ENRICH … WITH`, `FROM … METADATA`) so they're not flagged as unmapped on the next pipe stage. The `_id` / `_version` / `_index` system fields are likewise treated as Elasticsearch metadata, not missing fields.
- **Sync mirrors Kibana reliably and never deletes during a Kibana outage.** Pagination now uses Kibana's documented page size, retries each page on transient errors, and compares the fetched count against Kibana's `total`. Clean fetches reconcile the local database against Kibana (so deleted rules are removed); incomplete fetches log a warning and preserve existing rows.

### Fixed

- **"Resync required" banner is now per-tenant.** Unmapped tenants no longer see the upgrade banner, and one tenant's verdict can no longer override another's for a minute.
- **Faster repeat syncs.** Mapping lookups are now cached for five minutes and the request asks only for the fields the rule actually uses, replacing the previous full-index mapping fetch.

## [4.1.1] - 2026-04-30

### Fixed

- **Per-SIEM rule-log export now actually scopes to that SIEM and its chosen space.** Previously every SIEM's daily log dumped every rule in the database. Logs now contain only the rules from the SIEM (and chosen space) the export was configured for.

### Changed

- **Rule Logging UI cleaned up and made consistent.**
  - Space picker is a single-line checkbox dropdown showing one of "All spaces", "<space>", or "N spaces selected" — replacing the multi-row listbox.
  - Per-SIEM output now lives in `…/<siem>/<date>-<space>-rules.log` (one folder per SIEM, files side-by-side per day and space).
  - The picker offers spaces discovered globally (so every SIEM sees the same option list); leaving the selection empty exports every discovered space, one file each.
  - The output-path row is now a read-only explanatory note instead of an editable field. The destination is controlled by the existing `./data` bind mount; set `RULE_LOG_PATH` in `.env` for a different host directory.

### Fixed

- **Rule logging now actually runs after enabling "Logging On" on a SIEM card.** A scheduling regression meant no cron job was being installed, so log files never appeared on disk. The scheduler now installs one job per logging-enabled SIEM at its configured time. The manual "Export now" button also uses the same per-SIEM logic.

## [4.1.0] - 2026-04-29

### Fixed

- **Baseline page coverage now agrees with the system page.** A baseline could render every technique red on the baseline-detail page while the same baseline was green on the system page. System-level rule applications are now read on both paths, so colours match.

### Changed

- **Coverage Quest redesigned around the baseline.** The quest is now launched from the baseline detail page and walks the baseline's techniques in MITRE-tactic columns with an inline "Add a detection" panel (SIEM / Manual / Sigma). Coverage state is data-driven, so changes made on the baseline page are reflected in the walker (and vice-versa). Ending or completing a quest returns to the baseline; updates made during the quest persist.

### Performance

- **Heatmap matrix and dashboard rollups are cached per tenant.** Repeat hits of the matrix and dashboard are materially faster (~50% and ~25% latency reductions on representative tenants). Off-screen heatmap columns and actor checkboxes are also skipped from layout/paint for large matrices.

### Added

- **Coverage Quest workflow.** A persistent journey from threat actor → baseline → system → covered techniques. State lives server-side keyed by user, so a refresh or login/logout no longer loses your place. A small tray in the page header surfaces the active quest from any page.
- **Consistent breadcrumbs and page chrome.** A new design-system bucket renders breadcrumbs from a route-metadata registry, and a shared "loading" component fixes a long-standing bug where the spinner sat to the left of the centred text.
- **Content-hashed asset bundles.** CSS and JS bundles are now content-hashed and served with a 1-year immutable cache, replacing the previous random cache-buster that re-downloaded the bundle on every page. Vendor JS (HTMX) keeps its existing cache policy.
- **Bounded DuckDB connection pool.** Per-tenant connections are pooled with sensible defaults (8 tenants × 2 connections) instead of opening and closing a fresh connection per request, with `/health` reporting hit / miss / eviction counts. Different tenants now run in parallel rather than serialising on a single mutex.
- **Tenant-isolation contract.** A runtime guard and a ratchet test catch routes that touch the shared database (or read deleted env vars) on tenant-scoped paths. Warns by default; set `TIDE_ISOLATION_STRICT=1` in CI to fail-hard. A second test forbids module-level tenant caches and reads of removed env vars (`ELASTIC_URL`, `ELASTIC_API_KEY`, `ELASTICSEARCH_URL`, `KIBANA_SPACES`).
- **Structured JSON logging.** Every request gets a `request_id` (honoured upstream from nginx), every log line carries `request_id`, `user_id`, `client_id`, route, and method, and a single `tide.perf` summary line is emitted per request. Unhandled exceptions return a generic 500 carrying an `X-TIDE-Error-Id` header that points at the matching log entry. Audit events are recorded for login and client switch.
- **SIEM-aware detection rules (Migration 37).** `detection_rules` is now keyed by `(rule_id, siem_id)` instead of `(rule_id, space)`. The legacy table is wiped on upgrade and an in-app banner directs operators to trigger a sync. The next sync repopulates correctly with each row's true SIEM, fixing the long-standing rule mis-attribution and the resulting Test Rule 401 when two SIEMs shared a space name.
- **Manual migration entrypoint.** `python -m app.scripts.migrate` runs pending migrations and reports per-migration summaries for offline maintenance windows.

### Changed

- **Rule reads, writes, sync, and tenant distribution are now SIEM-scoped.** Subtractive delete is per-(SIEM, space) so SIEM A's empty space can no longer wipe SIEM B's rows. Test Rule, Validate, Rule Detail, and Promotion now accept and forward the rule's SIEM so the right Kibana and API key are used; missing `siem_id` falls back to the legacy first-match behaviour with a warning for one release.
- **Test Rule 401/403 messages now actionable.** Failures log the resolved SIEM/space/key prefix and surface a popup naming the likely causes (rotated key, lost privilege, renamed space, mapping drift) instead of just the raw Kibana body.

### Fixed

- **OpenCTI threat actors no longer leak across tenants.** The Threats and Heatmap pages now scope actors to tenants that have OpenCTI linked; tenants without an OpenCTI link see only MITRE baseline actors.

## [4.0.12] - 2026-04-28

### Added

- **Per-SIEM rule-log destination path.** The Rule Logging accordion now exposes an operator-controlled output directory per SIEM. Leaving it blank preserves the previous container-default location.

### Fixed

- **Newly-added SIEMs no longer disappear on the next Management refresh.** Tenant admins now see unassigned SIEMs (with no client links) so they can finish wiring them up.
- **Concurrent `/api/external/*` calls no longer 500 with a database conflict.** The best-effort `last_used_at` write on API key validation now degrades gracefully on contention.
- **Management page renders correctly and the Clients tab loads quickly on tenants with many baselines.** Replaced an expensive per-tenant per-baseline count with lightweight `COUNT(*)` queries, and a single broken tenant DB now degrades to a `0` badge instead of failing the whole panel. Also fixed a literal `\u2026` rendering as four characters on the Tenants & Users placeholder.

## [4.0.11] - 2026-04-27

### Added

- **Per-tenant Role Templates on the Client Detail page.** The previously-global permissions matrix now lives per tenant. Changing a checkbox here scopes the change to *this* client only — a tenant admin in DC can no longer cascade changes into Marvel. The ADMIN role is intentionally read-only here to preserve full access.
- **One-click "Remove" button on each assigned-user row.**
- **Tenant-scoped roles** (Migration 34/35). Granting `darral` ENGINEER in DC no longer makes them ENGINEER in Marvel. The default tenant for new users is the client they were just assigned to.
- **Keycloak group → TIDE role passthrough.** Login maps Keycloak `groups` / `realm_access.roles` to one of `ADMIN`, `ENGINEER`, `ANALYST` (highest wins) for the Primary tenant only. Manual per-tenant role assignments in other tenants are preserved across logins.
- **Keycloak `superadmin` group → platform super-admin.** A new `users.is_superadmin` flag drives platform-wide access; the bootstrap `admin` account is promoted on upgrade.
- **Offline-fallback bcrypt cache for SSO users.** After a successful Keycloak sign-in, the local password hash is cached so subsequent logins work even when Keycloak is offline.

### Changed

- **The Management hub is tenant-scoped for non-super-admins.** A DC admin sees only DC, only DC's SIEMs, and only users that share at least one tenant with them; super-admins continue to see everything.
- **`POST /api/management/users` writes to the active tenant only.**

### Fixed

- **Could not log in once Keycloak was offline.** SSO-provisioned users had no local password hash, so the local fallback never matched. After the first successful sign-in the hash is cached and offline logins work.
- **Elastic/Kibana connections no longer fall back to global `.env` variables.** Every sync, Sigma deploy, promotion, and exception/mapping helper now resolves credentials from the per-tenant SIEM inventory. Removed `ELASTIC_URL`, `ELASTIC_API_KEY`, `ELASTICSEARCH_URL`, and `KIBANA_SPACES` from configuration.

## [4.0.9] - 2026-04-27

### Fixed

- **External Query API examples in the README now use full tenant UUIDs.** The previous truncated UUIDs (`8bab9263-...`) were sent on the wire as literal strings and rejected with a 403. The API and validation code were already correct; only the documentation needed updating. README now uses a `<TENANT_CLIENT_ID>` placeholder and prints full UUIDs in the example response.

## [4.0.8] - 2026-04-24

### Added

- **Management Hub Phase 3 — Sigma Assets editor.** Two-pane CodeMirror editor for Sigma pipelines and templates, with per-file tenant assignment ("force-assign-on-save"); empty assignments are rejected so an asset cannot be left orphaned.
- **Management Hub Phase 3 — Classifications editor** wired to the existing CRUD endpoints.
- **Per-SIEM Rule Logging.** Each SIEM card carries its own logging settings (enabled, target space, schedule, retention) and writes to its own subdirectory. Replaces the previous global config.
- **Management Hub — Threat Intel, GitLab, and Keycloak tabs** for registering and linking external instances to clients (encrypted tokens, CRUD, Test Connection).
- **Per-card status pill and Test Connection button on every Management card.** Status (Active / Failed / Untested) persists across reloads and carries a tooltip with timestamp and last error.
- **Clickable tenant chips** on each integration card link directly to the tenant's detail page.
- **Configurable bootstrap admin credentials** via `BOOTSTRAP_ADMIN_USERNAME` / `BOOTSTRAP_ADMIN_PASSWORD`.

### Changed

- **Management hub layout.** The seven-tab strip is gone; Clients / Users / Permissions live inside a Tenants & Users collapsible, and integrations are reached through the redesigned card layout.
- **Settings page trimmed to Profile only.** Logging, Integrations, Sigma, and Classifications now live in the Management Hub.
- **Cleaned-up `.env.example`.** Removed deprecated variables now managed in-app (SIEM URLs, tokens, MITRE/Sigma sources, rule-log path, etc.).
- **OpenCTI sync is now database-driven.** `run_mitre_sync()` reads from the OpenCTI inventory first and supports multiple instances in a single pass.

### Fixed

- **Test Connection status pill correctly switches to Active or Failed.** The status writer only accepted a legacy value and was silently rejecting every result; the pill now updates as expected.
- **OpenCTI token edits persist and the "Token not set" badge reflects reality.**
- **Editing a SIEM no longer requires re-entering the API token.** Test Connection in edit mode falls back to the stored token when the field is blank.
- **Direct URL navigation to `/management?tab=threat-intel|gitlab|keycloak` works** instead of redirecting to Clients.
- **Test Rule built `None/api/...` after the env-to-UI credentials migration.** The preview now resolves Kibana and API key per tenant from the SIEM inventory.
- **OpenCTI enrichment no longer leaks across tenants.** Cached vulnerability indices are keyed per client; tenants without OpenCTI linked see an empty index.
- **Login no longer redirects to a global default tenant.** Users land on their assigned default client.
- **Various Management Hub fit-and-finish:** unified icon macro, sidebar hidden on login, Keycloak Test Connection button, and consistent OOB swap targets.

## [4.0.7] - 2026-04-23

### Fixed

- **External API: `POST /api/external/query` no longer rejects valid keys.** The validator was returning early when an API key had no creator user, even though the same key successfully listed tenants via `GET /api/external/clients`. The validator was updated and a new end-to-end test (`test/test_external_api.py`) covers auth, multi-tenant routing, SQL injection blocking, and CTE queries.

## [4.0.6] - 2026-04-16

### Fixed

- **Sigma conversion works in air-gapped environments again.** Conversion now uses the in-process pySigma API instead of spawning `sigma-cli`, which was trying to download ~45 MB of MITRE ATT&CK data over the internet and timing out after 30 seconds. File-based pipelines and templates still work.
- **"Create Baseline from Threat Actor(s)" works again.** A missing `client_id` parameter was causing a `TypeError` on every attempt.

## [4.0.5] - 2026-04-16

### Fixed

- **Cross-SIEM promotion no longer silently loses rules.** Promoting a rule between staging and production on *different* Elastic instances was deleting from the source without creating on the target. Promotion now resolves source and target SIEM credentials independently and verifies the rule exists on the target before deleting from the source.
- **Kibana default-space URLs are handled correctly during promotion.** The default space uses a different URL form than named spaces; all helpers now use the right pattern.
- **Empty / NULL space mappings are normalised to `default`.** Production SIEMs are no longer invisible to sync and promotion because of a blank space value.
- **Sync now sources spaces from SIEM inventory.** The legacy `KIBANA_SPACES` env var is no longer required.
- **Management Hub user actions work reliably.** Role saves, deletions, and toggle-active no longer silently no-op due to HTMX attribute conflicts; dedicated management endpoints were added.

### Changed

- **Linked SIEMs UI:** production first, enabled rule counts in green, disabled in muted grey.

## [4.0.4] - 2026-04-16

### Fixed

- **Promotion and Rule Health use environment role, not hard-coded space names.** Clients whose SIEM mapped roles to non-default space names (e.g. Production → `staging` space) saw incorrect rule counts and broken promotion. Roles are now resolved from `client_siem_map`.
- **UI labels show friendly role names instead of raw Kibana space names** (e.g. "Elastic (Production)" instead of `staging`) across rule cards, rule detail, test results, metrics, and the dashboard. Kibana deep-links still use the real space name in the URL.

## [4.0.3] - 2026-04-16

### Fixed

- **External Query API works with multi-tenant databases.** The endpoint now resolves the API key owner's accessible tenants from `user_clients` and opens the target tenant DB directly in read-only mode. `client_id` is required in the request body for multi-tenant users.

### Added

- **`GET /api/external/clients`** lets API key holders discover which tenants they can query.

## [4.0.2] - 2026-04-15

### Added

- **`sigma_rules_index` table** indexing every SigmaHQ rule's logsource metadata, severity, status, and MITRE techniques/tactics, refreshed on each app start.
- **"Generate Baselines" workflow.** A new button on the system detail page opens a product-first tech-stack questionnaire. Selecting a technology (e.g. Windows) generates the relevant modular baselines, automatically loading each Sigma rule's metadata and applying the baselines to the triggering system.
- **"+ Add Sigma Rule" button** on the tactic detail page, with a searchable dropdown filtered by the tactic's mapped techniques.
- **Three colour-coded "Add Detection" buttons** (SIEM / Manual / Sigma) with searchable dropdowns.
- **Sigma rule selector in Convert & Deploy** for tactics with multiple Sigma detections.
- **Clickable SIEM rule names** on the tactic detection section open the rule detail modal.

### Changed

- **Clickable MITRE technique pills** on baseline pages now open the technique detail slide panel.
- **Coverage-coloured pills** on baseline pages reflect actual coverage (green with rule count, red for gaps) instead of neutral blue.
- **SIEM rule dropdown** now shows MITRE pills, severity, and enabled status.
- **Detection rules are colour-coded by source** (SIEM = green, Manual = blue, Sigma = amber).
- **Tactic detail descriptions render Markdown** (bold, italic, code, line breaks).

### Fixed

- **Technique coverage counts now match the detail view.** Case-insensitive MITRE ID matching brings the aggregate count and the per-technique list into agreement.

## [4.0.1] - 2026-04-15

### Fixed

- **500 errors on tactic edit, CISA KEV upload, MITRE CVE map upload, and blind-spot updates** caused by inconsistent `client_id` parameter handling across the API and engine layer.

## [4.0.0] - 2026-04-14

### Added

- **Management Hub (`/management`).** New admin-only area with a tabbed interface for Clients, SIEMs, Users, and Permissions.
- **Move System workflow.** Move a system between clients with a pre-flight dependency check showing affected baselines, host/software counts, and SIEM compatibility. Applied detections are reset when the target client's production SIEM spaces differ. Works across tenant databases in the new per-tenant architecture.
- **Graceful "resource not found" redirects.** Browsing a system / host / CVE / baseline / tactic from a different tenant redirects (or HTMX-redirects) instead of returning a hard 404.
- **Database-per-tenant architecture.** Each client now has its own DuckDB file, guaranteeing zero cross-tenant data leakage at the storage layer and removing DuckDB's single-writer bottleneck. Reference data (MITRE, SIEM inventory, tenant mapping) is synced as a physical copy into each tenant database. Detection rules are distributed into each tenant database after sync, filtered to the client's mapped SIEM spaces.
- **One-time migration script** (`migrate_to_multi_db.py`) splits an existing single-database deployment into per-tenant databases. `--dry-run` supported.
- **External query API is tenant-scoped.** `/api/external/query` enforces isolation via temporary views, filtered by the API key's owning `client_id`. Explicit `main.*` schema references are rejected.
- **Playwright multi-tenancy E2E suite** covering cross-tenant URL guards, system card navigation, move flow, SIEM reset on move, and API cross-tenant guards.
- **SIEM Inventory.** Central CRUD for SIEMs (Elastic, Splunk, Sentinel) with separate Elasticsearch and Kibana URLs and API key. A single SIEM can be linked to multiple clients with different environment roles.
- **Environment Role model.** Each client-SIEM link carries `environment_role` (`production` or `staging`) and a single `space`. Production SIEMs drive dashboard and heatmap coverage; staging SIEMs drive promotion.
- **Test Connection** for SIEMs via Kibana `/api/status`.
- **Client-aware coverage queries.** All coverage, TTP, rule-count, and Sigma queries accept an optional `client_id` so results are scoped to that client's production SIEM spaces.
- **Manage Assets page.** Client detail page now shows Systems, Baselines, Linked SIEMs, and Assigned Users with counts.
- **User → client assignment checklist** updates the `user_clients` join table directly.

### Changed

- **~40 shared-only methods** in the database service now use the shared connection explicitly, so migrations and user/role/permission/client CRUD always target the shared database.
- **Tenant context is set per request** via `contextvars`; all tenant-scoped queries route to the right database automatically.
- **App startup** initialises multi-DB routing and refreshes reference data on each boot.
- **Tenant switcher** redirects to the dashboard after switching, avoiding 404s on resource-detail pages that belong to the previous tenant.
- **Management partials and the client detail page** use the right tenant context for their queries.
- **Sidebar:** replaced "Clients" with "Management".
- **Settings page:** Users and Permissions tabs removed (now only in Management Hub).
- **HTMX-driven Management Hub tabs** keep state in the URL across client switches.
- **SIEM cards** match the Systems page card pattern.
- **"Space" labels renamed to "SIEM"** on Rule Health and Sigma pages.
- **Sigma deploy targets** are client-scoped (e.g. "DC (Production)") instead of every Kibana space from the environment.
- **Heatmap, Sigma, inventory engine, and reports** are now client-aware end-to-end.
- **Modal consistency** across the Management Hub matches the Systems page pattern.
- **Architectural reset & instruction hardening.** Removed host-side `node_modules/` and lockfiles that had been committed; documented HARD STOPs banning host-side `npm`/`npx`/`pip` installs and mandating `--rm` for Playwright containers.

### Fixed

- **Baseline reports no longer show cross-tenant system names.** Coverage and `system_baselines` joins are filtered by `client_id`.
- **Rule Health is scoped to the active client's linked SIEM spaces.** Clients with no SIEMs see 0 rules, 0% coverage (previously they saw the global pool).
- **Rule metrics, the space filter, and the dashboard all respect the active client's spaces.**
- **Login redirects to the user's default client** instead of always landing on the system default ("Primary Client").
- **User deletion cleans up `user_clients` and `api_keys` references** instead of leaving orphaned rows.
- **Threat Landscape is scoped to the active client's spaces.** Clients with no SIEMs see 0% coverage across all actors.
- **Baseline assignment validates same-client ownership** of both the system and the playbook before insert/delete.
- **Asset reassignment is rejected** if the system or baseline already belongs to a different client.
- **Sync status banner no longer leaks the global rule count.** Now shows "Sync complete" and dispatches a refresh event for scoped metrics.
- **Sigma deployment is restricted to the active client's linked SIEMs;** the deploy endpoint validates the target space belongs to the client.
- **Baseline detail isolation:** the systems list and step-coverage matrix filter by `client_id`.
- **Management responses no longer leak UUIDs** in error toasts.

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
