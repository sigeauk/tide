# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [6.3.1] - 2026-10-29

### Added
- **Find rules by where they are linked.** **Rule Health**'s **State** filter has **Linked to**, which narrows **Linked** to the rules linked to a copy at one SIEM destination. For example, pick your production destination in **SIEM**, then your staging one under **Linked to**, to see the production rules that have a copy in staging.
- **Link a client's GitLab projects.** A client's page has a **GitLab Projects** section, where its Admins link a project to back up its rules to and any number to raise issues in, each with its own access token. One project can do both. TIDE tests each project the way it will use it and says what to fix: the token, the project's path, its role, a protected branch, issues turned off, a project that isn't private, or a token about to expire. **Diagnostics** lists projects that need attention. A GitLab integration in **Management** now holds only GitLab's address: it no longer takes a token or a default group, and a token saved on one before is removed when you upgrade, since nothing used it. The `GITLAB_URL` and `GITLAB_TOKEN` settings in `.env` are no longer read: the Dashboard's **Connected services** now shows the client's GitLab projects instead.
- **Back up every rule to GitLab.** After each sync, TIDE backs up the rules of the destinations it covered to the client's GitLab backup project: every rule, Elastic's prebuilt ones too, and their exception lists, one file per rule in a folder per destination, with a README listing them by name. Files change only when the rule does, each commit says what changed and who last changed it in Kibana, and commits are marked `[skip ci]`. A rule given its own rule id moves to its new file, keeping its history. **Back up now** on the client's page backs up everything at once, and **Pause backups** stops backups without unlinking the project. Every destination is backed up, including ones linked later, unless you untick it under the project's **Back up**. Kibana wins: a rule file changed in GitLab is put back to Kibana's version at the next backup, and Rule Monitoring lists it under **Backup changed in GitLab**. A destination never synced is left as it is, so an empty TIDE can't empty a backup.
- **Raise Rule Monitoring's findings as GitLab issues.** **Copy for engineers** now has **Raise in GitLab**: pick one of the client's GitLab issues projects, optionally assign it to one of the project's members, adjust the title and labels, and TIDE opens the issue with the Markdown shown as its description. Each cause then links to its issue, and raising a cause again offers to add what TIDE finds now as a comment on the issue already raised, rather than raising a duplicate.

### Changed
- **An OpenCTI actor that is an ATT&CK group shows as that group, with techniques from both.** When an intrusion set from a client's OpenCTI is an ATT&CK group by name or alias (Fancy Bear for APT28, say), Threat Landscape shows the ATT&CK group with OpenCTI's techniques added and both sources. Each **Sync Threats** replaces the client's OpenCTI actors with what OpenCTI holds then, so one deleted in OpenCTI goes; if OpenCTI doesn't answer, the client keeps the actors it had and the sync says why.
- **Settings opens on Management.** For admins, **Settings** now opens on **Management**, and **Profile & Preferences** is the last tab. Everyone else still opens on **Profile & Preferences**, now at `/settings/profile`; links and bookmarks to `/settings` still work.
- **⋮ menus in place of buttons, and page headers laid out alike.** A client's page, a device's page and a CVE's page now have the same header as every other page: breadcrumb, title, description and **⋮** in the same places. On a client's page, each section's **Edit** is now **Manage …** in its **⋮**, the page's **Edit** and **Delete** are in the **⋮** at its top, and each row's actions are in a **⋮** of its own: a GitLab project's **Back up now**, **Pause backups**, **Test** and **Edit**, a destination's **Edit**, and **Remove from client** for a user. In **Management → Integrations**, each card's test, edit and delete buttons are now **Test connection**, **Edit** and **Delete** in its **⋮**. A device's page has **Edit device** in its **⋮**, **Add package** in the **⋮** on **Packages**, and each package's **Edit** and **Remove** in its own **⋮**. A CVE's **Export report** is in its page's **⋮**.
- **Filter counts follow your filters.** The number beside each choice in **Rule Health**'s and **Rule Monitoring**'s filters is now how many rules you would see by picking it, with your other filters as they are, and it changes as you filter. Before, it counted every rule whatever was chosen.
- **Moved and copied rules use index patterns, not data views.** A data view belongs to one Kibana space, so a rule that searches one is now always copied with the data view's index patterns (for example `logs-*`), wherever it goes. If TIDE can't read the data view, nothing is changed and it says so.
- **Indicator match and machine learning rules are scored on what they use.** An indicator match rule's **Mapping** now checks the fields in its indicator mapping, each in its own indexes and each indicator field in its indicator indexes, where before only its query's fields were checked, and a query such as `file.hash.*:*` left nothing to check. **Rule Monitoring** also reports an indicator field its indicator indexes don't have. A machine learning rule is no longer marked down for **Timestamp override** or **Query language**, which it doesn't have. These rules' scores change at their next sync, and the Dashboard's **Avg Quality** can't be compared with days before then.
- **Unlinking a rule from Elastic also gives it its own rule id.** A rule you unlink from Elastic is your own, so if it uses Elastic's rule id, **Unlink from Elastic** now also creates it again in Kibana under a new rule id, as **Give it its own rule id** does, and Kibana can then install Elastic's rule in that space. **Rule Monitoring** now offers **Unlink from Elastic** beside **Give it its own rule id** for a custom rule using one of Elastic's rule ids, for a rule that isn't Elastic's.
- **No Test for machine learning rules.** **Test** in the rule window ran a machine learning rule as an empty query, so what it showed wasn't the rule's. A machine learning rule has no query to run, so its window no longer offers **Test**.
- **Copy for engineers gives each team what it needs.** Each issue in **Rule Monitoring** now has its own **Copy for engineers**, for all its causes at once. A missing index or field is copied as a table of each field and index to fix on each SIEM, with how many rules it affects, instead of a list of rules; where the rule may be at fault instead, such as a field name no index has, the rules and the fields each uses follow, for their author. Every other issue lists its rules with what was found on each, where before only the first rule's message from Kibana was copied.

### Fixed
- **Every rule comes in at each sync, however many are running.** With many rules enabled, a sync could read some rules twice and miss others, so the destination's sync was incomplete: a missed rule kept TIDE's old copy, and a rule deleted in Kibana wasn't marked deprecated. Each sync now reads every rule once.
- **Syncs, Rule Health and Rule Monitoring are faster.** Saving a sync's rules, and the changes Kibana made to them, now takes seconds rather than up to a minute for a few thousand rules, and the first visit to **Rule Health** after TIDE starts no longer waits several seconds. Opening **Rule Health** also works out its figures and filter counts once instead of twice. **Rule Monitoring** shows the rules of a large group when you open it, so a long list opens quickly instead of drawing thousands of rules at once.
- **A client's OpenCTI threat actors are its own again.** **Sync Threats** stored the threat actors read from a client's OpenCTI where every client's Threat Landscape read them, so one client's OpenCTI techniques could be added to the ATT&CK groups every client sees. They are now kept for that client alone. The first time TIDE starts after upgrading, it removes any OpenCTI data from the actors all clients share: run **Sync Threats** on each client that has an OpenCTI to bring its actors back.
- **Threat Landscape's figures count the actors it lists.** **Tracked Actors**, **Unique TTPs** and the coverage figures came from an old copy of the actors kept in each client's database, so a new client's showed nothing and others could count actors of vendors TIDE no longer supports. They now count exactly the actors the page lists.
- **The Dashboard's Connected services shows the client's own OpenCTI and GitLab.** Its OpenCTI and GitLab cards showed settings from `.env`, which TIDE doesn't use for either, so they said "No Token" whatever was set up. They now show each OpenCTI connector and GitLab project linked to the client, as its last test found it.
- **Your initials sat too high in their circle.** Without a picture, the initials TIDE shows for you now sit in the middle of the circle, in the sidebar and on your profile.
- **Rule Monitoring keeps its filters and folded groups.** Reloading the page, including **Close and refresh** after a bulk change, cleared its filters, and every group opened or closed as it first did. The filters are now kept in the page's address, and each group stays as you left it. Other sections TIDE remembers as open or closed, such as the contents in **Settings → Documentation**, also no longer reopen when the page reloads.
- **Giving a rule its own rule id, or moving it, keeps every exception.** A rule whose own exception list was empty couldn't be given its own rule id, only a list's first 20 exceptions were read, and Move went ahead without a list it couldn't copy. Every exception is now copied, with its comments; if a list can't be copied, nothing is changed and TIDE names the list. A list shared by every space, such as Elastic Defend's, stays shared when the rule stays on the same SIEM.
- **Moving a rule whose connector the target lacks.** When Kibana refused the copy over a missing connector, the move sometimes failed instead of going ahead without that action. It now always goes ahead, and names the actions left behind.
- **Scrolling Rule Health keeps the Upstream filter.** With **Upstream** set, the rules loaded as you scrolled down came from every rule, not only those matching it.
- **The YAML editors load in full however you reach their page.** Opening **Management** from a link, rather than by its address, could load the **Sigma Assets** editors without YAML highlighting and show a script error in the browser. They now load the same way the Sigma page's own-rule editor does.
- **TIDE no longer stops answering after it starts or a Sync Threats.** Now and then, when TIDE started, after **Sync Threats** or when a client was added, TIDE stopped answering, busy at full CPU, until it was restarted. It now carries on.

### Removed
- **The old Clients page.** The client list is in **Settings → Management → Clients**; the old page's address, `/clients`, now opens it there. An unused OpenCTI dialog left in Management, which could no longer save, is gone too.
- **OpenCTI CVE lookups.** When `OPENCTI_URL` and `OPENCTI_TOKEN` were set in `.env`, TIDE asked that one OpenCTI, for every client, which versions of a product each CVE affects while matching devices. Device matching now uses the NVD data built into TIDE alone, and those settings are no longer read. The OpenCTI connectors Threat Landscape uses are unaffected.

## [6.3.0] - 2026-10-23

### Added
- **All your integrations in one list.** **Settings → Management → Integrations** now shows every SIEM, OpenCTI, GitLab and Keycloak together, the Keycloak TIDE signs in with first. **Add integration** asks what to add and opens its form. **Group by** → **Type** puts them in a group for each kind (SIEMs, Threat intel, Identity, Source control), and your browser remembers the choice.
- **Keycloak is managed in TIDE.** The Keycloak TIDE signs people in with is now an integration: change its address, realm, client or secrets in TIDE, without editing `.env` and restarting. When you upgrade, TIDE makes it from the Keycloak settings in your `.env`, so sign-in carries on as before; after that the `.env` lines are not read, and **Diagnostics** says if they still differ, for example when your deployment rewrites `.env`. Saving a change to where Keycloak is first checks that its realm answers, so a mistake can't stop everyone signing in.

### Changed
- **TIDE's database engine is DuckDB 2.0, since 6.2.4.** Databases that TIDE 6.2.4 or later creates, including every backup, can't be opened by TIDE 6.2.3 or earlier. To go back to an earlier version, restore the backup you took before upgrading. Each release is now built with fixed versions of the database engine and every other package TIDE installs, so the same release always installs the same ones.
- **OpenCTI connectors are Threat Landscape's link to OpenCTI.** **Sync Threats** still brings in the intrusion sets of the client's OpenCTI. A connector now asks for OpenCTI's address (the TAXII root an existing connector holds still works), and the arrow button on its card checks the address and token that sync uses.
- **Diagnostics sections fold away, and Query has moved there.** Each section of **Settings → Diagnostics** now opens and closes from its heading, as in Management. The client choice and **Run all checks** sit on the right of **Checks**, on one line. The read-only **Query** console has moved from Management to the bottom of Diagnostics.

### Removed
- **The CTI pages, and the feeds that filled them.** The **CTI** menu, with its **Indicators**, **Actors** and **Reports** pages, is gone. So are the CTI database each client had, the Mandiant, CrowdStrike, GreyNoise and MITRE ATT&CK connectors, a connector's sync and **Auto-sync interval**, and **CTI Egress Targets** on a client's page. TIDE no longer reads the `tide_tlp_max` token claim. When you upgrade, TIDE deletes each client's CTI database and those connectors; to keep them, take a backup in **Settings → Management → Backups** first.

### Fixed
- **Access asks for a client only for Support.** In **Diagnostics → Access**, the client choice showed whatever you chose to change, since 6.2.1. It now shows only for **Grant Support** and **Revoke Support**, and drop-downs elsewhere that should be out of sight stay hidden too.
- **CVE Overview's sort arrow points the same way as every other list's.** It now points down when the CVEs run from highest to lowest (the newest first, as the page opens) and up for the reverse.

## [6.2.4] - 2026-10-22

### Added
- **Compare a custom copy with Elastic's rule before choosing what to do.** Where Kibana holds a custom copy beside one of Elastic's prebuilt rules under the same rule id, or two custom rules share one, the two are usually the same detection, so with both enabled each alert is raised twice. **Compare with the copy**, on the rule's row in **Rule Monitoring** and in its window, reads both from Kibana and shows how they differ, whether they detect the same thing and which is enabled. Then choose: **Delete the copy**, **Keep both** (the copy gets a rule id of its own) or **Keep both and disable Elastic's**. **Compare them one by one** takes you through every such rule in turn. This replaces **Give the copy its own rule id**, and **Rule Monitoring** now names the rule TIDE doesn't show.
- **Rule Monitoring finds rules linked to an Elastic rule they don't match.** TIDE links a custom rule to one of Elastic's rules by its rule id, or because it was copied from it, and shows Elastic's updates for it. At each sync it now compares each such rule with Elastic's, and lists those whose rule type, query or filters differ under **Linked to an Elastic rule it doesn't match**. **Compare with Elastic** shows the two; then **Keep the link** for a copy you changed on purpose, or **Unlink from Elastic** for a rule that isn't Elastic's, which makes it your own rule even while it uses Elastic's rule id. Nothing changes in Kibana.

- **The Dashboard shows how figures have changed.** Set a section to **Compare with** yesterday, or 7, 30 or 90 days ago, and each figure that can show a change says how much it has gone up or down since the end of that day: green when that is better, red when worse, with what it was then on hover. A Rule Health section shows the change in **Total Rules**, **Enabled**, **Validated** and **Avg Quality**, a system's section in each of its cards, and a Baselines section in **Rules Mapped**, **Uncovered** and **Fully Covered**. TIDE works out the earlier figures from the history it already keeps, so there is nothing to capture or schedule.

- **TIDE at a glance, in the guide.** **Settings → Documentation** now opens with **About TIDE → TIDE at a glance**, for decision makers: what TIDE does for rules, their quality, coverage and threat intelligence, and for secure environments, each part with your own figures beside it, plus how to get the most from TIDE and what's new in 6.2.

### Changed
- **Up to date no longer reads as "Matches Elastic's rule".** For a custom rule linked to one of Elastic's rules, the rule window's **Upstream** section now says Elastic hasn't changed its rule since this one was taken, which is what **Up to date** means; whether the two match is what **Rule Monitoring** now checks.
- **The system report's coverage trend comes from the system's history.** It charts each chosen baseline's coverage at the end of every week, as far back as TIDE has the history (from its 6.0 upgrade, up to a year), and lists the weeks where it changed, in the PDF and the Markdown. It no longer depends on snapshots someone took.
- **Removing a technique or a baseline from a system keeps a record of it.** TIDE now keeps the history of what you remove, and when, so the system's coverage figures for earlier dates can still count it. Deleting a system still deletes everything about it. In a technique's **History**, a change to which destinations a system counts now shows one line per destination.

### Removed
- **Coverage snapshots.** The snapshots of a system's coverage, which could no longer be taken since 6.0.0, are deleted when you upgrade. Each technique's **History** keeps every change to its coverage, and the system report's coverage trend is now drawn from it. To keep the old snapshots, take a backup in **Settings → Management → Backups** before upgrading.

### Fixed
- **A copy that has been dealt with is no longer offered again.** After the custom copy beside one of Elastic's rules was given its own rule id, the rule's window and **Rule Monitoring** still offered it until the next sync of the destination, and trying again failed. It now goes at once.
- **A rule Kibana no longer has is marked deprecated.** **Give it its own rule id** on a rule deleted in Kibana since the last sync failed, asking you to sync. TIDE now marks the rule deprecated there and then.

## [6.2.3] - 2026-10-20

### Added
- **Rule Monitoring finds rules whose schedule misses events.** A rule that searches back less time than it waits between runs leaves part of every interval unsearched, so events there never raise an alert; it is now listed as **Blind windows between runs**, saying how much is missed. A rule with under a minute of additional look-back is listed as **Little or no additional look-back**, since events that arrive late fall between its runs. Kibana reports neither.
- **Fix many rules at once from Rule Monitoring.** **Custom rule using one of Elastic's rule ids** has **Give them their own rule ids**, which gives every rule of the cause its own rule id in one go, and **Change not finished in TIDE** has **Finish them in TIDE**. Rule Health's bulk edit has **Give own rule id** for any rules you tick; selected rules that don't need one are left out.
- **Diagnostics can test a database's indexes.** Two new checks copy a client's database, or TIDE's own, and test every table on the copy for indexes missing rows, the damage that stopped syncs in 6.2.2. The database itself is only read. They take a while on a large database, so they run on their own **Run**, not with **Run all checks**.

### Changed
- **Backups are named with the TIDE version that made them,** for example `tide-backup-20261020-181056-v6.2.3`, and each backup in **Settings → Management → Backups** has **Restore steps** for that backup. They say whether the backup was made by the version you run, and if not, how to restore it into the version that made it, or into the newer one you run, which upgrades it as it starts. The Operations guide explains each step of a restore, and that you can carry each one out your own way, for example in the deployment that writes your `.env`.

### Fixed
- **Syncing rules and Give it its own rule id no longer stop TIDE.** A damaged record of a tenant's rule history and score history could stop TIDE at a sync, or make **Give it its own rule id** fail with an error, and that tenant then failed until TIDE was restarted. The first sync after upgrading to 6.2.2 was the usual trigger. TIDE now repairs that record each time it starts.
- **TIDE restarts itself when its database engine stops a client's data.** After a fatal database error, every page for that client failed until someone restarted TIDE. TIDE now restarts on its own, which also repairs the rule history. If the same error comes back within 10 minutes, it doesn't restart again: it leaves that client's data closed, says why on its pages and in **Diagnostics**, and keeps the other clients working.
- **Changes TIDE makes in Kibana can be finished when TIDE couldn't record them.** If Kibana gave a rule its own rule id, moved or copied it, or restored it, but TIDE then couldn't save the change, TIDE showed an error and kept showing the rule as it was. Trying again failed, because Kibana no longer had the original, or, for a restore, created the rule in Kibana a second time. TIDE now says what happened, and **Finish in TIDE** on the rule, in its window or in **Rule Monitoring**, completes it without changing Kibana again, keeping the rule's history, links and mappings. Trying the action again, or the next sync, also completes it.
- **A sync whose later steps fail now says so.** A sync could read the rules and show **Done** while a step it runs afterwards, such as cleaning up score history, had failed, and only TIDE's log said so. It now shows **Done, steps failed**, naming the step and the error, with **Retry**, and **Rule Monitoring** lists it until a sync's steps succeed.

## [6.2.2] - 2026-10-20

### Added
- **Rule Monitoring: the rules that need action, in one place.** A new page, below Rule Health, lists every rule that needs action, grouped by what causes it, so ten rules failing on one missing index are one thing to fix. It shows what Kibana reported on each rule's last run (an index pattern matching no index, indexes missing the timestamp override field such as `event.ingested`, queries that won't parse, missing privileges, missed runs), fields the indexes don't have, rule id problems, SIEMs that didn't answer, and destinations not synced for 7 days. Each issue says who fixes it (data / ingest, the rule's author, Kibana / platform, or TIDE), what it means and what to check, and how long it has been happening. Filter by SIEM, severity, who fixes and issue; group by issue, who fixes, destination or rule; include disabled rules to see what would fail if they were switched on; and see what was fixed in the last 14 days. It is up to date as of each destination's last sync.
  - **Copy for engineers** gives a cause, or everything shown, as Markdown for a ticket or a chat, with the rules it affects.
  - **Acknowledge…** mutes a cause you know about, with a note, until it affects more rules; **Unmute** brings it back.
  - **Sync these rules** checks whether a cause is fixed, and rules TIDE can fix itself have the fix on their row.
  - A cause found through two SIEMs linked to the same cluster is listed once.
  - A Dashboard can have a Rule Monitoring section, with the page's cards and filters.
- **Help on every page.** A **?** beside each page's title opens that page's part of the user guide in the side panel, so you can read how to use it without leaving what you're doing. **Open in Documentation** at the foot of the panel goes to the whole guide page.
- **Editing one of Elastic's prebuilt rules says what it does.** The Edit form now explains, before you save, that Kibana will mark the rule as customised, and that when Elastic's next update for it is installed in Kibana, Kibana either merges your change with Elastic's or replaces it, depending on your Elastic licence. The rule stays Elastic's, so TIDE still shows when Elastic has an update for it. Rules of your own show nothing extra.
- **Diagnostics shows syncs that can't read every rule, and destinations not synced lately.** Three new checks: destinations whose last two syncs couldn't read every rule, with how many rules TIDE still holds there that Kibana didn't return; rules sharing a rule id in Kibana, naming both rules, which is Elastic's prebuilt one, and which one TIDE holds; and destinations not synced for 7 days, with when each was last synced.
- **Copies of Elastic's rules no longer get in the way of Elastic's own.** Moving, copying or restoring one of Elastic's prebuilt rules, or any rule under one of Elastic's rule ids, now creates it under a new rule id. Kibana can then still install and update Elastic's own rule in that space, and TIDE still shows Elastic's updates for the copy. Rules made the old way are listed in **Settings → Diagnostics**, and each one's window offers **Give it its own rule id**, keeping its history, links and baseline mappings. Where Kibana holds a custom copy beside Elastic's prebuilt rule, the prebuilt rule's window offers **Give the copy its own rule id**.
- **Bulk edit can sync rules, and delete them from Elastic.** **Sync** reads just the ticked rules again from their SIEM, and lists any no longer in Kibana, now marked deprecated with their history kept. **Delete** has **Also delete them from Elastic**, as deleting one rule does, and asks once more before it does.
- **The rule window shows where a rule came from.** A rule taken from Elastic's or the Sigma rules shows an **Elastic** or **Sigma** badge in its window's header, as it already did in the table, with whether an update is available.

### Changed
- **Loading, messages and buttons look the same everywhere.**
  - Anything still loading shows the same spinning loader and words, whether it's a whole page, a section of Settings, a list loading more as you scroll, or a suggestion list in a window.
  - When something can't be done, TIDE says so the same way everywhere: "Could not …", then why. When TIDE can't be reached at all, it gives one message: "TIDE could not be reached, so nothing was changed. Check your connection and try again."
  - The buttons at the foot of every dialog are the same size and spacing, Cancel or Close first.
  - Main buttons, such as **Create** and **Save**, were a pixel smaller than the **Cancel** beside them. They're now the same size.
  - **Validate** in the rule window had smaller text than other buttons. It now has the same text size as other buttons, and is as tall as the buttons beside it.
  - Settings' lists of clients, SIEMs, threat feeds, GitLab and Keycloak show the same "nothing here yet" panel as the rest of TIDE. Their icons are TIDE's own.
  - Text cut short ends in "…" everywhere.
- **Rule Health's Last Synced card shows the date, and warns when data is stale.** It shows the day of the newest sync, with the time beneath, or how many destinations haven't been synced for 7 days, in red. The same card is on Rule Monitoring and a Dashboard's Rule Health section.
- **Reports say when the rules were last synced.** Threat, system and CVE reports show **Rules last synced** beneath **Generated**, on the PDF's cover and at the top of the Markdown, with how many destinations haven't been synced for 7 days. Whoever reads the report can tell how current its coverage is.
- **Rule Health's filters say what they mean.**
  - In **State**, **Live** is now **Unlinked**: found at the last sync, with no copy linked in another destination.
  - **Upstream** names the source: **Elastic update available**, **Sigma update available**, **Up to date**, **Deprecated by Elastic**, **Deprecated by Sigma**, **No longer in TIDE's Elastic or Sigma rules** and **Your own rules**. Saved links and dashboards that used the old choices still work. A rule's badge reads, for example, *Elastic · Deprecated*.

### Fixed
- **Rule history showed changes from Kibana at the wrong time, and some edits twice.** Changes found when syncing were timed in UTC while the rest of a rule's history is in your local time, so they could appear an hour or more out of order. Because the times didn't line up, an edit made in TIDE sometimes appeared a second time, as an edit by *elastic*. Changes from Kibana are now shown in local time, entries already recorded are corrected at the next sync, and an edit made in TIDE appears once.
- **Rules deleted in Kibana kept counting in TIDE.** When Kibana held two rules under the same rule id in a space (usually a copy made under one of Elastic's rule ids, next to Elastic's own prebuilt rule installed later), TIDE thought it hadn't read every rule there. So it never marked rules deleted in Kibana as deprecated in that space, and they kept counting, including as coverage. TIDE now counts every rule Kibana returns, so the next sync marks them deprecated and keeps their history. Log messages about an incomplete sync now name the SIEM as well as the space.
- **A copy of an Elastic prebuilt rule was described as installed by Kibana.** Moving or copying a prebuilt rule creates it in the other destination as a rule of your own, but its **Upstream** section still said Kibana had installed it. It no longer does, and still shows when Elastic has an update for it. Copies made before are corrected at the next sync.
- **A failed request showed two error messages.** TIDE showed both "An error occurred" and "Request failed". It now shows one, which says what happened.
- **Some error messages in Settings showed as plain text.** Errors from the database query console, the threat feed connectors and Hunting appeared as unstyled text instead of in a red box. They now look like every other error.
- **Client settings showed "Loading role templates…" while loading.** It now shows "Loading role templates…".
- **Moving or copying a rule with a rule id of your own now links it and shows it straight away.** Rules created from your own JSON often have a readable rule id, such as *acme-k8s-001*, instead of Elastic's long random ones. Moving or copying one reached the target SIEM, but TIDE then couldn't fetch the new copy: Kibana refused the way TIDE asked for it. So the copy was missing from TIDE until the next full sync, and it wasn't linked to its source. TIDE now asks for these rules in the way Kibana accepts. Rules already moved this way can be linked with **Add link** in the rule window.
- **Saving a rule with a missing field now shows every field that needs filling.** When a required field was in a folded section of the rule form, only the first problem was shown, and other missing fields stayed hidden in their folded sections. Every section with a problem now opens. When the first problem is a dropdown, such as **Target SIEM / space**, the cursor goes to that dropdown.

## [6.2.1] - 2026-10-19

### Added
- **A guide to using TIDE, inside TIDE.** **Settings → Documentation** now explains how to use every page, task by task: creating a system, building a baseline and adding its techniques, mapping rules, recording known gaps, editing, validating, moving and merging rules, taking Elastic and Sigma updates, converting and deploying rules, running hunts, working with threat intelligence, and setting up a client. Each task says who can do it and walks through it by the names you see on screen.
  - The guide has one sidebar: a search across every page, then its pages grouped as **Using TIDE**, **Detection engineering**, **Administration** and **Reference**. The page you are reading opens out there to its sections, and search results take the groups' place while you search. **Start here** shows the groups and their pages. The README is now **Installing TIDE**, under Administration, and links to it open there.

### Changed
- **Every dropdown in TIDE works the same way.** Filters, settings, form fields in dialogs and fields in the rule and technique windows all use one dropdown: a button naming what is chosen opens a list. Picking one choice closes it; where you can tick several, it stays open while you tick. Only one is open at a time, and clicking elsewhere or pressing Escape closes it.
  - On Rule Health, SIEM, Status, State and Upstream show how many rules each choice holds. The Upstream button no longer shows how many updates are waiting; that number is in its list, which now counts **Your own rules** too.
  - The CTI pages and Systems filter as soon as you choose, like the rest of TIDE, so their **Apply** buttons have gone; Systems' search filters as you type. CVE Overview's search, system, coverage, "matched only" and sort are now in one filter bar.
  - Every field label reads the same way, in sentence case (**Risk status**, **Sort by**), and the Sigma Rules, Elastic Rules and Hunting pages label their settings and filters like every other page.
- **Dialogs look and behave the same.** Every dialog, rule or technique window and side panel closes with the same X at the top right, and dialogs come in four widths to suit what they hold. A button that leaves a dialog says **Cancel** when leaving discards what you entered, **Close** when there was nothing to save, and **Back to rule** when it returns to the rule window, and it comes before the main button.
- **Every "more actions" button is the same ⋮.** Pages, sections and rows across TIDE open their extra actions from the same button, in the same place, including CVE Overview's import menu. A SIEM destination's edit button on a client is now a pencil.
- **The MITRE pages show each tactic's icon**, as a system's technique cards do: on technique and mitigation cards and in the table, on tactic cards, beside each group when grouped by tactic, and in the technique, group and mitigation windows. A technique card's sub-technique count has an icon of its own, so it no longer looks like a tactic.
- **Counts and "nothing here" messages look the same everywhere.** A count beside a heading is the same small grey label on every page (the NIST pages and test results showed it in brackets), and a count at the end of a list row matches the filter lists'. A page, list or panel with nothing to show has the same icon, message and next step everywhere, and a rule action that fails or succeeds now says so as a red or green message.
- **TIDE uses the same fonts on every computer and browser.** It used whatever font each computer had, so the same page looked different from one machine to the next, and figures could sit higher or lower than the words beside them. TIDE now brings its own fonts, Inter for text and JetBrains Mono for code, rule IDs and queries, so pages look the same everywhere, including without internet access. Figures in cards, tables and counts are all one width, so they line up. PDF reports are unchanged.
- **Icons look the same everywhere too.** Sort arrows, ticks and crosses, the Enabled and Disabled markers, the Previous and Next buttons and the space picker's arrow were typed characters, drawn by each computer's own fonts, so they changed size and shape from one machine to another, or went missing. They are now TIDE's own icons, like the rest of the app. Previous and Next read the same on every page that pages through results (the CTI pages said "Prev").

### Fixed
- **Moving, copying or merging a rule that has actions to another SIEM or space no longer fails** with "Failed to load action … saved object not found". An action's connector belongs to one Kibana space, so the copy now keeps an action when the destination has the same connector (or one of the same type and name) and goes without the rest, saying which to add to the rule in Kibana.
- **An Elastic rule is no longer flagged Update available when its new version changes nothing TIDE compares.** Elastic sometimes raises a rule's version for something outside the rule itself, and Compare with Elastic then had nothing to show. TIDE now moves such a rule to the new version itself at each sync, and when it first starts after an upgrade, and shows it as Up to date (for a prebuilt rule, saying which version Kibana still has installed). If you open one before that, Compare with Elastic offers **Move to version N** instead of Merge.

## [6.2.0] - 2026-10-18

### Added
- **Elastic's detection rules are built into TIDE.** A new **Elastic Rules** page under **Rules** lists Elastic's detection rules and building blocks as they were in Elastic's public rule repository when your TIDE image was built, so they are there without internet access. Search them by name, ATT&CK technique (part of an id works too: T10 finds T1078 and T1059), platform, integration, type, severity and status; the list loads more as you scroll. Open one to see its query, techniques, investigation guide, setup, source and the oldest Elastic version it runs on, shown as Elastic packages it for Kibana. Its **Version** also gives the version Elastic ships to newer Elastic versions when that differs (for example *· 109 on Elastic 9.5+*), with a tip saying which one is shown and what the newer build changes. **In your SIEMs** shows where this client already has the rule, Kibana's prebuilt copy or yours, with its version and whether it is up to date; click one to open it. **Deploy** opens the rule form filled in with Elastic's rule, set to the **Deploy to** destination and **Deploy as** state chosen across the top, so you can change it first; settings the form doesn't show, such as a new terms or threshold rule's, are kept as Elastic has them. It goes in as your own rule, under a new rule id so Kibana can still install Elastic's prebuilt copy there, and with the version Elastic gives that SIEM's Elastic version. TIDE asks first if that SIEM runs an older Elastic than the rule needs, and refuses a second copy in the same place. Technique windows and the technique side panel now suggest Elastic rules next to Sigma rules, and a technique window can deploy one straight away. The Dashboard's **Built-in data** section shows which copy of Elastic's rules your TIDE has. Each role starts with the same access to the page as it has to the Sigma page.
- **Hunting.** A new **Hunting** page under **Rules** brings together Elastic's hunting queries and SigmaHQ's threat-hunting rules, both built into TIDE: searches for activity your detection rules may not alert on. Filter them by source, platform, ATT&CK technique or text (the list loads more as you scroll), and open one to read it: an Elastic hunt with its queries and notes, or a Sigma rule laid out like on the Sigma page, each with its source. **Run** a query on one of your SIEMs: choose the destination and the time range across the top (or keep the time the query sets). Elastic's ES|QL and EQL queries run as they are written; a Sigma rule is converted to ES|QL first, with the Sigma pipeline and index pattern chosen there, and the query that ran is shown. The hits show under the query: how many, where, over what time and how long it took, the first 50 rows, and **Copy** to paste them into a spreadsheet. A SIEM with no data in the query's indices says so instead of failing. Osquery queries run on your hosts rather than the SIEM, so they have no Run. **Save to Kibana** saves an ES|QL query (a Sigma rule as converted) in the chosen destination's Kibana space as a Discover search, named after the hunt and with the chosen time range, and links to it; saving it again replaces it. EQL queries can't be saved, as Discover doesn't run them. Saving needs edit access to the Hunting page, and an API key with Discover access in that space. Each role starts with the same access as it has to the Elastic Rules page.
- **TIDE tells you when Elastic or Sigma has updated a rule you use.** TIDE now remembers which of Elastic's rules or the Sigma rules each of your rules came from: those you deploy from TIDE, and those it finds at a sync, including Elastic's prebuilt rules installed by Kibana, copies of them made in other spaces (compared by the Elastic version they carry), and rules made from Sigma rules before this version (found by their Sigma title and Sigma's ATT&CK tags). After you upgrade TIDE, the ones with a newer version are flagged. Elastic's rules are compared with the version Elastic ships for each SIEM's Elastic version, which TIDE now reads at each sync. Rule Health has a new **Upstream** column and filter (Update available, Up to date, Retired upstream, No longer upstream, Your own rules); the filter counts the rules in each state, and its button shows how many updates are waiting. The rule window has an **Upstream** section, and its ⋮ menu **Compare with Elastic** (or Sigma). Laid out like Compare, it shows your rule beside the new version with a tick per section, and **Merge** writes the ticked sections of the new version into your rule: keep your query, say, and take the new investigation guide. Or keep your rule as it is; either way the update is marked as reviewed. Elastic's prebuilt rules can be merged too: Kibana keeps them as Elastic's and marks them customised, and asks how to combine the two when it later installs Elastic's update itself.

### Changed
- **The Sigma Rules, Elastic Rules and Hunting pages look and work the same.** Each has its settings across the top (Sigma: how rules convert; Elastic: where Deploy puts a rule; Hunting: where and how hunts run), a rule browser with the same filters and rows on the left, and the open rule on the right, laid out to read with its source, colour-coded, at the bottom. On the Sigma page a rule now shows its query converted with the settings across the top, following any change to them, and **In your SIEMs** shows where this client already has a copy; **Convert** opens the rule form filled in. The YAML editor has moved off the page: **Add your own Sigma rule** in the ⋮ menu takes a rule of your own, shown and converted the same way. The page's Create Rule button has gone (Rule Health has it).
- **Rule Health cards are simpler.** A card shows the score ring, the title and one line of facts: the destination (a filled dot when the rule is enabled), its severity and its ATT&CK techniques. Below that, a flag appears only when something needs noticing: Linked, Deprecated, SIEM offline, an upstream update or a retired upstream rule. Cards or table is now chosen in the ⋮ menu (**Show as cards**, **Show as table**), so the filters fit on one line.
- **Moving or copying a rule onto a destination that already has its rule id now asks instead of refusing.** Nothing is overwritten. If the two are the same rule (index patterns and whether it is enabled aside), **Link them** for a copy, or **Move onto it** for a move, which deletes this copy and points its baseline mappings at the one already there. If they differ, the dialog shows how, and **Copy under a new rule id** puts this rule beside the other one with an id of its own; TIDE records which rule it was copied from and keeps tracking Elastic and Sigma updates for it. Bulk Move moves every other rule first, then lists the ones that clash so you can decide each.
- **Merge can take only some sections.** Compare now has a tick beside each section that differs; untick one to leave it as the other rule has it. With every section ticked, Merge copies the whole rule over as before. Compare also shows more of each rule: its setup guide, rule type settings, timestamp override, alert suppression, maximum alerts and whether it is a building block. Long items, such as false positives and references, now show as lines rather than coloured chips, and text that differs only in its line breaks or indentation is no longer shown as a difference, here or in Review update.

### Fixed
- **Moving or copying a rule no longer overwrites a different rule that has the same name in the destination.** When the destination had no rule with the moved rule's id but did have one with the same name, that rule was replaced.
- **Merging the whole of a rule onto its linked rule now always overwrites that rule.** When the two had different rule ids and names, Merge created a second copy beside the linked rule instead.
- **With debug on, the API documentation's sign-in redirect page is now under `/api/docs`** with the rest of the API documentation, instead of on its own at `/docs/oauth2-redirect`.

## [6.1.4] - 2026-10-16

### Added
- **Scheduled backups.** A new **Backups** section in **Settings → Management** (super admins) backs up TIDE every day at the time you choose, and keeps the number of backups you choose; **Back up now** makes one straight away. Each backup copies every database, the key to the stored credentials and your Sigma pipelines and templates, while TIDE keeps running. Backups hold only live data, so they are usually far smaller than the `data` folder, whose database files never shrink. The panel shows the last result (or why it failed), the backups kept, and the commands to restore one. Backups are off until you turn them on.
  - **When upgrading:** backups are saved on the host in `backups/` next to `docker-compose.yml`, or the folder `BACKUP_PATH` in `.env` names. Use the `docker-compose.yml` from this release (it maps that folder) and run `docker compose up -d`; until then the panel warns that the folder isn't mapped. Put backups on another disk if you can.
- **Filter Rule Health by Linked, and leave linked rules out.** The **State** filter now has the same four choices as the badge on each rule: **Live**, **Linked**, **SIEM offline** and **Deprecated**, and every rule is in exactly one. **Live** alone now shows live rules with no copy linked in another destination, for example to find rules that are safe to move. Tick **Live** and **Linked** together for every live rule, as **Live** showed before. Saved Dashboard sections and bookmarked links filtered by **Live** keep showing every live rule. Dashboard Rule Health sections offer the same four choices.

### Changed
- **Without a picture, your avatar shows your first and last initials**, for example "JS" for Jane Smith, rather than one letter.
- **The guide is split into short documents, and the release notes have their own tab.** The README now covers what TIDE does and how to install it. Configuration (settings, certificates, single sign-on, users and roles), Operations (syncing, coverage, backups and upgrades, moving hosts, disk space, Diagnostics and troubleshooting) and the External Query API each have their own document, in a `docs` folder beside the README. In TIDE they are tabs under **Settings → Documentation**, and links between them open the right tab. The release notes moved to a new **Settings → Changelog** tab. Single sign-on now has step-by-step Keycloak set-up. The README's design-system, project-structure and old v3 API migration sections are gone.
- **Documentation is easier to find your way around.** Headings are in the accent colour. In the contents list, each section's subsections fold away until you click its arrow, and the whole list folds to give the page the full width. Both are remembered in your browser.

### Fixed
- **Rule Health's table no longer jumps when a filter is applied.** For a moment after a short list loaded, the Rule column shrank to half its width and then sprang back.
- **Status labels are centred.** The text in labels such as **Reachable**, **Enabled** and the SIEM name on a rule sat slightly high, with more space below it than above.
- **Diagnostics lists each client's destinations evenly.** Every row is the same height, with its text and **Reachable** label lined up.
- **Management → Query no longer fails with "database does not exist"** when another TIDE process, such as a maintenance command, starts while a query runs. Starting it cleared every query's working copy, including ones in use.
- **The API key panel no longer says a client's database is opened read-only for queries.** It isn't: queries are kept to reading by the checks described there, which the panel and the API document now explain correctly.
- **Diagnostics' "Rule mappings that need relinking" says which system each one is on.** Each system has its own copy of a baseline, so after you relinked a technique on one system, the same technique on another system was still listed and looked like the one you had just fixed. Each finding now names its system, and the destination it was mapped from.

## [6.1.3] - 2026-10-15

### Added
- **Settings & Administration, under your name.** Your name at the bottom of the sidebar opens like the other sidebar groups, with **Settings**, a switch to the light or dark theme, and **Log Out**. Settings opens Settings & Administration: one page with a tab each for Profile & Preferences, Management, Diagnostics and Documentation, so the sidebar keeps only the pages you use day to day. You see the same tabs your role allowed before: Management for admins, Diagnostics for super admins and Support. Bookmarks to the old Management, Diagnostics and Preferences pages open the right tab.
- **Your own name and picture.** In **Profile & Preferences**, choose the name TIDE shows for you, and add a picture (PNG, JPEG, WebP or GIF, up to 256 KB). Single sign-on users can do this too. The tab also shows how you sign in, your access, and when you last signed in, alongside the theme, brand colour and your API keys, with Profile, Sign-in and Appearance side by side.
- **The TIDE guide, inside TIDE.** The **Documentation** tab shows the guide with a list of its sections, and works without internet access. It starts with what's new: every change in the current major version, taken from these release notes, newest first. Every role can read it; admins can change that in Role Templates.
- **Choose each dashboard section's icon.** In **Edit**, click a section's icon to choose any of TIDE's icons, with a search to find one. **Default icon** puts back the section's own.

### Changed
- **Figure cards show figures, not descriptions.** Across TIDE (Dashboard, Systems, Baselines, CVE Overview, Threat Landscape, the MITRE pages, CTI and Diagnostics), a card shows its figure, its name, and a second line only when that line holds figures, such as "8 of 24 scored" or the coloured counts under Validated. What the card counts is in a tip when you hover over it or tab to it. When a card has no figure, it still says why.
- **The Dashboard's Repositories section is now Built-in data, and covers everything TIDE works from offline.** Besides ATT&CK and Sigma, it now shows the CISA KEV catalogue and the two ATT&CK mappings (KEV to ATT&CK, and NIST 800-53 to ATT&CK). Each tile says only whether the data is available. Hover over a tile to see its version or date and when it was bundled into TIDE, for example "Catalogue 2026.10.13, 1,741 vulnerabilities" or "3,154 rules". Tiles no longer show file locations. A section that showed every tile shows the new ones too.
- **The threat report's coverage table heads its rules column "Detection Rules"**, since the rules come from the client's connected SIEMs.

### Removed
- **The Notifications and Display preferences.** They were saved in your browser but never changed anything.
- **The Elastic Detection Rules tile.** TIDE never bundled those rules, so the tile always said "Not Found". Rules come from the client's connected SIEMs. The `ELASTIC_REPO_URL`, `ELASTIC_REPO_PATH`, `SIGMA_REPO_URL` and `MITRE_*_SOURCE` settings are gone too, as nothing reads them. If they're still set, TIDE ignores them.
- **PRE-ATT&CK.** MITRE retired it in ATT&CK v8 (2020) and moved its content into Enterprise, as the Reconnaissance and Resource Development tactics. TIDE no longer bundles it. It added nothing current: its techniques were all retired, and its seven groups are in Enterprise too. The MITRE pages' source filter no longer offers PRE, and the Built-in data section no longer lists it. Until the next threat sync, the seven actors it covered still show PRE as one of their sources.

### Fixed
- **The brand colour now changes TIDE's accent colour.** The brand colour slider (now in **Profile & Preferences**) used to change nothing. It now recolours buttons, links, tabs and highlights in both themes, and **Reset** puts back the default.

## [6.1.2] - 2026-10-14

### Added
- **Several dashboards, built from sections you choose and filter.** A client can have as many dashboards as it needs. Pick one from the list beside the page title. Each person sees the dashboard they opened last, or the client's default. **Edit** names a dashboard and adds, arranges and filters its sections. The **…** menu makes a new dashboard, duplicates one, sets the default, or deletes one (other than the default). Anyone who can edit the Dashboard can do all of this, for everyone on the client.
  - A section shows the figures from one page: Rule Health, a system, Threat Landscape, Baselines, Asset Inventory or CVE Overview. A section can also show the state of the connected services or repositories. Add the same kind of section as often as you like, give each its own name, and tick which figures it shows. For example, one section can show Total Rules and Validated for one SIEM's enabled rules, and another the average quality of a second SIEM's rules.
  - A Rule Health section is filtered as the Rule Health page is: by SIEM, status, state, score, validation date and search. A system's section shows that system's figures. Other sections show figures for the whole client, as their pages do. While you edit, each section shows its figures as they will look.
  - A section's figures share its width, however many it shows. Make a section narrower to put another beside it.
  - Figures are worked out each time a dashboard opens, so a change, such as a rule mapped on a system, shows as soon as you reload.
  - Clicking a figure opens its page, filtered the same way, so you can see the rules or techniques behind it.

### Changed
- **Your Dashboard layouts are now dashboards.** The client's layout is now its default dashboard, "Overview". A client that never changed its layout gets TIDE's default layout as "Overview". Each person's own layout is now a dashboard named after them, which anyone who can edit the Dashboard can rename or delete. **Edit** replaces **Customise**, **Edit my layout** and **Edit the layout for** the client.
- **The Dashboard's Promotion section is gone.** It counted rules under the old production and staging split, which destinations replaced. A Rule Health section filtered to a SIEM shows the same figures.
- **Windows have tidier headers.** The rule, MITRE and baseline technique windows now have the same controls on the right of the header, in the same order: the window's main action, previous and next, the **…** menu, then close. In the rule window, the date the rule was last validated sits beside **Validate**, and **Edit** is now the first item in the **…** menu.
- **Arranging sections works the same everywhere.** Every window, and each system's page, has **Sections** in its **…** menu. There you choose which sections show, turn on **Move sections** to drag them into a new order, or reset the layout. The move handles show only while **Move sections** is on. In a window it stays on until you close the window. A system's page can now hide sections too. Moving a section in a baseline technique window no longer goes through that section's own **…** menu.
- **The Last run section in the rule window is easier to read.** The first row shows the run's status, when it ran, how long it took and any gap. The second row shows how often the rule runs, how far back it looks and its maximum alerts. Kibana's message is in a quieter box, and **Test** sits on one line below.
- **Score breakdown has a plain heading.** It no longer repeats the rule's score, which is shown at the top of the window, or the scoring model version.

### Fixed
- **Sigma rules in a technique window stays collapsed.** Once its suggested rules loaded, the section opened again, so it never stayed collapsed. It now stays as you left it, including when you move to the next or previous technique.
- **The rule window's header no longer flickers when you move to the next or previous rule.** While the next rule loaded, **Validate** briefly showed a spinner and the validation date jumped sideways. Both now stay still until the next rule appears.

## [6.1.1] - 2026-10-13

### Changed
- **Management → Query is much faster.** Every query used to copy the whole database first, which took tens of seconds on a large client. A copy is now reused for 5 minutes, so the queries after the first answer at once. The result says how old the copy is, and **Fresh copy** takes a new one. Queries still never touch the live database. The copy now also refuses to read files or other databases, even if a query got past TIDE's own checks. If the disk hasn't room for a copy, the query says so instead of running.
- **Save and Cancel stay in view in the rule Edit form.** They are pinned to the bottom of the form while you scroll, with **Reason for Change** beside them instead of inside **About Rule**, since every edit needs one.
- **Rule Health no longer repeats the last sync under the page title.** The **Last Synced** card shows when the rules were last synced. A sync that failed, only partly finished or was interrupted is still shown there, with why and **Retry**.

### Fixed
- **A Diagnostics fix could overwrite the backup of another one.** Two fixes on the same client within the same second got backups with the same name, so the copy taken before the first fix was lost. Each backup now has its own name.
- **TIDE could sign everyone out at the end of a sync.** Once TIDE held sync records more than 90 days old, clearing them out at the end of each rule or CTI sync hit a fault in TIDE's database. For a moment everyone's sign-in stopped working: the next click went to the sign-in page, and anything being saved then was lost. Upgrading repairs the database by itself; there is nothing to do by hand. A brief database error also no longer signs anyone out.
- **Editing a rule in TIDE now reliably changes it in Kibana.**
  - **Save did nothing for some rules.** A rule with an empty query, such as a KQL rule that matches only on filters, couldn't be saved: the form refused to send it without saying why. These rules can now be edited. When a field needs fixing, the form opens its section and says what's wrong.
  - **Only what you change is sent**, onto the rule as Kibana has it at that moment. Saving used to send TIDE's whole copy of the rule back. That could undo changes made in Kibana since TIDE last synced the rule, and could add you as the rule's author. It also sent threshold, new terms and indicator match rules as plain query rules, without their settings. These rules now keep their settings: the form says they stay as they are in Kibana, and doesn't offer a query language the rule can't use.
  - **Changes made in Kibana aren't overwritten.** If someone changed a field in Kibana since TIDE last synced the rule, and you change that field too, nothing is saved. The form says which field it was, and TIDE loads Kibana's version so you can check it and make your change again.
  - **Errors are shown in the form.** When Kibana refuses a change, or the rule can't be saved for another reason, the form stays open with what you typed and shows the reason. It used to show nothing, or only "Request failed" messages. Creating a rule does the same.
  - **You can see it working.** Save shows it is busy and can't be pressed twice. The rule window then says what was saved to Kibana, for example "Changed: investigation guide". A save that changes nothing says so, sends nothing to Kibana and adds nothing to the rule's History.
  - **Clearing a field removes it.** Clearing the timestamp override used to put `event.ingested` back while still saying the rule was updated. Now an empty field removes the override, and the rule uses `@timestamp`. Editing a rule with no override shows the field empty, so saving another change no longer adds one. Clearing **Highlighted fields** removes them too. New rules still start with `event.ingested`.

## [6.1.0] - 2026-10-12

### Added
- **Diagnostics page for super admins and Support.** A new **Diagnostics** item in the sidebar shows the install at a glance: TIDE version, database schema, super admins, each client's destinations with their rule counts and whether the SIEM answered at the last sync, and recent errors from the log. Its checks look for known problems and say what each finding means and what to do. You can run every check or one, for all clients or one. They cover:
  - one of TIDE's background services not running: the CTI connector scheduler or the rule-log export schedule. TIDE also says so plainly in its log when it starts;
  - a database not yet migrated, or a client whose database file is missing;
  - destinations on a deleted SIEM, with spaces around their name, unreachable, or with no rules;
  - rule mappings that need relinking, links to a rule that is gone, and rule names that repeat or have spaces around them.
  - **Look up** shows everything TIDE holds for one rule, user or destination, across every client. For a rule, that's every copy with its ID, destination, state, score, links and the baseline techniques mapped to it. For a user, their sign-in, Platform Admin and roles on each client. For a destination, its SIEM, space, rule counts and last sync check. Names and spaces are shown exactly as stored, so a stray space or invisible character, which makes two names look the same but not match, is marked.
  - Checks and look-ups only read data, never change it, and never show stored keys or passwords. Each is recorded in the audit log.
  - **Fixes.** Three checks offer a fix: relinking rule mappings that have exactly one match, removing links to a rule that is gone, and removing baseline rows left behind when their baseline was deleted. A fix shows what it will change first, and you type its name to confirm. TIDE copies that client's database aside before changing anything and keeps the last three copies. **Undo** puts back exactly what the fix changed. A fix won't run while that client is syncing. Fixes are off for every client until a super admin turns on **Allow diagnostic fixes** for it on the Diagnostics page. Each fix and undo is listed on the page and recorded in the audit log.
  - **Support role.** A super admin can give someone the new **Support** role on a client. They can then open Diagnostics for that client only: its checks, its rule and destination look-ups, its errors, and its fixes if the client allows them. They see nothing about other clients, users or TIDE's own setup. Only super admins can grant or remove Support, and it isn't shown in Role Templates, so a client's admins can't change what it allows.
  - **Access.** Super admins see who has Platform Admin and who has Support on each client. They can grant or revoke either by username, or revoke from a person's row. Granting Support also adds the user to that client. You can't change your own Platform Admin, a deactivated user can't be granted either, and every change is recorded in the audit log.
- **Sync history, and Retry.** Every rule sync and CTI sync is now recorded with its client, what it covered, who started it (or that it was scheduled), how long it took, and how it ended: done; partly done, naming the destinations that didn't answer; failed, with the reason; or interrupted, when TIDE restarted while it ran. Records are kept for 90 days.
  - **Rule Health** shows the client's last rule sync under the page title. When it failed, only partly finished or was interrupted, it says why and offers **Retry**, which runs the same sync again over the same destinations. Anyone who can sync rules can retry.
  - **Diagnostics → Sync activity** lists recent syncs, with Retry for the selected client's rule syncs.
  - TIDE's log lines written by a sync carry its id, and each sync's start and end is one log entry with its result and reason. The reason is the same text shown on screen, so a failure can be found in the log. A CTI sync that partly failed shows its errors when you hover over its result.
- **Several roles on one client.** A user can now hold more than one role on a client, for example Analyst and Support, and different roles on different clients. Management's client Users list uses tick boxes instead of a single choice, as Settings → Users already did. On each client, a user can do whatever any of their roles there allows.
- **Arrange the Dashboard.** **Customise** on the Dashboard lets you add titles and text blocks, move sections (drag them, use their arrows, or the arrow keys), make them narrower or wider so they sit side by side, and remove or add them back. **Edit the layout for** the client changes what everyone on that client sees; **Edit my layout** keeps your own arrangement for yourself. Either can be reset to go back to the client's layout or TIDE's default. Layouts are saved with the client, so they follow you to any browser. Anyone who can edit the Dashboard can customise it (Admins and Analysts by default); everyone else sees the client's layout without the controls. The Dashboard now only works out the figures for the sections it shows.
- **Create a baseline from a MITRE group, software or campaign.** Their windows on the MITRE pages now have **Create baseline**. It makes a baseline with one technique for each ATT&CK technique the group, software or campaign uses, each described by what ATT&CK says it does with it, and opens it in Baselines. You can name it and add a description first. It is shown to anyone who can edit Baselines.
- **See a rule's last run, and whether its indexes exist, in the rule window.**
  - A new **Last run** section shows how the rule's last run in Kibana went: succeeded, warning, partial failure or failed. It also shows when it ran, how long it took, any gap between runs, and Kibana's message, which is the reason a run failed. It is as Kibana reported it at TIDE's last sync of the rule (hover over the result to see when); **Sync this rule** fetches the latest. Beside the run are how often the rule runs, how far back it looks and its maximum alerts, and **Test** below them tries the rule against a recent time window. Compare leaves it out, because each copy of a rule runs on its own.
  - **Field mappings** now starts with each of the rule's index patterns and whether it matches any index in the SIEM, not only whether each field exists. A pattern that matches no index means the rule searches nothing there. A pattern not checked yet says so, rather than counting as missing.

### Changed
- **TIDE is named "Threat Informed Detection Engine" throughout**: on the home and sign-in pages, on every report's cover, page header and footer (PDF and Markdown), and in the API description. Some places still said "Threat Intelligence Detection Engineering".
- **Rule Health is much faster for a client with thousands of rules.** The page opens about ten times faster, and its numbers and rule list update several times faster after a filter change. It slows down much less while a sync is running.
- **The Threat Landscape list loads about five times faster.** Working out each actor's country flag took most of its time.
- **The README covers installing and running TIDE.** Installation now walks through a fresh install, offline or online, and the first sign-in and setup: SIEMs, clients, destinations, users and the first sync. A new "Running TIDE day to day" section explains what runs on its own and what you start. It covers syncing rules and what each sync result means, CTI connectors (manual or scheduled, their status and the CTI pages' Sync buttons), the CTI pages and rule-log export. It also says what to do when a sync fails or a connector is unreachable. The list of `.env` settings no longer includes SIEM settings, which are set in Management. The rest of the README now matches the app: the feature overview covers every page, the theme section names the settings to change, and "which rules count for a system" replaces the old production/staging explanation. The external query API's table list now includes only tables you can query. Claims about features TIDE doesn't have, such as publishing reports to GitLab, are gone.
- **Creating a baseline from Threat Landscape or the ATT&CK heatmap needs permission to edit Baselines**, as it does everywhere else baselines are made. It used to need permission to edit the heatmap. The button is hidden from anyone who can't use it.
- **Pages carry no styling or scripts of their own.** All of TIDE's styling now comes from its one stylesheet, and its page behaviour from its one script file, which the browser downloads once and keeps. Pages look and work as before.
- **Text sizes and spacing follow one scale on every page**, set in one place, so the app looks the same throughout. Text that was a fraction of a pixel larger or smaller than its neighbours now matches them, and the Export and Create Baseline dialogs look like the rest of TIDE's dialogs.
- **The rule window stays open after you edit, move or merge a rule**, so you can carry on through the list. Saving an edit shows the rule with your change. Copying it to another destination keeps you on the rule, and moving it opens the moved copy. Merging opens the copy that received the merge. Previous and next carry on from the same place in the list, and the page behind no longer reloads and jumps back to the top. Saving an edit now refreshes just that rule from Kibana instead of syncing every rule.
- **A tidier rule window.** **Validate** and **Edit** sit at the top right, and every other action (Sync this rule, Move, Compare, Restore, View in Kibana, Delete) is in the **…** menu beside them, so the Actions panel is gone. Choosing which sections show has its own button. The date the rule was last validated shows beside its severity, coloured as before, with when and by whom on hover, or N/A if it never was. **About this rule** keeps the description, risk score, language, indexes and tags.
- **Badges look the same everywhere and no longer glow.** Status, severity, rule state and ATT&CK badges across TIDE are flat with slightly rounded corners and softer colours. Score breakdown bars are softer too, and each check shows its points as earned/maximum, with the earned points in the check's colour.
- **Rule syncs start from Rule Health only.** The Dashboard's **Sync Elastic** button is gone: it ran the same sync without the permission check Rule Health's **Sync** has.
- **User and access changes are recorded in the audit log.** Creating, deactivating, reactivating and deleting a user, changing their roles or which clients they belong to, and changing a client's Role Templates each write an audit entry saying who did it, to whom and what changed. Before this, only sign-ins, client switches and Platform Admin changes were recorded.

### Security
- **An API key could read every SIEM's API key, and credentials were stored unencrypted.** The external query API let anyone with an API key for one client read the connection settings of every SIEM on the install, API keys included, and every client's destinations. Those tables are now refused, and each client's database now holds only its own destinations and no SIEM API keys. SIEM, connector, GitLab and Keycloak credentials are now stored encrypted, with a key TIDE creates in `data/credentials.key`; existing credentials are encrypted the first time TIDE starts. Back up `credentials.key` with the rest of `data/`: without it, stored credentials must be entered again.
  - **When upgrading:** old unencrypted copies can remain in the database files' free space until they are compacted. Compact `tide.duckdb` and each client's database (see "Reclaiming disk space" in the README). If API keys have been given to people or systems that shouldn't have access to your SIEMs, change the SIEMs' API keys in Kibana and update them in Management → SIEMs.
- **Signing out didn't end a local session.** It removed the session from your browser, but a copy of it kept working for up to 24 hours. So did sessions from before a password change or reset. Signing out, changing your password, an admin resetting it, and deactivating an account now end all of that person's local sessions, so signing out in one browser signs you out of the others too. After changing your own password you stay signed in where you changed it. Single sign-on is unchanged.
- **A deactivated user's API keys kept working.** Deactivating someone in Settings or Management stopped them signing in, but their API keys could still query the clients they belonged to through the external API. Their keys now stop working while they are deactivated, and work again if they are reactivated.
- **API keys were visible to, and could be revoked by, any client's admin.** Settings → API keys listed every key on the install to an admin of any client, with its label and owner, and let them revoke it. An admin now sees and revokes their own keys and those of users on clients they administer; a super admin still sees all of them. Creating and revoking a key is recorded in the audit log. Settings → API keys also no longer logs an "isolation_violation" warning each time it opens.
- **An admin of one client could manage other clients.** Management's client pages checked that you were an admin of the client you had selected, not of the client being changed. An admin of one client could therefore change another client's users and roles, including giving themselves Admin there. They could also change its Role Templates, linked SIEMs, connectors, baselines and scoring, and move its systems into their own client. Each of these now needs Admin on the client being changed. Moving a system between two clients needs Admin on both, and super admins can still manage every client. Removing someone from a client now also removes their roles there, so their roles no longer count there, and adding them back starts them with none. Check the users and roles on each client if several clients' admins use the same TIDE.
- **An admin of one client could change the CTI connectors, GitLab and Keycloak entries every client uses.** These serve the whole install and hold its credentials, but any client's admin could edit, delete, test or sync them. Changing a connector's address kept its stored key, so the next sync could send that key elsewhere. Like SIEMs, they are now set up by Platform Admins only, and client admins see a note in their place on Management. Client admins still link connectors to the clients they administer from the client page.
- **A user's email or an API key's name could run code in an admin's browser.** Settings showed usernames, emails and API key names exactly as typed, so text that looked like web page code ran when an admin opened Settings → Users or API keys. Anyone can set their own email and name their own API keys. They are now shown as plain text.
- **An admin of one client could reset any user's password, a Platform Admin's included, and so sign in as them.** Settings → Users and Management → Users let a client's admin reset the password of, deactivate or delete any user, and add anyone, themselves included, to any client. A client admin can now reset, deactivate or delete only users whose every client is one they administer, and never a Platform Admin; a super admin can still manage anyone. They change roles only for users on their own client, and add or remove users only on clients they administer. Settings → Users lists the selected client's users, and a client admin adds an existing user to their client by typing the user's exact username, instead of picking from a list of every user, with names and emails, on the install. Users an admin can't manage are listed without those controls. Nobody can deactivate their own account. Password resets are now recorded in the audit log. If several clients' admins use the same TIDE, check that your Platform Admins' passwords and the list of active users are as you expect.

### Fixed
- **Moving a rule left its baseline techniques on the rule it replaced.** When a rule was moved to another destination and removed from the first, the baseline techniques mapped to it still named the old destination, so they could count as not covered. They now follow the rule to its new destination, and each technique's History records the move. Mappings of the same rule at other destinations, such as a copy that stays, are left as they are. Folding duplicate rules together no longer touches mappings at other destinations either.
- **A rule Kibana couldn't decrypt couldn't be changed from TIDE.** A rule created or imported under a different Kibana encryption key failed every edit, enable, disable and Merge onto it with "Unable to decrypt attribute apiKey". TIDE now refreshes the rule's API key in Kibana and tries again. If that doesn't work, it deletes the rule and creates it again with the same rule ID and your change, and if that create fails, it puts the old rule back.
  - A re-created rule has a new Kibana ID, so alerts it raised before are no longer linked to it in Kibana. In TIDE its baselines, links, validation and search times carry on, and its History records the re-creation.
  - TIDE never re-creates an Elastic prebuilt rule. If one can't be fixed, TIDE says so; reinstall it in Kibana.
- **Some buttons stopped working, or worked more than once, depending on how you reached the page:**
  - Management: Edit did nothing for a SIEM, GitLab or Keycloak entry, or a client, whose name contains an apostrophe. A connector you had just created or imported couldn't be edited until you reloaded the page.
  - CVE Overview: the Import buttons did nothing if you opened the page from another page; they only worked after a reload.
  - A host's page: clicking a package to see its CVEs stopped working once its package list was refreshed.
  - Rule Health and Threat Landscape repeated some actions once for every earlier visit in the same tab. For example, switching Rule Health to the table view reloaded the rules several times.
- **Smaller fixes.** Management → Sigma Assets' **+ New Template** now starts with the `{{ query }}` placeholder a template needs; it was left out. Rules in a technique's Add coverage picker now highlight when you point at them. Messages after importing a validation file showed characters such as `<` as codes. A system's heatmap put a technique under Other when no tactic was set on it in the baseline; it now goes under its ATT&CK technique's tactic.
- **Analysts and Engineers couldn't switch client, or change their own email or password.** Picking another client in the sidebar just reloaded the page on the same client, and the Settings profile forms were refused, unless you were an Admin of the client you were on. Anyone can now switch between the clients they belong to and change their own email and password, whatever their role.
- **ATT&CK's Stealth and Defense Impairment tactics were missing in several places.** ATT&CK renamed Defense Evasion to Stealth and added Defense Impairment, but parts of TIDE still used the old list. The ATT&CK heatmap, the Threat Landscape matrix and reports put those techniques under Other; they now have their own columns. Baselines made from a threat actor gave them no tactic, and Baselines sorted them after every other tactic; they now carry their tactic and sort in ATT&CK's order. A rule created in TIDE with one of those techniques lost that MITRE mapping when saved to the SIEM, and Sigma rules tagged with them lost the tactic when converted; both now keep it. Older rules and baselines that say "Defense Evasion" keep that name and sort next to Stealth.
- **The light theme showed dark-theme colours in many places.** Some panels stayed near-black, and warnings, errors and highlights used the dark theme's shades, on every page. Technique pills were dark blue on dark blue, and green, red and amber text was pale on a light background. The heatmaps' technique cells stayed dark in the light theme; they now take softer, muted shades of the theme's own colours in both themes. A system's heatmap also showed the ATT&CK heatmap's legend under its own, with "GAP" meaning something different in each; it now shows only its own. Everything now follows the theme you pick in Preferences. Some dialogs and fields had no background or shadow at all, in either theme, and now have one.
- **Management looked inconsistent in places.** The Sigma **Assign tenants** dialog had no dialog styling, the *unassigned* badge had no colour, and the Import Connectors box was an unstyled text area. They now match the rest of the page. The spaces in a SIEM's Rule Logging list are now in A–Z order instead of a different order each time.
- **Rule Health on a narrow screen loaded every rule in turn.** On a phone or a narrow window it kept fetching the next page of rules until all of them were loaded, instead of loading more as you scroll. Scrolling down any Rule Health list also reloaded the figures above it twice for every page, although they hadn't changed. Both now happen only when they should.
- **Granting or revoking Platform Admin now sticks for single sign-on users.** A grant made in Management → Users used to be undone as soon as the user loaded another page, unless they were in the Keycloak `superadmin` group; a revoke came back the same way. TIDE now keeps what you set there. Signing in no longer writes to the database on every page, only when you actually sign in.
  - **When upgrading:** each user's current Platform Admin setting is kept. From now on, the Keycloak `superadmin` group only applies when TIDE first creates a user's account; after that, grant and revoke Platform Admin in Management → Users. See "Superadmins and Keycloak" in the README.

- **A certificate TIDE refused was reported as "Connection refused".** With Verify TLS certificate ticked, a SIEM whose certificate failed the check showed "Connection refused" in Test Connection, and its rules showed SIEM offline with the same reason, which sent you looking at the network. It now says the certificate was refused, why (not signed by a CA TIDE trusts, a CA certificate missing fields that TLS now requires, a certificate for a different host name, or an expired one) and what to do. GitLab and Keycloak's Test Connection do the same. The README's "TLS certificates" section explains each case.

## [6.0.2] - 2026-10-01

### Added
- **Every integration has its own "Verify TLS certificate" setting.** SIEMs, GitLab and Keycloak entries in Management and every CTI connector now have a box, off by default, that decides whether TIDE checks that integration's certificate. It applies to everything TIDE sends to that integration, including rule sync, promotion, Sigma deploys and CTI exports to a SIEM. Test Connection uses whatever is ticked on the form. See "TLS certificates" in the README.
  - **When upgrading:** every SIEM starts with the box off. Until now, rule sync and promotion checked the SIEM's certificate against any CA certificate you had installed, while other calls did not check it. If you installed your SIEM's CA certificate, tick the box on each SIEM to keep its certificate checked. CTI connectors keep their current setting.

### Changed
- **A system's report now matches its page.** It shows the same six figures as the system page (Covered, Techniques, No coverage, Known gaps, Unmapped, Not counted), a list of priority gaps, and a Coverage by SIEM section. Rules mapped somewhere the system isn't measured are highlighted in red, because they don't count toward its coverage. In Export report you choose which baselines to include, and the figures cover only those baselines.
  - Rules are shown by name, never by ID. Each rule, dashboard, report, log or known gap shows the date it was added.
  - The technical report adds a coverage matrix by baseline and tactic, and a detail entry for each technique: its status, risks, what covers it and its ATT&CK techniques. You choose the gaps only, every technique, or none. Sigma suggestions and the ATT&CK heatmap are no longer included.
  - Markdown exports have the same sections and figures. The PDF has a linked table of contents, bookmarks and "Page X of Y".
- **A sync now deletes the score history of rules that no longer exist** (deleted in Kibana, re-created under a new ID, or at a destination no longer linked), so client databases stop growing with history nobody can see. Rules marked deprecated keep theirs. The README has a new section, "Reclaiming disk space", on compacting a database to recover the space.

### Security
- **A NIST 800-53 capability page now shows coverage only for a client you belong to.** It took the client from the browser without checking you were assigned to it, so a user could see another client's rule coverage of that capability's techniques.
- **The Management query page can no longer read files in the container.** A query may now read only the chosen database's own tables and views, the same rule the external query API has followed since 6.0.1. A slow query no longer holds up the rest of TIDE while it runs.

### Fixed
- **Add link in a rule's window links the rule you pick.** It could reply "No rule found in that destination" for a rule it had just suggested, when the name was typed in different capitals or not picked from the list. It now links the suggestion you click, even when another rule in that destination has the same name, and accepts a typed name in any capitals. The suggestion list no longer covers the Add link button, so a click there can't pick a different rule by mistake.
- **The Systems list and each system's page load faster.** They no longer read every rule in the client to label a technique's mapped rules. Each mapping already records its rule and the SIEM and space it was picked from, so a rule with the same ID in another SIEM can no longer be shown in its place.
- **A rule's History shows again when it was created and edited in Kibana.** Since 6.0.0 these events were recorded but not shown against the rule. The next sync of each client attaches the ones already recorded, and new ones show as they happen.
- **A baseline on another client's page in Management now opens.** Clicking it switches you to that client and opens the template on the Baselines page, instead of an empty page for the client you were on. Only superadmins and users assigned to that client get the link; everyone else sees the name only.
- **Two of the Management query page's ready-made queries failed**: "Systems in selected tenant DB" and "Threat actors in selected tenant DB" now run.
- **Clicking a technique's ATT&CK pill on a system's or template's technique card now opens its side panel**, as it does everywhere else, instead of the technique's window. The same goes for the table view and for the pills in Add coverage's rule list. Clicking anywhere else on the card still opens the technique's window.

## [6.0.1] - 2026-09-30

### Added
- **Sync one destination at a time.** Rule Health's Sync and Sync with mappings buttons now open a list of the client's linked destinations on hover — "Sync DM3-Prod only" — so a slow or overloaded Elastic doesn't have to answer for every linked SIEM and space just to refresh one of them. The buttons themselves still sync everything, unchanged.

### Changed
- **The Baselines page shows templates the way a system's page shows its baselines.** Every template's techniques are in one grid of cards (or a table), grouped by template, with the same search, template, tactic, name and group-by filters, remembered and kept in the address bar. There is no Coverage filter: a template has no coverage until it is applied to a system.
  - Each template's heading has **Manage**, to rename it, add a technique, apply it to a system, import techniques, export a report or TIDE JSON, or delete it. The page's own **…** menu has New baseline, Import and Add technique. A new template shows straight away, ready for its first technique.
  - A technique opens in a window like a system's technique: **Description**, **Sigma rules** (suggested or searched, and converted), **Risks** and **MITRE ATT&CK**, each with its **…** menu and Move, and Delete technique in the window's menu. There is no Coverage or History, as a template has neither until it is applied to a system.
  - The old page for each template now opens the Baselines page filtered to that template.
- **Adding a technique opens its window straight away.** Add technique, on a system's page or the Baselines page, opens the technique window blank: give it a title (the only thing required) and Create, and the window becomes the technique's own, ready for its coverage, ATT&CK techniques and risks. A **+** beside the window's previous and next buttons adds another technique to the same baseline, for entering several in a row. The blank window keeps the section arrangement you have chosen for technique windows, with the title always shown.
- **Templates can set each technique's risks.** A template technique's priority and category are copied to each system it is applied to, as a starting point that the system can then change.
- **Each ATT&CK tactic has its own icon.** Technique cards, the Tactic column in table view, tactic group headings and the technique window's header show an icon for the technique's tactic (binoculars for Reconnaissance, an open padlock for Initial Access, a flame for Impact, and so on) instead of the same generic one for all.
- **A rule's History filled up with a "Synced" entry for every refresh** — promoting, demoting, restoring, bulk-editing or clicking Sync this rule all record one. It now shows one Synced entry per day (that day's latest), the same as the score chart. Every other event (created, edited, validated, promoted, merged, ...) still shows every time, unchanged.
- **MITRE Groups works like Rule Health.** Groups show as cards or a table, with search, source, coverage, sort and group-by, remembered in this browser and kept in the address bar, and more load as you scroll instead of the whole list at once. Each group shows how many of its techniques your enabled rules cover, left edge coloured to match, and the metric strip totals them. A group opens in a window (details, coverage, description, techniques, software, campaigns and mitigations) with previous and next, sections you can collapse (click the section's title) and move, and its own link; old group links open it there.
- **MITRE Techniques works the same way.** Techniques and sub-techniques show as cards or a table with search, source, tactic, type and coverage filters, sort, and group-by tactic (a technique under several tactics appears in each), parent technique or coverage. Each shows whether your enabled rules carry it, or only some of its sub-techniques, and the metric strip counts the gaps known groups use. A technique opens in a window with your rules for it, its sub-techniques, the groups that use it and how, software, campaigns, mitigations, Sigma rules and NIST 800-53 capabilities; sub-techniques, parents and groups open in the same window. Your rules show as the same cards as on a system's technique (score, SIEM destination, enabled, fields found and validation), each opening its rule; the first 50 show, with Show all for the rest. Old technique and tactic links open there too. Wherever an ATT&CK technique is listed (a rule's window, a system's or template's technique window, the other MITRE windows, the side panel and NIST capabilities), its name opens this window and its pill the side panel. ATT&CK links inside descriptions, and the side panel's related groups, software, campaigns and mitigations, open their windows too instead of leaving the page.
- **MITRE Tactics, Software, Campaigns and Mitigations work the same way.** Each shows as cards or a table with search, source, sort and group-by, and how many of each one's techniques your enabled rules cover. Tactics are listed in kill-chain order and can be grouped by source. Software can be filtered and grouped by type and platform. Campaigns can be filtered and grouped by the group they are attributed to, or grouped by the year they were last seen, and list the most recent first. Mitigations can be filtered and grouped by tactic. For a mitigation, coverage means how many of the techniques it addresses your rules would also detect. Each opens in a window: a tactic lists its techniques and the groups that use them, software lists the groups and campaigns that used it, and a mitigation's window breaks its coverage down by tactic. Related groups, software, campaigns and mitigations open in their own windows, and old links open there too.
- **A window section folds when you click its title**, in the rule and technique windows as well as the new MITRE windows, not only from the small arrow beside it. A window also keeps where you put a section, and whether it is hidden, after you rearrange another window of the same kind that doesn't have that section. Choosing Update in a collapsed section now opens it, so the form is not hidden.
- **On the Systems page, a baseline technique's title opens its window in place**, instead of going to the system's page.
- **Dialogs and the client page share the app's styles.** The ✕ that closes a dialog, the client page's section headers, counts and empty states, and the Generate Baselines dialog now use shared styles instead of their own copies. Nothing moves; the ✕ now follows the light theme's muted colour, and the Generate dialog's buttons space their icons like every other button.

### Removed
- **An old Promotion-page sync endpoint nothing has called since the Promotion page itself was removed in 5.1.0.**
- **Unused code left from earlier versions:** an old GitLab rule importer nothing called, and nine page templates no page used any more.

### Fixed
- **Testing a SIEM or Keycloak connection froze TIDE for everyone until it finished.** The test now runs in the background, so other pages keep working while it waits on Kibana or Keycloak.
- **Creating, editing, restoring, enabling or disabling a rule could freeze TIDE for everyone while Kibana answered**, with no limit if Kibana stopped responding mid-request. These now run in the background and give up after Kibana's usual time limit, with the error shown on the rule.
- **A SIEM's connection test failed when Kibana was slow to answer, with an unclear error.** Each check now allows Kibana 30 seconds to answer, says plainly when it connected but did not answer in time, and shows how long each check took. The spaces TIDE syncs are checked first, together, and decide the result; other spaces are reported but no longer fail the test.
- **A slow Kibana could mark a SIEM offline before a sync.** Its reachability check now allows 30 seconds for an answer, and only a failed connection takes the whole SIEM offline; a space that is just slow is reported on its own.
- **Baseline templates could be changed by anyone who could log in.** Creating, editing, importing or deleting a template, and its techniques, now needs permission to edit Baselines. Anything that changes a system needs permission to edit Systems, from whichever page it is done: applying a template to a system or removing it, generating a system's baselines, and mapping rules to its techniques. The template window only offers Apply to a system to those who may edit systems.
- **A rule's score history filled up with same-day entries**, making the score-over-time chart and history table hard to read. Both now show one entry per day (that day's latest score) instead of every rescore.
- **TIDE would start with a weak, shipped-default session-signing secret if `SESSION_SECRET` was never set.** It now refuses to start without a real `SESSION_SECRET` (unless `AUTH_DISABLED=true` for local/dev use), so a session cookie can no longer be forged against the placeholder key. **Before you upgrade**, add a long random `SESSION_SECRET` to your `.env` if it has none (6.0.0's example file did not list it; `.env.example` shows how to make one offline), or TIDE will not start. Everyone will need to sign in again afterwards.
- **The dashboard's Elasticsearch/Kibana cards always showed "No API Key"**, even when a client had a SIEM connected, because they checked a setting that no longer exists. They now show each SIEM actually linked to the active client, and whether it's active.
- **A query through the external query API could read files outside the tenant database**, through DuckDB's file-reading functions or by naming a file as if it were a table. Each query is now checked by DuckDB before it runs and may read only the tenant database's own tables and views; anything else is refused with the name of what was not allowed.
- **The CTI actor, indicator and report pages (list and detail) carried their own one-off spacing** instead of the shared page header, section heading and list-header styles the rest of the app uses, and their muted "no results" text used a colour token that never adapted to light mode. All six pages now share the same classes, so spacing is consistent and the text follows the theme.
- **Two Elastic syncs running close together could show each other's progress**, or one's completion could overwrite another's in-progress message, because the Rules page's Sync button and the dashboard's Sync button shared one process-wide status. Each sync now gets its own tracker, so two syncs — even for different clients — report their own progress independently.
- **A search time recorded from a Test run could be lost the next time "Sync this rule" ran**, reverting "Search time" to not-scored even though the sample was still there. Sync this rule was looking the sample up by the wrong one of a rule's two ids; it now uses the same one the sample was recorded under.
- **The rule window's prev/next arrows could stop working** after an action changed the rule's score (recording a search time, syncing, validating) enough to move it out of the loaded page. They now step through the list of rules as it was when the window opened, instead of re-finding the current rule in a grid that may no longer show it.
- **"Sync this rule" could say a rule's score was unchanged when it visibly wasn't** — it was only comparing against the score as of the start of that click, which an action moments before (like recording a search time) could already have moved. The message now just confirms the refresh happened; the score-over-time chart is the accurate record of what changed and when.
- **Some rules could not be added to a system's technique.** When more than 50 rules carry a technique's ATT&CK IDs, the rules past the first 50 were left out of both lists in Add coverage, so they could not be picked. They now appear under All SIEM Rules.
- **The same person could appear up to three times in a history's user filter**, under their username, full name or email, depending on which action they took. A technique's and a rule's history now show everyone by username, including older entries, and new entries record the username.

## [6.0.0] - 2026-09-28

### Added

- **Name your SIEM destinations.** Every space in a linked Elastic SIEM can now be linked to a client as its own destination, with a name and colour you choose (Management → a client → Linked SIEMs). Existing links become "Staging" and "Production", so nothing looks different until you change them. Renaming a destination never touches its rules, scores or validation.
- **Destination colours.** Each destination has a colour, shown on the left edge of its rules' cards and on its tags. New destinations get one automatically; change it from the destination's **…** menu, which also holds its name and default index.
- **Linked rules.** The rule window lists every rule linked to this one, by name and destination. Each link has its own **×**, and **Add link** (with search as you type) links two rules yourself. On upgrade, rules that were promoted or demoted with the original kept are linked automatically.
- **Compare and Merge.** **Compare**, in the rule window, shows what differs between a rule and a linked rule. **Merge**, inside Compare, lets you choose which side wins and whether to delete the other side afterwards.
- **SIEM offline.** A SIEM that can't be reached during a sync is skipped rather than having its rules marked as lost. Its rules keep showing with a **SIEM offline** state, with the reason on hover, and Rule Health shows a notice. The state clears on the next sync that reaches the SIEM, and the State filter can list these rules, so a retired SIEM's rules can be removed in bulk.
- **Delete from TIDE in bulk edit.** Removes the selected rules from TIDE only. Elastic is never touched, so a rule still in Elastic comes back on the next sync.
- **A window for each technique on a system**, laid out like the rule window: **History**, **Description**, **Coverage**, **Sigma rules**, **Risks** and **MITRE ATT&CK**.
  - Each section's **…** menu holds its actions: **Update** for the description (and title), the ATT&CK techniques and the risks, **Add coverage** under Coverage, and **Move** in every section (arrows, drag or arrow keys, until you press Done). **Delete technique** is in the window's own **…** menu.
  - **Coverage** lists everything that catches the technique: a known gap or N/A with its reason; dashboards, reports and logs; and each mapped rule with its score, destination, whether it is enabled and counted, its field check and its validation.
  - The header's score ring shows the strongest rule protecting the system. Previous/next (and the arrow keys) step through techniques in the order the page shows them, and each technique has its own link to share or bookmark.
- **Non-alerting coverage.** A technique can be covered by dashboards, reports and logs as well as rules, each with a title, an optional link and a rationale, and each can be updated or deleted from its **…** menu. They count as covered and are labelled **Non-alerting**, since someone has to look and nothing alerts.
- **Risks for each technique.** Set a **Priority** (Critical, High, Medium or Low) and a **Category** (Identity, Endpoint, Network, Cloud & SaaS, Container, IMPEX, Email, SecOps or OT/ICS) per system. Priority shows on the technique's card.
- **Sigma rules for each technique.** SigmaHQ rules are suggested from the technique's ATT&CK techniques (or its tactic), and a search finds any other. **Convert** opens the Create Rule form filled in with the converted rule; creating it starts a sync, so it can be mapped once the sync finishes. Suggestions never count as coverage until created and mapped.
- **A history for every technique.** Rules mapped, relinked or removed (with the rule's score at the time), known gaps and N/A marks, dashboards, reports and logs, edits to the technique and changes to SIEM coverage are recorded with who and when, and can be filtered. On upgrade it starts from what already exists.
- **Review dates on known gaps and N/A marks.** From the date you set, the technique shows **Review due** in its window and on the system page. Marks can also be edited in place, and the history keeps what they said before.
- **Choose which destinations count for each system.** A rule only covers a system's technique if it lives at a destination that system is measured on; a rule in staging alone no longer counts. Set it under **SIEM coverage** in the Baselines section's menu. Every system starts out counting all of its destinations, a rule that doesn't count says **Not counted**, and a system with none ticked reads **Not set** rather than 0%.
- **Covers, in the rule window.** Lists every technique the rule is mapped to, with its system, baseline and tactic, including through a linked copy. Clicking one opens its technique window.
- **Relink a mapped rule TIDE can't find.** A mapping whose rule has been deleted, moved or renamed, or that predates destinations, is marked **Needs relinking** with the reason on hover. **Relink**, in its **…** menu, opens the rule picker searched by its name; the rule you pick replaces it, keeping its history. Administrators can relink every unambiguous one at once with the `relink_rule_mappings` maintenance script.

### Changed

- **Move replaces Promote and Demote.** Move a rule to any linked destination, from the rule window or bulk edit. Keep the original to link the two copies, or tick **Delete source after move**. A move that would overwrite a rule already at the destination is refused, with a note to link the two and use Merge instead; if the SIEM can't be reached to check, nothing is moved.
- **Every rule has its own card.** Rule Health no longer folds a staging and production pair into one "Migrated" card. The State filter is now **Live**, **SIEM offline** or **Deprecated**, and validating or editing a rule refreshes only that copy's card.
- **Delete rule removes the rule from TIDE straight away**, and a sync brings it back if it is still in Elastic. Tick **Also delete it from Elastic** to remove it from the SIEM too; only that asks you to confirm, and if Elastic refuses, nothing is deleted. Sync and Delete are no longer in the Edit rule form.
- **Editing a rule changes only that rule**, never a rule it is linked to; bring them back in line with Merge. Deleting a rule also removes its links.
- **Arrange the rule window.** The **…** menu in its header shows or hides each section, sections can be dragged to any column, and the layout is remembered until **Reset layout**. The technique window works the same way.
- **The rule and technique windows look alike.** "Recent activity" is now **History**, mapped rules, linked rules and gaps share one card style, destinations show as tags in their colour, and Delete is now **Delete rule**.
- **A system's page has been rebuilt.** The header's **…** menu holds Edit system and Export report. A metric strip summarises the whole system, and the **Baselines**, **Devices** and **Heatmap** sections collapse and reorder, remembered per browser.
  - The Baselines section has its own **…** menu (Manage baselines, Add technique, Generate baselines, SIEM coverage) and a filter bar: search, baseline, tactic (kill-chain order or A–Z), coverage, name, group by, and cards or table. Your choices are kept in the address bar, so a refresh or shared link shows the same view.
  - Each technique shows its coverage as a coloured label, and each group heading shows its coverage, such as "7/10 covered (70%)".
- **Baselines are now templates, and each system has its own copy.** Applying a template copies its techniques to the system; changing a system's copy never changes the template or another system, and changing a template never changes an existing copy. A template can be applied to a system more than once.
  - Manage a system's baselines from its page: apply, rename, remove, or start an empty one with **Add baseline**. **Generate baselines** creates baselines of the system's own.
  - The Baselines page and dashboard count and score the systems' own baselines, and a template's report describes the template alone.
  - On upgrade, each system keeps its own copy of its baselines with their mappings, known gaps and history. Rule mappings on a template no system used are not carried over, so keep a copy of the data folder if you may want them back.
  - A system's baselines always move with it to another client.
- **Adding or editing a technique picks ATT&CK techniques the way the rule form does**: a tactic, then a technique, as many as needed, shown as pills with their names.
- **A mapped rule records which destination it means.** The Add SIEM Rule list shows each copy with its destination's name and colour, and the mapping keeps the one you picked, with who and when. Existing mappings are matched to their destination on upgrade wherever TIDE can tell.
- **A known gap or N/A decides a technique's status, even with a rule mapped.** Not applicable comes first, then known gap, then covered, then no coverage.
- **"Step" is now "technique"** throughout, including reports.
- **The ATT&CK technique side panel matches the rule and technique windows**, with badges for coverage, tactics and platforms and one line per related item.
- **Confirmation prompts open in TIDE's own window**, with the destructive choice marked. Cancel is focused, and Esc cancels.

### Removed

- **Coverage Quests.** Map rules from each technique's window on the system's page.
- **The separate page for each baseline technique.** Templates are edited on the Baselines page, and a system's techniques in their window.
- **"Also move associated baselines" when moving a system to another client.** Its baselines always go with it.
- **Snapshot all and the Audit History tab on a system's page.** The technique history records every change instead. Existing snapshots are kept and still appear in the system report.
- **Merge rule ID in the Edit rule form.** Link the two rules and use Compare and Merge instead. Find duplicate rules is unaffected.
- **Archive in TIDE.** Sync already marks a rule deprecated once it is gone from Elastic.

### Fixed

- **Some ATT&CK techniques were missing from tactic lists** when writing a rule or picking a technique. A technique with several tactics was only offered under the first; for example, T1078 Valid Accounts was missing from Initial Access.
- **Users who could only view systems could add, edit or remove known gaps and N/A marks.** This now needs permission to edit Systems.
- **Removing a rule from a baseline, or deleting a technique, baseline or system, left orphaned records behind.** They are now removed with it.
- **In the Add SIEM Rule list, clicking a rule's MITRE tag didn't select the rule.** The whole row now selects it.
- **A technique with no rule mapped could show a green tag, as if covered**, whenever any rule in the client mentioned its ATT&CK technique. The tag is now a plain label, the technique's own rule count is always shown, and matching rules elsewhere show as "N to consider".
- **Bulk edit's progress showed rule ids instead of names.** Rules are now named throughout, including in failures.
- **Red and amber notifications were unreadable, and could appear behind an open window.** They are now styled and always in front.
- **Merge rule failed the first time two rules were merged**, with "Both rules must exist in their selected SIEM and space".
- **Filtering Rule Health by SIEM could show rules from other states or other SIEMs.** The SIEM and State filters now work together on every page, and two SIEMs with a space of the same name are separate choices.
- **Deleting a rule left its window open** on a rule that no longer existed. The window now closes and Rule Health refreshes.
- **The rule window showed the rule's id twice.**
- **The rule window's History controls moved when its filters wrapped onto a second line.**
- **Mapping and Field type scored rules with half-mapped fields as fully mapped.** Both are now scored per field and index pattern, and an index pattern that matches nothing counts as not found. Scores update on the next sync.
- **The rule window flashed when stepping to the next or previous rule.**
- **Compare ran changed words together**, dropping the spaces between them (for example "additionofanewmember").

## [5.1.3] - 2026-09-22

### Changed
- **Promoting, demoting, restoring, choosing a master copy, deploying a Sigma rule, and bulk edit no longer re-sync the whole client afterwards.** Each of those already knows exactly which rule it just changed in Elastic, so it now refreshes only that one row (the same lightweight check "Sync this rule" uses) instead of re-fetching and re-scoring every rule in every linked space. A deliberate full sync — the Sync button, or a scheduled run — is unaffected. On a large ruleset this removes most of the "continuously running" full syncs a busy day of promotions used to cause.
- **A rule is now identified by the id Elastic itself guarantees is unique, not by Kibana's internal per-space id.** The two used to differ, quietly, and were both called "the rule's id" in different parts of TIDE — the internal id is generated fresh whenever a rule is recreated rather than updated in place, which is what let the duplicate bug below happen at all. Every tenant's rules are re-keyed onto the Elastic id automatically, once, the first time this version starts (any duplicates found in the process are resolved the same way the new Find duplicate rules tool does). Staging/production pairs, baseline links and validation dates all carry across unaffected — a promoted rule already tracks its pairing this way, by id, regardless of what either side's id is.

### Added
- **Find duplicate rules, from Rule Health.** The "&hellip;" menu can find rules TIDE has stored more than once — they always share a validated date, since validation follows Elastic's own rule id and that is identical across the copies. Pick which row to keep in each group, or mark it as not a duplicate; merging moves any baseline links to the kept row and removes the others from TIDE's database only, nothing in Elastic is touched. The rule window also now shows the rule's id (TIDE's own row id and Elastic's own id, when they differ), under MITRE ATT&CK, collapsible and reorderable like the other sections.

## [5.1.2] - 2026-09-22

### Fixed
- **Sync could wrongly mark live rules as deprecated on tenants with a few hundred rules or more.** Rules are fetched a page at a time; if a rule appeared on two pages while another fell through the gap between them, the total row count still looked complete even though a real rule was missing, and that rule was then marked deprecated (a direct "Sync this rule" always found it, since that path never paginates). Sync now keeps fetching until every rule Kibana advertised has actually been seen at least once, and never reconciles a space unless that is confirmed — a rule that was genuinely deleted may now take one extra sync to be marked deprecated, which is the safer side to land on.
- **A rule recreated in Kibana instead of updated in place could end up stored twice (or more) in TIDE.** Kibana's own uniqueness guarantee is on a rule's portable id, not on the internal id TIDE stores each row under; if a rule was ever recreated (a retried promotion, or similar) rather than updated, the old row was never removed, both copies showed as Production, and neither could safely be bulk-deleted. Every sync now recognises when a rule it just fetched shares its portable id with an old row under a different stored id, and folds the old one in automatically. The new Find duplicate rules tool cleans up any that already exist.
- **Promoting a rule could create a duplicate in the target SIEM instead of updating the existing copy, on a target space with more rules than fit on one page.** Checking whether the target already had the rule fetched every rule in that space to look; on a large space that carries the same pagination risk as the sync fix above, and separately, checking by name alone (the fallback when that check found nothing) only ever looked at the first page of search results. Promotion now checks by looking the rule up directly by its own id, which is neither paginated nor size-limited.

## [5.1.1] - 2026-09-22

### Added
- **Bulk edit on Rule Health.** Select several rules (a checkbox on each card or table row, shown only while Bulk edit is on) and validate, enable, disable, promote or demote them together, with a progress bar and a Stop button. Select all matching the current filters, not just the loaded page — filter to staging and select all, and only staging rules are picked. Promote is only offered when every selected rule is staging, and demote only when every one is production; the bar explains why otherwise. Promote follows the client's "delete source after promotion" setting from Management; demote never deletes the production copy by default. This shipped in 5.1.0 but was missed from that changelog entry.
- **Import a validation file from Rule Health.** The "&hellip;" menu has an Import validation file option that takes a `checkedRule.json`-shaped file and applies it to the active client, matching by rule name. By default it only fills rules with no validation yet, the same as the automatic startup import; tick Overwrite to also replace existing validation dates. An optional Checked by field records the import under one name instead of whatever is in the file. This is a manual, repeatable version of the one-time import that already runs at startup — that one is unchanged.

## [5.1.0] - 2026-09-21

### Changed
- **Rule scoring has a new, fairer model (version 2), and scores are now a percentage.** Field mapping is scored per field, and a field counts if any of the rule's indexes has it. Text inside quotes, such as Windows paths, web addresses and times, is no longer mistaken for a field, and fields used inside EQL functions and sequence keys are now checked. Rules whose indexes can't be reached are no longer marked down, and checks that can't be judged (such as search time for a rule that has never run) are left out. Search time uses the median of recent runs, the investigation guide is scored on length, more field types are recognised, tactics and techniques are one MITRE check, and highlighted fields and the timestamp override are checked against the mapping. The query language can be scored but is off by default. The rule window shows the model version, hover any score to see how it is worked out, and the score chart marks where the model or the weights changed. Expect scores to move on the next sync.
- **Set how many points each scoring check is worth, per client.** On a client's page, under Linked SIEMs, the new collapsible Rule scoring section lets you give each check its own points, or set it to 0 to switch it off. Checks set to 0 don't appear in the rule window. Eleven extra checks are available and start at 0: query language, last execution result, schedule coverage, enabled, freshness, description, references, known false positives, tags, setup guide and alert suppression. A rule's score is the percentage of the allocated points it earns, so the points don't need to add up to 100. Saving re-scores that client's rules straight away, and Reset returns to the defaults.
- **Field mapping checks are faster and more accurate.** TIDE now remembers each SIEM's index mappings for 24 hours instead of asking Elastic on every sync, and checks every index a pattern matches rather than only the newest one. Rule Health's Full mapping sync refreshes them on demand.
- **Sync a single rule.** The rule window has a Sync this rule button that re-checks just that rule against its SIEM, refreshes its index mappings and re-scores it in about a second, without syncing every rule. If the SIEM can't be reached, nothing changes.
- **Rule Health cards are cleaner and four to a row.** Each card shows the rule name with the SIEM at top right and the MITRE techniques beneath it, a score ring under the name, and severity and the rule's state (Production, Staging, Migrated or Deprecated) stacked under the MITRE techniques, and the validation status (bottom left, hover for the date) with the author (bottom right). The card's left edge is coloured by validation status (green valid, amber due soon, red expired, grey never). Validate, Logic and Kibana moved into the detail window, and the severity badge has a softer glow.
- **New table view for Rule Health.** Switch between cards and a full-width table with columns for score, rule, SIEM, state, severity, validated, author, MITRE and language. Click any column header except MITRE to sort by it. Your view choice is remembered.
- **Migrated and Deprecated rules are now flagged** on cards, table rows and the detail window (a rule in both staging and production is Migrated; in neither is Deprecated). Production-only and Staging-only rules are identified by their SIEM. The State filter lists all four states, and filtering or sorting by state is much faster.
- **New rule detail window.** Click any rule to see its description, schedule, index patterns and tags, the highlighted logic, investigation guide, references, field mappings, a score breakdown with bars, its MITRE techniques by name (click one to open the technique panel), and a score-over-time chart with validation and edit markers. Validate, Edit, Test, View in Kibana, Promote and Compare versions are here. Use the arrows (or the left and right keys) to move through the list without closing (the window is a compact fixed size for every rule, so the arrows stay under your mouse), the Field mappings table keeps its header in view as you scroll, show or hide the history column from the header, and collapse or reorder any section with the section controls (activity, score chart, logic, actions and MITRE included, all with the same header). Esc closes the window and returns you to the rule. Your history choice, section order and which sections are open are remembered.
- **Rule windows now show a loading placeholder** while they open, instead of nothing on screen.
- **The MITRE technique side panel shows the same rule cards as Rule Health**, and clicking one opens the same detail window. Production rules are listed first, enabled ones before disabled.
- **Cancelling or closing Edit Rule returns to the rule detail window**, and the edit form now matches the new look.
- **Interface colours are now managed in the shared stylesheet.** Backgrounds previously set page-by-page now come from one place, so colours stay consistent across pages. No change to how pages look.

- **Promotion now lives in the rule window, and the Promotion page is gone.** Open a staging-only rule and choose Promote, then confirm whether to delete the source rule (it starts from the client's default setting). The Promotion menu item and home card are removed, and old `/promotion` links go to Rule Health.
- **Compare a migrated rule's staging and production copies.** Migrated rules have a Compare versions button in the rule window. It shows only the fields worth reviewing (description, query, severity, tags, MITRE techniques, filters and so on), ignores scores and run details, and highlights the exact words that changed. Switch between inline and side-by-side views; your choice is remembered.
<!-- - **Pages that don't exist now show a "Page Not Found" screen** with a link home, instead of a bare error. -->
- **ATT&CK, NIST 800-53 and the Sigma library now ship as one read-only file inside the image.** They are no longer copied into every client's database, so client databases are smaller and the bundled data updates with the image. Nothing changes on screen.
- **Leftover client data in the main database is removed on first start.** Since each client got its own database, the main `tide.duckdb` has held stale copies of systems, hosts, playbooks, software and similar tables. They are now dropped, and custom classifications that existed only there are copied to their client first. There is no undo, so keep a copy of the data folder from before you upgrade.
- **Rule log exports now list each client's rules separately.** Every entry carries `tenant` and `client_id`, and a rule shared by several clients appears once per client with that client's own score and validation, instead of the first client's values.
- **Moving TIDE to new hardware is now documented and checked.** The README has the steps, and a new verification command records file checksums and row counts on the old host and confirms the copy on the new one.
- **Demote a rule back to staging.** Rules that exist only in production now have a Demote button in the rule window, the reverse of Promote. It copies the rule to the client's staging space and keeps the production rule live, so nothing is removed by accident. Tick Delete the production copy in the confirmation to move it instead.
- **Bulk promote.** A Bulk promote button on Rule Health promotes every staging rule that matches the current filters, with a progress bar and a Stop button. Choose how validation is treated: keep each rule's current validation (for moving between SIEMs), mark every promoted rule as validated now, or mark only the rules that never were. You can also promote only rules that are validated in date, and choose whether to delete each rule from the source SIEM. Promoting a single rule still marks it as validated.
- **Switch a linked SIEM between Production and Staging.** Each linked SIEM on a client's page has a Switch button that changes its role in place. Unlinking and re-linking removes the SIEM's rules until the next sync; switching keeps every rule, score and validation. Use it to make an old SIEM Staging before linking a new one as Production. Rules keep the right state afterwards: earlier promotion records that no longer match the SIEM roles are ignored, so rules don't show as Deprecated.
- **Cleaned up unused files.** The empty sync-state folder and two obsolete one-off migration scripts are gone, and the data folder no longer needs a separate validation file.

### Fixed
- **The Validated count on Rule Health is now green.** It was red whenever fewer than half the rules had been validated, which made a good number look like a warning. Due-soon and expired counts keep their colours.
- **The MITRE technique side panel no longer shows a broken loading indicator** while its detection rules load.
- **Sorting Rule Health by validation date now works.** Newest to oldest and oldest to newest both put dated rules in the right order, with never-validated rules always at the end instead of first.
- **A rule promoted with Delete source no longer shows twice.** It appeared as a Deprecated staging card next to its Production card, which also inflated Total Rules and Validated. The pair now shows once, and earlier ones are repaired automatically.
- **The SIEM counts on Rule Health now count every rule in each SIEM.** Promoting a rule no longer lowers the Staging count, because the rule is still in staging; Total Rules still counts a promoted pair once, as the grid shows it.
- **Rule validations are now kept per client and follow the rule.** Validating a rule for one client no longer marks a rule with the same name as validated for another. A validation belongs to the rule's own Kibana rule ID (the name is kept for readability), which stays the same when a rule is promoted or copied to another space or SIEM, so a promoted rule is validated exactly like its source, and renaming a rule no longer loses it. Existing validations are imported the first time this version starts (any for rules that are not in a client's list yet go to the default client, so none are lost), and the old `checkedRule.json` is renamed `checkedRule.json.imported` and can be deleted.
- **MITRE technique pills no longer say "Gap" when hovered, on every page.** They now show the technique ID and name, for example "T1059 - Command and Scripting Interpreter".
- **Searching Rule Health now lists rules whose name matches first.** A short search such as "111" previously buried the rule with that name among rules whose IDs happened to contain it.
- **Rule Health filters and view now stay in the address bar.** Refreshing the page or sharing the link restores the search, filters, sort order and cards or table view, which the address bar previously dropped.
- **Rule Health, Promotion and other pages now load much faster.** For a tenant with about 1,700 rules the rule list dropped from around 12 seconds to under 2, and pages across the app render more quickly.
- **Syncing rules from Elastic is roughly twice as fast** for large rule sets.
- **Rule history no longer fills with false "MITRE techniques changed" entries.** Techniques returned in a different order were being logged as edits on every sync. Elastic creation and edit history now also appears on the rule it belongs to.
- **The Sigma library index now builds correctly at startup.** It previously failed with a database error and was never refreshed.
- **Missing icons now appear.** The Edit Rule heading, the Pattern type card on CTI Indicators, and the Attachments heading on CTI Reports previously showed blank space where an icon should be.
- **CTI and MITRE page access now follows Role Templates.** CTI Indicators, Actors and Reports, and the MITRE Software, Campaigns and Mitigations pages now respect their own read permission instead of being open to any signed-in user or governed only by the broader MITRE permission.

## [5.0.18] - 2026-09-18

### Changed
- **Rule Health and Promotion now load rules continuously as operators scroll.** Statistics and search, sort, and filter controls remain fixed while the rule cards scroll independently.

### Fixed
- **Promotion statistics now reflect the active filters.** Counts stay aligned with the staging rules shown, including migrated rules, without including deprecated copies from non-staging SIEM mappings.
- **Promotion score and validation sorting now follows the selected direction.** Sorting remains correct when lifecycle or validation filters require the staging rule list to be processed before display.
- **Per-client user roles now remain stable after Keycloak sign-in.** TIDE-managed role changes are no longer replaced by the user's initial Keycloak role, and role editors show and update only the active client's assignment.
- **Rule sync and promotion permissions now fail cleanly when access is denied.** Read permissions control page visibility, write permissions control page actions, and an administrator role in one client no longer grants actions in another client.

## [5.0.17] - 2026-09-17

### Added
- **Rule Health stats cards now reflect the active filters.** Total rules, enabled/disabled, validation, quality, and severity counts update to match the current search, SIEM, status, state, score, and validated-date filters instead of always showing the whole tenant's totals.
- **Rule Health filters and pagination now survive a page refresh.** Reopening or reloading the page restores the last-applied filters instead of resetting to the unfiltered view, and moving between result pages scrolls back to the top of the list.

### Fixed
- **Validating a rule no longer reverts the stats cards to unfiltered totals.** The metrics refresh triggered by a validation now keeps the currently applied filters.
- **Rule Health stats no longer overcount rules that have both a staging and production copy.** Counts now match the number of cards actually shown, instead of counting each linked copy separately.
- **The Validated stats card no longer counts rules that are due for revalidation as validated.** It now only counts rules that are currently in-policy, with a new "due soon" figure alongside expired and never-validated counts.
- **Rule Health pagination and sorting are now correct across multiple pages.** Linked staging/production rule pairs are now collapsed to a single card before pages are built, so a pair can no longer be split across two pages and double-counted, the "Page X of Y" total now matches the stats cards, and sorting by score or validation date is now applied across the whole result set instead of only within each page.

## [5.0.16] - 2026-09-16

### Fixed
- **Rule validation now completes and refreshes the Rule Health card.** Operators no longer see an error after validating a rule.

## [5.0.15] - 2026-09-15

### Changed
- **Technique detail panels now open at a smaller width and can be resized.** Operators can drag the panel edge to choose a comfortable width, and TIDE remembers that preference for the signed-in user.
- **Rule Health cards now give MITRE pills more space.** Only migrated or deprecated lifecycle states are shown on the card, while MITRE technique pills wrap cleanly instead of being clipped on the right side.
- **Expandable sidebar headings now render without divider lines.** The grouped navigation titles look cleaner whether the sidebar is expanded or collapsed.

## [5.0.14] - 2026-09-14

### Fixed
- **Deleting a promoted rule from production no longer leaves a duplicate card.** Rule Health showed both a `Deprecated` card and a `Staging` card for the same rule when only the production copy was removed; it now correctly collapses to the one live copy, matching the existing behavior when the staging copy is removed instead.

## [5.0.13] - 2026-09-14

### Added
- **Missing SIEM rules are now retained as deprecated records.** Rules that are absent after a successful sync remain visible with a grey `Deprecated` label so baseline links and migration history are preserved; they become active again when they reappear.
- **Baselines and system configurations can be transferred as JSON.** Operators can export a baseline with its mapped rules or export the tenant system configuration, then import baseline copies with their original rule identities retained for replacement mapping.
- **Rule migration actions are available in Edit Rule.** Operators can target-sync one rule, archive or delete it from TIDE, and move baseline references from an imported rule to its replacement in another SIEM and space.
- **System configuration JSON exports now download and can be imported.** The Systems export dialog keeps PDF and Markdown reports and adds TIDE JSON for moving systems, baseline copies, assignments, and rule migration data between installations.
- **Promotion now tracks copied rules across staging and production.** TIDE records the destination rule ID, derives `Staging`, `Migrated`, `Production`, or `Deprecated` lifecycle states, supports retaining the source rule, and lets operators compare versions and choose the master rule.
- **Copy-only promotion now waits for sync reconciliation without deprecating the destination copy.** Generated Elastic IDs are retained correctly, so a successfully copied rule shows `Migrated` while the staging source remains available.
- **Rule Health no longer renders stale source-ID aliases as duplicate rules.** Cross-SIEM copies now reconcile to their real Elastic IDs while legitimate same-name rules in different SIEM spaces remain distinct.
- **Migrated rules now appear as one Rule Health card.** The card uses the production master’s enabled state and remains marked `Migrated`, while the Promotion page continues to show the staging copy for operator workflow.
- **Existing staging/production pairs are now linked when the match is unambiguous.** Rule Health collapses them to one production-master card; duplicate names with multiple possible matches remain separate for explicit operator mapping.
- **Promotion now respects the active Keep source selection.** The source rule is deleted by default when the client setting is enabled, while checking Keep source reliably preserves it.
- **Client promotion settings are easier to read.** The source-deletion default now appears directly beneath Validation mode instead of beside the other validation controls.
- **Deprecated rules can now be restored from Edit Rule.** Restore recreates the rule in the selected replacement SIEM/space, captures its new Elastic ID, and re-links the baseline references while retaining the old TIDE record for migration history.
- **Restored rules now replace their old TIDE identity.** After recreation in Elastic, TIDE moves baseline references to the new rule ID and removes the old SIEM-scope cache row instead of creating a migration pair.
- **Baseline rule remapping is now an explicit Merge rule action.** Merging creates one logical TIDE identity, moves all baseline links to the selected master rule, and requires both rule IDs to exist in their selected SIEM/space scopes.
- **Imported baseline rules now preserve their original Elastic IDs.** TIDE can associate those IDs with newly discovered SIEM copies through the logical merge workflow without changing the baseline’s stable identity.
- **Existing tenants now receive logical rule identity tables during startup.** Rule Health no longer fails while older tenant databases are upgraded to support baseline rule merging.
- **Baseline and system JSON transfers now support selectable content.** Operators can include or omit mapped rules, baselines, and hosts/software; imported baselines are assigned to imported systems, duplicate names can create copies or override existing records, and older tenant schemas are repaired before baseline detections are imported.
- **System migration export/import now lives on the Systems page.** Operators select the systems to export and choose baselines, mapped rules, or hosts/software; system detail keeps its existing report export only, and imports assign included baselines to imported systems.
- **Imported systems and baselines now keep their original names unless the target tenant already has that name.** Baseline, Applied Systems, and Coverage Quest detection lists now show rule names while retaining rule IDs as the stored reference, and JSON transfers preserve the display label when rules move between clients.
- **Rule editing now follows the rule lifecycle.** Normal rules update their current SIEM scope, migrated rules update both recorded copies with a partial-update warning when one side fails, and deprecated rules update TIDE only so restored content is available for the next Elastic recreation.
- **Merged logical rules now synchronize edits across every member copy.** Rule edits use logical identity membership as well as legacy migration records, so both staging and production copies receive the change or return a clear partial-update error.
- **Migrated rule edits now use each member’s Elastic `rule_id`.** This prevents the saved-object ID from being sent to the update endpoint and makes any remaining partial failure identify the exact SIEM, space, and target ID.
- **Editing either side of a migrated rule now updates both members.** Opening the production master no longer skips the staging copy; both scopes are updated and any one-sided failure is reported explicitly.
- **Field mapping scores no longer count query comments as fields.** `//` and `/* */` comments in KQL, Lucene, EQL, and ES|QL queries are now ignored when detecting field references, so annotated queries score accurately.
- **Rules built on a Kibana data view now carry a portable index list.** TIDE resolves the underlying index pattern when a rule is synced, so promoting the rule to another space no longer leaves it pointing at a data view that doesn't exist there.
- **Rule Health filters have been reworked for clarity.** Criticality sorting is replaced by a State checklist (Production, Staging, Migrated, Deprecated); Score and Validate now support min/max and date-range filtering alongside their sort direction; and only the most recently changed sort (Score, Validate, or Name) is applied at a time, instead of silently stacking with the others.
- **Creating an EQL or ES|QL rule in TIDE no longer fails.** The rule type is now derived from the selected query language instead of always submitting a KQL-only rule type, so EQL and ES|QL rules save successfully.
- **Rule Health's Score and Validate filters are now single-line dropdowns.** Each combines its sort direction with its range filter (score min/max, validated date range) behind one control instead of stacking extra rows in the filter bar; the same layout has been applied to the Promotion page, which also gains Score, Validate, and Name filtering to match Rule Health.
- **Filter dropdown panels (State, Score, Validate) now render with a solid background.** They previously used an undefined style token that left the panel transparent, making the options hard to read against the page behind them.
- **Validate sort now actually reorders Rule Health results.** Rules linked across staging and production were swapped for their counterpart after sorting, which could carry a different validation date and silently undo the requested order; the sort is now re-applied after that swap.
- **Promotion now has the same State filter as Rule Health.** Staging rules can be filtered by Production, Staging, Migrated, or Deprecated state, matching the Rule Health filter bar.

## [5.0.12] - 2026-08-11

### Changed
- **MITRE detail pages now use a compact Source selector container.** Technique, Group, Software, Mitigation, and Campaign detail pages no longer render the oversized filter-box wrapper when only the Source dropdown is present.
- **Rule Health cards now keep titles stable when many MITRE techniques are mapped.** Technique pills are now capped on the card with a `+N` indicator so long technique sets no longer push the rule title or SIEM/severity pills out of layout.
- **Rule history modal header is now clean and consistent.** The duplicate rule title and extra `Rule History` subtitle were removed, and severity/scope pills now match the front-card color treatment.
- **MITRE accordion interactions are now consistent across pages.** Clicking a card still expands it, while clicking a title link inside a card now navigates without unintentionally toggling expansion.
- **Technique detail sub-techniques and procedure examples now follow card-first expansion behavior.** Clicking each sub-card expands to reveal description content, while clicking the item title still opens its full detail page.
- **Rule history modal header layout now better matches operator workflow.** Severity and SIEM pills now sit directly under the rule title, and the Edit action is aligned to the top-right under the modal close control.
- **Technique detail Software and NIST capability rows now use the same interaction model as the rest of MITRE cards.** Clicking each row expands inline details, while clicking the row title navigates to the corresponding detail page.
- **Technique detail Sigma rows now follow the same card-title interaction pattern.** Sigma rows expand on card click, and the Sigma rule title now opens the targeted Sigma workflow route directly.
- **All-source Tactics group cards now expose a direct title navigation path.** Clicking a grouped tactic title now opens the corresponding Techniques filter view while preserving card expand/collapse behavior.
- **Technique sidebar modal cards now use the same interaction contract as MITRE detail cards.** Related entity rows now keep IDs/status as non-navigation labels and move navigation to the row title link so card click remains expand/collapse.
- **Detection Rules remains the single intentional sidebar outlier.** It continues to act as the dedicated coverage/results section rather than a title-link relation card.

## [5.0.11] - 2026-08-10

### Added
- **Threat-baseline techniques now include ATT&CK procedure context when available.** Baselines created from Threat Landscape actor selections now populate each matching technique with the selected actor's ATT&CK group-technique procedure description, including citation text and internal MITRE links where provided by ATT&CK data.


## [5.0.10] - 2026-08-07

### Changed
- **Rule History modal now uses one unified timeline with compact accordion cards.** The previous Table/Activity/Scores tabs were replaced with a single Rule History stream that starts collapsed and supports inline expansion for score breakdowns and edit context.
- **Rule History filtering now follows analyst workflow order.** The modal now presents Date, Action, and User controls together at the top so operators can quickly isolate Score, Validation, or Edits records without switching views.
- **Rule History score expansions now use a three-panel operator layout.** Score entries now open into dedicated Quality Scores, Meta Scores, and Rule Score panels with progress bars and per-metric totals for faster audit review.
- **Technique-to-Sigma navigation now preloads without auto-convert modal behavior.** Clicking related Sigma entries in the technique panel now navigates to Sigma with the target rule preloaded into `rule.yml`, while conversion remains a manual operator action.
- **Sigma rule selection highlighting is now consistent for deep links and manual clicks.** The selected Sigma row now uses the blue highlight styling whether it is preselected from technique navigation or selected directly in the Sigma rule list.
- **Technique relationship sections now use compact expandable rows with smaller ID/status columns.** Groups, Campaigns, Software & Tools, Mitigations, Procedure Examples, NIST capabilities, and Sigma relationship rows now share the same compact collapsed height and expand inline to reveal descriptions with wrapped titles.
- **Technique side-panel cards now use accordion behavior.** Top-level cards in the technique side panel are now single-open, so opening one section closes the others for cleaner scanning.
- **Inner relationship rows now use accordion behavior per section.** Expandable rows inside each side-panel card now single-open within their own section to reduce visual clutter.
- **Technique side-panel headings now support direct page navigation.** The technique title now links directly to its MITRE technique page; MITRE/Sigma action buttons were removed, and Group/Campaign/NIST/Sigma card headings now navigate to their corresponding pages while keeping card expand/collapse behavior.
- **All requested MITRE side-panel headings now link to their list pages.** Sub-techniques, Groups, Software & Tools, Campaigns, Mitigations, and NIST headings now provide direct navigation links while preserving in-card expand/collapse.
- **Sigma browser cards now use consistent corner rounding.** Expandable and non-expandable Sigma rule rows now share unified rounded card edges.
- **MITRE technique detail pages now include an inline Sigma Rules section.** Operators can now review related Sigma rules directly on `/mitre/technique/{id}` pages using the same rule content and coverage styling as the side panel.

### Fixed
- **Rule score history no longer appends duplicate snapshots on unchanged syncs.** During sync, TIDE now compares each rule's latest stored score payload with the new payload and only writes a new score-history record when there is an actual score delta.
- **Elastic-sync edit events now retain field-level diffs and consistent attribution.** Automated sync edits now record changed fields with before/after values and are attributed to `elastic` so user history no longer splits between sync activity and operator actions.
- **Sigma workbench no longer shows duplicate raw YAML alongside the editor.** The plain `rule.yml` textarea is now hidden in the UI so only the CodeMirror editor is visible.
- **Technique Description card now matches compact section heights.** The Description section now uses the same collapsed card sizing structure as other technique relationship cards.
- **MITRE technique pages no longer 500 when Sigma rule storage is unavailable.** The new Sigma section now degrades safely when `detection_rules` is absent and skips rule-list loading unless rules are present.
- **MITRE technique Sigma counts now match the side panel.** The technique detail page now sources Sigma rules from the same Sigma catalog query as the slide panel, so totals and listed related Sigma rules stay consistent.

## [5.0.9] - 2026-08-06

### Added
- **Technique detail relationship coverage expanded.** Technique detail pages now include a dedicated **Campaigns Using This Technique** section and campaign data in the related-entity model.
- **Heatmap technique popup metadata and procedures.** The popup now includes a **Data Sources** line and a dedicated **Procedure Examples** card fed from MITRE use descriptions.
- **Offline NIST mappings-explorer support.** TIDE now bakes the NIST 800-53 mappings-explorer JSON into the image at build time, adds a new MITRE NIST section with list and detail pages, and surfaces NIST capabilities on technique detail pages.

### Changed
- **MITRE section headers now include counts across pages.** Collapsible relationship sections now display item totals consistently across MITRE detail/list experiences (techniques, groups, software, campaigns, mitigations, tactics, and unmapped sub-techniques).
- **Technique totals are now consistent between views.** The MITRE technique detail header/summary totals were aligned with popup/entity counts so related-entity numbers match across pages.
- **MITRE pages now use explicit breadcrumb trails and standard page header layout.** MITRE list/detail pages now follow the shared breadcrumb and title/subtitle spacing pattern used across TIDE.
- **MITRE page access is now explicitly permissioned in Role Templates.** MITRE routes now map to dedicated page resources instead of a shared fallback, so tenant admins can manage MITRE page access directly in the role matrix.
- **Systems and baseline pages now follow the unified investigation layout.** Systems, system detail, and baseline technique views now share the same breadcrumb, details panel, filter bar, and collapsible entity-card structure for more consistent navigation and scanning.
- **Systems and baseline card polish now matches MITRE card grammar more closely.** Collapsed system/device rows are now single-line without secondary status text, baseline tactic headers render MITRE tactic IDs (for example TA0001) instead of generic labels, and the baseline header action cluster keeps Start coverage quest visibly aligned with peer actions.
- **System baseline coverage nesting and inventory header alignment were tightened.** System detail baseline coverage removed the third nested card level by flattening step rows into a single compact layer, and Systems/System Detail/Baseline pages now share consistent top-right Details panel sizing and alignment behavior.
- **System detail baseline view now mirrors MITRE list structure more closely.** Removed tactic-level nested card containers entirely from System Detail baseline coverage so each baseline expands to one flat technique-row list with consistent row grammar.
- **Generate Baselines no longer 500s when Sigma index is absent.** The generator now detects missing `sigma_rules_index`, returns an empty catalog safely, and shows a clear modal empty state with Preview disabled instead of raising a server error.
- **System detail baseline hierarchy and visuals refined for consistency.** Baseline cards no longer show a default blue left accent, techniques are grouped under plain collapsible tactic headings (MITRE order), technique cards use left-edge status color (green/red/amber/grey), status text pills were removed, and page-level Expand all / Collapse all controls were removed while per-card collapse memory remains active.
- **Sigma rule browser cards now match the shared list-card style and prioritise rule status.** Rule cards now show MITRE technique pills on the left, the rule title in the center, and Sigma rule status on the right, and the list is ordered by status priority (`stable`, `test`, `experimental`, `deprecated`, `unsupported`) to keep operationally-ready rules at the top.
- **Sigma rule cards now stay single-line until expanded.** Collapsed rows now show one MITRE pill plus a `+N` counter, status is rendered as colored text (no pill), and clicking a row expands the card to show all MITRE pills stacked vertically.
- **Sigma rule browser now includes a status filter and inline technique expansion.** Operators can now filter Sigma rules by status, and expanded rows reveal additional MITRE pills directly under the first pill while keeping the collapsed row to a strict one-line height.
- **Sigma card expansion now behaves as a single-open accordion.** Only rules with more than one MITRE pill are expandable, one expanded rule closes the others, and single-pill or no-pill rows remain fixed-height without title shift.
- **Expanded Sigma rows now hide the collapsed `+N` counter.** When a rule is opened, the stacked MITRE pills are shown directly and the collapsed counter is removed to reduce duplicate technique indicators.
- **Technique detail cards now include Sigma catalog context with cleaner related rows.** The technique panel now includes a Sigma Rules card for the selected technique, while Sub-technique and NIST capability rows were simplified to ID + title for faster scanning.
- **Technique relation cards were further flattened for scanability.** Sigma-related rows now use status as the leading identifier instead of Sigma ID, Software/Tools and Procedure Examples now render as single-line ID + title rows, and expandable Sigma cards no longer show the blue left accent.
- **Sigma navigation from technique cards now opens and converts the selected rule directly.** Clicking a Sigma row in the technique panel now keeps the technique filter applied on Sigma and auto-loads + converts that exact Sigma rule; collapsed Sigma rows were also tightened with a smaller left ID column so more title text remains visible.

### Fixed
- **MITRE software visibility on technique detail pages.** Software relationships are now rendered reliably on technique detail pages, including section totals.
- **Procedure example rendering in heatmap popup.** Fixed broken procedure-card markup caused by nested links; procedure entries now render cleanly with proper link behavior and description formatting.
- **Baseline list MITRE behavior and rule isolation.** Baseline list MITRE pills now open the technique side panel reliably, expanded baseline cards preserve their collapse state across navigation/refresh, and technique rule lookups now respect SIEM+space tenant scopes to prevent cross-tenant rule bleed.
- **Baseline and system-baseline MITRE pills now use tenant-scoped rule counts as the colour source.** Pills no longer show green when a tenant has zero visible rules, and badges now display explicit counts (including 0) so colour and count stay aligned with the technique modal.

## [5.0.8] - 2026-08-03

### Fixed
- **MITRE pages fix bundle.** This release resolves source-domain consistency, MITRE pill behavior/alignment, and cross-page MITRE navigation/detail rendering in one grouped update.

## [5.0.7] - 2026-07-30

### Added
- **Offline MITRE ATT&CK knowledge base in TIDE.** TIDE now provides a standalone `/mitre` experience for air-gapped operations with dedicated Tactics, Techniques, and Groups pages plus linked detail pages.
- **Six-page MITRE expansion released as one feature bundle.** Added dedicated list and detail pages for Software, Campaigns, and Mitigations so operators can investigate malware/tools, campaigns, and courses of action directly in TIDE.
- **End-to-end relationship navigation across MITRE entities.** Operators can now move directly between groups, campaigns, tactics, techniques, software, and mitigations through in-page relationship sections and detail links.
- **MITRE relationship sections expanded for analyst workflow.** Group detail now includes campaigns, software, tactics, techniques, and mitigations, and technique detail mitigations now open mitigation detail pages.
- **ATT&CK hyperlinks now resolve internally.** ATT&CK links in descriptions now open the corresponding `/mitre/...` pages (including sub-techniques, software, campaigns, and mitigations) instead of sending analysts to external sites.
- **MITRE data remains build-time and local-only.** All MITRE pages are populated from bundled ATT&CK JSON during startup/rebuild, with source-change detection, and are not dependent on runtime internet access.

## [5.0.6] - 2026-07-29

### Fixed
- **Home page layout** Increase logo size and centered, removed the title.
- **Heatmap page now loads reliably.** Opening Heatmap no longer returns a 500 error when rendering the source filter list.
- **System Details baseline snapshots now complete successfully.** Taking an all-baselines snapshot no longer fails with a 500 error.
- **Client CTI connector panels now load reliably after upgrades.** Tenant CTI databases now self-repair missing egress target type metadata on startup, so linked connector and CTI target sections no longer fail on older tenant data files.
- **Threat Landscape sync now refreshes linked CTI connectors for the active tenant.** Clicking Sync on Threat Landscape now runs MITRE plus the tenant's active linked CTI connectors (including OpenCTI TAXII), so actor coverage updates correctly on upgraded customer environments.
- **Threat Landscape sync no longer times out on long CTI pulls.** Sync now runs as a background job with live polling, so large tenant connector refreshes complete without returning reverse-proxy 504 errors.
- **Threat Landscape sync now targets OpenCTI intrusion sets only.** The Sync action now uses a lightweight OpenCTI GraphQL intrusion-set refresh for linked OpenCTI connectors instead of running full connector backfills, reducing runtime and avoiding long, clumsy CTI paging during threat coverage updates.
- **Disabled APM no longer emits stray warning logs.** When `ELASTIC_APM_ENABLED=false`, TIDE now skips APM label and span helper calls entirely so Elastic APM library warnings do not appear without an active transaction.

## [5.0.5] - 2026-07-13

### Added
- **Elastic RUM.** Integrated Real-time User Monitoring.

## [5.0.4] - 2026-07-10

### Added

- **Optional Elastic APM instrumentation for TIDE.** Operators can now enable Elastic APM tracing with environment-based configuration, while standalone deployments keep it disabled by default.
- **DuckDB spans, tenant labels, and browser RUM tracing.** Query-heavy DuckDB work is now broken out as database spans, active tenant transactions carry tenant labels for Kibana filtering, and the browser shell loads the local Elastic RUM agent for HTMX-driven request tracing.

- **Air-gapped APM defaults are now explicit.** The deployment templates now include APM settings with `ELASTIC_APM_CENTRAL_CONFIG=false` so the agent does not poll Kibana for remote config.
- **TIDE APM endpoint now defaults to container-reachable Fleet intake.** Default APM wiring now uses the internal `fleet:8200` address so telemetry from `tide-app` works without host-loopback overrides.
- **RUM environment now maps from configuration correctly.** Frontend APM initialization now resolves the configured `ELASTIC_APM_ENVIRONMENT` value instead of always falling back when rendering templates.

### Fixed

- **HTMX page navigation now lands in Kibana UX with page-load metrics.** Browser-side APM now preserves UX-compatible `page-load` telemetry for HTMX route changes, and the regression test verifies both the browser intake request and the indexed RUM document shape in Elasticsearch.

## [5.0.3] - 2026-07-02

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
- **Tenant-scoped roles** (Migration 34/35). Granting a user ENGINEER on one client no longer makes them ENGINEER on another. The default tenant for new users is the client they were just assigned to.
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

### Fixed
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

## [1.2.3] - 2026-01-24

### Changed
- Updated README
    - Removed icons

## [1.2.2] - 2026-01-23

### Added
- Add description to each page. 

### Fixed
- Title uniformity

## [1.2.0] - 2026-01-22

### Added
- Search for Threat actors by aliases

### Fixed
- Author not displaying on some cards
- Pills on rule health now full width

## [1.1.6] - 2026-01-21

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
