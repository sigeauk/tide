# Rules

How to keep your detection rules healthy: syncing them from your SIEMs, reading and editing them, validating them, moving them between destinations, and taking updates from Elastic and Sigma. Read [Getting started](GETTING_STARTED.md) first for the controls every page shares.

## Where rules come from

TIDE reads your detection rules from each **SIEM destination** linked to the client: one space of one Elastic SIEM, with a name and colour your administrator chose (for example *DM3-Prod*). The same rule can live at several destinations; each copy is its own rule in TIDE, shown with its destination's tag.

TIDE gives each rule a **score** (0 to 100) for how well it is likely to work: whether its fields exist in the SIEM, how it is written, whether it has an investigation guide and ATT&CK techniques, and so on. Your administrator decides how many points each check is worth for the client.

## Rule Health

**Rule Health** lists every rule of the client, with figures across the top: **Total Rules**, **Enabled**, **Validated**, **Avg Quality**, **Severity** and **Last Synced**.

### Sync rules from your SIEMs

Who can: anyone who can edit Rule Health.

TIDE doesn't fetch rules by itself: sync when you want the latest.

- **Sync** reads every destination linked to the client. Hover over it to sync one destination only, for example **Sync *DM3-Prod* only**.
- **Sync with mappings** also asks each SIEM which fields its indices hold, so the field checks in each rule's score are up to date. It takes longer; use it after index changes.

**Last Synced** shows when the rules were last synced. If a sync failed, only partly finished or was interrupted, it says why and offers **Retry**.

A SIEM that can't be reached is skipped: its rules keep showing, marked **SIEM offline**, until a sync reaches it again.

### Find rules

Filter by **Search** (name, author, ID or ATT&CK technique), **SIEM**, **Status** (enabled or disabled), **State**, **Upstream**, **Score** (with a range) and **Validate** (with a date range), and sort by score, validation date or **Name**. The number beside each choice is how many rules it holds.

**State** is the badge each rule shows:

- **Unlinked**: found at the last sync, with no copy linked in another destination.
- **Linked**: found at the last sync, with a copy linked in another destination.
- **SIEM offline**: its SIEM couldn't be reached at the last sync; shown from TIDE's last copy.
- **Deprecated**: no longer found in the SIEM.

Tick **Unlinked** and **Linked** together for every rule found at the last sync.

The page's **⋮** menu switches between **Show as cards** and **Show as table**. In the table, click a heading to sort by it, drag a column's edge to resize it, and choose which columns show; **Reset table columns** puts them back.

## Rule Monitoring

**Rule Monitoring** lists the rules that need action, grouped by what causes it, so a problem many rules share is one thing to fix. It is as of each destination's last sync: every sync reads what Kibana says about each rule's last run, and checks the rules against the SIEM's indexes and fields.

- **What it finds:** an index pattern that matches no index, indexes missing the rule's timestamp override field (such as `event.ingested`), fields no index has or that have conflicting types, queries Kibana can't parse or Elasticsearch refuses, missing privileges, missed runs, rules sharing a rule id, custom rules using one of Elastic's rule ids, SIEMs that didn't answer, syncs that couldn't read every rule, and destinations not synced for 7 days. Anything else Kibana reports goes under **Other Kibana errors**, in Kibana's words.
- **Who fixes** says who acts: **Data / ingest** (the indexes and pipelines, usually the Elastic engineers), **Rule author** (the rule's query), **Kibana / platform** (the SIEM itself) or **TIDE** (something TIDE can fix, or a sync).
- Each issue opens to its causes, such as an index pattern or a field in a data stream, with how many rules each affects and for how long. Open a cause for its rules; click a rule to open its window.
- Filter by **Search**, **SIEM**, **Severity**, **Who fixes** and **Issue**. **Rules** shows enabled rules, or **Include disabled** for what would fail if they were switched on. **Show** lists what is open, or what was fixed in the last 14 days. **Group by** lists by **Issue**, **Who fixes**, **SIEM / destination** or **Rule**.
- The cards count the rules needing action (beneath: how many of the enabled rules, and any disabled ones counted because of a rule id problem TIDE can fix), errors and warnings (and how many began in the last 7 days, once Rule Monitoring has a week of history; until then, the day it began), the **Things to Fix** by who fixes them, what was **Resolved** in the last 14 days, and when the client was **Last Synced**.
- The page's **⋮** menu holds **Sync**, as on Rule Health; what a sync finds fixed moves to **Resolved recently**.

### Act on a cause

Open a cause for its actions. Anyone who can edit Rule Health can use them.

- **Copy for engineers** gives the cause as Markdown, ready to paste into a ticket or a chat: what is wrong, who fixes it, since when, what to check, Kibana's message and a table of the rules. **⋮ › Copy shown for engineers** does the same for every cause the filters show.
- **Sync these rules** reads the cause's rules again from their SIEM, to see whether it is fixed; for a whole destination, **Sync this destination**.
- **Acknowledge…** mutes a cause you know about, with a note (for example, an index not onboarded yet). It moves to **Acknowledged** at the bottom of the list and isn't counted, until it affects more rules than when it was acknowledged; then it comes back, saying so. **Unmute** puts it back at once.
- Where TIDE can fix it, the rule's row has the fix: **Give it its own rule id** for a custom rule using one of Elastic's rule ids, **Give the copy its own rule id** where Kibana holds a custom copy beside Elastic's rule.

## The rule window

Click a rule to open its window. The header shows its score, destination, state, whether it came from Elastic's or the Sigma rules, severity and author, with **Validate** and the date it was last validated at the top right, and the rest of its actions in the **⋮** menu: **Edit**, **Sync this rule**, **Move**, **Compare**, **View in Kibana**, **Delete rule**, and **Restore** for a deprecated rule.

| Section | What it holds |
|---|---|
| **About this rule** | Its description, risk score, language, indexes and tags |
| **Rule logic** | Its query, highlighted |
| **Investigation guide** | Its guide for analysts, formatted |
| **Last run** | How its last run in Kibana went, how often it runs, how far back it looks, and **Test** |
| **Score breakdown** | Each check, with the points earned out of its maximum; hover a check for how it is judged |
| **Rule score over time** | Its score each day |
| **History** | Edits, validations, moves, merges and syncs, with who and when, filterable |
| **Field mappings** | Each index pattern and field, and whether the SIEM has it |
| **MITRE ATT&CK** | The ATT&CK techniques it carries |
| **Covers** | The baseline techniques it is mapped to, on which systems; click one to open it |
| **Linked** | Its copies at other destinations |
| **Upstream** | Whether Elastic or Sigma has a newer version of the rule it came from |
| **References**, **Rule ID** | Its references, and its IDs |

### Validate a rule

Validating records that someone checked the rule works. Click **Validate** in the rule window: it is marked validated now, by you. As the date ages, the validation turns from current to *due soon* to *expired* (your administrator sets how long each lasts), and the score reflects it.

To record many validations at once, use the page's **⋮ › Import validation file**, with a `checkedRule.json` file. Rules are matched by name. **Checked by** records them all under one name instead of each entry's own.

### Test a rule

In **Last run**, choose a time window in **Test against last** and click **Test**. TIDE runs the rule against that window in Kibana and shows what it would have found. The time it took is recorded as the rule's search time, which counts toward its score.

### Edit a rule

Who can: anyone who can edit Rule Health.

1. In the rule window, choose **⋮ › Edit**.
2. Change what you need. The form is in folding sections: **Define Rule** (query language, index patterns, query), **About Rule** (name, severity, risk score, description, author, tags, timestamp override, MITRE ATT&CK techniques, highlighted fields, investigation guide), **Schedule** (how often it runs, how far back it looks) and **Action** (whether it is enabled).
3. Give a **Reason for change**. Every edit needs one; it is kept in the rule's History.
4. Click **Save**.

Only what you change is sent to Kibana, onto the rule as Kibana holds it at that moment. If someone changed the same field in Kibana since TIDE last synced it, nothing is saved: the form says which field, and TIDE loads Kibana's version so you can check it and make your change again. Editing a rule changes only that copy, never a rule linked to it.

Editing one of Elastic's prebuilt rules keeps it as Elastic's rule, so TIDE still shows when Elastic has an update for it. Kibana marks it as customised. When Elastic's next update for it is installed in Kibana, Kibana merges your change with Elastic's, or replaces it with Elastic's version, depending on your Elastic licence. The form says so above **Save**. Older versions of Kibana refuse changes to prebuilt rules; the form then shows Kibana's reason.

### Create a rule

Use the page's **⋮ › Create rule**. Choose the **Target SIEM / space**, a **Rule name**, the **Query language** and query, then fill in the rest as when editing, and click **Create Rule**. Rules converted from Sigma or deployed from Elastic's library open this same form, filled in (see [Sigma, Elastic & Hunting](LIBRARIES.md)).

### Enable or disable rules

Change **Status** in the rule's **Action** section when editing it, or use bulk edit's **Enable** and **Disable** for several.

## Moving, copying and linking

### Move or copy a rule to another destination

Who can: anyone who can edit Rule Health.

1. In the rule window, choose **⋮ › Move**.
2. Pick the **Target** destination.
3. Leave **Delete source after move** ticked to move the rule, or untick it to copy it. A copy keeps the source live and links the two.
4. Click **Move**.

A true move takes the rule's baseline mappings with it, so the techniques it covers stay covered.

The copy keeps the rule's actions (notifications and the like) only where the target has the same connector, or one of the same type and name. Any it couldn't take are named afterwards, so you can add them to the rule in Kibana.

A rule under one of Elastic's rule ids, such as one of Elastic's prebuilt rules, is copied under a new rule id. Kibana can then still install Elastic's own rule in the target, and TIDE still shows Elastic's updates for the copy.

### When the target already has the rule

A rule's ID is shared by every copy of it, so the target may already hold one with the same ID. TIDE never overwrites it. It asks instead:

- If the two are the same rule (index patterns and whether it is enabled aside): **Link them** for a copy, or **Move onto it** for a move, which deletes this copy and points its baseline mappings at the one already there.
- If they differ, the dialog shows how. **Copy under a new rule id** (*Move* under a new rule id, when moving) puts this rule beside the other with an ID of its own. **Compare and merge** opens Compare, when the two are linked.

### Link two rules yourself

In the rule window's **Linked** section, type a rule's name in **Add link**, pick it from the suggestions, and add it. **×** on a linked rule removes the link (never the rule).

### Compare and merge linked rules

1. In the rule window, choose **⋮ › Compare**, and pick the linked rule in **Comparing against** if it has several.
2. Compare shows each section that differs, **Inline** or **Side by side**, with a tick beside each.
3. To bring them in line, choose the **Direction** (which rule's version wins) and untick any section to leave as it is, for example keep your query and take the other's investigation guide.
4. Under **After merging**, keep both rules or delete one.
5. Click **Merge**.

With every section ticked, Merge copies the whole rule over.

## Updates from Elastic and Sigma

TIDE remembers which of Elastic's or the Sigma rules each of your rules came from, including Elastic's prebuilt rules installed by Kibana. When TIDE is upgraded with newer versions, the rules they changed are flagged.

- The **Upstream** filter on Rule Health shows **Elastic update available**, **Sigma update available**, **Up to date**, **Deprecated by Elastic**, **Deprecated by Sigma**, **No longer in TIDE's Elastic or Sigma rules** and **Your own rules**.
- The rule window's header shows **Elastic** or **Sigma** for a rule that came from either.
- The rule window's **Upstream** section says what changed, and **⋮ › Compare with *Elastic*** (or *Sigma*) shows your rule beside the new version.

To take an update:

1. Open **Compare with *Elastic*** (or *Sigma*). Each differing section has a tick.
2. Untick what you want to keep as it is, then click **Merge ticked sections**. Or click **Keep this rule as it is**. Either way the update is marked as reviewed.
3. When nothing TIDE compares has changed (Elastic sometimes raises a version for something outside the rule itself), there is nothing to merge: **Move to version *N*** marks it. TIDE also does this by itself at each sync.

An Elastic prebuilt rule can take sections too: Kibana keeps it as Elastic's and marks it customised.

### A custom rule using one of Elastic's rule ids

Rules moved, copied or restored by earlier versions of TIDE can be custom rules under the rule id of one of Elastic's prebuilt rules. While one is, Kibana can't install Elastic's own rule in that space, or installs it beside the custom one under the same rule id. **Settings → Diagnostics** lists them.

- In the rule's window, **Upstream** says so. **Give it its own rule id** creates the rule again in Kibana under a new rule id and deletes the original. TIDE keeps its history, links and baseline mappings, and still shows Elastic's updates for it.
- When Kibana holds a custom copy beside Elastic's prebuilt rule, TIDE shows the prebuilt one, and its **Upstream** section offers **Give the copy its own rule id**, so you keep both.

Kibana keeps the original's past alerts and runs with it; the rule under its new id starts without them.

## Bulk edit

1. On Rule Health, choose **⋮ › Bulk edit**.
2. Tick the rules, or tick the box at the top to select every rule the filters show.
3. Choose **Move**, **Enable**, **Disable**, **Validate**, **Sync** or **Delete**. Move asks for a **Target destination**, and how to treat the rules' validation.
   - **Sync** reads each rule again from its SIEM, as **Sync this rule** does. A rule its SIEM no longer has is marked **Deprecated**, keeping its history, and is listed when the sync ends: a quick way to find which of a few rules is no longer in Kibana.
   - **Delete** removes the rules from TIDE. Tick **Also delete them from Elastic** to delete them in their SIEM too, which asks once more; otherwise a rule still in Elastic comes back at the next sync.
4. Progress shows each rule by name, with any that failed and why. A Move that meets a rule already at the target moves the rest first, then asks about each that clashed.

**Exit bulk edit** returns to the list.

## Delete and restore

- **⋮ › Delete rule** removes the rule from TIDE straight away; a sync brings it back if it is still in Elastic. Tick **Also delete it from Elastic** to remove it from the SIEM too.
- A rule deleted in Elastic becomes **Deprecated** at the next sync. **⋮ › Restore** puts it back in Elastic, disabled, in the destination you choose in **Recreate in**. A rule under one of Elastic's rule ids comes back under a new one, keeping its history, links and mappings.

## Find duplicate rules

**⋮ › Find duplicate rules** finds rules recorded more than once at the same destination. Choose which row of each group to keep, then **Merge selected groups**. Their baseline mappings move to the row you keep. Nothing is changed in Elastic.
