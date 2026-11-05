# Rules

How to keep your detection rules healthy: syncing them from your SIEMs, reading and editing them, validating them, moving them between destinations, and taking updates from Elastic and Sigma. Read [Getting started](GETTING_STARTED.md) first for the controls every page shares.

## Where rules come from

TIDE reads your detection rules from each **SIEM destination** linked to the client: one space of one Elastic SIEM, with a name and colour your administrator chose (for example *DM3-Prod*). The same rule can live at several destinations; each copy is its own rule in TIDE, shown with its destination's tag.

TIDE gives each rule a **score** (0 to 100) for how well it is likely to work: whether its fields exist in the SIEM, how it is written, whether it has an investigation guide and ATT&CK techniques, and so on. Your administrator decides how many points each check is worth for the client. A check that doesn't fit the rule isn't counted: a machine learning rule has no query or timestamp override to judge. For an indicator match rule, the fields checked include its indicator mapping: each field in its own indexes, and each indicator field in its indicator indexes.

## Rule Health

**Rule Health** lists every rule of the client, with figures across the top: **Total Rules**, **Enabled**, **Validated**, **Avg Quality**, **Severity** and **Last Synced**.

### Sync rules from your SIEMs

Who can: anyone who can edit Rule Health.

TIDE doesn't fetch rules by itself: sync when you want the latest.

- **Sync** reads every destination linked to the client. Hover over it to sync one destination only, for example **Sync *DM3-Prod* only**.
- **Sync with mappings** also asks each SIEM which fields its indices hold, so the field checks in each rule's score are up to date. It takes longer; use it after index changes.

**Last Synced** shows when the rules were last synced. If a sync failed, only partly finished, was interrupted, or read the rules but then had a step fail, it says why and offers **Retry**.

A SIEM that can't be reached is skipped: its rules keep showing, marked **SIEM offline**, until a sync reaches it again.

### Find rules

Filter by **Search** (name, author, ID or ATT&CK technique), **SIEM**, **Status** (enabled or disabled), **State**, **Upstream**, **Type**, **Language**, **Score** (with a range) and **Validate** (with a date range), and sort by score, validation date or **Name**. The number beside each choice is how many rules you would see by picking it, with your other filters as they are.

**Type** is the rule's type, as Kibana names it: **Custom query**, **Saved query**, **EQL**, **ES|QL**, **Threshold**, **New terms**, **Indicator match** or **Machine learning**. **Language** is its query language: **KQL**, **Lucene**, **EQL** or **ES|QL**. Threshold, new terms and indicator match rules have a language too, so *Indicator match* with *Lucene* finds the indicator match rules written in Lucene. A machine learning rule has no language.

Under **Validate**, **Show** narrows the rules by where their validation stands, as the **Validated** figure counts them: **Validated**, **Due soon**, **Expired** or **Never validated**. Sorting by validation date always puts rules never validated last, so tick **Never validated** to see them; tick **Expired** as well for every rule that needs validating. A date range narrows the validated rules only: with **Never validated** ticked, rules with no date still show.

**State** is the badge each rule shows:

- **Unlinked**: found at the last sync, with no rule linked to it.
- **Linked**: found at the last sync, with a rule linked to it: a copy in another destination, or a duplicate in its own.
- **SIEM offline**: its SIEM couldn't be reached at the last sync; shown from TIDE's last copy.
- **Deprecated**: no longer found in the SIEM.

Tick **Unlinked** and **Linked** together for every rule found at the last sync.

Under **Linked to**, pick a SIEM to narrow **Linked** to the rules linked to a copy there; picking one ticks **Linked** for you. For example, choose your production destination in **SIEM**, then your staging one under **Linked to**, to see the production rules that have a copy in staging.

The page's **⋮** menu switches between **Show as cards** and **Show as table**. In the table, click a heading to sort by it, drag a column's edge to resize it, and choose which columns show; **Reset table columns** puts them back.

## Rule Monitoring

**Rule Monitoring** lists the rules that need action, grouped by what causes it, so a problem many rules share is one thing to fix. It is as of each destination's last sync: every sync reads what Kibana says about each rule's last run, and checks the rules against the SIEM's indexes and fields. A rule you delete in TIDE, or move to another destination, leaves the list straight away; one deleted in Kibana leaves it at the next sync, or when you choose **Sync this rule** in its window.

- **What it finds:** an index pattern that matches no index, indexes missing the rule's timestamp override field (such as `event.ingested`), fields no index has or that have conflicting types, queries Kibana can't parse or Elasticsearch refuses, missing privileges, missed runs, schedules that leave part of each interval unsearched or too little look-back for late events, rules sharing a rule id, custom rules using one of Elastic's rule ids, custom rules linked to an Elastic rule they don't match, changes TIDE made in Kibana but couldn't finish recording (a new rule id, a move, a restore), SIEMs that didn't answer, syncs that couldn't read every rule, a step of the last sync that failed (such as cleaning up score history), and destinations not synced for 7 days. Anything else Kibana reports goes under **Other Kibana errors**, in Kibana's words.
- **Who fixes** says who acts: **Engineer** (the indexes, pipelines and the SIEM itself), **Author** (the rule's query and schedule) or **TIDE** (something TIDE can fix, or a sync).
- Each issue opens to its causes, such as an index pattern or a field in a data stream, with how many rules each affects and for how long. Open a cause for its rules; click a rule to open its window. **Previous** and **Next** in the window step through the rules listed, each rule once though it may be listed under several issues, so you can work through a list without going back to it.
- Filter by **Search**, **SIEM**, **Severity**, **Who fixes** and **Issue**; the number beside each choice is how many rules (or whole destinations) you would see by picking it, with your other filters as they are. **Rules** shows enabled rules, or **Include disabled** for what would fail if they were switched on. **Show** lists what is open, or what was fixed in the last 14 days. **Group by** lists by **Issue**, **Who fixes**, **SIEM / destination** or **Rule**. The page keeps your filters when it reloads, and each group stays open or closed as you left it.
- The cards count the rules needing action (beneath: how many of the enabled rules, and any disabled ones counted because of a rule id problem TIDE can fix), errors and warnings (and how many began in the last 7 days, once Rule Monitoring has a week of history; until then, the day it began), the **Things to Fix** (beneath: the rules they are on, and who fixes them), what was **Resolved** in the last 14 days (beneath: the rules it was on), and when the client was **Last Synced**. **Things to Fix** and **Resolved** count causes: a missing index or field once, however many rules it affects, and a problem without a cause, such as one with a rule's id or its link to Elastic's rule, once per destination.
- The page's **⋮** menu holds **Sync**, as on Rule Health; what a sync finds fixed moves to **Resolved recently**.

### Act on a cause

Open a cause for its actions. Anyone who can edit Rule Health can use them.

- **Raise issue** gives the cause as Markdown, to raise in GitLab or, with **Copy** in its corner, paste into a ticket or a chat: what is wrong, who fixes it, since when and what to do, then a table of what the person fixing it needs. An index or field problem is each index and field to fix on each SIEM, with how many rules it affects. Any other issue is its rules, with what was found on each; a rule in several destinations is one row naming them all. Anything that is the same on every row, such as the timestamp override field, is said once above the table instead.
- Where either can fix it (a field no index maps, a missing timestamp override field, a field Elasticsearch can't find), choose who it is **For**: the **Engineer** gets the indexes and fields to fix, the **Author** the rules and the fields each uses. It starts on whoever usually fixes that issue.
- An open issue has its own **Raise issue**, for all its causes at once, and **⋮ › Raise issue for all shown** does the same for every issue the filters show.
- **Raise in GitLab**, in the same dialog, opens it as an issue in one of the client's GitLab issues projects (see [Link GitLab projects](CLIENTS.md#link-gitlab-projects)): pick the project each time, optionally **Assign to** one of its members (it starts on **Nobody**), change the title or labels if you like, and **Raise issue**. The issue's description is the Markdown shown, with who raised it from TIDE and when. Each cause then shows a link to its issue, green while it's open in GitLab. Opening the dialog for a cause already raised lists its issues with their state in GitLab now, and **Add as a comment** adds what TIDE finds now to one of them instead of raising another. Raising needs the same right as fixing (changing Rule Health).
- **Sync these rules** reads the cause's rules again from their SIEM, to see whether it is fixed; for a whole destination, **Sync this destination**.
- **Give them their own rule ids**, on **Custom rule using one of Elastic's rule ids**, gives every rule of the cause its own rule id in one go; **Finish them in TIDE**, on **Change not finished in TIDE**, finishes them all. Each shows what it will do first, then its progress, with any rule that failed and why.
- **Compare them one by one**, on **Rules sharing a rule id in Kibana**, opens **Compare with the copy** for each rule of the cause in turn. Choose for each, or **Skip** it; what each choice did shows at the top of the next.
- **Mute cause…** mutes a cause you know about on every rule it affects, with a note (for example, an index not onboarded yet). It moves to **Muted** at the bottom of the list and isn't counted, until it affects more rules than when it was muted; then it comes back, saying so. **Unmute cause** puts it back at once.
- To mute one rule, use the bell at the end of its row, **Mute rule…**, and choose what to mute: **This problem on this rule**, or **Every problem on this rule, now and later**, each until you unmute it, or the problem's cause on every rule it affects, as **Mute cause…** does. Add a note if you like.
- Each row under **Muted** says why it is there. **Rule muted** says by whom, when and why, and its bell, **Unmute rule**, unmutes it. **Muted with its cause** is lifted by **Unmute cause**: above the rows, or on the row itself when you group by rule. A rule muted with its cause can be muted on its own too, so it stays muted if the cause comes back.
- Where TIDE can fix it, the rule's row has the fix: **Give it its own rule id** for a custom rule using one of Elastic's rule ids (TIDE still shows Elastic's updates for it), or **Unlink from Elastic** if it isn't Elastic's rule (which also gives it its own rule id), **Compare with the copy** where Kibana holds a custom copy beside Elastic's rule, **Compare with *Elastic*** for a rule linked to an Elastic rule it doesn't match (both below), and **Finish in TIDE** where Kibana made a change (a new rule id, a move, a restore) but TIDE couldn't record it.

## The rule window

Click a rule to open its window. The header shows its score, destination, state, whether it came from Elastic's or the Sigma rules, severity and author, with **Validate** and the date it was last validated at the top right, and the rest of its actions in the **⋮** menu: **Edit**, **Sync this rule**, **Move**, **Duplicate**, **Compare**, **View in Kibana**, **Delete rule**, and **Restore** for a deprecated rule.

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
| **Linked** | The rules linked to it: its copies at other destinations, and duplicates linked to it |
| **Upstream** | Whether Elastic or Sigma has a newer version of the rule it came from |
| **References**, **Rule ID** | Its references, and its IDs |

### Validate a rule

Validating records that someone checked the rule works. Click **Validate** in the rule window: it is marked validated now, by you. As the date ages, the validation turns from current to *due soon* to *expired* (your administrator sets how long each lasts), and the score reflects it.

To record many validations at once, use the page's **⋮ › Import validation file**, with a `checkedRule.json` file. Rules are matched by name. **Checked by** records them all under one name instead of each entry's own.

### Test a rule

In **Last run**, choose a time window in **Test against last** and click **Test**. TIDE runs the rule against that window in Kibana and shows what it would have found. The time it took is recorded as the rule's search time, which counts toward its score. A machine learning rule has no query to run, so it has no **Test**.

### Edit a rule

Who can: anyone who can edit Rule Health.

1. In the rule window, choose **⋮ › Edit**.
2. Change what you need. The form is in folding sections: **Define Rule** (rule type, query language, index patterns, query, and a threshold, new terms or indicator match rule's own settings), **About Rule** (name, severity, risk score, description, author, tags, timestamp override, MITRE ATT&CK techniques, highlighted fields, investigation guide), **Schedule** (how often it runs, how far back it looks) and **Action** (whether it is enabled).
3. Give a **Reason for change**. Every edit needs one; it is kept in the rule's History.
4. Click **Save**.

Only what you change is sent to Kibana, onto the rule as Kibana holds it at that moment. If someone changed the same field in Kibana since TIDE last synced it, nothing is saved: the form says which field, and TIDE loads Kibana's version so you can check it and make your change again. Editing a rule changes only that copy, never a rule linked to it.

A rule keeps its **Rule type** once it is made, as in Kibana, except that a custom query, EQL and ES|QL rule can become one of the others by changing its type (Kibana makes it again, keeping its history in TIDE). Filters set in Kibana are shown under the query and kept as they are.

A rule that searches a data view shows its **Data view** in place of index patterns: Kibana searches the data view, not index patterns. To search index patterns instead, tick **Use index patterns instead**. It fills in the data view's patterns for you to change, and saving switches the rule to them; its History names the data view it searched before. Taking index patterns from a linked rule ([Compare and merge linked rules](#compare-and-merge-linked-rules)) or from an update ([Updates from Elastic and Sigma](#updates-from-elastic-and-sigma)) switches it the same way.

Editing one of Elastic's prebuilt rules keeps it as Elastic's rule, so TIDE still shows when Elastic has an update for it. Kibana marks it as customised. When Elastic's next update for it is installed in Kibana, Kibana merges your change with Elastic's, or replaces it with Elastic's version, depending on your Elastic licence. The form says so above **Save**. Older versions of Kibana refuse changes to prebuilt rules; the form then shows Kibana's reason.

### Create a rule

Use the page's **⋮ › Create rule**. Choose the **Target SIEM / space**, a **Rule name**, the **Rule type** (**Custom query**, **EQL**, **ES|QL**, **Threshold**, **New terms** or **Indicator match**), the **Query language** and query, then fill in the rest as when editing, and click **Create Rule**. Rules converted from Sigma or deployed from Elastic's library open this same form, filled in (see [Sigma, Elastic & Hunting](LIBRARIES.md)).

### Threshold and new terms rules

A **Threshold** rule alerts when its query matches a number of events or more. In **Define Rule**:

- **Group by**: up to three fields (**Add field**), so the threshold counts each of their values on its own. Optional.
- **Threshold**: how many events. It starts at Kibana's 100.
- **Count**: a field and a number of **Unique values**, to alert only when the events have that many different values of the field or more. Optional.

A **New terms** rule alerts on a value it hasn't seen before. In **Define Rule**:

- **Fields**: one to three fields (**Add field**). With more than one, it is their combination of values that is new.
- **History window size**: how far back a value counts as seen, as a number and s, m, h or d, such as *7d*.

As you type a field, TIDE suggests the fields it has checked in the rule's index patterns. The rule window's **Rule logic** shows these settings below the query. Alert suppression set in Kibana is kept as it is.

### Indicator match rules

An indicator match rule alerts when a field of your events matches a field of your threat indicators. Choose **Indicator match** as the **Rule type**, then, in **Define Rule**, beside the index patterns and query of your events:

- **Indicator index patterns**: the indexes holding your indicators, such as `logs-ti_*`.
- **Indicator index query** and **Indicator query language**: which indicators to use. It starts as Kibana's, the last 30 days.
- **Indicator mapping**: a field of your events, and the indicator index field it matches. **AND** adds a field that must match as well; **OR** adds another group, any one of which is enough. As you type, TIDE suggests the fields it has checked in those indexes; you can type any other.
- **Indicator prefix override**, under **About Rule**: where the matched indicator goes in the alert. Blank is Kibana's own, `threat.indicator`.

The rule window's **Rule logic** shows these settings below the query. Filters on either query, set in Kibana, are shown and kept as they are. Kibana 9 can also map a field that *does not match*; TIDE shows such an entry and keeps it, but doesn't add one.

### Duplicate a rule

Who can: anyone who can edit Rule Health.

In the rule window, choose **⋮ › Duplicate** to make a copy of the rule in its own destination, under a new rule id, as Kibana's Duplicate does. To copy it to another destination, use **Move** instead (see [Move or copy a rule to another destination](#move-or-copy-a-rule-to-another-destination)).

1. Choose what the copy takes from the rule's exceptions: **Duplicate rule and its exceptions** (its own exception list with every item; lists it shares with other rules stay shared), **Duplicate rule and its active exceptions** (the same, leaving out expired ones) or **Duplicate rule only** (none, not even the shared lists).
2. Tick **Link the copy to this rule** to work on a copy while the rule keeps running: each shows the other in its **Linked** section, so when the copy is ready you can compare the two and merge it onto the rule (see [Compare and merge linked rules](#compare-and-merge-linked-rules)), then delete the copy.
3. If the rule came from Elastic's or the Sigma rules, **Keep the link to its *Elastic* rule** is ticked: TIDE shows that rule's updates for the copy too. Untick it to make the copy your own rule.
4. Click **Duplicate**.

The copy is named after the rule with *[Duplicate]* at the end, and is disabled, so it doesn't run until you enable it. Its window opens, so you can edit it. It starts unvalidated and isn't mapped to any baseline technique; its History says which rule it was duplicated from.

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

The copy takes the rule's exceptions with it, every one with its comments, in an exception list of its own; a list shared by every space, such as Elastic Defend's, stays shared when the copy stays on the same SIEM. A rule that searches a data view is copied with the data view's index patterns (for example `logs-*`), since a data view belongs to one space and the target may not have it. If TIDE can't copy an exception list or read the data view, nothing is changed and it says why.

A rule under one of Elastic's rule ids, such as one of Elastic's prebuilt rules, is copied under a new rule id. Kibana can then still install Elastic's own rule in the target, and TIDE still shows Elastic's updates for the copy.

If Kibana made the move but TIDE couldn't record it, TIDE says so and the rule's window offers **Finish in TIDE**, which completes it without changing Kibana again. Moving it again, or the next sync of the target, also completes it.

### When the target already has the rule

A rule's ID is shared by every copy of it, so the target may already hold one with the same ID. TIDE never overwrites it. It asks instead:

- If the two are the same rule (index patterns and whether it is enabled aside): **Link them** for a copy, or **Move onto it** for a move, which deletes this copy and points its baseline mappings at the one already there.
- If they differ, the dialog shows how. **Copy under a new rule id** (*Move* under a new rule id, when moving) puts this rule beside the other with an ID of its own. **Compare and merge** opens Compare, when the two are linked.

### Link two rules yourself

In the rule window's **Linked** section, choose a destination, type a rule's name in **Add link**, pick it from the suggestions, and add it. The rule's own destination is last in the list, to link a duplicate beside it, for example. **×** on a linked rule removes the link (never the rule). A link within one destination changes no coverage; it lets you compare and merge the two.

### Compare and merge linked rules

1. In the rule window, choose **⋮ › Compare**, and pick the linked rule in **Comparing against** if it has several.
2. Compare shows each section that differs, **Inline** or **Side by side**, with a tick beside each.
3. To bring them in line, choose the **Direction** (which rule's version wins) and untick any section to leave as it is, for example keep your query and take the other's investigation guide.
4. To combine a section rather than take one side's, see [Combining a section](#combining-a-section) below.
5. Under **After merging**, keep both rules or delete one.
6. Click **Merge**.

With every section ticked and none combined, Merge copies the whole rule over.

## Updates from Elastic and Sigma

TIDE remembers which of Elastic's or the Sigma rules each of your rules came from, including Elastic's prebuilt rules installed by Kibana. When TIDE is upgraded with newer versions, the rules they changed are flagged.

- The **Upstream** filter on Rule Health shows **Elastic update available**, **Sigma update available**, **Up to date**, **Deprecated by Elastic**, **Deprecated by Sigma**, **No longer in TIDE's Elastic or Sigma rules** and **Your own rules**.
- The rule window's header shows **Elastic** or **Sigma** for a rule that came from either.
- The rule window's **Upstream** section says what changed, and **⋮ › Compare with *Elastic*** (or *Sigma*) shows your rule beside the new version.

To take an update:

1. Open **Compare with *Elastic*** (or *Sigma*). Each differing section has a tick.
2. Untick what you want to keep as it is. To keep your own items in a list and add Elastic's new ones, such as highlighted fields, tick your items too; see [Combining a section](#combining-a-section).
3. Click **Merge ticked sections**. Or click **Keep this rule as it is**. Either way the update is marked as reviewed, TIDE says what it did, and you are back in the rule's window, or in the list you opened the comparison from.
4. When nothing TIDE compares has changed (Elastic sometimes raises a version for something outside the rule itself), there is nothing to merge: **Move to version *N*** marks it. TIDE also does this by itself at each sync.

An Elastic prebuilt rule can take sections too: Kibana keeps it as Elastic's and marks it customised.

When the new version is another type of rule, such as a custom query rule that Elastic rewrote in EQL or ES|QL, its **Rule type**, **Query language** and **Query** go together: ticking one ticks the others. Kibana can't change a rule's type in place, so merging them deletes the rule in Kibana and creates it again under the same rule ID, with its exceptions, actions and whether it is enabled. Its past alerts stay. Elastic's prebuilt rules aren't re-created: install Elastic's update in Kibana (**Rules › Rule updates**) instead. Merging two linked rules of different types in **Compare** works the same way.

### Link a rule to the Elastic or Sigma rule it came from

TIDE knows a rule came from Elastic's or the Sigma rules when it deployed or copied it, or when the rule uses that rule's id. A copy made otherwise, such as with Kibana's Duplicate or by hand, is shown as your own. To see its updates, link it:

1. In the rule window's **Upstream** section, choose **Elastic** or **Sigma**.
2. Type the name of the rule it came from, or keep the rule's own name, which is filled in without Kibana's *[Duplicate]*, and pick it from the suggestions.
3. Click **Link for updates**.

TIDE doesn't know which version of that rule it was copied from, so it shows **Compare to confirm** rather than **Up to date**. Open **Compare with *Elastic*** (or *Sigma*) once: take what you want, or **Keep this rule as it is**. From then on TIDE shows its updates as for any other rule. When Elastic's rule differs from it in nothing TIDE compares, the next sync confirms it for you. **Unlink from *Elastic*** (or *Sigma*) undoes a link made by mistake.

### Combining a section

In **Compare** and **Compare with *Elastic*** (or *Sigma*), a ticked section is taken whole from the side that wins, unless you combine it:

- **A list** (highlighted fields, tags, MITRE ATT&CK, index patterns, filters, references, false positives, author): each item only one side has has a tick, and the merged rule has what is ticked, as well as what both have. To begin with, the winning side's items are ticked. To keep yours as well, tick them; to drop one, untick it, and it is struck through. A MITRE ATT&CK sub-technique brings its technique with it.
- **A text** (query, description, investigation guide, setup guide): **Edit result** opens a box holding the winning side's text. What you write there is merged, in place of either side's. **Discard edit** closes it again. A query or description can't be left empty.

In **Compare**, changing the **Direction** moves the ticks and the box's text to the other side, for each section you haven't touched. The rule's history says which sections were combined or edited.

### Rules linked to an Elastic rule they don't match

TIDE links a custom rule to one of Elastic's rules when it uses that rule's id, or was copied or deployed from it, and then shows Elastic's updates for it. A link found by the rule id can be wrong: the rule may only share the id, or have become another detection since. So at each sync TIDE compares every custom rule linked to an Elastic rule with that rule, and **Rule Monitoring** lists those whose rule type, query or filters differ under **Linked to an Elastic rule it doesn't match**. Their name, index patterns and timestamp override are each destination's own, so they don't count.

- **Compare with Elastic**, on the rule's row or in its window's **Upstream** section, shows the two side by side.
- **Keep the link** if it is a copy you changed on purpose: TIDE goes on showing Elastic's updates for it, and doesn't ask again.
- **Unlink from Elastic** if it isn't Elastic's rule: it becomes your own rule, and TIDE no longer shows Elastic's updates for it. This works for any custom rule linked to an Elastic rule, from its window's **Upstream** section too. A rule that uses Elastic's rule id is also given its own (below), since your own rule shouldn't hold Elastic's; otherwise nothing changes in Kibana.

### A custom rule using one of Elastic's rule ids

Rules moved, copied or restored by earlier versions of TIDE can be custom rules under the rule id of one of Elastic's prebuilt rules. While one is, Kibana can't install Elastic's own rule in that space, or installs it beside the custom one under the same rule id. **Settings → Diagnostics** lists them.

- In the rule's window, **Upstream** says so. **Give it its own rule id** creates the rule again in Kibana under a new rule id and deletes the original. TIDE keeps its history, links and baseline mappings, and still shows Elastic's updates for it.
- If it isn't Elastic's rule, **Unlink from Elastic** gives it its own rule id the same way, and TIDE no longer shows Elastic's updates for it. If Kibana can't give it one, the rule is still unlinked, and **Give it its own rule id** finishes the job.
- If Kibana made the change but TIDE couldn't record it, TIDE says so, and the rule's window offers **Finish in TIDE**, which completes it without changing Kibana again. The next sync of that destination also completes it.
- If Kibana no longer has the rule, TIDE marks it deprecated rather than changing it.

Kibana keeps the original's past alerts and runs with it; the rule under its new id starts without them.

### A custom copy beside Elastic's rule

Kibana can hold a custom copy beside Elastic's prebuilt rule under the same rule id, and now and then two custom rules under one rule id. TIDE holds one rule per rule id in a destination, so it shows only one of them, whatever their names: Elastic's prebuilt rule, or the older of two custom rules. **Rule Monitoring** lists it under **Rules sharing a rule id in Kibana**, naming the other. The two are usually the same detection, so with both enabled each alert is raised twice. Compare them before you choose.

- **Compare with the copy**, on the rule's row in **Rule Monitoring** or in its window's **Upstream** section, reads both rules from Kibana and shows how they differ, whether they detect the same thing (the same rule type, query, index patterns and filters), and which of them is enabled.
- **Delete the copy** deletes it in Kibana, after asking. Its past alerts stay there; the rule TIDE shows is not changed.
- **Keep both** gives the copy a rule id of its own, and TIDE then shows it as a rule of its own. A copy beside Elastic's rule still shows Elastic's updates; if it doesn't match Elastic's rule, **Rule Monitoring** says so (see above).
- **Keep both and disable Elastic's** (**Keep both and disable the original**, for two custom rules) does the same, then disables the rule TIDE shows.

Only the copy takes a new rule id: Elastic's rule always keeps Elastic's. If Kibana no longer has the copy, TIDE stops listing it.

## Bulk edit

1. On Rule Health, choose **⋮ › Bulk edit**.
2. Tick the rules, or tick the box at the top to select every rule the filters show.
3. Choose **Move**, **Enable**, **Disable**, **Validate**, **Sync**, **Give own rule id** or **Delete**. Move asks for a **Target destination**, and how to treat the rules' validation.
   - **Give own rule id** gives each selected custom rule that uses one of Elastic's rule ids a rule id of its own, as the rule window does. Selected rules that don't need one are left out, and the dialog says how many.
   - **Sync** reads each rule again from its SIEM, as **Sync this rule** does. A rule its SIEM no longer has is marked **Deprecated**, keeping its history, and is listed when the sync ends: a quick way to find which of a few rules is no longer in Kibana.
   - **Delete** removes the rules from TIDE. Tick **Also delete them from Elastic** to delete them in their SIEM too, which asks once more; otherwise a rule still in Elastic comes back at the next sync.
4. Progress shows each rule by name, with any that failed and why. A Move that meets a rule already at the target moves the rest first, then asks about each that clashed.

**Exit bulk edit** returns to the list.

## Delete and restore

- **⋮ › Delete rule** removes the rule from TIDE straight away; a sync brings it back if it is still in Elastic. Tick **Also delete it from Elastic** to remove it from the SIEM too.
- A rule deleted in Elastic becomes **Deprecated** at the next sync. **⋮ › Restore** puts it back in Elastic, disabled, in the destination you choose in **Recreate in**. A rule under one of Elastic's rule ids comes back under a new one, keeping its history, links and mappings. If Kibana restored it but TIDE couldn't record that, the rule's window offers **Finish in TIDE**; restoring again completes it too, without creating the rule in Kibana twice.

## Find duplicate rules

**⋮ › Find duplicate rules** finds rules recorded more than once at the same destination. Choose which row of each group to keep, then **Merge selected groups**. Their baseline mappings move to the row you keep. Nothing is changed in Elastic.
