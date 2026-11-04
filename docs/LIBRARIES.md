# Sigma, Elastic & Hunting

TIDE has three rule libraries built in, so they work without internet access: SigmaHQ's detection rules, Elastic's detection rules, and hunting queries from both. This page covers browsing them, turning their rules into rules in your SIEM, and running hunts. Read [Getting started](GETTING_STARTED.md) first for the controls every page shares.

The libraries are as they were when your TIDE image was built; upgrading TIDE brings newer versions, and [Rules](RULES.md#updates-from-elastic-and-sigma) explains how TIDE flags the rules of yours they changed.

## How the library pages work

**Sigma**, **Elastic** and **Hunting** (under **Rules** in the sidebar) are laid out the same way:

- **Settings across the top**: how a rule is converted (Sigma), where it is deployed (Elastic), or where and how a hunt runs (Hunting). They apply to whichever rule you open.
- **A rule browser on the left**: search, a **MITRE technique** box (part of an ID works: *T10* finds T1078 and T1059), and filters. The list loads more as you scroll.
- On the Sigma and Elastic pages, tick as many choices in a filter as you like: a rule with any of them shows, and every filter applies. The number beside each choice is how many rules you would see by ticking it, with your other filters as they are; choices that would show none are left out until the other filters change. For example, Elastic's **Platform** *windows*, **Status** *Production*, **Severity** *High* and technique *T1059.001* list 38 rules, and **Data source** then shows how many of them read PowerShell logs, Sysmon or Elastic Defend.
- **The open rule on the right**: its details, its ATT&CK techniques, **In your SIEMs** (where this client already has the rule, and whether it is up to date; click one to open it), and its **Source**, colour-coded, with **Copy**.
- The browser and the open rule reach the bottom of the window, and each scrolls on its own.

## Sigma rules

### Convert a Sigma rule for your SIEM

1. Open **Sigma** and find the rule. Filter by **Product**, **Category** and **Service** (the log source the rule reads, as Sigma writes it: *windows*, *process_creation*, *security*), **Tactic**, **Level** and **Status**.
2. Set the conversion across the top:
   - **Target**: the query language to convert to: Elasticsearch (Lucene), Elasticsearch (EQL), Elasticsearch (ES|QL), Splunk SPL or Microsoft 365 Defender (KQL).
   - **Format**: what the conversion produces. The formats offered depend on the target.
   - **Pipeline**: how Sigma's field names map to your SIEM's, or **No Pipeline** to leave them as Sigma writes them.
   - **Custom pipelines** and **Templates**: your own pipelines and output templates, applied in the order you tick them. Your administrator manages these in **Settings → Management**.
3. The open rule's **Query** shows the conversion with these settings, and follows any change to them.
4. Click **Convert**. The rule form opens, filled in with the converted rule, to change and create in your SIEM (see [Create a rule](RULES.md#create-a-rule)).

A Sigma rule converted in TIDE is remembered as coming from Sigma, with how it was converted, so a later Sigma update to it can be converted the same way.

### Use a Sigma rule of your own

**⋮ › Add your own Sigma rule** opens an editor. Paste or write the rule, **Validate** it, then **Show rule**: it opens on the right like the library's rules, converted with the settings across the top, ready to **Convert**. **Clear** empties the editor.

## Elastic rules

### Deploy one of Elastic's rules

Who can: anyone who can edit the Elastic page.

1. Open **Elastic** and set **Deploy to** (the destination) and **Deploy as** (**Disabled** or **Enabled**) across the top.
2. Find the rule. Filter by **Platform**, **Data source** (the logs Elastic tags the rule as reading, such as *Sysmon* or *PowerShell Logs*), **Integration**, **Tactic**, **Type**, **Severity**, **Status** (**Production**, **Building block** or **Deprecated**), and Elastic's **Profile** (*Recommended*, *Beta*, *Aggressive*, or **None** for the many rules without one) and **Noise** tags.
3. Check its details: query, ATT&CK techniques, investigation guide, setup, and **Needs Elastic** (the oldest Elastic version it runs on). **Version** is the version Elastic ships for your SIEM's Elastic version.
4. Click **Deploy**. The rule form opens, filled in and set to the chosen destination and state, so you can change it first. Settings the form doesn't show, such as a threshold or new terms rule's, are kept as Elastic has them.
5. Create the rule.

It goes in as your own rule, under a new rule ID, so Kibana can still install Elastic's prebuilt copy beside it. TIDE asks first if the destination's SIEM runs an older Elastic than the rule needs, and refuses a second copy at the same destination.

## Make a baseline from a library's rules

Who can: anyone who can edit Baselines.

1. On **Sigma** or **Elastic**, filter the browser to the rules you want. For example, Elastic's **Platform** *windows*, **Status** *Production*, **Severity** *High* and technique *T1059.001* list 38 rules.
2. Choose **⋮ › Create baseline**. It says how many rules it will use and what you filtered by. Deprecated rules, and Sigma's unsupported ones, are left out. It warns you when the baseline would have 100 techniques or more, since each is worked through on every system it's applied to.
3. Keep or change the suggested name and description. Or choose a baseline under **Add to** to add these rules to it instead; rules already in it are left out.
4. Click **Create**. **Baselines** opens on it.

Each rule becomes one technique, titled and described as the rule is (with its false positives), and carrying every ATT&CK technique the rule does. Its main one, listed first, is the technique you filtered by (else the rule's first sub-technique), and its tactic is the one the rule puts that technique under. So filtering by *T1059.001* gives 38 techniques for T1059.001 under Execution. The technique remembers which rule it was made from, and keeps that when the baseline is applied to a system, exported or imported. Apply it to systems from **Baselines**, or with **Add baseline** on a system. There, its window offers that rule's copies in your SIEMs to map (see [A technique made from a rule](SYSTEMS.md#a-technique-made-from-a-rule)).

## Hunting

Hunting queries look for activity your detection rules may not alert on. The **Hunting** page has Elastic's hunting queries and SigmaHQ's threat-hunting rules; filter by source, platform and ATT&CK technique.

### Run a hunt

1. Across the top, choose **Run on / save to** (the destination whose SIEM runs it) and the **Time** range, or keep the time the query sets.
2. For a Sigma rule, choose the **Sigma pipeline** and **Index pattern** it is converted with. Elastic's ES|QL and EQL queries run as written.
3. Open the hunt and click **Run** beside its query.

The hits show under the query: how many, where, over what time and how long it took, with the first 50 rows. **Copy** puts the rows on your clipboard to paste into a spreadsheet. **The query that ran** shows exactly what was sent. A SIEM with no data in the query's indices says so instead of failing.

Osquery hunts run on your hosts through Osquery Manager rather than the SIEM, so they have no **Run**.

### Save a hunt to Kibana

**Save to Kibana** saves an ES|QL query (a Sigma rule as converted) in the destination's Kibana space as a Discover search, named after the hunt and with the chosen time range, and links to it. Saving again replaces it. EQL queries can't be saved, as Discover doesn't run them. Saving needs edit access to Hunting, and an API key with Discover access in that space.
