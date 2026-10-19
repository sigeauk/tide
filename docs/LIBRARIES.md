# Sigma, Elastic & Hunting

TIDE has three rule libraries built in, so they work without internet access: SigmaHQ's detection rules, Elastic's detection rules, and hunting queries from both. This page covers browsing them, turning their rules into rules in your SIEM, and running hunts. Read [Getting started](GETTING_STARTED.md) first for the controls every page shares.

The libraries are as they were when your TIDE image was built; upgrading TIDE brings newer versions, and [Rules](RULES.md#updates-from-elastic-and-sigma) explains how TIDE flags the rules of yours they changed.

## How the library pages work

**Sigma**, **Elastic** and **Hunting** (under **Rules** in the sidebar) are laid out the same way:

- **Settings across the top**: how a rule is converted (Sigma), where it is deployed (Elastic), or where and how a hunt runs (Hunting). They apply to whichever rule you open.
- **A rule browser on the left**: search, a **MITRE technique** box (part of an ID works: *T10* finds T1078 and T1059), and filters. The list loads more as you scroll.
- **The open rule on the right**: its details, its ATT&CK techniques, **In your SIEMs** (where this client already has the rule, and whether it is up to date; click one to open it), and its **Source**, colour-coded, with **Copy**.

## Sigma rules

### Convert a Sigma rule for your SIEM

1. Open **Sigma** and find the rule.
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
2. Find the rule. Filter by platform, integration, type, severity and status (**Production**, **Building block** or **Deprecated**).
3. Check its details: query, ATT&CK techniques, investigation guide, setup, and **Needs Elastic** (the oldest Elastic version it runs on). **Version** is the version Elastic ships for your SIEM's Elastic version.
4. Click **Deploy**. The rule form opens, filled in and set to the chosen destination and state, so you can change it first. Settings the form doesn't show, such as a threshold or new terms rule's, are kept as Elastic has them.
5. Create the rule.

It goes in as your own rule, under a new rule ID, so Kibana can still install Elastic's prebuilt copy beside it. TIDE asks first if the destination's SIEM runs an older Elastic than the rule needs, and refuses a second copy at the same destination.

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
