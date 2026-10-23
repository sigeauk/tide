# Threat intelligence

How to see who might attack you, what they do, and how much of it your rules would catch: Threat Landscape, the Heatmap and the MITRE pages. Read [Getting started](GETTING_STARTED.md) first for the controls every page shares.

## Where it comes from

- **MITRE ATT&CK**, built into TIDE: the tactics, techniques, groups, software, campaigns and mitigations ATT&CK describes, for Enterprise, ICS and Mobile, and how NIST 800-53 controls map to them.
- **OpenCTI**, when your administrator links an OpenCTI connector to the client: its intrusion sets join ATT&CK's groups on Threat Landscape.

**Coverage** here always means: does an *enabled* rule of yours carry the ATT&CK technique? It is worked out from your rules' ATT&CK tags, across all your destinations. It is not a system's coverage, which also needs the rule mapped to a baseline technique (see [Systems & baselines](SYSTEMS.md)).

## Threat Landscape

**Threat Landscape** lists the threat actors known to the client, from ATT&CK and your feeds, with what each uses and how much of it you cover. Filter by **Origin** and **Source**, and **Sort By** TTPs or coverage. **Sync Threats** refreshes them from the feeds.

Click an actor's name to open its MITRE group window.

### Create a baseline from a threat actor

Who can: anyone who can edit Baselines.

1. On the actor's card, click **Create Baseline**.
2. Give it a **Baseline name** and, if you like, a **Description (optional)**, then click **Generate Baseline**.

It holds one technique for each ATT&CK technique the actor uses. Find it on **Baselines**, ready to apply to a system.

## Heatmap

The **Heatmap** shows ATT&CK's tactics as columns, with the techniques one or more actors use, coloured by whether your enabled rules cover them.

1. **Select Adversaries**: tick the actors to show. **Search actors** narrows the list.
2. Optionally pick a **Source**, and tick **Show defense in depth** to add the techniques you cover that these actors don't use.
3. Each cell is a technique: **Covered** (COV), **No Detection** (GAP), or **Defense in Depth** (DEF). Hover over a cell for detail; click its ID for the side panel.
4. The search box above the matrix highlights the techniques matching an ID, a name or a tactic.

**Export Report** makes a threat report for the chosen actors: choose PDF or Markdown, the classification marking, and *Executive / CISO* or *Technical / Engineer*. **Create Baseline** makes a baseline from the chosen actors' techniques, as from Threat Landscape.

## The MITRE pages

**Tactics**, **Techniques**, **Groups**, **Software**, **Campaigns** and **Mitigations** (under **MITRE** in the sidebar) each list one kind of ATT&CK object, with how much of it your enabled rules cover. They work alike:

- Filter by **Source** (Enterprise, ICS or Mobile) and the page's own filters: for example tactic, type and coverage for techniques, or platform for software.
- **Sort** them, **Group by** a field such as tactic or coverage, and switch between cards and a table.
- The left edge of each card is coloured by coverage, and the figures across the top total it, for example *Gaps groups use*: techniques a known group uses that no enabled rule of yours carries.

Wherever a tactic appears, it shows with its own icon.

### Open an ATT&CK object

Click one to open its window. A **technique** shows your rules for it, its sub-techniques, the groups that use it and how, software, campaigns, mitigations, Sigma rules and NIST 800-53 capabilities. A **group**, **software** or **campaign** shows the techniques it uses and how much you cover them, and links to the others. A **mitigation** breaks its coverage down by tactic. Names inside a window open their own windows; technique pills open the side panel.

### Create a baseline from a group, software or campaign

Who can: anyone who can edit Baselines.

1. Open the group, software or campaign.
2. Click **Create baseline** in its window.
3. Name it (**Baseline name**), add a **Description (optional)**, and create it.

The baseline has one technique for each ATT&CK technique it uses, each described by what ATT&CK says it does with it, and opens on **Baselines**.

### NIST 800-53

**NIST** lists NIST 800-53 control families. Open a family to see its capabilities, and a capability to see the ATT&CK techniques it mitigates and whether your rules cover them.
