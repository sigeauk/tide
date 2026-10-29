# Systems & baselines

How to describe what you protect, measure it against baselines, and record what covers each technique. Read [Getting started](GETTING_STARTED.md) first for the controls every page shares.

## How it fits together

- A **system** is something you protect: an application, a network zone, a site. It has devices, and one or more baselines.
- A **baseline** is a list of techniques an attacker could use against a system, grouped by ATT&CK tactic. The **Baselines** page holds the *templates*. Applying a template to a system gives the system **its own copy**: changing the system's copy never changes the template or another system, and changing the template never changes a copy already made.
- A **technique** in a baseline (a *baseline technique*) is one thing an attacker could do, in your words, linked to one or more ATT&CK techniques (such as **T1059.001**).
- A technique's **coverage** is what would catch it: your detection rules mapped to it, dashboards, reports and logs someone watches, or a decision that it is a known gap or doesn't apply.
- A rule only counts toward a system when it lives at a **SIEM destination** that system is measured on (see [Choose which destinations count](#choose-which-destinations-count)).

## The Systems page

**Systems** lists every system with its coverage. Search by name, description or classification, and filter by **Classification** and **Risk status**; **Clear** resets the filters.

### Add a system

Who can: anyone who can edit Systems.

1. On **Systems**, click **Add System**.
2. Give it a **Name**, and optionally a **Classification** and a **Description**.
3. Click **Create**. The system opens, ready for its first baseline.

### Load devices from a Nessus scan

1. On **Systems**, click **Upload Nessus**.
2. Pick the system the devices belong to, or **+ Create new system…** to make one.
3. Choose the `.nessus` or `.xml` scan file and upload it. TIDE adds each device with its operating system and installed packages, and matches the packages against known exploited vulnerabilities (see [CVEs](#cves)).

### Move systems between installations

**Export** downloads your systems as a JSON file; **Import** loads one, for example on another TIDE. When an imported system has the same name as one you already have, choose whether to **Create copy** or **Override existing**.

## A system's page

Click a system to open its page. Across the top are its figures: **Covered** (the share of techniques with coverage), **Techniques**, **No coverage**, **Known gaps**, **Unmapped** (techniques with no rule mapped) and **Not counted** (techniques whose rules sit only at destinations this system isn't measured on). Below are three sections, **Baselines**, **Devices** and **Heatmap**, which fold, move and hide like a window's (**⋮ › Sections**).

The page's **⋮** menu has **Edit system** and **Export report**.

### Apply a baseline to a system

Who can: anyone who can edit Systems.

1. In the **Baselines** section's **⋮** menu, choose **Manage baselines**.
2. Pick a template and click **Apply a baseline**. The system gets its own copy, with each technique's risks as a starting point.

In the same dialog you can **Edit** a baseline's name and description on this system, **Remove** it from the system (its techniques, mappings and known gaps go with it), or start an empty baseline of the system's own.

### Choose which destinations count

A system is measured on the SIEM destinations you choose, for example production but not a test space.

1. In the **Baselines** section's **⋮** menu, choose **SIEM coverage**.
2. Tick the destinations whose rules count for this system, and click **Save**.

A rule mapped at a destination that isn't ticked shows **Not counted**. With none ticked, the system's coverage reads **Not set** rather than 0%.

### Generate baselines from your technologies

**Generate baselines** (in the **Baselines** section's **⋮** menu) builds baselines from the SigmaHQ rules built into TIDE.

1. Tick the technologies the system runs (operating systems, cloud services, applications and so on). Each shows how many Sigma rules it has.
2. Check the **Generation Preview**: one baseline per technology, with the techniques its rules detect. Baselines the system already has are unticked.
3. Untick any you don't want, then click **Generate *N* Baselines**. They are the system's own baselines.

### Find a technique

The **Baselines** section has its own filter bar:

- **Search** titles, descriptions and ATT&CK IDs.
- **Baseline** shows one baseline.
- **Tactic** sorts in ATT&CK order or A to Z, and shows only the tactics you tick.
- **Coverage** filters by status (Covered, No coverage, Known gap, Not applicable) and by rules (No rules mapped, Has rules, Has rules that don't count).
- **Name** sorts by title.
- **Group by** puts the techniques under each baseline, each tactic, or both.
- **View** switches between cards and a table.

Your choices are remembered in this browser and kept in the address bar. Each group heading shows its coverage, for example *7/10 covered (70%)*.

### Export a system report

1. In the page's **⋮** menu, choose **Export report**.
2. Choose the **Format** (PDF or Markdown), the **Classification** marking, and the **Audience**: *Executive / CISO* for a summary, *Technical / Engineer* for the detail.
3. Tick the baselines to include. The report's figures cover only those.
4. For a technical report, choose its **Technique detail pages**: every technique, only those with no coverage or a known gap, or none.
5. Click **Download**.

The report shows the same figures as the page, the priority gaps, and coverage by SIEM, with rules mapped somewhere the system isn't measured highlighted in red. Its coverage trend charts each chosen baseline's coverage at the end of every week, from the system's history (kept from TIDE's 6.0 upgrade on, up to a year), and lists the weeks where it changed. Its cover says when it was generated and when the rules were last synced, with how many destinations haven't been synced for 7 days; threat and CVE reports say the same.

## Baseline templates

The **Baselines** page shows every template's techniques in one grid, grouped by template, with the same filters as a system's page (without Coverage: a template has no coverage until it is applied). Its **⋮** menu has **New baseline**, **Import** and **Add technique**. Each template's heading has **Manage**.

### Create a baseline

Who can: anyone who can edit Baselines.

1. On **Baselines**, open the **⋮** menu and choose **New baseline**.
2. Give it a **Name** and a **Description**, and create it. It shows straight away, ready for its first technique.

You can also make a baseline from a threat: a MITRE group, software or campaign, a threat actor on Threat Landscape, or the actors you picked on the Heatmap. See [Threat intelligence](THREATS.md).

### Add techniques to a baseline

1. Choose **Add technique**: from the Baselines page's **⋮** menu, from a template's **Manage**, or on a system from the **Baselines** section's **⋮** menu.
2. A blank technique window opens. Give it a **Title** (the only thing required), pick its baseline, and click **Create**.
3. The window becomes the technique's own. Use each section's **⋮ › Update** to fill it in:
   - **Description**: what the attacker does, in your words.
   - **MITRE ATT&CK**: pick a tactic, then a technique, as many as apply. Rule and Sigma suggestions come from these.
   - **Risks**: a **Priority** (Critical, High, Medium or Low) and a **Category** (Identity, Endpoint, Network, Cloud & SaaS, Container, IMPEX, Email, SecOps or OT/ICS).
4. To add another, click **+** beside the window's previous and next buttons.

### Import techniques

- Into one template: **Manage › Import techniques**, with a CSV or Excel file whose columns are **Title**, **Tactic**, **Technique** (an ATT&CK ID) and **Description**. Its rows are added to the template.
- As a new or existing template: the page's **⋮ › Import**, with a TIDE JSON export or a CSV or Excel file like the one above. Choose what to **Import into**, and name the baseline if it is new.

### Apply, export, rename or delete a template

From the template's **Manage**:

- **Apply to a system** gives that system its own copy and opens it. (Needs permission to edit Systems.)
- **Export** downloads a PDF or Markdown report of the template, or **TIDE JSON** to import elsewhere.
- Change its **Name** and **Description** and **Save**. This changes the template only; systems keep their own copy and name.
- **Delete template** removes the template and its techniques. Systems it was applied to keep their copy.

## Working with a technique

Click a technique on a system's page or the Baselines page to open its window. A system's technique has these sections (a template's has no History or Coverage):

| Section | What it holds |
|---|---|
| **History** | Every change: rules mapped, relinked or removed (with the rule's score then), gaps and N/A marks, edits, and SIEM coverage changes, with who and when |
| **Description** | The technique in your words |
| **Coverage** | Everything that catches it on this system |
| **Sigma rules**, **Elastic rules** | Rules from the libraries built into TIDE that detect its ATT&CK techniques |
| **Risks** | Its priority and category |
| **MITRE ATT&CK** | The ATT&CK techniques it covers |

The score ring in the header shows the strongest rule protecting the system. The window's **⋮** menu has **Delete technique**.

### Map a rule to a technique

Who can: anyone who can edit Systems.

1. In **Coverage**, open the **⋮** menu and choose **Add coverage**, then **Rule (alerting)**.
2. Rules that **carry this technique's ATT&CK IDs** are listed first, then **All SIEM Rules**. Type in **Search rules…** to narrow the list.
3. Each row names the rule's destination, as the same rule can live in several places. Click the copy you mean. It is mapped straight away.

The rule's card in **Coverage** shows its score, destination, whether it is enabled, whether its fields exist in the SIEM, and when it was last validated. It also says **Not counted** if its destination isn't one the system is measured on. Click its name to open the rule; **×** removes the mapping (never the rule).

A technique with no rule mapped shows *N to consider* when rules elsewhere carry its ATT&CK techniques.

### Record a known gap or that it doesn't apply

1. **Add coverage**, then **Known gap** or **Not applicable**.
2. Give a **Reason** (so the next person knows), and optionally a **Review by** date.
3. Click **Save**. From the review date the technique shows **Review due**, here and on the system page. Choose the same option again to edit it; the History keeps what it said before.

### Record coverage that doesn't alert

Some techniques are covered by a dashboard, a report or a log someone checks, rather than a rule. **Add coverage**, choose the kind (non-alerting), and give it a **Title**, an optional **Link** and a **Rationale** (what it watches, and who looks at it). It counts as covered and is labelled **Non-alerting**.

### Relink a rule TIDE can't find

When a mapped rule has been deleted, moved or renamed, its card says **Needs relinking**, with why on hover. Choose **Relink** from its **⋮** menu: the rule picker opens, searched by its name. The rule you pick replaces it, keeping its history.

### Use a suggested rule

**Sigma rules** suggests SigmaHQ rules for the technique's ATT&CK techniques; **Convert** opens the rule form with the converted rule, ready to create in your SIEM. **Elastic rules** suggests Elastic's detection rules; **Deploy** puts one in your SIEM. A suggestion never counts as coverage until it is in your SIEM, synced and mapped. See [Sigma, Elastic & Hunting](LIBRARIES.md).

## How a technique's status is decided

A technique's status is the first of these that applies:

1. **Not applicable**: marked as not applying to this system.
2. **Known gap**: marked as a gap you accept for now.
3. **Covered**: a rule mapped at a destination the system counts, or non-alerting coverage.
4. **No coverage**: none of the above.

A rule at a destination the system doesn't count leaves the technique uncovered, and shows **Not counted**.

## Devices and CVEs

### Add or edit a device

In a system's **Devices** section, **Add Device** takes a **Device name**, **IP address** and **Operating system**; **Upload Nessus** loads devices from a scan. Click a device to open its page, where you can edit its details (**Edit device**, in its **⋮**), add packages (**Add package**, in the **⋮** on **Packages**), edit or remove each package from its own **⋮**, and see the known exploited vulnerabilities its packages match.

### CVEs

**CVE Overview** lists CISA's catalogue of known exploited vulnerabilities, with the ones matching your devices first. Filter by system and coverage (has rules, no rules, available, unaffected), or show matched CVEs only.

To load the catalogue, use the page's **⋮** menu: **Import CVE** takes CISA's KEV JSON file, and **Upload MITRE Map** takes the mapping from CVEs to ATT&CK techniques.

Open a CVE to see its details, the devices it affects and its ATT&CK techniques. For each affected device, **Apply rule…** records which detection covers it, or **Log Blind Spot** records why nothing can (with a **Reason**). **Detection Rules** lists the rules recorded against the CVE. **Export report**, in the page's **⋮**, makes a CVE audit report (PDF or Markdown).
