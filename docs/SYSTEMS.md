# Systems & baselines

How to describe what you protect, measure it against baselines, and record what covers each technique. Read [Getting started](GETTING_STARTED.md) first for the controls every page shares.

## How it fits together

- A **system** is something you protect: an application, a network zone, a site. It has devices, and one or more baselines.
- A **baseline** is a list of techniques an attacker could use against a system, grouped by ATT&CK tactic. The **Baselines** page holds the *templates*. Applying a template to a system gives the system **its own copy**: changing the system's copy never changes the template or another system, and changing the template never changes a copy already made.
- A **technique** in a baseline (a *baseline technique*) is one thing an attacker could do, in your words, linked to one or more ATT&CK techniques (such as **T1059.001**).
- A technique's **coverage** is what would catch it: your detection rules mapped to it, dashboards, reports and logs someone watches, or a decision that it is a known gap or doesn't apply.
- A rule only counts toward a system when it is enabled and lives at a **SIEM destination** that system is measured on (see [Choose which destinations count](#choose-which-destinations-count)). A disabled rule is as good as no rule.
- A rule that counts is **effective** unless Rule Monitoring finds it can't work now (see [Effective coverage](#effective-coverage)).

## The Systems page

**Systems** lists every system with its coverage. Across the top are the figures for all of them: **Systems**, **Devices**, **Packages**, **CVE Matches**, **Affected Devices** and **Baseline Assignments**. Its **⋮** menu has **Add system**, **Upload Nessus**, **Import** and **Export**. Search by name, description or classification, and filter by **Classification** and **Risk status**; **Clear** resets the filters.

### Add a system

Who can: anyone who can edit Systems.

1. On **Systems**, choose **Add system** from the **⋮** menu.
2. Give it a **Name**, and optionally a **Classification** and a **Description**.
3. Click **Create**. The system opens, ready for its first baseline.

### Load devices from a Nessus scan

1. On **Systems**, choose **Upload Nessus** from the **⋮** menu.
2. Pick the system the devices belong to, or **+ Create new system…** to make one.
3. Choose the `.nessus` or `.xml` scan file and upload it. TIDE adds each device with its operating system and installed packages, and matches the packages against known exploited vulnerabilities (see [CVEs](#cves)).

### Move systems between installations

**Export**, in the **Systems** page's **⋮** menu, downloads your systems as a JSON file; **Import** loads one, for example on another TIDE. When an imported system has the same name as one you already have, choose whether to **Create copy** or **Override existing**.

## A system's page

Click a system to open its page. Across the top are its figures: **Covered** (the share of techniques with coverage), **Effective** (the share covered by rules that can work now, see [Effective coverage](#effective-coverage)), **Techniques**, **No coverage**, **Known gaps**, **Unmapped** (techniques with no rule mapped) and **Not counted** (techniques with a mapped rule that is disabled, or sits only at a destination this system isn't measured on). Below are three sections, **Baselines**, **Devices** and **Heatmap**, which fold, move and hide like a window's (**⋮ › Sections**).

The page's **⋮** menu has **Edit system** and **Export report**. As on Rule Health, the page fits the window: its heading and figures stay put, and every section's heading is always in view. A section you open scrolls inside itself, under its filter bar, holding the baseline you're in at the top of the techniques. Fold the sections you aren't using to give the others their room; open sections share the height, with Baselines getting twice the others' share, and none taller than it needs.

### Add a baseline to a system

Who can: anyone who can edit Systems.

1. In the **Baselines** section's **⋮** menu, choose **Add baseline**.
2. Either pick a template and click **Apply**, or name an empty baseline of the system's own and click **Create baseline**. Applying gives the system its own copy, with each technique's risks as a starting point.

The page then shows the new baseline, even an empty one. Each baseline's heading has its own **⋮**:

- **Edit baseline** changes its name and description on this system.
- **Add technique** adds a technique to it (see [Add techniques to a baseline](#add-techniques-to-a-baseline)).
- **Remove baseline** removes it from the system, with its techniques, mappings and known gaps. The template and other systems aren't affected.

The techniques are grouped by baseline until you choose otherwise in **Group by**. A baseline's **⋮** shows only while they're grouped by baseline.

### Choose which destinations count

A system is measured on the SIEM destinations you choose, for example production but not a test space.

1. In the **Baselines** section's **⋮** menu, choose **SIEM coverage**.
2. Tick the destinations whose rules count for this system, and click **Save**.

A rule mapped at a destination that isn't ticked shows **Not counted**. With none ticked, the system's coverage reads **Not set** rather than 0%.

### Baselines from Sigma or Elastic rules

To make a baseline from the rules built into TIDE, filter the **Sigma** or **Elastic** page to the rules the system needs and choose **⋮ › Create baseline** there (see [Make a baseline from a library's rules](LIBRARIES.md#make-a-baseline-from-a-librarys-rules)). It becomes a template on **Baselines**; apply it here with **Add baseline**.

### Find a technique

The **Baselines** section has its own filter bar:

- **Search** titles, descriptions and ATT&CK IDs.
- **Baseline** shows one baseline.
- **Tactic** sorts in ATT&CK order or A to Z, and shows only the tactics you tick.
- **Coverage** filters by status (Covered, No coverage, Known gap, Partial coverage, Not effective, Not applicable) and by rules (No rules mapped, Has rules, Has rules that don't count). Known gap includes the techniques with partial coverage; Partial coverage shows only them. Not effective shows the techniques covered only by rules that can't work now.
- **Name** sorts by title.
- **Group by** puts the techniques under each baseline (until you choose otherwise), each tactic, or both.
- **View** switches between cards and a table.

Your choices are remembered in this browser and kept in the address bar. Each group heading shows its coverage, for example *7/10 covered (70%)*.

Each technique's card has its window's score ring: the score of the strongest rule protecting the system, or for partial coverage that score in the share its rules make up beside its known gaps. A technique no rule covers has an empty ring in its status's colour, red for no coverage and amber for a known gap. The card's left edge is coloured by its status too.

### Export a system report

1. In the page's **⋮** menu, choose **Export report**.
2. Choose the **Format** (PDF or Markdown), the **Classification** marking, and the **Audience**: *Executive / CISO* for a summary, *Technical / Engineer* for the detail.
3. Tick the baselines to include. The report's figures cover only those.
4. For a technical report, choose its **Technique detail pages**: every technique, only those with no coverage or a known gap, or none.
5. Click **Download**.

The report shows the same figures as the page, the priority gaps, and coverage by SIEM, with rules that don't count (disabled, or mapped somewhere the system isn't measured) highlighted in red and rules that aren't effective marked. Its **Rule Health** section lists the open Rule Monitoring findings on the rules covering the chosen baselines, grouped by what is wrong with who fixes each, and when the rules were last synced: a technical report names each rule, an executive one says how many. A finding muted in Rule Monitoring isn't listed, and the section says how many are muted. Its coverage trend charts each chosen baseline's coverage at the end of every week, from the system's history (kept from TIDE's 6.0 upgrade on, up to a year), and lists the weeks where it changed. Its cover says when it was generated and when the rules were last synced, with how many destinations haven't been synced for 7 days; threat and CVE reports say the same.

## Baseline templates

The **Baselines** page shows every template's techniques in one grid, grouped by template, with the same filters as a system's page (without Coverage: a template has no coverage until it is applied). Its **⋮** menu has **New baseline**, **Import** and **Add technique**. Each template's heading has its own **⋮**, as a system's baselines do: **Edit baseline**, **Add technique**, **Apply to a system**, **Import techniques**, **Export** and **Delete template**.

### Create a baseline

Who can: anyone who can edit Baselines.

1. On **Baselines**, open the **⋮** menu and choose **New baseline**.
2. Give it a **Name** and a **Description**, and create it. It shows straight away, ready for its first technique.

You can also make a baseline from a threat: a MITRE group, software or campaign, a threat actor on Threat Landscape, or the actors you picked on the Heatmap. See [Threat intelligence](THREATS.md).

### Add techniques to a baseline

1. Choose **Add technique**: from the Baselines page's **⋮** menu, from a template's own **⋮**, or on a system from the **Baselines** section's **⋮** menu or a baseline's own **⋮**, which picks that baseline for you.
2. A blank technique window opens. Give it a **Title** (the only thing required), pick its baseline, and click **Create**.
3. The window becomes the technique's own. Use each section's **⋮ › Update** to fill it in:
   - **Description**: what the attacker does, in your words.
   - **MITRE ATT&CK**: pick a tactic, then a technique, as many as apply. Rule and Sigma suggestions come from these.
   - **Risks**: a **Priority** (Critical, High, Medium or Low) and a **Category** (Identity, Endpoint, Network, Cloud & SaaS, Container, IMPEX, Email, SecOps or OT/ICS).
4. To add another, click **+** beside the window's previous and next buttons.

### Import techniques

- Into one template: its **⋮ › Import techniques**, with a CSV or Excel file whose columns are **Title**, **Tactic**, **Technique** (an ATT&CK ID) and **Description**. Its rows are added to the template.
- As a new or existing template: the page's **⋮ › Import**, with a TIDE JSON export or a CSV or Excel file like the one above. Choose what to **Import into**, and name the baseline if it is new.

### Apply, export, rename or delete a template

From the **⋮** on the template's heading:

- **Edit baseline** changes its **Name** and **Description**. This changes the template only; systems keep their own copy and name.
- **Apply to a system** gives that system its own copy and opens it. (Needs permission to edit Systems.)
- **Export** downloads a PDF or Markdown report of the template, or **TIDE JSON** to import elsewhere.
- **Delete template** removes the template and its techniques, once you confirm. Systems it was applied to keep their copy.

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
2. For a technique made from a Sigma or Elastic rule, that rule's copies in your SIEMs are listed first (**Made from this rule**). Then come rules that **carry this technique's ATT&CK IDs**, then **All SIEM Rules**. Type in **Search rules…** to narrow the list.
3. Each row names the rule's destination, as the same rule can live in several places. Click the copy you mean. It is mapped straight away.

The rule's card in **Coverage** shows its score, destination, whether it is enabled, whether its fields exist in the SIEM, and when it was last validated. It also says **Not counted** if the rule is disabled or deprecated, or its destination isn't one the system is measured on (hover over it to see which), and **Not effective** if Rule Monitoring finds it can't work now (hover over it to see why). Click its name to open the rule; **×** removes the mapping (never the rule). The rule's own window lists the techniques it covers under **Covers**, and says there when it is disabled or not effective.

A technique with no rule mapped shows *N to consider* when rules elsewhere carry its ATT&CK techniques.

### Record a known gap or that it doesn't apply

1. **Add coverage**, then **Known gap** or **Not applicable**.
2. Give a **Reason** (so the next person knows), and optionally a **Review by** date.
3. Click **Save**. From the review date the technique shows **Review due**, here and on the system page.

A technique can have several known gaps, each a part of it that isn't covered, such as Linux hosts that aren't logged or a cloud service not onboarded yet: choose **Known gap** again to add another. It can have one **Not applicable**, which is offered only while it has none. To change a mark, choose **Update** from its card's **⋮**: its type, reason or review date; **Delete** removes it. The History keeps what each said before.

### Record coverage that doesn't alert

Some techniques are covered by a dashboard, a report or a log someone checks, rather than a rule. **Add coverage**, choose the kind (non-alerting), and give it a **Title**, an optional **Link** and a **Rationale** (what it watches, and who looks at it). It counts as covered and is labelled **Non-alerting**.

### Relink a rule TIDE can't find

When a mapped rule has been deleted, moved or renamed, its card says **Needs relinking**, with why on hover. Choose **Relink** from its **⋮** menu: the rule picker opens, searched by its name. The rule you pick replaces it, keeping its history.

### A technique made from a rule

A technique made from a Sigma or Elastic rule (**⋮ › Create baseline** on the Sigma or Elastic page) says so at the top of **Coverage**, with the rule's name. Each copy of that rule in your SIEMs that isn't mapped yet is listed under it, with its destination and whether it's enabled; **Map** maps that copy, as picking it would. TIDE never maps it for you. With no copy anywhere, it says to deploy or convert the rule from **Elastic rules** or **Sigma rules** below, where it's listed first under **Made from this rule**. If Elastic has deprecated the rule, or SigmaHQ no longer has it, it says that too.

A rule covers more than one technique, and a rule tagged with an ATT&CK technique doesn't cover every way that technique is used. So the copies of a technique's own rule are what it was made to be covered by. Other rules can still be mapped from **Add coverage**.

### Use a suggested rule

**Sigma rules** suggests SigmaHQ rules for the technique's ATT&CK techniques; **Convert** opens the rule form with the converted rule, ready to create in your SIEM. **Elastic rules** suggests Elastic's detection rules; **Deploy** puts one in your SIEM. A suggestion never counts as coverage until it is in your SIEM, synced and mapped. See [Sigma, Elastic & Hunting](LIBRARIES.md).

## How a technique's status is decided

A technique's status is the first of these that applies:

1. **Not applicable**: marked as not applying to this system.
2. **Known gap**: marked as a gap you accept for now. With coverage beside its known gaps (an enabled rule mapped at a destination the system counts, or non-alerting coverage) it is **Partial coverage**.
3. **Covered**: an enabled rule mapped at a destination the system counts, or non-alerting coverage.
4. **No coverage**: none of the above.

A rule that is disabled or deprecated, or at a destination the system doesn't count, leaves the technique uncovered, and shows **Not counted**. Past figures (a Dashboard section's **Compare with**, a report's coverage trend) count a rule only on the days it was enabled.

Partial coverage counts as a known gap: in **Known gaps**, which says how many are partly covered, and not in **Covered**. Its score ring shows the strongest rule's score in the share its rules make up beside its known gaps: a rule scoring 50 with one known gap shows 25, with two 17. Hover over the ring for the sum.

### Effective coverage

A rule can count toward a system and still catch nothing: its index pattern matches no index, its data has stopped arriving, Kibana can't run its query, or a field it matches on is missing or never filled. **Effective** leaves those out. A rule is not effective while Rule Monitoring lists one of these for it: any error (such as **No index matches the index pattern**, **No recent events in the index pattern** on all its patterns, **Query won't parse**, **Machine learning job not running** or **Blind windows between runs**), **Field not in the index mappings**, **Field mapped but has no data**, or **Enabled but never run**. It is worked out from the rule's state each time the page opens; nothing about the mapping changes, and it is effective again once Rule Monitoring no longer lists the problem.

A technique covered, or partly covered, only by rules that aren't effective keeps its status and shows **Not effective** on its card, its row and its window, with each rule's reasons when you hover over it. A rule or dashboard that works beside them makes it effective. **Effective** on the page is covered, less those. The Systems page shows each system's and baseline's effective share beside its coverage where they differ, a system report shows **Effective** beside **Covered**, and on the Dashboard a System section has an **Effective** card and a Baselines section a **Not Effective** card (system baselines with a technique that isn't). Effective is today's figure: it shows no change when compared with an earlier day.

## Devices and CVEs

### Add or edit a device

In a system's **Devices** section, **Add Device** takes a **Device name**, **IP address** and **Operating system**; **Upload Nessus** loads devices from a scan. Click a device to open its page, where you can edit its details (**Edit device**, in its **⋮**), add packages (**Add package**, in the **⋮** on **Packages**), edit or remove each package from its own **⋮**, and see the known exploited vulnerabilities its packages match.

### CVEs

**CVE Overview** lists CISA's catalogue of known exploited vulnerabilities, with the ones matching your devices first. Filter by system and coverage (has rules, no rules, available, unaffected), or show matched CVEs only.

To load the catalogue, use the page's **⋮** menu: **Import CVE** takes CISA's KEV JSON file, and **Upload MITRE Map** takes the mapping from CVEs to ATT&CK techniques.

Open a CVE to see its details, the devices it affects and its ATT&CK techniques. For each affected device, **Apply rule…** records which detection covers it, or **Log Blind Spot** records why nothing can (with a **Reason**). **Detection Rules** lists the rules recorded against the CVE. **Export report**, in the page's **⋮**, makes a CVE audit report (PDF or Markdown).
