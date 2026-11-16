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

**Systems** lists every system with its coverage. Across the top are the figures for all of them: **Systems**, **Devices** (beneath: their packages, and the known exploited CVEs those match), **Affected devices** and **Baseline assignments**. Its **⋮** menu has **Add system**, **Upload Nessus**, **Import** and **Export**. Search by name, description or classification, and filter by **Classification** and **Risk status**; **Clear** resets the filters.

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

Click a system to open its page. Across the top are its figures: **Covered** (the share of techniques with coverage; beneath: how many of how many), **Effective** (the share covered by rules that can work now, see [Effective coverage](#effective-coverage)), **No coverage** (beneath: how many have no rule mapped, and how many have a mapped rule that is **Not counted** because it is disabled or sits only at a destination this system isn't measured on; red when a technique of **Critical** priority has none) and **Known gaps**. A system with Wazuh devices also shows **Vulnerabilities** (Wazuh's findings on them, and how many are known exploited) and **Hardening** (the average score of the CIS benchmark policies Wazuh ran on them). Below are its sections, **Baselines**, **Devices**, **Log sources**, **Hardening** (with Wazuh devices) and **Heatmap**, which fold, move and hide like a window's (**⋮ › Sections**).

The page's **⋮** menu has **Edit system** and **Export report**. As on the Baselines page, an open section scrolls inside itself under its filter bar, holding the baseline you're in at the top of the techniques. Each section is at most the window's height and the page scrolls between them: the section you're on fills the window, and scrolling past its end moves the page on to the next. Fold the sections you aren't using to skip them.

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

To make a baseline from the rules built into TIDE, filter the **Sigma Rules** or **Elastic Rules** page to the rules the system needs and choose **⋮ › Create baseline** there (see [Make a baseline from a library's rules](LIBRARIES.md#make-a-baseline-from-a-librarys-rules)). It becomes a template on **Baselines**; apply it here with **Add baseline**.

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

### See the log sources a system needs

A system's **Log sources** section lists what MITRE ATT&CK says to log to detect its baseline techniques, on the system's platforms: each log source (such as `WinEventLog:Security` or `auditd:SYSCALL`), its platforms, the events to collect (a Windows log's event codes on one line) and how many techniques need it (hover the number for which). Techniques marked N/A are left out, and the note under the list says how many have no MITRE analytic for the system's platforms. It comes from ATT&CK's detection strategies, built into TIDE, and doesn't check whether those logs reach your SIEM. Take it to whoever runs your logging.

A system's platforms come from its devices' operating systems (Windows, Linux, macOS, ESXi, network devices, Android and iOS), and from any you add. No device shows a cloud service or an identity provider, so:

1. In the page's **⋮** menu, choose **Edit system**.
2. Under **Platforms**, tick the ones its devices don't show, such as SaaS, IaaS, Identity Provider or Office Suite. The line under it says which its devices already show.
3. Click **Save**.

The section says how many devices have no operating system TIDE recognises (hover for which); give each one under **Devices** to count it. The same platforms put the right analytics first in a technique's **How to detect**.

### Export a system report

1. In the page's **⋮** menu, choose **Export report**.
2. Choose the **Format** (PDF or Markdown), the **Classification** marking, and the **Audience**: *Executive / CISO* for a briefing of two or three pages, *Technical / Engineer* for the full report.
3. Under **Include sections**, tick **Include devices** for the device exposure sections and, for a system with Wazuh devices, keep **Include vulnerabilities and hardening** ticked for Wazuh's findings and benchmark results.
4. Tick the baselines to include. The report's figures cover only those.
5. For a technical report, choose its **Technique detail pages**: every technique, only those with no coverage or a known gap, or none.
6. Click **Download**.

The technical report shows the same figures as the page, the priority gaps, and coverage by SIEM, with rules that don't count (disabled, or mapped somewhere the system isn't measured) highlighted in red and rules that aren't effective marked. Its **Rule Health** section lists the open Rule Monitoring findings on the rules covering the chosen baselines, grouped by what is wrong with who fixes each and naming each rule, and when the rules were last synced. A finding muted in Rule Monitoring isn't listed, and the section says how many are muted. Its coverage trend charts each chosen baseline's coverage at the end of every week, from the system's history (kept from TIDE's 6.0 upgrade on, up to a year), and lists the weeks where it changed. Its cover says when it was generated and when the rules were last synced, with how many destinations haven't been synced for 7 days; threat and CVE reports say the same. With **Include vulnerabilities and hardening**, a system with Wazuh devices gets a **Vulnerabilities** section (Wazuh's findings by severity, the CVEs on most devices with known exploited first, and each device's agent and findings) and a **Hardening** section (each CIS benchmark policy's average and lowest score, and the checks most devices fail, with their CIS ids), in PDF and Markdown alike. When no device has a known exploited vulnerability, one line says so, in place of the CVE sections.

The executive report is a briefing for the CISO, from the same figures, in two or three pages:

- Its first page gives four figures, **Effective coverage**, **Threat baselines assessed**, **Critical exposure gaps** (techniques nothing detects) and **Device fleet health** (the devices with no known exploited vulnerability), then a summary of what they mean in a few plain sentences, and the coverage trend.
- **Threat Exposure** shows each baseline, and **Kill-chain coverage** the techniques by ATT&CK tactic, in the order an attack runs.
- **Remediation Roadmap** lists what would close the gaps. Quick wins come first, which need no new engineering: rules mapped outside the system's SIEM coverage, rules that are disabled, rules in your SIEMs that carry a technique's ATT&CK ids but aren't mapped, rules that can't work now, and known gaps due for review. Then the detections to build, most urgent first. Each says how many techniques it would cover and how many points it would add.
- **Device & Vulnerability Posture** gives the devices' figures and the known exploited CVEs on most of them, or one line when there are none.

It has no contents page, coverage matrix, technique detail or CVE breakdown. Threat, CVE and baseline reports have the same tables as system reports: a dark header that repeats on every page a table runs onto.

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
| **Hardening checks** | Checks from Wazuh's CIS benchmarks named on it, with how many of the system's devices pass each: mitigation beside its coverage, never counted in it (see [Name hardening checks on a technique](#name-hardening-checks-on-a-technique)) |
| **Sigma rules**, **Elastic rules** | Rules from the libraries built into TIDE that detect its ATT&CK techniques |
| **Risks** | Its priority and category |
| **MITRE ATT&CK** | The ATT&CK techniques it covers |
| **How to detect** | MITRE ATT&CK's detection strategy for each of those techniques: for each platform, what to look for, the log sources to read (hover one for what it records) and what to tune. On a system, its own platforms come first and the rest fold under **Other platforms** |

The score ring in the header shows the strongest rule protecting the system. The window's **⋮** menu has **Delete technique**.

### Map a rule to a technique

Who can: anyone who can edit Systems.

1. In **Coverage**, open the **⋮** menu and choose **Add coverage**, then **Rule (alerting)**.
2. For a technique made from a Sigma or Elastic rule, that rule's copies in your SIEMs are listed first (**Made from this rule**). Then come rules that **carry this technique's ATT&CK IDs**, then **All SIEM Rules**. Type in **Search rules…** to narrow the list.
3. Each row names the rule's destination, as the same rule can live in several places. Click the copy you mean. It is mapped straight away.

The rule's card in **Coverage** shows its score, destination, whether it is enabled, whether its fields exist in the SIEM, and when it was last validated. It also says **Not counted** if the rule is disabled or deprecated, or its destination isn't one the system is measured on (hover over it to see which), and **Not effective** if Rule Monitoring finds it can't work now (hover over it to see why). Click its name to open the rule; **×** removes the mapping (never the rule). The rule's own window lists the techniques it covers under **Covers**, and says there when it is disabled or not effective.

A technique with no rule mapped shows *N to consider* when rules elsewhere carry its ATT&CK techniques.

### Map rules by their ATT&CK ids

Who can: anyone who can edit Systems.

Wazuh and Elastic rules name the ATT&CK techniques they detect, so many can be mapped at once, still by you:

1. In the **Baselines** section's **⋮** menu, choose **Map rules by ATT&CK id…**.
2. Each technique with no rule mapped (and not N/A) is listed with the enabled rules that carry one of its ATT&CK ids, at the destinations the system counts (every destination while it counts none): the best scored first, with each rule's destination and score. None is ticked: a broad technique such as *Valid Accounts* matches rules for every platform.
3. To see disabled rules too, tick **Include disabled rules**. A disabled rule you map counts towards coverage once it's enabled.
4. Tick the ones that detect what the technique asks for, then choose **Map**.

Each is mapped as if you had picked it in the technique's window: it shows in the technique's **History**, and **×** on its card removes it. Nothing is mapped without this step: a rule's ATT&CK ids alone count only towards the ATT&CK technique, never a system's technique.

### Record a known gap or that it doesn't apply

1. **Add coverage**, then **Known gap** or **Not applicable**.
2. Give a **Reason** (so the next person knows), and optionally a **Review by** date.
3. Click **Save**. From the review date the technique shows **Review due**, here and on the system page.

A technique can have several known gaps, each a part of it that isn't covered, such as Linux hosts that aren't logged or a cloud service not onboarded yet: choose **Known gap** again to add another. It can have one **Not applicable**, which is offered only while it has none. To change a mark, choose **Update** from its card's **⋮**: its type, reason or review date; **Delete** removes it. The History keeps what each said before.

### Name hardening checks on a technique

Who can: anyone who can edit Systems, on a system with Wazuh devices.

A configuration check that passes makes a technique harder without detecting it, so TIDE shows it beside coverage, never in it. The technique's window has a **Hardening checks** section while the system's devices have hardening results: open its **⋮** menu and choose **Add hardening check**. The checks on the system's devices whose Wazuh ATT&CK ids include one of the technique's are listed first, each with how many devices pass it; search the rest by CIS id or title. Click one to name it. The section then shows each as *passed on N of M devices*, as the devices stand now; the check's own **⋮** removes it. Both are in the technique's **History**.

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

A technique covered, or partly covered, only by rules that aren't effective keeps its status and shows **Not effective** on its card, its row and its window, with each rule's reasons when you hover over it. A rule or dashboard that works beside them makes it effective. **Effective** on the page is covered, less those. The Systems page shows each system's and baseline's effective share beside its coverage where they differ, a system report shows **Effective** beside **Covered**, and on the Dashboard a System section has an **Effective** card and a Baselines section a **Not effective** card (system baselines with a technique that isn't). Effective is today's figure: it shows no change when compared with an earlier day.

## Detection Backlog

**Detection Backlog**, under **Systems** in the sidebar, is what to build next, across all your systems. Each row is an ATT&CK technique that a baseline technique on one or more systems still needs covered: it has **No coverage**, a **Known gap** (**Partial coverage** included), or is **Not effective** (covered only by rules that can't work now). Each baseline technique's status is the one its system's page shows. One with several ATT&CK techniques is listed under each, and those with none are together at the end, under **No ATT&CK technique**.

Across the top are the figures for the whole backlog: **Techniques to cover** (and the systems they're on), **No coverage** (red when a technique of **Critical** priority has none), **Known gaps** (beneath: how many are partly covered, and how many techniques are **Not effective**) and **KEV CVEs**.

The rows are most urgent first, in this order:

1. one with a known gap past its **Review by** date (**Review due**);
2. the highest priority set on one of its baseline techniques;
3. its **KEV CVEs**: known exploited vulnerabilities on its systems' devices that are exploited through it, from the mapping of CISA's catalogue to ATT&CK built into TIDE, and any technique you've added to a CVE;
4. how many of your threat actors use it, those on **Threat Landscape**;
5. how many systems it's on.

**Sort by** puts **KEV CVEs**, **Threat actors** or **Systems** first instead, or lists the rows by **ATT&CK id**. Choose a **System** or a **Coverage** status to see only those: each row's figures are then for the systems and statuses chosen. **Search** finds an ATT&CK id or name, a baseline technique or a system.

Click a row to open it. It shows:

- the ATT&CK technique: its pill opens the side panel, its name the technique's window;
- its **Threat actors** and **KEV CVEs**; each CVE opens its page;
- the rules ready to use: **Your rules** (enabled rules at your destinations that carry it, which may only need mapping), and **Elastic rules** to deploy and **Sigma rules** to convert, none of them deprecated. Each opens where you can see them;
- each system's baseline technique, as its card. Click one to open its window on that system, to map a rule or record a known gap.

Once a rule is in your SIEM and synced, map it from each technique's window, or to all of a system's techniques at once with [Map rules by their ATT&CK ids](#map-rules-by-their-attck-ids). The backlog changes as you do.

## Devices and CVEs

### Add or edit a device

In a system's **Devices** section, **Add device** takes a **Device name**, **IP address** and **Operating system**; **Upload Nessus** loads devices from a scan. Click a device to open its page, where you can edit its details (**Edit device**, in its **⋮**), add packages (**Add package**, in the **⋮** on **Packages**), edit or remove each package from its own **⋮**, and see the known exploited vulnerabilities its packages match.

### Wazuh agents as devices

Who can: anyone who can edit Systems, on a client with a Wazuh destination.

1. In the system's **⋮** menu, choose **Wazuh agents…**.
2. Tick each Wazuh destination (an agent group, or every agent) whose agents are this system's devices. A **Name pattern** narrows it to the agents whose name fits, such as `alpha-*`; blank takes them all.
3. **Save** reads the agents at once, and every sync refreshes them.

Each agent becomes a device with its name, address and operating system from Wazuh, its agent's status, its CIS benchmark results, and Wazuh's own vulnerability findings: each CVE with its severity, CVSS score, the package and version, what fixes it, and when it was first seen. A finding Wazuh no longer reports is kept as resolved. A CVE in CISA's known exploited catalogue is marked **Known exploited**, counts in the device's CVE matches and on **CVE Overview**, and opens the CVE's page. An agent that is renamed stays the same device; one that no longer matches is removed, its findings with it. Devices you added by hand, or from Nessus, are never touched. The manager's own agent (000) is nobody's device, and an agent can be a device of more than one system.

**Hardening.** A Wazuh device's page shows each CIS benchmark policy Wazuh ran on it: its score, how many checks passed, failed and don't apply, when it was scanned, and the failing checks with their CIS ids and remediation. The system's page has a **Hardening** section with each policy over its Wazuh devices: the average and lowest score, and the checks most devices fail. The checks are read again only when Wazuh has run a new scan. The system's figures gain **Vulnerabilities** and **Hardening**, on its page and in a Dashboard section for it, where **Compare with** shows how they have changed. [Rule Monitoring](RULES.md#rule-monitoring) lists the destination's agents that have stopped reporting, and a sync that couldn't read everything.

### CVEs

**CVE Overview** lists CISA's catalogue of known exploited vulnerabilities, newest first, 50 at a time: more load as you scroll, and the count beside the filters says how many match. Search, filter by system and coverage (has rules, no rules, available, unaffected), show matched CVEs only, or sort by **Matched first** to put the ones on your devices at the top.

To load the catalogue, use the page's **⋮** menu: **Import CVE** takes CISA's KEV JSON file, and **Upload MITRE map** takes the mapping from CVEs to ATT&CK techniques.

Open a CVE to see its details, the devices it affects and its ATT&CK techniques. For each affected device, **Apply rule…** records which detection covers it, or **Log blind spot** records why nothing can (with a **Reason**). **Detection rules** lists the rules recorded against the CVE. **Export report**, in the page's **⋮**, makes a CVE audit report (PDF or Markdown).
