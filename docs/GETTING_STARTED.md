# Getting started

How to find your way around TIDE: signing in, choosing a client, and the controls every page shares. The other parts of this guide build on it.

## Signing in

Open TIDE in your browser and sign in with your TIDE **Username** and **Password**, or through your organisation's single sign-on if your administrator has set it up. Your administrator gives you your account and decides what you can see and change on each client (your *role*: Analyst, Engineer or Admin).

To sign out, click your name at the bottom of the sidebar, then **Log out**. Signing out in one browser signs you out of the others too.

## Choosing a client

TIDE keeps each **client** (an organisation, or a part of one) separate: its systems, rules, baselines and threat intelligence are its own, and nothing from one client shows on another.

The client you are working on is named at the top of the sidebar. If you belong to more than one, click its name and pick another; the page reloads with that client's data. If you belong to one client only, its name is shown without a menu.

## The sidebar

The sidebar lists TIDE's pages, grouped as they are in this guide:

| Group | Pages | What they are for |
|---|---|---|
| | **Home**, **Dashboard** | What needs attention on the client, and dashboards you build |
| Systems | **Systems**, **Baselines**, **Detection Backlog**, **CVE Overview** | The systems you protect and how well their techniques are covered, the baseline templates they are measured against, what to build next across them, and the known exploited vulnerabilities on their devices |
| Rules | **Rule Health**, **Rule Monitoring** | Your detection rules, and the ones that need action |
| Libraries | **Sigma Rules**, **Elastic Rules**, **Hunting** | The rules and hunting queries built into TIDE, to convert, deploy or run |
| Threats | **Threat Landscape**, **Heatmap** | Threat actors, and how well you cover what they do |
| MITRE | **Tactics**, **Techniques**, **Groups**, **Software**, **Campaigns**, **Mitigations**, **NIST 800-53** | The ATT&CK knowledge base, with your coverage of each part |

You only see the pages your role allows. The arrow at the foot of the sidebar (**Expand**) widens it to show the page names; click it again to keep just the icons.

Your name, at the bottom, opens **Settings** (your profile, and for administrators the rest of TIDE's set-up), a switch between the light and dark theme, and **Log out**.

## How every page works

Pages are built from the same few controls, so once you know one page you know them all.

### Filters

Most pages have a filter bar across the top: a **Search** box and a dropdown for each thing you can filter by.

- Click a dropdown to open its list. Where you choose **one** option (a round button beside each), the list closes as you pick. Where you can tick **several** (a tick box beside each), it stays open while you tick; tick none to see everything.
- The button always names what is chosen: **Any** when the filter is off, or *Unlinked, Linked* when you tick two.
- On Rule Health, the number beside each option is how many rules it holds.
- On Rule Health, Rule Monitoring and the rule libraries, the filters you'll use less are under **Filters**, which says how many of them are set. It stays open or closed as you left it.
- Only one list is open at a time. Click elsewhere or press **Esc** to close it.
- Filters apply as soon as you choose. Most pages keep your filters in the address bar, so a refresh, a bookmark or a link you share shows the same view.

### Cards or table

Lists such as Rule Health, a system's techniques and the MITRE pages show as cards or as a table. Switch between them with the two **View** buttons at the end of the filter bar (on Rule Health, **Show as cards** and **Show as table** in the page's **⋮** menu). In a table, click a column heading to sort by it. Long lists load more as you scroll.

### The ⋮ menu

The **⋮** button holds a page's or a section's less frequent actions, for example **New baseline** on Baselines or **Export report** on a system. Rows and sections in windows have their own **⋮** too.

### Tips and folded sections

Hover over a button, badge or name, or tab to it, to see what it is or does: the tip shows above it after a moment, the same on every page and in every window. A section of a page or window, or a group in a list, that you fold or unfold stays that way when you come back, in this browser.

### Figures

Many pages open with a row of up to four figure cards (Enabled, Covered, and so on), with related figures on the line beneath each. A figure is red only when something needs fixing. Hover over a card, or tab to it, to see what it counts. A Dashboard section can show any of a page's figures as a card of its own.

## Windows

Clicking a rule, a technique or an ATT&CK object opens it in a **window** over the page, so you keep your place in the list.

- **Previous** and **Next** in the window's header step through the list as the page shows it; the arrow keys do too. Each window has its own address, so you can bookmark or share it.
- The window's main action (for example **Validate** on a rule) sits at the top right, with its other actions in the **⋮** menu beside it.
- A window is made of **sections**. Click a section's title to fold it away or open it again. A window opens with the sections you'll want first: a rule's with its history, score chart and alerts folded, an ATT&CK technique's with its description and how to detect it. Open another and it stays open in the next window of that kind.
- To choose what shows, open the window's **⋮** menu and choose **Sections**: untick a section to hide it. Turn on **Move sections** to drag sections into a new order or another column (or use the arrow keys on a section's handle). **Reset layout** puts everything back. TIDE remembers your layout for every window of the same kind, in this browser.
- Press **Esc**, or click **✕** at the top right, to close the window.

### Technique pills and the side panel

An ATT&CK technique ID, such as **T1059.001**, shows as a small *pill*. Clicking a pill opens the **side panel**: a quick summary of the technique, its tactics and platforms, and the groups, software and rules related to it. Clicking a technique's *name* opens its full window instead (see [Threat intelligence](THREATS.md)).

## Dialogs

Actions that need more from you (creating, importing, exporting) open a **dialog**. **Cancel** closes it without saving; **Close** closes one that had nothing to save. When TIDE asks you to confirm something that can't be undone, the risky choice is marked and **Cancel** is selected, so pressing **Esc** or **Enter** straight away is safe.

## Home

**Home** opens when you sign in. It lists what needs attention on the client you are working on, as of its last sync, in four sections. Each shows its first five, with a link to the rest:

- **Rule Monitoring:** how many rules need action, by their worst problem (errors, warnings, info), how many began and how many were fixed in the last 7 days, and the kinds of problem, errors first. Click one to open [Rule Monitoring](RULES.md#rule-monitoring) on it.
- **Known gaps to review:** each known gap or not applicable mark on a system's technique whose review date has passed (**Review due**) or comes in the next 14 days, soonest first. Click the technique to open it on its system and review the mark ([recording a known gap](SYSTEMS.md#record-a-known-gap-or-that-it-doesnt-apply)).
- **Validations lapsing:** enabled rules whose validation has expired or is due soon, expired first, with how many were validated and how many lapsed in the last 7 days. Click a rule to open it and [validate it](RULES.md#validate-a-rule).
- **GitLab issues:** the open issues raised for the client's rules, newest first, with the rule each is about ([raising an issue](RULES.md#raise-an-issue-for-a-rule)). Shown when the client has a GitLab project linked or an issue open.

You see only the sections for pages your role allows. Click a section's title to fold it away; TIDE remembers it in this browser.

## Dashboards

The **Dashboard** page shows the figures you choose, from across TIDE. A client can have several dashboards: pick one from the list beside the page title. You see the one you opened last, or the client's default.

If you can edit the Dashboard (Admins and Analysts can, by default):

1. Choose **⋮ › Edit dashboard**.
2. Give the dashboard a **Name**, then add sections: a page's figures (Rule Health, Rule Monitoring, a system, Threat Landscape, Baselines, Asset Inventory, CVE Overview), the state of connected services and built-in data, a **Title** or a **Text block**.
3. For each section, tick which figures it shows and set its filters. A Rule Health section is filtered like the Rule Health page: by SIEM, status, state, score, validation date and search. A Rule Monitoring section is filtered like its page: by SIEM, severity, who fixes, issue, whether disabled rules count, and search.
4. To see how a section's figures have changed, choose **Compare with**: **Yesterday**, **7 days ago**, **30 days ago** or **90 days ago**. Each figure that can show a change then says how much it has gone up or down since the end of that day: green when that is better, red when worse. Hover over the figure to see what it was then. A Rule Health section shows the change in **Total rules**, **Enabled** and **Avg quality**, when it has no filter other than SIEM; a rule counts from the day it was created in Kibana. Its **Validated** instead says how many rules were validated in that time and how many lapsed, such as "26 validated · 26 lapsed in 30 days": a rule validated again while still in policy counts as validated, and one lapses when its last validation goes past the client's period for its severity, so it is due. Kept up, the two match and Validated stays as it was. A system's section shows the change in each of its cards but **Effective** (for a system with Wazuh devices, **Vulnerabilities** and **Hardening** too, from TIDE's 7.0 upgrade on), and a Baselines section in **Rules mapped**, **Uncovered** and **Fully covered**; TIDE has the history for these from its 6.0 upgrade on. A Rule Monitoring section instead shows how many began and how many were fixed in that time, on **Rules needing action**, **Errors**, **Warnings** and **Things to fix**, such as "12 new · 30 fixed in 30 days", when it has no **Search**. What TIDE found the first time it looked at a SIEM was there already, so it isn't counted as new; TIDE has the history for this from its 6.3.2 upgrade on, and the 14 days before. Avg quality shows no change from before most of its rules were scored the way TIDE scores them now.
5. Arrange the sections: drag them, use their arrows or the arrow keys, and make them **Narrower** or **Wider** to sit side by side. Click a section's icon to choose another.
6. Click **Save**, or **Cancel** to leave it as it was.

The **⋮** menu beside the dashboard also makes a **New dashboard**, **Duplicate**s this one, **Set as default** for everyone on the client, or **Delete**s it (other than the default). Figures are worked out each time a dashboard opens, and clicking one opens its page with the same filters.

## Your profile

Click your name at the bottom of the sidebar, then **Settings**. Settings opens on **Management** if you're an admin; **Profile & Preferences** is its last tab, and where it opens for everyone else. It has:

- **Profile:** the name TIDE shows for you, and your picture (PNG, JPEG, WebP or GIF, up to 256 KB). Without a picture, TIDE shows your initials.
- **Sign-in:** how you sign in, your roles on each client, when you last signed in, and your email and password if you sign in with a TIDE account.
- **Appearance:** light or dark **Theme**, and a **Brand colour** for TIDE's accent; **Reset** puts the default back.
- **API Key Management:** keys for reading a client's data from other tools (see [External Query API](API.md)).

## Getting help

- Help with the page you're on: the **?** beside its title opens its part of this guide in the side panel, without leaving the page. **Open in Documentation** at the foot of the panel goes to the whole page.
- This guide: **Settings → Documentation**. Search it from the box at the top of its sidebar.
- What has changed in each release: **Settings → Changelog**.
- If something doesn't work as this guide says, your administrator can check TIDE's health in **Settings → Diagnostics**.
