# Getting started

How to find your way around TIDE: signing in, choosing a client, and the controls every page shares. The other parts of this guide build on it.

## Signing in

Open TIDE in your browser and sign in with your TIDE **Username** and **Password**, or through your organisation's single sign-on if your administrator has set it up. Your administrator gives you your account and decides what you can see and change on each client (your *role*: Analyst, Engineer or Admin).

To sign out, click your name at the bottom of the sidebar, then **Log Out**. Signing out in one browser signs you out of the others too.

## Choosing a client

TIDE keeps each **client** (an organisation, or a part of one) separate: its systems, rules, baselines and threat intelligence are its own, and nothing from one client shows on another.

The client you are working on is named at the top of the sidebar. If you belong to more than one, click its name and pick another; the page reloads with that client's data. If you belong to one client only, its name is shown without a menu.

## The sidebar

The sidebar lists TIDE's pages, grouped as they are in this guide:

| Group | Pages | What they are for |
|---|---|---|
| | **Home**, **Dashboard** | A summary of the client, and dashboards you build |
| | **Systems** | The systems you protect, and how well their techniques are covered |
| Risks | **CVE Overview**, **Baselines** | Known exploited vulnerabilities, and the baseline templates systems are measured against |
| Rules | **Rule Health**, **Sigma**, **Elastic**, **Hunting** | Your detection rules, and the rule libraries built into TIDE |
| Threats | **Threat Landscape**, **Heatmap** | Threat actors, and how well you cover what they do |
| MITRE | **Tactics**, **Techniques**, **Groups**, **Software**, **Campaigns**, **Mitigations**, **NIST** | The ATT&CK knowledge base, with your coverage of each part |
| CTI | **Indicators**, **Actors**, **Reports** | Threat intelligence from your feeds |

You only see the pages your role allows. The arrow at the foot of the sidebar (**Expand**) widens it to show the page names; click it again to keep just the icons.

Your name, at the bottom, opens **Settings** (your profile, and for administrators the rest of TIDE's set-up), a switch between the light and dark theme, and **Log Out**.

## How every page works

Pages are built from the same few controls, so once you know one page you know them all.

### Filters

Most pages have a filter bar across the top: a **Search** box and a dropdown for each thing you can filter by.

- Click a dropdown to open its list. Where you choose **one** option (a round button beside each), the list closes as you pick. Where you can tick **several** (a tick box beside each), it stays open while you tick; tick none to see everything.
- The button always names what is chosen, for example **All SIEMs**, or *Live, Linked* when you tick two.
- On Rule Health, the number beside each option is how many rules it holds.
- Only one list is open at a time. Click elsewhere or press **Esc** to close it.
- Filters apply as soon as you choose. Most pages keep your filters in the address bar, so a refresh, a bookmark or a link you share shows the same view.

### Cards or table

Lists such as Rule Health, a system's techniques and the MITRE pages show as cards or as a table. Switch between them with the two **View** buttons at the end of the filter bar (on Rule Health, **Show as cards** and **Show as table** in the page's **⋮** menu). In a table, click a column heading to sort by it. Long lists load more as you scroll.

### The ⋮ menu

The **⋮** button holds a page's or a section's less frequent actions, for example **New baseline** on Baselines or **Export report** on a system. Rows and sections in windows have their own **⋮** too.

### Figures

Many pages open with a row of figure cards (Total Rules, Covered, and so on). Hover over a card, or tab to it, to see what it counts.

## Windows

Clicking a rule, a technique or an ATT&CK object opens it in a **window** over the page, so you keep your place in the list.

- **Previous** and **Next** in the window's header step through the list as the page shows it; the arrow keys do too. Each window has its own address, so you can bookmark or share it.
- The window's main action (for example **Validate** on a rule) sits at the top right, with its other actions in the **⋮** menu beside it.
- A window is made of **sections**. Click a section's title to fold it away or open it again.
- To choose what shows, open the window's **⋮** menu and choose **Sections**: untick a section to hide it. Turn on **Move sections** to drag sections into a new order or another column (or use the arrow keys on a section's handle). **Reset layout** puts everything back. TIDE remembers your layout for every window of the same kind, in this browser.
- Press **Esc**, or click **✕** at the top right, to close the window.

### Technique pills and the side panel

An ATT&CK technique ID, such as **T1059.001**, shows as a small *pill*. Clicking a pill opens the **side panel**: a quick summary of the technique, its tactics and platforms, and the groups, software and rules related to it. Clicking a technique's *name* opens its full window instead (see [Threat intelligence](THREATS.md)).

## Dialogs

Actions that need more from you (creating, importing, exporting) open a **dialog**. **Cancel** closes it without saving; **Close** closes one that had nothing to save. When TIDE asks you to confirm something that can't be undone, the risky choice is marked and **Cancel** is selected, so pressing **Esc** or **Enter** straight away is safe.

## Dashboards

The **Dashboard** page shows the figures you choose, from across TIDE. A client can have several dashboards: pick one from the list beside the page title. You see the one you opened last, or the client's default.

If you can edit the Dashboard (Admins and Analysts can, by default):

1. Click **Edit**.
2. Give the dashboard a **Name**, then add sections: a page's figures (Rule Health, a system, Threat Landscape, Baselines, Asset Inventory, CVE Overview), the state of connected services and built-in data, a **Title** or a **Text block**.
3. For each section, tick which figures it shows and set its filters. A Rule Health section is filtered like the Rule Health page: by SIEM, status, state, score, validation date and search.
4. Arrange the sections: drag them, use their arrows or the arrow keys, and make them **Narrower** or **Wider** to sit side by side. Click a section's icon to choose another.
5. Click **Save**, or **Cancel** to leave it as it was.

The **⋮** menu beside the dashboard makes a **New dashboard**, **Duplicate**s this one, **Set as default** for everyone on the client, or **Delete**s it (other than the default). Figures are worked out each time a dashboard opens, and clicking one opens its page with the same filters.

## Your profile

Click your name at the bottom of the sidebar, then **Settings**. **Profile & Preferences** has:

- **Profile:** the name TIDE shows for you, and your picture (PNG, JPEG, WebP or GIF, up to 256 KB). Without a picture, TIDE shows your initials.
- **Sign-in:** how you sign in, your roles on each client, when you last signed in, and your email and password if you sign in with a TIDE account.
- **Appearance:** light or dark **Theme**, and a **Brand colour** for TIDE's accent; **Reset** puts the default back.
- **API Key Management:** keys for reading a client's data from other tools (see [External Query API](API.md)).

## Getting help

- This guide: **Settings → Documentation**. Search it from the box at the top of its sidebar.
- What has changed in each release: **Settings → Changelog**.
- If something doesn't work as this guide says, your administrator can check TIDE's health in **Settings → Diagnostics**.
