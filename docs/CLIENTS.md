# Setting up clients

How an administrator connects TIDE to its SIEMs and threat feeds and sets up each client: its destinations, users and roles, rule validation and scoring. For signing in, single sign-on and what each role means, see [Configuration](CONFIGURATION.md); for syncing, backups and upgrades, [Operations](OPERATIONS.md).

Everything here is in **Settings → Management**. Integrations (SIEMs, OpenCTI connectors, GitLab, Keycloak) are set up by Platform Admins; a client's own settings by that client's Admins.

## The order to set things up

1. [Add your SIEMs](#add-a-siem) (Platform Admin).
2. [Create the client](#create-a-client).
3. [Link its destinations](#link-destinations-to-a-client): the SIEM spaces its rules live in.
4. [Assign its users and their roles](#assign-users-and-roles).
5. Sync its rules from **Rule Health** (see [Rules](RULES.md#sync-rules-from-your-siems)).
6. Optionally: [validation](#set-how-long-a-validation-lasts), [scoring](#choose-how-rules-are-scored), [threat feeds](#connect-threat-feeds), [GitLab projects](#link-gitlab-projects), classifications and Sigma assets.

## Add a SIEM

Who can: Platform Admins.

1. In **Management**, under **Integrations**, click **Add integration** and choose **SIEM**.
2. Give it a name and choose its type. For Elastic, enter its **Elasticsearch URL**, **Kibana URL** and **API key / token**. (Splunk and Sentinel SIEMs can be recorded but don't sync yet.)
3. Tick **Verify TLS certificate** if TIDE should check its certificate (see [Certificates](CONFIGURATION.md#certificates)).
4. Click **Test Connection**: it checks each Kibana space and how long each took to answer. Then save.

The API key needs to read and write detection rules in every space TIDE should use. To deploy rules, run hunts or save searches, it needs those rights too.

**OpenCTI** (for Threat Landscape's threat actors), **GitLab** and **Keycloak** (single sign-on, see [Configuration](CONFIGURATION.md#single-sign-on-with-keycloak)) are added the same way, with **Add integration**. A GitLab needs only its address: the tokens belong to the projects each client links (see [Link GitLab projects](#link-gitlab-projects)).

## Create a client

1. In **Management**, under **Tenants & Users**, open **Clients** and click **New Client**.
2. Give it a name and create it. Click the client to open its page.

A client's page has a section for each part of its set-up, most with a **⋮** menu to manage it: **Linked SIEMs**, **Assigned Users**, **Systems**, **Baselines**, **Linked CTI Connectors**, **GitLab Projects**, **Rule scoring** and **Role Templates**. The **⋮** at the top of the page has **Edit client** and **Delete client**.

## Link destinations to a client

A **destination** is one space of one SIEM, linked to the client with a name and colour of your choosing (for example *DM3-Prod*). TIDE reads the client's rules from its destinations, and a system counts the rules at the destinations you choose for it.

1. On the client's page, open the **⋮** on **Linked SIEMs** and choose **Manage SIEMs**.
2. Under **Add SIEM**, pick the SIEM, **Name** the destination, and give the Kibana **space** ID (blank for Kibana's default space). The space ID is the space's real ID in Kibana, not the name.
3. Optionally set a **Default index pattern**, used when rules are created there.
4. Click **Link SIEM**. Link as many spaces of as many SIEMs as the client uses.

**Edit**, in the **⋮** beside a destination, changes its **Name**, **Default index** and **Card colour** (the colour on its rules' cards and tags). Renaming a destination never touches its rules, scores or validation.

## Assign users and roles

1. On the client's page, open the **⋮** on **Assigned Users** and choose **Manage users**.
2. Pick a user and tick their **Roles on this client**, then **Assign User**.

A user can hold several roles on a client, and different roles on different clients. What each role may read and change on each page is set in the client's **Role Templates**. Users themselves are created under **Tenants & Users → Users**, or by single sign-on.

## Set how long a validation lasts

In **Linked SIEMs**, **Validation mode** decides when a rule's validation turns *due soon* and then *expired* (see [Validate a rule](RULES.md#validate-a-rule)):

- **Master cadence**: one schedule for every rule. Set the weeks until it turns amber and until it expires.
- **By criticality**: a schedule per severity, so critical rules are rechecked sooner.

Click **Save thresholds**.

## Choose how rules are scored

**Rule scoring** sets how many points each check is worth for this client. A rule's score is the percentage it earns of the points that apply to it, so the points needn't add up to 100. Set a check to 0 to switch it off. The section shows **Default weights** or **Custom weights**, and the total allocated.

## Connect threat feeds

- **Linked CTI Connectors**: **⋮** → **Manage connectors**, then pick an OpenCTI connector set up under **Integrations** and add it. **Sync Threats** on Threat Landscape then brings in its intrusion sets.

## Link GitLab projects

Who can: the client's Admins, once a Platform Admin has added the GitLab under **Integrations**.

A client links the GitLab projects TIDE should use: one to back up its rules to, and any number to raise issues in, for example one for engineers and one for analysts. One project can do both. Each project has its own access token, so TIDE reaches only the projects you link. Issues are raised from Rule Monitoring's **Copy for engineers** (see [Rule Monitoring](RULES.md)); rules are backed up as below.

1. In the project, make a project access token (**Settings → Access tokens**) with the `api` scope. Give it the **Developer** role for rule backup (**Maintainer** if the branch is protected), or **Planner** or above for issues only. Keep the project private: a backup holds every rule's logic.
2. On the client's page, open the **⋮** on **GitLab Projects** and choose **Manage projects**. Choose the GitLab, tick what it's for under **Use it for** (**Rule backup**, **Issues** or both), then enter its path (as in its address, `group/project`), an optional name, and the token. For rule backup, also the branch (`main` unless you choose another), optionally a folder in it, and under **Back up** the destinations to back up (all of them unless you untick some).
3. Click **Link and test**. TIDE tests the project the way it will use it and says whether it's ready, or what to fix: a token GitLab doesn't accept, a project the token can't see, a role too low, a protected branch it can't push to, issues turned off, a project that isn't private, or a token that expires within 14 days.

Each project's **⋮** has **Test**, which tests it again, and **Edit**, which changes what it's for, its name and its token and, for rule backup, its branch, folder and destinations. TIDE never shows a token again; leave the token blank to keep it. **Settings → Diagnostics** lists projects that failed their last test or whose token is about to expire.

### Rule backup

Kibana holds the rules; the backup project holds their copy. After each sync, TIDE backs up the destinations that sync covered: every rule, Elastic's prebuilt rules too, and the exception lists they use. **Back up now**, in the backup project's **⋮**, backs up all its destinations at once (use it for the first backup). The project shows its last backup, how it went and a link to the commit.

- *Which destinations:* every destination of the client, including ones linked later, unless you untick it under **Back up** (the project's **Edit**). A destination you untick keeps its folder as it was then, and the README says it isn't backed up; delete the folder in GitLab if you don't want it. Tick it again and the next backup brings it up to date.
- *Pausing:* **Pause backups**, in the same **⋮**, stops every backup to the project, after syncs and **Back up now**, and keeps the project linked with its settings. **Resume backups** starts them again; the next backup catches up on everything that changed meanwhile.
- *Where:* in the project's folder (or at its top), each destination has a folder named after it, with `rules/<rule id>.json` and `exceptions/<list id>.json`. A `README.md` in the folder (`RULES.md` at the top of the project) lists every rule by name with a link to its file. A destination you rename moves its folder; a rule you rename keeps its file; a rule given its own rule id moves to its new file. Git keeps each file's history through a move.
- *What:* each rule as Kibana holds it, with its keys in order and without what changes when the rule hasn't (when it was last updated, its revision, its last run), so a file changes only when the rule does. Each commit lists what changed and who last changed it in Kibana, and carries `[skip ci]`, so the project's pipelines don't run on a backup.
- *Changes made in GitLab:* Kibana wins. A rule file changed in GitLab is put back to Kibana's version at the next backup, and a file added to a destination's `rules` or `exceptions` folder that isn't one of its rules or lists is removed. The commit says what it put back, Rule Monitoring lists the rule under **Backup changed in GitLab** for 7 days, and the project's history keeps the change. Make changes to rules in Kibana or TIDE instead. Anything else in the project, including other files in the destination's folder, is never touched.
- *When it leaves things as they are:* a destination TIDE holds no rules for yet (sync it first), and an exception list Kibana didn't give at that time, keep what the backup has. If GitLab doesn't answer, the backup fails and changes nothing: the sync still finishes, and Rule Monitoring shows the failed step.

## Move systems and baselines between clients

- **Systems → ⋮ → Manage systems** lists the client's systems. **Move from another client** brings a system here with **Move Here**, and each system can be moved to another client. A system takes its baselines, devices and history with it. You need Admin on both clients.
- **Baselines → ⋮ → Manage baselines** lists the client's baseline templates, and **Clone from another client** copies one here.

## Shared settings

- **Classifications**: the classification names and colours systems can carry.
- **Sigma Assets**: **Custom Pipelines** and **Postprocessing Templates** for converting Sigma rules; **Assign tenants** chooses which clients may use each.
- **Data export & import** and **Backups** are covered in [Operations](OPERATIONS.md). **Query** is in [Diagnostics](OPERATIONS.md#diagnostics).
