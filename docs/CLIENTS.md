# Setting up clients

How an administrator connects TIDE to its SIEMs and threat feeds and sets up each client: its destinations, users and roles, rule validation and scoring. For signing in, single sign-on and what each role means, see [Configuration](CONFIGURATION.md); for syncing, backups and upgrades, [Operations](OPERATIONS.md).

Everything here is in **Settings → Management**. Integrations (SIEMs, OpenCTI connectors, GitLab, Keycloak) are set up by Platform Admins; a client's own settings by that client's Admins.

## The order to set things up

1. [Add your SIEMs](#add-a-siem) (Platform Admin).
2. [Create the client](#create-a-client).
3. [Link its destinations](#link-destinations-to-a-client): the SIEM spaces its rules live in.
4. [Assign its users and their roles](#assign-users-and-roles).
5. Sync its rules from **Rule Health** (see [Rules](RULES.md#sync-rules-from-your-siems)).
6. Optionally: [validation](#set-how-long-a-validation-lasts), [scoring](#choose-how-rules-are-scored), [threat feeds](#connect-threat-feeds), classifications and Sigma assets.

## Add a SIEM

Who can: Platform Admins.

1. In **Management**, under **Integrations**, click **Add integration** and choose **SIEM**.
2. Give it a name and choose its type. For Elastic, enter its **Elasticsearch URL**, **Kibana URL** and **API key / token**. (Splunk and Sentinel SIEMs can be recorded but don't sync yet.)
3. Tick **Verify TLS certificate** if TIDE should check its certificate (see [Certificates](CONFIGURATION.md#certificates)).
4. Click **Test Connection**: it checks each Kibana space and how long each took to answer. Then save.

The API key needs to read and write detection rules in every space TIDE should use. To deploy rules, run hunts or save searches, it needs those rights too.

**OpenCTI** (for Threat Landscape's threat actors), **GitLab** and **Keycloak** (single sign-on, see [Configuration](CONFIGURATION.md#single-sign-on-with-keycloak)) are added the same way, with **Add integration**.

## Create a client

1. In **Management**, under **Tenants & Users**, open **Clients** and click **New Client**.
2. Give it a name and create it. Click the client to open its page.

A client's page has a section for each part of its set-up, each with an **Edit** button: **Linked SIEMs**, **Assigned Users**, **Systems**, **Baselines**, **Linked CTI Connectors**, **Rule scoring** and **Role Templates**.

## Link destinations to a client

A **destination** is one space of one SIEM, linked to the client with a name and colour of your choosing (for example *DM3-Prod*). TIDE reads the client's rules from its destinations, and a system counts the rules at the destinations you choose for it.

1. On the client's page, click **Edit** on **Linked SIEMs**.
2. Under **Add SIEM**, pick the SIEM, **Name** the destination, and give the Kibana **space** ID (blank for Kibana's default space). The space ID is the space's real ID in Kibana, not the name.
3. Optionally set a **Default index pattern**, used when rules are created there.
4. Click **Link SIEM**. Link as many spaces of as many SIEMs as the client uses.

The pencil beside a destination changes its **Name**, **Default index** and **Card colour** (the colour on its rules' cards and tags). Renaming a destination never touches its rules, scores or validation.

## Assign users and roles

1. On the client's page, click **Edit** on **Assigned Users**.
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

- **Linked CTI Connectors**: **Edit**, then pick an OpenCTI connector set up under **Integrations** and add it. **Sync Threats** on Threat Landscape then brings in its intrusion sets.

## Move systems and baselines between clients

- **Systems → Edit** lists the client's systems. **Move from another client** brings a system here with **Move Here**, and each system can be moved to another client. A system takes its baselines, devices and history with it. You need Admin on both clients.
- **Baselines → Edit** lists the client's baseline templates, and **Clone from another client** copies one here.

## Shared settings

- **Classifications**: the classification names and colours systems can carry.
- **Sigma Assets**: **Custom Pipelines** and **Postprocessing Templates** for converting Sigma rules; **Assign tenants** chooses which clients may use each.
- **Data export & import** and **Backups** are covered in [Operations](OPERATIONS.md). **Query** is in [Diagnostics](OPERATIONS.md#diagnostics).
