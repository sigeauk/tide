# TIDE at a glance

<p class="doc-lead">What TIDE does for your security team, with your own figures beside each part, and how to get the most from it. The rest of this guide shows how each part works.</p>

## Why TIDE

Without one place for them, every answer about your detection rules is put together by hand.

<div class="doc-cards">
<section class="card card-padded doc-card">
<h3><tide-icon name="layers" size="18"></tide-icon> Scattered rules, quiet drift</h3>
<ul>
<li>Rules spread across SIEMs and Kibana spaces, with no single view.</li>
<li>Staging and production copies grow apart, and Elastic's updates are tracked in spreadsheets.</li>
</ul>
</section>
<section class="card card-padded doc-card">
<h3><tide-icon name="triangle-alert" size="18"></tide-icon> Unknown quality, hidden gaps</h3>
<ul>
<li>A faulty rule is found when it misses an attack.</li>
<li>Coverage is estimated, not checked against the data you collect.</li>
</ul>
</section>
<section class="card card-padded doc-card">
<h3><tide-icon name="clipboard-list" size="18"></tide-icon> Audit effort</h3>
<ul>
<li>Audits ask why each rule exists and why each gap is accepted.</li>
<li>No one record of who changed a rule, and when.</li>
</ul>
</section>
</div>

## What TIDE is

TIDE sits between your SIEMs and the people who decide what to detect. It reads every rule, scores it, maps it to the threats and systems that matter, and records every decision.

<div class="doc-flow">
<section class="card card-padded doc-card">
<h3><tide-icon name="server" size="18"></tide-icon> Your SIEMs</h3>
<p>Elastic SIEMs and their Kibana spaces, with Elastic's and the Sigma rules.</p>
</section>
<span class="doc-flow__arrow"><tide-icon name="arrow-right" size="22"></tide-icon></span>
<section class="card card-padded doc-card doc-card--hub">
<h3><tide-icon name="shield-check" size="18"></tide-icon> TIDE</h3>
<p>Rule Health, Rule Monitoring, scoring, baselines and coverage, in one place.</p>
</section>
<span class="doc-flow__arrow"><tide-icon name="arrow-right" size="22"></tide-icon></span>
<section class="card card-padded doc-card">
<h3><tide-icon name="circle-check" size="18"></tide-icon> Outcomes</h3>
<p>Coverage you can show, evidence for audits, and analyst time saved.</p>
</section>
</div>

<div class="doc-cards">
<section class="card card-padded doc-card">
<h3><tide-icon name="database" size="18"></tide-icon> One place for every rule</h3>
<p>Rules from every linked SIEM and space, side by side.</p>
</section>
<section class="card card-padded doc-card">
<h3><tide-icon name="users" size="18"></tide-icon> People decide</h3>
<p>A person makes every coverage decision and every change TIDE makes in a SIEM, and TIDE records who.</p>
</section>
<section class="card card-padded doc-card">
<h3><tide-icon name="wifi-off" size="18"></tide-icon> Works without the internet</h3>
<p>Everything it needs is built in, so it runs on isolated networks.</p>
</section>
</div>

## One place for every rule

Create, edit and look after rules from every space in one place, instead of moving between consoles.

<div class="doc-cards doc-cards--two">
<section class="card card-padded doc-card">
<h3><tide-icon name="list" size="18"></tide-icon> Every rule in one list</h3>
<p>Rule Health holds every rule from every linked SIEM and space, with its score, state and last validation, as of each sync.</p>
<p class="doc-card__gain"><tide-icon name="check" size="14"></tide-icon> No space left unchecked.</p>
<p class="doc-card__more"><a href="RULES.md#rule-health">Rule Health in the guide</a></p>
</section>
<section class="card card-padded doc-card">
<h3><tide-icon name="arrow-right-left" size="18"></tide-icon> Create, edit and move</h3>
<p>Create, edit and validate rules in TIDE. Move, copy, compare and merge them between destinations, and TIDE checks for a rule already there.</p>
<p class="doc-card__gain"><tide-icon name="check" size="14"></tide-icon> Promote a rule without copying it by hand.</p>
<p class="doc-card__more"><a href="RULES.md#moving-copying-and-linking">Moving, copying and linking in the guide</a></p>
</section>
<section class="card card-padded doc-card">
<h3><tide-icon name="sigma" size="18"></tide-icon> Elastic's and the Sigma rules built in</h3>
<p>Convert a Sigma rule for your SIEM, or deploy one of Elastic's, from TIDE's own libraries.</p>
<p class="doc-card__gain"><tide-icon name="check" size="14"></tide-icon> Over 2,300 of Elastic's rules and over 3,000 Sigma rules ready.</p>
<p class="doc-card__more"><a href="LIBRARIES.md#how-the-library-pages-work">The libraries in the guide</a></p>
</section>
<section class="card card-padded doc-card">
<h3><tide-icon name="git-branch" size="18"></tide-icon> Updates you review first</h3>
<p>When Elastic or Sigma update a rule you use, compare the two section by section and take only what you want.</p>
<p class="doc-card__gain"><tide-icon name="check" size="14"></tide-icon> Your own changes are kept.</p>
<p class="doc-card__more"><a href="RULES.md#updates-from-elastic-and-sigma">Updates from Elastic and Sigma in the guide</a></p>
</section>
</div>

<tide-figures source="rule_health" metrics="total,enabled,validated,quality,last_synced"></tide-figures>

## Rule quality

Know that a rule works before it is needed, and hear about it when it stops.

<div class="doc-cards doc-cards--two">
<section class="card card-padded doc-card">
<h3><tide-icon name="target" size="18"></tide-icon> Every rule scored</h3>
<ul>
<li><strong>Scoring:</strong> each rule is scored against checks you weight for your team.</li>
<li><strong>Fields:</strong> every field a rule uses is checked against your real index mappings.</li>
<li><strong>Validation:</strong> who validated each rule, and when, and which are due again.</li>
</ul>
<p class="doc-card__more"><a href="CLIENTS.md#choose-how-rules-are-scored">Scoring in the guide</a></p>
</section>
<section class="card card-padded doc-card">
<h3><tide-icon name="activity" size="18"></tide-icon> Rule Monitoring</h3>
<ul>
<li><strong>Failures:</strong> failed runs, index patterns that match nothing, missing fields.</li>
<li><strong>Blind windows:</strong> time between runs that a rule never searches.</li>
<li><strong>Rule ids:</strong> rules sharing a rule id, and rules linked to an Elastic rule they don't match.</li>
<li><strong>Who fixes it:</strong> data, the rule's author, Kibana or TIDE, with the fix where TIDE can make it.</li>
</ul>
<p class="doc-card__gain"><tide-icon name="check" size="14"></tide-icon> Problems fixed before an attack slips through.</p>
<p class="doc-card__more"><a href="RULES.md#rule-monitoring">Rule Monitoring in the guide</a></p>
</section>
</div>

<tide-figures source="rule_monitoring" metrics="rules,errors,warnings,causes,resolved"></tide-figures>

## Baselines and coverage

From coverage assumed in spreadsheets to coverage worked out from the rules you have.

<div class="doc-cards">
<section class="card card-padded doc-card">
<h3><tide-icon name="clipboard-list" size="18"></tide-icon> Baselines</h3>
<p>Describe each system you defend and the ATT&amp;CK techniques it should detect.</p>
<ul>
<li>Map rules to techniques.</li>
<li>Build a baseline from a system's technologies, or from a threat actor.</li>
</ul>
<p class="doc-card__more"><a href="SYSTEMS.md#baseline-templates">Baselines in the guide</a></p>
</section>
<section class="card card-padded doc-card">
<h3><tide-icon name="crosshair" size="18"></tide-icon> Gaps you decide on</h3>
<p>Tell a real gap from a decision.</p>
<ul>
<li><strong>Known gap:</strong> a rule is still needed.</li>
<li><strong>Doesn't apply:</strong> the technique can't affect this system.</li>
<li><strong>Coverage that doesn't alert:</strong> logged, not alerted on.</li>
</ul>
<p class="doc-card__more"><a href="SYSTEMS.md#working-with-a-technique">Working with a technique in the guide</a></p>
</section>
<section class="card card-padded doc-card">
<h3><tide-icon name="file-text" size="18"></tide-icon> Reports for audits</h3>
<p>Evidence you can hand over.</p>
<ul>
<li>Coverage for each system.</li>
<li>PDF and Markdown reports.</li>
<li>Every coverage decision recorded, with who made it.</li>
</ul>
<p class="doc-card__more"><a href="SYSTEMS.md#export-a-system-report">Reports in the guide</a></p>
</section>
</div>

<tide-figures source="baselines" metrics="system_baselines,techniques,rules_mapped,fully_covered,uncovered"></tide-figures>

## Threat-informed

Measure detection against how real adversaries behave, and against the intelligence you receive.

<div class="doc-cards doc-cards--two">
<section class="card card-padded doc-card">
<h3><tide-icon name="flame" size="18"></tide-icon> Threat Landscape and Heatmap</h3>
<ul>
<li><strong>Threat actors:</strong> how much of each one's behaviour your rules cover.</li>
<li><strong>Heatmap:</strong> where your rules cluster across ATT&amp;CK, and where they are thin.</li>
</ul>
<p class="doc-card__more"><a href="THREATS.md#threat-landscape">Threat Landscape in the guide</a></p>
</section>
<section class="card card-padded doc-card">
<h3><tide-icon name="globe" size="18"></tide-icon> Intelligence and frameworks</h3>
<p>Built in, or read from your own feeds:</p>
<div class="doc-tags">
<span class="rm-tag rm-tag--system">MITRE ATT&amp;CK</span>
<span class="rm-tag rm-tag--system">NIST 800-53</span>
<span class="rm-tag rm-tag--system">CVEs and CISA KEV</span>
<span class="rm-tag rm-tag--system">OpenCTI</span>
<span class="rm-tag rm-tag--system">Mandiant</span>
<span class="rm-tag rm-tag--system">CrowdStrike</span>
<span class="rm-tag rm-tag--system">TAXII feeds</span>
<span class="rm-tag rm-tag--system">Nessus scans</span>
</div>
<p class="doc-card__more"><a href="THREATS.md#cti">CTI in the guide</a></p>
</section>
</div>

<tide-figures source="threat_landscape" metrics="actors,ttps,coverage,fully_covered,gaps"></tide-figures>

## Built for secure environments

Designed for isolated networks and strict compliance from the start.

<div class="doc-cards doc-cards--two">
<section class="card card-padded doc-card">
<h3><tide-icon name="wifi-off" size="18"></tide-icon> Your data stays with you</h3>
<p>MITRE ATT&amp;CK, NIST 800-53, the Sigma rules, Elastic's rules and the CISA KEV catalogue are built in, so TIDE needs no internet access. It connects only to the services you set up: your SIEMs, single sign-on and threat feeds.</p>
</section>
<section class="card card-padded doc-card">
<h3><tide-icon name="users" size="18"></tide-icon> Clients kept apart</h3>
<p>Each client, a team or a customer, has its own database, users, roles and SIEM destinations. Single sign-on with Keycloak.</p>
</section>
<section class="card card-padded doc-card">
<h3><tide-icon name="clock" size="18"></tide-icon> Every change on record</h3>
<p>Each rule's history records every change, whoever made it and wherever: in TIDE, in Kibana or by an Elastic update.</p>
</section>
<section class="card card-padded doc-card">
<h3><tide-icon name="shield" size="18"></tide-icon> Looks after itself</h3>
<p>Daily backups, once a super admin turns them on; Diagnostics that find known problems and say how to fix them; and an External Query API for other tools.</p>
<p class="doc-card__more"><a href="OPERATIONS.md#scheduled-backups">Backups in the guide</a></p>
</section>
</div>

## Good to know

- **Elastic SIEMs.** TIDE reads and changes rules in Elastic SIEMs: Elasticsearch and Kibana.
- **Rules are read when you sync.** TIDE reads a destination's rules when someone syncs it, so its figures are as current as the last sync. Rule Monitoring says when a destination hasn't been synced for 7 days.
- **Built-in libraries come with each release.** Elastic's rules, the Sigma rules, MITRE ATT&CK, NIST 800-53 and the CISA KEV catalogue are updated with each TIDE release, so upgrading brings the newest.

## Getting the most from TIDE

1. [Link every Kibana space](CLIENTS.md#link-destinations-to-a-client) whose rules TIDE should see.
2. [Sync](RULES.md#sync-rules-from-your-siems) after rules change in Kibana, so your figures are current.
3. Choose [how rules are scored](CLIENTS.md#choose-how-rules-are-scored) and [how long a validation lasts](CLIENTS.md#set-how-long-a-validation-lasts) for your team.
4. Describe your key systems and [apply a baseline](SYSTEMS.md#apply-a-baseline-to-a-system) to each.
5. Review [Rule Monitoring](RULES.md#rule-monitoring) each week, starting with its errors.
6. [Connect your threat feeds](CLIENTS.md#connect-threat-feeds).
7. [Turn on daily backups](OPERATIONS.md#scheduled-backups).

## Recent improvements

In TIDE 6.2:

- **Rule Monitoring** lists every rule that needs action, grouped by what causes it, with who fixes it and how long it has been happening.
- **Blind windows between runs:** rules whose schedule leaves part of every interval unsearched are found.
- **Fix many rules at once** from Rule Monitoring, and finish changes Kibana made but TIDE couldn't record.
- **Compare before you choose:** a custom copy beside one of Elastic's rules, and rules linked to an Elastic rule they don't match.

Every change, release by release, is in the [Changelog](CHANGELOG.md).
