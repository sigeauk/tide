# TIDE demo script: rogue root certificate

For whoever presents TIDE. The demo shows a client that looks covered and isn't: rules that are fine in Kibana but can't work, a noisy rule, a technique covered only half way, and steps with no rule at all. Then you fix it all in TIDE and replay the attack to prove every fix.

**How to read it:**
- Bold is what TIDE shows on screen.
- *Say:* lines are suggestions, not a script to read out.
- `<id>` is the simulation's id, shown on its row in **Simulations → Run**. Its Kibana space is `sim-<id>`.

**You need:**
- **TIDE** with an Elastic SIEM whose API key may make Kibana spaces (see *What its API key needs* in Documentation → Simulations);
- **a client** to run it in: everything the demo adds is removed afterwards.

## The story

A banking trojan reaches a finance user, Bob Smith, through an invoice opened from Outlook on his desktop, we8105desk. It is 24 August 2016, at Wayne Enterprises: the background is real network data from Splunk's Boss of the SOC v1. The attack's events were made for the demo, as Sysmon would have logged them on that desktop.

| Step | What the attacker does | ATT&CK |
|---|---|---|
| 1 | The invoice's macro starts PowerShell from Word | T1566.001 |
| 2 | PowerShell downloads and runs a script (a download cradle) | T1059.001 |
| 3 | certutil fetches the attacker's root certificate | T1105 |
| 4 | The certificate is made a trusted root two ways: certutil into Bob's store (procedure A), PowerShell into the machine's (procedure B, after Bob accepts a UAC prompt) | T1553.004 |
| 5 | The browser's proxy auto-config points at the attacker | T1112 |
| 6 | PDFs are made to open the trojan | T1546.001 |
| 7 | A scheduled task, named as Adobe's updater, starts it at every logon | T1053.005 |
| 8 | The attacker reads Bob's HTTPS traffic through its proxy | T1557 |

## What's wrong at the start, and the fix

| Step | At the start | What TIDE says | The fix |
|---|---|---|---|
| 1 | Elastic's *Suspicious MS Office Child Process* | Covered | Nothing: the part that works |
| 2 | *PowerShell started*, on every PowerShell | Covered, but **Reached the maximum alerts per run**, **Alerts spiked** and **Too many alerts** | Tighten it to the download cradle |
| 3 | *Certificate downloaded with certutil␠*: disabled, a space after its name | No coverage (not counted); **Rule name has spaces around it** | **Remove the spaces**, **Enable** |
| 4 | Sigma's certutil root rule (procedure A), and a known gap for procedure B | Partial coverage | **Deploy** Elastic's registry rule, map it, delete the gap |
| 5 | *Proxy auto-config changed* on Splunk's field `registry_path` | Covered but not effective: **Field not in the index mappings** | Change the field to `registry.path` |
| 6 | No rule | No coverage | **Convert** Sigma's assoc rule, create it, map it |
| 7 | *Scheduled task created at logon*, on Elastic Defend's data, every 10 minutes looking back 5 | Covered but not effective: **No index matches the index pattern**, **Blind windows between runs** | Point it at the Sysmon data, every minute |
| 8 | A known gap: no TLS inspection | Known gap, with its reason and review date | Stays: a decision on record |

## 1. Before the audience (start 15 minutes ahead)

1. **Simulations → Run → Start a simulation:**
   - **SIEM**: the demo SIEM.
   - **Noise**: *Normal*. **Speed**: 10.
   - **Scenario**: *TIDE demo: rogue root certificate*, with everything under **What to do** ticked.
   - **Players**: none (the demo has no questions).
   - **Start simulation**.
2. **Wait for *Playing*,** about 3 minutes: setting up, then the 2-minute first pass, then its sync.
3. **Wait 5 more minutes,** then in **Rule Health** choose **Sync**. By then every rule has run on the data, and the noisy rule has raised enough alerts for Rule Tuning's **Too many alerts**.
4. **Open, each in its own tab:**
   - **Threat Landscape**, with *Banking trojan crew (sim `<id>`)* open;
   - the system *Finance workstations (sim `<id>`)* on **Systems**;
   - **Rule Monitoring** and **Rule Tuning**;
   - Kibana's rules in the simulation's space: **Open its space in Kibana** on the simulation, then Rules.
5. **Check the system's figures:**
   - **Covered 50%** (4 of 8 techniques) and **Effective 25%** (2 not effective);
   - **No coverage 2** (2 unmapped · 1 not counted);
   - **Known gaps 2** (1 partly covered).

   Anything else: see section 12.

## 2. The ask (CISO), 2 minutes

*Say:* "Our CISO's question is trust store integrity. A banking trojan reaches a finance user through an invoice. It installs its own root certificate and points the browser at its proxy, so it can read their HTTPS traffic, the bank's included. Are we covered?"

**Threat Landscape** → *Banking trojan crew (sim `<id>`)*, marked **SIM**. The simulation added it: the attacker, with the attack's 8 techniques.

- **Coverage:** a technique counts as covered as soon as one of your enabled rules is tagged with it. With only the demo's rules that is 5 of the 8.

*Say:* "This is the group we're worried about: eight techniques. Threat Landscape counts five as covered, because we have a rule tagged for each, which is how Kibana's ATT&CK view counts too. Sounds good. Let's ask the question properly."

*Say:* "A baseline can be a group's techniques: **⋮ → Create baseline** here makes one. Or it can be a scenario, as ours is: the steps of this attack, in order, on the systems it would hit."

## 3. Where we stand (Manager), 3 minutes

- **The system:** **Systems** → *Finance workstations (sim `<id>`)*, the baseline *Trust store integrity: banking trojan interception*: one technique for each step of the attack.
- **The figures:** read them out.
  - **Covered 50%**: "Half the steps have a rule."
  - **Effective 25%**: "Only a quarter have a rule that can actually work."
  - **Known gaps 2** and **No coverage 2**.
- **Kibana, for contrast:** its rules list shows the proxy rule (*Proxy auto-config changed*) as succeeding on every run. *Say:* "Kibana says the proxy rule ran fine. TIDE says it can't work. Let's see why."

## 4. Rules that can't work (Engineer), 6 minutes

**Rule Monitoring** lists what Kibana doesn't:

| Rule | Finding | What to say |
|---|---|---|
| *Proxy auto-config changed* | **Field not in the index mappings**: `registry_path` | "Ported from Splunk as written: `registry_path` is Splunk's field. In our data it's `registry.path`. Kibana runs it every minute and it never matches, silently." |
| *Scheduled task created at logon* | **No index matches the index pattern**; **Blind windows between runs** | "Written for Elastic Defend's data, which we don't collect, and run every 10 minutes looking back 5, so half of every interval is never searched." |
| *Certificate downloaded with certutil␠* | **Rule name has spaces around it** (info) | "The team's own rule: someone left it disabled, and a space after its name." |
| *PowerShell started* | **Reached the maximum alerts per run** | "This one works too well: it stops at Kibana's 100-alert cap every run." (section 6) |

**The fixes**, each in its rule's window (open it from the finding). TIDE writes each one to Kibana and records it in the rule's **History**.

- **Proxy rule:**
  1. **Edit** → **Define rule**: change the query to `registry.path : *AutoConfigURL*`.
  2. **Reason for change**: "Its field was Splunk's: ECS calls it registry.path." Save.
- **Scheduled task rule:**
  1. **Edit** → under **Index patterns**, tick **Use the default index** (`logs-*-sim<id>`, the simulation's data).
  2. **Schedule**: **Run every** `1m`, **Look back** `now-6m`.
  3. Give a reason, and save.
- **certutil rule:**
  1. On Rule Monitoring's *Rule name has spaces around it*, choose **Remove the spaces**.
  2. Enable the rule: in **Rule Health**, tick it and choose **Enable**. Or **Edit** → **Status**: *Enabled*, with a reason.

*Say:* "None of these was visible in Kibana as a problem. Each was one edit, made in TIDE and recorded."

## 5. Close the gaps (Engineer), 6 minutes

**Step 4, *Rogue root certificate installed*: Partial coverage.**
1. Open it. Its **Coverage** has the Sigma rule *New Root Certificate Installed Via Certutil.EXE*, and a known gap: "Procedure B: a root certificate added to the machine's store, by PowerShell or straight in the registry."
   *Say:* "Kibana's ATT&CK coverage counts T1553.004 as covered because one rule carries the tag. TIDE says partly: the attacker can do it two ways, and we watch one."
2. **Elastic rules** → *Creation or Modification of Root Certificate* → **⋮ → Deploy**.
   - In the form, under **Index patterns**, tick **Use the default index** (`logs-*-sim<id>`). Elastic's own patterns search every namespace on the SIEM.
   - **Status**: *Enabled*, **Run every** `1m`, **Author**: your name.
   - **Deploy rule**.
3. Once the sync after saving finishes: **Coverage ⋮ → Add coverage → Rule (alerting)**, search *Root Certificate*, and pick the new rule.
4. The gap's **⋮ → Delete**. Its reason stays in the technique's **History**.

**Step 6, *PDFs made to open the payload*: No coverage.**
1. Open it, then **Sigma rules** → *Change Default File Association Via Assoc* → **⋮ → Convert**.
2. Choose the pipeline *ECS Windows*.
3. In the **Create rule** form, the query is filled in for you:
   - **Create rule**: the destination *Simulation `<id>`* (its index patterns follow, `logs-*-sim<id>`);
   - **Status**: *Enabled*, **Run every** `1m`, **Author**: your name, and a reason;
   - **Create rule**.
4. Map it from **Coverage**, as in step 4.

**Step 8, *HTTPS read through the attacker's proxy*: Known gap.** Open it.

*Say:* "There's no TLS inspection, so the interception itself can't be seen. That's accepted, on record, with who accepted it and a review date. A gap with a reason is a decision; a gap without one is an accident."

## 6. Tuning, 3 minutes (45-minute version)

- **Rule Tuning:** *PowerShell started* shows **Too many alerts** and **Alerts spiked**. *Say:* "Most of these are the Splunk forwarder's own PowerShell, on every server. Alerts like these bury the real ones."
- **In its window:**
  1. **Record outcome…**: **Outcome** *Benign true positive* (the forwarder's own PowerShell: expected, but no use to the SOC), **Alerts** 100, and **Needs tuning** ticked.
  2. **Edit**:
     - **Rule name**: *PowerShell download cradle*;
     - **Index patterns**: the Sysmon data only, `logs-windows.sysmon_operational-sim<id>`;
     - the query: `event.type : "start" and process.name : "powershell.exe" and process.command_line : (*DownloadString* or *Net.WebClient*)`;
     - and a reason.
  3. **Mark as tuned…**.
- **If the client has GitLab:** **Raise issue** on the rule shows how a finding becomes someone's task.
- **What stays:** both Rule Tuning findings stay on the tuned rule. They describe the alerts it raised today, and **Mark as tuned…** says TIDE shows the effect after 14 days.

In the 20-minute version, leave the rule as it is. It counts as covered and effective, because a noisy rule still works.

## 7. Prove it, 5 minutes

1. **Simulations → Run** → the simulation → **Replay again…** on its row → **Replay again**. *Say:* "The same attack, again, stamped now. A rule only looks a few minutes back, so the rules we just fixed never saw the first one."
2. **Wait for it:** about 2 minutes, while it shows *Replaying*. It's back to *Playing* once the data is in and the sync is done.
3. **Wait a minute for the 1-minute rules to run,** then **Rule Health → Sync**.
4. **The system's figures:**
   - **Covered 88%** (7 of 8) and **Effective 88%** (7 of 8);
   - **No coverage 0**;
   - **Known gaps 1**, the interception.
5. **Kibana's alerts in the space:** each fixed rule has fired on the second pass. And **Threat Landscape**: the crew is now 8 of 8 covered. Elastic's root certificate rule is also tagged Adversary-in-the-Middle (T1557), yet the system still shows the interception as a known gap. *Say:* "The tag says we catch the interception. We don't: the rule sees the certificate go in, not the traffic being read. TIDE keeps the gap on record."
6. **⋮ → Export report** on the system: the coverage, each technique's state, what covers it and its rules' health, ready for the CISO.

*Say:* "We didn't just write rules. We proved each one fires on the attack, and the report says so. And the lesson of the last step: an ATT&CK id on a rule isn't coverage. Know the procedures you need to catch, because one technique can have many."

## 8. Talking points

- **An ATT&CK id isn't coverage.** A tag says what a rule relates to, not which procedure it catches. Install Root Certificate (T1553.004) is two procedures here, certutil and the registry, and needs a rule for each. Adversary-in-the-Middle (T1557) is tagged on a rule that can't see the interception at all. Know the specific procedures, and expect many for one technique: TIDE's baseline techniques are procedures, each with its own rules and gaps.
- **Covered isn't effective.** A rule can be enabled, mapped and green in Kibana, and still never match. Threat Landscape said 5 of 8 at the start; the system said 2 worked. At the end the tags say 8 of 8; the system, rightly, 7.
- **Findings Kibana doesn't raise:** a field the data doesn't have, an index that doesn't exist, gaps between runs, names that break searches.
- **Known gaps are decisions,** with a reason, who made them and when to look again.
- **Every change is a person's.** It is recorded in History, and made in Kibana through TIDE, never behind its back.
- **Proof over assertion:** replay the attack, and see each rule fire.

## 9. Questions audiences ask

- **Is the data real?**
  - The background is real: Splunk's Boss of the SOC v1, a public dataset (CC0) of a company's network on 24 August 2016.
  - The attack's 26 events were made for the demo, as Sysmon would have logged them on that desktop.
- **Does TIDE change our rules on its own?** No. Each change here was someone's, made through TIDE into Kibana and recorded.
- **Where do the Sigma and Elastic rules come from?** Both libraries, and MITRE ATT&CK, are bundled in TIDE. It needs no internet.
- **What makes a rule not effective?** Any error Rule Monitoring finds, a field the rule matches on that no index has, or one that's never filled, or a rule that has never run.
- **How often does TIDE check?** At each sync: when someone chooses Sync, or in the maintenance window if a super admin turns it on.
- **Can we run this on our own SIEM?** Yes: the simulation makes its own space, replays into its own data streams, and Clean up removes it all.

## 10. The 20- and 45-minute versions

| | 20 minutes | 45 minutes |
|---|---|---|
| 2. The ask | 2 | 3 (and **Create baseline** from the crew) |
| 3. Where we stand | 3 | 5 (Kibana side by side) |
| 4. Rules that can't work | 5: the proxy rule, the scheduled task rule, and the certutil rule's **Remove the spaces** and **Enable** | 8: all three, and History |
| 5. Close the gaps | 5: step 4 (Deploy, Partial → covered) | 10: steps 4 and 6, and step 8's gap |
| 6. Tuning | skipped | 5, with Raise issue if there is GitLab |
| 7. Prove it | 5 | 7, with the report |
| Questions | | 7 |
| **End figures** | **Covered 75%** (6 of 8), Effective 75%, No coverage 1 (step 6 isn't fixed) | **Covered 88%** (7 of 8), Effective 88% |

In the 20-minute version, Sigma's assoc rule (step 6) is left out: *PDFs made to open the payload* stays **No coverage**, which is a fair point to end on ("the next one on the list"). Keep step 3 in even when short of time: without it the figures end on 5 of 8, which shows as 62%.

## 11. Resetting between demos

1. On the simulation: **End simulation**, then **Clean up**. This removes its space, data and alerts, the system, the baseline, and its rules, those made during the demo too.
2. **Clear results**.
3. Start a new one, as in section 1, at least 15 minutes before the next audience.

Two simulations can't set up, replay or clean up on the same SIEM at once.

## 12. When something misbehaves

| You see | Why | Do |
|---|---|---|
| The figures don't match section 1 | A rule hasn't run on the data yet, or the last sync was too early | Wait a minute, then **Rule Health → Sync** |
| No **Too many alerts** on Rule Tuning | It needs about 700 alerts: a few minutes into the first pass | Wait, and **Sync**. **Alerts spiked** shows the same story |
| A fixed rule is still not effective | It hasn't run since the fix | Wait a minute, then **Sync this rule** in its window |
| The deployed root certificate rule shows **No recent events in the index pattern** | **Use the default index** wasn't ticked, so it searches Elastic's own patterns on every namespace | **Edit** → under **Index patterns**, tick **Use the default index** |
| The converted Sigma query names `Image` or `CommandLine` | The wrong pipeline | **Convert** again with *ECS Windows* |
| A new rule isn't in **Add coverage**'s list | The sync after saving it hasn't finished | Wait for it, then search again |
| No **Replay again…** button | It is still setting up | Wait for *Replaying* or *Playing* |
| The simulation says *Interrupted* | TIDE restarted while it ran | **End simulation**, **Clean up**, start again |
| A fixed rule's alerts include some from the first pass | A rule's first run looks back 6 minutes, so a rule made soon after a pass sees it | Nothing: count the second pass's (`botes.replay.loop : 2` in Kibana) |
| The start fails with *Could not make the space* | The SIEM's key can't manage spaces | Use a key with the privileges in *What its API key needs* (Documentation → Simulations) |
| *Banking trojan crew* isn't on **Threat Landscape** | The set-up couldn't add it: **In TIDE** on the simulation says why | Start the simulation again; meanwhile open the system straight away (section 3) |

---

This script goes with the scenario in this folder (`scenario.toml`, `tide.toml`, `rules.toml`): the figures above are what those files set up. *The TIDE demo*, in Documentation → Simulations, describes the same demo in short.
