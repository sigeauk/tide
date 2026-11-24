# TIDE demo script: USB, insider and rogue device

For whoever presents TIDE. The demo shows an air-gapped network that looks safe and isn't: a gap accepted for a reason that's no longer true, rules that can't work, and steps with no rule at all, one of them with no rule anywhere for your stack. Then you fix it all in TIDE, hunt what no library covers, and replay the attack to prove every fix.

**How to read it:**
- Bold is what TIDE shows on screen.
- *Say:* lines are suggestions, not a script to read out.
- `<id>` is the simulation's id, shown on its row in **Simulations → Run**. Its Kibana space is `sim-<id>`.

**You need:**
- **TIDE** with an Elastic SIEM whose API key may make Kibana spaces (see *What its API key needs* in Documentation → Simulations);
- **a client** to run it in: everything the demo adds is removed afterwards;
- **yourself as one of the client's users,** so you can be its player.

## The story

Halcyon Marine designs warships on an engineering network with no internet connection. A contractor, c.morgan, wants the drawings of the Typhoon class. It is 12 March 2026. The events were made for the demo, as the workstation's Sysmon and Security log and the network sensor would have recorded them. There is no background traffic: every event is the attack's.

| Step | What happens | ATT&CK |
|---|---|---|
| 1 | His USB stick is plugged into ENG-WS07 | T1200 |
| 2 | He opens `Drawings.lnk` on it: rundll32 runs a DLL from the stick | T1204.002, T1218.011 |
| 3 | The DLL lists the drives and the domain's admins | T1120, T1069.002 |
| 4 | A Raspberry Pi he hid behind a printer answers a laptop's DHCP before the domain controller does | T1557.003 |
| 5 | With svc_eng's password, which the Pi collected, runas /netonly gives him a shell as svc_eng | T1078.002, T1550.002 |
| 6 | The drawings are copied from the file server's D$ share | T1039, T1021.002 |
| 7 | They are put in an archive with a password | T1560.001 |
| 8 | The archive is written to the stick | T1052.001 |
| 9 | The Security log is cleared | T1070.001 |

## What's wrong at the start, and the fix

| Step | At the start | What TIDE says | The fix |
|---|---|---|---|
| 1 | A known gap: "USB storage is blocked by Group Policy" | **Known gap** | The data shows a stick recognised: **Convert** Sigma's USB rule, map it, delete the gap |
| 2 | No rule | **No coverage** | **Deploy** Elastic's *Suspicious Execution from a Mounted Device* |
| 3 | Elastic's *Peripheral Device Discovery* | **Covered**, effective | Nothing |
| 4 | No rule, and Elastic's needs stack 9.4 | **No coverage** | A hunt under **Coverage**, **Run**, then **Create rule** |
| 5 | Sigma's *Successful Overpass the Hash Attempt* | **Covered**, effective | Nothing |
| 6 | Sigma's admin share rule, left disabled | **No coverage** (not counted) | **Enable** it |
| 7 | No rule | **No coverage** | **Deploy** Elastic's *Encrypting Files with WinRar or 7z* |
| 8 | A custom rule written for Elastic Defend's data | **Covered** but not effective: **No index matches the index pattern** | **Edit** → **Use the default index** |
| 9 | Elastic's *Clearing Windows Event Logs* | **Covered**, effective | Nothing |

## 1. Before the audience (start 10 minutes ahead)

1. **Simulations → Run → Start a simulation:**
   - **SIEM**: the demo SIEM.
   - **Noise**: any: the scenario has none. **Speed**: 10.
   - **Scenarios**: *TIDE demo: USB, insider and rogue device* only (untick any other).
   - **Players**: yourself.
   - **Start simulation**.
2. **Wait for *Playing*,** about 3 minutes: setting up, the first pass, then its sync.
3. **Wait 2 more minutes,** then in **Rule Health** choose **Sync**. By then every rule has run on the data.
4. **Open, each in its own tab:**
   - **Threat Landscape**, with *Rogue contractor (sim `<id>`)* open;
   - the system *Engineering enclave (sim `<id>`)* on **Systems**;
   - **Rule Monitoring**;
   - Kibana in the simulation's space: **Open its space in Kibana** on the simulation.
5. **Check the system's figures:**
   - **Covered 44%** (4 of 9 techniques) and **Effective 33%** (1 not effective);
   - **No coverage 4** (3 unmapped · 1 not counted);
   - **Known gaps 1**.

   Anything else: see section 10.

## 2. The ask (CISO), 2 minutes

*Say:* "Our design network has no internet connection. People say that makes it safe. The threat isn't someone breaking in: it's someone already inside, with a USB stick and a device of their own. What stops them taking the drawings out?"

**Threat Landscape** → *Rogue contractor (sim `<id>`)*, marked **SIM**: the attacker, with the attack's 13 ATT&CK techniques. Its **Coverage** counts **4 of 13** covered, because an enabled rule is tagged with each.

*Say:* "That's how Kibana's ATT&CK view counts too: a rule tagged with the id. Let's ask the question step by step instead."

## 3. Where we stand (Manager), 3 minutes

- **The system:** **Systems** → *Engineering enclave (sim `<id>`)*, the baseline *Air-gapped design network: insider with a USB stick and a rogue device*: one technique for each step.
- **The figures:** read them out.
  - **Covered 44%**: "Four steps have a rule."
  - **Effective 33%**: "Three have a rule that can actually work."
  - **No coverage 4** and **Known gaps 1**.

## 4. What isn't what it seems (Engineer), 5 minutes

- **Step 8, *Archive written to the USB*:** **Rule Monitoring** lists *Archive written to removable drive* under **No index matches the index pattern**: `logs-endpoint.events.file-sim<id>`.
  *Say:* "Written for Elastic Defend's file events. Our endpoints run Sysmon. Kibana runs it every minute and it never finds a thing."
  1. Open the rule → **Edit** → under **Index patterns**, tick **Use the default index** (`logs-*-sim<id>`, the destination's own).
  2. A reason, and save.
- **Step 6, *Design drawings copied from the file server's admin share*:** its rule is there and disabled, so it isn't counted.
  *Say:* "Tested once, too noisy then, never switched back on."
  - In **Rule Health**, tick *SIGMA - Copy From Or To Admin Share Or Sysvol Folder* and choose **Enable**. Or **Edit** → **Status**: *Enabled*, with a reason.
- **Step 1, *USB storage plugged into an engineering workstation*:** a known gap. Open it and read its reason: "USB storage is blocked by Group Policy on the engineering workstations, so no rule is needed for it."
  - In Kibana's Discover on the space, search `event.code : 6416`: a *SanDisk Cruzer Blade USB Device*, recognised at 09:02. *Say:* "The policy the gap relies on isn't doing its job. A gap's reason is a claim: check it."
  1. In the technique's window, under **Sigma rules**, *External Disk Drive Or USB Storage Device Was Recognized By The System* → **⋮ → Convert**, pipeline *ECS Windows*.
  2. In the **Create rule** form, tick **Use the default index**; **Status** *Enabled*, **Run every** `1m`, **Author** your name, and a reason. **Create rule**.
  3. Once the sync after saving finishes: **Coverage ⋮ → Add coverage → Rule (alerting)**, search *External Disk*, pick it.
  4. The gap's **⋮ → Delete**. Its reason stays in the technique's **History**.

## 5. Close the gaps (Engineer), 8 minutes

**Steps 2 and 7: rules from Elastic's library.** For each, open the technique:
- Step 2, *A shortcut on the USB runs a DLL*: under **Elastic rules**, *Suspicious Execution from a Mounted Device* → **⋮ → Deploy**.
- Step 7, *Drawings archived with a password*: *Encrypting Files with WinRar or 7z* → **⋮ → Deploy**.

In each form, under **Index patterns**, tick **Use the default index**. Elastic's own patterns search every namespace on the SIEM. **Status** *Enabled*, **Run every** `1m`, **Author** your name, **Deploy rule**. Once the sync finishes, map it: **Coverage ⋮ → Add coverage → Rule (alerting)**.

**Step 4, *A rogue device answers DHCP*: no rule anywhere for this stack.**
1. Open it. **Elastic rules** suggests *Multiple DHCP Servers Responding to the Same Transaction*; its **⋮ → Deploy** warns that it needs Elastic 9.4 or later. *Say:* "Elastic wrote that rule for stack 9.4. We run 8.19. The tag is in the library, but it isn't coverage here." **Hunting** has none for it either. Cancel the deploy.
2. **Coverage ⋮ → Add coverage**, **Type** *Hunt (non-alerting)*:
   - **Title**: `Two DHCP servers answer one request`;
   - **ES|QL query**:
     ```
     FROM logs-network_traffic.dhcpv4-*
     | WHERE dhcpv4.option.message_type IN ("offer", "ack")
     | STATS servers = COUNT_DISTINCT(dhcpv4.option.server_identifier), answered_by = VALUES(dhcpv4.option.server_identifier), client = VALUES(dhcpv4.client_mac) BY dhcpv4.transaction_id
     | WHERE servers > 1
     ```
   - **Rationale**: "Elastic's rule needs 9.4. Run daily until a rule is in place." **Add**.

   The technique shows **Covered**, **Non-alerting**.
3. The hunt's **⋮ → Run**: **1 hit**, transaction `0x5e1f2a90`, answered by `10.40.1.10` and `10.40.12.250`. *Say:* "Our domain controller, and a device we don't own. On an air-gapped network there's nothing else to see it with: no agent on a Raspberry Pi."
4. The hunt's **⋮ → Create rule**: the rule form opens as an ES|QL rule with the hunt's query. **Status** *Enabled*, **Run every** `1m`, **Author** your name. **Create rule**. Once the sync finishes, map it as above. The hunt can stay as well: a person still looks.

*Say:* "No library covered this on our stack. A hunt found it today, and the rule catches it from now on."

## 6. Prove it, 5 minutes

1. **Simulations → Run** → the simulation → **Replay data**. *Say:* "The same attack, stamped now. The rules we just fixed never saw the first one."
2. **Wait for it:** about 2 minutes, while it shows *Replaying*. It's back to *Playing* once the data is in and the sync is done.
3. **Wait a minute for the 1-minute rules to run,** then **Rule Health → Sync**.
4. **The system's figures:**
   - **Covered 100%** (9 of 9) and **Effective 100%**;
   - **No coverage 0**, **Known gaps 0**.
5. **Kibana's alerts in the space:** each step's rule has fired on the second pass. The hunt's rule may show two: an ES|QL rule that counts raises one on each run while the transaction is in its look-back.
6. **Threat Landscape:** *Rogue contractor* is now **11 of 13** covered by tags, while the system says every step is caught. *Say:* "The tags and the steps don't agree, and the steps are the ones to trust: a technique is covered when its procedure is caught."
7. **⋮ → Export report** on the system: the coverage, each technique's state, what covers it and its rules' health.

## 7. Talking points

- **An air gap moves the threat, it doesn't remove it.** Removable media brings tools in and takes data out; a device plugged into a spare port sees the traffic no agent watches.
- **A library tag isn't coverage on your stack.** Elastic's rogue DHCP rule needs 9.4. Its pass-the-hash rule is a new terms rule. Its hidden share rule can't fire on Sysmon's events at all. TIDE judges the rule against your data, not its tag.
- **One detection's false positive is another's attack.** Sigma's *Successful Overpass the Hash Attempt* lists "runas /netonly" as its false positive. Here it is how the stolen password was used.
- **A known gap is a claim to check.** "USB storage is blocked by Group Policy" was the reason; the 6416 event says otherwise.
- **Hunt what no rule covers yet,** record it as coverage so it's on the books, and turn it into a rule once you know what to alert on.
- **Proof over assertion:** replay the attack, and see each rule fire.

## 8. Questions audiences ask

- **Is the data real?** Made for the demo: 31 events, as ENG-WS07's Sysmon and Security log and the network sensor's DHCP would record them. Halcyon Marine and its people are made up.
- **Does TIDE need the internet?** No. The Sigma and Elastic libraries, the hunts and MITRE ATT&CK are bundled in TIDE.
- **Why not deploy Elastic's DHCP rule?** It needs stack 9.4. On 9.4 or later, deploy it and keep the hunt as a second pair of eyes.
- **Does TIDE change our rules on its own?** No. Each change here was someone's, made through TIDE into Kibana and recorded in **History**.
- **Can we run this on our own SIEM?** Yes: the simulation makes its own space, replays into its own data streams, and **Clean up** removes it all.

## 9. Resetting between demos

1. On the simulation: **End simulation**, then **Clean up**. This removes its space, data and alerts, the system, the baseline, the threat actor and its rules, those made during the demo too.
2. **Clear results**.
3. Start a new one, as in section 1, at least 10 minutes before the next audience.

Two simulations can't set up, replay or clean up on the same SIEM at once.

## 10. When something misbehaves

| You see | Why | Do |
|---|---|---|
| The figures don't match section 1 | A rule hasn't run on the data yet, or the last sync was too early | Wait a minute, then **Rule Health → Sync** |
| A fixed rule is still not effective | It hasn't run since the fix | Wait a minute, then **Sync this rule** in its window |
| A deployed rule shows **No recent events in the index pattern** | **Use the default index** wasn't ticked, so it searches Elastic's own patterns | **Edit** → under **Index patterns**, tick **Use the default index** |
| The hunt finds nothing | **Run on** or **Time** under **Hunting** points elsewhere | Choose the simulation's destination and *Last 24 hours*, and run it again |
| The converted Sigma query names `ClassName` without `winlog.event_data` | The wrong pipeline | **Convert** again with *ECS Windows* |
| A new rule isn't in **Add coverage**'s list | The sync after saving it hasn't finished | Wait for it, then search again |
| No **Replay data** button | The first pass isn't done | Wait for *Playing* |
| The simulation says *Interrupted* | TIDE restarted while it ran | **End simulation**, **Clean up**, start again |
| *Rogue contractor* isn't on **Threat Landscape** | The set-up couldn't add it: **In TIDE** on the simulation says why | Start the simulation again; meanwhile open the system straight away (section 3) |

Checked end to end on a SIEM by `test/sim_airgap_live.py`: the figures above are its.
