# Simulations

A simulation replays a recorded attack into your SIEM as if it were happening now, in a Kibana space made for it, with detection rules that watch it. The people you choose investigate it in Kibana and answer questions about it in TIDE. It is a way to train your analysts on a real attack, and to see which rules catch it, without touching your own data or rules.

TIDE comes with two attacks from Splunk's Boss of the SOC v1 (public domain): the defacement of a company's website (18 questions) and Cerber ransomware spreading from a desktop to a file share (14 questions).

## Who runs them

A simulation is started and ended by a **Sim Admin**: a role beside Admin, Analyst and Engineer that a super admin gives someone on a client, in the client's **Assigned users**. Admins can run simulations too. Analysts and engineers can't, unless an admin changes the client's **Role Templates**. Anyone the Sim Admin chooses can play one.

## The Simulations page

**Simulations** in the sidebar has three tabs:

- **Run** starts simulations and lists the client's, newest first. Choose a row to open it below the list.
- **Dashboard** shows how a simulation's players are doing: each player's score over time, the **Board**, how each question went, by its number with its words on hover (how many solved it, who first, the hints taken and the wrong answers), and how many alerts each rule raised. It updates itself while the simulation runs.
- **Answers** shows a simulation's questions, each with its answer (in blue), the searches that find it in that simulation's data (each in a box named for its language, KQL, ES|QL or EQL, and coloured as a rule's query is), and what its rules do with that step. Players never see the notes on the rules.
  - **Save in Kibana** saves a question's KQL and ES|QL searches in the simulation's space, named after the question, so they open in Discover on the simulation's data and its time so far. Saving them again replaces them, and cleaning the simulation up deletes them with its space. Discover can't save an EQL search; copy it into the Correlation tab of a Timeline in Kibana instead.

**Dashboard** and **Answers** open on the simulation that is running, or the latest; **Simulation** above them picks another. A simulation you start shows there straight away. Their sections, and each question on **Answers**, fold by their heading, and stay as you left them.

### Start a simulation

Under **Start a simulation**:

1. **SIEM**: which Elastic SIEM to make the simulation's space on. Any Elastic SIEM set up in TIDE with its Elasticsearch URL, its Kibana URL and an API key can be chosen (see [What its API key needs](#what-its-api-key-needs)); the client doesn't need to be linked to it, as the simulation's space becomes one of the client's destinations.
2. **Noise**: how much ordinary traffic the attack hides in. *Quiet* is the attack window alone; *Normal* adds the routine events of the same minutes; *Busy* also adds the half hour either side, and the same network's traffic from earlier that day, so the attack is harder to find.
3. **Speed**: how many times faster than it happened. At 10, an hour of the attack takes six minutes; at 0 it goes as fast as your SIEM takes it.
4. **Scenarios**: one or more, replayed one after the other.
5. **Players**: the client's users who answer its questions.
6. **Start simulation**.

TIDE makes a Kibana space for the simulation on the SIEM, with a data view on its own logs and the scenario's detection rules, which search only the simulation's own logs. Then it sets the simulation up in the client, and replays the attack into the space. Your players see the space with the Kibana access they already have, so give them access to every space, or add the simulation's space to their Kibana roles.

### What it sets up in the client

Until it is cleaned up, the simulation is part of the client like anything else:

- Its space is one of the client's destinations, named *Simulation* and its id, and its rules are synced in, so they show in **Rule Health**, **Rule Monitoring** and the dashboards.
- Each scenario's attack is a baseline, such as *Web defacement: Po1s0n1vy*, and the systems it hit are systems, such as *imreallynotbatman.com*, with their devices. Their names end with the simulation's id.
- Each system has the baseline applied and counts the simulation's destination as its coverage. Each of the scenario's rules is mapped to the technique it is there to catch, and a step nothing catches is recorded as a known gap. A system's **Covered** and **Effective** figures then show how much of the attack the rules catch. As on any SIEM, a rule that is disabled doesn't count, and one that **Rule Monitoring** finds can't work isn't effective.
- Elastic's rules are copies under rule ids of their own, as **Deploy** makes them, so Elastic's own rules can still be installed in the space.
- Where a scenario names its attacker, as the TIDE demo does, the attacker is a threat actor on **Threat Landscape**, marked SIM, with the attack's techniques. A threat sync leaves it there, and Clean up removes it.

Everything it adds counts in the client's figures, so keep a client for exercises and run simulations there. The simulation lists what it set up under **In TIDE**, with any problem it met.

### Following it

An open simulation shows what it is doing (setting up, replaying, playing once the replay is done), how many events it has sent, and how far through the attack's original time it is. **Open its space in Kibana** goes straight to its alerts. Below are what it set up **In TIDE**, the **Board**, and the **Rules** and how many alerts each raised.

One simulation at a time can set up, replay or clean up on a SIEM. If TIDE restarts during one, it shows as *Interrupted*: end it (or clean it up) again.

### Replaying its data

Once the replay is done, **Replay data** sends the simulation's logs again, stamped with the time they are sent. Detection rules only look a few minutes back, so a rule made or fixed after the first replay never saw the attack: replaying the data shows whether it catches it now. The players can go on answering meanwhile. Kibana keeps every replay, and the field `botes.replay.run_id` tells them apart. Once it is done, the simulation's rules are synced again, as after the first replay.

### Ending it, and cleaning up

**End simulation** stops the replay if it is still running, stops the players answering (their **Simulation** goes), and counts each rule's alerts. Everything else stays: its space with its rules, logs and alerts on the SIEM, and what it set up in the client, so you can go through it with the players afterwards.

**Clean up**, once it has ended, removes what it set up in the client (its systems, its baselines, and its destination with its rules) and deletes what it made on the SIEM: its space with its rules and data view, its logs and their template, and its alerts. If something can't be removed, the simulation says so and **Clean up again** tries once more. The logs also delete themselves after seven days, in case a simulation is never cleaned up.

The results (the board, the answers given, the rules and their alerts) stay in TIDE until you **Clear results**, once it is cleaned up.

## The TIDE demo

*TIDE demo: rogue root certificate* is a scenario for showing TIDE to others rather than for training, so it has no questions. A banking trojan, opened from an invoice on a finance desktop, adds its own root certificate and points the browser at its proxy, hidden in the routine traffic of the same morning. Its system, *Finance workstations*, starts as many do:

- one rule that works, and one that raises far too many alerts on routine PowerShell;
- a rule someone left disabled, with a space after its name;
- rules that look fine in Kibana but can't work: one searches a field the data doesn't have, another data the SIEM never receives, with gaps between its runs;
- a technique done two ways with a rule for only one, recorded as a known gap, so it is partly covered;
- two techniques with no rule at all;
- the interception itself, which nothing can see, recorded as a known gap with its reason and a review date.

Start it before your audience arrives, with **Noise** *Normal*, **Speed** 10 and one player: setting up and the first replay take a few minutes. Begin on **Threat Landscape** with its attacker, *Banking trojan crew*: its techniques are the attack's, and it counts most of them as covered because a rule is tagged with each. Then show what TIDE finds that Kibana doesn't, in **Rule Monitoring**, **Rule Tuning** and the system's **Covered** and **Effective** figures. Fix each rule in its window, and for each technique without a rule, **Deploy** one of Elastic's rules or **Convert** a Sigma rule from the technique's window, then map it. **Replay data** sends the attack again: every fixed rule fires on it, and the system shows 7 of its 8 techniques covered and effective, with the interception still a known gap on record.

## The air-gap demo

*TIDE demo: USB, insider and rogue device* is a second demo, with no questions and no routine traffic: only the attack's events. On an air-gapped design network, a contractor's USB stick runs a DLL, a Raspberry Pi behind a printer answers DHCP and collects a service account's password, and the drawings leave on the same stick. Its system, *Engineering enclave*, starts with:

- three rules that work;
- a rule someone left disabled, and one written for data the network hasn't (Elastic Defend's), so its index pattern matches nothing;
- a known gap whose reason the data shows is no longer true ("USB storage is blocked by Group Policy");
- steps with no rule at all, one of them, the rogue device, with no rule in Elastic's or Sigma's library that runs on this stack.

Fix the two rules (the second with **Use the default index**), **Deploy** or **Convert** a rule from the libraries for the steps without one, and for the rogue device add a hunt under **Coverage** and make a rule from it with **Create rule**. **Replay data** sends the attack again, and every fixed rule fires on it: the system ends with all 9 techniques covered and effective. The presenter's script is `sim/scenarios/airgap/DEMO_SCRIPT.md`.

## Playing a simulation

**Simulation** appears in the sidebar as soon as a simulation you are a player in starts, and goes when it ends. While it sets up you can read the questions; answers open when the replay starts. It has two tabs: **Questions** shows each scenario's story, **Open the space in Kibana**, and its questions, each of which folds by its text and stays as you left it; **Dashboard** shows each player's score over time, the **Board**, and how many players have solved each question.

- Type your answer and choose **Answer**. Answers aren't case-sensitive, and quotes and extra spaces don't matter. Wait a moment between answers.
- **Hint** shows one of the question's hints, and costs a quarter of its points, whether you answer it or not.
- Once you have answered a question, **How to find it** shows the searches that find the answer, ready to paste into Kibana's Discover.
- The **Board** ranks the players by their points, less the hints they took.

## What its API key needs

A simulation uses the SIEM's own API key (the one set up with it in **Integrations**). On top of what TIDE needs for its rules, it needs:

- in Elasticsearch: `manage_index_templates`, and on `logs-*-sim*`: `create_index`, `auto_configure`, `write`, `read`, `view_index_metadata` and `delete_index`;
- in Kibana: to manage spaces, and to create data views and detection rules in them.

A simulation that can't do one of these stops and says what it couldn't do; ending it and cleaning it up removes only what it had made.
