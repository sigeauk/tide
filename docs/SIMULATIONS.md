# Simulations

A simulation replays a recorded attack into your SIEM as if it were happening now, in a Kibana space made for it, with detection rules that watch it. The people you choose investigate it in Kibana and answer questions about it in TIDE. It is a way to train your analysts on a real attack, and to see which rules catch it, without touching your own data or rules.

TIDE comes with two attacks from Splunk's Boss of the SOC v1 (public domain): the defacement of a company's website (18 questions) and Cerber ransomware spreading from a desktop to a file share (14 questions).

## Who runs them

A simulation is started and ended by a **Sim Admin**: a role beside Admin, Analyst and Engineer that a super admin gives someone on a client, in the client's **Assigned users**. Admins can run simulations too. Analysts and engineers can't, unless an admin changes the client's **Role Templates**. Anyone the Sim Admin chooses can play one.

## The Simulations page

**Simulations** in the sidebar has three tabs:

- **Run** starts simulations and lists the client's, newest first. Choose a row to open it below the list.
- **Dashboard** shows how a simulation's players are doing: each player's score over time, the **Board**, how each question went (how many solved it, who first, the hints taken and the wrong answers), and how many alerts each rule raised. It updates itself while the simulation runs.
- **Answers** shows a simulation's questions, each with its answer, the searches that find it in that simulation's data, and what its rules do with that step. Players never see the notes on the rules.

**Dashboard** and **Answers** open on the simulation that is running, or the latest; **Simulation** above them picks another.

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
- Each system has the baseline applied and counts the simulation's destination as its coverage. Each of the scenario's rules is mapped to the technique it is there to catch, and a step nothing catches is recorded as a known gap. A system's **Covered** and **Effective** figures then show how much of the attack the rules catch.

Everything it adds counts in the client's figures, so keep a client for exercises and run simulations there. The simulation lists what it set up under **In TIDE**, with any problem it met.

### Following it

An open simulation shows what it is doing (setting up, replaying, playing once the replay is done), how many events it has sent, and how far through the attack's original time it is. **Open its space in Kibana** goes straight to its alerts. Below are what it set up **In TIDE**, the **Board**, and the **Rules** and how many alerts each raised.

One simulation at a time can set up, replay or clean up on a SIEM. If TIDE restarts during one, it shows as *Interrupted*: end it (or clean it up) again.

### Ending it, and cleaning up

**End simulation** stops the replay if it is still running, stops the players answering (their **Simulation** goes), and counts each rule's alerts. Everything else stays: its space with its rules, logs and alerts on the SIEM, and what it set up in the client, so you can go through it with the players afterwards.

**Clean up**, once it has ended, removes what it set up in the client (its systems, its baselines, and its destination with its rules) and deletes what it made on the SIEM: its space with its rules and data view, its logs and their template, and its alerts. If something can't be removed, the simulation says so and **Clean up again** tries once more. The logs also delete themselves after seven days, in case a simulation is never cleaned up.

The results (the board, the answers given, the rules and their alerts) stay in TIDE until you **Clear results**, once it is cleaned up.

## Playing a simulation

**Simulation** appears in the sidebar as soon as a simulation you are a player in starts, and goes when it ends. While it sets up you can read the questions; answers open when the replay starts. It has two tabs: **Questions** shows each scenario's story, **Open the space in Kibana**, and its questions; **Dashboard** shows each player's score over time, the **Board**, and how many players have solved each question.

- Type your answer and choose **Answer**. Answers aren't case-sensitive, and quotes and extra spaces don't matter. Wait a moment between answers.
- **Hint** shows one of the question's hints, and costs a quarter of its points, whether you answer it or not.
- Once you have answered a question, **How to find it** shows the searches that find the answer, ready to paste into Kibana's Discover.
- The **Board** ranks the players by their points, less the hints they took.

## What its API key needs

A simulation uses the SIEM's own API key (the one set up with it in **Integrations**). On top of what TIDE needs for its rules, it needs:

- in Elasticsearch: `manage_index_templates`, and on `logs-*-sim*`: `create_index`, `auto_configure`, `write`, `read`, `view_index_metadata` and `delete_index`;
- in Kibana: to manage spaces, and to create data views and detection rules in them.

A simulation that can't do one of these stops and says what it couldn't do; ending it and cleaning it up removes only what it had made.
