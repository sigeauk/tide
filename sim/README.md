# Simulation scenarios

The attack scenarios for TIDE's simulations: recorded attacks that are replayed into a SIEM as if they were happening now, with questions for the people investigating them. This folder is data. It is built into TIDE's image at `/app/sim` and read-only there.

| Path | What it holds |
|---|---|
| `scenarios/<id>/scenario.toml` | What the scenario is: its title and date, where its logs came from and their licence, the attack's window in original time (UTC), the half hour kept either side, its noise pack, the attacker's indicators, and the noise levels its answers have been checked at |
| `scenarios/<id>/logs/` | The attack's events: one gzipped file per source, oldest first, each event as its source wrote it. They are mapped to ECS as they are replayed |
| `scenarios/<id>/noise/` | The scenario's own routine, high-volume events, which no question needs. Replayed at noise levels *normal* and *busy* |
| `scenarios/<id>/manifest.json` | Each log file's source, number of events, and first and last times |
| `scenarios/<id>/questions.md`, `answers.md`, `answer_key.toml` | The questions, the write-ups with the searches that find each answer, and the answer key: points, accepted answers and hints |
| `scenarios/<id>/rules.toml` | The detection rules a simulation of the scenario runs in its own space: Elastic's prebuilt rules and Sigma rules by their ids, and rules written for it in full. Each searches only the simulation's own data, and names the step of the attack it is there to catch (`covers`) |
| `scenarios/<id>/tide.toml` | What a simulation of the scenario sets up in its client's TIDE while it runs: the attack as a baseline (its techniques, with their ATT&CK ids, priority and category), the systems it hit with their devices, and the steps known to be uncovered |
| `scenarios/demo/DEMO_SCRIPT.md` | The TIDE demo's script for whoever presents it: what to set up, what to click, the figures to expect and what to say, with 20- and 45-minute versions |
| `scenarios/airgap/DEMO_SCRIPT.md` | The air-gap demo's script: what to set up, what to click (the hunt and the rule made from it among it), the figures to expect and what to say |
| `scenarios/intro.md`, `scenarios/searches.md` | What players read before they start, and how to read the searches in the answers |
| `noise/<id>/` | A noise pack: routine traffic from the same network at another time (`noise.toml`, `logs/`, `manifest.json`). At noise level *busy* it is laid over its scenario's timeline |
| `sigma/ecs.yml` | The Sigma pipeline the scenarios' Sigma rules are converted with, for the replayed events' ECS fields |

## The scenarios

| Scenario | Original time (UTC) | What happens |
|---|---|---|
| `airgap` | 12 March 2026, 08:55–09:20 | The air-gap demo: a contractor's USB stick, a rogue DHCP device and a service account's password on Halcyon Marine's air-gapped design network, and the drawings carried out on the stick. Its events are made for the demo (`test/sim_airgap_events.py`), with no noise. Its rules start broken or missing, for a presenter to fix in TIDE. No questions |
| `defacement` | 10 August 2016, 21:35–22:25 | A vulnerability scan of imreallynotbatman.com, a Joomla administrator brute force, a web shell, an uploaded tool run on the server, and the site defaced. 18 questions |
| `demo` | 24 August 2016, 15:25–15:45 | The TIDE demo: a banking trojan from an invoice adds its own root certificate on Bob Smith's desktop and points the browser at its proxy. Its rules start as a client's often are (disabled, noisy, or unable to work), for a presenter to fix in TIDE. No questions |
| `ransomware` | 24 August 2016, 16:40–17:20 | A USB drive, a Word macro, a payload hidden in an image, Cerber ransomware, shadow copies deleted, and files on the file share encrypted. 14 questions |

Each CTF scenario's answers have been checked against a replay at every noise level: *quiet* (the attack window), *normal* (with its routine events) and *busy* (with the half hour either side and its noise pack). The demo has no lead and no noise pack: its routine events are already in its `noise/`, so *busy* sends the same as *normal*.

## Source and licence

The logs come from Splunk's **Boss of the SOC v1** dataset (Wayne Enterprises, August 2016), published under **CC0 1.0** (public domain). The demo's attack is events made for it, as Sysmon would have logged them on that desktop, also **CC0 1.0**; its routine events are BOTS v1's. Its attacker's domain and address are reserved for documentation, so they point at nothing real. Each `scenario.toml` and `noise.toml` names its source and licence. A scenario from anywhere else has its licence checked before it is added here.

## Antivirus

The logs and the answers quote the attacks' real command lines. Antivirus on a machine holding a copy of this folder may quarantine some of its files; exclude the folder.
