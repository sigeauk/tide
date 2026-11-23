# BOTES: how to read the searches

For every scenario's answers.

- **KQL** goes in Discover's search bar, with the data view **BOTES replay**. It also works inside ES|QL's `KQL()` function. That is why several values are written out in full (`process.name : "net.exe" or process.name : "whoami.exe"`), not grouped (`process.name : ("net.exe" or "whoami.exe")`): Discover takes either, but `KQL()`, a technical preview in 8.19, matches nothing for the grouped form.
- **ES|QL**: in Discover, switch to ES|QL and paste it. The time picker still applies.
- **More than one replay:** add `| WHERE botes.replay.run_id == "<id>"` after the `FROM` line. To list the replays: `FROM logs-*-botes | STATS events = COUNT(*), started = MIN(@timestamp) BY botes.replay.run_id`.
- **Times** are the original times (`original_timestamp`, UTC). Sort on `original_timestamp`, never `@timestamp`: the replay stamps each event with the moment it was sent.
- **With TIDE** notes are for the Sim Admin: players don't see them. A rule named there with its source, such as *External Alerts* (Elastic), is one of the scenario's rules (its `rules.toml`), in the simulation's space from the start: *(Elastic)* is one of Elastic's prebuilt rules, *(Sigma)* a Sigma rule converted with the scenarios' pipeline (`sim/sigma/ecs.yml`), and *(custom)* a rule written for the scenario. The **Rules** table on the Simulations page counts each one's alerts when the simulation ends.
