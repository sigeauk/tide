# BOTES: before you start

Real attacks, replayed into Elastic as if they were happening now. Each scenario is one attack, with its own questions: answer them in Kibana, with Discover (KQL or ES|QL) and the Security app. Each scenario's answers.md has the answers, the searches that find them and what TIDE does with each.

## Before you start

- Open the Kibana space **BOTES** and, in **Discover**, the data view **BOTES replay** (`logs-*-botes`).
- **Time picker:** `@timestamp` is when each event was replayed, not when it happened. Set the time picker to cover the replay, for example *Last 24 hours*.
- **The real time** is in `original_timestamp` (UTC). Every time in the questions is an original time. Add it as a column and sort on it.
- **More than one replay?** Each pass has its own `botes.replay.run_id`. Filter on one, or every count comes out doubled.
- **Exact counts:** a field's top values in Discover's sidebar come from a sample of documents. For an exact count, use ES|QL (`STATS`) or Lens.
- **Antivirus:** some events hold real attackers' command lines. Read them in Kibana. Saved to a file on Windows (a Discover CSV export, a command line pasted into a note), Microsoft Defender may quarantine the file.
