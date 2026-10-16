# External Query API

Read TIDE's data from other tools (SOAR platforms, dashboards, scripts) over HTTPS, with read-only SQL.

[← Back to the README](../README.md)

**Contents:** [Overview](#overview) · [API keys](#api-keys) · [Endpoints](#endpoints) · [Choosing a client](#choosing-a-client) · [What a query may do](#what-a-query-may-do) · [Tables](#tables) · [Examples](#examples) · [Errors](#errors)

---

## Overview

| | |
|---|---|
| **Base address** | Your TIDE address (`APP_URL`), for example `https://tide.example.local` |
| **Authentication** | An API key in the `X-TIDE-API-KEY` header |
| **Format** | JSON in, JSON out |
| **Access** | Read only. Each query reads one client's database, and a key can read only the clients its owner belongs to. |

---

## API keys

Create a key in TIDE: your name at the bottom of the sidebar → **Settings → Profile & Preferences → API Key Management** → **Create Key**.

- The key is shown **once**, when it's created. Copy it then; TIDE keeps only a hash of it.
- A key can read the clients its owner belongs to. To give it another client, add its owner to that client in Management.
- A key stops working while its owner is deactivated, and works again if they're reactivated.
- Each person sees and revokes their own keys. A client's admins can also revoke the keys of people they manage, and super admins all keys.

---

## Endpoints

| Method | Path | What it does |
|--------|------|--------------|
| `GET` | `/api/external/clients` | Lists the clients your key can read. |
| `POST` | `/api/external/query` | Runs one read-only SQL query against one client's database. |

### `GET /api/external/clients`

**Response:**

```json
{
  "clients": [
    {"id": "1b650e71-db8e-4de4-852a-d67cada3fed7", "name": "Primary Client", "slug": "primary"},
    {"id": "8bab9263-2c1b-4b0f-9288-407729eef30d", "name": "DC", "slug": "dc"}
  ]
}
```

### `POST /api/external/query`

**Request body:**

| Field | Required | What it is |
|-------|----------|------------|
| `sql` | Yes | One `SELECT` (or `WITH … SELECT`) statement, up to 4,000 characters. |
| `client_id` | When your key can read more than one client | The client's full `id` from `/api/external/clients`. |

```json
{
  "sql": "SELECT rule_id, name, severity, score FROM detection_rules ORDER BY score DESC LIMIT 10",
  "client_id": "8bab9263-2c1b-4b0f-9288-407729eef30d"
}
```

**Response:** the column names, then one object per row.

```json
{
  "columns": ["rule_id", "name", "severity", "score"],
  "rows": [
    {"rule_id": "0d160033-fab7-4e72-85a3-3a9d80c8bff7", "name": "Multiple Alerts Involving a User", "severity": "high", "score": 84}
  ],
  "row_count": 1
}
```

All matching rows are returned, so use `LIMIT` on large tables.

---

## Choosing a client

Each client's data is in its own database, and a query reads exactly one.

| Your key can read | `client_id` |
|-------------------|-------------|
| One client | Optional: that client is used. |
| Several clients | Required. Get the ids from `GET /api/external/clients`. |
| A client it can't read | The query is refused with `403`. |

Use the `id` exactly as returned: the full UUID. A shortened id (for example `8bab9263-…`) is refused.

---

## What a query may do

Every query is checked twice before it runs, and refused with `400` if either check fails:

1. **The statement.** It must be a single statement starting with `SELECT` or `WITH`. Anything containing a keyword that changes data or reaches outside the database is refused, including `INSERT`, `UPDATE`, `DELETE`, `DROP`, `CREATE`, `ALTER`, `ATTACH`, `COPY`, `INSTALL`, `LOAD`, `PRAGMA` and `SET`, and DuckDB's file-reading functions such as `read_csv`, `read_parquet` and `read_json`.
2. **What it reads.** DuckDB parses the query, and it may read only the client database's own tables and views (and its own `WITH` sections). A file path used as a table, another database, and table functions other than `range`, `generate_series` and `unnest` are refused.

The copies of SIEM connection settings that TIDE keeps in each client's database for its own use can't be read; they are refused as if they didn't exist. ATT&CK and other reference data aren't in the client's database and can't be queried either.

---

## Tables

The most useful tables in a client's database:

| Table | What it holds |
|-------|---------------|
| `detection_rules` | Synced rules: `rule_id`, `siem_id`, `space`, `name`, `severity`, `enabled`, `score` and its parts, `mitre_ids`, `raw_data` |
| `rule_score_history` | Each rule's score over time |
| `checkedRule` | Rule validations: when, and by whom |
| `rule_links` | Linked copies of a rule in other destinations |
| `threat_actors` | Threat actors: `name`, `aliases`, `origin`, `ttps`, `ttp_count` |
| `systems`, `hosts`, `software_inventory` | Systems, their devices, and installed software (CPE 2.3) |
| `vuln_detections` | CVEs matched to software |
| `playbooks`, `playbook_steps`, `step_techniques` | Baselines, their techniques, and the ATT&CK ids on each (`playbooks.system_id` is the system a baseline belongs to; empty for a template) |
| `step_detections`, `applied_detections` | Rules mapped to baseline techniques, and where they apply |
| `blind_spots` | Known gaps and N/A marks |
| `system_baselines`, `system_coverage_destinations` | Baselines applied to systems, and which destinations count for each system |
| `system_baseline_snapshots` | Point-in-time coverage captures |

---

## Examples

In each example, replace `tide.example.local` with your TIDE address and `YOUR_API_KEY` with your key. If TIDE uses a self-signed certificate, add `-k` to `curl` (or `--cacert certs/ca.crt` to trust your CA).

### List your clients

```bash
curl -s https://tide.example.local/api/external/clients \
  -H "X-TIDE-API-KEY: YOUR_API_KEY"
```

### Count the rules

With a key that reads one client, `client_id` can be left out:

```bash
curl -s -X POST https://tide.example.local/api/external/query \
  -H "Content-Type: application/json" \
  -H "X-TIDE-API-KEY: YOUR_API_KEY" \
  -d '{"sql": "SELECT COUNT(*) AS total_rules FROM detection_rules"}'
```

```json
{"columns": ["total_rules"], "rows": [{"total_rules": 501}], "row_count": 1}
```

### The best-scoring rules in one client

```bash
curl -s -X POST https://tide.example.local/api/external/query \
  -H "Content-Type: application/json" \
  -H "X-TIDE-API-KEY: YOUR_API_KEY" \
  -d '{"sql": "SELECT rule_id, name, severity, score FROM detection_rules WHERE score IS NOT NULL ORDER BY score DESC LIMIT 5",
       "client_id": "8bab9263-2c1b-4b0f-9288-407729eef30d"}'
```

### Rules and average score per space

```bash
curl -s -X POST https://tide.example.local/api/external/query \
  -H "Content-Type: application/json" \
  -H "X-TIDE-API-KEY: YOUR_API_KEY" \
  -d '{"sql": "SELECT space, COUNT(*) AS rules, ROUND(AVG(score), 1) AS avg_score FROM detection_rules GROUP BY space ORDER BY avg_score DESC"}'
```

```json
{
  "columns": ["space", "rules", "avg_score"],
  "rows": [
    {"space": "two", "rules": 467, "avg_score": 38.6},
    {"space": "production", "rules": 34, "avg_score": 28.4}
  ],
  "row_count": 2
}
```

### Threat actors with the most techniques

```bash
curl -s -X POST https://tide.example.local/api/external/query \
  -H "Content-Type: application/json" \
  -H "X-TIDE-API-KEY: YOUR_API_KEY" \
  -d '{"sql": "SELECT name, origin, ttp_count FROM threat_actors ORDER BY ttp_count DESC LIMIT 5"}'
```

### Techniques per system

```bash
curl -s -X POST https://tide.example.local/api/external/query \
  -H "Content-Type: application/json" \
  -H "X-TIDE-API-KEY: YOUR_API_KEY" \
  -d '{"sql": "SELECT s.name AS system, COUNT(DISTINCT st.id) AS techniques FROM systems s JOIN playbooks p ON p.system_id = s.id JOIN playbook_steps st ON st.playbook_id = p.id GROUP BY 1 ORDER BY 2 DESC"}'
```

---

## Errors

Errors return a JSON body with a `detail` message:

```json
{"detail": "API key does not have access to the requested tenant."}
```

| Status | `detail` | What to do |
|--------|----------|------------|
| `400` | `Only SELECT statements are allowed.` | Send one `SELECT` or `WITH … SELECT` statement. |
| `400` | `Forbidden SQL keyword: …` | Remove the named keyword: queries can only read. |
| `400` | `client_id is required when the API key owner has access to multiple tenants…` | Add `client_id`, from `GET /api/external/clients`. |
| `400` | Another message, such as `Query error: …` | The SQL is invalid, or reads something it may not (a file, another database, a hidden table); the message says what. |
| `401` | `Invalid or missing API key.` | Check the `X-TIDE-API-KEY` header, or create a new key. |
| `403` | `API key does not have access to the requested tenant.` | Use a full `id` from `GET /api/external/clients`, or add the key's owner to that client. |
| `403` | `API key owner has no tenant access…` | Add the key's owner to at least one client. |
| `404` | `Tenant database not found for the requested client.` | The client's database file is missing. A super admin can confirm it with **Diagnostics → Run all checks**. |

**`curl` problems:**

| `curl` says | Cause |
|-------------|-------|
| `Could not resolve host` (exit code 6) | The address is wrong, or still the example `tide.example.local`. |
| `SSL certificate problem` (exit code 60) | TIDE's certificate isn't trusted by this machine. Use `--cacert certs/ca.crt`, or `-k`. |
