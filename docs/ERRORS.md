# Error codes

<!-- Written from TIDE's error codes (app/services/errors.py) by python -m app.scripts.error_codes --markdown: change them there, not here. -->

When something goes wrong, TIDE's message ends with a short error code, such as D500, and TIDE's log records the same code. Quote the code when you ask for help: this page says what each one means and what to do. A failure TIDE didn't expect also gives a reference, which finds it in TIDE's log (see [Logs](OPERATIONS.md#logs)).

## Reading a code

The letter says where it went wrong:

| Letter | Stands for | Covers |
|---|---|---|
| T | TIDE | TIDE itself: pages, forms, its settings and files, its background services. |
| D | Databases | TIDE's databases: its own, each client's, and the bundled reference database. |
| S | SIEMs | A SIEM TIDE reads: Elastic (Kibana, Elasticsearch) or Wazuh. |
| A | Access | Who you are and what you may do: signing in, sessions, roles, API keys, Keycloak. |
| I | Integrations | GitLab and OpenCTI. |

The first digit says whose side: 4 means something to put right (the request, a setting, a permission), 5 means something failed or wasn't available. Where the web has a number for the same thing, the code uses it (404 is "not found" there too). For a SIEM, GitLab, OpenCTI or Keycloak, it is what that system answered: S401 means the SIEM answered 401, it didn't accept TIDE's key.

## Looking a code up in the container

When TIDE's pages aren't there to read this one, look a code up from the command line:

```bash
docker exec tide-app python -m app.scripts.error_codes D500
```

Without a code it lists them all. In the log (`docker compose logs tide-app`, or `data/log/tide.log`) each error has its code in its `code` field.

## T: TIDE

### T400

The request wasn't one TIDE can act on.

*What to do:* Refresh the page and try again.

### T404

That item doesn't exist, or no longer does.

*What to do:* It may have been deleted or moved: refresh the list and look for it again.

### T409

That already exists, or changed while you were working on it.

*What to do:* Refresh, look at what is there now, and choose again.

### T422

A field is missing or not valid.

*What to do:* Check the fields the form marks, then try again.

### T460

SESSION_SECRET isn't set, or is still the example value, so TIDE won't start.

*What to do:* Set SESSION_SECRET in .env to a long random string (make one with openssl rand -base64 48), then start TIDE again (docker compose up -d).

### T461

Stored keys and passwords can't be read: data/credentials.key isn't the key they were saved with.

*What to do:* Put back the data/credentials.key that was backed up with this data, then restart TIDE. Without it, enter each SIEM's and integration's key or password again in Settings → Management.

### T500

TIDE hit an unexpected error.

*What to do:* Try again. If it happens again, report the code, the reference and the time: the reference finds the error in TIDE's log.

### T503

TIDE is starting or restarting.

*What to do:* Wait a minute: the page reloads by itself. If TIDE doesn't come back, its log says why (docker compose logs tide-app).

### T504

TIDE didn't answer in time.

*What to do:* Try again. If every page hangs, restart TIDE (docker compose restart tide-app).

### T560

A background service isn't running, so rule-log exports, scheduled backups and the maintenance window won't happen on their own.

*What to do:* Restart TIDE (docker compose restart tide-app). If it says so again, report the log from startup: the error before this one says why.

## D: Databases

### D404

A client's database file is missing from the data folder.

*What to do:* Settings → Diagnostics → Run all checks names the file. Restore it from a backup, or remove the client if it is no longer used.

### D409

Two changes to the same data met at once, and one was stopped.

*What to do:* Try again. If it keeps happening, wait for any sync that is running to finish.

### D500

A database query failed.

*What to do:* Try again. If it happens again, report the code, the reference and the time: the reference finds the error in TIDE's log.

### D503

A database file is locked by another program.

*What to do:* Something else has TIDE's database open: a second TIDE on the same data folder, or a DuckDB tool on the host. Stop it, then try again. If nothing else is running, restart TIDE (docker compose restart tide-app).

### D507

The disk TIDE keeps its data on is full.

*What to do:* Free space on the data volume (the guide's Operations page, Reclaiming disk space), then try again.

### D560

A database stopped after a DuckDB fatal error, so TIDE restarted to open it afresh.

*What to do:* Usually nothing: wait a minute, then try again, as the restart repairs it. Settings → Diagnostics shows the error.

### D561

A database stopped again soon after TIDE restarted for it, so TIDE didn't restart again.

*What to do:* Restart TIDE (docker compose restart tide-app). If it happens again, back up the data folder and report it. Settings → Diagnostics shows the error.

### D562

A database doesn't match this version of TIDE: a table or column it needs is missing.

*What to do:* Restart TIDE (docker compose restart tide-app) so its upgrades run. If it happens again, run Settings → Diagnostics → Run all checks and report the result with the code and reference.

### D563

A database upgrade failed while TIDE was starting.

*What to do:* Report the log from startup (docker compose logs tide-app). Don't delete the database: to go back, restore the backup taken before the upgrade (the guide's Operations page, Restore a backup).

### D565

The bundled reference database (MITRE ATT&CK, NIST 800-53, the Sigma and Elastic rule libraries) couldn't be opened.

*What to do:* Restart TIDE. If it happens again, recreate its container (docker compose up -d --force-recreate tide-app), which puts the file back from the image.

### D566

A database ran out of memory.

*What to do:* Give TIDE's container more memory, or do the work for fewer clients or rules at a time, then try again.

## S: SIEMs

### S401

The SIEM didn't accept TIDE's API key, user or password.

*What to do:* Check it with Test connection in the SIEM's dialog (Settings → Management → Integrations), and enter it again if it has changed or expired.

### S403

The SIEM accepted TIDE's key, but the key isn't allowed to do this.

*What to do:* Give the key the privileges the guide lists (Setting up clients → The Elastic API key; for Wazuh, Configuration → Wazuh), then Test connection.

### S404

The SIEM has no such space (for Wazuh, no such agent group).

*What to do:* Check the destination's space on the client's page, or link the destination again.

### S495

TIDE didn't trust the SIEM's certificate.

*What to do:* Install the CA certificate that signed it, or untick Verify TLS certificate in the SIEM's dialog (Settings → Management → Integrations). Configuration → When a certificate is refused says how.

### S502

The SIEM answered with an error, or with something TIDE can't read.

*What to do:* Check the SIEM is working, then try again. If it keeps happening, report the code and the message.

### S503

The SIEM couldn't be reached: the connection was refused or timed out, or its address doesn't resolve.

*What to do:* Check the SIEM's address in the SIEM's dialog (Settings → Management → Integrations) and that TIDE's network can reach it, then Test connection.

### S504

The SIEM accepted the connection but didn't answer in time.

*What to do:* It is up but slow: try again later. If it is always slow, check how busy the SIEM is.

## A: Access

### A401

You aren't signed in, or your session has ended; or an API key is missing or not valid.

*What to do:* Sign in again. For the External Query API, check the X-TIDE-API-KEY header, or create a new key.

### A403

You aren't allowed to do that: your role doesn't allow it, or you have no access to this client.

*What to do:* Ask an admin of the client for the role or the access you need.

### A460

Keycloak didn't accept TIDE's settings: its realm, client id or client secret.

*What to do:* Correct them in the Keycloak integration (Settings → Management → Integrations), then Test connection. Configuration → Single sign-on with Keycloak says what they should be.

### A495

TIDE didn't trust Keycloak's certificate.

*What to do:* Install the CA certificate that signed it, or untick Verify TLS certificate in the Keycloak integration (Settings → Management → Integrations).

### A502

Keycloak answered with an error, or with something TIDE can't read.

*What to do:* Check Keycloak is working, then sign in again. If it keeps happening, report the code and the time.

### A503

Keycloak couldn't be reached: the connection was refused or timed out, or its address doesn't resolve.

*What to do:* Check Keycloak is running, and its address in the Keycloak integration (Settings → Management → Integrations). Signing in with a TIDE password still works.

### A504

Keycloak accepted the connection but didn't answer in time.

*What to do:* It is up but slow: sign in again in a minute.

## I: Integrations

### I401

GitLab or OpenCTI didn't accept TIDE's token.

*What to do:* Make a new token, put it in the GitLab project's or the OpenCTI connector's dialog, and test it.

### I403

GitLab or OpenCTI accepted the token, but it isn't allowed to do this.

*What to do:* Give the token the role the guide lists (Setting up clients → Link GitLab projects), then test it.

### I404

The GitLab project isn't there, or the token can't see it.

*What to do:* Check the project's path on the client's page, or link the project again.

### I495

TIDE didn't trust GitLab's or OpenCTI's certificate.

*What to do:* Install the CA certificate that signed it, or untick Verify TLS certificate in its dialog. Configuration → When a certificate is refused says how.

### I502

GitLab or OpenCTI answered with an error, or with something TIDE can't read.

*What to do:* Check it is working, then try again. If it keeps happening, report the code and the message.

### I503

GitLab or OpenCTI couldn't be reached: the connection was refused or timed out, or its address doesn't resolve.

*What to do:* Check its address in its dialog and that TIDE's network can reach it, then test it.

### I504

GitLab or OpenCTI accepted the connection but didn't answer in time.

*What to do:* It is up but slow: try again later.
