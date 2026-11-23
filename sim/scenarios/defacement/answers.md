# imreallynotbatman.com is defaced: answers

The answers to [the questions](questions.md). For each, how to find it in Elastic, and what TIDE does with it: the rule that catches that step, or how to build one. [How to read the searches](../searches.md) is the same for every scenario.

Every answer and search here has been checked against a replay of this scenario at each noise level. The notes headed **With TIDE** are for the Sim Admin, not the players: they say which of the scenario's rules ([rules.toml](rules.toml)) catches each step, and how to catch the steps none of them does.

## Answers at a glance

| # | Answer |
|---|---|
| 1 | 40.80.148.42 |
| 2 | Acunetix |
| 3 | Joomla |
| 4 | 23.22.63.114 |
| 5 | 12345678 |
| 6 | yellow |
| 7 | batman |
| 8 | 6 |
| 9 | 412 |
| 10 | 92.17 |
| 11 | 3791.exe |
| 12 | aae3f5a29935e6abcc2c2754d12a9af0 |
| 13 | W32/Swrort.C!tr |
| 14 | php-cgi.exe |
| 15 | `net user`, 21:58:59 |
| 16 | poisonivy-is-coming-for-you-batman.jpeg |
| 17 | prankglassinebracket.jumpingcrab.com |
| 18 | 23.22.63.114: the brute force, and 3791.exe's connection back |

---

### 1. The scanner's IP address

**Answer: 40.80.148.42**

One outside address made almost every request in the web server's IIS log (20,967 in a replay). Suricata and the FortiGate raise their alerts against the same address.

```kql
event.dataset : "iis.access"
```

```esql
FROM logs-iis.access-botes
| STATS requests = COUNT(*) BY source.ip
| SORT requests DESC
| LIMIT 5
```

**With TIDE:** *External Alerts* (Elastic) turns each Suricata and FortiGate alert in the simulation's data into an alert in its space, so the scan is seen without anyone searching for it. The two raised over 5,000 alerts in the attack's window, nearly all about the scan, so this is by far the set's noisiest rule. The one alert that mattered comes later, among them (question 13). In your own TIDE, **Rule Monitoring** lists a rule like this under **Too many alerts**, and analysts record what its alerts turned out to be with **Record outcome…** in its rule window, so the case for tuning it in **Rule Tuning** rests on evidence.

### 2. The scanner's maker

**Answer: Acunetix**

The IDS signatures name the scanner: Suricata's *ET SCAN Acunetix Version 6 (Free Edition) Scan Detected*, and the FortiGate's *Acunetix.Web.Vulnerability.Scanner* (4,230 alerts).

```kql
event.kind : "alert" and source.ip : "40.80.148.42"
```

```esql
FROM logs-suricata.eve-botes, logs-fortinet_fortigate.log-botes
| WHERE event.kind == "alert" AND source.ip == "40.80.148.42"
| STATS alerts = COUNT(*) BY event.dataset, rule.name
| SORT alerts DESC
| LIMIT 10
```

**With TIDE:** *Web Server Potential SQL Injection Request* (Elastic) looks for SQL injection in the addresses the web server was asked for, and fires on a few of the scan's probes. Sigma's web rules, such as *SQL Injection Strings In URI* or *Path Traversal Exploitation Attempts*, need a pipeline that maps the web log's fields: TIDE's built-in **ECS Windows** leaves them as Sigma names them (`cs-uri-query`), so a web rule converted with it never matches. The scenarios' pipeline maps them to this data's fields. For your own SIEM, add one for your web logs under **Custom pipelines**.

### 3. The site's content management system

**Answer: Joomla**

The scanner's requests are almost all under `/joomla/`, including the administrator page `/joomla/administrator/index.php`. The server itself checks `update.joomla.org` for updates (question 16's search shows it).

```kql
event.dataset : "iis.access" and source.ip : "40.80.148.42"
```

```esql
FROM logs-iis.access-botes
| WHERE source.ip == "40.80.148.42"
| EVAL path_start = SUBSTRING(url.path, 1, 30)
| STATS requests = COUNT(*) BY path_start
| SORT requests DESC
| LIMIT 6
```

**With TIDE:** no rule is needed here: this is what the investigation learns about the site. In your own TIDE, a system's **Log sources** section lists what ATT&CK says to collect for its baseline's techniques, which is how a team knows web logs like these are worth keeping.

### 4. The brute force's source

**Answer: 23.22.63.114**

412 logins were posted to the Joomla administrator page from 23.22.63.114, all with the user agent `Python-urllib/2.7`: a script, not a person. Splunk Stream captured each form, password included, in `http.request.body.content`.

```kql
event.dataset : "network_traffic.http" and http.request.method : "POST" and url.path : "/joomla/administrator/index.php"
```

```esql
FROM logs-network_traffic.http-botes
| WHERE http.request.method == "POST" AND url.path == "/joomla/administrator/index.php"
| STATS posts = COUNT(*) BY source.ip, user_agent.original
| SORT posts DESC
```

**With TIDE:** *Joomla administrator login brute force* (custom) is a threshold rule: 25 or more posts to the administrator page in the IIS log from one `source.ip`. It fires on 23.22.63.114. In your own TIDE, **Rule Health → Create rule** makes one like it (**Group by** `source.ip`, **Threshold** 25), and **Test** in its rule window shows what it would have found, so it can be checked before anyone relies on it.

### 5. The first password tried

**Answer: 12345678**

ES|QL's `GROK` takes the password out of the form data. Sort on `original_timestamp`: the replay sends many events in the same millisecond, so `@timestamp` doesn't keep their order.

```esql
FROM logs-network_traffic.http-botes
| WHERE source.ip == "23.22.63.114" AND url.path == "/joomla/administrator/index.php" AND http.request.body.content LIKE "*passwd=*"
| GROK http.request.body.content "passwd=(?<password>[^&]*)"
| SORT original_timestamp
| KEEP original_timestamp, password
| LIMIT 5
```

### 6. The Coldplay song

**Answer: yellow**

213 of the passwords tried are six letters long. Check them against a list of six-letter Coldplay titles:

```esql
FROM logs-network_traffic.http-botes
| WHERE url.path == "/joomla/administrator/index.php" AND http.request.body.content LIKE "*passwd=*"
| GROK http.request.body.content "passwd=(?<password>[^&]*)"
| WHERE LENGTH(password) == 6 AND TO_LOWER(password) IN ("yellow", "clocks", "shiver", "sparks", "murder", "church", "oceans")
| STATS tries = COUNT(*) BY password
```

### 7. The correct password

**Answer: batman**

It is the only password posted from two addresses: once by the brute force (23.22.63.114), and then by the attacker logging in from the scanner's address (40.80.148.42) with a browser.

```esql
FROM logs-network_traffic.http-botes
| WHERE url.path == "/joomla/administrator/index.php" AND http.request.body.content LIKE "*passwd=*"
| GROK http.request.body.content "passwd=(?<password>[^&]*)"
| STATS uses = COUNT(*), sources = VALUES(source.ip) BY password
| WHERE uses > 1
```

### 8. The average password length

**Answer: 6** (6.17)

```esql
FROM logs-network_traffic.http-botes
| WHERE source.ip == "23.22.63.114" AND url.path == "/joomla/administrator/index.php" AND http.request.body.content LIKE "*passwd=*"
| GROK http.request.body.content "passwd=(?<password>[^&]*)"
| STATS average = AVG(LENGTH(password)), rounded = ROUND(AVG(LENGTH(password)))
```

### 9. The number of passwords tried

**Answer: 412**

Each of the 412 posts tried a different password. (The address also loaded the login page between posts: those requests have no form data, so leave them out.)

```esql
FROM logs-network_traffic.http-botes
| WHERE source.ip == "23.22.63.114" AND url.path == "/joomla/administrator/index.php" AND http.request.body.content LIKE "*passwd=*"
| GROK http.request.body.content "passwd=(?<password>[^&]*)"
| STATS attempts = COUNT(*), passwords = COUNT_DISTINCT(password)
```

### 10. From finding the password to using it

**Answer: 92.17 seconds**

The brute force tried `batman` at 21:46:33.689, and the attacker logged in with it at 21:48:05.858. This only works with `original_timestamp`: the replay speeds time up and shortens long gaps, so the same sum on `@timestamp` gives nonsense.

```esql
FROM logs-network_traffic.http-botes
| WHERE url.path == "/joomla/administrator/index.php" AND http.request.body.content LIKE "*passwd=batman*"
| STATS found = MIN(original_timestamp), logged_in = MAX(original_timestamp)
| EVAL seconds = DATE_DIFF("milliseconds", found, logged_in) / 1000.0
```

### 11. The uploaded executable

**Answer: 3791.exe**

Suricata records the files carried over HTTP. One `.exe` was posted to the Joomla administrator page, from 40.80.148.42, at 21:52:47. Sysmon then shows `C:\inetpub\wwwroot\joomla\3791.exe` started at 21:56:18. A plain search for `3791.exe` finds it in every source that saw it.

```kql
event.dataset : "suricata.eve" and http.request.method : "POST" and url.path : "/joomla/administrator/index.php" and file.name : *.exe
```

**With TIDE:** *Executable started from the web root* (custom) fires when `3791.exe` starts: any program started from under `inetpub`. It describes the behaviour, not the file, so it catches the next tool whatever its name or hash. In your own TIDE it is **Rule Health → Create rule**, language EQL, `process where host.os.type == "windows" and event.type == "start" and process.executable : "*inetpub*.exe"`.

### 12. Its MD5 hash

**Answer: aae3f5a29935e6abcc2c2754d12a9af0** (Splunk's answer writes it in capitals)

```kql
event.dataset : "windows.sysmon_operational" and event.code : 1 and process.name : "3791.exe"
```

The process start event has `process.hash.md5`, `process.hash.sha256` and the rest.

**With TIDE:** no rule in the set looks for the hash: a hash catches this one file. To use hashes anyway, TIDE's rule form makes **Indicator match** rules: match `process.hash.md5` against an index of threat indicators, such as `logs-ti_*` from a threat feed. Question 11's rule is the better cover.

### 13. The firewall's antivirus signature

**Answer: W32/Swrort.C!tr**

FortiGate's antivirus flagged the upload at 21:52:45, two seconds before Suricata saw the file and three minutes before it ran. `rule.ruleset` holds the FortiGate log's subtype: `virus`, `ips` or `webfilter`.

```kql
event.dataset : "fortinet_fortigate.log" and rule.ruleset : "virus" and destination.ip : "192.168.250.70"
```

**With TIDE:** *External Alerts* raised this too, as one alert among thousands from the scan. That is the reason to tune a noisy rule: the alert that mattered was there, and nobody would have seen it. **Rule Monitoring** and **Rule Tuning** (question 1) are where that work starts.

### 14. The process behind the attacker's commands

**Answer: php-cgi.exe**

On we1149srv, `php-cgi.exe` (the web server's PHP) started `cmd.exe` 17 times, from 21:55:22: a web shell. Its first commands were `echo`, `dir`, `ls` and `ifconfig`, then `3791.exe`. From 21:58, `3791.exe` starts its own `cmd.exe` (question 15).

```kql
event.dataset : "windows.sysmon_operational" and host.name : "we1149srv" and event.code : 1 and process.name : "cmd.exe"
```

```esql
FROM logs-windows.sysmon_operational-botes
| WHERE host.name == "we1149srv" AND event.code == "1" AND process.name == "cmd.exe"
| STATS started = COUNT(*), first_seen = MIN(original_timestamp) BY process.parent.name
| SORT first_seen
```

**With TIDE:** *Suspicious Process By Web Server Process* (Sigma) fires on each of the 17 `cmd.exe` that `php-cgi.exe` started: a web server starting a shell or a discovery tool is the mark of a web shell (T1505.003). Elastic's *Web Shell Detection: Script Process Child of Common Web Processes* also fits, but it is a new terms rule: it alerts only the first time it sees a value, so the set uses the Sigma rule, which alerts every time.

### 15. Listing the local user accounts

**Answer: `net user`, at 21:58:59**

Not through the web shell. At 21:56:19, a second after it started, `3791.exe` connected back to 23.22.63.114 on port 3791: a reverse shell (Swrort, the FortiGate's name for it, is the antivirus family name for Metasploit's payloads). From 21:58 the `cmd.exe` it started ran `net view /domain`, `whoami`, `net share`, `net session`, `net user` and `net use`, until 21:59:12. `tasklist` follows at 22:17:22. `process.parent.pid` ties each command to its shell.

```kql
event.dataset : "windows.sysmon_operational" and host.name : "we1149srv" and event.code : 1 and (process.name : "net.exe" or process.name : "whoami.exe" or process.name : "tasklist.exe")
```

```esql
FROM logs-windows.sysmon_operational-botes
| WHERE host.name == "we1149srv" AND event.code == "1" AND process.name IN ("net.exe", "whoami.exe", "tasklist.exe")
| KEEP original_timestamp, process.command_line, process.parent.pid
| SORT original_timestamp
```

**With TIDE:** *Local Accounts Discovery* (Sigma) fires on the reverse shell's `whoami` at 21:58:30 and `net user` at 21:58:59: commands that list who uses the machine. The rest (`net view /domain`, `net share`, `net session`, `net use`) are discovery too, but no rule in the set looks for them.

### 16. The defacement file

**Answer: poisonivy-is-coming-for-you-batman.jpeg**

A web server rarely browses. At 22:06:21 we1149srv fetched this image from `prankglassinebracket.jumpingcrab.com` on port 1337. Splunk Stream keeps the port in `url.domain`.

```kql
event.dataset : "network_traffic.http" and source.ip : "192.168.250.70"
```

```esql
FROM logs-network_traffic.http-botes
| WHERE source.ip == "192.168.250.70"
| STATS requests = COUNT(*), first_seen = MIN(original_timestamp) BY url.domain, destination.port, url.path
| SORT first_seen
```

**With TIDE:** no rule in the set catches the defacement: the network had no file integrity monitoring on the web root. A custom rule that would have caught this step is the web server making HTTP requests on an unusual port. In this data it matches only the two defacement requests:

```kql
event.dataset : "network_traffic.http" and source.ip : "192.168.250.70" and not (destination.port : 80 or destination.port : 443)
```

### 17. The dynamic DNS name

**Answer: prankglassinebracket.jumpingcrab.com**

`jumpingcrab.com` is a free dynamic DNS service. The lookups come from 192.168.250.20, the office DNS server, which resolves names for the other hosts.

```kql
event.dataset : "network_traffic.dns" and dns.question.name : *jumpingcrab*
```

**With TIDE:** no rule in the set looks at DNS. A custom rule on lookups of dynamic DNS providers would: add the providers your network shouldn't use. In this data it matches only the attacker's domain:

```kql
event.dataset : "network_traffic.dns" and (dns.question.name : *.jumpingcrab.com or dns.question.name : *.duckdns.org or dns.question.name : *.no-ip.org or dns.question.name : *.ddns.net)
```

### 18. The attacker's server

**Answer: 23.22.63.114.** It is also where the brute force came from (question 4), and where `3791.exe` connected back to (question 15).

```esql
FROM logs-network_traffic.dns-botes
| WHERE dns.question.name == "prankglassinebracket.jumpingcrab.com" AND dns.resolved_ip IS NOT NULL
| KEEP original_timestamp, dns.question.name, dns.resolved_ip
```

Sysmon's network events (event 3) show `3791.exe` connecting to it on port 3791:

```kql
event.dataset : "windows.sysmon_operational" and event.code : 3 and process.name : "3791.exe"
```

**With TIDE:** an address seen in three steps of an attack is an indicator worth keeping. An **Indicator match** rule (question 12) raises an alert the next time it appears.
