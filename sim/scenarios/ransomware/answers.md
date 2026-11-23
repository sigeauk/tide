# Cerber ransomware: answers

The answers to [the questions](questions.md). For each, how to find it in Elastic, and what TIDE does with it: the rule that catches that step, or how to build one. [How to read the searches](../searches.md) is the same for every scenario.

Every answer and search here has been checked against a replay of this scenario at each noise level. Where Elastic's answer differs from the Splunk BOTS answer, the answer says why (question 4). The notes headed **With TIDE** are for the Sim Admin, not the players: they say which of the scenario's rules ([rules.toml](rules.toml)) catches each step, and how to catch the steps none of them does.

## Answers at a glance

| # | Answer |
|---|---|
| 1 | 192.168.250.100 |
| 2 | MIRANDA_PRI |
| 3 | Miranda_Tate_unveiled.dotm; cmd.exe |
| 4 | 4,426 (Splunk: 4,490) |
| 5 | 3968 |
| 6 | solidaritedeproximite.org |
| 7 | mhtr.jpg |
| 8 | Steganography |
| 9 | vssadmin.exe, WMIC.exe, bcdedit.exe; run by osk.exe |
| 10 | 192.168.250.20 |
| 11 | 257 |
| 12 | 406 |
| 13 | cerberhhyed5frqa.xmfir0.win |
| 14 | 2816763 |

---

### 1. we8105desk's IP address

**Answer: 192.168.250.100**

Sysmon's events on this host don't carry `host.ip`. Its network connections (event 3) do, as `source.ip`.

```kql
event.dataset : "windows.sysmon_operational" and host.name : "we8105desk" and event.code : 3
```

```esql
FROM logs-windows.sysmon_operational-botes
| WHERE host.name == "we8105desk" AND event.code == "3"
| STATS connections = COUNT(*) BY source.ip
| SORT connections DESC
| LIMIT 3
```

**With TIDE:** most of the set's rules fire on this desktop, and name it we8105desk. *Mass file access on a network share* (question 11) fires on the file server, and knows the desktop only by this address.

### 2. The USB key's name

**Answer: MIRANDA_PRI**

Windows records a USB drive's name in the registry value `FriendlyName` when it is plugged in, here at 16:42:17.

```kql
event.dataset : "windows.registry" and host.name : "we8105desk" and registry.value : "friendlyname"
```

**With TIDE:** *Suspicious Execution from a Mounted Device* (Elastic) is in the set for the infected USB drive: a program such as `cmd.exe` or `rundll32.exe` started from Explorer, with its working directory on a drive such as `D:`. It fires at 16:56:47, but not on the attack: on Windows' *Open with* (`rundll32.exe … OpenAs_RunDLL`) for a PDF on `D:\`. Word isn't one of the programs it looks for, so the document itself (question 3) doesn't set it off. The alert still leads to the drive. Rules for the drive being plugged in, such as *New USB Storage Device Mounted*, need device events from Elastic Defend or Windows, which this 2016 network didn't collect. In your own TIDE, find this rule by searching a technique's **Elastic rules** section for *Mounted Device*: Elastic tags it T1204.002, T1218 and T1059, not T1091, so TIDE doesn't suggest it for an infected USB drive.

### 3. The document and what Word started

**Answer: Miranda_Tate_unveiled.dotm, opened from `D:\`; Word started `cmd.exe`**

Word opened the document at 16:43:12, and nine seconds later started `cmd.exe`. Word has no reason to start a command shell. (Its other child, `splwow64.exe`, is Windows' print helper.)

```kql
event.dataset : "windows.sysmon_operational" and host.name : "we8105desk" and event.code : 1 and (process.name : "WINWORD.EXE" or process.parent.name : "WINWORD.EXE")
```

In **Security → Timelines**, the **Correlation** tab runs EQL. This sequence finds the whole chain, Word → `cmd.exe` → `wscript.exe`:

```eql
sequence by host.name with maxspan=5m
  [process where event.type == "start" and process.name == "WINWORD.EXE"]
  [process where event.type == "start" and process.parent.name == "WINWORD.EXE" and process.name == "cmd.exe"]
  [process where event.type == "start" and process.name == "wscript.exe"]
```

**With TIDE:** *Suspicious MS Office Child Process* (Elastic) fires on this step: Word starting `cmd.exe` at 16:43:21. In your own TIDE, search a technique's **Elastic rules** section for *MS Office Child* to find it for a malicious document (T1204.002): Elastic tags it as phishing (T1566.001) and several execution techniques, not T1204.002, so TIDE doesn't suggest it there, and **Map rules by ATT&CK id…** doesn't offer it for that technique.

### 4. The length of the script's command line

**Answer: 4,426 characters in Elastic. Splunk's BOTS answer is 4,490.**

The field is the `cmd.exe` that Word started: its `process.command_line` starts with the program's name and holds the whole script.

```esql
FROM logs-windows.sysmon_operational-botes
| WHERE host.name == "we8105desk" AND event.code == "1" AND process.parent.name == "WINWORD.EXE" AND process.name == "cmd.exe"
| EVAL length = LENGTH(process.command_line)
| KEEP original_timestamp, process.pid, length
```

Why the two answers differ: Sysmon writes its events as XML, where `&`, `<` and `>` are written `&amp;`, `&lt;` and `&gt;`. Splunk counted the XML text. This replay decodes it, as Elastic's own Windows integration does, so the command line is what actually ran. The script's 13 `&` and 4 `<`/`>` add exactly 64 characters. Splunk's text is kept in `botes.splunk.CommandLine`, searchable with KQL, though ES|QL can't read that field type.

**With TIDE:** no rule looks at the script's length. *Command and Scripting Interpreter via Windows Scripts* (Elastic) catches what the script does next: at 16:48:21 `wscript.exe`, running it, starts a `cmd.exe` to run `121214.tmp` (question 5).

### 5. The parent of the cmd.exe that starts 121214.tmp

**Answer: 3968**

That's the process ID of `wscript.exe`, the script host running the VBScript. The chain: `WINWORD.EXE` (3756) → `cmd.exe` (3884) → `wscript.exe` (3968) → `cmd.exe` (1476) → `121214.tmp` (2948).

```kql
event.dataset : "windows.sysmon_operational" and host.name : "we8105desk" and event.code : 1 and process.parent.name : "wscript.exe"
```

**With TIDE:** next, `121214.tmp` copies itself to `osk.exe` in AppData, starts it, and deletes itself with `taskkill` and `del`. *File Deletion Via Del* (Sigma) fires on that at 16:48:41, and again at 17:15:29, when `osk.exe` deletes itself the same way.

### 6. The first suspicious domain

**Answer: solidaritedeproximite.org**, looked up at 16:48:12

Leave out the internal names, the reverse lookups and Microsoft's, then sort by first lookup. Names with no dot, such as `FHEFDJDADEDB…`, are Windows' NetBIOS name lookups, encoded, so keep only names with a dot. Next comes `ipinfo.io` (16:49:24): Cerber checking which public address it is behind.

```esql
FROM logs-network_traffic.dns-botes
| WHERE source.ip == "192.168.250.100" AND original_timestamp >= "2016-08-24T00:00:00Z" AND dns.question.name LIKE "*.*"
| WHERE NOT (dns.question.name LIKE "*.arpa" OR dns.question.name LIKE "*waynecorpinc.local" OR dns.question.name LIKE "*microsoft.com" OR dns.question.name LIKE "*msn.com" OR dns.question.name LIKE "*bing.com" OR dns.question.name LIKE "*live.com" OR dns.question.name LIKE "*windows.com" OR dns.question.name LIKE "*msftncsi.com" OR dns.question.name LIKE "*windowsupdate.com")
| STATS first_seen = MIN(original_timestamp), lookups = COUNT(*) BY dns.question.name
| SORT first_seen
```

**With TIDE:** no rule in the set looks at DNS. Elastic's *External IP Lookup from Non-Browser Process* and Sigma's *Suspicious DNS Query for IP Lookup Service APIs* would catch the `ipinfo.io` lookup, but they need DNS events that name the process (Sysmon event 22), which this 2016 network didn't collect. A custom rule on the network's DNS log works with the data there is:

```kql
event.dataset : "network_traffic.dns" and (dns.question.name : "ipinfo.io" or dns.question.name : "api.ipify.org" or dns.question.name : "icanhazip.com" or dns.question.name : "checkip.amazonaws.com")
```

### 7. The file with the encryption code

**Answer: mhtr.jpg**, from solidaritedeproximite.org (37.187.37.150) at 16:48:13

```kql
event.dataset : "network_traffic.http" and source.ip : "192.168.250.100" and url.domain : "solidaritedeproximite.org"
```

**With TIDE:** no rule in the set catches the download (T1105). One that would is question 8's.

### 8. The obfuscation technique

**Answer: Steganography** (ATT&CK T1027.003)

A `.jpg` that holds code, hidden in an image. The giveaway in this data: the web server sent `mhtr.jpg` as `text/html`, not as an image.

**With TIDE:** a custom rule for "an image that isn't one" would catch it: an internal host fetching a `.jpg`, `.png` or `.gif` that comes back as something else. Without `source.ip`, the scanner's path traversal probes (`/windows/win.ini%00.jpg`) match too. With it, this data matches only `mhtr.jpg`. **Test** in the rule window shows matches like those before the rule goes live.

```kql
event.dataset : "network_traffic.http" and source.ip : "192.168.0.0/16" and (url.path : *.jpg or url.path : *.jpeg or url.path : *.png or url.path : *.gif) and http.response.mime_type : * and not http.response.mime_type : image*
```

### 9. Shadow copies deleted and recovery turned off

**Answer: vssadmin.exe, WMIC.exe and bcdedit.exe (twice), all started by osk.exe** at 16:49:23–24

`vssadmin` deletes the shadow copies, `WMIC` deletes them again through WMI, and `bcdedit` turns off Windows' recovery options, so the files can't be restored. `process.name` keeps the case Windows logged (`WMIC.exe`); `process.name.caseless` matches any case.

```kql
event.dataset : "windows.sysmon_operational" and host.name : "we8105desk" and event.code : 1 and process.parent.name : "osk.exe"
```

**With TIDE:** three rules in the set (all Elastic) catch this step (T1490), one for each tool: *Volume Shadow Copy Deleted or Resized via VssAdmin* and *Volume Shadow Copy Deletion via WMIC* fire at 16:49:23, and *Modification of Boot Configuration* at 16:49:24. Each tool has its own rule, so the step is still caught when ransomware uses one tool but not another.

### 10. The file server

**Answer: 192.168.250.20** (we9041srv)

Nearly all of we8105desk's SMB traffic goes to it (38,717 events), and its Security log has the matching share access.

```esql
FROM logs-network_traffic.smb-botes
| WHERE source.ip == "192.168.250.100"
| STATS events = COUNT(*) BY destination.ip
| SORT events DESC
| LIMIT 3
```

**With TIDE:** *Potential Network Share Discovery* (Elastic) is in the set for share enumeration (T1135). It fires, but not on Cerber: on 192.168.69.103, signed in as Administrator, checking 2,850 files on the file server's administrative share `C$` at 17:04. Their names (`.DS_Store`, `AFP_AfpInfo`) are a Mac's, and the address is in the network's routine traffic too. It can reach Kibana's limit of 100 alerts in a run, and then drops the rest. The desktop reached the file server through the share `fileshare`, which the rule doesn't look at. Whether an administrator browsing `C$` in the middle of an encryption is part of the attack is a good question for the debrief.

### 11. PDFs encrypted on the file server

**Answer: 257**

Windows event 5145 records each file checked on a share. Count the distinct PDFs we8105desk reached on we9041srv (525 events, 257 files).

```kql
event.dataset : "system.security" and event.code : 5145 and source.ip : "192.168.250.100" and file.extension : "pdf"
```

```esql
FROM logs-system.security-botes
| WHERE event.code == "5145" AND source.ip == "192.168.250.100" AND file.extension == "pdf"
| STATS pdfs = COUNT_DISTINCT(file.path), events = COUNT(*), on_host = VALUES(host.name)
```

**With TIDE:** *Mass file access on a network share* (custom) is a threshold rule: 300 or more file checks on a share (event 5145) from one `source.ip` to one `host.name`. It fires on this step, the desktop encrypting the file share (T1486). It also fires on question 10's 192.168.69.103, whose 2,850 checks in a minute cross the same line: a threshold counts events, not why they happened.

### 12. .txt files encrypted in Bob Smith's profile

**Answer: 406**

As it encrypts each file, `osk.exe` changes the file's creation time, and Sysmon logs that as event 2. Count the distinct `.txt` files under `C:\Users\bob.smith.WAYNECORPINC`.

```kql
event.dataset : "windows.sysmon_operational" and host.name : "we8105desk" and event.code : 2 and file.extension : "txt" and file.path : *bob.smith.WAYNECORPINC*
```

```esql
FROM logs-windows.sysmon_operational-botes
| WHERE host.name == "we8105desk" AND event.code == "2" AND file.extension == "txt" AND file.path LIKE "*bob.smith.WAYNECORPINC*"
| STATS txt_files = COUNT_DISTINCT(file.path), by_process = VALUES(process.name)
```

**With TIDE:** no rule in the set watches the desktop's own files. A second encryption rule would: a threshold rule on `event.dataset : "windows.sysmon_operational" and event.code : 2`, grouped by `host.name` and `process.executable`, at 300. In this data only `osk.exe` crosses it (1,136 files); the next busiest, `backgroundTaskHost.exe`, changed 234.

### 13. Where Cerber sends the user

**Answer: cerberhhyed5frqa.xmfir0.win**, looked up at 17:15:12

At 17:15:11 `osk.exe` started Notepad and Internet Explorer to show the ransom note. A second later the desktop looked up this name, the address the note sends the victim to.

```kql
event.dataset : "network_traffic.dns" and source.ip : "192.168.250.100" and dns.question.name : *.win
```

### 14. The Cerber signature that alerted least

**Answer: 2816763** (*ETPRO TROJAN Ransomware/Cerber Checkin 2*, once)

```kql
event.dataset : "suricata.eve" and event.kind : "alert" and rule.name : *Cerber*
```

```esql
FROM logs-suricata.eve-botes
| WHERE event.kind == "alert" AND rule.name LIKE "*Cerber*"
| STATS alerts = COUNT(*) BY rule.id, rule.name
| SORT alerts
```

**With TIDE:** no rule in this scenario's set raises the IDS's own alerts, so these stay in Discover. In a simulation that runs the defacement too, its *External Alerts* rule searches all the simulation's data, and turns each of these into an alert as well.
