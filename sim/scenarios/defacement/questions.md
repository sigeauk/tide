# imreallynotbatman.com is defaced (10 August 2016)

Wayne Enterprises' public website, imreallynotbatman.com, runs on the server we1149srv (192.168.250.70). On the evening of 10 August 2016 its home page was replaced. The group Po1s0n1vy is suspected. Find out how they got in and what they did.

| Data (`event.dataset`) | What it is |
|---|---|
| `windows.sysmon_operational` | Sysmon on the Windows hosts: processes, network connections, file times |
| `system.security`, `system.system` | Windows Security and System event logs |
| `windows.registry` | Registry changes on the Windows hosts |
| `iis.access` | The web server's IIS access log |
| `network_traffic.http`, `network_traffic.dns`, `network_traffic.smb` | Splunk Stream's capture of HTTP, DNS and SMB on the network |
| `suricata.eve` | Suricata IDS: alerts, and HTTP, DNS and file records |
| `fortinet_fortigate.log` | The FortiGate firewall's threat (UTM) log |

1. What is the IP address of the Po1s0n1vy attacker who scanned imreallynotbatman.com for web application vulnerabilities?
2. Which company makes the vulnerability scanner they used?
3. Which content management system does imreallynotbatman.com run?
4. Which IP address tried to brute-force the site's administrator password?
5. What was the first password it tried?
6. One of the passwords tried is the title of a Coldplay song, six letters long. Which is it?
7. What was the correct administrator password?
8. What was the average length of the passwords tried, to the nearest whole number?
9. How many different passwords did the brute force try?
10. How many seconds passed between the brute force finding the correct password and the attacker logging in with it? Give two decimal places.
11. What is the name of the executable the attacker uploaded?
12. What is its MD5 hash?
13. The firewall's antivirus saw the upload. Which signature did it raise?
14. Which process on the web server started the attacker's first commands?
15. Once the executable was running, the attacker explored the server and the domain. Which command listed the server's local user accounts, and at what time (UTC) did it run?
16. What is the name of the file that defaced the website?
17. The attack used dynamic DNS. What is the fully qualified domain name (FQDN) the defacement file was fetched from?
18. What IP address did that domain resolve to? Where else in this attack have you seen it?
