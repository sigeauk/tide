# Cerber ransomware (24 August 2016)

On 24 August 2016 Bob Smith's desktop, we8105desk, showed a ransom note, and files on the company's file share were encrypted. Find out how the ransomware arrived, what it did on the desktop, and how far it reached.

| Data (`event.dataset`) | What it is |
|---|---|
| `windows.sysmon_operational` | Sysmon on the Windows hosts: processes, network connections, file times |
| `system.security`, `system.system` | Windows Security and System event logs |
| `windows.registry` | Registry changes on the Windows hosts |
| `iis.access` | The web server's IIS access log |
| `network_traffic.http`, `network_traffic.dns`, `network_traffic.smb` | Splunk Stream's capture of HTTP, DNS and SMB on the network |
| `suricata.eve` | Suricata IDS: alerts, and HTTP, DNS and file records |
| `fortinet_fortigate.log` | The FortiGate firewall's threat (UTM) log |

1. What was we8105desk's IPv4 address on 24 August 2016?
2. What is the name of the USB key Bob Smith plugged in?
3. Which document did Bob open from the USB key, and which program did Word then start?
4. Word's command shell writes and runs a VBScript. The whole script, with the name of the program that runs it in front, is in one field. How many characters long is it?
5. The script starts `121214.tmp` through another `cmd.exe`. What is the process ID of that `cmd.exe`'s parent (its ParentProcessId)?
6. What was the first suspicious domain we8105desk looked up on 24 August?
7. The malware downloads the file that holds Cerber's encryption code. What is the file's name?
8. What obfuscation technique does that file most likely use?
9. Which three built-in Windows programs did the ransomware run to delete the shadow copies and turn off recovery, and which process ran them?
10. we8105desk was connected to a file server during the outbreak. What is the file server's IPv4 address?
11. How many distinct PDF files did the ransomware encrypt on the file server?
12. How many `.txt` files did it encrypt in Bob Smith's Windows profile?
13. At the end of the encryption, which FQDN does Cerber send the user to?
14. Of the Suricata signatures that detected Cerber, which alerted the fewest times? Give its signature ID.
