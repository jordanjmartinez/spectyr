# Sysmon Normal Traffic Patterns for Spectyr

> Purpose: Realistic background noise for SOC training scenarios
> Source: Microsoft Sysmon documentation, real-world event patterns

---

## Schema

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE | KEY VALUE PAIRS |
|------|------------|------------|-----------|---------|----------|---------|-----------------|

**MESSAGE** = Raw log line (shown in main table view)
**KEY VALUE PAIRS** = Parsed fields (shown in expanded/collapsed view only)

---

## Normal Traffic Logs (20 Events)

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE | KEY VALUE PAIRS |
|------|------------|------------|-----------|---------|----------|---------|-----------------|
| 08:01:12 | ProcessCreate | Sysmon | 10.0.1.45 | | | `Process Create: UtcTime=2024-01-15 08:01:12.025 ProcessGuid={A23EAE89-BD56-5903-0000-0010E9D95E00} ProcessId=4528 Image=C:\Windows\System32\svchost.exe CommandLine="C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule" User=NT AUTHORITY\SYSTEM ParentImage=C:\Windows\System32\services.exe` | `image=svchost.exe, commandline=svchost.exe -k netsvcs -p -s Schedule, user=NT AUTHORITY\SYSTEM, parent_image=services.exe, process_id=4528, integrity_level=System` |
| 08:15:33 | ProcessCreate | Sysmon | 10.0.1.45 | | | `Process Create: UtcTime=2024-01-15 08:15:33.112 ProcessGuid={A23EAE89-BD56-5903-0000-0010F1D95E01} ProcessId=8824 Image=C:\Program Files\Google\Chrome\Application\chrome.exe CommandLine="C:\Program Files\Google\Chrome\Application\chrome.exe" User=CORP\jsmith ParentImage=C:\Windows\explorer.exe` | `image=chrome.exe, commandline=chrome.exe, user=CORP\jsmith, parent_image=explorer.exe, process_id=8824, integrity_level=Medium` |
| 08:15:45 | NetworkConnection | Sysmon | 10.0.1.45 | 142.250.191.46 | TCP/443 | `Network connection detected: UtcTime=2024-01-15 08:15:45.234 ProcessGuid={A23EAE89-BD56-5903-0000-0010F1D95E01} ProcessId=8824 Image=C:\Program Files\Google\Chrome\Application\chrome.exe User=CORP\jsmith Protocol=tcp SourceIp=10.0.1.45 SourcePort=49200 DestinationIp=142.250.191.46 DestinationPort=443 DestinationHostname=www.google.com` | `image=chrome.exe, user=CORP\jsmith, protocol=tcp, src_ip=10.0.1.45, src_port=49200, dst_ip=142.250.191.46, dst_port=443, dst_hostname=www.google.com, initiated=true` |
| 08:16:02 | DNSQuery | Sysmon | 10.0.1.45 | 10.0.1.1 | UDP/53 | `Dns query: UtcTime=2024-01-15 08:16:02.445 ProcessGuid={A23EAE89-BD56-5903-0000-0010F1D95E01} ProcessId=8824 QueryName=www.google.com QueryStatus=0 QueryResults=142.250.191.46 Image=C:\Program Files\Google\Chrome\Application\chrome.exe` | `image=chrome.exe, query_name=www.google.com, query_status=SUCCESS, query_results=142.250.191.46, process_id=8824` |
| 08:22:18 | ProcessCreate | Sysmon | 10.0.1.45 | | | `Process Create: UtcTime=2024-01-15 08:22:18.556 ProcessGuid={A23EAE89-BD56-5903-0000-0010F2D95E02} ProcessId=9120 Image=C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE CommandLine="C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE" User=CORP\jsmith ParentImage=C:\Windows\explorer.exe` | `image=OUTLOOK.EXE, commandline=OUTLOOK.EXE, user=CORP\jsmith, parent_image=explorer.exe, process_id=9120, integrity_level=Medium` |
| 08:22:31 | NetworkConnection | Sysmon | 10.0.1.45 | 52.96.166.24 | TCP/443 | `Network connection detected: UtcTime=2024-01-15 08:22:31.667 ProcessGuid={A23EAE89-BD56-5903-0000-0010F2D95E02} ProcessId=9120 Image=C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE User=CORP\jsmith Protocol=tcp SourceIp=10.0.1.45 SourcePort=49215 DestinationIp=52.96.166.24 DestinationPort=443 DestinationHostname=outlook.office365.com` | `image=OUTLOOK.EXE, user=CORP\jsmith, protocol=tcp, src_ip=10.0.1.45, src_port=49215, dst_ip=52.96.166.24, dst_port=443, dst_hostname=outlook.office365.com, initiated=true` |
| 08:30:05 | ProcessCreate | Sysmon | 10.0.1.45 | | | `Process Create: UtcTime=2024-01-15 08:30:05.778 ProcessGuid={A23EAE89-BD56-5903-0000-0010F3D95E03} ProcessId=6644 Image=C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.19041.1_none_e780d76cd8ec063e\TiWorker.exe CommandLine=C:\Windows\winsxs\amd64_microsoft-windows-servicingstack...\TiWorker.exe -Embedding User=NT AUTHORITY\SYSTEM ParentImage=C:\Windows\System32\svchost.exe` | `image=TiWorker.exe, commandline=TiWorker.exe -Embedding, user=NT AUTHORITY\SYSTEM, parent_image=svchost.exe, process_id=6644, description=Windows Update` |
| 08:30:22 | NetworkConnection | Sysmon | 10.0.1.45 | 20.109.186.68 | TCP/443 | `Network connection detected: UtcTime=2024-01-15 08:30:22.889 ProcessGuid={A23EAE89-BD56-5903-0000-0010E9D95E00} ProcessId=1284 Image=C:\Windows\System32\svchost.exe User=NT AUTHORITY\NETWORK SERVICE Protocol=tcp SourceIp=10.0.1.45 SourcePort=49250 DestinationIp=20.109.186.68 DestinationPort=443 DestinationHostname=update.microsoft.com` | `image=svchost.exe, user=NT AUTHORITY\NETWORK SERVICE, protocol=tcp, src_ip=10.0.1.45, src_port=49250, dst_ip=20.109.186.68, dst_port=443, dst_hostname=update.microsoft.com, initiated=true` |
| 08:45:11 | FileCreate | Sysmon | 10.0.1.45 | | | `File created: UtcTime=2024-01-15 08:45:11.990 ProcessGuid={A23EAE89-BD56-5903-0000-0010F1D95E01} ProcessId=8824 Image=C:\Program Files\Google\Chrome\Application\chrome.exe TargetFilename=C:\Users\jsmith\Downloads\Q4_Report.pdf CreationUtcTime=2024-01-15 08:45:11.990` | `image=chrome.exe, target_filename=C:\Users\jsmith\Downloads\Q4_Report.pdf, user=CORP\jsmith, process_id=8824` |
| 09:01:44 | DNSQuery | Sysmon | 10.0.1.45 | 10.0.1.1 | UDP/53 | `Dns query: UtcTime=2024-01-15 09:01:44.101 ProcessGuid={A23EAE89-BD56-5903-0000-0010E9D95E00} ProcessId=1284 QueryName=settings-win.data.microsoft.com QueryStatus=0 QueryResults=40.77.226.250 Image=C:\Windows\System32\svchost.exe` | `image=svchost.exe, query_name=settings-win.data.microsoft.com, query_status=SUCCESS, query_results=40.77.226.250, process_id=1284` |
| 09:15:08 | ProcessCreate | Sysmon | 10.0.1.45 | | | `Process Create: UtcTime=2024-01-15 09:15:08.212 ProcessGuid={A23EAE89-BD56-5903-0000-0010F4D95E04} ProcessId=7788 Image=C:\Windows\System32\taskhostw.exe CommandLine=taskhostw.exe User=NT AUTHORITY\SYSTEM ParentImage=C:\Windows\System32\svchost.exe` | `image=taskhostw.exe, commandline=taskhostw.exe, user=NT AUTHORITY\SYSTEM, parent_image=svchost.exe, process_id=7788, description=Task Scheduler` |
| 09:22:35 | RegistryEvent | Sysmon | 10.0.1.45 | | | `Registry value set: UtcTime=2024-01-15 09:22:35.323 ProcessGuid={A23EAE89-BD56-5903-0000-0010F5D95E05} ProcessId=4412 Image=C:\Windows\explorer.exe TargetObject=HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs Details=Binary Data` | `image=explorer.exe, event_type=SetValue, target_object=HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs, user=CORP\jsmith, process_id=4412` |
| 09:30:00 | ProcessCreate | Sysmon | 10.0.1.45 | | | `Process Create: UtcTime=2024-01-15 09:30:00.434 ProcessGuid={A23EAE89-BD56-5903-0000-0010F6D95E06} ProcessId=10244 Image=C:\Windows\System32\notepad.exe CommandLine="C:\Windows\System32\notepad.exe" User=CORP\jsmith ParentImage=C:\Windows\explorer.exe` | `image=notepad.exe, commandline=notepad.exe, user=CORP\jsmith, parent_image=explorer.exe, process_id=10244, integrity_level=Medium` |
| 09:45:12 | FileCreate | Sysmon | 10.0.1.45 | | | `File created: UtcTime=2024-01-15 09:45:12.545 ProcessGuid={A23EAE89-BD56-5903-0000-0010F7D95E07} ProcessId=11456 Image=C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE TargetFilename=C:\Users\jsmith\Documents\Meeting_Notes.docx CreationUtcTime=2024-01-15 09:45:12.545` | `image=WINWORD.EXE, target_filename=C:\Users\jsmith\Documents\Meeting_Notes.docx, user=CORP\jsmith, process_id=11456` |
| 10:00:03 | NetworkConnection | Sysmon | 10.0.1.45 | 13.107.42.16 | TCP/443 | `Network connection detected: UtcTime=2024-01-15 10:00:03.656 ProcessGuid={A23EAE89-BD56-5903-0000-0010F8D95E08} ProcessId=12580 Image=C:\Users\jsmith\AppData\Local\Microsoft\Teams\current\Teams.exe User=CORP\jsmith Protocol=tcp SourceIp=10.0.1.45 SourcePort=49400 DestinationIp=13.107.42.16 DestinationPort=443 DestinationHostname=teams.microsoft.com` | `image=Teams.exe, user=CORP\jsmith, protocol=tcp, src_ip=10.0.1.45, src_port=49400, dst_ip=13.107.42.16, dst_port=443, dst_hostname=teams.microsoft.com, initiated=true` |
| 10:15:27 | DNSQuery | Sysmon | 10.0.1.45 | 10.0.1.1 | UDP/53 | `Dns query: UtcTime=2024-01-15 10:15:27.767 ProcessGuid={A23EAE89-BD56-5903-0000-0010F9D95E09} ProcessId=13692 QueryName=www.bing.com QueryStatus=0 QueryResults=204.79.197.200 Image=C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe` | `image=msedge.exe, query_name=www.bing.com, query_status=SUCCESS, query_results=204.79.197.200, process_id=13692` |
| 10:22:18 | NetworkConnection | Sysmon | 10.0.1.45 | 104.16.85.20 | TCP/443 | `Network connection detected: UtcTime=2024-01-15 10:22:18.878 ProcessGuid={A23EAE89-BD56-5903-0000-0010F1D95E01} ProcessId=8824 Image=C:\Program Files\Google\Chrome\Application\chrome.exe User=CORP\jsmith Protocol=tcp SourceIp=10.0.1.45 SourcePort=49750 DestinationIp=104.16.85.20 DestinationPort=443 DestinationHostname=cdn.jsdelivr.net` | `image=chrome.exe, user=CORP\jsmith, protocol=tcp, src_ip=10.0.1.45, src_port=49750, dst_ip=104.16.85.20, dst_port=443, dst_hostname=cdn.jsdelivr.net, initiated=true` |
| 10:30:45 | FileCreate | Sysmon | 10.0.1.45 | | | `File created: UtcTime=2024-01-15 10:30:45.989 ProcessGuid={A23EAE89-BD56-5903-0000-0010E9D95E00} ProcessId=1284 Image=C:\Windows\System32\svchost.exe TargetFilename=C:\Windows\Prefetch\CHROME.EXE-ABC12345.pf CreationUtcTime=2024-01-15 10:30:45.989` | `image=svchost.exe, target_filename=C:\Windows\Prefetch\CHROME.EXE-ABC12345.pf, user=NT AUTHORITY\SYSTEM, process_id=1284` |
| 10:45:33 | ProcessCreate | Sysmon | 10.0.1.45 | | | `Process Create: UtcTime=2024-01-15 10:45:33.090 ProcessGuid={A23EAE89-BD56-5903-0000-0010FAD95E10} ProcessId=14804 Image=C:\Users\jsmith\AppData\Local\slack\slack.exe CommandLine="C:\Users\jsmith\AppData\Local\slack\slack.exe" User=CORP\jsmith ParentImage=C:\Windows\explorer.exe` | `image=slack.exe, commandline=slack.exe, user=CORP\jsmith, parent_image=explorer.exe, process_id=14804, integrity_level=Medium` |
| 11:00:12 | NetworkConnection | Sysmon | 10.0.1.45 | 99.181.64.71 | TCP/443 | `Network connection detected: UtcTime=2024-01-15 11:00:12.101 ProcessGuid={A23EAE89-BD56-5903-0000-0010FAD95E10} ProcessId=14804 Image=C:\Users\jsmith\AppData\Local\slack\slack.exe User=CORP\jsmith Protocol=tcp SourceIp=10.0.1.45 SourcePort=49700 DestinationIp=99.181.64.71 DestinationPort=443 DestinationHostname=slack.com` | `image=slack.exe, user=CORP\jsmith, protocol=tcp, src_ip=10.0.1.45, src_port=49700, dst_ip=99.181.64.71, dst_port=443, dst_hostname=slack.com, initiated=true` |

---

## Event Type Distribution

| EVENT TYPE | Count | Description |
|------------|-------|-------------|
| ProcessCreate | 7 | User and system process launches |
| NetworkConnection | 6 | Outbound connections to known services |
| DNSQuery | 4 | DNS lookups for legitimate domains |
| FileCreate | 3 | Document saves, downloads, prefetch |
| RegistryEvent | 1 | User preference updates |

---

## Patterns Represented

### User Activity (jsmith)
- Opening browser (Chrome)
- Opening email (Outlook)
- Opening documents (Notepad, Word)
- Opening collaboration tools (Teams, Slack)
- Downloading files (Q4_Report.pdf)

### System Activity (SYSTEM)
- Service host processes (svchost.exe)
- Windows Update (TiWorker.exe)
- Scheduled tasks (taskhostw.exe)
- Prefetch file creation

### Network Destinations (All Legitimate)
- Google (142.250.80.68)
- Microsoft Office 365 (52.96.166.24)
- Windows Update (13.107.4.50)
- Microsoft Teams (13.107.42.16)
- Bing (204.79.197.200)
- CDN (104.16.85.20)
- Slack (99.181.64.71)

---

## Usage Notes

1. **SOURCE IP** (10.0.1.45) represents a single workstation - vary this for multiple endpoints
2. **DNS Server** (10.0.1.1) is the internal DNS resolver
3. **Empty fields** indicate the event type doesn't use that field
4. **Time progression** shows realistic business hours activity pattern
5. All processes use legitimate paths (C:\Program Files\, C:\Windows\)

---

## Sysmon Event ID Reference

| Event Type in Spectyr | Sysmon EventID |
|-----------------------|----------------|
| ProcessCreate | 1 |
| NetworkConnection | 3 |
| ProcessTerminate | 5 |
| FileCreate | 11 |
| RegistryEvent | 13 |
| DNSQuery | 22 |
