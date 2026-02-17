# Data Exfiltration - Level 3 Scenario

> **Category:** Exfiltration  
> **Subcategory:** Archive Collected Data / Exfiltration Over Alternative Protocol  
> **Difficulty:** Level 3 (Context Analysis)  
> **Events:** 2

---

## Scenario Description

A workstation generated a process creation event showing a command-line archiving tool compressing files from a local staging folder. Shortly after, the firewall logged an unusually large outbound HTTPS connection from the same workstation to an external cloud storage service. Review the Sysmon and Firewall logs and determine if these events represent data exfiltration.

---

## Attack Pattern Reference

| Framework | ID | Name | Link |
|-----------|-----|------|------|
| MITRE ATT&CK | **T1560.001** | Archive Collected Data: Archive via Utility | [attack.mitre.org](https://attack.mitre.org/techniques/T1560/001/) |
| MITRE ATT&CK | **T1567.002** | Exfiltration Over Web Service: Exfiltration to Cloud Storage | [attack.mitre.org](https://attack.mitre.org/techniques/T1567/002/) |
| ATT&CK Tactic | **TA0010** | Exfiltration | |
| CAPEC | **CAPEC-118** | Collect and Analyze Information | [capec.mitre.org](https://capec.mitre.org/data/definitions/118.html) |

---

## Log Events

### Event 1 of 2 — Sensitive Files Compressed into Password-Protected Archive

#### Table View

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| 19:08:14 | ProcessCreate | Sysmon | 10.0.1.45 | | | `Process Create: UtcTime=2026-01-27 19:08:14.305 ProcessGuid={A23EAE89-BD56-5903-0000-0010KLP95E55} ProcessId=15820 Image=C:\Program Files\7-Zip\7z.exe CommandLine="C:\Program Files\7-Zip\7z.exe" a -tzip -pF1nance2026 -mhe=on C:\Users\jsmith\Desktop\Project_Archive\backup.zip C:\Users\jsmith\Desktop\Project_Archive\*.xlsx User=CORP\jsmith ParentImage=C:\Windows\System32\cmd.exe ParentCommandLine=cmd.exe ParentProcessId=15604` |

#### Expanded Key Value Pairs

```
event_id = 1
event_type = ProcessCreate
utc_time = 2026-01-27 19:08:14.305
process_guid = {A23EAE89-BD56-5903-0000-0010KLP95E55}
process_id = 15820
image = C:\Program Files\7-Zip\7z.exe
command_line = "C:\Program Files\7-Zip\7z.exe" a -tzip -pF1nance2026 -mhe=on C:\Users\jsmith\Desktop\Project_Archive\backup.zip C:\Users\jsmith\Desktop\Project_Archive\*.xlsx
user = CORP\jsmith
parent_image = C:\Windows\System32\cmd.exe
parent_command_line = cmd.exe
parent_process_id = 15604
integrity_level = Medium
host = WS-PC045
hashes = SHA256=4F71A43A4D3F6F24D5D0C1BFAE0E7D2B8C9A1E3F5D7B9C2A4E6F8D0B3C5A7E91
```

---

### Event 2 of 2 — Large Outbound Transfer to Cloud Storage

#### Table View

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| 19:10:47 | ALLOW | Firewall | 10.0.1.45 | 31.13.84.2 | TCP/443 | `firewall src=10.0.1.45 dst=31.13.84.2 mac=00:1A:2B:3C:4D:45 protocol=tcp sport=51344 dport=443 pattern: allow https_outbound bytes_sent=4782091 bytes_recv=1245 duration=38` |

#### Expanded Key Value Pairs

```
src_ip = 10.0.1.45
dst_ip = 31.13.84.2
src_port = 51344
dst_port = 443
protocol = tcp
action = allow
rule = https_outbound
direction = outbound
dst_host = mega.nz
mac = 00:1A:2B:3C:4D:45
bytes_sent = 4782091
bytes_recv = 1245
duration = 38
host = FW01
```

---

## Expected Answer

**Classification:** Malicious - Exfiltration

**Threat Category:** Data Archiving and Exfiltration to Cloud Storage

---

## Triage Review

### What is it?

**Data Exfiltration** is the final stage of many attack chains — the point where stolen data actually leaves the network. In this scenario, an employee used 7-Zip to compress sensitive files from a local staging folder into a **password-protected archive**, then uploaded that archive to **Mega.nz**, a cloud storage service commonly used for data exfiltration due to its strong encryption and anonymous account creation.

This is the culmination of a data theft operation. The preparation (data collection and staging) has already occurred — this is the attacker getting the data out. Seeing these two events together means:
- Sensitive data has been collected and staged on the workstation (prior activity)
- The data has been compressed and password-protected to evade DLP inspection
- The data has been transferred to an external cloud service outside corporate control
- The data is now in the attacker's hands — the breach is complete

| Indicator | What It Means | Why It's Suspicious |
|-----------|---------------|---------------------|
| **`7z.exe` with `-p` flag** | Password-protected archive creation | Password protection prevents DLP tools from inspecting the archive contents |
| **`-mhe=on`** | Encrypt filenames inside archive | Even the file names are hidden — extra operational security |
| **Source: `Project_Archive\*.xlsx`** | Archiving all spreadsheets from a staging folder | Bulk collection of financial data from the same folder seen in the Insider Threat scenario |
| **Parent: `cmd.exe`** | Command executed via command prompt | Users typically use 7-Zip's GUI — command-line usage suggests deliberate, scripted action |
| **Destination: `mega.nz` (31.13.84.2)** | Mega cloud storage | Mega offers end-to-end encryption and anonymous accounts — favored by data thieves |
| **`bytes_sent=4,782,091` (~4.6 MB)** | Large outbound upload | This workstation's normal outbound traffic is small web requests — 4.6 MB upload is anomalous |
| **`bytes_recv=1,245`** | Tiny response from server | Asymmetric transfer: massive upload, minimal response — upload confirmation pattern |
| **`duration=38` seconds** | Quick, focused transfer | Not a browsing session — single large file upload |
| **Time: 19:08-19:10** | After business hours | Continuing the after-hours pattern from the staging activity |

### Understanding the Exfiltration Chain

```
PRIOR (Insider Threat scenario):
  jsmith accessed \\FS01\Finance_Confidential at 18:47
  Copied salary data to C:\Users\jsmith\Desktop\Project_Archive\
       │
       ▼
STEP 1: Archive and encrypt the staged data (19:08)
   │
   ├── 7z.exe compresses all .xlsx files in Project_Archive
   ├── Creates password-protected archive: backup.zip
   ├── Password: F1nance2026 (visible in command line)
   └── Encrypts filenames with -mhe=on → Event 1 (Sysmon ProcessCreate)
          │
          STEP 2: Upload archive to cloud storage (19:10)
          │
          ├── jsmith opens browser or uses upload tool
          ├── Connects to mega.nz (31.13.84.2) via HTTPS
          └── Uploads backup.zip (4.6 MB) → Event 2 (Firewall ALLOW)
               │
               └── Data is now outside the network — breach complete
```

### Understanding the 7-Zip Command

```
"C:\Program Files\7-Zip\7z.exe" a -tzip -pF1nance2026 -mhe=on C:\Users\jsmith\Desktop\Project_Archive\backup.zip C:\Users\jsmith\Desktop\Project_Archive\*.xlsx
```

| Component | Purpose | Suspicion Level |
|-----------|---------|-----------------|
| `7z.exe` | 7-Zip archiving utility — legitimate tool | Normal by itself |
| `a` | Add files to archive (create) | Normal |
| `-tzip` | Create ZIP format archive | Normal |
| `-pF1nance2026` | Set archive password to `F1nance2026` | **High** — password protection blocks DLP inspection |
| `-mhe=on` | Encrypt file header (hides filenames) | **Critical** — extra concealment, unnecessary for legitimate use |
| `backup.zip` | Output archive name | **Medium** — generic name hides true contents |
| `*.xlsx` | Archive all Excel files in the folder | **High** — bulk collection of spreadsheet data |

### Why Password-Protected Archives Are a Red Flag

| Feature | Legitimate Use | Exfiltration Use |
|---------|---------------|------------------|
| **Password protection** | Sharing sensitive files with external partner via email | Prevents DLP and security tools from scanning contents |
| **Filename encryption (`-mhe`)** | Rarely used legitimately | Hides evidence of what was archived — no legitimate business need in most cases |
| **Command-line execution** | Automated build/deployment scripts | Avoids 7-Zip GUI which might draw attention |
| **Source: staging folder** | Project backup before migration | Collecting stolen data for extraction |

### Common Exfiltration Destinations (Reference)

| Destination | Why Attackers Use It | Detection Indicator |
|-------------|---------------------|---------------------|
| **Mega.nz** | End-to-end encryption, anonymous accounts, 20GB free storage | Large outbound to mega.nz / mega.io IPs (this scenario) |
| **Personal Google Drive** | Ubiquitous, high storage limits, easy web upload | Upload to drive.google.com from non-corporate Google account |
| **Dropbox** | File sharing features, direct link generation | Large upload to dropbox.com outside corporate Dropbox |
| **Anonymous FTP** | No account needed for some servers | Outbound FTP (TCP/21) — unusual in modern networks |
| **Personal Email** | Attachments sent to personal address | Email with large attachment to non-corporate domain |
| **Pastebin / GitHub Gist** | Quick text/code sharing | POST to paste sites — unusual for business use |
| **USB Drive** | No network traffic generated | Sysmon removable media events, no firewall log |
| **Tor / VPN** | Anonymous routing | Connections to known Tor entry nodes |

### Attack Context

Data exfiltration (TA0010) is the objective that makes all preceding attack stages matter. Without successful exfiltration, an intrusion causes less lasting damage. Adversaries use archiving (T1560.001) combined with cloud storage exfiltration (T1567.002) because:

- **Password-protected archives bypass DLP** — Data Loss Prevention tools cannot inspect encrypted contents
- **Cloud storage is expected traffic** — HTTPS to cloud services blends with normal business activity
- **Encrypted filenames hide evidence** — even if the archive is intercepted, the contents are concealed
- **Cloud services offer large free storage** — Mega.nz provides 20GB free with anonymous signup
- **HTTPS encryption prevents inspection** — network security tools cannot read the upload payload

This two-step pattern (archive → upload) is the most common data exfiltration method for both insider threats and external attackers who have gained persistent access.

### Real-World Examples

| Incident | Exfiltration Method |
|----------|-------------------|
| **Tesla Insider Theft (2023)** | Employees copied confidential data to personal Dropbox accounts before departing |
| **Capital One (2019)** | Attacker exfiltrated 100M+ records by syncing data to personal cloud storage |
| **Waymo vs. Uber (2017)** | Engineer downloaded 14,000 files to a personal external hard drive |
| **APT29 (Cozy Bear)** | Used encrypted channels and cloud services to exfiltrate government data |
| **FIN7** | Archived and encrypted POS data before exfiltrating over HTTPS to attacker infrastructure |
| **Lapsus$ Group** | Exfiltrated source code via personal Mega.nz and Telegram accounts |

### MITRE ATT&CK Context

**Technique T1560.001 - Archive Collected Data: Archive via Utility**

> "Adversaries may use utilities to compress and/or encrypt collected data prior to exfiltration. Many utilities include functionalities to compress, encrypt, or otherwise package data into a format that is easier/more secure to transport."

**Technique T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage**

> "Adversaries may exfiltrate data to a cloud storage service rather than over their primary command and control channel. Cloud storage services allow for the storage, edit, and retrieval of data from a remote cloud storage server over the Internet."

**Detection Focus:**
- Monitor for command-line archiving tools (7z.exe, rar.exe, zip.exe) with password flags (`-p`, `-hp`)
- Alert on encrypted filename flags (`-mhe`) — almost never legitimate
- Track large outbound transfers (>1 MB) to cloud storage domains
- Detect asymmetric transfer patterns — large upload, tiny response
- Correlate archive creation events with subsequent large outbound connections from the same host

---

## Recommended Response Actions

### Immediate Actions
1. **Isolate the workstation** (WS-PC045) — prevent any additional data from leaving the network
2. **Block the destination** — add `mega.nz` and IP `31.13.84.2` to proxy/firewall blocklists (consider blocking Mega entirely)
3. **Preserve evidence** — capture the `Project_Archive` folder contents, the `backup.zip` archive, and browser history before the employee can delete them

### Investigation Steps
4. **Determine what was exfiltrated** — the password `F1nance2026` is visible in the command line; use it to decrypt `backup.zip` and inventory the contents
5. **Quantify the breach** — identify all files in the `Project_Archive` folder and assess sensitivity (connect to Insider Threat scenario)
6. **Check for additional exfiltration** — search firewall logs for other large outbound transfers from WS-PC045 to cloud storage, personal email, or file sharing services
7. **Review Mega.nz access** — determine if jsmith has an account, when it was created, and what else may have been uploaded
8. **Correlate with prior activity** — connect this exfiltration to the earlier data staging events (Insider Threat scenario at 18:47)

### Remediation
9. **Revoke access** — disable jsmith's domain account and VPN access immediately
10. **Legal engagement** — notify legal team for potential civil or criminal action; preserve evidence chain of custody
11. **Data recovery** — if possible, issue takedown request to Mega.nz (requires legal involvement)

### Post-Incident
12. **Document the full chain** — create incident report covering collection (18:47), staging, archiving (19:08), and exfiltration (19:10)
13. **Implement DLP controls** — deploy Data Loss Prevention that can detect password-protected archive creation and block unauthorized cloud storage uploads
14. **Block personal cloud storage** — evaluate policy to block personal Mega.nz, Dropbox, Google Drive (non-corporate) at the proxy/firewall level

---

## Log Authenticity Notes

### Event 1 — Sysmon ProcessCreate

| Field | Value | Why It's Realistic |
|-------|-------|-------------------|
| `Image=7z.exe` | Legitimate 7-Zip installed in Program Files — attackers use tools already on the system |
| `-pF1nance2026` | Password visible in command line — Sysmon captures full command-line arguments |
| `-mhe=on` | Filename encryption — extra OPSEC that stands out as unusual |
| `*.xlsx` | Wildcard archiving — grabbing all spreadsheets at once |
| `ParentImage=cmd.exe` | Command prompt — not the 7-Zip GUI, suggests scripted or deliberate action |
| `User=CORP\jsmith` | Same user from the Insider Threat staging scenario |
| `IntegrityLevel=Medium` | Standard user privileges — no elevation needed for archiving |

### Event 2 — Firewall ALLOW

| Field | Value | Why It's Realistic |
|-------|-------|-------------------|
| `dst_host=mega.nz` | Cloud storage known for privacy/anonymity — common exfil destination |
| `bytes_sent=4,782,091` | ~4.6 MB upload — abnormal for this workstation's typical web browsing |
| `bytes_recv=1,245` | Tiny response — server acknowledged the upload, no large download |
| `duration=38` | 38-second connection — focused upload, not a browsing session |
| `dport=443` | HTTPS — encrypted, so firewall can only see metadata, not content |
| `rule=https_outbound` | Standard outbound HTTPS rule — allowed because it's port 443 |

### Legitimate vs Malicious Comparison

| Legitimate Archive + Upload | Data Exfiltration (This Scenario) |
|----------------------------|-----------------------------------|
| Archiving project files for backup | Archiving sensitive financial data from a staging folder |
| No password, or shared team password | Password set via command line (`-pF1nance2026`) — personal, concealing |
| No filename encryption | `-mhe=on` — actively hiding what was archived |
| 7-Zip GUI with manual file selection | Command-line with wildcard (`*.xlsx`) — bulk, scripted |
| Upload to corporate cloud storage (OneDrive, SharePoint) | Upload to personal Mega.nz — anonymous, unmonitored |
| During business hours as part of workflow | After hours (19:08) — same pattern as staging activity |
| Symmetric transfer (upload and download) | Asymmetric — massive upload, tiny response |

---

## Cross-Log Correlation Guide

### How the Two Events Connect

```
Timeline on WS-PC045 and FW01:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
19:08:14  ─── Sysmon ProcessCreate ─── 7z.exe creates password-protected backup.zip from staged files
    │
    │  ~2 min 33 sec (user opens browser, navigates to Mega.nz, initiates upload)
    │
19:10:47  ─── Firewall ALLOW ─── 4.6 MB uploaded from WS-PC045 to mega.nz over HTTPS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Correlation Anchors

| Anchor Point | Event 1 (Sysmon) | Event 2 (Firewall) |
|-------------|-------------------|---------------------|
| **Source Host** | `host=WS-PC045` | `src_ip=10.0.1.45 (WS-PC045)` |
| **User** | `user=CORP\jsmith` | MAC `00:1A:2B:3C:4D:45` (jsmith's workstation) |
| **Time Proximity** | `19:08:14` | `19:10:47` (~2.5 min later) |
| **Data Flow** | Archive created (~4.6 MB of xlsx files) | ~4.6 MB uploaded outbound (`bytes_sent=4,782,091`) |
| **Context** | Files archived from staging folder | Archive uploaded to anonymous cloud storage |

### Why Neither Event Alone Is Conclusive

| Event Alone | Why It's Ambiguous |
|-------------|-------------------|
| **Sysmon ProcessCreate (7z.exe) only** | Users compress files regularly — project archives, email attachments, backups. 7-Zip is a common legitimate tool |
| **Firewall ALLOW (large outbound) only** | Outbound HTTPS traffic happens all day. A 4.6 MB transfer could be a video call, cloud sync, or file share upload |
| **Together** | Password-protected archive created from a staging folder + same-size upload to anonymous cloud storage 2.5 minutes later = data exfiltration. The password protection, filename encryption, destination (Mega.nz), and timing (after hours) complete the picture |

### The Level 3 Difficulty Factor

This scenario requires the player to connect technical indicators with behavioral context:

| Context Factor | What the Player Must Recognize |
|---------------|-------------------------------|
| **Archive password in command line** | `-pF1nance2026` — the password is visible and themed to the stolen data. Also, password-protecting an archive is a DLP evasion technique |
| **Filename encryption** | `-mhe=on` is almost never used in legitimate business operations — it's operational security |
| **File size correlation** | The archive size (~4.6 MB) approximately matches the outbound transfer size (`bytes_sent=4,782,091`) |
| **Destination reputation** | Mega.nz is not a corporate-approved cloud service — it's known for anonymous, encrypted file storage |
| **Transfer asymmetry** | 4.6 MB sent, 1.2 KB received — this is an upload, not browsing or downloading |
| **Continuity from Insider Threat** | The source folder (`Project_Archive`) and user (jsmith) match the earlier data staging activity |

### Full Attack Chain (Connecting Scenarios)

```
18:47:22  ─── Insider Threat ─── jsmith accesses \\FS01\Finance_Confidential
18:48:05  ─── Insider Threat ─── Salary data copied to Desktop\Project_Archive\
    │
    │  ~20 minutes
    │
19:08:14  ─── Data Exfil ─── 7z.exe archives Project_Archive\*.xlsx with password
19:10:47  ─── Data Exfil ─── 4.6 MB uploaded to mega.nz
    │
    └── Breach complete — salary data for all staff now in jsmith's personal cloud storage
```

---

## Level Progression Preview

| Level | Events | Complexity |
|-------|--------|------------|
| **Level 1** | 1 | Single event — Large outbound transfer to unusual destination |
| **Level 2** | 2 | Two events — Data archived + transferred (clear indicators) |
| **Level 3** (Current) | 2 | Two events — Password-protected archive + cloud upload (context-heavy, connects to prior insider threat activity) |

---

## Related Log Sources

For more advanced scenarios, data exfiltration can be detected across multiple sources:

| Log Source | Event Type | What It Shows |
|------------|------------|---------------|
| **Sysmon Event 1** | ProcessCreate | Archive utility execution with command-line arguments (this scenario) |
| **Firewall ALLOW** | Outbound HTTPS | Large outbound data transfer (this scenario) |
| **Sysmon Event 11** | FileCreate | Archive file written to disk (backup.zip creation) |
| **Proxy HTTP_POST** | Upload | Detailed upload URL and destination analysis |
| **Sysmon Event 3** | NetworkConnection | Process-level identification of which application made the upload |
| **DNS QUERY_RECEIVED** | DNS Query | Resolution of cloud storage domain before upload |
| **Windows Security 4663** | Object Access | File-level read operations on sensitive data before archiving |
| **DLP Alerts** | Policy Violation | Triggered by sensitive data patterns in outbound traffic (if not encrypted) |

---

## Detection Rule Logic (Reference)

```
# Sysmon: Password-protected archive creation
MATCH sysmon_logs WHERE
  event_type = "ProcessCreate"
  AND (
    image CONTAINS "7z.exe" OR
    image CONTAINS "rar.exe" OR
    image CONTAINS "WinRAR.exe" OR
    image CONTAINS "zip.exe"
  )
  AND (
    command_line CONTAINS "-p" OR
    command_line CONTAINS "-hp" OR
    command_line CONTAINS "-mhe" OR
    command_line CONTAINS "--password"
  )

# Firewall: Abnormal large outbound transfer
MATCH firewall_logs WHERE
  action = "ALLOW"
  AND direction = "outbound"
  AND dst_port = 443
  AND bytes_sent > 1000000
  AND (
    dst_host IN ("mega.nz", "mega.io", "anonfiles.com", "gofile.io", 
                  "transfer.sh", "file.io", "wetransfer.com") OR
    dst_host NOT IN corporate_approved_cloud_services
  )

# Correlation: Archive creation followed by large upload
MATCH sysmon_logs AS archive
  JOIN firewall_logs AS upload
  ON archive.host_ip = upload.src_ip
  AND upload.event_time BETWEEN archive.utc_time AND archive.utc_time + 600s
WHERE
  archive.event_type = "ProcessCreate"
  AND archive.image MATCHES "*7z*" OR archive.image MATCHES "*rar*"
  AND archive.command_line CONTAINS "-p"
  AND upload.action = "ALLOW"
  AND upload.bytes_sent > 1000000
  AND upload.dst_host NOT IN corporate_approved_cloud_services
```

---

## Common False Positives

Understanding legitimate scenarios helps avoid alert fatigue:

| False Positive Scenario | How to Identify |
|-------------------------|-----------------|
| Employee archiving project files for handoff to colleague | No password protection, uploaded to corporate OneDrive/SharePoint, during business hours |
| IT backup process compressing logs for retention | Service account, automated schedule, destination is corporate backup storage |
| Developer archiving source code for release | Known build pipeline, destination is corporate artifact repository |
| Employee sharing large files with external vendor | Documented in project plan, uploaded to approved file sharing service |
| Automated cloud sync uploading changed files | Consistent daily pattern, small incremental transfers, known sync agent process |

**Key Differentiators:**
- Legitimate: No password/encryption, corporate cloud destination, business hours, consistent pattern, documented
- Malicious: Password-protected, filename encryption, personal cloud destination, after hours, anomalous volume, connects to prior suspicious activity

---

## Process Chain Analysis

Understanding the archiving and upload behavior:

### Suspicious Chain (This Scenario)
```
[WS-PC045] cmd.exe (jsmith — manually opened command prompt)
  └── 7z.exe a -tzip -pF1nance2026 -mhe=on backup.zip *.xlsx
      └── Creates: C:\Users\jsmith\Desktop\Project_Archive\backup.zip
           │
           └── Browser uploads backup.zip to mega.nz
               └── Firewall: 4.6 MB outbound to 31.13.84.2:443
```
**Why Suspicious:** Password-protected archive with filename encryption, source is staged sensitive data, uploaded to anonymous cloud storage, after hours, command-line execution

### Legitimate Chain (IT Backup)
```
[WS-PC045] svchost.exe (Scheduled Task)
  └── 7z.exe a -tzip C:\Backups\logs_2026-01-27.zip C:\Logs\*.log
      └── Creates: C:\Backups\logs_2026-01-27.zip
           │
           └── robocopy syncs to \\BACKUP01\Archives\
               └── Firewall: internal traffic to 10.0.1.100:445
```
**Why Legitimate:** No password protection, system logs (not sensitive data), automated via scheduled task, destination is internal backup server, standard business process

---

## Exfiltration Detection Cheat Sheet

Quick reference for identifying data exfiltration vs normal uploads:

| Indicator | Normal Upload | Data Exfiltration |
|-----------|--------------|-------------------|
| **Archive tool** | GUI-based, no password | Command-line, password-protected, encrypted filenames |
| **Source files** | Project docs, meeting notes | Sensitive data (salary, financials, client lists, source code) |
| **Destination** | Corporate OneDrive, SharePoint, Teams | Personal Mega, Dropbox, Google Drive, anonymous file hosts |
| **Transfer size** | Varies, consistent with workflow | Anomalously large for the user's baseline |
| **Transfer pattern** | Symmetric (upload and download) | Asymmetric (large upload, tiny response) |
| **Timing** | Business hours | After hours, weekends |
| **User behavior** | Consistent with role | Outside normal access patterns (connects to prior anomalies) |
| **DLP visibility** | Contents inspectable | Password protection blocks DLP inspection |

---

*Last Updated: January 2026*  
*Spectyr Training Platform*
