# Insider Threat: Shadow IT — Unauthorized Cloud Storage (Dropbox) — Level 5

> **Category:** Insider Threat
> **Subcategory:** Shadow IT: Unauthorized Cloud Storage
> **Difficulty:** Level 5 (Contextual Analysis)
> **Events:** 3
> **MITRE ATT&CK:** T1567.002 — Exfiltration Over Web Service: Exfiltration to Cloud Storage

---

## Scenario Description

A workstation generated a Sysmon process creation event showing the Dropbox desktop sync client launching at system startup. Minutes later, a sensitive legal document appeared in the user's local Dropbox sync folder. Shortly after, the proxy logged a large HTTP POST to Dropbox's data sync servers. The company's approved cloud storage is OneDrive — Dropbox is not authorized. Review the logs and determine if this represents a Shadow IT policy violation with data exposure risk.

---

## Attack Pattern Reference

| Framework | ID | Name | Link |
|-----------|-----|------|------|
| MITRE ATT&CK | **T1567.002** | Exfiltration Over Web Service: Exfiltration to Cloud Storage | [attack.mitre.org](https://attack.mitre.org/techniques/T1567/002/) |
| MITRE ATT&CK | **T1567** | Exfiltration Over Web Service | [attack.mitre.org](https://attack.mitre.org/techniques/T1567/) |
| ATT&CK Tactic | **TA0010** | Exfiltration | |
| ATT&CK Tactic | **TA0048** | Initial Access (potential — creates unmonitored entry point) | |

> **Note:** While T1567.002 is technically an exfiltration technique, the intent here is not malicious data theft. The employee is using Dropbox for convenience — this is Shadow IT. The MITRE mapping reflects what the logs show (data leaving to cloud storage), but the classification is Insider Threat because the root cause is unauthorized tool usage, not deliberate exfiltration. This distinction matters for triage — the response is policy enforcement, not incident response.

---

## Log Events

### Event 1 of 3 — Dropbox Sync Client Running (Sysmon ProcessCreate)

**Table View:**

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| {timestamp_1} | ProcessCreate | Sysmon | {src_ip} | — | — | Process created: Dropbox.exe by {user_domain}. |

**Key Value Pairs:**

```
timestamp = {timestamp_1}
event_type = ProcessCreate
source_type = Sysmon
host = {hostname}
src_ip = {src_ip}
user = {user_domain}
command_line = "C:\Users\{username}\AppData\Roaming\Dropbox\bin\Dropbox.exe" /systemstartup
parent_process = C:\Windows\explorer.exe
process = C:\Users\{username}\AppData\Roaming\Dropbox\bin\Dropbox.exe
process_id = 14320
message = Process created: Dropbox.exe by {user_domain}.
```

---

### Event 2 of 3 — Sensitive File Copied to Dropbox Folder (Sysmon FileCreate)

**Table View:**

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| {timestamp_2} | FileCreate | Sysmon | {src_ip} | — | — | File created: ACME_Client_NDA_2026.pdf by {user_domain}. |

**Key Value Pairs:**

```
timestamp = {timestamp_2}
event_type = FileCreate
source_type = Sysmon
host = {hostname}
src_ip = {src_ip}
user = {user_domain}
process = C:\Windows\explorer.exe
process_id = 4892
target_filename = C:\Users\{username}\Dropbox\Work Documents\ACME_Client_NDA_2026.pdf
message = File created: ACME_Client_NDA_2026.pdf by {user_domain}.
```

---

### Event 3 of 3 — Data Uploaded to Dropbox Servers (Proxy HTTP_POST)

**Table View:**

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| {timestamp_3} | HTTP_POST | Proxy | {src_ip} | 162.125.64.18 | TCP/443 | POST request to d.dropbox.com/upload returned 200 OK. |

**Key Value Pairs:**

```
timestamp = {timestamp_3}
event_type = HTTP_POST
source_type = Proxy
host = {hostname}
src_ip = {src_ip}
user = {user_domain}
domain = d.dropbox.com
dst_ip = 162.125.64.18
http_status = 200
url_path = /upload
content_type = application/octet-stream
bytes = 2847561
message = POST request to d.dropbox.com/upload returned 200 OK.
```

---

## Expected Answer

**Classification:** Insider Threat — Shadow IT (Unauthorized Cloud Storage)
**Threat Level:** Medium-High
**Confidence:** High

---

## Triage Review

### What is it?

**Shadow IT** is when employees use technology — software, services, hardware — that hasn't been approved, vetted, or monitored by the IT or security team. In this scenario, an employee installed the Dropbox desktop sync client on their corporate workstation and is syncing sensitive legal documents to their personal Dropbox account. The company's approved cloud storage platform is OneDrive.

This isn't a malicious insider trying to steal data. The employee probably just finds Dropbox more convenient, wants access to files on their personal devices, or doesn't realize there's a policy against it. But the security impact is the same regardless of intent:

- **Sensitive corporate data is now stored on a personal cloud account** outside of IT's control
- **No DLP, no encryption, no access controls** — Dropbox's personal tier doesn't have enterprise security features
- **The data could be shared, synced to other devices, or exposed** if the employee's Dropbox account is compromised
- **IT has no visibility** — they can't audit, monitor, or revoke access to data in the employee's personal Dropbox
- **Legal and compliance risk** — client NDAs and legal documents stored on unsanctioned platforms may violate data handling requirements

| Indicator | What It Means | Why It's Suspicious |
|-----------|---------------|---------------------|
| **`Dropbox.exe` running on corporate workstation** | Dropbox desktop client is installed and active | Not an approved application — Shadow IT |
| **`/systemstartup` flag** | Dropbox is set to auto-launch at login | This has been installed for a while — not a first-time run |
| **`AppData\Roaming\Dropbox\bin\` path** | Installed in user profile, not Program Files | User-level install — didn't need admin privileges, IT wasn't involved |
| **`explorer.exe` as process for FileCreate** | User manually copied the file via File Explorer | Deliberate action — the user dragged or copied the file into Dropbox |
| **`\Dropbox\Work Documents\` folder** | User created a "Work Documents" folder inside Dropbox | They've organized a system for syncing work files — this is ongoing, not a one-time accident |
| **`ACME_Client_NDA_2026.pdf` filename** | Client-facing legal document | Sensitive data — NDAs contain confidential client information |
| **`d.dropbox.com` upload** | Dropbox's data sync subdomain | The file is actively being uploaded to Dropbox's servers |
| **2.8 MB upload** | Full document uploaded | The complete file left the corporate environment |

### Understanding the Attack Chain

```
PRIOR (not visible in these logs):
  Employee installed Dropbox desktop client
  Created personal Dropbox account (or linked existing one)
  Set up "Work Documents" folder for syncing
       │
       ▼
EVENT 1: Dropbox starts at login ({timestamp_1})
   │
   ├── Dropbox.exe launches with /systemstartup
   ├── Auto-start means this is an established setup
   └── Begins syncing in the background
          │
          EVENT 2: User copies NDA to Dropbox folder (minutes later)
          │
          ├── explorer.exe = manual file copy (drag and drop)
          ├── Target: \Dropbox\Work Documents\ folder
          ├── File: ACME_Client_NDA_2026.pdf (sensitive legal document)
          └── Dropbox client detects new file
               │
               EVENT 3: Dropbox uploads file to cloud (~10-30s later)
               │
               ├── POST to d.dropbox.com/upload
               ├── 2.8 MB uploaded (full document)
               └── File is now on Dropbox's servers
                    │
                    RESULT: Sensitive legal document is now stored on
                    an unsanctioned personal cloud account outside
                    IT's control, monitoring, and security policies
```

### Shadow IT vs Data Exfiltration — How the Player Should Distinguish

This scenario uses the same MITRE technique (T1567.002) as deliberate data exfiltration, but the context is completely different. The player needs to learn that **the same technical indicators can mean different things depending on context.**

| Factor | Shadow IT (This Scenario) | Deliberate Data Exfiltration |
|--------|--------------------------|------------------------------|
| **Tool** | Well-known consumer app (Dropbox, Google Drive) | Attacker-controlled infrastructure, encrypted channels, Tor |
| **Installation** | User-level install in AppData, auto-start enabled | Hidden tool, no persistence, or disguised process name |
| **Behavior** | Regular sync pattern, "Work Documents" folder | Bulk download followed by single large upload, then tool deleted |
| **Timing** | Business hours, matches normal work patterns | After hours, weekends, right before employee departure |
| **Volume** | Individual files synced over time | Large archive (ZIP/RAR) uploaded in one session |
| **User profile** | Regular employee with no HR flags | Employee on PIP, just gave notice, or recently had access change |
| **Intent** | Convenience — "I just want my files on my laptop" | Theft — deliberate collection and removal of data |
| **Response** | Policy enforcement, user education, IT remediation | Incident response, legal hold, potential termination |

### The Scale of Shadow IT

Shadow IT isn't a rare edge case — it's one of the most common security issues in every organization:

- 65% of SaaS applications in the average enterprise are unsanctioned
- The average company has 975 unknown cloud services vs only 108 IT-approved ones
- 69% of employees deliberately bypass cybersecurity measures
- Shadow IT accounts for 30-40% of IT spending in large enterprises
- 11% of cyber incidents in the past two years were caused by unauthorized Shadow IT usage

For SOC analysts, Shadow IT alerts are among the most frequent tickets. Learning to identify, classify, and respond to them correctly is a core skill.

### Why This Matters for Law Firms

Legal environments have heightened sensitivity to Shadow IT because:

- **Attorney-client privilege** — documents stored on unsanctioned platforms may not be protected
- **Client data handling requirements** — NDAs and contracts may specify where data can be stored
- **Regulatory compliance** — legal industry regulations often require data residency and access controls
- **Malpractice liability** — improper handling of client documents creates legal exposure
- **eDiscovery** — data scattered across personal cloud accounts complicates legal holds and discovery

A client NDA on a personal Dropbox account isn't just a policy violation — it's a potential compliance incident.

---

## Recommended Triage Steps

### 1. Confirm the Application
Verify that `Dropbox.exe` is not on the list of approved applications. Check with IT asset management — if Dropbox hasn't been deployed through SCCM, Intune, or another management tool, it's unauthorized.

### 2. Assess the Data Sensitivity
Review the filename: `ACME_Client_NDA_2026.pdf`. This is a client-facing legal document. Determine the sensitivity classification — client NDAs typically contain confidential information and may have specific handling requirements.

### 3. Check Scope of Sync
Search for additional FileCreate events in the `\Dropbox\` directory on this host. Is this one file, or has the employee been syncing an entire folder of work documents? The "Work Documents" subfolder suggests ongoing usage, not a one-time incident.

### 4. Review Proxy History
Check proxy logs for historical traffic to `*.dropbox.com` from {src_ip}. How long has this been going on? Volume and duration determine the scope of potential data exposure.

### 5. Notify IT and Management
This is a policy violation, not a criminal act. The appropriate response is:
- IT: Remove Dropbox from the workstation, block the domain at the proxy
- Management: Inform the employee's supervisor
- HR: Document the policy violation
- Legal/Compliance: Assess whether any data handling requirements were violated

### 6. Recover and Remediate
- Work with the employee to identify all corporate files in their personal Dropbox
- Have the employee delete corporate files from Dropbox (and verify deletion)
- If the employee resists or the data is highly sensitive, involve legal
- Ensure the employee has access to the approved cloud storage (OneDrive)

### 7. Do Not Escalate as Incident Response
Unless there are additional indicators of malicious intent (employee on PIP, about to leave, bulk data download), this is a **policy enforcement** matter, not an incident response scenario. Treat the employee as someone who needs education, not as a threat.

---

## Generation Rules

| Variable | Rule |
|----------|------|
| {src_ip} | Same across all 3 events — same host |
| {hostname} | Same across all 3 events — same host |
| {username} | Same across all 3 events — employee using unauthorized tool |
| {user_domain} | ACME\\{username} |
| process_id (Event 1) | 14320 — Dropbox client process |
| process_id (Event 2) | 4892 — explorer.exe (user copying files) |
| {timestamp_1} → {timestamp_2} | Minutes to hours (Dropbox starts at login, file copied during work) |
| {timestamp_2} → {timestamp_3} | ~10-30 seconds (Dropbox syncs new files almost immediately) |
| Timestamps | Business hours — employee doing normal work, just using wrong tool |
| Filename | Should be clearly corporate/sensitive — client-facing legal document |

---

## What the Player Should Recognize

| Indicator | Evidence |
|-----------|----------|
| Unauthorized application running | Dropbox.exe is not an approved corporate tool — Shadow IT |
| User-level installation | AppData\Roaming path = installed without admin/IT involvement |
| Auto-start configured | `/systemstartup` flag = ongoing usage, not a first-time run |
| Sensitive file in sync folder | Client NDA in `\Dropbox\Work Documents\` = corporate data leaving the environment |
| Manual file copy | explorer.exe as process = user deliberately moved the file |
| Active cloud upload | POST to d.dropbox.com confirms data reached external servers |
| Upload size matches file | 2.8 MB = full document uploaded, not just metadata |
| "Work Documents" subfolder | Employee has an organized system = this is habitual behavior |

### The Level 5 Difficulty Factor

| Stage | What the Player Must Recognize | Difficulty |
|-------|-------------------------------|------------|
| **1. Application Identification** | Player must know Dropbox isn't an approved corporate tool — requires knowledge of the organization's software policy | Medium |
| **2. Intent Classification** | This is Shadow IT, not malicious exfiltration — the player must distinguish convenience from theft based on context clues (consumer app, business hours, organized folder structure) | High |
| **3. Data Sensitivity Assessment** | The filename reveals this is a client NDA — the player must recognize that legal documents in personal cloud storage creates compliance risk | High |
| **4. Cross-Source Correlation** | Connecting Sysmon ProcessCreate + Sysmon FileCreate + Proxy POST across two log sources to build the complete picture | Medium |
| **5. Appropriate Response** | The player must recommend policy enforcement rather than incident response — overtriaging Shadow IT as a malicious threat wastes resources | High |

---

## Level Progression Preview

| Level | Events | Complexity |
|-------|--------|------------|
| **Level 3** (Data Theft) | 2 | Employee accesses restricted share and stages files — clear malicious pattern |
| **Level 5** (Current) | 3 | Shadow IT — player must distinguish convenience from malice, assess data sensitivity, recommend proportional response |
| **Level 7+** (Future) | 4-5 | Departing employee systematically exfiltrating data through multiple Shadow IT channels over weeks |

---

## Related Log Sources

Additional logs that would appear in a real environment during this scenario:

| Log Source | Event | What It Shows |
|------------|-------|---------------|
| **Proxy** | HTTP_GET | Download of Dropbox installer from `www.dropbox.com` (historical — installation event) |
| **Sysmon ProcessCreate** | Installer execution | `DropboxInstaller.exe` running (historical — installation event) |
| **DNS** | Query | Repeated queries for `d.dropbox.com`, `notify.dropboxapi.com`, `api.dropbox.com` |
| **Firewall** | ALLOW | Persistent outbound HTTPS (443) connections to Dropbox IP ranges |
| **Windows Security 4688** | Process Created | Shows Dropbox.exe launch with command-line arguments |
| **Sysmon NetworkConnection** | Outbound connection | Dropbox.exe connecting to Dropbox servers |

---

## Detection Rule Logic

```
# Detect unauthorized cloud storage clients running
MATCH sysmon_logs WHERE
  event_type = "ProcessCreate"
  AND (
    process LIKE "%Dropbox.exe"
    OR process LIKE "%GoogleDriveSync.exe"
    OR process LIKE "%iCloudDrive.exe"
    OR process LIKE "%pCloud.exe"
    OR process LIKE "%SyncClient.exe"
  )
  AND process NOT IN approved_software_list

# Detect files created in cloud sync folders
MATCH sysmon_logs WHERE
  event_type = "FileCreate"
  AND (
    target_filename LIKE "%\Dropbox\%"
    OR target_filename LIKE "%\Google Drive\%"
    OR target_filename LIKE "%\pCloud\%"
    OR target_filename LIKE "%\Box Sync\%"
  )
  AND target_filename NOT LIKE "%\OneDrive\%" -- OneDrive is approved

# Detect uploads to unauthorized cloud storage domains
MATCH proxy_logs WHERE
  event_type = "HTTP_POST"
  AND (
    domain LIKE "%dropbox.com"
    OR domain LIKE "%drive.google.com"
    OR domain LIKE "%pcloud.com"
    OR domain LIKE "%box.com"
  )
  AND bytes > 100000 -- Files larger than 100KB being uploaded

# Detect persistent cloud sync connections
MATCH firewall_logs WHERE
  dst_ip IN dropbox_ip_ranges
  AND connection_count > 50 WITHIN 1 HOUR
  -- Cloud sync clients maintain persistent connections
```

---

## Common False Positives

| False Positive Scenario | How to Identify |
|-------------------------|-----------------|
| IT-approved Dropbox Business deployment | Dropbox installed via SCCM/Intune, appears in software inventory, Business plan domain |
| Employee viewing shared Dropbox link in browser | Proxy shows GET to `www.dropbox.com` but no desktop client running, no sync folder |
| OneDrive sync (approved service) | Different process name (`OneDrive.exe`), different sync folder path, approved domain |
| Browser file download that lands in Downloads | File not in a cloud sync folder, no corresponding upload POST |

**Key Differentiators:**
- Shadow IT: Consumer app in AppData, user-level install, personal account, auto-start enabled, corporate files in sync folder
- Legitimate: Enterprise deployment via IT, managed device policy, business account linked to corporate domain, IT-approved software list

---

## Common Shadow IT Cloud Storage Services

| Service | Client Process | Sync Folder | Data Domain |
|---------|---------------|-------------|-------------|
| **Dropbox** | Dropbox.exe | `\Dropbox\` | d.dropbox.com |
| **Google Drive** | GoogleDriveSync.exe | `\Google Drive\` | drive.google.com |
| **pCloud** | pCloud.exe | `\pCloud\` | p-def6.pcloud.com |
| **Box** | Box.exe | `\Box Sync\` | upload.box.com |
| **iCloud** | iCloudDrive.exe | `\iCloud Drive\` | p-upload.icloud.com |
| **Sync.com** | SyncClient.exe | `\Sync\` | cp.sync.com |
| **MEGA** | MEGAsync.exe | `\MEGA\` | g.api.mega.co.nz |

---

## Process Chain Analysis

### Suspicious Chain (This Scenario)
```
[{hostname}] explorer.exe (user session)
  ├── Dropbox.exe /systemstartup (SHADOW IT — unauthorized sync client)
  │   └── Running in background, monitoring Dropbox sync folder
  │
  └── explorer.exe copies file (USER ACTION — manual file copy)
      └── ACME_Client_NDA_2026.pdf → \Dropbox\Work Documents\
          └── Dropbox.exe detects new file
              └── POST to d.dropbox.com/upload (DATA LEAVES NETWORK)
                  └── Sensitive legal document now on personal cloud account
```
**Why Suspicious:** Unauthorized application, user-level install in AppData, sensitive legal document copied to sync folder, data uploaded to personal cloud account outside IT control

### Legitimate Chain (Approved Cloud Storage)
```
[{hostname}] OneDrive.exe (IT-deployed sync client)
  └── User saves file to \OneDrive - ACME Corporation\Legal\
      └── OneDrive syncs to corporate tenant
          └── DLP policies applied, encryption in transit and at rest
              └── IT has full visibility, audit trail, and revocation capability
```
**Why Legitimate:** IT-deployed application, corporate tenant with DLP, encryption, access controls, full audit trail, revocation capability

---

*Last Updated: February 2026*
*Spectyr Training Platform*
