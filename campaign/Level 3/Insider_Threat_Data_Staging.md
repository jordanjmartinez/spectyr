# Insider Threat - Level 3 Scenario

> **Category:** Insider Threat  
> **Subcategory:** Data from Information Repositories / Local Data Staging  
> **Difficulty:** Level 3 (Context Analysis)  
> **Events:** 2

---

## Scenario Description

A file server logged a network logon from an employee workstation accessing a restricted financial share, followed by a file creation event on the employee's local machine showing sensitive documents being copied to a staging folder. Review the Windows Security and Sysmon logs and determine if these events represent an insider threat.

---

## Attack Pattern Reference

| Framework | ID | Name | Link |
|-----------|-----|------|------|
| MITRE ATT&CK | **T1213** | Data from Information Repositories | [attack.mitre.org](https://attack.mitre.org/techniques/T1213/) |
| MITRE ATT&CK | **T1074.001** | Data Staged: Local Data Staging | [attack.mitre.org](https://attack.mitre.org/techniques/T1074/001/) |
| ATT&CK Tactic | **TA0009** | Collection | |
| CAPEC | **CAPEC-118** | Collect and Analyze Information | [capec.mitre.org](https://capec.mitre.org/data/definitions/118.html) |

---

## Log Events

### Event 1 of 2 — Network Logon to Restricted Financial Share

#### Table View

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| 18:47:22 | 4624 | Windows Security | 10.0.1.45 | 10.0.1.10 | | `An account was successfully logged on. Subject: Security ID: S-1-0-0 Account Name: - Account Domain: - Logon ID: 0x0 Logon Type: 3 New Logon: Security ID: S-1-5-21-xxx-1001 Account Name: jsmith Account Domain: CORP Logon ID: 0x9C4D82 Logon Process: NtLmSsp Authentication Package: NTLM Network Information: Workstation Name: WS-PC045 Source Network Address: 10.0.1.45 Source Port: 50892 Share Name: \\FS01\Finance_Confidential Share Path: \??\D:\Shares\Finance_Confidential` |

#### Expanded Key Value Pairs

```
event_id = 4624
event_type = Successful Logon
logon_type = 3
logon_type_name = Network
target_user = jsmith
target_domain = CORP
logon_id = 0x9C4D82
auth_package = NTLM
logon_process = NtLmSsp
src_ip = 10.0.1.45
src_port = 50892
workstation = WS-PC045
target_server = FS01
share_name = \\FS01\Finance_Confidential
share_path = \??\D:\Shares\Finance_Confidential
status = Success
host = FS01
```

---

### Event 2 of 2 — Sensitive File Copied to Local Staging Folder

#### Table View

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| 18:48:05 | FileCreate | Sysmon | 10.0.1.45 | | | `File created: UtcTime=2026-01-27 18:48:05.217 ProcessGuid={A23EAE89-BD56-5903-0000-0010GHD95E33} ProcessId=4412 Image=C:\Windows\explorer.exe TargetFilename=C:\Users\jsmith\Desktop\Project_Archive\2026_Salary_Compensation_AllStaff.xlsx CreationUtcTime=2026-01-27 18:48:05.217` |

#### Expanded Key Value Pairs

```
event_id = 11
event_type = FileCreate
utc_time = 2026-01-27 18:48:05.217
process_guid = {A23EAE89-BD56-5903-0000-0010GHD95E33}
process_id = 4412
image = C:\Windows\explorer.exe
target_filename = C:\Users\jsmith\Desktop\Project_Archive\2026_Salary_Compensation_AllStaff.xlsx
creation_utc_time = 2026-01-27 18:48:05.217
user = CORP\jsmith
host = WS-PC045
```

---

## Expected Answer

**Classification:** Malicious - Insider Threat (Data Collection / Staging)

**Threat Category:** Unauthorized Data Access / Local Data Staging

---

## Triage Review

### What is it?

**Insider Threat** is when a trusted employee, contractor, or partner misuses their legitimate access to harm the organization. Unlike external attacks where the indicators are technical (malware, exploits, C2), insider threat indicators are **behavioral** — the actions themselves are normal, but the context makes them suspicious.

In this scenario, an employee accessed a restricted financial share containing sensitive compensation data and copied files to a local staging folder on their desktop. This is a data collection and staging activity that typically precedes exfiltration.

This is difficult to detect because:
- The employee has legitimate network credentials
- The network logon to a file share is a normal daily activity
- File copy operations happen constantly
- No malware, exploits, or external attacker infrastructure is involved

| Indicator | What It Means | Why It's Suspicious |
|-----------|---------------|---------------------|
| **Share: `\\FS01\Finance_Confidential`** | Restricted financial data share | jsmith is not in the Finance department — no business need |
| **File: `2026_Salary_Compensation_AllStaff.xlsx`** | Company-wide salary and compensation data | Highly sensitive — access should be limited to HR and Finance leadership |
| **Staging path: `Desktop\Project_Archive\`** | Local folder on employee's workstation | Innocuous folder name chosen to avoid suspicion — not a standard project folder |
| **Time: 18:47 (6:47 PM)** | After typical business hours | Most employees have left — reduced chance of being observed |
| **NTLM authentication** | Legacy authentication protocol | May indicate direct `\\server\share` mapping rather than normal mapped drive (Kerberos) |
| **Process: `explorer.exe`** | Windows File Explorer | Manual drag-and-drop or copy-paste — user-initiated, deliberate action |

### Why This Is Hard to Detect

The core challenge of insider threat detection is distinguishing **authorized access** from **unauthorized intent**:

| Normal Employee Behavior | This Scenario |
|-------------------------|---------------|
| Accesses file shares relevant to their role | Accesses a share outside their department (Finance_Confidential) |
| Copies files to work on locally during the day | Copies sensitive HR/compensation data to a generically named folder |
| Works during business hours | Active at 18:47 — after most staff have left |
| Opens files from their normal mapped drives | Manually navigates to a restricted share using direct path |
| Files are related to their job function | File contains all-staff salary data — no legitimate need for this role |

### Understanding the Staging Behavior

```
STEP 1: jsmith accesses Finance_Confidential share on FS01
   │
   ├── Authenticates via NTLM (direct \\FS01\Finance_Confidential path)
   ├── Browses the share contents → Event 1 (4624 Type 3)
   │
   └── STEP 2: Copies sensitive file to local workstation
       │
       ├── Creates staging folder: C:\Users\jsmith\Desktop\Project_Archive\
       └── Copies 2026_Salary_Compensation_AllStaff.xlsx → Event 2 (Sysmon FileCreate)
            │
            └── NEXT (not seen in these events): Exfiltration via USB, email, cloud upload, etc.
```

### Insider Threat Motivation Categories (Reference)

| Motivation | Description | Behavioral Indicators |
|-----------|-------------|----------------------|
| **Financial gain** | Selling data to competitors or on dark web | Accessing financial/IP data outside role, after hours activity |
| **Disgruntlement** | Retaliating against employer after conflict | Sudden access to sensitive data after negative review, PIP, or termination notice |
| **Pre-departure theft** | Taking data before leaving for competitor | Bulk file access in weeks before resignation, staging to personal devices |
| **Espionage** | Acting on behalf of external entity | Targeted access to specific IP, unusual working hours, encrypted communications |
| **Negligence** | Unintentional data exposure | Copying sensitive files to unapproved locations, emailing to personal accounts |

### Common Insider Threat Indicators (Reference)

| Indicator Category | Examples | Detection Priority |
|-------------------|----------|-------------------|
| **Access anomaly** | Accessing shares/systems outside normal role | **High** (this scenario) |
| **Volume anomaly** | Downloading/copying unusually large amounts of data | **High** |
| **Time anomaly** | Activity during off-hours, weekends, holidays | **Medium** (this scenario) |
| **Staging behavior** | Copying files to USB-accessible paths, desktop, temp folders | **High** (this scenario) |
| **Sensitive data access** | HR records, financial data, source code, client lists | **Critical** (this scenario) |
| **Resignation correlation** | Data access spikes in weeks before departure | **Critical** |
| **Circumvention** | Disabling DLP, using personal cloud storage, encrypting files | **Critical** |

### Attack Context

Insider threats account for a significant portion of data breaches and are among the most costly to remediate. Unlike external attacks, insiders already have:

- **Legitimate credentials** — no need to brute force or phish
- **Knowledge of data locations** — they know where the valuable files are
- **Understanding of security controls** — they know what's monitored and what isn't
- **Trusted access** — their activity blends with normal business operations

Data staging (T1074.001) is a key preparatory step before exfiltration. Insiders collect files from network shares into a local folder before transferring them out via USB drives, personal email, cloud storage, or physical media. The staging folder is often given an innocuous name to avoid casual detection.

### Real-World Examples

| Incident | What Happened |
|----------|---------------|
| **Tesla (2023)** | Two former employees copied confidential data including salary information for 75,000+ employees to personal devices before departing |
| **Capital One (2019)** | Insider with AWS access exploited misconfigured firewall to access 100M+ customer records and credit applications |
| **Twitter/X (2022)** | Employee accessed internal tools to sell user data including email addresses and phone numbers |
| **Coca-Cola (2018)** | Departing employee stole trade secrets on a personal hard drive worth an estimated $119 million |
| **SunTrust Banks (2018)** | Former employee stole 1.5 million customer records including names, addresses, and account balances |
| **Waymo vs. Uber (2017)** | Engineer downloaded 14,000 confidential files including self-driving car trade secrets before joining competitor |

### MITRE ATT&CK Context

**Technique T1213 - Data from Information Repositories / T1074.001 - Data Staged: Local Data Staging**

> "Adversaries may leverage information repositories to mine valuable information. Information repositories are tools that allow for storage of information, typically to facilitate collaboration or information sharing between users, and can store a wide variety of data that may aid adversaries in further objectives, or direct access to the target information."

**Detection Focus:**
- Monitor file share access patterns — alert when users access shares outside their normal baseline
- Track bulk file copy operations from network shares to local workstations
- Alert on access to designated sensitive shares by users not in authorized groups
- Correlate file access with HR events (resignation, termination, performance issues)
- Monitor for staging folder creation patterns (generic names on Desktop, Downloads, Temp)

---

## Recommended Response Actions

### Immediate Actions
1. **Do not alert the employee** — insider threat investigations require discretion to avoid evidence destruction
2. **Preserve evidence** — snapshot jsmith's workstation file system and capture the `Project_Archive` folder contents
3. **Engage HR and Legal** — insider threat response requires coordination across security, HR, and legal teams

### Investigation Steps
4. **Establish access baseline** — review jsmith's historical file access patterns to determine if Finance_Confidential access is anomalous
5. **Check authorization** — verify whether jsmith has a legitimate business reason to access this share (project assignment, temporary role, etc.)
6. **Determine scope** — search for additional file copy events from the same share or other restricted shares to this workstation
7. **Review HR context** — check for recent performance issues, resignation notice, disciplinary actions, or job applications at competitors
8. **Monitor for exfiltration** — watch for USB device connections, personal email sends, cloud storage uploads, or large outbound transfers from WS-PC045

### Remediation
9. **Revoke access** — remove jsmith's permissions to Finance_Confidential and other sensitive shares pending investigation
10. **Recover data** — secure or delete the staged copies on the workstation
11. **Assess exposure** — determine if the data has already been exfiltrated and estimate the impact

### Post-Incident
12. **Document findings** — create incident report for HR, Legal, and executive leadership
13. **Review access controls** — audit share permissions to ensure least-privilege is enforced
14. **Implement UEBA** — consider User and Entity Behavior Analytics to establish access baselines and detect anomalies automatically

---

## Log Authenticity Notes

### Event 1 — Windows Security 4624

| Field | Value | Why It's Realistic |
|-------|-------|-------------------|
| `Logon Type=3` | Network logon — standard for file share access via SMB |
| `AuthPackage=NTLM` | Direct `\\server\share` access often uses NTLM rather than Kerberos mapped drives |
| `Share Name=\\FS01\Finance_Confidential` | Named share — realistic corporate share structure |
| `Share Path=\??\D:\Shares\Finance_Confidential` | Local disk path on file server — standard Windows share configuration |
| `Source=10.0.1.45 (WS-PC045)` | Employee's assigned workstation — not a shared or unknown device |
| `User=CORP\jsmith` | Legitimate domain account — insider uses their own credentials |

### Event 2 — Sysmon FileCreate

| Field | Value | Why It's Realistic |
|-------|-------|-------------------|
| `Image=explorer.exe` | Windows File Explorer — manual copy operation (drag-and-drop or Ctrl+C/V) |
| `TargetFilename=...\Project_Archive\2026_Salary_Compensation_AllStaff.xlsx` | Sensitive file saved to innocuously named local folder |
| `Desktop\Project_Archive\` | Staging folder on Desktop — accessible and easy to transfer to USB or upload |
| `User=CORP\jsmith` | Same user as the share access — consistent identity across both events |
| `Host=WS-PC045` | File created locally — data has been moved from server to workstation |

### Legitimate vs Malicious Comparison

| Legitimate File Share Access | Insider Threat (This Scenario) |
|-----------------------------|-------------------------------|
| User accesses shares relevant to their department | User accesses Finance_Confidential (not their department) |
| Files relate to active work projects | File is all-staff salary data — no standard business need |
| During business hours | After hours (18:47) — reduced observation |
| Files opened in place or saved to department folder | Files copied to generically named local staging folder |
| Normal mapped drive access (Kerberos auth) | Direct UNC path access (NTLM auth) |
| Consistent access pattern over weeks/months | New or unusual access to this share |

---

## Cross-Log Correlation Guide

### How the Two Events Connect

```
Timeline across FS01 and WS-PC045:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
18:47:22  ─── Windows Security 4624 ─── jsmith authenticates to \\FS01\Finance_Confidential
    │
    │  ~43 seconds (user browses share, locates target file, initiates copy)
    │
18:48:05  ─── Sysmon FileCreate ─── Salary file appears in Desktop\Project_Archive\ on WS-PC045
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Correlation Anchors

| Anchor Point | Event 1 (Windows Security) | Event 2 (Sysmon) |
|-------------|---------------------------|-------------------|
| **User** | `target_user=jsmith` | `user=CORP\jsmith` |
| **Source Workstation** | `src_ip=10.0.1.45 (WS-PC045)` | `host=WS-PC045` |
| **Data Source** | `share_name=\\FS01\Finance_Confidential` | Filename: `2026_Salary_Compensation_AllStaff.xlsx` (financial data) |
| **Time Proximity** | `18:47:22` | `18:48:05` (43 sec later) |
| **Process Context** | Network logon (SMB file access) | `explorer.exe` (manual file copy) |

### Why Neither Event Alone Is Conclusive

| Event Alone | Why It's Ambiguous |
|-------------|-------------------|
| **4624 Type 3 only** | Network logons to file shares happen hundreds of times per day. jsmith accessing FS01 is a routine event — the share name is the key detail, and it's buried in the log |
| **Sysmon FileCreate only** | Users create files on their desktops constantly — downloads, document saves, screenshots. An xlsx file appearing on the desktop is unremarkable without context |
| **Together** | Authentication to a restricted financial share + sensitive salary file appearing on a local staging folder 43 seconds later = data collection by someone accessing files outside their role |

### The Level 3 Difficulty Factor

Unlike Level 2 scenarios where at least one event had a clear technical red flag (PSEXESVC.exe, C2 domain, external RDP), **neither event in this scenario contains an obvious malicious indicator**. The suspicion comes entirely from context:

| Context Factor | What the Player Must Recognize |
|---------------|-------------------------------|
| **Role mismatch** | jsmith is not in Finance — why are they on this share? |
| **Data sensitivity** | Salary/compensation data is among the most sensitive in any organization |
| **Timing** | 18:47 is after hours — fewer witnesses, lower monitoring |
| **Staging pattern** | Files copied to a local folder with a bland name — preparation for removal |
| **Authentication method** | NTLM via direct path suggests intentional navigation, not a normal mapped drive |

---

## Level Progression Preview

| Level | Events | Complexity |
|-------|--------|------------|
| **Level 1** | 1 | Single event — User accesses a share flagged as restricted |
| **Level 2** | 2 | Two events — Unusual share access + bulk download indicator |
| **Level 3** (Current) | 2 | Two events — No technical red flags; context-only detection (role mismatch, data sensitivity, timing, staging) |

---

## Related Log Sources

For more advanced scenarios, insider threats can be detected across multiple sources:

| Log Source | Event Type | What It Shows |
|------------|------------|---------------|
| **Windows Security 4624** | Network Logon (Type 3) | Share access authentication (this scenario) |
| **Sysmon Event 11** | FileCreate | File copy to local staging folder (this scenario) |
| **Windows Security 4663** | Object Access | Specific file read/write operations on audited shares |
| **Windows Security 5140** | Network Share Access | Share-level access events (which share was connected) |
| **Windows Security 5145** | Detailed Share Access | File-level access within a share (each file opened/read/written) |
| **Sysmon Event 3** | NetworkConnection | SMB connection to file server |
| **Proxy** | HTTP_POST / CONNECT | Potential exfiltration to cloud storage or personal email |
| **Sysmon Event 11** | FileCreate (Removable) | USB device file writes — exfiltration to physical media |

---

## Detection Rule Logic (Reference)

```
# Windows Security: Sensitive share access by non-authorized users
MATCH windows_security_logs WHERE
  event_id = 4624
  AND logon_type = 3
  AND share_name IN ("\\FS01\Finance_Confidential", "\\FS01\HR_Records", 
                      "\\FS01\Executive_Data", "\\FS01\Legal_Privileged")
  AND target_user NOT IN finance_authorized_users
  AND target_user NOT IN hr_authorized_users

# Sysmon: Sensitive file staging detection
MATCH sysmon_logs WHERE
  event_type = "FileCreate"
  AND image = "explorer.exe"
  AND (
    target_filename MATCHES "*Salary*" OR
    target_filename MATCHES "*Compensation*" OR
    target_filename MATCHES "*Confidential*" OR
    target_filename MATCHES "*AllStaff*" OR
    target_filename MATCHES "*SSN*" OR
    target_filename MATCHES "*Client_List*"
  )
  AND target_filename MATCHES "*Desktop*" OR target_filename MATCHES "*Downloads*"

# Correlation: Insider data staging
MATCH windows_security_logs AS access
  JOIN sysmon_logs AS staging
  ON access.target_user = staging.user
  AND access.src_ip = staging.host_ip
  AND staging.utc_time BETWEEN access.event_time AND access.event_time + 300s
WHERE
  access.event_id = 4624
  AND access.logon_type = 3
  AND access.share_name IN sensitive_shares
  AND access.target_user NOT IN authorized_users_for_share
  AND staging.event_type = "FileCreate"
  AND staging.image = "explorer.exe"
```

---

## Common False Positives

Understanding legitimate scenarios is especially important for insider threat — over-reporting destroys trust:

| False Positive Scenario | How to Identify |
|-------------------------|-----------------|
| Employee temporarily assigned to cross-department project | HR confirms project assignment, manager approval documented |
| Finance team member using a non-standard workstation | User is in Finance group, accessing from a loaner/shared machine |
| IT admin auditing share permissions | User in IT security group, documented audit task |
| Employee preparing for an approved presentation | Manager confirms the data was requested for leadership meeting |
| Automated backup or sync process | Process is a known backup agent, not explorer.exe |

**Key Differentiators:**
- Legitimate: Business justification exists, access is within role or approved, normal hours, files opened in place
- Suspicious: No business need, outside department, after hours, files copied to local staging folder, sensitive data types

**Critical Note:** Insider threat investigations have significant HR and legal implications. False accusations can damage careers and expose the organization to liability. Always **verify context with HR and management** before escalating.

---

## Process Chain Analysis

Understanding user behavior helps distinguish normal access from data staging:

### Suspicious Chain (This Scenario)
```
[WS-PC045] explorer.exe (jsmith — user shell)
  ├── SMB connection to \\FS01\Finance_Confidential (direct UNC path)
  │   └── Authenticates via NTLM (not mapped drive)
  ├── Browses share contents (43 seconds)
  └── Copies: 2026_Salary_Compensation_AllStaff.xlsx
      └── Destination: C:\Users\jsmith\Desktop\Project_Archive\
```
**Why Suspicious:** User outside Finance, accessing salary data, copying to local staging folder, after hours, direct path access

### Legitimate Chain (Finance Employee)
```
[WS-PC082] explorer.exe (mgarcia — Finance Analyst)
  ├── Opens mapped drive F:\ (\\FS01\Finance_Confidential via Kerberos GPO)
  ├── Opens: 2026_Budget_Q1_Draft.xlsx in Excel (read in place)
  └── Saves edits back to F:\2026_Budget_Q1_Draft.xlsx
```
**Why Legitimate:** Finance department employee, using normal mapped drive (Kerberos), opening file in place for editing, not copying to local machine, during business hours

---

## Insider Threat Investigation Framework

Unlike external attacks, insider threat investigations require a different approach:

| Phase | External Attack Response | Insider Threat Response |
|-------|------------------------|------------------------|
| **Detection** | Technical alerts (malware, C2, exploits) | Behavioral anomalies (access patterns, timing, volume) |
| **Notification** | SOC → IR team → management | SOC → HR → Legal → management (controlled disclosure) |
| **Investigation** | Forensics on compromised systems | Forensics + HR context + employee history review |
| **Containment** | Isolate hosts, block IPs | Discretely revoke access — do not tip off employee |
| **Interviews** | N/A (external attacker) | Coordinated with HR and Legal before any employee contact |
| **Resolution** | Remediate and patch | May involve termination, legal action, or law enforcement |
| **Documentation** | IR report | IR report + HR file + potential legal proceedings |

---

*Last Updated: January 2026*  
*Spectyr Training Platform*
