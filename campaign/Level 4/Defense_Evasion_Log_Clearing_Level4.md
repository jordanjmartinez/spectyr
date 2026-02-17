# Defense Evasion: Clear Windows Event Logs — Level 4

> **Category:** Defense Evasion
> **Subcategory:** Indicator Removal: Clear Windows Event Logs
> **Difficulty:** Level 4 (Multi-Stage Analysis)
> **Events:** 3
> **MITRE ATT&CK:** T1070.001 — Indicator Removal on Host: Clear Windows Event Logs

---

## Scenario Description

A workstation generated two Sysmon process creation events showing the Windows Event Utility (`wevtutil.exe`) being used to clear event logs, followed by a Windows Security event confirming the audit log was cleared. The attacker systematically wiped the Security log and the Sysmon Operational log within seconds of each other. Review the logs and determine if this represents an attacker covering their tracks.

---

## Attack Pattern Reference

| Framework | ID | Name | Link |
|-----------|-----|------|------|
| MITRE ATT&CK | **T1070.001** | Indicator Removal on Host: Clear Windows Event Logs | [attack.mitre.org](https://attack.mitre.org/techniques/T1070/001/) |
| MITRE ATT&CK | **T1070** | Indicator Removal on Host | [attack.mitre.org](https://attack.mitre.org/techniques/T1070/) |
| ATT&CK Tactic | **TA0005** | Defense Evasion | |
| CAPEC | **CAPEC-268** | Audit Log Manipulation | |

> **Note:** T1070.001 is specifically about clearing Windows Event Logs to hide intrusion activity. This is one of the most common post-compromise actions — attackers clear logs after completing their objective to make incident response harder. Real-world usage includes APT28, APT32, APT38, APT41, LockBit ransomware, and numerous other threat actors.

---

## Log Events

### Event 1 of 3 — wevtutil Clears Security Log (Sysmon ProcessCreate)

**Table View:**

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| {timestamp_1} | ProcessCreate | Sysmon | {src_ip} | — | — | Process created: wevtutil.exe by {user_domain}. |

**Key Value Pairs:**

```
timestamp = {timestamp_1}
event_type = ProcessCreate
source_type = Sysmon
host = {hostname}
src_ip = {src_ip}
user = {user_domain}
command_line = wevtutil.exe cl Security
parent_process = C:\Windows\System32\cmd.exe
process = C:\Windows\System32\wevtutil.exe
process_id = 22480
message = Process created: wevtutil.exe by {user_domain}.
```

---

### Event 2 of 3 — Windows Confirms Audit Log Cleared (Windows Security 1102)

**Table View:**

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| {timestamp_2} | 1102 | Windows Security | {src_ip} | — | — | The audit log was cleared. |

**Key Value Pairs:**

```
timestamp = {timestamp_2}
event_type = 1102
source_type = Windows Security
host = {hostname}
src_ip = {src_ip}
subject_user = {username}
subject_domain = ACME
logon_id = 0x7A3B2C
message = The audit log was cleared.
```

---

### Event 3 of 3 — wevtutil Clears Sysmon Log (Sysmon ProcessCreate)

**Table View:**

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| {timestamp_3} | ProcessCreate | Sysmon | {src_ip} | — | — | Process created: wevtutil.exe by {user_domain}. |

**Key Value Pairs:**

```
timestamp = {timestamp_3}
event_type = ProcessCreate
source_type = Sysmon
host = {hostname}
src_ip = {src_ip}
user = {user_domain}
command_line = wevtutil.exe cl Microsoft-Windows-Sysmon/Operational
parent_process = C:\Windows\System32\cmd.exe
process = C:\Windows\System32\wevtutil.exe
process_id = 22544
message = Process created: wevtutil.exe by {user_domain}.
```

---

## Expected Answer

**Classification:** Defense Evasion — Clear Windows Event Logs
**Threat Level:** Critical
**Confidence:** High

---

## Triage Review

### What is it?

**Windows Event Log clearing** is a defense evasion technique where an attacker deliberately wipes event logs to destroy evidence of their activity. Event logs are the primary forensic record on a Windows system — they track logins, process execution, privilege use, and security events. By clearing them, the attacker erases the trail of everything they did before this point.

The irony of this technique is that it's self-defeating in one specific way: **Windows automatically generates Event ID 1102 whenever the Security log is cleared.** The attacker can't prevent this event from being created. So the act of destroying evidence creates new evidence. A SOC analyst who sees Event 1102 knows immediately that someone tampered with the logs.

In this scenario, the attacker used `wevtutil.exe` — a legitimate Windows command-line utility — to clear both the Security log and the Sysmon Operational log in rapid succession. This systematic clearing of multiple log sources indicates an attacker covering their tracks after completing some other objective (lateral movement, credential theft, data exfiltration, etc.).

| Indicator | What It Means | Why It's Suspicious |
|-----------|---------------|---------------------|
| **`wevtutil.exe cl Security`** | Clears the entire Windows Security Event Log | Destroys all authentication, logon, and privilege use records |
| **`wevtutil.exe cl Microsoft-Windows-Sysmon/Operational`** | Clears the Sysmon log | Destroys all process creation, network connection, and file creation records |
| **Event 1102** | Windows confirms the Security log was cleared | This event cannot be suppressed — it's the system's own tamper evidence |
| **`cmd.exe` as parent process** | Both commands launched from command prompt | Interactive attacker session — they're at the keyboard |
| **Regular user context** | `{user_domain}` is not an admin account performing maintenance | Normal users have no business clearing security logs |
| **Rapid succession** | Both logs cleared within seconds | Systematic clearing — not a single accidental action |
| **Multiple log sources targeted** | Security AND Sysmon wiped | Attacker knows which logs to target — they understand the detection environment |

### Understanding the Attack Chain

```
PRIOR (not visible — already cleared):
  Attacker performed malicious activity
  (credential theft, lateral movement, data exfil, etc.)
  Evidence existed in Security and Sysmon logs
       │
       ▼
EVENT 1: Clear Security Log ({timestamp_1})
   │
   ├── wevtutil.exe cl Security
   ├── All Security events destroyed
   ├── Authentication records gone
   └── Privilege use records gone
          │
          EVENT 2: Windows confirms clearing (~1-2s later)
          │
          ├── Event 1102 automatically generated
          ├── Cannot be prevented by the attacker
          └── Records WHO cleared the log and WHEN
               │
               EVENT 3: Clear Sysmon Log (~3-5s later)
               │
               ├── wevtutil.exe cl Microsoft-Windows-Sysmon/Operational
               ├── All Sysmon events destroyed
               ├── Process creation records gone
               └── Network connection records gone
                    │
                    RESULT: Attacker's prior activity is now invisible
                    EXCEPT: These 3 events survived because Sysmon
                    logged Events 1 and 3 before being cleared,
                    and Event 1102 is automatically generated
```

### Why This Attack is Paradoxical

The attacker wants to be invisible, but the act of clearing logs is itself one of the most suspicious things a SOC analyst can see. In a healthy environment, Event 1102 should **never** appear during normal operations. Its mere existence demands investigation.

| What the Attacker Gains | What the Attacker Loses |
|--------------------------|-------------------------|
| All prior malicious activity evidence destroyed | Event 1102 proves tampering occurred |
| Incident response team has fewer forensic artifacts | The clearing itself triggers high-priority alerts |
| Timeline reconstruction becomes much harder | Sysmon caught the wevtutil commands before being cleared |
| May delay detection if logs aren't centrally forwarded | If logs are forwarded to a SIEM, the originals are already preserved |

### What is wevtutil.exe?

`wevtutil.exe` (Windows Event Utility) is a legitimate command-line tool built into every Windows installation. It's used to manage event logs — query them, export them, archive them, and clear them.

| wevtutil Command | What It Does |
|-----------------|-------------|
| `wevtutil el` | Lists all event log names on the system |
| `wevtutil gl Security` | Gets configuration for the Security log |
| `wevtutil qe Security` | Queries events from the Security log |
| `wevtutil epl Security backup.evtx` | Exports Security log to a file |
| `wevtutil cl Security` | **Clears the entire Security log** |
| `wevtutil cl System` | **Clears the System log** |
| `wevtutil cl Application` | **Clears the Application log** |

Administrators occasionally clear logs during maintenance, but this is rare, documented, and performed from an admin account — not from a compromised user workstation via `cmd.exe`.

### What Logs Do Attackers Target?

| Log | Why Attackers Clear It |
|-----|----------------------|
| **Security** | Contains 4624/4625 (logon), 4648 (credential use), 4672 (privilege escalation), 4688 (process creation) — the core forensic evidence |
| **Sysmon Operational** | Contains process creation with command lines, network connections, file creation, DNS queries — the detailed behavioral evidence |
| **System** | Contains service installations, driver loads — evidence of persistence mechanisms |
| **PowerShell Operational** | Contains every PowerShell command executed — evidence of scripted attacks |
| **Application** | Contains application errors and events — sometimes reveals malware crashes or misconfigurations |

In this scenario, the attacker targeted the two most forensically valuable logs: Security and Sysmon. This shows operational awareness — they know exactly which logs a SOC team would use to investigate.

---

## Recommended Triage Steps

### 1. Confirm Log Clearing Occurred
Event 1102 is definitive proof. Verify the `subject_user` and `logon_id` — this tells you exactly which account cleared the log and ties back to their authentication session.

### 2. Check Log Forwarding
If the environment forwards logs to a central SIEM or log server, the original events may still exist there. The attacker only cleared the local copies. Check the SIEM for all events from {hostname} prior to {timestamp_1} — this is your forensic goldmine.

### 3. Identify the Cleared Timeframe
The last event timestamp before the gap (if any events survived) tells you when the attack started. Everything between the last surviving event and Event 1102 was destroyed.

### 4. Investigate the User Account
Why is {user_domain} clearing security logs? If this is a standard user account, it's almost certainly compromised. Check:
- How did this account get admin privileges? (wevtutil cl requires admin)
- When did this account last authenticate? (may still be in SIEM)
- What other systems has this account accessed?

### 5. Look for Related Activity Across Other Sources
The attacker cleared Security and Sysmon, but they may have forgotten other log sources:
- **Firewall logs** — network connections from {src_ip} are still intact
- **Proxy logs** — web traffic from {src_ip} is still intact
- **DNS logs** — query history from {src_ip} is still intact
- **Other host logs** — if the attacker moved laterally, the destination host logs may still exist

### 6. Check for Persistence
Attackers who cover their tracks usually intend to come back. Search for:
- New user accounts created (net user /add)
- Scheduled tasks (schtasks)
- Registry run keys
- New services installed (Event 7045)

### 7. Escalate
Log clearing is a critical severity event. It confirms an active compromise with an attacker sophisticated enough to cover their tracks. Escalate to incident response immediately — assume the worst-case scenario until you can prove otherwise.

---

## Generation Rules

| Variable | Rule |
|----------|------|
| {src_ip} | Same across all 3 events — same host |
| {hostname} | Same across all 3 events — same host |
| {username} | Same across all 3 events — compromised user |
| {user_domain} | ACME\\{username} |
| process_id (Event 1) | 22480 — first wevtutil instance |
| process_id (Event 3) | 22544 — second wevtutil instance (new process) |
| {timestamp_1} → {timestamp_2} | ~1-2 second gap (Windows generates 1102 instantly after clearing) |
| {timestamp_2} → {timestamp_3} | ~3-5 second gap (attacker types the next command) |
| Timestamps | After hours preferred — attacker covers tracks when fewer people are watching |

---

## What the Player Should Recognize

| Indicator | Evidence |
|-----------|----------|
| `wevtutil.exe cl` is a log clearing command | `cl` = clear-log — this destroys event history |
| Security log targeted first | Security holds authentication and access records — highest forensic value |
| Event 1102 confirms tampering | This event auto-generates and cannot be suppressed — it's the smoking gun |
| Sysmon log targeted second | Attacker knows Sysmon exists and is recording their activity — operational awareness |
| Multiple logs cleared in rapid succession | Systematic behavior, not accidental — indicates intentional cover-up |
| cmd.exe parent process | Interactive session — attacker is manually typing commands |
| Regular user context | Standard user clearing security logs = compromised account with escalated privileges |

### The Level 4 Difficulty Factor

| Stage | What the Player Must Recognize | Difficulty |
|-------|-------------------------------|------------|
| **1. Tool Recognition** | `wevtutil.exe` is a legitimate Windows tool — the player must know that `cl Security` means clearing the Security log, not querying it | Medium |
| **2. Event 1102 Significance** | Event 1102 is a rare, high-severity event that should never appear in normal operations — the player must understand its forensic importance | High |
| **3. Multi-Log Targeting** | Clearing both Security AND Sysmon shows the attacker understands the detection environment — this elevates severity from "suspicious" to "confirmed compromise" | High |
| **4. Inferring Prior Activity** | The player must understand that log clearing implies something worse already happened — the cleared logs contained evidence of the real attack | High |

---

## Level Progression Preview

| Level | Events | Complexity |
|-------|--------|------------|
| **Level 1** (Disable Security Tools) | 1 | Single event — security service stopped |
| **Level 4** (Current) | 3 | Log clearing chain — player recognizes systematic evidence destruction |
| **Level 6+** (Future) | 4-5 | Advanced evasion: process injection, timestomping, or disabling ETW at the kernel level |

---

## Related Log Sources

Additional logs that would appear in a real environment during this attack:

| Log Source | Event | What It Shows |
|------------|-------|---------------|
| **Windows Security 4688** | Process Created | Shows wevtutil.exe execution with command-line arguments |
| **Windows Security 4672** | Special Privileges Assigned | Shows the account had admin privileges needed to clear logs |
| **Windows System 104** | Log Cleared | Fires when System or Application log is cleared (separate from 1102) |
| **PowerShell 4104** | Script Block Logging | If attacker used PowerShell Clear-EventLog instead |
| **Sysmon Event 1** | ProcessCreate | The events we see in this scenario — caught wevtutil before Sysmon was cleared |
| **Firewall** | ALLOW/DENY | Network activity from {src_ip} survives — attacker can't clear firewall logs from the host |

---

## Detection Rule Logic

```
# Detect wevtutil clearing any event log
MATCH sysmon_logs WHERE
  event_type = "ProcessCreate"
  AND process LIKE "%wevtutil.exe"
  AND command_line LIKE "%cl %"

# Detect Security log cleared (Event 1102)
MATCH windows_security_logs WHERE
  event_type = "1102"

# Detect PowerShell clearing event logs
MATCH sysmon_logs WHERE
  event_type = "ProcessCreate"
  AND process LIKE "%powershell%"
  AND command_line LIKE "%Clear-EventLog%"

# Detect bulk log clearing (all logs at once)
MATCH sysmon_logs WHERE
  event_type = "ProcessCreate"
  AND process LIKE "%wevtutil.exe"
  AND command_line LIKE "%cl%"
  COUNT >= 2 WITHIN 60 SECONDS

# Detect direct log file deletion
MATCH sysmon_logs WHERE
  event_type = "FileCreate"
  AND target_filename LIKE "C:\Windows\System32\winevt\logs\%.evtx"
```

---

## Common False Positives

| False Positive Scenario | How to Identify |
|-------------------------|-----------------|
| IT admin clearing logs during scheduled maintenance | Documented change ticket, admin account, performed during maintenance window, single log cleared |
| Log rotation policy executing | Automated task (not cmd.exe parent), runs on schedule, exports before clearing |
| System rebuild or reimaging | Part of a documented build process, all logs cleared simultaneously, no prior suspicious activity |
| Test/lab environment reset | Non-production hostname, documented lab procedures |

**Key Differentiators:**
- Legitimate: Admin account, documented change ticket, single log during maintenance window, export before clear
- Malicious: Regular user context, no documentation, multiple logs cleared rapidly, cmd.exe parent, after-hours timing, no prior export

---

## Real-World Threat Actors Using This Technique

| Threat Actor / Malware | Context |
|------------------------|---------|
| **APT28 (Fancy Bear)** | Russian military intelligence — clears logs after espionage operations |
| **APT38 (Lazarus Group)** | North Korean state-sponsored — clears logs after financial theft operations |
| **APT41 (Double Dragon)** | Chinese state-sponsored — clears logs during dual espionage/cybercrime operations |
| **LockBit Ransomware** | Clears Security, System, and Application logs after encryption to hinder recovery |
| **Play Ransomware** | Clears event logs as part of post-encryption cleanup |
| **SynAck Ransomware** | Uses wevtutil to clear logs before and after encryption |

---

## Other Log Clearing Methods Attackers Use

| Method | Command | Detection |
|--------|---------|-----------|
| **wevtutil** (this scenario) | `wevtutil cl Security` | Sysmon ProcessCreate + Event 1102 |
| **PowerShell** | `Clear-EventLog -LogName Security` | PowerShell 4104 Script Block + Event 1102 |
| **PowerShell Remove** | `Remove-EventLog -LogName Security` | Deletes the log entirely (requires reboot to take effect) |
| **Event Viewer GUI** | Right-click → Clear Log | Event 1102 still fires |
| **Meterpreter** | `clearev` | Clears Application, System, and Security simultaneously |
| **Direct file deletion** | `del C:\Windows\System32\winevt\logs\Security.evtx` | Sysmon FileDelete + file may be locked by service |
| **Disable logging** | `auditpol /clear /y` | Stops future events without clearing existing ones |

---

## Process Chain Analysis

### Suspicious Chain (This Scenario)
```
[{hostname}] cmd.exe (attacker interactive session)
  ├── wevtutil.exe cl Security (CLEAR SECURITY LOG)
  │   └── Windows generates Event 1102 (tamper evidence)
  │       └── All authentication, logon, and privilege records destroyed
  │
  └── wevtutil.exe cl Microsoft-Windows-Sysmon/Operational (CLEAR SYSMON LOG)
      └── All process creation, network, and file creation records destroyed
          └── Attacker's prior activity is now invisible
              EXCEPT: These 3 events survived the clearing
```
**Why Suspicious:** Two critical logs cleared within seconds, cmd.exe parent, regular user context, no documentation or change ticket, no export before clearing

### Legitimate Chain (Admin Maintenance)
```
[ACME-SVR01] powershell.exe (admin maintenance script)
  └── wevtutil.exe epl Security C:\LogArchive\Security_20260215.evtx (EXPORT FIRST)
      └── wevtutil.exe cl Security (CLEAR AFTER EXPORT)
          └── Single log cleared during documented maintenance window
```
**Why Legitimate:** Export before clear, admin account, scheduled maintenance window, documented change ticket, single log (not systematic clearing of multiple sources)

---

*Last Updated: February 2026*
*Spectyr Training Platform*
