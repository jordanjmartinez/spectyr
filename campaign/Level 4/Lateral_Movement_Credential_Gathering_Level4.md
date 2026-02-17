# Lateral Movement: Credential Gathering (LSASS Memory Dump) — Level 4

> **Category:** Lateral Movement
> **Subcategory:** OS Credential Dumping: LSASS Memory
> **Difficulty:** Level 4 (Multi-Stage Analysis)
> **Events:** 3
> **MITRE ATT&CK:** T1003.001 — OS Credential Dumping: LSASS Memory

---

## Scenario Description

A workstation generated a Sysmon process creation event showing a known diagnostic tool targeting the LSASS process. Shortly after, a large `.dmp` file was written to a temporary directory. Minutes later, a second process launched from the same directory — a credential extraction tool that loaded the dump file. Review the three Sysmon events and determine if this represents credential theft activity.

---

## Attack Pattern Reference

| Field | Value |
|-------|-------|
| **Attack Category** | Lateral Movement — Credential Gathering |
| **MITRE ATT&CK Technique** | T1003.001 — OS Credential Dumping: LSASS Memory |
| **MITRE ATT&CK Tactic** | TA0006 — Credential Access |
| **CAPEC** | CAPEC-560 — Use of Known Domain Credentials |
| **Kill Chain Phase** | Credential Access → enables Lateral Movement |
| **Severity** | Critical |
| **Log Sources Used** | Sysmon (ProcessCreate, FileCreate, ProcessCreate) |

---

## Log Events

### Event 1 of 3 — Sysmon ProcessCreate (LSASS Dump Tool)

**Table View:**

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| {timestamp_1} | ProcessCreate | Sysmon | {src_ip} | | | `Process Create: UtcTime={timestamp_1} ProcessId=19840 Image=C:\Users\{username}\Downloads\procdump64.exe CommandLine="C:\Users\{username}\Downloads\procdump64.exe" -ma lsass.exe C:\Users\{username}\AppData\Local\Temp\debug_report.dmp User={user_domain} ParentImage=C:\Windows\System32\cmd.exe` |

**Key Value Pairs:**

```
timestamp = {timestamp_1}
event_type = ProcessCreate
source_type = Sysmon
host = {hostname}
src_ip = {src_ip}
image = C:\Users\{username}\Downloads\procdump64.exe
commandline = "C:\Users\{username}\Downloads\procdump64.exe" -ma lsass.exe C:\Users\{username}\AppData\Local\Temp\debug_report.dmp
user = {user_domain}
parent_image = C:\Windows\System32\cmd.exe
process_id = 19840
message = Process created: procdump64.exe by {user_domain}.
```

---

### Event 2 of 3 — Sysmon FileCreate (Dump File Written)

**Table View:**

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| {timestamp_2} | FileCreate | Sysmon | {src_ip} | | | `File created: UtcTime={timestamp_2} ProcessId=19840 Image=C:\Users\{username}\Downloads\procdump64.exe TargetFilename=C:\Users\{username}\AppData\Local\Temp\debug_report.dmp User={user_domain}` |

**Key Value Pairs:**

```
timestamp = {timestamp_2}
event_type = FileCreate
source_type = Sysmon
host = {hostname}
src_ip = {src_ip}
image = C:\Users\{username}\Downloads\procdump64.exe
target_filename = C:\Users\{username}\AppData\Local\Temp\debug_report.dmp
user = {user_domain}
process_id = 19840
message = File created: debug_report.dmp by {user_domain}.
```

---

### Event 3 of 3 — Sysmon ProcessCreate (Credential Extraction Tool)

**Table View:**

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| {timestamp_3} | ProcessCreate | Sysmon | {src_ip} | | | `Process Create: UtcTime={timestamp_3} ProcessId=21056 Image=C:\Users\{username}\AppData\Local\Temp\mimikatz.exe CommandLine="C:\Users\{username}\AppData\Local\Temp\mimikatz.exe" "sekurlsa::minidump C:\Users\{username}\AppData\Local\Temp\debug_report.dmp" "sekurlsa::logonPasswords" "exit" User={user_domain} ParentImage=C:\Windows\System32\cmd.exe` |

**Key Value Pairs:**

```
timestamp = {timestamp_3}
event_type = ProcessCreate
source_type = Sysmon
host = {hostname}
src_ip = {src_ip}
image = C:\Users\{username}\AppData\Local\Temp\mimikatz.exe
commandline = "C:\Users\{username}\AppData\Local\Temp\mimikatz.exe" "sekurlsa::minidump C:\Users\{username}\AppData\Local\Temp\debug_report.dmp" "sekurlsa::logonPasswords" "exit"
user = {user_domain}
parent_image = C:\Windows\System32\cmd.exe
process_id = 21056
message = Process created: mimikatz.exe by {user_domain}.
```

---

## Expected Answer

**Classification:** Lateral Movement — Credential Gathering
**Threat Level:** Critical
**Confidence:** High

---

## Triage Review

### What is it?

**LSASS (Local Security Authority Subsystem Service)** is the Windows process responsible for authenticating users. It runs as `lsass.exe` under SYSTEM and holds credentials in memory — password hashes, Kerberos tickets, and sometimes plaintext passwords — for every user currently logged into that machine.

Attackers target LSASS because dumping its memory gives them credentials they can use to move laterally across the network. If an IT admin logged in remotely last week, their domain admin credentials might still be cached in LSASS. One successful dump on one workstation can compromise the entire domain.

In this scenario, the attacker used ProcDump (a legitimate Microsoft Sysinternals tool) to dump LSASS memory to a file, then ran Mimikatz to extract credentials from that dump.

| Indicator | What It Means | Why It's Suspicious |
|-----------|---------------|---------------------|
| **`procdump64.exe` in Downloads** | Tool was downloaded, not installed by IT | Legitimate ProcDump lives in admin tool directories, not user Downloads |
| **`-ma lsass.exe` in command line** | Full memory dump targeting LSASS specifically | The `-ma` flag means "dump everything" — targeting lsass.exe is the critical red flag |
| **`debug_report.dmp` filename** | Attacker named the dump file to look benign | Real debug reports are generated by Windows Error Reporting, not ProcDump |
| **`.dmp` file in Temp directory** | Credential dump artifact on disk | A 50-150 MB .dmp file from LSASS contains all cached credentials |
| **`mimikatz.exe` in Temp** | Known credential theft tool | Mimikatz is the most widely used credential extraction tool in real breaches |
| **`sekurlsa::minidump` command** | Mimikatz loading the LSASS dump file | This command tells Mimikatz to read credentials from a dump file instead of live memory |
| **`sekurlsa::logonPasswords`** | Extracting all cached passwords | This command outputs every credential LSASS had stored — hashes, tickets, plaintext |
| **`cmd.exe` as parent for both** | Both tools launched from command prompt | Indicates an interactive attacker session, not automated malware |
| **Same user context** | Regular user account, not SYSTEM | Attacker is operating under a compromised standard user account |

### Understanding the Attack Chain

```
PRIOR (not visible in these logs):
  Attacker compromises workstation (phishing, malware, etc.)
  Opens cmd.exe session
       │
       ▼
EVENT 1: ProcDump targets LSASS ({timestamp_1})
   │
   ├── procdump64.exe runs from Downloads folder
   ├── -ma flag = full memory dump
   ├── Target = lsass.exe (the credential store)
   └── Output = debug_report.dmp in Temp
          │
          EVENT 2: Dump file written (~5-10s later)
          │
          ├── procdump64.exe creates the .dmp file
          ├── Same process_id (19840) ties to Event 1
          └── File contains all LSASS memory = all credentials
               │
               EVENT 3: Mimikatz extracts credentials (~2-5 min later)
               │
               ├── mimikatz.exe runs from Temp directory
               ├── sekurlsa::minidump loads the dump file
               ├── sekurlsa::logonPasswords extracts everything
               └── Attacker now has credentials for lateral movement
```

### Why ProcDump is Dangerous

ProcDump is a legitimate Microsoft Sysinternals diagnostic tool. IT administrators use it to capture crash dumps for debugging. It's digitally signed by Microsoft and often whitelisted by security tools.

| | Legitimate ProcDump Use | This Scenario |
|---|---|---|
| **Location** | `C:\Sysinternals\` or `C:\Tools\` | `C:\Users\{username}\Downloads\` |
| **Target** | Crashing application (e.g., `-e outlook.exe`) | `lsass.exe` — the credential store |
| **Flags** | `-e` (exception), `-h` (hung), `-t` (terminate) | `-ma` (full memory dump) |
| **Context** | IT admin troubleshooting, change ticket exists | No documentation, user account context |
| **Output** | Named after the crashing app | Named `debug_report.dmp` to blend in |

The `-ma lsass.exe` combination is the key indicator. No legitimate troubleshooting scenario requires a full memory dump of LSASS from a user workstation.

### What is Mimikatz?

Mimikatz is an open-source tool created by Benjamin Delpy that extracts credentials from Windows memory. It's used in the majority of real-world Active Directory compromises.

| Mimikatz Command | What It Does |
|-----------------|-------------|
| `sekurlsa::logonPasswords` | Dumps all cached credentials (NTLM hashes, Kerberos tickets, plaintext) |
| `sekurlsa::minidump <file>` | Loads a memory dump file instead of reading live LSASS |
| `kerberos::golden` | Creates Golden Ticket for persistent domain access |
| `lsadump::sam` | Dumps local SAM database |
| `lsadump::dcsync` | Simulates domain controller replication to steal credentials |

In this scenario, the attacker uses `sekurlsa::minidump` to load the dump file, then `sekurlsa::logonPasswords` to extract everything. The `exit` at the end closes Mimikatz automatically — the attacker scripted the whole operation to minimize time on disk.

### What Credentials Are in LSASS?

| Credential Type | Description | What Attacker Gets |
|----------------|-------------|-------------------|
| **NTLM Hashes** | Password hashes for every logged-in user | Can be used in pass-the-hash attacks without knowing the actual password |
| **Kerberos TGTs** | Ticket-Granting Tickets for domain authentication | Can be used to impersonate users and access any domain resource |
| **Kerberos Service Tickets** | Tickets for specific services | Can be used to access file shares, databases, etc. |
| **WDigest Plaintext** | Plaintext passwords (if WDigest enabled) | Direct password access — worst case scenario |
| **Cached Domain Credentials** | Hashes for recently authenticated domain users | Access to accounts that logged in days or weeks ago |

---

## Recommended Triage Steps

### 1. Confirm the Tool and Target
Verify that `procdump64.exe` was targeting `lsass.exe` in the command line. The `-ma` flag combined with `lsass.exe` as the target is the definitive indicator — no legitimate use case exists for this combination on a user workstation.

### 2. Verify Tool Origin
Check where `procdump64.exe` came from. In the Downloads folder means it was recently downloaded — check proxy logs for the download source. Legitimate ProcDump deployments are pushed by IT through SCCM or stored in admin tool shares.

### 3. Confirm Mimikatz Execution
The presence of `mimikatz.exe` with `sekurlsa::` commands confirms this is a credential theft operation, not a false positive. Mimikatz has no legitimate use in a production environment.

### 4. Identify Compromised Credentials
Determine which users were logged into {hostname} at the time of the dump. Every cached credential in LSASS is now compromised — this includes the current user, any admin who recently logged in, and any service accounts with cached sessions.

### 5. Check for Lateral Movement
After credential extraction, the attacker will likely use stolen credentials to access other systems. Search for:
- Windows Security 4624 (Type 3 Network logon) from {src_ip} using different accounts
- Windows Security 4648 (Explicit Credential logon) showing credential switching
- Firewall logs showing new SMB (445) or RDP (3389) connections from {src_ip}

### 6. Isolate and Reset
- Immediately isolate {hostname} from the network
- Force password reset for ALL accounts that had cached credentials on the machine
- Revoke all Kerberos tickets (krbtgt double-reset if domain admin was compromised)
- Scan other systems for ProcDump/Mimikatz artifacts

### 7. Escalate
LSASS credential dumping is never a Tier 1 close. This is an active compromise with potential domain-wide impact. Escalate to incident response immediately — the attacker likely already has credentials and may be moving laterally.

---

## Generation Rules

| Variable | Rule |
|----------|------|
| {src_ip} | Same across all 3 events — same host |
| {hostname} | Same across all 3 events — same host |
| {username} | Same across all 3 events — compromised user |
| {user_domain} | ACME\\{username} |
| process_id (Event 1-2) | 19840 — ProcDump process creates the dump |
| process_id (Event 3) | 21056 — Mimikatz is a separate process |
| {timestamp_1} → {timestamp_2} | ~5-10 second gap (dump writes quickly) |
| {timestamp_2} → {timestamp_3} | ~2-5 minute gap (attacker transfers Mimikatz, then runs it) |
| Timestamps | Business hours — attacker operates when users are logged in to maximize cached credentials |

---

## What the Player Should Recognize

| Indicator | Evidence |
|-----------|----------|
| ProcDump targeting LSASS | `-ma lsass.exe` in command line — no legitimate reason on a user workstation |
| Tool in wrong location | `procdump64.exe` in Downloads, not an admin tools directory |
| Dump file with deceptive name | `debug_report.dmp` sounds benign but contains all cached credentials |
| Same PID ties Events 1 and 2 | process_id 19840 in both ProcessCreate and FileCreate |
| Mimikatz is a known threat tool | Any SOC analyst should recognize `mimikatz.exe` by name |
| `sekurlsa::` commands | These are Mimikatz credential extraction modules |
| Both tools launched from cmd.exe | Interactive attacker session — they're at the keyboard |
| Gap between dump and extraction | 2-5 minute delay suggests attacker moved Mimikatz onto the host between steps |

### The Level 4 Difficulty Factor

| Stage | What the Player Must Recognize | Difficulty |
|-------|-------------------------------|------------|
| **1. LOLBin Awareness** | ProcDump is a legitimate Microsoft tool — the player must know that targeting LSASS specifically is the red flag, not the tool itself | High |
| **2. Artifact Recognition** | The `.dmp` file with a benign name is the credential dump — requires understanding that LSASS memory contains credentials | Medium |
| **3. Tool Recognition** | Mimikatz is a well-known credential theft tool — most SOC training covers it, so the name alone should trigger escalation | Medium |
| **4. Chain Correlation** | PID 19840 connects Events 1 and 2, the dump filename connects Events 2 and 3 — player must trace the full chain | High |

---

## Level Progression Preview

| Level | Events | Complexity |
|-------|--------|------------|
| **Level 2** (Recon) | 2 | Network scanning — player identifies port scan pattern |
| **Level 4** (Current) | 3 | Credential dump + extraction — player recognizes tool chain and LSASS targeting |
| **Level 6+** (Future) | 4-5 | Full kill chain: credential dump → extraction → lateral movement to new host → privilege escalation |

---

## Related Log Sources

Additional logs that would appear in a real environment during this attack:

| Log Source | Event | What It Shows |
|------------|-------|---------------|
| **Windows Security 4688** | Process Created | Shows procdump64.exe and mimikatz.exe execution with creator process chain |
| **Windows Security 4663** | Object Access | Shows read access to lsass.exe process memory |
| **Sysmon Event 10** | ProcessAccess | Shows procdump64.exe accessing lsass.exe with PROCESS_ALL_ACCESS rights |
| **Windows Security 4648** | Explicit Credential Logon | Shows attacker using stolen credentials after extraction |
| **Windows Security 4624** | Successful Logon (Type 3) | Shows lateral movement using stolen credentials on other hosts |
| **Proxy** | HTTP_GET | May show download of procdump64.exe or mimikatz.exe |

---

## Detection Rule Logic

```
# Detect ProcDump targeting LSASS
MATCH sysmon_logs WHERE
  event_type = "ProcessCreate"
  AND image LIKE "%procdump%"
  AND commandline LIKE "%lsass%"

# Detect Mimikatz execution
MATCH sysmon_logs WHERE
  event_type = "ProcessCreate"
  AND (
    image LIKE "%mimikatz%"
    OR commandline LIKE "%sekurlsa::%"
    OR commandline LIKE "%lsadump::%"
    OR commandline LIKE "%kerberos::golden%"
  )

# Detect suspicious .dmp file creation from non-standard paths
MATCH sysmon_logs WHERE
  event_type = "FileCreate"
  AND target_filename LIKE "%.dmp"
  AND image NOT LIKE "C:\Windows\System32\WerFault.exe"
  AND image NOT LIKE "C:\Windows\System32\svchost.exe"

# Detect any process accessing LSASS memory (Sysmon Event 10)
MATCH sysmon_logs WHERE
  event_type = "ProcessAccess"
  AND target_image LIKE "%lsass.exe"
  AND granted_access IN ("0x1010", "0x1410", "0x1FFFFF")
```

---

## Common False Positives

| False Positive Scenario | How to Identify |
|-------------------------|-----------------|
| IT admin using ProcDump for crash diagnostics | Target is a crashing application (not lsass.exe), documented change ticket exists, run from admin tools share |
| Windows Error Reporting creating dump files | WerFault.exe is the image, dump goes to `C:\ProgramData\Microsoft\Windows\WER\`, SYSTEM context |
| Endpoint protection scanning LSASS | Security product path (e.g., CrowdStrike, Defender), runs as SYSTEM, matches known EDR behavior |
| Task Manager creating dump file | Image is `taskmgr.exe`, user is admin, single occurrence during troubleshooting |

**Key Differentiators:**
- Legitimate: Admin account, documented purpose, standard tool path, target is NOT lsass.exe (or if it is, it's from an EDR product)
- Malicious: User account context, tool in Downloads/Temp, targeting lsass.exe with `-ma`, followed by Mimikatz

---

## Common LSASS Dumping Tools

| Tool | Type | Detection Indicator |
|------|------|---------------------|
| **Mimikatz** | Purpose-built credential tool | `mimikatz.exe`, `sekurlsa::` commands |
| **ProcDump** | Legitimate Sysinternals tool (LOLBin) | `procdump.exe -ma lsass.exe` |
| **comsvcs.dll** | Built-in Windows DLL (LOLBin) | `rundll32.exe comsvcs.dll, MiniDump <lsass_pid>` |
| **Task Manager** | Built-in Windows tool | Right-click lsass.exe → Create dump file |
| **PowerShell** | Built-in scripting | `Out-Minidump` or direct API calls to `MiniDumpWriteDump` |
| **SQLDumper.exe** | SQL Server utility (LOLBin) | `sqldumper.exe <lsass_pid> 0 0x01100` |
| **createdump.exe** | .NET diagnostic tool (LOLBin) | `createdump.exe -f output.dmp <lsass_pid>` |

---

## LSASS Protection Reference

| Control | What It Does |
|---------|-------------|
| **Credential Guard** | Isolates LSASS credentials in a virtualization-based security container — Mimikatz cannot read them |
| **RunAsPPL** | Runs LSASS as Protected Process Light — blocks unauthorized tools from accessing LSASS memory |
| **ASR Rules** | Microsoft Defender Attack Surface Reduction rule blocks credential stealing from LSASS |
| **Disable WDigest** | Prevents plaintext passwords from being stored in LSASS memory |
| **Tiered Administration** | Prevents admin credentials from being cached on user workstations — limits blast radius |

---

## Process Chain Analysis

### Suspicious Chain (This Scenario)
```
[{hostname}] cmd.exe (attacker interactive session)
  ├── procdump64.exe -ma lsass.exe (CREDENTIAL DUMP — from Downloads)
  │   └── Creates: AppData\Local\Temp\debug_report.dmp
  │       └── Contains all LSASS memory = all cached credentials
  │
  └── mimikatz.exe sekurlsa::minidump ... sekurlsa::logonPasswords (CREDENTIAL EXTRACTION — from Temp)
      └── Reads: debug_report.dmp
          └── Outputs: NTLM hashes, Kerberos tickets, plaintext passwords
              └── Attacker now has credentials for lateral movement
```
**Why Suspicious:** ProcDump in Downloads targeting lsass.exe, dump file with deceptive name in Temp, Mimikatz with sekurlsa commands, cmd.exe parent, regular user context

### Legitimate Chain (Real Diagnostic Dump)
```
[{hostname}] WerFault.exe (Windows Error Reporting)
  └── Creates: C:\ProgramData\Microsoft\Windows\WER\ReportArchive\AppCrash_outlook.exe.dmp
      └── Crash dump of a failing application for Microsoft telemetry
```
**Why Legitimate:** WerFault.exe is the parent (not cmd.exe), dump is in the WER directory (not Temp), target is a crashing application (not lsass.exe), runs as SYSTEM

---

*Last Updated: February 2026*
*Spectyr Training Platform*
