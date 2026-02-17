# Defense Evasion - Level 1 Scenario

> **Category:** Defense Evasion  
> **Subcategory:** Disable or Modify Tools (Windows Defender)  
> **Difficulty:** Level 1 (Fundamentals)  
> **Events:** 1

---

## Scenario Description

A workstation generated a process creation event showing PowerShell execution with suspicious command-line arguments. Review the Sysmon log and determine if this represents a security threat.

---

## Attack Pattern Reference

| Framework | ID | Name | Link |
|-----------|-----|------|------|
| MITRE ATT&CK | **T1562.001** | Impair Defenses: Disable or Modify Tools | [attack.mitre.org](https://attack.mitre.org/techniques/T1562/001/) |
| ATT&CK Tactic | **TA0005** | Defense Evasion | |
| CAPEC | **CAPEC-578** | Disable Security Software | [capec.mitre.org](https://capec.mitre.org/data/definitions/578.html) |

---

## Log Event

### Table View

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| 14:23:47 | ProcessCreate | Sysmon | 10.0.1.45 | | | `Process Create: UtcTime=2026-01-27 14:23:47.532 ProcessGuid={A23EAE89-BD56-5903-0000-0010FBD95E11} ProcessId=9472 Image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe CommandLine=powershell.exe -ExecutionPolicy Bypass -Command "Set-MpPreference -DisableRealtimeMonitoring $true" User=CORP\jsmith ParentImage=C:\Windows\explorer.exe` |

### Expanded Key Value Pairs

```
event_id = 1
event_type = ProcessCreate
utc_time = 2026-01-27 14:23:47.532
process_guid = {A23EAE89-BD56-5903-0000-0010FBD95E11}
process_id = 9472
image = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
command_line = powershell.exe -ExecutionPolicy Bypass -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
user = CORP\jsmith
parent_image = C:\Windows\explorer.exe
parent_command_line = C:\Windows\Explorer.EXE
parent_process_id = 4412
integrity_level = High
host = ACME-WS14
hashes = SHA256=9F914D42706FE215501044ACD85A32D58AAEF1419D404FDDFA5D3B48F66CCD9F
```

---

## Expected Answer

**Classification:** Malicious - Defense Evasion

**Threat Category:** Impair Defenses / Disable Security Tools

---

## Triage Review

### What is it?

**Defense Evasion** is a tactic where attackers disable, modify, or bypass security tools to avoid detection. In this scenario, the attacker used PowerShell to disable Windows Defender's real-time monitoring — a critical protection feature that scans files and processes as they execute.

This is a preparatory step. Attackers disable antivirus **before** deploying malware, establishing persistence, or exfiltrating data. Seeing this event means:
- The attacker has already gained access to the system
- They have elevated privileges (required to modify Defender)
- Malicious activity is likely to follow immediately

| Indicator | What It Means |
|-----------|---------------|
| **`Set-MpPreference -DisableRealtimeMonitoring`** | Windows Defender real-time scanning is now OFF |
| **`-ExecutionPolicy Bypass`** | PowerShell security restrictions were ignored |
| **Parent Process: `explorer.exe`** | Command was run interactively by a user (not automated) |
| **Standard User Account** | A regular employee account was used — potentially compromised |
| **Integrity Level: High** | The process ran with administrator privileges |

### Understanding the Command

```powershell
powershell.exe -ExecutionPolicy Bypass -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
```

| Component | Purpose |
|-----------|---------|
| `powershell.exe` | Windows PowerShell interpreter |
| `-ExecutionPolicy Bypass` | Ignores script execution restrictions |
| `-Command` | Execute the following as a PowerShell command |
| `Set-MpPreference` | Windows Defender configuration cmdlet |
| `-DisableRealtimeMonitoring $true` | Turns OFF real-time malware scanning |

### Common Defense Evasion Commands (Reference)

| Command | Effect | Detection Priority |
|---------|--------|-------------------|
| `Set-MpPreference -DisableRealtimeMonitoring $true` | Disables real-time scanning | **Critical** |
| `Set-MpPreference -DisableBehaviorMonitoring $true` | Disables behavior monitoring | **Critical** |
| `Set-MpPreference -DisableScriptScanning $true` | Disables script scanning | **Critical** |
| `Set-MpPreference -DisableBlockAtFirstSeen $true` | Disables cloud-based protection | **High** |
| `Add-MpPreference -ExclusionPath "C:\Temp"` | Excludes folder from scanning | **High** |
| `Add-MpPreference -ExclusionExtension ".exe"` | Excludes file type from scanning | **Critical** |
| `sc stop WinDefend` | Stops Windows Defender service | **Critical** |
| `net stop WinDefend` | Stops Windows Defender service | **Critical** |
| `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1` | Disables Defender via registry | **Critical** |

### Attack Context

Disabling security tools (T1562.001) is a critical step in many attack chains. Adversaries disable antivirus and endpoint detection to:

- **Execute malware undetected** — Ransomware, RATs, and other payloads trigger AV alerts
- **Establish persistence** — Malicious scheduled tasks and registry keys get flagged
- **Exfiltrate data** — Data loss prevention tools may block unauthorized transfers
- **Move laterally** — Credential dumping tools like Mimikatz are detected by Defender

This technique is often observed **immediately before** malware deployment, making it a critical early warning indicator.

### Real-World Examples

| Threat Actor / Malware | How They Disable Defender |
|------------------------|---------------------------|
| **Ryuk Ransomware** | Uses GMER to kill AV processes before encryption |
| **LockBit / BlackCat** | ToggleDefender tool to disable Defender components |
| **WhisperGate** | Adds malware path to Defender exclusion list |
| **AvosLocker** | Exploits vulnerabilities to disable AV in Safe Mode |
| **DoppelPaymer** | Terminates security processes before payload execution |
| **SUNBURST (SolarWinds)** | Modified Defender settings on compromised systems |

### MITRE ATT&CK Context

**Technique T1562.001 - Impair Defenses: Disable or Modify Tools**

> "Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities. This may take many forms, such as killing security software processes or services, modifying / deleting Registry keys or configuration files so that tools do not operate properly, or other methods to interfere with security tools scanning or reporting information."

**Detection Focus:**
- Monitor for `Set-MpPreference` and `Add-MpPreference` cmdlets
- Track process termination of security services
- Alert on registry modifications to Defender keys
- Monitor for `sc stop` or `net stop` against security services

---

## Recommended Response Actions

### Immediate Actions
1. **Isolate** the affected host from the network to prevent lateral movement
2. **Preserve evidence** — collect logs, memory dump, and disk image before remediation
3. **Re-enable security controls** that were disabled

### Investigation Steps
4. **Determine scope** — search for similar events across other endpoints
5. **Build timeline** — identify what happened before and after this event
6. **Identify root cause** — how did the attacker gain initial access?

### Remediation
7. **Remove threat** — eliminate any malware, persistence mechanisms, or unauthorized accounts
8. **Reset credentials** — assume compromised accounts need password resets
9. **Patch vulnerabilities** — address the entry point used by the attacker

### Post-Incident
10. **Document findings** — create incident report for lessons learned
11. **Update detections** — improve monitoring to catch similar attacks earlier
12. **User awareness** — if social engineering was involved, reinforce training

---

## Log Authenticity Notes

| Field | Value | Why It's Realistic |
|-------|-------|-------------------|
| `Image=powershell.exe` | Full path to legitimate PowerShell — attackers use the real binary |
| `ParentImage=explorer.exe` | User-initiated from desktop/shell — common for interactive attacks |
| `User=CORP\jsmith` | Standard domain user, not SYSTEM — indicates user-level compromise or social engineering |
| `IntegrityLevel=High` | Elevated privileges — required to modify Defender settings |
| `ProcessGuid` | Unique identifier for correlation with other events |
| `CommandLine` | Full command captured — requires command-line auditing enabled |

### Legitimate vs Malicious Comparison

| Legitimate IT Activity | Malicious Activity (This Scenario) |
|------------------------|-----------------------------------|
| Scheduled maintenance window | Random time during business hours |
| Executed by IT admin account (`svc_admin`) | Standard user account (`jsmith`) |
| Documented change request | No change management record |
| Temporary disable, then re-enable | One-way disable with no re-enable |
| Parent process: management tool | Parent process: `explorer.exe` |

---

## Level Progression Preview

| Level | Events | Complexity |
|-------|--------|------------|
| **Level 1** (Current) | 1 | Single event — Defender disabled via PowerShell |
| **Level 2** | 2-3 | Defender disabled → Malware downloaded → Executed |
| **Level 3** | 5-7 | Full kill chain: Disable AV → Drop payload → Persistence → C2 |

---

## Related Log Sources

For more advanced scenarios, defense evasion can be detected across multiple sources:

| Log Source | Event Type | What It Shows |
|------------|------------|---------------|
| **Sysmon Event 1** | ProcessCreate | PowerShell execution with command line (this scenario) |
| **Sysmon Event 13** | RegistryEvent | Defender registry key modifications |
| **Windows Security 4688** | Process Creation | Same as Sysmon but less detail by default |
| **Windows Defender 5001** | Protection Disabled | Direct notification Defender was disabled |
| **Windows Defender 5007** | Configuration Changed | Defender settings modified |
| **Sysmon Event 3** | NetworkConnection | Post-compromise C2 connections |

---

## Detection Rule Logic (Reference)

```
# Sysmon-based detection for Defender tampering
MATCH sysmon_logs WHERE
  event_type = "ProcessCreate"
  AND image CONTAINS "powershell.exe"
  AND (
    command_line CONTAINS "Set-MpPreference" OR
    command_line CONTAINS "Add-MpPreference" OR
    command_line CONTAINS "DisableRealtimeMonitoring" OR
    command_line CONTAINS "DisableBehaviorMonitoring" OR
    command_line CONTAINS "ExclusionPath" OR
    command_line CONTAINS "ExclusionExtension"
  )

# Alternative: Service stop detection
MATCH sysmon_logs WHERE
  event_type = "ProcessCreate"
  AND (
    (image CONTAINS "sc.exe" AND command_line CONTAINS "stop WinDefend") OR
    (image CONTAINS "net.exe" AND command_line CONTAINS "stop WinDefend")
  )
```

---

## Common False Positives

Understanding legitimate scenarios helps avoid alert fatigue:

| False Positive Scenario | How to Identify |
|-------------------------|-----------------|
| IT admin performing maintenance | User account in IT security group, change ticket exists |
| Software deployment requiring temp disable | Parent process is SCCM/Intune/deployment tool |
| Automated patching process | Occurs during scheduled maintenance window |
| Developer testing AV compatibility | User in developer group, non-production machine |

**Key Differentiators:**
- Legitimate: Scheduled, documented, admin account, temporary
- Malicious: Unscheduled, undocumented, standard user, permanent

---

## Process Chain Analysis

Understanding parent-child relationships helps identify attack patterns:

### Suspicious Chain (This Scenario)
```
explorer.exe (user shell)
  └── powershell.exe -ExecutionPolicy Bypass -Command "Set-MpPreference..."
```
**Why Suspicious:** User-initiated PowerShell with Defender tampering

### Legitimate Chain (IT Admin)
```
services.exe
  └── svchost.exe (SCCM Agent)
      └── powershell.exe -File "C:\ProgramData\SCCM\Scripts\Maintenance.ps1"
```
**Why Legitimate:** System service, known script path, scheduled task

---

*Last Updated: January 2026*  
*Spectyr Training Platform*
