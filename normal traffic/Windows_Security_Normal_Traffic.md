# Windows Security Normal Traffic Patterns for Spectyr

> Purpose: Realistic background noise for SOC training scenarios
> Source: Windows Security Event Log, Microsoft documentation

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
| 08:00:15 | 4624 | Windows Security | | | | `An account was successfully logged on. Subject: Security ID: S-1-5-18 Account Name: WS-PC045$ Account Domain: CORP Logon ID: 0x3E7 Logon Type: 2 New Logon: Security ID: S-1-5-21-xxx-1001 Account Name: jsmith Account Domain: CORP Logon ID: 0x1A2B3C Logon Process: User32 Authentication Package: Kerberos Workstation Name: WS-PC045` | `event_id=4624, logon_type=2, logon_type_name=Interactive, target_user=jsmith, target_domain=CORP, auth_package=Kerberos, workstation=WS-PC045, logon_id=0x1A2B3C, status=Success` |
| 08:00:16 | 4672 | Windows Security | | | | `Special privileges assigned to new logon. Subject: Security ID: S-1-5-21-xxx-1001 Account Name: jsmith Account Domain: CORP Logon ID: 0x1A2B3C Privileges: SeChangeNotifyPrivilege SeIncreaseWorkingSetPrivilege SeShutdownPrivilege` | `event_id=4672, target_user=jsmith, target_domain=CORP, logon_id=0x1A2B3C, privileges=SeChangeNotifyPrivilege;SeIncreaseWorkingSetPrivilege;SeShutdownPrivilege` |
| 08:01:03 | 4624 | Windows Security | | | | `An account was successfully logged on. Subject: Security ID: S-1-5-18 Logon Type: 5 New Logon: Security ID: S-1-5-18 Account Name: SYSTEM Account Domain: NT AUTHORITY Logon ID: 0x3E8 Logon Process: Advapi Authentication Package: Negotiate Process Name: C:\Windows\System32\services.exe` | `event_id=4624, logon_type=5, logon_type_name=Service, target_user=SYSTEM, target_domain=NT AUTHORITY, auth_package=Negotiate, process_name=services.exe, logon_id=0x3E8, status=Success` |
| 08:05:22 | 4688 | Windows Security | | | | `A new process has been created. Subject: Security ID: S-1-5-18 Account Name: WS-PC045$ Account Domain: CORP Process Information: New Process ID: 0x1234 New Process Name: C:\Windows\explorer.exe Creator Process ID: 0x0ABC Creator Process Name: C:\Windows\System32\winlogon.exe Process Command Line: C:\Windows\Explorer.EXE` | `event_id=4688, new_process_name=explorer.exe, new_process_id=0x1234, creator_process_name=winlogon.exe, creator_process_id=0x0ABC, command_line=C:\Windows\Explorer.EXE, user=jsmith` |
| 08:05:45 | 4688 | Windows Security | | | | `A new process has been created. Subject: Security ID: S-1-5-21-xxx-1001 Account Name: jsmith Account Domain: CORP Process Information: New Process ID: 0x1456 New Process Name: C:\Windows\System32\RuntimeBroker.exe Creator Process ID: 0x0890 Creator Process Name: C:\Windows\System32\svchost.exe` | `event_id=4688, new_process_name=RuntimeBroker.exe, new_process_id=0x1456, creator_process_name=svchost.exe, creator_process_id=0x0890, user=jsmith` |
| 08:15:33 | 4624 | Windows Security | 10.0.1.45 | 10.0.1.10 | | `An account was successfully logged on. Subject: Security ID: S-1-0-0 Logon Type: 3 New Logon: Security ID: S-1-5-21-xxx-1001 Account Name: jsmith Account Domain: CORP Network Information: Workstation Name: WS-PC045 Source Network Address: 10.0.1.45 Source Port: 49300 Authentication Package: NTLM` | `event_id=4624, logon_type=3, logon_type_name=Network, target_user=jsmith, target_domain=CORP, auth_package=NTLM, src_ip=10.0.1.45, src_port=49300, workstation=WS-PC045, target_server=FS01, status=Success` |
| 08:16:02 | 4634 | Windows Security | | | | `An account was logged off. Subject: Security ID: S-1-5-21-xxx-1001 Account Name: jsmith Account Domain: CORP Logon ID: 0x1A2B3C Logon Type: 3` | `event_id=4634, logon_type=3, logon_type_name=Network, target_user=jsmith, target_domain=CORP, logon_id=0x1A2B3C` |
| 08:30:00 | 4624 | Windows Security | | | | `An account was successfully logged on. Subject: Security ID: S-1-5-18 Logon Type: 5 New Logon: Security ID: S-1-5-18 Account Name: SYSTEM Account Domain: NT AUTHORITY Logon ID: 0x3E9 Logon Process: Advapi Authentication Package: Negotiate Process Name: C:\Windows\System32\svchost.exe` | `event_id=4624, logon_type=5, logon_type_name=Service, target_user=SYSTEM, target_domain=NT AUTHORITY, auth_package=Negotiate, process_name=svchost.exe, logon_id=0x3E9, service=Windows Update, status=Success` |
| 09:00:12 | 4624 | Windows Security | | | | `An account was successfully logged on. Subject: Security ID: S-1-5-18 Logon Type: 7 New Logon: Security ID: S-1-5-21-xxx-1001 Account Name: jsmith Account Domain: CORP Logon ID: 0x2C3D4E Logon Process: User32 Authentication Package: Kerberos Workstation Name: WS-PC045` | `event_id=4624, logon_type=7, logon_type_name=Unlock, target_user=jsmith, target_domain=CORP, auth_package=Kerberos, workstation=WS-PC045, logon_id=0x2C3D4E, status=Success` |
| 09:15:44 | 4688 | Windows Security | | | | `A new process has been created. Subject: Security ID: S-1-5-21-xxx-1001 Account Name: jsmith Account Domain: CORP Process Information: New Process ID: 0x2468 New Process Name: C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE Creator Process ID: 0x1234 Creator Process Name: C:\Windows\explorer.exe` | `event_id=4688, new_process_name=OUTLOOK.EXE, new_process_id=0x2468, creator_process_name=explorer.exe, creator_process_id=0x1234, user=jsmith` |
| 09:22:18 | 4648 | Windows Security | | | | `A logon was attempted using explicit credentials. Subject: Security ID: S-1-5-21-xxx-1001 Account Name: jsmith Account Domain: CORP Logon ID: 0x2C3D4E Account Whose Credentials Were Used: Account Name: jsmith Account Domain: CORP Target Server: Target Server Name: FS01 Additional Information: Process ID: 0x2468 Process Name: C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE` | `event_id=4648, subject_user=jsmith, target_user=jsmith, target_server=FS01, process_name=OUTLOOK.EXE, process_id=0x2468, logon_id=0x2C3D4E` |
| 09:30:05 | 4624 | Windows Security | 10.0.1.45 | 10.0.1.20 | | `An account was successfully logged on. Subject: Security ID: S-1-0-0 Logon Type: 3 New Logon: Security ID: S-1-5-21-xxx-1001 Account Name: jsmith Account Domain: CORP Network Information: Workstation Name: WS-PC045 Source Network Address: 10.0.1.45 Source Port: 49350 Authentication Package: Kerberos` | `event_id=4624, logon_type=3, logon_type_name=Network, target_user=jsmith, target_domain=CORP, auth_package=Kerberos, src_ip=10.0.1.45, src_port=49350, workstation=WS-PC045, target_server=PRINT01, status=Success` |
| 10:00:33 | 4688 | Windows Security | | | | `A new process has been created. Subject: Security ID: S-1-5-18 Account Name: WS-PC045$ Account Domain: CORP Process Information: New Process ID: 0x3580 New Process Name: C:\Windows\System32\svchost.exe Creator Process ID: 0x02AC Creator Process Name: C:\Windows\System32\services.exe Process Command Line: C:\Windows\System32\svchost.exe -k netsvcs -p` | `event_id=4688, new_process_name=svchost.exe, new_process_id=0x3580, creator_process_name=services.exe, creator_process_id=0x02AC, command_line=svchost.exe -k netsvcs -p, user=SYSTEM` |
| 10:15:00 | 4624 | Windows Security | 10.0.1.100 | 10.0.1.45 | | `An account was successfully logged on. Subject: Security ID: S-1-0-0 Logon Type: 3 New Logon: Security ID: S-1-5-21-xxx-2001 Account Name: svc_backup Account Domain: CORP Network Information: Workstation Name: BACKUP01 Source Network Address: 10.0.1.100 Source Port: 49600 Authentication Package: Negotiate` | `event_id=4624, logon_type=3, logon_type_name=Network, target_user=svc_backup, target_domain=CORP, auth_package=Negotiate, src_ip=10.0.1.100, src_port=49600, workstation=BACKUP01, status=Success` |
| 10:15:01 | 4672 | Windows Security | | | | `Special privileges assigned to new logon. Subject: Security ID: S-1-5-21-xxx-2001 Account Name: svc_backup Account Domain: CORP Logon ID: 0x4D5E6F Privileges: SeBackupPrivilege SeRestorePrivilege SeChangeNotifyPrivilege` | `event_id=4672, target_user=svc_backup, target_domain=CORP, logon_id=0x4D5E6F, privileges=SeBackupPrivilege;SeRestorePrivilege;SeChangeNotifyPrivilege` |
| 10:45:22 | 4634 | Windows Security | | | | `An account was logged off. Subject: Security ID: S-1-5-21-xxx-1001 Account Name: jsmith Account Domain: CORP Logon ID: 0x2C3D4E Logon Type: 7` | `event_id=4634, logon_type=7, logon_type_name=Unlock, target_user=jsmith, target_domain=CORP, logon_id=0x2C3D4E` |
| 11:00:08 | 4624 | Windows Security | | | | `An account was successfully logged on. Subject: Security ID: S-1-5-18 Logon Type: 2 New Logon: Security ID: S-1-5-21-xxx-1001 Account Name: jsmith Account Domain: CORP Logon ID: 0x5E6F70 Logon Process: User32 Authentication Package: Kerberos Workstation Name: WS-PC045` | `event_id=4624, logon_type=2, logon_type_name=Interactive, target_user=jsmith, target_domain=CORP, auth_package=Kerberos, workstation=WS-PC045, logon_id=0x5E6F70, status=Success` |
| 11:30:15 | 4688 | Windows Security | | | | `A new process has been created. Subject: Security ID: S-1-5-18 Account Name: WS-PC045$ Account Domain: CORP Process Information: New Process ID: 0x4692 New Process Name: C:\Windows\System32\taskhostw.exe Creator Process ID: 0x0890 Creator Process Name: C:\Windows\System32\svchost.exe` | `event_id=4688, new_process_name=taskhostw.exe, new_process_id=0x4692, creator_process_name=svchost.exe, creator_process_id=0x0890, user=SYSTEM` |
| 12:00:00 | 4624 | Windows Security | | | | `An account was successfully logged on. Subject: Security ID: S-1-5-18 Logon Type: 2 New Logon: Security ID: S-1-5-90-0-1 Account Name: DWM-1 Account Domain: Window Manager Logon ID: 0x6F7080 Logon Process: Advapi Authentication Package: Negotiate` | `event_id=4624, logon_type=2, logon_type_name=Interactive, target_user=DWM-1, target_domain=Window Manager, auth_package=Negotiate, logon_id=0x6F7080, service=Desktop Window Manager, status=Success` |
| 12:15:44 | 4688 | Windows Security | | | | `A new process has been created. Subject: Security ID: S-1-5-21-xxx-1001 Account Name: jsmith Account Domain: CORP Process Information: New Process ID: 0x57A4 New Process Name: C:\Program Files\Google\Chrome\Application\chrome.exe Creator Process ID: 0x1234 Creator Process Name: C:\Windows\explorer.exe Process Command Line: "C:\Program Files\Google\Chrome\Application\chrome.exe"` | `event_id=4688, new_process_name=chrome.exe, new_process_id=0x57A4, creator_process_name=explorer.exe, creator_process_id=0x1234, command_line="C:\Program Files\Google\Chrome\Application\chrome.exe", user=jsmith` |

---

## Event Type Distribution

| Event ID | EVENT TYPE | Count | Description |
|----------|------------|-------|-------------|
| 4624 | Successful Logon | 9 | User and service authentication events |
| 4634 | Successful Logoff | 2 | Session termination |
| 4672 | Special Privileges | 2 | Elevated rights assigned at logon |
| 4688 | Process Created | 6 | Process execution tracking |
| 4648 | Explicit Credentials | 1 | Alternate credential usage |

---

## Logon Type Reference

| Type | Name | Description | Normal Use Case |
|------|------|-------------|-----------------|
| 2 | Interactive | Console login at keyboard | User logging into workstation |
| 3 | Network | Accessing network resources | File shares, printers, mapped drives |
| 5 | Service | Windows service startup | Background services |
| 7 | Unlock | Unlocking locked workstation | User returning from break |
| 10 | RemoteInteractive | RDP session | Remote administration |
| 11 | CachedInteractive | Cached domain credentials | Laptop offline login |

---

## Authentication Packages

| Package | Description | Typical Use |
|---------|-------------|-------------|
| Kerberos | Domain authentication protocol | Domain-joined machines, SSO |
| NTLM | Legacy authentication | Older systems, workgroup, fallback |
| Negotiate | Auto-selects Kerberos or NTLM | Most common, flexible |

---

## Patterns Represented

### User Activity (jsmith)
- Morning login (Type 2 Interactive)
- Workstation unlock (Type 7)
- Network file share access (Type 3)
- Print server access (Type 3)
- Application launches (4688)

### System Activity (SYSTEM)
- Service startups (Type 5)
- Scheduled tasks
- Background processes (svchost.exe, taskhostw.exe)
- Desktop Window Manager (DWM)

### Service Accounts
- svc_backup: Backup service with SeBackupPrivilege/SeRestorePrivilege

### Normal Process Chains
- winlogon.exe → explorer.exe
- explorer.exe → chrome.exe, OUTLOOK.EXE
- services.exe → svchost.exe
- svchost.exe → taskhostw.exe, RuntimeBroker.exe

---

## Network Context

| IP | Role | Description |
|----|------|-------------|
| 10.0.1.45 | WS-PC045 | User workstation (jsmith) |
| 10.0.1.10 | FS01 | File server |
| 10.0.1.20 | PRINT01 | Print server |
| 10.0.1.100 | BACKUP01 | Backup server |

---

## Usage Notes

1. **PROTOCOL column** is blank for Windows Security Events (authentication package shown in MESSAGE)
2. **SOURCE/DEST IP** only populated for Type 3 Network logons where remote system is involved
3. **Logon IDs** (0x1A2B3C format) correlate 4624 with 4634/4647 for session tracking
4. **4672 always follows 4624** for accounts with special privileges
5. **Type 5 (Service) logons** are normal for SYSTEM account
6. **DWM and UMFD logons** are high-volume system noise - whitelist in detection rules
7. **Type 3 Network logons** disconnect quickly after resource access

---

## Windows Security Event ID Quick Reference

| Event ID | Description | Detection Value |
|----------|-------------|-----------------|
| 4624 | Successful Logon | Baseline authentication activity |
| 4625 | Failed Logon | Brute force detection |
| 4634 | Logoff | Session duration tracking |
| 4647 | User Initiated Logoff | Interactive session end |
| 4648 | Explicit Credentials | RunAs, credential switching |
| 4672 | Special Privileges | Admin activity tracking |
| 4688 | Process Created | Process execution chain |
| 4689 | Process Exited | Process termination |
| 4776 | NTLM Authentication | Credential validation |
| 4768 | Kerberos TGT Request | Domain authentication |
| 4769 | Kerberos Service Ticket | Service access |
