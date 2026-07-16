"""Noise profile library (Phase 2 Stage 1): benign endpoint baselines per host
role, consumed by snapshot_generator.py.

Realism bar: every process, service, and autorun entry is real Windows (or
real vendor) content with correct binary paths, service names, and default
start modes. Anything not known with certainty is NOT invented: it is either
omitted or stubbed with an entry in FLAGS below, which the Stage 1 review
checkpoint walks through. Profiles contain no scenario placeholders; the
generator substitutes concrete owner/host values at build time.

A profile is data only. It never generates anything itself; the snapshot
generator derives one world state per session from (environment + substituted
event pool + profile), so tabs are pure views of the same data.

Process spec fields:
    name / path / cmdline   image identity; cmdline None means path only
    parent                  parent process NAME, resolved to a PID at build
                            time ("<exited>" renders a dead parent, which is
                            how explorer.exe really looks: userinit exits)
    user                    account context; OWNER is replaced with the
                            host's owning domain account at build time
    signer                  Authenticode signer display string, None=unsigned
    dup                     how many instances to spawn (svchost etc.)
"""

SYSTEM = "NT AUTHORITY\\SYSTEM"
LOCAL_SERVICE = "NT AUTHORITY\\LOCAL SERVICE"
NETWORK_SERVICE = "NT AUTHORITY\\NETWORK SERVICE"
OWNER = "__OWNER__"          # replaced with DOMAIN\username of the host owner
MS = "Microsoft Windows"
MS_CORP = "Microsoft Corporation"

# Review flags: every deliberate simplification or unresolved identity in this
# library. The Stage 1 acceptance bar is zero UNFLAGGED guesses, not zero flags.
FLAGS = [
    "Defender platform paths RESOLVED at Stage 1 review: MsMpEng.exe and "
    "NisSrv.exe run from C:\\ProgramData\\Microsoft\\Windows Defender\\"
    "Platform\\<platform version>\\, verified against learn.microsoft.com "
    "(microsoft-defender-antivirus-updates, doc dated 2026-05-14, fetched "
    "2026-07-16); the version segment is a stable-key pick from the "
    "documented DEFENDER_PLATFORM_VERSIONS. The doc does not document the "
    "'-0' style folder suffix seen on some live systems, so it is omitted "
    "rather than guessed.",
    "Proxy role: RESOLVED at Stage 1 review. The logs win: proxy events "
    "follow Palo Alto CIM, so ACME-SVR06 is a PAN-OS VM-Series explicit "
    "proxy appliance. Like the firewall it is a log source, never a managed "
    "endpoint, and carries no Windows noise profile.",
    "Backup role: only the Veeam Backup Service and its default 9392 port "
    "are modeled. Console, catalog/database engine, and mount services are "
    "omitted rather than guessed; the 10006 agent port comes from the "
    "scenario chain itself.",
    "Firewall role: PAN-OS appliance. Windows-style endpoint telemetry is "
    "intentionally not fabricated; the endpoint page renders an appliance "
    "notice instead of process/service tabs.",
    "Workstation user-app set (Chrome, Edge, Outlook, Slack, Zoom, OneDrive) "
    "matches LEGIT_EXTERNAL_DOMAINS so network noise and process noise agree. "
    "Versioned install paths (new Teams, WindowsApps packages) are omitted "
    "rather than invented.",
]


def P(name, path, parent, user=SYSTEM, cmdline=None, signer=MS, dup=1):
    return {"name": name, "path": path, "parent": parent, "user": user,
            "cmdline": cmdline or path, "signer": signer, "dup": dup}


def SVC(name, display, path, start, status="Running", account="LocalSystem"):
    return {"name": name, "display_name": display, "path": path,
            "start_type": start, "status": status, "account": account}


# --- Windows core process tree (client and server) ---------------------------
_SYS32 = "C:\\Windows\\System32\\"

# Microsoft Defender platform: binaries run from the versioned platform
# directory. Versions below are documented current releases (Microsoft Learn,
# microsoft-defender-antivirus-updates, fetched 2026-07-16). The generator
# substitutes __DEFENDERVER__ per host via the stable-key scheme.
DEFENDER_PLATFORM_VERSIONS = ("4.18.25050.5", "4.18.25040.2")
_DEFENDER_DIR = ("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\"
                 "__DEFENDERVER__\\")

WINDOWS_CORE_PROCESSES = [
    P("System", "", "", user=SYSTEM, cmdline="", signer=MS),
    P("Registry", "", "System", user=SYSTEM, cmdline="", signer=MS),
    # Session Manager reports its NT device path, as real EDRs show it.
    P("smss.exe", "\\Device\\HarddiskVolume2\\Windows\\System32\\smss.exe",
      "System", cmdline="\\SystemRoot\\System32\\smss.exe"),
    P("csrss.exe", _SYS32 + "csrss.exe", "smss.exe", dup=2),
    P("wininit.exe", _SYS32 + "wininit.exe", "smss.exe"),
    P("winlogon.exe", _SYS32 + "winlogon.exe", "smss.exe"),
    P("services.exe", _SYS32 + "services.exe", "wininit.exe"),
    P("lsass.exe", _SYS32 + "lsass.exe", "wininit.exe"),
    P("fontdrvhost.exe", _SYS32 + "fontdrvhost.exe", "wininit.exe",
      user="Font Driver Host\\UMFD-0"),
    P("dwm.exe", _SYS32 + "dwm.exe", "winlogon.exe",
      user="Window Manager\\DWM-1"),
    P("svchost.exe", _SYS32 + "svchost.exe", "services.exe",
      cmdline=_SYS32 + "svchost.exe -k DcomLaunch -p"),
    P("svchost.exe", _SYS32 + "svchost.exe", "services.exe",
      user=NETWORK_SERVICE, cmdline=_SYS32 + "svchost.exe -k RPCSS -p"),
    # Win10+ splits services into per-process svchost instances on hosts with
    # more than 3.5 GB RAM, so several instances per group is the real shape.
    P("svchost.exe", _SYS32 + "svchost.exe", "services.exe",
      cmdline=_SYS32 + "svchost.exe -k netsvcs -p", dup=3),
    P("svchost.exe", _SYS32 + "svchost.exe", "services.exe",
      user=LOCAL_SERVICE, cmdline=_SYS32 + "svchost.exe -k LocalService -p", dup=2),
    P("svchost.exe", _SYS32 + "svchost.exe", "services.exe",
      user=NETWORK_SERVICE, cmdline=_SYS32 + "svchost.exe -k NetworkService -p"),
    P("svchost.exe", _SYS32 + "svchost.exe", "services.exe", user=LOCAL_SERVICE,
      cmdline=_SYS32 + "svchost.exe -k LocalServiceNetworkRestricted -p"),
    P("svchost.exe", _SYS32 + "svchost.exe", "services.exe",
      cmdline=_SYS32 + "svchost.exe -k LocalSystemNetworkRestricted -p"),
    P("svchost.exe", _SYS32 + "svchost.exe", "services.exe", user=LOCAL_SERVICE,
      cmdline=_SYS32 + "svchost.exe -k LocalServiceNoNetwork -p"),
    P("svchost.exe", _SYS32 + "svchost.exe", "services.exe",
      cmdline=_SYS32 + "svchost.exe -k utcsvc -p"),
    P("svchost.exe", _SYS32 + "svchost.exe", "services.exe",
      cmdline=_SYS32 + "svchost.exe -k wsappx -p"),
    P("taskhostw.exe", _SYS32 + "taskhostw.exe", "svchost.exe",
      cmdline=_SYS32 + "taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}"),
    P("SearchIndexer.exe", _SYS32 + "SearchIndexer.exe", "services.exe",
      cmdline=_SYS32 + "SearchIndexer.exe /Embedding"),
    P("MsMpEng.exe", _DEFENDER_DIR + "MsMpEng.exe",
      "services.exe", signer=MS_CORP),
    P("NisSrv.exe", _DEFENDER_DIR + "NisSrv.exe",
      "services.exe", user=LOCAL_SERVICE, signer=MS_CORP),
    P("SecurityHealthService.exe", _SYS32 + "SecurityHealthService.exe",
      "services.exe"),
    P("Sysmon64.exe", "C:\\Windows\\Sysmon64.exe", "services.exe",
      signer="Microsoft Corporation (Sysinternals)"),
]

# --- interactive user session (workstations) ---------------------------------
WORKSTATION_SESSION_PROCESSES = [
    P("svchost.exe", _SYS32 + "svchost.exe", "services.exe", user=OWNER,
      cmdline=_SYS32 + "svchost.exe -k UnistackSvcGroup"),
    P("svchost.exe", _SYS32 + "svchost.exe", "services.exe", user=OWNER,
      cmdline=_SYS32 + "svchost.exe -k ClipboardSvcGroup -p"),
    P("sihost.exe", _SYS32 + "sihost.exe", "svchost.exe", user=OWNER),
    P("ctfmon.exe", _SYS32 + "ctfmon.exe", "svchost.exe", user=OWNER),
    P("explorer.exe", "C:\\Windows\\explorer.exe", "<exited>", user=OWNER,
      cmdline="C:\\Windows\\Explorer.EXE"),
    P("RuntimeBroker.exe", _SYS32 + "RuntimeBroker.exe", "svchost.exe",
      user=OWNER, cmdline=_SYS32 + "RuntimeBroker.exe -Embedding", dup=2),
    P("ShellExperienceHost.exe",
      "C:\\Windows\\SystemApps\\ShellExperienceHost_cw5n1h2txyewy\\ShellExperienceHost.exe",
      "svchost.exe", user=OWNER,
      cmdline="\"C:\\Windows\\SystemApps\\ShellExperienceHost_cw5n1h2txyewy\\ShellExperienceHost.exe\" -ServerName:App.AppXtk181tbxbce2qsex02s8tw7hfxa9xb3t.mca"),
    P("StartMenuExperienceHost.exe",
      "C:\\Windows\\SystemApps\\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\\StartMenuExperienceHost.exe",
      "svchost.exe", user=OWNER),
    P("dllhost.exe", _SYS32 + "dllhost.exe", "svchost.exe", user=OWNER,
      cmdline=_SYS32 + "dllhost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}"),
    P("spoolsv.exe", _SYS32 + "spoolsv.exe", "services.exe"),
    P("SecurityHealthSystray.exe", _SYS32 + "SecurityHealthSystray.exe",
      "explorer.exe", user=OWNER),
    P("OneDrive.exe",
      "C:\\Users\\__OWNERNAME__\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
      "explorer.exe", user=OWNER, signer=MS_CORP, cmdline=None),
    P("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
      "explorer.exe", user=OWNER, signer="Google LLC"),
    P("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
      "chrome.exe", user=OWNER, signer="Google LLC",
      cmdline="\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=renderer",
      dup=2),
    P("msedge.exe",
      "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
      "explorer.exe", user=OWNER, signer=MS_CORP),
    P("OUTLOOK.EXE",
      "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
      "explorer.exe", user=OWNER, signer=MS_CORP),
    P("slack.exe",
      "C:\\Users\\__OWNERNAME__\\AppData\\Local\\slack\\slack.exe",
      "explorer.exe", user=OWNER, signer="Slack Technologies, LLC"),
    P("Zoom.exe",
      "C:\\Users\\__OWNERNAME__\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe",
      "explorer.exe", user=OWNER, signer="Zoom Video Communications, Inc."),
]

# --- role-specific server processes -------------------------------------------
DC_PROCESSES = [
    # No dns.exe here: the DNS role lives on ACME-SVR03 in this environment.
    P("dfsrs.exe", _SYS32 + "dfsrs.exe", "services.exe"),
    P("ismserv.exe", _SYS32 + "ismserv.exe", "services.exe"),
    P("dfssvc.exe", _SYS32 + "dfssvc.exe", "services.exe"),
    P("Microsoft.ActiveDirectory.WebServices.exe",
      "C:\\Windows\\ADWS\\Microsoft.ActiveDirectory.WebServices.exe",
      "services.exe"),
]

DNS_PROCESSES = [
    P("dns.exe", _SYS32 + "dns.exe", "services.exe"),
]

FILE_PROCESSES = [
    # File serving is svchost-hosted (LanmanServer); no extra image needed.
]

WEB_PROCESSES = [
    P("svchost.exe", _SYS32 + "svchost.exe", "services.exe",
      cmdline=_SYS32 + "svchost.exe -k iissvcs"),
    P("w3wp.exe", _SYS32 + "inetsrv\\w3wp.exe", "svchost.exe",
      user="IIS APPPOOL\\DefaultAppPool",
      cmdline=_SYS32 + "inetsrv\\w3wp.exe -ap \"DefaultAppPool\"", dup=2),
]

BACKUP_PROCESSES = [
    P("Veeam.Backup.Service.exe",
      "C:\\Program Files\\Veeam\\Backup and Replication\\Backup\\Veeam.Backup.Service.exe",
      "services.exe", signer="Veeam Software Group GmbH"),
]

PRINT_PROCESSES = [
    P("spoolsv.exe", _SYS32 + "spoolsv.exe", "services.exe"),
]

# --- services ------------------------------------------------------------------
_SVCHOST = _SYS32 + "svchost.exe"

WINDOWS_CORE_SERVICES = [
    SVC("EventLog", "Windows Event Log", _SVCHOST + " -k LocalServiceNetworkRestricted",
        "Automatic", account="NT AUTHORITY\\LocalService"),
    SVC("Schedule", "Task Scheduler", _SVCHOST + " -k netsvcs -p", "Automatic"),
    SVC("RpcSs", "Remote Procedure Call (RPC)", _SVCHOST + " -k rpcss",
        "Automatic", account="NT AUTHORITY\\NetworkService"),
    SVC("DcomLaunch", "DCOM Server Process Launcher", _SVCHOST + " -k DcomLaunch -p",
        "Automatic"),
    SVC("Dnscache", "DNS Client", _SVCHOST + " -k NetworkService -p",
        "Automatic", account="NT AUTHORITY\\NetworkService"),
    SVC("Dhcp", "DHCP Client", _SVCHOST + " -k LocalServiceNetworkRestricted -p",
        "Automatic", account="NT AUTHORITY\\LocalService"),
    SVC("LanmanWorkstation", "Workstation", _SVCHOST + " -k NetworkService -p",
        "Automatic", account="NT AUTHORITY\\NetworkService"),
    SVC("LanmanServer", "Server", _SVCHOST + " -k netsvcs -p", "Automatic"),
    SVC("Netlogon", "Netlogon", _SYS32 + "lsass.exe", "Automatic"),
    SVC("W32Time", "Windows Time", _SVCHOST + " -k LocalService",
        "Manual", account="NT AUTHORITY\\LocalService"),
    SVC("WinDefend", "Microsoft Defender Antivirus Service",
        "\"" + _DEFENDER_DIR + "MsMpEng.exe\"", "Automatic"),
    SVC("WdNisSvc", "Microsoft Defender Antivirus Network Inspection Service",
        "\"" + _DEFENDER_DIR + "NisSrv.exe\"", "Manual",
        account="NT AUTHORITY\\LocalService"),
    SVC("SecurityHealthService", "Windows Security Service",
        _SYS32 + "SecurityHealthService.exe", "Manual"),
    SVC("Sysmon64", "Sysmon64", "C:\\Windows\\Sysmon64.exe", "Automatic"),
    SVC("wuauserv", "Windows Update", _SVCHOST + " -k netsvcs -p", "Manual"),
    SVC("BITS", "Background Intelligent Transfer Service",
        _SVCHOST + " -k netsvcs -p", "Manual"),
    SVC("CryptSvc", "Cryptographic Services", _SVCHOST + " -k NetworkService -p",
        "Automatic", account="NT AUTHORITY\\NetworkService"),
    SVC("DiagTrack", "Connected User Experiences and Telemetry",
        _SVCHOST + " -k utcsvc -p", "Automatic"),
]

WORKSTATION_SERVICES = [
    SVC("WSearch", "Windows Search", _SYS32 + "SearchIndexer.exe /Embedding",
        "Automatic"),
    SVC("Spooler", "Print Spooler", _SYS32 + "spoolsv.exe", "Automatic"),
    SVC("Themes", "Themes", _SVCHOST + " -k netsvcs -p", "Automatic"),
    SVC("Audiosrv", "Windows Audio", _SVCHOST + " -k LocalServiceNetworkRestricted -p",
        "Automatic", account="NT AUTHORITY\\LocalService"),
]

SERVER_BASE_SERVICES = [
    SVC("WinRM", "Windows Remote Management (WS-Management)",
        _SVCHOST + " -k NetworkService -p", "Automatic",
        account="NT AUTHORITY\\NetworkService"),
    SVC("TermService", "Remote Desktop Services",
        _SVCHOST + " -k NetworkService", "Manual",
        account="NT AUTHORITY\\NetworkService"),
]

ROLE_SERVICES = {
    "dc": [
        SVC("NTDS", "Active Directory Domain Services", _SYS32 + "lsass.exe",
            "Automatic"),
        SVC("Kdc", "Kerberos Key Distribution Center", _SYS32 + "lsass.exe",
            "Automatic"),
        SVC("DFSR", "DFS Replication", _SYS32 + "dfsrs.exe", "Automatic"),
        SVC("Dfs", "DFS Namespace", _SYS32 + "dfssvc.exe", "Automatic"),
        SVC("ADWS", "Active Directory Web Services",
            "C:\\Windows\\ADWS\\Microsoft.ActiveDirectory.WebServices.exe",
            "Automatic"),
        SVC("IsmServ", "Intersite Messaging", _SYS32 + "ismserv.exe",
            "Automatic"),
    ],
    "dns": [
        SVC("DNS", "DNS Server", _SYS32 + "dns.exe", "Automatic"),
    ],
    "file": [
        SVC("VSS", "Volume Shadow Copy", _SYS32 + "vssvc.exe", "Manual",
            status="Stopped"),
    ],
    "web": [
        SVC("W3SVC", "World Wide Web Publishing Service",
            _SVCHOST + " -k iissvcs", "Automatic"),
        SVC("WAS", "Windows Process Activation Service",
            _SVCHOST + " -k iissvcs", "Automatic"),
        SVC("AppHostSvc", "Application Host Helper Service",
            _SVCHOST + " -k apphost", "Automatic"),
    ],
    "print": [
        SVC("Spooler", "Print Spooler", _SYS32 + "spoolsv.exe", "Automatic"),
    ],
    "backup": [
        SVC("VeeamBackupSvc", "Veeam Backup Service",
            "\"C:\\Program Files\\Veeam\\Backup and Replication\\Backup\\Veeam.Backup.Service.exe\"",
            "Automatic"),
    ],
    # no "proxy" entry: PAN-OS appliance, never a managed endpoint
}

# --- autoruns --------------------------------------------------------------------
WORKSTATION_AUTORUNS = [
    {"location": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
     "name": "SecurityHealth",
     "command": _SYS32 + "SecurityHealthSystray.exe",
     "_signer": "Microsoft Windows"},
    {"location": "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
     "name": "OneDrive",
     "command": "\"C:\\Users\\__OWNERNAME__\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background",
     "_signer": "Microsoft Corporation"},
]

# --- local users -------------------------------------------------------------------
CLIENT_LOCAL_USERS = [
    {"username": "Administrator", "domain": "__HOSTNAME__", "type": "Local",
     "enabled": False, "groups": ["Administrators"],
     "description": "Built-in account for administering the computer/domain"},
    {"username": "DefaultAccount", "domain": "__HOSTNAME__", "type": "Local",
     "enabled": False, "groups": ["System Managed Accounts Group"],
     "description": "A user account managed by the system"},
    {"username": "Guest", "domain": "__HOSTNAME__", "type": "Local",
     "enabled": False, "groups": ["Guests"],
     "description": "Built-in account for guest access to the computer/domain"},
    {"username": "WDAGUtilityAccount", "domain": "__HOSTNAME__", "type": "Local",
     "enabled": False, "groups": [],
     "description": "A user account managed and used by the system for Windows Defender Application Guard scenarios"},
]

SERVER_LOCAL_USERS = [
    {"username": "Administrator", "domain": "__HOSTNAME__", "type": "Local",
     "enabled": True, "groups": ["Administrators"],
     "description": "Built-in account for administering the computer/domain"},
    {"username": "DefaultAccount", "domain": "__HOSTNAME__", "type": "Local",
     "enabled": False, "groups": ["System Managed Accounts Group"],
     "description": "A user account managed by the system"},
    {"username": "Guest", "domain": "__HOSTNAME__", "type": "Local",
     "enabled": False, "groups": ["Guests"],
     "description": "Built-in account for guest access to the computer/domain"},
]

# Domain controllers have no local SAM: built-in domain accounts instead.
DC_USERS = [
    {"username": "Administrator", "domain": "ACME", "type": "Domain",
     "enabled": True,
     "groups": ["Administrators", "Domain Admins", "Domain Users", "Enterprise Admins"],
     "description": "Built-in account for administering the computer/domain"},
    {"username": "Guest", "domain": "ACME", "type": "Domain",
     "enabled": False, "groups": ["Guests", "Domain Guests"],
     "description": "Built-in account for guest access to the computer/domain"},
    {"username": "krbtgt", "domain": "ACME", "type": "Domain",
     "enabled": False,
     "groups": ["Domain Users", "Denied RODC Password Replication Group"],
     "description": "Key Distribution Center Service Account"},
]

# --- network noise ------------------------------------------------------------------
# Benign external destinations: (domain, ip, port). IPs sit in the vendor's
# real address space, matching the style already authored in scenario chains
# (52.96.x M365, 142.250.x Google, 140.82.x GitHub, 13.107.x Microsoft).
BENIGN_EXTERNAL = [
    ("outlook.office365.com", "52.96.165.18", 443),
    ("login.microsoftonline.com", "20.190.151.68", 443),
    ("teams.microsoft.com", "52.113.194.132", 443),
    ("www.google.com", "142.250.80.36", 443),
    ("github.com", "140.82.113.4", 443),
    ("slack.com", "3.94.224.37", 443),
    ("ctldl.windowsupdate.com", "13.107.4.50", 80),
    ("v10.events.data.microsoft.com", "13.89.179.10", 443),
]

# Benign DNS query noise beyond the connection targets above:
# (domain, record type, resolved address). "__DC__" resolves to the domain
# controller at build time; SRV answers are names, shown as "-".
BENIGN_DNS_EXTRA = [
    ("sharepoint.com", "A", "13.107.136.10"),
    ("office365.com", "A", "52.96.88.14"),
    ("zoom.us", "A", "170.114.52.2"),
    ("stackoverflow.com", "A", "104.18.32.7"),
    ("cloudflare.com", "A", "104.16.132.229"),
    ("_ldap._tcp.acme.local", "SRV", "-"),
    ("acme.local", "A", "__DC__"),
]

# Listening ports per role (proto, port, process name). Textbook defaults;
# the backup agent port 10006 is established by the scenario chain itself.
ROLE_LISTENING = {
    "workstation": [("tcp", 135, "svchost.exe"), ("tcp", 445, "System"),
                    ("tcp", 5985, "System")],
    "dc": [("tcp", 88, "lsass.exe"), ("tcp", 135, "svchost.exe"),
           ("tcp", 389, "lsass.exe"), ("tcp", 445, "System"),
           ("tcp", 464, "lsass.exe"), ("tcp", 636, "lsass.exe"),
           ("tcp", 3268, "lsass.exe"), ("tcp", 3269, "lsass.exe"),
           ("tcp", 3389, "svchost.exe"), ("tcp", 5985, "System"),
           ("tcp", 9389, "Microsoft.ActiveDirectory.WebServices.exe")],
    "file": [("tcp", 135, "svchost.exe"), ("tcp", 445, "System"),
             ("tcp", 3389, "svchost.exe"), ("tcp", 5985, "System")],
    "dns": [("tcp", 53, "dns.exe"), ("udp", 53, "dns.exe"),
            ("tcp", 135, "svchost.exe"), ("tcp", 445, "System"),
            ("tcp", 3389, "svchost.exe"), ("tcp", 5985, "System")],
    "web": [("tcp", 80, "System"), ("tcp", 443, "System"),
            ("tcp", 135, "svchost.exe"), ("tcp", 445, "System"),
            ("tcp", 3389, "svchost.exe"), ("tcp", 5985, "System")],
    "print": [("tcp", 135, "svchost.exe"), ("tcp", 445, "System"),
              ("tcp", 3389, "svchost.exe"), ("tcp", 5985, "System")],
    "backup": [("tcp", 135, "svchost.exe"), ("tcp", 445, "System"),
               ("tcp", 3389, "svchost.exe"), ("tcp", 5985, "System"),
               ("tcp", 9392, "Veeam.Backup.Service.exe"),
               ("tcp", 10006, "Veeam.Backup.Service.exe")],
    "server": [("tcp", 135, "svchost.exe"), ("tcp", 445, "System"),
               ("tcp", 3389, "svchost.exe"), ("tcp", 5985, "System")],
}


def processes_for_role(role):
    procs = [dict(p) for p in WINDOWS_CORE_PROCESSES]
    extra = {
        "workstation": WORKSTATION_SESSION_PROCESSES,
        "dc": DC_PROCESSES,
        "dns": DNS_PROCESSES,
        "file": FILE_PROCESSES,
        "web": WEB_PROCESSES,
        "print": PRINT_PROCESSES,
        "backup": BACKUP_PROCESSES,
        "server": [],
    }.get(role, [])
    procs.extend(dict(p) for p in extra if p.get("dup", 1) > 0)
    return procs


def services_for_role(role):
    svcs = [dict(s) for s in WINDOWS_CORE_SERVICES]
    if role == "workstation":
        svcs.extend(dict(s) for s in WORKSTATION_SERVICES)
    else:
        svcs.extend(dict(s) for s in SERVER_BASE_SERVICES)
    svcs.extend(dict(s) for s in ROLE_SERVICES.get(role, []))
    return svcs


def users_for_role(role):
    if role == "workstation":
        return [dict(u) for u in CLIENT_LOCAL_USERS]
    if role == "dc":
        return [dict(u) for u in DC_USERS]
    return [dict(u) for u in SERVER_LOCAL_USERS]


def autoruns_for_role(role):
    return [dict(a) for a in WORKSTATION_AUTORUNS] if role == "workstation" else []
