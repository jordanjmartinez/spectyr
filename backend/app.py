from flask import Flask, request, jsonify, g
from flask_cors import CORS
import os
import json
import uuid
import random
import time
import copy
import shutil
from datetime import datetime, timezone, timedelta
import threading

app = Flask(__name__)
CORS(app, supports_credentials=True, expose_headers=["X-Session-ID"], origins=[
    "http://localhost:3000",
    "https://spectyr.dev",
    "https://www.spectyr.dev"
])

LOG_DIR = "logs"
SCENARIO_PATH = os.path.join(LOG_DIR, "simulated_attack_logs.ndjson")
os.makedirs(LOG_DIR, exist_ok=True)

TIMER_DURATIONS = {1: 900, 2: 900, 3: 900, 4: 900, 5: 900}

def get_timer_duration(level):
    return TIMER_DURATIONS.get(level, 900)

# --- Session Management ---
SESSION_COOKIE_NAME = "spectyr_session"
SESSION_TTL_SECONDS = 1800  # 30 minutes
IS_PRODUCTION = os.environ.get("FLASK_ENV") == "production" or os.environ.get("SPECTYR_PROD") or os.environ.get("RENDER")

sessions = {}
sessions_lock = threading.Lock()

def create_session():
    """Create a new session with fresh state."""
    session_id = str(uuid.uuid4())
    session_dir = os.path.join(LOG_DIR, session_id)
    os.makedirs(session_dir, exist_ok=True)

    paths = {
        "generated_logs": os.path.join(session_dir, "generated_logs.ndjson"),
        "analyst_actions": os.path.join(session_dir, "analyst_actions.ndjson"),
        "incident_reports": os.path.join(session_dir, "incident_reports.ndjson"),
    }
    for p in paths.values():
        open(p, "a").close()

    session = {
        "id": session_id,
        "paths": paths,
        "session_dir": session_dir,
        "current_scenario": None,
        "paused": True,
        "current_level": 0,
        "game_mode": "training",
        "timer_start": None,
        "analyst_name": None,
        "used_alert_ids": set(),
        "selected_level_option": None,
        "scenario_history": [],
        "last_active": datetime.now(timezone.utc),
    }
    with sessions_lock:
        sessions[session_id] = session
    return session

def get_session():
    """Get existing session or create a new one."""
    session_id = request.headers.get('X-Session-ID') or request.cookies.get(SESSION_COOKIE_NAME)
    with sessions_lock:
        if session_id and session_id in sessions:
            sessions[session_id]["last_active"] = datetime.now(timezone.utc)
            return sessions[session_id]
    return create_session()

def set_session_cookie(response, session):
    """Attach the session cookie and header to the response."""
    response.headers['X-Session-ID'] = session["id"]
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session["id"],
        httponly=True,
        samesite="None" if IS_PRODUCTION else "Lax",
        secure=bool(IS_PRODUCTION),
        max_age=SESSION_TTL_SECONDS,
        path="/"
    )
    return response

@app.before_request
def load_session():
    if request.method == "OPTIONS":
        return
    g.session = get_session()

@app.after_request
def attach_session_cookie(response):
    if hasattr(g, "session"):
        set_session_cookie(response, g.session)
    return response

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok"}), 200

def session_cleanup_thread():
    """Remove sessions idle for more than SESSION_TTL_SECONDS."""
    while True:
        time.sleep(60)
        now = datetime.now(timezone.utc)
        expired_ids = []
        with sessions_lock:
            for sid, session in sessions.items():
                elapsed = (now - session["last_active"]).total_seconds()
                if elapsed > SESSION_TTL_SECONDS:
                    expired_ids.append(sid)
        for sid in expired_ids:
            with sessions_lock:
                session = sessions.pop(sid, None)
            if session:
                session_dir = session.get("session_dir")
                if session_dir and os.path.exists(session_dir):
                    try:
                        shutil.rmtree(session_dir)
                        print(f"[CLEANUP] Removed session {sid[:8]}", flush=True)
                    except Exception as e:
                        print(f"[CLEANUP ERROR] {sid[:8]}: {e}", flush=True)

_cleanup = threading.Thread(target=session_cleanup_thread, daemon=True)
_cleanup.name = "SessionCleanup"
_cleanup.start()

with open(SCENARIO_PATH, "r") as f:
    all_scenarios = [json.loads(line) for line in f if line.strip()]

attack_chains = {}
for log in all_scenarios:
    label = log.get("label", "generic")
    attack_chains.setdefault(label, []).append(log)

# Pool of scenarios that SPECTYR can auto-detect (appear in NOTABLE EVENTS without manual flagging)
# Map detected_by/event_source values to standardized source_type values
SOURCE_TYPE_MAP = {
    # Windows Event Logs (Security, System, Application)
    "Windows Security": "WinEventLog",
    "Windows Event Log": "WinEventLog",
    "Windows Security Log": "WinEventLog",
    "Active Directory": "WinEventLog",
    "Print Server": "WinEventLog",

    # Sysmon (separate from generic Windows Events - critical for security)
    "Sysmon": "Sysmon",

    # EDR / Endpoint Detection & Response
    "CrowdStrike": "CrowdStrike",
    "Windows Defender": "Defender",
    "EDR": "EDR",
    "Endpoint Monitor": "EDR",
    "Registry Monitor": "EDR",
    "File Integrity Monitor": "EDR",
    "OS": "EDR",

    # Network IDS (Zeek/Bro, Suricata, etc.)
    "Zeek DNS": "Zeek",
    "Zeek SSL": "Zeek",
    "Zeek Conn": "Zeek",
    "Zeek HTTP": "Zeek",
    "Zeek SMB": "Zeek",
    "Zeek LDAP": "Zeek",
    "Network Sensor": "Zeek",
    "Network Monitor": "Zeek",
    "NetworkMonitor": "Zeek",
    "Intrusion Detection System": "IDS",
    "Network Intrusion Detection System": "IDS",

    # Firewall
    "Firewall": "Firewall",

    # Web Proxy
    "Web Proxy": "Proxy",
    "WAF": "WAF",

    # VPN
    "VPN Gateway": "VPN",
    "Authentication Gateway": "VPN",

    # Email
    "Exchange": "Exchange",
    "Exchange Online": "O365",
    "Mail Gateway": "Email Gateway",

    # Cloud / Identity
    "Azure AD": "Azure AD",
    "Identity Provider": "Azure AD",
    "Cloud Identity Provider": "Azure AD",

    # DNS
    "DNS Resolver": "DNS",

    # Database
    "SQL Server": "SQL Server",
    "Database Audit Log": "Database",

    # DHCP
    "DHCP Server": "DHCP",

    # DLP
    "DLP Agent": "DLP",
    "DLP": "DLP",

    # Wireless
    "Wireless Controller": "Wireless",
    "WiFi Controller": "Wireless",

    # Performance
    "Performance Monitor": "PerfMon",

    # Other
    "Veeam Backup": "Veeam",
    "Syslog": "Syslog",
    "Infrastructure Monitor": "Infrastructure",
    "Application Performance Monitor": "APM",
    "Threat Intelligence Feed": "Threat Intel",
    "Various": "Unknown",
    "Unknown": "Unknown",
}

def get_source_type(detected_by):
    """Map detected_by value to standardized source_type"""
    return SOURCE_TYPE_MAP.get(detected_by, "Unknown")


# Triage Review educational content - shown after analyst completes a scenario
# Provides MITRE ATT&CK references, indicators, and response actions for learning
TRIAGE_REVIEWS = {
    "malware_usb": {
        "mitre": {
            "id": "T1091",
            "name": "Replication Through Removable Media",
            "tactic": "Initial Access",
            "url": "https://attack.mitre.org/techniques/T1091/"
        },
        "what_is_it": {
            "title": "USB-Based Malware",
            "description": "USB-based malware uses removable drives to deliver malicious payloads. Attackers leave infected drives in public spaces or mail them directly to targets. When plugged in, the device can auto-execute malware or trick users into running malicious files disguised as normal documents."
        },
        "response_actions": [
            "Isolate the workstation",
            "Interview the user about where the USB came from",
            "Analyze the USB contents in a sandbox",
            "Check for processes launched from the USB path",
            "Search other endpoints for similar USB activity",
            "Enforce USB device control policies"
        ]
    },
    "phishing_1": {
        "mitre": {
            "id": "T1583.001",
            "name": "Acquire Infrastructure: Domains",
            "tactic": "Resource Development",
            "url": "https://attack.mitre.org/techniques/T1583/001/"
        },
        "what_is_it": {
            "title": "Typosquatting",
            "description": "Typosquatting is when attackers register domains that look almost identical to legitimate ones to trick users into visiting them, using techniques like character substitution, missing or extra characters, wrong TLDs, or visually identical characters from different alphabets."
        },
        "response_actions": [
            "Block the domain",
            "Identify any users who visited it or entered credentials",
            "Reset credentials for any affected users",
            "Search logs for other lookalike domains from the same source",
            "Report the domain to the registrar"
        ]
    },
    "defense_evasion": {
        "mitre": {
            "id": "T1562.001",
            "name": "Impair Defenses: Disable or Modify Tools",
            "tactic": "Defense Evasion",
            "url": "https://attack.mitre.org/techniques/T1562/001/"
        },
        "what_is_it": {
            "title": "Disabling Security Tools",
            "description": "Attackers disable or modify security tools like antivirus, EDR agents, or Windows Defender to avoid detection before carrying out their main objective, whether that is deploying malware, dumping credentials, or exfiltrating data."
        },
        "response_actions": [
            "Isolate the affected host",
            "Re-enable the security tools that were disabled",
            "Preserve evidence and collect logs",
            "Search for similar activity across other endpoints",
            "Identify how the attacker gained access in the first place"
        ]
    },
    "lateral_movement_1": {
        "mitre": {
            "id": "T1046",
            "name": "Network Service Scanning",
            "tactic": "Discovery",
            "url": "https://attack.mitre.org/techniques/T1046/"
        },
        "what_is_it": {
            "title": "Network Service Scanning (Port Scan)",
            "description": "Network service scanning is when someone probes target systems to discover open ports and running services, typically using tools like Nmap. When a scanning tool is found on a standard user's workstation, it indicates either unauthorized reconnaissance or a compromised machine."
        },
        "response_actions": [
            "Investigate whether the user intentionally ran the tool or if the workstation is compromised",
            "Remove the scanning tool",
            "Search firewall logs for scan activity from the same source",
            "Check for follow-up activity like exploitation attempts or lateral movement",
            "Review segmentation rules to confirm workstations cannot reach server management ports"
        ]
    },
    "brute_force_attack": {
        "mitre": {
            "id": "T1110.001",
            "name": "Brute Force: Password Guessing",
            "tactic": "Credential Access",
            "url": "https://attack.mitre.org/techniques/T1110/001/"
        },
        "what_is_it": {
            "title": "Dictionary Attack (Password Guessing)",
            "description": "A dictionary attack is a brute force method where attackers use automated tools to rapidly cycle through a wordlist of common passwords against a single account. This differs from password spraying, which tries one password across many accounts, and credential stuffing, which reuses stolen credentials from previous breaches."
        },
        "response_actions": [
            "Lock the targeted account and reset the password",
            "Block the attacking source IP at the firewall",
            "Determine if any successful authentication occurred from the attacker's IP",
            "If compromised, investigate for lateral movement to other systems",
            "Verify MFA is enabled on the account and enforce it if not"
        ]
    },
    "phishing_link": {
        "mitre": {
            "id": "T1566.002",
            "name": "Phishing: Spearphishing Link",
            "tactic": "Initial Access",
            "url": "https://attack.mitre.org/techniques/T1566/002/"
        },
        "what_is_it": {
            "title": "Spearphishing Link (Payload Download)",
            "description": "Spearphishing with a link is when attackers send targeted emails containing URLs to malicious files instead of attaching them directly. This bypasses email security that scans attachments but may not inspect linked content. Attackers typically impersonate trusted services like DocuSign, SharePoint, or Dropbox to convince the victim to click, download, and execute the payload."
        },
        "response_actions": [
            "Isolate the affected workstation",
            "Block the phishing domain and IP",
            "Preserve the downloaded file for analysis",
            "Search email and proxy logs for other users who received the same link",
            "Check the host for post-execution activity",
            "Quarantine the original phishing email across all mailboxes"
        ]
    },
    "data_exfil_archive": {
        "mitre": {
            "id": "T1560.001",
            "name": "Archive Collected Data: Archive via Utility",
            "tactic": "Collection",
            "url": "https://attack.mitre.org/techniques/T1560/001/"
        },
        "what_is_it": {
            "title": "Data Archiving and Exfiltration to Cloud Storage",
            "description": "Data exfiltration is when stolen files are transferred out of the network. Attackers often compress and password-protect data using tools like 7-Zip before uploading it to cloud storage services like Mega.nz. The password protection prevents DLP tools from inspecting the contents, and services with anonymous accounts make the destination harder to trace."
        },
        "response_actions": [
            "Isolate the workstation to prevent further exfiltration",
            "Block the cloud storage destination",
            "Preserve the staging folder and archive for forensic analysis",
            "Inventory what data was stolen",
            "Trace where the archived files originated from",
            "Engage HR and Legal if insider threat is suspected"
        ]
    },
    "insider_staging": {
        "mitre": {
            "id": "T1074.001",
            "name": "Data Staged: Local Data Staging",
            "tactic": "Collection",
            "url": "https://attack.mitre.org/techniques/T1074/001/"
        },
        "what_is_it": {
            "title": "Insider Threat Data Staging",
            "description": "Insider threat data staging is when a trusted employee uses their legitimate access to collect and consolidate sensitive files into a centralized local folder before exfiltrating them. It is primarily detected through behavioral anomalies like bulk downloads, after-hours file activity, and access to resources outside the employee's normal job function."
        },
        "response_actions": [
            "Do not alert the employee to preserve evidence",
            "Capture a forensic snapshot of the workstation and staging folder",
            "Engage HR and Legal before any direct employee contact",
            "Verify whether the employee has a legitimate business need for the staged data",
            "Monitor for exfiltration activity such as USB connections, personal email, or cloud uploads"
        ]
    },
    "malware_ransomware": {
        "mitre": {
            "id": "T1486",
            "name": "Data Encrypted for Impact",
            "tactic": "Impact",
            "url": "https://attack.mitre.org/techniques/T1486/"
        },
        "what_is_it": {
            "title": "Ransomware File Encryption",
            "description": "Ransomware encrypts files on a victim's system and demands payment for the decryption key. It typically uses fast symmetric encryption for the files and asymmetric encryption to lock the key, meaning only the attacker can decrypt. Many variants spread across the network using stolen credentials or SMB shares to maximize damage."
        },
        "response_actions": [
            "Isolate the host immediately but do not shut it down, encryption keys may still be in memory",
            "Capture a memory dump before any remediation",
            "Identify the ransomware variant using the ransom note, file extensions, or hash lookups",
            "Trace how it was delivered",
            "Block the malicious hash across all endpoints",
            "Assess scope: what was encrypted, do clean backups exist, and was data exfiltrated before encryption"
        ]
    },
    "lateral_movement_2": {
        "mitre": {
            "id": "T1003.001",
            "name": "OS Credential Dumping: LSASS Memory",
            "tactic": "Credential Access",
            "url": "https://attack.mitre.org/techniques/T1003/001/"
        },
        "what_is_it": {
            "title": "LSASS Credential Dumping",
            "description": "LSASS is the Windows process that caches credentials for every user logged into a machine, including password hashes, Kerberos tickets, and sometimes plaintext passwords. Attackers dump LSASS memory using legitimate tools like ProcDump or Task Manager, then extract credentials offline with tools like Mimikatz. One dump on one workstation can compromise every account cached on that machine, including domain admins."
        },
        "response_actions": [
            "Isolate the workstation but do not shut it down",
            "Identify every account that was logged into that machine and treat them all as compromised",
            "Reset passwords and revoke Kerberos tickets for all affected accounts",
            "Search for lateral movement from the compromised host",
            "Scan other endpoints for dumping tools or suspicious .dmp files",
            "Escalate to incident response"
        ]
    },
    "defense_evasion_log_clearing": {
        "mitre": {
            "id": "T1070.001",
            "name": "Indicator Removal: Clear Windows Event Logs",
            "tactic": "Defense Evasion",
            "url": "https://attack.mitre.org/techniques/T1070/001/"
        },
        "what_is_it": {
            "title": "Windows Event Log Clearing",
            "description": "Attackers clear Windows event logs to destroy forensic evidence of their activity using built-in tools like wevtutil.exe. Clearing the Security log generates Event ID 1102, meaning the act of destroying evidence ironically creates its own detection artifact."
        },
        "response_actions": [
            "Isolate the host immediately as an attacker is actively covering their tracks",
            "Recover cleared logs from centralized log collection such as your SIEM or syslog server",
            "Identify who cleared the logs using the subject account in the 1102 event",
            "Search other hosts for the same account performing similar activity",
            "Escalate to incident response as log clearing is a late-stage indicator"
        ]
    },
    "insider_shadow_it": {
        "mitre": {
            "id": "T1567.002",
            "name": "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
            "tactic": "Exfiltration",
            "url": "https://attack.mitre.org/techniques/T1567/002/"
        },
        "what_is_it": {
            "title": "Shadow IT (Unauthorized Cloud Storage)",
            "description": "Shadow IT is when employees use unapproved software, cloud services, or personal devices for work without IT's knowledge. Common examples include syncing files to personal Dropbox or Google Drive, or using personal laptops and phones to access corporate data. Even without malicious intent, this puts company data in unmanaged locations with no security controls or audit trail."
        },
        "response_actions": [
            "Confirm the application or device is not on the approved list",
            "Assess the sensitivity of any data that was accessed or synced",
            "Remove the application and block the domain",
            "Work with the employee to recover corporate files from the personal account or device",
            "Document the policy violation and notify management"
        ]
    },
    "c2_dns_tunnel": {
        "mitre": {
            "id": "T1071.004",
            "name": "Application Layer Protocol: DNS",
            "tactic": "Command and Control",
            "url": "https://attack.mitre.org/techniques/T1071/004/"
        },
        "what_is_it": {
            "title": "DNS Tunneling: Covert C2 Channel",
            "description": "DNS tunneling is when malware hides command and control communication inside DNS queries by encoding data into long subdomain labels that route through normal DNS infrastructure to an attacker-controlled server. Because DNS traffic is rarely blocked or inspected, the channel operates over port 53 without triggering most security tools."
        },
        "response_actions": [
            "Isolate the host immediately as the tunnel is an active C2 channel",
            "Kill the tunneling process and preserve the binary for analysis",
            "Block the tunneling domain at the DNS server",
            "Search DNS logs for other hosts querying the same domain",
            "Investigate how the tunneling tool was delivered to the host"
        ]
    },
    "password_spray": {
        "mitre": {
            "id": "T1110.003",
            "name": "Brute Force: Password Spraying",
            "tactic": "Credential Access",
            "url": "https://attack.mitre.org/techniques/T1110/003/"
        },
        "what_is_it": {
            "title": "Password Spraying",
            "description": "Password spraying is a brute force technique where the attacker tries one or two common passwords across many accounts simultaneously, staying below lockout thresholds so no single account triggers an alert. The pattern only becomes visible when you correlate failed logins across accounts and notice the same source hitting different users in a short time window."
        },
        "response_actions": [
            "Confirm the spray pattern: same source IP targeting many accounts in a short time window",
            "Search for any successful authentication from the attacking source IP",
            "Reset passwords for all targeted accounts, prioritizing any with successful logons",
            "Determine if the source is external or internal, as an internal source indicates prior compromise",
            "Block the source IP and monitor for follow-up waves"
        ]
    },
    "c2_http": {
        "mitre": {
            "id": "T1071.001",
            "name": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control",
            "url": "https://attack.mitre.org/techniques/T1071/001/"
        },
        "what_is_it": {
            "title": "HTTPS C2 Beaconing",
            "description": "C2 beaconing is when malware on a compromised machine regularly phones home to an attacker-controlled server over HTTPS to receive commands. Because the traffic uses port 443 and looks like normal web browsing, it blends into everyday network activity. Key indicators include connections to lookalike domains, destination IPs that don't belong to the impersonated service, and regular timed intervals between connections."
        },
        "response_actions": [
            "Isolate the host immediately, the C2 channel is active",
            "Block the C2 domain and destination IP",
            "Search logs for other hosts connecting to the same domain or IP",
            "Identify which process on the workstation made the connection",
            "Trace how the malware was delivered",
            "Check for any post-compromise activity like credential theft or lateral movement"
        ]
    },
    "false_positive_pentest": {
        "what_is_it": {
            "title": "Security Awareness Training Campaign",
            "description": "Phishing simulation platforms send realistic-looking emails to test employee awareness. These generate alerts identical to real phishing — lookalike domains, credential harvesting pages, and clicked links — but originate from authorized training vendors."
        },
        "response_actions": [
            "Verify with the security awareness team if a campaign is active",
            "Check the sending domain against the approved vendor list",
            "Confirm SPF/DKIM alignment with the training platform",
            "Document as false positive and close the ticket",
            "Notify the SOC to expect similar alerts during the campaign window"
        ]
    },
    "false_positive_robocopy": {
        "what_is_it": {
            "title": "Scheduled Data Migration",
            "description": "Robocopy and similar bulk file transfer tools generate high-volume file access patterns that closely resemble data exfiltration. Legitimate IT migrations involving large outbound transfers to cloud endpoints can trigger data loss prevention and exfiltration alerts."
        },
        "response_actions": [
            "Check change management for approved migration tasks",
            "Verify the service account running the transfer is authorized",
            "Confirm the destination endpoint is an approved cloud target",
            "Validate the transfer volume against the migration scope",
            "Whitelist the scheduled task for the migration window"
        ]
    },
    "false_positive_veeam": {
        "what_is_it": {
            "title": "Backup Agent Beaconing",
            "description": "Backup agents like Veeam communicate with their management server at regular intervals, transferring large volumes of data during backup windows. This periodic outbound traffic to a fixed destination closely mimics command-and-control beaconing patterns."
        },
        "response_actions": [
            "Verify the process is a known backup agent by checking its hash and path",
            "Confirm the destination is the authorized backup server",
            "Cross-reference with the backup schedule and retention policy",
            "Check with the backup team for recent agent deployments",
            "Add the backup process and destination to the monitoring whitelist"
        ]
    },
    "false_positive_oauth": {
        "what_is_it": {
            "title": "OAuth Token Refresh Activity",
            "description": "Modern authentication using OAuth generates non-interactive sign-in events from Microsoft's global infrastructure. Token refreshes can originate from data centers in different countries, triggering impossible travel and anomalous location alerts even when the user hasn't moved."
        },
        "response_actions": [
            "Check if the sign-ins are non-interactive token refreshes versus user logins",
            "Verify the application is a known first-party service like Exchange Online",
            "Confirm with the identity team if modern auth was recently enabled",
            "Review the user's interactive sign-in history for actual anomalies",
            "Tune the impossible travel policy to exclude non-interactive sign-ins"
        ]
    },
    "false_positive_ssl_inspection": {
        "what_is_it": {
            "title": "SSL Inspection Policy Expansion",
            "description": "When a corporate proxy expands its SSL inspection scope to new domains, endpoints may generate repeated TLS handshake failures while certificate trust is established. The retry pattern with consistent intervals to fixed destinations closely resembles command-and-control communication."
        },
        "response_actions": [
            "Check with the network team for recent proxy policy changes",
            "Verify the destination domains are legitimate Microsoft 365 endpoints",
            "Confirm the TLS failures correlate with the inspection policy rollout timeline",
            "Push updated root certificates to affected workstations",
            "Monitor for resolution as endpoints pick up the new trust chain"
        ]
    }
}

# Level-based campaign progression with randomized category pools
# Each level: 1 threat randomly selected from pool of 3 categories
CAMPAIGN_LEVELS = [
    # === LEVEL 1 ===
    {
        "level": 1,
        "category_pool": ["Malware", "Phishing", "Defense Evasion", "False Positive"],
        "scenarios": {
            "Malware": {
                "scenario_label": "malware_usb",
                "ticket_title": "Suspicious Process from Removable Media",
                "storyline": "A USB drive was discovered in the parking lot by an employee this morning. Against policy, they connected it to their workstation to identify the owner. Minutes later, the endpoint began generating alerts. The activity did not stop at execution.",
            },
            "Phishing": {
                "scenario_label": "phishing_1",
                "ticket_title": "Microsoft 365 Account Login from Unusual Location",
                "storyline": "An employee received a Microsoft 365 password reset email and clicked the link. The page looked like a normal Microsoft sign-in. The proxy logged the connection but did not block it. Shortly after, account activity was detected from an unexpected location.",
            },
            "Defense Evasion": {
                "scenario_label": "defense_evasion",
                "ticket_title": "Endpoint Protection Disabled on Workstation",
                "storyline": "Unusual activity was detected on a workstation outside of business hours. No user was logged in at the time. Review the logs and determine the scope of what occurred.",
            },
            "False Positive": {
                "scenario_label": "false_positive_pentest",
                "ticket_title": "Suspicious Password Reset Email Reported",
                "storyline": "An employee reported receiving a password reset email they did not request. The email contained a link to what appears to be a lookalike domain. Proxy logs show the user clicked the link. SPF checks passed. The security awareness team recently onboarded a new training vendor.",
            }
        }
    },
    # === LEVEL 2 ===
    {
        "level": 2,
        "category_pool": ["Lateral Movement", "Command & Control", "Brute Force", "False Positive"],
        "scenarios": {
            "Lateral Movement": {
                "scenario_label": "lateral_movement_1",
                "ticket_title": "Internal Port Scan from Workstation",
                "storyline": "Unexpected network activity was detected originating from an internal workstation with no scheduled maintenance or administrative tasks. The firewall logged multiple connection attempts to an internal server in rapid succession.",
            },
            "Command & Control": {
                "scenario_label": "c2_http",
                "ticket_title": "Unusual HTTPS Traffic to Unrecognized External Domain",
                "storyline": "An endpoint began generating repeated outbound HTTPS connections to an external domain not present on any internal allowlist. The connections appear to follow a regular interval.",
            },
            "Brute Force": {
                "scenario_label": "brute_force_attack",
                "ticket_title": "Account Locked After External Login Failures",
                "storyline": "The Domain Controller began logging unusual authentication activity from an external source outside of business hours. The targeted account has since been locked out.",
            },
            "False Positive": {
                "scenario_label": "false_positive_robocopy",
                "ticket_title": "Large Outbound Transfer to OneDrive",
                "storyline": "A scheduled task executed on a workstation under a service account and began copying a large volume of files from an internal file share. Over 2 GB of data was transferred outbound to a cloud endpoint. IT operations has a standing migration project scheduled this quarter.",
            }
        }
    },
    # === LEVEL 3 ===
    {
        "level": 3,
        "category_pool": ["Phishing", "Data Exfiltration", "Insider Threat", "False Positive"],
        "scenarios": {
            "Phishing": {
                "scenario_label": "phishing_link",
                "ticket_title": "Suspicious Email Reported by Employee",
                "storyline": "An employee contacted the help desk after interacting with an email they now believe may have been fraudulent. The email appeared to come from a trusted third-party service. Endpoint and proxy logs show activity on the workstation following the interaction.",
            },
            "Data Exfiltration": {
                "scenario_label": "data_exfil_archive",
                "ticket_title": "Encrypted Archive Followed by External Upload",
                "storyline": "A compression utility was executed on an endpoint outside of business hours. No software deployment or IT task was scheduled for this host. Shortly after, outbound connections were established to an external file hosting service.",
            },
            "Insider Threat": {
                "scenario_label": "insider_staging",
                "ticket_title": "Unauthorized Access to Financial Records",
                "storyline": "A user account accessed a file share containing sensitive financial records outside of their normal role. A document was copied locally before an outbound connection was established to a personal cloud storage service. No transfer approval or business justification exists for this activity.",
            },
            "False Positive": {
                "scenario_label": "false_positive_veeam",
                "ticket_title": "Beaconing-Like Pattern from Workstation",
                "storyline": "An endpoint began generating repeated outbound connections to an internal server at regular intervals outside of business hours. The process runs under SYSTEM and has transferred over 1.75 GB of data. The backup team recently deployed Veeam agents to all workstations as part of the endpoint protection initiative.",
            }
        }
    },
    # === LEVEL 4 ===
    {
        "level": 4,
        "category_pool": ["Malware", "Lateral Movement", "Defense Evasion", "False Positive"],
        "scenarios": {
            "Malware": {
                "scenario_label": "malware_ransomware",
                "ticket_title": "Mass File Encryption with Ransom Note",
                "storyline": "An employee discovered a text file on their desktop demanding Bitcoin payment to restore access to their documents. Multiple files on the workstation appear to have been renamed with an unfamiliar extension. The employee did not make these changes and no maintenance was scheduled.",
            },
            "Lateral Movement": {
                "scenario_label": "lateral_movement_2",
                "ticket_title": "Suspicious Process Accessing System Memory",
                "storyline": "A workstation generated alerts indicating a process accessed sensitive system memory. A second tool was later executed from a temporary directory. Shortly after, a network authentication was recorded on an internal server from the same host.",
            },
            "Defense Evasion": {
                "scenario_label": "defense_evasion_log_clearing",
                "ticket_title": "Event Logs Cleared on Workstation",
                "storyline": "An automated monitoring alert fired when a workstation's event logs were unexpectedly emptied. No maintenance was scheduled. Investigate what activity preceded the clearing.",
            },
            "False Positive": {
                "scenario_label": "false_positive_oauth",
                "ticket_title": "Impossible Travel Sign-In Alert",
                "storyline": "Entra ID Protection flagged a user account for anomalous token activity originating from Dublin, Ireland. The user is based in Miami and has not reported any travel. Multiple non-interactive sign-ins were recorded against Office 365 Exchange Online. The identity team recently migrated all endpoints to modern authentication with OAuth refresh tokens.",
            }
        }
    },
    # === LEVEL 5 ===
    {
        "level": 5,
        "category_pool": ["Insider Threat", "Brute Force", "Command & Control", "False Positive"],
        "scenarios": {
            "Insider Threat": {
                "scenario_label": "insider_shadow_it",
                "ticket_title": "Possible Data Leak via Unauthorized Application",
                "storyline": "A workstation launched an application not on the approved software list. Shortly after, multiple sensitive documents were moved into a folder associated with the application, and the proxy logged an upload to an external cloud storage provider. The employee has not submitted a software installation request.",
            },
            "Brute Force": {
                "scenario_label": "password_spray",
                "ticket_title": "Multiple Account Logon Failures from Single Source",
                "storyline": "The Domain Controller logged a cluster of failed logon attempts from the same source. Each attempt targets a different user account in quick succession using NTLM authentication. One account then logged on successfully. None of the targeted accounts have reported issues.",
            },
            "Command & Control": {
                "scenario_label": "c2_dns_tunnel",
                "ticket_title": "DNS Queries to Unrecognized Domain",
                "storyline": "The DNS server logged repeated TXT queries from a single workstation to subdomains of a domain not on any internal or approved service list. The subdomain labels appear non-standard. Shortly before the queries began, the workstation launched an unfamiliar process from the Downloads folder.",
            },
            "False Positive": {
                "scenario_label": "false_positive_ssl_inspection",
                "ticket_title": "Repeated TLS Failures from Multiple Workstations",
                "storyline": "Multiple workstations are generating repeated failed TLS connections to Microsoft 365 endpoints. The connection pattern resembles command-and-control beaconing with consistent retry intervals. The network team recently expanded the corporate proxy's SSL inspection policy to cover additional domains.",
            }
        }
    }
]


def select_level_scenarios(level_config):
    """
    Randomly select ONE category from the level's pool of 3.
    Returns selected_option dict with scenario details and metadata.
    """
    # Pick one category randomly from the pool
    selected_category = random.choice(level_config["category_pool"])

    # Get the scenario for that category
    scenario = level_config["scenarios"][selected_category]

    return {
        "scenario_label": scenario["scenario_label"],
        "category": selected_category,
        "ticket_title": scenario["ticket_title"],
        "storyline": scenario["storyline"]
    }


# Realistic corporate network configuration
CORP_DOMAIN = "acme.local"
CORP_SUBNET = "10.0.1"

# Employees with realistic names, departments, and email (firstname.lastname@acme.com)
# ~45 users for 78 workstations (some users have multiple devices: laptop + desktop)
EMPLOYEES = [
    # IT Department (8 users)
    {"name": "jsmith", "full_name": "John Smith", "email": "john.smith@acme.com", "dept": "IT", "workstation": "ACME-WS01", "ip": "10.0.1.1"},
    {"name": "rgarcia", "full_name": "Robert Garcia", "email": "robert.garcia@acme.com", "dept": "IT", "workstation": "ACME-WS02", "ip": "10.0.1.2"},
    {"name": "astewart", "full_name": "Anthony Stewart", "email": "anthony.stewart@acme.com", "dept": "IT", "workstation": "ACME-WS03", "ip": "10.0.1.3"},
    {"name": "mchen", "full_name": "Michelle Chen", "email": "michelle.chen@acme.com", "dept": "IT", "workstation": "ACME-WS04", "ip": "10.0.1.4"},
    {"name": "dpark", "full_name": "Daniel Park", "email": "daniel.park@acme.com", "dept": "IT", "workstation": "ACME-WS05", "ip": "10.0.1.5"},
    {"name": "lwright", "full_name": "Laura Wright", "email": "laura.wright@acme.com", "dept": "IT", "workstation": "ACME-WS06", "ip": "10.0.1.6"},
    {"name": "jperez", "full_name": "Jose Perez", "email": "jose.perez@acme.com", "dept": "IT", "workstation": "ACME-WS07", "ip": "10.0.1.7"},
    {"name": "alee", "full_name": "Amanda Lee", "email": "amanda.lee@acme.com", "dept": "IT", "workstation": "ACME-WS08", "ip": "10.0.1.8"},
    # HR Department (5 users)
    {"name": "mjohnson", "full_name": "Maria Johnson", "email": "maria.johnson@acme.com", "dept": "HR", "workstation": "ACME-WS09", "ip": "10.0.1.9"},
    {"name": "gmorales", "full_name": "Grace Morales", "email": "grace.morales@acme.com", "dept": "HR", "workstation": "ACME-WS10", "ip": "10.0.1.10"},
    {"name": "ewalker", "full_name": "Emily Walker", "email": "emily.walker@acme.com", "dept": "HR", "workstation": "ACME-WS11", "ip": "10.0.1.11"},
    {"name": "nkhan", "full_name": "Nadia Khan", "email": "nadia.khan@acme.com", "dept": "HR", "workstation": "ACME-WS12", "ip": "10.0.1.12"},
    {"name": "tharris", "full_name": "Tyler Harris", "email": "tyler.harris@acme.com", "dept": "HR", "workstation": "ACME-WS13", "ip": "10.0.1.13"},
    # Finance Department (6 users)
    {"name": "bwilliams", "full_name": "Brian Williams", "email": "brian.williams@acme.com", "dept": "Finance", "workstation": "ACME-WS14", "ip": "10.0.1.14"},
    {"name": "spatel", "full_name": "Sarah Patel", "email": "sarah.patel@acme.com", "dept": "Finance", "workstation": "ACME-WS15", "ip": "10.0.1.15"},
    {"name": "slopez", "full_name": "Sophia Lopez", "email": "sophia.lopez@acme.com", "dept": "Finance", "workstation": "ACME-WS16", "ip": "10.0.1.16"},
    {"name": "rhall", "full_name": "Ryan Hall", "email": "ryan.hall@acme.com", "dept": "Finance", "workstation": "ACME-WS17", "ip": "10.0.1.17"},
    {"name": "kscott", "full_name": "Katherine Scott", "email": "katherine.scott@acme.com", "dept": "Finance", "workstation": "ACME-WS18", "ip": "10.0.1.18"},
    {"name": "jnelson", "full_name": "James Nelson", "email": "james.nelson@acme.com", "dept": "Finance", "workstation": "ACME-WS19", "ip": "10.0.1.19"},
    # Engineering Department (10 users)
    {"name": "achen", "full_name": "Alice Chen", "email": "alice.chen@acme.com", "dept": "Engineering", "workstation": "ACME-WS20", "ip": "10.0.1.20"},
    {"name": "twong", "full_name": "Thomas Wong", "email": "thomas.wong@acme.com", "dept": "Engineering", "workstation": "ACME-WS21", "ip": "10.0.1.21"},
    {"name": "rnguyen", "full_name": "Rachel Nguyen", "email": "rachel.nguyen@acme.com", "dept": "Engineering", "workstation": "ACME-WS22", "ip": "10.0.1.22"},
    {"name": "jkim", "full_name": "Jennifer Kim", "email": "jennifer.kim@acme.com", "dept": "Engineering", "workstation": "ACME-WS23", "ip": "10.0.1.23"},
    {"name": "mramirez", "full_name": "Marcus Ramirez", "email": "marcus.ramirez@acme.com", "dept": "Engineering", "workstation": "ACME-WS24", "ip": "10.0.1.24"},
    {"name": "ssharma", "full_name": "Sanjay Sharma", "email": "sanjay.sharma@acme.com", "dept": "Engineering", "workstation": "ACME-WS25", "ip": "10.0.1.25"},
    {"name": "ecarter", "full_name": "Emma Carter", "email": "emma.carter@acme.com", "dept": "Engineering", "workstation": "ACME-WS26", "ip": "10.0.1.26"},
    {"name": "owilson", "full_name": "Oliver Wilson", "email": "oliver.wilson@acme.com", "dept": "Engineering", "workstation": "ACME-WS27", "ip": "10.0.1.27"},
    {"name": "hzhang", "full_name": "Henry Zhang", "email": "henry.zhang@acme.com", "dept": "Engineering", "workstation": "ACME-WS28", "ip": "10.0.1.28"},
    {"name": "vsingh", "full_name": "Vikram Singh", "email": "vikram.singh@acme.com", "dept": "Engineering", "workstation": "ACME-WS29", "ip": "10.0.1.29"},
    # Sales Department (6 users)
    {"name": "dlee", "full_name": "David Lee", "email": "david.lee@acme.com", "dept": "Sales", "workstation": "ACME-WS30", "ip": "10.0.1.30"},
    {"name": "bwilson", "full_name": "Brandon Wilson", "email": "brandon.wilson@acme.com", "dept": "Sales", "workstation": "ACME-WS31", "ip": "10.0.1.31"},
    {"name": "crodriguez", "full_name": "Carlos Rodriguez", "email": "carlos.rodriguez@acme.com", "dept": "Sales", "workstation": "ACME-WS32", "ip": "10.0.1.32"},
    {"name": "jadams", "full_name": "Jessica Adams", "email": "jessica.adams@acme.com", "dept": "Sales", "workstation": "ACME-WS33", "ip": "10.0.1.33"},
    {"name": "mturner", "full_name": "Matthew Turner", "email": "matthew.turner@acme.com", "dept": "Sales", "workstation": "ACME-WS34", "ip": "10.0.1.34"},
    {"name": "lgreen", "full_name": "Lauren Green", "email": "lauren.green@acme.com", "dept": "Sales", "workstation": "ACME-WS35", "ip": "10.0.1.35"},
    # Marketing Department (5 users)
    {"name": "kbrown", "full_name": "Karen Brown", "email": "karen.brown@acme.com", "dept": "Marketing", "workstation": "ACME-WS36", "ip": "10.0.1.36"},
    {"name": "wcho", "full_name": "Wendy Cho", "email": "wendy.cho@acme.com", "dept": "Marketing", "workstation": "ACME-WS37", "ip": "10.0.1.37"},
    {"name": "ahill", "full_name": "Andrew Hill", "email": "andrew.hill@acme.com", "dept": "Marketing", "workstation": "ACME-WS38", "ip": "10.0.1.38"},
    {"name": "srobinson", "full_name": "Stephanie Robinson", "email": "stephanie.robinson@acme.com", "dept": "Marketing", "workstation": "ACME-WS39", "ip": "10.0.1.39"},
    {"name": "nflores", "full_name": "Nathan Flores", "email": "nathan.flores@acme.com", "dept": "Marketing", "workstation": "ACME-WS40", "ip": "10.0.1.40"},
    # Legal Department (3 users)
    {"name": "lmartinez", "full_name": "Lisa Martinez", "email": "lisa.martinez@acme.com", "dept": "Legal", "workstation": "ACME-WS41", "ip": "10.0.1.41"},
    {"name": "mthompson", "full_name": "Michael Thompson", "email": "michael.thompson@acme.com", "dept": "Legal", "workstation": "ACME-WS42", "ip": "10.0.1.42"},
    {"name": "cwhite", "full_name": "Christine White", "email": "christine.white@acme.com", "dept": "Legal", "workstation": "ACME-WS43", "ip": "10.0.1.43"},
    # Operations (2 users)
    {"name": "pbaker", "full_name": "Patrick Baker", "email": "patrick.baker@acme.com", "dept": "Operations", "workstation": "ACME-WS44", "ip": "10.0.1.44"},
    {"name": "rclark", "full_name": "Rebecca Clark", "email": "rebecca.clark@acme.com", "dept": "Operations", "workstation": "ACME-WS45", "ip": "10.0.1.45"},
]

# Internal servers (10.0.1.200+ range)
SERVERS = {
    "dc": {"hostname": "ACME-SVR01", "ip": "10.0.1.200", "desc": "Domain Controller"},
    "file": {"hostname": "ACME-SVR02", "ip": "10.0.1.201", "desc": "File Server"},
    "dns": {"hostname": "ACME-SVR03", "ip": "10.0.1.202", "desc": "DNS Server"},
    "print": {"hostname": "ACME-SVR04", "ip": "10.0.1.203", "desc": "Print Server"},
    "web": {"hostname": "ACME-SVR05", "ip": "10.0.1.204", "desc": "Web Server"},
    "proxy": {"hostname": "ACME-SVR06", "ip": "10.0.1.205", "desc": "Proxy Server"},
}

# Network firewalls
FIREWALLS = {
    "perimeter": {"hostname": "ACME-FW01", "ip": "10.0.1.1", "desc": "Perimeter Firewall"},
}

# Legitimate external domains employees would access
LEGIT_EXTERNAL_DOMAINS = [
    "microsoft.com", "office365.com", "outlook.com", "sharepoint.com",
    "google.com", "googleapis.com", "gstatic.com",
    "slack.com", "zoom.us", "teams.microsoft.com",
    "github.com", "gitlab.com", "stackoverflow.com",
    "salesforce.com", "hubspot.com", "zendesk.com",
    "aws.amazon.com", "azure.microsoft.com", "cloudflare.com",
    "linkedin.com", "indeed.com",
    "dropbox.com", "box.com", "onedrive.live.com",
    "adobe.com", "figma.com", "canva.com",
    "okta.com", "duo.com", "1password.com",
]

# Common file shares and paths
FILE_PATHS = [
    "\\\\ACME-SVR02\\Shared\\Documents\\Q4_Report.xlsx",
    "\\\\ACME-SVR02\\Shared\\Marketing\\Campaign_2024.pptx",
    "\\\\ACME-SVR02\\Finance\\Budgets\\Annual_Budget.xlsx",
    "\\\\ACME-SVR02\\HR\\Policies\\Employee_Handbook.pdf",
    "\\\\ACME-SVR02\\Engineering\\Specs\\Architecture_v2.docx",
    "\\\\ACME-SVR02\\Shared\\Templates\\Invoice_Template.docx",
    "\\\\ACME-SVR02\\IT\\Documentation\\Network_Diagram.vsd",
    "\\\\ACME-SVR02\\Legal\\Contracts\\Vendor_Agreement.pdf",
    "\\\\ACME-SVR02\\Sales\\Proposals\\Client_Proposal.pptx",
    "\\\\ACME-SVR02\\Shared\\Photos\\Company_Event.jpg",
]

# =============================================================================
# NORMAL TRAFFIC TEMPLATES - 100 realistic log templates from 5 sources
# Placeholders: {src_ip}, {hostname}, {username}, {user_domain}, {user_fullname},
#               {user_email}, {dns_server}, {file_server}, {dc_server}, {print_server}
# =============================================================================
NORMAL_TRAFFIC_TEMPLATES = [
    # =========================================================================
    # DNS LOGS (20 events) - Windows DNS Server Analytical Logs
    # =========================================================================
    {
        "event_type": "QUERY",
        "source_type": "DNS",
        "source_ip": "{src_ip}",
        "message": "DNS query received for www.google.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "52314", "dest_port": "53", "transport": "udp", "query": "www.google.com", "query_type": "A", "message_type": "QUERY", "reply_code": "NOERROR", "dvc": "ACME-SVR03"}
    },
    {
        "event_type": "ALLOWED",
        "source_type": "DNS",
        "source_ip": "{dns_server}",
        "message": "DNS response sent for www.google.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "52315", "dest_port": 53, "transport": "udp", "query": "www.google.com", "query_type": "A", "message_type": "Response", "reply_code": "NoError", "answer": "142.250.191.46", "dvc": "ACME-FW01"}
    },
    {
        "event_type": "QUERY",
        "source_type": "DNS",
        "source_ip": "{src_ip}",
        "message": "DNS query received for outlook.office365.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "52418", "dest_port": "53", "transport": "udp", "query": "outlook.office365.com", "query_type": "A", "message_type": "QUERY", "reply_code": "NOERROR", "dvc": "ACME-SVR03"}
    },
    {
        "event_type": "ALLOWED",
        "source_type": "DNS",
        "source_ip": "{dns_server}",
        "message": "DNS response sent for outlook.office365.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "52419", "dest_port": 53, "transport": "udp", "query": "outlook.office365.com", "query_type": "A", "message_type": "Response", "reply_code": "NoError", "answer": "52.96.166.24", "dvc": "ACME-FW01"}
    },
    {
        "event_type": "QUERY",
        "source_type": "DNS",
        "source_ip": "{src_ip}",
        "message": "DNS query received for www.google.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "52512", "dest_port": "53", "transport": "udp", "query": "www.google.com", "query_type": "AAAA", "message_type": "QUERY", "reply_code": "NOERROR", "dvc": "ACME-SVR03"}
    },
    {
        "event_type": "ALLOWED",
        "source_type": "DNS",
        "source_ip": "{dns_server}",
        "message": "DNS response sent for www.google.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "52513", "dest_port": 53, "transport": "udp", "query": "www.google.com", "query_type": "AAAA", "message_type": "Response", "reply_code": "NoError", "answer": "2607:f8b0:4004:800::2004", "dvc": "ACME-FW01"}
    },
    {
        "event_type": "QUERY",
        "source_type": "DNS",
        "source_ip": "{src_ip}",
        "message": "DNS query received for teams.microsoft.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "52620", "dest_port": "53", "transport": "udp", "query": "teams.microsoft.com", "query_type": "A", "message_type": "QUERY", "reply_code": "NOERROR", "dvc": "ACME-SVR03"}
    },
    {
        "event_type": "ALLOWED",
        "source_type": "DNS",
        "source_ip": "{dns_server}",
        "message": "DNS response sent for teams.microsoft.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "52621", "dest_port": 53, "transport": "udp", "query": "teams.microsoft.com", "query_type": "A", "message_type": "Response", "reply_code": "NoError", "answer": "13.107.42.16", "dvc": "ACME-FW01"}
    },
    {
        "event_type": "QUERY",
        "source_type": "DNS",
        "source_ip": "{src_ip}",
        "message": "DNS query received for slack.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "53100", "dest_port": "53", "transport": "udp", "query": "slack.com", "query_type": "A", "message_type": "QUERY", "reply_code": "NOERROR", "dvc": "ACME-SVR03"}
    },
    {
        "event_type": "ALLOWED",
        "source_type": "DNS",
        "source_ip": "{dns_server}",
        "message": "DNS response sent for slack.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "53101", "dest_port": 53, "transport": "udp", "query": "slack.com", "query_type": "A", "message_type": "Response", "reply_code": "NoError", "answer": "99.181.64.71", "dvc": "ACME-FW01"}
    },
    {
        "event_type": "QUERY",
        "source_type": "DNS",
        "source_ip": "{src_ip}",
        "message": "DNS query received for github.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "53200", "dest_port": "53", "transport": "udp", "query": "github.com", "query_type": "A", "message_type": "QUERY", "reply_code": "NOERROR", "dvc": "ACME-SVR03"}
    },
    {
        "event_type": "ALLOWED",
        "source_type": "DNS",
        "source_ip": "{dns_server}",
        "message": "DNS response sent for github.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "53201", "dest_port": 53, "transport": "udp", "query": "github.com", "query_type": "A", "message_type": "Response", "reply_code": "NoError", "answer": "140.82.112.4", "dvc": "ACME-FW01"}
    },
    {
        "event_type": "QUERY",
        "source_type": "DNS",
        "source_ip": "{src_ip}",
        "message": "DNS query received for login.microsoftonline.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "53300", "dest_port": "53", "transport": "udp", "query": "login.microsoftonline.com", "query_type": "A", "message_type": "QUERY", "reply_code": "NOERROR", "dvc": "ACME-SVR03"}
    },
    {
        "event_type": "ALLOWED",
        "source_type": "DNS",
        "source_ip": "{dns_server}",
        "message": "DNS response sent for _dmarc.google.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "53301", "dest_port": 53, "transport": "udp", "query": "_dmarc.google.com", "query_type": "TXT", "message_type": "Response", "reply_code": "NoError", "answer": "v=DMARC1; p=reject...", "dvc": "ACME-FW01"}
    },
    {
        "event_type": "QUERY",
        "source_type": "DNS",
        "source_ip": "{src_ip}",
        "message": "DNS query received for _ldap._tcp.acme.local.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "53400", "dest_port": "53", "transport": "udp", "query": "_ldap._tcp.acme.local", "query_type": "SRV", "message_type": "QUERY", "reply_code": "NOERROR", "dvc": "ACME-SVR03"}
    },
    {
        "event_type": "ALLOWED",
        "source_type": "DNS",
        "source_ip": "{dns_server}",
        "message": "DNS response sent for _ldap._tcp.acme.local.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "53401", "dest_port": 53, "transport": "udp", "query": "_ldap._tcp.acme.local", "query_type": "SRV", "message_type": "Response", "reply_code": "NoError", "answer": "ACME-SVR01.acme.local", "dvc": "ACME-FW01"}
    },
    {
        "event_type": "QUERY",
        "source_type": "DNS",
        "source_ip": "{src_ip}",
        "message": "DNS query received for 200.1.0.10.in-addr.arpa.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "53500", "dest_port": "53", "transport": "udp", "query": "200.1.0.10.in-addr.arpa", "query_type": "PTR", "message_type": "QUERY", "reply_code": "NOERROR", "dvc": "ACME-SVR03"}
    },
    {
        "event_type": "ALLOWED",
        "source_type": "DNS",
        "source_ip": "{dns_server}",
        "message": "DNS response sent for 200.1.0.10.in-addr.arpa.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "53501", "dest_port": 53, "transport": "udp", "query": "200.1.0.10.in-addr.arpa", "query_type": "PTR", "message_type": "Response", "reply_code": "NoError", "answer": "ACME-SVR01.acme.local", "dvc": "ACME-FW01"}
    },
    {
        "event_type": "QUERY",
        "source_type": "DNS",
        "source_ip": "{src_ip}",
        "message": "DNS query received for wpad.acme.local.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "53700", "dest_port": "53", "transport": "udp", "query": "wpad.acme.local", "query_type": "A", "message_type": "QUERY", "reply_code": "NOERROR", "dvc": "ACME-SVR03"}
    },
    {
        "event_type": "NXDOMAIN",
        "source_type": "DNS",
        "source_ip": "{dns_server}",
        "message": "DNS query failed for wpad.acme.local.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "54891", "dest_port": 53, "transport": "udp", "query": "wpad.acme.local", "query_type": "A", "message_type": "Response", "reply_code": "NXDomain", "dvc": "ACME-FW01"}
    },
    {
        "event_type": "ALLOWED",
        "source_type": "DNS",
        "source_ip": "{dns_server}",
        "message": "DNS AAAA response sent for www.google.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "53124", "dest_port": 53, "transport": "udp", "query": "www.google.com", "query_type": "AAAA", "message_type": "Response", "reply_code": "NoError", "answer": "2607:f8b0:4004:c08::6a", "dvc": "ACME-FW01"}
    },
    {
        "event_type": "ALLOWED",
        "source_type": "DNS",
        "source_ip": "{dns_server}",
        "message": "DNS AAAA response sent for outlook.office365.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "53892", "dest_port": 53, "transport": "udp", "query": "outlook.office365.com", "query_type": "AAAA", "message_type": "Response", "reply_code": "NoError", "answer": "2603:1006:1400:e::2", "dvc": "ACME-FW01"}
    },
    {
        "event_type": "ALLOWED",
        "source_type": "DNS",
        "source_ip": "{dns_server}",
        "message": "DNS AAAA response sent for github.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "54683", "dest_port": 53, "transport": "udp", "query": "github.com", "query_type": "AAAA", "message_type": "Response", "reply_code": "NoError", "answer": "2606:50c0:8000::154", "dvc": "ACME-FW01"}
    },
    {
        "event_type": "NXDOMAIN",
        "source_type": "DNS",
        "source_ip": "{dns_server}",
        "message": "DNS AAAA query failed for stackoverflow.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "54217", "dest_port": 53, "transport": "udp", "query": "stackoverflow.com", "query_type": "AAAA", "message_type": "Response", "reply_code": "NXDomain", "dvc": "ACME-FW01"}
    },
    {
        "event_type": "NXDOMAIN",
        "source_type": "DNS",
        "source_ip": "{dns_server}",
        "message": "DNS AAAA query failed for acme-print01.acme.local.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "55029", "dest_port": 53, "transport": "udp", "query": "acme-print01.acme.local", "query_type": "AAAA", "message_type": "Response", "reply_code": "NXDomain", "dvc": "ACME-FW01"}
    },
    {
        "event_type": "ALLOWED",
        "source_type": "DNS",
        "source_ip": "{dns_server}",
        "message": "DNS SRV response sent for _ldap._tcp.acme.local.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "55471", "dest_port": 53, "transport": "udp", "query": "_ldap._tcp.acme.local", "query_type": "SRV", "message_type": "Response", "reply_code": "NoError", "answer": "0 100 389 acme-svr01.acme.local", "dvc": "ACME-FW01"}
    },
    {
        "event_type": "ALLOWED",
        "source_type": "DNS",
        "source_ip": "{dns_server}",
        "message": "DNS SRV response sent for _kerberos._tcp.acme.local.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "55892", "dest_port": 53, "transport": "udp", "query": "_kerberos._tcp.acme.local", "query_type": "SRV", "message_type": "Response", "reply_code": "NoError", "answer": "0 100 88 acme-svr01.acme.local", "dvc": "ACME-FW01"}
    },
    {
        "event_type": "ALLOWED",
        "source_type": "DNS",
        "source_ip": "{dns_server}",
        "message": "DNS SRV response sent for _ldap._tcp.dc._msdcs.acme.local.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "56218", "dest_port": 53, "transport": "udp", "query": "_ldap._tcp.dc._msdcs.acme.local", "query_type": "SRV", "message_type": "Response", "reply_code": "NoError", "answer": "0 100 389 acme-svr01.acme.local", "dvc": "ACME-FW01"}
    },
    {
        "event_type": "ALLOWED",
        "source_type": "DNS",
        "source_ip": "{dns_server}",
        "message": "DNS PTR response sent for 200.1.0.10.in-addr.arpa.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "56541", "dest_port": 53, "transport": "udp", "query": "200.1.0.10.in-addr.arpa", "query_type": "PTR", "message_type": "Response", "reply_code": "NoError", "answer": "acme-svr01.acme.local", "dvc": "ACME-FW01"}
    },
    {
        "event_type": "ALLOWED",
        "source_type": "DNS",
        "source_ip": "{dns_server}",
        "message": "DNS PTR response sent for 201.1.0.10.in-addr.arpa.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "56892", "dest_port": 53, "transport": "udp", "query": "201.1.0.10.in-addr.arpa", "query_type": "PTR", "message_type": "Response", "reply_code": "NoError", "answer": "acme-svr02.acme.local", "dvc": "ACME-FW01"}
    },
    # =========================================================================
    # FIREWALL LOGS (20 events) - Generic firewall syslog format
    # =========================================================================
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Outbound DNS request allowed to internal DNS server.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "49152", "dest_port": "53", "transport": "udp", "action": "allow", "app": "dns", "dvc": "ACME-FW01", "rule": "dns_outbound"}
    },
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Outbound HTTPS request allowed to google.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "142.250.191.46", "src_port": "49200", "dest_port": "443", "transport": "tcp", "action": "allow", "app": "ssl", "dvc": "ACME-FW01", "rule": "https_outbound"}
    },
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Outbound HTTPS request allowed to outlook.office365.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "52.96.166.24", "src_port": "49215", "dest_port": "443", "transport": "tcp", "action": "allow", "app": "ssl", "dvc": "ACME-FW01", "rule": "https_outbound"}
    },
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Internal SMB request allowed to file server.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{file_server}", "src_port": "49300", "dest_port": "445", "transport": "tcp", "action": "allow", "app": "microsoft-ds", "dvc": "ACME-FW01", "rule": "smb_internal"}
    },
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Internal print request allowed to print server.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{print_server}", "src_port": "49350", "dest_port": "9100", "transport": "tcp", "action": "allow", "app": "raw-printing", "dvc": "ACME-FW01", "rule": "print_internal"}
    },
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Outbound HTTPS request allowed to teams.microsoft.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "13.107.42.16", "src_port": "49400", "dest_port": "443", "transport": "tcp", "action": "allow", "app": "ssl", "dvc": "ACME-FW01", "rule": "https_outbound"}
    },
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Outbound DNS request allowed to internal DNS server.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "49500", "dest_port": "53", "transport": "udp", "action": "allow", "app": "dns", "dvc": "ACME-FW01", "rule": "dns_outbound"}
    },
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Outbound HTTPS request allowed to youtube.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "208.65.153.238", "src_port": "49550", "dest_port": "443", "transport": "tcp", "action": "allow", "app": "ssl", "dvc": "ACME-FW01", "rule": "https_outbound"}
    },
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{file_server}",
        "message": "Internal SMB response from file server.",
        "key_value_pairs": {"src_ip": "{file_server}", "dst_ip": "{src_ip}", "src_port": "49600", "dest_port": "445", "transport": "tcp", "action": "allow", "app": "microsoft-ds", "dvc": "ACME-FW01", "rule": "smb_internal"}
    },
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Outbound HTTPS request allowed to slack.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "99.181.64.71", "src_port": "49700", "dest_port": "443", "transport": "tcp", "action": "allow", "app": "ssl", "dvc": "ACME-FW01", "rule": "https_outbound"}
    },
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Outbound HTTPS request allowed to sharepoint.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "13.107.136.9", "src_port": "49750", "dest_port": "443", "transport": "tcp", "action": "allow", "app": "ssl", "dvc": "ACME-FW01", "rule": "https_outbound"}
    },
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{dns_server}",
        "message": "Outbound NTP request allowed to time.nist.gov.",
        "key_value_pairs": {"src_ip": "{dns_server}", "dst_ip": "129.6.15.28", "src_port": "49800", "dest_port": "123", "transport": "udp", "action": "allow", "app": "ntp", "dvc": "ACME-FW01", "rule": "ntp_outbound"}
    },
    {
        "event_type": "DENY",
        "source_type": "Firewall",
        "source_ip": "203.0.113.50",
        "message": "Inbound SSH request denied from external IP.",
        "key_value_pairs": {"src_ip": "203.0.113.50", "dst_ip": "{dc_server}", "src_port": "45123", "dest_port": "22", "transport": "tcp", "action": "deny", "app": "ssh", "dvc": "ACME-FW01", "rule": "inbound_default"}
    },
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Internal SMB request allowed to file server.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{file_server}", "src_port": "49900", "dest_port": "445", "transport": "tcp", "action": "allow", "app": "microsoft-ds", "dvc": "ACME-FW01", "rule": "smb_internal"}
    },
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Outbound HTTPS request allowed to reddit.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "151.101.1.140", "src_port": "49950", "dest_port": "443", "transport": "tcp", "action": "allow", "app": "ssl", "dvc": "ACME-FW01", "rule": "https_outbound"}
    },
    {
        "event_type": "DENY",
        "source_type": "Firewall",
        "source_ip": "198.51.100.22",
        "message": "Inbound RDP request denied from external IP.",
        "key_value_pairs": {"src_ip": "198.51.100.22", "dst_ip": "{dc_server}", "src_port": "52100", "dest_port": "3389", "transport": "tcp", "action": "deny", "app": "ms-wbt-server", "dvc": "ACME-FW01", "rule": "inbound_default"}
    },
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Outbound HTTPS request allowed to github.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "140.82.112.4", "src_port": "50000", "dest_port": "443", "transport": "tcp", "action": "allow", "app": "ssl", "dvc": "ACME-FW01", "rule": "https_outbound"}
    },
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Outbound DNS request allowed to internal DNS server.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{dns_server}", "src_port": "50050", "dest_port": "53", "transport": "udp", "action": "allow", "app": "dns", "dvc": "ACME-FW01", "rule": "dns_outbound"}
    },
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Outbound HTTPS request allowed to facebook.com.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "157.240.214.35", "src_port": "50100", "dest_port": "443", "transport": "tcp", "action": "allow", "app": "ssl", "dvc": "ACME-FW01", "rule": "https_outbound"}
    },
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Internal SMB request allowed to file server.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "{file_server}", "src_port": "50150", "dest_port": "445", "transport": "tcp", "action": "allow", "app": "microsoft-ds", "dvc": "ACME-FW01", "rule": "smb_internal"}
    },
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Kerberos authentication request allowed to domain controller.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "10.0.1.200", "src_port": "52341", "dest_port": 88, "transport": "tcp", "action": "allow", "app": "kerberos", "dvc": "ACME-FW01", "rule": "internal-ad-services"}
    },
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "LDAP query allowed to domain controller.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "10.0.1.200", "src_port": "49823", "dest_port": 389, "transport": "tcp", "action": "allow", "app": "ldap", "dvc": "ACME-FW01", "rule": "internal-ad-services"}
    },
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "SMB file share access allowed to file server.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "10.0.1.201", "src_port": "51247", "dest_port": 445, "transport": "tcp", "action": "allow", "app": "ms-ds-smb", "dvc": "ACME-FW01", "rule": "internal-file-services"}
    },
    {
        "event_type": "ALLOW",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "RDP session allowed to web server.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "10.0.1.204", "src_port": "48562", "dest_port": 3389, "transport": "tcp", "action": "allow", "app": "ms-rdp", "dvc": "ACME-FW01", "rule": "admin-rdp-access"}
    },
    {
        "event_type": "SESSION_END",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Session ended for outbound HTTPS connection to Office 365.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "52.96.165.18", "src_port": "52341", "dest_port": 443, "transport": "tcp", "action": "allow", "app": "ssl", "dvc": "ACME-FW01", "rule": "outbound-web", "bytes_in": 184729, "bytes_out": 24816, "session_end_reason": "tcp-fin"}
    },
    {
        "event_type": "SESSION_END",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Session ended for outbound HTTPS connection to SharePoint.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "13.107.42.14", "src_port": "49823", "dest_port": 443, "transport": "tcp", "action": "allow", "app": "ssl", "dvc": "ACME-FW01", "rule": "outbound-web", "bytes_in": 892341, "bytes_out": 47215, "session_end_reason": "tcp-fin"}
    },
    {
        "event_type": "SESSION_END",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Session ended for outbound HTTPS connection to Google.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "142.250.191.46", "src_port": "51247", "dest_port": 443, "transport": "tcp", "action": "allow", "app": "web-browsing", "dvc": "ACME-FW01", "rule": "outbound-web", "bytes_in": 41825, "bytes_out": 8294, "session_end_reason": "tcp-fin"}
    },
    {
        "event_type": "SESSION_END",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Session ended for outbound HTTPS connection to Bing.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "204.79.197.200", "src_port": "48562", "dest_port": 443, "transport": "tcp", "action": "allow", "app": "web-browsing", "dvc": "ACME-FW01", "rule": "outbound-web", "bytes_in": 36172, "bytes_out": 6841, "session_end_reason": "tcp-fin"}
    },
    {
        "event_type": "SESSION_END",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Session ended for outbound HTTPS connection to GitHub.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "151.101.1.140", "src_port": "53891", "dest_port": 443, "transport": "tcp", "action": "allow", "app": "ssl", "dvc": "ACME-FW01", "rule": "outbound-web", "bytes_in": 124583, "bytes_out": 18472, "session_end_reason": "tcp-fin"}
    },
    {
        "event_type": "SESSION_END",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Session ended for outbound HTTPS connection to LinkedIn.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "157.240.241.35", "src_port": "54129", "dest_port": 443, "transport": "tcp", "action": "allow", "app": "ssl", "dvc": "ACME-FW01", "rule": "outbound-web", "bytes_in": 728194, "bytes_out": 39528, "session_end_reason": "tcp-fin"}
    },
    {
        "event_type": "SESSION_END",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Session ended for outbound HTTPS connection to Microsoft login.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "20.190.151.7", "src_port": "55672", "dest_port": 443, "transport": "tcp", "action": "allow", "app": "ssl", "dvc": "ACME-FW01", "rule": "outbound-web", "bytes_in": 12847, "bytes_out": 4193, "session_end_reason": "tcp-fin"}
    },
    {
        "event_type": "SESSION_END",
        "source_type": "Firewall",
        "source_ip": "{src_ip}",
        "message": "Session ended for outbound HTTPS connection to jsDelivr CDN.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "199.232.45.172", "src_port": "56218", "dest_port": 443, "transport": "tcp", "action": "allow", "app": "ssl", "dvc": "ACME-FW01", "rule": "outbound-web", "bytes_in": 67392, "bytes_out": 9128, "session_end_reason": "tcp-fin"}
    },
    # =========================================================================
    # PROXY LOGS (20 events) - Squid Native Format
    # =========================================================================
    {
        "event_type": "HTTP_GET",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "GET request to www.google.com returned 200 OK.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "142.250.191.46", "src_user": "{user_domain}", "dvc": "{hostname}", "url": "www.google.com", "app": "web-browsing", "transport": "tcp", "dest_port": "443", "action": "allow", "http_method": "GET"}
    },
    {
        "event_type": "HTTP_GET",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "GET request to www.reddit.com returned 200 OK.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "151.101.1.69", "src_user": "{user_domain}", "dvc": "{hostname}", "url": "www.reddit.com", "app": "web-browsing", "transport": "tcp", "dest_port": "443", "action": "allow", "http_method": "GET"}
    },
    {
        "event_type": "HTTP_GET",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "GET request to docs.microsoft.com returned 200 OK.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "52.84.214.93", "src_user": "{user_domain}", "dvc": "{hostname}", "url": "docs.microsoft.com/en-us/windows/", "app": "web-browsing", "transport": "tcp", "dest_port": "443", "action": "allow", "http_method": "GET"}
    },
    {
        "event_type": "HTTP_GET",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "GET request to github.com returned 200 OK.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "140.82.112.4", "src_user": "{user_domain}", "dvc": "{hostname}", "url": "github.com", "app": "web-browsing", "transport": "tcp", "dest_port": "443", "action": "allow", "http_method": "GET"}
    },
    {
        "event_type": "HTTP_GET",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "GET request to twitter.com returned 200 OK.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "104.244.42.193", "src_user": "{user_domain}", "dvc": "{hostname}", "url": "twitter.com/home", "app": "web-browsing", "transport": "tcp", "dest_port": "443", "action": "allow", "http_method": "GET"}
    },
    {
        "event_type": "HTTP_GET",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "GET request to outlook.office365.com returned 200 OK.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "13.107.42.14", "src_user": "{user_domain}", "dvc": "{hostname}", "url": "outlook.office365.com/mail/inbox", "app": "web-browsing", "transport": "tcp", "dest_port": "443", "action": "allow", "http_method": "GET"}
    },
    {
        "event_type": "HTTP_POST",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "POST request to outlook.office365.com returned 200 OK.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "13.107.42.14", "src_user": "{user_domain}", "dvc": "{hostname}", "url": "outlook.office365.com/api/v2.0/me/sendmail", "app": "web-browsing", "transport": "tcp", "dest_port": "443", "action": "allow", "http_method": "POST"}
    },
    {
        "event_type": "HTTP_GET",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "GET request to teams.microsoft.com returned 200 OK.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "52.96.166.130", "src_user": "{user_domain}", "dvc": "{hostname}", "url": "teams.microsoft.com/conversations", "app": "web-browsing", "transport": "tcp", "dest_port": "443", "action": "allow", "http_method": "GET"}
    },
    {
        "event_type": "HTTP_GET",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "GET request to www.linkedin.com returned 200 OK.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "31.13.65.36", "src_user": "{user_domain}", "dvc": "{hostname}", "url": "www.linkedin.com/feed/", "app": "web-browsing", "transport": "tcp", "dest_port": "443", "action": "allow", "http_method": "GET"}
    },
    {
        "event_type": "HTTP_GET",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "GET request to drive.google.com returned 200 OK.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "172.217.14.110", "src_user": "{user_domain}", "dvc": "{hostname}", "url": "drive.google.com/drive/my-drive", "app": "web-browsing", "transport": "tcp", "dest_port": "443", "action": "allow", "http_method": "GET"}
    },
    {
        "event_type": "HTTP_GET",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "GET request to sharepoint.com returned 200 OK.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "13.107.136.9", "src_user": "{user_domain}", "dvc": "{hostname}", "url": "sharepoint.com/sites/", "app": "web-browsing", "transport": "tcp", "dest_port": "443", "action": "allow", "http_method": "GET"}
    },
    {
        "event_type": "HTTP_GET",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "GET request to stackoverflow.com returned 200 OK.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "151.101.65.69", "src_user": "{user_domain}", "dvc": "{hostname}", "url": "stackoverflow.com/questions", "app": "web-browsing", "transport": "tcp", "dest_port": "443", "action": "allow", "http_method": "GET"}
    },
    {
        "event_type": "HTTP_GET",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "GET request to aws.amazon.com returned 200 OK.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "54.230.202.113", "src_user": "{user_domain}", "dvc": "{hostname}", "url": "aws.amazon.com/console/", "app": "web-browsing", "transport": "tcp", "dest_port": "443", "action": "allow", "http_method": "GET"}
    },
    {
        "event_type": "HTTP_GET",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "GET request to zoom.us returned 200 OK.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "52.84.150.44", "src_user": "{user_domain}", "dvc": "{hostname}", "url": "zoom.us/j/meetings", "app": "web-browsing", "transport": "tcp", "dest_port": "443", "action": "allow", "http_method": "GET"}
    },
    {
        "event_type": "HTTP_GET",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "GET request to www.youtube.com returned 200 OK.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "216.58.214.206", "src_user": "{user_domain}", "dvc": "{hostname}", "url": "www.youtube.com", "app": "web-browsing", "transport": "tcp", "dest_port": "443", "action": "allow", "http_method": "GET"}
    },
    {
        "event_type": "HTTP_GET",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "GET request to docs.github.com returned 200 OK.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "185.199.108.154", "src_user": "{user_domain}", "dvc": "{hostname}", "url": "docs.github.com/en/repositories", "app": "web-browsing", "transport": "tcp", "dest_port": "443", "action": "allow", "http_method": "GET"}
    },
    {
        "event_type": "HTTP_GET",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "GET request to onedrive.live.com returned 200 OK.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "52.96.166.130", "src_user": "{user_domain}", "dvc": "{hostname}", "url": "onedrive.live.com", "app": "web-browsing", "transport": "tcp", "dest_port": "443", "action": "allow", "http_method": "GET"}
    },
    {
        "event_type": "HTTP_GET",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "GET request to wordpress.com returned 200 OK.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "192.0.78.24", "src_user": "{user_domain}", "dvc": "{hostname}", "url": "wordpress.com/home", "app": "web-browsing", "transport": "tcp", "dest_port": "443", "action": "allow", "http_method": "GET"}
    },
    {
        "event_type": "HTTP_CONNECT",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "CONNECT tunnel established to outlook.office365.com:443.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "52.96.165.18", "src_user": "{username}", "dvc": "ACME-SVR06", "url": "outlook.office365.com:443", "app": "ssl", "transport": "tcp", "dest_port": 443, "action": "allow", "http_method": "CONNECT", "category": "business-and-economy"}
    },
    {
        "event_type": "HTTP_CONNECT",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "CONNECT tunnel established to acme-my.sharepoint.com:443.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "13.107.42.14", "src_user": "{username}", "dvc": "ACME-SVR06", "url": "acme-my.sharepoint.com:443", "app": "ssl", "transport": "tcp", "dest_port": 443, "action": "allow", "http_method": "CONNECT", "category": "business-and-economy"}
    },
    {
        "event_type": "HTTP_CONNECT",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "CONNECT tunnel established to teams.microsoft.com:443.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "52.114.128.10", "src_user": "{username}", "dvc": "ACME-SVR06", "url": "teams.microsoft.com:443", "app": "ssl", "transport": "tcp", "dest_port": 443, "action": "allow", "http_method": "CONNECT", "category": "business-and-economy"}
    },
    {
        "event_type": "HTTP_CONNECT",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "CONNECT tunnel established to login.microsoftonline.com:443.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "20.190.151.7", "src_user": "{username}", "dvc": "ACME-SVR06", "url": "login.microsoftonline.com:443", "app": "ssl", "transport": "tcp", "dest_port": 443, "action": "allow", "http_method": "CONNECT", "category": "business-and-economy"}
    },
    {
        "event_type": "HTTP_CONNECT",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "CONNECT tunnel established to www.google.com:443.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "142.250.191.46", "src_user": "{username}", "dvc": "ACME-SVR06", "url": "www.google.com:443", "app": "ssl", "transport": "tcp", "dest_port": 443, "action": "allow", "http_method": "CONNECT", "category": "search-engines"}
    },
    {
        "event_type": "HTTP_CONNECT",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "CONNECT tunnel established to github.com:443.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "151.101.1.140", "src_user": "{username}", "dvc": "ACME-SVR06", "url": "github.com:443", "app": "ssl", "transport": "tcp", "dest_port": 443, "action": "allow", "http_method": "CONNECT", "category": "computer-and-internet-info"}
    },
    {
        "event_type": "HTTP_CONNECT",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "CONNECT tunnel established to stackoverflow.com:443.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "104.18.32.115", "src_user": "{username}", "dvc": "ACME-SVR06", "url": "stackoverflow.com:443", "app": "ssl", "transport": "tcp", "dest_port": 443, "action": "allow", "http_method": "CONNECT", "category": "computer-and-internet-info"}
    },
    {
        "event_type": "HTTP_CONNECT",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "CONNECT tunnel established to www.linkedin.com:443.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "157.240.241.35", "src_user": "{username}", "dvc": "ACME-SVR06", "url": "www.linkedin.com:443", "app": "ssl", "transport": "tcp", "dest_port": 443, "action": "allow", "http_method": "CONNECT", "category": "social-networking"}
    },
    {
        "event_type": "HTTP_CONNECT",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "CONNECT tunnel established to www.cnn.com:443.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "23.52.16.123", "src_user": "{username}", "dvc": "ACME-SVR06", "url": "www.cnn.com:443", "app": "ssl", "transport": "tcp", "dest_port": 443, "action": "allow", "http_method": "CONNECT", "category": "news"}
    },
    {
        "event_type": "HTTP_CONNECT",
        "source_type": "Proxy",
        "source_ip": "{src_ip}",
        "message": "CONNECT tunnel established to cdn.jsdelivr.net:443.",
        "key_value_pairs": {"src_ip": "{src_ip}", "dst_ip": "199.232.45.172", "src_user": "{username}", "dvc": "ACME-SVR06", "url": "cdn.jsdelivr.net:443", "app": "ssl", "transport": "tcp", "dest_port": 443, "action": "allow", "http_method": "CONNECT", "category": "content-delivery-networks"}
    },
    # =========================================================================
    # SYSMON LOGS (20 events) - Windows Sysmon
    # =========================================================================
    {
        "event_type": "ProcessCreate",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Process created: svchost.exe by NT AUTHORITY\\SYSTEM.",
        "key_value_pairs": {"event_id": 1, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "", "process_id": "4528", "image": "C:\\Windows\\System32\\svchost.exe", "command_line": "svchost.exe -k netsvcs -p -s Schedule", "user": "NT AUTHORITY\\SYSTEM", "parent_process_id": "668", "parent_image": "C:\\Windows\\System32\\services.exe", "parent_command_line": "C:\\Windows\\System32\\services.exe"}
    },
    {
        "event_type": "ProcessCreate",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Process created: chrome.exe by {user_domain}.",
        "key_value_pairs": {"event_id": 1, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "", "process_id": "8824", "image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "command_line": "chrome.exe", "user": "{user_domain}", "parent_process_id": "4412", "parent_image": "C:\\Windows\\explorer.exe", "parent_command_line": "C:\\Windows\\Explorer.EXE"}
    },
    {
        "event_type": "NetworkConnect",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Outbound connection to www.google.com on port 443.",
        "key_value_pairs": {"event_id": 3, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "", "process_id": "8824", "image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "user": "{user_domain}", "protocol": "tcp", "initiated": True, "source_is_ipv6": False, "source_ip": "{src_ip}", "source_hostname": "{hostname}", "source_port_name": "", "destination_is_ipv6": False, "destination_ip": "142.250.191.46", "destination_hostname": "www.google.com", "destination_port": "443", "destination_port_name": "https"}
    },
    {
        "event_type": "DNSQuery",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "DNS query for www.google.com resolved to 142.250.191.46.",
        "key_value_pairs": {"event_id": 22, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "-", "utc_time": "{timestamp}", "process_guid": "{a1b2c3d4-5e6f-7890-abcd-ef1234567890}", "process_id": "8824", "query_name": "www.google.com", "query_status": "0", "query_results": "type:  5 www.google.com;::ffff:142.250.191.46;", "image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "user": "ACME\\{username}"}
    },
    {
        "event_type": "ProcessCreate",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Process created: OUTLOOK.EXE by {user_domain}.",
        "key_value_pairs": {"event_id": 1, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "", "process_id": "9120", "image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "command_line": "OUTLOOK.EXE", "user": "{user_domain}", "parent_process_id": "4412", "parent_image": "C:\\Windows\\explorer.exe", "parent_command_line": "C:\\Windows\\Explorer.EXE"}
    },
    {
        "event_type": "NetworkConnect",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Outbound connection to outlook.office365.com on port 443.",
        "key_value_pairs": {"event_id": 3, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "", "process_id": "9120", "image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "user": "{user_domain}", "protocol": "tcp", "initiated": True, "source_is_ipv6": False, "source_ip": "{src_ip}", "source_hostname": "{hostname}", "source_port_name": "", "destination_is_ipv6": False, "destination_ip": "52.96.166.24", "destination_hostname": "outlook.office365.com", "destination_port": "443", "destination_port_name": "https"}
    },
    {
        "event_type": "ProcessCreate",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Process created: TiWorker.exe launched by svchost.exe.",
        "key_value_pairs": {"event_id": 1, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "", "process_id": "6644", "image": "C:\\Windows\\WinSxS\\amd64_microsoft-windows-servicingstack\\TiWorker.exe", "command_line": "TiWorker.exe -Embedding", "user": "NT AUTHORITY\\SYSTEM", "parent_process_id": "4528", "parent_image": "C:\\Windows\\System32\\svchost.exe", "parent_command_line": "svchost.exe -k netsvcs -p -s TrustedInstaller"}
    },
    {
        "event_type": "NetworkConnect",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Outbound connection to update.microsoft.com on port 443.",
        "key_value_pairs": {"event_id": 3, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "", "process_id": "1284", "image": "C:\\Windows\\System32\\svchost.exe", "user": "NT AUTHORITY\\NETWORK SERVICE", "protocol": "tcp", "initiated": True, "source_is_ipv6": False, "source_ip": "{src_ip}", "source_hostname": "{hostname}", "source_port_name": "", "destination_is_ipv6": False, "destination_ip": "20.109.186.68", "destination_hostname": "update.microsoft.com", "destination_port": "443", "destination_port_name": "https"}
    },
    {
        "event_type": "FileCreate",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "File created: Q4_Report.pdf by {user_domain}.",
        "key_value_pairs": {"event_id": 11, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "", "process_id": "8824", "image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "target_filename": "C:\\Users\\{username}\\Downloads\\Q4_Report.pdf", "user": "{user_domain}"}
    },
    {
        "event_type": "DNSQuery",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "DNS query for settings-win.data.microsoft.com resolved to 40.77.226.250.",
        "key_value_pairs": {"event_id": 22, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "-", "utc_time": "{timestamp}", "process_guid": "{b2c3d4e5-6f78-9012-bcde-f23456789012}", "process_id": "1284", "query_name": "settings-win.data.microsoft.com", "query_status": "0", "query_results": "type:  5 settings-win-data-microsoft-com.akadns.net;::ffff:40.77.226.250;", "image": "C:\\Windows\\System32\\svchost.exe", "user": "NT AUTHORITY\\NETWORK SERVICE"}
    },
    {
        "event_type": "ProcessCreate",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Process created: taskhostw.exe by NT AUTHORITY\\SYSTEM.",
        "key_value_pairs": {"event_id": 1, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "", "process_id": "7788", "image": "C:\\Windows\\System32\\taskhostw.exe", "command_line": "taskhostw.exe", "user": "NT AUTHORITY\\SYSTEM", "parent_process_id": "4528", "parent_image": "C:\\Windows\\System32\\svchost.exe", "parent_command_line": "svchost.exe -k netsvcs -p -s Schedule"}
    },
    {
        "event_type": "SetValue",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Registry value updated by explorer.exe on recent documents list.",
        "key_value_pairs": {"event_id": 13, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "", "event_type": "SetValue", "process_id": "4412", "image": "C:\\Windows\\explorer.exe", "target_object": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", "details": "Binary Data", "user": "{user_domain}"}
    },
    {
        "event_type": "ProcessCreate",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Process created: notepad.exe by {user_domain}.",
        "key_value_pairs": {"event_id": 1, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "", "process_id": "10244", "image": "C:\\Windows\\System32\\notepad.exe", "command_line": "notepad.exe", "user": "{user_domain}", "parent_process_id": "4412", "parent_image": "C:\\Windows\\explorer.exe", "parent_command_line": "C:\\Windows\\Explorer.EXE"}
    },
    {
        "event_type": "FileCreate",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "File created: Meeting_Notes.docx by {user_domain}.",
        "key_value_pairs": {"event_id": 11, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "", "process_id": "11456", "image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "target_filename": "C:\\Users\\{username}\\Documents\\Meeting_Notes.docx", "user": "{user_domain}"}
    },
    {
        "event_type": "NetworkConnect",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Outbound connection to teams.microsoft.com on port 443.",
        "key_value_pairs": {"event_id": 3, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "", "process_id": "12580", "image": "C:\\Users\\{username}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", "user": "{user_domain}", "protocol": "tcp", "initiated": True, "source_is_ipv6": False, "source_ip": "{src_ip}", "source_hostname": "{hostname}", "source_port_name": "", "destination_is_ipv6": False, "destination_ip": "13.107.42.16", "destination_hostname": "teams.microsoft.com", "destination_port": "443", "destination_port_name": "https"}
    },
    {
        "event_type": "DNSQuery",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "DNS query for www.bing.com resolved to 204.79.197.200.",
        "key_value_pairs": {"event_id": 22, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "-", "utc_time": "{timestamp}", "process_guid": "{c3d4e5f6-7890-1234-cdef-345678901234}", "process_id": "13692", "query_name": "www.bing.com", "query_status": "0", "query_results": "type:  5 www-bing-com.dual-a-0001.a-msedge.net;::ffff:204.79.197.200;", "image": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "user": "ACME\\{username}"}
    },
    {
        "event_type": "NetworkConnect",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Outbound connection to sharepoint.com on port 443.",
        "key_value_pairs": {"event_id": 3, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "", "process_id": "8824", "image": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "user": "{user_domain}", "protocol": "tcp", "initiated": True, "source_is_ipv6": False, "source_ip": "{src_ip}", "source_hostname": "{hostname}", "source_port_name": "", "destination_is_ipv6": False, "destination_ip": "13.107.136.9", "destination_hostname": "sharepoint.com", "destination_port": "443", "destination_port_name": "https"}
    },
    {
        "event_type": "FileCreate",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "File created: CHROME.EXE-D43B7FE7.pf by NT AUTHORITY\\SYSTEM.",
        "key_value_pairs": {"event_id": 11, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "", "process_id": "1284", "image": "C:\\Windows\\System32\\svchost.exe", "target_filename": "C:\\Windows\\Prefetch\\CHROME.EXE-D43B7FE7.pf", "user": "NT AUTHORITY\\SYSTEM"}
    },
    {
        "event_type": "ProcessCreate",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Process created: slack.exe by {user_domain}.",
        "key_value_pairs": {"event_id": 1, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "", "process_id": "14804", "image": "C:\\Users\\{username}\\AppData\\Local\\slack\\slack.exe", "command_line": "slack.exe", "user": "{user_domain}", "parent_process_id": "4412", "parent_image": "C:\\Windows\\explorer.exe", "parent_command_line": "C:\\Windows\\Explorer.EXE"}
    },
    {
        "event_type": "NetworkConnect",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Outbound connection to slack.com on port 443.",
        "key_value_pairs": {"event_id": 3, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "", "process_id": "14804", "image": "C:\\Users\\{username}\\AppData\\Local\\slack\\slack.exe", "user": "{user_domain}", "protocol": "tcp", "initiated": True, "source_is_ipv6": False, "source_ip": "{src_ip}", "source_hostname": "{hostname}", "source_port_name": "", "destination_is_ipv6": False, "destination_ip": "99.181.64.71", "destination_hostname": "slack.com", "destination_port": "443", "destination_port_name": "https"}
    },
    {
        "event_type": "ImageLoaded",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Process terminated: chrome.exe.",
        "key_value_pairs": {"event_id": 5, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "-", "utc_time": "{timestamp}", "process_guid": "{a1b2c3d4-5e6f-7890-abcd-ef1234567890}", "process_id": "8824", "image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "user": "ACME\\{username}"}
    },
    {
        "event_type": "ProcessTerminate",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Process terminated: OUTLOOK.EXE.",
        "key_value_pairs": {"event_id": 5, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "-", "utc_time": "{timestamp}", "process_guid": "{b2c3d4e5-6f78-9012-bcde-f23456789012}", "process_id": "2468", "image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "user": "ACME\\{username}"}
    },
    {
        "event_type": "ProcessTerminate",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Process terminated: taskhostw.exe.",
        "key_value_pairs": {"event_id": 5, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "-", "utc_time": "{timestamp}", "process_guid": "{f6789012-3456-7890-f012-678901234567}", "process_id": "4692", "image": "C:\\Windows\\System32\\taskhostw.exe", "user": "ACME\\{username}"}
    },
    {
        "event_type": "ProcessTerminate",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Process terminated: RuntimeBroker.exe.",
        "key_value_pairs": {"event_id": 5, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "-", "utc_time": "{timestamp}", "process_guid": "{1234abcd-5678-90ef-1234-567890abcdef}", "process_id": "1456", "image": "C:\\Windows\\System32\\RuntimeBroker.exe", "user": "ACME\\{username}"}
    },
    {
        "event_type": "ProcessTerminate",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Process terminated: notepad.exe.",
        "key_value_pairs": {"event_id": 5, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "-", "utc_time": "{timestamp}", "process_guid": "{2345bcde-6789-01f0-2345-67890abcdef1}", "process_id": "6128", "image": "C:\\Windows\\System32\\notepad.exe", "user": "ACME\\{username}"}
    },
    {
        "event_type": "ImageLoaded",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Image loaded: chrome.dll by chrome.exe.",
        "key_value_pairs": {"event_id": 7, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "-", "utc_time": "{timestamp}", "process_guid": "{a1b2c3d4-5e6f-7890-abcd-ef1234567890}", "process_id": "8824", "image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "image_loaded": "C:\\Program Files\\Google\\Chrome\\Application\\133.0.6943.142\\chrome.dll", "file_version": "133.0.6943.142", "description": "Google Chrome", "product": "Google Chrome", "company": "Google LLC", "original_file_name": "chrome.dll", "hashes": "SHA256=A1B2C3D4E5F67890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0", "signed": "true", "signature": "Google LLC", "signature_status": "Valid", "user": "ACME\\{username}"}
    },
    {
        "event_type": "ImageLoaded",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Image loaded: olmapi32.dll by OUTLOOK.EXE.",
        "key_value_pairs": {"event_id": 7, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "-", "utc_time": "{timestamp}", "process_guid": "{b2c3d4e5-6f78-9012-bcde-f23456789012}", "process_id": "2468", "image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "image_loaded": "C:\\Program Files\\Microsoft Office\\root\\Office16\\olmapi32.dll", "file_version": "16.0.17328.20550", "description": "Microsoft Outlook MAPI 1.0", "product": "Microsoft Office", "company": "Microsoft Corporation", "original_file_name": "olmapi32.dll", "hashes": "SHA256=B2C3D4E5F6789012345678901BCDEF0123456789ABCDEF0123456789ABCDEF01", "signed": "true", "signature": "Microsoft Corporation", "signature_status": "Valid", "user": "ACME\\{username}"}
    },
    {
        "event_type": "ImageLoaded",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Image loaded: combase.dll by svchost.exe.",
        "key_value_pairs": {"event_id": 7, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "-", "utc_time": "{timestamp}", "process_guid": "{c3d4e5f6-7890-1234-cdef-345678901234}", "process_id": "1284", "image": "C:\\Windows\\System32\\svchost.exe", "image_loaded": "C:\\Windows\\System32\\combase.dll", "file_version": "10.0.19041.4894", "description": "Microsoft COM for Windows", "product": "Microsoft\u00ae Windows\u00ae Operating System", "company": "Microsoft Corporation", "original_file_name": "combase.dll", "hashes": "SHA256=C3D4E5F67890123456789012CDEF0123456789ABCDEF0123456789ABCDEF0123", "signed": "true", "signature": "Microsoft Windows", "signature_status": "Valid", "user": "NT AUTHORITY\\SYSTEM"}
    },
    {
        "event_type": "ImageLoaded",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Image loaded: shell32.dll by explorer.exe.",
        "key_value_pairs": {"event_id": 7, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "-", "utc_time": "{timestamp}", "process_guid": "{d4e5f678-9012-3456-def0-456789012345}", "process_id": "4892", "image": "C:\\Windows\\explorer.exe", "image_loaded": "C:\\Windows\\System32\\shell32.dll", "file_version": "10.0.19041.5072", "description": "Windows Shell Common Dll", "product": "Microsoft\u00ae Windows\u00ae Operating System", "company": "Microsoft Corporation", "original_file_name": "SHELL32.dll", "hashes": "SHA256=D4E5F6789012345678901234DEF0123456789ABCDEF0123456789ABCDEF01234", "signed": "true", "signature": "Microsoft Windows", "signature_status": "Valid", "user": "ACME\\{username}"}
    },
    {
        "event_type": "ImageLoaded",
        "source_type": "Sysmon",
        "source_ip": "{src_ip}",
        "message": "Image loaded: winhttp.dll by msedge.exe.",
        "key_value_pairs": {"event_id": 7, "channel": "Microsoft-Windows-Sysmon/Operational", "computer": "{hostname}", "rule_name": "-", "utc_time": "{timestamp}", "process_guid": "{e5f67890-1234-5678-ef01-567890123456}", "process_id": "13692", "image": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "image_loaded": "C:\\Windows\\System32\\winhttp.dll", "file_version": "10.0.19041.5005", "description": "Windows HTTP Services", "product": "Microsoft\u00ae Windows\u00ae Operating System", "company": "Microsoft Corporation", "original_file_name": "winhttp.dll", "hashes": "SHA256=E5F678901234567890123456EF0123456789ABCDEF0123456789ABCDEF012345", "signed": "true", "signature": "Microsoft Windows", "signature_status": "Valid", "user": "ACME\\{username}"}
    },
    # =========================================================================
    # WINDOWS SECURITY LOGS (20 events) - Windows Security Event Log
    # =========================================================================
    {
        "event_type": "4624",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "An account was successfully logged on.",
        "key_value_pairs": {"event_id": 4624, "channel": "WinEventLog:Security", "computer": "{hostname}", "subject_security_id": "NULL SID", "subject_account_name": "-", "subject_account_domain": "-", "subject_logon_id": "0x0", "logon_type": "2", "account_name": "{username}", "account_domain": "ACME", "new_logon_logon_id": "0x1A2B3C", "logon_guid": "{00000000-0000-0000-0000-000000000000}", "process_id": "0x0", "process_name": "-", "workstation_name": "{hostname}", "src_ip": "{src_ip}", "src_port": "-", "logon_process": "User32", "authentication_package": "Kerberos", "transited_services": "-", "package_name": "-", "key_length": "0"}
    },
    {
        "event_type": "4672",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "Special privileges assigned to new logon.",
        "key_value_pairs": {"event_id": 4672, "channel": "WinEventLog:Security", "computer": "{hostname}", "subject_security_id": "S-1-5-21-1547161642-1842894336-919524151-1105", "account_name": "{username}", "account_domain": "ACME", "subject_logon_id": "0x1A2B3C", "privileges": "SeChangeNotifyPrivilege\n\t\t\tSeIncreaseWorkingSetPrivilege\n\t\t\tSeShutdownPrivilege"}
    },
    {
        "event_type": "4624",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "An account was successfully logged on.",
        "key_value_pairs": {"event_id": 4624, "channel": "WinEventLog:Security", "computer": "{hostname}", "subject_security_id": "NULL SID", "subject_account_name": "-", "subject_account_domain": "-", "subject_logon_id": "0x0", "logon_type": "5", "account_name": "SYSTEM", "account_domain": "NT AUTHORITY", "new_logon_logon_id": "0x3E8", "logon_guid": "{00000000-0000-0000-0000-000000000000}", "process_id": "0x0", "process_name": "-", "workstation_name": "{hostname}", "src_ip": "-", "src_port": "-", "logon_process": "Advapi", "authentication_package": "Negotiate", "transited_services": "-", "package_name": "-", "key_length": "0"}
    },
    {
        "event_type": "4688",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "A new process has been created.",
        "key_value_pairs": {"event_id": 4688, "channel": "WinEventLog:Security", "computer": "{hostname}", "subject_security_id": "S-1-5-18", "account_name": "ACME-WKS01$", "account_domain": "ACME", "subject_logon_id": "0x3e7", "target_security_id": "S-1-5-21-1547161642-1842894336-919524151-1105", "target_account_name": "{username}", "target_account_domain": "ACME", "target_logon_id": "0x1A2B3C", "new_process_id": "0x1234", "new_process_name": "C:\\Windows\\explorer.exe", "token_elevation_type": "%%1936", "mandatory_label": "S-1-16-8192", "creator_process_id": "0x4a8", "creator_process_name": "C:\\Windows\\System32\\winlogon.exe", "process_command_line": "C:\\Windows\\Explorer.EXE"}
    },
    {
        "event_type": "4688",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "A new process has been created.",
        "key_value_pairs": {"event_id": 4688, "channel": "WinEventLog:Security", "computer": "{hostname}", "subject_security_id": "S-1-5-21-1547161642-1842894336-919524151-1105", "account_name": "{username}", "account_domain": "ACME", "subject_logon_id": "0x1A2B3C", "target_security_id": "S-1-5-21-1547161642-1842894336-919524151-1105", "target_account_name": "{username}", "target_account_domain": "ACME", "target_logon_id": "0x1A2B3C", "new_process_id": "0x1456", "new_process_name": "C:\\Windows\\System32\\RuntimeBroker.exe", "token_elevation_type": "%%1938", "mandatory_label": "S-1-16-8192", "creator_process_id": "0x6f4", "creator_process_name": "C:\\Windows\\System32\\svchost.exe", "process_command_line": "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding"}
    },
    {
        "event_type": "4624",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "An account was successfully logged on.",
        "key_value_pairs": {"event_id": 4624, "channel": "WinEventLog:Security", "computer": "{hostname}", "subject_security_id": "NULL SID", "subject_account_name": "-", "subject_account_domain": "-", "subject_logon_id": "0x0", "logon_type": "3", "account_name": "{username}", "account_domain": "ACME", "new_logon_logon_id": "0x49300", "logon_guid": "{00000000-0000-0000-0000-000000000000}", "process_id": "0x0", "process_name": "-", "workstation_name": "{hostname}", "src_ip": "{src_ip}", "src_port": "-", "logon_process": "NtLmSsp", "authentication_package": "NTLM", "transited_services": "-", "package_name": "NTLM V2", "key_length": "128"}
    },
    {
        "event_type": "4634",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "An account was logged off.",
        "key_value_pairs": {"event_id": 4634, "channel": "WinEventLog:Security", "computer": "{hostname}", "subject_security_id": "S-1-5-21-1547161642-1842894336-919524151-1105", "subject_account_name": "{username}", "subject_account_domain": "ACME", "subject_logon_id": "0x1A2B3C", "logon_type": 3}
    },
    {
        "event_type": "4624",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "An account was successfully logged on.",
        "key_value_pairs": {"event_id": 4624, "channel": "WinEventLog:Security", "computer": "{hostname}", "subject_security_id": "NULL SID", "subject_account_name": "-", "subject_account_domain": "-", "subject_logon_id": "0x0", "logon_type": "5", "account_name": "SYSTEM", "account_domain": "NT AUTHORITY", "new_logon_logon_id": "0x3E9", "logon_guid": "{00000000-0000-0000-0000-000000000000}", "process_id": "0x0", "process_name": "-", "workstation_name": "{hostname}", "src_ip": "-", "src_port": "-", "logon_process": "Advapi", "authentication_package": "Negotiate", "transited_services": "-", "package_name": "-", "key_length": "0"}
    },
    {
        "event_type": "4624",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "An account was successfully logged on.",
        "key_value_pairs": {"event_id": 4624, "channel": "WinEventLog:Security", "computer": "{hostname}", "subject_security_id": "NULL SID", "subject_account_name": "-", "subject_account_domain": "-", "subject_logon_id": "0x0", "logon_type": "7", "account_name": "{username}", "account_domain": "ACME", "new_logon_logon_id": "0x2C3D4E", "logon_guid": "{00000000-0000-0000-0000-000000000000}", "process_id": "0x0", "process_name": "-", "workstation_name": "{hostname}", "src_ip": "{src_ip}", "src_port": "-", "logon_process": "User32", "authentication_package": "Kerberos", "transited_services": "-", "package_name": "-", "key_length": "0"}
    },
    {
        "event_type": "4688",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "A new process has been created.",
        "key_value_pairs": {"event_id": 4688, "channel": "WinEventLog:Security", "computer": "{hostname}", "subject_security_id": "S-1-5-21-1547161642-1842894336-919524151-1105", "account_name": "{username}", "account_domain": "ACME", "subject_logon_id": "0x1A2B3C", "target_security_id": "S-1-5-21-1547161642-1842894336-919524151-1105", "target_account_name": "{username}", "target_account_domain": "ACME", "target_logon_id": "0x1A2B3C", "new_process_id": "0x2468", "new_process_name": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "token_elevation_type": "%%1938", "mandatory_label": "S-1-16-8192", "creator_process_id": "0x1234", "creator_process_name": "C:\\Windows\\explorer.exe", "process_command_line": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\""}
    },
    {
        "event_type": "4648",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "A logon was attempted using explicit credentials.",
        "key_value_pairs": {"event_id": 4648, "channel": "WinEventLog:Security", "computer": "{hostname}", "subject_security_id": "S-1-5-21-1547161642-1842894336-919524151-1105", "account_name": "{username}", "account_domain": "ACME", "subject_logon_id": "0x2C3D4E", "subject_logon_guid": "{00000000-0000-0000-0000-000000000000}", "target_account_name": "{username}", "target_account_domain": "ACME", "target_logon_guid": "{00000000-0000-0000-0000-000000000000}", "target_server_name": "ACME-SVR02", "target_info": "ACME-SVR02", "process_id": "0x1a4c", "process_name": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "ip_address": "-", "ip_port": "-"}
    },
    {
        "event_type": "4624",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "An account was successfully logged on.",
        "key_value_pairs": {"event_id": 4624, "channel": "WinEventLog:Security", "computer": "{hostname}", "subject_security_id": "NULL SID", "subject_account_name": "-", "subject_account_domain": "-", "subject_logon_id": "0x0", "logon_type": "3", "account_name": "{username}", "account_domain": "ACME", "new_logon_logon_id": "0x49350", "logon_guid": "{00000000-0000-0000-0000-000000000000}", "process_id": "0x0", "process_name": "-", "workstation_name": "{hostname}", "src_ip": "{src_ip}", "src_port": "-", "logon_process": "Kerberos", "authentication_package": "Kerberos", "transited_services": "-", "package_name": "-", "key_length": "0"}
    },
    {
        "event_type": "4688",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "A new process has been created.",
        "key_value_pairs": {"event_id": 4688, "channel": "WinEventLog:Security", "computer": "{hostname}", "subject_security_id": "S-1-5-18", "account_name": "ACME-WKS01$", "account_domain": "ACME", "subject_logon_id": "0x3e7", "target_security_id": "S-1-5-18", "target_account_name": "ACME-WKS01$", "target_account_domain": "ACME", "target_logon_id": "0x3e7", "new_process_id": "0x3580", "new_process_name": "C:\\Windows\\System32\\svchost.exe", "token_elevation_type": "%%1936", "mandatory_label": "S-1-16-16384", "creator_process_id": "0x2c8", "creator_process_name": "C:\\Windows\\System32\\services.exe", "process_command_line": "C:\\Windows\\System32\\svchost.exe -k netsvcs -p"}
    },
    {
        "event_type": "4624",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "An account was successfully logged on.",
        "key_value_pairs": {"event_id": 4624, "channel": "WinEventLog:Security", "computer": "{hostname}", "subject_security_id": "NULL SID", "subject_account_name": "-", "subject_account_domain": "-", "subject_logon_id": "0x0", "logon_type": "3", "account_name": "svc_backup", "account_domain": "ACME", "new_logon_logon_id": "0x49600", "logon_guid": "{00000000-0000-0000-0000-000000000000}", "process_id": "0x0", "process_name": "-", "workstation_name": "{hostname}", "src_ip": "{src_ip}", "src_port": "-", "logon_process": "Kerberos", "authentication_package": "Negotiate", "transited_services": "-", "package_name": "-", "key_length": "0"}
    },
    {
        "event_type": "4672",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "Special privileges assigned to new logon.",
        "key_value_pairs": {"event_id": 4672, "channel": "WinEventLog:Security", "computer": "{hostname}", "subject_security_id": "S-1-5-21-1547161642-1842894336-919524151-2001", "account_name": "svc_backup", "account_domain": "ACME", "subject_logon_id": "0x4D5E6F", "privileges": "SeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeChangeNotifyPrivilege"}
    },
    {
        "event_type": "4634",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "An account was logged off.",
        "key_value_pairs": {"event_id": 4634, "channel": "WinEventLog:Security", "computer": "{hostname}", "subject_security_id": "S-1-5-21-1547161642-1842894336-919524151-1105", "subject_account_name": "{username}", "subject_account_domain": "ACME", "subject_logon_id": "0x2C3D4E", "logon_type": 7}
    },
    {
        "event_type": "4624",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "An account was successfully logged on.",
        "key_value_pairs": {"event_id": 4624, "channel": "WinEventLog:Security", "computer": "{hostname}", "subject_security_id": "NULL SID", "subject_account_name": "-", "subject_account_domain": "-", "subject_logon_id": "0x0", "logon_type": "2", "account_name": "{username}", "account_domain": "ACME", "new_logon_logon_id": "0x5E6F70", "logon_guid": "{00000000-0000-0000-0000-000000000000}", "process_id": "0x0", "process_name": "-", "workstation_name": "{hostname}", "src_ip": "{src_ip}", "src_port": "-", "logon_process": "User32", "authentication_package": "Kerberos", "transited_services": "-", "package_name": "-", "key_length": "0"}
    },
    {
        "event_type": "4688",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "A new process has been created.",
        "key_value_pairs": {"event_id": 4688, "channel": "WinEventLog:Security", "computer": "{hostname}", "subject_security_id": "S-1-5-21-1547161642-1842894336-919524151-1105", "account_name": "{username}", "account_domain": "ACME", "subject_logon_id": "0x1A2B3C", "target_security_id": "S-1-5-21-1547161642-1842894336-919524151-1105", "target_account_name": "{username}", "target_account_domain": "ACME", "target_logon_id": "0x1A2B3C", "new_process_id": "0x4692", "new_process_name": "C:\\Windows\\System32\\taskhostw.exe", "token_elevation_type": "%%1938", "mandatory_label": "S-1-16-8192", "creator_process_id": "0x6f4", "creator_process_name": "C:\\Windows\\System32\\svchost.exe", "process_command_line": "taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}"}
    },
    {
        "event_type": "4624",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "An account was successfully logged on.",
        "key_value_pairs": {"event_id": 4624, "channel": "WinEventLog:Security", "computer": "{hostname}", "subject_security_id": "NULL SID", "subject_account_name": "-", "subject_account_domain": "-", "subject_logon_id": "0x0", "logon_type": "2", "account_name": "DWM-1", "account_domain": "Window Manager", "new_logon_logon_id": "0x6F7080", "logon_guid": "{00000000-0000-0000-0000-000000000000}", "process_id": "0x0", "process_name": "-", "workstation_name": "{hostname}", "src_ip": "-", "src_port": "-", "logon_process": "User32", "authentication_package": "Negotiate", "transited_services": "-", "package_name": "-", "key_length": "0"}
    },
    {
        "event_type": "4688",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "A new process has been created.",
        "key_value_pairs": {"event_id": 4688, "channel": "WinEventLog:Security", "computer": "{hostname}", "subject_security_id": "S-1-5-21-1547161642-1842894336-919524151-1105", "account_name": "{username}", "account_domain": "ACME", "subject_logon_id": "0x1A2B3C", "target_security_id": "S-1-5-21-1547161642-1842894336-919524151-1105", "target_account_name": "{username}", "target_account_domain": "ACME", "target_logon_id": "0x1A2B3C", "new_process_id": "0x57A4", "new_process_name": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "token_elevation_type": "%%1938", "mandatory_label": "S-1-16-8192", "creator_process_id": "0x1234", "creator_process_name": "C:\\Windows\\explorer.exe", "process_command_line": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\""}
    },
    {
        "event_type": "4647",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "User initiated logoff.",
        "key_value_pairs": {"event_id": 4647, "channel": "WinEventLog:Security", "computer": "{hostname}", "subject_security_id": "S-1-5-21-1547161642-1842894336-919524151-1105", "account_name": "{username}", "account_domain": "ACME", "subject_logon_id": "0x1A2B3C"}
    },
    {
        "event_type": "4768",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "A Kerberos authentication ticket (TGT) was requested.",
        "key_value_pairs": {"event_id": 4768, "channel": "WinEventLog:Security", "computer": "{hostname}", "account_name": "{username}", "supplied_realm_name": "ACME.LOCAL", "user_id": "S-1-5-21-1547161642-1842894336-919524151-1105", "service_name": "krbtgt", "service_id": "S-1-5-21-1547161642-1842894336-919524151-502", "ticket_options": "0x40810010", "result_code": "0x0", "ticket_encryption_type": "0x12", "pre_authentication_type": "2", "client_address": "::ffff:10.42.18.55", "client_port": "52341", "certificate_issuer_name": "-", "certificate_serial_number": "-", "certificate_thumbprint": "-"}
    },
    {
        "event_type": "4768",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "A Kerberos authentication ticket (TGT) was requested.",
        "key_value_pairs": {"event_id": 4768, "channel": "WinEventLog:Security", "computer": "{hostname}", "account_name": "{username}", "supplied_realm_name": "ACME.LOCAL", "user_id": "S-1-5-21-1547161642-1842894336-919524151-1105", "service_name": "krbtgt", "service_id": "S-1-5-21-1547161642-1842894336-919524151-502", "ticket_options": "0x40810010", "result_code": "0x0", "ticket_encryption_type": "0x12", "pre_authentication_type": "2", "client_address": "::ffff:{src_ip}", "client_port": "49823", "certificate_issuer_name": "-", "certificate_serial_number": "-", "certificate_thumbprint": "-"}
    },
    {
        "event_type": "4768",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "A Kerberos authentication ticket (TGT) was requested.",
        "key_value_pairs": {"event_id": 4768, "channel": "WinEventLog:Security", "computer": "{hostname}", "account_name": "{username}", "supplied_realm_name": "ACME.LOCAL", "user_id": "S-1-5-21-1547161642-1842894336-919524151-1105", "service_name": "krbtgt", "service_id": "S-1-5-21-1547161642-1842894336-919524151-502", "ticket_options": "0x40810010", "result_code": "0x0", "ticket_encryption_type": "0x12", "pre_authentication_type": "2", "client_address": "::ffff:{src_ip}", "client_port": "51247", "certificate_issuer_name": "-", "certificate_serial_number": "-", "certificate_thumbprint": "-"}
    },
    {
        "event_type": "4768",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "A Kerberos authentication ticket (TGT) was requested.",
        "key_value_pairs": {"event_id": 4768, "channel": "WinEventLog:Security", "computer": "{hostname}", "account_name": "{username}", "supplied_realm_name": "ACME.LOCAL", "user_id": "S-1-5-21-1547161642-1842894336-919524151-1105", "service_name": "krbtgt", "service_id": "S-1-5-21-1547161642-1842894336-919524151-502", "ticket_options": "0x40810010", "result_code": "0x0", "ticket_encryption_type": "0x12", "pre_authentication_type": "2", "client_address": "::ffff:{src_ip}", "client_port": "48562", "certificate_issuer_name": "-", "certificate_serial_number": "-", "certificate_thumbprint": "-"}
    },
    {
        "event_type": "4768",
        "source_type": "Windows Security",
        "source_ip": "{src_ip}",
        "message": "A Kerberos authentication ticket (TGT) was requested.",
        "key_value_pairs": {"event_id": 4768, "channel": "WinEventLog:Security", "computer": "{hostname}", "account_name": "{username}", "supplied_realm_name": "ACME.LOCAL", "user_id": "S-1-5-21-1547161642-1842894336-919524151-1105", "service_name": "krbtgt", "service_id": "S-1-5-21-1547161642-1842894336-919524151-502", "ticket_options": "0x40810010", "result_code": "0x0", "ticket_encryption_type": "0x12", "pre_authentication_type": "2", "client_address": "::ffff:10.42.18.63", "client_port": "52098", "certificate_issuer_name": "-", "certificate_serial_number": "-", "certificate_thumbprint": "-"}
    },
]

def get_random_employee():
    return random.choice(EMPLOYEES)

def get_random_server(server_type=None):
    if server_type:
        return SERVERS.get(server_type)
    return random.choice(list(SERVERS.values()))


def generate_scenario_id():
    return str(uuid.uuid4())

def infer_event_type(config, dynamic_fields, config_key):
    """Infer realistic event_type based on event_source and event_id per EVENT_TYPE_MAPPINGS.md"""
    # If explicit event_type_name is set, use it
    if "event_type_name" in config:
        return config["event_type_name"]

    event_source = config.get("event_source", "Unknown").lower()
    event_id = dynamic_fields.get("event_id") or dynamic_fields.get("event_type_id")

    # Sysmon event mapping
    if "sysmon" in event_source:
        sysmon_map = {
            1: "ProcessCreate",
            2: "FileCreateTime",
            3: "NetworkConnect",
            5: "ProcessTerminate",
            6: "DriverLoad",
            7: "ImageLoad",
            8: "CreateRemoteThread",
            10: "ProcessAccess",
            11: "FileCreate",
            12: "RegistryEvent",
            13: "RegistryEvent",
            14: "RegistryEvent",
            15: "FileCreateStreamHash",
            17: "PipeEvent",
            18: "PipeEvent",
            22: "DNSQuery",
            23: "FileDelete",
        }
        if event_id and int(event_id) in sysmon_map:
            return sysmon_map[int(event_id)]
        # Default for Sysmon process events
        if dynamic_fields.get("process_path"):
            return "ProcessCreate"

    # Windows Security events - use Event ID as event_type
    if "windows security" in event_source or "active directory" in event_source:
        if event_id:
            return str(event_id)
        # Infer from config key
        if "lockout" in config_key:
            return "4740"
        if "failed" in config_key or "brute" in config_key:
            return "4625"
        if "login" in config_key or "signin" in config_key:
            return "4624"

    # Zeek/Network logs
    if "zeek" in event_source:
        zeek_map = {
            "dns_query": "dns",
            "ssl_conn": "ssl",
            "conn_log": "conn",
            "http_log": "http",
            "smb_files": "smb_files",
        }
        if config_key in zeek_map:
            return zeek_map[config_key]
        # Extract type from event_source (e.g., "Zeek HTTP" -> "http")
        parts = config.get("event_source", "").split()
        if len(parts) > 1:
            return parts[1].lower()

    # Proxy logs
    if "proxy" in event_source:
        return "TCP_MISS"

    # Firewall logs
    if "firewall" in event_source:
        return "ALLOW"

    # Email logs
    if "exchange" in event_source or "email" in event_source or "mail" in event_source:
        if "recv" in config_key or "received" in config_key:
            return "RECEIVE"
        if "sent" in config_key or "send" in config_key:
            return "SEND"
        return "RECEIVE"

    # EDR/Endpoint logs with process info
    if "edr" in event_source and dynamic_fields.get("process_path"):
        return "ProcessCreate"

    # Print Server - Windows Print Event ID 307
    if "print" in event_source:
        return "307"

    # VPN logs - Generic VPN event
    if "vpn" in event_source:
        return "SessionConnect"

    # Azure AD / Identity
    if "azure" in event_source or "aad" in event_source or "identity" in event_source:
        return "SignInLogs"

    # Backup logs - Veeam Event ID 190 (job completed)
    if "backup" in event_source or "veeam" in event_source:
        return "190"

    # DHCP - Windows DHCP Event ID 10 (new lease)
    if "dhcp" in event_source:
        return "10"

    # SQL/Database - SQL Server Audit Event ID
    if "sql" in event_source or "database" in event_source:
        return "33205"

    # AV/Antivirus - Windows Defender Event ID 1001 (scan completed)
    if "antivirus" in event_source or "defender" in event_source or " av" in event_source:
        return "1001"

    # Wireless Controller - 802.1X authentication events
    if "wireless" in event_source or "wifi" in event_source:
        return "5632"  # Windows WLAN-AutoConfig Event ID for 802.1X auth

    # Default: use config key but cleaned up
    return config_key

def substitute_placeholders(text, subs):
    """Replace placeholders like {src_ip} with actual values."""
    if not isinstance(text, str):
        return text
    for placeholder, value in subs.items():
        text = text.replace(placeholder, str(value))
    return text

def substitute_dict(d, subs):
    """Apply placeholder substitution to all string values in a dict."""
    result = {}
    for k, v in d.items():
        if isinstance(v, str):
            result[k] = substitute_placeholders(v, subs)
        elif isinstance(v, dict):
            result[k] = substitute_dict(v, subs)
        else:
            result[k] = v
    return result

def apply_dynamic_substitution(log_dict):
    """Apply dynamic employee/server substitution to a scenario log.

    Replaces placeholders like {username}, {hostname}, {src_ip} with
    randomly selected employee data for realistic log generation.
    """
    emp = random.choice(EMPLOYEES)

    subs = {
        "{src_ip}": emp["ip"],
        "{hostname}": emp["workstation"],
        "{username}": emp["name"],
        "{user_domain}": f"ACME\\{emp['name']}",
        "{user_fullname}": emp["full_name"],
        "{user_email}": emp["email"],
        "{dns_server}": SERVERS["dns"]["ip"],
        "{file_server}": SERVERS["file"]["ip"],
        "{dc_server}": SERVERS["dc"]["ip"],
        "{print_server}": SERVERS["print"]["ip"],
    }

    result = {}
    for k, v in log_dict.items():
        if isinstance(v, str):
            result[k] = substitute_placeholders(v, subs)
        elif isinstance(v, dict):
            result[k] = substitute_dict(v, subs)
        else:
            result[k] = v
    return result

def apply_substitution_with_subs(log_dict, subs):
    """Apply provided substitutions to a log dict (for chain-level consistency)."""
    result = {}
    for k, v in log_dict.items():
        if isinstance(v, str):
            result[k] = substitute_placeholders(v, subs)
        elif isinstance(v, dict):
            result[k] = substitute_dict(v, subs)
        else:
            result[k] = v
    return result

def generate_normal_event(scenario_id=None):
    """Generate a normal traffic event from the curated template pool."""
    template = random.choice(NORMAL_TRAFFIC_TEMPLATES)
    emp = random.choice(EMPLOYEES)

    # Build substitution map
    subs = {
        "{src_ip}": emp["ip"],
        "{hostname}": emp["workstation"],
        "{username}": emp["name"],
        "{user_domain}": f"ACME\\{emp['name']}",
        "{user_fullname}": emp["full_name"],
        "{user_email}": emp["email"],
        "{dns_server}": SERVERS["dns"]["ip"],
        "{file_server}": SERVERS["file"]["ip"],
        "{dc_server}": SERVERS["dc"]["ip"],
        "{print_server}": SERVERS["print"]["ip"],
    }

    # Apply substitutions
    message = substitute_placeholders(template["message"], subs)
    source_ip = substitute_placeholders(template.get("source_ip", ""), subs)
    destination_ip = substitute_placeholders(template.get("destination_ip", ""), subs)
    key_value_pairs = substitute_dict(template.get("key_value_pairs", {}), subs)

    # Auto-populate destination_ip for network log types if not set in template
    if not destination_ip:
        src_type = template.get("source_type", "")
        if src_type == "DNS":
            # Queries go to DNS server; responses go back to the client
            if template.get("source_ip") == "{dns_server}":
                destination_ip = emp["ip"]
            else:
                destination_ip = SERVERS["dns"]["ip"]
        elif src_type in ("Firewall", "Proxy"):
            destination_ip = key_value_pairs.get("dst_ip", "")

    timestamp = datetime.now(timezone.utc) - timedelta(seconds=random.randint(0, 300))

    return {
        "id": str(uuid.uuid4()),
        "scenario_id": scenario_id or generate_scenario_id(),
        "timestamp": timestamp.isoformat(),
        "event_type": template["event_type"],
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "hostname": emp["workstation"],
        "severity": "low",
        "protocol": template.get("protocol", ""),
        "detected_by": template["source_type"],
        "source_type": template["source_type"],
        "message": message,
        "key_value_pairs": key_value_pairs,
        "label": "normal_traffic",
        "flagged": False,
        "user": f"ACME\\{emp['name']}",
        "process_id": random.randint(1000, 65535),
        "parent_process_id": random.randint(500, 5000),
    }
def log_writer(session, interval=1):
    count = 0

    # Randomize when attack is injected (position in the log stream)
    inject_at = random.randint(3, 15)  # Attack can start anywhere from position 3-15
    total_logs_target = random.randint(18, 25)  # Total logs before pause

    # Attack queue for staggered injection
    attack_queue = []
    logs_since_last_attack = 0
    next_attack_gap = random.randint(2, 3)  # 2-3 normal logs between attack events
    pending_scenario_info = None  # Store scenario info until all logs are written
    trailing_logs_remaining = 0  # Normal logs to generate after last attack before pausing

    fake_log_path = session["paths"]["generated_logs"]

    while True:
        # Exit if session was cleaned up
        if session["id"] not in sessions:
            print(f"[SESSION EXPIRED] Thread for {session['id'][:8]} exiting.", flush=True)
            return

        if session["paused"]:
            time.sleep(1)
            continue

        # Check if we've completed all levels
        if session["current_level"] >= len(CAMPAIGN_LEVELS):
            print("[CAMPAIGN COMPLETE] All levels finished!", flush=True)
            session["paused"] = True
            time.sleep(1)
            continue

        # Check if we're in trailing logs phase (after all attacks written)
        if trailing_logs_remaining > 0 and pending_scenario_info:
            normal_log = generate_normal_event()
            with open(fake_log_path, "a") as f:
                f.write(json.dumps(normal_log) + "\n")
            trailing_logs_remaining -= 1

            # If done with trailing logs, now pause
            if trailing_logs_remaining == 0:
                session["current_scenario"] = pending_scenario_info
                pending_scenario_info = None
                session["paused"] = True

                # Mark all logs for this scenario as chain complete
                scenario_id = session["current_scenario"].get("scenario_id")
                if scenario_id:
                    with open(fake_log_path, "r") as f:
                        all_logs = [json.loads(line) for line in f if line.strip()]
                    for log in all_logs:
                        if log.get("scenario_id") == scenario_id:
                            log["chain_complete"] = True
                    with open(fake_log_path, "w") as f:
                        for log in all_logs:
                            f.write(json.dumps(log) + "\n")

                # Start timer in hardcore mode
                if session["game_mode"] == "hardcore":
                    session["timer_start"] = datetime.now(timezone.utc)
                    print(f"[TIMER] Started - {get_timer_duration(session['current_level'])} seconds to respond!", flush=True)

                # Reset for next level with new random positions
                count = 0
                inject_at = random.randint(3, 15)
                total_logs_target = random.randint(18, 25)
            count += 1
            time.sleep(interval)
            continue

        # Check if we should inject an attack log from the queue
        if attack_queue and logs_since_last_attack >= next_attack_gap:
            attack_log = attack_queue.pop(0)
            print(f"[SCENARIO] {attack_log.get('event_type', 'N/A')} | {attack_log.get('message', '')[:60]}...", flush=True)
            with open(fake_log_path, "a") as f:
                f.write(json.dumps(attack_log) + "\n")
            logs_since_last_attack = 0
            next_attack_gap = random.randint(2, 3)

            # If queue is now empty, calculate trailing logs to reach target
            if not attack_queue and pending_scenario_info:
                # Random trailing logs (at least 2, but vary based on where we are)
                trailing_logs_remaining = random.randint(2, max(3, total_logs_target - count))
                continue

        if count == inject_at and not attack_queue and session["selected_level_option"]:
            # Use the already-selected scenario (selected at start or level advance)
            level_config = CAMPAIGN_LEVELS[session["current_level"]]
            selected = session["selected_level_option"]

            print(f"\n[INJECTING] Level {level_config['level']} - {selected['ticket_title']}", flush=True)
            print(f"[CATEGORY] {selected['category']}", flush=True)

            scenario_label = selected["scenario_label"]
            scenario_id = generate_scenario_id()

            # Get the attack chain for this scenario
            if scenario_label in attack_chains:
                chain = attack_chains[scenario_label]
            else:
                print(f"[ERROR] Scenario '{scenario_label}' not found, skipping", flush=True)
                count += 1
                continue

            # Inject all events from the attack chain
            chain_to_inject = chain
            print(f"[SCENARIO] {scenario_label} - {len(chain_to_inject)} events", flush=True)

            # Build the logs for this scenario with progressive timestamps
            threat_logs = []
            base_time = datetime.now(timezone.utc)

            # Pick employee ONCE for entire chain - all events share same user/host/ip
            emp = random.choice(EMPLOYEES)
            chain_subs = {
                "{src_ip}": emp["ip"],
                "{hostname}": emp["workstation"],
                "{username}": emp["name"],
                "{user_domain}": f"ACME\\{emp['name']}",
                "{user_fullname}": emp["full_name"],
                "{user_email}": emp["email"],
                "{dns_server}": SERVERS["dns"]["ip"],
                "{file_server}": SERVERS["file"]["ip"],
                "{dc_server}": SERVERS["dc"]["ip"],
                "{print_server}": SERVERS["print"]["ip"],
            }

            prev_offset = 0
            for i, original in enumerate(chain_to_inject):
                log = copy.deepcopy(original)
                # Apply chain-level substitution (same employee for all events)
                log = apply_substitution_with_subs(log, chain_subs)
                # Progressive timestamps - use custom offset if specified, otherwise 3-8 seconds
                if i == 0:
                    prev_offset = 0
                else:
                    custom_offset = original.get("time_offset_seconds")
                    if custom_offset:
                        prev_offset += custom_offset
                    else:
                        prev_offset += random.randint(3, 8)
                log.pop("time_offset_seconds", None)
                log["timestamp"] = (base_time + timedelta(seconds=prev_offset)).isoformat()
                log["id"] = str(uuid.uuid4())
                # Preserve severity from attack template; fallback to "high"
                if "severity" not in log or not log["severity"]:
                    log["severity"] = "high"
                log["scenario_id"] = scenario_id
                log["status"] = "active"
                log["level"] = level_config["level"]
                log["level_name"] = selected["ticket_title"]
                log["category"] = selected["category"]
                log["flagged"] = True  # Auto-promoted to incident
                if "source_type" not in log or not log["source_type"]:
                    log["source_type"] = get_source_type(log.get("detected_by", "Unknown"))
                threat_logs.append(log)

            # Assign alert ID to this scenario's logs
            while True:
                alert_id = f"INC-{random.randint(1000, 9999)}"
                if alert_id not in session["used_alert_ids"]:
                    session["used_alert_ids"].add(alert_id)
                    break
            for log in threat_logs:
                log["alert_id"] = alert_id

            # Queue the attack logs for staggered injection
            attack_queue.extend(threat_logs)
            logs_since_last_attack = 0
            next_attack_gap = random.randint(2, 3)

            # Store scenario info to set after all logs are written
            pending_scenario_info = {
                "label": selected["scenario_label"],
                "logs": threat_logs,
                "scenario_id": scenario_id,
                "level": level_config["level"],
                "level_name": selected["ticket_title"],
                "storyline": selected["storyline"],
                "category": selected["category"]
            }

            count += 1
            continue

        # Generate normal traffic log
        normal_log = generate_normal_event()
        with open(fake_log_path, "a") as f:
            f.write(json.dumps(normal_log) + "\n")
        logs_since_last_attack += 1
        count += 1
        time.sleep(interval)

@app.route('/api/fake-events', methods=['GET'])
def get_fake_events():
    s = g.session
    seen_ids = set()
    unique_logs = []
    try:
        with open(s["paths"]["generated_logs"], "r") as f:
            for line in f:
                if not line.strip():
                    continue
                log = json.loads(line)
                if log["id"] not in seen_ids:
                    seen_ids.add(log["id"])
                    unique_logs.append(log)
    except FileNotFoundError:
        return jsonify({"error": "Fake log file not found"}), 404
    return jsonify(unique_logs)

@app.route("/api/reset-simulator", methods=["POST"])
def reset_simulator():
    s = g.session

    s["paused"] = True
    s["current_scenario"] = None
    s["current_level"] = 0
    s["game_mode"] = "training"
    s["timer_start"] = None
    s["analyst_name"] = None
    s["used_alert_ids"] = set()
    s["selected_level_option"] = None
    s["scenario_start_time"] = None
    s["scenario_history"] = []

    for filepath in [s["paths"]["generated_logs"], s["paths"]["analyst_actions"], s["paths"]["incident_reports"]]:
        with open(filepath, "w") as f:
            f.truncate(0)

    print("[RESET] Files cleared. Level reset to 1. Waiting for analyst to resume.")
    return jsonify({"message": "Simulator reset. Click 'Simulate Events' to restart from Level 1."}), 200


@app.route("/api/current-level", methods=["GET"])
def get_current_level():
    s = g.session

    # Build level results from action history
    level_results = {}
    if os.path.exists(s["paths"]["analyst_actions"]):
        with open(s["paths"]["analyst_actions"], "r") as f:
            actions = [json.loads(line) for line in f if line.strip()]

        # Get scenario info from logs
        scenario_info = {}
        if os.path.exists(s["paths"]["generated_logs"]):
            with open(s["paths"]["generated_logs"], "r") as f:
                for line in f:
                    if line.strip():
                        log = json.loads(line)
                        sid = log.get("scenario_id")
                        if sid and sid not in scenario_info:
                            scenario_info[sid] = {
                                "category": log.get("category", ""),
                                "level": log.get("level")
                            }

        # Track all actions per level: {level: {correct: X, total: Y}}
        level_stats = {}
        seen_scenarios = set()  # Avoid counting same scenario twice

        # Filter to only scenario-level actions (classify only, no more resolve)
        scenario_actions = [a for a in actions if a.get("action") == "classify"]
        for action in scenario_actions:
            sid = action.get("scenario_id")
            info = scenario_info.get(sid, {})
            level = info.get("level")

            if level is None or sid in seen_scenarios:
                continue
            seen_scenarios.add(sid)

            true_category = info.get("category", "")

            # Determine if action was correct (category match)
            selected = action.get("selected_category", "")
            correct = (selected == true_category)

            # Track stats per level
            level_key = str(level)
            if level_key not in level_stats:
                level_stats[level_key] = {"correct": 0, "total": 0}
            level_stats[level_key]["total"] += 1
            if correct:
                level_stats[level_key]["correct"] += 1

        # Convert stats to results: "correct" or "incorrect"
        for level_key, stats in level_stats.items():
            if stats["correct"] == stats["total"]:
                level_results[level_key] = "correct"
            else:
                level_results[level_key] = "incorrect"

    if s["current_level"] >= len(CAMPAIGN_LEVELS):
        return jsonify({
            "completed": True,
            "total_levels": len(CAMPAIGN_LEVELS),
            "level_results": level_results,
            "scenario_history": s.get("scenario_history", []),
            "message": "Congratulations! You've completed all levels!"
        })

    level_config = CAMPAIGN_LEVELS[s["current_level"]]

    # Use selected_level_option if available (randomized scenario), otherwise show placeholder
    if s["selected_level_option"]:
        ticket_title = s["selected_level_option"].get("ticket_title", "Unknown")
        storyline = s["selected_level_option"].get("storyline", "")
        category = s["selected_level_option"].get("category", "Unknown")
    else:
        # No scenario selected yet - return null so frontend hides the card
        ticket_title = None
        storyline = None
        category = None

    return jsonify({
        "completed": False,
        "current_level": level_config["level"],
        "ticket_title": ticket_title,
        "storyline": storyline,
        "category": category,
        "category_pool": level_config.get("category_pool", []),
        "total_levels": len(CAMPAIGN_LEVELS),
        "progress": f"{s['current_level']}/{len(CAMPAIGN_LEVELS)}",
        "level_results": level_results,
        "scenario_history": s.get("scenario_history", []),
        "scenario_start_time": s.get("scenario_start_time")
    })



@app.route('/api/analytics', methods=['GET'])
def get_analytics():
    s = g.session
    if not os.path.exists(s["paths"]["generated_logs"]):
        return jsonify({
            "total_alerts": 0,
            "critical_alerts": 0,
            "high_severity_rate": 0.0,
            "weekly_alerts": []
        })

    with open(s["paths"]["generated_logs"], "r") as f:
        logs = [json.loads(line) for line in f if line.strip()]

    total = len(logs)
    critical = sum(1 for log in logs if log.get("severity") == "critical" and log.get("status") in ["active"])
    high = sum(1 for log in logs if log.get("severity") == "high")
    rate = round(((critical + high) / total) * 100, 2) if total else 0.0

    weekdays = {d: 0 for d in ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]}
    for log in logs:
        try:
            ts = datetime.fromisoformat(log["timestamp"].replace("Z", ""))
            d = ts.strftime("%a")
            if d in weekdays:
                weekdays[d] += 1
        except Exception:
            continue

    return jsonify({
        "total_alerts": total,
        "critical_alerts": critical,
        "high_severity_rate": rate,
        "weekly_alerts": [{"day": d, "alerts": c} for d, c in weekdays.items()]
    })

@app.route("/api/analytics/report_card", methods=["GET"])
def get_analyst_report_card():
    s = g.session
    try:
        # Handle missing files gracefully
        actions = []
        all_logs = []

        if os.path.exists(s["paths"]["analyst_actions"]):
            with open(s["paths"]["analyst_actions"], "r") as f:
                actions = [json.loads(line) for line in f if line.strip()]

        if os.path.exists(s["paths"]["generated_logs"]):
            with open(s["paths"]["generated_logs"], "r") as f:
                all_logs = [json.loads(line) for line in f if line.strip()]

        # Build lookup: scenario_id -> category
        scenario_info = {}
        for log in all_logs:
            sid = log.get("scenario_id")
            if sid and sid not in scenario_info:
                scenario_info[sid] = {
                    "category": log.get("category", "")
                }

        correct_threat_identified = 0  # Correctly classified real threats
        wrong_category = 0             # Wrong category selected on real threats
        fp_identified = 0              # False positives correctly identified
        fp_missed = 0                  # False positives wrongly classified as real threats

        # Flag accuracy tracking
        correct_flags = 0
        wrong_flags = 0

        for action in actions:
            sid = action.get("scenario_id")
            act = action.get("action")

            # Handle flag actions
            if act == "flag":
                if action.get("correct", False):
                    correct_flags += 1
                else:
                    wrong_flags += 1
                continue

            if act == "classify":
                if action.get("correct_category", "").lower() == "false positive":
                    # This was a false positive scenario
                    if action.get("category_correct", False):
                        fp_identified += 1   # Analyst correctly spotted the FP
                    else:
                        fp_missed += 1       # Analyst fell for the FP
                else:
                    # This was a real threat scenario
                    if action.get("category_correct", False):
                        correct_threat_identified += 1  # Correct category!
                    else:
                        wrong_category += 1  # Wrong category selected

        # Calculate classification accuracy (exclude flags)
        classification_actions = [a for a in actions if a.get("action") == "classify"]
        total_classifications = len(classification_actions)
        total_correct = correct_threat_identified + fp_identified
        classification_accuracy = round((total_correct / total_classifications) * 100, 2) if total_classifications else 0

        # Calculate flag accuracy
        total_flags = correct_flags + wrong_flags
        flag_accuracy = round((correct_flags / total_flags) * 100, 2) if total_flags else 0

        return jsonify({
            "threats_caught": correct_threat_identified,
            "wrong_category": wrong_category,
            "total_actions": total_classifications,
            "accuracy": classification_accuracy,
            "fp_identified": fp_identified,
            "fp_missed": fp_missed,
            "correct_flags": correct_flags,
            "wrong_flags": wrong_flags,
            "total_flags": total_flags,
            "flag_accuracy": flag_accuracy
        })

    except Exception as e:
        print(f"[ERROR] report_card failed: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/analytics/action_history", methods=["GET"])
def get_action_history():
    """Returns detailed history of analyst actions with correctness feedback."""
    s = g.session
    try:
        actions = []
        all_logs = []

        if os.path.exists(s["paths"]["analyst_actions"]):
            with open(s["paths"]["analyst_actions"], "r") as f:
                actions = [json.loads(line) for line in f if line.strip()]

        if os.path.exists(s["paths"]["generated_logs"]):
            with open(s["paths"]["generated_logs"], "r") as f:
                all_logs = [json.loads(line) for line in f if line.strip()]

        # Build lookups
        scenario_info = {}
        for log in all_logs:
            sid = log.get("scenario_id")
            if sid and sid not in scenario_info:
                scenario_info[sid] = {
                    "category": log.get("category", ""),
                    "level": log.get("level"),
                    "level_name": log.get("level_name", ""),
                    "scenario_label": log.get("label", "")
                }

        history = []
        # Filter to only classify actions
        scenario_actions = [a for a in actions if a.get("action") == "classify"]
        for action in reversed(scenario_actions):  # Most recent first
            sid = action.get("scenario_id")
            timestamp = action.get("timestamp")

            info = scenario_info.get(sid, {})
            true_category = info.get("category", "Unknown")
            level = info.get("level")
            level_name = info.get("level_name", "")
            scenario_label = info.get("scenario_label", "")

            # Determine correctness and feedback
            selected_category = action.get("selected_category", "Unknown")
            correct = action.get("category_correct", False)

            if correct:
                feedback = f"Correct! You identified this {true_category} threat accurately."
            else:
                feedback = f"Incorrect category. You selected {selected_category}, but this was {true_category}."

            history.append({
                "timestamp": timestamp,
                "level": level,
                "level_name": level_name,
                "action": "classify",
                "user_choice": selected_category,
                "correct": correct,
                "true_category": true_category,
                "feedback": feedback,
                "scenario_label": scenario_label
            })

        return jsonify(history[:10])  # Return last 10 actions

    except Exception as e:
        print(f"[ERROR] action_history failed: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/triage-review/<scenario_label>", methods=["GET"])
def get_triage_review(scenario_label):
    """Get educational triage review content for a scenario."""
    review = TRIAGE_REVIEWS.get(scenario_label)
    if not review:
        return jsonify({"error": f"No triage review found for {scenario_label}"}), 404
    return jsonify({
        "scenario_label": scenario_label,
        **review
    })


@app.route("/api/current-scenario", methods=["GET"])
def get_current_scenario():
    s = g.session
    return jsonify(s["current_scenario"] if s["current_scenario"] else {})

@app.route("/api/resume", methods=["POST"])
def resume_generation():
    s = g.session
    data = request.json
    action = data.get("analyst_action")
    scenario_id = data.get("scenario_id")
    label = data.get("label", "unknown")
    selected_category = data.get("selected_category")  # For classify action

    if not scenario_id:
        return jsonify({"error": "Missing scenario_id"}), 400

    print(f"\n[ANALYST ACTION] {action.upper()} on {label} ({scenario_id})", flush=True)
    if selected_category:
        print(f"[CATEGORY SELECTED] {selected_category}", flush=True)

    existing_category = None

    if os.path.exists(s["paths"]["generated_logs"]):
        with open(s["paths"]["generated_logs"], "r") as f:
            all_logs = [json.loads(line) for line in f if line.strip()]

        for log in all_logs:
            if log.get("scenario_id") == scenario_id:
                if log.get("category") and not existing_category:
                    existing_category = log["category"]
                    break

        # Guard against duplicate classify actions
        already_classified = any(
            log.get("scenario_id") == scenario_id and log.get("status") == "classified"
            for log in all_logs
        )
        if already_classified and action == "classify":
            return jsonify({"status": "already_classified", "category": existing_category or "Unknown"})

        # Determine correctness for classify action
        category_correct = False
        if action == "classify" and selected_category:
            category_correct = selected_category.lower() == (existing_category or "").lower()
            print(f"[SCORING] Selected: {selected_category}, Actual: {existing_category}, Match: {category_correct}", flush=True)

        updated_logs = []
        for log in all_logs:
            if log.get("scenario_id") == scenario_id:
                if action == "classify":
                    log["status"] = "classified"
                    log["analyst_category"] = selected_category
                    log["category_correct"] = category_correct
                else:
                    log["status"] = action
                log["analyst_action"] = action
            updated_logs.append(log)

        with open(s["paths"]["generated_logs"], "w") as f:
            for log in updated_logs:
                f.write(json.dumps(log) + "\n")

    action_log = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scenario_id": scenario_id,
        "action": action,
        "label": label
    }

    # Add classify-specific fields
    if action == "classify":
        action_log["selected_category"] = selected_category
        action_log["correct_category"] = existing_category
        action_log["category_correct"] = category_correct

    with open(s["paths"]["analyst_actions"], "a") as f:
        f.write(json.dumps(action_log) + "\n")

    # Determine if answer was wrong for hardcore mode failure
    answer_wrong = False
    failure_reason = None

    if action == "classify" and not category_correct:
        # Wrong category selected
        answer_wrong = True
        failure_reason = f"Wrong category: selected {selected_category}, was {existing_category}"

    # Handle hardcore mode failure
    if answer_wrong and s["game_mode"] == "hardcore":
        print(f"\n[HARDCORE FAILURE] {failure_reason}", flush=True)
        print(f"[HARDCORE] Resetting to Level 1...", flush=True)

        # Reset game state - stay paused until user selects difficulty again
        s["current_level"] = 0
        s["timer_start"] = None
        s["current_scenario"] = None
        s["paused"] = True

        # Clear log files
        for path in [s["paths"]["generated_logs"], s["paths"]["analyst_actions"], s["paths"]["incident_reports"]]:
            if os.path.exists(path):
                os.remove(path)

        return jsonify({
            "status": "hardcore_failure",
            "action": action,
            "failure_reason": failure_reason,
            "category": existing_category or "Unknown"
        })

    # Check if all incidents for current level are resolved
    if os.path.exists(s["paths"]["generated_logs"]):
        with open(s["paths"]["generated_logs"], "r") as f:
            all_logs = [json.loads(line) for line in f if line.strip()]

        # Get current level number
        current_level_num = CAMPAIGN_LEVELS[s["current_level"]]["level"] if s["current_level"] < len(CAMPAIGN_LEVELS) else None

        # Find all active incidents for current level
        active_for_level = [
            log for log in all_logs
            if log.get("level") == current_level_num
            and log.get("status") == "active"
            and log.get("label") != "normal_traffic"
        ]

        # Get unique scenario_ids that are still active
        active_scenarios = set(log.get("scenario_id") for log in active_for_level)

        if len(active_scenarios) == 0:
            # Save completed scenario to history
            if s["selected_level_option"]:
                s["scenario_history"].append({
                    "level": current_level_num,
                    "ticket_title": s["selected_level_option"].get("ticket_title", "Unknown"),
                    "storyline": s["selected_level_option"].get("storyline", ""),
                    "startTime": s.get("scenario_start_time"),
                })
            # All incidents resolved - advance to next level
            s["current_level"] += 1
            s["timer_start"] = None  # Reset timer for next level
            if s["current_level"] < len(CAMPAIGN_LEVELS):
                # Select next scenario immediately so Scenario Card shows
                next_level = CAMPAIGN_LEVELS[s["current_level"]]
                s["selected_level_option"] = select_level_scenarios(next_level)
                s["scenario_start_time"] = time.time() * 1000
                print(f"[LEVEL UP] Advancing to Level {next_level['level']}", flush=True)
                print(f"[SCENARIO SELECTED] {s['selected_level_option']['ticket_title']} ({s['selected_level_option']['category']})", flush=True)
            else:
                s["selected_level_option"] = None
                print("[CAMPAIGN COMPLETE] All levels finished!", flush=True)
            s["paused"] = False  # Unpause to allow next level injection
        else:
            print(f"[WAITING] {len(active_scenarios)} incident(s) still active for this level", flush=True)
            # Stay paused - don't inject new scenarios until all are resolved

    s["current_scenario"] = None
    return jsonify({"status": "action logged", "action": action})


@app.route('/api/grouped-alerts', methods=['GET'])
def get_grouped_alerts():
    s = g.session
    if not os.path.exists(s["paths"]["generated_logs"]):
        return jsonify({"alerts": [], "stats": {"total_alerts": 0, "closed_alerts": 0, "open_alerts": 0, "severity_breakdown": {"low": 0, "medium": 0, "high": 0, "critical": 0}, "source_breakdown": {}}})

    with open(s["paths"]["generated_logs"], "r") as f:
        logs = [json.loads(line) for line in f if line.strip()]

    grouped = {}

    for log in logs:
        scenario_id = log.get("scenario_id")
        threat_pattern = log.get("threat_pattern", "Suspicious Activity")

        if not scenario_id or log.get("label") == "normal_traffic":
            continue

        group_key = scenario_id

        if group_key not in grouped:
            grouped[group_key] = {
                "scenario_id": scenario_id,
                "threat_pattern": threat_pattern,
                "label": log.get("label", "Unknown"),
                "status": log.get("status", "unknown"),
                "severity": log.get("severity", "unknown"),
                "category": log.get("category", ""),
                "analyst_category": log.get("analyst_category", ""),
                "alert_id": log.get("alert_id", ""),
                "level": log.get("level"),
                "log_count": 0,
                "logs": [],
                "severity_breakdown": {"low": 0, "medium": 0, "high": 0, "critical": 0}
            }
        else:
            # Update analyst_category if it exists in this log
            if log.get("analyst_category"):
                grouped[group_key]["analyst_category"] = log.get("analyst_category")

        grouped[group_key]["logs"].append(log)
        grouped[group_key]["log_count"] += 1
        sev = log.get("severity", "medium").lower()
        if sev in grouped[group_key]["severity_breakdown"]:
            grouped[group_key]["severity_breakdown"][sev] += 1

    # Only return groups where the full attack chain has been injected
    result = [grp for grp in grouped.values() if any(log.get("chain_complete") for log in grp["logs"])]

    # Compute unified group severity (highest in the group)
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    for grp in result:
        highest = max(severity_order.get(log.get("severity", "medium").lower(), 2) for log in grp["logs"])
        grp["group_severity"] = {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}[highest]

    # Compute aggregate stats
    total_alerts = len(result)
    closed_alerts = sum(1 for grp in result if grp["status"] in ["classified", "resolved"])
    open_alerts = total_alerts - closed_alerts
    severity_totals = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    source_totals = {}
    for grp in result:
        # Sum per-log severities (not per-scenario), so the donut reflects
        # the real distribution of event severities, not just chain peaks.
        for sev_key, sev_count in grp["severity_breakdown"].items():
            if sev_key in severity_totals:
                severity_totals[sev_key] += sev_count
        for log in grp["logs"]:
            src = log.get("source_type") or "Unknown"
            source_totals[src] = source_totals.get(src, 0) + 1

    return jsonify({
        "alerts": result,
        "stats": {
            "total_alerts": total_alerts,
            "closed_alerts": closed_alerts,
            "open_alerts": open_alerts,
            "severity_breakdown": severity_totals,
            "source_breakdown": source_totals
        }
    })


@app.route("/api/reports", methods=["POST"])
def submit_report():
    s = g.session

    data = request.json
    scenario_id = data.get("scenario_id")
    submitted_category = data.get("threat_category")
    data["timestamp"] = datetime.now(timezone.utc).isoformat()
    data["id"] = str(uuid.uuid4())
    if "owner" not in data:
        data["owner"] = "Unassigned"

    correct_category = None
    scenario_label = None

    if os.path.exists(s["paths"]["generated_logs"]):
        with open(s["paths"]["generated_logs"], "r") as f:
            for line in f:
                log = json.loads(line)
                if log.get("scenario_id") == scenario_id:
                    correct_category = log.get("category")
                    scenario_label = log.get("label")
                    break

    # Fallback: if category not in log, look it up from CAMPAIGN_LEVELS using label
    if not correct_category and scenario_label:
        for level_config in CAMPAIGN_LEVELS:
            if level_config["scenario_label"] == scenario_label:
                correct_category = level_config["category"]
                break

    is_correct = (submitted_category or "").lower() == (correct_category or "").lower()
    data["correct_category"] = correct_category
    data["category_match"] = is_correct

    print(f"[REPORT] scenario_id={scenario_id}, submitted={submitted_category}, correct={correct_category}, match={is_correct}", flush=True)

    with open(s["paths"]["incident_reports"], "a") as f:
        f.write(json.dumps(data) + "\n")

    if scenario_id and not data.get("skip_advance"):
        if os.path.exists(s["paths"]["generated_logs"]):
            with open(s["paths"]["generated_logs"], "r") as f:
                logs = [json.loads(line) for line in f if line.strip()]

            for log in logs:
                if log.get("scenario_id") == scenario_id:
                    log["status"] = "investigating"
                    log["analyst_action"] = "investigate"

            with open(s["paths"]["generated_logs"], "w") as f:
                for log in logs:
                    f.write(json.dumps(log) + "\n")

        label = "unknown"
        if scenario_id and os.path.exists(s["paths"]["generated_logs"]):
            with open(s["paths"]["generated_logs"], "r") as f:
                for line in f:
                    log = json.loads(line)
                    if log.get("scenario_id") == scenario_id:
                        label = log.get("label", "unknown")
                        break

        action_log = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scenario_id": scenario_id,
            "action": "investigate",
            "label": label
        }
        with open(s["paths"]["analyst_actions"], "a") as f:
            f.write(json.dumps(action_log) + "\n")

        # Save completed scenario to history
        if s["selected_level_option"]:
            completed_level_num = CAMPAIGN_LEVELS[s["current_level"]]["level"] if s["current_level"] < len(CAMPAIGN_LEVELS) else None
            if completed_level_num is not None:
                s["scenario_history"].append({
                    "level": completed_level_num,
                    "ticket_title": s["selected_level_option"].get("ticket_title", "Unknown"),
                    "storyline": s["selected_level_option"].get("storyline", ""),
                    "startTime": s.get("scenario_start_time"),
                })

        s["current_level"] += 1
        if s["current_level"] < len(CAMPAIGN_LEVELS):
            next_level = CAMPAIGN_LEVELS[s["current_level"]]
            s["selected_level_option"] = select_level_scenarios(next_level)
            s["scenario_start_time"] = time.time() * 1000
            print(f"[LEVEL UP] Advancing to Level {next_level['level']} (categories: {next_level.get('category_pool', [])})", flush=True)
            print(f"[SCENARIO SELECTED] {s['selected_level_option']['ticket_title']} ({s['selected_level_option']['category']})", flush=True)
        else:
            s["selected_level_option"] = None
            print("[CAMPAIGN COMPLETE] All levels finished!", flush=True)

        s["current_scenario"] = None
        s["paused"] = False

    return jsonify({"message": "Report submitted and scenario resolved"}), 200


@app.route("/api/reports", methods=["GET"])
def get_reports():
    s = g.session
    if not os.path.exists(s["paths"]["incident_reports"]):
        return jsonify([])
    with open(s["paths"]["incident_reports"], "r") as f:
        reports = [json.loads(line) for line in f if line.strip()]
    return jsonify(reports)


@app.route('/api/reports/<report_id>', methods=['DELETE'])
def delete_report(report_id):
    s = g.session
    try:
        if not os.path.exists(s["paths"]["incident_reports"]):
            return jsonify({'error': 'Report storage not found'}), 404

        remaining_reports = []
        found = False

        with open(s["paths"]["incident_reports"], 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                report = json.loads(line)
                if report.get('id') == report_id:
                    found = True
                else:
                    remaining_reports.append(report)

        if not found:
            return jsonify({'error': 'Report not found'}), 404

        with open(s["paths"]["incident_reports"], 'w') as f:
            for report in remaining_reports:
                f.write(json.dumps(report) + '\n')

        return jsonify({'message': 'Report deleted'}), 200

    except Exception as e:
        print(f"Error deleting report: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/reports/<report_id>', methods=['PUT'])
def update_report(report_id):
    s = g.session
    try:
        if not os.path.exists(s["paths"]["incident_reports"]):
            return jsonify({'error': 'Report storage not found'}), 404

        updated_data = request.json
        updated_data['id'] = report_id
        updated_reports = []

        with open(s["paths"]["incident_reports"], 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                report = json.loads(line)
                if report.get('id') == report_id:
                    updated_reports.append(updated_data)
                else:
                    updated_reports.append(report)

        with open(s["paths"]["incident_reports"], 'w') as f:
            for report in updated_reports:
                f.write(json.dumps(report) + '\n')

        return jsonify({'message': 'Report updated'}), 200

    except Exception as e:
        print(f"Error updating report: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/game-state', methods=['GET'])
def get_game_state():
    """Returns current game state including mode, timer, etc."""
    s = g.session

    timer_remaining = None
    timer_expired = False

    if s["game_mode"] == "hardcore" and s["timer_start"]:
        elapsed = (datetime.now(timezone.utc) - s["timer_start"]).total_seconds()
        duration = get_timer_duration(s["current_level"])
        timer_remaining = max(0, duration - elapsed)
        timer_expired = timer_remaining <= 0

    return jsonify({
        "game_mode": s["game_mode"],
        "timer_remaining": timer_remaining,
        "timer_expired": timer_expired,
        "timer_duration": get_timer_duration(s["current_level"]),
        "paused": s["paused"],
        "current_level": s["current_level"],
        "analyst_name": s["analyst_name"]
    })


@app.route('/api/game-timeout', methods=['POST'])
def handle_game_timeout():
    """Handle timeout in hardcore mode - reset to level 1."""
    s = g.session

    if s["game_mode"] != "hardcore":
        return jsonify({"error": "Not in hardcore mode"}), 400

    print(f"\n[TIMEOUT] Time's up! Resetting to Level 1...", flush=True)

    # Reset game state - stay paused until user selects difficulty again
    s["current_level"] = 0
    s["timer_start"] = None
    s["current_scenario"] = None
    s["paused"] = True

    # Clear log files
    for path in [s["paths"]["generated_logs"], s["paths"]["analyst_actions"], s["paths"]["incident_reports"]]:
        if os.path.exists(path):
            os.remove(path)

    return jsonify({"message": "Game reset due to timeout", "reset": True})


@app.route('/api/start-simulator', methods=['POST'])
def start_simulator():
    s = g.session

    data = request.json or {}
    s["game_mode"] = data.get("game_mode", "training")
    s["timer_start"] = None
    s["analyst_name"] = data.get("analyst_name")

    print(f"\n[GAME MODE] Starting in {s['game_mode'].upper()} mode (session {s['id'][:8]})", flush=True)
    if s["analyst_name"]:
        print(f"[ANALYST] {s['analyst_name']}", flush=True)

    # Select scenario for current level immediately so Scenario Card shows
    if s["current_level"] < len(CAMPAIGN_LEVELS):
        level_config = CAMPAIGN_LEVELS[s["current_level"]]
        s["selected_level_option"] = select_level_scenarios(level_config)
        s["scenario_start_time"] = time.time() * 1000
        print(f"[SCENARIO SELECTED] {s['selected_level_option']['ticket_title']} ({s['selected_level_option']['category']})", flush=True)

    thread_name = f"LogWriter-{s['id']}"
    running_threads = [t.name for t in threading.enumerate()]
    thread_exists = thread_name in running_threads

    # If thread exists and is paused, just unpause it
    if thread_exists and s["paused"]:
        s["paused"] = False
        return jsonify({"message": "Simulator resumed", "game_mode": s["game_mode"]}), 200

    # If thread doesn't exist, start it
    if not thread_exists:
        s["paused"] = False
        thread = threading.Thread(target=log_writer, args=(s,), kwargs={"interval": 1}, daemon=True)
        thread.name = thread_name
        thread.start()
        return jsonify({"message": "Simulator started", "game_mode": s["game_mode"]}), 200

    # Thread exists and not paused - already running
    return jsonify({"message": "Simulator already running", "game_mode": s["game_mode"]}), 200


if __name__ == '__main__':
    app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
    app.run(port=5000)
