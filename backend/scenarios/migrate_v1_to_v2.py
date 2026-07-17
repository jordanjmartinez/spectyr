"""Migrate every v1 scenario YAML into schema v2 (Phase 2 Stage 0).

The migration WRAPS the v1 scenario, it never edits it: every line of the v1
file's narrative/entities/chain/triage_review sections is carried over
byte-for-byte. The only change inside the chain body is the injected per-step
id/host/user tag lines; the section is renamed chain: -> attack:. New sections
(schema_version, environment, noise, answer_key) are emitted around it with
convert.py's JSON-quoted scalar style so YAML type coercion cannot touch
type-sensitive values.

Inference is rule-based and conservative:
  - host tag = the environment host the activity OCCURRED ON (the actor),
    not the sensor that logged it. Endpoint telemetry (Sysmon, Windows
    Security) on a host tags that host; network sensor events (DNS, Proxy,
    Firewall) tag the host that originated the traffic, resolved from the
    step's source_ip placeholder.
  - user tag = the employee entity whose username/user_domain the step
    references. Literal (non-placeholder) accounts need an OVERRIDES entry.
  - environment hosts = every workstation/server/firewall the chain touches,
    placeholder-driven wherever the chain is placeholder-driven.
  - answer_key: classification = the v1 category (what classify scoring
    already grades against); techniques = the triage_review MITRE id; scope =
    the actor hosts plus attack-traffic source hosts, and the user-tagged
    accounts; root_cause = the first chain step for attacks, null for FPs.

Anything the rules cannot tag is a hard error listing the step — add an
explicit OVERRIDES entry instead of letting the script guess.

Each generated file is verified before writing:
  1. parsed attack steps minus tags == parsed v1 chain (deep equality)
  2. every verbatim section == its v1 original (deep equality)
  3. scenario_loader_v2.validate_scenario_v2 passes

Run from backend/:  python scenarios/migrate_v1_to_v2.py
Writes scenarios/v2/<label>.yaml and scenarios/v2/MIGRATION_REPORT.md.
Idempotent; overwrites previous output.
"""
import copy
import json
import os
import re
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
V2_DIR = os.path.join(HERE, "v2")
sys.path.insert(0, BACKEND)

import scenario_corrections  # noqa: E402
import scenario_loader as v1  # noqa: E402
import scenario_loader_v2 as v2  # noqa: E402

# --- reference environment (the plan's server mapping table) ---------------
# Emitted hostnames/ips stay in {infra.*} placeholder form; the literals here
# are only used in the migration report for reviewer context.
SERVER_TABLE = {
    "dc":     ("ACME-SVR01", "10.0.1.200", "Domain Controller"),
    "file":   ("ACME-SVR02", "10.0.1.201", "File Server"),
    "dns":    ("ACME-SVR03", "10.0.1.202", "DNS Server"),
    "print":  ("ACME-SVR04", "10.0.1.203", "Print Server"),
    "web":    ("ACME-SVR05", "10.0.1.204", "Web Server"),
    "proxy":  ("ACME-SVR06", "10.0.1.205", "Proxy (PAN-OS VM-Series)"),
    "backup": ("ACME-VEEAM01", "10.0.1.206", "Backup Server"),
    "scan":   ("ACME-SEC01", "10.0.1.207", "Security Scanner"),
}

# Stage 1 review ruling: proxy events follow Palo Alto CIM, so the proxy is
# a PAN-OS appliance, not a Windows server. Like the firewall, it is a log
# source, never a managed endpoint.
ROLE_OS = {"proxy": "PAN-OS"}
# SERVER_TABLE key -> host role when the role name differs from the key.
SERVER_ROLE = {"scan": "scanner"}

# internal_host entities that map onto a reference-environment role.
INTERNAL_HOST_ROLES = {"backup_server": ("backup", "Backup Server")}
FW_HOSTNAME = "ACME-FW01"  # hardcoded per the reference environment
FW_IP = "10.0.1.254"

ORG_NAME = "ACME Corp"
ORG_DOMAIN = "acme.local"

# Stage 2 detections, authored per scenario (keyed by label). Each fires on a
# trigger step id and carries a server-side disposition. Rule names and
# descriptions are ORIGINAL (no SigmaHQ rule text copied), so the Detection
# Rule License attribution requirement does not attach; "sigma_behavioral"
# denotes the behavioral-rule format, not adapted SigmaHQ content. YARA-typed
# detections simulate a signature hit (yara_rule_name is a fictional Spectyr
# signature). Attack scenarios carry a true_positive on the trigger; the five
# FP scenarios carry a false_positive. Ambient benign_expected detections are
# generated at runtime from detection_templates.py, not authored here.
def _det(id, rule_name, rule_type, severity, triggers, disposition,
         description, mitre=None, yara_rule_name=None):
    d = {"id": id, "rule_name": rule_name, "rule_type": rule_type,
         "severity": severity, "triggers": triggers,
         "disposition": disposition, "description": description}
    if mitre:
        d["mitre"] = {"id": mitre[0], "tactic": mitre[1]}
    if yara_rule_name:
        d["yara_rule_name"] = yara_rule_name
    return d


DETECTIONS = {
    "brute_force_attack": [_det(
        "det_lockout", "Account Lockout After Repeated External Failures",
        "sigma_behavioral", "high", ["s5"], "true_positive",
        "A domain account locked out (4740) after a burst of failed logons "
        "from a single external source, consistent with online password "
        "guessing.", mitre=("T1110.001", "Credential Access"))],
    "c2_dns_tunnel": [_det(
        "det_dns_tunnel", "Anomalous DNS TXT Query Volume to Rare Domain",
        "sigma_behavioral", "high", ["s3"], "true_positive",
        "Repeated TXT lookups to non-standard subdomains of a rarely seen "
        "parent domain, a common DNS tunneling and C2 pattern.",
        mitre=("T1071.004", "Command and Control"))],
    "c2_http": [_det(
        "det_beacon", "Periodic HTTPS Beacon to Uncategorized Domain",
        "sigma_behavioral", "high", ["s3"], "true_positive",
        "Regular-interval outbound HTTPS connections to a domain absent from "
        "any allowlist, consistent with C2 beaconing.",
        mitre=("T1071.001", "Command and Control"))],
    "data_exfil_archive": [_det(
        "det_exfil_upload", "Outbound Transfer to Consumer File-Sharing Host",
        "sigma_behavioral", "high", ["s5"], "true_positive",
        "A large outbound transfer to a consumer file-sharing service shortly "
        "after local archive creation, consistent with staged exfiltration.",
        mitre=("T1560.001", "Collection"))],
    "defense_evasion": [_det(
        "det_av_disabled", "Endpoint Protection Real-Time Scanning Disabled",
        "sigma_behavioral", "high", ["s2"], "true_positive",
        "Defender real-time protection was turned off (5007) outside a "
        "maintenance window, a common precursor to payload execution.",
        mitre=("T1562.001", "Defense Evasion"))],
    "defense_evasion_log_clearing": [_det(
        # classification_event ruling (2026-07-16): bound to the 1102 step s5.
        "det_log_cleared", "Windows Security Event Log Cleared (1102)",
        "sigma_behavioral", "high", ["s5"], "true_positive",
        "The Windows Security event log was cleared (1102). Clearing destroys "
        "forensic evidence and, absent a change record, indicates an attacker "
        "removing traces.", mitre=("T1070.001", "Defense Evasion"))],
    "insider_shadow_it": [_det(
        "det_shadow_upload", "Upload to Unsanctioned Cloud Storage",
        "sigma_behavioral", "medium", ["s5"], "true_positive",
        "Sensitive files uploaded to an unsanctioned cloud provider by an "
        "unapproved application, consistent with insider data movement.",
        mitre=("T1567.002", "Exfiltration"))],
    "insider_staging": [_det(
        "det_staging", "Sensitive Share Access Then Local Staging",
        "sigma_behavioral", "medium", ["s5"], "true_positive",
        "A user accessed a sensitive file share outside their role and staged "
        "a copy locally before an outbound connection.",
        mitre=("T1074.001", "Collection"))],
    # Density pilot (Stage 2 content pass): 2 TP + 1 coexisting FP. Severity
    # deliberately inverted (FP is high, one TP is medium) so severity never
    # reveals disposition; two scan-shaped detections can't be told apart by
    # rule-name class.
    "lateral_movement_1": [
        _det("det_lateral_logon",
             "Anomalous Internal Logon Following Connection Sweep",
             "sigma_behavioral", "high", ["s5"], "true_positive",
             "A network logon landed on the file server from a workstation "
             "that had just probed its service ports. No admin task or ticket "
             "explains it; the account is a standard user.",
             mitre=("T1046", "Discovery")),
        _det("det_portscan_exec",
             "Network Scanning Utility Executed from User Profile",
             "sigma_behavioral", "medium", ["s1"], "true_positive",
             "nmap ran from a standard user's Downloads folder on a non-IT "
             "workstation. Scanning tools there are unusual; here it is the "
             "recon that precedes the lateral logon.",
             mitre=("T1046", "Discovery")),
        _det("det_scanner_sweep",
             "Rapid Internal Port Connections Across Segment",
             "sigma_behavioral", "high", ["sup2"], "false_positive",
             "The security team's authenticated vulnerability scanner ran its "
             "scheduled sweep from the scanner host, connecting rapidly to "
             "many internal hosts including the file server, and tripped a "
             "lateral-recon rule. The source is the scanner host under a "
             "service account on the scan schedule.")],
    "lateral_movement_2": [_det(
        "det_lsass", "LSASS Process Memory Access",
        "sigma_behavioral", "critical", ["s2"], "true_positive",
        "A non-system process opened a handle to lsass.exe memory, the "
        "signature action of credential dumping.",
        mitre=("T1003.001", "Credential Access"))],
    "malware_ransomware": [_det(
        "det_ransom_note", "Ransom Note File Signature Match",
        "yara", "high", ["s3"], "true_positive",
        "A file matching a generic ransom-note signature was written to disk "
        "amid mass file renames with an unfamiliar extension.",
        mitre=("T1486", "Impact"),
        yara_rule_name="Spectyr_Ransom_Note_Generic")],
    "malware_usb": [_det(
        "det_usb_exec", "Executable Launched from Removable Media",
        "yara", "high", ["s2"], "true_positive",
        "A binary matching a suspicious-loader signature executed directly "
        "from a removable drive path.",
        mitre=("T1091", "Initial Access"),
        yara_rule_name="Spectyr_USB_Loader_Generic")],
    "password_spray": [_det(
        "det_spray", "Password Spray Pattern Across Many Accounts",
        "sigma_behavioral", "high", ["s6"], "true_positive",
        "One source attempted single logons against many distinct accounts in "
        "a short window, then authenticated successfully, the password-spray "
        "signature.", mitre=("T1110.003", "Credential Access"))],
    "phishing_1": [_det(
        "det_impossible_travel", "Entra Impossible-Travel Risk Detection",
        "sigma_behavioral", "high", ["s4"], "true_positive",
        "Entra ID flagged risky sign-in activity from an unexpected location "
        "after a credential-harvest page interaction.",
        mitre=("T1583.001", "Resource Development"))],
    "phishing_link": [_det(
        "det_link_payload", "Payload Process Spawned After Email Link Click",
        "sigma_behavioral", "high", ["s3"], "true_positive",
        "A process launched from a user profile path shortly after the user "
        "followed a link to a lookalike domain.",
        mitre=("T1566.002", "Initial Access"))],
    "false_positive_oauth": [_det(
        "det_fp_oauth", "Impossible-Travel Sign-In (OAuth Refresh Token)",
        "sigma_behavioral", "medium", ["s4"], "false_positive",
        "An impossible-travel risk event driven by modern-auth OAuth refresh "
        "tokens after an endpoint migration, a common benign trigger.")],
    "false_positive_pentest": [_det(
        "det_fp_pentest", "Credential-Harvest POST to Lookalike Domain",
        "sigma_behavioral", "medium", ["s3"], "false_positive",
        "A credential-submission POST to a lookalike domain generated by an "
        "authorized security-awareness phishing simulation.")],
    "false_positive_robocopy": [_det(
        "det_fp_robocopy", "Bulk File Copy by Service Account",
        "sigma_behavioral", "medium", ["s1"], "false_positive",
        "A scheduled service account copied a large volume of files to a cloud "
        "endpoint as part of a planned migration project.")],
    "false_positive_ssl_inspection": [_det(
        "det_fp_ssl", "Repeated TLS Handshake Failures Resembling Beacon",
        "sigma_behavioral", "medium", ["s2"], "false_positive",
        "Regular-interval TLS handshake failures caused by an expanded "
        "corporate proxy SSL-inspection policy, not C2.")],
    # Density pilot 2: 3 FP, all TP-looking, spanning Medium/High/Critical.
    # The scenario must read like it might contain a real threat until the
    # analyst reads the evidence (signed Veeam binary, internal backup
    # destination, backup schedule). No supplemental events needed: every
    # benign chain step is available to trigger on.
    "false_positive_veeam": [
        _det("det_fp_veeam", "Periodic Outbound Beacon to Internal Host",
             "sigma_behavioral", "high", ["s3"], "false_positive",
             "The endpoint backup agent makes regular, fixed-interval outbound "
             "connections to the backup server. The cadence reads like C2 "
             "beaconing. It is the signed Veeam agent to the internal backup "
             "server, running under SYSTEM on the backup schedule."),
        _det("det_veeam_bulk_egress", "Large Off-Hours Data Egress Volume",
             "sigma_behavioral", "critical", ["s5"], "false_positive",
             "Over 1.75 GB left the host outside business hours, the "
             "volume-plus-timing shape of staged exfiltration. It is the "
             "nightly full backup completing to the internal repository, "
             "logged by Veeam itself."),
        _det("det_veeam_svc_persist",
             "Service Binary Establishing Scheduled Outbound",
             "sigma_behavioral", "medium", ["s2"], "false_positive",
             "A service binary that establishes regular outbound connections "
             "overlaps with C2 service persistence. It is the signed Veeam "
             "endpoint service in Program Files, installed by the backup "
             "deployment.")],
}


# Stage 2 density: authored benign supplemental telemetry, keyed by label.
# Merged into the session pool; referenceable by detections via sup* ids.
# offset is relative to the attack base time and may be negative.
def _sup(id, host, offset, event_type, source_type, severity, hostname,
         message, key_value_pairs, source_ip=None, destination_ip=None,
         user_account=None, log_source=None, user=None, red_herring=False):
    d = {"id": id, "host": host, "offset": offset, "event_type": event_type,
         "source_type": source_type, "log_source": log_source or source_type,
         "severity": severity, "hostname": hostname}
    if red_herring:
        d["red_herring"] = True
    if source_ip:
        d["source_ip"] = source_ip
    if destination_ip:
        d["destination_ip"] = destination_ip
    if user_account:
        d["user_account"] = user_account
    if user:
        d["user"] = user
    d["message"] = message
    d["key_value_pairs"] = key_value_pairs
    return d


SUPPLEMENTAL_EVENTS = {
    "lateral_movement_1": [
        # The vulnerability scanner's process on ACME-SEC01. Placed 120s before
        # the attack. DECLARED red herring (Stage 2 review, amendment 1): it
        # sits within the attack's plausible correlation window, so it is a
        # deliberate distractor. The intended resolution is the dismissal
        # evidence (ACME-SEC01 scanner role, svc_vulnscan service account,
        # nessusd scanner process), not the timing.
        _sup("sup1", "scan", -120, "ProcessCreate", "Sysmon", "low",
             "{infra.scan.hostname}", user="svc_vulnscan", red_herring=True,
             source_ip="{infra.scan.ip}", user_account="ACME\\svc_vulnscan",
             message="Process created: nessusd.exe scheduled vulnerability scan",
             key_value_pairs={
                 "event_id": 1,
                 "channel": "Microsoft-Windows-Sysmon/Operational",
                 "computer": "{infra.scan.hostname}",
                 "rule_name": "",
                 "process_id": "4120",
                 "image": "C:\\Program Files\\Tenable\\Nessus\\nessusd.exe",
                 "file_version": "10.7.2",
                 "description": "Nessus Vulnerability Scanner",
                 "product": "Nessus",
                 "company": "Tenable, Inc.",
                 "original_file_name": "nessusd.exe",
                 "command_line": "\"C:\\Program Files\\Tenable\\Nessus\\nessusd.exe\" -q",
                 "current_directory": "C:\\Program Files\\Tenable\\Nessus\\",
                 "user": "ACME\\svc_vulnscan",
                 "terminal_session_id": "0",
                 "integrity_level": "System",
                 "parent_process_id": "784",
                 "parent_image": "C:\\Windows\\System32\\services.exe",
                 "parent_command_line": "C:\\Windows\\System32\\services.exe",
                 "parent_user": "NT AUTHORITY\\SYSTEM",
             }),
        # The scanner's rapid connections across the segment, reported by the
        # firewall (det_scanner_sweep triggers here). 118s before the attack;
        # DECLARED red herring (within the correlation window).
        _sup("sup2", "scan", -118, "ALLOW", "Firewall", "medium",
             "ACME-FW01", red_herring=True, source_ip="{infra.scan.ip}",
             destination_ip="{infra.file.ip}",
             message="Scheduled scan connections from {infra.scan.hostname} to "
                     "{infra.file.hostname} across service ports 22,80,443,445,3389",
             key_value_pairs={
                 "src_ip": "{infra.scan.ip}",
                 "dst_ip": "{infra.file.ip}",
                 "src_port": "51200",
                 "dest_port": "445",
                 "transport": "tcp",
                 "action": "allow",
                 "app": "vuln-scan",
                 "dvc": "ACME-FW01",
                 "rule": "security_scanning",
             }),
    ],
}


# One-off external actors referenced by supplemental events (none for the
# pilots; the scanner is a canonical internal actor).
SUPPLEMENTAL_ENTITIES = {}

# Canonical non-roster accounts to declare in a scenario's environment when its
# supplemental events reference them (mirrors app.SERVICE_ACCOUNTS). id ->
# environment account entry.
CANONICAL_ACCOUNTS = {
    "svc_vulnscan": {
        "id": "svc_vulnscan", "username": "svc_vulnscan", "domain": "ACME",
        "type": "service", "host": "scan",
        "groups": ["Domain Users", "Scanning Service Accounts"],
    },
}

# Which canonical accounts each scenario's supplemental content needs.
SCENARIO_CANONICAL_ACCOUNTS = {
    "lateral_movement_1": ["svc_vulnscan"],
}


# OS labels are simulation metadata (nothing renders them until Stage 1).
# Stage 0 review outcome: workstations default to Windows 11 Enterprise,
# EXCEPT scenarios whose chain embeds Win10-specific artifacts on the
# workstation (10.0.19041.* system binary versions, explicit "Windows 10"
# device strings) — those keep the Win10 label so the environment never
# contradicts the rendered evidence. Servers stay WS2019, firewall PAN-OS.
WS_OS = "Windows 11 Enterprise"
SRV_OS = "Windows Server 2019"
FW_OS = "PAN-OS"                  # firewall/proxy logs follow Palo Alto CIM

# label -> the workstation-hosted Win10 evidence that pins the label.
WIN10_WS_LABELS = {
    "c2_http": "s1 rundll32.exe file_version 10.0.19041.1",
    "defense_evasion": "s1 system binary file_version 10.0.19041.1",
    "defense_evasion_log_clearing": "s4/s6 system binary file_version 10.0.19041.1",
    "false_positive_oauth": "s1/s3 DeviceDetail 'Windows 10 - Compliant - Entra Joined'",
    "false_positive_robocopy": "s1 robocopy.exe file_version 10.0.19041.1",
    "malware_ransomware": "s2 system binary file_version 10.0.19041.1",
    "phishing_link": "s4 system binary file_version 10.0.19041.1",
}

# Sources that are host-local telemetry: an event from one of these on host X
# means the activity occurred on X.
ENDPOINT_SOURCES = {"Sysmon", "Windows Security", "Windows Defender", "Defender", "Veeam"}
# Sources that observe traffic: the actor is whoever originated the traffic.
SENSOR_SOURCES = {"DNS", "Proxy", "Firewall"}

# --- per-scenario overrides (reviewed by hand, they ARE the decision record) -
# step_users / step_hosts are keyed by 0-based chain index.
OVERRIDES = {
    "password_spray": {
        # The spray's 4625/4624 account names are literal roster usernames in
        # the v1 chain (grandfathered; parity forbids touching them). Declare
        # them as environment accounts and tag each step with its target.
        "extra_accounts": [
            {"id": u, "username": u, "domain": "ACME", "type": "user"}
            for u in ("dpark", "mjohnson", "bwilliams", "achen", "jkim", "lgreen")
        ],
        "step_users": {0: "dpark", 1: "mjohnson", 2: "bwilliams", 3: "achen",
                       4: "jkim", 5: "lgreen"},
        "flags": [
            "Literal sprayed usernames (dpark, mjohnson, bwilliams, achen, jkim, "
            "lgreen) are pre-existing v1 chain content, grandfathered for parity. "
            "They are also roster employees, so the runtime victim pick can "
            "collide with a sprayed account (pre-existing v1 behavior).",
            "lgreen is the compromised account (4624 success); the other five "
            "were targeted but not breached. answer_key.scope treats all six "
            "as involved, matching the triage guidance to reset every "
            "targeted account.",
        ],
    },
    "false_positive_veeam": {
        "flags": [
            "backup_server (ACME-VEEAM01, 10.0.1.206) is the canonical "
            "backup role of the reference environment; the environment entry "
            "references it through {backup_server.*} placeholders. Optional "
            "cleanup, deferred: retire the entity in favor of "
            "{infra.backup.*} references.",
        ],
    },
    "false_positive_robocopy": {
        "flags": [
            "Step 2's hostname field carries {infra.file.ip} (an IP in a "
            "hostname slot) in the v1 source. Preserved byte-for-byte for "
            "parity; flagged for the schema correction workflow.",
        ],
    },
    "false_positive_ssl_inspection": {
        "flags": [
            "ACME-PROXY-CA (inspection CA name) stays as authored: a CA "
            "common name is an org naming choice, not a device reference, "
            "so it does not conflict with the reference environment.",
        ],
    },
}

# ATT&CK ID audit (Stage 0 review follow-up 5; closed at Stage 1 review).
# Verified 2026-07-16 against attack.mitre.org (Enterprise): 13 of 15 IDs
# confirmed live by fetch, T1562.001 and T1070.001 confirmed live by the
# reviewer the same day. All 15 current.
ATTACK_AUDIT = {
    "result": "All 15 answer_key technique IDs are current; none deprecated, "
              "revoked, or merged. Zero ID replacements. All 15 verified "
              "live against attack.mitre.org on 2026-07-16.",
    "flags": [
        "T1046 display-name drift resolved at Stage 1 review: renamed to "
        "'Network Service Discovery' in the v2 triage copy via approved "
        "triage corrections (scenario_corrections.py); the frozen v1 corpus "
        "keeps the old name. CANONICAL_TECHNIQUE_NAMES in "
        "test_scenario_loader_v2.py guards future drift.",
    ],
}

GLOBAL_FLAGS = [
    "OS labels (Stage 0 review outcome): workstations Windows 11 Enterprise "
    "by default; the scenarios listed under 'Windows 10 label kept' below "
    "keep Windows 10 Enterprise because their chains embed Win10-specific "
    "workstation artifacts. Servers Windows Server 2019, firewall PAN-OS. "
    "Full version string formatting (edition/release/build) is deferred to "
    "Stage 1.",
    "Server-side Sysmon steps (lateral_movement_1/2 net.exe on the file "
    "server) carry file_version 10.0.19041.1, a Windows 10 2004-era build, on "
    "a host labeled Windows Server 2019. Pre-existing v1 content; parity "
    "forbids changing it here. Flagged for the schema correction workflow.",
    "The proxy role (ACME-SVR06) is named like a Windows server while "
    "proxy/firewall log fields follow Palo Alto CIM. Which OS its Stage 1 "
    "endpoint page should show needs a call before Stage 1.",
    "root_cause is set to the FIRST chain step of every attack scenario "
    "(patient zero = earliest malicious event). Distinct from the trigger "
    "step, which is where the analyst ENTERS the scenario.",
    "Corpus-wide, Proxy steps carry the CLIENT hostname in dvc "
    "({victim.hostname}); Splunk CIM defines dvc as the reporting device, "
    "which for proxy logs is the proxy itself. Pre-existing v1 convention "
    "across 14 steps; NOT changed (each change needs its own approved "
    "correction). Flagged for the schema correction workflow.",
]


def emit(v):
    return json.dumps(v)  # JSON escaping == YAML double-quoted scalar


# --- inference ---------------------------------------------------------------

def entity_sets(doc):
    employees = {n for n, s in doc["entities"].items() if s["type"] == "employee"}
    internals = {n: s for n, s in doc["entities"].items()
                 if s["type"] == "internal_host"}
    return employees, internals


def actor_from_source_ip(step, employees, internals):
    src = step.get("source_ip", "")
    m = re.fullmatch(r"\{([a-z][a-z0-9_]*)\.ip\}", src)
    if m:
        name = m.group(1)
        if name in employees:
            return f"ws_{name}"
        if name in internals:
            return name
    m = re.fullmatch(r"\{infra\.([a-z]+)\.ip\}", src)
    if m:
        return m.group(1)
    return None


def infer_step_tags(doc, label):
    """Per step: (step_id, host_tag, user_tag_or_None). Hard error on any step
    the rules cannot tag and no override covers."""
    employees, internals = entity_sets(doc)
    over = OVERRIDES.get(label, {})
    tags = []
    problems = []
    for i, step in enumerate(doc["chain"]):
        hn = step.get("hostname", "")
        st = step.get("source_type", "")

        host = over.get("step_hosts", {}).get(i)
        if host is None:
            m = re.fullmatch(r"\{([a-z][a-z0-9_]*)\.hostname\}", hn)
            if m and m.group(1) in employees:
                host = f"ws_{m.group(1)}"
            elif m and m.group(1) in internals:
                host = m.group(1)
            else:
                m = re.fullmatch(r"\{infra\.([a-z]+)\.(?:hostname|ip)\}", hn)
                if m and st in ENDPOINT_SOURCES:
                    host = m.group(1)
                elif m and st in SENSOR_SOURCES:
                    host = actor_from_source_ip(step, employees, internals)
                elif hn == FW_HOSTNAME:
                    host = actor_from_source_ip(step, employees, internals)
                else:
                    literal = next((n for n, s in internals.items()
                                    if s.get("hostname") == hn), None)
                    host = literal
        if host is None:
            problems.append(f"step {i}: hostname={hn!r} source_type={st!r}")
            tags.append((f"s{i+1}", None, None))
            continue

        user = over.get("step_users", {}).get(i)
        if user is None:
            text = json.dumps(step)
            hits = sorted(e for e in employees
                          if f"{{{e}.username}}" in text or f"{{{e}.user_domain}}" in text)
            if len(hits) > 1:
                problems.append(f"step {i}: multiple employee refs {hits}")
            user = hits[0] if len(hits) == 1 else None

        tags.append((f"s{i+1}", host, user))

    if problems:
        raise SystemExit(
            f"[FLAG] {label}: cannot infer tags, add an OVERRIDES entry:\n  "
            + "\n  ".join(problems)
        )
    return tags


def build_environment(doc, tags, label):
    """hosts + accounts inferred from the chain AND the scenario's supplemental
    events (which may reference canonical hosts/accounts not in the chain)."""
    employees, internals = entity_sets(doc)
    over = OVERRIDES.get(label, {})
    sup_events = SUPPLEMENTAL_EVENTS.get(label, [])
    # supplemental events can pull in canonical hosts (infra.*) the chain never
    # touches; scan both when deciding which hosts the environment declares.
    chain_text = json.dumps(doc["chain"]) + json.dumps(sup_events)
    tag_hosts = {h for _, h, _ in tags} | {s["host"] for s in sup_events}

    hosts = []
    for name in doc["entities"]:  # declaration order
        if name not in employees:
            continue
        if (f"{{{name}.hostname}}" in chain_text or f"{{{name}.ip}}" in chain_text):
            ws_os = "Windows 10 Enterprise" if label in WIN10_WS_LABELS else WS_OS
            hosts.append({
                "id": f"ws_{name}", "role": "workstation",
                "hostname": f"{{{name}.hostname}}", "ip": f"{{{name}.ip}}",
                "os": ws_os, "desc": "User workstation",
            })
    for key, (_hn, _ip, desc) in SERVER_TABLE.items():
        if f"{{infra.{key}." in chain_text:
            hosts.append({
                "id": key, "role": SERVER_ROLE.get(key, key),
                "hostname": f"{{infra.{key}.hostname}}",
                "ip": f"{{infra.{key}.ip}}",
                "os": ROLE_OS.get(key, SRV_OS), "desc": desc,
            })
    if FW_HOSTNAME in chain_text:
        hosts.append({
            "id": "fw_perimeter", "role": "firewall",
            "hostname": FW_HOSTNAME, "ip": FW_IP,
            "os": FW_OS, "desc": "Perimeter Firewall",
        })
    for name in internals:
        role, desc = INTERNAL_HOST_ROLES.get(name, ("server", "Internal server"))
        hosts.append({
            "id": name, "role": role,
            "hostname": f"{{{name}.hostname}}", "ip": f"{{{name}.ip}}",
            "os": SRV_OS, "desc": desc,
        })

    host_ids = {h["id"] for h in hosts}
    missing = tag_hosts - host_ids
    if missing:
        raise SystemExit(f"[FLAG] {label}: step tags reference hosts not in the "
                         f"inferred environment: {sorted(missing)}")

    accounts = []
    for name in doc["entities"]:
        if name in employees:
            acct = {"id": name, "username": f"{{{name}.username}}",
                    "domain": "ACME", "type": "user"}
            if f"ws_{name}" in host_ids:
                acct["host"] = f"ws_{name}"
            accounts.append(acct)
    accounts.extend(over.get("extra_accounts", []))
    # canonical service/admin accounts this scenario's supplemental content
    # references (e.g. the scanner's svc_vulnscan)
    for acct_id in SCENARIO_CANONICAL_ACCOUNTS.get(label, []):
        accounts.append(dict(CANONICAL_ACCOUNTS[acct_id]))
    return hosts, accounts


def build_answer_key(doc, tags, label):
    employees, internals = entity_sets(doc)
    is_fp = doc["category"] == "False Positive"

    scope_hosts = []
    for _, h, _ in tags:
        if h not in scope_hosts:
            scope_hosts.append(h)
    # A host that only ever appears as the SOURCE of attack traffic (its own
    # telemetry never fires) is still involved — e.g. the workstation a
    # password spray originates from.
    for step in doc["chain"]:
        src_host = actor_from_source_ip(step, employees, internals)
        if src_host and src_host not in scope_hosts:
            scope_hosts.append(src_host)

    scope_accounts = []
    for _, _, u in tags:
        if u and u not in scope_accounts:
            scope_accounts.append(u)

    mitre_id = doc["triage_review"].get("mitre", {}).get("id")
    return {
        "classification": doc["category"],
        "scope": {"hosts": scope_hosts, "accounts": scope_accounts},
        "root_cause": None if is_fp else tags[0][0],
        "techniques": [] if is_fp else [mitre_id],
        "actions": [],
    }


# --- emission ---------------------------------------------------------------

def emit_environment(hosts, accounts):
    L = ["environment:"]
    L.append("  org:")
    L.append(f"    name: {emit(ORG_NAME)}")
    L.append(f"    domain: {emit(ORG_DOMAIN)}")
    L.append("  hosts:")
    for h in hosts:
        L.append(f"    - id: {emit(h['id'])}")
        for k in ("role", "hostname", "ip", "os", "desc"):
            L.append(f"      {k}: {emit(h[k])}")
    L.append("  accounts:")
    for a in accounts:
        L.append(f"    - id: {emit(a['id'])}")
        for k in ("username", "domain", "type", "host"):
            if k in a:
                L.append(f"      {k}: {emit(a[k])}")
        if a.get("groups"):
            L.append(f"      groups: {emit(a['groups'])}")
    return L


def emit_supplemental(events, entities):
    L = ["supplemental_events:"]
    if not events:
        L[-1] = "supplemental_events: []"
    for e in events:
        L.append(f"  - id: {emit(e['id'])}")
        L.append(f"    host: {emit(e['host'])}")
        if "user" in e:
            L.append(f"    user: {emit(e['user'])}")
        L.append(f"    offset: {json.dumps(e['offset'])}")
        if e.get("red_herring"):
            L.append("    red_herring: true")
        for k in ("event_type", "source_type", "log_source", "severity",
                  "hostname", "source_ip", "destination_ip", "user_account",
                  "message"):
            if k in e and e[k] not in (None, ""):
                L.append(f"    {k}: {emit(e[k])}")
        if e.get("key_value_pairs"):
            L.append("    key_value_pairs:")
            for k, v in e["key_value_pairs"].items():
                L.append(f"      {k}: {emit(v)}")
    L.append("")
    if entities:
        L.append("supplemental_entities:")
        for ent in entities:
            L.append(f"  - id: {emit(ent['id'])}")
            for k in ("type", "value", "description"):
                L.append(f"    {k}: {emit(ent[k])}")
    else:
        L.append("supplemental_entities: []")
    return L


def emit_answer_key(ak):
    L = ["answer_key:"]
    L.append(f"  classification: {emit(ak['classification'])}")
    L.append("  scope:")
    L.append(f"    hosts: {emit(ak['scope']['hosts'])}")
    L.append(f"    accounts: {emit(ak['scope']['accounts'])}")
    L.append(f"  root_cause: {'null' if ak['root_cause'] is None else emit(ak['root_cause'])}")
    L.append(f"  techniques: {emit(ak['techniques'])}")
    L.append("  actions: []")
    return L


def emit_detections(dets):
    L = ["detections:"]
    for d in dets:
        L.append(f"  - id: {emit(d['id'])}")
        L.append(f"    rule_name: {emit(d['rule_name'])}")
        L.append(f"    rule_type: {emit(d['rule_type'])}")
        L.append(f"    severity: {emit(d['severity'])}")
        L.append(f"    triggers: {emit(d['triggers'])}")
        if "mitre" in d:
            L.append("    mitre:")
            L.append(f"      id: {emit(d['mitre']['id'])}")
            L.append(f"      tactic: {emit(d['mitre']['tactic'])}")
        if "yara_rule_name" in d:
            L.append(f"    yara_rule_name: {emit(d['yara_rule_name'])}")
        L.append(f"    description: {emit(d['description'])}")
        L.append(f"    disposition: {emit(d['disposition'])}")
    return L


def split_sections(lines):
    """Indices of the v1 file's top-level anchors. The v1 corpus is
    converter-emitted, so the layout is fixed: comments, label:..., chain:,
    triage_review:."""
    label_i = chain_i = triage_i = None
    for i, ln in enumerate(lines):
        if ln.startswith("label:"):
            label_i = i if label_i is None else label_i
        elif ln == "chain:":
            chain_i = i
        elif ln == "triage_review:":
            triage_i = i
    if None in (label_i, chain_i, triage_i):
        raise SystemExit(f"unexpected v1 layout (label/chain/triage_review anchors)")
    return label_i, chain_i, triage_i


def transform_chain_body(body_lines, tags):
    """Rename each step's leading '  - offset:' into the tag block + offset.
    Every other line passes through byte-for-byte."""
    out = []
    step = 0
    for ln in body_lines:
        if ln.startswith("  - offset:"):
            sid, host, user = tags[step]
            step += 1
            out.append(f"  - id: {emit(sid)}")
            out.append(f"    host: {emit(host)}")
            if user:
                out.append(f"    user: {emit(user)}")
            out.append("    " + ln[4:])  # '  - offset: X' -> '    offset: X'
        else:
            out.append(ln)
    if step != len(tags):
        raise SystemExit(f"step anchor mismatch: found {step}, expected {len(tags)}")
    return out


def migrate(fname, report):
    path = os.path.join(HERE, fname)
    with open(path, encoding="utf-8") as f:
        text = f.read()
    doc = yaml.safe_load(text)
    label = doc["label"]
    lines = text.split("\n")

    # Approved schema corrections applied structurally first, so inference
    # (tags, environment, answer key) sees the corrected content. The
    # exact-line rewrites below keep the emitted text byte-faithful
    # everywhere else.
    corrections = scenario_corrections.for_label(label)
    corrected_chain = copy.deepcopy(doc["chain"])
    corrected_entities = copy.deepcopy(doc["entities"])
    corrected_triage = copy.deepcopy(doc["triage_review"])
    for corr in corrections:
        if corr["kind"] == "triage":
            node = corrected_triage
            *parents, leaf = corr["field"].split(".")
            for part in parents:
                node = node[part]
            assert node.get(leaf) == corr["v1"], (
                f"{label}: correction precondition failed on triage_review."
                f"{corr['field']}")
            node[leaf] = corr["v2"]
        elif corr["kind"] == "entity":
            spec = corrected_entities[corr["entity"]]
            assert spec.get(corr["field"]) == corr["v1"], (
                f"{label}: correction precondition failed on entity "
                f"{corr['entity']}.{corr['field']}")
            spec[corr["field"]] = corr["v2"]
        elif corr["field"].startswith("kvp."):
            step = corrected_chain[corr["step"]]
            key = corr["field"][4:]
            assert step["key_value_pairs"].get(key) == corr["v1"], (
                f"{label}: correction precondition failed at step "
                f"{corr['step']} {corr['field']}")
            step["key_value_pairs"][key] = corr["v2"]
        else:
            step = corrected_chain[corr["step"]]
            assert step.get(corr["field"]) == corr["v1"]
            step[corr["field"]] = corr["v2"]
    corrected_doc = {**doc, "chain": corrected_chain, "entities": corrected_entities}

    tags = infer_step_tags(corrected_doc, label)
    hosts, accounts = build_environment(corrected_doc, tags, label)
    answer_key = build_answer_key(corrected_doc, tags, label)

    label_i, chain_i, triage_i = split_sections(lines)
    head = lines[label_i:chain_i]          # label: ... through entities block
    body = lines[chain_i + 1:triage_i]     # chain steps
    tail = lines[triage_i:]                # triage_review: ... to EOF
    while head and head[-1] == "":
        head.pop()
    while body and body[-1] == "":
        body.pop()

    # Approved schema corrections: exact-line rewrites mirroring the
    # structural application above; parity_check_v2.py holds the rendered
    # side of the contract. Entity corrections live in the head section,
    # triage corrections in the tail, step corrections in the chain body.
    # Step corrections match within their own step's line range, so the same
    # line text may be corrected in several steps of one file independently.
    step_starts = [i for i, ln in enumerate(body) if ln.startswith("  - offset:")]
    for corr in corrections:
        if corr["kind"] == "step":
            k = corr["step"]
            lo = step_starts[k]
            hi = step_starts[k + 1] if k + 1 < len(step_starts) else len(body)
            matches = [i for i in range(lo, hi) if body[i] == corr["old_line"]]
            section = body
        else:
            section = head if corr["kind"] == "entity" else tail
            matches = [i for i, ln in enumerate(section) if ln == corr["old_line"]]
        if len(matches) != 1:
            raise SystemExit(
                f"[FLAG] {label}: correction line matched {len(matches)} times "
                f"in its scope, expected exactly 1: {corr['old_line']!r}"
            )
        section[matches[0]] = corr["new_line"]

    L = []
    L.append("# Schema v2 (Phase 2 Stage 0). Migrated from scenarios/%s by" % fname)
    L.append("# scenarios/migrate_v1_to_v2.py; the attack steps are the v1 chain")
    L.append("# byte-for-byte plus id/host/user tags (parity_check_v2.py proves it).")
    L.append("# Edit this file, not the v1 copy, once the loader flag flips to yaml_v2.")
    L.append("schema_version: 2")
    L.extend(head)
    L.append("")
    L.extend(emit_environment(hosts, accounts))
    L.append("")
    L.append("attack:")
    L.extend(transform_chain_body(body, tags))
    L.append("")
    L.append("noise: {}")
    L.append("")
    L.extend(emit_supplemental(SUPPLEMENTAL_EVENTS.get(label, []),
                               SUPPLEMENTAL_ENTITIES.get(label, [])))
    L.append("")
    L.extend(emit_detections(DETECTIONS[label]))
    L.append("")
    L.extend(emit_answer_key(answer_key))
    L.append("")
    L.extend(tail)
    new_text = "\n".join(L)
    if not new_text.endswith("\n"):
        new_text += "\n"

    # --- verify before writing ---
    # The parsed attack minus tags must equal the v1 chain with exactly the
    # approved corrections applied; anything else differing is a migration bug.
    new_doc = yaml.safe_load(new_text)
    stripped = [v2.strip_step(s) for s in new_doc["attack"]]
    assert stripped == corrected_chain, f"{label}: attack != corrected v1 chain after strip"
    assert new_doc["entities"] == corrected_entities, f"{label}: entities diverged"
    assert new_doc["triage_review"] == corrected_triage, f"{label}: triage diverged"
    assert new_doc["detections"] == DETECTIONS[label], f"{label}: detections diverged"
    assert new_doc.get("supplemental_events", []) == SUPPLEMENTAL_EVENTS.get(label, []), \
        f"{label}: supplemental_events diverged"
    assert new_doc.get("supplemental_entities", []) == SUPPLEMENTAL_ENTITIES.get(label, []), \
        f"{label}: supplemental_entities diverged"
    for key in ("label", "category", "difficulty", "threat_pattern", "narrative"):
        assert new_doc[key] == doc[key], f"{label}: section {key} diverged"
    v2.validate_scenario_v2(new_doc, v2._load_schema_v2(), v1._load_schema(),
                            f"v2/{fname}")

    os.makedirs(V2_DIR, exist_ok=True)
    with open(os.path.join(V2_DIR, fname), "w", encoding="utf-8", newline="\n") as f:
        f.write(new_text)

    # --- report section ---
    report.append(f"## {label}")
    report.append("")
    report.append(f"- classification: `{answer_key['classification']}`"
                  f" | root_cause: `{answer_key['root_cause']}`"
                  f" | techniques: `{answer_key['techniques']}`")
    report.append(f"- scope.hosts: `{answer_key['scope']['hosts']}`"
                  f" | scope.accounts: `{answer_key['scope']['accounts']}`")
    report.append(f"- environment hosts: "
                  + ", ".join(f"`{h['id']}` ({h['role']})" for h in hosts))
    report.append(f"- environment accounts: "
                  + (", ".join(f"`{a['id']}`" for a in accounts) or "(none)"))
    report.append("")
    report.append("| step | event | source | hostname (v1 field) | host tag | user tag |")
    report.append("|---|---|---|---|---|---|")
    for i, step in enumerate(doc["chain"]):
        sid, host, user = tags[i]
        trig = " *(trigger)*" if step.get("trigger") else ""
        report.append(
            f"| {sid}{trig} | {step.get('event_type', '')} | "
            f"{step.get('source_type', '')} | `{step.get('hostname', '')}` | "
            f"`{host}` | `{user or '-'}` |"
        )
    for corr in corrections:
        if corr["kind"] == "entity":
            where = f"entity {corr['entity']}.{corr['field']}"
        elif corr["kind"] == "triage":
            where = f"triage_review.{corr['field']}"
        else:
            where = f"step {corr['step'] + 1} {corr['field']}"
        report.append("")
        report.append(f"**CORRECTION ({corr['approved']}):** {where}: "
                      f"`{corr['v1']}` -> `{corr['v2']}` "
                      f"(renders as `{corr['rendered_v2']}`). {corr['reason']}")
    for flag in OVERRIDES.get(label, {}).get("flags", []):
        report.append("")
        report.append(f"**FLAG:** {flag}")
    report.append("")


def main():
    files = sorted(f for f in os.listdir(HERE)
                   if f.endswith(".yaml"))
    report = [
        "# v1 -> v2 Migration Report (Phase 2 Stage 0)",
        "",
        "Generated by scenarios/migrate_v1_to_v2.py. Every scenario below wraps",
        "its v1 original: chain content is byte-identical (verified by deep",
        "equality here and by parity_check_v2.py at the render layer). Review",
        "the inferred tags, environments, and answer keys before Stage 1.",
        "",
        "## Global assumptions and flags",
        "",
    ]
    report.extend(f"- **FLAG:** {f}" for f in GLOBAL_FLAGS)
    report.append("")
    report.append("## Windows 10 label kept (workstation-hosted Win10 artifacts)")
    report.append("")
    report.extend(f"- `{label}`: {why}" for label, why in sorted(WIN10_WS_LABELS.items()))
    report.append("")
    report.append("All other workstations carry Windows 11 Enterprise. "
                  "lateral_movement_1's 10.0.19041.1 artifact sits on the file "
                  "server (s6), not the workstation, so its workstation is "
                  "Windows 11; the server-side artifact remains flagged below.")
    report.append("")
    report.append("## ATT&CK ID audit (follow-up 5)")
    report.append("")
    report.append(ATTACK_AUDIT["result"])
    report.append("")
    report.extend(f"- **FLAG:** {f}" for f in ATTACK_AUDIT["flags"])
    report.append("")

    for fname in files:
        migrate(fname, report)
        print(f"migrated v2/{fname}")

    with open(os.path.join(V2_DIR, "MIGRATION_REPORT.md"), "w",
              encoding="utf-8", newline="\n") as f:
        f.write("\n".join(report) + "\n")
    print(f"\n{len(files)} scenarios migrated; report at scenarios/v2/MIGRATION_REPORT.md")


if __name__ == "__main__":
    main()
