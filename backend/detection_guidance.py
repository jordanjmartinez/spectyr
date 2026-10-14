"""Detection decision-layer content (owner Detections pass, 2026-10-13).

Three client-facing additions to every sanitized detection view, all derived
from OBSERVABLE material only so the Stage 2 leak discipline holds by
construction:

  why       one instance-specific sentence composed by `render_why` from the
            sanitized first triggering event plus the entity. A pure function
            of whitelisted event fields; it never reads the disposition,
            the scenario linkage, or any answer-key state.
  guidance  per-RULE teaching copy keyed by rule_name: a "when this can be
            harmless" line and a 3-5 step "what to check" list. Written as a
            SOC runbook would write it for the rule in the real world, never
            for the corpus: the same rule text ships whether an instance is a
            true positive, a false positive, or ambient benign, so the copy
            carries no verdict (test_detection_guidance.py enforces a
            verdict-word denylist and full corpus coverage).
  mitre     technique NAME and a one-sentence plain gloss, keyed by the
            technique id already serialized (pinned Enterprise ATT&CK v19.1
            names; the coverage guard pins every id the corpus tags).

All text here is original.
"""

# --- ATT&CK v19.1 technique names + plain glosses ------------------------------
# Names match test_scenario_loader_v2.CANONICAL_TECHNIQUE_NAMES for the answer-key
# techniques (a guard asserts equality) and the pinned detection-only techniques.
TECHNIQUES = {
    "T1091": ("Replication Through Removable Media",
              "Malware spreads by being carried in on a USB drive or other removable media and run from it."),
    "T1583.001": ("Acquire Infrastructure: Domains",
                  "Attackers register domains, often lookalikes of real brands, to host phishing pages or command servers."),
    "T1685": ("Disable or Modify Tools",
              "Attackers switch off or weaken security tools such as antivirus so their activity is not blocked or recorded."),
    "T1685.005": ("Disable or Modify Tools: Clear Windows Event Logs",
                  "Attackers clear Windows event logs to destroy the record of what they did on a host."),
    "T1046": ("Network Service Discovery",
              "Attackers scan the network to find which hosts and services are reachable before moving laterally."),
    "T1071.001": ("Application Layer Protocol: Web Protocols",
                  "Malware hides its command-and-control traffic inside ordinary HTTP or HTTPS connections."),
    "T1071.004": ("Application Layer Protocol: DNS",
                  "Malware hides command-and-control traffic or stolen data inside DNS queries and answers."),
    "T1110.001": ("Brute Force: Password Guessing",
                  "An attacker tries many passwords against one account until one works."),
    "T1110.003": ("Brute Force: Password Spraying",
                  "An attacker tries one or a few common passwords against many accounts to avoid lockouts."),
    "T1566.002": ("Phishing: Spearphishing Link",
                  "A targeted email carries a link to a credential-harvesting page or a malicious download."),
    "T1560.001": ("Archive Collected Data: Archive via Utility",
                  "Stolen files are bundled into an archive with a tool such as 7-Zip before being sent out."),
    "T1074.001": ("Data Staged: Local Data Staging",
                  "Collected files are gathered in one local location before exfiltration."),
    "T1486": ("Data Encrypted for Impact",
              "Ransomware encrypts files so they are unusable until a ransom is paid."),
    "T1003.001": ("OS Credential Dumping: LSASS Memory",
                  "Attackers read the LSASS process memory to extract cached passwords and hashes."),
    "T1567.002": ("Exfiltration Over Web Service: Exfiltration to Cloud Storage",
                  "Stolen data is uploaded to a cloud storage service that blends in with normal web traffic."),
    "T1218.011": ("System Binary Proxy Execution: Rundll32",
                  "Attackers run malicious code through the trusted Windows rundll32.exe so it looks legitimate."),
    "T1490": ("Inhibit System Recovery",
              "Attackers delete backups and shadow copies so encrypted or destroyed data cannot be restored."),
    "T1547.001": ("Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                  "A program is registered to start automatically at logon so the attacker keeps access after a reboot."),
    "T1036.005": ("Masquerading: Match Legitimate Resource Name or Location",
                  "Malware is named or placed to look like a legitimate system file."),
    "T1078": ("Valid Accounts",
              "Attackers use real, stolen credentials, so their activity looks like a normal user signing in."),
    "T1543.003": ("Create or Modify System Process: Windows Service",
                  "Attackers install or alter a Windows service so their code runs with system privileges and persists."),
    "T1090": ("Proxy",
              "Traffic is routed through an intermediary to hide its true origin or bypass inspection."),
}


def technique_name(tid):
    return TECHNIQUES.get(tid, (None, None))[0]


def technique_gloss(tid):
    return TECHNIQUES.get(tid, (None, None))[1]


def enrich_mitre(mitre):
    """The serialized mitre block: the authored {id, tactic} plus the pinned
    technique name and gloss (null when the id is unpinned, never a guess)."""
    if not mitre:
        return mitre
    out = dict(mitre)
    out["name"] = technique_name(mitre.get("id"))
    out["gloss"] = technique_gloss(mitre.get("id"))
    return out


# --- per-rule teaching copy ----------------------------------------------------
# rule_name -> {"harmless": one sentence, "checks": 3-5 steps}. Neutral by
# construction: each entry describes when the RULE fires on benign activity in
# any environment and what an analyst verifies, never what this instance is.
GUIDANCE = {
    # brute_force_attack
    "Account Lockout After Repeated External Failures": {
        "harmless": "A user mistyping a changed password from a remembered device, or a stale credential cached on a phone or VPN client, locks accounts out the same way.",
        "checks": [
            "Confirm the failure source: an external IP with no VPN session is different from a known device the user owns.",
            "Count distinct accounts from that source; one account with many failures reads differently from many accounts with one each.",
            "Check whether the lockout was followed by a successful logon from the same source.",
            "Ask the account owner whether they recently changed a password or travelled.",
        ],
    },
    "Repeated Failed Logons from a Single External Source": {
        "harmless": "Misconfigured mail clients, mobile devices with an old password, and monitoring probes retry at a steady rate from one address.",
        "checks": [
            "Resolve the source IP: hosting provider or residential ISP versus a corporate egress or VPN gateway.",
            "Look at the failure reason codes; bad password at a constant rate differs from mixed account-unknown and bad-password noise.",
            "Check for any success from the same source after the failures.",
            "Compare the targeted account's normal sign-in locations.",
        ],
    },
    "Privileged Service Account Locked Out": {
        "harmless": "A service account with a rotated password that was not updated on one scheduled job will fail at the job cadence until it locks out.",
        "checks": [
            "Identify the workstation or server the failures come from and what job runs there under this account.",
            "Match the failure timestamps to a schedule; fixed cadence points to a task, bursts point to a person or tool.",
            "Check the change log for a recent password rotation on the account.",
            "Verify no logon succeeded for the account from an unexpected host.",
        ],
    },
    # c2_dns_tunnel
    "Anomalous DNS TXT Query Volume to Rare Domain": {
        "harmless": "Email authentication checks, some security agents, and certificate validators legitimately issue TXT lookups in volume.",
        "checks": [
            "Identify the process on the host that issued the queries and where it runs from.",
            "Inspect the subdomain labels: long, random-looking labels differ from readable, repeating names.",
            "Check the parent domain's age, registrar, and category in the proxy or threat intel.",
            "Compare the query rate and spacing with the host's normal DNS profile.",
        ],
    },
    "Process from Downloads Generating Anomalous DNS": {
        "harmless": "A user-installed utility or a portable application run from Downloads can resolve many names during an update check.",
        "checks": [
            "Check the binary's signer, file name, and whether it exists on other hosts.",
            "Review the command line for a domain, key, or secret argument.",
            "Trace the parent process: a shell or script launcher differs from an installer or the browser.",
            "Correlate the DNS queries with the process start time.",
        ],
    },
    "High-Volume DNS Query Rate to Single Domain": {
        "harmless": "Telemetry, update, and CDN domains receive bursts of lookups from the agents that use them.",
        "checks": [
            "Check the domain's category and whether other hosts in the estate query it too.",
            "Look at the hostname labels: readable product names differ from encoded strings.",
            "Identify the querying process and its signer.",
            "Confirm whether the answers are normal A records or unusually large TXT responses.",
        ],
    },
    # c2_http
    "Periodic HTTPS Beacon to Uncategorized Domain": {
        "harmless": "New SaaS tools, internal apps on fresh domains, and update services often sit in no proxy category for weeks.",
        "checks": [
            "Identify the process behind the connections and its signer.",
            "Check the domain's registration date and whether any other host in the estate reaches it.",
            "Measure the interval between connections; a fixed heartbeat with small, similar byte counts is the beacon shape.",
            "Look for a process launch or download on the host shortly before the first connection.",
        ],
    },
    "rundll32 Executed Without a Module": {
        "harmless": "Some installers and shell extensions call rundll32 with arguments that the logging truncated or that resolve later.",
        "checks": [
            "Confirm the full command line really carries no DLL path or entry point.",
            "Check the parent process and the user context.",
            "Look for network connections or child processes from this rundll32 instance.",
            "Compare with how rundll32 is normally invoked on this host.",
        ],
    },
    "Periodic HTTPS Connections to External Host": {
        "harmless": "Operating-system telemetry, antivirus cloud lookups, and chat clients all poll fixed endpoints on a timer.",
        "checks": [
            "Identify the destination's owner and whether it is a categorized, allowlisted vendor domain.",
            "Check which process makes the connection and whether it is signed.",
            "Compare against other hosts: an estate-wide pattern differs from one host.",
            "Look at request sizes and timing for a heartbeat shape.",
        ],
    },
    # data_exfil_archive
    "Outbound Transfer to Consumer File-Sharing Host": {
        "harmless": "Users legitimately send large files to a customer or vendor through a consumer sharing service when no sanctioned path exists.",
        "checks": [
            "Confirm the destination is a consumer service rather than the company tenant.",
            "Look for an archive created on the host shortly before the transfer.",
            "Check the transfer size against the user's normal upload volume.",
            "Ask whether a business reason or ticket covers the transfer.",
        ],
    },
    "Outbound Upload to Cloud Storage": {
        "harmless": "Sanctioned OneDrive or SharePoint sync to the corporate tenant produces large uploads every day.",
        "checks": [
            "Check whether the destination is the company tenant or an external account.",
            "Identify the uploading process; the sync client differs from a browser or script.",
            "Compare the upload volume with the user's typical sync activity.",
            "Look for staging activity on the host before the upload.",
        ],
    },
    "Archive Utility Created a Large Archive": {
        "harmless": "Backup agents, build systems, and users packaging project files create large archives routinely.",
        "checks": [
            "Check the parent process: a backup service differs from a shell started by the user.",
            "Look at the archive's path and name; a product's own folder differs from Temp or a user profile.",
            "Review what was archived and whether it matches the user's role.",
            "Look for an outbound transfer of the archive afterwards.",
        ],
    },
    # defense_evasion
    "Endpoint Protection Real-Time Scanning Disabled": {
        "harmless": "Administrators disable real-time scanning briefly during a software install or a troubleshooting session inside a change window.",
        "checks": [
            "Identify who or what changed the setting and under which account.",
            "Check for a change record or maintenance window covering the time.",
            "Look at what ran on the host in the minutes after protection went off.",
            "Confirm whether protection was re-enabled and when.",
        ],
    },
    "Masquerading Binary Executed from Public Folder": {
        "harmless": "A poorly packaged internal tool or a vendor installer sometimes drops a look-alike named binary into a shared folder.",
        "checks": [
            "Compare the file name with the real system binary and check its signer and hash.",
            "Trace the parent process and the user who launched it.",
            "Look for persistence, network connections, or child processes from the binary.",
            "Check whether security tooling was altered just before the launch.",
        ],
    },
    "Windows Defender Policy Setting Modified": {
        "harmless": "Endpoint management agents push Defender exclusions and policy values on a schedule under the SYSTEM context.",
        "checks": [
            "Identify the process that wrote the value and whether it is a signed management agent.",
            "Check the user context: SYSTEM via a management service differs from an interactive user.",
            "Read the new value: a scoped exclusion differs from disabling protection outright.",
            "Confirm the change against the endpoint management console or change log.",
        ],
    },
    # defense_evasion_log_clearing
    "Windows Security Event Log Cleared (1102)": {
        "harmless": "Log rotation jobs and administrators reclaiming disk space clear logs, usually with a backup and a change record.",
        "checks": [
            "Identify the account that cleared the log and whether it is an admin or a service account.",
            "Look for the clearing command and whether it saved a backup first.",
            "Check what happened on the host in the period just before the clear.",
            "Confirm a change record or scheduled task covers the action.",
        ],
    },
    "Event Log Utility Executed to Clear a Log": {
        "harmless": "Scheduled maintenance tasks run wevtutil to archive and clear operational logs.",
        "checks": [
            "Read the command line: which log was cleared and whether a backup path was given.",
            "Check the parent process; a scheduler service differs from an interactive shell.",
            "Identify the user context.",
            "Look for other suspicious activity on the host before the clear.",
        ],
    },
    "Event Log Cleared by Scheduled Process": {
        "harmless": "Log archiving tasks clear operational logs on a schedule after saving them to a backup file.",
        "checks": [
            "Confirm the parent is the task scheduler or a service host and the user is SYSTEM.",
            "Check which log was cleared; an operational log differs from the Security log.",
            "Verify a backup file path appears in the command and exists.",
            "Match the time to a known schedule.",
        ],
    },
    # false_positive_oauth
    "Impossible-Travel Sign-In Risk": {
        "harmless": "VPN exits, mobile carrier routing, and token renewals from a migrated device produce location jumps without any travel.",
        "checks": [
            "Compare the two locations and IPs with the user's known devices and VPN exits.",
            "Check whether the sign-in was interactive or a token refresh.",
            "Look at the device: compliant and known, or unmanaged.",
            "Review what the session accessed afterwards.",
        ],
    },
    "Non-Interactive OAuth Token Activity from New Location": {
        "harmless": "Refresh-token renewals from a device that moved networks or was recently migrated look like new-location activity.",
        "checks": [
            "Identify the application and client that presented the token.",
            "Check whether the device is registered and compliant.",
            "Compare the location with the user's recent interactive sign-ins.",
            "Look for a credential-harvest interaction or a risky sign-in shortly before.",
        ],
    },
    # false_positive_pentest
    "Credential Page Load on Lookalike Domain": {
        "harmless": "Authorized phishing-awareness campaigns deliberately send users to lookalike credential pages.",
        "checks": [
            "Check the domain's owner and whether the security team has a campaign scheduled.",
            "Look at what happened after the page load: credentials submitted, a download, or nothing.",
            "Check how many users reached the same domain in the window.",
            "Review the email that carried the link, if available.",
        ],
    },
    "Outbound POST to External Tracker After Credential Page": {
        "harmless": "Awareness-training platforms record clicks and submissions through a tracking endpoint right after the lure page.",
        "checks": [
            "Identify the tracker's owner: a known training vendor or an unknown host.",
            "Check whether the preceding credential page belongs to the same vendor.",
            "Look at the POST size and content type.",
            "Confirm with the security team whether a campaign is running.",
        ],
    },
    "DNS Resolution of a Newly-Observed Lookalike Domain": {
        "harmless": "Vendors running awareness campaigns, marketing microsites, and typo-squat protection domains all appear as first-seen lookalikes.",
        "checks": [
            "Check the domain's registration date and registrar.",
            "See which hosts resolved it and whether the resolution led to a connection.",
            "Compare the resolved IP with known vendor or hosting ranges.",
            "Look for a related email or campaign notice.",
        ],
    },
    # false_positive_robocopy
    "Bulk File Copy by Service Account": {
        "harmless": "Migration projects and backup jobs copy entire profiles with robocopy under a service account on a schedule.",
        "checks": [
            "Read the command line: source, destination, and whether a log file is named.",
            "Check the parent process and whether the service account is expected to run this job.",
            "Confirm a migration or backup ticket covers the copy.",
            "Verify the destination is an internal or sanctioned location.",
        ],
    },
    "Large Upload to Cloud Storage": {
        "harmless": "Tenant sync clients upload large volumes during migrations, onboarding, and the first sync of a new device.",
        "checks": [
            "Confirm the destination tenant is the company's own.",
            "Identify the uploading process and user.",
            "Compare the volume with any planned migration or sync.",
            "Look for staging or archiving on the host beforehand.",
        ],
    },
    "Mass File Access on File Share": {
        "harmless": "Backups, migrations, indexing services, and antivirus scans read large numbers of files on a share in one pass.",
        "checks": [
            "Identify the account and the process behind the reads.",
            "Check whether the access pattern is sequential (a copy) or selective (a search).",
            "Look for a copy or upload that follows the reads.",
            "Confirm the account's role justifies access to the share.",
        ],
    },
    # false_positive_ssl_inspection
    "Repeated TLS Handshake Failures Resembling Beacon": {
        "harmless": "Certificate-pinned clients fail repeatedly after a proxy inspection policy change, retrying on a fixed timer.",
        "checks": [
            "Read the failure reason and the presented versus expected certificate issuer.",
            "Identify the client process and whether it pins certificates.",
            "Check whether the inspection policy changed recently.",
            "See if other hosts show the same failures to the same destination.",
        ],
    },
    "Client Repeatedly Reconnecting to External Host After TLS Failures": {
        "harmless": "Office and collaboration clients reconnect on a fixed interval when TLS inspection breaks their certificate pinning.",
        "checks": [
            "Identify the process and confirm it is a signed, known client.",
            "Check the destination: a vendor service domain or an unknown host.",
            "Correlate the reconnects with the handshake failures.",
            "Check whether the inspection policy or CA changed.",
        ],
    },
    "Traffic Allowed Around SSL Inspection": {
        "harmless": "Inspection bypass rules exist for pinned applications, banking sites, and health data by policy.",
        "checks": [
            "Identify the firewall rule that permitted the flow and why it exists.",
            "Check the destination owner and category.",
            "Identify the client process on the source host.",
            "Confirm the bypass is documented policy.",
        ],
    },
    # false_positive_veeam
    "Periodic Outbound Beacon to Internal Host": {
        "harmless": "Backup, monitoring, and management agents check in with their internal server on a fixed interval.",
        "checks": [
            "Identify the process and its signer.",
            "Confirm the destination is the expected internal server and port for that product.",
            "Check the user context: a service under SYSTEM differs from a user process.",
            "Match the cadence to the product's schedule.",
        ],
    },
    "Large Off-Hours Data Egress Volume": {
        "harmless": "Nightly backups and scheduled syncs move gigabytes outside business hours to an internal repository or the company tenant.",
        "checks": [
            "Confirm where the data went: an internal repository, the company tenant, or an external host.",
            "Identify the process or job that moved it.",
            "Check the logging source: a backup product reporting its own job differs from a proxy seeing an unknown upload.",
            "Compare with the host's normal nightly volume.",
        ],
    },
    "Service Binary Establishing Scheduled Outbound": {
        "harmless": "Backup and management services run from Program Files, are signed, and connect out on their schedule.",
        "checks": [
            "Check the binary's path, signer, and parent service.",
            "Confirm the destination and port match the product.",
            "Verify the service was installed by a known deployment.",
            "Look for any child processes or unexpected destinations.",
        ],
    },
    # insider_shadow_it
    "Upload to Unsanctioned Cloud Storage": {
        "harmless": "Personal cloud clients left running on a work device upload the user's own files, which may be unsanctioned but not malicious.",
        "checks": [
            "Identify the provider and whether the account is personal or corporate.",
            "Check which files or folders were uploaded and whether they are sensitive.",
            "Identify the application that performed the upload.",
            "Check policy: is the provider blocked, tolerated, or approved.",
        ],
    },
    "Unsanctioned File-Transfer Application Launched from User Profile": {
        "harmless": "Users install consumer sync clients in their profile for personal use without any intent to move corporate data.",
        "checks": [
            "Confirm the application and whether it is on the approved list.",
            "Check what it synced after launch and where.",
            "Look at the user's role and the sensitivity of the data on the host.",
            "Check whether the install was recent and self-initiated.",
        ],
    },
    "Outbound File Upload to Cloud Storage": {
        "harmless": "Corporate OneDrive and SharePoint sync upload files continuously over an authenticated tenant session.",
        "checks": [
            "Confirm the destination tenant and account.",
            "Identify the uploading process.",
            "Check file names or counts for sensitive material.",
            "Compare against the user's normal sync activity.",
        ],
    },
    # insider_staging
    "Sensitive Share Access Then Local Staging": {
        "harmless": "Users preparing a handover or an audit response legitimately copy a batch of files locally before sharing them.",
        "checks": [
            "Confirm the user's role justifies access to the share.",
            "Review what was copied and where it was staged.",
            "Look for an outbound transfer after staging.",
            "Ask the user's manager about an approved reason.",
        ],
    },
    "Sensitive File Share Accessed Outside Role": {
        "harmless": "Role changes, project assignments, and broad group memberships give users access the model did not expect.",
        "checks": [
            "Check the share name and what it holds.",
            "Confirm the user's current role and group memberships.",
            "Look at how much was read and whether copies were made.",
            "Check for staging or transfer activity afterwards.",
        ],
    },
    # lateral_movement_1
    "Anomalous Internal Logon Following Connection Sweep": {
        "harmless": "Administrators and vulnerability scanners probe ports and then authenticate to the same host as part of their job.",
        "checks": [
            "Identify the source host and the account; an admin or scanner account differs from a standard user.",
            "Check the logon type and whether a ticket or scan schedule explains it.",
            "Look at what the session did on the target host after logon.",
            "Check whether the source host ran a scanning tool.",
        ],
    },
    "Network Scanning Utility Executed from User Profile": {
        "harmless": "IT staff and developers run port scanners from their own machines for troubleshooting.",
        "checks": [
            "Check the user's role and whether scanning is part of it.",
            "Read the command line: targets and ports.",
            "Look for a logon to a scanned host afterwards.",
            "Check whether the tool was downloaded recently and from where.",
        ],
    },
    "Rapid Internal Port Connections Across Segment": {
        "harmless": "The security team's vulnerability scanner sweeps many hosts and ports on its schedule.",
        "checks": [
            "Identify the source host and whether it is the known scanner.",
            "Check the account used and whether it is the scanning service account.",
            "Match the time to the scan schedule.",
            "Look for authentication or payload activity following the sweep.",
        ],
    },
    # lateral_movement_2
    "LSASS Process Memory Access": {
        "harmless": "Antivirus engines, EDR sensors, and some diagnostic tools open LSASS with read access as part of normal operation.",
        "checks": [
            "Identify the accessing process and its signer.",
            "Check the granted access mask and the call trace.",
            "Look for a memory dump file written afterwards.",
            "Check where the accessing binary runs from.",
        ],
    },
    "Credential-Dump Tool Executed from Downloads": {
        "harmless": "Engineers use Sysinternals tools such as procdump to capture a crashing application for support.",
        "checks": [
            "Read the command line: which process was targeted and where the dump was written.",
            "Check the user's role and whether a support case exists.",
            "Look for the dump file and any transfer of it.",
            "Check the parent process and how the tool arrived on the host.",
        ],
    },
    "Process Memory Dump Written After LSASS Access": {
        "harmless": "Crash-reporting tools write dumps of hung applications, and support engineers capture dumps of a failing process.",
        "checks": [
            "Identify the process that wrote the dump and the process it dumped.",
            "Check the dump file's path and name.",
            "Look for a transfer or archive of the file afterwards.",
            "Check whether LSASS was the target.",
        ],
    },
    "Process Memory Dump File Created": {
        "harmless": "Windows Error Reporting writes crash dumps for hung or crashed applications routinely.",
        "checks": [
            "Identify the writing process: a signed crash reporter or a user-run tool.",
            "Check which process was dumped.",
            "Look at the path: the error-reporting queue or a Temp or user folder.",
            "Look for a transfer of the file.",
        ],
    },
    # malware_ransomware
    "Ransom Note File Signature Match": {
        "harmless": "Security research samples, awareness-training materials, and signature test files can match a generic note pattern.",
        "checks": [
            "Open the file name and path; a note dropped beside renamed files differs from a document in a research folder.",
            "Identify the writing process and its signer.",
            "Look for mass file renames or an unfamiliar extension on the host.",
            "Check for shadow copy deletion or backup tampering.",
        ],
    },
    "Shadow Copy Deletion via vssadmin": {
        "harmless": "Backup products and administrators delete shadow copies to free disk space or reset a broken backup chain.",
        "checks": [
            "Identify the parent process: a backup service or admin shell versus an unknown binary.",
            "Check the user context and whether a change record exists.",
            "Look for file encryption or ransom-note activity on the host.",
            "Check whether backups elsewhere are intact.",
        ],
    },
    "Rapid Mass File Writes with Unfamiliar Extension": {
        "harmless": "Build systems, archivers, and bulk converters write many files with a new extension in seconds.",
        "checks": [
            "Identify the writing process and where it runs from.",
            "Look at the extension and whether original files were replaced.",
            "Check for a ransom note or shadow copy deletion.",
            "Determine whether the writes touched user documents or a build folder.",
        ],
    },
    # malware_usb
    "Executable Launched from Removable Media": {
        "harmless": "Vendors and field engineers carry signed installers and diagnostic tools on USB drives.",
        "checks": [
            "Check the binary's signer and name.",
            "Identify the user and whether the device was expected.",
            "Look for persistence, network connections, or child processes after the launch.",
            "Check the device registration event for the drive.",
        ],
    },
    "Run Key Persistence to Public-Folder Binary": {
        "harmless": "Some poorly built internal tools and legacy installers register themselves to start from a shared folder.",
        "checks": [
            "Check the binary's signer and whether its name imitates a system component.",
            "Identify the process that wrote the Run key.",
            "Look for how the binary arrived on the host.",
            "Check whether the same key exists on other hosts.",
        ],
    },
    "Executable Launched from Software-Deployment Staging Path": {
        "harmless": "Endpoint management agents stage signed installers and run them from their own staging directory.",
        "checks": [
            "Confirm the parent is the management agent service.",
            "Check the installer's signer and the deployment record.",
            "Read the command line for silent-install flags consistent with a deployment.",
            "Check whether the same package ran on other managed hosts.",
        ],
    },
    # password_spray
    "Password Spray Pattern Across Many Accounts": {
        "harmless": "A misconfigured application that tries a shared password for many mailboxes or service accounts produces the spray shape.",
        "checks": [
            "Identify the source: one external IP, a VPN exit, or an internal host.",
            "Count the distinct accounts and the attempts per account.",
            "Find any successful logon from the same source and what it did next.",
            "Check which accounts succeeded and whether MFA was involved.",
        ],
    },
    "Failed Logons Across Many Accounts from One Source": {
        "harmless": "Directory sync, a mail connector with stale credentials for many users, or a scanner testing accounts can fail across accounts from one host.",
        "checks": [
            "Identify the source host or IP and what runs there.",
            "Look at the failure reason: bad password versus unknown account.",
            "Check the timing: one pass across accounts or repeated rounds.",
            "Look for any success from the source afterwards.",
        ],
    },
    "Repeated Authentication Failures for a Single Account": {
        "harmless": "A scheduled job or service with a stale password fails at a fixed cadence from the same server.",
        "checks": [
            "Identify the source host and whether the account is a service account tied to it.",
            "Check the cadence: fixed intervals point to a job.",
            "Look for a password rotation on the account.",
            "Confirm no success from an unexpected source.",
        ],
    },
    # phishing_1
    "Entra Impossible-Travel Risk Detection": {
        "harmless": "VPN exits, cloud proxies, and token refreshes from a travelling device trigger impossible-travel risk without compromise.",
        "checks": [
            "Compare the locations and IPs with the user's known devices and VPN.",
            "Check whether the sign-in was interactive and whether MFA was satisfied.",
            "Look for a credential-harvest page interaction shortly before.",
            "Review what the session accessed afterwards.",
        ],
    },
    "Credentials Submitted to a Lookalike Domain": {
        "harmless": "Awareness campaigns and brand-protection tests send users to lookalike sign-in pages by design.",
        "checks": [
            "Check the domain's registration date and owner.",
            "Confirm whether a campaign is scheduled with the security team.",
            "Look for a risky or new-location sign-in for the user afterwards.",
            "Check whether other users submitted to the same domain.",
        ],
    },
    "Risky Sign-In From New Location": {
        "harmless": "Non-interactive token refreshes from a compliant device on a new network are a common source of new-location risk.",
        "checks": [
            "Check whether the sign-in was interactive or a token refresh.",
            "Verify the device is registered and compliant and MFA was satisfied.",
            "Compare the location with recent sign-ins.",
            "Look for a phishing interaction before the sign-in.",
        ],
    },
    # phishing_link
    "Payload Process Spawned After Email Link Click": {
        "harmless": "Users download and run legitimate installers from links in vendor emails.",
        "checks": [
            "Check the binary's signer, name, and download source.",
            "Trace the parent process and the preceding browser or mail activity.",
            "Look for persistence or outbound connections after the launch.",
            "Check whether the link's domain is a lookalike.",
        ],
    },
    "Run Key Persistence Written by a Download": {
        "harmless": "Legitimate installers downloaded by the user register their updater in a Run key.",
        "checks": [
            "Identify the process that wrote the key and where the target binary lives.",
            "Check the binary's signer.",
            "Look at how the download arrived and from where.",
            "Check for outbound connections from the registered binary.",
        ],
    },
    "Document Downloaded From an External Site": {
        "harmless": "Users download documents from the company tenant, partners, and vendors all day.",
        "checks": [
            "Check the source domain: the company tenant, a known partner, or an unknown host.",
            "Look at the file type and whether it was opened or executed.",
            "Look for a process launch from the download folder afterwards.",
            "Check the email or link that led to the download, if any.",
        ],
    },
    # ambient benign templates (detection_templates.BENIGN_DETECTIONS)
    "Software Updater Outbound Connection": {
        "harmless": "Browser and application updaters poll vendor endpoints on a timer from every managed workstation.",
        "checks": [
            "Confirm the binary's path and signer match the vendor.",
            "Check the destination is the vendor's update service.",
            "Compare with other workstations: an estate-wide pattern is expected.",
            "Look for any unexpected child processes.",
        ],
    },
    "Microsoft Edge Update Service Beacon": {
        "harmless": "The Edge updater checks Microsoft update endpoints on a schedule on every managed workstation.",
        "checks": [
            "Confirm the binary's path and signer.",
            "Check the destination is a Microsoft update endpoint.",
            "Compare with other workstations.",
            "Look for any unexpected child processes or destinations.",
        ],
    },
    "Backup Agent Periodic Beacon": {
        "harmless": "The endpoint backup agent checks in with the backup server at a fixed interval during backup windows.",
        "checks": [
            "Confirm the binary is the signed backup agent in Program Files.",
            "Check the destination is the backup server on its service port.",
            "Match the cadence to the backup schedule.",
            "Look for any destination outside the backup infrastructure.",
        ],
    },
    "Remote Admin Tool Service Install": {
        "harmless": "Administrators install the PsExec service for remote management inside a change window.",
        "checks": [
            "Identify the administrator account and the source host.",
            "Check for a change record or ticket.",
            "Look at what the service ran on the target.",
            "Check whether the install repeats across many hosts in a short window.",
        ],
    },
    "Vulnerability Scanner Authenticated Sweep": {
        "harmless": "The security team's scanner authenticates to hosts on scan days to inventory patches.",
        "checks": [
            "Confirm the source is the scanner host and the account is the scanning service account.",
            "Match the time to the scan schedule.",
            "Check the agent binary's path and signer.",
            "Look for any activity beyond inventory on the scanned host.",
        ],
    },
    "Backup Agent Bulk File Read via Shadow Copy": {
        "harmless": "Backup agents read large file sets through a volume shadow copy during scheduled backups.",
        "checks": [
            "Confirm the reading process is the signed backup agent.",
            "Match the time to the backup schedule.",
            "Check that files were read, not renamed or rewritten.",
            "Look for shadow copy deletion or a ransom note, which a backup never produces.",
        ],
    },
}

_FALLBACK = {
    "harmless": "Legitimate administration, scheduled jobs, and user activity can match this pattern; the surrounding evidence decides.",
    "checks": [
        "Identify the process or account behind the activity and where it runs from.",
        "Check whether a change record, schedule, or business reason explains it.",
        "Look at what happened on the host immediately before and after.",
        "Compare with the same activity on other hosts in the estate.",
    ],
}


def guidance_for(rule_name):
    g = GUIDANCE.get(rule_name, _FALLBACK)
    return {"harmless": g["harmless"], "checks": list(g["checks"])}


# --- the instance-specific "why" line -----------------------------------------

def _base(p):
    if not p:
        return ""
    return str(p).replace("/", "\\").split("\\")[-1]


def _dir(p):
    if not p:
        return ""
    s = str(p).replace("/", "\\")
    return s.rsplit("\\", 1)[0] if "\\" in s else ""


def _short_account(v):
    if not v or v == "-":
        return ""
    return str(v)


def _words(v):
    """camelCase identifiers (Entra risk types) read as words."""
    import re as _re
    return _re.sub(r"(?<=[a-z])(?=[A-Z])", " ", str(v)).lower()


def _human_bytes(v):
    try:
        n = float(v)
    except (TypeError, ValueError):
        return f"{v} bytes"
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{int(n)} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{v} bytes"


def render_why(event, entity):
    """One plain sentence describing what was observed, from the sanitized
    first triggering event and the entity. Pure function of whitelisted
    fields (timestamp, event_type, source_type, hostname, source_ip,
    destination_ip, user_account, message, key_value_pairs) plus the entity
    host/account; it never consults the disposition or scenario linkage."""
    ev = event or {}
    kv = ev.get("key_value_pairs") or {}
    host = ev.get("hostname") or (entity or {}).get("host") or "an unknown host"
    user = (_short_account(kv.get("user")) or _short_account(ev.get("user_account"))
            or _short_account((entity or {}).get("account")) or "")
    src = ev.get("source_type")
    et = str(ev.get("event_type") or "")
    msg = (ev.get("message") or "").strip()

    def as_user():
        return f" as {user}" if user else ""

    if src == "Sysmon":
        if et == "ProcessCreate" and kv.get("image"):
            s = f"{_base(kv['image'])} ran from {_dir(kv['image']) or 'an unknown path'} on {host}{as_user()}"
            if kv.get("parent_image"):
                s += f", launched by {_base(kv['parent_image'])}"
            return s + "."
        if et == "FileCreate":
            writer = _base(kv.get("image")) or "A process"
            target = kv.get("target_filename")
            if target:
                return f"{writer} wrote {_base(target)} to {_dir(target) or 'an unknown path'} on {host}{as_user()}."
            return f"{writer} wrote a file on {host}{as_user()}."
        if et == "SetValue":
            writer = _base(kv.get("image")) or "A process"
            target = kv.get("target_object")
            s = f"{writer} set the registry value {target} on {host}" if target else f"{writer} set a registry value on {host}"
            if kv.get("details"):
                s += f" to {kv['details']}"
            return s + "."
        if et == "NetworkConnect":
            proc = _base(kv.get("image")) or "A process"
            dest = kv.get("destination_hostname") or kv.get("destination_ip") or ev.get("destination_ip") or "an external host"
            port = kv.get("destination_port")
            return f"{proc} on {host} connected to {dest}{(':' + str(port)) if port else ''}{as_user()}."
        if et == "ProcessAccess":
            return (f"{_base(kv.get('source_image')) or 'A process'} opened a handle to "
                    f"{_base(kv.get('target_image')) or 'another process'} on {host}"
                    f"{(' with access ' + str(kv['granted_access'])) if kv.get('granted_access') else ''}.")
        if et.startswith("WmiEvent"):
            return f"WMI {et.replace('WmiEvent', '').lower() or 'subscription'} activity was recorded on {host}{as_user()}."
    if src == "Windows Security":
        acct = _short_account(kv.get("account_name")) or user or "an account"
        dom = kv.get("account_domain") or kv.get("domain_name")
        full = f"{dom}\\{acct}" if dom and "\\" not in acct and "@" not in acct else acct
        origin = kv.get("src_ip") or ev.get("source_ip") or kv.get("workstation_name")
        if et == "4625":
            reason = kv.get("failure_reason") or kv.get("status")
            s = f"A logon for {full} failed on {host}"
            if origin:
                s += f" from {origin}"
            if reason:
                s += f" ({reason})"
            return s + "."
        if et == "4624":
            s = f"{full} logged on to {host}"
            if origin:
                s += f" from {origin}"
            if kv.get("logon_type"):
                s += f" (logon type {kv['logon_type']})"
            return s + "."
        if et == "4740":
            target = kv.get("target_account_name") or acct
            s = f"The account {target} was locked out on {host}"
            if kv.get("caller_computer_name") and kv["caller_computer_name"] != "-":
                s += f"; the lockout came from {kv['caller_computer_name']}"
            return s + "."
        if et == "1102":
            return f"The Security event log on {host} was cleared by {full}."
        if et == "5140":
            share = kv.get("share_name")
            s = f"{full} accessed {('share ' + share) if share else 'a network share'} on {host}"
            if origin:
                s += f" from {origin}"
            return s + "."
        if et == "4663":
            obj = kv.get("object_name")
            proc = _base(kv.get("process_name"))
            s = f"{full} accessed {obj or 'an object'} on {host}"
            if proc:
                s += f" via {proc}"
            return s + "."
        if et == "6416":
            dev = kv.get("device_name") or "A new external device"
            return f"{dev} was recognized on {host}{as_user()}."
    if src == "Defender":
        return f"{msg or 'A Windows Defender setting changed'} on {host}{as_user()}."
    if src == "Proxy":
        who = _short_account(kv.get("src_user")) or user
        actor = f"{who} on {host}" if who else host
        url = kv.get("url") or kv.get("site_url") or ev.get("destination_ip") or "an external host"
        if et == "HTTP_CONNECT":
            return f"{actor} opened an HTTPS tunnel to {url}."
        if et == "SSL_HANDSHAKE_FAILED":
            proc = kv.get("process")
            s = f"A TLS handshake to {url} from {(proc + ' on ' + host) if proc else host} failed"
            if kv.get("failure_reason"):
                s += f" ({kv['failure_reason']})"
            if kv.get("failure_count_last_hour"):
                s += f", {kv['failure_count_last_hour']} failures in the last hour"
            return s + "."
        if et == "SSL_INSPECT":
            return f"The proxy inspected a TLS session from {actor} to {url}."
        if et == "FileSyncUploadedFull":
            s = f"{actor} synced"
            if kv.get("file_count"):
                s += f" {kv['file_count']} files"
            if kv.get("bytes_uploaded"):
                s += f" ({_human_bytes(kv['bytes_uploaded'])})"
            return s + f" to {url}."
        method = kv.get("http_method") or et.replace("HTTP_", "")
        s = f"{actor} sent a {method} request to {url}"
        if kv.get("bytes_sent"):
            s += f" with {_human_bytes(kv['bytes_sent'])}"
        return s + "."
    if src == "DNS":
        q = kv.get("query")
        qt = kv.get("query_type")
        if q:
            return f"{host} queried {q}{(' (' + str(qt) + ' record)') if qt else ''}."
        return f"{host} issued a DNS query: {msg or 'details unavailable'}."
    if src == "Firewall":
        action = (kv.get("action") or et or "handled").lower()
        s_ip = kv.get("src_ip") or ev.get("source_ip") or host
        d_ip = kv.get("dst_ip") or ev.get("destination_ip") or "an external host"
        port = kv.get("dest_port")
        s = f"The firewall {action}ed {s_ip} to {d_ip}{(':' + str(port)) if port else ''}"
        if kv.get("app"):
            s += f" ({kv['app']})"
        if kv.get("rule"):
            s += f" under rule {kv['rule']}"
        return s + "."
    if src == "Veeam":
        job = kv.get("job_name")
        if et == "190":
            s = f"Backup job {job!r} on {host} completed" if job else f"A backup job on {host} completed"
            if kv.get("bytes_backed_up_human"):
                s += f", {kv['bytes_backed_up_human']}"
            if kv.get("repository"):
                s += f" to {kv['repository']}"
            return s + "."
        return f"{msg or 'A backup job event was logged'} ({host})."
    if src == "Azure AD":
        upn = kv.get("UserPrincipalName") or user or "an account"
        loc = kv.get("Location")
        ip = kv.get("IPAddress") or ev.get("source_ip")
        where = ""
        if loc or ip:
            where = " from " + " ".join(x for x in [loc, f"({ip})" if ip else ""] if x)
        if et == "SigninLogs":
            kind = "non-interactive" if str(kv.get("IsInteractive", "")).lower() == "false" else "interactive"
            app = kv.get("AppDisplayName") or kv.get("ClientAppUsed")
            return f"{upn} completed a {kind} sign-in{where}{(' via ' + app) if app else ''}."
        risk = (_words(kv["RiskEventType"]) + " risk") if kv.get("RiskEventType") else (msg or "a risk event")
        lvl = kv.get("RiskLevel")
        return f"Entra flagged {risk} for {upn}{where}{(' at ' + str(lvl) + ' risk') if lvl else ''}."
    if msg:
        return f"{msg.rstrip('.')} on {host}{as_user()}."
    return f"Activity matching this rule was recorded on {host}{as_user()}."
