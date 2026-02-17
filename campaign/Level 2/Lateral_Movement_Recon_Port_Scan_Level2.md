# Lateral Movement: Reconnaissance (Port Scan) — Level 2

> **Category:** Lateral Movement
> **Subcategory:** Network Service Scanning (Port Scan)
> **Difficulty:** Level 2 (Correlation)
> **Events:** 2

---

## Scenario Description

A Sysmon alert shows a well-known network scanning tool launching from a user's Downloads folder, targeting an internal file server across multiple ports. Shortly after, the internal firewall logged a denied connection attempt from that same workstation to the file server on a service port. Review the Sysmon and Firewall logs and determine if these events represent reconnaissance activity.

---

## Attack Pattern Reference

| Framework | ID | Name | Link |
|-----------|-----|------|------|
| MITRE ATT&CK | **T1046** | Network Service Scanning | [attack.mitre.org](https://attack.mitre.org/techniques/T1046/) |
| ATT&CK Tactic | **TA0007** | Discovery | |

> **Note:** T1046 covers adversaries scanning remote hosts to discover which services are running and which ports are open. This is a pre-attack reconnaissance step — the attacker maps the target before attempting to exploit it. Port scanning is often the first detectable activity after an attacker gains a foothold. If you catch the scan, you can stop the attack before lateral movement begins. Used by APT28, FIN7, Conti ransomware, Cobalt Strike, WannaCry, and virtually every attacker who moves laterally.

---

## Log Events

### Event 1 of 2 — Network Scanning Tool Launched on Workstation

#### Table View

| TIME | EVENT TYPE | SOURCE TYPE | SOURCE IP | DEST IP | MESSAGE |
|------|------------|-------------|-----------|---------|---------|
| {timestamp_1} | ProcessCreate | Sysmon | {src_ip} | — | Process created: nmap.exe by {user_domain}. |

#### Key Value Pairs

```
timestamp = {timestamp_1}
event_type = ProcessCreate
source_type = Sysmon
host = {hostname}
src_ip = {src_ip}
commandline = nmap.exe -sS -p 22,80,443,445,3389 {file_server}
process_id = 8844
message = Process created: nmap.exe by {user_domain}.
```

---

### Event 2 of 2 — Connection Attempt Denied by Internal Firewall

#### Table View

| TIME | EVENT TYPE | SOURCE TYPE | SOURCE IP | DEST IP | MESSAGE |
|------|------------|-------------|-----------|---------|---------|
| {timestamp_2} | DENY | Firewall | {src_ip} | {file_server} | Connection denied from {hostname} to ACME-SVR02 on port 445 (tcp). |

#### Key Value Pairs

```
timestamp = {timestamp_2}
event_type = DENY
source_type = Firewall
host = ACME-FW01
src_ip = {src_ip}
dst_ip = {file_server}
dst_port = 445
protocol = tcp
action = deny
direction = internal
rule = default_internal
src_port = 49157
message = Connection denied from {hostname} to ACME-SVR02 on port 445 (tcp).
```

---

## Expected Answer

**Classification:** Malicious — Reconnaissance (Network Service Scanning)

**Threat Category:** Discovery: Port Scanning

---

## Triage Review

### What is it?

**Network Service Scanning** is a reconnaissance technique where an attacker probes a target host to discover which services are running and which ports are open. In this scenario, a user ran **Nmap** — the most widely used network scanning tool — from their workstation to scan an internal file server for common services.

This is a **pre-attack** activity. The attacker is mapping the target before attempting to exploit it. Seeing these two events together means:
- Someone downloaded and ran a hacking tool (Nmap) on a corporate workstation
- They are actively targeting an internal server for reconnaissance
- The scan is probing for exploitable services (SSH, SMB, RDP)
- Lateral movement or exploitation attempts are likely to follow

| Indicator | What It Means | Why It's Suspicious |
|-----------|---------------|---------------------|
| **`nmap.exe` on a workstation** | Known network scanning tool running on a corporate endpoint | Nmap is not standard corporate software — it was manually downloaded |
| **`-sS` flag (SYN scan)** | Stealth scan — sends SYN packets without completing the handshake | Designed to avoid detection by not creating full TCP connections |
| **`-p 22,80,443,445,3389`** | Targeting specific high-value service ports | Attacker checking for SSH, HTTP, HTTPS, SMB, RDP — services that enable lateral movement |
| **Target is {file_server}** | Scanning an internal file server | Workstations should not be probing server ports directly |
| **Firewall DENY on port 445** | SMB connection attempt blocked | SMB is the primary lateral movement protocol — this is what the attacker wants most |
| **`direction = internal`** | East-west traffic between workstation and server | Internal scanning indicates post-compromise reconnaissance, not external probing |
| **`rule = default_internal`** | Default deny rule triggered | Proper segmentation blocked the probe — workstations aren't allowed to reach these ports |

### Understanding the Nmap Command

```
nmap.exe -sS -p 22,80,443,445,3389 {file_server}
```

| Component | Purpose |
|-----------|---------|
| `nmap.exe` | Network Mapper — open-source network scanning tool |
| `-sS` | **SYN scan (stealth scan)** — sends TCP SYN packets and reads responses without completing the 3-way handshake |
| `-p 22,80,443,445,3389` | Target specific ports — the attacker chose high-value service ports |
| `{file_server}` | Target IP — ACME-SVR02 (file server) |

### What Each Scanned Port Reveals

| Port | Service | Why Attacker Scans It | If Open, Attacker Could... |
|------|---------|----------------------|---------------------------|
| **22** | SSH | Remote shell access | Brute force SSH credentials or use stolen keys |
| **80** | HTTP | Web server | Exploit web application vulnerabilities |
| **443** | HTTPS | Encrypted web server | Exploit web apps or identify management interfaces |
| **445** | SMB | File sharing / Windows admin shares | Lateral movement via PsExec, access shared files, deploy ransomware |
| **3389** | RDP | Remote Desktop | Brute force RDP or use stolen credentials for interactive access |

### Understanding the Reconnaissance Chain

```
PRIOR (not visible in these logs):
  Attacker gained access to workstation (phishing, exploit, etc.)
  Downloaded nmap to the workstation
       │
       ▼
EVENT 1: Nmap launches ({timestamp_1})
   │
   ├── nmap.exe starts from user's workstation
   ├── Command line shows target: {file_server}
   ├── SYN scan (-sS) across 5 high-value ports
   └── Scanning begins — SYN packets sent to each port
          │
          EVENT 2: Firewall blocks probe (~2 seconds later)
          │
          ├── SYN packet to port 445 (SMB) hits internal firewall
          ├── ACME-FW01 applies default_internal deny rule
          └── Connection blocked — but attacker learns the firewall exists
               │
               WHAT HAPPENS NEXT (not visible in Level 2):
               │
               ├── Attacker analyzes results — which ports responded?
               ├── Open ports become exploitation targets
               ├── SMB (445) open → lateral movement via PsExec
               ├── RDP (3389) open → remote desktop with stolen creds
               └── Attacker pivots to the next phase of the attack
```

### How Port Scanning Works (Reference)

```
STEP 1: Attacker selects target (ACME-SVR02 / {file_server})
   │
   STEP 2: Nmap sends SYN packets to each target port
   │
   ├── Port 22:  SYN → [DENIED by firewall] → Port FILTERED
   ├── Port 80:  SYN → [DENIED by firewall] → Port FILTERED
   ├── Port 443: SYN → [DENIED by firewall] → Port FILTERED
   ├── Port 445: SYN → [DENIED by firewall] → Port FILTERED
   └── Port 3389: SYN → [DENIED by firewall] → Port FILTERED
          │
          STEP 3: All ports blocked by internal segmentation
          │
          └── Attacker may try again from different source
              or with different techniques to bypass firewall
```

### Common Nmap Scan Types (Reference)

| Scan Type | Flag | How It Works | Stealth Level |
|-----------|------|-------------|---------------|
| **SYN scan** | `-sS` | Sends SYN, reads response, never completes handshake | **High** — most common scan (this scenario) |
| **Connect scan** | `-sT` | Completes full TCP handshake | **Low** — full connections logged everywhere |
| **UDP scan** | `-sU` | Sends UDP packets to discover UDP services | **Medium** — slower, harder to detect |
| **FIN scan** | `-sF` | Sends FIN packet — closed ports respond, open ports don't | **High** — bypasses some firewalls |
| **Ping sweep** | `-sn` | ICMP ping to find live hosts — no port scan | **Low** — just host discovery |
| **Version detection** | `-sV` | Probes open ports to identify service version | **Low** — active banner grabbing |

### Real-World Threat Actors Using Network Scanning

| Threat Actor / Malware | How They Use Scanning |
|------------------------|----------------------|
| **APT28 (Fancy Bear)** | Internal port scans to identify domain controllers and email servers |
| **FIN7** | Nmap and custom scanning tools to map POS systems in retail networks |
| **Conti Ransomware** | Aggressive internal scanning for SMB (445) to identify lateral movement targets |
| **Cobalt Strike** | Built-in port scanner module used post-exploitation for service discovery |
| **WannaCry** | Scanned for open SMB port 445 to spread via EternalBlue exploit |

---

## Recommended Triage Steps

### 1. IMMEDIATE — Investigate the Workstation
Determine if the user intentionally ran Nmap or if the workstation is compromised. This changes the response — insider threat vs external attacker.

### 2. Remove the Scanning Tool
Delete Nmap from the workstation. Unauthorized scanning tools should not exist on corporate endpoints.

### 3. Identify the Full Scan Scope
Search the SIEM for all firewall denials from {src_ip} — the scan may not be limited to ACME-SVR02:
- Any other DENY events from {src_ip} targeting other internal hosts
- Any ALLOW events that may have succeeded before the firewall blocked
- Check for scanning activity over the past 24-48 hours

### 4. Check for Follow-Up Activity
Scanning is step one. Search for what happened next:
- Any successful logon attempts from {src_ip} to the scanned hosts
- Any exploitation attempts (SMB exploits, RDP brute force)
- Any lateral movement indicators (PsExec, WMI, remote service creation)

### 5. Verify Scan Results
Determine if any ports responded before the firewall blocked. Some ports may have been open — the attacker may already know which services are available.

### 6. Remediation
- Enforce application control (AppLocker) to prevent unauthorized tools
- Review internal firewall rules — confirm segmentation between workstation and server subnets
- Remind employees that unauthorized scanning tools violate acceptable use policy

### 7. Escalate if Compromised
If the workstation is compromised (not an insider), escalate to incident response. The attacker has a foothold and is actively mapping the network.

---

## Generation Rules

| Variable | Rule |
|----------|------|
| {src_ip} | Same across both events — same workstation |
| {hostname} | Same across both events — same workstation |
| {username} | Same across both events |
| {user_domain} | ACME\\{username} |
| {file_server} | Target server IP (ACME-SVR02) |
| process_id | 8844 in Sysmon event |
| Firewall host | ACME-FW01 — internal firewall |
| dst_port | 445 in firewall event — SMB (highest-value port for lateral movement) |
| {timestamp_1} → {timestamp_2} | ~2 second gap (Nmap launches, then SYN packets hit firewall) |
| Timestamps | Business hours — attacker scanning while blending with normal traffic |

---

## What the Player Should Recognize

| Indicator | Evidence |
|-----------|----------|
| Known scanning tool | `nmap.exe` is the most widely used network scanning tool |
| Tool shouldn't be on workstation | Nmap is not standard corporate software — manually downloaded |
| Stealth scan flag | `-sS` is a SYN scan designed to avoid detection |
| High-value target ports | 22, 80, 443, 445, 3389 — services that enable lateral movement |
| Internal target | Scanning an internal file server, not an external host |
| Firewall blocked the scan | DENY on port 445 confirms the scan hit internal segmentation |
| Same source in both events | Nmap process on {hostname} matches the firewall deny from {src_ip} |
| Timing correlation | Nmap launched 2 seconds before firewall deny — process caused the blocked traffic |

### The Level 2 Difficulty Factor

Level 2 requires the player to **correlate two events across two different log sources** and connect the tool to the traffic:

| Stage | What the Player Must Recognize | Difficulty |
|-------|-------------------------------|------------|
| **1. Tool Recognition** | `nmap.exe` is a scanning tool — requires knowing what Nmap is | Medium |
| **2. Cross-Source Correlation** | The Sysmon process (Event 1) caused the firewall deny (Event 2) — same host, same target, seconds apart | Level 2 skill |
| **3. Intent Recognition** | Port scanning an internal server from a workstation is reconnaissance — a pre-attack step | Medium |

---

## Level Progression Preview

| Level | Events | Complexity |
|-------|--------|------------|
| **Level 1** | 1 | Single event — Identify a port scan from firewall logs alone |
| **Level 2** (Current) | 2 | Two events — Correlate firewall denials with the scanning tool on the source host |
| **Level 4** | 3 | Three events — Credential gathering techniques (post-reconnaissance escalation) |

---

## Related Log Sources

For more advanced scenarios, network reconnaissance can be detected across multiple sources:

| Log Source | Event Type | What It Shows |
|------------|------------|---------------|
| **Sysmon Event 1** | ProcessCreate | Scanning tool execution with command-line arguments (this scenario) |
| **Firewall DENY** | Blocked Connections | Port scan probes blocked by segmentation rules (this scenario) |
| **Sysmon Event 3** | NetworkConnection | Outbound connections from the scanning process to target |
| **Windows Security 4688** | Process Creation | Corroborating process creation from Windows audit logs |
| **IDS/IPS** | Alert | Signature-based detection of scanning patterns |
| **Netflow** | Traffic Metadata | Volume and pattern analysis of connection attempts |

---

## Detection Rule Logic (Reference)

```
# Firewall: Port scan pattern detection
MATCH firewall_logs WHERE
  action = "DENY"
  AND direction = "internal"
  GROUP BY src_ip, dst_ip
  HAVING COUNT(DISTINCT dst_port) > 3
  AND TIMESPAN < 10s

# Sysmon: Known scanning tool execution
MATCH sysmon_logs WHERE
  event_type = "ProcessCreate"
  AND (
    commandline MATCHES "*nmap*" OR
    commandline MATCHES "*masscan*" OR
    commandline MATCHES "*rustscan*" OR
    commandline MATCHES "*zenmap*" OR
    commandline MATCHES "*angry*ip*"
  )

# Correlation: Scanning tool + matching firewall denials
MATCH sysmon_logs AS scan
  JOIN firewall_logs AS deny
    ON scan.src_ip = deny.src_ip
    AND deny.timestamp BETWEEN scan.timestamp AND scan.timestamp + 60s
WHERE
  scan.event_type = "ProcessCreate"
  AND scan.commandline MATCHES "*-p*"
  AND deny.action = "DENY"
  AND deny.direction = "internal"
```

---

## Common False Positives

Understanding legitimate scenarios helps avoid alert fatigue:

| False Positive Scenario | How to Identify |
|-------------------------|-----------------|
| IT security team running authorized vulnerability scan | Source is dedicated security scanner host, user in security group, documented assessment |
| Network monitoring tool checking service availability | Known monitoring tool (Nagios, PRTG), checks same ports on schedule |
| Application misconfiguration generating connection failures | Same application process repeatedly, consistent target port, not sequential ports |
| SCCM or Intune probing client status | Source is management server, known service account |
| Developer testing connectivity to a new service | Single target port, documented development activity |

**Key Differentiators:**
- Legitimate: Authorized scanner, security team, documented, from management subnet, scheduled
- Malicious: Unauthorized tool (downloaded Nmap), standard user, multiple ports scanned rapidly, from user workstation, no documentation

---

## Port Scan Quick Reference

| Pattern | What It Looks Like | Classification |
|---------|-------------------|----------------|
| **Single host, many ports** | One source → one target → 5+ ports in seconds | **Vertical scan** (this scenario) — profiling one target |
| **Many hosts, one port** | One source → many targets → same port | **Horizontal scan** — looking for a specific service across the network |
| **Many hosts, many ports** | One source → many targets → many ports | **Network sweep** — comprehensive reconnaissance |
| **Slow scan** | Same as above but spread over hours/days | **Low-and-slow** — evading time-based detection thresholds |

---

## Process Chain Analysis

### Suspicious Chain (This Scenario)
```
[{hostname}] cmd.exe ({user_domain} — opened command prompt)
  └── nmap.exe -sS -p 22,80,443,445,3389 {file_server}
      ├── SYN → {file_server}:22   → DENIED by ACME-FW01
      ├── SYN → {file_server}:80   → DENIED by ACME-FW01
      ├── SYN → {file_server}:443  → DENIED by ACME-FW01
      ├── SYN → {file_server}:445  → DENIED by ACME-FW01 (Event 2)
      └── SYN → {file_server}:3389 → DENIED by ACME-FW01
```
**Why Suspicious:** Unauthorized scanning tool, standard user, targeting internal server, probing for exploitable services, run from command prompt

### Legitimate Chain (Security Assessment)
```
[SEC-SCAN01] scheduled_task.exe (svc_vuln_scanner)
  └── nessus_scanner.exe --target 10.0.1.0/24 --policy internal_audit
      ├── Scans all hosts on subnet
      ├── Results sent to vulnerability management platform
      └── Report generated for security team review
```
**Why Legitimate:** Dedicated security scanner, service account, scheduled assessment, results reported to security team

---

*Last Updated: February 2026*
*Spectyr Training Platform*
