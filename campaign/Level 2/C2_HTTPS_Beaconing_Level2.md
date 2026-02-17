# Command and Control: HTTPS C2 Beaconing — Level 2

> **Category:** Command and Control (C2)
> **Subcategory:** Application Layer Protocol: Web Protocols (HTTPS C2 Beaconing)
> **Difficulty:** Level 2 (Correlation)
> **Events:** 2

---

## Scenario Description

A workstation generated a DNS query for an unfamiliar domain followed by an outbound HTTPS connection logged by the proxy server. The domain looks like a legitimate Microsoft service but isn't quite right. Review the DNS and Proxy logs and determine if these events represent command and control communication.

---

## Attack Pattern Reference

| Framework | ID | Name | Link |
|-----------|-----|------|------|
| MITRE ATT&CK | **T1071.001** | Application Layer Protocol: Web Protocols | [attack.mitre.org](https://attack.mitre.org/techniques/T1071/001/) |
| ATT&CK Tactic | **TA0011** | Command and Control | |

> **Note:** T1071.001 covers adversaries using web protocols (HTTP/HTTPS) to communicate with compromised systems, blending C2 traffic with normal web browsing. HTTPS is the most common C2 channel because encrypted web traffic is expected in every corporate network. Used by Cobalt Strike, Metasploit, Sliver, APT29, FIN7, Emotet, and virtually every modern malware family.

---

## Log Events

### Event 1 of 2 — DNS Resolution of Suspicious Domain

#### Table View

| TIME | EVENT TYPE | SOURCE TYPE | SOURCE IP | DEST IP | MESSAGE |
|------|------------|-------------|-----------|---------|---------|
| {timestamp_1} | QUERY_RECEIVED | DNS | {src_ip} | — | DNS query received for microsoftonline.co. |

#### Key Value Pairs

```
timestamp = {timestamp_1}
event_type = QUERY_RECEIVED
source_type = DNS
host = ACME-SVR03
src_ip = {src_ip}
client_ip = {src_ip}
qname = microsoftonline.co
qtype = A
src_port = 54819
message = DNS query received for microsoftonline.co.
```

---

### Event 2 of 2 — Outbound HTTPS Connection via Proxy

#### Table View

| TIME | EVENT TYPE | SOURCE TYPE | SOURCE IP | DEST IP | MESSAGE |
|------|------------|-------------|-----------|---------|---------|
| {timestamp_2} | HTTP_CONNECT | Proxy | {src_ip} | — | CONNECT tunnel established to microsoftonline.co on port 443. |

#### Key Value Pairs

```
timestamp = {timestamp_2}
event_type = HTTP_CONNECT
source_type = Proxy
host = {hostname}
src_ip = {src_ip}
user = -
domain = microsoftonline.co
dst_ip = 185.234.72.19
http_status = 200
message = CONNECT tunnel established to microsoftonline.co on port 443.
```

---

## Expected Answer

**Classification:** Malicious — Command and Control (HTTPS Beaconing)

**Threat Category:** C2 Beaconing / Application Layer Protocol (HTTPS)

---

## Triage Review

### What is it?

**Command and Control (C2) beaconing** is when malware on a compromised workstation "phones home" to an attacker-controlled server. The malware connects to the server at regular intervals — like a heartbeat — waiting for instructions. The attacker can then remotely command the malware to steal files, dump credentials, spread to other machines, or deploy ransomware.

In this scenario, malware on the workstation resolved `microsoftonline.co` — a domain designed to look like Microsoft's real `microsoftonline.com` — then established an encrypted HTTPS tunnel to that server. From the network's perspective, it looks like normal web browsing. That's the whole point.

Here's what happens in a typical C2 beacon cycle:

1. Malware resolves the C2 domain via DNS (Event 1)
2. Malware connects to the C2 server over HTTPS port 443 (Event 2)
3. Malware sends a small check-in: "I'm alive, anything for me?"
4. Attacker's server responds: "sit tight" or "run this command" or "send me that file"
5. Repeat every 30-60 seconds

All of this happens over encrypted HTTPS through port 443 — the same port used by every website, email service, and cloud application. That's why it's so hard to catch.

| Indicator | What It Means | Why It's Suspicious |
|-----------|---------------|---------------------|
| **`microsoftonline.co`** | Domain looks like Microsoft but uses `.co` instead of `.com` | Real Microsoft authentication uses `microsoftonline.com` — the `.co` TLD is a different domain entirely, registered by the attacker |
| **`dst_ip = 185.234.72.19`** | The domain resolved to a non-Microsoft IP address | Real `microsoftonline.com` resolves to Microsoft's IP ranges (20.x.x.x, 40.x.x.x, 52.x.x.x). This IP doesn't belong to Microsoft. |
| **`user = -`** | No authenticated user behind the proxy connection | Normal browsing always shows a user like `ACME\jsmith`. No user means a background process made this connection — not a human in a browser |
| **`HTTP_CONNECT` to port 443** | Encrypted HTTPS tunnel established | The connection is encrypted, so the proxy can't inspect what's being sent — the attacker's commands and stolen data are hidden inside |
| **DNS query immediately before proxy connection** | Same workstation, same domain, seconds apart | The malware resolved the domain then connected — this is the standard C2 initialization sequence |

### Understanding the C2 Beaconing Chain

```
PRIOR (not visible in these logs):
  Malware delivered via phishing email, malicious download, or exploit
  Malware installed on workstation, persistence established
       │
       ▼
EVENT 1: DNS resolution ({timestamp_1})
   │
   ├── Workstation queries DNS for microsoftonline.co
   ├── DNS server resolves it to 185.234.72.19
   └── This is the malware finding its C2 server's address
          │
          EVENT 2: HTTPS connection (~1 second later)
          │
          ├── Workstation establishes encrypted tunnel to 185.234.72.19:443
          ├── Proxy logs the CONNECT but can't see inside (it's encrypted)
          ├── user = - (no human session — this is malware, not browsing)
          └── C2 channel is now active — attacker has remote access
               │
               WHAT HAPPENS NEXT (not visible in Level 2):
               │
               ├── Malware beacons every 30-60 seconds
               ├── Attacker sends commands: steal credentials, scan network
               ├── Stolen data exfiltrated back over the same HTTPS channel
               └── Attacker may deploy ransomware or move laterally
```

### Why `.co` vs `.com` Matters

The entire attack hinges on one character. The attacker registered `microsoftonline.co` because:

| | Real Microsoft | Attacker's Domain |
|---|---|---|
| **Domain** | `microsoftonline.com` | `microsoftonline.co` |
| **TLD** | `.com` (commercial) | `.co` (Colombia country code, commonly used for short URLs) |
| **Owner** | Microsoft Corporation | Attacker |
| **IP ranges** | Microsoft-owned (20.x, 40.x, 52.x) | Random hosting provider (185.234.72.19) |
| **Purpose** | Azure AD / Microsoft 365 authentication | C2 server for malware communication |

An analyst scrolling through hundreds of DNS queries might see `microsoftonline.co` and assume it's Microsoft traffic. The skill being tested is reading the domain carefully and catching the difference.

### Why `user = -` is the Biggest Red Flag

In a corporate network with a proxy server, every web connection from a browser includes the user's identity. The proxy authenticates the user before allowing the connection.

| | Normal Browsing | C2 Beaconing |
|---|---|---|
| **User field** | `ACME\jsmith` | `-` |
| **What's happening** | Person opened a browser, proxy authenticated them | Malware running as a background process, no browser involved |
| **Process** | `chrome.exe`, `msedge.exe`, `outlook.exe` | `rundll32.exe`, `svchost.exe`, or unknown malware |
| **Initiated by** | Human clicking links | Automated malware on a timer |

If you see `user = -` on an HTTPS connection to an unfamiliar domain, something on that machine is talking to the internet without a human driving it. That's malware.

### How C2 Beaconing Works (Reference)

| Phase | What Happens | Detection Point |
|-------|-------------|-----------------|
| 1. **DNS Resolution** | Malware resolves C2 domain | DNS logs — unfamiliar or lookalike domain |
| 2. **HTTPS Connection** | Encrypted tunnel established to C2 server | Proxy logs — CONNECT to suspicious destination with no user |
| 3. **Beacon Check-in** | Malware sends system info, requests instructions | Proxy logs — small, regular-interval connections |
| 4. **Command Delivery** | C2 server sends tasking to malware | Encrypted — not visible in proxy logs |
| 5. **Task Execution** | Malware executes received commands | Sysmon — process creation, file operations |
| 6. **Data Exfiltration** | Stolen data sent back over C2 channel | Proxy logs — larger outbound payloads |

### Common C2 Frameworks (Reference)

| Framework | Typical C2 Protocol | Detection Priority |
|-----------|---------------------|--------------------|
| **Cobalt Strike** | HTTPS (443) — configurable interval, malleable C2 profiles | Critical |
| **Metasploit (Meterpreter)** | HTTPS (443) / TCP — reverse shell | Critical |
| **Sliver** | HTTPS / mTLS / WireGuard — configurable paths and headers | High |
| **Havoc** | HTTPS (443) — modern framework, sleep obfuscation | High |
| **Empire / Starkiller** | HTTPS (443) — PowerShell/Python agents | High |

### Real-World Threat Actors Using HTTPS C2

| Threat Actor / Malware | How They Use HTTPS C2 |
|------------------------|----------------------|
| **APT29 (Cozy Bear)** | HTTPS beacons to domains impersonating cloud services — used in SolarWinds breach |
| **FIN7** | HTTPS C2 using domains impersonating hotel booking and payment platforms |
| **Emotet** | HTTPS POST beacons to compromised WordPress sites acting as C2 proxies |
| **QakBot** | HTTPS beaconing with rotating C2 infrastructure and DGA domains |
| **Cobalt Strike (widely used)** | Malleable C2 profiles that mimic legitimate CDN and API traffic patterns |

---

## Recommended Triage Steps

### 1. IMMEDIATE — Isolate the Host
Pull the affected workstation off the network. The HTTPS tunnel is an active C2 channel — the attacker can send commands right now. Every second connected is another command executed.

### 2. Block the Domain and IP
Block `microsoftonline.co` at the DNS server and proxy. Block `185.234.72.19` at the firewall. This cuts the C2 channel for any other potentially infected hosts.

### 3. Identify the Scope
Search the SIEM for other hosts with the same indicators:
- Any other DNS queries to `microsoftonline.co`
- Any other proxy connections to `185.234.72.19`
- Any other `HTTP_CONNECT` events with `user = -` to unfamiliar domains

### 4. Identify the Malware Process
Check Sysmon logs on the affected workstation:
- Sysmon Event 3 (NetworkConnection) — which process made the outbound connection to `185.234.72.19`
- Sysmon Event 22 (DNSQuery) — which process resolved `microsoftonline.co`
- Sysmon Event 1 (ProcessCreate) — when did the malware process start

### 5. Trace the Delivery Method
Work backwards — how did the malware get on this workstation?
- Check email logs for recent phishing attempts to this user
- Check Proxy logs for recent downloads (drive-by download)
- Check Sysmon FileCreate for when the malware binary was written to disk
- Check PowerShell logs for download cradles

### 6. Assess the Damage
The C2 channel was active — assume the attacker accomplished something:
- Were credentials stolen? Reset the affected user's passwords
- Were files accessed? Check for data exfiltration indicators in proxy logs
- Did the attacker move laterally? Check for unusual logon events from this workstation to other hosts

### 7. Escalate
An active C2 channel is a confirmed compromise. Escalate to incident response, notify management. This is not a "close and move on" alert.

---

## Generation Rules

| Variable | Rule |
|----------|------|
| {src_ip} | Same across both events — same compromised host |
| {hostname} | Same across both events — same compromised host |
| {username} | Same across both events |
| {user_domain} | ACME\\{username} |
| DNS host | ACME-SVR03 — DNS server perspective |
| Proxy host | {hostname} — workstation making the connection |
| C2 domain | microsoftonline.co — consistent across both events |
| C2 IP | 185.234.72.19 — non-Microsoft IP |
| Proxy user | Always `-` for C2 (no human session) |
| {timestamp_1} → {timestamp_2} | ~1-2 second gap (DNS resolution then immediate connection) |
| Timestamps | Business hours — malware beacons continuously but player sees one snapshot |

---

## What the Player Should Recognize

| Indicator | Evidence |
|-----------|----------|
| Lookalike domain | `microsoftonline.co` looks like Microsoft's `microsoftonline.com` but uses `.co` TLD — registered by the attacker |
| IP doesn't match the domain | `185.234.72.19` is not a Microsoft IP address — real Microsoft uses 20.x, 40.x, 52.x ranges |
| No user behind the connection | `user = -` in proxy log means a background process (malware), not a human in a browser |
| DNS immediately before proxy | Same workstation resolved the domain then connected — standard C2 initialization |
| HTTPS tunnel to unknown domain | Encrypted connection hides the attacker's commands and stolen data |

### The Level 2 Difficulty Factor

Level 2 requires the player to **correlate two events across two different log sources** and recognize indicators that look almost normal:

| Stage | What the Player Must Recognize | Difficulty |
|-------|-------------------------------|------------|
| **1. Domain Analysis** | `microsoftonline.co` is NOT `microsoftonline.com` — requires reading the domain carefully instead of skimming | Medium |
| **2. Cross-Source Correlation** | The DNS query (Event 1) and proxy connection (Event 2) are the same attack — same workstation, same domain, seconds apart | Level 2 skill |
| **3. Missing User** | `user = -` means no human is browsing — this is malware, not a person | Medium |

---

## Level Progression Preview

| Level | Events | Complexity |
|-------|--------|------------|
| **Level 1** | 1 | Single event — Suspicious outbound connection to known-bad IP |
| **Level 2** (Current) | 2 | Two events — Correlate DNS query with proxy C2 tunnel, spot lookalike domain |
| **Level 5** (DNS Tunneling) | 4 | DNS tunneling — covert channel hidden in DNS protocol, requires understanding DNS abuse + tool recognition + cross-source correlation |

---

## Related Log Sources

For more advanced scenarios, C2 beaconing can be detected across multiple sources:

| Log Source | Event Type | What It Shows |
|------------|------------|---------------|
| **DNS QUERY_RECEIVED** | DNS Query | Domain resolution for C2 server (this scenario) |
| **Proxy HTTP_CONNECT** | HTTPS Tunnel | Outbound encrypted connection to C2 (this scenario) |
| **Sysmon Event 3** | NetworkConnection | Process-level network connection — identifies which binary made the call |
| **Sysmon Event 22** | DNSQuery | Process-level DNS — which executable resolved the C2 domain |
| **Firewall ALLOW** | Outbound TCP/443 | Network-level C2 connection permitted |
| **Sysmon Event 1** | ProcessCreate | Malware process launch that initiates C2 |
| **Proxy HTTP_POST** | Data Upload | Potential exfiltration over C2 channel |

---

## Detection Rule Logic (Reference)

```
# DNS: Lookalike domain detection
MATCH dns_logs WHERE
  event_type = "QUERY_RECEIVED"
  AND (
    qname MATCHES "*microsoftonline.co" OR
    qname MATCHES "*windowsupdate.ms" OR
    qname MATCHES "*office365.net" OR
    qname MATCHES "*teams-microsoft.com"
  )
  AND qname NOT IN known_legitimate_domains

# Proxy: HTTPS tunnel with no user session
MATCH proxy_logs WHERE
  event_type = "HTTP_CONNECT"
  AND user = "-"
  AND domain NOT IN known_business_domains
  AND dst_ip NOT IN known_cdn_ip_ranges

# Correlation: DNS query + proxy C2 connection
MATCH dns_logs AS dns
  JOIN proxy_logs AS proxy
    ON dns.src_ip = proxy.src_ip
    AND proxy.domain = dns.qname
    AND proxy.event_type = "HTTP_CONNECT"
    AND proxy.user = "-"
    AND proxy.timestamp BETWEEN dns.timestamp AND dns.timestamp + 5s
WHERE
  dns.event_type = "QUERY_RECEIVED"
  AND dns.qname NOT IN known_legitimate_domains

# Beaconing detection (advanced — regular interval connections)
MATCH proxy_logs WHERE
  event_type = "HTTP_CONNECT"
  AND user = "-"
  GROUP BY domain, src_ip
  HAVING COUNT(*) >= 10
  AND STDDEV(interval_seconds) < 10
  WITHIN 3600 SECONDS
```

---

## Common False Positives

Understanding legitimate scenarios helps avoid alert fatigue:

| False Positive Scenario | How to Identify |
|-------------------------|-----------------|
| Legitimate Microsoft services | Real Microsoft domains end in `.com`, `.net`, or `.microsoft.com` — never `.co`, `.ms`, or hyphenated variants |
| Background Windows updates | `windowsupdate.com` (real) has authenticated connections with user sessions, not `user = -` |
| Cloud service health checks | Known applications (OneDrive, Teams) — domains in corporate whitelist, authenticated proxy sessions |
| Software update services | Chrome, Firefox auto-updates — known domains, known processes, standard intervals |
| VPN or remote access tools | IT-approved tools on corporate whitelist — known domains and IP ranges |

**Key Differentiators:**
- C2 Beaconing: Lookalike domain, non-matching IP, `user = -`, regular intervals, small uniform payloads, background process making connection
- Legitimate: Real domain with correct TLD, IP matches domain owner, authenticated user session, variable sizes, known browser or application process

---

## C2 Indicator Cheat Sheet

Quick reference for identifying C2 beaconing vs normal traffic:

| Indicator | Normal Traffic | C2 Beaconing |
|-----------|---------------|--------------|
| **Domain** | google.com, office365.com, slack.com | Lookalike domains — microsoftonline.co, windowsupdate.ms |
| **IP/Domain Match** | google.com → Google IP ranges | microsoftonline.co → non-Microsoft IP |
| **Proxy User** | `ACME\jsmith` (authenticated) | `-` (no authentication) |
| **Payload Size** | Variable (1KB-100KB+) | Small, uniform (1KB-5KB) |
| **Timing** | Irregular (human browsing patterns) | Regular intervals (30s, 60s, 300s) |
| **Process** | chrome.exe, msedge.exe, outlook.exe | rundll32.exe, svchost.exe, or unknown .exe |
| **Request Method** | Mix of GET, POST, CONNECT | Primarily CONNECT or POST |

---

## Common Lookalike Domain Patterns

Attackers use these patterns to create convincing C2 domains:

| Pattern | Example | Mimics |
|---------|---------|--------|
| **Wrong TLD** | `microsoftonline.co` | `microsoftonline.com` (Microsoft) |
| **Wrong TLD** | `windowsupdate.ms` | `windowsupdate.com` (Microsoft) |
| **Wrong TLD** | `office365.net` | `office365.com` (Microsoft) |
| **Hyphen added** | `teams-microsoft.com` | `teams.microsoft.com` (Microsoft) |
| **Typosquatting** | `gooogle-analytics.com` | `google-analytics.com` (Google) |
| **Subdomain trick** | `login.microsoft.com.attacker.co` | `login.microsoft.com` (Microsoft) |

The player's skill at Level 2 is learning to read domains carefully — character by character — instead of skimming.

---

## Process Chain Analysis

### Suspicious Chain (This Scenario)
```
[{hostname}] Malware (delivered via phishing, exploit, etc.)
  ├── DNS A: microsoftonline.co → 185.234.72.19
  │          (LOOKALIKE DOMAIN — .co not .com, non-Microsoft IP)
  │
  └── HTTPS CONNECT: microsoftonline.co:443
                      user = - (NO HUMAN SESSION)
                      dst_ip = 185.234.72.19
                      │
                      └── C2 channel active — attacker has remote access
                          Commands, data theft, lateral movement all possible
```
**Why Suspicious:** Lookalike domain (.co not .com), destination IP doesn't belong to Microsoft, no user behind the proxy connection, DNS query immediately followed by HTTPS tunnel

### Legitimate Chain (Normal Microsoft Traffic)
```
[{hostname}] chrome.exe (user browsing)
  ├── DNS A: login.microsoftonline.com → 20.190.159.0
  │          (REAL Microsoft domain, Microsoft-owned IP)
  │
  └── HTTPS CONNECT: login.microsoftonline.com:443
                      user = ACME\jsmith (AUTHENTICATED)
                      dst_ip = 20.190.159.0
                      │
                      └── Normal Microsoft 365 authentication
```
**Why Legitimate:** Real Microsoft domain (.com), IP belongs to Microsoft (20.x range), authenticated user session, initiated by a known browser process

---

*Last Updated: February 2026*
*Spectyr Training Platform*
