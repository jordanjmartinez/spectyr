# Phishing - Level 3 Scenario

> **Category:** Initial Access  
> **Subcategory:** Phishing: Spearphishing Link (Payload Download and Execution)  
> **Difficulty:** Level 3 (Context Analysis)  
> **Events:** 2

---

## Scenario Description

A proxy server logged an outbound HTTP request from a workstation downloading a file from an unfamiliar domain. Shortly after, a Sysmon process creation event showed the downloaded file executing on the same workstation. Review the Proxy and Sysmon logs and determine if these events represent a phishing attack.

---

## Attack Pattern Reference

| Framework | ID | Name | Link |
|-----------|-----|------|------|
| MITRE ATT&CK | **T1566.002** | Phishing: Spearphishing Link | [attack.mitre.org](https://attack.mitre.org/techniques/T1566/002/) |
| ATT&CK Tactic | **TA0001** | Initial Access | |
| CAPEC | **CAPEC-163** | Spear Phishing | [capec.mitre.org](https://capec.mitre.org/data/definitions/163.html) |

---

## Log Events

### Event 1 of 2 — Malicious File Downloaded via Phishing Link

#### Table View

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| 09:12:38 | HTTP_GET | Proxy | 10.0.1.50 | 91.215.85.29 | TCP | `1706342558.482 892 10.0.1.50 TCP_MISS/200 248576 GET https://docusign-review.shanoindustries.com/secure/Invoice_2026-0127.exe - DIRECT/91.215.85.29 application/octet-stream` |

#### Expanded Key Value Pairs

```
timestamp = 1706342558.482
elapsed_ms = 892
src_ip = 10.0.1.50
cache_result = TCP_MISS
http_status = 200
bytes = 248576
method = GET
url = https://docusign-review.shanoindustries.com/secure/Invoice_2026-0127.exe
user = -
hierarchy_code = DIRECT
dst_ip = 91.215.85.29
content_type = application/octet-stream
dst_port = 443
host = PROXY01
```

---

### Event 2 of 2 — Downloaded Payload Executed on Workstation

#### Table View

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| 09:14:22 | ProcessCreate | Sysmon | 10.0.1.50 | | | `Process Create: UtcTime=2026-01-27 09:14:22.653 ProcessGuid={C58DAB71-EF82-5903-0000-001037BC9A44} ProcessId=11284 Image=C:\Users\mwilliams\Downloads\Invoice_2026-0127.exe CommandLine="C:\Users\mwilliams\Downloads\Invoice_2026-0127.exe" User=CORP\mwilliams ParentImage=C:\Windows\explorer.exe ParentCommandLine=C:\Windows\Explorer.EXE ParentProcessId=3892` |

#### Expanded Key Value Pairs

```
event_id = 1
event_type = ProcessCreate
utc_time = 2026-01-27 09:14:22.653
process_guid = {C58DAB71-EF82-5903-0000-001037BC9A44}
process_id = 11284
image = C:\Users\mwilliams\Downloads\Invoice_2026-0127.exe
command_line = "C:\Users\mwilliams\Downloads\Invoice_2026-0127.exe"
user = CORP\mwilliams
parent_image = C:\Windows\explorer.exe
parent_command_line = C:\Windows\Explorer.EXE
parent_process_id = 3892
integrity_level = Medium
host = WS-PC050
hashes = SHA256=3E7B14DC2A7183CF6A17428B7E8CD40183DEA8F1B2AE89E4C3D5BC1F72A6E890
```

---

## Expected Answer

**Classification:** Malicious - Initial Access (Phishing)

**Threat Category:** Spearphishing Link / Payload Download and Execution

---

## Triage Review

### What is it?

**Phishing** is a social engineering technique where attackers send deceptive messages to trick employees into performing a malicious action. In this scenario, an employee clicked a link in a phishing email that led to a fake DocuSign page hosting a malicious executable disguised as an invoice. The employee downloaded and executed the file, compromising their workstation.

This is an **initial access** event — the beginning of an attack chain. Once the payload executes, the attacker gains a foothold on the network. What follows depends on the payload: it could establish C2, steal credentials, deploy ransomware, or all of the above.

| Indicator | What It Means | Why It's Suspicious |
|-----------|---------------|---------------------|
| **Domain: `docusign-review.shanoindustries.com`** | Subdomain impersonating DocuSign on an unrelated domain | Legitimate DocuSign uses `docusign.com` / `docusign.net` — this is a lookalike hosted on a compromised or attacker-owned domain |
| **File: `Invoice_2026-0127.exe`** | Executable disguised as an invoice | Invoices are `.pdf` or `.xlsx` — never `.exe`. The name creates urgency ("invoice needs review") |
| **Content-Type: `application/octet-stream`** | Binary executable download | Legitimate document downloads return `application/pdf` or similar — `octet-stream` means raw binary |
| **File size: 248,576 bytes (~243 KB)** | Small executable payload | Too large for a simple script, too small for legitimate software — typical dropper/loader size |
| **Execution from Downloads folder** | User double-clicked the downloaded file | Executables running from `Downloads` is a classic phishing indicator |
| **Parent: `explorer.exe`** | User manually opened the file | Confirms the user was tricked into executing the payload themselves |
| **~2 minute gap between download and execution** | User downloaded, then opened the file | Consistent with a user finding the file in Downloads and double-clicking it |

### Understanding the Phishing Chain

```
STEP 0: Attacker sends phishing email to mwilliams
   │
   ├── Email subject: "Action Required: Invoice #2026-0127 for Review"
   ├── Email body: "Please review and sign the attached invoice via DocuSign"
   └── Link: https://docusign-review.shanoindustries.com/secure/Invoice_2026-0127.exe
          │
          STEP 1: mwilliams clicks the link
          │
          ├── Browser (Chrome) follows the URL
          └── Proxy logs the request → Event 1 (Proxy HTTP_GET)
               │
               ├── File downloads: Invoice_2026-0127.exe (248 KB)
               └── Saved to: C:\Users\mwilliams\Downloads\
                    │
                    STEP 2: mwilliams opens the downloaded file (~2 min later)
                    │
                    ├── Double-clicks Invoice_2026-0127.exe in Downloads folder
                    └── explorer.exe spawns the payload → Event 2 (Sysmon ProcessCreate)
                         │
                         └── NEXT (not seen): Payload establishes persistence, contacts C2, etc.
```

### Anatomy of the Phishing URL

```
https://docusign-review.shanoindustries.com/secure/Invoice_2026-0127.exe
│       │                │                    │       │
│       │                │                    │       └── .exe — executable, NOT a document
│       │                │                    └── /secure/ — implies security, builds trust
│       │                └── shanoindustries.com — attacker-controlled or compromised domain
│       └── docusign-review — subdomain impersonating DocuSign
└── https:// — uses HTTPS to appear legitimate (padlock icon in browser)
```

| Component | Attacker's Intent | How to Spot It |
|-----------|-------------------|----------------|
| `docusign-review` subdomain | Victim sees "docusign" and trusts it | Real DocuSign links come from `docusign.com` or `docusign.net` — never a subdomain on another domain |
| `shanoindustries.com` | Obscure domain that victim won't scrutinize | Not a DocuSign domain — check the root domain, not just the subdomain |
| `/secure/` path | Implies the document is in a secure portal | Generic path name designed to build confidence |
| `.exe` extension | Executable payload masquerading as a document | Invoices are never `.exe` files — legitimate documents are `.pdf`, `.docx`, `.xlsx` |
| HTTPS | Green padlock makes the site look safe | HTTPS only means the connection is encrypted — it does NOT mean the site is legitimate |

### Common Phishing Lure Themes (Reference)

| Theme | Example Subject Line | Why It Works |
|-------|---------------------|--------------|
| **Invoice / Payment** | "Invoice #2026-0127 Requires Your Signature" | Creates urgency, implies financial obligation (this scenario) |
| **Shared Document** | "John shared a document with you" | Mimics OneDrive/Google Drive sharing notifications |
| **Password Expiry** | "Your password expires in 24 hours" | Creates urgency, targets credentials |
| **IT Notification** | "Mailbox storage full — click to expand" | Impersonates internal IT team |
| **Delivery / Shipping** | "Your package delivery failed — reschedule" | Exploits online shopping habits |
| **HR / Payroll** | "Updated benefits enrollment — action required" | Appeals to self-interest |
| **Executive Request** | "CEO: Need you to handle this urgently" | Exploits authority and urgency |
| **Legal / Compliance** | "Subpoena notification — immediate response required" | Creates fear and urgency |

### Suspicious File Types in Downloads (Reference)

| Extension | Risk Level | Context |
|-----------|-----------|---------|
| `.exe` | **Critical** | Executable — never a legitimate document delivery format (this scenario) |
| `.scr` | **Critical** | Screensaver — actually an executable, often used by attackers |
| `.bat` / `.cmd` | **Critical** | Batch scripts — can execute arbitrary commands |
| `.ps1` | **Critical** | PowerShell scripts — powerful attack vector |
| `.js` / `.vbs` | **High** | Script files — can download and execute payloads |
| `.msi` | **High** | Installer package — can install malware |
| `.docm` / `.xlsm` | **High** | Macro-enabled Office docs — macros can execute code |
| `.iso` / `.img` | **High** | Disk images — bypass Mark of the Web protection |
| `.zip` / `.rar` | **Medium** | Archives — may contain any of the above |
| `.pdf` | **Low** | Generally safe but can contain exploits or phishing links |

### Attack Context

Spearphishing links (T1566.002) are the most common initial access technique across all threat actor types. Unlike spearphishing attachments (T1566.001), link-based phishing hosts the payload externally, which:

- **Bypasses email attachment scanning** — no malicious file attached to the email itself
- **Allows payload updates** — attacker can change the hosted file after sending the email
- **Evades email gateway filters** — link may point to a legitimate-looking domain
- **Exploits trust in known brands** — DocuSign, SharePoint, Google Drive links are expected in business email
- **Leverages HTTPS** — encrypted connection prevents inline inspection by some security tools

Phishing remains the **#1 initial access vector** for both targeted and opportunistic attacks. Over 90% of successful breaches begin with a phishing email.

### Real-World Examples

| Threat Actor / Campaign | Phishing Technique |
|------------------------|-------------------|
| **Emotet** | Phishing emails with links to malicious Word documents hosted on compromised WordPress sites |
| **QakBot / Qbot** | Reply-chain phishing with links to password-protected ZIP files containing malicious executables |
| **APT29 (Cozy Bear)** | Spearphishing links impersonating government portals and cloud services |
| **BazarLoader** | Phishing emails linking to fake document previews that download malicious executables |
| **IcedID** | Invoice-themed phishing with links to ISO files containing malicious DLLs |
| **Nobelium (SolarWinds actors)** | Spearphishing from compromised Constant Contact accounts with links to malicious payloads |

### MITRE ATT&CK Context

**Technique T1566.002 - Phishing: Spearphishing Link**

> "Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems. Spearphishing with a link is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of links to download malware contained in email, instead of attaching malicious files to the email itself."

**Detection Focus:**
- Monitor proxy logs for downloads of executable files from unfamiliar or newly registered domains
- Alert on executable files running from user `Downloads` folders
- Track `content_type=application/octet-stream` downloads — legitimate documents don't use this type
- Correlate proxy download events with Sysmon process creation from the same filename
- Flag domains that impersonate known services (DocuSign, SharePoint, Office 365) on non-standard root domains

---

## Recommended Response Actions

### Immediate Actions
1. **Isolate the workstation** (WS-PC050) — the payload has executed and may be establishing persistence or C2
2. **Block the phishing domain** — add `docusign-review.shanoindustries.com` and IP `91.215.85.29` to firewall/proxy blocklists
3. **Quarantine the payload** — preserve `Invoice_2026-0127.exe` from the Downloads folder for analysis (do not delete)

### Investigation Steps
4. **Analyze the payload** — submit the hash (`SHA256=3E7B14DC2A...`) to VirusTotal and sandbox environments to determine malware family and capabilities
5. **Check for post-execution activity** — search Sysmon logs on WS-PC050 for child processes, network connections, file writes, and registry modifications after 09:14:22
6. **Find the phishing email** — search email gateway logs for emails containing the phishing URL sent to mwilliams and potentially other employees
7. **Scope the attack** — search proxy logs for any other workstations that visited the same domain or downloaded the same file
8. **Check for C2** — review DNS and proxy logs from WS-PC050 for outbound connections to suspicious domains after payload execution

### Remediation
9. **Remove the malware** — clean WS-PC050 of the payload and any persistence mechanisms it installed
10. **Reset credentials** — assume mwilliams' credentials are compromised (the malware likely harvested them)
11. **Email recall** — if the phishing email was sent to multiple employees, issue a recall and send a warning notification

### Post-Incident
12. **Document findings** — create incident report documenting the full phishing chain from email to execution
13. **Update email filtering** — add detection rules for the phishing domain pattern and executable file attachments/links
14. **User awareness training** — conduct targeted phishing awareness training, using this incident (anonymized) as a case study

---

## Log Authenticity Notes

### Event 1 — Proxy HTTP_GET

| Field | Value | Why It's Realistic |
|-------|-------|-------------------|
| `url=.../Invoice_2026-0127.exe` | Executable download from phishing URL — attackers use business-themed filenames |
| `content_type=application/octet-stream` | Binary download — web servers return this for `.exe` files |
| `bytes=248576` | ~243 KB — realistic dropper/loader size (too big for scripts, too small for legit software) |
| `dst_ip=91.215.85.29` | Non-DocuSign IP — domain impersonates DocuSign but doesn't resolve to their infrastructure |
| `user=-` | No proxy authentication captured — may indicate link opened from email client directly |
| `cache_result=TCP_MISS` | Fresh download from origin — not cached, first time this URL was accessed |
| `http_status=200` | Download succeeded — payload was delivered to the workstation |

### Event 2 — Sysmon ProcessCreate

| Field | Value | Why It's Realistic |
|-------|-------|-------------------|
| `Image=...\Downloads\Invoice_2026-0127.exe` | Executable running from Downloads folder — classic phishing indicator |
| `ParentImage=explorer.exe` | User double-clicked the file in File Explorer — manual execution |
| `User=CORP\mwilliams` | Regular employee account — phishing targets standard users |
| `IntegrityLevel=Medium` | Standard user privileges — no elevation (UAC not triggered) |
| `Host=WS-PC050` | Different workstation from jsmith (10.0.1.50 vs 10.0.1.45) — shows attacks target multiple users |
| `SHA256 hash` | Unique hash for threat intelligence lookup and IOC sharing |

### Legitimate vs Malicious Comparison

| Legitimate File Download | Phishing Payload Download (This Scenario) |
|-------------------------|-------------------------------------------|
| Domain matches the expected service (`docusign.com`) | Domain impersonates DocuSign on an unrelated root domain |
| File type matches expected content (`.pdf`, `.docx`) | Executable file (`.exe`) disguised as an invoice |
| Content-Type matches file type (`application/pdf`) | Content-Type is `application/octet-stream` (binary) |
| File opened by appropriate application (Acrobat, Word) | File executes as a process — it IS the application |
| Download initiated from known business workflow | Download triggered by link in unsolicited email |
| File saved to project-specific folder | File sitting in generic Downloads folder |

---

## Cross-Log Correlation Guide

### How the Two Events Connect

```
Timeline across PROXY01 and WS-PC050:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
09:12:38  ─── Proxy HTTP_GET ─── 10.0.1.50 downloads Invoice_2026-0127.exe from phishing domain
    │
    │  ~1 min 44 sec (user locates file in Downloads, double-clicks to open)
    │
09:14:22  ─── Sysmon ProcessCreate ─── Invoice_2026-0127.exe executes from Downloads folder
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Correlation Anchors

| Anchor Point | Event 1 (Proxy) | Event 2 (Sysmon) |
|-------------|-----------------|-------------------|
| **Source Host** | `src_ip=10.0.1.50` | `host=WS-PC050` (10.0.1.50) |
| **Filename** | URL ends with `Invoice_2026-0127.exe` | `image=...\Downloads\Invoice_2026-0127.exe` |
| **Time Proximity** | `09:12:38` | `09:14:22` (~1m 44s later) |
| **Flow** | File downloaded from external source | Same file executing locally |

### Why Neither Event Alone Is Conclusive

| Event Alone | Why It's Ambiguous |
|-------------|-------------------|
| **Proxy download only** | Users download files from the internet constantly — software updates, shared documents, images. A single download to an unfamiliar domain could be a new vendor, a shared link from a colleague, or a one-time resource |
| **Sysmon ProcessCreate only** | Users run executables from Downloads regularly — installers, utilities, tools. An `.exe` running from Downloads with `explorer.exe` as parent is common for legitimate software installs |
| **Together** | File downloaded from a domain impersonating DocuSign + that exact file executing from Downloads 2 minutes later = phishing payload delivery and execution. The domain impersonation, `.exe` disguised as an invoice, and `application/octet-stream` content type complete the picture |

### The Level 3 Difficulty Factor

This scenario requires the player to evaluate **multiple subtle indicators** that individually could be innocent:

| Context Factor | What the Player Must Recognize |
|---------------|-------------------------------|
| **Domain impersonation** | `docusign-review.shanoindustries.com` is not DocuSign — the player must check the root domain, not just the subdomain |
| **File type mismatch** | An "invoice" should be a `.pdf` or `.xlsx`, not an `.exe` — the name is social engineering |
| **Content-Type** | `application/octet-stream` means binary executable — legitimate documents have specific MIME types |
| **Download-to-execution pipeline** | Connecting a proxy download event to a Sysmon process creation requires recognizing the same filename across different log sources |
| **Time gap** | ~2 minutes between download and execution is realistic for a user who downloaded, then navigated to their Downloads folder |

---

## Level Progression Preview

| Level | Events | Complexity |
|-------|--------|------------|
| **Level 1** | 1 | Single event — Executable download from known-bad URL |
| **Level 2** | 2 | Two events — Phishing email received + suspicious link clicked |
| **Level 3** (Current) | 2 | Two events — Download from impersonation domain + payload execution (context-heavy, no obvious IOCs) |

---

## Related Log Sources

For more advanced scenarios, phishing attacks can be detected across multiple sources:

| Log Source | Event Type | What It Shows |
|------------|------------|---------------|
| **Proxy HTTP_GET** | File Download | Payload delivery from phishing URL (this scenario) |
| **Sysmon Event 1** | ProcessCreate | Payload execution on workstation (this scenario) |
| **DNS QUERY_RECEIVED** | DNS Query | Resolution of phishing domain — precedes the download |
| **Sysmon Event 11** | FileCreate | Payload written to Downloads folder |
| **Sysmon Event 3** | NetworkConnection | Post-execution C2 connection from the payload |
| **Sysmon Event 13** | RegistryEvent | Persistence mechanism installed by payload |
| **Email Gateway** | Inbound Email | Original phishing email with URL |
| **Windows Security 4688** | Process Creation | Alternative to Sysmon for execution tracking |

---

## Detection Rule Logic (Reference)

```
# Proxy: Executable download from impersonation domain
MATCH proxy_logs WHERE
  method = "GET"
  AND http_status = 200
  AND content_type = "application/octet-stream"
  AND (
    url MATCHES "*.exe" OR
    url MATCHES "*.scr" OR
    url MATCHES "*.bat" OR
    url MATCHES "*.ps1" OR
    url MATCHES "*.msi"
  )
  AND dst_ip NOT IN known_software_vendors

# Sysmon: Executable running from Downloads folder
MATCH sysmon_logs WHERE
  event_type = "ProcessCreate"
  AND image MATCHES "*\\Downloads\\*.exe"
  AND parent_image CONTAINS "explorer.exe"

# Correlation: Phishing payload delivery and execution
MATCH proxy_logs AS download
  JOIN sysmon_logs AS execution
  ON download.src_ip = execution.host_ip
  AND download.url_filename = execution.image_filename
  AND execution.utc_time BETWEEN download.timestamp AND download.timestamp + 600s
WHERE
  download.method = "GET"
  AND download.content_type = "application/octet-stream"
  AND execution.event_type = "ProcessCreate"
  AND execution.image MATCHES "*\\Downloads\\*"
  AND execution.parent_image CONTAINS "explorer.exe"
```

---

## Common False Positives

Understanding legitimate scenarios helps avoid alert fatigue:

| False Positive Scenario | How to Identify |
|-------------------------|-----------------|
| Employee downloading approved software installer | Known vendor domain, IT-approved application, download from official site |
| Auto-update downloading new version | Parent process is the update service (GoogleUpdate.exe, AdobeARM.exe), not explorer.exe |
| Developer downloading tools from GitHub releases | Domain is `github.com` or `objects.githubusercontent.com`, known tool |
| IT deploying software via download link | IT-sanctioned URL, communicated via official channels, known file hash |
| Browser downloading PDF that gets misidentified | Content-Type is `application/pdf`, file extension is `.pdf`, opens in Acrobat |

**Key Differentiators:**
- Legitimate: Known vendor domain, expected file type, official download source, IT-approved
- Malicious: Impersonation domain, executable disguised as document, `octet-stream` content type, unsolicited email source, file runs from Downloads

---

## Process Chain Analysis

Understanding the execution flow helps identify phishing payloads:

### Suspicious Chain (This Scenario)
```
[WS-PC050] Phishing email → user clicks link in Outlook/browser
  └── chrome.exe downloads Invoice_2026-0127.exe
      └── Saved to C:\Users\mwilliams\Downloads\
           │
           └── User double-clicks file in explorer.exe
               └── Invoice_2026-0127.exe (MALWARE)
                   └── NEXT: establish persistence, contact C2, harvest credentials...
```
**Why Suspicious:** Executable downloaded from impersonation domain, disguised as invoice, executed manually from Downloads

### Legitimate Chain (Software Install)
```
[WS-PC050] IT email: "Please install the new VPN client from https://vendor.com/download"
  └── chrome.exe downloads VPNClient-v3.2.1.exe
      └── Saved to C:\Users\mwilliams\Downloads\
           │
           └── User double-clicks file in explorer.exe
               └── VPNClient-v3.2.1.exe (LEGITIMATE)
                   └── msiexec.exe installs VPN client to Program Files
```
**Why Legitimate:** Known vendor domain, expected software, IT-sanctioned, installs to standard location

---

## Phishing Red Flags Quick Reference

| Category | Red Flag | Example |
|----------|----------|---------|
| **Domain** | Subdomain impersonation on unrelated root | `docusign-review.shanoindustries.com` |
| **Domain** | Typosquatting | `docuslgn.com`, `d0cusign.com` |
| **Domain** | Recently registered domain | Domain age < 30 days |
| **File** | Executable disguised as document | `Invoice.exe`, `Report.scr` |
| **File** | Double extension | `Invoice.pdf.exe` |
| **File** | Content-Type mismatch | `.pdf` filename but `application/octet-stream` |
| **Behavior** | Download from email link → immediate execution | Proxy GET → Sysmon ProcessCreate |
| **Behavior** | File runs from Downloads/Temp/Desktop | Not installed to Program Files |
| **Email** | Urgency language | "Immediate action required", "Account suspended" |
| **Email** | Sender domain doesn't match brand | DocuSign email from `@shanoindustries.com` |

---

*Last Updated: January 2026*  
*Spectyr Training Platform*
