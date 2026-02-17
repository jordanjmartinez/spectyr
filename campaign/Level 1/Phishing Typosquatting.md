# Phishing - Level 1 Scenario

> **Category:** Phishing  
> **Subcategory:** Typosquatting / Lookalike Domain  
> **Difficulty:** Level 1 (Fundamentals)  
> **Events:** 1

---

## Scenario Description

A user's workstation made an HTTP request to a suspicious domain. Review the web proxy log and determine if this represents a security threat.

---

## Attack Pattern Reference

| Framework | ID | Name | Link |
|-----------|-----|------|------|
| MITRE ATT&CK | **T1583.001** | Acquire Infrastructure: Domains | [attack.mitre.org](https://attack.mitre.org/techniques/T1583/001/) |
| ATT&CK Tactic | **TA0042** | Resource Development | |
| CAPEC | **CAPEC-630** | Typosquatting | [capec.mitre.org](https://capec.mitre.org/data/definitions/630.html) |
| Related Technique | **T1566** | Phishing (likely delivery method) | [attack.mitre.org](https://attack.mitre.org/techniques/T1566/) |

> **Note:** The proxy log shows the user accessed a typosquatted domain. This is likely the result of clicking a phishing link (T1566), but the email delivery cannot be confirmed from proxy logs alone.

---

## Log Event

### Table View

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| 09:47:33.245 | HTTP_GET | Proxy | 10.0.1.45 | 185.234.72.19 | TCP | `1705315653.245 892 10.0.1.45 TCP_MISS/200 34521 GET https://micr0soft.com/signin - DIRECT/185.234.72.19 text/html` |

### Expanded Key Value Pairs

```
src_ip = 10.0.1.45
dst_ip = 185.234.72.19
url = https://micr0soft.com/signin
method = GET
http_status = 200
bytes = 34521
elapsed_ms = 892
cache_result = TCP_MISS
hierarchy_code = DIRECT
content_type = text/html
user = -
host = WS-PC045
domain = micr0soft.com
url_path = /signin
```

---

## Expected Answer

**Classification:** Malicious - Phishing (Typosquatting)

**Threat Category:** Credential Harvesting via Lookalike Domain

---

## Triage Review

### Why This Event is Suspicious

| Indicator | Explanation |
|-----------|-------------|
| **Typosquatted Domain** | `micr0soft.com` uses "0" (zero) instead of "o" to impersonate Microsoft |
| **Login Path** | `/signin` indicates a credential harvesting page |
| **Unfamiliar IP Address** | `185.234.72.19` is not a Microsoft-owned IP range (Microsoft uses 13.x.x.x, 20.x.x.x, 40.x.x.x, 52.x.x.x, etc.) |
| **TCP_MISS** | Content fetched from origin, not cached — suggests first visit to a new/unknown site |

### What is Typosquatting?

Typosquatting (CAPEC-630) is when attackers register domains that closely resemble legitimate ones to deceive users. Common techniques include:

| Technique | Legitimate | Typosquat Example |
|-----------|------------|-------------------|
| **Character Substitution** | microsoft.com | micr**0**soft.com (zero for 'o') |
| **Homograph Attack** | microsoft.com | mícrosoft.com (accented character) |
| **Missing Character** | microsoft.com | microoft.com |
| **Extra Character** | microsoft.com | microsoftt.com |
| **Adjacent Key** | microsoft.com | microsofy.com ('y' next to 't') |
| **TLD Swap** | microsoft.com | microsoft**.net** |

### Attack Context

Typosquatted domains are commonly used in phishing campaigns to:

- **Harvest credentials** — Fake login pages capture usernames and passwords
- **Distribute malware** — Drive-by downloads or malicious file hosting
- **Steal session tokens** — OAuth consent phishing to gain account access
- **Impersonate brands** — Social engineering to build false trust

This proxy log shows the user accessed a typosquatted domain. The most likely cause is that the user clicked a link in a phishing email (T1566), but this cannot be confirmed without email gateway logs.

### Real-World Examples

| Campaign/Threat | Typosquatting Use |
|-----------------|-------------------|
| **Credential Phishing** | Fake Microsoft, Google, and banking login pages |
| **BEC (Business Email Compromise)** | Lookalike domains for invoice fraud |
| **Watering Hole Attacks** | Typosquatted developer tool sites (npm, PyPI) |
| **Brand Impersonation** | Fake customer support or IT helpdesk domains |

### MITRE ATT&CK Context

**Technique T1583.001 - Acquire Infrastructure: Domains**

> "Adversaries may acquire domains that can be used during targeting. Domain names are the human readable names used to represent one or more IP addresses... Adversaries may use acquired domains for a variety of purposes, including for Phishing, Drive-by Compromise, and Command and Control."

**Related Technique: T1566 - Phishing**

If this domain access originated from an email link, the full attack chain would include:
- **T1566.002** (Spearphishing Link) — Targeted email with malicious URL
- **T1583.001** (Acquire Infrastructure: Domains) — Typosquatted domain registration
- **T1078** (Valid Accounts) — If credentials were harvested and used

---

## Recommended Response Actions

1. **Immediate:** Block domain `micr0soft.com` at proxy/firewall
2. **User Contact:** Interview user at 10.0.1.45 (WS-PC045) about the activity
3. **Credential Reset:** If user entered credentials, force immediate password reset
4. **Session Invalidation:** Revoke active sessions for affected accounts
5. **Email Search:** Query email logs for messages containing links to this domain
6. **Scope Assessment:** Check proxy logs for other users who accessed this domain
7. **Threat Intel:** Submit domain to threat intelligence platforms for enrichment

---

## Log Authenticity Notes

| Field | Value | Why It's Realistic |
|-------|-------|-------------------|
| `TCP_MISS/200` | Page loaded successfully from origin server (not cached) — typical for first visit to an unknown site |
| `elapsed_ms=892` | Slightly higher latency common for overseas-hosted phishing infrastructure |
| `bytes=34521` | Reasonable size for a credential harvesting page mimicking Microsoft branding |
| `content_type=text/html` | Expected for a login/signin page |
| `DIRECT/185.234.72.19` | Direct connection to phishing server IP |
| `user=-` | No proxy authentication (common in many environments) |

### Legitimate vs Malicious Domain Comparison

| Legitimate Microsoft Domains | Malicious (This Scenario) |
|------------------------------|---------------------------|
| `microsoft.com` | `micr0soft.com` |
| `login.microsoftonline.com` | Uses "0" (zero) instead of "o" |
| `outlook.office365.com` | |
| Microsoft IP ranges: 13.x, 20.x, 40.x, 52.x, 104.x | `185.234.72.19` (non-Microsoft IP) |

---

## Level Progression Preview

| Level | Events | Complexity |
|-------|--------|------------|
| **Level 1** (Current) | 1 | Single proxy event — user accessed typosquatted domain |
| **Level 2** | 2-3 | DNS query + Proxy GET + Proxy POST (credential submission) |
| **Level 3** | 4-6 | Full chain: DNS → GET → POST → Foreign IP login (account takeover) |

---

## Related Log Sources

For more advanced scenarios, typosquatting/phishing can be detected across multiple log sources:

| Log Source | Event Type | What It Shows |
|------------|------------|---------------|
| **DNS** | QUERY_RECEIVED | Resolution request for typosquatted domain |
| **Proxy** | HTTP_GET | User accessed phishing page (this scenario) |
| **Proxy** | HTTP_POST | User submitted credentials to phishing page |
| **Firewall** | ALLOW/DENY | Connection to suspicious/blocked IP |
| **Sysmon Event 22** | DNS Query | Process-level attribution (Outlook.exe, Chrome.exe queried the domain) |
| **Windows Security** | 4624/4625 | Logon attempts with potentially stolen credentials |

---

## Detection Rule Logic (Reference)

```
# Proxy-based typosquatting detection
MATCH proxy_logs WHERE
  (
    domain MATCHES "micr.soft" OR      # Character substitution patterns
    domain MATCHES "g..gle" OR
    domain MATCHES "amaz.n"
  )
  AND domain NOT IN (legitimate_domain_allowlist)
  
# DNS-based detection
MATCH dns_logs WHERE
  qname MATCHES "*micr0soft*" OR
  qname MATCHES "*0ffice365*" OR
  qname MATCHES "*paypa1*"
```

---

## Common Typosquatting Patterns by Brand

| Brand Target | Typosquat Examples |
|--------------|-------------------|
| **Microsoft** | micr0soft, micosoft, microsft, mircosoft, rnicrosoft |
| **Google** | g00gle, googie, go0gle, goog1e, gooogle |
| **Amazon** | amaz0n, arnazon, amazonn, arnezon |
| **Apple** | app1e, appie, aple, applle |
| **PayPal** | paypa1, paypai, paypal-secure, payypal |

---

*Last Updated: January 2026*  
*Spectyr Training Platform*
