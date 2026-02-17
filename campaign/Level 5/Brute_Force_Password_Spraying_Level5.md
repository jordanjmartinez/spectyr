# Brute Force: Password Spraying — Level 5

> **Category:** Brute Force
> **Subcategory:** Password Spraying
> **Difficulty:** Level 5 (Pattern Recognition)
> **Events:** 5
> **MITRE ATT&CK:** T1110.003 — Brute Force: Password Spraying

---

## Scenario Description

Five Windows Security failed logon events appeared within a short time window. Each event targets a different user account, but all originate from the same source IP and workstation. No individual account triggered a lockout threshold. Review the events and determine if this pattern represents a password spraying attack.

---

## Attack Pattern Reference

| Framework | ID | Name | Link |
|-----------|-----|------|------|
| MITRE ATT&CK | **T1110.003** | Brute Force: Password Spraying | [attack.mitre.org](https://attack.mitre.org/techniques/T1110/003/) |
| MITRE ATT&CK | **T1110** | Brute Force | [attack.mitre.org](https://attack.mitre.org/techniques/T1110/) |
| ATT&CK Tactic | **TA0006** | Credential Access | |
| CAPEC | **CAPEC-565** | Password Spraying | |

> **Note:** T1110.003 is specifically about trying a small number of commonly used passwords against many accounts. Unlike dictionary attacks (T1110.001) which try many passwords against one account, password spraying distributes attempts across accounts to avoid triggering lockout policies. This is the most common brute force technique used by real-world threat actors today because it's designed to evade the exact controls that catch traditional brute force.

---

## Log Events

### Event 1 of 5 — Failed Logon: jsmith (Windows Security 4625)

**Table View:**

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| {timestamp_1} | 4625 | Windows Security | {src_ip} | — | — | An account failed to log on. |

**Key Value Pairs:**

```
timestamp = {timestamp_1}
event_type = 4625
source_type = Windows Security
host = ACME-DC01
src_ip = {src_ip}
target_user = jsmith
target_domain = ACME
logon_type = 3
failure_reason = Unknown user name or bad password.
status = 0xC000006D
sub_status = 0xC000006A
auth_package = NTLM
workstation_name = {hostname}
message = An account failed to log on.
```

---

### Event 2 of 5 — Failed Logon: mramirez (Windows Security 4625)

**Table View:**

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| {timestamp_2} | 4625 | Windows Security | {src_ip} | — | — | An account failed to log on. |

**Key Value Pairs:**

```
timestamp = {timestamp_2}
event_type = 4625
source_type = Windows Security
host = ACME-DC01
src_ip = {src_ip}
target_user = mramirez
target_domain = ACME
logon_type = 3
failure_reason = Unknown user name or bad password.
status = 0xC000006D
sub_status = 0xC000006A
auth_package = NTLM
workstation_name = {hostname}
message = An account failed to log on.
```

---

### Event 3 of 5 — Failed Logon: lwright (Windows Security 4625)

**Table View:**

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| {timestamp_3} | 4625 | Windows Security | {src_ip} | — | — | An account failed to log on. |

**Key Value Pairs:**

```
timestamp = {timestamp_3}
event_type = 4625
source_type = Windows Security
host = ACME-DC01
src_ip = {src_ip}
target_user = lwright
target_domain = ACME
logon_type = 3
failure_reason = Unknown user name or bad password.
status = 0xC000006D
sub_status = 0xC000006A
auth_package = NTLM
workstation_name = {hostname}
message = An account failed to log on.
```

---

### Event 4 of 5 — Failed Logon: kbrown (Windows Security 4625)

**Table View:**

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| {timestamp_4} | 4625 | Windows Security | {src_ip} | — | — | An account failed to log on. |

**Key Value Pairs:**

```
timestamp = {timestamp_4}
event_type = 4625
source_type = Windows Security
host = ACME-DC01
src_ip = {src_ip}
target_user = kbrown
target_domain = ACME
logon_type = 3
failure_reason = Unknown user name or bad password.
status = 0xC000006D
sub_status = 0xC000006A
auth_package = NTLM
workstation_name = {hostname}
message = An account failed to log on.
```

---

### Event 5 of 5 — Failed Logon: dpatel (Windows Security 4625)

**Table View:**

| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE |
|------|------------|------------|-----------|---------|----------|---------|
| {timestamp_5} | 4625 | Windows Security | {src_ip} | — | — | An account failed to log on. |

**Key Value Pairs:**

```
timestamp = {timestamp_5}
event_type = 4625
source_type = Windows Security
host = ACME-DC01
src_ip = {src_ip}
target_user = dpatel
target_domain = ACME
logon_type = 3
failure_reason = Unknown user name or bad password.
status = 0xC000006D
sub_status = 0xC000006A
auth_package = NTLM
workstation_name = {hostname}
message = An account failed to log on.
```

---

## Expected Answer

**Classification:** Brute Force — Password Spraying
**Threat Level:** High
**Confidence:** High

---

## Triage Review

### What is it?

**Password spraying** is a brute force technique where the attacker tries one or two common passwords against many different user accounts. Instead of hammering one account with thousands of passwords (which triggers lockout), the attacker spreads attempts across the entire user base — staying below the lockout threshold for every individual account.

This is the most common brute force technique used by real-world threat actors today. It works because:

- Most organizations set account lockout at 3-5 failed attempts
- The attacker only tries 1-2 passwords per account, so no lockout triggers
- Common passwords like `Spring2026!`, `Welcome123`, `Company1!` are used by at least a few employees in every organization
- The attacker only needs *one* success across hundreds of attempts to get a foothold

In this scenario, the attacker tried the same password against 5 different ACME accounts from a single workstation. All 5 failed — but this is likely just one wave of a larger spray. The attacker may try another password across the same accounts in 30-60 minutes.

| Indicator | What It Means | Why It's Suspicious |
|-----------|---------------|---------------------|
| **Same source IP across all 5 events** | All attempts originate from one machine | Single source systematically targeting multiple accounts |
| **5 different target accounts** | jsmith, mramirez, lwright, kbrown, dpatel | Distributed targeting — the hallmark of password spraying |
| **All failures within ~30-50 seconds** | Rapid sequential attempts | Automated tool, not a human mistyping passwords |
| **Logon Type 3 (Network)** | Remote authentication over the network | Not someone at a keyboard — network-based attack |
| **NTLM authentication** | Older authentication protocol | Many spray tools default to NTLM because it's simpler to automate |
| **sub_status 0xC000006A** | Specifically means "bad password" | Confirms the accounts exist — attacker has a valid user list |
| **All targeting ACME-DC01** | Authenticating directly against the domain controller | Attacker is hitting the central authentication server |
| **No lockout triggered** | Only 1 attempt per account | Deliberately staying below lockout threshold — sophisticated attacker |

### Understanding the Attack Pattern

```
ATTACKER WORKSTATION ({src_ip})
  │
  ├── {timestamp_1}: Try password against jsmith → FAILED
  ├── {timestamp_2}: Try password against mramirez → FAILED
  ├── {timestamp_3}: Try password against lwright → FAILED
  ├── {timestamp_4}: Try password against kbrown → FAILED
  └── {timestamp_5}: Try password against dpatel → FAILED
       │
       ▼
  WAVE 1 COMPLETE — 0 successes out of 5
       │
       ▼
  ATTACKER WAITS 30-60 MINUTES (avoids detection)
       │
       ▼
  WAVE 2: Try a DIFFERENT password against same 5 accounts
  (not visible in these logs — hasn't happened yet, or
   is happening and these events are in a different batch)
```

### Password Spraying vs Dictionary Attack — How the Player Should Distinguish

Level 2 taught the player to recognize a dictionary attack. Level 5 requires them to understand why password spraying is different and harder to detect.

| Factor | Dictionary Attack (Level 2) | Password Spraying (This Scenario) |
|--------|----------------------------|-----------------------------------|
| **Target** | One account, many passwords | Many accounts, one password |
| **Attempts per account** | 10-100+ failures on same account | 1-2 failures per account |
| **Lockout triggered?** | Yes — account locks after threshold | No — stays below threshold per account |
| **Detection pattern** | Obvious — many 4625s for same user | Subtle — single 4625 per user looks normal individually |
| **What the player sees** | Repeated failures for `jsmith` | Single failures across jsmith, mramirez, lwright, kbrown, dpatel |
| **Key indicator** | Volume of failures on one account | Distribution of failures across accounts from same source |
| **Attacker sophistication** | Low — noisy, triggers alerts | Medium-High — designed to evade lockout and detection |
| **MITRE technique** | T1110.001 (Dictionary) | T1110.003 (Password Spraying) |

### Why No Individual Event Looks Suspicious

This is what makes password spraying hard to detect. Look at any single event in isolation:

```
Event 3 alone:
  4625 — lwright failed to log on from {src_ip}
  → "lwright probably mistyped their password. Normal."
```

One failed logon for one user is noise. It happens hundreds of times a day. The attack only becomes visible when you **aggregate across accounts** and notice:

- Same source IP
- Different target accounts
- Same time window
- Same failure reason

This is a critical SOC skill: individual events are meaningless, but the *pattern* across events reveals the attack.

### Sub-Status Codes Reference

The `sub_status` field in Event 4625 tells you exactly why the logon failed. This matters for distinguishing attack types:

| Sub-Status Code | Meaning | What It Tells You |
|-----------------|---------|-------------------|
| **0xC000006A** | Bad password (this scenario) | Account exists, password is wrong — attacker has valid usernames |
| 0xC0000064 | User does not exist | Attacker is guessing usernames — less targeted |
| 0xC0000234 | Account locked out | Lockout threshold hit — dictionary attack, not spray |
| 0xC0000072 | Account disabled | Targeting inactive accounts — possibly using an old user list |
| 0xC000006D | Generic logon failure | Catch-all — could be username or password |
| 0xC0000071 | Password expired | Account exists but password needs reset |

In this scenario, all events show `0xC000006A` (bad password), which confirms the attacker has a valid list of ACME usernames. They know *who* to target — they're just guessing the password.

### Where Do Attackers Get Username Lists?

| Source | Method |
|--------|--------|
| **LinkedIn** | Scrape employee names, convert to username format (first initial + last name) |
| **Company website** | About Us page, team directory, press releases |
| **Email harvesting** | If email format is jsmith@acme.com, username is likely jsmith |
| **Previous breach** | Leaked credentials from another service may include corporate emails |
| **OSINT tools** | theHarvester, Hunter.io, LinkedIn2Username |
| **LDAP enumeration** | If the attacker already has a foothold, they can query Active Directory directly |

The fact that all 5 accounts in this scenario exist (sub_status 0xC000006A, not 0xC0000064) suggests the attacker did reconnaissance first to build a valid target list.

### Common Passwords Used in Spraying

| Pattern | Examples |
|---------|----------|
| **Season + Year + Special** | Spring2026!, Winter2025!, Summer2026# |
| **Company + Number** | Acme123!, Acme2026, AcmeLegal1 |
| **Welcome/Password** | Welcome1!, Password123, P@ssw0rd! |
| **Month + Year** | February2026!, January2026! |
| **Keyboard patterns** | Qwerty123!, 1qaz2wsx |

These patterns meet most password complexity requirements (uppercase, lowercase, number, special character) while being easy to guess. Organizations with password policies but no password blacklist are especially vulnerable.

---

## Recommended Triage Steps

### 1. Confirm the Spray Pattern
Verify that all 5 events share the same source IP but target different accounts. This is the defining characteristic of password spraying — distributed attempts from a single source.

### 2. Expand the Search Window
These 5 events may be a subset of a larger spray. Search for all 4625 events from {src_ip} in the past 24 hours. The attacker may have targeted dozens or hundreds of accounts across multiple waves.

### 3. Check for Any Successes
Search for 4624 events from {src_ip} after the spray window. If the attacker found a valid password, the success event is the most critical finding — that account is now compromised.

### 4. Identify the Source
What is {src_ip}? Options:
- **Internal workstation** — a compromised machine is being used as a launchpad. This means the attacker already has a foothold.
- **VPN IP** — attacker is using stolen VPN credentials or the corporate VPN gateway.
- **External IP** — attacker is spraying from outside. Check if this IP has been seen in threat intelligence feeds.

### 5. Verify the User List
All 5 targeted accounts exist (sub_status 0xC000006A). How did the attacker get a valid username list? Check for prior reconnaissance:
- LDAP queries from {src_ip}
- Access to the Global Address List
- LinkedIn scraping wouldn't show in logs, but it's the most common source

### 6. Enforce Password Resets
Even though all 5 attempts failed, the attacker may have succeeded against accounts not captured in these events. Consider:
- Forcing password reset for all targeted accounts
- Checking if any targeted account has a password matching common spray patterns
- Implementing a password blacklist if one doesn't exist

### 7. Block and Monitor
- Block {src_ip} at the firewall if it's external
- If internal, isolate the source machine for investigation
- Set up enhanced monitoring for future spray waves — the attacker will likely try again with a different password

### 8. Escalate Appropriately
Password spraying is a confirmed attack, not a false positive. Even though no accounts were compromised in this wave, the attacker has valid usernames and will try again. Escalate to ensure:
- Source is investigated and blocked
- Targeted accounts are protected
- Detection rules are tuned for future waves

---

## Generation Rules

| Variable | Rule |
|----------|------|
| {src_ip} | Same across all 5 events — single attacker source |
| {hostname} | Same across all 5 events — attacker workstation |
| host | ACME-DC01 across all 5 events — domain controller receiving authentication requests |
| target_user | Different for each event — jsmith, mramirez, lwright, kbrown, dpatel |
| target_domain | ACME across all events |
| logon_type | 3 (Network) across all events |
| auth_package | NTLM across all events |
| status / sub_status | 0xC000006D / 0xC000006A across all events (bad password) |
| {timestamp_1} → {timestamp_5} | ~5-10 second gaps between each attempt (automated tool pacing) |
| Timestamps | Can be any time — spraying happens during and after business hours |

---

## What the Player Should Recognize

| Indicator | Evidence |
|-----------|----------|
| Same source IP across all events | {src_ip} appears in every event — single origin point |
| Different target accounts | 5 different usernames — distributed targeting |
| Rapid sequential timing | ~30-50 seconds total — automated, not manual |
| All bad password failures | sub_status 0xC000006A means accounts exist, passwords wrong |
| No lockout triggered | 1 attempt per account — deliberately below threshold |
| Network logon type | Logon Type 3 = remote authentication, not local |
| NTLM authentication | Common for spray tools — simpler to automate than Kerberos |
| Domain controller targeted | ACME-DC01 = authenticating against central AD server |

### The Level 5 Difficulty Factor

| Stage | What the Player Must Recognize | Difficulty |
|-------|-------------------------------|------------|
| **1. Pattern Recognition** | No single event is suspicious — the player must aggregate across all 5 events and recognize the distributed targeting pattern | High |
| **2. Spray vs Dictionary** | Level 2 taught dictionary attacks (many passwords, one account). The player must recognize the inverse pattern and classify correctly | High |
| **3. Sub-Status Interpretation** | 0xC000006A specifically means bad password, not account-not-found — the player must understand this means the attacker has valid usernames | Medium |
| **4. No Success Event** | There's no 4624 confirming the attack worked — the player must classify this as an attack based purely on the failed logon pattern, without a "smoking gun" success | High |
| **5. Threat Assessment Without Confirmation** | The player must escalate despite all attempts failing — understanding that the attacker will try again with a different password | Medium |

---

## Level Progression Preview

| Level | Events | Complexity |
|-------|--------|------------|
| **Level 2** (Dictionary Attack) | 5 | Many failures against one account + success — obvious pattern |
| **Level 5** (Current) | 5 | Distributed failures across accounts, no success — requires pattern recognition |
| **Level 7+** (Future) | 5-7 | Low-and-slow spray over days/weeks, mixed with legitimate failures, multiple source IPs |

---

## Related Log Sources

Additional logs that would appear in a real environment during this attack:

| Log Source | Event | What It Shows |
|------------|-------|---------------|
| **Windows Security 4624** | Successful Logon | Would appear if any sprayed account had the guessed password — the critical event to search for |
| **Windows Security 4776** | Credential Validation | NTLM credential validation events on the domain controller — shows the authentication attempt |
| **Windows Security 4771** | Kerberos Pre-Authentication Failed | If the attacker used Kerberos instead of NTLM |
| **Windows Security 4768** | Kerberos TGT Requested | Successful Kerberos authentication — would follow a spray success |
| **Firewall** | ALLOW/DENY | Network connections from {src_ip} to ACME-DC01 on port 445 (SMB) or 389 (LDAP) |
| **DNS** | Query | If the attacker resolved ACME-DC01's hostname before spraying |

---

## Detection Rule Logic

```
# Detect password spraying — multiple accounts failed from same source
MATCH windows_security_logs WHERE
  event_type = "4625"
  AND sub_status = "0xC000006A"
  GROUP BY src_ip
  HAVING COUNT(DISTINCT target_user) >= 3 WITHIN 300 SECONDS

# Detect spray followed by success — the worst case
MATCH windows_security_logs WHERE
  event_type = "4625"
  AND sub_status = "0xC000006A"
  GROUP BY src_ip
  HAVING COUNT(DISTINCT target_user) >= 3 WITHIN 300 SECONDS
FOLLOWED BY
  event_type = "4624"
  AND src_ip = same_source
  WITHIN 3600 SECONDS

# Detect NTLM spray specifically (many attackers use NTLM)
MATCH windows_security_logs WHERE
  event_type = "4625"
  AND auth_package = "NTLM"
  AND logon_type = 3
  GROUP BY src_ip
  HAVING COUNT(DISTINCT target_user) >= 5 WITHIN 600 SECONDS

# Detect low-and-slow spray (advanced — across longer windows)
MATCH windows_security_logs WHERE
  event_type = "4625"
  AND sub_status = "0xC000006A"
  GROUP BY src_ip
  HAVING COUNT(DISTINCT target_user) >= 10 WITHIN 86400 SECONDS
  AND MAX(count_per_user) <= 2
```

---

## Common False Positives

| False Positive Scenario | How to Identify |
|-------------------------|-----------------|
| Service account with expired password failing across multiple servers | Same target_user in all events (not different users), service account name pattern |
| Misconfigured application authenticating as wrong user | Same target_user, source is a known application server, consistent timing pattern |
| Employee trying remembered passwords after password change | Same target_user (one account), different passwords, not distributed across accounts |
| VPN concentrator logging multiple users' failed attempts under one IP | Source IP is a known VPN gateway, target_users are unrelated, timing doesn't show sequential pattern |
| Automated vulnerability scan | Source IP is a known scanner, targets many services not just authentication |

**Key Differentiators:**
- Password Spraying: Same source IP, different target accounts, same short time window, same failure type, no lockout triggered
- Legitimate Failures: Same user retrying their own password, source matches user's assigned workstation, isolated incident

---

## Real-World Threat Actors Using Password Spraying

| Threat Actor | Context |
|-------------|---------|
| **APT28 (Fancy Bear)** | Russian military intelligence — sprays against government and military targets globally |
| **APT33 (Elfin)** | Iranian state-sponsored — sprays against energy and aviation sectors |
| **DEV-0537 (LAPSUS$)** | Cybercriminal group — used spraying as initial access against Microsoft, Okta, and others |
| **Storm-0558** | Chinese state-sponsored — sprayed Microsoft cloud accounts to access government emails |
| **Midnight Blizzard (APT29)** | Russian intelligence — sprayed Microsoft corporate accounts in 2023-2024 breach |

---

## Password Spraying Prevention Reference

| Control | What It Does |
|---------|-------------|
| **Password blacklist** | Blocks common passwords (Season+Year, Company+Number patterns) at the policy level |
| **Smart lockout (Azure AD)** | Tracks failed attempts per user AND per IP — locks out attackers without affecting legitimate users |
| **MFA** | Even if the password is guessed, the attacker can't complete authentication without the second factor |
| **Conditional Access** | Blocks authentication from untrusted IPs, devices, or locations |
| **NTLM restrictions** | Disabling NTLM forces Kerberos, which is harder to spray and provides better logging |
| **Password expiration with blacklist** | Regular rotation combined with blacklist prevents predictable patterns |

---

## Process Chain Analysis

### Suspicious Pattern (This Scenario)
```
[{hostname}] Spray tool running (automated)
  │
  ├── {timestamp_1}: 4625 → jsmith @ ACME-DC01 (FAILED — bad password)
  ├── {timestamp_2}: 4625 → mramirez @ ACME-DC01 (FAILED — bad password)
  ├── {timestamp_3}: 4625 → lwright @ ACME-DC01 (FAILED — bad password)
  ├── {timestamp_4}: 4625 → kbrown @ ACME-DC01 (FAILED — bad password)
  └── {timestamp_5}: 4625 → dpatel @ ACME-DC01 (FAILED — bad password)
       │
       ▼
  5 different accounts, same source, ~30-50 seconds
  = PASSWORD SPRAYING PATTERN
```
**Why Suspicious:** Single source targeting multiple accounts sequentially, all bad-password failures, automated timing, NTLM authentication, no lockout triggered because only 1 attempt per account

### Legitimate Pattern (User Mistyping Password)
```
[ACME-WS15] User at keyboard
  │
  ├── 08:01:15: 4625 → jsmith @ ACME-DC01 (FAILED — mistyped password)
  ├── 08:01:22: 4625 → jsmith @ ACME-DC01 (FAILED — mistyped again)
  └── 08:01:30: 4624 → jsmith @ ACME-DC01 (SUCCESS — got it right)
       │
       ▼
  Same account, same source, followed by success
  = NORMAL USER BEHAVIOR
```
**Why Legitimate:** Same target account (not distributed), source is user's assigned workstation, ends with successful logon, consistent with human typing errors

---

*Last Updated: February 2026*
*Spectyr Training Platform*
