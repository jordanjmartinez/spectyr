# Detection Density — Pilot Narrative Scaffolds (step 3a)

SCAFFOLD ONLY. No schema change, no scenario edit, no commit until the owner
approves these narratives. This document reflects the ruled architecture.

## Ruled architecture (for reference; implemented later, not now)

- **supplemental_events**: a scenario-level section in schema v2, sibling to
  `attack` and `noise`. Authored benign telemetry with stable ids, merged into
  the single cached session pool (same seed, frozen clock, placeholders,
  sanitization, leak guards, integrity checks). Renders in SIEM and on
  relevant endpoint pages. NO per-detection synthetic events.
- **Detection triggers**: `triggers` stays required; a detection references
  attack step ids and/or supplemental event ids only. Supplemental ids use a
  distinct prefix (`sup1`, `sup2`, ...) so the id-space stays unique.
- **Entities (hybrid)**: recurring internal actors become canonical in the
  reference environment; one-off externals go in a `supplemental_entities`
  section. Every host/account/IP/domain referenced by any event must resolve
  to the canonical environment or supplemental_entities (registry-resolution
  test). Authorization GROUND TRUTH (benign/authorized) is server-side only;
  authorization EVIDENCE (source host role, account type, timing, group
  membership) is world-visible.
- Parity, root_cause, scoring, radar, answer-key order: untouched.

## Safeguards applied to every narrative

- Disposition not inferable from count, order, severity, rule name, source, or
  authored status. FPs span severities incl. Critical-looking; TPs include
  Medium-looking.
- Every FP has a believable investigative story at the USB-parking-lot bar.
- Single world state: every trigger, PID, host, account, IP resolves
  consistently in SIEM, endpoints, and detections.

---

# PILOT 1 — lateral_movement_1 (Lateral Movement)

Attack chain (unchanged): s1 nmap.exe exec on the victim workstation → s2-s4
firewall probes victim→file server → s5 anomalous 4624 logon on the file
server (root_cause/trigger, TP) → s6 net.exe on the file server.

Current detections: 1 (`det_lateral_logon`, true_positive, s5).
Proposed: 3 detections (2 TP + 1 FP). Severity deliberately inverted vs the
naive expectation (an FP is the highest severity; a TP is Medium).

### D1. det_lateral_logon  (KEEP)
- disposition: **true_positive**
- rule name: "Anomalous Internal Logon Following Connection Sweep"
- severity: **high**  | source: Windows Security | mitre: T1046 Discovery
- trigger: attack step **s5** (4624 network logon on the file server)
- story: A network logon landed on the file server from a workstation that had
  just probed its service ports. No admin task or ticket explains it; the
  logon account is a standard user. This is the lateral step.
- entities: existing (ws_victim, file server, victim account).
- timestamp: inherited from s5. Not a red herring.

### D2. det_portscan_exec  (ADD, TP)
- disposition: **true_positive**
- rule name: "Network Scanning Utility Executed from User Profile"
- severity: **medium**  (deliberately Medium-looking TP)  | source: Sysmon
  | mitre: T1046 Discovery
- trigger: attack step **s1** (nmap.exe ProcessCreate on ws_victim)
- story: nmap ran from a standard user's Downloads folder on a non-IT
  workstation. Scanning tools there are unusual and warrant a look; here it is
  the recon that precedes the lateral logon. A real but quieter signal than
  the logon.
- entities: existing (ws_victim, victim account).
- timestamp: inherited from s1. Not a red herring.

### D3. det_scanner_sweep  (ADD, coexisting FP)
- disposition: **false_positive**
- rule name: "Rapid Internal Port Connections Across Segment"
- severity: **high**  (deliberately High-looking FP; reads like recon)
  | source: Firewall | mitre: (none, or T1046-shaped)
- trigger: **supplemental event sup1** (see below)
- story: The security team's authenticated vulnerability scanner runs a
  scheduled weekly sweep from ACME-SEC01, connecting rapidly to many internal
  hosts including the file server. The sweep tripped the same lateral-recon
  rule. Authorization evidence the analyst can see: the source is the
  scanner host (scanner role), the account is a service account, and the
  timing matches the scan schedule. Benign.
- entities NEEDED:
  - **Canonical add**: `ACME-SEC01`, role `scanner`, IP `10.0.1.207` (next
    free), OS Windows Server 2019, managed=true. Account `svc_vulnscan`
    (service, domain ACME, member of a scanning group). Flag both in
    ENVIRONMENT_REPORT.md; update CLAUDE.md server table.
  - **STUB-FLAG**: ACME-SEC01 / svc_vulnscan / the Nessus install are invented
    infrastructure; approve or supply canonical identities.
- supplemental event **sup1**: Firewall telemetry of rapid connections from
  ACME-SEC01 (svc_vulnscan, nessusd.exe context) to internal hosts incl. the
  file server. Passes PID/PPID/host integrity; renders in SIEM and on the
  ACME-SEC01 endpoint page.
- **timestamp placement**: sup1 authored at **attack_base − 120s** (the
  scanner's scheduled run precedes the intrusion by ~2 minutes), a distinct
  cluster in the SIEM timeline, deliberately separated from the s1-s6 window.
  **Red-herring declaration: NOT a red herring.** Deliberately time-separated
  to avoid accidental correlation; the analyst distinguishes it by source
  (ACME-SEC01 scanner, service account), not by guessing.
  - Alternative on request: place sup1 in-window as a DECLARED intentional
    red herring (two scan-shaped signals at once, distinguished only by
    source). Harder; flag for approval if you want it.

Disposition-hiding check: count 3; a Medium TP (portscan) and a High FP
(scanner sweep) invert the naive severity heuristic; two scan-shaped
detections (portscan TP, scanner FP) can't be told apart by rule-name class;
sources spread across Sysmon / Windows Security / Firewall; all authored.

---

# PILOT 2 — false_positive_veeam (False Positive)

Attack chain (all benign): s1 Veeam backup start → s2 Veeam endpoint service
ProcessCreate → s3 NetworkConnect service→backup server (trigger) → s4
firewall ALLOW → s5 Veeam backup complete (transfer volume). This scenario
needs NO supplemental event: every benign chain step is available to trigger
on. It demonstrates the case where supplemental_events are not required.

Current detections: 1 (`det_fp_veeam`, false_positive, s3).
Proposed: 3 detections, all false_positive, all TP-looking, spanning
severities up to Critical-looking.

### D1. det_fp_veeam  (KEEP)
- disposition: **false_positive**
- rule name: "Periodic Outbound Beacon to Internal Host"
- severity: **high**  | source: Sysmon | mitre: (C2-shaped, none authored)
- trigger: attack step **s3** (NetworkConnect to the backup server)
- story: The endpoint backup agent makes regular, fixed-interval outbound
  connections to the backup server. The cadence reads exactly like C2
  beaconing. Evidence it is benign: the process is the signed Veeam agent, the
  destination is the internal backup server, and it runs under SYSTEM on the
  backup schedule.
- entities: existing (ws_victim, backup_server ACME-VEEAM01).
- timestamp: inherited from s3. Not a red herring.

### D2. det_veeam_bulk_egress  (ADD, FP)
- disposition: **false_positive**
- rule name: "Large Off-Hours Data Egress Volume"
- severity: **critical**  (deliberately Critical-looking FP; big off-hours
  transfer reads like mass exfiltration) | source: Veeam | mitre: (exfil-shaped)
- trigger: attack step **s5** (Veeam 190 completion, carries the >1.75 GB
  volume)
- story: Over 1.75 GB left the host outside business hours. Volume-plus-timing
  is the classic staged-exfiltration shape. Evidence it is benign: it is the
  nightly full backup completing to the internal backup repository, logged by
  Veeam itself.
- entities: existing.
- timestamp: inherited from s5. Not a red herring.

### D3. det_veeam_svc_persist  (ADD, FP)
- disposition: **false_positive**
- rule name: "Service Binary Establishing Scheduled Outbound"
- severity: **medium**  | source: Sysmon | mitre: (persistence-shaped)
- trigger: attack step **s2** (Veeam endpoint service ProcessCreate)
- story: A service binary that establishes regular outbound connections
  overlaps with the shape of C2 service persistence. Evidence it is benign:
  the binary is the signed Veeam endpoint service in Program Files, installed
  by the backup deployment.
- entities: existing.
- timestamp: inherited from s2. Not a red herring.

Disposition-hiding check: all three are believable threats (beacon, mass
egress, service persistence) spanning Medium/High/Critical; nothing in count,
severity, source, or naming says "benign." The scenario must be
indistinguishable from an attack scenario until the analyst reads the evidence
(signed Veeam binary, internal backup destination, backup schedule).

---

## PILOTS DONE (commits 5801cd1, 099b908) + amendments (cf3d26d, 95efd99).

Rules from the pilot review, applied to every 3c scaffold:
- Any supplemental event within the attack's plausible correlation window is a
  DECLARED red herring (`red_herring: true`); else moved genuinely outside.
- Detection entity resolves from source_ip for sensor events (firewall/proxy/
  dns), so the actor shows, not the reporting device.
- Supplemental events only where a benign chain step cannot carry the story.
- Severity inverted where it aids indistinguishability; FPs span up to
  Critical-looking, TPs include Medium-looking.
- Every invented entity/product is stub-flagged for owner approval or
  verification (Tenable-style) before its flag closes.

---

# STEP 3c BATCH 1 — candidate narratives (SCAFFOLD, awaiting approval)

Four scenarios: malware_usb, c2_http, password_spray, false_positive_pentest.
One scenario per commit on approval.

## B1.1 malware_usb (Malware) — 1 -> 3 (2 TP + 1 FP)

Chain: s1 6416 device install, s2 payload exec from E:\ (trigger, TP), s3
FileCreate, s4 SetValue Run key to C:\Users\Public\winupdate.exe, s5
NetworkConnect. Env: workstation only.

- **D1 KEEP** `det_usb_exec` (TP, yara, high, s2): executable launched from
  removable media (existing).
- **D2 ADD** `det_usb_persist` (TP, sigma, **medium**, s4): "Run Key
  Persistence to Public-Folder Binary". mitre T1547.001 Persistence. "A Run
  key was set to a binary in C:\Users\Public with a system-update masquerade
  name (winupdate.exe). Persistence following the removable-media execution."
- **D3 ADD** `det_pubfolder_autorun_fp` (FP, sigma, **medium**, supplemental
  **sup1**): "Autorun Registration to Public-Folder Binary". "An endpoint
  management agent registered a Run key pointing to a signed binary under
  C:\Users\Public. Reads like the persistence above; it is a routine managed
  deployment." Resolution evidence: the binary is vendor-signed and the Run
  key was written by the management agent, not the USB payload.
  - supplemental sup1: Sysmon EventID 13 (SetValue) on the victim workstation,
    a Run key to a signed agent binary in C:\Users\Public. In-window ->
    **RED HERRING** (two Public-folder Run keys, distinguished by signer).
  - entities NEEDED: a signed endpoint-management agent product (binary name,
    vendor/signer, install path). **STUB-FLAG** — propose e.g. ManageEngine
    Endpoint Central agent, or supply the product to use; verify identity
    (Tenable-style) before its flag closes.

## B1.2 c2_http (Command & Control) — 1 -> 3 (2 TP + 1 FP)

Chain: s1 rundll32.exe (loader), s2/s4 DNS to c2 domain, s3/s5 HTTPS beacon to
c2 (s3 trigger, TP). Env: workstation, dns, proxy.

- **D1 KEEP** `det_beacon` (TP, sigma, high, s3): periodic HTTPS beacon to
  uncategorized domain (existing).
- **D2 ADD** `det_rundll_no_args` (TP, sigma, **medium**, s1): "rundll32
  Executed Without a Module". mitre T1218.011. "rundll32.exe launched by
  explorer with no DLL/entry-point argument, a common loader pattern that
  preceded the beacon."
- **D3 ADD** `det_saas_poll_fp` (FP, sigma, **high**, supplemental **sup1**):
  "Periodic HTTPS Connections to External Host". "A SaaS telemetry/updater
  agent polls its vendor endpoint on a fixed interval, the same beacon shape.
  Benign: the destination is an allowlisted, categorized vendor domain."
  Resolution evidence: destination is a categorized vendor domain on the
  allowlist, vs the C2's uncategorized lookalike.
  - supplemental sup1: Proxy HTTP_CONNECT from the victim workstation to a
    benign SaaS domain at a regular interval. In-window -> **RED HERRING**
    (two beacon-shaped signals, distinguished by domain reputation/category).
  - entities NEEDED: one benign external SaaS/telemetry domain in
    `supplemental_entities` (one-off external). **STUB-FLAG** — propose e.g.
    an updater/telemetry domain; approve or supply.

## B1.3 password_spray (Brute Force) — 1 -> 3 (2 TP + 1 FP)

Chain: s1-s5 4625 failures across accounts from one source, s6 4624 success
(trigger, TP). Env: workstation, dc.

- **D1 KEEP** `det_spray` (TP, sigma, high, s6): spray pattern then a
  successful logon (existing).
- **D2 ADD** `det_multi_account_failures` (TP, sigma, **medium**, s1): "Failed
  Logons Across Many Accounts from One Source". mitre T1110.003. "One source
  attempted single NTLM logons against many distinct accounts in a short
  window, the spray signature, before the success."
- **D3 ADD** `det_svc_stale_creds_fp` (FP, sigma, **high**, supplemental
  **sup1**): "Repeated Authentication Failures for a Single Account". "A
  service account with a stale password repeatedly failed against the DC,
  generating a lockout-shaped burst that reads like targeted brute force.
  Benign: a known service account misconfiguration." Resolution evidence: one
  account (not many), from a known service host, failure cause = bad password
  from a scheduled task, vs the spray's many-accounts-one-source.
  - supplemental sup1: 4625 failures on the DC for one service account from a
    known internal service host. In-window -> **RED HERRING** (both
    4625-bursts on the DC, distinguished by account cardinality and source).
  - entities NEEDED: a canonical service account + the host it runs on.
    **STUB-FLAG** — propose e.g. svc_reporting on a canonical app server, or
    supply.

## B1.4 false_positive_pentest (False Positive) — 1 -> 3 (all TP-looking FP)

Chain: s1 GET to KnowBe4 phish sim, s2 DNS to training domain, s3 GET to
lookalike login (trigger), s4 firewall ALLOW, s5 POST to KnowBe4 tracker. Env:
workstation, dns, proxy, firewall. All benign (authorized KnowBe4 campaign).
No supplemental events needed: every benign chain step carries a story.

- **D1 KEEP** `det_fp_pentest` (FP, sigma, medium, s3): credential-harvest POST
  to a lookalike domain (existing; reads like phishing).
- **D2 ADD** `det_pentest_tracker_fp` (FP, sigma, **high**, s5): "Outbound POST
  to Recently-Seen Domain After Credential Page". "A POST to an external
  tracking endpoint right after a credential-harvest page reads like
  exfiltration of harvested creds. Benign: the authorized KnowBe4 campaign
  tracker." Resolution: destination is the security-awareness training
  platform; the campaign is scheduled.
- **D3 ADD** `det_pentest_newdomain_fp` (FP, sigma, **medium**, s2): "DNS
  Resolution of a Newly-Observed Lookalike Domain". "A first-seen lookalike
  domain (acme-password-reset.com) was resolved, the shape of phishing infra.
  Benign: the training vendor's simulated lure domain." Resolution: SPF
  passes, the domain belongs to the onboarded training vendor.
  - spans medium/high; all three read as real threats (phishing, exfil,
    phishing-infra) until the analyst sees the KnowBe4 / training-platform
    evidence.

---

## STOP — awaiting owner approval of Batch 1 (step 3c)

Two decisions needed at approval, each stub-flagged above:
1. B1.1 management-agent product (name/vendor/signer/path) — approve a proposed
   product or supply one; I verify its identity before implementing.
2. B1.2 benign SaaS/telemetry domain and B1.3 service account + host — approve
   proposed values or supply canonical ones.

On approval I implement Batch 1 one scenario per commit, run full gates after
the batch, print the distribution report (per-scenario TP/FP counts, severity
spread, source spread), and STOP for review.

---

# BATCH 1 DONE (commits a9c1dbb, 0a26dd7, 57c5310, 9ae27b5).

# STEP 3c BATCH 2 — candidate narratives (SCAFFOLD, awaiting approval)

Four scenarios chosen to cover four NEW disposition mixes (batch 1 was all
2TP+1FP / 3FP). Severity deliberately varied so the authored FP is NOT
predictably the high-severity detection (several FPs are medium; several TPs
are high/critical).

| Scenario | Category | Mix | FP severities | note |
|---|---|---|---|---|
| lateral_movement_2 | Lateral Movement | **3TP + 1FP** | medium | FP is the lowest severity |
| malware_ransomware | Malware | **all-TP (3TP)** | (none authored) | dismissables from ambient benign |
| data_exfil_archive | Data Exfiltration | **1TP + 2FP** | medium, high | one real exfil hidden among benign uploads |
| false_positive_oauth | False Positive | **2 FP** | high, medium | |

Reused canonical actors (no new invented identities): WerFault (Windows),
ambient benign, the Veeam endpoint agent, real Microsoft/SharePoint domains.
One identity to verify: the benign cloud-sync domain (real Microsoft domain,
verified, never invented).

## B2.1 lateral_movement_2 (Lateral Movement, T1003.001) — 3TP + 1FP

Chain: s1 procdump.exe from Downloads, s2 ProcessAccess on lsass (trigger),
s3 FileCreate (lsass dump), s4 ProcessCreate from Temp, s5 4624 on file server.
Env: workstation, file.

- **D1 KEEP** `det_lsass` (TP, sigma, **critical**, s2): a non-system process
  opened lsass memory, the credential-dumping signature.
- **D2 ADD** `det_procdump_exec` (TP, sigma, **medium**, s1): procdump.exe ran
  from a user's Downloads folder, the tool that performed the dump.
- **D3 ADD** `det_lsass_dumpfile` (TP, sigma, **high**, s3): a memory dump
  file was written to disk immediately after the lsass access.
- **D4 ADD** `det_crashdump_fp` (FP, sigma, **medium**, supplemental **sup1**):
  "Process Memory Dump File Created". "A .dmp file was written, the artifact
  of credential dumping. It is Windows Error Reporting (WerFault.exe) writing
  a crash dump of a hung application, not lsass." Resolution: the dumping
  process is WerFault.exe (Windows), target is a crashed app, not lsass.
  - sup1: Sysmon FileCreate of a WER crash .dmp by WerFault.exe on the victim
    workstation. In-window -> **RED HERRING**. No new entity (WerFault is
    built-in Windows).

Severity: TP critical/high/medium, FP medium. The FP is the lowest severity,
inverting batch 1 where the FP was the high one.

## B2.2 malware_ransomware (Malware, T1486) — all-TP (3TP)

Chain: s1 payload from Temp, s2 vssadmin, s3 FileCreate first .locked
(trigger), s4/s5 more .locked. Env: workstation only. NO authored FP: the
dismissables are the workstation's ambient benign detections (updaters/backup
agent). This is the all-TP mix.

- **D1 KEEP** `det_ransom_note` (TP, yara, **high**, s3): ransom-note file
  signature match amid mass file changes.
- **D2 ADD** `det_vss_delete` (TP, sigma, **high**, s2): "Shadow Copy Deletion
  via vssadmin". mitre T1490 Impact. "vssadmin deleted volume shadow copies,
  inhibiting recovery, a ransomware precursor."
- **D3 ADD** `det_mass_encrypt` (TP, sigma, **critical**, s5): "Rapid Mass
  File Writes with Unfamiliar Extension". mitre T1486 Impact. "Many files
  rewritten with an unfamiliar extension in seconds, the encryption stage."

Severity: high/high/critical, no FP. Dismissables come from ambient benign.

## B2.3 data_exfil_archive (Data Exfiltration, T1560.001) — 1TP + 2FP

Chain: s1 7z.exe launch, s2 FileCreate archive, s3 DNS to mega.nz, s4 firewall
ALLOW, s5 HTTP_CONNECT to mega.nz (trigger). Env: workstation, dns, proxy,
firewall. One real exfil hidden among two benign uploads/archives.

- **D1 KEEP** `det_exfil_upload` (TP, sigma, **high**, s5): outbound to a
  consumer file-sharing host after local archiving, the real exfil.
- **D2 ADD** `det_cloud_sync_fp` (FP, sigma, **medium**, supplemental
  **sup1**): "Outbound Upload to Cloud Storage". "A large upload to an
  external cloud endpoint reads like exfiltration. It is corporate OneDrive
  sync to the sanctioned tenant." Resolution: destination is the corporate
  SharePoint/OneDrive tenant (sanctioned), not a consumer file host.
  - sup1: Proxy HTTP_CONNECT from the victim workstation to the corporate
    OneDrive/SharePoint tenant. In-window -> **RED HERRING**.
  - entity: the corporate SharePoint domain in supplemental_entities. **Verify
    a real Microsoft domain** (e.g. acme-my.sharepoint.com, the pattern the
    robocopy FP already uses); never invented.
- **D3 ADD** `det_backup_archive_fp` (FP, sigma, **high**, supplemental
  **sup2**): "Archive Utility Created a Large Archive". "An archive utility
  created a large archive, the collection/staging shape. It is the Veeam
  endpoint backup agent creating a scheduled local backup archive."
  Resolution: the archiver's parent is the signed Veeam agent, output to the
  backup path.
  - sup2: Sysmon ProcessCreate of an archiver launched by the Veeam endpoint
    agent on the victim workstation. In-window -> **RED HERRING**. Reuses the
    Veeam identity (established in false_positive_veeam).

Severity: TP high, FP medium + high. Two upload/archive FPs coexist with the
single real exfil; severity does not separate them.

## B2.4 false_positive_oauth (False Positive, benign) — 2 FP

Chain: s1 SigninLogs, s2 HTTP_POST OAuth token to login.microsoftonline.com,
s3 SigninLogs, s4 AADUserRiskEvents impossible-travel (trigger). Env:
workstation, proxy. All benign (modern-auth OAuth refresh tokens after an
endpoint migration). Two FPs (varying from batch 1's three).

- **D1 KEEP** `det_fp_oauth` (FP, sigma, **high**, s4): "Impossible-Travel
  Sign-In Risk". Reads like account takeover; benign OAuth refresh tokens.
- **D2 ADD** `det_oauth_noninteractive_fp` (FP, sigma, **medium**, s2):
  "Non-Interactive OAuth Token Activity from New Location". "A token-based
  sign-in from an unexpected location reads like token theft or replay. It is
  a modern-auth refresh token after the endpoint's migration to OAuth."
  Resolution: the sign-ins are non-interactive refresh-token renewals from the
  migrated device.

Severity: high + medium (the high one is the kept detection, not the added
one), so the added FP is medium here.

---

## STOP — awaiting owner approval of Batch 2 (step 3c)

One verification at approval: the corporate SharePoint/OneDrive domain for
B2.3 sup1 (real Microsoft domain; I will verify or reuse the established
acme-my.sharepoint.com pattern). Everything else reuses Windows built-ins,
ambient benign, and the established Veeam identity. On approval I implement
one scenario per commit, run full gates, print the distribution report with
the varied mixes, and STOP.

---

# BATCH 2 DONE (commits 6ec2a29, 69e4706, d3b202e, 2cfd293).

# STEP 3c BATCH 3 — candidate narratives (SCAFFOLD, awaiting approval)

Four scenarios: **defense_evasion, c2_dns_tunnel, insider_shadow_it,
false_positive_robocopy.** One scenario per commit on approval.

## Batch 3 focus: FP severity-rank de-correlation

The severity-rank target (validated at 3d): across the final densified corpus,
the authored FP's rank within its scenario (top / shared-top / middle /
bottom) must be roughly uniform — no rank may hold more than ~40% of
FP-bearing scenarios. The current baseline is top-skewed:

| rank | densified attack scenarios so far |
|---|---|
| shared-top | lateral_movement_1, malware_usb, c2_http, password_spray, data_exfil_archive(FP2) = **5** |
| middle | **0** |
| bottom | lateral_movement_2, data_exfil_archive(FP1) = **2** |
| sole-top | 0 |

Batch 3 therefore adds **only middle and bottom FPs, zero new shared-top**, to
begin offsetting the batch-1 residual (batch 4 finishes the balance):

| Scenario | Category | Mix | FP severity | **FP rank** |
|---|---|---|---|---|
| defense_evasion | Defense Evasion | 2TP + 1FP | high | **middle** (between critical & medium TPs) |
| c2_dns_tunnel | Command & Control | 2TP + 1FP | medium | **bottom** (under two high TPs) |
| insider_shadow_it | Insider Threat | 2TP + 1FP | medium | **bottom** (under two high TPs) |
| false_positive_robocopy | False Positive | 3 FP | medium/high/medium | all-FP (no TP to rank against) |

Batch 3 deliberately holds the attack mix constant at 2TP+1FP to isolate the
rank-correction variable; corpus mix variety was already achieved in batches
1–2. **Entity discipline: zero new invented identities — every FP reuses an
already-established, already-flagged actor.**

## B3.1 defense_evasion (Defense Evasion, T1562.001) — 1 → 3 (2TP + 1FP)

Chain: s1 PowerShell exec, s2 Defender 5007 real-time-protection disabled
(trigger, TP), s3 FileCreate PS transcript, s4 svchost32.exe from
C:\Users\Public, s5 SetValue Run key, s6 NetworkConnect C2. Env: workstation.

- **D1 KEEP** `det_av_disabled` (TP, sigma, **critical**, s2): Windows Defender
  real-time protection disabled via PowerShell (bumped high→critical; disabling
  AV is a critical impairment). mitre T1562.001.
- **D2 ADD** `det_pubfolder_masquerade` (TP, sigma, **medium**, s4):
  "Masquerading Binary Executed from Public Folder". mitre T1036.005. "A binary
  named svchost32.exe (system-binary masquerade) launched from C:\Users\Public
  right after AV was disabled — the payload the evasion cleared the way for. A
  real but quieter signal than the AV-disable." (deliberately medium-looking TP.)
- **D3 ADD** `det_defender_policy_fp` (FP, sigma, **high**, supplemental
  **sup1**): "Windows Defender Policy Setting Modified". "A Defender
  configuration value was changed, the AV-tampering shape. Benign: the endpoint
  management agent applied a scheduled Defender policy push." Resolution
  evidence: the modifying process is the signed ZOHO agent (dcagentservice.exe),
  the value is a management-policy key (not the real-time-protection disable the
  attack performed), and it lands in the deployment window.
  - **sup1**: Sysmon EventID 13 (SetValue) on a Windows Defender **policy**
    registry key by dcagentservice.exe on the victim workstation. In-window ->
    **RED HERRING: true** (two Defender-modification signals, distinguished by
    process identity/signer, not by guessing).
  - entities NEEDED: **REUSE** ManageEngine Endpoint Central agent
    (dcagentservice.exe / ZOHO signer / staging path) established in B1.1. No
    new entity. Realism note (non-blocking, for owner): Endpoint Central's
    Security-Configuration / Defender-management behavior — consistent with the
    already-open staging-path stub; verify in-browser at leisure.

FP rank: TPs **critical + medium**, FP **high** -> **MIDDLE** (a new rank).

## B3.2 c2_dns_tunnel (Command & Control, T1071.004) — 1 → 3 (2TP + 1FP)

Chain: s1 loader exec from Downloads, s2 DNS data.<tunnel>, s3 DNS high-entropy
subdomain (trigger, TP), s4 firewall ALLOW, s5 DNS. Env: workstation, dns,
firewall.

- **D1 KEEP** `det_dns_tunnel` (TP, sigma, **high**, s3): high-entropy,
  data-bearing subdomains under a single parent — the tunneling signature.
  mitre T1071.004.
- **D2 ADD** `det_dns_loader_exec` (TP, sigma, **high**, s1): "Process Launched
  from Downloads Generating Anomalous DNS". mitre T1071.004. "A binary run from
  the user's Downloads folder is the source of the anomalous DNS traffic — the
  tunnel client." (second high TP, so the medium FP is strictly the lowest.)
- **D3 ADD** `det_dns_volume_fp` (FP, sigma, **medium**, supplemental
  **sup1–sup3**): "High-Volume DNS Query Rate to Single Domain". "A host issued
  many DNS queries to one external domain in a short window — the volume shape
  of DNS beaconing/tunneling. Benign: a Microsoft telemetry agent's routine
  check-ins." Resolution evidence: the destination is a categorized
  Microsoft-owned telemetry domain and the subdomains are low-entropy and
  stable (no encoded data), vs the tunnel's high-entropy data subdomains.
  - **sup1–sup3**: three DNS QUERY events from the victim workstation to
    `v10.events.data.microsoft.com` at a regular interval, so the "volume" is
    genuinely present in the pool (not just narrative). Detection triggers on
    sup1. In-window -> **RED HERRING: true**.
  - entities NEEDED: **REUSE** `v10.events.data.microsoft.com` (the Microsoft
    telemetry domain established as a supplemental_entity in c2_http). Add it to
    this scenario's supplemental_entities (self-contained, byte-identical
    literal). No new entity.

FP rank: TPs **high + high**, FP **medium** -> **BOTTOM**.

## B3.3 insider_shadow_it (Insider Threat, T1567.002) — 1 → 3 (2TP + 1FP)

Chain: s1 shadow app exec from AppData\Roaming, s2/s3 FileCreate staging, s4
DNS to unsanctioned cloud, s5 HTTP_POST upload (trigger, TP). Env: workstation,
dns, proxy.

- **D1 KEEP** `det_shadow_upload` (TP, sigma, **high**, s5): outbound upload to
  an unsanctioned personal-cloud endpoint. mitre T1567.002.
- **D2 ADD** `det_shadow_app_exec` (TP, sigma, **high**, s1): "Unsanctioned
  File-Transfer Application Launched from User Profile". mitre T1567. "An
  unsanctioned cloud/file-transfer client ran from a user AppData path and then
  moved corporate files out — shadow-IT tooling used for exfil." (second high
  TP, so the medium FP is the lowest.)
- **D3 ADD** `det_cloud_upload_fp` (FP, sigma, **medium**, supplemental
  **sup1**): "Outbound File Upload to Cloud Storage". "A file upload left the
  host for external cloud storage — the exfil shape. Benign: sanctioned
  corporate OneDrive/SharePoint sync to the company tenant." Resolution
  evidence: the destination is the sanctioned company tenant
  (acme-my.sharepoint.com) over an authenticated corporate session, vs the
  attack's unsanctioned personal-cloud destination.
  - **sup1**: Proxy FileSyncUploadedFull (or HTTP_POST) from the victim
    workstation to `acme-my.sharepoint.com`. In-window -> **RED HERRING: true**.
  - entities NEEDED: **REUSE** `acme-my.sharepoint.com` (established in
    false_positive_robocopy and data_exfil_archive). Add it to this scenario's
    supplemental_entities. **Update the BACKLOG org-prefix note** to list this
    third consumer of the tenant literal. No new entity.

FP rank: TPs **high + high**, FP **medium** -> **BOTTOM**.

## B3.4 false_positive_robocopy (False Positive, benign) — 1 → 3 (all-FP, 3 FP)

Chain: s1 robocopy (trigger), s2 4663 mass file access, s3 DNS to the corporate
tenant, s4 firewall ALLOW, s5 Proxy FileSyncUploadedFull to the tenant. Env:
workstation, file, dns, proxy, firewall. All benign (an authorized bulk data
migration to the corporate SharePoint/OneDrive tenant). NO supplemental events:
every benign chain step carries an FP story.

- **D1 KEEP** `det_fp_robocopy` (FP, sigma, **medium**, s1): "Bulk File Copy via
  robocopy" — reads like collection/staging. Benign IT-driven migration.
- **D2 ADD** `det_fp_cloud_sync` (FP, sigma, **high**, s5): "Large Upload to
  Cloud Storage" — reads like mass exfiltration (the scariest-looking detection
  in the scenario, and it is benign). Benign: sanctioned-tenant sync completing
  the migration. Resolution: destination is the corporate tenant.
- **D3 ADD** `det_fp_mass_fileaccess` (FP, sigma, **medium**, s2): "Mass File
  Access on File Share" (4663) — reads like bulk collection. Benign: the source
  files being read for the migration copy.
  - severities span **medium / high / medium**; the high-severity detection is
    an FP, so within an all-FP scenario the scary one is not a tell. Reuses the
    existing `sharepoint` entity (acme-my.sharepoint.com already in-environment);
    no supplemental events, no new entity.

## Post-batch-3 FP-rank trajectory (recorded, validated at 3d)

| rank | after batch 3 (attack-scenario FP instances) |
|---|---|
| shared-top | 5 (unchanged — batch 3 adds none) |
| **middle** | **1** (defense_evasion) — new |
| **bottom** | **4** (lateral_movement_2, data_exfil FP1, c2_dns_tunnel, insider_shadow_it) |
| sole-top | 0 |

Shared-top drops from 5/7 to 5/10 (50%); still above the ~40% target, so
**batch 4 will add further middle / sole-top / bottom FPs** to bring shared-top
under 40% corpus-wide. The 3d close-out then validates uniformity after the
deterministic stable-key detection-order shuffle, against all three solver
priors (odd-one-out, promote-N, dismiss-the-top-severity).

---

## STOP — awaiting owner approval of Batch 3 (step 3c)

No new identities to approve or verify — every batch-3 FP reuses an
already-established, already-flagged actor:
- B3.1 reuses the Endpoint Central agent (staging-path stub already open;
  Defender-management behavior is a non-blocking realism note for in-browser
  verification at leisure).
- B3.2 reuses `v10.events.data.microsoft.com`; B3.3 reuses
  `acme-my.sharepoint.com` (backlog org-prefix note gains a third consumer).
- B3.4 reuses the in-scenario `sharepoint` entity; no supplemental events.

On approval I implement one scenario per commit, run full gates after the
batch, print the distribution report (per-scenario mix, severity spread, **FP
severity rank**, source spread), and STOP for review.

---

# BATCH 3 DONE (commits 87497e1, a56959c, f423cd3, b3e0588; +86950a7 follow-up).

# STEP 3c BATCH 4 — candidate narratives (SCAFFOLD, awaiting approval)

The final six: **brute_force_attack, defense_evasion_log_clearing,
insider_staging, phishing_1, phishing_link** (attacks) + **false_positive_ssl_
inspection** (FP). One scenario per commit on approval.

## Batch 4 focus: finish the FP severity-rank de-correlation

After batch 3 the attack-scenario FP-rank stands at **shared-top 5 / bottom 4 /
middle 1 / sole-top 0** (10 instances; shared-top 50%). Batch 4 introduces the
corpus's **first sole-top FPs** plus more middle/bottom, **zero new shared-top**,
to bring shared-top to ~5/15 (33%) and spread the other ranks:

| Scenario | Category | Mix | FP sev | **FP rank** |
|---|---|---|---|---|
| brute_force_attack | Brute Force | 2TP+1FP | critical | **sole-top** |
| insider_staging | Insider Threat | 2TP+1FP | critical | **sole-top** |
| phishing_1 | Phishing | 2TP+1FP | high | **middle** (crit + med TPs) |
| phishing_link | Phishing | 2TP+1FP | high | **middle** (crit + med TPs) |
| defense_evasion_log_clearing | Defense Evasion | 2TP+1FP | medium | **bottom** (two high TPs) |
| false_positive_ssl_inspection | False Positive | 3FP | med/high/med | all-FP |

**Entity discipline: zero new invented identities.** Every FP reuses an
established, already-flagged actor (svc_backup / ACME-VEEAM01, the Veeam agent,
the SharePoint tenant, MS Office/outlook, Windows built-ins). No vendor identity
needs verification; the only set-dressing additions are canonical hosts/accounts
joined to a scenario env via the established `SCENARIO_CANONICAL_ACCOUNTS` +
`build_environment` mechanism (same as lateral_movement_1 / password_spray).

## B4.1 brute_force_attack (Brute Force, T1110.001) — 2TP + 1FP

Chain: s1-s4 4625 failures from an external source, s5 4740 lockout (trigger,
TP). Env: dc.

- **D1 KEEP** `det_lockout` (TP, sigma, **high**, s5): account lockout after
  external failures. mitre T1110.001.
- **D2 ADD** `det_bruteforce_burst` (TP, sigma, **medium**, s1): "Repeated
  Failed Logons from a Single External Source". The 4625 burst preceding the
  lockout. mitre T1110.001 (pinned, scenario's own).
- **D3 ADD** `det_privileged_lockout_fp` (FP, sigma, **critical**, supplemental
  **sup1**): "Privileged Service Account Locked Out". A backup service account
  locked out on the DC reads like a targeted attack on backup infrastructure
  (critical). Benign: `svc_backup` failed repeatedly after a password rotation
  wasn't propagated, then locked out. Resolution: one privileged service account
  from the internal backup server on a rotation window, vs the attack's targeted
  user from an external source.
  - **sup1**: 4740 lockout (optionally preceded by a small 4625 burst) on the DC
    for `svc_backup`, source `ACME-VEEAM01`. In-window -> **RED HERRING: true**
    (two lockout signals, distinguished by account privilege + source).
  - entities NEEDED: **REUSE** `svc_backup` + `ACME-VEEAM01` (canonical). Add
    both to this scenario's env via `SCENARIO_CANONICAL_ACCOUNTS` (as
    password_spray already does). No new identity.

FP rank: TPs **high + medium**, FP **critical** -> **SOLE-TOP** (a new rank; the
scariest detection is the benign one).

## B4.2 insider_staging (Insider Threat, T1074.001) — 2TP + 1FP

Chain: s1 4624 logon, s2 5140 sensitive-share access, s3 FileCreate local
staging, s4 NetworkConnect, s5 HTTP_CONNECT to an external exfil host (trigger,
TP). Env: workstation, file, proxy.

- **D1 KEEP** `det_staging` (TP, sigma, bumped medium -> **high**, s5): sensitive
  share access then local staging then an outbound connection. mitre T1074.001.
- **D2 ADD** `det_share_harvest` (TP, sigma, **medium**, s2): "Sensitive Share
  Accessed Outside Role" (5140). mitre T1074.001 (pinned, scenario's own).
- **D3 ADD** `det_mass_egress_fp` (FP, sigma, **critical**, supplemental
  **sup1**): "Large Off-Hours Data Egress Volume". A large volume leaving the
  host off-hours reads like mass exfiltration (critical). Benign: the scheduled
  Veeam endpoint backup completing a large transfer to the internal backup
  repository. Resolution: signed Veeam agent to the internal backup server on
  schedule, vs the attack's outbound to an external exfil host.
  - **sup1**: a Veeam backup-completion / large NetworkConnect from the victim
    workstation to `ACME-VEEAM01` (>1.75 GB). In-window -> **RED HERRING: true**.
    Reuses the established Veeam identity (`_VEEAM_SVC`, ACME-VEEAM01) and mirrors
    false_positive_veeam's critical bulk-egress FP shape. No new identity.

FP rank: TPs **high + medium**, FP **critical** -> **SOLE-TOP**.

## B4.3 phishing_1 (Phishing, T1583.001) — 2TP + 1FP

Chain: s1 GET lookalike/signin, s2 POST creds to lookalike, s3 SigninLogs, s4
AADUserRiskEvents impossible-travel (trigger, TP). Env: workstation, proxy;
Azure AD events.

- **D1 KEEP** `det_impossible_travel` (TP, sigma, bumped high -> **critical**,
  s4): Entra confirmed impossible-travel risk = account takeover. mitre
  T1583.001 (unchanged).
- **D2 ADD** `det_credential_post` (TP, sigma, **medium**, s2): "Credentials
  Submitted to a Lookalike Sign-In Page". mitre **T1566.002** (pinned; the
  Spearphishing-Link technique accurately fits the credential-submission action;
  flagged here because it is borrowed from phishing_link's answer key — pinned,
  so no new string. Alternatively omit the tag; owner's call).
- **D3 ADD** `det_benign_risky_signin_fp` (FP, sigma, **high**, supplemental
  **sup1**): "Risky Sign-In From New Location". A risky sign-in from an
  unexpected location reads like the account-takeover TP. Benign: a
  non-interactive OAuth refresh-token renewal from a new-but-known device with
  MFA satisfied (reuses the false_positive_oauth benign-auth pattern; no new
  external entity — it concerns the user's own account). Resolution: no
  preceding credential POST, non-interactive token, known device.
  - **sup1**: an Azure AD SigninLogs / risk entry for a benign non-interactive
    sign-in. In-window -> **RED HERRING: true**. **Implementation check:** Azure
    AD is not a sensor source, so the detection entity resolves from the event
    `hostname`; confirm phishing_1's Azure AD steps carry a resolvable host.

FP rank: TPs **critical + medium**, FP **high** -> **MIDDLE**.

## B4.4 phishing_link (Phishing, T1566.002) — 2TP + 1FP

Chain: s1 DNS phish domain, s2 GET invoice lure, s3 Invoice.exe from Downloads
(trigger, TP), s4 PowerShell, s5 SetValue Run key. Env: workstation, dns, proxy.

- **D1 KEEP** `det_link_payload` (TP, sigma, bumped high -> **critical**, s3): a
  malicious executable launched from Downloads right after the link click. mitre
  T1566.002.
- **D2 ADD** `det_payload_persistence` (TP, sigma, **medium**, s5): "Run Key
  Persistence Written by a Downloaded Payload". mitre **T1547.001** (pinned;
  already in `PINNED_DETECTION_TECHNIQUES`).
- **D3 ADD** `det_doc_download_fp` (FP, sigma, **high**, supplemental **sup1**):
  "Document Downloaded From an External Site". A document fetched from an
  external site reads like the invoice lure. Benign: a routine download from the
  sanctioned SharePoint/OneDrive tenant. Resolution: sanctioned corporate tenant
  vs the phishing domain.
  - **sup1**: a Proxy GET/download of a document from `acme-my.sharepoint.com`
    by the victim. In-window -> **RED HERRING: true**. **REUSE** the
    byte-identical SharePoint tenant literal (`_SHAREPOINT_TENANT`) — this is the
    **fourth** consumer; update the BACKLOG org-prefix note. No new identity.

FP rank: TPs **critical + medium**, FP **high** -> **MIDDLE**.

## B4.5 defense_evasion_log_clearing (Defense Evasion, T1070.001) — 2TP + 1FP

Chain: s1-s3 WMI event-subscription persistence, s4 wevtutil ProcessCreate, s5
1102 Security-log cleared (trigger, TP), s6 wevtutil ProcessCreate. Env:
workstation. **The s5 binding (classification_event = s5, pinned T1070.001 /
Defense Evasion) is UNTOUCHED; density surrounds it, never replaces it.**

- **D1 KEEP** `det_log_cleared` (TP, sigma, **high**, s5, mitre T1070.001):
  unchanged — the s5-bound detection, counts in the mix.
- **D2 ADD** `det_wevtutil_exec` (TP, sigma, **high**, s4): "Event Log Utility
  Executed to Clear a Log" (`wevtutil cl`). mitre T1070.001 (pinned, scenario's
  own) — the clearing action that produced the 1102.
- **D3 ADD** `det_maint_logclear_fp` (FP, sigma, **medium**, supplemental
  **sup1**): "Event Log Cleared by Scheduled Process". A log clear reads like
  evidence destruction. Benign: a scheduled maintenance task rotating/clearing a
  **non-Security operational** channel (there is no 1102 — that is Security-only)
  under SYSTEM with a change record. Resolution: the channel cleared (a benign
  operational log, not Security), the parent (scheduled task), and the change
  record.
  - **sup1**: a Sysmon ProcessCreate of `wevtutil.exe cl <operational-channel>`
    launched by a scheduled maintenance task under SYSTEM (Windows built-in; no
    new identity). In-window -> **RED HERRING: true**.

FP rank: TPs **high + high**, FP **medium** -> **BOTTOM**.

## B4.6 false_positive_ssl_inspection (False Positive, benign) — 3 FP

Chain: s1 SSL_INSPECT outlook.office365.com, s2 SSL_HANDSHAKE_FAILED (trigger),
s3 firewall ALLOW, s4 NetworkConnect Office, s5 SSL_INSPECT owa. Env:
workstation, proxy, firewall. All benign (an expanded corporate proxy
SSL-inspection policy breaking certificate-pinned Office connections). No
supplemental events: every benign chain step carries a story.

- **D1 KEEP** `det_fp_ssl` (FP, sigma, **medium**, s2): repeated TLS handshake
  failures resembling a beacon.
- **D2 ADD** `det_fp_pinned_tls` (FP, sigma, **high**, s4): "Repeated TLS
  Failures to a Cloud Service" — reads like C2 connection failures. Benign: a
  certificate-pinned Office client rejecting the new inspection CA.
- **D3 ADD** `det_fp_inspection_bypass` (FP, sigma, **medium**, s3): "Flow
  Allowed Around Inspection Policy" — reads like proxy/inspection evasion.
  Benign: the firewall allow for the same inspected Office flow.
  - severities span **medium / high / medium**; the high detection is an FP.
    Reuses outlook.office365.com / Office (already in-chain, real Microsoft); no
    supplemental events, no new entity.

## Projected post-batch-4 FP-rank (validated at 3d)

| rank | after batch 4 (attack-scenario FP instances) | share |
|---|---|---|
| shared-top | 5 (unchanged — batch 4 adds none) | 33% |
| bottom | 5 (+ log_clearing) | 33% |
| middle | 3 (+ phishing_1, phishing_link) | 20% |
| **sole-top** | **2** (brute_force, insider_staging) — new | 13% |

15 attack-scenario FP instances; every rank ≤ ~40%, target met. The 3d close-out
then lands the deterministic stable-key detection-order shuffle and validates
all three solver priors (odd-one-out, promote-N, dismiss-the-top-severity) score
no better than chance corpus-wide, plus the rank uniformity above.

---

## STOP — awaiting owner approval of Batch 4 (step 3c)

No new identities to approve or verify — every batch-4 FP reuses an established,
already-flagged actor:
- B4.1 reuses svc_backup / ACME-VEEAM01 (canonical); B4.2 reuses the Veeam agent
  identity; B4.4 reuses `acme-my.sharepoint.com` (backlog note gains a 4th
  consumer); B4.3 reuses the false_positive_oauth benign-auth pattern; B4.5
  reuses Windows built-ins; B4.6 reuses in-chain MS Office/outlook.
- Two implementation checks flagged (non-blocking): phishing_1's Azure AD event
  host resolution for the FP entity, and the phishing_1 D2 borrowed T1566.002
  tag (pinned) vs omitting it — owner's call.

On approval I implement one scenario per commit, run full gates after the batch,
print the final distribution report (per-scenario mix, severity spread, FP
severity rank), and STOP before the 3d close-out.
