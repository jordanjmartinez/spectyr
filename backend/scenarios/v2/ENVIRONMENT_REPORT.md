# Environment Report: Stage 1+ Flag Ledger

Running ledger for every stub, simplification, and unresolved identity in the
simulated environment from Stage 1 onward. MIGRATION_REPORT.md is frozen as
the Stage 0 artifact; new flags land here. Each entry stays until a review
resolves it (resolution noted inline, entry kept for the record).

## Stage 2 (Detection Density Pass)

### Canonical environment additions (FLAG for review)

- **ACME-SEC01** (`10.0.1.207`, role `scanner`, Windows Server 2019, managed):
  the security team's vulnerability-scanner host, added to `SERVERS['scan']`.
  A recurring benign actor whose scheduled sweeps trip recon rules. Appears as
  a managed endpoint. **Invented infrastructure; approve or supply canonical
  identity.**
- **svc_vulnscan** (service account, domain ACME, groups Domain Users +
  Scanning Service Accounts, on ACME-SEC01): the scanner's service account,
  in `SERVICE_ACCOUNTS`. Authorization ground truth (that it is legitimate) is
  server-side; its evidence (service type, scanner host, group) is
  world-visible. **APPROVED by owner (batch 1 review, 2026-07-16).**

### Density batch 1

- **svc_backup** (canonical service account, `SERVICE_ACCOUNTS['svc_backup']`,
  domain ACME, groups Domain Users + Backup Operators, on ACME-VEEAM01): the
  backup job's service account (password_spray FP). A stale password produces
  rhythmic auth failures against the DC that read like targeted brute force;
  the dismissal evidence is the single account, the backup-server source, and
  the scheduled cadence. **Invented; flagged for owner approval.** ACME-VEEAM01
  (canonical backup role) enters the password_spray environment via the
  supplemental events.
- **ManageEngine Endpoint Central agent** (malware_usb FP): the agent process
  `dcagentservice.exe` is VERIFIED against manageengine.com (agent footprint).
  The install path (C:\Program Files (x86)\DesktopCentral_Agent\...), the
  staging path, and the signer (ZOHO Corporation Private Limited) are NOT
  documented in the accessible pages -> **STUB, flagged; verify in-browser or
  supply.** REALISM ADJUSTMENT (owner visibility): the scaffolded FP was a
  Run-key-to-Public-folder registration; Endpoint Central is a service-based
  agent that deploys software via staged installers, not a Run-key mechanism,
  so the FP is now "executable launched from the deployment staging path"
  (documented deploy behavior). file_version is set dressing.
- **Tenable Nessus identity: VERIFIED (amendment 2).** The process
  `nessusd.exe`, the Windows service name and display name `"Tenable Nessus"`,
  and the install path `C:\Program Files\Tenable\Nessus\` are verified against
  official Tenable documentation (docs.tenable.com: `net start "Tenable
  Nessus"`; `nessuscli.exe`/`nessusd.exe` under that directory), 2026-07-16.
  Rendered in ACME-SEC01's Processes tab (sup1) and Services tab. The
  `file_version` "10.7.2" in sup1 is set dressing (a plausible version), not a
  documentation-verified value. NOTE: the Tenable SOFTWARE identity is
  verified; the scenario INFRASTRUCTURE it runs on (ACME-SEC01 host, IP
  10.0.1.207, svc_vulnscan account) remains invented and awaits owner approval
  above.

### Supplemental events

- `supplemental_events` (schema v2, sibling to attack): authored benign
  telemetry merged into the session pool, referenceable by detections via
  `sup*` ids. lateral_movement_1 pilot carries `sup1` (nessusd ProcessCreate
  on ACME-SEC01, integrity-checked) and `sup2` (firewall rapid connections).
  Timestamps authored at attack_base minus 118-120s. **DECLARED red herring**
  (review amendment 1): within the attack's plausible correlation window, so
  `red_herring: true` is set on both; resolution is the dismissal evidence
  (ACME-SEC01 scanner role, svc_vulnscan service account, nessusd process),
  not the timing. The correlation-window rule is in
  docs/classification-rubrics.md. Parity CLEAN (supplemental events never
  touch the attack chain).

### Recorded decisions

- **Sigma Detection Rule License check: no attribution required.** All
  detection rule names and descriptions in `scenarios/migrate_v1_to_v2.py`
  (`DETECTIONS`) and in `detection_templates.py` are ORIGINAL text authored
  for Spectyr. No SigmaHQ rule content (titles, detection logic, or
  descriptions) was copied or adapted, so the Sigma Detection Rule License
  (DRL 1.1) attribution requirement does not attach. `rule_type:
  sigma_behavioral` denotes the behavioral-detection FORMAT, not adapted
  SigmaHQ rules. If a future rule adapts SigmaHQ text, DRL attribution must be
  added and this entry updated.
- **Detection dispositions are server-side answer keys.** `disposition`
  (true_positive / false_positive / benign_expected) lives only in the
  scenario/template data and the session world; the API serializes detections
  through a whitelist (`sanitize_detection`) so disposition and scoring never
  reach the client. Enforced by a leak-guard test.

### Open flags (Stage 2)

- **Benign detection templates minimally modeled.** `detection_templates.py`
  covers common benign_expected triggers (software updaters, backup agents,
  admin tooling). The set is intentionally small and marked as a stub in that
  file's FLAGS; expand only from real product behavior, same bar as
  noise_profiles.

## Stage 1 (Endpoint Context Pages)

### Open flags

- **Backup role minimally modeled.** Only the Veeam Backup Service
  (VeeamBackupSvc) and its default 9392 port, plus the 10006 agent port the
  scenario chain itself establishes. Console, catalog/database engine, and
  mount services are omitted rather than guessed.

### Closed at Stage 1 review (2026-07-16)

- **Defender platform paths now real.** MsMpEng.exe / NisSrv.exe (processes
  and the WinDefend / WdNisSvc service paths) run from
  C:\ProgramData\Microsoft\Windows Defender\Platform\<platform version>\,
  verified against learn.microsoft.com (microsoft-defender-antivirus-updates,
  doc dated 2026-05-14, fetched live 2026-07-16). The version segment is a
  stable-key pick per host from the doc's current releases (4.18.25050.5,
  4.18.25040.2). The '-0' folder suffix, initially omitted as undocumented,
  was verified from deployed-path evidence on Microsoft-hosted sources
  (registry InstallLocation values and service image paths, reviewer,
  2026-07-16) and is now appended: Platform\<version>-0\.

- **phishing_link `.ex` flag was FALSE: no typo exists.** The authored
  SetValue details value is, and always was,
  `C:\Users\{victim.username}\AppData\Roaming\InvoiceService.exe`
  (61 characters). The Stage 1 survey that raised the flag printed the value
  through a `[:60]` display truncation, which dropped the final `e` and
  manufactured the apparent `.ex`. Verified against both the frozen v1 file
  and the v2 corpus. No correction made; nothing to correct. Lesson recorded:
  never flag content from truncated display output; re-read the source line
  before flagging.

- **Proxy identity RESOLVED: the logs win.** Proxy events are Palo Alto
  through Splunk CIM, so ACME-SVR06 is a PAN-OS VM-Series explicit proxy
  appliance (hostname and 10.0.1.205 unchanged; environment OS label
  PAN-OS). Same treatment as ACME-FW01: present in the environment and in
  network events, never in the Endpoints list, no Windows telemetry. Its
  Windows noise profile entries were deleted.
- **ATT&CK verification (FU1) — STALE as of 2026-07-16.** The audit conclusion
  "all 15 answer_key technique IDs current, no deprecated/revoked/merged IDs"
  was performed against **cached pre-v19 pages** and is superseded. Current live
  ATT&CK is **v19.1 (2026-04-28)**: at minimum `T1070.001` and `T1562.001` have
  v19 successors (their content merged under `T1685` "Disable or Modify Tools";
  Defense Evasion split into Stealth + Defense Impairment). The 15 IDs remain
  valid under the **pinned v18.1 baseline** the corpus deliberately targets, but
  are NOT "current." A dedicated v19 migration (re-verify every ID/name/tactic
  against live v19 pages) is pending owner scheduling. Original audit note kept
  below for provenance:
  - _All 15 answer_key technique IDs verified live against attack.mitre.org on
    2026-07-16 (13 by fetch during the audit; T1562.001 and T1070.001 by the
    reviewer). Display names updated where ATT&CK renamed: T1046 is now Network
    Service Discovery (approved triage corrections in scenario_corrections.py;
    the frozen v1 corpus keeps the old name). T1070.001 already carried the
    "Indicator Removal: Clear Windows Event Logs" title._ The canonical name map
    test in test_scenario_loader_v2.py fails loudly on future drift.

### Recorded decisions (not open)

- **Firewall is a log source, not a managed endpoint.** ACME-FW01 never
  enters the endpoint world; no Windows telemetry is fabricated for PAN-OS.
  It remains in every scenario environment and in network events.
- **Org egress IP is generated.** No scenario chain declares an organization
  egress address (source IPs are internal 10.0.1.x; external addresses are
  attacker or destination infrastructure), so one RFC 5737 TEST-NET-3 address
  (203.0.113.x, excluding the .50 inbound-scanner template) is derived per
  session from the stable key (session_seed, "org_egress_ip"). Every managed
  endpoint displays the same address. If a future scenario authors a real
  egress address, resolve_egress_ip must learn to prefer it and to fail on
  conflicts.
- **MAC addresses use the VMware manual-assignment OUI** (00:50:56, fourth
  octet masked to the manual 00-3F range): the fleet reads as virtualized.
  Set dressing, stable per (session, host).
- **Process memory values are set dressing**, stable-key derived per
  (session, host, process identity), range-banded by process type.
- **explorer.exe's PPID dangles by design** and is marked parent_exited:
  userinit.exe spawns it and exits. This is how real EDR process tables look.
- **Host status is scenario-declared** (schema v2 host `status`, default
  online). No generator may set it; only derived timestamps use the seed.
- **spectyr-agent 1.0.0** is the agent identity constant on every endpoint.
