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

## STOP — awaiting owner approval of these two pilot narratives (step 3a)

On approval I proceed to 3b: implement the pilot one scenario per commit
(schema supplemental_events + supplemental_entities, ACME-SEC01 canonical add,
the detections, integrity + leak + parity + density gates), STOP for review.
