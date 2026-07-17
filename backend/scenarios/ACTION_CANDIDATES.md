# Response-Action Answer Keys: Scaffolds for Owner Review (Stage 3c)

Cadence per the 3c ruling: scaffold a batch of 5 with rationale, STOP for
owner approval, then implement one scenario per commit (each commit flips
its scenario to `actions_reviewed: true`), full gates per batch. Scoring
semantics: docs/action-scoring.md. Every proposed target is verified
against the achievability rule (authored sources only; seed-independent).

Legend per scenario: proposed `actions:` YAML, rationale per action,
declared orderings (only where the sequence genuinely matters), designed
collateral traps with their dismissal evidence (red-herring discipline),
expected end-state.

## Batch-level principles proposed for ratification

- **P1. Breached-account contract.** An account the attacker successfully
  used (a success event under attacker control) requires all three
  identity actions: disable_account, revoke_sessions,
  force_password_reset. Targeted-but-not-breached accounts (failures
  only) are trap targets. This keeps identity grading uniform: no
  defensible identity action on a breached account is ever collateral.
- **P2. Authored-attack-pid completeness.** Every authored
  malicious-lineage PID on a scoped host appears in the required set, so
  killing any attack process is never collateral. Boundary cases (a
  user's own shell that launched the tool) are flagged per scenario
  rather than silently decided. If the owner prefers a leaner required
  set, the alternative is accepting collateral on defensible kills or
  ruling a neutral tier (grammar change, not proposed here).
- **P3. Ordering restraint.** `after` only for the
  containment-before-credential-reset class, where an online attack
  source could re-capture or re-use credentials reset too early. Two
  declarations in this batch, both that class.
- **P4. Offline-host wrinkle.** Not used in Batch 1. Reserved for a later
  batch (max 1-2 corpus-wide, non-required only, per the amendment).

---

## 1. malware_usb (Malware, difficulty 1) - canonical endpoint response

Proposed answer key:

```yaml
  actions_reviewed: true
  actions:
    - id: "a_iso"
      action: "isolate_host"
      target: { host: "ws_victim" }
    - action: "kill_process"
      target: { host: "ws_victim", pid: 7412 }
    - action: "kill_process"
      target: { host: "ws_victim", pid: 8044 }
    - action: "delete_file"
      target: { host: "ws_victim", path: "C:\\Users\\Public\\winupdate.exe" }
    - action: "delete_file"
      target: { host: "ws_victim", path: "E:\\Payroll_2026.exe" }
```

Rationale:
- isolate ws_victim: live C2 channel (s5: winupdate.exe to 185.141.62.11:443).
  End-state graded; releasing before submission forfeits.
- kill 7412 (E:\Payroll_2026.exe, s2): the dropper, running from removable
  media, visible in the process list with a removable-media path.
- kill 8044 (C:\Users\Public\winupdate.exe, s4/s5): the implant holding
  the C2 connection and the Run-key persistence.
- delete C:\Users\Public\winupdate.exe (authored: s4 run-key details, s5
  image): removes the persisted payload; the WindowsUpdate autorun row
  leaves the live view.
- delete E:\Payroll_2026.exe (authored: s2 image). OPEN QUESTION O1:
  recommended INCLUDED (thoroughness; the infection vector is still on a
  mounted drive). Alternative: exclude, accepting that a player deleting
  it takes collateral on a malicious file, which the model cannot excuse
  once the scenario is reviewed. Owner decides.

No ordering declared (P3: kills and deletes are host-local; isolation
order does not genuinely matter here). No identity actions: no
identity-provider events; credentials were not taken (P1 does not fire).

Designed traps (collateral, dismissal evidence documented):
- T1: the Endpoint Central staged installer (sup1: pid 7340, or its
  parent dcagentservice.exe 3180, or deleting
  EC_Patch_KB5039211.exe). Dismissal: ZOHO-signed installer, signed
  deployment-agent parent, matching FP detection det_deploy_staging_fp,
  established corpus actor.
- T2: ambient benign processes surfaced by the host's benign_expected
  detections (updaters, backup agent). Killing any is collateral.

Expected end-state: ws_victim isolated; PIDs 7412 and 8044 absent from
live Processes; the WindowsUpdate autorun row gone; no account changes.

---

## 2. phishing_1 (Phishing, difficulty 1) - identity-first response

Proposed answer key:

```yaml
  actions_reviewed: true
  actions:
    - action: "disable_account"
      target: { account: "victim" }
    - action: "revoke_sessions"
      target: { account: "victim" }
    - action: "force_password_reset"
      target: { account: "victim" }
```

Rationale (P1, breached account): s3 is a successful attacker sign-in
(Shanghai, single-factor, high risk) with harvested credentials. The
compromise lives in the ACCOUNT: disable benches it, revoke kills the
attacker's session and tokens, reset evicts the stolen credential.
Identity actions bind to the account entity in the Threats view per the
standing identity-entity rule.

No ordering declared (P3): there is no internal attack source to contain
first; the revoke/reset gap is symmetric, and both are required, so
sequence does not genuinely matter. Deliberately NOT the after class.

Designed trap (the marquee of this scenario):
- T1: isolate_host ws_victim. Host-think instead of identity-think. The
  workstation only rendered a credential-harvest page: the chain has zero
  endpoint execution or file events, and both TP detections are
  network/identity layer. Isolation is collateral only if still in effect
  at submission, so a player who realizes the mistake can release and pay
  only the lesson.

Expected end-state: victim account disabled, sessions revoked, password
reset; no host isolated; no processes killed; no files deleted.

---

## 3. password_spray (Brute Force, difficulty 3) - containment before reset

Proposed answer key:

```yaml
  actions_reviewed: true
  actions:
    - id: "a_iso"
      action: "isolate_host"
      target: { host: "ws_victim" }
    - action: "disable_account"
      target: { account: "lgreen" }
    - action: "revoke_sessions"
      target: { account: "lgreen" }
    - id: "a_reset"
      action: "force_password_reset"
      target: { account: "lgreen" }
      after: ["a_iso"]
```

Rationale:
- isolate ws_victim: every 4625 and the s6 success carry the
  workstation's source IP and name; the spray operates FROM this internal
  host. Containing the source is the incident's first lever.
- lgreen (P1, breached: s6 is the one successful logon): all three
  identity actions.
- DECLARED ORDERING (P3, the ruled isolate-before-reset class): a_reset
  after a_iso. Resetting lgreen while the spray host is still on-network
  lets the operator re-capture or immediately re-spray the fresh
  credential; containment must precede eradication. Only the reset
  carries `after` (disable and revoke are not credential material).

Designed traps:
- T1: disabling or resetting the five sprayed-but-FAILED accounts (dpark,
  mjohnson, bwilliams, achen, jkim). They were targeted, not breached:
  every event for them is a 4625 failure. Five separate collateral
  opportunities; locking out five employees is the classic
  over-response.
- T2: svc_backup (sup1/sup2 on the backup server). Dismissal: the
  stale-scheduled-task-credential FP (det_svc_stale_creds_fp), Backup
  Operators context; disabling or resetting it breaks the backup chain.
- T3: isolate dc. Big-hammer containment: the DC is the authentication
  target and reporting sensor, not compromised; isolating it takes down
  org-wide auth. All malicious activity originates from ws_victim.

Expected end-state: ws_victim isolated; lgreen disabled + revoked + reset
with the reset sequenced after isolation; the five sprayed accounts,
svc_backup, and the DC untouched.

---

## 4. lateral_movement_1 (Lateral Movement, difficulty 2) - two-host response

Proposed answer key:

```yaml
  actions_reviewed: true
  actions:
    - id: "a_iso"
      action: "isolate_host"
      target: { host: "ws_victim" }
    - action: "kill_process"
      target: { host: "ws_victim", pid: 8844 }
    - action: "delete_file"
      target: { host: "ws_victim", path: "C:\\Users\\{victim.username}\\Downloads\\nmap-7.95\\nmap.exe" }
    - action: "kill_process"
      target: { host: "file", pid: 2104 }
    - action: "kill_process"
      target: { host: "file", pid: 3312 }
    - action: "disable_account"
      target: { account: "victim" }
    - action: "revoke_sessions"
      target: { account: "victim" }
    - id: "a_reset"
      action: "force_password_reset"
      target: { account: "victim" }
      after: ["a_iso"]
```

Rationale:
- isolate ws_victim: recon origin (nmap sweep, firewall DENY/ALLOW trail)
  and the source of the lateral logon.
- kill 8844 (nmap.exe, s1): the staged recon tool, still running.
- delete the nmap image (authored: s1 image; placeholder path substitutes
  like chain content): removes the staged tool from the Downloads path.
- kill 2104 and 3312 on the file server (s6 parent cmd.exe and net.exe):
  the attacker's session shell and its enumeration child on the second
  host (P2: authored malicious-lineage pids on a scoped host are
  required, never collateral).
- victim account (P1, breached: s5 is a successful lateral 4624 with the
  victim's credentials from the compromised host): all three identity
  actions; a_reset after a_iso, same genuine class as password_spray
  (the foothold host could re-use a fresh credential while online).

FLAG F1 (boundary case for P2): pid 6240, the ws-side cmd.exe that
launched nmap, is authored (s1 parent) but is the interactive user
shell. Options: (a) add kill (ws_victim, 6240) for lineage completeness,
(b) leave it out and accept that killing it is collateral, (c) rule a
neutral tier. Recommended: (a), one more required kill; the shell that
launched the tool is part of the malicious session either way. Owner
decides.

Designed traps:
- T1: the scanner. Isolating ACME-SEC01, disabling svc_vulnscan, or
  killing nessusd.exe (sup1: 4120). Dismissal: authorized scanning host,
  service account with the Scanning Service Accounts group, verified
  Tenable identity, matching FP detection det_scanner_sweep.
- T2: deleting C:\Windows\System32\net.exe or C:\Windows\System32\cmd.exe
  on the file server (both authored images, so both deletable). The
  PROCESSES were malicious; the FILES are native OS binaries. Deleting
  them is collateral with real in-fiction damage.
- T3: isolate file (the file server). Defensible-looking but wrong-cost:
  the file server is the movement TARGET and serves org shares; the
  required response is killing the session, not cutting the org off its
  storage. Collateral only while still in effect at submission.

Expected end-state: ws_victim isolated; 8844, 2104, 3312 killed (6240
per F1 ruling); nmap.exe gone from Downloads; victim disabled + revoked +
reset (after isolation); scanner, svc_vulnscan, file server connectivity,
and system binaries untouched.

---

## 5. false_positive_veeam (False Positive) - the inaction contract

Proposed answer key:

```yaml
  actions_reviewed: true
  actions: []
```

Rationale: routine Veeam endpoint-backup behavior (job start 110, agent
manager spawn, service beacon to the backup server, bulk egress during
the window, job finish 190). Correct response is NO action:
`actions_reviewed: true` with an empty set makes the scenario one graded
unit of intentional inaction. Clean hands earn the credit; any successful
action in its scope is collateral AND costs the credit.

Documented temptations (all become collateral automatically):
- kill Veeam.EndPoint.Service.exe (s3: 2916) or Veeam.Agent.Manager.exe
  (s2: 3844); delete either authored Veeam binary path.
- isolate ws_victim or backup_server mid-backup-window.
Dismissal evidence: all three detections carry false_positive
dispositions; signed Veeam images; the established canonical backup
actor; 110/190 job events bracket the exact window the egress happened
in.

Expected end-state: nothing changed; the Response section shows the
inaction unit credited.

---

## Batch 1 summary for approval

| Scenario | Required actions | Declared `after` | Traps documented |
|---|---|---|---|
| malware_usb | 5 (1 iso, 2 kill, 2 delete; O1 open) | none | 2 |
| phishing_1 | 3 (identity only) | none | 1 |
| password_spray | 4 (1 iso, 3 identity) | reset after iso | 3 |
| lateral_movement_1 | 8 (1 iso, 3 kill, 1 delete, 3 identity; F1 open) | reset after iso | 3 |
| false_positive_veeam | 0 (inaction contract) | none | documented set |

Open items for the owner at this STOP:
- O1 (malware_usb): include delete of E:\Payroll_2026.exe in the required
  set? Recommended yes.
- F1 (lateral_movement_1): require kill of the ws-side launching shell
  pid 6240? Recommended yes.
- P1/P2/P3 batch principles: ratify, amend, or replace. P2 in particular
  decides whether any defensible kill can ever be collateral.

No implementation until this scaffold is approved. Each approved scenario
lands as its own commit (actions + actions_reviewed: true together),
gates after the batch.
