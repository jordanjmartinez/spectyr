# Response-Action Answer Keys: Scaffolds for Owner Review (Stage 3c)

Re-scaffold under the required/acceptable scoring schema (supersedes the
prior Batch 1 scaffold). Cadence: this scaffold STOPS for owner approval,
then implementation is one scenario per commit (each commit lands the
actions and `actions_reviewed: true` together), full gates per batch.
Scoring semantics: docs/action-scoring.md. Every proposed target,
required and acceptable alike, is verified against the achievability rule
(authored sources only; seed-independent).

Statuses are deliberate: REQUIRED earns credit and its omission is a
miss; ACCEPTABLE is defensible-but-nonessential (no credit, never
collateral, out of the denominator, surfaced factually if executed);
anything on neither list is collateral. Designed traps are collateral by
construction: they appear on neither list.

## Batch principles for ratification (full text)

- **P1 (revised): justified-minimum identity response.** Identity
  scenarios require only the justified minimum the scenario's evidence
  supports. For a stolen-credential victim that minimum is
  force_password_reset + revoke_sessions (evict the credential, evict
  the sessions); disable_account is typically ACCEPTABLE unless the
  scenario justifies benching the account. Disruptive action requires
  evidence of compromise; precautionary credential hygiene is
  defensible. Accounts that were targeted but never breached are never
  required targets; hygiene on them may be acceptable, disruption on
  them is collateral.
- **P2 (replacement, ruled).** REQUIRED: active malicious processes and
  the actions necessary to stop ongoing execution or compromise.
  ACCEPTABLE: defensible but nonessential containment and cleanup.
  COLLATERAL: benign or unrelated targets, and everything on neither
  list. Designed traps remain collateral by construction (they appear on
  neither list).
- **P3: ordering restraint.** `after` only where the sequence genuinely
  matters (the containment-before-credential-reset class: an online
  attack source could re-capture or re-use credentials reset too early),
  declared on required actions referencing required actions. Two
  declarations in this batch, both that class.
- **P4: offline-host wrinkle.** Not used in Batch 1. Reserved for a
  later batch (max 1-2 corpus-wide; non-required only: a
  tempting-but-wrong containment target or a surfaced failed attempt;
  the validator rejects required credit on it).

---

## 1. malware_usb (Malware, difficulty 1) - canonical endpoint response

```yaml
  actions_reviewed: true
  actions:
    - id: "a_iso"
      action: "isolate_host"
      status: "required"
      target: { host: "ws_victim" }
    - action: "kill_process"
      status: "required"
      target: { host: "ws_victim", pid: 7412 }
    - action: "kill_process"
      status: "required"
      target: { host: "ws_victim", pid: 8044 }
    - action: "delete_file"
      status: "required"
      target: { host: "ws_victim", path: "C:\\Users\\Public\\winupdate.exe" }
    - action: "delete_file"
      status: "acceptable"
      target: { host: "ws_victim", path: "E:\\Payroll_2026.exe" }
```

Rationale:
- isolate ws_victim REQUIRED: live C2 channel (s5: winupdate.exe to
  185.141.62.11:443); stopping ongoing compromise. End-state graded.
- kill 7412 and 8044 REQUIRED (P2: active malicious processes; both are
  live payload PIDs, the dropper and the implant).
- delete C:\Users\Public\winupdate.exe REQUIRED per the re-ruling
  (installed implant; authored via s4 run-key details and s5 image);
  removing it also clears the WindowsUpdate autorun row.
- delete E:\Payroll_2026.exe ACCEPTABLE per the re-ruling: the scenario
  does not establish that the media remains mounted or that its deletion
  is essential (s1 records insertion; no event makes the file an ongoing
  mechanism once 7412 is dead). Defensible cleanup, so executing it
  surfaces as an acceptable response, never collateral.

No ordering (P3: kills and deletes are host-local; sequence does not
genuinely matter). No identity actions (no identity-provider events; no
credential theft in evidence, P1 does not fire).

Designed traps (neither list, collateral by construction):
- T1: the Endpoint Central staged installer (sup1: pid 7340, its parent
  dcagentservice.exe 3180, or deleting EC_Patch_KB5039211.exe).
  Dismissal: ZOHO-signed installer, signed deployment-agent parent,
  matching FP detection det_deploy_staging_fp, established corpus actor.
- T2: ambient benign processes surfaced by the host's benign_expected
  detections (updaters, backup agent).

Expected end-state: ws_victim isolated; 7412 and 8044 absent from live
Processes; the WindowsUpdate autorun row gone; account untouched;
E:\Payroll_2026.exe deleted or not with zero score difference.

---

## 2. phishing_1 (Phishing, difficulty 1) - identity-first response

```yaml
  actions_reviewed: true
  actions:
    - action: "revoke_sessions"
      status: "required"
      target: { account: "victim" }
    - action: "force_password_reset"
      status: "required"
      target: { account: "victim" }
    - action: "disable_account"
      status: "acceptable"
      target: { account: "victim" }
```

Rationale (P1 justified minimum for a stolen-credential victim): s3 is a
successful attacker sign-in with harvested credentials; revoke evicts the
attacker's session and tokens, reset evicts the stolen credential.
disable ACCEPTABLE: benching the account is defensible mid-incident but
not the scenario-justified minimum (single-account compromise with the
credential and sessions already evicted). Identity actions bind to the
account entity in the Threats view per the standing identity-entity rule.

No ordering (P3: no internal attack source to contain first; both
required actions are immediate and symmetric).

Designed trap (the marquee of this scenario):
- T1: isolate_host ws_victim. Host-think instead of identity-think. The
  workstation only rendered a credential-harvest page: zero endpoint
  execution or file events; both TP detections are network and identity
  layer. Collateral only while still in effect at submission, so
  realizing the mistake and releasing costs only the lesson.

Expected end-state: victim sessions revoked and password reset (disabled
or not with zero score difference); no host isolated; no processes
killed; no files deleted.

---

## 3. password_spray (Brute Force, difficulty 3) - containment before reset

```yaml
  actions_reviewed: true
  actions:
    - id: "a_iso"
      action: "isolate_host"
      status: "required"
      target: { host: "ws_victim" }
    - action: "revoke_sessions"
      status: "required"
      target: { account: "lgreen" }
    - id: "a_reset"
      action: "force_password_reset"
      status: "required"
      target: { account: "lgreen" }
      after: ["a_iso"]
    - action: "disable_account"
      status: "acceptable"
      target: { account: "lgreen" }
    - action: "force_password_reset"
      status: "acceptable"
      target: { account: "dpark" }
    - action: "force_password_reset"
      status: "acceptable"
      target: { account: "mjohnson" }
    - action: "force_password_reset"
      status: "acceptable"
      target: { account: "bwilliams" }
    - action: "force_password_reset"
      status: "acceptable"
      target: { account: "achen" }
    - action: "force_password_reset"
      status: "acceptable"
      target: { account: "jkim" }
```

Rationale:
- isolate ws_victim REQUIRED: every 4625 and the s6 success carry this
  workstation's source IP and name; the spray operates FROM it; stopping
  ongoing compromise (P2).
- lgreen (breached, s6 success): revoke + reset REQUIRED, disable
  ACCEPTABLE, per the re-ruling and P1.
- DECLARED ORDERING (P3, the ruled class): a_reset after a_iso.
  Resetting lgreen while the spray host is on-network lets the operator
  re-capture or re-spray the fresh credential.
- The five sprayed-but-never-breached accounts: force_password_reset
  ACCEPTABLE each (precautionary credential hygiene, defensible);
  disable on them is deliberately on NEITHER list: the designed trap.
  Rubric principle, stated for the triage review: disruptive action
  requires evidence of compromise; precautionary credential hygiene is
  defensible. Their evidence is 4625 failures only.
- NOTE N1 for the owner: revoke_sessions on the five sprayed accounts is
  also on neither list, so it grades as collateral. Consistent with the
  rubric (session revocation is disruptive without evidence of
  compromise), but flagged since reasonable analysts differ; say the
  word and it becomes acceptable per account.

Designed traps:
- T1: disable_account on dpark, mjohnson, bwilliams, achen, or jkim.
  Targeted, not breached; locking out five employees is the classic
  over-response. Five separate collateral opportunities.
- T2: svc_backup (sup1/sup2 stale-scheduled-task-credential FP,
  det_svc_stale_creds_fp): any identity action on it breaks the backup
  chain; Backup Operators context.
- T3: isolate dc. The DC is the authentication target and sensor, not
  compromised; isolating it takes down org-wide auth.

Expected end-state: ws_victim isolated; lgreen revoked + reset (reset
after isolation; disabled or not, zero difference); sprayed accounts
reset-or-not with zero difference, never disabled; svc_backup and the DC
untouched.

---

## 4. lateral_movement_1 (Lateral Movement, difficulty 2) - two-host response

```yaml
  actions_reviewed: true
  actions:
    - id: "a_iso"
      action: "isolate_host"
      status: "required"
      target: { host: "ws_victim" }
    - action: "kill_process"
      status: "required"
      target: { host: "ws_victim", pid: 8844 }
    - action: "kill_process"
      status: "required"
      target: { host: "file", pid: 2104 }
    - action: "kill_process"
      status: "acceptable"
      target: { host: "file", pid: 3312 }
    - action: "kill_process"
      status: "acceptable"
      target: { host: "ws_victim", pid: 6240 }
    - action: "delete_file"
      status: "acceptable"
      target: { host: "ws_victim", path: "C:\\Users\\{victim.username}\\Downloads\\nmap-7.95\\nmap.exe" }
    - action: "revoke_sessions"
      status: "required"
      target: { account: "victim" }
    - id: "a_reset"
      action: "force_password_reset"
      status: "required"
      target: { account: "victim" }
      after: ["a_iso"]
    - action: "disable_account"
      status: "acceptable"
      target: { account: "victim" }
```

Rationale:
- isolate ws_victim REQUIRED: recon origin and lateral-movement source;
  stopping ongoing compromise.
- kill 8844 (nmap.exe, s1) REQUIRED: the active malicious payload (P2).
- kill 2104 (file-server cmd.exe, s6 parent) REQUIRED: the attacker's
  session shell on the second host, an active control mechanism (P2).
- kill 3312 (net.exe, s6) ACCEPTABLE per the justified-minimum test: a
  transient enumeration child whose work is done; killing it is
  defensible cleanup, not necessary to stop ongoing compromise.
- kill 6240 (ws-side launching shell, s1 parent) ACCEPTABLE per the
  re-ruling: it launched the tool but is not itself an active execution
  or control mechanism once the host is isolated and 8844 is dead.
- delete nmap.exe ACCEPTABLE per the justified-minimum test, stated:
  deletion is not necessary to stop ongoing execution (the process kill
  and isolation do that); removing the staged tool is defensible
  cleanup. Authored via s1 image; placeholder substitutes like chain
  content.
- victim (stolen-credential use in the s5 lateral 4624): revoke + reset
  REQUIRED, disable ACCEPTABLE (P1); a_reset after a_iso, the same
  genuine containment-before-reset class as password_spray.

Designed traps:
- T1: the scanner. Isolating ACME-SEC01, disabling svc_vulnscan, or
  killing nessusd.exe (sup1: 4120). Dismissal: authorized scanning host,
  service account with the Scanning Service Accounts group, verified
  Tenable identity, matching FP detection det_scanner_sweep.
- T2: deleting C:\Windows\System32\net.exe or C:\Windows\System32\cmd.exe
  on either host (authored images, so deletable and in scope). The
  PROCESSES were malicious; the FILES are native OS binaries.
- T3: isolate file (the file server): the movement TARGET serving org
  shares; the response is killing the session, not cutting the org off
  its storage. Collateral only while still in effect.

Expected end-state: ws_victim isolated; 8844 and 2104 dead (3312, 6240,
and the nmap file at the player's discretion with zero score
difference); victim revoked + reset after isolation; scanner,
svc_vulnscan, file-server connectivity, and system binaries untouched.

---

## 5. false_positive_veeam (False Positive) - the inaction contract

APPROVED UNCHANGED by the re-ruling:

```yaml
  actions_reviewed: true
  actions: []
```

Routine Veeam endpoint-backup behavior (job start 110, agent manager
spawn, service beacon, bulk egress in the backup window, job finish
190). One graded unit of intentional inaction; clean hands earn it; any
successful action in scope is collateral AND costs the unit. Documented
temptations: killing Veeam.EndPoint.Service.exe (2916) or
Veeam.Agent.Manager.exe (3844), deleting either authored Veeam binary,
isolating ws_victim or backup_server mid-window. Dismissal: all three
detections carry false_positive dispositions; signed Veeam images;
canonical backup actor; the 110/190 job events bracket the window.

---

## Batch 1 summary for approval

| Scenario | Required | Acceptable | `after` | Traps |
|---|---|---|---|---|
| malware_usb | iso + 2 kills + 1 delete | 1 delete (USB file) | none | 2 |
| phishing_1 | revoke + reset | disable | none | 1 |
| password_spray | iso + revoke + reset (lgreen) | disable (lgreen) + 5 hygiene resets | reset after iso | 3 |
| lateral_movement_1 | iso + 2 kills + revoke + reset | 2 kills + 1 delete + disable | reset after iso | 3 |
| false_positive_veeam | none (inaction) | none | none | documented set |

Open item: N1 (revoke_sessions on the five sprayed accounts currently
grades collateral; flag if it should be acceptable instead).

No implementation until this scaffold is approved. Each approved
scenario lands as its own commit (actions + actions_reviewed: true
together), gates after the batch.
