# Response-Action Answer Keys: Scaffolds for Owner Review (Stage 3c)

Cadence: each batch scaffold STOPS for owner approval, then
implementation is one scenario per commit (each commit lands the actions
and `actions_reviewed: true` together), full gates per batch via the
canonical gate runner. Scoring semantics: docs/action-scoring.md.
Identity-action statuses follow the ratified P1 rubric
(docs/classification-rubrics.md). Every proposed target, required and
acceptable alike, is verified against the achievability rule (authored
sources only; seed-independent).

**Expressibility check (ruled at the Batch 1 review, binding for
Batches 2-4):** if a scenario implies a correct response outside the
seven-action vocabulary (for example revoking an OAuth application
grant), the scaffold must flag it explicitly. The owner chooses one of
two resolutions: reshape the scenario evidence so the correct response
is expressible, or extend the action vocabulary through a separate
reviewed schema and engineering change. Never stretch an existing
action's meaning to cover a different response. A scenario with an
unresolved expressibility issue remains blocked from implementation and
must not be marked `actions_reviewed`.

Statuses are deliberate: REQUIRED earns credit and its omission is a
miss; ACCEPTABLE is defensible-but-nonessential (no credit, never
collateral, out of the denominator, surfaced factually if executed);
anything on neither list is collateral. Designed traps are collateral by
construction: they appear on neither list.

---

# Batch 1 (IMPLEMENTED, review passed 2026-07-17)

Commits f8a9f85 (malware_usb), aad3964 (phishing_1), 66962a2
(password_spray + N1 rubric), de6a891 (lateral_movement_1, fix-forward
41b98f2), a554b1a (false_positive_veeam). P2, P3, P4 ratified as
written below; P1 ratified with refinement, recorded in
docs/classification-rubrics.md (the response must evict what the
evidence shows the attacker controls). The scenario sections below are
the approved record.

## Batch principles (ratified; P1 superseded by the refined rubric text)

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
| password_spray | iso + revoke + reset (lgreen) | disable (lgreen) + hygiene reset (dpark only) | reset after iso | 3 |
| lateral_movement_1 | iso + 2 kills + revoke + reset | 2 kills + 1 delete + disable | reset after iso | 3 |
| false_positive_veeam | none (inaction) | none | none | documented set |

N1 ruled: revoke and disable on the sprayed-never-breached accounts stay
collateral; hygiene reset acceptable. Recorded in the P1 rubric.

---

# Batch 2 (SCAFFOLD, awaiting owner approval)

Next five scenarios. Statuses per the ratified P2 (required = active
malicious processes + actions necessary to stop ongoing
execution/compromise; acceptable = defensible nonessential
containment/cleanup; collateral = neither list). Identity per the P1
rubric (evict what the evidence shows the attacker controls). Every
target achievability-checked (authored sources, seed-independent).

## Cross-batch flags surfaced by this batch (owner decisions)

- **FX1 - FileCreate'd data files are not deletable in the world model.**
  data_exfil_archive and insider_staging both create a staging archive
  via Sysmon FileCreate (event_id 11). The Stage 1-3 world model only
  materializes deletable files from process images and run-key autoruns
  (snapshot_generator + action_overlay `_host_file_set`), so a
  `delete_file` on the archive is unachievable (the validator would
  reject it; the overlay could not execute it). This is a world-model
  limitation, not a vocabulary gap. Archive deletion is remediation
  cleanup, not containment: both scenarios have a complete containment
  answer key without it. RECOMMENDED: accept (author no archive delete;
  the required sets do not need it). Alternatives per the expressibility
  rule: reshape (make the archive a process/autorun artifact - not
  natural) or extend (materialize FileCreate targets as a deletable
  surface - a reviewed engineering change). Not blocking: no required
  action depends on it.

- **FX2 - delete_file is UI-reachable only from Autoruns rows.** The
  response UI offers Kill on process rows, Isolate/Release on the host,
  identity actions on Threats accounts, and Delete only on autorun image
  rows. A delete on a process-image file (not an autorun) is API-valid
  but has no button. No Batch 2 scenario has an autorun-backed malicious
  file, so no Batch 2 required action is an unreachable delete. Batch 2
  therefore proposes ZERO required deletes; any delete is acceptable at
  most. Flag for a future engineering pass IF a later batch needs a
  required delete on a non-autorun file. (Batch 1's one required delete,
  winupdate.exe, is autorun-backed and UI-reachable; malware_usb's
  acceptable E:\ delete and lateral_movement_1's acceptable nmap delete
  are process-image, API-only - acceptable, so reachability is moot.)

- **FX3 - OAuth-grant revocation is out of vocabulary (near-miss, not
  triggered).** false_positive_oauth is the BENIGN token-cycle scenario,
  so its correct response is inaction and nothing is unexpressible. But a
  future MALICIOUS illicit-consent / OAuth-grant-abuse scenario would
  imply "revoke the application's grant," which the seven-action
  vocabulary cannot express. Flagged now so the choice (reshape vs.
  extend vocabulary) is made deliberately before such a scenario is
  scaffolded, never by stretching disable_account.

## 6. c2_http (Command & Control, difficulty 2) - fileless C2

```yaml
  actions_reviewed: true
  actions:
    - action: "isolate_host"
      status: "required"
      target: { host: "ws_victim" }
    - action: "kill_process"
      status: "required"
      target: { host: "ws_victim", pid: 5912 }
```

Rationale:
- isolate ws_victim REQUIRED: severs the active HTTPS C2 channel (s3/s5
  beacons to the non-allowlisted domain).
- kill 5912 (rundll32.exe, s1) REQUIRED: rundll32 launched with no module
  (the fileless C2 loader, det_rundll_no_module); the active malicious
  process holding the beacon. Its parent is explorer.exe (3456, the user
  shell) - not a target (same class as the launching shells left
  acceptable/off-list elsewhere; here simply omitted).

No delete (fileless: no dropped payload file). No identity actions: the
host runs the implant, but no chain event shows credential or session
compromise, so identity is off-list (see T1).

No ordering (host-local containment; sequence does not matter).

Designed traps:
- T1: disable/revoke/reset the victim account. Host compromise, not
  credential compromise: nothing in the chain shows the account or its
  sessions were taken. Disruptive account action is collateral (P1); even
  a precautionary reset is collateral here (no targeting-of-credentials
  evidence at all).
- T2: isolate the DNS or proxy device (both in the environment as log
  sources / infra). The proxy is a PAN-OS non-endpoint (isolate would
  fail-precondition and surface factually); isolating the DNS server is
  collateral (infra, not the compromised host).

Expected end-state: ws_victim isolated; rundll32 5912 gone from live
Processes (its beacon connections drop with it); account and infra
untouched.

## 7. malware_ransomware (Malware, difficulty 1) - active encryption

```yaml
  actions_reviewed: true
  actions:
    - action: "isolate_host"
      status: "required"
      target: { host: "ws_victim" }
    - action: "kill_process"
      status: "required"
      target: { host: "ws_victim", pid: 18204 }
    - action: "kill_process"
      status: "acceptable"
      target: { host: "ws_victim", pid: 19301 }
    - action: "delete_file"
      status: "acceptable"
      target: { host: "ws_victim", path: "C:\\Users\\{victim.username}\\AppData\\Local\\Temp\\svchost.exe" }
```

Rationale:
- kill 18204 (Temp\svchost.exe, s1) REQUIRED: the encryptor, actively
  mass-encrypting (s5 critical det_mass_encrypt); stopping it stops the
  ongoing damage (P2).
- isolate ws_victim REQUIRED (FLAG R1): canonical ransomware containment
  - prevent encryption spread to mapped drives and network shares. This
  chain shows no network events, so a strict reading of P2 ("necessary to
  stop ONGOING compromise") could make isolation ACCEPTABLE instead,
  since killing 18204 halts the local encryption. Recommended REQUIRED
  (you cannot know it will not reach shares, and isolate-first is the
  ransomware playbook), but flagged for the owner.
- kill 19301 (vssadmin.exe, s2) ACCEPTABLE: the shadow-copy deletion
  LOLBin; a transient child that has already run by response time.
  Defensible to kill if still present, not necessary.
- delete Temp\svchost.exe ACCEPTABLE: removing the malware binary is
  defensible cleanup, not containment (the kill stops execution). It is a
  process image (deletable, achievable) but NOT autorun-backed, so it is
  API-only per FX2 - acceptable, so unreachability is moot.

No identity actions: local malware, no credential/session evidence.
No ordering.

Designed traps:
- T1: disable/revoke/reset the victim account (no credential compromise;
  the malware ran in the user's session but did not steal creds).
- T2: killing or deleting benign processes surfaced by the host's ambient
  benign detections.
- T3: deleting the victim's encrypted documents or the ransom note (both
  FileCreate'd, so not deletable anyway per FX1 - a non-trap by
  construction, but named so the triage review can warn against it).

Expected end-state: ws_victim isolated; encryptor 18204 gone (vssadmin
and the binary at discretion); account untouched.

## 8. data_exfil_archive (Data Exfiltration, difficulty 2) - exfil in progress

```yaml
  actions_reviewed: true
  actions:
    - action: "isolate_host"
      status: "required"
      target: { host: "ws_victim" }
    - action: "kill_process"
      status: "acceptable"
      target: { host: "ws_victim", pid: 15820 }
```

Rationale:
- isolate ws_victim REQUIRED: the exfil upload is an in-progress
  proxy-tunneled HTTP_CONNECT (s5) with no process-level kill target, so
  ISOLATION is the only lever that stops the ongoing exfiltration (P2).
  A deliberate teaching point, not an expressibility gap: isolate covers
  it.
- kill 15820 (7z.exe, s1) ACCEPTABLE: the archiver already produced the
  archive (s2) by upload time; killing it is defensible but does not stop
  the upload. Authored (s1 image), achievable.

No delete: the staged archive is FileCreate'd (FX1, unachievable); the
7z binary is a legitimate tool (deleting it is collateral, T2). No
identity: no auth events in the chain, no credential evidence. No
ordering.

Designed traps:
- T1: disable/revoke/reset the victim account. Classified Data
  Exfiltration with no authentication events: nothing shows credential
  compromise, so all identity action is collateral.
- T2: deleting C:\Program Files\7-Zip\7z.exe (authored image, in scope):
  destroying a legitimate installed tool.
- T3: killing the benign backup 7z (sup2: pid 6820, det_backup_archive_fp)
  or treating the cloud-sync FP (sup1, det_cloud_sync_fp) as hostile.

Expected end-state: ws_victim isolated (exfil severed); 7z 15820 at
discretion; account, the 7z binary, and the benign backup untouched.

## 9. insider_staging (Insider Threat, difficulty 3) - the account is the threat

```yaml
  actions_reviewed: true
  actions:
    - action: "disable_account"
      status: "required"
      target: { account: "victim" }
    - action: "revoke_sessions"
      status: "required"
      target: { account: "victim" }
    - action: "isolate_host"
      status: "required"
      target: { host: "ws_victim" }
    - action: "kill_process"
      status: "acceptable"
      target: { host: "ws_victim", pid: 7832 }
```

Rationale (the canonical P1 insider case):
- disable_account victim REQUIRED: the insider actor is operating with
  their own legitimate credentials; the evidence justifies removing the
  account from use (P1: disable required for an insider actor). This is
  the primary response.
- revoke_sessions victim REQUIRED: the active session is the one
  performing the exfil (s4/s5); it is a compromised-in-use session that
  must be evicted (P1: session compromise -> revoke required).
- isolate ws_victim REQUIRED: stops the in-progress cloud upload (s5),
  same proxy-tunneled no-kill-target shape as data_exfil.
- kill 7832 (chrome.exe, s4) ACCEPTABLE (FLAG I1): chrome is the exfil
  vehicle but a legitimate browser; isolation already severs the upload,
  so killing it is defensible containment of the channel, not necessary.
  Flagged because reasonable analysts differ on killing a user's browser.

- force_password_reset victim is deliberately OFF-LIST -> collateral
  (FLAG I2): there is no stolen password to evict (the insider owns the
  credential and authenticated legitimately). Resetting it evicts nothing
  the attacker controls; per the P1 unifying test it is not defensible
  hygiene here. Recommended COLLATERAL (the clean insider-vs-credential-
  compromise distinction), but flagged since one could argue it is
  acceptable account-decommissioning hygiene.

No ordering: disable, revoke, and isolate are all immediate containment
with no credential-reset re-capture risk (no required reset), so P3
declares nothing.

Designed traps:
- T1: force_password_reset victim (I2 above).
- T2: any action on the file server (s1/s2: the victim logged in and
  read the share). The file server is the data SOURCE, not compromised;
  isolating it cuts the org off its storage, and there is no process or
  account on it to action.
- T3: treating the benign bulk-egress FP (sup1: Veeam 190,
  det_mass_egress_fp) as the insider's exfil.

Expected end-state: victim disabled and sessions revoked; ws_victim
isolated (upload severed); chrome at discretion; the file server,
victim's password state, and the backup egress untouched.

## 10. false_positive_oauth (False Positive, difficulty 3) - benign token cycle

APPROVED SHAPE: the inaction contract.

```yaml
  actions_reviewed: true
  actions: []
```

Rationale: Entra flagged anomalous token activity (Dublin vs. Miami), but
the chain is a benign non-interactive M365 OAuth refresh-token cycle from
a compliant device (both detections carry false_positive dispositions).
Correct response is NO action: one graded unit of intentional inaction.
This is the hardest inaction scenario in the batch precisely because it
LOOKS like account takeover - the whole exercise is resisting the
identity-action reflex.

Designed traps (all collateral, all costing the inaction unit):
- disable / revoke / reset the victim account: the identity-action reflex
  the scenario is built to test. Benign token cycle, no compromise.
- isolate ws_victim: host-think against a benign identity event.

Expressibility: none (inaction is fully expressible). Note FX3: a
malicious sibling scenario would need OAuth-grant revocation, out of
vocabulary - not this benign one.

Expected end-state: nothing changed; the Response section credits the
inaction unit.

## Batch 2 summary for approval

| Scenario | Required | Acceptable | `after` | Traps | Flags |
|---|---|---|---|---|---|
| c2_http | iso + kill rundll32 | none | none | 2 | - |
| malware_ransomware | iso + kill encryptor | kill vssadmin + delete encryptor | none | 3 | R1 (iso required vs acceptable) |
| data_exfil_archive | iso | kill 7z | none | 3 | FX1 |
| insider_staging | disable + revoke + iso | kill chrome | none | 3 | I1 (kill chrome), I2 (reset collateral), FX1 |
| false_positive_oauth | none (inaction) | none | none | 2 | FX3 (near-miss) |

Open items for the owner at this STOP:
- R1: ransomware isolate REQUIRED (recommended) vs ACCEPTABLE.
- I1: insider kill-chrome ACCEPTABLE (recommended) vs off-list.
- I2: insider force_password_reset COLLATERAL (recommended) vs ACCEPTABLE.
- FX1/FX2/FX3: the modeling/vocabulary flags above (FX1 recommend accept;
  FX2 no Batch 2 impact; FX3 decide before any malicious-OAuth scenario).

No ordering declarations in Batch 2 (no required credential resets, so
the isolate-before-reset class does not arise; P3 restraint honored). No
implementation until this scaffold is approved. Batch 3 remains blocked
until Batch 2 review.

---

# Reachability correction (3c Batch 2 review, 2026-07-17)

The fixed-seed UI-reachability harness now validates EVERY required action,
EVERY acceptable action, and EVERY declared trap (previously required
actions only). An unreachable action must not appear in the answer key.
Seven acceptable actions were unreachable and were removed:

- password_spray: `force_password_reset` on mjohnson, bwilliams, achen,
  jkim - no detection surfaces these sprayed-but-unbreached accounts, so
  no Threats-view identity control exists for them. `dpark` is surfaced
  (det_multi_account_failures on its 4625) and its acceptable reset is
  KEPT and test-proven reachable.
- malware_usb: `delete_file` E:\Payroll_2026.exe - a process-image file,
  not an autorun; delete is surfaced only on Autoruns image rows.
- malware_ransomware: `delete_file` on the Temp\svchost.exe encryptor -
  process-image, same reason.
- lateral_movement_1: `delete_file` on the nmap.exe image - same reason.

No artificial detections were added to expose buttons. The rubric
(docs/classification-rubrics.md) still explains that credential hygiene
on the unsurfaced sprayed accounts, and removing the malware binaries,
would be defensible in principle; they are simply not authored actions
because no current UI surface exposes them (arbitrary-file deletion is
FX2 backlog).

[SCENARIOS] yaml_v2 source: 20 scenarios loaded
# Declared Action + Trap Ledger (authored form, source-reviewable)

Every entry names the exact action verb and authored composite target
(environment host/account id, authored pid, or authored path) exactly as
it appears in the scenario YAML. Every required, acceptable, and trap
entry is validated UI-reachable + executable across the fixed five-seed
set by test_action_scoring; traps additionally grade collateral.

## malware_usb  (required 4, acceptable 0, traps 2)

- REQUIRED  `isolate_host`  host=ws_victim
- REQUIRED  `kill_process`  host=ws_victim pid=7412
- REQUIRED  `kill_process`  host=ws_victim pid=8044
- REQUIRED  `delete_file`  host=ws_victim path=C:\Users\Public\winupdate.exe
- TRAP  `kill_process`  host=ws_victim pid=7340
- TRAP  `disable_account`  account=victim

## phishing_1  (required 2, acceptable 1, traps 1)

- REQUIRED  `revoke_sessions`  account=victim
- REQUIRED  `force_password_reset`  account=victim
- ACCEPTABLE  `disable_account`  account=victim
- TRAP  `isolate_host`  host=ws_victim

## password_spray  (required 3, acceptable 2, traps 3)

- REQUIRED  `isolate_host`  host=ws_victim
- REQUIRED  `revoke_sessions`  account=lgreen
- REQUIRED  `force_password_reset`  account=lgreen
- ACCEPTABLE  `disable_account`  account=lgreen
- ACCEPTABLE  `force_password_reset`  account=dpark
- TRAP  `isolate_host`  host=dc
- TRAP  `disable_account`  account=dpark
- TRAP  `disable_account`  account=svc_backup

## lateral_movement_1  (required 5, acceptable 3, traps 3)

- REQUIRED  `isolate_host`  host=ws_victim
- REQUIRED  `kill_process`  host=ws_victim pid=8844
- REQUIRED  `kill_process`  host=file pid=2104
- REQUIRED  `revoke_sessions`  account=victim
- REQUIRED  `force_password_reset`  account=victim
- ACCEPTABLE  `kill_process`  host=file pid=3312
- ACCEPTABLE  `kill_process`  host=ws_victim pid=6240
- ACCEPTABLE  `disable_account`  account=victim
- TRAP  `isolate_host`  host=scan
- TRAP  `kill_process`  host=scan pid=4120
- TRAP  `isolate_host`  host=file

## false_positive_veeam  (required 0, acceptable 0, traps 2)

- TRAP  `kill_process`  host=ws_victim pid=2916
- TRAP  `isolate_host`  host=ws_victim

## c2_http  (required 2, acceptable 0, traps 2)

- REQUIRED  `isolate_host`  host=ws_victim
- REQUIRED  `kill_process`  host=ws_victim pid=5912
- TRAP  `disable_account`  account=victim
- TRAP  `isolate_host`  host=dns

## malware_ransomware  (required 2, acceptable 1, traps 1)

- REQUIRED  `isolate_host`  host=ws_victim
- REQUIRED  `kill_process`  host=ws_victim pid=18204
- ACCEPTABLE  `kill_process`  host=ws_victim pid=19301
- TRAP  `disable_account`  account=victim

## data_exfil_archive  (required 1, acceptable 1, traps 3)

- REQUIRED  `isolate_host`  host=ws_victim
- ACCEPTABLE  `kill_process`  host=ws_victim pid=15820
- TRAP  `disable_account`  account=victim
- TRAP  `isolate_host`  host=dns
- TRAP  `kill_process`  host=ws_victim pid=6820

## insider_staging  (required 3, acceptable 2, traps 1)

- REQUIRED  `disable_account`  account=insider
- REQUIRED  `revoke_sessions`  account=insider
- REQUIRED  `isolate_host`  host=ws_victim
- ACCEPTABLE  `kill_process`  host=ws_victim pid=7832
- ACCEPTABLE  `force_password_reset`  account=insider
- TRAP  `isolate_host`  host=file

## false_positive_oauth  (required 0, acceptable 0, traps 2)

- TRAP  `disable_account`  account=victim
- TRAP  `isolate_host`  host=ws_victim

