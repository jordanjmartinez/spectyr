# Classification Rubrics (authoring guidance)

Rubrics for classifying and difficulty-tiering scenarios. Guidance for future
authoring; recording a rubric changes no existing scenario.

## ATT&CK baseline (pinned to v19.1)

Spectyr's ATT&CK mappings are **pinned to Enterprise ATT&CK v19.1** — migrated
on 2026-07-17 from the pre-v19 (v18.1) baseline. Every technique ID, name, and
tactic name in the corpus (answer keys, `DETECTIONS` mitre tags, v2
`triage_review`, `CANONICAL_TECHNIQUE_NAMES`, `CANONICAL_TACTICS`, radar axes) is
interpreted against this pinned baseline.

**Verification basis.** The migration validated all 22 active technique mappings
against the official v19.1 STIX dataset (github.com/mitre/cti tag
`ATT&CK-v19.1`; `enterprise-attack.json` sha256
`fc783039f17fba646f79448f1322996457c658a9474f6d14c3bc924a2cf1c97d`, recorded in
`test_scenario_loader_v2.py`): each target ID exists, is non-revoked/deprecated,
its name matches the dataset, and it carries the target tactic. v19 retired
Defense Evasion, splitting it into **Stealth (TA0005)** and **Defense Impairment
(TA0112)**, and merged `T1562`/`T1070.001` (both revoked) under **`T1685`
(Disable or Modify Tools)** — log-clearing now lives at `T1685.005`. The radar
carries 13 axes in live-matrix order.

**Upgrades are deliberate migrations, never ambient drift.** A version bump is a
single dedicated migration that updates together: the pinned version, the
canonical technique/tactic maps, ALL corpus values (answer keys, detection tags,
triage via the correction registry, radar axes), validated against that
version's official STIX dataset (tag + file hash recorded). A technique ID,
name, or tactic must never change value incidentally inside an unrelated commit.
Commit boundaries fall where the repo is internally consistent per its own
invariant guards (pin, name-match, coverage); a guard red at a boundary means
the boundary is wrong — never land a knowingly-red commit, never loosen a guard.

## Log-clearing scenarios (Indicator Removal: Clear Windows Event Logs)

### Ruling for `defense_evasion_log_clearing` (final, 2026-07-16)

The Stage 2 blocker on this scenario's tier/classification is resolved:

| Field | Value |
|---|---|
| difficulty | medium (corpus difficulty 2) |
| detection disposition | `true_positive` |
| classification_event | step `s5` (the Windows Security Event ID 1102 step) |
| mitre_technique | `T1685.005` (v19.1; was `T1070.001` pre-migration) |
| mitre_tactic | Defense Impairment (v19.1; was Defense Evasion) |

`classification_event` is the 1102 step (`s5`), verified present in the
scenario. It is distinct from `answer_key.root_cause` (`s1`, patient zero):
root_cause is the earliest malicious event, classification_event is where the
1102 clearing is confirmed. Stage 2 detection authoring binds the scenario's
true-positive detection to `s5`.

### PIN GUARD (retraction recorded 2026-07-16 — do not remove)

An earlier ruling here declared `T1685.005` and a tactic "Defense Impairment"
**nonexistent**. That was WRONG and is **retracted**. Both are real, current
**ATT&CK v19.1** identifiers, verified live on 2026-07-16:
`T1685.005` "Clear Windows Event Logs" (sub-technique of `T1685` "Disable or
Modify Tools"), tactic **Defense Impairment (TA0112)** —
attack.mitre.org/techniques/T1685/005/ and attack.mitre.org/tactics/TA0112/.
They are the **v19 successors** of the log-clearing mapping (see the ATT&CK
baseline section above).

As of the **v19.1 migration (2026-07-17)** these successors are now the corpus
values: the log-clearing scenario carries `T1685.005` (Disable or Modify Tools:
Clear Windows Event Logs, tactic Defense Impairment). The guard is a **positive
pin**: every technique ID and tactic name in the corpus must be a pinned v19.1
string, so a value from a different ATT&CK version fails loudly. Enforced by
`test_corpus_strings_match_pinned_attack_baseline` in `test_scenario_loader_v2.py`.

### Difficulty rubric for log-clearing variants

- **Easy**: 1102 shown directly, obvious account, minimal correlation.
- **Medium**: 1102 confirms clearing; the player must correlate it to the
  logon, the process (e.g. `wevtutil cl Security`), and the account.
  `defense_evasion_log_clearing` is a medium variant.
- **Hard**: 1102 absent or not the entry point; clearing is discovered via
  process/file evidence; missing telemetry is itself evidence.

### False positive rubric

A false positive requires affirmative evidence of legitimate administration:
a maintenance window, a named admin, backup-before-clear, or a change record.
The `wevtutil` command alone proves clearing occurred, NOT malicious intent.
FP variants use `classification: false_positive` with `root_cause: null` (per
the schema conditional in schema_v2.json).

## Supplemental events: correlation-window red-herring rule

(Stage 2 density pass, review amendment 1, 2026-07-16.)

Any supplemental (authored benign) event whose timestamp falls within the
attack's plausible correlation window MUST be declared a deliberate red
herring (`red_herring: true` on the supplemental event) at narrative approval.
Accidental correlation is prohibited: a benign event near the attack in time
is either moved genuinely outside the window (hours away) or declared an
intentional distractor whose resolution is the dismissal evidence (source host
role, account type, process identity, group membership), never the timing.

The lateral_movement_1 pilot's `sup1`/`sup2` (the scanner sweep at
attack_base minus 118-120s) are declared red herrings: the analyst resolves
them by recognizing the ACME-SEC01 scanner role and the svc_vulnscan service
account, not by the offset. All 3c scaffolds follow this rule.

## Response-action rubric: identity actions (P1, ratified with refinement)

(3c Batch 1 review, final, 2026-07-17. Supersedes the earlier P1 text;
the N1 threshold below is unchanged.)

**Unifying test: the response must evict what the evidence shows the
attacker controls.**

- **Confirmed password or reusable-credential compromise:**
  force_password_reset AND revoke_sessions are required (the attacker
  holds the credential and may hold sessions; both must be evicted).
- **Session or token compromise without evidence that the password was
  exposed:** revoke_sessions is required; force_password_reset may be
  acceptable as credential hygiene.
- **disable_account is required only when the evidence justifies removing
  the account from use** (for example an insider actor, or an account
  whose continued operation is itself the threat). Otherwise it is
  acceptable or collateral according to the evidence.
- **Targeting without compromise may justify credential hygiene.**
  Disruptive account action is collateral. (The N1 threshold, unchanged:
  attempted compromise may justify a precautionary force_password_reset
  as `acceptable`; session revocation or account disablement requires
  evidence that the account or its sessions were actually compromised.)

The password_spray answer key is the canonical N1 application: a sprayed
account (4625 failures only) may carry an acceptable hygiene reset, while
any revoke or disable on it is collateral. The identical actions on
lgreen are REQUIRED because the evidence exists there: the s6 4624
success is an attacker logon with that account.

**Reachability constraint on the answer key (3c Batch 2 review ruling):**
an action may be authored (required OR acceptable) only if a current UI
surface actually exposes it; an unreachable action must not appear in the
answer key. In password_spray, only `dpark` is surfaced (by
det_multi_account_failures on its 4625), so only `dpark` carries the
acceptable hygiene reset; the four sprayed accounts with no surfacing
detection (mjohnson, bwilliams, achen, jkim) get none, even though the
same hygiene would be defensible in principle. The rubric explains the
principle; the answer key carries only the reachable action. (Related:
arbitrary-file deletion of a process-image or FileCreate file has no UI
affordance today - delete is surfaced only on Autoruns image rows - so
such deletes are not authored as required or acceptable; FX2 backlog.)

## Response-action rubric: insider disable requires established intent (S1)

(3c Batch 4, insider_shadow_it ruling, 2026-07-17.)

Same category, same account-owner-is-the-actor structure, different
evidence, different required response. `disable_account` on the actor's
own account is required only when the evidence establishes intentional
exfiltration, policy evasion, or a need to remove the employee's access.
Shadow-IT use alone (an unapproved tool) does not prove deliberate
malicious intent. The intended contrast pair:

- **insider_staging**: deliberate exfiltration is established (a user
  accessed a sensitive share outside their role, staged a copy, and
  exfiltrated it), so disable_account is REQUIRED.
- **insider_shadow_it**: unsanctioned tool use is established, but
  malicious intent is not, so disable_account is ACCEPTABLE - only
  isolate_host and revoke_sessions are required (contain the endpoint,
  evict the active session), and disable / reset / kill-the-app are
  defensible options.

(In insider_shadow_it the account holder is the actor but not proven
malicious, so the account entity is named `employee`, not `insider`.)

## Response-action rubric: insider accounts and password reset (I2)

(3c Batch 2, insider_staging ruling, 2026-07-17.)

For an insider actor operating with their own legitimate credentials, the
eviction is disable_account (remove the account from use), and
revoke_sessions evicts the active malicious session. A
force_password_reset cannot evict an account's legitimate owner: the
insider knows and owns the credential, so resetting it is nonessential
offboarding hygiene, not evidence-driven eviction. Author it acceptable,
never required, and never treat it as the eviction. The insider_staging
answer key applies this: disable and revoke are required, reset is
acceptable. (In this scenario the account holder is the threat, not a
victim; the account entity is named `insider` accordingly.)

## Response-action rubric: containment class doctrine (R1)

(3c Batch 2, ransomware isolation ruling, 2026-07-17.)

Isolation is class-based containment, not only a per-process reaction.
For an actively compromised endpoint, isolation is a REQUIRED containment
step independent of whether another action already halted the visible
process. In ransomware specifically: killing the encryptor stops the
running process, but the host is an actively compromised endpoint, so
isolation is required containment (it prevents encryption from spreading
to mapped drives and network shares, and forecloses any second-stage or
C2 channel the single chain may not have surfaced). The
malware_ransomware answer key applies this: isolate is required alongside
killing the encryptor.

## Response-action rubric: persistence removal and the GENERAL RULE (Stage 3c.5)

(3c.5 persistence-response increment, 2026-07-17.)

`remove_persistence` neutralizes a persistence artifact as a first-class
response: a WMI event subscription (Sysmon 19/20/21, correlated into one
logical subscription) or a registry Run-key value. It is a real verb, never
a stretched `delete_file`. A persistence artifact carries two flags:
registration (cleared by `remove_persistence`) and, when file-backed, a
file flag (cleared by `delete_file` of the payload). The Autoruns row is a
persistence-artifact view and survives until BOTH flags are neutralized (a
registration-only WMI subscription is neutralized by registration alone).

**GENERAL RULE (invariant, enforced by the dual-flag model):** no
acceptable action may render a required action unreachable. Because the
row survives on whichever flag is still live, a required `delete_file`
stays reachable after an acceptable `remove_persistence` on the same Run
key, and vice versa, under either ordering. Authoring corollary: never
declare an acceptable action whose effect would remove the only surface a
required action is reached from.

**Identity (never a display name).** A WMI subscription's identity is the
correlated triple (host + normalized namespace + filter path + consumer
path), never the consumer name alone; two subscriptions sharing a consumer
name stay distinct and an ambiguous name fails closed. A Run-key identity
is host + normalized key + value name, never the payload path; two values
sharing a payload stay distinct. Answer keys REFERENCE an artifact by a
selector (`wmi:<ConsumerName>` / `run_key:<KeyPath\ValueName>`) that
resolves to the correlated identity; the identity itself is always
derived server-side.

## Difficulty tier table

Marked **final** for `defense_evasion_log_clearing`: medium (difficulty 2).
The pending clarification that blocked Stage 2 is resolved.
