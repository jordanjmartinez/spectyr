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

The password_spray answer key is the canonical N1 application: the five
sprayed accounts (4625 failures only) carry acceptable hygiene resets,
while any revoke or disable on them is collateral. The identical actions
on lgreen are REQUIRED because the evidence exists there: the s6 4624
success is an attacker logon with that account.

## Difficulty tier table

Marked **final** for `defense_evasion_log_clearing`: medium (difficulty 2).
The pending clarification that blocked Stage 2 is resolved.
