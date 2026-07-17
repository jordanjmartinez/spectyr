# Classification Rubrics (authoring guidance)

Rubrics for classifying and difficulty-tiering scenarios. Guidance for future
authoring; recording a rubric changes no existing scenario.

## ATT&CK baseline (pinned to pre-v19)

Spectyr's ATT&CK mappings are **pinned to the pre-v19 baseline (Enterprise
ATT&CK v18.1 semantics)**. Every technique ID, name, and tactic name in the
corpus (answer keys, `DETECTIONS` mitre tags, `TRIAGE_REVIEWS`,
`CANONICAL_TECHNIQUE_NAMES`) is interpreted against this pinned baseline.

**The pinned baseline is NOT the current live model.** Current live ATT&CK is
**v19.1 (released 2026-04-28)**, verified against attack.mitre.org/resources/
versions/ on 2026-07-16. v19 restructured Defense Evasion — it split into
**Stealth (TA0005)** and **Defense Impairment (TA0112)**, and merged `T1562`
and `T1070.001` content under **`T1685` (Disable or Modify Tools)** (so
log-clearing now lives at `T1685.005`). Spectyr stays on v18.1 semantics until a
**dedicated, owner-scheduled v19 migration** (recommended after Batch 4).

**Upgrades are deliberate migrations, never ambient drift.** The v19 migration
is a single dedicated commit that updates together: the pinned version here, the
canonical technique/tactic maps, ALL answer keys re-verified against live v19
pages (URL per change), the radar tactic axes re-enumerated from the live v19
Enterprise matrix (Defense Evasion retired; Stealth + Defense Impairment
replace it), the rubrics docs, and the guard test. A technique ID, name, or
tactic must never change value incidentally inside an unrelated commit.

**Live-URL rule (standing).** No ATT&CK technique or tactic change may enter the
repo without a live attack.mitre.org URL for the specific technique page
attached to the change request, regardless of who requests it. This applies to
new `DETECTIONS` mitre tags as much as to answer-key edits.

## Log-clearing scenarios (Indicator Removal: Clear Windows Event Logs)

### Ruling for `defense_evasion_log_clearing` (final, 2026-07-16)

The Stage 2 blocker on this scenario's tier/classification is resolved:

| Field | Value |
|---|---|
| difficulty | medium (corpus difficulty 2) |
| detection disposition | `true_positive` |
| classification_event | step `s5` (the Windows Security Event ID 1102 step) |
| mitre_technique | `T1070.001` |
| mitre_tactic | Defense Evasion |

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

Because Spectyr is pinned to the pre-v19 baseline, the log-clearing scenario
keeps `T1070.001` (Indicator Removal: Clear Windows Event Logs, tactic Defense
Evasion) under v18.1 semantics until the deliberate v19 migration. The guard is
therefore no longer a blacklist of "fake" strings; it is a **positive pin**:
every technique ID and tactic name in the corpus must be a pinned-baseline
string, so a v19 successor entering ahead of the migration fails loudly.
Enforced by `test_corpus_strings_match_pinned_attack_baseline` in
`test_scenario_loader_v2.py`.

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

## Difficulty tier table

Marked **final** for `defense_evasion_log_clearing`: medium (difficulty 2).
The pending clarification that blocked Stage 2 is resolved.
