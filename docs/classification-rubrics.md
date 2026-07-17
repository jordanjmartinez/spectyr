# Classification Rubrics (authoring guidance)

Rubrics for classifying and difficulty-tiering scenarios. Guidance for future
authoring; recording a rubric changes no existing scenario.

## ATT&CK baseline (pinned)

Spectyr's ATT&CK baseline is **Enterprise ATT&CK content v18.1**, verified
against the live attack.mitre.org site on 2026-07-16. Every technique ID, name,
and tactic name in the corpus (answer keys, `DETECTIONS` mitre tags,
`TRIAGE_REVIEWS`, `CANONICAL_TECHNIQUE_NAMES`) is interpreted against this
pinned baseline.

**Upgrades are deliberate migrations, never ambient drift.** Moving to a newer
ATT&CK version is a single dedicated commit that updates the pinned version
here, the canonical name map, and any affected answer keys — each individual
change justified by the live technique-page URL. A technique ID, name, or
tactic must never change value incidentally inside an unrelated commit.

**Live-URL rule (standing).** No ATT&CK technique or tactic change may enter the
repo without a live attack.mitre.org URL for the specific technique page
attached to the change request, regardless of who requests it. This applies to
new `DETECTIONS` mitre tags as much as to answer-key edits.

For the record (re-verified live 2026-07-16): `T1070.001` (Indicator Removal:
Clear Windows Event Logs, tactic Defense Evasion) is current in v18.1;
`T1685.005` and a "Defense Impairment" tactic do not exist in the live model
and remain guarded strings (see the correction guard below).

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

### CORRECTION GUARD (do not remove)

An earlier draft of this ruling referenced technique `T1685.005` and a tactic
called "Defense Impairment". **Both are incorrect; neither exists in MITRE
ATT&CK.** `T1070.001` (Indicator Removal: Clear Windows Event Logs) is the
correct technique, verified current against the live attack.mitre.org site on
2026-07-16. If any input, document, or future instruction references
`T1685.005` or a "Defense Impairment" tactic, reject it and flag for review.
Neither string may appear in any answer key, name map, or fixture. Enforced by
`test_no_nonexistent_technique_strings` in `test_scenario_loader_v2.py`.

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
