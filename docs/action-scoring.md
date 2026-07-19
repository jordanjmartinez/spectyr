# Response-Action Scoring (Stage 3b, amended by the 3c rulings)

The single reference for how response actions are scored, surfaced, or
rejected. `compute_action_score` (backend/app.py) implements exactly this
model; `test_action_scoring.py` proves it cell by cell.

## The grading model

- **Successful actions only.** The scorer consumes successful log entries.
  Everything else is score-neutral by construction.
- **Every answer-key action carries an explicit status** (`required` or
  `acceptable`; no default, authoring is deliberate):
  - `required`: earns credit; omission is a missing-action deduction.
  - `acceptable`: defensible but nonessential. No positive credit, never
    collateral, and excluded from the score denominator entirely, so
    omitting it never lowers the score. If executed, it is surfaced in
    the report as an acceptable response (factual wording, zero score
    impact).
  - Any successful action matching neither list is collateral.
- **Isolation grades on end-state** at scoring time. Required containment
  released before submission forfeits that credit; the forfeiture is the
  whole cost (no stacked reversal penalty). Re-isolating before
  submission restores it. An ACCEPTABLE isolation is score-neutral
  whether it remains active or is later released: the author explicitly
  approved it as defensible, so it never triggers the clean-host
  end-state penalty. Isolation matching neither list is collateral only
  while still in effect.
- **Kill / delete / identity / remove_persistence grade on occurrence**
  from successful log entries, matched on full composites: process =
  (host, PID), file = (host, normalized path), account = (domain,
  username), persistence = the correlated artifact identity (host +
  normalized namespace + filter path + consumer path for WMI; host +
  normalized reg key + value name for a Run key). The right PID, path, or
  persistence on the wrong host is a miss plus collateral, never credit.
- **Persistence dual-flag state model.** A persistence artifact carries a
  registration flag (removed by `remove_persistence`) and, when
  file-backed, a file flag (cleared by `delete_file` of its payload). Its
  Autoruns row survives until BOTH flags are neutralized (a
  registration-only WMI subscription is neutralized by registration
  alone). GENERAL RULE, enforced by this model: no acceptable action may
  render a required action unreachable. Because the row survives on the
  remaining flag, a required `delete_file` stays reachable after an
  acceptable `remove_persistence` and vice versa, under either ordering.
- **release_host is globally score-neutral.** Never credit, never
  collateral merely because it is absent from the answer key; it is
  absent from the answer-key grammar altogether. Its only scoring effect
  is indirect: releasing a host that must remain isolated forfeits the
  required isolation credit.
- **Order sensitivity only where declared** (`after` in the answer key,
  on required actions referencing required actions; loader-enforced).
  Comparison uses FIRST successful occurrence sequence numbers:
  occurrence, not credit, so releasing containment later does not
  retroactively invalidate an action correctly taken under it. An
  order-violated action loses its credit and counts in
  `order_violations`.
- **Accuracy — collateral pricing (owner ruling 2026-07-19).** Required
  credit is PROPORTIONAL to the required set; collateral harm is ABSOLUTE.
  "Credit is proportional to the job; harm is absolute."
  - For a scenario with one or more required actions:
    `base = required credit earned / total required credit * 100`
    (isolation end-state and declared `after` ordering are folded into the
    earned credit), then
    `final = max(0, base - 20 * successful_collateral_count)`.
    So one collateral costs a flat 20 points regardless of the required-set
    size (a `20/20`-priced mistake), never diluted by the denominator.
  - For a reviewed scenario with zero required actions (inaction-correct:
    the five FP scenarios and brute_force_attack): clean hands = 100; any
    successful collateral in its scope = 0 (the strict inaction contract,
    retained deliberately).
  - `required`/`correct` fold in the weight-1 inaction units, so a single
    scenario reduces to the per-scenario formula above and a multi-scenario
    session pools proportionally; `graded` is the proportional denominator
    (required + inaction units), NOT required + collateral. Acceptable,
    `failed_precondition`, and `no_op` stay neutral. Letter grade on the
    shared 10-point scale; `-` before anything is graded.
- **Loader guarantees:** duplicate expected actions are rejected, as is
  any action-target pair declared under both statuses. The status field
  is server-side answer-key data and never serializes (planted-marker
  leak test); unexecuted acceptable targets never surface.

## The tri-state grading marker (`answer_key.actions_reviewed`)

Server-side only; never serialized (leak-guard tested).

| Marker | actions | Meaning |
|---|---|---|
| absent / `false` | any | Not yet reviewed: the scenario is EXCLUDED from action scoring. It earns nothing, costs nothing, and targets it claims are out of grading scope. The Response section renders `-` until a reviewed scenario drips. |
| `true` | has required actions | Graded normally. |
| `true` | no required actions (`[]`, or acceptable-only) | Intentional correct inaction: the scenario contributes one graded unit, credited when no collateral lands in its scope; a hit costs both the collateral and the inaction credit. Executing an acceptable action never costs the unit. |

**Correct inaction is not exclusive to false positives.** A reviewed
ATTACK scenario may also have no required action when the environment
already contained the attack and no vocabulary action remains. The
canonical case is `brute_force_attack` (3c Batch 3): a failed external
brute force that the account lockout (4740) already contained, with no
breach and no expressible containment (blocking the source IP is out of
vocabulary). Its correct response is investigation plus an optional
acceptable hygiene reset on the locked account; both doing nothing and
performing only that reset score A/100 (proven by
test_brute_force_system_contained_scores_a_for_nothing_and_reset_only).
The lesson is not to over-react (isolating the DC or disabling the
account is collateral) to an attack the system already stopped.

Collateral scoping while the corpus review is in flight: a successful
unnecessary action is collateral only when its target is claimed by at
least one reviewed scenario and by NO unreviewed scenario. Shared targets
(infra hosts appearing in both) get the benefit of the doubt; the
ambiguity vanishes at the 3d all-reviewed gate. A shared-target collateral
hit costs every claiming reviewed inaction scenario its credit
(deterministic multi-attribution).

Each 3c scenario commit flips its scenario to `actions_reviewed: true`.
3d completion gate: all 20 reviewed; a close-out test asserts no
unreviewed scenario remains.

## The consolidated taxonomy: scored, surfaced, rejected

| Event | Fate |
|---|---|
| Successful REQUIRED action | Credit (per the model above); omission is a miss |
| Successful ACCEPTABLE action | Neutral; surfaced factually as an acceptable response; excluded from the denominator; never collateral |
| Successful action on neither list | Collateral penalty (any scenario, including FPs) |
| `release_host` success | Globally score-neutral; only indirect effect is forfeiting a required isolation's end-state credit |
| `failed_precondition` attempt | Score-neutral; surfaced FACTUALLY in the report's Response section as attempted actions that did not execute (count + entries, no editorial label); full detail in the Response Log |
| `no_op` repeat | Score-neutral; surfaced FACTUALLY (count + entries; the first success already carried whatever it earned or cost) |
| Malformed / foreign-session / stale / wrong-kind target | API rejection (identical 400 body; no cross-session existence leak), never logged, never scored |
| Required actions | Must be achievable from the initial scenario state (validator-enforced, seed-independent); the same bar applies to acceptable actions |

## Achievability (validator-enforced, seed-independent)

Every answer-key action, REQUIRED and ACCEPTABLE alike, must be
executable from the scenario's initial world state and resolve only to
authored sources. Enforced, not advisory: a scenario with
`actions_reviewed: true` failing achievability is a hard validation error,
same severity as a schema violation (`scenario_loader_v2.py`), and the
runtime harness re-proves it by executing every reviewed scenario's
required set against freshly built worlds across the fixed seed set
(`test_action_scoring.py`).

- isolate: target host declared online and a managed endpoint (PAN-OS
  devices can never be action targets)
- kill: (host, PID) is an authored artifact of this scenario
- delete: (host, path) is an authored deletable file (Sysmon
  image/parent_image or run-key autorun)
- identity: the account exists in the environment
- remove_persistence: the selector (`wmi:<ConsumerName>` or
  `run_key:<KeyPath\ValueName>`) resolves to an authored persistence
  artifact of this scenario, correlated the same way materialization does.
  A Run-key SetValue (Sysmon 13) or a COMPLETE WMI subscription (Sysmon
  19/20/21) qualifies; an incomplete or ambiguous subscription, or a
  seed-generated benign artifact, never does.
- `after` orderings are satisfiable (reference + cycle checks guarantee a
  topological order)

**Seed independence** is structural: answer-key targets may resolve only
to authored sources (attack chain, supplemental events, canonical
environment). Seed-generated noise never qualifies, so achievability and
grading are identical under every seed.

**Offline-host wrinkle:** permitted in at most 1-2 scenarios, and only as
a non-required element: a tempting-but-wrong containment target or a
factually surfaced failed attempt. It can never carry required-action
credit (the validator rejects a required isolate on a declared-offline
host).

## Report-card presentation (Stage 3d ruling: 40/30/30 composite headline)

The headline grade is a fixed composite: **40% classification + 30%
detection dispositions + 30% response actions** (owner ruling 2026-07-18,
Option C). `compute_composite_grade` combines the three components from
their UNROUNDED accuracies and rounds only the final composite (one
decimal); weights are fixed and never renormalized; the composite is '-'
until all three components have graded units. It is served on
`/api/analytics/report_card` as `composite` and is the headline ring in the
UI. Classification, Detections, and Response each still render as their own
scored section beneath the headline (with full details, misses, collateral,
acceptable actions, and failed attempts), so no weak component hides behind
the composite. Superseded the interim Option A side-by-side (3b checkpoint).

Verified exact cases (unrounded components): 100/100/100 = 100 A;
100/60/70 = 79 C; 60/100/100 = 84 B; 100/100/55 = 86.5 B;
100/66.7/6.2 = 61.9 D.

## Stage 3d full-corpus response baselines (measured, 20 x 5 seeds)

Deterministic action-score baselines, three strategies, before and after
the collateral-pricing ruling:

| Strategy | pre-ruling micro/macro | post-ruling micro/macro |
|---|---|---|
| Correct response | 100.0 / 100.0 | 100.0 / 100.0 |
| Act on nothing | 13.3 / 30.0 | 13.3 / 30.0 |
| Act on everything | 1.4 / 1.5 | 0.0 / 0.0 |

Both naive strategies score strictly below correct on micro AND macro under
both scorers. Act-on-nothing is unchanged (no collateral, so the pricing
never bites) and reproduces macro exactly 30.0 (100 on the six no-required
scenarios, 0 on the 14 attack scenarios). Act-on-everything drops to 0
under pricing (collateral penalties plus the inaction-scope zeroing). The
per-scenario single-collateral cost is now UNIFORM: exactly 20 points on
every attack scenario (independent of required-set size) and 100 (zeroed)
on every inaction scenario. See docs/stage-3-final-report.md for the full
run.

## Composite headline-grade options (Stage 3d — RULED: Option C, wired)

The options below were presented at the 3d checkpoint; the owner ruled
**Option C (40/30/30)**, now wired (see the section above). Kept for the
record of the trade-offs weighed.

Three sub-scores, each on the shared 10-point band, each A/100 for a
correct player: Classification, Detection, Response. No-required scenarios
contribute one inaction unit to Response (credited on clean hands); no
dimension is dropped/renormalized in practice (corpus density guarantees
all three are always present). Worked examples (C/D/R -> composite):

| Run (C/D/R) | B 50/25/25 | C 40/30/30 | D 60/20/20 |
|---|---|---|---|
| 100/100/100 | 100 A | 100 A | 100 A |
| 100/60/70 (weak triage) | 82.5 B | 79.0 C | 86.0 B |
| 60/100/100 (wrong class) | 80.0 B | 84.0 B | 76.0 C |
| 100/100/55 (over-responder) | 88.8 B | 86.5 B | 91.0 A |

- D under-penalizes collateral (over-responder still A); B cushions a wrong
  classification to B; C makes both failure modes cost a grade while
  keeping classification the largest single weight.
- **RULED: Option C (40/30/30)**, adopted and wired 2026-07-18. The
  decision was made at 3d and is not deferred again.
