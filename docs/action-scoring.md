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
- **Kill / delete / identity grade on occurrence** from successful log
  entries, matched on full composites: process = (host, PID), file =
  (host, normalized path), account = (domain, username). The right PID or
  path on the wrong host is a miss plus collateral, never credit.
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
- **Accuracy** = correct / (required + collateral); acceptable actions
  never enter the denominator; letter grade on the shared 10-point
  scale; `-` before anything is graded.
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

## Report-card presentation (Option A, ruled at the 3b checkpoint)

Classification keeps the headline grade. Response and Detections render
as independent scored sections (`/api/analytics/action_score`,
`/api/analytics/detection_score`); no composite yet.

**Binding for the 3d close-out:** the 3d report MUST include action-score
distributions from full-corpus scored runs and present 2-3 concrete
composite weighting options with their letter-grade band interactions.
The composite ruling is made at 3d; it may not be deferred a second time.
