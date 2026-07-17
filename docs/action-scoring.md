# Response-Action Scoring (Stage 3b, amended by the 3c rulings)

The single reference for how response actions are scored, surfaced, or
rejected. `compute_action_score` (backend/app.py) implements exactly this
model; `test_action_scoring.py` proves it cell by cell.

## The grading model

- **Successful actions only.** The scorer consumes successful log entries.
  Everything else is score-neutral by construction.
- **Isolation grades on end-state** at scoring time. Required containment
  released before submission forfeits that credit; the forfeiture is the
  whole cost (no stacked reversal penalty). Re-isolating before
  submission restores it. Clean-host isolation is collateral only while
  still in effect.
- **Kill / delete / identity grade on occurrence** from successful log
  entries, matched on full composites: process = (host, PID), file =
  (host, normalized path), account = (domain, username). The right PID or
  path on the wrong host is a miss plus collateral, never credit.
- **release_host is a rollback control.** Never credit, never collateral,
  absent from the answer-key grammar.
- **Order sensitivity only where declared** (`after` in the answer key).
  Comparison uses FIRST successful occurrence sequence numbers:
  occurrence, not credit, so releasing containment later does not
  retroactively invalidate an action correctly taken under it. An
  order-violated action loses its credit and counts in
  `order_violations`.
- **Accuracy** = correct / (required + collateral); letter grade on the
  shared 10-point scale; `-` before anything is graded.

## The tri-state grading marker (`answer_key.actions_reviewed`)

Server-side only; never serialized (leak-guard tested).

| Marker | actions | Meaning |
|---|---|---|
| absent / `false` | any | Not yet reviewed: the scenario is EXCLUDED from action scoring. It earns nothing, costs nothing, and targets it claims are out of grading scope. The Response section renders `-` until a reviewed scenario drips. |
| `true` | non-empty | Graded normally. |
| `true` | `[]` | Intentional correct inaction (the FP contract): the scenario contributes one graded unit, credited when no collateral lands in its scope; a hit costs both the collateral and the inaction credit. |

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
| Successful required action | Credit (per the model above) |
| Successful unnecessary action | Collateral penalty (any scenario, including FPs) |
| `failed_precondition` attempt | Score-neutral; surfaced FACTUALLY in the report's Response section as attempted actions that did not execute (count + entries, no editorial label); full detail in the Response Log |
| `no_op` repeat | Score-neutral, not surfaced in the report (the first success already carried whatever it earned or cost) |
| Malformed / foreign-session / stale / wrong-kind target | API rejection (identical 400 body; no cross-session existence leak), never logged, never scored |

## Achievability (validator-enforced, seed-independent)

Every required answer-key action must be executable from the scenario's
initial world state. Enforced, not advisory: a scenario with
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
