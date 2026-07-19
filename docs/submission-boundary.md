# The Submission Boundary (Phase 2 Stage 3.9A)

The single reference for how grading is gated behind a per-incident submission.
`backend/app.py` implements exactly this model; `test_submission_gate.py`
proves it end to end through the HTTP layer.

## The one rule

**The engine is complex. The game should not be.** Grading is served ONLY
across a submission boundary, from an immutable stored record.

The corpus already had strong leak guards, but they all protect a single axis:
FIELDS. The answer key, the `status`/`actions_reviewed` markers, and the raw
composite targets never serialize. Stage 3.9A adds the orthogonal guard on the
other axis: TIMING. No grade, disposition score, response score, composite,
pass/fail, or classification correctness is disclosed for an incident until
that incident has been submitted.

Guards protect fields; the boundary protects timing. Both are permanent.

## Scope (and what did NOT change)

Session-flow, presentation, and disclosure only. Explicitly unchanged:

- the scoring functions `compute_action_score`, `compute_detection_score`,
  `compute_composite_grade` (they are called once per incident at submit, over
  frozen inputs; their behavior is byte-identical to Stage 3d),
- schema v2, scenario content, world generation,
- the frozen revert boundaries (the v1 YAML loader, the legacy NDJSON loader).

New session state is limited to two kinds the ruling permits: immutable
submission records, and the active-incident UI context.

## Submit: the one boundary

`submit_incident(s, incident_id, payload)` — atomic under `session["io_lock"]`,
idempotent, confirmed on the client:

1. Resolve `incident_id` (an opaque `INC-####`, == the alert_id stamped at
   drip) to its internal `scenario_id` via `session["incident_index"]`.
2. Freeze this incident's inputs: the classification payload (verdict +
   category + optional report note), the detection dispositions on its
   scenario-tagged and ambient-benign detections, the successful response
   actions in scope, and the isolation end state.
3. Run the UNCHANGED `compute_*` scorers once over those frozen inputs to build
   the per-incident report card (classification / detection / response /
   composite).
4. Store the immutable record in `session["submissions"][incident_id]`, mark the
   raw events classified, resolve the queue entry, and append the post-boundary
   rows (`scenario_history` for pass/fail, `analyst_actions` for the Triage
   Review panel).

Because nothing recomputes a submitted incident against later session state, a
submitted grade is byte-identical on every subsequent read regardless of what
the player does afterward (proven by
`test_submission_is_idempotent_and_immutable`).

### New session state

| Key | Meaning |
|---|---|
| `submissions` | `incident_id -> immutable stored record` (inputs + report card) |
| `incident_index` | opaque client `INC-####` -> internal `scenario_id` |
| `assisted` | incident ids whose Guided-mode Check Answer was used |

All reset with the session (create / reset / start).

## Submission readiness (submit means "ready to be graded")

Because a submitted record is immutable, submit must mean the incident is ready
to be graded, so the record always carries a COMPLETE grade. Readiness uses only
observable player work; no answer-key information is ever consulted.

Two conditions, both required (`incident_submission_readiness`):

1. **The detection roster is sealed.** Detections are materialized synchronously
   at drip start (`build_attack_chain_logs`); the queue entry's
   `chain_complete_at` is stamped only when the chain has fully written. That
   monotonic marker is the seal: after it, every detection scoped to the
   incident is attached and the roster is fixed. While unsealed, submission is
   refused with neutral copy — "Incident telemetry is still loading." No new
   detection may attach to an incident after its submission record exists (the
   roster is fixed at seal, which precedes any submission, and the record
   snapshots the dispositions regardless).
2. **Every detection in the sealed roster is dispositioned** (promoted or
   dismissed). While any remain open, submission is refused with the observable
   count only — "N detections still need review." Never whether any disposition
   is correct.

The incident's roster is its authoritative server-side set (`_incident_detections`
= its scenario-tagged detections plus ambient-benign detections on its hosts),
NOT whatever the UI currently shows. Detections from other incidents never
affect readiness (per-incident scoping; a shared host's ambient benign is
dispositioned once and counts for every incident that scopes it). **Response
actions never gate submission** — a required-action count is hidden answer-key
information and must never be revealed.

`submit_incident` returns a discriminated dict: `unknown` (404), `sealing`
(409), `open_detections` with a count (409), `idempotent` (200), or `created`
(200). The grouped-alerts group carries observable readiness
(`detections_sealed`, `open_detections`, `submission_ready`) so the frontend can
block Submit before the round-trip; the backend enforces the same rule
authoritatively, so a stale client count still 409s.

Because readiness guarantees all detections are dispositioned and every scenario
is reviewed (so response always has a graded unit) and classification is always
supplied at submit, **all three components are graded at submit and the
composite is always a real grade, never `-`.**

## Classification enforcement

"Classification always supplied" is enforced server-side, never defaulted. Before
any record is created, `submit_incident` requires a valid classification
(`_valid_classification`): a verdict of `false_positive`, or `threat` with a
non-empty attack category. Absence or an unknown verdict is rejected with a
neutral 400 (`{"reason": "invalid_classification"}`) and NO record is created; a
defaulted verdict would silently grade a call the analyst never made. The order
inside `submit_incident` is: unknown (404) -> idempotent (200) -> invalid
classification (400) -> readiness sealing/open (409) -> created (200).

## The discriminated shape

Every session-wide grading surface and the per-incident score view return one of
two whitelisted shapes:

```jsonc
// no incident submitted yet
{ "state": "in_progress",
  "progress": { "submitted": 0, "detections_triaged": 0, "detections_open": 5,
                "actions_attempted": 0, "actions_executed": 0 } }

// at least one incident submitted
{ "state": "submitted",
  "grading": { "classification": {…}, "detection": {…}, "response": {…},
               "composite": {…}, … } }
```

The `progress` payload carries observable activity ONLY: submitted / triaged /
attempted counts. It never carries a required-action count or any
answer-key-derived total (`test_progress_shape_is_observable_activity_only`).
`"grading"` is structurally impossible while `state` is `in_progress`.

Gated endpoints: `/api/analytics/report_card`, `/api/analytics/action_score`,
`/api/analytics/detection_score`, `/api/incidents/<id>/score`. The
current-level pass/fail (`level_results`) reads only `scenario_history`, which
is written solely at submit, so it is gated by construction.

## Session aggregate

`aggregate_submitted(s)` pools the immutable stored records over SUBMITTED
incidents only. Each session component is the MACRO mean of the frozen
per-incident component accuracies. Because the response pricing (proportional
credit, absolute -20 collateral, inaction-zero) is applied once per incident
inside `compute_action_score`, the macro mean reproduces the Stage 3d baseline
convention exactly: response over all 20 scenarios is 30.0 for act-on-nothing
(six inaction scenarios at 100, fourteen attacks at 0). The composite is `-`
until all three components have graded units.

## Check Answer (Guided-mode only, allow-list)

`/api/incidents/<id>/check-answer` is the single, deliberate exception, and a
narrow one. It is gated by an **allow-list, never a deny-list**: available ONLY
when the session mode is in `GUIDED_MODES` (currently `{"training"}`), and
refused (403) in every other mode — Hardcore, Analyst, and any future SOC Queue
mode alike. So a mode added later is locked out by default, not accidentally
permitted. It reveals CLASSIFICATION correctness alone for the supplied
verdict/category WITHOUT submitting, in exchange for permanently marking the
incident Assisted. It never discloses detection, response, or composite grading,
and the eventual submission carries the assisted flag.

## Deprecated parallel paths

- The legacy `/api/resume` classify branch is now a non-revealing shim: it
  routes classification through `submit_incident` and returns no correctness
  before the boundary (the only post-boundary signal is the Hardcore failure,
  which the run reveals by design). Non-classify actions annotate event status.
- `/api/reports` (POST) files documentation only: it no longer resolves the
  queue, computes correctness, or stores the actual category (that would leak
  the answer key before submission).

## Frontend

- **Notable Events:** one unified **Submit** button per incident (verdict via
  ClassificationSelector, then a confirm dialog naming the incident with an
  optional report note) replaces the separate Classify and Report buttons. The
  triage-review reveal moved to AFTER submit.
- **Metrics:** submission-gated. `Analytics.jsx` renders an in-progress banner
  ("Grading appears once you submit an incident") with observable progress only
  until a grade exists, then flattens `report.grading` for the cards.
  `ScoreSections.jsx` reads `report.detection` / `report.response` and no longer
  polls the score endpoints. The Triage Review panel is empty until the first
  submission.

## Ratified amendment (3.9B): the Post-Incident Review content read

`GET /api/incidents/<id>/triage-review` (added for the 3.9B Incidents-workspace
Review) is retroactively ratified as the Post-Incident Review content amendment:
submitted-only (404 otherwise), post-boundary, serializing exactly the scenario's
triage-review educational content (`mitre`, `what_is_it`, `response_actions`)
with `scenario_label` stripped. It is the SINGLE Review-content source; it powers
the one Review surface in the Incidents workspace. The lock rule stands: future
features arrive as amendment requests before implementation, not after.

## Confirmed invariants (3.9A re-review)

Three invariants, each with a permanent test in `test_submission_gate.py`:

1. **Roster finality.** The sealed roster is fixed. Detections materialize once
   at drip start; a host is recorded in `benign_hosts` so no later drip
   re-attaches ambient benign to it; duplicate polling never regenerates the
   roster (reads never mutate `session["detections"]`); another incident's
   detections never enter this roster; and after submission the frozen record's
   detection set cannot change (a detection attached afterward, even one scoped
   to the same scenario and host, never alters the stored grade). Every
   sealed-roster detection is present in the `/api/detections` feed, so readiness
   can never demand a disposition the player cannot perform.
2. **Guided assistance.** Check Answer (Guided allow-list only) permanently marks
   the incident Assisted; the flag survives submission and an idempotent
   resubmission byte-identically, and rides on the immutable per-incident report
   (`assisted`). It reveals classification feedback only. An incident submitted
   without Check Answer reports `assisted: false`.
3. **Classification enforcement.** `submit_incident` requires a valid
   classification and rejects its absence with a neutral 400; no record is
   created without one (never defaulted).

## Closure records

- **The original incomplete `-` submission record** (the pre-correction Chrome
  run that submitted with Detection `-` / Composite `-`) is **moot by session
  lifecycle**: submissions are in-memory only, cleared on `reset-simulator` and
  discarded on process restart, and that session was both reset and its process
  restarted. With readiness now enforced, such an incomplete record can never be
  created again (proven by the readiness tests).
- **Blind re-verification mode:** the `defense_evasion_log_clearing` workflow ran
  in **Guided (Training)** mode; INC-9172's stored record is `assisted: false`
  (Check Answer was not used). Its per-incident grade was 100 / 100 / 100 / 100
  with a complete composite.

## Gate

`python backend/test_submission_gate.py` (also in `run_gates.py`). It asserts,
through the HTTP layer: no surface leaks before submission; the progress shape is
observable-only; grading appears only after submission and matches the stored
record; submissions are idempotent, and a submitted grade is byte-identical
under later cross-incident activity; open detections and an unsealed roster each
block submission (observable count / neutral copy only, no correctness);
completing every disposition enables submission and yields a complete composite;
the remaining count is incident-scoped and concurrent incidents have independent
readiness; an inaction-correct FP scenario reaches readiness and grades fully;
the sealed roster does not grow on poll or unrelated activity and every roster
detection is dispositionable; no detection attaches to a submitted incident;
Assisted survives submission and idempotent resubmission; a submit without a
valid classification is a neutral 400 that creates no record; Check Answer
reveals classification only, marks Assisted, and follows the Guided allow-list
(rejected in Hardcore AND Analyst); unknown incident ids are 404 everywhere.

## Presentation distinction (recorded for 3.9B)

Per-incident grade and session aggregate are different numbers and must be
labelled so they cannot be confused. In the blind run INC-9172's **Incident
Grade** was 100 / 100 / 100 / 100 (A), while the **Session Performance** was the
67.1% aggregate over all ten submitted incidents (the drained intermediates
dragged detection and response down). 3.9B's Incident Dashboard and the Metrics
view must label **Incident Grade** and **Session Performance** distinctly.

## Not in this stage

3.9B (Workflow Clarity: the Incident Dashboard, modes, and navigation) is a
separate checkpoint and was not started here.
