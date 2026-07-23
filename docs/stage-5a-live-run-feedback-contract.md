# Stage 5A Contract — Live Run Feedback, Teaching, and Player Trust

**Status: DRAFT for owner and reviewer review. Not locked. No implementation
scaffold exists; no product code lands from this document until the contract
is locked and its scaffold is separately approved (scaffold -> approve ->
implement, the standing cadence).**

**Repository baseline:** `main` at `a204995` ("Pre-Stage-5 hotfix closure:
merge one-shared-incident-roster fix (57368f5..2e52dcb)"); merged-main gates
ALL GREEN (backend 27 suites; frontend 17 suites / 164 tests). Branch:
`stage-5a-live-run-feedback-contract`. Repository claims in this contract
cite `path:line` at this baseline.

Decision markers, matching the Stage 4A convention: **[Ratified]** (an
inherited recorded ruling), **[Recommendation]** (this contract's proposal,
requiring the owner's lock to become binding), **[Owner Decision]** (open —
enumerated in Section 21), **[Deferred]**.

---

## 1. Executive summary

Stage 4 made the investigation workflow *functional*: a real query language,
frozen snapshots, pivots, descent, and a submission boundary that never leaks
grading. The first real playthrough showed it is not yet *understandable*:
the game frequently fails to tell the player what just happened, what counts
as progress, why their view changed, where they are inside the investigation,
and — after submission — what they did right, what they missed, and what they
should not have done.

Stage 5A is the contract for the feedback, teaching, and trust layer over the
unchanged engine. Its six workstreams:

- **5.1 Post-Incident Review teaching layer** — after submission, the review
  must answer: What did I do correctly? What should I have done but missed?
  What did I do that was unnecessary or harmful? And why? Today it shows four
  component grades and a technique explainer; the response breakdown
  serializes counts with no identities (Section 7).
- **5.2 Pivot and scope-transition clarity** — a pivot must name the clue it
  followed and the scope transition it made, keep the origin visible, and
  explain itself on first use (Section 8).
- **5.3 SIEM selection and inspector continuity** — selecting a result row
  must feel connected to the inspector that opens (Section 9).
- **5.4 Neutral progress and state clarity** — one observable, answer-free
  vocabulary for triage/response/readiness progress on every surface,
  resolving the transient "0 of 0 reviewed" defect (Section 10).
- **5.5 First-run Guided onboarding** — a dismissible, contextual, Guided-only
  explanation of the concepts the first playthrough stumbled on (Section 12).
- **5.6 Investigation context and scope truth** — one source of truth for
  "current case" and "data scope"; the F9 contradictory-signals defect is
  diagnosed to its root cause in this contract (Section 11).

Scope discipline: presentation, disclosure-timing, and teaching content only.
No scoring function, weight, readiness rule, roster semantics, LCQL grammar,
snapshot/token semantics, or submission-record grading changes — with one
narrow, explicitly surfaced exception class: *post-submission* serialization
of answer-bearing content for the submitted incident only, which inherited
boundary 3 permits and Section 7 specifies. Every open product choice is in
the Section 21 owner decision register, not silently made.

---

## 2. Problem statement

The engine is complex. The game should not be. The Stage 3.9/4 engine is
correct and guarded, but its player-facing explanations stop at the level a
reviewer needs, not the level a first-time player needs. The owner's first
real playthrough (the primary product evidence, Section 3) surfaced seven
recurring failures:

1. The game does not say **what just happened** (a pivot silently rewrites
   the query and scope; a submission reveals grades without a debrief).
2. It does not say **what counts as progress** (what "reviewed" means,
   whether Promote/Dismiss/Reopen/response actions advance anything, what
   must happen before Submit).
3. It does not say **why the view changed** (Incident scope became
   Session-wide; results changed; the followed clue is never named).
4. It does not say **where the player is** (focused incident vs data scope
   vs pivot origin vs timeline mode vs which query produced the rows).
5. After submission it does not say **what the player did correctly**.
6. It does not say **what the player missed** (two missed required responses
   were invisible in the review).
7. It does not say **what was unnecessary or harmful** (four collateral
   actions appeared only as a count).

Stage 5 must make the game understandable **without revealing answers before
submission**. The disclosure-timing boundary (Stage 3.9A) and the field
boundary (the leak-guard suites) are non-negotiable; everything in this
contract is designed inside them.

---

## 3. First-playthrough evidence, verified against the repository

Each finding was re-diagnosed against the code at baseline `a204995`. Where
the finding named a suspected defect, the root cause is identified here.

### F1 — submission roster mismatch (FIXED, inherited invariant)

Fixed and merged before this stage (diagnosis `57368f5`, fix `3b97a89`,
report `75ff960`, closure `2e52dcb`, merge `a204995`). The standing invariant
is inherited unchanged and this contract must not reopen roster semantics:

> displayed incident roster == readiness roster == submission roster ==
> grading roster == immutable-record roster

The shared roster is the incident's scenario-tagged detections plus ambient
detections on its **observable participant hosts** only
(`_incident_roster`, app.py:3358). Environment-declared but never-observable
hosts add nothing; ambient detections on observable hosts still gate
readiness. Guards: `test_incident_scope.py`, `test_submission_gate.py`,
`test_incident_roster_corpus.py` (all in `run_gates.py`). Every progress
count Stage 5A touches MUST read this shared derivation (Section 10).

### F2 — Post-Incident Review does not teach (verified gap)

Repository truth of the current review path:

- The response section of the immutable record serializes **counts only**:
  `{required, correct, missed, collateral, order_violations, graded,
  accuracy, grade}` (`compute_action_score`, app.py:4425-4437) plus three
  factual entry lists added by `_incident_report_card` (app.py:3423-3431):
  `acceptable_taken`, `not_executed`, `no_effect` — each entry a sanitized
  action-log row. **Nothing identifies which required actions were missed or
  which executed actions were collateral.** Expected composites never
  serialize (the pre-submission leak rule, applied unconditionally — even
  after submission).
- The Post-Incident Review modal (`Incidents.jsx:379-416`) renders the four
  component grade rows, the composite, and the triage review's
  `what_is_it` + `mitre` blocks. It does **not** render the
  `response_actions` playbook list that
  `GET /api/incidents/<id>/triage-review` (app.py:4611-4628) already serves
  — generic teaching text that exists server-side today is dropped on the
  floor by the UI.
- The Metrics tab's `ScoreSections.jsx` shows the same counts
  session-aggregated, with the same three factual blocks, and the same
  absence of missed/collateral identities.

So the observed run ("3 required, 1 correct, 2 missed, 4 collateral; only
the one correct response visible") is exactly what the code produces. The
teaching outcome (correct / missed / unnecessary-or-harmful, each with a
why) requires a new post-boundary, per-submitted-incident data contract
(Section 7) — the only place in Stage 5A where answer-bearing content
serializes, and only after submission, only for that incident.

### F3 — pivoting is confusing (verified gap)

`Siem.jsx:224-231` (`pivotAndRun`): a pivot generates the query, sets scope
to `session`, and executes. The scope control visibly flips and the
generated LCQL lands in the bar (both deliberate Stage 4 behaviors), but
**nothing names the followed clue or announces the transition**; only
descent and surrounding-events render a banner (`Siem.jsx:552-583`). The
return chip ("Back to INC-####", `Siem.jsx:437-447`) exists but its
relationship to the pivot is unexplained. There is no first-use
explanation of what Pivot means. Section 8 specifies the fix.

### F4 — row selection feels disconnected from the inspector (verified gap)

One shared `EventInspector` renders **below** the full results pane
(`Siem.jsx:651-657`). `SiemTable` highlights the selected row with a subtle
background (`SiemTable.jsx:190-192`) and rotates a chevron that visually
promises inline expansion which never happens (`SiemTable.jsx:196-203`);
`SiemCards` uses a clearer ring highlight (`SiemCards.jsx:90-92`). Nothing
scrolls the inspector into view (the only scroll-into-view is the
surrounding-events focus row). On a 20-row table page the inspector opens
off-viewport. Selection DOES persist across Cards/Table switches and client
sorting (shell-owned, id-keyed, `Siem.jsx:53`). Section 9 compares the two
remedies and recommends one.

### F5 — triage and response progress are unclear (verified copy inventory)

The established meanings are all repository truth: Promote and Dismiss both
count as reviewed (`triaged` counts `player_action != 'open'`,
app.py:3917-3918); Reopen returns a detection to unresolved
(`set_detection_disposition`, app.py:3018-3033); response actions never
review detections and never gate submission (app.py readiness; CLAUDE.md);
Threats shows promoted detections only (`Detections.jsx:193`); Feed shows
all. The current copy is scattered and partially misleading — full surface
inventory in Section 10, including the phase strip's "Respond N related"
count, which is derived by fuzzy substring matching of action-log labels
against scope hosts/accounts (`Incidents.jsx:84-88`), not by a principled
join.

### F6 — `==`, `!=`, and Pivot needed explanation (accepted symbols)

The player accepted the symbols; they are not renamed. Current state:
`==`/`!=` buttons carry aria-labels but no meaning explanation
(`EventInspector.jsx:100-133`); the pivot button already carries a title
tooltip ("Pivot: <label> (runs Session-wide)"). Definitions to teach
(Sections 8, 12): `==` adds an equality filter to the current query; `!=`
excludes that value; Pivot makes the selected clue the new investigation
focus.

### F7 — Stage 5 backlog items (classified, per the required scheme)

1. **`false_positive_robocopy` IP in the hostname field — CONTENT DEFECT.**
   Root cause found: `backend/scenarios/v2/false_positive_robocopy.yaml`
   attack step `s2` authors `hostname: '{infra.file.ip}'` (resolving to
   `10.0.1.201`), so an IP string enters the observable host set (and the
   Related-hosts line, endpoint pivots, and descent host anchors).
   **[Recommendation]** venue: a **separate content micro-fix** before
   Stage 5B — a one-line YAML correction to `{infra.file.hostname}` through
   the standing correction-registry + parity-divergence process
   (`scenario_corrections.py`), because it touches frozen scenario content
   (v1/v2 parity) and no Stage 5 presentation work depends on it. It is NOT
   folded into any 5A workstream. [Owner Decision 10]
2. **Transient "0 of 0 reviewed" on a completed incident — PRESENTATION
   DEFECT.** Root cause found: completed cards from `/api/incidents` carry
   `incident_grade` but no `triage` field (app.py:3959-3963), and
   `Incidents.jsx:240` renders the phase strip for submitted incidents with
   `sealed` forced true, so `PhaseStrip` falls back to
   `{total: 0, triaged: 0}` (`Incidents.jsx:21`) — displaying "Triage 0 of 0
   reviewed … Submit pending" on a submitted incident. Frontend-only; the
   scope API serves correct post-submit counts. **[Recommendation]** venue:
   resolved **inside workstream 5.4** (it is precisely a progress-state
   presentation defect and its fix must use the same completed-state
   vocabulary 5.4 defines), not a separate micro-fix. [Owner Decision 11]

### F8 — investigation context is hard to follow (verified layering)

Three *independent* context layers exist, each with its own state and none
aware of the others:

| Layer | State owner | Surface |
|---|---|---|
| Focused incident ("current case") | `Dashboard.jsx:24` `activeIncidentId` | Global banner "Focused on incident INC-####" on every non-dashboard tab (`Dashboard.jsx:303-313`) |
| SIEM data scope + pivot origin | `Siem.jsx:50` `scope` state machine, `Siem.jsx:69` `lastIncident`, `Siem.jsx:75` `timeline` | Scope select, scope chip, return chip, descent/surrounding banner |
| Detections/Endpoints data scope | `Detections.jsx:101-102` / `Endpoints.jsx:64-65` (`scopeIds`/`scopeHosts` + `scoped`) | Per-tab scope label + This-incident/Session-wide toggle |

Verified consequences: the header can honestly show one focused incident
while the SIEM scope is Session-wide (two different concepts, never labeled
as such); the return chip can name a different incident than the focus
banner (it tracks the last SIEM-scoped incident, `Siem.jsx:105`, which is
legitimate provenance but unexplained); the query bar's editable text can
diverge from the executed snapshot (the snapshot status line does echo the
executed canonical query, `Siem.jsx:526` — a partial existing answer); and
on a parse failure the prior snapshot remains displayed with the error shown
but **no statement that the visible rows belong to the previous successful
query** (`Siem.jsx:509-517`; the snapshot object is deliberately preserved).
Section 11 defines the Investigation Context summary and the labeling that
separates "current case" from "data scope".

### F9 — scope controls and labels contradict each other (ROOT CAUSE FOUND)

**This is a real presentation-state defect, not just unclear wording.** In
both `Detections.jsx` and `Endpoints.jsx`:

- The **toggle highlight** reads the raw preference `scoped`
  (`Detections.jsx:218-224`, `Endpoints.jsx:145-152`).
- The **label** and the **row filter** read the derived
  `scopeActive = !!(activeIncidentId && scoped && scopeIds)`
  (`Detections.jsx:192-194,213-215`; `Endpoints.jsx:103-105,140-142`).

When the one-shot scope fetch has not resolved (in flight) or failed
(`.catch` sets `scopeIds = null`, `Detections.jsx:130`), `scoped` is still
`true`: the "This incident" button renders selected while the label says
"Session-wide view" and the rows are unfiltered. Combined with the *global*
focus banner (a third signal from a different state owner, F8), the player
sees exactly the reported contradiction. Classification under the F7 scheme:

- **Stale label:** no — the label is consistent with the data.
- **Wrong toggle highlight state:** YES — the highlight reads a different
  derivation than label + data.
- **Data filtered by a different scope than the controls show:** YES, in the
  window where the highlight disagrees (data follows the label, both
  disagree with the control), and additionally the scoped filter can go
  **stale**: `scopeIds`/`scopeHosts` are fetched once per incident selection
  (`Detections.jsx:124-132`, `Endpoints.jsx:92-100`) and never re-polled, so
  a pre-seal roster that grows after the fetch is filtered against an old
  id set until the incident is re-selected or reset.
- **A transient loading/race state:** YES — the in-flight window is the
  guaranteed reproduction; the fetch-failure case makes it persistent.

**[Recommendation]** Because the defect misrepresents which data the player
is looking at (a trust defect of exactly the class the hotfix just closed on
the server side), fix it as a **separate pre-5B presentation micro-fix**
(derive all three signals from one state value + explicit loading/error
presentation, plus scope re-fetch on the existing poll cadence), with the
full single-source-of-truth architecture landing in workstream 5.6. The
micro-fix is small, testable, and should not wait for the 5.6 design.
[Owner Decision 16]

---

## 4. Current repository inventory

### 4.1 Backend surfaces relevant to Stage 5A

| Surface | Repository truth |
|---|---|
| Submission record | `session["submissions"][id]` = `{incident_id, assisted, submitted_at, inputs: {classification {verdict, category, report}, detection_dispositions {det_id: action}, action_seq_cutoff, isolation_end_state}, report_card}` (app.py:3543-3556). Immutable; byte-identical reads. |
| Per-incident report card | `report_card` = `{classification, detection, response, composite, _response_raw, _inaction_collateral}` (app.py:3439-3447); leading-underscore keys stripped at serialization (app.py:3647-3649). |
| Response section fields | counts + grade (app.py:4425-4437) + `acceptable_taken` / `not_executed` / `no_effect` `{count, entries}` blocks of sanitized log rows (app.py:3423-3431). No missed/collateral identities. |
| Expected actions | `session["expected_actions"]` materialized composites per drip: `{scenario_id, eid, action, status, target composite, after}` (`materialize_expected_actions`, app.py:2340). Server-side only; never serialized anywhere today. Append-only per drip; an incident's set is fixed once dripped. |
| Response log | `GET /api/actions` = every attempt, sanitized `{seq, timestamp, action, outcome, reason, target {id, kind, label}}` (app.py:3110-3117; `sanitize_action_entry`, action_overlay.py:485-498). |
| Readiness / progress | `incident_submission_readiness` (app.py) and `_incident_progress` (app.py:3641-3661) — both consume the shared `_incident_roster`. Progress = observable counts only. |
| Incident cards | `/api/incidents`: active sealed cards carry `triage {total, triaged}`, `open_detections`, `ready`; completed cards carry `incident_grade` + `assisted` and **no triage** (app.py:3951-3974). Plus `stats.severity_breakdown`. |
| Incident scope | `/api/incidents/<id>/scope`: `{incident_id, sealed, hosts, accounts, detection_ids, triage?}` (app.py:4112-4134); observable-only; structurally guarded. |
| Post-Incident Review content | `/api/incidents/<id>/triage-review`: submitted-only 404 gate; serializes the scenario's `mitre`, `what_is_it`, `response_actions`, label stripped (app.py:4611-4628). |
| Check Answer | Guided allow-list; classification correctness only; marks Assisted (app.py:4137+). |
| Guided catalog / intake | `/api/guided-catalog` answer-neutral picker; `build_guided_queue` single-incident run (app.py:4070). |
| Score endpoints | `/api/incidents/<id>/score`, `/api/analytics/report_card` / `action_score` / `detection_score` — discriminated `{state, progress|grading}` shapes, submission-gated. |

### 4.2 Frontend surfaces relevant to Stage 5A

| Component | Role and Stage 5A-relevant state |
|---|---|
| `Dashboard.jsx` | Tab shell; global `activeIncidentId` focus + banner; `descentRequest` plumbing; mode/reset/practice-another flows. |
| `Incidents.jsx` | Workspace: Active/Ready/Completed views; `PhaseStrip` (Triage "X of Y reviewed" / Investigate / Respond "N related" / Submit ready-pending); readiness copy ("N detections still need review.", "Incident telemetry is still loading."); Submit -> classifier -> confirm; Check Answer; Post-Incident Review modal (grades + what_is_it only); Practice Another warning; fuzzy Related-response matching (`:84-88`). |
| `Detections.jsx` | Feed/Threats/Response Log toggle; scope toggle + one-shot `scopeIds` fetch (F9); "N open · N promoted · N dismissed" line; Promote/Dismiss/Reopen; identity response actions on Threats. |
| `DetectionDetail.jsx` | Rule-evidence trigger cards; Open Evidence Timeline (entity-anchored); triage buttons. |
| `Endpoints.jsx` | List + one-shot `scopeHosts` scope filter (F9); Isolate/Release in detail. |
| `Siem.jsx` | Workbench shell: query text vs executed snapshot; scope state machine (loading/ready/error, no silent fallback); return chip (`lastIncident`); descent/surrounding `timeline` banner; new-count indicator + stale de-emphasis; parse-error box (no stale-results statement); snapshot status line (echoes executed canonical query). |
| `SiemTable.jsx` / `SiemCards.jsx` | Frozen-row renderers; pagination; client sort (table); subtle row highlight + misleading chevron (table) / ring highlight (cards); surrounding-focus scroll centering exists for the focus row only. |
| `EventInspector.jsx` | One shared lens below results; ==/!=/pivot per-field actions; Surrounding events; no scroll-into-view on selection. |
| `FieldSidebar.jsx` | Snapshot-scoped top values; value clicks -> refine. |
| `IncidentDashboard.jsx` | Overview; distinct Session Performance labeling; "N to review" copy on active rows. |
| `Analytics.jsx` + `ScoreSections.jsx` + `AnalystReportCard`/`PerformanceGrade`/`CampaignProgress`/`ActionHistory` | Metrics: submission-gated report card; in-progress banner with observable counts; response section counts + factual blocks; Triage Review panel (post-submit classify history). |
| `DifficultySelector.jsx` | Mode picker + Guided catalog; no onboarding/first-run machinery exists anywhere. |

### 4.3 What already exists that Stage 5A builds on (not from scratch)

- The snapshot status line already names the executed query (F8's "Results
  from" requirement is partially built, unlabeled).
- Descent and surrounding-events already have origin banners with a
  self-consistency guard (banner renders only while the displayed snapshot
  is the timeline's own query, `Siem.jsx:352-353`) — the pattern Section 8
  generalizes to entity pivots.
- The triage-review endpoint already serves per-scenario response playbook
  text (`response_actions`) that the review UI never renders.
- The scope-error state machine (chip retained, Run disabled, no silent
  fallback) is the designed pattern 5.6's atomicity requirement extends to
  Detections/Endpoints.

---

## 5. Inherited invariants and forbidden behaviors

Binding, inherited, and not reopened by this contract:

1. **No correctness disclosure before submission** (timing axis, 3.9A) —
   including no answer-key-derived totals; required-action counts are hidden
   answer-key information and never gate or serialize pre-submission.
2. **Submitted records remain immutable** — byte-identical on every read.
3. **Post-submission review may reveal answer-bearing information only for
   the submitted incident** (the ratified triage-review amendment is the
   precedent and the venue pattern).
4. **One-shared-roster invariant** (F1) — every count from `_incident_roster`.
5. **Incident scope remains observable-only** — structural guards extend to
   any new reader.
6. **No hidden scenario/expected-action/grading inputs shape pre-submission
   UI** — the structural no-answer-key guard technique applies to every new
   pre-submission read.
7. **Guided may teach; Hardcore must not receive tutorial interruptions** —
   mode gating by allow-list, never deny-list (the GUIDED_MODES pattern).
8. **Response actions remain distinct from detection review** — they never
   review detections and never gate submission.
9. **No redesign of scoring weights or readiness rules** absent an explicit
   approved amendment (40/30/30 composite, collateral pricing, readiness
   conditions all frozen).
10. **Stage 4 SIEM query/snapshot/scope/pivot/descent behavior remains
    functionally intact** — Stage 5A changes presentation around them, not
    their semantics; no LCQL changes, no client-side query execution.

Additional standing rules that bind implementation: scaffold -> approve ->
implement; concern-level gate-green commits (never-land-red,
`run_gates.py`); every serialized-field and endpoint change disclosed;
deviation-flagging rule; em-dash frontend copy scan; the recorded UI
restraint rules (chrome on charcoal `#101218`, `#16436b` INC-link as the
only accent, color reserved for severity meaning; minimal error treatments).

---

## 6. Proposed player journey (Guided, first run)

1. **Start.** Pick Guided, pick a scenario. On first entering the Incidents
   workspace, a dismissible first-run explainer (5.5) introduces: incidents
   arrive as telemetry loads; the phase strip is your map; "reviewed" means
   every detection Promoted or Dismissed.
2. **Triage.** The Detections tab shows the incident-scoped feed with the
   scope truthfully labeled (5.6): "Current case: INC-8541 · Data scope:
   This incident". First-run subcopy explains Feed vs Threats and
   Promote/Dismiss/Reopen (5.5). Progress copy everywhere uses one
   vocabulary (5.4): "Detections reviewed: 4 of 5 — 1 still needs Promote
   or Dismiss."
3. **Investigate.** Open Evidence Timeline descends into the SIEM with the
   origin banner (existing). Selecting a row visibly connects to the
   inspector (5.3). Clicking `==`/`!=`/Pivot shows first-use hints (5.5);
   a pivot announces itself (5.2): "Following clue: user_account =
   "ACME\dpark" — scope changed to Session-wide. Back to INC-8541 is one
   click." The Investigation Context summary (5.6) persistently shows
   current case / data scope / followed clue / view mode / the query that
   produced the snapshot.
4. **Respond.** Response actions log visibly ("Response actions taken: 6",
   5.4) with no correctness signal.
5. **Submit.** Readiness copy is observable-only (unchanged rules). Submit
   locks the classification and opens the enriched Post-Incident Review.
6. **Learn.** The review (5.1) answers, for this incident only: what you did
   correctly (completed required actions and correct dispositions), what you
   missed (each missed required action, named), what was unnecessary or
   harmful (each collateral action taken, named), each with a short why, the
   technique explainer, and the response playbook. The Incident Grade is
   unchanged; the teaching wraps it.
7. **Repeat.** Practice Another; the first-run explainers do not reappear
   (persistence per 5.5); Hardcore runs never see any of them.

---

## 7. Post-Incident Review data and UI contract (workstream 5.1)

### 7.1 The teaching payload (new, post-boundary, per submitted incident)

A new server-computed **response breakdown** for a SUBMITTED incident,
answering the three acceptance questions with identities, not counts:

```
"response_review": {
  "completed":  [ { "action", "target_label", "why" } ],   // required, achieved (incl. order-ok)
  "missed":     [ { "action", "target_label", "why" } ],   // required, not achieved (or order-violated, flagged)
  "collateral": [ { "action", "target_label", "why" } ],   // successful, matched neither list, in scope
  "acceptable": [ { "action", "target_label", "why" } ],   // executed acceptable (existing acceptable_taken, enriched)
  "not_executed": [...], "no_effect": [...],               // existing factual blocks, unchanged
  "inaction": { "expected": bool, "clean": bool, "why" }   // for no-required scenarios
}
```

plus a **detection breakdown**: for each roster detection (ids from the
frozen `inputs.detection_dispositions`), `{rule_name, entity_label,
your_call, correct: bool}` — the per-detection disposition correctness the
record already implies (`compute_detection_score` consumes
`disposition` x `player_action`; correctness per detection is
`promote==TP / dismiss==FP / dismiss==benign`).

Rules:

- **Join semantics** (from the scorer, reused not reimplemented): required
  and acceptable match on `(action, full composite target)`; occurrence =
  FIRST successful log entry (duplicates collapse to one credited
  occurrence; later repeats are `no_op` and stay in the factual block);
  isolation completed-ness is END-STATE (a released required isolation lists
  under `missed` with a why naming the release); order-violated actions list
  under `missed` flagged `out of order`. Target labels use the registry's
  existing display labels (`target_label`, action_overlay.py:441-459) and
  for missed actions a server-rendered label from the expected composite in
  the same display grammar (host name; "name (PID n) on host"; file path on
  host; DOMAIN\user; persistence entry on host).
- **Shared actions across incidents:** one successful action can appear in
  several submitted incidents' breakdowns (completed in one, collateral in
  another) — each incident's review describes that incident's scope,
  factually; the entry's `why` names the scope relationship. No
  cross-incident deduplication.
- **Empty states**, each with designed copy: no response required (the
  inaction block: "No response action was required. Correct response here
  was investigation without action." / with collateral: "…but N actions
  landed in this incident's scope"); all correct; no actions taken (missed
  list only); no collateral.
- **Loading/error states:** the review modal already fetches score +
  triage-review; the breakdown rides the same fetch pattern; a failed fetch
  renders the existing grade rows with a one-line "The detailed breakdown
  could not be loaded" and a retry.

### 7.2 Where the breakdown is computed and stored [Owner Decision 2]

Two implementable options, surfaced not decided:

- **Option A — computed at submit, stored in the immutable record.** The
  breakdown becomes part of `report_card` (or a sibling record field) at
  `submit_incident` time. Byte-identical reads for free; but it **adds
  fields to the submission-record schema**, which is a frozen boundary that
  only an explicit owner approval may cross (this decision is that request).
- **Option B — derived at read time from frozen inputs.** A pure function of
  (the immutable record's `inputs`, the incident's expected-action
  composites, the action log truncated at `inputs.action_seq_cutoff`).
  Deterministic because expected actions are fixed at drip and the log is
  append-only with the cutoff frozen; no record-schema change; but
  byte-identity now rests on a derivation invariant instead of storage, and
  that invariant needs its own permanent test.

**[Recommendation]** Option A. The record is the product's "what you were
graded on" artifact; teaching content about that grading belongs in it, and
the schema change is small, additive, and disclosed. Serving venue: extend
`GET /api/incidents/<id>/score`'s submitted `grading` (already the review's
data source, already submitted-gated) rather than minting a new endpoint —
one boundary, one gate. [Owner Decision 2 covers both the storage and the
venue.]

### 7.3 Rationale content ("why") [Owner Decisions 1, 3, 4]

Measured authoring baseline (Section 14): 39 required + 20 acceptable = 59
authored answer-key actions; no rationale-like field exists anywhere in
schema v2; 106 generic per-scenario playbook steps already exist
(`triage_review.response_actions`). Three content tiers:

- **Tier 1 — deterministic generic rationale (zero authoring).** Server
  templates per (verb, status, outcome-class), e.g. missed required
  isolate: "This host was the compromise's foothold; isolating it cuts the
  attacker's access while you investigate." — generic per verb, composed
  with the target label. Collateral why is likewise deterministic: "This
  target was not implicated by the evidence; acting on it disrupted a clean
  asset." ~10 templates total.
- **Tier 2 — scenario-level rationale (moderate authoring).** One authored
  "expected response and why" paragraph per scenario (~20 entries; the 6
  inaction scenarios need the "why nothing" lesson — `brute_force_attack`'s
  is already written in docs/action-scoring.md), plus rendering the existing
  `response_actions` playbook in the review.
- **Tier 3 — full per-action rationale (highest fidelity).** One authored
  `why` per answer-key action: **59 new entries**, plus the ~10 generic
  templates for collateral (collateral targets are unbounded; per-action
  authoring cannot enumerate them).

**[Recommendation]** Ship Tier 1 + Tier 2 in Stage 5: render the existing
playbook (free), author the ~20 scenario paragraphs, use deterministic
per-action templates — and defer Tier 3 unless the owner wants per-action
voice. Where rationale content lives [Owner Decision 3]: **[Recommendation]**
scenario YAML for the scenario-level paragraph (schema v2 addition,
loader-validated, review-gated like all content) and code constants for the
generic verb templates (engine voice, not per-scenario content). Collateral
explanations [Owner Decision 4]: **[Recommendation]** deterministic generic
rules (Tier 1), since the target space is unbounded.

### 7.4 Answer-key boundary and guards

- Nothing in 7.1 serializes before submission, for any incident, on any
  surface; the breakdown exists only inside the submitted branch of the
  discriminated shape.
- Foreign/unknown/unsubmitted incident ids: the existing 404 gates hold; new
  permanent tests prove the breakdown is absent for unsubmitted incidents
  and unreachable cross-session.
- The planted-marker technique extends: plant a marker in an expected-action
  composite and in a rationale string; assert absence from every
  pre-submission payload (progress shapes, cards, scope, detections, query
  reads) and presence only in the submitted incident's own review.
- The structural no-answer-key guard extends to every pre-submission reader
  touched in 5A; the review renderer is post-boundary by construction.
- Guided Check Answer is unchanged (classification-only, Assisted).

### 7.5 Acceptance for this workstream

After submitting an incident the player can answer, from the review alone:
What did I do correctly? What should I have done but missed? What did I do
that was unnecessary or harmful? Why? — with every required response
displayed exactly once as Completed or Missed, every collateral action taken
displayed exactly once, dispositions itemized with correctness, empty states
designed, and zero pre-submission leakage (Section 19 criteria).

---

## 8. Pivot-transition contract (workstream 5.2)

### 8.1 Current inventory (verified)

Generator: `lcqlPivots.js` (single choke point, fixture-pinned). Shell
behaviors: entity pivots always Session-wide with visible scope flip
(`pivotAndRun`); refine (`==`/`!=`/sidebar) appends under the
conjunction-only rule with the OR fresh-query notice; descent and
surrounding render origin banners with the snapshot-identity guard; return
chip re-runs the current query under the last focused incident; scope-error
behavior per the revised Stage 4 rule; timeline state renders only while the
displayed snapshot is its own query.

### 8.2 The pivot announcement (binding design)

Every entity pivot and refine renders a **transition banner** in the same
slot (and same self-consistency guard) as the existing descent banner:

- **Clue naming:** "Following clue: `<field> = "<value>"`" — field in
  catalog case, value as generated (escaped display). For refines: "Filter
  added: `<field> == "<value>"`" / "Excluded: `<field> != "<value>"`".
- **Scope transition, stated only when it happened:** "Scope changed:
  INC-8541 → Session-wide." with the example-direction copy available as
  subcopy: "Showing Session-wide activity for ACME\dpark."
- **Origin context preserved:** the banner names where the pivot started
  ("from the ACME-WS05 timeline" / "from INC-8541") and the return path
  ("Back to INC-8541 restores that incident's scope for this query").
- **First-use explainer** (Guided-gated per 5.5): "A pivot follows a user,
  host, IP, file, process, or other clue across available evidence."
- **No-results:** the banner persists over the 0-events state so the player
  sees *what* returned nothing; subcopy offers the two designed outs
  (broaden TIMEFRAME; return to the origin scope).
- The banner is presentation only: it renders from the generated query +
  the pivot request, changes no request, and dies when the snapshot stops
  being its query (the existing timeline guard generalized).

### 8.3 Per-source behavior matrix (all verified paths specified)

| Pivot source | Behavior |
|---|---|
| From incident scope | Banner names clue + the Incident → Session-wide transition + return path; scope control flips visibly (unchanged mechanics). |
| From Session-wide | Banner names clue; "Scope: Session-wide (unchanged)". |
| From an OR query (refine) | Existing fresh-query notice is folded INTO the transition banner (one notice, not two stacked). |
| From identity descent | Account-anchored banner (existing) + pivot transitions from it announce normally. |
| From surrounding-events view | Leaving the surrounding view via pivot announces the clue and that the centered-context view ended. |
| Repeat use | The banner always renders (it is context, not a tip); only the first-use *explainer* is once-only (5.5). |

### 8.4 Shared vocabulary rule

The clue-naming vocabulary here and the Investigation Context summary's
"Following clue" line (Section 11) are ONE vocabulary — same field naming,
same value rendering, same transition phrasing — specified once in the
scaffold and consumed by both surfaces. No LCQL semantics change; no
client-side query execution; the generator remains the only query author.

---

## 9. Inspector-selection contract (workstream 5.3)

### 9.1 Options inventoried

**Option A — connect to the one shared inspector** (preserve the model):
visibly highlight the selected row (strengthen the table treatment to match
the cards' ring), scroll the inspector into view on selection, briefly
emphasize the inspector (a short highlight-fade on open), fix the table's
misleading chevron (replace with a selection affordance that does not
promise inline expansion), preserve selection across Cards/Table and client
sorting (already shell-owned).

**Option B — inline row expansion**: render the inspector inside the
expanded row (table) / below the card (cards).

Evaluation against the required axes:

| Axis | Option A | Option B |
|---|---|---|
| Implementation cost | Small: shell + two renderers; scroll + emphasis + highlight | Large: two inline layouts (table colspan row + card flow), pagination/sort interactions, focus handling per row |
| Accessibility | One landmark inspector; `aria-expanded` on rows; focus moved predictably | Expansion is a familiar pattern, but per-row disclosure duplicates the actions block and complicates focus order across pages/sorts |
| Mobile / narrow | Inspector already full-width below; works | Inline expansion inside a horizontally scrolled 1000px-min table is poor |
| Table sorting / pagination | Unaffected (id-keyed selection survives; it already does) | Expanded row must follow the row across sort/page changes or collapse — both surprising |
| Cards/Table parity | Identical inspector both views (today's invariant) | Two different expansion layouts to build and test |
| One-inspector invariant | Preserved — the recursive leak-guard and kvp-order fixtures keep ONE surface to prove | Weakened: N potential inspector instances; the leak-guard surface multiplies |
| Existing tests/state | `workbench-inspector`, `workbench-snapshot` extend | Significant rewrite of inspector + snapshot suites |

**[Recommendation — Option A**, exactly as the preferred initial direction,
Owner Decision 5.] Binding behavior: selecting a row (either view) applies
the strong selected treatment (cards' existing ring pattern; table gets an
equivalent left-accent + background, severity color untouched), scrolls the
inspector into view (`block: 'nearest'` so the selected row stays visible
where viewport height allows; respecting `prefers-reduced-motion`), and
plays a single short emphasis transition on the inspector container (one
run per selection change; no looping animation). Deselecting closes the
inspector (existing). Selection persistence guarantees are retained
verbatim and re-asserted in tests.

---

## 10. Neutral progress vocabulary and state table (workstream 5.4)

### 10.1 One vocabulary (binding; observable-only)

| State / count | Canonical copy | Source of truth |
|---|---|---|
| Telemetry loading | "Incident telemetry is still loading." | `sealed == false` (queue seal marker) |
| Detections reviewed | "Detections reviewed: {triaged} of {total}" | shared roster (`card.triage` / `scope.triage`) |
| Detections remaining | "{n} detection{s} still need Promote or Dismiss" | roster open count |
| Promoted / Dismissed / Reopened | "Promoted" / "Dismissed" / "Reopened (needs review again)" | `player_action` |
| Response actions taken | "Response actions taken: {n}" | successful log entries in the incident's observable scope (see 10.3) |
| Ready | "Ready to submit" | `ready` (all roster detections reviewed + sealed) |
| Submitted | "Submitted — grade locked" | record existence |
| Completed strip | "Reviewed {total} of {total} · Submitted" | the frozen record's roster size |

Forbidden pre-submission on every surface, permanently: "correct", "wrong",
"solved", any answer-key-derived total, any correctness-implying phrasing.
The vocabulary is a checked copy inventory: a frontend test asserts the
canonical strings and the absence of the forbidden class on pre-submission
surfaces (extending the copy-scan pattern).

### 10.2 Surface mapping (every current surface adopts the vocabulary)

Incident card rows ("N left" → "N to review"), Dashboard active rows
(already "N to review"), phase strip, Incidents readiness line, Detections
counters line, Threats/Feed toggle subcopy (Owner Decision 9: whether
explanatory subcopy ships — **[Recommendation]** yes, one line each: "Feed:
every detection, including reviewed" / "Threats: detections you promoted"),
Submit modal, Metrics in-progress banner, per-incident `/score` progress,
completed states, Post-Incident Review header.

### 10.3 The "Respond" count [Owner Decision 8]

The phase strip's "Respond: N related" is currently a fuzzy label-substring
join (`Incidents.jsx:84-88`). Options: (a) keep a response count in the
strip but compute it honestly — successful actions whose registry target
resolves to a scope host/account (the server can serialize a per-incident
observable `related_actions` count on the card, a non-answer-bearing
observable count); (b) drop the count from the strip and leave response
activity to the existing Related-response list. **[Recommendation]** (a),
with the fuzzy client join replaced by the server count; "Response actions
taken: N" phrasing.

### 10.4 The "0 of 0 reviewed" resolution (F7 item 2)

The completed detail pane renders a **completed strip**: "Reviewed {total}
of {total} · Submitted" (total from the frozen record's disposition count,
which the score view already serializes as `detection.total`), replacing the
active-phase strip for submitted incidents. No backend change strictly
required (the score view has the number); if the card is preferred as the
source, adding `triage` to completed cards is a disclosed serialized-field
addition. The transient contradiction becomes structurally impossible: the
active strip renders only for `state == 'in_progress'`.

---

## 11. Investigation context and scope truth (workstream 5.6; F8 + F9)

### 11.1 Single source of truth (binding architecture requirement)

Two concepts, named and separated everywhere:

- **Current case** — the incident the player is working (today
  `activeIncidentId`). One owner: the app shell.
- **Data scope** — what the displayed rows are filtered to (Session-wide or
  one incident), **per data surface** (SIEM scope is deliberately
  independent — a deliberate Session-wide pivot while working a case is the
  designed workflow).

Rules:

1. For every scoped surface (Endpoints, Detections, SIEM), the scope label,
   the control's selected state, and the row filter derive from **one state
   value** (plus an explicit fetch status), never from parallel derivations.
   The F9 pattern (highlight reads `scoped`, label/data read `scopeActive`)
   is prohibited; the micro-fix (Section 3 F9) lands first, and 5.6
   completes the architecture: scope resolution states are explicit
   (`loading` / `ready` / `error`), rendered honestly ("Loading incident
   scope…"), and scope data refreshes on the surface's existing poll cadence
   so a pre-seal roster cannot go stale.
2. **Atomic scope change:** changing scope updates label, control, and data
   in one state transition; while the scope read is in flight the surface
   says so; on failure the SIEM's revised-error pattern (keep control state,
   show error, offer retry/Session-wide, never silently broaden) becomes the
   uniform pattern on all three surfaces.
3. When current case and data scope differ, both render, labeled:
   "Current case: INC-8541 · Data scope: Session-wide."

### 11.2 The Investigation Context summary

One persistent, compact summary (the F8 requirement), rendered from existing
observable state only:

```
Current case: INC-8541
Data scope:   Session-wide
Following clue: user_account = "ACME\dpark"     (when a pivot/descent is live)
View: Surrounding events                        (when a timeline mode is live)
Results from: all | * | * | user_account == "ACME\dpark"   (the executed snapshot's canonical query)
```

- Contents: current case; data scope; pivot/descent origin; followed clue
  (shared vocabulary with Section 8); active timeline mode; the executed
  snapshot's canonical query (the existing status-line echo, now labeled
  "Results from").
- Placement and persistence [Owner Decisions 12, 13]:
  **[Recommendation]** on the SIEM always (it subsumes the current status
  line + banner stack into one coherent block, collapsible to one line);
  on Endpoints and Detections a one-line reduction (case + data scope only,
  which is exactly the corrected F9 header). Always-visible vs collapsible:
  **[Recommendation]** one-line summary always visible, expandable.
- The summary is read-only presentation over existing state; it issues no
  requests of its own.

### 11.3 Editable query vs executed snapshot; parse-failure truth

- The query bar (editable) and "Results from" (executed) are visually
  distinguished; when the bar text differs from the executed query the
  existing indicator de-emphasis extends to a one-line note: "Edited —
  results below are from the last run."
- **On parse failure:** the error box gains the explicit statement:
  "Displayed results are from the previous successful query." (The prior
  snapshot is already preserved; the statement makes the preservation
  honest.) Same statement for a failed execution.

### 11.4 Return controls: two names for two destinations

"Back" must never ambiguously mean two things [Owner Decision 14]:

- **"Return to current case: INC-8541"** — re-scopes the current query to
  the *focused* incident (exists today as the return chip when the focus and
  chip agree).
- **"Back to pivot origin: INC-1332"** — returns to where the pivot/descent
  started when that is a *different* incident (today's chip silently plays
  this role; F8's confusion).
- When both would name the same incident, ONE control renders (no
  duplicates); when they differ, both render, each naming its target
  incident. **[Recommendation]** contextual rendering (only applicable
  controls appear) over always-both.

### 11.5 Tests (binding for this workstream)

Three-way synchronization tests on Endpoints, Detections, and SIEM: for each
scope state (session, incident-ready, incident-loading, incident-error,
post-reset), assert label text, control selected-state, and rendered row
set agree with the single state value; a mocked slow/failed scope read can
never render a selected "This incident" with unfiltered rows; scope-change
atomicity (no intermediate frame where any two disagree — asserted at the
state-model level); parse-failure notice presence; both return controls
labeled with their targets when they differ; context summary names the
executed query exactly.

---

## 12. Guided onboarding contract (workstream 5.5)

### 12.1 Required concept inventory (verbatim from the owner's list)

what reviewed means; Promote versus Dismiss; Reopen; Feed versus Threats;
incident scope versus Session-wide; `==` and `!=`; Pivot; response actions
versus detection review; telemetry loading; Ready to submit; Post-Incident
Review.

### 12.2 Form and gating

- **Lightweight, contextual, dismissible:** small anchored callouts/tips at
  the moment a concept first becomes relevant (first sealed incident ->
  reviewed/Ready; first Detections visit -> Promote/Dismiss/Reopen +
  Feed/Threats; first scoped surface -> scope concepts; first inspector
  open -> ==/!=/Pivot; first response action -> response vs review; first
  submit-ready -> Ready + what submission locks; first review -> what the
  review teaches). Each is one short paragraph, dismissible individually
  and collectively ("Don't show tips").
- **First-run only** unless manually reopened; reopenable from the Docs
  page and a "Show tips again" affordance [Owner Decision 7:
  **[Recommendation]** reopenable via Docs + a Help entry, not a nav item].
- **Guided mode only by default; never in Hardcore** — gated by allow-list
  (`ONBOARDING_MODES = {"guided"}` mirroring the GUIDED_MODES pattern;
  Hardcore and SOC Queue excluded by default; SOC Queue inclusion is a
  later deliberate decision, not an accident).
- **Answer-free by construction:** copy explains mechanics and vocabulary
  only; a permanent test scans onboarding copy for the forbidden class
  (correctness phrasing, scenario answers, category names tied to the
  active scenario).
- Not a separate tutorial mode; no new mode is created.
- First-use tooltip vs guided callout [Owner Decision 6]:
  **[Recommendation]** anchored callouts for the five load-bearing moments,
  plain tooltips for `==`/`!=`/Pivot buttons (augmenting the existing title
  attributes with accessible tooltips).

### 12.3 Persistence [Owner Decision 7]

Options: localStorage; session state (server); account/profile (does not
exist). **[Recommendation]** `localStorage` keyed
`spectyr_onboarding_v1` (per-browser, per-device): survives Reset, Practice
Another, and backend restart — all deliberate ("seen once" should not
re-trigger on every practice run); Reset does NOT clear it; "Show tips
again" clears it. Server profile state is deferred with persistent history
(the standing 3.9B deferral). The exact key layout (per-concept seen flags)
is scaffold-level.

---

## 13. Data model and serialized-field plan

Every addition is post-boundary or observable; each lands with its guard.

| # | Change | Axis | Venue |
|---|---|---|---|
| D1 | `response_review` breakdown (7.1) — completed/missed/collateral/acceptable identities + whys; detection per-roster-item correctness | **Post-submission only**, per submitted incident | Submitted branch of `/api/incidents/<id>/score` (grading), stored in the record per Owner Decision 2 |
| D2 | Scenario-level rationale text (Tier 2) | Content, post-boundary render | schema v2 `triage_review` sibling field (loader-validated) per Owner Decision 3 |
| D3 | Completed-card `triage` totals OR completed strip fed from score view (10.4) | Observable (frozen record counts) | `/api/incidents` completed cards (disclosed) or none (frontend-only) |
| D4 | Per-incident observable `related_actions` count (10.3, if ruled in) | Observable activity count | `/api/incidents` active cards (disclosed) |
| D5 | Onboarding persistence | Client-only | localStorage; no server field |
| D6 | NO changes | — | Event payloads, LCQL, snapshot identity/tokens, readiness rules, scoring functions/weights, detection generation, world, answer-key grammar (except the D2 content field), pre-submission shapes |

Every serialized-field change above is disclosed in the implementation
report per the standing rule; pre-submission progress shapes gain **no**
fields beyond D4's observable count (if ruled in).

---

## 14. Authoring-cost inventory (measured, all 20 scenarios)

Measured at baseline from `backend/scenarios/v2/*.yaml` (script over the
corpus; per-scenario table):

| Scenario | required | acceptable | with `after` | playbook steps | detections |
|---|---|---|---|---|---|
| brute_force_attack | 0 | 1 | 0 | 5 | 3 |
| c2_dns_tunnel | 2 | 0 | 0 | 5 | 3 |
| c2_http | 2 | 0 | 0 | 6 | 3 |
| data_exfil_archive | 1 | 1 | 0 | 6 | 3 |
| defense_evasion | 3 | 2 | 0 | 5 | 3 |
| defense_evasion_log_clearing | 2 | 2 | 0 | 5 | 3 |
| false_positive_oauth | 0 | 0 | 0 | 5 | 2 |
| false_positive_pentest | 0 | 0 | 0 | 5 | 3 |
| false_positive_robocopy | 0 | 0 | 0 | 5 | 3 |
| false_positive_ssl_inspection | 0 | 0 | 0 | 5 | 3 |
| false_positive_veeam | 0 | 0 | 0 | 5 | 3 |
| insider_shadow_it | 2 | 3 | 0 | 5 | 3 |
| insider_staging | 3 | 2 | 0 | 5 | 3 |
| lateral_movement_1 | 5 | 3 | 1 | 5 | 3 |
| lateral_movement_2 | 5 | 1 | 1 | 6 | 4 |
| malware_ransomware | 2 | 1 | 0 | 6 | 3 |
| malware_usb | 4 | 0 | 0 | 6 | 3 |
| password_spray | 3 | 2 | 1 | 5 | 3 |
| phishing_1 | 2 | 1 | 0 | 5 | 3 |
| phishing_link | 3 | 1 | 0 | 6 | 3 |

Totals: **39 required + 20 acceptable = 59 answer-key actions** across 14
scenarios with actions; **6 scenarios with zero required** (the five FPs +
brute_force_attack — the inaction set); 3 actions carry `after` orderings;
verb distribution: kill_process 21, isolate_host 13, force_password_reset 8,
disable_account 6, revoke_sessions 6, delete_file 3, remove_persistence 2.
**No rationale-like field exists** on any action (checked: no
`rationale`/`why`/`explanation`/`reason` keys). **106 generic playbook
steps already exist** (`triage_review.response_actions`, 5-6 per scenario,
currently unrendered in the review).

Cost per tier (Section 7.3): Tier 1 ≈ 10 code templates, zero content
authoring; Tier 2 ≈ **20 authored scenario paragraphs** (one per scenario;
six of them "why inaction was correct") + zero for the playbook render;
Tier 3 ≈ **59 authored per-action entries** + the Tier 1 collateral
templates (collateral is unbounded and cannot be per-action authored).
Every Tier 2/3 entry is answer-bearing content and must live in a
review-gated, loader-validated source (Owner Decision 3), landing under the
per-scenario commit discipline.

---

## 15. Security and grading-leak analysis

- **The timing axis is the whole risk.** Stage 5A deliberately serializes
  answer-bearing teaching content — but only post-submission, only for the
  submitted incident (inherited boundary 3; the ratified triage-review
  amendment is the precedent). The threat model: (a) a pre-submission
  surface accidentally reading the new content; (b) an unsubmitted or
  foreign incident id reaching the breakdown; (c) rationale content leaking
  answer signal for OTHER incidents (a scenario paragraph must describe its
  own scenario only); (d) onboarding copy carrying answers.
- **Guards, all permanent:** planted markers in expected-action composites
  and rationale strings, asserted absent from every pre-submission payload
  and every other incident's payloads, present only in the owning submitted
  incident's review; structural no-answer-key guard extended over every new
  pre-submission reader (the 5.6 context summary and progress surfaces read
  observable state only); 404/absence tests for unsubmitted/foreign ids;
  the onboarding copy denylist test; the forbidden-phrase copy scan on
  progress surfaces (10.1). The full existing batteries (submission gate,
  event disclosure, detection indistinguishability, guided catalog) run
  green untouched.
- **No new pre-submission observables** except (if ruled in) the D4
  related-actions count — a count of the player's own successful actions,
  observable by definition (the player performed them); it carries no
  required-total or correctness signal.
- **Mode gating:** onboarding by allow-list; Hardcore receives nothing new
  except the same truthful progress vocabulary (which is mode-uniform and
  answer-free).

---

## 16. Accessibility and interaction requirements

- Transition banners, context summary changes, and progress-state changes
  announce via `role="status"`/`aria-live="polite"` (the existing banner
  pattern, applied uniformly).
- Scroll-to-inspector respects `prefers-reduced-motion` (jump, no smooth
  scroll; the emphasis transition disabled); focus management: opening the
  inspector moves focus to its container exactly once per selection change;
  row selection state exposed via `aria-selected`/`aria-expanded`.
- Scope toggles expose `aria-pressed` consistent with the ONE state value
  (the F9 fix is also an accessibility fix — today the visual highlight and
  any assistive announcement can disagree with the data).
- Onboarding callouts: focus-trapped only while open, Escape dismisses,
  never steal focus from an in-progress form; tooltips keyboard-reachable.
- Color discipline per the recorded UI rules: chrome stays charcoal
  `#101218`; `#16436b` INC-link accent only; color is never the sole
  signal (the selected-row treatment pairs accent with a non-color cue);
  severity colors remain reserved for severity.
- All new copy passes the em-dash frontend scan; error treatments follow
  the minimal-error-UI rule (no red borders beyond existing patterns).

---

## 17. Test strategy

| Workstream | Backend | Frontend |
|---|---|---|
| 5.1 Review teaching | New suite (`test_response_review.py`): breakdown correctness vs the scorer's verdicts on fixture incidents (completed/missed/collateral/acceptable/inaction, order-violation flag, released-isolation case, shared-target multi-incident case); immutability (byte-identical re-reads; Option A: stored-record equality / Option B: derivation-invariant test); 404s for unsubmitted/foreign; planted-marker extension; empty-state shapes. Corpus test: every scenario's Tier 2 rationale present + loader-validated (if D2 ships). | Review modal renders every breakdown section + playbook + empty states; no breakdown UI reachable pre-submission. |
| 5.2 Pivot clarity | Generator fixtures unchanged (no query changes). | Banner content per pivot form (clue naming, transition statement, origin, no-results persistence); OR-notice folding; banner dies with its snapshot (identity guard); first-use gating. |
| 5.3 Inspector | — | Scroll-into-view called once per selection change; emphasis once; reduced-motion path; selection persistence re-asserted across views/sort/refresh; chevron affordance replaced; recursive leak-guard and kvp-order fixtures still green (one inspector). |
| 5.4 Progress vocabulary | D3/D4 field tests if ruled in (observable-only shape). | Canonical-copy assertions per surface; forbidden-phrase scan; completed strip replaces active strip for submitted (0-of-0 regression test); "N to review" everywhere. |
| 5.5 Onboarding | — | First-run-once per concept; dismiss/dismiss-all; reopen path; localStorage persistence across reset/practice-another; **Hardcore-never** and SOC-Queue-never assertions (allow-list test); copy denylist. |
| 5.6 Scope truth | Structural guard extension over any new reader. | The Section 11.5 three-way synchronization battery on all three surfaces; F9 micro-fix regression (mocked in-flight + failed scope read); parse-failure notice; dual return controls; context summary == executed query. |
| Cross-cutting | Full existing batteries green every commit (never-land-red); `run_gates.py` suite lists extended. | copy-emdash; scope-no-mutation extended over new interactions (all reads). |

---

## 18. Chrome workflow plan

Run in Phase-final certification against a dedicated backend (dev-harness
rule: batteries never run against the live backend's `backend/logs`):

1. **Guided teaching run (5.1/5.4/5.5):** fresh browser profile; first-run
   callouts appear once each, dismiss correctly, and are absent after
   Practice Another; play an attack scenario taking one required action,
   omitting one, and taking one collateral; submit; the review names all
   three with whys, playbook rendered; re-open review — byte-identical.
2. **Inaction scenario (5.1):** false-positive run with zero actions; the
   review's inaction block explains why nothing was required; then a run
   with one collateral in an inaction scenario shows the collateral named
   and the inaction credit lost, factually.
3. **Pivot chain (5.2/5.6):** descent → row → account pivot → IP pivot →
   host pivot; every step's banner names the clue and any scope transition;
   the context summary tracks case/scope/clue/query; return controls: force
   the focus/origin divergence (focus INC-A, pivot from INC-B's timeline)
   and verify both controls render with distinct targets and behaviors.
4. **Scope truth (F9 regression, 5.6):** with fetch-blocking on
   `/api/incidents/<id>/scope` (the Stage 4 A2 workflow technique), select
   This-incident on Detections and Endpoints: control shows loading/error
   truthfully, never a selected "This incident" over unfiltered rows;
   recovery via retry and via Session-wide; scope re-fetch catches a
   pre-seal roster growth.
5. **Parse-failure truth (5.6):** run a valid query, then an invalid edit:
   error box + "Displayed results are from the previous successful query."
   with the old snapshot intact and the context summary still naming the
   executed query.
6. **Inspector connection (5.3):** 50-row table page; select a bottom row;
   inspector scrolls into view with emphasis; selection survives
   Cards/Table switch and a client sort; reduced-motion mode jumps.
7. **Hardcore purity (5.5/5.4):** full Hardcore run; zero onboarding
   surfaces; progress vocabulary present; timer/failure flows unchanged;
   zero console errors.
8. **Leak audit:** network capture across a full run pre-submission: no
   response_review, no rationale strings, no expected-action content in any
   payload; planted-marker spot-check via the test suite; all-tab console
   sweep zero errors.
9. **"0 of 0" regression:** submit an incident; the completed pane shows
   the completed strip, never the active phase strip.

---

## 19. Acceptance criteria (all testable)

1. After submission, every required response is displayed exactly once as
   Completed or Missed (named, labeled, with a why).
2. Every collateral action taken by the player appears exactly once in the
   review, named, with a why.
3. Each roster detection appears in the review with the player's call and
   its correctness.
4. No post-submission teaching field serializes for an unsubmitted or
   foreign incident (404/absence, planted-marker proven).
5. A pivot names the followed clue and any scope transition, preserves
   origin context, and offers the return path; the banner never outlives
   its snapshot.
6. The selected SIEM event and the inspector remain visibly connected:
   selection highlight + inspector scroll-into-view + one emphasis run;
   selection persists across Cards/Table and client sorting.
7. Every detection progress count on every surface equals the shared
   incident roster's counts (`_incident_roster` derivation).
8. Guided first-run help appears once per concept, is dismissible, is
   reopenable through the designed path, and never appears in Hardcore or
   SOC Queue (allow-list test).
9. No Stage 5 surface exposes correctness, answer-key totals, or forbidden
   phrasing before submission (copy scan + planted markers + structural
   guards).
10. The scope label, scope control, and displayed rows always agree on
    Endpoints, Detections, and SIEM, including in-flight and failed scope
    reads (three-way synchronization battery).
11. When the focused incident and the pivot origin differ, both return
    controls are present and each names its target incident; when they
    coincide, exactly one renders.
12. After a failed parse or failed execution, the UI states that the
    displayed results are from the previous successful query.
13. The Investigation Context summary names the executed snapshot's
    canonical query, the current case, the data scope, the followed clue,
    and the active timeline mode, and never disagrees with any of them.
14. A completed incident never renders the active phase strip ("0 of 0"
    structurally impossible); it renders the completed vocabulary.
15. The full inherited batteries stay green untouched; every new serialized
    field is disclosed; all-tab console sweep zero errors.

---

## 20. Deferred work

Explicitly out of Stage 5A (existing deferrals restated + new):
Tier 3 per-action authored rationale (unless ruled in); server-side
onboarding/profile persistence and cross-run Guided history (3.9B
deferral); SOC Queue onboarding (deliberate later inclusion);
difficulty rubric; response-vocabulary-v2 (arbitrary-file delete, OAuth
revocation, perimeter block, control re-enable); trusted-actor-compromised
scenario + offline-host exercise; A2 same-seed replay; exact-id descent;
detection-materialization vs raw-visibility timing; saved searches /
snapshot history / investigation graph / live tail; advanced LCQL
operators; CampaignProgress micro-fix (standing separate ruling);
cross-session identity; visual-polish phase (separately authorized only);
timeline-coherent Response Log display (the recorded Stage 4 note).

---

## 21. Owner decision register (open — to surface, not silently make)

| # | Decision | Options | This contract's recommendation |
|---|---|---|---|
| 1 | Rationale fidelity | Tier 1 generic / Tier 2 scenario-level / Tier 3 full per-action (59 entries) | Tier 1 + Tier 2 (Section 7.3) |
| 2 | Where the breakdown lives + serving venue | In-record at submit (schema addition) vs derived-at-read; score-view extension vs new endpoint | In-record; served on the score view's submitted grading (7.2) |
| 3 | Where rationale content lives | scenario YAML / separate teaching catalog / code constants | YAML for scenario paragraphs; code constants for generic verb templates (7.3) |
| 4 | Collateral explanations | authored text vs deterministic generic rules | Deterministic generic (7.3) |
| 5 | Inspector connection | Option A scroll-to-shared-inspector vs Option B inline expansion | Option A (Section 9) |
| 6 | First-use help form | tooltips vs anchored callouts | Callouts for the five load-bearing moments; tooltips for ==/!=/Pivot (12.2) |
| 7 | Onboarding persistence + reopen | localStorage / session state / profile; reopen path | localStorage `spectyr_onboarding_v1`; reopen via Docs + Help affordance (12.3) |
| 8 | Response-action count in the phase strip | keep (server-computed observable count) vs drop | Keep, server-computed (10.3) |
| 9 | Threats/Feed explanatory subcopy | yes/no | Yes, one line each (10.2) |
| 10 | robocopy hostname defect venue | separate content micro-fix vs in-Stage-5 | Separate content micro-fix (correction registry) before 5B (F7) |
| 11 | "0 of 0 reviewed" venue | inside 5.4 progress work vs separate micro-fix | Inside 5.4 (F7) |
| 12 | Context summary visibility | always visible vs collapsible | One-line always, expandable (11.2) |
| 13 | Context summary on Endpoints/Detections | full summary vs one-line case+scope vs SIEM-only | One-line reduction on both (11.2) |
| 14 | Return controls | always both vs contextual | Contextual, each naming its target (11.4) |
| 15 | Pivot from a non-focused incident | transfer focus to that incident vs preserve existing focus | Preserve focus; the origin is tracked and named by the pivot-origin control (11.4) — focus changes only by explicit selection |
| 16 | F9 state defect venue | pre-5B presentation micro-fix vs inside 5.6 | Pre-5B micro-fix (minimal one-source derivation + honest loading/error + scope re-fetch), architecture completed in 5.6 (F9) |

---

## 22. Reference matrix

Interaction patterns only; no product design is copied. Exact official page
titles recorded; each row names the decision it informs.

| # | Pattern (source) | Citation (exact title, URL) | Informs | Verdict |
|---|---|---|---|---|
| 1 | Incident investigation keeps the incident's entities/context visible while drilling into evidence (Microsoft Sentinel) | "Investigate Microsoft Sentinel incidents in depth in the Azure portal", learn.microsoft.com/en-us/azure/sentinel/investigate-incidents (title verified at the Stage 4A citation hardening) | 5.6 current-case vs data-scope layering; context summary contents | **Adapt.** Persistent case context around evidence views; Spectyr renders it as the two labeled concepts, no graph. |
| 2 | An investigation has an explicit workbench with a visible artifact scope the analyst adds to and pivots from (Splunk Enterprise Security) | "Investigate a potential security incident on the investigation workbench in Splunk Enterprise Security", docs.splunk.com/Documentation/ES/7.3.1/User/InvestigationWorkbench | 5.6 Investigation Context summary (visible scope of what is being followed); 5.2 origin retention | **Adapt.** The visible-scope idea only; Spectyr's roster is sealed and never analyst-edited (inherited R2 divergence). |
| 3 | Timeline is a named investigation workspace where the driving query is always visible and the analyst drags clues into it (Elastic Security) | "Timeline | Elastic Docs", elastic.co/docs/solutions/security/investigate/timeline | 5.6 "Results from" labeling (query as first-class context); 5.2 clue-following vocabulary | **Adapt.** Query-as-visible-context adopted; drag-composition and saved timelines stay deferred (saved searches). |
| 4 | Detection-to-investigation flow pivots on observables from the detection detail, with the pivot's subject named (CrowdStrike Falcon) | "CrowdStrike Falcon® Insight XDR Walkthrough | Tech Hub", crowdstrike.com/tech-hub/endpoint-security/falcon-insight-xdr-walkthrough/ (console docs are login-gated; this is the official public walkthrough) | 5.2 naming the followed clue on pivot; descent origin banners | **Adopt** the named-pivot pattern through the existing single generator. |
| 5 | Guided questions with per-step hints that are opt-in and never shown in the standard mode (Hack The Box) | "Guided Mode on HTB Labs | Hack The Box Help Center", help.hackthebox.com/en/articles/8117054-guided-mode-for-machines | 5.5 Guided-only gating, opt-in hints, no tutorial interruptions outside Guided | **Adapt.** Mode-gated help; Spectyr keeps help contextual and answer-free (hints never reveal scenario answers, unlike HTB flag hints). |
| 6 | Structured learning rooms teach by question/check/feedback loops inside the exercise surface (TryHackMe) | "TryHackMe | Tutorial", tryhackme.com/room/tutorial | 5.5 contextual first-run teaching moments; 5.1 the review as the feedback loop's close | **Adapt.** The in-surface teaching-moment pattern; no question/flag mechanics are added. |
| 7 | Post-exercise after-action review structured as strengths / areas for improvement / recommendations (CISA HSEEP AAR/IP) | "CISA Tabletop Exercise Packages | CISA", cisa.gov/resources-tools/services/cisa-tabletop-exercise-packages (AAR/IP template: "After-Action Report / Improvement Plan", cisa.gov/sites/default/files/publications/8%20-%20CTEP%20AAR-IP%20Template%20(2020)%20FINAL_508.pdf) | 5.1 review structure: correct (strengths) / missed (improvements) / collateral (harm) / why (recommendations) | **Adapt.** The three-part debrief structure, per incident, automated. |

---

## 23. Implementation-phase recommendation

Order rationale: trust before teaching — a player must believe the labels
before the labels can teach; the two trust defects (F9, 0-of-0) and the
content defect land first and cheap; the review teaching layer is the
largest single workstream and has the only data-model work, so it gets its
own phase late enough to inherit the settled vocabulary.

- **Pre-5B micro-fixes (if ruled as such; each its own concern commit):**
  M1 F9 scope-truth presentation fix (Detections + Endpoints, with the
  three-way sync tests); M2 robocopy content correction (correction
  registry + parity divergence record).
- **Phase 1 — Scope truth and investigation context (5.6):** single-source
  scope state on all three surfaces; context summary; parse-failure
  truth; dual return controls. (F8/F9 closed architecturally.)
- **Phase 2 — Neutral progress vocabulary (5.4):** one vocabulary
  everywhere; completed strip (0-of-0 resolved); server related-actions
  count if ruled in; copy scans.
- **Phase 3 — Pivot transition clarity (5.2):** transition banners on the
  generalized banner mechanism; shared clue vocabulary with the Phase 1
  summary.
- **Phase 4 — Inspector continuity (5.3):** Option A behaviors.
- **Phase 5 — Post-Incident Review teaching layer (5.1):** breakdown data
  contract per Owner Decisions 1-4; review UI; playbook render; guards;
  scenario rationale authoring under per-scenario commits.
- **Phase 6 — Guided onboarding (5.5):** callouts/tooltips, persistence,
  reopen, mode gating.
- **Phase 7 — Certification:** the Section 18 Chrome workflows, full
  batteries, closing report with every disclosure.

Each phase is independently gate-green and stoppable; no phase depends on a
later one. Phases 3/4 are small and could merge into one review cycle at
the owner's discretion.

**Contract risks (register):**

| # | Risk | Mitigation |
|---|---|---|
| R1 | The 5.1 breakdown misclassifies an action vs the scorer (two truths) | Breakdown derives from the SAME scorer pathways (reuse, not reimplementation); fixture battery pins every taxonomy row to the scorer's verdict |
| R2 | Answer-bearing content leaks pre-submission through a new surface | Planted-marker + structural + 404 guards land in the same commits as the data (never after) |
| R3 | Record-schema change (Option A) ripples into frozen 3.9A tests | Additive field only; byte-identity tests extended, never weakened; Option B fallback exists |
| R4 | Rationale authoring stalls the stage | Tier 1 ships without authoring; Tier 2 lands per-scenario, incremental, non-blocking for the other five workstreams |
| R5 | Context summary becomes a second source of truth and drifts | It renders existing state only, no state of its own; the sync battery covers it |
| R6 | Onboarding leaks into Hardcore or nags | Allow-list gating + never-in-Hardcore test + per-concept once-only persistence |
| R7 | Copy churn breaks the em-dash/copy scans late | Vocabulary lands as constants with its own test in Phase 2; later phases consume constants |

---

*Deliverable mapping: contract draft (this document); repository inventory
(Sections 3-4); authoring-cost totals (Section 14); unresolved owner
decisions (Section 21); proposed phases and risks (Section 23); reference
matrix (Section 22). This contract is NOT locked; no scaffold exists; no
implementation or Stage 5B work begins from this document.*
