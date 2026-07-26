# Stage 5A Contract — Live Run Feedback, Teaching, and Player Trust

**Status: LOCKED (owner final lock review PASSED, 2026-07-24). Revision 3
is the locked text; the lock applies at repository baseline `main`
`09eea3b`. All 16 owner decisions RATIFIED (owner review 2026-07-22, the
seven corrections folded in at Revision 2; zero decisions open); both
ratified pre-lock micro-fixes are MERGED and in the baseline — M1 F9
scope truth (merge `38ee145`) and M2 robocopy hostname (merge `09eea3b`).
From this lock, the contract changes ONLY through an explicit
owner-approved amendment — never a new general review cycle, never silent
drift; reason-code registry additions (Section 7.1) are contract
amendments. Everything Section 20 defers stays deferred until separately
authorized. No implementation scaffold exists; no product code lands from
this document until the separately approved scaffold (scaffold ->
approve -> implement).**

**Repository baseline:** `main` at `09eea3b` ("Pre-lock micro-fix M2: merge
robocopy s2 hostname fix (c510c50, ratified OD-10)"), whose ancestry
includes M1 at `38ee145` ("Pre-lock micro-fix M1: merge F9 scope-truth fix
(0fef8ae, ratified OD-16)"). **Both pre-lock micro-fixes are IN this
baseline: the F9 split-derivation defect and the robocopy IP-in-hostname
defect no longer exist at baseline** (their findings below are retained as
historical evidence, marked FIXED). Merged-main gates ALL GREEN
(`run_gates.py --all`, 2026-07-24: backend 27 suites; frontend 18 suites /
173 tests — M1 added `scope-truth.test.js`). Branch:
`stage-5a-live-run-feedback-contract`, brought to this tip by merge (no
history rewrite); both micro-fix merge commits verified as ancestors.
Repository claims in this contract cite `path:line` at this baseline;
every citation was re-verified at the Revision 3 baseline update and those
the two micro-fix diffs moved were updated.

Decision markers, matching the Stage 4A convention: **[Ratified]** (a
recorded owner ruling — including the sixteen Section 21 rulings of
2026-07-22), **[Recommendation]** (superseded in this revision: every
recommendation was ratified), **[Deferred]**.

**Lock record (2026-07-24):** the owner's final lock review PASSED; the
contract is LOCKED with Revision 3 as the locked text, at baseline `main`
`09eea3b`. This lock-record edit changes the status block, this entry,
and the two statements of lock state (Section 23 and the closing
deliverable mapping) only — no substantive content changed. From this
point the contract changes only through explicit owner-approved
amendments (including reason-code registry additions, Section 7.1).

**Changelog from Revision 2 (the pre-lock baseline update; docs-only):**

1. The two ratified pre-lock micro-fixes recorded as MERGED: M1 F9
   scope-truth fix (branch commit `0fef8ae`, merge `38ee145`) and M2
   robocopy hostname correction (branch commit `c510c50`, merge
   `09eea3b`). Baseline moved from `a204995` to `09eea3b`; gates re-run
   and suite/test counts recorded.
2. Every `path:line` citation re-verified at the new baseline; the
   Detections/Endpoints citations M1 moved were updated (Sections 3-F5,
   3-F8, 3-F9, 4.2, 11.1); F9 and the F7 robocopy defect marked FIXED
   with their merge hashes, diagnoses retained as historical evidence;
   several Rev 2 `app.py` citation ranges corrected for accuracy
   (`app.py` itself is unchanged since `a204995`; the old ranges were
   inexact at authoring).
3. Section 14 counts confirmed against the corrected corpus by script
   re-run: every per-scenario row and every total unchanged; no count
   change to report at final lock review.
4. Section 7.1 editorial fix from owner review: `acceptable_completed`
   added to the enumeration of entries that also carry
   `source_action_seq`, matching the null-only rule.

**Changelog from Revision 1 (the seven review corrections):**

1. F9 scope-truth and robocopy hostname defects ratified as **two separate
   pre-lock micro-fixes** (Sections 3, 21, 23); post-merge baseline update
   + final lock review sequence recorded; confirmed the robocopy correction
   changes **no Section 14 count** (Section 14).
2. `response_review` reworked to one-primary-bucket teaching entries with a
   separate stable `reason_code` axis, exact `source_action_seq` semantics
   (null only for never-executed required actions), and a separately
   labeled seq-keyed attempt history that never duplicates a teaching
   entry (Section 7.1).
3. Count-reconciliation acceptance criterion added, with the exact
   entry-to-scorer-count mapping stated explicitly — including the
   inaction-unit fold-in and the order-violation subset rule (Sections 17,
   19).
4. Generic rationale templates constrained to action purpose only, never
   scenario-specific facts; the foothold example replaced with a factually
   narrow template (Section 7.3).
5. Exact scope loading/error/refresh behavior specified per surface for
   Detections and Endpoints, including the honesty statement for stale
   scoped rows and a defined Endpoints refresh trigger (Sections 3-F9,
   11.1).
6. Option A freeze completeness: the entire teaching breakdown (buckets,
   reason codes, labels, rendered why text, detection correctness, seq
   references) freezes into the record at submission; template/YAML
   changes reach future submissions only (Sections 7.2, 13).
7. The two canonical copy strings containing em dashes rewritten (Sections
   10.1, 11.3); recorded that Section 6's journey narrative is not a copy
   source of truth (Section 6).

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
  diagnosed to its root cause in this contract and fixed at baseline by
  pre-lock micro-fix M1 (Sections 3, 11).

Scope discipline: presentation, disclosure-timing, and teaching content only.
No scoring function, weight, readiness rule, roster semantics, LCQL grammar,
snapshot/token semantics, or submission-record grading changes — with one
narrow, explicitly surfaced exception class: *post-submission* serialization
of answer-bearing content for the submitted incident only, which inherited
boundary 3 permits and Section 7 specifies. Every product choice was
surfaced in the Section 21 owner decision register; all sixteen are now
RATIFIED (owner review 2026-07-22), subject to the seven corrections this
revision folds in.

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

Each finding was re-diagnosed against the code at the Revision 2 baseline
`a204995`. Where the finding named a suspected defect, the root cause is
identified here. **Revision 3 note:** the two defects ratified as pre-lock
micro-fixes (F7 item 1, F9) are FIXED at the current baseline `09eea3b`
and are marked so below, their diagnoses retained as historical evidence;
every other citation in this section was re-verified at `09eea3b`.

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
  factual entry lists added by `_incident_report_card` (app.py:3449-3457):
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
app.py:3908); Reopen returns a detection to unresolved
(`set_detection_disposition`, app.py:3018-3033); response actions never
review detections and never gate submission (app.py readiness; CLAUDE.md);
Threats shows promoted detections only (`Detections.jsx:195`); Feed shows
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

1. **`false_positive_robocopy` IP in the hostname field — CONTENT DEFECT,
   FIXED at baseline** (micro-fix M2, branch commit `c510c50`, merge
   `09eea3b`). Historical root cause (diagnosed at `a204995`):
   `backend/scenarios/v2/false_positive_robocopy.yaml` attack step `s2`
   authored `hostname: '{infra.file.ip}'` (resolving to `10.0.1.201`), so
   an IP string entered the observable host set (and the Related-hosts
   line, endpoint pivots, and descent host anchors). **[Ratified, OD-10]**
   venue: a **separate content micro-fix landing BEFORE this contract is
   locked** through the standing correction-registry + parity-divergence
   process — landed exactly as ruled, not folded into any 5A workstream.
   At this baseline the step authors `hostname: '{infra.file.hostname}'`
   (scenarios/v2/false_positive_robocopy.yaml:38, rendering `ACME-SVR02`);
   the registered correction record in `scenario_corrections.py` is the
   approved v1/v2 parity-divergence record (parity_check_v2 CLEAN,
   robocopy at 2 approved divergences, 24 total); the frozen v1 corpus is
   untouched; targeted regression `test_incident_roster_corpus.py::`
   `test_robocopy_file_server_hostname_is_not_an_ip` proves the IP-free
   observable host set with `ACME-SVR02` present on a real drip.
   **Section 14 impact, re-confirmed post-merge:** the landed correction
   touched no `answer_key.actions` entry, no
   `triage_review.response_actions` step, and no `detections` entry;
   every Section 14 count is unchanged (re-verified by script at
   `09eea3b`, Section 14). Backlog observation from M2's report, flagged
   there rather than silently changed: the same step's kvp `computer`
   field still carries the IP placeholder (outside the ruled one-line
   correction; UNC-path IP usages in `command_line`/`object_name` are
   correct and deliberate).
2. **Transient "0 of 0 reviewed" on a completed incident — PRESENTATION
   DEFECT.** Root cause found: completed cards from `/api/incidents` carry
   `incident_grade` but no `triage` field (app.py:3976-3981), and
   `Incidents.jsx:240` renders the phase strip for submitted incidents with
   `sealed` forced true, so `PhaseStrip` falls back to
   `{total: 0, triaged: 0}` (`Incidents.jsx:21`) — displaying "Triage 0 of 0
   reviewed … Submit pending" on a submitted incident. Frontend-only; the
   scope API serves correct post-submit counts. **[Ratified, OD-11]**
   venue: resolved **inside workstream 5.4** (it is precisely a
   progress-state presentation defect and its fix must use the same
   completed-state vocabulary 5.4 defines), not a separate micro-fix.

### F8 — investigation context is hard to follow (verified layering)

Three *independent* context layers exist, each with its own state and none
aware of the others:

| Layer | State owner | Surface |
|---|---|---|
| Focused incident ("current case") | `Dashboard.jsx:24` `activeIncidentId` | Global banner "Focused on incident INC-####" on every non-dashboard tab (`Dashboard.jsx:303-313`) |
| SIEM data scope + pivot origin | `Siem.jsx:50` `scope` state machine, `Siem.jsx:69` `lastIncident`, `Siem.jsx:75` `timeline` | Scope select, scope chip, return chip, descent/surrounding banner |
| Detections/Endpoints data scope | `Detections.jsx:103` / `Endpoints.jsx:67` — the shared `useIncidentScope` hook (post-M1: ONE selection + fetch-status state per surface) | Per-tab `IncidentScopeBar` (scope label + This-incident/Session-wide toggle, rendered from that same state) |

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

### F9 — scope controls and labels contradict each other (ROOT CAUSE FOUND; FIXED at baseline)

**FIXED at baseline by pre-lock micro-fix M1** (branch commit `0fef8ae`,
merge `38ee145`), which implements the Section 11.1 behavior table. The
diagnosis below is retained as historical evidence; its `path:line`
citations are at the pre-fix baseline `a204995` and **those lines no
longer exist** — the current implementation is cited at the end of this
finding.

**This was a real presentation-state defect, not just unclear wording.** In
both `Detections.jsx` and `Endpoints.jsx` (as of `a204995`):

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

**[Ratified, OD-16]** Because the defect misrepresents which data the
player is looking at (a trust defect of exactly the class the hotfix just
closed on the server side), it was fixed as a **separate presentation
micro-fix landing BEFORE this contract is locked** (derive all three
signals from one state value + explicit loading/error presentation + the
per-surface scope refresh triggers), with the full single-source-of-truth
architecture landing in workstream 5.6. The micro-fix implements exactly
the Section 11.1 loading/error/refresh behavior table (review correction
5) — that table, not this paragraph, is the binding specification.

**Landed as ruled (M1, in baseline).** The current implementation derives
all three signals from ONE state value:

- `frontend/src/components/useIncidentScope.js` — the per-surface hook:
  single `selection` + explicit fetch `status`; scoped data retained
  through in-flight refreshes and failures and replaced atomically;
  dropped on incident change; the row policy
  (`all`/`scoped`/`loading`/`error`) derives from that one state
  (useIncidentScope.js:76-78).
- `frontend/src/components/IncidentScopeBar.jsx` — label, toggle
  (`aria-pressed`), and loading/error notices, including the stale-rows
  honesty statement "Displayed rows are from the last successful scope
  read." (IncidentScopeBar.jsx:37) and the explicit Retry / Use
  Session-wide controls, all rendered from the same state.
- Consumers: `Detections.jsx:103` (rows derive at `Detections.jsx:192-198`;
  the scope refetch joins the existing 2.5s feed poll,
  `Detections.jsx:131-138`) and `Endpoints.jsx:67` (rows derive at
  `Endpoints.jsx:106-112`; refetch on every tab-visibility change,
  `Endpoints.jsx:86-93`, no poll introduced).
- Permanent guard: `frontend/src/__tests__/scope-truth.test.js` (the
  three-way label/control/rows synchronization battery, in the frontend
  gate suite).

The stale-scoped-filter consequence diagnosed above (one-shot fetch, never
re-polled) is likewise gone: the per-surface refresh triggers are live.

---

## 4. Current repository inventory

### 4.1 Backend surfaces relevant to Stage 5A

| Surface | Repository truth |
|---|---|
| Submission record | `session["submissions"][id]` = `{incident_id, assisted, submitted_at, inputs: {classification {verdict, category, report}, detection_dispositions {det_id: action}, action_seq_cutoff, isolation_end_state}, report_card}` (app.py:3571-3584). Immutable; byte-identical reads. |
| Per-incident report card | `report_card` = `{classification, detection, response, composite, _response_raw, _inaction_collateral}` (app.py:3465-3473); leading-underscore keys stripped at serialization (app.py:3676-3677). |
| Response section fields | counts + grade (app.py:4425-4437) + `acceptable_taken` / `not_executed` / `no_effect` `{count, entries}` blocks of sanitized log rows (app.py:3449-3457). No missed/collateral identities. |
| Expected actions | `session["expected_actions"]` materialized composites per drip: `{scenario_id, eid, action, status, target composite, after}` (`materialize_expected_actions`, app.py:2340). Server-side only; never serialized anywhere today. Append-only per drip; an incident's set is fixed once dripped. |
| Response log | `GET /api/actions` = every attempt, sanitized `{seq, timestamp, action, outcome, reason, target {id, kind, label}}` (app.py:3110-3117; `sanitize_action_entry`, action_overlay.py:485-498). |
| Readiness / progress | `incident_submission_readiness` (app.py) and `_incident_progress` (app.py:3643-3663) — both consume the shared `_incident_roster`. Progress = observable counts only. |
| Incident cards | `/api/incidents`: active sealed cards carry `triage {total, triaged}`, `open_detections`, `ready`; completed cards carry `incident_grade` + `assisted` and **no triage** (app.py:3963-3993). Plus `stats.severity_breakdown`. |
| Incident scope | `/api/incidents/<id>/scope`: `{incident_id, sealed, hosts, accounts, detection_ids, triage?}` (app.py:4102-4125); observable-only; structurally guarded. |
| Post-Incident Review content | `/api/incidents/<id>/triage-review`: submitted-only 404 gate; serializes the scenario's `mitre`, `what_is_it`, `response_actions`, label stripped (app.py:4611-4628). |
| Check Answer | Guided allow-list; classification correctness only; marks Assisted (app.py:4127+). |
| Guided catalog / intake | `/api/guided-catalog` answer-neutral picker; `build_guided_queue` single-incident run (app.py:4070). |
| Score endpoints | `/api/incidents/<id>/score`, `/api/analytics/report_card` / `action_score` / `detection_score` — discriminated `{state, progress|grading}` shapes, submission-gated. |

### 4.2 Frontend surfaces relevant to Stage 5A

| Component | Role and Stage 5A-relevant state |
|---|---|
| `Dashboard.jsx` | Tab shell; global `activeIncidentId` focus + banner; `descentRequest` plumbing; mode/reset/practice-another flows. |
| `Incidents.jsx` | Workspace: Active/Ready/Completed views; `PhaseStrip` (Triage "X of Y reviewed" / Investigate / Respond "N related" / Submit ready-pending); readiness copy ("N detections still need review.", "Incident telemetry is still loading."); Submit -> classifier -> confirm; Check Answer; Post-Incident Review modal (grades + what_is_it only); Practice Another warning; fuzzy Related-response matching (`:84-88`). |
| `Detections.jsx` | Feed/Threats/Response Log toggle; incident scope via the shared `useIncidentScope` state (post-M1; the scope refetch joins the existing 2.5s feed poll); "N open · N promoted · N dismissed" line; Promote/Dismiss/Reopen; identity response actions on Threats. |
| `DetectionDetail.jsx` | Rule-evidence trigger cards; Open Evidence Timeline (entity-anchored); triage buttons. |
| `Endpoints.jsx` | List + incident scope via `useIncidentScope` (post-M1; refetch on tab visibility, reset, and pivot — no poll); Isolate/Release in detail. |
| `useIncidentScope.js` / `IncidentScopeBar.jsx` | New in M1: the per-surface single scope-truth state (selection + fetch status + derived row policy) and its label/toggle/notice bar — the seed 5.6's single-source architecture completes. |
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

**Copy authority note (review correction 7):** this journey narrative is
illustrative and is NOT a copy source of truth. The scaffold pulls
player-facing strings ONLY from the Section 10.1 canonical vocabulary and
the Section 8.2 canonical transition forms; any string appearing here that
differs from those sections has no standing.

---

## 7. Post-Incident Review data and UI contract (workstream 5.1)

### 7.1 The teaching payload (new, post-boundary, per submitted incident)

A new server-computed **response breakdown** for a SUBMITTED incident,
answering the three acceptance questions with identities, not counts.
Structure per review correction 2: **flat teaching entries, one primary
bucket each**, with classification bucket and reason code as two separate
axes, plus a separately labeled seq-keyed attempt history:

```
"response_review": {
  "entries": [
    {
      "bucket":  "completed" | "missed" | "collateral" | "acceptable" | "inaction",
      "reason_code": <one stable code from the registry below>,
      "action":  <verb, or null on an inaction entry>,
      "target_label": <display label, or null on an inaction entry>,
      "why": <frozen rendered rationale text>,
      "source_action_seq": <int | null>,
      "expected_ref": <stable expected-action identity | null>
    }, ...
  ],
  "attempt_history": [
    { "seq": <int>, "action", "target_label", "outcome",
      "reason_code": "failed_precondition" | "no_effect_repeat" }
  ],
  "detections": [
    { "rule_name", "entity_label", "your_call", "correct": <bool> }
  ]
}
```

**Entry model (binding):**

- A teaching entry represents **either an expected action or an executed
  action occurrence** — never an unanchored composite of both. Its subject
  determines its identity fields:
  - Entries whose subject is an **expected action** (buckets `completed`,
    `missed`, `acceptable`-with-execution, `inaction`) carry
    `expected_ref`: the stable expected-action identity — the answer key's
    `(action, composite target)` pair, which the loader guarantees unique
    per scenario (duplicate pairs are a load error). A `completed`,
    `acceptable_completed`, `out_of_order`, or `released_after_isolation`
    entry ALSO carries the `source_action_seq` of the executed occurrence
    that satisfied (or failed to credit) it.
  - Entries whose subject is an **executed action occurrence** (bucket
    `collateral`) carry their exact `source_action_seq` and
    `expected_ref: null`.
  - **`source_action_seq` is null ONLY for required actions that were never
    successfully executed** (`required_not_attempted`,
    `required_attempt_failed`) and for the scenario-level `inaction` entry.
- **Every entry carries exactly one bucket and exactly one stable
  `reason_code`.** Distinguishing cases never relies on prose alone; the
  `why` text is teaching prose, the `reason_code` is the machine-stable
  discriminator. The reason-code registry (binding set; additions are a
  contract amendment):

  | bucket | reason_code | Meaning |
  |---|---|---|
  | completed | `required_completed` | required action achieved (order satisfied where declared) |
  | missed | `required_not_attempted` | no attempt of any outcome exists for the required composite |
  | missed | `required_attempt_failed` | attempts exist but no successful occurrence (the attempts live in attempt_history) |
  | missed | `out_of_order` | successful occurrence exists but a declared `after` ordering was violated (seq carried) |
  | missed | `released_after_isolation` | required isolation executed but released before submission (end-state forfeit; seq of the isolate occurrence carried) |
  | acceptable | `acceptable_completed` | authored-acceptable action executed (neutral; factual) |
  | collateral | `collateral_in_scope` | successful action matching neither list, target in this incident's grading scope |
  | inaction | `inaction_correct` | no-required scenario, clean hands: the correct response was investigation without action |
  | inaction | `inaction_spoiled` | no-required scenario with at least one collateral in its scope (the collateral actions are their own entries) |
  | (attempt history only) | `failed_precondition` | attempt that did not execute; factual, score-neutral |
  | (attempt history only) | `no_effect_repeat` | repeat of an already-effective action; factual, score-neutral |

- **Attempt history is not a teaching bucket.** No-effect and repeated
  attempts remain ONLY in the separately labeled, seq-keyed
  `attempt_history` (the same entries today's `not_executed` / `no_effect`
  factual blocks carry) **unless an occurrence independently qualifies for
  a teaching bucket** (e.g. the first success that is collateral is a
  `collateral` entry; its later `no_op` repeats stay in history). An
  occurrence never appears both as a primary teaching entry and as an
  attempt-history row; the history row for a failed attempt of a missed
  required action coexists with (does not duplicate) the expected-side
  `missed` entry.

The **detection breakdown** lists each roster detection (ids from the
frozen `inputs.detection_dispositions`): `{rule_name, entity_label,
your_call, correct}` — the per-detection disposition correctness the record
already implies (`compute_detection_score` consumes `disposition` x
`player_action`; correct = promote==TP / dismiss==FP / dismiss==benign).

Rules:

- **Join semantics** (from the scorer, reused not reimplemented): required
  and acceptable match on `(action, full composite target)`; occurrence =
  FIRST successful log entry (duplicates collapse to one credited
  occurrence; later repeats are `no_effect_repeat` history rows);
  isolation completed-ness is END-STATE (`released_after_isolation`);
  order violations are `out_of_order`. Target labels use the registry's
  existing display labels (`target_label`, action_overlay.py:445-459) and
  for never-executed required actions a server-rendered label from the
  expected composite in the same display grammar (host name; "name (PID n)
  on host"; file path on host; DOMAIN\user; persistence entry on host).
- **Shared actions across incidents:** one successful action occurrence can
  appear in several submitted incidents' breakdowns (completed in one,
  collateral in another) — each incident's review describes that incident's
  scope, factually; the entry's `why` names the scope relationship. No
  cross-incident deduplication; the `source_action_seq` is the same in
  both, which is the honest cross-reference.
- **Empty states**, each with designed copy: no response required (the
  `inaction_correct` entry: "No response action was required. The correct
  response here was investigation without action."; spoiled:
  `inaction_spoiled` plus the collateral entries themselves); all correct
  (no missed entries); no actions taken (missed entries only, empty
  history); no collateral (no collateral entries).
- **Loading/error states:** the review modal already fetches score +
  triage-review; the breakdown rides the same fetch pattern; a failed fetch
  renders the existing grade rows with a one-line "The detailed breakdown
  could not be loaded" and a retry.

### 7.2 Where the breakdown is computed and stored [Ratified, OD-2: Option A]

The weighed alternative is kept for the record:

- **Option A — computed at submit, stored in the immutable record**
  (RATIFIED). The breakdown becomes part of the stored record at
  `submit_incident` time. Byte-identical reads by storage; it **adds fields
  to the submission-record schema**, a frozen boundary crossed here by this
  explicit owner ratification.
- **Option B — derived at read time from frozen inputs** (rejected; kept as
  the recorded fallback): deterministic but rests byte-identity on a
  derivation invariant instead of storage.

**Freeze completeness (review correction 6, binding):** at submission the
COMPLETE teaching breakdown freezes into the immutable record — every
entry's classification bucket, `reason_code`, target label, **rendered why
text** (the final prose, not a template reference), the detection labels
and per-detection correctness, and every `source_action_seq` reference
(null exactly where the entry represents a never-executed required action
or the inaction unit). The submitted score view SERVES the frozen result
and never rebuilds any part of it from later mutable content: subsequent
changes to generic templates or YAML rationale text reach **future
submissions only**. A permanent test submits, mutates the template/YAML
sources in memory, re-reads, and asserts byte-identical teaching content.

Serving venue (ratified with OD-2): extend
`GET /api/incidents/<id>/score`'s submitted `grading` (already the review's
data source, already submitted-gated) rather than minting a new endpoint —
one boundary, one gate.

### 7.3 Rationale content ("why") [Ratified, OD-1, OD-3, OD-4]

Measured authoring baseline (Section 14): 39 required + 20 acceptable = 59
authored answer-key actions; no rationale-like field exists anywhere in
schema v2; 106 generic per-scenario playbook steps already exist
(`triage_review.response_actions`). Three content tiers:

- **Tier 1 — deterministic generic rationale (zero authoring).**
  **Template constraint (review correction 4, binding): a generic template
  may explain the ACTION'S PURPOSE but may never invent scenario-specific
  facts.** Scenario-specific causality (what this host was to this attack,
  what the account did) lives ONLY in the Tier 2 scenario paragraph.
  Factually narrow examples of the required form:
  - missed required `isolate_host`: "Isolating an implicated host cuts an
    attacker's access to it while the investigation continues. This host
    required isolation and was not isolated at submission."
  - `collateral_in_scope`: "This action was not part of the expected
    response for this incident. Acting on targets the evidence does not
    implicate disrupts clean assets."
  ~10 templates total, one per (verb, reason-code class), each composed
  with the target label only — no template may assert why the target
  mattered in the scenario.
- **Tier 2 — scenario-level rationale (moderate authoring).** One authored
  "expected response and why" paragraph per scenario (~20 entries; the 6
  inaction scenarios need the "why nothing" lesson — `brute_force_attack`'s
  is already written in docs/action-scoring.md), plus rendering the existing
  `response_actions` playbook in the review. Scenario causality lives here
  and only here.
- **Tier 3 — full per-action rationale (highest fidelity, DEFERRED).** One
  authored `why` per answer-key action: **59 new entries**, plus the ~10
  generic templates for collateral (collateral targets are unbounded;
  per-action authoring cannot enumerate them).

**[Ratified, OD-1]** Tier 1 + Tier 2 ship in Stage 5; Tier 3 deferred.
**[Ratified, OD-3]** rationale content lives in scenario YAML for the
scenario-level paragraph (schema v2 addition, loader-validated,
review-gated like all content) and in code constants for the generic verb
templates (engine voice, not per-scenario content). **[Ratified, OD-4]**
collateral explanations are deterministic generic rules (Tier 1), since
the target space is unbounded.

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
designed, zero pre-submission leakage, and the teaching-entry counts
reconciling exactly against the frozen score section per the Section 19
count-reconciliation criterion (review correction 3).

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

**[Ratified, OD-5 — Option A**, exactly as the preferred initial
direction.] Binding behavior: selecting a row (either view) applies
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
| Submitted | "Submitted. Grade locked." | record existence |
| Completed strip | "Reviewed {total} of {total} · Submitted" | the frozen record's roster size |

Forbidden pre-submission on every surface, permanently: "correct", "wrong",
"solved", any answer-key-derived total, any correctness-implying phrasing.
The vocabulary is a checked copy inventory: a frontend test asserts the
canonical strings and the absence of the forbidden class on pre-submission
surfaces (extending the copy-scan pattern).

### 10.2 Surface mapping (every current surface adopts the vocabulary)

Incident card rows ("N left" → "N to review"), Dashboard active rows
(already "N to review"), phase strip, Incidents readiness line, Detections
counters line, Threats/Feed toggle subcopy (**[Ratified, OD-9]** yes, one
line each: "Feed: every detection, including reviewed" / "Threats:
detections you promoted"), Submit modal, Metrics in-progress banner,
per-incident `/score` progress, completed states, Post-Incident Review
header.

### 10.3 The "Respond" count [Ratified, OD-8: keep, server-computed]

The phase strip's "Respond: N related" is currently a fuzzy label-substring
join (`Incidents.jsx:84-88`). The weighed alternative (dropping the count)
is kept for the record. **[Ratified, OD-8]** option (a): the strip keeps a
response count computed honestly — successful actions whose registry target
resolves to a scope host/account, serialized as a per-incident observable
`related_actions` count on the card (a non-answer-bearing count of the
player's own actions); the fuzzy client join is replaced; phrasing
"Response actions taken: N".

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
   is prohibited. The merged pre-lock micro-fix M1 (`38ee145`; Section 3
   F9, OD-16) implements the exact behavior below through the shared
   `useIncidentScope` state + `IncidentScopeBar`; 5.6 completes the
   architecture.

   **Exact scope loading/error/refresh behavior (review correction 5,
   binding for Detections and Endpoints):**

   | Situation ("This incident" selected) | Required behavior |
   |---|---|
   | Initial incident-scope load | A loading state ("Loading incident scope"), **never Session-wide rows** rendered under the This-incident selection |
   | Scope refresh succeeds with scoped rows already displayed | The displayed scoped rows are retained until the new scope resolves, then replaced atomically (no flash of unfiltered or empty data) |
   | Scope refresh fails with prior scoped rows present | Prior scoped rows preserved; error shown; the surface states: "Displayed rows are from the last successful scope read." (the same honesty rule as the SIEM parse-failure statement) |
   | Scope load fails with no prior scoped rows | An empty error state (error + retry + explicit Use Session-wide), zero rows |
   | Any failure or in-flight state | **Never silently display Session-wide rows while This incident is selected**; broadening happens only through the explicit Use Session-wide control |

   **Refresh triggers, per surface (explicit, since the surfaces differ):**
   - **Detections:** scope refetch rides the surface's EXISTING 2.5s feed
     poll (implemented by M1: `Detections.jsx:131-138`) — the scope read
     joins that interval while an incident scope is selected.
   - **Endpoints:** the surface deliberately has NO poll (fetch on tab
     open and reset — `Endpoints.jsx:82-84`; pivot —
     `Endpoints.jsx:95-101`). No poll is introduced: the scope is
     refetched **on every tab-visibility change** (each time the
     Endpoints view becomes visible; implemented by M1:
     `Endpoints.jsx:86-93`), plus the existing reset and pivot triggers.
     This bounds staleness to the current visit without changing the
     surface's no-polling design.
   - **SIEM:** unchanged (its scope state machine already implements the
     load/error pattern; snapshots are explicit-run only).
2. **Atomic scope change:** changing scope updates label, control, and data
   in one state transition; while the scope read is in flight the surface
   says so; on failure the SIEM's revised-error pattern (keep control state,
   show error, offer retry/Session-wide, never silently broaden) is the
   uniform pattern on all three surfaces, with the stale-rows honesty
   statement above.
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
- Placement and persistence: **[Ratified, OD-13]** on the SIEM the full
  summary (it subsumes the current status line + banner stack into one
  coherent block); on Endpoints and Detections a one-line reduction (case +
  data scope only, which is exactly the corrected F9 header).
  **[Ratified, OD-12]** one-line summary always visible, expandable.
- The summary is read-only presentation over existing state; it issues no
  requests of its own.

### 11.3 Editable query vs executed snapshot; parse-failure truth

- The query bar (editable) and "Results from" (executed) are visually
  distinguished; when the bar text differs from the executed query the
  existing indicator de-emphasis extends to a one-line note: "Edited.
  Results below are from the last run."
- **On parse failure:** the error box gains the explicit statement:
  "Displayed results are from the previous successful query." (The prior
  snapshot is already preserved; the statement makes the preservation
  honest.) Same statement for a failed execution.

### 11.4 Return controls: two names for two destinations

"Back" must never ambiguously mean two things:

- **"Return to current case: INC-8541"** — re-scopes the current query to
  the *focused* incident (exists today as the return chip when the focus and
  chip agree).
- **"Back to pivot origin: INC-1332"** — returns to where the pivot/descent
  started when that is a *different* incident (today's chip silently plays
  this role; F8's confusion).
- When both would name the same incident, ONE control renders (no
  duplicates); when they differ, both render, each naming its target
  incident. **[Ratified, OD-14]** contextual rendering (only applicable
  controls appear), never one vague Back for both.
- **[Ratified, OD-15]** starting a pivot from a non-focused incident's
  timeline PRESERVES the existing focus; the origin is tracked and named
  by the pivot-origin control. Focus changes only by explicit selection.

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
- **First-run only** unless manually reopened; **[Ratified, OD-7 reopen
  path]** reopenable via the Docs page + a "Show tips again" Help
  affordance, not a nav item.
- **Guided mode only by default; never in Hardcore** — gated by allow-list
  (`ONBOARDING_MODES = {"guided"}` mirroring the GUIDED_MODES pattern;
  Hardcore and SOC Queue excluded by default; SOC Queue inclusion is a
  later deliberate decision, not an accident).
- **Answer-free by construction:** copy explains mechanics and vocabulary
  only; a permanent test scans onboarding copy for the forbidden class
  (correctness phrasing, scenario answers, category names tied to the
  active scenario).
- Not a separate tutorial mode; no new mode is created.
- **[Ratified, OD-6]** anchored callouts for the five load-bearing moments,
  plain tooltips for `==`/`!=`/Pivot buttons (augmenting the existing title
  attributes with accessible tooltips).

### 12.3 Persistence [Ratified, OD-7]

Options weighed: localStorage; session state (server); account/profile
(does not exist). **[Ratified, OD-7]** `localStorage` keyed
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
| D1 | `response_review` breakdown (7.1) — one-bucket teaching entries with reason codes, seq references, frozen rendered why text; attempt history; detection per-roster-item correctness. **Frozen INTO the record at submission (7.2, correction 6): the score view serves the stored result and never rebuilds it; template/YAML changes reach future submissions only** | **Post-submission only**, per submitted incident | Submitted branch of `/api/incidents/<id>/score` (grading), stored in the record [Ratified, OD-2] |
| D2 | Scenario-level rationale text (Tier 2) — consumed at SUBMIT time into D1's frozen why text, never re-read for an existing record | Content, post-boundary render | schema v2 `triage_review` sibling field (loader-validated) [Ratified, OD-3] |
| D3 | Completed-card `triage` totals OR completed strip fed from score view (10.4) | Observable (frozen record counts) | `/api/incidents` completed cards (disclosed) or none (frontend-only) |
| D4 | Per-incident observable `related_actions` count (10.3) [Ratified, OD-8] | Observable activity count | `/api/incidents` active cards (disclosed) |
| D5 | Onboarding persistence | Client-only | localStorage; no server field |
| D6 | NO changes | — | Event payloads, LCQL, snapshot identity/tokens, readiness rules, scoring functions/weights, detection generation, world, answer-key grammar (except the D2 content field), pre-submission shapes |

Every serialized-field change above is disclosed in the implementation
report per the standing rule; pre-submission progress shapes gain **no**
fields beyond D4's observable count.

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
review-gated, loader-validated source [Ratified, OD-3], landing under the
per-scenario commit discipline.

**Pre-lock micro-fix impact on this section (review correction 1) —
RE-VERIFIED at the Revision 3 baseline update (2026-07-24):** the landed
robocopy correction (OD-10, merge `09eea3b`) rewrote one hostname
placeholder in `false_positive_robocopy.yaml` chain step `s2`. It touched
no `answer_key.actions` entry, no `triage_review.response_actions` step,
and no `detections` entry. The counting script was re-run over the
corrected corpus at `09eea3b`: **every per-scenario row and every total
above is UNCHANGED** (robocopy row 0/0/0/5/3; 39 required + 20 acceptable
= 59; 3 `after` orderings; 106 playbook steps; 6 inaction scenarios).
There is no count change to report to the owner at final lock review.

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
- **No new pre-submission observables** except the ratified D4
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
| 5.1 Review teaching | New suite (`test_response_review.py`): every reason-code row of the 7.1 registry pinned to the scorer's verdict on fixture incidents (required_completed, required_not_attempted, required_attempt_failed, out_of_order, released_after_isolation, acceptable_completed, collateral_in_scope, inaction_correct, inaction_spoiled); one-bucket-per-entry and no-teaching-entry-duplicated-in-attempt-history structural asserts; `source_action_seq` exactness (null only on never-executed required + inaction entries); the Section 19 **count-reconciliation criterion** as a permanent test over fixtures AND a real-drip corpus pass; **freeze test (correction 6): submit, mutate template/YAML sources in memory, re-read, assert byte-identical teaching content**; byte-identical re-reads; 404s for unsubmitted/foreign; planted-marker extension; empty-state shapes. Corpus test: every scenario's Tier 2 rationale present + loader-validated; template-purity test: no generic template output contains scenario-specific tokens beyond the target label. | Review modal renders every bucket + attempt history + playbook + empty states; no breakdown UI reachable pre-submission. |
| 5.2 Pivot clarity | Generator fixtures unchanged (no query changes). | Banner content per pivot form (clue naming, transition statement, origin, no-results persistence); OR-notice folding; banner dies with its snapshot (identity guard); first-use gating. |
| 5.3 Inspector | — | Scroll-into-view called once per selection change; emphasis once; reduced-motion path; selection persistence re-asserted across views/sort/refresh; chevron affordance replaced; recursive leak-guard and kvp-order fixtures still green (one inspector). |
| 5.4 Progress vocabulary | D3/D4 field tests (observable-only shape; D4 ratified). | Canonical-copy assertions per surface; forbidden-phrase scan; completed strip replaces active strip for submitted (0-of-0 regression test); "N to review" everywhere. |
| 5.5 Onboarding | — | First-run-once per concept; dismiss/dismiss-all; reopen path; localStorage persistence across reset/practice-another; **Hardcore-never** and SOC-Queue-never assertions (allow-list test); copy denylist. |
| 5.6 Scope truth | Structural guard extension over any new reader. | The Section 11.5 three-way synchronization battery on all three surfaces; the Section 11.1 behavior table row by row (initial load never shows Session-wide rows; atomic scoped-row replacement on refresh; stale-rows honesty statement on failure-with-prior-rows; empty error state on failure-without; no silent broadening); per-surface refresh triggers (Detections 2.5s poll join; Endpoints tab-visibility refetch); parse-failure notice; dual return controls; context summary == executed query. |
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
16. **Count reconciliation (review correction 3, permanently tested).** For
    every submitted incident's frozen breakdown:
    - `len(entries where bucket == completed) == response.correct`, and
    - `len(entries where bucket == missed) == response.missed`, and
    - `len(entries where bucket == collateral) == response.collateral`, and
    - acceptable entries reconcile separately:
      `len(entries where bucket == acceptable) == acceptable_taken.count`,
      and acceptable entries are never included in the required-action
      equalities above,
    **with the exact mapping for the two scorer fold-ins stated here so no
    equality is left implicit:**
    - *Inaction fold-in:* `compute_action_score` folds each reviewed
      no-required scenario into `required`/`correct`/`missed` as one
      weight-1 unit (app.py:4395-4403). Per incident this means: for an
      incident whose scenario HAS required actions, the completed/missed
      entries are required-action entries and the equalities above hold
      directly (the incident has no inaction entry). For an inaction
      incident, the completed/missed required-entry sets are EMPTY and the
      single `inaction` entry carries the unit: `inaction_correct`
      reconciles against `response.correct == 1`, `inaction_spoiled`
      against `response.missed == 1`. The test asserts whichever case
      applies; the two cases are mutually exclusive per incident.
    - *Order-violation mapping:* `out_of_order` entries sit in the `missed`
      bucket and are counted inside `response.missed`;
      `response.order_violations` is a SUBSET ANNOTATION
      (`len(entries where reason_code == out_of_order) ==
      response.order_violations`), never a separate bucket, so the missed
      equality remains exact.

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

## 21. Owner decision register — ALL 16 RATIFIED (owner review, 2026-07-22)

Every decision below was ratified as recommended, subject to the seven
review corrections folded into this revision (the Ruling column is the
binding form). The weighed options are retained for the record.

| # | Decision | Options weighed | RULING [Ratified] |
|---|---|---|---|
| 1 | Rationale fidelity | Tier 1 generic / Tier 2 scenario-level / Tier 3 full per-action (59 entries) | Tier 1 + Tier 2; Tier 3 deferred. Templates purpose-only per correction 4 (7.3) |
| 2 | Where the breakdown lives + serving venue | In-record at submit (schema addition) vs derived-at-read; score-view extension vs new endpoint | In-record at submit, COMPLETE freeze per correction 6; served on the score view's submitted grading (7.2) |
| 3 | Where rationale content lives | scenario YAML / separate teaching catalog / code constants | YAML for scenario paragraphs (scenario causality lives ONLY there); code constants for generic verb templates (7.3) |
| 4 | Collateral explanations | authored text vs deterministic generic rules | Deterministic generic, purpose-only (7.3) |
| 5 | Inspector connection | Option A scroll-to-shared-inspector vs Option B inline expansion | Option A (Section 9) |
| 6 | First-use help form | tooltips vs anchored callouts | Callouts for the five load-bearing moments; tooltips for ==/!=/Pivot (12.2) |
| 7 | Onboarding persistence + reopen | localStorage / session state / profile; reopen path | localStorage `spectyr_onboarding_v1`; reopen via Docs + Help affordance (12.3) |
| 8 | Response-action count in the phase strip | keep (server-computed observable count) vs drop | Keep, server-computed `related_actions` (10.3) |
| 9 | Threats/Feed explanatory subcopy | yes/no | Yes, one line each (10.2) |
| 10 | robocopy hostname defect venue | separate content micro-fix vs in-Stage-5 | Separate content micro-fix (correction registry), landing BEFORE lock per correction 1; Section 14 counts confirmed unchanged (F7, 14) |
| 11 | "0 of 0 reviewed" venue | inside 5.4 progress work vs separate micro-fix | Inside 5.4 (F7) |
| 12 | Context summary visibility | always visible vs collapsible | One-line always visible, expandable (11.2) |
| 13 | Context summary on Endpoints/Detections | full summary vs one-line case+scope vs SIEM-only | One-line reduction on both; full summary on SIEM (11.2) |
| 14 | Return controls | always both vs contextual | Contextual, each naming its target; never one vague Back (11.4) |
| 15 | Pivot from a non-focused incident | transfer focus vs preserve existing focus | Preserve focus; origin tracked and named by the pivot-origin control; focus changes only by explicit selection (11.4) |
| 16 | F9 state defect venue | pre-5B presentation micro-fix vs inside 5.6 | Separate presentation micro-fix landing BEFORE lock per correction 1, implementing the 11.1 behavior table exactly; architecture completed in 5.6 (F9, 11.1) |

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

- **Pre-LOCK micro-fixes (RULED, review correction 1; two separate
  merges, each its own concern commit; NOT implemented by this contract
  task):** M1 F9 scope-truth presentation fix (Detections + Endpoints,
  implementing the Section 11.1 behavior table with the three-way sync
  tests); M2 robocopy content correction (correction registry + parity
  divergence record; Section 14 counts confirmed unaffected). **Lock
  sequence:** after both merge, this contract's baseline block and every
  factual line reference are updated, then the contract returns for final
  lock review. Any Section 14 count change caused by M2 is reported at
  that review, never silently updated. **Status at Revision 3: BOTH
  MERGED** — M1 at `38ee145` (with the `scope-truth.test.js` three-way
  sync battery), M2 at `09eea3b` (with the roster-corpus hostname
  regression test); the baseline and line references are updated in this
  revision; Section 14 re-verified with no count change to report. Final
  lock review PASSED 2026-07-24: the contract is LOCKED.
- **Phase 1 — Scope truth and investigation context (5.6):** single-source
  scope state on all three surfaces; context summary; parse-failure
  truth; dual return controls. (F8/F9 closed architecturally.)
- **Phase 2 — Neutral progress vocabulary (5.4):** one vocabulary
  everywhere; completed strip (0-of-0 resolved); server related-actions
  count (ratified); copy scans.
- **Phase 3 — Pivot transition clarity (5.2):** transition banners on the
  generalized banner mechanism; shared clue vocabulary with the Phase 1
  summary.
- **Phase 4 — Inspector continuity (5.3):** Option A behaviors.
- **Phase 5 — Post-Incident Review teaching layer (5.1):** breakdown data
  contract per the ratified OD-1 through OD-4; review UI; playbook render; guards;
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

*Deliverable mapping: locked contract, Revision 3 (this document);
repository inventory (Sections 3-4); authoring-cost totals (Section 14);
ratified owner decisions (Section 21); phases, lock sequence, and risks
(Section 23); reference matrix (Section 22). This contract is LOCKED
(owner final lock review PASSED, 2026-07-24, at baseline `main`
`09eea3b`); changes require explicit owner-approved amendments. No
scaffold exists; the implementation scaffold is the next separately
approved artifact; no implementation or Stage 5B work begins from this
document.*

---
---

# AMENDMENT 1 — CASE-CONSTANT SCOPE + LEARNING FEEDBACK (RATIFIED)

**Status: BOTH DELTAS RATIFIED — owner ruling 2026-07-25, recorded in
A1-R: every drafted recommendation ratified as recommended, with two
owner adjustments (B-OD-5 narrowed to Guided-only; the T1 sealed-roster
count note). The A1-R record is the governing resolution of the
surfaced owner decisions (A-OD-1..4, B-OD-1..5).**
Drafted 2026-07-25 on branch `stage-5-amendment-1` at repository baseline
`main` `2e74b86` (the Stage 5 scaffold-approval merge; gates verified ALL
GREEN at this baseline: backend 27 suites, frontend 18 suites / 173
tests, both runs 2026-07-25). This appendix is appended AFTER the locked
Revision 3 text through the recorded amendment discipline. **The locked
text above is byte-unchanged and remains the historical record; no locked
clause is edited, annotated, retitled, retagged, or marked in place. All
supersession marking lives here.** Upon ratification of a delta, where
that delta differs from the locked text, THIS APPENDIX is the governing
record for that delta's items; unratified deltas have no standing.

## A1-P. Preamble: structure, independence, and discipline

### A1-P.1 Two independently ratifiable deltas

Amendment 1 contains two deltas, each with its own complete supersession
map, replacement text, scaffold delta, and surfaced owner decisions, so
the owner can ratify them independently — both, or one while returning
the other for revision:

- **Delta A — the case-constant scope model** (simplifies): replaces the
  two-scopes-as-equal-modes presentation with a case-constant model.
- **Delta B — learning feedback and motivation** (expands): revises the
  Stage 5 feedback model (live reinforcement, post-submission payoff,
  always-available help).

Each delta's map stands alone. Neither delta's normative text depends on
the other's ratification; every shared surface is resolved by the
combination table (A1-P.2). The scaffold deltas (A1-A.8, A1-B.8) are
drafted HERE as planned change lists and are applied to
`docs/stage-5-live-run-feedback-implementation-scaffold.md` only after
the owning delta's ratification — the scaffold document is untouched by
this draft.

### A1-P.2 Combination outcomes for shared surfaces

| Shared surface | Both ratified | A only | B only |
|---|---|---|---|
| Scaffold Phase 2 | Renamed "Live Progress and Reinforcement"; toasts + checklist; vocabulary rows use the case-constant terms | Vocabulary rows swap to case-constant terms only | Renamed; toasts + checklist; the locked two-scope vocabulary stays |
| Scaffold Phase 6 | Tooltip + hint model; scope teaching = the "Expanded search" tooltip | Locked onboarding model with the scope concept simplified (A1-A.8) | Tooltip + hint model; scope teaching = a scope-toggle tooltip in the locked vocabulary |
| Phase 3 transition surface | Expanded-search block; first-use explainer retired into the Pivot tooltip/hints | Expanded-search block; locked Phase 6 explainer slot survives | Locked 8.2 banner; explainer retired into the Pivot tooltip/hints |
| §12.1 "incident scope versus Session-wide" concept + D5 `scope` concept id | Superseded by both (A renames the concept; B replaces the delivery) | Concept renamed "case evidence versus expanded search" | Concept delivered as a tooltip, locked vocabulary |
| §10.1 canonical vocabulary | Gains A's terms AND B's toast/checklist rows | Gains A's terms | Gains B's rows |

### A1-P.3 Engine-untouched verification (both deltas)

The kickoff's stop condition ("if anything in the model would require an
engine change, STOP and report") was checked against the repository at
`2e74b86` and is NOT triggered:

- **Delta A** consumes only existing engine surfaces: the observable
  incident-scope endpoint (`/api/incidents/<id>/scope`), the Stage 4
  query API's existing session and incident scope parameters, snapshot
  identity/HMAC tokens, and today's no-case session-wide reads (the
  `useIncidentScope` `all` policy). The SIEM scope SELECT control is
  removed, but the underlying scope request semantics, LCQL grammar,
  scope tokens, and snapshot semantics are byte-unchanged (inherited
  invariant 10 reading recorded in A1-A.7). Descent already establishes
  its own scope explicitly (`Siem.jsx:265-303`) and is untouched.
- **Delta B** consumes only: existing card observables (`sealed`,
  `triage`, `ready`), the ratified D4 `related_actions` count, the
  disposition and action POST responses, local classification-selection
  state, and the submitted grading record (including the ratified D1
  `response_review` and D2 `expected_response` once Phase 5 lands). No
  new fields, endpoints, or readiness/scoring changes. Level 3 hints
  WOULD require a new pre-submission serving path — which is exactly why
  they are costed and surfaced (B-OD-2), not committed.

Rosters, readiness, sealing, scoring, LCQL semantics, snapshot identity,
and the scope endpoints are untouched by both deltas. Both are
presentation/workflow-model amendments plus (Delta B) new render-only
consumers of already-ratified data.

### A1-P.4 Ratification states

Each delta carries one state, recorded in A1-R by the owner:
**DRAFT** (this document's state), **RATIFIED** (the delta's appendix
text governs its superseded items; its scaffold delta may be applied to
the scaffold document), or **RETURNED** (the delta has no standing; a
revision cycle follows). This task does not ratify anything.

---

## DELTA A — THE CASE-CONSTANT SCOPE MODEL

### A1-A.1 Rationale and product references

The locked contract models "current case" and "data scope" as two
first-class, co-equal concepts with a persistent per-page
This-incident/Session-wide toggle (§11.1) and a labeled divergence state
(§11.1 rule 3). The first-playthrough evidence (F8, F9) shows the player
experienced this as contradiction, not power. The mature products the
Stage 5A reference matrix already cites resolve the same tension the
same way: **the case is the stable container; broader evidence is
deliberately explored and explained, never a persistent per-page
toggle:**

1. **Microsoft Sentinel** (§22 row 1): incident investigation keeps the
   incident pinned as the workspace; drilling into broader evidence
   happens from the incident, with the incident context retained.
2. **Splunk Enterprise Security investigations** (§22 row 2): the
   investigation is the durable workbench; the analyst ranges over all
   data from it and returns to it; the investigation never silently
   changes under the analyst.
3. **Elastic Security cases** (§22 row 3): the case is the stable
   record; Timeline explorations range across all evidence while the
   case remains the anchor the analyst attaches findings to.

Delta A adopts that shape: ONE stable concept (the current incident),
case-scoped work surfaces, and a self-explaining, deliberately entered
**Expanded search** state on the SIEM — the hunting surface — with
exactly one return action. "Session-wide" disappears from player-facing
copy; the LCQL scope token in the canonical query echo remains the one
deliberately technical layer.

### A1-A.2 The model (normative)

1. **One stable concept: the current incident.** Selecting a case on
   Incidents enters its workspace. The current case stays pinned and
   NEVER changes implicitly — no pivot, descent, search, navigation,
   error, or refresh may change it; it changes only by explicit
   selection (or explicit exit) on Incidents. This makes ratified OD-15
   structural rather than asserted: no control exists anywhere else
   that can change the case.
2. **Detections and Endpoints, case selected: always case-scoped.** No
   This-incident/Session-wide toggle, no Use Session-wide control.
   Header form: "Investigating INC-####". Case-scoped rows only. The
   shared-roster invariant guarantees this can never orphan a
   readiness-gating detection: the displayed case roster IS the
   readiness roster (`_incident_roster`), so everything submission
   requires is reachable without ever leaving case scope.
3. **Detections and Endpoints, no case selected: the All Activity
   state** — header "All activity", full session data, defined
   precisely in A1-A.3 (row 1). Selecting a case on Incidents enters
   its workspace; these pages carry no case-entry or case-exit control
   of their own.
4. **SIEM: two states, not two modes.**
   - **Case evidence** — the default while a case is active; the
     incident-scoped view (state label "INC-#### evidence").
   - **Expanded search** — entered ONLY through an entity Pivot or the
     explicit search-all action. The state always explains itself
     (which clue is being followed, across all evidence), keeps the
     current case pinned and visible, and offers exactly ONE return
     action ("Return to INC-#### evidence", keeping the existing
     return-chip mechanic: the current query re-runs under the case
     scope). Because expansion always launches from the current case,
     the origin is ALWAYS the current case: OD-14's dual return
     controls are superseded by the single return, and the
     divergent-origin state becomes unrepresentable — there is no
     reachable path to another incident's timeline while a case is
     pinned (Detections descent is case-scoped; expanded-search rows
     from other incidents pivot within the state without moving the
     case).
   - With no case active, the SIEM searches all activity naturally (no
     block, no return action, no search-all action — it is already
     searching everything).
   - Descent and surrounding-events are VIEW MODES, not scope states:
     they keep their existing origin banners and their existing
     explicit scope mechanics (`Siem.jsx:265-303` — descent
     establishes incident scope when opened from an incident context,
     session scope otherwise) and present inside whichever state their
     executed scope lands.
   - Refines (`==`/`!=`/sidebar) are scope-preserving in BOTH states
     (today's behavior: refines never flip scope; only entity pivots
     do).
5. **Copy.** "Session-wide" is removed from ALL player-facing copy. The
   working names are "Expanded search", "All activity", "Return to
   INC-#### evidence"; proposed finals in A1-A.5 (all free of em
   dashes). The LCQL scope token remains visible in the canonical query
   echo ("Results from"): the query language is the one layer where
   scope legitimately stays technical.
6. **M1 survives.** The `useIncidentScope` state machine — selection,
   fetch status, atomic replacement, loading/error honesty including
   "Displayed rows are from the last successful scope read." — remains
   the mechanism behind every case-scoped surface. What is removed is
   the toggle UI and the Use Session-wide control (both shipped by M1
   in `IncidentScopeBar.jsx`); the hook, the honesty rows, and the
   per-surface refresh triggers are kept verbatim. Nobody re-plans what
   already exists.
7. **The engine is untouched** (verified, A1-P.3): rosters, readiness,
   sealing, scoring, LCQL semantics, snapshot identity, scope
   endpoints. This delta is presentation-model only.

### A1-A.3 Three-state behavior table (translating §11.1)

This table translates the surviving §11.1 rows into the case-constant
model; it does not reopen them. The §11.1 refresh triggers are UNCHANGED
(Detections: scope read rides the existing 2.5s feed poll; Endpoints:
refetch on tab-visibility change plus reset and pivot, no poll; SIEM:
explicit-run only). Atomicity is UNCHANGED in force: case selection
change updates label, state, and rows in one transition; while a read is
in flight the surface says so; no intermediate frame disagrees.

| State | Label | Controls | Rows | Loading | Error |
|---|---|---|---|---|---|
| **No case ("All activity")** | Header "All activity" on Detections, Endpoints, SIEM | Detections: Feed/Threats/Response Log toggles, search/filters, Promote/Dismiss/Reopen, identity actions on Threats (session-wide triage stays fully available — ambient detections outside any roster remain session material per the hotfix invariant). Endpoints: full host list + org, detail tabs, all response actions. SIEM: query bar, Run, presets, pivots/refines/descent. No scope toggle, no search-all, no return action, no case-entry control (cases are selected on Incidents) | Full session data: whole feed, all endpoints, session-scope snapshots | Each surface's existing fetch/loading presentation; no incident-scope read exists in this state | Each surface's existing fetch-error presentation |
| **Case evidence (case selected; the default)** | "Investigating INC-####" (Detections, Endpoints; unifies the global focus banner); SIEM state label "INC-#### evidence" | Same page controls with NO scope toggle and NO Use Session-wide anywhere; SIEM adds the explicit search-all action (A-OD-4) and its pivots/descent per A1-A.2.4 | Case-scoped only: the incident's shared-roster detections; participant endpoints; incident-scope snapshots | Initial case read: "Loading incident scope", NEVER all-activity rows under a selected case; refresh with scoped rows displayed: rows retained until the new read resolves, replaced atomically (M1, verbatim) | With prior scoped rows: rows retained + error + "Displayed rows are from the last successful scope read." With none: empty error state + Retry, zero rows. Never all-activity rows; there is no broadening control on these pages at all (structural). Recovery: Retry, or explicitly leaving/switching the case on Incidents |
| **Expanded search (SIEM only; case selected)** | The expanded-search block: "Expanded search" + clue line (when entered by pivot) + "Searching all evidence. Your case INC-#### stays open."; the case stays pinned and visible | Exactly ONE return action: "Return to INC-#### evidence" (existing return mechanic). Query bar, pivots, refines active and state-preserving; search-all absent (already expanded). Not reachable on Detections/Endpoints (A-OD-2 recommendation: no expand action) | Session-scope snapshot rows of the executed query | Existing explicit-run snapshot loading presentation (unchanged) | Existing parse/execution failure presentation + the §11.3 honesty statement (unchanged); the block persists over the 0-events state with the two designed outs (broaden TIMEFRAME; return to case evidence) |

Entry and exit (normative): Expanded search is entered only by an entity
Pivot or the explicit search-all action; exited only by the return
action or by an explicit case change/exit on Incidents (which atomically
re-anchors the SIEM to the new state). Nothing else moves between
states.

**Deliberate narrowing, surfaced (part of A-OD-3):** the locked §11.1
error-empty row offered an explicit "Use Session-wide" escape; the
case-constant model removes it (the control ceases to exist). Recovery
from a persistent scope-read failure is Retry or explicitly leaving the
case — never silent or one-click broadening on the data page.

### A1-A.4 Context presentation (replaces §11.2; OD-12/13 re-ruled)

The five-line expandable Investigation Context summary SHRINKS to:

1. **One pinned case line, always visible** on every evidence surface:
   "Investigating INC-####" (or "All activity"). It unifies and
   replaces the global "Focused on incident INC-####" banner — one
   case signal, one owner (the app shell), rendered per surface.
2. **The expanded-search block, only while that state is live** (SIEM):
   state name, followed clue (shared §8.4 vocabulary), the
   all-evidence statement, the single return action. This block IS the
   scope-transition surface (it subsumes the locked 8.2 banner's
   scope-change portion).
3. **Existing timeline banners** (descent/surrounding) unchanged.
4. **The snapshot status line** retained with the locked "Results from:"
   labeling and the canonical query echo — the scope token stays
   visible here and only here as the technical truth. The §11.3
   edited-query note and parse-failure statement are retained verbatim.

Re-rulings this presentation requires (both pending this delta's
ratification): **OD-12 superseded** — no expandable summary; the pinned
line is always visible and there is nothing left to expand (each
remaining fact has its own existing home). **OD-13 superseded** —
Detections/Endpoints get the pinned case header instead of the two-line
"Current case / Data scope" reduction; the SIEM gets pinned header +
state label + conditional block + status line instead of the full
five-line summary. The R5 discipline is unchanged: every element renders
existing state only, owns no state, issues no requests.

### A1-A.5 Copy table (proposed finals; no em dashes in any string)

Working names from the kickoff are direction; the owner ratifies or
edits the finals (A-OD-1).

| Concept | Locked / current string | Proposed final | Surfaces |
|---|---|---|---|
| Pinned case line | "Focused on incident INC-8541" (banner); "Current case: INC-8541" (11.2) | "Investigating INC-8541" | All evidence surfaces, case selected |
| No-case header | (none; implicit session view) | "All activity" | Detections, Endpoints, SIEM, no case |
| SIEM case-evidence state label | "Data scope: This incident" | "INC-8541 evidence" | SIEM state chip |
| Expanded-search state name | "Data scope: Session-wide" | "Expanded search" | SIEM block title |
| Expansion explanation (pivot entry) | "Scope changed: INC-8541 → Session-wide." + "Showing Session-wide activity for ACME\dpark." | Line 1: 'Following clue: user_account = "ACME\dpark"' (locked 8.2 clue form, kept). Line 2: "Searching all evidence. Your case INC-8541 stays open." | SIEM expanded-search block |
| Expansion explanation (search-all entry) | (state did not exist) | "Searching all evidence. Your case INC-8541 stays open." | SIEM expanded-search block |
| Return action | "Back to INC-8541" / "Return to current case: INC-8541" / "Back to pivot origin: INC-1332" | "Return to INC-8541 evidence" | SIEM, expanded search live |
| Search-all action | (none; scope select) | "Search all evidence" | SIEM, case evidence state |
| Return-path explainer subcopy | "Back to INC-8541 restores that incident's scope for this query" | "Return to INC-8541 evidence runs this query over the case evidence again." | Expanded-search block subcopy |
| Refine notices | "Filter added: ..." / "Excluded: ..." | unchanged | SIEM |
| Scope-read honesty strings | "Loading incident scope" / "Displayed rows are from the last successful scope read." / "Retry" | unchanged | Detections, Endpoints, SIEM case read |
| Removed outright | "Use Session-wide"; "Session-wide view"; "This incident / Session-wide" toggle labels; "Current case: ... · Data scope: ..." | (no replacement; the concepts they named no longer exist) | — |

The LCQL scope token in the canonical echo is exempt by design (A1-A.2
point 5).

### A1-A.6 Translated acceptance criteria (replacing §19.10-13)

Same testability bar; each replaces its number upon ratification:

- **10.** On Detections, Endpoints, and the SIEM, the rendered
  header/state label, the case selection, and the displayed rows always
  agree with the single scope state, including in-flight and failed
  case-evidence reads (three-state synchronization battery); a
  case-selected surface never renders all-activity rows, and no
  broadening control exists on Detections or Endpoints.
- **11.** While Expanded search is live, exactly one return action
  renders and names the current case; the current case never changes
  except by explicit selection on Incidents (structural assertion: no
  other code path writes the case); no state is representable in which
  an expansion origin differs from the current case.
- **12.** (Unchanged in substance, restated for block completeness.)
  After a failed parse or failed execution, the UI states that the
  displayed results are from the previous successful query.
- **13.** The pinned case line, the expanded-search block (state, clue,
  return target), the active timeline mode, and the "Results from"
  canonical echo each match the executed snapshot and current state and
  never disagree with any of them; the echo retains the LCQL scope
  token.

### A1-A.7 Delta A supersession map (complete)

Dispositions: **T** translated (guarantee survives in new form; the
appendix text cited is governing), **S** superseded (replaced;
appendix text governing), **U** unchanged (inspected, not touched),
**A** augmented (locked text stands; appendix adds a recorded reading).

| # | Locked item | Disp. | Governing text / note |
|---|---|---|---|
| 1 | §11.1 preamble: "current case" + "data scope" as two named co-equal concepts | S | A1-A.2.1, A1-A.4 — one stable concept plus per-page states |
| 2 | §11.1 rule 1: one state value per surface; F9 pattern prohibited; M1 mechanism | T | A1-A.2.6, A1-A.3 — mechanism kept verbatim; toggle UI + Use Session-wide removed |
| 3 | §11.1 behavior table rows: initial load / refresh-success / refresh-fail-with-rows / never-silent | T | A1-A.3 case-evidence row (guarantees verbatim) |
| 4 | §11.1 behavior table row: load-fails-no-rows incl. "explicit Use Session-wide" | T (narrowed) | A1-A.3 — Retry only; escape removed; narrowing surfaced in A-OD-3 |
| 5 | §11.1 refresh triggers (Detections poll join; Endpoints tab-visibility; SIEM explicit-run) | U | Kept verbatim (A1-A.3 preamble) |
| 6 | §11.1 rule 2: atomic scope change | T | A1-A.3 preamble — atomic case-selection change |
| 7 | §11.1 rule 3: divergence labeled "Current case ... Data scope: Session-wide." | S | A1-A.4 — divergence unrepresentable on Detections/Endpoints; on SIEM the expanded-search block explains it |
| 8 | §11.2 Investigation Context summary (contents, layout, subsumption) | S | A1-A.4 — shrunk to pinned line + conditional block + retained status line |
| 9 | OD-12 (one-line always visible, expandable) | S | A1-A.4 — pinned line always visible; expansion retired (re-ruling pending ratification) |
| 10 | OD-13 (full summary on SIEM; one-line reduction on Detections/Endpoints) | S | A1-A.4 (re-ruling pending ratification) |
| 11 | §11.3 edited-query note + parse/execution-failure statement | U | Retained verbatim (A1-A.4 item 4) |
| 12 | §11.4 dual return controls ("Return to current case" / "Back to pivot origin") | S | A1-A.2.4 — single return action |
| 13 | OD-14 (contextual dual return controls, never one vague Back) | S | A1-A.2.4 — superseded by the single return; the two-destinations problem is dissolved, not re-answered |
| 14 | OD-15 (pivot preserves focus; focus changes only by explicit selection) | T | A1-A.2.1 — made structural: no control outside Incidents can change the case |
| 15 | §11.5 test battery (three-way sync; dual-control matrix; summary==query) | T | A1-A.3, A1-A.6 — three-state battery; single-return + unrepresentability assertions; pinned-line/block agreement |
| 16 | §8.2 clue-naming forms ("Following clue:" / "Filter added:" / "Excluded:") | U | Kept verbatim (A1-A.5) |
| 17 | §8.2 "Scope changed: INC-8541 → Session-wide." + Session-wide subcopy | S | A1-A.5 — expanded-search wording |
| 18 | §8.2 origin-context + return-path lines | T | A1-A.2.4 — origin is always the pinned case; single return + subcopy |
| 19 | §8.2 first-use explainer (Guided-gated) | U | Untouched by Delta A; Delta B relocates it (A1-P.2) |
| 20 | §8.2 no-results persistence + two designed outs | T | A1-A.3 expanded-search row — block persists; outs reworded |
| 21 | §8.3 per-source matrix (from incident / from Session-wide / OR refine / descent / surrounding / repeat) | T | A1-A.2.4 — from case evidence enters Expanded search; within Expanded search updates the clue; no-case is plain; descent/surrounding unchanged mechanics; repeat-use unchanged |
| 22 | §8.4 shared vocabulary rule | U | One vocabulary, now consumed by the block + pinned line |
| 23 | §10.1 canonical vocabulary table | U | Inspected: contains NO scope rows (the kickoff's "Session-wide view" pointer resolves to §11.x/8.2/M1 strings, handled above); gains A's new terms as additive rows |
| 24 | §10.2 surface mapping | U | No scope copy present |
| 25 | §12.1 concept "incident scope versus Session-wide" | T | Renamed "case evidence versus expanded search"; delivery per A1-P.2 |
| 26 | §12.2 OD-6 anchor "first scoped surface -> scope concepts" | T | Simplified to the expanded-search explanation (A1-A.8 Phase 6; superseded wholesale if Delta B ratifies) |
| 27 | §6 journey steps 2-3 (scope copy in the narrative) | T | Narrative re-reads under A1-A.2; the §6 copy-authority note stands (journey is not a copy source) |
| 28 | §19 acceptance criteria 10-13 | T | A1-A.6 |
| 29 | §17 rows 5.6 + 5.2 (frontend batteries) | T | A1-A.3/A1-A.6 — three-state battery, block tests, single-return matrix |
| 30 | §18 Chrome workflows 3-4 (forced focus/origin divergence; Use Session-wide recovery) | T | Divergence walk is unrepresentable; replaced by a pinned-case pivot chain + single-return walk; recovery = Retry + explicit case exit |
| 31 | §5 inherited invariant 10 (Stage 4 scope semantics intact) | A | Reading recorded: the scope SELECT is a control surface, not semantics; LCQL scope params, tokens, snapshots byte-unchanged (A1-P.3) |
| 32 | §22 reference rows 1-3 (Sentinel / Splunk ES / Elastic) | A | A1-A.1 records the case-constant reading of the same sources |
| 33 | §3 F8/F9 (evidence; M1 landed record) | U | Historical record; unchanged |
| 34 | M1 shipped strings: toggle labels + "Use Session-wide" | S | Removed at Phase 1 (scaffold delta); honesty strings kept (A1-A.5) |
| 35 | Scaffold §1.3 "5.6 still requires" list (dual controls; two-concept labeling; full summary) | S | A1-A.8 Phase 1 |
| 36 | Scaffold §2.1 target; §2.3 target ("Scope changed" copy) | T | A1-A.8 Phases 1 and 3 |
| 37 | Scaffold §5 copy rows (8.2 scope-changed row; 11.2 family; 11.1 Use Session-wide) | T/S | A1-A.5 |
| 38 | Scaffold §6 Phase 1/2/3 commit plans; §8 traceability rows 10-13; §10 workflows 3-5; §12 sizing rows 1-3, 6 | T | A1-A.8 |
| 39 | Scaffold approval rulings A-H | U | None touches the scope model; ruling G (Phases 3/4 one review cycle) stands |
| 40 | Contract risk R5 (context summary drift) | U | Applies unchanged to the pinned line + block (render-only, no state) |

### A1-A.8 Scaffold delta (applied to the scaffold only after ratification)

**Phase 1 — scope truth and investigation context. Size M -> S-M.**
- *Loses:* dual return controls + their matrix tests (11.4/OD-14); the
  two-concept "Current case / Data scope" labeling on
  `IncidentScopeBar`; the expandable full-summary form (OD-12/13); all
  divergence-labeling states.
- *Gains:* pinned case header unification (including replacing the
  `Dashboard.jsx` global focus banner — file added to the phase's
  touch list); All-activity headers/states per A1-A.3 row 1; SIEM state
  pair (scope select removed; search-all action + single return action
  + state label); removal of the M1 toggle + Use Session-wide from
  `IncidentScopeBar` (hook untouched); `scope-truth.test.js` translated
  to the three-state battery; the structural
  case-never-changes-implicitly assertion.
- *Keeps:* `useIncidentScope` verbatim; the loading/error honesty rows
  and refresh triggers; §11.3 notes; `uiCopy.js` seeding (R7);
  `InvestigationContext.jsx` shrinks to the pinned line + block (or
  folds into existing chrome at implementation's discretion).
- Commit shape: 1.1 (internal: strings + component vs mocked state)
  and 1.2/1.3 **[STOP]**s consolidate to: 1.2 **[STOP]** state model +
  headers + SIEM state pair + toggle removal; 1.3 **[STOP]** §11.3
  notes + expanded-search return + structural assertion + battery
  translation.

**Phase 2 — neutral progress vocabulary. Size M (unchanged).**
- *Loses/Gains:* vocabulary rows only — the removed strings (A1-A.5
  "Removed outright" row) leave the module; the new terms (pinned
  header, state names, return/search-all actions, All activity) enter
  as canonical rows with the same canonical-copy test coverage.
- *Keeps:* everything else (10.1 sweep, D4 + guards, completed strip,
  0-of-0 regression, forbidden-phrase scan).

**Phase 3 — pivot transition clarity. Size S-M (unchanged).**
- *Loses:* the "Scope changed: INC-#### -> Session-wide." banner copy
  and its conditional per-source scope-transition statements.
- *Gains:* the expanded-search block as the transition surface (entry
  via pivot names the clue; entry via search-all names the state);
  state entry/exit tests (pivot-entry, search-all-entry, return-exit,
  case-change-exit).
- *Keeps:* clue naming, OR-notice folding, no-results persistence,
  identity-guard death, the translated 8.3 matrix, `lcqlPivots.js`
  untouched with fixtures green.

**Phase 6 — Guided onboarding (Delta A alone; superseded wholesale by
Delta B if both ratify). Size M (slightly lighter).**
- *Loses:* the two-scope form of the scope concept.
- *Gains:* the simplified expanded-search concept — recommend the block
  itself carries the first-use explanation, dropping the separate scope
  callout (concept count 8 -> 7; D5 `scope` id retired or renamed).
- *Keeps:* everything else in the locked Phase 6.

**Net for Delta A: the stage SHRINKS** (Phase 1 M -> S-M; Phases 2/3
flat with simpler copy; Phase 6 one concept lighter; Phase 7 workflows
3-4 simpler by one forced-divergence walk).

### A1-A.9 Owner decisions surfaced (not made)

- **A-OD-1 — final naming.** Ratify or edit the A1-A.5 proposed finals
  ("Investigating INC-####", "All activity", "INC-#### evidence",
  "Expanded search", "Search all evidence", "Return to INC-####
  evidence", the two explanation lines).
- **A-OD-2 — expand action on Detections/Endpoints.**
  **Recommendation: NO.** The SIEM is the hunting surface; Detections
  and Endpoints stay single-purpose (triage; host state). An expand
  control on either page would recreate the removed toggle under a new
  name and reintroduce the two-mode reading this delta exists to
  retire; broader exploration always routes through the SIEM, where
  the query echo, clue vocabulary, and return discipline live.
- **A-OD-3 — the All Activity state contents per page, and the
  error-state narrowing.** Confirm A1-A.3 row 1 (Detections keeps full
  session triage with no case selected; Endpoints keeps all actions;
  SIEM plain) and the surfaced narrowing: the error-empty state offers
  Retry only, with no Use Session-wide escape (A1-A.3 note).
- **A-OD-4 — where the explicit search-all action lives on the SIEM.**
  **Recommendation:** the state label adjacent to the query bar renders
  the current state ("INC-#### evidence") with "Search all evidence"
  beside it; the return action renders in the expanded-search block.
  Alternative (weighed): inside the pinned case line. The query-bar
  placement keeps scope state next to the thing it governs.

---

## DELTA B — LEARNING FEEDBACK AND MOTIVATION

### A1-B.1 Rationale and references

The locked feedback model teaches at two moments: first-run-only
onboarding callouts (§12) and the post-submission review (§7). The
revised model follows the pattern of the training platforms the
reference matrix already cites — **TryHackMe** (§22 row 6: in-surface
feedback loops with instant confirmation of progress inside the
exercise) and **HTB Academy / Guided Mode** (§22 row 5: opt-in,
mode-gated hints on explicit request; help never interrupts the
standard mode): **instant confirmation of observable progress during
the exercise; correctness, rewards, and coaching after completion; help
available on demand rather than first-run-only.**

### A1-B.2 The governing invariant, restated, and the guard extension

Before submission, feedback may say that an action executed, a
detection was reviewed, or an observable milestone was reached; it must
NEVER say or imply that any decision was correct, optimal, required,
missing, or harmful. After submission, everything teaches. **The
forbidden-phrase scan, the planted-marker battery, and the structural
no-answer-key guards extend to every new surface this delta creates —
toasts, checklist, hints** — and, per scaffold ruling B's discipline,
the surfaces and observable inputs are enumerated BY NAME, never an
unenumerated "every":

- Toast renderers read ONLY: the disposition POST response, the action
  POST response (`seq`, `outcome`, `reason`, `target.label`), and card
  observables (`sealed`, `triage`, `ready`).
- Checklist lines read ONLY: card observables (`sealed`, `triage`,
  `ready`, `related_actions` [D4]) and local classification-selection
  state.
- Hint levels 1-2 read ONLY: (active surface id, control id, requested
  level) — a permanent structural test asserts the hint module imports
  and receives no scenario, detection, grading, or answer state.
- Achievements and the Case Closed flow read ONLY the submitted
  grading record (post-boundary by construction).

### A1-B.3 Live Progress and Reinforcement (Phase 2, renamed)

#### A1-B.3.1 The exact toast trigger list (closed set)

Action-result toasts fire for discrete state-changing player actions
ONLY. The trigger list is exact; anything not listed does not toast.

| # | Trigger | Toast content (canonical vocabulary) | Observable source |
|---|---|---|---|
| T1 | Detection disposition set (Promote / Dismiss / Reopen) | "Promoted" / "Dismissed" / "Reopened (needs review again)" + the observable remaining count ("{n} detection{s} still need Promote or Dismiss") | disposition POST response + shared-roster counts |
| T2 | Response action executed, `success` | action verb + registry target label (e.g. "Isolated ACME-WS12") | action POST response fields only |
| T3 | Response action attempt, `no_op` or `failed_precondition` | the factual outcome + the in-fiction reason, verbatim from the response | action POST response fields only |
| T4 | Milestone: an incident's sealed roster reaches fully reviewed | "All detections reviewed for INC-####" | roster counts (open hits 0 on a sealed roster) |
| T5 | Milestone: an incident becomes ready to submit | "INC-#### is ready to submit" | the card `ready` observable |

Exclusions (normative): NO toasts for read-only operations (queries,
refines, pivots, descent, expanded-search entry/exit, tab changes); NO
toast for case selection (the pinned header announces it); NO toast for
classification selection (the selector and the checklist line announce
it); NO toast for submission (the Case Closed moment is the
announcement); NO toast that duplicates a persistent surface already
announcing the same fact — the transition surface (locked 8.2 banner
or, under Delta A, the expanded-search block) and the checklist are
persistent surfaces, and one fact gets one announcement (the R5
lesson). T2/T3 render identical shapes for required, acceptable, and
collateral targets alike (the response is disposition-blind by
construction). If one disposition completes several incidents' rosters
(shared ambient detections), each affected incident's milestone fires
once.

#### A1-B.3.2 The incident-progress checklist (one surface, not two)

ONE persistent per-incident checklist showing observable work
remaining. It **folds INTO the existing phase-strip/progress surface**
(the `PhaseStrip` evolves into it); it is NOT a second parallel
progress surface with its own state — one source of truth per fact.

| Line | Rendering | Observable source |
|---|---|---|
| Telemetry | "Incident telemetry is still loading." -> complete when sealed | card `sealed` (the seal marker) |
| Detections | "Detections reviewed: {triaged} of {total}" | card/scope `triage` (shared roster) |
| Classification | "Classification: selected ({verdict})" / "Classification: not selected" | local selection state (the player's own input; the workspace selector) |
| Response | "Response actions taken: {n}" plus at most ONE static prompt (below) | the D4 `related_actions` count |
| Ready | "Ready to submit" / pending | card `ready` |

The locked strip's "Investigate evidence" step has no observable
completion state (investigation is reading) and does not survive as a
checklist line; investigation remains implicit (flagged in A1-B.7 as a
deliberate drop, not an oversight).

**LEAK RULE (binding):** every line renders identically for every
incident regardless of the answer key. The response line shows only the
count taken plus at most one STATIC prompt — proposed final: "Consider
whether containment or remediation is needed." — that appears for EVERY
incident, including inaction scenarios, with identical wording. Its
presence, absence, or phrasing must never vary with hidden
expectations; it never shows a target count or denominator
(required-action counts are hidden answer-key information). The line
set, line order, and line copy are constants; only the observable
numbers and the local selection vary. Leak analysis over the set: every
input is player-derived or roster-observable (A1-B.2 enumeration); no
input distinguishes attack from FP from inaction scenarios beyond what
the player already sees; the planted-marker battery adds the checklist
and toast renderers to its named pre-submission surface list.

**Mode presentation:** the checklist and factual toasts are
mode-universal (observable, answer-free). The static consider-prompt is
coaching: it renders in Guided and SOC Queue and is SUPPRESSED in
Hardcore (no coaching there; the count line stays) — surfaced as
B-OD-5 because it reads two kickoff clauses together.

### A1-B.4 Post-submission payoff (Phase 5)

#### A1-B.4.1 The sequence

1. **Case Closed moment** (restrained): on submit success, a single
   static completion moment naming the incident ("Case Closed:
   INC-####") with the earned achievement labels. No looping animation,
   no sound, honors `prefers-reduced-motion`; one render per
   submission.
2. **Grade reveal:** the Incident Grade (composite + components),
   labeled per the 3.9B distinction (Incident Grade, never Session
   Performance).
3. **The review:** what you did well (completed required actions,
   correct dispositions), what you missed, what was unnecessary or
   harmful (each with the frozen whys), per-detection verdicts, the
   playbook, and **Key takeaway**.

#### A1-B.4.2 Key takeaway (zero new authoring)

Key takeaway is RENDERED FROM the Tier 2 scenario paragraph (the
ratified D2 `expected_response` field, frozen into the record as
`scenario_rationale` at submit). It is a presentation heading over
existing content, not a third authored content type; this delta creates
ZERO new authoring lines. Where a record froze `scenario_rationale:
null` (scaffold ruling H, unchanged), the Key takeaway section is
omitted and the Tier 1 whys still teach — the ruling-H interplay is
recorded, not altered.

#### A1-B.4.3 Achievements (deterministic, frozen-record-only)

Computed at render time from the served submitted grading record —
never stored, never tracked, mode-universal (they are final results,
permitted in Hardcore). Proposed set with per-achievement derivation
(the frozen fields that prove it):

| Label | Derivation (frozen record fields) |
|---|---|
| Case Closed | the submitted record exists (`state == "submitted"`); subtitle "All {detection.total} detections reviewed" — the readiness gate makes full triage structurally universal at submit, so "Complete Triage" folds into this subtitle rather than standing as a separate label (flagged in A1-B.7) |
| Clean Triage | `report_card.detection.accuracy == 100` (equivalently: every `response_review.detections[].correct` true) |
| Response Ready | `report_card.response.accuracy == 100` (for inaction scenarios this is clean hands) |
| No Collateral | `report_card.response.collateral == 0` |
| Solo Close | `assisted == false` (the flag rides the immutable record) |
| Perfect Case | `report_card.composite == 100` |

**Deferred list (require NEW behavior tracking; per-item cost; DEFERRED
unless the owner rules otherwise):**

| Deferred achievement | Tracking cost |
|---|---|
| Tool-usage labels (First Pivot, Query Author, Timeline Diver) | a new client interaction-event store + leak review of anything serialized; no such tracking exists |
| Speed labels (Swift Close) | an additive frozen record field (drip-to-submit duration); byte-identity test extension + record-schema disclosure — new tracking even though low leak risk |
| Run-level labels (Clean Run: every incident in a run at 100) | derivable from stored records at render, but it is streak-shaped; per the kickoff, no points, streaks, leaderboards, or currency without a separate owner ruling |
| Cross-session labels | server or local persistence that does not exist; see the A1-B.5.5 research report |

#### A1-B.4.4 One durable Learning Review venue (B-OD-1)

Two candidate structures, one recommendation; either way there is
exactly ONE teaching surface:

- **Option 1 (RECOMMENDED): the Metrics/Analytics tab becomes the
  per-incident Learning Review home.** The Incidents completed pane
  shows the Case Closed summary (moment + grade + achievements) and a
  "Review what you learned" path into the Learning Review; the tab
  hosts the full teaching content (buckets + whys, attempt history,
  per-detection verdicts, playbook, Key takeaway) for any submitted
  incident, durably revisitable. Conditions: the in-workspace review
  modal's teaching content MOVES (the modal never renders teaching
  content again — one venue); the tab keeps the 3.9B labeling rule
  with an explicit per-incident selector ("Learning Review, Incident
  Grade") separated from "Session Performance". Rationale: the payoff
  content outgrew a modal; durability and revisitability are the
  point; Incidents stays focused on working cases.
- **Option 2: the single review modal remains the venue**, enriched in
  place. Cheaper (no relocation), but the modal is transient and
  cramped for the full sequence, and Metrics then must never grow
  per-incident teaching of its own (or two surfaces exist).

### A1-B.5 Help model (Phase 6, replacing first-run-only onboarding)

#### A1-B.5.1 Always-available control tooltips (all modes)

Once-only callout persistence is retired as the primary model. Control
explanations become permanently available accessible tooltips —
**Promote, Dismiss, Reopen, Feed/Threats, `==`, `!=`, Pivot, Expanded
search** (the last under Delta A; under B-only, the scope toggle) —
every visit, all modes: controls are always understandable. Reading of
inherited invariant 7, recorded: tooltips are passive, player-invoked,
mechanics-only explanations, not tutorial interruptions, so Hardcore
may carry them; coaching stays out of Hardcore.

#### A1-B.5.2 The Guided hint flow ("Need a hint?")

Guided mode adds an optional hint flow, allow-list gated
(`HINT_MODES = {"guided"}`, the GUIDED_MODES pattern; Hardcore and SOC
Queue excluded by default):

- **Level 1 — mechanics help:** static copy ("how do I review a
  detection / run a query / submit").
- **Level 2 — generic investigation nudges:** a static,
  scenario-independent library (e.g. "Check which account appears
  across the flagged events."), optionally filtered by the ACTIVE
  SURFACE only.
- **Level 3 — scenario-specific guidance:** NOT committed; costed in
  A1-B.5.4 and surfaced as B-OD-2.

**Neutrality rule (binding, verbatim from the kickoff):** Level 1 and
Level 2 hint availability, ordering, and wording must not depend on the
active scenario's hidden answer key, expected actions, detection truth,
grading state, or correctness. They may depend only on the visible
surface, the control the player asks about, and the hint level the
player explicitly selects. (Enforced structurally per A1-B.2.)

**Hardcore:** accessible tooltips only. No coaching, nudges, hints, or
reward popups beyond factual confirmations (A1-B.3.1 toasts) and final
results (the post-submission payoff).

#### A1-B.5.3 Hint-level content-sourcing table

| Level | Content | Source | Scenario-dependent | Modes | Cost |
|---|---|---|---|---|---|
| Tooltips | per-control meaning (one line each) | `uiCopy.js` constants | No | All | copy only (8 controls) |
| L1 | task mechanics (how-to) | `uiCopy.js` constants | No (surface-keyed) | Guided | copy only (~6-8 entries) |
| L2 | generic investigation nudges | static client library | No (surface-filtered at most) | Guided | copy only (~10-20 entries) |
| L3 | scenario-specific guidance | server-side, per-scenario authored | YES | Guided, explicit request, marks Assisted | measured below; NOT committed |

#### A1-B.5.4 Level 3 cost measurement (surfaced, not committed)

Per the 5A costing rule, measured across all 20 scenarios: authoring
**2-3 hints x 20 scenarios = 40-60 authored answer-adjacent lines** —
a second authoring pass of roughly Tier 2 scale, review-gated,
per-scenario commit cadence. Serving: the Check Answer precedent
applies (explicit player request, Guided-only allow-list, marks the run
Assisted, served server-side) but the payload is authored prose, not a
boolean — this would be the FIRST pre-submission answer-bearing prose
serving path in the game, requiring a new endpoint or Check Answer
extension, planted-marker and leak-guard extensions, denylist review of
every hint line, and its own permanent test battery. That risk class,
not the authoring volume, is the dominant cost. **B-OD-2:** rule it in
(with the above scope) or leave it out of Stage 5; this draft
recommends OUT (defer), consistent with the locked Tier 3 precedent.

#### A1-B.5.5 Local progression research (report only; no decision)

Researched per the kickoff; the owner decides venue and timing
(B-OD-4):

- **Feasibility:** Guided `catalog_id` is a stable salted digest of the
  scenario label (`_catalog_id_for`, app.py:4012; salt
  `spectyr-guided-catalog-v1`) — deterministic across sessions and
  restarts, opaque, answer-neutral: a safe local key.
- **Shape:** `localStorage["spectyr_progress_v1"]` =
  `{ "<catalog_id>": { "completed": <int>, "best_composite": <int>,
  "best_grade": "<letter>", "last_completed": "<iso>" } }` — under 2 KB
  for 20 scenarios; written only when a submitted record renders in
  Guided (the player's own results, post-boundary data).
- **Cost drivers:** the store itself is trivial (S). The real cost is
  UI on the Guided catalog (best-grade/completed badges on a reviewed
  answer-neutral surface) plus tests. The server catalog payload is
  unchanged, so `test_guided_catalog.py` is untouched; badges render
  from local data only. A small leak review is still owed: the badge
  layer must render identically for unplayed scenarios (no
  server-derived variation).
- **Assessment:** small enough for Stage 5 mechanically (S overall);
  equally separable to final polish with zero coupling. **Reported;
  not decided.**

### A1-B.6 Replacement and new acceptance criteria

**Replacing §19.8 (same testability bar):**

- **8.** Control tooltips are available on every visit in every mode
  and explain mechanics only (copy denylist). The hint flow exists
  only in Guided by allow-list (never Hardcore or SOC Queue); Levels
  1-2 render from static scenario-independent sources whose
  availability, ordering, and wording never vary with hidden state
  (structural input test); Hardcore renders no coaching, nudges,
  hints, or reward popups beyond factual confirmations and final
  results.

**New criteria (folded in as §19.17-19 upon ratification):**

- **17.** Toasts fire for exactly the A1-B.3.1 trigger list and nothing
  else; no toast duplicates a persistent surface's announcement; T2/T3
  toasts render only fields from the action response, shape-identical
  across required, acceptable, and collateral targets.
- **18.** Every checklist line renders identically for every incident
  regardless of the answer key: constant line set, order, and copy;
  the static response prompt (where the mode shows it) is byte-
  identical for every incident including inaction scenarios; no line
  ever shows an answer-key-derived total (planted-marker + copy-scan
  proven).
- **19.** The Case Closed moment, achievement labels, and Key takeaway
  derive deterministically from the submitted record alone
  (byte-identical on re-render), appear only post-submission, and the
  teaching content renders in exactly ONE venue.

### A1-B.7 Delta B supersession map (complete)

Dispositions as in A1-A.7.

| # | Locked item | Disp. | Governing text / note |
|---|---|---|---|
| 1 | §12.1 concept inventory | T | A1-B.5 — every concept re-homed: controls -> tooltips; reviewed/telemetry/Ready/review meanings -> checklist lines + L1 mechanics; scope concept per A1-P.2 |
| 2 | §12.2 form: five anchored first-run callouts, dismiss/dismiss-all | S | A1-B.5.1 — permanent tooltips + on-demand hints; callout machinery retired |
| 3 | OD-6 (callouts for five moments; tooltips for ==/!=/Pivot) | S | A1-B.5.1 — tooltips extended to the full control list; callouts retired (re-ruling pending ratification) |
| 4 | §12.2 gating: `ONBOARDING_MODES` allow-list | T | A1-B.5.2 — `HINT_MODES = {"guided"}` for hints; tooltips mode-universal under the recorded invariant-7 reading |
| 5 | §12.2 answer-free rule + copy denylist test | T | A1-B.2 — extended over tooltips, hints, toasts, checklist |
| 6 | §12.2 "not a separate tutorial mode" | U | Holds for the hint flow |
| 7 | §12.3 / OD-7: `spectyr_onboarding_v1` persistence; reopen via Docs + "Show tips again" | S | A1-B.5.1 — no once-only persistence to manage; reopen path moot (re-ruling pending ratification) |
| 8 | §13 D5 row (onboarding persistence, client-only) | S | Superseded; the only candidate localStorage use is the A1-B.5.5 progression store, undecided (B-OD-4) |
| 9 | Scaffold ratified decision: the `spectyr_onboarding_v1` key layout (2.6) | S | Superseded with D5 |
| 10 | §19.8 acceptance | S | A1-B.6 replacement 8 |
| 11 | Contract risk R6 (onboarding leaks into Hardcore or nags) | T | Translated + extended: allow-listed hints; passive tooltips; the toast trigger list + no-duplication rule are the new anti-nag mitigations; checklist leak rule guards the new surface (A1-B.6 criteria 17-18) |
| 12 | §10.1 canonical vocabulary | A | Gains toast + checklist rows (additive; existing rows unchanged; "Reopened (needs review again)" and the remaining-count string reused verbatim in T1) |
| 13 | §15 threat (d) (onboarding copy carrying answers) | T | Extended over toasts, checklist, hints (A1-B.2 enumerated-inputs discipline) |
| 14 | §16 onboarding-callout accessibility bullet | T | Tooltips keyboard-reachable (`aria-describedby`); toasts `role="status"`/`aria-live="polite"`, never steal focus, dismissible, reduced-motion honored; Case Closed moment static under reduced motion |
| 15 | §17 row 5.5 | S | A1-B.6 test surface: tooltip availability/all-modes; hint allow-list + structural input test; toast trigger-list exactness; checklist leak battery; achievement determinism |
| 16 | §18 workflow 1 (first-run callouts appear once, absent after Practice Another) | T | Tooltips present every visit; hints on request mark nothing below L3; toasts fire per trigger list; payoff sequence + Key takeaway + achievements verified; re-open byte-identical |
| 17 | §18 workflow 7 (Hardcore purity) | T | Zero hints/coaching/prompt line; tooltips present; factual toasts permitted; payoff after submission permitted; timer flows unchanged |
| 18 | §6 journey steps 1-3, 5-7 | T | Narrative re-reads: always-available help; step 5-6 gain Case Closed -> grade -> review -> Key takeaway; step 7's "explainers do not reappear" becomes moot (nothing is once-only) |
| 19 | §7.1/7.2/7.3 breakdown contract; OD-1..4 | U | Untouched — A1-B.4 renders ON the ratified data; Key takeaway is a heading over D2 content (zero new content types, reaffirming OD-1/OD-3) |
| 20 | Scaffold ruling H (null `scenario_rationale`) | U | Interplay recorded: Key takeaway omitted when null; Tier 1 whys remain |
| 21 | Scaffold ruling A (related-activity count only, no list) | U | Reaffirmed: the checklist response line consumes the D4 COUNT; nothing resurrects the list |
| 22 | Scaffold §2.2 + Phase 2 commits | T | A1-B.8 — renamed "Live Progress and Reinforcement"; toasts + checklist added |
| 23 | Scaffold §2.5 + Phase 5 commits (esp. 5.4 modal UI) | T | A1-B.8 — payoff sequence + achievements + Key takeaway + venue per B-OD-1 |
| 24 | Scaffold §2.6 + Phase 6 commits | S | A1-B.8 — help-model replacement |
| 25 | Scaffold §5 copy rows: onboarding concept copy; "Show tips again"/"Don't show tips" | S | Retired with the callout model |
| 26 | Scaffold §5 row: pivot first-use explainer + Phase 3's explainer slot (2.3/6.2) | T | Becomes the Pivot tooltip + L1 hint content; the once-only banner slot is retired |
| 27 | Scaffold §8 traceability row 8 | S | Re-mapped to A1-B.6 criteria (8, 17-19) |
| 28 | Scaffold §9 R6 row | T | Per map row 11 |
| 29 | Scaffold §10 workflows 1, 7 | T | Per map rows 16-17 |
| 30 | Scaffold §12 sizing rows 2, 5, 6 | T | Re-estimated in A1-B.8 |
| 31 | §5 inherited invariant 7 (Guided may teach; Hardcore no tutorial interruptions) | A | Reading recorded: passive player-invoked tooltips are not interruptions; coaching remains Guided-only |
| 32 | §22 rows 5-6 (HTB, TryHackMe) | A | A1-B.1 records the feedback-model reading |
| 33 | OD-9 (Feed/Threats subcopy) | U | Subcopy stands; its text seeds the Feed/Threats tooltip content |
| 34 | PhaseStrip "Investigate evidence" step | S | No observable completion state exists; dropped from the checklist line set (deliberate, flagged) |

### A1-B.8 Scaffold delta (applied to the scaffold only after ratification)

**Phase 2 — renamed "Live Progress and Reinforcement". Size M -> M-L.**
- *Gains:* the toast system (trigger list T1-T5, exclusions, mode
  carve-out, a11y, trigger-exactness tests); the checklist evolution of
  `PhaseStrip` (line set incl. the classification line and static
  prompt; leak battery per A1-B.6.18); the no-duplication rule tests.
- *Keeps:* the vocabulary module + canonical-copy test (10.1 sweep),
  D4 + guards (the count now also feeds the checklist), completed
  strip, 0-of-0 regression, forbidden-phrase scan.
- *Loses:* nothing.
- Commit shape: 2.1 as locked; 2.2 as locked + checklist line set;
  new 2.4 **[STOP]** toasts (trigger list + tests + a11y).

**Phase 5 — post-incident review teaching. Size L (grown).**
- *Gains:* the Case Closed moment; achievements (derivation set +
  determinism tests); Key takeaway section (renders
  `scenario_rationale`; zero new authoring); the venue restructure per
  B-OD-1 (under Option 1, commit 5.4 reshapes: teaching content renders
  in the Learning Review home; Incidents gains the Case Closed summary
  + path).
- *Keeps:* the ENTIRE D1/D2 data plan, scorer-reuse conditions (ruling
  B), freeze/byte-identity/reconciliation tests, Tier 1/Tier 2 plan and
  cadence, ruling H.
- *Loses:* nothing. The growth is UI-side only; the swing item is the
  venue restructure.

**Phase 6 — help model (replaces the locked onboarding phase). Size M
(recomposed, comparable).**
- *Loses:* anchored-callout machinery, once-only persistence,
  dismiss/dismiss-all, the Docs/Help reopen path, the D5 key layout.
- *Gains:* permanent accessible tooltips (8 controls); the "Need a
  hint?" flow (L1/L2 static libraries; `HINT_MODES` gating; the
  structural neutrality test); Hardcore purity assertions
  (tooltips-only + no prompt line).
- *Keeps:* the denylist pattern, the answer-free rule, the allow-list
  pattern, `uiCopy.js` sourcing, the [STOP] review of all new copy.

**Direction, stated honestly: Delta A shrinks the stage; Delta B grows
it. Net with both ratified:** Phase 1 S-M (down), Phase 2 M-L (up),
Phase 3 S-M (flat), Phase 4 S (untouched), Phase 5 L grown (up),
Phase 6 M (flat, recomposed), Phase 7 M (workflow translations only) —
**the stage lands modestly LARGER than the locked scaffold**, with the
growth concentrated in Phases 2 and 5 and partially offset by Delta A's
Phase 1 shrink.

### A1-B.9 Owner decisions surfaced (not made)

- **B-OD-1 — Learning Review venue.** Option 1 (Metrics/Analytics
  becomes the per-incident Learning Review home; Incidents shows the
  Case Closed summary + "Review what you learned" path) vs Option 2
  (the review modal remains). **Recommendation: Option 1**, with the
  one-venue conditions in A1-B.4.4.
- **B-OD-2 — Level 3 scenario-specific hints.** Measured at 40-60
  authored answer-adjacent lines + the first pre-submission
  answer-bearing prose serving path (A1-B.5.4).
  **Recommendation: defer** (out of Stage 5), consistent with the
  Tier 3 precedent.
- **B-OD-3 — deferred achievements.** The A1-B.4.3 deferred list with
  tracking costs; any promotion is its own reviewed addition. No
  points, streaks, leaderboards, or currency without a separate owner
  ruling (restated).
- **B-OD-4 — local progression store.** The A1-B.5.5 research report;
  Stage 5 vs final polish is the owner's scheduling call. Reported,
  not decided.
- **B-OD-5 — the Hardcore prompt carve-out.** The checklist's static
  consider-prompt renders in Guided and SOC Queue and is suppressed in
  Hardcore (count line stays), reading the leak rule and the Hardcore
  no-coaching rule together. Confirm or adjust.

---

## A1-R. Ratification record (owner; append-only)

| Delta | State | Date | Notes |
|---|---|---|---|
| Delta A — case-constant scope | **RATIFIED** | 2026-07-25 | As recommended; rulings in A1-R.1 |
| Delta B — learning feedback | **RATIFIED** | 2026-07-25 | As recommended, two owner adjustments; rulings in A1-R.1 |

### A1-R.1 Owner ratification rulings (2026-07-25)

The owner ratified BOTH deltas with every drafted recommendation
standing, plus two adjustments stated in the ratification directive.
Resolution of each surfaced decision:

- **A-OD-1 (naming):** the A1-A.5 proposed finals are RATIFIED as
  canonical ("Investigating INC-####", "All activity", "INC-####
  evidence", "Expanded search", "Searching all evidence. Your case
  INC-#### stays open.", "Return to INC-#### evidence", "Search all
  evidence", and the return subcopy).
- **A-OD-2:** NO expand action on Detections or Endpoints — the SIEM is
  the hunting surface; the pages stay single-purpose.
- **A-OD-3:** the All Activity state contents per A1-A.3 row 1 are
  CONFIRMED, and the surfaced error narrowing is CONFIRMED: the
  case-evidence error-empty state offers Retry only (no broadening
  control exists on the data pages; the explicit exit lives on
  Incidents).
- **A-OD-4:** search-all placement RATIFIED as recommended: the state
  label adjacent to the query bar ("INC-#### evidence") with "Search
  all evidence" beside it; the return action renders in the
  expanded-search block.
- **B-OD-1 (venue):** Option 1 RATIFIED — the Metrics/Analytics tab
  becomes the per-incident Learning Review home with the one-venue
  conditions of A1-B.4.4 (the in-workspace modal never renders teaching
  content; the Incidents completed pane shows the Case Closed summary
  and the "Review what you learned" path; Incident Grade vs Session
  Performance labeling preserved with a per-incident selector).
- **B-OD-2:** Level 3 scenario-specific hints DEFERRED (out of
  Stage 5), consistent with the Tier 3 precedent.
- **B-OD-3:** the deferred achievements remain DEFERRED with their
  recorded tracking costs; no points, streaks, leaderboards, or
  currency without a separate owner ruling.
- **B-OD-4:** the local progression store is DEFERRED (out of Stage 5;
  a final-polish candidate). No client store ships in Stage 5.
- **B-OD-5 (OWNER ADJUSTMENT — narrower than drafted):** the
  checklist's static consider-prompt ("Consider whether containment or
  remediation is needed.") renders in **Guided ONLY** — suppressed in
  SOC Queue AND Hardcore (the draft proposed Guided + SOC Queue). The
  count line renders in all modes.
- **T1 (OWNER ADJUSTMENT — the sealed-roster note):** the disposition
  toast's remaining-count line derives from the shared roster and
  renders only once the incident's roster is SEALED; before seal, or
  for a disposition belonging to no sealed incident roster, the toast
  confirms the disposition alone (the checklist's telemetry line
  already announces loading). This binds A1-B.3.1 trigger T1.
- **Section 19 numbering:** Delta B's three new criteria take
  **19.17-19**, final per the owner-directed merge order (Amendment 1
  before Amendment 2; the corresponding record lives in Amendment 2's
  A2-R.2).
- **Scaffold application:** this ratification authorizes applying
  A1-A.8 and A1-B.8 (with the two adjustments above) to the
  implementation scaffold in the consolidated scaffold update.

*Amendment 1 drafted 2026-07-25 at baseline `2e74b86` on branch
`stage-5-amendment-1`; gates ALL GREEN at baseline (backend 27 suites;
frontend 18 suites / 173 tests). This draft is docs-only: the locked
Revision 3 text above is byte-unchanged; the implementation scaffold
document is untouched (its deltas are drafted in A1-A.8 / A1-B.8 and
applied only after ratification); owner asset files untouched; nothing
pushed; no product code, no Phase 1. The deltas are ratified
independently; this task ratifies nothing.*

---
---

# AMENDMENT 2 — GUIDED SIEM SEARCH AND QUERY CLARITY (RATIFIED)

**Status: RATIFIED — owner rulings recorded in A2-R, 2026-07-25. The
A2-R rulings are the governing finals wherever they differ from the
drafted body below (three drafted string families are superseded there).
The Section 19 criteria numbering assignment is FINAL (A2-R.2): the
Amendment 1 ratification was subsequently recorded (A1-R, merge
`935f824`) and the appendices are ordered on one branch — Amendment 1
Delta B = 19.17-19; Amendment 2 A2-AC-1..7 = 19.20-26.**
Drafted 2026-07-25 on branch `stage-5-amendment-2` at repository baseline
`main` `2e74b86` (the Stage 5 scaffold-approval merge; gates re-verified
ALL GREEN on this branch at this baseline: backend 27 suites, frontend 18
suites / 173 tests, both runs 2026-07-25). Appended AFTER the locked
Revision 3 text through the recorded amendment discipline. **The locked
text above is byte-unchanged; no locked clause is edited, annotated,
retitled, retagged, or marked in place. All supersession marking lives
here; where a ratified item below differs from the locked text, this
appendix is the governing record for that item.**

## A2-P. Preamble

### A2-P.1 Independence from Amendment 1

Amendment 2 is INDEPENDENT of Amendment 1 (drafted separately on
`stage-5-amendment-1`; not present in this baseline's text): it is
approvable, revisable, or rejectable on its own. Every reference to
Amendment 1's case-constant model defines both readings:

- **Delta A ratified:** an entity pivot enters the Expanded search state
  (the expanded-search block is the transition surface; return =
  "Return to INC-#### evidence").
- **Delta A not ratified (locked model):** an entity pivot performs
  today's Session-wide flip (the locked 8.2 transition banner is the
  surface; return = the "Back to INC-####" chip / 11.4 controls).

The verb grammar, chips, error taxonomy, placeholder, surrounding-events
return, and invariant test below are label-stable and mechanism-stable
under both readings. Where Amendment 1 Delta B's tooltip set is
ratified, the ruled tooltips below join it; otherwise this amendment
carries its own permanent-tooltip requirement for exactly the controls
it names.

### A2-P.2 Owner playtest finding (recorded verbatim as evidence)

> The SIEM search experience is too cognitively heavy for a new player.
> No parser defect was demonstrated: the gray LCQL text was placeholder
> text, and Run was clicked with an empty field. The problems are
> usability: the placeholder resembles a real query; the editable query
> and the executed snapshot are not clearly separated; stale results
> persist unlabeled after failed or empty runs; sidebar value clicks,
> ==, !=, Pivot, Surrounding events, and Run overlap with no way to
> predict which action narrows, follows, opens context, edits, or
> executes.

### A2-P.3 Operator and Pivot ruling (recorded verbatim; governs A2-2.1)

> - Keep == and != as the primary visible labels.
> - Do not rename them to Only this or Exclude this.
> - Add permanent accessible explanations:
>   - ==: Show only events matching this value.
>   - !=: Exclude events matching this value.
> - Preserve the operators in the query and interface so Spectyr teaches
>   real LCQL concepts.
>
> Pivot remains the primary visible term, but receives clearer
> explanation:
>
> - Button label: Pivot
> - Tooltip/help: Follow this clue across all available evidence.
> - After execution, the transition surface names:
>   - the field and value followed
>   - whether the search expanded beyond the current incident
>   - how to return to incident evidence
>
> The goal is to teach Pivot, not replace the term.

Consequence, stated plainly: the kickoff's proposed primary-label
renames ("Only this", "Exclude this", "Follow this clue" as button
labels) are **considered and overruled** by this ruling. The locked F6
default (accepted symbols, not renamed) is therefore **reaffirmed, not
superseded** — the anticipated F6 supersession does not occur. What this
amendment adds over F6 is the exact permanent explanation copy (ruled
above), the effect-class grammar, and the transition-surface naming
requirements.

### A2-P.4 Presentation-only discipline and the deferral rule

Everything drafted below is presentation-layer: frontend components,
frontend-owned copy, the frontend generator module (`lcqlPivots.js`, the
sanctioned single query author, extended with one new remove/join form),
and TEST-ONLY extensions to `backend/test_lcql.py` (fixture corpus).
No engine, LCQL-grammar, endpoint, payload, scoring, or readiness change
is drafted. Anything that would require one is reported and DEFERRED
(register in A2-7): the bounded surrounding-events time window (question
8) and chip editing.

### A2-P.5 Ratification state

One state for the whole amendment, recorded in A2-R: **DRAFT** (current),
**RATIFIED**, or **RETURNED**. This task ratifies nothing.

---

## A2-1. Repository truth: the eight questions, answered at `2e74b86`

**Q1 — which interactions execute immediately, and which only edit the
bar?** Hypothesis CONFIRMED, with a complete inventory:

- *Execute immediately:* sidebar value clicks (`FieldSidebar.jsx:49`
  `onValueClick(field, '==', value)` -> `refineAndRun`, Siem.jsx:206-211,
  which generates via `refineFilter` and calls `execute`); inspector
  `==`/`!=` (`EventInspector.jsx:107,115` -> the same `refineAndRun`);
  Pivot (`EventInspector.jsx:124` -> `pivotAndRun`, Siem.jsx:224-231);
  Surrounding events (`EventInspector.jsx:229` -> `surroundingAndRun`,
  Siem.jsx:238-246); Run / Enter (Siem.jsx:493,501); Refresh
  (Siem.jsx:192-195, re-executes the snapshot's canonical query +
  executed scope, never the bar); the return chip
  (Siem.jsx:252-263 — loads the incident scope, then executes the
  CURRENT BAR TEXT under it, `execute(queryText, id)` at :260); descent
  requests (Siem.jsx:279-303).
- *Edit only (no request):* typing in the bar (Siem.jsx:492); the
  Timeframe select (`setTimeframe`, Siem.jsx:123-132 — rewrites the
  first segment in place); the empty-state example buttons
  (Siem.jsx:610-611, `setQueryText(ex)` only).
- *Neither (state only):* the Scope select (`selectScope`,
  Siem.jsx:115-118) changes the pending scope and loads the scope read
  but does NOT re-execute — the displayed snapshot remains the old
  scope's results until the next run; only the stale de-emphasis
  (`indicatorStale`, Siem.jsx:337-339) signals the divergence.

**Q2 — is Run enabled on an empty field?** Hypothesis CONFIRMED. The
Run button disables only on `running || scopeBlocked` (Siem.jsx:502);
an empty bar runs `execute('', scope)` and the parser rejects it:
`_split_segments('')` yields one segment, so `parse` raises
"expected 4 |-separated segments (TIMEFRAME | SENSOR_SELECTOR |
EVENT_TYPE | FILTERS), found 1" at position 0 (lcql.py:291-300),
rendered as "Parse error at position 0: …" (Siem.jsx:511). This is
exactly the playtest error: player error by construction, not a parser
defect.

**Q3 — how are placeholder, edited text, last executed, and canonical
represented?** Four distinct representations:

- *Placeholder:* the HTML `placeholder` attribute (Siem.jsx:490) set to
  `QUERY_PLACEHOLDER = '1h | Sysmon | ProcessCreate | command_line
  contains "powershell"'` (Siem.jsx:20-21), styled gray
  (`placeholder-[#8b949e]`, Siem.jsx:497) in the same monospace as run
  queries — a full realistic query with no "example" marking: the
  playtest confusion is faithful to the code.
- *Edited text:* `queryText` state (Siem.jsx:44).
- *Last executed / canonical:* `snapshot.identity.canonical_query`,
  echoed on the status line (Siem.jsx:526) AND written back into the
  bar after every successful run (`applySnapshot`, Siem.jsx:147) — so
  bar text equals the canonical until the player edits.
- *Divergence signal:* `indicatorStale` dims the new-count indicator
  when bar or scope differs from the executed identity
  (Siem.jsx:337-339, 530-533).

"Restore last working query" is frontend-only feasible: the canonical
is already held client-side.

**Q4 — how do Pivot and Surrounding events alter or preserve the prior
query, snapshot, and scope?**

- *Pivot* (Siem.jsx:224-231): mints a new query from the executed
  snapshot's TIMEFRAME token only (`splitSegments(...)[0]`), always
  sets scope to session, writes the bar, executes. The prior query is
  NOT stored; the return chip re-establishes the incident SCOPE over
  the CURRENT bar text (Siem.jsx:260), not the prior query.
- *Surrounding events* (Siem.jsx:238-246): generates
  `descentHost(hostname)` = `all | H | * | *` (lcqlPivots.js:179-181 —
  hardcoded `all`, so the view deliberately widens the timeframe),
  keeps the CURRENT scope (`execute(query, scopeParam)`), sets the
  timeline provenance `{kind:'surrounding', host, focusId, focusSeq,
  query}`, and REPLACES the snapshot.
- **Correction to the design assumption (negative answer): there is NO
  surrounding-events return today.** The banner's back button renders
  only for `timeline.kind === 'descent' && timeline.backView`
  (Siem.jsx:573-580); a surrounding view offers no return, the prior
  snapshot is not held anywhere, and the only exits are running another
  query or a pivot. The "ONE obvious return" in A2-2.5 is an ADDITION,
  not a reframe of an existing control.

**Q5 — what does the parse error carry, and can the errored section be
derived client-side?** Hypothesis CONFIRMED, frontend-only. `LcqlError`
carries a 0-based character position into the ORIGINAL query string, a
human reason, and optional near-match suggestions (lcql.py:45-53);
`/api/events/query` serializes exactly `{error: {position, reason[,
suggestions]}}` on 400 (app.py:2834, 2860-2866; the 300-cap variant at
app.py:2839-2841); the frontend already renders all three
(Siem.jsx:46, 175-179, 509-517). The client holds the submitted string,
and `splitSegments` (lcqlPivots.js:36-52) mirrors the backend's
quote-aware `_split_segments` (lcql.py:78-98), so the top-level pipe
offsets — and therefore the section (Time / Source / Event type /
Filters) containing any error position — are derivable client-side with
no backend change. Structure-level errors (segment count != 4 at
lcql.py:291-300, positioned at end-of-string or the extra pipe; the
300-character cap) name the structure rather than a section.

**Q6 — can the canonical filter section be decomposed client-side into
conjunctive chips, and regenerated on removal? Which shapes cannot?**
YES for the conjunction-only class, with an established boundary:

- The grammar is OR-of-AND-groups with no parentheses (GD-3,
  lcql.py:16, 174-230); canonical text joins AND-groups with
  `" or "` and predicates with `" and "`, single-spaced, raw values
  byte-preserved, and is idempotent (`canonical`, lcql.py:579-589).
  A conjunction-only query is exactly one AND-group
  (`conjunction_only`, lcql.py:498-504).
- The client already has the two needed mirrors: quote-aware segment
  splitting (`splitSegments`) and the quote-aware top-level-`or` scan
  (`isConjunctionOnly`, lcqlPivots.js:70-97), pinned to the backend AST
  verdicts by the shared ten-entry `OR_SCAN_CORPUS`
  (test_lcql.py:456-474; ported verbatim,
  workbench-pivots.test.js:170-196). Chip decomposition needs one more
  mirror of the same kind: a quote-aware top-level `and` split over the
  canonical FILTERS text — same mechanism, same equivalence boundary
  (valid ONLY while LCQL has no grouping; MUST BE REPLACED, not
  patched, if grouping arrives — the recorded lcqlPivots.js:55-69
  notice extends to it), pinned by the same shared-corpus pattern.
- Removal regenerates through the generator module: one new exported
  form (join the remaining conjuncts with `" and "`, `*` when none;
  TIMEFRAME/SENSOR/EVENT_TYPE preserved) added to `lcqlPivots.js` — the
  single query author gains a form, not a second author — and to the
  parity corpus.
- **Cannot decompose (renders the single "Custom filters" chip):** any
  FILTERS with a top-level `or` — hand-written OR queries, and notably
  two PRODUCT-GENERATED forms: the IP pivot (`source_ip == V or
  destination_ip == V`, lcqlPivots.js:153-155) and identity descent
  (`user_account == A or UserPrincipalName == A`,
  lcqlPivots.js:197-200). Hand edits that still parse decompose
  whenever they are conjunction-only (the projection reads the
  CANONICAL echo, so spacing/case variance is already normalized).
- **Verdict for the ship decision (A2-OD-3):** decomposition IS clean
  within the honesty rule — chips can ship in Stage 5 remove-only, with
  the OR-form pivots honestly rendered as the Custom filters chip.

**Q7 — do existing fixtures already prove every product-generated query
parses?** PARTIALLY — the pattern exists, closure does not:

- Exists: the 13-entry `_PIVOT_DESCENT_FIXTURES` corpus parses and is
  byte-canonical backend-side (test_lcql.py:413-440), and the frontend
  asserts its generator outputs equal that list byte-for-byte, in order
  (workbench-pivots.test.js:91-105) — every PIVOT and DESCENT form is
  proven end to end for one representative value each (backslash
  escaping exercised). One refine composition parses backend-side
  (`test_sidebar_conjunction_append_composes`, test_lcql.py:443-448);
  the OR-scan corpus pins the append-vs-fresh verdict both sides.
- Missing for closure: refineFilter OUTPUT shapes beyond the one append
  (the `!=` append, the fresh OR-fallback output, append-after-append,
  appends onto each documented pivot/descent canonical); adversarial
  values through `escapeValue` (embedded double quotes, spaces,
  reserved words, `*`/`|` characters) for every form; and, if chips
  ratify, the removal-join outputs. **The strengthened invariant test
  (A2-2.6) closes exactly this gap.**

**Q8 — would a bounded surrounding-events time window require LCQL or
backend changes?** YES, confirmed: TIMEFRAME is a closed token set
(`15m/1h/4h/12h/24h/all`, lcql.py:39) resolved at execution relative to
the pool (app.py:2868); the grammar has no absolute or event-anchored
range form. A window centered on an arbitrary event's timestamp is an
LCQL grammar extension or a backend query parameter — an engine change.
**OUT of this amendment; recorded as DEFERRED (A2-7).**

---

## A2-2. The design (normative; smallest shippable)

The structured query builder is explicitly NOT in this amendment.

### A2-2.1 Verb grammar (binding; per the A2-P.3 ruling)

Every SIEM control, its visible label, its permanent accessible
explanation, its effect class, and what announces the result. Labels
for `==`, `!=`, and Pivot are RULED (not open); the explanations for
`==`, `!=`, and Pivot are the ruled strings verbatim. Effect classes:
**narrows** / **follows** / **opens context** / **edits only** /
**executes**.

| Control | Visible label | Permanent explanation (tooltip/help) | Effect class | Announced by |
|---|---|---|---|---|
| Inspector equals | `==` (ruled) | "Show only events matching this value." (ruled) | narrows (executes immediately) | Refine notice family ("Filter added: …") + status line |
| Inspector not-equals | `!=` (ruled) | "Exclude events matching this value." (ruled) | narrows (executes immediately) | "Excluded: …" + status line |
| Sidebar value click | the value row (existing) | "Show only events matching this value." (same family; the existing `field == "value"` title kept as the technical detail) | narrows (executes immediately) | "Filter added: …" + status line |
| Pivot | `Pivot` (ruled; today's lowercase `pivot` at EventInspector.jsx:129 is corrected to the ruled casing) | "Follow this clue across all available evidence." (ruled), with the per-kind detail ("host timeline", "account activity", …) as a secondary line | follows (executes; new investigation focus) | The transition surface, which MUST name: the field and value followed; whether the search expanded beyond the current incident; how to return to incident evidence (ruled). Delta A reading: the expanded-search block. Locked reading: the 8.2 banner ("Scope changed…" + return path) |
| Surrounding events | `Surrounding events` (proposed keep; A2-OD-1) | "Show activity around this event." | opens context (temporary; executes under the CURRENT scope; widens TIMEFRAME to `all` by design) | The surrounding banner + the ONE return action (A2-2.5) |
| Hostname value link | the hostname (existing) | "Open {host} in Endpoints" (existing title) | opens context (Endpoints tab; no query) | The Endpoints view itself |
| Run Query / Enter | `Run Query` (existing) | "Run the query in the bar." | executes | Snapshot status line |
| Refresh | `Refresh` (existing) | "Re-run the last executed query." | executes (the snapshot's own definition, never the bar) | Status line |
| Return chip / action | locked: "Back to INC-####"; Delta A: "Return to INC-#### evidence" | (per governing model) | executes (re-scopes the current query) | Scope chip / block exit |
| Query bar typing | — | (bar aria-label existing) | edits only | The 11.3 edited note ("Edited. Results below are from the last run.") |
| Timeframe select | `Timeframe` (existing) | "Sets the query's time window (first segment)." | edits only | Same 11.3 edited note |
| Example buttons (empty state) | the example text | "Puts this example in the bar. Run executes it." | edits only | — (bar fills; nothing runs) |
| Scope select (locked model only) | existing | (per locked 11.x) | edits pending scope only (does NOT re-execute; repository truth Q1) | Stale de-emphasis until the next run |

The permanent-tooltip requirement stands under both Amendment 1
readings (A2-P.1): if Delta B's tooltip set ratifies, these entries
join it; otherwise Amendment 2 itself requires permanent accessible
tooltips for exactly `==`, `!=`, Pivot, and Surrounding events,
augmenting the existing `title` attributes (EventInspector.jsx:126 is
today's only pivot explanation), all modes.

### A2-2.2 Filter chips: a READ projection with remove (binding honesty rule)

- Chips render the EXECUTED canonical query's FILTERS section
  (`snapshot.identity.canonical_query`), never the editable bar text.
- Decomposition per Q6: conjunction-only canonical FILTERS (one
  AND-group) render one chip per predicate, showing the predicate's
  canonical text (`field op raw_value`, byte-preserved). Any other
  shape — any top-level `or`, including the IP pivot and identity
  descent forms — renders exactly ONE "Custom filters" chip that opens
  (focuses) the raw query in the bar. `*` renders no chips.
- **The honesty rule is binding: chips must never misrepresent the
  query.** The chip set either equals the canonical conjunct list
  exactly or collapses to the Custom filters chip; there is no partial
  projection.
- Removing a chip regenerates the query through the generator module's
  new remove/join form (Q6) and runs it (execute-immediately, matching
  the refine actions and the same A2-OD-2 decision). Chip editing is
  DEFERRED; chips are remove-only.
- The client `and`-split mirror carries the same equivalence-boundary
  notice as `isConjunctionOnly` and is pinned by a shared fixture
  corpus asserted against the backend AST decomposition (the
  OR_SCAN_CORPUS pattern: one corpus, two implementations, byte-equal
  verdicts).
- Ship-or-defer is the owner's call (A2-OD-3); this draft recommends
  SHIP in Stage 5, remove-only, on the Q6 verdict.

### A2-2.3 Empty and error behavior (binding error taxonomy)

Three classes, exhaustive:

1. **Empty (not an error).** Run disables ONLY when the bar is truly
   empty (`queryText.trim() === ''`). Guidance renders in place of an
   error: "No query entered." with the example affordance (the existing
   empty-state examples); when a snapshot exists, the preserved-results
   statement renders (the ratified 11.3 statements, CONSUMED here, not
   redefined). No request is ever issued for an empty bar. (The
   existing scope-error disable, Siem.jsx:120/502, is untouched — a
   second, independent disable condition is added.)
2. **Malformed non-empty (a teaching error).** The query RUNS — a
   well-named error teaches the language and a disabled button does
   not. The error box names the SECTION derived client-side from
   `error.position` against the submitted string's top-level pipe
   offsets (Q5): "Check the Time section." / "… Source section." /
   "… Event type section." / "… Filters section.", followed by the
   parser's reason and suggestions (both kept verbatim; the character
   position demotes to the technical detail rather than the headline).
   Structure-level errors (segment count, the 300 cap) render the
   structure line: "The query needs four sections separated by |."
   Prior results stay, labeled by the ratified 11.3 statement
   ("Displayed results are from the previous successful query.").
   A **"Restore last working query"** action renders whenever a
   snapshot exists and the bar differs from its canonical text: it
   sets the bar back to `snapshot.identity.canonical_query` and clears
   the error, issuing NO request (the displayed results already ARE
   that query's results, so the restore is instantly truthful).
3. **Generated-query failure (a defect, never a player error).** Any
   query minted by the generator module that fails to parse is a
   product defect by definition, guarded by the A2-2.6 invariant
   corpus. If one ever occurs live it renders as class 2, but its
   classification is DEFECT and the corpus test is the permanent
   regression net.

### A2-2.4 Placeholder (binding)

Example text must be visually unmistakable as non-executed guidance:
the placeholder becomes `Example: 1h | Sysmon | ProcessCreate |
command_line contains "powershell"` — the "Example: " prefix is part of
the placeholder text — and is styled distinctly from executed-query
text (italic, existing gray; never the plain monospace a run query
uses). It never resembles a run query; it vanishes on input as normal.
The empty-state help panel (Siem.jsx:597-624) is already truthful
(edit-only example buttons) and is unchanged apart from consuming the
same "Example" framing.

### A2-2.5 Surrounding events as temporary context (binding)

The player experiences a centered timeline over the selected event
(source event, entity, occurrence-ascending — the existing view) with
**ONE obvious return to the prior evidence view**. Repository truth
(Q4): no such return exists today, and the prior view is not held — so
this is an addition riding the existing mechanism, not a rebuild:

- On entering a surrounding view, the shell HOLDS the prior evidence
  view: the displayed snapshot object, its scope, and the bar text.
- The surrounding banner (existing slot, existing identity guard,
  reframed copy) gains the single return action **"Back to previous
  results"**: it restores the held snapshot object exactly (frozen
  redisplay — no request; the new-count poll resumes on the restored
  token, and a token invalidated by reset halts neutrally via the
  existing `countHalted` path), restores the bar text, and drops the
  surrounding provenance.
- The hold is single-depth, not a history stack: running anything else
  (a query, pivot, refine, chip removal) drops the held view, and the
  banner dies with its snapshot exactly as today (the
  `timelineActive` guard, Siem.jsx:352-353, unchanged).
- Scope is untouched in both Amendment 1 readings (surrounding runs
  under the current scope today and continues to). The banner copy
  states the deliberate widening: the view covers the host's full
  timeline (`all`), and the return restores the prior timeframe view.

### A2-2.6 The permanent invariant test: every product-generated query parses

Extending the established two-consumer shared-fixture pattern
(`_PIVOT_DESCENT_FIXTURES` + `OR_SCAN_CORPUS` precedents) to CLOSURE
over the generator module:

- A closed **generated-forms corpus**: every exported generator
  function (all pivots, both descents, `refineFilter`, and the chip
  remove/join form if ratified) x representative AND adversarial
  values (backslashes, embedded double quotes, spaces, reserved words
  `and`/`or`/`not`/`contains` as values, `*` and `|` characters — all
  of which `escapeValue`/quoting must neutralize), plus refine CLOSURE
  cases: an append onto each documented form's canonical output, an
  append after an append, the fresh OR-fallback output, and `!=`
  appends.
- Frontend: the generator outputs are asserted byte-equal to the
  corpus. Backend (`test_lcql.py`, tests only): every corpus string
  parses and is canonical-idempotent.
- Binding classification: a generated string failing this corpus — or
  failing live — is a DEFECT, never a player error (A2-2.3 class 3).

---

## A2-3. Copy table (every new or changed string; no em dashes)

| String | Source | Where |
|---|---|---|
| "Show only events matching this value." | RULED (A2-P.3) -> canonical | `==` tooltip; sidebar value family |
| "Exclude events matching this value." | RULED -> canonical | `!=` tooltip |
| "Pivot" (button casing) | RULED -> canonical | Pivot button label |
| "Follow this clue across all available evidence." | RULED -> canonical | Pivot tooltip/help |
| "Show activity around this event." | Kickoff direction -> canonical | Surrounding events tooltip |
| "Surrounding events" | existing, kept (A2-OD-1) | Button label |
| 'Example: 1h | Sysmon | ProcessCreate | command_line contains "powershell"' | NEW (supersedes the bare `QUERY_PLACEHOLDER`) | Query bar placeholder |
| "No query entered." | NEW | Empty-bar guidance (Run disabled) |
| "Check the Time section." / "Check the Source section." / "Check the Event type section." / "Check the Filters section." | NEW | Section-named parse errors |
| "The query needs four sections separated by |." | NEW | Structure-level parse errors |
| "Restore last working query" | NEW | Error box / edited-bar action |
| "Back to previous results" | NEW | Surrounding banner return action |
| "Custom filters" | NEW | Non-decomposable chip |
| "Remove filter: {field}" | NEW (aria label) | Chip remove control |
| "Run the query in the bar." / "Re-run the last executed query." / "Sets the query's time window (first segment)." / "Puts this example in the bar. Run executes it." | NEW | Run / Refresh / Timeframe / example tooltips |
| 11.3 statements ("Edited. Results below are from the last run."; "Displayed results are from the previous successful query.") | canonical (locked 11.3), CONSUMED | Preserved-results labeling |
| "Filter added: …" / "Excluded: …" / "Following clue: …" | canonical (locked 8.2), CONSUMED | Refine/pivot announcements |

All NEW strings follow the standing new-copy register (scaffold ruling
F): drafted at implementation, reviewed at their owning [STOP],
denylist- and em-dash-scanned; the strings above are the proposed
finals for A2-OD-1.

---

## A2-4. New acceptance criteria (testable; final §19 numbers assigned at ratification, avoiding collision with Amendment 1's proposed additions)

- **A2-AC-1 (empty-run).** With an empty query bar, Run is disabled,
  "No query entered." renders, no request is issued, and any existing
  results remain labeled by the ratified 11.3 statement.
- **A2-AC-2 (section-named errors).** A malformed non-empty query
  executes and produces an error naming the section (Time / Source /
  Event type / Filters) derived from the parser position, with the
  parser's reason and suggestions preserved; structure-level errors
  render the four-sections line; prior results persist with the 11.3
  statement.
- **A2-AC-3 (restore).** "Restore last working query" returns the bar
  to the executed snapshot's canonical text and clears the error
  without issuing a request.
- **A2-AC-4 (chip honesty; if chips ratify in).** Every rendered chip
  equals one conjunct of the executed canonical FILTERS byte-for-byte;
  any query with a top-level `or` renders exactly the Custom filters
  chip; removing a chip regenerates through the generator module and
  the regenerated query parses; no state exists where chips render a
  projection unequal to the canonical query.
- **A2-AC-5 (generated queries always parse).** The closed
  generated-forms corpus is byte-pinned frontend-side and parses
  (canonical-idempotent) backend-side; a failure is classified a
  defect, and no player-facing surface attributes it to the player.
- **A2-AC-6 (surrounding return).** Entering Surrounding events holds
  the prior evidence view; the banner offers exactly ONE return action
  while live; the return restores the prior snapshot, scope, and bar
  text exactly with no request; running anything else drops the held
  view and the banner dies with its snapshot.
- **A2-AC-7 (verb tooltips).** The ruled tooltips for `==`, `!=`, and
  Pivot and the Surrounding events tooltip are permanently available,
  accessible, and mode-universal; the Pivot transition surface names
  the followed field and value, whether the search expanded beyond the
  current incident, and the return path (in whichever Amendment 1
  reading governs).

---

## A2-5. Supersession map (complete)

Dispositions: **T** translated, **S** superseded, **U** unchanged
(inspected), **A** augmented (locked text stands; appendix adds a
binding addition or recorded reading).

| # | Locked item | Disp. | Governing text / note |
|---|---|---|---|
| 1 | §3 F6 — accepted symbols, not renamed; definitions to teach | U (reaffirmed) + A | A2-P.3 ruling reaffirms the default; A2-2.1 supplies the exact permanent explanation copy and effect classes. The kickoff-anticipated supersession does NOT occur |
| 2 | §12.2 OD-6, tooltip half ("plain tooltips for ==/!=/Pivot … accessible") | A | A2-2.1 — tooltips become permanent, mode-universal, ruled copy, extended to Surrounding events; standalone under Amendment 2 regardless of Amendment 1 (A2-P.1). Callout half untouched here |
| 3 | §8.2 first-use pivot explainer | U | Coexists with the ruled tooltip under the locked model; Amendment 1 Delta B (if ratified) relocates it — combination handled there, not here |
| 4 | §8.2 transition banner contents (clue naming; scope statement; origin/return) | A (reaffirmed as ruled requirements) | A2-2.1 Pivot row — the ruled three naming requirements are already satisfied by BOTH readings (locked 8.2 banner / Delta A block); recorded as binding |
| 5 | §8.2 "Filter added:" / "Excluded:" refine forms | U (consumed) | A2-2.1 announcements |
| 6 | §10.1 canonical vocabulary | A | Gains the A2-3 rows (additive) |
| 7 | §12.1 concepts "== and !=; Pivot" | U | Concepts stand; their content is now the ruled strings; delivery per whichever amendment governs Phase 6 |
| 8 | §11.3 edited-note + stale-results statements | U (consumed) | A2-2.3 consumes them verbatim; nothing redefined |
| 9 | §6 journey step 3 (==/!=/Pivot narration) | T | Narrative re-reads with the ruled explanations; the §6 copy-authority note stands |
| 10 | §9 / OD-5 inspector-connection work | U | Untouched by A2 (shares the merged review cycle only) |
| 11 | §17 row 5.2 (frontend tests) | A | Gains: verb-tooltip presence, empty-run gating, section-named errors, restore, placeholder form, surrounding hold/return, chip honesty (if in), the generated-forms corpus (frontend half) |
| 12 | §18 workflows 3 and 5 | A | The pivot-chain walk gains an empty-run attempt, a malformed run with section-named error, a restore, and a surrounding enter/return leg |
| 13 | §19 acceptance criteria | A | A2-4 criteria appended; numbering assigned at ratification (Amendment 1's draft independently proposes additions — collision resolved by merge order, noted in both) |
| 14 | Locked scope-error Run-disable rule (Stage 4 revised behavior; Siem.jsx:120,502) | U | A second, independent disable condition (truly-empty bar) is ADDED; the scope-error machine is untouched |
| 15 | `QUERY_PLACEHOLDER` bare-query placeholder (Siem.jsx:20-21) | S | A2-2.4 "Example:"-prefixed, distinctly styled placeholder |
| 16 | Pivot button lowercase label `pivot` (EventInspector.jsx:129) + title tooltip (:126) | S | A2-2.1 — ruled casing "Pivot"; ruled tooltip replaces the title text (per-kind detail demoted to secondary line) |
| 17 | Surrounding-events control + banner (no return; Siem.jsx:238-246, 552-583) | A | A2-2.5 — hold + single return ADDED; banner copy reframed; identity guard and view mechanics unchanged |
| 18 | "The generator remains the only query author" (§8.4 rule; lcqlPivots.js discipline) | A (reading recorded) | The chip remove/join form is a new GENERATOR form inside the same module — the author gains a form, no second author appears; pinned by the extended parity corpus |
| 19 | §5 inherited invariant 10 (Stage 4 query/snapshot/scope semantics intact) | U (verified) | No LCQL, endpoint, payload, or semantics change; backend touch is tests-only (A2-P.4) |
| 20 | Scaffold §2.3/§2.4 (Phase 3/4 plans), §6 Phase 3/4 commits, §8 rows 5-6, §12 sizing rows 3-4 | T | A2-6 scaffold delta (merged cycle gains the A2 work) |
| 21 | Scaffold ruling G (Phases 3+4, one review cycle, separable commits) | U | The venue this amendment's work lands in |
| 22 | Scaffold §5 copy rows (8.2/11.3 families) | U (consumed) + A | Existing rows unchanged; the A2-3 rows join the register |
| 23 | Empty-state help panel + `QUERY_HELP_EXAMPLES` (Siem.jsx:23-26, 597-624) | U | Already truthful (edit-only); consumes the Example framing only |
| 24 | Backend parse-error payload `{position, reason, suggestions}` (app.py:2834,2860-2866) | U | Consumed client-side for section naming; no payload change |

---

## A2-6. Scaffold delta (applied to the scaffold only after ratification)

All Amendment 2 work lands in the MERGED Phase 3/4 review cycle
(scaffold ruling G) — **no new phase**. The cycle's commits stay
concern-separated and independently revertible:

- **(3.1) as locked** (transition banner work, in whichever Amendment 1
  reading governs) **plus** the Pivot-row naming requirements of
  A2-2.1 (already satisfied by the banner/block content; asserted).
- **(3.2, new) query clarity:** ruled verb tooltips (==/!=/Pivot/
  Surrounding events) + placeholder change + empty-run gating with
  "No query entered." + section-named parse errors + "Restore last
  working query" + the generated-forms corpus (frontend half byte-pin +
  `test_lcql.py` tests-only extension).
- **(3.3, new, only if A2-OD-3 ratifies chips in) filter chips:**
  read-projection chips + Custom filters fallback + the generator
  remove/join form + the and-split mirror with its shared parity corpus
  + chip tests.
- **(3.4, new) surrounding return:** the held prior view + "Back to
  previous results" + banner reframe + hold/drop tests.
- **(4.1) as locked** (inspector connection, untouched by A2).

**Files (delta):** `Siem.jsx`, `EventInspector.jsx`, `FieldSidebar.jsx`
(tooltip only), `lcqlPivots.js` (remove/join form + corpus),
`uiCopy.js` (A2-3 strings), new `query-clarity.test.js` (+ chips test
file if in), extended `pivot-transitions.test.js`,
`workbench-pivots.test.js` (corpus port), backend `test_lcql.py`
(tests only). No endpoint or payload changes; `run_gates.py` lists
unchanged (both touched suites are already gates) apart from the new
frontend test file riding the existing frontend suite.

**Sizing:** locked Phase 3 **S-M** + Phase 4 **S**; the merged cycle
re-estimates to **M** (the kickoff's expectation, confirmed by the
gains list — the swing items are the error/empty taxonomy with its
tests and, if ratified in, chips). What the cycle gains: the verb
grammar surface, the error taxonomy, restore, placeholder, surrounding
return, the invariant corpus, and optionally chips. What it keeps:
everything locked for Phases 3 and 4. What it loses: nothing.

---

## A2-7. Owner decisions surfaced (not made) and the deferred register

- **A2-OD-1 — final labels and strings.** The `==`/`!=`/Pivot labels
  and their three explanation sentences are RULED and not open. Open
  for ratification: the Surrounding events label (recommend KEEP
  "Surrounding events" per the ruling's teach-the-term principle, with
  "Show activity around this event." as its explanation), the section
  names (Time / Source / Event type / Filters), "No query entered.",
  "Restore last working query", "Back to previous results",
  "Custom filters", the placeholder form, and the secondary tooltip
  lines (A2-3).
- **A2-OD-2 — refinement immediacy.** Current behavior (repository
  truth, Q1): sidebar clicks and `==`/`!=` EXECUTE IMMEDIATELY.
  **Recommendation: KEEP immediate** — every refine announces itself
  (the notice family), the executed canonical lands in the bar and
  teaches the form, and an Apply-batched model would add a pending
  state the honesty rules would then have to label. The batched
  alternative is recorded as weighed.
- **A2-OD-3 — chips in Stage 5 vs polish.** Informed by Q6:
  decomposition is clean for the conjunction-only class with an
  established boundary-and-parity pattern; OR-form product queries
  (IP pivot, identity descent) honestly collapse to the Custom filters
  chip. **Recommendation: SHIP in Stage 5, remove-only**, as commit
  (3.3); deferring to polish is the recorded alternative if the owner
  prefers zero new client mirrors this stage.
- **Deferred register (engine-touching; per A2-P.4):**
  - Bounded surrounding-events time window (Q8: TIMEFRAME grammar has
    no absolute or event-anchored ranges) — engine change, DEFERRED.
  - Chip editing (chips are remove-only) — DEFERRED.
  - Any structured query builder — explicitly NOT in this amendment.

---

## A2-R. Ratification record (owner; append-only)

| Amendment | State | Date | Notes |
|---|---|---|---|
| Amendment 2 — guided SIEM search and query clarity | **RATIFIED** | 2026-07-25 | Owner rulings below are the governing finals |

### A2-R.1 Owner ratification rulings (2026-07-25, recorded verbatim)

> - Labels: ==, !=, Pivot, and Surrounding events keep their technical
>   names. F6 stands reaffirmed.
> - Permanent tooltips (canonical finals, joining the Amendment 1
>   tooltip set, which grows to nine controls):
>   ==: "Show only events matching this value."
>   !=: "Exclude events matching this value."
>   Pivot: "Follow this clue across all available evidence."
>   Surrounding events: "Temporarily show activity around the selected
>   event."
> - Refines stay execute-immediately; no Apply state. The chips make
>   the change visible.
> - Chips ship IN Stage 5, remove-only. Removing a chip reruns the
>   query. Any top-level OR renders one "Custom filters" chip that
>   reveals the raw query. Binding boundary test: Custom filters never
>   renders for a conjunction-only query and always renders for any
>   top-level OR, including the IP-pivot and identity-descent product
>   forms.
> - Empty and failed searches: Run disables only when the field is
>   truly empty; the placeholder is unmistakably an example; add
>   "Restore last working query"; malformed queries name the broken
>   section. Canonical error form:
>   "This search was not run."
>   "The {Time / Source / Event type / Filters} section could not be
>   read."
>   "Displayed results are from the previous successful query."
>   (third line is the locked 11.3 string, reused verbatim, not a new
>   variant).
> - Surrounding events becomes reversible: single-depth hold, block
>   copy "Activity around the selected event on {host}" / "Occurrence
>   ascending" / "Back to previous results"; returning redisplays the
>   prior frozen snapshot with zero requests.
> - Deferred register ratified: bounded surrounding window (engine),
>   chip editing, structured query builder, autocomplete overhaul.
> All new strings pass the em-dash scan and denylist review.

### A2-R.2 Recording notes (what the rulings resolve and supersede)

- **A2-OD-1 resolved:** all four controls keep their technical names
  (Surrounding events included); the four tooltip strings above are the
  canonical finals. The ruled Surrounding events tooltip ("Temporarily
  show activity around the selected event.") SUPERSEDES the drafted
  "Show activity around this event." (A2-2.1 / A2-3).
- **A2-OD-2 resolved:** refines stay execute-immediately; the
  Apply-batched alternative is closed.
- **A2-OD-3 resolved:** chips ship in Stage 5, remove-only, rerun on
  removal; the boundary test in the ruling is BINDING and joins
  A2-AC-4 (Custom filters never for conjunction-only, always for any
  top-level OR, the two product OR forms included).
- **Canonical error form:** the ruled three-line form SUPERSEDES the
  drafted "Check the {Section} section." headline (A2-2.3 / A2-3).
  Line three is the locked 11.3 string reused verbatim. The
  structure-level line ("The query needs four sections separated
  by |.") stands for errors that precede section identification.
- **Surrounding block copy:** the ruled three strings ("Activity
  around the selected event on {host}" / "Occurrence ascending" /
  "Back to previous results") SUPERSEDE the drafted banner copy
  (A2-2.5); the single-depth hold and zero-request frozen-snapshot
  restore are ratified as drafted.
- **Deferred register ratified** with one ADDITION by ruling:
  autocomplete overhaul (joins bounded surrounding window, chip
  editing, structured query builder).
- **Em-dash and denylist:** every ruled string above contains no em
  dash; all NEW strings remain subject to the standing scans at
  implementation (scaffold ruling F).
- **Amendment 1 interaction, recorded at ratification time:** the
  pre-check found NO committed Amendment 1 ratification (its A1-R
  still reads DRAFT at `stage-5-amendment-1` tip `83f8175`; `main`
  tip `2e74b86` contains neither appendix). The ruling's
  "joining the Amendment 1 tooltip set, which grows to nine controls"
  therefore operates through A2-P.1's independence clause: Amendment 2
  carries its own permanent-tooltip requirement for `==`, `!=`, Pivot,
  and Surrounding events until Amendment 1 Delta B's ratification is
  recorded, at which point the four join its set (nine controls
  total). **Section 19 numbering assignment is PENDING** the same
  resolution: the owner-directed order (Amendment 1's additions as
  19.17-19, Amendment 2's A2-AC-1..7 as 19.20-26) is recorded here as
  the intended assignment and becomes final when the Amendment 1
  ratification is committed and the appendices are ordered on one
  branch.
- **Assignment FINAL (2026-07-25, recorded after the fact):** the
  Amendment 1 ratification was recorded (A1-R rulings commit `b6d11e7`,
  merged to `main` at `935f824`) and the appendices are ordered on this
  branch (Amendment 1 first, Amendment 2 second). The Section 19
  numbers are therefore FINAL: **Amendment 1 Delta B = 19.17-19;
  Amendment 2 A2-AC-1 through A2-AC-7 = 19.20-26.** The nine-control
  tooltip set is likewise in force: Delta B's eight (Promote, Dismiss,
  Reopen, Feed/Threats, `==`, `!=`, Pivot, Expanded search) plus
  Surrounding events, with the ruled A2 finals governing `==`, `!=`,
  Pivot, and Surrounding events.

*Amendment 2 drafted 2026-07-25 at baseline `2e74b86` on branch
`stage-5-amendment-2`; gates ALL GREEN at this baseline on this branch
(backend 27 suites; frontend 18 suites / 173 tests). Docs-only: the
locked Revision 3 text above is byte-unchanged; the implementation
scaffold document is untouched (its delta is drafted in A2-6 and applied
only after ratification); owner asset files untouched; nothing pushed;
no product code, no Phase 1. This task ratifies nothing.*


---
---

# AMENDMENT 3 — RETURN SEMANTICS, SURROUNDING-EVENTS REMOVAL, FINAL SUBMISSION, AND SIMPLE SEARCH (DRAFT)

**Status: DRAFT. This amendment is drafted for owner and reviewer
review; it governs nothing until the A3-R record reads RATIFIED. Four
items, ONE ratification: F2 (expanded-search return becomes the model B
back-stack restore), F3 (surrounding events removed from the
player-facing product), F4b (final submission gating), F7 (simple
search mode). They ship together in the Stage 5 closeout; the binding
internal sequencing is recorded in A3-P.3.**

Drafted 2026-07-26 at baseline `74198f2` on branch
`stage-5-amendment-3`. The baseline INCLUDES the C1 checkpoint fixes
(`a2cc3dc..74198f2`, docs/stage-5-checkpoint-fix-report.md): the
evidence-surface nav badges are deleted, the Learning Review buckets
conform to A1-B.4.1, the A1-B.3.2 workspace classification selector is
mounted, the interim failed-return guard is live, and the Reports nav
entry is hidden. Gates at the baseline: `run_gates.py --all` ALL GREEN
at the C1 product tip `80878da` (backend battery complete; frontend 27
suites / 253 tests); `74198f2` adds docs only. All file:line citations
below are at `74198f2` unless marked otherwise.

## A3-P. Preamble

### A3-P.1 Discipline and relationship to prior text

The locked Revision 3 text and the Amendment 1 and Amendment 2
appendices above are byte-unchanged by this draft and remain so at
ratification: per the established discipline, every supersession this
amendment makes is recorded HERE, in this appendix's per-item
supersession maps, and this appendix is the governing record for its
items upon ratification. Where this appendix and any earlier text
differ on an item this amendment covers, this appendix governs.

The C1 checkpoint fixes are part of the baseline, not of this
amendment: F4b builds ON the mounted workspace selector (C1 item 3),
and F2 SUPERSEDES the C1 interim scope-read guard (C1 item 4), both
stated explicitly below.

### A3-P.2 Owner rulings encoded (closed, not reopened)

The checkpoint-review directive rules the following; this amendment
ENCODES them as normative design and does not reopen them:

1. Model B replaces model A for the expanded-search return (F2), with
   the hold contents, lifetime, discard-on-return, repeat-pivot,
   stale-snapshot, and failed-query behaviors as specified in A3-2.
2. Equal tabs for case evidence / expanded search are REJECTED on the
   record (A3-2.7).
3. Surrounding events is REMOVED from the player-facing product (F3),
   with `descentHost()` and descent untouched, and the A2 hold
   machinery migrating to F2 rather than dying.
4. The checklist Ready line and the client Submit gate require every
   observable step INCLUDING a selected classification; Submit becomes
   a bare confirmation, never a data-entry step; the server gate is
   untouched (F4b).
5. Simple search ships as Option A: a frontend projection over
   canonical LCQL; no grammar, token, parser, endpoint, or
   snapshot-identity change; the `ip` alias is out of the first cut
   (F7).

### A3-P.3 One ratification; binding internal sequencing

The four items are ratified together and ship together in the
closeout. **Binding sequencing: F2 lands before F3, or the hold
migrates from the surrounding path to the expanded-search path in the
same commit.** Rationale: the single-depth hold and its zero-request
restore (`Siem.jsx:101-102` state; write `Siem.jsx:362-363`; restore
`Siem.jsx:374-394`) are today owned by the surrounding path. F3 alone
would delete them; F2 alone must not fork a second hold. The scaffold
delta (A3-8) encodes the ordering as commits A3.2 then A3.3.

### A3-P.4 Presentation-only discipline and the STOP rule

Everything in this amendment is presentation-layer: frontend
components, frontend-owned copy, the frontend generator module
(`lcqlPivots.js`, extended with the forms named in A3-5), and
TEST-ONLY corpus extensions in `backend/test_lcql.py`. No engine,
LCQL-grammar, token, parser, endpoint, payload, scoring, readiness,
sealing, or snapshot-identity change is drafted. **If implementation
surfaces any need for one, the rule is STOP and report** (the A2-P.4
deferral rule, restated as binding here); the item waits rather than
stretching.

### A3-P.5 Ratification state

One state for the whole amendment, recorded in A3-R: **DRAFT**
(current), **RATIFIED**, or **RETURNED**. This task ratifies nothing.

---

## A3-1. Repository truth at `74198f2` (verified mechanics each item builds on)

1. **The A2 hold.** `heldView` (`Siem.jsx:101`) holds
   `{snapshot, queryText, scope}` written ONLY at surrounding entry
   (`Siem.jsx:362-363`, with `preserveHoldRef` exempting that one run
   from the drop); ANY other `execute` drops it (`Siem.jsx:252-253`);
   `restoreHeldView` (`Siem.jsx:374-394`) restores snapshot, bar text,
   and scope with ZERO query requests, clears error/timeline/notices,
   resets the new-count indicator, and re-validates the selection
   against the restored rows. Pinned by
   `workbench-surrounding.test.js` (zero-request restore,
   single-depth drop).
2. **Expanded search** is derived, not stored:
   `Siem.jsx:192` `expandedSearch = !!(activeIncidentId && scope.kind
   === 'session')`. Entry sites: entity pivot (`pivotAndRun` sets
   session scope), `searchAll` (`Siem.jsx:199`), and the descent
   effect's no-context branch. Exit sites: `returnToIncident`
   (`Siem.jsx:401-421`, carrying the C1 guard: a failed scope read
   stays in session scope and renders `returnReadFailed` +
   the 11.3 honesty statement, `Siem.jsx:575-585`), the case-anchor
   effect (case change/exit), an incident-scoped descent entry, and
   reset.
3. **Model A return as ratified and landed:** the return re-runs the
   CURRENT BAR TEXT under the case scope after a fresh scope read
   (`Siem.jsx:404-411`); the bar text is retained, the rows change.
   Ratified by A1-A.2.4 and the A1-A.5 subcopy row; pinned by
   `workbench-cross-host.test.js` ("the return action re-runs the
   current query under the case participant scope").
4. **Surrounding events**: `EventInspector.jsx:231-247` control ->
   `surroundingAndRun` (`Siem.jsx:356-368`) -> `descentHost(hostname)`
   = `all | H | * | *` (`lcqlPivots.js:280-282`, TIMEFRAME hardcoded
   to `all`); the event id is ONLY a client viewport target
   (`SiemCards.jsx` / `SiemTable.jsx` focus effects); no timestamp
   predicate exists; no backend involvement exists (the query endpoint
   reads only `q` and `scope`). The tooltip set has exactly NINE keys
   (`helpContent.js:24-32`), `surrounding` among them.
5. **Submission flow at the C1 baseline:** the workspace selector is
   mounted on sealed active incidents and drives the checklist
   Classification line; the Submit control renders on
   `selected.sealed && selected.ready` (`Incidents.jsx:434`), and the
   modal flow (classifier `Incidents.jsx:461` -> category `:475` ->
   confirm `:487`) still performs classification data entry, arriving
   pre-filled. The server readiness gate excludes classification;
   `_valid_classification` enforces it inside `submit_incident`
   (400 `invalid_classification`) as the authoritative backstop.
   "Ready" renders from the server card field at THREE sites:
   `Incidents.jsx:291` (list chip), `Incidents.jsx:174-182` (Ready
   view + counts), `IncidentDashboard.jsx:115` (dashboard row chip).
6. **Query authorship:** `lcqlPivots.js` is the single generation
   chokepoint (module contract, `lcqlPivots.js:1-5`) with ONE
   documented bypass: the Timeframe picker's raw first-segment splice
   (`Siem.jsx:205-214`, `indexOf('|')`). The picker edits pending
   state only (A2-1 Q1, still true). The bar shows the executed
   canonical after every run (`applySnapshot` write-back); the
   canonical echo ("Results from:") and the scope token render from
   `snapshot.identity`, server-minted and HMAC-bound
   (`app.py:2872-2878`, `:2787-2796`).
7. **Error mapping:** the server serializes `{position, reason,
   suggestions?}` only; the section is derived client-side by
   `sectionIndexAtPosition` (`lcqlPivots.js:108-126`) over the
   SUBMITTED string, which rides the error (`Siem.jsx` execute).
   The ruled three-line error form and `STRUCTURE_LINE`
   (`uiCopy.js:132`) render it.
8. **Corpora:** `GENERATED_FORMS_CORPUS` is pinned two-sided at
   exactly 12 entries (`backend/test_lcql.py:514`,
   `query-clarity.test.js:232`); `_PIVOT_DESCENT_FIXTURES`,
   `OR_SCAN_CORPUS`, and `CONJUNCT_SPLIT_CORPUS` follow the same
   shared-fixture pattern. `SOURCE_FAMILIES` is the closed sensor
   family set (`backend/lcql.py:355-356`: Sysmon, Windows Security,
   Proxy, DNS, Firewall, Azure AD, Veeam, Defender).

---

## A3-2. ITEM F2 — the expanded-search return becomes model B

### A3-2.1 The model (normative)

Ratified model A (the return re-runs the current query under the case
scope) is SUPERSEDED. Model B: **entering Expanded search captures a
single-depth hold of the pre-entry state; "Return to INC-#### evidence"
restores it exactly, with zero requests.** The excursion is an
excursion: what the player had before expanding comes back
byte-identically; what they did while expanded is not carried home.

- **Entry** (any transition into `expandedSearch` true: entity pivot
  from case evidence, the search-all action, or the descent
  no-context branch while a case is pinned) writes the hold. Re-entry
  after an exit writes a NEW hold of the then-current case state.
- **Return** restores the hold and consumes it. No scope read, no
  query request: the C1 interim guard's failure mode (a failed scope
  read on return) becomes structurally unreachable and the guard is
  removed (A3-2.6).
- The return ACTION label stays the ratified A-OD-1 final
  ("Return to INC-#### evidence"); only its mechanics and subcopy
  change (A3-6).

### A3-2.2 Hold contents; what restores and what resets

The hold captures what the shell owns:

| Held | Restored |
|---|---|
| `queryText` (the bar as of entry) | exactly |
| `snapshot` (the executed frozen snapshot object, MAY BE NULL if no case-evidence run had happened) | exactly; a null snapshot restores the case-evidence empty state with the held bar text, still zero requests |
| `scope` (the case-evidence scope object incl. its sealed flag) | exactly; no re-read |
| `timeline` (the active view mode: a descent context, or null) | exactly; a held descent banner and its ascending order come back |

NOT held, by rule:

- **Row selection** is not held; on restore the existing
  selection-survival check runs (kept when the inspected id is in the
  restored rows, else cleared with the existing one-line notice) —
  the same behavior the A2 restore ships today.
- **Child pagination and sort reset on restore.** The results
  children own them (`SiemCards.jsx` page, `SiemTable.jsx`
  page/sort), the shell cannot capture them, and the amendment states
  this plainly rather than implying a pixel-perfect restore.
- The expanded excursion's provenance dies with the return: the
  pivot clue (`transition`), any query notice, and any expanded error
  are cleared; the new-count indicator resets and its poll resumes on
  the restored token (a token invalidated by reset halts neutrally via
  the existing `countHalted` path — the A2 restore mechanics,
  unchanged).

**Recorded edge (sealed-flag lag):** a hold captured pre-seal restores
`scope.sealed` as held, so the pre-seal telemetry note may briefly
out-live the actual seal until the next scope read (anchor, descent,
or Retry). Seal is monotonic and the note is observable-only; the lag
is accepted and self-corrects. No request is added to avoid it.

### A3-2.3 Hold lifetime (a change to the A2 hold, not a drop-in reuse)

**This is explicitly a LIFETIME change to the A2 hold, not a reuse.**
Today the hold is written only at surrounding entry and dropped by any
other run (`Siem.jsx:252-253`). Under model B:

- Written ONLY at expanded-search entry (the transition, never
  mid-state).
- **Survives every run, pivot, refine, and chip removal while
  expanded** — the drop-on-execute rule is deleted with the
  surrounding path (F3); `preserveHoldRef` goes with it.
- Cleared only by: **Return** (consuming it), **case change or exit**
  (the ratified atomic re-anchor already clears it,
  `Siem.jsx` case-anchor effect), an **incident-scoped descent entry**
  (an explicit navigation to a new case-evidence view, which exits
  the expanded state without returning), and **reset**.
- Still single-depth, never a history stack: one hold, overwritten
  only by a fresh entry after an exit.

### A3-2.4 Behavior under the one rule

| Event while expanded | Behavior |
|---|---|
| Repeated entity pivot | Updates the clue line and the snapshot; the hold is untouched |
| Manual query edit | Edits pending text only (no request, unchanged); the hold is untouched |
| Run / refine / chip removal | Executes in the expanded state; the hold is untouched |
| Case change or exit on Incidents | The atomic re-anchor clears the hold with the rest of the SIEM state (unchanged mechanics) |
| Incident-scoped descent request | Exits Expanded search to the new case-evidence timeline; the hold is cleared, not restored |
| Failed expanded query (parse or execution) | The 11.3 stale-results presentation, unchanged; the hold is untouched, so a subsequent Return restores the held state unchanged |
| Return | Restores the hold exactly (A3-2.2), zero requests, and consumes it |
| Return onto a stale held snapshot | Redisplays it frozen; the existing as-of marker ("as of seq #N" + sim time) dates it and the new-count indicator offers the refresh path — no silent refresh |

Refinements made while expanded are DISCARDED by the return; the
return subcopy states it (the A3-6 copy table row; ruled direction:
"Your expanded refinements stay in Expanded search.", final proposed
in A3-6).

### A3-2.5 Entry capture is total

Every entry site captures the hold, including entries from a degraded
case-evidence state: an entry while the case scope read had failed
(the designed search-all escape) holds `{queryText, snapshot: <the
displayed snapshot or null>, scope: <the errored scope>, timeline}`;
Return restores that state including its error presentation — the
excursion never launders a pre-existing case-evidence error.

### A3-2.6 The C1 interim guard is superseded

C1 item 4 (`763b116`) guards the model A failure mode: a failed scope
read during the return. Model B performs NO scope re-run on return, so
the failure mode is unreachable. At F2 implementation the guard is
REMOVED: the `returnError` state, the `returnReadFailed` string
(`uiCopy.js:34-36`), its render block (`Siem.jsx:575-585`), its
enumerated-scan row, and its tests (`workbench-cross-host.test.js` C1
guard test; the anchor-path scope-error test in
`workbench-states.test.js` is UNTOUCHED — the anchor read and its
A-OD-3 behavior survive model B).

### A3-2.7 Rejection on the record: equal tabs

Equal tabs (case evidence and expanded search as two persistent
co-equal tabs) are REJECTED. A1-A.2.4 rules "two states, not two
modes"; the A1-A.7 supersession retired the two co-equal concepts
(row 1) and the dual return controls (rows 12-13). Tabs would restore
exactly the F9 two-equal-modes contradiction Delta A dissolved and
would recreate a second return destination. The rejection is recorded
here so it is not re-litigated at implementation.

### A3-2.8 Supersession map — F2

Dispositions: **S** superseded (this appendix governs), **T**
translated (guarantee survives in new form), **U** unchanged
(inspected, not touched), **A** augmented (text stands; reading
recorded).

| # | Item | Disp. | Governing text / note |
|---|---|---|---|
| 1 | A1-A.2.4 return mechanic ("keeping the existing return-chip mechanic: the current query re-runs under the case scope") | S | A3-2.1/A3-2.2 — restore, not re-run. The rest of A1-A.2.4 (one stable concept, entry sites, single return action, no-case behavior) stands |
| 2 | A1-A.5 row "Return action" (label) | U | "Return to INC-#### evidence" unchanged (A-OD-1 final) |
| 3 | A1-A.5 row "Return-path explainer subcopy" ("...runs this query over the case evidence again.") | S | A3-6 row F2-1 (restore semantics + the discard statement) |
| 4 | A1-A.6 criterion 11 (single return renders and names the case; case changes only by selection) | T | A3-7 replacement 11: adds the model B semantics (exact restore, zero requests, hold lifetime) to the surviving single-return and structural-case assertions |
| 5 | A1-A.6 criterion 13 (pinned line / block / timeline / echo never disagree) | T | A3-7 replacement 13: after a restore, all four agree with the RESTORED snapshot; the echo still carries the scope token |
| 6 | A1-A.6 criterion 12 (stale-results statement after failed parse/execution) | U | Verified: the return is not a failed-run path; the 11.3 statements and their triggers are untouched |
| 7 | A1-A.3 expanded-search row (block, one return action, entry/exit list) | A | Reading recorded: "exited only by the return action or by an explicit case change/exit" gains the incident-scoped descent exit (A3-2.3), and the return's mechanics are A3-2.2 |
| 8 | §8.3 matrix row "From incident scope" (return path wording) + row "Repeat use" | T | A3-2.4 — the transition surface still names clue/expansion/return; the return path is the restore |
| 9 | C1 interim guard (checkpoint fix 4; docs/stage-5-checkpoint-fix-report.md item 4) | S | A3-2.6 — removed at F2 implementation, failure mode unreachable |
| 10 | A2-2.5 hold mechanics (single-depth, zero-request restore, indicator/selection treatment) | T | The MECHANISM migrates to the expanded-search path with the A3-2.3 lifetime; A2-2.5's surrounding-specific framing is superseded by F3 (A3-3.6) |
| 11 | Tests: `workbench-cross-host.test.js` return re-run assertion; `workbench-states.test.js` search-all/return leg; C1 guard test | T/S | A3-2.9 |
| 12 | §18 / scaffold §10 workflows W3-W5 (return leg wording) | T | A3-9 — the walk asserts the zero-request restore |

### A3-2.9 Tests (binding structure; names final at implementation)

- Model B battery (extends `workbench-cross-host.test.js` /
  `workbench-states.test.js`): hold captured at each entry site
  (pivot, search-all, degraded-entry per A3-2.5); hold SURVIVES a run,
  a repeat pivot, a refine, and a chip removal while expanded; Return
  restores snapshot object, bar text, scope, and timeline
  byte-exactly with ZERO `/api/events/query` and ZERO scope requests;
  Return consumes the hold (no second return offered); case change
  clears it; incident-scoped descent clears it; a failed expanded run
  leaves it restorable; the null-snapshot hold restores the empty
  case-evidence state; selection survival and indicator reset per the
  existing A2 assertions, retargeted.
- Deleted with the C1 guard: the guard test (A3-2.6).
- Translated: the model A re-run assertion becomes the restore
  assertion; the byte-pinned subcopy test rows update to the A3-6
  strings.

### A3-2.10 Sizing

**S-M.** The restore function, entry-capture, and lifetime edits are
concentrated in `Siem.jsx` (the mechanism already exists); the bulk is
test translation. Net product LOC roughly +30 before F3's deletions.

---

## A3-3. ITEM F3 — surrounding events removed from the player-facing product

### A3-3.1 Removal rationale (recorded)

1. **Never actually bounded.** The feature runs `all | H | * | *`
   (`lcqlPivots.js:280-282`): the selected event's id is only a
   client-side viewport target; no time bound around the event exists
   or can exist without an engine change (A2-1 Q8: TIMEFRAME is a
   closed token set with no event-anchored form).
2. **Silent TIMEFRAME widening.** The view widens to `all` by design
   and no copy announces it; the ruled banner names the host, not the
   widening.
3. **Overlap.** The emitted query is the host pivot's form modulo the
   timeframe token; ordinary search and Pivot cover the need.
4. The honest bounded version is DEFERRED ENGINE WORK (the ratified
   A2 deferred register) and stays deferred; removing the dishonest
   approximation shrinks net risk and code.

### A3-3.2 The removal surface (normative, complete; lines at `74198f2`)

- Inspector: the control block `EventInspector.jsx:231-247`, the
  `onSurrounding` prop (`:92`), the `TOOLTIP_SURROUNDING` import
  (`:5`); the shell wiring `Siem.jsx:933`.
- Shell: `surroundingAndRun` (`Siem.jsx:356-368`); the surrounding
  branches of the timeline banner (`Siem.jsx:818-821` banner text,
  `:832` ascending-label ternary collapses to the descent literal,
  `:834-843` the return-button block); the focus/centering prop chain
  end to end (`Siem.jsx` focus props into SiemCards/SiemTable; the
  focus effects and markers in `SiemCards.jsx` and `SiemTable.jsx`);
  `focusSeqRef` (`Siem.jsx:103`).
- Hold plumbing SPECIFIC to surrounding: `preserveHoldRef`
  (`Siem.jsx:102`) and the drop-on-execute lines (`Siem.jsx:252-253`)
  — both die as part of F2's lifetime change (A3-2.3);
  `restoreHeldView` is MIGRATED by F2 into the return action, not
  deleted-then-recreated (A3-P.3).
- Copy: `TOOLTIP_SURROUNDING` (`uiCopy.js:124-125`),
  `surroundingBanner` (`:138-139`), `OCCURRENCE_ASCENDING` (`:140`),
  `BACK_TO_PREVIOUS_RESULTS` (`:141`); `helpContent.js:31`
  (`surrounding` key) and the module doc's "NINE controls" wording;
  the player-docs clause `Docs.jsx:168-169` (A3-6 row F3-1).
- **The permanent tooltip set goes NINE -> EIGHT** (Delta B's eight
  plus surrounding, minus surrounding): `helpContent.js` keys, the
  literal nine-element list in `help-model.test.js`, and every
  "nine-control" statement in test prose.

### A3-3.3 What is KEPT (binding)

- **`descentHost()` (`lcqlPivots.js:280-282`) is NOT deleted**: it is
  shared with evidence descent (`Siem.jsx` descent effect) and pinned
  by `workbench-pivots.test.js` and the generated-forms corpus.
- **Descent is untouched** in behavior, banner, back-navigation, copy,
  and tests: the timeline machinery is `kind`-discriminated and the
  descent branches stand.
- The hold machinery (state + zero-request restore) survives via F2.

### A3-3.4 Supersession map — F3

| # | Item | Disp. | Governing text / note |
|---|---|---|---|
| 1 | A2-2.1 verb-grammar row "Surrounding events" | S | Control removed; the row's other entries stand |
| 2 | A2-2.5 "Surrounding events as temporary context" (whole section) | S | A3-3.2; the hold mechanics inside it survive via F2 (A3-2.8 row 10) |
| 3 | A2-AC-6 / §19.25 (surrounding hold + return) | S | DELETED as a criterion; its hold/restore substance survives inside the A3-7 replacement criterion 11 (model B) |
| 4 | A2-AC-7 / §19.26, Surrounding half ("...and the Surrounding events tooltip...") | T | A3-7: reworded to the three ruled query tooltips; the pivot-transition half stands |
| 5 | A2-OD-1 resolved strings for surrounding (label + tooltip) and A2-R.1 ruling bullets ("Labels: ... Surrounding events keep their technical names"; "Permanent tooltips ... Surrounding events: ..."; "Surrounding events becomes reversible: ...") | S | The A2 record remains byte-unchanged as history; upon ratification these bullets are superseded by this appendix for the removed control |
| 6 | A2-R.2 "nine-control tooltip set ... plus Surrounding events" statement; A1 Delta B tooltip-set growth records | S | The set is EIGHT (Delta B's eight); A3-3.2 |
| 7 | A1-A.2.4 sentence "Descent and surrounding-events are VIEW MODES..." | T | Reads "Descent is a VIEW MODE..." upon ratification; the mechanics described survive for descent |
| 8 | A1-A.7 row 21 (per-source matrix incl. surrounding) and §8.3 row "From surrounding-events view" | S | Row deleted from the matrix |
| 9 | A2 deferred-register entry "Bounded surrounding-events time window (engine)" | S | MOOT: with the feature removed there is nothing to bound. Struck from the ACTIVE register; the historical record stands. A future bounded-context feature would be a NEW design, not this register entry |
| 10 | Stage 4A contract appendix bullet "Surrounding events execute under the current scope as a context view (ratified interpretation...)" (docs/stage-4a-siem-workbench-contract.md, 2026-07-22 appendix) | A | That file is append-only history and is NOT edited; the bullet remains the record of shipped Stage 4/5 behavior. Upon ratification the interpretation is moot for the removed control; recorded here, in the governing appendix |
| 11 | Scaffold merged-cycle commit (3.4) "reversible surrounding events" and its cert legs | S | A3-8 / A3-9 |
| 12 | Tests: `workbench-surrounding.test.js` (six surrounding tests; two OR-fallback tests move); `help-model.test.js` nine-control list + surrounding assertions; `query-clarity.test.js` four-tooltip test | T/S | A3-3.5 |

### A3-3.5 Tests

- DELETED: the six surrounding tests in `workbench-surrounding.test.js`
  (banner emission, zero-request return, single-depth drop, viewport
  centering, case-scope execution, no-hostname absence) — the
  zero-request-restore GUARANTEE does not die, it re-pins on the F2
  model B battery (A3-2.9).
- MOVED: the two OR-fallback tests that live in that file
  (fresh-query notice; fresh-by-design forms) relocate to
  `workbench-pivots.test.js`; the file is then deleted.
- UPDATED: `help-model.test.js` (nine -> eight literal list;
  surrounding tooltip assertions removed), `query-clarity.test.js`
  (ruled-explanations test covers `==`, `!=`, Pivot).
- The em-dash and forbidden-phrase scans are unaffected (deletions
  only).

### A3-3.6 Sizing

**S, net-negative.** Roughly 120 lines of product code, four copy
strings, one tooltip, one test file, and one criterion are removed;
no new machinery. The only added text is the descent-literal collapse
of one ternary.

---

## A3-4. ITEM F4b — final submission gating

### A3-4.1 The model (normative)

With the workspace selector mounted (C1 item 3), classification is an
inline workspace step. **The checklist's Ready line and the client
Submit gate require every observable step INCLUDING a selected valid
classification; Submit performs final submission with a bare
confirmation only, never a data-entry step.** Plainly classified:
frontend flow reordering. No serialized field changes, no backend
boundary moves, no frozen 3.9A test is touched; the server gate
(`_valid_classification` inside `submit_incident`, 400
`invalid_classification`) is untouched and remains the authoritative
backstop.

### A3-4.2 Submission-ready: one client-side definition

`submissionReady(card, chosen) = card.sealed && card.ready &&
validClassification(chosen[card.incident_id])`, where
`validClassification` mirrors the server rule exactly (verdict
`false_positive`, or `threat` with a non-empty category). The server
`ready` field keeps its meaning (sealed roster fully triaged) and its
serialization, unchanged.

- **Checklist Ready line:** "Ready to submit" renders only when
  telemetry is sealed, the roster is fully reviewed, AND a valid
  classification is selected; otherwise "Submit pending". The line
  strings are unchanged; only the condition changes. The response
  line stays a neutral count and NEVER gates (a required-action count
  is answer-key information — the standing rule, restated).
- **Submit control:** renders once sealed; enabled only when
  `submissionReady`; when the only missing step is classification,
  the adjacent observable line reads the A3-6 string
  ("Select a classification to submit."), replacing the
  detections-remaining line once triage is complete.
- **19.18 leak rule, reading recorded:** the checklist line set,
  order, and copy remain constants; the Ready line now varies with
  the player's own local selection in addition to observable card
  fields. Both of its states are constant strings; nothing varies
  with the answer key. The rule stands unchanged in force.

### A3-4.3 One meaning of "Ready" across surfaces [A3-OD-3]

"Ready" renders today at three sites from the server field alone
(A3-1 fact 5). Requiring classification only in the workspace would
recreate the F9 pattern (two surfaces asserting different readiness
for the same incident). Resolution proposed as A3-OD-3
(recommendation: ONE definition everywhere — the `chosen`
selection state lifts from `Incidents.jsx` to the Dashboard shell
beside `activeIncidentId`, and every Ready render site — the
Incidents list chip, the Ready view filter and its count, the
IncidentDashboard row chip, the checklist line, and the Submit gate —
consumes the single `submissionReady` derivation).

### A3-4.4 The bare confirmation; modal data entry retired

- Submit opens ONE confirmation dialog naming the incident and the
  classification being filed. **The landed confirm copy is kept
  verbatim** ("Submit incident INC-####" / "Filing as {category}.
  This locks your classification for this incident and reveals how it
  scored. You cannot change it afterward." / Cancel / Submit
  Incident) — it is already a bare confirmation and passes every
  scan; no new strings are minted for it.
- The classifier and category modal steps are RETIRED from the submit
  flow (`Incidents.jsx:461`, `:475`): classification data entry
  happens only in the workspace.
- **Hardcore:** the "Hardcore: one wrong call ends the run." warning
  currently lives in the retired modals; it moves verbatim into the
  confirmation dialog (Hardcore only). Trust requires the warning at
  the last gate.
- **Check Answer** currently shares the classifier modal
  (`Incidents.jsx:197`). Resolution proposed as A3-OD-2
  (recommendation: Check Answer reads the SAME workspace selection —
  the control disables until a valid classification is selected, with
  the same A3-6 line as its adjacent hint; the modal variants of
  `ClassificationSelector`/`CategorySelector` then have zero
  consumers and are deleted). Check Answer's server behavior
  (Guided-only allow-list, classification-only reveal, Assisted
  marking) is untouched either way.

### A3-4.5 Interaction verification

- **Criterion 16 (count reconciliation):** verified NO interaction —
  it binds `response_review` counts; classification plays no part.
- **Criteria 19.17-19 (Delta B live progress):** the toast trigger
  list and checklist leak rule stand; the T4/T5 milestone toast
  ("All detections reviewed. INC-#### is ready to submit.") keeps its
  ratified trigger — the observable false->true transition of the
  SERVER ready field. Its wording remains truthful under F4b: it
  announces triage completion; the checklist's Ready line is the
  submission gate. Verified compatible; no toast change.
- **3.9A boundary:** `submit_incident`, readiness, idempotency, and
  `test_submission_gate.py` are untouched. The client cannot reach
  the server's `invalid_classification` 400 through the gated UI; the
  existing flash path remains as the safety net.

### A3-4.6 Supersession map — F4b

| # | Item | Disp. | Governing text / note |
|---|---|---|---|
| 1 | A1-B.3.2 Ready-line row ("Ready to submit / pending" from card `ready`) | S | A3-4.2 — the line's OBSERVABLE SOURCE becomes the client conjunction (server `ready` AND the player's own selection); both inputs remain observable/player-derived |
| 2 | A1-B.3.2 Classification row | U | Already satisfied by C1 item 3 (the workspace selector); F4b changes nothing about the line itself |
| 3 | A1-B.3.2 leak rule (19.18) | A | Reading recorded in A3-4.2; rule unchanged in force |
| 4 | Locked submit-flow description (3.9B/D7: Submit -> verdict via ClassificationSelector -> confirm) and its C1-era pre-fill behavior | S | A3-4.4 — data entry moves wholly to the workspace; the modal steps retire; the confirm dialog survives verbatim |
| 5 | Check Answer flow (shared classifier modal) | S (per A3-OD-2 resolution) | A3-4.4 |
| 6 | "Ready" render sites (list chip, Ready view/count, IncidentDashboard chip) | T (per A3-OD-3 resolution) | A3-4.3 — one `submissionReady` definition |
| 7 | Criterion 16; Delta B toast triggers; 3.9A server gate and suite | U | A3-4.5, verified |
| 8 | Tests: `incidents-workspace.test.js` submit-flow tests (incl. the C1 pre-fill test), `review-teaching.test.js` 19.19 submit walk, `live-progress.test.js` checklist normalizer | T | A3-4.7 — the normalizer that erases the Ready/classification distinction must stop erasing it |
| 9 | Cert workflow W1 (submit leg) and W7 (Hardcore leg: warning placement) | T | A3-9 |

### A3-4.7 Tests (binding structure)

- Ready gating: server-ready + no classification -> "Submit pending",
  Submit disabled, the classify-to-submit line renders; selecting a
  classification flips the line to "Ready to submit" and enables
  Submit; clearing back (threat with category unpicked) disables
  again. Leak leg: the checklist remains byte-identical across
  incidents per state.
- Bare confirmation: Submit opens the confirm directly (no classifier
  modal, no category modal), names the workspace classification, and
  POSTs it; Hardcore renders the warning line in the confirm.
- Check Answer (per A3-OD-2 resolution): disabled until a valid
  selection; checks the workspace selection; no modal.
- One-Ready: list chip, Ready view count, dashboard chip, and
  checklist agree for the same incident in both states (the F9
  regression battery, extended).
- Translated: the C1 pre-fill test (the modal it pre-fills no longer
  exists in the submit flow) becomes the confirm-names-the-selection
  test; the 19.19 walk drops its modal click.

### A3-4.8 Sizing

**S-M.** `Incidents.jsx` flow surgery + the `chosen` lift (per
A3-OD-3) + test translation; component deletions if A3-OD-2 resolves
as recommended. No backend work.

---

## A3-5. ITEM F7 — simple search mode (Option A: a projection over canonical LCQL)

### A3-5.1 The model (normative)

Two modes, one truth. **The canonical four-part LCQL query remains the
single truth; simple mode is a PROJECTION over it** (the ratified
chips principle extended from read-only to authoring). Default mode:
**Simple.**

- **Simple mode:** the query bar accepts ONLY the FILTERS expression.
  The Timeframe picker owns the first token (it already edits pending
  state; A2-1 Q1). NEW optional **Source** and **Event type** selects
  own the second and third tokens, defaulting to `*` ("All sources" /
  "All event types"). Run compiles the four parts through the
  generator chokepoint and executes; the canonical echo
  ("Results from:") continues to show the full four-part truth with
  the scope token — the projection's honesty anchor, unchanged.
- **Advanced mode:** one toggle away; the bar holds the full
  four-part form exactly as today. All A2 rulings continue to govern
  advanced mode verbatim.
- The mode toggle is session-local React state (no persistence:
  B-OD-4 stands). Default mode and mode universality are A3-OD-4
  (recommendation: Simple is the default in ALL play modes).

### A3-5.2 Controls are value-driven projections (the mode-stability mechanism)

The ratified Timeframe pattern (the control's value DERIVES from the
query text; an out-of-list value renders as its own option) is
GENERALIZED to the new selects:

- **Source select options:** `All sources` (`*`) + the closed
  `SOURCE_FAMILIES` set (mirrored client-side and PINNED to
  `backend/lcql.py:355-356` by a shared two-sided fixture corpus, the
  OR_SCAN_CORPUS pattern) + the CURRENT token when it is anything
  else (an observable hostname from a host pivot or descent renders
  as its own option).
- **Event type select options:** `All event types` (`*`) + the event
  types present in the last executed snapshot's rows + the CURRENT
  token when not among them.
- Because every control displays whatever token the canonical
  carries, **every server-canonical query is representable in simple
  mode by construction** — a canonical always splits into four
  segments (quote-aware `splitSegments`), each of which the picker,
  selects, and FILTERS bar can hold. This satisfies the
  mode-stability requirement structurally rather than by enumeration.
- **After every successful run the controls re-derive from the
  executed canonical** (the projection write-back): in simple mode
  `applySnapshot` decomposes the canonical into picker/select values
  and the FILTERS bar text instead of writing the whole string into
  the bar. Refines, chip removals, and pivots (which mint full
  canonical queries through the generator, unchanged) therefore
  update the simple controls consistently.
- The 11.3 edited-note rule translates: "edited" means the COMPILED
  pending query differs from the executed canonical (field edits and
  picker/select changes alike trigger it). Same honesty, same
  strings.

### A3-5.3 Compilation through the chokepoint; the splice migrates

- ONE new generator form: `composeQuery(tf, sensor, eventType,
  filtersText)` in `lcqlPivots.js` — joins the four parts, mapping an
  empty or whitespace FILTERS field to `*`. Simple-mode Run compiles
  through it; nothing else in the frontend ever assembles a query
  string ad hoc.
- **The Timeframe picker's raw splice migrates into the chokepoint as
  part of this item**: `setTimeframe`'s `indexOf('|')` splice
  (`Siem.jsx:205-214`) is replaced by a quote-aware
  `replaceTimeframe(text, token)` generator form (built on
  `splitSegments`) used by advanced mode; in simple mode the picker
  feeds `composeQuery` directly. The chokepoint's one documented
  bypass is thereby closed.
- **Empty-run rule, mode-scoped:** advanced mode keeps A2-AC-1
  verbatim (empty bar: Run disabled, "No query entered.", no
  request). In simple mode a fully-empty state does not exist (the
  picker and selects always hold tokens); an empty FILTERS field
  compiles to `*` and legitimately runs as match-all. "No query
  entered." never renders in simple mode.

### A3-5.4 Validation: compile, server-parse, map back; the boundary rule

Validation is compile-then-server-parse; the parser remains the only
authority. The client section mapping gains the projection offset:

- The submitted string is the compiled canonical-form string; the
  server error's `position` indexes into it.
  `sectionIndexAtPosition` names the section as today.
- **Boundary rule (binding): an error whose position falls in the
  FILTERS section is the player's** — the ruled three-line error form
  renders, naming the Filters section, with the parser reason and
  suggestions kept and the position remapped to the FILTERS FIELD
  (position minus the segment-3 offset) as the technical detail.
- **An error before the FILTERS section is a COMPILER DEFECT**
  (A2-2.3 class 3, verbatim mechanism): the picker/select tokens are
  product-generated, so a parse failure there can never be attributed
  to the player. It fails the extended corpus and the structural
  tests; if one ever occurs live it renders as class 2 while
  classified DEFECT — never as a player error.
- "Restore last working query" restores the canonical (unchanged,
  request-free). Across modes: in simple mode the restored canonical
  renders through the projection (picker + selects + FILTERS field);
  the defensive total-rule stands — a restored text that fails to
  decompose (structurally impossible for a server canonical, possible
  only for hand-authored advanced text) opens Advanced with the full
  form. Mode toggling never loses text: Simple -> Advanced shows the
  compiled four-part form; Advanced -> Simple projects when the text
  decomposes, else stays in Advanced with the existing error
  presentation.

### A3-5.5 Deferred: the `ip` alias (recorded with reasoning)

An `ip ==` convenience alias is OUT of the first cut: field aliases
were deliberately retired at Stage 4 ("Aliases: none; the old client
alias table is superseded"), and compiling `ip` to the two-field OR
form would collapse the chip row to one un-removable Custom filters
chip under the ratified honesty rule — trading a typing convenience
for the loss of chip-level removal and a second place where simple
mode secretly writes ORs. Deferred to the register with this
reasoning; the IP pivot remains the sanctioned OR author.

### A3-5.6 Invariants untouched (verified)

- No grammar, token, parser, endpoint, payload, or engine change.
  Snapshot identity is server-minted from the parsed canonical and
  HMAC-bound (`app.py:2872-2878`, `:2787-2796`); a frontend mode
  cannot influence it. If implementation surfaces any engine need:
  STOP and report (A3-P.4).
- The `==`/`!=` tooltips and refine mechanics are UNCHANGED and
  mode-neutral (verified: refines operate on the executed canonical
  and re-run; in simple mode the result re-projects). Chips are
  UNCHANGED and honest in both modes (they read the executed
  canonical, never the editable controls).
- Scope semantics, the case-constant model, and Expanded search are
  orthogonal to the mode and unchanged.

### A3-5.7 Corpus and parity extensions (test-only)

- `GENERATED_FORMS_CORPUS` extends with `composeQuery` and
  `replaceTimeframe` outputs x adversarial values (embedded quotes,
  backslashes, reserved words, `*` and `|` characters in FILTERS) and
  a picker/select combination matrix (each family, a hostname token,
  event types, empty-FILTERS -> `*`); both sides and both hardcoded
  counts update (`backend/test_lcql.py:514`,
  `query-clarity.test.js:232`).
- NEW `SOURCE_FAMILIES` parity corpus: the client family list is
  asserted equal to `backend/lcql.py`'s tuple (two-sided, the
  established shared-fixture pattern; backend side test-only).
- Round-trip representability battery: for every corpus canonical,
  decompose -> recompile -> byte-equal canonical; the projection
  never rewrites what it displays.

### A3-5.8 Supersession map — F7

| # | Item | Disp. | Governing text / note |
|---|---|---|---|
| 1 | A2-2.4 placeholder ruling ("Example: 1h \| Sysmon \| ...") | T | Mode-scoped: advanced keeps it verbatim; simple mode's placeholder is the FILTERS-only example (A3-6 row F7-1), same Example-prefix italic rule |
| 2 | A2-2.3 class 1 (empty, "No query entered.") and A2-AC-1 / §19.20 | T | Mode-scoped per A3-5.3: advanced verbatim; simple has no empty state (empty FILTERS compiles to `*`) |
| 3 | A2-2.3 class 2 (section-named errors) and A2-AC-2 / §19.21 | T | A3-5.4 — the ruled three-line form stands; simple mode names the Filters section for player errors and adds the boundary rule (pre-FILTERS = defect) |
| 4 | A2-2.3 class 3 (generated-query failure = defect) and A2-AC-5 / §19.24 | A | Extended over the new forms and the picker/select matrix (A3-5.7) |
| 5 | A2-AC-3 / §19.22 (Restore) | A | Reading recorded: restore-the-canonical + the A3-5.4 cross-mode projection rule |
| 6 | `STRUCTURE_LINE` (`uiCopy.js:132`) and the four-segment empty-state help panel + `QUERY_HELP_EXAMPLES` | T | Advanced-only; simple mode gets the A3-6 F7 strings. The structure line cannot name a player error in simple mode (structure is compiled) |
| 7 | A2-2.1 rows for Run/Timeframe; A2-1 Q1 record | A | Reading recorded: the picker still edits pending state; its splice now routes through the chokepoint (A3-5.3) |
| 8 | Delta B `==`/`!=` tooltip interaction; chips (A2-2.2, A2-AC-4 / §19.23) | U | Verified unchanged and mode-neutral (A3-5.6) |
| 9 | Contract Section 13 / scaffold chokepoint statements ("the single query author") | A | Strengthened: the last bypass (the timeframe splice) closes |
| 10 | A2 deferred register | A | Gains the `ip` alias entry with the A3-5.5 reasoning; "structured query builder" stays deferred and is NOT this item (simple mode is a projection, not a builder: no predicate UI, the FILTERS text stays hand-authored) |
| 11 | Scaffold Phase 3/4 cycle; §18/§10 cert workflows | T | A3-8 / A3-9 (the W-simple walk) |

### A3-5.9 Tests (binding structure)

- Mode battery (`query-clarity.test.js` extension or a new
  `simple-search.test.js`): default mode per A3-OD-4; compile on Run
  (the wire query equals `composeQuery` of the controls); projection
  write-back after a run; refine/chip/pivot results re-project;
  toggle round-trips without text loss; empty-FILTERS runs as `*`
  with no "No query entered." in simple mode; advanced empty-run
  unchanged.
- Error boundary: a FILTERS player error renders the ruled form with
  the remapped detail position; a forced pre-FILTERS error is
  asserted DEFECT-classified (structural test), and the corpus proves
  the pickers cannot produce one.
- Corpus/parity/round-trip per A3-5.7.
- Timeframe migration: `replaceTimeframe` byte-matches the old splice
  on every valid form (a translation corpus), and the picker still
  never issues a request.

### A3-5.10 Sizing

**M.** The mode state, two selects, the compiler/decomposer pair, the
error offset, mode-scoped copy, and the corpus extensions. The largest
of the four items; no backend product code.

---

## A3-6. Copy table (every new or changed string; no em dashes in any string)

| Row | String (proposed final) | Replaces / where |
|---|---|---|
| F2-1 | "Return to INC-8541 evidence restores the results you had before expanding. Queries run while expanded are not kept." | The A1-A.5 return subcopy row ("...runs this query over the case evidence again."); the expanded-search block subcopy |
| F2-2 | (removed) `returnReadFailed` "Could not load {INC} evidence. Try the return again." | C1 guard string deleted with the guard (A3-2.6) |
| F3-1 | Player docs sentence drops its surrounding clause: "Open Evidence Timeline on an incident or detection descends into its evidence, sorted occurrence-ascending." | `Docs.jsx:168-169` (the "...and Surrounding events centers the host timeline on the event you are inspecting." clause is deleted) |
| F3-2 | (removed) `TOOLTIP_SURROUNDING`, `surroundingBanner(host)`, `OCCURRENCE_ASCENDING`, `BACK_TO_PREVIOUS_RESULTS` | `uiCopy.js:124-125, 138-141`; `helpContent.js:31`; the tooltip set is EIGHT |
| F4b-1 | "Select a classification to submit." | New; the observable line beside a disabled Submit when classification is the only missing step (also the Check Answer hint under the A3-OD-2 recommendation) |
| F4b-2 | Confirm dialog strings KEPT VERBATIM ("Submit incident INC-####"; "Filing as {category}. This locks your classification for this incident and reveals how it scored. You cannot change it afterward."; "Cancel"; "Submit Incident"); Hardcore adds the existing "Hardcore: one wrong call ends the run." line | The bare confirmation (A3-4.4); zero new confirm strings |
| F7-1 | Placeholder (simple): "Example: command_line contains \"powershell\"" | Mode-scoped A2-2.4; advanced placeholder unchanged |
| F7-2 | "Simple search" / "Advanced LCQL" | The mode toggle labels |
| F7-3 | "Source" / "All sources"; "Event type" / "All event types" | The two select labels and their any-token options |
| F7-4 | Empty-state help (simple): "Filters match fields against values. Try one of these:" with example buttons `user_account == "spatel"` and `command_line contains "powershell" and hostname == "ACME-WS12"` | Mode-scoped counterpart of the four-segment help panel; edit-only example buttons, same mechanics |
| F7-5 | (unchanged, scope narrowed) "No query entered.", `STRUCTURE_LINE`, four-segment help panel, advanced placeholder and examples | Advanced mode only (A3-5.3, A3-5.8 rows 2/6) |

Every NEW string above is ASCII-punctuated and em-dash-free; all land
in `uiCopy.js` first (R7) and join the em-dash scan automatically; the
F4b-1 line joins the enumerated pre-submission forbidden-phrase scan.
Final wording is A3-OD-1.

---

## A3-7. Acceptance criteria (replacements in place; additions numbered 19.27+)

Replacements (same numbers, new text upon ratification):

- **11 (replaces the A1-A.6 translation).** While Expanded search is
  live, exactly one return action renders and names the current case;
  the hold is written only at entry, survives every run while
  expanded, and is consumed by the return, which restores the held
  snapshot, bar text, scope, and timeline mode exactly with zero
  requests; the current case never changes except by explicit
  selection (structural); no state is representable in which an
  expansion origin differs from the current case.
- **13 (replaces the A1-A.6 translation).** The pinned case line, the
  expanded-search block, the active timeline mode, and the
  "Results from" canonical echo each match the executed snapshot and
  current state and never disagree — including immediately after a
  model B restore, where all four agree with the RESTORED snapshot;
  the echo retains the LCQL scope token.
- **19.20 / 19.21 / 19.22 (A2-AC-1/2/3), mode-scoped** per A3-5.3 and
  A3-5.4: advanced mode verbatim; simple mode per the boundary rule
  (FILTERS errors are the player's, pre-FILTERS errors are defects,
  no empty state exists, restore projects).
- **19.25 (A2-AC-6): DELETED** (the surrounding return); its
  hold-restore substance lives in replacement criterion 11.
- **19.26 (A2-AC-7), reworded:** the ruled tooltips for `==`, `!=`,
  and Pivot are permanently available, accessible, and
  mode-universal; the pivot transition surface names the followed
  field and value, whether the search expanded beyond the current
  incident, and the return path.

Additions:

- **19.27 (F4b gating).** "Ready to submit" and an enabled Submit
  render if and only if the incident is sealed, its roster is fully
  reviewed, and a valid classification is selected; Submit opens a
  bare confirmation naming the incident and the classification, with
  no data-entry step; every player-facing "Ready" indicator for an
  incident agrees with this definition; the server gate remains
  untouched and unreachable through the gated UI.
- **19.28 (F7 compile-and-parse).** In simple mode every executed
  query is compiled through the generator chokepoint and parsed by
  the server; the canonical echo always shows the four-part truth;
  a parse error inside FILTERS renders the ruled form naming the
  Filters section with a field-relative detail; a parse error outside
  FILTERS is classified a product defect and never renders as a
  player error.
- **19.29 (F7 representability round-trip).** Every server-canonical
  query decomposes into the simple-mode controls and recompiles
  byte-identically; mode toggling never loses or rewrites query text;
  every generator output and picker/select combination parses
  (corpus-pinned, two-sided).

---

## A3-8. Scaffold delta (applied to the scaffold only after ratification)

The Stage 5 phases are complete; Amendment 3 runs as ONE consolidated
implementation cycle following the merged Phase 3/4 pattern (one
review cycle, the ruling G analog), appended to the scaffold as the
A3 cycle. Copy lands first (R7).

- **A3.1 — copy constants + scans.** The A3-6 strings land in
  `uiCopy.js` (removals deferred to their items); the enumerated-scan
  rows update. Size XS.
- **A3.2 — F2 model B.** Hold migration to the expanded-search path,
  the A3-2.3 lifetime, the restore-with-timeline, entry-capture at
  all sites, C1 guard removal, test translation + the model B
  battery. Size S-M. **Binding: lands before A3.3, or A3.3's hold
  deletion happens in this same commit.**
- **A3.3 — F3 removal.** The A3-3.2 surface, tooltip set to eight,
  test deletions/moves, docs sentence. Size S, net-negative.
- **A3.4 — F4b gating.** `submissionReady`, the Ready-line condition,
  Submit enable + the classify-to-submit line, modal retirement, the
  Hardcore warning relocation, the `chosen` lift and one-Ready
  unification (per A3-OD-2/3 resolutions), test translation. Size
  S-M.
- **A3.5 — F7 core.** Mode state + toggle, the two value-driven
  selects, `composeQuery` + `replaceTimeframe` (the splice
  migration), projection write-back, mode-scoped placeholder/help.
  Size M.
- **A3.6 — F7 validation + corpora.** The error-offset boundary,
  restore-across-modes, the corpus/parity/round-trip extensions
  (both sides, counts bumped). Size S-M.
- **A3.7 — certification.** The A3-9 workflow walk, the 10.1
  conformance-sweep updates, the closing report (serialized-field
  disclosure expected: NONE), gate outputs. Size S.

Net size: **M for the cycle** (F3's deletions offset much of F7's
additions; the net product-LOC delta is modest). Every commit passes
the versioned hook; never-land-red stands; the em-dash and
forbidden-phrase scans run per commit.

Scaffold Phase 2 note: no Phase 2 re-work — the copy additions ride
A3.1 into the same `uiCopy.js` module under the same R7 rule.

---

## A3-9. Certification workflows (updated list) and the conformance sweep

Workflow deltas from the scaffold §10 list as landed:

- **W1 (Guided teaching run):** the submit leg becomes
  workspace-classify -> gated Ready -> bare confirm; the review path
  unchanged.
- **W3-W5 (pivot chain / scope truth / parse-failure truth):** the
  return leg asserts the model B restore (zero requests, exact
  redisplay, as-of marker on a stale hold); the surrounding
  enter/return leg is DELETED; the parse-failure leg runs in BOTH
  modes (simple FILTERS error naming; advanced unchanged).
- **W7 (Hardcore purity):** adds the confirm-dialog warning
  assertion; still no coaching, no hints, no Check Answer.
- **NEW W-simple:** a full simple-mode investigation — default mode,
  picker + selects + FILTERS run, refine re-projection, chip removal,
  malformed FILTERS error with the Filters section named, toggle to
  Advanced showing the identical canonical, Restore across modes,
  and the canonical echo matching at every step.
- Zero-console-error sweeps continue on every walk.

**Ratified-copy conformance sweep (scaffold 10.1, the C1 standing
rule):** the sweep runs at the A3 certification with these row
updates upon ratification — row 2 (A1-B.3.2): the Ready-line source
becomes the A3-4.2 conjunction; row 3 (A1-A.5): the return subcopy
row points at F2-1; row 4 (A2 finals): three ruled tooltips, the
surrounding block rows removed; NEW row 6: the F7 mode-dependent
strings (placeholder, empty/error copy, toggle and select labels)
against A3-6. Each row is read ratified-sentence-against-rendered-
surface, per the C1 rule.

---

## A3-10. Owner decisions surfaced (genuinely open; everything else above is closed)

- **A3-OD-1 — final strings.** The A3-6 proposed finals (the F2
  return subcopy, the classify-to-submit line, the simple-mode
  placeholder/help/toggle/select labels, the docs sentence). The
  confirm-dialog strings are kept verbatim and are not open.
- **A3-OD-2 — Check Answer input source after modal retirement.**
  RECOMMENDED: Check Answer reads the same workspace selection
  (disabled until a valid classification is selected; the F4b-1 line
  is its hint; the modal variants of the two selectors are then
  deleted as consumerless). Alternative recorded: keep the classifier
  modal for Check Answer alone (rejected by recommendation: it keeps
  a data-entry modal alive for one Guided affordance and two input
  paths for one fact).
- **A3-OD-3 — one meaning of "Ready".** RECOMMENDED: the `chosen`
  selection state lifts to the Dashboard shell and every Ready render
  site consumes the single `submissionReady` derivation (A3-4.3).
  Alternative recorded: leave the list/dashboard chips on the server
  field and rename them away from "Ready" (rejected by
  recommendation: two readiness vocabularies for one incident is the
  F9 pattern in miniature).
- **A3-OD-4 — simple-mode default.** RECOMMENDED: Simple is the
  default in ALL play modes; the toggle is session-local memory only
  (B-OD-4: no client store). Alternative recorded: Guided-only
  default with SOC Queue/Hardcore defaulting to Advanced (rejected by
  recommendation: the mode is a usability projection, not coaching;
  Hardcore purity concerns copy and hints, not ergonomics).

---

## A3-R. Ratification record (owner; append-only)

| Amendment | State | Date | Notes |
|---|---|---|---|
| Amendment 3 — return semantics, surrounding removal, final submission, simple search | **RATIFIED** | 2026-07-26 | Owner rulings in A3-R.1 are the governing finals; implementation authorized |

*Amendment 3 drafted 2026-07-26 at baseline `74198f2` on branch
`stage-5-amendment-3` (the C1 checkpoint tip; C1 fixes
`a2cc3dc..74198f2` are part of the baseline and are reported in
docs/stage-5-checkpoint-fix-report.md). Gates ALL GREEN at the C1
product tip `80878da` (backend battery complete; frontend 27 suites /
253 tests); `74198f2` is docs-only above it. This draft is docs-only:
the locked Revision 3 text and the Amendment 1 and Amendment 2
appendices above are byte-unchanged; the implementation scaffold
document is untouched (its delta is drafted in A3-8 and applied only
after ratification); owner asset files untouched; nothing pushed; no
product code. This task ratifies nothing.*

### A3-R.1 Owner ratification rulings (2026-07-26, recorded verbatim)

> AMENDMENT 3 FINAL REVIEW VERDICT: PASS. RATIFY AND IMPLEMENT.
>
> A3-OD-1 — Final copy
>
> Use these canonical strings:
>
> - Return subcopy:
>   "Return restores the incident evidence you were viewing before
>   Expanded search. Changes made in Expanded search are not kept."
> - Simple-search placeholder:
>   'Example: source_ip == "10.0.1.32"'
> - Simple-search help:
>   "Enter a filter expression. Timeframe, source, and event type are
>   controlled above."
> - Advanced toggle:
>   "Advanced LCQL"
> - Selector labels:
>   "Source"
>   "Event type"
> - Documentation distinction:
>   "Simple search accepts a filter expression. Advanced LCQL accepts
>   the complete four-part query."
>
> All copy remains em-dash-free.
>
> A3-OD-2 — Check Answer input
>
> - Check Answer consumes the workspace classification selection.
> - Check Answer is disabled until a valid classification is selected.
> - Delete the redundant classification-entry modal variants.
> - No backend, score, or payload change.
>
> A3-OD-3 — One meaning of Ready
>
> - Every Ready surface derives from one shell-owned state.
> - Ready is true only when:
>   1. the existing server observable-readiness value is true, and
>   2. a valid workspace classification is selected.
> - The response-action count remains informational and never gates
>   readiness.
> - No surface may show Ready while Classification says not selected.
> - Submit incident uses the same derived state.
>
> A3-OD-4 — Search-mode default
>
> - Simple search is the default in Guided, SOC Queue, and Hardcore.
> - Advanced LCQL remains available in every mode.
> - The mode toggle is session-local only.
> - Do not add localStorage or server persistence.
> - Search semantics remain identical across modes.

### A3-R.2 Recording notes (what the rulings resolve and supersede)

- **A3-OD-1 resolved.** The six ruled strings are the canonical
  finals. They SUPERSEDE the drafted A3-6 proposals they touch:
  row F2-1 (the return subcopy becomes the ruled two-sentence form,
  id-free, so the parameterized template retires for a constant), row
  F7-1 (the simple placeholder becomes the ruled source_ip example,
  keeping the A2-2.4 Example-prefix italic rule), and row F7-4 (the
  simple help line becomes the ruled sentence; the edit-only example
  buttons keep the existing empty-state mechanics with FILTERS-only
  example text). The ruled documentation-distinction sentence is NEW
  and lands on the player docs page beside the F3-1 trim. Drafted
  finals the ruling does not touch STAND as canonical: F4b-1
  ("Select a classification to submit."), the F3-1 docs trim, the
  "Simple search" return-toggle label (the ruled "Advanced LCQL" is
  the enter-advanced label), and the any-token option labels
  ("All sources" / "All event types"). Every string is em-dash-free.
- **A3-OD-2 resolved as recommended.** Check Answer consumes the
  workspace selection and disables until a valid classification is
  selected; the modal variants of ClassificationSelector and
  CategorySelector are DELETED (zero consumers remain); no backend,
  score, or payload change.
- **A3-OD-3 resolved as recommended.** One shell-owned selection
  state; ONE derived readiness (server observable readiness AND a
  valid workspace classification) consumed by every Ready surface and
  by Submit; the response-action count stays informational and never
  gates; no surface may show Ready while the checklist says
  "Classification: not selected".
- **A3-OD-4 resolved as recommended.** Simple search is the default
  in Guided, SOC Queue, and Hardcore; Advanced LCQL is available in
  every mode; the toggle is session-local memory only (no
  localStorage, no server persistence; B-OD-4 stands); search
  semantics are identical across modes.
- **Implementation authorized:** merge `stage-5-amendment-3` into
  `stage-5-live-run-feedback` with `--no-ff`; apply the A3-8 scaffold
  delta; implement the four items in the binding order (F2, F3, F4b,
  F7) as the A3.1-A3.7 cycle, each concern independently revertible,
  gates per concern and the complete battery at the final boundary;
  Chrome verification and the ratified-copy conformance sweep at
  certification; the closing report update per the owner directive.
  STOP at the final Stage 5 checkpoint: no merge to `main`, no push,
  no final UI polish, no new stage.

*Ratification recorded 2026-07-26 on branch `stage-5-amendment-3` at
the drafted baseline; the A3-R state table above is updated to
RATIFIED and the rulings are appended verbatim. Docs-only; owner
asset files untouched; nothing pushed.*
