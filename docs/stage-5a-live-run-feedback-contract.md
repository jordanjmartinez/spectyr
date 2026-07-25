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

# AMENDMENT 2 — GUIDED SIEM SEARCH AND QUERY CLARITY (DRAFT, NOT RATIFIED)

**Status: DRAFT FOR RATIFICATION. Nothing in this appendix is in force.**
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
| Amendment 2 — guided SIEM search and query clarity | DRAFT | — | — |

*Amendment 2 drafted 2026-07-25 at baseline `2e74b86` on branch
`stage-5-amendment-2`; gates ALL GREEN at this baseline on this branch
(backend 27 suites; frontend 18 suites / 173 tests). Docs-only: the
locked Revision 3 text above is byte-unchanged; the implementation
scaffold document is untouched (its delta is drafted in A2-6 and applied
only after ratification); owner asset files untouched; nothing pushed;
no product code, no Phase 1. This task ratifies nothing.*
