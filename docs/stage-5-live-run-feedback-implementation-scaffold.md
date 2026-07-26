# Stage 5 Live Run Feedback — Implementation Scaffold

**Status: APPROVED (owner review verdict PASS, 2026-07-25) — subject to
the owner rulings recorded in the append-only approval appendix at the
end of this document (rulings A-H; every [Scaffold decision] ratified as
written; the ruling-A change to commit 2.2 recorded there). This remains
a planning document: no product code, tests, schemas, scenarios,
components, or endpoints change with it. Implementation is authorized on
branch `stage-5-live-run-feedback` from `main` after this scaffold's
merge, in the phase order below, stopping at every [STOP] checkpoint and
phase stop point. Phase 1 has NOT begun.**

**CONSOLIDATED REVISION (2026-07-25): contract Amendments 1 (both
deltas) and 2 are RATIFIED; this scaffold is updated in ONE pass to the
consolidated plan. The amendment appendices (contract A1-A.8, A1-B.8,
A2-6, and the ratification rulings A1-R / A2-R) are the GOVERNING
sources; the changelog below records every applied change. The original
approved text remains in git history; the approval appendix at the end
of this document is unchanged.**

Governing document: `docs/stage-5a-live-run-feedback-contract.md` — the
LOCKED Stage 5A contract (Revision 3; lock recorded 2026-07-24 at `main`
`09eea3b`). This scaffold translates every locked requirement into a
buildable sequence with independently reviewable checkpoints. Where the
contract delegates a detail to the scaffold, the choice is made here,
marked **[Scaffold decision]**, and is part of what approval ratifies.
Nothing here amends the contract; Section 11 lists every ambiguity,
repository disagreement, and interpretation found while planning — each
is REPORTED for the owner, none is silently resolved. Contract changes
happen only through the recorded amendment discipline, and proposing one
is the owner's call, not this scaffold's.

## Changelog — consolidated revision (2026-07-25)

Applied in ONE pass after the ratifications of contract Amendments 1
and 2 (governing sources: A1-A.8, A1-B.8, A2-6, A1-R, A2-R):

1. **Delta A (case-constant scope):** Phase 1 reshaped — pinned case
   header ("Investigating INC-####" / "All activity") unifying the
   Dashboard focus banner; SIEM case-evidence/expanded-search state
   pair (scope select removed; "Search all evidence"; ONE return
   action); `IncidentScopeBar` toggle + Use Session-wide REMOVED
   (`useIncidentScope`, honesty rows, refresh triggers kept verbatim;
   error-empty state Retry-only per ratified A-OD-3); dual return
   controls and the expandable two-concept summary DROPPED (OD-12/13/14
   superseded; OD-15 structural). Phase 2 vocabulary rows swapped;
   Phase 3's transition surface is the expanded-search block. Sizing:
   Phase 1 M -> S-M.
2. **Delta B (learning feedback):** Phase 2 renamed "Live Progress and
   Reinforcement", gaining toasts T1-T5 (T1 sealed-roster note as
   ruled) and the incident checklist folded into `PhaseStrip` (B-OD-5
   as ruled: the static consider-prompt is GUIDED-ONLY). Phase 5 gains
   the Case Closed -> grade -> review payoff, achievements, Key
   takeaway, and the ratified B-OD-1 venue (Metrics/Analytics = the
   per-incident Learning Review home; one teaching venue). Phase 6
   becomes the help model (permanent tooltips — nine controls with
   Amendment 2; Guided-only "Need a hint?" L1/L2; no once-only
   persistence — D5 superseded; L3 hints and the progression store
   DEFERRED per B-OD-2/B-OD-4). Sizing: Phase 2 M -> M-L, Phase 5 L
   (grown), Phase 6 M (recomposed).
3. **Amendment 2 (SIEM search clarity):** the merged Phase 3/4 review
   cycle (ruling G) gains commits 3.2 (ruled verb tooltips; "Example:"
   placeholder; empty-run gating; the ruled three-line section-named
   error form; "Restore last working query"; the generated-forms parse
   corpus), 3.3 (chips, remove-only, with the binding Custom-filters
   boundary test), and 3.4 (reversible surrounding events with the
   ruled block copy). Merged-cycle sizing S-M + S -> M.
4. **Section 19 numbering final:** Amendment 1 Delta B = 19.17-19;
   Amendment 2 A2-AC-1..7 = 19.20-26.

Every in-place edit below is one of these four items; anything not
listed is unchanged from the approved text.

Standing constraints restated as binding for every phase: the two owner
asset files (`frontend/public/videos/spectyrvideo.mp4`,
`frontend/public/spectyr_svg.svg`) remain untouched; nothing is pushed to
origin; never land red (`run_gates.py`, pre-commit hook); **no LLM-based
grading anywhere** (every verdict in this plan is a deterministic pure
function); no answer-bearing serialization before submission; Section 20
deferrals stay deferred.

---

## 1. Baseline and scope

### 1.1 Commit baseline

| Anchor | Commit |
|---|---|
| Current `main` tip (at scaffold authoring) | `7675260` (Stage 5A contract closure merge) |
| Contract lock record | `c81d0af` (locked text = Revision 3, `cd3a74a`) |
| Contract baseline | `09eea3b` (M2 merge; M1 at `38ee145`) |
| Stage 4 product baseline | `a863264` (workbench merge) |
| Pre-Stage-5 hotfix (shared roster) | `a204995` |

### 1.2 Test baseline (at `7675260`)

- **Backend: 27 gate suites** (`run_gates.py` `BACKEND_SUITES` +
  `parity_check.py` / `parity_check_v2.py` / `fairness_check.py`), all
  green at the lock-gate run of 2026-07-24.
- **Frontend: 18 suites / 173 tests** (`frontend/src/__tests__/`,
  including M1's `scope-truth.test.js`), all green same run.
- Every citation below (`path:line`) was verified against the working
  tree at `7675260` during scaffold authoring.

### 1.3 Existing foundation — what M1 landed and Phase 1 must NOT rebuild

Micro-fix M1 (merge `38ee145`) already implements the Section 11.1
behavior table on Detections and Endpoints:

| Piece | Exists today (NOT re-implemented) |
|---|---|
| `frontend/src/components/useIncidentScope.js` | ONE scope state per surface: `selection` + explicit fetch `status`; scoped data retained through in-flight refresh/failure, replaced atomically, dropped on incident change; row policy `all`/`scoped`/`loading`/`error` derived from that one state (`useIncidentScope.js:76-78`) |
| `frontend/src/components/IncidentScopeBar.jsx` | Label, toggle (`aria-pressed`), loading/error notices including the stale-rows honesty statement "Displayed rows are from the last successful scope read." (`IncidentScopeBar.jsx:37`), Retry + Use Session-wide controls — all from the same state |
| `Detections.jsx` | Hook consumed at `:103`; scope refetch joins the existing 2.5s feed poll (`:131-138`); rows derive from the one state (`:192-198`); loading/error empty states (`:314-316`) |
| `Endpoints.jsx` | Hook at `:67`; fetch on tab open/reset (`:82-84`) and pivot (`:95-101`); scope refetch on tab visibility (`:86-93`, no poll); rows (`:110-112`) |
| `frontend/src/__tests__/scope-truth.test.js` | The three-way label/control/rows synchronization battery for both surfaces |

What workstream 5.6 (Phase 1) **still requires** (Section 2.1, as
consolidated under Amendment 1 Delta A): the pinned case header
("Investigating INC-####" / "All activity") unifying the Dashboard
focus banner; the SIEM case-evidence/expanded-search state pair (scope
select removed; "Search all evidence" + the single "Return to INC-####
evidence" action); removal of the M1 toggle and Use Session-wide
controls from `IncidentScopeBar` (the hook, honesty rows, and refresh
triggers are kept verbatim; the error-empty state is Retry-only per
ratified A-OD-3); the 11.3 edited-query and parse-failure honesty notes
(unchanged); and the three-state sync-battery translation plus the
structural case-never-changes-implicitly assertion (A1-A.3/A1-A.6 —
dual return controls and the expandable two-concept summary are
DROPPED; OD-12/13/14 superseded, OD-15 structural).

### 1.4 Frozen boundaries inherited (unchanged by Stage 5)

Scoring semantics and weights (collateral pricing, 40/30/30 composite),
readiness rules and detection-roster sealing, the shared-roster
invariant (`_incident_roster`), the submission boundary
(`submit_incident`, app.py:3531) and record immutability, answer keys
and scenario content parity (v1/v2, `test_corpus_matches_v1_content`),
response actions/overlay/traps, detection generation and
indistinguishability, LCQL grammar and snapshot/token semantics, world
generation, `GUIDED_MODES` (app.py:3481), mode intake. **One authorized
crossing, ratified in the contract (OD-2 / D1):** the submission-record
schema gains the additive frozen `response_review` breakdown at Phase 5
— disclosed in full in Section 3. **One content addition (OD-3 / D2):**
the schema v2 Tier 2 rationale field — Section 3.4.

### 1.5 Explicitly NOT in this implementation

Tier 3 per-action rationale; server-side onboarding/profile persistence;
SOC Queue onboarding; difficulty rubric; response-vocabulary-v2;
trusted-actor scenario; A2 replay; exact-id descent; saved searches /
snapshot history / graph / live tail; advanced LCQL operators;
CampaignProgress micro-fix; cross-session identity; visual-polish phase;
timeline-coherent Response Log display; detection-materialization timing
(all Section 20 deferrals). Also not here: any change to the server 409
readiness strings or any other 3.9A-pinned payload text (Section 11
item E records the choice).

---

## 2. Architecture map (per workstream: current -> target)

### 2.1 Workstream 5.6 — investigation context and scope truth (Phase 1)

- **Current:** SIEM scope state machine (`Siem.jsx:50` `scope`,
  `:105` loading transition, scope select + chip `:400-436` with
  "loading scope"/"scope unavailable"); return chip "Back to
  {lastIncident}" (`:437-447`, tracks `lastIncident` `:69`); parse-error
  box (`:509-517`, no stale-results statement); snapshot status line
  (`:519-538` — count, `as of seq #N`, sim time, canonical query at
  `:526`, new-count indicator + stale de-emphasis, Refresh); timeline
  banner (`:552-583`, identity guard `timelineActive` `:352-353`);
  selection/query notices (`:584-594`). Detections/Endpoints scope truth
  per Section 1.3 (M1).
- **Target (consolidated, A1-A.4 / A1-A.8):** **added**
  `frontend/src/components/InvestigationContext.jsx` — the SHRUNK
  case-constant presentation: ONE pinned case line ("Investigating
  INC-####" / "All activity") plus the expanded-search block rendered
  only while that state is live (title, followed clue when entered by
  pivot, "Searching all evidence. Your case INC-#### stays open.", the
  single "Return to INC-#### evidence" action). Pure presentation over
  props; zero requests (risk R5 by construction). **Adapted**
  `Dashboard.jsx`: the global "Focused on incident INC-####" banner is
  REPLACED by the pinned header. **Adapted** `Siem.jsx`: the scope
  select is REMOVED in favor of the state pair (case evidence default
  with the query-bar-adjacent "INC-#### evidence" label + "Search all
  evidence" action per ratified A-OD-4; expanded search entered only by
  entity pivot or search-all, exited only by the return action or an
  explicit case change on Incidents); the status line kept with
  "Results from:" labeling (the LCQL scope token stays visible there
  and only there); 11.3 notes (bar text differs from executed ->
  "Edited. Results below are from the last run."; parse/execution
  failure -> "Displayed results are from the previous successful
  query.", prior-snapshot preservation is already the behavior).
  **Adapted** `IncidentScopeBar.jsx`: toggle + Use Session-wide
  REMOVED; pinned header rendered; `useIncidentScope`, the honesty rows
  ("Loading incident scope", "Displayed rows are from the last
  successful scope read.", Retry), and the per-surface refresh triggers
  kept verbatim (error-empty state Retry-only, ratified A-OD-3).
- **Constrained today by:** `scope-truth.test.js` (M1 battery),
  `workbench*.test.js` (shell behavior), `scope-no-mutation.test.js`.
- **Tests to add:** `investigation-context.test.js` (pinned line in
  both states; block with/without clue; single return naming the case
  — translated acceptance 13); `scope-truth.test.js` TRANSLATED to the
  three-state battery (a case-selected surface never renders
  all-activity rows; atomicity at the state-model level);
  `workbench-states.test.js` (11.3 notes; the single-return matrix +
  the structural no-implicit-case-change assertion — the dual-control
  matrix is dropped).

### 2.2 Workstream 5.4 — Live Progress and Reinforcement (Phase 2)

- **Current copy inventory (verified):** `PhaseStrip`
  (`Incidents.jsx:19-40`): "Incident telemetry is still loading." /
  "Triage {t} of {T} reviewed" / "Investigate evidence" / "Respond {n}
  related" / "Submit ready|pending", rendered for submitted incidents
  with `sealed` forced true and `{total:0,triaged:0}` fallback
  (`:21`, `:240-241` — the 0-of-0 defect); incident card rows
  "`${open_detections} left`" (`Incidents.jsx:212`); readiness line
  "N detections still need review." (`:301-302`); Related response
  activity via the fuzzy label-substring join (`:84-88`, list rendered
  `:274-282`); Dashboard active rows "N to review"
  (`IncidentDashboard.jsx:114`); Detections counters line (`:258`) and
  Feed/Threats toggle (`:240`); Metrics in-progress banner
  (`Analytics.jsx` / `ScoreSections.jsx`).
- **Target:** **added** `frontend/src/components/uiCopy.js` — the ONE
  canonical vocabulary module: every Section 10.1 string as a named
  constant/template, plus the Section 8.2 transition forms (consumed by
  Phases 1 and 3 — see the R7 note below), plus the 11.x strings M1/Phase
  1 introduced (imported back so the module is the single source).
  **Adapted:** every surface in the 10.2 mapping consumes the constants;
  `PhaseStrip` renders the canonical strings, gains the **completed
  strip** variant "Reviewed {total} of {total} · Submitted" (total from
  the score view's `detection.total` — **[Scaffold decision, D3]**
  frontend-only source, the contract's stated default; no completed-card
  field added), and the active strip renders ONLY for
  `state == 'in_progress'` (0-of-0 structurally impossible —
  acceptance 14). **Adapted backend:** `list_incidents`
  (app.py:3963-3993) active sealed cards gain `related_actions` (D4,
  OD-8): count of successful log entries whose registry-resolved target
  is in the incident's **observable** scope (hosts + accounts from
  `_incident_observable_scope`) — a new small helper
  `_entry_in_observable_scope` mirroring `_entry_in_scope`
  (app.py:3401-3408) but joining against observable sets, because
  `_entry_in_scope` joins against the grading record (Section 11 item
  D). The fuzzy client join (`Incidents.jsx:84-88`) is deleted; the
  strip's Respond step reads the card field with the canonical phrasing.
- **R7 ordering note (binding):** the vocabulary constants + their test
  land in Phase 2 commit 2.1 **before any later phase consumes them**;
  Phase 1 (which precedes Phase 2) introduces only its own 11.x context
  strings and does so in the same module file (created at Phase 1 with
  the 11.x strings; completed + tested as the canonical vocabulary in
  2.1) so no string is ever defined twice.
- **Constrained today by:** `incidents-workspace.test.js`,
  `incident-dashboard.test.js`, `detections.test.js`,
  `copy-emdash.test.js` (scans ALL non-test source with comments
  stripped — every new string is automatically covered).
- **Tests to add:** `progress-vocabulary.test.js` — canonical-copy
  assertions per surface driven by the constants; the forbidden-phrase
  scan (10.1's forbidden class) over pre-submission surfaces; the 0-of-0
  regression (completed incident never renders the active strip);
  "N to review" everywhere. Backend: D4 field test (observable-only
  shape; count correctness on a fixture session; structural no-answer-key
  guard extended over the new reader).
- **Consolidated additions (A1-B.8; ruled adjustments):** action-result
  **toasts** for exactly the A1-B.3.1 trigger list T1-T5 (disposition
  results with the observable remaining count; action results rendered
  from the action POST response fields only, shape-identical across
  required/acceptable/collateral; the two milestones). **T1
  sealed-roster note (ruled):** the remaining-count line derives from
  the shared roster and renders only once the incident's roster is
  SEALED; before seal, or for a disposition in no sealed incident
  roster, the toast confirms the disposition alone. NO toast for
  read-only operations, case selection, classification selection,
  submission, or any fact a persistent surface already announces (one
  announcement per fact). The **incident checklist** folds INTO
  `PhaseStrip` (lines: telemetry / detections reviewed / classification
  selected / response actions taken / ready to submit; the "Investigate
  evidence" step is dropped — no observable completion state). **Leak
  rule binding (A1-B.3.2 / 19.18):** every line renders identically for
  every incident; the response line shows the D4 count plus the ONE
  static prompt "Consider whether containment or remediation is
  needed." — **GUIDED-ONLY as ruled (B-OD-5)**, suppressed in SOC Queue
  and Hardcore; the count line renders in all modes. Vocabulary rows:
  the Session-wide strings leave the module; the case-constant terms
  (A1-A.5 ratified finals) and the toast/checklist strings enter as
  canonical rows.

### 2.3 Workstream 5.2 — pivot transition clarity (Phase 3)

- **Current:** `pivotAndRun` (`Siem.jsx:224-231`) flips scope and runs,
  announcing nothing; refine path appends with the OR fresh-query notice
  (`queryNotice`, `:590-594`); descent/surrounding banner exists with
  the snapshot-identity guard (`:352-353`, `:552-583`); pivot buttons
  carry title tooltips (`EventInspector.jsx:126`); `PIVOT_MAP`
  (`EventInspector.jsx:31-43`) names the clue kinds; `lcqlPivots.js` is
  the single generation choke point.
- **Target:** **added** transition-banner rendering in the SAME slot and
  under the SAME identity guard as the descent banner (generalizing
  `timelineActive`): every entity pivot and refine announces per 8.2 —
  clue naming ("Following clue: `<field> = "<value>"`" / "Filter added:"
  / "Excluded:"), scope transition stated only when it happened ("Scope
  changed: INC-#### → Session-wide." + subcopy), origin + return path,
  no-results persistence (banner survives the 0-events state with the
  two designed outs), OR fresh-query notice FOLDED into the banner (one
  notice, not two — `queryNotice` retires into it). The banner state
  rides the existing `timeline`-style provenance object extended with a
  `transition` kind; it renders from the generated query + pivot request
  only and dies when the snapshot stops being its query. The 8.3
  per-source matrix is the behavior spec; the 8.4 shared-vocabulary rule
  is satisfied by both the banner and the Phase 1 context summary
  consuming the same `uiCopy.js` transition forms. First-use explainer
  text is NOT rendered here (it is 5.5 machinery; Phase 6 adds it into
  the banner's explainer slot).
- **Tests to add:** `pivot-transitions.test.js` — the transition
  surface per the translated 8.3 matrix (from case evidence enters
  Expanded search; within Expanded search updates the clue; no-case is
  plain; OR-refine folding; from-descent; from-surrounding; repeat-use
  always-renders); the surface dies with its snapshot; no-results
  persistence; state entry/exit (pivot-entry, search-all-entry,
  return-exit, case-change-exit).
- **Consolidated (A1-A.8 Phase 3; A2-6):** the transition surface IS
  the expanded-search block (Delta A): a pivot from case evidence
  enters Expanded search naming the clue; "Scope changed: INC-#### ->
  Session-wide." copy is retired; the OR fresh-query notice still folds
  into the one announcement. The merged Phase 3/4 review cycle
  additionally lands Amendment 2:
  - **Commit 3.2 (query clarity):** ruled verb tooltips for
    `==`/`!=`/Pivot/Surrounding events (A2-R.1 canonical finals); the
    "Example:" placeholder; empty-run gating ("No query entered.";
    Run disables ONLY on a truly empty bar); the RULED three-line error
    form — "This search was not run." / "The {Time / Source / Event
    type / Filters} section could not be read." / the locked 11.3 third
    line — section named client-side from the parser position;
    "Restore last working query"; the generated-forms parse corpus
    (frontend byte-pin + `test_lcql.py` tests-only extension;
    generated-query failure is a DEFECT, never a player error).
  - **Commit 3.3 (chips):** remove-only read projection of the
    executed canonical FILTERS; removal regenerates through the new
    `lcqlPivots.js` remove/join generator form and reruns; the BINDING
    boundary test — "Custom filters" never renders for a
    conjunction-only query and always renders for any top-level OR,
    including the IP-pivot and identity-descent product forms.
  - **Commit 3.4 (reversible surrounding events):** single-depth hold
    of the prior evidence view; ruled block copy "Activity around the
    selected event on {host}" / "Occurrence ascending" / "Back to
    previous results"; return redisplays the held frozen snapshot with
    zero requests.
  - First-use explainer: retired into the Pivot tooltip (Delta B help
    model); the Phase 6 explainer slot is gone.
  `lcqlPivots.js` gains the remove/join form (the single query author
  gains a form, never a second author); `workbench-pivots.test.js` and
  backend `test_lcql.py` extend to the closed corpus (tests only).

### 2.4 Workstream 5.3 — inspector-selection connection (Phase 4)

- **Current:** shared inspector below results (`Siem.jsx:651-657`);
  table selected row = subtle background (`SiemTable.jsx:190-192`) +
  misleading rotating chevron (`:196-203`); severity is the row's
  left border color (`:195`); cards use a ring (`SiemCards.jsx:90-92`);
  no scroll-into-view; selection is shell-owned and id-keyed
  (`Siem.jsx:53`).
- **Target (OD-5, Option A):** **adapted** `SiemTable.jsx` — strong
  selected treatment equivalent to the cards' ring: background +
  selection accent that must NOT occupy the severity border (the
  severity left border at `:195` stays untouched; the selection accent
  is an additional treatment — ring/outline per the cards' pattern);
  chevron replaced by a selection affordance that does not promise
  inline expansion; `aria-selected` on rows. **Adapted** `Siem.jsx` —
  on selection change: inspector scroll-into-view (`block: 'nearest'`),
  one emphasis transition run on the inspector container, both gated by
  `prefers-reduced-motion` (jump, no animation); focus moved to the
  container exactly once per selection change (Section 16). Deselection
  closes (existing). Selection persistence across Cards/Table and client
  sort retained verbatim and re-asserted.
- **Tests to add:** `inspector-connection.test.js` — scroll called once
  per selection change; emphasis once (no loop); reduced-motion path;
  chevron affordance replaced; persistence re-asserted across
  views/sort/refresh; existing `workbench-inspector.test.js` leak-guard
  and kvp-order fixtures stay green (one inspector).

### 2.5 Workstream 5.1 — post-incident review teaching (Phase 5)

Sections 3 (data plan) and 6 Phase 5 (commits) carry the full detail;
summary: **adapted** `compute_action_score` (app.py:4256) gains an
additive, popped `_review` detail output built inside its existing joins
(no semantic change — Section 11 item B); **adapted**
`_incident_report_card` (app.py:3425) assembles and FREEZES the complete
`response_review` into the stored record at submit; **adapted** review
modal (`Incidents.jsx:379-416`) renders the three teaching buckets +
attempt history + the already-served `response_actions` playbook +
empty states; **added** Tier 1 generic templates (code constants) and
Tier 2 scenario paragraphs (schema v2 top-level field, per-scenario
authored commits).

**Consolidated additions (A1-B.8; ratified B-OD-1 Option 1):** the
submit-success flow becomes Case Closed (restrained, static,
reduced-motion honoring) -> Incident Grade reveal -> review. The
**Learning Review home moves to the Metrics/Analytics tab**
(per-incident, durably revisitable, Incident Grade vs Session
Performance labeling preserved with a per-incident selector); the
Incidents completed pane shows the Case Closed summary + the "Review
what you learned" path; the in-workspace modal NEVER renders teaching
content again (one venue). Achievements (Case Closed, Clean Triage,
Response Ready, No Collateral, Solo Close, Perfect Case) are computed
at render from the served frozen record only (derivations A1-B.4.3);
deferred achievements stay deferred (B-OD-3). Key takeaway renders
`scenario_rationale` (null -> section omitted, ruling H); zero new
authoring.

### 2.6 Workstream 5.5 — Guided onboarding (Phase 6)

- **Current:** no onboarding machinery anywhere (verified — contract
  4.2); mode is client-known (`Dashboard.jsx:35` `gameMode`, set from
  `/api/game-state` at `:87`); a Docs page exists
  (`frontend/src/pages/Docs.jsx`) — the OD-7 reopen path has a home.
- **Target (consolidated, A1-B.5 + A2-R rulings; replaces the
  callout/persistence model — the previously ratified
  `spectyr_onboarding_v1` layout is SUPERSEDED with D5):** **added**
  permanent accessible tooltips for NINE controls (Promote, Dismiss,
  Reopen, Feed/Threats, `==`, `!=`, Pivot, Expanded search, Surrounding
  events) with the ruled canonical finals; all modes, every visit
  (invariant-7 reading recorded: passive player-invoked mechanics help,
  not a tutorial interruption). **Added** the Guided-only "Need a
  hint?" flow: Level 1 mechanics help + Level 2 generic investigation
  nudges, both static and scenario-independent
  (`HINT_MODES = ['guided']` allow-list; the binding neutrality rule —
  availability, ordering, and wording never vary with hidden state —
  enforced by a structural inputs test: surface id, control id, level,
  nothing else). Level 3 scenario hints DEFERRED (B-OD-2). Hardcore:
  tooltips + factual confirmations + final results only. No once-only
  persistence, no reopen machinery, no Docs-page coupling.
- **Tests to add:** `help-model.test.js` — tooltip presence on all nine
  controls in every mode; hint flow Guided-only (**Hardcore-never and
  SOC-Queue-never** allow-list assertions); the structural hint-inputs
  (neutrality) test; the copy denylist over tooltip/hint strings
  (correctness phrasing, scenario answers, active-scenario category
  names); Hardcore purity (no prompt line, no hints, no coaching).

---

## 3. Data model and serialized-field plan (D1-D6, complete)

No new endpoints in Stage 5. Two payload changes and one content field,
each disclosed here and again in the Phase 7 report:

| # | Change | Venue | Phase/commit |
|---|---|---|---|
| D1 | `response_review` frozen into the submission record, serialized inside the submitted `grading` | stored in `record["report_card"]["response_review"]` at submit (**[Scaffold decision]** below); served automatically by `incident_score_view` (app.py:3673-3679) | 5.3 |
| D2 | Tier 2 scenario rationale | **top-level** schema v2 field `expected_response` (**[Scaffold decision]** — a SIBLING of `triage_review`, Section 11 item C) | 5.5 + per-scenario |
| D3 | Completed-strip total | **none** — frontend reads the score view's `detection.total` (contract's stated default) | 2.3 |
| D4 | `related_actions` observable count on active incident cards | `GET /api/incidents` active sealed cards | 2.2 |
| D5 | SUPERSEDED (consolidated revision): the help model has no once-only persistence; no client store ships in Stage 5 (progression store deferred, B-OD-4) | — | — |
| D6 | NO other changes | event payloads, LCQL, snapshot identity/tokens, readiness rules, scoring semantics/weights, detection generation, world, answer-key grammar (except D2), pre-submission shapes | — |

### 3.1 D1 — the `response_review` frozen breakdown (complete field plan)

**Storage [Scaffold decision]:** a first-class key of the stored
`report_card` (beside `classification`/`detection`/`response`/
`composite`, app.py:3465-3473). Consequences, verified against the code:
(a) `incident_score_view` serves it inside `grading` with **zero serving
change** (the underscore-strip at app.py:3676-3677 passes it through);
(b) `aggregate_submitted` (app.py:3690+) builds its own aggregate shape
from named dims, so the per-incident teaching payload **never enters the
session aggregate** (asserted by a new test); (c) byte-identity rides
the existing record immutability.

**Shape (frozen at submit; exactly contract 7.1):**

```
"response_review": {
  "entries":         [ { bucket, reason_code, action, target_label,
                         why, source_action_seq, expected_ref } ],
  "attempt_history": [ { seq, action, target_label, outcome,
                         reason_code } ],
  "detections":      [ { rule_name, entity_label, your_call, correct } ],
  "scenario_rationale": <string | null>   // Tier 2 paragraph frozen at
                                          // submit; null when unauthored
                                          // (Section 11 item H)
}
```

**Derivation (R1: reuse, not reimplementation).** Every entry verdict is
computed INSIDE `compute_action_score`'s existing joins, in the same
pass, and returned as a popped internal key (the established
`acceptable_seqs` pattern, app.py:4437 / consumed app.py:3443-3446):

| 7.1 reason_code | Exact code site producing the verdict |
|---|---|
| `required_completed` | the required loop's `achieved and order_ok` branch (app.py:4356-4357), seq from `occurrence_seq` over the `first` map (app.py:4325-4338) |
| `required_not_attempted` / `required_attempt_failed` | `seq is None` in the required loop; the two codes are split OUTSIDE the scorer by `_incident_report_card`, which scans the overlay log for registry-resolved failed attempts of the same composite (the scorer never sees failed attempts — `successful_executions`, action_overlay.py:501-515, filters to SUCCESS; the log and registry are both in scope at app.py:3437-3457). No matching failed attempt -> `required_not_attempted` |
| `out_of_order` | `achieved and not order_ok` (app.py:4360-4362), seq carried |
| `released_after_isolation` | isolation exp with `occurrence_seq` non-None but hostname not in `isolated_hosts` (app.py:4346-4349) — distinguishable from never-attempted by the seq's existence; seq of the isolate occurrence carried |
| `acceptable_completed` | `acceptable_seqs` membership (app.py:4369-4371), seq carried (per the Revision 3 Section 7.1 enumeration) |
| `collateral_in_scope` | `collateral_hits` (occurrence collateral app.py:4373-4381; end-state isolation collateral app.py:4382-4390), seq from the `first` map |
| `inaction_correct` / `inaction_spoiled` | the inaction fold-in branch (app.py:4395-4403), one entry per incident, `source_action_seq: null` |
| `failed_precondition` / `no_effect_repeat` (history only) | the existing `not_executed` / `no_effect` block entries (app.py:3449-3457), re-labeled with the stable codes |

`expected_ref` = the answer key's `(action, composite target)` pair
identity (loader-unique per scenario), taken from the materialized
expected composites (`materialize_expected_actions`, app.py:2340).
`target_label`: executed occurrences reuse the registry display label
(`target_label`, action_overlay.py:445-459); never-executed required
targets resolve composite -> registry entity (achievability guarantees
every required target exists in the initial world, so a registry entity
and its label exist) with a composite-grammar fallback renderer for
robustness **[Scaffold decision]**.

**Detections block:** built at submit from the frozen
`inputs.detection_dispositions` (app.py:3579) joined to the roster
instances (`rule_name`, `entity` — detection_templates.py:363-383);
`correct` from the same disposition-correctness rule
`compute_detection_score` applies (extracted as a tiny shared helper
with the detection-scoring suite untouched — Section 11 item B).

**Whys:** Tier 1 generic templates (code constants, ~10, one per
(verb, reason-code class), composed with the target label ONLY —
template-purity test enforces no scenario tokens); the two contract
examples (7.3) are canonical copy, the remainder are new copy
(Section 5). `scenario_rationale` = the D2 paragraph when authored.

**Freeze completeness (review correction 6):** the complete rendered
breakdown — buckets, codes, labels, why prose, detection correctness,
seq refs, scenario_rationale — is stored at `submit_incident` time;
the score view serves the stored object and never recomputes. The
permanent freeze test submits, mutates template constants and the loaded
YAML rationale in memory, re-reads, and asserts byte-identical teaching
content.

**Byte-identity extension:** the existing
`test_submission_gate.py::test_submission_is_idempotent_and_immutable`
(:246) and `::test_submitted_grade_byte_identical_under_cross_incident_activity`
(:269) are extended to cover the breakdown (never weakened); the
count-reconciliation criterion (Section 19.16, both fold-in mappings)
lands as a permanent fixture test AND a real-drip corpus pass.

### 3.2 D4 — `related_actions` (Phase 2)

Active sealed cards on `GET /api/incidents` gain
`"related_actions": <int>` — successful log entries whose
registry-resolved target is an observable scope host/account
(new `_entry_in_observable_scope`; the observable sets from
`_incident_observable_scope`, app.py:3880). A count of the player's own
actions: observable by definition, no required-total or correctness
signal. Guards land in the same commit (R2): shape test, count fixture,
structural no-answer-key extension over the new reader.

### 3.3 D3 — completed strip source

Frontend-only: the completed detail pane already has the score fetch;
`detection.total` feeds "Reviewed {total} of {total} · Submitted". No
backend change (contract 10.4's stated default).

### 3.4 D2 — schema v2 `expected_response` (Phase 5.5 + authoring)

**[Scaffold decision — field placement]:** a **top-level** optional
schema property (sibling of `triage_review`), NOT a key inside
`triage_review`: `test_scenario_loader_v2.py::test_corpus_matches_v1_content`
(:127-139) asserts the v2 triage-review dict EQUALS the corrected v1
dict (:134-136), so an in-`triage_review` key would land a red guard —
and the migration-boundary principle says the boundary would be wrong,
not the guard. Top-level placement leaves triage parity byte-identical.
Schema: `"expected_response": {"type": "string", "minLength": 1}`,
optional during rollout; loader validates when present; a **ledger
test** (the 3c cadence pattern) pins which scenarios carry it and
ratchets as authoring lands; it flips to required-by-ledger at 20/20
(never a schema-required flip that would land red mid-rollout). The v1
corpus and revert paths are untouched.

---

## 4. Legacy-record behavior (verified and stated)

**Submitted records lacking the frozen breakdown CANNOT exist at deploy
time.** `session["submissions"]` is in-memory only — created empty at
`create_session` (app.py:225) and `start`/reset (app.py:3153, 4905),
written only at app.py:3585, and **never persisted to any file**
(verified: every `submissions` reference is a dict access; the session
NDJSON files carry logs/actions/reports only). Deploying Phase 5
restarts the single-worker process, which discards every session and
record; sessions also expire after 30 minutes of inactivity. Therefore
no review modal will ever fetch a pre-Phase-5 record, and immutability
is never in tension with the new field — no backfill, no migration, no
owner decision needed. Defensively, the modal's 7.1 failed-fetch line
("The detailed breakdown could not be loaded" + retry) also renders if
`response_review` is ever absent from a payload — a degraded-render
guard, not a legacy path.

---

## 5. Copy inventory and sourcing

The em-dash scan (`copy-emdash.test.js`) covers ALL non-test source with
comments stripped, so every string below is automatically scanned the
moment it lands. Sources: **10.1** = canonical vocabulary table, **8.2**
= canonical transition forms, **7.1/11.x/12** = strings quoted in those
contract sections, **NEW** = originates in implementation (flagged here;
none originates in this scaffold's own voice — NEW strings are drafted
at implementation and reviewed at the phase's [STOP]).

| String (or family) | Source | Lands |
|---|---|---|
| "Incident telemetry is still loading." | 10.1 (already live) | — |
| "Detections reviewed: {triaged} of {total}" | 10.1 | 2.2 |
| "{n} detection{s} still need Promote or Dismiss" | 10.1 | 2.2 |
| "Promoted" / "Dismissed" / "Reopened (needs review again)" | 10.1 | 2.2 |
| "Response actions taken: {n}" | 10.1 | 2.2 |
| "Ready to submit" / "Submitted. Grade locked." | 10.1 | 2.2 |
| "Reviewed {total} of {total} · Submitted" | 10.1 | 2.3 |
| "{n} to review" (card rows; replaces "{n} left", Incidents.jsx:212) | 10.2 | 2.2 |
| "Feed: every detection, including reviewed" / "Threats: detections you promoted" | 10.2 / OD-9 | 2.2 |
| "Following clue: `<field> = "<value>"`" / "Filter added:" / "Excluded:" | 8.2 | 3.1 |
| "Scope changed: INC-#### → Session-wide." + "Showing Session-wide activity for {account}." | 8.2 | 3.1 |
| Origin/return lines ("from the {host} timeline" / "Back to INC-#### restores that incident's scope for this query") | 8.2 | 3.1 |
| Pivot first-use explainer ("A pivot follows a user, host, IP, file, process, or other clue across available evidence.") | 8.2 | 6.2 |
| "Current case:" / "Data scope:" / "Following clue:" / "View:" / "Results from:" | 11.2 | 1.2 |
| "Edited. Results below are from the last run." | 11.3 | 1.3 |
| "Displayed results are from the previous successful query." | 11.3 | 1.3 |
| "Loading incident scope" / "Displayed rows are from the last successful scope read." / Retry / Use Session-wide | 11.1 (live since M1) | — |
| Inaction empty-state ("No response action was required. The correct response here was investigation without action.") | 7.1 | 5.4 |
| "The detailed breakdown could not be loaded" + retry | 7.1 | 5.4 |
| Tier 1 why templates: the two 7.3 examples | 7.3 | 5.1 |
| Tier 1 why templates: the remaining ~8 | **NEW** (purpose-only rule; template-purity test) | 5.1, [STOP] review |
| Review section headers (correct/missed/unnecessary-or-harmful framing) | **NEW** (7.5 acceptance language) | 5.4, [STOP] review |
| Onboarding concept copy (12.1 inventory) | **NEW** (answer-free; denylist test) | 6.2, [STOP] review |
| "Show tips again" / "Don't show tips" | 12.2 | 6.1 |
| PhaseStrip "Investigate" step detail | **NEW** (kept observable-neutral) | 2.2, [STOP] review |

**Consolidated copy changes (governing: A1-A.5 ratified finals; A2-R.1
ruled finals; A1-B strings):** the "Scope changed: INC-#### →
Session-wide." row, its Session-wide subcopy, the 11.2 "Current case: /
Data scope:" family, "Use Session-wide", and the onboarding rows ("Show
tips again" / "Don't show tips", the once-only pivot explainer) are
SUPERSEDED. Entering as canonical rows in their owning commits (all
em-dash and denylist scanned): the case-constant terms ("Investigating
INC-####", "All activity", "INC-#### evidence", "Expanded search",
"Searching all evidence. Your case INC-#### stays open.", "Return to
INC-#### evidence", "Search all evidence", the return subcopy); the
nine ruled tooltips; the ruled three-line error form ("This search was
not run." / "The {Time / Source / Event type / Filters} section could
not be read." / the locked 11.3 third line); "No query entered.";
"Restore last working query"; "Back to previous results"; "Custom
filters"; the "Example:" placeholder; the surrounding block copy
("Activity around the selected event on {host}" / "Occurrence
ascending"); the toast strings (T1-T5); the checklist lines + the
Guided-only prompt ("Consider whether containment or remediation is
needed."); Case Closed, the achievement labels, and "Review what you
learned".

Tier 2 scenario paragraphs are answer-bearing authored content — they
follow the per-scenario review cadence (Section 6, Phase 5), not this
table.

---

## 6. Build phases and checkpoints

Phase order is the contract's ratified Section 23 order — fixed. Every
phase ends independently gate-green and stoppable; no phase depends on a
later one. **[STOP]** marks a commit that changes player-facing behavior
or a serialized payload: it halts for owner approval before proceeding
(the M1 checkpoint pattern). Unmarked commits are internal (constants,
tests, refactors with no behavior change) and proceed to the phase gate.
Gate checkpoint after EVERY commit: `run_gates.py` scoped to what the
commit touches (`--all` when a serialized payload changes — the Stage 4
rule); the phase gate is always `--all`.

---

**Phase 0 — scaffold approval.** This document, committed docs-only on
`stage-5-implementation-scaffold`. Stop condition: owner approval of
this scaffold (which ratifies the [Scaffold decision] items and rules on
the Section 11 register). No product code.

---

**Phase 1 — scope truth and investigation context (5.6).**
- **Concern:** one truthful context layer over existing state; F8 closed
  architecturally; M1 foundation extended, never rebuilt.
- **Prerequisites:** Phase 0 approval.
- **Files:** added `InvestigationContext.jsx`, `uiCopy.js`
  (case-constant context strings at this phase),
  `investigation-context.test.js`; adapted `Siem.jsx`,
  `IncidentScopeBar.jsx`, `Dashboard.jsx`, `scope-truth.test.js`,
  `workbench-states.test.js`.
- **Endpoint/field changes:** none (frontend-only phase; the summary
  issues no requests).
- **Commits:**
  - (1.1) internal: `uiCopy.js` created with the case-constant context
    strings (A1-A.5 ratified finals + the 11.3 notes);
    `InvestigationContext` (pinned line + expanded-search block) +
    tests rendering from mocked state (not yet mounted). No behavior
    change.
  - (1.2) **[STOP]** the case-constant state model lands: pinned header
    on Detections/Endpoints/SIEM (replacing the Dashboard focus
    banner); All-activity states; SIEM state pair (scope select
    removed; "Search all evidence" per A-OD-4; expanded-search block;
    single return); `IncidentScopeBar` toggle + Use Session-wide
    removed (hook + honesty rows kept); "Results from" labeling of the
    existing canonical-query echo; `scope-truth.test.js` translated to
    the three-state battery. Section 17 rows landing: 5.6 frontend
    "pinned line/block == executed state" (translated 13).
  - (1.3) **[STOP]** 11.3 notes (edited-note; parse/execution-failure
    stale-results statement); the structural
    case-never-changes-implicitly assertion; the single-return matrix
    (translated 11); battery completion — translated acceptance 10-13
    green. Section 17 rows: parse-failure notice; single return; the
    SIEM leg of the three-state battery + case-change atomicity
    (state-model level).
- **Section 17 battery rows:** 5.6 frontend rows split across 1.2/1.3 as
  above; 5.6 backend row (structural guard over new readers) is N/A this
  phase — no new backend reader exists (recorded; D4's reader lands in
  Phase 2 with its guard).
- **Gate checkpoint:** `--frontend` per commit; `--all` at phase end.
- **Stop point:** acceptance 10-13 demonstrably green (tests + a Chrome
  spot-check of the summary/controls); owner approves the two [STOP]
  commits.
- **Rollback:** frontend-only; each commit reverts cleanly.

---

**Phase 2 — Live Progress and Reinforcement (5.4, consolidated).**
- **Concern:** one observable vocabulary everywhere; 0-of-0 resolved;
  the honest related-actions count.
- **Prerequisites:** Phase 1.
- **Files:** adapted `uiCopy.js` (completed as the canonical module),
  `Incidents.jsx` (PhaseStrip + rows + readiness line + related list),
  `IncidentDashboard.jsx`, `Detections.jsx` (toggle subcopy),
  `Analytics.jsx`/`ScoreSections.jsx` (banner copy); added
  `progress-vocabulary.test.js`; backend adapted `app.py`
  (`list_incidents` + `_entry_in_observable_scope`), extended
  `test_submission_gate.py` or a small `test_incident_cards.py` for D4;
  `run_gates.py` list if a new suite file is added.
- **Endpoint/field changes:** D4 `related_actions` on active sealed
  cards (disclosed).
- **Commits:**
  - (2.1) internal: the complete 10.1 vocabulary in `uiCopy.js` + the
    canonical-copy test + forbidden-phrase scan (R7 lands HERE, before
    any consumer).
  - (2.2) **[STOP]** D4 backend field + guards (same commit, R2) + all
    surfaces adopt the vocabulary + fuzzy join deleted + "N to review"
    rows + Feed/Threats subcopy (OD-9). Section 17 rows: D4 field tests;
    canonical-copy per surface; forbidden-phrase scan.
  - (2.3) **[STOP]** completed strip (score-view-fed) + active strip
    gated to in_progress + 0-of-0 regression test. Section 17 row:
    completed-strip regression.
  - (2.4) **[STOP]** toasts T1-T5 (trigger-exactness tests; the ruled
    T1 sealed-roster note; `role="status"`/polite a11y; the
    no-duplication rule) + the checklist line set folded into
    `PhaseStrip` (classification line; the D4 count line; the
    GUIDED-ONLY static prompt per ruled B-OD-5; the leak battery per
    19.18). Section 17 rows: 19.17 toast exactness; 19.18 checklist
    leak.
- **Gate checkpoint:** `--all` for 2.2 (payload change); `--frontend`
  for 2.3 and 2.4; `--all` at phase end.
- **Stop point:** acceptance 7, 14, and 19.17-18 green; every 10.2
  surface reads constants; owner approves the [STOP] commits (the
  related-activity LIST question — Section 11 item A — is RULED:
  ruling A, count only).
- **Rollback:** 2.2 reverts as one commit (field + consumers together).

---

**Phase 3 — pivot transition clarity (5.2).**
- **Concern:** every pivot/refine announces itself; one notice system.
- **Prerequisites:** Phase 2 (consumes `uiCopy` 8.2 forms).
- **Files:** adapted `Siem.jsx` (transition surface + provenance state
  + queryNotice folding + query-clarity + surrounding hold),
  `EventInspector.jsx` (ruled tooltips + Pivot casing),
  `FieldSidebar.jsx` (tooltip), `lcqlPivots.js` (the remove/join
  generator form + corpus — the one sanctioned author gains a form),
  `uiCopy.js` (transition forms + A2 ruled strings); added
  `pivot-transitions.test.js`, `query-clarity.test.js`, chips tests;
  extended `workbench-pivots.test.js` and backend `test_lcql.py`
  (tests only).
- **Endpoint/field changes:** none (backend touch is tests-only).
- **Commits (ONE review cycle with Phase 4, ruling G; each separable):**
  - (3.1) **[STOP]** the expanded-search block as the transition
    surface (Delta A): clue naming, all-evidence statement, single
    return, OR-notice folding, no-results persistence, identity-guard
    death, state entry/exit tests.
  - (3.2) **[STOP]** query clarity (Amendment 2): ruled verb tooltips;
    "Example:" placeholder; empty-run gating ("No query entered.");
    the ruled three-line section-named error form; "Restore last
    working query"; the generated-forms parse corpus (19.20-22, 19.24,
    19.26).
  - (3.3) **[STOP]** chips: remove-only read projection; the
    `lcqlPivots.js` remove/join form; rerun on removal; the BINDING
    Custom-filters boundary test (19.23).
  - (3.4) **[STOP]** reversible surrounding events: single-depth hold;
    ruled block copy; zero-request frozen-snapshot restore (19.25).
- **Gate checkpoint:** `--frontend` per commit (`--all` where
  `test_lcql.py` extends); `--all` at phase end.
- **Stop point:** acceptance 5 and 19.20-26 green; the translated 8.3
  matrix + the A2 legs demonstrated in Chrome.
- **Rollback:** each commit reverts separably.

---

**Phase 4 — inspector continuity (5.3).**
- **Concern:** selection visibly connects to the inspector (OD-5 A).
- **Prerequisites:** Phase 3 (or merged with it — Section 7).
- **Files:** adapted `SiemTable.jsx`, `SiemCards.jsx` (shared treatment
  parity), `Siem.jsx` (scroll/emphasis/focus); added
  `inspector-connection.test.js`.
- **Endpoint/field changes:** none.
- **Commits:**
  - (4.1) **[STOP]** selected treatment + chevron replacement +
    `aria-selected` + scroll-into-view + one-run emphasis +
    reduced-motion + focus-once + persistence re-assertions. Section 17
    rows: all 5.3 rows.
- **Gate checkpoint:** `--frontend`; `--all` at phase end.
- **Stop point:** acceptance 6 green; Chrome check on a 50-row page.
- **Rollback:** single-commit revert.

---

**Phase 5 — post-incident review teaching (5.1).**
- **Concern:** the only data-model work of the stage; the review answers
  the three acceptance questions with identities and whys.
- **Prerequisites:** Phase 4 (settled vocabulary; Section 23 rationale).
- **Files:** backend adapted `app.py` (`compute_action_score`,
  `_incident_report_card`, `submit_incident` path), added
  `response_review.py` (templates + assembly helpers — keeping app.py
  additions small) + `test_response_review.py`; `run_gates.py` list;
  schema `scenarios/schema_v2.json` + `scenario_loader_v2.py` +
  `migrate_v1_to_v2.py` untouched-check; frontend adapted
  `Incidents.jsx` (modal), added `review-teaching.test.js`; content
  `scenarios/v2/*.yaml` per-scenario; `scenarios/RATIONALE_CANDIDATES.md`
  (authoring scaffold).
- **Endpoint/field changes:** D1 (`response_review` inside submitted
  grading) — the stage's one record-schema crossing, ratified OD-2.
- **Commits:**
  - (5.1) internal: reason-code registry constants (the 7.1 table,
    binding set) + Tier 1 templates + template-purity test. Nothing
    serialized.
  - (5.2) internal: scorer detail extraction — `compute_action_score`
    builds `_review` verdicts inside its existing joins, returned popped
    (Section 3.1 mapping); the detection disposition-correctness helper
    extraction; **R1 pin:** every 7.1 registry row fixture-pinned to the
    scorer's verdict; equivalence test (score dict byte-identical across
    the whole `test_action_scoring.py` fixture set — that suite itself
    untouched); the Section 19.16 count-reconciliation fixtures (both
    fold-in mappings). Nothing serialized.
  - (5.3) **[STOP]** freeze + serve: `_incident_report_card` assembles
    the complete `response_review` (entries + labels + whys +
    attempt_history + detections block + scenario_rationale slot) into
    the stored record; byte-identity test extensions; the correction-6
    freeze test (mutate sources in memory post-submit); 404/absence for
    unsubmitted/foreign; planted markers (expected-action composite +
    rationale string) asserted absent from EVERY pre-submission payload
    and other incidents' payloads; aggregate-shape assertion (teaching
    payload never in the session aggregate); real-drip corpus
    reconciliation pass. **R2: these guards land in THIS commit, with
    the data.** Disclosure: the one serialized-field change.
  - (5.4) **[STOP]** the payoff + Learning Review home (ratified
    B-OD-1 Option 1): Case Closed moment -> Incident Grade reveal; the
    full teaching render (Completed / Missed / Unnecessary-or-harmful
    sections + whys, attempt history separately labeled, per-detection
    dispositions with correctness, the `response_actions` playbook
    render — already served, app.py:4611-4628 — Key takeaway from
    `scenario_rationale`, achievements from the frozen record) moves to
    the Metrics/Analytics **Learning Review home** with a per-incident
    selector; the Incidents completed pane renders the Case Closed
    summary + "Review what you learned" path; the modal never renders
    teaching content (ONE venue, 19.19); 7.1 empty states,
    loading/error + retry; Incident Grade vs Session Performance
    labeling preserved.
  - (5.5) internal->**[STOP]** at schema disclosure: D2 schema field
    (top-level `expected_response`) + loader validation + ledger test +
    freeze wiring (`scenario_rationale` from the field at submit; null
    when absent) + parity suites green (the Section 3.4 placement).
  - (5.6..5.N) content: Tier 2 paragraphs — batch scaffold in
    `RATIONALE_CANDIDATES.md`, **[STOP] owner approval of the batch**,
    then one scenario per commit flipping its ledger row (the 3c
    cadence), each gate-green. R4: phases 1-4 are already done; a stall
    here delays only these content commits — the review teaches with
    Tier 1 whys meanwhile.
- **Section 17 battery rows:** the full 5.1 backend row lands across
  5.2 (registry pins, reconciliation) and 5.3 (freeze, byte-identity,
  404s, markers, empty shapes) and 5.5/5.6 (ledger + corpus Tier 2
  presence); the 5.1 frontend row lands at 5.4.
- **Gate checkpoint:** backend battery per commit; `--all` at 5.3, 5.4,
  and phase end.
- **Stop point:** acceptance 1-4 and 16 green; owner approves 5.3, 5.4,
  5.5, and the rationale batch.
- **Rollback:** 5.1/5.2 revert without payload effect; 5.3 is the
  record-schema point of no return per session lifecycle (additive only;
  Option B remains the recorded fallback).

---

**Phase 6 — the help model (5.5, consolidated).**
- **Concern:** controls always understandable; coaching Guided-only;
  answer-free by construction.
- **Prerequisites:** Phase 5 (Section 23 order).
- **Files:** added `helpContent.js` (tooltip + hint libraries), a
  tooltip component, `help-model.test.js`; adapted the surfaces
  carrying the nine controls; `uiCopy.js` (help copy).
- **Endpoint/field changes:** none (client-only; D5 superseded — no
  persistence store).
- **Commits:**
  - (6.1) internal: tooltip + hint libraries (`HINT_MODES` allow-list;
    the structural hint-inputs neutrality test; denylist battery). Not
    mounted.
  - (6.2) **[STOP]** mounting: permanent accessible tooltips on the
    nine controls (ruled finals) + the Guided "Need a hint?" flow
    (L1/L2) + Hardcore purity assertions.
- **Section 17 battery rows:** all 5.5 replacement rows at 6.1
  (machinery) and 6.2 (surface gating).
- **Gate checkpoint:** `--frontend`; `--all` at phase end.
- **Stop point:** replacement acceptance 8 green; Chrome tooltip/hint +
  Hardcore-purity passes.
- **Rollback:** 6.2 unmounts cleanly; 6.1 is inert without it.

---

**Phase 7 — certification.** Section 10 of this scaffold (the Section 18
Chrome workflows, full batteries, the closing report with every
disclosure). Stop condition: owner review of
`docs/stage-5-implementation-report.md`; merge decision.

---

## 7. Phase 3/4 merge recommendation (owner decision)

The contract permits merging Phases 3 and 4 into one review cycle at
owner discretion (Section 23). **Recommendation: MERGE them into one
review cycle.** Reasoning: both are small single-commit frontend phases
on the same surface (`Siem.jsx` + its renderers), share test
infrastructure and the same Chrome session for evidence, and neither
touches a payload; one review cycle halves owner overhead while the
commits stay concern-separated ((3.1) transitions, (4.1) inspector) so
rollback granularity is unchanged. The cost — a slightly larger single
review — is bounded by the two commits' independence. **This is the
owner's call:** approve merged (one [STOP] covering 3.1+4.1) or
separate (two cycles) at scaffold approval; the plan above is written
separable so either ruling applies without restructuring.

---

## 8. Traceability — Section 19 acceptance criteria

Every criterion mapped to phase, commit, and named proving test (files
per Section 2/6; names final at implementation, structure binding):

| # | Criterion (abbrev.) | Phase/commit | Proving test(s) |
|---|---|---|---|
| 1 | Every required response exactly once, Completed/Missed, named + why | 5.2/5.3 | `test_response_review.py::test_every_required_action_exactly_once_completed_or_missed`; modal render in `review-teaching.test.js` |
| 2 | Every collateral exactly once, named + why | 5.2/5.3 | `test_response_review.py::test_every_collateral_exactly_once_named` |
| 3 | Each roster detection with call + correctness | 5.3/5.4 | `test_response_review.py::test_detection_block_matches_frozen_dispositions` |
| 4 | No teaching field for unsubmitted/foreign (404/absence, markers) | 5.3 | `test_response_review.py::test_absent_pre_submission_and_foreign` + planted-marker suite |
| 5 | Pivot names clue + transition, origin, return; banner dies with snapshot | 3.1 | `pivot-transitions.test.js` (8.3 matrix + identity-guard death) |
| 6 | Selection–inspector connection; persistence across views/sort | 4.1 | `inspector-connection.test.js` |
| 7 | Every progress count == shared roster counts | 2.2 | `progress-vocabulary.test.js` count-source assertions + existing `test_incident_scope.py` roster guards (unchanged) |
| 8 | REPLACED (A1-B.6): tooltips all modes, mechanics-only; hints Guided-only, static, hidden-state-independent; Hardcore coaching-free | 6.1/6.2 | `help-model.test.js` allow-list + neutrality + purity battery |
| 9 | No pre-submission correctness/totals/forbidden phrasing | 2.1 scan + 5.3 markers + every phase | forbidden-phrase scan; planted markers; structural guards; full inherited batteries |
| 10 | TRANSLATED (A1-A.6): header/state/rows agree with the single scope state on all three surfaces; a case-selected surface never renders all-activity rows | 1.2/1.3 (+M1 base) | `scope-truth.test.js` three-state battery |
| 11 | TRANSLATED (A1-A.6): exactly one return action in Expanded search naming the current case; the case changes only by explicit selection (structural) | 1.3 | `workbench-states.test.js::single_return_and_structural_assertion` |
| 12 | Stale-results statement after failed parse/execution | 1.3 | `workbench-states.test.js::parse_failure_stale_statement` |
| 13 | TRANSLATED (A1-A.6): pinned line, expanded-search block, timeline mode, and Results-from echo never disagree; the echo keeps the scope token | 1.2 | `investigation-context.test.js` |
| 14 | Completed incident never renders active strip | 2.3 | `progress-vocabulary.test.js::completed_strip_regression` |
| 15 | Inherited batteries green; fields disclosed; zero console errors | every phase; 7 | `run_gates.py --all` per phase; Phase 7 report + console sweep |
| 16 | Count reconciliation (incl. inaction fold-in + out_of_order subset) | 5.2 (fixtures) + 5.3 (corpus) | `test_response_review.py::test_count_reconciliation_fixtures` / `::test_count_reconciliation_real_drip_corpus` |
| 17 | Toast trigger-list exactness; no duplication; action toasts shape-identical (A1-B.6) | 2.4 | `progress-vocabulary.test.js` toast battery |
| 18 | Checklist renders identically regardless of the answer key; the Guided-only prompt byte-identical; no answer-derived totals (A1-B.6) | 2.4 | checklist leak battery |
| 19 | Case Closed / achievements / Key takeaway deterministic from the frozen record; post-submission only; ONE venue (A1-B.6) | 5.4 | `review-teaching.test.js` determinism + venue assertions |
| 20 | Empty-run behavior (A2-AC-1) | 3.2 | `query-clarity.test.js` |
| 21 | Section-named malformed errors, ruled three-line form (A2-AC-2) | 3.2 | `query-clarity.test.js` |
| 22 | Restore last working query, request-free (A2-AC-3) | 3.2 | `query-clarity.test.js` |
| 23 | Chip honesty + the binding Custom-filters boundary (A2-AC-4) | 3.3 | chips battery |
| 24 | Every product-generated query parses; failure is a defect (A2-AC-5) | 3.2 | generated-forms corpus (frontend byte-pin + `test_lcql.py`) |
| 25 | Surrounding-events hold + zero-request restore (A2-AC-6) | 3.4 | `query-clarity.test.js` surrounding battery |
| 26 | Ruled tooltips permanent, accessible, mode-universal; pivot transition naming (A2-AC-7) | 3.2 (+6.2) | `query-clarity.test.js` + `help-model.test.js` |

No criterion is unmapped; no test is "covered implicitly."

---

## 9. Risk mitigations placed (R1-R7)

| Risk | Mitigation | Lands in |
|---|---|---|
| R1 two-truths misclassification | verdicts computed inside `compute_action_score`'s own joins (popped detail); every registry row fixture-pinned to the scorer; score-dict equivalence over the action-scoring fixture set | 5.2 |
| R2 pre-submission leak of teaching content | planted markers + structural guard extension + 404/absence **in the same commit as the data**: 5.3 (D1), 2.2 (D4), 5.5 (D2) | 5.3, 2.2, 5.5 |
| R3 record-schema ripple into 3.9A tests | additive-only field; byte-identity tests extended never weakened; Option B fallback recorded | 5.3 |
| R4 rationale authoring stalls the stage | Tier 1 ships at 5.1 (zero authoring); Tier 2 is the LAST sub-batch, per-scenario, non-blocking (phases 1-4 already closed; review teaches with generic whys meanwhile) | 5.1 + 5.6..N |
| R5 context summary drifts (second truth) | renders existing state only, no state or requests of its own; covered by the sync battery | 1.1/1.2 |
| R6 coaching leaks into Hardcore / feedback nags | `HINT_MODES` allow-list + Hardcore/SOC-never tests + passive tooltips; the toast trigger list, the no-duplication rule, and the checklist leak battery are the anti-nag mitigations, landing with the machinery before mounting | 2.4, 6.1 |
| R7 copy churn breaks scans late | the vocabulary lands as constants with its own test in **2.1**, before any later phase consumes it; Phase 1's 11.x strings live in the same module from 1.1 so nothing is defined twice | 2.1 (module seeded 1.1) |

---

## 10. Phase 7 certification plan

Executed against a dedicated backend (the dev-harness rule: batteries
never run against the live backend's `backend/logs`); fresh browser
profile where first-run state matters.

Section 18 workflows, scheduled: (1) Guided teaching run —
callouts once + dismiss + absent after Practice Another; play with one
required taken / one omitted / one collateral; review names all three
with whys + playbook; re-open byte-identical. (2) Inaction scenario —
zero-action FP run (inaction block) then a collateral-in-inaction run
(named + credit lost, factually). (3) Pivot chain — descent -> row ->
account -> IP -> host; banners name clue + transition each step; context
summary tracks; forced focus/origin divergence shows both return
controls. (4) Scope truth (F9 regression) — fetch-blocked scope on
Detections/Endpoints: truthful loading/error, never a selected
This-incident over unfiltered rows; retry + Session-wide recovery;
pre-seal roster growth caught by the refresh triggers. (5) Parse-failure
truth — invalid edit: error + stale-results statement + old snapshot +
summary still naming the executed query. (6) Inspector connection —
50-row page, bottom-row select, scroll + emphasis; persistence across
view switch + sort; reduced-motion jump. (7) Hardcore purity — full run,
zero onboarding surfaces, vocabulary present, timer/failure flows
unchanged, zero console errors. (8) Leak audit — network capture of a
full pre-submission run: no response_review, no rationale strings, no
expected-action content in any payload; planted-marker spot-check;
all-tab console sweep. (9) 0-of-0 regression — submitted incident shows
the completed strip, never the active strip.

Consolidated workflow translations (Amendments 1+2): workflow 1
verifies tooltips every visit, Guided hints on request, toasts per the
trigger list, and the Case Closed -> grade -> Learning Review path
(byte-identical re-render); workflows 3-5 walk the pinned-case chain
(the focus/origin divergence is unrepresentable), Retry-only
scope-error recovery, the empty-run and malformed-run legs (ruled
error form), restore, and the surrounding enter/return leg; workflow 7
asserts Hardcore purity (tooltips only, no prompt line, factual toasts,
payoff after submission).

Full batteries (`run_gates.py --all`) before and after the workflow
sweep. Closing report `docs/stage-5-implementation-report.md` MUST
disclose: every serialized-field change (D1, D4, D2) with payload
before/after; every endpoint whose response changed; the acceptance
table (Section 8 here) with final test names and results; Chrome
workflow transcripts; the copy inventory as landed; any deviation,
flagged per the deviation-flagging rule at the time it was made.

### 10.1 Ratified-copy conformance sweep (post-checkpoint addition, 2026-07-26, append-only)

Added at the C1 checkpoint after the post-Stage-5 product review found
two divergences from ratified content specifications that the Phase 7
certification did not catch (F4a: no workspace selector despite the
A1-B.3.2 source parenthetical; F5a: the well bucket rendered response
entries only despite the A1-B.4.1 item 3 parenthetical). Root cause in
both: acceptance rows tested the implementation's own routing against
the payload shape, and no certification step diffed the RATIFIED TEXT
against the RENDERED OUTPUT.

**Standing rule: every ratified content specification for a teaching or
progress surface gets an explicit verification row diffing the ratified
sentence against the rendered surface.** The sweep runs at every future
certification (this stage's checkpoint fixes included) and grows a row
whenever an amendment ratifies new surface content. Initial rows:

| # | Ratified source (contract) | Specified content | Rendered surface | Verified by |
|---|---|---|---|---|
| 1 | A1-B.4.1 item 3 (the review) | "what you did well (completed required actions, correct dispositions), what you missed, what was unnecessary or harmful (each with the frozen whys), per-detection verdicts, the playbook, and Key takeaway" | Metrics Learning Review sections | `review-teaching.test.js` A1-B.4.1 conformance test + C1 Chrome walk (INC-9709: "Detection calls: 5 of 5 correct" beside the missed-actions whys) |
| 2 | A1-B.3.2 line table (checklist) | Each checklist line's OBSERVABLE SOURCE as specified, incl. Classification = "local selection state (the player's own input; the workspace selector)" | PhaseStrip lines + the workspace classification block | `incidents-workspace.test.js` A1-B.3.2 tests + C1 Chrome walk (selection updates the line pre-submit) |
| 3 | A1-A.5 copy table (case-constant finals) | The ratified A-OD-1 strings byte-exact | Pinned line, state chip, expanded-search block, return action | `progress-vocabulary.test.js` byte-exact battery + `investigation-context.test.js` |
| 4 | A2-3 + A2-R.1 (query clarity finals) | The four ruled tooltips, three-line error form, placeholder, Restore, surrounding block copy | SIEM bar, inspector, error box, banner | `query-clarity.test.js` + `help-model.test.js` byte pins |
| 5 | A1-B.3.1/T1-T5 (toasts) + B-OD-5 (prompt) | Trigger list exactness; Guided-only consider-prompt | Toast container + checklist prompt | `live-progress.test.js` |

A future amendment that changes any specified content MUST update the
matching row in the same change; a certification that cannot tick every
row is not complete. Rows verify CONTENT AGAINST RATIFIED TEXT, not
merely that a test exists: the reviewer reads the contract sentence and
the rendered surface side by side.

---

## 11. Ambiguities, repository disagreements, and decisions requiring ratification

Items the owner rules on at scaffold approval (none resolved silently;
A and B block their phases until ruled):

- **A. Related response activity LIST after the fuzzy join dies
  (blocks 2.2).** D4 ratifies a **count**; the existing detail pane also
  renders a LIST of related entries (`Incidents.jsx:274-282`) fed by the
  same fuzzy join the contract orders replaced. The client cannot
  registry-resolve, so an honest list needs either (i) a serialized
  observable `related_action_seqs` (player's own action seqs — a D4
  extension the contract did not enumerate), (ii) dropping the list
  (count only), or (iii) listing all session actions unfiltered.
  **Recommendation: (i)**, as the minimal honest addition preserving the
  3.9B "Related response activity" surface — but it extends a ratified
  field set, so it is the owner's call, possibly via the amendment
  discipline.
- **B. "Scoring functions unchanged" (D6) vs "reuse the scorer's
  pathways" (R1).** The plan extends `compute_action_score` with an
  additive, popped internal detail output (the existing
  `acceptable_seqs` pattern) and extracts the disposition-correctness
  rule into a shared helper — input->output scoring semantics
  byte-identical, proven by the untouched `test_action_scoring.py` /
  detection-scoring suites plus a dedicated equivalence test. This
  scaffold interprets D6 as freezing scoring SEMANTICS, not forbidding
  behavior-preserving internal additions; the alternative (a parallel
  derivation) is exactly R1's warned failure mode. **Ratified by
  approving this scaffold, or overruled here.**
- **C. D2 field placement forced by a guard.** The contract calls D2 a
  "schema v2 `triage_review` sibling field" — ambiguous between inside
  `triage_review` and beside it. Inside would land
  `test_corpus_matches_v1_content` red (triage-dict equality,
  test_scenario_loader_v2.py:134-136); the scaffold places it
  **top-level beside `triage_review`** per the never-land-red boundary
  principle. Flagged because the contract phrasing tolerates the red
  reading.
- **D. Repository observation (no change planned):** contract 4.1 calls
  `_incident_progress` "observable counts only," but its
  actions-attempted/executed counts join through the GRADING record
  (`_entry_in_scope`, app.py:3401-3408 — environment-declared hostnames),
  a frozen 3.9A behavior. The counts themselves are of the player's own
  actions. D4 deliberately uses a new observable-scope join instead;
  `_incident_progress` is left untouched. Reported so the difference is
  a record, not drift.
- **E. Server 409/readiness strings stay as pinned.** 10.1's
  "still need Promote or Dismiss" is adopted on CLIENT surfaces; the
  server 409 message ("N detections still need review",
  3.9A-test-pinned) is not reworded — scope discipline over frozen
  payload text. If the owner wants payload strings aligned too, that is
  a separate ruling (it touches `test_submission_gate.py` assertions).
- **F. New-copy register.** Section 5 flags every string not sourced
  from the contract (Tier 1 non-example templates, review section
  headers, onboarding copy, PhaseStrip "Investigate" detail) — drafted
  at implementation, reviewed at their [STOP]s, denylist- and
  em-dash-scanned.
- **G. Phase 3/4 review-cycle merge** — Section 7's recommendation
  (merge), owner's call.
- **H. Tier 2 rollout consequence.** A record submitted before its
  scenario's paragraph lands freezes `scenario_rationale: null`
  permanently (immutability; generic whys still present). Accepted
  consequence of ratified incremental authoring (R4) — surfaced so it is
  chosen, not discovered. Moot for most sessions (in-memory records,
  Section 4), visible only within a session spanning an authoring
  deploy: practically never.
- **[Scaffold decisions] for ratification (detailed in place):** D1
  stored inside `report_card` (3.1); expected-label rendering via
  registry lookup with composite fallback (3.1); D3 frontend-only
  source (3.3); D2 field name `expected_response` + optional-with-ledger
  rollout (3.4); onboarding key layout (2.6); `uiCopy.js` seeded in
  Phase 1, canonicalized in 2.1 (R7 note, 2.2).

---

## 12. Branch and relative sizing

**Implementation branch:** `stage-5-live-run-feedback` (from `main`
after scaffold approval), concern-level gate-green commits, merged to
`main` after Phase 7 evidence review — the Stage 4 convention. This
scaffold's own branch (`stage-5-implementation-scaffold`) carries only
this document.

| Phase | Size | Dominant cost |
|---|---|---|
| 1 scope truth + context (case-constant) | **S-M** | state-pair rework + battery translation; dual controls and the expandable summary dropped |
| 2 Live Progress and Reinforcement + D4 | **M-L** | vocabulary sweep + toasts + checklist leak battery + the one backend field |
| 3+4 merged cycle: transitions, query clarity, chips, surrounding, inspector | **M** | expanded-search surface + ruled error taxonomy + chips + generated-forms corpus + inspector polish |
| 5 review teaching + payoff | **L** (grown) | scorer detail + freeze + fixtures + schema + the Learning Review home + achievements + 20 authored paragraphs |
| 6 help model | **M** | nine tooltips, hint libraries, gating, neutrality + denylist |
| 7 certification | **M** | nine workflows (consolidated translations) + report |

Net vs the approved plan: modestly larger — growth concentrated in
Phases 2 and 5, partially offset by Phase 1's shrink (the A1-B.8 net
statement).

---

*End of scaffold. No product code lands from this document. Phase 1
begins only after explicit owner approval of this scaffold and its
Section 11 rulings, on the implementation branch, in the phase order
above.*

---

## Appendix: Owner approval and rulings (2026-07-25, append-only)

**Verdict: PASS — the scaffold is APPROVED subject to the rulings
below, which bind implementation.** Every section above stands as
written except where a ruling supersedes it; only ruling A changes a
planned commit.

**A. Related response activity (supersedes Section 11 item A's
recommendation; changes commit 2.2):** the ratified observable
`related_actions` COUNT ships exactly as ratified — **no contract
amendment is required; the locked contract stands unamended; D4 ships
exactly as ratified.** The existing fuzzy related-activity LIST
(`Incidents.jsx:274-282`, fed by the `:84-88` join) is **removed in
commit 2.2**; the detail pane displays the honest count only. No
`related_action_seqs` or any other serialized list field is added.
Session-wide actions are not shown as a substitute; the Response Log
remains the venue for the player's own action history.

**B. Scorer reuse (Section 11 item B): APPROVED**, with binding
conditions: `compute_action_score` may produce an additive internal
detail result that is removed before its existing public score result
returns; the internal detail key is removed at EVERY
`compute_action_score` call site, with a structural assertion that no
served payload anywhere contains it; the planted-marker suite
enumerates the pre-submission surfaces it covers BY NAME (at minimum:
the in-progress score endpoint, incident cards, scope, and detections
payloads) — never an unenumerated "every"; scoring semantics and score
payloads remain byte-identical; the equivalence test over the full
action-scoring fixture set is required and permanent.

**C. Tier 2 rationale placement: APPROVED** as the top-level schema v2
field `expected_response`, beside `triage_review` (Section 3.4 as
written).

**D. `_incident_progress` observation: record only.** No change is
authorized; D4 continues to use the new observable-scope join.

**E. Server readiness copy:** the existing 409 payload wording and its
pinned tests stay unchanged. The canonical Stage 5 wording applies to
client surfaces; Phase 2 verifies the client renders canonical copy
rather than raw payload text where both exist.

**F. New-copy register: accepted as the standing process** — NEW
strings are drafted at implementation, reviewed at their owning
[STOP], and denylist- and em-dash-scanned.

**G. Phases 3 and 4: ONE owner-review cycle for both**, with commits
3.1 and 4.1 kept concern-separated and independently revertible
(Section 7's recommendation adopted).

**H. Incremental Tier 2 authoring: accepted.** A submission created
before its scenario paragraph exists may freeze
`scenario_rationale: null`; generic Tier 1 explanations remain
available.

**[Scaffold decision] items, ratified as written:** `response_review`
stored inside `report_card`; expected-label resolution through registry
lookup with composite fallback; completed-strip total sourced
frontend-side from `detection.total`; `expected_response` optional with
a ratcheting ledger during rollout; the proposed
`spectyr_onboarding_v1` localStorage layout; `uiCopy.js` seeded in
Phase 1 and completed as the canonical vocabulary module in Phase 2.

**Legacy-record conclusion: accepted.** Submissions are memory-only; no
pre-Stage-5 persisted records require migration or backfill; the
degraded missing-breakdown UI remains a defensive fallback only.
