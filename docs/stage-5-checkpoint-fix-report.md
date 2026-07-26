# Stage 5 C1 Checkpoint Fix Report

Post-review checkpoint fixes on `stage-5-live-run-feedback`, executed
2026-07-26 under the owner's C1 directive (five defects against
already-ratified text or invariants, confirmed in the post-Stage-5
checkpoint product review). Base: the certified Stage 5 tip `a883508`.

- **Commit range:** `a883508..80878da` (5 concern-level commits + this
  docs commit)
- **Scope:** frontend + docs + tests ONLY. `backend/` is untouched: no
  endpoint, serialized field, scoring, roster, readiness, or record
  change of any kind. No merge. No Amendment 3 item begun.
- **Gates:** every commit passed the versioned pre-commit hook (full
  frontend battery per commit); `python backend/run_gates.py --all` at
  the final tip: **ALL GREEN** (backend battery complete; frontend 27
  suites / 253 tests). No commit landed red; `--no-verify` never used.
- Protected owner assets untouched and excluded from every commit
  (`frontend/public/videos/spectyrvideo.mp4`,
  `frontend/public/spectyr_svg.svg`).

---

## 1. Commit ledger

| Commit | Item | Summary |
|---|---|---|
| `a2cc3dc` | 1 (F1) | Evidence-surface nav badges removed; dead setXCount paths deleted end to end |
| `0a1fcd2` | 2 (F5a) | Learning Review buckets conform to ratified A1-B.4.1 item 3 |
| `7ac299d` | 3 (F4a) | The ratified A1-B.3.2 workspace classification selector, mounted |
| `763b116` | 4 (F2 latent) | Failed-return guard: no incident relabel over expanded rows |
| `80878da` | 5 (F6 slice) | Reports nav entry hidden (ruled default); lying empty-state copy replaced |
| (this) | process | Scaffold 10.1 ratified-copy conformance sweep + this report |

## 2. Changes by item (files with line ranges, as landed)

### Item 1 — nav badges (F1). Ruled fix: deletion.

The SIEM/Detections/Endpoints badges read unfiltered session payloads
while the page headers rendered case-scoped counts; the Endpoints badge
additionally froze at its first-visit value and ignored the page search
filter. All three badges and their setter paths are deleted; the
Incidents badge stays (cases are a global concept). The Metrics badge
(session action history on a session surface, no scope mismatch) was
not named by the ruling and is untouched.

- `frontend/src/pages/Dashboard.jsx` 17-18 (state removed), 30-37
  (state removed), 209-219 (tab entries lose `count`, rationale
  comment), 335-345 (props removed from Siem/Detections/Endpoints)
- `frontend/src/components/Siem.jsx` 53 (prop removed), former 148-150
  (badge effect deleted)
- `frontend/src/components/Detections.jsx` 87, 107-116 (setter call +
  dep removed)
- `frontend/src/components/Endpoints.jsx` 56-57, 71-80 (setter call +
  dep removed)
- Dead stub props swept from 16 test files (mechanical; no assertion
  touched -- no test anywhere asserted a badge value)
- **New:** `frontend/src/__tests__/nav-badges.test.js` -- renders the
  full Dashboard with NON-ZERO session payloads routed at every
  surface and pins: evidence-surface entries carry no numeric badge;
  the Incidents entry keeps its badge. (Technical note: react-router-dom
  v7 ships ESM that CRA's jest cannot resolve; the suite mocks its
  `Link` with a `{ virtual: true }` factory.)

### Item 2 — Learning Review bucket conformance (F5a)

Ratified A1-B.4.1 item 3 defines the well bucket as "completed required
actions, correct dispositions"; the shipped render enumerated
`response_review.entries` only. Now:

- The well bucket renders BOTH halves: a correct-calls line read from
  the frozen per-detection verdicts (`Detection calls: {n} of {total}
  correct`, or `No detection calls were correct.`) plus the completed
  required entries (or `No required response actions were completed.`).
- Every bucket heading names its category:
  `Correct detection calls and completed response actions` /
  `Required response actions missed` / `Unnecessary or harmful actions`
  / `Additional defensible actions taken`. (Headings were unruled
  implementation copy; renaming needed no amendment.)
- Every empty state names its category; the bare `None.`
  (`REVIEW_NONE`) is deleted from the module.
- Frozen records, `response_review` payloads, and every backend surface
  untouched.

Files: `frontend/src/components/uiCopy.js` 156-181 (renamed headings +
six new strings); `frontend/src/components/LearningReview.jsx` 3-12
(imports), 101-115 (correct-call derivation), 190-215 (the well-bucket
block + category empty lines), 240-241 (detections empty line);
`frontend/src/__tests__/review-teaching.test.js` (imports, full-render
addition, inaction-test rewrite to the category-named lines, new test).

**New test:** `review-teaching.test.js` --
`A1-B.4.1 conformance (C1, F5a): correct dispositions surface in the
well bucket even with zero completed response actions` -- pins the
owner-observed defect case (correct classification + 3/5 correct calls
+ zero completed required actions) and asserts `None.` never renders.

### Item 3 — workspace classification selector (F4a)

Ratified A1-B.3.2 names the checklist Classification line's source as
"local selection state (the player's own input; the workspace
selector)"; no workspace selector existed. Now:

- `ClassificationSelector.jsx` and `CategorySelector.jsx` gain
  `variant="inline"` (compact grids, no overlay) and a `selected`
  pre-fill prop with `aria-pressed`; the default modal variant is
  byte-compatible with the old flow and gains a `data-testid`.
- The Incidents workspace mounts the inline selector on sealed active
  incidents (`workspace-classification` block); choosing False Positive
  completes the classification; choosing True Positive reveals the
  inline category grid; the checklist line updates from the same
  `chosen` map, now shaped `{verdict, category, categoryId}`.
- The submit/check modal flow is UNCHANGED (still classifier ->
  category -> confirm) and arrives pre-filled from the workspace
  choice. Submit gating and the Ready calculation are deliberately
  untouched -- that is Amendment 3 item F4b.
- Leak rule holds: the selector block is byte-identical for every
  incident (static options, player-local state only).

Files: `frontend/src/components/ClassificationSelector.jsx` (rewritten,
75 lines); `frontend/src/components/CategorySelector.jsx` (rewritten,
89 lines); `frontend/src/components/Incidents.jsx` 79-105 (chosen map +
handlers), 344-346 (PhaseStrip prop), 349-367 (workspace block),
469-495 (modal pre-fill + object writes);
`frontend/src/__tests__/incidents-workspace.test.js` (modal-scoped
click + four new tests); `frontend/src/__tests__/review-teaching.test.js`
(19.19 modal-scoped click).

**New tests:** `incidents-workspace.test.js` --
`A1-B.3.2 (C1): the workspace selector drives the checklist
Classification line before Submit`;
`C1 (F4a): the workspace threat path reveals the inline category step
and completes the line`;
`C1 (F4a): the submit modal flow is unchanged and arrives pre-filled
from the workspace selection`;
`C1 (F4a): no workspace selector before the roster seals`.

### Item 4 — failed-return guard (F2 latent defect)

A failed case-evidence read inside `returnToIncident` left scope in
`{kind:'incident', status:'error'}`, relabeling the view as incident
evidence (case chip + scope error) over the still-displayed expanded
session rows -- violating criteria 10/13. The guard:

- On that failure the state stays Expanded search (`setScope({kind:
  'session'})`), a notice names the failure
  (`Could not load {INC} evidence. Try the return again.`) beside the
  RATIFIED 11.3 honesty statement (`Displayed results are from the
  previous successful query.` -- chosen because it is exactly true:
  the displayed rows are the last successful query's), and the return
  chip remains as the retry.
- The ANCHOR-read error behavior (ratified A-OD-3: label retained, Run
  disabled, Retry-only) is untouched.
- `returnError` clears on any run, the case anchor, reset, and the next
  return attempt. Nothing else changed; the guard is superseded by
  Amendment 3 model B when it ships.

Files: `frontend/src/components/uiCopy.js` 28-36 (`returnReadFailed`);
`frontend/src/components/Siem.jsx` 104-108 (state), 152 + 186-187 +
199 (clears), 262 (execute clear), 414-434 (guarded handler), 590-603
(notice render); `frontend/src/__tests__/progress-vocabulary.test.js`
(string joins the enumerated forbidden/em-dash scans);
`frontend/src/__tests__/workbench-cross-host.test.js` (scopeFails
harness + new guard test); `frontend/src/__tests__/workbench-states.test.js`
(translated test, see Deviations D-C1-1).

**New test:** `workbench-cross-host.test.js` --
`C1 guard (F2): a failed case-evidence read on return keeps Expanded
search and states the honesty line` (asserts: block + chip persist, no
scope-chip, zero query requests, both notice lines, and the retry
completing the return).

### Item 5 — Reports tab (F6 checkpoint slice). Ruled default: hide.

No frontend POST to `/api/reports` exists (the create modal is a
dangling comment), so the tab was a permanently-empty shell whose empty
state instructed the player to "Write a report from Alerts" -- a
workflow 3.9B retired. The nav entry is hidden until a working workflow
exists; `Reports.jsx`, `IncidentReportForm.jsx`, and the backend routes
are KEPT for that future work; the lying string is replaced with
truthful copy (`No reports have been filed in this session.`) so the
surface cannot lie if remounted.

Files: `frontend/src/pages/Dashboard.jsx` 8 (import removed), 17-18
(state removed), 75-80 (keyboard case '7' removed), 216-221 (tab entry
removed, rationale comment), 356-359 (render block removed);
`frontend/src/components/Reports.jsx` 341-344 (string);
`frontend/src/__tests__/nav-badges.test.js` (Reports-absent test).

## 3. Root causes for the two unflagged divergences (process patch)

- **F4a (workspace selector):** the A1-B.3.2 source parenthetical
  "(the workspace selector)" was treated as descriptive rather than
  normative -- the modal's local writes satisfied the letter of "local
  selection state", and no certification step compared the ratified
  line-source table against actual component mounts.
- **F5a (well bucket):** the Phase 5 acceptance row tested bucket
  ROUTING (completed/missed/collateral/acceptable over
  `response_review.entries`) against the 7.1 payload shape; the
  A1-B.4.1 item 3 parenthetical "(completed required actions, correct
  dispositions)" was never diffed against the rendered section, and the
  W1 walk recorded "What you did correctly: None." as expected output
  because the tester validated against the payload, not the ratified
  sentence.

Both defects were of one kind -- implementation tested against itself
instead of against ratified text -- which is what the new scaffold 10.1
**ratified-copy conformance sweep** (this docs commit) makes a standing
certification step.

## 4. Gate outputs

Per-commit (versioned pre-commit hook, frontend battery scoped by
staged paths): `a2cc3dc` 27 suites / 246 tests; `0a1fcd2` 27/247;
`7ac299d` 27/251; `763b116` ALL GREEN; `80878da` ALL GREEN. Final
certification at the tip: `python backend/run_gates.py --all` = **ALL
GREEN** -- backend battery complete (halt-on-failure ordering),
frontend **27 suites / 253 passed** (was 26/244 at `a883508`: +1 suite,
+9 tests net).

## 5. Chrome evidence (items 1-3, live walk 2026-07-26)

Fresh Guided run, `defense_evasion_log_clearing`
("Event Logs Cleared on Workstation"), INC-9709, dev servers
frontend :3000 / backend :5000. Zero console errors across the full
walk including a post-submission clean reload (onlyErrors sweep, twice).

1. **Badge-free rail (item 1):** nav shows `Incidents 1` (badge) with
   SIEM / Detections / Endpoints badge-free while the session carried
   5 open detections and 1 managed endpoint; **no Reports entry**
   (item 5 visible in the same frame).
2. **Workspace selector (item 3):** the INC-9709 workspace renders the
   CLASSIFICATION block under the checklist; checklist reads
   "Classification: not selected"; clicking True Positive highlights it
   and reveals the inline category grid (line honestly still "not
   selected"); clicking Defense Evasion completes it -- checklist
   updates to "Classification: Defense Evasion" BEFORE any submit
   action. After full triage (5 of 5, milestone toast fired), Submit
   opened the UNCHANGED modal flow with True Positive pre-highlighted,
   then Defense Evasion pre-highlighted, then the confirm naming
   "Filing as Defense Evasion".
3. **Restored buckets (item 2):** submitted with all 5 dispositions
   correct and zero response actions -- Incident Grade: Classification
   A 100 / Detections A 100 / Response F 0 / Composite C 70. The
   Learning Review renders "CORRECT DETECTION CALLS AND COMPLETED
   RESPONSE ACTIONS" with **"Detection calls: 5 of 5 correct"** and
   "No required response actions were completed."; "REQUIRED RESPONSE
   ACTIONS MISSED" lists Isolate Host ACME-WS34 and Remove Persistence
   WMI subscription 'WindowsUpdConsumer' with their frozen whys;
   "UNNECESSARY OR HARMFUL ACTIONS" reads "No unnecessary or harmful
   actions were taken."; the per-detection verdicts, T1685.005
   education, playbook, and Key takeaway render below. The
   owner-observed "What you did correctly: None." contradiction is
   gone.

(Walk mechanics note: dispositions were issued through the same
session's API to reach the evidence state quickly; the classification,
submit, and review interactions above were performed in the browser.)

## 6. Deviations and notes (flagged per the deviation rule)

- **D-C1-1 (test translation, item 4):** `workbench-states.test.js`
  `scope-error: ...` pinned the PRE-GUARD failed-return behavior (case
  chip + alert over expanded rows) -- the exact state item 4 removes.
  It was TRANSLATED, not weakened: its A-OD-3 guarantees (label
  retained, Run disabled by the scope block alone, no query issued,
  Retry recovery, no Use Session-wide, search-all available) are
  re-pinned on the ANCHOR-read path they govern, and the return path's
  guarantees (snapshot preserved, zero requests, retry) are pinned by
  the new cross-host guard test. The
  incident-label-over-session-rows state is now unrepresentable on the
  SIEM, so no test can pin it.
- **D-C1-2 (heading synthesis, item 2):** the directive asked that
  every bucket heading "name its category" while the well bucket
  "includes BOTH" halves. The well heading therefore names both
  ("Correct detection calls and completed response actions") rather
  than a single category; the three response-only buckets name response
  actions. Flagged as the interpretation taken.
- **Metrics badge kept** (item 1 names only the three evidence
  surfaces; the Metrics count is session data on a session surface).
- **Known stale docs, not touched (out of C1 scope):** CLAUDE.md's UI
  Architecture section still describes 6 tabs with always-shown counts
  and the pre-3.9B Alerts tab; `TriageFeedback.jsx` remains orphaned;
  `ActionHistory.jsx`'s "Post-Incident Review" heading still coexists
  with "Learning Review" in the Metrics venue (review item 5c, optional
  polish, not authorized here).
- **No serialized-field or endpoint change anywhere** (backend
  untouched); the em-dash scan covers every new string
  (`copy-emdash.test.js` walks all of `frontend/src`); the new
  pre-submission guard string joined the enumerated forbidden-phrase
  scan.

## 7. Stop

Stopped at the checkpoint: fixes landed on `stage-5-live-run-feedback`
only. **No merge. No push. No Amendment 3 work** (F4b submit-gating,
model B, surrounding-events removal, and simple search remain
unstarted, awaiting the amendment discipline).
