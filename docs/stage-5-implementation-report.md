# Stage 5 Implementation Report — Live Run Feedback

Phase 7 certification artifact (scaffold Section 10; contract Section 18
closing-evidence list). Produced 2026-07-25 under the owner's one-shot
implementation authorization (Phases 1.2 through 7 unattended, checkpoint
self-review at every former [STOP], stop conditions armed throughout).
Governing sources: the locked Stage 5A contract
(docs/stage-5a-live-run-feedback-contract.md, Revision 3 + ratified
Amendment 1 + ratified Amendment 2) and the consolidated implementation
scaffold (docs/stage-5-live-run-feedback-implementation-scaffold.md).

- **Branch:** `stage-5-live-run-feedback` (from `main` @ `cc0b249`)
- **Final tip:** `2f6735b` (this report lands one docs-only commit above it)
- **Git status at certification:** clean except the two protected owner
  assets, untouched by the stage
  (`M frontend/public/videos/spectyrvideo.mp4`,
  `?? frontend/public/spectyr_svg.svg` — both predate the run and were
  excluded from every commit per the authorization)
- **NOT merged to main. NOT pushed.** (The final-stop rule.)

---

## 1. Commit ledger (39 commits, `fa3df0c..2f6735b`)

**Phase 1 — scope truth and investigation context** (case-constant model,
Amendment 1 Delta A):
- `fa3df0c` 1.1 uiCopy seeded + InvestigationContext (unmounted)
- `b31c924` 1.2 the case-constant state model *(checkpoint passed)*
- `6b00fbe` 1.3 11.3 honesty notes + single-return battery *(checkpoint passed)*

**Phase 2 — Live Progress and Reinforcement:**
- `6bbc8ea` 2.1 the complete Section 10.1 canonical vocabulary
- `9c12d71` 2.2 D4 `related_actions` + vocabulary surface sweep *(checkpoint passed)*
- `70d1586` 2.3 completed strip; 0-of-0 structurally impossible *(checkpoint passed)*
- `c0f6e7e` 2.4 toasts + checklist (T1-T5, PhaseStrip evolved) *(checkpoint passed)*

**Merged Phase 3/4 — pivot transitions + query clarity (Amendment 2):**
- `45b9bc0` 3.1 expanded-search transition surface *(checkpoint passed)*
- `72f6aa6` 3.2 query clarity per the A2 rulings *(checkpoint passed)*
- `40aecde` 3.3 filter chips, remove-only + Custom-filters boundary *(checkpoint passed)*
- `df54334` 3.4 reversible surrounding events *(checkpoint passed)*
- `525cd25` 4.1 inspector-selection connection (OD-5 Option A) *(checkpoint passed)*

**Phase 5 — post-incident review teaching:**
- `032fdcf` 5.1+5.2 reason-code registry, Tier 1 templates, scorer `_review`
  detail (internal; ruling B honored — built inside the scorer's joins,
  popped at every call site)
- `0f10491` 5.3 freeze + serve `response_review` (the ONE record-schema
  crossing, ratified OD-2/D1) *(checkpoint passed)*
- `abd82d6` 5.4 Case Closed payoff + Metrics Learning Review home
  (ratified B-OD-1 Option 1) *(checkpoint passed)*
- `a3d460c` 5.5 D2 schema field `expected_response` + loader validation +
  ledger + freeze wiring *(checkpoint passed at schema disclosure)*
- `8e50525` 5.6 Tier 2 rationale batch scaffold (RATIONALE_CANDIDATES.md,
  docs-only) *(checkpoint: batch self-review — see Deviations D-3)*
- `fd8d426` rollout harness fix **+ malware_usb landing** (see Deviations D-1)
- `8fb6c81..6ee3960` eighteen per-scenario rationale commits (one scenario
  per commit, YAML field + ledger row together, hook battery green each):
  phishing_1, defense_evasion, false_positive_pentest, lateral_movement_1,
  c2_http, brute_force_attack, false_positive_robocopy, phishing_link,
  data_exfil_archive, insider_staging, malware_ransomware,
  lateral_movement_2, defense_evasion_log_clearing (`21cea79`),
  insider_shadow_it, password_spray, c2_dns_tunnel, false_positive_veeam,
  false_positive_oauth, false_positive_ssl_inspection
- `131fcd9` rollout complete: the 20/20 required-by-ledger gate

**Phase 6 — the help model:**
- `d30de40` 6.1 help-model libraries (tooltips + Guided hint flow), not mounted
- `2f6735b` 6.2 mounting: nine-control tooltips + "Need a hint?" *(checkpoint passed)*

Every commit passed the versioned pre-commit hook (`run_gates.py` scoped
to staged paths); no commit landed red; no test was weakened, deleted, or
bypassed; `--no-verify` was never used.

---

## 2. Gate outputs (authoritative, final tip)

Final certification run (`python backend/run_gates.py --all` at `2f6735b`):

```
[gate] ALL GREEN            (backend battery: all 29 suites, halt-on-failure)
Test Suites: 26 passed, 26 total
Tests:       244 passed, 244 total
```

Backend suite counts at the tip (per-suite authoritative outputs from the
final runs): `test_response_review.py` 20 passed;
`test_scenario_loader_v2.py` 65 passed (63 + the 20/20 rationale gate + the
validated-when-present test); `test_action_scoring.py` 39,
`test_persistence_response.py` 19, `test_submission_gate.py` 26/26,
`test_incident_scope.py`, `test_incident_roster_corpus.py` (real-drip
all-20), `test_lcql.py` 49, `test_guided_catalog.py`, `test_detections.py`,
and the rest of the battery — all green under `run_gates.py`'s
halt-on-failure ordering. Frontend: 26 suites / 244 tests (CRA jest,
CI=true), including the em-dash scan over all non-test source and the
word-boundary forbidden-phrase scan.

`--all` was run at every phase boundary and at commits 5.3/5.4 per the
scaffold's gate-checkpoint rule; the backend battery ran per backend
commit via the hook (including all 20 rationale commits).

## 3. Serialized-field and endpoint changes (complete list)

No new endpoints. Three payload changes, exactly the ratified D1/D2/D4 set:

| # | Change | Payload before → after | Venue |
|---|---|---|---|
| D1 | `response_review` frozen into the submission record | submitted `grading` had keys `{classification, detection, response, composite}` → gains `response_review = {entries, attempt_history, detections, scenario_rationale}`; each entry `{bucket, reason_code, action, target_label, why, source_action_seq, expected_ref}` (contract 7.1 shape, byte-frozen at submit; correction 6) | `GET /api/incidents/<id>/score`, submitted branch ONLY (served by the existing underscore-strip; session-wide aggregates never carry it) |
| D2 | `expected_response` schema v2 top-level optional string | scenario YAML gains the Tier 2 paragraph; frozen into the record as `scenario_rationale` at submit; `null` records stay null (ruling H) | content field; serialized only inside D1's frozen block, post-boundary |
| D4 | `related_actions` observable count | active sealed incident cards gain the server-computed count (successful log entries joined over observable scope via `resolve_account_key`; ruling A: count only, fuzzy list deleted) | `GET /api/incidents` active sealed cards |

D3 (completed-strip total) confirmed as **no field**: the frontend reads
the frozen `detection.total` from the score view.

Endpoints whose RESPONSE changed: `/api/incidents` (D4 count),
`/api/incidents/<id>/score` (D1 block inside submitted grading). No other
endpoint's shape changed; the discriminated in-progress shapes are
untouched (progress payloads still carry observable activity only).

---

## 4. Behavior and copy changes (as landed)

- **Case-constant model (P1):** `activeIncidentId` is the pinned case;
  Detections/Endpoints always case-scoped with Retry-only errors (no
  toggle, no "Use Session-wide" — both structurally absent); SIEM renders
  the case-evidence chip + "Search all evidence" vs the Expanded-search
  block with ONE "Return to INC-#### evidence"; "All activity" with no
  case; "Session-wide" banned from player copy (word-boundary scan); the
  technical `scope=` token survives only in the status-line echo.
- **Live Progress (P2):** toasts T1-T5 (`uiToasts.js`, role=status,
  bottom-right, limit 4): disposition confirmations with the sealed-roster
  remaining count, factual action results, the ONE coinciding
  readiness/triage-complete milestone toast on the observable false→true
  transition. The checklist is the evolved PhaseStrip
  (telemetry/detections/classification/response/ready lines,
  constants-only; the Guided-only consider-prompt per B-OD-5); the
  completed strip replaces the active strip on submitted incidents.
- **Query clarity (merged P3/4, A2):** `==`/`!=`/Pivot/Surrounding keep
  their labels with the four ruled tooltip finals; "Example: " italic
  placeholder; empty-run gating ("No query entered."); the ruled
  three-line error form with client section naming
  (`sectionIndexAtPosition` mirror pinned to the backend AST by shared
  corpora); "Restore last working query" (request-free); remove-only
  filter chips with the binding Custom-filters honesty boundary;
  reversible surrounding events (single-depth hold, zero-request
  restore, ruled block copy); inspector connection per OD-5 Option A
  (ring + selection dot + aria-selected + one emphasis run,
  reduced-motion honored).
- **Review teaching (P5):** the frozen teaching model (Section 5/6 of
  this report); Case Closed moment (static, reduced-motion honored, one
  render per submission); achievements = the six ratified A1-B.4.3
  derivations computed at render from the served record only; the Metrics
  tab is the ONE Learning Review venue (per-incident selector; sections
  "What you did correctly / What you missed / Unnecessary or harmful /
  Additional defensible steps"; attempt history separately labeled;
  per-detection verdicts; MITRE education + playbook moved from the modal;
  Key takeaway from `scenario_rationale`, omitted when null); "Session
  Performance" heading (was "Report Card") completes the 3.9B labeling
  split; the Incidents completed pane renders the Case Closed summary +
  "Review what you learned"; Practice Another preserved.
- **Help model (P6):** nine-control tooltips (title + `data-help` +
  `.help-tip` CSS `:focus-visible`/hover layer — keyboard-reachable, no
  timers, no focus stealing), mode-universal; the Guided-only
  "Need a hint?" flow (L1 mechanics / L2 per-surface nudges), HINT_MODES
  allow-list; L3 deferred (B-OD-2); no persistence store (D5 superseded,
  B-OD-4 deferred).
- **Tier 2 content:** all 20 `expected_response` paragraphs authored per
  the batch scaffold (`backend/scenarios/RATIONALE_CANDIDATES.md`), each
  grounded 1:1 in its ratified answer key, role-language only, ASCII
  punctuation; `brute_force_attack`'s adapts the owner-written "why
  nothing" lesson from docs/action-scoring.md.

---

## 5. Acceptance mapping (scaffold Section 8, criteria 1-26)

Final test names (structure binding, names final at implementation):

| # | Criterion | Result | Proving test(s) as landed |
|---|---|---|---|
| 1 | Required exactly once, Completed/Missed + why | PASS | `test_response_review.py::test_frozen_record_carries_the_complete_response_review`, `::test_required_completed_and_not_attempted_pin`; `review-teaching.test.js` full render |
| 2 | Collateral exactly once, named + why | PASS | `::test_acceptable_completed_and_collateral_pins`, `::test_endstate_isolation_collateral_pin`, corpus reconciliation |
| 3 | Detections block: call + correctness | PASS | frozen-record test (detections block rows) + `::test_corpus_real_drip_review_reconciles_with_frozen_scores` (block == graded roster; shared `disposition_call_correct`) |
| 4 | No teaching pre-submission / foreign (404 + markers) | PASS | `::test_unknown_incident_404_and_no_review_before_submission`, `::test_planted_template_marker_never_leaks_pre_submission` (template + rationale canaries over the enumerated surfaces) |
| 5 | Pivot names clue/transition/origin/return; banner dies with snapshot | PASS | `pivot-transitions.test.js` |
| 6 | Selection-inspector connection | PASS | `inspector-connection.test.js` |
| 7 | Progress counts == shared roster | PASS | `progress-vocabulary.test.js` + inherited roster guards |
| 8 | (A1-B.6 replacement) tooltips all modes; hints Guided-only, neutral; Hardcore coaching-free | PASS | `help-model.test.js` (10 tests: allow-list, structural neutrality, denylist, mounting, purity) |
| 9 | No pre-submission correctness/totals/forbidden phrasing | PASS | forbidden-phrase scan; planted markers; inherited temporal suite (`test_submission_gate.py` 26/26) |
| 10 | Scope truth three-state (translated) | PASS | `scope-truth.test.js` |
| 11 | Single return, case changes only by selection (structural) | PASS | `workbench-states.test.js` |
| 12 | Stale-results statement | PASS | `workbench-states.test.js` |
| 13 | Pinned line/block/timeline/echo never disagree | PASS | `investigation-context.test.js` |
| 14 | Completed incident never renders active strip | PASS | `progress-vocabulary.test.js` |
| 15 | Inherited batteries green; fields disclosed; zero console errors | PASS | `run_gates.py --all` per phase; this report; console sweeps below |
| 16 | Count reconciliation (inaction fold-in + out_of_order subset) | PASS | `::test_count_reconciliation_fixtures_both_fold_ins` + `::test_corpus_real_drip_review_reconciles_with_frozen_scores` (real drips, all 20) |
| 17 | Toast trigger-list exactness, no duplication | PASS | `live-progress.test.js` + `progress-vocabulary.test.js` |
| 18 | Checklist answer-key-independent; prompt byte-identical Guided-only | PASS | checklist leak battery (`progress-vocabulary.test.js`) |
| 19 | Case Closed/achievements/takeaway deterministic, post-submission, ONE venue | PASS | `review-teaching.test.js` (determinism + zero-writes + venue through the real submit flow + exact derivation table) |
| 20 | Empty-run behavior (A2-AC-1) | PASS | `query-clarity.test.js` |
| 21 | Ruled three-line error form (A2-AC-2) | PASS | `query-clarity.test.js` |
| 22 | Restore last working query, request-free (A2-AC-3) | PASS | `query-clarity.test.js` |
| 23 | Chip honesty + Custom-filters boundary (A2-AC-4) | PASS | chips battery + `CONJUNCT_SPLIT_CORPUS` |
| 24 | Every product-generated query parses (A2-AC-5) | PASS | `GENERATED_FORMS_CORPUS` (frontend byte-pin + `test_lcql.py` 49) |
| 25 | Surrounding hold + zero-request restore (A2-AC-6) | PASS | `query-clarity.test.js` surrounding battery |
| 26 | Ruled tooltips permanent/accessible/mode-universal; pivot naming (A2-AC-7) | PASS | `query-clarity.test.js` + `help-model.test.js` |

No criterion unmapped; no test covered implicitly.

---

## 6. Chrome workflow transcripts (Section 18, consolidated forms)

Executed against a FRESH dev backend each time (the dev-harness rule:
batteries sweep session dirs, so the backend was restarted before every
walk). App route `/sim`; frontend dev server on :3000.

- **W1 Guided teaching run (Phase 5 boundary):** Guided →
  "Event Logs Cleared on Workstation" (defense_evasion_log_clearing).
  Verified live: checklist (0-of-5 → 5-of-5, classification line updating,
  Guided consider-prompt, Ready line), T1 toasts with descending
  sealed-roster counts, the ONE readiness milestone toast ("All detections
  reviewed. INC-8619 is ready to submit."), the submit confirm naming the
  filing, the Case Closed modal (moment + achievements "Case Closed · All
  5 detections reviewed / No Collateral / Solo Close" + grade rows A·100 /
  B·80 / F·0 / D·64, NO teaching content), "Review what you learned" →
  Metrics Learning Review: selector chip INC-8619 D, sections with the
  frozen whys ("What you did correctly: None."; missed Isolate Host
  ACME-WS34 + Remove Persistence WMI subscription 'WindowsUpdConsumer'
  with registry-grammar labels), per-detection verdicts (Correct/Wrong),
  T1685.005 education, 5-step playbook, and **Key takeaway rendering the
  authored frozen paragraph** — the complete D2 loop live. Pre-submission
  Metrics showed the Learning Review empty state + Session Performance
  banner with zero teaching. The mixed-bucket render
  (taken+omitted+collateral in one record) is test-proven
  (`review-teaching.test.js` full-render fixture).
- **W2 Inaction:** test-proven this stage (7.1 inaction empty-state test +
  the all-20 act-on-nothing corpus reconciliation covering the six
  inaction scenarios); the correct-inaction Chrome workflow was last
  walked at the Stage 3d/3.9 certifications and its engine is unchanged.
- **W3-W5 pivot chain / scope truth / parse-failure truth:** walked at the
  merged Phase 3/4 boundary (pinned-case chain, Retry-only recovery,
  empty-run + malformed-run ruled error form, Restore, surrounding
  enter/return); the focus/origin divergence is structurally
  unrepresentable under the case-constant model.
- **W6 inspector connection:** walked at the Phase 4 checkpoint (scroll +
  single emphasis + selection dot; persistence across views/sort);
  reduced-motion leg unit-proven.
- **W7 Hardcore purity (Phase 6 boundary):** full Hardcore start
  (password_spray drip): 15:00 timer live, NO "Need a hint?", NO
  consider-prompt on the checklist, NO Check Answer; tooltips present and
  rendering (the Promote CSS tooltip verified on hover in Hardcore);
  vocabulary intact.
- **W8 leak audit:** live pre-submission network sweep — GET-only traffic
  (incidents, detections, actions, analytics, game-state, health,
  reports), zero writes on render (matches the determinism test's
  zero-writes assertion). Payload-body guarantees are mechanical: the
  planted-marker suite asserts template AND rationale canaries absent
  from the response bodies of those same routes, and
  `test_submission_gate.py` holds the temporal boundary. All-tab console
  sweeps: zero errors attributable to product code (see Environment
  notes).
- **W9 0-of-0 regression:** the submitted incident's pane rendered the
  completed strip ("Reviewed 5 of 5 · Submitted") + Case Closed summary,
  never the active strip (also pinned by `progress-vocabulary.test.js`).
- **W-Guided-hints (Phase 6 boundary):** Guided random run
  (ssl-inspection FP): "Need a hint?" renders bottom-left; L1 "How the
  controls work" (four mechanics lines); "Nudges" → the
  detections-surface library only. Hint content identical regardless of
  scenario (structural neutrality test).

## 7. Leak-audit results

- Planted markers: a canary planted in EVERY Tier 1 template and in the
  fixture scenario's `expected_response` appears in NO pre-submission
  payload across the enumerated surfaces (incident cards, per-incident
  score, detections feed, threats, response log, the three session-wide
  analytics) — `test_planted_template_marker_never_leaks_pre_submission`.
- Temporal boundary: `test_submission_gate.py` 26/26 (unchanged suite,
  untouched assertions) + the new absence tests (no `response_review`,
  `reason_code`, `bucket`, `why`, `expected_ref`, `scenario_rationale`
  strings in any in-progress payload).
- Aggregate shape: session-wide `report_card` / `action_score` /
  `detection_score` never carry review content
  (`::test_aggregates_never_carry_review_content`).
- Freeze integrity: stored records byte-identical under template,
  registry, AND YAML mutation, idempotent resubmit included
  (`::test_stored_review_is_frozen_against_template_and_registry_change`,
  `::test_rationale_freeze_wiring_and_ruling_h`). Ruling H proven both
  directions.
- Help-model copy: the denylist battery proves no tooltip or hint string
  carries category names, scenario-label-shaped tokens, correctness
  phrasing, or em dashes; hint neutrality is structural (pure function of
  surface + level).
- Checklist/toasts: the leak rule (19.18) battery — constants only,
  byte-identical for every incident, observable numbers only.

## 8. Accessibility results

- Tooltips: native `title` (pointer) + visible text/aria-labels (screen
  readers) + the `.help-tip` CSS layer rendering the same line on
  `:focus-visible` (keyboard) — no timers, no focus stealing; verified
  live on hover in Hardcore.
- Toasts: `role="status"` container (polite announcements), never steal
  focus; limit 4; `pauseOnFocusLoss` disabled.
- Case Closed: one-shot 200ms entrance, no loop, no sound;
  `animation: none` under `prefers-reduced-motion` (index.css).
- Inspector emphasis: one run per selection change; skipped under
  reduced motion (jump scroll, no pulse) — unit-proven.
- Result rows expose `aria-selected`; the selection dot replaced the
  misleading rotating chevron; hint panel and dialogs carry labels and
  explicit close controls.

## 9. Deferred items (unchanged, none silently expanded)

- Tier 3 per-action rationale (ratified OD-1 deferral).
- L3 scenario-specific hints (B-OD-2); achievements requiring new
  tracking (B-OD-3: tool-usage, speed, run-level, cross-session);
  progression store (B-OD-4; D5 superseded — no client store shipped).
- The A2 deferred register (autocomplete overhaul et al.) and the
  contract Section 19 deferrals (Stage 4 list) — untouched.
- `response-vocabulary-v2` backlog — untouched.

## 10. Deviations and irregularities (flagged per the deviation rule)

- **D-1 (`fd8d426`):** the harness-fix commit ALSO carries the
  malware_usb rationale landing. Cause: the hook had aborted the first
  malware_usb commit red (see D-2), leaving its files staged; the
  follow-up `git commit` consumed the whole index. The commit is green
  and internally consistent (content-wise it is still "one scenario +
  its ledger row", plus a test-only harness change), but its subject
  line under-describes it; disclosed here and in the ledger above.
- **D-2 (caught red, never landed):** the 5.3/5.5 review fixtures
  hardcoded `malware_usb` as an unauthored scenario; the first Tier 2
  landing broke that baseline and the pre-commit battery aborted the
  commit. Fix: the fixtures now use a synthetic catalog label and inject
  their own entries, valid at every rollout state; no assertion weakened
  (`fd8d426`).
- **D-3 (process substitution, one-shot):** the scaffold's 5.6 cadence
  names an owner approval of the rationale batch. Under the one-shot
  authorization ("complete … the authorized Tier 2 rationale rollout"),
  the batch was instead self-reviewed against every dumped answer key
  (required/acceptable/trap sets restated 1:1, password_spray's shape
  verified against its chain) and recorded in RATIONALE_CANDIDATES.md.
  Each paragraph is one revertable commit; post-hoc rewording reaches
  future submissions only (correction 6). The owner may strike or reword
  any paragraph without engine impact.
- **D-4 (checklist prefix collision, docs-only):** ticking
  `defense_evasion` in RATIONALE_CANDIDATES.md also ticked the
  `defense_evasion_log_clearing` row (substring replace). The very next
  landing made the row true; the helper was fixed to line-anchored
  matching. No code or YAML affected.
- **D-5 (tooling, no repo effect):** `textwrap` hyphen-splitting
  corrupted one uncommitted YAML fold (false_positive_oauth), caught by
  the helper's own round-trip assertion; the file was restored from HEAD
  and re-landed with `break_on_hyphens=False`. Never staged, never
  committed.
- **Scaffold test-name finals:** several Section 8 provisional test names
  differ from the landed names (mapping in Section 5); the scaffold
  declares names final at implementation, structure binding.

**Environment notes (not product defects):** dev-proxy "Proxy error"
console bursts occur in the exact windows where the backend restarts
(timestamps verified pre-run; walks were clean after clearing);
first-attempt CDP screenshot timeouts recur in the automation window and
succeed on retry; rAF throttling in unfocused windows delays
react-toastify auto-close, so toast stacks linger during automation. A
stray `icout.txt` (a mis-redirected command capture from the Phase 4
debugging) was removed from the repo root at certification.

---

## 11. Copy inventory as landed

All canonical strings live in `frontend/src/components/uiCopy.js` (R7:
one vocabulary module), consumed by the surfaces and pinned by tests; the
help-model strings in `helpContent.js` import the four ruled query finals
from uiCopy byte-identically. Phase additions: case-constant terms (1.x),
the 10.1 vocabulary + toast strings (2.x), the A2 ruled finals — tooltips,
three-line error form, "No query entered.", "Restore last working query",
"Back to previous results", "Custom filters", the "Example:" placeholder,
the surrounding block copy (3.x), Case Closed / achievement labels /
"Review what you learned" / Learning Review labels / review section
headers / 7.1 empty+error strings (5.4), and the five new one-line control
explanations (6.1). The em-dash scan covers every non-test source file;
the forbidden-phrase scan stayed word-boundary-anchored and green
throughout.

## 12. Certification statement

All seven phases of the consolidated scaffold are implemented on
`stage-5-live-run-feedback` at `2f6735b` (+ this docs commit); the full
`--all` battery is green at the tip; the acceptance table is fully mapped
with landed test names; the three ratified payload changes are the only
serialized-shape changes; teaching is served exclusively across the
submission boundary from byte-frozen records; the help model is
answer-free by construction and Guided-gated where it coaches. Stopped at
the Stage 5 checkpoint: **no merge to main, no push, no polish, no new
stage.**


---
---

# Part II — C1 Checkpoint Fixes + Amendment 3 (2026-07-26, append-only)

Extends the Phase 7 certification above. Two owner-directed increments
landed on `stage-5-live-run-feedback` after the post-Stage-5 checkpoint
product review: the C1 checkpoint fixes (defects against ratified text;
docs/stage-5-checkpoint-fix-report.md is their own artifact) and the
ratified Amendment 3 implementation (contract appendix A3 + the A3-R.1
owner rulings). **NOT merged to main, NOT pushed.** Gates at the A3
product tip `afbf93b`: `run_gates.py --all` **ALL GREEN** (backend
battery complete incl. `test_lcql.py` 50; frontend **27 suites / 264
tests**; was 26/244 at `a883508`).

## II.1 Complete ordered commit ledger (`a883508..`)

**C1 checkpoint fixes (post-review; defects against ratified text):**
- `a2cc3dc` C1-1 (F1): evidence-surface nav badges removed (+ dead
  setXCount paths); nav-badges.test.js
- `0a1fcd2` C1-2 (F5a): Learning Review buckets conform to A1-B.4.1
  (correct dispositions join the well bucket; category headings and
  empty states; bare "None." deleted)
- `7ac299d` C1-3 (F4a): the ratified A1-B.3.2 workspace classification
  selector mounted (modal flow then unchanged, pre-filled)
- `763b116` C1-4 (F2 latent): interim failed-return guard (criteria
  10/13), later superseded by A3.2
- `80878da` C1-5 (F6 slice): Reports nav entry hidden; lying
  empty-state copy replaced
- `74198f2` C1 docs: fix report + the standing scaffold 10.1
  ratified-copy conformance sweep

**Amendment 3 (drafted, ratified, implemented):**
- `72e286b` A3 DRAFT appended after Amendment 2 (docs-only,
  append-only verified; branch `stage-5-amendment-3`)
- `b30ff4c` A3 RATIFIED: A3-R.1 owner rulings recorded verbatim
  (OD-1 final copy; OD-2 Check Answer on the workspace selection with
  the modal variants deleted; OD-3 one shell-owned Ready; OD-4 Simple
  default everywhere, session-local)
- `74dbd34` merge `stage-5-amendment-3` into
  `stage-5-live-run-feedback` (`--no-ff`)
- `393b484` A3-8 scaffold delta applied (docs-only)
- `7acde0a` **A3.1** copy constants ahead of consumers (R7): the six
  ruled finals + four standing drafted finals; byte pins + scan rows
- `ed5bbc8` **A3.2 (F2)** model B: expanded-search entry captures
  the pre-entry {queryText, snapshot, scope, timeline}; the return
  RESTORES it exactly with zero query/scope requests and consumes it;
  the hold survives every run while expanded; cleared by case change,
  incident-scoped descent, and reset; ruled RETURN_SUBCOPY; the C1
  guard removed as unreachable; the model A re-run tests translated
  to the restore battery
- `75e2d6d` **A3.3 (F3)** Surrounding events removed end to end
  (control, banner branches, focus chain, the A2 hold machinery, four
  strings, the docs clause); tooltip set NINE to EIGHT; descentHost
  and descent untouched; the two OR-fallback tests relocated; net
  -313 lines
- `6a20750` **A3.4 (F4b)** final submission gating: shell-owned
  `chosen`, the ONE `submissionReady` derivation (server readiness
  AND a valid classification) at every Ready surface (checklist,
  Submit, list chip, Ready view/count, IncidentDashboard chip, with
  "Submit pending" when server-ready unclassified); the bare
  confirmation only (landed copy verbatim + the Hardcore warning
  relocated in); the modal variants DELETED; Check Answer consumes
  the workspace selection and disables until it is valid
- `680fc1b` **A3.5 (F7)** simple search: the FILTERS-only bar +
  value-driven Source / Event type selects projecting the ONE
  canonical pending text; composeQuery / replaceTimeframe /
  rawFiltersOf chokepoint forms (the raw timeframe splice migrated);
  mode-scoped placeholder/help/empty rules; Simple default in every
  play mode, session-local toggle; Advanced unchanged one toggle
  away; simple-search.test.js
- `afbf93b` **A3.6 (F7)** the FILTERS-vs-compiler error boundary with
  the field-relative position remap; GENERATED_FORMS_CORPUS 12 to 18
  on both sides; the SOURCE_FAMILIES two-sided parity pin; the
  splice-translation corpus; the representability round-trip battery;
  backend test_lcql.py TESTS ONLY
- (this commit) **A3.7** certification: the Chrome walks, the
  conformance sweep, this report

## II.2 Behavioral changes (player-facing, complete)

1. **Nav rail:** no numeric badges on SIEM/Detections/Endpoints; the
   Incidents badge stays; the Reports entry is hidden until a working
   workflow exists.
2. **Learning Review:** the well bucket states correct detection
   calls ("Detection calls: N of M correct") beside completed
   required actions; every bucket heading and empty state names its
   category.
3. **Classification is an inline workspace step** (the selector on
   sealed active incidents) driving the checklist line.
4. **Ready means submission-ready everywhere:** server observable
   readiness AND a valid classification; a server-ready unclassified
   incident reads "Submit pending" on every surface; Submit disables
   with "Select a classification to submit." until then; Submit opens
   ONE bare confirmation (no data entry; Hardcore carries its warning
   there); Check Answer (Guided) consumes the same selection and
   disables until valid. The server gate is untouched as the
   authoritative backstop.
5. **Expanded search returns by RESTORE (model B):** entering holds
   the pre-entry view; "Return to INC-#### evidence" redisplays it
   exactly, zero requests, hold consumed; work done while expanded is
   not kept (the ruled subcopy says so); a restored stale snapshot is
   dated by its existing as-of marker.
6. **Surrounding events is REMOVED** (rationale recorded in A3-3.1);
   evidence descent unchanged; eight permanent tooltips.
7. **Simple search is the default search** in Guided, SOC Queue, and
   Hardcore: a filter-expression bar + Source / Event type / Timeframe
   controls compiling to canonical LCQL through the one generator; the
   canonical echo keeps showing the four-part truth; Advanced LCQL is
   one toggle away; FILTERS parse errors name the Filters section with
   field-relative positions; pre-FILTERS errors are corpus-guarded
   product defects, never player errors.

**Serialized-field and endpoint changes: NONE in either increment.**
Backend product code is byte-untouched (the only backend diff is
test_lcql.py, tests only). Scoring, rosters, readiness, sealing,
records, snapshot identity, and the LCQL engine are unchanged;
`test_submission_gate.py` untouched at 26/26.

## II.3 Final test inventory (delta)

New suites: `nav-badges.test.js` (3), `simple-search.test.js` (9).
Deleted: `workbench-surrounding.test.js` (the control is removed; its
two OR-fallback tests live in query-clarity). Extended: the model B
battery (workbench-cross-host + workbench-states + the
workbench-descent timeline-restore leg), the F4b gating/one-Ready
battery (incidents-workspace), the A1-B.4.1 conformance regression
(review-teaching), and the corpus/parity/round-trip pins
(query-clarity + backend test_lcql.py: GENERATED_FORMS_CORPUS 18,
SOURCE_FAMILIES parity, 50 passing). The pre-A3 Siem batteries mount
`initialQueryMode="advanced"` (see Deviations).

## II.4 Chrome verification (2026-07-26; dev servers; zero console errors on both walks including clean reloads)

- **C1 walk (Guided INC-9709, defense_evasion_log_clearing):** the
  badge-free rail with no Reports entry; the workspace selector
  driving the checklist live; all-correct triage + zero response
  actions submitted A/A/F C-70; the Learning Review rendered
  "Detection calls: 5 of 5 correct" and "No required response actions
  were completed." beside the missed-action whys (the owner-observed
  "None." contradiction gone).
- **A3 walk (Guided INC-7180, defense_evasion_log_clearing):** default
  Simple mode (ruled placeholder and help, both selects, the Advanced
  LCQL toggle); an untouched Run compiled `1h | * | * | *` with the
  four-part echo; the case anchored as INC-7180 evidence with
  scope=INC-7180; the inspector shows ==, !=, Pivot and NO Surrounding
  control; a hostname pivot entered Expanded search (clue line, ruled
  subcopy, and the Source select showing ACME-WS17, the value-driven
  mode-stability live); **Return restored the case evidence
  instantly: the same snapshot marker (seq #23, 12:42:06 sim), the
  echo back to `1h | * | * | *` scope=INC-7180, selection preserved,
  zero requests**; 4/4 correct triage fired the milestone toast
  (announcing triage completion) while the checklist read "Submit
  pending" with Submit disabled and "Select a classification to
  submit."; True Positive then Defense Evasion flipped EVERY surface
  to Ready together (list chip, Ready 1, checklist, Submit, Check
  Answer); the bare confirmation named the filing with no classifier
  step; submitted A/A/F C-70, Solo Close earned.
- **W7 (Hardcore INC-8744):** the 15:00 timer live; no "Need a
  hint?", no consider-prompt, no Check Answer; the dashboard and list
  chips read "Submit pending" for server-ready unclassified
  incidents; a workspace classification flipped INC-8744 alone to
  Ready; the confirmation carried "Hardcore: one wrong call ends the
  run."; the walk CANCELLED the dialog (no submission).

## II.5 Ratified-copy conformance sweep (scaffold 10.1, executed with the A3 row updates)

| Row | Ratified source | Verified against rendered output |
|---|---|---|
| 1 | A1-B.4.1 item 3 (the well bucket incl. correct dispositions) | PASS: the review-teaching conformance test + the C1 walk render |
| 2 | A1-B.3.2 line sources; Ready = the A3-4.2 conjunction | PASS: the incidents-workspace gating battery + both walks (no surface showed Ready while "Classification: not selected") |
| 3 | A1-A.5 finals + the A3 F2-1 return subcopy | PASS: progress-vocabulary byte pins + the expanded-search block render (the ruled two-sentence subcopy on screen) |
| 4 | A2/A3 query finals: three ruled tooltips; surrounding rows removed | PASS: the help-model eight-control pin + query-clarity + the inspector render (no surrounding control) |
| 5 | A1-B.3.1 toasts + the B-OD-5 prompt | PASS: live-progress + the milestone toast live (announces triage completion only) + the Hardcore prompt suppression live |
| 6 | A3-6/A3-R.1 F7 strings (placeholder, help, toggle, selects) | PASS: progress-vocabulary byte pins + the simple-mode render |

## II.6 Deviations and notes (flagged per the deviation rule)

- **D-II-1 (`initialQueryMode` prop):** the pre-A3 Siem test batteries
  author four-part LCQL directly, so they mount
  `initialQueryMode="advanced"` instead of clicking the toggle (the
  first attempt clicked the real toggle inside the suites' outer act
  wrappers, where React defers the nested-act flush and the control
  is not yet in the DOM). The product always mounts the default; the
  REAL toggle path is pinned by the simple-search round-trip test. A
  test-harness affordance on a product component, flagged as such.
- **D-II-2 (hold convergence shape):** the binding F2-before-F3
  sequencing was implemented as A3.2 introducing the expanded-search
  hold ALONGSIDE the A2 surrounding hold (each commit independently
  revertible, both gates green), with A3.3 deleting the surrounding
  hold; the amendment's "one hold with a changed lifetime" is the
  FINAL state, reached at A3.3 rather than by mutating the A2
  variable in place. Interim behavior stayed coherent (surrounding's
  return worked until its removal).
- **D-II-3 (milestone toast reading):** verified per A3-4.5: the
  T4/T5 toast keeps its ratified server-readiness trigger and wording
  ("...is ready to submit"), announcing triage completion while the
  checklist gates submission on classification; recorded as the
  verified-compatible reading, not reopened.
- Known stale docs, untouched (out of scope): CLAUDE.md's UI
  Architecture tab list; `TriageFeedback.jsx` remains orphaned;
  `ActionHistory.jsx`'s "Post-Incident Review" heading (review item
  5c, optional polish, unauthorized).
- Owner assets untouched throughout
  (`frontend/public/videos/spectyrvideo.mp4`,
  `frontend/public/spectyr_svg.svg`); every commit passed the
  versioned hook; `--no-verify` never used; nothing pushed.

## II.7 Stop

Stopped at the FINAL Stage 5 checkpoint: C1 + Amendment 3 are
implemented and certified on `stage-5-live-run-feedback`. **No merge
of Stage 5 into main. No push. No final UI polish begun. No new stage
begun.**
