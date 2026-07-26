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


---
---

# Part III — Final Product Simplification and Polish (2026-07-26, append-only)

## III.0 Owner ruling (recorded before implementation; no further planning cycle)

The owner authorizes the final current-product implementation pass
before merge, at baseline `fd6b98f` (verified: branch
`stage-5-live-run-feedback`, `--all` ALL GREEN 27/264, working tree
clean except the two pre-existing owner assets). Eight areas:

1. **Response becomes a first-class workspace** — SUPERSEDED mid-pass
   by the broader Response information-architecture ruling (III.0.1
   below), which governs.
2. **Remove the remaining scope furniture**: with an active incident
   the SIEM searches that incident's complete observable evidence
   pool; Pivot changes the query, never the evidence universe; no
   player evidence-scope switch, no Expanded-search state, no
   Return action, no Search all evidence, no incident-evidence chip,
   no repeated SIEM-level Investigating line, no hold. "All activity"
   remains the no-case fallback with no toggle. Preserve: scope
   loading, Retry, atomic replacement, stale-row honesty, no silent
   broadening, query execution, Pivot, filters, chips, Simple and
   Advanced LCQL, snapshots, scoring, and roster behavior. STOP if
   engine invariants would move.
3. **SIEM search-state truth**: distinguish initial evidence (never
   labeled a player query; "Initial incident evidence"), an executed
   search (readable filter primary in Simple mode: "Results for: X";
   the canonical stays available as the technical disclosure), edited
   but not run ("Search edited but not run. Showing results from the
   previous search." -- pickers and typing never execute; explicit
   ==/!=/chip/Pivot actions keep their ruled immediacy), failed
   search ("This search was not run." + "Showing results from the
   previous successful search." + the section-specific error), and a
   selected event hidden by the results ("The selected event is
   hidden by the current results. Change the filters or select
   another event." -- never silently close the inspector or alter
   filters). The placeholder stays unmistakably an example.
4. **Replace the unclear Refresh**: the existing authoritative
   new-count exists (the token-bound `/api/events/query/new-count`
   poll), so the action becomes "N new events available" + "Load new
   events"; no live tail, no silent row movement, snapshot stable
   until invoked, truthful reset after loading, no generic Refresh
   label, snapshot identity and atomic replacement preserved.
5. **Rename the evidence entry action**: "Open Evidence Timeline"
   becomes "Investigate in SIEM"; it prepares and opens the existing
   SIEM search; no separate Timeline concept survives; an executed
   prepared search is identified by the readable filter expression;
   no redundant origin line.
6. **Compact Metrics summary**: the large vertical Classification /
   Detections / Response grade cards become one compact responsive
   summary (Overall grade once + three equal columns; same values and
   calculations; responsive stacking; accessible order); the detailed
   teaching sections remain beneath; no distinct grading information
   removed.
7. **Reports stay hidden**; nothing may imply a report workflow
   exists.
8. **Tests, certification, and documentation** per the directive: the
   permanent regression batteries, the full gate battery, the
   ratified-copy conformance sweep, a fresh Guided Chrome playthrough
   plus Hardcore purity checks, zero steady-state console errors, no
   duplicate action requests, owner assets untouched, and this Part
   III record. FINAL STOP at the product checkpoint: no merge to
   main, no push, no further planning or feature cycle.

## III.0.1 Response information-architecture ruling (superseding; recorded verbatim in substance)

Binding product model: **Investigate -> Triage -> Respond -> Submit ->
Learn.** Response is the ONE canonical action-execution workspace.

- **Detections owns triage only** (Promote / Dismiss / Reopen). The
  Threats tab, Response Log tab, Respond column, and every
  response-action execution control leave Detections. Promotion
  contributes context to Response but never implies a response is
  correct or required.
- **Endpoints own investigation only**: overview, processes, network,
  services, users, autoruns, system state, and action-state
  indicators stay; every direct action execution (Isolate, Kill,
  Delete File, Remove Persistence, identity verbs) leaves. Removed
  contextual actions are replaced by neutral navigation ("Respond to
  this host/process/target", "Open in Response") that selects the
  target in Response and executes nothing. No verb may remain
  uniquely accessible through an Endpoint subpage.
- **Response is the only execution surface**: primary navigation
  beside SIEM / Detections / Endpoints / Metrics. Actions view groups
  actionable incident entities by target type (Hosts, Accounts,
  Processes, Files, Persistence, and any other type the existing
  action system supports), each showing only factual context (target
  identity, host or parent, related promoted detections where
  applicable, observable action state, available existing verbs,
  actions already executed) and never required / recommended /
  correct / sufficient / remaining / expected or answer-key-derived
  ordering. The Response Log moves in as the single chronological
  history (time, action, target, result, detail).
- **One action system**: one registry, one availability calculation,
  one confirmation path, one request path, one state-update path, one
  log; existing controls and handlers extracted, never reimplemented;
  every current behavior preserved (preconditions, no-effect,
  ordering, outcomes, action sequence identity, scoring, immutable
  records, toasts, target-state badges, response-action count). No
  backend / scoring / schema / endpoint / serialized-field change
  unless repository truth proves sharing impossible; STOP first.
- **Contextual navigation**: promoted detections may offer "Open in
  Response"; endpoint surfaces offer "Respond to this target"; both
  select, never execute or recommend. Response remains fully usable
  from primary navigation alone.
- **Empty and state behavior** (never revealing whether inaction is
  correct): no incident -> "Select an incident to begin response.";
  no promoted detections -> "No detections have been promoted." +
  "You can still review incident entities and actions below."; no
  actionable entities -> "No response targets are currently
  available."; no actions taken -> "No response actions taken."
- **Progress**: "Response actions taken: N" stays informational and
  never gates Ready or Submit; the Response navigation shows no
  correctness or required-action counts (and, consistent with the C1
  badge ruling, no numeric nav badge).
- Required regression coverage and Chrome verification per the
  ruling, including the exact before/after action inventory.

## III.0.2 Action inventory — before and after (exact)

| Verb | Old execution location(s) | New execution location | Old surface becomes |
|---|---|---|---|
| isolate_host / release_host | Endpoint Overview reserved area (`EndpointDetail.jsx` Overview, target `snap.entity_id`) | Response > Actions > Hosts | Overview keeps the Isolated badge + gains "Respond to this host" |
| kill_process | Endpoint Processes rows (`p.entity_id`) | Response > Actions > Processes | Process rows keep state display + gain "Respond" navigation |
| delete_file | Endpoint Autoruns rows (`a.file_entity_id`, `file_state === 'present'`) | Response > Actions > Files | Autorun rows keep flag badges + gain "Respond" navigation |
| remove_persistence | Endpoint Autoruns rows (`a.persistence_entity_id`, `registration !== 'removed'`) | Response > Actions > Persistence | same as above |
| disable_account / revoke_sessions / force_password_reset | Detections > Threats view Respond column (target `d.entity.account_id`) | Response > Actions > Accounts | Threats view removed; promoted rows gain "Open in Response" |
| (history) Response Log | Detections > Response Log view | Response > Response Log | view removed |

Endpoint Users tab was display-only (no action moved). Services carry
no verb in the existing action system, so no Services action group
exists (recorded, not silently omitted). All target entity ids already
ride existing payloads (endpoint snapshot `entity_id` /
`p.entity_id` / `a.persistence_entity_id` / `a.file_entity_id`;
detection `entity.account_id`), so the move is frontend-only.

Implementation ledger, evidence, and verification follow in III.1+.

## III.1 Implementation ledger (one concern per commit, never landed red)

| Commit | Area | Substance |
|---|---|---|
| `b2b480f` FP1 | III.0.1 | Response is the one canonical action-execution workspace (Actions grouped by target type + Response Log); Detections triage-only; Endpoint surfaces investigation-only with neutral Respond navigation; one action system (`responseActions.js`); ruled empty states; `feed_threats` tooltip retired; new `response-workspace.test.js` battery |
| `114c2d2` FP2 | III.0 item 2 | One evidence universe: with an active incident every SIEM search runs in that incident's observable pool; Pivot changes the QUERY, never the universe, announced via `followingClue` on the one notice line; Expanded-search state/block, model B hold + return, Search all evidence, the case-evidence chip, and the repeated SIEM-level case labeling all removed; scope-error recovery is Retry alone; descent untouched (locked Stage 4 contract) |
| `ca31f38` FP3 | III.0 item 3 | Search-state truth: snapshot provenance (`prepared` vs `player`); "Initial incident evidence" / "Initial evidence" for prepared entries, "Results for: X" (readable filters; match-all reads "all events") for player runs with the canonical kept as the technical disclosure; ruled edited / failed sentences; hidden selection RETAINED with the ruled notice; placeholder example guarded; new `search-state-truth.test.js` |
| `ce0bfc1` FP4 | III.0 item 4 | "N new events available" + "Load new events", rendered ONLY beside the nonzero token-bound count; no generic Refresh label survives; action re-executes the displayed identity, preserves provenance, resets the count truthfully; fake-timer Load battery in `workbench-snapshot.test.js` |
| `c9551af` FP5 | III.0 item 5 | "Open Evidence Timeline" becomes "Investigate in SIEM" on Incidents + DetectionDetail + Docs + the Guided nudge; NO separate Timeline concept survives (origin banner, breadcrumb Back, occurrence-ascending re-sort, `timeline` state, and the Siem `onNavigate` prop all removed); entry requests slim to observable `{hosts, account, scopeIncidentId}`; "host timeline" pivot label becomes "host activity" |
| `efaa6f1` FP6 | III.0 item 6 | The three vertical grade cards become ONE compact responsive Score Summary: Overall grade exactly once, three equal columns (same values and calculations), `grid-cols-1 -> sm:grid-cols-3` stacking in accessible DOM order, the factual teaching blocks beneath; the Session Performance composite ring untouched |
| `f2d280a` FP7 | III.0 item 7 | Remaining report-workflow implications removed: player Docs Reports section + nav entry + intro sentence, landing Reports link, reset-modal copy (also correcting stale pre-3.9B "alerts" naming); permanent guard `no-report-workflow.test.js` (the hidden nav tab stays guarded by `nav-badges.test.js`) |
| (docs) FP8 | III.0 item 8 | This record; full battery + Chrome verification below |

## III.2 Flagged deviations and rulings of necessity (deviation-flagging rule)

1. **TOOLTIP_PIVOT (A2 ratified final) reworded** -- FLAGGED consequential
   change: item 2 removed the pivot's scope broadening, so the ruled
   sentence "Follow this clue across all available evidence." became
   untrue. It now reads "Follow this clue across the evidence you are
   searching."; the SIEM Guided nudge and the player Docs paragraph follow
   the same truth. The A2 `==`/`!=` finals are untouched.
2. **The 11.3 locked note wordings superseded** -- item 3 itself rules the
   new sentences ("Search edited but not run. Showing results from the
   previous search." / "Showing results from the previous successful
   search."), so this is the authorized supersession, recorded here
   because the old strings were locked contract finals.
3. **`INITIAL_EVIDENCE` minimal variant** -- item 3 names only "Initial
   incident evidence"; a prepared entry can also exist with NO case (a
   session-wide detection entry), where naming an incident would be false.
   That state reads "Initial evidence". Flagged as the one string the
   ruling did not letter.
4. **Hidden-selection retention** -- the pre-pass behavior CLEARED a
   selection missing from new results; item 3's "never silently close the
   inspector" is implemented as retention: the id is kept, the ruled
   notice explains, the pane reopens when a later result set includes the
   event, and no filter is altered on the player's behalf.
5. **Entry-request slimming** -- `origin` and `backView` left the descent
   request shape (Incidents / DetectionDetail -> Dashboard -> Siem); they
   carried nothing but the removed banner and Back link. Observable-data
   discipline is unchanged.
6. **Known edge (inherited, recorded)** -- a detection opened while the
   case's scope read is in a FAILED state descends session-wide under the
   locked Stage 4 rule ("the player-selected incident context when the
   entry carries one"); with the banner gone, that state is disclosed by
   the technical `scope=session` line beside the pinned case line. It is
   reachable only from a degraded scope read and exits on the next case
   re-anchor.
7. **Dev-environment observation (backend untouched, not fixed here)** --
   during verification the long-running dev backend held an in-memory
   session whose log directory no longer existed; its drip thread dies on
   the first append and the run never injects. Fresh sessions are
   unaffected; the session-lifecycle code predates this pass and is out of
   its authorized scope. Recorded for a future hardening ticket
   (recreate the session dir on start), not acted on.

## III.3 Verification evidence (III.0 item 8)

- **Full gate battery**: `python backend/run_gates.py --all` exit 0,
  `[gate] ALL GREEN` -- all 29 backend suites (test_scenario_loader_v2
  through fairness_check, re-confirmed in a second per-suite run) plus
  the frontend suite at 30 suites / 271 tests (up from 27/262 at the
  `fd6b98f` baseline: `search-state-truth`, `no-report-workflow`, and
  `response-workspace` added; every retranslated suite green). The
  versioned pre-commit hook ran the frontend battery at every FP commit;
  no commit landed red and `--no-verify` was never used.
- **Ratified-copy conformance**: the pinned-copy suites
  (`progress-vocabulary`, `help-model`, `score-sections`,
  `search-state-truth`) carry the Part III finals byte-exact; the retired
  strings (`caseEvidenceLabel`, `SEARCH_ALL_EVIDENCE`,
  `EXPANDED_SEARCH_TITLE`, `expandedSearchExplanation`,
  `returnToCaseEvidence`, `RETURN_SUBCOPY`, `NO_RESULTS_OUTS`,
  `RESULTS_FROM_LABEL`, `TOOLTIPS.expanded_search`) are gone from the
  module and every consumer.
- **Fresh Guided Chrome playthrough** (scenario
  `defense_evasion_log_clearing`, INC-7599, unassisted): Investigate in
  SIEM opened the prepared host search labeled "Initial incident
  evidence" over the one "Investigating INC-7599" line -- no chip, no
  search-all, no banner, rows as served; a `source_type` pivot executed
  under `scope=INC-7599` announcing "Following clue: source_type =
  \"Sysmon\"" and the label became "Results for: all events" with the
  canonical disclosed beside it; changing a picker executed nothing and
  surfaced the ruled edited sentence with Restore; 5/5 detections triaged
  in triage-only Detections (promoted rows offering only "Open in
  Response"); Isolate Host + Remove Persistence (the WMI subscription)
  executed from the Response workspace through the confirm dialogs, the
  Response Log holding exactly one row per action; submit through the
  one boundary produced Incident Grade A · 100 on all three components
  (Classification / Detection dispositions / Response actions, composite
  A · 100, all six achievements, `assisted: false`); the Learning Review
  and the Metrics tab rendered the SAME numbers, with the compact Score
  Summary showing the Overall grade exactly once and the three equal
  columns in accessible order.
- **Load new events**: at rest with a zero count NO load control and NO
  generic Refresh label exist anywhere on the surface (verified by DOM
  probe live; the completed Guided run's pool is static, so the hidden
  control is the truthful state). The nonzero flow -- count-paired
  existence, identity binding, truthful reset, selection survival -- is
  pinned by the fake-timer battery.
- **Hardcore purity**: a fresh Hardcore run (3 incidents in flight,
  15:00 timer live) shows NO Check Answer, NO hint affordance, NO
  Guided consider-prompt in the checklist; "Investigate in SIEM" and the
  triage tooltips remain (mode-universal).
- **Zero steady-state console errors** across the entire walk (reset
  flows, playthrough, submit, review, Hardcore) and **no duplicate
  action requests** (the authoritative Response Log recorded exactly one
  attempt per executed action; a duplicate would surface as a `no_op`
  row).
- **Owner assets untouched**: the working tree before and after the pass
  carries exactly the two pre-existing owner assets
  (`frontend/public/videos/spectyrvideo.mp4` modified,
  `frontend/public/spectyr_svg.svg` untracked) and nothing else; no FP
  commit stages them.

## III.4 Final product checkpoint (FINAL STOP)

All eight authorized areas are implemented, tested, Chrome-verified, and
recorded. The engine invariants named in III.0 item 2's preserve list --
scope loading, Retry, atomic replacement, stale-row honesty, no silent
broadening, query execution, Pivot, filters, chips, Simple and Advanced
LCQL, snapshots, scoring, and roster behavior -- moved nowhere; every FP
commit is frontend-only. Branch `stage-5-live-run-feedback` stands at
FP7 + this record. Per the directive: NO merge to main, NO push, NO
further planning or feature cycle. The final product pass is COMPLETE.

---

# Part IV. Visual Identity and Dashboard Polish

Authorized as the visual-identity pass over the completed Stage 5
product. Behavior, scoring, the incident engine, response
centralization, query semantics, and the Learning Review model were
already complete and are unchanged here. Seventeen concern-separated
commits, `908e2d7..3d41d1a`, each landing green.

## IV.1 Provenance note (recorded first)

This pass was requested "before the merge," but the Stage 5 merge had
already completed under the preceding FINAL MERGE AUTHORIZATION
(`fed2ce1`, closure record `6ec048b`). The work therefore ran on
`stage-5-live-run-feedback`, which still stood exactly at the approved
tip `e3bfbdf`. Preconditions verified before the first commit: branch
tip `e3bfbdf`; FP0-FP8 all ancestors of it; `run_gates.py --all` exit 0
(29 backend suites, frontend 30/271); the two owner assets untouched
(`spectyrvideo.mp4` SHA256 `1FF6F983...`, `spectyr_svg.svg`
`48CD642E...`). Bringing this pass into `main` needs a fresh merge
authorization.

## IV.2 Design principles

1. Solve each visual problem ONCE. `components/ui.jsx` is the single
   visual-language module (tokens, card surface, severity/grade maps,
   PageHeader, SegmentedToggle, Btn, StateChip, empty/loading/error
   states); `components/icons.jsx` is the single icon system;
   `index.css` holds the one type scale and the one table system.
2. Uniformity is the visual language, never the layout. Each workspace
   keeps the information architecture its function needs.
3. Dark surfaces are reserved for chrome: primary navigation, the app
   header, selected segmented controls, primary buttons. Data surfaces
   are light.
4. Data truth over decoration: every number names a real source; no
   trends, deltas, or sparklines exist because no historical series
   exists; correctness is never disclosed before submission.
5. Never color alone: every state carries a word, an icon, or a text
   equivalent.

## IV.3 Commit ledger

| # | Commit | Concern |
|---|--------|---------|
| VP1 | `908e2d7` | Remove the pre-submission Check Answer (V1) |
| VP2 | `b48d464` | Shared visual-language module + design tokens (VG) |
| VP3 | `b24ee2c` | One icon system, distinct nav identities (V2) |
| VP4 | `0741ec7` | Platform/device identity on endpoint surfaces (V2b/V7) |
| VP5 | `2623715` | Shell utility region + ghost avatar (V3) |
| VP6 | `cb9c6a7` | ATT&CK catalog mirror + corpus pin gate (V6a) |
| VP7 | `8d7c216` | Dashboard analytic overview grid (V5/V6b) |
| VP8 | `02ffe8b` | Page identities: Detections, SIEM, Incidents (V8/V4) |
| VP9 | `4cd1c62` | Response command-center identity (V9) |
| VP10 | `a3ecb6a` | Metrics identity + three-cards Score summary (V10) |
| VP11 | `99f3f12` | ATT&CK coverage RADAR replaces the matrix (owner correction) |
| VP12 | `acc0922` | Severity bars, Environment status, folded progress (owner) |
| VP13 | `a26199d` | Inter-first typography + type tokens (owner) |
| VP14 | `0edc998` | Radar to the right-hand supporting column (owner) |
| VP15 | `d35df79` | Clean app header; session banner retired (owner) |
| VP16 | `f11bff4` | Light table system, no card stripes, micro-heading scale (owner) |
| VP16f | `3d41d1a` | Header title ink fix (found in Chrome) |

## IV.4 Icon inventory

One family (lucide-react, already installed; audited before any
dependency question). Navigation renders at 19px, inline identity at
15-18px, all strokeWidth 1.75; icons are decorative (`aria-hidden`)
with the accessible name on the control; no emoji anywhere.

| Surface | Icon |
|---|---|
| Dashboard | `LayoutDashboard` |
| Incidents | `AlertTriangle` (restored by the VP16 correction) |
| SIEM | `ScanSearch` |
| Detections | `Crosshair` |
| Endpoints | `Monitor` |
| Response | `ShieldCheck` |
| Metrics | `LineChart` |
| Rail chrome | `BookOpen`, `RotateCcw`, `Play`, `Ghost` |

Device/platform layer: `platformFor()` maps the REAL serialized fields
(`system.platform`, `os`, `role`) to a device class + platform key;
`DeviceGlyph` (server / workstation / laptop / generic), `PlatformBadge`
(local Windows four-pane mark, lucide `Apple`, local Linux silhouette;
`role="img"` + label). **Unknown platforms render NO badge**; the
PAN-OS appliance is the live case. lucide ships no Windows or Linux
brand mark, so two local glyphs on the same 24-unit grid were drawn
rather than adding a brand-icon dependency (reported, not silently
done).

## IV.5 Page-identity inventory

| Workspace | Anatomy |
|---|---|
| Dashboard | Analytic overview grid: supporting column (Active investigation with folded progress, Severity distribution, Environment status) + main region (KPI tiles, Recent results, ATT&CK radar) |
| Incidents | Master-detail case workspace |
| SIEM | Query and evidence workbench |
| Detections | Triage queue |
| Endpoints | Asset explorer (list + two-pane detail) |
| Response | Action command center (Actions / Response log, grouped targets) |
| Metrics | Learning Review dashboard + Score summary |

The workspace title lives in the ONE application header; page-identity
cards carry icon, count, subtitle, and controls but never repeat the
title (asserted: exactly one `t-page` per screen).

## IV.6 Typography tokens

`t-page` 26/650/1.2 - `t-section` 18/600/1.3 - `t-subsection` 14/600 -
`t-card` 14/600 - `t-body` 14/400/1.5 - `t-nav` 14/500 - `t-kpi`
28/650 tabular - `t-meta` 12/400 - `t-overline` 12/600/1.3 at 0.03em,
no uppercase transform. Inter leads the product stack. Mono
(`log-mono` / `font-mono`) is reserved for LCQL, raw events, IPs,
hostnames, INC ids, technique ids, timestamps, PIDs, and account
strings; identifiers are never lowercased or humanized.

## IV.7 Dashboard data sources

| Element | Source | Truth note |
|---|---|---|
| Active investigation | `/api/incidents` active card | Observable only; no correctness |
| Progress bar + text | card `triage` + shell classification state | Folded into the card |
| Severity distribution | incident `/scope` detection ids joined to `/api/detections` | Active incident; exact counts; bars scaled to the largest count; no percentage implied |
| Environment status | `/api/endpoints` | Current state only; availability = online/managed; platform breakdown from real fields; no uptime claim |
| Detections reviewed | `/api/detections` counts (promoted+dismissed) | Session observable |
| Response actions executed | `/api/actions`, success outcomes | Session observable |
| Incidents completed | `/api/incidents` completed | Session observable |
| Latest incident grade | newest submitted card `incident_grade` | Post-submission |
| Session performance | `/api/analytics/report_card` composite | Post-submission, aggregate |
| Recent results | per-incident frozen `/score` records | Post-submission; labeled "This session" |
| ATT&CK radar | static corpus mirror | Catalog coverage; no player overlay |

Omitted for lack of data (stated, not faked): trend lines, deltas,
sparklines, historical accuracy, MTTR-over-time, cross-session mastery.

## IV.8 ATT&CK radar data contract

One polygon over the 15 canonical pinned v19.1 tactics. Axis value =
Spectyr-represented techniques in that tactic divided by the
authoritative Enterprise technique count in that tactic.

- **Denominators**: derived from the official pinned STIX dataset
  (github.com/mitre/cti tag `ATT&CK-v19.1`,
  `enterprise-attack/enterprise-attack.json`), downloaded and
  sha256-VERIFIED byte-identical to the repo pin
  `fc783039...2cf1c97d`. No STOP condition applied.
- **Counting rule (both sides)**: parent techniques only
  (sub-techniques roll up), excluding revoked and deprecated objects,
  counted once per kill-chain tactic; 222 parents, e.g. Discovery 34,
  Stealth 30, Persistence 22, Lateral Movement 9.
- **Numerators**: the corpus answer keys under the same rule
  (Credential Access = T1003 + T1110 = 2, not 3).
- Percentages are plain represented/total, NEVER normalized against
  the largest Spectyr category. Honest range: 0-18%.
- Rings 0/25/50/75/100; radius labels off-axis (angle 18) so they never
  overlap a tactic name; concise visual labels with canonical names in
  the tooltip, each label SVG `<title>`, and the sr-only table; no
  animation; no adversary or player overlay.
- Guard: `test_scenario_loader_v2.test_frontend_attack_catalog_mirror`
  pins the provenance sha256, the exact 15 denominators, ids/names vs
  the canonical map, counts vs the corpus, and numerator <= denominator.

## IV.9 Tests

Frontend **36 suites / 317 tests**, backend **29 suites** (loader now
65). New permanent batteries: `no-check-answer` (6), `icons` (7),
`app-header` (4, replacing `utility-bar`), `attack-radar` (4),
`typography` (4), `surface-system` (5), plus additions to `endpoints`,
`incidents-workspace`, `response-workspace`, `score-sections`, and a
rewritten `incident-dashboard` (13). Final battery:
`python backend/run_gates.py --all` exit 0, ALL GREEN.

## IV.10 Chrome verification

Live Guided run (`INC-8340`, log-clearing) at 1536x960: mode picker
(V1 copy, "hints available", no Check Answer), Dashboard empty /
active / after-submission, Detections queue + detail, Incidents
workspace + submit flow, Metrics Learning Review, Endpoints list. The
light table system, the radar in its right column, the dark header with
its outline, and the platform identity all render as specified. Zero
steady-state console errors observed. **VP16f was found here**, not by
a suite: the workspace title rendered dark-on-dark because the
`.t-page` token ink outranks a Tailwind utility.

## IV.11 Deviations and honest gaps

1. **Provenance** (IV.1): the pass ran post-merge on the stage branch.
2. **v19.1 tactic list**: the V6 brief listed the pre-v19 tactics
   (Defense Evasion); the corpus is pinned to v19.1, where Stealth and
   Defense Impairment replace it. The pin wins.
3. **Services group omitted from Response** (V9): no service verb
   exists in the eight-action vocabulary; an actionless table would
   imply one. Backlogged to `response-vocabulary-v2`.
4. **Related-host identity stays text-only** (V7): the Incidents scope
   line is a comma-joined inline list where a per-host glyph pair does
   not fit (the "where space permits" clause).
5. **Batch-swap encoding damage**: a PowerShell pass wrote BOMs and
   mangled sort-caret glyphs; both were detected and repaired inside the
   same change, before any commit.
6. **Narrow-width Chrome verification NOT completed**: `resize_window`
   reported success but the rendered viewport stayed at desktop width,
   so tablet and narrow layouts are evidenced only by the responsive
   class structure and DOM reading-order assertions, not by a confirmed
   narrow screenshot. Stated rather than claimed.
7. **One unexplained live grade**: a Guided submission of True Positive
   plus "Defense Evasion" on the log-clearing scenario returned
   Classification F. Both halves were then proven correct in isolation:
   a new UI test asserts the submitted body is exactly
   `{verdict:'threat', category:'Defense Evasion'}`, and an engine probe
   shows `_classification_grade` returns A for that pair (F only when
   `actual_category` is None). The originating session could not be
   re-examined: a diagnostic script that imported `app.py` while the dev
   server was live triggered the boot-time orphan sweep and deleted the
   running session log directory (the known dev-environment hazard
   recorded in Part III). Flagged UNRESOLVED, needing one clean
   reproduction; no evidence implicates the visual pass, which touched
   no scoring path.
8. **`react-scripts` act() warnings** in the Siem/Incidents tests are
   pre-existing noise, unchanged by this pass.

## IV.12 Final state

Branch `stage-5-live-run-feedback`, tip **`3d41d1a`**. The working tree
carries ONLY the two owner asset items (`spectyrvideo.mp4` modified,
`spectyr_svg.svg` untracked), both byte-identical to their pre-pass
hashes. NOT merged, NOT pushed. Stopped at the visual-polish checkpoint.
