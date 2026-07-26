// Stage 5 Phase 1 commit 1.1 (consolidated scaffold; contract Amendment 1
// Delta A, ratified A-OD-1 naming finals). The ONE canonical player-facing
// copy module: seeded here with the case-constant context strings and the
// 11.3 honesty notes. The R7 rule applies: strings land as constants BEFORE
// any surface consumes them, and this module is completed as the full
// Section 10.1 vocabulary in Phase 2 commit 2.1 -- nothing is ever defined
// twice. Player-facing strings only; the copy-emdash scan covers this file
// the moment it lands.

// --- the pinned case line (contract A1-A.4 item 1) -------------------------
export const investigatingCase = (incidentId) => `Investigating ${incidentId}`;
export const ALL_ACTIVITY = 'All activity';

// --- the SIEM state pair (A1-A.2 point 4; ratified A-OD-4 placement) -------
export const caseEvidenceLabel = (incidentId) => `${incidentId} evidence`;
export const SEARCH_ALL_EVIDENCE = 'Search all evidence';

// --- the expanded-search block (A1-A.4 item 2) -----------------------------
export const EXPANDED_SEARCH_TITLE = 'Expanded search';
export const followingClue = (field, value) =>
  `Following clue: ${field} = "${value}"`;
export const expandedSearchExplanation = (incidentId) =>
  `Searching all evidence. Your case ${incidentId} stays open.`;
export const returnToCaseEvidence = (incidentId) =>
  `Return to ${incidentId} evidence`;
// Amendment 3 (ratified A3-R.1) return subcopy: the model B restore.
// The model A subcopy and the C1 interim guard string retired with the
// model A mechanics (F2: the return performs no scope re-run, so the
// guarded failure mode is unreachable).
export const RETURN_SUBCOPY =
  'Return restores the incident evidence you were viewing before Expanded search. Changes made in Expanded search are not kept.';

// --- the snapshot echo label (locked contract 11.2 "Results from") ---------
export const RESULTS_FROM_LABEL = 'Results from:';

// --- 11.3 honesty notes (locked contract Section 11.3, consumed verbatim) --
export const EDITED_NOTE = 'Edited. Results below are from the last run.';
export const STALE_RESULTS_NOTE =
  'Displayed results are from the previous successful query.';

// === Phase 2 commit 2.1: the complete Section 10.1 canonical vocabulary ===
// (locked contract 10.1/10.2; consolidated scaffold). Observable-only; the
// forbidden class (correctness phrasing, answer-key totals) never appears
// pre-submission -- progress-vocabulary.test.js scans every string below.

export const TELEMETRY_LOADING = 'Incident telemetry is still loading.';
export const detectionsReviewed = (triaged, total) =>
  `Detections reviewed: ${triaged} of ${total}`;
export const detectionsRemaining = (n) =>
  `${n} detection${n === 1 ? '' : 's'} still need Promote or Dismiss`;
export const PROMOTED_LABEL = 'Promoted';
export const DISMISSED_LABEL = 'Dismissed';
export const REOPENED_LABEL = 'Reopened (needs review again)';
export const responseActionsTaken = (n) => `Response actions taken: ${n}`;
export const READY_TO_SUBMIT = 'Ready to submit';
export const SUBMITTED_GRADE_LOCKED = 'Submitted. Grade locked.';
export const completedStrip = (total) =>
  `Reviewed ${total} of ${total} · Submitted`;
export const toReview = (n) => `${n} to review`;

// Feed/Threats explanatory subcopy (ratified OD-9), one line each.
export const FEED_SUBCOPY = 'Feed: every detection, including reviewed';
export const THREATS_SUBCOPY = 'Threats: detections you promoted';

// --- Section 8.2 canonical transition forms (consumed by the transition
// surface and any context line -- the 8.4 one-vocabulary rule) --------------
export const filterAdded = (field, value) =>
  `Filter added: ${field} == "${value}"`;
export const excludedFilter = (field, value) =>
  `Excluded: ${field} != "${value}"`;

// === Phase 2 commit 2.4: Live Progress and Reinforcement (A1-B.3) ==========
// Toast + checklist strings. Factual and observable only: an action
// executed, a detection was reviewed, a milestone was reached -- never that
// a decision was right, expected, or harmful.

// The ONE action display-label map (previously duplicated in Detections and
// ScoreSections; centralized so nothing is defined twice).
export const ACTION_LABELS = {
  isolate_host: 'Isolate Host',
  release_host: 'Release Host',
  kill_process: 'Kill Process',
  delete_file: 'Delete File',
  disable_account: 'Disable Account',
  revoke_sessions: 'Revoke Sessions',
  force_password_reset: 'Force Password Reset',
  remove_persistence: 'Remove Persistence',
};

// T4/T5 (ruled trigger list): readiness and triage-complete coincide by
// construction (readiness == every roster detection reviewed on a sealed
// roster), so ONE milestone toast carries both facts -- one announcement
// per fact.
export const allReviewedReady = (incidentId) =>
  `All detections reviewed. ${incidentId} is ready to submit.`;

// Checklist lines (A1-B.3.2). The consider-prompt is the ONE static prompt,
// byte-identical for every incident; it renders in Guided only (ruled
// B-OD-5) and never varies with hidden expectations.
export const CLASSIFICATION_NOT_SELECTED = 'Classification: not selected';
export const classificationSelected = (category) =>
  `Classification: ${category}`;
export const CONSIDER_PROMPT =
  'Consider whether containment or remediation is needed.';
export const SUBMIT_PENDING = 'Submit pending';

// === Phase 3 commit 3.1: the expanded-search transition surface ============
// The 0-events state keeps the block visible with the two designed outs
// (translated 8.2 no-results rule).
export const NO_RESULTS_OUTS =
  'No events matched. Broaden the Timeframe or return to the case evidence.';

// === Merged Phase 3/4 commit 3.2: query clarity (Amendment 2, A2-R.1) ======
// The ruled canonical finals: the four permanent tooltip sentences, the
// three-line error form (line 3 is the locked 11.3 string, reused
// verbatim), the empty-run guidance, and Restore.
export const TOOLTIP_EQ = 'Show only events matching this value.';
export const TOOLTIP_NEQ = 'Exclude events matching this value.';
export const TOOLTIP_PIVOT = 'Follow this clue across all available evidence.';
export const TOOLTIP_SURROUNDING =
  'Temporarily show activity around the selected event.';
export const NO_QUERY_ENTERED = 'No query entered.';
export const PRESERVED_RESULTS_LABEL = 'Results below are from the last run.';
export const SEARCH_NOT_RUN = 'This search was not run.';
export const QUERY_SECTION_NAMES = ['Time', 'Source', 'Event type', 'Filters'];
export const sectionCouldNotBeRead = (section) =>
  `The ${section} section could not be read.`;
export const STRUCTURE_LINE = 'The query needs four sections separated by |.';
export const RESTORE_LAST_QUERY = 'Restore last working query';

// === Merged Phase 3/4 commit 3.4: reversible surrounding events ============
// The ruled block copy (A2-R.1): temporary context with ONE clear return
// that redisplays the prior frozen results with zero requests.
export const surroundingBanner = (host) =>
  `Activity around the selected event on ${host}`;
export const OCCURRENCE_ASCENDING = 'Occurrence ascending';
export const BACK_TO_PREVIOUS_RESULTS = 'Back to previous results';

// === Phase 5 commit 5.4: Case Closed + Learning Review (A1-B.4) ============
// The payoff vocabulary: the Case Closed moment, the six ratified
// achievement labels (A1-B.4.3, frozen-record derivations only), the
// Learning Review home labels (B-OD-1 Option 1; Incident Grade vs Session
// Performance stay distinctly labelled per 3.9B), the review section
// headers (7.5 framing), and the 7.1 loading/error strings.
export const caseClosed = (incidentId) => `Case Closed: ${incidentId}`;
export const REVIEW_WHAT_YOU_LEARNED = 'Review what you learned';
export const LEARNING_REVIEW_TITLE = 'Learning Review';
export const INCIDENT_GRADE_LABEL = 'Incident Grade';
export const SESSION_PERFORMANCE_LABEL = 'Session Performance';
export const ACHIEVEMENT_LABELS = {
  case_closed: 'Case Closed',
  clean_triage: 'Clean Triage',
  response_ready: 'Response Ready',
  no_collateral: 'No Collateral',
  solo_close: 'Solo Close',
  perfect_case: 'Perfect Case',
};
export const allDetectionsReviewed = (total) =>
  `All ${total} detection${total === 1 ? '' : 's'} reviewed`;
// C1 checkpoint fix (post-Stage-5 review, F5a): every bucket heading names
// its category and every empty state names its category -- a bucket line
// must never read as a verdict on the whole incident. The well bucket
// carries BOTH ratified A1-B.4.1 item 3 halves (completed required actions
// AND correct dispositions), so its heading names both.
export const REVIEW_SECTION_CORRECT =
  'Correct detection calls and completed response actions';
export const REVIEW_SECTION_MISSED = 'Required response actions missed';
export const REVIEW_SECTION_COLLATERAL = 'Unnecessary or harmful actions';
export const REVIEW_SECTION_ACCEPTABLE = 'Additional defensible actions taken';
export const REVIEW_SECTION_ATTEMPTS = 'Attempt history';
export const REVIEW_SECTION_DETECTIONS = 'Detection calls';
export const REVIEW_SECTION_PLAYBOOK = 'Response playbook';
export const REVIEW_SECTION_TAKEAWAY = 'Key takeaway';
export const correctDetectionCalls = (n, total) =>
  `Detection calls: ${n} of ${total} correct`;
export const NO_CORRECT_CALLS = 'No detection calls were correct.';
export const NO_COMPLETED_REQUIRED =
  'No required response actions were completed.';
export const REVIEW_EMPTY_MISSED = 'No required response actions were missed.';
export const REVIEW_EMPTY_COLLATERAL =
  'No unnecessary or harmful actions were taken.';
export const REVIEW_EMPTY_DETECTIONS = 'No detection calls to review.';
export const BREAKDOWN_LOAD_ERROR = 'The detailed breakdown could not be loaded';
export const SELECT_REVIEW_INCIDENT = 'Select a submitted incident to review.';
export const NO_SUBMITTED_INCIDENTS =
  'No submitted incidents yet. Submit an incident to unlock its Learning Review.';
export const CALL_CORRECT = 'Correct';
export const CALL_WRONG = 'Wrong';

// === Amendment 3 cycle commit A3.1: the ratified A3-R.1 finals and the ===
// === standing drafted finals, landed ahead of their consumers (R7). ======

// F4b (A3-4.2): the observable line beside a disabled Submit (and the
// disabled Check Answer hint) when classification is the only step left.
export const CLASSIFY_TO_SUBMIT = 'Select a classification to submit.';

// F7 (A3-5, ruled + standing finals): simple search as a projection over
// canonical LCQL. The mode toggle labels name the mode you switch TO.
export const SIMPLE_PLACEHOLDER = 'Example: source_ip == "10.0.1.32"';
export const SIMPLE_HELP =
  'Enter a filter expression. Timeframe, source, and event type are controlled above.';
export const SIMPLE_TOGGLE = 'Simple search';
export const ADVANCED_TOGGLE = 'Advanced LCQL';
export const SOURCE_LABEL = 'Source';
export const EVENT_TYPE_LABEL = 'Event type';
export const ALL_SOURCES = 'All sources';
export const ALL_EVENT_TYPES = 'All event types';
