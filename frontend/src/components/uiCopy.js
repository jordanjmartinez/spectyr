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
export const returnSubcopy = (incidentId) =>
  `Return to ${incidentId} evidence runs this query over the case evidence again.`;

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
