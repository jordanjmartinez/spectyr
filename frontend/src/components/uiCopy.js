// Stage 5 Phase 1 commit 1.1 (consolidated scaffold; contract Amendment 1
// Delta A, ratified A-OD-1 naming finals). The ONE canonical player-facing
// copy module: seeded here with the case-constant context strings and the
// 11.3 honesty notes. The R7 rule applies: strings land as constants BEFORE
// any surface consumes them, and this module is completed as the full
// Section 10.1 vocabulary in Phase 2 commit 2.1 -- nothing is ever defined
// twice. Player-facing strings only; the copy-emdash scan covers this file
// the moment it lands.

// --- the pinned case line (contract A1-A.4 item 1) -------------------------
// VA1 (amendment): the "Investigating INC-####" body line and the
// "All activity" scope container are RETIRED. Active-incident context
// renders exactly once per page as the compact IncidentPill beside the
// functional subtitle; with no active incident each page uses its own
// truthful empty state. (The constants remain exported only because the
// retired-copy scan asserts they no longer render.)
export const investigatingCase = (incidentId) => `Investigating ${incidentId}`;
export const ALL_ACTIVITY = 'All activity';

// The functional page subtitles (amendment section 2): what the page is
// FOR. Decorative organization branding never appears here -- org names
// belong to evidence, entities, and scenario content.
// (Owner UI pass 2026-10-12: PAGE_SUBTITLE retired -- the per-tab
// functional summary line under the header title is removed everywhere;
// the title stands alone. page-intro.test.js keeps the retired strings
// as negative probes so no page resurrects them.)

// (Final pass III.0 item 2: the SIEM state pair and the expanded-search
// block copy -- caseEvidenceLabel, SEARCH_ALL_EVIDENCE,
// EXPANDED_SEARCH_TITLE, expandedSearchExplanation, returnToCaseEvidence,
// RETURN_SUBCOPY, NO_RESULTS_OUTS -- retired with the expanded-search
// state itself. followingClue lives on below as the pivot announcement.)

// --- the search-state labels (Final pass III.0 item 3; supersede the 11.2
// "Results from" echo and the 11.3 note wordings with the ruled finals) -----
// An executed search is identified by its READABLE filter expression
// ("Results for: X"), the canonical staying visible as the technical
// disclosure; evidence the player did not author is never labeled a player
// query ("Initial incident evidence"; a caseless prepared entry reads
// "Initial evidence" -- the flagged minimal variant, see the Part III
// ledger). The edited / failed / hidden-selection notes are the ruled
// sentences verbatim.
export const resultsFor = (readable) => `Results for: ${readable}`;
export const ALL_EVENTS_LABEL = 'all events';
export const INITIAL_INCIDENT_EVIDENCE = 'Initial Incident Evidence';
export const INITIAL_EVIDENCE = 'Initial Evidence';
// (EDITED_NOTE retired with the editable bar, owner follow-up 2026-10-13.)
export const STALE_RESULTS_NOTE =
  'Showing results from the previous successful search.';
export const SELECTED_EVENT_HIDDEN =
  'The selected event is hidden by the current results. Change the filters or select another event.';

// --- the new-events action (Final pass III.0 item 4; replaces the generic
// Refresh label). The token-bound new-count poll is the ONE authority: the
// count line and the action render together only while it reports new
// events; the snapshot stays stable until the action is invoked.
export const newEventsAvailable = (n) =>
  `${n} New Event${n === 1 ? '' : 's'} Available`;
export const LOAD_NEW_EVENTS = 'Load New Events';

// === Phase 2 commit 2.1: the complete Section 10.1 canonical vocabulary ===
// (locked contract 10.1/10.2; consolidated scaffold). Observable-only; the
// forbidden class (correctness phrasing, answer-key totals) never appears
// pre-submission -- progress-vocabulary.test.js scans every string below.

// Visual pass V3: the ONE mode display-label map (previously local to
// IncidentDashboard; the shell utility region is a second consumer).
// "training" is the legacy Guided alias; "analyst" backs SOC Queue.
export const MODE_LABEL = { training: 'Guided', guided: 'Guided', analyst: 'SOC Queue', hardcore: 'Hardcore' };

export const TELEMETRY_LOADING = 'Incident telemetry is still loading.';
export const detectionsReviewed = (triaged, total) =>
  `Detections Reviewed: ${triaged} of ${total}`;
export const detectionsRemaining = (n) =>
  `${n} detection${n === 1 ? '' : 's'} still need Promote or Dismiss`;
export const PROMOTED_LABEL = 'Promoted';
export const DISMISSED_LABEL = 'Dismissed';
export const REOPENED_LABEL = 'Reopened (needs review again)';
export const responseActionsTaken = (n) => `Response Actions Taken: ${n}`;
export const READY_TO_SUBMIT = 'Ready to Submit';
export const SUBMITTED_GRADE_LOCKED = 'Submitted. Grade locked.';
export const completedStrip = (total) =>
  `Reviewed ${total} of ${total} · Submitted`;
export const toReview = (n) => `${n} to Review`;

// (Owner UI pass 2026-10-12: the OD-9 Feed/Threats explanatory subcopy
// pair is retired -- the Feed line was removed from Detections and the
// Threats line had no remaining render site.)

// --- Section 8.2 canonical clue forms (the 8.4 one-vocabulary rule; the
// ONE notice line announces refines and pivots alike, III.0 item 2) ---------
export const followingClue = (field, value) =>
  `Following clue: ${field} = "${value}"`;
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
export const CLASSIFICATION_NOT_SELECTED = 'Classification: Not Selected';
export const classificationSelected = (category) =>
  `Classification: ${category}`;
export const CONSIDER_PROMPT =
  'Consider whether containment or remediation is needed.';
export const SUBMIT_PENDING = 'Submit Pending';

// === Merged Phase 3/4 commit 3.2: query clarity (Amendment 2, A2-R.1),
// trimmed by the owner follow-up pass (2026-10-13): the LCQL bar and its
// error apparatus retired with Advanced mode; the tooltip finals and the
// not-run / stale sentences live on.
export const TOOLTIP_EQ = 'Show only events matching this value.';
export const TOOLTIP_NEQ = 'Exclude events matching this value.';
// Final pass III.0 item 2 (flagged consequential change to an A2 final): a
// pivot no longer broadens to all evidence, so the ruled sentence's "across
// all available evidence" became untrue; the verb sentence follows the
// truth (the pivot searches the evidence pool you are already in).
export const TOOLTIP_PIVOT = 'Follow this clue across the evidence you are searching.';
export const SEARCH_NOT_RUN = 'This search was not run.';

// (The reversible-surrounding-events block copy was removed with the
// control by Amendment 3 F3; the F2 model B hold-and-restore mechanic that
// briefly survived it retired with Expanded search, Final pass III.0
// item 2.)

// === Phase 5 commit 5.4: Case Closed + Learning Review (A1-B.4) ============
// The payoff vocabulary: the Case Closed moment, the six ratified
// achievement labels (A1-B.4.3, frozen-record derivations only), the
// Learning Review home labels (B-OD-1 Option 1; Incident Grade vs Session
// Performance stay distinctly labelled per 3.9B), the review section
// headers (7.5 framing), and the 7.1 loading/error strings.
export const caseClosed = (incidentId) => `Case Closed: ${incidentId}`;
export const REVIEW_WHAT_YOU_LEARNED = 'Review What You Learned';
export const LEARNING_REVIEW_TITLE = 'Learning Review';
export const INCIDENT_GRADE_LABEL = 'Incident Grade';
// VT (owner correction): sentence case for visible section labels; the
// Incident Grade vs Session performance DISTINCTION is unchanged.
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
  'Correct Detection Calls and Completed Response Actions';
export const REVIEW_SECTION_MISSED = 'Required Response Actions Missed';
export const REVIEW_SECTION_COLLATERAL = 'Unnecessary or Harmful Actions';
export const REVIEW_SECTION_ACCEPTABLE = 'Additional Defensible Actions Taken';
export const REVIEW_SECTION_ATTEMPTS = 'Attempt History';
export const REVIEW_SECTION_DETECTIONS = 'Detection Calls';
export const REVIEW_SECTION_PLAYBOOK = 'Response Playbook';
export const REVIEW_SECTION_TAKEAWAY = 'Key Takeaway';
export const correctDetectionCalls = (n, total) =>
  `Detection Calls: ${n} of ${total} Correct`;
export const NO_CORRECT_CALLS = 'No detection calls were correct.';
export const NO_COMPLETED_REQUIRED =
  'No required response actions were completed.';
export const REVIEW_EMPTY_MISSED = 'No required response actions were missed.';
export const REVIEW_EMPTY_COLLATERAL =
  'No unnecessary or harmful actions were taken.';
export const REVIEW_EMPTY_DETECTIONS = 'No detection calls to review.';
// Stage 6 (A4): the post-submit expected-response disclosure.
export const REVIEW_SECTION_EXPECTED = 'Expected Response Actions';
export const REVIEW_EMPTY_EXPECTED =
  'No response actions were expected for this incident.';
export const EXPECTED_REQUIRED_LABEL = 'Required';
export const EXPECTED_ACCEPTABLE_LABEL = 'Acceptable';
export const INACTION_ZERO_HEADING = 'Why the Response Score Is Zero';
export const BREAKDOWN_LOAD_ERROR = 'The detailed breakdown could not be loaded';
export const SELECT_REVIEW_INCIDENT = 'Select a submitted incident to review.';
export const NO_SUBMITTED_INCIDENTS =
  'No submitted incidents yet. Submit an incident to unlock its Learning Review.';
export const CALL_CORRECT = 'Correct';
export const CALL_WRONG = 'Wrong';

// === Amendment 3 cycle commit A3.1: the ratified A3-R.1 finals and the ===
// === standing drafted finals, landed ahead of their consumers (R7). ======

// F4b (A3-4.2), re-targeted by the owner Incidents-panel pass (2026-10-12):
// Submit stays ENABLED; these are the inline group errors shown when an
// incomplete Submit scrolls to the first missing group.
export const CLASSIFY_TO_SUBMIT = 'Select a classification to submit.';
export const SELECT_CATEGORY = 'Select a category to submit.';
// Owner footer refinement (2026-10-13): the ONE footer readiness item is
// the requirement NOT visible in the panel -- detections triage.
export const detectionsQueueItem = (n) => `Detections: ${n} to Triage`;
export const DETECTIONS_TRIAGED = 'Detections Triaged';

// Owner SIEM simplification pass (2026-10-13): ONE filter system. The F7
// simple-search projection (its placeholder, the Source / Event Type
// selects and their copy) is retired -- those dimensions are facet groups
// now. The follow-up pass the same day retired Advanced LCQL entirely:
// the one simple search box below is the only typed entry, and everything
// it parses becomes filter chips.
export const FILTERS_TOGGLE = 'Filters';

// --- the facet rail (the ONE filter system) --------------------------------
export const MORE_FILTERS = 'More Filters';
export const SHOW_MORE_VALUES = 'Show More';
export const SHOW_FEWER_VALUES = 'Show Fewer';
export const NO_GROUP_VALUES = 'No values in these results.';
export const TOO_MANY_FILTERS =
  'Too many combined filters for one search. Remove a filter and try again.';
export const SHOW_EVENTS = 'Show Events';
export const FILTERS_EMPTY_HINT =
  'Pick a timeframe and show events, then narrow them with the filters beside the results.';
export const INCIDENT_WINDOW_LABEL = 'Incident Window';
export const ALL_TIME_LABEL = 'All Time';

// --- the one simple search box (owner follow-up pass, 2026-10-13) ----------
export const SEARCH_PLACEHOLDER = 'Search events...';
export const SEARCH_BUTTON = 'Search';
export const searchUnknownField = (name) =>
  `No filter field called "${name}". Try: Computer, User Account, Source IP, `
  + 'Destination IP, Severity, Event, Log Source, Process, Command, File, or URL.';
export const SEARCH_IP_CONTAINS =
  'Use Source IP or Destination IP with contains.';

// --- the entity action menu (inspector) -------------------------------------
export const FILTER_TO_THIS = 'Filter to Just This';
export const FILTER_OUT_THIS = 'Filter This Out';
export const PIVOT_SEE_ALL = 'Pivot: See Everything About This';
export const COPY_VALUE = 'Copy';
export const OPEN_IN_ENDPOINTS = 'Open in Endpoints';

// --- the two-tier inspector ---------------------------------------------------
export const KEY_FACTS_LABEL = 'Key Facts';
export const ALL_FIELDS_TOGGLE = 'All Fields';

// === Final pass (Part III.0.1): the Response workspace ====================
// The ruled state copy (never revealing whether inaction is correct) and
// the neutral navigation labels (they select a target in Response and
// execute nothing).
export const RESPONSE_SELECT_INCIDENT = 'Select an incident to begin response.';
export const RESPONSE_NO_PROMOTED = 'No detections have been promoted.';
export const RESPONSE_NO_PROMOTED_SUB =
  'You can still review incident entities and actions below.';
export const RESPONSE_NO_TARGETS = 'No response targets are currently available.';
export const RESPONSE_NO_ACTIONS = 'No response actions taken.';
export const OPEN_IN_RESPONSE = 'Open in Response';
export const RESPOND_TO_HOST = 'Respond to This Host';
export const RESPOND_ROW = 'Respond';
