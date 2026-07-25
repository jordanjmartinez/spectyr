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
