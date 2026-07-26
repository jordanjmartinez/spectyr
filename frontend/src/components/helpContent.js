// Stage 5 Phase 6 commit 6.1 (contract A1-B.5, consolidated; A2-R.1 ruled
// finals): the help-model libraries. NOT mounted by this commit.
//
// Two layers, strictly separated:
// - TOOLTIPS: permanent accessible one-line control explanations for the
//   EIGHT controls (Promote, Dismiss, Reopen, Feed/Threats, ==, !=,
//   Pivot, Expanded search; Surrounding events removed by Amendment 3
//   F3). Mode-universal under the recorded invariant-7 reading: passive,
//   player-invoked, mechanics-only, so Hardcore carries them; coaching
//   stays out of Hardcore.
// - The Guided "Need a hint?" flow: Level 1 mechanics help + Level 2
//   generic investigation nudges, allow-list gated (HINT_MODES, the
//   GUIDED_MODES pattern - Hardcore and SOC Queue excluded by default).
//
// NEUTRALITY RULE (binding, A1-B.5.2): hint availability, ordering, and
// wording depend ONLY on the visible surface and the requested level -
// never on the active scenario's answer key, expected actions, detection
// truth, grading state, or correctness. hintsFor is a pure function of
// exactly (surface, level); the structural test pins its inputs.
import {
  TOOLTIP_EQ, TOOLTIP_NEQ, TOOLTIP_PIVOT,
} from './uiCopy';

export const TOOLTIPS = {
  promote: 'Promote: mark this detection as a real threat in this incident.',
  dismiss: 'Dismiss: mark this detection as not a threat (a false alarm or expected activity).',
  reopen: 'Reopen: send this detection back for review; it will need Promote or Dismiss again.',
  eq: TOOLTIP_EQ,
  neq: TOOLTIP_NEQ,
  pivot: TOOLTIP_PIVOT,
  expanded_search: 'Search all evidence: run this query beyond the case evidence. Your case stays open, and one control returns you to it.',
};

// The GUIDED_MODES pattern: allow-list, never deny-list. A future mode is
// locked out by default, not accidentally permitted.
export const HINT_MODES = ['guided'];

export const hintsAllowed = (gameMode) => HINT_MODES.includes(gameMode);

// Level 1 - mechanics help: how the controls work, nothing about any
// scenario. Static, identical every session.
const L1_MECHANICS = [
  'Review a detection: open Detections, read it, then Promote a real threat or Dismiss a false alarm. Reopen sends it back for review.',
  'Run a query: in SIEM the bar reads Time | Source | Event type | Filters. Run Query executes it; the pinned line above the results names what you are investigating.',
  'Respond: containment and remediation run from the Response tab. Detections is for triage; Endpoints is for investigation.',
  'Submit: once every detection in the incident is reviewed, choose a classification and Submit locks in your call and grades the incident.',
];

// Level 2 - generic investigation nudges, optionally filtered by the
// ACTIVE SURFACE only. Static and scenario-independent by construction.
const L2_NUDGES = {
  incidents: [
    'Read the briefing, then open the evidence timeline to see what actually happened on the related hosts.',
    'The checklist under the briefing shows what still needs attention before Submit.',
  ],
  siem: [
    'Check which account appears across the flagged events.',
    'Pivot on a suspicious value to follow it across all available evidence.',
    'Narrow the Timeframe around the earliest suspicious event and read outward from there.',
  ],
  detections: [
    'Open a detection and read its triggering events before you make the call.',
    'Compare the process lineage in the detail view with what the rule says happened.',
  ],
  endpoints: [
    'Compare running processes and autoruns against what the detections claim is on the host.',
    'Check network connections for destinations that do not fit the host role.',
  ],
  response: [
    'Targets are grouped by type: hosts, accounts, processes, files, and persistence.',
    'The Response Log records every attempt, including actions that had no effect.',
  ],
  metrics: [
    'Grades appear after you submit an incident; its Learning Review then explains every call.',
  ],
  default: [
    'Work from the incident: its related hosts and accounts are the evidence that matters.',
  ],
};

export function hintsFor(surface, level) {
  if (level === 1) return L1_MECHANICS;
  if (level === 2) return L2_NUDGES[surface] || L2_NUDGES.default;
  return [];
}
