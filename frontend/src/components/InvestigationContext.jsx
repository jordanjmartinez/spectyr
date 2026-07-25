import React from 'react';
import {
  ALL_ACTIVITY, EXPANDED_SEARCH_TITLE, followingClue,
  expandedSearchExplanation, returnToCaseEvidence,
} from './uiCopy';

// Stage 5 Phase 1 commit 1.1 (consolidated scaffold; contract Amendment 1
// Delta A, A1-A.4): the case-constant context presentation. ONE pinned case
// line ("Investigating INC-####" / "All activity") plus the expanded-search
// block rendered only while that state is live AND a case is pinned (with
// no case the SIEM is plain All activity -- A1-A.2 point 4). Pure
// presentation over props: no state, no requests, nothing derived beyond
// the strings (risk R5 by construction). NOT mounted until commit 1.2
// wires the surfaces.
//
// Props:
//   incidentId     string | null -- the pinned current case (null = no case)
//   expandedSearch null | { clue: {field, value} | null, onReturn: fn }
//                  -- live only while the SIEM expanded-search state is
//                     active; clue is null on a search-all entry
//
// The pinned line's rendered text is asserted byte-equal to the canonical
// uiCopy template (investigatingCase) by investigation-context.test.js --
// the copy module stays the single source of truth while the incident id
// carries the app's INC accent treatment.
const InvestigationContext = ({ incidentId, expandedSearch }) => (
  <div data-testid="investigation-context" className="text-xs">
    <div data-testid="pinned-case-line" className="text-[#57606a]">
      {incidentId
        ? (
          <>Investigating <span className="log-mono text-[#16436b] font-medium">{incidentId}</span></>
        )
        : ALL_ACTIVITY}
    </div>
    {expandedSearch && incidentId && (
      <div
        data-testid="expanded-search-block"
        role="status"
        className="mt-2 px-3 py-1.5 rounded-md border border-[#16436b]/30 bg-[#16436b]/5 text-[#1a2332] flex flex-wrap items-center gap-x-2 gap-y-1"
      >
        <span className="font-medium">{EXPANDED_SEARCH_TITLE}</span>
        {expandedSearch.clue && (
          <span className="log-mono">
            {followingClue(expandedSearch.clue.field, expandedSearch.clue.value)}
          </span>
        )}
        <span className="text-[#57606a]">{expandedSearchExplanation(incidentId)}</span>
        <button
          type="button"
          data-testid="return-chip"
          onClick={expandedSearch.onReturn}
          className="ml-auto text-[#16436b] hover:underline"
        >
          {returnToCaseEvidence(incidentId)}
        </button>
      </div>
    )}
  </div>
);

export default InvestigationContext;
