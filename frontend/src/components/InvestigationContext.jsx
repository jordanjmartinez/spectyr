import React from 'react';
import { ALL_ACTIVITY } from './uiCopy';

// Stage 5 Phase 1 commit 1.1 (contract Amendment 1 Delta A, A1-A.4),
// simplified by the Final pass (III.0 item 2): the case-constant context is
// ONE pinned case line ("Investigating INC-####" / "All activity"). The
// expanded-search block, its clue line, and the return action left with the
// expanded-search state itself -- with a case the SIEM always searches that
// case's evidence, so there is no second state to announce. Pure
// presentation over props: no state, no requests, nothing derived beyond
// the strings (risk R5 by construction).
//
// The pinned line's rendered text is asserted byte-equal to the canonical
// uiCopy template (investigatingCase) by investigation-context.test.js --
// the copy module stays the single source of truth while the incident id
// carries the app's INC accent treatment.
const InvestigationContext = ({ incidentId }) => (
  <div data-testid="investigation-context" className="text-xs">
    <div data-testid="pinned-case-line" className="text-[#57606a]">
      {incidentId
        ? (
          <>Investigating <span className="log-mono text-[#16436b] font-medium">{incidentId}</span></>
        )
        : ALL_ACTIVITY}
    </div>
  </div>
);

export default InvestigationContext;
