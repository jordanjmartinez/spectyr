import React from 'react';
import InvestigationContext from './InvestigationContext';

// The case-constant header bar shared by Detections and Endpoints (Stage 5
// Phase 1, Amendment 1 Delta A over the M1 foundation). The pinned case line
// ("Investigating INC-####" / "All activity"), the loading and error honesty
// notices, and the row filter all render from the SAME useIncidentScope
// state, so the signals cannot disagree (the F9 defect class). There is NO
// scope toggle and NO broadening control here (ratified A-OD-2 / A-OD-3):
// a selected case is always case-scoped; recovery from a failed scope read
// is Retry, or explicitly leaving the case on Incidents.
const IncidentScopeBar = ({ scope, incidentId }) => {
  const { status, data, refetch } = scope;
  return (
    <div className="mb-3 rounded-lg border border-[#d0d7de] bg-white px-3 py-2 text-xs">
      <div className="flex items-center justify-between gap-2">
        <InvestigationContext incidentId={incidentId || null} />
        {incidentId && status === 'loading' && !data && (
          <span className="text-[#6e7781]">Loading incident scope</span>
        )}
      </div>
      {incidentId && status === 'error' && (
        <div role="alert" className="mt-2 text-[#1a2332]">
          Incident scope could not be loaded.
          {data && (
            <span className="text-[#57606a]"> Displayed rows are from the last successful scope read.</span>
          )}
          <button
            type="button"
            onClick={refetch}
            className="ml-2 px-2 py-0.5 rounded border border-[#d0d7de] bg-white text-[#1a2332]"
          >
            Retry
          </button>
        </div>
      )}
    </div>
  );
};

export default IncidentScopeBar;
