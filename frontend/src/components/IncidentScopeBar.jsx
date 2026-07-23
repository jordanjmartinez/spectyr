import React from 'react';

// Scope bar shared by Detections and Endpoints (pre-lock micro-fix M1,
// Stage 5A contract Section 11.1). The label, the toggle's selected state
// (visual + aria-pressed), and the error/loading notices all render from the
// SAME useIncidentScope state the row filter consumes, so the three signals
// cannot disagree (the F9 defect class). Broadening to Session-wide happens
// only through the explicit controls here.
const IncidentScopeBar = ({ scope, incidentId, groupLabel }) => {
  const { mode, selection, setSelection, status, data, refetch } = scope;
  const scoped = selection === 'incident';
  const label = mode === 'session'
    ? <>Session-wide view</>
    : data
      ? <>Scoped to incident <span className="log-mono text-[#16436b]">{incidentId}</span></>
      : status === 'error'
        ? <>Incident scope could not be loaded.</>
        : <>Loading incident scope</>;
  return (
    <div className="mb-3 rounded-lg border border-[#d0d7de] bg-white px-3 py-2 text-xs">
      <div className="flex items-center justify-between">
        <span className="text-[#57606a]">{label}</span>
        <div className="inline-flex rounded-md border border-[#d0d7de] overflow-hidden" role="group" aria-label={groupLabel}>
          <button type="button" aria-pressed={scoped} onClick={() => setSelection('incident')}
            className={`px-2.5 py-1 font-medium transition ${scoped ? 'bg-[#101218] text-white' : 'bg-white text-[#57606a] hover:bg-[#eef1f4]'}`}>
            This incident
          </button>
          <button type="button" aria-pressed={!scoped} onClick={() => setSelection('session')}
            className={`px-2.5 py-1 font-medium transition ${!scoped ? 'bg-[#101218] text-white' : 'bg-white text-[#57606a] hover:bg-[#eef1f4]'}`}>
            Session-wide
          </button>
        </div>
      </div>
      {mode === 'incident' && status === 'error' && (
        <div role="alert" className="mt-2 text-[#1a2332]">
          {data
            ? <>Incident scope could not be loaded. <span className="text-[#57606a]">Displayed rows are from the last successful scope read.</span></>
            : null}
          <button type="button" onClick={refetch}
            className={`px-2 py-0.5 rounded border border-[#d0d7de] bg-white text-[#1a2332] ${data ? 'ml-2' : ''}`}>
            Retry
          </button>
          <button type="button" onClick={() => setSelection('session')}
            className="ml-2 px-2 py-0.5 rounded border border-[#d0d7de] bg-white text-[#57606a]">
            Use Session-wide
          </button>
        </div>
      )}
    </div>
  );
};

export default IncidentScopeBar;
