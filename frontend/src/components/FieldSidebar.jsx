import React from 'react';
import { computeFieldSummary } from './fieldSummary';
import { renderFieldValue } from './siemUtils';
import { TOOLTIP_EQ } from './uiCopy';

// Field sidebar (Stage 4 Phase 6.2, contract Section 10.3). Derives fields,
// top-5 values, and counts EXCLUSIVELY from the frozen snapshot's `rows`
// prop -- computeFieldSummary is a pure function of that array alone, so
// this component structurally cannot inspect the live pool or any hidden
// server state. Value clicks route only through the pivot generator
// (lcqlPivots.refineFilter, called by the parent's onValueClick).

const FieldSidebar = ({ snapshot, running, onValueClick }) => {
  if (!snapshot) {
    if (!running) return null;
    return (
      <div
        data-testid="field-sidebar-skeleton"
        className="w-full lg:w-56 shrink-0 flex flex-col gap-2 animate-pulse"
      >
        {[0, 1, 2].map((i) => (
          <div key={i} className="h-4 rounded bg-[#eef1f4]" />
        ))}
      </div>
    );
  }

  if (snapshot.count === 0) {
    return (
      <div className="w-full lg:w-56 shrink-0 text-xs text-[#6e7781] p-3">
        No fields to summarize.
      </div>
    );
  }

  const summary = computeFieldSummary(snapshot.rows);

  return (
    <div data-testid="field-sidebar" className="w-full lg:w-56 shrink-0 flex flex-col gap-3">
      {summary.map(({ field, addr, topValues }) => (
        <div key={`${addr}:${field}`}>
          <div className="text-xs font-medium text-[#1a2332] mb-1">
            {field} <span className="text-[#8b949e] font-normal">({topValues.length})</span>
          </div>
          <ul className="space-y-0.5">
            {topValues.map(({ value, count }) => (
              <li key={value}>
                <button
                  type="button"
                  onClick={() => onValueClick(field, '==', value)}
                  title={`${TOOLTIP_EQ} (${field} == "${value}")`}
                  data-help={`${TOOLTIP_EQ} (${field} == "${value}")`}
                  className="help-tip w-full flex items-center justify-between gap-2 text-xs text-[#57606a] hover:bg-[#eef1f4] px-1.5 py-0.5 rounded"
                >
                  <span className="truncate">{renderFieldValue(field, value)}</span>
                  <span className="text-[#8b949e] shrink-0">{count}</span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
};

export default FieldSidebar;
