import React, { useState } from 'react';
import { hintsAllowed, hintsFor } from './helpContent';

// Stage 5 Phase 6 commit 6.2 (contract A1-B.5.2): the Guided-only
// "Need a hint?" flow. Allow-list gated through hintsAllowed
// (HINT_MODES = ['guided']): Hardcore, SOC Queue, and any future mode
// render NOTHING here by default. Content comes exclusively from the
// static libraries via hintsFor(surface, level) -- the binding neutrality
// rule means nothing about the active scenario can influence what shows.
// Level 1 = mechanics help; Level 2 = generic investigation nudges
// filtered by the active surface only.

const HintPanel = ({ gameMode, surface }) => {
  const [open, setOpen] = useState(false);
  const [level, setLevel] = useState(1);
  if (!hintsAllowed(gameMode)) return null;

  return (
    <div className="fixed bottom-5 left-20 lg:left-60 z-40" data-testid="hint-panel">
      {open && (
        <div className="mb-2 w-80 max-w-[85vw] bg-white border border-[#e2e6ea] rounded-xl shadow-xl overflow-hidden">
          <div className="h-0.5" style={{ background: 'linear-gradient(to right, #16436b, #101218)' }} />
          <div className="p-4">
            <div className="flex items-center justify-between gap-2">
              <p className="t-overline">
                {level === 1 ? 'How the controls work' : 'Investigation nudges'}
              </p>
              <button type="button" onClick={() => setOpen(false)} aria-label="Close hints"
                className="p-0.5 text-[#57606a] hover:text-[#1a2332]">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <ul className="mt-2 space-y-2">
              {hintsFor(surface, level).map((h, i) => (
                <li key={i} className="text-xs text-[#57606a]">{h}</li>
              ))}
            </ul>
            <div className="mt-3 flex items-center gap-2">
              <button type="button" onClick={() => setLevel(1)}
                className={`px-2 py-1 text-[11px] rounded-md border ${level === 1 ? 'bg-[#101218] text-white border-transparent' : 'border-[#d0d7de] text-[#57606a] hover:bg-[#eef1f4]'}`}>
                Mechanics
              </button>
              <button type="button" onClick={() => setLevel(2)}
                className={`px-2 py-1 text-[11px] rounded-md border ${level === 2 ? 'bg-[#101218] text-white border-transparent' : 'border-[#d0d7de] text-[#57606a] hover:bg-[#eef1f4]'}`}>
                Nudges
              </button>
            </div>
          </div>
        </div>
      )}
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        className="px-3 py-1.5 text-xs rounded-full border border-[#d0d7de] bg-white text-[#57606a] shadow-sm hover:bg-[#eef1f4]"
      >
        Need a hint?
      </button>
    </div>
  );
};

export default HintPanel;
