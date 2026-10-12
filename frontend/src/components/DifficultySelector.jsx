import React, { useState, useEffect } from 'react';
import { apiFetch } from '../api';
import { SeverityBadge } from './ui';
import { ChromeIcons, NAV_ICONS, NAV_STROKE } from './icons';

// VA2 (amendment section 4): the mode chooser. Two experiences only --
// Guided and Hardcore. SOC Queue is removed from the player-facing
// product; the engine's dormant "analyst" mode is NOT deleted (the
// frozen backend batteries exercise it as a mode-universal path) and no
// UI can reach it.
//
// The analyst-name input is gone with the invented identity it invited.
// A session still needs a name field server-side (it is what marks a
// session active), so the product supplies its own generic role label,
// ANALYST_LABEL -- a role, never a fabricated person.
export const ANALYST_LABEL = 'Analyst';

const MODES = [
  {
    id: 'guided',
    label: 'Guided',
    Icon: ChromeIcons.BookOpen,
    lines: ['Learn with immediate feedback and optional hints.', 'No timer.'],
  },
  {
    id: 'hardcore',
    label: 'Hardcore',
    Icon: NAV_ICONS.response,
    lines: ['Investigate independently under time pressure.',
            'Feedback appears after submission.'],
  },
];

const DifficultySelector = ({ onSelect, onCancel, initialName = '', initialStep = 'mode' }) => {
  const [step, setStep] = useState(initialStep);     // 'mode' | 'catalog'
  const [mode, setMode] = useState('guided');        // the selected experience
  const [catalog, setCatalog] = useState(null);      // null while loading

  const loadCatalog = () => {
    setCatalog(null);
    apiFetch('/api/guided-catalog')
      .then((r) => r.json())
      .then((d) => setCatalog(d.catalog || []))
      .catch(() => setCatalog([]));
  };

  // Practice Another opens straight at the answer-neutral Guided catalog.
  useEffect(() => { if (initialStep === 'catalog') loadCatalog(); }, [initialStep]);

  const analyst = (initialName && initialName.trim()) || ANALYST_LABEL;
  const cont = () => {
    if (mode === 'guided') { setStep('catalog'); loadCatalog(); }
    else onSelect(mode, analyst);
  };
  const pickScenario = (catalogId) => onSelect('guided', analyst, catalogId);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/70" onClick={onCancel} />
      <div
        role="dialog"
        aria-modal="true"
        aria-label={step === 'mode' ? 'Choose Your Experience' : 'Choose a Scenario'}
        className="relative bg-white border border-[#e2e6ea] rounded-xl p-6 w-full max-w-lg mx-4 shadow-2xl animate-modalIn max-h-[90vh] overflow-y-auto"
      >
        <button
          type="button"
          onClick={onCancel}
          aria-label="Close"
          className="absolute top-3 right-3 p-1 text-muted hover:text-[#1a2332] transition-colors"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>

        {step === 'mode' ? (
          <>
            {/* Owner UI pass (2026-10-12): subtitle removed -- title +
                the two mode rows (which carry their own descriptions). */}
            <h3 className="t-section pr-8 mb-4">Choose Your Experience</h3>

            <div role="radiogroup" aria-label="Experience" className="space-y-2">
              {MODES.map((m) => {
                const selected = mode === m.id;
                const Icon = m.Icon;
                return (
                  <button
                    key={m.id}
                    type="button"
                    role="radio"
                    aria-checked={selected}
                    onClick={() => setMode(m.id)}
                    className={`w-full text-left flex items-start gap-3 rounded-lg border p-3 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[#16436b]/40 ${
                      selected
                        ? 'border-[#101218] bg-[#f6f8fa]'
                        : 'border-[#d0d7de] bg-white hover:bg-[#f6f8fa]'
                    }`}
                  >
                    <span
                      aria-hidden="true"
                      className={`mt-0.5 w-4 h-4 rounded-full border-[5px] shrink-0 ${
                        selected ? 'border-[#101218]' : 'border-[#d0d7de]'
                      }`}
                    />
                    <span className="min-w-0">
                      <span className="flex items-center gap-1.5">
                        <Icon size={15} strokeWidth={NAV_STROKE} aria-hidden="true" className="text-muted" />
                        <span className="t-subsection">{m.label}</span>
                      </span>
                      {m.lines.map((l) => (
                        <span key={l} className="block text-sm text-muted">{l}</span>
                      ))}
                    </span>
                  </button>
                );
              })}
            </div>

            <div className="mt-5 flex justify-end">
              <button
                type="button"
                onClick={cont}
                className="px-4 py-2 text-sm font-medium rounded-md bg-[#101218] text-white hover:bg-[#1e2330] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#16436b]/40"
              >
                Continue
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="flex items-center gap-3 mb-4 pr-8">
              <button type="button" onClick={() => setStep('mode')} className="text-sm text-[#16436b] hover:underline">Back</button>
              <h3 className="t-section">Choose a Scenario</h3>
            </div>

            <button
              type="button"
              onClick={() => pickScenario('random')}
              className="w-full text-left p-3 mb-3 rounded-lg border border-[#d0d7de] hover:bg-[#f6f8fa] transition-colors"
            >
              <span className="t-subsection block">Random Scenario</span>
              <span className="text-xs text-muted block mt-0.5">Start a randomly chosen incident from the catalog.</span>
            </button>

            {catalog === null ? (
              <p className="text-sm text-muted text-center py-6">Loading scenarios...</p>
            ) : catalog.length === 0 ? (
              <p className="text-sm text-muted text-center py-6">No scenarios available.</p>
            ) : (
              <div className="space-y-2">
                {/* Stage 6 catalog cut: a missing playable flag means
                    playable (backward-compatible); shelved entries are
                    summarized by the coming-soon line below. */}
                {catalog.filter((e) => e.playable !== false).map((e) => (
                  <button
                    key={e.catalog_id}
                    type="button"
                    onClick={() => pickScenario(e.catalog_id)}
                    className="w-full text-left p-3 rounded-lg border border-[#d0d7de] hover:bg-[#f6f8fa] transition-colors"
                  >
                    <span className="flex items-center gap-2 flex-wrap">
                      <span className="t-subsection">{e.title}</span>
                      <SeverityBadge severity={e.severity} />
                    </span>
                    <span className="text-xs text-muted block mt-1">{e.description}</span>
                  </button>
                ))}
                {/* Owner UI pass (2026-10-12): the greyed-out shelved rows
                    are deleted; the coming-soon line stays alone, in the
                    title font, as the honest forward signal. */}
                {catalog.some((e) => e.playable === false) && (
                  <div className="pt-3 mt-3 border-t border-[#eef1f4]" data-testid="coming-soon">
                    <p className="t-subsection">More Scenarios Coming Soon</p>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default DifficultySelector;
