import React, { useState, useEffect } from 'react';
import { apiFetch } from '../api';

// Stage 3.9B Step 3: the three final modes. Guided (from the training engine)
// opens the answer-neutral catalog picker and starts a single chosen incident;
// SOC Queue (analyst engine) and Hardcore push the sampled queue. The picker
// shows only title / severity / neutral description (difficulty is intentionally
// not presented this stage).
const MODES = [
  {
    id: 'guided',
    label: 'Guided',
    image: '/ghost_training.PNG',
    points: ['Learn the workflow', 'Pick one scenario. Unlimited time, Check Answer available.'],
  },
  {
    id: 'analyst',
    label: 'SOC Queue',
    image: '/ghost_analytics.png',
    points: ['Triggered evidence arrival', 'A queue pushes in; only the trigger shows first.'],
  },
  {
    id: 'hardcore',
    label: 'Hardcore',
    image: '/ghost_hacker.png',
    points: ['Beat the clock', 'Clear the queue without a mistake.'],
  },
];

const SEV_DOT = { Critical: '#b45858', High: '#c08a3e', Medium: '#c0a93e', Low: '#6fa868' };

const DifficultySelector = ({ onSelect, onCancel, initialName = '', initialStep = 'mode' }) => {
  const [analystName, setAnalystName] = useState(initialName);
  const [step, setStep] = useState(initialStep);     // 'mode' | 'catalog'
  const [catalog, setCatalog] = useState(null);       // null while loading

  const isNameValid = analystName.trim().length > 0;

  const loadCatalog = () => {
    setCatalog(null);
    apiFetch('/api/guided-catalog')
      .then((r) => r.json())
      .then((d) => setCatalog(d.catalog || []))
      .catch(() => setCatalog([]));
  };

  // Practice Another opens straight at the answer-neutral Guided catalog.
  useEffect(() => { if (initialStep === 'catalog') loadCatalog(); }, [initialStep]);

  const pickMode = (mode) => {
    if (!isNameValid) return;
    if (mode === 'guided') { setStep('catalog'); loadCatalog(); }
    else onSelect(mode, analystName.trim());
  };

  const pickScenario = (catalogId) => onSelect('guided', analystName.trim(), catalogId);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/70" onClick={onCancel} />
      <div className="relative bg-white border border-[#e2e6ea] rounded-xl p-6 w-full max-w-3xl mx-4 shadow-2xl animate-modalIn max-h-[90vh] overflow-y-auto">
        <button
          type="button"
          onClick={onCancel}
          aria-label="Close"
          className="absolute top-3 right-3 p-1 text-[#57606a] hover:text-[#1a2332] transition-colors"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>

        {step === 'mode' ? (
          <>
            <h3 className="text-lg font-semibold text-[#1a2332] mb-4 pr-8">Select Mode</h3>
            <div className="mb-5" style={{ height: '1px', background: 'linear-gradient(to right, rgba(0,0,0,0.08), transparent)' }} />

            <div className="mb-6">
              <input
                type="text"
                value={analystName}
                onChange={(e) => setAnalystName(e.target.value)}
                placeholder="Your Name"
                maxLength={12}
                className="w-full px-4 py-2 rounded-md bg-white border border-[#d0d7de] text-[#1a2332] text-sm placeholder-[#8b949e] focus:border-[#8b949e] focus:outline-none transition-colors"
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 items-stretch">
              {MODES.map((mode) => (
                <button
                  key={mode.id}
                  onClick={() => pickMode(mode.id)}
                  disabled={!isNameValid}
                  className={`group relative bg-[#101218] border-2 rounded-xl p-4 sm:p-5 text-center transition-all duration-200 ${
                    !isNameValid
                      ? 'border-transparent opacity-50 cursor-not-allowed'
                      : 'border-white/10 hover:border-white/40 hover:bg-[#1e2330] cursor-pointer'
                  }`}
                >
                  <div className="flex flex-col items-center mb-3">
                    <h4 className="text-lg font-semibold text-white mb-2">{mode.label}</h4>
                    <div className="h-20 sm:h-24 flex items-center justify-center">
                      <img src={mode.image} alt={mode.label} className="w-20 h-24 sm:w-24 sm:h-28 object-contain" />
                    </div>
                  </div>
                  <ul className="space-y-1.5 text-xs sm:text-sm text-gray-300">
                    {mode.points.map((p, i) => (
                      <li key={p} className={i === 0 ? 'font-medium text-gray-100' : ''}>{p}</li>
                    ))}
                  </ul>
                </button>
              ))}
            </div>
          </>
        ) : (
          <>
            <div className="flex items-center gap-3 mb-4 pr-8">
              <button type="button" onClick={() => setStep('mode')} className="text-sm text-[#16436b] hover:underline">Back</button>
              <h3 className="text-lg font-semibold text-[#1a2332]">Choose a scenario</h3>
            </div>
            <div className="mb-4" style={{ height: '1px', background: 'linear-gradient(to right, rgba(0,0,0,0.08), transparent)' }} />

            <button
              type="button"
              onClick={() => pickScenario('random')}
              className="w-full text-left p-3 mb-3 rounded-lg border border-[#d0d7de] hover:bg-[#f6f8fa] transition-colors"
            >
              <span className="text-sm font-medium text-[#1a2332]">Random scenario</span>
              <span className="text-xs text-[#8b949e] block mt-0.5">Start a randomly chosen incident from the catalog.</span>
            </button>

            {catalog === null ? (
              <p className="text-sm text-[#8b949e] text-center py-6">Loading scenarios...</p>
            ) : catalog.length === 0 ? (
              <p className="text-sm text-[#8b949e] text-center py-6">No scenarios available.</p>
            ) : (
              <div className="space-y-2">
                {catalog.map((e) => (
                  <button
                    key={e.catalog_id}
                    type="button"
                    onClick={() => pickScenario(e.catalog_id)}
                    className="w-full text-left p-3 rounded-lg border border-[#d0d7de] hover:bg-[#f6f8fa] transition-colors"
                  >
                    <span className="flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: SEV_DOT[e.severity] || '#8b949e' }} />
                      <span className="text-sm font-medium text-[#1a2332]">{e.title}</span>
                      <span className="text-[11px] text-[#8b949e]">{e.severity}</span>
                    </span>
                    <span className="text-xs text-[#57606a] block mt-1">{e.description}</span>
                  </button>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default DifficultySelector;
