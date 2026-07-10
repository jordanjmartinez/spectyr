import React, { useState } from 'react';

const MODES = [
  {
    id: 'training',
    label: 'Training',
    image: '/ghost_training.PNG',
    points: ['No time pressure', 'Feedback after each call', 'Chain shown grouped'],
  },
  {
    id: 'hardcore',
    label: 'Hardcore',
    image: '/ghost_hacker.PNG',
    points: ['15:00 on the clock', 'One wrong call ends it', 'Chain shown grouped'],
  },
  {
    id: 'analyst',
    label: 'Analyst',
    image: '/ghost_analytics.PNG',
    points: ['Only the trigger fires', 'Pivot to find the chain', 'Investigate like the job'],
  },
];

const DifficultySelector = ({ onSelect, onCancel }) => {
  const [analystName, setAnalystName] = useState('');

  const isNameValid = analystName.trim().length > 0;

  const pickMode = (mode) => {
    if (isNameValid) onSelect(mode, analystName.trim());
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/70" onClick={onCancel} />
      <div className="relative bg-white border border-[#e2e6ea] rounded-xl p-6 w-full max-w-3xl mx-4 shadow-2xl animate-modalIn">
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
              className={`group relative bg-[#0f2942] border-2 rounded-xl p-4 sm:p-5 text-center transition-all duration-200 ${
                !isNameValid
                  ? 'border-transparent opacity-50 cursor-not-allowed'
                  : 'border-white/10 hover:border-white/40 hover:bg-[#16436b] cursor-pointer'
              }`}
            >
              <div className="flex flex-col items-center mb-3">
                <h4 className="text-lg font-semibold text-white mb-2">{mode.label}</h4>
                <div className="h-20 sm:h-24 flex items-center justify-center">
                  <img src={mode.image} alt={mode.label} className="w-20 h-24 sm:w-24 sm:h-28 object-contain" />
                </div>
              </div>
              <ul className="space-y-1.5 text-xs sm:text-sm text-gray-300">
                {mode.points.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};

export default DifficultySelector;
