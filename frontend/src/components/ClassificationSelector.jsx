import React from 'react';

const CLASSIFICATIONS = [
  { id: 'true_positive', label: 'True Positive' },
  { id: 'false_positive', label: 'False Positive' },
];

// C1 checkpoint fix (post-Stage-5 review, F4a): the selector serves two
// mounts -- the original submit-flow modal (default variant, unchanged
// flow) and the ratified A1-B.3.2 workspace selector (variant="inline",
// the checklist Classification line's local-input source). `selected`
// pre-fills either mount from the player's existing workspace choice.
const OptionGrid = ({ onSelect, selected, compact }) => (
  <div className={compact ? 'grid grid-cols-2 gap-2' : 'grid grid-cols-1 sm:grid-cols-2 gap-3'}>
    {CLASSIFICATIONS.map((c) => {
      const isSel = selected === c.id;
      return (
        <button
          key={c.id}
          onClick={() => onSelect(c.id)}
          aria-pressed={isSel}
          className={`flex items-center justify-center rounded-lg border-2 transition-all duration-200 group ${
            compact ? 'px-3 py-2' : 'px-4 py-8'
          } ${isSel
            ? 'bg-[#eef1f4] border-[#101218]'
            : 'bg-white border-[#d0d7de] hover:bg-[#eef1f4] hover:border-[#8b949e]'}`}
        >
          <span className={`${compact ? 'text-sm font-medium' : 'text-lg font-semibold'} text-center text-[#1a2332]`}>
            {c.label}
          </span>
        </button>
      );
    })}
  </div>
);

const ClassificationSelector = ({ onSelect, onCancel, isHardcore, variant = 'modal', selected = null }) => {
  if (variant === 'inline') {
    return <OptionGrid onSelect={onSelect} selected={selected} compact />;
  }
  return (
    <div className="fixed inset-0 z-50 bg-black bg-opacity-70 flex items-center justify-center p-4" data-testid="classification-modal">
      <div className="relative bg-white border border-[#e2e6ea] rounded-xl shadow-2xl max-w-2xl w-full animate-modalIn">
        <button
          onClick={onCancel}
          aria-label="Close"
          className="absolute top-3 right-3 p-1 text-[#57606a] hover:text-[#1a2332] transition-colors"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
        <div className="px-6 py-4">
          <h2 className="text-xl font-semibold text-[#1a2332]">Classification</h2>
        </div>
        <div style={{ height: '1px', background: 'linear-gradient(to right, rgba(0,0,0,0.08), transparent)' }} />

        {isHardcore && (
          <div className="px-6 pt-4 flex items-center gap-3">
            <span className="inline-flex items-center justify-center w-8 h-8 rounded-md bg-[#101218] shrink-0">
              <img src="/hacker_icon.jpeg" alt="" className="w-5 h-5 object-contain" />
            </span>
            <p className="text-sm font-medium text-[#b26666]">Hardcore: one wrong call ends the run.</p>
          </div>
        )}

        <div className="p-4 sm:p-6">
          <OptionGrid onSelect={onSelect} selected={selected} />
        </div>
      </div>
    </div>
  );
};

export default ClassificationSelector;
