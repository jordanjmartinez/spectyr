import React from 'react';

const CLASSIFICATIONS = [
  { id: 'true_positive', label: 'True Positive' },
  { id: 'false_positive', label: 'False Positive' },
];

// Amendment 3 F4b (ratified A3-OD-2): the workspace classification
// selector, grid-only. The modal variant is DELETED -- classification is
// an inline workspace step (ratified A1-B.3.2 source), consumed by the
// checklist line, the Ready derivation, Submit, and Guided Check Answer;
// the submit flow performs no data entry.
const ClassificationSelector = ({ onSelect, selected = null }) => (
  <div className="grid grid-cols-2 gap-2">
    {CLASSIFICATIONS.map((c) => {
      const isSel = selected === c.id;
      return (
        <button
          key={c.id}
          onClick={() => onSelect(c.id)}
          aria-pressed={isSel}
          className={`flex items-center justify-center rounded-lg border-2 transition-all duration-200 group px-3 py-2 ${
            isSel
              ? 'bg-[#eef1f4] border-[#101218]'
              : 'bg-white border-[#d0d7de] hover:bg-[#eef1f4] hover:border-[#8b949e]'}`}
        >
          <span className="text-sm font-medium text-center text-[#1a2332]">
            {c.label}
          </span>
        </button>
      );
    })}
  </div>
);

export default ClassificationSelector;
