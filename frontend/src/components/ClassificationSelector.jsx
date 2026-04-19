import React from 'react';

const CLASSIFICATIONS = [
  {
    id: 'true_positive',
    label: 'True Positive',
    description: 'Confirmed threat that needs categorization',
  },
  {
    id: 'false_positive',
    label: 'False Positive',
    description: 'Benign activity, not an actual threat',
  },
];

const ClassificationSelector = ({ onSelect, onCancel }) => {
  return (
    <div className="fixed inset-0 z-50 bg-black bg-opacity-70 flex items-center justify-center p-4">
      <div className="relative bg-[#161b22] border border-gray-700 rounded-xl shadow-2xl max-w-2xl w-full animate-modalIn">
        <button
          onClick={onCancel}
          aria-label="Close"
          className="absolute top-3 right-3 p-1 text-gray-400 hover:text-white transition-colors"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
        <div className="px-6 py-4">
          <h2 className="text-xl font-semibold text-white">Classification</h2>
        </div>
        <div style={{ height: '1px', background: 'linear-gradient(to right, rgba(88,130,180,0.3), transparent)' }} />

        <div className="p-4 sm:p-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {CLASSIFICATIONS.map((c) => (
              <button
                key={c.id}
                onClick={() => onSelect(c.id)}
                className="flex flex-col items-center justify-center gap-2 px-4 py-8 rounded-lg border-2 transition-all duration-200 group border-gray-600 bg-[#21262d] hover:bg-[#30363d] hover:border-gray-400 hover:shadow-[0_0_10px_rgba(156,163,175,0.1)]"
              >
                <span className="text-lg font-semibold text-center text-gray-300 group-hover:text-white">
                  {c.label}
                </span>
                <span className="text-xs text-gray-500 text-center">{c.description}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ClassificationSelector;
