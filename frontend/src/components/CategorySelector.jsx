import React from 'react';

const ATTACK_CATEGORIES = [
  { id: 'malware', label: 'Malware' },
  { id: 'phishing', label: 'Phishing' },
  { id: 'lateral_movement', label: 'Lateral Movement' },
  { id: 'data_exfiltration', label: 'Data Exfiltration' },
  { id: 'command_control', label: 'Command & Control' },
  { id: 'insider_threat', label: 'Insider Threat' },
  { id: 'brute_force', label: 'Brute Force' },
  { id: 'defense_evasion', label: 'Defense Evasion' },
];

const CategorySelector = ({ onSelect, onCancel, scenarioInfo }) => {
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
        {/* Header */}
        <div className="px-6 py-4">
          <h2 className="text-xl font-semibold text-white">Select Attack Category</h2>
        </div>
        <div style={{ height: '1px', background: 'linear-gradient(to right, rgba(240,246,252,0.1), transparent)' }} />

        {/* Category Grid */}
        <div className="p-4 sm:p-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {ATTACK_CATEGORIES.map((category) => (
              <button
                key={category.id}
                onClick={() => onSelect(category.id, category.label)}
                className="flex items-center justify-center h-20 px-3 rounded-lg border-2 transition-all duration-200 group border-gray-600 bg-[#0d1117] hover:bg-[#30363d] hover:border-[#8b949e]"
              >
                <span className="text-sm font-medium text-center text-gray-300 group-hover:text-white">
                  {category.label}
                </span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default CategorySelector;
