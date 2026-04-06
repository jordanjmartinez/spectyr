import React, { useState } from 'react';

const ATTACK_CATEGORIES = [
  {
    id: 'malware',
    label: 'Malware',
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
    )
  },
  {
    id: 'phishing',
    label: 'Phishing',
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
      </svg>
    )
  },
  {
    id: 'lateral_movement',
    label: 'Lateral Movement',
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
      </svg>
    )
  },
  {
    id: 'data_exfiltration',
    label: 'Data Exfiltration',
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
      </svg>
    )
  },
  {
    id: 'command_control',
    label: 'Command & Control',
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
      </svg>
    )
  },
  {
    id: 'insider_threat',
    label: 'Insider Threat',
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
      </svg>
    )
  },
  {
    id: 'brute_force',
    label: 'Brute Force',
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
      </svg>
    )
  },
  {
    id: 'defense_evasion',
    label: 'Defense Evasion',
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
      </svg>
    )
  },
];

const CategorySelector = ({ onSelect, onCancel, scenarioInfo }) => {
  const [selected, setSelected] = useState(null);

  return (
    <div className="fixed inset-0 z-50 bg-black bg-opacity-70 flex items-center justify-center p-4">
      <div className="bg-[#161b22] border border-gray-700 rounded-xl shadow-2xl max-w-2xl w-full">
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-700">
          <h2 className="text-xl font-semibold text-white">Select Attack Category</h2>
        </div>

        {/* Category Grid */}
        <div className="p-4 sm:p-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {ATTACK_CATEGORIES.map((category) => (
              <button
                key={category.id}
                onClick={() => setSelected(category)}
                className={`flex flex-col items-center gap-2 p-4 rounded-lg border-2 transition-all duration-200 group ${
                  selected?.id === category.id
                    ? 'border-gray-300 bg-[#21262d] shadow-[0_0_12px_rgba(209,213,219,0.15)]'
                    : 'border-gray-600 bg-[#21262d] hover:bg-[#30363d] hover:border-gray-400 hover:shadow-[0_0_10px_rgba(156,163,175,0.1)]'
                }`}
              >
                <div className={`transition-colors ${selected?.id === category.id ? 'text-white' : 'text-gray-400 group-hover:text-white'}`}>
                  {category.icon}
                </div>
                <span className={`text-sm font-medium text-center ${selected?.id === category.id ? 'text-white' : 'text-gray-300 group-hover:text-white'}`}>
                  {category.label}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 flex justify-end gap-3">
          <button
            onClick={onCancel}
            className="px-2 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm font-medium text-gray-400 hover:text-white bg-[#21262d] hover:bg-[#30363d] border border-gray-600 rounded-md transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={() => selected && onSelect(selected.id, selected.label)}
            disabled={!selected}
            className={`px-2 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm font-medium rounded-md border transition ${
              selected
                ? 'bg-[#21262d] hover:bg-[#30363d] text-gray-300 border-gray-600 cursor-pointer'
                : 'bg-[#21262d] text-gray-500 border-gray-700 opacity-50 cursor-not-allowed'
            }`}
          >
            Confirm
          </button>
        </div>
      </div>
    </div>
  );
};

export default CategorySelector;
