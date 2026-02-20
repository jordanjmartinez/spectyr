import React, { useState } from 'react';

const DifficultySelector = ({ onSelect, onCancel }) => {
  const [analystName, setAnalystName] = useState('');

  const handleSelect = (mode) => {
    if (analystName.trim()) {
      onSelect(mode, analystName.trim());
    }
  };

  const isNameValid = analystName.trim().length > 0;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div
        className="absolute inset-0 bg-black/70"
        onClick={onCancel}
      />
      <div className="relative bg-[#161b22] border border-gray-700 rounded-xl p-6 w-full max-w-lg mx-4 shadow-2xl">
        <div className="text-center mb-6">
          <h3 className="text-2xl font-bold text-white mb-2">Mission Briefing</h3>
        </div>

        <div className="mb-6">
          <input
            type="text"
            value={analystName}
            onChange={(e) => setAnalystName(e.target.value)}
            placeholder="Your name"
            className="w-full px-4 py-2 text-sm font-medium rounded-md bg-[#21262d] border border-gray-600 text-gray-300 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:border-transparent transition"
          />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6 items-start">
          {/* Training Mode */}
          <button
            onClick={() => handleSelect('training')}
            disabled={!isNameValid}
            className={`group relative bg-[#21262d] border-2 rounded-xl p-4 sm:p-6 text-center transition-all duration-200 ${
              isNameValid
                ? 'border-gray-600 hover:border-gray-400 cursor-pointer'
                : 'border-gray-700 opacity-50 cursor-not-allowed'
            }`}
          >
            <div className="flex flex-col items-center mb-3">
              <h4 className="text-lg font-semibold text-white mb-2">Training</h4>
              <img src="/ghost-searching.png" alt="Training" className="w-20 h-24 sm:w-24 sm:h-28 object-contain" />
            </div>
            <ul className="space-y-2 text-sm text-gray-400">
              <li>No time pressure</li>
              <li>Learn at your pace</li>
              <li>Perfect for beginners</li>
            </ul>
          </button>

          {/* Hardcore Mode */}
          <button
            onClick={() => handleSelect('hardcore')}
            disabled={!isNameValid}
            className={`group relative bg-[#21262d] border-2 rounded-xl p-4 sm:p-6 text-center transition-all duration-200 ${
              isNameValid
                ? 'border-gray-600 hover:border-gray-400 cursor-pointer'
                : 'border-gray-700 opacity-50 cursor-not-allowed'
            }`}
          >
            <div className="flex flex-col items-center mb-3">
              <h4 className="text-lg font-semibold text-white mb-2">Hardcore</h4>
              <img src="/ghost_hacker.png" alt="Hardcore" className="w-20 h-24 sm:w-28 sm:h-28 object-contain" />
            </div>
            <ul className="space-y-2 text-sm text-gray-400">
              <li>Clock is ticking</li>
              <li>No room for error</li>
              <li>For seasoned veterans</li>
            </ul>
          </button>
        </div>

        <div className="flex justify-center">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-sm font-medium rounded-md bg-[#21262d] hover:bg-[#30363d] text-gray-300 border border-gray-600 transition"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
};

export default DifficultySelector;
