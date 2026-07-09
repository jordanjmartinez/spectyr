import React, { useState } from 'react';

const DifficultySelector = ({ onSelect, onCancel }) => {
  const [analystName, setAnalystName] = useState('');

  const isNameValid = analystName.trim().length > 0;

  const pickMode = (mode) => {
    if (isNameValid) onSelect(mode, analystName.trim());
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div
        className="absolute inset-0 bg-black/70"
        onClick={onCancel}
      />
      <div className="relative bg-[#161b22] border border-gray-700 rounded-xl p-6 w-full max-w-3xl mx-4 shadow-2xl animate-modalIn">
        <button
          type="button"
          onClick={onCancel}
          aria-label="Close"
          className="absolute top-3 right-3 p-1 text-gray-400 hover:text-white transition-colors"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
        <h3 className="text-lg font-semibold text-white mb-4 pr-8">Select Mode</h3>
        <div className="mb-5" style={{ height: '1px', background: 'linear-gradient(to right, rgba(88,130,180,0.3), transparent)' }} />

        <div className="mb-6">
          <input
            type="text"
            value={analystName}
            onChange={(e) => setAnalystName(e.target.value)}
            placeholder="Your Name"
            maxLength={12}
            className="w-full px-4 py-2 rounded-md bg-[#0d1117] border border-gray-700 text-white text-sm placeholder-gray-400 focus:border-[#5882b4] focus:outline-none transition-colors"
          />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 items-stretch">
          {/* Training Mode */}
          <button
            onClick={() => pickMode('training')}
            disabled={!isNameValid}
            className={`group relative bg-[#0d1117] border-2 rounded-xl p-4 sm:p-5 text-center transition-all duration-200 ${
              !isNameValid
                ? 'border-gray-700 opacity-50 cursor-not-allowed'
                : 'border-gray-600 hover:border-[#5882b4] cursor-pointer'
            }`}
          >
            <div className="flex flex-col items-center mb-3">
              <h4 className="text-lg font-semibold text-white mb-2">Training</h4>
              <div className="h-20 sm:h-24 flex items-center justify-center">
                <img src="/ghost_training.PNG" alt="Training" className="w-20 h-24 sm:w-24 sm:h-28 object-contain" />
              </div>
            </div>
            <ul className="space-y-1.5 text-xs sm:text-sm text-gray-400">
              <li>No time pressure</li>
              <li>Feedback after each call</li>
              <li>Chain shown grouped</li>
            </ul>
          </button>

          {/* Hardcore Mode */}
          <button
            onClick={() => pickMode('hardcore')}
            disabled={!isNameValid}
            className={`group relative bg-[#0d1117] border-2 rounded-xl p-4 sm:p-5 text-center transition-all duration-200 ${
              !isNameValid
                ? 'border-gray-700 opacity-50 cursor-not-allowed'
                : 'border-gray-600 hover:border-[#5882b4] cursor-pointer'
            }`}
          >
            <div className="flex flex-col items-center mb-3">
              <h4 className="text-lg font-semibold text-white mb-2">Hardcore</h4>
              <div className="h-20 sm:h-24 flex items-center justify-center">
                <img src="/ghost_hacker.png" alt="Hardcore" className="w-20 h-24 sm:w-24 sm:h-28 object-contain" />
              </div>
            </div>
            <ul className="space-y-1.5 text-xs sm:text-sm text-gray-400">
              <li>15:00 on the clock</li>
              <li>One wrong call ends it</li>
              <li>Chain shown grouped</li>
            </ul>
          </button>

          {/* Analyst Mode */}
          <button
            onClick={() => pickMode('analyst')}
            disabled={!isNameValid}
            className={`group relative bg-[#0d1117] border-2 rounded-xl p-4 sm:p-5 text-center transition-all duration-200 ${
              !isNameValid
                ? 'border-gray-700 opacity-50 cursor-not-allowed'
                : 'border-gray-600 hover:border-[#5882b4] cursor-pointer'
            }`}
          >
            <div className="flex flex-col items-center mb-3">
              <h4 className="text-lg font-semibold text-white mb-2">Analyst</h4>
              <div className="h-20 sm:h-24 flex items-center justify-center">
                <img src="/ghost_hacker.PNG" alt="Analyst" className="w-20 h-24 sm:w-24 sm:h-28 object-contain" />
              </div>
            </div>
            <ul className="space-y-1.5 text-xs sm:text-sm text-gray-400">
              <li>Only the trigger fires</li>
              <li>Pivot to find the chain</li>
              <li>Investigate like the job</li>
            </ul>
          </button>
        </div>
      </div>
    </div>
  );
};

export default DifficultySelector;
