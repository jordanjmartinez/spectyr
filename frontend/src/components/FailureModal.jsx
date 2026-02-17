import React from 'react';

const FailureModal = ({ onRestart }) => {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/70" />
      <div className="relative bg-[#161b22] border border-gray-700 rounded-xl p-6 w-full max-w-md mx-4 shadow-2xl text-center">
        <div className="flex items-center justify-center gap-3 mb-4">
          <img src="/hacker_fav.png" alt="" className="w-14 h-14" />
          <h3 className="text-2xl font-bold text-white">You've Been Hacked..</h3>
        </div>
        <p className="text-gray-400 mb-6">The threat slipped through your defenses before you could respond.</p>
        <div className="flex justify-center">
          <button
            onClick={onRestart}
            className="px-4 py-2 text-sm font-medium rounded-md bg-[#21262d] hover:bg-[#30363d] text-gray-300 border border-gray-600 transition"
          >
            Return to Menu
          </button>
        </div>
      </div>
    </div>
  );
};

export default FailureModal;
