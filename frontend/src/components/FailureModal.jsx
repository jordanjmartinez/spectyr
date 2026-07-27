import React, { useState, useEffect } from 'react';

const FailureModal = ({ onRetry, onQuit, failureType }) => {
  const [selected, setSelected] = useState(0);

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
        setSelected(0);
        e.preventDefault();
      } else if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
        setSelected(1);
        e.preventDefault();
      } else if (e.key === 'Enter') {
        (selected === 0 ? onRetry : onQuit)?.();
        e.preventDefault();
      } else if (e.key === 'Escape') {
        onQuit?.();
        e.preventDefault();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [selected, onRetry, onQuit]);

  const detail = failureType === 'timeout'
    ? 'The clock ran out before the threat was contained.'
    : 'A critical alert was misclassified. The intrusion went undetected.';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#0d1117]/95">
      {/* Faint red gravity glow, no scanlines */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{ background: 'radial-gradient(circle at 50% 42%, rgba(178,102,102,0.14), transparent 60%)' }}
      />

      <div className="relative text-center px-6 max-w-md mx-auto animate-modalIn">
        <img
          src="/hacker_icon.jpeg"
          alt=""
          className="w-20 h-20 sm:w-24 sm:h-24 mx-auto mb-6 object-contain"
        />

        <h1
          className="text-3xl sm:text-4xl font-semibold tracking-[0.15em] text-white select-none mb-3"
          style={{ fontFamily: "'IBM Plex Sans', sans-serif", textShadow: '0 0 24px rgba(178,102,102,0.45)' }}
        >
          SYSTEM COMPROMISED
        </h1>

        <div className="inline-flex items-center gap-2 mb-5">
          <span className="w-1.5 h-1.5 rounded-full bg-[#b26666]" />
          <span
            className="log-mono text-xs tracking-[0.2em] text-[#b26666] uppercase"
          >
            Session Terminated
          </span>
        </div>

        <p className="text-gray-400 text-sm sm:text-base mb-8 leading-relaxed">
          {detail}
        </p>

        <div className="flex justify-center gap-3">
          <button
            onClick={onRetry}
            onMouseEnter={() => setSelected(0)}
            className={`px-6 py-2.5 rounded-md text-sm font-medium bg-white text-[#101218] hover:bg-gray-100 transition-colors focus:outline-none ${
              selected === 0 ? 'ring-2 ring-white/70 ring-offset-2 ring-offset-[#0d1117]' : ''
            }`}
          >
            Retry
          </button>
          <button
            onClick={onQuit}
            onMouseEnter={() => setSelected(1)}
            className={`px-6 py-2.5 rounded-md text-sm font-medium border border-white/25 text-gray-300 hover:bg-white/10 hover:text-white transition-colors focus:outline-none ${
              selected === 1 ? 'ring-2 ring-white/40 ring-offset-2 ring-offset-[#0d1117]' : ''
            }`}
          >
            Exit
          </button>
        </div>
      </div>
    </div>
  );
};

export default FailureModal;
