import React from 'react';

const FailureModal = ({ onRetry, onQuit }) => {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Dark overlay */}
      <div className="absolute inset-0 bg-black/90" />

      {/* Scanline overlay */}
      <div
        className="absolute inset-0 pointer-events-none opacity-[0.03]"
        style={{
          backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255,255,255,0.1) 2px, rgba(255,255,255,0.1) 4px)',
        }}
      />


      <div className="relative text-center px-6 max-w-lg mx-auto animate-modalIn">
        {/* Glitch title */}
        <div className="relative mb-6">
          <h1
            className="text-4xl sm:text-5xl font-normal tracking-widest text-gray-100 select-none"
            style={{
              fontFamily: "'Aldrich', sans-serif",
              textShadow: '1px 0 rgba(0,255,255,0.3), -1px 0 rgba(255,0,255,0.3)',
              animation: 'glitch 4s infinite',
            }}
          >
            SYSTEM COMPROMISED
          </h1>
          {/* Subtle chromatic layers */}
          <h1
            className="absolute top-0 left-0 w-full text-4xl sm:text-5xl font-normal tracking-widest text-cyan-400 select-none opacity-0"
            style={{
              fontFamily: "'Aldrich', sans-serif",
              clipPath: 'polygon(0 0, 100% 0, 100% 45%, 0 45%)',
              animation: 'glitch-top 4s infinite',
            }}
            aria-hidden="true"
          >
            SYSTEM COMPROMISED
          </h1>
          <h1
            className="absolute top-0 left-0 w-full text-4xl sm:text-5xl font-normal tracking-widest text-fuchsia-400 select-none opacity-0"
            style={{
              fontFamily: "'Aldrich', sans-serif",
              clipPath: 'polygon(0 55%, 100% 55%, 100% 100%, 0 100%)',
              animation: 'glitch-bottom 4s infinite',
            }}
            aria-hidden="true"
          >
            SYSTEM COMPROMISED
          </h1>
        </div>

        {/* Hacker image */}
        <img src="/hacker_icon.jpeg" alt="Hacker" className="w-28 h-28 sm:w-36 sm:h-36 mx-auto mb-6 opacity-90" />

        {/* Terminal message */}
        <p
          className="text-gray-400 text-sm sm:text-base mb-8 tracking-wide"
          style={{ fontFamily: "'JetBrains Mono', sans-serif" }}
        >
          &gt;<span className="animate-blink">|</span> The attacker is already inside.
        </p>

        {/* Try Again prompt */}
        <p className="text-gray-400 text-sm mb-4">
          Try Again?
        </p>

        <div className="flex justify-center gap-3">
          <button
            onClick={onRetry}
            className="px-2 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm font-medium rounded-md bg-[#21262d] hover:bg-[#30363d] text-gray-300 border border-gray-600 transition"
          >
            Yes, I'm brave
          </button>
          <button
            onClick={onQuit}
            className="px-2 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm font-medium rounded-md bg-[#21262d] hover:bg-[#30363d] text-gray-300 border border-gray-600 transition"
          >
            No, maybe later
          </button>
        </div>
      </div>

      {/* Glitch keyframes */}
      <style>{`
        @keyframes glitch {
          0%, 100% { transform: translate(0); }
          2% { transform: translate(-1px, 0); }
          4% { transform: translate(1px, 0); }
          6% { transform: translate(0); }
          50% { transform: translate(0); }
          52% { transform: translate(-1px, 0); }
          54% { transform: translate(0); }
        }
        @keyframes glitch-top {
          0%, 100% { transform: translate(0); opacity: 0; }
          2% { transform: translate(1px, 0); opacity: 0.25; }
          4% { transform: translate(-1px, 0); opacity: 0.25; }
          6% { transform: translate(0); opacity: 0; }
        }
        @keyframes glitch-bottom {
          0%, 100% { transform: translate(0); opacity: 0; }
          50% { transform: translate(0); opacity: 0; }
          52% { transform: translate(-1px, 0); opacity: 0.25; }
          54% { transform: translate(1px, 0); opacity: 0.25; }
          56% { transform: translate(0); opacity: 0; }
        }
      `}</style>
    </div>
  );
};

export default FailureModal;
