import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { Menu, X, Play } from 'lucide-react';

const VIDEO_URL = '/videos/spectyrvideo.mp4';

const NAV_LINKS = [
  { label: 'Campaign', to: '/docs#campaign' },
  { label: 'Game Modes', to: '/docs#game-modes' },
  { label: 'Scenarios', to: '/docs#scenarios' },
  { label: 'Analytics', to: '/docs#analytics' },
  { label: 'Reports', to: '/docs#reports' },
];

// Single full-viewport cinematic hero — no scrolling, no additional sections
const Landing = () => {
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <div className="relative h-dvh overflow-hidden bg-black text-white flex flex-col">
      {/* Flat fill sampled from the video's dark corners, so its edges dissolve into the page */}
      <div className="fixed inset-0 z-0 bg-[#04040a]" />

      {/* Main video — centered at its natural aspect, never cropped or stretched */}
      <div className="fixed inset-0 z-[1] flex items-center justify-center">
        <video
          className="max-w-full max-h-full"
          src={VIDEO_URL}
          autoPlay
          loop
          muted
          playsInline
        />
      </div>

      {/* Bottom blur overlay */}
      <div
        className="fixed inset-0 backdrop-blur-xl pointer-events-none z-[2]"
        style={{
          maskImage: 'linear-gradient(to top, black 0%, transparent 45%)',
          WebkitMaskImage: 'linear-gradient(to top, black 0%, transparent 45%)',
        }}
      />

      {/* Black scrim keeping the title readable over the bright ghost */}
      <div className="fixed inset-x-0 bottom-0 h-[55%] z-[3] bg-gradient-to-t from-black/80 via-black/40 to-transparent pointer-events-none" />

      {/* Navbar */}
      <nav className="relative z-50 flex items-center justify-between px-4 sm:px-6 md:px-12 py-4 md:py-6">
        <Link
          to="/"
          className="animate-blur-fade-up flex items-center h-8 md:h-10"
          style={{ animationDelay: '0ms' }}
        >
          <span
            className="text-2xl md:text-3xl tracking-wider"
            style={{ fontFamily: "'Aldrich', sans-serif" }}
          >
            Spectyr
          </span>
        </Link>

        {/* Desktop nav links */}
        <div className="hidden lg:flex items-center gap-8">
          {NAV_LINKS.map(({ label, to }, i) => (
            <Link
              key={label}
              to={to}
              className="animate-blur-fade-up text-sm hover:text-gray-300 transition-colors"
              style={{ animationDelay: `${100 + i * 50}ms` }}
            >
              {label}
            </Link>
          ))}
        </div>

        <div className="flex items-center gap-3">
          {/* Hamburger (below lg) with animated Menu/X swap */}
          <button
            onClick={() => setMenuOpen((o) => !o)}
            className="animate-blur-fade-up liquid-glass lg:hidden flex items-center justify-center w-10 h-10 rounded-full"
            style={{ animationDelay: '350ms' }}
            aria-label={menuOpen ? 'Close menu' : 'Open menu'}
          >
            <span className="relative w-[18px] h-[18px]">
              <Menu
                size={18}
                className={`absolute inset-0 transition-all duration-500 ease-out ${
                  menuOpen ? 'rotate-180 opacity-0 scale-50' : 'rotate-0 opacity-100 scale-100'
                }`}
              />
              <X
                size={18}
                className={`absolute inset-0 transition-all duration-500 ease-out ${
                  menuOpen ? 'rotate-0 opacity-100 scale-100' : '-rotate-180 opacity-0 scale-50'
                }`}
              />
            </span>
          </button>
        </div>
      </nav>

      {/* Mobile menu */}
      <div
        className={`lg:hidden absolute top-[72px] left-0 right-0 z-40 bg-gray-900/95 backdrop-blur-lg border-t border-b border-gray-800 shadow-2xl transition-all duration-500 ease-out ${
          menuOpen ? 'translate-y-0 opacity-100' : '-translate-y-4 opacity-0 pointer-events-none'
        }`}
      >
        <div className="flex flex-col px-4 py-4">
          {NAV_LINKS.map(({ label, to }, i) => (
            <Link
              key={label}
              to={to}
              onClick={() => setMenuOpen(false)}
              className={`text-left py-3 px-3 rounded-lg hover:bg-gray-800/50 transition-all duration-300 ${
                menuOpen ? 'translate-x-0 opacity-100' : '-translate-x-4 opacity-0'
              }`}
              style={{ transitionDelay: `${i * 50}ms` }}
            >
              {label}
            </Link>
          ))}
        </div>
      </div>

      {/* Hero content pinned to the bottom */}
      <div className="relative z-10 flex-1 flex flex-col justify-end px-4 sm:px-6 md:px-12 pb-8 md:pb-16">
        <div className="flex flex-col md:flex-row md:items-end gap-8">
          <div className="flex-1">
            <h1
              className="animate-blur-fade-up text-3xl sm:text-5xl md:text-6xl lg:text-7xl font-medium leading-[1.1] mb-4 md:mb-6"
              style={{ animationDelay: '300ms', fontFamily: "'Montserrat', sans-serif", letterSpacing: '-0.02em' }}
            >
              <span className="block">Triage Real Alerts.</span>
              <span className="block">Build Real Instincts.</span>
            </h1>

            <p
              className="animate-blur-fade-up text-base sm:text-lg md:text-xl text-gray-400 mb-6 md:mb-12 max-w-2xl"
              style={{ animationDelay: '400ms' }}
            >
              A simulated SIEM with realistic log chains across different attack scenarios.
            </p>

            {/* CTA */}
            <div className="flex flex-wrap gap-3 sm:gap-4">
              <Link
                to="/sim"
                className="animate-blur-fade-up flex items-center gap-2 bg-white text-black rounded-full font-medium px-6 sm:px-8 py-2.5 sm:py-3 hover:bg-gray-200 transition-colors"
                style={{ animationDelay: '500ms' }}
              >
                <Play size={18} className="fill-black" />
                Enter the Sim
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Landing;
