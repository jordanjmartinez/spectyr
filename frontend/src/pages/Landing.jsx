import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { Menu, X } from 'lucide-react';
import StartButton from '../components/StartButton';

const VIDEO_URL = '/videos/spectyrvideo.mp4';

// Final pass III.0 item 7: no Reports destination exists (nothing may
// imply a report workflow). Docs-correction pass: the links target the
// rewritten current-product documentation sections.
const NAV_LINKS = [
  { label: 'How Spectr Works', to: '/docs#how-spectr-works' },
  { label: 'Guided and Hardcore', to: '/docs#guided-and-hardcore' },
  { label: 'SIEM', to: '/docs#siem' },
  { label: 'Learning Review', to: '/docs#learning-review' },
];

// Single full-viewport cinematic hero — no scrolling, no additional sections
const Landing = () => {
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <div className="relative h-dvh overflow-hidden bg-[#101218] text-white flex flex-col">
      {/* Flat fill matched to the video's own background tone (sampled #101218),
          so the video edges dissolve into one continuous surface */}
      <div className="fixed inset-0 z-0 bg-[#101218]" />

      {/* Main video — centered at its natural aspect, never cropped or stretched.
          Its side edges are feathered so the rectangle has no hard seam. */}
      <div className="fixed inset-0 z-[1] flex items-center justify-center">
        <video
          className="max-w-full max-h-full"
          src={VIDEO_URL}
          autoPlay
          loop
          muted
          playsInline
          style={{
            WebkitMaskImage: 'linear-gradient(to right, transparent 0%, #000 8%, #000 92%, transparent 100%)',
            maskImage: 'linear-gradient(to right, transparent 0%, #000 8%, #000 92%, transparent 100%)',
          }}
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
          {/* VC3: the landing hero's visible wordmark joins the shared
              brand treatment (the VB2 swap landed in the shared Navbar,
              which this route never renders). Text-only here: the hero
              3D ghost is the page's mark. */}
          <span className="brand-wordmark text-2xl md:text-3xl">
            SPECTR
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
            {/* Final polish (section 5): the hero is the heading and the
                shared Start control alone -- the descriptive subheading is
                deleted, not replaced, and the freed space stays open. */}
            <h1
              className="animate-blur-fade-up text-3xl sm:text-5xl md:text-6xl lg:text-7xl font-semibold leading-[1.1] mb-6 md:mb-10"
              style={{ animationDelay: '300ms', fontFamily: "'IBM Plex Sans', sans-serif", letterSpacing: '-0.02em' }}
            >
              <span className="block">Triage Real Alerts.</span>
              <span className="block">Build Real Instincts.</span>
            </h1>

            {/* CTA */}
            <div className="flex flex-wrap gap-3 sm:gap-4">
              <StartButton
                to="/sim"
                className="animate-blur-fade-up"
                style={{ animationDelay: '400ms' }}
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Landing;
