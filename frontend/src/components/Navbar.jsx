import React from 'react';
import { Link, useLocation } from 'react-router-dom';

const Navbar = () => {
  const location = useLocation();

  const isActive = (path) => location.pathname === path;

  return (
    <nav className="sticky top-0 z-50 bg-[#0d1117]/90 backdrop-blur-md text-white px-4 py-3 sm:px-6 border-b border-[#30363d] flex items-center justify-between gap-4">
      <div className="flex items-center gap-2.5 min-w-0">
        <img
          src="/spectyr_logo.png"
          alt=""
          aria-hidden="true"
          className="h-8 w-8 sm:h-9 sm:w-9 object-contain"
        />
        {/* VB2: the SPECTR wordmark (visible branding only) */}
        <span
          className="text-xl sm:text-2xl font-semibold text-white hidden min-[460px]:inline"
          style={{ fontFamily: "'Space Grotesk', 'Inter', sans-serif", letterSpacing: '0.06em' }}
        >
          SPECTR
        </span>
      </div>
      <div className="flex items-center gap-3 shrink-0">
        <div id="navbar-timer-slot" className="flex items-center" />
        {!isActive('/sim') && (
          <Link
            to="/sim"
            className="bg-[#f0f6fc] hover:bg-white text-[#0d1117] text-sm sm:text-base font-medium rounded-full px-4 sm:px-6 py-2 transition-colors shadow-[inset_0_2px_8px_0_rgba(255,255,255,0.35)] whitespace-nowrap"
          >
            Launch Sim
          </Link>
        )}
      </div>
    </nav>
  );
};

export default Navbar;