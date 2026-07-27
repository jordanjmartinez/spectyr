import React from 'react';
import { useLocation } from 'react-router-dom';
import StartButton from './StartButton';

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
        {/* VC2: the SPECTR wordmark in the shared brand display face
            (visible branding only) */}
        <span className="brand-wordmark text-xl sm:text-2xl text-white hidden min-[460px]:inline">
          SPECTR
        </span>
      </div>
      <div className="flex items-center gap-3 shrink-0">
        <div id="navbar-timer-slot" className="flex items-center" />
        {/* Final polish (section 4): the legacy chrome's entry control is
            the shared StartButton (the light "Launch Sim" pill retired). */}
        {!isActive('/sim') && <StartButton to="/sim" />}
      </div>
    </nav>
  );
};

export default Navbar;