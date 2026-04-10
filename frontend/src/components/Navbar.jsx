import React from 'react';
import { Link, useLocation } from 'react-router-dom';

const Navbar = () => {
  const location = useLocation();

  const isActive = (path) => location.pathname === path;

  return (
    <nav className="bg-[#0d1117] text-white px-4 pt-0 pb-0 sm:px-6 sm:pt-0 sm:pb-0 shadow-md flex items-center">
      <div className="flex items-center gap-3">
        <img
          src="/spectyr_logo.png"
          alt="Spectyr"
          className="h-14 w-14 sm:h-20 sm:w-20 object-contain"
        />
        <span
          className="text-3xl sm:text-5xl tracking-wider text-white"
          style={{ fontFamily: "'Aldrich', sans-serif" }}
        >
          SPECTYR
        </span>
      </div>
    </nav>
  );
};

export default Navbar;