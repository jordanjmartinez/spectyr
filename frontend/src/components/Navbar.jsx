import React from 'react';
import { Link, useLocation } from 'react-router-dom';

const Navbar = () => {
  const location = useLocation();

  const isActive = (path) => location.pathname === path;

  return (
    <nav className="bg-[#0d1117] text-white px-4 py-3 sm:px-6 sm:py-4 shadow-md flex items-center">
      <span
        className="text-3xl sm:text-5xl tracking-wider text-white"
        style={{ fontFamily: "'Aldrich', sans-serif" }}
      >
        SPECTYR
      </span>
    </nav>
  );
};

export default Navbar;