import React, { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { MODE_LABEL } from './uiCopy';
import { ChromeIcons, NAV_STROKE } from './icons';

// VH (owner correction): the clean application header. Left: the current
// workspace title (the shared t-page token) -- never a mode or analyst
// name. Right: a compact utility area of REAL functionality only. No
// notification surface exists in this product and the only Help surface
// is the Guided floating hint control (already on screen in Guided), so
// the utility area is the circular Spectyr ghost avatar alone -- no fake
// search, bell, settings, or profile controls to mimic a reference.
//
// The avatar (32px, subtle border, labeled) opens a menu of EXISTING
// real controls: the Local analyst identity lines (the analyst name is
// the real session field entered at start; nothing else about a user
// exists), Reset Simulation (routes to the existing confirm modal),
// Documentation, and Back to home. No invented account, email,
// subscription, profile settings, logout, or cloud identity.

const AppHeader = ({ title, gameMode, analystName, simActive, onReset }) => {
  const [open, setOpen] = useState(false);
  const rootRef = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    const onDown = (e) => {
      if (rootRef.current && !rootRef.current.contains(e.target)) setOpen(false);
    };
    const onKey = (e) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const itemCls = 'w-full text-left flex items-center gap-2 px-3 py-2 text-sm text-[#57606a] hover:bg-[#f6f8fa] hover:text-[#1a2332]';

  return (
    <header className="mb-4 flex items-center justify-between gap-4" data-testid="app-header">
      <h1 className="t-page">{title}</h1>

      <div ref={rootRef} className="relative shrink-0">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          aria-label="Analyst menu"
          aria-haspopup="menu"
          aria-expanded={open}
          className="flex items-center justify-center w-8 h-8 rounded-full bg-white border border-[#d0d7de] hover:border-[#8b949e] transition-colors overflow-hidden"
        >
          <img src="/spectyr_logo.png" alt="" aria-hidden="true" className="w-6 h-6 object-contain" />
        </button>

        {open && (
          <div
            role="menu"
            aria-label="Analyst menu"
            className="absolute right-0 top-10 z-50 w-56 bg-white border border-[#e2e6ea] rounded-lg shadow-xl overflow-hidden"
          >
            <div className="px-3 py-2.5 border-b border-[#eef1f4]">
              <p className="t-overline">Local analyst</p>
              <p className="text-sm font-medium text-[#1a2332] truncate">{simActive && analystName ? analystName : 'No active session'}</p>
              {simActive && (
                <p className="text-xs text-[#57606a]">{MODE_LABEL[gameMode] || gameMode} mode</p>
              )}
            </div>
            {simActive && onReset && (
              <button
                type="button"
                role="menuitem"
                onClick={() => { setOpen(false); onReset(); }}
                className={itemCls}
              >
                <ChromeIcons.RotateCcw size={15} strokeWidth={NAV_STROKE} aria-hidden="true" />
                Reset Simulation
              </button>
            )}
            <Link to="/docs" role="menuitem" className={itemCls} onClick={() => setOpen(false)}>
              <ChromeIcons.BookOpen size={15} strokeWidth={NAV_STROKE} aria-hidden="true" />
              Documentation
            </Link>
            <Link to="/" role="menuitem" className={itemCls} onClick={() => setOpen(false)}>
              <ChromeIcons.Ghost size={15} strokeWidth={NAV_STROKE} aria-hidden="true" />
              Back to home
            </Link>
          </div>
        )}
      </div>
    </header>
  );
};

export default AppHeader;
