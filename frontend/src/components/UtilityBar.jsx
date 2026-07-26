import React, { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { MODE_LABEL } from './uiCopy';
import { ChromeIcons, NAV_STROKE } from './icons';

// Visual pass V3: the compact top utility region, consistent with the
// dark navigation shell. Left: the REAL session identity (mode label +
// the analyst name the player entered at session start) -- nothing is
// invented (no email, no account, no subscription, no cloud sync, no
// logout; none of those exist in this product). Right: the circular
// Spectyr ghost avatar. The avatar opens a small menu of EXISTING real
// controls only: Reset Simulation (routes to the existing confirm
// modal), Documentation, and Back to home -- so it is never a dead
// button. It carries no case context: the pinned case line lives on the
// working surfaces (no stacked duplicate headers).

const UtilityBar = ({ gameMode, analystName, simActive, onReset }) => {
  const [open, setOpen] = useState(false);
  const rootRef = useRef(null);

  // Click-outside + Escape close the menu.
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
    <div className="h-11 mb-4 rounded-lg bg-[#101218] text-gray-300 flex items-center justify-between pl-4 pr-2" data-testid="utility-bar">
      <div className="flex items-center gap-2 min-w-0 text-xs">
        {simActive ? (
          <>
            <span className="t-overline text-gray-400">{MODE_LABEL[gameMode] || gameMode}</span>
            {analystName && (
              <>
                <span className="text-gray-600" aria-hidden="true">·</span>
                <span className="text-gray-200 font-medium truncate">{analystName}</span>
              </>
            )}
          </>
        ) : (
          <span className="text-gray-500">No active session</span>
        )}
      </div>

      <div ref={rootRef} className="relative shrink-0">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          aria-label="Analyst menu"
          aria-haspopup="menu"
          aria-expanded={open}
          className="flex items-center justify-center w-8 h-8 rounded-full bg-white/10 border border-white/15 hover:border-white/40 transition-colors overflow-hidden"
        >
          <img src="/spectyr_logo.png" alt="" aria-hidden="true" className="w-6 h-6 object-contain" />
        </button>

        {open && (
          <div
            role="menu"
            aria-label="Analyst menu"
            className="absolute right-0 top-10 z-50 w-56 bg-white border border-[#e2e6ea] rounded-lg shadow-xl overflow-hidden"
          >
            {/* The local analyst identity: factual fields only. */}
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
    </div>
  );
};

export default UtilityBar;
