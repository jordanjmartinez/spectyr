import React from 'react';
import { Link } from 'react-router-dom';
import { ChromeIcons } from './icons';

// ============================================================================
// Final polish (section 4): the ONE shared product-entry CTA.
//
// Every surface that presents the primary "begin the simulation" control
// renders THIS component: the landing hero, both Docs shells, the sim
// rail's inactive-session slot, and the legacy top navbar. The visible
// label is "Start" everywhere (Start Sim / Start Simulation / Launch Sim
// are retired) on the liquid-glass pill the landing established: one
// fixed height, one horizontal padding, one radius, one type size, one
// filled play glyph, and one hover/focus/disabled behavior. Hover changes
// background and shadow only (the .liquid-btn token), never layout.
// `className` carries placement concerns only (width inside a rail,
// entrance animation, margins); `labelClass` lets the collapsed icon rail
// hide the label below lg (the BrandLockup wordmarkClass pattern) while
// the aria-label keeps the accessible name. This component is for the
// product-entry Start action only -- Submit, Resume, response verbs, and
// ordinary secondary actions keep their own styles.
// ============================================================================

const StartButton = ({ to, onClick, className = '', labelClass = '', style, title }) => {
  const cls = `liquid-btn inline-flex items-center justify-center gap-2 h-[44px] px-[26px] rounded-full text-[15px] font-medium text-white whitespace-nowrap focus:outline-none focus-visible:ring-2 focus-visible:ring-white/50 disabled:opacity-50 disabled:pointer-events-none ${className}`.trim();
  const content = (
    <>
      <ChromeIcons.Play size={18} className="fill-white shrink-0" aria-hidden="true" />
      <span className={labelClass || undefined}>Start</span>
    </>
  );
  if (onClick) {
    return (
      <button type="button" onClick={onClick} aria-label="Start" title={title} style={style} className={cls}>
        {content}
      </button>
    );
  }
  return (
    <Link to={to || '/sim'} aria-label="Start" title={title} style={style} className={cls}>
      {content}
    </Link>
  );
};

export default StartButton;
