import React from 'react';

// VC3 + VC4 (final lockup correction + owner size instruction): the ONE
// shared SPECTR brand lockup, rendered identically by every shell (the
// sim sidebar brand cell and both Docs shells). VC4 doubles the ghost
// mark to 80px per the owner's 2026-07-26 instruction ("at least double
// its size"); the 30px wordmark ruling is unchanged. Both are px-FIXED
// and shrink-0, so the designed proportion never drifts with the
// viewer's rem scale, a parent flex squeeze, or a navigation-label size
// token; no transform scaling, no max-height, no clipping (max-w-none
// defuses the preflight img max-width). The wordmark face, weight,
// tracking, and line-height live on the shared .brand-wordmark token --
// the display-face selection and licensing note sit on that rule in
// index.css. White ink is baked in: every shell lockup sits on the dark
// #101218 rail. Visible branding only; the asset filename and all
// internal identifiers stay unrenamed.
const BrandLockup = ({ wordmarkClass = '' }) => (
  <span className="flex items-center gap-2.5">
    <img
      src="/spectyr_logo.png"
      alt=""
      aria-hidden="true"
      className="h-[80px] w-[80px] max-w-none object-contain shrink-0"
    />
    <span className={`brand-wordmark text-[30px] text-white whitespace-nowrap shrink-0 ${wordmarkClass}`.trim()}>
      SPECTR
    </span>
  </span>
);

export default BrandLockup;
