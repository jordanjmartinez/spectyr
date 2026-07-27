import React from 'react';

// VC3 + VC4 (final lockup correction + owner size instruction): the ONE
// shared SPECTR brand lockup, rendered identically by every shell (the
// sim sidebar brand cell and both Docs shells). VC4 doubled the ghost
// mark to 80px per the owner's 2026-07-26 instruction ("at least double
// its size"); VC6 trims it to 72px per the follow-up ("a little too
// big now, maybe just a tad bit smaller"). VD6 (visual correction
// section 6): the shared shell row is now ruled 68px, superseding the
// earlier 72-76px target. The cell's vertical padding is already zero,
// so per the instruction's own priority (reduce padding BEFORE
// shrinking the brand) the ghost takes the minimal trim 72px -> 68px to
// sit in the fixed cell unclipped -- FLAGGED as the sanctioned
// brand-shrink fallback, recorded in the correction appendix. The 30px
// wordmark ruling is unchanged. Both are px-FIXED
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
      className="h-[68px] w-[68px] max-w-none object-contain shrink-0"
    />
    <span className={`brand-wordmark text-[30px] text-white whitespace-nowrap shrink-0 ${wordmarkClass}`.trim()}>
      SPECTR
    </span>
  </span>
);

export default BrandLockup;
