import React from 'react';

// VC3 + VC4 (final lockup correction + owner size instruction): the ONE
// shared SPECTR brand lockup, rendered by every shell. VC4 doubled the
// ghost mark to 80px per the owner's 2026-07-26 instruction; VC6 trimmed
// it to 72px; VD6 trimmed to 68px to sit in the ruled 68px shell row
// unclipped (the sanctioned brand-shrink fallback, recorded in the
// correction appendix), with the 30px wordmark ruling unchanged. Those
// sizes remain the DEFAULT ('md': the Docs shells and any full-bleed
// surface). Owner sidebar redesign follow-up (2026-10-12): the sim rail's
// floating panel wears the compact 'sm' variant (40px ghost + text-lg
// wordmark) so the brand row stops crowding the collapse/pin control --
// an owner-directed size instruction in the same series as VC4/VC6/VD6.
// Both variants are px-fixed and shrink-0 so the designed proportion
// never drifts with rem scale or a flex squeeze; no transform scaling,
// no max-height, no clipping (max-w-none defuses the preflight img
// max-width). The wordmark face/weight/tracking live on the shared
// .brand-wordmark token (face selection + licensing note in index.css).
// White ink is baked in: every shell lockup sits on the dark #101218
// surface. Visible branding only; internal identifiers stay unrenamed.
const GAP = { md: 'gap-2.5', sm: 'gap-2' };
const IMG_SIZE = { md: 'h-[68px] w-[68px]', sm: 'h-10 w-10' };
const WORD_SIZE = { md: 'text-[30px]', sm: 'text-lg' };

const BrandLockup = ({ wordmarkClass = '', size = 'md' }) => (
  <span className={`flex items-center ${GAP[size] || GAP.md}`}>
    <img
      src="/spectyr_logo.png"
      alt=""
      aria-hidden="true"
      className={`${IMG_SIZE[size] || IMG_SIZE.md} max-w-none object-contain shrink-0`}
    />
    <span className={`brand-wordmark ${WORD_SIZE[size] || WORD_SIZE.md} text-white whitespace-nowrap shrink-0 ${wordmarkClass}`.trim()}>
      SPECTR
    </span>
  </span>
);

export default BrandLockup;
