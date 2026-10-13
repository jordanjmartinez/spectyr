import React, { useRef } from 'react';

// ============================================================================
// Owner Incidents-panel pass (2026-10-12, compact refinement 2026-10-13):
// the ONE radio-card group behind the verdict pair and the category grid.
// - Real radio semantics: role=radiogroup + role=radio with aria-checked,
//   ONE tab stop per group with arrow-key navigation (roving tabindex;
//   arrows move AND select, the WAI-ARIA radio pattern), targets >= 48px,
//   the whole card clickable.
// - Every card leads with a NEUTRAL OUTLINE icon (one consistent stroke
//   set, never green or red); the selection check sits in a reserved
//   TRAILING slot so labels never shift.
// - Cards are compact: `columns` renders the fixed grid (categories, four
//   columns from md up); without it the cards size to content in a
//   wrapping row (the verdict pair).
// - Selected state (identical for EVERY option): neutral tonal fill + 2px
//   ink border + semibold label. Unselected cards keep a 2px edge-tint
//   border so selecting never shifts layout. Hover is a light wash only;
//   keyboard focus gets its own outer offset ring (focus-visible).
// ============================================================================

export const CheckIcon = ({ className = 'w-4 h-4' }) => (
  <svg viewBox="0 0 16 16" className={className} aria-hidden="true" fill="none"
    stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3 8.5l3.5 3.5L13 5" />
  </svg>
);

// the one stroke shell every leading card icon wears (outlines only)
const LeadIcon = ({ children }) => (
  <svg viewBox="0 0 24 24" className="w-4 h-4 shrink-0 text-[#57606a]" aria-hidden="true"
    fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    {children}
  </svg>
);

const GRID_COLS = { 2: 'grid grid-cols-2 gap-2', 4: 'grid grid-cols-2 md:grid-cols-4 gap-2' };

const RadioCardGroup = ({
  labelledBy, options, value = null, onSelect, disabled = false, columns = null,
}) => {
  const refs = useRef({});
  const ids = options.map((o) => o.id);
  const move = (from, delta) => {
    const next = ids[(ids.indexOf(from) + delta + ids.length) % ids.length];
    onSelect(next);
    refs.current[next]?.focus();
  };
  const onKey = (e, id) => {
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') { e.preventDefault(); move(id, 1); }
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') { e.preventDefault(); move(id, -1); }
  };
  // one tab stop: the checked option, else the first
  const tabTarget = value && ids.includes(value) ? value : ids[0];

  return (
    <div role="radiogroup" aria-labelledby={labelledBy}
      className={`${GRID_COLS[columns] || 'flex flex-wrap gap-2'} ${disabled ? 'opacity-50' : ''}`}>
      {options.map((o) => {
        const checked = value === o.id;
        return (
          <button
            key={o.id}
            ref={(el) => { refs.current[o.id] = el; }}
            type="button"
            role="radio"
            aria-checked={checked}
            disabled={disabled}
            tabIndex={disabled ? -1 : (o.id === tabTarget ? 0 : -1)}
            onClick={() => onSelect(o.id)}
            onKeyDown={(e) => onKey(e, o.id)}
            className={`flex items-center gap-2 min-h-[48px] px-3 rounded-lg text-left transition
              focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#16436b] focus-visible:ring-offset-2
              ${checked
                ? 'border-2 border-[#101218] bg-[#eef1f4]'
                : 'border-2 border-[#e2e6ea] bg-white hover:bg-[#f6f8fa]'}`}
          >
            {o.icon && <LeadIcon>{o.icon}</LeadIcon>}
            <span className={`text-xs text-[#1a2332] ${checked ? 'font-semibold' : 'font-medium'}`}>
              {o.label}
            </span>
            {/* the reserved TRAILING check slot: present on every card so
                the label never shifts when selection changes */}
            <span className="w-4 h-4 shrink-0 ml-auto text-[#101218]" aria-hidden="true">
              {checked && <CheckIcon />}
            </span>
          </button>
        );
      })}
    </div>
  );
};

export default RadioCardGroup;
