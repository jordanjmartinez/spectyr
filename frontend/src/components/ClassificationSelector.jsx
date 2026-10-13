import React from 'react';
import RadioCardGroup from './RadioCardGroup';

// Owner compact refinement (2026-10-13): neutral OUTLINE icons -- the
// verdict pair wears check-circle / x-circle shapes with no green or red
// (the shape carries the meaning; color never does in classification).
const ICONS = {
  true_positive: (   // check-circle
    <>
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
      <polyline points="22 4 12 14.01 9 11.01" />
    </>
  ),
  false_positive: (  // x-circle
    <>
      <circle cx="12" cy="12" r="10" />
      <line x1="15" y1="9" x2="9" y2="15" />
      <line x1="9" y1="9" x2="15" y2="15" />
    </>
  ),
};

const CLASSIFICATIONS = [
  { id: 'true_positive', label: 'True Positive', icon: ICONS.true_positive },
  { id: 'false_positive', label: 'False Positive', icon: ICONS.false_positive },
];

// The workspace verdict step (ratified A1-B.3.2 source; the modal variant
// was deleted by A3-OD-2). Owner panel pass (2026-10-12) + compact
// refinement (2026-10-13): two COMPACT content-width radio cards (never
// full-width halves), identical neutral selected treatment, real radio
// semantics, one tab stop.
const ClassificationSelector = ({ onSelect, selected = null, labelledBy }) => (
  <RadioCardGroup
    labelledBy={labelledBy}
    options={CLASSIFICATIONS}
    value={selected}
    onSelect={onSelect}
  />
);

export default ClassificationSelector;
