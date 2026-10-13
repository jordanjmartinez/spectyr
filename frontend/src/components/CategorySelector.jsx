import React from 'react';
import RadioCardGroup from './RadioCardGroup';

// Owner compact refinement (2026-10-13): one consistent neutral outline
// icon per category (bug / mail / arrows / upload / signal / user / key /
// eye-off) -- shapes only, never a color meaning.
const ICONS = {
  malware: (         // bug
    <>
      <path d="M9 7V6a3 3 0 0 1 6 0v1" />
      <path d="M18 11a4 4 0 0 0-4-4h-4a4 4 0 0 0-4 4v3a6 6 0 0 0 12 0z" />
      <path d="M12 20v-9" />
      <path d="M6.5 9C4.6 8.8 3 7.1 3 5" />
      <path d="M6 13H2" />
      <path d="M3 21c0-2.1 1.7-3.9 3.8-4" />
      <path d="M17.5 9c1.9-.2 3.5-1.9 3.5-4" />
      <path d="M22 13h-4" />
      <path d="M17.2 17c2.1.1 3.8 1.9 3.8 4" />
    </>
  ),
  phishing: (        // mail
    <>
      <rect x="2" y="4" width="20" height="16" rx="2" />
      <polyline points="22,6 12,13 2,6" />
    </>
  ),
  lateral_movement: ( // arrows (left-right)
    <>
      <polyline points="18 8 22 12 18 16" />
      <polyline points="6 8 2 12 6 16" />
      <line x1="2" y1="12" x2="22" y2="12" />
    </>
  ),
  data_exfiltration: ( // upload
    <>
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="17 8 12 3 7 8" />
      <line x1="12" y1="3" x2="12" y2="15" />
    </>
  ),
  command_control: ( // signal
    <>
      <circle cx="12" cy="12" r="2" />
      <path d="M16.24 7.76a6 6 0 0 1 0 8.49" />
      <path d="M7.76 16.24a6 6 0 0 1 0-8.49" />
      <path d="M19.07 4.93a10 10 0 0 1 0 14.14" />
      <path d="M4.93 19.07a10 10 0 0 1 0-14.14" />
    </>
  ),
  insider_threat: (  // user
    <>
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
      <circle cx="12" cy="7" r="4" />
    </>
  ),
  brute_force: (     // key
    <>
      <path d="M21 2l-2 2" />
      <path d="M15.5 7.5l3 3L22 7l-3-3-3.5 3.5z" />
      <path d="M15.5 7.5L11.4 11.6" />
      <circle cx="7.5" cy="15.5" r="5.5" />
    </>
  ),
  defense_evasion: ( // eye-off
    <>
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
      <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
      <path d="M14.12 14.12a3 3 0 1 1-4.24-4.24" />
      <line x1="1" y1="1" x2="23" y2="23" />
    </>
  ),
};

const ATTACK_CATEGORIES = [
  { id: 'malware', label: 'Malware', icon: ICONS.malware },
  { id: 'phishing', label: 'Phishing', icon: ICONS.phishing },
  { id: 'lateral_movement', label: 'Lateral Movement', icon: ICONS.lateral_movement },
  { id: 'data_exfiltration', label: 'Data Exfiltration', icon: ICONS.data_exfiltration },
  { id: 'command_control', label: 'Command & Control', icon: ICONS.command_control },
  { id: 'insider_threat', label: 'Insider Threat', icon: ICONS.insider_threat },
  { id: 'brute_force', label: 'Brute Force', icon: ICONS.brute_force },
  { id: 'defense_evasion', label: 'Defense Evasion', icon: ICONS.defense_evasion },
];

// The workspace category step (ratified A3-OD-2, grid-only). Owner panel
// pass (2026-10-12) + compact refinement (2026-10-13): the 8 categories as
// compact radio cards in a FOUR-column grid (two columns below md), same
// neutral selected treatment as the verdict pair, real radio semantics,
// one tab stop. Disabled while the verdict is False Positive (a category
// does not apply).
const CategorySelector = ({ onSelect, selected = null, labelledBy, disabled = false }) => (
  <RadioCardGroup
    labelledBy={labelledBy}
    options={ATTACK_CATEGORIES}
    value={selected}
    disabled={disabled}
    columns={4}
    onSelect={(id) => {
      const cat = ATTACK_CATEGORIES.find((c) => c.id === id);
      onSelect(id, cat ? cat.label : id);
    }}
  />
);

export default CategorySelector;
