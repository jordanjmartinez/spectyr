import React from 'react';

const ATTACK_CATEGORIES = [
  { id: 'malware', label: 'Malware' },
  { id: 'phishing', label: 'Phishing' },
  { id: 'lateral_movement', label: 'Lateral Movement' },
  { id: 'data_exfiltration', label: 'Data Exfiltration' },
  { id: 'command_control', label: 'Command & Control' },
  { id: 'insider_threat', label: 'Insider Threat' },
  { id: 'brute_force', label: 'Brute Force' },
  { id: 'defense_evasion', label: 'Defense Evasion' },
];

// Amendment 3 F4b (ratified A3-OD-2): the workspace category step,
// grid-only; the modal variant is DELETED (see ClassificationSelector).
const CategorySelector = ({ onSelect, selected = null }) => (
  <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
    {ATTACK_CATEGORIES.map((category) => {
      const isSel = selected === category.id;
      return (
        <button
          key={category.id}
          onClick={() => onSelect(category.id, category.label)}
          aria-pressed={isSel}
          className={`flex items-center justify-center rounded-lg border-2 transition-all duration-200 group h-10 px-2 ${
            isSel
              ? 'bg-[#eef1f4] border-[#101218]'
              : 'bg-white border-[#d0d7de] hover:bg-[#eef1f4] hover:border-[#8b949e]'}`}
        >
          <span className="text-xs font-medium text-center text-[#1a2332]">
            {category.label}
          </span>
        </button>
      );
    })}
  </div>
);

export default CategorySelector;
