import React from 'react';

export const SEVERITY_COLORS = { Critical: '#b26666', High: '#c28e46', Medium: '#d4cc6e', Low: '#6fa868' };

const hexToRgba = (hex, alpha) => {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${alpha})`;
};

const SeverityPill = ({ level }) => {
  const color = SEVERITY_COLORS[level] || '#9ca3af';
  const filled = level === 'Critical' || level === 'High';
  return (
    <span
      className="inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-medium border whitespace-nowrap"
      style={{
        color: filled ? '#ffffff' : color,
        backgroundColor: filled ? color : hexToRgba(color, 0.15),
        borderColor: filled ? color : hexToRgba(color, 0.45),
      }}
    >
      {level || 'Unset'}
    </span>
  );
};

export default SeverityPill;
