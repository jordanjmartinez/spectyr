import React from "react";

const formatDuration = (seconds) => {
  if (seconds == null || seconds < 0) return null;
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  if (m < 60) return s === 0 ? `${m}m` : `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  const rem = m % 60;
  return rem === 0 ? `${h}h` : `${h}h ${rem}m`;
};

// The composite BREAKDOWN beside the headline grade (Stage 3d): the three
// weighted components and Mean Time to Resolve. The detailed Classification,
// Detections, and Response sections render below (ScoreSections); this is the
// transparent 40/30/30 make-up of the headline, never a substitute for them.
const cellGrade = (comp) => {
  if (!comp || comp.accuracy == null) return '-';
  return `${comp.grade} · ${comp.accuracy}%`;
};

const AnalystReportCard = ({ report }) => {
  if (report?.error) {
    return <div className="text-red-600">Error loading report.</div>;
  }

  const comps = report?.composite?.components || {};
  const rows = [
    ['Classification', comps.classification],
    ['Detection dispositions', comps.detection],
    ['Response actions', comps.response],
  ];

  return (
    <div className="h-full">
      <table className="w-full text-xs sm:text-base">
        <colgroup>
          <col />
          <col className="w-28" />
        </colgroup>
        <tbody className="text-[#1a2332]">
          {rows.map(([label, comp], i) => (
            <tr key={label} className={i > 0 ? 'border-t border-[#e2e6ea]' : ''}>
              <td className="py-3 text-[#57606a]">
                {label}
                <span className="ml-2 text-[11px] text-[#8b949e]">{comp?.weight ?? ''}%</span>
              </td>
              <td className="py-3 text-center">
                <span className="text-[#1a2332] font-semibold">{cellGrade(comp)}</span>
              </td>
            </tr>
          ))}
          <tr className="border-t border-[#e2e6ea]">
            <td className="py-3 text-[#57606a]">Mean Time to Resolve</td>
            <td className="py-3 text-center">
              <span className="text-[#1a2332] font-semibold">
                {formatDuration(report?.avg_time_to_resolve_seconds ?? 0)}
              </span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  );
};

export default AnalystReportCard;
