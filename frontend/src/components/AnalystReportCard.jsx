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

// Bare content (heading + counts table) — Analytics wraps this and GradeCard
// together in one container. Overall Grade is intentionally omitted here since
// the Grade panel sits right beside it.
const AnalystReportCard = ({ report }) => {
  if (report?.error) {
    return <div className="text-red-600">Error loading report.</div>;
  }

  const threatsCorrect = report?.threats_caught || 0;
  const threatsMissed = report?.wrong_category || 0;
  const threatsTotal = threatsCorrect + threatsMissed;
  const fpCorrect = report?.fp_identified || 0;
  const fpMissed = report?.fp_missed || 0;
  const fpTotal = fpCorrect + fpMissed;

  return (
    <div className="h-full">
      <h3 className="text-base font-semibold text-[#1a2332] mb-3">Report Card</h3>
      <table className="w-full text-xs sm:text-base">
        <colgroup>
          <col />
          <col className="w-20" />
        </colgroup>
        <tbody className="text-[#1a2332]">
          <tr>
            <td className="py-3 text-[#57606a]">True Positives</td>
            <td className="py-3 text-center">
              <span className="text-[#1a2332] font-semibold">{threatsCorrect}/{threatsTotal}</span>
            </td>
          </tr>
          <tr className="border-t border-[#e2e6ea]">
            <td className="py-3 text-[#57606a]">False Positives</td>
            <td className="py-3 text-center">
              <span className="text-[#1a2332] font-semibold">{fpCorrect}/{fpTotal}</span>
            </td>
          </tr>
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
