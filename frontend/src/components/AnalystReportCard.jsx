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

const AnalystReportCard = ({ report }) => {
  if (report?.error) {
    return <div className="text-red-400">Error loading report.</div>;
  }

  const threatsCorrect = report?.threats_caught || 0;
  const threatsMissed = report?.wrong_category || 0;
  const threatsTotal = threatsCorrect + threatsMissed;
  const fpCorrect = report?.fp_identified || 0;
  const fpMissed = report?.fp_missed || 0;
  const fpTotal = fpCorrect + fpMissed;

  const grade = report?.grade || '-';

  return (
    <div className="h-full flex flex-col">
      <h2 className="text-xl sm:text-2xl font-semibold text-white mb-4">Report Card</h2>

      <div className="p-4 sm:p-6 rounded-2xl flex-1" style={{ background: 'linear-gradient(#161b22, #161b22) padding-box, linear-gradient(to bottom, rgba(240,246,252,0.1), transparent) border-box', border: '1px solid transparent', boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05)' }}>
      <table className="w-full h-full text-xs sm:text-base">
        <colgroup>
          <col />
          <col className="w-20" />
        </colgroup>
        <tbody className="text-gray-300">
          <tr>
            <td className="py-3">True Positives</td>
            <td className="py-3 text-center">
              <span className="text-white font-semibold">{threatsCorrect}/{threatsTotal}</span>
            </td>
          </tr>
          <tr className="border-t border-gray-800">
            <td className="py-3">False Positives</td>
            <td className="py-3 text-center">
              <span className="text-white font-semibold">{fpCorrect}/{fpTotal}</span>
            </td>
          </tr>
          <tr className="border-t border-gray-800">
            <td className="py-3">Mean Time to Resolve</td>
            <td className="py-3 text-center">
              <span className="text-white font-semibold">
                {formatDuration(report?.avg_time_to_resolve_seconds ?? 0)}
              </span>
            </td>
          </tr>
          <tr className="border-t border-gray-700">
            <td className="py-3 font-normal text-gray-300">Overall Grade</td>
            <td className="py-3 text-center">
              <span className="text-white font-bold text-xl">{grade}</span>
            </td>
          </tr>
        </tbody>
      </table>
      </div>
    </div>
  );
};

export default AnalystReportCard;
