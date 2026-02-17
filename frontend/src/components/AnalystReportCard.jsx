import React from "react";

const AnalystReportCard = ({ report }) => {
  const hasActivity = report && report.total_actions > 0;

  if (!hasActivity) {
    return (
      <div className="bg-[#161b22] p-6 rounded-2xl border border-gray-700 shadow-md h-full">
        <h2 className="text-2xl font-semibold text-white mb-4">Report Card</h2>

        {/* Empty State */}
        <div className="flex flex-col items-center justify-center py-8 min-h-[320px]">
          <img src="/ghost_report.png" alt="Ghost with Report" className="w-40 h-40 opacity-90 mb-3" />
          <p className="font-mono text-sm text-gray-400">&gt; No data yet. Scores populate after each level.</p>
        </div>
      </div>
    );
  }

  if (report.error) {
    return <div className="text-red-400">Error loading report.</div>;
  }

  return (
    <div className="bg-[#161b22] p-6 rounded-2xl border border-gray-700 shadow-md h-full">
      <h2 className="text-2xl font-semibold text-white mb-4">Report Card</h2>

      <table className="w-full text-base mt-8" style={{ fontFamily: "'Open Sans', sans-serif" }}>
        <thead>
          <tr className="text-base text-gray-500 tracking-wider">
            <th className="text-left pb-3 font-medium">Category</th>
            <th className="text-center pb-3 font-medium w-16">Score</th>
          </tr>
        </thead>
        <tbody className="text-gray-300">
          <tr className="border-t border-gray-800">
            <td className="py-3">Correct</td>
            <td className="py-3 text-center">
              <span className="text-white font-semibold">{report.threats_caught || 0}</span>
            </td>
          </tr>
          <tr className="border-t border-gray-800">
            <td className="py-3">Missed</td>
            <td className="py-3 text-center">
              <span className="text-white font-semibold">{report.wrong_category || 0}</span>
            </td>
          </tr>
          <tr className="border-t border-gray-700">
            <td className="py-3 font-semibold text-gray-400">Accuracy</td>
            <td className="py-3 text-center">
              <span className="text-white font-bold">{report.accuracy}%</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  );
};

export default AnalystReportCard;
