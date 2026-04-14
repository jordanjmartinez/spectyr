import React from "react";

const AnalystReportCard = ({ report }) => {
  if (report?.error) {
    return <div className="text-red-400">Error loading report.</div>;
  }

  return (
    <div className="h-full flex flex-col">
      <h2 className="text-xl sm:text-2xl font-semibold text-white mb-4">Report Card</h2>

      <div className="p-4 sm:p-6 rounded-2xl flex-1" style={{ background: 'linear-gradient(#161b22, #161b22) padding-box, linear-gradient(to bottom, rgba(88,130,180,0.3), transparent) border-box', border: '1px solid transparent', boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05)' }}>
      <table className="w-full h-full text-xs sm:text-base">
        <colgroup>
          <col />
          <col className="w-16" />
        </colgroup>
        <tbody className="text-gray-300">
          <tr>
            <td className="py-3">Correct</td>
            <td className="py-3 text-center">
              <span className="text-white font-semibold">{(report?.threats_caught || 0) + (report?.fp_identified || 0)}</span>
            </td>
          </tr>
          <tr className="border-t border-gray-800">
            <td className="py-3">Missed</td>
            <td className="py-3 text-center">
              <span className="text-white font-semibold">{(report?.wrong_category || 0) + (report?.fp_missed || 0)}</span>
            </td>
          </tr>
          <tr className="border-t border-gray-800">
            <td className="py-3">FP Caught</td>
            <td className="py-3 text-center">
              <span className="text-white font-semibold">{report?.fp_identified || 0}</span>
            </td>
          </tr>
          <tr className="border-t border-gray-800">
            <td className="py-3">FP Missed</td>
            <td className="py-3 text-center">
              <span className="text-white font-semibold">{report?.fp_missed || 0}</span>
            </td>
          </tr>
          <tr className="border-t border-gray-700">
            <td className="py-3 font-normal text-gray-300">Overall Grade</td>
            <td className="py-3 text-center">
              <span className="text-white font-bold text-xl">{(() => {
                if (!report?.total_actions) return '-';
                const acc = report.accuracy || 0;
                return acc >= 100 ? 'A' : acc >= 80 ? 'B' : acc >= 60 ? 'C' : acc >= 40 ? 'D' : 'F';
              })()}</span>
            </td>
          </tr>
        </tbody>
      </table>
      </div>
    </div>
  );
};

export default AnalystReportCard;
