import React from "react";

const AnalystReportCard = ({ report }) => {
  if (report?.error) {
    return <div className="text-red-400">Error loading report.</div>;
  }

  return (
    <div className="h-full flex flex-col">
      <h2 className="text-xl sm:text-2xl font-semibold text-white mb-4">Report Card</h2>

      <div className="bg-[#161b22] p-4 sm:p-6 rounded-2xl border border-gray-700 shadow-md flex-1">
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
            <td className="py-3 font-normal text-gray-300">Overall</td>
            <td className="py-3 text-center">
              <span className="text-white font-bold">{report?.accuracy || 0}%</span>
            </td>
          </tr>
        </tbody>
      </table>
      </div>
    </div>
  );
};

export default AnalystReportCard;
