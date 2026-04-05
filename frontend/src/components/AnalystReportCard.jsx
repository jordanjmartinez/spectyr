import React from "react";

const AnalystReportCard = ({ report }) => {
  if (report?.error) {
    return <div className="text-red-400">Error loading report.</div>;
  }

  return (
    <div className="bg-[#161b22] p-4 sm:p-6 rounded-2xl border border-gray-700 shadow-md h-full">
      <h2 className="text-xl sm:text-2xl font-semibold text-white mb-4">Report Card</h2>

      <table className="w-full text-sm sm:text-base mt-8">
        <thead>
          <tr className="text-sm sm:text-base text-gray-300 tracking-wider">
            <th className="text-left pb-3 font-medium">Category</th>
            <th className="text-center pb-3 font-medium w-16">Score</th>
          </tr>
        </thead>
        <tbody className="text-gray-300">
          <tr className="border-t border-gray-800">
            <td className="py-3">Correct</td>
            <td className="py-3 text-center">
              <span className="text-white font-semibold">{report?.threats_caught || 0}</span>
            </td>
          </tr>
          <tr className="border-t border-gray-800">
            <td className="py-3">Missed</td>
            <td className="py-3 text-center">
              <span className="text-white font-semibold">{report?.wrong_category || 0}</span>
            </td>
          </tr>
          <tr className="border-t border-gray-700">
            <td className="py-3 font-semibold text-gray-400">Accuracy</td>
            <td className="py-3 text-center">
              <span className="text-white font-bold">{report?.accuracy || 0}%</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  );
};

export default AnalystReportCard;
