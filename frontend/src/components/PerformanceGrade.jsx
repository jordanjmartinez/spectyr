import React from "react";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
} from "recharts";

const DARK_GRAY = "#374151";

const getGradeInfo = (accuracy) => {
  if (accuracy >= 90) return {
    grade: "A",
    color: "#10b981",
    feedback: "> Exceptional threat detection. You're ready for production."
  };
  if (accuracy >= 80) return {
    grade: "B",
    color: "#22c55e",
    feedback: "> Strong performance. Review the misses to reach the next level."
  };
  if (accuracy >= 70) return {
    grade: "C",
    color: "#eab308",
    feedback: "> Solid foundation. Focus on pattern recognition to improve."
  };
  if (accuracy >= 60) return {
    grade: "D",
    color: "#f97316",
    feedback: "> Keep practicing. Study the indicators you missed below."
  };
  return {
    grade: "F",
    color: "#ef4444",
    feedback: "> Take your time with each alert. Quality over speed."
  };
};

const PerformanceGrade = ({ report }) => {
  const hasData = report && report.total_actions > 0;
  const accuracy = hasData ? parseFloat(report.accuracy) : 0;
  const { grade, color: ringColor, feedback } = hasData
    ? getGradeInfo(accuracy)
    : { grade: "?", color: DARK_GRAY, feedback: "> Your performance grade will appear after your first triage." };

  const data = [
    { name: "Correct", value: hasData ? accuracy : 0 },
    { name: "Incorrect", value: hasData ? 100 - accuracy : 100 },
  ];

  return (
    <div>
      <h2 className="text-xl sm:text-2xl font-semibold text-white mb-4">Grade</h2>
      <div className="bg-[#161b22] p-4 sm:p-6 rounded-2xl border border-gray-700 shadow-md flex flex-col items-center">

      {/* Grade Circle */}
      <div className="relative w-36 h-36 sm:w-56 sm:h-56 mx-auto border-dashed border-2 border-gray-700 rounded-full p-2">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              innerRadius="70%"
              outerRadius="100%"
              dataKey="value"
              startAngle={90}
              endAngle={-270}
            >
              <Cell fill={ringColor} />
              <Cell fill={DARK_GRAY} />
            </Pie>
          </PieChart>
        </ResponsiveContainer>

        <div className="absolute inset-0 flex items-center justify-center">
          <span className={`text-4xl sm:text-7xl font-bold ${hasData ? 'text-white' : 'text-gray-500'}`}>{grade}</span>
        </div>
      </div>

      {/* Ghost Feedback */}
      <p className="mt-4 text-center text-xs sm:text-sm text-gray-400 font-mono">
        {feedback}
      </p>

      </div>
    </div>
  );
};

export default PerformanceGrade;
