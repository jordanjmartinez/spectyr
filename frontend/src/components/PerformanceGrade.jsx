import React, { useState, useEffect } from "react";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

const DARK_GRAY = "#374151";

const getGradeInfo = (accuracy) => {
  if (accuracy >= 90) return { grade: "A", color: "#6fa868" };
  if (accuracy >= 80) return { grade: "B", color: "#a3a35c" };
  if (accuracy >= 70) return { grade: "C", color: "#c28e46" };
  if (accuracy >= 60) return { grade: "D", color: "#c4755a" };
  return { grade: "F", color: "#b26666" };
};

const useIsMobile = () => {
  const [isMobile, setIsMobile] = useState(window.innerWidth < 640);
  useEffect(() => {
    const onResize = () => setIsMobile(window.innerWidth < 640);
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);
  return isMobile;
};

const PerformanceGrade = ({ report }) => {
  const [view, setView] = useState('grade');
  const isMobile = useIsMobile();

  const hasData = report && report.total_actions > 0;
  const accuracy = hasData ? parseFloat(report.accuracy) : 0;
  const { grade, color: ringColor } = hasData
    ? getGradeInfo(accuracy)
    : { grade: "?", color: DARK_GRAY };

  const gradeData = [
    { name: "Correct", value: hasData ? accuracy : 0 },
    { name: "Incorrect", value: hasData ? 100 - accuracy : 100 },
  ];

  const correct = hasData ? report.threats_caught : 0;
  const missed = hasData ? report.wrong_category : 0;
  const tp = hasData ? report.true_positives : 0;
  const fp = hasData ? report.false_positives_caught : 0;

  const barData = [
    { name: 'Correct', value: correct, fill: '#6fa868' },
    { name: 'Missed', value: missed, fill: '#b26666' },
    { name: isMobile ? 'TP' : 'True Positive', value: tp, fill: '#9ca3af' },
    { name: isMobile ? 'FP' : 'False Positive', value: fp, fill: '#9ca3af' },
  ];

  return (
    <div className="h-full flex flex-col">
      <h2 className="text-xl sm:text-2xl font-semibold text-white mb-4">
        {view === 'grade' ? 'Grade' : 'Accuracy'}
      </h2>
      <div className="bg-[#161b22] p-4 sm:p-6 rounded-2xl border border-gray-700 shadow-md flex flex-col items-center flex-1">
        <div className="flex items-center justify-end mb-4 w-full">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setView('grade')}
              className={`px-2 sm:px-3 py-1.5 text-xs sm:text-sm font-medium rounded-md border transition ${
                view === 'grade'
                  ? 'bg-[#30363d] text-white border-gray-600'
                  : 'bg-[#161b22] text-gray-400 border-gray-700 hover:text-gray-200'
              }`}
            >
              Grade
            </button>
            <button
              onClick={() => setView('accuracy')}
              className={`px-2 sm:px-3 py-1.5 text-xs sm:text-sm font-medium rounded-md border transition ${
                view === 'accuracy'
                  ? 'bg-[#30363d] text-white border-gray-600'
                  : 'bg-[#161b22] text-gray-400 border-gray-700 hover:text-gray-200'
              }`}
            >
              Accuracy
            </button>
          </div>
        </div>

        {view === 'grade' && (
          <div className="relative w-36 h-36 sm:w-56 sm:h-56 mx-auto border-dashed border-2 border-gray-700 rounded-full p-2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={gradeData} innerRadius="70%" outerRadius="100%" dataKey="value" startAngle={90} endAngle={-270} stroke="none">
                  <Cell fill={ringColor} />
                  <Cell fill={DARK_GRAY} />
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className={`text-4xl sm:text-7xl font-bold ${hasData ? 'text-white' : 'text-gray-500'}`}>{grade}</span>
            </div>
          </div>
        )}

        {view === 'accuracy' && (
          <div className="flex-1 w-full min-h-[220px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={barData} margin={{ top: 16, right: 10, left: -20, bottom: 10 }} barCategoryGap="20%">
                <CartesianGrid strokeDasharray="3 3" stroke="#21262d" vertical={false} />
                <XAxis
                  dataKey="name"
                  tick={{ fill: '#d1d5db', fontSize: isMobile ? 13 : 16, dy: 6 }}
                  axisLine={{ stroke: '#30363d' }}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: '#6b7280', fontSize: isMobile ? 13 : 16 }}
                  axisLine={false}
                  tickLine={false}
                  allowDecimals={false}
                />
                <Tooltip
                  cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                  contentStyle={{ backgroundColor: '#161b22', border: '1px solid #30363d', borderRadius: '8px', fontSize: '13px' }}
                  labelStyle={{ color: '#9ca3af' }}
                  itemStyle={{ color: '#e5e7eb' }}
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]} maxBarSize={44}>
                  {barData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </div>
  );
};

export default PerformanceGrade;
