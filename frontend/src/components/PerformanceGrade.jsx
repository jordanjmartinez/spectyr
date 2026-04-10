import React, { useState, useEffect } from "react";
import {
  BarChart,
  Bar,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

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
  const isMobile = useIsMobile();

  const hasData = report && report.total_actions > 0;
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
      <h2 className="text-xl sm:text-2xl font-semibold text-white mb-4">Accuracy</h2>
      <div className="bg-[#161b22] p-4 sm:p-6 rounded-2xl border border-gray-700 shadow-md flex flex-col items-center flex-1">
        <div className="flex-1 w-full flex items-center justify-center min-h-[220px]">
          <div className="w-full h-[220px]">
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
        </div>
      </div>
    </div>
  );
};

export default PerformanceGrade;
