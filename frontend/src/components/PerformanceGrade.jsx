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
  const [isMobile, setIsMobile] = useState(window.innerWidth < 1024);
  useEffect(() => {
    const onResize = () => setIsMobile(window.innerWidth < 1024);
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
  const fpIdentified = hasData ? report.fp_identified : 0;
  const fpMissed = hasData ? report.fp_missed : 0;

  const barData = [
    { name: 'Correct', fullName: 'Correct', value: correct, fill: '#6fa868' },
    { name: 'Missed', fullName: 'Missed', value: missed, fill: '#b26666' },
    { name: 'FP Caught', fullName: 'FP Caught', value: fpIdentified, fill: '#9ca3af' },
    { name: 'FP Missed', fullName: 'FP Missed', value: fpMissed, fill: '#9ca3af' },
  ];

  return (
    <div className="h-full flex flex-col">
      <h2 className="text-xl sm:text-2xl font-semibold text-white mb-4">Results</h2>
      <div className="bg-[#161b22] px-4 pt-4 pb-3 sm:px-6 sm:pt-6 sm:pb-4 rounded-2xl border border-gray-700 shadow-md flex flex-col items-center flex-1">
        <div className="flex-1 w-full flex items-center justify-center min-h-[220px]">
          <div className="w-full h-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={barData} margin={{ top: 10, right: 4, left: 0, bottom: 0 }} barCategoryGap="20%">
                <CartesianGrid strokeDasharray="3 3" stroke="#21262d" vertical={false} />
                <XAxis
                  dataKey="name"
                  interval={0}
                  tick={{ fill: '#d1d5db', fontSize: isMobile ? 11 : 16, dy: isMobile ? 2 : 6 }}
                  axisLine={{ stroke: '#30363d' }}
                  tickLine={false}
                />
                <YAxis
                  domain={[0, 5]}
                  ticks={[0, 1, 2, 3, 4, 5]}
                  tick={{ fill: '#6b7280', fontSize: isMobile ? 13 : 16, textAnchor: 'end' }}
                  width={20}
                  axisLine={false}
                  tickLine={false}
                  allowDecimals={false}
                />
                <Tooltip
                  cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                  content={({ active, payload }) => {
                    if (!active || !payload?.length) return null;
                    const item = barData.find((d) => d.name === payload[0].payload.name);
                    const label = item ? item.fullName : payload[0].payload.name;
                    return (
                      <div style={{ backgroundColor: '#161b22', border: '1px solid #30363d', borderRadius: '8px', padding: '6px 12px', fontSize: '13px' }}>
                        <span style={{ color: '#e5e7eb' }}>{label}: <span style={{ color: '#fff', fontWeight: 600 }}>{payload[0].value}</span></span>
                      </div>
                    );
                  }}
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
