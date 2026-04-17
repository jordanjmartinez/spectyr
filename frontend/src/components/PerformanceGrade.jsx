import React, { useState } from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

const PieTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  const { name, value } = payload[0];
  if (name === 'Empty' || name === 'None') return null;
  return (
    <div style={{ backgroundColor: '#161b22', border: '1px solid #30363d', borderRadius: '8px', padding: '6px 12px', fontSize: '13px' }}>
      <span style={{ color: '#e5e7eb' }}>{name}: <span style={{ color: '#fff', fontWeight: 600 }}>{value}</span></span>
    </div>
  );
};

const PerformanceGrade = ({ report }) => {
  const [resultsView, setResultsView] = useState('threats');

  const hasData = report && report.total_actions > 0;
  const threatsCorrect = hasData ? report.threats_caught : 0;
  const threatsMissed = hasData ? report.wrong_category : 0;
  const fpCorrect = hasData ? report.fp_identified : 0;
  const fpMissed = hasData ? report.fp_missed : 0;

  const correct = resultsView === 'threats' ? threatsCorrect : fpCorrect;
  const missed = resultsView === 'threats' ? threatsMissed : fpMissed;
  const total = correct + missed;

  const grade = (() => {
    if (!report?.total_actions) return '-';
    const acc = report.accuracy || 0;
    return acc >= 100 ? 'A' : acc >= 80 ? 'B' : acc >= 60 ? 'C' : acc >= 40 ? 'D' : 'F';
  })();

  const pieData = total === 0
    ? [{ name: 'Empty', value: 1 }]
    : [
        ...(correct > 0 ? [{ name: 'Correct', value: correct, color: '#6fa868' }] : []),
        ...(missed > 0 ? [{ name: 'Missed', value: missed, color: '#b26666' }] : []),
      ];

  return (
    <div className="h-full flex flex-col">
      <h2 className="text-xl sm:text-2xl font-semibold text-white mb-4">
        {resultsView === 'threats' ? 'Threats' : 'False Positives'}
      </h2>
      <div className="rounded-2xl p-4 sm:p-6 flex-1" style={{ background: 'linear-gradient(#161b22, #161b22) padding-box, linear-gradient(to bottom, rgba(88,130,180,0.3), transparent) border-box', border: '1px solid transparent', boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05)' }}>
        <div className="flex flex-col gap-4">
          <div className="flex items-center justify-start gap-2">
            <button
              onClick={() => setResultsView('threats')}
              className={`px-2 sm:px-3 py-1.5 text-xs sm:text-sm font-medium rounded-md border transition ${
                resultsView === 'threats'
                  ? 'bg-[#30363d] text-white border-gray-600'
                  : 'bg-[#161b22] text-gray-400 border-gray-700 hover:text-gray-200'
              }`}
            >
              Threats
            </button>
            <button
              onClick={() => setResultsView('fp')}
              className={`px-2 sm:px-3 py-1.5 text-xs sm:text-sm font-medium rounded-md border transition ${
                resultsView === 'fp'
                  ? 'bg-[#30363d] text-white border-gray-600'
                  : 'bg-[#161b22] text-gray-400 border-gray-700 hover:text-gray-200'
              }`}
            >
              <span className="sm:hidden">False Pos</span>
              <span className="hidden sm:inline">False Positives</span>
            </button>
          </div>
          <div className="flex flex-col items-center gap-4 sm:gap-6 lg:flex-row-reverse lg:items-center">
            <div className="flex-shrink-0 flex items-center lg:pr-2 xl:pr-6">
              <div className="relative w-36 h-36 sm:w-80 sm:h-80 md:w-40 md:h-40 lg:w-56 lg:h-56 xl:w-80 xl:h-80 aspect-square border-dashed border-2 border-gray-700 rounded-full p-2">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      innerRadius="70%"
                      outerRadius="100%"
                      startAngle={90}
                      endAngle={-270}
                      dataKey="value"
                      stroke="none"
                    >
                      {total === 0
                        ? [<Cell key="empty" fill="#374151" />]
                        : pieData.map((seg, i) => <Cell key={i} fill={seg.color} />)}
                    </Pie>
                    <Tooltip content={<PieTooltip />} wrapperStyle={{ zIndex: 20, outline: 'none', border: 'none' }} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                  <span className="text-5xl sm:text-8xl md:text-6xl lg:text-7xl xl:text-8xl font-bold text-white">{grade}</span>
                </div>
              </div>
            </div>
            <div className="min-w-0 flex items-center lg:flex-1 lg:pl-4 xl:pl-6">
              <div className="grid grid-cols-2 gap-x-4 gap-y-2 sm:gap-y-3 lg:grid-cols-1 lg:gap-3 text-xs sm:text-base md:text-xs lg:text-sm">
                <div className="flex items-center gap-1.5 min-w-0">
                  <span className="w-2.5 h-2.5 flex-shrink-0 rounded-md" style={{backgroundColor: '#6fa868'}} />
                  <span className="text-gray-300 truncate">Correct</span>
                  <span className="text-white font-semibold flex-shrink-0">{correct}</span>
                </div>
                <div className="flex items-center gap-1.5 min-w-0">
                  <span className="w-2.5 h-2.5 flex-shrink-0 rounded-md" style={{backgroundColor: '#b26666'}} />
                  <span className="text-gray-300 truncate">Missed</span>
                  <span className="text-white font-semibold flex-shrink-0">{missed}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PerformanceGrade;
