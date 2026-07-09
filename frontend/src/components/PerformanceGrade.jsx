import React, { useState, useEffect } from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  ReferenceLine,
} from "recharts";

const formatDuration = (seconds) => {
  if (seconds == null || seconds < 0) return '0s';
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  if (m < 60) return s === 0 ? `${m}m` : `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  const rem = m % 60;
  return rem === 0 ? `${h}h` : `${h}h ${rem}m`;
};

const PieTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  const { name, value } = payload[0];
  if (name === 'Empty' || name === 'None') return null;
  return (
    <div style={{ backgroundColor: '#ffffff', border: '1px solid #e2e6ea', borderRadius: '8px', padding: '6px 12px', fontSize: '13px', whiteSpace: 'nowrap' }}>
      <span style={{ color: '#57606a' }}>{name}: <span style={{ color: '#1a2332', fontWeight: 600 }}>{value}</span></span>
    </div>
  );
};

const MttrTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  if (p.synthetic) return null;
  return (
    <div style={{ backgroundColor: '#ffffff', border: '1px solid #e2e6ea', borderRadius: '8px', padding: '6px 12px', fontSize: '13px', whiteSpace: 'nowrap' }}>
      <div style={{ color: '#57606a' }}>{p.incident_name || p.category || 'Scenario'}</div>
      <div style={{ color: '#1a2332', fontWeight: 600 }}>{formatDuration(p.seconds)}</div>
    </div>
  );
};

const GRADE_MESSAGES = {
  A: 'Pack it up. The attackers went home.',
  B: 'Clean work. The coffee is still warm.',
  C: 'You did not get called at 3 AM. Victory.',
  D: 'You are not fired. Congratulations.',
  F: 'You are the data breach.',
};

const PerformanceGrade = ({ report }) => {
  const [resultsView, setResultsView] = useState('grade');
  const [isSmUp, setIsSmUp] = useState(() => typeof window !== 'undefined' && window.matchMedia('(min-width: 640px)').matches);

  useEffect(() => {
    const mql = window.matchMedia('(min-width: 640px)');
    const onChange = (e) => setIsSmUp(e.matches);
    mql.addEventListener('change', onChange);
    return () => mql.removeEventListener('change', onChange);
  }, []);

  const hasData = report && report.total_actions > 0;
  const correct = hasData ? (report.threats_caught + report.fp_identified) : 0;
  const missed = hasData ? (report.wrong_category + report.fp_missed) : 0;
  const total = correct + missed;

  const grade = report?.grade || '-';

  const pieData = total === 0
    ? [{ name: 'Empty', value: 1 }]
    : [
        ...(correct > 0 ? [{ name: 'Correct', value: correct, color: '#6fa868' }] : []),
        ...(missed > 0 ? [{ name: 'Missed', value: missed, color: '#b26666' }] : []),
      ];

  const resolveTimes = report?.scenario_resolve_times || [];
  const mttrData = [
    { index: 0, seconds: 0, synthetic: true },
    ...resolveTimes.map((r, i) => ({
      index: i + 1,
      ticket_title: r.ticket_title,
      incident_name: r.incident_name,
      category: r.category,
      seconds: r.seconds,
      is_fp: r.is_fp,
      correct: r.correct,
    })),
  ];
  const avgMttr = report?.avg_time_to_resolve_seconds ?? 0;

  const MttrDot = (props) => {
    const { cx, cy, payload } = props;
    if (cx == null || cy == null) return null;
    if (payload?.synthetic) return null;
    const color = payload?.correct ? '#6fa868' : '#b26666';
    const size = 10;
    const half = size / 2;
    return (
      <rect
        x={cx - half}
        y={cy - half}
        width={size}
        height={size}
        fill="#ffffff"
        stroke={color}
        strokeWidth={2}
        transform={`rotate(45 ${cx} ${cy})`}
      />
    );
  };

  return (
    <div className="h-full flex flex-col">
      <h2 className="text-xl sm:text-2xl font-semibold text-[#1a2332] mb-4">Performance</h2>
      <div className="rounded-2xl p-4 sm:p-6 flex-1" style={{ background: '#ffffff', border: '1px solid #e2e6ea', boxShadow: '0 1px 2px rgba(0,0,0,0.04)' }}>
        <div className="flex flex-col gap-4">
          <div className="flex items-center justify-start gap-2">
            <button
              onClick={() => setResultsView('grade')}
              className={`px-2 sm:px-3 py-1.5 min-w-[5rem] sm:min-w-[6rem] text-xs sm:text-sm font-medium rounded-md border transition ${
                resultsView === 'grade'
                  ? 'bg-[#eef1f4] text-[#1a2332] border-[#8b949e]'
                  : 'bg-white text-[#57606a] border-[#e2e6ea] hover:text-[#1a2332]'
              }`}
            >
              Grade
            </button>
            <button
              onClick={() => setResultsView('mttr')}
              className={`px-2 sm:px-3 py-1.5 min-w-[5rem] sm:min-w-[6rem] text-xs sm:text-sm font-medium rounded-md border transition ${
                resultsView === 'mttr'
                  ? 'bg-[#eef1f4] text-[#1a2332] border-[#8b949e]'
                  : 'bg-white text-[#57606a] border-[#e2e6ea] hover:text-[#1a2332]'
              }`}
            >
              MTTR
            </button>
          </div>
          {resultsView !== 'mttr' ? (
          <div className="flex items-center justify-center">
            <div className="relative w-52 h-52 sm:w-72 sm:h-72 aspect-square border-dashed border-2 border-[#e2e6ea] rounded-full p-2">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    innerRadius="70%"
                    outerRadius="100%"
                    startAngle={90}
                    endAngle={-270}
                    dataKey="value"
                    stroke="#ffffff" strokeWidth={2}
                  >
                    {total === 0
                      ? [<Cell key="empty" fill="#e5e7eb" />]
                      : pieData.map((seg, i) => <Cell key={i} fill={seg.color} />)}
                  </Pie>
                  <Tooltip content={<PieTooltip />} wrapperStyle={{ zIndex: 20, outline: 'none', border: 'none' }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="text-7xl sm:text-9xl font-bold text-[#1a2332]">{grade}</span>
              </div>
            </div>
          </div>
          ) : (
          <div className="w-full h-52 sm:h-72">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={mttrData} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e6ea" />
                <XAxis dataKey="index" stroke="#9ca3af" tick={{ fill: '#9ca3af', fontSize: 14 }} tickFormatter={(v) => v === 0 ? '' : v} />
                <YAxis stroke="#9ca3af" tick={{ fill: '#9ca3af', fontSize: isSmUp ? 14 : 12 }} tickFormatter={(v) => formatDuration(v)} width={isSmUp ? 64 : 68} />
                <Tooltip content={<MttrTooltip />} wrapperStyle={{ zIndex: 20, outline: 'none', border: 'none' }} />
                {avgMttr > 0 && (
                  <ReferenceLine y={avgMttr} stroke="#8b949e" strokeDasharray="4 4" />
                )}
                <Line type="monotone" dataKey="seconds" stroke="#4b5563" strokeWidth={2} strokeDasharray="4 4" dot={<MttrDot />} activeDot={<MttrDot />} />
              </LineChart>
            </ResponsiveContainer>
          </div>
          )}
          <p className="font-mono text-xs sm:text-sm text-[#57606a] text-center">
            {resultsView !== 'mttr' && GRADE_MESSAGES[grade] ? (
              <>&gt;<span className="animate-blink">|</span> {GRADE_MESSAGES[grade]}</>
            ) : (
              <>&nbsp;</>
            )}
          </p>
        </div>
      </div>
    </div>
  );
};

export default PerformanceGrade;
