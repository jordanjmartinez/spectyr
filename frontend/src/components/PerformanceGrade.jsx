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

const CARD_STYLE = { background: '#ffffff', border: '1px solid #e2e6ea', boxShadow: '0 1px 2px rgba(0,0,0,0.04)' };

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

// Grade: the Stage 3d headline COMPOSITE (40/30/30) as a gauge ring filled
// to the composite accuracy, letter in the center. The per-component
// breakdown sits beside it and the detailed sections below, so no weak
// component hides behind the headline.
export const GradeCard = ({ report }) => {
  const composite = report?.composite;
  const grade = composite?.grade || '-';
  const acc = composite?.accuracy;
  const graded = acc != null;

  const pieData = !graded
    ? [{ name: 'Empty', value: 1, color: '#e5e7eb' }]
    : [
        { name: 'Composite', value: acc, color: '#6fa868' },
        ...(acc < 100 ? [{ name: 'None', value: 100 - acc, color: '#e5e7eb' }] : []),
      ];

  return (
    <div className="h-full flex flex-col justify-center">
      <div className="flex flex-col gap-4">
        <div className="flex items-center justify-center">
          <div className="relative w-48 h-48 sm:w-64 sm:h-64 aspect-square border-dashed border-2 border-[#b4bcc4] rounded-full p-2">
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
                  {pieData.map((seg, i) => <Cell key={i} fill={seg.color} />)}
                </Pie>
                <Tooltip content={<PieTooltip />} wrapperStyle={{ zIndex: 20, outline: 'none', border: 'none' }} />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-6xl sm:text-8xl font-bold text-[#1a2332]">{grade}</span>
              {graded && <span className="mt-1 text-sm text-[#6e7781]">{acc}%</span>}
            </div>
          </div>
        </div>
        <p className="t-overline text-center">Composite grade · 40 / 30 / 30</p>
        <p className="text-sm text-[#57606a] text-center min-h-[1.25rem]">{GRADE_MESSAGES[grade] || ' '}</p>
      </div>
    </div>
  );
};

// MTTR: per-scenario time-to-resolve trend with the average reference line.
export const MttrCard = ({ report }) => {
  const [isSmUp, setIsSmUp] = useState(() => typeof window !== 'undefined' && window.matchMedia('(min-width: 640px)').matches);

  useEffect(() => {
    const mql = window.matchMedia('(min-width: 640px)');
    const onChange = (e) => setIsSmUp(e.matches);
    mql.addEventListener('change', onChange);
    return () => mql.removeEventListener('change', onChange);
  }, []);

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

  return (
    /* VF (section 5): Dashboard card anatomy -- the title sits inside the
       container (shared t-section token) and the card joins the page's
       rounded-xl radius (the one rounded-2xl drift is retired). */
    <div className="flex flex-col">
      <div className="rounded-xl p-4 sm:p-6 flex-1" style={CARD_STYLE}>
        <h2 className="t-section mb-4">Mean Time to Resolve</h2>
        <div className="w-full h-52 sm:h-64">
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
      </div>
    </div>
  );
};

export default GradeCard;
