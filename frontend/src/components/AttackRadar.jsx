import React, { useRef, useState, useEffect } from 'react';
import {
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, Tooltip,
} from 'recharts';
import { ATTACK_TACTICS, incidentProfile } from './attackCatalog';
import { CARD_STYLE, SectionLabel } from './ui';

// ============================================================================
// VA3 (amendment section 5): the INCIDENT ATT&CK PROFILE.
//
// This chart is the ATT&CK shape of the CURRENT ACTIVE INCIDENT. It is
// NOT catalog coverage, NOT Enterprise-framework coverage, NOT session
// performance, and never a two-series comparison.
//
// Data: the incident's roster detections' mitre mappings. Those tags are
// already rendered on every detection's detail view in EVERY mode, so
// aggregating them is not a new disclosure and never reads the answer
// key -- which is also why no mode needs a locked state here. (Were the
// source ever changed to answer-key techniques, Hardcore before
// submission would have to show the locked state instead; that
// constraint is recorded with the leak-safety tests.)
//
// Normalization (ruled): each tactic's mapped-technique count divided by
// the HIGHEST tactic count in this same incident, so the strongest
// tactic renders at 100% and the polygon reads as a full game-stat
// profile. Absent tactics stay exactly 0% -- no artificial minimum.
// ============================================================================

export const SHORT_TACTIC = {
  'Reconnaissance': 'Recon',
  'Resource Development': 'Resource Dev',
  'Initial Access': 'Initial Access',
  'Execution': 'Execution',
  'Persistence': 'Persistence',
  'Privilege Escalation': 'Priv Esc',
  'Stealth': 'Stealth',
  'Defense Impairment': 'Def Impairment',
  'Credential Access': 'Cred Access',
  'Discovery': 'Discovery',
  'Lateral Movement': 'Lateral Mvmt',
  'Collection': 'Collection',
  'Command and Control': 'C2',
  'Exfiltration': 'Exfil',
  'Impact': 'Impact',
};

export const NO_INCIDENT = 'Start an investigation to see its ATT&CK profile.';
export const NO_MAPPINGS = 'No ATT&CK techniques are mapped to this incident.';

const AngleTick = ({ payload, x, y, textAnchor }) => (
  <text x={x} y={y} textAnchor={textAnchor} fill="#57606a" fontSize={10}>
    <title>{payload.value}</title>
    {SHORT_TACTIC[payload.value] || payload.value}
  </text>
);

const ProfileTooltip = ({ active, payload }) => {
  if (!active || !payload || !payload.length) return null;
  const d = payload[0].payload;
  return (
    <div className="rounded-md border border-[#e2e6ea] bg-white px-2.5 py-1.5 text-xs shadow-md max-w-xs">
      <p className="font-medium text-[#1a2332]">{d.tactic}</p>
      <p className="text-[#57606a]">{d.count} technique{d.count === 1 ? '' : 's'}</p>
      {d.techniques.map((t) => (
        <p key={t.id} className="text-[#57606a]">
          <span className="log-mono">{t.id}</span> {t.name}
        </p>
      ))}
      <p className="text-[#57606a]">Relative incident profile: {d.pct}%</p>
    </div>
  );
};

const AttackRadar = ({ isVisible = true, incidentId = null, mappings = null }) => {
  const wrapRef = useRef(null);
  const [width, setWidth] = useState(440);

  useEffect(() => {
    const measure = () => {
      const w = wrapRef.current ? wrapRef.current.clientWidth : 0;
      setWidth(Math.max(300, Math.min(480, w || 440)));
    };
    measure();
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, []);

  const profile = incidentProfile(mappings);
  const height = Math.round(width * 0.94);

  const Frame = ({ children }) => (
    <div className="rounded-xl min-w-0" style={CARD_STYLE} data-testid="attack-radar">
      <div className="px-4 pt-4">
        <SectionLabel className="t-subsection">Incident ATT&amp;CK profile</SectionLabel>
        <p className="t-meta text-[#6e7781]">Tactics represented in this investigation</p>
      </div>
      {children}
    </div>
  );

  // truthful states: never a meaningless zero polygon
  if (!incidentId) {
    return <Frame><p className="px-4 py-8 text-sm text-[#57606a]">{NO_INCIDENT}</p></Frame>;
  }
  if (profile.max === 0) {
    return <Frame><p className="px-4 py-8 text-sm text-[#57606a]">{NO_MAPPINGS}</p></Frame>;
  }

  return (
    <Frame>
      <div ref={wrapRef} className="px-1 flex justify-center" aria-hidden="true">
        {isVisible && (
          <RadarChart
            width={width}
            height={height}
            data={profile.rows}
            cx="50%"
            cy="50%"
            outerRadius="76%"
            margin={{ top: 8, right: 8, bottom: 8, left: 8 }}
          >
            <PolarGrid stroke="#e2e6ea" />
            <PolarAngleAxis dataKey="tactic" tick={<AngleTick />} />
            {/* off-axis so ring labels never collide with tactic names */}
            <PolarRadiusAxis
              angle={18}
              domain={[0, 100]}
              tickCount={5}
              tick={{ fill: '#8b949e', fontSize: 9 }}
              tickFormatter={(v) => `${v}%`}
              stroke="#e2e6ea"
              axisLine={false}
            />
            <Radar
              dataKey="pct"
              stroke="#16436b"
              strokeWidth={2.5}
              fill="#16436b"
              fillOpacity={0.25}
              dot={{ r: 2.5, fill: '#16436b', stroke: '#ffffff', strokeWidth: 1 }}
              isAnimationActive={false}
            />
            <Tooltip content={<ProfileTooltip />} isAnimationActive={false} wrapperStyle={{ zIndex: 20 }} />
          </RadarChart>
        )}
      </div>

      {/* the complete text equivalent */}
      <table className="sr-only">
        <caption>
          Incident ATT&amp;CK profile for {incidentId}: mapped techniques per tactic,
          shown relative to the strongest tactic in this incident.
        </caption>
        <thead>
          <tr><th>Tactic</th><th>Techniques</th><th>Mapped techniques</th><th>Relative incident profile</th></tr>
        </thead>
        <tbody>
          {profile.rows.map((r) => (
            <tr key={r.tactic}>
              <td>{r.tactic}</td>
              <td>{r.count}</td>
              <td>{r.techniques.map((t) => `${t.id} ${t.name}`).join(', ') || 'none'}</td>
              <td>{r.pct}%</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="px-4 pb-3 text-[11px] text-[#8b949e]">
        Relative to the strongest tactic in this incident.
      </div>
    </Frame>
  );
};

export default AttackRadar;
