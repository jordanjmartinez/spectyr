import React, { useRef, useState, useEffect } from 'react';
import {
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, Tooltip,
} from 'recharts';
import { incidentProfile } from './attackCatalog';
import { CARD_STYLE, SectionLabel, LoadingState } from './ui';

// ============================================================================
// VA3 (amendment section 5) + VD3 (visual correction section 4): the
// INCIDENT ATT&CK PROFILE, disclosed only ACROSS THE SUBMISSION BOUNDARY.
//
// This chart is the ATT&CK shape of ONE incident. It is NOT catalog
// coverage, NOT Enterprise-framework coverage, NOT session performance,
// and never a two-series comparison.
//
// Disclosure (VD3, ruled): although each roster detection's mitre tag is
// individually visible in every mode, AGGREGATING them into a tactic
// shape biases the incident classification the player has not yet
// committed. So before submission the card renders ONLY the neutral
// locked state -- no tactic axes, no technique identities, no polygon,
// no normalized values, not even in the accessible table. The rule is
// mode-independent by construction (this component has no mode input;
// `submitted` is the only key), so Guided and Hardcore share the same
// dashboard boundary. After submission the profile renders from the
// incident's FROZEN roster (sealed at drip, immutable per the standing
// roster-finality invariant), so later content changes cannot mutate it.
//
// Normalization (ruled, unchanged): each tactic's mapped-technique count
// divided by the HIGHEST tactic count in this same incident, so the
// strongest tactic renders at 100% and the polygon reads as a full
// game-stat profile. Absent tactics stay exactly 0% -- no artificial
// minimum.
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
export const LOCKED = 'Available after submission.';
export const LOCKED_SUB = 'Complete the investigation to reveal the mapped tactics.';

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

const AttackRadar = ({
  isVisible = true, incidentId = null, submitted = false, mappings = null,
}) => {
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

  if (!incidentId) {
    return <Frame><p className="px-4 py-8 text-sm text-[#57606a]">{NO_INCIDENT}</p></Frame>;
  }
  // VD3: the temporal boundary. Before submission NOTHING derived from
  // the incident renders here -- mappings are ignored even if supplied.
  if (!submitted) {
    return (
      <Frame>
        <div className="px-4 py-8" data-testid="attack-radar-locked">
          <p className="text-sm font-medium text-[#1a2332]">{LOCKED}</p>
          <p className="text-sm text-[#57606a] mt-1">{LOCKED_SUB}</p>
        </div>
      </Frame>
    );
  }
  // the frozen record is still arriving (one fetch per submitted id)
  if (mappings === null) {
    return <Frame><LoadingState /></Frame>;
  }

  const profile = incidentProfile(mappings);
  // truthful states: never a meaningless zero polygon
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
