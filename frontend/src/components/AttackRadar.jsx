import React, { useRef, useState, useEffect } from 'react';
import {
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, Tooltip,
} from 'recharts';
import { ATTACK_VERSION, SOURCE_DATASET, coverageByTactic } from './attackCatalog';
import { CARD_STYLE, SectionLabel } from './ui';

// ============================================================================
// V6-R (owner correction): the ATT&CK coverage radar -- ONE restrained
// polygon across the canonical pinned v19.1 Enterprise tactics, replacing
// the scrolling matrix, its tabs, and its list view entirely.
//
// Axis value = techniques represented by Spectyr scenarios in that tactic
// divided by the AUTHORITATIVE number of Enterprise techniques in that
// tactic. Denominators are derived from the pinned STIX dataset
// (sha256-verified against the repo pin; provenance in the mirror's
// source_dataset), under one counting rule for both sides: parent
// techniques only. Percentages are never normalized against Spectyr's
// own largest category. No adversary overlay, no player-performance
// overlay, no animation (isAnimationActive false everywhere).
//
// Accessibility: the chart is presentation; the sr-only table beneath it
// is the complete text equivalent (tactic, represented, total, percent),
// and the hover tooltip shows the same four facts. Sizing follows the
// container width (window-resize listener only -- no ResizeObserver, per
// the standing radar precedent) and the chart renders only while the
// Dashboard tab is visible.
// ============================================================================

const ROWS = coverageByTactic();

// VL (owner correction): concise tactic labels on the chart itself; the
// canonical full names stay exposed through the tooltip and the sr
// table (and each label's SVG <title>).
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

const AngleTick = ({ payload, x, y, textAnchor }) => (
  <text x={x} y={y} textAnchor={textAnchor} fill="#57606a" fontSize={10}>
    <title>{payload.value}</title>
    {SHORT_TACTIC[payload.value] || payload.value}
  </text>
);

const RadarTooltip = ({ active, payload }) => {
  if (!active || !payload || !payload.length) return null;
  const d = payload[0].payload;
  return (
    <div className="rounded-md border border-[#e2e6ea] bg-white px-2.5 py-1.5 text-xs shadow-md">
      <p className="font-medium text-[#1a2332]">{d.tactic}</p>
      <p className="text-[#57606a]">{d.represented} of {d.total} techniques represented</p>
      <p className="text-[#57606a]">{d.pct}% coverage</p>
    </div>
  );
};

const AttackRadar = ({ isVisible = true }) => {
  const wrapRef = useRef(null);
  const [width, setWidth] = useState(440);

  useEffect(() => {
    const measure = () => {
      const w = wrapRef.current ? wrapRef.current.clientWidth : 0;
      // VL: near-square chart area, ~400-480px where available.
      setWidth(Math.max(300, Math.min(480, w || 440)));
    };
    measure();
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, []);

  const height = Math.round(width * 0.94);

  return (
    <div className="rounded-xl min-w-0" style={CARD_STYLE} data-testid="attack-radar">
      <div className="px-4 pt-4">
        <SectionLabel>ATT&amp;CK coverage</SectionLabel>
        <p className="t-meta text-[#6e7781]">Catalog technique coverage</p>
      </div>
      <div ref={wrapRef} className="px-1 flex justify-center" aria-hidden="true">
        {isVisible && (
          <RadarChart
            width={width}
            height={height}
            data={ROWS}
            cx="50%"
            cy="50%"
            outerRadius="76%"
            margin={{ top: 8, right: 8, bottom: 8, left: 8 }}
          >
            <PolarGrid stroke="#e2e6ea" />
            <PolarAngleAxis dataKey="tactic" tick={<AngleTick />} />
            {/* the radius labels sit off-axis (angle 18) so the ring
                percentages never overlap a tactic name */}
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
              strokeWidth={1.5}
              fill="#16436b"
              fillOpacity={0.14}
              isAnimationActive={false}
            />
            <Tooltip content={<RadarTooltip />} isAnimationActive={false} wrapperStyle={{ zIndex: 20 }} />
          </RadarChart>
        )}
      </div>

      {/* the complete text equivalent for screen readers */}
      <table className="sr-only">
        <caption>
          ATT&amp;CK coverage: Spectyr-represented techniques per tactic against the
          authoritative technique counts of {ATTACK_VERSION}, dataset {SOURCE_DATASET.tag}.
        </caption>
        <thead>
          <tr><th>Tactic</th><th>Represented techniques</th><th>Total techniques</th><th>Coverage</th></tr>
        </thead>
        <tbody>
          {ROWS.map((r) => (
            <tr key={r.tactic}>
              <td>{r.tactic}</td><td>{r.represented}</td><td>{r.total}</td><td>{r.pct}%</td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* concise footer; the full derivation rides the accessible info
          tooltip (the existing help-tip pattern) and the sr caption */}
      <div className="px-4 pb-3 text-[11px] text-[#8b949e] flex items-center gap-1.5">
        <span>v19.1 &middot; represented / total techniques per tactic</span>
        <button
          type="button"
          aria-label="Coverage data source"
          data-help={`${ATTACK_VERSION}. Coverage = scenario-represented techniques divided by the authoritative Enterprise technique count per tactic (dataset ${SOURCE_DATASET.tag}, parent-technique counting).`}
          className="help-tip w-4 h-4 rounded-full border border-[#d0d7de] text-[#8b949e] text-[10px] leading-none inline-flex items-center justify-center"
        >
          i
        </button>
      </div>
    </div>
  );
};

export default AttackRadar;
