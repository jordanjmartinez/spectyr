/**
 * VA3 (amendment section 5): the INCIDENT ATT&CK PROFILE. One polygon
 * showing the ATT&CK shape of the CURRENT ACTIVE INCIDENT, normalized
 * against that incident's own strongest tactic. Never catalog coverage,
 * never Enterprise-framework coverage, never session performance, never
 * a second series. Absent tactics stay exactly 0%.
 */
import React from 'react';
import fs from 'fs';
import path from 'path';
import { render, screen, within } from '@testing-library/react';
import AttackRadar, { NO_INCIDENT, NO_MAPPINGS } from '../components/AttackRadar';
import { incidentProfile, ATTACK_TACTICS, TECHNIQUE_NAMES } from '../components/attackCatalog';

// the amendment's worked example
const EXAMPLE = [
  { id: 'T1685', tactic: 'Defense Impairment' },
  { id: 'T1685.005', tactic: 'Defense Impairment' },
  { id: 'T1036.005', tactic: 'Defense Impairment' },
  { id: 'T1218.011', tactic: 'Stealth' },
  { id: 'T1090', tactic: 'Command and Control' },
  { id: 'T1071.001', tactic: 'Command and Control' },
  { id: 'T1046', tactic: 'Discovery' },
];

const rowFor = (rows, tactic) => rows.find((r) => r.tactic === tactic);

test('normalization is incident-relative: strongest tactic is 100%, others proportional, absent 0%', () => {
  const { rows, max } = incidentProfile(EXAMPLE);
  expect(max).toBe(3);
  expect(rowFor(rows, 'Defense Impairment')).toMatchObject({ count: 3, pct: 100 });
  expect(rowFor(rows, 'Command and Control')).toMatchObject({ count: 2, pct: 67 });
  expect(rowFor(rows, 'Stealth')).toMatchObject({ count: 1, pct: 33 });
  expect(rowFor(rows, 'Discovery')).toMatchObject({ count: 1, pct: 33 });
  // every other tactic is EXACTLY zero -- no artificial minimum
  const named = new Set(EXAMPLE.map((m) => m.tactic));
  rows.filter((r) => !named.has(r.tactic)).forEach((r) => {
    expect([r.tactic, r.count, r.pct]).toEqual([r.tactic, 0, 0]);
  });
  // canonical tactic order preserved
  expect(rows.map((r) => r.tactic)).toEqual(ATTACK_TACTICS);
});

test('duplicate technique ids within a tactic count once', () => {
  const { rows, max } = incidentProfile([
    { id: 'T1685', tactic: 'Defense Impairment' },
    { id: 'T1685', tactic: 'Defense Impairment' },
    { id: 'T1046', tactic: 'Discovery' },
  ]);
  expect(max).toBe(1);
  expect(rowFor(rows, 'Defense Impairment').count).toBe(1);
  expect(rowFor(rows, 'Defense Impairment').pct).toBe(100);
  expect(rowFor(rows, 'Discovery').pct).toBe(100);
});

test('no catalog-wide data feeds the profile (scenario counts are never read)', () => {
  const empty = incidentProfile([]);
  expect(empty.max).toBe(0);
  expect(empty.rows.every((r) => r.count === 0 && r.pct === 0)).toBe(true);
  // the component must not import the catalog coverage helper
  const src = fs.readFileSync(path.join(__dirname, '..', 'components', 'AttackRadar.jsx'), 'utf8');
  expect(src).not.toMatch(/coverageByTactic|TACTIC_TOTALS|scenarios/);
});

test('renders one polygon with markers, rings, and the exact tooltip identities', () => {
  const { container } = render(<AttackRadar incidentId="INC-8340" mappings={EXAMPLE} />);
  expect(container.querySelectorAll('.recharts-radar')).toHaveLength(1);
  for (const ring of ['0%', '25%', '50%', '75%', '100%']) {
    expect(container.textContent).toContain(ring);
  }
  expect(container.querySelectorAll('.recharts-radar-dot').length).toBeGreaterThan(0);
  // the text equivalent carries tactic, count, technique identities, percent
  const table = screen.getByRole('table');
  const di = within(table).getByText('Defense Impairment').closest('tr');
  expect(di.textContent).toContain('3');
  expect(di.textContent).toContain('T1685.005');
  expect(di.textContent).toContain(TECHNIQUE_NAMES['T1685.005']);
  expect(di.textContent).toContain('100%');
  expect(container.querySelector('caption').textContent).toMatch(/INC-8340/);
});

test('card copy is the incident profile, never a framework-coverage claim', () => {
  const { container } = render(<AttackRadar incidentId="INC-8340" mappings={EXAMPLE} />);
  expect(screen.getByText('Incident ATT&CK profile')).toBeInTheDocument();
  expect(screen.getByText('Tactics represented in this investigation')).toBeInTheDocument();
  expect(container.textContent).toMatch(/Relative to the strongest tactic in this incident\./);
  expect(container.textContent).not.toMatch(/catalog|coverage of|Enterprise ATT&CK v|represented \/ total/i);
  expect(container.textContent).not.toMatch(/mastery|session performance|adversar/i);
  // no tabs, selectors, expand, or list controls
  expect(screen.queryAllByRole('button')).toHaveLength(0);
  expect(screen.queryAllByRole('tab')).toHaveLength(0);
});

test('truthful states: no incident, and an incident with no mapped techniques', () => {
  const a = render(<AttackRadar incidentId={null} mappings={[]} />);
  expect(screen.getByText(NO_INCIDENT)).toBeInTheDocument();
  expect(a.container.querySelector('.recharts-radar')).toBeNull();   // no zero polygon
  a.unmount();
  const b = render(<AttackRadar incidentId="INC-1" mappings={[]} />);
  expect(screen.getByText(NO_MAPPINGS)).toBeInTheDocument();
  expect(b.container.querySelector('.recharts-radar')).toBeNull();
});

test('leak safety: the profile reads only already-visible detection mappings', () => {
  // The dashboard feeds mitre tags from the incident roster's detections
  // -- data every detection detail already renders in every mode. The
  // card itself never fetches and never sees answer-key material.
  // comments may DESCRIBE the boundary; only executable code is scanned
  const src = fs.readFileSync(path.join(__dirname, '..', 'components', 'AttackRadar.jsx'), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  expect(src).not.toMatch(/apiFetch|answer|expected_|disposition|scenario_label/);
  const dash = fs.readFileSync(path.join(__dirname, '..', 'components', 'IncidentDashboard.jsx'), 'utf8');
  // the mappings come from the sanitized feed joined to the observable
  // scope -- never from triage-review or any grading payload
  expect(dash).toMatch(/profileMappings\s*=\s*scopedIds/);
  expect(dash).toMatch(/feed\.filter\(d => scopedIds\.has\(d\.id\) && d\.mitre/);
});
