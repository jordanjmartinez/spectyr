/**
 * VA3 (amendment section 5) + VD3 (visual-consistency correction,
 * section 4): the INCIDENT ATT&CK PROFILE, disclosed only across the
 * submission boundary. Before submission the card renders a neutral
 * locked state -- no tactic axes, no technique identities, no polygon,
 * no normalized values, in EVERY mode. After submission one polygon
 * shows the submitted incident's ATT&CK shape from its frozen record,
 * normalized against that incident's own strongest tactic. Never catalog
 * coverage, never framework coverage, never session performance, never a
 * second series. Absent tactics stay exactly 0%.
 */
import React from 'react';
import fs from 'fs';
import path from 'path';
import { render, screen, within, waitFor, act } from '@testing-library/react';
import AttackRadar, {
  NO_INCIDENT, NO_MAPPINGS, LOCKED, LOCKED_SUB,
} from '../components/AttackRadar';
import { incidentProfile, ATTACK_TACTICS, TECHNIQUE_NAMES } from '../components/attackCatalog';
import IncidentDashboard from '../components/IncidentDashboard';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

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

// ---- the temporal boundary (VD3) --------------------------------------------

test('before submission NOTHING renders: no tactics, no techniques, no polygon, no values', () => {
  // mappings are deliberately supplied -- the locked card must ignore them
  const { container } = render(
    <AttackRadar incidentId="INC-8340" submitted={false} mappings={EXAMPLE} />,
  );
  expect(screen.getByTestId('attack-radar-locked')).toBeInTheDocument();
  expect(screen.getByText(LOCKED)).toBeInTheDocument();
  expect(screen.getByText(LOCKED_SUB)).toBeInTheDocument();
  // no polygon, no rings, no dots
  expect(container.querySelector('.recharts-radar')).toBeNull();
  expect(container.querySelector('.recharts-wrapper')).toBeNull();
  // no tactic name, technique id, technique name, or normalized value
  // reaches the DOM -- not even in an accessible table
  for (const t of ATTACK_TACTICS) {
    expect(container.textContent).not.toContain(t);
  }
  expect(container.textContent).not.toMatch(/T\d{4}/);
  expect(container.textContent).not.toMatch(/\d+%/);
  expect(container.querySelector('table')).toBeNull();
});

test('the boundary is mode-independent: the component has no mode input at all', () => {
  // Guided and Hardcore share the same dashboard disclosure boundary
  // structurally: `submitted` is the only disclosure key, and neither the
  // card nor the dashboard branches the profile on the session mode.
  const radar = fs.readFileSync(path.join(__dirname, '..', 'components', 'AttackRadar.jsx'), 'utf8');
  expect(radar).not.toMatch(/gameMode|GUIDED|HARDCORE|MODE_LABEL/);
  const dash = fs.readFileSync(path.join(__dirname, '..', 'components', 'IncidentDashboard.jsx'), 'utf8');
  const radarCall = dash.match(/<AttackRadar[\s\S]*?\/>/)[0];
  expect(radarCall).toMatch(/submitted=\{profileSubmitted\}/);
  expect(radarCall).not.toMatch(/gameMode|isGuided/);
});

test('after submission the profile renders with markers, rings, and the exact tooltip identities', () => {
  const { container } = render(<AttackRadar incidentId="INC-8340" submitted mappings={EXAMPLE} />);
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
  const { container } = render(<AttackRadar incidentId="INC-8340" submitted mappings={EXAMPLE} />);
  expect(screen.getByText('Incident ATT&CK profile')).toBeInTheDocument();
  expect(screen.getByText('Tactics represented in this investigation')).toBeInTheDocument();
  expect(container.textContent).toMatch(/Relative to the strongest tactic in this incident\./);
  expect(container.textContent).not.toMatch(/catalog|coverage of|Enterprise ATT&CK v|represented \/ total/i);
  expect(container.textContent).not.toMatch(/mastery|session performance|adversar/i);
  // no tabs, selectors, expand, or list controls
  expect(screen.queryAllByRole('button')).toHaveLength(0);
  expect(screen.queryAllByRole('tab')).toHaveLength(0);
});

test('truthful states: no incident; a submitted incident with no mapped techniques; record loading', () => {
  const a = render(<AttackRadar incidentId={null} mappings={[]} />);
  expect(screen.getByText(NO_INCIDENT)).toBeInTheDocument();
  expect(a.container.querySelector('.recharts-radar')).toBeNull();   // no zero polygon
  a.unmount();
  const b = render(<AttackRadar incidentId="INC-1" submitted mappings={[]} />);
  expect(screen.getByText(NO_MAPPINGS)).toBeInTheDocument();
  expect(b.container.querySelector('.recharts-radar')).toBeNull();
  b.unmount();
  const c = render(<AttackRadar incidentId="INC-1" submitted mappings={null} />);
  expect(screen.getByText('Loading')).toBeInTheDocument();
  expect(c.container.querySelector('.recharts-radar')).toBeNull();
});

test('leak safety: the card never fetches; the dashboard derives mappings ONLY from frozen submitted records', () => {
  // comments may DESCRIBE the boundary; only executable code is scanned
  const src = fs.readFileSync(path.join(__dirname, '..', 'components', 'AttackRadar.jsx'), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  expect(src).not.toMatch(/apiFetch|answer|expected_|disposition|scenario_label/);
  const dash = fs.readFileSync(path.join(__dirname, '..', 'components', 'IncidentDashboard.jsx'), 'utf8');
  // the mappings derive from the per-submitted-id record (sealed roster
  // ids joined to the sanitized feed) -- never from the active scope
  expect(dash).toMatch(/const profileMappings = profileSubmitted/);
  expect(dash).toMatch(/profileRecord\.rosterIds\.has\(d\.id\) && d\.mitre/);
  expect(dash).not.toMatch(/profileMappings\s*=\s*scopedIds/);
});

// ---- dashboard integration (the boundary end to end) ------------------------

const FEED = {
  counts: { open: 0, promoted: 0, dismissed: 0 },
  detections: [
    { id: 'da', severity: 'high', mitre: { id: 'T1685', tactic: 'Defense Impairment', name: 'Impair Defenses' } },
    { id: 'db', severity: 'low', mitre: { id: 'T1046', tactic: 'Discovery', name: 'Network Service Discovery' } },
    { id: 'dz', severity: 'low', mitre: { id: 'T1090', tactic: 'Command and Control', name: 'Proxy' } },
  ],
};
const dashMock = ({ active, completed }) => {
  apiFetch.mockReset();
  apiFetch.mockImplementation((p) => {
    const ok = (b) => Promise.resolve({ ok: true, json: () => Promise.resolve(b) });
    if (p === '/api/incidents') {
      return ok({ queue_length: 1, resolved_count: 0, active, completed });
    }
    if (p === '/api/detections') return ok(FEED);
    if (p === '/api/endpoints') return ok({ endpoints: [] });
    if (p === '/api/actions') return ok({ actions: [] });
    if (p === '/api/analytics/report_card') return ok({ state: 'in_progress', progress: {} });
    if (String(p).endsWith('/score')) {
      return ok({ state: 'submitted', assisted: false, grading: { composite: { grade: 'A', accuracy: 100 } } });
    }
    if (String(p).endsWith('/triage-review')) return ok({ mitre: { id: 'T1685' } });
    if (String(p).endsWith('/scope')) {
      return ok({ incident_id: 'x', sealed: true, hosts: [], accounts: [], detection_ids: ['da', 'db'] });
    }
    if (String(p).startsWith('/api/events/query')) {
      return ok({ count: 0, rows: [], identity: { cutoff_seq: 1 } });
    }
    return ok({});
  });
};

const ACTIVE = {
  incident_id: 'INC-1000', title: 'Active', severity: 'High', state: 'in_progress',
  sealed: true, ready: false, open_detections: 1, triage: { total: 2, triaged: 1 },
};
const DONE = {
  incident_id: 'INC-2000', title: 'Done', severity: 'High', state: 'submitted',
  submitted_at: '2026-07-26T12:00:00Z', incident_grade: { grade: 'A', accuracy: 100 },
};

test('an ACTIVE focus locks the dashboard profile even with mitre-tagged roster detections', async () => {
  dashMock({ active: [ACTIVE], completed: [] });
  await act(async () => { render(<IncidentDashboard gameMode="hardcore" />); });
  const radar = await screen.findByTestId('attack-radar');
  expect(within(radar).getByText(LOCKED)).toBeInTheDocument();
  expect(radar.textContent).not.toContain('Defense Impairment');
  expect(radar.textContent).not.toMatch(/T\d{4}/);
  expect(radar.querySelector('.recharts-radar')).toBeNull();
});

test('with no active focus the latest submitted incident profiles from its frozen roster', async () => {
  dashMock({ active: [], completed: [DONE] });
  await act(async () => { render(<IncidentDashboard gameMode="guided" />); });
  const radar = await screen.findByTestId('attack-radar');
  // the frozen record arrives (score + scope fetched once), then the polygon
  await waitFor(() => expect(radar.querySelector('.recharts-radar')).not.toBeNull());
  // the profile carries exactly the roster detections' tactics (da + db);
  // the out-of-roster dz tactic (C2) contributes nothing
  const table = within(radar).getByRole('table');
  expect(within(table).getByText('Defense Impairment').closest('tr').textContent).toContain('100%');
  expect(within(table).getByText('Discovery').closest('tr').textContent).toContain('100%');
  expect(within(table).getByText('Command and Control').closest('tr').textContent).toContain('0%');
  expect(within(radar).queryByText(LOCKED)).toBeNull();
});
