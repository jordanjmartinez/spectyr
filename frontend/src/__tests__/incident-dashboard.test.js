/**
 * Stage 3.9B Dashboard, redesigned by Visual pass V5: the analytic
 * overview grid (session band; supporting column = Active Investigation +
 * Investigation Progress + Severity + Environment; main region = KPI stat
 * tiles + ATT&CK Coverage Matrix + Recent results). Invariants kept from
 * 3.9B: navigation-level actions only (never a graded Submit), no POST on
 * render, severity from /api/incidents stats (grouped-alerts never
 * called), the band's mode language, and Incident Grade vs Session
 * Performance staying distinct. V11: every value is an existing
 * observable or a post-submission disclosure; active incidents never
 * fetch grading.
 */
import React from 'react';
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react';
import IncidentDashboard from '../components/IncidentDashboard';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const INCIDENTS = {
  queue_length: 10, resolved_count: 1,
  active: [
    { incident_id: 'INC-1000', title: 'Loading Incident', severity: 'High', state: 'in_progress', sealed: false },
    { incident_id: 'INC-2000', title: 'Ready Incident', severity: 'Critical', state: 'in_progress', sealed: true, ready: true, open_detections: 0, triage: { total: 3, triaged: 3 }, related_actions: 2 },
  ],
  completed: [
    { incident_id: 'INC-3000', title: 'Done Incident', severity: 'Medium', state: 'submitted', assisted: true, submitted_at: '2026-07-19T12:00:00Z', incident_grade: { grade: 'B', accuracy: 84.0 } },
  ],
  // P8.2 (scaffold Section 3.5): severity stats ride on /api/incidents.
  stats: { severity_breakdown: { critical: 2, high: 1, medium: 0, low: 3 } },
};
const SCORE_3000 = {
  state: 'submitted', assisted: true,
  grading: {
    classification: { grade: 'A', accuracy: 100, category: 'Malware', verdict: 'threat', correct: true },
    detection: { grade: 'A', accuracy: 100 },
    response: { grade: 'C', accuracy: 75 },
    composite: { grade: 'B', accuracy: 84.0 },
  },
};
const ENDPOINTS = {
  endpoints: [
    { hostname: 'ACME-SVR02', status: 'online', os: 'Windows Server 2019', platform: 'windows', role: 'file' },
    { hostname: 'ACME-WS12', status: 'online', os: 'Windows 11 Pro', platform: 'windows', role: 'workstation' },
    { hostname: 'ACME-WS13', status: 'offline', os: 'Windows 11 Pro', platform: 'windows', role: 'workstation' },
  ],
};
// the focus incident's observable roster: 1 critical + 2 high detections
const FEED = {
  counts: { open: 4, promoted: 2, dismissed: 3 },
  detections: [
    { id: 'da', severity: 'critical' }, { id: 'db', severity: 'high' },
    { id: 'dc', severity: 'high' }, { id: 'dz', severity: 'low' },   // dz out of scope
  ],
};
const routeJson = (path) => {
  if (path === '/api/incidents') return INCIDENTS;
  if (path === '/api/analytics/report_card') return { state: 'submitted', grading: { composite: { grade: 'C', accuracy: 71.0 } } };
  if (path === '/api/endpoints') return ENDPOINTS;
  if (path === '/api/detections') return FEED;
  if (path === '/api/actions') return { actions: [{ outcome: 'success' }, { outcome: 'no_op' }, { outcome: 'success' }, { outcome: 'failed_precondition' }] };
  if (path === '/api/incidents/INC-3000/score') return SCORE_3000;
  if (path === '/api/incidents/INC-3000/triage-review') return { mitre: { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' } };
  if (path.endsWith('/scope')) return { incident_id: path.split('/')[3], sealed: true, hosts: [], accounts: [], detection_ids: ['da', 'db', 'dc'] };
  return {};
};
beforeEach(() => {
  apiFetch.mockReset();
  apiFetch.mockImplementation((path) => Promise.resolve({ ok: true, json: () => Promise.resolve(routeJson(path)) }));
});

test('renders the overview grid in reading order: A, B, then the main region', async () => {
  const { container } = render(<IncidentDashboard gameMode="analyst" analystName="A" />);
  await screen.findByText('INC-2000');
  // VL: the radar is SECONDARY -- it stacks beneath the operational
  // content and Recent results (the ruled hierarchy).
  const order = ['active-investigation', 'severity-distribution', 'environment-status', 'kpi-row', 'recent-results', 'attack-radar'];
  const nodes = order.map(id => container.querySelector(`[data-testid="${id}"]`));
  nodes.forEach(n => expect(n).not.toBeNull());
  for (let i = 0; i < nodes.length - 1; i += 1) {
    // eslint-disable-next-line no-bitwise
    expect(nodes[i].compareDocumentPosition(nodes[i + 1]) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  }
});

test('A: the Active Investigation card shows observable fields only and Resume navigates', async () => {
  const onSelectIncident = jest.fn();
  const onNavigate = jest.fn();
  render(<IncidentDashboard gameMode="analyst" activeIncidentId="INC-2000"
    onSelectIncident={onSelectIncident} onNavigate={onNavigate} />);
  const card = await screen.findByTestId('active-investigation');
  expect(within(card).getByText('INC-2000')).toBeInTheDocument();
  expect(within(card).getByText('Ready Incident')).toBeInTheDocument();
  expect(within(card).getByText('Critical')).toBeInTheDocument();
  expect(within(card).getByText('Detections reviewed: 3 of 3')).toBeInTheDocument();
  expect(within(card).getByText('Classification: not selected')).toBeInTheDocument();
  expect(within(card).getByText('Response actions taken: 2')).toBeInTheDocument();
  // never pre-submission correctness; never a graded Submit control
  expect(within(card).queryByText(/correct/i)).toBeNull();
  expect(screen.queryByRole('button', { name: /^Submit/ })).toBeNull();
  fireEvent.click(within(card).getByRole('button', { name: 'Resume investigation' }));
  expect(onSelectIncident).toHaveBeenCalledWith('INC-2000');
  expect(onNavigate).toHaveBeenCalledWith('incidents');
  // the second active incident rides as a compact row
  expect(within(card).getByText('INC-1000')).toBeInTheDocument();
});

test('VS: progress is folded INTO Active Investigation (accessible bar + exact text, no separate card)', async () => {
  render(<IncidentDashboard gameMode="analyst" activeIncidentId="INC-2000" chosen={{ 'INC-2000': { verdict: 'false_positive', category: 'False Positive' } }} />);
  const card = await screen.findByTestId('active-investigation');
  const bar = within(card).getByRole('progressbar');
  expect(bar).toHaveAttribute('aria-valuenow', '3');
  expect(bar).toHaveAttribute('aria-valuemax', '3');
  expect(within(card).getByText('Detections reviewed: 3 of 3')).toBeInTheDocument();
  expect(within(card).getByText('Classification: False Positive')).toBeInTheDocument();
  expect(within(card).getByText('Ready to submit')).toBeInTheDocument();
  // the fragmenting card is gone
  expect(screen.queryByTestId('investigation-progress')).toBeNull();
  expect(screen.queryByText('Investigation Progress')).toBeNull();
});

test('VS: severity bars show the active incident detections in order with exact counts', async () => {
  render(<IncidentDashboard gameMode="analyst" activeIncidentId="INC-2000" />);
  const card = await screen.findByTestId('severity-distribution');
  await waitFor(() => expect(within(card).getByText('Critical')).toBeInTheDocument());
  // row order + exact right-aligned counts (dz stays out: not in the scope)
  const rows = within(card).getAllByText(/^(Critical|High|Medium|Low)$/).map(el => el.textContent);
  expect(rows).toEqual(['Critical', 'High', 'Medium', 'Low']);
  const counts = Array.from(card.querySelectorAll('.tabular-nums')).map(el => el.textContent);
  expect(counts).toEqual(['1', '2', '0', '0']);
  expect(within(card).getByText('Active incident')).toBeInTheDocument();
  // no percentages implied, no correctness/hidden-answer vocabulary
  expect(card.textContent).not.toMatch(/%/);
  expect(card.textContent).not.toMatch(/correct|expected|true.positive|disposition/i);
});

test('VS: all-zero severity shows the honest empty state, never empty bars', async () => {
  apiFetch.mockImplementation((path) => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(path.endsWith('/scope')
      ? { incident_id: path.split('/')[3], sealed: false, hosts: [], accounts: [], detection_ids: [] }
      : routeJson(path)),
  }));
  render(<IncidentDashboard gameMode="analyst" activeIncidentId="INC-1000" />);
  const card = await screen.findByTestId('severity-distribution');
  await waitFor(() => expect(within(card).getByText('No detections observed yet.')).toBeInTheDocument());
  expect(card.querySelectorAll('[style*="width"]')).toHaveLength(0);
});

test('VS: environment status shows managed count, indicators, real availability, and real platform breakdown', async () => {
  const onNavigate = jest.fn();
  render(<IncidentDashboard gameMode="analyst" onNavigate={onNavigate} />);
  const card = await screen.findByTestId('environment-status');
  await waitFor(() => expect(within(card).getByText('3')).toBeInTheDocument());
  expect(card.textContent).toContain('managed hosts');
  expect(within(card).getByText('2')).toBeInTheDocument();       // online
  expect(within(card).getByText('1')).toBeInTheDocument();       // offline
  // availability = online / managed, exact and visible + sr equivalent
  expect(within(card).getByText('67%')).toBeInTheDocument();
  expect(card.textContent).toContain('2 of 3 managed hosts online (67% availability).');
  // platform breakdown from REAL fields only
  expect(card.textContent).toContain('Windows Server 1');
  expect(card.textContent).toContain('Windows Workstation 2');
  // no invented history or uptime claims
  expect(card.textContent).not.toMatch(/uptime|trend|last (week|month)|history/i);
  fireEvent.click(within(card).getByRole('button', { name: 'View endpoints' }));
  expect(onNavigate).toHaveBeenCalledWith('endpoints');
});

test('VS: zero managed hosts renders the honest environment empty state', async () => {
  apiFetch.mockImplementation((path) => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(path === '/api/endpoints' ? { endpoints: [] } : routeJson(path)),
  }));
  render(<IncidentDashboard gameMode="analyst" />);
  const card = await screen.findByTestId('environment-status');
  await waitFor(() => expect(within(card).getByText('No managed hosts available.')).toBeInTheDocument());
  expect(card.textContent).not.toMatch(/%/);
});

test('C: KPI tiles carry real session values only (no trends, deltas, or sparklines)', async () => {
  render(<IncidentDashboard gameMode="analyst" />);
  const row = await screen.findByTestId('kpi-row');
  await waitFor(() => expect(within(row).getByText('5')).toBeInTheDocument());   // 2 promoted + 3 dismissed
  expect(within(row).getByText('Detections reviewed')).toBeInTheDocument();
  expect(within(row).getByText('2')).toBeInTheDocument();                        // successes only
  expect(within(row).getByText('Response actions executed')).toBeInTheDocument();
  expect(within(row).getByText('Incidents completed')).toBeInTheDocument();
  expect(within(row).getByText('Latest incident grade')).toBeInTheDocument();
  expect(within(row).getByText('B')).toBeInTheDocument();
  expect(row.textContent).not.toMatch(/vs last|trend|%\s*change|[+-]\d+%/i);
});

test('E: Recent results is honestly labeled, newest first, from the frozen records', async () => {
  render(<IncidentDashboard gameMode="analyst" />);
  const card = await screen.findByTestId('recent-results');
  expect(within(card).getByText('Recent results')).toBeInTheDocument();
  expect(within(card).getByText(/This session/)).toBeInTheDocument();
  // grades + submitted category come from the served post-submission record
  await waitFor(() => expect(within(card).getByText('Malware')).toBeInTheDocument());
  expect(within(card).getByText('SOC Queue')).toBeInTheDocument();
  expect(within(card).getByText(/B · 84%/)).toBeInTheDocument();
  expect(within(card).getByText('C')).toBeInTheDocument();       // response grade
});

test('empty states are honest before any activity', async () => {
  apiFetch.mockImplementation((path) => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(path === '/api/incidents'
      ? { queue_length: 0, resolved_count: 0, active: [], completed: [], stats: { severity_breakdown: {} } }
      : routeJson(path)),
  }));
  render(<IncidentDashboard gameMode="analyst" />);
  expect(await screen.findByText('No active investigations.')).toBeInTheDocument();
  expect(screen.getByText('No detections observed yet.')).toBeInTheDocument();
  expect(screen.getByText(/No incidents submitted yet this session/)).toBeInTheDocument();
});

test('V6-R: the coverage radar carries no session/player overlay; grading is fetched ONLY for submitted ids', async () => {
  render(<IncidentDashboard gameMode="analyst" />);
  const radar = await screen.findByTestId('attack-radar');
  // catalog-coverage only: no tabs, no player-performance vocabulary
  expect(within(radar).queryByText('This session')).toBeNull();
  expect(within(radar).queryByText('Catalog coverage')).toBeNull();
  expect(radar.textContent).not.toMatch(/Incident Grade|submitted/i);
  // the frozen records feed Recent results alone; grading/triage endpoints
  // were touched ONLY for the submitted id (active ids never graded)
  await waitFor(() => expect(screen.getByText('Malware')).toBeInTheDocument());
  const graded = apiFetch.mock.calls
    .map(([p]) => String(p))
    .filter(p => p.includes('/score') || p.includes('/triage-review'));
  expect(graded.length).toBeGreaterThan(0);
  graded.forEach(p => expect(p).toContain('INC-3000'));
});

test('VH: Session performance is a KPI tile, distinct from the per-incident grade', async () => {
  render(<IncidentDashboard gameMode="analyst" />);
  await screen.findByText('INC-3000');
  const kpi = screen.getByTestId('kpi-row');
  expect(within(kpi).getByText('Session performance')).toBeInTheDocument();
  await waitFor(() => expect(within(kpi).getByText('71%')).toBeInTheDocument());  // session C 71%
  expect(screen.getByText(/B · 84%/)).toBeInTheDocument();               // incident grade row
  // the retired full-width banner is gone
  expect(screen.queryByText('Run completed')).toBeNull();
  expect(screen.queryByText('1 incident in this run')).toBeNull();
});

test('issues no state-changing (POST) call on render', async () => {
  render(<IncidentDashboard gameMode="training" />);
  await waitFor(() => expect(apiFetch).toHaveBeenCalledWith('/api/incidents'));
  const posts = apiFetch.mock.calls.filter(([, o]) => o && o.method && o.method !== 'GET');
  expect(posts).toHaveLength(0);
});

// P8.2 migration guard (retargeted by the VS correction): the severity
// card now reads the active incident's observable scope + the sanitized
// detections feed; the retired /api/grouped-alerts is STILL never called.
test('severity reads the observable scope + feed; grouped-alerts is never called', async () => {
  render(<IncidentDashboard gameMode="training" activeIncidentId="INC-2000" />);
  await screen.findByTestId('severity-distribution');
  await waitFor(() =>
    expect(apiFetch.mock.calls.some(([p]) => p === '/api/incidents/INC-2000/scope')).toBe(true));
  expect(apiFetch.mock.calls.some(([p]) => p === '/api/grouped-alerts')).toBe(false);
});

test('VH: the queue count is one compact line inside Active investigation (SOC Queue), with the mode badge', async () => {
  render(<IncidentDashboard gameMode="analyst" activeIncidentId="INC-2000" />);
  const card = await screen.findByTestId('active-investigation');
  await waitFor(() => expect(within(card).getByText('1 of 10 resolved')).toBeInTheDocument());
  expect(within(card).getByText('SOC Queue')).toBeInTheDocument();   // compact badge beside identity
});

test('VH: Guided carries no queue denominator anywhere', async () => {
  render(<IncidentDashboard gameMode="guided" activeIncidentId="INC-2000" />);
  await screen.findByTestId('active-investigation');
  expect(screen.queryByText(/of 10 resolved/)).toBeNull();
});
