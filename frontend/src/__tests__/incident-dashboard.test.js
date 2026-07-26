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
const routeJson = (path) => {
  if (path === '/api/incidents') return INCIDENTS;
  if (path === '/api/analytics/report_card') return { state: 'submitted', grading: { composite: { grade: 'C', accuracy: 71.0 } } };
  if (path === '/api/endpoints') return { endpoints: [{ hostname: 'H1', status: 'online' }] };
  if (path === '/api/detections') return { counts: { open: 4, promoted: 2, dismissed: 3 } };
  if (path === '/api/actions') return { actions: [{ outcome: 'success' }, { outcome: 'no_op' }, { outcome: 'success' }, { outcome: 'failed_precondition' }] };
  if (path === '/api/incidents/INC-3000/score') return SCORE_3000;
  if (path === '/api/incidents/INC-3000/triage-review') return { mitre: { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' } };
  return {};
};
beforeEach(() => {
  apiFetch.mockReset();
  apiFetch.mockImplementation((path) => Promise.resolve({ ok: true, json: () => Promise.resolve(routeJson(path)) }));
});

test('renders the overview grid in reading order: A, B, then the main region', async () => {
  const { container } = render(<IncidentDashboard gameMode="analyst" analystName="A" />);
  await screen.findByText('INC-2000');
  const order = ['active-investigation', 'investigation-progress', 'kpi-row', 'attack-radar', 'recent-results'];
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

test('B: Investigation Progress renders an accessible bar with its exact textual equivalent', async () => {
  render(<IncidentDashboard gameMode="analyst" activeIncidentId="INC-2000" chosen={{ 'INC-2000': { verdict: 'false_positive', category: 'False Positive' } }} />);
  const card = await screen.findByTestId('investigation-progress');
  const bar = within(card).getByRole('progressbar');
  expect(bar).toHaveAttribute('aria-valuenow', '3');
  expect(bar).toHaveAttribute('aria-valuemax', '3');
  expect(within(card).getByText('Detections reviewed: 3 of 3')).toBeInTheDocument();
  expect(within(card).getByText('Classification: False Positive')).toBeInTheDocument();
  expect(within(card).getByText('Ready to submit')).toBeInTheDocument();
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
  expect(screen.getByText('Progress appears when an investigation is active.')).toBeInTheDocument();
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

test('Incident Grade and Session Performance are both present and distinct', async () => {
  render(<IncidentDashboard gameMode="analyst" />);
  await screen.findByText('INC-3000');
  expect(screen.getByText('Session Performance')).toBeInTheDocument();
  expect(screen.getAllByText(/71%/).length).toBeGreaterThanOrEqual(1);   // session grade C 71%
  expect(screen.getByText(/B · 84%/)).toBeInTheDocument();               // incident grade row
});

test('issues no state-changing (POST) call on render', async () => {
  render(<IncidentDashboard gameMode="training" />);
  await waitFor(() => expect(apiFetch).toHaveBeenCalledWith('/api/incidents'));
  const posts = apiFetch.mock.calls.filter(([, o]) => o && o.method && o.method !== 'GET');
  expect(posts).toHaveLength(0);
});

// P8.2 migration guard: the severity widget renders from /api/incidents
// stats.severity_breakdown, and the retired /api/grouped-alerts is NEVER
// called by the Dashboard.
test('severity widget renders from /api/incidents stats; grouped-alerts is never called', async () => {
  render(<IncidentDashboard gameMode="training" />);
  const label = await screen.findByText('Severity distribution');
  const widget = label.parentElement;
  expect(widget.textContent).toContain('critical2');
  expect(widget.textContent).toContain('high1');
  expect(widget.textContent).toContain('medium0');
  expect(widget.textContent).toContain('low3');
  expect(apiFetch.mock.calls.some(([p]) => p === '/api/grouped-alerts')).toBe(false);
});

test('SOC Queue band shows the mode label and the queue denominator', async () => {
  render(<IncidentDashboard gameMode="analyst" />);
  await screen.findAllByText('SOC Queue');
  expect(screen.getByText(/of 10 resolved/)).toBeInTheDocument();   // N of 10
});

test('Guided band uses independent-run language, not a queue denominator', async () => {
  render(<IncidentDashboard gameMode="guided" />);   // resolved_count 1 in the mock
  await screen.findAllByText('Guided');
  expect(screen.getByText('Run completed')).toBeInTheDocument();
  expect(screen.queryByText(/of 10 resolved/)).toBeNull();
});
