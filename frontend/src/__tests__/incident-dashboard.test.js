/**
 * Stage 3.9B Dashboard, redesigned by Visual pass V5: the analytic
 * overview grid (session band; supporting column = Active Investigation +
 * Investigation Progress + Severity + Environment; main region = KPI stat
 * tiles + ATT&CK Coverage Matrix + Recent Results). Invariants kept from
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
  if (path.endsWith('/scope')) return { incident_id: path.split('/')[3], sealed: true, hosts: [], accounts: [], detection_ids: ['da', 'db', 'dc'] };
  return {};
};
beforeEach(() => {
  apiFetch.mockReset();
  apiFetch.mockImplementation((path) => Promise.resolve({ ok: true, json: () => Promise.resolve(routeJson(path)) }));
});

test('renders the overview grid in reading order: A, B, then the main region', async () => {
  const { container } = render(<IncidentDashboard gameMode="hardcore" analystName="A" />);
  await screen.findByText('INC-2000');
  // VB1 (amendment section 1): the ruled narrow stack order --
  // Active Investigation, KPI summary, Evidence Activity, Severity,
  // Environment, ATT&CK profile, Recent Results. Evidence Activity is
  // the primary visualization; the ATT&CK profile stays secondary.
  const order = ['active-investigation', 'kpi-row', 'evidence-activity',
                 'severity-distribution', 'environment-status',
                 'recent-results'];
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
  render(<IncidentDashboard gameMode="hardcore" activeIncidentId="INC-2000"
    onSelectIncident={onSelectIncident} onNavigate={onNavigate} />);
  const card = await screen.findByTestId('active-investigation');
  expect(within(card).getByText('INC-2000')).toBeInTheDocument();
  expect(within(card).getByText('Ready Incident')).toBeInTheDocument();
  expect(within(card).getByText('Critical')).toBeInTheDocument();
  // owner UI pass (2026-10-12): the detail lines are removed -- identity,
  // title, and Resume only (the KPI strip and the workspace own the rest)
  expect(within(card).queryByText(/Detections Reviewed:/)).toBeNull();
  expect(within(card).queryByText(/Classification:/)).toBeNull();
  expect(within(card).queryByText(/Response Actions Taken:/)).toBeNull();
  expect(within(card).queryByText(/to Review$/)).toBeNull();
  // never pre-submission correctness; never a graded Submit control
  expect(within(card).queryByText(/correct/i)).toBeNull();
  expect(screen.queryByRole('button', { name: /^Submit/ })).toBeNull();
  // owner layout pass 2 (2026-10-12): the stage line is gone entirely; in
  // its place the View incidents link -- bottom-right, View-endpoints style
  expect(within(card).queryByText('Ready to Submit')).toBeNull();
  expect(within(card).queryByText(/Detections to Triage/)).toBeNull();
  const viewIncidents = within(card).getByRole('button', { name: 'View incidents' });
  expect(viewIncidents.parentElement.className).toMatch(/justify-end/);
  expect(viewIncidents.className).toMatch(/text-\[#16436b\]/);
  fireEvent.click(viewIncidents);
  expect(onNavigate).toHaveBeenCalledWith('incidents');
  expect(onSelectIncident).not.toHaveBeenCalled();     // plural link: no selection
  // the Resume button stays removed; row navigation still works via the
  // other-active compact rows
  expect(within(card).queryByRole('button', { name: 'Resume investigation' })).toBeNull();
  fireEvent.click(within(card).getByText('INC-1000').closest('button'));
  expect(onSelectIncident).toHaveBeenCalledWith('INC-1000');
});

test('VS: progress is folded INTO Active Investigation (accessible bar, no separate card)', async () => {
  render(<IncidentDashboard gameMode="hardcore" activeIncidentId="INC-2000" chosen={{ 'INC-2000': { verdict: 'false_positive', category: 'False Positive' } }} />);
  const card = await screen.findByTestId('active-investigation');
  const bar = within(card).getByRole('progressbar');
  expect(bar).toHaveAttribute('aria-valuenow', '3');
  expect(bar).toHaveAttribute('aria-valuemax', '3');
  // owner UI pass (2026-10-12): the visible detail lines are removed; the
  // bar stays as the one glanceable visual and its ACCESSIBLE LABEL still
  // carries the exact reviewed count
  expect(bar).toHaveAttribute('aria-label', 'Detections Reviewed: 3 of 3');
  expect(within(card).queryByText('Detections Reviewed: 3 of 3')).toBeNull();
  expect(within(card).queryByText('Classification: False Positive')).toBeNull();
  // owner layout pass 2 (2026-10-12): the stage line is removed entirely
  // (even when Ready); the View incidents link stands in its place
  expect(within(card).queryByText('Ready to Submit')).toBeNull();
  expect(within(card).getByRole('button', { name: 'View incidents' })).toBeInTheDocument();
  // the fragmenting card is gone
  expect(screen.queryByTestId('investigation-progress')).toBeNull();
  expect(screen.queryByText('Investigation Progress')).toBeNull();
});

test('VS: severity bars show the active incident detections in order with exact counts', async () => {
  render(<IncidentDashboard gameMode="hardcore" activeIncidentId="INC-2000" />);
  const card = await screen.findByTestId('severity-distribution');
  await waitFor(() => expect(within(card).getByText('Critical')).toBeInTheDocument());
  // row order + exact right-aligned counts (dz stays out: not in the scope)
  const rows = within(card).getAllByText(/^(Critical|High|Medium|Low)$/).map(el => el.textContent);
  expect(rows).toEqual(['Critical', 'High', 'Medium', 'Low']);
  const counts = Array.from(card.querySelectorAll('.tabular-nums')).map(el => el.textContent);
  expect(counts).toEqual(['1', '2', '0', '0']);
  // owner UI pass (2026-10-12): card subtitles are stripped -- title +
  // content only, like Environment status
  expect(within(card).queryByText('Active incident')).toBeNull();
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
  render(<IncidentDashboard gameMode="hardcore" activeIncidentId="INC-1000" />);
  const card = await screen.findByTestId('severity-distribution');
  await waitFor(() => expect(within(card).getByText('No detections observed yet.')).toBeInTheDocument());
  expect(card.querySelectorAll('[style*="width"]')).toHaveLength(0);
});

test('VS: environment status is ONE state-first line plus View endpoints', async () => {
  const onNavigate = jest.fn();
  render(<IncidentDashboard gameMode="hardcore" onNavigate={onNavigate} />);
  const card = await screen.findByTestId('environment-status');
  // owner UI pass (2026-10-12): the four restatements of the same fact
  // collapse to a status dot + "N/M Hosts Online" (2 of 3 online here)
  await waitFor(() => expect(within(card).getByText('2/3 Hosts Online')).toBeInTheDocument());
  expect(card.textContent).not.toMatch(/managed hosts|Availability|%/);
  expect(card.textContent).not.toMatch(/Windows Server|Windows Workstation/);
  expect(within(card).queryByText(/Offline/)).toBeNull();
  // no invented history or uptime claims
  expect(card.textContent).not.toMatch(/uptime|trend|last (week|month)|history/i);
  // owner layout pass 2 (2026-10-12): the link sits bottom-right
  const viewEndpoints = within(card).getByRole('button', { name: 'View endpoints' });
  expect(viewEndpoints.parentElement.className).toMatch(/justify-end/);
  fireEvent.click(viewEndpoints);
  expect(onNavigate).toHaveBeenCalledWith('endpoints');
});

test('VS: zero managed hosts renders the honest environment empty state', async () => {
  apiFetch.mockImplementation((path) => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(path === '/api/endpoints' ? { endpoints: [] } : routeJson(path)),
  }));
  render(<IncidentDashboard gameMode="hardcore" />);
  const card = await screen.findByTestId('environment-status');
  await waitFor(() => expect(within(card).getByText('No managed hosts available.')).toBeInTheDocument());
  expect(card.textContent).not.toMatch(/%/);
});

test('C: KPI tiles carry real session values only (no trends, deltas, or sparklines)', async () => {
  render(<IncidentDashboard gameMode="hardcore" />);
  const row = await screen.findByTestId('kpi-row');
  await waitFor(() => expect(within(row).getByText('5')).toBeInTheDocument());   // 2 promoted + 3 dismissed
  expect(within(row).getByText('Detections Reviewed')).toBeInTheDocument();
  expect(within(row).getByText('2')).toBeInTheDocument();                        // successes only
  // owner UI pass (2026-10-12): shortened from "Response Actions Executed"
  expect(within(row).getByText('Response Actions')).toBeInTheDocument();
  expect(within(row).getByText('Incidents Completed')).toBeInTheDocument();
  expect(within(row).getByText('Latest Incident Grade')).toBeInTheDocument();
  expect(within(row).getByText('B')).toBeInTheDocument();
  expect(row.textContent).not.toMatch(/vs last|trend|%\s*change|[+-]\d+%/i);
});

test('E: Recent Results is honestly labeled, newest first, from the frozen records', async () => {
  render(<IncidentDashboard gameMode="hardcore" />);
  const card = await screen.findByTestId('recent-results');
  expect(within(card).getByText('Recent Results')).toBeInTheDocument();
  // owner UI pass (2026-10-12): the "This session" subtitle is stripped
  expect(within(card).queryByText(/This session/)).toBeNull();
  // grades + submitted category come from the served post-submission record
  await waitFor(() => expect(within(card).getByText('Malware')).toBeInTheDocument());
  expect(within(card).getByText('Hardcore')).toBeInTheDocument();
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
  render(<IncidentDashboard gameMode="hardcore" />);
  expect(await screen.findByText('No active investigations.')).toBeInTheDocument();
  expect(screen.getByText('No detections observed yet.')).toBeInTheDocument();
  expect(screen.getByText(/No incidents submitted yet this session/)).toBeInTheDocument();
});

test('the ATT&CK matrix is gone entirely; grading fetched ONLY for submitted ids (score view alone)', async () => {
  render(<IncidentDashboard gameMode="hardcore" activeIncidentId="INC-2000" />);
  // owner layout pass (2026-10-12): the Session ATT&CK Coverage card and
  // its grid are removed from the dashboard
  await screen.findByTestId('active-investigation');
  expect(screen.queryByTestId('attack-matrix')).toBeNull();
  expect(screen.queryByText('Session ATT&CK Coverage')).toBeNull();
  // the frozen records feed Recent Results alone; grading endpoints were
  // touched ONLY for the submitted id (active ids never graded); the
  // triage-review and per-submitted scope fetches are retired with the card
  await waitFor(() => expect(screen.getByText('Malware')).toBeInTheDocument());
  const graded = apiFetch.mock.calls
    .map(([p]) => String(p))
    .filter(p => p.includes('/score') || p.includes('/triage-review'));
  expect(graded.length).toBeGreaterThan(0);
  graded.forEach(p => expect(p).toContain('INC-3000'));
  expect(graded.some(p => p.includes('/triage-review'))).toBe(false);
  expect(apiFetch.mock.calls.some(([p]) => String(p) === '/api/incidents/INC-3000/scope')).toBe(false);
});

test('VH: Session Performance is a KPI tile, distinct from the per-incident grade', async () => {
  render(<IncidentDashboard gameMode="hardcore" />);
  await screen.findByText('INC-3000');
  const kpi = screen.getByTestId('kpi-row');
  expect(within(kpi).getByText('Session Performance')).toBeInTheDocument();
  // owner UI pass (2026-10-12): the tile is grade-only (sub line stripped);
  // accuracy detail lives in Metrics
  await waitFor(() => expect(within(kpi).getByText('C')).toBeInTheDocument()); // session grade
  expect(within(kpi).queryByText('71%')).toBeNull();
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

test('the mode is plain muted text on the card title row; the pill and queue-count line are retired', async () => {
  render(<IncidentDashboard gameMode="hardcore" activeIncidentId="INC-2000" />);
  const card = await screen.findByTestId('active-investigation');
  // owner layout pass (2026-10-12): no mode pill -- the mode rides the
  // TITLE ROW as plain muted text, styled like the Evidence Activity
  // events-observed count
  const mode = within(card).getByText('Hardcore');
  expect(mode.getAttribute('class')).toMatch(/text-muted/);
  expect(mode.parentElement).toBe(within(card).getByText('Active Investigation').parentElement);
  expect(within(card).queryByTestId('mode-badge')).toBeNull();
  // the canonical identity row (inline follow-up 2026-10-12): [INC id]
  // [Severity] then the TITLE inline, same as the Incidents detail header;
  // still no mode pill
  await waitFor(() => expect(within(card).getByTestId('incident-pill')).toBeInTheDocument());
  const row = within(card).getByTestId('incident-pill');
  const kids = [...row.children];
  expect(kids.slice(0, 2).map(el => el.getAttribute('data-testid')))
    .toEqual(['incident-id-badge', 'severity-badge']);
  expect(kids[2].textContent).toBe('Ready Incident');   // the title, inline
  // owner UI pass (2026-10-12): the VH queue-count line went with the
  // other detail lines; the queue denominator lives in the KPI strip
  expect(within(card).queryByText(/of 10 Resolved/)).toBeNull();
});

test('no stage line in any state: open detections render no "to Triage" copy (owner layout pass 2)', async () => {
  apiFetch.mockImplementation((path) => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(path === '/api/incidents'
      ? { queue_length: 10, resolved_count: 0, completed: [], stats: { severity_breakdown: {} },
          active: [{ incident_id: 'INC-4000', title: 'Open Work', severity: 'High', state: 'in_progress',
                     sealed: true, ready: false, open_detections: 3, triage: { total: 5, triaged: 2 } }] }
      : routeJson(path)),
  }));
  render(<IncidentDashboard gameMode="hardcore" />);
  const card = await screen.findByTestId('active-investigation');
  await waitFor(() => expect(within(card).getByText('Open Work')).toBeInTheDocument());
  expect(within(card).queryByText(/Detections to Triage/)).toBeNull();
  expect(within(card).queryByText('Ready to Submit')).toBeNull();
  expect(within(card).getByRole('button', { name: 'View incidents' })).toBeInTheDocument();
});

test('VH: Guided carries no queue denominator anywhere', async () => {
  render(<IncidentDashboard gameMode="guided" activeIncidentId="INC-2000" />);
  await screen.findByTestId('active-investigation');
  expect(screen.queryByText(/of 10 Resolved/)).toBeNull();
});
