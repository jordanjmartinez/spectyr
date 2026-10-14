/**
 * Workbench pane states under the one-evidence-universe model (Final pass
 * III.0 item 2 over the Stage 5 Phase 1 case-constant translation), under
 * the owner simplification pass + follow-up (2026-10-13: no LCQL bar; the
 * facet system + one search box are the whole typed surface).
 *
 * A selected case ANCHORS the SIEM to that case's evidence: every query
 * carries the case scope. With no case the SIEM is the All activity state.
 * There is NO player evidence-scope switch, NO expanded-search state, NO
 * search-all action, NO return action, and NO case-evidence chip. The
 * scope-error behavior keeps M1's guarantees on the ANCHOR read: the case
 * stays pinned, every search entry is blocked, recovery by Retry (ratified
 * A-OD-3) with no session escape of any kind. Plus: the pre-seal banner.
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import Siem from '../components/Siem';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const INC = 'INC-4242';

const ROW = {
  id: 'e1', event_seq: 3, timestamp: '2026-03-17T04:00:00+00:00',
  event_type: 'ProcessCreate', source_type: 'Sysmon', severity: 'high',
  hostname: 'ACME-WS12', source_ip: '10.0.1.12',
  message: 'Process created: nmap.exe launched by cmd.exe',
  key_value_pairs: {},
};
const snapWith = (scope) => ({
  token: 'tok.abc',
  identity: {
    canonical_query: '1h | * | * | *', scope,
    resolved_scope_hosts: [],
    resolved_range: { start: '2026-03-17T03:41:00+00:00', end: '2026-03-17T04:00:00+00:00' },
    cutoff_seq: 3,
  },
  count: 1, rows: [ROW],
});

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

let scopeResponse;
beforeEach(() => {
  scopeResponse = () => ok({ incident_id: INC, sealed: true, hosts: ['ACME-WS12'], accounts: [], detection_ids: [] });
  apiFetch.mockImplementation((path) => {
    if (path.startsWith(`/api/incidents/${INC}/scope`)) return scopeResponse();
    if (path.startsWith('/api/events/query?')) {
      const scope = decodeURIComponent(path).match(/&scope=(.+)$/)[1];
      return ok(snapWith(scope));
    }
    return ok({});
  });
});

const renderShell = (props = {}) => {
  const utils = render(<Siem resetTrigger={0} onHostPivot={() => {}}
               activeIncidentId={INC} {...props} />);
  return utils;
};

const showEvents = async () => {
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Show Events' })); });
};

const results = () => within(screen.getByTestId('workbench-results'));
const queryCalls = () =>
  apiFetch.mock.calls.map((c) => c[0]).filter((p) => p.startsWith('/api/events/query?'))
    .map(decodeURIComponent);

test('a selected case anchors the SIEM to case evidence; the anchor read happens on selection', async () => {
  const props = { resetTrigger: 0, onHostPivot: () => {} };
  const { rerender } = render(<Siem {...props} activeIncidentId={null} />);
  // no case: All activity, no scope read
  expect(apiFetch.mock.calls.map(c => c[0]).filter(p => p.includes('/scope'))).toEqual([]);
  // a case is selected on Incidents -> the SIEM re-anchors
  await act(async () => { rerender(<Siem {...props} activeIncidentId={INC} />); });
  expect(apiFetch.mock.calls.map(c => c[0]).filter(p => p.includes('/scope')).length)
    .toBeGreaterThanOrEqual(1);
});

test('no case: queries carry scope=session', async () => {
  renderShell({ activeIncidentId: null });
  await showEvents();
  expect(queryCalls().pop()).toMatch(/scope=session$/);
});

test('case evidence is the only state with a case: queries carry the case scope', async () => {
  await act(async () => { renderShell(); });
  await showEvents();
  expect(queryCalls().pop()).toMatch(new RegExp(`scope=${INC}$`));
});

test('no scope furniture exists with a case: no chip, no search-all, no return, no expanded block (III.0 item 2)', async () => {
  await act(async () => { renderShell(); });
  await showEvents();
  expect(screen.queryByTestId('scope-chip')).toBeNull();
  expect(screen.queryByTestId('search-all')).toBeNull();
  expect(screen.queryByTestId('return-chip')).toBeNull();
  expect(screen.queryByTestId('expanded-search-block')).toBeNull();
  expect(screen.queryAllByTestId('pinned-case-line')).toHaveLength(0);   // VA1: retired case line
});

test('the case never changes from the SIEM: no control exists that mutates it (OD-15 structural)', async () => {
  await act(async () => { renderShell(); });
  await showEvents();
  expect(screen.queryByText(/Investigating/)).toBeNull();   // VA1: retired case line
  // no scope select, no toggle, no clear control on this surface
  expect(screen.queryByLabelText('Scope')).toBeNull();
  expect(screen.queryByRole('button', { name: 'Session-wide' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Use Session-wide' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Clear scope' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Search all evidence' })).toBeNull();
});

test('pre-seal banner shows for an unsealed case and only then', async () => {
  scopeResponse = () => ok({ incident_id: INC, sealed: false, hosts: [], accounts: [], detection_ids: [] });
  await act(async () => { renderShell(); });
  expect(screen.getByText('Incident telemetry is still loading.')).toBeInTheDocument();
});

test('a sealed case shows no pre-seal banner; search entry stays enabled', async () => {
  await act(async () => { renderShell(); });
  expect(screen.queryByText('Incident telemetry is still loading.')).toBeNull();
  expect(screen.getByRole('button', { name: 'Show Events' })).not.toBeDisabled();
  fireEvent.change(screen.getByLabelText('Search events'),
    { target: { value: 'severity = high' } });
  expect(screen.getByRole('button', { name: 'Search' })).not.toBeDisabled();
});

test('scope-error on the case read: case retained, searches blocked, Retry-only recovery, no session escape', async () => {
  // The case-evidence read fails at the ANCHOR (ratified A-OD-3 behavior,
  // unchanged): searches stay blocked, recovery is Retry alone -- NO
  // control can run outside the case while it stays pinned.
  scopeResponse = () => Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({}) });
  await act(async () => { renderShell(); });

  expect(screen.getByRole('alert').textContent).toContain('Incident scope could not be loaded.');
  expect(screen.getByRole('button', { name: 'Show Events' })).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Search events'),
    { target: { value: 'severity = high' } });
  expect(screen.getByRole('button', { name: 'Search' })).toBeDisabled();
  await act(async () => {
    fireEvent.keyDown(screen.getByLabelText('Search events'), { key: 'Enter' });
  });
  // no query was issued by the failed read or the blocked entries
  expect(queryCalls()).toEqual([]);
  // A-OD-3: Retry is the recovery; no session escape of any kind
  expect(screen.queryByRole('button', { name: 'Use Session-wide' })).toBeNull();
  expect(screen.queryByTestId('search-all')).toBeNull();

  // retry succeeds -> ready -> search entry enabled
  scopeResponse = () => ok({ incident_id: INC, sealed: true, hosts: [], accounts: [], detection_ids: [] });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Retry' })); });
  expect(screen.getByRole('button', { name: 'Show Events' })).not.toBeDisabled();
});

test('a server failure preserves the prior snapshot with the stale statement; absent with no snapshot', async () => {
  apiFetch.mockImplementation((path) => {
    if (path.startsWith(`/api/incidents/${INC}/scope`)) return scopeResponse();
    if (path.startsWith('/api/events/query?')) {
      const q = decodeURIComponent(path);
      if (q.includes('broken')) {
        return Promise.resolve({ ok: false, status: 500,
          json: () => Promise.resolve(null) });
      }
      return ok(snapWith('session'));
    }
    return ok({});
  });
  await act(async () => { renderShell({ activeIncidentId: null }); });
  // first search fails with NO prior snapshot: error, no stale-results claim
  fireEvent.change(screen.getByLabelText('Search events'),
    { target: { value: 'broken request' } });
  await act(async () => {
    fireEvent.keyDown(screen.getByLabelText('Search events'), { key: 'Enter' });
  });
  expect(screen.getByRole('alert').textContent).toContain('This search was not run.');
  expect(screen.queryByText('Showing results from the previous successful search.')).toBeNull();
  // a successful run, then a failure: prior rows preserved + the statement
  await showEvents();
  expect(results().getByText(/nmap.exe launched/)).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Search events'),
    { target: { value: 'broken request' } });
  await act(async () => {
    fireEvent.keyDown(screen.getByLabelText('Search events'), { key: 'Enter' });
  });
  expect(screen.getByRole('alert').textContent)
    .toContain('Showing results from the previous successful search.');
  expect(results().getByText(/nmap.exe launched/)).toBeInTheDocument();
});
