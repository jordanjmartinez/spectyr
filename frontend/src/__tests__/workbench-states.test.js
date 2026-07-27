/**
 * Workbench pane states under the one-evidence-universe model (Final pass
 * III.0 item 2 over the Stage 5 Phase 1 case-constant translation).
 *
 * A selected case ANCHORS the SIEM to that case's evidence: the pinned
 * header announces it and every query carries the case scope. With no case
 * the SIEM is the All activity state. There is NO player evidence-scope
 * switch, NO expanded-search state, NO search-all action, NO return
 * action, and NO case-evidence chip: the pinned line is the one context
 * marker. The scope-error behavior keeps M1's guarantees on the ANCHOR
 * read: pinned case retained, Run disabled, recovery by Retry (ratified
 * A-OD-3) with no session escape of any kind. Plus: the pre-seal banner,
 * and the TIMEFRAME control proving control and text cannot disagree in
 * either direction.
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import Siem from '../components/Siem';
import { investigatingCase, ALL_ACTIVITY } from '../components/uiCopy';

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
    canonical_query: 'all | * | * | *', scope,
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
    if (path === '/api/endpoints') return ok({ org: { name: 'ACME Corp' }, endpoints: [] });
    if (path.startsWith(`/api/incidents/${INC}/scope`)) return scopeResponse();
    if (path.startsWith('/api/events/query?')) {
      const scope = decodeURIComponent(path).match(/&scope=(.+)$/)[1];
      return ok(snapWith(scope));
    }
    return ok({});
  });
});

const renderShell = (props = {}) => {
  const utils = render(<Siem initialQueryMode="advanced" resetTrigger={0} onHostPivot={() => {}}
               activeIncidentId={INC} {...props} />);
  return utils;
};

const runQuery = async () => {
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'all | * | * | *' } });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Run Query/ })); });
};

const results = () => within(screen.getByTestId('workbench-results'));
const queryCalls = () =>
  apiFetch.mock.calls.map((c) => c[0]).filter((p) => p.startsWith('/api/events/query?'))
    .map(decodeURIComponent);

test('a selected case anchors the SIEM to case evidence; the anchor is announced, never silent', async () => {
  const props = { resetTrigger: 0, onHostPivot: () => {} };
  const { rerender } = render(<Siem initialQueryMode="advanced" {...props} activeIncidentId={null} />);
  // no case: All activity, no scope read
  expect(screen.queryByTestId('pinned-case-line')).toBeNull();   // VA1: the case line is retired; context is the shell pill
  expect(apiFetch.mock.calls.map(c => c[0]).filter(p => p.includes('/scope'))).toEqual([]);
  // a case is selected on Incidents -> the SIEM re-anchors, visibly
  await act(async () => { rerender(<Siem initialQueryMode="advanced" {...props} activeIncidentId={INC} />); });
  expect(screen.queryByText(/Investigating/)).toBeNull();   // VA1: the case line is retired; context is the shell pill
  expect(apiFetch.mock.calls.map(c => c[0]).filter(p => p.includes('/scope')).length)
    .toBeGreaterThanOrEqual(1);
});

test('no case: All activity; queries carry scope=session', async () => {
  renderShell({ activeIncidentId: null });
  expect(screen.queryByTestId('pinned-case-line')).toBeNull();   // VA1: the case line is retired; context is the shell pill
  await runQuery();
  expect(queryCalls().pop()).toMatch(/scope=session$/);
});

test('case evidence is the only state with a case: queries carry the case scope', async () => {
  await act(async () => { renderShell(); });
  expect(screen.queryByText(/Investigating/)).toBeNull();   // VA1: the case line is retired; context is the shell pill
  await runQuery();
  expect(queryCalls().pop()).toMatch(new RegExp(`scope=${INC}$`));
});

test('no scope furniture exists with a case: no chip, no search-all, no return, no expanded block (III.0 item 2)', async () => {
  await act(async () => { renderShell(); });
  await runQuery();
  expect(screen.queryByTestId('scope-chip')).toBeNull();
  expect(screen.queryByTestId('search-all')).toBeNull();
  expect(screen.queryByTestId('return-chip')).toBeNull();
  expect(screen.queryByTestId('expanded-search-block')).toBeNull();
  // the pinned line is the ONE context marker, rendered exactly once
  expect(screen.queryAllByTestId('pinned-case-line')).toHaveLength(0);   // VA1: the case line is retired; context is the shell pill
});

test('the case never changes from the SIEM: no control exists that mutates it (OD-15 structural)', async () => {
  await act(async () => { renderShell(); });
  await runQuery();
  expect(screen.queryByText(/Investigating/)).toBeNull();   // VA1: the case line is retired; context is the shell pill
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

test('a sealed case shows no pre-seal banner; submitted incidents stay anchorable (no special casing)', async () => {
  await act(async () => { renderShell(); });
  expect(screen.queryByText('Incident telemetry is still loading.')).toBeNull();
  // A2 3.2: Run disables only on a truly EMPTY bar; with text and a ready
  // case scope it is enabled (the scope never blocks a sealed case).
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'all | * | * | *' } });
  expect(screen.getByRole('button', { name: /Run Query/ })).not.toBeDisabled();
});

test('scope-error on the case read: case retained, Run disabled, Retry-only recovery, no session escape', async () => {
  // The case-evidence read fails at the ANCHOR (ratified A-OD-3 behavior,
  // unchanged): the pinned line keeps the case, Run is blocked, recovery
  // is Retry alone -- with the expanded-search escape removed (III.0
  // item 2) NO control can run outside the case while it stays pinned.
  scopeResponse = () => Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({}) });
  await act(async () => { renderShell(); });

  expect(screen.queryByText(/Investigating/)).toBeNull();   // VA1: the case line is retired; context is the shell pill
  expect(screen.getByRole('alert').textContent).toContain('Incident scope could not be loaded.');
  // with bar text present, Run stays disabled by the scope block alone
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'all | * | * | *' } });
  expect(screen.getByRole('button', { name: /Run Query/ })).toBeDisabled();
  // no query was issued by the failed read
  expect(queryCalls()).toEqual([]);
  // A-OD-3: Retry is the recovery; no session escape of any kind
  expect(screen.queryByRole('button', { name: 'Use Session-wide' })).toBeNull();
  expect(screen.queryByTestId('search-all')).toBeNull();

  // retry succeeds -> ready -> Run enabled
  scopeResponse = () => ok({ incident_id: INC, sealed: true, hosts: [], accounts: [], detection_ids: [] });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Retry' })); });
  expect(screen.getByRole('button', { name: /Run Query/ })).not.toBeDisabled();
});

test('11.3: an edited bar shows the edited note; a run that lands clears it', async () => {
  await act(async () => { renderShell({ activeIncidentId: null }); });
  await runQuery();
  expect(screen.queryByTestId('edited-note')).toBeNull();
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'all | * | * | * draft' } });
  // the note carries the ruled III.0 item 3 sentence plus the A2 Restore action
  expect(screen.getByTestId('edited-note').textContent)
    .toContain('Search edited but not run. Showing results from the previous search.');
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'all | * | * | *' } });
  expect(screen.queryByTestId('edited-note')).toBeNull();
});

test('a failed parse states the results are from the previous successful search; absent with no snapshot', async () => {
  apiFetch.mockImplementation((path) => {
    if (path === '/api/endpoints') return ok({ org: {}, endpoints: [] });
    if (path.startsWith(`/api/incidents/${INC}/scope`)) return scopeResponse();
    if (path.startsWith('/api/events/query?')) {
      const q = decodeURIComponent(path);
      if (q.includes('broken')) {
        return Promise.resolve({ ok: false, status: 400,
          json: () => Promise.resolve({ error: { position: 0, reason: 'unknown TIMEFRAME' } }) });
      }
      return ok(snapWith('session'));
    }
    return ok({});
  });
  await act(async () => { renderShell({ activeIncidentId: null }); });
  // first run fails with NO prior snapshot: error, no stale-results claim
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'broken | * | * | *' } });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Run Query/ })); });
  expect(screen.getByRole('alert').textContent).toContain('unknown TIMEFRAME');
  expect(screen.queryByText('Showing results from the previous successful search.')).toBeNull();
  // a successful run, then a failed parse: prior rows preserved + the statement
  await runQuery();
  expect(results().getByText(/nmap.exe launched/)).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'broken | * | * | *' } });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Run Query/ })); });
  expect(screen.getByRole('alert').textContent)
    .toContain('Showing results from the previous successful search.');
  expect(results().getByText(/nmap.exe launched/)).toBeInTheDocument();
});

test('TIMEFRAME control: text drives the control (control can never disagree)', async () => {
  await act(async () => { renderShell(); });
  const bar = screen.getByLabelText('LCQL query');
  const tf = screen.getByLabelText('Timeframe');
  expect(tf).toHaveValue('1h');                 // documented default on empty
  fireEvent.change(bar, { target: { value: '24h | Sysmon | * | *' } });
  expect(tf).toHaveValue('24h');
  fireEvent.change(bar, { target: { value: '2h | Sysmon | * | *' } });
  expect(tf).toHaveValue('');                   // unknown token -> neutral, never a wrong claim
  fireEvent.change(bar, { target: { value: 'ALL | Sysmon | * | *' } });
  expect(tf).toHaveValue('all');                // case-insensitive derivation
});

test('TIMEFRAME control: selecting a token edits the first segment in place', async () => {
  await act(async () => { renderShell(); });
  const bar = screen.getByLabelText('LCQL query');
  const tf = screen.getByLabelText('Timeframe');
  fireEvent.change(bar, { target: { value: '24h | Sysmon | 4625 | user_account == "spatel"' } });
  fireEvent.change(tf, { target: { value: '4h' } });
  expect(bar).toHaveValue('4h | Sysmon | 4625 | user_account == "spatel"');
  expect(tf).toHaveValue('4h');                 // both directions agree after the edit
  // empty bar: the control bootstraps a full valid query
  fireEvent.change(bar, { target: { value: '' } });
  fireEvent.change(tf, { target: { value: 'all' } });
  expect(bar).toHaveValue('all | * | * | *');
});
