/**
 * Stage 4 Phase 4.2: workbench pane states (contract Section 6).
 *
 * The scope control's REVISED error behavior (review item 8): a failed
 * incident-scope read keeps the selected chip, shows the notice, preserves
 * the prior snapshot untouched, and disables Run Query until a retry
 * succeeds or the player EXPLICITLY selects Session-wide. Scope never
 * broadens silently. Plus: the pre-seal banner, submitted-incident
 * selectability, and the TIMEFRAME control proving control and text cannot
 * disagree in either direction.
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
const SNAPSHOT = {
  token: 'tok.abc',
  identity: {
    canonical_query: 'all | * | * | *', scope: 'session',
    resolved_scope_hosts: [],
    resolved_range: { start: '2026-03-17T03:41:00+00:00', end: '2026-03-17T04:00:00+00:00' },
    cutoff_seq: 3,
  },
  count: 1, rows: [ROW],
};

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

let scopeResponse;
beforeEach(() => {
  scopeResponse = () => ok({ incident_id: INC, sealed: true, hosts: ['ACME-WS12'], accounts: [], detection_ids: [] });
  apiFetch.mockImplementation((path) => {
    if (path === '/api/endpoints') return ok({ org: { name: 'ACME Corp' }, endpoints: [] });
    if (path.startsWith(`/api/incidents/${INC}/scope`)) return scopeResponse();
    if (path.startsWith('/api/events/query')) return ok(SNAPSHOT);
    return ok({});
  });
});

const renderShell = () =>
  render(<Siem setSiemCount={() => {}} resetTrigger={0} onHostPivot={() => {}} activeIncidentId={INC} />);

const runSessionQuery = async () => {
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'all | * | * | *' } });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Run Query/ })); });
};

const selectIncidentScope = async () => {
  await act(async () => {
    fireEvent.change(screen.getByLabelText('Scope'), { target: { value: INC } });
  });
};

// The field sidebar (P6.2) also renders top message VALUES, which can
// duplicate a row's own message text; scope row-content queries to the
// results pane specifically so they cannot match a sidebar button too.
const results = () => within(screen.getByTestId('workbench-results'));

test('an active incident elsewhere never scopes the SIEM silently', async () => {
  // Default-scope rule (R10, Phase 4 closure): ordinary navigation opens
  // Session-wide; incident scope is entered ONLY through explicit scope
  // selection (or, from Phase 7, Open Evidence Timeline descent). An
  // incident focused elsewhere in the app merely OFFERS a scope option.
  const props = { setSiemCount: () => {}, resetTrigger: 0, onHostPivot: () => {} };
  const { rerender } = render(<Siem {...props} activeIncidentId={null} />);
  expect(screen.getByLabelText('Scope')).toHaveValue('session');
  // an incident becomes active elsewhere while the SIEM stays mounted
  rerender(<Siem {...props} activeIncidentId={INC} />);
  expect(screen.getByLabelText('Scope')).toHaveValue('session');
  // and no scope read fires without an explicit selection
  const scopeCalls = apiFetch.mock.calls.map(c => c[0])
    .filter(p => p.includes('/scope'));
  expect(scopeCalls).toEqual([]);
});

test('default Session-wide; queries carry scope=session', async () => {
  renderShell();
  expect(screen.getByLabelText('Scope')).toHaveValue('session');
  await runSessionQuery();
  const call = apiFetch.mock.calls.map(c => c[0]).find(p => p.startsWith('/api/events/query'));
  expect(call).toMatch(/scope=session$/);
});

test('incident scope: ready chip; queries carry the incident id', async () => {
  renderShell();
  await selectIncidentScope();
  expect(screen.getByTestId('scope-chip').textContent).toContain(INC);
  await runSessionQuery();
  const call = apiFetch.mock.calls.map(c => c[0]).filter(p => p.startsWith('/api/events/query')).pop();
  expect(call).toMatch(new RegExp(`scope=${INC}$`));
});

test('pre-seal banner shows for an unsealed scoped incident and only then', async () => {
  scopeResponse = () => ok({ incident_id: INC, sealed: false, hosts: [], accounts: [], detection_ids: [] });
  renderShell();
  await selectIncidentScope();
  expect(screen.getByText('Incident telemetry is still loading.')).toBeInTheDocument();
  scopeResponse = () => ok({ incident_id: INC, sealed: true, hosts: [], accounts: [], detection_ids: [] });
  await selectIncidentScope();
  expect(screen.queryByText('Incident telemetry is still loading.')).toBeNull();
});

test('submitted incidents stay selectable as scope (no special casing)', async () => {
  renderShell();
  await selectIncidentScope();
  expect(screen.getByRole('button', { name: /Run Query/ })).not.toBeDisabled();
});

test('scope-error: chip retained, prior snapshot preserved, Run disabled, no silent fallback; retry and explicit Session-wide recover', async () => {
  renderShell();
  await runSessionQuery();
  expect(results().getByText(/nmap.exe launched/)).toBeInTheDocument();
  const callsBefore = apiFetch.mock.calls.length;

  scopeResponse = () => Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({}) });
  await selectIncidentScope();

  // chip retained with the incident id; the notice shows
  expect(screen.getByTestId('scope-chip').textContent).toContain(INC);
  expect(screen.getByRole('alert').textContent).toContain('Incident scope could not be loaded.');
  // prior snapshot untouched
  expect(results().getByText(/nmap.exe launched/)).toBeInTheDocument();
  // Run disabled
  expect(screen.getByRole('button', { name: /Run Query/ })).toBeDisabled();
  // no silent Session-wide fallback: the control still shows the incident
  // and NO query was issued by the failed selection
  expect(screen.getByLabelText('Scope')).toHaveValue(INC);
  const eventCalls = apiFetch.mock.calls.slice(callsBefore).map(c => c[0])
    .filter(p => p.startsWith('/api/events/query'));
  expect(eventCalls).toEqual([]);

  // retry succeeds -> ready -> Run enabled
  scopeResponse = () => ok({ incident_id: INC, sealed: true, hosts: [], accounts: [], detection_ids: [] });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Retry' })); });
  expect(screen.getByRole('button', { name: /Run Query/ })).not.toBeDisabled();

  // and from a fresh error, the EXPLICIT Session-wide choice recovers too
  scopeResponse = () => Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({}) });
  await selectIncidentScope();
  expect(screen.getByRole('button', { name: /Run Query/ })).toBeDisabled();
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Use Session-wide' })); });
  expect(screen.getByLabelText('Scope')).toHaveValue('session');
  expect(screen.getByRole('button', { name: /Run Query/ })).not.toBeDisabled();
});

test('TIMEFRAME control: text drives the control (control can never disagree)', () => {
  renderShell();
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

test('TIMEFRAME control: selecting a token edits the first segment in place', () => {
  renderShell();
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
