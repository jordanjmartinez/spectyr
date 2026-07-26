/**
 * Workbench pane states, translated to the case-constant model (Stage 5
 * Phase 1, Amendment 1 Delta A over the Stage 4 Phase 4.2 battery).
 *
 * A selected case ANCHORS the SIEM to case evidence (the pinned header and
 * the "INC-#### evidence" state label announce it; queries carry the case
 * scope). With no case the SIEM is the All activity state. Expanded search
 * is entered ONLY through an entity pivot or the explicit search-all
 * action; exactly ONE return action restores the case evidence. The
 * scope-error behavior keeps M1's guarantees on the ANCHOR read: state
 * label retained, Run disabled, recovery by Retry (ratified A-OD-3) --
 * the deliberate Expanded search remains available as the designed
 * exploration path. A failed RETURN read is governed by the C1 guard
 * (workbench-cross-host suite): the state stays Expanded search, so an
 * incident label never sits over expanded session rows. Plus: the
 * pre-seal banner, and the TIMEFRAME control proving control and text
 * cannot disagree in either direction.
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import Siem from '../components/Siem';
import {
  investigatingCase, ALL_ACTIVITY, caseEvidenceLabel, EXPANDED_SEARCH_TITLE,
  returnToCaseEvidence, SEARCH_ALL_EVIDENCE,
} from '../components/uiCopy';

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

const renderShell = (props = {}) =>
  render(<Siem resetTrigger={0} onHostPivot={() => {}}
               activeIncidentId={INC} {...props} />);

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
  const { rerender } = render(<Siem {...props} activeIncidentId={null} />);
  // no case: All activity, no state chip, no scope read
  expect(screen.getByTestId('pinned-case-line').textContent).toBe(ALL_ACTIVITY);
  expect(screen.queryByTestId('scope-chip')).toBeNull();
  expect(apiFetch.mock.calls.map(c => c[0]).filter(p => p.includes('/scope'))).toEqual([]);
  // a case is selected on Incidents -> the SIEM re-anchors, visibly
  await act(async () => { rerender(<Siem {...props} activeIncidentId={INC} />); });
  expect(screen.getByTestId('pinned-case-line').textContent).toBe(investigatingCase(INC));
  expect(screen.getByTestId('scope-chip').textContent).toContain(caseEvidenceLabel(INC));
  expect(apiFetch.mock.calls.map(c => c[0]).filter(p => p.includes('/scope')).length)
    .toBeGreaterThanOrEqual(1);
});

test('no case: All activity; queries carry scope=session', async () => {
  renderShell({ activeIncidentId: null });
  expect(screen.getByTestId('pinned-case-line').textContent).toBe(ALL_ACTIVITY);
  await runQuery();
  expect(queryCalls().pop()).toMatch(/scope=session$/);
});

test('case evidence is the default with a case: queries carry the case scope', async () => {
  await act(async () => { renderShell(); });
  expect(screen.getByTestId('scope-chip').textContent).toContain(caseEvidenceLabel(INC));
  await runQuery();
  expect(queryCalls().pop()).toMatch(new RegExp(`scope=${INC}$`));
});

test('search-all enters Expanded search visibly: block, explanation, exactly one return action', async () => {
  await act(async () => { renderShell(); });
  await runQuery();
  expect(screen.queryByTestId('expanded-search-block')).toBeNull();
  await act(async () => {
    fireEvent.click(screen.getByTestId('search-all'));
  });
  expect(queryCalls().pop()).toMatch(/scope=session$/);
  const block = screen.getByTestId('expanded-search-block');
  expect(block.textContent).toContain(EXPANDED_SEARCH_TITLE);
  expect(within(block).getAllByRole('button')).toHaveLength(1);
  expect(within(block).getByRole('button').textContent).toBe(returnToCaseEvidence(INC));
  // the case stays pinned through the expansion
  expect(screen.getByTestId('pinned-case-line').textContent).toBe(investigatingCase(INC));
  // returning restores the case evidence
  await act(async () => { fireEvent.click(screen.getByTestId('return-chip')); });
  expect(queryCalls().pop()).toMatch(new RegExp(`scope=${INC}$`));
  expect(screen.queryByTestId('expanded-search-block')).toBeNull();
  expect(screen.getByTestId('scope-chip').textContent).toContain(caseEvidenceLabel(INC));
});

test('the case never changes from the SIEM: no control exists that mutates it (OD-15 structural)', async () => {
  await act(async () => { renderShell(); });
  await runQuery();
  // enter and leave Expanded search; the pinned case is byte-identical
  await act(async () => { fireEvent.click(screen.getByTestId('search-all')); });
  expect(screen.getByTestId('pinned-case-line').textContent).toBe(investigatingCase(INC));
  await act(async () => { fireEvent.click(screen.getByTestId('return-chip')); });
  expect(screen.getByTestId('pinned-case-line').textContent).toBe(investigatingCase(INC));
  // no scope select, no toggle, no clear control on this surface
  expect(screen.queryByLabelText('Scope')).toBeNull();
  expect(screen.queryByRole('button', { name: 'Session-wide' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Use Session-wide' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Clear scope' })).toBeNull();
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

test('scope-error on the case read: label retained, Run disabled, Retry-only recovery; Expanded search stays available', async () => {
  // The case-evidence read fails at the ANCHOR (ratified A-OD-3 behavior,
  // unchanged): the label keeps the case with the error marker, Run is
  // blocked, recovery is Retry or the deliberate Expanded search. The
  // failed-RETURN path is governed by the C1 guard instead (cross-host
  // suite): it stays in Expanded search, so an incident label can never
  // sit over expanded session rows on this surface.
  scopeResponse = () => Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({}) });
  await act(async () => { renderShell(); });

  expect(screen.getByTestId('scope-chip').textContent).toContain(caseEvidenceLabel(INC));
  expect(screen.getByRole('alert').textContent).toContain('Incident scope could not be loaded.');
  // with bar text present, Run stays disabled by the scope block alone
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'all | * | * | *' } });
  expect(screen.getByRole('button', { name: /Run Query/ })).toBeDisabled();
  // no query was issued by the failed read
  expect(queryCalls()).toEqual([]);
  // A-OD-3: Retry is the recovery; no Use Session-wide control exists
  expect(screen.queryByRole('button', { name: 'Use Session-wide' })).toBeNull();
  // the deliberate Expanded search remains available (the designed path out)
  expect(screen.getByTestId('search-all')).not.toBeDisabled();

  // retry succeeds -> ready -> Run enabled
  scopeResponse = () => ok({ incident_id: INC, sealed: true, hosts: [], accounts: [], detection_ids: [] });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Retry' })); });
  expect(screen.getByRole('button', { name: /Run Query/ })).not.toBeDisabled();
});

test('search-all from a failed case read enters Expanded search honestly (block visible, all-evidence run)', async () => {
  scopeResponse = () => Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({}) });
  await act(async () => { renderShell(); });
  expect(screen.getByRole('alert').textContent).toContain('Incident scope could not be loaded.');
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'all | * | * | *' } });
  await act(async () => { fireEvent.click(screen.getByTestId('search-all')); });
  expect(queryCalls().pop()).toMatch(/scope=session$/);
  expect(screen.getByTestId('expanded-search-block')).toBeInTheDocument();
  expect(screen.getByTestId('pinned-case-line').textContent).toBe(investigatingCase(INC));
});

test('search-all is disabled on an empty bar (nothing to run)', async () => {
  await act(async () => { renderShell(); });
  expect(screen.getByLabelText('LCQL query').value).toBe('');
  expect(screen.getByTestId('search-all')).toBeDisabled();
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'all | * | * | *' } });
  expect(screen.getByTestId('search-all')).not.toBeDisabled();
  expect(screen.getByTestId('search-all').textContent).toBe(SEARCH_ALL_EVIDENCE);
});

test('11.3: an edited bar shows the edited note; a run that lands clears it', async () => {
  await act(async () => { renderShell({ activeIncidentId: null }); });
  await runQuery();
  expect(screen.queryByTestId('edited-note')).toBeNull();
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'all | * | * | * draft' } });
  // the note carries the canonical 11.3 string plus the A2 Restore action
  expect(screen.getByTestId('edited-note').textContent)
    .toContain('Edited. Results below are from the last run.');
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'all | * | * | *' } });
  expect(screen.queryByTestId('edited-note')).toBeNull();
});

test('11.3: a failed parse states the displayed results are from the previous successful query; absent with no snapshot', async () => {
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
  expect(screen.queryByText('Displayed results are from the previous successful query.')).toBeNull();
  // a successful run, then a failed parse: prior rows preserved + the statement
  await runQuery();
  expect(results().getByText(/nmap.exe launched/)).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'broken | * | * | *' } });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Run Query/ })); });
  expect(screen.getByRole('alert').textContent)
    .toContain('Displayed results are from the previous successful query.');
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
