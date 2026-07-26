/**
 * Scope truth on Detections and Endpoints -- the three-state battery
 * (Stage 5 Phase 1, Amendment 1 Delta A, translating the M1 battery; the
 * A1-A.3 behavior table is the specification):
 *  - case selected: the pinned header ("Investigating INC-####"), the
 *    honesty notices, and the rendered row set derive from ONE state value
 *  - initial case read shows the loading state, NEVER all-activity rows
 *    under a selected case
 *  - a refresh with scoped rows already displayed retains them and replaces
 *    them atomically
 *  - a failure with prior scoped rows preserves them and states:
 *    "Displayed rows are from the last successful scope read."
 *  - a failure with no prior scoped rows renders the empty error state
 *    (Retry ONLY -- no broadening control exists on these pages, ratified
 *    A-OD-3), zero rows
 *  - no case selected: the All activity state (full session data)
 *  - NO scope toggle and NO Use Session-wide control exist (structural)
 *  - refresh triggers unchanged: Detections joins the existing 2.5s feed
 *    poll; Endpoints refetches on tab-visibility change, no poll introduced
 */
import React from 'react';
import { render, screen, fireEvent, act } from '@testing-library/react';
import Detections from '../components/Detections';
import Endpoints from '../components/Endpoints';
import { investigatingCase, ALL_ACTIVITY } from '../components/uiCopy';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const ok = (body) => ({ ok: true, json: () => Promise.resolve(body) });
const fail = () => ({ ok: false, status: 500, json: () => Promise.resolve({}) });
const deferred = () => {
  let resolve;
  const p = new Promise((res) => { resolve = res; });
  return { p, resolve };
};

const FEED = {
  detections: [
    { id: 'det-aaa', rule_name: 'LSASS Process Memory Access', rule_type: 'sigma_behavioral',
      severity: 'critical', mitre: null, yara_rule_name: null, description: 'x',
      entity: { host: 'ACME-WS12', account: 'nkhan' }, time: '2026-07-16T12:10:00+00:00',
      sha256: null, player_action: 'open' },
    { id: 'det-bbb', rule_name: 'Software Updater Outbound Connection', rule_type: 'sigma_behavioral',
      severity: 'medium', mitre: null, yara_rule_name: null, description: 'x',
      entity: { host: 'ACME-WS12', account: 'nkhan' }, time: '2026-07-16T12:05:00+00:00',
      sha256: null, player_action: 'open' },
    { id: 'det-ccc', rule_name: 'Impossible Travel Sign-in', rule_type: 'sigma_behavioral',
      severity: 'high', mitre: null, yara_rule_name: null, description: 'x',
      entity: { host: null, account: 'nkhan@acme.local' }, time: '2026-07-16T12:12:00+00:00',
      sha256: null, player_action: 'open' },
  ],
  counts: { open: 3, promoted: 0, dismissed: 0 },
};
const LOG = { actions: [], count: 0 };
const SCOPE = {
  incident_id: 'INC-0001', sealed: true, hosts: ['ACME-WS12'], accounts: [],
  detection_ids: ['det-aaa', 'det-bbb'], triage: { total: 2, triaged: 0 },
};
const EP_LIST = {
  org: { name: 'ACME Corp' },
  endpoints: [
    { hostname: 'ACME-WS12', ip: '10.0.1.12', external_ip: '203.0.113.25',
      os: 'Windows 11 Enterprise', platform: 'windows', status: 'online',
      isolation: 'not_isolated', tags: [], first_seen: '2026-05-02T08:11:00+00:00',
      last_seen: '2026-07-16T12:00:00+00:00' },
    { hostname: 'ACME-SVR02', ip: '10.0.1.201', external_ip: '203.0.113.25',
      os: 'Windows Server 2019', platform: 'windows', status: 'offline',
      isolation: 'not_isolated', tags: [], first_seen: '2026-03-14T02:40:00+00:00',
      last_seen: '2026-07-15T22:12:00+00:00' },
  ],
};

const mockApi = (scopeImpl) => {
  apiFetch.mockImplementation((path) => {
    if (path.includes('/scope')) return Promise.resolve(scopeImpl());
    if (path === '/api/actions') return Promise.resolve(ok(LOG));
    if (path === '/api/detections') return Promise.resolve(ok(FEED));
    if (path === '/api/endpoints') return Promise.resolve(ok(EP_LIST));
    return Promise.resolve(ok({}));
  });
};

const pinnedLine = () => screen.getByTestId('pinned-case-line').textContent;
const noToggle = () => {
  expect(screen.queryByRole('button', { name: 'This incident' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Session-wide' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Use Session-wide' })).toBeNull();
};
const noEmDash = (container) => expect(container.textContent).not.toMatch(/—/);

beforeEach(() => {
  apiFetch.mockReset();
  jest.useRealTimers();
});

test('Detections: pinned header and rows agree across loading, ready, and post-reset; no toggle exists', async () => {
  const d1 = deferred();
  let settled = false;
  mockApi(() => (settled ? ok(SCOPE) : { ok: true, json: () => d1.p }));
  const { container, rerender } = render(
    <Detections isVisible resetTrigger={0}
      onHostPivot={() => {}} activeIncidentId="INC-0001" />
  );
  // loading: pinned case header, loading copy, ZERO rows, NO toggle
  expect(pinnedLine()).toBe(investigatingCase('INC-0001'));
  expect((await screen.findAllByText('Loading incident scope')).length).toBeGreaterThanOrEqual(1);
  noToggle();
  expect(screen.queryByText('LSASS Process Memory Access')).toBeNull();
  expect(screen.queryByText('Impossible Travel Sign-in')).toBeNull();
  // resolve -> ready: case-scoped rows only, header unchanged
  settled = true;
  await act(async () => { d1.resolve(SCOPE); });
  expect(await screen.findByText('LSASS Process Memory Access')).toBeInTheDocument();
  expect(screen.queryByText('Impossible Travel Sign-in')).toBeNull();
  expect(pinnedLine()).toBe(investigatingCase('INC-0001'));
  // post-reset: refetch resolves and every signal still agrees
  rerender(
    <Detections isVisible resetTrigger={1}
      onHostPivot={() => {}} activeIncidentId="INC-0001" />
  );
  expect(await screen.findByText('LSASS Process Memory Access')).toBeInTheDocument();
  expect(screen.queryByText('Impossible Travel Sign-in')).toBeNull();
  expect(pinnedLine()).toBe(investigatingCase('INC-0001'));
  noEmDash(container);
});

test('Detections: no case selected is the All activity state with the full feed', async () => {
  mockApi(() => ok(SCOPE));
  const { container } = render(
    <Detections isVisible resetTrigger={0}
      onHostPivot={() => {}} activeIncidentId={null} />
  );
  expect(await screen.findByText('LSASS Process Memory Access')).toBeInTheDocument();
  expect(screen.getByText('Impossible Travel Sign-in')).toBeInTheDocument();
  expect(pinnedLine()).toBe(ALL_ACTIVITY);
  noToggle();
  // no case, no scope read
  const scopeCalls = apiFetch.mock.calls.map(c => c[0]).filter(p => p.includes('/scope'));
  expect(scopeCalls).toEqual([]);
  noEmDash(container);
});

test('Endpoints: pinned header and rows agree across loading, ready, and All activity', async () => {
  const d1 = deferred();
  let settled = false;
  mockApi(() => (settled ? ok(SCOPE) : { ok: true, json: () => d1.p }));
  const { rerender } = render(
    <Endpoints isVisible resetTrigger={0}
      pivotHost={null} activeIncidentId="INC-0001" />
  );
  expect(pinnedLine()).toBe(investigatingCase('INC-0001'));
  expect((await screen.findAllByText('Loading incident scope')).length).toBeGreaterThanOrEqual(1);
  noToggle();
  expect(screen.queryByText('ACME-WS12')).toBeNull();
  expect(screen.queryByText('ACME-SVR02')).toBeNull();
  settled = true;
  await act(async () => { d1.resolve(SCOPE); });
  expect(await screen.findByText('ACME-WS12')).toBeInTheDocument();
  expect(screen.queryByText('ACME-SVR02')).toBeNull();
  // clearing the case (explicitly, on Incidents) lands the All activity state
  rerender(
    <Endpoints isVisible resetTrigger={0}
      pivotHost={null} activeIncidentId={null} />
  );
  expect(await screen.findByText('ACME-SVR02')).toBeInTheDocument();
  expect(pinnedLine()).toBe(ALL_ACTIVITY);
});

test('a slow scope read never renders a selected case over unfiltered rows', async () => {
  const never = new Promise(() => {});
  mockApi(() => ({ ok: true, json: () => never }));
  render(
    <Detections isVisible resetTrigger={0}
      onHostPivot={() => {}} activeIncidentId="INC-0001" />
  );
  expect((await screen.findAllByText('Loading incident scope')).length).toBeGreaterThanOrEqual(1);
  expect(pinnedLine()).toBe(investigatingCase('INC-0001'));
  expect(screen.queryByText('LSASS Process Memory Access')).toBeNull();
  expect(screen.queryByText('Impossible Travel Sign-in')).toBeNull();
});

test('a failed scope load with no prior rows renders the empty error state with Retry ONLY', async () => {
  let failing = true;
  mockApi(() => (failing ? fail() : ok(SCOPE)));
  const { container } = render(
    <Endpoints isVisible resetTrigger={0}
      pivotHost={null} activeIncidentId="INC-0001" />
  );
  expect((await screen.findAllByText('Incident scope could not be loaded.')).length).toBeGreaterThanOrEqual(1);
  expect(pinnedLine()).toBe(investigatingCase('INC-0001'));
  expect(screen.queryByText('ACME-WS12')).toBeNull();
  expect(screen.queryByText('ACME-SVR02')).toBeNull();
  expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  // A-OD-3: no broadening control exists on the data pages
  noToggle();
  // Retry while healthy again -> scoped rows appear
  failing = false;
  fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
  expect(await screen.findByText('ACME-WS12')).toBeInTheDocument();
  expect(screen.queryByText('ACME-SVR02')).toBeNull();
  noEmDash(container);
});

test('a persistent scope failure keeps zero rows: no broadening path exists on the page', async () => {
  mockApi(() => fail());
  render(
    <Endpoints isVisible resetTrigger={0}
      pivotHost={null} activeIncidentId="INC-0001" />
  );
  expect((await screen.findAllByText('Incident scope could not be loaded.')).length).toBeGreaterThanOrEqual(1);
  // still zero rows: no silent broadening, and no control that could broaden
  expect(screen.queryByText('ACME-SVR02')).toBeNull();
  noToggle();
  expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  expect(pinnedLine()).toBe(investigatingCase('INC-0001'));
});

test('a failed scope refresh with prior scoped rows preserves them and states the last-successful-read notice', async () => {
  let failing = false;
  mockApi(() => (failing ? fail() : ok(SCOPE)));
  const { container, rerender } = render(
    <Endpoints isVisible resetTrigger={0}
      pivotHost={null} activeIncidentId="INC-0001" />
  );
  expect(await screen.findByText('ACME-WS12')).toBeInTheDocument();
  expect(screen.queryByText('ACME-SVR02')).toBeNull();
  // visibility change triggers the refetch, which now fails
  failing = true;
  rerender(
    <Endpoints isVisible={false} resetTrigger={0}
      pivotHost={null} activeIncidentId="INC-0001" />
  );
  rerender(
    <Endpoints isVisible resetTrigger={0}
      pivotHost={null} activeIncidentId="INC-0001" />
  );
  expect(await screen.findByText(/Displayed rows are from the last successful scope read\./))
    .toBeInTheDocument();
  // prior scoped rows preserved; the case stays pinned; no broadening
  expect(screen.getByText('ACME-WS12')).toBeInTheDocument();
  expect(screen.queryByText('ACME-SVR02')).toBeNull();
  expect(pinnedLine()).toBe(investigatingCase('INC-0001'));
  noEmDash(container);
});

test('a scope refresh with scoped rows already displayed replaces them atomically', async () => {
  const d2 = deferred();
  let hold = false;
  mockApi(() => (hold ? { ok: true, json: () => d2.p } : ok(SCOPE)));
  const { rerender } = render(
    <Endpoints isVisible resetTrigger={0}
      pivotHost={null} activeIncidentId="INC-0001" />
  );
  expect(await screen.findByText('ACME-WS12')).toBeInTheDocument();
  // trigger the refresh (visibility change); leave the new read pending
  hold = true;
  rerender(
    <Endpoints isVisible={false} resetTrigger={0}
      pivotHost={null} activeIncidentId="INC-0001" />
  );
  rerender(
    <Endpoints isVisible resetTrigger={0}
      pivotHost={null} activeIncidentId="INC-0001" />
  );
  // retained: old scoped rows stay; still never unfiltered
  expect(screen.getByText('ACME-WS12')).toBeInTheDocument();
  expect(screen.queryByText('ACME-SVR02')).toBeNull();
  // resolve with a different scope -> atomic swap to the new scoped set
  await act(async () => {
    d2.resolve({ ...SCOPE, hosts: ['ACME-SVR02'], detection_ids: [] });
  });
  expect(await screen.findByText('ACME-SVR02')).toBeInTheDocument();
  expect(screen.queryByText('ACME-WS12')).toBeNull();
  expect(pinnedLine()).toBe(investigatingCase('INC-0001'));
});

test('Detections: the scope read joins the 2.5s feed poll while a case is selected, and stops without one', async () => {
  jest.useFakeTimers();
  let scopeCalls = 0;
  mockApi(() => { scopeCalls += 1; return ok(SCOPE); });
  const { rerender } = render(
    <Detections isVisible resetTrigger={0}
      onHostPivot={() => {}} activeIncidentId="INC-0001" />
  );
  await act(async () => {});
  const initial = scopeCalls;
  expect(initial).toBeGreaterThanOrEqual(1);
  act(() => { jest.advanceTimersByTime(2500); });
  await act(async () => {});
  expect(scopeCalls).toBe(initial + 1);
  // with the case cleared (on Incidents) the poll stops refetching the scope
  rerender(
    <Detections isVisible resetTrigger={0}
      onHostPivot={() => {}} activeIncidentId={null} />
  );
  await act(async () => {});
  const beforeIdle = scopeCalls;
  act(() => { jest.advanceTimersByTime(5000); });
  await act(async () => {});
  expect(scopeCalls).toBe(beforeIdle);
});

test('Endpoints: scope refetches on tab-visibility change and never from a timer', async () => {
  jest.useFakeTimers();
  let scopeCalls = 0;
  mockApi(() => { scopeCalls += 1; return ok(SCOPE); });
  const { rerender } = render(
    <Endpoints isVisible resetTrigger={0}
      pivotHost={null} activeIncidentId="INC-0001" />
  );
  await act(async () => {});
  const initial = scopeCalls;
  expect(initial).toBeGreaterThanOrEqual(1);
  // no poll exists on this surface: time alone never refetches
  act(() => { jest.advanceTimersByTime(30000); });
  await act(async () => {});
  expect(scopeCalls).toBe(initial);
  // a visibility change refetches
  rerender(
    <Endpoints isVisible={false} resetTrigger={0}
      pivotHost={null} activeIncidentId="INC-0001" />
  );
  await act(async () => {});
  rerender(
    <Endpoints isVisible resetTrigger={0}
      pivotHost={null} activeIncidentId="INC-0001" />
  );
  await act(async () => {});
  expect(scopeCalls).toBe(initial + 1);
});
