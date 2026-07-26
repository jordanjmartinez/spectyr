/**
 * Stage 4 Phase 5: stable-result experience (contract Section 7).
 *
 * 5.1: deterministic mocked assertions for byte-stable rows and order,
 * atomic replacement, Refresh bound to the executed identity (never the
 * bar text), selection persistence by id, and the one-line absence notice.
 * 5.2 extends this file with the new-events indicator battery.
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import Siem from '../components/Siem';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const row = (id, seq, msg, ts) => ({
  id, event_seq: seq, timestamp: ts,
  event_type: 'ProcessCreate', source_type: 'Sysmon', severity: 'high',
  hostname: 'ACME-WS12', source_ip: '10.0.1.12', user_account: 'ACME\\nkhan',
  message: msg, key_value_pairs: { image: 'C:\\x.exe' },
});

const R1 = row('e1', 1, 'alpha event one', '2026-03-17T04:00:10+00:00');
const R2 = row('e2', 2, 'bravo event two', '2026-03-17T04:00:20+00:00');
const R3 = row('e3', 3, 'charlie event three', '2026-03-17T04:00:30+00:00');

const snap = (rows, { cutoff, token = 'tok.one', canonical = 'all | * | * | *', scope = 'session' } = {}) => ({
  token,
  identity: {
    canonical_query: canonical, scope, resolved_scope_hosts: [],
    resolved_range: { start: '2026-03-17T03:41:00+00:00', end: '2026-03-17T04:01:00+00:00' },
    cutoff_seq: cutoff ?? rows.length,
  },
  count: rows.length,
  rows,
});

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

let queryResponses;
let countResponse;
beforeEach(() => {
  queryResponses = [];
  countResponse = () => ok({ new_count: 0, pool_growth: 0 });
  apiFetch.mockImplementation((path) => {
    if (path === '/api/endpoints') return ok({ org: { name: 'ACME Corp' }, endpoints: [] });
    if (path.startsWith('/api/events/query/new-count')) return countResponse();
    if (path.startsWith('/api/events/query')) {
      return queryResponses.length ? queryResponses.shift() : ok(snap([R2, R1]));
    }
    return ok({});
  });
});

const renderShell = () => {
  const utils = render(<Siem initialQueryMode="advanced" resetTrigger={0} onHostPivot={() => {}} />);
  return utils;
};

const run = async (text) => {
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: text } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: /Run Query/ }));
  });
};

const resultsHtml = () => document.querySelector('.grid').outerHTML;
// The field sidebar (P6.2) also renders top message VALUES, which can
// duplicate a row's own message text; scope row-content queries to the
// results pane specifically so they cannot match a sidebar button too.
const results = () => within(screen.getByTestId('workbench-results'));

test('rows and order are byte-stable across unrelated re-renders', async () => {
  renderShell();
  await run('all | * | * | *');
  const before = resultsHtml();
  // unrelated interactions that re-render the shell but must not touch rows
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'draft edit' } });
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'another draft' } });
  expect(resultsHtml()).toBe(before);
});

test('atomic replacement: prior rows fully visible while a run is pending, then swap whole', async () => {
  renderShell();
  await run('all | * | * | *');
  expect(results().getByText(/alpha event one/)).toBeInTheDocument();
  expect(results().getByText(/bravo event two/)).toBeInTheDocument();

  let resolveNext;
  queryResponses.push(new Promise((res) => {
    resolveNext = () => res({ ok: true, status: 200, json: () => Promise.resolve(snap([R3], { token: 'tok.two' })) });
  }));
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'all | * | * | *' } });
  fireEvent.click(screen.getByRole('button', { name: /Run Query|Running/ }));
  // pending: the prior snapshot is untouched and complete
  expect(results().getByText(/alpha event one/)).toBeInTheDocument();
  expect(results().getByText(/bravo event two/)).toBeInTheDocument();
  expect(screen.queryByText(/charlie event three/)).toBeNull();
  await act(async () => { resolveNext(); });
  // swapped whole: only the new row set renders
  expect(results().getByText(/charlie event three/)).toBeInTheDocument();
  expect(screen.queryByText(/alpha event one/)).toBeNull();
  expect(screen.queryByText(/bravo event two/)).toBeNull();
});

test('Refresh re-executes the executed identity, never the edited bar text', async () => {
  renderShell();
  await run('all | * | * | *');
  fireEvent.change(screen.getByLabelText('LCQL query'), {
    target: { value: 'this is not even lcql' } });
  queryResponses.push(ok(snap([R2, R1], { token: 'tok.two', cutoff: 9 })));
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
  });
  const calls = apiFetch.mock.calls.map(c => c[0])
    .filter(p => p.startsWith('/api/events/query?'));
  expect(calls[calls.length - 1]).toBe(
    `/api/events/query?q=${encodeURIComponent('all | * | * | *')}&scope=session`);
  expect(screen.getByText(/as of seq #9/)).toBeInTheDocument();
});

test('selection persists across Refresh when the inspected id survives', async () => {
  renderShell();
  await run('all | * | * | *');
  fireEvent.click(results().getByText(/alpha event one/));
  expect(document.querySelector('pre')).not.toBeNull();   // inspector open
  queryResponses.push(ok(snap([R3, R2, R1], { token: 'tok.two' })));
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
  });
  expect(document.querySelector('pre')).not.toBeNull();   // still open on e1
  expect(screen.queryByText('The inspected event is not in the new snapshot.')).toBeNull();
});

test('inspector closes with the one-line notice when the inspected id is gone', async () => {
  renderShell();
  await run('all | * | * | *');
  fireEvent.click(results().getByText(/alpha event one/));
  expect(document.querySelector('pre')).not.toBeNull();
  queryResponses.push(ok(snap([R3], { token: 'tok.two' })));
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
  });
  expect(document.querySelector('pre')).toBeNull();       // inspector closed
  expect(screen.getByText('The inspected event is not in the new snapshot.')).toBeInTheDocument();
  // the notice clears on the next selection
  fireEvent.click(results().getByText(/charlie event three/));
  expect(screen.queryByText('The inspected event is not in the new snapshot.')).toBeNull();
});

test('selection is shared across the Cards/Table view toggle', async () => {
  renderShell();
  await run('all | * | * | *');
  fireEvent.click(results().getByText(/alpha event one/));
  fireEvent.click(screen.getByRole('button', { name: 'Table' }));
  expect(await screen.findByText('Src Type')).toBeInTheDocument();
  // the expanded table row for e1 renders the detail view
  expect(document.body.textContent).toContain('alpha event one');
});

// --- Phase 5.2: the new-events indicator ------------------------------------

const tickPoll = async (ms = 3000) => {
  await act(async () => { jest.advanceTimersByTime(ms); });
  await act(async () => {});          // flush the poll's promise chain
};

const countCalls = () => apiFetch.mock.calls.map(c => c[0])
  .filter(p => p.startsWith('/api/events/query/new-count'));

describe('indicator (fake timers)', () => {
  beforeEach(() => { jest.useFakeTimers(); });
  afterEach(() => { jest.useRealTimers(); });

  test('rows stay byte-stable across multiple poll cycles while the count climbs', async () => {
    renderShell();
    await run('all | * | * | *');
    const before = resultsHtml();
    let n = 0;
    countResponse = () => { n += 1; return ok({ new_count: n * 2, pool_growth: n * 3 }); };
    await tickPoll();
    await tickPoll();
    await tickPoll();
    expect(resultsHtml()).toBe(before);   // zero automatic row movement
    expect(screen.getByTestId('new-events-indicator').textContent).toBe('6 new');
    expect(screen.getByTestId('pool-growth').textContent).toBe('pool: +9');
  });

  test('zero state: the indicator is hidden at count 0', async () => {
    renderShell();
    await run('all | * | * | *');
    countResponse = () => ok({ new_count: 0, pool_growth: 0 });
    await tickPoll();
    expect(screen.queryByTestId('new-events-indicator')).toBeNull();
    expect(screen.queryByTestId('pool-growth')).toBeNull();
  });

  test('de-emphasized when the bar differs from the executed canonical query', async () => {
    renderShell();
    await run('all | * | * | *');
    countResponse = () => ok({ new_count: 4, pool_growth: 4 });
    await tickPoll();
    const badge = screen.getByTestId('new-events-indicator');
    expect(badge.className).not.toMatch(/opacity-50/);
    expect(badge.textContent).toBe('4 new');
    // the bar was synced to the canonical text on run; an edit diverges it
    fireEvent.change(screen.getByLabelText('LCQL query'),
      { target: { value: 'all | * | * | * draft' } });
    const stale = screen.getByTestId('new-events-indicator');
    expect(stale.className).toMatch(/opacity-50/);
    expect(stale.textContent).toBe('4 new (last run)');
  });

  // (The Expanded-search scope-divergence case retired with the state
  // itself, Final pass III.0 item 2: a pivot or run can no longer flip the
  // executed scope away from the displayed snapshot's. The text-divergence
  // de-emphasis above remains the honest edited-bar behavior.)

  test('the indicator resets after a deliberate Refresh', async () => {
    renderShell();
    await run('all | * | * | *');
    countResponse = () => ok({ new_count: 5, pool_growth: 8 });
    await tickPoll();
    expect(screen.getByTestId('new-events-indicator').textContent).toBe('5 new');
    queryResponses.push(ok(snap([R3, R2, R1], { token: 'tok.two', cutoff: 12 })));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    });
    expect(screen.queryByTestId('new-events-indicator')).toBeNull();
    expect(screen.getByText(/as of seq #12/)).toBeInTheDocument();
  });

  test('the poll carries ONLY the token, bound to the executed snapshot', async () => {
    renderShell();
    await run('all | * | * | *');
    fireEvent.change(screen.getByLabelText('LCQL query'),
      { target: { value: 'edited draft text' } });
    countResponse = () => ok({ new_count: 1, pool_growth: 1 });
    await tickPoll();
    await tickPoll();
    const calls = countCalls();
    expect(calls.length).toBeGreaterThanOrEqual(2);
    for (const url of calls) {
      expect(url).toBe(`/api/events/query/new-count?token=${encodeURIComponent('tok.one')}`);
    }
  });

  test('the poll halts neutrally on token invalidation', async () => {
    renderShell();
    await run('all | * | * | *');
    countResponse = () => ok({ new_count: 3, pool_growth: 3 });
    await tickPoll();
    expect(screen.getByTestId('new-events-indicator')).toBeInTheDocument();
    // token invalidated (reset/restart server-side): neutral 400
    countResponse = () => Promise.resolve({ ok: false, status: 400,
      json: () => Promise.resolve({ error: 'Unknown token' }) });
    await tickPoll();
    expect(screen.queryByTestId('new-events-indicator')).toBeNull();
    expect(screen.queryByRole('alert')).toBeNull();          // neutral: no error surface
    const after = countCalls().length;
    await tickPoll();
    await tickPoll();
    expect(countCalls().length).toBe(after);                 // polling stopped
  });

  test('client column sorting issues no network request and keeps the snapshot token', async () => {
    renderShell();
    await run('all | * | * | *');
    fireEvent.click(screen.getByRole('button', { name: 'Table' }));
    await screen.findByText('Src Type');
    const callsBefore = apiFetch.mock.calls.length;
    fireEvent.click(screen.getByRole('button', { name: /^Time/ }));
    fireEvent.click(screen.getByRole('button', { name: /^Time/ }));
    fireEvent.click(screen.getByRole('button', { name: /Event Type/ }));
    expect(apiFetch.mock.calls.length).toBe(callsBefore);    // zero requests
    expect(screen.getByText(/as of seq #2/)).toBeInTheDocument();  // same snapshot
    countResponse = () => ok({ new_count: 1, pool_growth: 1 });
    await tickPoll();
    // the poll still carries the ORIGINAL token after sorting
    expect(countCalls().pop()).toBe(
      `/api/events/query/new-count?token=${encodeURIComponent('tok.one')}`);
  });
});
