/**
 * Stage 4 Phase 5: stable-result experience (contract Section 7), under
 * the Final-pass Load-new-events action (III.0 item 4).
 *
 * 5.1: deterministic mocked assertions for byte-stable rows and order,
 * atomic replacement, Load New Events bound to the executed identity
 * (never the bar text) and existing ONLY beside a nonzero authoritative
 * count, selection persistence by id, and the ruled hidden-selection
 * notice. 5.2 extends this file with the new-events indicator battery.
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import Siem from '../components/Siem';
import { SELECTED_EVENT_HIDDEN } from '../components/uiCopy';

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
  const utils = render(<Siem resetTrigger={0} onHostPivot={() => {}} />);
  return utils;
};

const showEvents = async () => {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Show Events' }));
  });
};

const resultsHtml = () => document.querySelector('.grid').outerHTML;
// The field sidebar (P6.2) also renders top message VALUES, which can
// duplicate a row's own message text; scope row-content queries to the
// results pane specifically so they cannot match a sidebar button too.
const results = () => within(screen.getByTestId('workbench-results'));

test('rows and order are byte-stable across unrelated re-renders', async () => {
  renderShell();
  await showEvents();
  const before = resultsHtml();
  // unrelated interactions that re-render the shell but must not touch rows
  fireEvent.change(screen.getByLabelText('Search events'), { target: { value: 'draft edit' } });
  fireEvent.change(screen.getByLabelText('Search events'), { target: { value: 'another draft' } });
  expect(resultsHtml()).toBe(before);
});

test('atomic replacement: prior rows fully visible while a run is pending, then swap whole', async () => {
  renderShell();
  await showEvents();
  expect(results().getByText(/alpha event one/)).toBeInTheDocument();
  expect(results().getByText(/bravo event two/)).toBeInTheDocument();

  let resolveNext;
  queryResponses.push(new Promise((res) => {
    resolveNext = () => res({ ok: true, status: 200, json: () => Promise.resolve(snap([R3], { token: 'tok.two' })) });
  }));
  fireEvent.change(screen.getByLabelText('Search events'), { target: { value: 'severity = high' } });
  fireEvent.keyDown(screen.getByLabelText('Search events'), { key: 'Enter' });
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

test('selection is shared across the Cards/Table view toggle', async () => {
  renderShell();
  await showEvents();
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

// --- the Load New Events action (III.0 item 4): it exists only beside the
// authoritative nonzero count, so this battery runs under fake timers ------

describe('Load New Events (fake timers)', () => {
  beforeEach(() => { jest.useFakeTimers(); });
  afterEach(() => { jest.useRealTimers(); });

  const arrangeCount = async (n = 2) => {
    countResponse = () => ok({ new_count: n, pool_growth: n });
    await tickPoll();
  };

  test('Load New Events re-executes the executed identity, never any draft search text', async () => {
    renderShell();
    await showEvents();
    await arrangeCount();
    fireEvent.change(screen.getByLabelText('Search events'), {
      target: { value: 'severity = high' } });   // a draft, never submitted
    queryResponses.push(ok(snap([R2, R1], { token: 'tok.two', cutoff: 9 })));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Load New Events' }));
    });
    const calls = apiFetch.mock.calls.map(c => c[0])
      .filter(p => p.startsWith('/api/events/query?'));
    expect(calls[calls.length - 1]).toBe(
      `/api/events/query?q=${encodeURIComponent('all | * | * | *')}&scope=session`);
    // the landed load resets the indicator truthfully
    expect(screen.queryByTestId('new-events-indicator')).toBeNull();
  });

  test('the action exists ONLY beside a nonzero count; loading resets both truthfully; no generic Refresh label', async () => {
    renderShell();
    await showEvents();
    // zero new events: no load control and no generic Refresh anywhere
    expect(screen.queryByTestId('load-new-events')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Refresh' })).toBeNull();
    await arrangeCount(3);
    expect(screen.getByTestId('new-events-indicator').textContent)
      .toBe('3 New Events Available');
    // loading lands a fresh snapshot: count and action leave together
    queryResponses.push(ok(snap([R3, R2, R1], { token: 'tok.two', cutoff: 12 })));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Load New Events' }));
    });
    expect(screen.queryByTestId('new-events-indicator')).toBeNull();
    expect(screen.queryByTestId('load-new-events')).toBeNull();
    expect(screen.getAllByText('3 events').length).toBeGreaterThan(0);
  });

  test('selection persists across Load New Events when the inspected id survives', async () => {
    renderShell();
    await showEvents();
    fireEvent.click(results().getByText(/alpha event one/));
    expect(screen.getByTestId('event-inspector')).toBeInTheDocument();   // inspector open
    await arrangeCount();
    queryResponses.push(ok(snap([R3, R2, R1], { token: 'tok.two' })));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Load New Events' }));
    });
    expect(screen.getByTestId('event-inspector')).toBeInTheDocument();   // still open on e1
    expect(screen.queryByText(SELECTED_EVENT_HIDDEN)).toBeNull();
  });

  test('a hidden inspected event keeps its selection with the ruled notice and reopens when results include it again (III.0 item 3)', async () => {
    renderShell();
    await showEvents();
    fireEvent.click(results().getByText(/alpha event one/));
    expect(screen.getByTestId('event-inspector')).toBeInTheDocument();
    await arrangeCount();
    queryResponses.push(ok(snap([R3], { token: 'tok.two' })));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Load New Events' }));
    });
    // the pane cannot render a hidden event, but the selection is NOT
    // silently dropped and no filter is altered on the player's behalf:
    // the ruled notice explains the state
    expect(screen.queryByTestId('event-inspector')).toBeNull();
    expect(screen.getByText(SELECTED_EVENT_HIDDEN)).toBeInTheDocument();
    // a later result set that includes the event again reopens the SAME
    // selection without a new click
    await arrangeCount();
    queryResponses.push(ok(snap([R3, R2, R1], { token: 'tok.three' })));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Load New Events' }));
    });
    expect(screen.getByTestId('event-inspector')).toBeInTheDocument();
    expect(screen.queryByText(SELECTED_EVENT_HIDDEN)).toBeNull();
    // and selecting another event clears the notice path directly
    await arrangeCount();
    queryResponses.push(ok(snap([R3], { token: 'tok.four' })));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Load New Events' }));
    });
    expect(screen.getByText(SELECTED_EVENT_HIDDEN)).toBeInTheDocument();
    fireEvent.click(results().getByText(/charlie event three/));
    expect(screen.queryByText(SELECTED_EVENT_HIDDEN)).toBeNull();
  });
});

describe('indicator (fake timers)', () => {
  beforeEach(() => { jest.useFakeTimers(); });
  afterEach(() => { jest.useRealTimers(); });

  test('rows stay byte-stable across multiple poll cycles while the count climbs', async () => {
    renderShell();
    await showEvents();
    const before = resultsHtml();
    let n = 0;
    countResponse = () => { n += 1; return ok({ new_count: n * 2, pool_growth: n * 3 }); };
    await tickPoll();
    await tickPoll();
    await tickPoll();
    expect(resultsHtml()).toBe(before);   // zero automatic row movement
    expect(screen.getByTestId('new-events-indicator').textContent)
      .toBe('6 New Events Available');
    expect(screen.getByTestId('pool-growth').textContent).toBe('pool: +9');
  });

  test('zero state: the indicator is hidden at count 0', async () => {
    renderShell();
    await showEvents();
    countResponse = () => ok({ new_count: 0, pool_growth: 0 });
    await tickPoll();
    expect(screen.queryByTestId('new-events-indicator')).toBeNull();
    expect(screen.queryByTestId('pool-growth')).toBeNull();
  });

  // (The edited-bar de-emphasis case retired with the LCQL bar itself,
  // owner follow-up 2026-10-13: a draft in the search box never resembles
  // the executed query, so the indicator always describes the last run.)

  test('the indicator resets after a deliberate Load New Events', async () => {
    renderShell();
    await showEvents();
    countResponse = () => ok({ new_count: 5, pool_growth: 8 });
    await tickPoll();
    expect(screen.getByTestId('new-events-indicator').textContent)
      .toBe('5 New Events Available');
    queryResponses.push(ok(snap([R3, R2, R1], { token: 'tok.two', cutoff: 12 })));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Load New Events' }));
    });
    expect(screen.queryByTestId('new-events-indicator')).toBeNull();
    expect(screen.getAllByText('3 events').length).toBeGreaterThan(0);
  });

  test('the poll carries ONLY the token, bound to the executed snapshot', async () => {
    renderShell();
    await showEvents();
    fireEvent.change(screen.getByLabelText('Search events'),
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
    await showEvents();
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
    await showEvents();
    fireEvent.click(screen.getByRole('button', { name: 'Table' }));
    await screen.findByText('Src Type');
    const callsBefore = apiFetch.mock.calls.length;
    fireEvent.click(screen.getByRole('button', { name: /^Time/ }));
    fireEvent.click(screen.getByRole('button', { name: /^Time/ }));
    fireEvent.click(screen.getByRole('button', { name: /Event Type/ }));
    expect(apiFetch.mock.calls.length).toBe(callsBefore);    // zero requests
    expect(screen.getAllByText('2 events').length).toBeGreaterThan(0);  // same snapshot
    countResponse = () => ok({ new_count: 1, pool_growth: 1 });
    await tickPoll();
    // the poll still carries the ORIGINAL token after sorting
    expect(countCalls().pop()).toBe(
      `/api/events/query/new-count?token=${encodeURIComponent('tok.one')}`);
  });
});
