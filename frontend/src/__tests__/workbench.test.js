/**
 * The SIEM shell (Stage 4 Phase 4 core, under the owner simplification
 * pass + follow-up 2026-10-13: ONE filter system, one simple search box,
 * no LCQL bar).
 *
 * Core contract points carried forward: the shell submits chokepoint-
 * compiled LCQL to the server and renders the response, nothing more (P8:
 * no client-side query execution); a failed run preserves the prior
 * snapshot with the not-run + stale sentences; the shell never polls for
 * rows; display sanitization (sanitizeEvent strip + raw JSON behind All
 * Fields). New points: the search box's three accepted shapes become
 * chips; unknown fields get a friendly error; the snapshot meta line is
 * the trimmed Results for / Snapshot / Scope form.
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import Siem from '../components/Siem';
import { sanitizeEvent } from '../components/siemUtils';
import { SEARCH_NOT_RUN, STALE_RESULTS_NOTE, searchUnknownField } from '../components/uiCopy';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const ROW = {
  id: 'e1', event_seq: 7, timestamp: '2026-03-17T04:00:00+00:00',
  event_type: 'ProcessCreate', source_type: 'Sysmon', severity: 'high',
  hostname: 'ACME-WS12', source_ip: '10.0.1.12', user_account: 'ACME\\nkhan',
  message: 'Process created: nmap.exe launched by cmd.exe',
  key_value_pairs: { event_id: 1, process_id: '8844' },
};

const SNAPSHOT = {
  token: 'tok.abc',
  identity: {
    canonical_query: '1h | * | * | *',
    scope: 'session',
    resolved_scope_hosts: [],
    resolved_range: { start: '2026-03-17T03:41:00+00:00', end: '2026-03-17T04:00:00+00:00' },
    cutoff_seq: 7,
  },
  count: 1,
  rows: [ROW],
};

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

let queryResponses;
beforeEach(() => {
  queryResponses = [];
  apiFetch.mockImplementation((path) => {
    if (path.startsWith('/api/events/query/new-count')) return ok({ new_count: 0, pool_growth: 0 });
    if (path.startsWith('/api/events/query')) {
      if (queryResponses.length) return queryResponses.shift();
      const q = decodeURIComponent(path).match(/\?q=(.+)&scope=/)[1];
      return ok({ ...SNAPSHOT, identity: { ...SNAPSHOT.identity, canonical_query: q } });
    }
    return ok({});
  });
});

const renderShell = () => render(<Siem resetTrigger={0} onHostPivot={() => {}} />);

const showEvents = async () => {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Show Events' }));
  });
};

const search = async (text) => {
  fireEvent.change(screen.getByLabelText('Search events'), { target: { value: text } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Search' }));
  });
};

const results = () => within(screen.getByTestId('workbench-results'));
const queryCalls = () =>
  apiFetch.mock.calls.map((c) => c[0]).filter((p) => p.startsWith('/api/events/query?'))
    .map(decodeURIComponent);

test('empty state: Show Events, the search box, and NO LCQL bar anywhere', () => {
  renderShell();
  expect(screen.getByText('No events loaded yet.')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Show Events' })).toBeInTheDocument();
  expect(screen.getByLabelText('Search events')).toBeInTheDocument();
  expect(screen.queryByLabelText('LCQL query')).toBeNull();
  expect(screen.queryByTestId('query-mode-toggle')).toBeNull();
  expect(screen.queryByText(/LCQL has four segments/)).toBeNull();
});

test('Show Events submits the compiled match-all and renders the returned rows', async () => {
  renderShell();
  await showEvents();
  expect(queryCalls().pop()).toBe('/api/events/query?q=1h | * | * | *&scope=session');
  expect(results().getByText(/nmap.exe launched/)).toBeInTheDocument();
});

test('the search box: field = value compiles through the chokepoint and lands as a chip', async () => {
  renderShell();
  await showEvents();
  await search('computer = ACME-WS12');
  expect(queryCalls().pop())
    .toBe('/api/events/query?q=1h | * | * | hostname == "ACME-WS12"&scope=session');
  expect(screen.getByTestId('filter-chips').textContent).toContain('Computer: ACME-WS12');
  expect(screen.getByLabelText('Search events')).toHaveValue('');   // cleared on success
});

test('the search box: plain free text searches the event message', async () => {
  renderShell();
  await showEvents();
  await search('nmap launched');
  expect(queryCalls().pop())
    .toBe('/api/events/query?q=1h | * | * | message contains "nmap launched"&scope=session');
  expect(screen.getByTestId('filter-chips').textContent)
    .toContain('Message contains "nmap launched"');
});

test('an unknown field gets the friendly error and nothing runs', async () => {
  renderShell();
  await showEvents();
  const before = queryCalls().length;
  await search('computr = ACME-WS12');
  expect(queryCalls().length).toBe(before);
  expect(screen.getByTestId('search-error').textContent)
    .toBe(searchUnknownField('computr'));
  // typing again clears the error
  fireEvent.change(screen.getByLabelText('Search events'), { target: { value: 'c' } });
  expect(screen.queryByTestId('search-error')).toBeNull();
});

test('no client-side query execution: rows render exactly as served (P8)', async () => {
  // The served row does not lexically match the search at all; a client
  // that re-filtered would drop it. The shell must render it verbatim.
  renderShell();
  await showEvents();
  queryResponses.push(ok(SNAPSHOT));
  await search('zzz-no-such-string');
  expect(results().getByText(/nmap.exe launched/)).toBeInTheDocument();
});

test('a failed run preserves the prior snapshot with the not-run and stale sentences', async () => {
  renderShell();
  await showEvents();
  expect(results().getByText(/nmap.exe launched/)).toBeInTheDocument();
  queryResponses.push(Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve(null) }));
  await search('severity = high');
  const alert = screen.getByRole('alert');
  expect(alert.textContent).toContain(SEARCH_NOT_RUN);
  expect(alert.textContent).toContain(STALE_RESULTS_NOTE);
  expect(results().getByText(/nmap.exe launched/)).toBeInTheDocument();
});

test('the trimmed snapshot meta line: Results for / Snapshot / Scope, nothing more', async () => {
  renderShell();
  await showEvents();
  const metaRow = screen.getByTestId('results-label').parentElement;
  expect(screen.getByTestId('results-label').textContent).toBe('Results for: all events');
  expect(metaRow.textContent).toContain('Snapshot: 1 events');
  expect(metaRow.textContent).toContain('Scope: Session');
  // the seq number, sim timestamp, and raw segment dump are gone
  expect(metaRow.textContent).not.toMatch(/as of seq #/);
  expect(metaRow.textContent).not.toMatch(/\d{2}:\d{2}:\d{2} sim/);
  expect(metaRow.textContent).not.toContain('1h | * | * | *');
  expect(metaRow.textContent).not.toContain('scope=');
});

test('the shell never polls: no event requests without an explicit action', async () => {
  jest.useFakeTimers();
  renderShell();
  await act(async () => { jest.advanceTimersByTime(10000); });
  const eventCalls = apiFetch.mock.calls.map(c => c[0])
    .filter(p => p.startsWith('/api/events/query'));
  expect(eventCalls).toEqual([]);
  jest.useRealTimers();
});

test('sanitizeEvent strips every simulation-internal field (carried forward)', () => {
  const clean = sanitizeEvent({
    ...ROW, label: 'lateral_movement_1', category: 'Lateral Movement',
    scenario_id: 'scenario-abc', storyline: 'secret', flagged: true,
    alert_id: 'INC-1234', status: 'active', chain_complete: true, trigger: true,
  });
  for (const k of ['label', 'category', 'scenario_id', 'storyline', 'flagged',
                   'alert_id', 'status', 'chain_complete', 'trigger']) {
    expect(clean).not.toHaveProperty(k);
  }
  expect(clean.event_type).toBe('ProcessCreate');
  expect(clean.key_value_pairs.process_id).toBe('8844');
});

test('the raw JSON behind All Fields is sanitized only (carried forward)', async () => {
  renderShell();
  await showEvents();
  fireEvent.click(results().getByText(/nmap.exe launched/));
  fireEvent.click(screen.getByRole('button', { name: /All Fields/ }));
  const pre = document.querySelector('pre');
  expect(pre).not.toBeNull();
  for (const k of ['label', 'category', 'scenario_id', 'storyline', 'alert_id']) {
    expect(pre.textContent).not.toContain(`"${k}"`);
  }
  expect(pre.textContent).toContain('"event_type"');
});

test('table view toggle renders the frozen snapshot rows', async () => {
  renderShell();
  await showEvents();
  fireEvent.click(screen.getByRole('button', { name: 'Table' }));
  expect(await screen.findByText('Src Type')).toBeInTheDocument();
  expect(screen.getAllByText(/nmap.exe launched/).length).toBeGreaterThan(0);
});
