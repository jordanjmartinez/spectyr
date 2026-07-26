/**
 * Stage 4 Phase 4.1: the SIEM Investigation Workbench shell.
 *
 * Supersedes the retired siem.test.js live-feed cases in the same commit
 * that removes the code they tested (the 2s poll, dropdown filters,
 * field=value search, client time presets). Carries forward the two
 * display-sanitization guards (sanitizeEvent strip + expanded raw JSON).
 *
 * Core contract points: the shell submits LCQL text to the server and
 * renders the response, nothing more (P8: no client-side query execution);
 * parse errors render position + reason with the prior snapshot intact;
 * the placeholder is a canonical conforming example; the GD-5a
 * unquoted-value rules surface in the player-facing query help.
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import Siem, { QUERY_PLACEHOLDER, QUERY_HELP_EXAMPLES } from '../components/Siem';
import { sanitizeEvent } from '../components/siemUtils';

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
    canonical_query: 'all | * | * | *',
    scope: 'session',
    resolved_scope_hosts: [],
    resolved_range: { start: '2026-03-17T03:41:00+00:00', end: '2026-03-17T04:00:00+00:00' },
    cutoff_seq: 7,
  },
  count: 1,
  rows: [ROW],
};

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
const bad = (status, body) => Promise.resolve({ ok: false, status, json: () => Promise.resolve(body) });

let queryResponses;
beforeEach(() => {
  queryResponses = [];
  apiFetch.mockImplementation((path) => {
    if (path === '/api/endpoints') return ok({ org: { name: 'ACME Corp' }, endpoints: [] });
    if (path.startsWith('/api/events/query')) {
      return queryResponses.length ? queryResponses.shift() : ok(SNAPSHOT);
    }
    return ok({});
  });
});

const renderShell = () =>
  render(<Siem resetTrigger={0} onHostPivot={() => {}} />);

const run = async (text) => {
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: text } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: /Run Query/ }));
  });
};

// The field sidebar (P6.2) also renders top message VALUES, which can
// duplicate a row's own message text; scope row-content queries to the
// results pane specifically so they cannot match a sidebar button too.
const results = () => within(screen.getByTestId('workbench-results'));

test('empty state: example placeholder, two valid examples, GD-5a rules in the help copy', () => {
  renderShell();
  const bar = screen.getByLabelText('LCQL query');
  expect(bar).toHaveAttribute('placeholder', QUERY_PLACEHOLDER);
  // A2 (ruled): the placeholder is unmistakably an EXAMPLE -- the prefix is
  // part of the text, and the remainder is a conforming four-segment query
  expect(QUERY_PLACEHOLDER).toMatch(/^Example: \S+ \| .+ \| .+ \| .+$/);
  expect(QUERY_PLACEHOLDER).not.toMatch(/\w+=\w/);   // never key=value drift
  expect(screen.getByText('Run a query to begin.')).toBeInTheDocument();
  for (const ex of QUERY_HELP_EXAMPLES) {
    expect(screen.getByText(ex)).toBeInTheDocument();
  }
  // GD-5a player-facing help (contract post-lock amendment)
  const help = document.body.textContent;
  expect(help).toMatch(/must be quoted/);
  expect(help).toMatch(/and, or, not, contains/);
  expect(help).toMatch(/single quotes match exactly/i);
});

test('Run Query submits the exact encoded text and renders the returned rows', async () => {
  renderShell();
  const q = '1h | Sysmon | * | message contains "nmap"';
  await run(q);
  const call = apiFetch.mock.calls.map(c => c[0]).find(p => p.startsWith('/api/events/query'));
  expect(call).toBe(`/api/events/query?q=${encodeURIComponent(q)}&scope=session`);
  expect(results().getByText(/nmap.exe launched/)).toBeInTheDocument();
  expect(screen.getByText(/as of seq #7/)).toBeInTheDocument();
});

test('no client-side query execution: rows render exactly as served (P8)', async () => {
  // The served row does not lexically match the query text at all; a client
  // that re-filtered would drop it. The shell must render it verbatim.
  renderShell();
  await run('1h | DNS | QUERY | query contains "zzz-no-such"');
  expect(results().getByText(/nmap.exe launched/)).toBeInTheDocument();
});

test('parse error renders position + reason + suggestions; prior snapshot intact', async () => {
  renderShell();
  await run('all | * | * | *');
  expect(results().getByText(/nmap.exe launched/)).toBeInTheDocument();

  queryResponses.push(bad(400, {
    error: { position: 14, reason: 'unknown field \'commandline\'', suggestions: ['command_line'] },
  }));
  await run('all | * | * | commandline == "x"');
  expect(screen.getByRole('alert').textContent).toMatch(/position 14/);
  expect(screen.getByRole('alert').textContent).toMatch(/unknown field/);
  expect(screen.getByRole('alert').textContent).toMatch(/command_line/);
  // the prior snapshot is untouched
  expect(results().getByText(/nmap.exe launched/)).toBeInTheDocument();
  expect(screen.getByText(/as of seq #7/)).toBeInTheDocument();
});

test('no-results state echoes the canonical query', async () => {
  queryResponses.push(ok({ ...SNAPSHOT, count: 0, rows: [],
    identity: { ...SNAPSHOT.identity, canonical_query: '15m | Proxy | * | *' } }));
  renderShell();
  await run('15m | proxy | * | *');
  expect(screen.getByText('0 events match')).toBeInTheDocument();
  // echoed in the no-results pane (and again in the snapshot status bar)
  expect(screen.getAllByText('15m | Proxy | * | *').length).toBeGreaterThanOrEqual(2);
});

test('loading state disables Run and makes the bar read-only until completion', async () => {
  let resolveQuery;
  queryResponses.push(new Promise(res => { resolveQuery = () => res({ ok: true, status: 200, json: () => Promise.resolve(SNAPSHOT) }); }));
  renderShell();
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'all | * | * | *' } });
  fireEvent.click(screen.getByRole('button', { name: /Run Query/ }));
  expect(screen.getByRole('button', { name: /Running/ })).toBeDisabled();
  expect(screen.getByLabelText('LCQL query')).toHaveAttribute('readonly');
  await act(async () => { resolveQuery(); });
  expect(results().getByText(/nmap.exe launched/)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /Run Query/ })).not.toBeDisabled();
});

test('the shell never polls: no event requests without an explicit Run', async () => {
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

test('expanding a card shows sanitized JSON only (carried forward)', async () => {
  renderShell();
  await run('all | * | * | *');
  fireEvent.click(results().getByText(/nmap.exe launched/));
  const pre = document.querySelector('pre');
  expect(pre).not.toBeNull();
  for (const k of ['label', 'category', 'scenario_id', 'storyline', 'alert_id']) {
    expect(pre.textContent).not.toContain(`"${k}"`);
  }
  expect(pre.textContent).toContain('"event_type"');
});

test('table view toggle renders the frozen snapshot rows', async () => {
  renderShell();
  await run('all | * | * | *');
  fireEvent.click(screen.getByRole('button', { name: 'Table' }));
  expect(await screen.findByText('Src Type')).toBeInTheDocument();
  expect(screen.getAllByText(/nmap.exe launched/).length).toBeGreaterThan(0);
});
