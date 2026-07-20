/**
 * Stage 4 Phase 5: stable-result experience (contract Section 7).
 *
 * 5.1: deterministic mocked assertions for byte-stable rows and order,
 * atomic replacement, Refresh bound to the executed identity (never the
 * bar text), selection persistence by id, and the one-line absence notice.
 * 5.2 extends this file with the new-events indicator battery.
 */
import React from 'react';
import { render, screen, fireEvent, act } from '@testing-library/react';
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

const renderShell = () =>
  render(<Siem setSiemCount={() => {}} resetTrigger={0} onHostPivot={() => {}} />);

const run = async (text) => {
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: text } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: /Run Query/ }));
  });
};

const resultsHtml = () => document.querySelector('.grid').outerHTML;

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
  expect(screen.getByText(/alpha event one/)).toBeInTheDocument();
  expect(screen.getByText(/bravo event two/)).toBeInTheDocument();

  let resolveNext;
  queryResponses.push(new Promise((res) => {
    resolveNext = () => res({ ok: true, status: 200, json: () => Promise.resolve(snap([R3], { token: 'tok.two' })) });
  }));
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'all | * | * | *' } });
  fireEvent.click(screen.getByRole('button', { name: /Run Query|Running/ }));
  // pending: the prior snapshot is untouched and complete
  expect(screen.getByText(/alpha event one/)).toBeInTheDocument();
  expect(screen.getByText(/bravo event two/)).toBeInTheDocument();
  expect(screen.queryByText(/charlie event three/)).toBeNull();
  await act(async () => { resolveNext(); });
  // swapped whole: only the new row set renders
  expect(screen.getByText(/charlie event three/)).toBeInTheDocument();
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
  fireEvent.click(screen.getByText(/alpha event one/));
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
  fireEvent.click(screen.getByText(/alpha event one/));
  expect(document.querySelector('pre')).not.toBeNull();
  queryResponses.push(ok(snap([R3], { token: 'tok.two' })));
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
  });
  expect(document.querySelector('pre')).toBeNull();       // inspector closed
  expect(screen.getByText('The inspected event is not in the new snapshot.')).toBeInTheDocument();
  // the notice clears on the next selection
  fireEvent.click(screen.getByText(/charlie event three/));
  expect(screen.queryByText('The inspected event is not in the new snapshot.')).toBeNull();
});

test('selection is shared across the Cards/Table view toggle', async () => {
  renderShell();
  await run('all | * | * | *');
  fireEvent.click(screen.getByText(/alpha event one/));
  fireEvent.click(screen.getByRole('button', { name: 'Table' }));
  expect(await screen.findByText('Src Type')).toBeInTheDocument();
  // the expanded table row for e1 renders the detail view
  expect(document.body.textContent).toContain('alpha event one');
});
