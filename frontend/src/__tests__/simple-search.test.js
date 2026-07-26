/**
 * Amendment 3 F7 (A3.5): simple search as a projection over canonical
 * LCQL (ratified A3-OD-1 strings, A3-OD-4 default).
 * - Simple is the DEFAULT mode: the bar holds ONLY the FILTERS expression
 *   (ruled placeholder), the Timeframe picker and the Source / Event type
 *   selects own the other tokens, and Run compiles the four-part
 *   canonical through the generator chokepoint.
 * - The controls are value-driven: every server-canonical query
 *   re-projects (a hostname sensor from a pivot renders as its own
 *   option), so mode stability holds by construction.
 * - An empty FILTERS field compiles to `*` (the legitimate match-all);
 *   "No query entered." is advanced-only.
 * - One toggle to Advanced LCQL shows the identical canonical text; mode
 *   toggling never loses or rewrites query text.
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import Siem from '../components/Siem';
import {
  SIMPLE_PLACEHOLDER, SIMPLE_HELP, SIMPLE_TOGGLE, ADVANCED_TOGGLE,
  NO_QUERY_ENTERED,
} from '../components/uiCopy';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
const EVENT = {
  id: 'ss-1', event_seq: 9, timestamp: '2026-03-17T05:10:00+00:00',
  event_type: 'ProcessCreate', source_type: 'Sysmon', severity: 'high',
  hostname: 'ACME-WS12', message: 'simple fixture event', key_value_pairs: {},
};
const snapWithQ = (canonical) => ({
  token: 'tok.one',
  identity: {
    canonical_query: canonical, scope: 'session', resolved_scope_hosts: [],
    resolved_range: { start: '2026-03-17T03:41:00+00:00', end: '2026-03-17T05:20:00+00:00' },
    cutoff_seq: 9,
  },
  count: 1, rows: [EVENT],
});

let queryResponses;
beforeEach(() => {
  queryResponses = [];
  apiFetch.mockReset();
  apiFetch.mockImplementation((p) => {
    if (p === '/api/endpoints') return ok({ org: {}, endpoints: [] });
    if (p.startsWith('/api/events/query/new-count')) return ok({ new_count: 0, pool_growth: 0 });
    if (p.startsWith('/api/events/query')) {
      return queryResponses.length ? queryResponses.shift()
        : ok(snapWithQ('1h | * | * | *'));
    }
    return ok({});
  });
});

const renderSimple = () => render(<Siem resetTrigger={0} onHostPivot={() => {}} />);
const queryCalls = () =>
  apiFetch.mock.calls.map((c) => c[0]).filter((p) => p.startsWith('/api/events/query?'))
    .map(decodeURIComponent);

test('A3-OD-4: Simple search is the default; the ruled placeholder and help render; Advanced is one toggle away', () => {
  renderSimple();
  const bar = screen.getByLabelText('Filters');
  expect(bar.getAttribute('placeholder')).toBe(SIMPLE_PLACEHOLDER);
  expect(screen.getByText(SIMPLE_HELP)).toBeInTheDocument();
  expect(screen.getByTestId('query-mode-toggle').textContent).toBe(ADVANCED_TOGGLE);
  expect(screen.getByLabelText('Source')).toBeInTheDocument();
  expect(screen.getByLabelText('Event type')).toBeInTheDocument();
});

test('an untouched simple state runs the compiled default (empty FILTERS is match-all; never "No query entered.")', async () => {
  renderSimple();
  const runBtn = screen.getByRole('button', { name: /Run Query/ });
  expect(runBtn).not.toBeDisabled();
  await act(async () => { fireEvent.click(runBtn); });
  expect(queryCalls().pop()).toBe('/api/events/query?q=1h | * | * | *&scope=session');
  expect(screen.queryByText(NO_QUERY_ENTERED)).toBeNull();
});

test('the controls compile through the chokepoint: filters text + picker + selects land in the four-part query', async () => {
  queryResponses.push(ok(snapWithQ('24h | Sysmon | ProcessCreate | source_ip == "10.0.1.32"')));
  renderSimple();
  fireEvent.change(screen.getByLabelText('Filters'), { target: { value: 'source_ip == "10.0.1.32"' } });
  fireEvent.change(screen.getByLabelText('Timeframe'), { target: { value: '24h' } });
  fireEvent.change(screen.getByLabelText('Source'), { target: { value: 'Sysmon' } });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Run Query/ })); });
  expect(queryCalls().pop()).toBe(
    '/api/events/query?q=24h | Sysmon | * | source_ip == "10.0.1.32"&scope=session');
});

test('mode toggling never loses text: Advanced shows the identical canonical; Simple re-projects it', async () => {
  queryResponses.push(ok(snapWithQ('1h | Sysmon | * | source_ip == "10.0.1.32"')));
  renderSimple();
  fireEvent.change(screen.getByLabelText('Filters'), { target: { value: 'source_ip == "10.0.1.32"' } });
  fireEvent.change(screen.getByLabelText('Source'), { target: { value: 'Sysmon' } });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Run Query/ })); });
  fireEvent.click(screen.getByTestId('query-mode-toggle'));
  const advBar = screen.getByLabelText('LCQL query');
  expect(advBar).toHaveValue('1h | Sysmon | * | source_ip == "10.0.1.32"');
  expect(screen.getByTestId('query-mode-toggle').textContent).toBe(SIMPLE_TOGGLE);
  fireEvent.click(screen.getByTestId('query-mode-toggle'));
  expect(screen.getByLabelText('Filters')).toHaveValue('source_ip == "10.0.1.32"');
  expect(screen.getByLabelText('Source')).toHaveValue('Sysmon');
});

test('a pivot canonical re-projects: the hostname sensor renders as its own Source option (mode stability)', async () => {
  renderSimple();
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Run Query/ })); });
  fireEvent.click(within(screen.getByTestId('workbench-results')).getByText('simple fixture event'));
  queryResponses.push(ok(snapWithQ('1h | ACME-WS12 | * | *')));
  await act(async () => { fireEvent.click(screen.getByLabelText('Pivot hostname')); });
  expect(queryCalls().pop()).toBe('/api/events/query?q=1h | ACME-WS12 | * | *&scope=session');
  // the executed canonical projects back into the simple controls
  expect(screen.getByLabelText('Source')).toHaveValue('ACME-WS12');
  expect(screen.getByLabelText('Filters')).toHaveValue('');
});

test('a hand-authored advanced text that does not split into four sections cannot project: the toggle disables', async () => {
  renderSimple();
  fireEvent.click(screen.getByTestId('query-mode-toggle'));   // to Advanced
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'not a query' } });
  expect(screen.getByTestId('query-mode-toggle')).toBeDisabled();
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'all | * | * | *' } });
  expect(screen.getByTestId('query-mode-toggle')).not.toBeDisabled();
});

test('the simple help examples are edit-only FILTERS snippets', () => {
  renderSimple();
  fireEvent.click(screen.getByText('source_ip == "10.0.1.32"'));
  expect(screen.getByLabelText('Filters')).toHaveValue('source_ip == "10.0.1.32"');
  expect(queryCalls()).toEqual([]);   // nothing ran
});
