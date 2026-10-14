/**
 * Owner follow-up pass (2026-10-13): the ONE simple search box, replacing
 * the Advanced LCQL toggle (which replaced the A3 F7 projection earlier
 * the same day). This suite proves:
 * - there is no mode toggle and no LCQL bar; Timeframe + the search box
 *   are the whole typed surface;
 * - the three accepted shapes (field = value with friendly aliases, field
 *   contains text, plain free text) all become filter chips and execute
 *   through the chokepoint;
 * - parsed chips MERGE with the existing facet state (search and facets
 *   are one filter system);
 * - unknown fields get the friendly error inline, and nothing executes;
 * - the Timeframe `all` token reads Incident Window with a case pinned
 *   and All Time otherwise, and a timeframe change reruns current filters;
 * - the search box works as the FIRST action too (no snapshot needed).
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import Siem from '../components/Siem';
import {
  INCIDENT_WINDOW_LABEL, ALL_TIME_LABEL, SHOW_EVENTS,
  searchUnknownField, SEARCH_IP_CONTAINS,
} from '../components/uiCopy';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
const EVENT = {
  id: 'ss-1', event_seq: 9, timestamp: '2026-03-17T05:10:00+00:00',
  event_type: 'ProcessCreate', source_type: 'Sysmon', severity: 'high',
  hostname: 'ACME-WS12', message: 'filters fixture event', key_value_pairs: {},
};
const snapWithQ = (canonical, scope = 'session') => ({
  token: 'tok.one',
  identity: {
    canonical_query: canonical, scope, resolved_scope_hosts: [],
    resolved_range: { start: '2026-03-17T03:41:00+00:00', end: '2026-03-17T05:20:00+00:00' },
    cutoff_seq: 9,
  },
  count: 1, rows: [EVENT],
});

beforeEach(() => {
  apiFetch.mockReset();
  apiFetch.mockImplementation((p) => {
    if (p.startsWith('/api/events/query/new-count')) return ok({ new_count: 0, pool_growth: 0 });
    if (p.startsWith('/api/events/query')) {
      const m = decodeURIComponent(p).match(/\?q=(.+)&scope=(.+)$/);
      return ok(snapWithQ(m[1], m[2]));
    }
    if (p.match(/^\/api\/incidents\/[^/]+\/scope$/)) {
      return ok({ incident_id: p.split('/')[3], sealed: true, hosts: [], accounts: [], detection_ids: [] });
    }
    return ok({});
  });
});

const renderDefault = (props = {}) =>
  render(<Siem resetTrigger={0} onHostPivot={() => {}} {...props} />);
const queryCalls = () =>
  apiFetch.mock.calls.map((c) => c[0]).filter((p) => p.startsWith('/api/events/query?'))
    .map(decodeURIComponent);
const search = async (text) => {
  fireEvent.change(screen.getByLabelText('Search events'), { target: { value: text } });
  await act(async () => {
    fireEvent.keyDown(screen.getByLabelText('Search events'), { key: 'Enter' });
  });
};

test('no mode toggle, no LCQL bar, no dropdowns: Timeframe + the one search box', () => {
  renderDefault();
  expect(screen.queryByTestId('query-mode-toggle')).toBeNull();
  expect(screen.queryByLabelText('LCQL query')).toBeNull();
  expect(screen.queryByLabelText('Source')).toBeNull();
  expect(screen.queryByLabelText('Event Type')).toBeNull();
  expect(screen.getByLabelText('Timeframe')).toBeInTheDocument();
  expect(screen.getByLabelText('Search events')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Search' })).toBeInTheDocument();
});

test('a search is a valid FIRST action: no snapshot needed', async () => {
  renderDefault();
  await search('computer = ACME-WS12');
  expect(queryCalls().pop())
    .toBe('/api/events/query?q=1h | * | * | hostname == "ACME-WS12"&scope=session');
  expect(screen.getByTestId('filter-chips').textContent).toContain('Computer: ACME-WS12');
});

test('field contains text and ip = value both land as their chip shapes', async () => {
  renderDefault();
  await search('user contains khan');
  expect(queryCalls().pop())
    .toBe('/api/events/query?q=1h | * | * | user_account contains "khan"&scope=session');
  await search('ip = 10.0.1.5');
  // the entity pair ANDs with the existing contains chip on every arm
  expect(queryCalls().pop()).toBe(
    '/api/events/query?q=1h | * | * | '
    + 'source_ip == "10.0.1.5" and user_account contains "khan"'
    + ' or destination_ip == "10.0.1.5" and user_account contains "khan"'
    + '&scope=session');
  const chips = screen.getByTestId('filter-chips').textContent;
  expect(chips).toContain('User Account contains "khan"');
  expect(chips).toContain('IP: 10.0.1.5');
});

test('search merges with facet selections: one filter system', async () => {
  renderDefault();
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: SHOW_EVENTS }));
  });
  await act(async () => {
    fireEvent.click(within(screen.getByTestId('facet-group-severity')).getByLabelText('Severity: high'));
  });
  await search('computer = ACME-WS12');
  expect(queryCalls().pop()).toBe(
    '/api/events/query?q=1h | * | * | severity == "high" and hostname == "ACME-WS12"&scope=session');
  // a duplicate search adds nothing and reruns the same compiled query
  await search('severity = high');
  expect(queryCalls().pop()).toBe(
    '/api/events/query?q=1h | * | * | severity == "high" and hostname == "ACME-WS12"&scope=session');
  expect(screen.getAllByLabelText(/Remove filter:/)).toHaveLength(2);
});

test('unknown fields and ip-contains get friendly inline errors; nothing executes', async () => {
  renderDefault();
  const before = queryCalls().length;
  await search('computr = ACME-WS28');
  expect(screen.getByTestId('search-error').textContent).toBe(searchUnknownField('computr'));
  await search('ip contains 10.0.');
  expect(screen.getByTestId('search-error').textContent).toBe(SEARCH_IP_CONTAINS);
  expect(queryCalls().length).toBe(before);
});

test('the Timeframe all token reads All Time without a case and Incident Window with one', async () => {
  const noCase = renderDefault();
  const options = () => Array.from(screen.getByLabelText('Timeframe').options)
    .map((o) => [o.value, o.textContent]);
  expect(options()).toContainEqual(['all', ALL_TIME_LABEL]);
  noCase.unmount();

  await act(async () => {
    renderDefault({ activeIncidentId: 'INC-77' });
  });
  expect(options()).toContainEqual(['all', INCIDENT_WINDOW_LABEL]);
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: SHOW_EVENTS }));
  });
  await act(async () => {
    fireEvent.change(screen.getByLabelText('Timeframe'), { target: { value: 'all' } });
  });
  expect(queryCalls().pop()).toBe('/api/events/query?q=all | * | * | *&scope=INC-77');
});

test('a timeframe change with a snapshot reruns the current filters immediately', async () => {
  renderDefault();
  await search('severity = high');
  await act(async () => {
    fireEvent.change(screen.getByLabelText('Timeframe'), { target: { value: '4h' } });
  });
  expect(queryCalls().pop())
    .toBe('/api/events/query?q=4h | * | * | severity == "high"&scope=session');
});
