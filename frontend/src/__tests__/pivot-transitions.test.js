/**
 * Phase 3 commit 3.1 (translated 8.2/8.3), retranslated by the Final pass
 * (III.0 item 2) and the owner SIEM simplification pass (2026-10-13): the
 * ONE query-notice line is the transition surface, and every pivot/refine
 * flows through the entity menu + facet chips.
 *
 * - A pivot executes inside the CURRENT evidence pool (the case scope with
 *   a case pinned, session without) and announces the followed clue on the
 *   same notice line refines use; the notice dies with the next plain run.
 * - Refines announce themselves with the canonical Filter added / Excluded
 *   forms; refining an entity-OR snapshot keeps its context (the new
 *   filter distributes across the pair through the one chokepoint).
 * - The 0-events pivot outcome is the honest scoped answer, still named.
 * - The generator stays untouched (workbench-pivots corpus pins it).
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import Siem from '../components/Siem';
import {
  followingClue, filterAdded, excludedFilter,
} from '../components/uiCopy';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

const EVENT = {
  id: 'pv-1', event_seq: 401, timestamp: '2026-03-17T05:10:00+00:00',
  event_type: 'ProcessCreate', source_type: 'Sysmon', severity: 'high',
  hostname: 'ACME-WS12', source_ip: '10.0.1.12', user_account: 'ACME\\nkhan',
  message: 'pivot fixture event', key_value_pairs: {},
};

const snapWith = (rows, canonical = 'all | * | * | *', scope = 'session') => ({
  token: 'tok.one',
  identity: {
    canonical_query: canonical, scope, resolved_scope_hosts: [],
    resolved_range: { start: '2026-03-17T03:41:00+00:00', end: '2026-03-17T05:20:00+00:00' },
    cutoff_seq: 500,
  },
  count: rows.length, rows,
});

let queryResponses;
beforeEach(() => {
  queryResponses = [];
  apiFetch.mockReset();
  apiFetch.mockImplementation((p) => {
    if (p.startsWith('/api/events/query/new-count')) return ok({ new_count: 0, pool_growth: 0 });
    if (p.startsWith('/api/events/query')) {
      if (queryResponses.length) return queryResponses.shift();
      const q = decodeURIComponent(p);
      const m = q.match(/\?q=(.+)&scope=(.+)$/);
      return ok(snapWith([EVENT], m[1], m[2]));
    }
    if (p === '/api/incidents/INC-A/scope') {
      return ok({ incident_id: 'INC-A', sealed: true, hosts: ['ACME-WS12'], accounts: [], detection_ids: [] });
    }
    return ok({});
  });
});

const renderShell = (props = {}) => {
  const utils = render(<Siem resetTrigger={0} onHostPivot={() => {}} {...props} />);
  return utils;
};

const showEvents = async (tfToken = 'all') => {
  fireEvent.change(screen.getByLabelText('Timeframe'), { target: { value: tfToken } });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Show Events' })); });
};
const selectEvent = () =>
  fireEvent.click(within(screen.getByTestId('workbench-results')).getByText('pivot fixture event'));
const menuAction = async (field, item) => {
  fireEvent.click(screen.getAllByLabelText(`Actions for ${field}`)[0]);
  await act(async () => {
    fireEvent.click(screen.getByRole('menuitem', { name: item }));
  });
};
const queryCalls = () =>
  apiFetch.mock.calls.map((c) => c[0]).filter((p) => p.startsWith('/api/events/query?'))
    .map(decodeURIComponent);

test('a pivot with a case executes in the case scope and announces the clue; the notice dies with the next plain run', async () => {
  await act(async () => { renderShell({ activeIncidentId: 'INC-A' }); });
  await showEvents();
  selectEvent();
  await menuAction('user_account', 'Pivot: See Everything About This');
  // the pivot never leaves the case's evidence pool, and the account pivot
  // mints the ruled two-field identity pair through the chokepoint
  const last = queryCalls().pop();
  expect(last).toMatch(/&scope=INC-A$/);
  expect(last).toContain(
    'user_account == "ACME\\\\nkhan" or UserPrincipalName == "ACME\\\\nkhan"');
  expect(screen.getByTestId('query-notice').textContent)
    .toBe(followingClue('user_account', 'ACME\\nkhan'));
  // a plain re-run (a timeframe change) clears the announcement
  await act(async () => {
    fireEvent.change(screen.getByLabelText('Timeframe'), { target: { value: '4h' } });
  });
  expect(screen.queryByTestId('query-notice')).toBeNull();
});

test('no expanded-search furniture exists with a case: no block, no search-all, no return, no scope chip', async () => {
  await act(async () => { renderShell({ activeIncidentId: 'INC-A' }); });
  await showEvents();
  selectEvent();
  await menuAction('hostname', 'Pivot: See Everything About This');
  expect(screen.queryByTestId('expanded-search-block')).toBeNull();
  expect(screen.queryByTestId('search-all')).toBeNull();
  expect(screen.queryByTestId('return-chip')).toBeNull();
  expect(screen.queryByTestId('scope-chip')).toBeNull();
  expect(screen.queryByText(/Investigating INC-/)).toBeNull();   // VA1: retired case line; context is the shell pill
});

test('refines announce the canonical clue forms on the one notice line', async () => {
  renderShell();
  queryResponses.push(ok(snapWith([EVENT], 'all | * | * | *')));
  await showEvents();
  selectEvent();
  await menuAction('hostname', 'Filter to Just This');
  expect(screen.getByTestId('query-notice').textContent)
    .toBe(filterAdded('hostname', 'ACME-WS12'));
  // exclusion form (selection persists across the refine; inspector open)
  await menuAction('source_ip', 'Filter This Out');
  expect(screen.getByTestId('query-notice').textContent)
    .toBe(excludedFilter('source_ip', '10.0.1.12'));
});

test('refining an entity-OR snapshot keeps its context: ONE notice, the filter distributed across the pair', async () => {
  renderShell();
  await showEvents();
  selectEvent();
  // the ip pivot mints the documented OR pair as one entity chip...
  await menuAction('source_ip', 'Pivot: See Everything About This');
  // ...and a refine on top of it distributes through the chokepoint
  await menuAction('hostname', 'Filter to Just This');
  expect(queryCalls().pop()).toBe(
    '/api/events/query?q=all | * | * | '
    + 'source_ip == "10.0.1.12" and hostname == "ACME-WS12"'
    + ' or destination_ip == "10.0.1.12" and hostname == "ACME-WS12"'
    + '&scope=session');
  expect(screen.getAllByTestId('query-notice')).toHaveLength(1);
  expect(screen.getByTestId('query-notice').textContent)
    .toBe(filterAdded('hostname', 'ACME-WS12'));
});

test('a 0-events pivot outcome is the honest scoped answer, with the clue still named', async () => {
  await act(async () => { renderShell({ activeIncidentId: 'INC-A' }); });
  await showEvents();
  selectEvent();
  queryResponses.push(ok(snapWith([],
    'all | * | * | user_account == "ACME\\\\nkhan" or UserPrincipalName == "ACME\\\\nkhan"', 'INC-A')));
  await menuAction('user_account', 'Pivot: See Everything About This');
  expect(screen.getByText('No events match the current filters.')).toBeInTheDocument();
  expect(queryCalls().pop()).toMatch(/&scope=INC-A$/);
  expect(screen.getByTestId('query-notice').textContent)
    .toBe(followingClue('user_account', 'ACME\\nkhan'));
  expect(screen.queryByTestId('expanded-search-block')).toBeNull();
});

test('with no case a pivot runs in the session pool and still announces its clue', async () => {
  renderShell();
  await showEvents();
  selectEvent();
  await menuAction('hostname', 'Pivot: See Everything About This');
  expect(queryCalls().pop()).toMatch(/&scope=session$/);
  expect(screen.getByTestId('query-notice').textContent)
    .toBe(followingClue('hostname', 'ACME-WS12'));
  expect(screen.queryByTestId('expanded-search-block')).toBeNull();
  expect(screen.queryByTestId('return-chip')).toBeNull();
  expect(screen.queryByText('All activity')).toBeNull();   // VA1: retired case line; context is the shell pill
});
