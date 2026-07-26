/**
 * Phase 3 commit 3.1 (translated 8.2/8.3), retranslated by the Final pass
 * (III.0 item 2): the ONE query-notice line is the transition surface.
 *
 * - A pivot executes inside the CURRENT evidence pool (the case scope with
 *   a case pinned, session without) and announces the followed clue on the
 *   same notice line refines use; the notice dies with the next plain run.
 * - No expanded-search state exists: no block, no search-all action, no
 *   return action, with or without a case.
 * - Refines announce themselves with the canonical Filter added / Excluded
 *   forms; the OR fresh-query sentence FOLDS INTO that one announcement.
 * - The 0-events pivot outcome is the honest scoped answer, still named.
 * - The generator stays untouched (workbench-pivots corpus pins it).
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import Siem from '../components/Siem';
import {
  followingClue, filterAdded, excludedFilter,
} from '../components/uiCopy';
import { OR_FALLBACK_NOTICE } from '../components/lcqlPivots';

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
    if (p === '/api/endpoints') return ok({ org: {}, endpoints: [] });
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
  const utils = render(<Siem initialQueryMode="advanced" resetTrigger={0} onHostPivot={() => {}} {...props} />);
  return utils;
};

const run = async (text) => {
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: text } });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Run Query/ })); });
};
const selectEvent = () =>
  fireEvent.click(within(screen.getByTestId('workbench-results')).getByText('pivot fixture event'));
const queryCalls = () =>
  apiFetch.mock.calls.map((c) => c[0]).filter((p) => p.startsWith('/api/events/query?'))
    .map(decodeURIComponent);

test('a pivot with a case executes in the case scope and announces the clue; the notice dies with the next plain run', async () => {
  await act(async () => { renderShell({ activeIncidentId: 'INC-A' }); });
  await run('all | * | * | *');
  selectEvent();
  await act(async () => { fireEvent.click(screen.getByLabelText('Pivot user_account')); });
  // the pivot never leaves the case's evidence pool
  expect(queryCalls().pop()).toMatch(/&scope=INC-A$/);
  expect(screen.getByTestId('query-notice').textContent)
    .toBe(followingClue('user_account', 'ACME\\nkhan'));
  // a plain re-run clears the announcement (one notice, one lifecycle)
  await run('all | Sysmon | * | *');
  expect(screen.queryByTestId('query-notice')).toBeNull();
});

test('no expanded-search furniture exists with a case: no block, no search-all, no return, no scope chip', async () => {
  await act(async () => { renderShell({ activeIncidentId: 'INC-A' }); });
  await run('all | * | * | *');
  selectEvent();
  await act(async () => { fireEvent.click(screen.getByLabelText('Pivot user_account')); });
  expect(screen.queryByTestId('expanded-search-block')).toBeNull();
  expect(screen.queryByTestId('search-all')).toBeNull();
  expect(screen.queryByTestId('return-chip')).toBeNull();
  expect(screen.queryByTestId('scope-chip')).toBeNull();
  // the pinned case line is the one context marker, untouched by the pivot
  expect(screen.getByTestId('pinned-case-line').textContent).toBe('Investigating INC-A');
});

test('refines announce the canonical clue forms; the OR sentence folds into ONE notice', async () => {
  renderShell();
  queryResponses.push(ok(snapWith([EVENT], 'all | * | * | *')));
  await run('all | * | * | *');
  selectEvent();
  await act(async () => { fireEvent.click(screen.getByLabelText('Filter hostname equals')); });
  expect(screen.getByTestId('query-notice').textContent)
    .toBe(filterAdded('hostname', 'ACME-WS12'));
  // exclusion form (selection persists across the refine; inspector open)
  await act(async () => { fireEvent.click(screen.getByLabelText('Filter severity not equals')); });
  expect(screen.getByTestId('query-notice').textContent)
    .toBe(excludedFilter('severity', 'high'));
});

test('refining an OR snapshot announces the folded fresh-query notice (one line, both facts)', async () => {
  renderShell();
  const orCanonical = 'all | * | * | source_ip == "10.0.1.5" or destination_ip == "10.0.1.5"';
  queryResponses.push(ok(snapWith([EVENT], orCanonical)));
  await run(orCanonical);
  selectEvent();
  await act(async () => { fireEvent.click(screen.getByLabelText('Filter hostname equals')); });
  const notice = screen.getByTestId('query-notice').textContent;
  expect(notice).toContain(filterAdded('hostname', 'ACME-WS12'));
  expect(notice).toContain(OR_FALLBACK_NOTICE);
  expect(screen.getAllByTestId('query-notice')).toHaveLength(1);
});

test('a 0-events pivot outcome is the honest scoped answer, with the clue still named', async () => {
  await act(async () => { renderShell({ activeIncidentId: 'INC-A' }); });
  await run('all | * | * | *');
  selectEvent();
  queryResponses.push(ok(snapWith([], 'all | * | * | user_account == "ACME\\\\nkhan"', 'INC-A')));
  await act(async () => { fireEvent.click(screen.getByLabelText('Pivot user_account')); });
  expect(screen.getByText('0 events match')).toBeInTheDocument();
  expect(queryCalls().pop()).toMatch(/&scope=INC-A$/);
  expect(screen.getByTestId('query-notice').textContent)
    .toBe(followingClue('user_account', 'ACME\\nkhan'));
  expect(screen.queryByTestId('expanded-search-block')).toBeNull();
});

test('with no case a pivot runs in the session pool and still announces its clue', async () => {
  renderShell();
  await run('all | * | * | *');
  selectEvent();
  await act(async () => { fireEvent.click(screen.getByLabelText('Pivot hostname')); });
  expect(queryCalls().pop()).toMatch(/&scope=session$/);
  expect(screen.getByTestId('query-notice').textContent)
    .toBe(followingClue('hostname', 'ACME-WS12'));
  expect(screen.queryByTestId('expanded-search-block')).toBeNull();
  expect(screen.queryByTestId('return-chip')).toBeNull();
  expect(screen.getByTestId('pinned-case-line').textContent).toBe('All activity');
});
