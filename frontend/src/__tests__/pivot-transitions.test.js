/**
 * Phase 3 commit 3.1 (translated 8.2/8.3, Amendment 1 Delta A): the
 * expanded-search block IS the transition surface.
 *
 * - A pivot from case evidence enters Expanded search naming the followed
 *   clue (canonical 8.2 form); the clue line dies with its snapshot (the
 *   identity guard) while the state block persists.
 * - A search-all entry shows the block without a clue line.
 * - Refines announce themselves with the canonical Filter added / Excluded
 *   forms; the OR fresh-query sentence FOLDS INTO that one announcement.
 * - The 0-events state keeps the block visible with the two designed outs.
 * - No case: pivots run plainly (no block, no return).
 * - The generator stays untouched (workbench-pivots corpus pins it).
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import Siem from '../components/Siem';
import {
  followingClue, filterAdded, excludedFilter, NO_RESULTS_OUTS,
  EXPANDED_SEARCH_TITLE,
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
      const canonical = q.match(/\?q=(.+)&scope=/)[1];
      return ok(snapWith([EVENT], canonical));
    }
    if (p === '/api/incidents/INC-A/scope') {
      return ok({ incident_id: 'INC-A', sealed: true, hosts: ['ACME-WS12'], accounts: [], detection_ids: [] });
    }
    return ok({});
  });
});

const renderShell = (props = {}) =>
  render(<Siem resetTrigger={0} onHostPivot={() => {}} {...props} />);

const run = async (text) => {
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: text } });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Run Query/ })); });
};
const selectEvent = () =>
  fireEvent.click(within(screen.getByTestId('workbench-results')).getByText('pivot fixture event'));

test('a pivot from case evidence names the followed clue; the clue dies with its snapshot, the block persists', async () => {
  await act(async () => { renderShell({ activeIncidentId: 'INC-A' }); });
  await run('all | * | * | *');
  selectEvent();
  await act(async () => { fireEvent.click(screen.getByLabelText('Pivot user_account')); });
  const block = screen.getByTestId('expanded-search-block');
  expect(block.textContent).toContain(EXPANDED_SEARCH_TITLE);
  expect(block.textContent).toContain(followingClue('user_account', 'ACME\\nkhan'));
  // a plain re-run of a DIFFERENT query: the clue line dies (identity
  // guard), the state block persists
  await run('all | Sysmon | * | *');
  const block2 = screen.getByTestId('expanded-search-block');
  expect(block2.textContent).not.toContain('Following clue:');
  expect(block2.textContent).toContain(EXPANDED_SEARCH_TITLE);
});

test('a search-all entry shows the block without a clue line', async () => {
  await act(async () => { renderShell({ activeIncidentId: 'INC-A' }); });
  await run('all | * | * | *');
  await act(async () => { fireEvent.click(screen.getByTestId('search-all')); });
  const block = screen.getByTestId('expanded-search-block');
  expect(block.textContent).not.toContain('Following clue:');
  expect(block.textContent).toContain(EXPANDED_SEARCH_TITLE);
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

test('the 0-events state keeps the block visible with the two designed outs', async () => {
  await act(async () => { renderShell({ activeIncidentId: 'INC-A' }); });
  await run('all | * | * | *');
  selectEvent();
  queryResponses.push(ok(snapWith([], 'all | * | * | user_account == "ACME\\\\nkhan"')));
  await act(async () => { fireEvent.click(screen.getByLabelText('Pivot user_account')); });
  expect(screen.getByText('0 events match')).toBeInTheDocument();
  const block = screen.getByTestId('expanded-search-block');
  expect(block.textContent).toContain(NO_RESULTS_OUTS);
  expect(block.textContent).toContain('Return to INC-A evidence');
});

test('with no case a pivot runs plainly: no block, no return, no clue banner', async () => {
  renderShell();
  await run('all | * | * | *');
  selectEvent();
  await act(async () => { fireEvent.click(screen.getByLabelText('Pivot hostname')); });
  expect(screen.queryByTestId('expanded-search-block')).toBeNull();
  expect(screen.queryByTestId('return-chip')).toBeNull();
  expect(screen.getByTestId('pinned-case-line').textContent).toBe('All activity');
});
