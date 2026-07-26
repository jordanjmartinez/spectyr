/**
 * Stage 4 Phase 7.1: entity pivots and cross-host scope transitions
 * (contract Sections 12/13/14, Section 18 "Cross-host pivots").
 *
 * Proves: every per-field inspector pivot emits its documented Section 13
 * query (pinned as LITERAL text, not re-derived through the generator) and
 * executes Session-wide; the scope control visibly flips as part of the
 * pivot; the return chip re-runs the current query under the incident's
 * participant scope; ordinary navigation (Run, refinement) never changes
 * scope; and -- structurally -- pivot sources are only serialized
 * observable fields and the generator module is pure (no imports, no
 * fetch), so no answer-key or hidden field can enter query generation.
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import fs from 'fs';
import path from 'path';
import Siem from '../components/Siem';
import { PIVOT_MAP } from '../components/EventInspector';
import { FILTERABLE_TOP_FIELDS } from '../components/fieldSummary';
import kvpCatalogOrder from '../components/kvpCatalogOrder.json';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

// One event carrying every pivot-source field, with escaping-hostile values.
const PIVOT_EVENT = {
  id: 'pv-1', event_seq: 401, timestamp: '2026-03-17T05:10:00+00:00',
  event_type: 'ProcessCreate', source_type: 'Sysmon', severity: 'high',
  hostname: 'ACME-WS12', source_ip: '10.0.1.12', destination_ip: '52.96.84.228',
  user_account: 'ACME\\nkhan',
  message: 'pivot fixture event',
  key_value_pairs: {
    image: 'C:\\Users\\Public\\winupdate.exe',
    parent_image: 'C:\\Windows\\explorer.exe',
    target_filename: 'C:\\Users\\nkhan\\Documents\\payroll.xlsx',
    url: 'micr0soft.com/signin',
    query: 'updates.micr0soft.com',
  },
};

const snapWith = (rows, extra = {}) => ({
  token: 'tok.one',
  identity: {
    canonical_query: 'all | * | * | *', scope: 'session', resolved_scope_hosts: [],
    resolved_range: { start: '2026-03-17T03:41:00+00:00', end: '2026-03-17T05:20:00+00:00' },
    cutoff_seq: 500,
    ...extra,
  },
  count: rows.length, rows,
});

let queryResponses;
let scopeFails;
beforeEach(() => {
  queryResponses = [];
  scopeFails = false;
  apiFetch.mockReset();
  apiFetch.mockImplementation((p) => {
    if (p === '/api/endpoints') return ok({ org: {}, endpoints: [] });
    if (p.startsWith('/api/events/query/new-count')) return ok({ new_count: 0, pool_growth: 0 });
    if (p.startsWith('/api/events/query')) {
      return queryResponses.length ? queryResponses.shift() : ok(snapWith([PIVOT_EVENT]));
    }
    if (p === '/api/incidents/INC-A/scope') {
      if (scopeFails) return Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({}) });
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

const queryCalls = () =>
  apiFetch.mock.calls.map((c) => c[0]).filter((p) => p.startsWith('/api/events/query?'))
    .map(decodeURIComponent);

// --- every documented pivot form, pinned as literal text ---------------------
// Expected strings are the contract Section 13 shapes VERBATIM (with GD-5
// escaping applied by hand), deliberately NOT built via lcqlPivots here --
// the test would be tautological otherwise.

const CASES = [
  ['hostname', 'all | ACME-WS12 | * | *'],
  ['user_account', 'all | * | * | user_account == "ACME\\\\nkhan"'],
  ['source_ip', 'all | * | * | source_ip == "10.0.1.12" or destination_ip == "10.0.1.12"'],
  ['destination_ip', 'all | * | * | source_ip == "52.96.84.228" or destination_ip == "52.96.84.228"'],
  ['image', 'all | * | * | image == "C:\\\\Users\\\\Public\\\\winupdate.exe"'],
  ['parent_image', 'all | * | * | image == "C:\\\\Windows\\\\explorer.exe"'],
  ['target_filename', 'all | * | * | target_filename == "C:\\\\Users\\\\nkhan\\\\Documents\\\\payroll.xlsx"'],
  ['url', 'all | Proxy | * | url contains "micr0soft.com/signin"'],
  ['query', 'all | DNS | QUERY | query contains "updates.micr0soft.com"'],
  ['event_type', 'all | * | ProcessCreate | *'],
  ['source_type', 'all | Sysmon | * | *'],
];

test.each(CASES)(
  'pivot on %s emits its documented query and executes Session-wide',
  async (field, expected) => {
    renderShell();
    await run('all | * | * | *');
    selectEvent();
    await act(async () => {
      fireEvent.click(screen.getByLabelText(`Pivot ${field}`));
    });
    const calls = queryCalls();
    expect(calls[calls.length - 1]).toBe(`/api/events/query?q=${expected}&scope=session`);
  }
);

test('a pivot inherits the EXECUTED snapshot TIMEFRAME token', async () => {
  queryResponses.push(ok(snapWith([PIVOT_EVENT], { canonical_query: '1h | * | * | *' })));
  renderShell();
  await run('1h | * | * | *');
  selectEvent();
  await act(async () => {
    fireEvent.click(screen.getByLabelText('Pivot hostname'));
  });
  const calls = queryCalls();
  expect(calls[calls.length - 1]).toBe('/api/events/query?q=1h | ACME-WS12 | * | *&scope=session');
});

// --- Section 18 "Cross-host pivots", case-constant (Amendment 1 Delta A):
// an entity pivot from case evidence enters Expanded search visibly; the
// single return action restores the case evidence -------------------------

test('an entity pivot from case evidence enters Expanded search visibly with the single return action', async () => {
  await act(async () => { renderShell({ activeIncidentId: 'INC-A' }); });
  await run('all | * | * | *');
  expect(queryCalls().pop()).toBe('/api/events/query?q=all | * | * | *&scope=INC-A');
  expect(screen.queryByTestId('return-chip')).toBeNull();   // case evidence: no return
  expect(screen.queryByTestId('expanded-search-block')).toBeNull();

  selectEvent();
  await act(async () => {
    fireEvent.click(screen.getByLabelText('Pivot hostname'));
  });
  // the pivot executed across all evidence; the block announces the state
  expect(queryCalls().pop()).toBe('/api/events/query?q=all | ACME-WS12 | * | *&scope=session');
  expect(screen.getByTestId('expanded-search-block')).toBeInTheDocument();
  expect(screen.getByTestId('return-chip')).toHaveTextContent('Return to INC-A evidence');
  // the case stays pinned through the expansion (OD-15 structural)
  expect(screen.getByTestId('pinned-case-line').textContent).toBe('Investigating INC-A');
});

// --- Amendment 3 F2 (model B): the return RESTORES the pre-entry hold ------

const scopeCalls = () =>
  apiFetch.mock.calls.map((c) => c[0]).filter((p) => p.includes('/scope'));

test('the return action restores the pre-expansion evidence with zero query or scope requests (model B)', async () => {
  const EVENT_B = { ...PIVOT_EVENT, id: 'pv-2', message: 'expanded fixture event' };
  queryResponses.push(ok(snapWith([PIVOT_EVENT], { canonical_query: '1h | * | * | *', scope: 'INC-A' })));
  queryResponses.push(ok(snapWith([EVENT_B], { canonical_query: '1h | ACME-WS12 | * | *' })));
  await act(async () => { renderShell({ activeIncidentId: 'INC-A' }); });
  await run('1h | * | * | *');
  selectEvent();
  await act(async () => {
    fireEvent.click(screen.getByLabelText('Pivot hostname'));
  });
  expect(within(screen.getByTestId('workbench-results')).getByText('expanded fixture event')).toBeInTheDocument();
  const queriesBefore = queryCalls().length;
  const scopesBefore = scopeCalls().length;
  await act(async () => {
    fireEvent.click(screen.getByTestId('return-chip'));
  });
  // zero requests: no re-run, no scope re-read (the C1 guard's failure
  // mode is unreachable; the new-count poll may resume by design)
  expect(queryCalls().length).toBe(queriesBefore);
  expect(scopeCalls().length).toBe(scopesBefore);
  // the pre-expansion evidence is back exactly
  expect(screen.getByLabelText('LCQL query')).toHaveValue('1h | * | * | *');
  expect(within(screen.getByTestId('workbench-results')).getByText('pivot fixture event')).toBeInTheDocument();
  expect(within(screen.getByTestId('workbench-results')).queryByText('expanded fixture event')).toBeNull();
  expect(screen.queryByTestId('expanded-search-block')).toBeNull();
  expect(screen.getByTestId('scope-chip').textContent).toContain('INC-A evidence');
  // the hold is CONSUMED: no return remains
  expect(screen.queryByTestId('return-chip')).toBeNull();
});

test('model B: the hold survives runs and refines while expanded and still restores the pre-entry state', async () => {
  queryResponses.push(ok(snapWith([PIVOT_EVENT], { canonical_query: '1h | * | * | *', scope: 'INC-A' })));
  await act(async () => { renderShell({ activeIncidentId: 'INC-A' }); });
  await run('1h | * | * | *');
  selectEvent();
  await act(async () => {
    fireEvent.click(screen.getByLabelText('Pivot hostname'));   // enter expanded
  });
  // a manual edit + run while expanded (this dropped the A2-style hold);
  // the selection and open inspector survive the re-run (same event id)
  await run('all | * | * | *');
  // and a refine while expanded
  await act(async () => {
    fireEvent.click(screen.getByLabelText('Filter hostname equals'));
  });
  // the return still restores the ORIGINAL pre-entry state
  await act(async () => {
    fireEvent.click(screen.getByTestId('return-chip'));
  });
  expect(screen.getByLabelText('LCQL query')).toHaveValue('1h | * | * | *');
  expect(screen.getByTestId('scope-chip').textContent).toContain('INC-A evidence');
  expect(screen.queryByTestId('expanded-search-block')).toBeNull();
});

test('model B: a failed expanded run leaves the hold restorable; the excursion error dies with the return', async () => {
  queryResponses.push(ok(snapWith([PIVOT_EVENT], { canonical_query: '1h | * | * | *', scope: 'INC-A' })));
  await act(async () => { renderShell({ activeIncidentId: 'INC-A' }); });
  await run('1h | * | * | *');
  selectEvent();
  await act(async () => {
    fireEvent.click(screen.getByLabelText('Pivot hostname'));
  });
  queryResponses.push(Promise.resolve({ ok: false, status: 400,
    json: () => Promise.resolve({ error: { position: 0, reason: 'unknown token' } }) }));
  await run('garbage');
  expect(screen.getByText('This search was not run.')).toBeInTheDocument();
  await act(async () => {
    fireEvent.click(screen.getByTestId('return-chip'));
  });
  expect(screen.getByLabelText('LCQL query')).toHaveValue('1h | * | * | *');
  expect(screen.queryByText('This search was not run.')).toBeNull();
  expect(screen.getByTestId('scope-chip').textContent).toContain('INC-A evidence');
});

test('model B: a search-all entry before any run holds a null snapshot; return restores the empty case-evidence state', async () => {
  await act(async () => { renderShell({ activeIncidentId: 'INC-A' }); });
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'all | * | * | *' } });
  await act(async () => {
    fireEvent.click(screen.getByTestId('search-all'));
  });
  expect(screen.getByTestId('expanded-search-block')).toBeInTheDocument();
  await act(async () => {
    fireEvent.click(screen.getByTestId('return-chip'));
  });
  expect(screen.queryByTestId('expanded-search-block')).toBeNull();
  expect(screen.getByTestId('scope-chip').textContent).toContain('INC-A evidence');
  expect(screen.getByLabelText('LCQL query')).toHaveValue('all | * | * | *');
  expect(screen.getByText('Run a query to begin.')).toBeInTheDocument();
});

test('ordinary navigation without a case stays plain All activity: no block, no return', async () => {
  renderShell();
  await run('all | * | * | *');
  selectEvent();
  await act(async () => {
    fireEvent.click(screen.getByLabelText('Filter hostname equals'));
  });
  for (const call of queryCalls()) {
    expect(call.endsWith('&scope=session')).toBe(true);
  }
  expect(screen.getByTestId('pinned-case-line').textContent).toBe('All activity');
  expect(screen.queryByTestId('expanded-search-block')).toBeNull();
  expect(screen.queryByTestId('return-chip')).toBeNull();
});

// --- structural: nothing hidden can enter query generation ------------------

test('every pivot-source field is a serialized observable field (commons or cataloged kvp)', () => {
  const top = new Set(FILTERABLE_TOP_FIELDS);
  for (const field of Object.keys(PIVOT_MAP)) {
    expect(top.has(field) || kvpCatalogOrder.includes(field)).toBe(true);
  }
});

test('the pivot generator module is pure: no imports, no fetch, no api access', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'components', 'lcqlPivots.js'), 'utf8');
  expect(src).not.toMatch(/^\s*import\s/m);
  expect(src).not.toMatch(/require\s*\(/);
  expect(src).not.toMatch(/apiFetch|fetch\s*\(|XMLHttpRequest|localStorage/);
});

test('non-entity fields carry no pivot action (severity, message, event_seq)', async () => {
  renderShell();
  await run('all | * | * | *');
  selectEvent();
  expect(screen.queryByLabelText('Pivot severity')).toBeNull();
  expect(screen.queryByLabelText('Pivot message')).toBeNull();
  expect(screen.queryByLabelText('Pivot event_seq')).toBeNull();
  expect(screen.queryByLabelText('Pivot timestamp')).toBeNull();
  expect(screen.queryByLabelText('Pivot id')).toBeNull();
});
