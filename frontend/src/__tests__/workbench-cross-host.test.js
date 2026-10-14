/**
 * Entity pivots and cross-host behavior (Stage 4 Sections 12/13/14 under
 * the one-evidence-universe model), retranslated by the owner SIEM
 * simplification pass (2026-10-13): pivots live ONLY on entity fields
 * (user, source IP, workstation, host, destination, process name), through
 * the ONE menu verb "Pivot: See Everything About This", and compile
 * through the facet chokepoint.
 *
 * Proves: every entity pivot emits its documented query (pinned as LITERAL
 * text, not re-derived through the generator) and executes in the CURRENT
 * evidence pool -- session with no case, the case scope with one; a pivot
 * never changes the evidence universe; ordinary navigation never changes
 * scope; non-entity fields (url, dns query, event type, source family,
 * file, severity, message...) carry NO pivot; and -- structurally -- pivot
 * sources are only serialized observable fields and the generator modules
 * are pure, so no answer-key or hidden field can enter query generation.
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import fs from 'fs';
import path from 'path';
import Siem from '../components/Siem';
import { ENTITY_FIELDS, FILTERABLE_TOP_FIELDS } from '../components/facetModel';
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
    workstation_name: 'ACME-WS08',
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
beforeEach(() => {
  queryResponses = [];
  apiFetch.mockReset();
  apiFetch.mockImplementation((p) => {
    if (p.startsWith('/api/events/query/new-count')) return ok({ new_count: 0, pool_growth: 0 });
    if (p.startsWith('/api/events/query')) {
      return queryResponses.length ? queryResponses.shift() : ok(snapWith([PIVOT_EVENT]));
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

// Load events over the whole window (the CASES pin the `all` token).
const showEvents = async (tfToken = 'all') => {
  fireEvent.change(screen.getByLabelText('Timeframe'), { target: { value: tfToken } });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Show Events' })); });
};

const selectEvent = () => {
  fireEvent.click(within(screen.getByTestId('workbench-results')).getByText('pivot fixture event'));
  // the full field list carries the menus for facts the Key Facts cap cuts
  fireEvent.click(screen.getByRole('button', { name: /All Fields/ }));
};

const menuAction = async (field, item) => {
  fireEvent.click(screen.getAllByLabelText(`Actions for ${field}`)[0]);
  await act(async () => {
    fireEvent.click(screen.getAllByRole('menuitem', { name: item })[0]);
  });
};

const queryCalls = () =>
  apiFetch.mock.calls.map((c) => c[0]).filter((p) => p.startsWith('/api/events/query?'))
    .map(decodeURIComponent);

// --- every entity pivot form, pinned as literal text --------------------------
// Expected strings are the documented chokepoint shapes VERBATIM (with GD-5
// escaping applied by hand), deliberately NOT built via the generator here
// -- the test would be tautological otherwise.

const CASES = [
  ['hostname', 'all | * | * | hostname == "ACME-WS12"'],
  ['workstation_name', 'all | * | * | hostname == "ACME-WS08"'],
  ['user_account', 'all | * | * | user_account == "ACME\\\\nkhan" or UserPrincipalName == "ACME\\\\nkhan"'],
  ['source_ip', 'all | * | * | source_ip == "10.0.1.12" or destination_ip == "10.0.1.12"'],
  ['destination_ip', 'all | * | * | source_ip == "52.96.84.228" or destination_ip == "52.96.84.228"'],
  ['image', 'all | * | * | image == "C:\\\\Users\\\\Public\\\\winupdate.exe"'],
  ['parent_image', 'all | * | * | image == "C:\\\\Windows\\\\explorer.exe"'],
];

test.each(CASES)(
  'pivot on %s emits its documented query and executes Session-wide',
  async (field, expected) => {
    renderShell();
    await showEvents();
    selectEvent();
    await menuAction(field, 'Pivot: See Everything About This');
    const calls = queryCalls();
    expect(calls[calls.length - 1]).toBe(`/api/events/query?q=${expected}&scope=session`);
  }
);

test('a pivot inherits the EXECUTED snapshot TIMEFRAME token', async () => {
  queryResponses.push(ok(snapWith([PIVOT_EVENT], { canonical_query: '1h | * | * | *' })));
  renderShell();
  await showEvents('1h');
  selectEvent();
  await menuAction('hostname', 'Pivot: See Everything About This');
  const calls = queryCalls();
  expect(calls[calls.length - 1])
    .toBe('/api/events/query?q=1h | * | * | hostname == "ACME-WS12"&scope=session');
});

// --- Section 18 "Cross-host pivots" under III.0 item 2: a pivot from case
// evidence follows the clue INSIDE the case's evidence pool ----------------

test('an entity pivot from case evidence executes under the case scope and announces the clue', async () => {
  await act(async () => { renderShell({ activeIncidentId: 'INC-A' }); });
  await showEvents();
  expect(queryCalls().pop()).toBe('/api/events/query?q=all | * | * | *&scope=INC-A');

  selectEvent();
  await menuAction('hostname', 'Pivot: See Everything About This');
  // the documented query text, executed in the SAME evidence universe
  expect(queryCalls().pop())
    .toBe('/api/events/query?q=all | * | * | hostname == "ACME-WS12"&scope=INC-A');
  expect(screen.getByTestId('query-notice'))
    .toHaveTextContent('Following clue: hostname = "ACME-WS12"');
  // no expanded-search furniture; the case stays pinned (OD-15 structural)
  expect(screen.queryByTestId('expanded-search-block')).toBeNull();
  expect(screen.queryByTestId('return-chip')).toBeNull();
  expect(screen.queryByTestId('search-all')).toBeNull();
  expect(screen.queryByText(/Investigating INC-/)).toBeNull();   // VA1: retired case line; context is the shell pill
});

test('ONE evidence universe with a case: run, pivot, refine, and chip removal all carry the case scope', async () => {
  await act(async () => { renderShell({ activeIncidentId: 'INC-A' }); });
  await showEvents();
  selectEvent();
  await menuAction('hostname', 'Pivot: See Everything About This');
  // a refine that lands an exclude chip, then remove it
  await menuAction('source_ip', 'Filter This Out');
  await act(async () => {
    fireEvent.click(screen.getByLabelText('Remove filter: Not Source IP: 10.0.1.12'));
  });
  const calls = queryCalls();
  expect(calls).toHaveLength(4);
  for (const call of calls) {
    expect(call.endsWith('&scope=INC-A')).toBe(true);
  }
});

test('ordinary navigation without a case stays plain All activity: no block, no return', async () => {
  renderShell();
  await showEvents();
  selectEvent();
  await menuAction('hostname', 'Filter to Just This');
  for (const call of queryCalls()) {
    expect(call.endsWith('&scope=session')).toBe(true);
  }
  expect(screen.queryByText('All activity')).toBeNull();   // VA1: retired case line; context is the shell pill
  expect(screen.queryByTestId('expanded-search-block')).toBeNull();
  expect(screen.queryByTestId('return-chip')).toBeNull();
});

// --- structural: nothing hidden can enter query generation ------------------

test('every entity field is a serialized observable field (commons or cataloged kvp)', () => {
  const top = new Set(FILTERABLE_TOP_FIELDS);
  for (const field of Object.keys(ENTITY_FIELDS)) {
    expect(top.has(field) || kvpCatalogOrder.includes(field)).toBe(true);
  }
});

test('the pivot generator module is pure: no imports, no fetch, no api access', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'components', 'lcqlPivots.js'), 'utf8');
  expect(src).not.toMatch(/^\s*import\s/m);
  expect(src).not.toMatch(/require\s*\(/);
  expect(src).not.toMatch(/apiFetch|fetch\s*\(|XMLHttpRequest|localStorage/);
});

test('non-entity fields carry NO filter or pivot action (owner simplification)', async () => {
  renderShell();
  await showEvents();
  selectEvent();
  // the old url / dns / event-type / sensor / file pivots are gone with the
  // ==/!=/Pivot buttons; only entity fields carry the one menu
  for (const f of ['severity', 'message', 'event_seq', 'timestamp', 'id',
    'event_type', 'source_type', 'url', 'query', 'target_filename']) {
    expect(screen.queryByLabelText(`Actions for ${f}`)).toBeNull();
  }
  expect(screen.getAllByLabelText('Actions for hostname').length).toBeGreaterThanOrEqual(1);
});
