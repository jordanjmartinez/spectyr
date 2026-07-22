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
beforeEach(() => {
  queryResponses = [];
  apiFetch.mockReset();
  apiFetch.mockImplementation((p) => {
    if (p === '/api/endpoints') return ok({ org: {}, endpoints: [] });
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

const renderShell = (props = {}) =>
  render(<Siem setSiemCount={() => {}} resetTrigger={0} onHostPivot={() => {}} {...props} />);

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

// --- Section 18 "Cross-host pivots": visible flip + return chip --------------

test('an entity pivot from incident scope visibly lands Session-wide and offers the return chip', async () => {
  renderShell({ activeIncidentId: 'INC-A' });
  await act(async () => {
    fireEvent.change(screen.getByLabelText('Scope'), { target: { value: 'INC-A' } });
  });
  await run('all | * | * | *');
  expect(queryCalls().pop()).toBe('/api/events/query?q=all | * | * | *&scope=INC-A');
  expect(screen.queryByTestId('return-chip')).toBeNull();   // focused: no chip

  selectEvent();
  await act(async () => {
    fireEvent.click(screen.getByLabelText('Pivot hostname'));
  });
  // the pivot executed Session-wide and the scope control flipped on screen
  expect(queryCalls().pop()).toBe('/api/events/query?q=all | ACME-WS12 | * | *&scope=session');
  expect(screen.getByLabelText('Scope').value).toBe('session');
  expect(screen.getByTestId('return-chip')).toHaveTextContent('Back to INC-A');
});

test('the return chip re-runs the current query under the incident participant scope', async () => {
  renderShell({ activeIncidentId: 'INC-A' });
  await act(async () => {
    fireEvent.change(screen.getByLabelText('Scope'), { target: { value: 'INC-A' } });
  });
  await run('all | * | * | *');
  selectEvent();
  await act(async () => {
    fireEvent.click(screen.getByLabelText('Pivot hostname'));
  });
  // the executed pivot's canonical query is now in the bar (mock echoes the
  // default canonical); returning re-runs exactly that text under INC-A
  const barText = screen.getByLabelText('LCQL query').value;
  await act(async () => {
    fireEvent.click(screen.getByTestId('return-chip'));
  });
  expect(queryCalls().pop()).toBe(`/api/events/query?q=${barText}&scope=INC-A`);
  expect(screen.getByLabelText('Scope').value).toBe('INC-A');
  expect(screen.queryByTestId('return-chip')).toBeNull();   // back home: chip gone
});

test('ordinary navigation stays Session-wide: Run and refinement never change scope, no chip appears', async () => {
  renderShell();
  await run('all | * | * | *');
  selectEvent();
  await act(async () => {
    fireEvent.click(screen.getByLabelText('Filter hostname equals'));
  });
  for (const call of queryCalls()) {
    expect(call.endsWith('&scope=session')).toBe(true);
  }
  expect(screen.getByLabelText('Scope').value).toBe('session');
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
