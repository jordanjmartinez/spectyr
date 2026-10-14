/**
 * The facet rail (owner SIEM simplification pass 2026-10-13; replaces the
 * Stage 4 FieldSidebar suite in the same commit that replaces the
 * component).
 *
 * Proves: the six default plain-language groups render in order with top-5
 * values by count; multi-select checkboxes toggle include chips and run the
 * compiled query immediately through the one generator; selected values pin
 * (visible even at 0 matching rows); everything else sits behind More
 * Filters; the DELETED groups (id, timestamp, message, logon_guid,
 * key_length, channel, caller_process_id) never render as groups; event_seq
 * can never become a filter; values and counts derive ONLY from served rows
 * and stay pinned to the displayed snapshot while the pool grows; and the
 * sibling baseline for a narrowed group is fetched only on Show More.
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import Siem from '../components/Siem';
import FacetRail from '../components/FacetRail';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

const ROWS = [
  { id: 'e1', event_seq: 11, timestamp: '2026-03-17T04:00:00+00:00',
    event_type: 'ProcessCreate', source_type: 'Sysmon', severity: 'high',
    hostname: 'ACME-WS12', source_ip: '10.0.1.12', user_account: 'ACME\\nkhan',
    message: 'm1', key_value_pairs: { image: 'a.exe', process_id: '1', logon_guid: 'g-1' } },
  { id: 'e2', event_seq: 12, timestamp: '2026-03-17T04:00:05+00:00',
    event_type: 'ProcessCreate', source_type: 'Sysmon', severity: 'high',
    hostname: 'ACME-WS12', source_ip: '10.0.1.13', user_account: 'ACME\\nkhan',
    message: 'm2', key_value_pairs: { image: 'a.exe', process_id: '2' } },
  { id: 'e3', event_seq: 13, timestamp: '2026-03-17T04:00:10+00:00',
    event_type: 'QUERY', source_type: 'DNS', severity: 'low',
    hostname: 'ACME-WS08', source_ip: '10.0.1.8',
    message: 'm3', key_value_pairs: { query: 'evil.example' } },
];

const SNAPSHOT = {
  token: 'tok.abc',
  identity: {
    canonical_query: 'all | * | * | *', scope: 'session', resolved_scope_hosts: [],
    resolved_range: { start: '2026-03-17T03:41:00+00:00', end: '2026-03-17T04:00:10+00:00' },
    cutoff_seq: 13,
  },
  count: 3, rows: ROWS,
};

const noop = () => {};
const railProps = {
  running: false, chips: [], customActive: false, baselines: {},
  onToggle: noop, onRequestBaseline: noop,
};

// --- FacetRail: pure rendering over the snapshot prop -----------------------

test('the six default groups render in the owner-specified order with plain-language names', () => {
  render(<FacetRail snapshot={SNAPSHOT} {...railProps} />);
  const rail = screen.getByTestId('facet-rail');
  const text = rail.textContent;
  const order = ['Event', 'Severity', 'User Account', 'Computer',
    'Source IP', 'Log Source', 'More Filters'];
  let last = -1;
  for (const label of order) {
    const idx = text.indexOf(label);
    expect({ label, present: idx >= 0 }).toEqual({ label, present: true });
    expect(idx).toBeGreaterThan(last);
    last = idx;
  }
});

test('values show counts and decoded names; counts are correct', () => {
  render(<FacetRail snapshot={SNAPSHOT} {...railProps} />);
  const group = screen.getByTestId('facet-group-event_type');
  const proc = within(group).getByLabelText('Event: Process Started (ProcessCreate)');
  expect(proc).toBeInTheDocument();
  expect(within(group).getByText('Process Started (ProcessCreate)').parentElement.textContent)
    .toContain('2');
  const sev = screen.getByTestId('facet-group-severity');
  expect(within(sev).getByText('high').parentElement.textContent).toContain('2');
  expect(within(sev).getByText('low').parentElement.textContent).toContain('1');
});

test('top values cap at 5 with Show More revealing the rest client-side', () => {
  const rows = Array.from({ length: 8 }, (_, i) => ({
    id: `e${i}`, event_seq: i, hostname: `HOST-${i}`, key_value_pairs: {},
  }));
  render(<FacetRail snapshot={{ count: 8, rows }} {...railProps} />);
  const group = screen.getByTestId('facet-group-hostname');
  expect(within(group).getAllByRole('checkbox')).toHaveLength(5);
  fireEvent.click(within(group).getByText('Show More'));
  expect(within(group).getAllByRole('checkbox')).toHaveLength(8);
  fireEvent.click(within(group).getByText('Show Fewer'));
  expect(within(group).getAllByRole('checkbox')).toHaveLength(5);
});

test('clicking a value calls onToggle with (field, value); checked state follows the chips', () => {
  const onToggle = jest.fn();
  render(<FacetRail snapshot={SNAPSHOT} {...railProps}
    chips={[{ type: 'include', field: 'severity', value: 'high' }]}
    onToggle={onToggle} />);
  const sev = screen.getByTestId('facet-group-severity');
  expect(within(sev).getByLabelText('Severity: high')).toBeChecked();
  expect(within(sev).getByLabelText('Severity: low')).not.toBeChecked();
  fireEvent.click(within(sev).getByLabelText('Severity: low'));
  expect(onToggle).toHaveBeenCalledWith('severity', 'low');
});

test('a selected value pins into its group even when no served row carries it', () => {
  render(<FacetRail snapshot={SNAPSHOT} {...railProps}
    chips={[{ type: 'include', field: 'severity', value: 'critical' }]} />);
  const sev = screen.getByTestId('facet-group-severity');
  const pinned = within(sev).getByLabelText('Severity: critical');
  expect(pinned).toBeChecked();
  expect(pinned.closest('label').textContent).toContain('0');
});

test('everything beyond the defaults sits behind More Filters; deleted groups never render', () => {
  render(<FacetRail snapshot={SNAPSHOT} {...railProps} />);
  // closed by default: no kvp group visible
  expect(screen.queryByTestId('facet-group-image')).toBeNull();
  const more = screen.getByRole('button', { name: /More Filters/ });
  expect(more).toHaveAttribute('aria-expanded', 'false');
  fireEvent.click(more);
  expect(screen.getByTestId('facet-group-image')).toBeInTheDocument();
  expect(screen.getByTestId('facet-group-query')).toBeInTheDocument();
  // the DELETED filter groups are gone entirely, open or closed
  for (const f of ['id', 'timestamp', 'message', 'logon_guid', 'key_length',
    'channel', 'caller_process_id', 'event_seq']) {
    expect(screen.queryByTestId(`facet-group-${f}`)).toBeNull();
  }
});

test('no rail interaction can ever produce an event_seq filter (structural: no group exists)', () => {
  const onToggle = jest.fn();
  const poisoned = [{ ...ROWS[0], key_value_pairs: { ...ROWS[0].key_value_pairs, event_seq: '99' } }];
  render(<FacetRail snapshot={{ count: 1, rows: poisoned }} {...railProps} onToggle={onToggle} />);
  fireEvent.click(screen.getByRole('button', { name: /More Filters/ }));
  expect(screen.queryByTestId('facet-group-event_seq')).toBeNull();
  for (const box of screen.getAllByRole('checkbox')) fireEvent.click(box);
  for (const call of onToggle.mock.calls) expect(call[0]).not.toBe('event_seq');
});

test('rail states: hidden with no snapshot, skeleton while the first query runs', () => {
  const { container, rerender } = render(
    <FacetRail snapshot={null} {...railProps} />);
  expect(container).toBeEmptyDOMElement();
  rerender(<FacetRail snapshot={null} {...railProps} running />);
  expect(screen.getByTestId('facet-rail-skeleton')).toBeInTheDocument();
});

test('0-match results keep the rail usable: selected values stay visible to back out of', () => {
  render(<FacetRail snapshot={{ count: 0, rows: [] }} {...railProps}
    chips={[{ type: 'include', field: 'severity', value: 'critical' }]} />);
  expect(screen.getByLabelText('Severity: critical')).toBeChecked();
  expect(screen.getAllByText('No values in these results.').length).toBeGreaterThan(0);
});

// --- integration through the shell -------------------------------------------

const snapWith = (canonical, rows = ROWS) => ({
  token: 'tok.one',
  identity: {
    canonical_query: canonical, scope: 'session', resolved_scope_hosts: [],
    resolved_range: { start: '2026-03-17T03:41:00+00:00', end: '2026-03-17T04:00:10+00:00' },
    cutoff_seq: 13,
  },
  count: rows.length, rows,
});

let queryResponses;
let countResponse;
const mockRoutes = () => {
  queryResponses = [];
  countResponse = () => ok({ new_count: 0, pool_growth: 0 });
  apiFetch.mockReset();
  apiFetch.mockImplementation((path) => {
    if (path.startsWith('/api/events/query/new-count')) return countResponse();
    if (path.startsWith('/api/events/query')) {
      if (queryResponses.length) return queryResponses.shift();
      const q = decodeURIComponent(path).match(/\?q=(.+)&scope=/)[1];
      return ok(snapWith(q));
    }
    return ok({});
  });
};

const queryCalls = () =>
  apiFetch.mock.calls.map((c) => c[0]).filter((p) => p.startsWith('/api/events/query?'))
    .map(decodeURIComponent);

const showEvents = async () => {
  render(<Siem resetTrigger={0} onHostPivot={() => {}} />);
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Show Events' }));
  });
};

test('a facet click compiles through the generator and executes immediately end-to-end', async () => {
  mockRoutes();
  await showEvents();
  expect(queryCalls().pop()).toBe('/api/events/query?q=1h | * | * | *&scope=session');
  const sev = screen.getByTestId('facet-group-severity');
  await act(async () => {
    fireEvent.click(within(sev).getByLabelText('Severity: high'));
  });
  expect(queryCalls().pop())
    .toBe('/api/events/query?q=1h | * | * | severity == "high"&scope=session');
  // the applied filter renders as a removable chip above the results
  expect(screen.getByTestId('filter-chips').textContent).toContain('Severity: high');
});

test('multi-select within a group: the second value ORs with the first', async () => {
  mockRoutes();
  await showEvents();
  const sev = screen.getByTestId('facet-group-severity');
  await act(async () => {
    fireEvent.click(within(sev).getByLabelText('Severity: high'));
  });
  // the narrowed group keeps its selected value pinned; Show More fetches
  // the sibling baseline (the same search without this group's selections)
  await act(async () => {
    fireEvent.click(within(screen.getByTestId('facet-group-severity')).getByText('Show More'));
  });
  const baselineCall = queryCalls().pop();
  expect(baselineCall).toBe('/api/events/query?q=1h | * | * | *&scope=session');
  // the baseline restores the full value list; selecting low now ORs
  await act(async () => {
    fireEvent.click(within(screen.getByTestId('facet-group-severity')).getByLabelText('Severity: low'));
  });
  expect(queryCalls().pop()).toBe(
    '/api/events/query?q=1h | * | * | severity == "high" or severity == "low"&scope=session');
});

test('removing a chip recompiles and reruns; removing the last chip returns to match-all', async () => {
  mockRoutes();
  await showEvents();
  await act(async () => {
    fireEvent.click(within(screen.getByTestId('facet-group-severity')).getByLabelText('Severity: high'));
  });
  await act(async () => {
    fireEvent.click(screen.getByLabelText('Remove filter: Severity: high'));
  });
  expect(queryCalls().pop()).toBe('/api/events/query?q=1h | * | * | *&scope=session');
  expect(screen.queryByTestId('filter-chips')).toBeNull();
});

test('rail values and counts stay pinned to the displayed snapshot while the pool grows', async () => {
  mockRoutes();
  jest.useFakeTimers();
  try {
    await showEvents();
    const before = screen.getByTestId('facet-rail').innerHTML;
    countResponse = () => ok({ new_count: 7, pool_growth: 12 });
    await act(async () => { jest.advanceTimersByTime(3000); });
    await act(async () => {});
    await act(async () => { jest.advanceTimersByTime(3000); });
    await act(async () => {});
    expect(screen.getByTestId('new-events-indicator')).toHaveTextContent('7 New');
    expect(screen.getByTestId('facet-rail').innerHTML).toBe(before);
  } finally {
    jest.useRealTimers();
  }
});

test('no sibling baseline is fetched without a Show More on a narrowed group', async () => {
  mockRoutes();
  await showEvents();
  await act(async () => {
    fireEvent.click(within(screen.getByTestId('facet-group-severity')).getByLabelText('Severity: high'));
  });
  // exactly two query reads so far: the initial run + the facet run
  expect(queryCalls()).toHaveLength(2);
});
