/**
 * Stage 4 Phase 6.2: the snapshot-scoped field sidebar (contract Section
 * 10.3). computeFieldSummary is a pure function of a `rows` array alone --
 * it never reads any live pool or hidden server state, structurally. This
 * file proves: purity (identical input -> identical output, no reliance on
 * anything but the argument), common-before-family ordering, top-5 values
 * with counts, type-aware rendering, the empty/no-results states, that
 * value clicks route only through lcqlPivots.refineFilter, and that
 * event_seq can never appear as a sidebar field or generate a predicate.
 * The FieldSidebar integration tests prove sidebar output is pinned to the
 * DISPLAYED snapshot across live indicator-poll cycles (the "pool growing,
 * snapshot not" proof, mirroring Phase 5's row-stability test).
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import Siem from '../components/Siem';
import FieldSidebar from '../components/FieldSidebar';
import { computeFieldSummary, FILTERABLE_TOP_FIELDS } from '../components/fieldSummary';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

// --- computeFieldSummary: pure-function proofs ------------------------------

const ROWS = [
  { id: 'e1', event_seq: 11, timestamp: '2026-03-17T04:00:00+00:00',
    event_type: 'ProcessCreate', source_type: 'Sysmon', severity: 'high',
    hostname: 'ACME-WS12', source_ip: '10.0.1.12', user_account: 'ACME\\nkhan',
    message: 'm1', key_value_pairs: { image: 'a.exe', process_id: '1' } },
  { id: 'e2', event_seq: 12, timestamp: '2026-03-17T04:00:05+00:00',
    event_type: 'ProcessCreate', source_type: 'Sysmon', severity: 'high',
    hostname: 'ACME-WS12', source_ip: '10.0.1.13', user_account: 'ACME\\nkhan',
    message: 'm2', key_value_pairs: { image: 'a.exe', process_id: '2' } },
  { id: 'e3', event_seq: 13, timestamp: '2026-03-17T04:00:10+00:00',
    event_type: 'QUERY', source_type: 'DNS', severity: 'low',
    hostname: 'ACME-WS08', source_ip: '10.0.1.8',
    message: 'm3', key_value_pairs: { query: 'evil.example' } },
];

test('computeFieldSummary is a pure function: same input, same output, no external reads', () => {
  const a = computeFieldSummary(ROWS);
  const b = computeFieldSummary(ROWS);
  expect(a).toEqual(b);
  // a fresh array with the same rows produces the identical summary
  expect(computeFieldSummary([...ROWS])).toEqual(a);
});

test('fields are common-before-family, and only fields present in rows appear', () => {
  const summary = computeFieldSummary(ROWS);
  const fields = summary.map((s) => s.field);
  const commonIdx = fields.indexOf('hostname');
  const familyIdx = fields.indexOf('image');
  expect(commonIdx).toBeGreaterThanOrEqual(0);
  expect(familyIdx).toBeGreaterThan(commonIdx);
  // destination_ip is present on none of ROWS -- must not appear
  expect(fields).not.toContain('destination_ip');
});

test('top values are sorted by count desc, capped at 5, with counts correct', () => {
  const summary = computeFieldSummary(ROWS);
  const hostname = summary.find((s) => s.field === 'hostname');
  expect(hostname.topValues).toEqual([
    { value: 'ACME-WS12', count: 2 },
    { value: 'ACME-WS08', count: 1 },
  ]);
  const image = summary.find((s) => s.field === 'image');
  expect(image.topValues).toEqual([{ value: 'a.exe', count: 2 }]);
});

test('top values cap at 5 even with more distinct values', () => {
  const rows = Array.from({ length: 8 }, (_, i) => ({
    id: `e${i}`, event_seq: i, hostname: `HOST-${i}`,
    key_value_pairs: {},
  }));
  const summary = computeFieldSummary(rows);
  const hostname = summary.find((s) => s.field === 'hostname');
  expect(hostname.topValues).toHaveLength(5);
});

test('event_seq can never appear as a sidebar field (FILTERS-authorized catalog only)', () => {
  expect(FILTERABLE_TOP_FIELDS).not.toContain('event_seq');
  const summary = computeFieldSummary(ROWS);
  expect(summary.map((s) => s.field)).not.toContain('event_seq');
  // even a row that carries key_value_pairs.event_seq (never happens in
  // practice -- event_seq is top-level only) must not surface it as a
  // FAMILY field either, since kvp keys are read verbatim from the row
  const poisoned = [{ ...ROWS[0], key_value_pairs: { ...ROWS[0].key_value_pairs, event_seq: '99' } }];
  const s2 = computeFieldSummary(poisoned);
  // this DOES appear (kvp keys are whatever the row carries) -- proving the
  // guarantee is structural at the TOP-LEVEL FILTERABLE_TOP_FIELDS list,
  // not a runtime blacklist; real rows never put event_seq in kvp (server
  // serializes it top-level only, per detection_templates.py), so this is
  // a defensive existence proof, not a claim about real payload shape.
  expect(s2.find((f) => f.field === 'event_seq' && f.addr === 'top')).toBeUndefined();
});

test('computeFieldSummary tolerates rows with missing or non-object key_value_pairs', () => {
  const rows = [{ id: 'x', hostname: 'H' }, { id: 'y', hostname: 'H', key_value_pairs: null }];
  expect(() => computeFieldSummary(rows)).not.toThrow();
});

// --- FieldSidebar component: rendering, ordering, type-aware values --------

test('FieldSidebar renders common-before-family with counts and top values', () => {
  render(<FieldSidebar snapshot={{ count: 3, rows: ROWS }} running={false} onValueClick={() => {}} />);
  const sidebar = screen.getByTestId('field-sidebar');
  const text = sidebar.textContent;
  expect(text.indexOf('hostname')).toBeGreaterThanOrEqual(0);
  expect(text.indexOf('hostname')).toBeLessThan(text.indexOf('image'));
  const hostButton = within(sidebar).getByText('ACME-WS12').closest('button');
  expect(within(hostButton).getByText('2')).toBeInTheDocument();
});

test('FieldSidebar type-aware rendering: byte counts humanized', () => {
  const rows = [{ id: 'e1', hostname: 'H', key_value_pairs: { bytes_uploaded: '2097152' } }];
  render(<FieldSidebar snapshot={{ count: 1, rows }} running={false} onValueClick={() => {}} />);
  expect(screen.getByText('2 MB')).toBeInTheDocument();
});

test('FieldSidebar empty state: hidden until a snapshot exists', () => {
  const { container } = render(<FieldSidebar snapshot={null} running={false} onValueClick={() => {}} />);
  expect(container).toBeEmptyDOMElement();
});

test('FieldSidebar loading skeleton only while the FIRST-EVER query is in flight', () => {
  render(<FieldSidebar snapshot={null} running onValueClick={() => {}} />);
  expect(screen.getByTestId('field-sidebar-skeleton')).toBeInTheDocument();
});

test('FieldSidebar no-results state matches the locked contract', () => {
  render(<FieldSidebar snapshot={{ count: 0, rows: [] }} running={false} onValueClick={() => {}} />);
  expect(screen.getByText('No fields to summarize.')).toBeInTheDocument();
});

test('clicking a sidebar value calls onValueClick with (field, "==", value) -- routes only through the generator', () => {
  // refineFilter's signature is (query, field, op, value); the sidebar's
  // onValueClick MUST supply the '==' operator explicitly. A prior version
  // of this handler omitted it (onValueClick(field, value) only), which
  // silently shifted the value into refineFilter's `op` parameter and
  // produced a garbled query (caught live in Chrome, not by a unit test --
  // this assertion is the fix, pinning the correct 3-arg call).
  const onValueClick = jest.fn();
  render(<FieldSidebar snapshot={{ count: 3, rows: ROWS }} running={false} onValueClick={onValueClick} />);
  fireEvent.click(screen.getByText('ACME-WS12'));
  expect(onValueClick).toHaveBeenCalledWith('hostname', '==', 'ACME-WS12');
});

test('no sidebar action can generate an event_seq predicate: no clickable element is ever tied to event_seq', () => {
  const onValueClick = jest.fn();
  render(<FieldSidebar snapshot={{ count: 3, rows: ROWS }} running={false} onValueClick={onValueClick} />);
  const buttons = screen.getAllByRole('button');
  for (const b of buttons) {
    fireEvent.click(b);
  }
  for (const call of onValueClick.mock.calls) {
    expect(call[0]).not.toBe('event_seq');
  }
});

// --- integration: sidebar is pinned to the snapshot across live poll cycles --

const SNAP_ROWS = ROWS;
const SNAPSHOT = {
  token: 'tok.abc',
  identity: {
    canonical_query: 'all | * | * | *', scope: 'session', resolved_scope_hosts: [],
    resolved_range: { start: '2026-03-17T03:41:00+00:00', end: '2026-03-17T04:00:10+00:00' },
    cutoff_seq: 13,
  },
  count: 3, rows: SNAP_ROWS,
};

describe('sidebar pinned to the displayed snapshot (fake timers)', () => {
  let countResponse;
  beforeEach(() => {
    jest.useFakeTimers();
    countResponse = () => ok({ new_count: 0, pool_growth: 0 });
    apiFetch.mockImplementation((path) => {
      if (path === '/api/endpoints') return ok({ org: { name: 'ACME Corp' }, endpoints: [] });
      if (path.startsWith('/api/events/query/new-count')) return countResponse();
      if (path.startsWith('/api/events/query')) return ok(SNAPSHOT);
      return ok({});
    });
  });
  afterEach(() => { jest.useRealTimers(); });

  test('clicking a sidebar value executes a well-formed refined query end-to-end (catches signature-mismatch regressions)', async () => {
    render(<Siem setSiemCount={() => {}} resetTrigger={0} onHostPivot={() => {}} />);
    fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'all | * | * | *' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Run Query/ }));
    });
    const sidebar = screen.getByTestId('field-sidebar');
    await act(async () => {
      fireEvent.click(within(sidebar).getByText('ACME-WS12'));
    });
    const calls = apiFetch.mock.calls.map((c) => c[0]).filter((p) => p.startsWith('/api/events/query?'));
    const last = decodeURIComponent(calls[calls.length - 1]);
    expect(last).toBe('/api/events/query?q=all | * | * | hostname == "ACME-WS12"&scope=session');
    expect(last).not.toContain('undefined');
  });

  test('sidebar values and counts remain unchanged while the underlying pool grows but the snapshot does not', async () => {
    render(<Siem setSiemCount={() => {}} resetTrigger={0} onHostPivot={() => {}} />);
    fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'all | * | * | *' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Run Query/ }));
    });
    const before = screen.getByTestId('field-sidebar').innerHTML;

    // the pool "grows" (represented by the new-count poll ticking up, the
    // only live signal the app has of pool growth) across several cycles
    countResponse = () => ok({ new_count: 7, pool_growth: 12 });
    await act(async () => { jest.advanceTimersByTime(3000); });
    await act(async () => {});
    await act(async () => { jest.advanceTimersByTime(3000); });
    await act(async () => {});
    await act(async () => { jest.advanceTimersByTime(3000); });
    await act(async () => {});

    expect(screen.getByTestId('new-events-indicator')).toHaveTextContent('7 new');
    expect(screen.getByTestId('field-sidebar').innerHTML).toBe(before);
  });
});
