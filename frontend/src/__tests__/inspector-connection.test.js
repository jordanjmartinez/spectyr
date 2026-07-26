/**
 * Phase 4 commit 4.1 (locked OD-5 Option A; acceptance 6): the selected
 * event and the ONE shared inspector stay visibly connected.
 * - scroll-into-view (block nearest) + focus + ONE emphasis run per
 *   selection change; nothing loops.
 * - prefers-reduced-motion: jump (behavior auto), no emphasis animation.
 * - the misleading rotating chevron is replaced by a selection dot that
 *   promises no inline expansion; rows expose aria-selected.
 * Selection persistence across views/sort stays asserted by the existing
 * workbench suites (unchanged).
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import Siem from '../components/Siem';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
const row = (id, seq, msg) => ({
  id, event_seq: seq, timestamp: `2026-03-17T04:00:${String(seq).padStart(2, '0')}+00:00`,
  event_type: 'ProcessCreate', source_type: 'Sysmon', severity: 'high',
  hostname: 'ACME-WS12', message: msg, key_value_pairs: {},
});
const R1 = row('e1', 1, 'alpha inspector event');
const R2 = row('e2', 2, 'bravo inspector event');
const SNAP = {
  token: 'tok.one',
  identity: {
    canonical_query: 'all | * | * | *', scope: 'session', resolved_scope_hosts: [],
    resolved_range: { start: '2026-03-17T03:41:00+00:00', end: '2026-03-17T04:01:00+00:00' },
    cutoff_seq: 2,
  },
  count: 2, rows: [R2, R1],
};

let reducedMotion = false;
beforeEach(() => {
  reducedMotion = false;
  // plain functions, immune to CRA's automatic resetMocks
  window.HTMLElement.prototype.scrollIntoView = jest.fn();
  window.matchMedia = (query) => ({
    matches: reducedMotion, media: query, onchange: null,
    addListener: () => {}, removeListener: () => {},
    addEventListener: () => {}, removeEventListener: () => {},
    dispatchEvent: () => false,
  });
  apiFetch.mockReset();
  apiFetch.mockImplementation((p) => {
    if (p === '/api/endpoints') return ok({ org: {}, endpoints: [] });
    if (p.startsWith('/api/events/query/new-count')) return ok({ new_count: 0, pool_growth: 0 });
    if (p.startsWith('/api/events/query')) return ok(SNAP);
    return ok({});
  });
});

const renderShell = () =>
  render(<Siem resetTrigger={0} onHostPivot={() => {}} />);
const run = async () => {
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'all | * | * | *' } });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Run Query/ })); });
};
const results = () => within(screen.getByTestId('workbench-results'));
const scrollCalls = () => window.HTMLElement.prototype.scrollIntoView.mock.calls;

test('selection scrolls the inspector into view once, focuses it, and runs the emphasis once', async () => {
  renderShell();
  await run();
  expect(scrollCalls()).toHaveLength(0);
  await act(async () => { fireEvent.click(results().getByText('alpha inspector event')); });
  expect(scrollCalls()).toHaveLength(1);
  expect(scrollCalls()[0][0]).toEqual({ block: 'nearest', behavior: 'smooth' });
  const container = screen.getByTestId('inspector-container');
  expect(container).toHaveFocus();
  expect(container.className).toContain('inspector-emphasis');
  // selecting a DIFFERENT row scrolls + emphasizes again (once per change)
  await act(async () => { fireEvent.click(results().getByText('bravo inspector event')); });
  expect(scrollCalls()).toHaveLength(2);
});

test('prefers-reduced-motion jumps (behavior auto) and skips the emphasis animation', async () => {
  reducedMotion = true;
  renderShell();
  await run();
  await act(async () => { fireEvent.click(results().getByText('alpha inspector event')); });
  expect(scrollCalls()).toHaveLength(1);
  expect(scrollCalls()[0][0]).toEqual({ block: 'nearest', behavior: 'auto' });
  expect(screen.getByTestId('inspector-container').className)
    .not.toContain('inspector-emphasis');
});

test('the rotating chevron is replaced by a selection dot; rows expose aria-selected', async () => {
  renderShell();
  await run();
  fireEvent.click(screen.getByRole('button', { name: 'Table' }));
  const table = screen.getByTestId('workbench-results');
  // no chevron inside any ROW (the page-size dropdown chevron is not a row
  // affordance and stays)
  expect(table.querySelector('tbody svg path[d="M19 9l-7 7-7-7"]')).toBeNull();
  const rows = table.querySelectorAll('tbody tr');
  expect(rows.length).toBeGreaterThanOrEqual(2);
  for (const r of rows) expect(r.getAttribute('aria-selected')).toBe('false');
  await act(async () => {
    fireEvent.click(within(table).getByText('alpha inspector event'));
  });
  const selected = Array.from(table.querySelectorAll('tbody tr'))
    .find(r => r.getAttribute('aria-selected') === 'true');
  expect(selected).toBeTruthy();
  expect(within(selected).getByTestId('row-selected-dot')).toBeInTheDocument();
});
