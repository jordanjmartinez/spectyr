/**
 * Stage 6 playtest fix 9, carried through the owner SIEM simplification
 * pass (2026-10-13): below lg the SIEM results stack (flex-col), so the
 * facet rail sits behind a disclosure, default CLOSED so events render
 * first; at lg+ the disclosure is hidden and the rail is always visible.
 * A facet click closes the disclosure (the refined events are immediately
 * visible) and still runs the compiled query.
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import Siem from '../components/Siem';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

const ROWS = [
  { id: 'e1', event_seq: 11, timestamp: '2026-03-17T04:00:00+00:00',
    event_type: 'ProcessCreate', source_type: 'Sysmon', severity: 'high',
    hostname: 'ACME-WS12', source_ip: '10.0.1.12', user_account: 'ACME\\nkhan',
    message: 'm1', key_value_pairs: { image: 'a.exe' } },
];
const snapWith = (canonical) => ({
  token: 'tok.abc',
  identity: {
    canonical_query: canonical, scope: 'session', resolved_scope_hosts: [],
    resolved_range: { start: '2026-03-17T03:41:00+00:00', end: '2026-03-17T04:00:10+00:00' },
    cutoff_seq: 13,
  },
  count: 1, rows: ROWS,
});

beforeEach(() => {
  apiFetch.mockReset();
  apiFetch.mockImplementation((path) => {
    if (path.startsWith('/api/events/query/new-count')) return ok({ new_count: 0, pool_growth: 0 });
    if (path.startsWith('/api/events/query')) {
      const q = decodeURIComponent(path).match(/\?q=(.+)&scope=/)[1];
      return ok(snapWith(q));
    }
    return ok({});
  });
});

const showEvents = async () => {
  render(<Siem resetTrigger={0} onHostPivot={() => {}} />);
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Show Events' }));
  });
};

test('the rail disclosure exists below lg only and defaults closed; lg+ keeps the rail always visible', async () => {
  await showEvents();
  const toggle = screen.getByRole('button', { name: /Filters (Show|Hide)/ });
  expect(toggle.className).toMatch(/\blg:hidden\b/);     // a below-lg control only
  expect(toggle).toHaveAttribute('aria-expanded', 'false');
  const wrapper = screen.getByTestId('facet-rail').parentElement;
  expect(wrapper.className).toMatch(/\bhidden\b/);       // collapsed below lg...
  expect(wrapper.className).toMatch(/\blg:block\b/);     // ...always visible at lg+
});

test('the disclosure opens the rail, and a facet click closes it while still running the compiled query', async () => {
  await showEvents();
  const toggle = screen.getByRole('button', { name: /Filters (Show|Hide)/ });
  fireEvent.click(toggle);
  expect(toggle).toHaveAttribute('aria-expanded', 'true');
  const wrapper = screen.getByTestId('facet-rail').parentElement;
  expect(wrapper.className).not.toMatch(/\bhidden\b/);

  await act(async () => {
    fireEvent.click(within(screen.getByTestId('facet-group-hostname'))
      .getByLabelText('Computer: ACME-WS12'));
  });
  const calls = apiFetch.mock.calls.map((c) => c[0]).filter((p) => p.startsWith('/api/events/query?'));
  expect(decodeURIComponent(calls[calls.length - 1]))
    .toContain('hostname == "ACME-WS12"');
  // and the disclosure closed so the events are immediately visible below lg
  expect(screen.getByRole('button', { name: /Filters (Show|Hide)/ }))
    .toHaveAttribute('aria-expanded', 'false');
  expect(screen.getByTestId('facet-rail').parentElement.className).toMatch(/\bhidden\b/);
});
