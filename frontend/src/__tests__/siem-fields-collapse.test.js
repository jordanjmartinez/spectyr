/**
 * Stage 6 playtest fix 9: below lg the SIEM results stack (flex-col), and
 * the ~60-group field panel buried the events under a full-width scroll.
 * The panel now sits behind a disclosure below lg, default CLOSED so events
 * render first; at lg+ the disclosure is hidden and the panel is always
 * visible exactly as before. A value click closes the disclosure (the
 * refined events are immediately visible) and still runs the refined query.
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
const SNAPSHOT = {
  token: 'tok.abc',
  identity: {
    canonical_query: 'all | * | * | *', scope: 'session', resolved_scope_hosts: [],
    resolved_range: { start: '2026-03-17T03:41:00+00:00', end: '2026-03-17T04:00:10+00:00' },
    cutoff_seq: 13,
  },
  count: 1, rows: ROWS,
};

beforeEach(() => {
  apiFetch.mockReset();
  apiFetch.mockImplementation((path) => {
    if (path === '/api/endpoints') return ok({ org: { name: 'ACME Corp' }, endpoints: [] });
    if (path.startsWith('/api/events/query/new-count')) return ok({ new_count: 0, pool_growth: 0 });
    if (path.startsWith('/api/events/query')) return ok(SNAPSHOT);
    return ok({});
  });
});

const runQuery = async () => {
  render(<Siem initialQueryMode="advanced" resetTrigger={0} onHostPivot={() => {}} />);
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'all | * | * | *' } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: /Run Query/ }));
  });
};

test('the fields disclosure exists below lg only and defaults closed; lg+ keeps the panel always visible', async () => {
  await runQuery();
  const toggle = screen.getByRole('button', { name: /Fields/ });
  expect(toggle.className).toMatch(/\blg:hidden\b/);     // a below-lg control only
  expect(toggle).toHaveAttribute('aria-expanded', 'false');
  const wrapper = screen.getByTestId('field-sidebar').parentElement;
  expect(wrapper.className).toMatch(/\bhidden\b/);       // collapsed below lg...
  expect(wrapper.className).toMatch(/\blg:block\b/);     // ...always visible at lg+
});

test('the disclosure opens the panel, and a value click closes it while still running the refined query', async () => {
  await runQuery();
  const toggle = screen.getByRole('button', { name: /Fields/ });
  fireEvent.click(toggle);
  expect(toggle).toHaveAttribute('aria-expanded', 'true');
  const wrapper = screen.getByTestId('field-sidebar').parentElement;
  expect(wrapper.className).not.toMatch(/\bhidden\b/);

  await act(async () => {
    fireEvent.click(within(screen.getByTestId('field-sidebar')).getByText('ACME-WS12'));
  });
  // the refined query executed (end-to-end shape is pinned in workbench-sidebar)
  const calls = apiFetch.mock.calls.map((c) => c[0]).filter((p) => p.startsWith('/api/events/query?'));
  expect(decodeURIComponent(calls[calls.length - 1]))
    .toContain('hostname == "ACME-WS12"');
  // and the disclosure closed so the events are immediately visible below lg
  expect(screen.getByRole('button', { name: /Fields/ })).toHaveAttribute('aria-expanded', 'false');
  expect(screen.getByTestId('field-sidebar').parentElement.className).toMatch(/\bhidden\b/);
});
