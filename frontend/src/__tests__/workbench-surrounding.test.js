/**
 * Stage 4 Phase 7.3: surrounding-event investigation + OR-fallback UX
 * (contract Section 13 "Surrounding events" row; Section 11 OR notice).
 *
 * Proves: the inspector's Surrounding events action emits the documented
 * `all | H | * | *` form under the CURRENT scope (it is a context view,
 * not an entity pivot); the timeline displays occurrence ASCENDING with
 * the viewport centered on the source event (page jump + scrollIntoView +
 * retained selection); hostless (identity-provider) events have no host to
 * anchor and no control; refinement from an OR snapshot mints a fresh
 * standalone query with the EXACT approved notice, while fresh-by-design
 * forms (pivots, surrounding) never show it.
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import Siem from '../components/Siem';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

const EV = (id, seq, ts, msg, extra = {}) => ({
  id, event_seq: seq, timestamp: ts, event_type: 'QUERY', source_type: 'DNS',
  severity: 'low', hostname: 'ACME-WS10', message: msg, key_value_pairs: {}, ...extra,
});

// 15 events on one host, 05:01..05:15; the SOURCE event is 05:14 --
// ascending index 13, i.e. cards page 2 (12 per page).
const HOST_EVENTS = Array.from({ length: 15 }, (_, i) => {
  const mm = String(i + 1).padStart(2, '0');
  return EV(`s${i + 1}`, i + 1, `2026-03-17T05:${mm}:00+00:00`, `host event ${mm}`);
});
const SOURCE = HOST_EVENTS[13];
const SERVED_DESC = [...HOST_EVENTS].reverse();   // canonical newest-first

const snapWith = (rows, canonical, scope = 'session') => ({
  token: 'tok.one',
  identity: {
    canonical_query: canonical, scope, resolved_scope_hosts: [],
    resolved_range: { start: '2026-03-17T03:41:00+00:00', end: '2026-03-17T05:20:00+00:00' },
    cutoff_seq: 500,
  },
  count: rows.length, rows,
});

let queryResponses;
beforeAll(() => {
  window.HTMLElement.prototype.scrollIntoView = jest.fn();
});
beforeEach(() => {
  window.HTMLElement.prototype.scrollIntoView.mockClear();
  queryResponses = [];
  apiFetch.mockReset();
  apiFetch.mockImplementation((p) => {
    if (p === '/api/endpoints') return ok({ org: {}, endpoints: [] });
    if (p.startsWith('/api/events/query/new-count')) return ok({ new_count: 0, pool_growth: 0 });
    if (p.startsWith('/api/events/query')) {
      return queryResponses.length ? queryResponses.shift() : ok(snapWith([SOURCE], 'all | * | * | *'));
    }
    if (p.match(/^\/api\/incidents\/[^/]+\/scope$/)) {
      const id = p.split('/')[3];
      return ok({ incident_id: id, sealed: true, hosts: ['ACME-WS10'], accounts: [], detection_ids: [] });
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

const queryCalls = () =>
  apiFetch.mock.calls.map((c) => c[0]).filter((p) => p.startsWith('/api/events/query?'))
    .map(decodeURIComponent);

const surround = async () => {
  fireEvent.click(within(screen.getByTestId('workbench-results')).getByText('host event 14'));
  queryResponses.push(ok(snapWith(SERVED_DESC, 'all | ACME-WS10 | * | *')));
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Surrounding events' }));
  });
};

test('Surrounding events emits all | H | * | * under the CURRENT scope with the ascending banner', async () => {
  renderShell();
  await run('all | * | * | *');
  await surround();
  expect(queryCalls().pop()).toBe('/api/events/query?q=all | ACME-WS10 | * | *&scope=session');
  const banner = screen.getByTestId('descent-banner');
  expect(banner).toHaveTextContent('Surrounding events for ACME-WS10, centered on the selected event');
  expect(banner).toHaveTextContent('occurrence ascending');
  expect(banner.textContent).not.toMatch(/—/);   // approved copy punctuation only
});

test('the viewport centers on the source event: page jump, scrollIntoView, focus marker, retained selection', async () => {
  renderShell();
  await run('all | * | * | *');
  await surround();
  // ascending index 13 of 15 -> cards page 2 of 2
  expect(screen.getByText('2 / 2')).toBeInTheDocument();
  const focused = document.querySelector('[data-focused="true"]');
  expect(focused).not.toBeNull();
  expect(focused.textContent).toContain('host event 14');
  expect(window.HTMLElement.prototype.scrollIntoView).toHaveBeenCalled();
  // the source event stays selected and inspected
  expect(screen.getByTestId('event-inspector').textContent).toContain('s14');
});

test('the surrounding timeline runs under an incident scope when that scope is current', async () => {
  renderShell({ activeIncidentId: 'INC-A' });
  await act(async () => {
    fireEvent.change(screen.getByLabelText('Scope'), { target: { value: 'INC-A' } });
  });
  queryResponses.push(ok(snapWith([SOURCE], 'all | * | * | *', 'INC-A')));
  await run('all | * | * | *');
  await surround();
  expect(queryCalls().pop()).toBe('/api/events/query?q=all | ACME-WS10 | * | *&scope=INC-A');
  expect(screen.getByLabelText('Scope').value).toBe('INC-A');
});

test('an event without a hostname has no Surrounding events control', async () => {
  const identityEvent = {
    id: 'aad-9', event_seq: 9, timestamp: '2026-03-17T05:05:00+00:00',
    event_type: 'SigninLogs', source_type: 'Azure AD', severity: 'medium',
    user_account: 'rnguyen@acme.com', message: 'identity sign-in event',
    key_value_pairs: {},
  };
  queryResponses.push(ok(snapWith([identityEvent], 'all | * | * | *')));
  renderShell();
  await run('all | * | * | *');
  fireEvent.click(within(screen.getByTestId('workbench-results')).getByText('identity sign-in event'));
  expect(screen.getByTestId('event-inspector')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Surrounding events' })).toBeNull();
});

// --- OR-fallback UX (Section 11): exact notice on refinement, never on fresh forms

const OR_CANONICAL = 'all | * | * | source_ip == "10.0.1.5" or destination_ip == "10.0.1.5"';

test('refining an OR snapshot mints a fresh standalone query and shows the EXACT approved notice', async () => {
  queryResponses.push(ok(snapWith([SOURCE], OR_CANONICAL)));
  renderShell();
  await run(OR_CANONICAL);
  fireEvent.click(within(screen.getByTestId('workbench-results')).getByText('host event 14'));
  queryResponses.push(ok(snapWith([SOURCE], 'all | * | * | hostname == "ACME-WS10"')));
  await act(async () => {
    fireEvent.click(screen.getByLabelText('Filter hostname equals'));
  });
  expect(queryCalls().pop()).toBe(
    '/api/events/query?q=all | * | * | hostname == "ACME-WS10"&scope=session');
  expect(screen.getByTestId('query-notice'))
    .toHaveTextContent('Started a new query; the previous one mixed or-conditions.');
});

test('fresh-by-design forms (entity pivot, surrounding) never show the OR notice', async () => {
  queryResponses.push(ok(snapWith([SOURCE], OR_CANONICAL)));
  renderShell();
  await run(OR_CANONICAL);
  fireEvent.click(within(screen.getByTestId('workbench-results')).getByText('host event 14'));
  // entity pivot from the OR snapshot: fresh by design, no notice
  await act(async () => {
    fireEvent.click(screen.getByLabelText('Pivot hostname'));
  });
  expect(screen.queryByTestId('query-notice')).toBeNull();
  // the selection survived the pivot (s14 is in the new snapshot), so the
  // inspector is still open; surrounding from it: also no notice
  queryResponses.push(ok(snapWith(SERVED_DESC, 'all | ACME-WS10 | * | *')));
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Surrounding events' }));
  });
  expect(screen.queryByTestId('query-notice')).toBeNull();
});
