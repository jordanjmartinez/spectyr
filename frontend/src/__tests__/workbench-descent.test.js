/**
 * Stage 4 Phase 7.2/7.4 evidence entry, renamed "Investigate in SIEM"
 * (Final pass III.0 item 5; contract Sections 13, 16; OD-9 host-anchored
 * v1 ruling; R17 uniform control).
 *
 * Proves: the SIEM shell consumes an entry request built ONLY from
 * observable data and generates the documented forms (single participant
 * host -> `all | H | * | *`; several -> `all | * | * | *` under the
 * incident's participant scope; identity -> the uniform two-field OR);
 * the entry explicitly establishes scope (incident context when the entry
 * carries one, Session-wide otherwise); NO separate Timeline concept
 * survives -- no origin banner, no breadcrumb, no occurrence-ascending
 * re-sort: the prepared search lands as 'prepared' initial evidence
 * (III.0 item 3) identified by the readable expression in the bar and
 * displays exactly as served; and both entry points (Incidents workspace,
 * DetectionDetail) supply exactly the observable fields with the SAME
 * control and request shape for every detection kind.
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import Siem from '../components/Siem';
import Incidents from '../components/Incidents';
import DetectionDetail from '../components/DetectionDetail';
import {
  INITIAL_EVIDENCE, INITIAL_INCIDENT_EVIDENCE,
} from '../components/uiCopy';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

const EV = (id, seq, ts, msg) => ({
  id, event_seq: seq, timestamp: ts, event_type: 'QUERY', source_type: 'DNS',
  severity: 'low', hostname: 'ACME-WS10', message: msg, key_value_pairs: {},
});
// Served deliberately OUT of occurrence order (newest-first canonical).
const ROWS_UNORDERED = [
  EV('e3', 30, '2026-03-17T05:03:00+00:00', 'third event'),
  EV('e1', 10, '2026-03-17T05:01:00+00:00', 'first event'),
  EV('e2', 20, '2026-03-17T05:02:00+00:00', 'second event'),
];

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
beforeEach(() => {
  queryResponses = [];
  apiFetch.mockReset();
  apiFetch.mockImplementation((p) => {
    if (p === '/api/endpoints') return ok({ org: {}, endpoints: [] });
    if (p.startsWith('/api/events/query/new-count')) return ok({ new_count: 0, pool_growth: 0 });
    if (p.startsWith('/api/events/query')) {
      return queryResponses.length
        ? queryResponses.shift()
        : ok(snapWith(ROWS_UNORDERED, 'all | ACME-WS10 | * | *'));
    }
    if (p.match(/^\/api\/incidents\/[^/]+\/scope$/)) {
      const id = p.split('/')[3];
      return ok({ incident_id: id, sealed: true, hosts: ['ACME-WS10'], accounts: [], detection_ids: [] });
    }
    return ok({});
  });
});

const queryCalls = () =>
  apiFetch.mock.calls.map((c) => c[0]).filter((p) => p.startsWith('/api/events/query?'))
    .map(decodeURIComponent);

const renderSiem = (props = {}) => {
  const utils = render(<Siem initialQueryMode="advanced" resetTrigger={0} onHostPivot={() => {}} {...props} />);
  return utils;
};

// --- the shell consumes entry requests --------------------------------------

test('a single-host entry with no incident context runs all | H | * | * Session-wide as initial evidence', async () => {
  await act(async () => {
    renderSiem({
      descentRequest: { hosts: ['ACME-WS10'], scopeIncidentId: null, seq: 1 },
    });
  });
  expect(queryCalls().pop()).toBe('/api/events/query?q=all | ACME-WS10 | * | *&scope=session');
  // no case: the All activity state; the prepared search is identified by
  // the readable expression in the bar plus the initial-evidence label
  expect(screen.getByTestId('pinned-case-line').textContent).toBe('All activity');
  expect(screen.getByLabelText('LCQL query')).toHaveValue('all | ACME-WS10 | * | *');
  expect(screen.getByTestId('results-label').textContent).toBe(INITIAL_EVIDENCE);
  // no separate Timeline concept: no banner, no breadcrumb, no back link
  expect(screen.queryByTestId('descent-banner')).toBeNull();
  expect(screen.queryByRole('button', { name: /Back to/ })).toBeNull();
});

test('a single-host incident entry explicitly establishes the incident scope', async () => {
  queryResponses.push(ok(snapWith(ROWS_UNORDERED, 'all | ACME-WS10 | * | *', 'INC-9368')));
  await act(async () => {
    renderSiem({
      activeIncidentId: 'INC-9368',
      descentRequest: { hosts: ['ACME-WS10'], scopeIncidentId: 'INC-9368', seq: 1 },
    });
  });
  expect(apiFetch).toHaveBeenCalledWith('/api/incidents/INC-9368/scope');
  expect(queryCalls().pop()).toBe('/api/events/query?q=all | ACME-WS10 | * | *&scope=INC-9368');
  expect(screen.getByTestId('pinned-case-line').textContent).toBe('Investigating INC-9368');
  expect(screen.getByTestId('results-label').textContent).toBe(INITIAL_INCIDENT_EVIDENCE);
  expect(screen.queryByTestId('descent-banner')).toBeNull();
});

test('a multi-host incident entry runs the whole-pool query under the incident scope', async () => {
  queryResponses.push(ok(snapWith(ROWS_UNORDERED, 'all | * | * | *', 'INC-9368')));
  await act(async () => {
    renderSiem({
      activeIncidentId: 'INC-9368',
      descentRequest: { hosts: ['ACME-WS10', 'ACME-WS22'], scopeIncidentId: 'INC-9368', seq: 1 },
    });
  });
  expect(queryCalls().pop()).toBe('/api/events/query?q=all | * | * | *&scope=INC-9368');
  expect(screen.getByTestId('results-label').textContent).toBe(INITIAL_INCIDENT_EVIDENCE);
});

test('entry results display exactly as served: no occurrence-ascending re-sort survives (III.0 item 5)', async () => {
  await act(async () => {
    renderSiem({
      descentRequest: { hosts: ['ACME-WS10'], scopeIncidentId: null, seq: 1 },
    });
  });
  const text = screen.getByTestId('workbench-results').textContent;
  // the served (newest-first) order, exactly like any executed search
  expect(text.indexOf('third event')).toBeGreaterThan(-1);
  expect(text.indexOf('third event')).toBeLessThan(text.indexOf('first event'));
  expect(text.indexOf('first event')).toBeLessThan(text.indexOf('second event'));
});

// --- entry point: the Incidents workspace ------------------------------------

test('the Incidents workspace entry button supplies exactly the observable participant scope', async () => {
  apiFetch.mockImplementation((p) => {
    if (p === '/api/incidents') {
      return ok({
        active: [{ incident_id: 'INC-A', title: 'Suspicious DNS', state: 'in_progress', sealed: true, ready: false, open_detections: 2, severity: 'High' }],
        completed: [], queue_length: 10, resolved_count: 0,
      });
    }
    if (p === '/api/incidents/INC-A/scope') {
      return ok({ incident_id: 'INC-A', sealed: true, hosts: ['ACME-WS10', 'ACME-WS22'], accounts: ['ACME\\nkhan'], detection_ids: [] });
    }
    if (p === '/api/actions') return ok([]);
    return ok({});
  });
  const onDescent = jest.fn();
  render(<Incidents gameMode="soc_queue" activeIncidentId="INC-A" onEvidenceDescent={onDescent} />);
  const btn = await screen.findByRole('button', { name: 'Investigate in SIEM' });
  fireEvent.click(btn);
  expect(onDescent).toHaveBeenCalledWith({
    hosts: ['ACME-WS10', 'ACME-WS22'],
    account: null,
    scopeIncidentId: 'INC-A',
  });
});

// --- entry point: DetectionDetail --------------------------------------------

const DET_FIXTURES = {
  'det-aaa1': {
    id: 'det-aaa1', rule_name: 'Encoded Subdomain Beacon Pattern', rule_type: 'sigma_behavioral',
    severity: 'high', time: '2026-03-17T05:05:00+00:00', description: 'Rule text A.',
    entity: { host: 'ACME-WS10' }, player_action: 'open',
    triggering_events: [{ event_type: 'QUERY', source_type: 'DNS', hostname: 'ACME-WS10', message: 'DNS query.', key_value_pairs: {} }],
  },
  'det-bbb2': {
    id: 'det-bbb2', rule_name: 'Scheduled Update Check', rule_type: 'sigma_behavioral',
    severity: 'low', time: '2026-03-17T05:06:00+00:00', description: 'Rule text B.',
    entity: { host: 'ACME-WS10' }, player_action: 'open',
    triggering_events: [{ event_type: 'ProcessCreate', source_type: 'Sysmon', hostname: 'ACME-WS10', message: 'Updater ran.', key_value_pairs: {} }],
  },
  // P7.4 identity fixtures: both carry a DOMAIN-BACKSLASH account so the
  // identity-entry path exercises GD-5 escaping itself; one attack-looking,
  // one benign-looking payload (kind is not even present in the sanitized
  // payload -- the control must not vary with it).
  'det-ids1': {
    id: 'det-ids1', rule_name: 'Password Spray Pattern Across Accounts', rule_type: 'sigma_behavioral',
    severity: 'high', time: '2026-03-17T05:07:00+00:00', description: 'Rule text C.',
    entity: { account: 'ACME\\dlee' }, player_action: 'open',
    triggering_events: [{ event_type: '4625', source_type: 'Windows Security', message: 'Failed logon.', key_value_pairs: {} }],
  },
  'det-ida2': {
    id: 'det-ida2', rule_name: 'Conditional Access Policy Evaluation', rule_type: 'sigma_behavioral',
    severity: 'low', time: '2026-03-17T05:08:00+00:00', description: 'Rule text D.',
    entity: { account: 'ACME\\rhall' }, player_action: 'open',
    triggering_events: [{ event_type: 'SigninLogs', source_type: 'Azure AD', message: 'Sign-in.', key_value_pairs: {} }],
  },
};

const mockDetRoutes = () => {
  apiFetch.mockImplementation((p) => {
    const m = p.match(/^\/api\/detections\/([^/]+)$/);
    if (m) return ok(DET_FIXTURES[decodeURIComponent(m[1])]);
    return ok({});
  });
};

test('a host-entity detection entry supplies exactly the observable entity host (Session-wide without context)', async () => {
  mockDetRoutes();
  const onDescent = jest.fn();
  render(<DetectionDetail detId="det-aaa1" onBack={() => {}} onAction={() => {}} onEvidenceDescent={onDescent} descentScopeIncidentId={null} />);
  const btn = await screen.findByRole('button', { name: 'Investigate in SIEM' });
  fireEvent.click(btn);
  expect(onDescent).toHaveBeenCalledWith({
    hosts: ['ACME-WS10'], account: null, scopeIncidentId: null,
  });
});

test('a detection viewed under the player-selected incident context enters that scope', async () => {
  mockDetRoutes();
  const onDescent = jest.fn();
  render(<DetectionDetail detId="det-aaa1" onBack={() => {}} onAction={() => {}} onEvidenceDescent={onDescent} descentScopeIncidentId="INC-A" />);
  fireEvent.click(await screen.findByRole('button', { name: 'Investigate in SIEM' }));
  expect(onDescent.mock.calls[0][0].scopeIncidentId).toBe('INC-A');
});

test('every detection kind exposes the SAME control and request shape (indistinguishability through the entry)', async () => {
  mockDetRoutes();
  const calls = [];
  for (const id of ['det-aaa1', 'det-bbb2']) {
    const onDescent = jest.fn();
    const { unmount } = render(
      <DetectionDetail detId={id} onBack={() => {}} onAction={() => {}} onEvidenceDescent={onDescent} descentScopeIncidentId={null} />
    );
    const btn = await screen.findByRole('button', { name: 'Investigate in SIEM' });
    expect(btn.textContent).toBe('Investigate in SIEM');   // identical label
    fireEvent.click(btn);
    calls.push(onDescent.mock.calls[0][0]);
    unmount();
  }
  // identical request SHAPE: same keys, same query form (host-anchored)
  expect(Object.keys(calls[0]).sort()).toEqual(Object.keys(calls[1]).sort());
  expect(calls[0].hosts).toEqual(calls[1].hosts);
  expect(calls[0].scopeIncidentId).toBe(calls[1].scopeIncidentId);
});

// --- P7.4: identity-detection entry (R17 uniform control) --------------------

test('an identity detection enters anchored to its observable account', async () => {
  mockDetRoutes();
  const onDescent = jest.fn();
  render(<DetectionDetail detId="det-ids1" onBack={() => {}} onAction={() => {}} onEvidenceDescent={onDescent} descentScopeIncidentId={null} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Investigate in SIEM' }));
  expect(onDescent).toHaveBeenCalledWith({
    hosts: [], account: 'ACME\\dlee', scopeIncidentId: null,
  });
});

test('scenario-looking and ambient-looking identity detections expose the identical control and request shape', async () => {
  mockDetRoutes();
  const calls = [];
  for (const id of ['det-ids1', 'det-ida2']) {
    const onDescent = jest.fn();
    const { unmount } = render(
      <DetectionDetail detId={id} onBack={() => {}} onAction={() => {}} onEvidenceDescent={onDescent} descentScopeIncidentId={null} />
    );
    const btn = await screen.findByRole('button', { name: 'Investigate in SIEM' });
    expect(btn.textContent).toBe('Investigate in SIEM');   // identical label
    fireEvent.click(btn);
    calls.push(onDescent.mock.calls[0][0]);
    unmount();
  }
  // identical key set and values, differing ONLY by the visible account
  expect(Object.keys(calls[0]).sort()).toEqual(Object.keys(calls[1]).sort());
  expect(calls[0].hosts).toEqual(calls[1].hosts);
  expect(calls[0].scopeIncidentId).toBe(calls[1].scopeIncidentId);
  expect(calls[0].account).toBe('ACME\\dlee');
  expect(calls[1].account).toBe('ACME\\rhall');
});

// The P7.5 uniform two-field OR identity form, as one decoded query string.
const IDENTITY_OR_QUERY =
  'all | * | * | user_account == "ACME\\\\dlee" or UserPrincipalName == "ACME\\\\dlee"';

test('an identity entry runs the uniform two-field OR Session-wide without an incident context (GD-5 escaped)', async () => {
  queryResponses.push(ok(snapWith(ROWS_UNORDERED, IDENTITY_OR_QUERY)));
  await act(async () => {
    renderSiem({
      descentRequest: { hosts: [], account: 'ACME\\dlee', scopeIncidentId: null, seq: 1 },
    });
  });
  expect(queryCalls().pop())
    .toBe(`/api/events/query?q=${IDENTITY_OR_QUERY}&scope=session`);
  expect(screen.getByTestId('pinned-case-line').textContent).toBe('All activity');
  // the prepared search is identified by its readable expression in the bar
  expect(screen.getByLabelText('LCQL query'))
    .toHaveValue(IDENTITY_OR_QUERY);
  // an entry starts a FRESH query: no OR-fallback notice at entry time
  expect(screen.queryByTestId('query-notice')).toBeNull();
});

test('an identity entry under a player-selected incident context RETAINS that scope (no special-case, no silent broadening)', async () => {
  queryResponses.push(ok(snapWith([], IDENTITY_OR_QUERY, 'INC-9368')));
  await act(async () => {
    renderSiem({
      activeIncidentId: 'INC-9368',
      descentRequest: { hosts: [], account: 'ACME\\dlee', scopeIncidentId: 'INC-9368', seq: 1 },
    });
  });
  expect(queryCalls().pop())
    .toBe(`/api/events/query?q=${IDENTITY_OR_QUERY}&scope=INC-9368`);
  expect(screen.getByTestId('pinned-case-line').textContent).toBe('Investigating INC-9368');
  // zero rows is the honest case-scoped outcome when the account's events
  // lack participant hostnames; leaving the case on Incidents is the
  // designed path out (III.0 item 2: no SIEM-level session escape exists)
  expect(screen.getByText('0 events match')).toBeInTheDocument();
  expect(screen.queryByTestId('search-all')).toBeNull();
  // no silent scope broadening: nothing executed across all evidence
  expect(queryCalls().some((c) => c.endsWith('&scope=session'))).toBe(false);
});

test('a refinement from the identity-entry OR results mints a fresh standalone query with the exact approved notice', async () => {
  queryResponses.push(ok(snapWith(ROWS_UNORDERED, IDENTITY_OR_QUERY)));
  await act(async () => {
    renderSiem({
      descentRequest: { hosts: [], account: 'ACME\\dlee', scopeIncidentId: null, seq: 1 },
    });
  });
  expect(screen.queryByTestId('query-notice')).toBeNull();   // fresh at entry
  fireEvent.click(within(screen.getByTestId('workbench-results')).getByText('first event'));
  queryResponses.push(ok(snapWith(ROWS_UNORDERED, 'all | * | * | hostname == "ACME-WS10"')));
  await act(async () => {
    fireEvent.click(screen.getByLabelText('Filter hostname equals'));
  });
  expect(queryCalls().pop())
    .toBe('/api/events/query?q=all | * | * | hostname == "ACME-WS10"&scope=session');
  expect(screen.getByTestId('query-notice'))
    .toHaveTextContent('Started a new query; the previous one mixed or-conditions.');
});

test('a hand-broadened query from an entry view stays in the case evidence pool', async () => {
  queryResponses.push(ok(snapWith(ROWS_UNORDERED, 'all | ACME-WS10 | * | *', 'INC-9368')));
  await act(async () => {
    renderSiem({
      activeIncidentId: 'INC-9368',
      descentRequest: { hosts: ['ACME-WS10'], scopeIncidentId: 'INC-9368', seq: 1 },
    });
  });
  expect(screen.getByTestId('results-label').textContent).toBe(INITIAL_INCIDENT_EVIDENCE);
  // broaden the QUERY by hand and run: the evidence universe is unchanged
  // (III.0 item 2) and the label becomes an executed player search
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'all | * | * | *' } });
  queryResponses.push(ok(snapWith(ROWS_UNORDERED, 'all | * | * | *', 'INC-9368')));
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Run Query/ })); });
  expect(queryCalls().pop()).toBe('/api/events/query?q=all | * | * | *&scope=INC-9368');
  expect(screen.getByTestId('results-label').textContent).not.toBe(INITIAL_INCIDENT_EVIDENCE);
  expect(screen.getByTestId('pinned-case-line').textContent).toBe('Investigating INC-9368');
});

test('re-entering with a new seq re-executes the same prepared search', async () => {
  const props = {
    descentRequest: { hosts: ['ACME-WS10'], scopeIncidentId: null, seq: 1 },
  };
  let utils;
  await act(async () => { utils = renderSiem(props); });
  const before = queryCalls().length;
  await act(async () => {
    utils.rerender(
      <Siem initialQueryMode="advanced" resetTrigger={0} onHostPivot={() => {}}
            descentRequest={{ ...props.descentRequest, seq: 2 }} />
    );
  });
  expect(queryCalls().length).toBe(before + 1);
});
