/**
 * Final pass III.0 item 3: SIEM search-state truth.
 *
 * The five distinguishable states, each labeled with its ruled sentence:
 *  - initial evidence (a prepared entry the player never wrote) is NEVER
 *    labeled a player query: "Initial incident evidence" (case-scoped) /
 *    "Initial evidence" (the caseless prepared entry, flagged variant)
 *  - an executed search is identified by its READABLE filter expression
 *    ("Results for: X"; a match-all filter reads "all events") with the
 *    canonical query still visible as the technical disclosure
 *  - edited but not run: pickers and typing never execute; the ruled
 *    edited sentence names the state (workbench-states pins the copy)
 *  - failed search: ruled three-line form (query-clarity pins the copy)
 *  - hidden selection: retained, never silently closed (workbench-snapshot
 *    pins the behavior)
 * The placeholder stays unmistakably an example in both modes.
 */
import React from 'react';
import { render, screen, fireEvent, act } from '@testing-library/react';
import Siem from '../components/Siem';
import {
  resultsFor, ALL_EVENTS_LABEL, INITIAL_INCIDENT_EVIDENCE, INITIAL_EVIDENCE,
} from '../components/uiCopy';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

const EVENT = {
  id: 'st-1', event_seq: 11, timestamp: '2026-03-17T05:10:00+00:00',
  event_type: 'ProcessCreate', source_type: 'Sysmon', severity: 'high',
  hostname: 'ACME-WS10', source_ip: '10.0.1.12', user_account: 'ACME\\nkhan',
  message: 'state fixture event', key_value_pairs: {},
};

let queryResponses;
beforeEach(() => {
  queryResponses = [];
  apiFetch.mockReset();
  apiFetch.mockImplementation((p) => {
    if (p === '/api/endpoints') return ok({ org: {}, endpoints: [] });
    if (p.startsWith('/api/events/query/new-count')) return ok({ new_count: 0, pool_growth: 0 });
    if (p.startsWith('/api/events/query')) {
      if (queryResponses.length) return queryResponses.shift();
      const q = decodeURIComponent(p);
      const m = q.match(/\?q=(.+)&scope=(.+)$/);
      return ok({
        token: 'tok.one',
        identity: {
          canonical_query: m[1], scope: m[2], resolved_scope_hosts: [],
          resolved_range: { start: '2026-03-17T03:41:00+00:00', end: '2026-03-17T05:20:00+00:00' },
          cutoff_seq: 500,
        },
        count: 1, rows: [EVENT],
      });
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

const run = async (text) => {
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: text } });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Run Query/ })); });
};

test('an executed player search reads "Results for:" with the readable filter expression; the canonical stays as the technical disclosure', async () => {
  render(<Siem initialQueryMode="advanced" resetTrigger={0} onHostPivot={() => {}} />);
  await run('all | * | * | source_ip == "10.0.1.32"');
  expect(screen.getByTestId('results-label').textContent)
    .toBe(resultsFor('source_ip == "10.0.1.32"'));
  // technical disclosure: the canonical query remains visible
  expect(screen.getAllByText('all | * | * | source_ip == "10.0.1.32"').length)
    .toBeGreaterThanOrEqual(1);
});

test('a match-all player search reads "Results for: all events", never a bare star', async () => {
  render(<Siem initialQueryMode="advanced" resetTrigger={0} onHostPivot={() => {}} />);
  await run('all | * | * | *');
  expect(screen.getByTestId('results-label').textContent)
    .toBe(resultsFor(ALL_EVENTS_LABEL));
});

test('a prepared incident entry is labeled "Initial incident evidence", never a player query; Refresh preserves it; a player run replaces it', async () => {
  await act(async () => {
    render(<Siem initialQueryMode="advanced" resetTrigger={0} onHostPivot={() => {}}
      activeIncidentId="INC-9368" onNavigate={() => {}}
      descentRequest={{ origin: 'INC-9368', hosts: ['ACME-WS10'], scopeIncidentId: 'INC-9368', backView: 'incidents', seq: 1 }}
    />);
  });
  expect(queryCalls().pop()).toBe('/api/events/query?q=all | ACME-WS10 | * | *&scope=INC-9368');
  expect(screen.getByTestId('results-label').textContent).toBe(INITIAL_INCIDENT_EVIDENCE);
  expect(screen.getByTestId('results-label').textContent).not.toContain('Results for');
  // Refresh re-executes the displayed identity: still initial evidence
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Refresh' })); });
  expect(screen.getByTestId('results-label').textContent).toBe(INITIAL_INCIDENT_EVIDENCE);
  // the player authors a run: the label becomes an executed search
  await run('all | ACME-WS10 | * | user_account == "ACME\\nkhan"');
  expect(screen.getByTestId('results-label').textContent)
    .toBe(resultsFor('user_account == "ACME\\nkhan"'));
});

test('a caseless prepared entry is labeled "Initial evidence" (no incident to name)', async () => {
  await act(async () => {
    render(<Siem initialQueryMode="advanced" resetTrigger={0} onHostPivot={() => {}}
      onNavigate={() => {}}
      descentRequest={{ origin: 'DET-42', hosts: ['ACME-WS10'], scopeIncidentId: null, backView: 'detections', seq: 1 }}
    />);
  });
  expect(queryCalls().pop()).toBe('/api/events/query?q=all | ACME-WS10 | * | *&scope=session');
  expect(screen.getByTestId('results-label').textContent).toBe(INITIAL_EVIDENCE);
});

test('pickers and typing never execute: only Run (and the ruled immediate actions) issue queries', async () => {
  await act(async () => {
    render(<Siem resetTrigger={0} onHostPivot={() => {}} />);
  });
  // simple mode is the product default: type a filter, change the pickers
  fireEvent.change(screen.getByLabelText('Filters'), { target: { value: 'source_ip == "10.0.1.32"' } });
  fireEvent.change(screen.getByLabelText('Timeframe'), { target: { value: '24h' } });
  fireEvent.change(screen.getByLabelText('Source'), { target: { value: 'Sysmon' } });
  expect(queryCalls()).toEqual([]);
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Run Query/ })); });
  expect(queryCalls()).toHaveLength(1);
});

test('the placeholder stays unmistakably an example in both modes', async () => {
  render(<Siem resetTrigger={0} onHostPivot={() => {}} />);
  expect(screen.getByLabelText('Filters').placeholder).toMatch(/^Example:/);
  fireEvent.click(screen.getByTestId('query-mode-toggle'));
  expect(screen.getByLabelText('LCQL query').placeholder).toMatch(/^Example:/);
});
