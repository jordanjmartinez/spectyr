/**
 * SIEM search-state truth (Final pass III.0 item 3, under the owner
 * simplification pass + follow-up 2026-10-13).
 *
 * The distinguishable states, each labeled with its ruled sentence:
 *  - initial evidence (a prepared entry the player never wrote) is NEVER
 *    labeled a player query: "Initial Incident Evidence" (case-scoped) /
 *    "Initial Evidence" (the caseless prepared entry)
 *  - an executed search is identified by its READABLE filter expression
 *    ("Results for: X"; a match-all filter reads "all events")
 *  - the snapshot meta line is the trimmed Results for / Snapshot / Scope
 *    form: no seq number, no sim timestamp, no raw canonical dump
 *  - hidden selection: retained, never silently closed (workbench-snapshot
 *    pins the behavior)
 *  - typing in the search box never executes; Enter / Search does.
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
let countResponse;
beforeEach(() => {
  queryResponses = [];
  countResponse = () => ok({ new_count: 0, pool_growth: 0 });
  apiFetch.mockReset();
  apiFetch.mockImplementation((p) => {
    if (p.startsWith('/api/events/query/new-count')) return countResponse();
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

const search = async (text) => {
  fireEvent.change(screen.getByLabelText('Search events'), { target: { value: text } });
  await act(async () => {
    fireEvent.keyDown(screen.getByLabelText('Search events'), { key: 'Enter' });
  });
};

test('an executed player search reads "Results for:" with the readable filter expression; the raw canonical never prints', async () => {
  render(<Siem resetTrigger={0} onHostPivot={() => {}} />);
  await search('source ip = 10.0.1.32');
  expect(screen.getByTestId('results-label').textContent)
    .toBe(resultsFor('source_ip == "10.0.1.32"'));
  const metaRow = screen.getByTestId('results-label').parentElement;
  expect(metaRow.textContent).toContain('Snapshot: 1 events');
  expect(metaRow.textContent).toContain('Scope: Session');
  expect(metaRow.textContent).not.toContain('1h | * | * |');
  expect(metaRow.textContent).not.toMatch(/as of seq #/);
});

test('a match-all search reads "Results for: all events", never a bare star', async () => {
  render(<Siem resetTrigger={0} onHostPivot={() => {}} />);
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Show Events' }));
  });
  expect(screen.getByTestId('results-label').textContent)
    .toBe(resultsFor(ALL_EVENTS_LABEL));
});

test('a prepared incident entry is labeled "Initial Incident Evidence", never a player query; loading new events preserves it; a player search replaces it', async () => {
  jest.useFakeTimers();
  try {
    await act(async () => {
      render(<Siem resetTrigger={0} onHostPivot={() => {}}
        activeIncidentId="INC-9368" onNavigate={() => {}}
        descentRequest={{ hosts: ['ACME-WS10'], scopeIncidentId: 'INC-9368', seq: 1 }}
      />);
    });
    expect(queryCalls().pop()).toBe('/api/events/query?q=all | ACME-WS10 | * | *&scope=INC-9368');
    expect(screen.getByTestId('results-label').textContent).toBe(INITIAL_INCIDENT_EVIDENCE);
    expect(screen.getByTestId('results-label').textContent).not.toContain('Results for');
    // the incident scope reads honestly on the trimmed meta line
    expect(screen.getByTestId('results-label').parentElement.textContent)
      .toContain('Scope: INC-9368');
    // Load New Events re-executes the displayed identity: still initial evidence
    countResponse = () => ok({ new_count: 2, pool_growth: 2 });
    await act(async () => { jest.advanceTimersByTime(3000); });
    await act(async () => {});
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Load New Events' }));
    });
    expect(screen.getByTestId('results-label').textContent).toBe(INITIAL_INCIDENT_EVIDENCE);
    // the player authors a search: the label becomes an executed search,
    // merged with the adopted host filter (one filter system)
    await search('user = nkhan');
    expect(screen.getByTestId('results-label').textContent)
      .toBe(resultsFor('hostname == "ACME-WS10" and user_account == "nkhan"'));
  } finally {
    jest.useRealTimers();
  }
});

test('a caseless prepared entry is labeled "Initial Evidence" (no incident to name)', async () => {
  await act(async () => {
    render(<Siem resetTrigger={0} onHostPivot={() => {}}
      onNavigate={() => {}}
      descentRequest={{ hosts: ['ACME-WS10'], scopeIncidentId: null, seq: 1 }}
    />);
  });
  expect(queryCalls().pop()).toBe('/api/events/query?q=all | ACME-WS10 | * | *&scope=session');
  expect(screen.getByTestId('results-label').textContent).toBe(INITIAL_EVIDENCE);
});

test('typing in the search box never executes; Enter does', async () => {
  await act(async () => {
    render(<Siem resetTrigger={0} onHostPivot={() => {}} />);
  });
  fireEvent.change(screen.getByLabelText('Search events'),
    { target: { value: 'severity = high' } });
  fireEvent.change(screen.getByLabelText('Timeframe'), { target: { value: '24h' } });
  expect(queryCalls()).toEqual([]);
  await act(async () => {
    fireEvent.keyDown(screen.getByLabelText('Search events'), { key: 'Enter' });
  });
  expect(queryCalls()).toEqual(['/api/events/query?q=24h | * | * | severity == "high"&scope=session']);
});
