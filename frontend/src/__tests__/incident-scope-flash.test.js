/**
 * Stage 6 playtest fix 7, re-targeted by the owner declutter (2026-10-12):
 * the detail panel no longer DISPLAYS related hosts/accounts (the block is
 * removed), so the never-act-against-the-wrong-host guarantee now lives at
 * the one remaining scope consumer -- the Investigate in SIEM descent. The
 * panel still reads the ONE shared scope state (useIncidentScope): data
 * drops the moment the incident changes and a late response for the OLD
 * incident is discarded, so the descent can never carry a previous
 * incident's hosts.
 */
import React from 'react';
import { render, screen, act, fireEvent } from '@testing-library/react';
import Incidents from '../components/Incidents';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');
const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

const card = (id, title) => ({
  incident_id: id, title, briefing: 'brief', severity: 'High',
  state: 'in_progress', sealed: true, ready: false, open_detections: 1,
  triage: { total: 2, triaged: 1 },
});
const LIST = {
  queue_length: 2, resolved_count: 0,
  active: [card('INC-A', 'Alpha'), card('INC-B', 'Beta')], completed: [],
};
const scopeBody = (id, hosts, accounts) =>
  ({ incident_id: id, sealed: true, hosts, accounts, detection_ids: [] });

const Host = (props) => {
  const [chosen, setChosen] = React.useState({});
  return <Incidents chosen={chosen} setChosen={setChosen} {...props} />;
};

beforeEach(() => { apiFetch.mockReset(); });

test('the panel renders NO related hosts/accounts/loading display (owner declutter)', async () => {
  apiFetch.mockImplementation((path) => {
    if (path === '/api/incidents') return ok(LIST);
    if (path === '/api/incidents/INC-A/scope') return ok(scopeBody('INC-A', ['HOST-A'], ['ACME\\usera']));
    return ok({});
  });
  render(<Host gameMode="soc_queue" activeIncidentId="INC-A" onEvidenceDescent={() => {}} />);
  // the descent entry appears once the scope loads...
  await screen.findByRole('button', { name: 'Investigate in SIEM' });
  // ...but no scope text ever displays
  expect(screen.queryByText('HOST-A')).toBeNull();
  expect(screen.queryByText(/Related Hosts:/)).toBeNull();
  expect(screen.queryByText(/Related Accounts:/)).toBeNull();
  expect(screen.queryByText('Loading incident scope')).toBeNull();
});

test('a late scope response for the previous incident never reaches the descent payload', async () => {
  let resolveA;
  const onEvidenceDescent = jest.fn();
  apiFetch.mockImplementation((path) => {
    if (path === '/api/incidents') return ok(LIST);
    if (path === '/api/incidents/INC-A/scope') return new Promise((resolve) => { resolveA = resolve; });
    if (path === '/api/incidents/INC-B/scope') return ok(scopeBody('INC-B', ['HOST-B'], []));
    return ok({});
  });
  const view = render(<Host gameMode="soc_queue" activeIncidentId="INC-A"
    onEvidenceDescent={onEvidenceDescent} />);
  await screen.findAllByText('Alpha');   // row + detail header
  // A's scope is still in flight: no descent entry yet (no stale target)
  expect(screen.queryByRole('button', { name: 'Investigate in SIEM' })).toBeNull();

  await act(async () => {
    view.rerender(<Host gameMode="soc_queue" activeIncidentId="INC-B"
      onEvidenceDescent={onEvidenceDescent} />);
  });
  const btn = await screen.findByRole('button', { name: 'Investigate in SIEM' });
  // A's slow response lands AFTER B is current: it must be dropped
  await act(async () => {
    resolveA({ ok: true, status: 200, json: () => Promise.resolve(scopeBody('INC-A', ['HOST-A'], [])) });
  });
  fireEvent.click(btn);
  expect(onEvidenceDescent).toHaveBeenCalledTimes(1);
  expect(onEvidenceDescent).toHaveBeenCalledWith({
    hosts: ['HOST-B'], account: null, scopeIncidentId: 'INC-B',
  });
});
