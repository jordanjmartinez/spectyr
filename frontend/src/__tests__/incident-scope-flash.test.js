/**
 * Stage 6 playtest fix 7: switching incidents never flashes the previous
 * incident's related hosts/accounts (an analyst could act against the wrong
 * host). The detail panel now reads the ONE shared scope state
 * (useIncidentScope, the same machinery behind Detections / Endpoints /
 * Response): data drops the moment the incident changes (the loading line
 * renders instead), and a late response for the OLD incident is discarded,
 * never rendered.
 */
import React from 'react';
import { render, screen, act } from '@testing-library/react';
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

test('switching incidents shows the loading line, then the new scope; never the old hosts', async () => {
  let resolveB;
  apiFetch.mockImplementation((path) => {
    if (path === '/api/incidents') return ok(LIST);
    if (path === '/api/incidents/INC-A/scope') return ok(scopeBody('INC-A', ['HOST-A'], ['ACME\\usera']));
    if (path === '/api/incidents/INC-B/scope') return new Promise((resolve) => { resolveB = resolve; });
    return ok({});
  });
  const view = render(<Host gameMode="soc_queue" activeIncidentId="INC-A" />);
  await screen.findByText('HOST-A');

  // switch to B while B's scope is still in flight
  await act(async () => {
    view.rerender(<Host gameMode="soc_queue" activeIncidentId="INC-B" />);
  });
  expect(screen.queryByText('HOST-A')).toBeNull(); // the reported flash
  expect(screen.getByText('Loading incident scope')).toBeInTheDocument();

  await act(async () => {
    resolveB({ ok: true, status: 200, json: () => Promise.resolve(scopeBody('INC-B', ['HOST-B'], [])) });
  });
  expect(screen.getByText('HOST-B')).toBeInTheDocument();
  expect(screen.queryByText('HOST-A')).toBeNull();
});

test('a late response for the previous incident is discarded, never rendered', async () => {
  let resolveA;
  apiFetch.mockImplementation((path) => {
    if (path === '/api/incidents') return ok(LIST);
    if (path === '/api/incidents/INC-A/scope') return new Promise((resolve) => { resolveA = resolve; });
    if (path === '/api/incidents/INC-B/scope') return ok(scopeBody('INC-B', ['HOST-B'], []));
    return ok({});
  });
  const view = render(<Host gameMode="soc_queue" activeIncidentId="INC-A" />);
  await screen.findByText('Loading incident scope');
  await act(async () => {
    view.rerender(<Host gameMode="soc_queue" activeIncidentId="INC-B" />);
  });
  await screen.findByText('HOST-B');
  // A's slow response lands AFTER B rendered: it must be dropped
  await act(async () => {
    resolveA({ ok: true, status: 200, json: () => Promise.resolve(scopeBody('INC-A', ['HOST-A'], [])) });
  });
  expect(screen.queryByText('HOST-A')).toBeNull();
  expect(screen.getByText('HOST-B')).toBeInTheDocument();
});
