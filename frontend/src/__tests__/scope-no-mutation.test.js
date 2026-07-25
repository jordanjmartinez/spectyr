/**
 * Stage 3.9B (C1/§8, D9): the active-incident context is presentation only.
 * Selecting incident A, switching to incident B, clearing to Session-wide, and
 * navigating between the scoped tabs (Detections, Endpoints) must issue READS
 * ONLY -- no POST/PUT/DELETE -- so nothing about the world, response log,
 * grading, readiness, or submission records changes. This is the exact
 * interaction test; no-POST-on-render does not replace it.
 */
import React from 'react';
import { render, screen, fireEvent, act, waitFor, within } from '@testing-library/react';
import Detections from '../components/Detections';
import Endpoints from '../components/Endpoints';
import Incidents from '../components/Incidents';
import Siem from '../components/Siem';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const WORKBENCH_EVENT = {
  id: 'nm-1', event_seq: 7, timestamp: '2026-03-17T05:00:00+00:00',
  event_type: 'QUERY', source_type: 'DNS', severity: 'low',
  hostname: 'ACME-WS10', message: 'no-mutation fixture event', key_value_pairs: {},
};

const routeJson = (path) => {
  if (path === '/api/detections') return { detections: [], counts: { open: 0, promoted: 0, dismissed: 0 } };
  if (path === '/api/endpoints') return { endpoints: [], org: {} };
  if (path === '/api/incidents') return { active: [], completed: [], queue_length: 0, resolved_count: 0 };
  if (path === '/api/actions') return [];
  if (path.startsWith('/api/events/query/new-count')) return { new_count: 0, pool_growth: 0 };
  if (path.startsWith('/api/events/query')) {
    return {
      token: 'tok.one',
      identity: {
        canonical_query: 'all | ACME-WS10 | * | *', scope: 'session',
        resolved_scope_hosts: [],
        resolved_range: { start: '2026-03-17T03:41:00+00:00', end: '2026-03-17T05:20:00+00:00' },
        cutoff_seq: 100,
      },
      count: 1, rows: [WORKBENCH_EVENT],
    };
  }
  if (path.endsWith('/scope')) return { incident_id: path.split('/')[3], sealed: true, hosts: [], accounts: [], detection_ids: [] };
  return {};
};
beforeEach(() => {
  apiFetch.mockClear();
  apiFetch.mockImplementation((path) => Promise.resolve({ ok: true, json: () => Promise.resolve(routeJson(path)) }));
});

const mutatingCalls = () =>
  apiFetch.mock.calls.filter(([, o]) => o && typeof o.method === 'string' && o.method.toUpperCase() !== 'GET');

test('select A, switch to B, clear to Session-wide across scoped tabs issues reads only', async () => {
  // Detections: no scope -> A -> B -> clear
  const d = render(<Detections isVisible activeIncidentId={null} />);
  await waitFor(() => expect(apiFetch).toHaveBeenCalledWith('/api/detections'));
  d.rerender(<Detections isVisible activeIncidentId="INC-A" />);
  await waitFor(() => expect(apiFetch).toHaveBeenCalledWith('/api/incidents/INC-A/scope'));
  d.rerender(<Detections isVisible activeIncidentId="INC-B" />);
  await waitFor(() => expect(apiFetch).toHaveBeenCalledWith('/api/incidents/INC-B/scope'));
  d.rerender(<Detections isVisible activeIncidentId={null} />);   // clear to Session-wide
  d.unmount();

  // Navigate to Endpoints: no scope -> A -> B -> clear
  const e = render(<Endpoints isVisible activeIncidentId={null} />);
  await waitFor(() => expect(apiFetch).toHaveBeenCalledWith('/api/endpoints'));
  e.rerender(<Endpoints isVisible activeIncidentId="INC-A" />);
  e.rerender(<Endpoints isVisible activeIncidentId="INC-B" />);
  e.rerender(<Endpoints isVisible activeIncidentId={null} />);
  e.unmount();

  // Incidents workspace: switch the focused incident A -> B -> clear
  const w = render(<Incidents gameMode="training" activeIncidentId="INC-A" />);
  await waitFor(() => expect(apiFetch).toHaveBeenCalledWith('/api/incidents'));
  w.rerender(<Incidents gameMode="training" activeIncidentId="INC-B" />);
  w.rerender(<Incidents gameMode="training" activeIncidentId={null} />);

  expect(mutatingCalls()).toHaveLength(0);   // reads only; nothing was mutated
});

// Stage 4 P7 (contract Section 18 "No-mutation reads", extended): the whole
// investigation surface -- descent entry, query run, entity pivot, scope
// switching, and the return chip -- issues READS ONLY. Nothing about the
// world, response log, grading, readiness, or submissions can change from
// investigating.
test('P7 descent, pivot, scope switch, and return-to-incident issue reads only', async () => {
  await act(async () => {
    render(
      <Siem
        setSiemCount={() => {}} resetTrigger={0} onHostPivot={() => {}}
        activeIncidentId="INC-A" onNavigate={() => {}}
        descentRequest={{ origin: 'INC-A', hosts: ['ACME-WS10'], scopeIncidentId: 'INC-A', backView: 'incidents', seq: 1 }}
      />
    );
  });
  await waitFor(() => expect(screen.getByTestId('descent-banner')).toBeInTheDocument());

  // entity pivot out of the case evidence (visible Expanded search entry)
  fireEvent.click(within(screen.getByTestId('workbench-results')).getByText('no-mutation fixture event'));
  await act(async () => {
    fireEvent.click(screen.getByLabelText('Pivot hostname'));
  });
  // return to the case evidence via the single return action
  await act(async () => {
    fireEvent.click(screen.getByTestId('return-chip'));
  });
  // deliberate Expanded search entry and return, both directions
  await act(async () => {
    fireEvent.click(screen.getByTestId('search-all'));
  });
  await act(async () => {
    fireEvent.click(screen.getByTestId('return-chip'));
  });

  expect(mutatingCalls()).toHaveLength(0);   // the investigation surface is read-only
});

// P7.4: identity-detection descent (account-anchored) is a read like every
// other descent -- under an incident context and Session-wide alike.
test('P7.4 identity descent issues reads only', async () => {
  await act(async () => {
    render(
      <Siem
        setSiemCount={() => {}} resetTrigger={0} onHostPivot={() => {}}
        activeIncidentId="INC-A" onNavigate={() => {}}
        descentRequest={{ origin: 'det-ids1', hosts: [], account: 'ACME\\dlee', scopeIncidentId: 'INC-A', backView: 'detections', seq: 1 }}
      />
    );
  });
  await waitFor(() =>
    expect(apiFetch).toHaveBeenCalledWith(expect.stringContaining('/api/events/query')));
  expect(mutatingCalls()).toHaveLength(0);
});
