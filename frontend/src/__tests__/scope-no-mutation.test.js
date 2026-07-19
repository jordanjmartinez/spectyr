/**
 * Stage 3.9B (C1/§8, D9): the active-incident context is presentation only.
 * Selecting incident A, switching to incident B, clearing to Session-wide, and
 * navigating between the scoped tabs (Detections, Endpoints) must issue READS
 * ONLY -- no POST/PUT/DELETE -- so nothing about the world, response log,
 * grading, readiness, or submission records changes. This is the exact
 * interaction test; no-POST-on-render does not replace it.
 */
import React from 'react';
import { render, waitFor } from '@testing-library/react';
import Detections from '../components/Detections';
import Endpoints from '../components/Endpoints';
import Incidents from '../components/Incidents';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const routeJson = (path) => {
  if (path === '/api/detections') return { detections: [], counts: { open: 0, promoted: 0, dismissed: 0 } };
  if (path === '/api/endpoints') return { endpoints: [], org: {} };
  if (path === '/api/incidents') return { active: [], completed: [], queue_length: 0, resolved_count: 0 };
  if (path === '/api/actions') return [];
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
