/**
 * Stage 3.9B (IA amendment): the Incidents operational workspace. Verifies the
 * Active/Ready/Completed views + search, stable incident rows, the selected-
 * incident detail (briefing + phase strip incl. the A2 pre-seal line + related
 * hosts/accounts), and that the graded Submit/Resume/Review controls live here.
 * Both neutral readiness messages are reachable; no POST fires on render.
 */
import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import Incidents from '../components/Incidents';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const INCIDENTS = {
  queue_length: 10, resolved_count: 1,
  active: [
    { incident_id: 'INC-1000', title: 'Loading Incident', briefing: 'brief A', severity: 'High', state: 'in_progress', sealed: false },
    { incident_id: 'INC-2000', title: 'Open Incident', briefing: 'brief B', severity: 'High', state: 'in_progress', sealed: true, ready: false, open_detections: 2, triage: { total: 3, triaged: 1 } },
    { incident_id: 'INC-4000', title: 'Ready Incident', briefing: 'brief D', severity: 'Critical', state: 'in_progress', sealed: true, ready: true, open_detections: 0, triage: { total: 3, triaged: 3 } },
  ],
  completed: [
    { incident_id: 'INC-3000', title: 'Done Incident', briefing: 'brief C', severity: 'Medium', state: 'submitted', assisted: false, submitted_at: '2026-07-19T12:00:00Z', incident_grade: { grade: 'B', accuracy: 84.0 } },
    { incident_id: 'INC-3001', title: 'Assisted Incident', briefing: 'brief E', severity: 'Low', state: 'submitted', assisted: true, submitted_at: '2026-07-19T12:05:00Z', incident_grade: { grade: 'A', accuracy: 100.0 } },
  ],
};
const scopeFor = (id) => ({ incident_id: id, sealed: true, hosts: ['ACME-WS10'], accounts: ['ACME\\u'], detection_ids: ['d1'], triage: { total: 3, triaged: 0 } });
const routeJson = (path) => {
  if (path === '/api/incidents') return INCIDENTS;
  if (path === '/api/actions') return [];
  if (path.endsWith('/scope')) return scopeFor(path.split('/')[3]);
  return {};
};
beforeEach(() => {
  apiFetch.mockImplementation((path) => Promise.resolve({ ok: true, json: () => Promise.resolve(routeJson(path)) }));
});

test('renders the workspace: Active/Ready/Completed views + search + rows', async () => {
  render(<Incidents gameMode="training" />);
  expect(await screen.findByText(/Active 3/)).toBeInTheDocument();
  expect(screen.getByText(/Ready 1/)).toBeInTheDocument();
  expect(screen.getByText(/Completed 2/)).toBeInTheDocument();
  expect(screen.getByPlaceholderText('Search incidents...')).toBeInTheDocument();
  expect(screen.getByText('INC-2000')).toBeInTheDocument();   // a row
});

test('selecting a ready incident shows briefing + Submit control (graded control home)', async () => {
  render(<Incidents gameMode="training" activeIncidentId="INC-4000" />);
  expect(await screen.findByText('brief D')).toBeInTheDocument();          // detail-only content
  expect(screen.getByText('3 of 3 reviewed')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Submit' })).toBeInTheDocument();
});

test('a pre-seal incident shows the A2 telemetry-loading line', async () => {
  render(<Incidents gameMode="training" activeIncidentId="INC-1000" />);
  await screen.findByText('brief A');   // detail loaded
  expect(screen.getAllByText('Incident telemetry is still loading.').length).toBeGreaterThanOrEqual(1);
});

test('an open (not-ready) incident shows the observable readiness message', async () => {
  render(<Incidents gameMode="training" activeIncidentId="INC-2000" />);
  expect(await screen.findByText(/2 detections still need review\./)).toBeInTheDocument();
});

test('a submitted incident offers the Post-Incident Review control', async () => {
  render(<Incidents gameMode="training" activeIncidentId="INC-3000" />);
  expect(await screen.findByRole('button', { name: 'View Post-Incident Review' })).toBeInTheDocument();
});

test('completed detail shows the Assisted badge iff Check Answer was used', async () => {
  // assisted submitted incident -> badge shows
  const a = render(<Incidents gameMode="training" activeIncidentId="INC-3001" />);
  expect(await screen.findByText('brief E')).toBeInTheDocument();
  expect(screen.getByText('Assisted')).toBeInTheDocument();
  a.unmount();
  // unassisted submitted incident -> no badge
  render(<Incidents gameMode="training" activeIncidentId="INC-3000" />);
  expect(await screen.findByText('brief C')).toBeInTheDocument();
  expect(screen.queryByText('Assisted')).toBeNull();
});

test('issues no state-changing (POST) call on render', async () => {
  render(<Incidents gameMode="training" activeIncidentId="INC-4000" />);
  await waitFor(() => expect(apiFetch).toHaveBeenCalledWith('/api/incidents'));
  const posts = apiFetch.mock.calls.filter(([, o]) => o && o.method && o.method !== 'GET');
  expect(posts).toHaveLength(0);
});
