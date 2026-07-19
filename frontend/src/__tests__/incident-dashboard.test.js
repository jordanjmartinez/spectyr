/**
 * Stage 3.9B (IA amendment): the Dashboard is the compact SESSION-WIDE OVERVIEW.
 * It carries summary metrics, compact Active/Completed overviews with
 * NAVIGATION-LEVEL actions only, and overview widgets. It never hosts the graded
 * Submit/Resume/Review controls (those live in Incidents). "Incident Grade" and
 * "Session Performance" remain both present and distinct.
 */
import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import IncidentDashboard from '../components/IncidentDashboard';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const INCIDENTS = {
  queue_length: 10, resolved_count: 1,
  active: [
    { incident_id: 'INC-1000', title: 'Loading Incident', severity: 'High', state: 'in_progress', sealed: false },
    { incident_id: 'INC-2000', title: 'Ready Incident', severity: 'Critical', state: 'in_progress', sealed: true, ready: true, open_detections: 0 },
  ],
  completed: [
    { incident_id: 'INC-3000', title: 'Done Incident', severity: 'Medium', state: 'submitted', assisted: true, submitted_at: '2026-07-19T12:00:00Z', incident_grade: { grade: 'B', accuracy: 84.0 } },
  ],
};
const routeJson = (path) => {
  if (path === '/api/incidents') return INCIDENTS;
  if (path === '/api/analytics/report_card') return { state: 'submitted', grading: { composite: { grade: 'C', accuracy: 71.0 } } };
  if (path === '/api/grouped-alerts') return { stats: { severity_breakdown: { critical: 1, high: 1, medium: 0, low: 0 } } };
  if (path === '/api/analytics/attack_coverage') return { tactics_covered: 2, total_tactics: 13, completed: 1 };
  if (path === '/api/endpoints') return { endpoints: [{ hostname: 'H1', status: 'online' }] };
  if (path === '/api/detections') return { counts: { open: 4 } };
  if (path === '/api/game-state') return { game_mode: 'training', queue_length: 10 };
  return {};
};
beforeEach(() => {
  apiFetch.mockImplementation((path) => Promise.resolve({ ok: true, json: () => Promise.resolve(routeJson(path)) }));
});

test('renders the compact overview: metrics + Active/Completed overviews', async () => {
  render(<IncidentDashboard gameMode="training" analystName="A" />);
  expect(await screen.findByText('Active incidents')).toBeInTheDocument();     // metric label
  expect(screen.getByText('Completed incidents')).toBeInTheDocument();
  expect(screen.getByText('Active Incidents')).toBeInTheDocument();            // section
  expect(screen.getByText('Recent Completed')).toBeInTheDocument();
  expect(await screen.findByText('INC-2000')).toBeInTheDocument();
});

test('Incident Grade and Session Performance are both present and distinct', async () => {
  render(<IncidentDashboard gameMode="training" />);
  await screen.findByText('INC-3000');
  expect(screen.getByText('Session Performance')).toBeInTheDocument();
  expect(screen.getByText('C')).toBeInTheDocument();          // session grade
  expect(screen.getByText(/B · 84%/)).toBeInTheDocument();    // incident grade on the completed row
});

test('Dashboard hosts NO graded controls (no Submit, navigation-only)', async () => {
  render(<IncidentDashboard gameMode="training" />);
  await screen.findByText('INC-2000');
  expect(screen.queryByRole('button', { name: /^Submit/ })).toBeNull();
  expect(screen.queryByText(/still need review/)).toBeNull();
});

test('issues no state-changing (POST) call on render', async () => {
  render(<IncidentDashboard gameMode="training" />);
  await waitFor(() => expect(apiFetch).toHaveBeenCalledWith('/api/incidents'));
  const posts = apiFetch.mock.calls.filter(([, o]) => o && o.method && o.method !== 'GET');
  expect(posts).toHaveLength(0);
});

test('SOC Queue band shows the mode label and the queue denominator', async () => {
  render(<IncidentDashboard gameMode="analyst" />);
  await screen.findByText('SOC Queue');
  expect(screen.getByText(/of 10 resolved/)).toBeInTheDocument();   // N of 10
});

test('Guided band uses independent-run language, not a queue denominator', async () => {
  render(<IncidentDashboard gameMode="guided" />);   // resolved_count 1 in the mock
  await screen.findByText('Guided');
  expect(screen.getByText('Run completed')).toBeInTheDocument();
  expect(screen.queryByText(/of 10 resolved/)).toBeNull();
});
