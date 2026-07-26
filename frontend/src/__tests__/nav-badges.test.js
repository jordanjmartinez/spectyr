/**
 * C1 checkpoint fix (post-Stage-5 review, F1): the nav rail badge contract.
 * The evidence-surface entries (SIEM, Detections, Endpoints) carry NO
 * numeric badge: the removed badges read unfiltered session payloads while
 * the page headers rendered case-scoped counts, so with a case pinned the
 * rail and the page could not agree (confirmed live: password_spray shows
 * 3 session endpoints vs 1 case participant). The Incidents badge stays --
 * cases are a global concept, and its count is the active-incident list the
 * page itself renders.
 */
import React from 'react';
import { render, screen, waitFor, act } from '@testing-library/react';
import Dashboard from '../pages/Dashboard';

// react-router-dom v7 ships ESM that CRA's jest cannot resolve; Dashboard
// uses only <Link>, so a factory mock stands in for it.
jest.mock('react-router-dom', () => ({
  Link: ({ to, children, ...rest }) => {
    const R = require('react');
    return R.createElement('a', { href: typeof to === 'string' ? to : '#', ...rest }, children);
  },
}), { virtual: true });
jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

// Every routed payload deliberately carries NON-ZERO session-wide numbers,
// so a badge that survived on any of the three entries would render.
const route = (path) => {
  if (path === '/api/game-state') return ok({ analyst_name: 'A', game_mode: 'guided', injected_count: 0 });
  if (path === '/api/incidents') {
    return ok({
      active: [{ incident_id: 'INC-1', title: 'T', briefing: 'b', severity: 'High',
                 state: 'in_progress', sealed: true, ready: false, open_detections: 2,
                 triage: { total: 3, triaged: 1 }, related_actions: 0 }],
      completed: [], queue_length: 1, resolved_count: 0,
      stats: { severity_breakdown: { critical: 0, high: 1, medium: 0, low: 0 } },
    });
  }
  if (path === '/api/detections') return ok({ detections: [], counts: { open: 5, promoted: 1, dismissed: 0 } });
  if (path === '/api/endpoints') return ok({ org: {}, endpoints: [{ hostname: 'H1' }, { hostname: 'H2' }, { hostname: 'H3' }] });
  if (path === '/api/reports') return ok([]);
  if (path === '/api/analytics/report_card') return ok({ state: 'in_progress', progress: { submitted: 0 } });
  if (path === '/api/analytics/action_history') return ok([]);
  if (path === '/api/analytics/attack_coverage') return ok({ tactics: [] });
  if (path === '/api/current-level') return ok({});
  if (path === '/api/actions') return ok({ actions: [] });
  if (path.endsWith('/scope')) return ok({ incident_id: 'INC-1', sealed: true, hosts: [], accounts: [], detection_ids: [] });
  return ok({});
};

beforeEach(() => {
  apiFetch.mockReset();
  apiFetch.mockImplementation(route);
});

const renderDashboard = async () => {
  await act(async () => {
    render(<Dashboard />);
  });
};

test('the evidence-surface nav entries render no numeric badge', async () => {
  await renderDashboard();
  // the Incidents badge (the control case) proves counts had time to land
  await waitFor(() => expect(screen.getByTitle('Incidents').textContent).toBe('Incidents1'));
  for (const label of ['SIEM', 'Detections', 'Endpoints']) {
    expect(screen.getByTitle(label).textContent).toBe(label);
  }
});

test('the Incidents nav entry keeps its active-incident badge', async () => {
  await renderDashboard();
  await waitFor(() => expect(screen.getByTitle('Incidents').textContent).toBe('Incidents1'));
});
