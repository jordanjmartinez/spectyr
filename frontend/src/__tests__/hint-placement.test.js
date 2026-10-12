/**
 * Stage 6 playtest fix 8: the Guided "Need a hint?" pill never buries
 * content.
 *
 * - The pill docks bottom-RIGHT (supersedes the VE5 left offset, which sat
 *   exactly over the SIEM facet column and, with the rail hidden below md,
 *   floated over content).
 * - While the pill is active (Guided only), the shell's content area adds
 *   bottom clearance so the last rows of any column scroll clear of it;
 *   other modes carry no dead space.
 */
import React from 'react';
import { render, screen, act, waitFor } from '@testing-library/react';
import HintPanel from '../components/HintPanel';
import Dashboard from '../pages/Dashboard';

jest.mock('react-router-dom', () => ({
  Link: ({ to, children, ...rest }) => {
    const R = require('react');
    return R.createElement('a', { href: typeof to === 'string' ? to : '#', ...rest }, children);
  },
}), { virtual: true });
jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
const route = (gameMode) => (path) => {
  if (path === '/api/game-state') return ok({ analyst_name: 'A', game_mode: gameMode, injected_count: 0 });
  if (path === '/api/incidents') {
    return ok({ active: [], completed: [], queue_length: 0, resolved_count: 0,
                stats: { severity_breakdown: {} } });
  }
  if (path === '/api/detections') return ok({ detections: [], counts: { open: 0, promoted: 0, dismissed: 0 } });
  if (path === '/api/endpoints') return ok({ org: {}, endpoints: [] });
  if (path === '/api/analytics/report_card') return ok({ state: 'in_progress', progress: { submitted: 0 } });
  if (path === '/api/actions') return ok({ actions: [] });
  return ok({});
};

beforeEach(() => { apiFetch.mockReset(); });

test('the pill docks bottom-right, never the old rail-clearing left offset', () => {
  render(<HintPanel gameMode="guided" surface="siem" />);
  const panel = screen.getByTestId('hint-panel');
  expect(panel.className).toMatch(/\bbottom-5\b/);
  expect(panel.className).toMatch(/\bright-5\b/);
  expect(panel.className).not.toMatch(/left-/);
});

test('Guided adds bottom clearance to the content area; other modes carry none', async () => {
  apiFetch.mockImplementation(route('guided'));
  const guided = render(<Dashboard />);
  await act(async () => {});
  await waitFor(() => expect(guided.container.querySelector('[data-testid="hint-panel"]')).not.toBeNull());
  expect(guided.container.querySelector('.p-4.pb-20')).not.toBeNull();
  guided.unmount();

  apiFetch.mockImplementation(route('hardcore'));
  const hardcore = render(<Dashboard />);
  await act(async () => {});
  await waitFor(() => expect(hardcore.container.textContent).toContain('Dashboard'));
  expect(hardcore.container.querySelector('[data-testid="hint-panel"]')).toBeNull();
  expect(hardcore.container.querySelector('.p-4.pb-20')).toBeNull();
});
