/**
 * VH (owner correction): the clean application header. Left: the current
 * workspace title (t-page), never a mode or analyst name. Right: real
 * utilities only -- the 32px circular ghost avatar (no fake search,
 * bells, settings, or profile controls; no notification surface exists
 * and the only Help surface is the Guided floating hint control). The
 * avatar opens existing real controls only and is never a dead button.
 */
import React from 'react';
import { render, screen, waitFor, fireEvent, within, act } from '@testing-library/react';

jest.mock('react-router-dom', () => ({
  Link: ({ to, children, ...rest }) => {
    const R = require('react');
    return R.createElement('a', { href: typeof to === 'string' ? to : '#', ...rest }, children);
  },
}), { virtual: true });
jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');
const Dashboard = require('../pages/Dashboard').default;

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
const route = (analyst) => (path) => {
  if (path === '/api/game-state') {
    return ok({ analyst_name: analyst, game_mode: 'guided', injected_count: 0 });
  }
  if (path === '/api/incidents') return ok({ active: [], completed: [], queue_length: 0, resolved_count: 0 });
  if (path === '/api/detections') return ok({ detections: [], counts: { open: 0 } });
  if (path === '/api/endpoints') return ok({ org: {}, endpoints: [] });
  if (path === '/api/analytics/report_card') return ok({ state: 'in_progress', progress: {} });
  if (path === '/api/analytics/action_history') return ok([]);
  if (path === '/api/actions') return ok({ actions: [] });
  return ok({});
};

const renderDashboard = async (analyst = 'Jordan') => {
  apiFetch.mockReset();
  apiFetch.mockImplementation(route(analyst));
  await act(async () => { render(<Dashboard />); });
};

const FORBIDDEN_IDENTITY = [/@/, /sign out/i, /log ?out/i, /account settings/i,
  /subscription/i, /billing/i, /cloud/i, /profile/i, /upgrade/i];

test('the header reads [current workspace title] + [avatar]; never mode or analyst as the title', async () => {
  await renderDashboard('Jordan');
  const header = await screen.findByTestId('app-header');
  const h1 = header.querySelector('h1.t-page');
  expect(h1).not.toBeNull();
  expect(h1.textContent).toBe('Dashboard');
  // the shell never renders the analyst name or mode outside the menu
  expect(header.textContent).toBe('Dashboard');
  // and no invented utility controls exist beside the avatar
  const buttons = within(header).getAllByRole('button');
  expect(buttons).toHaveLength(1);
  expect(buttons[0]).toHaveAccessibleName('Analyst menu');
});

test('the title follows the active workspace', async () => {
  await renderDashboard('Jordan');
  fireEvent.click(screen.getByTitle('Detections'));
  expect((await screen.findByTestId('app-header')).querySelector('h1').textContent).toBe('Detections');
  fireEvent.click(screen.getByTitle('Metrics'));
  expect(screen.getByTestId('app-header').querySelector('h1').textContent).toBe('Metrics');
});

test('the avatar opens a menu of existing real controls; Reset routes to the existing confirm modal', async () => {
  await renderDashboard('Jordan');
  const avatar = await screen.findByRole('button', { name: 'Analyst menu' });
  expect(avatar.className).toMatch(/w-8 h-8 rounded-full/);   // ~32px circular
  fireEvent.click(avatar);
  const menu = screen.getByRole('menu', { name: 'Analyst menu' });
  expect(within(menu).getByText('Local analyst')).toBeInTheDocument();
  await waitFor(() => expect(within(menu).getByText('Jordan')).toBeInTheDocument());
  expect(within(menu).getByText('Guided mode')).toBeInTheDocument();
  expect(within(menu).getByText('Documentation')).toBeInTheDocument();
  expect(within(menu).getByText('Back to home')).toBeInTheDocument();
  FORBIDDEN_IDENTITY.forEach((re) => expect(menu.textContent).not.toMatch(re));
  fireEvent.click(within(menu).getByRole('menuitem', { name: /Reset Simulation/ }));
  expect(await screen.findByText(/clear all events and incidents/)).toBeInTheDocument();
  const posts = apiFetch.mock.calls.filter(([, o]) => o && o.method === 'POST');
  expect(posts).toHaveLength(0);
});

test('Escape closes the labeled menu; no session keeps it honest with live destinations', async () => {
  await renderDashboard(null);
  const avatar = await screen.findByRole('button', { name: 'Analyst menu' });
  expect(avatar).toHaveAttribute('aria-haspopup', 'menu');
  fireEvent.click(avatar);
  const menu = screen.getByRole('menu', { name: 'Analyst menu' });
  expect(within(menu).getByText('No active session')).toBeInTheDocument();
  expect(within(menu).queryByText('Reset Simulation')).toBeNull();
  expect(within(menu).getByText('Documentation')).toBeInTheDocument();
  fireEvent.keyDown(document, { key: 'Escape' });
  await waitFor(() => expect(screen.queryByRole('menu', { name: 'Analyst menu' })).toBeNull());
  expect(avatar).toHaveAttribute('aria-expanded', 'false');
});
