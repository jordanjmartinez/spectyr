/**
 * Visual pass V3: the compact top utility region + the Spectyr ghost
 * avatar. The avatar is NOT a dead control: it opens a menu of existing
 * real controls only (Reset Simulation -> the existing confirm modal,
 * Documentation, Back to home). Nothing is invented: no user name beyond
 * the real analyst-entered one, no email, no account/subscription/cloud
 * sync/logout vocabulary anywhere in the region.
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
  if (path === '/api/analytics/attack_coverage') return ok({ tactics: [] });
  if (path === '/api/actions') return ok({ actions: [] });
  return ok({});
};

const renderDashboard = async (analyst = 'Jordan') => {
  apiFetch.mockReset();
  apiFetch.mockImplementation(route(analyst));
  await act(async () => { render(<Dashboard />); });
};

const FORBIDDEN_IDENTITY = [/@/, /sign out/i, /log ?out/i, /account settings/i,
  /subscription/i, /billing/i, /cloud sync/i, /profile/i, /upgrade/i];

test('the utility region shows the REAL session identity (mode + analyst name)', async () => {
  await renderDashboard('Jordan');
  const bar = await screen.findByTestId('utility-bar');
  await waitFor(() => expect(bar.textContent).toContain('Jordan'));
  expect(bar.textContent).toContain('Guided');
  FORBIDDEN_IDENTITY.forEach((re) => expect(bar.textContent).not.toMatch(re));
});

test('the avatar opens a menu of existing real controls; Reset routes to the existing confirm modal', async () => {
  await renderDashboard('Jordan');
  const avatar = await screen.findByRole('button', { name: 'Analyst menu' });
  await waitFor(() => expect(screen.getByTestId('utility-bar').textContent).toContain('Jordan'));
  fireEvent.click(avatar);
  const menu = screen.getByRole('menu', { name: 'Analyst menu' });
  expect(within(menu).getByText('Local analyst')).toBeInTheDocument();
  expect(within(menu).getByText('Jordan')).toBeInTheDocument();
  expect(within(menu).getByText('Guided mode')).toBeInTheDocument();
  expect(within(menu).getByText('Documentation')).toBeInTheDocument();
  expect(within(menu).getByText('Back to home')).toBeInTheDocument();
  FORBIDDEN_IDENTITY.forEach((re) => expect(menu.textContent).not.toMatch(re));
  // Reset is the EXISTING control: it opens the existing confirm modal
  fireEvent.click(within(menu).getByRole('menuitem', { name: /Reset Simulation/ }));
  expect(await screen.findByText(/clear all events and incidents/)).toBeInTheDocument();
  // and no state-changing request fired from opening things
  const posts = apiFetch.mock.calls.filter(([, o]) => o && o.method === 'POST');
  expect(posts).toHaveLength(0);
});

test('the avatar menu closes on Escape and is labeled (never a dead control)', async () => {
  await renderDashboard('Jordan');
  const avatar = await screen.findByRole('button', { name: 'Analyst menu' });
  expect(avatar).toHaveAttribute('aria-haspopup', 'menu');
  fireEvent.click(avatar);
  expect(avatar).toHaveAttribute('aria-expanded', 'true');
  fireEvent.keyDown(document, { key: 'Escape' });
  await waitFor(() => expect(screen.queryByRole('menu', { name: 'Analyst menu' })).toBeNull());
  expect(avatar).toHaveAttribute('aria-expanded', 'false');
});

test('with no active session the region is honest and the menu still has real destinations', async () => {
  await renderDashboard(null);
  const bar = await screen.findByTestId('utility-bar');
  await waitFor(() => expect(bar.textContent).toContain('No active session'));
  fireEvent.click(screen.getByRole('button', { name: 'Analyst menu' }));
  const menu = screen.getByRole('menu', { name: 'Analyst menu' });
  // no Reset without a session; the two navigation destinations remain
  expect(within(menu).queryByText('Reset Simulation')).toBeNull();
  expect(within(menu).getByText('Documentation')).toBeInTheDocument();
  expect(within(menu).getByText('Back to home')).toBeInTheDocument();
});
