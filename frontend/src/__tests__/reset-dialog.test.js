/**
 * Stage 6 playtest fix: the Reset Simulation dialog can never trap the user.
 *
 * The reported hang: a stalled reset POST held the dialog on "Resetting..."
 * for 40s+ with Cancel disabled and the X / backdrop gated behind the busy
 * flag -- no recovery short of reloading. Pinned here:
 * - the dialog stays dismissible (Cancel) while the request is in flight,
 *   and dismissing aborts the attempt;
 * - the request is bounded: after RESET_TIMEOUT_MS the abort surfaces a
 *   visible error and the dialog is usable again (retry or cancel);
 * - a failed response surfaces the same error without closing the dialog;
 * - a successful reset still closes the dialog.
 */
import React from 'react';
import { render, screen, waitFor, act, fireEvent } from '@testing-library/react';
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

const baseRoute = (path) => {
  if (path === '/api/game-state') return ok({ analyst_name: 'A', game_mode: 'guided', injected_count: 0 });
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

beforeEach(() => {
  apiFetch.mockReset();
});
afterEach(() => {
  jest.useRealTimers();
});

// The rail Reset control also carries a "Reset" span; the dialog confirm is
// the BUTTON whose own text is "Reset".
const confirmButton = () =>
  screen.getAllByText(/^Reset$|^Resetting\.\.\.$/).find((el) => el.tagName === 'BUTTON');

const openDialog = async () => {
  await act(async () => {
    render(<Dashboard />);
  });
  await waitFor(() => screen.getByTitle('Reset Simulation'));
  fireEvent.click(screen.getByTitle('Reset Simulation'));
  await screen.findByRole('heading', { name: 'Reset Simulation' });
};

test('the dialog stays dismissible while a stalled reset is in flight', async () => {
  apiFetch.mockImplementation((path) => {
    if (path === '/api/reset-simulator') return new Promise(() => {}); // stalled forever
    return baseRoute(path);
  });
  await openDialog();
  fireEvent.click(confirmButton());
  await screen.findByText('Resetting...');
  fireEvent.click(screen.getByText('Cancel')); // never gated behind the busy flag
  await waitFor(() =>
    expect(screen.queryByRole('heading', { name: 'Reset Simulation' })).toBeNull());
});

test('a stalled reset times out into a visible error and a retryable dialog', async () => {
  apiFetch.mockImplementation((path, opts) => {
    if (path === '/api/reset-simulator') {
      return new Promise((resolve, reject) => {
        opts?.signal?.addEventListener('abort', () =>
          reject(new DOMException('Aborted', 'AbortError')));
      });
    }
    return baseRoute(path);
  });
  await openDialog();
  jest.useFakeTimers();
  fireEvent.click(confirmButton());
  await act(async () => {
    jest.advanceTimersByTime(10500); // past RESET_TIMEOUT_MS: the abort fires
  });
  jest.useRealTimers();
  const alert = await screen.findByRole('alert');
  expect(alert.textContent).toMatch(/did not complete/);
  expect(screen.queryByText('Resetting...')).toBeNull();
  expect(confirmButton().disabled).toBe(false); // retry is possible
  expect(screen.getByRole('heading', { name: 'Reset Simulation' })).toBeTruthy();
});

test('a failed reset surfaces the error without closing the dialog', async () => {
  apiFetch.mockImplementation((path) => {
    if (path === '/api/reset-simulator') {
      return Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({}) });
    }
    return baseRoute(path);
  });
  await openDialog();
  fireEvent.click(confirmButton());
  const alert = await screen.findByRole('alert');
  expect(alert.textContent).toMatch(/did not complete/);
  expect(screen.getByRole('heading', { name: 'Reset Simulation' })).toBeTruthy();
});

test('a successful reset closes the dialog', async () => {
  apiFetch.mockImplementation((path) => {
    if (path === '/api/reset-simulator') return ok({ message: 'Simulator reset.' });
    return baseRoute(path);
  });
  await openDialog();
  await act(async () => {
    fireEvent.click(confirmButton());
  });
  await waitFor(() =>
    expect(screen.queryByRole('heading', { name: 'Reset Simulation' })).toBeNull());
  expect(screen.queryByRole('alert')).toBeNull();
});
