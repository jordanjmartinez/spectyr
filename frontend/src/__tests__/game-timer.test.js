/**
 * Stage 6 playtest fix: the Hardcore failure overlay fires AT 0:00.
 *
 * The countdown is local: each poll only re-syncs a deadline, and a 250ms
 * tick drives the display and the one-shot onTimeout. Pinned here:
 * - onTimeout fires the moment the deadline passes even when every poll
 *   after the last sync is dropped (the reported bug: the overlay waited
 *   for the next interaction-driven read to deliver timer_expired);
 * - the server timer_expired flag is the backup trigger and fires once;
 * - a non-expired read (reset / fresh run) re-arms the trigger;
 * - a paused (frozen) server clock pins the display: no local drift, no fire;
 * - outside hardcore nothing renders and nothing fires.
 */
import React from 'react';
import { render, act } from '@testing-library/react';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');
const GameTimer = require('../components/GameTimer').default;

const state = (over = {}) => ({
  game_mode: 'hardcore',
  timer_remaining: 3,
  timer_expired: false,
  timer_duration: 900,
  elapsed: 897,
  paused: false,
  analyst_name: 'tester',
  ...over,
});
const ok = (data) => Promise.resolve({ json: () => Promise.resolve(data) });
const never = () => new Promise(() => {});

beforeEach(() => {
  jest.useFakeTimers();
  apiFetch.mockReset();
});
afterEach(() => {
  jest.useRealTimers();
});

const flush = async (ms = 0) => {
  await act(async () => {
    if (ms) jest.advanceTimersByTime(ms);
  });
};

test('onTimeout fires at 0:00 from the local countdown even when polls stop', async () => {
  const onTimeout = jest.fn();
  apiFetch
    .mockImplementationOnce(() => ok(state({ timer_remaining: 2 })))
    .mockImplementation(never); // every later poll is dropped
  const { container } = render(<GameTimer onTimeout={onTimeout} disabled={false} />);
  await flush(); // initial sync: 2s remaining
  await flush(1000);
  expect(onTimeout).not.toHaveBeenCalled();
  await flush(1250); // the local tick crosses the deadline
  expect(onTimeout).toHaveBeenCalledTimes(1);
  expect(container.querySelector('.log-mono').textContent).toBe('0:00');
  await flush(2000); // one shot: no re-fire without a server re-arm
  expect(onTimeout).toHaveBeenCalledTimes(1);
});

test('the server timer_expired flag is the backup trigger and fires once', async () => {
  const onTimeout = jest.fn();
  apiFetch.mockImplementation(() =>
    ok(state({ timer_remaining: 0, timer_expired: true })));
  render(<GameTimer onTimeout={onTimeout} disabled={false} />);
  await flush();
  expect(onTimeout).toHaveBeenCalledTimes(1);
  await flush(3000); // repeated expired reads + local ticks never re-fire
  expect(onTimeout).toHaveBeenCalledTimes(1);
});

test('a non-expired read re-arms the trigger for the next run', async () => {
  const onTimeout = jest.fn();
  apiFetch.mockImplementation(() =>
    ok(state({ timer_remaining: 0, timer_expired: true })));
  render(<GameTimer onTimeout={onTimeout} disabled={false} />);
  await flush();
  expect(onTimeout).toHaveBeenCalledTimes(1);
  // the reset lands: no timer in the lobby state
  apiFetch.mockImplementation(() =>
    ok(state({ game_mode: 'training', timer_remaining: null,
               timer_expired: false, elapsed: null })));
  await flush(1000);
  // a fresh hardcore run expires again
  apiFetch.mockImplementation(() =>
    ok(state({ timer_remaining: 0, timer_expired: true })));
  await flush(1000);
  expect(onTimeout).toHaveBeenCalledTimes(2);
});

test('a paused (frozen) server clock pins the display and never fires', async () => {
  const onTimeout = jest.fn();
  apiFetch.mockImplementation(() =>
    ok(state({ timer_remaining: 62, paused: true })));
  const { container } = render(<GameTimer onTimeout={onTimeout} disabled={false} />);
  await flush();
  expect(container.querySelector('.log-mono').textContent).toBe('1:02');
  await flush(5000);
  expect(container.querySelector('.log-mono').textContent).toBe('1:02');
  expect(onTimeout).not.toHaveBeenCalled();
});

test('a stale out-of-order poll response can never fire the trigger', async () => {
  // Retry hazard: a slow poll issued against the dead run (expired) resolves
  // AFTER the retried run already started. It must be dropped, not fire the
  // overlay (which would halt the fresh run via /api/game-timeout).
  const onTimeout = jest.fn();
  let resolveStale;
  apiFetch
    .mockImplementationOnce(() => new Promise((resolve) => { resolveStale = resolve; }))
    .mockImplementation(() => ok(state({ timer_remaining: 900 })));
  const { container } = render(<GameTimer onTimeout={onTimeout} disabled={false} />);
  await flush();     // poll 1 hangs (issued against the dead run)
  await flush(1000); // poll 2 lands: the fresh run, 15:00
  expect(container.querySelector('.log-mono').textContent).toBe('15:00');
  await act(async () => {
    resolveStale({
      json: () => Promise.resolve(state({ timer_remaining: 0, timer_expired: true })),
    });
  });
  await flush(500);
  expect(onTimeout).not.toHaveBeenCalled();
  expect(container.querySelector('.log-mono').textContent).not.toBe('0:00');
});

test('outside hardcore nothing renders and nothing fires', async () => {
  const onTimeout = jest.fn();
  apiFetch.mockImplementation(() =>
    ok(state({ game_mode: 'guided', timer_remaining: null, elapsed: 42 })));
  const { container } = render(<GameTimer onTimeout={onTimeout} disabled={false} />);
  await flush(2000);
  expect(container.firstChild).toBeNull();
  expect(onTimeout).not.toHaveBeenCalled();
});
