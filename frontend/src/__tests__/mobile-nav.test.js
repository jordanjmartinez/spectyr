/**
 * Stage 6 playtest fixes 5+6: the rail below the desktop breakpoints.
 *
 * - Collapsed rail alignment (fix 5): below lg the labels hide, so the nav
 *   buttons and the Docs link center their icons (justify-center
 *   lg:justify-start, px-2 lg:px-3) instead of hugging the left of the
 *   96px column (source guard, same style as brand-lockup).
 * - Mobile drawer (fix 6): below md the rail column is hidden and the
 *   header hamburger opens an off-canvas drawer with the same nav (one
 *   render source). Selecting a destination navigates AND closes it.
 * - The Hardcore timer mounts exactly ONCE either way: the rail instance
 *   on desktop, the header slot on mobile (never both, never zero).
 */
import React from 'react';
import fs from 'fs';
import path from 'path';
import { render, screen, act, fireEvent } from '@testing-library/react';
import Dashboard from '../pages/Dashboard';

jest.mock('react-router-dom', () => ({
  Link: ({ to, children, ...rest }) => {
    const R = require('react');
    return R.createElement('a', { href: typeof to === 'string' ? to : '#', ...rest }, children);
  },
}), { virtual: true });
jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const SRC = path.join(__dirname, '..');
const dashSrc = fs.readFileSync(path.join(SRC, 'pages', 'Dashboard.jsx'), 'utf8');

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
const route = (path_) => {
  if (path_ === '/api/game-state') {
    return ok({ analyst_name: 'A', game_mode: 'hardcore', timer_remaining: 900,
                timer_expired: false, timer_duration: 900, paused: false, injected_count: 0 });
  }
  if (path_ === '/api/incidents') {
    return ok({ active: [], completed: [], queue_length: 0, resolved_count: 0,
                stats: { severity_breakdown: {} } });
  }
  if (path_ === '/api/detections') return ok({ detections: [], counts: { open: 0, promoted: 0, dismissed: 0 } });
  if (path_ === '/api/endpoints') return ok({ org: {}, endpoints: [] });
  if (path_ === '/api/analytics/report_card') return ok({ state: 'in_progress', progress: { submitted: 0 } });
  if (path_ === '/api/actions') return ok({ actions: [] });
  return ok({});
};

// Query-aware viewport mock: the shell watches (max-width: 767px) for the
// drawer/timer split and (min-width: 1024px) for the sidebar pin.
// setMatchMedia(true) = phone; setMatchMedia(false) = lg+ desktop.
const setMatchMedia = (mobile, lg = !mobile) => {
  window.matchMedia = jest.fn().mockImplementation((query) => ({
    matches: query.includes('max-width') ? mobile : lg,
    media: query,
    addEventListener: jest.fn(), removeEventListener: jest.fn(),
    addListener: jest.fn(), removeListener: jest.fn(),
  }));
};

beforeEach(() => {
  apiFetch.mockReset();
  apiFetch.mockImplementation(route);
  window.localStorage.clear(); // the rail pin preference persists per browser
});
afterEach(() => {
  delete window.matchMedia;
});

const renderDashboard = async () => {
  let utils;
  await act(async () => { utils = render(<Dashboard />); });
  return utils;
};

test('fix 5 source guard: the collapsed rail centers its icons (one shared align source)', () => {
  // The owner sidebar redesign made expansion state-driven (pin + hover),
  // superseding the breakpoint variants, but the ruled fix holds: ONE
  // alignment source feeds every rail entry, and collapsed means centered.
  expect(dashSrc).toMatch(/const align = expanded \? 'justify-start' : 'justify-center'/);
  expect(dashSrc).toMatch(/const pad = expanded \? 'px-3' : 'px-2'/);
  expect(dashSrc).toMatch(/\$\{align\} gap-3 rounded-md \$\{pad\} py-2\.5/);
  // the rail column itself hides below md (fix 6's column half) and wears
  // the floating-panel treatment (rounded, inset, never edge-to-edge)
  expect(dashSrc).toMatch(/hidden md:block shrink-0/);
  expect(dashSrc).toMatch(/fixed left-3 top-3 bottom-3 z-30 rounded-2xl/);
});

test('fix 6: the hamburger opens the drawer, selecting a destination navigates and closes it', async () => {
  setMatchMedia(true); // mobile viewport
  await renderDashboard();
  // closed by default: one rail instance only
  expect(screen.getAllByTitle('Detections')).toHaveLength(1);
  fireEvent.click(screen.getByLabelText('Open navigation'));
  const both = screen.getAllByTitle('Detections');
  expect(both).toHaveLength(2); // rail + drawer (one render source)
  await act(async () => { fireEvent.click(both[1]); });
  // navigated...
  expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Detections');
  // ...and the drawer closed
  expect(screen.getAllByTitle('Detections')).toHaveLength(1);
});

test('the drawer backdrop dismisses without navigating', async () => {
  setMatchMedia(true);
  await renderDashboard();
  fireEvent.click(screen.getByLabelText('Open navigation'));
  expect(screen.getAllByTitle('Incidents')).toHaveLength(2);
  const overlay = screen.getAllByTitle('Incidents')[1].closest('.fixed');
  fireEvent.click(overlay.firstChild); // the backdrop layer
  expect(screen.getAllByTitle('Incidents')).toHaveLength(1);
  expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Dashboard');
});

test('owner redesign: collapse toggle, hover expansion, pin restore, and persistence', async () => {
  setMatchMedia(false); // lg+ desktop
  const { container } = await renderDashboard();
  const aside = container.querySelector('aside');
  const wordmark = () => container.querySelector('aside .brand-wordmark');
  const navButton = () => screen.getAllByTitle('Incidents')[0];

  // pinned default: expanded panel (slimmed w-60 per the owner follow-up),
  // full lockup, collapse control beside it
  expect(wordmark().className).not.toMatch(/\bhidden\b/);
  expect(aside.className).toMatch(/\bw-60\b/);

  // collapse -> icon-only rail: wordmark + labels hide, icons center,
  // the control leaves with the expanded header
  fireEvent.click(screen.getByLabelText('Collapse sidebar'));
  expect(wordmark().className).toMatch(/\bhidden\b/);
  expect(aside.className).toMatch(/\bw-24\b/);
  expect(navButton().className).toMatch(/\bjustify-center\b/);
  expect(screen.queryByLabelText('Collapse sidebar')).toBeNull();
  expect(window.localStorage.getItem('spectyr_rail_pinned')).toBe('0');

  // unpinned: hover expands OVER the content and offers the pin
  fireEvent.mouseEnter(aside);
  expect(wordmark().className).not.toMatch(/\bhidden\b/);
  expect(aside.className).toMatch(/\bw-60\b/);
  fireEvent.mouseLeave(aside);
  expect(wordmark().className).toMatch(/\bhidden\b/); // leaves -> collapses

  // pin restores the open panel and persists
  fireEvent.mouseEnter(aside);
  fireEvent.click(screen.getByLabelText('Pin sidebar open'));
  fireEvent.mouseLeave(aside);
  expect(wordmark().className).not.toMatch(/\bhidden\b/);
  expect(window.localStorage.getItem('spectyr_rail_pinned')).toBe('1');
});

test('the brand link is content-width so the collapse control sits beside the title', async () => {
  setMatchMedia(false);
  const { container } = await renderDashboard();
  const brandLink = container.querySelector('aside a[title="Back to Home"]');
  expect(brandLink.className).toMatch(/\bshrink-0\b/);
  expect(brandLink.className).not.toMatch(/\bflex-1\b|\bw-full\b/);
  // the control shares the brand row
  const row = brandLink.parentElement;
  expect(row.contains(screen.getByLabelText('Collapse sidebar'))).toBe(true);
});

test('the Hardcore timer mounts exactly once: header slot on mobile, rail slot on desktop', async () => {
  setMatchMedia(true);
  const mobile = await renderDashboard();
  expect(screen.getAllByText('15:00')).toHaveLength(1);
  mobile.unmount();

  setMatchMedia(false);
  await renderDashboard();
  expect(screen.getAllByText('15:00')).toHaveLength(1);
});
