/**
 * Visual pass V2: the one icon system. Navigation identities are the
 * ruled lucide mapping (every destination DISTINCT -- the old rail shared
 * one triangle between Incidents and Detections); icons stay decorative
 * with the accessible name on the control; the platform/device mapping
 * follows the ACTUAL serialized fields and never guesses a brand
 * (PAN-OS-style network devices get no badge).
 */
import React from 'react';
import { render, screen, waitFor, act } from '@testing-library/react';
import {
  LayoutDashboard, AlertTriangle, ScanSearch, Crosshair, Monitor, ShieldCheck,
  LineChart,
} from 'lucide-react';
import {
  NAV_ICONS, platformFor, PlatformBadge, DeviceGlyph, HostIdentity,
} from '../components/icons';

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
const route = (path) => {
  if (path === '/api/game-state') return ok({ analyst_name: 'A', game_mode: 'guided', injected_count: 0 });
  if (path === '/api/incidents') return ok({ active: [], completed: [], queue_length: 0, resolved_count: 0 });
  if (path === '/api/detections') return ok({ detections: [], counts: { open: 0 } });
  if (path === '/api/endpoints') return ok({ org: {}, endpoints: [] });
  if (path === '/api/analytics/report_card') return ok({ state: 'in_progress', progress: {} });
  if (path === '/api/analytics/action_history') return ok([]);
  if (path === '/api/analytics/attack_coverage') return ok({ tactics: [] });
  if (path === '/api/actions') return ok({ actions: [] });
  return ok({});
};
beforeEach(() => { apiFetch.mockReset(); apiFetch.mockImplementation(route); });

// ---- the ruled navigation identity map -------------------------------------

test('the navigation identity map is the ruled lucide mapping', () => {
  expect(NAV_ICONS.dashboard).toBe(LayoutDashboard);
  // VP16 (owner correction): Incidents returns to the caution/alert triangle
  expect(NAV_ICONS.incidents).toBe(AlertTriangle);
  expect(NAV_ICONS.siem).toBe(ScanSearch);
  expect(NAV_ICONS.detections).toBe(Crosshair);
  expect(NAV_ICONS.endpoints).toBe(Monitor);
  expect(NAV_ICONS.response).toBe(ShieldCheck);
  expect(NAV_ICONS.analytics).toBe(LineChart);
});

test('every primary destination has a DISTINCT icon (no shared identities)', () => {
  const icons = Object.values(NAV_ICONS);
  expect(new Set(icons).size).toBe(icons.length);
});

test('nav entries keep their accessible names; icons are decorative; no emoji', async () => {
  await act(async () => { render(<Dashboard />); });
  await waitFor(() => expect(screen.getByTitle('Dashboard')).toBeInTheDocument());
  const emoji = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u;
  for (const label of ['Dashboard', 'Incidents', 'SIEM', 'Detections', 'Endpoints', 'Response', 'Metrics']) {
    const btn = screen.getByTitle(label);
    expect(btn.textContent).toBe(label);               // the visible accessible name
    expect(btn.textContent).not.toMatch(emoji);
    const svg = btn.querySelector('svg');
    expect(svg).not.toBeNull();
    expect(svg.getAttribute('aria-hidden')).toBe('true');  // decorative
  }
  // the old defect class: Incidents and Detections rendered the same path
  const inc = screen.getByTitle('Incidents').querySelector('svg').innerHTML;
  const det = screen.getByTitle('Detections').querySelector('svg').innerHTML;
  expect(inc).not.toBe(det);
});

// ---- the platform / device mapping -----------------------------------------

test('platformFor maps the real serialized fields, never guessing a brand', () => {
  // the two real managed shapes in the corpus
  expect(platformFor({ platform: 'windows', os: 'Windows Server 2022', role: 'dc' }))
    .toEqual({ platformKey: 'windows', deviceKind: 'server' });
  expect(platformFor({ platform: 'windows', os: 'Windows 11 Pro', role: 'workstation' }))
    .toEqual({ platformKey: 'windows', deviceKind: 'workstation' });
  // future-platform fixtures (no corpus host carries these today)
  expect(platformFor({ platform: 'macos', os: 'macOS 14' }).platformKey).toBe('macos');
  expect(platformFor({ platform: 'linux', os: 'Ubuntu 22.04 LTS' }).platformKey).toBe('linux');
  expect(platformFor({ os: 'Ubuntu 22.04 LTS' }).platformKey).toBe('linux');
  // the REAL unknown in this environment: the PAN-OS appliance (log
  // source, not a managed endpoint) -- and Apple hardware-lookalikes must
  // NOT become macOS without the platform field saying so
  expect(platformFor({ os: 'PAN-OS 11.0' })).toEqual({ platformKey: 'unknown', deviceKind: 'unknown' });
  expect(platformFor({})).toEqual({ platformKey: 'unknown', deviceKind: 'unknown' });
});

test('platform badges carry accessible labels; unknown renders NO badge', () => {
  const win = render(<PlatformBadge platformKey="windows" />);
  expect(win.getByRole('img', { name: 'Windows' })).toBeInTheDocument();
  win.unmount();
  const mac = render(<PlatformBadge platformKey="macos" />);
  expect(mac.getByRole('img', { name: 'macOS' })).toBeInTheDocument();
  mac.unmount();
  const lin = render(<PlatformBadge platformKey="linux" />);
  expect(lin.getByRole('img', { name: 'Linux' })).toBeInTheDocument();
  lin.unmount();
  const none = render(<PlatformBadge platformKey="unknown" />);
  expect(none.container.querySelector('svg')).toBeNull();
  expect(none.queryByRole('img')).toBeNull();
});

test('device glyphs are decorative and distinct between server and workstation', () => {
  const srv = render(<DeviceGlyph deviceKind="server" />);
  const srvHtml = srv.container.querySelector('svg').innerHTML;
  expect(srv.container.querySelector('svg').getAttribute('aria-hidden')).toBe('true');
  srv.unmount();
  const ws = render(<DeviceGlyph deviceKind="workstation" />);
  expect(ws.container.querySelector('svg').innerHTML).not.toBe(srvHtml);
});

test('HostIdentity composes the same mapping (server + Windows badge from real fields)', () => {
  const { container, getByRole } = render(
    <HostIdentity platform="windows" os="Windows Server 2022" role="file" />,
  );
  expect(getByRole('img', { name: 'Windows' })).toBeInTheDocument();
  // two marks: the decorative device glyph + the labeled platform badge
  expect(container.querySelectorAll('svg').length).toBe(2);
});
