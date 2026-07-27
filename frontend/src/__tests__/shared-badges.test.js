/**
 * VD2 (visual-consistency correction, section 2): the shared identity
 * badges. ONE IncidentIdPill (JetBrains Mono, compact, neutral bg +
 * border, the INC accent ink, never a severity color), ONE SeverityBadge
 * (the approved Detections treatment: direct label + restrained semantic
 * tint + border + subtle background + status dot, never color alone),
 * ONE ModeBadge (Guided / Hardcore) -- defined once in ui.jsx and
 * consumed everywhere a severity or incident-context badge renders. The
 * Active investigation card composes them as a wrapping metadata row
 * with no clipping and no compressed type.
 */
import React from 'react';
import fs from 'fs';
import path from 'path';
import { render, screen, within, act } from '@testing-library/react';
import { IncidentIdPill, SeverityBadge, ModeBadge, IncidentPill } from '../components/ui';
import IncidentDashboard from '../components/IncidentDashboard';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const SRC = path.join(__dirname, '..');
const read = (rel) => fs.readFileSync(path.join(SRC, rel), 'utf8');

// ---- the primitives ---------------------------------------------------------

test('IncidentIdPill: mono, compact, neutral surface, accent ink, no severity color', () => {
  render(<IncidentIdPill id="INC-1598" />);
  const pill = screen.getByTestId('incident-id-pill');
  expect(pill.textContent).toBe('INC-1598');
  expect(pill.className).toMatch(/log-mono/);                    // JetBrains Mono token
  expect(pill.className).toMatch(/text-xs/);                     // compact height
  expect(pill.className).toMatch(/px-2 py-0\.5/);                // consistent padding
  expect(pill.className).toMatch(/bg-\[#eef1f4\]/);              // neutral background
  expect(pill.className).toMatch(/border-\[#d0d7de\]/);          // neutral border
  // the ink is the app accent; NEVER a severity tint
  expect(pill.className).toMatch(/text-\[#16436b\]/);
  expect(pill.className).not.toMatch(/red|orange|amber|emerald|green/);
});

test('SeverityBadge: the approved Detections treatment, case-insensitive, never color alone', () => {
  const { container, rerender } = render(<SeverityBadge severity="critical" />);
  const badge = () => screen.getByTestId('severity-badge');
  // direct label (color never carries the meaning alone)
  expect(badge().textContent).toBe('Critical');
  // border + subtle background + the status dot
  expect(badge().className).toMatch(/border/);
  expect(badge().className).toMatch(/bg-red-50 text-red-700 border-red-200/);
  expect(container.querySelector('[data-testid="severity-badge"] > span')).not.toBeNull();
  // 'Critical' and 'critical' render byte-identically (one canonical form)
  const upper = render(<SeverityBadge severity="Critical" />);
  const both = screen.getAllByTestId('severity-badge');
  expect(both[1].outerHTML).toBe(both[0].outerHTML);
  upper.unmount();
  // the four canonical levels each carry their ruled tint
  for (const [level, cls] of [['High', 'orange'], ['Medium', 'amber'], ['Low', 'border-\\[#d0d7de\\]']]) {
    rerender(<SeverityBadge severity={level} />);
    expect(badge().textContent).toBe(level);
    expect(badge().className).toMatch(new RegExp(cls));
  }
});

test('ModeBadge: the compact shared mode chip for Guided and Hardcore', () => {
  const { rerender } = render(<ModeBadge mode="guided" />);
  expect(screen.getByTestId('mode-badge').textContent).toBe('Guided');
  rerender(<ModeBadge mode="hardcore" />);
  expect(screen.getByTestId('mode-badge').textContent).toBe('Hardcore');
});

test('the incident-context pill is composed FROM the shared badges', () => {
  render(<IncidentPill incidentId="INC-8340" title="T" severity="High" mode="guided" />);
  const pill = screen.getByTestId('incident-pill');
  expect(within(pill).getByTestId('incident-id-pill').textContent).toBe('INC-8340');
  expect(within(pill).getByTestId('severity-badge').textContent).toBe('High');
  expect(within(pill).getByTestId('mode-badge').textContent).toBe('Guided');
});

// ---- one definition, consumed everywhere ------------------------------------

test('no page defines its own severity badge or tint map (solve it once)', () => {
  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) return ['__tests__', 'fonts'].includes(e.name) ? [] : walk(p);
    return /\.(js|jsx)$/.test(e.name) ? [p] : [];
  });
  for (const p of walk(SRC)) {
    const rel = path.relative(SRC, p).replace(/\\/g, '/');
    const s = fs.readFileSync(p, 'utf8');
    // the tint map lives in ui.jsx alone
    if (rel !== 'components/ui.jsx') {
      expect([rel, /SEVERITY_PILL\s*=/.test(s)]).toEqual([rel, false]);
      expect([rel, /const SeverityBadge\s*=/.test(s)]).toEqual([rel, false]);
    }
  }
  // the retired legacy pill component is referenced only by the hidden
  // Reports surface (not player-reachable), never by a live workspace
  for (const f of ['components/Detections.jsx', 'components/DetectionDetail.jsx',
                   'components/Incidents.jsx', 'components/IncidentDashboard.jsx',
                   'components/DifficultySelector.jsx']) {
    expect([f, /from '\.\/SeverityPill'/.test(read(f))]).toEqual([f, false]);
    expect([f, /SeverityBadge/.test(read(f))]).toEqual([f, true]);
  }
});

test('severity dots without a label survive ONLY as chart fills, never as the sole severity display', () => {
  // after VD2 the raw dot palette feeds the severity-distribution bar
  // fills (label + count text beside every bar) and the badge itself;
  // no workspace renders a bare dot + plain-text severity pair anymore
  for (const f of ['components/Incidents.jsx', 'components/DifficultySelector.jsx']) {
    expect([f, /severityDot/.test(read(f))]).toEqual([f, false]);
  }
  const dash = read('components/IncidentDashboard.jsx');
  // the one remaining severityDot use is the severity-distribution fill
  const uses = dash.match(/severityDot\(/g) || [];
  expect(uses.length).toBe(1);
  expect(dash).toMatch(/severityDot\(r\.key\)/);
});

// ---- the Active investigation card (fit + wrapping metadata) ----------------

const CARD_INCIDENT = {
  incident_id: 'INC-1598', title: 'Suspicious Sign-in Burst From Unfamiliar Network Range',
  severity: 'Critical', state: 'in_progress', sealed: true, ready: false,
  open_detections: 2, triage: { total: 4, triaged: 2 }, related_actions: 1,
};

const mockDashboard = () => {
  apiFetch.mockReset();
  apiFetch.mockImplementation((p) => {
    const ok = (b) => Promise.resolve({ ok: true, json: () => Promise.resolve(b) });
    if (p === '/api/incidents') {
      return ok({ queue_length: 0, resolved_count: 0, completed: [], active: [CARD_INCIDENT] });
    }
    if (p === '/api/detections') return ok({ detections: [], counts: {} });
    if (p === '/api/endpoints') return ok({ endpoints: [] });
    if (p === '/api/actions') return ok({ actions: [] });
    if (p === '/api/analytics/report_card') return ok({ state: 'in_progress', progress: {} });
    if (String(p).includes('/scope')) {
      return ok({ incident_id: 'INC-1598', sealed: true, hosts: [], accounts: [], detection_ids: [] });
    }
    if (String(p).startsWith('/api/events/query')) {
      return ok({ count: 0, rows: [], identity: { cutoff_seq: 1 } });
    }
    return ok({});
  });
};

test('Active investigation: wrapping metadata row of the three shared badges, content intact', async () => {
  mockDashboard();
  await act(async () => { render(<IncidentDashboard gameMode="guided" />); });
  const card = await screen.findByTestId('active-investigation');
  // the metadata row is [INC pill] [Severity badge] [Mode badge], wrapping
  expect(within(card).getByTestId('incident-id-pill').textContent).toBe('INC-1598');
  expect(within(card).getByTestId('severity-badge').textContent).toBe('Critical');
  expect(within(card).getByTestId('mode-badge').textContent).toBe('Guided');
  const row = within(card).getByTestId('incident-id-pill').parentElement;
  expect(row.className).toMatch(/flex-wrap/);
  // the long title renders in full -- no truncation, no compressed type
  const title = within(card).getByText(CARD_INCIDENT.title);
  expect(title.className).not.toMatch(/truncate|text-\[1?0px\]/);
  // the incident facts remain: progress, triage line, classification
  // state, response actions, readiness, Resume
  expect(within(card).getByRole('progressbar')).toBeInTheDocument();
  expect(within(card).getByText('Detections reviewed: 2 of 4')).toBeInTheDocument();
  expect(within(card).getByText('Classification: not selected')).toBeInTheDocument();
  expect(within(card).getByText('Response actions taken: 1')).toBeInTheDocument();
  expect(within(card).getByRole('button', { name: 'Resume investigation' })).toBeInTheDocument();
});
