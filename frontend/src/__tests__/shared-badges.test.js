/**
 * VD2 (visual correction section 2), reruled by VD8 (owner mid-run
 * identity correction): the shared incident identity system. ONE
 * dimension contract (BADGE_BASE: Inter, 12px, medium, identical
 * line-height / vertical padding / min-height / radius, ~22px tall)
 * across IncidentIdBadge (Inter by ruling, neutral surface, dark ink,
 * no severity color, no mono), SeverityBadge (the approved Detections
 * treatment: label + semantic tint + border + subtle bg + dot, never
 * color alone), and ModeBadge (Guided / Hardcore, neutral, never a
 * smaller tag). IncidentIdentityRow is the ONE canonical composition
 * and order: [INC id] [Severity] ([Mode]) then the title, wrapping
 * naturally. No page keeps a local variant.
 */
import React from 'react';
import fs from 'fs';
import path from 'path';
import { render, screen, within, act } from '@testing-library/react';
import {
  BADGE_BASE, IncidentIdBadge, SeverityBadge, ModeBadge, IncidentIdentityRow,
} from '../components/ui';
import IncidentDashboard from '../components/IncidentDashboard';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const SRC = path.join(__dirname, '..');
const read = (rel) => fs.readFileSync(path.join(SRC, rel), 'utf8');

// ---- the shared dimension contract ------------------------------------------

test('all three badge types share the ONE dimension contract (height, radius, type, centering)', () => {
  // the contract itself carries the ruled metrics
  expect(BADGE_BASE).toMatch(/inline-flex items-center/);   // vertically centered content
  expect(BADGE_BASE).toMatch(/rounded-full/);               // identical radius
  expect(BADGE_BASE).toMatch(/text-xs/);                    // 12px
  expect(BADGE_BASE).toMatch(/font-medium/);                // weight 500
  expect(BADGE_BASE).toMatch(/leading-4/);                  // identical line-height
  expect(BADGE_BASE).toMatch(/py-0\.5/);                    // identical vertical padding
  expect(BADGE_BASE).toMatch(/min-h-\[22px\]/);             // the ruled ~22-24px height
  render(
    <>
      <IncidentIdBadge id="INC-1598" />
      <SeverityBadge severity="Medium" />
      <ModeBadge mode="guided" />
    </>,
  );
  for (const id of ['incident-id-badge', 'severity-badge', 'mode-badge']) {
    const el = screen.getByTestId(id);
    // every badge wears the full contract -- identical metrics by construction
    BADGE_BASE.split(' ').forEach((cls) => expect([id, el.className.includes(cls)]).toEqual([id, true]));
    // and a border (real or transparent) so box heights match exactly
    expect([id, /border/.test(el.className)]).toEqual([id, true]);
  }
});

test('IncidentIdBadge: Inter by ruling -- neutral surface, dark readable ink, no mono, no severity color', () => {
  render(<IncidentIdBadge id="INC-1598" />);
  const b = screen.getByTestId('incident-id-badge');
  expect(b.textContent).toBe('INC-1598');
  expect(b.className).not.toMatch(/log-mono|font-mono/);         // Inter, not JetBrains Mono
  expect(b.className).toMatch(/bg-\[#eef1f4\]/);                 // neutral background
  expect(b.className).toMatch(/border-\[#d0d7de\]/);             // neutral border
  expect(b.className).toMatch(/text-\[#1a2332\]/);               // dark readable text
  expect(b.className).not.toMatch(/red|orange|amber|emerald|green|#16436b/);
});

test('SeverityBadge: the approved Detections treatment, case-insensitive, never color alone', () => {
  const { container, rerender } = render(<SeverityBadge severity="critical" />);
  const badge = () => screen.getByTestId('severity-badge');
  expect(badge().textContent).toBe('Critical');
  expect(badge().className).toMatch(/bg-red-50 text-red-700 border-red-200/);
  expect(container.querySelector('[data-testid="severity-badge"] > span')).not.toBeNull();  // dot
  const upper = render(<SeverityBadge severity="Critical" />);
  const both = screen.getAllByTestId('severity-badge');
  expect(both[1].outerHTML).toBe(both[0].outerHTML);             // one canonical form
  upper.unmount();
  for (const [level, cls] of [['High', 'orange'], ['Medium', 'amber'], ['Low', 'border-\\[#d0d7de\\]']]) {
    rerender(<SeverityBadge severity={level} />);
    expect(badge().textContent).toBe(level);
    expect(badge().className).toMatch(new RegExp(cls));
  }
});

test('ModeBadge: Guided and Hardcore share the identical badge, never a smaller tag', () => {
  const { rerender } = render(<ModeBadge mode="guided" />);
  const el = () => screen.getByTestId('mode-badge');
  expect(el().textContent).toBe('Guided');
  const guidedClasses = el().className;
  rerender(<ModeBadge mode="hardcore" />);
  expect(el().textContent).toBe('Hardcore');
  expect(el().className).toBe(guidedClasses);                    // byte-identical treatment
  expect(guidedClasses).not.toMatch(/text-\[1?0px\]|text-\[11px\]/);  // no shrunken tag type
});

// ---- the canonical composition and order ------------------------------------

test('IncidentIdentityRow renders the ONE canonical order: [INC] [Severity] [Mode] then title', () => {
  render(<IncidentIdentityRow incidentId="INC-1598" severity="Medium" mode="guided"
    title="Multiple Account Logon Failures" />);
  const row = screen.getByTestId('incident-pill');
  const kids = [...row.children];
  expect(kids[0].getAttribute('data-testid')).toBe('incident-id-badge');
  expect(kids[1].getAttribute('data-testid')).toBe('severity-badge');
  expect(kids[2].getAttribute('data-testid')).toBe('mode-badge');
  expect(kids[3].textContent).toBe('Multiple Account Logon Failures');
  // natural wrapping; the title never shrinks or clips to force one line
  expect(row.className).toMatch(/flex-wrap/);
  expect(kids[3].className).not.toMatch(/truncate|text-ellipsis|text-\[1?0px\]/);
});

test('every surface consumes the shared system; no page-local badge or plain-text INC variant remains', () => {
  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) return ['__tests__', 'fonts'].includes(e.name) ? [] : walk(p);
    return /\.(js|jsx)$/.test(e.name) ? [p] : [];
  });
  for (const p of walk(SRC)) {
    const rel = path.relative(SRC, p).replace(/\\/g, '/');
    const s = fs.readFileSync(p, 'utf8');
    if (rel !== 'components/ui.jsx') {
      // one tint map, one severity badge, one id badge -- defined once
      expect([rel, /SEVERITY_PILL\s*=/.test(s)]).toEqual([rel, false]);
      expect([rel, /const SeverityBadge\s*=/.test(s)]).toEqual([rel, false]);
      expect([rel, /const IncidentIdBadge\s*=/.test(s)]).toEqual([rel, false]);
      // no mono/accent plain-text incident id render survives anywhere
      expect([rel, /log-mono[^\n]{0,120}incident_id/.test(s)]).toEqual([rel, false]);
    }
  }
  // the migrated identity surfaces all reach the shared components
  for (const f of ['components/IncidentDashboard.jsx', 'components/Incidents.jsx']) {
    expect([f, /IncidentIdBadge/.test(read(f))]).toEqual([f, true]);
    expect([f, /SeverityBadge/.test(read(f))]).toEqual([f, true]);
  }
  expect(read('components/ui.jsx')).toMatch(/<IncidentIdentityRow \{\.\.\.incident\}/);
  // canonical order in the composed markup: severity NEVER precedes the
  // id badge at any site (the rendered-order tests above pin the rest)
  for (const f of ['components/IncidentDashboard.jsx', 'components/Incidents.jsx',
                   'components/ui.jsx']) {
    expect([f, /<SeverityBadge[^/]*\/>\s*\n?\s*<IncidentIdBadge/.test(read(f))]).toEqual([f, false]);
  }
});

test('severity dots without a label survive ONLY as chart fills, never as the sole severity display', () => {
  for (const f of ['components/Incidents.jsx', 'components/DifficultySelector.jsx']) {
    expect([f, /severityDot/.test(read(f))]).toEqual([f, false]);
  }
  const dash = read('components/IncidentDashboard.jsx');
  const uses = dash.match(/severityDot\(/g) || [];
  expect(uses.length).toBe(1);
  expect(dash).toMatch(/severityDot\(r\.key\)/);
});

// ---- the Active investigation card (canonical structure + fit) --------------

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

test('Active investigation: canonical structure with the shared badges, content intact, no clipping', async () => {
  mockDashboard();
  await act(async () => { render(<IncidentDashboard gameMode="guided" />); });
  const card = await screen.findByTestId('active-investigation');
  // the canonical metadata row [INC] [Severity] [Mode], wrapping
  const row = within(card).getByTestId('incident-id-badge').parentElement;
  expect([...row.children].map((el) => el.getAttribute('data-testid')))
    .toEqual(['incident-id-badge', 'severity-badge', 'mode-badge']);
  expect(row.className).toMatch(/flex-wrap/);
  expect(within(card).getByTestId('incident-id-badge').textContent).toBe('INC-1598');
  expect(within(card).getByTestId('severity-badge').textContent).toBe('Critical');
  expect(within(card).getByTestId('mode-badge').textContent).toBe('Guided');
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
