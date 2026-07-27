/**
 * VT (owner correction): the global typography system. Inter is the
 * primary product typeface; ONE shared token scale (t-page / t-section /
 * t-card / t-body / t-nav / t-kpi / t-meta / t-overline) is defined once
 * in index.css and consumed by every workspace; visible section labels
 * are sentence case; mono stays reserved for technical values; broad
 * uppercase + wide tracking are out of the overline path. Technical
 * identifiers (INC-####, T####.###) are never lowercased.
 */
import React from 'react';
import fs from 'fs';
import path from 'path';
import { render, screen } from '@testing-library/react';

jest.mock('react-router-dom', () => ({
  Link: ({ to, children, ...rest }) => {
    const R = require('react');
    return R.createElement('a', { href: typeof to === 'string' ? to : '#', ...rest }, children);
  },
}), { virtual: true });

const { PageHeader, SectionLabel } = require('../components/ui');
const AppHeader = require('../components/AppHeader').default;
const { SESSION_PERFORMANCE_LABEL } = require('../components/uiCopy');

const css = fs.readFileSync(path.join(__dirname, '..', 'index.css'), 'utf8');

test('the ruled token scale is defined once, with the ruled values', () => {
  expect(css).toMatch(/\.t-page\s*{[^}]*font-size:\s*26px[^}]*font-weight:\s*650[^}]*line-height:\s*1\.2/);
  expect(css).toMatch(/\.t-section\s*{[^}]*font-size:\s*18px[^}]*font-weight:\s*600[^}]*line-height:\s*1\.3/);
  expect(css).toMatch(/\.t-card\s*{[^}]*font-size:\s*14px[^}]*font-weight:\s*600/);
  expect(css).toMatch(/\.t-body\s*{[^}]*font-size:\s*14px[^}]*font-weight:\s*400[^}]*line-height:\s*1\.5/);
  expect(css).toMatch(/\.t-nav\s*{[^}]*font-size:\s*14px[^}]*font-weight:\s*500/);
  expect(css).toMatch(/\.t-kpi\s*{[^}]*font-size:\s*28px[^}]*font-weight:\s*650[^}]*tabular-nums/);
  expect(css).toMatch(/\.t-meta\s*{[^}]*font-size:\s*12px[^}]*font-weight:\s*400/);
  // VP16 (owner correction): micro-headings are 12px minimum, 600,
  // line-height 1.3, tracking <= 0.03em, and NO uppercase transform
  const overline = css.match(/\.t-overline\s*{[^}]*}/)[0];
  const size = parseFloat(overline.match(/font-size:\s*([\d.]+)px/)[1]);
  expect(size).toBeGreaterThanOrEqual(12);
  expect(overline).toMatch(/font-weight:\s*600/);
  expect(overline).toMatch(/line-height:\s*1\.3/);
  const tracking = parseFloat(overline.match(/letter-spacing:\s*([\d.]+)em/)[1]);
  expect(tracking).toBeLessThanOrEqual(0.03);
  expect(overline).toMatch(/text-transform:\s*none/);
  // the ordinary subsection title token
  expect(css).toMatch(/\.t-subsection\s*{[^}]*font-size:\s*14px[^}]*font-weight:\s*600/);
  // Inter leads the product body stack
  expect(css).toMatch(/body\s*{[^}]*font-family:\s*'Inter'/);
});

test('the shared primitives wear the tokens (every consumer inherits them)', () => {
  const { container } = render(
    <div>
      <AppHeader title="Endpoints" simActive={false} />
      <PageHeader title="Endpoints" subtitle="x" />
      <SectionLabel>Severity distribution</SectionLabel>
    </div>,
  );
  // VH: the WORKSPACE TITLE lives in the one AppHeader (t-page); the
  // page-identity card repeats no title (no stacked duplicates).
  expect(container.querySelector('h1.t-page')).not.toBeNull();
  expect(container.querySelectorAll('.t-page')).toHaveLength(1);
  expect(container.querySelector('p.t-overline')).not.toBeNull();
});

test('every primary workspace consumes the shared tokens (no page styles its own hierarchy)', () => {
  // Source-level proof: each workspace either renders the token classes
  // directly or through the shared primitives (PageHeader/SectionLabel/
  // WidgetLabel). A page with NEITHER has invented its own hierarchy.
  const comp = (f) => fs.readFileSync(path.join(__dirname, '..', 'components', f), 'utf8');
  const uses = (src) => /t-(page|section|card|kpi|overline|meta|nav|subsection)/.test(src)
    || /PageHeader|PageIntro|SectionLabel/.test(src);
  expect(uses(comp('IncidentDashboard.jsx'))).toBe(true);   // Dashboard
  expect(uses(comp('Incidents.jsx'))).toBe(true);           // Incidents
  expect(uses(comp('Siem.jsx'))).toBe(true);                // SIEM
  expect(uses(comp('Detections.jsx'))).toBe(true);          // Detections
  expect(uses(comp('Endpoints.jsx')) && uses(comp('EndpointDetail.jsx'))).toBe(true); // Endpoints
  expect(uses(comp('Response.jsx'))).toBe(true);            // Response
  expect(uses(comp('Analytics.jsx')) && uses(comp('ScoreSections.jsx'))
    && uses(comp('LearningReview.jsx'))).toBe(true);        // Metrics
});

test('ruled section labels are sentence case; technical identifiers stay technical', () => {
  // the ruled label set
  expect(SESSION_PERFORMANCE_LABEL).toBe('Session performance');
  const dash = fs.readFileSync(path.join(__dirname, '..', 'components', 'IncidentDashboard.jsx'), 'utf8');
  expect(dash).toContain('Active investigation');
  expect(dash).not.toContain('>Active Investigation<');
  expect(dash).toContain('Severity distribution');
  expect(dash).toContain('Environment status');
  expect(dash).toContain('Recent results');
  const radar = fs.readFileSync(path.join(__dirname, '..', 'components', 'AttackRadar.jsx'), 'utf8');
  expect(radar).toContain('ATT&amp;CK coverage');
  const scores = fs.readFileSync(path.join(__dirname, '..', 'components', 'ScoreSections.jsx'), 'utf8');
  expect(scores).toContain('Score summary');
  // technical identifiers are never humanized: the INC accent + technique
  // ids render verbatim in mono
  expect(dash).toMatch(/log-mono[^>]*>\{c\.incident_id\}|\{focus\.incident_id\}/);
});
