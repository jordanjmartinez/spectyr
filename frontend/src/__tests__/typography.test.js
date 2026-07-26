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
import { PageHeader, SectionLabel } from '../components/ui';
import { SESSION_PERFORMANCE_LABEL } from '../components/uiCopy';

const css = fs.readFileSync(path.join(__dirname, '..', 'index.css'), 'utf8');

test('the ruled token scale is defined once, with the ruled values', () => {
  expect(css).toMatch(/\.t-page\s*{[^}]*font-size:\s*26px[^}]*font-weight:\s*650[^}]*line-height:\s*1\.2/);
  expect(css).toMatch(/\.t-section\s*{[^}]*font-size:\s*18px[^}]*font-weight:\s*600[^}]*line-height:\s*1\.3/);
  expect(css).toMatch(/\.t-card\s*{[^}]*font-size:\s*14px[^}]*font-weight:\s*600/);
  expect(css).toMatch(/\.t-body\s*{[^}]*font-size:\s*14px[^}]*font-weight:\s*400[^}]*line-height:\s*1\.5/);
  expect(css).toMatch(/\.t-nav\s*{[^}]*font-size:\s*14px[^}]*font-weight:\s*500/);
  expect(css).toMatch(/\.t-kpi\s*{[^}]*font-size:\s*28px[^}]*font-weight:\s*650[^}]*tabular-nums/);
  expect(css).toMatch(/\.t-meta\s*{[^}]*font-size:\s*12px[^}]*font-weight:\s*400/);
  // overline: 11/600, tracking <= 0.04em, and NO uppercase transform
  const overline = css.match(/\.t-overline\s*{[^}]*}/)[0];
  expect(overline).toMatch(/font-size:\s*11px/);
  expect(overline).toMatch(/font-weight:\s*600/);
  const tracking = parseFloat(overline.match(/letter-spacing:\s*([\d.]+)em/)[1]);
  expect(tracking).toBeLessThanOrEqual(0.04);
  expect(overline).toMatch(/text-transform:\s*none/);
  // Inter leads the product body stack; table heads drop broad uppercase
  expect(css).toMatch(/body\s*{[^}]*font-family:\s*'Inter'/);
  expect(css).toMatch(/\.dark-thead th\s*{[^}]*text-transform:\s*none/);
});

test('the shared primitives wear the tokens (every consumer inherits them)', () => {
  const { container } = render(
    <div>
      <PageHeader title="Endpoints" subtitle="x" />
      <SectionLabel>Severity distribution</SectionLabel>
    </div>,
  );
  expect(container.querySelector('h2.t-page')).not.toBeNull();
  expect(container.querySelector('p.t-overline')).not.toBeNull();
});

test('every primary workspace consumes the shared tokens (no page styles its own hierarchy)', () => {
  // Source-level proof: each workspace either renders the token classes
  // directly or through the shared primitives (PageHeader/SectionLabel/
  // WidgetLabel). A page with NEITHER has invented its own hierarchy.
  const comp = (f) => fs.readFileSync(path.join(__dirname, '..', 'components', f), 'utf8');
  const uses = (src) => /t-(page|section|card|kpi|overline|meta|nav)/.test(src)
    || /PageHeader|SectionLabel/.test(src);
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
