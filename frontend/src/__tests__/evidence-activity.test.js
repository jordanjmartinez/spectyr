/**
 * VB1 (amendment section 2) + VD7 (owner mid-run instruction): Evidence
 * activity as the compact ROLLING EVENT-DENSITY chart. Deterministic,
 * exact rolling-window counts over the ACTIVE incident's observable
 * event timestamps at evenly spaced sample points; exact event-time
 * ticks; the honest sparse state below three distinct event times;
 * frozen-snapshot honesty (later evidence is announced, never merged
 * automatically); truthful loading and empty states; and a complete
 * textual equivalent. Volume only -- never suspiciousness, correctness,
 * or answer-key data.
 */
import React from 'react';
import fs from 'fs';
import path from 'path';
import { render, screen, fireEvent, waitFor, within, act } from '@testing-library/react';
import EvidenceActivity, { NO_INCIDENT, NO_EVENTS } from '../components/EvidenceActivity';
import {
  rollingDensity, chooseWindowSeconds, steppedPath, tickColumnPct, clampPct,
  SAMPLE_POINTS, SPARSE_MESSAGE,
} from '../components/evidenceDensity';
import IncidentDashboard from '../components/IncidentDashboard';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const at = (isoMinute, seconds = 0) => `2026-07-26T${isoMinute}:${String(seconds).padStart(2, '0')}Z`;
const rows = (...stamps) => stamps.map((t, i) => ({ id: `e${i}`, timestamp: t }));

// the worked example: 6 events across 175s (05, 40, 61, 62, 63, 180
// seconds after 19:45:00), so the 30s short-investigation window applies
const SIX = rows(at('19:45', 5), at('19:45', 40), at('19:46', 1), at('19:46', 2),
                 at('19:46', 3), at('19:48', 0));

// ---- the rolling window ----------------------------------------------------

test('the rolling window is deterministic: 30s short, 60s ordinary, ladder beyond', () => {
  expect(chooseWindowSeconds(0)).toBe(30);
  expect(chooseWindowSeconds(175)).toBe(30);         // a typical chain span
  expect(chooseWindowSeconds(300)).toBe(30);
  expect(chooseWindowSeconds(301)).toBe(60);
  expect(chooseWindowSeconds(1800)).toBe(60);
  // longer investigations step a fixed ladder keyed to sample spacing
  expect(chooseWindowSeconds(1801)).toBe(120);
  expect(chooseWindowSeconds(3600)).toBe(300);
  expect(chooseWindowSeconds(7200)).toBe(600);
  expect(chooseWindowSeconds(10 * 3600)).toBe(3600);
  expect(chooseWindowSeconds(24 * 3600)).toBe(2 * 3600);  // still deterministic past the ladder
  // pure function: identical input, identical output
  expect(chooseWindowSeconds(1234)).toBe(chooseWindowSeconds(1234));
});

test('rolling-window counts are EXACT over real events; nothing fabricated or redistributed', () => {
  const m = rollingDensity(SIX);
  expect(m.sparse).toBe(false);
  expect(m.total).toBe(6);
  expect(m.windowSeconds).toBe(30);
  expect(m.samples).toHaveLength(SAMPLE_POINTS);
  // every sample count equals the definition: events in (t - W, t]
  const stamps = SIX.map((r) => Date.parse(r.timestamp));
  for (const s of m.samples) {
    const brute = stamps.filter((x) => x > s.t - 30000 && x <= s.t).length;
    expect(s.count).toBe(brute);
  }
  // hand-checked values (independent of the implementation)
  expect(m.samples[0].count).toBe(1);     // (…, first]: the first event alone
  expect(m.samples[7].count).toBe(4);     // covers 40 + the 61/62/63 burst
  expect(m.samples[19].count).toBe(1);    // (150s, 180s]: the last event alone
  // the peak is exact and single
  expect(m.peak.count).toBe(4);
  expect(m.samples.filter((s) => s.isPeak)).toHaveLength(1);
  expect(m.samples[m.peak.index].count).toBe(4);
});

test('sampling points are deterministic and evenly spaced across the visible range', () => {
  const m = rollingDensity(SIX);
  const first = Date.parse(SIX[0].timestamp);
  const last = Date.parse(SIX[5].timestamp);
  const span = last - first;
  m.samples.forEach((s, i) => {
    expect(s.t).toBe(first + (i * span) / (SAMPLE_POINTS - 1));
  });
  expect(m.samples[0].t).toBe(first);
  expect(m.samples[SAMPLE_POINTS - 1].t).toBe(last);
  // identical rows give byte-identical models (frozen-snapshot stability)
  expect(rollingDensity(SIX)).toEqual(m);
});

test('peak ties resolve to the EARLIEST sample (deterministic)', () => {
  // two symmetric bursts of equal density
  const m = rollingDensity(rows(
    at('10:00', 0), at('10:00', 1), at('10:00', 2),
    at('10:04', 0), at('10:04', 1), at('10:04', 2),
  ));
  expect(m.samples.filter((s) => s.isPeak)).toHaveLength(1);
  const firstMax = m.samples.findIndex((s) => s.count === m.peak.count);
  expect(m.peak.index).toBe(firstMax);
});

test('event ticks match the source timestamps exactly (nothing invented, moved, or dropped)', () => {
  const m = rollingDensity(SIX);
  const stamps = SIX.map((r) => Date.parse(r.timestamp)).sort((a, b) => a - b);
  expect(m.ticks.map((tk) => tk.t)).toEqual(stamps);
  const first = stamps[0];
  const span = stamps[stamps.length - 1] - first;
  m.ticks.forEach((tk) => expect(tk.x).toBe((tk.t - first) / span));
});

test('malformed or missing timestamps are ignored, never invented', () => {
  const m = rollingDensity([
    { id: 'a', timestamp: at('08:00') },
    { id: 'b' },
    { id: 'c', timestamp: 'not-a-time' },
    { id: 'd', timestamp: null },
  ]);
  expect(m.total).toBe(1);
  expect(m.sparse).toBe(true);            // one distinct time cannot shape density
  expect(rollingDensity([]).total).toBe(0);
  expect(rollingDensity(null).samples).toEqual([]);
});

test('the sparse fallback engages below three DISTINCT event times', () => {
  // two events -> sparse
  expect(rollingDensity(rows(at('09:00'), at('09:05'))).sparse).toBe(true);
  // three events at only two distinct times -> still sparse
  const twoDistinct = rollingDensity(rows(at('09:00'), at('09:00'), at('09:05')));
  expect(twoDistinct.sparse).toBe(true);
  expect(twoDistinct.total).toBe(3);
  expect(twoDistinct.ticks).toHaveLength(3);
  // three distinct times -> a real density shape
  expect(rollingDensity(rows(at('09:00'), at('09:02'), at('09:05'))).sparse).toBe(false);
});

// ---- the stepped outline ----------------------------------------------------

test('the stepped outline is exact per sample: no curves, no interpolation, zeros on the baseline', () => {
  const m = rollingDensity(SIX);
  const { tops, outline, area } = steppedPath(m.samples);
  expect(tops).toHaveLength(m.samples.length);
  const max = Math.max(...m.samples.map((s) => s.count));
  m.samples.forEach((s, i) => {
    expect([tops[i].x0, tops[i].x1]).toEqual([i, i + 1]);
    expect(tops[i].y).toBe(100 - (s.count / max) * 100);
    if (s.count === 0) expect(tops[i].y).toBe(100);
  });
  expect(outline).toMatch(/^M [\d. ]+(?: [HV] [\d.]+)+$/);
  expect(outline).not.toMatch(/[CQSTAcqsta]/);
  expect(area).toBe(`${outline} V 100 H 0 Z`);
  // degenerate inputs draw nothing rather than inventing a shape
  expect(steppedPath([])).toEqual({ outline: '', area: '', tops: [] });
  expect(steppedPath([{ count: 0 }])).toEqual({ outline: '', area: '', tops: [] });
});

// ---- the card ---------------------------------------------------------------

const SNAP = {
  count: 6,
  identity: { cutoff_seq: 42, canonical_query: 'all | * | * | *', scope: 'INC-8340' },
  rows: SIX,
};

test('renders the factual summary, the peak, and the accessible rolling-window equivalent', () => {
  render(<EvidenceActivity incidentId="INC-8340" snapshot={SNAP} />);
  expect(screen.getByText('Evidence activity')).toBeInTheDocument();
  expect(screen.getByText('Event volume during this investigation')).toBeInTheDocument();
  expect(screen.getByText('6 events observed')).toBeInTheDocument();
  // the ruled summary form; the peak count is the rolling-window count
  expect(screen.getByText(/Peak: \d\d:\d\d:\d\d · 4 events/)).toBeInTheDocument();
  // the textual equivalent names the rolling window explicitly, carries
  // every sample, the peak, the axis, and the snapshot boundary
  const table = screen.getByRole('table');
  expect(within(table).getAllByRole('row').length).toBe(SAMPLE_POINTS + 1);
  const caption = table.querySelector('caption').textContent;
  expect(caption).toMatch(/6 events observed/);
  expect(caption).toMatch(/30-second rolling window/);
  expect(caption).toMatch(/Peak \d\d:\d\d:\d\d with 4 events/);
  expect(caption).toMatch(/sequence 42/);
});

test('the chart is the ruled density composition: steps, lines, one accent peak, exact ticks', () => {
  const { container } = render(<EvidenceActivity incidentId="INC-8340" snapshot={SNAP} />);
  const m = rollingDensity(SNAP.rows);
  // one tooltip column per sample, naming the exact window
  const columns = container.querySelectorAll('[title*="in the preceding 30s"]');
  expect(columns).toHaveLength(SAMPLE_POINTS);
  m.samples.forEach((s, i) => {
    expect(columns[i].getAttribute('title'))
      .toBe(`${s.label} · ${s.count} event${s.count === 1 ? '' : 's'} in the preceding 30s`);
  });
  // ONE stepped outline over the subtle fill; no curve commands
  const paths = container.querySelectorAll('svg path');
  expect(paths).toHaveLength(2);
  const { outline, area } = steppedPath(m.samples);
  expect(paths[0].getAttribute('d')).toBe(area);
  expect(paths[1].getAttribute('d')).toBe(outline);
  // the single accent: peak column band + point marker + Peak label
  expect(screen.getByTestId('evidence-peak-column')).toBeInTheDocument();
  expect(screen.getByTestId('evidence-peak-marker')).toBeInTheDocument();
  expect(screen.getByTestId('evidence-peak-label').textContent).toBe('Peak');
  const accentLines = [...container.querySelectorAll('span')]
    .filter((s) => /#16436b|rgb\(22,\s*67,\s*107\)/.test(s.getAttribute('style') || '')
      && /height/.test(s.getAttribute('style') || ''));
  expect(accentLines).toHaveLength(1);
  // exact event ticks: one per source event, at the column-space position
  const ticks = screen.getAllByTestId('evidence-tick');
  expect(ticks).toHaveLength(6);
  ticks.forEach((tk, i) => {
    expect(tk.getAttribute('style')).toContain(`left: ${tickColumnPct(m.ticks[i].x)}%`);
  });
  // the compact ruled height band
  const plane = screen.getByTestId('evidence-peak-column').parentElement;
  expect(plane.className).toMatch(/min-h-\[180px\]/);
  expect(plane.className).toMatch(/max-h-\[220px\]/);
});

test('the axis carries exactly start / midpoint / end in normal flow -- nothing can clip or overlap', () => {
  const { container } = render(<EvidenceActivity incidentId="INC-8340" snapshot={SNAP} />);
  const m = rollingDensity(SNAP.rows);
  const axisRow = [...container.querySelectorAll('div')]
    .find((el) => el.className.includes('justify-between') && el.className.includes('text-[10px]'));
  const axis = [...axisRow.children].map((el) => el.textContent);
  expect(axis).toEqual([
    m.samples[0].label,
    m.samples[Math.floor((SAMPLE_POINTS - 1) / 2)].label,
    m.samples[SAMPLE_POINTS - 1].label,
  ]);
  // flex children in normal flow: no truncation/ellipsis classes exist
  expect(container.innerHTML).not.toMatch(/truncate|text-ellipsis/);
  // the Peak label is clamped inside the chart bounds even at the edges
  expect(clampPct(97.5)).toBe(94);
  expect(clampPct(1)).toBe(6);
  const endBurst = rows(at('12:00', 0), at('12:00', 10),
    at('12:02', 50), at('12:02', 51), at('12:02', 52), at('12:02', 53), at('12:02', 55));
  const b = render(<EvidenceActivity incidentId="INC-2" snapshot={{ count: 7, rows: endBurst, identity: { cutoff_seq: 9 } }} />);
  const lbl = within(b.container).getByTestId('evidence-peak-label');
  const left = parseFloat(lbl.getAttribute('style').match(/left:\s*([\d.]+)%/)[1]);
  expect(left).toBeGreaterThanOrEqual(6);
  expect(left).toBeLessThanOrEqual(94);
});

test('the sparse state renders exact ticks, the activity line, the total, and the honest message', () => {
  const sparseSnap = { count: 2, rows: rows(at('11:00'), at('11:03')), identity: { cutoff_seq: 7 } };
  const { container } = render(<EvidenceActivity incidentId="INC-1" snapshot={sparseSnap} />);
  expect(screen.getByText('2 events observed')).toBeInTheDocument();
  expect(screen.getByText(SPARSE_MESSAGE)).toBeInTheDocument();
  expect(screen.getByTestId('evidence-sparse')).toBeInTheDocument();
  expect(screen.getAllByTestId('evidence-tick')).toHaveLength(2);
  // no density shape is forced: no samples, no peak, no stepped svg
  expect(container.querySelector('svg path')).toBeNull();
  expect(screen.queryByText(/Peak/)).toBeNull();
  expect(screen.queryByTestId('evidence-peak-marker')).toBeNull();
});

test('volume is never described as suspicious, anomalous, or attack timing', () => {
  const { container } = render(<EvidenceActivity incidentId="INC-8340" snapshot={SNAP} newCount={5} />);
  expect(container.textContent).not.toMatch(/anomal|suspicious|malicious|attack|threat|correct/i);
});

test('later evidence is announced but never merged until the player loads it', async () => {
  const onLoad = jest.fn();
  const { rerender } = render(
    <EvidenceActivity incidentId="INC-8340" snapshot={SNAP} newCount={5} onLoadNewEvents={onLoad} />,
  );
  expect(screen.getByTestId('evidence-new-count').textContent).toBe('5 new events available');
  // the frozen chart still shows only the snapshot's six events
  expect(screen.getByText('6 events observed')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Load new events' }));
  expect(onLoad).toHaveBeenCalledTimes(1);
  // an atomic replacement swaps the whole model at once
  const bigger = { ...SNAP, count: 8, rows: [...SNAP.rows, ...rows(at('19:49'), at('19:49', 30))] };
  rerender(<EvidenceActivity incidentId="INC-8340" snapshot={bigger} newCount={0} />);
  expect(screen.getByText('8 events observed')).toBeInTheDocument();
  expect(screen.queryByTestId('evidence-new-count')).toBeNull();
});

test('honest loading and empty states; no false zero-event chart', () => {
  const a = render(<EvidenceActivity incidentId={null} />);
  expect(screen.getByText(NO_INCIDENT)).toBeInTheDocument();
  a.unmount();
  const b = render(<EvidenceActivity incidentId="INC-1" loading snapshot={null} />);
  expect(screen.getByText('Incident telemetry is still loading.')).toBeInTheDocument();
  expect(screen.queryByText(/events observed/)).toBeNull();   // never a false zero
  b.unmount();
  render(<EvidenceActivity incidentId="INC-1" snapshot={{ count: 0, rows: [], identity: { cutoff_seq: 1 } }} />);
  expect(screen.getByText(NO_EVENTS)).toBeInTheDocument();
});

// ---- isolation + leak safety ------------------------------------------------

test('the card reads only the supplied snapshot: it cannot fetch or see grading', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'components', 'EvidenceActivity.jsx'), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  expect(src).not.toMatch(/apiFetch|answer|expected_|disposition|scenario_label|grading/);
});

test('the dashboard scopes the evidence read to the ACTIVE incident and never polls it', async () => {
  const calls = [];
  apiFetch.mockImplementation((p) => {
    calls.push(String(p));
    const ok = (b) => Promise.resolve({ ok: true, json: () => Promise.resolve(b) });
    if (p === '/api/incidents') {
      return ok({ queue_length: 1, resolved_count: 0, completed: [],
        active: [{ incident_id: 'INC-8340', title: 'T', severity: 'High', state: 'in_progress',
                   sealed: true, ready: false, open_detections: 1, triage: { total: 1, triaged: 0 } }] });
    }
    if (String(p).startsWith('/api/events/query?')) return ok(SNAP);
    if (String(p).startsWith('/api/events/query/new-count')) return ok({ new_count: 0, pool_growth: 0 });
    if (p === '/api/detections') return ok({ detections: [], counts: {} });
    if (p === '/api/endpoints') return ok({ endpoints: [] });
    if (p === '/api/actions') return ok({ actions: [] });
    if (p === '/api/analytics/report_card') return ok({ state: 'in_progress', progress: {} });
    if (String(p).includes('/scope')) return ok({ incident_id: 'INC-8340', sealed: true, hosts: [], accounts: [], detection_ids: [] });
    return ok({});
  });
  await act(async () => { render(<IncidentDashboard gameMode="guided" />); });
  await waitFor(() => expect(screen.getByText('6 events observed')).toBeInTheDocument());
  const queries = calls.filter((c) => c.startsWith('/api/events/query?'));
  // exactly ONE frozen read for the incident -- scoped to it, never polled
  expect(queries).toHaveLength(1);
  expect(queries[0]).toContain('scope=INC-8340');
  // the read is a GET; nothing about it mutates
  const posts = apiFetch.mock.calls.filter(([, o]) => o && o.method === 'POST');
  expect(posts).toHaveLength(0);
});
