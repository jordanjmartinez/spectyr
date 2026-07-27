/**
 * VB1 (amendment section 2): Evidence activity. Deterministic bucketing
 * over the ACTIVE incident's observable event timestamps, exact totals
 * and peak, frozen-snapshot honesty (later evidence is announced, never
 * merged automatically), truthful loading and empty states, and a
 * complete textual equivalent. Volume only -- never suspiciousness,
 * correctness, or answer-key data.
 */
import React from 'react';
import fs from 'fs';
import path from 'path';
import { render, screen, fireEvent, waitFor, within, act } from '@testing-library/react';
import EvidenceActivity, { NO_INCIDENT, NO_EVENTS } from '../components/EvidenceActivity';
import {
  bucketEvidence, chooseBucketSeconds, BUCKET_LADDER, MAX_BUCKETS, steppedPath,
} from '../components/evidenceBuckets';
import IncidentDashboard from '../components/IncidentDashboard';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const at = (isoMinute, seconds = 0) => `2026-07-26T${isoMinute}:${String(seconds).padStart(2, '0')}Z`;
const rows = (...stamps) => stamps.map((t, i) => ({ id: `e${i}`, timestamp: t }));

// ---- bucketing --------------------------------------------------------------

test('the bucket ladder is deterministic and keeps the chart within MAX_BUCKETS', () => {
  // VD1: sub-minute steps join the ladder so a short run fills the chart
  // with many exact thin buckets instead of a few isolated bars
  expect(BUCKET_LADDER).toEqual([5, 10, 15, 30, 60, 120, 300, 600, 1800, 3600]);
  // very short runs land on the small steps; ordinary runs are unchanged
  expect(chooseBucketSeconds(0)).toBe(5);
  expect(chooseBucketSeconds(60)).toBe(5);                // 1 min chain -> 13 buckets
  expect(chooseBucketSeconds(3 * 60)).toBe(5);            // 3 min -> 37 buckets
  expect(chooseBucketSeconds(200)).toBe(10);              // 41 at 5s, steps up
  expect(chooseBucketSeconds(500)).toBe(15);
  expect(chooseBucketSeconds(10 * 60)).toBe(30);          // 10 min -> 21 buckets (unchanged)
  expect(chooseBucketSeconds(19 * 60)).toBe(30);          // 19.5 min -> 39 buckets, still 30s
  expect(chooseBucketSeconds(20 * 60)).toBe(60);          // 20 min -> 41 at 30s, so it steps up
  expect(chooseBucketSeconds(30 * 60)).toBe(60);          // 30 min -> 31 buckets
  expect(chooseBucketSeconds(60 * 60)).toBe(120);         // 1 h
  expect(chooseBucketSeconds(6 * 60 * 60)).toBe(600);     // 6 h
  // beyond the ladder (no authored run reaches this) the cap is still
  // honored by stepping to whole hours rather than silently overflowing
  expect(chooseBucketSeconds(24 * 60 * 60)).toBe(3600);
  expect(chooseBucketSeconds(7 * 24 * 60 * 60)).toBe(5 * 3600);   // 34 buckets
  // the chosen size always fits the cap
  for (const span of [0, 60, 600, 3600, 86400, 604800]) {
    const size = chooseBucketSeconds(span);
    expect(Math.floor(span / size) + 1).toBeLessThanOrEqual(MAX_BUCKETS);
  }
  // pure function: identical input, identical output
  expect(chooseBucketSeconds(1234)).toBe(chooseBucketSeconds(1234));
});

// ---- the stepped outline (VD1) ---------------------------------------------

test('stepped points correspond exactly to bucket counts, zeros included', () => {
  const m = bucketEvidence(rows(
    at('19:45', 5), at('19:45', 6),          // 2 in the first bucket
    at('19:45', 21), at('19:45', 22), at('19:45', 23),   // 3 (peak)
    at('19:45', 40),                          // 1, after a zero bucket
  ));
  const { tops, outline, area } = steppedPath(m.buckets);
  // one step per bucket, contiguous unit-wide x spans
  expect(tops).toHaveLength(m.buckets.length);
  tops.forEach((t, i) => { expect([t.x0, t.x1]).toEqual([i, i + 1]); });
  // each step's height is the exact count/max ratio; zero buckets sit on
  // the baseline (y = 100) -- represented, never skipped or interpolated
  const max = Math.max(...m.buckets.map((b) => b.count));
  m.buckets.forEach((b, i) => {
    expect(tops[i].y).toBe(100 - (b.count / max) * 100);
  });
  expect(m.buckets.some((b) => b.count === 0)).toBe(true);
  m.buckets.forEach((b, i) => { if (b.count === 0) expect(tops[i].y).toBe(100); });
  // horizontal/vertical steps only: no curve or arc commands, no smoothing
  expect(outline).toMatch(/^M [\d. ]+(?: [HV] [\d.]+)+$/);
  expect(outline).not.toMatch(/[CQSTAcqsta]/);
  // the fill is the same outline closed to the baseline
  expect(area).toBe(`${outline} V 100 H 0 Z`);
});

test('the outline never changes event totals; boundaries are stable multiples of the interval', () => {
  const input = rows(at('09:00', 3), at('09:00', 9), at('09:01', 30), at('09:02', 0));
  const m = bucketEvidence(input);
  // total preserved exactly through bucketing (no interpolation, no
  // fabricated nonzero values)
  expect(m.buckets.reduce((a, b) => a + b.count, 0)).toBe(m.total);
  expect(m.total).toBe(4);
  // every bucket start is an exact multiple of the chosen interval
  for (const b of m.buckets) {
    expect(b.start % (m.bucketSeconds * 1000)).toBe(0);
  }
  // deterministic: identical rows give identical buckets and geometry
  const again = bucketEvidence(rows(at('09:00', 3), at('09:00', 9), at('09:01', 30), at('09:02', 0)));
  expect(again).toEqual(m);
  expect(steppedPath(again.buckets)).toEqual(steppedPath(m.buckets));
});

test('steppedPath degrades honestly: no buckets or all-zero input draws nothing', () => {
  expect(steppedPath([])).toEqual({ outline: '', area: '', tops: [] });
  expect(steppedPath(null)).toEqual({ outline: '', area: '', tops: [] });
  expect(steppedPath([{ count: 0 }, { count: 0 }])).toEqual({ outline: '', area: '', tops: [] });
});

test('exact totals, contiguous buckets, and an exact single peak', () => {
  const m = bucketEvidence(rows(
    at('19:45', 5), at('19:45', 40),                    // bucket 19:45 -> 2
    at('19:46', 1), at('19:46', 2), at('19:46', 3),     // bucket 19:46 -> 3 (peak)
    at('19:48', 0),                                     // bucket 19:48 -> 1
  ));
  expect(m.total).toBe(6);
  expect(m.bucketSeconds).toBe(5);   // VD1: a 175s run takes the 5s ladder step
  // contiguity: a quiet interval renders as a real zero, never skipped
  const counts = m.buckets.map((b) => b.count);
  expect(counts.reduce((a, b) => a + b, 0)).toBe(6);
  expect(counts).toContain(0);
  expect(m.peak.count).toBe(3);
  expect(m.buckets.filter((b) => b.isPeak)).toHaveLength(1);
  // ties resolve to the EARLIEST interval (deterministic)
  const tie = bucketEvidence(rows(at('10:00'), at('10:05')));
  expect(tie.buckets.filter((b) => b.isPeak)).toHaveLength(1);
  expect(tie.buckets.find((b) => b.isPeak).label).toBe(tie.buckets[0].label);
});

test('malformed or missing timestamps are ignored, never invented', () => {
  const m = bucketEvidence([
    { id: 'a', timestamp: at('08:00') },
    { id: 'b' },
    { id: 'c', timestamp: 'not-a-time' },
    { id: 'd', timestamp: null },
  ]);
  expect(m.total).toBe(1);
  expect(bucketEvidence([]).total).toBe(0);
  expect(bucketEvidence(null).buckets).toEqual([]);
});

// ---- the card ---------------------------------------------------------------

const SNAP = {
  count: 6,
  identity: { cutoff_seq: 42, canonical_query: 'all | * | * | *', scope: 'INC-8340' },
  rows: rows(at('19:45', 5), at('19:45', 40), at('19:46', 1), at('19:46', 2), at('19:46', 3), at('19:48', 0)),
};

test('renders the factual summary, the peak, and the accessible equivalent', () => {
  render(<EvidenceActivity incidentId="INC-8340" snapshot={SNAP} />);
  expect(screen.getByText('Evidence activity')).toBeInTheDocument();
  expect(screen.getByText('Event volume during this investigation')).toBeInTheDocument();
  expect(screen.getByText('6 events observed')).toBeInTheDocument();
  // sub-minute buckets label with second precision (VD1)
  expect(screen.getByText(/Peak: \d\d:\d\d:\d\d · 3 events/)).toBeInTheDocument();
  // the textual equivalent carries every bucket, the peak, the total, and
  // the snapshot boundary -- available without hover or color
  const table = screen.getByRole('table');
  expect(within(table).getAllByRole('row').length).toBeGreaterThan(1);
  const caption = table.closest('table').querySelector('caption').textContent;
  expect(caption).toMatch(/6 events observed/);
  expect(caption).toMatch(/Peak interval/);
  expect(caption).toMatch(/sequence 42/);
});

test('the chart is visually continuous: every bucket renders, zeros stay zero, the outline is stepped (VD1)', () => {
  const { container } = render(<EvidenceActivity incidentId="INC-8340" snapshot={SNAP} />);
  const model = bucketEvidence(SNAP.rows);
  // the complete deterministic range renders: one tooltip column per
  // bucket (zeros included), matching the model exactly
  const columns = container.querySelectorAll('[title*=" event"]');
  expect(columns).toHaveLength(model.buckets.length);
  expect(model.buckets.length).toBeGreaterThan(10);           // continuous, not isolated bars
  expect(model.buckets.some((b) => b.count === 0)).toBe(true);
  // exact tooltip per bucket
  model.buckets.forEach((b, i) => {
    expect(columns[i].getAttribute('title'))
      .toBe(`${b.label} · ${b.count} event${b.count === 1 ? '' : 's'}`);
  });
  // ONE stepped outline over a subtle fill; no curve commands anywhere
  const paths = container.querySelectorAll('svg path');
  expect(paths).toHaveLength(2);
  const { outline, area } = steppedPath(model.buckets);
  expect(paths[0].getAttribute('d')).toBe(area);
  expect(paths[1].getAttribute('d')).toBe(outline);
  expect(outline).not.toMatch(/[CQSTAcqsta]/);
  // the peak alone carries the restrained accent and its marker
  expect(screen.getByTestId('evidence-peak-marker')).toBeInTheDocument();
  const accentBars = [...container.querySelectorAll('span')]
    .filter((s) => /#16436b|rgb\(22,\s*67,\s*107\)/.test(s.getAttribute('style') || '')
      && /height/.test(s.getAttribute('style') || ''));
  expect(accentBars).toHaveLength(1);
  // compact start / peak / end labels
  const axis = [...container.querySelectorAll('.text-\\[10px\\]')].map((s) => s.textContent).filter(Boolean);
  expect(axis).toHaveLength(3);
  expect(axis).toContain(model.buckets[0].label);
  expect(axis).toContain(model.buckets[model.buckets.length - 1].label);
  expect(axis).toContain(model.peak.label);
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
