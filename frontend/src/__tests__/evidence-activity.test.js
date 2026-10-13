/**
 * VB1 (amendment section 2) + owner simplification (2026-10-12,
 * superseding the VD7/VE4 rolling-density composition): Evidence Activity
 * as a PLAIN EVENTS-PER-MINUTE BAR CHART over the ACTIVE incident's
 * observable event timestamps. Exact per-minute counts (gaps
 * zero-filled), the busiest minute as the single accent peak,
 * frozen-snapshot honesty (later evidence is announced, never merged
 * automatically), truthful loading/empty states with the zeroed plane,
 * and a complete textual equivalent. The "Rolling density..." caption is
 * retired. Volume only -- never suspiciousness, correctness, or
 * answer-key data.
 */
import React from 'react';
import fs from 'fs';
import path from 'path';
import { render, screen, fireEvent, waitFor, within, act } from '@testing-library/react';
import EvidenceActivity, { NO_INCIDENT, NO_EVENTS } from '../components/EvidenceActivity';
import { minuteBuckets, minuteLabel } from '../components/evidenceDensity';
import IncidentDashboard from '../components/IncidentDashboard';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const at = (isoMinute, seconds = 0) => `2026-07-26T${isoMinute}:${String(seconds).padStart(2, '0')}Z`;
const rows = (...stamps) => stamps.map((t, i) => ({ id: `e${i}`, timestamp: t }));

// the worked example: 6 events -- 2 in 19:45, 3 in 19:46, none in 19:47,
// 1 in 19:48 -> four buckets, peak 19:46 with 3
const SIX = rows(at('19:45', 5), at('19:45', 40), at('19:46', 1), at('19:46', 2),
                 at('19:46', 3), at('19:48', 0));

// ---- the per-minute model ---------------------------------------------------

test('per-minute counts are EXACT over real events; gaps are zero-filled, nothing fabricated', () => {
  const m = minuteBuckets(SIX);
  expect(m.total).toBe(6);
  expect(m.buckets).toHaveLength(4);                       // 19:45 .. 19:48 inclusive
  expect(m.buckets.map((b) => b.count)).toEqual([2, 3, 0, 1]);
  // bucket starts are consecutive whole minutes
  for (let i = 1; i < m.buckets.length; i += 1) {
    expect(m.buckets[i].t - m.buckets[i - 1].t).toBe(60000);
  }
  expect(m.buckets[0].t % 60000).toBe(0);
  // the peak is the busiest minute
  expect(m.peak.count).toBe(3);
  expect(m.peak.index).toBe(1);
  expect(m.peak.label).toBe(minuteLabel(m.buckets[1].t));
  // identical rows give byte-identical models (frozen-snapshot stability)
  expect(minuteBuckets(SIX)).toEqual(m);
});

test('peak ties resolve to the EARLIEST minute (deterministic)', () => {
  const m = minuteBuckets(rows(
    at('10:00', 0), at('10:00', 1), at('10:02', 0), at('10:02', 1),
  ));
  expect(m.buckets.map((b) => b.count)).toEqual([2, 0, 2]);
  expect(m.peak.index).toBe(0);
});

test('malformed or missing timestamps are ignored, never invented', () => {
  const m = minuteBuckets([
    { id: 'a', timestamp: at('08:00') },
    { id: 'b' },
    { id: 'c', timestamp: 'not-a-time' },
    { id: 'd', timestamp: null },
  ]);
  expect(m.total).toBe(1);
  expect(m.buckets).toHaveLength(1);
  expect(m.buckets[0].count).toBe(1);
  expect(minuteBuckets([]).total).toBe(0);
  expect(minuteBuckets(null).buckets).toEqual([]);
});

// ---- the card ---------------------------------------------------------------

const SNAP = {
  count: 6,
  identity: { cutoff_seq: 42, canonical_query: 'all | * | * | *', scope: 'INC-8340' },
  rows: SIX,
};

test('renders the factual summary, the peak, and the accessible per-minute equivalent', () => {
  render(<EvidenceActivity incidentId="INC-8340" snapshot={SNAP} />);
  expect(screen.getByText('Evidence Activity')).toBeInTheDocument();
  // owner UI pass (2026-10-12): card subtitles are stripped
  expect(screen.queryByText('Event volume during this investigation')).toBeNull();
  expect(screen.getByText('6 Events Observed')).toBeInTheDocument();
  // the peak chip names the busiest minute and its exact count
  expect(screen.getByText(/Peak: \d\d:\d\d · 3 Events/)).toBeInTheDocument();
  // the textual equivalent: one row per minute, the peak marked, the
  // snapshot boundary named (accessible PROSE stays sentence case)
  const table = screen.getByRole('table');
  expect(within(table).getAllByRole('row').length).toBe(4 + 1);
  const caption = table.querySelector('caption').textContent;
  expect(caption).toMatch(/6 events observed/);
  expect(caption).toMatch(/events per minute/);
  expect(caption).toMatch(/Peak \d\d:\d\d with 3 events/);
  expect(caption).toMatch(/sequence 42/);
});

test('the chart is plain per-minute bars: exact heights, one accent peak, no density furniture', () => {
  const { container } = render(<EvidenceActivity incidentId="INC-8340" snapshot={SNAP} />);
  const m = minuteBuckets(SNAP.rows);
  // one tooltip column per minute bucket
  const columns = screen.getByTestId('evidence-bars').children;
  expect(columns).toHaveLength(m.buckets.length);
  [...columns].forEach((col, i) => {
    expect(col.getAttribute('title'))
      .toBe(`${m.buckets[i].label} · ${m.buckets[i].count} event${m.buckets[i].count === 1 ? '' : 's'}`);
  });
  // bars render only for nonzero minutes; exactly one wears the accent
  expect(screen.getAllByTestId('evidence-bar')).toHaveLength(2);
  const peak = screen.getByTestId('evidence-bar-peak');
  expect(peak.getAttribute('style')).toContain('height: 100%');
  // heights are proportional to exact counts
  const first = screen.getAllByTestId('evidence-bar')[0];
  expect(first.getAttribute('style')).toContain(`height: ${(2 / 3) * 100}%`);
  // the retired density furniture is structurally gone
  expect(container.querySelector('svg')).toBeNull();
  expect(screen.queryByTestId('evidence-tick')).toBeNull();
  expect(screen.queryByTestId('evidence-peak-marker')).toBeNull();
  expect(screen.queryByTestId('evidence-peak-column')).toBeNull();
  expect(container.textContent).not.toMatch(/Rolling density|preceding \d+s|Ticks mark/);
  // the compact ruled height band stays
  const plane = screen.getByTestId('evidence-bars').parentElement;
  expect(plane.className).toMatch(/min-h-\[180px\]/);
  expect(plane.className).toMatch(/max-h-\[220px\]/);
});

test('the axis carries the first and last minute in normal flow', () => {
  const { container } = render(<EvidenceActivity incidentId="INC-8340" snapshot={SNAP} />);
  const m = minuteBuckets(SNAP.rows);
  const axisRow = [...container.querySelectorAll('div')]
    .find((el) => el.className.includes('justify-between') && el.className.includes('text-[10px]')
      && !el.className.includes('opacity-60'));
  const axis = [...axisRow.children].map((el) => el.textContent);
  expect(axis).toEqual([m.buckets[0].label, m.buckets[m.buckets.length - 1].label]);
  expect(container.innerHTML).not.toMatch(/truncate|text-ellipsis/);
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
  expect(screen.getByTestId('evidence-new-count').textContent).toBe('5 New Events Available');
  // the frozen chart still shows only the snapshot's six events
  expect(screen.getByText('6 Events Observed')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Load New Events' }));
  expect(onLoad).toHaveBeenCalledTimes(1);
  // an atomic replacement swaps the whole model at once
  const bigger = { ...SNAP, count: 8, rows: [...SNAP.rows, ...rows(at('19:49'), at('19:49', 30))] };
  rerender(<EvidenceActivity incidentId="INC-8340" snapshot={bigger} newCount={0} />);
  expect(screen.getByText('8 Events Observed')).toBeInTheDocument();
  expect(screen.queryByTestId('evidence-new-count')).toBeNull();
});

test('honest loading and empty states; no false zero-event chart', () => {
  const a = render(<EvidenceActivity incidentId={null} />);
  expect(screen.getByText(NO_INCIDENT)).toBeInTheDocument();
  expect(screen.getByTestId('evidence-empty-plane')).toBeInTheDocument();
  a.unmount();
  const b = render(<EvidenceActivity incidentId="INC-1" loading snapshot={null} />);
  expect(screen.getByText('Incident telemetry is still loading.')).toBeInTheDocument();
  expect(screen.queryByText(/events observed/i)).toBeNull();   // never a false zero
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
  await waitFor(() => expect(screen.getByText('6 Events Observed')).toBeInTheDocument());
  const queries = calls.filter((c) => c.startsWith('/api/events/query?'));
  // exactly ONE frozen read for the incident -- scoped to it, never polled
  expect(queries).toHaveLength(1);
  expect(queries[0]).toContain('scope=INC-8340');
  // the read is a GET; nothing about it mutates
  const posts = apiFetch.mock.calls.filter(([, o]) => o && o.method === 'POST');
  expect(posts).toHaveLength(0);
});
