/**
 * VB1 (amendment section 2) + owner simplification (2026-10-12, superseding
 * the events-per-minute bars, which themselves superseded the VD7/VE4
 * rolling-density composition): Evidence Activity as EVIDENCE COMPOSITION --
 * event counts grouped by the serialized source_type, rendered as simple
 * count bars. The time-volume chart, the "Peak" line, the time axis, and
 * the density caption are retired (scripted events on a session wall-clock
 * axis carry no signal). Frozen-snapshot honesty (later evidence is
 * announced, never merged automatically), truthful loading/empty states
 * with the zeroed plane, and visible-text rows (the chart is its own
 * textual equivalent). Volume only -- never suspiciousness, correctness,
 * or answer-key data.
 */
import React from 'react';
import fs from 'fs';
import path from 'path';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import EvidenceActivity, { NO_INCIDENT, NO_EVENTS } from '../components/EvidenceActivity';
import { sourceComposition } from '../components/evidenceComposition';
import IncidentDashboard from '../components/IncidentDashboard';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const evt = (src, i) => ({
  id: `e-${src}-${i}`, timestamp: '2026-07-26T19:45:00Z', source_type: src,
});

// the worked example: 6 events -- 3 Sysmon, 2 Windows Security, 1 DNS
const SIX = [
  evt('Sysmon', 1), evt('Windows Security', 1), evt('Sysmon', 2),
  evt('DNS', 1), evt('Sysmon', 3), evt('Windows Security', 2),
];

// ---- the composition model --------------------------------------------------

test('counts group EXACTLY by source_type, ordered by count then label', () => {
  const m = sourceComposition(SIX);
  expect(m.total).toBe(6);
  expect(m.groups).toEqual([
    { label: 'Sysmon', count: 3 },
    { label: 'Windows Security', count: 2 },
    { label: 'DNS', count: 1 },
  ]);
  expect(m.max).toBe(3);
  // identical rows give byte-identical models (frozen-snapshot stability)
  expect(sourceComposition(SIX)).toEqual(m);
});

test('count ties order alphabetically (deterministic)', () => {
  const m = sourceComposition([evt('Proxy', 1), evt('DNS', 1), evt('Firewall', 1)]);
  expect(m.groups.map((g) => g.label)).toEqual(['DNS', 'Firewall', 'Proxy']);
});

test('rows without a source land in Other; nothing is invented or dropped', () => {
  const m = sourceComposition([
    evt('Sysmon', 1),
    { id: 'b', timestamp: '2026-07-26T19:45:00Z' },
    { id: 'c', timestamp: '2026-07-26T19:45:00Z', source_type: '   ' },
    null,
  ]);
  expect(m.total).toBe(3);
  expect(m.groups).toEqual([
    { label: 'Other', count: 2 },
    { label: 'Sysmon', count: 1 },
  ]);
  expect(sourceComposition([]).total).toBe(0);
  expect(sourceComposition(null).groups).toEqual([]);
});

// ---- the card ---------------------------------------------------------------

const SNAP = {
  count: 6,
  identity: { cutoff_seq: 42, canonical_query: 'all | * | * | *', scope: 'INC-8340' },
  rows: SIX,
};

test('renders the factual summary and one labeled count row per source', () => {
  render(<EvidenceActivity incidentId="INC-8340" snapshot={SNAP} />);
  expect(screen.getByText('Evidence Activity')).toBeInTheDocument();
  // owner UI pass (2026-10-12): card subtitles are stripped
  expect(screen.queryByText('Event volume during this investigation')).toBeNull();
  // owner tweak (2026-10-12): the summary rides the TITLE ROW, muted --
  // not its own line
  const summary = screen.getByText('6 Events Observed');
  expect(summary.getAttribute('class')).toMatch(/text-muted/);
  expect(summary.parentElement).toBe(screen.getByText('Evidence Activity').parentElement);
  // visible rows: label and exact count, count-descending order
  const groups = screen.getAllByTestId('evidence-group');
  expect(groups).toHaveLength(3);
  expect(groups.map((g) => g.textContent)).toEqual([
    'Sysmon3', 'Windows Security2', 'DNS1',
  ]);
  // the snapshot boundary stays named for screen readers
  expect(document.body.textContent).toMatch(/Snapshot boundary at sequence 42/);
});

test('bars are proportional to exact counts; the time-volume furniture is gone', () => {
  const { container } = render(<EvidenceActivity incidentId="INC-8340" snapshot={SNAP} />);
  const bars = screen.getAllByTestId('evidence-group-bar');
  expect(bars).toHaveLength(3);
  expect(bars[0].getAttribute('style')).toContain('width: 100%');
  expect(bars[1].getAttribute('style')).toContain(`width: ${(2 / 3) * 100}%`);
  expect(bars[2].getAttribute('style')).toContain(`width: ${(1 / 3) * 100}%`);
  // owner tweak (2026-10-12): every track caps at a fixed max width (the
  // Severity Distribution proportions), so the count sits right after the
  // bar instead of the bar stretching the full card width
  bars.forEach((b) => expect(b.parentElement.getAttribute('class')).toContain('max-w-[10rem]'));
  // owner unification (2026-10-12): the Severity Distribution anatomy --
  // text-sm rows, h-2 track, navy fill via the shared BarRow
  bars.forEach((b) => {
    expect(b.parentElement.getAttribute('class')).toContain('h-2');
    expect(b.getAttribute('style')).toContain('background:');
  });
  screen.getAllByTestId('evidence-group').forEach((row) => {
    expect(row.getAttribute('class')).toContain('text-sm');
  });
  // the retired chart, peak line, axis, and caption are structurally gone
  expect(container.querySelector('svg')).toBeNull();
  expect(screen.queryByTestId('evidence-bars')).toBeNull();
  expect(screen.queryByTestId('evidence-bar')).toBeNull();
  expect(screen.queryByTestId('evidence-bar-peak')).toBeNull();
  expect(container.textContent).not.toMatch(/Peak[: ]/);
  expect(container.textContent).not.toMatch(/Rolling density|preceding \d+s|Ticks mark/);
  expect(container.textContent).not.toMatch(/\d\d:\d\d/);   // no wall-clock axis
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
  // the frozen card still shows only the snapshot's six events
  expect(screen.getByText('6 Events Observed')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Load New Events' }));
  expect(onLoad).toHaveBeenCalledTimes(1);
  // an atomic replacement swaps the whole model at once
  const bigger = { ...SNAP, count: 8, rows: [...SNAP.rows, evt('DNS', 2), evt('DNS', 3)] };
  rerender(<EvidenceActivity incidentId="INC-8340" snapshot={bigger} newCount={0} />);
  expect(screen.getByText('8 Events Observed')).toBeInTheDocument();
  expect(screen.queryByTestId('evidence-new-count')).toBeNull();
});

test('honest loading and empty states; no false zero-event rows', () => {
  const a = render(<EvidenceActivity incidentId={null} />);
  expect(screen.getByText(NO_INCIDENT)).toBeInTheDocument();
  expect(screen.getByTestId('evidence-empty-plane')).toBeInTheDocument();
  expect(screen.queryByTestId('evidence-group')).toBeNull();
  // the zeroed plane keeps the SAME capped-track geometry as the data state
  expect(screen.getByTestId('evidence-empty-plane')
    .querySelectorAll('.max-w-\\[10rem\\]')).toHaveLength(3);
  a.unmount();
  const b = render(<EvidenceActivity incidentId="INC-1" loading snapshot={null} />);
  expect(screen.getByText('Incident telemetry is still loading.')).toBeInTheDocument();
  expect(screen.queryByText(/events observed/i)).toBeNull();   // never a false zero
  expect(document.body.textContent).not.toMatch(/(^|[^-])0([^-]|$)/);
  b.unmount();
  render(<EvidenceActivity incidentId="INC-1" snapshot={{ count: 0, rows: [], identity: { cutoff_seq: 1 } }} />);
  expect(screen.getByText(NO_EVENTS)).toBeInTheDocument();
});

// ---- the shared bar-list anatomy ---------------------------------------------

test('ONE shared bar-list component across Evidence Activity and Severity Distribution', () => {
  const ev = fs.readFileSync(path.join(__dirname, '..', 'components', 'EvidenceActivity.jsx'), 'utf8');
  const dash = fs.readFileSync(path.join(__dirname, '..', 'components', 'IncidentDashboard.jsx'), 'utf8');
  const ui = fs.readFileSync(path.join(__dirname, '..', 'components', 'ui.jsx'), 'utf8');
  // both cards render rows through the shared BarList/BarRow (ui.jsx);
  // identical label font, bar height, track, count typography, and row
  // spacing by construction -- only the fill color is passed per card
  for (const src of [ev, dash]) {
    expect(src).toMatch(/<BarRow\b/);
    expect(src).toMatch(/<BarList>/);
  }
  // the one track definition lives in ui.jsx; evidence keeps no local copy
  // (the zeroed empty plane mirrors the geometry but renders no data bar)
  const TRACK = 'max-w-[10rem] h-2 rounded-full bg-[#eef1f4] overflow-hidden';
  expect(ui).toContain(TRACK);
  expect(ev).not.toContain(TRACK);
  expect(dash).not.toContain(TRACK);
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
