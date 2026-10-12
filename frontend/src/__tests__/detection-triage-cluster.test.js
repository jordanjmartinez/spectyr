/**
 * Stage 6 playtest fix 13: a reviewed detection row never renders the
 * contradictory "Promote Dismiss Reopen" cluster.
 *
 * - An OPEN row offers exactly the two decisions: Promote + Dismiss.
 * - A reviewed row reads STATE (the Promoted/Dismissed chip, a
 *   non-interactive span) + Reopen, the one way back. Changing a call is
 *   deliberately two-step: Reopen, then decide again (the disposition API
 *   is unchanged).
 * - The detail card follows the same shape.
 *
 * Stage 6 playtest fixes 14+15 (same surface): the disposition POST's
 * authoritative response applies to the row and the header counts in the
 * same frame as the toast -- the header can no longer trail the toast by a
 * refetch round-trip, and the just-clicked (still-hovered) button unmounts
 * immediately so its CSS tooltip line cannot linger as a doubled label.
 * One in-flight disposition per detection: double-clicks never double-POST.
 */
import React from 'react';
import { render, screen, act, within } from '@testing-library/react';
import Detections from '../components/Detections';
import DetectionDetail from '../components/DetectionDetail';

jest.mock('react-toastify', () => ({ toast: jest.fn(), ToastContainer: () => null }));
jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');
const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

const det = (id, rule, player_action) => ({
  id, rule_name: rule, rule_type: 'sigma_behavioral', severity: 'high',
  mitre: null, yara_rule_name: null, description: 'x',
  entity: { host: 'ACME-WS12', account: 'nkhan' },
  time: '2026-07-16T12:10:00+00:00', sha256: null, player_action,
});
const FEED = {
  detections: [
    det('det-o', 'Rule Open', 'open'),
    det('det-p', 'Rule Promoted', 'promoted'),
    det('det-d', 'Rule Dismissed', 'dismissed'),
  ],
  counts: { open: 1, promoted: 1, dismissed: 1 },
};

beforeEach(() => {
  apiFetch.mockReset();
  apiFetch.mockImplementation((path) => {
    if (path === '/api/detections') return ok(FEED);
    if (path.startsWith('/api/detections/')) return ok(FEED.detections[1]);
    if (path === '/api/actions') return ok({ actions: [], count: 0 });
    return ok({});
  });
});

const rowOf = (rule) => screen.getByText(rule).closest('tr');

test('feed rows: open offers the two decisions; reviewed shows the state chip + Reopen only', async () => {
  await act(async () => {
    render(<Detections isVisible resetTrigger={0} activeIncidentId={null} />);
  });
  await screen.findByText('Rule Open');

  const open = within(rowOf('Rule Open'));
  expect(open.getByRole('button', { name: 'Promote' })).toBeInTheDocument();
  expect(open.getByRole('button', { name: 'Dismiss' })).toBeInTheDocument();
  expect(open.queryByText('Reopen')).toBeNull();
  expect(open.queryByText('Promoted')).toBeNull();

  for (const [rule, chip] of [['Rule Promoted', 'Promoted'], ['Rule Dismissed', 'Dismissed']]) {
    const row = within(rowOf(rule));
    expect(row.queryByRole('button', { name: 'Promote' })).toBeNull();
    expect(row.queryByRole('button', { name: 'Dismiss' })).toBeNull();
    expect(row.getByRole('button', { name: 'Reopen' })).toBeInTheDocument();
    const chipEl = row.getByText(chip);
    expect(chipEl.tagName).toBe('SPAN'); // state, not a control
  }
});

test('the row and header counts flip with the toast, before any refetch lands (fixes 14+15)', async () => {
  let feedCalls = 0;
  apiFetch.mockImplementation((path, opts) => {
    if (opts?.method === 'POST' && path.includes('/disposition')) {
      return ok({ ...FEED.detections[0], player_action: 'dismissed' });
    }
    if (path === '/api/detections') {
      feedCalls += 1;
      if (feedCalls === 1) return ok(FEED);
      return new Promise(() => {}); // the reconciliation refetch hangs
    }
    if (path === '/api/actions') return ok({ actions: [], count: 0 });
    return ok({});
  });
  const { container } = render(<Detections isVisible resetTrigger={0} activeIncidentId={null} />);
  await screen.findByText('Rule Open');
  expect(container.textContent).toContain('1 Open');

  await act(async () => {
    within(rowOf('Rule Open')).getByRole('button', { name: 'Dismiss' }).click();
  });
  // the refetch is still hanging: everything below is the same-frame update
  const row = within(rowOf('Rule Open'));
  expect(row.queryByRole('button', { name: 'Dismiss' })).toBeNull(); // tooltip host unmounted
  expect(row.getByText('Dismissed').tagName).toBe('SPAN');
  expect(row.getByRole('button', { name: 'Reopen' })).toBeInTheDocument();
  expect(container.textContent).toContain('0 Open');
  expect(container.textContent).toContain('2 Dismissed');
});

test('a rapid double-click submits exactly one disposition', async () => {
  let postCalls = 0;
  apiFetch.mockImplementation((path, opts) => {
    if (opts?.method === 'POST' && path.includes('/disposition')) {
      postCalls += 1;
      return new Promise(() => {}); // in flight
    }
    if (path === '/api/detections') return ok(FEED);
    if (path === '/api/actions') return ok({ actions: [], count: 0 });
    return ok({});
  });
  render(<Detections isVisible resetTrigger={0} activeIncidentId={null} />);
  await screen.findByText('Rule Open');
  const btn = within(rowOf('Rule Open')).getByRole('button', { name: 'Dismiss' });
  await act(async () => { btn.click(); btn.click(); });
  expect(postCalls).toBe(1);
});

test('the detail card follows the same shape for a reviewed detection', async () => {
  await act(async () => {
    render(<DetectionDetail detId="det-p" onBack={() => {}} />);
  });
  await screen.findByText('Rule Promoted');
  expect(screen.queryByRole('button', { name: 'Promote to Threat' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Dismiss' })).toBeNull();
  expect(screen.getByRole('button', { name: 'Reopen' })).toBeInTheDocument();
  expect(screen.getByText('Promoted').tagName).toBe('SPAN');
});
