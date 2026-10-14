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
// decision-layer pass (owner 2026-10-13): the decisions sit behind the
// row's ONE "..." menu with their full labels; open it to read them
const openMenu = (rule) => {
  within(rowOf(rule)).getByRole('button', { name: `Actions for ${rule}` }).click();
  return within(rowOf(rule));
};

test('feed rows: open offers the two decisions; reviewed shows the state chip + Reopen only', async () => {
  const { container } = render(<Detections isVisible resetTrigger={0} activeIncidentId={null} />);
  await screen.findByText('Rule Open');

  // the uniform toolbar (owner list-page pass): reviewed rows live behind
  // their disposition tabs; the default Open tab shows only open rows
  let open;
  await act(async () => { open = openMenu('Rule Open'); });
  expect(open.getByRole('menuitem', { name: 'Promote to Threat' })).toBeInTheDocument();
  expect(open.getByRole('menuitem', { name: 'Dismiss as Benign' })).toBeInTheDocument();
  expect(open.queryByText('Reopen')).toBeNull();
  expect(container.textContent).not.toContain('Rule Promoted');

  for (const [tab, rule, chip] of [
    ['Promoted 1', 'Rule Promoted', 'Promoted'],
    ['Dismissed 1', 'Rule Dismissed', 'Dismissed'],
  ]) {
    await act(async () => {
      screen.getByRole('button', { name: tab }).click();
    });
    let row;
    await act(async () => { row = openMenu(rule); });
    expect(row.queryByRole('menuitem', { name: 'Promote to Threat' })).toBeNull();
    expect(row.queryByRole('menuitem', { name: 'Dismiss as Benign' })).toBeNull();
    expect(row.getByRole('menuitem', { name: 'Reopen' })).toBeInTheDocument();
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
  expect(screen.getByRole('button', { name: 'Open 1' })).toBeInTheDocument();

  await act(async () => { openMenu('Rule Open'); });
  await act(async () => {
    within(rowOf('Rule Open')).getByRole('menuitem', { name: 'Dismiss as Benign' }).click();
  });
  // the refetch is still hanging: everything below is the same-frame
  // update. Under the uniform toolbar the dismissed row LEAVES the Open
  // tab (the clicked, still-hovered button unmounts with it -- the
  // doubled-tooltip class stays impossible) and the tab counts flip with
  // the toast.
  expect(container.textContent).not.toContain('Rule Open');
  expect(screen.getByRole('button', { name: 'Open 0' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Dismissed 2' })).toBeInTheDocument();
  await act(async () => {
    screen.getByRole('button', { name: 'Dismissed 2' }).click();
  });
  expect(within(rowOf('Rule Open')).getByText('Dismissed').tagName).toBe('SPAN');
  let row;
  await act(async () => { row = openMenu('Rule Open'); });
  expect(row.getByRole('menuitem', { name: 'Reopen' })).toBeInTheDocument();
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
  // two rapid menu-driven dismissals: the second re-opens the menu and
  // clicks again while the first POST is still in flight
  for (let i = 0; i < 2; i += 1) {
    await act(async () => { openMenu('Rule Open'); });
    await act(async () => {
      within(rowOf('Rule Open')).getByRole('menuitem', { name: 'Dismiss as Benign' }).click();
    });
  }
  expect(postCalls).toBe(1);
});

test('the detail card follows the same shape for a reviewed detection', async () => {
  await act(async () => {
    render(<DetectionDetail detId="det-p" onBack={() => {}} />);
  });
  await screen.findByText('Rule Promoted');
  expect(screen.queryByRole('button', { name: 'Promote to Threat' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Dismiss as Benign' })).toBeNull();
  expect(screen.getByRole('button', { name: 'Reopen' })).toBeInTheDocument();
  expect(screen.getByText('Promoted').tagName).toBe('SPAN');
});
