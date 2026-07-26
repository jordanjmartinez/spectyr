/**
 * Phase 2 commit 2.4 (A1-B.3, ruled adjustments): Live Progress and
 * Reinforcement.
 *
 * - Toast trigger-list EXACTNESS (19.17): toasts fire for the enumerated
 *   triggers only (disposition results; action results rendered from the
 *   action response fields, shape-identical across targets; the coinciding
 *   readiness milestone). Read-only surfaces are structurally toast-free.
 * - T1 sealed-roster note (ruled): the remaining-count line renders only
 *   for a disposition inside a SEALED case roster; otherwise the toast
 *   confirms alone.
 * - Checklist LEAK RULE (19.18): the line set, order, and copy are
 *   identical for every incident regardless of the answer key; the ONE
 *   static consider-prompt is byte-identical and Guided-only (B-OD-5).
 * - Milestone fires on the observable false -> true readiness transition
 *   only; first sight of an already-ready card never toasts.
 */
import React from 'react';
import fs from 'fs';
import path from 'path';
import { render, screen, act, waitFor } from '@testing-library/react';

jest.mock('react-toastify', () => ({
  toast: jest.fn(),
  ToastContainer: () => null,
}));
jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { toast } = require('react-toastify');
const { apiFetch } = require('../api');

const {
  toastDisposition, toastActionResult, toastReady,
} = require('../components/uiToasts');
const { PhaseStrip } = require('../components/Incidents');
const Incidents = require('../components/Incidents').default;
const { CONSIDER_PROMPT } = require('../components/uiCopy');

beforeEach(() => {
  toast.mockClear();
  apiFetch.mockReset();
});

// --- T1 -------------------------------------------------------------------

test('T1: a disposition toast carries the remaining count only for a sealed case roster', () => {
  toastDisposition('promoted', 2);
  expect(toast).toHaveBeenLastCalledWith(
    'Promoted. 2 detections still need Promote or Dismiss.', { role: 'status' });
  toastDisposition('dismissed', null);      // unsealed / no sealed roster
  expect(toast).toHaveBeenLastCalledWith('Dismissed', { role: 'status' });
  toastDisposition('open', null);
  expect(toast).toHaveBeenLastCalledWith(
    'Reopened (needs review again)', { role: 'status' });
  toastDisposition('promoted', 0);          // zero: the milestone announces it
  expect(toast).toHaveBeenLastCalledWith('Promoted', { role: 'status' });
});

// --- T2/T3 ----------------------------------------------------------------

test('T2/T3: action toasts render only response fields, shape-identical across targets', () => {
  toastActionResult({ action: 'isolate_host', outcome: 'success',
    reason: null, target: { label: 'ACME-WS12' } });
  expect(toast).toHaveBeenLastCalledWith(
    'Isolate Host: ACME-WS12', { role: 'status' });
  // a different target, same shape (disposition-blind by construction)
  toastActionResult({ action: 'kill_process', outcome: 'success',
    reason: null, target: { label: 'helper.exe (PID 500) on ACME-WS77' } });
  expect(toast).toHaveBeenLastCalledWith(
    'Kill Process: helper.exe (PID 500) on ACME-WS77', { role: 'status' });
  // factual non-success outcomes surface the in-fiction reason verbatim
  toastActionResult({ action: 'isolate_host', outcome: 'failed_precondition',
    reason: 'The isolation command could not be delivered to the endpoint agent.',
    target: { label: 'ACME-OFF01' } });
  expect(toast).toHaveBeenLastCalledWith(
    'Isolate Host: The isolation command could not be delivered to the endpoint agent.',
    { role: 'status' });
  toastActionResult({ action: 'disable_account', outcome: 'no_op',
    reason: 'Account is already disabled.', target: { label: 'ACME\\jdoe' } });
  expect(toast).toHaveBeenLastCalledWith(
    'Disable Account: Account is already disabled.', { role: 'status' });
});

// --- T4/T5 (coinciding milestone) -----------------------------------------

const cards = (ready) => ({
  active: [{ incident_id: 'INC-1', title: 'T', briefing: 'b',
             severity: 'High', state: 'in_progress', sealed: true,
             triage: { total: 3, triaged: ready ? 3 : 2 },
             open_detections: ready ? 0 : 1, ready, related_actions: 0 }],
  completed: [], queue_length: 1, resolved_count: 0,
});

test('the milestone toast fires on the observable false -> true readiness transition only', async () => {
  let ready = false;
  apiFetch.mockImplementation((p) => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(
      p === '/api/incidents' ? cards(ready)
        : p.endsWith('/scope')
          ? { incident_id: 'INC-1', sealed: true, hosts: [], accounts: [], detection_ids: [] }
          : {}),
  }));
  jest.useFakeTimers();
  render(<Incidents gameMode="soc_queue" activeIncidentId={null}
    onSelectIncident={() => {}} />);
  await act(async () => {});
  expect(toast).not.toHaveBeenCalled();
  ready = true;
  act(() => { jest.advanceTimersByTime(3000); });
  await act(async () => {});
  expect(toast).toHaveBeenCalledWith(
    'All detections reviewed. INC-1 is ready to submit.', { role: 'status' });
  const calls = toast.mock.calls.length;
  act(() => { jest.advanceTimersByTime(6000); });
  await act(async () => {});
  expect(toast.mock.calls.length).toBe(calls);   // fires once, not per poll
  jest.useRealTimers();
});

test('first sight of an already-ready card never toasts (no transition observed)', async () => {
  apiFetch.mockImplementation((p) => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(
      p === '/api/incidents' ? cards(true)
        : p.endsWith('/scope')
          ? { incident_id: 'INC-1', sealed: true, hosts: [], accounts: [], detection_ids: [] }
          : {}),
  }));
  render(<Incidents gameMode="soc_queue" activeIncidentId={null}
    onSelectIncident={() => {}} />);
  await act(async () => {});
  expect(toast).not.toHaveBeenCalled();
});

// --- trigger-list exactness: read-only surfaces are toast-free -------------

test('read-only investigation surfaces never import the toast machinery (structural)', () => {
  for (const f of ['Siem.jsx', 'FieldSidebar.jsx', 'EventInspector.jsx',
                   'SiemTable.jsx', 'SiemCards.jsx', 'lcqlPivots.js',
                   'InvestigationContext.jsx']) {
    const src = fs.readFileSync(
      path.join(__dirname, '..', 'components', f), 'utf8');
    expect({ f, toasts: /react-toastify|uiToasts/.test(src) })
      .toEqual({ f, toasts: false });
  }
});

// --- the checklist leak rule (19.18) --------------------------------------

const stripLines = (container) =>
  Array.from(container.querySelectorAll('[data-testid="incident-checklist"] > div'))
    .map(d => d.textContent);

test('the checklist renders the identical line set and copy for different incidents (numbers aside)', () => {
  const a = render(<PhaseStrip sealed triage={{ total: 4, triaged: 1 }}
    related={2} ready={false} classification={null} showPrompt />);
  const b = render(<PhaseStrip sealed triage={{ total: 2, triaged: 2 }}
    related={0} ready classification="False Positive" showPrompt />);
  const norm = (lines) => lines.map(l => l.replace(/\d+/g, 'N')
    .replace(/Classification: .*$/, 'Classification: X')
    .replace('Ready to submit', 'READY').replace('Submit pending', 'READY'));
  const la = stripLines(a.container);
  const lb = stripLines(b.container);
  expect(la).toHaveLength(4);
  expect(lb).toHaveLength(4);
  expect(norm(la)).toEqual(norm(lb));
  // the static prompt is byte-identical for both incidents
  expect(la[2]).toContain(CONSIDER_PROMPT);
  expect(lb[2]).toContain(CONSIDER_PROMPT);
});

test('the consider-prompt is Guided-only (B-OD-5) and never carries a count', () => {
  const guided = render(<PhaseStrip sealed triage={{ total: 1, triaged: 0 }}
    related={0} ready={false} classification={null} showPrompt />);
  expect(guided.container.textContent).toContain(CONSIDER_PROMPT);
  const soc = render(<PhaseStrip sealed triage={{ total: 1, triaged: 0 }}
    related={0} ready={false} classification={null} showPrompt={false} />);
  expect(soc.container.textContent).not.toContain(CONSIDER_PROMPT);
  expect(CONSIDER_PROMPT).not.toMatch(/\d/);
});

test('the pre-seal checklist is the telemetry line alone', () => {
  render(<PhaseStrip sealed={false} triage={null} related={0} ready={false}
    classification={null} showPrompt />);
  expect(screen.getByText('Incident telemetry is still loading.')).toBeInTheDocument();
  expect(screen.queryByTestId('incident-checklist')).toBeNull();
});
