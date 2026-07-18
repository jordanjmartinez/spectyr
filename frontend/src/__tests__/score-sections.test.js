/**
 * Option A score sections (3b checkpoint ruling): Detections and Response
 * render as independent scored sections; the Response card surfaces failed
 * attempts factually; ungraded renders "-"; clean copy (no em dashes); no
 * answer-key material in the fixtures' payload shapes.
 */
import React from 'react';
import { render, screen } from '@testing-library/react';
import ScoreSections from '../components/ScoreSections';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const DET_SCORE = {
  tp_promoted: 3, tp_dismissed: 1, fp_dismissed: 2, fp_promoted: 0,
  benign_dismissed: 1, benign_promoted: 0, open: 4,
  correct: 6, wrong: 1, graded: 7, total: 11, accuracy: 85.7, grade: 'B',
};

const ACT_SCORE = {
  required: 3, correct: 2, missed: 1, collateral: 1, order_violations: 1,
  graded: 4, accuracy: 50.0, grade: 'F',
  not_executed: {
    count: 1,
    entries: [{ seq: 4, timestamp: '2026-07-17T12:00:04+00:00',
      action: 'isolate_host', outcome: 'failed_precondition',
      reason: 'Host is offline. The isolation command could not be delivered to the endpoint agent.',
      target: { id: 'ent-aaaa11112222', kind: 'host', label: 'ACME-OFF01' } }],
  },
  no_effect: {
    count: 1,
    entries: [{ seq: 5, timestamp: '2026-07-17T12:00:05+00:00',
      action: 'disable_account', outcome: 'no_op',
      reason: 'Account is already disabled.',
      target: { id: 'ent-cccc11112222', kind: 'account', label: 'ACME\\nkhan' } }],
  },
  acceptable_taken: {
    count: 1,
    entries: [{ seq: 2, timestamp: '2026-07-17T12:00:02+00:00',
      action: 'kill_process', outcome: 'success', reason: null,
      target: { id: 'ent-bbbb11112222', kind: 'process', label: 'cmd.exe (PID 6240) on ACME-WS12' } }],
  },
};

const UNGRADED_ACT = {
  required: 0, correct: 0, missed: 0, collateral: 0, order_violations: 0,
  graded: 0, accuracy: 0.0, grade: '-',
  not_executed: { count: 0, entries: [] },
  no_effect: { count: 0, entries: [] },
  acceptable_taken: { count: 0, entries: [] },
};

const mockScores = (act) => {
  apiFetch.mockImplementation((path) => {
    if (path === '/api/analytics/detection_score') {
      return Promise.resolve({ ok: true, json: () => Promise.resolve(DET_SCORE) });
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve(act) });
  });
};

test('renders both sections with grades, counts, and factual failed attempts', async () => {
  mockScores(ACT_SCORE);
  const { container } = render(<ScoreSections isVisible />);
  expect(screen.getByText('Detections')).toBeInTheDocument();
  expect(screen.getByText('Response')).toBeInTheDocument();
  expect(await screen.findByText('B')).toBeInTheDocument();
  expect(await screen.findByText('F')).toBeInTheDocument();
  expect(screen.getByText('85.7% accuracy')).toBeInTheDocument();
  expect(screen.getByText('collateral')).toBeInTheDocument();
  expect(screen.getByText('out of order')).toBeInTheDocument();
  // the three factual blocks, no editorial labels
  expect(screen.getByText('Attempted, not executed (1)')).toBeInTheDocument();
  expect(screen.getByText('ACME-OFF01')).toBeInTheDocument();
  expect(container.textContent).toMatch(/isolation command could not be delivered/);
  expect(screen.getByText('Acceptable response (1)')).toBeInTheDocument();
  expect(screen.getByText('cmd.exe (PID 6240) on ACME-WS12')).toBeInTheDocument();
  expect(screen.getByText('No effect, already in state (1)')).toBeInTheDocument();
  expect(container.textContent).not.toMatch(/—/);
});

test('ungraded response renders dash without the attempts block', async () => {
  mockScores(UNGRADED_ACT);
  render(<ScoreSections isVisible />);
  expect(screen.getByText('Response')).toBeInTheDocument();
  expect(await screen.findByText('B')).toBeInTheDocument(); // detections graded
  expect(screen.getByText('-')).toBeInTheDocument();        // response ungraded
  expect(screen.getAllByText('Not graded yet').length).toBeGreaterThanOrEqual(1);
  expect(screen.queryByText(/Attempted, not executed/)).toBeNull();
});
