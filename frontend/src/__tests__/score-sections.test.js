/**
 * Stage 3d composite sections, compacted by the Final pass (III.0 item 6):
 * ONE compact responsive summary -- the Overall grade exactly once, then
 * Classification / Detections / Response as three equal columns with the
 * same values and calculations; the factual teaching blocks remain
 * beneath; ungraded renders "-"; clean copy (no em dashes).
 *
 * Stage 3.9A: ScoreSections reads the SUBMISSION-GATED grading from its report
 * prop (report.detection / report.response, aggregated over submitted
 * incidents). It no longer polls detection_score / action_score, so these
 * tests pass the grading in directly.
 */
import React from 'react';
import { render, screen } from '@testing-library/react';
import ScoreSections from '../components/ScoreSections';

const DETECTION = {
  correct: 6, wrong: 1, open: 4, graded: 7, accuracy: 85.7, grade: 'B',
};

const RESPONSE = {
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

const UNGRADED_RESPONSE = {
  required: 0, correct: 0, missed: 0, collateral: 0, order_violations: 0,
  graded: 0, accuracy: 0.0, grade: '-',
  not_executed: { count: 0, entries: [] },
  no_effect: { count: 0, entries: [] },
  acceptable_taken: { count: 0, entries: [] },
};

const REPORT = {
  threats_caught: 4, wrong_category: 0, fp_identified: 2, fp_missed: 0,
  composite: {
    accuracy: 79.0, grade: 'C',
    weights: { classification: 40, detection: 30, response: 30 },
    components: {
      classification: { accuracy: 100.0, grade: 'A', graded: 6, weight: 40 },
      detection: { accuracy: 85.7, grade: 'B', graded: 7, weight: 30 },
      response: { accuracy: 50.0, grade: 'F', graded: 4, weight: 30 },
    },
  },
  detection: DETECTION,
  response: RESPONSE,
};

test('the compact summary shows the Overall grade exactly once, columns in accessible order (III.0 item 6)', () => {
  const { container } = render(<ScoreSections isVisible report={REPORT} />);
  expect(screen.getByText('Overall grade')).toBeInTheDocument();
  // the composite grade renders once, never repeated per column
  expect(screen.getAllByText('C')).toHaveLength(1);
  // DOM (reading) order: Overall, then the three equal columns
  const text = container.textContent;
  expect(text.indexOf('Overall grade')).toBeLessThan(text.indexOf('Classification'));
  expect(text.indexOf('Classification')).toBeLessThan(text.indexOf('Detections'));
  expect(text.indexOf('Detections')).toBeLessThan(text.indexOf('Response'));
});

test('renders all three sections with grades, counts, and factual failed attempts', () => {
  const { container } = render(<ScoreSections isVisible report={REPORT} />);
  // all three components render inside the one compact summary
  expect(screen.getByText('Classification')).toBeInTheDocument();
  expect(screen.getByText('Detections')).toBeInTheDocument();
  expect(screen.getByText('Response')).toBeInTheDocument();
  expect(screen.getByText('A')).toBeInTheDocument(); // classification grade
  expect(screen.getByText('B')).toBeInTheDocument(); // detection grade
  expect(screen.getByText('F')).toBeInTheDocument(); // response grade
  expect(screen.getByText('threats caught')).toBeInTheDocument();
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

test('ungraded response renders dash without the attempts block', () => {
  const rpt = {
    ...REPORT,
    response: UNGRADED_RESPONSE,
    composite: { ...REPORT.composite, components: {
      ...REPORT.composite.components,
      response: { accuracy: null, grade: '-', graded: 0, weight: 30 },
    } },
  };
  render(<ScoreSections isVisible report={rpt} />);
  expect(screen.getByText('Response')).toBeInTheDocument();
  expect(screen.getByText('B')).toBeInTheDocument(); // detections graded
  expect(screen.getByText('-')).toBeInTheDocument(); // response ungraded
  expect(screen.getAllByText('Not graded yet').length).toBeGreaterThanOrEqual(1);
  expect(screen.queryByText(/Attempted, not executed/)).toBeNull();
});

// --- Visual pass V10: presentation changed, values did not -------------------

test('V10: the three-cards treatment keeps every served value and adds no trend', () => {
  const { container } = render(<ScoreSections isVisible report={REPORT} />);
  // the same served numbers render (nothing recomputed client-side)
  expect(screen.getByText('79% accuracy')).toBeInTheDocument();    // composite
  expect(screen.getByText('100% accuracy')).toBeInTheDocument();   // classification
  expect(screen.getByText('85.7% accuracy')).toBeInTheDocument();  // detections
  expect(screen.getByText('50% accuracy')).toBeInTheDocument();    // response
  // no invented trend, delta, or history vocabulary
  expect(container.textContent).not.toMatch(/vs last|trend|change from|previous session|[+-]\d+(\.\d+)?%/i);
});
