/**
 * Stage 5 Phase 5 commit 5.4 (contract 7.1/7.5; A1-B.4; ratified B-OD-1
 * Option 1): the Learning Review home + the Case Closed payoff.
 * - The Metrics Learning Review renders the full frozen teaching content:
 *   the three acceptance-question sections with the frozen whys, the
 *   acceptable section (only when taken), the separately labeled attempt
 *   history, per-detection verdicts with correctness, the playbook, the
 *   MITRE/what-is-it education, and Key takeaway (ruling H: null omits).
 * - Achievements + Case Closed + all teaching derive from the SERVED frozen
 *   record only (acceptance 19: deterministic; reads only, no writes).
 * - ONE venue (19.19): the in-workspace Case Closed modal never renders
 *   teaching content; "Review what you learned" is the path to Metrics.
 * - 7.1 error state: failed fetch renders the one-line error + Retry.
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import LearningReview from '../components/LearningReview';
import Analytics from '../components/Analytics';
import Incidents from '../components/Incidents';
import { deriveAchievements } from '../components/achievements';
import {
  REVIEW_SECTION_CORRECT, REVIEW_SECTION_MISSED, REVIEW_SECTION_COLLATERAL,
  REVIEW_SECTION_ACCEPTABLE, REVIEW_SECTION_ATTEMPTS, REVIEW_SECTION_TAKEAWAY,
  correctDetectionCalls, NO_CORRECT_CALLS, NO_COMPLETED_REQUIRED,
  REVIEW_EMPTY_MISSED, REVIEW_EMPTY_COLLATERAL,
  BREAKDOWN_LOAD_ERROR, NO_SUBMITTED_INCIDENTS,
  SESSION_PERFORMANCE_LABEL, LEARNING_REVIEW_TITLE,
} from '../components/uiCopy';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');
const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

const INACTION_WHY = 'No response action was required. The correct response here was investigation without action.';

const REVIEW = {
  entries: [
    { bucket: 'completed', reason_code: 'required_completed', action: 'isolate_host',
      target_label: 'ACME-WS12', why: 'WHY-COMPLETED', source_action_seq: 1,
      expected_ref: 'isolate_host:ACME-WS12' },
    { bucket: 'missed', reason_code: 'required_attempt_failed', action: 'kill_process',
      target_label: 'payload.exe (PID 4756) on ACME-WS12', why: 'WHY-MISSED',
      source_action_seq: null, expected_ref: 'kill_process:ACME-WS12/4756' },
    { bucket: 'collateral', reason_code: 'collateral_in_scope', action: 'delete_file',
      target_label: 'C:\\clean\\doc.txt on ACME-WS12', why: 'WHY-COLLATERAL',
      source_action_seq: 3, expected_ref: null },
    { bucket: 'acceptable', reason_code: 'acceptable_completed', action: 'revoke_sessions',
      target_label: 'ACME\\nkhan', why: 'WHY-ACCEPTABLE', source_action_seq: 4,
      expected_ref: 'revoke_sessions:acme/nkhan' },
  ],
  attempt_history: [
    { seq: 2, action: 'kill_process', target_label: 'payload.exe (PID 4756) on ACME-WS12',
      outcome: 'failed_precondition', reason_code: 'failed_precondition' },
  ],
  detections: [
    { rule_name: 'Rule A', entity_label: 'ACME-WS12', your_call: 'promoted', correct: true },
    { rule_name: 'Rule B', entity_label: 'ACME-WS12', your_call: 'promoted', correct: false },
  ],
  scenario_rationale: 'TAKEAWAY-TEXT',
};
const GRADING = {
  classification: { grade: 'A', accuracy: 100 },
  detection: { grade: 'F', accuracy: 50, total: 2, correct: 1, wrong: 1, open: 0, graded: 2 },
  response: { grade: 'F', accuracy: 30, collateral: 1, required: 2, correct: 1, missed: 1, graded: 2 },
  composite: { grade: 'C', accuracy: 74 },
  response_review: REVIEW,
};
const SCORE_VIEW = { state: 'submitted', assisted: false, grading: GRADING };
const TRIAGE = {
  mitre: { id: 'T1091', name: 'Replication Through Removable Media' },
  what_is_it: { title: 'USB-Based Malware', description: 'EDU-DESCRIPTION' },
  response_actions: ['Playbook step one', 'Playbook step two'],
};
const COMPLETED_LIST = { active: [], completed: [
  { incident_id: 'INC-0001', title: 'Done Incident', state: 'submitted', severity: 'High',
    assisted: false, incident_grade: { grade: 'C', accuracy: 74 } },
] };

const routeReview = (scoreBody = SCORE_VIEW, triageBody = TRIAGE) => (path) => {
  if (path === '/api/incidents') return ok(COMPLETED_LIST);
  if (path.endsWith('/score')) return ok(scoreBody);
  if (path.endsWith('/triage-review')) return ok(triageBody);
  return ok({});
};

beforeEach(() => { apiFetch.mockReset(); });

const renderReview = async (scoreBody, triageBody) => {
  apiFetch.mockImplementation(routeReview(scoreBody, triageBody));
  let utils;
  await act(async () => {
    utils = render(<LearningReview reviewRequest={{ id: 'INC-0001', seq: 1 }} />);
  });
  return utils;
};

test('renders the full frozen teaching content with bucket routing, whys, verdicts, playbook, and takeaway', async () => {
  await renderReview();
  const detail = await screen.findByTestId('learning-review-detail');
  const d = within(detail);
  // the three acceptance-question sections + acceptable, each with its why
  expect(d.getByText(REVIEW_SECTION_CORRECT)).toBeInTheDocument();
  expect(d.getByText('WHY-COMPLETED')).toBeInTheDocument();
  expect(d.getByText(REVIEW_SECTION_MISSED)).toBeInTheDocument();
  expect(d.getByText('WHY-MISSED')).toBeInTheDocument();
  expect(d.getByText(REVIEW_SECTION_COLLATERAL)).toBeInTheDocument();
  expect(d.getByText('WHY-COLLATERAL')).toBeInTheDocument();
  expect(d.getByText(REVIEW_SECTION_ACCEPTABLE)).toBeInTheDocument();
  expect(d.getByText('WHY-ACCEPTABLE')).toBeInTheDocument();
  // attempt history: separately labeled, factual
  expect(d.getByText(REVIEW_SECTION_ATTEMPTS)).toBeInTheDocument();
  expect(d.getByText('(did not execute)')).toBeInTheDocument();
  // per-detection verdicts with correctness
  expect(d.getByText('Rule A')).toBeInTheDocument();
  expect(d.getByText('Correct')).toBeInTheDocument();
  expect(d.getByText('Wrong')).toBeInTheDocument();
  // C1 (F5a): the well bucket also reads the correct dispositions
  expect(d.getByText(correctDetectionCalls(1, 2))).toBeInTheDocument();
  // educational content + playbook (moved venue) + Key takeaway
  expect(d.getByText('USB-Based Malware')).toBeInTheDocument();
  expect(d.getByText('Playbook step one')).toBeInTheDocument();
  expect(d.getByText(REVIEW_SECTION_TAKEAWAY)).toBeInTheDocument();
  expect(d.getByText('TAKEAWAY-TEXT')).toBeInTheDocument();
  // achievements derive from the frozen record: collateral=1 and detection
  // 50% suppress No Collateral / Clean Triage; assisted=false earns Solo
  // Close; Case Closed carries the readiness-total subtitle
  const chips = within(d.getByTestId('achievements'));
  expect(chips.getByText('Case Closed')).toBeInTheDocument();
  expect(chips.getByText('All 2 detections reviewed')).toBeInTheDocument();
  expect(chips.getByText('Solo Close')).toBeInTheDocument();
  expect(chips.queryByText('No Collateral')).toBeNull();
  expect(chips.queryByText('Clean Triage')).toBeNull();
  expect(chips.queryByText('Perfect Case')).toBeNull();
});

test('ruling H: a null scenario_rationale omits the Key takeaway section', async () => {
  const grading = { ...GRADING, response_review: { ...REVIEW, scenario_rationale: null } };
  await renderReview({ ...SCORE_VIEW, grading });
  await screen.findByTestId('learning-review-detail');
  expect(screen.queryByText(REVIEW_SECTION_TAKEAWAY)).toBeNull();
  expect(screen.queryByText('TAKEAWAY-TEXT')).toBeNull();
  // the Tier 1 whys still teach
  expect(screen.getByText('WHY-COMPLETED')).toBeInTheDocument();
});

test('7.1 inaction empty state: the canonical entry answers "correct", every empty state names its category', async () => {
  const inactionReview = {
    entries: [{ bucket: 'inaction', reason_code: 'inaction_correct', action: null,
      target_label: null, why: INACTION_WHY, source_action_seq: null, expected_ref: 'inaction' }],
    attempt_history: [], detections: REVIEW.detections, scenario_rationale: null,
  };
  await renderReview({ ...SCORE_VIEW, grading: { ...GRADING, response_review: inactionReview } });
  const detail = await screen.findByTestId('learning-review-detail');
  const d = within(detail);
  expect(d.getByText(INACTION_WHY)).toBeInTheDocument();
  // C1 (F5a): category-named empty lines, never a bare global "None."
  expect(d.getByText(REVIEW_EMPTY_MISSED)).toBeInTheDocument();
  expect(d.getByText(REVIEW_EMPTY_COLLATERAL)).toBeInTheDocument();
  expect(d.queryByText('None.')).toBeNull();
  expect(d.queryByText(REVIEW_SECTION_ACCEPTABLE)).toBeNull(); // none taken
  expect(d.queryByText(REVIEW_SECTION_ATTEMPTS)).toBeNull();   // empty history
});

test('A1-B.4.1 conformance (C1, F5a): correct dispositions surface in the well bucket even with zero completed response actions', async () => {
  // The owner-observed defect case: strong classification and detection
  // work, missed response. The well bucket must state the correct calls,
  // and its response half names its own category instead of a bare None.
  const review = {
    entries: [
      { bucket: 'missed', reason_code: 'required_not_attempted', action: 'isolate_host',
        target_label: 'ACME-WS34', why: 'WHY-MISS-1', source_action_seq: null,
        expected_ref: 'isolate_host:ACME-WS34' },
      { bucket: 'missed', reason_code: 'required_not_attempted', action: 'remove_persistence',
        target_label: "WMI subscription 'WindowsUpdConsumer'", why: 'WHY-MISS-2',
        source_action_seq: null, expected_ref: 'remove_persistence:wmi' },
    ],
    attempt_history: [],
    detections: [
      { rule_name: 'R1', entity_label: 'H', your_call: 'promoted', correct: true },
      { rule_name: 'R2', entity_label: 'H', your_call: 'dismissed', correct: true },
      { rule_name: 'R3', entity_label: 'H', your_call: 'promoted', correct: true },
      { rule_name: 'R4', entity_label: 'H', your_call: 'promoted', correct: false },
      { rule_name: 'R5', entity_label: 'H', your_call: 'dismissed', correct: false },
    ],
    scenario_rationale: null,
  };
  const grading = { ...GRADING,
    classification: { grade: 'A', accuracy: 100 },
    response_review: review };
  await renderReview({ ...SCORE_VIEW, grading });
  const d = within(await screen.findByTestId('learning-review-detail'));
  expect(d.getByText(correctDetectionCalls(3, 5))).toBeInTheDocument();
  expect(d.getByText(NO_COMPLETED_REQUIRED)).toBeInTheDocument();
  expect(d.queryByText(NO_CORRECT_CALLS)).toBeNull();
  expect(d.getByText('WHY-MISS-1')).toBeInTheDocument();
  expect(d.getByText('WHY-MISS-2')).toBeInTheDocument();
  expect(d.queryByText('None.')).toBeNull();
});

test('acceptance 19: the review is deterministic from the served record and issues no writes', async () => {
  const first = await renderReview();
  const text1 = (await screen.findByTestId('learning-review-detail')).textContent;
  first.unmount();
  await renderReview();
  const text2 = (await screen.findByTestId('learning-review-detail')).textContent;
  expect(text2).toBe(text1);
  const writes = apiFetch.mock.calls.filter(([, o]) => o && o.method && o.method !== 'GET');
  expect(writes).toHaveLength(0);
});

test('7.1 error state: failed score fetch renders the one-line error and Retry recovers', async () => {
  let fail = true;
  apiFetch.mockImplementation((path) => {
    if (path === '/api/incidents') return ok(COMPLETED_LIST);
    if (path.endsWith('/score')) return fail ? Promise.reject(new Error('net')) : ok(SCORE_VIEW);
    if (path.endsWith('/triage-review')) return ok(TRIAGE);
    return ok({});
  });
  await act(async () => { render(<LearningReview reviewRequest={{ id: 'INC-0001', seq: 1 }} />); });
  expect(await screen.findByText(BREAKDOWN_LOAD_ERROR)).toBeInTheDocument();
  fail = false;
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Retry' })); });
  expect(await screen.findByTestId('learning-review-detail')).toBeInTheDocument();
  expect(screen.queryByText(BREAKDOWN_LOAD_ERROR)).toBeNull();
});

test('19.19 one venue: the Case Closed modal after submit carries the moment + achievements + the path, never teaching content', async () => {
  const onOpenLearningReview = jest.fn();
  const LIST = { queue_length: 1, resolved_count: 0, active: [
    { incident_id: 'INC-4000', title: 'Ready Incident', briefing: 'brief', severity: 'High',
      state: 'in_progress', sealed: true, ready: true, open_detections: 0,
      triage: { total: 2, triaged: 2 } }], completed: [] };
  apiFetch.mockImplementation((path, opts) => {
    if (opts && opts.method === 'POST' && path.endsWith('/submit')) return ok({ state: 'submitted' });
    if (path === '/api/incidents') return ok(LIST);
    if (path.endsWith('/scope')) return ok({ incident_id: 'INC-4000', hosts: [], accounts: [] });
    if (path.endsWith('/score')) return ok(SCORE_VIEW);
    return ok({});
  });
  const Host = (props) => {
    const [chosen, setChosen] = React.useState({});
    return <Incidents chosen={chosen} setChosen={setChosen} {...props} />;
  };
  render(<Host gameMode="soc_queue" activeIncidentId="INC-4000"
    onOpenLearningReview={onOpenLearningReview} />);
  // A3.4 (F4b): classification is a workspace step; Submit opens the bare
  // confirmation directly (the classifier modal is retired).
  fireEvent.click(within(await screen.findByTestId('workspace-classification')).getByText('False Positive'));
  fireEvent.click(screen.getByRole('button', { name: 'Submit' }));
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Submit Incident' })); });
  const modal = await screen.findByTestId('case-closed-modal');
  const m = within(modal);
  expect(m.getByText('Case Closed: INC-4000')).toBeInTheDocument();
  expect(m.getByText('Solo Close')).toBeInTheDocument();      // achievements render
  // NEVER teaching content: no section headers, no whys, no takeaway
  for (const marker of [REVIEW_SECTION_CORRECT, REVIEW_SECTION_MISSED,
    REVIEW_SECTION_COLLATERAL, 'WHY-COMPLETED', 'WHY-MISSED', 'WHY-COLLATERAL',
    'TAKEAWAY-TEXT']) {
    expect(m.queryByText(marker)).toBeNull();
  }
  fireEvent.click(m.getByRole('button', { name: 'Review what you learned' }));
  expect(onOpenLearningReview).toHaveBeenCalledWith('INC-4000');
  expect(screen.queryByTestId('case-closed-modal')).toBeNull(); // closes to the venue
});

test('the Metrics tab keeps the labeling split: Learning Review (Incident Grade) above Session Performance', async () => {
  apiFetch.mockImplementation((path) => {
    if (path === '/api/analytics/report_card') return ok({ state: 'in_progress', progress: { submitted: 0 } });
    if (path === '/api/current-level') return ok({});
    if (path === '/api/analytics/action_history') return ok([]);
    if (path === '/api/incidents') return ok({ active: [], completed: [] });
    return ok({});
  });
  await act(async () => { render(<Analytics isVisible={false} />); });
  expect(screen.getByText(LEARNING_REVIEW_TITLE)).toBeInTheDocument();
  expect(screen.getByText(SESSION_PERFORMANCE_LABEL)).toBeInTheDocument();
  expect(screen.getByText(NO_SUBMITTED_INCIDENTS)).toBeInTheDocument();
});

test('achievement derivations match the ratified A1-B.4.3 table exactly', () => {
  const mk = (over = {}, assisted = false) => deriveAchievements({
    state: 'submitted', assisted,
    grading: {
      detection: { accuracy: 100, total: 3 },
      response: { accuracy: 100, collateral: 0 },
      composite: { accuracy: 100 },
      ...over,
    },
  }).map(a => a.key);
  expect(mk()).toEqual(['case_closed', 'clean_triage', 'response_ready', 'no_collateral', 'solo_close', 'perfect_case']);
  expect(mk({ detection: { accuracy: 99, total: 3 } })).not.toContain('clean_triage');
  expect(mk({ response: { accuracy: 99, collateral: 0 } })).not.toContain('response_ready');
  expect(mk({ response: { accuracy: 100, collateral: 1 } })).not.toContain('no_collateral');
  expect(mk({ composite: { accuracy: 99.9 } })).not.toContain('perfect_case');
  expect(mk({}, true)).not.toContain('solo_close');
  expect(deriveAchievements({ state: 'in_progress' })).toEqual([]);
  expect(deriveAchievements(null)).toEqual([]);
});
