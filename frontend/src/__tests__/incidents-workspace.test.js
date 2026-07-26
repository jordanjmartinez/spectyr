/**
 * Stage 3.9B (IA amendment): the Incidents operational workspace. Verifies the
 * Active/Ready/Completed views + search, stable incident rows, the selected-
 * incident detail (briefing + phase strip incl. the A2 pre-seal line + related
 * hosts/accounts), and that the graded Submit/Resume/Review controls live here.
 * Both neutral readiness messages are reachable; no POST fires on render.
 */
import React from 'react';
import { render, screen, waitFor, fireEvent, within, act } from '@testing-library/react';
import Incidents from '../components/Incidents';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const INCIDENTS = {
  queue_length: 10, resolved_count: 1,
  active: [
    { incident_id: 'INC-1000', title: 'Loading Incident', briefing: 'brief A', severity: 'High', state: 'in_progress', sealed: false },
    { incident_id: 'INC-2000', title: 'Open Incident', briefing: 'brief B', severity: 'High', state: 'in_progress', sealed: true, ready: false, open_detections: 2, triage: { total: 3, triaged: 1 } },
    { incident_id: 'INC-4000', title: 'Ready Incident', briefing: 'brief D', severity: 'Critical', state: 'in_progress', sealed: true, ready: true, open_detections: 0, triage: { total: 3, triaged: 3 } },
  ],
  completed: [
    { incident_id: 'INC-3000', title: 'Done Incident', briefing: 'brief C', severity: 'Medium', state: 'submitted', assisted: false, submitted_at: '2026-07-19T12:00:00Z', incident_grade: { grade: 'B', accuracy: 84.0 } },
    { incident_id: 'INC-3001', title: 'Assisted Incident', briefing: 'brief E', severity: 'Low', state: 'submitted', assisted: true, submitted_at: '2026-07-19T12:05:00Z', incident_grade: { grade: 'A', accuracy: 100.0 } },
  ],
};
const scopeFor = (id) => ({ incident_id: id, sealed: true, hosts: ['ACME-WS10'], accounts: ['ACME\\u'], detection_ids: ['d1'], triage: { total: 3, triaged: 0 } });
const GRADE = { grade: 'A', accuracy: 100 };
const routeJson = (path) => {
  if (path === '/api/incidents') return INCIDENTS;
  if (path === '/api/actions') return [];
  if (path.endsWith('/scope')) return scopeFor(path.split('/')[3]);
  if (path.endsWith('/score')) return { state: 'submitted', assisted: false, grading: { classification: GRADE, detection: GRADE, response: GRADE, composite: GRADE } };
  if (path.endsWith('/triage-review')) return { what_is_it: { title: 'What', description: 'Why' } };
  if (path.endsWith('/check-answer')) return { assisted: true, classification: { correct: true, your_category: 'False Positive', actual_category: 'False Positive' } };
  return {};
};
beforeEach(() => {
  apiFetch.mockImplementation((path) => Promise.resolve({ ok: true, json: () => Promise.resolve(routeJson(path)) }));
});

test('renders the workspace: Active/Ready/Completed views + search + rows', async () => {
  render(<Incidents gameMode="training" />);
  expect(await screen.findByText(/Active 3/)).toBeInTheDocument();
  expect(screen.getByText(/Ready 1/)).toBeInTheDocument();
  expect(screen.getByText(/Completed 2/)).toBeInTheDocument();
  expect(screen.getByPlaceholderText('Search incidents...')).toBeInTheDocument();
  expect(screen.getByText('INC-2000')).toBeInTheDocument();   // a row
});

test('selecting a ready incident shows briefing + Submit control (graded control home)', async () => {
  render(<Incidents gameMode="training" activeIncidentId="INC-4000" />);
  expect(await screen.findByText('brief D')).toBeInTheDocument();          // detail-only content
  expect(screen.getByText('Detections reviewed: 3 of 3')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Submit' })).toBeInTheDocument();
});

test('a pre-seal incident shows the A2 telemetry-loading line', async () => {
  render(<Incidents gameMode="training" activeIncidentId="INC-1000" />);
  await screen.findByText('brief A');   // detail loaded
  expect(screen.getAllByText('Incident telemetry is still loading.').length).toBeGreaterThanOrEqual(1);
});

test('an open (not-ready) incident shows the observable readiness message', async () => {
  render(<Incidents gameMode="training" activeIncidentId="INC-2000" />);
  expect(await screen.findByText(/2 detections still need Promote or Dismiss/)).toBeInTheDocument();
});

test('a submitted incident renders the Case Closed summary with the Review what you learned path', async () => {
  // 5.4 translation of the retired "View Post-Incident Review" control: the
  // completed pane now renders the Case Closed summary inline (moment +
  // grade + achievements) and the path into the Metrics Learning Review.
  const onOpenLearningReview = jest.fn();
  render(<Incidents gameMode="training" activeIncidentId="INC-3000"
    onOpenLearningReview={onOpenLearningReview} />);
  expect(await screen.findByText('Case Closed: INC-3000')).toBeInTheDocument();
  const btn = await screen.findByRole('button', { name: 'Review what you learned' });
  fireEvent.click(btn);
  expect(onOpenLearningReview).toHaveBeenCalledWith('INC-3000');
});

test('completed detail shows the Assisted badge iff Check Answer was used', async () => {
  // assisted submitted incident -> badge shows
  const a = render(<Incidents gameMode="training" activeIncidentId="INC-3001" />);
  expect(await screen.findByText('brief E')).toBeInTheDocument();
  expect(screen.getByText('Assisted')).toBeInTheDocument();
  a.unmount();
  // unassisted submitted incident -> no badge
  render(<Incidents gameMode="training" activeIncidentId="INC-3000" />);
  expect(await screen.findByText('brief C')).toBeInTheDocument();
  expect(screen.queryByText('Assisted')).toBeNull();
});

test('issues no state-changing (POST) call on render', async () => {
  render(<Incidents gameMode="training" activeIncidentId="INC-4000" />);
  await waitFor(() => expect(apiFetch).toHaveBeenCalledWith('/api/incidents'));
  const posts = apiFetch.mock.calls.filter(([, o]) => o && o.method && o.method !== 'GET');
  expect(posts).toHaveLength(0);
});

test('Check Answer is offered in Guided on a sealed incident, and hidden in Hardcore', async () => {
  const g = render(<Incidents gameMode="training" activeIncidentId="INC-2000" />);   // guided, sealed
  expect(await g.findByText('Check Answer')).toBeInTheDocument();
  g.unmount();
  render(<Incidents gameMode="hardcore" activeIncidentId="INC-2000" />);
  await screen.findByText('brief B');
  expect(screen.queryByText('Check Answer')).toBeNull();
});

test('Check Answer reads nested classification.correct and marks Assisted', async () => {
  render(<Incidents gameMode="training" activeIncidentId="INC-2000" />);   // guided, sealed
  fireEvent.click(await screen.findByText('Check Answer'));
  // C1 (F4a): the workspace selector also renders 'False Positive'; the
  // check flow's click is scoped to the modal (FP path -> immediate check).
  const cmodal = await screen.findByTestId('classification-modal');
  fireEvent.click(within(cmodal).getByText('False Positive'));
  expect(await screen.findByText('Classification correct')).toBeInTheDocument();
  expect(screen.getByText(/now marked/)).toBeInTheDocument();   // Assisted note
});

// --- C1 checkpoint fix (F4a): the ratified A1-B.3.2 workspace selector ----

test('A1-B.3.2 (C1): the workspace selector drives the checklist Classification line before Submit', async () => {
  render(<Incidents gameMode="soc_queue" activeIncidentId="INC-2000" />);
  await screen.findByText('brief B');
  expect(screen.getByText('Classification: not selected')).toBeInTheDocument();
  const ws = screen.getByTestId('workspace-classification');
  fireEvent.click(within(ws).getByText('False Positive'));
  expect(screen.getByText('Classification: False Positive')).toBeInTheDocument();
  expect(screen.queryByText('Classification: not selected')).toBeNull();
  // local input only: no state-changing call fired
  const posts = apiFetch.mock.calls.filter(([, o]) => o && o.method && o.method !== 'GET');
  expect(posts).toHaveLength(0);
});

test('C1 (F4a): the workspace threat path reveals the inline category step and completes the line', async () => {
  render(<Incidents gameMode="soc_queue" activeIncidentId="INC-2000" />);
  await screen.findByText('brief B');
  const ws = screen.getByTestId('workspace-classification');
  fireEvent.click(within(ws).getByText('True Positive'));
  // a threat verdict without a category is not yet a valid classification
  expect(screen.getByText('Classification: not selected')).toBeInTheDocument();
  fireEvent.click(within(ws).getByText('Malware'));
  expect(screen.getByText('Classification: Malware')).toBeInTheDocument();
});

test('C1 (F4a): the submit modal flow is unchanged and arrives pre-filled from the workspace selection', async () => {
  render(<Incidents gameMode="training" activeIncidentId="INC-4000" />);
  await screen.findByText('brief D');
  fireEvent.click(within(screen.getByTestId('workspace-classification')).getByText('False Positive'));
  fireEvent.click(screen.getByRole('button', { name: 'Submit' }));
  // the classifier modal still opens (flow unchanged), pre-filled
  const modal = await screen.findByTestId('classification-modal');
  expect(within(modal).getByText('False Positive').closest('button'))
    .toHaveAttribute('aria-pressed', 'true');
  expect(within(modal).getByText('True Positive').closest('button'))
    .toHaveAttribute('aria-pressed', 'false');
  // the verdict still requires its explicit click before the confirm step
  await act(async () => { fireEvent.click(within(modal).getByText('False Positive')); });
  expect(await screen.findByText(/Filing as/)).toBeInTheDocument();
});

test('C1 (F4a): no workspace selector before the roster seals', async () => {
  render(<Incidents gameMode="training" activeIncidentId="INC-1000" />);
  await screen.findByText('brief A');
  expect(screen.queryByTestId('workspace-classification')).toBeNull();
});

test('Practice Another (Guided) warns, cancels back, and calls back on confirm', async () => {
  // 5.4: Practice Another lives in the completed pane's Case Closed summary
  // (the modal is the submit-success moment only).
  const onPracticeAnother = jest.fn();
  render(<Incidents gameMode="training" activeIncidentId="INC-3000" onPracticeAnother={onPracticeAnother} />);
  fireEvent.click(await screen.findByText('Practice Another'));
  expect(screen.getByText(/clears the current Guided run/)).toBeInTheDocument();
  fireEvent.click(screen.getByText('Cancel'));                       // cancel keeps the summary
  expect(screen.queryByText(/clears the current Guided run/)).toBeNull();
  expect(onPracticeAnother).not.toHaveBeenCalled();
  fireEvent.click(screen.getByText('Practice Another'));
  fireEvent.click(screen.getByText('Clear and pick another'));       // confirm
  expect(onPracticeAnother).toHaveBeenCalled();
});
