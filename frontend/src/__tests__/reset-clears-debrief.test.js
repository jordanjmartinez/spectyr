/**
 * Stage 6 playtest fix: a reset kills the dead run's debrief.
 *
 * The Case Closed modal holds a frozen copy of the submitted incident's
 * grading in workspace-local state; before the fix a Reset Simulation left
 * it (and the other run-scoped local state) on screen until a full reload.
 * Pinned here: bumping resetTrigger unmounts the open debrief.
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import Incidents from '../components/Incidents';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');
const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

const GRADING = {
  classification: { grade: 'A', accuracy: 100 },
  detection: { grade: 'A', accuracy: 100, total: 2, correct: 2, wrong: 0, open: 0, graded: 2 },
  response: { grade: 'A', accuracy: 100, collateral: 0, required: 0, correct: 0, missed: 0, graded: 0 },
  composite: { grade: 'A', accuracy: 100 },
};
const SCORE_VIEW = { state: 'submitted', assisted: false, grading: GRADING };
const LIST = {
  queue_length: 1, resolved_count: 0,
  active: [
    { incident_id: 'INC-4000', title: 'Ready Incident', briefing: 'brief', severity: 'High',
      state: 'in_progress', sealed: true, ready: true, open_detections: 0,
      triage: { total: 2, triaged: 2 } },
  ],
  completed: [],
};

beforeEach(() => {
  apiFetch.mockReset();
  apiFetch.mockImplementation((path, opts) => {
    if (opts && opts.method === 'POST' && path.endsWith('/submit')) return ok({ state: 'submitted' });
    if (path === '/api/incidents') return ok(LIST);
    if (path.endsWith('/scope')) return ok({ incident_id: 'INC-4000', hosts: [], accounts: [] });
    if (path.endsWith('/score')) return ok(SCORE_VIEW);
    return ok({});
  });
});

const Host = ({ resetTrigger = 0, ...props }) => {
  const [chosen, setChosen] = React.useState({});
  return <Incidents chosen={chosen} setChosen={setChosen} resetTrigger={resetTrigger} {...props} />;
};

test('a reset unmounts the open Case Closed debrief', async () => {
  const view = render(<Host resetTrigger={0} gameMode="soc_queue" activeIncidentId="INC-4000" />);
  // Submit the incident to open the debrief (the real flow: classify,
  // Submit, confirm).
  fireEvent.click(within(await screen.findByTestId('workspace-classification')).getByText('False Positive'));
  fireEvent.click(screen.getByRole('button', { name: 'Submit' }));
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Submit Incident' })); });
  expect(await screen.findByTestId('case-closed-modal')).toBeInTheDocument();

  // Reset Simulation lands: the shell bumps resetTrigger. The dead run's
  // debrief must leave with it, without a reload.
  await act(async () => {
    view.rerender(<Host resetTrigger={1} gameMode="soc_queue" activeIncidentId="INC-4000" />);
  });
  expect(screen.queryByTestId('case-closed-modal')).toBeNull();
});
