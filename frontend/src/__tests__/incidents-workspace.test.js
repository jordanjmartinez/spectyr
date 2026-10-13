/**
 * Stage 3.9B (IA amendment), reshaped by the owner queue pass (2026-10-12):
 * the Incidents operational workspace. The left panel is the SESSION QUEUE
 * (header + fraction + every scenario slot in queue order; the view toggle
 * and search are retired); the detail panel is the decluttered working
 * surface (title-only header, link row, verdict card, sticky Submit
 * footer). No POST fires on render.
 */
import React from 'react';
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react';
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
  return {};
};
beforeEach(() => {
  apiFetch.mockImplementation((path) => Promise.resolve({ ok: true, json: () => Promise.resolve(routeJson(path)) }));
});

// A3.4 (ratified A3-OD-3): the classification selection state is
// shell-owned; interactive tests host it the way Dashboard does.
const Host = (props) => {
  const [chosen, setChosen] = React.useState({});
  return <Incidents chosen={chosen} setChosen={setChosen} {...props} />;
};

test('the left panel is the SESSION QUEUE: header, fraction, every slot in queue order', async () => {
  render(<Incidents gameMode="soc_queue" />);
  const queue = await screen.findByTestId('incident-queue');
  // the queue header matches the detail title's panel-heading treatment
  expect(within(queue).getByText('Incident Queue').className)
    .toMatch(/text-base font-semibold/);
  expect(await within(queue).findByText('2 of 10')).toBeInTheDocument();   // 1 resolved -> working slot 2
  // the view toggle and search are retired
  expect(screen.queryByText(/Active 3/)).toBeNull();
  expect(screen.queryByText(/Ready 0/)).toBeNull();
  expect(screen.queryByPlaceholderText('Search incidents...')).toBeNull();
  // queue order: completed (submission order), in-flight (drip order),
  // then the undripped slots as muted non-clickable placeholders
  const rows = [...queue.querySelector('.divide-y').children];
  expect(rows).toHaveLength(10);
  expect(rows[0].textContent).toContain('INC-3000');
  expect(rows[1].textContent).toContain('INC-3001');
  expect(rows[2].textContent).toContain('INC-1000');
  expect(rows[3].textContent).toContain('INC-2000');
  expect(rows[4].textContent).toContain('INC-4000');
  expect(rows[5].textContent).toBe('Scenario 6');
  expect(rows[9].textContent).toBe('Scenario 10');
  expect(rows[5].tagName).toBe('DIV');                     // not clickable
  // completed row: muted with a grade chip
  expect(rows[0].querySelector('.font-semibold').textContent).toBe('B');
  expect(rows[0].querySelector('.opacity-60')).not.toBeNull();
  // the working row: tinted, left accent bar, to-review count, progress bar
  expect(rows[3].className).toMatch(/bg-\[#16436b\]\/5/);
  expect(rows[3].querySelector('.w-\\[3px\\]')).not.toBeNull();
  expect(rows[3].textContent).toContain('2 to Review');
  expect(rows[3].querySelector('.bg-\\[\\#eef1f4\\]')).not.toBeNull();   // the triage progress track
  // the ready row: normal (no accent bar), readiness chip only
  expect(rows[4].className).not.toMatch(/bg-\[#16436b\]\/5/);
  expect(rows[4].textContent).toContain('Submit Pending');
  // the pre-seal row: in-flight treatment, Loading chip, no bar yet
  expect(rows[2].textContent).toContain('Loading');
  expect(rows[2].querySelector('.bg-\\[\\#eef1f4\\]')).toBeNull();      // no progress track pre-seal
});

test('the selected queue row carries its own highlight, independent of state styling', async () => {
  render(<Incidents gameMode="soc_queue" activeIncidentId="INC-2000" />);
  await screen.findByText('brief B');
  const row = screen.getAllByText('INC-2000')[0].closest('button');
  expect(row.className).toMatch(/ring-2 ring-inset/);
});

test('selecting a ready incident shows briefing + the always-enabled Submit in the sticky footer', async () => {
  const { container } = render(<Host gameMode="training" activeIncidentId="INC-4000" />);
  expect(await screen.findByText('brief D')).toBeInTheDocument();          // detail-only content
  // owner declutter (2026-10-12): the status checklist left the panel
  expect(screen.queryByTestId('incident-checklist')).toBeNull();
  expect(screen.queryByText('Detections Reviewed: 3 of 3')).toBeNull();
  // owner panel pass (2026-10-12): no duplicate header pills -- the detail
  // header is TITLE ONLY (pills live on the list row); no Clear selection
  expect(screen.queryByRole('button', { name: 'Clear selected incident' })).toBeNull();
  const header = screen.getByText('brief D').parentElement;   // the title+description block
  expect(header.querySelector('[data-testid="incident-id-badge"]')).toBeNull();
  expect(header.querySelector('[data-testid="severity-badge"]')).toBeNull();
  // owner refinement (2026-10-12): group labels at the card-title token
  // (the incident title stays the one hero); the Required tags are gone
  expect(container.querySelector('#verdict-group-label').getAttribute('class')).toContain('t-subsection');
  expect(container.querySelector('#category-group-label').getAttribute('class')).toContain('t-subsection');
  expect(screen.queryByText('Required')).toBeNull();
  expect(screen.queryByText('Not required')).toBeNull();
  // Submit stays ENABLED; an incomplete click shows the inline group error
  // and never opens the confirmation
  const submit = screen.getByRole('button', { name: 'Submit' });
  expect(submit).not.toBeDisabled();
  fireEvent.click(submit);
  expect(screen.getByRole('alert').textContent).toBe('Select a classification to submit.');
  expect(screen.queryByText(/Filing as/)).toBeNull();
  // owner footer refinement (2026-10-13): the Verdict/Category checklist
  // items are gone; the triaged incident shows the checked detections item
  expect(screen.getByText('Detections Triaged')).toBeInTheDocument();
  expect(screen.queryByText('Verdict')).toBeNull();
});

test('compact icon cards: leading outline icon, trailing check slot, four-column category grid', async () => {
  render(<Host gameMode="soc_queue" activeIncidentId="INC-4000" />);
  await screen.findByText('brief D');
  const ws = screen.getByTestId('workspace-classification');
  const radios = within(ws).getAllByRole('radio');
  expect(radios).toHaveLength(10);                       // 2 verdicts + 8 categories
  for (const r of radios) {
    expect(r.querySelector('svg')).not.toBeNull();       // leading neutral outline icon
    expect([...r.children].pop().className).toMatch(/ml-auto/);  // reserved trailing check slot
    expect(r.className).toMatch(/min-h-\[48px\]/);
  }
  // verdict pair: compact content-width cards in a wrapping row (no grid)
  const groups = within(ws).getAllByRole('radiogroup');
  expect(groups[0].className).toMatch(/flex flex-wrap/);
  // categories: the compact four-column grid (two below md)
  expect(groups[1].className).toMatch(/md:grid-cols-4/);
  // selecting fills the TRAILING slot only; the label and lead icon stand
  fireEvent.click(within(ws).getByText('True Positive'));
  const tp = within(ws).getAllByRole('radio').find((r) => r.textContent === 'True Positive');
  expect(tp.getAttribute('aria-checked')).toBe('true');
  expect([...tp.children].pop().querySelector('svg')).not.toBeNull();
});

test('a pre-seal incident renders the decluttered panel: no strip, no loading line, no verdict card, no footer', async () => {
  render(<Incidents gameMode="training" activeIncidentId="INC-1000" />);
  await screen.findByText('brief A');   // detail loaded
  // owner declutter (2026-10-12): the A2 loading line went with the strip
  expect(screen.queryByText('Incident telemetry is still loading.')).toBeNull();
  expect(screen.queryByTestId('incident-checklist')).toBeNull();
  expect(screen.queryByTestId('workspace-classification')).toBeNull();
  expect(screen.queryByTestId('submit-footer')).toBeNull();
  expect(screen.getByRole('button', { name: 'Triage Detections' })).toBeInTheDocument();
});

test('an open (not-ready) incident shows the action row with NO remaining-count text (owner declutter)', async () => {
  render(<Incidents gameMode="training" activeIncidentId="INC-2000" />);
  await screen.findByText('brief B');
  // owner refinement (2026-10-12): the row is plain "View X"-pattern text
  // links (navigation to a scoped workspace), not outline buttons; they hug
  // the panel's right side (2026-10-13)
  const triage = screen.getByRole('button', { name: 'Triage Detections' });
  expect(triage.className).toMatch(/text-\[#16436b\]/);
  expect(triage.className).not.toMatch(/border|rounded-md/);
  expect(triage.parentElement.className).toMatch(/justify-end/);
  // owner footer refinement (2026-10-13): the one persistent footer item is
  // the out-of-panel requirement, detections triage
  expect(screen.getByText('Detections: 2 to Triage')).toBeInTheDocument();
  expect(screen.queryByText('Detections Triaged')).toBeNull();
  expect(screen.queryByText(/still need Promote or Dismiss/)).toBeNull();
  // the Related Hosts / Accounts display is gone too
  expect(screen.queryByText(/Related Hosts:/)).toBeNull();
  expect(screen.queryByText(/Related Accounts:/)).toBeNull();
  expect(screen.queryByText('Loading incident scope')).toBeNull();
});

test('a submitted incident renders the Case Closed summary with the Review What You Learned path', async () => {
  // 5.4 translation of the retired "View Post-Incident Review" control: the
  // completed pane now renders the Case Closed summary inline (moment +
  // grade + achievements) and the path into the Metrics Learning Review.
  const onOpenLearningReview = jest.fn();
  render(<Incidents gameMode="training" activeIncidentId="INC-3000"
    onOpenLearningReview={onOpenLearningReview} />);
  expect(await screen.findByText('Case Closed: INC-3000')).toBeInTheDocument();
  const btn = await screen.findByRole('button', { name: 'Review What You Learned' });
  fireEvent.click(btn);
  expect(onOpenLearningReview).toHaveBeenCalledWith('INC-3000');
});

test('completed detail shows the Assisted badge iff the frozen record is assisted', async () => {
  // The badge renders SERVER RECORD truth (the immutable per-incident
  // `assisted` flag). Visual pass V1 removed the player-facing Check
  // Answer entry point, so in-product runs never mark it; the display
  // stays because the record schema keeps the field.
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

// (Visual pass V1: the two Check Answer workspace tests moved to the
// permanent removal battery, no-check-answer.test.js -- the control no
// longer exists in any mode.)

// --- the ratified A1-B.3.2 workspace selector (C1) + F4b gating (A3.4) ----

test('A1-B.3.2 (C1): the workspace selector is pure local input (no request, no checklist line)', async () => {
  render(<Host gameMode="soc_queue" activeIncidentId="INC-2000" />);
  await screen.findByText('brief B');
  // owner declutter (2026-10-12): the checklist Classification line is gone
  expect(screen.queryByText('Classification: Not Selected')).toBeNull();
  const ws = screen.getByTestId('workspace-classification');
  fireEvent.click(within(ws).getByText('False Positive'));
  expect(screen.queryByText('Classification: False Positive')).toBeNull();
  // local input only: no state-changing call fired
  const posts = apiFetch.mock.calls.filter(([, o]) => o && o.method && o.method !== 'GET');
  expect(posts).toHaveLength(0);
});

test('C1 (F4a): the threat path -- an incomplete Submit shows the Category group error; completing it proceeds', async () => {
  render(<Host gameMode="soc_queue" activeIncidentId="INC-4000" />);
  await screen.findByText('brief D');
  const ws = screen.getByTestId('workspace-classification');
  fireEvent.click(within(ws).getByText('True Positive'));
  // a threat verdict without a category is not yet a valid classification:
  // Submit stays enabled but lands on the Category inline error
  fireEvent.click(screen.getByRole('button', { name: 'Submit' }));
  expect(screen.getByRole('alert').textContent).toBe('Select a category to submit.');
  expect(screen.queryByText(/Filing as/)).toBeNull();
  // picking the category clears the error; Submit now opens the confirmation
  fireEvent.click(within(ws).getByText('Malware'));
  expect(screen.queryByRole('alert')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Submit' }));
  expect(await screen.findByText(/Filing as/)).toBeInTheDocument();
});

test('A3.4 (F4b): Submit opens the bare confirmation from the workspace selection; no data-entry step', async () => {
  render(<Host gameMode="training" activeIncidentId="INC-4000" />);
  await screen.findByText('brief D');
  fireEvent.click(within(screen.getByTestId('workspace-classification')).getByText('False Positive'));
  const submit = screen.getByRole('button', { name: 'Submit' });
  expect(submit).not.toBeDisabled();
  fireEvent.click(submit);
  // the bare confirmation names the filing; no classifier step exists
  expect(await screen.findByText(/Filing as/)).toBeInTheDocument();
  expect(screen.getByText('Submit incident INC-4000')).toBeInTheDocument();
  expect(screen.queryByTestId('classification-modal')).toBeNull();
});

test('A3.4 (A3-OD-3): the queue row chip derives Ready from the one shared state', async () => {
  render(<Host gameMode="soc_queue" activeIncidentId="INC-4000" />);
  await screen.findByText('brief D');
  // the id renders ONLY on the queue row now (the detail header is title-only)
  const row = screen.getAllByText('INC-4000')[0].closest('button');
  expect(row.textContent.endsWith('Submit Pending')).toBe(true);
  fireEvent.click(within(screen.getByTestId('workspace-classification')).getByText('False Positive'));
  expect(row.textContent.endsWith('Ready')).toBe(true);
  // (the view-count and checklist Ready surfaces are retired -- owner queue
  // pass 2026-10-12; the row chip and the footer checklist remain)
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
  fireEvent.click(screen.getByText('Clear and Pick Another'));       // confirm
  expect(onPracticeAnother).toHaveBeenCalled();
});

// --- VC follow-up: the exact submit payload the workspace sends ----------

test('the workspace submits the selected verdict AND category verbatim', async () => {
  render(<Host gameMode="guided" activeIncidentId="INC-4000" />);
  await screen.findByText('brief D');
  const ws = screen.getByTestId('workspace-classification');
  fireEvent.click(within(ws).getByText('True Positive'));
  fireEvent.click(within(ws).getByText('Defense Evasion'));
  // (the checklist Classification display is gone -- owner declutter; the
  // enabled Submit is the observable completion signal)
  expect(screen.getByRole('button', { name: 'Submit' })).not.toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Submit' }));
  await screen.findByText(/Filing as/);
  fireEvent.click(screen.getByRole('button', { name: 'Submit Incident' }));
  await waitFor(() => {
    const post = apiFetch.mock.calls.find(([u, o]) => String(u).endsWith('/submit') && o?.method === 'POST');
    expect(post).toBeDefined();
    expect(JSON.parse(post[1].body)).toEqual({ verdict: 'threat', category: 'Defense Evasion' });
  });
});
