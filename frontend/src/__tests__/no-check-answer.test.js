/**
 * Visual pass V1 (permanent removal battery): the pre-submission
 * classification Check Answer workflow is GONE. Classification is a
 * workspace selection that feeds client submission readiness; its
 * correctness is disclosed ONLY across the submission boundary (the
 * submitted Learning Review). Guided and Hardcore reach correctness the
 * same way: Submit. The backend /api/incidents/<id>/check-answer endpoint
 * remains as intentionally dormant server capability (the frozen 3.9A
 * temporal leak-guard suite exercises it); nothing player-facing may call
 * or describe it.
 */
import React from 'react';
import fs from 'fs';
import path from 'path';
import { render, screen, fireEvent, within } from '@testing-library/react';
import Incidents from '../components/Incidents';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const INCIDENTS = {
  queue_length: 10, resolved_count: 0,
  active: [
    { incident_id: 'INC-2000', title: 'Open Incident', briefing: 'brief B', severity: 'High', state: 'in_progress', sealed: true, ready: false, open_detections: 2, triage: { total: 3, triaged: 1 } },
    { incident_id: 'INC-4000', title: 'Ready Incident', briefing: 'brief D', severity: 'Critical', state: 'in_progress', sealed: true, ready: true, open_detections: 0, triage: { total: 3, triaged: 3 } },
  ],
  completed: [],
};
const routeJson = (p) => {
  if (p === '/api/incidents') return INCIDENTS;
  if (p.endsWith('/scope')) return { incident_id: p.split('/')[3], sealed: true, hosts: ['ACME-WS10'], accounts: [], detection_ids: ['d1'] };
  if (p.endsWith('/submit')) return { state: 'submitted', assisted: false, grading: {} };
  return {};
};
beforeEach(() => {
  apiFetch.mockImplementation((p) => Promise.resolve({ ok: true, json: () => Promise.resolve(routeJson(p)) }));
});

// The shell-owned classification state, hosted the way Dashboard hosts it.
const Host = (props) => {
  const [chosen, setChosen] = React.useState({});
  return <Incidents chosen={chosen} setChosen={setChosen} {...props} />;
};

const classify = () =>
  fireEvent.click(within(screen.getByTestId('workspace-classification')).getByText('False Positive'));

test.each([['guided'], ['training'], ['hardcore'], ['analyst']])(
  'no Check Answer control renders in %s, even classified on a sealed incident',
  async (mode) => {
    const { container } = render(<Host gameMode={mode} activeIncidentId="INC-2000" />);
    await screen.findByText('brief B');
    classify();   // the exact conditions under which the control used to enable
    expect(screen.queryByText('Check Answer')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Check Answer' })).toBeNull();
    expect(container.textContent).not.toMatch(/check answer/i);
  },
);

test('no classification correctness is shown before submission', async () => {
  const { container } = render(<Host gameMode="guided" activeIncidentId="INC-4000" />);
  await screen.findByText('brief D');
  classify();
  // The workspace reflects the SELECTION (observable) but never a verdict
  // on it: none of the removed reveal vocabulary may render pre-submit.
  expect(screen.getByText('Classification: False Positive')).toBeInTheDocument();
  expect(container.textContent).not.toMatch(/classification correct/i);
  expect(container.textContent).not.toMatch(/not the right classification/i);
  expect(container.textContent).not.toMatch(/now marked/i);
});

test.each([['guided'], ['hardcore']])(
  '%s reaches classification correctness only through final submission',
  async (mode) => {
    render(<Host gameMode={mode} activeIncidentId="INC-4000" />);
    await screen.findByText('brief D');
    classify();
    const submit = screen.getByRole('button', { name: 'Submit' });
    expect(submit).not.toBeDisabled();
    fireEvent.click(submit);
    expect(await screen.findByText(/Filing as/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Submit Incident' }));
    // the ONE grading request is the submission boundary; nothing ever
    // calls the dormant check-answer endpoint
    await screen.findByText('brief D');
    const posts = apiFetch.mock.calls.filter(([, o]) => o && o.method === 'POST');
    expect(posts.map(([u]) => u)).toContain('/api/incidents/INC-4000/submit');
    expect(apiFetch.mock.calls.some(([u]) => String(u).includes('check-answer'))).toBe(false);
  },
);

test('classification selection still gates Submit exactly as before', async () => {
  render(<Host gameMode="guided" activeIncidentId="INC-4000" />);
  await screen.findByText('brief D');
  expect(screen.getByRole('button', { name: 'Submit' })).toBeDisabled();
  expect(screen.getByText('Select a classification to submit.')).toBeInTheDocument();
  classify();
  expect(screen.getByRole('button', { name: 'Submit' })).not.toBeDisabled();
});

test('no player-facing source references the Check Answer workflow', () => {
  // Source-level guard: components and pages carry neither the control
  // copy nor the dormant endpoint path. (Tests and this file excepted.)
  const roots = ['components', 'pages'].map((d) => path.join(__dirname, '..', d));
  const offenders = [];
  for (const root of roots) {
    for (const f of fs.readdirSync(root)) {
      if (!/\.(js|jsx)$/.test(f)) continue;
      const text = fs.readFileSync(path.join(root, f), 'utf8');
      // comments may record the REMOVAL itself; strip comments before scanning
      const code = text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
      if (/check.?answer/i.test(code)) offenders.push(f);
    }
  }
  expect(offenders).toEqual([]);
});
