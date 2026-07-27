/**
 * VA1 (amendment sections 1-3): the redundant "All activity" scope
 * furniture is gone from SIEM, Detections, Endpoints, and Response; each
 * page carries ONE concise functional subtitle and, when an incident is
 * active, the incident context EXACTLY ONCE as a compact pill. No
 * decorative organization branding remains in workspace subtitles, and
 * no page repeats "Investigating INC-####".
 */
import React from 'react';
import fs from 'fs';
import path from 'path';
import { render, screen } from '@testing-library/react';
import Detections from '../components/Detections';
import Endpoints from '../components/Endpoints';
import Response from '../components/Response';
import { PageIntro } from '../components/ui';
import { PAGE_SUBTITLE, RESPONSE_SELECT_INCIDENT } from '../components/uiCopy';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
jest.mock('react-toastify', () => ({ toast: jest.fn(), ToastContainer: () => null }));
const { apiFetch } = require('../api');

const ok = (b) => Promise.resolve({ ok: true, json: () => Promise.resolve(b) });
beforeEach(() => {
  apiFetch.mockReset();
  apiFetch.mockImplementation((p) => {
    if (p === '/api/detections') return ok({ detections: [], counts: { open: 0, promoted: 0, dismissed: 0 } });
    if (p === '/api/endpoints') return ok({ org: { name: 'ACME Corp' }, endpoints: [] });
    if (p === '/api/actions') return ok({ actions: [] });
    if (p.includes('/scope')) return ok({ incident_id: 'INC-8340', sealed: true, hosts: [], accounts: [], detection_ids: [] });
    return ok({});
  });
});

const INCIDENT = { incidentId: 'INC-8340', title: 'Event Logs Cleared on Workstation', severity: 'Medium' };

const src = (f) => fs.readFileSync(path.join(__dirname, '..', 'components', f), 'utf8');

test('the ruled functional subtitles are the shared constants (no org branding)', () => {
  expect(PAGE_SUBTITLE).toEqual({
    incidents: 'Select and manage an investigation.',
    siem: 'Search and inspect event data.',
    detections: 'Review detections and decide what is actionable.',
    endpoints: 'Inspect hosts, users, processes, and system activity.',
    response: 'Contain and remediate incident targets.',
    analytics: 'Review performance and learn from the investigation.',
  });
  // decorative "ACME Corp:" page branding is gone from every workspace
  for (const f of ['Siem.jsx', 'Endpoints.jsx', 'Detections.jsx', 'Response.jsx',
                   'Incidents.jsx', 'Analytics.jsx']) {
    expect([f, /ACME Corp/.test(src(f))]).toEqual([f, false]);
  }
});

test('the retired scope furniture is structurally gone from every page', () => {
  for (const f of ['Siem.jsx', 'Endpoints.jsx', 'Detections.jsx', 'Response.jsx']) {
    const s = src(f);
    expect([f, /IncidentScopeBar|InvestigationContext/.test(s)]).toEqual([f, false]);
    expect([f, /ALL_ACTIVITY|investigatingCase/.test(s)]).toEqual([f, false]);
  }
  // and the components themselves no longer exist
  expect(fs.existsSync(path.join(__dirname, '..', 'components', 'IncidentScopeBar.jsx'))).toBe(false);
  expect(fs.existsSync(path.join(__dirname, '..', 'components', 'InvestigationContext.jsx'))).toBe(false);
});

test('the pill renders the incident context ONCE, with id, title, and severity', () => {
  const { container } = render(<PageIntro subtitle={PAGE_SUBTITLE.siem} incident={INCIDENT} />);
  const pills = screen.getAllByTestId('incident-pill');
  expect(pills).toHaveLength(1);
  expect(pills[0].textContent).toContain('INC-8340');
  expect(pills[0].textContent).toContain('Event Logs Cleared on Workstation');
  expect(pills[0].textContent).toContain('Medium');
  // a compact tag, never another full-width container
  expect(pills[0].tagName).toBe('SPAN');
  expect(container.textContent).not.toMatch(/Investigating/);
  expect(container.textContent).not.toMatch(/All activity/);
});

test.each([
  ['Detections', (p) => <Detections isVisible resetTrigger={0} onHostPivot={() => {}} {...p} />, PAGE_SUBTITLE.detections],
  ['Endpoints', (p) => <Endpoints isVisible resetTrigger={0} pivotHost={null} {...p} />, PAGE_SUBTITLE.endpoints],
  ['Response', (p) => <Response isVisible resetTrigger={0} {...p} />, PAGE_SUBTITLE.response],
])('%s: subtitle plus exactly one pill with a case; no pill and no All-activity label without one', async (name, mk, subtitle) => {
  const withCase = render(mk({ activeIncidentId: 'INC-8340', activeIncident: INCIDENT }));
  expect(await screen.findByText(subtitle)).toBeInTheDocument();
  expect(screen.getAllByTestId('incident-pill')).toHaveLength(1);
  expect(withCase.container.textContent).not.toMatch(/Investigating INC-/);
  withCase.unmount();

  const noCase = render(mk({ activeIncidentId: null, activeIncident: null }));
  expect(await screen.findByText(subtitle)).toBeInTheDocument();
  expect(screen.queryAllByTestId('incident-pill')).toHaveLength(0);
  expect(noCase.container.textContent).not.toMatch(/All activity/);
});

test('Response with no incident keeps its own truthful state', async () => {
  render(<Response isVisible resetTrigger={0} activeIncidentId={null} activeIncident={null} />);
  expect(await screen.findByText(RESPONSE_SELECT_INCIDENT)).toBeInTheDocument();
});
