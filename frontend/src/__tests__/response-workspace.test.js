/**
 * Final pass Part III.0.1 (+ Visual pass V9): the Response workspace --
 * the ONE canonical action-execution surface (Investigate -> Triage ->
 * Respond -> Submit -> Learn).
 *  - actionable incident entities group by target type with factual
 *    context only (identity, state, promoted-detection chips, verbs,
 *    executed state); never correctness/required/remaining copy
 *  - every action runs through the one request path exactly once, with
 *    the one confirmation dialog and the one toast announcement
 *  - the Response Log is the single chronological history
 *  - the ruled empty states render exactly
 *  - contextual focus (Respond navigation) highlights the target and
 *    executes nothing
 */
import React from 'react';
import { render, screen, fireEvent, waitFor, within, act } from '@testing-library/react';
import Response from '../components/Response';
import {
  RESPONSE_SELECT_INCIDENT, RESPONSE_NO_PROMOTED, RESPONSE_NO_TARGETS,
  RESPONSE_NO_ACTIONS,
} from '../components/uiCopy';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
jest.mock('react-toastify', () => ({ toast: jest.fn(), ToastContainer: () => null }));
const { toast } = require('react-toastify');
const { apiFetch } = require('../api');

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

const SNAP = {
  hostname: 'ACME-WS12', status: 'online', isolation: 'not_isolated',
  entity_id: 'ent-aaaa11112222',
  system: {}, services: [], users: [], network: { connections: [], listening: [], dns: [] },
  processes: [
    { pid: 3456, ppid: 3400, name: 'explorer.exe', path: 'C:\\Windows\\explorer.exe',
      cmdline: 'C:\\Windows\\Explorer.EXE', user: 'ACME\\nkhan', memory_mb: 145,
      entity_id: 'ent-cccc11112222' },
    { pid: 7788, ppid: 3456, name: 'winupdate.exe', path: 'C:\\Users\\Public\\winupdate.exe',
      cmdline: 'winupdate.exe', user: 'ACME\\nkhan', memory_mb: 30,
      entity_id: 'ent-abab11112222', sha256: 'a'.repeat(64) },
  ],
  autoruns: [
    { location: 'HKCU\\...\\Run', name: 'WindowsUpdate', command: 'C:\\Users\\Public\\winupdate.exe',
      persist_type: 'run_key', registration: 'active', file_state: 'present',
      file_entity_id: 'ent-ffff11112222', persistence_entity_id: 'ent-1111ffff2222' },
    { location: 'root\\CimV2:__FilterToConsumerBinding', name: 'WindowsUpdConsumer',
      command: 'powershell.exe -enc AAAA', persist_type: 'wmi_subscription',
      registration: 'active', file_state: 'none',
      file_entity_id: null, persistence_entity_id: 'ent-2222aaaa3333' },
  ],
};

const FEED = {
  detections: [
    { id: 'det-aaa', rule_name: 'LSASS Access', rule_type: 'sigma_behavioral', severity: 'critical',
      entity: { host: 'ACME-WS12', account: 'nkhan' }, time: '2026-07-16T12:10:00+00:00',
      sha256: null, player_action: 'promoted' },
    { id: 'det-ccc', rule_name: 'Impossible Travel', rule_type: 'sigma_behavioral', severity: 'high',
      entity: { host: null, account: 'nkhan@acme.local', account_id: 'ent-1234567890ab',
                account_state: { disabled: false, sessions_revoked: false, password_reset: false } },
      time: '2026-07-16T12:12:00+00:00', sha256: null, player_action: 'promoted' },
    { id: 'det-zzz', rule_name: 'Out of roster', rule_type: 'sigma_behavioral', severity: 'low',
      entity: { host: 'ACME-XX99', account: 'other', account_id: 'ent-out9999999999' },
      time: '2026-07-16T12:13:00+00:00', sha256: null, player_action: 'promoted' },
  ],
  counts: { open: 0, promoted: 3, dismissed: 0 },
};

const LOG = {
  actions: [
    { seq: 1, timestamp: '2026-07-16T12:00:01+00:00', action: 'isolate_host',
      outcome: 'success', reason: null,
      target: { id: 'ent-aaaa11112222', kind: 'host', label: 'ACME-WS12' } },
    { seq: 2, timestamp: '2026-07-16T12:00:02+00:00', action: 'isolate_host',
      outcome: 'failed_precondition',
      reason: 'Host is offline. The isolation command could not be delivered to the endpoint agent.',
      target: { id: 'ent-bbbb11112222', kind: 'host', label: 'ACME-SVR02' } },
  ],
  count: 2,
};

const SCOPE = { incident_id: 'INC-A', sealed: true, hosts: ['ACME-WS12', 'ACME-FW01'],
  accounts: [], detection_ids: ['det-aaa', 'det-ccc'] };

let posted;
const mockApi = (overrides = {}) => {
  posted = [];
  apiFetch.mockImplementation((path, opts) => {
    if (path === '/api/actions' && opts?.method === 'POST') {
      const body = JSON.parse(opts.body);
      posted.push(body);
      return ok(overrides.postResult || {
        seq: 9, timestamp: '2026-07-16T12:09:00+00:00', action: body.action,
        outcome: 'success', reason: null,
        target: { id: body.target, kind: 'x', label: 'target' } });
    }
    if (path === '/api/actions') return ok(overrides.log || LOG);
    if (path === '/api/detections') return ok(overrides.feed || FEED);
    if (path === '/api/incidents/INC-A/scope') return ok(overrides.scope || SCOPE);
    if (path === '/api/endpoints/ACME-WS12') return ok(overrides.snap || SNAP);
    if (path === '/api/endpoints/ACME-FW01') return Promise.resolve({ ok: false, status: 404, json: () => Promise.resolve({}) });
    return ok({});
  });
};

const renderResponse = async (props = {}) => {
  await act(async () => {
    render(<Response isVisible resetTrigger={0} activeIncidentId="INC-A" {...props} />);
  });
};

afterEach(() => { toast.mockClear(); });

test('groups render by target type with factual context and the existing verbs', async () => {
  mockApi();
  await renderResponse();
  expect(await screen.findByText('Hosts')).toBeInTheDocument();
  expect(screen.getByText('Accounts')).toBeInTheDocument();
  expect(screen.getByText('Processes')).toBeInTheDocument();
  expect(screen.getByText('Files')).toBeInTheDocument();
  expect(screen.getByText('Persistence')).toBeInTheDocument();
  // host row: identity + verbs; the unmanaged log source never renders
  expect(screen.getByRole('button', { name: 'ACME-WS12' })).toBeInTheDocument();
  expect(screen.queryByText('ACME-FW01')).toBeNull();
  expect(screen.getByRole('button', { name: 'Isolate Host' })).toBeInTheDocument();
  // account row from the ROSTER only (the out-of-roster promoted account
  // never enters this incident's targets)
  expect(screen.getByText('nkhan@acme.local')).toBeInTheDocument();
  expect(screen.queryByText('other')).toBeNull();
  expect(screen.getByRole('button', { name: 'Disable' })).toBeInTheDocument();
  // promoted detections ride as factual context chips
  expect(screen.getByText('Promoted: LSASS Access')).toBeInTheDocument();
  expect(screen.getByText('Promoted: Impossible Travel')).toBeInTheDocument();
  // processes / files / persistence rows with their verbs
  expect(screen.getAllByRole('button', { name: 'Kill' })).toHaveLength(2);
  expect(screen.getByRole('button', { name: 'Delete File' })).toBeInTheDocument();
  expect(screen.getAllByRole('button', { name: 'Remove Persistence' })).toHaveLength(2);
});

test('an action executes through the one request path exactly once (confirm -> POST -> toast)', async () => {
  mockApi();
  await renderResponse();
  fireEvent.click(await screen.findByRole('button', { name: 'Isolate Host' }));
  expect(screen.getByRole('dialog')).toBeInTheDocument();
  await act(async () => {
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Isolate' }));
  });
  await waitFor(() => expect(posted).toEqual([{ action: 'isolate_host', target: 'ent-aaaa11112222' }]));
  expect(toast).toHaveBeenCalledTimes(1);
});

test('identity actions execute on the roster account and disabled flags read the observable state', async () => {
  const feed = JSON.parse(JSON.stringify(FEED));
  feed.detections[1].entity.account_state.sessions_revoked = true;
  mockApi({ feed });
  await renderResponse();
  await screen.findByText('nkhan@acme.local');
  expect(screen.getByText('Sessions revoked')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Revoke' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Disable' }));
  await act(async () => {
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Disable' }));
  });
  await waitFor(() => expect(posted).toEqual([{ action: 'disable_account', target: 'ent-1234567890ab' }]));
});

test('the Response Log is the single chronological history with outcomes and detail', async () => {
  mockApi();
  await renderResponse();
  fireEvent.click(await screen.findByRole('button', { name: 'Response log' }));
  expect(await screen.findByText('ACME-SVR02')).toBeInTheDocument();
  expect(screen.getAllByText('Isolate Host').length).toBeGreaterThanOrEqual(2);
  expect(screen.getByText('Success')).toBeInTheDocument();
  expect(screen.getByText('Failed')).toBeInTheDocument();
  expect(screen.getByText(/isolation command could not be delivered/)).toBeInTheDocument();
});

test('the ruled empty states render exactly and reveal nothing', async () => {
  mockApi({ log: { actions: [], count: 0 } });
  // no incident selected
  await act(async () => {
    render(<Response isVisible resetTrigger={0} activeIncidentId={null} />);
  });
  expect(screen.getByText(RESPONSE_SELECT_INCIDENT)).toBeInTheDocument();
});

test('no promoted detections shows the factual banner while targets stay reviewable', async () => {
  const feed = JSON.parse(JSON.stringify(FEED));
  feed.detections.forEach(d => { d.player_action = 'open'; });
  mockApi({ feed });
  await renderResponse();
  expect(await screen.findByText(RESPONSE_NO_PROMOTED)).toBeInTheDocument();
  // targets still render beneath (hosts group present)
  expect(screen.getByText('Hosts')).toBeInTheDocument();
});

test('no actionable targets and no actions taken states render the ruled lines', async () => {
  mockApi({
    scope: { ...SCOPE, hosts: [], detection_ids: [] },
    feed: { detections: [], counts: { open: 0, promoted: 0, dismissed: 0 } },
    log: { actions: [], count: 0 },
  });
  await renderResponse();
  expect(await screen.findByText(RESPONSE_NO_TARGETS)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Response log' }));
  expect(await screen.findByText(RESPONSE_NO_ACTIONS)).toBeInTheDocument();
});

test('contextual focus highlights the navigated target and executes nothing', async () => {
  mockApi();
  await renderResponse({ responseFocus: { kind: 'process', hostname: 'ACME-WS12', pid: 7788, seq: 1 } });
  await screen.findByText('Processes');
  const focused = document.querySelector('[data-focused="true"]');
  expect(focused).not.toBeNull();
  expect(focused.textContent).toContain('winupdate.exe');
  expect(posted).toEqual([]);
});

test('no pre-submission correctness or answer-key phrasing renders', async () => {
  mockApi();
  const { container } = render(<Response isVisible resetTrigger={0} activeIncidentId="INC-A" />);
  await screen.findByText('Hosts');
  const text = container.textContent;
  for (const bad of [/required/i, /recommended/i, /\bcorrect\b/i, /\bincorrect\b/i,
    /sufficient/i, /remaining/i, /expected/i, /—/]) {
    expect(text).not.toMatch(bad);
  }
});

// --- Visual pass V9: command-center structure guards ------------------------

test('V9: exactly the five actionable target groups render; no Services group exists', async () => {
  // FLAGGED V9 DEVIATION (documented in Response.jsx): no service verb
  // exists in the eight-action vocabulary, so an actionless Services
  // table would duplicate the Endpoints investigation surface and imply
  // a verb the product does not have.
  mockApi();
  await renderResponse();
  await screen.findByText('Hosts');
  for (const g of ['Hosts', 'Accounts', 'Processes', 'Files', 'Persistence']) {
    expect(screen.getByText(g)).toBeInTheDocument();
  }
  expect(screen.queryByText('Services')).toBeNull();
  expect(screen.queryByRole('button', { name: /stop service/i })).toBeNull();
});

test('V9: no correctness, recommendation, or expected-count vocabulary anywhere in the workspace', async () => {
  mockApi();
  const { container } = render(<Response isVisible resetTrigger={0} activeIncidentId="INC-A" />);
  await screen.findByText('Hosts');
  const text = container.textContent;
  expect(text).not.toMatch(/recommend/i);
  expect(text).not.toMatch(/expected action/i);
  expect(text).not.toMatch(/required action/i);
  expect(text).not.toMatch(/\bremaining\b/i);
  expect(text).not.toMatch(/correct(ly)?\b/i);
});

// --- VD4 (visual correction section 5): the flat command workspace ----------

test('VD4: target categories are flat sections -- no rounded card wraps a category, no card inside a card', async () => {
  mockApi();
  await renderResponse();
  await screen.findByText('Hosts');
  const sections = screen.getAllByTestId('target-section');
  // the five actionable groups, in the ruled order, as flat sections
  expect(sections.map(s => s.querySelector('h3').textContent))
    .toEqual(['Hosts', 'Accounts', 'Processes', 'Files', 'Persistence']);
  for (const s of sections) {
    // the section itself sits on the workspace surface: never a card
    expect(s.tagName).toBe('SECTION');
    expect(s.className).not.toMatch(/rounded|shadow|bg-white/);
    expect(s.getAttribute('style')).toBeNull();
    // heading + count pill directly on the surface
    expect(s.querySelector('h3.t-subsection')).not.toBeNull();
    expect(s.querySelector('h3 + span').textContent).toMatch(/^\d+$/);
    // inside: exactly ONE bordered container -- the minimal light table
    // boundary holding the table -- and nothing rounded nests within it
    const rounded = [...s.querySelectorAll('[class*="rounded-xl"]')];
    expect(rounded).toHaveLength(1);
    expect(rounded[0].querySelector(':scope > table')).not.toBeNull();
    expect(rounded[0].querySelector('[class*="rounded-xl"]')).toBeNull();
    // responsive: the boundary scrolls horizontally, the page never does
    expect(rounded[0].className).toMatch(/overflow-x-auto/);
    // the shared light table header survives the flattening
    expect(rounded[0].querySelector('thead.data-thead, thead[class*="data-thead"]')).not.toBeNull();
  }
  // the Processes search field stays, on the surface above its table
  const procs = sections[2];
  expect(within(procs).getByLabelText('Search processes')).toBeInTheDocument();
  expect(within(procs).getByLabelText('Search processes').closest('[class*="rounded-xl"]')).toBeNull();
});

test('VD4: the Response log is one flat chronological table, never a decorative card stack', async () => {
  mockApi();
  await renderResponse();
  fireEvent.click(await screen.findByRole('button', { name: 'Response log' }));
  expect(await screen.findByText('ACME-SVR02')).toBeInTheDocument();
  // heading + count on the surface, then the single table
  const heading = screen.getByRole('heading', { name: 'Response log' });
  expect(heading.className).toMatch(/t-subsection/);
  const tables = screen.getAllByRole('table');
  expect(tables).toHaveLength(1);
  // the table sits in the minimal boundary; NO rounded container above it
  const boundary = tables[0].parentElement;
  expect(boundary.className).toMatch(/border-\[#e2e6ea\]/);
  expect(boundary.className).toMatch(/overflow-x-auto/);
  let up = boundary.parentElement;
  while (up) {
    expect(/rounded-xl/.test(up.className || '')).toBe(false);
    up = up.parentElement;
  }
});
