/**
 * Stage 2 Detections UI tests (amended by Stage 3a): feed renders and
 * triages, the Section 8 detail shows the triggering-event + parent-process
 * lineage, no em dashes in copy, and the client payload carries no
 * answer-key fields. Stage 3a adds identity response actions on account
 * entities in the Threats view and the session Response Log.
 */
import React from 'react';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import Detections from '../components/Detections';
import DetectionDetail from '../components/DetectionDetail';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const FEED = {
  detections: [
    { id: 'det-aaa', rule_name: 'LSASS Process Memory Access', rule_type: 'sigma_behavioral',
      severity: 'critical', mitre: { id: 'T1003.001', tactic: 'Credential Access' },
      yara_rule_name: null, description: 'A non-system process opened a handle to lsass.exe memory.',
      entity: { host: 'ACME-WS12', account: 'nkhan' }, time: '2026-07-16T12:10:00+00:00',
      sha256: 'a'.repeat(64), player_action: 'open' },
    { id: 'det-bbb', rule_name: 'Software Updater Outbound Connection', rule_type: 'sigma_behavioral',
      severity: 'medium', mitre: null, yara_rule_name: null,
      description: 'Periodic Google Update check.', entity: { host: 'ACME-WS12', account: 'nkhan' },
      time: '2026-07-16T12:05:00+00:00', sha256: 'b'.repeat(64), player_action: 'open' },
    { id: 'det-ccc', rule_name: 'Impossible Travel Sign-in', rule_type: 'sigma_behavioral',
      severity: 'high', mitre: { id: 'T1078', tactic: 'Initial Access' },
      yara_rule_name: null, description: 'Sign-in from two distant locations.',
      entity: { host: null, account: 'nkhan@acme.local', account_id: 'ent-1234567890ab',
                account_state: { disabled: false, sessions_revoked: false, password_reset: false } },
      time: '2026-07-16T12:12:00+00:00', sha256: null, player_action: 'promoted' },
  ],
  counts: { open: 2, promoted: 1, dismissed: 0 },
};

const ACTION_LOG = {
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

const DETAIL = {
  id: 'det-aaa', rule_name: 'Executable Launched from Removable Media',
  rule_type: 'yara', severity: 'high', mitre: { id: 'T1091', tactic: 'Initial Access' },
  yara_rule_name: 'Spectyr_USB_Loader_Generic',
  description: 'A binary matching a suspicious-loader signature executed from removable media.',
  entity: { host: 'ACME-WS12', account: 'nkhan' }, time: '2026-07-16T12:10:00+00:00',
  sha256: 'c'.repeat(64), player_action: 'open',
  triggering_events: [{
    event_type: 'ProcessCreate', source_type: 'Sysmon', severity: 'high',
    hostname: 'ACME-WS12', source_ip: '10.0.1.12', message: 'Process created',
    key_value_pairs: {
      image: 'E:\\setup.exe', command_line: 'E:\\setup.exe -q', process_id: '8844',
      parent_process_id: '640', parent_image: 'C:\\Windows\\explorer.exe',
      parent_command_line: 'explorer.exe', parent_user: 'ACME\\nkhan', company: 'Unknown',
    },
  }],
};

// Fields that must never appear in a client payload (answer key / linkage).
const FORBIDDEN = ['disposition', 'scenario_id', 'detection_key', 'answer_key',
  'category', 'label', 'storyline'];

const assertClean = (container) => {
  const text = container.textContent;
  expect(text).not.toMatch(/—/);
};

const mockApi = (overrides = {}) => {
  apiFetch.mockImplementation((path, opts) => {
    if (path.includes('/disposition')) {
      overrides.onDisposition?.(path, opts);
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    }
    if (path === '/api/actions' && opts?.method === 'POST') {
      return Promise.resolve({ ok: true, json: () => Promise.resolve(
        overrides.postResult || { seq: 3, timestamp: '2026-07-16T12:00:03+00:00',
          action: JSON.parse(opts.body).action, outcome: 'success', reason: null,
          target: { id: JSON.parse(opts.body).target, kind: 'account', label: 'ACME\\nkhan' } }
      ) });
    }
    if (path === '/api/actions') {
      return Promise.resolve({ ok: true, json: () => Promise.resolve(overrides.log || ACTION_LOG) });
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve(overrides.feed || FEED) });
  });
};

test('feed renders detections and triages them', async () => {
  let promoted = false;
  mockApi({ onDisposition: () => { promoted = true; } });
  const { container } = render(
    <Detections isVisible resetTrigger={0} setDetectionCount={() => {}} onHostPivot={() => {}} />
  );
  expect(await screen.findByText('LSASS Process Memory Access')).toBeInTheDocument();
  expect(screen.getByText('2 open · 1 promoted · 0 dismissed')).toBeInTheDocument();
  expect(screen.getAllByText('CRITICAL').length).toBeGreaterThanOrEqual(1);
  assertClean(container);
  // promote the first detection
  fireEvent.click(screen.getAllByText('Promote')[0]);
  await waitFor(() => expect(promoted).toBe(true));
});

test('threats view offers identity actions on account entities only', async () => {
  let posted = null;
  mockApi();
  apiFetch.mockImplementation((path, opts) => {
    if (path === '/api/actions' && opts?.method === 'POST') {
      posted = JSON.parse(opts.body);
      return Promise.resolve({ ok: true, json: () => Promise.resolve({
        seq: 1, timestamp: '2026-07-16T12:00:01+00:00', action: posted.action,
        outcome: 'success', reason: null,
        target: { id: posted.target, kind: 'account', label: 'ACME\\nkhan' } }) });
    }
    if (path === '/api/actions') {
      return Promise.resolve({ ok: true, json: () => Promise.resolve(ACTION_LOG) });
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve(FEED) });
  });
  const { container } = render(
    <Detections isVisible resetTrigger={0} setDetectionCount={() => {}} onHostPivot={() => {}} />
  );
  await screen.findByText('LSASS Process Memory Access');
  fireEvent.click(screen.getByRole('button', { name: /Threats/ }));
  // only the promoted account-entity row is in the Threats view
  expect(await screen.findByText('Impossible Travel Sign-in')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Disable' })).toBeEnabled();
  fireEvent.click(screen.getByRole('button', { name: 'Disable' }));
  // confirm dialog, concise copy
  expect(screen.getByRole('dialog')).toBeInTheDocument();
  expect(screen.getByText(/Disable the account nkhan@acme.local/)).toBeInTheDocument();
  fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Disable' }));
  await waitFor(() => expect(posted).toEqual({ action: 'disable_account', target: 'ent-1234567890ab' }));
  assertClean(container);
});

test('response log renders every attempt with outcomes', async () => {
  mockApi();
  const { container } = render(
    <Detections isVisible resetTrigger={0} setDetectionCount={() => {}} onHostPivot={() => {}} />
  );
  await screen.findByText('LSASS Process Memory Access');
  fireEvent.click(screen.getByRole('button', { name: 'Response Log' }));
  expect(await screen.findByText('ACME-SVR02')).toBeInTheDocument();
  expect(screen.getAllByText('Isolate Host').length).toBe(2);
  expect(screen.getByText('Success')).toBeInTheDocument();
  expect(screen.getByText('Failed')).toBeInTheDocument();
  expect(container.textContent).toMatch(/isolation command could not be delivered/);
  assertClean(container);
});

test('detail shows triggering event and parent process lineage', async () => {
  apiFetch.mockImplementation(() => Promise.resolve({ ok: true, json: () => Promise.resolve(DETAIL) }));
  const { container } = render(
    <DetectionDetail detId="det-aaa" onBack={() => {}} onAction={() => {}} onHostPivot={() => {}} />
  );
  expect(await screen.findByText('Executable Launched from Removable Media')).toBeInTheDocument();
  // triggering event card
  expect(screen.getByText('Triggering event')).toBeInTheDocument();
  expect(screen.getAllByText('setup.exe').length).toBeGreaterThanOrEqual(1); // heading + file-name row
  expect(screen.getByText('E:\\setup.exe')).toBeInTheDocument();
  // parent process card
  expect(screen.getByText('Parent process')).toBeInTheDocument();
  expect(screen.getAllByText('explorer.exe').length).toBeGreaterThanOrEqual(1);
  // SHA256 present, copy button present, NO VirusTotal
  expect(screen.getAllByText('Copy').length).toBeGreaterThanOrEqual(1);
  expect(container.textContent).not.toMatch(/VirusTotal/i);
  // MITRE tactic chip
  expect(screen.getByText('Initial Access')).toBeInTheDocument();
  expect(screen.getByText('T1091')).toBeInTheDocument();
  // yara rule name
  expect(screen.getByText('Spectyr_USB_Loader_Generic')).toBeInTheDocument();
  assertClean(container);
});

test('client payloads carry no answer-key fields', () => {
  const blob = JSON.stringify(FEED) + JSON.stringify(DETAIL);
  FORBIDDEN.forEach(k => expect(blob).not.toContain(`"${k}"`));
});
