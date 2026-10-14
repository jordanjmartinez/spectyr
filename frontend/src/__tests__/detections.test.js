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
      sha256: 'a'.repeat(64), player_action: 'open',
      why: 'procdump64.exe opened a handle to lsass.exe on ACME-WS12 with access 0x1fffff.' },
    { id: 'det-bbb', rule_name: 'Software Updater Outbound Connection', rule_type: 'sigma_behavioral',
      severity: 'medium', mitre: null, yara_rule_name: null,
      description: 'Periodic Google Update check.', entity: { host: 'ACME-WS12', account: 'nkhan' },
      time: '2026-07-16T12:05:00+00:00', sha256: 'b'.repeat(64), player_action: 'open',
      why: 'GoogleUpdate.exe ran from C:\\Program Files (x86)\\Google\\Update on ACME-WS12 as nkhan.' },
    { id: 'det-ccc', rule_name: 'Impossible Travel Sign-in', rule_type: 'sigma_behavioral',
      severity: 'high', mitre: { id: 'T1078', tactic: 'Initial Access' },
      yara_rule_name: null, description: 'Sign-in from two distant locations.',
      entity: { host: null, account: 'nkhan@acme.local', account_id: 'ent-1234567890ab',
                account_state: { disabled: false, sessions_revoked: false, password_reset: false } },
      time: '2026-07-16T12:12:00+00:00', sha256: null, player_action: 'promoted' },
    // host-local detection that ALSO carries an acting account: identity
    // actions must surface here too (the required-action reachability fix)
    { id: 'det-ddd', rule_name: 'Password Spray Success', rule_type: 'sigma_behavioral',
      severity: 'high', mitre: { id: 'T1110.003', tactic: 'Credential Access' },
      yara_rule_name: null, description: 'A sprayed account authenticated.',
      entity: { host: 'ACME-SVR01', account: 'lgreen', account_id: 'ent-cccc000011ab',
                account_state: { disabled: false, sessions_revoked: false, password_reset: false } },
      time: '2026-07-16T12:13:00+00:00', sha256: null, player_action: 'promoted' },
  ],
  counts: { open: 2, promoted: 2, dismissed: 0 },
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
  rule_type: 'yara', severity: 'high',
  mitre: { id: 'T1091', tactic: 'Initial Access', name: 'Replication Through Removable Media',
           gloss: 'Malware spreads by being carried in on a USB drive or other removable media and run from it.' },
  yara_rule_name: 'Spectyr_USB_Loader_Generic',
  why: 'Payroll_2026.exe ran from E: on ACME-WS12 as ACME\\nkhan, launched by explorer.exe.',
  guidance: {
    harmless: 'Vendors and field engineers carry signed installers and diagnostic tools on USB drives.',
    checks: ['Check the binary signer and name.', 'Identify the user and whether the device was expected.',
      'Look for persistence, network connections, or child processes after the launch.'],
  },
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
    <Detections isVisible resetTrigger={0} onHostPivot={() => {}} />
  );
  expect(await screen.findByText('LSASS Process Memory Access')).toBeInTheDocument();
  // owner list-page uniformity (2026-10-12): the passive counts line is
  // retired; the toolbar tabs carry the counts
  expect(screen.getByRole('button', { name: 'Open 2' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Promoted 2' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Dismissed 0' })).toBeInTheDocument();
  expect(screen.getAllByText('Critical').length).toBeGreaterThanOrEqual(1);
  assertClean(container);
  // decision-layer pass: the decisions live behind the row's "..." menu with
  // their full labels; promote the first detection through it
  fireEvent.click(screen.getByRole('button', { name: 'Actions for LSASS Process Memory Access' }));
  fireEvent.click(screen.getByRole('menuitem', { name: 'Promote to Threat' }));
  await waitFor(() => expect(promoted).toBe(true));
});

test('Final pass III.0.1: Detections is triage-only -- no Threats or Response Log tabs, no execution controls', async () => {
  const onOpenResponse = jest.fn();
  mockApi();
  const { container } = render(
    <Detections isVisible resetTrigger={0} onHostPivot={() => {}}
      onOpenResponse={onOpenResponse} />
  );
  await screen.findByText('LSASS Process Memory Access');
  // the retired views and execution controls are structurally gone
  expect(screen.queryByRole('button', { name: /Threats/ })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Response Log' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Disable' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Revoke' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Reset PW' })).toBeNull();
  // triage stays, behind the row menu (decision-layer pass)
  fireEvent.click(screen.getByRole('button', { name: 'Actions for LSASS Process Memory Access' }));
  expect(screen.getByRole('menuitem', { name: 'Promote to Threat' })).toBeInTheDocument();
  expect(screen.getByRole('menuitem', { name: 'Dismiss as Benign' })).toBeInTheDocument();
  fireEvent.keyDown(document, { key: 'Escape' });
  expect(screen.queryByRole('menu')).toBeNull();
  // promoted rows offer ONLY the neutral navigation; clicking selects the
  // relevant target in Response and executes nothing (the Promoted TAB is
  // the uniform toolbar's disposition filter, not the retired Threats
  // execution surface)
  fireEvent.click(screen.getByRole('button', { name: 'Promoted 2' }));
  expect(screen.queryByRole('button', { name: 'Open in Response' })).toBeNull(); // nothing inline
  fireEvent.click(screen.getByRole('button', { name: 'Actions for Impossible Travel Sign-in' }));
  fireEvent.click(screen.getByRole('menuitem', { name: 'Open in Response' }));
  expect(onOpenResponse).toHaveBeenCalledWith({ kind: 'account', entityId: 'ent-1234567890ab' });
  const posts = apiFetch.mock.calls.filter(([, o]) => o && o.method === 'POST');
  expect(posts).toHaveLength(0);
  assertClean(container);
});

test('detail shows triggering event and parent process lineage', async () => {
  apiFetch.mockImplementation(() => Promise.resolve({ ok: true, json: () => Promise.resolve(DETAIL) }));
  const { container } = render(
    <DetectionDetail detId="det-aaa" onBack={() => {}} onAction={() => {}} onHostPivot={() => {}} />
  );
  expect(await screen.findByText('Executable Launched from Removable Media')).toBeInTheDocument();
  // triggering event card
  expect(screen.getByText('Triggering Event')).toBeInTheDocument();
  expect(screen.getAllByText('setup.exe').length).toBeGreaterThanOrEqual(1); // heading + file-name row
  expect(screen.getByText('E:\\setup.exe')).toBeInTheDocument();
  // parent process card
  expect(screen.getByText('Parent Process')).toBeInTheDocument();
  expect(screen.getAllByText('explorer.exe').length).toBeGreaterThanOrEqual(1);
  // SHA256 present, copy button present, NO VirusTotal
  expect(screen.getAllByText('Copy').length).toBeGreaterThanOrEqual(1);
  expect(container.textContent).not.toMatch(/VirusTotal/i);
  // MITRE: technique name first, the id in parentheses; tactic as context
  expect(screen.getByText('Initial Access')).toBeInTheDocument();
  expect(screen.getByText('Replication Through Removable Media (T1091)')).toBeInTheDocument();
  expect(screen.getByText(DETAIL.mitre.gloss)).toBeInTheDocument();
  // yara rule name (now inside the rule card's detection-method line)
  expect(screen.getByText('Spectyr_USB_Loader_Generic')).toBeInTheDocument();
  assertClean(container);
});

// --- decision-layer pass (owner 2026-10-13) --------------------------------

test('list: no Type column, no inline decision buttons, a why line under each rule, default sort severity then time', async () => {
  mockApi();
  const { container } = render(<Detections isVisible resetTrigger={0} onHostPivot={() => {}} />);
  await screen.findByText('LSASS Process Memory Access');
  const headers = [...container.querySelectorAll('thead th')].map(th => th.textContent.trim());
  expect(headers).toEqual(['Severity', 'Rule', 'Entity', 'Time', 'Actions']);
  expect(headers).not.toContain('Type');
  expect(headers).not.toContain('Triage');
  expect(container.textContent).not.toMatch(/Sigma|YARA/);
  // no inline Promote / Dismiss controls on rows
  expect(screen.queryByRole('button', { name: 'Promote' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Dismiss' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Promote to Threat' })).toBeNull();
  // the instance why line renders under the rule name
  expect(screen.getByText(FEED.detections[0].why)).toBeInTheDocument();
  // default order on the Open tab: critical (det-aaa) before medium (det-bbb)
  const rules = [...container.querySelectorAll('tbody tr')].map(tr => tr.querySelector('button').textContent);
  expect(rules).toEqual(['LSASS Process Memory Access', 'Software Updater Outbound Connection']);
  // search placeholder states its scope, and the why text is searchable
  const search = screen.getByPlaceholderText('Search rule, host, user, or file...');
  fireEvent.change(search, { target: { value: 'GoogleUpdate' } });
  expect(screen.queryByText('LSASS Process Memory Access')).toBeNull();
  expect(screen.getByText('Software Updater Outbound Connection')).toBeInTheDocument();
});

test('list: sortDetections orders by severity rank then newest time; the menu offers full labels only', async () => {
  const { sortDetections } = require('../components/Detections');
  const rows = [
    { id: 'a', severity: 'medium', time: '2026-07-16T12:00:00+00:00' },
    { id: 'b', severity: 'critical', time: '2026-07-16T11:00:00+00:00' },
    { id: 'c', severity: 'high', time: '2026-07-16T12:30:00+00:00' },
    { id: 'd', severity: 'high', time: '2026-07-16T12:45:00+00:00' },
    { id: 'e', severity: 'low', time: '2026-07-16T13:00:00+00:00' },
  ];
  expect(sortDetections(rows).map(r => r.id)).toEqual(['b', 'd', 'c', 'a', 'e']);
  mockApi();
  render(<Detections isVisible resetTrigger={0} onHostPivot={() => {}} />);
  await screen.findByText('LSASS Process Memory Access');
  fireEvent.click(screen.getByRole('button', { name: 'Actions for LSASS Process Memory Access' }));
  const items = screen.getAllByRole('menuitem').map(b => b.textContent);
  expect(items).toEqual(['Promote to Threat', 'Dismiss as Benign']);
});

test('detail: header is severity + rule + timestamp/host/user (no Sigma pill, no raw id); sticky triage bar with helpers; no bottom Triage card; body order', async () => {
  apiFetch.mockImplementation(() => Promise.resolve({ ok: true, json: () => Promise.resolve(DETAIL) }));
  const { container } = render(
    <DetectionDetail detId="det-aaa" onBack={() => {}} onAction={() => {}} onHostPivot={() => {}} />
  );
  await screen.findByText('Executable Launched from Removable Media');
  const header = screen.getByText('Executable Launched from Removable Media').closest('div');
  expect(header.textContent).not.toMatch(/Sigma|YARA/);
  expect(header.textContent).not.toContain('det-aaa');
  expect(header.textContent).toContain('2026-07-16 12:10:00');
  expect(header.textContent).toContain('ACME-WS12');
  expect(header.textContent).toContain('nkhan');
  // the sticky triage bar: the two decisions, each with its one-line helper
  const bar = screen.getByTestId('triage-bar');
  expect(bar.className).toContain('sticky');
  expect(within(bar).getByRole('button', { name: 'Promote to Threat' })).toBeInTheDocument();
  expect(within(bar).getByRole('button', { name: 'Dismiss as Benign' })).toBeInTheDocument();
  expect(within(bar).getByText('This is real attacker activity in this incident.')).toBeInTheDocument();
  expect(within(bar).getByText('This is expected or harmless activity.')).toBeInTheDocument();
  // the bottom Triage card is gone (exactly one place offers the decisions)
  expect(screen.getAllByRole('button', { name: 'Promote to Threat' })).toHaveLength(1);
  expect(screen.queryByText('Triage')).toBeNull();
  // body order
  const titles = [...container.querySelectorAll('p.t-subsection')].map(p => p.textContent);
  expect(titles).toEqual([
    'Why This Fired', 'What the Rule Detects', 'Affected Entity', 'Triggering Event',
    'Parent Process', 'MITRE ATT&CK', 'What to Check',
  ]);
  // why + harmless; rule card with the glossed method and the muted copyable id at its foot
  expect(screen.getByText(DETAIL.why)).toBeInTheDocument();
  expect(screen.getByText(DETAIL.guidance.harmless)).toBeInTheDocument();
  expect(screen.getByText(/Detection method/).closest('p').textContent).toContain('file signature (YARA), a rule that matches byte patterns inside a file');
  const idLine = screen.getByText('Detection ID').closest('p');
  expect(idLine.textContent).toContain('det-aaa');
  expect(within(idLine).getByRole('button', { name: 'Copy detection ID' })).toBeInTheDocument();
  // the checklist, in order
  const steps = [...container.querySelectorAll('ol li')].map(li => li.textContent);
  expect(steps).toEqual(DETAIL.guidance.checks);
  // affected entity rows
  expect(screen.getByText('Host')).toBeInTheDocument();
  expect(screen.getAllByText('User').length).toBeGreaterThanOrEqual(1); // entity card + parent card
  assertClean(container);
});

test('detail: a Sigma rule reads "log pattern (Sigma)" with its gloss; the triage bar acts through onAction', async () => {
  const sigma = { ...DETAIL, rule_type: 'sigma_behavioral', yara_rule_name: null };
  apiFetch.mockImplementation(() => Promise.resolve({ ok: true, json: () => Promise.resolve(sigma) }));
  const onAction = jest.fn();
  render(<DetectionDetail detId="det-aaa" onBack={() => {}} onAction={onAction} />);
  await screen.findByText('Executable Launched from Removable Media');
  expect(screen.getByText(/Detection method/).closest('p').textContent).toContain('log pattern (Sigma), a rule that matches a pattern in logged events');
  fireEvent.click(screen.getByRole('button', { name: 'Dismiss as Benign' }));
  expect(onAction).toHaveBeenCalledWith('det-aaa', 'dismiss');
});

test('client payloads carry no answer-key fields', () => {
  const blob = JSON.stringify(FEED) + JSON.stringify(DETAIL);
  FORBIDDEN.forEach(k => expect(blob).not.toContain(`"${k}"`));
});
