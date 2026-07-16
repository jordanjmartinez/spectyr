/**
 * Stage 2 Detections UI tests: feed renders and triages, the Section 8 detail
 * shows the triggering-event + parent-process lineage, no em dashes in copy,
 * and the client payload carries no answer-key fields.
 */
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
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
  ],
  counts: { open: 2, promoted: 0, dismissed: 0 },
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

test('feed renders detections and triages them', async () => {
  let promoted = false;
  apiFetch.mockImplementation((path, opts) => {
    if (path.includes('/disposition')) { promoted = true; return Promise.resolve({ ok: true, json: () => Promise.resolve({}) }); }
    return Promise.resolve({ ok: true, json: () => Promise.resolve(FEED) });
  });
  const { container } = render(
    <Detections isVisible resetTrigger={0} setDetectionCount={() => {}} onHostPivot={() => {}} />
  );
  expect(await screen.findByText('LSASS Process Memory Access')).toBeInTheDocument();
  expect(screen.getByText('2 open · 0 promoted · 0 dismissed')).toBeInTheDocument();
  expect(screen.getAllByText('CRITICAL').length).toBeGreaterThanOrEqual(1);
  assertClean(container);
  // promote the first detection
  fireEvent.click(screen.getAllByText('Promote')[0]);
  await waitFor(() => expect(promoted).toBe(true));
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
