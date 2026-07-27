/**
 * Stage 1 UI acceptance tests (amended by Stage 3a; Final pass III.0.1):
 * render the Endpoints routes against fixture data and inspect visible
 * text.
 *  - no rendered application copy contains an em dash
 *  - empty values render exactly as "-"
 *  - no Add Endpoint / Refresh / bulk action / uninstall / delete affordances
 *  - Final pass III.0.1: Endpoints are INVESTIGATION ONLY. No direct
 *    action execution exists on any endpoint surface (no Isolate, Kill,
 *    Remove Persistence, Delete File); the contextual Respond controls
 *    only NAVIGATE to the Response workspace with the target selected.
 *  - technical values render in mono
 */
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import Endpoints from '../components/Endpoints';
import EndpointDetail from '../components/EndpointDetail';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
jest.mock('react-toastify', () => ({ toast: jest.fn(), ToastContainer: () => null }));
const { toast } = require('react-toastify');
const { apiFetch } = require('../api');

const LIST_FIXTURE = {
  org: { name: 'ACME Corp', domain: 'acme.local' },
  endpoints: [
    {
      hostname: 'ACME-WS12', ip: '10.0.1.12', external_ip: '203.0.113.25',
      role: 'workstation', os: 'Windows 11 Enterprise', desc: 'User workstation',
      platform: 'windows', status: 'online', isolation: 'not_isolated',
      tags: [], first_seen: '2026-05-02T08:11:00+00:00',
      last_seen: '2026-07-16T12:00:00+00:00',
      owner: { username: 'nkhan', domain: 'ACME' },
    },
    {
      hostname: 'ACME-SVR02', ip: '10.0.1.201', external_ip: '203.0.113.25',
      role: 'file', os: 'Windows Server 2019', desc: 'File Server',
      platform: 'windows', status: 'offline', isolation: 'not_isolated',
      tags: [], first_seen: '2026-03-14T02:40:00+00:00',
      last_seen: '2026-07-15T22:12:00+00:00', owner: null,
    },
  ],
};

const DETAIL_FIXTURE = {
  host_id: 'ws_victim', hostname: 'ACME-WS12', ip: '10.0.1.12',
  role: 'workstation', os: 'Windows 11 Enterprise', desc: 'User workstation',
  status: 'online', isolation: 'not_isolated', entity_id: 'ent-aaaa11112222',
  owner: { username: 'nkhan', domain: 'ACME' },
  system: {
    platform: 'windows', architecture: 'x64', internal_ip: '10.0.1.12',
    external_ip: '203.0.113.25', mac_address: '00:50:56:1A:2B:3C',
    sensor_id: '9a1f0f6e-3b3a-4a56-8c1d-2f4e5a6b7c8d',
    agent: 'spectyr-agent 1.0.0', agent_version: '1.0.0',
    first_seen: '2026-05-02T08:11:00+00:00',
    registered: '2026-05-02T08:11:00+00:00',
    last_heartbeat: '2026-07-16T12:00:00+00:00',
  },
  processes: [
    { pid: 4, ppid: 0, parent_name: '-', name: 'System', path: '', cmdline: '',
      user: 'NT AUTHORITY\\SYSTEM', signer: 'Microsoft Windows', signed: true,
      memory_mb: 8, entity_id: 'ent-bbbb11112222' },
    { pid: 3456, ppid: 3400, parent_name: 'userinit.exe', parent_exited: true,
      name: 'explorer.exe', path: 'C:\\Windows\\explorer.exe',
      cmdline: 'C:\\Windows\\Explorer.EXE', user: 'ACME\\nkhan',
      signer: 'Microsoft Windows', signed: true, memory_mb: 145,
      entity_id: 'ent-cccc11112222' },
    { pid: 7184, ppid: 11112, parent_name: 'chrome.exe', parent_terminated: true,
      name: 'chrome.exe', path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      cmdline: '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=renderer',
      user: 'ACME\\nkhan', signer: 'Google LLC', signed: true, memory_mb: 189,
      entity_id: 'ent-abab11112222' },
  ],
  services: [
    { name: 'WinDefend', display_name: 'Microsoft Defender Antivirus Service',
      path: '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.25050.5-0\\MsMpEng.exe"',
      start_type: 'Automatic', status: 'Running', account: 'LocalSystem' },
  ],
  users: [
    { username: 'WDAGUtilityAccount', domain: 'ACME-WS12', type: 'Local',
      enabled: false, groups: [], description: 'system account',
      entity_id: 'ent-dddd11112222' },
    { username: 'nkhan', domain: 'ACME', type: 'Domain', enabled: true,
      groups: ['Domain Users'], description: 'Assigned workstation user',
      entity_id: 'ent-eeee11112222' },
  ],
  autoruns: [
    { location: 'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
      name: 'WindowsUpdate', command: 'C:\\Users\\Public\\winupdate.exe', signer: null,
      persist_type: 'run_key', registration: 'active', file_state: 'present',
      file_entity_id: 'ent-ffff11112222', persistence_entity_id: 'ent-1111ffff2222' },
    { location: 'root\\CimV2:__FilterToConsumerBinding',
      name: 'WindowsUpdConsumer', command: 'powershell.exe -enc AAAA', signer: null,
      persist_type: 'wmi_subscription', registration: 'active', file_state: 'none',
      file_entity_id: null, persistence_entity_id: 'ent-2222aaaa3333' },
  ],
  network: {
    connections: [
      { proto: 'tcp', local_ip: '10.0.1.12', local_port: 49820,
        remote_ip: '185.141.62.11', remote_port: 443, state: 'ESTABLISHED',
        process: 'winupdate.exe', pid: 7788 },
    ],
    dns: [
      { query: 'github.com', record_type: 'A', resolved: '140.82.113.4',
        process: 'svchost.exe', pid: 1220, timestamp: '2026-07-16T11:40:00+00:00' },
      { query: 'updates.badcdn.io', record_type: 'TXT', resolved: '-',
        process: '-', pid: null, timestamp: '2026-07-16T11:58:00+00:00' },
    ],
  },
};

const mockApi = () => {
  apiFetch.mockImplementation((path) => {
    if (path === '/api/endpoints') {
      return Promise.resolve({ ok: true, json: () => Promise.resolve(LIST_FIXTURE) });
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve(DETAIL_FIXTURE) });
  });
};

const FORBIDDEN_COPY = [/—/, /Add Endpoint/i, /Refresh/i, /Uninstall/i,
                        /Delete Sensor/i, /Bulk/i];

const assertCleanCopy = (container) => {
  const text = container.textContent;
  FORBIDDEN_COPY.forEach(re => {
    expect(text).not.toMatch(re);
  });
};

test('endpoints list renders fixture rows with clean copy', async () => {
  mockApi();
  const { container } = render(
    <Endpoints isVisible resetTrigger={0} pivotHost={null} />
  );
  expect(await screen.findByText('ACME-WS12')).toBeInTheDocument();
  expect(screen.getByText('1 online · 1 offline')).toBeInTheDocument();
  expect(screen.getByText('just now')).toBeInTheDocument();          // online host
  expect(screen.getAllByText('Not Isolated')).toHaveLength(2);
  // empty Tags cells render exactly "-"
  const dashes = screen.getAllByText('-');
  expect(dashes.length).toBeGreaterThanOrEqual(2);
  assertCleanCopy(container);
});

test('endpoint detail renders all tabs with clean copy and Respond navigation only', async () => {
  const onOpenResponse = jest.fn();
  mockApi();
  const { container } = render(
    <EndpointDetail hostname="ACME-WS12" org={{ name: 'ACME Corp' }} onBack={() => {}}
      onOpenResponse={onOpenResponse} />
  );
  expect(await screen.findByText('spectyr-agent 1.0.0')).toBeInTheDocument();
  // III.0.1: no direct execution on the overview; the reserved area
  // carries the neutral navigation only
  expect(screen.queryByRole('button', { name: 'Isolate Host' })).toBeNull();
  expect(screen.queryByRole('button', { name: /release/i })).toBeNull();
  expect(screen.getByRole('button', { name: 'Respond to this host' })).toBeInTheDocument();
  expect(screen.getByText('00:50:56:1A:2B:3C')).toBeInTheDocument();
  assertCleanCopy(container);

  fireEvent.click(screen.getByRole('button', { name: 'Processes' }));
  expect(await screen.findByText('C:\\Windows\\explorer.exe')).toBeInTheDocument();
  expect(screen.getByText('3 of 3')).toBeInTheDocument();
  // no Kill execution; each process row navigates to Response
  expect(screen.queryByRole('button', { name: 'Kill' })).toBeNull();
  expect(screen.getAllByRole('button', { name: 'Respond' })).toHaveLength(3);
  // orphan of an overlay-killed parent: original PPID annotated terminated
  expect(screen.getByText('(terminated)')).toBeInTheDocument();
  assertCleanCopy(container);

  fireEvent.click(screen.getByRole('button', { name: 'Network' }));
  expect(await screen.findByText('winupdate.exe (7788)')).toBeInTheDocument();
  expect(screen.getByText('updates.badcdn.io')).toBeInTheDocument();
  assertCleanCopy(container);

  fireEvent.click(screen.getByRole('button', { name: 'Users' }));
  // empty groups render exactly "-"
  expect(await screen.findByText('ACME\\nkhan')).toBeInTheDocument();
  expect(screen.getAllByText('-').length).toBeGreaterThanOrEqual(1);
  assertCleanCopy(container);

  fireEvent.click(screen.getByRole('button', { name: 'Autoruns' }));
  expect(await screen.findByText('WindowsUpdate')).toBeInTheDocument();
  // persistence-artifact view: artifact-type labels + per-flag state stay;
  // execution moved to Response (no Remove/Delete controls here)
  expect(screen.getByText('WMI subscription')).toBeInTheDocument();
  expect(screen.getByText('Run key')).toBeInTheDocument();
  expect(screen.getAllByText('Registered').length).toBe(2);
  expect(screen.getByText('File present')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Remove Persistence' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Delete File' })).toBeNull();
  expect(screen.getAllByRole('button', { name: 'Respond' })).toHaveLength(2);
  assertCleanCopy(container);

  fireEvent.click(screen.getByRole('button', { name: 'Services' }));
  expect(await screen.findByText('WinDefend')).toBeInTheDocument();
  assertCleanCopy(container);
});

test('III.0.1: Respond controls navigate with the target selected and never execute', async () => {
  const onOpenResponse = jest.fn();
  mockApi();
  render(<EndpointDetail hostname="ACME-WS12" org={{ name: 'ACME Corp' }} onBack={() => {}}
    onOpenResponse={onOpenResponse} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Respond to this host' }));
  expect(onOpenResponse).toHaveBeenCalledWith({ kind: 'host', hostname: 'ACME-WS12' });

  fireEvent.click(screen.getByRole('button', { name: 'Processes' }));
  await screen.findByText('C:\\Windows\\explorer.exe');
  fireEvent.click(screen.getAllByRole('button', { name: 'Respond' })[1]);
  expect(onOpenResponse).toHaveBeenCalledWith({ kind: 'process', hostname: 'ACME-WS12', pid: 3456 });

  fireEvent.click(screen.getByRole('button', { name: 'Autoruns' }));
  await screen.findByText('WindowsUpdConsumer');
  fireEvent.click(screen.getAllByRole('button', { name: 'Respond' })[1]);
  expect(onOpenResponse).toHaveBeenCalledWith({ kind: 'autorun', entityId: 'ent-2222aaaa3333' });

  // navigation only: no dialog opened, no action POST fired
  expect(screen.queryByRole('dialog')).toBeNull();
  const posts = apiFetch.mock.calls.filter(([, o]) => o && o.method === 'POST');
  expect(posts).toHaveLength(0);
  expect(toast).not.toHaveBeenCalled();
});

test('V7: the endpoint list renders the shared device-class + platform identity from real fields', async () => {
  mockApi();
  render(<Endpoints isVisible resetTrigger={0} pivotHost={null} />);
  await screen.findByText('ACME-WS12');
  // both rows are Windows (the real platform field), each with the
  // labeled brand badge
  expect(screen.getAllByRole('img', { name: 'Windows' })).toHaveLength(2);
  // server vs workstation distinction, derived from os/role (exact cell
  // words; the descriptions use different casing)
  expect(screen.getByText('Workstation')).toBeInTheDocument();
  expect(screen.getByText('Server')).toBeInTheDocument();
  // the device glyph rides inside the hostname control (decorative)
  const hostBtn = screen.getByText('ACME-WS12').closest('button');
  expect(hostBtn.querySelector('svg[aria-hidden="true"]')).not.toBeNull();
});

test('V7: the endpoint detail header carries the same identity and a derived Platform row', async () => {
  mockApi();
  render(<EndpointDetail hostname="ACME-WS12" org={{ name: 'ACME Corp' }} onBack={() => {}} />);
  await screen.findByText('spectyr-agent 1.0.0');
  // sidebar + overview each carry the labeled platform badge
  expect(screen.getAllByRole('img', { name: 'Windows' }).length).toBeGreaterThanOrEqual(2);
  // the System information Platform row is DERIVED, not hardcoded
  expect(screen.getByText('Windows Workstation')).toBeInTheDocument();
});

test('unknown host shows the not-managed notice', async () => {
  apiFetch.mockImplementation((path) => {
    if (path === '/api/endpoints') {
      return Promise.resolve({ ok: true, json: () => Promise.resolve(LIST_FIXTURE) });
    }
    return Promise.resolve({ ok: false, status: 404, json: () => Promise.resolve({}) });
  });
  const { container } = render(
    <EndpointDetail hostname="ACME-FW01" org={{ name: 'ACME Corp' }} onBack={() => {}} />
  );
  await waitFor(() => {
    expect(container.textContent).toMatch(/not a managed endpoint/);
  });
  assertCleanCopy(container);
});
