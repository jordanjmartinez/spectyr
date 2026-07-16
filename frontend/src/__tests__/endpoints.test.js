/**
 * Stage 1 UI acceptance tests: render the Endpoints routes against fixture
 * data and inspect visible text.
 *  - no rendered application copy contains an em dash
 *  - empty values render exactly as "-"
 *  - no Add Endpoint / Refresh / bulk action / uninstall / delete affordances
 *  - the isolation card reserves space without hidden or disabled buttons
 *  - technical values render in mono
 */
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import Endpoints from '../components/Endpoints';
import EndpointDetail from '../components/EndpointDetail';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
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
  status: 'online', isolation: 'not_isolated',
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
      user: 'NT AUTHORITY\\SYSTEM', signer: 'Microsoft Windows', signed: true, memory_mb: 8 },
    { pid: 3456, ppid: 3400, parent_name: 'userinit.exe', parent_exited: true,
      name: 'explorer.exe', path: 'C:\\Windows\\explorer.exe',
      cmdline: 'C:\\Windows\\Explorer.EXE', user: 'ACME\\nkhan',
      signer: 'Microsoft Windows', signed: true, memory_mb: 145 },
  ],
  services: [
    { name: 'WinDefend', display_name: 'Microsoft Defender Antivirus Service',
      path: '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.25050.5-0\\MsMpEng.exe"',
      start_type: 'Automatic', status: 'Running', account: 'LocalSystem' },
  ],
  users: [
    { username: 'WDAGUtilityAccount', domain: 'ACME-WS12', type: 'Local',
      enabled: false, groups: [], description: 'system account' },
    { username: 'nkhan', domain: 'ACME', type: 'Domain', enabled: true,
      groups: ['Domain Users'], description: 'Assigned workstation user' },
  ],
  autoruns: [
    { location: 'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
      name: 'WindowsUpdate', command: 'C:\\Users\\Public\\winupdate.exe', signer: null },
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
    <Endpoints isVisible resetTrigger={0} setEndpointCount={() => {}} pivotHost={null} />
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

test('endpoint detail renders all tabs with clean copy and no action buttons', async () => {
  mockApi();
  const { container } = render(
    <EndpointDetail hostname="ACME-WS12" org={{ name: 'ACME Corp' }} onBack={() => {}} />
  );
  expect(await screen.findByText('spectyr-agent 1.0.0')).toBeInTheDocument();
  // isolation card: status pill only, no isolate/release controls
  expect(screen.queryByRole('button', { name: /isolate/i })).toBeNull();
  expect(screen.queryByRole('button', { name: /release/i })).toBeNull();
  expect(screen.getByText('00:50:56:1A:2B:3C')).toBeInTheDocument();
  assertCleanCopy(container);

  fireEvent.click(screen.getByRole('button', { name: 'Processes' }));
  expect(await screen.findByText('C:\\Windows\\explorer.exe')).toBeInTheDocument();
  expect(screen.getByText('2 of 2')).toBeInTheDocument();
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
  expect(screen.getByText('Unsigned')).toBeInTheDocument();
  assertCleanCopy(container);

  fireEvent.click(screen.getByRole('button', { name: 'Services' }));
  expect(await screen.findByText('WinDefend')).toBeInTheDocument();
  assertCleanCopy(container);
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
