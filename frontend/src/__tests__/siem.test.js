/**
 * Stage 1.5 SIEM view tests: card/table views over a fixture pool, dropdown
 * values derived from the pool, session-clock time presets, and the
 * answer-leak guard on the raw-log JSON view.
 */
import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import Siem from '../components/Siem';
import { sanitizeEvent, withinPreset, poolAnchorMs } from '../components/siemUtils';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const EVENTS = [
  {
    id: 'e1', timestamp: '2026-07-16T12:10:00+00:00', event_type: 'ProcessCreate',
    source_type: 'Sysmon', severity: 'high', hostname: 'ACME-WS12',
    source_ip: '10.0.1.12', user_account: 'ACME\\nkhan',
    message: 'Process created: nmap.exe launched by cmd.exe',
    key_value_pairs: { event_id: 1, process_id: '8844' },
    // simulation-internal fields that must NEVER reach the JSON view:
    label: 'lateral_movement_1', category: 'Lateral Movement',
    scenario_id: 'scenario-abc', level: 3, level_name: 'Rapid Internal Connection Attempts',
    storyline: 'secret storyline', flagged: true, alert_id: 'INC-1234',
    status: 'active', chain_complete: true, trigger: true,
  },
  {
    id: 'e2', timestamp: '2026-07-16T10:00:00+00:00', event_type: 'QUERY',
    source_type: 'DNS', severity: 'low', hostname: 'ACME-SVR03',
    source_ip: '10.0.1.12', destination_ip: '10.0.1.202',
    message: 'DNS query received for www.google.com',
    key_value_pairs: { query: 'www.google.com' },
    label: 'normal_traffic',
  },
];

beforeEach(() => {
  apiFetch.mockImplementation((path) => {
    if (path === '/api/endpoints') {
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ org: { name: 'ACME Corp' }, endpoints: [] }) });
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve(EVENTS) });
  });
});

const FORBIDDEN_JSON_KEYS = ['label', 'category', 'scenario_id', 'level',
  'level_name', 'storyline', 'flagged', 'alert_id', 'status',
  'chain_complete', 'trigger', 'analyst_category', 'category_correct'];

test('sanitizeEvent strips every simulation-internal field', () => {
  const clean = sanitizeEvent(EVENTS[0]);
  FORBIDDEN_JSON_KEYS.forEach(k => expect(clean).not.toHaveProperty(k));
  expect(clean.event_type).toBe('ProcessCreate');
  expect(clean.key_value_pairs.process_id).toBe('8844');
});

test('time presets anchor to the pool clock, never wall time', () => {
  const anchor = poolAnchorMs(EVENTS);
  expect(anchor).toBe(Date.parse('2026-07-16T12:10:00+00:00'));
  expect(withinPreset(EVENTS[0], '15m', anchor)).toBe(true);   // at anchor
  expect(withinPreset(EVENTS[1], '15m', anchor)).toBe(false);  // 2h10m older
  expect(withinPreset(EVENTS[1], '4h', anchor)).toBe(true);
  expect(withinPreset(EVENTS[1], 'all', anchor)).toBe(true);
});

test('cards view renders by default with pool-derived filters and clean copy', async () => {
  const { container } = render(
    <Siem setSiemCount={() => {}} resetTrigger={0} pivotQuery={null} onHostPivot={() => {}} />
  );
  expect(await screen.findByText(/nmap.exe launched/)).toBeInTheDocument();
  expect(screen.getByText('SIEM')).toBeInTheDocument();
  // dropdown values derived from the pool
  const source = screen.getByLabelText('Filter by Source');
  expect([...source.options].map(o => o.value)).toEqual(['all', 'DNS', 'Sysmon']);
  const platform = screen.getByLabelText('Filter by Platform');
  expect([...platform.options].map(o => o.value)).toEqual(['all', 'Network', 'Windows']);
  expect(container.textContent).not.toMatch(/—/);
});

test('expanding a card shows sanitized JSON only', async () => {
  render(<Siem setSiemCount={() => {}} resetTrigger={0} pivotQuery={null} onHostPivot={() => {}} />);
  fireEvent.click(await screen.findByText(/nmap.exe launched/));
  const pre = document.querySelector('pre');
  expect(pre).not.toBeNull();
  FORBIDDEN_JSON_KEYS.forEach(k => {
    expect(pre.textContent).not.toContain(`"${k}"`);
  });
  expect(pre.textContent).toContain('"event_type"');
});

test('table view toggle works and filters apply', async () => {
  render(<Siem setSiemCount={() => {}} resetTrigger={0} pivotQuery={null} onHostPivot={() => {}} />);
  await screen.findByText(/nmap.exe launched/);
  fireEvent.click(screen.getByRole('button', { name: 'Table' }));
  expect(await screen.findByText('Src Type')).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Filter by Source'), { target: { value: 'DNS' } });
  expect(screen.queryByText(/nmap.exe launched/)).toBeNull();
  expect(screen.getAllByText(/www.google.com/).length).toBeGreaterThan(0);
});

// Pre-Stage-4 disclosure hotfix: the free-text SIEM search corpus is
// JSON.stringify(event) over the fetched pool. Now that the SERVER whitelists
// the feed, the client never receives hidden scenario/answer fields, so it
// cannot search-match a value that lived only in those hidden fields.
const HIDDEN_TERMS = ['Lateral Movement', 'lateral_movement_1',
  'secret storyline', 'scenario-abc', 'INC-1234'];
// What the fixed /api/fake-events returns: the whitelist fields only.
const SANITIZED_EVENTS = [
  {
    id: 'e1', timestamp: '2026-07-16T12:10:00+00:00', event_type: 'ProcessCreate',
    source_type: 'Sysmon', severity: 'high', hostname: 'ACME-WS12',
    source_ip: '10.0.1.12', user_account: 'ACME\\nkhan',
    message: 'Process created: nmap.exe launched by cmd.exe',
    key_value_pairs: { event_id: 1, process_id: '8844' },
  },
];

test('client search cannot match values that live only in hidden server fields', async () => {
  apiFetch.mockImplementation((path) => {
    if (path === '/api/endpoints') {
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ org: { name: 'ACME Corp' }, endpoints: [] }) });
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve(SANITIZED_EVENTS) });
  });
  render(<Siem setSiemCount={() => {}} resetTrigger={0} pivotQuery={null} onHostPivot={() => {}} />);
  await screen.findByText(/nmap.exe launched/);
  const search = screen.getByPlaceholderText(/Search events/i);
  // a visible field value still matches
  fireEvent.change(search, { target: { value: 'nmap' } });
  expect(screen.getByText(/nmap.exe launched/)).toBeInTheDocument();
  // hidden scenario/answer terms never match
  for (const hidden of HIDDEN_TERMS) {
    fireEvent.change(search, { target: { value: hidden } });
    expect(screen.queryByText(/nmap.exe launched/)).toBeNull();
  }
});
