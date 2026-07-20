/**
 * Stage 4 Phase 6.3: the event inspector (contract Section 12).
 *
 * Field-completeness matrix across all EIGHT source families, a recursive
 * rendered-props leak guard (no non-whitelisted field ever renders, even
 * when planted on the input object -- mirroring the backend's
 * planted-marker leak-test pattern applied to this component), the
 * malformed-event fallback, event_seq's no-filter-action guarantee, every
 * per-field action routed through lcqlPivots (via the shell's
 * refineAndRun), and Phase 5 selection-behavior preservation across
 * sorting and the Cards/Table toggle now that the inspector is the bigger,
 * shared component built in this phase.
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import EventInspector from '../components/EventInspector';
import Siem from '../components/Siem';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

// --- one representative event per source family, each with realistic kvp -

const FAMILY_EVENTS = {
  Sysmon: {
    id: 'sy-1', event_seq: 101, timestamp: '2026-03-17T04:00:00+00:00',
    event_type: 'ProcessCreate', source_type: 'Sysmon', severity: 'high',
    hostname: 'ACME-WS12', source_ip: '10.0.1.12', user_account: 'ACME\\nkhan',
    message: 'Process created: winupdate.exe launched by explorer.exe',
    key_value_pairs: {
      command_line: 'winupdate.exe -silent', image: 'C:\\Users\\Public\\winupdate.exe',
      parent_image: 'C:\\Windows\\explorer.exe', process_id: '4412',
    },
  },
  'Windows Security': {
    id: 'ws-1', event_seq: 102, timestamp: '2026-03-17T04:01:00+00:00',
    event_type: '4625', source_type: 'Windows Security', severity: 'medium',
    hostname: 'ACME-SVR01', source_ip: '10.0.1.50',
    message: 'An account failed to log on.',
    key_value_pairs: {
      account_name: 'jkim', logon_type: '3', status: '0xC000006D',
      workstation_name: 'ACME-WS08',
    },
  },
  Proxy: {
    id: 'px-1', event_seq: 103, timestamp: '2026-03-17T04:02:00+00:00',
    event_type: 'HTTP_CONNECT', source_type: 'Proxy', severity: 'medium',
    hostname: 'ACME-WS23', source_ip: '10.0.1.23', destination_ip: '52.96.84.228',
    user_account: 'ACME\\tharris',
    message: 'CONNECT tunnel established to outlook.office365.com:443',
    key_value_pairs: {
      url: 'outlook.office365.com:443', url_category: 'business',
      http_method: 'CONNECT',
    },
  },
  DNS: {
    id: 'dns-1', event_seq: 104, timestamp: '2026-03-17T04:03:00+00:00',
    event_type: 'QUERY', source_type: 'DNS', severity: 'low',
    hostname: 'ACME-WS08', source_ip: '10.0.1.8',
    message: 'DNS query received for slack.com.',
    key_value_pairs: { query: 'slack.com', query_type: 'A', reply_code: 'NOERROR' },
  },
  Firewall: {
    id: 'fw-1', event_seq: 105, timestamp: '2026-03-17T04:04:00+00:00',
    event_type: 'ALLOW', source_type: 'Firewall', severity: 'low',
    hostname: 'ACME-WS20', source_ip: '10.0.1.20', destination_ip: '10.0.1.201',
    message: 'Internal SMB request allowed to file server.',
    key_value_pairs: { action: 'allow', app: 'smb', dest_port: '445', rule: 'internal-file' },
  },
  'Azure AD': {
    // identity-provider events resolve to the ACCOUNT, never a host (the
    // identity-entity rule): no hostname field on a realistic fixture.
    id: 'aad-1', event_seq: 106, timestamp: '2026-03-17T04:05:00+00:00',
    event_type: 'SigninLogs', source_type: 'Azure AD', severity: 'medium',
    source_ip: '91.204.227.15', user_account: 'tharris@acme.com',
    message: 'Successful sign-in for tharris@acme.com from 91.204.227.15',
    key_value_pairs: {
      UserPrincipalName: 'tharris@acme.com', IPAddress: '91.204.227.15',
      Location: 'RO', ResultType: '0',
    },
  },
  Veeam: {
    id: 've-1', event_seq: 107, timestamp: '2026-03-17T04:06:00+00:00',
    event_type: '190', source_type: 'Veeam', severity: 'low',
    hostname: 'ACME-VEEAM01',
    message: 'Backup job completed.',
    key_value_pairs: {
      job_name: 'Nightly-Full', bytes_backed_up: '2097152',
      duration_seconds: '184', repository_ip: '10.0.1.206',
    },
  },
  Defender: {
    id: 'def-1', event_seq: 108, timestamp: '2026-03-17T04:07:00+00:00',
    event_type: '5007', source_type: 'Defender', severity: 'medium',
    hostname: 'ACME-WS12',
    message: 'Configuration setting changed.',
    key_value_pairs: {
      old_value: 'Enabled', new_value: 'Disabled', product_name: 'Microsoft Defender',
      channel: 'Microsoft-Windows-Windows Defender/Operational',
    },
  },
};

test.each(Object.entries(FAMILY_EVENTS))(
  'inspector completeness: every field of a representative %s event renders',
  (family, event) => {
    render(<EventInspector event={event} onFilter={() => {}} />);
    const el = screen.getByTestId('event-inspector');
    const text = el.textContent;
    // identity
    expect(text).toContain(event.id);
    expect(text).toContain(`arrived as event #${event.event_seq}`);
    // classification
    expect(text).toContain(event.source_type);
    expect(text).toContain(event.event_type);
    // canonical commons (only the ones this event actually carries)
    for (const f of ['hostname', 'user_account', 'source_ip', 'destination_ip', 'severity']) {
      if (event[f] !== undefined) expect(text).toContain(String(event[f]));
    }
    // every family (kvp) field
    for (const [k, v] of Object.entries(event.key_value_pairs)) {
      expect(text).toContain(k);
      // byte-count fields render humanized, not literal -- checked separately
      if (!/bytes/i.test(k)) expect(text).toContain(String(v));
    }
    // message
    expect(text).toContain(event.message);
    // the sanitized raw JSON view is present too (one lens, one truth)
    expect(el.querySelector('pre')).not.toBeNull();
  }
);

test('type-aware rendering: a byte-count kvp field is humanized, not printed literally', () => {
  render(<EventInspector event={FAMILY_EVENTS.Veeam} onFilter={() => {}} />);
  const el = screen.getByTestId('event-inspector');
  expect(within(el).getByText('2 MB')).toBeInTheDocument();
});

test('type-aware rendering: the identity timestamp is localized, not the raw ISO string', () => {
  // scoped to the structured Identity row's label (exact match), not the
  // raw JSON view further down -- that view legitimately shows the raw
  // ISO string verbatim (it is the sanitized RAW payload, by design).
  render(<EventInspector event={FAMILY_EVENTS.Sysmon} onFilter={() => {}} />);
  const label = screen.getByText('timestamp');
  const value = label.nextSibling.textContent;
  expect(value).not.toBe('2026-03-17T04:00:00+00:00');
  expect(value).toMatch(/\d{2}\/\d{2}\/\d{4}/); // en-GB date shape
});

test('an Azure AD identity event omits hostname (never force-resolved to a host)', () => {
  render(<EventInspector event={FAMILY_EVENTS['Azure AD']} onFilter={() => {}} />);
  expect(screen.queryByText('hostname')).toBeNull();
});

// --- recursive rendered-props leak guard ------------------------------------

const MARKER = 'ZZZ_ANSWER_KEY_MARKER_ZZZ';
const FORBIDDEN_KEYS = [
  'label', 'category', 'scenario_id', 'threat_pattern', 'storyline',
  'level_name', 'alert_id', 'level', 'flagged', 'status', 'chain_complete',
  'trigger', 'analyst_category', 'detected_by', 'process_id',
  'parent_process_id', 'user', 'log_source', 'host', '__future_internal__',
];

test('recursive leak guard: no non-whitelisted TOP-LEVEL field or planted marker ever renders', () => {
  // FORBIDDEN_KEYS includes process_id/parent_process_id/user/host: these
  // are forbidden as TOP-LEVEL served-event keys (matching the backend's
  // own FORBIDDEN set in test_event_disclosure.py), but legitimately
  // appear NESTED inside key_value_pairs -- SIEM raw-log detail is
  // arbitrary and is NOT screened at that level (same distinction the
  // backend draws). This fixture's kvp already carries a real
  // process_id="4412", so the guard checks parsed TOP-LEVEL JSON keys
  // specifically, not a flat substring scan that would false-positive on
  // that legitimate nested field.
  const poisoned = { ...FAMILY_EVENTS.Sysmon };
  for (const k of FORBIDDEN_KEYS) poisoned[k] = MARKER;
  render(<EventInspector event={poisoned} onFilter={() => {}} />);
  const el = screen.getByTestId('event-inspector');
  expect(el.textContent).not.toContain(MARKER);
  const rawJson = JSON.parse(el.querySelector('pre').textContent);
  for (const k of FORBIDDEN_KEYS) {
    expect(Object.keys(rawJson)).not.toContain(k);
  }
  expect(rawJson.key_value_pairs.process_id).toBe('4412'); // untouched, legitimate
});

// --- malformed-event fallback ------------------------------------------------

test('malformed event (non-object key_value_pairs) falls back to sanitized raw JSON with a notice', () => {
  const malformed = { id: 'bad-1', event_seq: 1, timestamp: 'x',
    key_value_pairs: 'not-an-object', message: 'oops', hostname: 'H' };
  render(<EventInspector event={malformed} onFilter={() => {}} />);
  expect(screen.getByRole('alert').textContent).toMatch(/could not be fully rendered/i);
  const el = screen.getByTestId('event-inspector');
  expect(el.querySelector('pre')).not.toBeNull();
  expect(el.querySelector('pre').textContent).toContain('"hostname"');
});

test('malformed event (missing id) also falls back rather than crashing', () => {
  const malformed = { event_seq: 1, timestamp: 'x', message: 'oops' };
  expect(() => render(<EventInspector event={malformed} onFilter={() => {}} />)).not.toThrow();
  expect(screen.getByRole('alert')).toBeInTheDocument();
});

test('no event selected renders nothing', () => {
  const { container } = render(<EventInspector event={null} onFilter={() => {}} />);
  expect(container).toBeEmptyDOMElement();
});

// --- event_seq: display-only, never a filter action -------------------------

test('event_seq renders as the arrival-position line with NO filter action anywhere', () => {
  render(<EventInspector event={FAMILY_EVENTS.Sysmon} onFilter={() => {}} />);
  const el = screen.getByTestId('event-inspector');
  expect(within(el).getByText(/arrived as event #101/)).toBeInTheDocument();
  expect(within(el).queryByLabelText(/Filter event_seq/)).toBeNull();
});

// --- per-field actions route only through the generator ---------------------

test('== and != actions call onFilter with the exact field and value', () => {
  const onFilter = jest.fn();
  render(<EventInspector event={FAMILY_EVENTS.Sysmon} onFilter={onFilter} />);
  fireEvent.click(screen.getByLabelText('Filter hostname equals'));
  expect(onFilter).toHaveBeenCalledWith('hostname', '==', 'ACME-WS12');
  fireEvent.click(screen.getByLabelText('Filter image not equals'));
  expect(onFilter).toHaveBeenCalledWith('image', '!=', 'C:\\Users\\Public\\winupdate.exe');
});

test('the hostname value is still a working Endpoints pivot alongside its filter actions', () => {
  const onHostPivot = jest.fn();
  render(<EventInspector event={FAMILY_EVENTS.Sysmon} onFilter={() => {}} onHostPivot={onHostPivot} />);
  fireEvent.click(screen.getByText('ACME-WS12'));
  expect(onHostPivot).toHaveBeenCalledWith('ACME-WS12');
});

// --- integration: inspector actions execute through the real query path ----

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
const snapWith = (rows, extra = {}) => ({
  token: 'tok.one',
  identity: {
    canonical_query: 'all | * | * | *', scope: 'session', resolved_scope_hosts: [],
    resolved_range: { start: '2026-03-17T03:41:00+00:00', end: '2026-03-17T04:10:00+00:00' },
    cutoff_seq: 200,
    ...extra,
  },
  count: rows.length, rows,
});

describe('inspector wired into the shell', () => {
  let queryResponses;
  beforeEach(() => {
    queryResponses = [];
    apiFetch.mockImplementation((path) => {
      if (path === '/api/endpoints') return ok({ org: { name: 'ACME Corp' }, endpoints: [] });
      if (path.startsWith('/api/events/query/new-count')) return ok({ new_count: 0, pool_growth: 0 });
      if (path.startsWith('/api/events/query')) {
        return queryResponses.length ? queryResponses.shift() : ok(snapWith([FAMILY_EVENTS.Sysmon]));
      }
      return ok({});
    });
  });

  const renderShell = () =>
    render(<Siem setSiemCount={() => {}} resetTrigger={0} onHostPivot={() => {}} />);

  const run = async (text) => {
    fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: text } });
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Run Query/ })); });
  };

  test('clicking == in the inspector executes a refined query via the generator', async () => {
    renderShell();
    await run('all | * | * | *');
    fireEvent.click(within(screen.getByTestId('workbench-results')).getByText(/winupdate.exe launched/));
    queryResponses.push(ok(snapWith([FAMILY_EVENTS.Sysmon], { canonical_query: 'all | * | * | hostname == "ACME-WS12"' })));
    await act(async () => {
      fireEvent.click(screen.getByLabelText('Filter hostname equals'));
    });
    const calls = apiFetch.mock.calls.map((c) => c[0]).filter((p) => p.startsWith('/api/events/query?'));
    expect(calls[calls.length - 1]).toBe(
      `/api/events/query?q=${encodeURIComponent('all | * | * | hostname == "ACME-WS12"')}&scope=session`);
  });

  // --- Phase 5 selection behavior preserved across sorting / view toggle ---

  test('selection and the inspector survive a client-side sort and stay pinned to the same event', async () => {
    const rows = [FAMILY_EVENTS.Sysmon, FAMILY_EVENTS.DNS];
    queryResponses.push(ok(snapWith(rows)));
    renderShell();
    await run('all | * | * | *');
    fireEvent.click(within(screen.getByTestId('workbench-results')).getByText(/winupdate.exe launched/));
    expect(screen.getByTestId('event-inspector').textContent).toContain('sy-1');

    fireEvent.click(screen.getByRole('button', { name: 'Table' }));
    await screen.findByText('Src Type');
    fireEvent.click(screen.getByRole('button', { name: /Event Type/ })); // client sort, no refetch
    expect(screen.getByTestId('event-inspector').textContent).toContain('sy-1');

    fireEvent.click(screen.getByRole('button', { name: 'Cards' }));
    expect(screen.getByTestId('event-inspector').textContent).toContain('sy-1');
  });
});
