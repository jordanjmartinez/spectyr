/**
 * The two-tier event inspector (owner SIEM simplification pass 2026-10-13,
 * over the Stage 4 Section 12 lens).
 *
 * Key Facts first (~9 fields, values DECODED: logon type 3 reads Network,
 * substatus 0xC000006A reads Incorrect Password), the complete field list
 * behind the All Fields toggle with the sanitized raw JSON below it.
 * Filter/pivot actions exist ONLY on entity fields through the ONE menu
 * with plain verbs; the old per-field == / != / Pivot buttons are gone.
 * Carried forward unchanged: the recursive rendered-props leak guard, the
 * malformed-event fallback, kvp catalog ordering, event_seq's
 * no-filter-action guarantee, and selection behavior through the shell.
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import EventInspector, { buildKeyFacts } from '../components/EventInspector';
import Siem from '../components/Siem';
import kvpCatalogOrder from '../components/kvpCatalogOrder.json';

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
      sub_status: '0xC000006A', workstation_name: 'ACME-WS08',
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

const renderInspector = (event, props = {}) =>
  render(<EventInspector event={event} onEntityAction={() => {}} {...props} />);

const openAllFields = () =>
  fireEvent.click(screen.getByRole('button', { name: /All Fields/ }));

// --- Key Facts: decoded, capped, presence-driven ------------------------------

test('Key Facts decodes the owner-specified codes: event type, logon type, failure substatus', () => {
  renderInspector(FAMILY_EVENTS['Windows Security']);
  const el = screen.getByTestId('event-inspector');
  expect(within(el).getByText('Key Facts')).toBeInTheDocument();
  const text = el.textContent;
  expect(text).toContain('Failed Logon (4625)');
  expect(text).toContain('Network (3)');
  expect(text).toContain('Incorrect Password (0xC000006A)');
  // plain-language labels, not raw field names, in the Key Facts tier
  expect(text).toContain('User Account');
  expect(text).toContain('Computer');
  expect(text).toContain('Source IP');
  expect(text).toContain('Why It Failed');
});

test('buildKeyFacts caps at ~9 facts, picked by presence from the priority order', () => {
  const facts = buildKeyFacts(FAMILY_EVENTS['Windows Security']);
  expect(facts.length).toBeLessThanOrEqual(9);
  expect(facts.map((f) => f.label)).toEqual([
    'Event', 'Time', 'Severity', 'Log Source', 'User Account', 'Computer',
    'Source IP', 'Logon Type', 'Why It Failed',
  ]);
  // the Sysmon shape reaches the process facts instead
  const sysmon = buildKeyFacts(FAMILY_EVENTS.Sysmon).map((f) => f.label);
  expect(sysmon).toContain('Process');
  expect(sysmon).toContain('Command');
});

test('an Azure AD identity event omits Computer (never force-resolved to a host) and reads its UPN', () => {
  renderInspector(FAMILY_EVENTS['Azure AD']);
  const el = screen.getByTestId('event-inspector');
  expect(within(el).queryByText('Computer')).toBeNull();
  expect(el.textContent).toContain('tharris@acme.com');
});

test('type-aware rendering carried forward: bytes humanize, timestamps localize', () => {
  renderInspector(FAMILY_EVENTS.Veeam);
  openAllFields();
  expect(within(screen.getByTestId('event-inspector')).getByText('2 MB')).toBeInTheDocument();
  const label = within(screen.getByTestId('all-fields')).getByText('timestamp');
  const value = label.nextSibling.textContent;
  expect(value).not.toBe('2026-03-17T04:06:00+00:00');
  expect(value).toMatch(/\d{2}\/\d{2}\/\d{4}/); // en-GB date shape
});

// --- All Fields: the complete structure behind ONE toggle ---------------------

test.each(Object.entries(FAMILY_EVENTS))(
  'All Fields completeness: every field of a representative %s event renders behind the toggle',
  (family, event) => {
    renderInspector(event);
    openAllFields();
    const el = screen.getByTestId('event-inspector');
    const text = el.textContent;
    expect(text).toContain(event.id);
    expect(text).toContain(`arrived as event #${event.event_seq}`);
    expect(text).toContain(event.source_type);
    expect(text).toContain(String(event.event_type));
    for (const f of ['hostname', 'user_account', 'source_ip', 'destination_ip', 'severity']) {
      if (event[f] !== undefined) expect(text).toContain(String(event[f]));
    }
    for (const [k, v] of Object.entries(event.key_value_pairs)) {
      expect(text).toContain(k);
      if (!/bytes/i.test(k)) expect(text).toContain(String(v));
    }
    expect(text).toContain(event.message);
    // the sanitized raw JSON sits below the full field list
    expect(el.querySelector('pre')).not.toBeNull();
  }
);

test('the raw JSON renders only inside All Fields (two tiers, raw below the full list)', () => {
  renderInspector(FAMILY_EVENTS.Sysmon);
  const el = screen.getByTestId('event-inspector');
  expect(el.querySelector('pre')).toBeNull();
  const toggle = screen.getByRole('button', { name: /All Fields/ });
  expect(toggle).toHaveAttribute('aria-expanded', 'false');
  openAllFields();
  expect(screen.getByTestId('all-fields').querySelector('pre')).not.toBeNull();
});

// --- kvp "catalog order" inside All Fields ------------------------------------

const familyFieldOrder = (event) => {
  const section = screen.getByTestId('all-fields');
  const labels = Array.from(section.querySelectorAll('span.text-muted'))
    .map((s) => s.textContent)
    .filter((f) => f in event.key_value_pairs);
  return labels;
};

test('family fields render in fixture order regardless of kvp insertion order', () => {
  const event = {
    id: 'ord-1', event_seq: 300, timestamp: '2026-03-17T05:00:00+00:00',
    event_type: 'SigninLogs', source_type: 'Azure AD', severity: 'low',
    user_account: 'ord@acme.com', message: 'ordering fixture',
    key_value_pairs: {
      ip_address: '91.204.227.15', UserPrincipalName: 'ord@acme.com',
      app: 'Outlook', Location: 'RO',
    },
  };
  for (const k of Object.keys(event.key_value_pairs)) {
    expect(kvpCatalogOrder).toContain(k);
  }
  renderInspector(event);
  openAllFields();
  expect(familyFieldOrder(event)).toEqual(['Location', 'UserPrincipalName', 'app', 'ip_address']);
});

test('an off-catalog kvp key still renders, after every cataloged key', () => {
  const event = {
    id: 'ord-2', event_seq: 301, timestamp: '2026-03-17T05:01:00+00:00',
    event_type: 'QUERY', source_type: 'DNS', severity: 'low',
    hostname: 'ACME-WS08', message: 'off-catalog ordering',
    key_value_pairs: {
      aaa_not_in_catalog: 'still-shown', query: 'slack.com', Location: 'RO',
    },
  };
  expect(kvpCatalogOrder).not.toContain('aaa_not_in_catalog');
  renderInspector(event);
  openAllFields();
  expect(familyFieldOrder(event)).toEqual(['Location', 'query', 'aaa_not_in_catalog']);
  expect(screen.getByText('still-shown')).toBeInTheDocument();
});

// --- recursive rendered-props leak guard (carried forward) --------------------

const MARKER = 'ZZZ_ANSWER_KEY_MARKER_ZZZ';
const FORBIDDEN_KEYS = [
  'label', 'category', 'scenario_id', 'threat_pattern', 'storyline',
  'level_name', 'alert_id', 'level', 'flagged', 'chain_complete',
  'trigger', 'analyst_category', 'detected_by', 'log_source', '__future_internal__',
];

test('recursive leak guard: no non-whitelisted TOP-LEVEL field or planted marker ever renders', () => {
  const poisoned = { ...FAMILY_EVENTS.Sysmon };
  for (const k of FORBIDDEN_KEYS) poisoned[k] = MARKER;
  // top-level process_id / user / host / status are forbidden as served
  // keys too, but 'status' collides with a legitimate kvp name -- plant
  // them separately at the TOP level only
  for (const k of ['process_id', 'parent_process_id', 'user', 'host', 'status']) {
    poisoned[k] = MARKER;
  }
  renderInspector(poisoned);
  openAllFields();
  const el = screen.getByTestId('event-inspector');
  expect(el.textContent).not.toContain(MARKER);
  const rawJson = JSON.parse(el.querySelector('pre').textContent);
  for (const k of [...FORBIDDEN_KEYS, 'process_id', 'user', 'host', 'status']) {
    expect(Object.keys(rawJson)).not.toContain(k);
  }
  expect(rawJson.key_value_pairs.process_id).toBe('4412'); // untouched, legitimate
});

// --- malformed-event fallback (carried forward) --------------------------------

test('malformed event (non-object key_value_pairs) falls back to sanitized raw JSON with a notice', () => {
  const malformed = { id: 'bad-1', event_seq: 1, timestamp: 'x',
    key_value_pairs: 'not-an-object', message: 'oops', hostname: 'H' };
  renderInspector(malformed);
  expect(screen.getByRole('alert').textContent).toMatch(/could not be fully rendered/i);
  const el = screen.getByTestId('event-inspector');
  expect(el.querySelector('pre')).not.toBeNull();
  expect(el.querySelector('pre').textContent).toContain('"hostname"');
});

test('malformed event (missing id) also falls back rather than crashing', () => {
  const malformed = { event_seq: 1, timestamp: 'x', message: 'oops' };
  expect(() => renderInspector(malformed)).not.toThrow();
  expect(screen.getByRole('alert')).toBeInTheDocument();
});

test('no event selected renders nothing', () => {
  const { container } = renderInspector(null);
  expect(container).toBeEmptyDOMElement();
});

// --- the entity action menu: plain verbs, entity fields ONLY ------------------

test('an entity field opens the ONE menu; the verbs call onEntityAction with (field, action, value)', () => {
  const onEntityAction = jest.fn();
  renderInspector(FAMILY_EVENTS.Sysmon, { onEntityAction });
  fireEvent.click(screen.getByLabelText('Actions for hostname'));
  fireEvent.click(screen.getByRole('menuitem', { name: 'Filter to Just This' }));
  expect(onEntityAction).toHaveBeenCalledWith('hostname', 'only', 'ACME-WS12');
  fireEvent.click(screen.getByLabelText('Actions for hostname'));
  fireEvent.click(screen.getByRole('menuitem', { name: 'Filter This Out' }));
  expect(onEntityAction).toHaveBeenCalledWith('hostname', 'exclude', 'ACME-WS12');
  fireEvent.click(screen.getByLabelText('Actions for hostname'));
  fireEvent.click(screen.getByRole('menuitem', { name: 'Pivot: See Everything About This' }));
  expect(onEntityAction).toHaveBeenCalledWith('hostname', 'pivot', 'ACME-WS12');
});

test('Copy copies the raw value; Open in Endpoints rides host fields only', () => {
  const onHostPivot = jest.fn();
  const writeText = jest.fn(() => Promise.resolve());
  Object.assign(navigator, { clipboard: { writeText } });
  renderInspector(FAMILY_EVENTS.Sysmon, { onHostPivot });
  fireEvent.click(screen.getByLabelText('Actions for hostname'));
  fireEvent.click(screen.getByRole('menuitem', { name: 'Copy' }));
  expect(writeText).toHaveBeenCalledWith('ACME-WS12');
  fireEvent.click(screen.getByLabelText('Actions for hostname'));
  fireEvent.click(screen.getByRole('menuitem', { name: 'Open in Endpoints' }));
  expect(onHostPivot).toHaveBeenCalledWith('ACME-WS12');
  // a non-host entity field carries no Endpoints item
  fireEvent.click(screen.getByLabelText('Actions for user_account'));
  expect(screen.queryByRole('menuitem', { name: 'Open in Endpoints' })).toBeNull();
});

test('the == / != / Pivot buttons are gone everywhere; non-entity fields carry NO actions', () => {
  renderInspector(FAMILY_EVENTS.Sysmon);
  openAllFields();
  expect(screen.queryByLabelText(/Filter .+ equals/)).toBeNull();
  expect(screen.queryByLabelText(/Filter .+ not equals/)).toBeNull();
  expect(screen.queryByRole('button', { name: /^Pivot \w+$/ })).toBeNull();
  // non-entity fields: no menu trigger at all
  for (const f of ['severity', 'message', 'timestamp', 'id', 'event_type',
    'source_type', 'command_line', 'event_seq']) {
    expect(screen.queryByLabelText(`Actions for ${f}`)).toBeNull();
  }
  // entity fields in the full list carry the menu
  expect(screen.getAllByLabelText('Actions for hostname').length).toBeGreaterThanOrEqual(1);
  expect(screen.getAllByLabelText('Actions for image').length).toBeGreaterThanOrEqual(1);
});

test('event_seq renders as the arrival-position line with NO action anywhere', () => {
  renderInspector(FAMILY_EVENTS.Sysmon);
  openAllFields();
  const el = screen.getByTestId('event-inspector');
  expect(within(el).getByText(/arrived as event #101/)).toBeInTheDocument();
  expect(within(el).queryByLabelText(/event_seq/)).toBeNull();
});

// --- integration: menu actions execute through the real query path ------------

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
      if (path.startsWith('/api/events/query/new-count')) return ok({ new_count: 0, pool_growth: 0 });
      if (path.startsWith('/api/events/query')) {
        return queryResponses.length ? queryResponses.shift() : ok(snapWith([FAMILY_EVENTS.Sysmon]));
      }
      return ok({});
    });
  });

  const renderShell = () => render(
    <Siem resetTrigger={0} onHostPivot={() => {}} />);

  const showEvents = async () => {
    fireEvent.change(screen.getByLabelText('Timeframe'), { target: { value: 'all' } });
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Show Events' })); });
  };

  test('Filter to Just This executes the compiled refined query via the generator', async () => {
    renderShell();
    await showEvents();
    fireEvent.click(within(screen.getByTestId('workbench-results')).getByText(/winupdate.exe launched/));
    queryResponses.push(ok(snapWith([FAMILY_EVENTS.Sysmon], { canonical_query: 'all | * | * | hostname == "ACME-WS12"' })));
    fireEvent.click(screen.getByLabelText('Actions for hostname'));
    await act(async () => {
      fireEvent.click(screen.getByRole('menuitem', { name: 'Filter to Just This' }));
    });
    const calls = apiFetch.mock.calls.map((c) => c[0]).filter((p) => p.startsWith('/api/events/query?'));
    expect(calls[calls.length - 1]).toBe(
      `/api/events/query?q=${encodeURIComponent('all | * | * | hostname == "ACME-WS12"')}&scope=session`);
  });

  test('selection and the inspector survive a client-side sort and stay pinned to the same event', async () => {
    const rows = [FAMILY_EVENTS.Sysmon, FAMILY_EVENTS.DNS];
    queryResponses.push(ok(snapWith(rows)));
    renderShell();
    await showEvents();
    fireEvent.click(within(screen.getByTestId('workbench-results')).getByText(/winupdate.exe launched/));
    openAllFields();
    expect(screen.getByTestId('event-inspector').textContent).toContain('sy-1');

    fireEvent.click(screen.getByRole('button', { name: 'Table' }));
    await screen.findByText('Src Type');
    fireEvent.click(screen.getByRole('button', { name: /Event Type/ })); // client sort, no refetch
    expect(screen.getByTestId('event-inspector')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Cards' }));
    expect(screen.getByTestId('event-inspector')).toBeInTheDocument();
  });
});
