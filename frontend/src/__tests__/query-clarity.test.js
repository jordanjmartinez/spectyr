/**
 * Query clarity (A2-R.1 finals under the owner simplification pass +
 * follow-up 2026-10-13):
 * - The ruled permanent tooltips ride the entity menu verbs (the ==/!=/
 *   Pivot buttons and the LCQL bar's error apparatus are retired with
 *   Advanced mode).
 * - Chips are the readable filter projection: plain-language labels,
 *   remove-only, recompiled through the one generator on removal.
 * - The two documented OR product forms adopt as entity chips, so refining
 *   them keeps their context.
 * - The generated-forms corpus, frontend half (19.24): generator calls
 *   byte-equal the verbatim port of backend GENERATED_FORMS_CORPUS. The
 *   retired simple-mode/advanced-bar consumers do not change the pinned
 *   generator surface (workbench-pivots holds the other corpus half).
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import Siem from '../components/Siem';
import {
  TOOLTIP_EQ, TOOLTIP_NEQ, TOOLTIP_PIVOT,
} from '../components/uiCopy';
import {
  sectionIndexAtPosition, pivotAccount, pivotFile, pivotProcessImage,
  pivotDomainProxy, pivotIp, refineFilter, descentAccount, descentHost,
  listConjuncts, removeConjunct, composeQuery, replaceTimeframe,
  rawFiltersOf, splitSegments, SOURCE_FAMILIES,
} from '../components/lcqlPivots';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
const EVENT = {
  id: 'qc-1', event_seq: 7, timestamp: '2026-03-17T05:10:00+00:00',
  event_type: 'ProcessCreate', source_type: 'Sysmon', severity: 'high',
  hostname: 'ACME-WS12', source_ip: '10.0.1.5',
  message: 'clarity fixture event', key_value_pairs: {},
};

let queryResponses;
beforeEach(() => {
  queryResponses = [];
  apiFetch.mockReset();
  apiFetch.mockImplementation((p) => {
    if (p.startsWith('/api/events/query/new-count')) return ok({ new_count: 0, pool_growth: 0 });
    if (p.startsWith('/api/events/query')) {
      if (queryResponses.length) return queryResponses.shift();
      const m = decodeURIComponent(p).match(/\?q=(.+)&scope=(.+)$/);
      return ok({
        token: 'tok.one',
        identity: {
          canonical_query: m[1], scope: m[2], resolved_scope_hosts: [],
          resolved_range: { start: '2026-03-17T03:41:00+00:00', end: '2026-03-17T05:20:00+00:00' },
          cutoff_seq: 7,
        },
        count: 1, rows: [EVENT],
      });
    }
    return ok({});
  });
});

const renderShell = () => render(<Siem resetTrigger={0} onHostPivot={() => {}} />);
const queryCalls = () =>
  apiFetch.mock.calls.map((c) => c[0]).filter((p) => p.startsWith('/api/events/query?'))
    .map(decodeURIComponent);
const showEvents = async (tfToken = 'all') => {
  fireEvent.change(screen.getByLabelText('Timeframe'), { target: { value: tfToken } });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Show Events' })); });
};
const menuAction = async (field, item) => {
  fireEvent.click(screen.getAllByLabelText(`Actions for ${field}`)[0]);
  await act(async () => {
    fireEvent.click(screen.getByRole('menuitem', { name: item }));
  });
};

// --- the ruled permanent tooltips on the menu verbs --------------------------

test('the ruled permanent explanations ride the entity menu verbs', async () => {
  renderShell();
  await showEvents();
  fireEvent.click(within(screen.getByTestId('workbench-results'))
    .getByText('clarity fixture event'));
  fireEvent.click(screen.getAllByLabelText('Actions for hostname')[0]);
  expect(screen.getByRole('menuitem', { name: 'Filter to Just This' }).getAttribute('title'))
    .toBe(TOOLTIP_EQ);
  expect(screen.getByRole('menuitem', { name: 'Filter This Out' }).getAttribute('title'))
    .toBe(TOOLTIP_NEQ);
  expect(screen.getByRole('menuitem', { name: 'Pivot: See Everything About This' }).getAttribute('title'))
    .toContain(TOOLTIP_PIVOT);
  expect(screen.queryByRole('button', { name: 'Surrounding events' })).toBeNull();
});

// --- chips: plain language, remove-only, recompiled through the generator ----

test('chips render the applied filters in plain language; a removal recompiles and reruns', async () => {
  renderShell();
  await showEvents();
  fireEvent.click(within(screen.getByTestId('workbench-results'))
    .getByText('clarity fixture event'));
  await menuAction('hostname', 'Filter to Just This');
  await act(async () => {
    fireEvent.click(within(screen.getByTestId('facet-group-severity'))
      .getByLabelText('Severity: high'));
  });
  const chips = screen.getByTestId('filter-chips');
  expect(chips.textContent).toContain('Computer: ACME-WS12');
  expect(chips.textContent).toContain('Severity: high');
  await act(async () => {
    fireEvent.click(screen.getByLabelText('Remove filter: Computer: ACME-WS12'));
  });
  expect(queryCalls().pop())
    .toBe('/api/events/query?q=all | * | * | severity == "high"&scope=session');
});

test('refining the documented ip-OR form keeps the IP context: the new filter distributes across the pair', async () => {
  renderShell();
  await showEvents();
  fireEvent.click(within(screen.getByTestId('workbench-results'))
    .getByText('clarity fixture event'));
  await menuAction('source_ip', 'Pivot: See Everything About This');
  // the documented product form IS the entity chip (never an opaque dump)
  expect(screen.getByTestId('filter-chips').textContent).toContain('IP: 10.0.1.5');
  await menuAction('hostname', 'Filter to Just This');
  expect(queryCalls().pop()).toBe(
    '/api/events/query?q=all | * | * | '
    + 'source_ip == "10.0.1.5" and hostname == "ACME-WS12"'
    + ' or destination_ip == "10.0.1.5" and hostname == "ACME-WS12"'
    + '&scope=session');
  expect(screen.getByTestId('query-notice'))
    .toHaveTextContent('Filter added: hostname == "ACME-WS12"');
});

// --- 19.24 the generated-forms corpus (frontend half) ---------------------
// Ported VERBATIM from backend/test_lcql.py::GENERATED_FORMS_CORPUS. Do not
// hand-edit one side; the backend parses these exact strings.

const GENERATED_FORMS_CORPUS = [
  '4h | * | * | user_account == "ACME\\\\o hara"',
  '12h | * | * | target_filename == "C:\\\\Tools\\\\say \\"hi\\".exe"',
  '24h | * | * | image == "and"',
  '15m | Proxy | * | url contains "evil|site*.example"',
  'all | * | * | severity == "high"',
  'all | * | * | severity == "high" and hostname != "ACME-WS10"',
  '1h | * | * | hostname == "ACME-WS10"',
  'all | * | * | message == "say \\"or\\" and | *"',
  'all | * | * | user_account == "O\'HARA@acme.com" or UserPrincipalName == "O\'HARA@acme.com"',
  'all | ACME-WS10 | * | severity == "high"',
  'all | * | * | hostname != "ACME-WS10"',
  'all | ACME-WS10 | * | *',
  '1h | * | * | *',
  '24h | Windows Security | 4625 | user_account == "spatel" and source_ip contains "10.0."',
  'all | ACME-WS12 | ProcessCreate | *',
  '15m | DNS | QUERY | message contains "say \\"or\\" | nicely"',
  '24h | Sysmon | ProcessCreate | image contains "winupdate"',
  'all | * | * | message contains "a|b"',
];

test('the generator emits the generated-forms corpus byte-exact (closure incl. adversarial values)', () => {
  const built = [
    pivotAccount('4h', 'ACME\\o hara'),
    pivotFile('12h', 'C:\\Tools\\say "hi".exe'),
    pivotProcessImage('24h', 'and'),
    pivotDomainProxy('15m', 'evil|site*.example'),
    refineFilter('all | * | * | *', 'severity', '==', 'high').query,
    refineFilter('all | * | * | severity == "high"', 'hostname', '!=', 'ACME-WS10').query,
    refineFilter(pivotIp('1h', '10.0.1.5'), 'hostname', '==', 'ACME-WS10').query,
    refineFilter('all | * | * | *', 'message', '==', 'say "or" and | *').query,
    descentAccount("O'HARA@acme.com"),
    refineFilter(descentHost('ACME-WS10'), 'severity', '==', 'high').query,
    removeConjunct('all | * | * | severity == "high" and hostname != "ACME-WS10"', 0),
    removeConjunct('all | ACME-WS10 | * | severity == "high"', 0),
    composeQuery('1h', '*', '*', ''),
    composeQuery('24h', 'Windows Security', '4625',
      'user_account == "spatel" and source_ip contains "10.0."'),
    composeQuery('all', 'ACME-WS12', 'ProcessCreate', '  '),
    composeQuery('15m', 'DNS', 'QUERY', 'message contains "say \\"or\\" | nicely"'),
    replaceTimeframe('1h | Sysmon | ProcessCreate | image contains "winupdate"', '24h'),
    replaceTimeframe('1h | * | * | message contains "a|b"', 'all'),
  ];
  expect(built).toEqual(GENERATED_FORMS_CORPUS);
  // the OR-base refine is the FRESH fallback (closure case pinned)
  expect(refineFilter(pivotIp('1h', '10.0.1.5'), 'hostname', '==', 'ACME-WS10').fresh)
    .toBe(true);
});

test('GENERATED_FORMS_CORPUS has exactly the eighteen entries the backend corpus has', () => {
  expect(GENERATED_FORMS_CORPUS).toHaveLength(18);
});

test('SOURCE_FAMILIES mirrors the backend family set (two-sided parity literal)', () => {
  expect(SOURCE_FAMILIES).toEqual([
    'Sysmon', 'Windows Security', 'Proxy', 'DNS', 'Firewall',
    'Azure AD', 'Veeam', 'Defender',
  ]);
});

test('sectionIndexAtPosition maps positions to sections, quote-aware (parity unit, no render site)', () => {
  const q = 'all | Sysmon | 4625 | message == "a | b"';
  expect(sectionIndexAtPosition(q, 0)).toBe(0);
  expect(sectionIndexAtPosition(q, 7)).toBe(1);
  expect(sectionIndexAtPosition(q, 16)).toBe(2);
  expect(sectionIndexAtPosition(q, 25)).toBe(3);
  expect(sectionIndexAtPosition(q, 36)).toBe(3);      // the piped value never splits
  expect(sectionIndexAtPosition(q, q.length)).toBe(3); // end-of-string errors
  expect(sectionIndexAtPosition('all | xyz', 5)).toBe(null); // structure-level
});

test('replaceTimeframe byte-matches the retired raw splice on ordinary forms and fixes the quoted-pipe case', () => {
  const oldSplice = (t, tok) => {
    if (t.trim() === '') return `${tok} | * | * | *`;
    const idx = t.indexOf('|');
    if (idx === -1) return tok;
    return `${tok} ${t.slice(idx)}`;
  };
  for (const t of ['1h | * | * | *',
    '24h | Windows Security | 4625 | user_account == "spatel"',
    'all | ACME-WS10 | * | severity == "high"', '', 'garbage']) {
    expect(replaceTimeframe(t, '4h')).toBe(oldSplice(t, '4h'));
  }
  // the old splice split INSIDE a quoted value; the chokepoint form cannot
  expect(replaceTimeframe('1h | * | * | message contains "a|b"', 'all'))
    .toBe('all | * | * | message contains "a|b"');
  expect(oldSplice('1h | * | * | message contains "a|b"', 'all'))
    .toBe('all | * | * | message contains "a|b"');   // same here by luck of the FIRST pipe
});

test('representability round-trip: every corpus canonical decomposes into segments and recompiles byte-identically', () => {
  for (const q of GENERATED_FORMS_CORPUS) {
    const segs = splitSegments(q);
    expect(segs).toHaveLength(4);
    const raw = rawFiltersOf(q);
    expect(raw).not.toBeNull();
    expect(composeQuery(segs[0], segs[1], segs[2], raw)).toBe(q);
  }
});

// --- 19.23 the conjunct projection (shared parity corpus) ---------------------
// Ported VERBATIM from backend/test_lcql.py::CONJUNCT_SPLIT_CORPUS.

const CONJUNCT_SPLIT_CORPUS = [
  ['*', []],
  ['a == "x"', ['a == "x"']],
  ['a == "x" and b != "y" and c contains "z z"',
   ['a == "x"', 'b != "y"', 'c contains "z z"']],
  ['message contains "black and white"',
   ['message contains "black and white"']],
  ['a == "x" or b == "y"', null],
  ['path == "C:\\\\and\\\\bin" and q == "w"',
   ['path == "C:\\\\and\\\\bin"', 'q == "w"']],
];

test('listConjuncts matches the backend AST decomposition (shared parity corpus)', () => {
  for (const [filters, expected] of CONJUNCT_SPLIT_CORPUS) {
    expect({ filters, got: listConjuncts(`all | * | * | ${filters}`) })
      .toEqual({ filters, got: expected });
  }
  expect(CONJUNCT_SPLIT_CORPUS).toHaveLength(6);
});

test('removeConjunct regenerates through the generator and stays canonical (parity unit)', () => {
  expect(listConjuncts(pivotIp('1h', '203.0.113.50'))).toBe(null);
  expect(listConjuncts(descentAccount('ACME\\dlee'))).toBe(null);
  expect(listConjuncts('all | * | * | severity == "high" and hostname != "A"'))
    .toEqual(['severity == "high"', 'hostname != "A"']);
  expect(removeConjunct('1h | Sysmon | 4625 | a == "x" and b == "y"', 1))
    .toBe('1h | Sysmon | 4625 | a == "x"');
  expect(removeConjunct('1h | Sysmon | 4625 | a == "x"', 0))
    .toBe('1h | Sysmon | 4625 | *');
  // out-of-range or non-decomposable removal is a no-op, never a corruption
  expect(removeConjunct(pivotIp('1h', '10.0.0.1'), 0))
    .toBe(pivotIp('1h', '10.0.0.1'));
});
