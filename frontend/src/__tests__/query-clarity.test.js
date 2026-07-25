/**
 * Merged Phase 3/4 commit 3.2 (Amendment 2, A2-R.1 ruled finals):
 * - Empty-run behavior (19.20): Run disables ONLY on a truly empty bar;
 *   guidance + the preserved-results label render; no request is issued.
 * - Section-named malformed errors, the ruled three-line form (19.21):
 *   "This search was not run." / "The {Section} section could not be
 *   read." (structure line when the text does not split into four) / the
 *   locked 11.3 stale statement exactly when prior results are preserved.
 * - Restore last working query (19.22): request-free, bar back to the
 *   executed canonical.
 * - The ruled permanent tooltips (19.26 at 3.2: title-attribute layer).
 * - The generated-forms corpus, frontend half (19.24): generator calls
 *   byte-equal the verbatim port of backend GENERATED_FORMS_CORPUS.
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import Siem, { QUERY_PLACEHOLDER } from '../components/Siem';
import {
  TOOLTIP_EQ, TOOLTIP_NEQ, TOOLTIP_PIVOT, TOOLTIP_SURROUNDING,
  NO_QUERY_ENTERED, SEARCH_NOT_RUN, sectionCouldNotBeRead, STRUCTURE_LINE,
  RESTORE_LAST_QUERY, PRESERVED_RESULTS_LABEL,
} from '../components/uiCopy';
import {
  sectionIndexAtPosition, pivotAccount, pivotFile, pivotProcessImage,
  pivotDomainProxy, pivotIp, refineFilter, descentAccount, descentHost,
} from '../components/lcqlPivots';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
const EVENT = {
  id: 'qc-1', event_seq: 7, timestamp: '2026-03-17T05:10:00+00:00',
  event_type: 'ProcessCreate', source_type: 'Sysmon', severity: 'high',
  hostname: 'ACME-WS12', message: 'clarity fixture event', key_value_pairs: {},
};
const SNAP = {
  token: 'tok.one',
  identity: {
    canonical_query: 'all | * | * | *', scope: 'session', resolved_scope_hosts: [],
    resolved_range: { start: '2026-03-17T03:41:00+00:00', end: '2026-03-17T05:20:00+00:00' },
    cutoff_seq: 7,
  },
  count: 1, rows: [EVENT],
};

let queryResponses;
beforeEach(() => {
  queryResponses = [];
  apiFetch.mockReset();
  apiFetch.mockImplementation((p) => {
    if (p === '/api/endpoints') return ok({ org: {}, endpoints: [] });
    if (p.startsWith('/api/events/query/new-count')) return ok({ new_count: 0, pool_growth: 0 });
    if (p.startsWith('/api/events/query')) {
      return queryResponses.length ? queryResponses.shift() : ok(SNAP);
    }
    return ok({});
  });
});

const renderShell = () =>
  render(<Siem setSiemCount={() => {}} resetTrigger={0} onHostPivot={() => {}} />);
const queryCalls = () =>
  apiFetch.mock.calls.map((c) => c[0]).filter((p) => p.startsWith('/api/events/query?'));
const run = async (text) => {
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: text } });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Run Query/ })); });
};

// --- 19.20 empty-run ------------------------------------------------------

test('Run disables ONLY on a truly empty bar; empty guidance + preserved results; no request', async () => {
  renderShell();
  const runBtn = screen.getByRole('button', { name: /Run Query/ });
  expect(runBtn).toBeDisabled();                       // empty at mount
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: '   ' } });
  expect(runBtn).toBeDisabled();                       // whitespace = empty
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: 'broken but not empty' } });
  expect(runBtn).not.toBeDisabled();                   // malformed still RUNS
  await run('all | * | * | *');
  const callsAfterRun = queryCalls().length;
  // empty the bar with results present: guidance line + label; Run disabled;
  // clicking issues nothing
  fireEvent.change(screen.getByLabelText('LCQL query'), { target: { value: '' } });
  expect(screen.getByTestId('empty-note').textContent)
    .toContain(NO_QUERY_ENTERED);
  expect(screen.getByTestId('empty-note').textContent)
    .toContain(PRESERVED_RESULTS_LABEL);
  expect(runBtn).toBeDisabled();
  fireEvent.click(runBtn);
  expect(queryCalls().length).toBe(callsAfterRun);
});

// --- 19.21 section-named errors -------------------------------------------

test('a malformed run produces the ruled three-line form with the broken section named', async () => {
  renderShell();
  await run('all | * | * | *');
  queryResponses.push(Promise.resolve({
    ok: false, status: 400,
    json: () => Promise.resolve({ error: { position: 0, reason: "unknown TIMEFRAME 'never'", suggestions: ['1h'] } }),
  }));
  await run('never | * | * | *');
  const alert = screen.getByRole('alert');
  expect(alert.textContent).toContain(SEARCH_NOT_RUN);
  expect(alert.textContent).toContain(sectionCouldNotBeRead('Time'));
  expect(alert.textContent).toContain("unknown TIMEFRAME 'never'");
  expect(alert.textContent).toContain('Did you mean: 1h?');
  // line 3 is the LOCKED 11.3 string, exactly because prior results persist
  expect(alert.textContent).toContain('Displayed results are from the previous successful query.');
  expect(within(screen.getByTestId('workbench-results'))
    .getByText('clarity fixture event')).toBeInTheDocument();
});

test('a first-run failure (no prior results) omits the stale-results line', async () => {
  renderShell();
  queryResponses.push(Promise.resolve({
    ok: false, status: 400,
    json: () => Promise.resolve({ error: { position: 7, reason: 'empty SENSOR_SELECTOR segment; use *' } }),
  }));
  await run('all |  | * | *');
  const alert = screen.getByRole('alert');
  expect(alert.textContent).toContain(sectionCouldNotBeRead('Source'));
  expect(alert.textContent).not.toContain('Displayed results are from the previous successful query.');
  expect(screen.queryByRole('button', { name: RESTORE_LAST_QUERY })).toBeNull();
});

test('a structure-level failure names the four-sections line, not a section', async () => {
  renderShell();
  queryResponses.push(Promise.resolve({
    ok: false, status: 400,
    json: () => Promise.resolve({ error: { position: 9, reason: 'expected 4 |-separated segments (TIMEFRAME | SENSOR_SELECTOR | EVENT_TYPE | FILTERS), found 2' } }),
  }));
  await run('all | xyz');
  expect(screen.getByRole('alert').textContent).toContain(STRUCTURE_LINE);
});

test('sectionIndexAtPosition maps positions to sections, quote-aware', () => {
  const q = 'all | Sysmon | 4625 | message == "a | b"';
  expect(sectionIndexAtPosition(q, 0)).toBe(0);
  expect(sectionIndexAtPosition(q, 7)).toBe(1);
  expect(sectionIndexAtPosition(q, 16)).toBe(2);
  expect(sectionIndexAtPosition(q, 25)).toBe(3);
  expect(sectionIndexAtPosition(q, 36)).toBe(3);      // the piped value never splits
  expect(sectionIndexAtPosition(q, q.length)).toBe(3); // end-of-string errors
  expect(sectionIndexAtPosition('all | xyz', 5)).toBe(null); // structure-level
});

// --- 19.22 restore --------------------------------------------------------

test('Restore last working query returns the bar to the canonical and clears the error, request-free', async () => {
  renderShell();
  await run('all | * | * | *');
  queryResponses.push(Promise.resolve({
    ok: false, status: 400,
    json: () => Promise.resolve({ error: { position: 0, reason: 'unknown TIMEFRAME' } }),
  }));
  await run('zzz | * | * | *');
  const before = queryCalls().length;
  fireEvent.click(screen.getByRole('button', { name: RESTORE_LAST_QUERY }));
  expect(screen.getByLabelText('LCQL query').value).toBe('all | * | * | *');
  expect(screen.queryByRole('alert')).toBeNull();
  expect(queryCalls().length).toBe(before);
});

// --- placeholder + tooltips (ruled finals) --------------------------------

test('the placeholder is unmistakably an example', () => {
  renderShell();
  expect(QUERY_PLACEHOLDER.startsWith('Example: ')).toBe(true);
  expect(screen.getByLabelText('LCQL query').getAttribute('placeholder'))
    .toBe(QUERY_PLACEHOLDER);
});

test('the ruled permanent explanations sit on ==, !=, Pivot, and Surrounding events', async () => {
  renderShell();
  await run('all | * | * | *');
  fireEvent.click(within(screen.getByTestId('workbench-results'))
    .getByText('clarity fixture event'));
  expect(screen.getAllByLabelText(/Filter .+ equals/)[0].getAttribute('title'))
    .toBe(TOOLTIP_EQ);
  expect(screen.getAllByLabelText(/Filter .+ not equals/)[0].getAttribute('title'))
    .toBe(TOOLTIP_NEQ);
  expect(screen.getAllByLabelText(/^Pivot /)[0].getAttribute('title'))
    .toContain(TOOLTIP_PIVOT);
  expect(screen.getByRole('button', { name: 'Surrounding events' }).getAttribute('title'))
    .toBe(TOOLTIP_SURROUNDING);
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
  ];
  expect(built).toEqual(GENERATED_FORMS_CORPUS);
  // the OR-base refine is the FRESH fallback (closure case pinned)
  expect(refineFilter(pivotIp('1h', '10.0.1.5'), 'hostname', '==', 'ACME-WS10').fresh)
    .toBe(true);
});

test('GENERATED_FORMS_CORPUS has exactly the ten entries the backend corpus has', () => {
  expect(GENERATED_FORMS_CORPUS).toHaveLength(10);
});
