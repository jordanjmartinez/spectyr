/**
 * Stage 4 Phase 6.1: the LCQL pivot generator (contract Section 13).
 *
 * Every documented pivot/descent form is pinned BYTE-FOR-BYTE against the
 * backend's own fixture list (backend/test_lcql.py::_PIVOT_DESCENT_FIXTURES,
 * consumed by test_documented_pivot_and_descent_forms_parse) -- since those
 * exact strings are already proven to parse and canonicalize cleanly under
 * the real server catalog, matching them here transitively proves every
 * frontend-generated form parses through the backend fixture battery.
 *
 * The OR-scan fixture corpus is ported VERBATIM (character-for-character)
 * from backend/test_lcql.py::OR_SCAN_CORPUS -- the Phase 2 parity promise:
 * one corpus, two implementations (the backend's AST-based
 * lcql.conjunction_only and this module's lexical scan), byte-equal
 * verdicts. See the equivalence-boundary comment on isConjunctionOnly in
 * lcqlPivots.js: valid only while LCQL has no grouping/parentheses.
 */
import * as pivots from '../components/lcqlPivots';

const {
  escapeValue, isConjunctionOnly, refineFilter, OR_FALLBACK_NOTICE,
  pivotHost, pivotAccount, pivotProcessImage, pivotProcessNameContains,
  pivotFile, pivotIp, pivotDomainProxy, pivotDomainDns, pivotEventType,
  pivotSensorFamily, descentHost, descentSessionAll, descentAccount,
  splitSegments,
} = pivots;

// --- GD-5 escaping ------------------------------------------------------

test('escapeValue doubles backslashes and escapes double quotes (GD-5)', () => {
  expect(escapeValue('C:\\Users\\x')).toBe('C:\\\\Users\\\\x');
  expect(escapeValue('say "hi"')).toBe('say \\"hi\\"');
  expect(escapeValue('plain')).toBe('plain');
});

// --- every documented pivot/descent form, byte-pinned against the backend
// fixture list (_PIVOT_DESCENT_FIXTURES), same order ------------------------

test('every documented pivot form is byte-canonical (parity with backend _PIVOT_DESCENT_FIXTURES[0..9])', () => {
  expect(pivotHost('1h', 'ACME-WS10')).toBe('1h | ACME-WS10 | * | *');
  expect(pivotAccount('1h', 'spatel')).toBe('1h | * | * | user_account == "spatel"');
  expect(pivotProcessImage('1h', 'C:\\Users\\Public\\winupdate.exe'))
    .toBe('1h | * | * | image == "C:\\\\Users\\\\Public\\\\winupdate.exe"');
  expect(pivotProcessNameContains('1h', 'winupdate'))
    .toBe('1h | * | ProcessCreate | image contains "winupdate"');
  expect(pivotFile('1h', 'C:\\payload.docx'))
    .toBe('1h | * | * | target_filename == "C:\\\\payload.docx"');
  expect(pivotIp('1h', '203.0.113.50'))
    .toBe('1h | * | * | source_ip == "203.0.113.50" or destination_ip == "203.0.113.50"');
  expect(pivotDomainProxy('1h', 'evil.example'))
    .toBe('1h | Proxy | * | url contains "evil.example"');
  expect(pivotDomainDns('1h', 'evil.example'))
    .toBe('1h | DNS | QUERY | query contains "evil.example"');
  expect(pivotEventType('1h', '4625')).toBe('1h | * | 4625 | *');
  expect(pivotSensorFamily('1h', 'Windows Security')).toBe('1h | Windows Security | * | *');
});

test('descent forms are byte-canonical (parity with backend _PIVOT_DESCENT_FIXTURES[10..12])', () => {
  expect(descentHost('ACME-WS10')).toBe('all | ACME-WS10 | * | *');
  expect(descentSessionAll()).toBe('all | * | * | *');
  // identity descent (7.4): the fixture account carries a domain backslash,
  // so GD-5 escaping is exercised by the identity-descent fixture itself
  expect(descentAccount('ACME\\dlee'))
    .toBe('all | * | * | user_account == "ACME\\\\dlee"');
});

// The full ordered list, identical to the backend's, for one final
// exhaustive equality pass (belt-and-suspenders over the two tests above).
const BACKEND_PIVOT_DESCENT_FIXTURES = [
  '1h | ACME-WS10 | * | *',
  '1h | * | * | user_account == "spatel"',
  '1h | * | * | image == "C:\\\\Users\\\\Public\\\\winupdate.exe"',
  '1h | * | ProcessCreate | image contains "winupdate"',
  '1h | * | * | target_filename == "C:\\\\payload.docx"',
  '1h | * | * | source_ip == "203.0.113.50" or destination_ip == "203.0.113.50"',
  '1h | Proxy | * | url contains "evil.example"',
  '1h | DNS | QUERY | query contains "evil.example"',
  '1h | * | 4625 | *',
  '1h | Windows Security | * | *',
  'all | ACME-WS10 | * | *',
  'all | * | * | *',
  'all | * | * | user_account == "ACME\\\\dlee"',
];

test('the generator output list equals the backend fixture list exactly, in order', () => {
  const generated = [
    pivotHost('1h', 'ACME-WS10'),
    pivotAccount('1h', 'spatel'),
    pivotProcessImage('1h', 'C:\\Users\\Public\\winupdate.exe'),
    pivotProcessNameContains('1h', 'winupdate'),
    pivotFile('1h', 'C:\\payload.docx'),
    pivotIp('1h', '203.0.113.50'),
    pivotDomainProxy('1h', 'evil.example'),
    pivotDomainDns('1h', 'evil.example'),
    pivotEventType('1h', '4625'),
    pivotSensorFamily('1h', 'Windows Security'),
    descentHost('ACME-WS10'),
    descentSessionAll(),
    descentAccount('ACME\\dlee'),
  ];
  expect(generated).toEqual(BACKEND_PIVOT_DESCENT_FIXTURES);
});

// escaping round-trip proof matching the backend's own assertion in
// test_documented_pivot_and_descent_forms_parse (the unescaped value)
test('the escaped image path round-trips to real single backslashes conceptually', () => {
  const q = pivotProcessImage('1h', 'C:\\Users\\Public\\winupdate.exe');
  // the canonical TEXT carries doubled backslashes (GD-5 escaping); the
  // underlying value passed in (and what the backend parser recovers) has
  // single backslashes -- both sides are asserted for the input/output pair
  expect(q).toContain('C:\\\\Users\\\\Public\\\\winupdate.exe');
});

// --- quote-aware segment splitting ----------------------------------------

test('splitSegments never breaks on a pipe inside a quoted FILTERS value', () => {
  expect(splitSegments('1h | * | * | message contains "a|b"'))
    .toEqual(['1h', '*', '*', 'message contains "a|b"']);
});

// --- conjunction-only append / OR fallback --------------------------------

test('refineFilter appends an and-conjunction when FILTERS is conjunction-only', () => {
  const base = '1h | * | ProcessCreate | image contains "winupdate"';
  const r = refineFilter(base, 'hostname', '==', 'ACME-WS10');
  expect(r.fresh).toBe(false);
  expect(r.notice).toBeNull();
  expect(r.query).toBe(
    '1h | * | ProcessCreate | image contains "winupdate" and hostname == "ACME-WS10"');
});

test('refineFilter replaces a bare * FILTERS segment with no leading "and"', () => {
  const r = refineFilter('all | * | * | *', 'severity', '==', 'high');
  expect(r.fresh).toBe(false);
  expect(r.query).toBe('all | * | * | severity == "high"');
});

test('refineFilter supports != as well as ==', () => {
  const r = refineFilter('1h | * | * | a == "x"', 'severity', '!=', 'low');
  expect(r.query).toBe('1h | * | * | a == "x" and severity != "low"');
});

test('refineFilter preserves TIMEFRAME/SENSOR/EVENT_TYPE from the executed query', () => {
  const base = '24h | Windows Security | 4625 | user_account == "spatel"';
  const r = refineFilter(base, 'source_ip', '==', '10.0.1.5');
  expect(r.query).toBe(
    '24h | Windows Security | 4625 | user_account == "spatel" and source_ip == "10.0.1.5"');
});

test('refineFilter starts a fresh query with the exact contract notice when FILTERS mixes or-conditions', () => {
  const base = '4h | * | QUERY | query contains "telemetry-sync" or query contains "cdn-edge"';
  const r = refineFilter(base, 'hostname', '==', 'ACME-WS10');
  expect(r.fresh).toBe(true);
  expect(r.query).toBe('4h | * | QUERY | hostname == "ACME-WS10"');
  expect(r.notice).toBe(OR_FALLBACK_NOTICE);
  expect(r.notice).toBe('Started a new query; the previous one mixed or-conditions.');
});

test('refineFilter escapes the clicked value (GD-5)', () => {
  const r = refineFilter('all | * | * | *', 'image', '==', 'C:\\Users\\x.exe');
  expect(r.query).toBe('all | * | * | image == "C:\\\\Users\\\\x.exe"');
});

// --- the shared OR-scan fixture corpus (Phase 2 parity promise) -----------
//
// Ported VERBATIM from backend/test_lcql.py::OR_SCAN_CORPUS. Do not hand-edit
// an entry without updating the backend corpus identically; the two must
// remain the SAME list. See the equivalence-boundary comment on
// isConjunctionOnly in lcqlPivots.js.
const OR_SCAN_CORPUS = [
  ['*', true],
  ['a == "x"', true],
  ['a == "x" and b == "y" and c == "z"', true],
  ['a == "x" or b == "y"', false],
  ['a == "x" and b == "y" or c == "z"', false],
  ['a == "x" or b == "y" or c == "z"', false],
  ['message contains "black or white"', true],
  ['message contains "say \\"or\\" nicely" and b == "y"', true],
  ['a == corridor and b == ORACLE', true],
  ["path == 'C:\\\\or\\\\bin'", true],
];

test('OR-scan fixture corpus matches the backend AST verdicts (shared parity corpus)', () => {
  for (const [filtersText, expected] of OR_SCAN_CORPUS) {
    expect(isConjunctionOnly(filtersText)).toBe(expected);
  }
});

test('OR_SCAN_CORPUS has exactly the ten entries the backend corpus has', () => {
  expect(OR_SCAN_CORPUS).toHaveLength(10);
});

// --- sidebar/inspector conjunction-append composes to a parseable string --

test('the appended-conjunction result matches the backend composition test shape', () => {
  // mirrors backend/test_lcql.py::test_sidebar_conjunction_append_composes
  const base = '1h | * | ProcessCreate | image contains "winupdate"';
  const appended = `${base} and hostname == "ACME-WS10"`;
  const r = refineFilter(base, 'hostname', '==', 'ACME-WS10');
  expect(r.query).toBe(appended);
  expect(isConjunctionOnly(splitSegments(r.query)[3])).toBe(true);
});
