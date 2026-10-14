/**
 * Owner SIEM simplification pass (2026-10-13): the ONE filter system's
 * model layer.
 *
 * - facetQuery (the lcqlPivots chokepoint form): AND-of-ORs distributes
 *   into the grammar's native OR-of-ANDs (no parentheses exist in LCQL),
 *   using ONLY documented operators and GD-5 double-quote escaping.
 * - compileChips: include groups OR within a field, AND across fields;
 *   entity chips mint the documented multi-field OR pairs; excludes and
 *   contains ride every arm.
 * - adoptQuery: a READ projection -- an executed canonical adopts into
 *   chips exactly when recompiling reproduces its semantics; everything
 *   else (grouping-ambiguous OR mixes, case-sensitive single quotes,
 *   contradictory duplicate ==) returns null, never an approximation.
 * - fieldDecodes: plain-language decodes (logon type 3 = Network, failure
 *   substatus 0xC000006A = incorrect password) that never hide the raw
 *   value, and the six default facet groups / deleted-group lists.
 */
import {
  facetQuery, splitSegments, isConjunctionOnly,
} from '../components/lcqlPivots';
import {
  compileChips, adoptQuery, toggleInclude, hasInclude, describeChip,
  entityChipFor, fieldValueCounts, ENTITY_FIELDS, ENTITY_ALTS,
  FILTERABLE_TOP_FIELDS, parseSearchInput, mergeChips,
} from '../components/facetModel';
import {
  decodeFieldValue, labelForField, DEFAULT_FACET_FIELDS, HIDDEN_FACET_FIELDS,
  EVENT_TYPE_LABELS, LOGON_TYPE_LABELS, STATUS_CODE_LABELS,
} from '../components/fieldDecodes';
import kvpCatalogOrder from '../components/kvpCatalogOrder.json';

// --- facetQuery: the generator form ----------------------------------------

test('no groups and no conjuncts compiles to the match-all FILTERS', () => {
  expect(facetQuery('1h', [])).toBe('1h | * | * | *');
});

test('one include group ORs within the field', () => {
  expect(facetQuery('1h', [[
    { field: 'event_type', value: '4625' },
    { field: 'event_type', value: '4624' },
  ]])).toBe('1h | * | * | event_type == "4625" or event_type == "4624"');
});

test('two groups distribute into OR-of-ANDs (LCQL has no grouping)', () => {
  const q = facetQuery('24h', [
    [{ field: 'event_type', value: '4625' }, { field: 'event_type', value: '4624' }],
    [{ field: 'severity', value: 'high' }],
  ]);
  expect(q).toBe(
    '24h | * | * | event_type == "4625" and severity == "high"'
    + ' or event_type == "4624" and severity == "high"');
});

test('excludes and contains ride EVERY arm', () => {
  const q = facetQuery('1h',
    [[{ field: 'severity', value: 'high' }, { field: 'severity', value: 'medium' }]],
    [{ field: 'hostname', op: '!=', value: 'ACME-WS10' },
     { field: 'image', op: 'contains', value: 'powershell' }]);
  expect(q).toBe(
    '1h | * | * | severity == "high" and hostname != "ACME-WS10" and image contains "powershell"'
    + ' or severity == "medium" and hostname != "ACME-WS10" and image contains "powershell"');
});

test('values are GD-5 escaped (backslashes doubled, quotes escaped)', () => {
  const q = facetQuery('1h', [[{ field: 'user_account', value: 'ACME\\o hara' }]]);
  expect(q).toBe('1h | * | * | user_account == "ACME\\\\o hara"');
});

// --- compileChips -------------------------------------------------------------

test('include chips group by field; entity chips mint the documented OR pairs', () => {
  const q = compileChips('1h', [
    { type: 'include', field: 'severity', value: 'high' },
    { type: 'entity', kind: 'ip', value: '10.0.1.5' },
  ]);
  expect(q).toBe(
    '1h | * | * | severity == "high" and source_ip == "10.0.1.5"'
    + ' or severity == "high" and destination_ip == "10.0.1.5"');
});

test('the account entity chip is the ruled two-field identity pair', () => {
  expect(compileChips('all', [{ type: 'entity', kind: 'account', value: 'ACME\\dlee' }]))
    .toBe('all | * | * | user_account == "ACME\\\\dlee" or UserPrincipalName == "ACME\\\\dlee"');
});

test('exclude and contains chips are universal conjuncts', () => {
  expect(compileChips('4h', [
    { type: 'exclude', field: 'severity', value: 'low' },
    { type: 'contains', field: 'command_line', value: 'enc', negated: false },
    { type: 'contains', field: 'url', value: 'cdn', negated: true },
  ])).toBe('4h | * | * | severity != "low" and command_line contains "enc" and url not contains "cdn"');
});

test('every compiled form stays inside the documented grammar (quick structural scan)', () => {
  const q = compileChips('1h', [
    { type: 'include', field: 'event_type', value: '4625' },
    { type: 'include', field: 'event_type', value: '4624' },
    { type: 'include', field: 'severity', value: 'high' },
    { type: 'exclude', field: 'hostname', value: 'ACME-WS10' },
  ]);
  const segs = splitSegments(q);
  expect(segs).toHaveLength(4);
  expect(segs[1]).toBe('*');
  expect(segs[2]).toBe('*');
  // only ==, !=, contains, and/or appear; no parentheses ever
  expect(q).not.toMatch(/[()]/);
});

// --- toggle / describe ---------------------------------------------------------

test('toggleInclude adds then removes the same value (multi-select)', () => {
  let chips = [];
  chips = toggleInclude(chips, 'severity', 'high');
  chips = toggleInclude(chips, 'severity', 'medium');
  expect(hasInclude(chips, 'severity', 'high')).toBe(true);
  expect(hasInclude(chips, 'severity', 'medium')).toBe(true);
  chips = toggleInclude(chips, 'severity', 'high');
  expect(hasInclude(chips, 'severity', 'high')).toBe(false);
  expect(chips).toHaveLength(1);
});

test('describeChip renders plain-language labels with decoded values', () => {
  expect(describeChip({ type: 'include', field: 'event_type', value: '4625' }))
    .toBe('Event: Failed Logon (4625)');
  expect(describeChip({ type: 'include', field: 'hostname', value: 'ACME-WS10' }))
    .toBe('Computer: ACME-WS10');
  expect(describeChip({ type: 'exclude', field: 'severity', value: 'low' }))
    .toBe('Not Severity: low');
  expect(describeChip({ type: 'entity', kind: 'ip', value: '10.0.1.5' }))
    .toBe('IP: 10.0.1.5');
  expect(describeChip({ type: 'contains', field: 'image', value: 'powershell.exe', negated: false }))
    .toBe('Process contains "powershell.exe"');
});

// --- entity map (the ONLY filter/pivot-bearing fields) -------------------------

test('every entity field is a serialized observable field (commons or cataloged kvp)', () => {
  const top = new Set(FILTERABLE_TOP_FIELDS);
  for (const field of Object.keys(ENTITY_FIELDS)) {
    expect({ field, known: top.has(field) || kvpCatalogOrder.includes(field) })
      .toEqual({ field, known: true });
  }
});

test('entityChipFor maps user to the account pair, ips to the ip pair, hosts and processes to includes', () => {
  expect(entityChipFor('user_account', 'dlee'))
    .toEqual({ type: 'entity', kind: 'account', value: 'dlee' });
  expect(entityChipFor('workstation_name', 'ACME-WS08'))
    .toEqual({ type: 'include', field: 'hostname', value: 'ACME-WS08' });
  expect(entityChipFor('destination_ip', '52.1.2.3'))
    .toEqual({ type: 'entity', kind: 'ip', value: '52.1.2.3' });
  expect(entityChipFor('parent_image', 'C:\\Windows\\explorer.exe'))
    .toEqual({ type: 'include', field: 'image', value: 'C:\\Windows\\explorer.exe' });
  expect(entityChipFor('process_name', 'powershell.exe'))
    .toEqual({ type: 'contains', field: 'image', value: 'powershell.exe', negated: false });
  expect(entityChipFor('severity', 'high')).toBeNull();
});

test('the entity alt pairs are exactly the two documented OR forms', () => {
  expect(ENTITY_ALTS.account.fields).toEqual(['user_account', 'UserPrincipalName']);
  expect(ENTITY_ALTS.ip.fields).toEqual(['source_ip', 'destination_ip']);
});

// --- adoption -------------------------------------------------------------------

test('adopt(compile(chips)) round-trips for single-value facet states', () => {
  const chips = [
    { type: 'include', field: 'event_type', value: '4625' },
    { type: 'include', field: 'severity', value: 'high' },
    { type: 'exclude', field: 'hostname', value: 'ACME-WS10' },
  ];
  const adopted = adoptQuery(compileChips('24h', chips));
  expect(adopted.tf).toBe('24h');
  expect(adopted.chips).toEqual(chips);
});

test('descent and pivot forms adopt: host sensor, event-type segment, identity OR, ip OR', () => {
  expect(adoptQuery('all | ACME-WS10 | * | *')).toEqual({
    tf: 'all', chips: [{ type: 'include', field: 'hostname', value: 'ACME-WS10' }],
  });
  expect(adoptQuery('1h | Sysmon | ProcessCreate | *')).toEqual({
    tf: '1h',
    chips: [
      { type: 'include', field: 'source_type', value: 'Sysmon' },
      { type: 'include', field: 'event_type', value: 'ProcessCreate' },
    ],
  });
  expect(adoptQuery('all | * | * | user_account == "ACME\\\\dlee" or UserPrincipalName == "ACME\\\\dlee"'))
    .toEqual({ tf: 'all', chips: [{ type: 'entity', kind: 'account', value: 'ACME\\dlee' }] });
  expect(adoptQuery('1h | * | * | source_ip == "10.0.1.5" or destination_ip == "10.0.1.5"'))
    .toEqual({ tf: '1h', chips: [{ type: 'entity', kind: 'ip', value: '10.0.1.5' }] });
});

test('adoption refuses what the chip model cannot represent exactly', () => {
  // grouping-ambiguous OR mix
  expect(adoptQuery('1h | * | * | severity == "high" or hostname == "A"')).toBeNull();
  // and/or mixed at the top level
  expect(adoptQuery('1h | * | * | a == "x" and b == "y" or c == "z"')).toBeNull();
  // case-sensitive single-quoted value
  expect(adoptQuery("1h | * | * | severity == 'High'")).toBeNull();
  // contradictory duplicate == on one field would silently become an OR
  expect(adoptQuery('1h | * | * | severity == "high" and severity == "low"')).toBeNull();
  // a FILTERS == on a field the sensor segment already pinned
  expect(adoptQuery('1h | Sysmon | * | source_type == "DNS"')).toBeNull();
  // structure-level garbage
  expect(adoptQuery('not a query')).toBeNull();
});

test('adoption keeps conjunction-only parity with the lexical scan on its inputs', () => {
  // whatever adopts from a pure conjunction must indeed be conjunction-only
  const q = 'all | * | * | severity == "high" and image contains "winupdate"';
  expect(isConjunctionOnly(splitSegments(q)[3])).toBe(true);
  expect(adoptQuery(q).chips).toEqual([
    { type: 'include', field: 'severity', value: 'high' },
    { type: 'contains', field: 'image', value: 'winupdate', negated: false },
  ]);
});

// --- fieldValueCounts -----------------------------------------------------------

test('fieldValueCounts counts top-level and kvp values, sorted by count then value', () => {
  const rows = [
    { id: 'a', hostname: 'H1', key_value_pairs: { image: 'a.exe' } },
    { id: 'b', hostname: 'H1', key_value_pairs: { image: 'b.exe' } },
    { id: 'c', hostname: 'H2', key_value_pairs: null },
  ];
  expect(fieldValueCounts(rows, 'hostname'))
    .toEqual([{ value: 'H1', count: 2 }, { value: 'H2', count: 1 }]);
  expect(fieldValueCounts(rows, 'image'))
    .toEqual([{ value: 'a.exe', count: 1 }, { value: 'b.exe', count: 1 }]);
  expect(fieldValueCounts(rows, 'absent')).toEqual([]);
});

// --- decodes + vocabulary --------------------------------------------------------

test('the owner-specified decodes are exact: logon types and failure substatus codes', () => {
  expect(LOGON_TYPE_LABELS[3]).toBe('Network');
  expect(LOGON_TYPE_LABELS[10]).toBe('Remote Desktop (RDP)');
  expect(STATUS_CODE_LABELS['0XC000006A']).toBe('Incorrect Password');
  expect(STATUS_CODE_LABELS['0XC0000064']).toBe('No Such User');
  expect(STATUS_CODE_LABELS['0XC0000234']).toBe('Account Locked Out');
  expect(decodeFieldValue('logon_type', '3')).toBe('Network (3)');
  expect(decodeFieldValue('logon_type', '10')).toBe('Remote Desktop (RDP) (10)');
  expect(decodeFieldValue('sub_status', '0xC000006A')).toBe('Incorrect Password (0xC000006A)');
  expect(decodeFieldValue('event_type', '4625')).toBe('Failed Logon (4625)');
  expect(EVENT_TYPE_LABELS.ProcessCreate).toBe('Process Started');
  // decoding never hides the raw value
  expect(decodeFieldValue('event_type', '4624')).toContain('(4624)');
  // unmapped values decode to null (render raw)
  expect(decodeFieldValue('event_type', 'ZZZ_UNKNOWN')).toBeNull();
  expect(decodeFieldValue('message', 'anything')).toBeNull();
});

test('the six default groups and the deleted groups are the owner-specified lists', () => {
  expect(DEFAULT_FACET_FIELDS).toEqual([
    'event_type', 'severity', 'user_account', 'hostname', 'source_ip', 'source_type',
  ]);
  expect(HIDDEN_FACET_FIELDS).toEqual([
    'id', 'timestamp', 'message', 'logon_guid', 'key_length', 'channel',
    'caller_process_id',
  ]);
  // playtest micro-fix (2026-10-13): plain "Event"
  expect(labelForField('event_type')).toBe('Event');
  // owner follow-up (2026-10-13): plain technical names for the IP groups
  expect(labelForField('source_ip')).toBe('Source IP');
  expect(labelForField('destination_ip')).toBe('Destination IP');
  expect(labelForField('hostname')).toBe('Computer');
  expect(labelForField('source_type')).toBe('Log Source');
  // the prettify fallback: snake_case and PascalCase both read plainly
  expect(labelForField('failure_reason')).toBe('Failure Reason');
  expect(labelForField('ConditionalAccessStatus')).toBe('Conditional Access Status');
  expect(labelForField('dest_port')).toBe('Dest Port');
});

// --- the simple search box parser (owner follow-up pass, 2026-10-13) -----------

test('field = value resolves friendly aliases and raw field names into include chips', () => {
  expect(parseSearchInput('computer = ACME-WS28'))
    .toEqual({ chips: [{ type: 'include', field: 'hostname', value: 'ACME-WS28' }] });
  expect(parseSearchInput('User Account = nkhan'))
    .toEqual({ chips: [{ type: 'include', field: 'user_account', value: 'nkhan' }] });
  expect(parseSearchInput('severity = high'))
    .toEqual({ chips: [{ type: 'include', field: 'severity', value: 'high' }] });
  // raw catalog names work too (top-level and kvp), case-insensitively
  expect(parseSearchInput('logon_type = 3'))
    .toEqual({ chips: [{ type: 'include', field: 'logon_type', value: '3' }] });
  expect(parseSearchInput('Source IP = 10.0.1.5'))
    .toEqual({ chips: [{ type: 'include', field: 'source_ip', value: '10.0.1.5' }] });
  // == works as a muscle-memory alias for =
  expect(parseSearchInput('severity == high'))
    .toEqual({ chips: [{ type: 'include', field: 'severity', value: 'high' }] });
  // quoted values unwrap
  expect(parseSearchInput('command = "foo bar.exe"'))
    .toEqual({ chips: [{ type: 'include', field: 'command_line', value: 'foo bar.exe' }] });
});

test('ip = value mints the two-field entity chip; ip contains is a friendly structured error', () => {
  expect(parseSearchInput('ip = 10.0.1.5'))
    .toEqual({ chips: [{ type: 'entity', kind: 'ip', value: '10.0.1.5' }] });
  expect(parseSearchInput('ip contains 10.0.'))
    .toEqual({ error: { kind: 'ip_contains' } });
});

test('field contains text becomes a contains chip', () => {
  expect(parseSearchInput('user contains khan'))
    .toEqual({ chips: [{ type: 'contains', field: 'user_account', value: 'khan', negated: false }] });
  expect(parseSearchInput('Process CONTAINS powershell'))
    .toEqual({ chips: [{ type: 'contains', field: 'image', value: 'powershell', negated: false }] });
});

test('plain free text searches the event message', () => {
  expect(parseSearchInput('nmap launched'))
    .toEqual({ chips: [{ type: 'contains', field: 'message', value: 'nmap launched', negated: false }] });
  expect(parseSearchInput('  '))
    .toEqual({ chips: [] });
});

test('an unknown field is a structured error naming what was typed', () => {
  expect(parseSearchInput('computr = ACME-WS28'))
    .toEqual({ error: { kind: 'unknown_field', name: 'computr' } });
  expect(parseSearchInput('zzz contains x'))
    .toEqual({ error: { kind: 'unknown_field', name: 'zzz' } });
});

test('mergeChips appends only chips not already present (dedupe by identity)', () => {
  const base = [{ type: 'include', field: 'severity', value: 'high' }];
  expect(mergeChips(base, [{ type: 'include', field: 'severity', value: 'high' }]))
    .toBe(base);
  const merged = mergeChips(base, [{ type: 'include', field: 'hostname', value: 'H' }]);
  expect(merged).toHaveLength(2);
});

// --- purity (the cross-host pattern applied to the new modules) -----------------

test('facetModel and fieldDecodes are pure: no fetch, no api access, no React', () => {
  const fs = require('fs');
  const path = require('path');
  for (const f of ['facetModel.js', 'fieldDecodes.js']) {
    const src = fs.readFileSync(path.join(__dirname, '..', 'components', f), 'utf8');
    expect(src).not.toMatch(/apiFetch|fetch\s*\(|XMLHttpRequest|localStorage/);
    expect(src).not.toMatch(/from 'react'/);
  }
});
