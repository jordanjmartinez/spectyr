// Owner SIEM simplification pass (2026-10-13): the ONE filter system's chip
// model. Chips are the player-facing filter state; they compile to canonical
// LCQL through the one generator chokepoint (lcqlPivots.facetQuery) and are
// re-derived from an executed canonical query by adoptQuery (a READ
// projection: adoption either reproduces the query's semantics exactly or
// returns null, never a lossy approximation). Pure functions only: no
// React, no fetch, no hidden state.
//
// Chip shapes:
//   { type: 'include',  field, value }            field == "value"; several
//                                                 on one field OR together
//   { type: 'exclude',  field, value }            field != "value" on every arm
//   { type: 'contains', field, value, negated }   field [not] contains "value"
//   { type: 'entity',   kind, value }             the multi-field OR entity
//                                                 forms (account, ip)
import { facetQuery, splitSegments, SOURCE_FAMILIES } from './lcqlPivots';
import { labelForField, decodeFieldValue } from './fieldDecodes';
import kvpCatalogOrder from './kvpCatalogOrder.json';

// The FILTERS-authorized top-level field catalog (contract 10.1 minus
// `event_seq`, which the backend catalog marks non-filterable -- see
// lcql.py's NON_FILTERABLE_TOP). Moved here from the retired
// fieldSummary.js with the facet rail; the cross-host structural suite
// pins ENTITY_FIELDS against this list plus the kvp catalog.
export const FILTERABLE_TOP_FIELDS = [
  'id', 'timestamp', 'event_type', 'source_type', 'severity',
  'hostname', 'source_ip', 'destination_ip', 'user_account', 'message',
];

// --- entity fields (the ONLY fields that carry filter/pivot actions in the
// inspector; owner spec: user, source IP, workstation, host, destination,
// process name). Every key is a serialized observable field -- canonical
// commons or cataloged kvp keys -- pinned structurally by the cross-host
// suite, so nothing hidden can enter query generation through this map.
export const ENTITY_FIELDS = {
  user_account: 'account',
  account_name: 'account',
  target_account_name: 'account',
  subject_account_name: 'account',
  UserPrincipalName: 'account',
  user: 'account',
  src_user: 'account',
  target_user: 'account',
  parent_user: 'account',
  source_ip: 'ip',
  destination_ip: 'ip',
  IPAddress: 'ip',
  ip_address: 'ip',
  client_address: 'ip',
  src_ip: 'ip',
  dst_ip: 'ip',
  hostname: 'host',
  workstation_name: 'host',
  computer: 'host',
  caller_computer_name: 'host',
  image: 'process_image',
  parent_image: 'process_image',
  source_image: 'process_image',
  target_image: 'process_image',
  process_name: 'process_name',
  new_process_name: 'process_name',
  caller_process_name: 'process_name',
};

// The two multi-field OR entity forms. The account pair mirrors the ruled
// uniform identity descent (user_account OR UserPrincipalName); the ip pair
// mirrors the documented ip pivot (source OR destination).
export const ENTITY_ALTS = {
  account: { label: 'Account', fields: ['user_account', 'UserPrincipalName'] },
  ip: { label: 'IP', fields: ['source_ip', 'destination_ip'] },
};

// "Pivot: See Everything About This" from an entity field mints ONE fresh
// chip for the entity (the whole new filter state).
export function entityChipFor(field, value) {
  const kind = ENTITY_FIELDS[field];
  if (kind === 'account') return { type: 'entity', kind: 'account', value };
  if (kind === 'ip') return { type: 'entity', kind: 'ip', value };
  if (kind === 'host') return { type: 'include', field: 'hostname', value };
  if (kind === 'process_image') return { type: 'include', field: 'image', value };
  if (kind === 'process_name') {
    return { type: 'contains', field: 'image', value, negated: false };
  }
  return null;
}

// --- compile -----------------------------------------------------------------

// Chips -> the canonical four-part query, through the one generator form.
// Include chips group by field (OR within a field); each entity chip is its
// own OR group; excludes and contains ride every arm.
export function compileChips(tf, chips) {
  const groups = [];
  const byField = new Map();
  const conjuncts = [];
  for (const chip of chips) {
    if (chip.type === 'include') {
      if (!byField.has(chip.field)) {
        byField.set(chip.field, []);
        groups.push(byField.get(chip.field));
      }
      byField.get(chip.field).push({ field: chip.field, value: chip.value });
    } else if (chip.type === 'entity') {
      groups.push(ENTITY_ALTS[chip.kind].fields
        .map((field) => ({ field, value: chip.value })));
    } else if (chip.type === 'exclude') {
      conjuncts.push({ field: chip.field, op: '!=', value: chip.value });
    } else if (chip.type === 'contains') {
      conjuncts.push({
        field: chip.field,
        op: chip.negated ? 'not contains' : 'contains',
        value: chip.value,
      });
    }
  }
  return facetQuery(tf, groups, conjuncts);
}

// --- chip identity + toggling ------------------------------------------------

export const chipKey = (chip) => (chip.type === 'entity'
  ? `entity|${chip.kind}|${chip.value}`
  : `${chip.type}|${chip.field}|${chip.value}|${chip.negated ? 1 : 0}`);

export const hasInclude = (chips, field, value) =>
  chips.some((c) => c.type === 'include' && c.field === field && c.value === value);

// Toggle one facet value (the rail's multi-select): add the include chip if
// absent, remove it if present.
export function toggleInclude(chips, field, value) {
  if (hasInclude(chips, field, value)) {
    return chips.filter((c) => !(c.type === 'include' && c.field === field && c.value === value));
  }
  return [...chips, { type: 'include', field, value }];
}

// --- display -----------------------------------------------------------------

const shortValue = (field, value) => decodeFieldValue(field, value) || String(value);

export function describeChip(chip) {
  if (chip.type === 'entity') return `${ENTITY_ALTS[chip.kind].label}: ${chip.value}`;
  if (chip.type === 'exclude') return `Not ${labelForField(chip.field)}: ${shortValue(chip.field, chip.value)}`;
  if (chip.type === 'contains') {
    return `${labelForField(chip.field)} ${chip.negated ? 'does not contain' : 'contains'} "${chip.value}"`;
  }
  return `${labelForField(chip.field)}: ${shortValue(chip.field, chip.value)}`;
}

// --- adoption (canonical query -> chips) --------------------------------------
// The READ projection: an executed canonical query is adopted into chip
// state exactly when the chips would recompile to the same semantics.
// Anything else -- grouping-ambiguous OR mixes, case-sensitive single-quoted
// values, duplicate == predicates on one field inside a conjunction --
// returns null and the shell shows the one Custom Query chip instead.

const TF_TOKENS = ['15m', '1h', '4h', '12h', '24h', 'all'];

// Unescape one canonical value lexeme. Double-quoted and unquoted values are
// case-insensitive like the compiled form; a single-quoted (case-sensitive)
// value is NOT representable as a chip.
function unquoteValue(raw) {
  const text = raw.trim();
  if (text.startsWith('"') && text.endsWith('"') && text.length >= 2) {
    const inner = text.slice(1, -1);
    let out = '';
    for (let i = 0; i < inner.length; i += 1) {
      const c = inner[i];
      if (c === '\\' && i + 1 < inner.length && ['"', "'", '\\'].includes(inner[i + 1])) {
        out += inner[i + 1];
        i += 1;
      } else if (c === '"') {
        return null;
      } else {
        out += c;
      }
    }
    return out;
  }
  if (text.startsWith("'")) return null;
  if (/^[^\s"'=!|*]+$/.test(text)) return text;
  return null;
}

// Parse one canonical predicate text into {field, op, value}, or null.
function parsePredicate(text) {
  const m = text.trim().match(
    /^([A-Za-z0-9_]+)\s+(==|!=|contains|not\s+contains)\s+([\s\S]+)$/);
  if (!m) return null;
  const value = unquoteValue(m[3]);
  if (value === null) return null;
  return { field: m[1], op: m[2].replace(/\s+/g, ' ').toLowerCase(), value };
}

// Quote-aware top-level token scan of a FILTERS text: returns the list of
// predicate texts split at the given connective word ('and' | 'or'), or
// null when the OTHER connective also appears at the top level.
function splitOn(text, word) {
  const other = word === 'and' ? 'or' : 'and';
  const tokens = [];
  let quote = null;
  let start = -1;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (quote) {
      if (c === '\\' && i + 1 < text.length) { i += 1; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") {
      if (start === -1) start = i;
      quote = c;
      continue;
    }
    if (/\s/.test(c)) {
      if (start !== -1) { tokens.push([start, i]); start = -1; }
      continue;
    }
    if (start === -1) start = i;
  }
  if (start !== -1) tokens.push([start, text.length]);
  const parts = [];
  let spanStart = null;
  let spanEnd = null;
  for (const [s, e] of tokens) {
    const tok = text.slice(s, e).toLowerCase();
    if (tok === other) return null;
    if (tok === word) {
      if (spanStart !== null) parts.push(text.slice(spanStart, spanEnd));
      spanStart = null;
      continue;
    }
    if (spanStart === null) spanStart = s;
    spanEnd = e;
  }
  if (spanStart !== null) parts.push(text.slice(spanStart, spanEnd));
  return parts;
}

// Adopt a conjunction-only FILTERS text into chips, or null.
function adoptConjunction(filtersText) {
  const parts = splitOn(filtersText, 'and');
  if (parts === null) return null;
  const chips = [];
  const seenEq = new Set();
  for (const part of parts) {
    const p = parsePredicate(part);
    if (p === null) return null;
    if (p.op === '==') {
      // two == on one field inside an AND is a contradiction the chip
      // model would silently turn into an OR -- not adoptable
      if (seenEq.has(p.field)) return null;
      seenEq.add(p.field);
      chips.push({ type: 'include', field: p.field, value: p.value });
    } else if (p.op === '!=') {
      chips.push({ type: 'exclude', field: p.field, value: p.value });
    } else {
      chips.push({
        type: 'contains', field: p.field, value: p.value,
        negated: p.op === 'not contains',
      });
    }
  }
  return chips;
}

// Adopt a pure-OR FILTERS text when it is one of the two documented
// entity forms (same value across the form's field pair), or null.
function adoptEntityOr(filtersText) {
  const parts = splitOn(filtersText, 'or');
  if (parts === null || parts.length !== 2) return null;
  const preds = parts.map(parsePredicate);
  if (preds.some((p) => p === null || p.op !== '==')) return null;
  if (preds[0].value !== preds[1].value) return null;
  const fields = preds.map((p) => p.field).sort();
  for (const [kind, { fields: alt }] of Object.entries(ENTITY_ALTS)) {
    if ([...alt].sort().join('|') === fields.join('|')) {
      return [{ type: 'entity', kind, value: preds[0].value }];
    }
  }
  return null;
}

// The executed canonical query -> { tf, chips }, or null (Custom Query).
export function adoptQuery(canonicalQuery) {
  const segs = splitSegments(canonicalQuery);
  if (segs.length !== 4) return null;
  const [tf, sensor, eventType, filters] = segs;
  if (!TF_TOKENS.includes(tf)) return null;
  const chips = [];
  if (sensor !== '*') {
    chips.push(SOURCE_FAMILIES.includes(sensor)
      ? { type: 'include', field: 'source_type', value: sensor }
      : { type: 'include', field: 'hostname', value: sensor });
  }
  if (eventType !== '*') {
    chips.push({ type: 'include', field: 'event_type', value: eventType });
  }
  if (filters !== '*') {
    const adopted = adoptConjunction(filters) || adoptEntityOr(filters);
    if (adopted === null) return null;
    // a FILTERS == on a field the SENSOR / EVENT_TYPE segment already pinned
    // would turn the original AND into a chip OR -- not adoptable
    const segmentFields = new Set(chips.map((c) => c.field));
    if (adopted.some((c) => c.type === 'include' && segmentFields.has(c.field))) {
      return null;
    }
    chips.push(...adopted);
  }
  return { tf, chips };
}

// --- the simple search box (owner follow-up pass, 2026-10-13) ----------------
// ONE search box replacing the Advanced LCQL toggle. It accepts
//   field = value          (computer = ACME-WS28)
//   field contains text    (user contains khan)
//   plain free text        (searches the event message)
// and everything it parses becomes the SAME chips the facets produce --
// still compiled through the one chokepoint, still executed server-side.
// Field names resolve through friendly aliases (the facet-group
// vocabulary) and, for precision, any raw catalog field name. An unknown
// field is a structured error the shell renders with friendly copy.

const SEARCH_ALIASES = {
  computer: 'hostname',
  host: 'hostname',
  hostname: 'hostname',
  machine: 'hostname',
  workstation: 'workstation_name',
  user: 'user_account',
  'user account': 'user_account',
  account: 'user_account',
  username: 'user_account',
  'source ip': 'source_ip',
  'src ip': 'source_ip',
  'came from': 'source_ip',
  'destination ip': 'destination_ip',
  'dest ip': 'destination_ip',
  'went to': 'destination_ip',
  severity: 'severity',
  event: 'event_type',
  'event type': 'event_type',
  outcome: 'event_type',
  source: 'source_type',
  'log source': 'source_type',
  sensor: 'source_type',
  process: 'image',
  image: 'image',
  command: 'command_line',
  'command line': 'command_line',
  file: 'target_filename',
  filename: 'target_filename',
  'file path': 'target_filename',
  url: 'url',
  'dns query': 'query',
  dns: 'query',
  message: 'message',
  text: 'message',
  ip: '@ip',                       // the two-field entity pair, equals only
};

function resolveSearchField(name) {
  const norm = name.trim().toLowerCase().replace(/\s+/g, ' ');
  if (norm === '') return null;
  if (SEARCH_ALIASES[norm]) return SEARCH_ALIASES[norm];
  const underscored = norm.replace(/ /g, '_');
  const top = FILTERABLE_TOP_FIELDS.find((f) => f.toLowerCase() === underscored);
  if (top) return top;
  const kvp = kvpCatalogOrder.find(
    (k) => k.toLowerCase() === underscored || k.toLowerCase() === norm);
  if (kvp) return kvp;
  return null;
}

// Strip one matching pair of surrounding quotes (people paste values).
function unquoteLoose(raw) {
  const text = raw.trim();
  for (const q of ['"', "'"]) {
    if (text.length >= 2 && text.startsWith(q) && text.endsWith(q)) {
      return text.slice(1, -1);
    }
  }
  return text;
}

// { chips: [...] } on success ({ chips: [] } for blank input), or
// { error: { kind: 'unknown_field', name } | { kind: 'ip_contains' } }.
export function parseSearchInput(text) {
  const input = text.trim();
  if (input === '') return { chips: [] };
  let m = input.match(/^(.+?)\s*={1,2}\s*(.+)$/);
  if (m) {
    const field = resolveSearchField(m[1]);
    if (field === null) return { error: { kind: 'unknown_field', name: m[1].trim() } };
    const value = unquoteLoose(m[2]);
    if (field === '@ip') return { chips: [{ type: 'entity', kind: 'ip', value }] };
    return { chips: [{ type: 'include', field, value }] };
  }
  m = input.match(/^(.+?)\s+contains\s+(.+)$/i);
  if (m) {
    const field = resolveSearchField(m[1]);
    if (field === null) return { error: { kind: 'unknown_field', name: m[1].trim() } };
    if (field === '@ip') return { error: { kind: 'ip_contains' } };
    const value = unquoteLoose(m[2]);
    return { chips: [{ type: 'contains', field, value, negated: false }] };
  }
  // plain free text searches the event message
  return {
    chips: [{ type: 'contains', field: 'message', value: unquoteLoose(input), negated: false }],
  };
}

// Merge parsed chips into the current state, skipping exact duplicates.
export function mergeChips(chips, additions) {
  const seen = new Set(chips.map(chipKey));
  const fresh = additions.filter((c) => !seen.has(chipKey(c)));
  return fresh.length === 0 ? chips : [...chips, ...fresh];
}

// --- rail support --------------------------------------------------------------

// Full value counts for ONE field over served rows (top-level or kvp),
// sorted by count desc then value: the rail's per-group list source.
export function fieldValueCounts(rows, field) {
  const counter = {};
  for (const row of rows) {
    let v = row[field];
    if (v === undefined || v === null || v === '') {
      const kvp = row.key_value_pairs;
      v = kvp && typeof kvp === 'object' ? kvp[field] : undefined;
    }
    if (v === undefined || v === null || v === '') continue;
    const key = String(v);
    counter[key] = (counter[key] || 0) + 1;
  }
  return Object.entries(counter)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([value, count]) => ({ value, count }));
}
