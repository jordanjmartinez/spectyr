// Stage 4 Phase 6.1: the SINGLE LCQL query-generation choke point (contract
// Section 13). Every pivot, sidebar action, and descent form used anywhere
// in the workbench MUST route through here -- one generator, one place to
// audit, one permanent parity proof against the backend parser
// (backend/test_lcql.py::test_documented_pivot_and_descent_forms_parse).
//
// Pure string generation only. This module NEVER executes a query,
// evaluates a predicate, or filters an event locally (contract P8): every
// string it builds is submitted to the server and parsed there. It has no
// React, no fetch, no state.
//
// `<tf>` inheritance: entity pivots (host, account, process, file, IP,
// domain, event type, sensor family) always take the current snapshot's
// TIMEFRAME token explicitly as a parameter -- callers extract it from
// `snapshot.identity.canonical_query`'s first segment. Descent forms
// (`descentHost`, `descentSessionAll`) are hardcoded to `all` regardless of
// the caller's timeframe (contract Section 13's descent rows; the
// surrounding-events consumer of `descentHost` was removed by A3 F3 --
// evidence descent keeps the form).

// --- GD-5 escaping ------------------------------------------------------

// Backslash-escape a value for placement inside a double-quoted LCQL string
// literal: backslash doubles, double-quote escapes. Mirrors the backend
// tokenizer's unescape in reverse (lcql.py's _tokenize_filters).
export function escapeValue(v) {
  return String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

const quoteValue = (v) => `"${escapeValue(v)}"`;

// --- quote-aware segment splitting (mirrors lcql.py's _split_segments) ---

// Split a canonical 4-segment query on top-level `|` only -- a pipe inside
// a quoted FILTERS value never splits. Returns [timeframe, sensor,
// eventType, filtersText], each trimmed.
export function splitSegments(query) {
  const segs = [];
  let quote = null;
  let start = 0;
  for (let i = 0; i < query.length; i++) {
    const c = query[i];
    if (quote) {
      if (c === '\\' && i + 1 < query.length) { i += 1; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; continue; }
    if (c === '|') { segs.push(query.slice(start, i)); start = i + 1; }
  }
  segs.push(query.slice(start));
  return segs.map((s) => s.trim());
}

// --- Amendment 3 F7: simple-mode composition forms ------------------------
// The simple-search projection compiles through THESE forms only (the
// chokepoint gains forms, never a second author). The canonical four-part
// text stays the single truth; the controls are its projection.

// The closed sensor-family set, mirrored from backend/lcql.py
// SOURCE_FAMILIES and pinned by a two-sided parity corpus (the
// OR_SCAN_CORPUS pattern): the Source select's static options.
export const SOURCE_FAMILIES = [
  'Sysmon', 'Windows Security', 'Proxy', 'DNS', 'Firewall',
  'Azure AD', 'Veeam', 'Defender',
];

// Compose the four-part canonical-form query from the simple controls.
// The FILTERS text rides RAW (live typing survives); an effectively empty
// FILTERS field compiles to `*` (simple mode's legitimate match-all).
export function composeQuery(tf, sensor, eventType, filtersText) {
  const f = filtersText || '';
  return `${tf} | ${sensor} | ${eventType} | ${f.trim() === '' ? '*' : f}`;
}

// Replace the first segment in place (the Timeframe picker's advanced-mode
// edit), quote-aware: the old raw indexOf('|') splice migrated into the
// chokepoint (A3-5.3) -- byte-identical output on every valid form, but a
// pipe inside a quoted value can no longer split.
export function replaceTimeframe(query, token) {
  if (query.trim() === '') return `${token} | * | * | *`;
  let quote = null;
  for (let i = 0; i < query.length; i++) {
    const c = query[i];
    if (quote) {
      if (c === '\\' && i + 1 < query.length) { i += 1; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; continue; }
    if (c === '|') return `${token} ${query.slice(i)}`;
  }
  return token;
}

// The RAW FILTERS tail of a four-segment text (quote-aware, the segment
// after the THIRD top-level pipe), leading whitespace dropped so the
// compose round trip is stable while trailing whitespace survives live
// typing. Null when the text does not have exactly four segments.
export function rawFiltersOf(query) {
  const bounds = [];
  let quote = null;
  for (let i = 0; i < query.length; i++) {
    const c = query[i];
    if (quote) {
      if (c === '\\' && i + 1 < query.length) { i += 1; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; continue; }
    if (c === '|') bounds.push(i);
  }
  if (bounds.length !== 3) return null;
  return query.slice(bounds[2] + 1).replace(/^\s+/, '');
}

// --- conjunction-only lexical scan ---------------------------------------
//
// EQUIVALENCE BOUNDARY (scaffold Section 2.15, permanent notice): this
// lexical scan is equivalent to the backend's AST-based
// `lcql.conjunction_only()` verdict ONLY WHILE LCQL HAS NO GROUPING OR
// PARENTHESES (a deferred grammar item, contract Section 19). It works by
// tokenizing the FILTERS text on top-level whitespace (quote-aware, GD-5
// escape-aware) and checking for a bare `or` token. If parentheses are ever
// introduced, `or` could appear nested inside a group that a flat AND/OR
// chain at the top level does not see, and this scan would need to walk
// the same grouping structure the parser does -- IT MUST BE REPLACED, NOT
// PATCHED, at that point. The shared OR_SCAN_CORPUS below is asserted
// against this scan; the identical corpus is asserted against the real AST
// in backend/test_lcql.py::test_or_scan_fixture_corpus_matches_ast_verdicts
// -- one corpus, two implementations, byte-equal verdicts (the Phase 2
// parity promise).
export function isConjunctionOnly(filtersText) {
  const text = filtersText.trim();
  if (text === '*') return true;
  let quote = null;
  let token = '';
  const tokens = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      token += c;
      if (c === '\\' && i + 1 < text.length) {
        i += 1;
        token += text[i];
        continue;
      }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; token += c; continue; }
    if (/\s/.test(c)) {
      if (token) { tokens.push(token); token = ''; }
      continue;
    }
    token += c;
  }
  if (token) tokens.push(token);
  return !tokens.some((t) => t.toLowerCase() === 'or');
}

// --- section identification (Amendment 2 commit 3.2) -------------------------
//
// Which of the four query sections a parser error position falls in, from
// the SAME quote-aware top-level-pipe scan splitSegments uses (the backend's
// _split_segments mirror). Returns 0..3, or null when the text does not
// split into exactly four top-level segments (a structure-level error, named
// by the structure line instead). EQUIVALENCE BOUNDARY: valid only while
// LCQL has no grouping/parentheses (the recorded isConjunctionOnly notice
// applies here identically -- replace, never patch, if grouping arrives).
export function sectionIndexAtPosition(query, position) {
  const segs = [];
  let quote = null;
  let start = 0;
  for (let i = 0; i < query.length; i++) {
    const c = query[i];
    if (quote) {
      if (c === '\\' && i + 1 < query.length) { i += 1; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; continue; }
    if (c === '|') { segs.push([start, i]); start = i + 1; }
  }
  segs.push([start, query.length]);
  if (segs.length !== 4) return null;
  const idx = segs.findIndex(([s, e]) => position >= s && position <= e);
  return idx === -1 ? 3 : idx;
}

// --- sidebar / per-field refinement (conjunction-only append vs OR fallback) -

// The exact contract-quoted notice (Section 11, OR-composition restriction).
export const OR_FALLBACK_NOTICE =
  'Started a new query; the previous one mixed or-conditions.';

// Refine the EXECUTED canonical query with one new predicate (a sidebar
// value click, or an inspector ==/!= action). If the current FILTERS AST
// is conjunction-only (or `*`), append `and field op "value"` (or replace
// the bare `*`); TIMEFRAME/SENSOR/EVENT_TYPE are carried over unchanged.
// If FILTERS mixes `or`, a UI click could otherwise emit a query whose
// precedence surprises the player (`A or B` + `and C` would mean
// `A or (B and C)`) -- so this generates a FRESH standalone query
// (TIMEFRAME/SENSOR/EVENT_TYPE unchanged, FILTERS reset to just the new
// predicate) and returns the exact contract notice.
export function refineFilter(executedCanonicalQuery, field, op, value) {
  const [tf, sensor, eventType, filtersText] = splitSegments(executedCanonicalQuery);
  const predicate = `${field} ${op} ${quoteValue(value)}`;
  if (isConjunctionOnly(filtersText)) {
    const newFilters = filtersText.trim() === '*' ? predicate : `${filtersText} and ${predicate}`;
    return { query: `${tf} | ${sensor} | ${eventType} | ${newFilters}`, fresh: false, notice: null };
  }
  return {
    query: `${tf} | ${sensor} | ${eventType} | ${predicate}`,
    fresh: true,
    notice: OR_FALLBACK_NOTICE,
  };
}

// --- filter chips (Amendment 2 commit 3.3, ratified remove-only) -------------
//
// listConjuncts: the READ projection of the executed canonical FILTERS
// section. Returns null when the query is NOT decomposable (any top-level
// `or` -- including the IP-pivot and identity-descent product forms -- or a
// text that does not split into four segments), [] for `*`, else the
// canonical conjunct texts byte-preserved (slices of the canonical string).
// Chips must never misrepresent the query: the projection equals the
// conjunct list exactly or collapses to the one Custom filters chip.
// EQUIVALENCE BOUNDARY: the same recorded isConjunctionOnly notice applies
// (valid only while LCQL has no grouping; replace, never patch); the
// backend AST decomposition pins this via the shared CONJUNCT_SPLIT_CORPUS
// (one corpus, two consumers, byte-equal verdicts).
export function listConjuncts(canonicalQuery) {
  const segs = splitSegments(canonicalQuery);
  if (segs.length !== 4) return null;
  const text = segs[3];
  if (text === '*') return [];
  if (!isConjunctionOnly(text)) return null;
  // quote-aware token scan over the canonical FILTERS text, recording
  // token offsets; conjunct spans split at bare top-level `and` tokens.
  const tokens = [];   // [start, end)
  let quote = null;
  let tokStart = -1;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === '\\' && i + 1 < text.length) { i += 1; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") {
      if (tokStart === -1) tokStart = i;
      quote = c;
      continue;
    }
    if (/\s/.test(c)) {
      if (tokStart !== -1) { tokens.push([tokStart, i]); tokStart = -1; }
      continue;
    }
    if (tokStart === -1) tokStart = i;
  }
  if (tokStart !== -1) tokens.push([tokStart, text.length]);
  const conjuncts = [];
  let spanStart = null;
  let spanEnd = null;
  for (const [s, e] of tokens) {
    const tok = text.slice(s, e);
    if (tok.toLowerCase() === 'and') {
      if (spanStart !== null) conjuncts.push(text.slice(spanStart, spanEnd));
      spanStart = null;
      continue;
    }
    if (spanStart === null) spanStart = s;
    spanEnd = e;
  }
  if (spanStart !== null) conjuncts.push(text.slice(spanStart, spanEnd));
  return conjuncts;
}

// removeConjunct: the ONE new generator form (the single query author gains
// a form; no second author appears). Rebuilds the query with the indexed
// conjunct removed, joining the rest with ` and ` (`*` when none);
// TIMEFRAME/SENSOR/EVENT_TYPE preserved byte-exact.
export function removeConjunct(canonicalQuery, index) {
  const conjuncts = listConjuncts(canonicalQuery);
  if (!conjuncts || index < 0 || index >= conjuncts.length) return canonicalQuery;
  const rest = conjuncts.filter((_, i) => i !== index);
  const [tf, sensor, eventType] = splitSegments(canonicalQuery);
  return `${tf} | ${sensor} | ${eventType} | ${rest.length ? rest.join(' and ') : '*'}`;
}

// --- entity pivots (contract Section 13 table) ---------------------------
// Every entity pivot mints a query from `<tf>` alone -- SENSOR/EVENT_TYPE
// are NOT inherited from the current query (Section 14: entity pivots
// always execute Session-wide with a full scope reset, wiring in Phase 7).

export function pivotHost(tf, hostname) {
  return `${tf} | ${hostname} | * | *`;
}

export function pivotAccount(tf, account) {
  return `${tf} | * | * | user_account == ${quoteValue(account)}`;
}

export function pivotProcessImage(tf, image) {
  return `${tf} | * | * | image == ${quoteValue(image)}`;
}

export function pivotProcessNameContains(tf, name) {
  return `${tf} | * | ProcessCreate | image contains ${quoteValue(name)}`;
}

export function pivotFile(tf, path) {
  return `${tf} | * | * | target_filename == ${quoteValue(path)}`;
}

export function pivotIp(tf, ip) {
  return `${tf} | * | * | source_ip == ${quoteValue(ip)} or destination_ip == ${quoteValue(ip)}`;
}

export function pivotDomainProxy(tf, domain) {
  return `${tf} | Proxy | * | url contains ${quoteValue(domain)}`;
}

export function pivotDomainDns(tf, domain) {
  return `${tf} | DNS | QUERY | query contains ${quoteValue(domain)}`;
}

export function pivotEventType(tf, eventType) {
  return `${tf} | * | ${eventType} | *`;
}

export function pivotSensorFamily(tf, family) {
  return `${tf} | ${family} | * | *`;
}

// --- descent forms (contract Section 13; UI wiring is Phase 7) -----------
// Pure string generation only, per the Phase 6 boundary clarification: the
// Open Evidence Timeline controls, navigation, banners, breadcrumbs, and
// scope behavior that USE these strings are Phase 7. Always `all`,
// regardless of the caller's current timeframe.

export function descentHost(hostname) {
  return `all | ${hostname} | * | *`;
}

export function descentSessionAll() {
  return 'all | * | * | *';
}

// Identity-detection descent (Phase 7.5 ruling): the UNIFORM two-field OR
// for every identity/account detection. UPN-carrying families (Azure AD)
// store the visible account in kvp UserPrincipalName while DOMAIN\username
// families store it in user_account, so a single-field anchor lands on an
// empty timeline for one of them (the live P7.4 finding). No branching on
// account format, source family, or anything else -- one shape always;
// correlating UPN identity with DOMAIN\username host activity remains
// player investigation work through pivots. Always `all`; scope follows
// the same rule as host descent (player-selected incident context or
// Session-wide -- never special-cased).
export function descentAccount(account) {
  const a = quoteValue(account);
  return `all | * | * | user_account == ${a} or UserPrincipalName == ${a}`;
}
