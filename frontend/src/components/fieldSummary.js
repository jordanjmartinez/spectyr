// Stage 4 Phase 6.2: snapshot-scoped field/value aggregation for the field
// sidebar (contract Section 10.3). Pure functions only: no React, no fetch,
// no access to any live pool or hidden server state -- computeFieldSummary
// takes ONLY the rows array a caller passes it (always the frozen
// snapshot's `rows`), so its output is structurally incapable of reflecting
// anything the analyst has not already been served.

// The FILTERS-authorized top-level field catalog (contract 10.1 minus
// `event_seq`, which the backend catalog marks non-filterable -- see
// lcql.py's NON_FILTERABLE_TOP and test_event_seq_rejected_as_filter_field).
// The sidebar is built from THIS list, not the full serialized/display
// catalog: event_seq is never a sidebar field, so no sidebar action can
// ever generate an event_seq predicate. Fixed order = "common" ordering;
// kvp ("family") fields are appended after, sorted alphabetically.
export const FILTERABLE_TOP_FIELDS = [
  'id', 'timestamp', 'event_type', 'source_type', 'severity',
  'hostname', 'source_ip', 'destination_ip', 'user_account', 'message',
];

function topN(counter, n = 5) {
  return Object.entries(counter)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, n)
    .map(([value, count]) => ({ value, count }));
}

// { field, addr: 'top'|'kvp', topValues: [{value,count}, ...<=5] }[],
// common-before-family, fields present in NO row are omitted entirely
// (contract Section 6: "Lists fields present in the current snapshot").
export function computeFieldSummary(rows) {
  const topCounters = {};
  for (const field of FILTERABLE_TOP_FIELDS) topCounters[field] = {};
  const kvpCounters = {};

  for (const row of rows) {
    for (const field of FILTERABLE_TOP_FIELDS) {
      const v = row[field];
      if (v === undefined || v === null || v === '') continue;
      const key = String(v);
      topCounters[field][key] = (topCounters[field][key] || 0) + 1;
    }
    const kvp = row.key_value_pairs;
    if (!kvp || typeof kvp !== 'object') continue;
    for (const [k, v] of Object.entries(kvp)) {
      if (v === undefined || v === null || v === '') continue;
      kvpCounters[k] = kvpCounters[k] || {};
      const key = String(v);
      kvpCounters[k][key] = (kvpCounters[k][key] || 0) + 1;
    }
  }

  const common = FILTERABLE_TOP_FIELDS
    .filter((f) => Object.keys(topCounters[f]).length > 0)
    .map((f) => ({ field: f, addr: 'top', topValues: topN(topCounters[f]) }));
  const family = Object.keys(kvpCounters).sort()
    .map((f) => ({ field: f, addr: 'kvp', topValues: topN(kvpCounters[f]) }));
  return [...common, ...family];
}
