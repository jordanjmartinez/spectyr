import React, { useState, useEffect } from 'react';
import { renderFieldValue } from './siemUtils';
import {
  DEFAULT_FACET_FIELDS, HIDDEN_FACET_FIELDS, labelForField, decodeFieldValue,
} from './fieldDecodes';
import { fieldValueCounts, hasInclude } from './facetModel';
import {
  MORE_FILTERS, SHOW_MORE_VALUES, SHOW_FEWER_VALUES, NO_GROUP_VALUES,
} from './uiCopy';

// The facet rail (owner SIEM simplification pass, 2026-10-13; replaces the
// Stage 4 FieldSidebar). ONE filter system: six default plain-language
// groups -- Event, Severity, User Account, Computer, Source IP,
// Log Source -- each a multi-select checkbox list of the top values by
// count, with everything else behind the More Filters disclosure and the
// deleted identifier/free-text groups gone entirely.
//
// Counts derive EXCLUSIVELY from served rows: the displayed snapshot's rows
// by default, and -- for a group the player has already narrowed -- the
// server-fetched sibling baseline (the same search without that group's own
// selections), requested only when the player asks for more values. Nothing
// here inspects the live pool or executes a predicate locally (contract P8
// posture unchanged).

const VISIBLE_VALUES = 5;

const displayValue = (field, value) =>
  decodeFieldValue(field, value) || renderFieldValue(field, value);

const FacetGroup = ({
  field, values, chips, running, onToggle, hasBaseline, onRequestBaseline,
}) => {
  const [expanded, setExpanded] = useState(false);
  useEffect(() => { setExpanded(false); }, [field]);

  const selected = new Set(chips
    .filter((c) => c.type === 'include' && c.field === field)
    .map((c) => c.value));

  // Selected values always render (checked, un-checkable) even when the
  // narrowed results no longer carry them; then the served values by count.
  const counts = new Map(values.map(({ value, count }) => [value, count]));
  const rows = [
    ...[...selected].filter((v) => !counts.has(v)).map((v) => ({ value: v, count: 0 })),
    ...values,
  ];
  const pinned = rows.filter((r) => selected.has(r.value));
  const unpinned = rows.filter((r) => !selected.has(r.value));
  const ordered = [...pinned, ...unpinned];
  const visible = expanded ? ordered : ordered.slice(0, VISIBLE_VALUES);
  // More values may exist beyond the slice; for a narrowed group the sibling
  // baseline (fetched on request) is the only way to see unselected values.
  const canShowMore = !expanded
    && (ordered.length > VISIBLE_VALUES || (selected.size > 0 && !hasBaseline));

  const showMore = () => {
    setExpanded(true);
    if (selected.size > 0 && !hasBaseline) onRequestBaseline(field);
  };

  return (
    <div data-testid={`facet-group-${field}`}>
      <div className="text-xs font-medium text-[#1a2332] mb-1">{labelForField(field)}</div>
      {ordered.length === 0 && (
        <p className="text-xs text-muted px-1.5">{NO_GROUP_VALUES}</p>
      )}
      <ul className="space-y-0.5">
        {visible.map(({ value, count }) => (
          <li key={value}>
            <label className="flex items-center gap-1.5 text-xs text-muted hover:bg-[#eef1f4] px-1.5 py-0.5 rounded cursor-pointer">
              <input
                type="checkbox"
                checked={selected.has(value)}
                disabled={running}
                onChange={() => onToggle(field, value)}
                aria-label={`${labelForField(field)}: ${displayValue(field, value)}`}
                className="shrink-0 accent-[#16436b]"
              />
              <span className="truncate flex-1">{displayValue(field, value)}</span>
              <span className="text-muted shrink-0 log-mono">{count}</span>
            </label>
          </li>
        ))}
      </ul>
      {canShowMore && (
        <button
          type="button"
          onClick={showMore}
          className="mt-0.5 px-1.5 text-xs text-[#16436b] hover:underline"
        >
          {SHOW_MORE_VALUES}
        </button>
      )}
      {expanded && ordered.length > VISIBLE_VALUES && (
        <button
          type="button"
          onClick={() => setExpanded(false)}
          className="mt-0.5 px-1.5 text-xs text-muted hover:underline"
        >
          {SHOW_FEWER_VALUES}
        </button>
      )}
    </div>
  );
};

const FacetRail = ({
  snapshot, running, chips, baselines,
  onToggle, onRequestBaseline,
}) => {
  const [moreOpen, setMoreOpen] = useState(false);

  if (!snapshot) {
    if (!running) return null;
    return (
      <div
        data-testid="facet-rail-skeleton"
        className="w-full lg:w-56 shrink-0 flex flex-col gap-2 animate-pulse"
      >
        {[0, 1, 2].map((i) => (
          <div key={i} className="h-4 rounded bg-[#eef1f4]" />
        ))}
      </div>
    );
  }

  const rows = snapshot.rows || [];
  const hidden = new Set([...HIDDEN_FACET_FIELDS, 'event_seq']);
  const effectiveChips = chips;

  // Every field present in the served rows (top-level commons + kvp keys),
  // minus the deleted groups and the six defaults.
  const present = new Set();
  for (const row of rows) {
    for (const [k, v] of Object.entries(row)) {
      if (k === 'key_value_pairs' || k === 'event_seq') continue;
      if (v !== undefined && v !== null && v !== '') present.add(k);
    }
    const kvp = row.key_value_pairs;
    if (kvp && typeof kvp === 'object') {
      for (const [k, v] of Object.entries(kvp)) {
        if (v !== undefined && v !== null && v !== '') present.add(k);
      }
    }
  }
  for (const c of effectiveChips) {
    if (c.type === 'include') present.add(c.field);
  }
  const moreFields = [...present]
    .filter((f) => !hidden.has(f) && !DEFAULT_FACET_FIELDS.includes(f) && f !== 'id')
    .sort((a, b) => (a === 'destination_ip' ? -1 : b === 'destination_ip' ? 1 : a.localeCompare(b)));

  const valuesFor = (field) => baselines[field] || fieldValueCounts(rows, field);

  const group = (field) => (
    <FacetGroup
      key={field}
      field={field}
      values={valuesFor(field)}
      chips={effectiveChips}
      running={running}
      onToggle={onToggle}
      hasBaseline={!!baselines[field]}
      onRequestBaseline={onRequestBaseline}
    />
  );

  return (
    <div data-testid="facet-rail" className="w-full lg:w-56 shrink-0 flex flex-col gap-3">
      {DEFAULT_FACET_FIELDS.map(group)}
      <button
        type="button"
        onClick={() => setMoreOpen((o) => !o)}
        aria-expanded={moreOpen}
        className="w-full flex items-center justify-between px-1.5 py-1.5 text-xs font-medium rounded-md border border-[#d0d7de] bg-white text-[#1a2332] hover:bg-[#eef1f4]"
      >
        <span>{MORE_FILTERS}</span>
        <span className="text-muted font-normal">{moreOpen ? 'Hide' : moreFields.length}</span>
      </button>
      {moreOpen && moreFields.map(group)}
    </div>
  );
};

export default FacetRail;
