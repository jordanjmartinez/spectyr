import React, { useState, useEffect } from 'react';
import { sanitizeEvent, renderFieldValue, formatDatetime } from './siemUtils';
import kvpCatalogOrder from './kvpCatalogOrder.json';
import { decodeFieldValue } from './fieldDecodes';
import { ENTITY_FIELDS } from './facetModel';
import {
  TOOLTIP_EQ, TOOLTIP_NEQ, TOOLTIP_PIVOT,
  FILTER_TO_THIS, FILTER_OUT_THIS, PIVOT_SEE_ALL, COPY_VALUE,
  OPEN_IN_ENDPOINTS, KEY_FACTS_LABEL, ALL_FIELDS_TOGGLE,
} from './uiCopy';

// Event inspector (owner SIEM simplification pass, 2026-10-13, over the
// Stage 4 Section 12 lens). Two tiers:
//  - KEY FACTS: ~9 fields with values DECODED into plain language (logon
//    type 3 reads Network, failure substatus 0xC000006A reads Incorrect
//    Password), picked by presence from a fixed priority order.
//  - ALL FIELDS: the complete Section 12 structure (identity,
//    classification, canonical commons, family fields in catalog order,
//    message) behind one toggle, with the sanitized raw JSON below it.
// Still one lens over exactly the whitelisted, sanitized event: no
// non-whitelisted field is ever read or rendered, and a malformed event
// falls back to its sanitized raw JSON with a notice.
//
// Filter/pivot actions exist ONLY on entity fields (facetModel's
// ENTITY_FIELDS: user, source IP, workstation, host, destination, process
// name), through ONE menu with plain verbs -- Filter to Just This, Filter
// This Out, Pivot: See Everything About This, Copy (plus Open in Endpoints
// on host fields). The old per-field == / != / Pivot buttons are gone
// everywhere else. Every filter and pivot still routes through the one
// generator chokepoint via the shell's onEntityAction.

// --- key facts ---------------------------------------------------------------

const KEY_FACTS_LIMIT = 9;

// Priority order; the first KEY_FACTS_LIMIT facts present on the event
// render. `sources` are tried in order: a top-level field or a kvp key.
const KEY_FACT_DEFS = [
  { label: 'Event', sources: ['event_type'] },
  { label: 'Time', sources: ['timestamp'] },
  { label: 'Severity', sources: ['severity'] },
  { label: 'Log Source', sources: ['source_type'] },
  { label: 'User Account', sources: ['user_account', 'UserPrincipalName', 'account_name', 'target_account_name'] },
  { label: 'Computer', sources: ['hostname'] },
  { label: 'Source IP', sources: ['source_ip', 'IPAddress', 'ip_address'] },
  { label: 'Destination IP', sources: ['destination_ip'] },
  { label: 'Logon Type', sources: ['logon_type'] },
  { label: 'Why It Failed', sources: ['sub_status', 'failure_reason'] },
  { label: 'Result', sources: ['ResultType', 'status'] },
  { label: 'Process', sources: ['image'] },
  { label: 'Command', sources: ['command_line'] },
  { label: 'Parent Process', sources: ['parent_image'] },
  { label: 'File', sources: ['target_filename'] },
  { label: 'URL', sources: ['url'] },
  { label: 'DNS Query', sources: ['query'] },
  { label: 'Workstation', sources: ['workstation_name'] },
];

const TOP_LEVEL_SOURCES = new Set([
  'event_type', 'timestamp', 'severity', 'source_type', 'user_account',
  'hostname', 'source_ip', 'destination_ip',
]);

export function buildKeyFacts(event) {
  const kvp = (event.key_value_pairs && typeof event.key_value_pairs === 'object'
    && !Array.isArray(event.key_value_pairs)) ? event.key_value_pairs : {};
  const read = (source) => (TOP_LEVEL_SOURCES.has(source) ? event[source] : kvp[source]);
  const facts = [];
  for (const def of KEY_FACT_DEFS) {
    for (const source of def.sources) {
      const value = read(source);
      if (value === undefined || value === null || value === '') continue;
      const display = source === 'timestamp'
        ? formatDatetime(value)
        : (decodeFieldValue(source, value) || renderFieldValue(source, value));
      facts.push({ label: def.label, field: source, value, display });
      break;
    }
    if (facts.length >= KEY_FACTS_LIMIT) break;
  }
  return facts;
}

// --- all-fields catalog order (unchanged from Stage 4) -----------------------

const CANONICAL_COMMONS = ['hostname', 'user_account', 'source_ip', 'destination_ip', 'severity'];

const KVP_RANK = new Map(kvpCatalogOrder.map((k, i) => [k, i]));
const kvpRank = (k) => (KVP_RANK.has(k) ? KVP_RANK.get(k) : Infinity);

// May throw for genuinely malformed shapes; the caller catches it and
// falls back to the raw-JSON-only view (contract Section 12 States).
function buildStructuredView(event) {
  if (!event || typeof event !== 'object') throw new Error('malformed event: not an object');
  if (!event.id) throw new Error('malformed event: missing id');
  const kvpRaw = event.key_value_pairs;
  if (kvpRaw !== undefined && kvpRaw !== null
      && (typeof kvpRaw !== 'object' || Array.isArray(kvpRaw))) {
    throw new Error('malformed event: key_value_pairs is not an object');
  }
  const kvpEntries = Object.entries(kvpRaw || {})
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .sort(([a], [b]) => kvpRank(a) - kvpRank(b) || a.localeCompare(b));
  const commons = CANONICAL_COMMONS
    .map((f) => [f, event[f]])
    .filter(([, v]) => v !== undefined && v !== null && v !== '');
  return {
    timestamp: event.timestamp,
    id: event.id,
    eventSeq: event.event_seq,
    sourceType: event.source_type,
    eventType: event.event_type,
    commons,
    kvpEntries,
    message: event.message,
  };
}

// Owner follow-up pass (2026-10-13): section headers render at the
// standard container-heading size (t-subsection, the VA3 "ONE primary
// container heading" token), not label size.
const SectionLabel = ({ children }) => (
  <div className="t-subsection mt-3 mb-1 first:mt-0">
    {children}
  </div>
);

const EventInspector = ({ event, onEntityAction, onHostPivot }) => {
  const [allFieldsOpen, setAllFieldsOpen] = useState(false);
  const [openMenu, setOpenMenu] = useState(null);
  useEffect(() => {
    setAllFieldsOpen(false);
    setOpenMenu(null);
  }, [event?.id]);

  if (!event) return null;

  let view = null;
  let malformed = false;
  try {
    view = buildStructuredView(event);
  } catch (e) {
    malformed = true;
  }

  const copyValue = (value) => {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(String(value)).catch(() => {});
    }
  };

  // The ONE entity action menu. Rendered only beside entity-field values;
  // the plain verbs carry the ruled tooltip finals.
  const EntityMenu = ({ menuKey, field, value }) => {
    const kind = ENTITY_FIELDS[field];
    if (!kind || value === undefined || value === null || value === '') return null;
    const open = openMenu === menuKey;
    const act = (action) => {
      setOpenMenu(null);
      onEntityAction?.(field, action, value);
    };
    return (
      <span className="relative shrink-0">
        <button
          type="button"
          onClick={() => setOpenMenu(open ? null : menuKey)}
          aria-label={`Actions for ${field}`}
          aria-haspopup="menu"
          aria-expanded={open}
          className="px-1.5 py-0.5 text-[10px] rounded border border-[#d0d7de] text-muted hover:bg-[#eef1f4]"
        >
          ...
        </button>
        {open && (
          <div
            role="menu"
            className="absolute right-0 top-full mt-1 z-20 min-w-[14rem] rounded-md border border-[#d0d7de] bg-white shadow-md py-1 text-xs"
          >
            <button
              type="button"
              role="menuitem"
              onClick={() => act('only')}
              title={TOOLTIP_EQ}
              data-help={TOOLTIP_EQ}
              className="help-tip w-full text-left px-3 py-1.5 text-[#1a2332] hover:bg-[#eef1f4]"
            >
              {FILTER_TO_THIS}
            </button>
            <button
              type="button"
              role="menuitem"
              onClick={() => act('exclude')}
              title={TOOLTIP_NEQ}
              data-help={TOOLTIP_NEQ}
              className="help-tip w-full text-left px-3 py-1.5 text-[#1a2332] hover:bg-[#eef1f4]"
            >
              {FILTER_OUT_THIS}
            </button>
            <button
              type="button"
              role="menuitem"
              onClick={() => act('pivot')}
              title={TOOLTIP_PIVOT}
              data-help={TOOLTIP_PIVOT}
              className="help-tip w-full text-left px-3 py-1.5 text-[#16436b] hover:bg-[#eef1f4]"
            >
              {PIVOT_SEE_ALL}
            </button>
            <button
              type="button"
              role="menuitem"
              onClick={() => { setOpenMenu(null); copyValue(value); }}
              className="w-full text-left px-3 py-1.5 text-[#1a2332] hover:bg-[#eef1f4]"
            >
              {COPY_VALUE}
            </button>
            {kind === 'host' && onHostPivot && (
              <button
                type="button"
                role="menuitem"
                onClick={() => { setOpenMenu(null); onHostPivot(value); }}
                className="w-full text-left px-3 py-1.5 text-[#1a2332] hover:bg-[#eef1f4]"
              >
                {OPEN_IN_ENDPOINTS}
              </button>
            )}
          </div>
        )}
      </span>
    );
  };

  const Row = ({ menuKey, label, field, value, display }) => (
    <div className="flex items-center justify-between gap-2 py-1 border-b border-[#eef1f4] text-xs">
      <div className="min-w-0 flex-1">
        <span className="text-muted mr-2">{label}</span>
        <span className="text-[#1a2332] break-all log-mono">
          {display ?? renderFieldValue(field, value)}
        </span>
      </div>
      <EntityMenu menuKey={menuKey} field={field} value={value} />
    </div>
  );

  if (malformed) {
    return (
      <div
        data-testid="event-inspector"
        className="mt-3 p-4 rounded-xl bg-white border border-[#e2e6ea]"
      >
        <p role="alert" className="text-xs text-[#b26666] mb-2">
          This event could not be fully rendered.
        </p>
        <pre className="p-3 rounded-lg bg-[#f6f8fa] border border-[#eef1f4] text-[11px] leading-relaxed log-mono text-[#1a2332] overflow-x-auto">
{JSON.stringify(sanitizeEvent(event || {}), null, 2)}
        </pre>
      </div>
    );
  }

  const facts = buildKeyFacts(event);

  return (
    <div
      data-testid="event-inspector"
      className="mt-3 p-4 rounded-xl bg-white border border-[#e2e6ea] flex flex-col"
    >
      {/* Owner follow-up pass (2026-10-13): no selected-event headline
          strip -- Key Facts opens the pane directly. */}
      <SectionLabel>{KEY_FACTS_LABEL}</SectionLabel>
      {facts.map((f) => (
        <Row
          key={`fact-${f.label}`}
          menuKey={`fact-${f.label}`}
          label={f.label}
          field={f.field}
          value={f.value}
          display={f.display}
        />
      ))}

      {/* Playtest correction (owner 2026-10-13): All Fields is a COMPACT
          content-width disclosure button -- the facet rail's More Filters
          box styling -- left-aligned directly under the last Key Facts
          row. Only the toggle is compact; the expanded field sections
          below stay full width, separated by a hairline before Identity. */}
      <button
        type="button"
        onClick={() => setAllFieldsOpen((o) => !o)}
        aria-expanded={allFieldsOpen}
        className="mt-3 self-start inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md border border-[#d0d7de] bg-white text-[#1a2332] hover:bg-[#eef1f4]"
      >
        <span>{ALL_FIELDS_TOGGLE}</span>
        <span className="text-muted font-normal">{allFieldsOpen ? 'Hide' : 'Show'}</span>
      </button>

      {allFieldsOpen && (
        <div data-testid="all-fields" className="mt-1 pt-2 border-t border-[#e2e6ea]">
          <SectionLabel>Identity</SectionLabel>
          <Row menuKey="all-timestamp" label="timestamp" field="timestamp"
               value={view.timestamp} display={formatDatetime(view.timestamp)} />
          <Row menuKey="all-id" label="id" field="id" value={view.id} />
          <div className="flex items-center justify-between py-1 border-b border-[#eef1f4] text-xs">
            <span className="text-muted">arrived as event #{view.eventSeq}</span>
          </div>

          <SectionLabel>Classification</SectionLabel>
          <Row menuKey="all-source_type" label="source_type" field="source_type" value={view.sourceType} />
          <Row menuKey="all-event_type" label="event_type" field="event_type"
               value={view.eventType}
               display={decodeFieldValue('event_type', view.eventType) || String(view.eventType)} />

          <SectionLabel>Canonical Commons</SectionLabel>
          {view.commons.map(([field, value]) => (
            <Row key={field} menuKey={`all-${field}`} label={field} field={field} value={value} />
          ))}

          {view.kvpEntries.length > 0 && (
            <>
              <SectionLabel>Family Fields</SectionLabel>
              {view.kvpEntries.map(([field, value]) => (
                <Row
                  key={field}
                  menuKey={`all-kvp-${field}`}
                  label={field}
                  field={field}
                  value={value}
                  display={decodeFieldValue(field, value) || renderFieldValue(field, value)}
                />
              ))}
            </>
          )}

          <SectionLabel>Message</SectionLabel>
          <Row menuKey="all-message" label="message" field="message" value={view.message} />

          <SectionLabel>Raw</SectionLabel>
          <pre className="p-3 rounded-lg bg-[#f6f8fa] border border-[#eef1f4] text-[11px] leading-relaxed log-mono text-[#1a2332] overflow-x-auto">
{JSON.stringify(sanitizeEvent(event), null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};

export default EventInspector;
