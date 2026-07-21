import React from 'react';
import { sourceColor, sanitizeEvent, renderFieldValue } from './siemUtils';
import kvpCatalogOrder from './kvpCatalogOrder.json';

// Event inspector (Stage 4 Phase 6.3, contract Section 12). One lens over
// exactly the whitelisted, sanitized event -- no non-whitelisted field is
// ever read or rendered. Order: Identity (timestamp, id, arrival
// position) -> Classification (source family, event type) -> Canonical
// commons (hostname, account, source_ip, destination_ip, severity) ->
// Family fields (every sanitized key_value_pairs entry, catalog order) ->
// Message -> the sanitized raw JSON view. Every filterable field (all of
// FILTERABLE_TOP_FIELDS plus every kvp entry -- NOT event_seq, which is
// display-only and non-filterable) carries ==/!= actions routed through
// the same lcqlPivots.refineFilter the sidebar uses (via the parent's
// onFilter). A malformed event falls back to its sanitized raw JSON with a
// notice rather than failing to render.

const CANONICAL_COMMONS = ['hostname', 'user_account', 'source_ip', 'destination_ip', 'severity'];

// "Catalog order" (contract Section 12) = the checked-in
// kvpCatalogOrder.json fixture: the backend field catalog's canonical kvp
// key union, sorted, byte-pinned to build_field_catalog by
// test_lcql.py::test_kvp_catalog_order_fixture_byte_equals_catalog_order
// (the 6.1 shared-fixture pattern -- one order, two consumers, drift fails
// the battery). A key absent from the catalog still renders, after every
// cataloged key, alphabetically.
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

const SectionLabel = ({ children }) => (
  <div className="text-[10px] uppercase tracking-wide text-[#8b949e] mt-2 mb-1 first:mt-0">
    {children}
  </div>
);

const EventInspector = ({ event, onFilter, onHostPivot }) => {
  if (!event) return null;

  let view = null;
  let malformed = false;
  try {
    view = buildStructuredView(event);
  } catch (e) {
    malformed = true;
  }

  const Actions = ({ field, value }) => {
    if (value === undefined || value === null || value === '') return null;
    return (
      <span className="flex gap-1 shrink-0">
        <button
          type="button"
          onClick={() => onFilter(field, '==', value)}
          aria-label={`Filter ${field} equals`}
          className="px-1.5 py-0.5 text-[10px] rounded border border-[#d0d7de] hover:bg-[#eef1f4]"
        >
          ==
        </button>
        <button
          type="button"
          onClick={() => onFilter(field, '!=', value)}
          aria-label={`Filter ${field} not equals`}
          className="px-1.5 py-0.5 text-[10px] rounded border border-[#d0d7de] hover:bg-[#eef1f4]"
        >
          !=
        </button>
      </span>
    );
  };

  const Row = ({ field, value, valueNode }) => (
    <div className="flex items-center justify-between gap-2 py-1 border-b border-[#eef1f4] text-xs">
      <div className="min-w-0 flex-1">
        <span className="text-[#8b949e] mr-2">{field}</span>
        <span className="text-[#1a2332] break-all">{valueNode ?? renderFieldValue(field, value)}</span>
      </div>
      <Actions field={field} value={value} />
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
        <pre className="p-3 rounded-lg bg-[#f6f8fa] border border-[#eef1f4] text-[11px] leading-relaxed font-mono text-[#1a2332] overflow-x-auto">
{JSON.stringify(sanitizeEvent(event || {}), null, 2)}
        </pre>
      </div>
    );
  }

  return (
    <div
      data-testid="event-inspector"
      className="mt-3 p-4 rounded-xl bg-white border border-[#e2e6ea] flex flex-col"
    >
      <SectionLabel>Identity</SectionLabel>
      <Row field="timestamp" value={view.timestamp} />
      <Row field="id" value={view.id} />
      <div className="flex items-center justify-between py-1 border-b border-[#eef1f4] text-xs">
        <span className="text-[#8b949e]">arrived as event #{view.eventSeq}</span>
      </div>

      <SectionLabel>Classification</SectionLabel>
      <div className="flex items-center gap-1.5 mb-1 text-xs">
        <span
          className="w-2 h-2 rounded-full shrink-0"
          style={{ backgroundColor: sourceColor(view.sourceType) }}
          aria-hidden="true"
        />
      </div>
      <Row field="source_type" value={view.sourceType} />
      <Row field="event_type" value={view.eventType} />

      <SectionLabel>Canonical commons</SectionLabel>
      {view.commons.map(([field, value]) => (
        <Row
          key={field}
          field={field}
          value={value}
          valueNode={field === 'hostname' && onHostPivot ? (
            <button
              type="button"
              onClick={() => onHostPivot(value)}
              className="text-[#16436b] hover:underline font-mono"
              title={`Open ${value} in Endpoints`}
            >
              {value}
            </button>
          ) : undefined}
        />
      ))}

      {view.kvpEntries.length > 0 && (
        <>
          <SectionLabel>Family fields</SectionLabel>
          {view.kvpEntries.map(([field, value]) => (
            <Row key={field} field={field} value={value} />
          ))}
        </>
      )}

      <SectionLabel>Message</SectionLabel>
      <Row field="message" value={view.message} />

      <SectionLabel>Raw</SectionLabel>
      <pre className="p-3 rounded-lg bg-[#f6f8fa] border border-[#eef1f4] text-[11px] leading-relaxed font-mono text-[#1a2332] overflow-x-auto">
{JSON.stringify(sanitizeEvent(event), null, 2)}
      </pre>
    </div>
  );
};

export default EventInspector;
