import React, { useEffect, useState } from 'react';

// SIEM card view: event cards color-coded by source family. Presentational
// only; renders the frozen snapshot rows. Selection is CONTROLLED by the
// workbench shell (Stage 4 P5.1: one inspector, selection keyed by event
// id, persisting across view toggles and surviving Load new events when the id
// survives). The selected card's full detail renders in the shared
// EventInspector below the results (Stage 4 P6.3) -- this component only
// highlights which card is selected; it has no inline expansion.

const PER_PAGE = 12;

const timeOf = (iso) =>
  iso ? new Date(iso).toLocaleTimeString('en-GB', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '-';

const SiemCards = ({ alerts, resetTrigger, selectedId, onSelect }) => {
  const [page, setPage] = useState(1);

  useEffect(() => {
    setPage(1);
  }, [resetTrigger]);

  useEffect(() => {
    const maxPage = Math.max(1, Math.ceil(alerts.length / PER_PAGE));
    if (page > maxPage) setPage(maxPage);
  }, [alerts.length, page]);

  const totalPages = Math.max(1, Math.ceil(alerts.length / PER_PAGE));
  const current = alerts.slice((page - 1) * PER_PAGE, page * PER_PAGE);

  if (alerts.length === 0) {
    return (
      /* Owner empty-state convention (2026-10-12): one muted line,
         top-left; no icon, no centering. */
      <div
        className="p-4 rounded-xl"
        style={{ background: '#ffffff', border: '1px solid #e2e6ea', boxShadow: '0 1px 2px rgba(0,0,0,0.04)' }}
      >
        <p className="text-sm text-muted">No events match the current filters.</p>
      </div>
    );
  }

  return (
    <>
      <div className="flex items-center justify-end gap-1 text-xs mb-3">
        <button
          onClick={() => setPage(p => Math.max(1, p - 1))}
          disabled={page === 1}
          className="px-3 py-1.5 text-xs font-medium rounded-md bg-white hover:bg-[#eef1f4] text-[#1a2332] border border-[#d0d7de] disabled:opacity-40 disabled:cursor-not-allowed transition"
        >
          Prev
        </button>
        <span className="px-2 text-muted">{page} / {totalPages}</span>
        <button
          onClick={() => setPage(p => Math.min(totalPages, p + 1))}
          disabled={page === totalPages}
          className="px-3 py-1.5 text-xs font-medium rounded-md bg-white hover:bg-[#eef1f4] text-[#1a2332] border border-[#d0d7de] disabled:opacity-40 disabled:cursor-not-allowed transition"
        >
          Next
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-3">
        {current.map((alert) => {
          const source = alert.source_type || alert.detected_by || 'Unknown';
          const isOpen = alert.id === selectedId;
          return (
            // Owner follow-up pass (2026-10-13): no severity edge, no
            // source dot -- the facet rail and the detail view carry
            // those dimensions as text.
            <div
              key={alert.id}
              className={`bg-white rounded-xl border overflow-hidden flex flex-col ${
                isOpen ? 'border-[#16436b] ring-1 ring-[#16436b]' : 'border-[#e2e6ea]'
              }`}
              style={{ boxShadow: '0 1px 2px rgba(0,0,0,0.04)' }}
            >
              <button
                type="button"
                onClick={() => onSelect?.(isOpen ? null : alert.id)}
                className="text-left p-4 flex-1 hover:bg-[#f6f8fa] transition-colors"
              >
                <div className="flex items-center gap-2">
                  <span className="log-mono font-semibold text-sm text-[#1a2332] truncate" title={alert.event_type}>
                    {alert.event_type || '-'}
                  </span>
                  <span className="ml-auto log-mono text-xs text-muted whitespace-nowrap">{timeOf(alert.timestamp)}</span>
                </div>
                <div className="mt-1.5 text-xs text-muted">
                  {source}
                </div>
                <dl className="mt-3 space-y-1 text-xs">
                  {[['host', alert.hostname], ['src', alert.source_ip], ['dst', alert.destination_ip], ['user', alert.user_account]]
                    .filter(([, v]) => v)
                    .map(([k, v]) => (
                      <div key={k} className="flex gap-2">
                        <dt className="w-8 shrink-0 text-muted">{k}</dt>
                        <dd className="log-mono text-[#1a2332] break-all">{v}</dd>
                      </div>
                    ))}
                </dl>
                <p className="mt-2 text-xs text-muted line-clamp-2" title={alert.message || '-'}>
                  {alert.message || '-'}
                </p>
              </button>
            </div>
          );
        })}
      </div>
    </>
  );
};

export default SiemCards;
