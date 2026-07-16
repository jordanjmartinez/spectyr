import React, { useEffect, useState } from 'react';
import { sevColor, sourceColor, sanitizeEvent } from './siemUtils';

// SIEM card view (Stage 1.5, default view): event cards color-coded by
// source family, expandable to the sanitized raw-log JSON. Presentational
// only; receives the already-filtered cached pool.

const PER_PAGE = 12;

const timeOf = (iso) =>
  iso ? new Date(iso).toLocaleTimeString('en-GB', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '-';

const SiemCards = ({ alerts, resetTrigger, onHostPivot }) => {
  const [page, setPage] = useState(1);
  const [expanded, setExpanded] = useState({});

  useEffect(() => {
    setPage(1);
    setExpanded({});
  }, [resetTrigger]);

  useEffect(() => {
    const maxPage = Math.max(1, Math.ceil(alerts.length / PER_PAGE));
    if (page > maxPage) setPage(maxPage);
  }, [alerts.length, page]);

  const totalPages = Math.max(1, Math.ceil(alerts.length / PER_PAGE));
  const current = alerts.slice((page - 1) * PER_PAGE, page * PER_PAGE);

  if (alerts.length === 0) {
    return (
      <div
        className="p-6 rounded-xl flex flex-col items-center justify-center py-12"
        style={{ background: '#ffffff', border: '1px solid #e2e6ea', boxShadow: '0 1px 2px rgba(0,0,0,0.04)' }}
      >
        <svg className="w-12 h-12 text-[#6e7781] mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
        </svg>
        <p className="text-sm text-[#6e7781]">No events match the current filters.</p>
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
        <span className="px-2 text-[#57606a]">{page} / {totalPages}</span>
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
          const isOpen = !!expanded[alert.id];
          return (
            <div
              key={alert.id}
              className="bg-white rounded-xl border border-[#e2e6ea] overflow-hidden flex flex-col"
              style={{ borderLeft: `3px solid ${sevColor(alert.severity)}`, boxShadow: '0 1px 2px rgba(0,0,0,0.04)' }}
            >
              <button
                type="button"
                onClick={() => setExpanded(prev => ({ ...prev, [alert.id]: !prev[alert.id] }))}
                className="text-left p-4 flex-1 hover:bg-[#f6f8fa] transition-colors"
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono font-semibold text-sm text-[#1a2332] truncate" title={alert.event_type}>
                    {alert.event_type || '-'}
                  </span>
                  <span className="ml-auto font-mono text-xs text-[#57606a] whitespace-nowrap">{timeOf(alert.timestamp)}</span>
                </div>
                <div className="mt-1.5 flex items-center gap-1.5 text-xs text-[#57606a]">
                  <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: sourceColor(source) }} aria-hidden="true" />
                  {source}
                </div>
                <dl className="mt-3 space-y-1 text-xs">
                  {[['host', alert.hostname], ['src', alert.source_ip], ['dst', alert.destination_ip], ['user', alert.user_account]]
                    .filter(([, v]) => v)
                    .map(([k, v]) => (
                      <div key={k} className="flex gap-2">
                        <dt className="w-8 shrink-0 text-[#8b949e]">{k}</dt>
                        <dd className="font-mono text-[#1a2332] break-all">{v}</dd>
                      </div>
                    ))}
                </dl>
                <p className="mt-2 text-xs text-[#57606a] line-clamp-2" title={alert.message || '-'}>
                  {alert.message || '-'}
                </p>
              </button>
              {isOpen && (
                <div className="border-t border-[#eef1f4]">
                  {alert.hostname && onHostPivot && (
                    <div className="px-4 pt-3 text-xs">
                      <button
                        type="button"
                        onClick={() => onHostPivot(alert.hostname)}
                        className="text-[#16436b] hover:underline font-mono"
                        title={`Open ${alert.hostname} in Endpoints`}
                      >
                        {alert.hostname}
                      </button>
                      <span className="text-[#8b949e]"> in Endpoints</span>
                    </div>
                  )}
                  <pre className="m-3 p-3 rounded-lg bg-[#f6f8fa] border border-[#eef1f4] text-[11px] leading-relaxed font-mono text-[#1a2332] overflow-x-auto">
{JSON.stringify(sanitizeEvent(alert), null, 2)}
                  </pre>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </>
  );
};

export default SiemCards;
