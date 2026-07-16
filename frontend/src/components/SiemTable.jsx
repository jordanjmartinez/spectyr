import React, { useEffect, useState } from 'react';
import { sevColor, sanitizeEvent } from './siemUtils';

// SIEM table view (Stage 1.5): presentational. Receives the already-filtered
// cached pool from Siem.jsx; owns only pagination, sorting, and expansion.

const SORTABLE = [
  { key: 'timestamp', label: 'Time' },
  { key: 'event_type', label: 'Event Type' },
  { key: 'source_type', label: 'Src Type' },
  { key: 'source_ip', label: 'Src IP' },
  { key: 'destination_ip', label: 'Dst IP' },
];

const SiemTable = ({ alerts, resetTrigger, onHostPivot }) => {
  const [currentPage, setCurrentPage] = useState(1);
  const [alertsPerPage, setAlertsPerPage] = useState(20);
  const [expandedRows, setExpandedRows] = useState({});
  const [sort, setSort] = useState(null); // { key, dir } or null = feed order
  const [pageSizeOpen, setPageSizeOpen] = useState(false);

  useEffect(() => {
    setCurrentPage(1);
    setExpandedRows({});
    setSort(null);
  }, [resetTrigger]);

  useEffect(() => {
    const maxPage = Math.max(1, Math.ceil(alerts.length / alertsPerPage));
    if (currentPage > maxPage) setCurrentPage(maxPage);
  }, [alerts.length, alertsPerPage, currentPage]);

  // Stable sort: chosen key, then timestamp desc, then id (addendum rule).
  const sorted = sort === null ? alerts : [...alerts].sort((a, b) => {
    const va = String(a[sort.key] ?? '');
    const vb = String(b[sort.key] ?? '');
    const cmp = va.localeCompare(vb);
    const primary = sort.dir === 'asc' ? cmp : -cmp;
    if (primary !== 0) return primary;
    const ts = String(b.timestamp ?? '').localeCompare(String(a.timestamp ?? ''));
    return ts !== 0 ? ts : String(a.id).localeCompare(String(b.id));
  });

  const toggleSort = (key) => {
    setSort(s => (s?.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' }));
    setCurrentPage(1);
  };

  const totalPages = Math.max(1, Math.ceil(sorted.length / alertsPerPage));
  const currentAlerts = sorted.slice((currentPage - 1) * alertsPerPage, currentPage * alertsPerPage);

  const changePage = (n) => { if (n >= 1 && n <= totalPages) setCurrentPage(n); };
  const toggleRow = (id) => setExpandedRows(prev => ({ ...prev, [id]: !prev[id] }));

  const renderCleanEventDetails = (log) => {
    const raw = sanitizeEvent(log);
    const commonFields = [
      ['timestamp', raw.timestamp ? raw.timestamp.replace('T', ' ').replace(/\.\d+.*$/, '') : null],
      ['event_type', raw.event_type],
      ['source_type', raw.source_type || 'Unknown'],
      ['host', raw.hostname],
      ['src_ip', raw.source_ip],
      ['user', raw.user_account],
    ];
    const excludedKvp = [
      'event_id', 'host', 'event_type', 'device_id', 'class_id',
      'compatible_ids', 'location', 'subject_user', 'subject_domain',
      'utc_time', 'process_guid', 'parent_command_line',
      'parent_process_id', 'integrity_level', 'hashes',
      'image', 'parent_image', 'user',
    ];
    const kvpFields = raw.key_value_pairs
      ? Object.entries(raw.key_value_pairs).filter(([k]) => !excludedKvp.includes(k))
      : [];
    const allKeys = [...commonFields.filter(([, v]) => v).map(([k]) => k), ...kvpFields.map(([k]) => k), 'message'];
    const maxKeyLen = Math.max(...allKeys.map(k => k.length));

    return (
      <div className="log-detail space-y-0.5">
        {commonFields
          .filter(([, v]) => v)
          .map(([k, v]) => (
            <div key={k}>
              <span className="text-[#6e7781]">{k.padEnd(maxKeyLen)}</span>
              <span className="text-[#6e7781]"> = </span>
              {k === 'host' && onHostPivot ? (
                <button
                  type="button"
                  onClick={() => onHostPivot(v)}
                  className="text-[#16436b] hover:underline"
                  title={`Open ${v} in Endpoints`}
                >
                  {v}
                </button>
              ) : (
                <span className="text-[#1a2332]">{v}</span>
              )}
            </div>
          ))}
        {kvpFields.map(([k, v]) => (
          <div key={k}>
            <span className="text-[#6e7781]">{k.padEnd(maxKeyLen)}</span>
            <span className="text-[#6e7781]"> = </span>
            <span className="text-[#1a2332]">{String(v)}</span>
          </div>
        ))}
        <div>
          <span className="text-[#6e7781]">{'message'.padEnd(maxKeyLen)}</span>
          <span className="text-[#6e7781]"> = </span>
          <span className="text-[#1a2332]">{raw.message || ''}</span>
        </div>
      </div>
    );
  };

  const renderPaginationButtons = () => {
    const buttons = [];
    const start = Math.max(2, currentPage - 2);
    const end = Math.min(totalPages - 1, currentPage + 2);
    const buttonClass = (isActive) =>
      `w-7 h-7 flex items-center justify-center rounded-md text-xs font-medium transition border border-[#d0d7de] ${
        isActive ? 'text-[#1a2332]' : 'bg-white text-[#57606a] hover:bg-[#eef1f4] hover:text-[#1a2332]'
      }`;
    const activePageStyle = { backgroundColor: 'rgba(0,0,0,0.06)' };
    buttons.push(
      <button key={1} onClick={() => changePage(1)} className={buttonClass(currentPage === 1)} style={currentPage === 1 ? activePageStyle : undefined}>1</button>
    );
    if (start > 2) buttons.push(<span key="s" className="px-1 text-[#8b949e]">...</span>);
    for (let i = start; i <= end; i++) {
      buttons.push(
        <button key={i} onClick={() => changePage(i)} className={buttonClass(currentPage === i)} style={currentPage === i ? activePageStyle : undefined}>{i}</button>
      );
    }
    if (end < totalPages - 1) buttons.push(<span key="e" className="px-1 text-[#8b949e]">...</span>);
    if (totalPages > 1) {
      buttons.push(
        <button key={totalPages} onClick={() => changePage(totalPages)} className={buttonClass(currentPage === totalPages)} style={currentPage === totalPages ? activePageStyle : undefined}>{totalPages}</button>
      );
    }
    return buttons;
  };

  return (
    <>
      <div className="flex flex-row justify-between items-center mb-3">
        <div className="hidden sm:flex items-center relative">
          <button
            onClick={() => setPageSizeOpen(!pageSizeOpen)}
            className="inline-flex items-center justify-center gap-1 px-2 sm:px-4 py-1.5 sm:py-2 text-xs font-medium rounded-md border transition bg-white hover:bg-[#eef1f4] text-[#1a2332] border-[#d0d7de] focus:outline-none focus:ring-2 focus:ring-gray-500"
          >
            <svg className={`w-4 h-4 transition-transform ${pageSizeOpen ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
            {alertsPerPage} Per Page
          </button>
          {pageSizeOpen && (
            <>
              <div className="fixed inset-0 z-10" onClick={() => setPageSizeOpen(false)} />
              <div className="absolute left-0 top-full mt-1 z-20 bg-white border border-[#e2e6ea] rounded py-1 flex flex-col min-w-[100px] sm:min-w-[120px]">
                {[10, 20, 50].map((size) => (
                  <button
                    key={size}
                    onClick={(e) => {
                      e.stopPropagation();
                      setAlertsPerPage(size);
                      setCurrentPage(1);
                      setPageSizeOpen(false);
                    }}
                    className="flex items-center gap-2 text-left px-2.5 sm:px-3 py-1 sm:py-1.5 text-xs hover:bg-[#eef1f4] transition text-[#57606a]"
                  >
                    <span className={`w-2.5 h-2.5 rounded border ${alertsPerPage === size ? 'bg-[#101218] border-[#101218]' : 'border-[#d0d7de]'}`} />
                    {size} Per Page
                  </button>
                ))}
              </div>
            </>
          )}
        </div>
        <div className="flex items-center gap-1 text-xs ml-auto">
          <button
            onClick={() => changePage(currentPage - 1)}
            disabled={currentPage === 1}
            className="px-2 sm:px-3 py-1 sm:py-1.5 text-xs font-medium rounded-md bg-white hover:bg-[#eef1f4] text-[#1a2332] border border-[#d0d7de] disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-white transition"
          >
            Prev
          </button>
          <div className="hidden sm:flex items-center gap-1 mx-1">{renderPaginationButtons()}</div>
          <span className="flex sm:hidden px-1.5 text-xs text-[#57606a]">{currentPage} / {totalPages}</span>
          <button
            onClick={() => changePage(currentPage + 1)}
            disabled={currentPage === totalPages}
            className="px-2 sm:px-3 py-1 sm:py-1.5 text-xs font-medium rounded-md bg-white hover:bg-[#eef1f4] text-[#1a2332] border border-[#d0d7de] disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-white transition"
          >
            Next
          </button>
        </div>
      </div>

      <div
        className="p-3 sm:p-6 rounded-xl flex-1 flex flex-col"
        style={{ background: '#ffffff', border: '1px solid #e2e6ea', boxShadow: '0 1px 2px rgba(0,0,0,0.04)' }}
      >
        {sorted.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12">
            <svg className="w-12 h-12 text-[#6e7781] mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
            </svg>
            <p className="text-sm text-[#6e7781]">No events match the current filters.</p>
          </div>
        ) : (
          <div className="overflow-x-auto overflow-y-hidden mobile-scroll-wrapper" style={{ minHeight: `${(alertsPerPage * 49) + 48}px` }}>
            <table className="w-full min-w-[900px] sm:min-w-[1000px] log-text text-left text-[#1a2332] border-separate border-spacing-0">
              <thead>
                <tr className="text-xs sm:text-sm text-[#57606a] tracking-wider">
                  <th className="px-2 sm:px-4 py-3 font-medium w-10 border-b border-[#d0d7de]"></th>
                  {SORTABLE.map(col => (
                    <th key={col.key} className="px-2 sm:px-4 py-3 font-medium whitespace-nowrap border-b border-[#d0d7de]">
                      <button type="button" onClick={() => toggleSort(col.key)} className="inline-flex items-center gap-1 hover:text-[#1a2332]">
                        {col.label}
                        {sort?.key === col.key && <span aria-hidden="true">{sort.dir === 'asc' ? '▴' : '▾'}</span>}
                      </button>
                    </th>
                  ))}
                  <th className="px-2 sm:px-4 py-3 font-medium w-[240px] sm:w-auto whitespace-nowrap border-b border-[#d0d7de]">Message</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#e2e6ea]">
                {currentAlerts.map((alert) => (
                  <React.Fragment key={alert.id}>
                    <tr
                      className="hover:bg-[#f6f8fa] transition-colors cursor-pointer border-b border-[#e2e6ea]/50"
                      onClick={() => toggleRow(alert.id)}
                    >
                      <td className="px-2 sm:px-4 py-4 border-l-[3px]" style={{ borderLeftColor: sevColor(alert.severity) }}>
                        <svg
                          className={`w-5 h-5 text-[#6e7781] hover:text-[#1a2332] transition-transform duration-300 ease-in-out ${
                            expandedRows[alert.id] ? 'rotate-180' : 'rotate-0'
                          }`}
                          fill="none" stroke="currentColor" viewBox="0 0 24 24"
                        >
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                        </svg>
                      </td>
                      <td className="log-mono px-2 sm:px-4 py-4 text-[#1a2332] whitespace-nowrap">
                        {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString('en-GB', {
                          hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit'
                        }) : '-'}
                      </td>
                      <td className="log-mono px-2 sm:px-4 py-4 font-medium text-[#1a2332] whitespace-nowrap" title={alert.event_type || '-'}>
                        {alert.event_type || '-'}
                      </td>
                      <td className="px-2 sm:px-4 py-4 text-[#1a2332] sm:whitespace-nowrap">
                        {alert.source_type || alert.detected_by || 'Unknown'}
                      </td>
                      <td className="log-mono px-2 sm:px-4 py-4 text-[#1a2332] sm:whitespace-nowrap">{alert.source_ip || '-'}</td>
                      <td className="log-mono px-2 sm:px-4 py-4 text-[#1a2332] sm:whitespace-nowrap">{alert.destination_ip || '-'}</td>
                      <td className="px-2 sm:px-4 py-4 text-[#1a2332] whitespace-nowrap" title={alert.message || '-'}>
                        {alert.message || '-'}
                      </td>
                    </tr>
                    <tr>
                      <td colSpan="7" className="p-0">
                        <div className={`grid transition-all duration-300 ease-in-out ${
                          expandedRows[alert.id] ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
                        }`}>
                          <div className="overflow-hidden min-h-0">
                            <div style={{ height: '1px', background: 'linear-gradient(to right, rgba(0,0,0,0.08), transparent)' }} />
                            <div className="px-6 py-4">{renderCleanEventDetails(alert)}</div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
};

export default SiemTable;
