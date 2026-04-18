import React, { useEffect, useRef, useState } from 'react';
import { apiFetch } from '../api';

const AlertTable = ({ setAlertCount, resetTrigger }) => {
  const [alerts, setAlerts] = useState([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [alertsPerPage, setAlertsPerPage] = useState(20);
  const [searchTerm, setSearchTerm] = useState('');
  const [searchField, setSearchField] = useState('all');
  const [expandedRows, setExpandedRows] = useState({});
  const [pageSizeOpen, setPageSizeOpen] = useState(false);
  const pageSizeRef = useRef(null);

  const searchFields = [
    { value: 'all', label: 'All Fields' },
    { value: 'event_type', label: 'Event Type' },
    { value: 'source_type', label: 'Source Type' },
    { value: 'source_ip', label: 'Source IP' },
    { value: 'destination_ip', label: 'Destination IP' },
    { value: 'protocol', label: 'Protocol' },
    { value: 'message', label: 'Message' },
    { value: 'hostname', label: 'Hostname' },
  ];

  const fetchAlerts = () => {
    apiFetch('/api/fake-events')
      .then(res => res.json())
      .then(data => {
        setAlerts([...data].reverse());
      })
      .catch(err => console.error('Error fetching fake events:', err));
  };

  useEffect(() => {
    const handleClickOutside = (e) => {
      if (pageSizeRef.current && !pageSizeRef.current.contains(e.target)) {
        setPageSizeOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 2000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    // Clear state on reset
    setAlerts([]);
    setAlertCount(0);
    fetchAlerts();
    setCurrentPage(1);
  }, [resetTrigger]);

  const filteredAlerts = alerts.filter(alert => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    if (searchField === 'all') {
      return JSON.stringify(alert).toLowerCase().includes(term);
    }
    const fieldValue = alert[searchField];
    return fieldValue && String(fieldValue).toLowerCase().includes(term);
  });

  useEffect(() => {
    if (setAlertCount) {
      setAlertCount(filteredAlerts.length);
    }
  }, [filteredAlerts, setAlertCount]);

  const totalPages = Math.ceil(filteredAlerts.length / alertsPerPage);
  const indexOfLast = currentPage * alertsPerPage;
  const indexOfFirst = indexOfLast - alertsPerPage;
  const currentAlerts = filteredAlerts.slice(indexOfFirst, indexOfLast);

  const changePage = (pageNum) => {
    if (pageNum >= 1 && pageNum <= totalPages) {
      setCurrentPage(pageNum);
    }
  };

  const handlePageSizeChange = (e) => {
    setAlertsPerPage(Number(e.target.value));
    setCurrentPage(1);
  };

  const toggleRow = (id) => {
    setExpandedRows(prev => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  // Clean key=value event display
  const renderCleanEventDetails = (log) => {
    // Excluded key_value_pairs fields (noise or redundant)
    const excludedKvp = [
      'event_id', 'host', 'event_type',  // already shown in common fields
      'device_id', 'class_id', 'compatible_ids', 'location',  // USB noise
      'subject_user', 'subject_domain',  // redundant with user field
      'utc_time', 'process_guid', 'parent_command_line',  // ProcessCreate noise
      'parent_process_id', 'integrity_level', 'hashes',
      'image', 'parent_image', 'user',  // replaced by display-friendly names
    ];

    // Common fields from top-level
    const commonFields = [
      ['timestamp', log.timestamp ? log.timestamp.replace('T', ' ').replace(/\.\d+.*$/, '') : null],
      ['event_type', log.event_type],
      ['source_type', log.source_type || log.detected_by || 'Unknown'],
      ['host', log.hostname],
      ['src_ip', log.source_ip],
      ['user', log.user_account],
    ];

    // Fields from key_value_pairs (filtered)
    const kvpFields = log.key_value_pairs
      ? Object.entries(log.key_value_pairs).filter(([k]) => !excludedKvp.includes(k))
      : [];

    // Trim message to first sentence
    const trimmedMessage = log.message || '';

    // Calculate max key length for alignment
    const allKeys = [...commonFields.filter(([, v]) => v).map(([k]) => k), ...kvpFields.map(([k]) => k), 'message'];
    const maxKeyLen = Math.max(...allKeys.map(k => k.length));

    return (
      <div className="log-detail space-y-0.5">
        {commonFields
          .filter(([, v]) => v)
          .map(([k, v]) => (
            <div key={k}>
              <span className="text-gray-500">{k.padEnd(maxKeyLen)}</span>
              <span className="text-gray-500"> = </span>
              <span className="text-gray-100">{v}</span>
            </div>
          ))}
        {kvpFields.map(([k, v]) => (
          <div key={k}>
            <span className="text-gray-500">{k.padEnd(maxKeyLen)}</span>
            <span className="text-gray-500"> = </span>
            <span className="text-gray-100">{String(v)}</span>
          </div>
        ))}
        <div>
          <span className="text-gray-500">{'message'.padEnd(maxKeyLen)}</span>
          <span className="text-gray-500"> = </span>
          <span className="text-gray-100">{trimmedMessage}</span>
        </div>
      </div>
    );
  };

  const highlightMatch = (text, query) => {
    if (!query) return text;
    const escapedQuery = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(`(${escapedQuery})`, 'gi');
    return text.replace(regex, '<mark class="bg-yellow-300 text-black">$1</mark>');
  };

  const renderPaginationButtons = () => {
    const buttons = [];
    const visibleRange = 2;
    const start = Math.max(2, currentPage - visibleRange);
    const end = Math.min(totalPages - 1, currentPage + visibleRange);

    const buttonClass = (isActive) =>
      `w-7 h-7 flex items-center justify-center rounded-md text-xs font-medium transition border border-gray-600 ${
        isActive
          ? 'text-white'
          : 'bg-[#21262d] text-gray-400 hover:bg-[#30363d] hover:text-gray-200'
      }`;
    const activePageStyle = { backgroundColor: 'rgba(255,255,255,0.08)' };

    buttons.push(
      <button key={1} onClick={() => changePage(1)} className={buttonClass(currentPage === 1)} style={currentPage === 1 ? activePageStyle : undefined}>
        1
      </button>
    );

    if (start > 2) buttons.push(<span key="start-ellipsis" className="px-1 text-gray-600">...</span>);

    for (let i = start; i <= end; i++) {
      buttons.push(
        <button key={i} onClick={() => changePage(i)} className={buttonClass(currentPage === i)} style={currentPage === i ? activePageStyle : undefined}>
          {i}
        </button>
      );
    }

    if (end < totalPages - 1) buttons.push(<span key="end-ellipsis" className="px-1 text-gray-600">...</span>);

    if (totalPages > 1) {
      buttons.push(
        <button key={totalPages} onClick={() => changePage(totalPages)} className={buttonClass(currentPage === totalPages)} style={currentPage === totalPages ? activePageStyle : undefined}>
          {totalPages}
        </button>
      );
    }

    return buttons;
  };

  const noAlertsLoaded = alerts.length === 0;
  const noSearchResults = !noAlertsLoaded && filteredAlerts.length === 0;

  return (
    <>
        <div className="mb-3">
          <div className="relative">
            <input
              type="text"
              placeholder="Search events..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setSearchField('all');
                setCurrentPage(1);
              }}
              maxLength={300}
              className="w-full pl-4 pr-10 py-2 rounded-md bg-[#0d1117] border border-gray-700 text-white text-sm placeholder-gray-400 focus:border-gray-500 focus:outline-none transition-colors"
            />
            {!searchTerm && (
              <svg className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            )}
            {searchTerm && (
              <button
                onClick={() => {
                  setSearchTerm('');
                  setCurrentPage(1);
                }}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            )}
          </div>
        </div>
      {!noAlertsLoaded && (
        <>
          <div className="flex flex-row justify-between items-center mb-3">
            <div className="hidden sm:flex items-center relative" ref={pageSizeRef}>
              <button
                onClick={() => setPageSizeOpen(!pageSizeOpen)}
                className="inline-flex items-center justify-center gap-1 px-2 sm:px-4 py-1.5 sm:py-2 text-xs font-medium rounded-md border transition bg-[#21262d] hover:bg-[#30363d] text-gray-200 border-gray-600 focus:outline-none focus:ring-2 focus:ring-gray-500"
              >
                <svg className={`w-4 h-4 transition-transform ${pageSizeOpen ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
                {alertsPerPage} Per Page
              </button>
              {pageSizeOpen && (
                <>
                  <div className="fixed inset-0 z-10" onClick={() => setPageSizeOpen(false)} />
                  <div className="absolute left-0 top-full mt-1 z-20 bg-[#161b22] border border-gray-700 rounded py-1 flex flex-col min-w-[100px] sm:min-w-[120px]">
                    {[10, 20, 50].map((size) => (
                      <button
                        key={size}
                        onClick={(e) => {
                          e.stopPropagation();
                          handlePageSizeChange({ target: { value: String(size) } });
                          setPageSizeOpen(false);
                        }}
                        className="flex items-center gap-2 text-left px-2.5 sm:px-3 py-1 sm:py-1.5 text-xs hover:bg-gray-700 transition text-gray-400"
                      >
                        <span className={`w-2.5 h-2.5 rounded border ${alertsPerPage === size ? 'bg-gray-300 border-gray-300' : 'border-gray-600'}`} />
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
                className="px-2 sm:px-3 py-1 sm:py-1.5 text-xs font-medium rounded-md bg-[#21262d] hover:bg-[#30363d] text-gray-200 border border-gray-600 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-[#21262d] transition"
              >
                Prev
              </button>
              <div className="hidden sm:flex items-center gap-1 mx-1">
                {renderPaginationButtons()}
              </div>
              <span className="flex sm:hidden px-1.5 text-xs text-gray-400">
                {currentPage} / {totalPages}
              </span>
              <button
                onClick={() => changePage(currentPage + 1)}
                disabled={currentPage === totalPages}
                className="px-2 sm:px-3 py-1 sm:py-1.5 text-xs font-medium rounded-md bg-[#21262d] hover:bg-[#30363d] text-gray-200 border border-gray-600 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-[#21262d] transition"
              >
                Next
              </button>
            </div>
          </div>

        </>
      )}

    <div
      className="p-3 sm:p-6 rounded-xl flex-1 flex flex-col"
      style={{
        background: 'linear-gradient(#161b22, #161b22) padding-box, linear-gradient(to bottom, rgba(88,130,180,0.3), transparent) border-box',
        border: '1px solid transparent',
        boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05)',
      }}
    >

      {noAlertsLoaded ? (
        <div className="flex flex-col items-center justify-center py-8 flex-1">
          <img src="/ghost-mascot.png" alt="Ghost" className="w-28 h-28 sm:w-40 sm:h-40 opacity-90 mb-3" />
          <p className="font-mono text-xs sm:text-sm text-gray-400 text-center sm:text-left">&gt; Click Start Simulation to begin.</p>
        </div>
      ) : noSearchResults ? (
        <div className="flex flex-col items-center justify-center py-12">
          <img src="/ghost-searching.png" alt="Ghost Searching" className="w-20 h-20 sm:w-28 sm:h-28 opacity-90 mb-3" />
          <p className="font-mono text-xs sm:text-sm text-gray-400 text-center sm:text-left">&gt; No matching logs for "{searchTerm}"</p>
        </div>
      ) : (
        <div className="overflow-x-auto overflow-y-hidden mobile-scroll-wrapper" style={{ minHeight: `${(alertsPerPage * 49) + 48}px` }}>
          <table className="w-full min-w-[900px] sm:min-w-[1000px] log-text text-left text-gray-300 border-separate border-spacing-0">
            <thead>
              <tr className="text-xs sm:text-sm uppercase text-gray-400 tracking-wider">
                <th className="px-2 sm:px-4 py-3 font-medium w-10"></th>
                <th className="px-2 sm:px-4 py-3 font-medium w-[100px] sm:w-[130px] whitespace-nowrap text-center">Time</th>
                <th className="px-2 sm:px-4 py-3 font-medium w-[160px] sm:w-[240px] whitespace-nowrap text-center">Event Type</th>
                <th className="px-2 sm:px-4 py-3 font-medium w-[110px] sm:w-[170px] whitespace-nowrap text-center">Src Type</th>
                <th className="px-2 sm:px-4 py-3 font-medium w-[120px] sm:w-[160px] whitespace-nowrap text-center">Src IP</th>
                <th className="px-2 sm:px-4 py-3 font-medium w-[120px] sm:w-[160px] whitespace-nowrap text-center">Dst IP</th>
                <th className="px-2 sm:px-4 py-3 font-medium w-[240px] sm:w-auto whitespace-nowrap">Message</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {currentAlerts.map((alert) => {
                const hasValue = (v) => v && v !== '—' && v !== 'N/A' && v !== '';
                const isRegistryEvent = hasValue(alert.target_object) || hasValue(alert.registry_details);
                const isProcessAccessEvent = hasValue(alert.source_image) || hasValue(alert.target_image);
                const isNetworkConnectionEvent = hasValue(alert.destination_hostname) || alert.destination_port;
                const isProcessEvent = hasValue(alert.process_path) || hasValue(alert.process_command_line);
                const isNetworkEvent = hasValue(alert.destination_ip) || (hasValue(alert.protocol) && alert.protocol !== 'N/A');

                return (
                  <React.Fragment key={alert.id}>
                    <tr
                      className="hover:bg-white/5 transition-colors cursor-pointer border-b border-gray-700/50"
                      onClick={() => toggleRow(alert.id)}
                    >
                      <td className="px-2 sm:px-4 py-4">
                        <svg
                          className={`w-5 h-5 text-gray-500 hover:text-white transition-transform duration-300 ease-in-out ${
                            expandedRows[alert.id] ? 'rotate-180' : 'rotate-0'
                          }`}
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                        </svg>
                      </td>
                      <td className="px-2 sm:px-4 py-4 whitespace-nowrap border-l-4 border-l-transparent text-center">
                        <span className="text-gray-300">
                          {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString('en-GB', {
                            hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit'
                          }) : '—'}
                        </span>
                      </td>
                      <td className="px-2 sm:px-4 py-4 font-medium text-gray-200 whitespace-nowrap text-center" title={alert.event_type || '—'}>
                        {alert.event_type || '—'}
                      </td>
                      <td className="px-2 sm:px-4 py-4 text-gray-200 sm:whitespace-nowrap text-center">
                        {alert.source_type || alert.detected_by || 'Unknown'}
                      </td>
                      <td className="px-2 sm:px-4 py-4 text-gray-200 sm:whitespace-nowrap text-center">
                        {alert.source_ip || '—'}
                      </td>
                      <td className="px-2 sm:px-4 py-4 text-gray-200 sm:whitespace-nowrap text-center">
                        {alert.destination_ip || '—'}
                      </td>
                      <td className="px-2 sm:px-4 py-4 text-gray-200 whitespace-nowrap" title={alert.message || '—'}>
                        {alert.message || '—'}
                      </td>
                    </tr>

                    {/* Expandable Details Row */}
                    <tr>
                      <td colSpan="7" className="p-0">
                        <div
                          className={`grid transition-all duration-300 ease-in-out ${
                            expandedRows[alert.id] ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
                          }`}
                        >
                          <div className="overflow-hidden min-h-0">
                            <div className="border-t border-gray-700 px-6 py-4">
                              {renderCleanEventDetails(alert)}
                            </div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

    </div>
    </>
  );
};

export default AlertTable;
