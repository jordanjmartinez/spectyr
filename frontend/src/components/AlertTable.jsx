import React, { useEffect, useRef, useState } from 'react';
import { apiFetch } from '../api';

const AlertTable = ({ setAlertCount, resetTrigger, onHardcoreFailure, onNewIncident }) => {
  const [alerts, setAlerts] = useState([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [alertsPerPage, setAlertsPerPage] = useState(20);
  const [searchTerm, setSearchTerm] = useState('');
  const [searchField, setSearchField] = useState('all');
  const [expandedRows, setExpandedRows] = useState({});
  const [flaggingIds, setFlaggingIds] = useState(new Set());
  const [showMobileTutorial, setShowMobileTutorial] = useState(() => {
    return !localStorage.getItem('spectyr_mobile_onboarded');
  });
  const [tutorialStep, setTutorialStep] = useState(0);
  const longPressTimer = useRef(null);
  const longPressTriggered = useRef(false);
  const [hintLevel, setHintLevel] = useState(0);
  const [scenarioHint, setScenarioHint] = useState('');
  const [gameMode, setGameMode] = useState(null);
  const [isPaused, setIsPaused] = useState(true);
  const [scenarioProgress, setScenarioProgress] = useState({ flagged: 0, total: 0 });
  const scenarioIdRef = useRef(null);

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

  const fetchGameState = () => {
    apiFetch('/api/game-state')
      .then(res => res.json())
      .then(data => { setGameMode(data.game_mode); setIsPaused(data.paused); })
      .catch(err => console.error('Error fetching game state:', err));
  };

  const fetchScenarioHint = () => {
    apiFetch('/api/current-scenario')
      .then(res => res.json())
      .then(data => {
        if (data && data.hint) {
          if (data.scenario_id && data.scenario_id !== scenarioIdRef.current) {
            setHintLevel(0);
            scenarioIdRef.current = data.scenario_id;
          }
          setScenarioHint(data.hint);
        } else {
          setScenarioHint('');
          setHintLevel(0);
          scenarioIdRef.current = null;
        }
      })
      .catch(() => {});
  };

  const fetchScenarioProgress = () => {
    if (!scenarioIdRef.current) return;
    apiFetch('/api/scenario-progress')
      .then(res => res.json())
      .then(data => {
        const match = (data.scenarios || []).find(s => s.scenario_id === scenarioIdRef.current);
        if (match) {
          setScenarioProgress({ flagged: match.flagged_count, total: match.total_count });
        }
      })
      .catch(() => {});
  };

  useEffect(() => {
    fetchAlerts();
    fetchGameState();
    fetchScenarioHint();
    fetchScenarioProgress();
    const interval = setInterval(() => {
      fetchAlerts();
      fetchGameState();
      fetchScenarioHint();
      fetchScenarioProgress();
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    // Clear state on reset
    setAlerts([]);
    setAlertCount(0);
    setHintLevel(0);
    setScenarioHint('');
    setScenarioProgress({ flagged: 0, total: 0 });
    scenarioIdRef.current = null;
    fetchAlerts();
    setCurrentPage(1);
  }, [resetTrigger]);

  const handleFlagEvent = async (eventId, shouldFlag) => {
    setFlaggingIds(prev => new Set([...prev, eventId]));

    try {
      const res = await apiFetch('/api/flag-event', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ event_id: eventId, flagged: shouldFlag })
      });

      const data = await res.json();

      // Handle hardcore failure (3 strikes)
      if (data.status === 'hardcore_failure') {
        if (onHardcoreFailure) {
          onHardcoreFailure();
        }
        return;
      }

      // Update local state
      setAlerts(prev => prev.map(a =>
        a.id === eventId ? { ...a, flagged: shouldFlag } : a
      ));

      // Update scenario progress immediately from response
      if (data.scenario_progress) {
        setScenarioProgress({
          flagged: data.scenario_progress.flagged_count,
          total: data.scenario_progress.total_count
        });
      }

      // Notify parent when a new incident is ready
      if (data.scenario_progress?.all_flagged && onNewIncident) {
        onNewIncident();
      }
    } catch (err) {
      console.error('Error flagging event:', err);
    } finally {
      setFlaggingIds(prev => {
        const next = new Set(prev);
        next.delete(eventId);
        return next;
      });
    }
  };

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
      `w-7 h-7 sm:w-8 sm:h-8 flex items-center justify-center rounded-lg text-xs sm:text-sm transition-colors ${
        isActive
          ? 'bg-gray-700 text-white font-medium border border-gray-600'
          : 'bg-gray-800 text-gray-400 hover:bg-gray-700 hover:text-gray-200'
      }`;

    buttons.push(
      <button key={1} onClick={() => changePage(1)} className={buttonClass(currentPage === 1)}>
        1
      </button>
    );

    if (start > 2) buttons.push(<span key="start-ellipsis" className="px-1 text-gray-600">...</span>);

    for (let i = start; i <= end; i++) {
      buttons.push(
        <button key={i} onClick={() => changePage(i)} className={buttonClass(currentPage === i)}>
          {i}
        </button>
      );
    }

    if (end < totalPages - 1) buttons.push(<span key="end-ellipsis" className="px-1 text-gray-600">...</span>);

    if (totalPages > 1) {
      buttons.push(
        <button key={totalPages} onClick={() => changePage(totalPages)} className={buttonClass(currentPage === totalPages)}>
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
      {!noAlertsLoaded && (
        <div className="mb-3">
          <div className="relative">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              type="text"
              placeholder="Search logs..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setSearchField('all');
                setCurrentPage(1);
              }}
              maxLength={300}
              className="w-full pl-10 pr-10 py-2 rounded-md bg-transparent border border-gray-700 text-white text-sm placeholder-gray-500 focus:border-gray-500 focus:outline-none transition-colors"
            />
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
      )}
      {!noAlertsLoaded && (
        <>
          <div className="flex flex-row justify-between items-center mb-3">
            <div className="flex items-center gap-1 text-xs sm:text-sm">
              <button
                onClick={() => changePage(currentPage - 1)}
                disabled={currentPage === 1}
                className="px-2 sm:px-3 py-1 sm:py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
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
                className="px-2 sm:px-3 py-1 sm:py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                Next
              </button>
            </div>
            <div className="hidden sm:flex items-center gap-2 text-sm text-gray-500">
              <select
                id="pageSize"
                value={alertsPerPage}
                onChange={handlePageSizeChange}
                className="bg-[#161b22] text-gray-400 text-sm px-3 py-1 rounded border border-gray-700 focus:border-gray-500 focus:outline-none cursor-pointer appearance-none text-center [&>option]:bg-[#161b22] [&>option]:text-center"
              >
                <option value={10}>10</option>
                <option value={20}>20</option>
                <option value={50}>50</option>
              </select>
            </div>
          </div>

          {gameMode === 'training' && scenarioHint && (() => {
            const hintReady = isPaused && Boolean(scenarioHint);
            return (
              <div className="flex items-center justify-between mb-3">
                {/* Left side: event count (always visible when ready) */}
                <div className="flex-1">
                  {!hintReady && (
                    <p className="text-xs sm:text-sm text-gray-500 italic">Scanning logs...</p>
                  )}
                  {hintReady && (
                    <p className="text-xs sm:text-sm text-gray-300 flex items-center gap-2">
                      <span className="font-semibold tabular-nums text-white">
                        {scenarioProgress.flagged}/{scenarioProgress.total}
                      </span>
                      <span className="text-gray-400">Events</span>
                    </p>
                  )}
                </div>
                {/* Hint button - toggles answer highlight */}
                <button
                  onClick={() => hintReady && setHintLevel(prev => prev === 0 ? 2 : 0)}
                  disabled={!hintReady}
                  className={`inline-flex items-center gap-1.5 px-2 sm:px-3 py-1 sm:py-1.5 text-xs sm:text-sm rounded-md border transition ${
                    !hintReady
                      ? 'text-gray-600 border-gray-700 opacity-40 cursor-not-allowed'
                      : hintLevel === 0
                      ? 'text-gray-400 border-gray-700 hover:text-gray-200 hover:border-gray-600'
                      : 'text-white border-gray-600 bg-[#21262d]'
                  }`}
                  title={!hintReady ? 'Scanning logs...' : hintLevel === 0 ? 'Show hint' : 'Hide hint'}
                >
                  <svg className="w-3.5 h-3.5 sm:w-4 sm:h-4" fill={hintLevel > 0 ? 'currentColor' : 'none'} stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                  </svg>
                  Hint
                </button>
              </div>
            );
          })()}
        </>
      )}

    <div className="bg-[#161b22] p-3 sm:p-6 rounded-xl">

      {!noAlertsLoaded && showMobileTutorial && (
        <div className="fixed inset-0 z-50 flex items-center justify-center sm:hidden">
          <div className="absolute inset-0 bg-black/70" />
          <div className="relative bg-[#161b22] border border-gray-700 rounded-xl p-6 w-full max-w-xs mx-4 shadow-2xl">

            {tutorialStep === 0 && (
              <div className="flex flex-col items-center text-center">
                <div className="w-16 h-16 flex items-center justify-center rounded-full bg-[#21262d] border border-gray-700 mb-4">
                  <svg className="w-8 h-8 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 18h.01M7 21h10a2 2 0 002-2V5a2 2 0 00-2-2H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                  </svg>
                  <svg className="w-4 h-4 text-gray-400 absolute ml-14 mt-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9" />
                  </svg>
                </div>
                <h3 className="text-base font-semibold text-white mb-2">Rotate your device</h3>
                <p className="text-sm text-gray-400">For the best experience, use landscape mode when reviewing logs.</p>
              </div>
            )}

            {tutorialStep === 1 && (
              <div className="flex flex-col items-center text-center">
                <div className="w-16 h-16 flex items-center justify-center rounded-full bg-[#21262d] border border-gray-700 mb-4">
                  <svg className="w-8 h-8 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 21v-4m0 0V5a2 2 0 012-2h6.5l1 1H21l-3 6 3 6h-8.5l-1-1H5a2 2 0 00-2 2zm9-13.5V9" />
                  </svg>
                </div>
                <h3 className="text-base font-semibold text-white mb-2">Long-press to flag</h3>
                <p className="text-sm text-gray-400">Press and hold a log entry to flag it for investigation.</p>
              </div>
            )}

            {/* Dot indicators */}
            <div className="flex justify-center gap-2 mt-5">
              <span className={`w-1.5 h-1.5 rounded-full ${tutorialStep === 0 ? 'bg-white' : 'bg-gray-600'}`} />
              <span className={`w-1.5 h-1.5 rounded-full ${tutorialStep === 1 ? 'bg-white' : 'bg-gray-600'}`} />
            </div>

            <button
              onClick={() => {
                if (tutorialStep === 0) {
                  setTutorialStep(1);
                } else {
                  localStorage.setItem('spectyr_mobile_onboarded', 'true');
                  setShowMobileTutorial(false);
                }
              }}
              className="w-full mt-4 px-4 py-2 text-sm font-medium rounded-md bg-[#21262d] hover:bg-[#30363d] text-gray-200 border border-gray-600 transition"
            >
              {tutorialStep === 0 ? 'Next' : 'Got it'}
            </button>
          </div>
        </div>
      )}

      {noAlertsLoaded ? (
        <div className="flex flex-col items-center justify-center py-8 min-h-[320px]">
          <img src="/ghost-mascot.png" alt="Ghost" className="w-28 h-28 sm:w-40 sm:h-40 opacity-90 mb-3" />
          <p className="font-mono text-sm text-gray-400 text-center sm:text-left">&gt; Click Start Training to begin.</p>
        </div>
      ) : noSearchResults ? (
        <div className="flex flex-col items-center justify-center py-12">
          <img src="/ghost-searching.png" alt="Ghost Searching" className="w-28 h-28 sm:w-40 sm:h-40 opacity-90 mb-3" />
          <p className="font-mono text-sm text-gray-400 text-center sm:text-left">&gt; No matching logs for "{searchTerm}"</p>
        </div>
      ) : (
        <div className="overflow-x-auto overflow-y-hidden mobile-scroll-wrapper">
          <table className="w-full min-w-[800px] log-text text-left text-gray-300 border-separate border-spacing-0">
            <thead>
              <tr className="text-sm uppercase text-gray-400 tracking-wider">
                <th className="px-4 py-3 font-medium w-[100px] whitespace-nowrap">Time</th>
                <th className="px-4 py-3 font-medium w-[140px] whitespace-nowrap">Event Type</th>
                <th className="px-4 py-3 font-medium w-[110px] whitespace-nowrap">Src Type</th>
                <th className="px-4 py-3 font-medium w-[120px] whitespace-nowrap">Src IP</th>
                <th className="px-4 py-3 font-medium w-[120px] whitespace-nowrap">Dst IP</th>
                <th className="px-4 py-3 font-medium whitespace-nowrap">Message</th>
                <th className="px-4 py-3 font-medium w-10"></th>
                <th className="px-4 py-3 font-medium w-10"></th>
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

                const handleTouchStart = (alertObj) => {
                  longPressTriggered.current = false;
                  longPressTimer.current = setTimeout(() => {
                    longPressTriggered.current = true;
                    handleFlagEvent(alertObj.id, !alertObj.flagged);
                  }, 500);
                };

                const handleTouchEnd = () => {
                  if (longPressTimer.current) {
                    clearTimeout(longPressTimer.current);
                    longPressTimer.current = null;
                  }
                };

                const handleRowClick = (alertId) => {
                  if (longPressTriggered.current) {
                    longPressTriggered.current = false;
                    return;
                  }
                  toggleRow(alertId);
                };

                return (
                  <React.Fragment key={alert.id}>
                    <tr
                      className={`hover:bg-white/5 transition-colors cursor-pointer border-b border-gray-700/50 ${alert.flagged ? 'bg-white/[0.03]' : ''}`}
                      onClick={() => handleRowClick(alert.id)}
                      onTouchStart={() => handleTouchStart(alert)}
                      onTouchEnd={handleTouchEnd}
                      onTouchMove={handleTouchEnd}
                    >
                      <td className={`px-4 py-4 whitespace-nowrap border-l-4 ${
                        hintLevel === 2 && alert.label !== 'normal_traffic' ? 'border-l-blue-500' : 'border-l-transparent'
                      }`}>
                        <span className="text-gray-300">
                          {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString('en-GB', {
                            hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit'
                          }) : '—'}
                        </span>
                      </td>
                      <td className="px-4 py-4 font-medium text-gray-200 whitespace-nowrap" title={alert.event_type || '—'}>
                        {alert.event_type || '—'}
                      </td>
                      <td className="px-4 py-4 text-gray-200">
                        {alert.source_type || alert.detected_by || 'Unknown'}
                      </td>
                      <td className="px-4 py-4 text-gray-200">
                        {alert.source_ip || '—'}
                      </td>
                      <td className="px-4 py-4 text-gray-200" title={alert.destination_ip || '—'}>
                        {alert.destination_ip || '—'}
                      </td>
                      <td className="px-4 py-4 text-gray-200">
                        {alert.message || '—'}
                      </td>
                      <td className="px-4 py-4 hidden sm:table-cell">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleFlagEvent(alert.id, !alert.flagged);
                          }}
                          disabled={flaggingIds.has(alert.id)}
                          className={`w-8 h-8 flex items-center justify-center rounded transition-all ${
                            alert.flagged
                              ? 'bg-[#21262d] text-white border border-gray-500 hover:bg-[#30363d]'
                              : 'bg-gray-700 text-gray-400 hover:bg-gray-600 hover:text-gray-200'
                          } ${flaggingIds.has(alert.id) ? 'opacity-50 cursor-not-allowed' : ''}`}
                          title={alert.flagged ? 'Remove from investigation' : 'Add to investigation'}
                        >
                          <svg className="w-4 h-4" fill={alert.flagged ? 'currentColor' : 'none'} stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 21v-4m0 0V5a2 2 0 012-2h6.5l1 1H21l-3 6 3 6h-8.5l-1-1H5a2 2 0 00-2 2zm9-13.5V9" />
                          </svg>
                        </button>
                      </td>
                      <td className="px-4 py-4">
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
                    </tr>

                    {/* Expandable Details Row */}
                    <tr>
                      <td colSpan="8" className="p-0">
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
