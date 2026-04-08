import React, { useEffect, useState, useRef } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import { apiFetch } from '../api';

import CategorySelector from '../components/CategorySelector';
import IncidentReportForm from '../components/IncidentReportForm';

const GroupedAlerts = ({ resetTrigger, onHardcoreFailure, onReset, isVisible, setGroupedAlertCount }) => {
  const [groups, setGroups] = useState([]);
  const [expanded, setExpanded] = useState(null);
  const [expandedLogs, setExpandedLogs] = useState({});
  const [alertStats, setAlertStats] = useState({ total_alerts: 0, closed_alerts: 0, open_alerts: 0, severity_breakdown: { low: 0, medium: 0, high: 0, critical: 0 }, source_breakdown: {} });
  const [dashView, setDashView] = useState('total');

  const [disappearingId, setDisappearingId] = useState(null);
  const [showCategorySelector, setShowCategorySelector] = useState(false);
  const [categoryScenario, setCategoryScenario] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [submittingIds, setSubmittingIds] = useState(new Set());
  const [currentLevel, setCurrentLevel] = useState(null);
  const [gameStarted, setGameStarted] = useState(false);
  const [analystName, setAnalystName] = useState('');
  const [reportScenario, setReportScenario] = useState(null);
  const [showReportForm, setShowReportForm] = useState(false);
  const [reportSubmitting, setReportSubmitting] = useState(false);
  const [reportedScenarios, setReportedScenarios] = useState(new Set());
  const [leftView, setLeftView] = useState('categories');
  const [scenarioExpanded, setScenarioExpanded] = useState(new Set());
  const [scenarioStartTime, setScenarioStartTime] = useState(null);
  const [scenarioHistory, setScenarioHistory] = useState([]);
  const prevLevelRef = useRef(null);
  const [, setTick] = useState(0);
  const [classificationData, setClassificationData] = useState({ categoryBreakdown: {} });
  const [searchTerm, setSearchTerm] = useState('');

  const fetchGroupedAlerts = () => {
    apiFetch('/api/grouped-alerts')
      .then(res => res.json())
      .then(data => {
        const alerts = data.alerts || [];
        if (data.stats) setAlertStats(data.stats);
        setGroups(prevGroups => {
          const prevMap = new Map(prevGroups.map(g => [g.scenario_id, g.selectedAction]));

          return alerts.map(group => ({
            ...group,
            selectedAction: prevMap.get(group.scenario_id) || 'investigate'
          }));
        });
        setLastUpdated(new Date());
      })
      .catch(err => console.error('Failed to load threat patterns', err));
  };


  const fetchCurrentLevel = () => {
    apiFetch('/api/current-level')
      .then(res => res.json())
      .then(data => setCurrentLevel(data))
      .catch(err => console.error("Failed to fetch current level", err));
  };

  const fetchGameState = () => {
    apiFetch('/api/game-state')
      .then(res => res.json())
      .then(data => {
        setGameStarted(!!data.analyst_name);
        if (data.analyst_name) setAnalystName(data.analyst_name);
      })
      .catch(err => console.error("Failed to fetch game state", err));
  };

  const fetchClassificationData = () => {
    apiFetch('/api/analytics/action_history')
      .then(res => res.json())
      .then(data => {
        const actions = Array.isArray(data) ? data : [];
        const catBreakdown = {};
        actions.forEach(a => {
          const cat = a.true_category || 'Unknown';
          catBreakdown[cat] = (catBreakdown[cat] || 0) + 1;
        });
        setClassificationData({ categoryBreakdown: catBreakdown });
      })
      .catch(() => {});
  };

  useEffect(() => {
    // Clear state on reset
    setGroups([]);
    setCurrentLevel(null);
    setExpanded(null);
    setGameStarted(false);
    setClassificationData({ categoryBreakdown: {} });
    setScenarioHistory([]);
    setScenarioExpanded(new Set());
    setScenarioStartTime(null);
    prevLevelRef.current = null;

    fetchGroupedAlerts();
    fetchCurrentLevel();
    fetchGameState();
    fetchClassificationData();

    const interval = setInterval(() => {
      fetchGroupedAlerts();
      fetchCurrentLevel();
      fetchGameState();
      fetchClassificationData();
    }, 3000);

    return () => clearInterval(interval);
  }, [resetTrigger]);

  // Track scenario changes and accumulate history
  useEffect(() => {
    const newLevelNum = currentLevel?.current_level || null;
    const prev = prevLevelRef.current;

    // New level detected — push previous into history
    if (newLevelNum && prev && newLevelNum !== prev.level) {
      setScenarioHistory(h => {
        if (h.some(s => s.level === prev.level)) return h;
        return [{ ...prev, completed: true }, ...h];
      });
      setScenarioStartTime(Date.now());
    }

    // All levels completed — push last scenario into history
    if (currentLevel?.completed === true && prev && !scenarioHistory.some(s => s.level === prev.level)) {
      setScenarioHistory(h => {
        if (h.some(s => s.level === prev.level)) return h;
        return [{ ...prev, completed: true }, ...h];
      });
    }

    // First scenario
    if (newLevelNum && !prev) {
      setScenarioStartTime(Date.now());
    }

    // Update ref with current data
    if (currentLevel?.ticket_title) {
      prevLevelRef.current = {
        level: newLevelNum,
        ticket_title: currentLevel.ticket_title,
        storyline: currentLevel.storyline,
        startTime: scenarioStartTime || Date.now(),
      };
    }

    if (!currentLevel?.ticket_title && !currentLevel?.completed) {
      setScenarioStartTime(null);
    }
  }, [currentLevel]);

  // Tick every minute to update relative time
  useEffect(() => {
    const interval = setInterval(() => setTick(t => t + 1), 60000);
    return () => clearInterval(interval);
  }, []);

  const getRelativeTime = (timestamp) => {
    const diffMs = Date.now() - timestamp;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    if (diffMins < 1) return 'just now';
    if (diffMins < 60) return `${diffMins} minute${diffMins !== 1 ? 's' : ''} ago`;
    return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
  };

  const toggleGroup = (key) => {
    setExpanded(expanded === key ? null : key);
  };

  const toggleLogRow = (id) => {
    setExpandedLogs(prev => ({ ...prev, [id]: !prev[id] }));
  };

  // Clean key=value event display
  const renderCleanEventDetails = (log) => {
    const excludedKvp = [
      'event_id', 'host', 'event_type',
      'device_id', 'class_id', 'compatible_ids', 'location',
      'subject_user', 'subject_domain',
      'utc_time', 'process_guid', 'parent_command_line',
      'parent_process_id', 'integrity_level', 'hashes',
      'image', 'parent_image', 'user',
    ];

    const commonFields = [
      ['timestamp', log.timestamp ? log.timestamp.replace('T', ' ').replace(/\.\d+.*$/, '') : null],
      ['event_type', log.event_type],
      ['source_type', log.source_type || log.detected_by || 'Unknown'],
      ['host', log.hostname],
      ['src_ip', log.source_ip],
      ['user', log.user_account],
    ];

    const kvpFields = log.key_value_pairs
      ? Object.entries(log.key_value_pairs).filter(([k]) => !excludedKvp.includes(k))
      : [];

    const trimmedMessage = log.message || '';

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

  const getHighestSeverity = (breakdown) => {
    if (breakdown.critical > 0) return 'Critical';
    if (breakdown.high > 0) return 'High';
    if (breakdown.medium > 0) return 'Medium';
    return 'Low';
  };

  const handleReportSubmit = async (formData) => {
    setReportSubmitting(true);
    try {
      const res = await apiFetch('/api/reports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...formData,
          scenario_id: reportScenario.scenario_id,
          threat_category: reportScenario.analyst_category || '',
          alert_id: reportScenario.alert_id || '',
          skip_advance: true,
        }),
      });
      if (res.ok) {
        setReportedScenarios(prev => new Set(prev).add(reportScenario.scenario_id));
        setShowReportForm(false);
        setReportScenario(null);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setReportSubmitting(false);
    }
  };

  const handleCategorySelect = async (categoryId, categoryLabel, scenarioOverride) => {
    const scenario = scenarioOverride || categoryScenario;
    if (!scenario) return;

    const updatedSet = new Set(submittingIds);
    updatedSet.add(scenario.scenario_id);
    setSubmittingIds(updatedSet);

    try {
      const res = await apiFetch('/api/resume', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          analyst_action: 'classify',
          scenario_id: scenario.scenario_id,
          label: scenario.label,
          selected_category: categoryLabel
        })
      });

      const data = await res.json();

      if (data.status === 'hardcore_failure') {
        setShowCategorySelector(false);
        setCategoryScenario(null);
        onHardcoreFailure?.(data.category);
        return;
      }

      setDisappearingId(scenario.scenario_id);

      setTimeout(() => {
        setGroups(prev =>
          prev.map(g =>
            g.scenario_id === scenario.scenario_id
              ? { ...g, status: 'classified', analyst_category: categoryLabel }
              : g
          )
        );
        setDisappearingId(null);
      }, 300);

      setShowCategorySelector(false);
      setCategoryScenario(null);
    } catch (err) {
      console.error('Error classifying incident:', err);
    } finally {
      const clearedSet = new Set(submittingIds);
      clearedSet.delete(scenario.scenario_id);
      setSubmittingIds(clearedSet);
    }
  };

  const filteredGroups = groups.filter(g => g.status === 'active');

  // Parse search term for filters like level=1, status=active
  const parseSearch = (term) => {
    let levelFilter = null;
    let statusFilter = null;
    let textFilter = '';
    const parts = term.split(/\s+/);
    for (const part of parts) {
      const lower = part.toLowerCase();
      if (lower.startsWith('level=')) {
        levelFilter = parseInt(lower.split('=')[1], 10);
      } else if (lower.startsWith('status=')) {
        statusFilter = lower.split('=')[1];
      } else {
        textFilter += (textFilter ? ' ' : '') + part;
      }
    }
    return { levelFilter, statusFilter, textFilter: textFilter.toLowerCase() };
  };

  const { levelFilter, statusFilter, textFilter } = parseSearch(searchTerm);

  const matchesScenario = (title, level, isActive) => {
    if (levelFilter !== null && level !== levelFilter) return false;
    if (statusFilter === 'active' && !isActive) return false;
    if (statusFilter === 'completed' && isActive) return false;
    if (textFilter && !title.toLowerCase().includes(textFilter)) return false;
    return true;
  };

  useEffect(() => {
    if (setGroupedAlertCount) setGroupedAlertCount(filteredGroups.length);
  }, [filteredGroups.length, setGroupedAlertCount]);

  return (
    <div className="space-y-4">
      <h2 className="text-xl sm:text-2xl font-semibold text-white whitespace-nowrap mb-1">
        Alerts <span className={`font-normal ml-1 ${filteredGroups.length > 0 ? "text-gray-500" : "invisible"}`}>{filteredGroups.length || "0"}</span>
      </h2>
      <div className="relative">
        <input
          type="text"
          placeholder="Search alerts..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          maxLength={300}
          className="w-full pl-4 pr-10 py-2 rounded-md bg-transparent border border-gray-700 text-white text-sm placeholder-gray-500 focus:border-gray-500 focus:outline-none transition-colors"
        />
        {!searchTerm && (
          <svg className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        )}
        {searchTerm && (
          <button
            onClick={() => setSearchTerm('')}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        )}
      </div>

      {/* Alert Scenario */}
      <div className="mb-6">
        {(gameStarted && currentLevel && currentLevel.ticket_title) || scenarioHistory.length > 0 ? (
          <div className="bg-[#161b22] p-3 sm:p-6 rounded-xl">
            {(() => {
              const activeMatches = currentLevel && currentLevel.ticket_title && !currentLevel.completed && matchesScenario(currentLevel.ticket_title, currentLevel.current_level, true);
              const historyMatches = scenarioHistory.filter(s => matchesScenario(s.ticket_title, s.level, false));
              const noResults = searchTerm && !activeMatches && historyMatches.length === 0;

              if (noResults) return (
                <div className="flex flex-col items-center justify-center py-12">
                  <img src="/ghost-searching.png" alt="Ghost Searching" className="w-20 h-20 sm:w-28 sm:h-28 opacity-90 mb-3" />
                  <p className="font-mono text-xs sm:text-sm text-gray-400 text-center sm:text-left">&gt; No matching alerts for "{searchTerm}"</p>
                </div>
              );

              return (
            <div className="overflow-x-auto overflow-y-hidden mobile-scroll-wrapper">
              <table className="w-full min-w-[600px] log-text text-left text-gray-300 border-separate border-spacing-0">
                <thead>
                  <tr className="text-xs sm:text-sm uppercase text-gray-400 tracking-wider">
                    <th className="w-10 px-2 sm:px-4 py-3 font-medium"></th>
                    <th className="w-12 px-1 sm:px-2 py-3 font-medium text-center">Level</th>
                    <th className="px-2 sm:px-4 py-3 font-medium">Title</th>
                    <th className="px-2 sm:px-4 py-3 font-medium text-center">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {/* Active scenario */}
                  {currentLevel && currentLevel.ticket_title && !currentLevel.completed && matchesScenario(currentLevel.ticket_title, currentLevel.current_level, true) && (
                    <React.Fragment>
                      <tr
                        className="hover:bg-white/5 transition-colors cursor-pointer border-b border-gray-700/50"
                        onClick={() => setScenarioExpanded(prev => { const next = new Set(prev); next.has('active') ? next.delete('active') : next.add('active'); return next; })}
                      >
                        <td className="w-10 pl-0 pr-1 sm:pr-2 py-4">
                          <svg
                            className={`w-5 h-5 text-gray-500 hover:text-white transition-transform duration-300 ease-in-out ${
                              scenarioExpanded.has('active') ? 'rotate-180' : 'rotate-0'
                            }`}
                            fill="none" stroke="currentColor" viewBox="0 0 24 24"
                          >
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                          </svg>
                        </td>
                        <td className="w-12 px-1 sm:px-2 py-4 text-center">
                          <span className="w-6 h-6 sm:w-7 sm:h-7 rounded-full inline-flex items-center justify-center text-xs font-bold border-[3px] border-[#d1d5db] text-white">{currentLevel.current_level}</span>
                        </td>
                        <td className="px-2 sm:px-4 py-4">
                          <p className="text-sm sm:text-base font-medium text-gray-200 whitespace-nowrap">{currentLevel.ticket_title}</p>
                          {scenarioStartTime && <p className="text-xs sm:text-sm text-gray-400 mt-0.5">Created {getRelativeTime(scenarioStartTime)}</p>}
                        </td>
                        <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-center">
                          <span className="text-gray-300">Active</span>
                        </td>
                      </tr>
                      <tr>
                        <td colSpan="4" className="p-0">
                          <div className={`grid transition-all duration-300 ease-in-out ${
                            scenarioExpanded.has('active') ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
                          }`}>
                            <div className="overflow-hidden min-h-0">
                              <div className="border-t border-gray-700 px-6 py-4">
                                <p className="text-gray-300 text-sm sm:text-base leading-relaxed">{currentLevel.storyline}</p>
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    </React.Fragment>
                  )}
                  {/* Past scenarios */}
                  {scenarioHistory.filter(s => matchesScenario(s.ticket_title, s.level, false)).map((scenario) => (
                    <React.Fragment key={scenario.level}>
                      <tr
                        className="hover:bg-white/5 transition-colors cursor-pointer border-b border-gray-700/50"
                        onClick={() => setScenarioExpanded(prev => { const next = new Set(prev); next.has(scenario.level) ? next.delete(scenario.level) : next.add(scenario.level); return next; })}
                      >
                        <td className="w-10 pl-0 pr-1 sm:pr-2 py-4">
                          <svg
                            className={`w-5 h-5 text-gray-500 hover:text-white transition-transform duration-300 ease-in-out ${
                              scenarioExpanded.has(scenario.level) ? 'rotate-180' : 'rotate-0'
                            }`}
                            fill="none" stroke="currentColor" viewBox="0 0 24 24"
                          >
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                          </svg>
                        </td>
                        <td className="w-12 px-1 sm:px-2 py-4 text-center">
                          <span className="w-6 h-6 sm:w-7 sm:h-7 rounded-full inline-flex items-center justify-center text-xs font-bold border-[3px] border-[#6fa868] text-white">{scenario.level}</span>
                        </td>
                        <td className="px-2 sm:px-4 py-4">
                          <p className="text-sm sm:text-base font-medium text-gray-200 whitespace-nowrap">{scenario.ticket_title}</p>
                          <p className="text-xs sm:text-sm text-gray-400 mt-0.5">Created {getRelativeTime(scenario.startTime)}</p>
                        </td>
                        <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-center">
                          <span className="text-gray-300">Completed</span>
                        </td>
                      </tr>
                      <tr>
                        <td colSpan="4" className="p-0">
                          <div className={`grid transition-all duration-300 ease-in-out ${
                            scenarioExpanded.has(scenario.level) ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
                          }`}>
                            <div className="overflow-hidden min-h-0">
                              <div className="border-t border-gray-700 px-6 py-4">
                                <p className="text-gray-300 text-sm sm:text-base leading-relaxed">{scenario.storyline}</p>
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            </div>
              );
            })()}
          </div>
        ) : (
          <div className="bg-[#161b22] p-3 sm:p-6 rounded-xl">
            <div className="flex flex-col items-center justify-center py-4">
              <img src="/ghost_scenario.PNG" alt="Ghost Scenario" className="w-28 h-28 sm:w-40 sm:h-40 opacity-90 mb-3" />
              <p className="font-mono text-xs sm:text-sm text-gray-400 text-center sm:text-left">&gt; Start simulation to receive your first briefing.</p>
            </div>
          </div>
        )}
      </div>

        {/* Categories/Alert Types + Total Alerts/Alert Source side by side */}
        <div className="grid gap-6 grid-cols-1 md:grid-cols-2">
          {/* Left Card: Total Alerts + Alert Source */}
          <div className="flex flex-col">
            <h2 className="text-xl sm:text-2xl font-semibold text-white mb-4">
              {dashView === 'total' ? 'Total Alerts' : 'Alert Source'}
            </h2>
            <div className="bg-[#161b22] border border-gray-700 rounded-2xl p-4 sm:p-6 shadow-md flex-1">
              <div className="flex items-center justify-end mb-4">
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setDashView('total')}
                    className={`px-2 sm:px-3 py-1.5 text-xs sm:text-sm font-medium rounded-md border transition ${
                      dashView === 'total'
                        ? 'bg-[#30363d] text-white border-gray-600'
                        : 'bg-[#161b22] text-gray-400 border-gray-700 hover:text-gray-200'
                    }`}
                  >
                    Total Alerts
                  </button>
                  <button
                    onClick={() => setDashView('source')}
                    className={`px-2 sm:px-3 py-1.5 text-xs sm:text-sm font-medium rounded-md border transition ${
                      dashView === 'source'
                        ? 'bg-[#30363d] text-white border-gray-600'
                        : 'bg-[#161b22] text-gray-400 border-gray-700 hover:text-gray-200'
                    }`}
                  >
                    Alert Source
                  </button>
                </div>
              </div>
              {dashView === 'total' && (
                <div className="flex items-center justify-center gap-6">
                  <div className="relative w-36 h-36 sm:w-56 sm:h-56 flex-shrink-0 border-dashed border-2 border-gray-700 rounded-full p-2">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={(() => {
                            if (alertStats.total_alerts === 0) return [{ name: 'Empty', value: 1 }];
                            const segs = [];
                            if (alertStats.closed_alerts > 0) segs.push({ name: 'Completed', value: alertStats.closed_alerts, color: '#6fa868' });
                            if (alertStats.open_alerts > 0) segs.push({ name: 'Active', value: alertStats.open_alerts, color: '#d1d5db' });
                            return segs;
                          })()}
                          innerRadius="70%"
                          outerRadius="100%"
                          startAngle={90}
                          endAngle={-270}
                          dataKey="value"
                          stroke="none"
                        >
                          {(() => {
                            if (alertStats.total_alerts === 0) return [<Cell key="empty" fill="#374151" />];
                            const cells = [];
                            if (alertStats.closed_alerts > 0) cells.push(<Cell key="closed" fill="#6fa868" />);
                            if (alertStats.open_alerts > 0) cells.push(<Cell key="open" fill="#d1d5db" />);
                            return cells;
                          })()}
                        </Pie>
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className="text-4xl sm:text-7xl font-bold text-white">{alertStats.total_alerts}</span>
                      <span className="text-xs sm:text-base text-gray-400">Alerts</span>
                    </div>
                  </div>
                  <div className="flex flex-col gap-1 sm:gap-2 text-xs sm:text-base w-32 sm:w-40">
                    <div className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 flex-shrink-0 rounded-sm" style={{backgroundColor: '#6fa868'}} />
                      <span className="text-gray-300">Completed</span>
                      <span className="text-white font-semibold">{alertStats.closed_alerts}</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 flex-shrink-0 rounded-sm" style={{backgroundColor: '#d1d5db'}} />
                      <span className="text-gray-300">Active</span>
                      <span className="text-white font-semibold">{alertStats.open_alerts}</span>
                    </div>
                  </div>
                </div>
              )}
              {dashView === 'source' && (() => {
                const SOURCE_TYPES = [
                  { name: 'Sysmon', color: '#5a7caa' },
                  { name: 'Firewall', color: '#4f98a0' },
                  { name: 'Win Security', key: 'Windows Security', color: '#5da88a' },
                  { name: 'Proxy', color: '#a3a35c' },
                  { name: 'DNS', color: '#c28e46' },
                  { name: 'Azure AD', color: '#b26666' },
                ];
                const sb = alertStats.source_breakdown || {};
                const segments = SOURCE_TYPES.map(s => ({ ...s, value: sb[s.key || s.name] || 0 }));
                const total = segments.reduce((sum, s) => sum + s.value, 0);
                return (
                  <div className="flex items-center justify-center gap-6">
                    <div className="relative w-36 h-36 sm:w-56 sm:h-56 flex-shrink-0 border-dashed border-2 border-gray-700 rounded-full p-2">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={total > 0 ? segments.filter(s => s.value > 0) : [{ name: 'None', value: 1, color: '#374151' }]}
                            innerRadius="70%"
                            outerRadius="100%"
                            startAngle={90}
                            endAngle={-270}
                            dataKey="value"
                            stroke="none"
                          >
                            {(total > 0 ? segments.filter(s => s.value > 0).map(s => s.color) : ['#374151']).map((color, i) => (
                              <Cell key={i} fill={color} />
                            ))}
                          </Pie>
                        </PieChart>
                      </ResponsiveContainer>
                      <div className="absolute inset-0 flex flex-col items-center justify-center">
                        <span className="text-4xl sm:text-7xl font-bold text-white">{total}</span>
                        <span className="text-xs sm:text-base text-gray-400">Events</span>
                      </div>
                    </div>
                    <div className="flex flex-col gap-1 sm:gap-2 text-xs sm:text-base w-32 sm:w-40">
                      {segments.map(item => (
                        <div key={item.name} className="flex items-center gap-1.5">
                          <span className="w-2.5 h-2.5 flex-shrink-0 rounded-sm" style={{ backgroundColor: item.color }} />
                          <span className="text-gray-300 truncate">{item.name}</span>
                          <span className="text-white font-semibold">{item.value}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })()}
            </div>
          </div>

          {/* Right Card: Categories + Alert Types */}
          <div className="flex flex-col">
            <h2 className="text-xl sm:text-2xl font-semibold text-white mb-4">
              {leftView === 'categories' ? 'Categories' : 'Alert Types'}
            </h2>
            <div className="bg-[#161b22] border border-gray-700 rounded-2xl p-4 sm:p-6 shadow-md flex-1">
              <div className="flex items-center justify-end mb-4">
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setLeftView('categories')}
                    className={`px-2 sm:px-3 py-1.5 text-xs sm:text-sm font-medium rounded-md border transition ${
                      leftView === 'categories'
                        ? 'bg-[#30363d] text-white border-gray-600'
                        : 'bg-[#161b22] text-gray-400 border-gray-700 hover:text-gray-200'
                    }`}
                  >
                    Categories
                  </button>
                  <button
                    onClick={() => setLeftView('types')}
                    className={`px-2 sm:px-3 py-1.5 text-xs sm:text-sm font-medium rounded-md border transition ${
                      leftView === 'types'
                        ? 'bg-[#30363d] text-white border-gray-600'
                        : 'bg-[#161b22] text-gray-400 border-gray-700 hover:text-gray-200'
                    }`}
                  >
                    Alert Types
                  </button>
                </div>
              </div>
              {leftView === 'categories' && (() => {
                const ALL_CATEGORIES = [
                  { name: 'Malware', key: 'Malware', color: '#5a7caa' },
                  { name: 'Phishing', key: 'Phishing', color: '#4f98a0' },
                  { name: 'Defense Evasion', key: 'Defense Evasion', color: '#5da88a' },
                  { name: 'Lateral Movement', key: 'Lateral Movement', color: '#6fa868' },
                  { name: 'Command & Control', key: 'Command & Control', color: '#a3a35c' },
                  { name: 'Brute Force', key: 'Brute Force', color: '#c28e46' },
                  { name: 'Data Exfiltration', key: 'Data Exfiltration', color: '#c4755a' },
                  { name: 'Insider Threat', key: 'Insider Threat', color: '#b26666' },
                  { name: 'False Positive', key: 'False Positive', color: '#9ca3af' },
                ];
                const cb = classificationData.categoryBreakdown;
                const segments = ALL_CATEGORIES.map(c => ({ ...c, value: cb[c.key] || 0 })).filter(s => s.value > 0);
                const total = segments.reduce((sum, s) => sum + s.value, 0);
                const chartData = total > 0 ? segments : [{ name: 'None', value: 1, color: '#374151' }];
                return (
                  <div className="flex items-center justify-center gap-6">
                    <div className="relative w-36 h-36 sm:w-56 sm:h-56 flex-shrink-0 border-dashed border-2 border-gray-700 rounded-full p-2">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie data={chartData} innerRadius="70%" outerRadius="100%" startAngle={90} endAngle={-270} dataKey="value" stroke="none">
                            {chartData.map((s, i) => <Cell key={i} fill={s.color} />)}
                          </Pie>
                        </PieChart>
                      </ResponsiveContainer>
                      <div className="absolute inset-0 flex flex-col items-center justify-center">
                        <span className="text-4xl sm:text-7xl font-bold text-white">{total}</span>
                        <span className="text-xs sm:text-base text-gray-400">Total</span>
                      </div>
                    </div>
                    <div className="flex flex-col gap-1 sm:gap-2 text-xs sm:text-base w-32 sm:w-40">
                      {segments.map(item => (
                        <div key={item.name} className="flex items-center gap-1.5">
                          <span className="w-2.5 h-2.5 flex-shrink-0 rounded-sm" style={{ backgroundColor: item.color }} />
                          <span className="text-gray-300 truncate">{item.name}</span>
                          <span className="text-white font-semibold">{item.value}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })()}
              {leftView === 'types' && (
                <div className="flex items-center justify-center gap-6">
                  <div className="relative w-36 h-36 sm:w-56 sm:h-56 flex-shrink-0 border-dashed border-2 border-gray-700 rounded-full p-2">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={(() => {
                            const sb = alertStats.severity_breakdown;
                            const segments = [
                              { name: 'Low', value: sb.low, color: '#6fa868' },
                              { name: 'Medium', value: sb.medium, color: '#a3a35c' },
                              { name: 'High', value: sb.high, color: '#c28e46' },
                              { name: 'Critical', value: sb.critical, color: '#b26666' },
                            ].filter(s => s.value > 0);
                            return segments.length > 0 ? segments : [{ name: 'None', value: 1, color: '#374151' }];
                          })()}
                          innerRadius="70%"
                          outerRadius="100%"
                          startAngle={90}
                          endAngle={-270}
                          dataKey="value"
                          stroke="none"
                        >
                          {(() => {
                            const sb = alertStats.severity_breakdown;
                            const segments = [
                              { name: 'Low', value: sb.low, color: '#6fa868' },
                              { name: 'Medium', value: sb.medium, color: '#a3a35c' },
                              { name: 'High', value: sb.high, color: '#c28e46' },
                              { name: 'Critical', value: sb.critical, color: '#b26666' },
                            ].filter(s => s.value > 0);
                            const colors = segments.length > 0 ? segments.map(s => s.color) : ['#374151'];
                            return colors.map((color, i) => <Cell key={i} fill={color} />);
                          })()}
                        </Pie>
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className="text-4xl sm:text-7xl font-bold text-white">
                        {alertStats.severity_breakdown.critical + alertStats.severity_breakdown.high + alertStats.severity_breakdown.medium + alertStats.severity_breakdown.low}
                      </span>
                      <span className="text-xs sm:text-base text-gray-400">Alerts</span>
                    </div>
                  </div>
                  <div className="flex flex-col gap-1 sm:gap-2 text-xs sm:text-base w-32 sm:w-40">
                    {[
                      { label: 'Low', value: alertStats.severity_breakdown.low, color: '#6fa868' },
                      { label: 'Medium', value: alertStats.severity_breakdown.medium, color: '#a3a35c' },
                      { label: 'High', value: alertStats.severity_breakdown.high, color: '#c28e46' },
                      { label: 'Critical', value: alertStats.severity_breakdown.critical, color: '#b26666' },
                    ].map(item => (
                      <div key={item.label} className="flex items-center gap-1.5">
                        <span className="w-2.5 h-2.5 flex-shrink-0 rounded-sm" style={{ backgroundColor: item.color }} />
                        <span className="text-gray-300">{item.label}</span>
                        <span className="text-white font-semibold">{item.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

      {filteredGroups.length === 0 && (
        <div className="mt-6">
          <h2 className="text-xl sm:text-2xl font-semibold text-white mb-4">Notable Event</h2>
          <div className="flex flex-col items-center justify-center py-8 min-h-[320px]">
            <img src="/ghost_incident.png" alt="Ghost Analyzing" className="w-28 h-28 sm:w-40 sm:h-40 opacity-90 mb-3" />
            <p className="font-mono text-xs sm:text-sm text-gray-400 text-center sm:text-left">&gt; No alerts detected yet. Alerts will appear here automatically.</p>
          </div>
        </div>
      )}

      <div className="divide-y divide-gray-700">
      {filteredGroups.map(group => {
        const groupKey = `${group.scenario_id}_${group.threat_pattern}`;
        return (
          <div
            key={groupKey}
            className={`py-4 first:pt-0 last:pb-0 transition-all duration-300 ease-in-out ${
              disappearingId === group.scenario_id ? 'opacity-0 scale-95' : 'opacity-100'
            }`}
          >
            <div className="flex justify-between items-start">
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-2">
                  <h2 className="text-xl sm:text-2xl font-semibold text-white">Notable Event</h2>
                  <span className="text-gray-400 text-sm">{group.log_count} {group.log_count === 1 ? 'Event' : 'Events'}</span>
                </div>
                {group.status === 'classified' && group.analyst_category && (
                  <p className="text-sm text-gray-400 mt-1">
                    Classified as: <span className="text-blue-400 font-medium">{group.analyst_category}</span>
                    {group.category && group.analyst_category === group.category && (
                      <span className="text-emerald-400 ml-2">Correct!</span>
                    )}
                    {group.category && group.analyst_category !== group.category && (
                      <span className="text-red-400 ml-2">Incorrect (was {group.category})</span>
                    )}
                  </p>
                )}
              </div>
            </div>

                <div className="mt-4">
                  <div className="overflow-x-auto overflow-y-hidden mobile-scroll-wrapper">
                    <table className="w-full min-w-[1000px] sm:min-w-[1100px] table-fixed log-text text-left text-gray-300 border-separate border-spacing-0">
                      <thead>
                        <tr className="text-xs sm:text-sm uppercase text-gray-400 tracking-wider">
                          <th className="w-10 px-2 py-3"></th>
                          <th className="px-2 sm:px-4 py-3 font-medium w-[100px] whitespace-nowrap">Alert ID</th>
                          <th className="px-2 sm:px-4 py-3 font-medium w-[100px] sm:w-[130px] whitespace-nowrap">Time</th>
                          <th className="px-2 sm:px-4 py-3 font-medium w-[160px] sm:w-[240px] whitespace-nowrap">Event Type</th>
                          <th className="px-2 sm:px-4 py-3 font-medium w-[110px] sm:w-[170px] whitespace-nowrap">Src Type</th>
                          <th className="px-2 sm:px-4 py-3 font-medium w-[120px] sm:w-[160px] whitespace-nowrap">Src IP</th>
                          <th className="px-2 sm:px-4 py-3 font-medium w-[120px] sm:w-[160px] whitespace-nowrap">Dst IP</th>
                          <th className="px-2 sm:px-4 py-3 font-medium w-[240px] sm:w-auto whitespace-nowrap">Message</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-700">
                        {group.logs.map((log) => (
                          <React.Fragment key={log.id}>
                            <tr
                              className="hover:bg-white/5 transition-colors cursor-pointer border-b border-gray-700/50"
                              onClick={() => toggleLogRow(log.id)}
                            >
                              <td className="px-2 py-4">
                                <svg
                                  className={`w-5 h-5 text-gray-500 hover:text-white transition-transform duration-300 ease-in-out ${
                                    expandedLogs[log.id] ? 'rotate-180' : 'rotate-0'
                                  }`}
                                  fill="none"
                                  stroke="currentColor"
                                  viewBox="0 0 24 24"
                                >
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                </svg>
                              </td>
                              <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-gray-400">
                                {log.alert_id || '—'}
                              </td>
                              <td className="px-2 sm:px-4 py-4 whitespace-nowrap">
                                <span className="text-gray-300">
                                  {new Date(log.timestamp).toLocaleTimeString('en-GB', {
                                    hour12: false,
                                    hour: '2-digit',
                                    minute: '2-digit',
                                    second: '2-digit'
                                  })}
                                </span>
                              </td>
                              <td className="px-2 sm:px-4 py-4 font-medium text-gray-200 sm:whitespace-nowrap">
                                {log.event_type}
                              </td>
                              <td className="px-2 sm:px-4 py-4 text-gray-200 sm:whitespace-nowrap">
                                {log.source_type || 'Unknown'}
                              </td>
                              <td className="px-2 sm:px-4 py-4 text-gray-200 sm:whitespace-nowrap">
                                {log.source_ip || '—'}
                              </td>
                              <td className="px-2 sm:px-4 py-4 text-gray-200 sm:whitespace-nowrap">
                                {log.destination_ip || '—'}
                              </td>
                              <td className="px-2 sm:px-4 py-4 text-gray-200 truncate" title={log.message || '—'}>
                                {log.message || '—'}
                              </td>
                            </tr>
                            <tr>
                              <td colSpan="8" className="p-0">
                                <div
                                  className={`grid transition-all duration-300 ease-in-out ${
                                    expandedLogs[log.id] ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
                                  }`}
                                >
                                  <div className="overflow-hidden min-h-0">
                                    <div className="border-t border-gray-700 px-6 py-4">
                                      {renderCleanEventDetails(log)}
                                    </div>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          </React.Fragment>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="mt-4 flex items-center justify-end gap-3">
                  <button
                    disabled={submittingIds.has(group.scenario_id)}
                    onClick={() => {
                      setCategoryScenario(group);
                      setShowCategorySelector(true);
                    }}
                    className={`inline-flex items-center gap-2 px-2 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm font-medium rounded-md border transition focus:outline-none focus:ring-2 focus:ring-gray-500 ${
                      submittingIds.has(group.scenario_id)
                        ? 'bg-[#161b22] text-gray-500 border-gray-700 cursor-not-allowed'
                        : 'bg-[#21262d] hover:bg-[#30363d] text-gray-200 border-gray-600'
                    }`}
                  >
                    Classify
                  </button>
                  <button
                    disabled={submittingIds.has(group.scenario_id)}
                    onClick={() => handleCategorySelect('false_positive', 'False Positive', group)}
                    className={`inline-flex items-center gap-2 px-2 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm font-medium rounded-md border transition focus:outline-none focus:ring-2 focus:ring-gray-500 ${
                      submittingIds.has(group.scenario_id)
                        ? 'bg-[#161b22] text-gray-500 border-gray-700 cursor-not-allowed'
                        : 'bg-[#21262d] hover:bg-[#30363d] text-gray-200 border-gray-600'
                    }`}
                  >
                    False Positive
                  </button>
                  <button
                    disabled={reportedScenarios.has(group.scenario_id)}
                    onClick={() => {
                      setReportScenario(group);
                      setShowReportForm(true);
                    }}
                    className={`inline-flex items-center justify-center gap-2 min-w-[6.5rem] sm:min-w-[7.5rem] px-2 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm font-medium rounded-md border transition focus:outline-none focus:ring-2 focus:ring-gray-500 ${
                      reportedScenarios.has(group.scenario_id)
                        ? 'bg-[#161b22] text-gray-500 border-gray-700 cursor-not-allowed'
                        : 'bg-[#21262d] hover:bg-[#30363d] text-gray-200 border-gray-600'
                    }`}
                  >
                    {reportedScenarios.has(group.scenario_id) ? 'Reported' : 'Create Report'}
                  </button>
                </div>
          </div>
        );
      })}
      </div>

      {showCategorySelector && categoryScenario && (
        <CategorySelector
          scenarioInfo={categoryScenario}
          onSelect={handleCategorySelect}
          onCancel={() => {
            setShowCategorySelector(false);
            setCategoryScenario(null);
          }}
        />
      )}

      {showReportForm && reportScenario && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div
            className="absolute inset-0 bg-black/70"
            onClick={() => { setShowReportForm(false); setReportScenario(null); }}
          />
          <div className="relative bg-[#161b22] border border-gray-700 rounded-xl p-6 w-full max-w-2xl mx-4 shadow-2xl max-h-[90vh] overflow-y-auto">
            <h2 className="text-xl sm:text-2xl font-semibold text-white mb-4">Incident Report</h2>
            <IncidentReportForm
              initialData={{
                title: currentLevel?.ticket_title || '',
                description: currentLevel?.storyline || '',
                severity: getHighestSeverity(reportScenario.severity_breakdown),
                affected_hosts: [...new Set(reportScenario.logs.map(l => l.hostname).filter(Boolean))].join(', '),
                scenario_id: reportScenario.scenario_id,
              }}
              onSubmit={handleReportSubmit}
              onCancel={() => { setShowReportForm(false); setReportScenario(null); }}
              submitting={reportSubmitting}
              inline
            />
          </div>
        </div>
      )}

    </div>
  );
};

export default GroupedAlerts;
