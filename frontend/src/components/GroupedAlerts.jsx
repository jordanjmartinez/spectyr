import React, { useEffect, useState, useRef } from 'react';
import { createPortal } from 'react-dom';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';
import { apiFetch } from '../api';

import CategorySelector from '../components/CategorySelector';
import ClassificationSelector from '../components/ClassificationSelector';
import IncidentReportForm from '../components/IncidentReportForm';
import SeverityPill from '../components/SeverityPill';
import TriageFeedback from '../components/TriageFeedback';

const PieTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  const { name, value } = payload[0];
  if (name === 'Empty' || name === 'None') return null;
  return (
    <div style={{ backgroundColor: '#161b22', border: '1px solid #30363d', borderRadius: '8px', padding: '6px 12px', fontSize: '13px', whiteSpace: 'nowrap' }}>
      <span style={{ color: '#e5e7eb' }}>{name}: <span style={{ color: '#fff', fontWeight: 600 }}>{value}</span></span>
    </div>
  );
};

const GroupedAlerts = ({ resetTrigger, onHardcoreFailure, onReset, isVisible, setGroupedAlertCount }) => {
  const [groups, setGroups] = useState([]);
  const [expanded, setExpanded] = useState(null);
  const [expandedLogs, setExpandedLogs] = useState({});
  const [alertStats, setAlertStats] = useState({ total_alerts: 0, closed_alerts: 0, open_alerts: 0, severity_breakdown: { low: 0, medium: 0, high: 0, critical: 0 }, source_breakdown: {} });
  const [dashView, setDashView] = useState('total');

  const [disappearingId, setDisappearingId] = useState(null);
  const [showCategorySelector, setShowCategorySelector] = useState(false);
  const [categoryScenario, setCategoryScenario] = useState(null);
  const [showClassificationSelector, setShowClassificationSelector] = useState(false);
  const [classificationScenario, setClassificationScenario] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [submittingIds, setSubmittingIds] = useState(new Set());
  const [currentLevel, setCurrentLevel] = useState(null);
  const [gameStarted, setGameStarted] = useState(false);
  const [gameMode, setGameMode] = useState('training');
  const [analystName, setAnalystName] = useState('');
  const [feedback, setFeedback] = useState(null);
  const [reportScenario, setReportScenario] = useState(null);
  const [showReportForm, setShowReportForm] = useState(false);
  const [reportSubmitting, setReportSubmitting] = useState(false);
  const [reportedScenarios, setReportedScenarios] = useState(new Set());
  const [leftView, setLeftView] = useState('types');
  const [scenarioExpanded, setScenarioExpanded] = useState(new Set());
  const [groupExpanded, setGroupExpanded] = useState({});
  const [openDropdownId, setOpenDropdownId] = useState(null);
  const [dropdownPos, setDropdownPos] = useState(null);
  const dropdownRef = useRef(null);
  const menuRef = useRef(null);

  useEffect(() => {
    if (!openDropdownId) return;
    const handleMouseDown = (e) => {
      const insideButton = dropdownRef.current?.contains(e.target);
      const insideMenu = menuRef.current?.contains(e.target);
      if (!insideButton && !insideMenu) {
        setOpenDropdownId(null);
      }
    };
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') setOpenDropdownId(null);
    };
    const handleReposition = () => setOpenDropdownId(null);
    document.addEventListener('mousedown', handleMouseDown);
    document.addEventListener('keydown', handleKeyDown);
    window.addEventListener('scroll', handleReposition, true);
    window.addEventListener('resize', handleReposition);
    return () => {
      document.removeEventListener('mousedown', handleMouseDown);
      document.removeEventListener('keydown', handleKeyDown);
      window.removeEventListener('scroll', handleReposition, true);
      window.removeEventListener('resize', handleReposition);
    };
  }, [openDropdownId]);
  const [scenarioStartTime, setScenarioStartTime] = useState(null);
  const [scenarioHistory, setScenarioHistory] = useState([]);
  const prevLevelRef = useRef(null);
  const [, setTick] = useState(0);
  const [classificationData, setClassificationData] = useState({ categoryBreakdown: {} });
  const [searchTerm, setSearchTerm] = useState('');
  const [filterActive, setFilterActive] = useState(true);
  const [filterCompleted, setFilterCompleted] = useState(false);
  const [showFilterDropdown, setShowFilterDropdown] = useState(false);
  const [fadingOutScenarioLevel, setFadingOutScenarioLevel] = useState(null);
  const [highlightedScenarioId, setHighlightedScenarioId] = useState(null);

  const scrollToNotableEvent = (group) => {
    if (!group) return;
    const groupKey = `${group.scenario_id}_${group.threat_pattern}`;
    setGroupExpanded(prev => ({ ...prev, [groupKey]: true }));
    setHighlightedScenarioId(group.scenario_id);
    setTimeout(() => {
      const el = document.getElementById(`notable-event-${group.scenario_id}`);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, 80);
    setTimeout(() => setHighlightedScenarioId(null), 1600);
  };

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
        if (data.game_mode) setGameMode(data.game_mode);
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
    setFeedback(null);
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

  // Sync scenario history from backend and track active scenario timing
  useEffect(() => {
    const newLevelNum = currentLevel?.current_level || null;
    const prev = prevLevelRef.current;

    // Sync history from backend — this is the source of truth
    if (currentLevel?.scenario_history) {
      const backendHistory = currentLevel.scenario_history.map(s => ({
        ...s,
        completed: true,
        startTime: s.startTime || null,
      }));
      setScenarioHistory(prevHistory => {
        // Fade out newly completed scenarios if filter is off
        if (!filterCompleted && backendHistory.length > prevHistory.length) {
          const newEntry = backendHistory[backendHistory.length - 1];
          if (newEntry) {
            setFadingOutScenarioLevel(newEntry.level);
            setTimeout(() => setFadingOutScenarioLevel(null), 700);
          }
        }
        return backendHistory;
      });
    }

    // Track active scenario start time from backend
    if (newLevelNum && prev && newLevelNum !== prev.level) {
      setScenarioStartTime(currentLevel?.scenario_start_time || Date.now());
    }
    if (newLevelNum && !prev) {
      setScenarioStartTime(currentLevel?.scenario_start_time || Date.now());
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
    if (!timestamp) return '';
    const ms = typeof timestamp === 'number' ? timestamp : new Date(timestamp).getTime();
    if (!Number.isFinite(ms)) return '';
    const diffMs = Date.now() - ms;
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

      // Training mode: immediate triage feedback (Hardcore defers to end-of-run).
      // data carries the verdict so no extra round-trip is needed.
      if (gameMode !== 'hardcore') {
        setFeedback({
          scenario_label: scenario.label,
          ticket_title: scenario.ticket_title || scenario.level_name || '',
          selected_category: data.selected_category ?? categoryLabel,
          correct_category: data.correct_category,
          correct: !!data.category_correct,
        });
      }
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
    <div>
      <div className="flex flex-row items-center justify-between mb-3 gap-2 sm:gap-3">
        <h2 className="text-xl sm:text-2xl font-semibold text-white whitespace-nowrap">
          Alerts <span className={`font-normal ml-1 ${filteredGroups.length > 0 ? "text-gray-500" : "invisible"}`}>{filteredGroups.length || "0"}</span>
        </h2>
        <div className="flex items-center gap-2 sm:gap-3">
          <div className="relative">
            <button
              onClick={() => setShowFilterDropdown(!showFilterDropdown)}
              className="inline-flex items-center justify-center gap-1 px-2 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm font-medium rounded-md border transition bg-[#21262d] hover:bg-[#30363d] text-gray-200 border-gray-600 focus:outline-none focus:ring-2 focus:ring-gray-500"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z" />
              </svg>
              Filter
            </button>
            {showFilterDropdown && (
              <>
                <div
                  className="fixed inset-0 z-10"
                  onClick={() => setShowFilterDropdown(false)}
                />
                <div className="absolute right-0 top-full mt-1 z-20 bg-[#161b22] border border-gray-700 rounded py-1 flex flex-col min-w-[100px] sm:min-w-[120px]">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setFilterActive(!filterActive);
                    }}
                    className="flex items-center gap-2 text-left px-2.5 sm:px-3 py-1 sm:py-1.5 text-xs sm:text-sm hover:bg-gray-700 transition text-gray-400"
                  >
                    <span className={`w-3 h-3 sm:w-3.5 sm:h-3.5 rounded border ${filterActive ? 'bg-gray-300 border-gray-300' : 'border-gray-600'}`} />
                    Active
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setFilterCompleted(!filterCompleted);
                    }}
                    className="flex items-center gap-2 text-left px-2.5 sm:px-3 py-1 sm:py-1.5 text-xs sm:text-sm hover:bg-gray-700 transition text-gray-400"
                  >
                    <span className={`w-3 h-3 sm:w-3.5 sm:h-3.5 rounded border ${filterCompleted ? 'bg-gray-300 border-gray-300' : 'border-gray-600'}`} />
                    Completed
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
      <div className="relative">
        <input
          type="text"
          placeholder="Search alerts..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          maxLength={300}
          className="w-full pl-4 pr-10 py-2 rounded-md bg-[#0d1117] border border-gray-700 text-white text-sm placeholder-gray-400 focus:border-[#5882b4] focus:outline-none transition-colors"
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
      <div className="mt-3 mb-6">
        {(gameStarted && (Array.isArray(currentLevel?.active_scenarios) && currentLevel.active_scenarios.length > 0)) || scenarioHistory.length > 0 ? (
          <div
            className="p-3 sm:p-6 rounded-xl"
            style={{
              background: 'linear-gradient(#161b22, #161b22) padding-box, linear-gradient(to bottom, rgba(88,130,180,0.3), transparent) border-box',
              border: '1px solid transparent',
              boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05)',
            }}
          >
            {(() => {
              const allActive = Array.isArray(currentLevel?.active_scenarios) ? currentLevel.active_scenarios : [];
              const activeMatches = filterActive && !currentLevel?.completed
                ? allActive.filter(s => matchesScenario(s.ticket_title || '', s.level, true))
                : [];
              const historyMatches = filterCompleted ? scenarioHistory.filter(s => matchesScenario(s.ticket_title, s.level, false)) : [];
              const noResults = (searchTerm || !filterActive || !filterCompleted) && activeMatches.length === 0 && historyMatches.length === 0;

              if (noResults) return (
                <div className="flex flex-col items-center justify-center py-12">
                  <svg
                    className="w-12 h-12 sm:w-16 sm:h-16 text-gray-500 mb-3"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
                  </svg>
                  <p className="font-mono text-xs sm:text-sm text-gray-400 text-center sm:text-left">&gt;<span className="animate-blink">|</span> {searchTerm ? `No matching alerts for "${searchTerm}"` : 'No alerts match the current filter'}</p>
                </div>
              );

              return (
            <div className="overflow-x-auto overflow-y-hidden mobile-scroll-wrapper">
              <table className="w-full min-w-[600px] log-text text-left text-gray-300 border-separate border-spacing-0">
                <thead>
                  <tr className="text-xs sm:text-sm uppercase text-gray-400 tracking-wider">
                    <th className="w-10 px-2 sm:px-4 py-3 font-medium border-b border-gray-600"></th>
                    <th className="w-12 px-1 sm:px-2 py-3 font-medium border-b border-gray-600"></th>
                    <th className="px-2 sm:px-4 py-3 font-medium border-b border-gray-600">Ticket</th>
                    <th className="w-[110px] sm:w-[140px] px-2 sm:px-4 py-3 font-medium whitespace-nowrap text-center border-b border-gray-600">Severity</th>
                    <th className="w-[110px] sm:w-[140px] px-2 sm:px-4 py-3 font-medium whitespace-nowrap text-center border-b border-gray-600">Assigned</th>
                    <th className="w-24 sm:w-28 px-2 sm:px-4 py-3 font-medium text-center border-b border-gray-600">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {/* Active scenarios (concurrent rolling queue) */}
                  {activeMatches.map((scenario) => {
                    const key = `active-${scenario.scenario_id || scenario.level}`;
                    const isExpanded = scenarioExpanded.has(key);
                    return (
                      <React.Fragment key={key}>
                        <tr
                          className="hover:bg-white/5 transition-colors cursor-pointer border-b border-gray-700/50"
                          onClick={() => setScenarioExpanded(prev => { const next = new Set(prev); next.has(key) ? next.delete(key) : next.add(key); return next; })}
                        >
                          <td className="w-10 pl-0 pr-1 sm:pr-2 py-4">
                            <svg
                              className={`w-5 h-5 text-gray-500 hover:text-white transition-transform duration-300 ease-in-out ${
                                isExpanded ? 'rotate-180' : 'rotate-0'
                              }`}
                              fill="none" stroke="currentColor" viewBox="0 0 24 24"
                            >
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                            </svg>
                          </td>
                          <td className="w-12 px-1 sm:px-2 py-4 text-center">
                            <svg className="w-5 h-5 sm:w-6 sm:h-6 inline-block text-[#d1d5db]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                            </svg>
                          </td>
                          <td className="px-2 sm:px-4 py-4">
                            <p className="text-sm sm:text-base font-medium text-gray-200 whitespace-nowrap">{scenario.ticket_title}</p>
                            {(() => {
                              const match = groups.find(g => g.scenario_id === scenario.scenario_id);
                              const alertId = match?.alert_id;
                              if (!alertId && !scenario.startTime) return null;
                              return (
                                <p className="text-xs sm:text-sm text-gray-400 mt-0.5">
                                  {alertId && (
                                    <button
                                      type="button"
                                      onClick={(e) => { e.stopPropagation(); scrollToNotableEvent(match); }}
                                      className="text-[#5882b4] hover:text-[#7aa4d4] hover:underline font-medium transition-colors"
                                    >{alertId}</button>
                                  )}
                                  {alertId && scenario.startTime && <span className="text-gray-600 mx-2">·</span>}
                                  {scenario.startTime && `Created ${getRelativeTime(scenario.startTime)}`}
                                </p>
                              );
                            })()}
                          </td>
                          <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-center">
                            <SeverityPill level={groups.find(g => g.scenario_id === scenario.scenario_id)?.group_severity} />
                          </td>
                          <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-center">
                            <span className="text-gray-300">{analystName || 'Unassigned'}</span>
                          </td>
                          <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-center">
                            <span className="text-gray-300">Active</span>
                          </td>
                        </tr>
                        <tr>
                          <td colSpan="6" className="p-0">
                            <div className={`grid transition-all duration-300 ease-in-out ${
                              isExpanded ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
                            }`}>
                              <div className="overflow-hidden min-h-0">
                                <div style={{ height: '1px', background: 'linear-gradient(to right, rgba(88,130,180,0.3), transparent)' }} />
                                <div className="px-6 py-4">
                                  <p className="text-gray-300 text-sm sm:text-base leading-relaxed">{scenario.storyline}</p>
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      </React.Fragment>
                    );
                  })}
                  {/* Past scenarios */}
                  {historyMatches.map((scenario) => (
                    <React.Fragment key={scenario.level}>
                      <tr
                        className={`hover:bg-white/5 cursor-pointer border-b border-gray-700/50 transition-all duration-700 ${fadingOutScenarioLevel === scenario.level ? 'opacity-0' : 'opacity-100'}`}
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
                          <svg className="w-5 h-5 sm:w-6 sm:h-6 inline-block text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                          </svg>
                        </td>
                        <td className="px-2 sm:px-4 py-4">
                          <p className="text-sm sm:text-base font-medium text-gray-200 whitespace-nowrap">{scenario.ticket_title}</p>
                          {(() => {
                            const match = groups.find(g => g.scenario_id === scenario.scenario_id);
                            const alertId = match?.alert_id;
                            if (!alertId && !scenario.startTime) return null;
                            return (
                              <p className="text-xs sm:text-sm text-gray-400 mt-0.5">
                                {alertId && <span className="text-[#5882b4] font-medium">{alertId}</span>}
                                {alertId && scenario.startTime && <span className="text-gray-600 mx-2">·</span>}
                                {scenario.startTime && `Created ${getRelativeTime(scenario.startTime)}`}
                              </p>
                            );
                          })()}
                        </td>
                        <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-center">
                          <SeverityPill level={groups.find(g => g.scenario_id === scenario.scenario_id)?.group_severity} />
                        </td>
                        <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-center">
                          <span className="text-gray-300">{analystName || 'Unassigned'}</span>
                        </td>
                        <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-center">
                          <span className="text-gray-300">Completed</span>
                        </td>
                      </tr>
                      <tr>
                        <td colSpan="6" className="p-0">
                          <div className={`grid transition-all duration-300 ease-in-out ${
                            scenarioExpanded.has(scenario.level) ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
                          }`}>
                            <div className="overflow-hidden min-h-0">
                              <div style={{ height: '1px', background: 'linear-gradient(to right, rgba(88,130,180,0.3), transparent)' }} />
                              <div className="px-6 py-4">
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
          <div
            className="p-3 sm:p-6 rounded-xl"
            style={{
              background: 'linear-gradient(#161b22, #161b22) padding-box, linear-gradient(to bottom, rgba(88,130,180,0.3), transparent) border-box',
              border: '1px solid transparent',
              boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05)',
            }}
          >
            <div className="flex flex-col items-center justify-center py-4">
              <img src="/ghost_scenario.PNG" alt="Ghost Scenario" className="w-28 h-28 sm:w-40 sm:h-40 opacity-90 mb-3" />
              <p className="font-mono text-xs sm:text-sm text-gray-400 text-center sm:text-left">&gt;<span className="animate-blink">|</span> Start simulation to receive your first briefing.</p>
            </div>
          </div>
        )}
      </div>

        {/* Categories/Alert Types + Total Alerts/Alert Source side by side */}
        <div className="grid gap-6 grid-cols-1 md:grid-cols-2">
          {/* Left Card: Total Alerts + Alert Source */}
          <div className="flex flex-col">
            <h2 className="text-xl sm:text-2xl font-semibold text-white mb-4">
              {dashView === 'total' ? 'Alert Queue' : 'Alert Source'}
            </h2>
            <div className="rounded-2xl p-4 sm:p-6 flex-1" style={{ background: 'linear-gradient(#161b22, #161b22) padding-box, linear-gradient(to bottom, rgba(88,130,180,0.3), transparent) border-box', border: '1px solid transparent', boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05)' }}>
              {(() => {
                const SOURCE_TYPES = [
                  { name: 'DNS', color: '#5dc8ec' },
                  { name: 'Firewall', color: '#2a96b8' },
                  { name: 'Win Security', key: 'Windows Security', color: '#4d7099' },
                  { name: 'Sysmon', color: '#3a5fb8' },
                  { name: 'Azure', key: 'Azure AD', color: '#1d3370' },
                  { name: 'Proxy', color: '#6b54b8' },
                  { name: 'Defender', color: '#7ba7cc' },
                  { name: 'Veeam', color: '#2a6b7a' },
                ];
                const sb = alertStats.source_breakdown || {};
                const sourceSegments = SOURCE_TYPES.map(s => ({ ...s, value: sb[s.key || s.name] || 0 }));
                const sourceTotal = sourceSegments.reduce((sum, s) => sum + s.value, 0);
                return (
                  <div className="flex flex-col gap-4">
                    {/* Toggle buttons */}
                    <div className="flex items-center justify-start gap-2">
                      <button
                        onClick={() => setDashView('total')}
                        className={`px-2 sm:px-3 py-1.5 min-w-[5rem] sm:min-w-[8rem] text-xs sm:text-sm font-medium rounded-md border transition ${
                          dashView === 'total'
                            ? 'bg-[#5882b4] text-white border-[#5882b4]'
                            : 'bg-[#161b22] text-gray-400 border-gray-700 hover:text-gray-200'
                        }`}
                      >
                        <span className="sm:hidden">Queue</span>
                        <span className="hidden sm:inline">Alert Queue</span>
                      </button>
                      <button
                        onClick={() => setDashView('source')}
                        className={`px-2 sm:px-3 py-1.5 min-w-[5rem] sm:min-w-[8rem] text-xs sm:text-sm font-medium rounded-md border transition ${
                          dashView === 'source'
                            ? 'bg-[#5882b4] text-white border-[#5882b4]'
                            : 'bg-[#161b22] text-gray-400 border-gray-700 hover:text-gray-200'
                        }`}
                      >
                        <span className="sm:hidden">Source</span>
                        <span className="hidden sm:inline">Alert Source</span>
                      </button>
                    </div>
                    {/* Chart + Legend */}
                    <div className="flex flex-col items-center gap-4 sm:gap-6 lg:flex-row-reverse lg:items-center">
                      <div className="flex-shrink-0 flex items-center lg:pr-2 xl:pr-6">
                        {dashView === 'total' && (() => {
                          const queueLength = currentLevel?.queue_length ?? 0;
                          const resolvedCount = currentLevel?.resolved_count ?? 0;
                          const activeCount = (currentLevel?.active_scenarios || []).length;
                          const queuedCount = Math.max(0, queueLength - resolvedCount - activeCount);
                          const ringTotal = activeCount + resolvedCount;
                          return (
                          <div className="relative w-36 h-36 sm:w-80 sm:h-80 md:w-40 md:h-40 lg:w-56 lg:h-56 xl:w-80 xl:h-80 aspect-square border-dashed border-2 border-gray-700 rounded-full p-2">
                            <ResponsiveContainer width="100%" height="100%">
                              <PieChart>
                                <Pie
                                  data={(() => {
                                    if (ringTotal === 0) return [{ name: 'Empty', value: 1 }];
                                    const segs = [];
                                    if (activeCount > 0) segs.push({ name: 'Active', value: activeCount, color: '#b26666' });
                                    if (resolvedCount > 0) segs.push({ name: 'Completed', value: resolvedCount, color: '#6fa868' });
                                    return segs;
                                  })()}
                                  innerRadius="70%"
                                  outerRadius="100%"
                                  startAngle={90}
                                  endAngle={-270}
                                  dataKey="value"
                                  stroke="#161b22" strokeWidth={2}
                                >
                                  {(() => {
                                    if (ringTotal === 0) return [<Cell key="empty" fill="#374151" />];
                                    const cells = [];
                                    if (activeCount > 0) cells.push(<Cell key="active" fill="#b26666" />);
                                    if (resolvedCount > 0) cells.push(<Cell key="completed" fill="#6fa868" />);
                                    return cells;
                                  })()}
                                </Pie>
                                <Tooltip content={<PieTooltip />} wrapperStyle={{ zIndex: 20, outline: 'none', border: 'none' }} />
                              </PieChart>
                            </ResponsiveContainer>
                            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                              <span className="text-5xl sm:text-8xl md:text-6xl lg:text-7xl xl:text-8xl font-bold text-white">{activeCount}</span>
                            </div>
                          </div>
                          );
                        })()}
                        {dashView === 'source' && (
                          <div className="relative w-36 h-36 sm:w-80 sm:h-80 md:w-40 md:h-40 lg:w-56 lg:h-56 xl:w-80 xl:h-80 aspect-square border-dashed border-2 border-gray-700 rounded-full p-2">
                            <ResponsiveContainer width="100%" height="100%">
                              <PieChart>
                                <Pie
                                  data={sourceTotal > 0 ? sourceSegments.filter(s => s.value > 0) : [{ name: 'None', value: 1, color: '#374151' }]}
                                  innerRadius="70%"
                                  outerRadius="100%"
                                  startAngle={90}
                                  endAngle={-270}
                                  dataKey="value"
                                  stroke="#161b22" strokeWidth={2}
                                >
                                  {(sourceTotal > 0 ? sourceSegments.filter(s => s.value > 0).map(s => s.color) : ['#374151']).map((color, i) => (
                                    <Cell key={i} fill={color} />
                                  ))}
                                </Pie>
                                <Tooltip content={<PieTooltip />} wrapperStyle={{ zIndex: 20, outline: 'none', border: 'none' }} />
                              </PieChart>
                            </ResponsiveContainer>
                            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                              <span className="text-5xl sm:text-8xl md:text-6xl lg:text-7xl xl:text-8xl font-bold text-white">{sourceTotal}</span>
                            </div>
                          </div>
                        )}
                      </div>
                      {dashView === 'source' && (
                        <div className="min-w-0 flex items-center lg:flex-1 lg:pl-4 xl:pl-6">
                          <div className="grid grid-cols-2 gap-x-4 gap-y-2 sm:gap-y-3 lg:grid-cols-1 lg:gap-3 text-xs sm:text-base md:text-xs lg:text-sm">
                            {sourceSegments.map(item => (
                              <div key={item.name} className="flex items-center gap-1.5 min-w-0">
                                <span className="w-2.5 h-2.5 flex-shrink-0 rounded-md" style={{ backgroundColor: item.color }} />
                                <span className="text-gray-300 truncate">{item.name}</span>
                                <span className="text-white font-semibold flex-shrink-0">{item.value}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })()}
            </div>
          </div>

          {/* Right Card: Categories + Alert Types */}
          <div className="flex flex-col">
            <h2 className="text-xl sm:text-2xl font-semibold text-white mb-4">
              {leftView === 'types' ? 'Alert Severity' : 'Alert Category'}
            </h2>
            <div className="rounded-2xl p-4 sm:p-6 flex-1" style={{ background: 'linear-gradient(#161b22, #161b22) padding-box, linear-gradient(to bottom, rgba(88,130,180,0.3), transparent) border-box', border: '1px solid transparent', boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05)' }}>
              {(() => {
                const ALL_CATEGORIES = [
                  { name: 'Malware', key: 'Malware', color: '#5da88a' },
                  { name: 'Phishing', key: 'Phishing', color: '#4f98a0' },
                  { name: 'Lateral Movement', key: 'Lateral Movement', color: '#4682b4' },
                  { name: 'Data Exfiltration', key: 'Data Exfiltration', color: '#5a7caa' },
                  { name: 'Command & Control', key: 'Command & Control', color: '#4e4d8c' },
                  { name: 'Insider Threat', key: 'Insider Threat', color: '#8e6b87' },
                  { name: 'Brute Force', key: 'Brute Force', color: '#b08989' },
                  { name: 'Defense Evasion', key: 'Defense Evasion', color: '#b26666' },
                ];
                const cb = classificationData.categoryBreakdown;
                const catSegments = ALL_CATEGORIES.map(c => ({ ...c, value: cb[c.key] || 0 }));
                const catTotal = catSegments.reduce((sum, s) => sum + s.value, 0);
                const catChartData = catTotal > 0 ? catSegments.filter(s => s.value > 0) : [{ name: 'None', value: 1, color: '#374151' }];

                const sb = alertStats.severity_breakdown;
                const sevSegments = [
                  { name: 'Low', value: sb.low, color: '#6fa868' },
                  { name: 'Medium', value: sb.medium, color: '#d4cc6e' },
                  { name: 'High', value: sb.high, color: '#c28e46' },
                  { name: 'Critical', value: sb.critical, color: '#b26666' },
                ];
                const sevFiltered = sevSegments.filter(s => s.value > 0);
                const sevChartData = sevFiltered.length > 0 ? sevFiltered : [{ name: 'None', value: 1, color: '#374151' }];
                const sevTotal = sb.critical + sb.high + sb.medium + sb.low;

                return (
                  <div className="flex flex-col gap-4">
                    {/* Toggle buttons */}
                    <div className="flex items-center justify-start gap-2">
                      <button
                        onClick={() => setLeftView('types')}
                        className={`px-2 sm:px-3 py-1.5 min-w-[5rem] sm:min-w-[8rem] text-xs sm:text-sm font-medium rounded-md border transition ${
                          leftView === 'types'
                            ? 'bg-[#5882b4] text-white border-[#5882b4]'
                            : 'bg-[#161b22] text-gray-400 border-gray-700 hover:text-gray-200'
                        }`}
                      >
                        <span className="sm:hidden">Severity</span>
                        <span className="hidden sm:inline">Alert Severity</span>
                      </button>
                      <button
                        onClick={() => setLeftView('categories')}
                        className={`px-2 sm:px-3 py-1.5 min-w-[5rem] sm:min-w-[8rem] text-xs sm:text-sm font-medium rounded-md border transition ${
                          leftView === 'categories'
                            ? 'bg-[#5882b4] text-white border-[#5882b4]'
                            : 'bg-[#161b22] text-gray-400 border-gray-700 hover:text-gray-200'
                        }`}
                      >
                        <span className="sm:hidden">Category</span>
                        <span className="hidden sm:inline">Alert Category</span>
                      </button>
                    </div>
                    {/* Chart + Legend */}
                    <div className="flex flex-col items-center gap-4 sm:gap-6 lg:flex-row-reverse lg:items-center">
                      <div className="flex-shrink-0 flex items-center lg:pr-2 xl:pr-6">
                        {leftView === 'types' && (
                          <div className="relative w-36 h-36 sm:w-80 sm:h-80 md:w-40 md:h-40 lg:w-56 lg:h-56 xl:w-80 xl:h-80 aspect-square border-dashed border-2 border-gray-700 rounded-full p-2">
                            <ResponsiveContainer width="100%" height="100%">
                              <PieChart>
                                <Pie
                                  data={sevChartData}
                                  innerRadius="70%"
                                  outerRadius="100%"
                                  startAngle={90}
                                  endAngle={-270}
                                  dataKey="value"
                                  stroke="#161b22" strokeWidth={2}
                                >
                                  {sevChartData.map((s, i) => <Cell key={i} fill={s.color} />)}
                                </Pie>
                                <Tooltip content={<PieTooltip />} wrapperStyle={{ zIndex: 20, outline: 'none', border: 'none' }} />
                              </PieChart>
                            </ResponsiveContainer>
                            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                              <span className="text-5xl sm:text-8xl md:text-6xl lg:text-7xl xl:text-8xl font-bold text-white">{sevTotal}</span>
                            </div>
                          </div>
                        )}
                        {leftView === 'categories' && (
                          <div className="relative w-36 h-36 sm:w-80 sm:h-80 md:w-40 md:h-40 lg:w-56 lg:h-56 xl:w-80 xl:h-80 aspect-square border-dashed border-2 border-gray-700 rounded-full p-2">
                            <ResponsiveContainer width="100%" height="100%">
                              <PieChart>
                                <Pie data={catChartData} innerRadius="70%" outerRadius="100%" startAngle={90} endAngle={-270} dataKey="value" stroke="#161b22" strokeWidth={2}>
                                  {catChartData.map((s, i) => <Cell key={i} fill={s.color} />)}
                                </Pie>
                                <Tooltip content={<PieTooltip />} wrapperStyle={{ zIndex: 20, outline: 'none', border: 'none' }} />
                              </PieChart>
                            </ResponsiveContainer>
                            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                              <span className="text-5xl sm:text-8xl md:text-6xl lg:text-7xl xl:text-8xl font-bold text-white">{catTotal}</span>
                            </div>
                          </div>
                        )}
                      </div>
                      <div className="min-w-0 flex items-center lg:flex-1 lg:pl-4 xl:pl-6">
                        <div className="grid grid-cols-2 gap-x-4 gap-y-2 sm:gap-y-3 lg:grid-cols-1 lg:gap-3 text-xs sm:text-base md:text-xs lg:text-sm">
                        {leftView === 'types' && sevSegments.map(item => (
                          <div key={item.name} className="flex items-center gap-1.5 min-w-0">
                            <span className="w-2.5 h-2.5 flex-shrink-0 rounded-md" style={{ backgroundColor: item.color }} />
                            <span className="text-gray-300 truncate">{item.name}</span>
                            <span className="text-white font-semibold flex-shrink-0">{item.value}</span>
                          </div>
                        ))}
                        {leftView === 'categories' && catSegments.map(item => (
                          <div key={item.name} className="flex items-center gap-1.5 min-w-0">
                            <span className="w-2.5 h-2.5 flex-shrink-0 rounded-md" style={{ backgroundColor: item.color }} />
                            <span className="text-gray-300 truncate">{item.name}</span>
                            <span className="text-white font-semibold flex-shrink-0">{item.value}</span>
                          </div>
                        ))}
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })()}
            </div>
          </div>
        </div>

      <div className="mt-6">
        <h2 className="text-xl sm:text-2xl font-semibold text-white mb-4">Notable Events</h2>
        {filteredGroups.length === 0 ? (
          <div
            className="p-3 sm:p-6 rounded-xl"
            style={{
              background: 'linear-gradient(#161b22, #161b22) padding-box, linear-gradient(to bottom, rgba(88,130,180,0.3), transparent) border-box',
              border: '1px solid transparent',
              boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05)',
            }}
          >
            <div className="flex flex-col items-center justify-center py-8 min-h-[320px]">
              <img src="/ghost_incident.png" alt="Ghost Analyzing" className="w-28 h-28 sm:w-40 sm:h-40 opacity-90 mb-3" />
              <p className="font-mono text-xs sm:text-sm text-gray-400 text-center sm:text-left">&gt;<span className="animate-blink">|</span> No alerts detected yet. Alerts will appear here automatically.</p>
            </div>
          </div>
        ) : (
          <div
            className="p-3 sm:p-6 rounded-xl"
            style={{
              background: 'linear-gradient(#161b22, #161b22) padding-box, linear-gradient(to bottom, rgba(88,130,180,0.3), transparent) border-box',
              border: '1px solid transparent',
              boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05)',
            }}
          >
            <div className="overflow-x-auto overflow-y-hidden mobile-scroll-wrapper">
              <table className="w-full min-w-[600px] log-text text-left text-gray-300 border-separate border-spacing-0">
                <thead>
                  <tr className="text-xs sm:text-sm uppercase text-gray-400 tracking-wider">
                    <th className="w-10 px-2 sm:px-4 py-3 font-medium border-b border-gray-600"></th>
                    <th className="w-12 px-1 sm:px-2 py-3 font-medium border-b border-gray-600"></th>
                    <th className="px-2 sm:px-4 py-3 font-medium border-b border-gray-600">Events</th>
                    <th className="w-32 sm:w-36 px-2 sm:px-4 py-3 font-medium text-center border-b border-gray-600">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {filteredGroups.map(group => {
                    const groupKey = `${group.scenario_id}_${group.threat_pattern}`;
                    const isExpanded = !!groupExpanded[groupKey];
                    const severityColors = { Critical: '#b26666', High: '#c28e46', Medium: '#d4cc6e', Low: '#6fa868' };
                    const groupSeverity = group.severity_breakdown ? getHighestSeverity(group.severity_breakdown) : 'Low';
                    const triangleColor = severityColors[groupSeverity];
                    return (
                      <React.Fragment key={groupKey}>
                        <tr
                          id={`notable-event-${group.scenario_id}`}
                          className={`hover:bg-white/5 transition-colors cursor-pointer border-b border-gray-700/50 transition-opacity duration-300 ${
                            disappearingId === group.scenario_id ? 'opacity-0' : 'opacity-100'
                          } ${highlightedScenarioId === group.scenario_id ? 'bg-[rgba(88,130,180,0.18)]' : ''}`}
                          onClick={() => setGroupExpanded(p => ({ ...p, [groupKey]: !p[groupKey] }))}
                        >
                          <td className="w-10 pl-0 pr-1 sm:pr-2 py-4">
                            <svg
                              className={`w-5 h-5 text-gray-500 hover:text-white transition-transform duration-300 ease-in-out ${
                                isExpanded ? 'rotate-180' : 'rotate-0'
                              }`}
                              fill="none" stroke="currentColor" viewBox="0 0 24 24"
                            >
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                            </svg>
                          </td>
                          <td className="w-12 px-1 sm:px-2 py-4 text-center">
                            <svg
                              className="w-6 h-6 sm:w-7 sm:h-7 inline-block"
                              fill="none" strokeWidth={2.25} viewBox="0 0 24 24"
                            >
                              <path
                                stroke={triangleColor} strokeLinecap="round" strokeLinejoin="round"
                                d="M2.697 16.126c-.866 1.5 .217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126z"
                              />
                              <path
                                stroke="#ffffff" strokeLinecap="round" strokeLinejoin="round"
                                d="M12 9v3.75 M12 15.75h.007v.008H12v-.008z"
                              />
                            </svg>
                          </td>
                          <td className="px-2 sm:px-4 py-4">
                            <p className="text-sm sm:text-base font-medium text-gray-200 whitespace-nowrap">
                              {group.ticket_title || 'Unknown'}
                            </p>
                            <p className="text-xs sm:text-sm text-gray-400 mt-0.5">
                              {group.alert_id && <span className="text-[#5882b4] font-medium">{group.alert_id}</span>}
                              {group.alert_id && <span className="text-gray-600 mx-2">·</span>}
                              <span>{group.log_count} {group.log_count === 1 ? 'Event' : 'Events'}</span>
                            </p>
                          </td>
                          <td
                            className="w-32 sm:w-36 px-2 sm:px-4 py-4 text-center"
                            onClick={(e) => e.stopPropagation()}
                          >
                            <div className="inline-flex items-center gap-2">
                              <button
                                type="button"
                                disabled={submittingIds.has(group.scenario_id)}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setClassificationScenario(group);
                                  setShowClassificationSelector(true);
                                }}
                                className="inline-flex items-center justify-center px-2 sm:px-3 py-1.5 sm:py-2 text-xs font-medium rounded-md border transition bg-[#21262d] hover:bg-[#30363d] text-gray-200 border-gray-600 focus:outline-none focus:ring-2 focus:ring-gray-500 disabled:text-gray-600 disabled:cursor-not-allowed disabled:hover:bg-[#21262d]"
                              >
                                Classify
                              </button>
                              <button
                                type="button"
                                disabled={reportedScenarios.has(group.scenario_id)}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setReportScenario(group);
                                  setShowReportForm(true);
                                }}
                                className="inline-flex items-center justify-center px-2 sm:px-3 py-1.5 sm:py-2 text-xs font-medium rounded-md border transition bg-[#21262d] hover:bg-[#30363d] text-gray-200 border-gray-600 focus:outline-none focus:ring-2 focus:ring-gray-500 disabled:text-gray-600 disabled:cursor-not-allowed disabled:hover:bg-[#21262d]"
                              >
                                {reportedScenarios.has(group.scenario_id) ? 'Reported' : 'Report'}
                              </button>
                            </div>
                          </td>
                        </tr>
                        <tr>
                          <td colSpan="4" className="p-0">
                            <div className={`grid transition-all duration-300 ease-in-out ${
                              isExpanded ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
                            }`}>
                              <div className="overflow-hidden min-h-0">
                                <div style={{ height: '1px', background: 'linear-gradient(to right, rgba(88,130,180,0.3), transparent)' }} />
                                <div className="px-6 py-4">
                                  {group.status === 'classified' && group.analyst_category && (
                                    <p className="text-sm text-gray-400 mb-3">
                                      Classified as: <span className="text-blue-400 font-medium">{group.analyst_category}</span>
                                      {group.category && group.analyst_category === group.category && (
                                        <span className="text-emerald-400 ml-2">Correct!</span>
                                      )}
                                      {group.category && group.analyst_category !== group.category && (
                                        <span className="text-red-400 ml-2">Incorrect (was {group.category})</span>
                                      )}
                                    </p>
                                  )}
                                  <div className="overflow-x-auto overflow-y-hidden mobile-scroll-wrapper">
                                    <table className="w-full min-w-[1000px] sm:min-w-[1100px] log-text text-left text-gray-300 border-separate border-spacing-0">
                                      <thead>
                                        <tr className="text-xs sm:text-sm uppercase text-gray-400 tracking-wider">
                                          <th className="w-10 px-2 py-3"></th>
                                          <th className="px-2 sm:px-4 py-3 font-medium w-[100px] whitespace-nowrap text-center">Alert ID</th>
                                          <th className="px-2 sm:px-4 py-3 font-medium w-[100px] sm:w-[130px] whitespace-nowrap text-center">Time</th>
                                          <th className="px-2 sm:px-4 py-3 font-medium w-[160px] sm:w-[240px] whitespace-nowrap text-center">Event Type</th>
                                          <th className="px-2 sm:px-4 py-3 font-medium w-[110px] sm:w-[170px] whitespace-nowrap text-center">Src Type</th>
                                          <th className="px-2 sm:px-4 py-3 font-medium w-[120px] sm:w-[160px] whitespace-nowrap text-center">Src IP</th>
                                          <th className="px-2 sm:px-4 py-3 font-medium w-[120px] sm:w-[160px] whitespace-nowrap text-center">Dst IP</th>
                                          <th className="px-2 sm:px-4 py-3 font-medium w-[240px] sm:w-auto whitespace-nowrap">Message</th>
                                        </tr>
                                      </thead>
                                      <tbody className="divide-y divide-gray-700">
                                        {group.logs.map((log) => {
                                          return (
                                          <React.Fragment key={log.id}>
                                            <tr
                                              className="hover:bg-white/5 transition-colors cursor-pointer border-b border-gray-700"
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
                                              <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-gray-400 text-center">
                                                {log.alert_id || '—'}
                                              </td>
                                              <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-center">
                                                <span className="text-gray-300">
                                                  {new Date(log.timestamp).toLocaleTimeString('en-GB', {
                                                    hour12: false,
                                                    hour: '2-digit',
                                                    minute: '2-digit',
                                                    second: '2-digit'
                                                  })}
                                                </span>
                                              </td>
                                              <td className="px-2 sm:px-4 py-4 font-medium text-gray-200 sm:whitespace-nowrap text-center">
                                                {log.event_type}
                                              </td>
                                              <td className="px-2 sm:px-4 py-4 text-gray-200 sm:whitespace-nowrap text-center">
                                                {log.source_type || 'Unknown'}
                                              </td>
                                              <td className="px-2 sm:px-4 py-4 text-gray-200 sm:whitespace-nowrap text-center">
                                                {log.source_ip || '—'}
                                              </td>
                                              <td className="px-2 sm:px-4 py-4 text-gray-200 sm:whitespace-nowrap text-center">
                                                {log.destination_ip || '—'}
                                              </td>
                                              <td className="px-2 sm:px-4 py-4 text-gray-200 whitespace-nowrap" title={log.message || '—'}>
                                                {log.message || '—'}
                                              </td>
                                            </tr>
                                            <tr>
                                              <td className="w-10 p-0"></td>
                                              <td colSpan="7" className="p-0">
                                                <div
                                                  className={`grid transition-all duration-300 ease-in-out ${
                                                    expandedLogs[log.id] ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
                                                  }`}
                                                >
                                                  <div className="overflow-hidden min-h-0">
                                                    <div style={{ height: '1px', background: 'linear-gradient(to right, rgba(88,130,180,0.3), transparent)' }} />
                                                    <div className="px-6 py-4">
                                                      {renderCleanEventDetails(log)}
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
          </div>
        )}
      </div>

      {showClassificationSelector && classificationScenario && (
        <ClassificationSelector
          onSelect={(classificationId) => {
            const scenario = classificationScenario;
            setShowClassificationSelector(false);
            setClassificationScenario(null);
            if (classificationId === 'false_positive') {
              handleCategorySelect('false_positive', 'False Positive', scenario);
            } else {
              setCategoryScenario(scenario);
              setShowCategorySelector(true);
            }
          }}
          onCancel={() => {
            setShowClassificationSelector(false);
            setClassificationScenario(null);
          }}
        />
      )}

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
          <div className="relative bg-[#161b22] border border-gray-700 rounded-xl p-6 w-full max-w-2xl mx-4 shadow-2xl max-h-[90vh] overflow-y-auto animate-modalIn">
            <IncidentReportForm
              initialData={{
                title: reportScenario.ticket_title || reportScenario.logs?.[0]?.level_name || '',
                description: '',
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

      {feedback && (
        <TriageFeedback result={feedback} onClose={() => setFeedback(null)} />
      )}

    </div>
  );
};

export default GroupedAlerts;
