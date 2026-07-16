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
    <div style={{ backgroundColor: '#ffffff', border: '1px solid #e2e6ea', borderRadius: '8px', padding: '6px 12px', fontSize: '13px', whiteSpace: 'nowrap' }}>
      <span style={{ color: '#57606a' }}>{name}: <span style={{ color: '#1a2332', fontWeight: 600 }}>{value}</span></span>
    </div>
  );
};

// Progress donut card (Alert Queue) for the Alerts dashboard.
const RingCard = ({ title, segments, centerValue }) => {
  const total = segments.reduce((sum, s) => sum + (s.value || 0), 0);
  const data = total > 0
    ? segments.filter(s => s.value > 0)
    : [{ name: 'None', value: 1, color: '#e5e7eb' }];
  return (
    <div className="flex flex-col">
      <h3 className="text-xl sm:text-2xl font-semibold text-[#1a2332] mb-3">{title}</h3>
      <div className="rounded-2xl p-4 sm:p-5 flex-1" style={{ background: '#ffffff', border: '1px solid #e2e6ea', boxShadow: '0 1px 2px rgba(0,0,0,0.04)' }}>
        <div className="flex items-center justify-center gap-5 sm:gap-8">
          <div className="relative w-28 h-28 sm:w-32 sm:h-32 shrink-0 aspect-square border-dashed border-2 border-[#b4bcc4] rounded-full p-1.5">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={data} innerRadius="70%" outerRadius="100%" startAngle={90} endAngle={-270} dataKey="value" stroke="#ffffff" strokeWidth={2}>
                  {data.map((s, i) => <Cell key={i} fill={s.color} />)}
                </Pie>
                <Tooltip content={<PieTooltip />} wrapperStyle={{ zIndex: 20, outline: 'none', border: 'none' }} />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
              <span className="text-2xl sm:text-3xl font-bold text-[#1a2332]">{centerValue}</span>
            </div>
          </div>
          <div className="flex flex-col gap-2 text-xs sm:text-sm">
            {segments.map(item => (
              <div key={item.name} className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 flex-shrink-0 rounded-md" style={{ backgroundColor: item.color }} />
                <span className="text-[#57606a]">{item.name}</span>
                <span className="text-[#1a2332] font-semibold">{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

// Horizontal bar list for a distribution (Severity / Source / Category) --
// easier to compare magnitudes than a donut.
const BarList = ({ title, segments }) => {
  const max = Math.max(1, ...segments.map(s => s.value || 0));
  const sorted = [...segments].sort((a, b) => (b.value || 0) - (a.value || 0));
  return (
    <div className="flex flex-col">
      <h3 className="text-xl sm:text-2xl font-semibold text-[#1a2332] mb-3">{title}</h3>
      <div className="rounded-2xl p-4 sm:p-5 flex-1" style={{ background: '#ffffff', border: '1px solid #e2e6ea', boxShadow: '0 1px 2px rgba(0,0,0,0.04)' }}>
        <div className="flex flex-col gap-2.5">
          {sorted.map(item => (
            <div key={item.name} className="flex items-center gap-3">
              <span className="w-24 sm:w-32 shrink-0 text-xs sm:text-sm text-[#57606a] truncate">{item.name}</span>
              <div className="flex-1 h-5 rounded bg-[#f0f2f5] overflow-hidden">
                <div className="h-full rounded transition-all duration-500" style={{ width: `${(item.value / max) * 100}%`, minWidth: item.value > 0 ? '3px' : '0', backgroundColor: item.color }} />
              </div>
              <span className="w-7 text-right text-xs sm:text-sm font-semibold text-[#1a2332] shrink-0 tabular-nums">{item.value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

const GroupedAlerts = ({ resetTrigger, onHardcoreFailure, onReset, isVisible, setGroupedAlertCount, onPivot, onHostPivot }) => {
  const [groups, setGroups] = useState([]);
  const [expanded, setExpanded] = useState(null);
  const [expandedLogs, setExpandedLogs] = useState({});
  const [alertStats, setAlertStats] = useState({ total_alerts: 0, closed_alerts: 0, open_alerts: 0, severity_breakdown: { low: 0, medium: 0, high: 0, critical: 0 }, source_breakdown: {} });

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
              <span className="text-[#6e7781]">{k.padEnd(maxKeyLen)}</span>
              <span className="text-[#6e7781]"> = </span>
              {k === 'host' && onHostPivot ? (
                <button
                  type="button"
                  onClick={(e) => { e.stopPropagation(); onHostPivot(v); }}
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
          <span className="text-[#1a2332]">{trimmedMessage}</span>
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

  // Analyst-mode pivot chips. The backend supplies pivot_values (distinguishing
  // entity values with infra servers excluded, so a pivot lands on this chain
  // and not the whole domain's noise); fall back to a local derivation if absent.
  const pivotChipsFor = (group) => {
    if (Array.isArray(group.pivot_values)) return group.pivot_values;
    const vals = new Set();
    (group.logs || []).forEach(log => {
      [log.source_ip, log.destination_ip, log.hostname].forEach(v => {
        if (v) vals.add(v);
      });
      const acct = log.key_value_pairs?.account_name;
      if (acct && acct !== '-') vals.add(acct);
    });
    return [...vals];
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
        <h2 className="text-xl sm:text-2xl font-semibold text-[#1a2332] whitespace-nowrap">
          Alerts <span className={`font-normal ml-1 ${filteredGroups.length > 0 ? "text-[#6e7781]" : "invisible"}`}>{filteredGroups.length || "0"}</span>
        </h2>
        <div className="flex items-center gap-2 sm:gap-3">
          <div className="relative">
            <button
              onClick={() => setShowFilterDropdown(!showFilterDropdown)}
              className="inline-flex items-center justify-center gap-1 px-2 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm font-medium rounded-md border border-transparent transition bg-[#101218] hover:bg-[#1e2330] text-white focus:outline-none focus:ring-2 focus:ring-[#8b949e]"
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
                <div className="absolute right-0 top-full mt-1 z-20 bg-white border border-[#e2e6ea] rounded py-1 flex flex-col min-w-[100px] sm:min-w-[120px]">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setFilterActive(!filterActive);
                    }}
                    className="flex items-center gap-2 text-left px-2.5 sm:px-3 py-1 sm:py-1.5 text-xs sm:text-sm hover:bg-[#eef1f4] transition text-[#57606a]"
                  >
                    <span className={`w-3 h-3 sm:w-3.5 sm:h-3.5 rounded border ${filterActive ? 'bg-[#101218] border-[#101218]' : 'border-[#d0d7de]'}`} />
                    Active
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setFilterCompleted(!filterCompleted);
                    }}
                    className="flex items-center gap-2 text-left px-2.5 sm:px-3 py-1 sm:py-1.5 text-xs sm:text-sm hover:bg-[#eef1f4] transition text-[#57606a]"
                  >
                    <span className={`w-3 h-3 sm:w-3.5 sm:h-3.5 rounded border ${filterCompleted ? 'bg-[#101218] border-[#101218]' : 'border-[#d0d7de]'}`} />
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
          className="w-full pl-4 pr-10 py-2 rounded-md bg-white border border-[#e2e6ea] text-[#1a2332] text-sm placeholder-[#8b949e] focus:border-[#8b949e] focus:outline-none transition-colors"
        />
        {!searchTerm && (
          <svg className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#6e7781]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        )}
        {searchTerm && (
          <button
            onClick={() => setSearchTerm('')}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-[#6e7781] hover:text-[#1a2332]"
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
              background: '#ffffff',
              border: '1px solid #e2e6ea',
              boxShadow: '0 1px 2px rgba(0,0,0,0.04)',
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
                    className="w-12 h-12 sm:w-16 sm:h-16 text-[#6e7781] mb-3"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
                  </svg>
                  <p className="text-sm text-[#6e7781]">{searchTerm ? `No matching alerts for "${searchTerm}"` : 'No alerts match the current filter'}</p>
                </div>
              );

              return (
            <div className="overflow-x-auto overflow-y-hidden mobile-scroll-wrapper">
              <table className="w-full min-w-[600px] log-text text-left text-[#1a2332] border-separate border-spacing-0">
                <thead>
                  <tr className="text-xs sm:text-sm text-[#57606a] tracking-wider">
                    <th className="w-10 px-2 sm:px-4 py-3 font-medium border-b border-[#d0d7de]"></th>
                    <th className="w-12 px-1 sm:px-2 py-3 font-medium border-b border-[#d0d7de]"></th>
                    <th className="px-2 sm:px-4 py-3 font-medium border-b border-[#d0d7de]">Ticket</th>
                    <th className="w-[110px] sm:w-[140px] px-2 sm:px-4 py-3 font-medium whitespace-nowrap text-center border-b border-[#d0d7de]">Severity</th>
                    <th className="w-[110px] sm:w-[140px] px-2 sm:px-4 py-3 font-medium whitespace-nowrap text-center border-b border-[#d0d7de]">Assigned</th>
                    <th className="w-24 sm:w-28 px-2 sm:px-4 py-3 font-medium text-center border-b border-[#d0d7de]">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#e2e6ea]">
                  {/* Active scenarios (concurrent rolling queue) */}
                  {activeMatches.map((scenario) => {
                    const key = `active-${scenario.scenario_id || scenario.level}`;
                    const isExpanded = scenarioExpanded.has(key);
                    return (
                      <React.Fragment key={key}>
                        <tr
                          className="hover:bg-[#f6f8fa] transition-colors cursor-pointer border-b border-[#e2e6ea]/50"
                          onClick={() => setScenarioExpanded(prev => { const next = new Set(prev); next.has(key) ? next.delete(key) : next.add(key); return next; })}
                        >
                          <td className="w-10 pl-0 pr-1 sm:pr-2 py-4">
                            <svg
                              className={`w-5 h-5 text-[#6e7781] hover:text-[#1a2332] transition-transform duration-300 ease-in-out ${
                                isExpanded ? 'rotate-180' : 'rotate-0'
                              }`}
                              fill="none" stroke="currentColor" viewBox="0 0 24 24"
                            >
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                            </svg>
                          </td>
                          <td className="w-12 px-1 sm:px-2 py-4 text-center">
                            <svg className="w-5 h-5 sm:w-6 sm:h-6 inline-block text-[#101218]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                            </svg>
                          </td>
                          <td className="px-2 sm:px-4 py-4">
                            <p className="text-sm sm:text-base font-medium text-[#1a2332] whitespace-nowrap">{scenario.ticket_title}</p>
                            {(() => {
                              const match = groups.find(g => g.scenario_id === scenario.scenario_id);
                              const alertId = match?.alert_id;
                              if (!alertId && !scenario.startTime) return null;
                              return (
                                <p className="text-xs sm:text-sm text-[#57606a] mt-0.5">
                                  {alertId && (
                                    <button
                                      type="button"
                                      onClick={(e) => { e.stopPropagation(); scrollToNotableEvent(match); }}
                                      className="log-mono text-[#16436b] hover:text-[#101218] hover:underline font-medium transition-colors"
                                    >{alertId}</button>
                                  )}
                                  {alertId && scenario.startTime && <span className="text-[#8b949e] mx-2">·</span>}
                                  {scenario.startTime && `Created ${getRelativeTime(scenario.startTime)}`}
                                </p>
                              );
                            })()}
                          </td>
                          <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-center">
                            <SeverityPill level={groups.find(g => g.scenario_id === scenario.scenario_id)?.group_severity} />
                          </td>
                          <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-center">
                            <span className="text-[#1a2332]">{analystName || 'Unassigned'}</span>
                          </td>
                          <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-center">
                            <span className="text-[#1a2332]">Active</span>
                          </td>
                        </tr>
                        <tr>
                          <td colSpan="6" className="p-0">
                            <div className={`grid transition-all duration-300 ease-in-out ${
                              isExpanded ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
                            }`}>
                              <div className="overflow-hidden min-h-0">
                                <div style={{ height: '1px', background: 'linear-gradient(to right, rgba(0,0,0,0.08), transparent)' }} />
                                <div className="px-6 py-4">
                                  <p className="text-[#1a2332] text-sm sm:text-base leading-relaxed">{scenario.storyline}</p>
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
                        className={`hover:bg-[#f6f8fa] cursor-pointer border-b border-[#e2e6ea]/50 transition-all duration-700 ${fadingOutScenarioLevel === scenario.level ? 'opacity-0' : 'opacity-100'}`}
                        onClick={() => setScenarioExpanded(prev => { const next = new Set(prev); next.has(scenario.level) ? next.delete(scenario.level) : next.add(scenario.level); return next; })}
                      >
                        <td className="w-10 pl-0 pr-1 sm:pr-2 py-4">
                          <svg
                            className={`w-5 h-5 text-[#6e7781] hover:text-[#1a2332] transition-transform duration-300 ease-in-out ${
                              scenarioExpanded.has(scenario.level) ? 'rotate-180' : 'rotate-0'
                            }`}
                            fill="none" stroke="currentColor" viewBox="0 0 24 24"
                          >
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                          </svg>
                        </td>
                        <td className="w-12 px-1 sm:px-2 py-4 text-center">
                          <svg className="w-5 h-5 sm:w-6 sm:h-6 inline-block text-[#101218]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                          </svg>
                        </td>
                        <td className="px-2 sm:px-4 py-4">
                          <p className="text-sm sm:text-base font-medium text-[#1a2332] whitespace-nowrap">{scenario.ticket_title}</p>
                          {(() => {
                            const match = groups.find(g => g.scenario_id === scenario.scenario_id);
                            const alertId = match?.alert_id;
                            if (!alertId && !scenario.startTime) return null;
                            return (
                              <p className="text-xs sm:text-sm text-[#57606a] mt-0.5">
                                {alertId && <span className="log-mono text-[#16436b] font-medium">{alertId}</span>}
                                {alertId && scenario.startTime && <span className="text-[#8b949e] mx-2">·</span>}
                                {scenario.startTime && `Created ${getRelativeTime(scenario.startTime)}`}
                              </p>
                            );
                          })()}
                        </td>
                        <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-center">
                          <SeverityPill level={groups.find(g => g.scenario_id === scenario.scenario_id)?.group_severity} />
                        </td>
                        <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-center">
                          <span className="text-[#1a2332]">{analystName || 'Unassigned'}</span>
                        </td>
                        <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-center">
                          <span className="text-[#1a2332]">Completed</span>
                        </td>
                      </tr>
                      <tr>
                        <td colSpan="6" className="p-0">
                          <div className={`grid transition-all duration-300 ease-in-out ${
                            scenarioExpanded.has(scenario.level) ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
                          }`}>
                            <div className="overflow-hidden min-h-0">
                              <div style={{ height: '1px', background: 'linear-gradient(to right, rgba(0,0,0,0.08), transparent)' }} />
                              <div className="px-6 py-4">
                                <p className="text-[#1a2332] text-sm sm:text-base leading-relaxed">{scenario.storyline}</p>
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
              background: '#ffffff',
              border: '1px solid #e2e6ea',
              boxShadow: '0 1px 2px rgba(0,0,0,0.04)',
            }}
          >
            <div className="flex flex-col items-center justify-center py-4">
              <svg className="w-8 h-8 text-[#8b949e] mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              <p className="text-sm text-[#6e7781]">Start a simulation to receive your first briefing.</p>
            </div>
          </div>
        )}
      </div>

        {/* Alerts dashboard: queue donut + distribution bar lists, no toggles */}
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
          const srcb = alertStats.source_breakdown || {};
          const sourceSegments = SOURCE_TYPES.map(s => ({ name: s.name, color: s.color, value: srcb[s.key || s.name] || 0 }));

          const sevb = alertStats.severity_breakdown || { low: 0, medium: 0, high: 0, critical: 0 };
          const sevSegments = [
            { name: 'Low', value: sevb.low, color: '#6fa868' },
            { name: 'Medium', value: sevb.medium, color: '#d4cc6e' },
            { name: 'High', value: sevb.high, color: '#c28e46' },
            { name: 'Critical', value: sevb.critical, color: '#b26666' },
          ];

          const cb = classificationData.categoryBreakdown || {};
          const catSegments = ALL_CATEGORIES.map(c => ({ name: c.name, color: c.color, value: cb[c.key] || 0 }));

          const activeCount = (currentLevel?.active_scenarios || []).length;
          const resolvedCount = currentLevel?.resolved_count ?? 0;
          const queueSegments = [
            { name: 'Active', value: activeCount, color: '#b26666' },
            { name: 'Completed', value: resolvedCount, color: '#6fa868' },
          ];

          return (
            <div className="grid gap-6 grid-cols-1 md:grid-cols-2">
              <RingCard title="Queue" centerValue={activeCount} segments={queueSegments} />
              <BarList title="Severity" segments={sevSegments} />
              <BarList title="Source" segments={sourceSegments} />
              <BarList title="Category" segments={catSegments} />
            </div>
          );
        })()}

      <div className="mt-6">
        <h2 className="text-xl sm:text-2xl font-semibold text-[#1a2332] mb-4">Notable Events</h2>
        {filteredGroups.length === 0 ? (
          <div
            className="p-3 sm:p-6 rounded-xl"
            style={{
              background: '#ffffff',
              border: '1px solid #e2e6ea',
              boxShadow: '0 1px 2px rgba(0,0,0,0.04)',
            }}
          >
            <div className="flex flex-col items-center justify-center py-8 min-h-[320px]">
              <svg className="w-8 h-8 text-[#8b949e] mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
              </svg>
              <p className="text-sm text-[#6e7781]">No alerts detected yet. Alerts will appear here automatically.</p>
            </div>
          </div>
        ) : (
          <div
            className="p-3 sm:p-6 rounded-xl"
            style={{
              background: '#ffffff',
              border: '1px solid #e2e6ea',
              boxShadow: '0 1px 2px rgba(0,0,0,0.04)',
            }}
          >
            <div className="overflow-x-auto overflow-y-hidden mobile-scroll-wrapper">
              <table className="w-full min-w-[600px] log-text text-left text-[#1a2332] border-separate border-spacing-0">
                <thead>
                  <tr className="text-xs sm:text-sm text-[#57606a] tracking-wider">
                    <th className="w-10 px-2 sm:px-4 py-3 font-medium border-b border-[#d0d7de]"></th>
                    <th className="w-12 px-1 sm:px-2 py-3 font-medium border-b border-[#d0d7de]"></th>
                    <th className="px-2 sm:px-4 py-3 font-medium border-b border-[#d0d7de]">Events</th>
                    <th className="w-32 sm:w-36 px-2 sm:px-4 py-3 font-medium text-center border-b border-[#d0d7de]">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#e2e6ea]">
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
                          className={`hover:bg-[#f6f8fa] transition-colors cursor-pointer border-b border-[#e2e6ea]/50 transition-opacity duration-300 ${
                            disappearingId === group.scenario_id ? 'opacity-0' : 'opacity-100'
                          } ${highlightedScenarioId === group.scenario_id ? 'bg-[rgba(0,0,0,0.04)]' : ''}`}
                          onClick={() => setGroupExpanded(p => ({ ...p, [groupKey]: !p[groupKey] }))}
                        >
                          <td className="w-10 pl-0 pr-1 sm:pr-2 py-4">
                            <svg
                              className={`w-5 h-5 text-[#6e7781] hover:text-[#1a2332] transition-transform duration-300 ease-in-out ${
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
                                stroke={triangleColor} strokeLinecap="round" strokeLinejoin="round"
                                d="M12 9v3.75 M12 15.75h.007v.008H12v-.008z"
                              />
                            </svg>
                          </td>
                          <td className="px-2 sm:px-4 py-4">
                            <p className="text-sm sm:text-base font-medium text-[#1a2332] whitespace-nowrap">
                              {group.ticket_title || 'Unknown'}
                            </p>
                            <p className="text-xs sm:text-sm text-[#57606a] mt-0.5">
                              {group.alert_id && <span className="log-mono text-[#16436b] font-medium">{group.alert_id}</span>}
                              {group.alert_id && <span className="text-[#8b949e] mx-2">·</span>}
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
                                className="inline-flex items-center justify-center px-2 sm:px-3 py-1.5 sm:py-2 text-xs font-medium rounded-md border transition bg-[#101218] hover:bg-[#1e2330] text-white border-transparent focus:outline-none focus:ring-2 focus:ring-[#101218]/40 disabled:opacity-50 disabled:cursor-not-allowed"
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
                                className="inline-flex items-center justify-center px-2 sm:px-3 py-1.5 sm:py-2 text-xs font-medium rounded-md border transition bg-[#101218] hover:bg-[#1e2330] text-white border-transparent focus:outline-none focus:ring-2 focus:ring-[#101218]/40 disabled:opacity-50 disabled:cursor-not-allowed"
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
                                <div style={{ height: '1px', background: 'linear-gradient(to right, rgba(0,0,0,0.08), transparent)' }} />
                                <div className="px-6 py-4">
                                  {gameMode === 'analyst' && group.hidden_count > 0 && (
                                    <div className="mb-4 rounded-lg border border-[#e2e6ea] bg-white px-4 py-3">
                                      <p className="text-xs sm:text-sm text-[#1a2332]">
                                        <span className="text-[#c28e46] font-medium">Detection fired on the event{group.log_count === 1 ? '' : 's'} below.</span>{' '}
                                        {group.hidden_count} related event{group.hidden_count === 1 ? '' : 's'} from this host are in the stream. Pivot to reconstruct the chain before you classify.
                                      </p>
                                      <div className="mt-2.5 flex flex-wrap items-center gap-2">
                                        <span className="text-xs tracking-wider text-[#6e7781]">Pivot on</span>
                                        {pivotChipsFor(group).map(v => (
                                          <button
                                            key={v}
                                            type="button"
                                            onClick={(e) => { e.stopPropagation(); onPivot?.(v); }}
                                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-mono border border-[#e2e6ea] bg-white text-[#8b949e] hover:bg-white hover:text-[#f0f6fc] transition-colors"
                                            title={`Filter Events by ${v}`}
                                          >
                                            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                                            </svg>
                                            {v}
                                          </button>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                  {group.status === 'classified' && group.analyst_category && (
                                    <p className="text-sm text-[#57606a] mb-3">
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
                                    <table className="w-full min-w-[1000px] sm:min-w-[1100px] log-text text-left text-[#1a2332] border-separate border-spacing-0">
                                      <thead>
                                        <tr className="text-xs sm:text-sm text-[#57606a] tracking-wider">
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
                                      <tbody className="divide-y divide-[#e2e6ea]">
                                        {group.logs.map((log) => {
                                          return (
                                          <React.Fragment key={log.id}>
                                            <tr
                                              className="hover:bg-[#f6f8fa] transition-colors cursor-pointer border-b border-[#e2e6ea]"
                                              onClick={() => toggleLogRow(log.id)}
                                            >
                                              <td className="px-2 py-4">
                                                <svg
                                                  className={`w-5 h-5 text-[#6e7781] hover:text-[#1a2332] transition-transform duration-300 ease-in-out ${
                                                    expandedLogs[log.id] ? 'rotate-180' : 'rotate-0'
                                                  }`}
                                                  fill="none"
                                                  stroke="currentColor"
                                                  viewBox="0 0 24 24"
                                                >
                                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                                </svg>
                                              </td>
                                              <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-[#57606a] text-center">
                                                {log.alert_id || '-'}
                                              </td>
                                              <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-center">
                                                <span className="text-[#1a2332]">
                                                  {new Date(log.timestamp).toLocaleTimeString('en-GB', {
                                                    hour12: false,
                                                    hour: '2-digit',
                                                    minute: '2-digit',
                                                    second: '2-digit'
                                                  })}
                                                </span>
                                              </td>
                                              <td className="px-2 sm:px-4 py-4 font-medium text-[#1a2332] sm:whitespace-nowrap text-center">
                                                {log.event_type}
                                              </td>
                                              <td className="px-2 sm:px-4 py-4 text-[#1a2332] sm:whitespace-nowrap text-center">
                                                {log.source_type || 'Unknown'}
                                              </td>
                                              <td className="px-2 sm:px-4 py-4 text-[#1a2332] sm:whitespace-nowrap text-center">
                                                {log.source_ip || '-'}
                                              </td>
                                              <td className="px-2 sm:px-4 py-4 text-[#1a2332] sm:whitespace-nowrap text-center">
                                                {log.destination_ip || '-'}
                                              </td>
                                              <td className="px-2 sm:px-4 py-4 text-[#1a2332] whitespace-nowrap" title={log.message || '-'}>
                                                {log.message || '-'}
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
                                                    <div style={{ height: '1px', background: 'linear-gradient(to right, rgba(0,0,0,0.08), transparent)' }} />
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
          isHardcore={gameMode === 'hardcore'}
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
          isHardcore={gameMode === 'hardcore'}
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
          <div className="relative bg-white border border-[#e2e6ea] rounded-xl p-6 w-full max-w-2xl mx-4 shadow-2xl max-h-[90vh] overflow-y-auto animate-modalIn">
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
