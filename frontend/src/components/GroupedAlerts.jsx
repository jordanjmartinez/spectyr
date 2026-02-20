import React, { useEffect, useState } from 'react';
import { apiFetch } from '../api';
import confetti from 'canvas-confetti';
import CategorySelector from '../components/CategorySelector';

const GroupedAlerts = ({ resetTrigger, onHardcoreFailure, onReset, isVisible }) => {
  const [groups, setGroups] = useState([]);
  const [expanded, setExpanded] = useState(null);
  const [expandedLogs, setExpandedLogs] = useState({});

  const [disappearingId, setDisappearingId] = useState(null);
  const [showCategorySelector, setShowCategorySelector] = useState(false);
  const [categoryScenario, setCategoryScenario] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [submittingIds, setSubmittingIds] = useState(new Set());
  const [currentLevel, setCurrentLevel] = useState(null);
  const [gameStarted, setGameStarted] = useState(false);

  const fetchGroupedAlerts = () => {
    apiFetch('/api/grouped-alerts')
      .then(res => res.json())
      .then(data => {
        setGroups(prevGroups => {
          const prevMap = new Map(prevGroups.map(g => [g.scenario_id, g.selectedAction]));

          return data.map(group => ({
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
      .then(data => setGameStarted(!!data.analyst_name))
      .catch(err => console.error("Failed to fetch game state", err));
  };

  useEffect(() => {
    // Clear state on reset
    setGroups([]);
    setCurrentLevel(null);
    setExpanded(null);
    setGameStarted(false);

    fetchGroupedAlerts();
    fetchCurrentLevel();
    fetchGameState();

    const interval = setInterval(() => {
      fetchGroupedAlerts();
      fetchCurrentLevel();
      fetchGameState();
    }, 3000);

    return () => clearInterval(interval);
  }, [resetTrigger]);

  useEffect(() => {
    if (isVisible && gameStarted && currentLevel?.completed) {
      confetti({ particleCount: 100, spread: 70, origin: { y: 0.6 } });
      const interval = setInterval(() => {
        confetti({ particleCount: 80, spread: 60, origin: { y: 0.6 } });
      }, 5000);
      return () => clearInterval(interval);
    }
  }, [isVisible, gameStarted, currentLevel]);

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

  const handleCategorySelect = async (categoryId, categoryLabel) => {
    if (!categoryScenario) return;

    const updatedSet = new Set(submittingIds);
    updatedSet.add(categoryScenario.scenario_id);
    setSubmittingIds(updatedSet);

    try {
      const res = await apiFetch('/api/resume', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          analyst_action: 'classify',
          scenario_id: categoryScenario.scenario_id,
          label: categoryScenario.label,
          selected_category: categoryLabel
        })
      });

      const data = await res.json();

      // Check for hardcore mode failure
      if (data.status === 'hardcore_failure') {
        setShowCategorySelector(false);
        setCategoryScenario(null);
        onHardcoreFailure?.(data.category);
        return;
      }

      setDisappearingId(categoryScenario.scenario_id);

      setTimeout(() => {
        setGroups(prev =>
          prev.map(g =>
            g.scenario_id === categoryScenario.scenario_id
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
      clearedSet.delete(categoryScenario.scenario_id);
      setSubmittingIds(clearedSet);
    }
  };

  const filteredGroups = groups.filter(g => g.status === 'active');

  return (
    <div className="space-y-4">
      {/* Scenario Card - only show when a scenario is actually assigned */}
      {gameStarted && currentLevel && !currentLevel.completed && currentLevel.ticket_title && (
        <div className="bg-[#161b22] border border-gray-700 rounded-xl p-4 sm:p-5 mb-6 shadow">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-3 gap-2">
            <div className="flex items-center gap-3">
              <span className="inline-flex items-center bg-gray-800/80 text-gray-200 text-xs px-2.5 py-1 rounded-md uppercase font-semibold tracking-wider border border-gray-700">
                Level {currentLevel.current_level}
              </span>
              <span className="text-base sm:text-lg font-semibold text-white">{currentLevel.ticket_title}</span>
            </div>
            <span className="text-sm text-gray-400">
              {Object.keys(currentLevel.level_results || {}).length} / {currentLevel.total_levels} Completed
            </span>
          </div>
          <p className="text-gray-300 text-base leading-relaxed">
            {currentLevel.storyline}
          </p>
        </div>
      )}

      {/* Training Complete Banner */}
      {gameStarted && currentLevel && currentLevel.completed && (
        <div className="bg-[#161b22] border border-gray-700 rounded-xl p-4 sm:p-5 mb-6 shadow">
          <h2 className="text-2xl font-semibold text-white mb-4">Mission Complete</h2>
          <div className="flex flex-col items-center text-center">
            <img
              src="/ghost-celebrate.png"
              alt="Ghost Celebrating"
              className="w-28 h-28 sm:w-40 sm:h-40 opacity-90 mb-3"
            />
            <p className="font-mono text-sm text-gray-400 mb-4">&gt; You've completed all {currentLevel.total_levels} levels. Reset the simulator to play again.</p>
            <button
              onClick={onReset}
              className="px-4 py-2 text-sm font-medium rounded-md border transition focus:outline-none focus:ring-2 focus:ring-gray-500 bg-[#21262d] hover:bg-[#30363d] text-gray-200 border-gray-600"
            >
              Reset
            </button>
          </div>
        </div>
      )}

      {!(gameStarted && currentLevel && currentLevel.completed) && (<>
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center mb-4 space-y-2 sm:space-y-0">
        <h2 className="text-2xl font-semibold text-white">
          Incidents <span className="text-gray-500 font-normal">({filteredGroups.length})</span>
        </h2>
      </div>

      {filteredGroups.length === 0 && (
        <div className="bg-[#161b22] p-6 rounded-xl">
          <div className="flex flex-col items-center justify-center py-8 min-h-[320px]">
            <img src="/ghost_incident.png" alt="Ghost Analyzing" className="w-28 h-28 sm:w-40 sm:h-40 opacity-90 mb-3" />
            <p className="font-mono text-sm text-gray-400">&gt; Nothing flagged yet. Classify threats in Events to populate this view.</p>
          </div>
        </div>
      )}

      {filteredGroups.map(group => {
        const groupKey = `${group.scenario_id}_${group.threat_pattern}`;
        return (
          <div
            key={groupKey}
            className={`bg-[#161b22] border border-gray-700 p-3 sm:p-4 rounded-xl shadow transition-all duration-300 ease-in-out ${
              disappearingId === group.scenario_id ? 'opacity-0 scale-95' : 'opacity-100'
            }`}
          >
            <div className="flex justify-between items-start cursor-pointer" onClick={() => toggleGroup(groupKey)}>
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-2">
                  <span className="inline-flex items-center gap-1.5 bg-gray-800/80 text-gray-200 text-xs px-2.5 py-1 rounded-md uppercase font-semibold tracking-wider border border-gray-700">
                    🕵️ Notable Event
                  </span>
                  <span className="text-gray-500 text-sm">{group.log_count} {group.log_count === 1 ? 'Event' : 'Events'}</span>
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
              <svg
                className={`ml-4 w-5 h-5 text-gray-500 hover:text-white transition-transform duration-300 ease-in-out flex-shrink-0 mt-1 ${
                  expanded === groupKey ? 'rotate-180' : 'rotate-0'
                }`}
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </div>

            <div
              className={`grid transition-all duration-300 ease-in-out ${
                expanded === groupKey ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
              }`}
            >
              <div className="overflow-hidden min-h-0">
                <div className="mt-4 border-t border-gray-700 pt-4">
                  <div className="overflow-x-auto overflow-y-hidden mobile-scroll-wrapper">
                    <table className="w-full min-w-[700px] log-text text-left text-gray-300 border-separate border-spacing-0">
                      <thead>
                        <tr className="text-sm uppercase text-gray-400 tracking-wider">
                          <th className="px-4 py-3 font-medium w-[100px]">Time</th>
                          <th className="px-4 py-3 font-medium w-[140px]">Event Type</th>
                          <th className="px-4 py-3 font-medium w-[110px] whitespace-nowrap">Source Type</th>
                          <th className="px-4 py-3 font-medium w-[120px]">Source IP</th>
                          <th className="px-4 py-3 font-medium w-[120px]">Dest IP</th>
                          <th className="px-4 py-3 font-medium">Message</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-700">
                        {group.logs.map((log) => (
                          <React.Fragment key={log.id}>
                            <tr
                              className="hover:bg-white/5 transition-colors cursor-pointer border-b border-gray-700/50"
                              onClick={() => toggleLogRow(log.id)}
                            >
                              <td className="px-4 py-4 whitespace-nowrap">
                                <div className="flex flex-col">
                                  <span className="text-gray-300">{new Date(log.timestamp).toLocaleDateString('en-GB')}</span>
                                  <span className="text-xs text-gray-500">
                                    {new Date(log.timestamp).toLocaleTimeString('en-GB', {
                                      hour12: false,
                                      hour: '2-digit',
                                      minute: '2-digit',
                                      second: '2-digit'
                                    })}
                                  </span>
                                </div>
                              </td>
                              <td className="px-4 py-4 font-medium text-gray-200">
                                {log.event_type}
                              </td>
                              <td className="px-4 py-4 text-gray-200">
                                {log.source_type || 'Unknown'}
                              </td>
                              <td className="px-4 py-4 text-gray-200">
                                {log.source_ip || '—'}
                              </td>
                              <td className="px-4 py-4 text-gray-200">
                                {log.destination_ip || '—'}
                              </td>
                              <td className="px-4 py-4 text-gray-200 truncate max-w-[300px]" title={log.message || '—'}>
                                {log.message || '—'}
                              </td>
                            </tr>
                            <tr>
                              <td colSpan="6" className="p-0">
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

                <div className="mt-4 pt-4 border-t border-gray-800 flex items-center justify-end gap-3">
                  <button
                    disabled={submittingIds.has(group.scenario_id)}
                    onClick={() => {
                      setCategoryScenario(group);
                      setShowCategorySelector(true);
                    }}
                    className={`inline-flex items-center gap-2 px-4 py-2 text-base font-medium rounded-md border transition focus:outline-none focus:ring-2 focus:ring-gray-500 ${
                      submittingIds.has(group.scenario_id)
                        ? 'bg-[#161b22] text-gray-500 border-gray-700 cursor-not-allowed'
                        : 'bg-[#21262d] hover:bg-[#30363d] text-gray-200 border-gray-600'
                    }`}
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
                    </svg>
                    Choose Category
                  </button>
                </div>
              </div>
            </div>
          </div>
        );
      })}

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
      </>)}

    </div>
  );
};

export default GroupedAlerts;
