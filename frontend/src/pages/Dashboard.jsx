import React, { useState, useEffect, useRef } from 'react';
import { apiFetch } from '../api';
import AlertTable from '../components/AlertTable';
import GroupedAlerts from '../components/GroupedAlerts';
import Analytics from '../components/Analytics';
import Reports from '../components/Reports';
import DifficultySelector from '../components/DifficultySelector';
import GameTimer from '../components/GameTimer';
import FailureModal from '../components/FailureModal';

const Dashboard = () => {
  const [alertCount, setAlertCount] = useState(0);
  const [groupedAlertCount, setGroupedAlertCount] = useState(0);
  const [reportCount, setReportCount] = useState(0);
  const [view, setView] = useState("table");
  const [resetTrigger, setResetTrigger] = useState(0);
  const [showResetModal, setShowResetModal] = useState(false);
  const [isResetting, setIsResetting] = useState(false);
  const [showSimulateModal, setShowSimulateModal] = useState(false);
  const [showDifficultyModal, setShowDifficultyModal] = useState(false);
  const [existingLogCount, setExistingLogCount] = useState(0);
  const [showFailureModal, setShowFailureModal] = useState(false);
  const [failureCategory, setFailureCategory] = useState(null);
  const [failureType, setFailureType] = useState(null); // 'timeout' or 'wrong_answer'
  const [analystName, setAnalystName] = useState(null);
  const [incidentBadge, setIncidentBadge] = useState(0);

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) return;
      switch (e.key) {
        case '1': setView('grouped'); setIncidentBadge(0); break;
        case '2': setView('table'); break;
        case '3': setView('analytics'); break;
        case '4': setView('reports'); break;
        default: break;
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Auto-detect new incidents when game pauses (attack chain complete)
  const wasPausedRef = useRef(true);
  useEffect(() => {
    const checkForIncidents = () => {
      apiFetch('/api/game-state')
        .then(res => res.json())
        .then(data => {
          if (wasPausedRef.current === false && data.paused === true) {
            // Transition from running to paused = attack chain complete
            if (view !== 'grouped') {
              setIncidentBadge(prev => prev + 1);
            }
          }
          wasPausedRef.current = data.paused;
        })
        .catch(() => {});
    };
    const interval = setInterval(checkForIncidents, 2000);
    return () => clearInterval(interval);
  }, [view]);

  const handleSimulateEvents = async () => {
    try {
      const res = await apiFetch('/api/fake-events');
      const data = await res.json();
      const logCount = Array.isArray(data) ? data.length : 0;

      if (logCount > 0) {
        setExistingLogCount(logCount);
        setShowSimulateModal(true);
      } else {
        // No logs - show difficulty selection
        setShowDifficultyModal(true);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleDifficultySelect = async (mode, name) => {
    setShowDifficultyModal(false);
    setAnalystName(name);
    try {
      await apiFetch('/api/start-simulator', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ game_mode: mode, analyst_name: name })
      });
    } catch (err) {
      console.error(err);
    }
  };

  const handleTimeout = async () => {
    // Get the current level's category for the failure message
    try {
      const res = await apiFetch('/api/current-level');
      const data = await res.json();
      setFailureCategory(data.category || 'Unknown');
    } catch (err) {
      setFailureCategory('Unknown');
    }
    setFailureType('timeout');
    setShowFailureModal(true);
  };

  const handleHardcoreFailure = (category) => {
    // Called when player gets a wrong answer in hardcore mode
    // Backend already reset the game, just show the failure modal
    setFailureCategory(category || 'Unknown');
    setFailureType('wrong_answer');
    setShowFailureModal(true);
  };

  const handleFailureRestart = async () => {
    setShowFailureModal(false);
    setFailureType(null);
    await handleResetSimulator();
  };

  const handleFailureRetry = async () => {
    setShowFailureModal(false);
    setFailureType(null);
    await handleResetSimulator();
    try {
      await apiFetch('/api/start-simulator', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ game_mode: 'hardcore', analyst_name: analystName })
      });
    } catch (err) {
      console.error(err);
    }
  };

  const handleResetSimulator = async () => {
    setIsResetting(true);
    try {
      await apiFetch('/api/reset-simulator', {
        method: 'POST',
      });
      setResetTrigger(prev => prev + 1);
      setShowResetModal(false);
    } catch (err) {
      console.error(err);
    } finally {
      setIsResetting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0d1117] text-white pt-2 pb-8 px-4 sm:px-8 lg:px-16">
      <div className="space-y-4">

        <div className="flex sm:hidden justify-end mb-2">
          <GameTimer onTimeout={handleTimeout} disabled={showFailureModal} />
        </div>
        <div className="bg-[#161b22] rounded-xl p-3 sm:p-6">
          <div className="flex pl-2 sm:pl-8 gap-6 sm:gap-12 border-b border-gray-700 mb-6 overflow-x-auto scrollbar-hide items-center">
            <button
              onClick={() => {
                setView("grouped");
                setIncidentBadge(0);
              }}
              className={`py-3 sm:py-4 text-sm sm:text-lg whitespace-nowrap transition-all duration-200 ${
                view === "grouped"
                  ? "text-white font-medium border-b-2 border-white"
                  : "text-gray-400 font-medium hover:text-white border-b-2 border-transparent"
              }`}
            >
              Alerts {groupedAlertCount > 0 && <span className="text-gray-500 font-normal">({groupedAlertCount})</span>}
            </button>
            <button
              onClick={() => setView("table")}
              className={`py-3 sm:py-4 text-sm sm:text-lg whitespace-nowrap transition-all duration-200 ${
                view === "table"
                  ? "text-white font-medium border-b-2 border-white"
                  : "text-gray-400 font-medium hover:text-white border-b-2 border-transparent"
              }`}
            >
              Events {alertCount > 0 && <span className="text-gray-500 font-normal">({alertCount})</span>}
            </button>
            <button
              onClick={() => setView("analytics")}
              className={`py-3 sm:py-4 text-sm sm:text-lg whitespace-nowrap transition-all duration-200 ${
                view === "analytics"
                  ? "text-white font-medium border-b-2 border-white"
                  : "text-gray-400 font-medium hover:text-white border-b-2 border-transparent"
              }`}
            >
              Analytics
            </button>
            <button
              onClick={() => setView("reports")}
              className={`py-3 sm:py-4 text-sm sm:text-lg whitespace-nowrap transition-all duration-200 ${
                view === "reports"
                  ? "text-white font-medium border-b-2 border-white"
                  : "text-gray-400 font-medium hover:text-white border-b-2 border-transparent"
              }`}
            >
              Reports {reportCount > 0 && <span className="text-gray-500 font-normal">({reportCount})</span>}
            </button>
            <div className="ml-auto hidden sm:block">
              <GameTimer onTimeout={handleTimeout} disabled={showFailureModal} />
            </div>
          </div>

          <div className={view === "grouped" ? "block" : "hidden"}>
            <GroupedAlerts resetTrigger={resetTrigger} onHardcoreFailure={handleHardcoreFailure} onReset={() => { handleResetSimulator(); setView("table"); }} isVisible={view === "grouped"} setGroupedAlertCount={setGroupedAlertCount} />
          </div>

          <div className={view === "table" ? "block" : "hidden"}>
            <div className="flex flex-row items-center justify-between mb-3 gap-2 sm:gap-3">
              <h2 className="text-xl sm:text-2xl font-semibold text-white whitespace-nowrap">
                Events <span className="text-gray-500 font-normal">({alertCount})</span>
              </h2>
              <div className="flex items-center gap-2 sm:gap-4">
                <button
                  onClick={handleSimulateEvents}
                  className="inline-flex items-center px-2 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm font-medium rounded-md bg-[#21262d] hover:bg-[#30363d] text-gray-200 border border-gray-600 transition focus:outline-none focus:ring-2 focus:ring-gray-500"
                >
                  Start Simulation
                </button>
                <button
                  onClick={() => setShowResetModal(true)}
                  className="inline-flex items-center px-2 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm font-medium rounded-md bg-[#21262d] hover:bg-[#30363d] text-gray-200 border border-gray-600 transition focus:outline-none focus:ring-2 focus:ring-gray-500"
                >
                  Reset Simulation
                </button>
              </div>
            </div>
            <AlertTable setAlertCount={setAlertCount} resetTrigger={resetTrigger} />
          </div>

          <div className={view === "analytics" ? "block" : "hidden"}>
            <Analytics />
          </div>

          <div className={view === "reports" ? "block" : "hidden"}>
            <Reports setReportCount={setReportCount} reportCount={reportCount} analystName={analystName} resetTrigger={resetTrigger} />
          </div>
        </div>
      </div>

      {/* Reset Confirmation Modal */}
      {showResetModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div
            className="absolute inset-0 bg-black/70"
            onClick={() => !isResetting && setShowResetModal(false)}
          />
          <div className="relative bg-[#161b22] border border-gray-700 rounded-xl p-6 w-full max-w-md mx-4 shadow-2xl">
            <h3 className="text-lg font-semibold text-white text-center mb-4">Reset Simulation</h3>
            <p className="text-gray-400 mb-6 text-center">
              This will clear all events, alerts, and reports. Your progress will be reset to Level 1. This action cannot be undone.
            </p>
            <div className="flex justify-center gap-3">
              <button
                onClick={() => setShowResetModal(false)}
                disabled={isResetting}
                className="px-2 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm font-medium rounded-md bg-[#21262d] hover:bg-[#30363d] text-gray-300 border border-gray-600 transition disabled:opacity-50"
              >
                No, go back
              </button>
              <button
                onClick={handleResetSimulator}
                disabled={isResetting}
                className="px-2 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm font-medium rounded-md bg-[#21262d] hover:bg-[#30363d] text-gray-300 border border-gray-600 transition disabled:opacity-50 inline-flex items-center gap-2"
              >
                {isResetting ? (
                  <>
                    <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Resetting...
                  </>
                ) : (
                  'Yes, reset it'
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Start Training Info Modal */}
      {showSimulateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div
            className="absolute inset-0 bg-black/70"
            onClick={() => setShowSimulateModal(false)}
          />
          <div className="relative bg-[#161b22] border border-gray-700 rounded-xl p-6 w-full max-w-md mx-4 shadow-2xl">
            <h3 className="text-lg font-semibold text-white text-center mb-4">Simulation Active</h3>
            <p className="text-gray-400 mb-6 text-center">
              You have <span className="text-white font-medium">{existingLogCount} events</span> from an active session. Use <span className="text-white font-medium">Reset Simulation</span> to restart from Level 1.
            </p>
            <div className="flex justify-center">
              <button
                onClick={() => setShowSimulateModal(false)}
                className="px-2 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm font-medium rounded-md bg-[#21262d] hover:bg-[#30363d] text-gray-300 border border-gray-600 transition"
              >
                Got it
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Difficulty Selection Modal */}
      {showDifficultyModal && (
        <DifficultySelector
          onSelect={handleDifficultySelect}
          onCancel={() => setShowDifficultyModal(false)}
        />
      )}

      {/* Failure Modal (Hardcore Mode) */}
      {showFailureModal && (
        <FailureModal
          category={failureCategory}
          failureType={failureType}
          onRetry={handleFailureRetry}
          onQuit={handleFailureRestart}
        />
      )}
    </div>
  );
};

export default Dashboard;
