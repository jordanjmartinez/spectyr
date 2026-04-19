import React, { useState, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
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
  const [analyticsCount, setAnalyticsCount] = useState(0);
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

  // Auto-detect new incidents as alerts drip into the queue (injected_count increases)
  const lastInjectedRef = useRef(0);
  useEffect(() => {
    const checkForIncidents = () => {
      apiFetch('/api/game-state')
        .then(res => res.json())
        .then(data => {
          const injected = data.injected_count ?? 0;
          if (injected > lastInjectedRef.current) {
            const delta = injected - lastInjectedRef.current;
            if (view !== 'grouped') {
              setIncidentBadge(prev => prev + delta);
            }
          }
          lastInjectedRef.current = injected;
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

  const timerSlot = document.getElementById('navbar-timer-slot');

  return (
    <div className="min-h-screen bg-[#0d1117] text-white pt-0 pb-8 flex flex-col">
      {timerSlot && createPortal(
        <GameTimer onTimeout={handleTimeout} disabled={showFailureModal} />,
        timerSlot
      )}
      <div className="flex flex-col flex-1 gap-2 sm:gap-4">

        <div className="bg-[#161b22] p-3 sm:p-6 flex-1 flex flex-col">
          <div className="flex overflow-x-auto [&::-webkit-scrollbar]:hidden [scrollbar-width:none] border-b border-gray-700 mb-6">
            <button
              onClick={() => {
                setView("grouped");
                setIncidentBadge(0);
              }}
              className={`relative py-3 sm:py-4 px-2 sm:px-6 text-[13px] sm:text-base whitespace-nowrap font-medium flex items-center justify-center transition-colors duration-200 ${
                view === "grouped" ? "text-white" : "text-gray-400 hover:text-white"
              }`}
            >
              <span className="relative">
                Alerts
                <span
                  className={`absolute left-0 right-0 h-0.5 -bottom-[13px] sm:-bottom-[17px] ${
                    view === "grouped" ? "bg-white" : "bg-transparent"
                  }`}
                />
              </span>
              {groupedAlertCount > 0 && <span className="text-gray-500 font-normal ml-1.5">{groupedAlertCount}</span>}
            </button>
            <button
              onClick={() => setView("table")}
              className={`relative py-3 sm:py-4 px-2 sm:px-6 text-[13px] sm:text-base whitespace-nowrap font-medium flex items-center justify-center transition-colors duration-200 ${
                view === "table" ? "text-white" : "text-gray-400 hover:text-white"
              }`}
            >
              <span className="relative">
                Events
                <span
                  className={`absolute left-0 right-0 h-0.5 -bottom-[13px] sm:-bottom-[17px] ${
                    view === "table" ? "bg-white" : "bg-transparent"
                  }`}
                />
              </span>
            </button>
            <button
              onClick={() => setView("analytics")}
              className={`relative py-3 sm:py-4 px-2 sm:px-6 text-[13px] sm:text-base whitespace-nowrap font-medium flex items-center justify-center transition-colors duration-200 ${
                view === "analytics" ? "text-white" : "text-gray-400 hover:text-white"
              }`}
            >
              <span className="relative">
                Metrics
                <span
                  className={`absolute left-0 right-0 h-0.5 -bottom-[13px] sm:-bottom-[17px] ${
                    view === "analytics" ? "bg-white" : "bg-transparent"
                  }`}
                />
              </span>
              {analyticsCount > 0 && <span className="text-gray-500 font-normal ml-1.5">{analyticsCount}</span>}
            </button>
            <button
              onClick={() => setView("reports")}
              className={`relative py-3 sm:py-4 px-2 sm:px-6 text-[13px] sm:text-base whitespace-nowrap font-medium flex items-center justify-center transition-colors duration-200 ${
                view === "reports" ? "text-white" : "text-gray-400 hover:text-white"
              }`}
            >
              <span className="relative">
                Reports
                <span
                  className={`absolute left-0 right-0 h-0.5 -bottom-[13px] sm:-bottom-[17px] ${
                    view === "reports" ? "bg-white" : "bg-transparent"
                  }`}
                />
              </span>
              {reportCount > 0 && <span className="text-gray-500 font-normal ml-1.5">{reportCount}</span>}
            </button>
          </div>

          <div className={view === "grouped" ? "block" : "hidden"}>
            <GroupedAlerts resetTrigger={resetTrigger} onHardcoreFailure={handleHardcoreFailure} onReset={() => { handleResetSimulator(); setView("table"); }} isVisible={view === "grouped"} setGroupedAlertCount={setGroupedAlertCount} />
          </div>

          <div className={view === "table" ? "block" : "hidden"}>
            <div className="flex flex-row items-center justify-between mb-3 gap-2 sm:gap-3">
              <h2 className="text-xl sm:text-2xl font-semibold text-white whitespace-nowrap">
                Events <span className={`font-normal ml-1 ${alertCount > 0 ? "text-gray-500" : "invisible"}`}>{alertCount || "0"}</span>
              </h2>
              <div className="flex items-center gap-2 sm:gap-4">
                <button
                  onClick={handleSimulateEvents}
                  className="inline-flex items-center px-2 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm font-medium rounded-md bg-[#21262d] hover:bg-[#30363d] text-gray-200 border border-gray-600 transition focus:outline-none focus:ring-2 focus:ring-gray-500"
                >
                  <span className="sm:hidden">Start Sim</span><span className="hidden sm:inline">Start Simulation</span>
                </button>
                <button
                  onClick={() => setShowResetModal(true)}
                  className="inline-flex items-center px-2 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm font-medium rounded-md bg-[#21262d] hover:bg-[#30363d] text-gray-200 border border-gray-600 transition focus:outline-none focus:ring-2 focus:ring-gray-500"
                >
                  <span className="sm:hidden">Reset Sim</span><span className="hidden sm:inline">Reset Simulation</span>
                </button>
              </div>
            </div>
            <AlertTable setAlertCount={setAlertCount} resetTrigger={resetTrigger} />
          </div>

          <div className={view === "analytics" ? "block" : "hidden"}>
            <Analytics onReset={() => setShowResetModal(true)} analystName={analystName} setAnalyticsCount={setAnalyticsCount} />
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
          <div className="relative bg-[#161b22] border border-gray-700 rounded-xl p-6 w-full max-w-md mx-4 shadow-2xl animate-modalIn">
            <button
              type="button"
              onClick={() => !isResetting && setShowResetModal(false)}
              aria-label="Close"
              className="absolute top-3 right-3 p-1 text-gray-400 hover:text-white transition-colors"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
            <h3 className="text-lg font-semibold text-white mb-4">Reset Simulation</h3>
            <div className="mb-5" style={{ height: '1px', background: 'linear-gradient(to right, rgba(88,130,180,0.3), transparent)' }} />
            <p className="text-gray-400 mb-6">
              This will clear all events, alerts, and reports. Your progress will be reset. This action cannot be undone.
            </p>
            <div className="flex justify-end">
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
          <div className="relative bg-[#161b22] border border-gray-700 rounded-xl p-6 w-full max-w-md mx-4 shadow-2xl animate-modalIn">
            <button
              type="button"
              onClick={() => setShowSimulateModal(false)}
              aria-label="Close"
              className="absolute top-3 right-3 p-1 text-gray-400 hover:text-white transition-colors"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
            <h3 className="text-lg font-semibold text-white mb-4">Simulation Active</h3>
            <div className="mb-5" style={{ height: '1px', background: 'linear-gradient(to right, rgba(88,130,180,0.3), transparent)' }} />
            <p className="text-gray-400">
              You have <span className="text-white font-medium">{existingLogCount} events</span> from an active session. Use <span className="text-white font-medium">Reset Simulation</span> to start fresh.
            </p>
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
