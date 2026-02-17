import React, { useState, useEffect } from 'react';
import AlertTable from '../components/AlertTable';
import GroupedAlerts from '../components/GroupedAlerts';
import Analytics from '../components/Analytics';
import Reports from '../components/Reports';
import DifficultySelector from '../components/DifficultySelector';
import GameTimer from '../components/GameTimer';
import FailureModal from '../components/FailureModal';

const Dashboard = () => {
  const [alertCount, setAlertCount] = useState(0);
  const [reportCount, setReportCount] = useState(0);
  const [view, setView] = useState("grouped");
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

  const handleNewIncident = () => {
    if (view !== 'grouped') {
      setIncidentBadge(prev => prev + 1);
    }
  };

  const handleSimulateEvents = async () => {
    try {
      const res = await fetch('http://localhost:5000/api/fake-events');
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
      await fetch('http://localhost:5000/api/start-simulator', {
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
      const res = await fetch('http://localhost:5000/api/current-level');
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

  const handleResetSimulator = async () => {
    setIsResetting(true);
    try {
      await fetch('http://localhost:5000/api/reset-simulator', {
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
    <div className="min-h-screen bg-[#0d1117] text-white py-8 px-4 sm:px-8 lg:px-16">
      <div className="max-w-7xl mx-auto space-y-8">

        <header className="flex justify-between items-start">
          <div>
            <h1 className="text-4xl font-bold text-white mb-2">SIEM Dashboard</h1>
            <p className="text-lg text-gray-400">Real-time alert monitoring and log analysis</p>
          </div>
          <GameTimer onTimeout={handleTimeout} />
        </header>

        <div className="bg-[#161b22] rounded-xl p-6">
          <div className="flex border-b border-gray-700 mb-6">
            <button
              onClick={() => {
                setView("grouped");
                setIncidentBadge(0);
              }}
              className={`w-36 text-center py-4 text-lg font-medium border-b-2 transition-all duration-200 relative ${
                view === "grouped"
                  ? "border-gray-300 text-white"
                  : "border-transparent text-gray-400 hover:text-white"
              }`}
            >
              Incidents<span className={incidentBadge > 0 && view !== "grouped" ? "" : "invisible"}> ({incidentBadge || 1})</span>
            </button>
            <button
              onClick={() => setView("table")}
              className={`w-36 text-center py-4 text-lg font-medium border-b-2 transition-all duration-200 ${
                view === "table"
                  ? "border-gray-300 text-white"
                  : "border-transparent text-gray-400 hover:text-white"
              }`}
            >
              Events
            </button>
            <button
              onClick={() => setView("analytics")}
              className={`w-36 text-center py-4 text-lg font-medium border-b-2 transition-all duration-200 ${
                view === "analytics"
                  ? "border-gray-300 text-white"
                  : "border-transparent text-gray-400 hover:text-white"
              }`}
            >
              Grade
            </button>
            <button
              onClick={() => setView("reports")}
              className={`w-36 text-center py-4 text-lg font-medium border-b-2 transition-all duration-200 ${
                view === "reports"
                  ? "border-gray-300 text-white"
                  : "border-transparent text-gray-400 hover:text-white"
              }`}
            >
              Reports
            </button>
          </div>

          <div className={view === "grouped" ? "block" : "hidden"}>
            <GroupedAlerts resetTrigger={resetTrigger} onHardcoreFailure={handleHardcoreFailure} onReset={() => { handleResetSimulator(); setView("table"); }} isVisible={view === "grouped"} />
          </div>

          <div className={view === "table" ? "block" : "hidden"}>
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-semibold text-white">
                Events <span className="text-gray-500 font-normal">({alertCount})</span>
              </h2>
              <div className="flex items-center gap-4">
                <button
                  onClick={handleSimulateEvents}
                  className="inline-flex items-center px-4 py-2 text-base font-medium rounded-md bg-[#21262d] hover:bg-[#30363d] text-gray-200 border border-gray-600 transition focus:outline-none focus:ring-2 focus:ring-gray-500"
                >
                  Start Training
                </button>
                <button
                  onClick={() => setShowResetModal(true)}
                  className="inline-flex items-center px-4 py-2 text-base font-medium rounded-md bg-[#21262d] hover:bg-[#30363d] text-gray-200 border border-gray-600 transition focus:outline-none focus:ring-2 focus:ring-gray-500"
                >
                  Clear Logs
                </button>
              </div>
            </div>
            <AlertTable setAlertCount={setAlertCount} resetTrigger={resetTrigger} onHardcoreFailure={handleHardcoreFailure} onNewIncident={handleNewIncident} />
          </div>

          <div className={view === "analytics" ? "block" : "hidden"}>
            <Analytics />
          </div>

          <div className={view === "reports" ? "block" : "hidden"}>
            <Reports setReportCount={setReportCount} reportCount={reportCount} analystName={analystName} />
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
            <h3 className="text-lg font-semibold text-white text-center mb-4">Reset Training</h3>
            <p className="text-gray-400 mb-6 text-center">
              This will clear all logs, incidents, and reports. Your progress will be reset to Level 1. This action cannot be undone.
            </p>
            <div className="flex justify-center gap-3">
              <button
                onClick={() => setShowResetModal(false)}
                disabled={isResetting}
                className="px-4 py-2 text-sm font-medium rounded-md bg-[#21262d] hover:bg-[#30363d] text-gray-300 border border-gray-600 transition disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                onClick={handleResetSimulator}
                disabled={isResetting}
                className="px-4 py-2 text-sm font-medium rounded-md bg-[#21262d] hover:bg-[#30363d] text-gray-300 border border-gray-600 transition disabled:opacity-50 inline-flex items-center gap-2"
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
                  'Clear Logs'
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
              You have <span className="text-white font-medium">{existingLogCount} events</span> from an active session. Use <span className="text-white font-medium">Clear Logs</span> to restart from Level 1.
            </p>
            <div className="flex justify-center">
              <button
                onClick={() => setShowSimulateModal(false)}
                className="px-4 py-2 text-sm font-medium rounded-md bg-[#21262d] hover:bg-[#30363d] text-gray-300 border border-gray-600 transition"
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
          onRestart={handleFailureRestart}
        />
      )}
    </div>
  );
};

export default Dashboard;
