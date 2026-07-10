import React, { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
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
  const [pivotQuery, setPivotQuery] = useState(null);
  const [simActive, setSimActive] = useState(false);

  // Analyst-mode entity pivot: a chip click in the Alerts tab jumps to the
  // Events stream pre-filtered to that entity value.
  const handlePivot = (query) => {
    setPivotQuery({ value: query, ts: Date.now() });
    setView('table');
  };

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
          setSimActive(!!data.analyst_name);
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

  const tabs = [
    { key: 'grouped', label: 'Alerts', count: groupedAlertCount,
      icon: 'M12 9v2m0 4h.01M5 19h14a2 2 0 001.84-2.75L13.74 4a2 2 0 00-3.48 0L3.16 16.25A2 2 0 005 19z' },
    { key: 'table', label: 'Events', count: alertCount,
      icon: 'M4 6h16M4 10h16M4 14h16M4 18h16' },
    { key: 'analytics', label: 'Metrics', count: analyticsCount,
      icon: 'M9 19v-6m4 6V5m4 14v-9M5 21h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v14a2 2 0 002 2z' },
    { key: 'reports', label: 'Reports', count: reportCount,
      icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z' },
  ];

  return (
    <div className="min-h-screen flex bg-[#f6f8fa] text-[#1a2332]">
      {/* Navy nav rail */}
      <aside className="sticky top-0 self-start h-screen w-16 lg:w-56 shrink-0 bg-[#0f2942] text-gray-300 flex flex-col z-30">
        <Link
          to="/"
          title="Back to home"
          className="flex items-center gap-2.5 h-16 px-3 lg:px-5 border-b border-white/10 hover:bg-white/5 transition-colors"
        >
          <img src="/spectyr_logo.png" alt="Spectyr" className="h-10 w-10 object-contain shrink-0" />
          <span className="hidden lg:inline text-xl font-semibold tracking-tight text-white" style={{ fontFamily: "'IBM Plex Sans', sans-serif" }}>Spectyr</span>
        </Link>

        <nav className="flex-1 py-3 px-2 lg:px-3 flex flex-col gap-1">
          {tabs.map(t => {
            const active = view === t.key;
            return (
              <button
                key={t.key}
                onClick={() => { setView(t.key); if (t.key === 'grouped') setIncidentBadge(0); }}
                title={t.label}
                className={`group relative flex items-center gap-3 rounded-md px-3 py-2.5 text-sm font-medium transition-colors ${
                  active ? 'bg-white/10 text-white' : 'text-gray-400 hover:bg-white/5 hover:text-white'
                }`}
              >
                {active && <span className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-full bg-white" />}
                <svg className="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d={t.icon} />
                </svg>
                <span className="hidden lg:inline flex-1 text-left">{t.label}</span>
                {t.count > 0 && <span className="hidden lg:inline text-xs text-gray-400">{t.count}</span>}
                {t.count > 0 && <span className="lg:hidden absolute top-1 right-1 w-1.5 h-1.5 rounded-full bg-white/70" />}
              </button>
            );
          })}
        </nav>

        <div className="px-2 lg:px-3 mb-1">
          <Link
            to="/docs"
            title="Documentation"
            className="flex items-center gap-3 rounded-md px-3 py-2.5 text-sm font-medium text-gray-400 hover:bg-white/5 hover:text-white transition-colors"
          >
            <svg className="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.247m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.247" />
            </svg>
            <span className="hidden lg:inline">Docs</span>
          </Link>
        </div>

        <div className="mt-auto p-2 lg:p-3 border-t border-white/10 flex flex-col gap-2">
          <GameTimer onTimeout={handleTimeout} disabled={showFailureModal} />
          {simActive ? (
            <button
              onClick={() => setShowResetModal(true)}
              title="Reset Simulation"
              className="flex items-center justify-center gap-2 rounded-md px-3 py-2 text-sm font-medium border border-white/20 text-white hover:bg-white/10 transition"
            >
              <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              <span className="hidden lg:inline">Reset</span>
            </button>
          ) : (
            <button
              onClick={handleSimulateEvents}
              title="Start Simulation"
              className="flex items-center justify-center gap-2 rounded-md px-3 py-2 text-sm font-semibold bg-white text-[#0f2942] hover:bg-gray-100 transition"
            >
              <svg className="w-4 h-4 shrink-0" fill="currentColor" viewBox="0 0 24 24">
                <path d="M8 5v14l11-7z" />
              </svg>
              <span className="hidden lg:inline">Start</span>
            </button>
          )}
        </div>
      </aside>

      {/* Light content */}
      <main className="flex-1 min-w-0 p-4 sm:p-6 overflow-x-hidden">
        <div className={view === "grouped" ? "block" : "hidden"}>
          <GroupedAlerts resetTrigger={resetTrigger} onHardcoreFailure={handleHardcoreFailure} onReset={() => { handleResetSimulator(); setView("table"); }} isVisible={view === "grouped"} setGroupedAlertCount={setGroupedAlertCount} onPivot={handlePivot} />
        </div>

        <div className={view === "table" ? "block" : "hidden"}>
          <h2 className="text-xl sm:text-2xl font-semibold text-[#1a2332] whitespace-nowrap mb-3">
            Events <span className={`font-normal ml-1 ${alertCount > 0 ? "text-gray-400" : "invisible"}`}>{alertCount || "0"}</span>
          </h2>
          <AlertTable setAlertCount={setAlertCount} resetTrigger={resetTrigger} pivotQuery={pivotQuery} />
        </div>

        <div className={view === "analytics" ? "block" : "hidden"}>
          <Analytics onReset={() => setShowResetModal(true)} analystName={analystName} setAnalyticsCount={setAnalyticsCount} />
        </div>

        <div className={view === "reports" ? "block" : "hidden"}>
          <Reports setReportCount={setReportCount} reportCount={reportCount} analystName={analystName} resetTrigger={resetTrigger} />
        </div>
      </main>

      {/* Reset Confirmation Modal */}
      {showResetModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div
            className="absolute inset-0 bg-black/70"
            onClick={() => !isResetting && setShowResetModal(false)}
          />
          <div className="relative bg-white border border-[#e2e6ea] rounded-xl p-6 w-full max-w-md mx-4 shadow-2xl animate-modalIn">
            <button
              type="button"
              onClick={() => !isResetting && setShowResetModal(false)}
              aria-label="Close"
              className="absolute top-3 right-3 p-1 text-[#57606a] hover:text-[#1a2332] transition-colors"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
            <h3 className="text-lg font-semibold text-[#1a2332] mb-4">Reset Simulation</h3>
            <p className="text-[#57606a] mb-6">
              This will clear all events, alerts, and reports. Your progress will be reset. This action cannot be undone.
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setShowResetModal(false)}
                disabled={isResetting}
                className="inline-flex items-center justify-center px-2 sm:px-3 py-1.5 sm:py-2 text-xs font-medium rounded-md border transition bg-white hover:bg-[#eef1f4] text-[#57606a] border-[#d0d7de] focus:outline-none focus:ring-2 focus:ring-[#8b949e] disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                onClick={handleResetSimulator}
                disabled={isResetting}
                className="inline-flex items-center justify-center gap-2 px-2 sm:px-3 py-1.5 sm:py-2 text-xs font-medium rounded-md border transition bg-[#1a2332] hover:bg-[#0f2942] text-white border-transparent focus:outline-none focus:ring-2 focus:ring-[#8b949e] disabled:opacity-50"
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
                  'Reset'
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
          <div className="relative bg-white border border-[#e2e6ea] rounded-xl p-6 w-full max-w-md mx-4 shadow-2xl animate-modalIn">
            <button
              type="button"
              onClick={() => setShowSimulateModal(false)}
              aria-label="Close"
              className="absolute top-3 right-3 p-1 text-[#57606a] hover:text-[#1a2332] transition-colors"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
            <h3 className="text-lg font-semibold text-[#1a2332] mb-4">Simulation Active</h3>
            <div className="mb-5" style={{ height: '1px', background: 'linear-gradient(to right, rgba(0,0,0,0.08), transparent)' }} />
            <p className="text-[#57606a] mb-6">
              You have <span className="text-[#1a2332] font-medium">{existingLogCount} events</span> from an active session. Use <span className="text-[#1a2332] font-medium">Reset Simulation</span> to start fresh.
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setShowSimulateModal(false)}
                className="inline-flex items-center justify-center px-2 sm:px-3 py-1.5 sm:py-2 text-xs font-medium rounded-md border transition bg-white hover:bg-[#eef1f4] text-[#57606a] border-[#d0d7de] focus:outline-none focus:ring-2 focus:ring-[#8b949e]"
              >
                Cancel
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
