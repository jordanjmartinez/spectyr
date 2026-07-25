import React, { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { apiFetch } from '../api';
import Siem from '../components/Siem';
import Incidents from '../components/Incidents';
import IncidentDashboard from '../components/IncidentDashboard';
import Analytics from '../components/Analytics';
import Reports from '../components/Reports';
import Endpoints from '../components/Endpoints';
import Detections from '../components/Detections';
import DifficultySelector from '../components/DifficultySelector';
import GameTimer from '../components/GameTimer';
import FailureModal from '../components/FailureModal';

const Dashboard = () => {
  const [alertCount, setAlertCount] = useState(0);
  const [groupedAlertCount, setGroupedAlertCount] = useState(0);
  const [reportCount, setReportCount] = useState(0);
  const [analyticsCount, setAnalyticsCount] = useState(0);
  const [view, setView] = useState("dashboard");
  // Stage 3.9B: the active-incident context (opaque INC id). Pure UI state, never
  // a server mutation; scopes the incident-aware tabs when set, session-wide when
  // null. Selecting/switching never mutates world/scoring/readiness/submission.
  const [activeIncidentId, setActiveIncidentId] = useState(null);
  const [resetTrigger, setResetTrigger] = useState(0);
  const [showResetModal, setShowResetModal] = useState(false);
  const [isResetting, setIsResetting] = useState(false);
  const [showSimulateModal, setShowSimulateModal] = useState(false);
  const [showDifficultyModal, setShowDifficultyModal] = useState(false);
  const [practiceAnother, setPracticeAnother] = useState(false); // opens picker at the Guided catalog
  const [showFailureModal, setShowFailureModal] = useState(false);
  const [failureCategory, setFailureCategory] = useState(null);
  const [failureType, setFailureType] = useState(null); // 'timeout' or 'wrong_answer'
  const [analystName, setAnalystName] = useState(null);
  const [gameMode, setGameMode] = useState('training');
  const [incidentBadge, setIncidentBadge] = useState(0);
  const [simActive, setSimActive] = useState(false);
  const [endpointCount, setEndpointCount] = useState(0);
  const [detectionCount, setDetectionCount] = useState(0);
  const [pivotHost, setPivotHost] = useState(null);
  // Stage 4 P7.2: Open Evidence Timeline descent requests (contract Sections
  // 13/16). The request carries ONLY observable data supplied by the origin
  // surface (origin label, participant hostnames, the player-selected
  // incident context); the SIEM shell generates the query through the one
  // generator. seq retriggers identical consecutive descents.
  const [descentRequest, setDescentRequest] = useState(null);
  const descentSeqRef = useRef(0);

  // Host pivot: a hostname link in an event view opens that endpoint page.
  const handleHostPivot = (hostname) => {
    setPivotHost({ value: hostname, ts: Date.now() });
    setView('endpoints');
  };

  const handleEvidenceDescent = (req) => {
    descentSeqRef.current += 1;
    setDescentRequest({ ...req, seq: descentSeqRef.current });
    setView('siem');
  };

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) return;
      switch (e.key) {
        case '1': setView('dashboard'); break;
        case '2': setView('incidents'); setIncidentBadge(0); break;
        case '3': setView('siem'); break;
        case '4': setView('detections'); break;
        case '5': setView('endpoints'); break;
        case '6': setView('analytics'); break;
        case '7': setView('reports'); break;
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
          if (data.game_mode) setGameMode(data.game_mode);
          const injected = data.injected_count ?? 0;
          if (injected > lastInjectedRef.current) {
            const delta = injected - lastInjectedRef.current;
            if (view !== 'incidents') {
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

  // Stage 4 P8.1 (scaffold Section 3.5): session existence comes from
  // /api/game-state (analyst_name set once a run started), not from counting
  // the legacy event feed. The feed route retires in P8.3.
  const handleSimulateEvents = async () => {
    try {
      const res = await apiFetch('/api/game-state');
      const data = await res.json();
      if (data.analyst_name) {
        setShowSimulateModal(true);
      } else {
        setShowDifficultyModal(true);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleDifficultySelect = async (mode, name, catalogId) => {
    setShowDifficultyModal(false);
    setPracticeAnother(false);
    setAnalystName(name);
    try {
      await apiFetch('/api/start-simulator', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // Guided carries an opaque catalog_id (or "random"); other modes omit it.
        body: JSON.stringify({ game_mode: mode, analyst_name: name, ...(catalogId ? { catalog_id: catalogId } : {}) })
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
      // A reset destroys the session's incidents; no case survives it, so
      // the pinned case clears here (explicit destructive act, not an
      // implicit case change).
      setActiveIncidentId(null);
      setResetTrigger(prev => prev + 1);
      setShowResetModal(false);
    } catch (err) {
      console.error(err);
    } finally {
      setIsResetting(false);
    }
  };

  // Guided Practice Another: clear the current run (reset-simulator wipes
  // submissions + world) and return to the answer-neutral picker. The warning is
  // shown in the Incidents Review before this runs.
  const handlePracticeAnother = async () => {
    await handleResetSimulator();
    setActiveIncidentId(null);
    setPracticeAnother(true);       // open the picker straight at the Guided catalog
    setShowDifficultyModal(true);
  };

  const tabs = [
    { key: 'dashboard', label: 'Dashboard', count: 0,
      icon: 'M4 5a1 1 0 011-1h5a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM14 5a1 1 0 011-1h4a1 1 0 011 1v3a1 1 0 01-1 1h-4a1 1 0 01-1-1V5zM14 13a1 1 0 011-1h4a1 1 0 011 1v6a1 1 0 01-1 1h-4a1 1 0 01-1-1v-6zM4 15a1 1 0 011-1h5a1 1 0 011 1v4a1 1 0 01-1 1H5a1 1 0 01-1-1v-4z' },
    { key: 'incidents', label: 'Incidents', count: groupedAlertCount,
      icon: 'M12 9v2m0 4h.01M5 19h14a2 2 0 001.84-2.75L13.74 4a2 2 0 00-3.48 0L3.16 16.25A2 2 0 005 19z' },
    { key: 'siem', label: 'SIEM', count: alertCount,
      icon: 'M4 6h16M4 10h16M4 14h16M4 18h16' },
    { key: 'detections', label: 'Detections', count: detectionCount,
      icon: 'M12 9v2m0 4h.01M5 19h14a2 2 0 001.84-2.75L13.74 4a2 2 0 00-3.48 0L3.16 16.25A2 2 0 005 19z' },
    { key: 'endpoints', label: 'Endpoints', count: endpointCount,
      icon: 'M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z' },
    { key: 'analytics', label: 'Metrics', count: analyticsCount,
      icon: 'M9 19v-6m4 6V5m4 14v-9M5 21h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v14a2 2 0 002 2z' },
    { key: 'reports', label: 'Reports', count: reportCount,
      icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z' },
  ];

  return (
    <div className="min-h-screen flex bg-[#f6f8fa] text-[#1a2332]">
      {/* Navy nav rail */}
      <aside className="sticky top-0 self-start h-screen w-16 lg:w-56 shrink-0 bg-[#101218] text-gray-300 flex flex-col z-30">
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
                onClick={() => { setView(t.key); if (t.key === 'incidents') setIncidentBadge(0); }}
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
              className="liquid-btn flex items-center justify-center gap-2 rounded-md px-3 py-2 text-sm font-medium text-white"
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
              className="liquid-btn flex items-center justify-center gap-2 rounded-md px-3 py-2 text-sm font-semibold text-white"
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
        {/* Stage 5 Phase 1 (Amendment 1 Delta A): the global focus banner is
            REPLACED by the per-surface pinned case header ("Investigating
            INC-####" / "All activity") on Detections, Endpoints, and the
            SIEM. The case changes only by explicit selection (or the
            explicit Clear selection control) on Incidents -- OD-15 is
            structural: no other control mutates activeIncidentId. */}
        <div className={view === "dashboard" ? "block" : "hidden"}>
          <IncidentDashboard
            gameMode={gameMode}
            analystName={analystName}
            activeIncidentId={activeIncidentId}
            onSelectIncident={setActiveIncidentId}
            onNavigate={setView}
            onReset={() => setShowResetModal(true)}
            isVisible={view === "dashboard"}
          />
        </div>

        <div className={view === "incidents" ? "block" : "hidden"}>
          <Incidents
            isVisible={view === "incidents"}
            resetTrigger={resetTrigger}
            onHardcoreFailure={handleHardcoreFailure}
            onReset={() => setShowResetModal(true)}
            gameMode={gameMode}
            activeIncidentId={activeIncidentId}
            onSelectIncident={setActiveIncidentId}
            onNavigate={setView}
            setGroupedAlertCount={setGroupedAlertCount}
            onPracticeAnother={handlePracticeAnother}
            onEvidenceDescent={handleEvidenceDescent}
          />
        </div>

        <div className={view === "siem" ? "block" : "hidden"}>
          <Siem setSiemCount={setAlertCount} resetTrigger={resetTrigger} onHostPivot={handleHostPivot} activeIncidentId={activeIncidentId} descentRequest={descentRequest} onNavigate={setView} />
        </div>

        <div className={view === "detections" ? "block" : "hidden"}>
          <Detections isVisible={view === "detections"} resetTrigger={resetTrigger} setDetectionCount={setDetectionCount} onHostPivot={handleHostPivot} activeIncidentId={activeIncidentId} onEvidenceDescent={handleEvidenceDescent} />
        </div>

        <div className={view === "endpoints" ? "block" : "hidden"}>
          <Endpoints isVisible={view === "endpoints"} resetTrigger={resetTrigger} setEndpointCount={setEndpointCount} pivotHost={pivotHost} activeIncidentId={activeIncidentId} />
        </div>

        <div className={view === "analytics" ? "block" : "hidden"}>
          <Analytics onReset={() => setShowResetModal(true)} analystName={analystName} setAnalyticsCount={setAnalyticsCount} isVisible={view === "analytics"} />
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
                className="inline-flex items-center justify-center gap-2 px-2 sm:px-3 py-1.5 sm:py-2 text-xs font-medium rounded-md border transition bg-[#101218] hover:bg-[#1e2330] text-white border-transparent focus:outline-none focus:ring-2 focus:ring-[#8b949e] disabled:opacity-50"
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
              A simulation session is already active. Use <span className="text-[#1a2332] font-medium">Reset Simulation</span> to start fresh.
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
          onCancel={() => { setShowDifficultyModal(false); setPracticeAnother(false); }}
          initialStep={practiceAnother ? 'catalog' : 'mode'}
          initialName={practiceAnother ? (analystName || '') : ''}
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
