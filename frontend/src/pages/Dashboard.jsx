import React, { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { ToastContainer } from 'react-toastify';
import { apiFetch } from '../api';
import Siem from '../components/Siem';
import Incidents from '../components/Incidents';
import IncidentDashboard from '../components/IncidentDashboard';
import Analytics from '../components/Analytics';
import Endpoints from '../components/Endpoints';
import Detections from '../components/Detections';
import Response from '../components/Response';
import DifficultySelector from '../components/DifficultySelector';
import GameTimer from '../components/GameTimer';
import FailureModal from '../components/FailureModal';
import HintPanel from '../components/HintPanel';
import { hintsAllowed } from '../components/helpContent';
import { NAV_ICONS, NAV_STROKE, ChromeIcons } from '../components/icons';
import AppHeader from '../components/AppHeader';
import BrandLockup from '../components/BrandLockup';
import StartButton, { CTA_PILL } from '../components/StartButton';

// Stage 6 playtest fix: the reset POST is bounded. A stalled request aborts
// after this long and surfaces an error in the dialog instead of holding it
// on "Resetting..." forever.
const RESET_TIMEOUT_MS = 10000;

// Owner sidebar redesign (2026-10-12): the pin preference persists per
// browser. Chrome preference only -- never session or grading state.
const RAIL_PIN_KEY = 'spectyr_rail_pinned';

const Dashboard = () => {
  const [groupedAlertCount, setGroupedAlertCount] = useState(0);
  const [analyticsCount, setAnalyticsCount] = useState(0);
  const [view, setView] = useState("dashboard");
  // Stage 3.9B: the active-incident context (opaque INC id). Pure UI state, never
  // a server mutation; scopes the incident-aware tabs when set, session-wide when
  // null. Selecting/switching never mutates world/scoring/readiness/submission.
  const [activeIncidentId, setActiveIncidentId] = useState(null);
  // VA1: the selected incident's observable summary, reported up by the
  // Incidents workspace (which already polls the list) so every page can
  // render the ONE context pill without a new request.
  const [activeIncident, setActiveIncident] = useState(null);
  // A3.4 (ratified A3-OD-3): the SHELL-OWNED classification selection per
  // incident ({verdict, category, categoryId}). Every player-facing Ready
  // surface (Incidents workspace + list, this dashboard's rows) derives
  // readiness from this one state through submissionReady(); local input
  // only, never a request; cleared with the session.
  const [chosen, setChosen] = useState({});
  const [resetTrigger, setResetTrigger] = useState(0);
  const [showResetModal, setShowResetModal] = useState(false);
  const [isResetting, setIsResetting] = useState(false);
  // Stage 6 playtest fix: the reset request is bounded (abortable, 10s
  // timeout) and failures surface in the dialog instead of freezing it.
  const [resetError, setResetError] = useState(null);
  const resetAbortRef = useRef(null);
  const [showSimulateModal, setShowSimulateModal] = useState(false);
  // Stage 6 playtest fix (mobile rail): below md the rail is an off-canvas
  // drawer behind a header hamburger. isMobileViewport (matchMedia, guarded
  // for test environments without it) decides which single GameTimer
  // instance mounts -- rail on desktop, header slot on mobile -- so the
  // timer never polls twice and stays visible during a Hardcore run with
  // the drawer closed.
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [isMobileViewport, setIsMobileViewport] = useState(() =>
    typeof window !== 'undefined' && typeof window.matchMedia === 'function'
      ? window.matchMedia('(max-width: 767px)').matches
      : false
  );
  useEffect(() => {
    if (typeof window.matchMedia !== 'function') return undefined;
    const mq = window.matchMedia('(max-width: 767px)');
    const onChange = (e) => {
      setIsMobileViewport(e.matches);
      if (!e.matches) setMobileNavOpen(false); // drawer is a below-md surface
    };
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  // Owner sidebar redesign (2026-10-12): the lg-and-up watcher (pinning
  // applies only where the expanded panel fits in flow) plus the pin/hover
  // state pair behind the floating-panel rail.
  const [isLgUp, setIsLgUp] = useState(() =>
    typeof window !== 'undefined' && typeof window.matchMedia === 'function'
      ? window.matchMedia('(min-width: 1024px)').matches
      : true
  );
  useEffect(() => {
    if (typeof window.matchMedia !== 'function') return undefined;
    const mq = window.matchMedia('(min-width: 1024px)');
    const onChange = (e) => setIsLgUp(e.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);
  const [railPinned, setRailPinnedState] = useState(() => {
    try { return window.localStorage.getItem(RAIL_PIN_KEY) !== '0'; } catch (e) { return true; }
  });
  const setRailPinned = (v) => {
    setRailPinnedState(v);
    try { window.localStorage.setItem(RAIL_PIN_KEY, v ? '1' : '0'); } catch (e) { /* storage unavailable */ }
  };
  const [railHover, setRailHover] = useState(false);
  const [showDifficultyModal, setShowDifficultyModal] = useState(false);
  const [practiceAnother, setPracticeAnother] = useState(false); // opens picker at the Guided catalog
  const [showFailureModal, setShowFailureModal] = useState(false);
  const [failureCategory, setFailureCategory] = useState(null);
  const [failureType, setFailureType] = useState(null); // 'timeout' or 'wrong_answer'
  const [analystName, setAnalystName] = useState(null);
  const [gameMode, setGameMode] = useState('training');
  const [incidentBadge, setIncidentBadge] = useState(0);
  const [simActive, setSimActive] = useState(false);
  const [pivotHost, setPivotHost] = useState(null);
  // Final pass III.0.1 item 5: contextual navigation into the Response
  // workspace -- {kind, hostname?, pid?, entityId?, seq}. Selection only;
  // navigating here never executes anything.
  const [responseFocus, setResponseFocus] = useState(null);
  const responseSeqRef = useRef(0);
  const handleOpenResponse = (target) => {
    responseSeqRef.current += 1;
    setResponseFocus({ ...target, seq: responseSeqRef.current });
    setView('response');
  };
  // Stage 4 P7.2 entry, renamed "Investigate in SIEM" (III.0 item 5). The
  // request carries ONLY observable data supplied by the origin surface
  // (participant hostnames / account, the player-selected incident
  // context); the SIEM shell generates and executes the prepared search
  // through the one generator. seq retriggers identical consecutive
  // entries.
  const [descentRequest, setDescentRequest] = useState(null);
  const descentSeqRef = useRef(0);
  // Stage 5 commit 5.4: "Review what you learned" requests -- opens the
  // Metrics Learning Review home with the incident preselected (B-OD-1
  // Option 1). Pure navigation state; seq retriggers repeat requests.
  const [reviewRequest, setReviewRequest] = useState(null);
  const reviewSeqRef = useRef(0);

  const handleOpenLearningReview = (incidentId) => {
    reviewSeqRef.current += 1;
    setReviewRequest({ id: incidentId, seq: reviewSeqRef.current });
    setView('analytics');
  };

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
        case '6': setView('response'); break;
        case '7': setView('analytics'); break;
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
          // V3: the utility region shows the REAL session identity, so the
          // analyst name follows the server (it previously survived only in
          // memory from the start dialog and vanished on reload).
          setAnalystName(data.analyst_name || null);
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
    // V3: run once immediately so the utility region shows the real session
    // identity on load instead of waiting out the first poll interval.
    checkForIncidents();
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

  const handleTimeout = () => {
    // Stage 6 playtest fix: the overlay shows IMMEDIATELY at expiry; no
    // fetch may sit in front of it (the old category lookup delayed the
    // modal and FailureModal never rendered the category anyway). The
    // backend is then told the run is dead so the session pauses even
    // before its own auto-pause read lands.
    setFailureType('timeout');
    setShowFailureModal(true);
    apiFetch('/api/game-timeout', { method: 'POST' }).catch(() => {});
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
    // Stage 6 playtest fix: Retry must land a genuinely fresh run. Start
    // only after a confirmed reset, and re-sync the shell once the new run
    // exists (a second resetTrigger bump) so the UI never sits on the dead
    // run's state after the overlay closes. If the start fails, the reset
    // already left a clean lobby with the Start control available.
    const resetOk = await handleResetSimulator();
    if (!resetOk) {
      // Surface the failure with a recovery path instead of silence: the
      // reset dialog opens showing the error and a working Reset button.
      setShowResetModal(true);
      return;
    }
    try {
      const res = await apiFetch('/api/start-simulator', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ game_mode: 'hardcore', analyst_name: analystName })
      });
      if (!res.ok) throw new Error('start-simulator failed');
      setGameMode('hardcore');
      setSimActive(true);
      setResetTrigger(prev => prev + 1);
    } catch (err) {
      console.error(err);
    }
  };

  const openResetModal = () => {
    setResetError(null);
    setShowResetModal(true);
  };

  const dismissResetModal = () => {
    // Always dismissible, even mid-flight: dismissing abandons the attempt
    // (the in-flight request is aborted). The playtest hang was a stalled
    // reset POST holding the dialog on "Resetting..." with every exit gated
    // behind the busy flag.
    resetAbortRef.current?.abort();
    setResetError(null);
    setShowResetModal(false);
  };

  const handleResetSimulator = async () => {
    setIsResetting(true);
    setResetError(null);
    const controller = new AbortController();
    resetAbortRef.current = controller;
    const timer = setTimeout(() => controller.abort(), RESET_TIMEOUT_MS);
    try {
      const res = await apiFetch('/api/reset-simulator', {
        method: 'POST',
        signal: controller.signal,
      });
      if (!res.ok) throw new Error('reset-simulator failed');
      // A reset destroys the session's incidents; no case survives it, so
      // the pinned case clears here (explicit destructive act, not an
      // implicit case change). The classification selections, the context
      // pill summary, and any pending Learning Review preselect die with it.
      setActiveIncidentId(null);
      setActiveIncident(null);
      setReviewRequest(null);
      setChosen({});
      setResetTrigger(prev => prev + 1);
      setShowResetModal(false);
      setResetError(null);
      return true;
    } catch (err) {
      console.error(err);
      setResetError('The reset did not complete. Check that the backend is reachable and try again.');
      return false;
    } finally {
      clearTimeout(timer);
      resetAbortRef.current = null;
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

  // Visual pass V2: every primary destination carries a DISTINCT identity
  // from the one icon system (components/icons.jsx NAV_ICONS) -- the old
  // rail drew inline paths and shared one triangle between Incidents and
  // Detections. Labels + title attributes stay the accessible names; the
  // icons are decorative (aria-hidden), so the active state never relies
  // on the icon alone.
  const tabs = [
    { key: 'dashboard', label: 'Dashboard', count: 0 },
    { key: 'incidents', label: 'Incidents', count: groupedAlertCount },
    // C1 checkpoint fix (post-Stage-5 review, F1): the evidence-surface nav
    // entries (SIEM, Detections, Endpoints) carry NO numeric badge. The old
    // badges read unfiltered session payloads while the page headers rendered
    // case-scoped counts, so badge and header could not agree with a case
    // pinned; the Incidents badge stays (cases are a global concept).
    { key: 'siem', label: 'SIEM' },
    { key: 'detections', label: 'Detections' },
    { key: 'endpoints', label: 'Endpoints' },
    // Final pass III.0.1: Response is the one action-execution workspace
    // (Investigate -> Triage -> Respond -> Submit -> Learn). Badge-free
    // per the C1 nav ruling.
    { key: 'response', label: 'Response' },
    { key: 'analytics', label: 'Metrics', count: analyticsCount },
    // C1 checkpoint fix (F6 slice): the Reports entry is HIDDEN until a
    // working report workflow exists (the ruled default). The tab was a
    // read-only shell over a store nothing writes (no create path since
    // 3.9B retired the Alerts flow), permanently stuck on an empty state
    // that cited that retired workflow.
  ];

  // Stage 6 playtest fix 8: the Guided hint pill docks bottom-right; while
  // it is active the content area gains bottom clearance and the toast
  // stack lifts above it. ONE allow-list source (hintsAllowed), never a
  // duplicated mode check.
  const hintActive = simActive && hintsAllowed(gameMode);

  // Owner sidebar redesign (2026-10-12): the desktop rail is a floating
  // panel with pin + hover semantics.
  //   pinned (lg+ default)  expanded in flow, stays open
  //   unpinned              icon-only rail; hover (or keyboard focus)
  //                         expands it OVER the content; leaving collapses
  //   below lg              always the icon rail with hover expansion (a
  //                         pinned 288px column would crush the content)
  //   below md              the drawer replaces the rail entirely
  const pinnedExpanded = isLgUp && railPinned;
  const railExpanded = pinnedExpanded || railHover;
  const railControl = !isLgUp ? null : pinnedExpanded ? (
    <button
      type="button"
      onClick={() => { setRailPinned(false); setRailHover(false); }}
      aria-label="Collapse sidebar"
      title="Collapse sidebar"
      className="shrink-0 flex items-center justify-center w-8 h-8 rounded-md text-gray-400 hover:bg-white/5 hover:text-white transition-colors"
    >
      <ChromeIcons.PanelLeftClose size={18} strokeWidth={NAV_STROKE} aria-hidden="true" />
    </button>
  ) : (
    <button
      type="button"
      onClick={() => setRailPinned(true)}
      aria-label="Pin sidebar open"
      title="Pin sidebar open"
      className="shrink-0 flex items-center justify-center w-8 h-8 rounded-md text-gray-400 hover:bg-white/5 hover:text-white transition-colors"
    >
      <ChromeIcons.Pin size={18} strokeWidth={NAV_STROKE} aria-hidden="true" />
    </button>
  );

  // ONE source for the rail content, rendered by the desktop floating
  // panel (expansion driven by the pin/hover state above, never a
  // breakpoint) and the below-md drawer (always expanded). A plain render
  // function, never a nested component, so children keep their identity
  // across renders. opts.control is the collapse/pin slot (desktop only);
  // opts.timer mounts the ONE desktop GameTimer (the drawer never does).
  const renderRail = (expanded, close = () => {}, { control = null, timer = false } = {}) => {
    const align = expanded ? 'justify-start' : 'justify-center';
    const label = expanded ? '' : 'hidden';
    const pad = expanded ? 'px-3' : 'px-2';
    return (
      <>
        {/* Brand row. Owner redesign + shrink instruction (2026-10-12):
            the floating panel wears the COMPACT lockup (40px ghost,
            text-lg wordmark) in a 56px row -- the 68px/30px lockup was
            sized for the retired full-bleed shell row and crowded the
            collapse/pin control. The brand link is CONTENT-WIDTH so the
            control sits beside the title; divider and real home
            navigation stay. Docs shells keep the ruled VD6 sizes via the
            lockup's default variant. */}
        <div className={`flex items-center h-14 shrink-0 border-b border-white/10 ${expanded ? `${pad} justify-between gap-2` : `${pad} justify-center`}`}>
          <Link
            to="/"
            title="Back to Home"
            className="flex items-center shrink-0 rounded-md hover:bg-white/5 transition-colors"
          >
            <BrandLockup size="sm" wordmarkClass={label} />
            <span className="sr-only">SPECTR home</span>
          </Link>
          {expanded && control}
        </div>

        <nav className={`flex-1 py-3 ${pad} flex flex-col gap-1 min-h-0`}>
          {tabs.map(t => {
            const active = view === t.key;
            const Icon = NAV_ICONS[t.key];
            return (
              <button
                key={t.key}
                onClick={() => { setView(t.key); if (t.key === 'incidents') setIncidentBadge(0); close(); }}
                title={t.label}
                className={`group relative flex items-center ${align} gap-3 rounded-md ${pad} py-2.5 text-sm font-medium transition-colors ${
                  active ? 'bg-white/10 text-white' : 'text-gray-400 hover:bg-white/5 hover:text-white'
                }`}
              >
                {active && <span className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-full bg-white" />}
                <Icon size={19} strokeWidth={NAV_STROKE} aria-hidden="true" className="shrink-0" />
                <span className={`${label} flex-1 text-left whitespace-nowrap`}>{t.label}</span>
                {t.count > 0 && <span className={`${label} text-xs text-gray-400`}>{t.count}</span>}
                {t.count > 0 && !expanded && <span className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full bg-white/70" />}
              </button>
            );
          })}
        </nav>

        <div className={`${pad} mb-1`}>
          <Link
            to="/docs"
            title="Documentation"
            className={`flex items-center ${align} gap-3 rounded-md ${pad} py-2.5 text-sm font-medium text-gray-400 hover:bg-white/5 hover:text-white transition-colors`}
          >
            <ChromeIcons.BookOpen size={19} strokeWidth={NAV_STROKE} aria-hidden="true" className="shrink-0" />
            <span className={`${label} whitespace-nowrap`}>Docs</span>
          </Link>
        </div>

        <div className={`mt-auto ${expanded ? 'p-3' : 'p-2'} border-t border-white/10 flex flex-col gap-2`}>
          {/* The ONE desktop timer instance (opts.timer; the drawer never
              carries it; on mobile it lives in the header slot). Mounted
              independent of `expanded` so pin/hover toggles never reset
              its polling. */}
          {timer && (
            <GameTimer onTimeout={handleTimeout} disabled={showFailureModal} />
          )}
          {simActive ? (
            /* VE5 (owner mid-run instruction): the rail Reset wears the
               same pill treatment as the shared Start control (one
               exported class list, so the geometry cannot drift). It is
               NOT a StartButton -- Reset is not a product-entry action. */
            <button
              onClick={() => { close(); openResetModal(); }}
              title="Reset Simulation"
              aria-label="Reset Simulation"
              className={`${CTA_PILL} w-full`}
            >
              <ChromeIcons.RotateCcw size={18} strokeWidth={NAV_STROKE} aria-hidden="true" className="shrink-0" />
              <span className={label}>Reset</span>
            </button>
          ) : (
            /* Final polish (section 4): the rail's inactive-session slot
               is the shared product-entry StartButton (label collapses
               below lg exactly like the lockup wordmark). */
            <StartButton
              onClick={() => { close(); handleSimulateEvents(); }}
              title="Start"
              className="w-full"
              labelClass={label}
            />
          )}
        </div>
      </>
    );
  };

  return (
    <div className="min-h-screen flex bg-[#f6f8fa] text-[#1a2332]">
      {/* Desktop floating sidebar (owner redesign 2026-10-12): a rounded
          panel inset from the viewport edges, never edge-to-edge. The
          outer div holds FLOW width (content never sits under the pinned
          panel); the fixed inner panel animates its own width, so an
          unpinned hover expansion overlays the content instead of
          reflowing it. Widths: w-24 icon rail / w-60 expanded (slimmed
          with the compact lockup per the owner's follow-up; the 40px
          ghost never clips). Below md the drawer replaces the rail
          (Stage 6 playtest fix 6). */}
      <div className={`hidden md:block shrink-0 transition-[width] duration-200 ${pinnedExpanded ? 'w-[16.5rem]' : 'w-[7.5rem]'}`}>
        <aside
          onMouseEnter={() => setRailHover(true)}
          onMouseLeave={() => setRailHover(false)}
          onFocus={() => setRailHover(true)}
          onBlur={(e) => { if (!e.currentTarget.contains(e.relatedTarget)) setRailHover(false); }}
          className={`fixed left-3 top-3 bottom-3 z-30 rounded-2xl bg-[#101218] text-gray-300 flex flex-col shadow-xl transition-[width] duration-200 ${railExpanded ? 'w-60' : 'w-24'}`}
        >
          {renderRail(railExpanded, () => {}, { control: railControl, timer: !isMobileViewport })}
        </aside>
      </div>

      {/* Mobile off-canvas drawer (below md), opened by the header hamburger */}
      {mobileNavOpen && (
        <div className="fixed inset-0 z-50 md:hidden">
          <div className="absolute inset-0 bg-black/70" onClick={() => setMobileNavOpen(false)} />
          <aside
            aria-label="Navigation"
            className="absolute inset-y-0 left-0 w-60 max-w-[85vw] rounded-r-2xl bg-[#101218] text-gray-300 flex flex-col shadow-2xl animate-drawerIn"
          >
            {renderRail(true, () => setMobileNavOpen(false))}
          </aside>
        </div>
      )}

      {/* Light content */}
      <main className="flex-1 min-w-0 overflow-x-hidden">
        {/* VC1 (owner correction): ONE inline application header row. The
            header is the light main cell -- full column width, 72px like
            the sidebar brand cell beside it, closed by a divider -- so
            brand cell + page title read as one shell row separated only
            by the sidebar boundary. It keeps the VH content: the current
            workspace title + the ghost avatar with its real-controls
            menu. No mode or analyst name in the shell; no case context
            here (the pinned case line lives on the working surfaces). */}
        {/* Owner UI pass (2026-10-12): the per-tab subtitle line is
            retired; the workspace title stands alone. */}
        <AppHeader
          title={(tabs.find(t => t.key === view) || {}).label || 'Dashboard'}
          gameMode={gameMode}
          analystName={analystName}
          simActive={simActive}
          onReset={openResetModal}
          onOpenNav={() => setMobileNavOpen(true)}
          timerSlot={isMobileViewport
            ? <GameTimer onTimeout={handleTimeout} disabled={showFailureModal} />
            : null}
        />
        {/* Stage 6 playtest fix 8: while the Guided hint pill floats bottom
            right, the content area carries bottom clearance so the last rows
            of any column (SIEM facets, Response tables, Metrics cards) can
            scroll clear of it instead of sitting underneath. */}
        <div className={`p-4 sm:p-6 ${hintActive ? 'pb-20 sm:pb-20' : ''}`}>
        {/* Stage 5 Phase 1 (Amendment 1 Delta A): the global focus banner is
            REPLACED by the per-surface pinned case header ("Investigating
            INC-####" / "All activity") on Detections, Endpoints, and the
            SIEM. The case changes only by explicit selection (or the
            explicit Clear selection control) on Incidents -- OD-15 is
            structural: no other control mutates activeIncidentId. */}
        <div className={view === "dashboard" ? "block" : "hidden"}>
          <IncidentDashboard
            gameMode={gameMode}
            activeIncidentId={activeIncidentId}
            onSelectIncident={setActiveIncidentId}
            onNavigate={setView}
            isVisible={view === "dashboard"}
            chosen={chosen}
          />
        </div>

        <div className={view === "incidents" ? "block" : "hidden"}>
          <Incidents
            isVisible={view === "incidents"}
            resetTrigger={resetTrigger}
            onHardcoreFailure={handleHardcoreFailure}
            onReset={openResetModal}
            gameMode={gameMode}
            activeIncidentId={activeIncidentId}
            onSelectIncident={setActiveIncidentId}
            onNavigate={setView}
            setGroupedAlertCount={setGroupedAlertCount}
            onPracticeAnother={handlePracticeAnother}
            onEvidenceDescent={handleEvidenceDescent}
            onOpenLearningReview={handleOpenLearningReview}
            onActiveIncidentSummary={setActiveIncident}
            chosen={chosen}
            setChosen={setChosen}
          />
        </div>

        <div className={view === "siem" ? "block" : "hidden"}>
          <Siem resetTrigger={resetTrigger} onHostPivot={handleHostPivot} activeIncidentId={activeIncidentId} descentRequest={descentRequest} />
        </div>

        <div className={view === "detections" ? "block" : "hidden"}>
          <Detections isVisible={view === "detections"} resetTrigger={resetTrigger} onHostPivot={handleHostPivot} activeIncidentId={activeIncidentId} onEvidenceDescent={handleEvidenceDescent} onOpenResponse={handleOpenResponse} />
        </div>

        <div className={view === "endpoints" ? "block" : "hidden"}>
          <Endpoints isVisible={view === "endpoints"} resetTrigger={resetTrigger} pivotHost={pivotHost} activeIncidentId={activeIncidentId} onOpenResponse={handleOpenResponse} activeIncident={activeIncident} />
        </div>

        <div className={view === "response" ? "block" : "hidden"}>
          <Response isVisible={view === "response"} resetTrigger={resetTrigger} activeIncidentId={activeIncidentId} responseFocus={responseFocus} onHostPivot={handleHostPivot} activeIncident={activeIncident} />
        </div>

        <div className={view === "analytics" ? "block" : "hidden"}>
          <Analytics analystName={analystName} setAnalyticsCount={setAnalyticsCount} isVisible={view === "analytics"} reviewRequest={reviewRequest} activeIncident={activeIncident} />
        </div>
        </div>
      </main>

      {/* Reset Confirmation Modal */}
      {showResetModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div
            className="absolute inset-0 bg-black/70"
            onClick={dismissResetModal}
          />
          <div className="relative bg-white border border-[#e2e6ea] rounded-xl p-6 w-full max-w-md mx-4 shadow-2xl animate-modalIn">
            <button
              type="button"
              onClick={dismissResetModal}
              aria-label="Close"
              className="absolute top-3 right-3 p-1 text-muted hover:text-[#1a2332] transition-colors"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
            <h3 className="text-lg font-semibold text-[#1a2332] mb-4">Reset Simulation</h3>
            <p className="text-muted mb-6">
              This will clear all events and incidents. Your progress will be reset. This action cannot be undone.
            </p>
            {resetError && (
              <p role="alert" className="text-sm text-[#a40e26] mb-4">
                {resetError}
              </p>
            )}
            <div className="flex justify-end gap-2">
              <button
                onClick={dismissResetModal}
                className="inline-flex items-center justify-center px-2 sm:px-3 py-1.5 sm:py-2 text-xs font-medium rounded-md border transition bg-white hover:bg-[#eef1f4] text-muted border-[#d0d7de] focus:outline-none focus:ring-2 focus:ring-[#8b949e]"
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
              className="absolute top-3 right-3 p-1 text-muted hover:text-[#1a2332] transition-colors"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
            <h3 className="text-lg font-semibold text-[#1a2332] mb-4">Simulation Active</h3>
            <div className="mb-5" style={{ height: '1px', background: 'linear-gradient(to right, rgba(0,0,0,0.08), transparent)' }} />
            <p className="text-muted mb-6">
              A simulation session is already active. Use <span className="text-[#1a2332] font-medium">Reset Simulation</span> to start fresh.
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setShowSimulateModal(false)}
                className="inline-flex items-center justify-center px-2 sm:px-3 py-1.5 sm:py-2 text-xs font-medium rounded-md border transition bg-white hover:bg-[#eef1f4] text-muted border-[#d0d7de] focus:outline-none focus:ring-2 focus:ring-[#8b949e]"
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

      {/* Live Progress and Reinforcement toasts (Phase 2 commit 2.4,
          A1-B.3.1): factual confirmations only, announced politely
          (role=status), never stealing focus. */}
      {/* Stage 6 playtest fix 8: with the hint pill docked bottom-right,
          the transient toast stack lifts above it so the two never collide;
          other modes keep the default corner. */}
      <ToastContainer position="bottom-right" autoClose={4000} newestOnTop
        closeOnClick pauseOnFocusLoss={false} limit={4} role="status"
        theme="light" style={hintActive ? { bottom: '4.5rem' } : undefined} />

      {/* Phase 6 commit 6.2 (A1-B.5.2): the Guided-only hint flow. The
          component itself enforces the HINT_MODES allow-list (renders
          null in Hardcore, SOC Queue, and any future mode) and reads only
          static libraries; the active tab is the ONLY context passed. */}
      {simActive && <HintPanel gameMode={gameMode} surface={view} />}
    </div>
  );
};

export default Dashboard;
