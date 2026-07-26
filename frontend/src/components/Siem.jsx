import React, { useState, useEffect, useRef } from 'react';
import { apiFetch } from '../api';
import SiemTable from './SiemTable';
import SiemCards from './SiemCards';
import FieldSidebar from './FieldSidebar';
import EventInspector from './EventInspector';
import {
  refineFilter, splitSegments, pivotHost, pivotAccount, pivotProcessImage,
  pivotFile, pivotIp, pivotDomainProxy, pivotDomainDns, pivotEventType,
  pivotSensorFamily, descentHost, descentSessionAll, descentAccount,
  OR_FALLBACK_NOTICE, sectionIndexAtPosition, listConjuncts, removeConjunct,
  composeQuery, replaceTimeframe, rawFiltersOf, filtersOffsetOf,
  SOURCE_FAMILIES,
} from './lcqlPivots';
import InvestigationContext from './InvestigationContext';
import {
  followingClue, resultsFor, ALL_EVENTS_LABEL, INITIAL_INCIDENT_EVIDENCE,
  INITIAL_EVIDENCE, SELECTED_EVENT_HIDDEN,
  EDITED_NOTE, STALE_RESULTS_NOTE, filterAdded, excludedFilter,
  NO_QUERY_ENTERED, PRESERVED_RESULTS_LABEL, SEARCH_NOT_RUN,
  QUERY_SECTION_NAMES, sectionCouldNotBeRead, STRUCTURE_LINE,
  RESTORE_LAST_QUERY, SIMPLE_PLACEHOLDER, SIMPLE_HELP, SIMPLE_TOGGLE,
  ADVANCED_TOGGLE, SOURCE_LABEL, EVENT_TYPE_LABEL, ALL_SOURCES,
  ALL_EVENT_TYPES,
} from './uiCopy';

// SIEM Investigation Workbench shell (Stage 4 Phase 4). Analyst-driven:
// the shell submits LCQL text to the server's single query read and renders
// the returned frozen snapshot exactly as served. No polling, no client-side
// filtering, no client-side query execution of any kind (contract P8): rows
// never insert, remove, or reorder until the analyst runs a query again.

// The placeholder is unmistakably an EXAMPLE (Amendment 2, ruled): the
// Example prefix is part of the placeholder text and the input styles
// placeholder text in italic, so guidance never resembles a run query.
export const QUERY_PLACEHOLDER =
  'Example: 1h | Sysmon | ProcessCreate | command_line contains "powershell"';

export const QUERY_HELP_EXAMPLES = [
  'all | * | * | *',
  '24h | Windows Security | 4625 | user_account == "spatel" and source_ip contains "10.0."',
];

// A3.5 (F7): the simple-mode edit-only examples are FILTERS expressions
// (the pickers own the other tokens).
export const SIMPLE_HELP_EXAMPLES = [
  'source_ip == "10.0.1.32"',
  'user_account == "spatel" and command_line contains "powershell"',
];

export const TF_TOKENS = ['15m', '1h', '4h', '12h', '24h', 'all'];

// The TIMEFRAME control derives its value FROM the text (single source of
// truth), so control and text can never disagree: the text's first segment
// is the control's value when it is a known token, a neutral placeholder
// otherwise, and the documented default (1h) only while the bar is empty.
const firstSegmentToken = (text) => {
  const idx = text.indexOf('|');
  const head = (idx === -1 ? text : text.slice(0, idx)).trim().toLowerCase();
  return TF_TOKENS.includes(head) ? head : null;
};

const Siem = ({ resetTrigger, onHostPivot, activeIncidentId,
                descentRequest, onNavigate,
                initialQueryMode = 'simple' }) => {
  const [org, setOrg] = useState({});
  const [view, setView] = useState('cards');
  // Amendment 3 F7 (ratified A3-OD-4): Simple search is the DEFAULT in
  // every play mode; Advanced LCQL is one toggle away. Session-local
  // memory only -- no localStorage, no server persistence (B-OD-4).
  // Search semantics are identical across modes: simple mode compiles to
  // the same canonical four-part query the advanced bar holds.
  // (initialQueryMode exists for the pre-A3 test batteries, which author
  // four-part LCQL directly; the product always mounts the default.)
  const [queryMode, setQueryMode] = useState(initialQueryMode);
  const [queryText, setQueryText] = useState('');
  const [snapshot, setSnapshot] = useState(null);   // {token, identity, count, rows}
  // Final pass III.0 item 3 (search-state truth): the displayed snapshot's
  // PROVENANCE. 'player' = the player authored the run (Run, refine, chip
  // removal, pivot); 'prepared' = the shell executed a prepared entry query
  // (evidence descent) the player never wrote -- labeled "Initial incident
  // evidence", never "Results for:". Refresh re-executes the displayed
  // identity, so it preserves the origin it refreshes.
  const [snapshotOrigin, setSnapshotOrigin] = useState('player');
  const [error, setError] = useState(null);         // {position, reason, suggestions?}
  const [running, setRunning] = useState(false);
  // Scope state machine (contract Section 6, revised scope-error behavior):
  // {kind:'session'} | {kind:'incident', id, status:'loading'|'ready'|'error', sealed}
  const [scope, setScope] = useState({ kind: 'session' });
  // P5.1: ONE inspector selection, keyed by event id, owned by the shell so
  // it persists across view toggles and Refresh (when the id survives).
  const [selectedId, setSelectedId] = useState(null);
  const [selectionNotice, setSelectionNotice] = useState(null);
  // P6.1/6.2: the OR-fallback notice from a sidebar/inspector refinement
  // (distinct lifecycle from selectionNotice -- set only when refineFilter
  // reports `fresh`, cleared by any subsequent plain Run/Refresh).
  const [queryNotice, setQueryNotice] = useState(null);
  // P5.2: the new-events indicator (contract Section 8, R16 refresh-now).
  // Token-bound: the poll carries ONLY the executed snapshot's token, so
  // edited bar text structurally cannot influence the count. countHalted
  // stops the poll neutrally after a token invalidation (reset/restart).
  const [newCount, setNewCount] = useState(0);
  const [poolGrowth, setPoolGrowth] = useState(0);
  const [countHalted, setCountHalted] = useState(false);
  // Stage 5 Phase 1 (Amendment 1 Delta A), simplified by the Final pass
  // (III.0 item 2): ONE evidence universe per case state. Scope kind
  // 'incident' anchors every search to the current case's complete
  // observable evidence pool; 'session' is the no-case All activity
  // fallback. The case itself is the activeIncidentId prop -- selected on
  // Incidents, never changeable from here (ratified OD-15, structural).
  // P7.2: the evidence-timeline context ({kind:'descent', origin, backView,
  // host, query}). Pure UI provenance (contract Section 12: the breadcrumb
  // "implies nothing about any row"); the banner and the ascending display
  // render ONLY while the displayed snapshot's canonical query is the
  // timeline's own query, so they can never mislabel another snapshot.
  const [timeline, setTimeline] = useState(null);
  // Final pass III item 2: the Expanded-search state, its hold, the
  // search-all action, the case-evidence chip, and the return action are
  // REMOVED. With an active incident the SIEM always searches that
  // incident's complete observable evidence pool; a Pivot changes the
  // query, never the evidence universe (it announces its clue through
  // the one notice line, like a refine).
  // Phase 4 commit 4.1 (OD-5 Option A): selection visibly connects to the
  // ONE shared inspector -- scroll-into-view (block nearest), a single
  // emphasis run, and focus moved to the container exactly once per
  // selection change; prefers-reduced-motion jumps with no animation.
  const inspectorRef = useRef(null);
  const [inspectorEmphasis, setInspectorEmphasis] = useState(false);
  useEffect(() => {
    if (!selectedId || !inspectorRef.current) return undefined;
    const reduced = typeof window.matchMedia === 'function'
      && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (typeof inspectorRef.current.scrollIntoView === 'function') {
      inspectorRef.current.scrollIntoView({
        block: 'nearest', behavior: reduced ? 'auto' : 'smooth',
      });
    }
    inspectorRef.current.focus({ preventScroll: true });
    if (reduced) return undefined;
    setInspectorEmphasis(true);
    const t = setTimeout(() => setInspectorEmphasis(false), 700);
    return () => clearTimeout(t);
  }, [selectedId]);

  useEffect(() => {
    apiFetch('/api/endpoints')
      .then(res => res.json())
      .then(data => setOrg(data.org || {}))
      .catch(() => {});
  }, [resetTrigger]);

  // Session reset clears every piece of workbench state (scaffold S6-S13).
  useEffect(() => {
    setQueryText('');
    setSnapshot(null);
    setSnapshotOrigin('player');
    setError(null);
    setRunning(false);
    setScope({ kind: 'session' });
    setSelectedId(null);
    setSelectionNotice(null);
    setQueryNotice(null);
    setTimeline(null);
  }, [resetTrigger]);

  const loadIncidentScope = (id) => {
    setScope({ kind: 'incident', id, status: 'loading' });
    apiFetch(`/api/incidents/${id}/scope`)
      .then((res) => { if (!res.ok) throw new Error('scope'); return res.json(); })
      .then((sc) => setScope({ kind: 'incident', id, status: 'ready',
                               sealed: !!sc.sealed }))
      // Revised scope-error behavior (kept from M1/Stage 4): preserve the
      // prior snapshot, disable Run; recovery is Retry only.
      .catch(() => setScope({ kind: 'incident', id, status: 'error' }));
  };

  // Case-constant anchor (Amendment 1 Delta A, A1-A.2): the SIEM re-anchors
  // atomically when the current case changes -- case evidence for a case,
  // All activity for none. The prior snapshot belonged to the prior anchor
  // and is dropped; nothing in this component can change the case itself
  // (ratified OD-15, structural: case selection lives on Incidents alone).
  useEffect(() => {
    setSnapshot(null);
    setSnapshotOrigin('player');
    setError(null);
    setQueryText('');
    setTimeline(null);
    setQueryNotice(null);
    setSelectedId(null);
    setSelectionNotice(null);
    if (activeIncidentId) loadIncidentScope(activeIncidentId);
    else setScope({ kind: 'session' });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeIncidentId]);

  const scopeBlocked = scope.kind === 'incident' && scope.status !== 'ready';
  const scopeParam = scope.kind === 'incident' ? scope.id : 'session';

  // --- Amendment 3 F7: the simple-search projection ----------------------
  // The canonical four-part text (queryText) stays the ONE pending truth;
  // simple mode PROJECTS it: the bar holds only the FILTERS expression,
  // the Timeframe picker and the Source / Event type selects own the
  // other tokens. Every control's value DERIVES from the text (the
  // ratified Timeframe pattern generalized), so every server-canonical
  // query is representable in simple mode by construction; edits
  // recompose through the generator chokepoint (composeQuery).
  const segs = splitSegments(queryText);
  const simpleParts = segs.length === 4
    ? { tf: segs[0], sensor: segs[1], et: segs[2] }
    : { tf: '1h', sensor: '*', et: '*' };
  const rawFilters = rawFiltersOf(queryText);
  const simpleFiltersDisplay = rawFilters === null || rawFilters.trim() === '*'
    ? '' : rawFilters;
  const simpleProjectable = queryText.trim() === '' || segs.length === 4;
  const composeFromControls = (over = {}) => composeQuery(
    over.tf ?? simpleParts.tf,
    over.sensor ?? simpleParts.sensor,
    over.et ?? simpleParts.et,
    over.filters ?? simpleFiltersDisplay,
  );
  const setSimplePart = (part, value) => {
    setQueryText(composeFromControls({ [part]: value }));
  };

  const setTimeframe = (tok) => {
    if (queryMode === 'simple') { setSimplePart('tf', tok); return; }
    // Advanced: replace the first segment in place through the chokepoint
    // (A3-5.3: the raw indexOf splice migrated to replaceTimeframe).
    setQueryText((t) => replaceTimeframe(t, tok));
  };
  const tfValue = firstSegmentToken(queryText) ||
    (queryText.trim() === '' ? '1h' : '');
  // The two value-driven selects: static families / snapshot-derived event
  // types, plus the CURRENT token whenever it is anything else (a hostname
  // sensor from a pivot renders as its own option -- mode stability).
  const sensorOptions = ['*', ...SOURCE_FAMILIES];
  if (!sensorOptions.includes(simpleParts.sensor)) sensorOptions.push(simpleParts.sensor);
  const snapshotEventTypes = snapshot
    ? [...new Set(snapshot.rows.map((r) => r.event_type).filter(Boolean))].sort()
    : [];
  const eventTypeOptions = ['*', ...snapshotEventTypes];
  if (!eventTypeOptions.includes(simpleParts.et)) eventTypeOptions.push(simpleParts.et);

  // Atomic replacement: the new snapshot object swaps in whole; a failed
  // run leaves the prior snapshot untouched. Selection survival (P5.1):
  // when the inspected id is present in the new rows, selection and the
  // open inspector persist; otherwise the inspector closes with a one-line
  // notice and nothing else is lost.
  const applySnapshot = (body, origin) => {
    setSnapshot(body);
    setSnapshotOrigin(origin);
    setError(null);
    // The bar shows the executed snapshot's canonical text (contract S6
    // Active state) -- clicks and runs teach the canonical form.
    setQueryText(body.identity.canonical_query);
    // A new snapshot means a new cutoff and token: the indicator resets.
    setNewCount(0);
    setPoolGrowth(0);
    setCountHalted(false);
    // Functional update so the survival check sees the selection as of
    // REPLACEMENT time (a click during an in-flight run must not be lost).
    // III.0 item 3: a selection hidden by the current results is NEVER
    // silently dropped -- it is retained with the ruled notice, the pane
    // reopens when a later result set includes the event again, and no
    // filter is altered on the player's behalf.
    setSelectedId((sel) => {
      if (sel && !body.rows.some((r) => r.id === sel)) {
        setSelectionNotice(SELECTED_EVENT_HIDDEN);
        return sel;
      }
      setSelectionNotice(null);
      return sel;
    });
  };

  // `noticeAfter`: the clue/OR-fallback text to show once THIS run lands
  // (null clears any stale notice from an earlier refinement -- plain
  // Run/Refresh always pass none). `origin` is the snapshot provenance
  // (III.0 item 3): 'player' unless the caller executed a prepared query.
  const execute = (q, scopeValue, noticeAfter = null, origin = 'player') => {
    if (running) return;
    setRunning(true);
    apiFetch(`/api/events/query?q=${encodeURIComponent(q)}&scope=${encodeURIComponent(scopeValue)}`)
      .then(async (res) => {
        const body = await res.json().catch(() => null);
        if (res.ok && body) {
          applySnapshot(body, origin);
          setQueryNotice(noticeAfter);
        } else if (body && body.error && typeof body.error === 'object') {
          // A2 3.2: the submitted text rides the error so the broken
          // SECTION can be named client-side from the parser position.
          setError({ ...body.error, submitted: q });
        } else {
          setError({ position: 0, reason: 'The query could not be executed.', submitted: q });
        }
      })
      .catch(() => setError({ position: 0, reason: 'The query could not be executed.', submitted: q }))
      .finally(() => setRunning(false));
  };

  const runQuery = () => {
    // A2 3.2 (ruled): in ADVANCED mode Run disables ONLY on a truly empty
    // bar -- an empty query is guidance territory, never an error; a
    // malformed non-empty query RUNS and receives a section-named teaching
    // error. In SIMPLE mode (A3-5.3) a fully-empty state does not exist:
    // the controls always hold tokens and an empty FILTERS field compiles
    // to `*`, the legitimate match-all.
    if (running || scopeBlocked) return;
    if (queryMode === 'simple') {
      execute(queryText.trim() === '' ? composeFromControls() : queryText, scopeParam);
      return;
    }
    if (queryText.trim() === '') return;
    execute(queryText, scopeParam);
  };

  // A2 3.2 (ruled): Restore last working query -- the canonical snapshot
  // query is already held client-side; restoring is an edit (no request)
  // and instantly truthful (the displayed results ARE that query's).
  const restoreLastWorking = () => {
    if (!snapshot) return;
    setQueryText(snapshot.identity.canonical_query);
    setError(null);
  };

  // Refresh re-executes the DISPLAYED snapshot's definition (its canonical
  // query and executed scope), never the editable bar text (contract S7).
  // It refreshes what is displayed, so the provenance label is preserved
  // (refreshed initial evidence is still initial evidence, III.0 item 3).
  const refresh = () => {
    if (!snapshot || running) return;
    execute(snapshot.identity.canonical_query, snapshot.identity.scope, null, snapshotOrigin);
  };

  const selectRow = (id) => {
    setSelectedId(id);
    setSelectionNotice(null);
  };

  // A2 3.3 (ratified: chips ship remove-only): removing a chip regenerates
  // through the generator's remove/join form and RERUNS under the current
  // scope (execute-immediately, the same A2-OD-2 ruling as refines).
  const queryInputRef = useRef(null);
  const removeChip = (index) => {
    if (!snapshot || running || scopeBlocked) return;
    const query = removeConjunct(snapshot.identity.canonical_query, index);
    setQueryText(query);
    execute(query, scopeParam);
  };

  // Sidebar value clicks and inspector ==/!= actions ROUTE ONLY through the
  // approved generator (lcqlPivots.refineFilter); the resulting query is
  // executed immediately as a new snapshot. Phase 3 (8.2/8.3): every refine
  // announces itself with the canonical clue form, and the OR fresh-query
  // sentence FOLDS INTO that one announcement (one notice, never two).
  const refineAndRun = (field, op, value) => {
    if (!snapshot || running || scopeBlocked) return;
    const { query, fresh } = refineFilter(snapshot.identity.canonical_query, field, op, value);
    const clueLine = op === '!=' ? excludedFilter(field, value) : filterAdded(field, value);
    setQueryText(query);
    execute(query, scopeParam, fresh ? `${clueLine} ${OR_FALLBACK_NOTICE}` : clueLine);
  };

  // P7.1 entity pivots (contract Sections 13/14; Final pass III.0 item 2):
  // every pivot mints its documented query from the EXECUTED snapshot's
  // TIMEFRAME token through the one generator and executes it in the
  // CURRENT evidence pool (the case's observable evidence with a case
  // pinned, all activity without).
  const PIVOT_FORMS = {
    host: pivotHost, account: pivotAccount, process: pivotProcessImage,
    file: pivotFile, ip: pivotIp, domain_proxy: pivotDomainProxy,
    domain_dns: pivotDomainDns, event_type: pivotEventType,
    sensor: pivotSensorFamily,
  };
  const pivotAndRun = (kind, value, field) => {
    if (!snapshot || running || scopeBlocked) return;
    const tf = splitSegments(snapshot.identity.canonical_query)[0];
    const query = PIVOT_FORMS[kind](tf, value);
    // Final pass item 2: a Pivot changes the QUERY inside the current
    // evidence pool (the incident's complete observable evidence with a
    // case, all activity without) -- it never changes the evidence
    // universe. It announces the followed clue through the one notice
    // line (the same channel refines use).
    setQueryText(query);
    execute(query, scopeParam, field ? followingClue(field, value) : null);
  };

  // Surrounding events removed (Amendment 3 F3): the control ran an
  // unbounded `all | H | * | *` with the timeframe silently widened and
  // overlapped the host pivot and ordinary search; the honest bounded
  // version is deferred engine work. Evidence descent and descentHost()
  // are untouched.

  // P7.2/P7.4 Open Evidence Timeline descent (contract Sections 13/16; R17
  // uniform control): descent explicitly establishes scope for this entry
  // and anchors to the OBSERVABLE ENTITY. An account-entity detection
  // descends account-anchored (all | * | * | user_account == "A"); one
  // participant host anchors that host's timeline (all | H | * | *);
  // several -- or none known yet -- anchor the scoped session query
  // (all | * | * | *) under the incident's participant scope. Scope
  // follows ONE rule for every anchor kind: the player-selected incident
  // context when the entry carries one, Session-wide otherwise -- identity
  // descent is deliberately NOT special-cased, so an incident-scoped
  // account timeline may honestly show zero rows when the account's events
  // lack participant hostnames; leaving the case on Incidents is the
  // designed path out (III.0 item 2: no SIEM-level scope control exists).
  // The request carries ONLY observable data from the origin
  // surface; the query is generated HERE through the one generator.
  useEffect(() => {
    if (!descentRequest) return;
    const { origin, hosts, account, scopeIncidentId, backView } = descentRequest;
    const host = !account && hosts && hosts.length === 1 ? hosts[0] : null;
    const query = account ? descentAccount(account)
      : host ? descentHost(host) : descentSessionAll();
    setQueryText(query);
    setTimeline({ kind: 'descent', origin, backView, host,
                  account: account || null, query });
    if (scopeIncidentId) {
      setScope({ kind: 'incident', id: scopeIncidentId, status: 'loading' });
      apiFetch(`/api/incidents/${scopeIncidentId}/scope`)
        .then((res) => { if (!res.ok) throw new Error('scope'); return res.json(); })
        .then((sc) => {
          setScope({ kind: 'incident', id: scopeIncidentId, status: 'ready', sealed: !!sc.sealed });
          execute(query, scopeIncidentId, null, 'prepared');
        })
        .catch(() => setScope({ kind: 'incident', id: scopeIncidentId, status: 'error' }));
    } else {
      setScope({ kind: 'session' });
      execute(query, 'session', null, 'prepared');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [descentRequest]);

  // P5.2 indicator poll: token-bound only; passive (the snapshot never
  // changes); stops neutrally when the token is invalidated (a 400 after
  // Reset / Practice Another / restart) -- no error surface, the indicator
  // simply disappears until the next run mints a fresh token.
  useEffect(() => {
    if (!snapshot || countHalted) return undefined;
    let cancelled = false;
    const token = snapshot.token;
    const tick = () => {
      apiFetch(`/api/events/query/new-count?token=${encodeURIComponent(token)}`)
        .then((res) => { if (!res.ok) throw new Error('token'); return res.json(); })
        .then((d) => {
          if (!cancelled) {
            setNewCount(d.new_count);
            setPoolGrowth(d.pool_growth);
          }
        })
        .catch(() => {
          if (!cancelled) {
            setNewCount(0);
            setPoolGrowth(0);
            setCountHalted(true);
          }
        });
    };
    const interval = setInterval(tick, 3000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [snapshot, countHalted]);

  // De-emphasis (contract Section 8): the indicator describes the LAST RUN;
  // when the bar or scope control differs from the executed identity, it
  // dims and says so rather than implying it tracks the edited text.
  const indicatorStale = !!snapshot
    && (queryText !== snapshot.identity.canonical_query
        || scopeParam !== snapshot.identity.scope);

  const simTime = (iso) => {
    const t = Date.parse(iso || '');
    return Number.isNaN(t)
      ? ''
      : new Date(t).toLocaleTimeString('en-GB', { hour12: false });
  };

  // Timeline presentation (contract Section 13: "sorted occurrence
  // ascending"): active only while the displayed snapshot IS the timeline's
  // query. The ascending order is client view state over the frozen row set
  // -- applied at display time, before the components' own column sorting.
  const timelineActive = !!(timeline && snapshot
    && snapshot.identity.canonical_query === timeline.query);
  const occAsc = (a, b) =>
    String(a.timestamp || '').localeCompare(String(b.timestamp || ''))
    || (a.event_seq || 0) - (b.event_seq || 0);
  const displayRows = !snapshot ? []
    : timelineActive ? [...snapshot.rows].sort(occAsc) : snapshot.rows;

  return (
    <div>
      {/* Header card */}
      <div className="bg-white border border-[#e2e6ea] rounded-xl overflow-hidden mb-4">
        <div className="h-0.5" style={{ background: 'linear-gradient(to right, #16436b, #101218)' }} />
        <div className="p-4 sm:p-5 flex flex-wrap items-center gap-4">
          <div className="w-10 h-10 rounded-lg bg-[#101218] flex items-center justify-center shrink-0">
            <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" role="img" aria-label="SIEM">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d="M4 6h16M4 10h16M4 14h16M4 18h16" />
            </svg>
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h2 className="text-xl sm:text-2xl font-semibold text-[#1a2332]">SIEM</h2>
              <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-[#eef1f4] text-[#57606a]">
                {snapshot ? snapshot.count : 0}
              </span>
            </div>
            <p className="text-sm text-[#57606a] truncate">
              {org.name || 'ACME Corp'}: investigation workbench over the session event pool
            </p>
          </div>
          <div className="ml-auto flex items-center rounded-md border border-[#d0d7de] overflow-hidden" role="group" aria-label="View">
            {[['cards', 'Cards'], ['table', 'Table']].map(([key, label]) => (
              <button
                key={key}
                type="button"
                onClick={() => setView(key)}
                className={`px-3 py-1.5 text-xs font-medium transition ${
                  view === key ? 'bg-[#101218] text-white' : 'bg-white text-[#57606a] hover:bg-[#eef1f4]'
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Case-constant context + TIMEFRAME + query bar (Final pass III.0
          item 2): ONE pinned case line, one evidence universe. The old
          scope select, the case-evidence chip, the search-all action, and
          the expanded-search block are all gone; scope loading surfaces
          beside the line and the error keeps its Retry block below. No
          control here can change the case (OD-15). */}
      <div className="mb-3 flex flex-col gap-2">
        <div className="flex items-center justify-between gap-2">
          <InvestigationContext incidentId={activeIncidentId || null} />
          {activeIncidentId && scope.kind === 'incident' && scope.status === 'loading' && (
            <span className="text-xs text-[#6e7781]">Loading incident scope</span>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {/* A3.5 (F7): the simple-mode Source / Event type selects own
              their tokens; value-driven (the current token always renders,
              a hostname sensor included), edits recompose through the
              chokepoint. Advanced mode hides them (the bar holds all). */}
          {queryMode === 'simple' && (
            <label className="flex items-center gap-1.5 text-[#6e7781] ml-auto">
              {SOURCE_LABEL}
              <select
                value={simpleParts.sensor}
                onChange={(e) => setSimplePart('sensor', e.target.value)}
                aria-label={SOURCE_LABEL}
                className="px-2.5 py-1.5 rounded-md border border-[#d0d7de] bg-white text-[#1a2332] max-w-[11rem]"
              >
                {sensorOptions.map((s) => (
                  <option key={s} value={s}>{s === '*' ? ALL_SOURCES : s}</option>
                ))}
              </select>
            </label>
          )}
          {queryMode === 'simple' && (
            <label className="flex items-center gap-1.5 text-[#6e7781]">
              {EVENT_TYPE_LABEL}
              <select
                value={simpleParts.et}
                onChange={(e) => setSimplePart('et', e.target.value)}
                aria-label={EVENT_TYPE_LABEL}
                className="px-2.5 py-1.5 rounded-md border border-[#d0d7de] bg-white text-[#1a2332] max-w-[11rem]"
              >
                {eventTypeOptions.map((t) => (
                  <option key={t} value={t}>{t === '*' ? ALL_EVENT_TYPES : t}</option>
                ))}
              </select>
            </label>
          )}
          <label className={`flex items-center gap-1.5 text-[#6e7781] ${queryMode === 'simple' ? '' : 'ml-auto'}`}>
            Timeframe
            <select
              value={tfValue}
              onChange={(e) => setTimeframe(e.target.value)}
              aria-label="Timeframe"
              className="px-2.5 py-1.5 rounded-md border border-[#d0d7de] bg-white text-[#1a2332]"
            >
              {tfValue === '' && <option value="">custom</option>}
              {TF_TOKENS.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </label>
          {/* A3.5 (F7): one toggle between the modes; a hand-authored
              advanced text that does not split into four sections cannot
              project, so the toggle disables with the structure line. */}
          <button
            type="button"
            data-testid="query-mode-toggle"
            onClick={() => setQueryMode((m) => (m === 'simple' ? 'advanced' : 'simple'))}
            disabled={queryMode === 'advanced' && !simpleProjectable}
            title={queryMode === 'advanced' && !simpleProjectable ? STRUCTURE_LINE : undefined}
            className="px-2 py-1 rounded-md border border-[#d0d7de] text-[#57606a] hover:bg-[#eef1f4] disabled:opacity-50"
          >
            {queryMode === 'simple' ? ADVANCED_TOGGLE : SIMPLE_TOGGLE}
          </button>
        </div>

        {scope.kind === 'incident' && scope.status === 'error' && (
          <div className="px-3 py-2 rounded-md border border-[#e2e6ea] bg-[#faf6f0] text-xs text-[#1a2332]" role="alert">
            Incident scope could not be loaded.
            <button
              type="button"
              onClick={() => loadIncidentScope(scope.id)}
              className="ml-2 px-2 py-0.5 rounded border border-[#d0d7de] bg-white text-[#1a2332]"
            >
              Retry
            </button>
          </div>
        )}
        {scope.kind === 'incident' && scope.status === 'ready' && scope.sealed === false && (
          <div className="px-3 py-1.5 rounded-md bg-[#eef1f4] text-xs text-[#57606a]">
            Incident telemetry is still loading.
          </div>
        )}

        <div className="flex gap-2">
          {/* A3.5 (F7): one input, two projections. Simple mode holds ONLY
              the FILTERS expression (edits recompose the canonical text
              through the chokepoint); Advanced holds the four-part form. */}
          <input
            type="text"
            ref={queryInputRef}
            placeholder={queryMode === 'simple' ? SIMPLE_PLACEHOLDER : QUERY_PLACEHOLDER}
            value={queryMode === 'simple' ? simpleFiltersDisplay : queryText}
            onChange={(e) => (queryMode === 'simple'
              ? setSimplePart('filters', e.target.value)
              : setQueryText(e.target.value))}
            onKeyDown={(e) => { if (e.key === 'Enter') runQuery(); }}
            readOnly={running}
            maxLength={300}
            aria-label={queryMode === 'simple' ? 'Filters' : 'LCQL query'}
            className="log-mono flex-1 pl-4 pr-4 py-2 rounded-md bg-white border border-[#e2e6ea] text-[#1a2332] text-sm placeholder-[#8b949e] placeholder:italic focus:border-[#8b949e] focus:outline-none transition-colors"
          />
          <button
            type="button"
            onClick={runQuery}
            disabled={running || scopeBlocked
              || (queryMode === 'advanced' && queryText.trim() === '')}
            title={queryMode === 'advanced' && queryText.trim() === ''
              ? NO_QUERY_ENTERED : 'Run the query in the bar.'}
            className="px-4 py-2 text-xs font-medium rounded-md bg-[#101218] text-white disabled:opacity-50"
          >
            {running ? 'Running' : 'Run Query'}
          </button>
        </div>

        {error && (
          // A2 3.2 (ruled canonical error form, three lines): the search was
          // not run; the broken SECTION in plain language (structure line
          // when the text does not split into four sections); the locked
          // 11.3 stale-results statement exactly when prior results are
          // preserved. The parser reason + suggestions stay as the
          // technical detail; Restore is the one-click recovery.
          <div className="px-3 py-2 rounded-md border border-[#e2e6ea] bg-[#faf6f0] text-xs text-[#1a2332]" role="alert">
            <span className="font-medium">{SEARCH_NOT_RUN}</span>{' '}
            <span>
              {(() => {
                const idx = sectionIndexAtPosition(error.submitted || '', error.position || 0);
                return idx === null ? STRUCTURE_LINE
                  : sectionCouldNotBeRead(QUERY_SECTION_NAMES[idx]);
              })()}
            </span>
            <span className="block mt-1 text-[#57606a]">
              {error.reason}{' '}
              <span className="text-[#8b949e]">
                {(() => {
                  // A3.6 (F7, the projection boundary): in simple mode a
                  // position inside the FILTERS section remaps to the
                  // FIELD the player actually typed in; positions before
                  // it are compiler territory (corpus-guarded defects) and
                  // keep the whole-query offset.
                  const idx = sectionIndexAtPosition(error.submitted || '', error.position || 0);
                  const off = filtersOffsetOf(error.submitted || '');
                  if (queryMode === 'simple' && idx === 3 && off !== null
                      && (error.position || 0) >= off) {
                    return <>(position {error.position - off} in Filters)</>;
                  }
                  return <>(position {error.position})</>;
                })()}
              </span>
              {error.suggestions && error.suggestions.length > 0 && (
                <> Did you mean: {error.suggestions.join(', ')}?</>
              )}
            </span>
            {snapshot && (
              <span className="block mt-1 text-[#57606a]">{STALE_RESULTS_NOTE}</span>
            )}
            {snapshot && (
              <button
                type="button"
                onClick={restoreLastWorking}
                className="mt-1.5 px-2 py-0.5 rounded border border-[#d0d7de] bg-white text-[#1a2332]"
              >
                {RESTORE_LAST_QUERY}
              </button>
            )}
          </div>
        )}
        {queryMode === 'advanced' && snapshot && !error && queryText.trim() === '' && (
          // A2 3.2 (advanced only; simple mode has no empty state, A3-5.3):
          // the truly-empty bar is guidance, not an error; the preserved
          // results stay labeled.
          <div role="status" data-testid="empty-note" className="px-3 py-1.5 rounded-md bg-[#eef1f4] text-xs text-[#57606a] flex items-center gap-2">
            <span>{NO_QUERY_ENTERED} {PRESERVED_RESULTS_LABEL}</span>
            <button
              type="button"
              onClick={restoreLastWorking}
              className="px-2 py-0.5 rounded border border-[#d0d7de] bg-white text-[#1a2332]"
            >
              {RESTORE_LAST_QUERY}
            </button>
          </div>
        )}
        {snapshot && !error && queryText.trim() !== '' && queryText !== snapshot.identity.canonical_query && (
          // 11.3 edited-query honesty: the bar no longer matches the
          // executed snapshot; the results below belong to the last run.
          <div role="status" data-testid="edited-note" className="px-3 py-1.5 rounded-md bg-[#eef1f4] text-xs text-[#57606a] flex items-center gap-2">
            <span>{EDITED_NOTE}</span>
            <button
              type="button"
              onClick={restoreLastWorking}
              className="px-2 py-0.5 rounded border border-[#d0d7de] bg-white text-[#1a2332]"
            >
              {RESTORE_LAST_QUERY}
            </button>
          </div>
        )}

        {snapshot && (() => {
          // A2 3.3 chips: a READ projection of the EXECUTED canonical
          // FILTERS. The binding boundary (ruled): Custom filters renders
          // for ANY top-level OR (never for conjunction-only), and chips
          // never render a projection unequal to the canonical query.
          const conjuncts = listConjuncts(snapshot.identity.canonical_query);
          if (conjuncts === null) {
            return (
              <div data-testid="filter-chips" className="flex flex-wrap items-center gap-1.5 text-xs">
                <button
                  type="button"
                  data-testid="custom-filters-chip"
                  onClick={() => queryInputRef.current?.focus()}
                  title={splitSegments(snapshot.identity.canonical_query)[3] || ''}
                  className="inline-flex items-center px-2 py-1 rounded-full border border-[#d0d7de] bg-[#eef1f4] text-[#57606a] hover:bg-white"
                >
                  Custom filters
                </button>
              </div>
            );
          }
          if (conjuncts.length === 0) return null;
          return (
            <div data-testid="filter-chips" className="flex flex-wrap items-center gap-1.5 text-xs">
              {conjuncts.map((c, i) => (
                <span
                  key={`${i}-${c}`}
                  className="inline-flex items-center gap-1 px-2 py-1 rounded-full border border-[#d0d7de] bg-white text-[#1a2332]"
                >
                  <span className="log-mono">{c}</span>
                  <button
                    type="button"
                    aria-label={`Remove filter: ${c.split(' ')[0]}`}
                    onClick={() => removeChip(i)}
                    disabled={running || scopeBlocked}
                    className="text-[#6e7781] hover:text-[#1a2332] disabled:opacity-50"
                  >
                    x
                  </button>
                </span>
              ))}
            </div>
          );
        })()}

        {snapshot && (() => {
          // III.0 item 3: the search-state label is primary. Evidence the
          // player did not author is never labeled a player query; an
          // executed search is identified by its READABLE filter
          // expression, the canonical staying beside it as the technical
          // disclosure.
          const filters = rawFiltersOf(snapshot.identity.canonical_query);
          const readable = filters === null || filters.trim() === '*'
            ? ALL_EVENTS_LABEL : filters.trim();
          const stateLabel = snapshotOrigin === 'prepared'
            ? (snapshot.identity.scope === 'session'
              ? INITIAL_EVIDENCE : INITIAL_INCIDENT_EVIDENCE)
            : resultsFor(readable);
          return (
          <div className="px-3 py-1.5 rounded-md bg-[#eef1f4] text-xs text-[#57606a] flex flex-wrap items-center gap-x-3 gap-y-1">
            <span data-testid="results-label" className="font-medium text-[#1a2332]">{stateLabel}</span>
            <span>
              Snapshot: <span className="font-medium text-[#1a2332]">{snapshot.count} events</span>
            </span>
            <span>as of seq #{snapshot.identity.cutoff_seq}</span>
            <span>{simTime(snapshot.identity.resolved_range.end)} sim</span>
            <span className="log-mono">{snapshot.identity.canonical_query}</span>
            <span className="log-mono text-[#8b949e]">scope={snapshot.identity.scope}</span>
            {newCount > 0 && (
              <span
                data-testid="new-events-indicator"
                className={`px-2 py-0.5 rounded-full text-white bg-[#16436b] font-medium ${indicatorStale ? 'opacity-50' : ''}`}
              >
                {newCount} new{indicatorStale ? ' (last run)' : ''}
              </span>
            )}
            {poolGrowth > 0 && (
              <span data-testid="pool-growth" className="text-[#8b949e]">
                pool: +{poolGrowth}
              </span>
            )}
            <button
              type="button"
              onClick={refresh}
              disabled={running}
              title={poolGrowth > 0 ? `pool: +${poolGrowth} events` : undefined}
              className="ml-auto px-2.5 py-1 text-xs font-medium rounded-md border border-[#d0d7de] bg-white text-[#1a2332] hover:bg-[#eef1f4] disabled:opacity-50"
            >
              Refresh
            </button>
          </div>
          );
        })()}

        {timelineActive && (
          <div
            data-testid="descent-banner"
            role="status"
            className="px-3 py-1.5 rounded-md border border-[#16436b]/30 bg-[#16436b]/5 text-xs text-[#1a2332] flex flex-wrap items-center gap-x-2 gap-y-1"
          >
            <span>
              Evidence timeline
              {timeline.host || timeline.account
                ? <> for <span className="log-mono font-medium">{timeline.host || timeline.account}</span></>
                : ' (all participant hosts)'}
              , from <span className="log-mono text-[#16436b]">{timeline.origin}</span>
            </span>
            <span className="text-[#8b949e]">occurrence ascending</span>
            {timeline.kind === 'descent' && timeline.backView && onNavigate && (
              <button
                type="button"
                onClick={() => onNavigate(timeline.backView)}
                className="ml-auto text-[#16436b] hover:underline"
              >
                Back to {timeline.backView === 'incidents' ? 'Incidents' : 'Detections'}
              </button>
            )}
          </div>
        )}
        {selectionNotice && (
          <div role="status" className="px-3 py-1.5 rounded-md bg-[#eef1f4] text-xs text-[#57606a]">
            {selectionNotice}
          </div>
        )}
        {queryNotice && (
          <div role="status" data-testid="query-notice" className="px-3 py-1.5 rounded-md bg-[#eef1f4] text-xs text-[#57606a]">
            {queryNotice}
          </div>
        )}
      </div>

      {/* Results */}
      {!snapshot ? (
        <div
          className="p-6 rounded-xl py-12"
          style={{ background: '#ffffff', border: '1px solid #e2e6ea', boxShadow: '0 1px 2px rgba(0,0,0,0.04)' }}
        >
          <p className="text-sm font-medium text-[#1a2332] mb-1">Run a query to begin.</p>
          {/* A3.5 (F7): mode-scoped guidance. Simple mode teaches the
              filter expression (the ruled help sentence); advanced keeps
              the four-segment teaching. Example buttons stay edit-only. */}
          <p className="text-xs text-[#57606a] mb-3">
            {queryMode === 'simple'
              ? SIMPLE_HELP
              : 'LCQL has four segments: TIMEFRAME | SENSOR | EVENT TYPE | FILTERS. Try one of these:'}
          </p>
          <div className="flex flex-col gap-1.5 mb-4">
            {(queryMode === 'simple' ? SIMPLE_HELP_EXAMPLES : QUERY_HELP_EXAMPLES).map((ex) => (
              <button
                key={ex}
                type="button"
                onClick={() => (queryMode === 'simple'
                  ? setSimplePart('filters', ex)
                  : setQueryText(ex))}
                className="log-mono text-left text-xs px-3 py-1.5 rounded-md border border-[#d0d7de] bg-[#f6f8fa] text-[#1a2332] hover:bg-[#eef1f4]"
              >
                {ex}
              </button>
            ))}
          </div>
          <p className="text-xs text-[#6e7781]">
            Values containing spaces or any of{' '}
            <span className="log-mono">&quot; &#39; = ! | *</span> must be quoted, and the bare
            words and, or, not, contains must be quoted to match literally. Double-quoted and
            unquoted values match case-insensitively; single quotes match exactly.
          </p>
        </div>
      ) : snapshot.count === 0 ? (
        <div className="flex flex-col lg:flex-row gap-4">
          <FieldSidebar snapshot={snapshot} running={running} onValueClick={refineAndRun} />
          <div
            className="flex-1 min-w-0 p-6 rounded-xl flex flex-col items-center justify-center py-14"
            style={{ background: '#ffffff', border: '1px solid #e2e6ea', boxShadow: '0 1px 2px rgba(0,0,0,0.04)' }}
          >
            <p className="text-sm text-[#1a2332] mb-1">0 events match</p>
            <p className="text-xs text-[#6e7781] log-mono">{snapshot.identity.canonical_query}</p>
          </div>
        </div>
      ) : (
        <div className="flex flex-col lg:flex-row gap-4">
          <FieldSidebar snapshot={snapshot} running={running} onValueClick={refineAndRun} />
          <div data-testid="workbench-results" className="flex-1 min-w-0">
            {view === 'cards' ? (
              <SiemCards alerts={displayRows} resetTrigger={resetTrigger}
                         selectedId={selectedId} onSelect={selectRow} />
            ) : (
              <SiemTable alerts={displayRows} resetTrigger={resetTrigger}
                         selectedId={selectedId} onSelect={selectRow} />
            )}
            <div
              ref={inspectorRef}
              tabIndex={-1}
              data-testid="inspector-container"
              className={`outline-none rounded-xl ${inspectorEmphasis ? 'inspector-emphasis' : ''}`}
            >
              <EventInspector
                event={snapshot.rows.find((r) => r.id === selectedId) || null}
                onFilter={refineAndRun}
                onHostPivot={onHostPivot}
                onPivot={pivotAndRun}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Siem;
