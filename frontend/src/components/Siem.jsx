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
} from './lcqlPivots';
import InvestigationContext from './InvestigationContext';
import { TOOLTIPS } from './helpContent';
import {
  caseEvidenceLabel, SEARCH_ALL_EVIDENCE, RESULTS_FROM_LABEL,
  EDITED_NOTE, STALE_RESULTS_NOTE, filterAdded, excludedFilter,
  NO_QUERY_ENTERED, PRESERVED_RESULTS_LABEL, SEARCH_NOT_RUN,
  QUERY_SECTION_NAMES, sectionCouldNotBeRead, STRUCTURE_LINE,
  RESTORE_LAST_QUERY, surroundingBanner, OCCURRENCE_ASCENDING,
  BACK_TO_PREVIOUS_RESULTS,
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
                descentRequest, onNavigate }) => {
  const [org, setOrg] = useState({});
  const [view, setView] = useState('cards');
  const [queryText, setQueryText] = useState('');
  const [snapshot, setSnapshot] = useState(null);   // {token, identity, count, rows}
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
  // Stage 5 Phase 1 (Amendment 1 Delta A): the case-constant state pair.
  // Case evidence = scope kind 'incident' anchored to the current case;
  // Expanded search = scope kind 'session' WHILE a case is pinned (entered
  // only through an entity pivot or the explicit search-all action). The
  // case itself is the activeIncidentId prop -- selected on Incidents,
  // never changeable from here (ratified OD-15, structural).
  // P7.2: the evidence-timeline context ({kind:'descent', origin, backView,
  // host, query}). Pure UI provenance (contract Section 12: the breadcrumb
  // "implies nothing about any row"); the banner and the ascending display
  // render ONLY while the displayed snapshot's canonical query is the
  // timeline's own query, so they can never mislabel another snapshot.
  const [timeline, setTimeline] = useState(null);
  // Phase 3 commit 3.1: the pivot transition provenance ({query, clue}).
  // The clue line renders ONLY while the displayed snapshot IS the pivot's
  // own query (the same identity guard the timeline banner uses), so it can
  // never mislabel another snapshot; the expanded-search block itself is
  // state-driven and persists across queries within the state.
  const [transition, setTransition] = useState(null);
  // A2 3.4 (ruled): the SINGLE-DEPTH hold behind a surrounding view -- the
  // prior evidence view (frozen snapshot + bar text + scope) held at entry,
  // overwritten on re-entry, dropped by any other run, restored with ZERO
  // requests by the one return action.
  const [heldView, setHeldView] = useState(null);
  const preserveHoldRef = useRef(false);
  const focusSeqRef = useRef(0);
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
    setError(null);
    setRunning(false);
    setScope({ kind: 'session' });
    setSelectedId(null);
    setSelectionNotice(null);
    setQueryNotice(null);
    setTimeline(null);
    setTransition(null);
    setHeldView(null);
  }, [resetTrigger]);

  const loadIncidentScope = (id) => {
    setScope({ kind: 'incident', id, status: 'loading' });
    apiFetch(`/api/incidents/${id}/scope`)
      .then((res) => { if (!res.ok) throw new Error('scope'); return res.json(); })
      .then((sc) => setScope({ kind: 'incident', id, status: 'ready',
                               sealed: !!sc.sealed }))
      // Revised scope-error behavior (kept from M1/Stage 4): keep the state
      // label, preserve the prior snapshot, disable Run; recovery is Retry
      // only (ratified A-OD-3) -- or the deliberate Expanded search, which
      // needs no case scope.
      .catch(() => setScope({ kind: 'incident', id, status: 'error' }));
  };

  // Case-constant anchor (Amendment 1 Delta A, A1-A.2): the SIEM re-anchors
  // atomically when the current case changes -- case evidence for a case,
  // All activity for none. The prior snapshot belonged to the prior anchor
  // and is dropped; nothing in this component can change the case itself
  // (ratified OD-15, structural: case selection lives on Incidents alone).
  useEffect(() => {
    setSnapshot(null);
    setError(null);
    setQueryText('');
    setTimeline(null);
    setTransition(null);
    setHeldView(null);
    setQueryNotice(null);
    setSelectedId(null);
    setSelectionNotice(null);
    if (activeIncidentId) loadIncidentScope(activeIncidentId);
    else setScope({ kind: 'session' });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeIncidentId]);

  const scopeBlocked = scope.kind === 'incident' && scope.status !== 'ready';
  const scopeParam = scope.kind === 'incident' ? scope.id : 'session';
  // Expanded search is live exactly while a case is pinned and the executed
  // scope is the session (entered ONLY via entity pivot or search-all).
  const expandedSearch = !!(activeIncidentId && scope.kind === 'session');

  // Enter Expanded search deliberately (A1-A.2 point 4; ratified A-OD-4
  // placement): run the current query across ALL evidence while the case
  // stays pinned. Deliberately NOT gated on the case-evidence read -- the
  // expanded state needs no case scope and is the designed exploration
  // path out of a failed scope read.
  const searchAll = () => {
    if (running || queryText.trim() === '') return;
    setScope({ kind: 'session' });
    execute(queryText, 'session');
  };

  const setTimeframe = (tok) => {
    setQueryText((t) => {
      if (t.trim() === '') return `${tok} | * | * | *`;
      const idx = t.indexOf('|');
      // the text up to the first pipe IS the first segment; replace it in
      // place (no pipe: the whole text is the first segment)
      if (idx === -1) return tok;
      return `${tok} ${t.slice(idx)}`;
    });
  };
  const tfValue = firstSegmentToken(queryText) ||
    (queryText.trim() === '' ? '1h' : '');

  // Atomic replacement: the new snapshot object swaps in whole; a failed
  // run leaves the prior snapshot untouched. Selection survival (P5.1):
  // when the inspected id is present in the new rows, selection and the
  // open inspector persist; otherwise the inspector closes with a one-line
  // notice and nothing else is lost.
  const applySnapshot = (body) => {
    setSnapshot(body);
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
    setSelectedId((sel) => {
      if (sel && !body.rows.some((r) => r.id === sel)) {
        setSelectionNotice('The inspected event is not in the new snapshot.');
        return null;
      }
      setSelectionNotice(null);
      return sel;
    });
  };

  // `noticeAfter`: the OR-fallback text to show once THIS run lands (null
  // clears any stale notice from an earlier refinement -- plain Run/Refresh
  // always pass none).
  const execute = (q, scopeValue, noticeAfter = null) => {
    if (running) return;
    // any run other than a surrounding ENTRY drops the held prior view
    // (single-depth, never a history stack)
    if (!preserveHoldRef.current) setHeldView(null);
    preserveHoldRef.current = false;
    setRunning(true);
    apiFetch(`/api/events/query?q=${encodeURIComponent(q)}&scope=${encodeURIComponent(scopeValue)}`)
      .then(async (res) => {
        const body = await res.json().catch(() => null);
        if (res.ok && body) {
          applySnapshot(body);
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
    // A2 3.2 (ruled): Run disables ONLY on a truly empty bar -- an empty
    // query is guidance territory, never an error; a malformed non-empty
    // query RUNS and receives a section-named teaching error.
    if (running || scopeBlocked || queryText.trim() === '') return;
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
  const refresh = () => {
    if (!snapshot || running) return;
    execute(snapshot.identity.canonical_query, snapshot.identity.scope);
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

  // P7.1 entity pivots (contract Sections 13/14; Amendment 1 Delta A):
  // every pivot mints its documented query from the EXECUTED snapshot's
  // TIMEFRAME token through the one generator, then ALWAYS executes across
  // all evidence. With a case pinned that IS the Expanded search state:
  // the block announces it on screen (never a silent side effect) and the
  // single return action restores the case evidence.
  const PIVOT_FORMS = {
    host: pivotHost, account: pivotAccount, process: pivotProcessImage,
    file: pivotFile, ip: pivotIp, domain_proxy: pivotDomainProxy,
    domain_dns: pivotDomainDns, event_type: pivotEventType,
    sensor: pivotSensorFamily,
  };
  const pivotAndRun = (kind, value, field) => {
    if (!snapshot || running) return;
    const tf = splitSegments(snapshot.identity.canonical_query)[0];
    const query = PIVOT_FORMS[kind](tf, value);
    // 8.2 clue naming: the followed field + value ride the transition
    // provenance; the block's clue line renders under the identity guard.
    setTransition({ query, clue: field ? { field, value } : null });
    setScope({ kind: 'session' });
    setQueryText(query);
    execute(query, 'session');
  };

  // P7.3 surrounding events (contract Section 13 row: `all | H | * | *`,
  // occurrence ascending, viewport centered on the source event). A context
  // view around one event, NOT an entity pivot -- Section 14's Session-wide
  // rule does not apply, so it runs under the CURRENT scope. The generated
  // string is the documented host-timeline form (the one generator).
  const surroundingAndRun = (hostname, eventId) => {
    if (!snapshot || running || scopeBlocked) return;
    const query = descentHost(hostname);
    focusSeqRef.current += 1;
    // hold the prior evidence view (A2 3.4): the frozen snapshot object,
    // its bar text, and its scope -- restored exactly, zero requests
    setHeldView({ snapshot, queryText, scope });
    preserveHoldRef.current = true;
    setQueryText(query);
    setTimeline({ kind: 'surrounding', host: hostname, focusId: eventId,
                  focusSeq: focusSeqRef.current, query });
    execute(query, scopeParam);
  };

  // The ONE return from a surrounding view (ruled): redisplay the held
  // frozen snapshot exactly. No request is issued; the new-count poll
  // resumes on the restored token (an invalidated token halts neutrally
  // through the existing countHalted path).
  const restoreHeldView = () => {
    if (!heldView || running) return;
    setSnapshot(heldView.snapshot);
    setQueryText(heldView.queryText);
    setScope(heldView.scope);
    setError(null);
    setTimeline(null);
    setQueryNotice(null);
    setNewCount(0);
    setPoolGrowth(0);
    setCountHalted(false);
    setSelectedId((sel) => {
      if (sel && !heldView.snapshot.rows.some((r) => r.id === sel)) {
        setSelectionNotice('The inspected event is not in the new snapshot.');
        return null;
      }
      setSelectionNotice(null);
      return sel;
    });
    setHeldView(null);
  };

  // The single return action (A1-A.2 point 4): "Return to INC-#### evidence"
  // re-runs the query currently in the bar under the case's participant
  // scope -- the existing Stage 4 return mechanic, now the ONE exit from
  // Expanded search. Uses the same scope-read + error behavior as the
  // case anchor (never a silent fallback).
  const returnToIncident = (id) => {
    if (running) return;
    setScope({ kind: 'incident', id, status: 'loading' });
    apiFetch(`/api/incidents/${id}/scope`)
      .then((res) => { if (!res.ok) throw new Error('scope'); return res.json(); })
      .then((sc) => {
        setScope({ kind: 'incident', id, status: 'ready', sealed: !!sc.sealed });
        execute(queryText, id);
      })
      .catch(() => setScope({ kind: 'incident', id, status: 'error' }));
  };

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
  // lack participant hostnames; the visible scope control is the designed
  // path out. The request carries ONLY observable data from the origin
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
          execute(query, scopeIncidentId);
        })
        .catch(() => setScope({ kind: 'incident', id: scopeIncidentId, status: 'error' }));
    } else {
      setScope({ kind: 'session' });
      execute(query, 'session');
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

      {/* Case-constant context + TIMEFRAME + query bar (Amendment 1 Delta A):
          the pinned case line, the case-evidence state label, the explicit
          search-all action, and the expanded-search block replace the old
          scope select. No control here can change the case (OD-15). */}
      <div className="mb-3 flex flex-col gap-2">
        <InvestigationContext
          incidentId={activeIncidentId || null}
          expandedSearch={expandedSearch
            ? {
                clue: (transition && snapshot
                       && snapshot.identity.canonical_query === transition.query)
                  ? transition.clue : null,
                noResults: !!(snapshot && snapshot.count === 0),
                onReturn: () => returnToIncident(activeIncidentId),
              }
            : null}
        />
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {activeIncidentId && scope.kind === 'incident' && (
            <span
              data-testid="scope-chip"
              className="inline-flex items-center gap-1.5 px-2 py-1 rounded-full bg-[#eef1f4] text-[#1a2332]"
            >
              <span className="log-mono text-[#16436b] font-medium">{caseEvidenceLabel(scope.id)}</span>
              {scope.status === 'loading' && <span className="text-[#6e7781]">loading scope</span>}
              {scope.status === 'error' && <span className="text-[#b26666]">scope unavailable</span>}
            </span>
          )}
          {activeIncidentId && scope.kind === 'incident' && (
            <button
              type="button"
              data-testid="search-all"
              onClick={searchAll}
              disabled={running || queryText.trim() === ''}
              title={TOOLTIPS.expanded_search}
              data-help={TOOLTIPS.expanded_search}
              className="help-tip inline-flex items-center gap-1 px-2 py-1 rounded-full border border-[#16436b]/40 text-[#16436b] text-xs hover:bg-[#16436b]/5 disabled:opacity-50"
            >
              {SEARCH_ALL_EVIDENCE}
            </button>
          )}
          <label className="flex items-center gap-1.5 text-[#6e7781] ml-auto">
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
          <input
            type="text"
            ref={queryInputRef}
            placeholder={QUERY_PLACEHOLDER}
            value={queryText}
            onChange={(e) => setQueryText(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') runQuery(); }}
            readOnly={running}
            maxLength={300}
            aria-label="LCQL query"
            className="log-mono flex-1 pl-4 pr-4 py-2 rounded-md bg-white border border-[#e2e6ea] text-[#1a2332] text-sm placeholder-[#8b949e] placeholder:italic focus:border-[#8b949e] focus:outline-none transition-colors"
          />
          <button
            type="button"
            onClick={runQuery}
            disabled={running || scopeBlocked || queryText.trim() === ''}
            title={queryText.trim() === '' ? NO_QUERY_ENTERED : 'Run the query in the bar.'}
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
              {error.reason} <span className="text-[#8b949e]">(position {error.position})</span>
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
        {snapshot && !error && queryText.trim() === '' && (
          // A2 3.2: the truly-empty bar is guidance, not an error; the
          // preserved results stay labeled.
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

        {snapshot && (
          <div className="px-3 py-1.5 rounded-md bg-[#eef1f4] text-xs text-[#57606a] flex flex-wrap items-center gap-x-3 gap-y-1">
            <span>
              Snapshot: <span className="font-medium text-[#1a2332]">{snapshot.count} events</span>
            </span>
            <span>as of seq #{snapshot.identity.cutoff_seq}</span>
            <span>{simTime(snapshot.identity.resolved_range.end)} sim</span>
            <span>
              {RESULTS_FROM_LABEL}{' '}
              <span className="log-mono">{snapshot.identity.canonical_query}</span>
            </span>
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
        )}

        {timelineActive && (
          <div
            data-testid="descent-banner"
            role="status"
            className="px-3 py-1.5 rounded-md border border-[#16436b]/30 bg-[#16436b]/5 text-xs text-[#1a2332] flex flex-wrap items-center gap-x-2 gap-y-1"
          >
            {timeline.kind === 'surrounding' ? (
              // A2 3.4 (ruled block copy): temporary context with the ONE
              // clear return to the prior frozen results.
              <span>{surroundingBanner(timeline.host)}</span>
            ) : (
              <span>
                Evidence timeline
                {timeline.host || timeline.account
                  ? <> for <span className="log-mono font-medium">{timeline.host || timeline.account}</span></>
                  : ' (all participant hosts)'}
                , from <span className="log-mono text-[#16436b]">{timeline.origin}</span>
              </span>
            )}
            <span className="text-[#8b949e]">
              {timeline.kind === 'surrounding' ? OCCURRENCE_ASCENDING : 'occurrence ascending'}
            </span>
            {timeline.kind === 'surrounding' && heldView && (
              <button
                type="button"
                data-testid="surrounding-return"
                onClick={restoreHeldView}
                className="ml-auto text-[#16436b] hover:underline"
              >
                {BACK_TO_PREVIOUS_RESULTS}
              </button>
            )}
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
          <p className="text-xs text-[#57606a] mb-3">
            LCQL has four segments: TIMEFRAME | SENSOR | EVENT TYPE | FILTERS. Try one of these:
          </p>
          <div className="flex flex-col gap-1.5 mb-4">
            {QUERY_HELP_EXAMPLES.map((ex) => (
              <button
                key={ex}
                type="button"
                onClick={() => setQueryText(ex)}
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
                         selectedId={selectedId} onSelect={selectRow}
                         focus={timelineActive && timeline.kind === 'surrounding'
                           ? { id: timeline.focusId, seq: timeline.focusSeq } : null} />
            ) : (
              <SiemTable alerts={displayRows} resetTrigger={resetTrigger}
                         selectedId={selectedId} onSelect={selectRow}
                         focus={timelineActive && timeline.kind === 'surrounding'
                           ? { id: timeline.focusId, seq: timeline.focusSeq } : null} />
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
                onSurrounding={surroundingAndRun}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Siem;
