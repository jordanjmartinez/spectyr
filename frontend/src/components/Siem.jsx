import React, { useState, useEffect, useRef } from 'react';
import { apiFetch } from '../api';
import SiemTable from './SiemTable';
import SiemCards from './SiemCards';
import FacetRail from './FacetRail';
import EventInspector from './EventInspector';
import {
  descentHost, descentSessionAll, descentAccount, rawFiltersOf,
} from './lcqlPivots';
import {
  compileChips, adoptQuery, toggleInclude, describeChip,
  entityChipFor, fieldValueCounts, parseSearchInput, mergeChips,
} from './facetModel';
import { CARD_STYLE, SegmentedToggle } from './ui';
import {
  followingClue, resultsFor, ALL_EVENTS_LABEL, INITIAL_INCIDENT_EVIDENCE,
  INITIAL_EVIDENCE, SELECTED_EVENT_HIDDEN, newEventsAvailable,
  LOAD_NEW_EVENTS, STALE_RESULTS_NOTE, filterAdded, excludedFilter,
  SEARCH_NOT_RUN, FILTERS_TOGGLE, TOO_MANY_FILTERS, SHOW_EVENTS,
  FILTERS_EMPTY_HINT, INCIDENT_WINDOW_LABEL, ALL_TIME_LABEL,
  SEARCH_PLACEHOLDER, SEARCH_BUTTON, searchUnknownField, SEARCH_IP_CONTAINS,
} from './uiCopy';

// SIEM Investigation Workbench shell (Stage 4 Phase 4; owner SIEM
// simplification pass + follow-up, 2026-10-13). Analyst-driven: the shell
// submits LCQL text to the server's single query read and renders the
// returned frozen snapshot exactly as served. No polling, no client-side
// filtering, no client-side query execution of any kind (contract P8):
// rows never insert, remove, or reorder until a search runs again.
//
// ONE filter system: the facet rail (six plain-language groups + More
// Filters), the entity action menu in the inspector, the removable chips
// above the results, and ONE simple search box (field = value / field
// contains text / plain free text -- everything it parses becomes the same
// chips). There is no LCQL bar: every interaction compiles through the
// facetModel / lcqlPivots chokepoint into canonical LCQL and executes
// immediately server-side. Timeframe stays on top, with an Incident Window
// preset when a case is pinned (under the incident anchor, `all` IS the
// incident's evidence window).

export const TF_TOKENS = ['15m', '1h', '4h', '12h', '24h', 'all'];

// Mirrors the server cap in app.py's query_events (raised with the facet
// system: multi-select distributes into OR-of-ANDs, which needs room).
const QUERY_MAX_LENGTH = 2000;

const firstSegmentToken = (text) => {
  const idx = text.indexOf('|');
  const head = (idx === -1 ? text : text.slice(0, idx)).trim().toLowerCase();
  return TF_TOKENS.includes(head) ? head : null;
};

const Siem = ({ resetTrigger, onHostPivot, activeIncidentId,
                descentRequest }) => {
  const [view, setView] = useState('cards');
  // Stage 6 playtest fix 9 (carried through this pass): below lg the
  // results column stacks, so the facet rail sits behind a disclosure
  // (default closed, events render first); at lg+ it is the always-visible
  // side column. A facet click closes the disclosure.
  const [railOpen, setRailOpen] = useState(false);
  // The facet filter state: ONE timeframe token + the chip list. Every
  // landed search keeps these truthful (facet runs carry their own state;
  // prepared descents ADOPT their canonical into chips at landing).
  const [tf, setTf] = useState('1h');
  const [chips, setChips] = useState([]);
  // Sibling baselines: for a group the player narrowed, the same search
  // WITHOUT that group's own selections, fetched on request (Show More) so
  // multi-select within a group stays possible. {field: [{value, count}]}
  const [facetBaselines, setFacetBaselines] = useState({});
  const baselineSeqRef = useRef(0);
  // The one simple search box (owner follow-up): its text and its friendly
  // parse error. Parsing produces chips; nothing executes until Enter.
  const [searchText, setSearchText] = useState('');
  const [searchError, setSearchError] = useState(null);
  const [snapshot, setSnapshot] = useState(null);   // {token, identity, count, rows}
  // Search-state truth (III.0 item 3): the displayed snapshot's PROVENANCE.
  // 'facets' = compiled from the chip state (facets, chips, search box,
  // menu); 'prepared' = the shell executed a prepared entry query (evidence
  // descent) the player never wrote -- labeled "Initial incident evidence",
  // never "Results for:". Load new events re-executes the displayed
  // identity, so it preserves the origin it loads.
  const [snapshotOrigin, setSnapshotOrigin] = useState('facets');
  const [error, setError] = useState(null);         // {reason} (server failure)
  const [running, setRunning] = useState(false);
  // Scope state machine (contract Section 6, revised scope-error behavior):
  // {kind:'session'} | {kind:'incident', id, status:'loading'|'ready'|'error', sealed}
  const [scope, setScope] = useState({ kind: 'session' });
  // P5.1: ONE inspector selection, keyed by event id, owned by the shell so
  // it persists across view toggles and Load new events (when the id
  // survives).
  const [selectedId, setSelectedId] = useState(null);
  const [selectionNotice, setSelectionNotice] = useState(null);
  // The one query-notice line: refine / exclude / pivot announcements
  // (cleared by any subsequent plain run / load).
  const [queryNotice, setQueryNotice] = useState(null);
  // P5.2: the new-events indicator (contract Section 8, R16 refresh-now).
  // Token-bound: the poll carries ONLY the executed snapshot's token.
  // countHalted stops the poll neutrally after a token invalidation.
  const [newCount, setNewCount] = useState(0);
  const [poolGrowth, setPoolGrowth] = useState(0);
  const [countHalted, setCountHalted] = useState(false);
  // ONE evidence universe per case state (Stage 5 / Final pass): scope kind
  // 'incident' anchors every search to the current case's complete
  // observable evidence pool; 'session' is the no-case fallback. The case
  // itself is the activeIncidentId prop -- selected on Incidents, never
  // changeable from here (ratified OD-15, structural).
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

  const clearFacetState = () => {
    setTf('1h');
    setChips([]);
    setFacetBaselines({});
    setSearchText('');
    setSearchError(null);
    baselineSeqRef.current += 1;
  };

  // Session reset clears every piece of workbench state (scaffold S6-S13).
  useEffect(() => {
    setSnapshot(null);
    setSnapshotOrigin('facets');
    setError(null);
    setRunning(false);
    setScope({ kind: 'session' });
    setSelectedId(null);
    setSelectionNotice(null);
    setQueryNotice(null);
    clearFacetState();
  }, [resetTrigger]);

  const loadIncidentScope = (id) => {
    setScope({ kind: 'incident', id, status: 'loading' });
    apiFetch(`/api/incidents/${id}/scope`)
      .then((res) => { if (!res.ok) throw new Error('scope'); return res.json(); })
      .then((sc) => setScope({ kind: 'incident', id, status: 'ready',
                               sealed: !!sc.sealed }))
      // Revised scope-error behavior (kept from M1/Stage 4): preserve the
      // prior snapshot, block new searches; recovery is Retry only.
      .catch(() => setScope({ kind: 'incident', id, status: 'error' }));
  };

  // Case-constant anchor (Amendment 1 Delta A, A1-A.2): the SIEM re-anchors
  // atomically when the current case changes. The prior snapshot belonged
  // to the prior anchor and is dropped; nothing in this component can
  // change the case itself (ratified OD-15, structural).
  useEffect(() => {
    setSnapshot(null);
    setSnapshotOrigin('facets');
    setError(null);
    setQueryNotice(null);
    setSelectedId(null);
    setSelectionNotice(null);
    clearFacetState();
    if (activeIncidentId) loadIncidentScope(activeIncidentId);
    else setScope({ kind: 'session' });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeIncidentId]);

  const scopeBlocked = scope.kind === 'incident' && scope.status !== 'ready';
  const scopeParam = scope.kind === 'incident' ? scope.id : 'session';

  // Atomic replacement: the new snapshot object swaps in whole; a failed
  // run leaves the prior snapshot untouched. Selection survival (P5.1):
  // when the inspected id is present in the new rows, selection and the
  // open inspector persist; otherwise the selection is retained with the
  // ruled notice and the pane reopens when a later result set includes the
  // event again.
  const applySnapshot = (body, origin, facetState) => {
    setSnapshot(body);
    setSnapshotOrigin(origin);
    setError(null);
    // The chip state follows every landed search: a facet-compiled run
    // carries its own state; a prepared descent ADOPTS the executed
    // canonical into chips (every prepared form is adoptable by
    // construction; the fallback is defensive).
    baselineSeqRef.current += 1;
    setFacetBaselines({});
    if (facetState) {
      setTf(facetState.tf);
      setChips(facetState.chips);
    } else {
      const adopted = adoptQuery(body.identity.canonical_query);
      if (adopted) {
        setTf(adopted.tf);
        setChips(adopted.chips);
      } else {
        setTf(firstSegmentToken(body.identity.canonical_query) || '1h');
        setChips([]);
      }
    }
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

  // `noticeAfter`: the clue text to show once THIS run lands (null clears
  // any stale notice from an earlier refinement). `origin` is the snapshot
  // provenance; `facetState` is the {tf, chips} a facet-compiled run
  // carries.
  const execute = (q, scopeValue, noticeAfter = null, origin = 'facets', facetState = null) => {
    if (running) return;
    setRunning(true);
    apiFetch(`/api/events/query?q=${encodeURIComponent(q)}&scope=${encodeURIComponent(scopeValue)}`)
      .then(async (res) => {
        const body = await res.json().catch(() => null);
        if (res.ok && body) {
          applySnapshot(body, origin, facetState);
          setQueryNotice(noticeAfter);
        } else if (body && body.error && typeof body.error === 'object') {
          setError({ reason: body.error.reason });
        } else {
          setError({ reason: 'The query could not be executed.' });
        }
      })
      .catch(() => setError({ reason: 'The query could not be executed.' }))
      .finally(() => setRunning(false));
  };

  // --- the ONE filter system: every interaction compiles and runs ----------

  const runFacets = (tfTok, nextChips, notice = null) => {
    if (running || scopeBlocked) return;
    const query = compileChips(tfTok, nextChips);
    if (query.length > QUERY_MAX_LENGTH) {
      setQueryNotice(TOO_MANY_FILTERS);
      return;
    }
    execute(query, scopeParam, notice, 'facets', { tf: tfTok, chips: nextChips });
  };

  const toggleFacetValue = (field, value) => {
    if (running || scopeBlocked || !snapshot) return;
    setRailOpen(false);
    runFacets(tf, toggleInclude(chips, field, value));
  };

  const removeChipAt = (index) => {
    if (running || scopeBlocked) return;
    runFacets(tf, chips.filter((_, i) => i !== index));
  };

  // The inspector's entity menu (Filter to Just This / Filter This Out /
  // Pivot). Every action lands in the chip state and executes immediately.
  const handleEntityAction = (field, action, value) => {
    if (running || scopeBlocked || !snapshot) return;
    if (action === 'only') {
      const next = [
        ...chips.filter((c) => !(c.type === 'include' && c.field === field)),
        { type: 'include', field, value },
      ];
      runFacets(tf, next, filterAdded(field, value));
      return;
    }
    if (action === 'exclude') {
      const next = chips
        .filter((c) => !(c.type === 'include' && c.field === field && c.value === value))
        .concat([{ type: 'exclude', field, value }]);
      runFacets(tf, next, excludedFilter(field, value));
      return;
    }
    if (action === 'pivot') {
      const chip = entityChipFor(field, value);
      if (!chip) return;
      // a pivot is fresh-by-design: it follows the clue inside the CURRENT
      // evidence pool with a clean filter state
      runFacets(tf, [chip], followingClue(field, value));
    }
  };

  // The one simple search box: parse to chips, merge, run. A friendly
  // error renders inline for unknown fields; nothing executes on error.
  const submitSearch = () => {
    if (running || scopeBlocked) return;
    const parsed = parseSearchInput(searchText);
    if (parsed.error) {
      setSearchError(parsed.error.kind === 'ip_contains'
        ? SEARCH_IP_CONTAINS
        : searchUnknownField(parsed.error.name));
      return;
    }
    if (parsed.chips.length === 0) return;
    setSearchError(null);
    setSearchText('');
    runFacets(tf, mergeChips(chips, parsed.chips));
  };

  // Sibling baseline for ONE narrowed group, fetched only when the player
  // asks for more values (Show More): the same search without that group's
  // own selections, executed server-side under the executed scope.
  const requestBaseline = (field) => {
    if (!snapshot) return;
    const rest = chips.filter((c) => !(c.type === 'include' && c.field === field));
    if (!chips.some((c) => c.type === 'include' && c.field === field)) return;
    const query = compileChips(tf, rest);
    const seq = baselineSeqRef.current;
    apiFetch(`/api/events/query?q=${encodeURIComponent(query)}&scope=${encodeURIComponent(snapshot.identity.scope)}`)
      .then((res) => (res.ok ? res.json() : null))
      .then((body) => {
        if (!body || !Array.isArray(body.rows)) return;
        if (baselineSeqRef.current !== seq) return;   // a newer search landed
        setFacetBaselines((prev) => ({
          ...prev, [field]: fieldValueCounts(body.rows, field),
        }));
      })
      .catch(() => {});
  };

  // --- timeframe (kept on top) ----------------------------------------------

  const setTimeframe = (tok) => {
    setTf(tok);
    if (snapshot) runFacets(tok, chips);
  };
  // The Incident Window preset: with a case pinned, every search already
  // runs inside that incident's complete observable evidence pool, so the
  // `all` token IS the incident's window; the label says so honestly.
  const allTokenLabel = activeIncidentId ? INCIDENT_WINDOW_LABEL : ALL_TIME_LABEL;

  // Load new events (III.0 item 4): re-executes the DISPLAYED snapshot's
  // definition (its canonical query and executed scope). The action renders
  // ONLY beside a nonzero authoritative new-count; a landed load resets the
  // count truthfully (applySnapshot) and preserves provenance + chips.
  const loadNewEvents = () => {
    if (!snapshot || running) return;
    const facetState = snapshotOrigin === 'facets' ? { tf, chips } : null;
    execute(snapshot.identity.canonical_query, snapshot.identity.scope, null,
            snapshotOrigin, facetState);
  };

  const selectRow = (id) => {
    setSelectedId(id);
    setSelectionNotice(null);
  };

  // P7.2/P7.4 "Investigate in SIEM" entry (contract Sections 13/16; R17
  // uniform control): the entry prepares and opens the existing SIEM
  // search, explicitly establishing scope and anchoring to the OBSERVABLE
  // ENTITY. An account-entity detection prepares the account form
  // (user_account == "A" or UserPrincipalName == "A"); one participant
  // host prepares that host's search; several -- or none known yet --
  // prepare the whole-pool query under the incident's participant scope.
  // Scope follows ONE rule for every anchor kind: the player-selected
  // incident context when the entry carries one, Session-wide otherwise.
  // The request carries ONLY observable data from the origin surface; the
  // query is generated HERE through the one generator, lands as a
  // 'prepared' snapshot, and its chips adopt at landing like every search.
  useEffect(() => {
    if (!descentRequest) return;
    const { hosts, account, scopeIncidentId } = descentRequest;
    const host = !account && hosts && hosts.length === 1 ? hosts[0] : null;
    const query = account ? descentAccount(account)
      : host ? descentHost(host) : descentSessionAll();
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

  // Stage 6 playtest fix 9: the ONE filter column, shared by the 0-events
  // and results layouts. Below lg it sits behind the disclosure (default
  // closed so events render first); at lg+ the disclosure is hidden and
  // the rail is always visible.
  const railColumn = (
    <div className="w-full lg:w-56 shrink-0">
      <button
        type="button"
        onClick={() => setRailOpen((o) => !o)}
        aria-expanded={railOpen}
        className="lg:hidden w-full flex items-center justify-between px-3 py-2 text-sm rounded-md border border-[#d0d7de] bg-white text-muted hover:bg-[#eef1f4]"
      >
        <span>{FILTERS_TOGGLE}</span>
        <span className="text-xs text-muted">{railOpen ? 'Hide' : 'Show'}</span>
      </button>
      <div className={`${railOpen ? 'mt-2' : 'hidden'} lg:mt-0 lg:block`}>
        <FacetRail
          snapshot={snapshot}
          running={running}
          chips={chips}
          baselines={facetBaselines}
          onToggle={toggleFacetValue}
          onRequestBaseline={requestBaseline}
        />
      </div>
    </div>
  );

  return (
    <div>
      {/* Owner follow-up pass (2026-10-13): no incident context line here
          (the shell header carries the session context); Timeframe + the
          one search box are the whole top bar. No control here can change
          the case (OD-15). */}
      <div className="mb-3 flex flex-col gap-2">
        {activeIncidentId && scope.kind === 'incident' && scope.status === 'loading' && (
          <span className="text-xs text-muted">Loading incident scope</span>
        )}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <label className="flex items-center gap-1.5 text-muted">
            Timeframe
            <select
              value={tf}
              onChange={(e) => setTimeframe(e.target.value)}
              aria-label="Timeframe"
              className="px-2.5 py-1.5 rounded-md border border-[#d0d7de] bg-white text-[#1a2332]"
            >
              {TF_TOKENS.map((t) => (
                <option key={t} value={t}>{t === 'all' ? allTokenLabel : t}</option>
              ))}
            </select>
          </label>
          <input
            type="text"
            value={searchText}
            onChange={(e) => { setSearchText(e.target.value); setSearchError(null); }}
            onKeyDown={(e) => { if (e.key === 'Enter') submitSearch(); }}
            placeholder={SEARCH_PLACEHOLDER}
            maxLength={300}
            aria-label="Search events"
            className="flex-1 min-w-[12rem] px-3 py-1.5 rounded-md bg-white border border-[#e2e6ea] text-[#1a2332] placeholder-[#8b949e] focus:border-[#8b949e] focus:outline-none transition-colors"
          />
          <button
            type="button"
            onClick={submitSearch}
            disabled={running || scopeBlocked || searchText.trim() === ''}
            className="px-3 py-1.5 text-xs font-medium rounded-md bg-[#101218] text-white disabled:opacity-50"
          >
            {SEARCH_BUTTON}
          </button>
        </div>
        {searchError && (
          <div role="alert" data-testid="search-error" className="px-3 py-1.5 rounded-md border border-[#e2e6ea] bg-[#faf6f0] text-xs text-[#1a2332]">
            {searchError}
          </div>
        )}

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
          <div className="px-3 py-1.5 rounded-md bg-[#eef1f4] text-xs text-muted">
            Incident telemetry is still loading.
          </div>
        )}

        {error && (
          // Parse errors are structurally impossible now (every executed
          // query comes from the chokepoint), so this is the server-failure
          // surface: the not-run sentence, the reason, and the stale line
          // exactly when prior results are preserved.
          <div className="px-3 py-2 rounded-md border border-[#e2e6ea] bg-[#faf6f0] text-xs text-[#1a2332]" role="alert">
            <span className="font-medium">{SEARCH_NOT_RUN}</span>{' '}
            <span className="text-muted">{error.reason}</span>
            {snapshot && (
              <span className="block mt-1 text-muted">{STALE_RESULTS_NOTE}</span>
            )}
          </div>
        )}

        {/* Applied filters as removable chips above the results. The chips
            ARE the filter state: removing one recompiles and reruns. */}
        {snapshot && chips.length > 0 && (
          <div data-testid="filter-chips" className="flex flex-wrap items-center gap-1.5 text-xs">
            {chips.map((c, i) => {
              const label = describeChip(c);
              return (
                <span
                  key={`${i}-${label}`}
                  className="inline-flex items-center gap-1 px-2 py-1 rounded-full border border-[#d0d7de] bg-white text-[#1a2332]"
                >
                  <span>{label}</span>
                  <button
                    type="button"
                    aria-label={`Remove filter: ${label}`}
                    onClick={() => removeChipAt(i)}
                    disabled={running || scopeBlocked}
                    className="text-muted hover:text-[#1a2332] disabled:opacity-50"
                  >
                    x
                  </button>
                </span>
              );
            })}
          </div>
        )}

        {snapshot && (() => {
          // Owner follow-up pass (2026-10-13): the trimmed snapshot meta
          // line -- the search-state label, the count, and the scope. The
          // seq number, sim timestamp, and raw canonical dump are gone.
          const filters = rawFiltersOf(snapshot.identity.canonical_query);
          const readable = filters === null || filters.trim() === '*'
            ? ALL_EVENTS_LABEL : filters.trim();
          const stateLabel = snapshotOrigin === 'prepared'
            ? (snapshot.identity.scope === 'session'
              ? INITIAL_EVIDENCE : INITIAL_INCIDENT_EVIDENCE)
            : resultsFor(readable);
          const scopeLabel = snapshot.identity.scope === 'session'
            ? 'Session' : snapshot.identity.scope;
          return (
          <div className="px-3 py-1.5 rounded-md bg-[#eef1f4] text-xs text-muted flex flex-wrap items-center gap-x-3 gap-y-1">
            <span data-testid="results-label" className="font-medium text-[#1a2332]">{stateLabel}</span>
            <span>
              Snapshot: <span className="font-medium text-[#1a2332]">{snapshot.count} events</span>
            </span>
            <span>Scope: {scopeLabel}</span>
            {newCount > 0 && (
              <span
                data-testid="new-events-indicator"
                className="px-2 py-0.5 rounded-full text-white bg-[#16436b] font-medium"
              >
                {newEventsAvailable(newCount)}
              </span>
            )}
            {poolGrowth > 0 && (
              <span data-testid="pool-growth" className="text-muted">
                pool: +{poolGrowth}
              </span>
            )}
            {newCount > 0 && (
              <button
                type="button"
                data-testid="load-new-events"
                onClick={loadNewEvents}
                disabled={running}
                className="ml-auto px-2.5 py-1 text-xs font-medium rounded-md border border-[#d0d7de] bg-white text-[#1a2332] hover:bg-[#eef1f4] disabled:opacity-50"
              >
                {LOAD_NEW_EVENTS}
              </button>
            )}
          </div>
          );
        })()}

        {selectionNotice && (
          <div role="status" className="px-3 py-1.5 rounded-md bg-[#eef1f4] text-xs text-muted">
            {selectionNotice}
          </div>
        )}
        {queryNotice && (
          <div role="status" data-testid="query-notice" className="px-3 py-1.5 rounded-md bg-[#eef1f4] text-xs text-muted">
            {queryNotice}
          </div>
        )}
      </div>

      {/* Results */}
      {!snapshot ? (
        <div
          className="p-6 rounded-xl py-12"
          style={CARD_STYLE}
        >
          <p className="text-sm font-medium text-[#1a2332] mb-1">No events loaded yet.</p>
          <p className="text-xs text-muted mb-3">{FILTERS_EMPTY_HINT}</p>
          <button
            type="button"
            onClick={() => runFacets(tf, chips)}
            disabled={running || scopeBlocked}
            className="px-4 py-2 text-xs font-medium rounded-md bg-[#101218] text-white disabled:opacity-50"
          >
            {running ? 'Running' : SHOW_EVENTS}
          </button>
        </div>
      ) : snapshot.count === 0 ? (
        <div className="flex flex-col lg:flex-row gap-4">
          {railColumn}
          {/* Owner empty-state convention (2026-10-12): top-left at the
              panel's content origin; no vertical centering. */}
          <div className="flex-1 min-w-0 p-4 rounded-xl" style={CARD_STYLE}>
            <p className="text-sm text-[#1a2332]">No events match the current filters.</p>
          </div>
        </div>
      ) : (
        <div className="flex flex-col lg:flex-row gap-4">
          {railColumn}
          <div data-testid="workbench-results" className="flex-1 min-w-0">
            {/* VA1: the Cards/Table control belongs with the RESULTS, not
                the page identity area. */}
            <div className="mb-2 flex items-center justify-between gap-2">
              <span className="t-meta text-muted">{snapshot.count} events</span>
              <SegmentedToggle
                ariaLabel="View"
                value={view}
                onChange={setView}
                options={[['cards', 'Cards'], ['table', 'Table']]}
              />
            </div>
            {view === 'cards' ? (
              <SiemCards alerts={snapshot.rows} resetTrigger={resetTrigger}
                         selectedId={selectedId} onSelect={selectRow} />
            ) : (
              <SiemTable alerts={snapshot.rows} resetTrigger={resetTrigger}
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
                onEntityAction={handleEntityAction}
                onHostPivot={onHostPivot}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Siem;
