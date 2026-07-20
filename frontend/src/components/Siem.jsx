import React, { useState, useEffect } from 'react';
import { apiFetch } from '../api';
import SiemTable from './SiemTable';
import SiemCards from './SiemCards';

// SIEM Investigation Workbench shell (Stage 4 Phase 4). Analyst-driven:
// the shell submits LCQL text to the server's single query read and renders
// the returned frozen snapshot exactly as served. No polling, no client-side
// filtering, no client-side query execution of any kind (contract P8): rows
// never insert, remove, or reorder until the analyst runs a query again.

// The placeholder is one canonical conforming LCQL example (never key=value).
export const QUERY_PLACEHOLDER =
  '1h | Sysmon | ProcessCreate | command_line contains "powershell"';

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

const Siem = ({ setSiemCount, resetTrigger, onHostPivot, activeIncidentId }) => {
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
  // P5.2: the new-events indicator (contract Section 8, R16 refresh-now).
  // Token-bound: the poll carries ONLY the executed snapshot's token, so
  // edited bar text structurally cannot influence the count. countHalted
  // stops the poll neutrally after a token invalidation (reset/restart).
  const [newCount, setNewCount] = useState(0);
  const [poolGrowth, setPoolGrowth] = useState(0);
  const [countHalted, setCountHalted] = useState(false);

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
  }, [resetTrigger]);

  useEffect(() => {
    setSiemCount?.(snapshot ? snapshot.count : 0);
  }, [snapshot, setSiemCount]);

  const loadIncidentScope = (id) => {
    setScope({ kind: 'incident', id, status: 'loading' });
    apiFetch(`/api/incidents/${id}/scope`)
      .then((res) => { if (!res.ok) throw new Error('scope'); return res.json(); })
      .then((sc) => setScope({ kind: 'incident', id, status: 'ready',
                               sealed: !!sc.sealed }))
      // Revised scope-error behavior: keep the chip, preserve the prior
      // snapshot, disable Run; NEVER fall back to Session-wide silently.
      .catch(() => setScope({ kind: 'incident', id, status: 'error' }));
  };

  const selectScope = (value) => {
    if (value === 'session') setScope({ kind: 'session' });
    else loadIncidentScope(value);
  };

  const scopeBlocked = scope.kind === 'incident' && scope.status !== 'ready';
  const scopeParam = scope.kind === 'incident' ? scope.id : 'session';

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

  const execute = (q, scopeValue) => {
    if (running) return;
    setRunning(true);
    apiFetch(`/api/events/query?q=${encodeURIComponent(q)}&scope=${encodeURIComponent(scopeValue)}`)
      .then(async (res) => {
        const body = await res.json().catch(() => null);
        if (res.ok && body) {
          applySnapshot(body);
        } else if (body && body.error && typeof body.error === 'object') {
          setError(body.error);
        } else {
          setError({ position: 0, reason: 'The query could not be executed.' });
        }
      })
      .catch(() => setError({ position: 0, reason: 'The query could not be executed.' }))
      .finally(() => setRunning(false));
  };

  const runQuery = () => {
    if (running || scopeBlocked) return;
    execute(queryText, scopeParam);
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

      {/* Scope + TIMEFRAME + query bar */}
      <div className="mb-3 flex flex-col gap-2">
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <label className="flex items-center gap-1.5 text-[#6e7781]">
            Scope
            <select
              value={scope.kind === 'incident' ? scope.id : 'session'}
              onChange={(e) => selectScope(e.target.value)}
              aria-label="Scope"
              className="px-2.5 py-1.5 rounded-md border border-[#d0d7de] bg-white text-[#1a2332]"
            >
              <option value="session">Session-wide</option>
              {activeIncidentId && (
                <option value={activeIncidentId}>{`Focused on ${activeIncidentId}`}</option>
              )}
              {scope.kind === 'incident' && scope.id !== activeIncidentId && (
                <option value={scope.id}>{`Focused on ${scope.id}`}</option>
              )}
            </select>
          </label>
          {scope.kind === 'incident' && (
            <span
              data-testid="scope-chip"
              className="inline-flex items-center gap-1.5 px-2 py-1 rounded-full bg-[#eef1f4] text-[#1a2332]"
            >
              <span className="log-mono text-[#16436b] font-medium">{scope.id}</span>
              {scope.status === 'loading' && <span className="text-[#6e7781]">loading scope</span>}
              {scope.status === 'error' && <span className="text-[#b26666]">scope unavailable</span>}
              <button
                type="button"
                aria-label="Clear scope"
                onClick={() => selectScope('session')}
                className="text-[#6e7781] hover:text-[#1a2332]"
              >
                x
              </button>
            </span>
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
            <button
              type="button"
              onClick={() => selectScope('session')}
              className="ml-2 px-2 py-0.5 rounded border border-[#d0d7de] bg-white text-[#57606a]"
            >
              Use Session-wide
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
            placeholder={QUERY_PLACEHOLDER}
            value={queryText}
            onChange={(e) => setQueryText(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') runQuery(); }}
            readOnly={running}
            maxLength={300}
            aria-label="LCQL query"
            className="log-mono flex-1 pl-4 pr-4 py-2 rounded-md bg-white border border-[#e2e6ea] text-[#1a2332] text-sm placeholder-[#8b949e] focus:border-[#8b949e] focus:outline-none transition-colors"
          />
          <button
            type="button"
            onClick={runQuery}
            disabled={running || scopeBlocked}
            className="px-4 py-2 text-xs font-medium rounded-md bg-[#101218] text-white disabled:opacity-50"
          >
            {running ? 'Running' : 'Run Query'}
          </button>
        </div>

        {error && (
          <div className="px-3 py-2 rounded-md border border-[#e2e6ea] bg-[#faf6f0] text-xs text-[#1a2332]" role="alert">
            <span className="font-medium">Parse error at position {error.position}:</span>{' '}
            {error.reason}
            {error.suggestions && error.suggestions.length > 0 && (
              <span className="text-[#57606a]"> Did you mean: {error.suggestions.join(', ')}?</span>
            )}
          </div>
        )}

        {snapshot && (
          <div className="px-3 py-1.5 rounded-md bg-[#eef1f4] text-xs text-[#57606a] flex flex-wrap items-center gap-x-3 gap-y-1">
            <span>
              Snapshot: <span className="font-medium text-[#1a2332]">{snapshot.count} events</span>
            </span>
            <span>as of seq #{snapshot.identity.cutoff_seq}</span>
            <span>{simTime(snapshot.identity.resolved_range.end)} sim</span>
            <span className="log-mono">{snapshot.identity.canonical_query}</span>
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

        {selectionNotice && (
          <div role="status" className="px-3 py-1.5 rounded-md bg-[#eef1f4] text-xs text-[#57606a]">
            {selectionNotice}
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
        <div
          className="p-6 rounded-xl flex flex-col items-center justify-center py-14"
          style={{ background: '#ffffff', border: '1px solid #e2e6ea', boxShadow: '0 1px 2px rgba(0,0,0,0.04)' }}
        >
          <p className="text-sm text-[#1a2332] mb-1">0 events match</p>
          <p className="text-xs text-[#6e7781] log-mono">{snapshot.identity.canonical_query}</p>
        </div>
      ) : view === 'cards' ? (
        <SiemCards alerts={snapshot.rows} resetTrigger={resetTrigger} onHostPivot={onHostPivot}
                   selectedId={selectedId} onSelect={selectRow} />
      ) : (
        <SiemTable alerts={snapshot.rows} resetTrigger={resetTrigger} onHostPivot={onHostPivot}
                   selectedId={selectedId} onSelect={selectRow} />
      )}
    </div>
  );
};

export default Siem;
