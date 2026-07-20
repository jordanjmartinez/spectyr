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

const Siem = ({ setSiemCount, resetTrigger, onHostPivot }) => {
  const [org, setOrg] = useState({});
  const [view, setView] = useState('cards');
  const [queryText, setQueryText] = useState('');
  const [snapshot, setSnapshot] = useState(null);   // {token, identity, count, rows}
  const [error, setError] = useState(null);         // {position, reason, suggestions?}
  const [running, setRunning] = useState(false);

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
  }, [resetTrigger]);

  useEffect(() => {
    setSiemCount?.(snapshot ? snapshot.count : 0);
  }, [snapshot, setSiemCount]);

  const runQuery = () => {
    if (running) return;
    setRunning(true);
    apiFetch(`/api/events/query?q=${encodeURIComponent(queryText)}&scope=session`)
      .then(async (res) => {
        const body = await res.json().catch(() => null);
        if (res.ok && body) {
          // Atomic replacement: the new snapshot object swaps in whole; a
          // failed run leaves the prior snapshot untouched.
          setSnapshot(body);
          setError(null);
        } else if (body && body.error && typeof body.error === 'object') {
          setError(body.error);
        } else {
          setError({ position: 0, reason: 'The query could not be executed.' });
        }
      })
      .catch(() => setError({ position: 0, reason: 'The query could not be executed.' }))
      .finally(() => setRunning(false));
  };

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

      {/* Query bar */}
      <div className="mb-3 flex flex-col gap-2">
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
            disabled={running}
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
          <div className="px-3 py-1.5 rounded-md bg-[#eef1f4] text-xs text-[#57606a] flex flex-wrap items-center gap-x-3">
            <span>
              Snapshot: <span className="font-medium text-[#1a2332]">{snapshot.count} events</span>
            </span>
            <span>as of seq #{snapshot.identity.cutoff_seq}</span>
            <span>{simTime(snapshot.identity.resolved_range.end)} sim</span>
            <span className="log-mono">{snapshot.identity.canonical_query}</span>
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
        <SiemCards alerts={snapshot.rows} resetTrigger={resetTrigger} onHostPivot={onHostPivot} />
      ) : (
        <SiemTable alerts={snapshot.rows} resetTrigger={resetTrigger} onHostPivot={onHostPivot} />
      )}
    </div>
  );
};

export default Siem;
