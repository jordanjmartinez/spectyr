import React, { useState, useEffect, useCallback, useRef } from 'react';
import { apiFetch } from '../api';
import DetectionDetail from './DetectionDetail';
import useIncidentScope from './useIncidentScope';
import {
  detectionsReviewed, detectionsRemaining, FEED_SUBCOPY, OPEN_IN_RESPONSE,
  PAGE_SUBTITLE,
} from './uiCopy';
import { TOOLTIPS } from './helpContent';
import { toastDisposition } from './uiToasts';
import { SEVERITY_PILL, severityDot, PageIntro, ErrorState } from './ui';

// Detections tab (Stage 2; Final pass Part III.0.1): TRIAGE ONLY --
// promote / dismiss / reopen. All dispositions are scored server-side;
// the client never sees the answer key. Execution moved wholesale to the
// Response workspace (the one action system): a promoted detection offers
// only the neutral Open in Response navigation, which selects the
// relevant target there and executes nothing.

// Visual pass VG: severity pills and dots read the shared maps (ui.jsx),
// unifying the dot palette with the Incidents/Dashboard severity dots
// (previously a slightly different set of hexes solved the same problem).
export const SeverityBadge = ({ severity }) => {
  const s = String(severity || '');
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium border ${SEVERITY_PILL[severity] || 'border-[#d0d7de] text-[#57606a]'}`}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: severityDot(severity) }} />
      {s ? s.charAt(0).toUpperCase() + s.slice(1) : ''}
    </span>
  );
};

export const RuleTypeChip = ({ type }) => (
  <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs border border-[#d0d7de] text-[#57606a] whitespace-nowrap">
    {type === 'yara' ? 'YARA' : 'Sigma'}
  </span>
);

const ActionButton = ({ onClick, active, activeClass, disabled, children, help }) => (
  <button
    type="button"
    disabled={disabled}
    onClick={(e) => { e.stopPropagation(); onClick(); }}
    title={help}
    data-help={help}
    className={`${help ? 'help-tip ' : ''}px-2.5 py-1 text-xs font-medium rounded-md border transition disabled:opacity-50 disabled:cursor-default ${
      active ? activeClass : 'bg-white text-[#57606a] border-[#d0d7de] hover:bg-[#eef1f4]'
    }`}
  >
    {children}
  </button>
);

const shortTime = (iso) =>
  iso ? new Date(iso).toLocaleTimeString('en-GB', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '-';

const Detections = ({ isVisible, resetTrigger, onHostPivot,
                      activeIncidentId = null, onEvidenceDescent,
                      onOpenResponse, activeIncident = null }) => {
  const [feed, setFeed] = useState([]);
  const [counts, setCounts] = useState({ open: 0, promoted: 0, dismissed: 0 });
  const [selected, setSelected] = useState(null);
  // Case-constant scope (Amendment 1 Delta A over the M1 foundation): ONE
  // scope state drives the pinned header, the honesty notices, and the row
  // filter. A selected case is ALWAYS case-scoped here (no toggle, no
  // broadening control); with no case the feed is the All activity state.
  // Read-only; selecting a case mutates nothing.
  const scope = useIncidentScope(activeIncidentId, resetTrigger);
  const scopeModeRef = useRef(scope.mode);
  scopeModeRef.current = scope.mode;
  const scopeRefetchRef = useRef(scope.refetch);
  scopeRefetchRef.current = scope.refetch;

  const fetchFeed = useCallback(() => {
    apiFetch('/api/detections')
      .then(res => res.json())
      .then(data => {
        setFeed(data.detections || []);
        setCounts(data.counts || { open: 0, promoted: 0, dismissed: 0 });
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!isVisible) return;
    fetchFeed();
    const interval = setInterval(() => {
      fetchFeed();
      // M1 (contract 11.1): the scope read joins this existing 2.5s poll
      // while an incident scope is selected, so a pre-seal roster cannot
      // go stale. No extra interval exists for the scope.
      if (scopeModeRef.current === 'incident') scopeRefetchRef.current();
    }, 2500);
    return () => clearInterval(interval);
  }, [isVisible, fetchFeed]);

  useEffect(() => {
    setSelected(null);
    fetchFeed();
  }, [resetTrigger, fetchFeed]);

  const act = (id, action) => {
    apiFetch(`/api/detections/${encodeURIComponent(id)}/disposition`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action }),
    }).then(res => (res.ok ? res.json() : null)).then(view => {
      if (view) {
        // T1 (ruled sealed-roster note): the remaining-count line derives
        // from the sealed case roster; a disposition outside any sealed
        // case roster confirms alone. Count = case-open AFTER this action,
        // from the same rows the surface renders.
        let remaining = null;
        if (activeIncidentId && scope.data?.sealed
            && scope.data.detectionIds.has(id)) {
          const openOthers = feed.filter(d =>
            scope.data.detectionIds.has(d.id) && d.id !== id
            && d.player_action === 'open').length;
          remaining = openOthers + (view.player_action === 'open' ? 1 : 0);
        }
        toastDisposition(view.player_action, remaining);
      }
      fetchFeed();
    }).catch(() => {});
  };

  if (selected) {
    return (
      <DetectionDetail
        detId={selected}
        onBack={() => { setSelected(null); fetchFeed(); }}
        onAction={act}
        onHostPivot={onHostPivot}
        onEvidenceDescent={onEvidenceDescent}
        // Section 16: descent opens the relevant incident scope for THIS
        // entry -- the current case while its scope is loaded; no case
        // otherwise. Observable UI state only.
        descentScopeIncidentId={activeIncidentId && scope.data ? activeIncidentId : null}
      />
    );
  }

  // Rows derive from the ONE scope state (A1-A.3): 'loading' and 'error'
  // render zero rows; all-activity rows never render while a case is
  // selected.
  const rows = scope.rowPolicy === 'all' ? feed
    : scope.rowPolicy === 'scoped' ? feed.filter(d => scope.data.detectionIds.has(d.id))
      : [];
  const headerCount = rows.length;

  // III.0.1 item 5: the neutral navigation target for a promoted
  // detection -- the account entity when one is resolved, else the host.
  const responseTargetFor = (d) => (d.entity?.account_id
    ? { kind: 'account', entityId: d.entity.account_id }
    : d.entity?.host ? { kind: 'host', hostname: d.entity.host } : null);

  return (
    <div>
      {/* VA1: the functional subtitle + the ONE incident pill; the
          retired All-activity bar and the identity card are gone. The
          scope-failure notice stays as an inline alert (never a
          full-width status bar) so scope truth is preserved. */}
      <PageIntro subtitle={PAGE_SUBTITLE.detections} incident={activeIncident} />
      {activeIncidentId && scope.status === 'error' && (
        <div className="mb-3 rounded-lg border border-[#e2e6ea] bg-[#faf6f0]">
          <ErrorState onRetry={scope.refetch}>
            Incident scope could not be loaded.
            {scope.data && (
              <span className="text-[#57606a]"> Displayed rows are from the last successful scope read.</span>
            )}
          </ErrorState>
        </div>
      )}

      {/* OD-9 explanatory subcopy, one line each; counters use the 10.1
          vocabulary. With a case selected the counts are the CASE-SCOPED
          rows (the same roster the strip and readiness read), so the line
          and the rows can never disagree; All activity keeps the session
          counts. */}
      <p className="text-sm text-[#57606a] mb-2">
        <span className="text-[#8b949e]">{FEED_SUBCOPY}.</span>{' '}
        {activeIncidentId && scope.rowPolicy === 'scoped' ? (
          <>
            {detectionsReviewed(
              rows.filter(d => d.player_action !== 'open').length, rows.length)}
            {rows.some(d => d.player_action === 'open') && (
              <> &middot; {detectionsRemaining(rows.filter(d => d.player_action === 'open').length)}</>
            )}
          </>
        ) : (
          <>{counts.open} open &middot; {counts.promoted} promoted &middot; {counts.dismissed} dismissed</>
        )}
      </p>

      {(
        <div className="bg-white border border-[#e2e6ea] rounded-xl overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="data-thead">
              <tr>
                <th className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap">Severity</th>
                <th className="px-3 sm:px-4 py-3 font-medium">Rule</th>
                <th className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap">Type</th>
                <th className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap">Entity</th>
                <th className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap">Time</th>
                <th className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap">Triage</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr><td colSpan={6} className="px-4 py-8 text-center text-[#8b949e]">
                  {scope.rowPolicy === 'loading' ? 'Loading incident scope'
                    : scope.rowPolicy === 'error' ? 'Incident scope could not be loaded.'
                      : 'No detections yet. They fire as scenarios reach the queue.'}
                </td></tr>
              )}
              {rows.map(d => (
                <tr
                  key={d.id}
                  className="border-b border-[#eef1f4] last:border-b-0 hover:bg-[#f6f8fa] cursor-pointer"
                  onClick={() => setSelected(d.id)}
                >
                  <td className="px-3 sm:px-4 py-3"><SeverityBadge severity={d.severity} /></td>
                  <td className="px-3 sm:px-4 py-3">
                    <button type="button" onClick={(e) => { e.stopPropagation(); setSelected(d.id); }} className="text-[#16436b] hover:underline text-left">
                      {d.rule_name}
                    </button>
                  </td>
                  <td className="px-3 sm:px-4 py-3"><RuleTypeChip type={d.rule_type} /></td>
                  <td className="px-3 sm:px-4 py-3 font-mono whitespace-nowrap text-[#1a2332]">
                    {d.entity?.host || d.entity?.account || '-'}
                    {d.entity?.host && d.entity?.account && (
                      <span className="block text-xs text-[#8b949e]">{d.entity.account}</span>
                    )}
                  </td>
                  <td className="px-3 sm:px-4 py-3 font-mono whitespace-nowrap text-[#57606a]">{shortTime(d.time)}</td>
                  <td className="px-3 sm:px-4 py-3">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <ActionButton onClick={() => act(d.id, 'promote')} active={d.player_action === 'promoted'} activeClass="bg-[#101218] text-white border-transparent" help={TOOLTIPS.promote}>Promote</ActionButton>
                      <ActionButton onClick={() => act(d.id, 'dismiss')} active={d.player_action === 'dismissed'} activeClass="bg-[#57606a] text-white border-transparent" help={TOOLTIPS.dismiss}>Dismiss</ActionButton>
                      {d.player_action !== 'open' && (
                        <ActionButton onClick={() => act(d.id, 'open')} active={false} help={TOOLTIPS.reopen}>Reopen</ActionButton>
                      )}
                      {/* III.0.1 item 5: neutral navigation only -- selects
                          the relevant target in Response, executes nothing,
                          recommends nothing. */}
                      {d.player_action === 'promoted' && onOpenResponse && responseTargetFor(d) && (
                        <button
                          type="button"
                          onClick={(e) => { e.stopPropagation(); onOpenResponse(responseTargetFor(d)); }}
                          className="px-2.5 py-1 text-xs font-medium rounded-md border border-[#16436b]/40 text-[#16436b] hover:bg-[#16436b]/5"
                        >
                          {OPEN_IN_RESPONSE}
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default Detections;
