import React, { useState, useEffect, useCallback, useRef } from 'react';
import { apiFetch } from '../api';
import DetectionDetail from './DetectionDetail';
import useIncidentScope from './useIncidentScope';
import {
  OPEN_IN_RESPONSE, PROMOTED_LABEL, DISMISSED_LABEL,
} from './uiCopy';
import { TOOLTIPS } from './helpContent';
import { toastDisposition } from './uiToasts';
import { SeverityBadge, PageIntro, ErrorState, SegmentedToggle, ToolbarSearch } from './ui';

// Detections tab (Stage 2; Final pass Part III.0.1): TRIAGE ONLY --
// promote / dismiss / reopen. All dispositions are scored server-side;
// the client never sees the answer key. Execution moved wholesale to the
// Response workspace (the one action system): a promoted detection offers
// only the neutral Open in Response navigation, which selects the
// relevant target there and executes nothing.

// VD2 (visual correction section 2): the severity badge this feed
// established is now the ONE shared SeverityBadge in ui.jsx (identical
// treatment on every player-facing severity display); this file simply
// consumes it.

export const RuleTypeChip = ({ type }) => (
  <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs border border-[#d0d7de] text-muted whitespace-nowrap">
    {type === 'yara' ? 'YARA' : 'Sigma'}
  </span>
);

// Stage 6 playtest fix 13: a reviewed detection's disposition renders as a
// STATE chip (the same colors the old active buttons wore), never as one of
// three sibling verbs. Shared by the feed rows and the detail card.
export const DispositionChip = ({ action, size = 'xs' }) => (
  <span
    className={`inline-flex items-center font-medium rounded-md border border-transparent text-white ${
      action === 'promoted' ? 'bg-[#101218]' : 'bg-[#57606a]'
    } ${size === 'sm' ? 'px-3 py-1.5 text-sm' : 'px-2.5 py-1 text-xs'}`}
  >
    {action === 'promoted' ? PROMOTED_LABEL : DISMISSED_LABEL}
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
      active ? activeClass : 'bg-white text-muted border-[#d0d7de] hover:bg-[#eef1f4]'
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
  // Owner list-page uniformity (2026-10-12): the shared toolbar pattern --
  // disposition tabs with counts plus the search bar (rule, entity, type,
  // severity). The passive count lines are retired; the tab counts carry
  // the same truth over the SAME scoped rows.
  const [dispoView, setDispoView] = useState('open');  // 'open'|'promoted'|'dismissed'
  const [search, setSearch] = useState('');
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
    setDispoView('open');
    setSearch('');
    fetchFeed();
  }, [resetTrigger, fetchFeed]);

  // Stage 6 playtest fixes 14+15: one in-flight disposition per detection
  // (a rapid double-click can no longer double-submit and double-toast).
  const actingRef = useRef(new Set());

  const act = (id, action) => {
    if (actingRef.current.has(id)) return;
    actingRef.current.add(id);
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
        // Stage 6 playtest fixes 14+15: apply the AUTHORITATIVE response to
        // the row and the counts in the same frame as the toast. The header
        // ("Detections reviewed: X of N" / open-promoted-dismissed) no
        // longer trails the toast by a refetch round-trip, and the
        // just-clicked, still-hovered button unmounts immediately so its
        // CSS tooltip line cannot linger beside the row as a doubled label.
        // The refetch below still reconciles against the server.
        const before = feed.find(d => d.id === id)?.player_action;
        const after = view.player_action;
        if (before && before !== after) {
          setCounts(c => ({
            ...c,
            [before]: Math.max(0, (c[before] || 0) - 1),
            [after]: (c[after] || 0) + 1,
          }));
          setFeed(prev => prev.map(d => (d.id === id ? { ...d, player_action: after } : d)));
        }
      }
      fetchFeed();
    }).catch(() => {}).finally(() => actingRef.current.delete(id));
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
  // Toolbar derivations: tab counts over the scoped rows (pre-search), so
  // the tabs and the rows can never disagree with the scope context.
  const dispoCounts = {
    open: rows.filter(d => d.player_action === 'open').length,
    promoted: rows.filter(d => d.player_action === 'promoted').length,
    dismissed: rows.filter(d => d.player_action === 'dismissed').length,
  };
  const q = search.trim().toLowerCase();
  const matchesSearch = (d) => !q
    || (d.rule_name || '').toLowerCase().includes(q)
    || (d.entity?.host || '').toLowerCase().includes(q)
    || (d.entity?.account || '').toLowerCase().includes(q)
    || (d.rule_type === 'yara' ? 'yara' : 'sigma').includes(q)
    || (d.severity || '').toLowerCase().includes(q);
  const visibleRows = rows.filter(d => d.player_action === dispoView && matchesSearch(d));

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
      <PageIntro
        incident={activeIncident}
        right={(
          <>
            <SegmentedToggle
              ariaLabel="Detection view"
              value={dispoView}
              onChange={setDispoView}
              options={[
                ['open', `Open ${dispoCounts.open}`],
                ['promoted', `Promoted ${dispoCounts.promoted}`],
                ['dismissed', `Dismissed ${dispoCounts.dismissed}`],
              ]}
            />
            <ToolbarSearch value={search} onChange={setSearch} placeholder="Search detections..." />
          </>
        )}
      />
      {activeIncidentId && scope.status === 'error' && (
        <div className="mb-3 rounded-lg border border-[#e2e6ea] bg-[#faf6f0]">
          <ErrorState onRetry={scope.refetch}>
            Incident scope could not be loaded.
            {scope.data && (
              <span className="text-muted"> Displayed rows are from the last successful scope read.</span>
            )}
          </ErrorState>
        </div>
      )}

      {/* Owner list-page uniformity (2026-10-12): the passive count lines
          are retired -- the toolbar tabs carry the same counts over the
          same scoped rows (incl. the former scoped reviewed/remaining
          line; the T1 remaining-count toast is untouched). */}
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
              {visibleRows.length === 0 && (
                <tr><td colSpan={6} className="px-4 py-4 text-left text-muted">
                  {scope.rowPolicy === 'loading' ? 'Loading incident scope'
                    : scope.rowPolicy === 'error' ? 'Incident scope could not be loaded.'
                      : rows.length === 0 ? 'No detections yet. They fire as scenarios reach the queue.'
                        : 'No detections in this view.'}
                </td></tr>
              )}
              {visibleRows.map(d => (
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
                  <td className="px-3 sm:px-4 py-3 log-mono whitespace-nowrap text-[#1a2332]">
                    {d.entity?.host || d.entity?.account || '-'}
                    {d.entity?.host && d.entity?.account && (
                      <span className="block text-xs text-muted">{d.entity.account}</span>
                    )}
                  </td>
                  <td className="px-3 sm:px-4 py-3 log-mono whitespace-nowrap text-muted">{shortTime(d.time)}</td>
                  <td className="px-3 sm:px-4 py-3">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      {/* Stage 6 playtest fix 13: an open row offers the two
                          decisions; a reviewed row reads STATE + the one way
                          back, never "Promote Dismiss Reopen" side by side.
                          Changing a reviewed call is deliberately two-step:
                          Reopen, then decide again (the API is unchanged). */}
                      {d.player_action === 'open' ? (
                        <>
                          <ActionButton onClick={() => act(d.id, 'promote')} active={false} help={TOOLTIPS.promote}>Promote</ActionButton>
                          <ActionButton onClick={() => act(d.id, 'dismiss')} active={false} help={TOOLTIPS.dismiss}>Dismiss</ActionButton>
                        </>
                      ) : (
                        <>
                          <DispositionChip action={d.player_action} />
                          <ActionButton onClick={() => act(d.id, 'open')} active={false} help={TOOLTIPS.reopen}>Reopen</ActionButton>
                        </>
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
