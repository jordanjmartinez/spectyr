import React, { useState, useEffect, useCallback, useRef } from 'react';
import { apiFetch } from '../api';
import DetectionDetail from './DetectionDetail';
import useIncidentScope from './useIncidentScope';
import {
  OPEN_IN_RESPONSE, PROMOTED_LABEL, DISMISSED_LABEL,
  PROMOTE_ACTION, DISMISS_ACTION, REOPEN_ACTION,
  DETECTION_SEARCH_PLACEHOLDER,
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
//
// Decision-layer pass (owner 2026-10-13): the list is a reading surface.
// The Type column, the per-row Promote/Dismiss buttons, and the Triage
// column are gone; each row carries the rule name with its instance "why"
// line beneath (server-composed from the sanitized triggering event), and
// the decisions live behind ONE "..." menu with their full labels. Default
// sort is severity, then time (newest first). The search states its scope.

// VD2 (visual correction section 2): the severity badge this feed
// established is now the ONE shared SeverityBadge in ui.jsx (identical
// treatment on every player-facing severity display); this file simply
// consumes it.

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

const shortTime = (iso) =>
  iso ? new Date(iso).toLocaleTimeString('en-GB', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '-';

// Default sort: severity rank, then time (newest first) inside a rank.
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };
export const sortDetections = (rows) => [...rows].sort((a, b) => {
  const ra = SEVERITY_RANK[(a.severity || '').toLowerCase()] ?? 9;
  const rb = SEVERITY_RANK[(b.severity || '').toLowerCase()] ?? 9;
  if (ra !== rb) return ra - rb;
  const ta = Date.parse(a.time || '') || 0;
  const tb = Date.parse(b.time || '') || 0;
  return tb - ta;
});

// The ONE per-row actions menu (the EventInspector "..." idiom): full
// labels, the ruled tooltip lines riding help-tip, and the same decision
// shape as before -- an open row offers the two decisions; a reviewed row
// offers Reopen (the one way back) and, when promoted, the neutral Open
// in Response navigation.
const RowMenu = ({ det, open, onToggle, onClose, onAct, onOpenResponse, responseTarget }) => {
  const item = (label, onClick, { help, accent } = {}) => (
    <button
      type="button"
      role="menuitem"
      onClick={(e) => { e.stopPropagation(); onClose(); onClick(); }}
      title={help}
      data-help={help}
      className={`${help ? 'help-tip ' : ''}w-full text-left px-3 py-1.5 whitespace-nowrap hover:bg-[#eef1f4] ${accent ? 'text-[#16436b]' : 'text-[#1a2332]'}`}
    >
      {label}
    </button>
  );
  return (
    <span className="relative inline-block">
      <button
        type="button"
        onClick={(e) => { e.stopPropagation(); onToggle(); }}
        aria-label={`Actions for ${det.rule_name}`}
        aria-haspopup="menu"
        aria-expanded={open}
        className="px-2 py-0.5 text-xs rounded border border-[#d0d7de] text-muted hover:bg-[#eef1f4]"
      >
        ...
      </button>
      {open && (
        <div
          role="menu"
          className="absolute right-0 top-full mt-1 z-20 min-w-[12rem] rounded-md border border-[#d0d7de] bg-white shadow-md py-1 text-xs"
        >
          {det.player_action === 'open' ? (
            <>
              {item(PROMOTE_ACTION, () => onAct(det.id, 'promote'), { help: TOOLTIPS.promote })}
              {item(DISMISS_ACTION, () => onAct(det.id, 'dismiss'), { help: TOOLTIPS.dismiss })}
            </>
          ) : (
            item(REOPEN_ACTION, () => onAct(det.id, 'open'), { help: TOOLTIPS.reopen })
          )}
          {det.player_action === 'promoted' && onOpenResponse && responseTarget && (
            item(OPEN_IN_RESPONSE, () => onOpenResponse(responseTarget), { accent: true })
          )}
        </div>
      )}
    </span>
  );
};

const Detections = ({ isVisible, resetTrigger, onHostPivot,
                      activeIncidentId = null, onEvidenceDescent,
                      onOpenResponse }) => {
  const [feed, setFeed] = useState([]);
  const [, setCounts] = useState({ open: 0, promoted: 0, dismissed: 0 });
  const [selected, setSelected] = useState(null);
  const [openMenu, setOpenMenu] = useState(null);
  // Owner list-page uniformity (2026-10-12): the shared toolbar pattern --
  // disposition tabs with counts plus the search bar. The passive count
  // lines are retired; the tab counts carry the same truth over the SAME
  // scoped rows.
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
    setOpenMenu(null);
    fetchFeed();
  }, [resetTrigger, fetchFeed]);

  // An open row menu closes on any outside click or Escape.
  useEffect(() => {
    if (!openMenu) return undefined;
    const close = () => setOpenMenu(null);
    const onKey = (e) => { if (e.key === 'Escape') close(); };
    document.addEventListener('click', close);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('click', close);
      document.removeEventListener('keydown', onKey);
    };
  }, [openMenu]);

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
        // no longer trails the toast by a refetch round-trip, and the row
        // leaves its tab immediately (the menu it carried unmounts with
        // it). The refetch below still reconciles against the server.
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
  // The search scope is exactly what the placeholder says: rule, host,
  // user, and the file/process names the why line carries.
  const q = search.trim().toLowerCase();
  const matchesSearch = (d) => !q
    || (d.rule_name || '').toLowerCase().includes(q)
    || (d.entity?.host || '').toLowerCase().includes(q)
    || (d.entity?.account || '').toLowerCase().includes(q)
    || (d.why || '').toLowerCase().includes(q);
  const visibleRows = sortDetections(rows.filter(d => d.player_action === dispoView && matchesSearch(d)));

  // III.0.1 item 5: the neutral navigation target for a promoted
  // detection -- the account entity when one is resolved, else the host.
  const responseTargetFor = (d) => (d.entity?.account_id
    ? { kind: 'account', entityId: d.entity.account_id }
    : d.entity?.host ? { kind: 'host', hostname: d.entity.host } : null);

  return (
    <div>
      {/* Detections uniformity pass (owner 2026-10-13): no incident
          context line here (same removal as the SIEM; the shell header
          carries session context). The PageIntro row keeps ONLY the page
          controls. The scope-failure notice stays as an inline alert
          (never a full-width status bar) so scope truth is preserved. */}
      <PageIntro
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
            <ToolbarSearch value={search} onChange={setSearch} placeholder={DETECTION_SEARCH_PLACEHOLDER} />
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

      <div className="bg-white border border-[#e2e6ea] rounded-xl overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="data-thead">
            <tr>
              <th className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap">Severity</th>
              <th className="px-3 sm:px-4 py-3 font-medium">Rule</th>
              <th className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap">Entity</th>
              <th className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap">Time</th>
              <th className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap"><span className="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {visibleRows.length === 0 && (
              <tr><td colSpan={5} className="px-4 py-4 text-left text-muted">
                {scope.rowPolicy === 'loading' ? 'Loading incident scope'
                  : scope.rowPolicy === 'error' ? 'Incident scope could not be loaded.'
                    : rows.length === 0 ? 'No detections yet. They fire as scenarios reach the queue.'
                      : 'No detections in this view.'}
              </td></tr>
            )}
            {visibleRows.map(d => (
              <tr
                key={d.id}
                className="border-b border-[#eef1f4] last:border-b-0 hover:bg-[#f6f8fa] cursor-pointer align-top"
                onClick={() => setSelected(d.id)}
              >
                <td className="px-3 sm:px-4 py-3"><SeverityBadge severity={d.severity} /></td>
                <td className="px-3 sm:px-4 py-3">
                  <button type="button" onClick={(e) => { e.stopPropagation(); setSelected(d.id); }} className="text-[#16436b] hover:underline text-left font-medium">
                    {d.rule_name}
                  </button>
                  {d.player_action !== 'open' && (
                    <span className="ml-2 align-middle"><DispositionChip action={d.player_action} /></span>
                  )}
                  {d.why && (
                    <p className="mt-0.5 text-xs text-muted leading-snug break-words">{d.why}</p>
                  )}
                </td>
                <td className="px-3 sm:px-4 py-3 log-mono whitespace-nowrap text-[#1a2332]">
                  {d.entity?.host || d.entity?.account || '-'}
                  {d.entity?.host && d.entity?.account && (
                    <span className="block text-xs text-muted">{d.entity.account}</span>
                  )}
                </td>
                <td className="px-3 sm:px-4 py-3 log-mono whitespace-nowrap text-muted">{shortTime(d.time)}</td>
                <td className="px-3 sm:px-4 py-3 text-right">
                  <RowMenu
                    det={d}
                    open={openMenu === d.id}
                    onToggle={() => setOpenMenu(openMenu === d.id ? null : d.id)}
                    onClose={() => setOpenMenu(null)}
                    onAct={act}
                    onOpenResponse={onOpenResponse}
                    responseTarget={responseTargetFor(d)}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Detections;
