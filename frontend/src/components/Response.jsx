import React, { useState, useEffect, useCallback, useRef } from 'react';
import { apiFetch } from '../api';
import ConfirmDialog from './ConfirmDialog';
import useIncidentScope from './useIncidentScope';
import { postResponseAction, confirmSpecs, PERSIST_LABEL } from './responseActions';
import {
  ACTION_LABELS, RESPONSE_SELECT_INCIDENT, RESPONSE_NO_PROMOTED,
  RESPONSE_NO_PROMOTED_SUB, RESPONSE_NO_TARGETS, RESPONSE_NO_ACTIONS,
} from './uiCopy';
import { CARD_STYLE, StateChip, PageIntro, SegmentedToggle } from './ui';
import { DeviceGlyph, PlatformBadge, platformFor } from './icons';

// Final pass Part III.0.1: the ONE canonical action-execution workspace
// (Investigate -> Triage -> Respond -> Submit -> Learn). Actionable
// incident entities are grouped by target type with FACTUAL context only:
// identity, host/parent, related promoted detections, observable action
// state, the available existing verbs, and actions already executed.
// Never required / recommended / correct / sufficient / remaining /
// expected -- promotion contributes context, not endorsement. The
// Response Log is the single chronological history. Everything executes
// through the one action system (responseActions.js); the endpoint and
// detection surfaces only navigate here.
//
// Visual pass V9 -- FLAGGED DEVIATION (Services group omitted): the V9
// spec lists a sixth target group, Services, but NO service verb exists
// in the eight-action vocabulary (services stop only through the kill
// cascade), so an actionless Services table in the EXECUTION workspace
// would duplicate the Endpoints Services investigation tab and imply a
// verb the product does not have (the expressibility rule forbids
// stretching one). The five actionable groups below match the pinned
// Guided hint copy. A service verb is response-vocabulary-v2 backlog
// material; the group joins this workspace when its verb exists.
// VD4 (visual correction section 5) re-flags the same deviation: the
// correction's sketch lists Services again, and the group stays out for
// the same still-standing reason.

// VD4 (visual correction section 5): ONE FLAT COMMAND WORKSPACE. The
// large rounded card around each target category is retired. Each
// category renders directly on the workspace surface as a section --
// heading + count pill, then the table in the same minimal light table
// boundary the Endpoints list uses (the shared light data-thead needs
// one clean container edge for its rounded corners; that boundary is
// the table's own, never a card around the section). Sections separate
// by vertical spacing and a subtle divider. No card sits inside another
// card; semantically different target types never merge into one table.

// Visual pass VG: StateChip from the shared module.

const shortTime = (iso) =>
  iso ? new Date(iso).toLocaleTimeString('en-GB', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '-';

const OUTCOME_CHIP = {
  success: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  no_op: 'border-[#d0d7de] text-[#57606a]',
  failed_precondition: 'bg-red-50 text-red-700 border-red-200',
};
const OUTCOME_LABEL = { success: 'Success', no_op: 'No effect', failed_precondition: 'Failed' };
const OutcomeChip = ({ outcome }) => (
  <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${OUTCOME_CHIP[outcome] || 'border-[#d0d7de] text-[#57606a]'}`}>
    {OUTCOME_LABEL[outcome] || outcome}
  </span>
);

const VerbButton = ({ onClick, disabled, dark, children }) => (
  <button
    type="button"
    disabled={disabled}
    onClick={onClick}
    className={`px-2.5 py-1 text-xs font-medium rounded-md border transition disabled:opacity-50 disabled:cursor-default ${
      dark ? 'bg-[#101218] text-white border-transparent hover:bg-[#1a2332]'
           : 'bg-white text-[#57606a] border-[#d0d7de] hover:bg-[#eef1f4]'}`}
  >
    {children}
  </button>
);

const PromotedChips = ({ rules }) => (rules && rules.length ? (
  <span className="flex flex-wrap gap-1 mt-1">
    {rules.map(r => <StateChip key={r}>Promoted: {r}</StateChip>)}
  </span>
) : null);

// The flat target section (VD4): heading + count on the workspace
// surface, content below; a subtle divider separates it from the
// section above (suppressed when it opens the list).
const TargetSection = ({ title, count, children }) => (
  <section
    data-testid="target-section"
    className="pt-4 border-t border-[#e2e6ea] first:pt-0 first:border-t-0"
  >
    <div className="mb-2 flex items-center gap-2">
      <h3 className="t-subsection">{title}</h3>
      <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-[#eef1f4] text-[#57606a]">{count}</span>
    </div>
    {children}
  </section>
);

// The minimal light table boundary (the Endpoints-list treatment): the
// table's own edge, not a section card.
const TableSurface = ({ scroll = false, children }) => (
  <div className={`bg-white border border-[#e2e6ea] rounded-xl overflow-x-auto ${
    scroll ? 'max-h-96 overflow-y-auto' : ''}`}>
    {children}
  </div>
);

const Response = ({ isVisible, resetTrigger, activeIncidentId = null,
                    responseFocus = null, onHostPivot, activeIncident = null }) => {
  const [view, setView] = useState('actions');   // 'actions' | 'log'
  const [feed, setFeed] = useState([]);
  const [snaps, setSnaps] = useState({});        // hostname -> snapshot | null (null = not managed)
  const [logEntries, setLogEntries] = useState([]);
  const [confirm, setConfirm] = useState(null);
  const [busy, setBusy] = useState(false);
  const [procSearch, setProcSearch] = useState('');
  const scope = useIncidentScope(activeIncidentId, resetTrigger);
  const scopeRefetchRef = useRef(scope.refetch);
  scopeRefetchRef.current = scope.refetch;

  const hostsKey = scope.data ? [...scope.data.hosts].sort().join(',') : '';

  const fetchAll = useCallback(() => {
    apiFetch('/api/detections').then(r => r.json())
      .then(d => setFeed(d.detections || [])).catch(() => {});
    apiFetch('/api/actions').then(r => r.json())
      .then(d => setLogEntries(d.actions || [])).catch(() => {});
    if (hostsKey) {
      hostsKey.split(',').forEach(h => {
        apiFetch(`/api/endpoints/${encodeURIComponent(h)}`)
          .then(res => (res.ok ? res.json() : null))
          .then(snap => setSnaps(prev => ({ ...prev, [h]: snap })))
          .catch(() => {});
      });
    }
  }, [hostsKey]);

  useEffect(() => {
    if (!isVisible) return;
    fetchAll();
    const iv = setInterval(() => {
      fetchAll();
      if (activeIncidentId) scopeRefetchRef.current();
    }, 3000);
    return () => clearInterval(iv);
  }, [isVisible, fetchAll, activeIncidentId]);

  useEffect(() => { setSnaps({}); setConfirm(null); setView('actions'); }, [resetTrigger, activeIncidentId]);

  // Contextual navigation (III.0.1 item 5): an incoming focus highlights
  // and scrolls to the target; it never executes or preselects an action.
  const focusRef = useRef(null);
  useEffect(() => {
    if (responseFocus && focusRef.current
        && typeof focusRef.current.scrollIntoView === 'function') {
      focusRef.current.scrollIntoView({ block: 'center' });
    }
  }, [responseFocus && responseFocus.seq, view, hostsKey]);   // eslint-disable-line react-hooks/exhaustive-deps

  const run = (spec) => {
    setBusy(true);
    postResponseAction(spec.action, spec.target)
      .then(() => { setConfirm(null); setBusy(false); fetchAll(); })
      .catch(() => { setConfirm(null); setBusy(false); });
  };

  // --- data derivations (roster-scoped, observable only) ------------------
  const detIds = scope.data ? scope.data.detectionIds : new Set();
  const roster = feed.filter(d => detIds.has(d.id));
  const promoted = roster.filter(d => d.player_action === 'promoted');
  const promotedFor = (match) => promoted.filter(match).map(d => d.rule_name);

  const accounts = [];
  const seenAcct = new Set();
  for (const d of roster) {
    const e = d.entity || {};
    if (e.account_id && !seenAcct.has(e.account_id)) {
      seenAcct.add(e.account_id);
      accounts.push({
        entityId: e.account_id, account: e.account, host: e.host || null,
        state: e.account_state || {},
        promotedRules: promotedFor(x => x.entity?.account_id === e.account_id),
      });
    }
  }

  const hostRows = [];
  const procRows = [];
  const fileRows = [];
  const persistRows = [];
  if (scope.data) {
    for (const h of [...scope.data.hosts].sort()) {
      const snap = snaps[h];
      if (!snap) continue;   // unmanaged (log source) or not yet loaded
      hostRows.push({
        hostname: h, entityId: snap.entity_id, status: snap.status,
        isolation: snap.isolation,
        // V7: the same device/platform identity mapping as the endpoint
        // list and detail header, from the same serialized fields.
        ident: platformFor({ platform: snap.system?.platform, os: snap.os, role: snap.role }),
        promotedRules: promotedFor(x => x.entity?.host === h),
      });
      for (const p of snap.processes || []) {
        if (p.entity_id) procRows.push({ ...p, hostname: h });
      }
      for (const a of snap.autoruns || []) {
        if (a.persistence_entity_id) {
          persistRows.push({ ...a, hostname: h });
        }
        if (a.file_entity_id) {
          fileRows.push({ ...a, hostname: h });
        }
      }
    }
  }
  const q = procSearch.trim().toLowerCase();
  const procFiltered = procRows.filter(p =>
    !q || p.name.toLowerCase().includes(q) || String(p.pid).includes(q)
      || (p.user || '').toLowerCase().includes(q) || p.hostname.toLowerCase().includes(q));

  const anyTargets = hostRows.length || accounts.length || procRows.length
    || fileRows.length || persistRows.length;

  const isFocused = (kind, row) => {
    const f = responseFocus;
    if (!f || f.kind !== kind) return false;
    if (kind === 'host') return f.hostname === row.hostname;
    if (kind === 'process') return f.hostname === row.hostname && f.pid === row.pid;
    if (kind === 'account') return f.entityId === row.entityId;
    if (kind === 'autorun') return f.entityId && (f.entityId === row.persistence_entity_id || f.entityId === row.file_entity_id);
    return false;
  };
  const focusProps = (kind, row) => (isFocused(kind, row)
    ? { ref: focusRef, 'data-focused': 'true',
        className: 'border-b border-[#eef1f4] last:border-b-0 bg-[#16436b]/5' }
    : { className: 'border-b border-[#eef1f4] last:border-b-0' });

  const logNewestFirst = [...logEntries].reverse();

  return (
    <div>
      {/* VA1/VC5: the ONE incident pill + view toggle (the functional
          subtitle lives in the AppHeader now). With no incident the
          Actions view renders its own truthful state. */}
      <PageIntro
        incident={activeIncident}
        right={(
          <SegmentedToggle
            ariaLabel="Response view"
            value={view}
            onChange={setView}
            options={[['actions', 'Actions'], ['log', 'Response log']]}
          />
        )}
      />

      {view === 'log' ? (
        <div>
        {/* VD4: the log is one flat section -- heading + count on the
            workspace surface, then the single chronological table in the
            minimal table boundary (no decorative card around it). VC5:
            the descriptive line stays with the list it describes. */}
        <div className="mb-2 flex items-center gap-2">
          <h3 className="t-subsection">Response log</h3>
          <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-[#eef1f4] text-[#57606a]">{logNewestFirst.length}</span>
        </div>
        <p className="t-body text-[#57606a] mb-2">Every response action this session, in order.</p>
        <TableSurface>
          <table className="w-full text-left text-sm">
            <thead className="data-thead">
              <tr>
                <th className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap">Time</th>
                <th className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap">Action</th>
                <th className="px-3 sm:px-4 py-3 font-medium">Target</th>
                <th className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap">Outcome</th>
                <th className="px-3 sm:px-4 py-3 font-medium">Detail</th>
              </tr>
            </thead>
            <tbody>
              {logNewestFirst.length === 0 && (
                <tr><td colSpan={5} className="px-4 py-8 text-center text-[#8b949e]">{RESPONSE_NO_ACTIONS}</td></tr>
              )}
              {logNewestFirst.map(e => (
                <tr key={e.seq} className="border-b border-[#eef1f4] last:border-b-0">
                  <td className="px-3 sm:px-4 py-3 font-mono whitespace-nowrap text-[#57606a]">{shortTime(e.timestamp)}</td>
                  <td className="px-3 sm:px-4 py-3 whitespace-nowrap">{ACTION_LABELS[e.action] || e.action}</td>
                  <td className="px-3 sm:px-4 py-3 font-mono break-all">{e.target?.label || '-'}</td>
                  <td className="px-3 sm:px-4 py-3"><OutcomeChip outcome={e.outcome} /></td>
                  <td className="px-3 sm:px-4 py-3 text-[#57606a]">{e.reason || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableSurface>
        </div>
      ) : !activeIncidentId ? (
        <div className="rounded-xl p-8 text-center text-sm text-[#57606a]" style={CARD_STYLE}>
          {RESPONSE_SELECT_INCIDENT}
        </div>
      ) : (
        <div className="space-y-4">
          {promoted.length === 0 && (
            <div className="rounded-xl px-4 py-3 text-sm" style={CARD_STYLE}>
              <span className="text-[#1a2332]">{RESPONSE_NO_PROMOTED}</span>{' '}
              <span className="text-[#57606a]">{RESPONSE_NO_PROMOTED_SUB}</span>
            </div>
          )}

          {!anyTargets ? (
            <div className="rounded-xl p-8 text-center text-sm text-[#57606a]" style={CARD_STYLE}>
              {RESPONSE_NO_TARGETS}
            </div>
          ) : (
            <>
              {hostRows.length > 0 && (
                <TargetSection title="Hosts" count={hostRows.length}>
                  <TableSurface>
                  <table className="w-full text-left text-sm">
                    <thead className="data-thead"><tr>
                      <th className="px-3 py-2.5 font-medium">Host</th>
                      <th className="px-3 py-2.5 font-medium whitespace-nowrap">State</th>
                      <th className="px-3 py-2.5 font-medium whitespace-nowrap">Actions</th>
                    </tr></thead>
                    <tbody>
                      {hostRows.map(h => (
                        <tr key={h.hostname} {...focusProps('host', h)}>
                          <td className="px-3 py-2.5">
                            <span className="inline-flex items-center gap-1.5">
                              <DeviceGlyph deviceKind={h.ident?.deviceKind} size={15} className="text-[#57606a]" />
                              <button type="button" onClick={() => onHostPivot?.(h.hostname)}
                                className="font-mono text-[#16436b] hover:underline" title={`Open ${h.hostname} in Endpoints`}>
                                {h.hostname}
                              </button>
                              <PlatformBadge platformKey={h.ident?.platformKey} size={12} className="text-[#57606a]" />
                            </span>
                            <PromotedChips rules={h.promotedRules} />
                          </td>
                          <td className="px-3 py-2.5">
                            <span className="flex flex-wrap gap-1">
                              <StateChip>{h.status === 'online' ? 'Online' : 'Offline'}</StateChip>
                              {h.isolation === 'isolated' && <StateChip>Isolated</StateChip>}
                            </span>
                          </td>
                          <td className="px-3 py-2.5 whitespace-nowrap">
                            {h.isolation === 'isolated' ? (
                              <VerbButton onClick={() => setConfirm(confirmSpecs.release_host(h))}>Release Host</VerbButton>
                            ) : (
                              <VerbButton dark onClick={() => setConfirm(confirmSpecs.isolate_host(h))}>Isolate Host</VerbButton>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  </TableSurface>
                </TargetSection>
              )}

              {accounts.length > 0 && (
                <TargetSection title="Accounts" count={accounts.length}>
                  <TableSurface>
                  <table className="w-full text-left text-sm">
                    <thead className="data-thead"><tr>
                      <th className="px-3 py-2.5 font-medium">Account</th>
                      <th className="px-3 py-2.5 font-medium whitespace-nowrap">State</th>
                      <th className="px-3 py-2.5 font-medium whitespace-nowrap">Actions</th>
                    </tr></thead>
                    <tbody>
                      {accounts.map(a => (
                        <tr key={a.entityId} {...focusProps('account', a)}>
                          <td className="px-3 py-2.5">
                            <span className="font-mono text-[#1a2332]">{a.account}</span>
                            {a.host && <span className="block text-xs text-[#8b949e] font-mono">{a.host}</span>}
                            <PromotedChips rules={a.promotedRules} />
                          </td>
                          <td className="px-3 py-2.5">
                            <span className="flex flex-wrap gap-1">
                              {a.state.disabled && <StateChip>Disabled</StateChip>}
                              {a.state.sessions_revoked && <StateChip>Sessions revoked</StateChip>}
                              {a.state.password_reset && <StateChip>Password reset</StateChip>}
                            </span>
                          </td>
                          <td className="px-3 py-2.5 whitespace-nowrap">
                            <div className="flex flex-wrap gap-1.5">
                              <VerbButton disabled={!!a.state.disabled}
                                onClick={() => setConfirm(confirmSpecs.disable_account(a))}>Disable</VerbButton>
                              <VerbButton disabled={!!a.state.sessions_revoked}
                                onClick={() => setConfirm(confirmSpecs.revoke_sessions(a))}>Revoke</VerbButton>
                              <VerbButton disabled={!!a.state.password_reset}
                                onClick={() => setConfirm(confirmSpecs.force_password_reset(a))}>Reset PW</VerbButton>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  </TableSurface>
                </TargetSection>
              )}

              {procRows.length > 0 && (
                <TargetSection title="Processes" count={procRows.length}>
                  <div className="mb-2">
                    <input value={procSearch} onChange={e => setProcSearch(e.target.value)}
                      placeholder="Search processes..." aria-label="Search processes"
                      className="w-full sm:w-72 px-3 py-1.5 text-sm rounded-md border border-[#d0d7de] bg-white text-[#1a2332] placeholder-[#8b949e] focus:outline-none focus:ring-2 focus:ring-[#101218]/20" />
                  </div>
                  <TableSurface scroll>
                    <table className="w-full text-left text-sm">
                      <thead className="data-thead sticky top-0 z-10"><tr>
                        <th className="px-3 py-2.5 font-medium whitespace-nowrap">Host</th>
                        <th className="px-3 py-2.5 font-medium whitespace-nowrap">PID</th>
                        <th className="px-3 py-2.5 font-medium">Process</th>
                        <th className="px-3 py-2.5 font-medium whitespace-nowrap">User</th>
                        <th className="px-3 py-2.5 font-medium whitespace-nowrap">Actions</th>
                      </tr></thead>
                      <tbody>
                        {procFiltered.map(p => (
                          <tr key={`${p.hostname}-${p.pid}`} {...focusProps('process', p)}>
                            <td className="px-3 py-2 font-mono whitespace-nowrap text-[#57606a]">{p.hostname}</td>
                            <td className="px-3 py-2 font-mono whitespace-nowrap">{p.pid}</td>
                            <td className="px-3 py-2 font-mono break-all min-w-[12rem]">
                              {p.name}
                              <PromotedChips rules={promotedFor(x => x.entity?.host === p.hostname && x.sha256 && x.sha256 === p.sha256)} />
                            </td>
                            <td className="px-3 py-2 font-mono whitespace-nowrap">{p.user || '-'}</td>
                            <td className="px-3 py-2 whitespace-nowrap">
                              <VerbButton onClick={() => setConfirm(confirmSpecs.kill_process(p))}>Kill</VerbButton>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </TableSurface>
                </TargetSection>
              )}

              {fileRows.length > 0 && (
                <TargetSection title="Files" count={fileRows.length}>
                  <TableSurface>
                  <table className="w-full text-left text-sm">
                    <thead className="data-thead"><tr>
                      <th className="px-3 py-2.5 font-medium whitespace-nowrap">Host</th>
                      <th className="px-3 py-2.5 font-medium">Payload</th>
                      <th className="px-3 py-2.5 font-medium whitespace-nowrap">State</th>
                      <th className="px-3 py-2.5 font-medium whitespace-nowrap">Actions</th>
                    </tr></thead>
                    <tbody>
                      {fileRows.map(a => (
                        <tr key={`f-${a.hostname}-${a.file_entity_id}`} {...focusProps('autorun', { ...a, persistence_entity_id: null })}>
                          <td className="px-3 py-2.5 font-mono whitespace-nowrap text-[#57606a]">{a.hostname}</td>
                          <td className="px-3 py-2.5 font-mono break-all min-w-[14rem]">
                            {a.name}
                            <span className="block text-xs text-[#8b949e]">{a.command}</span>
                          </td>
                          <td className="px-3 py-2.5">
                            <StateChip>{a.file_state === 'present' ? 'File present' : 'File deleted'}</StateChip>
                          </td>
                          <td className="px-3 py-2.5 whitespace-nowrap">
                            {a.file_state === 'present' && (
                              <VerbButton onClick={() => setConfirm(confirmSpecs.delete_file({ entityId: a.file_entity_id, name: a.name, hostname: a.hostname }))}>Delete File</VerbButton>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  </TableSurface>
                </TargetSection>
              )}

              {persistRows.length > 0 && (
                <TargetSection title="Persistence" count={persistRows.length}>
                  <TableSurface>
                  <table className="w-full text-left text-sm">
                    <thead className="data-thead"><tr>
                      <th className="px-3 py-2.5 font-medium whitespace-nowrap">Host</th>
                      <th className="px-3 py-2.5 font-medium whitespace-nowrap">Type</th>
                      <th className="px-3 py-2.5 font-medium">Artifact</th>
                      <th className="px-3 py-2.5 font-medium whitespace-nowrap">State</th>
                      <th className="px-3 py-2.5 font-medium whitespace-nowrap">Actions</th>
                    </tr></thead>
                    <tbody>
                      {persistRows.map(a => (
                        <tr key={`p-${a.hostname}-${a.persistence_entity_id}`} {...focusProps('autorun', { ...a, file_entity_id: null })}>
                          <td className="px-3 py-2.5 font-mono whitespace-nowrap text-[#57606a]">{a.hostname}</td>
                          <td className="px-3 py-2.5 whitespace-nowrap">{PERSIST_LABEL[a.persist_type] || 'Autorun'}</td>
                          <td className="px-3 py-2.5 font-mono break-all min-w-[14rem]">
                            {a.name}
                            <span className="block text-xs text-[#8b949e]">{a.location}</span>
                          </td>
                          <td className="px-3 py-2.5">
                            <StateChip>{a.registration === 'removed' ? 'Registration removed' : 'Registered'}</StateChip>
                          </td>
                          <td className="px-3 py-2.5 whitespace-nowrap">
                            {a.registration !== 'removed' && (
                              <VerbButton onClick={() => setConfirm(confirmSpecs.remove_persistence({ entityId: a.persistence_entity_id, name: a.name, hostname: a.hostname, persistType: a.persist_type }))}>Remove Persistence</VerbButton>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  </TableSurface>
                </TargetSection>
              )}
            </>
          )}
        </div>
      )}

      <ConfirmDialog
        open={!!confirm}
        title={confirm?.title}
        body={confirm?.body}
        confirmLabel={confirm?.confirmLabel}
        busy={busy}
        onConfirm={() => confirm && run(confirm)}
        onCancel={() => setConfirm(null)}
      />
    </div>
  );
};

export default Response;
