import React, { useState, useEffect, useCallback } from 'react';
import { apiFetch } from '../api';
import DetectionDetail from './DetectionDetail';
import ConfirmDialog from './ConfirmDialog';

// Detections tab (Stage 2). Raw detections feed with promote / dismiss /
// leave-open triage; promoted detections move to the Threats view. All
// dispositions are scored server-side; the client never sees the answer key.
// Stage 3a: identity response actions live on account entities in the
// Threats view, and the session Response Log renders every action attempt.

export const SEV_PILL = {
  critical: 'bg-red-50 text-red-700 border-red-200',
  high: 'bg-orange-50 text-orange-700 border-orange-200',
  medium: 'bg-amber-50 text-amber-700 border-amber-200',
};
export const SEV_DOT = { critical: '#b26666', high: '#c28e46', medium: '#d4cc6e' };

export const SeverityBadge = ({ severity }) => (
  <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium border ${SEV_PILL[severity] || 'border-[#d0d7de] text-[#57606a]'}`}>
    <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: SEV_DOT[severity] || '#8b949e' }} />
    {String(severity || '').toUpperCase()}
  </span>
);

export const RuleTypeChip = ({ type }) => (
  <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs border border-[#d0d7de] text-[#57606a] whitespace-nowrap">
    {type === 'yara' ? 'YARA' : 'Sigma'}
  </span>
);

const ActionButton = ({ onClick, active, activeClass, disabled, children }) => (
  <button
    type="button"
    disabled={disabled}
    onClick={(e) => { e.stopPropagation(); onClick(); }}
    className={`px-2.5 py-1 text-xs font-medium rounded-md border transition disabled:opacity-50 disabled:cursor-default ${
      active ? activeClass : 'bg-white text-[#57606a] border-[#d0d7de] hover:bg-[#eef1f4]'
    }`}
  >
    {children}
  </button>
);

const ACTION_LABELS = {
  isolate_host: 'Isolate Host',
  release_host: 'Release Host',
  kill_process: 'Kill Process',
  delete_file: 'Delete File',
  disable_account: 'Disable Account',
  revoke_sessions: 'Revoke Sessions',
  force_password_reset: 'Force Password Reset',
};

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

const IdentityStateChips = ({ state }) => {
  if (!state) return null;
  const chips = [];
  if (state.disabled) chips.push('Disabled');
  if (state.sessions_revoked) chips.push('Sessions revoked');
  if (state.password_reset) chips.push('Password reset');
  if (!chips.length) return null;
  return (
    <span className="flex flex-wrap gap-1 mt-1">
      {chips.map(c => (
        <span key={c} className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-[#eef1f4] text-[#57606a]">{c}</span>
      ))}
    </span>
  );
};

const shortTime = (iso) =>
  iso ? new Date(iso).toLocaleTimeString('en-GB', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '-';

const Detections = ({ isVisible, resetTrigger, setDetectionCount, onHostPivot }) => {
  const [feed, setFeed] = useState([]);
  const [counts, setCounts] = useState({ open: 0, promoted: 0, dismissed: 0 });
  const [view, setView] = useState('feed'); // 'feed' | 'threats' | 'log'
  const [selected, setSelected] = useState(null);
  const [logEntries, setLogEntries] = useState([]);
  const [confirm, setConfirm] = useState(null); // {title, body, confirmLabel, action, target}
  const [busy, setBusy] = useState(false);
  const [actionNotice, setActionNotice] = useState(null);

  const fetchFeed = useCallback(() => {
    apiFetch('/api/detections')
      .then(res => res.json())
      .then(data => {
        setFeed(data.detections || []);
        setCounts(data.counts || { open: 0, promoted: 0, dismissed: 0 });
        setDetectionCount?.((data.counts || {}).open || 0);
      })
      .catch(() => {});
  }, [setDetectionCount]);

  const fetchLog = useCallback(() => {
    apiFetch('/api/actions')
      .then(res => res.json())
      .then(data => setLogEntries(data.actions || []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!isVisible) return;
    fetchFeed();
    fetchLog();
    const interval = setInterval(() => { fetchFeed(); fetchLog(); }, 2500);
    return () => clearInterval(interval);
  }, [isVisible, fetchFeed, fetchLog]);

  useEffect(() => {
    setSelected(null);
    setActionNotice(null);
    setConfirm(null);
    fetchFeed();
    fetchLog();
  }, [resetTrigger, fetchFeed, fetchLog]);

  const act = (id, action) => {
    apiFetch(`/api/detections/${encodeURIComponent(id)}/disposition`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action }),
    }).then(() => fetchFeed()).catch(() => {});
  };

  const runResponse = (action, target) => {
    setBusy(true);
    apiFetch('/api/actions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action, target }),
    })
      .then(res => res.json())
      .then(entry => {
        setActionNotice(entry.outcome === 'success' ? null : (entry.reason || entry.error || null));
        setConfirm(null);
        setBusy(false);
        fetchFeed();
        fetchLog();
      })
      .catch(() => { setConfirm(null); setBusy(false); });
  };

  if (selected) {
    return (
      <DetectionDetail
        detId={selected}
        onBack={() => { setSelected(null); fetchFeed(); }}
        onAction={act}
        onHostPivot={onHostPivot}
      />
    );
  }

  const rows = view === 'threats' ? feed.filter(d => d.player_action === 'promoted') : feed;
  const headerCount = view === 'log' ? logEntries.length : rows.length;
  const logNewestFirst = [...logEntries].reverse();

  const CONFIRM_LABELS = { disable_account: 'Disable', revoke_sessions: 'Revoke', force_password_reset: 'Reset' };
  const identityConfirm = (d, action, verb) => setConfirm({
    title: ACTION_LABELS[action],
    body: `${verb} ${d.entity.account}. This is a response action; the detection record does not change.`,
    confirmLabel: CONFIRM_LABELS[action],
    action,
    target: d.entity.account_id,
  });

  return (
    <div>
      {/* Header card */}
      <div className="bg-white border border-[#e2e6ea] rounded-xl overflow-hidden mb-4">
        <div className="h-0.5" style={{ background: 'linear-gradient(to right, #16436b, #101218)' }} />
        <div className="p-4 sm:p-5 flex flex-wrap items-center gap-4">
          <div className="w-10 h-10 rounded-lg bg-[#101218] flex items-center justify-center shrink-0">
            <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" role="img" aria-label="Detections">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d="M12 9v2m0 4h.01M5 19h14a2 2 0 001.84-2.75L13.74 4a2 2 0 00-3.48 0L3.16 16.25A2 2 0 005 19z" />
            </svg>
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h2 className="text-xl sm:text-2xl font-semibold text-[#1a2332]">Detections</h2>
              <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-[#eef1f4] text-[#57606a]">{headerCount}</span>
            </div>
            <p className="text-sm text-[#57606a]">
              {view === 'log'
                ? 'Every response action this session, in order.'
                : 'Triage the feed: promote real threats, dismiss false positives.'}
            </p>
          </div>
          <div className="ml-auto flex items-center rounded-md border border-[#d0d7de] overflow-hidden" role="group" aria-label="View">
            {[['feed', `Feed`], ['threats', `Threats ${counts.promoted || 0}`], ['log', 'Response Log']].map(([key, label]) => (
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

      {view === 'feed' && (
        <p className="text-sm text-[#57606a] mb-2">
          {counts.open} open &middot; {counts.promoted} promoted &middot; {counts.dismissed} dismissed
        </p>
      )}
      {view === 'threats' && actionNotice && (
        <p className="text-sm text-[#57606a] mb-2">{actionNotice}</p>
      )}

      {view === 'log' ? (
        <div className="bg-white border border-[#e2e6ea] rounded-xl overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="dark-thead">
              <tr className="text-xs uppercase tracking-wider">
                <th className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap">Time</th>
                <th className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap">Action</th>
                <th className="px-3 sm:px-4 py-3 font-medium">Target</th>
                <th className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap">Outcome</th>
                <th className="px-3 sm:px-4 py-3 font-medium">Detail</th>
              </tr>
            </thead>
            <tbody>
              {logNewestFirst.length === 0 && (
                <tr><td colSpan={5} className="px-4 py-8 text-center text-[#8b949e]">
                  No response actions yet. Actions taken on endpoints and accounts appear here.
                </td></tr>
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
        </div>
      ) : (
        <div className="bg-white border border-[#e2e6ea] rounded-xl overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="dark-thead">
              <tr className="text-xs uppercase tracking-wider">
                <th className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap">Severity</th>
                <th className="px-3 sm:px-4 py-3 font-medium">Rule</th>
                <th className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap">Type</th>
                <th className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap">Entity</th>
                <th className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap">Time</th>
                <th className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap">Triage</th>
                {view === 'threats' && (
                  <th className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap">Respond</th>
                )}
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr><td colSpan={view === 'threats' ? 7 : 6} className="px-4 py-8 text-center text-[#8b949e]">
                  {view === 'threats' ? 'No promoted threats yet.' : 'No detections yet. They fire as scenarios reach the queue.'}
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
                    {view === 'threats' && d.entity?.account_id && (
                      <IdentityStateChips state={d.entity?.account_state} />
                    )}
                  </td>
                  <td className="px-3 sm:px-4 py-3 font-mono whitespace-nowrap text-[#57606a]">{shortTime(d.time)}</td>
                  <td className="px-3 sm:px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      <ActionButton onClick={() => act(d.id, 'promote')} active={d.player_action === 'promoted'} activeClass="bg-[#101218] text-white border-transparent">Promote</ActionButton>
                      <ActionButton onClick={() => act(d.id, 'dismiss')} active={d.player_action === 'dismissed'} activeClass="bg-[#57606a] text-white border-transparent">Dismiss</ActionButton>
                      {d.player_action !== 'open' && (
                        <ActionButton onClick={() => act(d.id, 'open')} active={false}>Reopen</ActionButton>
                      )}
                    </div>
                  </td>
                  {view === 'threats' && (
                    <td className="px-3 sm:px-4 py-3">
                      {/* Identity actions target the account entity wherever a
                          promoted detection resolves one (identity-provider
                          detections carry only an account; host-local
                          detections carry a host plus its acting account).
                          The action always binds to the account, never the
                          host. */}
                      {d.entity?.account_id ? (
                        <div className="flex items-center gap-1.5">
                          <ActionButton
                            disabled={!!d.entity.account_state?.disabled}
                            onClick={() => identityConfirm(d, 'disable_account', 'Disable the account')}
                          >
                            Disable
                          </ActionButton>
                          <ActionButton
                            disabled={!!d.entity.account_state?.sessions_revoked}
                            onClick={() => identityConfirm(d, 'revoke_sessions', 'Revoke all active sessions for')}
                          >
                            Revoke
                          </ActionButton>
                          <ActionButton
                            disabled={!!d.entity.account_state?.password_reset}
                            onClick={() => identityConfirm(d, 'force_password_reset', 'Force a password reset for')}
                          >
                            Reset PW
                          </ActionButton>
                        </div>
                      ) : (
                        <span className="text-xs text-[#8b949e]">
                          {d.entity?.account ? 'Unresolved account' : '-'}
                        </span>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <ConfirmDialog
        open={!!confirm}
        title={confirm?.title}
        body={confirm?.body}
        confirmLabel={confirm?.confirmLabel}
        busy={busy}
        onConfirm={() => confirm && runResponse(confirm.action, confirm.target)}
        onCancel={() => setConfirm(null)}
      />
    </div>
  );
};

export default Detections;
