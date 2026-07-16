import React, { useState, useEffect, useCallback } from 'react';
import { apiFetch } from '../api';
import DetectionDetail from './DetectionDetail';

// Detections tab (Stage 2). Raw detections feed with promote / dismiss /
// leave-open triage; promoted detections move to the Threats view. All
// dispositions are scored server-side; the client never sees the answer key.

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

const ActionButton = ({ onClick, active, activeClass, children }) => (
  <button
    type="button"
    onClick={(e) => { e.stopPropagation(); onClick(); }}
    className={`px-2.5 py-1 text-xs font-medium rounded-md border transition ${
      active ? activeClass : 'bg-white text-[#57606a] border-[#d0d7de] hover:bg-[#eef1f4]'
    }`}
  >
    {children}
  </button>
);

const shortTime = (iso) =>
  iso ? new Date(iso).toLocaleTimeString('en-GB', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '-';

const Detections = ({ isVisible, resetTrigger, setDetectionCount, onHostPivot }) => {
  const [feed, setFeed] = useState([]);
  const [counts, setCounts] = useState({ open: 0, promoted: 0, dismissed: 0 });
  const [view, setView] = useState('feed'); // 'feed' | 'threats'
  const [selected, setSelected] = useState(null);

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

  useEffect(() => {
    if (!isVisible) return;
    fetchFeed();
    const interval = setInterval(fetchFeed, 2500);
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
    }).then(() => fetchFeed()).catch(() => {});
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
              <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-[#eef1f4] text-[#57606a]">{rows.length}</span>
            </div>
            <p className="text-sm text-[#57606a]">Triage the feed: promote real threats, dismiss false positives.</p>
          </div>
          <div className="ml-auto flex items-center rounded-md border border-[#d0d7de] overflow-hidden" role="group" aria-label="View">
            {[['feed', `Feed`], ['threats', `Threats ${counts.promoted || 0}`]].map(([key, label]) => (
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
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-[#8b949e]">
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
                  {d.entity?.host || '-'}
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
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Detections;
