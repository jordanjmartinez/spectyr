import React, { useState, useEffect, useCallback } from 'react';
import { apiFetch } from '../api';

// Stage 3.9B Dashboard: the SESSION-WIDE OVERVIEW ("what is happening?"). It
// carries only compact, overview-level surfaces and navigation-level actions.
// The full incident-working experience (briefing, scoped triage, Related
// response activity, and the Submit / Resume / Review graded controls) lives in
// the Incidents workspace, NOT here (D1/D2/D7). Dashboard cards deep-link into
// Incidents; they never open a Submit dialog or a second Review implementation.

const SEV_DOT = { Critical: '#b45858', High: '#c08a3e', Medium: '#c0a93e', Low: '#6fa868' };
const gradeColor = (g) => (!g || g === '-') ? '#8b949e' : g === 'F' ? '#b45858' : g === 'D' ? '#c08a3e' : '#6fa868';
const CARD = { background: '#fff', border: '1px solid #e2e6ea', boxShadow: '0 1px 2px rgba(0,0,0,0.04)' };
const fmtTime = (iso) => { try { return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); } catch { return ''; } };

const Metric = ({ label, value, accent }) => (
  <div className="rounded-xl p-4" style={CARD}>
    <p className="text-2xl font-semibold" style={{ color: accent || '#1a2332' }}>{value}</p>
    <p className="text-xs text-[#6e7781] mt-0.5">{label}</p>
  </div>
);

const IncidentDashboard = ({
  gameMode, analystName, onSelectIncident, onNavigate, onReset, isVisible = true,
}) => {
  const [data, setData] = useState({ active: [], completed: [], queue_length: 0, resolved_count: 0 });
  const [session, setSession] = useState(null);
  const [stats, setStats] = useState(null);          // grouped-alerts stats (severity)
  const [coverage, setCoverage] = useState(null);    // attack_coverage
  const [env, setEnv] = useState(null);              // endpoints summary
  const [detCounts, setDetCounts] = useState({ open: 0 });

  const fetchAll = useCallback(() => {
    apiFetch('/api/incidents').then(r => r.json()).then(setData).catch(() => {});
    apiFetch('/api/analytics/report_card').then(r => r.json()).then(setSession).catch(() => {});
    apiFetch('/api/grouped-alerts').then(r => r.json()).then(d => setStats(d.stats)).catch(() => {});
    apiFetch('/api/analytics/attack_coverage').then(r => r.json()).then(setCoverage).catch(() => {});
    apiFetch('/api/endpoints').then(r => r.json()).then(d => setEnv(d.endpoints || [])).catch(() => {});
    apiFetch('/api/detections').then(r => r.json()).then(d => setDetCounts(d.counts || { open: 0 })).catch(() => {});
  }, []);

  useEffect(() => {
    fetchAll();
    const iv = setInterval(fetchAll, 3000);
    return () => clearInterval(iv);
  }, [fetchAll]);

  const sessionGrade = session?.state === 'submitted' ? session.grading?.composite : null;
  const queueLength = data.queue_length || 0;
  const criticalActive = data.active.filter(c => c.severity === 'Critical').length;
  const sev = stats?.severity_breakdown || {};
  const online = (env || []).filter(e => e.status === 'online').length;
  const offline = (env || []).length - online;

  // Navigation-level actions only (D7): deep-link into the Incidents workspace.
  const openInIncidents = (incidentId) => { onSelectIncident?.(incidentId); onNavigate?.('grouped'); };

  return (
    <div className="space-y-6">
      {/* Session band (session-wide) */}
      <div className="rounded-2xl p-4 sm:p-5" style={CARD}>
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <span className="text-xs uppercase tracking-wider text-[#6e7781] font-medium">{gameMode}</span>
            {analystName && <span className="text-sm text-[#1a2332] font-medium">{analystName}</span>}
            <span className="text-sm text-[#57606a]">
              <span className="font-medium text-[#1a2332]">{data.resolved_count}</span> of {queueLength} resolved
            </span>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <p className="text-[11px] uppercase tracking-wider text-[#6e7781]">Session Performance</p>
              <p className="text-lg font-semibold" style={{ color: gradeColor(sessionGrade?.grade) }}>
                {sessionGrade?.grade || '-'}
                {sessionGrade?.accuracy != null && <span className="ml-1.5 text-xs text-[#8b949e] font-normal">{sessionGrade.accuracy}%</span>}
              </p>
            </div>
            <button onClick={onReset} className="px-3 py-1.5 text-xs font-medium rounded-md border bg-white hover:bg-[#eef1f4] text-[#1a2332] border-[#d0d7de]">Reset</button>
          </div>
        </div>
      </div>

      {/* Summary metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Metric label="Active incidents" value={data.active.length} />
        <Metric label="Completed incidents" value={data.completed.length} />
        <Metric label="Critical active" value={criticalActive} accent={criticalActive ? '#b45858' : undefined} />
        <Metric label="Open detections" value={detCounts.open ?? 0} />
      </div>

      {/* Compact Active + Completed overviews (navigation-level only) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div>
          <h2 className="text-lg font-semibold text-[#1a2332] mb-3">Active Incidents</h2>
          <div className="rounded-2xl divide-y divide-[#eef1f4]" style={CARD}>
            {data.active.length === 0 ? (
              <p className="p-4 text-sm text-[#8b949e] text-center">No active incidents.</p>
            ) : data.active.map(c => (
              <button key={c.incident_id} onClick={() => openInIncidents(c.incident_id)}
                className="w-full text-left p-3 hover:bg-[#f6f8fa] flex items-center justify-between gap-3">
                <span className="min-w-0 flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: SEV_DOT[c.severity] || '#8b949e' }} />
                  <span className="log-mono text-[#16436b] text-xs">{c.incident_id}</span>
                  <span className="text-sm text-[#1a2332] truncate">{c.title}</span>
                </span>
                <span className="text-xs text-[#8b949e] shrink-0 whitespace-nowrap">
                  {!c.sealed ? 'Loading' : c.ready ? 'Ready' : `${c.open_detections} to review`}
                </span>
              </button>
            ))}
          </div>
        </div>
        <div>
          <h2 className="text-lg font-semibold text-[#1a2332] mb-3">Recent Completed</h2>
          <div className="rounded-2xl divide-y divide-[#eef1f4]" style={CARD}>
            {data.completed.length === 0 ? (
              <p className="p-4 text-sm text-[#8b949e] text-center">No submitted incidents yet.</p>
            ) : data.completed.slice(-6).reverse().map(c => (
              <button key={c.incident_id} onClick={() => openInIncidents(c.incident_id)}
                className="w-full text-left p-3 hover:bg-[#f6f8fa] flex items-center justify-between gap-3">
                <span className="min-w-0 flex items-center gap-2">
                  <span className="log-mono text-[#16436b] text-xs">{c.incident_id}</span>
                  <span className="text-sm text-[#1a2332] truncate">{c.title}</span>
                  {c.assisted && <span className="text-[9px] uppercase px-1 py-0.5 rounded bg-[#eef1f4] text-[#57606a] border border-[#d0d7de]">Assisted</span>}
                </span>
                <span className="text-xs font-medium shrink-0" style={{ color: gradeColor(c.incident_grade?.grade) }}>
                  {c.incident_grade?.grade || '-'} · {c.incident_grade?.accuracy ?? '-'}%
                </span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Queue status + severity + ATT&CK + environment overview widgets */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="rounded-xl p-4" style={CARD}>
          <p className="text-[11px] uppercase tracking-wider text-[#6e7781] mb-2">Queue status</p>
          <p className="text-sm text-[#1a2332]"><span className="font-semibold">{data.resolved_count}</span> resolved</p>
          <p className="text-sm text-[#57606a]"><span className="font-semibold text-[#1a2332]">{data.active.length}</span> in flight</p>
          <p className="text-sm text-[#57606a]">{queueLength} total</p>
        </div>
        <div className="rounded-xl p-4" style={CARD}>
          <p className="text-[11px] uppercase tracking-wider text-[#6e7781] mb-2">Severity distribution</p>
          {['critical', 'high', 'medium', 'low'].map(k => (
            <p key={k} className="text-sm text-[#57606a] flex justify-between"><span className="capitalize">{k}</span><span className="font-medium text-[#1a2332]">{sev[k] ?? 0}</span></p>
          ))}
        </div>
        <div className="rounded-xl p-4" style={CARD}>
          <p className="text-[11px] uppercase tracking-wider text-[#6e7781] mb-2">ATT&CK Coverage</p>
          <p className="text-2xl font-semibold text-[#1a2332]">{coverage?.tactics_covered ?? 0}<span className="text-sm text-[#8b949e]">/{coverage?.total_tactics ?? 13}</span></p>
          <p className="text-xs text-[#57606a]">{coverage?.completed ?? 0} completed scenarios</p>
        </div>
        <div className="rounded-xl p-4" style={CARD}>
          <p className="text-[11px] uppercase tracking-wider text-[#6e7781] mb-2">Environment</p>
          <p className="text-sm text-[#57606a]"><span className="font-semibold text-[#6fa868]">{online}</span> online</p>
          <p className="text-sm text-[#57606a]"><span className="font-semibold text-[#b45858]">{offline}</span> offline</p>
          <p className="text-xs text-[#8b949e] mt-1">{(env || []).length} managed hosts</p>
        </div>
      </div>
    </div>
  );
};

export default IncidentDashboard;
