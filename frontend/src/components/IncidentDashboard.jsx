import React, { useState, useEffect, useCallback, useRef } from 'react';
import { apiFetch } from '../api';
import {
  toReview, SUBMIT_PENDING, MODE_LABEL, TELEMETRY_LOADING,
  detectionsReviewed, responseActionsTaken, CLASSIFICATION_NOT_SELECTED,
  classificationSelected, READY_TO_SUBMIT, SESSION_PERFORMANCE_LABEL,
} from './uiCopy';
import { submissionReady, validClassification } from './submissionReady';
import { severityDot, gradeColor, CARD_STYLE } from './ui';
import { platformFor, PLATFORM_LABELS, DEVICE_LABELS } from './icons';
import AttackRadar from './AttackRadar';

// ============================================================================
// Stage 3.9B Dashboard, redesigned by Visual pass V5: the analytic
// overview grid. STILL the session-wide overview with NAVIGATION-LEVEL
// actions only -- the graded Submit/Resume-into-work/Review controls
// live in the Incidents workspace; rows and Resume here only navigate.
//
// Anatomy (desktop): the session band, then a supporting column (Active
// Investigation + Investigation Progress + Severity + Environment)
// beside the main region (KPI stat tiles, the ATT&CK Coverage Matrix,
// Recent results). Narrow screens stack: band, Active Investigation,
// Progress, Severity, Environment, then the main region -- the
// supporting column completes before the main region begins.
//
// DATA TRUTH (V11): every value is an existing observable or a
// post-submission disclosure. The per-incident grades/categories and the
// session-view matrix states come from each SUBMITTED incident's served
// score view + triage review (fetched once per submitted id); active
// incidents contribute a count only. No trends, deltas, or sparklines
// exist because no historical series exists. Nothing here reveals
// pre-submission correctness.
// ============================================================================

const gradeAccuracy = (g) =>
  g && g.accuracy != null ? `${g.accuracy}%` : '-';

const Metric = ({ label, value, accent, sub }) => (
  <div className="rounded-xl p-4" style={CARD_STYLE}>
    <p className="t-kpi" style={accent ? { color: accent } : undefined}>{value}</p>
    <p className="t-meta text-[#6e7781] mt-0.5">{label}</p>
    {sub && <p className="text-[11px] text-[#8b949e] mt-0.5">{sub}</p>}
  </div>
);

const WidgetLabel = ({ children }) => (
  <p className="t-overline mb-2">{children}</p>
);

const IncidentDashboard = ({
  gameMode, analystName, onSelectIncident, onNavigate, onReset, isVisible = true,
  // A3.4 (ratified A3-OD-3): the shell-owned classification selections --
  // this surface derives Ready from the SAME state as the workspace, so
  // no surface shows Ready while Classification says not selected.
  chosen = {},
  activeIncidentId = null,
}) => {
  const [data, setData] = useState({ active: [], completed: [], queue_length: 0, resolved_count: 0 });
  const [session, setSession] = useState(null);
  const [env, setEnv] = useState(null);              // endpoints summary
  const [detCounts, setDetCounts] = useState({ open: 0, promoted: 0, dismissed: 0 });
  const [feed, setFeed] = useState([]);              // sanitized detections feed
  // The FOCUS incident's observable scope (detection ids), feeding the
  // severity bars. Observable data only; refreshed on the same poll.
  const [focusScope, setFocusScope] = useState({ forId: null, ids: null });
  const focusIdRef = useRef(null);
  const [actionSuccesses, setActionSuccesses] = useState(0);
  // Post-submission records: incident_id -> {grading, techId}. Fetched
  // ONCE per submitted id (score view + disclosed triage review); never
  // requested for active incidents (the temporal rule).
  const [records, setRecords] = useState({});
  const fetchedRef = useRef(new Set());

  const fetchAll = useCallback(() => {
    apiFetch('/api/incidents').then(r => r.json()).then(setData).catch(() => {});
    apiFetch('/api/analytics/report_card').then(r => r.json()).then(setSession).catch(() => {});
    apiFetch('/api/endpoints').then(r => r.json()).then(d => setEnv(d.endpoints || [])).catch(() => {});
    apiFetch('/api/detections').then(r => r.json()).then(d => {
      setDetCounts(d.counts || { open: 0, promoted: 0, dismissed: 0 });
      setFeed(d.detections || []);
    }).catch(() => {});
    const fid = focusIdRef.current;
    if (fid) {
      apiFetch(`/api/incidents/${fid}/scope`).then(r => (r.ok ? r.json() : null))
        .then(sc => {
          if (sc) setFocusScope({ forId: fid, ids: new Set(sc.detection_ids || []) });
        })
        .catch(() => {});
    }
    apiFetch('/api/actions').then(r => r.json())
      .then(d => setActionSuccesses((d.actions || []).filter(a => a.outcome === 'success').length))
      .catch(() => {});
  }, []);

  useEffect(() => {
    fetchAll();
    const iv = setInterval(fetchAll, 3000);
    return () => clearInterval(iv);
  }, [fetchAll]);

  const completedKey = (data.completed || []).map(c => c.incident_id).join(',');
  useEffect(() => {
    const ids = completedKey ? completedKey.split(',') : [];
    if (ids.length === 0 && fetchedRef.current.size > 0) {
      // reset / Practice Another cleared the session's submissions
      fetchedRef.current.clear();
      setRecords({});
      return;
    }
    ids.filter(id => !fetchedRef.current.has(id)).forEach(id => {
      fetchedRef.current.add(id);
      Promise.all([
        apiFetch(`/api/incidents/${id}/score`).then(r => (r.ok ? r.json() : null)).catch(() => null),
        apiFetch(`/api/incidents/${id}/triage-review`).then(r => (r.ok ? r.json() : null)).catch(() => null),
      ]).then(([score, triage]) => {
        if (score?.state === 'submitted') {
          setRecords(prev => ({
            ...prev,
            [id]: { grading: score.grading, techId: triage?.mitre?.id || null },
          }));
        } else {
          fetchedRef.current.delete(id);   // not served yet; retry on a later poll
        }
      });
    });
  }, [completedKey]);

  const sessionGrade = session?.state === 'submitted' ? session.grading?.composite : null;
  const queueLength = data.queue_length || 0;
  const isGuided = gameMode === 'guided' || gameMode === 'training';
  const online = (env || []).filter(e => e.status === 'online').length;
  const offline = (env || []).length - online;

  // Navigation-level actions only (D7): deep-link into the Incidents workspace.
  const openInIncidents = (incidentId) => { onSelectIncident?.(incidentId); onNavigate?.('incidents'); };

  // The focused active investigation: the pinned case when it is active,
  // else the oldest active (drip order).
  const focus = data.active.find(c => c.incident_id === activeIncidentId) || data.active[0] || null;
  const otherActive = data.active.filter(c => focus && c.incident_id !== focus.incident_id);
  const focusId = focus?.incident_id || null;
  focusIdRef.current = focusId;

  // Fetch the focus scope the moment the focus is known (the poll keeps
  // it fresh as the roster attaches); observable data only.
  useEffect(() => {
    if (!focusId) { setFocusScope({ forId: null, ids: null }); return undefined; }
    let cancelled = false;
    apiFetch(`/api/incidents/${focusId}/scope`).then(r => (r.ok ? r.json() : null))
      .then(sc => {
        if (!cancelled && sc) setFocusScope({ forId: focusId, ids: new Set(sc.detection_ids || []) });
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [focusId]);

  // Severity bars (VS owner correction): the ACTIVE incident's observable
  // detections by severity, exact counts, scaled against the largest
  // displayed count (no percentage implied).
  const scopedIds = focus && focusScope.forId === focus.incident_id ? focusScope.ids : null;
  const sevRows = ['critical', 'high', 'medium', 'low'].map(k => ({
    key: k,
    label: k.charAt(0).toUpperCase() + k.slice(1),
    count: scopedIds ? feed.filter(d => scopedIds.has(d.id) && String(d.severity).toLowerCase() === k).length : 0,
  }));
  const sevMax = Math.max(...sevRows.map(r => r.count));

  // Environment status (VS owner correction): current observable state
  // only -- no uptime claims, no history. Platform breakdown from the
  // REAL serialized fields via the one shared mapping.
  const managed = (env || []).length;
  const availabilityPct = managed ? Math.round((online / managed) * 100) : 0;
  const platformGroups = {};
  for (const r of env || []) {
    const ident = platformFor(r);
    const label = `${PLATFORM_LABELS[ident.platformKey]} ${DEVICE_LABELS[ident.deviceKind]}`;
    platformGroups[label] = (platformGroups[label] || 0) + 1;
  }

  const readinessChip = (c) => (!c.sealed ? 'Loading'
    : submissionReady(c, chosen) ? 'Ready'
      : c.ready ? SUBMIT_PENDING
        : toReview(c.open_detections));

  // Latest submitted incident (KPI tile + newest-first results ordering).
  const completedSorted = [...(data.completed || [])]
    .sort((a, b) => String(b.submitted_at || '').localeCompare(String(a.submitted_at || '')));
  const latest = completedSorted[0] || null;

  const triage = focus?.triage || { total: 0, triaged: 0 };
  const focusChosen = focus ? chosen[focus.incident_id] : null;
  const focusReady = focus ? submissionReady(focus, chosen) : false;

  return (
    <div className="space-y-4">
      {/* Session band (session-wide) */}
      <div className="rounded-xl p-4 sm:p-5" style={CARD_STYLE}>
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <span className="t-overline">{MODE_LABEL[gameMode] || gameMode}</span>
            {analystName && <span className="text-sm text-[#1a2332] font-medium">{analystName}</span>}
            <span className="text-sm text-[#57606a]">
              {isGuided
                ? (data.resolved_count > 0 ? 'Run completed' : '1 incident in this run')
                : <><span className="font-medium text-[#1a2332]">{data.resolved_count}</span> of {queueLength} resolved</>}
            </span>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <p className="t-overline">{SESSION_PERFORMANCE_LABEL}</p>
              <p className="text-lg font-semibold" style={{ color: gradeColor(sessionGrade?.grade) }}>
                {sessionGrade?.grade || '-'}
                {sessionGrade?.accuracy != null && <span className="ml-1.5 text-xs text-[#8b949e] font-normal">{sessionGrade.accuracy}%</span>}
              </p>
            </div>
            <button onClick={onReset} className="px-3 py-1.5 text-xs font-medium rounded-md border bg-white hover:bg-[#eef1f4] text-[#1a2332] border-[#d0d7de]">Reset</button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[19rem_minmax(0,1fr)] gap-4 items-start">
        {/* ---- supporting column ---- */}
        <div className="space-y-4 min-w-0">
          {/* A. Active Investigation (observable fields only; Resume navigates) */}
          <div className="rounded-xl p-4" style={CARD_STYLE} data-testid="active-investigation">
            <WidgetLabel>Active investigation</WidgetLabel>
            {!focus ? (
              <p className="text-sm text-[#8b949e]">No active investigations.</p>
            ) : (
              <div className="space-y-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: severityDot(focus.severity) }} />
                  <span className="log-mono text-[#16436b] text-xs">{focus.incident_id}</span>
                  <span className="text-[11px] text-[#8b949e]">{focus.severity}</span>
                  <span className="text-[11px] text-[#8b949e]">{MODE_LABEL[gameMode] || gameMode}</span>
                </div>
                <p className="text-sm font-medium text-[#1a2332]">{focus.title}</p>
                {/* VS: Investigation Progress folded in here -- the bar and
                    its exact textual equivalent live with the incident's
                    facts, not in a separate fragmenting card. */}
                {focus.sealed && (
                  <div
                    role="progressbar"
                    aria-valuemin={0}
                    aria-valuemax={triage.total}
                    aria-valuenow={triage.triaged}
                    aria-label={detectionsReviewed(triage.triaged, triage.total)}
                    className="h-2 rounded-full bg-[#eef1f4] overflow-hidden"
                  >
                    <div
                      className="h-full rounded-full bg-[#16436b] transition-[width] duration-300 motion-reduce:transition-none"
                      style={{ width: `${triage.total ? Math.round((triage.triaged / triage.total) * 100) : 0}%` }}
                    />
                  </div>
                )}
                <div className="text-xs text-[#57606a] space-y-0.5">
                  <p>{focus.sealed ? detectionsReviewed(triage.triaged, triage.total) : TELEMETRY_LOADING}</p>
                  <p>{validClassification(focusChosen)
                    ? classificationSelected(focusChosen.category)
                    : CLASSIFICATION_NOT_SELECTED}</p>
                  <p>{responseActionsTaken(focus.related_actions ?? 0)}</p>
                  <p className="text-[#8b949e]">{focus.sealed && focusReady ? READY_TO_SUBMIT : readinessChip(focus)}</p>
                </div>
                <button
                  type="button"
                  onClick={() => openInIncidents(focus.incident_id)}
                  className="mt-1 px-3 py-1.5 text-xs font-medium rounded-md bg-[#101218] text-white hover:bg-[#1e2330]"
                >
                  Resume investigation
                </button>
                {otherActive.length > 0 && (
                  <div className="pt-2 border-t border-[#eef1f4] space-y-1">
                    {otherActive.map(c => (
                      <button key={c.incident_id} onClick={() => openInIncidents(c.incident_id)}
                        className="w-full text-left flex items-center justify-between gap-2 text-xs hover:bg-[#f6f8fa] rounded px-1 py-1">
                        <span className="min-w-0 flex items-center gap-1.5">
                          <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: severityDot(c.severity) }} />
                          <span className="log-mono text-[#16436b]">{c.incident_id}</span>
                          <span className="text-[#57606a] truncate">{c.title}</span>
                        </span>
                        <span className="text-[#8b949e] shrink-0">{readinessChip(c)}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Severity distribution (VS owner correction): compact
              horizontal bars over the ACTIVE incident's observable
              detections -- exact counts, bars scaled to the largest
              displayed count (no percentage implied), label + count text
              beside every bar (never color alone). */}
          <div className="rounded-xl p-4" style={CARD_STYLE} data-testid="severity-distribution">
            <WidgetLabel>Severity distribution</WidgetLabel>
            <p className="text-xs text-[#8b949e] mb-2">Active incident</p>
            {sevMax === 0 ? (
              <p className="text-sm text-[#57606a]">No detections observed yet.</p>
            ) : (
              <div className="space-y-1.5">
                {sevRows.map(r => (
                  <div key={r.key} className="flex items-center gap-2 text-sm">
                    <span className="w-16 shrink-0 text-[#57606a]">{r.label}</span>
                    <span className="flex-1 h-2 rounded-full bg-[#eef1f4] overflow-hidden" aria-hidden="true">
                      <span
                        className="block h-full rounded-full"
                        style={{ width: `${sevMax ? Math.round((r.count / sevMax) * 100) : 0}%`, background: severityDot(r.key) }}
                      />
                    </span>
                    <span className="w-6 shrink-0 text-right font-medium text-[#1a2332] tabular-nums">{r.count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Environment status (VS owner correction): current observable
              state only -- no gauges, no history, no uptime claims. */}
          <div className="rounded-xl p-4" style={CARD_STYLE} data-testid="environment-status">
            <WidgetLabel>Environment status</WidgetLabel>
            {managed === 0 ? (
              <p className="text-sm text-[#57606a]">No managed hosts available.</p>
            ) : (
              <div className="space-y-2">
                <p className="t-kpi">{managed}<span className="ml-1.5 text-sm font-normal text-[#57606a]">managed host{managed === 1 ? '' : 's'}</span></p>
                <p className="text-sm text-[#57606a] flex items-center gap-1.5">
                  <span aria-hidden="true" className="w-1.5 h-1.5 rounded-full" style={{ background: '#6fa868' }} />
                  <span><span className="font-medium text-[#1a2332]">{online}</span> online</span>
                  <span className="text-[#d0d7de]">·</span>
                  <span aria-hidden="true" className="w-1.5 h-1.5 rounded-full" style={{ background: '#b45858' }} />
                  <span><span className="font-medium text-[#1a2332]">{offline}</span> offline</span>
                </p>
                <div>
                  <p className="text-xs text-[#6e7781] mb-1">Availability</p>
                  <div className="flex items-center gap-2">
                    <span className="flex-1 h-1.5 rounded-full bg-[#eef1f4] overflow-hidden" aria-hidden="true">
                      <span className="block h-full rounded-full bg-[#6fa868]" style={{ width: `${availabilityPct}%` }} />
                    </span>
                    <span className="text-xs font-medium text-[#1a2332]">{availabilityPct}%</span>
                  </div>
                  <p className="sr-only">{online} of {managed} managed hosts online ({availabilityPct}% availability).</p>
                </div>
                {Object.keys(platformGroups).length > 0 && (
                  <p className="text-xs text-[#57606a]">
                    {Object.entries(platformGroups).map(([label, n], i) => (
                      <span key={label}>{i > 0 && <span className="text-[#d0d7de]"> · </span>}{label} {n}</span>
                    ))}
                  </p>
                )}
                <button
                  type="button"
                  onClick={() => onNavigate?.('endpoints')}
                  className="text-xs font-medium text-[#16436b] hover:underline"
                >
                  View endpoints
                </button>
              </div>
            )}
          </div>
        </div>

        {/* ---- main region ---- */}
        <div className="space-y-4 min-w-0">
          {/* C. KPI stat tiles: real session observables only -- no trends,
              deltas, or sparklines (no historical series exists). */}
          <div className="grid grid-cols-2 xl:grid-cols-4 gap-3" data-testid="kpi-row">
            <Metric label="Detections reviewed" value={(detCounts.promoted ?? 0) + (detCounts.dismissed ?? 0)} />
            <Metric label="Response actions executed" value={actionSuccesses} />
            <Metric label="Incidents completed" value={data.completed.length} />
            <Metric
              label="Latest incident grade"
              value={latest?.incident_grade?.grade || '-'}
              accent={latest ? gradeColor(latest.incident_grade?.grade) : undefined}
              sub={latest ? gradeAccuracy(latest.incident_grade) : 'No submissions yet'}
            />
          </div>

          {/* D. The ATT&CK coverage radar (V6-R owner correction): one
              polygon, catalog coverage against the authoritative pinned
              per-tactic technique counts. No session/player overlay. */}
          <AttackRadar isVisible={isVisible} />

          {/* E. Recent results -- submitted incidents this session, newest
              first; grades/categories are the frozen post-submission
              record. Rows navigate to the incident. */}
          <div className="rounded-xl" style={CARD_STYLE} data-testid="recent-results">
            <div className="px-4 pt-4 pb-2 flex items-baseline gap-2">
              <p className="text-sm font-semibold text-[#1a2332]">Recent results</p>
              <span className="text-xs text-[#6e7781]">&middot; This session</span>
            </div>
            {completedSorted.length === 0 ? (
              <p className="px-4 pb-4 text-sm text-[#8b949e]">No incidents submitted yet this session. Results appear here when you submit an incident.</p>
            ) : (
              <div className="overflow-x-auto pb-1">
                <table className="w-full text-left text-sm">
                  <thead className="dark-thead">
                    <tr>
                      <th className="px-3 py-2 font-medium whitespace-nowrap">Incident</th>
                      <th className="px-3 py-2 font-medium whitespace-nowrap">Category</th>
                      <th className="px-3 py-2 font-medium whitespace-nowrap">Mode</th>
                      <th className="px-3 py-2 font-medium whitespace-nowrap">Classification</th>
                      <th className="px-3 py-2 font-medium whitespace-nowrap">Detections</th>
                      <th className="px-3 py-2 font-medium whitespace-nowrap">Response</th>
                      <th className="px-3 py-2 font-medium whitespace-nowrap">Overall</th>
                    </tr>
                  </thead>
                  <tbody>
                    {completedSorted.map(c => {
                      const g = records[c.incident_id]?.grading || null;
                      return (
                        <tr key={c.incident_id} className="border-b border-[#eef1f4] last:border-b-0 hover:bg-[#f6f8fa]">
                          <td className="px-3 py-2 whitespace-nowrap">
                            <button type="button" onClick={() => openInIncidents(c.incident_id)}
                              className="log-mono text-[#16436b] hover:underline text-xs">{c.incident_id}</button>
                            <span className="block text-xs text-[#57606a] truncate max-w-[14rem]" title={c.title}>{c.title}</span>
                          </td>
                          <td className="px-3 py-2 whitespace-nowrap text-[#57606a]">{g?.classification?.category ?? '-'}</td>
                          <td className="px-3 py-2 whitespace-nowrap text-[#57606a]">{MODE_LABEL[gameMode] || gameMode}</td>
                          <td className="px-3 py-2 whitespace-nowrap font-medium" style={{ color: gradeColor(g?.classification?.grade) }}>{g?.classification?.grade ?? '-'}</td>
                          <td className="px-3 py-2 whitespace-nowrap font-medium" style={{ color: gradeColor(g?.detection?.grade) }}>{g?.detection?.grade ?? '-'}</td>
                          <td className="px-3 py-2 whitespace-nowrap font-medium" style={{ color: gradeColor(g?.response?.grade) }}>{g?.response?.grade ?? '-'}</td>
                          <td className="px-3 py-2 whitespace-nowrap font-semibold" style={{ color: gradeColor(c.incident_grade?.grade) }}>
                            {c.incident_grade?.grade || '-'} · {c.incident_grade?.accuracy ?? '-'}%
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default IncidentDashboard;
