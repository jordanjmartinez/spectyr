import React, { useState, useEffect, useCallback, useRef } from 'react';
import { apiFetch } from '../api';
import {
  toReview, SUBMIT_PENDING, MODE_LABEL, TELEMETRY_LOADING,
  detectionsReviewed, responseActionsTaken, CLASSIFICATION_NOT_SELECTED,
  classificationSelected, READY_TO_SUBMIT, SESSION_PERFORMANCE_LABEL,
} from './uiCopy';
import { submissionReady, validClassification } from './submissionReady';
import {
  severityDot, gradeColor, CARD_STYLE, IncidentIdPill, SeverityBadge, ModeBadge,
} from './ui';
import { platformFor, PLATFORM_LABELS, DEVICE_LABELS } from './icons';
import AttackRadar from './AttackRadar';
import EvidenceActivity from './EvidenceActivity';
import { descentSessionAll } from './lcqlPivots';

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

// VA3 section 6: primary container headings use the shared heading
// token, not the small label token.
const WidgetLabel = ({ children }) => (
  <p className="t-subsection mb-2">{children}</p>
);

const IncidentDashboard = ({
  gameMode, onSelectIncident, onNavigate, isVisible = true,
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
  // VB1: the Evidence activity FROZEN snapshot for the focus incident,
  // read through the existing single query path under the incident's
  // scope. Fetched once per incident; later evidence is announced by the
  // token-bound new-count and only enters on an explicit Load.
  const [evidence, setEvidence] = useState({ forId: null, snapshot: null, loading: false });
  const [evidenceNew, setEvidenceNew] = useState(0);
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

  // VB1: one frozen evidence read per focus incident (never a poll, so
  // the snapshot cannot move on its own).
  const loadEvidence = useCallback((id) => {
    if (!id) return;
    setEvidence({ forId: id, snapshot: null, loading: true });
    setEvidenceNew(0);
    apiFetch(`/api/events/query?q=${encodeURIComponent(descentSessionAll())}&scope=${encodeURIComponent(id)}`)
      .then(r => (r.ok ? r.json() : null))
      .then(body => setEvidence(body
        ? { forId: id, snapshot: body, loading: false }
        : { forId: id, snapshot: null, loading: false }))
      .catch(() => setEvidence({ forId: id, snapshot: null, loading: false }));
  }, []);

  // The read waits for the roster seal (the incident's chain has finished
  // writing). Before that the card shows the existing telemetry-loading
  // state rather than a false zero-event chart, and a single read after
  // the seal cannot land on a half-written chain.
  const focusSealed = !!focus?.sealed;
  useEffect(() => {
    if (!focusId) { setEvidence({ forId: null, snapshot: null, loading: false }); setEvidenceNew(0); return; }
    if (!focusSealed) { setEvidence({ forId: focusId, snapshot: null, loading: true }); return; }
    if (evidence.forId !== focusId || !evidence.snapshot) loadEvidence(focusId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusId, focusSealed]);

  // token-bound waiting count: counts only, never rows, never a mutation
  const evidenceToken = evidence.snapshot?.token || null;
  useEffect(() => {
    if (!evidenceToken) return undefined;
    let cancelled = false;
    const tick = () => {
      apiFetch(`/api/events/query/new-count?token=${encodeURIComponent(evidenceToken)}`)
        .then(r => (r.ok ? r.json() : null))
        .then(d => { if (!cancelled && d) setEvidenceNew(d.new_count || 0); })
        .catch(() => {});
    };
    tick();
    const iv = setInterval(tick, 3000);
    return () => { cancelled = true; clearInterval(iv); };
  }, [evidenceToken]);

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

  // VA3: the incident ATT&CK profile inputs -- the mitre mappings of the
  // focus incident's roster detections. Already-visible data (every
  // detection detail renders its tag in every mode); never the answer key.
  const profileMappings = scopedIds
    ? feed.filter(d => scopedIds.has(d.id) && d.mitre && d.mitre.id)
        .map(d => ({ id: d.mitre.id, tactic: d.mitre.tactic, name: d.mitre.name }))
    : [];

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
      {/* VH (owner correction): the full-width session banner is retired.
          Session performance is a dashboard metric (KPI tile); the mode
          rides the Active investigation card as a compact badge; the
          queue count is a compact line there too; Reset lives in the
          AppHeader avatar menu. */}
      {/* VB1 (amendment section 1): ONE grid whose DOM order IS the ruled
          narrow stack (Active investigation, KPI, Evidence activity,
          Severity, Environment, ATT&CK profile, Recent results) and whose
          desktop placement is explicit -- supporting column on the left,
          Evidence activity as the large centre visualization, the ATT&CK
          profile as the smaller near-square card on its right (tops
          aligned), Recent results across the wider centre region. Screen
          reader order and visual order agree at every width. */}
      <div className="grid grid-cols-1 xl:grid-cols-[19rem_minmax(0,1fr)_minmax(280px,30%)] gap-4 items-stretch">
          {/* A. Active Investigation (observable fields only; Resume navigates) */}
          <div className="rounded-xl p-4 xl:col-start-1 xl:row-start-2" style={CARD_STYLE} data-testid="active-investigation">
            <WidgetLabel>Active investigation</WidgetLabel>
            {!focus ? (
              <p className="text-sm text-[#8b949e]">No active investigations.</p>
            ) : (
              <div className="space-y-2">
                {/* VD2 (visual correction section 2): the wrapping metadata
                    row of shared badges -- [INC id] [Severity] [Mode] --
                    wraps cleanly, the card grows naturally, nothing clips
                    or compresses to force one line. */}
                <div className="flex items-center gap-1.5 flex-wrap">
                  <IncidentIdPill id={focus.incident_id} />
                  <SeverityBadge severity={focus.severity} />
                  <ModeBadge mode={gameMode} />
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
                  {/* VH: the queue count is one compact line, never a
                      full-width banner (Guided has no queue). */}
                  {!isGuided && queueLength > 0 && (
                    <p className="text-[#8b949e]">{data.resolved_count} of {queueLength} resolved</p>
                  )}
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
                          <SeverityBadge severity={c.severity} />
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

          {/* C. KPI stat tiles (moved into the one grid): real session
              observables only -- no trends, deltas, or sparklines. */}
          <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-3 xl:col-start-1 xl:col-span-3 xl:row-start-1" data-testid="kpi-row">
            <Metric label="Detections reviewed" value={(detCounts.promoted ?? 0) + (detCounts.dismissed ?? 0)} />
            <Metric label="Response actions executed" value={actionSuccesses} />
            <Metric label="Incidents completed" value={data.completed.length} />
            <Metric
              label="Latest incident grade"
              value={latest?.incident_grade?.grade || '-'}
              accent={latest ? gradeColor(latest.incident_grade?.grade) : undefined}
              sub={latest ? gradeAccuracy(latest.incident_grade) : 'No submissions yet'}
            />
            {/* VH: Session performance is a dashboard metric, distinct
                from the per-incident grade. */}
            <Metric
              label={SESSION_PERFORMANCE_LABEL}
              value={sessionGrade?.grade || '-'}
              accent={sessionGrade ? gradeColor(sessionGrade.grade) : undefined}
              sub={sessionGrade?.accuracy != null ? `${sessionGrade.accuracy}%` : 'Across submitted incidents'}
            />
          </div>

          {/* B. Evidence activity -- the PRIMARY visualization, centre.
              Stretches to the row height so the chart fills its card
              instead of floating in whitespace beside the radar. */}
          <div className="xl:col-start-2 xl:row-start-2 min-w-0 h-full">
            <EvidenceActivity
              incidentId={focusId}
              snapshot={evidence.forId === focusId ? evidence.snapshot : null}
              loading={evidence.forId === focusId && evidence.loading}
              newCount={evidenceNew}
              onLoadNewEvents={() => loadEvidence(focusId)}
            />
          </div>

          {/* Severity distribution (VS owner correction): compact
              horizontal bars over the ACTIVE incident's observable
              detections -- exact counts, bars scaled to the largest
              displayed count (no percentage implied), label + count text
              beside every bar (never color alone). */}
          <div className="rounded-xl p-4 xl:col-start-1 xl:row-start-3" style={CARD_STYLE} data-testid="severity-distribution">
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
          <div className="rounded-xl p-4 xl:col-start-1 xl:row-start-4" style={CARD_STYLE} data-testid="environment-status">
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

          {/* D. The incident ATT&CK profile (VA3): the smaller near-square
              SECONDARY card on the right, top-aligned with Evidence
              activity. Never the dashboard centrepiece. */}
          <div className="xl:col-start-3 xl:row-start-2 min-w-0">
            <AttackRadar
              isVisible={isVisible}
              incidentId={focusId}
              mappings={profileMappings}
            />
          </div>

          {/* E. Recent results -- submitted incidents this session, newest
              first; grades/categories are the frozen post-submission
              record. Rows navigate to the incident. */}
          <div className="rounded-xl min-w-0 xl:col-start-2 xl:col-span-2 xl:row-start-3 xl:row-span-2" style={CARD_STYLE} data-testid="recent-results">
            <div className="px-4 pt-4 pb-2 flex items-baseline gap-2">
              <p className="t-subsection">Recent results</p>
              <span className="text-xs text-[#6e7781]">&middot; This session</span>
            </div>
            {completedSorted.length === 0 ? (
              <p className="px-4 pb-4 text-sm text-[#8b949e]">No incidents submitted yet this session. Results appear here when you submit an incident.</p>
            ) : (
              <div className="overflow-x-auto pb-1">
                <table className="w-full text-left text-sm">
                  <thead className="data-thead">
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
  );
};

export default IncidentDashboard;
