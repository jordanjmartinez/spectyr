import React, { useState, useEffect, useCallback, useRef } from 'react';
import { apiFetch } from '../api';
import {
  toReview, SUBMIT_PENDING, MODE_LABEL,
  detectionsReviewed, SESSION_PERFORMANCE_LABEL,
} from './uiCopy';
import { submissionReady } from './submissionReady';
import {
  severityDot, gradeColor, CARD_STYLE, IncidentIdBadge, SeverityBadge,
  IncidentIdentityRow, BarList, BarRow,
} from './ui';
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
// beside the main region (KPI stat tiles, Evidence Activity, Recent
// results). Narrow screens stack: band, Active Investigation, Progress,
// Severity, Environment, then the main region -- the supporting column
// completes before the main region begins.
//
// DATA TRUTH (V11): every value is an existing observable or a
// post-submission disclosure. The per-incident grades/categories come
// from each SUBMITTED incident's served score view (fetched once per
// submitted id); active incidents contribute a count only. No trends,
// deltas, or sparklines exist because no historical series exists.
// Nothing here reveals pre-submission correctness.
// ============================================================================

const Metric = ({ label, value, accent, sub }) => (
  <div className="rounded-xl p-4" style={CARD_STYLE}>
    <p className="t-kpi" style={accent ? { color: accent } : undefined}>{value}</p>
    <p className="t-meta text-muted mt-0.5">{label}</p>
    {sub && <p className="text-[11px] text-muted mt-0.5">{sub}</p>}
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
  // Post-submission records: incident_id -> {grading}. Fetched ONCE per
  // submitted id (score view); never requested for active incidents (the
  // temporal rule).
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
      apiFetch(`/api/incidents/${id}/score`).then(r => (r.ok ? r.json() : null)).catch(() => null)
        .then(score => {
          if (score?.state === 'submitted') {
            setRecords(prev => ({ ...prev, [id]: { grading: score.grading } }));
          } else {
            fetchedRef.current.delete(id);   // not served yet; retry on a later poll
          }
        });
    });
  }, [completedKey]);

  const sessionGrade = session?.state === 'submitted' ? session.grading?.composite : null;
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


  // Environment status (VS owner correction): current observable state
  // only -- no uptime claims, no history. Owner UI pass (2026-10-12): the
  // availability percentage and the platform breakdown are retired with
  // the lines that rendered them; the endpoint page owns the breakdown.
  const managed = (env || []).length;

  const readinessChip = (c) => (!c.sealed ? 'Loading'
    : submissionReady(c, chosen) ? 'Ready'
      : c.ready ? SUBMIT_PENDING
        : toReview(c.open_detections));

  // Latest submitted incident (KPI tile + newest-first results ordering).
  const completedSorted = [...(data.completed || [])]
    .sort((a, b) => String(b.submitted_at || '').localeCompare(String(a.submitted_at || '')));
  const latest = completedSorted[0] || null;

  const triage = focus?.triage || { total: 0, triaged: 0 };

  return (
    <div className="space-y-4">
      {/* VH (owner correction): the full-width session banner is retired.
          Session performance is a dashboard metric (KPI tile); the mode
          rides the Active investigation card as a compact badge; the
          queue count is a compact line there too; Reset lives in the
          AppHeader avatar menu. */}
      {/* VB1 (amendment section 1): ONE grid whose DOM order IS the ruled
          narrow stack (Active investigation, KPI, Evidence activity,
          Severity, Environment, Recent results) and whose desktop
          placement is explicit -- supporting column on the left, Evidence
          activity beside the Active Investigation (equal-height row),
          Recent results across the right region beneath. Screen reader
          order and visual order agree at every width.
          Owner layout pass (2026-10-12): the Session ATT&CK Coverage card
          is REMOVED entirely.
          Owner layout pass 4 (same day, superseding pass 3's column
          widths): THREE EQUAL columns on the working row --
          [Active Investigation | Recent Results | Evidence Activity],
          same card size. Active and Evidence share the row-2 height
          (Evidence is h-full, so it never resizes with its own content);
          Recent Results is the ONE card that stretches, spanning down
          beside Severity/Environment. At xl the visual column order
          differs from DOM order for Evidence vs Recent; the ruled NARROW
          stack (Active, KPI, Evidence, Severity, Environment, Recent) is
          unchanged. */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 items-stretch">
          {/* A. Active Investigation (observable fields only; Resume navigates) */}
          <div className="rounded-xl p-4 xl:col-start-1 xl:row-start-2" style={CARD_STYLE} data-testid="active-investigation">
            {/* Owner layout pass (2026-10-12): the mode pill is retired --
                the mode rides the TITLE ROW as plain muted text, styled
                like the Evidence Activity events-observed count. */}
            <div className="flex items-baseline justify-between gap-3 mb-2">
              <p className="t-subsection">Active Investigation</p>
              <span className="text-sm text-muted shrink-0">{MODE_LABEL[gameMode] || gameMode}</span>
            </div>
            {!focus ? (
              <p className="text-sm text-muted">No active investigations.</p>
            ) : (
              <div className="space-y-2">
                {/* Owner card pass (2026-10-12, inline follow-up): the ONE
                    canonical identity composition, same as the Incidents
                    detail header -- [INC id] [Severity] then the title
                    INLINE on the same wrapping row (no mode pill; the mode
                    is plain text on the card title row). The progress bar
                    sits under it. */}
                <IncidentIdentityRow
                  incidentId={focus.incident_id}
                  severity={focus.severity}
                  title={focus.title}
                  titleClass="text-sm font-medium text-[#1a2332]"
                />
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
                {/* Owner layout pass 2 (2026-10-12): the stage line is
                    removed entirely; in its place the View incidents link
                    (bottom-right, same treatment as View endpoints). The
                    Resume button and the other detail lines stay removed
                    (the Incidents workspace owns the work itself). */}
                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={() => onNavigate?.('incidents')}
                    className="text-xs font-medium text-[#16436b] hover:underline"
                  >
                    View incidents
                  </button>
                </div>
                {otherActive.length > 0 && (
                  <div className="pt-2 border-t border-[#eef1f4] space-y-1">
                    {otherActive.map(c => (
                      <button key={c.incident_id} onClick={() => openInIncidents(c.incident_id)}
                        className="w-full text-left flex items-center justify-between gap-2 text-xs hover:bg-[#f6f8fa] rounded px-1 py-1">
                        <span className="min-w-0 flex items-center gap-1.5">
                          <IncidentIdBadge id={c.incident_id} />
                          <SeverityBadge severity={c.severity} />
                          <span className="text-muted truncate">{c.title}</span>
                        </span>
                        <span className="text-muted shrink-0">{readinessChip(c)}</span>
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
            <Metric label="Detections Reviewed" value={(detCounts.promoted ?? 0) + (detCounts.dismissed ?? 0)} />
            <Metric label="Response Actions" value={actionSuccesses} />
            <Metric label="Incidents Completed" value={data.completed.length} />
            {/* Owner UI pass (2026-10-12): the grade tiles drop their sub
                lines -- title + value only, uniform with the other KPI
                tiles; accuracy detail lives in Metrics. */}
            <Metric
              label="Latest Incident Grade"
              value={latest?.incident_grade?.grade || '-'}
              accent={latest ? gradeColor(latest.incident_grade?.grade) : undefined}
            />
            {/* VH: Session performance is a dashboard metric, distinct
                from the per-incident grade. */}
            <Metric
              label={SESSION_PERFORMANCE_LABEL}
              value={sessionGrade?.grade || '-'}
              accent={sessionGrade ? gradeColor(sessionGrade.grade) : undefined}
            />
          </div>

          {/* B. Evidence activity -- third card of the side-by-side
              working row (owner layout pass 4, 2026-10-12): SAME card
              size as Active Investigation -- h-full to the shared row
              height, never resizing with its own content. */}
          <div className="xl:col-start-3 xl:row-start-2 min-w-0 h-full">
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
            {/* Owner UI pass (2026-10-12): title + content only, no card
                subtitle (matching Environment status). */}
            <WidgetLabel>Severity Distribution</WidgetLabel>
            {sevMax === 0 ? (
              <p className="text-sm text-muted">No detections observed yet.</p>
            ) : (
              /* owner unification (2026-10-12): the shared BarRow anatomy,
                 severity keeping its color scale as the fill */
              <BarList>
                {sevRows.map(r => (
                  <BarRow key={r.key} label={r.label} count={r.count} max={sevMax}
                    fill={severityDot(r.key)} labelWidth="w-16" />
                ))}
              </BarList>
            )}
          </div>

          {/* Environment status (VS owner correction): current observable
              state only -- no gauges, no history, no uptime claims. */}
          <div className="rounded-xl p-4 xl:col-start-1 xl:row-start-4" style={CARD_STYLE} data-testid="environment-status">
            <WidgetLabel>Environment Status</WidgetLabel>
            {managed === 0 ? (
              <p className="text-sm text-muted">No managed hosts available.</p>
            ) : (
              /* Owner UI pass (2026-10-12): ONE state-first line. The four
                 restatements of the same fact (managed count,
                 Online/Offline pair, Availability bar + percent, and the
                 platform breakdown) collapse to a status dot plus
                 "N/M Hosts Online"; the dot carries the state, the numbers
                 carry the detail, and the endpoint page owns the
                 breakdown. */
              <div className="space-y-2">
                <p className="text-sm flex items-center gap-2">
                  <span
                    aria-hidden="true"
                    className="w-2 h-2 rounded-full shrink-0"
                    style={{ background: offline === 0 ? '#6fa868' : '#c08a3e' }}
                  />
                  <span className="font-medium text-[#1a2332]">{online}/{managed} Hosts Online</span>
                </p>
                {/* Owner layout pass 2 (2026-10-12): bottom-right */}
                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={() => onNavigate?.('endpoints')}
                    className="text-xs font-medium text-[#16436b] hover:underline"
                  >
                    View endpoints
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* E. Recent results -- submitted incidents this session, newest
              first; grades/categories are the frozen post-submission
              record. Rows navigate to the incident. */}
          <div className="rounded-xl min-w-0 xl:col-start-2 xl:row-start-2 xl:row-span-3" style={CARD_STYLE} data-testid="recent-results">
            {/* Owner UI pass (2026-10-12): title + content only, no card
                subtitle (matching Environment status). */}
            <div className="px-4 pt-4 pb-2">
              <p className="t-subsection">Recent Results</p>
            </div>
            {completedSorted.length === 0 ? (
              <p className="px-4 pb-4 text-sm text-muted">No incidents submitted yet this session. Results appear here when you submit an incident.</p>
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
                              className="hover:opacity-75" title={`Open ${c.incident_id}`}>
                              <IncidentIdBadge id={c.incident_id} />
                            </button>
                            <span className="block text-xs text-muted truncate max-w-[14rem] mt-0.5" title={c.title}>{c.title}</span>
                          </td>
                          <td className="px-3 py-2 whitespace-nowrap text-muted">{g?.classification?.category ?? '-'}</td>
                          <td className="px-3 py-2 whitespace-nowrap text-muted">{MODE_LABEL[gameMode] || gameMode}</td>
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
