import React, { useState, useEffect, useCallback, useRef } from 'react';
import { apiFetch } from '../api';
import ClassificationSelector from './ClassificationSelector';
import CategorySelector from './CategorySelector';
import {
  TELEMETRY_LOADING, detectionsReviewed, detectionsRemaining,
  responseActionsTaken, READY_TO_SUBMIT, toReview, completedStrip,
  SUBMITTED_GRADE_LOCKED, CLASSIFICATION_NOT_SELECTED,
  classificationSelected, CONSIDER_PROMPT, SUBMIT_PENDING,
  caseClosed, REVIEW_WHAT_YOU_LEARNED, CLASSIFY_TO_SUBMIT,
} from './uiCopy';
import { submissionReady, validClassification } from './submissionReady';
import { toastReady } from './uiToasts';
import { deriveAchievements } from './achievements';

// Stage 3.9B: the Incidents operational workspace ("what do I need to work?").
// Search + Active / Ready / Completed views, stable incident rows, and a
// selected-incident detail (briefing, scoped detection progress, related hosts
// and accounts, Related response activity) with the SINGLE home for the graded
// Submit / Resume / Review controls (D2/D7). This retires the legacy Alerts
// ticket table and the global Notable Events queue (D3/D4): the player-facing
// object is the incident. Raw underlying events stay in SIEM (D4, unchanged).

const SEV_DOT = { Critical: '#b45858', High: '#c08a3e', Medium: '#c0a93e', Low: '#6fa868' };
const gradeColor = (g) => (!g || g === '-') ? '#8b949e' : g === 'F' ? '#b45858' : g === 'D' ? '#c08a3e' : '#6fa868';
const CARD = { background: '#fff', border: '1px solid #e2e6ea', boxShadow: '0 1px 2px rgba(0,0,0,0.04)' };
const fmtTime = (iso) => { try { return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); } catch { return ''; } };

// The incident-progress checklist (Phase 2 commit 2.4, A1-B.3.2): the phase
// strip EVOLVED -- one progress surface, never a second parallel one. Lines
// are observable-only: seal state, roster triage counts, the player's own
// local classification choice, the D4 action count, readiness. LEAK RULE
// (binding, 19.18): the line set, order, and copy are constants, identical
// for every incident regardless of the answer key; only observable numbers
// and the player's own selection vary. The consider-prompt is the ONE static
// prompt, byte-identical for every incident, rendered in Guided only
// (ruled B-OD-5); it never carries a target count.
export const PhaseStrip = ({ sealed, triage, related, ready, classification,
                             showPrompt }) => {
  if (!sealed) return <p className="text-xs text-[#8b949e] italic">{TELEMETRY_LOADING}</p>;
  const t = triage || { total: 0, triaged: 0 };
  const lines = [
    ['triage', detectionsReviewed(t.triaged, t.total),
     t.total > 0 && t.triaged === t.total],
    ['classification',
     classification ? classificationSelected(classification) : CLASSIFICATION_NOT_SELECTED,
     !!classification],
    ['response', responseActionsTaken(related ?? 0), null],
    ['ready', ready ? READY_TO_SUBMIT : SUBMIT_PENDING, !!ready],
  ];
  return (
    <div className="space-y-0.5 text-[11px]" data-testid="incident-checklist">
      {lines.map(([key, text, done]) => (
        <div key={key} className="flex items-center gap-1.5">
          <span aria-hidden="true"
            className={`w-1.5 h-1.5 rounded-full shrink-0 ${done === null ? 'bg-[#d0d7de]' : done ? 'bg-[#6fa868]' : 'border border-[#8b949e]'}`} />
          <span className={done ? 'text-[#57606a]' : 'text-[#57606a]'}>{text}</span>
          {key === 'response' && showPrompt && (
            <span className="text-[#8b949e]">{CONSIDER_PROMPT}</span>
          )}
        </div>
      ))}
    </div>
  );
};

const Incidents = ({
  isVisible, resetTrigger, onHardcoreFailure, onReset, gameMode = 'training',
  activeIncidentId, onSelectIncident, onNavigate, setGroupedAlertCount, onPracticeAnother,
  onEvidenceDescent, onOpenLearningReview,
  // A3.4 (ratified A3-OD-3): the classification selection state is
  // SHELL-OWNED (Dashboard) so every Ready surface derives from the one
  // state; this component receives it and its setter.
  chosen = {}, setChosen,
}) => {
  const [data, setData] = useState({ active: [], completed: [], queue_length: 0, resolved_count: 0 });
  const [view, setView] = useState('active');    // 'active' | 'ready' | 'completed'
  const [search, setSearch] = useState('');
  const [scope, setScope] = useState(null);       // selected incident /scope

  const [pendingSubmit, setPendingSubmit] = useState(null);  // {..., action: 'submit'}
  useEffect(() => { prevReadyRef.current = {}; }, [resetTrigger]);
  const verdictOptionId = (v) =>
    v === 'threat' ? 'true_positive' : v === 'false_positive' ? 'false_positive' : null;
  // Workspace classification handlers: local input only, no request; a
  // threat verdict completes when its category is picked.
  const setWorkspaceVerdict = (incidentId, id) => {
    setChosen?.(c => {
      const prev = c[incidentId] || {};
      if (id === 'false_positive') {
        return { ...c, [incidentId]: { verdict: 'false_positive', category: 'False Positive', categoryId: null } };
      }
      const keep = prev.verdict === 'threat';
      return { ...c, [incidentId]: { verdict: 'threat',
        category: keep ? prev.category || null : null,
        categoryId: keep ? prev.categoryId || null : null } };
    });
  };
  const setWorkspaceCategory = (incidentId, cid, clabel) => {
    setChosen?.(c => ({ ...c, [incidentId]: { verdict: 'threat', category: clabel, categoryId: cid } }));
  };
  const [submitBusy, setSubmitBusy] = useState(false);
  const [checkResult, setCheckResult] = useState(null);      // Guided Check Answer feedback
  const [checkBusy, setCheckBusy] = useState(false);
  const [practiceWarn, setPracticeWarn] = useState(false);   // Practice Another reset warning
  const [notice, setNotice] = useState('');
  const [review, setReview] = useState(null);     // {incidentId, title, grading, assisted, triage}
  const noticeTimer = useRef(null);

  const selectedId = activeIncidentId;
  const isGuided = gameMode === 'guided' || gameMode === 'training';
  const flash = (m) => { setNotice(m); if (noticeTimer.current) clearTimeout(noticeTimer.current); noticeTimer.current = setTimeout(() => setNotice(''), 4500); };

  // T4/T5 milestone watcher (2.4): readiness and triage-complete coincide
  // by construction (readiness == full triage on a sealed roster), so the
  // ONE milestone toast fires on the observable false -> true transition.
  // First sight of an already-ready card never toasts (no transition seen).
  const prevReadyRef = useRef({});
  const fetchList = useCallback(() => {
    apiFetch('/api/incidents').then(r => r.json()).then(d => {
      const next = {};
      for (const c of d.active || []) {
        if (c.state === 'in_progress' && c.sealed) {
          next[c.incident_id] = !!c.ready;
          if (c.ready && prevReadyRef.current[c.incident_id] === false) {
            toastReady(c.incident_id);
          }
        }
      }
      prevReadyRef.current = next;
      setData(d);
      setGroupedAlertCount?.((d.active || []).length);
    }).catch(() => {});
  }, [setGroupedAlertCount]);

  useEffect(() => { fetchList(); const iv = setInterval(fetchList, 3000); return () => clearInterval(iv); }, [fetchList]);

  // Selected incident scope (Related hosts/accounts + descent inputs). The
  // fuzzy related-activity label join is DELETED (scaffold ruling A): the
  // honest count is the server's D4 related_actions card field.
  const fetchScope = useCallback(() => {
    if (!selectedId) { setScope(null); return; }
    apiFetch(`/api/incidents/${selectedId}/scope`).then(r => r.json())
      .then(setScope).catch(() => {});
  }, [selectedId]);

  useEffect(() => { fetchScope(); const iv = setInterval(fetchScope, 3000); return () => clearInterval(iv); }, [fetchScope]);

  // 2.3 completed strip (contract 10.4, scaffold decision D3): the total is
  // the score view's frozen detection.total -- frontend-only source, no
  // completed-card field added. Fetched once per selected submitted
  // incident; 5.4 keeps the WHOLE served view so the completed pane can
  // render the Case Closed summary (grade + achievements) inline.
  const [stripInfo, setStripInfo] = useState(null);   // {id, total, view}
  const selectedState = (data.active.concat(data.completed)
    .find(c => c.incident_id === selectedId) || {}).state;
  useEffect(() => {
    if (!selectedId || selectedState !== 'submitted') { setStripInfo(null); return; }
    let cancelled = false;
    apiFetch(`/api/incidents/${selectedId}/score`).then(r => r.json()).then(v => {
      if (!cancelled && v?.state === 'submitted') {
        setStripInfo({ id: selectedId, total: v.grading?.detection?.total ?? 0, view: v });
      }
    }).catch(() => {});
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId, selectedState]);

  const all = [...data.active.map(c => ({ ...c })), ...data.completed.map(c => ({ ...c }))];
  const q = search.trim().toLowerCase();
  // A3.4: the Ready view means submission-ready (the ONE derivation).
  const byView = (c) => view === 'completed' ? c.state === 'submitted'
    : view === 'ready' ? (c.state === 'in_progress' && submissionReady(c, chosen))
    : c.state === 'in_progress';
  const rows = all.filter(c => byView(c) && (!q || (c.title || '').toLowerCase().includes(q) || (c.incident_id || '').toLowerCase().includes(q)));
  const selected = all.find(c => c.incident_id === selectedId) || null;

  const counts = {
    active: data.active.length,
    ready: data.active.filter(c => c.state === 'in_progress' && submissionReady(c, chosen)).length,
    completed: data.completed.length,
  };

  // A3.4 (F4b): Submit is FINAL submission -- the classification comes
  // from the workspace selection (never a data-entry step); the click
  // opens the bare confirmation only. The server gate stays the
  // authoritative backstop behind this client gate.
  const beginSubmit = () => {
    if (!selected || selected.state !== 'in_progress') return;
    if (!selected.sealed) { flash(TELEMETRY_LOADING); return; }
    if (!selected.ready) { flash(detectionsRemaining(selected.open_detections ?? 0)); return; }
    const sel = chosen[selected.incident_id];
    if (!validClassification(sel)) { flash(CLASSIFY_TO_SUBMIT); return; }
    setPendingSubmit({ incident_id: selected.incident_id, title: selected.title,
      action: 'submit', verdict: sel.verdict, category: sel.category });
  };

  // Check Answer (Guided only; ratified A3-OD-2): consumes the WORKSPACE
  // classification selection (disabled until one is valid) and reveals
  // ONLY whether it is correct, without submitting; permanently marks the
  // incident Assisted. Never reveals detection, response, or composite
  // grading (server-enforced).
  const beginCheck = () => {
    if (!isGuided || !selected || selected.state !== 'in_progress' || !selected.sealed) return;
    const sel = chosen[selected.incident_id];
    if (!validClassification(sel)) return;
    doCheck({ incident_id: selected.incident_id, title: selected.title,
      action: 'check', verdict: sel.verdict, category: sel.category });
  };

  const doCheck = async (p) => {
    setCheckBusy(true);
    try {
      const res = await apiFetch(`/api/incidents/${p.incident_id}/check-answer`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ verdict: p.verdict, category: p.category }),
      });
      const b = await res.json().catch(() => ({}));
      setPendingSubmit(null);
      // check-answer nests correctness under `classification` (never top-level).
      if (res.ok) { setCheckResult({ correct: !!(b.classification && b.classification.correct) }); fetchList(); }
      else { flash(b.error || 'Check Answer is available in Guided mode only.'); }
    } catch { flash('Could not check the answer.'); }
    finally { setCheckBusy(false); }
  };

  const doSubmit = async () => {
    if (!pendingSubmit) return;
    setSubmitBusy(true);
    try {
      const res = await apiFetch(`/api/incidents/${pendingSubmit.incident_id}/submit`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ verdict: pendingSubmit.verdict, category: pendingSubmit.category }),
      });
      if (!res.ok) {
        const b = await res.json().catch(() => ({}));
        setPendingSubmit(null);
        flash(b.reason === 'sealing' ? 'Incident telemetry is still loading.' : (b.error || 'This incident could not be submitted yet.'));
        return;
      }
      const viewRes = await res.json();
      const inc = pendingSubmit.incident_id;
      setPendingSubmit(null);
      if (viewRes.hardcore_failure) { onHardcoreFailure?.(pendingSubmit.category); fetchList(); return; }
      fetchList();
      if (viewRes.state === 'submitted') openReview(inc);
    } catch { flash('This incident could not be submitted yet.'); }
    finally { setSubmitBusy(false); }
  };

  // The Case Closed moment (5.4, A1-B.4.1): submit success opens ONE static
  // summary naming the incident, with the earned achievements and the
  // Incident Grade. Teaching content lives ONLY in the Metrics Learning
  // Review (B-OD-1 Option 1, one venue): this modal never renders it.
  const openReview = async (incidentId) => {
    const scoreView = await apiFetch(`/api/incidents/${incidentId}/score`).then(r => r.json()).catch(() => null);
    if (scoreView?.state !== 'submitted') return;
    const card = all.find(c => c.incident_id === incidentId);
    setReview({ incidentId, title: card?.title, grading: scoreView.grading, assisted: scoreView.assisted, view: scoreView });
  };

  return (
    <div>
      {/* Header + search */}
      <div className="rounded-xl overflow-hidden mb-4" style={CARD}>
        <div className="h-0.5" style={{ background: 'linear-gradient(to right, #16436b, #101218)' }} />
        <div className="p-4 sm:p-5">
          <div className="flex items-center gap-2 mb-3">
            <h2 className="text-xl sm:text-2xl font-semibold text-[#1a2332]">Incidents</h2>
            <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-[#eef1f4] text-[#57606a]">{rows.length}</span>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <div className="inline-flex rounded-md border border-[#d0d7de] overflow-hidden" role="group" aria-label="Incident view">
              {[['active', `Active ${counts.active}`], ['ready', `Ready ${counts.ready}`], ['completed', `Completed ${counts.completed}`]].map(([k, label]) => (
                <button key={k} type="button" onClick={() => setView(k)}
                  className={`px-3 py-1.5 text-xs font-medium transition ${view === k ? 'bg-[#101218] text-white' : 'bg-white text-[#57606a] hover:bg-[#eef1f4]'}`}>{label}</button>
              ))}
            </div>
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search incidents..."
              className="flex-1 min-w-[180px] px-3 py-1.5 text-sm rounded-md border border-[#d0d7de] text-[#1a2332] placeholder-[#8b949e] focus:outline-none focus:ring-2 focus:ring-[#101218]/20" />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        {/* Incident rows (stable) */}
        <div className="lg:col-span-2 rounded-xl divide-y divide-[#eef1f4]" style={CARD}>
          {rows.length === 0 ? (
            <p className="p-4 text-sm text-[#8b949e] text-center">No incidents in this view.</p>
          ) : rows.map(c => (
            <button key={c.incident_id} onClick={() => onSelectIncident?.(c.incident_id)}
              className={`w-full text-left p-3 flex items-center justify-between gap-2 ${c.incident_id === selectedId ? 'bg-[#16436b]/5' : 'hover:bg-[#f6f8fa]'}`}>
              <span className="min-w-0 flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: SEV_DOT[c.severity] || '#8b949e' }} />
                <span className="log-mono text-[#16436b] text-xs shrink-0">{c.incident_id}</span>
                <span className="text-sm text-[#1a2332] truncate">{c.title}</span>
              </span>
              <span className="text-[11px] shrink-0 whitespace-nowrap" style={{ color: c.state === 'submitted' ? gradeColor(c.incident_grade?.grade) : '#8b949e' }}>
                {c.state === 'submitted' ? (c.incident_grade?.grade || '-')
                  : !c.sealed ? 'Loading'
                  : submissionReady(c, chosen) ? 'Ready'
                  : c.ready ? SUBMIT_PENDING
                  : toReview(c.open_detections)}
              </span>
            </button>
          ))}
        </div>

        {/* Selected incident detail (the workspace) */}
        <div className="lg:col-span-3 rounded-xl p-4 sm:p-5" style={CARD}>
          {!selected ? (
            <p className="text-sm text-[#8b949e] text-center py-8">Select an incident to work it.</p>
          ) : (
            <div className="space-y-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="log-mono text-[#16436b] text-xs">{selected.incident_id}</span>
                    <span className="w-1.5 h-1.5 rounded-full" style={{ background: SEV_DOT[selected.severity] || '#8b949e' }} />
                    <span className="text-[11px] text-[#8b949e]">{selected.severity}</span>
                    <span className="text-base font-semibold text-[#1a2332]">{selected.title}</span>
                    {selected.state === 'submitted' && selected.assisted && (
                      <span className="text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-[#eef1f4] text-[#57606a] border border-[#d0d7de]">Assisted</span>
                    )}
                  </div>
                  {selected.briefing && <p className="mt-1 text-sm text-[#57606a] break-words">{selected.briefing}</p>}
                </div>
                {/* The ONE explicit case exit (Amendment 1 Delta A): the case
                    changes only by selection in the list or this control.
                    Presentation only; deselecting mutates nothing. */}
                <button
                  type="button"
                  onClick={() => onSelectIncident?.(null)}
                  aria-label="Clear selected incident"
                  className="shrink-0 text-xs px-2 py-1 rounded-md border border-[#d0d7de] text-[#57606a] hover:bg-[#eef1f4]"
                >
                  Clear selection
                </button>
              </div>

              <div className="pt-2 border-t border-[#eef1f4]">
                {/* 2.3: the active strip renders ONLY for in_progress; a
                    submitted incident renders the completed vocabulary --
                    the 0-of-0 contradiction is structurally impossible. */}
                {selected.state === 'submitted' ? (
                  <p className="text-xs text-[#57606a]">
                    {stripInfo?.id === selected.incident_id
                      ? completedStrip(stripInfo.total)
                      : SUBMITTED_GRADE_LOCKED}
                  </p>
                ) : (
                  <PhaseStrip sealed={selected.sealed}
                    triage={selected.triage} related={selected.related_actions}
                    ready={submissionReady(selected, chosen)}
                    classification={chosen[selected.incident_id]?.category || null}
                    showPrompt={gameMode === 'guided'} />
                )}
              </div>

              {/* C1 checkpoint fix (F4a): the ratified A1-B.3.2 workspace
                  selector -- the checklist Classification line's specified
                  local-input source. Purely local state, no request; the
                  submit modal flow is unchanged and arrives pre-filled from
                  this choice. Identical for every incident (leak rule). */}
              {selected.state !== 'submitted' && selected.sealed && (
                <div className="pt-3 border-t border-[#eef1f4] space-y-2" data-testid="workspace-classification">
                  <p className="text-[11px] uppercase tracking-wider text-[#6e7781] font-medium">Classification</p>
                  <ClassificationSelector
                    selected={verdictOptionId(chosen[selected.incident_id]?.verdict)}
                    onSelect={(id) => setWorkspaceVerdict(selected.incident_id, id)} />
                  {chosen[selected.incident_id]?.verdict === 'threat' && (
                    <CategorySelector
                      selected={chosen[selected.incident_id]?.categoryId || null}
                      onSelect={(cid, clabel) => setWorkspaceCategory(selected.incident_id, cid, clabel)} />
                  )}
                </div>
              )}

              {/* Related hosts / accounts (observable scope) */}
              {scope && (scope.hosts?.length || scope.accounts?.length) ? (
                <div className="text-xs text-[#57606a] space-y-1">
                  {scope.hosts?.length ? <p><span className="text-[#8b949e]">Related hosts:</span> {scope.hosts.join(', ')}</p> : null}
                  {scope.accounts?.length ? <p><span className="text-[#8b949e]">Related accounts:</span> {scope.accounts.join(', ')}</p> : null}
                </div>
              ) : null}

              {/* P7.2 Open Evidence Timeline (contract Section 13 naming
                  ruling; Section 16 descent-sets-scope). Supplies ONLY the
                  observable participant scope; the SIEM shell generates the
                  query. Evidence stays reviewable after submission. */}
              {scope && scope.incident_id === selected.incident_id && onEvidenceDescent && (
                <div>
                  <button
                    type="button"
                    onClick={() => onEvidenceDescent({
                      origin: selected.incident_id,
                      hosts: scope.hosts || [],
                      account: null,
                      scopeIncidentId: selected.incident_id,
                      backView: 'incidents',
                    })}
                    className="px-3 py-1.5 text-sm rounded-md border border-[#d0d7de] text-[#16436b] hover:bg-[#eef1f4]"
                  >
                    Open Evidence Timeline
                  </button>
                </div>
              )}

              {/* Graded controls (single home, D7). A submitted incident
                  renders the Case Closed summary inline (5.4: moment +
                  grade + achievements) with the "Review what you learned"
                  path into the Metrics Learning Review -- teaching content
                  itself never renders in this workspace (one venue). */}
              <div className="pt-3 border-t border-[#eef1f4]">
                {selected.state === 'submitted' ? (
                  <div className="space-y-3" data-testid="case-closed-summary">
                    <p className="text-sm font-semibold text-[#1a2332]">{caseClosed(selected.incident_id)}</p>
                    {stripInfo?.id === selected.incident_id && stripInfo.view && (
                      <>
                        <div className="flex flex-wrap gap-1.5">
                          {deriveAchievements(stripInfo.view).map(a => (
                            <span key={a.key} className="inline-flex items-baseline gap-1 px-2 py-0.5 rounded-full text-xs bg-[#eef1f4] text-[#1a2332] border border-[#d0d7de]">
                              <span className="font-medium">{a.label}</span>
                              {a.subtitle && <span className="text-[#6e7781]">{a.subtitle}</span>}
                            </span>
                          ))}
                        </div>
                        <p className="text-sm text-[#57606a]">Incident Grade:{' '}
                          <span className="font-semibold" style={{ color: gradeColor(stripInfo.view.grading?.composite?.grade) }}>
                            {stripInfo.view.grading?.composite?.grade || '-'} · {stripInfo.view.grading?.composite?.accuracy ?? '-'}%
                          </span>
                        </p>
                      </>
                    )}
                    <div className="flex items-center gap-2 flex-wrap">
                      <button onClick={() => onOpenLearningReview?.(selected.incident_id)}
                        className="px-3 py-1.5 text-sm rounded-md bg-[#101218] text-white hover:bg-[#1e2330]">{REVIEW_WHAT_YOU_LEARNED}</button>
                      {isGuided && onPracticeAnother && (
                        <button onClick={() => setPracticeWarn(true)}
                          className="px-3 py-1.5 text-sm rounded-md border border-[#d0d7de] text-[#1a2332] hover:bg-[#eef1f4]">Practice Another</button>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center gap-2 flex-wrap">
                    {selected.sealed && selected.ready ? (
                      <>
                        {/* A3.4 (F4b): Submit gates on the ONE derived
                            readiness (server observable AND a valid
                            workspace classification); the observable line
                            names the remaining step. */}
                        <button onClick={beginSubmit}
                          disabled={!submissionReady(selected, chosen)}
                          className="px-3 py-1.5 text-sm rounded-md bg-[#101218] text-white hover:bg-[#1e2330] disabled:opacity-50">Submit</button>
                        {!validClassification(chosen[selected.incident_id]) && (
                          <span className="text-xs text-[#8b949e]">{CLASSIFY_TO_SUBMIT}</span>
                        )}
                      </>
                    ) : (
                      <>
                        <button onClick={() => { onSelectIncident?.(selected.incident_id); onNavigate?.('detections'); }}
                          className="px-3 py-1.5 text-sm rounded-md border border-[#d0d7de] text-[#1a2332] hover:bg-[#eef1f4]">Triage detections</button>
                        <span className="text-xs text-[#8b949e]">
                          {!selected.sealed ? TELEMETRY_LOADING : detectionsRemaining(selected.open_detections ?? 0)}
                        </span>
                      </>
                    )}
                    {isGuided && selected.sealed && (
                      <button onClick={beginCheck}
                        disabled={!validClassification(chosen[selected.incident_id])}
                        title={!validClassification(chosen[selected.incident_id]) ? CLASSIFY_TO_SUBMIT : undefined}
                        className="px-3 py-1.5 text-sm rounded-md border border-[#d0d7de] text-[#57606a] hover:bg-[#eef1f4] disabled:opacity-50">Check Answer</button>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* A3.4 (F4b): the bare confirmation -- Submit performs FINAL
          submission of the workspace classification; the classifier and
          category modal steps are retired (ratified A3-OD-2), so this
          dialog never performs data entry. The Hardcore warning relocates
          here from the retired modals (the last gate). */}
      {pendingSubmit && pendingSubmit.action === 'submit' && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" role="dialog" aria-modal="true">
          <div className="bg-white rounded-xl border border-[#e2e6ea] shadow-xl w-full max-w-md overflow-hidden">
            <div className="h-0.5" style={{ background: 'linear-gradient(to right, #16436b, #101218)' }} />
            <div className="p-5">
              <h3 className="text-base font-semibold text-[#1a2332]">Submit incident {pendingSubmit.incident_id}</h3>
              <p className="mt-2 text-sm text-[#57606a]">Filing as <span className="font-medium text-[#1a2332]">{pendingSubmit.category}</span>. This locks your classification for this incident and reveals how it scored. You cannot change it afterward.</p>
              {gameMode === 'hardcore' && (
                <p className="mt-2 text-sm font-medium text-[#b26666]">Hardcore: one wrong call ends the run.</p>
              )}
              <div className="mt-5 flex justify-end gap-2">
                <button type="button" onClick={() => setPendingSubmit(null)} disabled={submitBusy}
                  className="px-3 py-1.5 text-sm rounded-md border border-[#d0d7de] text-[#57606a] hover:bg-[#eef1f4] disabled:opacity-60">Cancel</button>
                <button type="button" onClick={doSubmit} disabled={submitBusy}
                  className="px-3 py-1.5 text-sm rounded-md bg-[#101218] text-white hover:bg-[#1a2332] disabled:opacity-60">{submitBusy ? 'Submitting…' : 'Submit Incident'}</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Guided Check Answer result: classification correctness ONLY */}
      {checkResult && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" role="dialog" aria-modal="true">
          <div className="bg-white rounded-xl border border-[#e2e6ea] shadow-xl w-full max-w-md overflow-hidden">
            <div className="h-0.5" style={{ background: 'linear-gradient(to right, #16436b, #101218)' }} />
            <div className="p-5">
              <p className="text-[11px] uppercase tracking-wider text-[#6e7781]">Check Answer</p>
              <h3 className="text-base font-semibold mt-0.5" style={{ color: checkResult.correct ? '#6fa868' : '#b45858' }}>
                {checkResult.correct ? 'Classification correct' : 'Not the right classification'}
              </h3>
              <p className="mt-2 text-sm text-[#57606a]">This reveals the classification only; detection and response are graded when you submit. This incident is now marked <span className="font-medium text-[#1a2332]">Assisted</span>.</p>
              <div className="mt-5 flex justify-end">
                <button type="button" onClick={() => setCheckResult(null)}
                  className="px-3 py-1.5 text-sm rounded-md bg-[#101218] text-white hover:bg-[#1e2330]">Close</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* The Case Closed moment (5.4, A1-B.4.1): one static summary per
          submission -- incident name, earned achievements, Incident Grade.
          Restrained: no looping animation, no sound; animate-modalIn is
          one-shot and disabled under prefers-reduced-motion (index.css).
          NEVER renders teaching content (one venue: the Metrics Learning
          Review); "Review what you learned" is the path there. */}
      {review && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/70" onClick={() => setReview(null)} />
          <div className="relative bg-white border border-[#e2e6ea] rounded-xl shadow-2xl max-w-lg w-full max-h-[90vh] overflow-y-auto p-6 animate-modalIn" data-testid="case-closed-modal">
            <div className="flex items-center justify-between">
              <div><p className="text-[11px] uppercase tracking-wider text-[#6e7781]">Incident Grade</p>
                <h2 className="text-lg font-semibold text-[#1a2332]">{caseClosed(review.incidentId)}</h2></div>
              {review.assisted && <span className="text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-[#eef1f4] text-[#57606a] border border-[#d0d7de]">Assisted</span>}
            </div>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {deriveAchievements(review.view).map(a => (
                <span key={a.key} className="inline-flex items-baseline gap-1 px-2 py-0.5 rounded-full text-xs bg-[#eef1f4] text-[#1a2332] border border-[#d0d7de]">
                  <span className="font-medium">{a.label}</span>
                  {a.subtitle && <span className="text-[#6e7781]">{a.subtitle}</span>}
                </span>
              ))}
            </div>
            <div className="mt-4 space-y-2 text-sm">
              {[['Classification', review.grading.classification], ['Detection dispositions', review.grading.detection], ['Response actions', review.grading.response]].map(([label, comp]) => (
                <div key={label} className="flex items-center justify-between border-t border-[#eef1f4] pt-2">
                  <span className="text-[#57606a]">{label}</span>
                  <span className="font-medium text-[#1a2332]">{comp?.grade || '-'} · {comp?.accuracy ?? '-'}%</span>
                </div>
              ))}
              <div className="flex items-center justify-between border-t border-[#e2e6ea] pt-2">
                <span className="text-[#1a2332] font-medium">Composite (Incident Grade)</span>
                <span className="font-semibold" style={{ color: gradeColor(review.grading.composite?.grade) }}>{review.grading.composite?.grade || '-'} · {review.grading.composite?.accuracy ?? '-'}%</span>
              </div>
            </div>
            <div className="mt-5 flex justify-end gap-2 flex-wrap">
              {isGuided && onPracticeAnother && (
                <button onClick={() => setPracticeWarn(true)}
                  className="px-4 py-2 text-sm rounded-md border border-[#d0d7de] text-[#1a2332] hover:bg-[#eef1f4]">Practice Another</button>
              )}
              <button onClick={() => { setReview(null); onOpenLearningReview?.(review.incidentId); }}
                className="px-4 py-2 text-sm rounded-md border border-[#d0d7de] text-[#1a2332] hover:bg-[#eef1f4]">{REVIEW_WHAT_YOU_LEARNED}</button>
              <button onClick={() => setReview(null)} className="px-4 py-2 text-sm rounded-md bg-[#101218] text-white hover:bg-[#1e2330]">Close</button>
            </div>
          </div>
        </div>
      )}

      {/* Practice Another (Guided): explicit reset warning before clearing the run */}
      {practiceWarn && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50 p-4" role="dialog" aria-modal="true">
          <div className="bg-white rounded-xl border border-[#e2e6ea] shadow-xl w-full max-w-md overflow-hidden">
            <div className="h-0.5" style={{ background: 'linear-gradient(to right, #16436b, #101218)' }} />
            <div className="p-5">
              <h3 className="text-base font-semibold text-[#1a2332]">Practice another scenario?</h3>
              <p className="mt-2 text-sm text-[#57606a]">This clears the current Guided run: its submitted incident record, your Session Performance, and this Post-Incident Review. The simulation resets and returns to the scenario picker.</p>
              <div className="mt-5 flex justify-end gap-2">
                <button type="button" onClick={() => setPracticeWarn(false)}
                  className="px-3 py-1.5 text-sm rounded-md border border-[#d0d7de] text-[#57606a] hover:bg-[#eef1f4]">Cancel</button>
                <button type="button" onClick={() => { setPracticeWarn(false); setReview(null); onPracticeAnother?.(); }}
                  className="px-3 py-1.5 text-sm rounded-md bg-[#101218] text-white hover:bg-[#1e2330]">Clear and pick another</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {notice && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 px-4 py-2 rounded-md bg-[#101218] text-white text-sm shadow-lg animate-modalIn">{notice}</div>
      )}
    </div>
  );
};

export default Incidents;
