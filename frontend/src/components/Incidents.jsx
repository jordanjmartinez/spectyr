import React, { useState, useEffect, useCallback, useRef } from 'react';
import { apiFetch } from '../api';
import ClassificationSelector from './ClassificationSelector';
import CategorySelector from './CategorySelector';
import {
  TELEMETRY_LOADING, detectionsReviewed, detectionsRemaining,
  responseActionsTaken, READY_TO_SUBMIT, toReview, completedStrip,
  SUBMITTED_GRADE_LOCKED, CLASSIFICATION_NOT_SELECTED,
  classificationSelected, CONSIDER_PROMPT, SUBMIT_PENDING,
  caseClosed, REVIEW_WHAT_YOU_LEARNED, CLASSIFY_TO_SUBMIT, SELECT_CATEGORY,
  detectionsQueueItem, DETECTIONS_TRIAGED,
} from './uiCopy';
import { CheckIcon } from './RadioCardGroup';
import { submissionReady, validClassification } from './submissionReady';
import { toastReady } from './uiToasts';
import useIncidentScope from './useIncidentScope';
import { deriveAchievements } from './achievements';
import {
  gradeColor, CARD_STYLE, IncidentIdBadge, SeverityBadge,
} from './ui';

// Stage 3.9B: the Incidents operational workspace ("what do I need to work?").
// Search + Active / Ready / Completed views, stable incident rows, and a
// selected-incident detail (briefing, scoped detection progress, related hosts
// and accounts, Related response activity) with the SINGLE home for the graded
// Submit / Resume / Review controls (D2/D7). This retires the legacy Alerts
// ticket table and the global Notable Events queue (D3/D4): the player-facing
// object is the incident. Raw underlying events stay in SIEM (D4, unchanged).

// Visual pass VG: severity dots, grade colors, and the card surface come
// from the ONE shared visual-language module (ui.jsx); nothing visual is
// defined twice.
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
// OWNER DECLUTTER (2026-10-12): the strip no longer renders in the detail
// panel (the panel keeps description, Classification, Investigate in SIEM,
// Triage detections). The component stays exported with its leak-rule
// guards pending a final presentation ruling.
export const PhaseStrip = ({ sealed, triage, related, ready, classification,
                             showPrompt }) => {
  if (!sealed) return <p className="text-xs text-muted italic">{TELEMETRY_LOADING}</p>;
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
          <span className={done ? 'text-muted' : 'text-muted'}>{text}</span>
          {key === 'response' && showPrompt && (
            <span className="text-muted">{CONSIDER_PROMPT}</span>
          )}
        </div>
      ))}
    </div>
  );
};

// Owner panel refinement (2026-10-12, superseding the eyebrow+tag form):
// the group label at the app's standard card-title size and weight
// (t-subsection: semibold, dark) -- the incident title stays the panel's
// one hero; the Required/Not-required tags are removed (the footer's
// readiness checklist already shows what's owed).
const GroupLabel = ({ id, children }) => (
  <p id={id} className="t-subsection">{children}</p>
);

// The sticky-footer readiness item (Verdict / Category) -- neutral ink, no
// red or green in classification.
const ReadyItem = ({ done, label }) => (
  <span className="inline-flex items-center gap-1.5 text-xs">
    <span aria-hidden="true"
      className={`w-3.5 h-3.5 rounded-full flex items-center justify-center shrink-0 ${
        done ? 'bg-[#101218] text-white' : 'border border-[#8b949e]'}`}>
      {done && <CheckIcon className="w-2.5 h-2.5" />}
    </span>
    <span className={done ? 'text-[#1a2332] font-medium' : 'text-muted'}>{label}</span>
  </span>
);

const Incidents = ({
  isVisible, resetTrigger, onHardcoreFailure, onReset, gameMode = 'training',
  activeIncidentId, onSelectIncident, onNavigate, setGroupedAlertCount, onPracticeAnother,
  onEvidenceDescent, onOpenLearningReview,
  // VA1: this workspace already polls the incident list, so it reports
  // the selected incident's observable summary up to the shell, which
  // hands it to the other pages for their ONE context pill. No new
  // request and no new endpoint field.
  onActiveIncidentSummary,
  // A3.4 (ratified A3-OD-3): the classification selection state is
  // SHELL-OWNED (Dashboard) so every Ready surface derives from the one
  // state; this component receives it and its setter.
  chosen = {}, setChosen,
}) => {
  const [data, setData] = useState({ active: [], completed: [], queue_length: 0, resolved_count: 0 });

  const [pendingSubmit, setPendingSubmit] = useState(null);  // {..., action: 'submit'}
  // Stage 6 playtest fix: a reset destroys the run, so every piece of
  // run-scoped local state dies with it -- the open debrief (Case Closed
  // modal), pending confirmations, cached per-incident views, and the list
  // filter. Previously the old run's debrief stayed on screen until a
  // reload because only the readiness ref was cleared here.
  useEffect(() => {
    prevReadyRef.current = {};
    setReview(null);
    setPendingSubmit(null);
    setPracticeWarn(false);
    setStripInfo(null);
    setNotice('');
    setFormError(null);
  }, [resetTrigger]);
  // the inline error belongs to one incident's form; switching cases clears it
  useEffect(() => { setFormError(null); }, [activeIncidentId]);
  const verdictOptionId = (v) =>
    v === 'threat' ? 'true_positive' : v === 'false_positive' ? 'false_positive' : null;
  // Workspace classification handlers: local input only, no request. Owner
  // panel pass (2026-10-12): the two groups are ORDER-INDEPENDENT -- a
  // category picked before the verdict is kept (never implies a verdict);
  // False Positive clears any picked category (the group disables); the FP
  // pseudo-category never survives a switch to True Positive (its
  // categoryId is null).
  const setWorkspaceVerdict = (incidentId, id) => {
    setChosen?.(c => {
      const prev = c[incidentId] || {};
      if (id === 'false_positive') {
        return { ...c, [incidentId]: { verdict: 'false_positive', category: 'False Positive', categoryId: null } };
      }
      return { ...c, [incidentId]: { verdict: 'threat',
        category: prev.categoryId ? prev.category || null : null,
        categoryId: prev.categoryId || null } };
    });
  };
  const setWorkspaceCategory = (incidentId, cid, clabel) => {
    setChosen?.(c => {
      const prev = c[incidentId] || {};
      return { ...c, [incidentId]: { verdict: prev.verdict || null, category: clabel, categoryId: cid } };
    });
  };
  // The incomplete-Submit inline error: 'verdict' | 'category' | null. Any
  // selection clears it; Submit re-derives it and scrolls to the first
  // missing group.
  const [formError, setFormError] = useState(null);
  const verdictGroupRef = useRef(null);
  const categoryGroupRef = useRef(null);
  const [submitBusy, setSubmitBusy] = useState(false);
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
    // The scope read joins this existing 3s poll while an incident is
    // selected (the Detections pattern), so a pre-seal roster cannot go
    // stale; no extra interval exists for the scope.
    if (scopeModeRef.current === 'incident') scopeRefetchRef.current();
  }, [setGroupedAlertCount]);

  useEffect(() => { fetchList(); const iv = setInterval(fetchList, 3000); return () => clearInterval(iv); }, [fetchList]);

  // Selected incident scope (Related hosts/accounts + descent inputs). The
  // fuzzy related-activity label join is DELETED (scaffold ruling A): the
  // honest count is the server's D4 related_actions card field.
  // Stage 6 playtest fix 7: the ad-hoc fetch is replaced by the ONE shared
  // scope state (useIncidentScope, the same machinery behind Detections /
  // Endpoints / Response). It drops data the moment the incident changes and
  // discards superseded responses, so the panel can never flash the previous
  // incident's hosts and accounts. Freshness joins the existing 3s list poll
  // below (the Detections pattern): no extra interval for the scope.
  const scope = useIncidentScope(selectedId, resetTrigger);
  const scopeRefetchRef = useRef(scope.refetch);
  scopeRefetchRef.current = scope.refetch;
  const scopeModeRef = useRef(scope.mode);
  scopeModeRef.current = scope.mode;

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
  // Owner queue pass (2026-10-12): the list panel is the SESSION QUEUE --
  // all slots in queue order (completed in submission order, then the
  // in-flight incidents in drip order, then the undripped slots as muted
  // "Scenario N" placeholders; their identity is not yet observable).
  const queuePlaced = [
    ...[...data.completed].sort((a, b) => String(a.submitted_at || '').localeCompare(String(b.submitted_at || ''))),
    ...data.active,
  ];
  const upcomingCount = Math.max(0, (data.queue_length || 0) - queuePlaced.length);
  const selected = all.find(c => c.incident_id === selectedId) || null;

  useEffect(() => {
    if (!onActiveIncidentSummary) return;
    const card = [...data.active, ...data.completed]
      .find(c => c.incident_id === activeIncidentId);
    onActiveIncidentSummary(card
      ? { incidentId: card.incident_id, title: card.title, severity: card.severity }
      : null);
  }, [activeIncidentId, data, onActiveIncidentSummary]);


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

  // Owner panel pass (2026-10-12): Submit stays ENABLED. An incomplete
  // click scrolls to the FIRST missing group and shows its inline error;
  // a complete one falls through to the unchanged beginSubmit gate
  // (seal/readiness flashes + the bare confirmation).
  const trySubmit = () => {
    const sel = chosen[selected?.incident_id] || null;
    if (!sel?.verdict) {
      setFormError('verdict');
      verdictGroupRef.current?.scrollIntoView?.({ behavior: 'smooth', block: 'center' });
      return;
    }
    if (sel.verdict === 'threat' && !sel.category) {
      setFormError('category');
      categoryGroupRef.current?.scrollIntoView?.({ behavior: 'smooth', block: 'center' });
      return;
    }
    setFormError(null);
    beginSubmit();
  };

  // Visual pass V1: the pre-submission Check Answer workflow is REMOVED.
  // Classification correctness is disclosed only across the submission
  // boundary (the submitted Learning Review); every mode reaches it the
  // same way, through Submit. The backend /check-answer endpoint stays as
  // intentionally dormant server capability (the frozen 3.9A temporal
  // leak-guard suite exercises it); no player-facing surface calls it.
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
      {/* Owner queue pass (2026-10-12): the Active/Ready/Completed view
          toggle and the search are retired -- the queue IS the whole
          session (five slots), so one list shows every state. */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        {/* The SESSION QUEUE (owner queue pass 2026-10-12): header with the
            session fraction, then every scenario slot in queue order.
            Completed rows mute with a grade chip; in-flight rows get the
            tinted background + left accent bar with pills, title, the
            to-review count, and a triage progress bar; Ready rows are
            normal; undripped slots are muted placeholders. The SELECTED
            row carries its own inset-ring highlight, independent of
            state styling. */}
        <div className="lg:col-span-2 rounded-xl" style={CARD_STYLE} data-testid="incident-queue">
          <div className="px-4 pt-4 pb-2 flex items-baseline justify-between gap-3">
            {/* owner refinement (2026-10-13): the queue header and the
                detail panel's incident title are BOTH panel-level headings
                of one workspace -- identical size and weight */}
            <p className="text-base font-semibold text-[#1a2332]">Incident Queue</p>
            {(data.queue_length || 0) > 0 && (
              <span className="text-sm text-muted shrink-0">
                {Math.min((data.resolved_count || 0) + 1, data.queue_length)} of {data.queue_length}
              </span>
            )}
          </div>
          <div className="divide-y divide-[#eef1f4] border-t border-[#eef1f4]">
            {queuePlaced.length === 0 && upcomingCount === 0 ? (
              /* Owner empty-state convention (2026-10-12): one muted line,
                 top-left at the panel's content origin -- app-wide. */
              <p className="p-4 text-sm text-muted">No incidents in this session.</p>
            ) : (
              <>
                {queuePlaced.map(c => {
                  const done = c.state === 'submitted';
                  const working = !done && !(c.sealed && c.ready);   // in flight, triage open
                  const isSel = c.incident_id === selectedId;
                  const t = c.triage || { total: 0, triaged: 0 };
                  return (
                    <button key={c.incident_id} onClick={() => onSelectIncident?.(c.incident_id)}
                      className={`relative w-full text-left p-3 space-y-1.5 ${working ? 'bg-[#16436b]/5' : ''} ${
                        isSel ? 'ring-2 ring-inset ring-[#16436b]/50' : 'hover:bg-[#f6f8fa]'}`}>
                      {working && <span aria-hidden="true" className="absolute left-0 top-0 bottom-0 w-[3px] bg-[#16436b]" />}
                      <span className={`flex items-center justify-between gap-2 ${done ? 'opacity-60' : ''}`}>
                        <span className="min-w-0 flex items-center gap-1.5">
                          <IncidentIdBadge id={c.incident_id} />
                          <SeverityBadge severity={c.severity} />
                          <span className="text-sm text-[#1a2332] truncate">{c.title}</span>
                        </span>
                        {done ? (
                          <span className="px-1.5 py-0.5 rounded text-[11px] font-semibold bg-[#eef1f4] shrink-0"
                            style={{ color: gradeColor(c.incident_grade?.grade) }}>
                            {c.incident_grade?.grade || '-'}
                          </span>
                        ) : (
                          <span className="text-[11px] text-[#8b949e] shrink-0 whitespace-nowrap">
                            {!c.sealed ? 'Loading'
                              : submissionReady(c, chosen) ? 'Ready'
                              : c.ready ? SUBMIT_PENDING
                              : toReview(c.open_detections)}
                          </span>
                        )}
                      </span>
                      {working && c.sealed && (
                        <span className="block h-1.5 rounded-full bg-[#eef1f4] overflow-hidden" aria-hidden="true">
                          <span className="block h-full rounded-full bg-[#16436b]"
                            style={{ width: `${t.total ? (t.triaged / t.total) * 100 : 0}%` }} />
                        </span>
                      )}
                    </button>
                  );
                })}
                {Array.from({ length: upcomingCount }, (_, i) => (
                  <div key={`upcoming-${i}`} className="p-3 text-sm text-muted opacity-60">
                    Scenario {queuePlaced.length + i + 1}
                  </div>
                ))}
              </>
            )}
          </div>
        </div>

        {/* Selected incident detail (the workspace) */}
        <div className="lg:col-span-3 rounded-xl p-4 sm:p-5" style={CARD_STYLE}>
          {!selected ? (
            <p className="text-sm text-muted">Select an incident to work it.</p>
          ) : (
            <div className="space-y-4">
                {/* Owner panel pass (2026-10-12): TITLE ONLY -- the INC and
                    severity pills live on the list row (no duplicate header
                    pills), and the Clear selection control is removed (the
                    case changes by list selection alone). */}
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="text-base font-semibold text-[#1a2332]">{selected.title}</span>
                    {selected.state === 'submitted' && selected.assisted && (
                      <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-[#eef1f4] text-muted border border-[#d0d7de]">Assisted</span>
                    )}
                  </div>
                  {selected.briefing && <p className="mt-1 text-sm text-muted break-words">{selected.briefing}</p>}
                </div>

                {/* Owner panel refinement (2026-10-12): ONE row of plain
                    text links under the description, the "View X" pattern --
                    these NAVIGATE to a scoped workspace, they do not act on
                    the incident. Investigate stays scope-gated (the forId
                    guard means it can never carry a previous incident's
                    hosts); Triage renders while the incident is open. */}
                {((scope.data && onEvidenceDescent) || selected.state === 'in_progress') && (
                  /* owner refinement (2026-10-13): the links hug the
                     panel's right side */
                  <div className="flex items-center justify-end gap-4 flex-wrap">
                    {scope.data && onEvidenceDescent && (
                      <button
                        type="button"
                        onClick={() => onEvidenceDescent({
                          hosts: scope.data.hostList,
                          account: null,
                          scopeIncidentId: selected.incident_id,
                        })}
                        className="text-xs font-medium text-[#16436b] hover:underline"
                      >
                        Investigate in SIEM
                      </button>
                    )}
                    {selected.state === 'in_progress' && (
                      <button
                        type="button"
                        onClick={() => { onSelectIncident?.(selected.incident_id); onNavigate?.('detections'); }}
                        className="text-xs font-medium text-[#16436b] hover:underline"
                      >
                        Triage Detections
                      </button>
                    )}
                  </div>
                )}

              {/* Owner declutter (2026-10-12): the status checklist no
                  longer renders here (in_progress incidents show no strip);
                  a SUBMITTED incident keeps the completed vocabulary (2.3:
                  the 0-of-0 contradiction stays structurally impossible). */}
              {selected.state === 'submitted' && (
                <div className="pt-2 border-t border-[#eef1f4]">
                  <p className="text-xs text-muted">
                    {stripInfo?.id === selected.incident_id
                      ? completedStrip(stripInfo.total)
                      : SUBMITTED_GRADE_LOCKED}
                  </p>
                </div>
              )}

              {/* The verdict card (owner panel pass 2026-10-12, built on the
                  ratified A1-B.3.2 local-input source -- purely local state,
                  no request; the submit confirmation arrives pre-filled from
                  this choice; identical for every incident, the leak rule).
                  Both groups ALWAYS render, nothing preselected, order-
                  independent; Category disables under False Positive. The
                  selected treatment is identical for every option: no red or
                  green in classification. */}
              {selected.state !== 'submitted' && selected.sealed && (
                <div className="pt-3 border-t border-[#eef1f4] space-y-4" data-testid="workspace-classification">
                  <div ref={verdictGroupRef} className="space-y-2">
                    <GroupLabel id="verdict-group-label">Classification</GroupLabel>
                    <ClassificationSelector
                      labelledBy="verdict-group-label"
                      selected={verdictOptionId(chosen[selected.incident_id]?.verdict)}
                      onSelect={(id) => { setWorkspaceVerdict(selected.incident_id, id); setFormError(null); }} />
                    {formError === 'verdict' && (
                      <p className="text-xs font-medium" style={{ color: '#b45858' }} role="alert">{CLASSIFY_TO_SUBMIT}</p>
                    )}
                  </div>
                  <div ref={categoryGroupRef} className="space-y-2">
                    <GroupLabel id="category-group-label">Category</GroupLabel>
                    <CategorySelector
                      labelledBy="category-group-label"
                      disabled={chosen[selected.incident_id]?.verdict === 'false_positive'}
                      selected={chosen[selected.incident_id]?.categoryId || null}
                      onSelect={(cid, clabel) => { setWorkspaceCategory(selected.incident_id, cid, clabel); setFormError(null); }} />
                    {formError === 'category' && (
                      <p className="text-xs font-medium" style={{ color: '#b45858' }} role="alert">{SELECT_CATEGORY}</p>
                    )}
                  </div>
                </div>
              )}

              {/* Graded controls (single home, D7). A submitted incident
                  renders the Case Closed summary inline (5.4: moment +
                  grade + achievements) with the "Review what you learned"
                  path into the Metrics Learning Review -- teaching content
                  itself never renders in this workspace (one venue). */}
              {selected.state === 'submitted' ? (
                <div className="pt-3 border-t border-[#eef1f4]">
                  <div className="space-y-3" data-testid="case-closed-summary">
                    <p className="text-sm font-semibold text-[#1a2332]">{caseClosed(selected.incident_id)}</p>
                    {stripInfo?.id === selected.incident_id && stripInfo.view && (
                      <>
                        <div className="flex flex-wrap gap-1.5">
                          {deriveAchievements(stripInfo.view).map(a => (
                            <span key={a.key} className="inline-flex items-baseline gap-1 px-1.5 py-0.5 rounded-full text-[11px] bg-[#eef1f4] text-[#1a2332] border border-[#d0d7de]">
                              <span className="font-medium">{a.label}</span>
                              {a.subtitle && <span className="text-muted">{a.subtitle}</span>}
                            </span>
                          ))}
                        </div>
                        <p className="text-sm text-muted">Incident Grade:{' '}
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
                </div>
              ) : selected.sealed && (
                /* Owner panel pass (2026-10-12): the STICKY FOOTER -- the
                   readiness checklist (Verdict, Category) and Submit, the
                   panel's ONLY primary button. Submit stays ENABLED; an
                   incomplete click scrolls to the first missing group with
                   an inline error (trySubmit); the unchanged beginSubmit +
                   server gates stay the authoritative backstop. */
                <div
                  data-testid="submit-footer"
                  className="sticky bottom-0 -mx-4 sm:-mx-5 -mb-4 sm:-mb-5 px-4 sm:px-5 py-3 bg-white border-t border-[#e2e6ea] rounded-b-xl flex items-center justify-between gap-3 flex-wrap"
                >
                  {/* Owner footer refinement (2026-10-13): the Verdict and
                      Category items are removed (the selected cards above
                      already show that state); the ONE persistent item is
                      the requirement NOT visible in this panel --
                      detections triage. */}
                  <ReadyItem
                    done={!!selected.ready}
                    label={selected.ready
                      ? DETECTIONS_TRIAGED
                      : detectionsQueueItem(selected.open_detections ?? 0)} />
                  <button type="button" onClick={trySubmit}
                    className="px-4 py-2 text-sm font-medium rounded-md bg-[#101218] text-white hover:bg-[#1e2330]">
                    Submit
                  </button>
                </div>
              )}
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
            <div className="p-5">
              <h3 className="text-base font-semibold text-[#1a2332]">Submit incident {pendingSubmit.incident_id}</h3>
              <p className="mt-2 text-sm text-muted">Filing as <span className="font-medium text-[#1a2332]">{pendingSubmit.category}</span>. This locks your classification for this incident and reveals how it scored. You cannot change it afterward.</p>
              {gameMode === 'hardcore' && (
                <p className="mt-2 text-sm font-medium text-[#b26666]">Hardcore: one wrong call ends the run.</p>
              )}
              <div className="mt-5 flex justify-end gap-2">
                <button type="button" onClick={() => setPendingSubmit(null)} disabled={submitBusy}
                  className="px-3 py-1.5 text-sm rounded-md border border-[#d0d7de] text-muted hover:bg-[#eef1f4] disabled:opacity-60">Cancel</button>
                <button type="button" onClick={doSubmit} disabled={submitBusy}
                  className="px-3 py-1.5 text-sm rounded-md bg-[#101218] text-white hover:bg-[#1a2332] disabled:opacity-60">{submitBusy ? 'Submitting…' : 'Submit Incident'}</button>
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
              <div><p className="t-overline">Incident Grade</p>
                <h2 className="text-lg font-semibold text-[#1a2332]">{caseClosed(review.incidentId)}</h2></div>
              {review.assisted && <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-[#eef1f4] text-muted border border-[#d0d7de]">Assisted</span>}
            </div>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {deriveAchievements(review.view).map(a => (
                <span key={a.key} className="inline-flex items-baseline gap-1 px-1.5 py-0.5 rounded-full text-[11px] bg-[#eef1f4] text-[#1a2332] border border-[#d0d7de]">
                  <span className="font-medium">{a.label}</span>
                  {a.subtitle && <span className="text-muted">{a.subtitle}</span>}
                </span>
              ))}
            </div>
            <div className="mt-4 space-y-2 text-sm">
              {[['Classification', review.grading.classification], ['Detection dispositions', review.grading.detection], ['Response actions', review.grading.response]].map(([label, comp]) => (
                <div key={label} className="flex items-center justify-between border-t border-[#eef1f4] pt-2">
                  <span className="text-muted">{label}</span>
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
            <div className="p-5">
              <h3 className="text-base font-semibold text-[#1a2332]">Practice another scenario?</h3>
              <p className="mt-2 text-sm text-muted">This clears the current Guided run: its submitted incident record, your Session performance, and this Post-Incident Review. The simulation resets and returns to the scenario picker.</p>
              <div className="mt-5 flex justify-end gap-2">
                <button type="button" onClick={() => setPracticeWarn(false)}
                  className="px-3 py-1.5 text-sm rounded-md border border-[#d0d7de] text-muted hover:bg-[#eef1f4]">Cancel</button>
                <button type="button" onClick={() => { setPracticeWarn(false); setReview(null); onPracticeAnother?.(); }}
                  className="px-3 py-1.5 text-sm rounded-md bg-[#101218] text-white hover:bg-[#1e2330]">Clear and Pick Another</button>
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
