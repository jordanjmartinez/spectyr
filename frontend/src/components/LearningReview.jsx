import React, { useState, useEffect, useCallback } from 'react';
import { apiFetch } from '../api';
import {
  LEARNING_REVIEW_TITLE, INCIDENT_GRADE_LABEL, SELECT_REVIEW_INCIDENT,
  NO_SUBMITTED_INCIDENTS, REVIEW_SECTION_CORRECT, REVIEW_SECTION_MISSED,
  REVIEW_SECTION_COLLATERAL, REVIEW_SECTION_ACCEPTABLE,
  REVIEW_SECTION_ATTEMPTS, REVIEW_SECTION_DETECTIONS,
  REVIEW_SECTION_PLAYBOOK, REVIEW_SECTION_TAKEAWAY,
  correctDetectionCalls, NO_CORRECT_CALLS, NO_COMPLETED_REQUIRED,
  REVIEW_EMPTY_MISSED, REVIEW_EMPTY_COLLATERAL, REVIEW_EMPTY_DETECTIONS,
  BREAKDOWN_LOAD_ERROR, CALL_CORRECT, CALL_WRONG, ACTION_LABELS,
} from './uiCopy';
import { deriveAchievements } from './achievements';

// Stage 5 Phase 5 commit 5.4 (ratified B-OD-1 Option 1): the Metrics tab is
// the ONE durable per-incident Learning Review home. Everything rendered
// here reads the SUBMITTED score view (the frozen record served across the
// submission boundary) plus the submitted-only triage review -- teaching is
// post-boundary by construction, and the in-workspace Case Closed modal
// never renders teaching content (one venue, 19.19). Labeling keeps the
// 3.9B distinction: this block is Incident Grade, never Session Performance.

const CARD = { background: '#ffffff', border: '1px solid #e2e6ea', boxShadow: '0 1px 2px rgba(0,0,0,0.04)' };
const gradeColor = (g) => (!g || g === '-') ? '#8b949e' : g === 'F' ? '#b45858' : g === 'D' ? '#c08a3e' : '#6fa868';

// One teaching entry row: verb + target + the frozen why.
const EntryRow = ({ e }) => (
  <li className="text-sm">
    {e.action ? (
      <p className="text-[#1a2332]">
        <span className="font-medium">{ACTION_LABELS[e.action] || e.action}</span>
        {e.target_label ? <span className="font-mono text-[#57606a]"> {e.target_label}</span> : null}
      </p>
    ) : null}
    <p className="text-[#57606a]">{e.why}</p>
  </li>
);

const Section = ({ title, entries, emptyLine }) => (
  <div className="pt-3 border-t border-[#eef1f4]">
    <p className="text-[11px] uppercase tracking-wider text-[#6e7781] font-medium mb-1.5">{title}</p>
    {entries.length === 0 ? (
      <p className="text-sm text-[#8b949e]">{emptyLine}</p>
    ) : (
      <ul className="space-y-2">{entries.map((e, i) => <EntryRow key={i} e={e} />)}</ul>
    )}
  </div>
);

const AchievementChips = ({ items }) => (
  <div className="flex flex-wrap gap-1.5" data-testid="achievements">
    {items.map(a => (
      <span key={a.key} className="inline-flex items-baseline gap-1 px-2 py-0.5 rounded-full text-xs bg-[#eef1f4] text-[#1a2332] border border-[#d0d7de]">
        <span className="font-medium">{a.label}</span>
        {a.subtitle && <span className="text-[#6e7781]">{a.subtitle}</span>}
      </span>
    ))}
  </div>
);

const LearningReview = ({ reviewRequest, isVisible = true }) => {
  const [completed, setCompleted] = useState([]);   // submitted incident cards
  const [selectedId, setSelectedId] = useState(null);
  const [scoreView, setScoreView] = useState(null); // the served frozen record view
  const [triage, setTriage] = useState(null);       // submitted-only educational content
  const [loadError, setLoadError] = useState(false);

  // The submitted list feeds the per-incident selector.
  const fetchList = useCallback(() => {
    apiFetch('/api/incidents').then(r => r.json())
      .then(d => setCompleted(d.completed || []))
      .catch(() => {});
  }, []);
  useEffect(() => { fetchList(); const iv = setInterval(fetchList, 3000); return () => clearInterval(iv); }, [fetchList]);

  // "Review what you learned" lands here with an incident preselected.
  useEffect(() => {
    if (reviewRequest?.id) setSelectedId(reviewRequest.id);
  }, [reviewRequest]);

  const fetchDetail = useCallback(() => {
    if (!selectedId) { setScoreView(null); setTriage(null); setLoadError(false); return; }
    setLoadError(false);
    apiFetch(`/api/incidents/${selectedId}/score`)
      .then(r => { if (!r.ok) throw new Error('score'); return r.json(); })
      .then(v => { setScoreView(v?.state === 'submitted' ? v : null); })
      .catch(() => { setScoreView(null); setLoadError(true); });
    apiFetch(`/api/incidents/${selectedId}/triage-review`)
      .then(r => (r.ok ? r.json() : null))
      .then(setTriage)
      .catch(() => setTriage(null));
  }, [selectedId]);
  useEffect(() => { fetchDetail(); }, [fetchDetail]);

  const grading = scoreView?.grading || null;
  const review = grading?.response_review || null;
  const achievements = deriveAchievements(scoreView);
  const selectedCard = completed.find(c => c.incident_id === selectedId) || null;

  // Bucket routing (7.1): inaction_correct answers "what you did
  // correctly"; inaction_spoiled belongs with what you missed; the
  // collateral entries themselves carry the harm.
  const entries = review?.entries || [];
  const correctEntries = entries.filter(e => e.bucket === 'completed' || e.reason_code === 'inaction_correct');
  const missedEntries = entries.filter(e => e.bucket === 'missed' || e.reason_code === 'inaction_spoiled');
  const collateralEntries = entries.filter(e => e.bucket === 'collateral');
  const acceptableEntries = entries.filter(e => e.bucket === 'acceptable');
  // C1 checkpoint fix (F5a): the well bucket reads BOTH ratified halves --
  // the frozen per-detection verdicts feed the correct-calls line.
  const detectionCalls = review?.detections || [];
  const correctCallCount = detectionCalls.filter(d => d.correct).length;

  return (
    <div>
      <div className="flex items-baseline gap-2 mb-4">
        <h2 className="text-xl sm:text-2xl font-semibold text-[#1a2332]">{LEARNING_REVIEW_TITLE}</h2>
        <span className="text-xs text-[#6e7781] uppercase tracking-wider">{INCIDENT_GRADE_LABEL}</span>
      </div>
      <div className="rounded-2xl p-4 sm:p-6" style={CARD}>
        {completed.length === 0 ? (
          <p className="text-sm text-[#57606a]">{NO_SUBMITTED_INCIDENTS}</p>
        ) : (
          <div className="space-y-4">
            {/* Per-incident selector (submitted incidents only) */}
            <div className="flex flex-wrap gap-1.5" role="group" aria-label="Submitted incidents">
              {completed.map(c => (
                <button key={c.incident_id} type="button"
                  onClick={() => setSelectedId(c.incident_id)}
                  className={`px-2.5 py-1 rounded-md text-xs border transition ${c.incident_id === selectedId
                    ? 'bg-[#101218] text-white border-transparent'
                    : 'bg-white text-[#57606a] border-[#d0d7de] hover:bg-[#eef1f4]'}`}>
                  <span className="log-mono">{c.incident_id}</span>
                  <span className="ml-1.5">{c.incident_grade?.grade || '-'}</span>
                </button>
              ))}
            </div>

            {!selectedId ? (
              <p className="text-sm text-[#8b949e]">{SELECT_REVIEW_INCIDENT}</p>
            ) : loadError || (scoreView && !review) ? (
              // 7.1 loading/error state (also the degraded-render guard when
              // a served grading lacks the breakdown): grade rows if we have
              // them, the one-line error, and a retry.
              <div className="space-y-3">
                {grading && (
                  <div className="text-sm text-[#57606a]">
                    {INCIDENT_GRADE_LABEL}: <span className="font-semibold" style={{ color: gradeColor(grading.composite?.grade) }}>{grading.composite?.grade || '-'} · {grading.composite?.accuracy ?? '-'}%</span>
                  </div>
                )}
                <p className="text-sm text-[#b45858]">{BREAKDOWN_LOAD_ERROR}</p>
                <button type="button" onClick={fetchDetail}
                  className="px-3 py-1.5 text-sm rounded-md border border-[#d0d7de] text-[#1a2332] hover:bg-[#eef1f4]">Retry</button>
              </div>
            ) : !scoreView ? (
              <p className="text-sm text-[#8b949e]">{SELECT_REVIEW_INCIDENT}</p>
            ) : (
              <div className="space-y-4" data-testid="learning-review-detail">
                {/* Header: incident + Assisted + achievements */}
                <div className="flex items-start justify-between gap-3 flex-wrap">
                  <div>
                    <p className="text-[11px] uppercase tracking-wider text-[#6e7781]">{INCIDENT_GRADE_LABEL}</p>
                    <h3 className="text-lg font-semibold text-[#1a2332]">
                      <span className="log-mono text-[#16436b] text-sm mr-2">{selectedId}</span>
                      {selectedCard?.title || ''}
                    </h3>
                  </div>
                  {scoreView.assisted && (
                    <span className="text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-[#eef1f4] text-[#57606a] border border-[#d0d7de]">Assisted</span>
                  )}
                </div>
                <AchievementChips items={achievements} />

                {/* Grade rows (composite + components) */}
                <div className="space-y-1.5 text-sm">
                  {[['Classification', grading.classification], ['Detection dispositions', grading.detection], ['Response actions', grading.response]].map(([label, comp]) => (
                    <div key={label} className="flex items-center justify-between border-t border-[#eef1f4] pt-1.5">
                      <span className="text-[#57606a]">{label}</span>
                      <span className="font-medium text-[#1a2332]">{comp?.grade || '-'} · {comp?.accuracy ?? '-'}%</span>
                    </div>
                  ))}
                  <div className="flex items-center justify-between border-t border-[#e2e6ea] pt-1.5">
                    <span className="text-[#1a2332] font-medium">Composite ({INCIDENT_GRADE_LABEL})</span>
                    <span className="font-semibold" style={{ color: gradeColor(grading.composite?.grade) }}>{grading.composite?.grade || '-'} · {grading.composite?.accuracy ?? '-'}%</span>
                  </div>
                </div>

                {/* The three acceptance questions (7.5), each with the
                    frozen whys; acceptable renders only when taken.
                    C1 checkpoint fix (F5a, ratified A1-B.4.1 item 3): the
                    well bucket includes correct dispositions alongside
                    completed required actions, and every empty state names
                    its own category (never a bare global negative). */}
                <div className="pt-3 border-t border-[#eef1f4]">
                  <p className="text-[11px] uppercase tracking-wider text-[#6e7781] font-medium mb-1.5">{REVIEW_SECTION_CORRECT}</p>
                  <div className="space-y-2">
                    {correctCallCount > 0 ? (
                      <p className="text-sm text-[#1a2332]">{correctDetectionCalls(correctCallCount, detectionCalls.length)}</p>
                    ) : (
                      <p className="text-sm text-[#8b949e]">{NO_CORRECT_CALLS}</p>
                    )}
                    {correctEntries.length === 0 ? (
                      <p className="text-sm text-[#8b949e]">{NO_COMPLETED_REQUIRED}</p>
                    ) : (
                      <ul className="space-y-2">{correctEntries.map((e, i) => <EntryRow key={i} e={e} />)}</ul>
                    )}
                  </div>
                </div>
                <Section title={REVIEW_SECTION_MISSED} entries={missedEntries} emptyLine={REVIEW_EMPTY_MISSED} />
                <Section title={REVIEW_SECTION_COLLATERAL} entries={collateralEntries} emptyLine={REVIEW_EMPTY_COLLATERAL} />
                {acceptableEntries.length > 0 && (
                  <Section title={REVIEW_SECTION_ACCEPTABLE} entries={acceptableEntries} />
                )}

                {/* Attempt history: factual, separately labeled, never a
                    teaching bucket (7.1). */}
                {(review.attempt_history || []).length > 0 && (
                  <div className="pt-3 border-t border-[#eef1f4]">
                    <p className="text-[11px] uppercase tracking-wider text-[#6e7781] font-medium mb-1.5">{REVIEW_SECTION_ATTEMPTS}</p>
                    <ul className="space-y-1">
                      {review.attempt_history.map(h => (
                        <li key={h.seq} className="text-sm text-[#57606a]">
                          <span className="text-[#1a2332]">{ACTION_LABELS[h.action] || h.action}</span>
                          {h.target_label ? <span className="font-mono"> {h.target_label}</span> : null}
                          {' '}<span className="text-[#8b949e]">({h.outcome === 'no_op' ? 'no effect, already in state' : 'did not execute'})</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Per-detection verdicts from the frozen record */}
                <div className="pt-3 border-t border-[#eef1f4]">
                  <p className="text-[11px] uppercase tracking-wider text-[#6e7781] font-medium mb-1.5">{REVIEW_SECTION_DETECTIONS}</p>
                  {(review.detections || []).length === 0 ? (
                    <p className="text-sm text-[#8b949e]">{REVIEW_EMPTY_DETECTIONS}</p>
                  ) : (
                    <ul className="space-y-1">
                      {review.detections.map((d, i) => (
                        <li key={i} className="text-sm flex items-center justify-between gap-2">
                          <span className="min-w-0 truncate text-[#1a2332]">{d.rule_name}
                            {d.entity_label ? <span className="text-[#8b949e]"> · {d.entity_label}</span> : null}
                          </span>
                          <span className="shrink-0 text-xs">
                            <span className="text-[#57606a]">{d.your_call}</span>
                            {' '}<span style={{ color: d.correct ? '#6fa868' : '#b45858' }}>{d.correct ? CALL_CORRECT : CALL_WRONG}</span>
                          </span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>

                {/* Educational content (moved from the modal: one venue) */}
                {triage?.what_is_it && (
                  <div className="pt-3 border-t border-[#eef1f4]">
                    {triage.mitre && <p className="text-xs text-[#16436b] font-medium mb-1">{triage.mitre.id} · {triage.mitre.name}</p>}
                    <p className="text-sm font-medium text-[#1a2332]">{triage.what_is_it.title}</p>
                    <p className="text-sm text-[#57606a] mt-1 break-words">{triage.what_is_it.description}</p>
                  </div>
                )}
                {(triage?.response_actions || []).length > 0 && (
                  <div className="pt-3 border-t border-[#eef1f4]">
                    <p className="text-[11px] uppercase tracking-wider text-[#6e7781] font-medium mb-1.5">{REVIEW_SECTION_PLAYBOOK}</p>
                    <ol className="list-decimal ml-5 space-y-1">
                      {triage.response_actions.map((step, i) => (
                        <li key={i} className="text-sm text-[#57606a]">{step}</li>
                      ))}
                    </ol>
                  </div>
                )}

                {/* Key takeaway: the frozen Tier 2 scenario rationale.
                    Ruling H: null -> section omitted (Tier 1 whys teach). */}
                {review.scenario_rationale && (
                  <div className="pt-3 border-t border-[#eef1f4]">
                    <p className="text-[11px] uppercase tracking-wider text-[#6e7781] font-medium mb-1.5">{REVIEW_SECTION_TAKEAWAY}</p>
                    <p className="text-sm text-[#57606a]">{review.scenario_rationale}</p>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default LearningReview;
