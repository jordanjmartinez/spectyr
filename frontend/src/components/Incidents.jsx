import React, { useState, useEffect, useCallback, useRef } from 'react';
import { apiFetch } from '../api';
import ClassificationSelector from './ClassificationSelector';
import CategorySelector from './CategorySelector';

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

const PhaseStrip = ({ sealed, triage, related, ready }) => {
  if (!sealed) return <p className="text-xs text-[#8b949e] italic">Incident telemetry is still loading.</p>;
  const t = triage || { total: 0, triaged: 0 };
  const steps = [
    ['Triage', `${t.triaged} of ${t.total} reviewed`, ready],
    ['Investigate', 'evidence', false],
    ['Respond', `${related} related`, false],
    ['Submit', ready ? 'ready' : 'pending', false],
  ];
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px]">
      {steps.map(([label, detail, done], i) => (
        <span key={label} className="inline-flex items-center gap-1.5">
          {i > 0 && <span className="text-[#d0d7de]">›</span>}
          <span className={`font-medium ${done ? 'text-[#6fa868]' : 'text-[#57606a]'}`}>{label}</span>
          <span className="text-[#8b949e]">{detail}</span>
        </span>
      ))}
    </div>
  );
};

const Incidents = ({
  isVisible, resetTrigger, onHardcoreFailure, onReset, gameMode = 'training',
  activeIncidentId, onSelectIncident, onNavigate, setGroupedAlertCount, onPracticeAnother,
}) => {
  const [data, setData] = useState({ active: [], completed: [], queue_length: 0, resolved_count: 0 });
  const [view, setView] = useState('active');    // 'active' | 'ready' | 'completed'
  const [search, setSearch] = useState('');
  const [scope, setScope] = useState(null);       // selected incident /scope
  const [related, setRelated] = useState(0);      // Related response activity count
  const [relatedList, setRelatedList] = useState([]);

  const [showClassifier, setShowClassifier] = useState(false);
  const [showCategory, setShowCategory] = useState(false);
  const [pendingSubmit, setPendingSubmit] = useState(null);  // {..., action: 'submit' | 'check'}
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

  const fetchList = useCallback(() => {
    apiFetch('/api/incidents').then(r => r.json()).then(d => {
      setData(d);
      setGroupedAlertCount?.((d.active || []).length);
    }).catch(() => {});
  }, [setGroupedAlertCount]);

  useEffect(() => { fetchList(); const iv = setInterval(fetchList, 3000); return () => clearInterval(iv); }, [fetchList]);

  // Selected incident scope + Related response activity.
  const fetchScope = useCallback(() => {
    if (!selectedId) { setScope(null); setRelated(0); setRelatedList([]); return; }
    apiFetch(`/api/incidents/${selectedId}/scope`).then(r => r.json()).then(async (sc) => {
      setScope(sc);
      const log = await apiFetch('/api/actions').then(r => r.json()).catch(() => []);
      const entries = Array.isArray(log) ? log : (log.entries || []);
      const hosts = new Set(sc.hosts || []); const accts = new Set(sc.accounts || []);
      const rel = entries.filter(e => e.outcome === 'success' && e.target?.label && (
        [...hosts].some(h => e.target.label.includes(h)) || [...accts].some(a => e.target.label.includes(a))
      ));
      setRelated(rel.length); setRelatedList(rel);
    }).catch(() => {});
  }, [selectedId]);

  useEffect(() => { fetchScope(); const iv = setInterval(fetchScope, 3000); return () => clearInterval(iv); }, [fetchScope]);

  const all = [...data.active.map(c => ({ ...c })), ...data.completed.map(c => ({ ...c }))];
  const q = search.trim().toLowerCase();
  const byView = (c) => view === 'completed' ? c.state === 'submitted'
    : view === 'ready' ? (c.state === 'in_progress' && c.sealed && c.ready)
    : c.state === 'in_progress';
  const rows = all.filter(c => byView(c) && (!q || (c.title || '').toLowerCase().includes(q) || (c.incident_id || '').toLowerCase().includes(q)));
  const selected = all.find(c => c.incident_id === selectedId) || null;

  const counts = {
    active: data.active.length,
    ready: data.active.filter(c => c.sealed && c.ready).length,
    completed: data.completed.length,
  };

  const beginSubmit = () => {
    if (!selected || selected.state !== 'in_progress') return;
    if (!selected.sealed) { flash('Incident telemetry is still loading.'); return; }
    if (!selected.ready) { const n = selected.open_detections ?? 0; flash(`${n} detection${n === 1 ? '' : 's'} still need review.`); return; }
    setPendingSubmit({ incident_id: selected.incident_id, title: selected.title, action: 'submit' });
    setShowClassifier(true);
  };

  // Check Answer (Guided only): pick a classification and reveal ONLY whether it
  // is correct, without submitting; permanently marks the incident Assisted. It
  // never reveals detection, response, or composite grading (server-enforced).
  const beginCheck = () => {
    if (!isGuided || !selected || selected.state !== 'in_progress' || !selected.sealed) return;
    setPendingSubmit({ incident_id: selected.incident_id, title: selected.title, action: 'check' });
    setShowClassifier(true);
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
      if (res.ok) { setCheckResult({ correct: !!b.correct }); fetchList(); }
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

  // The single Post-Incident Review surface (D7): Incident Grade breakdown +
  // the post-boundary educational triage review + Assisted badge.
  const openReview = async (incidentId) => {
    const scoreView = await apiFetch(`/api/incidents/${incidentId}/score`).then(r => r.json()).catch(() => null);
    if (scoreView?.state !== 'submitted') return;
    const tr = await apiFetch(`/api/incidents/${incidentId}/triage-review`).then(r => (r.ok ? r.json() : null)).catch(() => null);
    const card = all.find(c => c.incident_id === incidentId);
    setReview({ incidentId, title: card?.title, grading: scoreView.grading, assisted: scoreView.assisted, triage: tr });
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
                {c.state === 'submitted' ? (c.incident_grade?.grade || '-') : !c.sealed ? 'Loading' : c.ready ? 'Ready' : `${c.open_detections} left`}
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
              </div>

              <div className="pt-2 border-t border-[#eef1f4]">
                <PhaseStrip sealed={selected.state === 'submitted' ? true : selected.sealed}
                  triage={selected.triage} related={related} ready={selected.ready} />
              </div>

              {/* Related hosts / accounts (observable scope) */}
              {scope && (scope.hosts?.length || scope.accounts?.length) ? (
                <div className="text-xs text-[#57606a] space-y-1">
                  {scope.hosts?.length ? <p><span className="text-[#8b949e]">Related hosts:</span> {scope.hosts.join(', ')}</p> : null}
                  {scope.accounts?.length ? <p><span className="text-[#8b949e]">Related accounts:</span> {scope.accounts.join(', ')}</p> : null}
                </div>
              ) : null}

              {/* Related response activity (C5, non-exclusive) */}
              {relatedList.length > 0 && (
                <div className="text-xs text-[#57606a]">
                  <p className="text-[#8b949e] mb-1">Related response activity ({related})</p>
                  <ul className="space-y-0.5">
                    {relatedList.slice(0, 5).map(e => <li key={e.seq}>{e.action} · <span className="font-mono">{e.target?.label}</span></li>)}
                  </ul>
                </div>
              )}

              {/* Graded controls (single home, D7) */}
              <div className="pt-3 border-t border-[#eef1f4] flex items-center gap-2 flex-wrap">
                {selected.state === 'submitted' ? (
                  <button onClick={() => openReview(selected.incident_id)}
                    className="px-3 py-1.5 text-sm rounded-md border border-[#d0d7de] text-[#1a2332] hover:bg-[#eef1f4]">View Post-Incident Review</button>
                ) : (
                  <>
                    {selected.sealed && selected.ready ? (
                      <button onClick={beginSubmit}
                        className="px-3 py-1.5 text-sm rounded-md bg-[#101218] text-white hover:bg-[#1e2330]">Submit</button>
                    ) : (
                      <>
                        <button onClick={() => { onSelectIncident?.(selected.incident_id); onNavigate?.('detections'); }}
                          className="px-3 py-1.5 text-sm rounded-md border border-[#d0d7de] text-[#1a2332] hover:bg-[#eef1f4]">Triage detections</button>
                        <span className="text-xs text-[#8b949e]">
                          {!selected.sealed ? 'Incident telemetry is still loading.' : `${selected.open_detections} detections still need review.`}
                        </span>
                      </>
                    )}
                    {isGuided && selected.sealed && (
                      <button onClick={beginCheck}
                        className="px-3 py-1.5 text-sm rounded-md border border-[#d0d7de] text-[#57606a] hover:bg-[#eef1f4]">Check Answer</button>
                    )}
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Submit / Check-Answer classifier flow (note-free per A1/C2). Both Submit
          and Guided Check Answer share the verdict/category pickers; the pending
          action routes the completed classification to submit or check. */}
      {showClassifier && pendingSubmit && (
        <ClassificationSelector isHardcore={gameMode === 'hardcore'}
          onSelect={(id) => {
            setShowClassifier(false);
            if (id === 'false_positive') {
              const p = { ...pendingSubmit, verdict: 'false_positive', category: 'False Positive' };
              setPendingSubmit(p);
              if (p.action === 'check') doCheck(p);
            } else { setPendingSubmit(p => ({ ...p, verdict: 'threat' })); setShowCategory(true); }
          }}
          onCancel={() => { setShowClassifier(false); setPendingSubmit(null); }} />
      )}
      {showCategory && pendingSubmit && (
        <CategorySelector isHardcore={gameMode === 'hardcore'} scenarioInfo={pendingSubmit}
          onSelect={(cid, clabel) => {
            setShowCategory(false);
            const p = { ...pendingSubmit, category: clabel };
            setPendingSubmit(p);
            if (p.action === 'check') doCheck(p);
          }}
          onCancel={() => { setShowCategory(false); setPendingSubmit(null); }} />
      )}
      {pendingSubmit && pendingSubmit.action === 'submit' && pendingSubmit.verdict && !showClassifier && !showCategory && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" role="dialog" aria-modal="true">
          <div className="bg-white rounded-xl border border-[#e2e6ea] shadow-xl w-full max-w-md overflow-hidden">
            <div className="h-0.5" style={{ background: 'linear-gradient(to right, #16436b, #101218)' }} />
            <div className="p-5">
              <h3 className="text-base font-semibold text-[#1a2332]">Submit incident {pendingSubmit.incident_id}</h3>
              <p className="mt-2 text-sm text-[#57606a]">Filing as <span className="font-medium text-[#1a2332]">{pendingSubmit.category}</span>. This locks your classification for this incident and reveals how it scored. You cannot change it afterward.</p>
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

      {/* Post-Incident Review (single implementation, D7) */}
      {review && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/70" onClick={() => setReview(null)} />
          <div className="relative bg-white border border-[#e2e6ea] rounded-xl shadow-2xl max-w-lg w-full max-h-[90vh] overflow-y-auto p-6 animate-modalIn">
            <div className="flex items-center justify-between">
              <div><p className="text-[11px] uppercase tracking-wider text-[#6e7781]">Incident Grade</p>
                <h2 className="text-lg font-semibold text-[#1a2332]">{review.incidentId}</h2></div>
              {review.assisted && <span className="text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-[#eef1f4] text-[#57606a] border border-[#d0d7de]">Assisted</span>}
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
            {review.triage?.what_is_it && (
              <div className="mt-4 pt-3 border-t border-[#eef1f4]">
                {review.triage.mitre && <p className="text-xs text-[#16436b] font-medium mb-1">{review.triage.mitre.id} · {review.triage.mitre.name}</p>}
                <p className="text-sm font-medium text-[#1a2332]">{review.triage.what_is_it.title}</p>
                <p className="text-sm text-[#57606a] mt-1 break-words">{review.triage.what_is_it.description}</p>
              </div>
            )}
            <div className="mt-5 flex justify-end gap-2">
              {isGuided && onPracticeAnother && (
                <button onClick={() => setPracticeWarn(true)}
                  className="px-4 py-2 text-sm rounded-md border border-[#d0d7de] text-[#1a2332] hover:bg-[#eef1f4]">Practice Another</button>
              )}
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
