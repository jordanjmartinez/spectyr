import React, { useState, useEffect, useCallback, useRef } from 'react';
import { apiFetch } from '../api';
import ClassificationSelector from './ClassificationSelector';
import CategorySelector from './CategorySelector';

// Stage 3.9B: the Incidents operational workspace ("what do I need to work?").
// Search + Active / Ready / Completed views, stable incident rows, and a
// selected-incident detail (briefing + phase strip) with the SINGLE home for the
// graded Submit / Resume controls (D2/D7). This retires the legacy Alerts ticket
// table and the global Notable Events queue (D3/D4): the player-facing object is
// the incident. Raw underlying events stay in SIEM (D4, unchanged).

const SEV_DOT = { Critical: '#b45858', High: '#c08a3e', Medium: '#c0a93e', Low: '#6fa868' };
const gradeColor = (g) => (!g || g === '-') ? '#8b949e' : g === 'F' ? '#b45858' : g === 'D' ? '#c08a3e' : '#6fa868';
const CARD = { background: '#fff', border: '1px solid #e2e6ea', boxShadow: '0 1px 2px rgba(0,0,0,0.04)' };

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
  activeIncidentId, onSelectIncident, onNavigate, setGroupedAlertCount,
}) => {
  const [data, setData] = useState({ active: [], completed: [], queue_length: 0, resolved_count: 0 });
  const [view, setView] = useState('active');    // 'active' | 'ready' | 'completed'
  const [search, setSearch] = useState('');

  const [showClassifier, setShowClassifier] = useState(false);
  const [showCategory, setShowCategory] = useState(false);
  const [pendingSubmit, setPendingSubmit] = useState(null);
  const [submitBusy, setSubmitBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const noticeTimer = useRef(null);

  const selectedId = activeIncidentId;
  const flash = (m) => { setNotice(m); if (noticeTimer.current) clearTimeout(noticeTimer.current); noticeTimer.current = setTimeout(() => setNotice(''), 4500); };

  const fetchList = useCallback(() => {
    apiFetch('/api/incidents').then(r => r.json()).then(d => {
      setData(d);
      setGroupedAlertCount?.((d.active || []).length);
    }).catch(() => {});
  }, [setGroupedAlertCount]);

  useEffect(() => { fetchList(); const iv = setInterval(fetchList, 3000); return () => clearInterval(iv); }, [fetchList]);

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
    setPendingSubmit({ incident_id: selected.incident_id, title: selected.title });
    setShowClassifier(true);
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
      setPendingSubmit(null);
      if (viewRes.hardcore_failure) { onHardcoreFailure?.(pendingSubmit.category); fetchList(); return; }
      fetchList();
    } catch { flash('This incident could not be submitted yet.'); }
    finally { setSubmitBusy(false); }
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
                  </div>
                  {selected.briefing && <p className="mt-1 text-sm text-[#57606a] break-words">{selected.briefing}</p>}
                </div>
              </div>

              <div className="pt-2 border-t border-[#eef1f4]">
                <PhaseStrip sealed={selected.state === 'submitted' ? true : selected.sealed}
                  triage={selected.triage} related={0} ready={selected.ready} />
              </div>

              {/* Graded controls (single home, D7) */}
              <div className="pt-3 border-t border-[#eef1f4] flex items-center gap-2 flex-wrap">
                {selected.state === 'submitted' ? (
                  <span className="text-sm text-[#57606a]">
                    Submitted · Incident Grade{' '}
                    <span className="font-medium" style={{ color: gradeColor(selected.incident_grade?.grade) }}>{selected.incident_grade?.grade || '-'}</span>
                  </span>
                ) : selected.sealed && selected.ready ? (
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
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Submit lifecycle (note-free per A1/C2) */}
      {showClassifier && pendingSubmit && (
        <ClassificationSelector isHardcore={gameMode === 'hardcore'}
          onSelect={(id) => {
            setShowClassifier(false);
            if (id === 'false_positive') { setPendingSubmit(p => ({ ...p, verdict: 'false_positive', category: 'False Positive' })); }
            else { setPendingSubmit(p => ({ ...p, verdict: 'threat' })); setShowCategory(true); }
          }}
          onCancel={() => { setShowClassifier(false); setPendingSubmit(null); }} />
      )}
      {showCategory && pendingSubmit && (
        <CategorySelector isHardcore={gameMode === 'hardcore'} scenarioInfo={pendingSubmit}
          onSelect={(cid, clabel) => { setShowCategory(false); setPendingSubmit(p => ({ ...p, category: clabel })); }}
          onCancel={() => { setShowCategory(false); setPendingSubmit(null); }} />
      )}
      {pendingSubmit && pendingSubmit.verdict && !showClassifier && !showCategory && (
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

      {notice && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 px-4 py-2 rounded-md bg-[#101218] text-white text-sm shadow-lg animate-modalIn">{notice}</div>
      )}
    </div>
  );
};

export default Incidents;
