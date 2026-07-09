import React, { useEffect, useState } from 'react';
import { apiFetch } from '../api';

// Immediate post-classification feedback shown in Training mode. Fetches the
// scenario's triage review and renders the verdict + MITRE + playbook so the
// analyst learns at the decision point instead of hunting the Metrics tab.
const TriageFeedback = ({ result, onClose }) => {
  const [review, setReview] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    if (!result?.scenario_label) {
      setLoading(false);
      return;
    }
    apiFetch(`/api/triage-review/${result.scenario_label}`)
      .then(res => (res.ok ? res.json() : null))
      .then(data => { if (!cancelled) { setReview(data); setLoading(false); } })
      .catch(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [result]);

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' || e.key === 'Enter') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  if (!result) return null;
  const { correct, selected_category, correct_category } = result;
  const accent = correct ? '#6fa868' : '#b26666';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70" onClick={onClose} />
      <div className="relative bg-[#161b22] border border-gray-700 rounded-xl shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto animate-modalIn">
        {/* Verdict header */}
        <div className="px-6 py-5 flex items-center gap-4">
          <span
            className="w-10 h-10 rounded-full inline-flex items-center justify-center border-[3px] text-white shrink-0"
            style={{ borderColor: accent }}
          >
            {correct ? (
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
            ) : (
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            )}
          </span>
          <div className="min-w-0">
            <h2 className="text-lg sm:text-xl font-semibold text-white">
              {correct ? 'Correct classification' : 'Not quite'}
            </h2>
            <p className="text-sm text-gray-400 mt-0.5">
              You classified as <span className="text-gray-200 font-medium">{selected_category}</span>
              {!correct && correct_category && (
                <> · Actual: <span style={{ color: accent }} className="font-medium">{correct_category}</span></>
              )}
            </p>
          </div>
        </div>
        <div style={{ height: '1px', background: 'linear-gradient(to right, rgba(240,246,252,0.1), transparent)' }} />

        {/* Triage review */}
        <div className="px-6 py-5">
          {loading ? (
            <p className="text-sm text-gray-400">Loading triage review…</p>
          ) : review ? (
            <>
              {review.mitre && (
                <div className="mb-4">
                  <span className="text-sm sm:text-base text-white font-medium">MITRE ATT&CK</span>
                  <div className="mt-1">
                    <a
                      href={review.mitre.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-2 bg-[#21262d] text-gray-300 text-xs sm:text-sm px-3 py-1.5 rounded-md border border-gray-700 hover:bg-[#30363d] transition-colors"
                      style={{ fontFamily: "'Inter', sans-serif" }}
                    >
                      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke="currentColor" strokeWidth="2" fill="none" />
                      </svg>
                      <span className="font-semibold">{review.mitre.id}</span>
                      <span className="text-gray-500">|</span>
                      <span>{review.mitre.name}</span>
                    </a>
                  </div>
                </div>
              )}
              {review.what_is_it && (
                <div className="mb-4">
                  <span className="text-sm sm:text-base text-white font-medium">{review.what_is_it.title}</span>
                  <p className="text-gray-300 mt-2 leading-relaxed text-sm sm:text-base break-words">
                    {review.what_is_it.description}
                  </p>
                </div>
              )}
              {review.response_actions?.length > 0 && (
                <div>
                  <span className="text-sm sm:text-base text-white font-medium">Playbook</span>
                  <div className="mt-2">
                    {review.response_actions.map((action, i) => {
                      const isFirst = i === 0;
                      const isLast = i === review.response_actions.length - 1;
                      return (
                        <div key={i} className="flex gap-3">
                          <div className="relative w-3 flex-shrink-0 self-stretch">
                            {!isFirst && <div className="absolute left-1/2 -translate-x-1/2 w-px bg-gray-600" style={{ top: 0, bottom: '50%' }} />}
                            {!isLast && <div className="absolute left-1/2 -translate-x-1/2 w-px bg-gray-600" style={{ top: '50%', bottom: 0 }} />}
                            <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-2 h-2 rotate-45 border border-gray-500 bg-[#161b22]" />
                          </div>
                          <p className="text-sm sm:text-base text-gray-300 py-1.5">{action}</p>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </>
          ) : (
            <p className="text-sm text-gray-300">Triage review not available for this scenario.</p>
          )}
        </div>

        <div className="px-6 pb-6 flex justify-end">
          <button
            onClick={onClose}
            className="inline-flex items-center justify-center px-5 py-2 text-sm font-medium rounded-md bg-[#f0f6fc] hover:bg-white text-[#0d1117] border border-transparent transition focus:outline-none focus:ring-2 focus:ring-[#8b949e]"
          >
            Continue
          </button>
        </div>
      </div>
    </div>
  );
};

export default TriageFeedback;
