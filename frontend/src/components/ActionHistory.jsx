import React, { useState, useEffect } from "react";
import { apiFetch } from '../api';

const ActionHistory = ({ history: rawHistory }) => {
  const history = Array.isArray(rawHistory) ? rawHistory : [];
  const [triageReviews, setTriageReviews] = useState({});
  const [expandedItems, setExpandedItems] = useState(new Set());

  // Fetch triage review data for each unique scenario_label
  useEffect(() => {
    if (!history || history.length === 0) return;

    const fetchTriageReviews = async () => {
      const uniqueLabels = [...new Set(
        history
          .map(item => item.scenario_label)
          .filter(Boolean)
      )];

      for (const label of uniqueLabels) {
        if (triageReviews[label]) continue;

        try {
          const response = await apiFetch(`/api/triage-review/${label}`);
          if (response.ok) {
            const data = await response.json();
            setTriageReviews(prev => ({ ...prev, [label]: data }));
          }
        } catch (error) {
          console.error(`Failed to fetch triage review for ${label}:`, error);
        }
      }
    };

    fetchTriageReviews();
  }, [history]);

  const toggleExpanded = (index) => {
    setExpandedItems(prev => {
      const next = new Set(prev);
      next.has(index) ? next.delete(index) : next.add(index);
      return next;
    });
  };

  if (!history || history.length === 0) {
    return (
      <div>
        <h2 className="text-xl sm:text-2xl font-semibold text-white mb-4">Post-Incident Review</h2>
        <div
          className="p-3 sm:p-6 rounded-xl"
          style={{
            background: 'linear-gradient(#161b22, #161b22) padding-box, linear-gradient(to bottom, rgba(88,130,180,0.3), transparent) border-box',
            border: '1px solid transparent',
            boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05)',
          }}
        >
          <div className="flex flex-col items-center justify-center py-8 min-h-[320px]">
            <img src="/ghost_analytics.png" alt="Ghost Analyzing" className="w-28 h-28 sm:w-40 sm:h-40 opacity-90 mb-3" />
            <p className="font-mono text-xs sm:text-sm text-gray-400 text-center sm:text-left">&gt; Your post-incident review will appear after your first triage.</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <h2 className="text-xl sm:text-2xl font-semibold text-white mb-4">Post-Incident Review</h2>

      <div
        className="p-3 sm:p-6 rounded-xl"
        style={{
          background: 'linear-gradient(#161b22, #161b22) padding-box, linear-gradient(to bottom, rgba(88,130,180,0.3), transparent) border-box',
          border: '1px solid transparent',
          boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05)',
        }}
      >
        <div className="overflow-x-auto overflow-y-hidden mobile-scroll-wrapper">
          <table className="w-full min-w-[600px] log-text text-left text-gray-300 border-separate border-spacing-0">
          <thead>
            <tr className="text-xs sm:text-sm uppercase text-gray-400 tracking-wider">
              <th className="w-10 px-2 sm:px-4 py-3 font-medium"></th>
              <th className="w-12 px-1 sm:px-2 py-3 font-medium"></th>
              <th className="w-full px-2 sm:px-4 py-3 font-medium">Title</th>
              <th className="px-2 sm:px-4 py-3 font-medium text-center">Result</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700">
            {history.map((item, index) => {
              const review = triageReviews[item.scenario_label];
              const isExpanded = expandedItems.has(index);
              const resultLabel = item.correct ? 'Correct' : 'Missed';

              return (
                <React.Fragment key={index}>
                  <tr
                    className="hover:bg-white/5 transition-colors cursor-pointer border-b border-gray-700/50"
                    onClick={() => toggleExpanded(index)}
                  >
                    <td className="w-10 pl-0 pr-1 sm:pr-2 py-4">
                      <svg
                        className={`w-5 h-5 text-gray-500 hover:text-white transition-transform duration-300 ease-in-out ${
                          isExpanded ? 'rotate-180' : 'rotate-0'
                        }`}
                        fill="none" stroke="currentColor" viewBox="0 0 24 24"
                      >
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                      </svg>
                    </td>
                    <td className="w-12 px-1 sm:px-2 py-4 text-center">
                      <span className={`w-6 h-6 sm:w-7 sm:h-7 rounded-full inline-flex items-center justify-center border-[3px] ${
                        item.correct ? 'border-[#6fa868]' : 'border-[#b26666]'
                      } text-white`}>
                        {item.correct ? (
                          <svg className="w-3.5 h-3.5 sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                          </svg>
                        ) : (
                          <svg className="w-3.5 h-3.5 sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                          </svg>
                        )}
                      </span>
                    </td>
                    <td className="px-2 sm:px-4 py-4">
                      <p className="text-sm sm:text-base font-medium text-gray-200 whitespace-nowrap">
                        {review?.what_is_it?.title || item.true_category || 'Unknown'}
                      </p>
                    </td>
                    <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-center">
                      <span className="text-gray-300">{resultLabel}</span>
                    </td>
                  </tr>
                  <tr>
                    <td colSpan="4" className="p-0">
                      <div className={`grid transition-all duration-300 ease-in-out ${
                        isExpanded ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
                      }`}>
                        <div className="overflow-hidden min-h-0">
                          <div className="border-t border-gray-700 px-6 py-4">
                            <div className="mb-4">
                              <span className="text-sm sm:text-base text-white font-medium">Classification</span>
                              <p className="text-gray-300 mt-1 text-sm sm:text-base">{item.true_category}</p>
                            </div>
                            {review ? (
                              <>
                                {review.mitre && (
                                  <div className="mb-4">
                                    <span className="text-sm sm:text-base text-white font-medium">MITRE ATT&CK</span>
                                    <div className="mt-1">
                                      <a
                                        href={review.mitre.url}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        onClick={(e) => e.stopPropagation()}
                                        className="inline-flex items-center gap-2 bg-[#21262d] text-gray-300 text-xs sm:text-sm px-3 py-1.5 rounded-md border border-gray-700 hover:bg-[#30363d] transition-colors"
                                        style={{ fontFamily: "'Inter', sans-serif" }}
                                      >
                                        <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                                          <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke="currentColor" strokeWidth="2" fill="none"/>
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
                                    <span className="text-sm sm:text-base text-white font-medium">Description</span>
                                    <p className="text-gray-300 mt-2 leading-relaxed text-sm sm:text-base break-words">{review.what_is_it.description}</p>
                                  </div>
                                )}
                                {!review.what_is_it && review.indicators && review.indicators.length > 0 && (
                                  <div className="mb-4">
                                    <span className="text-sm sm:text-base text-white font-medium">Why This Was Suspicious</span>
                                    <div className="mt-2 space-y-1.5">
                                      {review.indicators.map((ind, i) => (
                                        <p key={i} className="text-sm sm:text-base text-gray-300">
                                          <span className="text-white font-medium">{ind.indicator}</span>
                                          <span className="text-gray-500 mx-1">—</span>
                                          {ind.explanation}
                                        </p>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                {review.response_actions && review.response_actions.length > 0 && (
                                  <div>
                                    <span className="text-sm sm:text-base text-white font-medium">Playbook</span>
                                    <div className="mt-2">
                                      {review.response_actions.map((action, i) => {
                                        const isFirst = i === 0;
                                        const isLast = i === review.response_actions.length - 1;
                                        return (
                                          <div key={i} className="flex gap-3">
                                            <div className="relative w-3 flex-shrink-0 self-stretch">
                                              {!isFirst && (
                                                <div className="absolute left-1/2 -translate-x-1/2 w-px bg-gray-600" style={{ top: 0, bottom: '50%' }} />
                                              )}
                                              {!isLast && (
                                                <div className="absolute left-1/2 -translate-x-1/2 w-px bg-gray-600" style={{ top: '50%', bottom: 0 }} />
                                              )}
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
                              <p className="text-sm sm:text-base text-gray-300 leading-relaxed">Triage review not yet available for this scenario.</p>
                            )}
                          </div>
                        </div>
                      </div>
                    </td>
                  </tr>
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
        </div>
      </div>
    </div>
  );
};

export default ActionHistory;
