import React, { useState, useEffect } from "react";
import { apiFetch } from '../api';

const ActionHistory = ({ history }) => {
  const [triageReviews, setTriageReviews] = useState({});
  const [expandedItems, setExpandedItems] = useState({});

  // Fetch triage review data for each unique scenario_label
  useEffect(() => {
    if (!history || history.length === 0) return;

    const fetchTriageReviews = async () => {
      const uniqueLabels = [...new Set(history.map(item => item.scenario_label).filter(Boolean))];

      for (const label of uniqueLabels) {
        if (triageReviews[label]) continue; // Already fetched

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
    setExpandedItems(prev => ({ ...prev, [index]: !prev[index] }));
  };

  if (!history || history.length === 0) {
    return (
      <div>
        <h2 className="text-xl sm:text-2xl font-semibold text-white mb-4">Post-Incident Review</h2>
        <div className="flex flex-col items-center justify-center py-8 min-h-[320px]">
          <img src="/ghost_analytics.png" alt="Ghost Analyzing" className="w-28 h-28 sm:w-40 sm:h-40 opacity-90 mb-3" />
          <p className="font-mono text-sm text-gray-400 text-center sm:text-left">&gt; Your post-incident review will appear after your first triage.</p>
        </div>
      </div>
    );
  }

  return (
    <div>
      <h2 className="text-xl sm:text-2xl font-semibold text-white mb-4">Post-Incident Review</h2>

      <div className="space-y-3">
        {history.map((item, index) => {
          const review = triageReviews[item.scenario_label];
          const isExpanded = expandedItems[index];

          return (
            <div
              key={index}
              className={`bg-[#161b22] p-4 sm:p-6 rounded-2xl border border-gray-700 shadow-md transition-all duration-200 ${review ? 'cursor-pointer hover:border-gray-500' : ''}`}
              onClick={() => review && toggleExpanded(index)}
            >
              <div>
                <div>
                  {/* Level + Ghost */}
                  <div className="flex items-center gap-2 mb-2">
                    {item.level && (
                      <>
                        <img
                          src={`/ghost_level_${item.level}.${item.level === 3 ? 'png' : 'PNG'}`}
                          alt={`Level ${item.level}`}
                          className="w-[72px] h-[72px] sm:w-24 sm:h-24 opacity-90"
                        />
                        <span className="text-gray-400 text-sm sm:text-base font-medium">Level {item.level}</span>
                      </>
                    )}
                  </div>

                  {/* Classification result */}
                  <div className="text-sm sm:text-base mb-3 flex flex-col sm:flex-row sm:items-center gap-0.5 sm:gap-0">
                    <span>
                      <span className="text-gray-400">Classified as </span>
                      <span className={item.correct ? 'text-emerald-400 font-medium' : 'text-red-400 font-medium'}>{item.user_choice}</span>
                    </span>
                    {!item.correct && (
                      <span>
                        <span className="text-gray-600 mx-2 hidden sm:inline">|</span>
                        <span className="text-gray-400">Correct: </span>
                        <span className="text-emerald-400 font-medium">{item.true_category}</span>
                      </span>
                    )}
                  </div>

                  {/* MITRE ATT&CK Badge */}
                  {review?.mitre && (
                    <a
                      href={review.mitre.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      onClick={(e) => e.stopPropagation()}
                      className="inline-flex items-center gap-2 bg-gray-800 text-gray-300 text-xs sm:text-sm px-3 py-1.5 rounded-md border border-gray-600 hover:bg-gray-700 transition-colors"
                      style={{ fontFamily: "'Inter', sans-serif" }}
                    >
                      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke="currentColor" strokeWidth="2" fill="none"/>
                      </svg>
                      <span className="font-semibold">{review.mitre.id}</span>
                      <span className="text-gray-500">|</span>
                      <span>{review.mitre.name}</span>
                    </a>
                  )}
                </div>
              </div>

              {/* Expanded Content */}
              {review && (
                <div className={`grid transition-all duration-300 ease-in-out ${
                  isExpanded ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
                }`}>
                  <div className="overflow-hidden min-h-0">
                    <div className="mt-5 space-y-5">
                      {/* What Is It - Callout card */}
                      {review.what_is_it && (
                        <div>
                          <h4 className="text-base sm:text-lg text-white font-semibold mb-3">
                            What is {review.what_is_it.title.replace(/\s*\(.*?\)/g, '')}?
                          </h4>
                          <div className="bg-[#161b22] border border-gray-700 rounded-xl p-4 sm:p-5 shadow">
                            <p className="text-sm sm:text-base text-gray-300 leading-relaxed">
                              {review.what_is_it.description}
                            </p>
                          </div>
                        </div>
                      )}

                      {/* Legacy indicators support */}
                      {!review.what_is_it && review.indicators && review.indicators.length > 0 && (
                        <div className="rounded-lg border border-gray-700 bg-[#1c2129] overflow-hidden">
                          <div className="border-l-4 border-yellow-500 px-4 sm:px-5 py-4">
                            <h4 className="text-sm sm:text-base text-yellow-400 font-semibold uppercase tracking-wider mb-3">
                              Why This Was Suspicious
                            </h4>
                            <ul className="space-y-1.5">
                              {review.indicators.map((ind, i) => (
                                <li key={i} className="text-sm sm:text-base">
                                  <span className="text-white font-medium">{ind.indicator}</span>
                                  <span className="text-gray-500 mx-1">—</span>
                                  <span className="text-gray-400">{ind.explanation}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      )}

                      {/* Response Actions - Stepper */}
                      {review.response_actions && review.response_actions.length > 0 && (
                        <div>
                          <h4 className="text-base sm:text-lg text-white font-semibold mb-3">
                            Playbook
                          </h4>
                          <div className="space-y-2">
                            {review.response_actions.map((action, i) => (
                              <div key={i} className="flex items-start gap-3 bg-[#161b22] border border-gray-700 rounded-xl p-4 sm:p-5 shadow">
                                <span className="flex-shrink-0 w-6 h-6 rounded-full bg-gray-700 text-gray-300 text-xs font-bold flex items-center justify-center mt-0.5">
                                  {i + 1}
                                </span>
                                <span className="text-sm sm:text-base text-gray-300 leading-relaxed">{action}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default ActionHistory;
