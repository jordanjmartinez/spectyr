import React, { useState, useEffect } from "react";

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
          const response = await fetch(`http://localhost:5000/api/triage-review/${label}`);
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
      <div className="bg-[#161b22] p-6 rounded-2xl border border-gray-700 shadow-md">
        <h2 className="text-2xl font-semibold text-white mb-4">Triage Review</h2>
        <div className="flex flex-col items-center justify-center py-8 min-h-[320px]">
          <img src="/ghost_analytics.png" alt="Ghost Analyzing" className="w-40 h-40 opacity-90 mb-3" />
          <p className="font-mono text-sm text-gray-400">&gt; Your triage decisions and learning details appear here.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-[#161b22] p-6 rounded-2xl border border-gray-700 shadow-md">
      <h2 className="text-2xl font-semibold text-white mb-4">Triage Review</h2>

      <div className="divide-y divide-gray-800">
        {history.map((item, index) => {
          const review = triageReviews[item.scenario_label];
          const isExpanded = expandedItems[index];

          return (
            <div key={index} className="py-4 first:pt-0 last:pb-0">
              {/* Clickable Header */}
              <div
                className={`flex justify-between items-start ${review ? 'cursor-pointer' : ''} rounded-lg p-2 -m-2`}
                onClick={() => review && toggleExpanded(index)}
              >
                <div>
                  {/* Tags and Details */}
                  <div className="flex items-center gap-2 mb-3 flex-wrap">
                    {item.level && (
                      <span className="inline-flex items-center bg-gray-800/80 text-gray-200 text-xs px-2.5 py-1 rounded-md uppercase font-semibold tracking-wider border border-gray-700">
                        Level {item.level}
                      </span>
                    )}
                    <span className={`w-8 h-8 rounded-full flex items-center justify-center ${
                      item.correct
                        ? "bg-emerald-500/20 text-emerald-400 border-2 border-emerald-500/30"
                        : "bg-red-500/20 text-red-400 border-2 border-red-500/30"
                    }`}>
                      {item.correct ? (
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                        </svg>
                      ) : (
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      )}
                    </span>
                    <span className="text-lg text-gray-400">
                      You chose: <span className="text-white">{item.user_choice}</span>
                      <span className="text-gray-600 mx-2">|</span>
                      Answer: <span className="text-white">{item.true_category}</span>
                    </span>
                  </div>

                  {/* MITRE ATT&CK Badge */}
                  {review?.mitre && (
                    <a
                      href={review.mitre.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      onClick={(e) => e.stopPropagation()}
                      className="inline-flex items-center gap-2 bg-gray-800 text-gray-300 text-xs px-3 py-1.5 rounded-md border border-gray-600 hover:bg-gray-700 transition-colors"
                      style={{ fontFamily: "'Consolas', sans-serif" }}
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

                {/* Chevron */}
                {review && (
                  <svg
                    className={`w-5 h-5 text-gray-500 hover:text-white transition-transform duration-300 ease-in-out flex-shrink-0 mt-1 ${
                      isExpanded ? 'rotate-180' : 'rotate-0'
                    }`}
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                )}
              </div>

              {/* Expanded Content */}
              {review && (
                <div className={`grid transition-all duration-300 ease-in-out ${
                  isExpanded ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
                }`}>
                  <div className="overflow-hidden min-h-0">
                    <div className="mt-5 divide-y divide-gray-700">
                      {/* What Is It - Educational explanation */}
                      {review.what_is_it && (
                        <div className="pb-5">
                          <h4 className="text-xl text-white font-semibold mb-2" style={{ fontFamily: "'Open Sans', sans-serif" }}>
                            What is {review.what_is_it.title}?
                          </h4>
                          <p className="text-sm text-gray-200 font-medium" style={{ fontFamily: "'Open Sans', sans-serif", lineHeight: '1.7' }}>
                            {review.what_is_it.description}
                          </p>
                        </div>
                      )}

                      {/* Legacy indicators support */}
                      {!review.what_is_it && review.indicators && review.indicators.length > 0 && (
                        <div className="pb-5">
                          <h4 className="text-xl uppercase tracking-wider text-gray-400 font-semibold mb-2">
                            Why This Was Suspicious
                          </h4>
                          <ul className="space-y-1.5">
                            {review.indicators.map((ind, i) => (
                              <li key={i} className="text-base">
                                <span className="text-white font-medium">{ind.indicator}</span>
                                <span className="text-gray-500 mx-1">—</span>
                                <span className="text-gray-400">{ind.explanation}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Response Actions */}
                      {review.response_actions && review.response_actions.length > 0 && (
                        <div className="pt-5">
                          <h4 className="text-xl text-white font-semibold mb-2" style={{ fontFamily: "'Open Sans', sans-serif" }}>
                            Response Actions
                          </h4>
                          <ol className="space-y-2 list-decimal list-inside text-sm" style={{ fontFamily: "'Open Sans', sans-serif", lineHeight: '1.7' }}>
                            {review.response_actions.map((action, i) => (
                              <li key={i} className="text-sm text-gray-200 font-medium">
                                {action}
                              </li>
                            ))}
                          </ol>
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
