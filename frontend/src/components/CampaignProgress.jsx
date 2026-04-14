import React, { useState, useEffect } from "react";

const CampaignProgress = ({ levelData, onReset, analystName }) => {
  const [ghostVisible, setGhostVisible] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => setGhostVisible(true), 100);
    return () => clearTimeout(timer);
  }, []);
  if (!levelData) return null;

  const { completed, current_level, total_levels, ticket_title, level_results = {} } = levelData;

  if (completed) {
    return (
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl sm:text-2xl font-semibold text-white">Simulation Complete</h2>
          <button
            onClick={onReset}
            className="px-2 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm font-medium rounded-md border transition focus:outline-none focus:ring-2 focus:ring-gray-500 bg-[#21262d] hover:bg-[#30363d] text-gray-200 border-gray-600"
          >
            <span className="sm:hidden">Reset Sim</span><span className="hidden sm:inline">Reset Simulation</span>
          </button>
        </div>
        <div className="mb-4" style={{ height: '1px', background: 'linear-gradient(to right, rgba(88,130,180,0.3), transparent)' }} />
        <div className={`flex flex-col items-center text-center transition-all duration-700 ease-out ${ghostVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}`}>
          <img
            src="/ghost-celebrate.png"
            alt="Ghost Celebrating"
            className="w-28 h-28 sm:w-40 sm:h-40 opacity-90 mb-3"
          />
          <p className="font-mono text-xs sm:text-sm text-gray-400 mb-6">&gt; Well done{analystName ? `, ${analystName}` : ''}. You've completed your simulation. The threats never stood a chance.</p>
        </div>
        {/* Level stepper with results */}
        <div className={`flex items-center justify-between px-4 sm:px-8 pt-10 pb-8 transition-all duration-700 delay-300 ease-out ${ghostVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}`}>
          {Array.from({ length: total_levels }).map((_, i) => {
            const level = i + 1;
            const result = level_results[level] ?? level_results[String(level)];
            const isCompleted = result !== undefined;
            const isCorrect = result === "correct" || result === true;
            const isLast = i === total_levels - 1;

            return (
              <React.Fragment key={level}>
                <div className="flex flex-col items-center">
                  <div
                    className={`w-9 h-9 sm:w-12 sm:h-12 rounded-full flex items-center justify-center text-sm sm:text-lg font-bold leading-none border-4 ${
                      isCompleted
                        ? isCorrect
                          ? "border-[#6fa868] text-white"
                          : "border-[#b26666] text-white"
                        : "border-gray-600 text-gray-500"
                    }`}
                  >
                    {isCompleted ? (
                      isCorrect ? (
                        <svg className="w-4 h-4 sm:w-6 sm:h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                        </svg>
                      ) : (
                        <svg className="w-4 h-4 sm:w-6 sm:h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      )
                    ) : (
                      <span>{level}</span>
                    )}
                  </div>
                </div>
                {!isLast && (
                  <div className="flex-1 mx-1 border-t-2 border-dashed border-gray-600" />
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl sm:text-2xl font-semibold text-white">Simulation Status</h2>
      </div>
      <div className="mb-6" style={{ height: '1px', background: 'linear-gradient(to right, rgba(88,130,180,0.3), transparent)' }} />

      {/* Level stepper */}
      <div className="flex items-center justify-between px-4 sm:px-8 pt-10 pb-8">
        {Array.from({ length: total_levels }).map((_, i) => {
          const level = i + 1;
          const result = level_results[level] ?? level_results[String(level)];
          const isCompleted = result !== undefined;
          const isCorrect = result === "correct" || result === true;
          const isCurrent = level === current_level && !completed;
          const isLast = i === total_levels - 1;

          // Line color: green if current level's previous is completed correctly
          const nextResult = level_results[level + 1] ?? level_results[String(level + 1)];
          const lineCompleted = isCompleted;

          return (
            <React.Fragment key={level}>
              <div className="flex flex-col items-center">
                <div
                  className={`w-9 h-9 sm:w-12 sm:h-12 rounded-full flex items-center justify-center text-sm sm:text-lg font-bold leading-none transition-all border-4 ${
                    isCompleted
                      ? isCorrect
                        ? "border-[#6fa868] text-white"
                        : "border-[#b26666] text-white"
                      : isCurrent
                      ? "border-[#d1d5db] text-white"
                      : "border-gray-600 text-gray-500"
                  }`}
                >
                  {isCompleted ? (
                    isCorrect ? (
                      <svg className="w-4 h-4 sm:w-6 sm:h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                    ) : (
                      <svg className="w-4 h-4 sm:w-6 sm:h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    )
                  ) : (
                    <span>{level}</span>
                  )}
                </div>
              </div>
              {!isLast && (
                <div className="flex-1 mx-1 border-t-2 border-dashed border-gray-600" />
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
};

export default CampaignProgress;
