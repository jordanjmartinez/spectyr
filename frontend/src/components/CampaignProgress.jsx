import React from "react";

const CampaignProgress = ({ levelData }) => {
  if (!levelData) return null;

  const { completed, current_level, total_levels, ticket_title, level_results = {} } = levelData;

  return (
    <div className="bg-[#161b22] p-6 rounded-2xl border border-gray-700 shadow-md">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-semibold text-white">Level Progress</h2>
        <span className="text-sm text-gray-400">
          {Object.keys(level_results).length} / {total_levels} completed
        </span>
      </div>

      {/* Level stepper */}
      <div className="flex items-center justify-between">
        {Array.from({ length: total_levels }).map((_, i) => {
          const level = i + 1;
          const result = level_results[level] ?? level_results[String(level)];
          const isCompleted = result !== undefined;
          const isCorrect = result === "correct" || result === true;
          const isPartial = result === "partial";
          const isCurrent = level === current_level && !completed;
          const isLast = i === total_levels - 1;

          // Line color: green if current level's previous is completed correctly
          const nextResult = level_results[level + 1] ?? level_results[String(level + 1)];
          const lineCompleted = isCompleted;

          return (
            <React.Fragment key={level}>
              <div className="flex flex-col items-center">
                <div
                  className={`w-12 h-12 rounded-full flex items-center justify-center text-lg font-bold leading-none transition-all border-4 ${
                    isCompleted
                      ? isCorrect
                        ? "border-emerald-500 bg-emerald-700 text-white"
                        : isPartial
                        ? "border-yellow-500 bg-yellow-600 text-white"
                        : "border-red-500 bg-red-700 text-white"
                      : isCurrent
                      ? "border-blue-500 bg-gray-700 text-white"
                      : "border-gray-600 bg-gray-700 text-gray-500"
                  }`}
                >
                  {isCompleted ? (
                    isCorrect ? (
                      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                    ) : isPartial ? (
                      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 12H4" />
                      </svg>
                    ) : (
                      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
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
