import React, { useState, useEffect } from "react";

const CIRCLE_ROW_SIZE = 5;

const CampaignProgress = ({ levelData, onReset, analystName }) => {
  const [ghostVisible, setGhostVisible] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => setGhostVisible(true), 100);
    return () => clearTimeout(timer);
  }, []);
  if (!levelData) return null;

  const { completed, total_levels, ticket_title, level_results = {} } = levelData;

  const resultsInOrder = Object.values(level_results || {});

  const rowCount = Math.ceil((total_levels || 0) / CIRCLE_ROW_SIZE);
  const rows = Array.from({ length: rowCount }, (_, r) => {
    const start = r * CIRCLE_ROW_SIZE;
    const len = Math.min(CIRCLE_ROW_SIZE, total_levels - start);
    const levels = Array.from({ length: len }, (_, j) => start + j + 1);
    return r % 2 === 1 ? levels.slice().reverse() : levels;
  });

  const renderCircle = (level, showCurrent) => {
    const result = resultsInOrder[level - 1];
    const isCompleted = result !== undefined;
    const isCorrect = result === "correct" || result === true;
    const isCurrent = showCurrent && !isCompleted && !completed;

    return (
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
    );
  };

  const renderRow = (levels, rowIdx, showCurrent) => (
    <div key={`row-${rowIdx}`} className="flex items-center justify-between px-4 sm:px-8">
      {levels.map((level, j) => (
        <React.Fragment key={level}>
          {renderCircle(level, showCurrent)}
          {j < levels.length - 1 && (
            <div className="flex-1 mx-1 border-t-2 border-dashed border-gray-600" />
          )}
        </React.Fragment>
      ))}
    </div>
  );

  const renderVerticalConnector = (side, key) => (
    <div key={key} className={`flex ${side === 'right' ? 'justify-end' : 'justify-start'} px-4 sm:px-8 py-1`}>
      <div className="w-9 sm:w-12 flex justify-center">
        <div className="border-l-2 border-dashed border-gray-600 h-6 sm:h-8" />
      </div>
    </div>
  );

  const renderStepper = (showCurrent) =>
    rows.flatMap((rowLevels, i) => {
      const items = [renderRow(rowLevels, i, showCurrent)];
      if (i < rows.length - 1) {
        items.push(renderVerticalConnector(i % 2 === 0 ? 'right' : 'left', `conn-${i}`));
      }
      return items;
    });

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
        <div
          className="p-6 rounded-xl"
          style={{
            background: 'linear-gradient(#161b22, #161b22) padding-box, linear-gradient(to bottom, rgba(88,130,180,0.3), transparent) border-box',
            border: '1px solid transparent',
            boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05)',
          }}
        >
        <div className={`flex flex-col items-center text-center transition-all duration-700 ease-out ${ghostVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}`}>
          <img
            src="/ghost-celebrate.png"
            alt="Ghost Celebrating"
            className="w-28 h-28 sm:w-40 sm:h-40 opacity-90 mb-3"
          />
          <p className="font-mono text-xs sm:text-sm text-gray-400 mb-6">&gt;<span className="animate-blink">|</span> Well done{analystName ? `, ${analystName}` : ''}. You've completed your simulation. The threats never stood a chance.</p>
        </div>
        {/* Level stepper with results - snake/backwards-C layout */}
        <div className={`flex flex-col pt-5 pb-5 transition-all duration-700 delay-300 ease-out ${ghostVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}`}>
          {renderStepper(false)}
        </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl sm:text-2xl font-semibold text-white">Simulation</h2>
      </div>
      {/* Level stepper - snake/backwards-C layout */}
      <div
        className="flex flex-col pt-5 pb-5 rounded-xl"
        style={{
          background: 'linear-gradient(#161b22, #161b22) padding-box, linear-gradient(to bottom, rgba(88,130,180,0.3), transparent) border-box',
          border: '1px solid transparent',
          boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05)',
        }}
      >
        {renderStepper(true)}
      </div>
    </div>
  );
};

export default CampaignProgress;
