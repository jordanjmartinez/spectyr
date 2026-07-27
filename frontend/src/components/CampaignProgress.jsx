import React, { useState, useEffect } from "react";
import { CARD_STYLE } from './ui';

const WIN_ART = `██╗   ██╗ ██████╗ ██╗   ██╗    ██╗    ██╗██╗███╗   ██╗██╗
╚██╗ ██╔╝██╔═══██╗██║   ██║    ██║    ██║██║████╗  ██║██║
 ╚████╔╝ ██║   ██║██║   ██║    ██║ █╗ ██║██║██╔██╗ ██║██║
  ╚██╔╝  ██║   ██║██║   ██║    ██║███╗██║██║██║╚██╗██║╚═╝
   ██║   ╚██████╔╝╚██████╔╝    ╚███╔███╔╝██║██║ ╚████║██╗
   ╚═╝    ╚═════╝  ╚═════╝      ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═╝`;

const PASS_ART = `██╗   ██╗ ██████╗ ██╗   ██╗    ██████╗  █████╗ ███████╗███████╗██╗
╚██╗ ██╔╝██╔═══██╗██║   ██║    ██╔══██╗██╔══██╗██╔════╝██╔════╝██║
 ╚████╔╝ ██║   ██║██║   ██║    ██████╔╝███████║███████╗███████╗██║
  ╚██╔╝  ██║   ██║██║   ██║    ██╔═══╝ ██╔══██║╚════██║╚════██║╚═╝
   ██║   ╚██████╔╝╚██████╔╝    ██║     ██║  ██║███████║███████║██╗
   ╚═╝    ╚═════╝  ╚═════╝     ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝`;

const LOSE_ART = `██╗   ██╗ ██████╗ ██╗   ██╗    ██╗      ██████╗ ███████╗███████╗██╗
╚██╗ ██╔╝██╔═══██╗██║   ██║    ██║     ██╔═══██╗██╔════╝██╔════╝██║
 ╚████╔╝ ██║   ██║██║   ██║    ██║     ██║   ██║███████╗█████╗  ██║
  ╚██╔╝  ██║   ██║██║   ██║    ██║     ██║   ██║╚════██║██╔══╝  ╚═╝
   ██║   ╚██████╔╝╚██████╔╝    ███████╗╚██████╔╝███████║███████║██╗
   ╚═╝    ╚═════╝  ╚═════╝     ╚══════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝`;

const gradeOf = (report) => report?.grade || '-';

// Segmented outcome bar: one cell per queue scenario, colored by result.
// Green = correct, red = missed, neutral = still pending.
const OutcomeBar = ({ total, results }) => {
  const resolved = results.length;
  const correctCount = results.filter((r) => r === 'correct' || r === true).length;
  const missedCount = resolved - correctCount;
  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm font-medium text-[#1a2332]">{resolved} of {total} resolved</span>
        {/* VF6 (owner mid-run instruction): the counts wear the SAME
            treatment as the Environment status online/offline line
            (IncidentDashboard): colored dot + medium-ink count + neutral
            label, verbatim classes and dot colors. */}
        <span className="text-sm text-[#57606a] flex items-center gap-1.5 whitespace-nowrap">
          <span aria-hidden="true" className="w-1.5 h-1.5 rounded-full" style={{ background: '#6fa868' }} />
          <span><span className="font-medium text-[#1a2332]">{correctCount}</span> correct</span>
          <span className="text-[#d0d7de]">·</span>
          <span aria-hidden="true" className="w-1.5 h-1.5 rounded-full" style={{ background: '#b45858' }} />
          <span><span className="font-medium text-[#1a2332]">{missedCount}</span> missed</span>
        </span>
      </div>
      <div className="flex items-center gap-1.5">
        {Array.from({ length: total }, (_, i) => {
          const r = results[i];
          const done = r !== undefined;
          const correct = r === 'correct' || r === true;
          const bg = done ? (correct ? '#6fa868' : '#b26666') : '#e2e6ea';
          const label = done ? `Scenario ${i + 1}: ${correct ? 'correct' : 'missed'}` : `Scenario ${i + 1}: pending`;
          return (
            <div
              key={i}
              title={label}
              className="h-3 flex-1 rounded-full transition-colors duration-500"
              style={{ backgroundColor: bg }}
            />
          );
        })}
      </div>
    </div>
  );
};

// Visual pass V10: this component no longer renders the page heading or
// its own Reset control -- the Metrics PageHeader (Analytics.jsx) owns
// both. Content (the outcome bar + the completed banner) is unchanged.
const CampaignProgress = ({ levelData, analystName, report }) => {
  const [revealed, setRevealed] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => setRevealed(true), 100);
    return () => clearTimeout(timer);
  }, []);
  if (!levelData) return null;

  const { completed, total_levels = 0, level_results = {} } = levelData;
  const results = Object.values(level_results || {});

  if (completed) {
    const grade = gradeOf(report);
    const useWin = grade === 'A' || grade === 'B' || grade === '-';
    const useFailed = grade === 'F';
    const banner = useWin ? WIN_ART : useFailed ? LOSE_ART : PASS_ART;
    const bannerLabel = useWin ? 'You Win!' : useFailed ? 'You Lose!' : 'You Pass!';
    const message = useWin
      ? `Well done${analystName ? `, ${analystName}` : ''}. You've completed your simulation. The threats never stood a chance.`
      : useFailed
        ? `Tough run${analystName ? `, ${analystName}` : ''}. Reset and run it back.`
        : `Not bad${analystName ? `, ${analystName}` : ''}. A few slipped by, but you held the line.`;
    return (
      <div>
        <div className="px-6 pt-8 pb-6 rounded-xl" style={CARD_STYLE}>
          <div className={`flex flex-col items-center text-center transition-all duration-700 ease-out ${revealed ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}`}>
            <pre
              aria-label={bannerLabel}
              className={`log-mono text-[7px] sm:text-[10px] leading-tight ${useFailed ? 'text-[#b45858]' : useWin ? 'text-[#58b458]' : 'text-[#8b949e]'} mb-3 select-none`}
            >
              {banner.split('').map((ch, i) =>
                ch === '█'
                  ? <span key={i} className="text-[#1a2332]">{ch}</span>
                  : ch
              )}
            </pre>
            {/* VT: the message is product copy (Inter); only the ASCII art
                banner above genuinely needs mono. */}
            <p className="text-sm text-[#57606a] mb-6"><span className="log-mono">&gt;<span className="animate-blink">|</span></span> {message}</p>
          </div>
          <div className={`pt-2 transition-all duration-700 delay-300 ease-out ${revealed ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}`}>
            <OutcomeBar total={total_levels} results={results} />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="rounded-xl p-5 sm:p-6" style={CARD_STYLE}>
        <OutcomeBar total={total_levels} results={results} />
      </div>
    </div>
  );
};

export default CampaignProgress;
