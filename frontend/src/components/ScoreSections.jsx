import React from 'react';
import { ACTION_LABELS } from './uiCopy';
import { Card } from './ui';

// Stage 3d composite ruling, compacted by the Final pass (III.0 item 6):
// the three large vertical Classification / Detections / Response grade
// cards become ONE compact responsive summary -- the Overall (composite)
// grade shown once, then three equal columns with the SAME values and
// calculations as before (component grade, accuracy, counts). Columns
// stack on small screens; DOM order (Overall, Classification, Detections,
// Response) matches the visual reading order. The detailed teaching
// sections (the factual Response attempt blocks) remain beneath the
// summary; no distinct grading information was removed.
//
// Stage 3.9A: all values read from the SUBMISSION-GATED report prop
// (report.detection / report.response / report.composite, aggregated over
// submitted incidents); nothing here polls a score endpoint.

// Visual pass VG: the card surface comes from the shared module.

const StatRow = ({ items }) => (
  <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm text-[#57606a]">
    {items.map(([label, value]) => (
      <span key={label}>
        <span className="font-medium text-[#1a2332]">{value}</span> {label}
      </span>
    ))}
  </div>
);

const ScoreSections = ({ isVisible = true, report = null }) => {
  const detScore = report?.detection ?? null;
  const actScore = report?.response ?? null;
  const composite = report?.composite ?? null;

  const notExecuted = actScore?.not_executed;
  const noEffect = actScore?.no_effect;
  const acceptableTaken = actScore?.acceptable_taken;

  const FactualBlock = ({ title, entries }) => (
    <div className="border-t border-[#eef1f4] px-4 sm:px-6 py-4">
      <p className="text-[11px] uppercase tracking-wider text-[#6e7781] font-medium mb-2">{title}</p>
      <ul className="space-y-1.5">
        {entries.map(e => (
          <li key={e.seq} className="text-sm text-[#57606a]">
            <span className="text-[#1a2332]">{ACTION_LABELS[e.action] || e.action}</span>
            {' '}<span className="font-mono">{e.target?.label}</span>
            {e.reason ? `: ${e.reason}` : ''}
          </li>
        ))}
      </ul>
    </div>
  );

  const clsComp = composite?.components?.classification;

  const columns = [
    {
      name: 'Classification',
      desc: 'Threat vs false-positive calls and attack category.',
      grade: clsComp?.grade, accuracy: clsComp?.accuracy ?? 0, graded: clsComp?.graded ?? 0,
      items: [
        ['threats caught', report?.threats_caught ?? 0],
        ['wrong category', report?.wrong_category ?? 0],
        ['FP caught', report?.fp_identified ?? 0],
        ['FP missed', report?.fp_missed ?? 0],
      ],
    },
    {
      name: 'Detections',
      desc: 'Triage decisions against the detection feed.',
      grade: detScore?.grade, accuracy: detScore?.accuracy ?? 0, graded: detScore?.graded ?? 0,
      items: [
        ['correct', detScore?.correct ?? 0],
        ['wrong', detScore?.wrong ?? 0],
        ['open', detScore?.open ?? 0],
      ],
    },
    {
      name: 'Response',
      desc: 'Response actions against the incident scope.',
      grade: actScore?.grade, accuracy: actScore?.accuracy ?? 0, graded: actScore?.graded ?? 0,
      items: [
        ['required', actScore?.required ?? 0],
        ['correct', actScore?.correct ?? 0],
        ['missed', actScore?.missed ?? 0],
        ['collateral', actScore?.collateral ?? 0],
        ...(actScore?.order_violations ? [['out of order', actScore.order_violations]] : []),
      ],
    },
  ];

  return (
    <div>
      <h2 className="text-xl sm:text-2xl font-semibold text-[#1a2332] mb-4">Score Summary</h2>
      <Card>
        <div className="p-4 sm:p-6">
          {/* the Overall grade, exactly once */}
          <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 pb-4 border-b border-[#eef1f4]">
            <p className="text-sm font-medium text-[#1a2332]">Overall grade</p>
            <p className="text-right">
              <span className="text-3xl font-semibold text-[#1a2332] leading-none">{composite?.grade || '-'}</span>
              <span className="ml-2 text-xs text-[#6e7781]">
                {composite?.accuracy != null ? `${composite.accuracy}% accuracy` : 'Not graded yet'}
              </span>
            </p>
          </div>
          {/* three equal columns; stacked on small screens in the same order */}
          <div className="grid grid-cols-1 sm:grid-cols-3 divide-y sm:divide-y-0 sm:divide-x divide-[#eef1f4]">
            {columns.map((col) => (
              <div key={col.name} className="py-4 sm:py-2 sm:px-5 sm:first:pl-0 sm:last:pr-0 space-y-2">
                <div className="flex items-baseline justify-between gap-2">
                  <p className="text-sm font-semibold text-[#1a2332]">{col.name}</p>
                  <p className="text-right shrink-0">
                    <span className="text-2xl font-semibold text-[#1a2332] leading-none">{col.grade || '-'}</span>
                    <span className="ml-1.5 text-xs text-[#6e7781]">
                      {col.graded > 0 ? `${col.accuracy}% accuracy` : 'Not graded yet'}
                    </span>
                  </p>
                </div>
                <p className="text-xs text-[#6e7781]">{col.desc}</p>
                <StatRow items={col.items} />
              </div>
            ))}
          </div>
        </div>
        {/* the detailed teaching sections remain beneath the summary */}
        {acceptableTaken?.count > 0 && (
          <FactualBlock title={`Acceptable response (${acceptableTaken.count})`}
                        entries={acceptableTaken.entries} />
        )}
        {notExecuted?.count > 0 && (
          <FactualBlock title={`Attempted, not executed (${notExecuted.count})`}
                        entries={notExecuted.entries} />
        )}
        {noEffect?.count > 0 && (
          <FactualBlock title={`No effect, already in state (${noEffect.count})`}
                        entries={noEffect.entries} />
        )}
      </Card>
    </div>
  );
};

export default ScoreSections;
