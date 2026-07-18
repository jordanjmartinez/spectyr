import React, { useState, useEffect, useCallback } from 'react';
import { apiFetch } from '../api';

// Option A (ruled at the 3b checkpoint): classification keeps the headline
// grade; Detections and Response render as independent scored sections.
// The Response card also surfaces failed attempts factually (count +
// entries, no editorial label); score-neutral by the standing rule.

const ACTION_LABELS = {
  isolate_host: 'Isolate Host',
  release_host: 'Release Host',
  kill_process: 'Kill Process',
  delete_file: 'Delete File',
  disable_account: 'Disable Account',
  revoke_sessions: 'Revoke Sessions',
  force_password_reset: 'Force Password Reset',
};

const Card = ({ children }) => (
  <div className="rounded-2xl" style={{ background: '#ffffff', border: '1px solid #e2e6ea', boxShadow: '0 1px 2px rgba(0,0,0,0.04)' }}>
    {children}
  </div>
);

const GradeBlock = ({ grade, accuracy, graded }) => (
  <div className="text-right shrink-0">
    <p className="text-4xl font-semibold text-[#1a2332] leading-none">{grade || '-'}</p>
    <p className="mt-1 text-xs text-[#6e7781]">
      {graded > 0 ? `${accuracy}% accuracy` : 'Not graded yet'}
    </p>
  </div>
);

const StatRow = ({ items }) => (
  <div className="flex flex-wrap gap-x-5 gap-y-1 text-sm text-[#57606a]">
    {items.map(([label, value]) => (
      <span key={label}>
        <span className="font-medium text-[#1a2332]">{value}</span> {label}
      </span>
    ))}
  </div>
);

const ScoreSections = ({ isVisible = true }) => {
  const [detScore, setDetScore] = useState(null);
  const [actScore, setActScore] = useState(null);

  const fetchScores = useCallback(() => {
    apiFetch('/api/analytics/detection_score')
      .then(res => res.json()).then(setDetScore).catch(() => {});
    apiFetch('/api/analytics/action_score')
      .then(res => res.json()).then(setActScore).catch(() => {});
  }, []);

  useEffect(() => {
    if (!isVisible) return;
    fetchScores();
    const interval = setInterval(fetchScores, 3000);
    return () => clearInterval(interval);
  }, [isVisible, fetchScores]);

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

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl sm:text-2xl font-semibold text-[#1a2332] mb-4">Detections</h2>
        <Card>
          <div className="p-4 sm:p-6 flex items-start justify-between gap-4">
            <div className="space-y-2">
              <p className="text-sm text-[#57606a]">Triage decisions against the detection feed.</p>
              <StatRow items={[
                ['correct', detScore?.correct ?? 0],
                ['wrong', detScore?.wrong ?? 0],
                ['open', detScore?.open ?? 0],
              ]} />
            </div>
            <GradeBlock grade={detScore?.grade} accuracy={detScore?.accuracy ?? 0} graded={detScore?.graded ?? 0} />
          </div>
        </Card>
      </div>

      <div>
        <h2 className="text-xl sm:text-2xl font-semibold text-[#1a2332] mb-4">Response</h2>
        <Card>
          <div className="p-4 sm:p-6 flex items-start justify-between gap-4">
            <div className="space-y-2 min-w-0">
              <p className="text-sm text-[#57606a]">Response actions against the incident scope.</p>
              <StatRow items={[
                ['required', actScore?.required ?? 0],
                ['correct', actScore?.correct ?? 0],
                ['missed', actScore?.missed ?? 0],
                ['collateral', actScore?.collateral ?? 0],
                ...(actScore?.order_violations ? [['out of order', actScore.order_violations]] : []),
              ]} />
            </div>
            <GradeBlock grade={actScore?.grade} accuracy={actScore?.accuracy ?? 0} graded={actScore?.graded ?? 0} />
          </div>
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
    </div>
  );
};

export default ScoreSections;
