import React from 'react';
import { CARD_STYLE } from './ui';
import { LOAD_NEW_EVENTS, newEventsAvailable, TELEMETRY_LOADING } from './uiCopy';
import {
  bucketEvidence, evidenceSummary, evidencePeak,
} from './evidenceBuckets';

// ============================================================================
// VB1 (amendment section 2): Evidence activity -- the dashboard's primary
// visualization. Observable event arrival volume for the ACTIVE incident.
//
// Factual volume only. The highlighted interval is the busiest one; it is
// never called an anomaly, never implies malice, and never marks
// answer-key attack timing. The chart renders the FROZEN snapshot the
// card holds; later evidence is announced as a waiting count and only
// enters on the player's explicit Load new events (never automatically).
// ============================================================================

export const NO_INCIDENT = 'Start an investigation to see evidence activity.';
export const NO_EVENTS = 'No evidence observed yet.';

const Frame = ({ children }) => (
  <div className="rounded-xl min-w-0 h-full flex flex-col" style={CARD_STYLE} data-testid="evidence-activity">
    <div className="px-4 pt-4">
      <p className="t-subsection">Evidence activity</p>
      <p className="t-meta text-[#6e7781]">Event volume during this investigation</p>
    </div>
    {children}
  </div>
);

const EvidenceActivity = ({
  incidentId = null,
  snapshot = null,      // {rows, count, identity} | null
  loading = false,
  newCount = 0,
  onLoadNewEvents = null,
}) => {
  if (!incidentId) {
    return <Frame><p className="px-4 py-10 text-sm text-[#57606a]">{NO_INCIDENT}</p></Frame>;
  }
  // never flash a false zero-event chart before the first read lands
  if (loading || !snapshot) {
    return <Frame><p className="px-4 py-10 text-sm text-[#8b949e] italic">{TELEMETRY_LOADING}</p></Frame>;
  }

  const model = bucketEvidence(snapshot.rows);
  if (model.total === 0) {
    return <Frame><p className="px-4 py-10 text-sm text-[#57606a]">{NO_EVENTS}</p></Frame>;
  }

  const max = Math.max(...model.buckets.map((b) => b.count));
  // compact time labels: first, peak, and last, so dense runs stay readable
  const labelAt = new Set([0, model.buckets.length - 1,
                           model.buckets.findIndex((b) => b.isPeak)]);

  return (
    <Frame>
      <div className="px-4 pt-3 pb-1 flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span className="text-sm font-medium text-[#1a2332]">{evidenceSummary(model)}</span>
        <span className="text-sm text-[#57606a]">{evidencePeak(model)}</span>
        {newCount > 0 && (
          <span className="ml-auto flex items-center gap-2">
            <span
              data-testid="evidence-new-count"
              className="px-2 py-0.5 rounded-full text-xs font-medium bg-[#16436b] text-white"
            >
              {newEventsAvailable(newCount)}
            </span>
            {onLoadNewEvents && (
              <button
                type="button"
                onClick={onLoadNewEvents}
                className="px-2.5 py-1 text-xs font-medium rounded-md border border-[#d0d7de] bg-white text-[#1a2332] hover:bg-[#eef1f4]"
              >
                {LOAD_NEW_EVENTS}
              </button>
            )}
          </span>
        )}
      </div>

      {/* thin vertical bars over a soft baseline fill; no curve, no
          animation, reduced-motion safe by construction (static) */}
      <div className="px-4 pb-2 flex-1 flex flex-col min-h-0" aria-hidden="true">
        <div className="relative flex-1 min-h-[10rem] rounded-md bg-[#f6f8fa] border border-[#eef1f4] flex items-end gap-[2px] px-2 pt-2 pb-0 overflow-hidden">
          {model.buckets.map((b) => (
            <span
              key={b.start}
              title={`${b.label} · ${b.count} event${b.count === 1 ? '' : 's'}`}
              className="flex-1 min-w-[2px] rounded-t-sm"
              style={{
                height: `${max ? Math.max(b.count === 0 ? 0 : 4, (b.count / max) * 100) : 0}%`,
                background: b.isPeak ? '#16436b' : '#c3ccd6',
              }}
            />
          ))}
        </div>
        <div className="flex justify-between mt-1">
          {model.buckets.map((b, i) => (
            <span key={b.start} className="text-[10px] text-[#8b949e] flex-1 text-center truncate">
              {labelAt.has(i) ? b.label : ''}
            </span>
          ))}
        </div>
      </div>

      {/* the complete textual equivalent */}
      <table className="sr-only">
        <caption>
          Evidence activity for {incidentId}: {model.total} events observed in{' '}
          {model.bucketSeconds}-second intervals. Peak interval {model.peak.label} with{' '}
          {model.peak.count} events. Snapshot boundary at sequence{' '}
          {snapshot.identity ? snapshot.identity.cutoff_seq : 'unknown'}
          {newCount > 0 ? `; ${newCount} later events are waiting to be loaded.` : '.'}
        </caption>
        <thead><tr><th>Interval</th><th>Events</th><th>Peak</th></tr></thead>
        <tbody>
          {model.buckets.map((b) => (
            <tr key={b.start}>
              <td>{b.label}</td><td>{b.count}</td><td>{b.isPeak ? 'peak' : ''}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="px-4 pb-3 text-[11px] text-[#8b949e]">
        Observed events in this investigation, in {model.bucketSeconds}-second intervals.
        {newCount > 0 && ' Later evidence stays out of this view until you load it.'}
      </div>
    </Frame>
  );
};

export default EvidenceActivity;
