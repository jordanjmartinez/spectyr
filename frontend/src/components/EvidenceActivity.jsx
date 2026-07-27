import React from 'react';
import { CARD_STYLE } from './ui';
import { LOAD_NEW_EVENTS, newEventsAvailable, TELEMETRY_LOADING } from './uiCopy';
import {
  bucketEvidence, evidenceSummary, evidencePeak, steppedPath,
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
//
// VD1 (visual-consistency correction, section 1): stepped presentation.
// Every deterministic bucket from the first observable event through the
// snapshot's evidence boundary renders -- zeros included -- as a thin
// vertical bar under ONE stepped outline (exact horizontal/vertical
// steps from steppedPath, never a smoothed curve) over a subtle neutral
// fill. The busiest bucket alone carries the restrained accent, a peak
// marker, and its label; start/end labels stay compact. Exact per-bucket
// tooltips and the complete sr-only table remain the accessible detail.
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
  const geom = steppedPath(model.buckets);
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

      {/* the stepped chart: exact bucket geometry, static, no animation,
          reduced-motion safe by construction */}
      <div className="px-4 pb-2 flex-1 flex flex-col min-h-0" aria-hidden="true">
        <div className="relative flex-1 min-h-[10rem] mt-2">
          {/* subtle neutral fill beneath ONE stepped outline; horizontal/
              vertical steps only (steppedPath emits no curve commands) */}
          <svg
            className="absolute inset-0 w-full h-full"
            viewBox={`0 0 ${model.buckets.length} 100`}
            preserveAspectRatio="none"
          >
            <path d={geom.area} fill="#eef1f4" />
            <path
              d={geom.outline}
              fill="none"
              stroke="#8b949e"
              strokeWidth="1.25"
              vectorEffect="non-scaling-stroke"
              strokeLinejoin="miter"
            />
          </svg>
          {/* thin per-bucket bars; a zero bucket stays a real zero (no bar,
              the outline runs along the baseline). Each column is the exact
              tooltip hit area for its bucket. */}
          <div className="absolute inset-0 flex items-stretch">
            {model.buckets.map((b) => (
              <span
                key={b.start}
                title={`${b.label} · ${b.count} event${b.count === 1 ? '' : 's'}`}
                className="flex-1 min-w-0 relative"
              >
                {b.count > 0 && (
                  <span
                    className="absolute bottom-0 left-1/2 -translate-x-1/2 w-[2px] rounded-t-sm"
                    style={{
                      height: `${(b.count / max) * 100}%`,
                      minHeight: '2px',
                      background: b.isPeak ? '#16436b' : '#c3ccd6',
                    }}
                  />
                )}
                {b.isPeak && (
                  <span
                    data-testid="evidence-peak-marker"
                    className="absolute left-1/2 -translate-x-1/2 w-1.5 h-1.5 rounded-full bg-[#16436b]"
                    style={{ bottom: `calc(${(b.count / max) * 100}% + 3px)` }}
                  />
                )}
              </span>
            ))}
          </div>
          {/* baseline */}
          <div className="absolute inset-x-0 bottom-0 border-t border-[#e2e6ea]" />
        </div>
        <div className="flex mt-1">
          {model.buckets.map((b, i) => (
            <span
              key={b.start}
              className={`flex-1 min-w-0 text-[10px] text-center truncate ${
                b.isPeak ? 'text-[#16436b] font-medium' : 'text-[#8b949e]'}`}
            >
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
