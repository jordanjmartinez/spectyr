import React from 'react';
import { CARD_STYLE } from './ui';
import { LOAD_NEW_EVENTS, newEventsAvailable, TELEMETRY_LOADING } from './uiCopy';
import { minuteBuckets, evidenceSummary, evidencePeak } from './evidenceDensity';

// ============================================================================
// VB1 (amendment section 2): Evidence Activity -- observable event arrival
// volume for the ACTIVE incident, over the FROZEN snapshot the card holds.
// Later evidence is announced as a waiting count and only enters on the
// player's explicit Load New Events (never automatically). Factual volume
// only: the busiest minute is the peak; it is never called an anomaly and
// never marks answer-key attack timing.
//
// Owner simplification (2026-10-12), superseding the VD7/VE4
// rolling-density composition AND its explanatory caption: a PLAIN
// EVENTS-PER-MINUTE BAR CHART. One bar per minute, exact counts, the peak
// minute in accent. The stepped outline, sample columns, peak marker,
// event ticks, sparse state, and the "Rolling density..." caption are all
// retired.
// ============================================================================

export const NO_INCIDENT = 'Start an investigation to see evidence activity.';
export const NO_EVENTS = 'No evidence observed yet.';

const Frame = ({ children }) => (
  <div className="rounded-xl min-w-0 h-full flex flex-col" style={CARD_STYLE} data-testid="evidence-activity">
    {/* Owner UI pass (2026-10-12): title + content only, no card
        subtitle (matching Environment status). */}
    <div className="px-4 pt-4">
      <p className="t-subsection">Evidence Activity</p>
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
  // Owner dashboard alignment + empty-chart rule (2026-10-12): the empty
  // states keep the SAME layout as the data state -- the status line sits
  // immediately below the title (where the summary row lives) and the
  // zeroed chart plane renders beneath it, instead of a lone centered
  // sentence. No count text renders in these states (never a false zero).
  const emptyPlane = (
    <div className="px-4 pb-4 flex-1 flex flex-col min-h-0" aria-hidden="true" data-testid="evidence-empty-plane">
      <div className="relative flex-1 min-h-[180px] max-h-[220px] mt-4 mb-2">
        <div className="absolute inset-x-0 bottom-0 border-t border-[#e2e6ea]" />
      </div>
      <div className="flex justify-between text-[10px] text-muted log-mono opacity-60">
        <span>--:--</span><span>--:--</span>
      </div>
    </div>
  );
  const emptyState = (line, italic = false) => (
    <Frame>
      <div className="px-4 pt-3 pb-1">
        <span className={`text-sm text-muted ${italic ? 'italic' : ''}`}>{line}</span>
      </div>
      {emptyPlane}
    </Frame>
  );

  if (!incidentId) {
    return emptyState(NO_INCIDENT);
  }
  // never flash a false zero-event chart before the first read lands
  if (loading || !snapshot) {
    return emptyState(TELEMETRY_LOADING, true);
  }

  const model = minuteBuckets(snapshot.rows);
  if (model.total === 0) {
    return emptyState(NO_EVENTS);
  }

  const max = model.peak.count;
  const axisStart = model.buckets[0].label;
  const axisEnd = model.buckets[model.buckets.length - 1].label;

  return (
    <Frame>
      <div className="px-4 pt-3 pb-1 flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span className="text-sm font-medium text-[#1a2332]">{evidenceSummary(model)}</span>
        <span className="text-sm text-muted">{evidencePeak(model)}</span>
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

      {/* the plain events-per-minute bars; exact counts, peak in accent */}
      <div className="px-4 pb-1 flex-1 flex flex-col min-h-0" aria-hidden="true">
        <div className="relative flex-1 min-h-[180px] max-h-[220px] mt-2 mb-2">
          <div className="absolute inset-0 flex items-end gap-[2px]" data-testid="evidence-bars">
            {model.buckets.map((b, i) => (
              <span
                key={b.t}
                title={`${b.label} · ${b.count} event${b.count === 1 ? '' : 's'}`}
                className="flex-1 min-w-[2px] h-full relative flex items-end"
              >
                {b.count > 0 && (
                  <span
                    data-testid={i === model.peak.index ? 'evidence-bar-peak' : 'evidence-bar'}
                    className={`w-full rounded-t-sm ${i === model.peak.index ? 'bg-[#16436b]' : 'bg-[#c3ccd6]'}`}
                    style={{ height: `${(b.count / max) * 100}%`, minHeight: '3px' }}
                  />
                )}
              </span>
            ))}
          </div>
          <div className="absolute inset-x-0 bottom-0 border-t border-[#e2e6ea]" />
        </div>
        <div className="flex items-baseline justify-between mt-1 text-[10px] text-muted">
          <span>{axisStart}</span>
          {model.buckets.length > 1 && <span>{axisEnd}</span>}
        </div>
      </div>

      {/* the complete textual equivalent. VE4b: the table sits INSIDE a
          visually-hidden wrapper because sr-only's 1px width cannot
          constrain a table box. */}
      <div className="sr-only">
      <table>
        <caption>
          Evidence activity for {incidentId}: {model.total} events observed, shown as
          events per minute from {axisStart} to {axisEnd}. Peak {model.peak.label} with{' '}
          {model.peak.count} events. Snapshot boundary at sequence{' '}
          {snapshot.identity ? snapshot.identity.cutoff_seq : 'unknown'}
          {newCount > 0 ? `; ${newCount} later events are waiting to be loaded.` : '.'}
        </caption>
        <thead><tr><th>Minute</th><th>Events</th><th>Peak</th></tr></thead>
        <tbody>
          {model.buckets.map((b, i) => (
            <tr key={b.t}>
              <td>{b.label}</td><td>{b.count}</td><td>{i === model.peak.index ? 'peak' : ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
      </div>
    </Frame>
  );
};

export default EvidenceActivity;
