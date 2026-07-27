import React from 'react';
import { CARD_STYLE } from './ui';
import { LOAD_NEW_EVENTS, newEventsAvailable, TELEMETRY_LOADING } from './uiCopy';
import {
  rollingDensity, steppedPath, evidenceSummary, evidencePeak,
  tickColumnPct, clampPct, SPARSE_MESSAGE,
} from './evidenceDensity';

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
// VD7 (owner mid-run instruction, superseding the VD1 fixed-bucket
// histogram): the compact ROLLING EVENT-DENSITY chart, composed after
// the owner's Pipeline Activity reference. A stepped outline over
// evenly spaced sample points (exact rolling-window counts of real
// events), thin neutral density lines beneath it, a subtle fill, ONE
// highlighted peak sample (restrained accent column, point marker, and
// a "Peak" label above it), exact event-time tick marks along the
// baseline, and a three-label axis (start / midpoint / end) that can
// never clip or overlap. Fewer than three distinct event times renders
// the honest sparse state instead of a malformed density shape.
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

  const model = rollingDensity(snapshot.rows);
  if (model.total === 0) {
    return <Frame><p className="px-4 py-10 text-sm text-[#57606a]">{NO_EVENTS}</p></Frame>;
  }

  const summaryRow = (
    <div className="px-4 pt-3 pb-1 flex flex-wrap items-baseline gap-x-3 gap-y-1">
      <span className="text-sm font-medium text-[#1a2332]">{evidenceSummary(model)}</span>
      {!model.sparse && <span className="text-sm text-[#57606a]">{evidencePeak(model)}</span>}
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
  );

  // -- the honest sparse state: fewer than three distinct event times --------
  if (model.sparse) {
    return (
      <Frame>
        {summaryRow}
        <div className="px-4 pb-2" aria-hidden="true">
          <div className="relative h-16" data-testid="evidence-sparse">
            {/* a simple short activity line through the burst region */}
            <span
              className="absolute bottom-0 h-[2px] bg-[#c3ccd6] rounded-full"
              style={{
                left: `${10 + model.ticks[0].x * 80}%`,
                right: `${100 - (10 + model.ticks[model.ticks.length - 1].x * 80) - 1}%`,
                minWidth: '2px',
              }}
            />
            {/* exact event ticks (one per observed event, real times) */}
            {model.ticks.map((tk, i) => (
              <span
                key={`${tk.t}-${i}`}
                data-testid="evidence-tick"
                className="absolute bottom-0 w-px h-3 bg-[#8b949e]"
                style={{ left: `${10 + tk.x * 80}%` }}
              />
            ))}
            <div className="absolute inset-x-0 bottom-0 border-t border-[#e2e6ea]" />
          </div>
        </div>
        <p className="px-4 pb-3 text-sm text-[#57606a]">{SPARSE_MESSAGE}</p>
        <div className="sr-only">
          Evidence activity for {incidentId}: {model.total} events observed at{' '}
          {model.ticks.map((tk) => new Date(tk.t).toISOString()).join(', ')}. {SPARSE_MESSAGE}
        </div>
      </Frame>
    );
  }

  // -- the rolling-density chart ---------------------------------------------
  const n = model.samples.length;
  const max = Math.max(...model.samples.map((s) => s.count));
  const geom = steppedPath(model.samples);
  const peakIndex = model.peak.index;
  const colPct = 100 / n;
  const peakCenter = (peakIndex + 0.5) * colPct;
  const axisStart = model.samples[0].label;
  const axisMid = model.samples[Math.floor((n - 1) / 2)].label;
  const axisEnd = model.samples[n - 1].label;

  return (
    <Frame>
      {summaryRow}

      <div className="px-4 pb-1 flex-1 flex flex-col min-h-0" aria-hidden="true">
        {/* compact density plane: fills the card's width and vertical room
            within the ruled 180-220px band; mt-4 leaves headroom for the
            Peak label, pb keeps room for the event ticks below the axis */}
        <div className="relative flex-1 min-h-[180px] max-h-[220px] mt-4 mb-2">
          {/* the restrained accent highlight through the peak column */}
          <span
            data-testid="evidence-peak-column"
            className="absolute inset-y-0 bg-[#16436b]/[0.07]"
            style={{ left: `${peakIndex * colPct}%`, width: `${colPct}%` }}
          />
          {/* subtle fill under ONE stepped outline; horizontal/vertical
              steps only (steppedPath emits no curve commands) */}
          <svg
            className="absolute inset-0 w-full h-full"
            viewBox={`0 0 ${n} 100`}
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
          {/* thin neutral density lines beneath the outline; each column
              is the exact tooltip hit area for its sample */}
          <div className="absolute inset-0 flex items-stretch">
            {model.samples.map((s) => (
              <span
                key={s.t}
                title={`${s.label} · ${s.count} event${s.count === 1 ? '' : 's'} in the preceding ${model.windowSeconds}s`}
                className="flex-1 min-w-0 relative"
              >
                {s.count > 0 && (
                  <span
                    className="absolute bottom-0 left-1/2 -translate-x-1/2 w-[2px] rounded-t-sm"
                    style={{
                      height: `${(s.count / max) * 100}%`,
                      minHeight: '2px',
                      background: s.isPeak ? '#16436b' : '#c3ccd6',
                    }}
                  />
                )}
              </span>
            ))}
          </div>
          {/* peak point marker + the "Peak" label above the interval,
              clamped so it can never extend outside the chart bounds */}
          <span
            data-testid="evidence-peak-marker"
            className="absolute w-1.5 h-1.5 rounded-full bg-[#16436b] -translate-x-1/2"
            style={{ left: `${peakCenter}%`, bottom: `calc(${(model.peak.count / max) * 100}% - 3px)` }}
          />
          <span
            data-testid="evidence-peak-label"
            className="absolute -top-4 text-[10px] font-medium text-[#16436b] -translate-x-1/2"
            style={{ left: `${clampPct(peakCenter)}%` }}
          >
            Peak
          </span>
          {/* baseline + exact event-time tick marks (real events only) */}
          <div className="absolute inset-x-0 bottom-0 border-t border-[#e2e6ea]" />
          {model.ticks.map((tk, i) => (
            <span
              key={`${tk.t}-${i}`}
              data-testid="evidence-tick"
              className="absolute -bottom-[5px] w-px h-[5px] bg-[#8b949e]/70"
              style={{ left: `${tickColumnPct(tk.x, n)}%` }}
            />
          ))}
        </div>
        {/* the three-label axis: start / midpoint / end, in normal flow so
            nothing can clip, ellipsize, or overlap */}
        <div className="flex items-baseline justify-between mt-1 text-[10px] text-[#8b949e]">
          <span>{axisStart}</span>
          <span>{axisMid}</span>
          <span>{axisEnd}</span>
        </div>
      </div>

      {/* the complete textual equivalent */}
      <table className="sr-only">
        <caption>
          Evidence activity for {incidentId}: {model.total} events observed. Rolling
          density at {n} evenly spaced sample times; each count is the number of
          observed events in the {model.windowSeconds}-second rolling window ending
          at that sample. Peak {model.peak.label} with {model.peak.count} events in
          its window. Axis start {axisStart}, midpoint {axisMid}, end {axisEnd}.
          Snapshot boundary at sequence{' '}
          {snapshot.identity ? snapshot.identity.cutoff_seq : 'unknown'}
          {newCount > 0 ? `; ${newCount} later events are waiting to be loaded.` : '.'}
        </caption>
        <thead><tr><th>Sample time</th><th>Events in window</th><th>Peak</th></tr></thead>
        <tbody>
          {model.samples.map((s) => (
            <tr key={s.t}>
              <td>{s.label}</td><td>{s.count}</td><td>{s.isPeak ? 'peak' : ''}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="px-4 pb-3 text-[11px] text-[#8b949e]">
        Rolling density: events in the preceding {model.windowSeconds}s at each sample.
        Ticks mark exact event times.
        {newCount > 0 && ' Later evidence stays out of this view until you load it.'}
      </div>
    </Frame>
  );
};

export default EvidenceActivity;
