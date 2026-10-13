import React from 'react';
import { CARD_STYLE, BarList, BarRow } from './ui';
import { LOAD_NEW_EVENTS, newEventsAvailable, TELEMETRY_LOADING } from './uiCopy';
import { sourceComposition, evidenceSummary } from './evidenceComposition';

// ============================================================================
// VB1 (amendment section 2): Evidence Activity -- the observable evidence
// for the ACTIVE incident, over the FROZEN snapshot the card holds. Later
// evidence is announced as a waiting count and only enters on the player's
// explicit Load New Events (never automatically). Factual volume only.
//
// Owner simplification (2026-10-12), superseding the events-per-minute bars
// (and before them the VD7/VE4 rolling-density composition): the time-volume
// chart, the "Peak" line, and the density caption are retired -- a handful
// of scripted events on a session wall-clock axis carries no signal. The
// card shows EVIDENCE COMPOSITION instead: counts grouped by source_type.
// Volume only -- never suspiciousness, correctness, or answer-key data.
//
// Owner unification (2026-10-12): the rows are the ONE shared BarRow
// anatomy (ui.jsx) that Severity Distribution also renders -- identical
// label font, bar height, track, count typography, and row spacing; only
// the fill differs (evidence keeps navy). The events-observed summary
// rides the TITLE ROW, right-aligned in muted text, not its own line.
// Owner layout pass 4 (2026-10-12, superseding the earlier same-day
// sizing rulings): the card is h-full -- on the dashboard it shares the
// working row's height with Active Investigation (same card size) and
// NEVER resizes with its own content. The bars stay capped and never
// stretch.
// ============================================================================

export const NO_INCIDENT = 'Start an investigation to see evidence activity.';
export const NO_EVENTS = 'No evidence observed yet.';

const EVIDENCE_FILL = '#16436b';

const Frame = ({ right = null, children }) => (
  <div className="rounded-xl min-w-0 h-full" style={CARD_STYLE} data-testid="evidence-activity">
    {/* Owner UI pass (2026-10-12): title + content only, no card subtitle;
        the factual summary sits right-aligned ON the title row. */}
    <div className="px-4 pt-4 flex items-baseline justify-between gap-3">
      <p className="t-subsection">Evidence Activity</p>
      {right && <span className="text-sm text-muted shrink-0">{right}</span>}
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
  // immediately below the title and zeroed composition rows render beneath
  // it, instead of a lone centered sentence. No counts render in these
  // states (never a false zero). The zeroed rows mirror the shared BarRow
  // geometry exactly.
  const emptyPlane = (
    <div className="px-4 pb-4 pt-2" aria-hidden="true" data-testid="evidence-empty-plane">
      <div className="space-y-1.5">
        {[0, 1, 2].map((i) => (
          <div key={i} className="flex items-center gap-2 text-sm">
            <span className="w-32 shrink-0 text-muted opacity-60">--</span>
            <span className="flex-1 max-w-[10rem] h-2 rounded-full bg-[#eef1f4]" />
            <span className="w-8 shrink-0 text-right text-muted opacity-60">--</span>
          </div>
        ))}
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
  // never flash a false zero-event card before the first read lands
  if (loading || !snapshot) {
    return emptyState(TELEMETRY_LOADING, true);
  }

  const model = sourceComposition(snapshot.rows);
  if (model.total === 0) {
    return emptyState(NO_EVENTS);
  }

  return (
    <Frame right={evidenceSummary(model)}>
      {newCount > 0 && (
        <div className="px-4 pt-3 flex flex-wrap items-center justify-end gap-2">
          <span
            data-testid="evidence-new-count"
            className="px-1.5 py-0.5 rounded-full text-[11px] font-medium bg-[#16436b] text-white"
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
        </div>
      )}

      {/* counts grouped by source: the shared label + track + count row.
          The rows are visible text, so the chart IS its own textual
          equivalent. */}
      <div className="px-4 pb-4 pt-3" data-testid="evidence-composition">
        <BarList>
          {model.groups.map((g) => (
            <BarRow key={g.label} label={g.label} count={g.count} max={model.max}
              fill={EVIDENCE_FILL} testid="evidence-group" />
          ))}
        </BarList>
      </div>

      {/* snapshot-boundary honesty for screen readers */}
      <p className="sr-only">
        Evidence for {incidentId}: {model.total} events observed, grouped by log source.
        Snapshot boundary at sequence {snapshot.identity ? snapshot.identity.cutoff_seq : 'unknown'}
        {newCount > 0 ? `; ${newCount} later events are waiting to be loaded.` : '.'}
      </p>
    </Frame>
  );
};

export default EvidenceActivity;
