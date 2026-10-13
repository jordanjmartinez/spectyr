// ============================================================================
// Owner simplification (2026-10-12), superseding the VD7/VE4 rolling-density
// model: a handful of observed events does not need sampled window density.
// The chart is a PLAIN EVENTS-PER-MINUTE BAR CHART -- one bucket per minute
// from the first to the last observed event (gaps zero-filled), exact
// counts, the busiest minute is the peak (earliest on ties). Pure functions
// of the frozen snapshot rows only; malformed timestamps are ignored, never
// invented.
// ============================================================================

const MINUTE_MS = 60000;
const minuteStart = (ms) => Math.floor(ms / MINUTE_MS) * MINUTE_MS;

export const minuteLabel = (ms) =>
  new Date(ms).toLocaleTimeString('en-GB', { hour12: false, hour: '2-digit', minute: '2-digit' });

export const minuteBuckets = (rows) => {
  const times = (rows || [])
    .map((r) => (r && r.timestamp ? Date.parse(r.timestamp) : NaN))
    .filter((t) => Number.isFinite(t))
    .sort((a, b) => a - b);
  const total = times.length;
  if (total === 0) return { total: 0, buckets: [], peak: null };

  const first = minuteStart(times[0]);
  const last = minuteStart(times[times.length - 1]);
  const buckets = [];
  for (let t = first; t <= last; t += MINUTE_MS) {
    buckets.push({ t, label: minuteLabel(t), count: 0 });
  }
  for (const ts of times) {
    buckets[(minuteStart(ts) - first) / MINUTE_MS].count += 1;
  }
  let peakIndex = 0;
  buckets.forEach((b, i) => { if (b.count > buckets[peakIndex].count) peakIndex = i; });
  return { total, buckets, peak: { ...buckets[peakIndex], index: peakIndex } };
};

export const evidenceSummary = (model) =>
  `${model.total} Event${model.total === 1 ? '' : 's'} Observed`;

export const evidencePeak = (model) =>
  (model.peak ? `Peak: ${model.peak.label} · ${model.peak.count} Event${model.peak.count === 1 ? '' : 's'}` : '');
