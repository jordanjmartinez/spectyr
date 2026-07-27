// ============================================================================
// VD7 (owner mid-run instruction, superseding the VD1 fixed-bucket
// histogram): the Evidence activity ROLLING EVENT-DENSITY model.
//
// Pure, deterministic sampling over OBSERVABLE event timestamps -- the
// same rows the SIEM query read serves for the incident's scope. It
// never sees expected-but-unarrived scenario events, answer-key data,
// dispositions, or grading. Volume is never suspiciousness: the peak
// marks the busiest rolling window, never an anomaly or attack moment.
//
// Model: at SAMPLE_POINTS evenly spaced sample times across the visible
// range [first event, last event], density = the EXACT count of real
// events in the preceding rolling window (t - W, t]. Windows overlap by
// design; nothing is fabricated, interpolated, or redistributed -- the
// exact event times additionally surface as tick marks. Fewer than
// three DISTINCT event times cannot support a density shape, so the
// model reports sparse: true and the card renders the honest sparse
// state instead of a malformed curve.
// ============================================================================

export const SAMPLE_POINTS = 20;          // within the ruled 16-24 band
export const SPARSE_MESSAGE = 'Evidence arrived in a small number of bursts.';

// The deterministic rolling window: short investigations use 30s,
// ordinary ones 60s, longer ones step up a fixed ladder so the window
// stays comparable to the sample spacing (span / (SAMPLE_POINTS - 1))
// and the chart stays readable.
const LONG_WINDOW_LADDER = [120, 300, 600, 1800, 3600];
export const chooseWindowSeconds = (spanSeconds) => {
  const span = Math.max(0, Number(spanSeconds) || 0);
  if (span <= 300) return 30;             // short investigation
  if (span <= 1800) return 60;            // ordinary investigation
  const target = span / (SAMPLE_POINTS - 1);
  for (const w of LONG_WINDOW_LADDER) {
    if (w >= target) return w;
  }
  return 3600 * Math.ceil(target / 3600);
};

const ms = (iso) => {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : t;
};

// Sub-minute windows need second precision to stay exact; minute-and-up
// windows keep the compact HH:MM.
export const timeLabel = (msValue, windowSeconds = 60) => {
  const d = new Date(msValue);
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  if (windowSeconds < 60) {
    const ss = String(d.getSeconds()).padStart(2, '0');
    return `${hh}:${mm}:${ss}`;
  }
  return `${hh}:${mm}`;
};

// rows: the frozen snapshot's rows (each carrying `timestamp`).
// Returns:
//   { total: 0, sparse: false, samples: [], ticks: [], peak: null } or
//   { total, sparse: true,  ticks, first, last } or
//   { total, sparse: false, windowSeconds, first, last, span,
//     samples: [{t, label, count, isPeak}], peak: {label, count}, ticks }
// ticks are the EXACT observed event times (ms + a 0..1 fraction of the
// visible range); ticksX additionally maps them into the sample-column
// coordinate space the stepped chart renders in, so ticks sit under the
// step that counts them.
export const rollingDensity = (rows) => {
  const stamps = (rows || [])
    .map((r) => ms(r && r.timestamp))
    .filter((t) => t !== null)
    .sort((a, b) => a - b);

  if (stamps.length === 0) {
    return { total: 0, sparse: false, samples: [], ticks: [], peak: null };
  }

  const first = stamps[0];
  const last = stamps[stamps.length - 1];
  const span = last - first;
  const frac = (t) => (span === 0 ? 0.5 : (t - first) / span);
  const ticks = stamps.map((t) => ({ t, x: frac(t) }));

  const distinct = new Set(stamps).size;
  if (distinct < 3) {
    return { total: stamps.length, sparse: true, ticks, first, last };
  }

  const windowSeconds = chooseWindowSeconds(span / 1000);
  const w = windowSeconds * 1000;
  const n = SAMPLE_POINTS;
  const samples = Array.from({ length: n }, (_, i) => {
    const t = first + (i * span) / (n - 1);
    // the EXACT rolling count over real events: (t - W, t]
    const count = stamps.filter((s) => s > t - w && s <= t).length;
    return { t, label: timeLabel(t, windowSeconds), count, isPeak: false };
  });

  // ONE highlighted sample: the highest density, earliest on a tie.
  let peakIndex = 0;
  samples.forEach((s, i) => { if (s.count > samples[peakIndex].count) peakIndex = i; });
  samples[peakIndex].isPeak = true;

  return {
    total: stamps.length,
    sparse: false,
    windowSeconds,
    first,
    last,
    span,
    samples,
    peak: { label: samples[peakIndex].label, count: samples[peakIndex].count, index: peakIndex },
    ticks,
  };
};

// The stepped-outline geometry, exact per sample column. Sample i
// occupies [i, i+1) on the x axis; its top edge sits at its exact
// count scaled to the busiest sample (y = 0 top / 100 baseline, so
// y = 100 is a real zero on the baseline). Horizontal/vertical steps
// ONLY -- no curve commands, no points between samples, no fabricated
// values. `area` is the same outline closed to the baseline for the
// subtle fill beneath the steps.
export const steppedPath = (samples) => {
  const max = Math.max(0, ...(samples || []).map((s) => s.count));
  if (!samples || samples.length === 0 || max === 0) {
    return { outline: '', area: '', tops: [] };
  }
  const y = (c) => 100 - (c / max) * 100;
  const tops = samples.map((s, i) => ({ x0: i, x1: i + 1, y: y(s.count) }));
  let d = `M 0 ${tops[0].y}`;
  for (let i = 0; i < tops.length; i += 1) {
    if (i > 0) d += ` V ${tops[i].y}`;
    d += ` H ${tops[i].x1}`;
  }
  return {
    outline: d,
    area: `${d} V 100 H 0 Z`,
    tops,
  };
};

// Maps a 0..1 time fraction into the sample-column coordinate space
// (percent), so an event tick sits under the column of the sample whose
// window ends nearest it.
export const tickColumnPct = (x, n = SAMPLE_POINTS) =>
  ((0.5 + x * (n - 1)) / n) * 100;

// Clamp a percent position so an absolutely-positioned label centered on
// it can never extend outside the chart bounds.
export const clampPct = (pct, lo = 6, hi = 94) => Math.min(hi, Math.max(lo, pct));

// The factual one-line summary (never a verdict on the activity).
export const evidenceSummary = (model) =>
  `${model.total} event${model.total === 1 ? '' : 's'} observed`;

export const evidencePeak = (model) =>
  (model.peak ? `Peak: ${model.peak.label} · ${model.peak.count} event${model.peak.count === 1 ? '' : 's'}` : '');
