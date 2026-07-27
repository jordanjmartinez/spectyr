// ============================================================================
// VB1 (amendment section 2): the Evidence activity data model.
//
// Pure, deterministic bucketing over OBSERVABLE event timestamps -- the
// same rows the SIEM query read serves for the incident's scope. It
// never sees expected-but-unarrived scenario events, answer-key data,
// dispositions, or grading; it counts arrival volume and nothing else.
// Volume is never suspiciousness: the peak marks the busiest interval,
// never an anomaly or an attack moment.
// ============================================================================

// The deterministic bucket ladder (seconds). The chart targets at most
// MAX_BUCKETS visible intervals; the smallest ladder step that fits wins,
// so a very short run lands on 30s, an ordinary run on 60s, and longer
// runs step up in stable increments rather than drifting continuously.
export const BUCKET_LADDER = [30, 60, 120, 300, 600, 1800, 3600];
export const MAX_BUCKETS = 40;

export const chooseBucketSeconds = (spanSeconds) => {
  const span = Math.max(0, Number(spanSeconds) || 0);
  for (const size of BUCKET_LADDER) {
    if (Math.floor(span / size) + 1 <= MAX_BUCKETS) return size;
  }
  // Beyond the ladder (a span no authored run reaches), keep the cap
  // honest by stepping to a whole number of hours that still fits, so
  // the function never silently exceeds MAX_BUCKETS.
  const hours = Math.ceil(span / (MAX_BUCKETS - 1) / 3600);
  return Math.max(BUCKET_LADDER[BUCKET_LADDER.length - 1], hours * 3600);
};

const ms = (iso) => {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : t;
};

export const bucketLabel = (msValue) => {
  const d = new Date(msValue);
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  return `${hh}:${mm}`;
};

// rows: the frozen snapshot's rows (each carrying `timestamp`).
// Returns { total, bucketSeconds, buckets:[{start,label,count,isPeak}],
//           peak: {label,count} | null }.
// Buckets are contiguous from the first to the last observed event, so a
// quiet interval renders as a real zero rather than being skipped.
export const bucketEvidence = (rows) => {
  const stamps = (rows || [])
    .map((r) => ms(r && r.timestamp))
    .filter((t) => t !== null)
    .sort((a, b) => a - b);

  if (stamps.length === 0) {
    return { total: 0, bucketSeconds: BUCKET_LADDER[0], buckets: [], peak: null };
  }

  const first = stamps[0];
  const last = stamps[stamps.length - 1];
  const bucketSeconds = chooseBucketSeconds((last - first) / 1000);
  const size = bucketSeconds * 1000;
  const start0 = Math.floor(first / size) * size;
  const count = Math.floor((last - start0) / size) + 1;

  const buckets = Array.from({ length: count }, (_, i) => ({
    start: start0 + i * size,
    label: bucketLabel(start0 + i * size),
    count: 0,
    isPeak: false,
  }));
  for (const t of stamps) {
    buckets[Math.floor((t - start0) / size)].count += 1;
  }

  // ONE highlighted interval: the highest volume, earliest on a tie.
  let peakIndex = 0;
  buckets.forEach((b, i) => { if (b.count > buckets[peakIndex].count) peakIndex = i; });
  buckets[peakIndex].isPeak = true;

  return {
    total: stamps.length,
    bucketSeconds,
    buckets,
    peak: { label: buckets[peakIndex].label, count: buckets[peakIndex].count },
  };
};

// The factual one-line summary (never a verdict on the activity).
export const evidenceSummary = (model) =>
  `${model.total} event${model.total === 1 ? '' : 's'} observed`;

export const evidencePeak = (model) =>
  (model.peak ? `Peak: ${model.peak.label} · ${model.peak.count} event${model.peak.count === 1 ? '' : 's'}` : '');
