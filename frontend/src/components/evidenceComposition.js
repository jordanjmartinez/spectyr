// ============================================================================
// Owner simplification (2026-10-12), superseding the events-per-minute bars
// (which themselves superseded the VD7/VE4 rolling-density model): a handful
// of scripted events on a session wall-clock axis carries no useful signal,
// and the "peak" was just when the scenario loaded. The card now shows
// EVIDENCE COMPOSITION -- event counts grouped by the serialized
// `source_type` (the closed sensor-family set the SIEM already displays;
// nothing is reinterpreted into an invented taxonomy). Pure functions of the
// frozen snapshot rows only; rows without a source land in "Other", never
// invented.
// ============================================================================

export const sourceComposition = (rows) => {
  const counts = new Map();
  let total = 0;
  for (const r of rows || []) {
    if (!r) continue;
    const src = typeof r.source_type === 'string' ? r.source_type.trim() : '';
    const label = src !== '' ? src : 'Other';
    counts.set(label, (counts.get(label) || 0) + 1);
    total += 1;
  }
  // deterministic order: count descending, ties alphabetical
  const groups = [...counts.entries()]
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
  return { total, groups, max: groups.length ? groups[0].count : 0 };
};

export const evidenceSummary = (model) =>
  `${model.total} Event${model.total === 1 ? '' : 's'} Observed`;
