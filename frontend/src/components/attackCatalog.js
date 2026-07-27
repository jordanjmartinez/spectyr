import catalog from './attackCatalog.json';

// ============================================================================
// Visual pass V6a: the ATT&CK catalog mirror (the matrix data foundation).
//
// DATA CONTRACT (reported in the V6 matrix section of the implementation
// report):
// - Source of truth: the corpus answer keys (backend/scenarios/v2). Each
//   entry is one pinned v19.1 technique with its CORPUS-RECORDED tactic
//   (the triage-review mitre tactic; detections agree) and the number of
//   scenarios whose answer key carries it. Names are byte-equal to the
//   pinned CANONICAL_TECHNIQUE_NAMES baseline.
// - The mirror is LABEL-FREE and identical every session: it aggregates
//   the fixed 20-scenario catalog and links to nothing in the live queue,
//   so it can never identify an active incident (FP scenarios carry no
//   technique and appear nowhere here).
// - Detection-tag-only techniques (PINNED_DETECTION_TECHNIQUES: rule
//   RESEMBLANCE tags, several deliberately on FP/ambient rules) are
//   EXCLUDED: they are not scenario coverage, and mirroring them would
//   hint at rule dispositions.
// - The permanent backend pin test
//   (test_scenario_loader_v2.test_frontend_attack_catalog_mirror) asserts
//   this file equals the loaded corpus exactly: tactic list vs the pinned
//   v19.1 set, ids/names vs the canonical map, per-technique counts vs
//   the answer keys, tactics vs the recorded review/detection pairs, key
//   whitelist, and no scenario label anywhere. Editing scenarios without
//   regenerating this mirror fails that gate.
// - v19.1 note (flagged deviation from the V6 spec text): the requested
//   tactic list was the pre-v19 one ("Defense Evasion"); this corpus is
//   pinned to v19.1, where Stealth + Defense Impairment replace it, so
//   the matrix follows the pin (the standing one-deliberate-migration
//   rule forbids mixing versions).
// ============================================================================

export const ATTACK_VERSION = catalog.attack_version;
export const ATTACK_TACTICS = catalog.tactics;
export const ATTACK_TECHNIQUES = catalog.techniques;
export const TACTIC_TOTALS = catalog.tactic_totals;
export const SOURCE_DATASET = catalog.source_dataset;
// VA3: canonical technique names for every id the product can surface
// (answer-key techniques + pinned detection tags), derived from the same
// sha256-verified dataset and pinned by the backend gate. Used to name
// techniques in the incident-profile tooltip and its text equivalent.
export const TECHNIQUE_NAMES = catalog.technique_names;

// VA3 (amendment section 5): the INCIDENT ATT&CK profile.
// Input: the ATT&CK mappings legitimately visible for the active
// incident (its roster detections' mitre tags -- already rendered on
// every detection detail in every mode, so aggregating them discloses
// nothing new and never touches the answer key).
// Output: per-tactic technique counts normalized against THIS
// INCIDENT's strongest tactic, so the profile shows the SHAPE of the
// current investigation. This is never framework coverage.
export const incidentProfile = (mappings) => {
  const perTactic = new Map(ATTACK_TACTICS.map((t) => [t, new Map()]));
  for (const m of mappings || []) {
    if (!m || !m.id || !perTactic.has(m.tactic)) continue;
    perTactic.get(m.tactic).set(m.id, TECHNIQUE_NAMES[m.id] || m.name || m.id);
  }
  const counts = ATTACK_TACTICS.map((tactic) => ({
    tactic,
    techniques: [...perTactic.get(tactic).entries()]
      .map(([id, name]) => ({ id, name }))
      .sort((a, b) => a.id.localeCompare(b.id)),
  }));
  const max = counts.reduce((m, r) => Math.max(m, r.techniques.length), 0);
  return {
    max,
    rows: counts.map((r) => ({
      ...r,
      count: r.techniques.length,
      // absent tactics stay exactly 0; no artificial minimum
      pct: max === 0 ? 0 : Math.round((r.techniques.length / max) * 100),
    })),
  };
};

// tactic -> [technique entries], in catalog (id) order.
export const techniquesByTactic = () => {
  const map = new Map(ATTACK_TACTICS.map((t) => [t, []]));
  for (const tech of ATTACK_TECHNIQUES) {
    if (map.has(tech.tactic)) map.get(tech.tactic).push(tech);
  }
  return map;
};

// V6-R (owner correction): the radar's per-tactic coverage rows.
// Numerator and denominator share ONE counting rule (the mirror's
// `counting` note): parent techniques only, so T1110.001 + T1110.003
// roll up to the single represented technique T1110; the denominator is
// the authoritative per-tactic parent-technique count derived from the
// pinned v19.1 STIX dataset (sha256-verified, recorded in
// source_dataset). Percentages are plain represented/total -- never
// normalized against Spectyr's own largest category.
export const coverageByTactic = () => {
  const parents = new Map(ATTACK_TACTICS.map((t) => [t, new Set()]));
  for (const tech of ATTACK_TECHNIQUES) {
    if (parents.has(tech.tactic)) parents.get(tech.tactic).add(tech.id.split('.')[0]);
  }
  return ATTACK_TACTICS.map((tactic) => {
    const represented = parents.get(tactic).size;
    const total = TACTIC_TOTALS[tactic];
    return {
      tactic,
      represented,
      total,
      pct: total ? Math.round((represented / total) * 100) : 0,
    };
  });
};

export default catalog;
