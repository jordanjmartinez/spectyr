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

// tactic -> [technique entries], in catalog (id) order; tactics with no
// represented technique map to an empty list (the muted matrix columns).
export const techniquesByTactic = () => {
  const map = new Map(ATTACK_TACTICS.map((t) => [t, []]));
  for (const tech of ATTACK_TECHNIQUES) {
    if (map.has(tech.tactic)) map.get(tech.tactic).push(tech);
  }
  return map;
};

export default catalog;
