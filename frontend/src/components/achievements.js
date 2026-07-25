// Stage 5 Phase 5 commit 5.4: achievements (contract A1-B.4.3, ratified).
// Computed at RENDER TIME from the served submitted grading record only --
// never stored, never tracked, mode-universal (final results, permitted in
// Hardcore). Each predicate is exactly the contract's frozen-field
// derivation; the deferred list (tool-usage, speed, run-level,
// cross-session labels) stays deferred (B-OD-3) because each needs NEW
// tracking that does not exist.
import { ACHIEVEMENT_LABELS, allDetectionsReviewed } from './uiCopy';

export function deriveAchievements(scoreView) {
  if (!scoreView || scoreView.state !== 'submitted') return [];
  const g = scoreView.grading || {};
  const out = [{
    key: 'case_closed',
    label: ACHIEVEMENT_LABELS.case_closed,
    // the readiness gate makes full triage structurally universal at
    // submit, so Complete Triage folds into this subtitle (A1-B.4.3)
    subtitle: allDetectionsReviewed(g.detection?.total ?? 0),
  }];
  if (g.detection?.accuracy === 100) {
    out.push({ key: 'clean_triage', label: ACHIEVEMENT_LABELS.clean_triage });
  }
  if (g.response?.accuracy === 100) {
    out.push({ key: 'response_ready', label: ACHIEVEMENT_LABELS.response_ready });
  }
  if (g.response?.collateral === 0) {
    out.push({ key: 'no_collateral', label: ACHIEVEMENT_LABELS.no_collateral });
  }
  if (scoreView.assisted === false) {
    out.push({ key: 'solo_close', label: ACHIEVEMENT_LABELS.solo_close });
  }
  if (g.composite?.accuracy === 100) {
    out.push({ key: 'perfect_case', label: ACHIEVEMENT_LABELS.perfect_case });
  }
  return out;
}

// Small shared chip renderer input: [{key, label, subtitle?}] -> the Case
// Closed modal and the Learning Review render the same derivation.
export default deriveAchievements;
