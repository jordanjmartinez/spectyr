import { toast } from 'react-toastify';
import {
  ACTION_LABELS, PROMOTED_LABEL, DISMISSED_LABEL, REOPENED_LABEL,
  detectionsRemaining, allReviewedReady,
} from './uiCopy';

// Stage 5 Phase 2 commit 2.4 (A1-B.3.1): the EXACT toast trigger list --
// T1 disposition results, T2 successful response actions, T3 factual
// no_op / failed_precondition results, T4/T5 the coinciding readiness
// milestone. Nothing else toasts: read-only operations (queries, pivots,
// descent, expanded search), case selection, classification selection, and
// submission are excluded (their announcements live on persistent
// surfaces; one announcement per fact). Every string is factual and
// observable; response toasts render ONLY fields from the action response,
// shape-identical across required, acceptable, and collateral targets --
// the response is disposition-blind by construction.

const OPTS = { role: 'status' };

// T1: a disposition was set. `remaining` is the case roster's open count
// AFTER this action, or null (unsealed roster / no sealed case roster
// containing this detection -- the ruled T1 sealed-roster note: the count
// line renders only once the roster is sealed).
export function toastDisposition(playerAction, remaining) {
  const label = playerAction === 'promoted' ? PROMOTED_LABEL
    : playerAction === 'dismissed' ? DISMISSED_LABEL
      : REOPENED_LABEL;
  const line = remaining !== null && remaining > 0
    ? `${label}. ${detectionsRemaining(remaining)}.`
    : label;
  toast(line, OPTS);
}

// T2/T3: a response action attempt returned. Success confirms the action
// and target; no_op / failed_precondition surface the factual in-fiction
// reason verbatim. Identical shape for every target.
export function toastActionResult(entry) {
  if (!entry || !entry.action) return;
  const label = ACTION_LABELS[entry.action] || entry.action;
  const target = entry.target?.label || '';
  if (entry.outcome === 'success') {
    toast(`${label}: ${target}`, OPTS);
  } else if (entry.outcome === 'no_op' || entry.outcome === 'failed_precondition') {
    toast(`${label}: ${entry.reason || 'No effect.'}`, OPTS);
  }
}

// T4/T5 (coinciding milestone): fired on the observable false -> true
// readiness transition of a sealed incident card.
export function toastReady(incidentId) {
  toast(allReviewedReady(incidentId), OPTS);
}
