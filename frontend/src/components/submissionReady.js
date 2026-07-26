// Amendment 3 F4b (ratified A3-OD-3): the ONE client-side
// submission-readiness derivation. Every player-facing "Ready" surface
// (the checklist Ready line, the Submit gate, the Incidents list chip and
// Ready view/count, the IncidentDashboard row chip) consumes THIS
// function over the ONE shell-owned selection state -- no surface may
// show Ready while the checklist says "Classification: not selected".
//
// validClassification mirrors the server rule exactly
// (_valid_classification: verdict false_positive, or threat with a
// non-empty category). The server submission gate is untouched and
// remains the authoritative backstop; the response-action count stays
// informational and never gates readiness (the standing leak rule).

export const validClassification = (sel) =>
  !!sel && (sel.verdict === 'false_positive'
    || (sel.verdict === 'threat'
        && typeof sel.category === 'string' && sel.category.trim() !== ''));

export const submissionReady = (card, chosen) =>
  !!(card && card.sealed && card.ready
     && validClassification((chosen || {})[card.incident_id]));
