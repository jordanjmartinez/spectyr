import React from 'react';
import { ATTACK_TACTICS, techniquesByTactic, TECHNIQUE_NAMES } from './attackCatalog';
import { CARD_STYLE, SectionLabel } from './ui';

// ============================================================================
// Owner dashboard redesign (2026-10-12): the ATT&CK MATRIX card, replacing
// the VA3/VD3 radar ("Incident ATT&CK Profile").
//
// Tactics are columns; every corpus technique renders as a cell; the cells
// whose techniques are observed in the current investigation highlight.
// Empty state (ruled by the owner): the FULL grid, nothing highlighted.
//
// Disclosure analysis (supersession flagged):
// - The grid itself is the corpus catalog mirror -- label-free, identical
//   every session, already ruled non-identifying when V6a built the mirror
//   (it aggregates the fixed catalog and can never identify an incident).
//   Rendering it at all times discloses nothing.
// - Highlights derive ONLY from the investigation's roster detections'
//   sanitized mitre tags -- each individually visible on the Detections
//   surface in every mode. The old VD3 ruling kept even this aggregation
//   behind the submission boundary (tactic-shape bias rationale); the
//   owner's matrix instruction explicitly SUPERSEDES that presentation
//   rule. The ANSWER KEY still never feeds this card, pre- or
//   post-submission alike.
// ============================================================================

export const SHORT_TACTIC = {
  'Reconnaissance': 'Recon',
  'Resource Development': 'Resource Dev',
  'Initial Access': 'Initial Access',
  'Execution': 'Execution',
  'Persistence': 'Persistence',
  'Privilege Escalation': 'Priv Esc',
  'Stealth': 'Stealth',
  'Defense Impairment': 'Def Impairment',
  'Credential Access': 'Cred Access',
  'Discovery': 'Discovery',
  'Lateral Movement': 'Lateral Mvmt',
  'Collection': 'Collection',
  'Command and Control': 'C2',
  'Exfiltration': 'Exfil',
  'Impact': 'Impact',
};

const AttackMatrix = ({ incidentId = null, mappings = null }) => {
  const byTactic = techniquesByTactic();
  const observed = new Set((mappings || []).map((m) => m && m.id).filter(Boolean));

  return (
    <div className="rounded-xl min-w-0" style={CARD_STYLE} data-testid="attack-matrix">
      <div className="px-4 pt-4">
        <SectionLabel className="t-subsection">ATT&amp;CK Matrix</SectionLabel>
      </div>

      {/* Owner alignment rule: content top-aligned immediately below the
          title. Owner readability follow-up (2026-10-12): 45-degree
          diagonal labels replace the 90-degree vertical ones, and the
          columns flex-fill the card width (cells scale, staying square). */}
      <div className="px-4 pt-3 pb-4 overflow-x-auto" aria-hidden="true">
        <div className="flex w-full gap-1 pr-10">
          {ATTACK_TACTICS.map((tactic) => {
            const techs = byTactic.get(tactic) || [];
            return (
              <div key={tactic} className="flex-1 min-w-[14px] flex flex-col gap-1">
                <div className="relative h-14 w-full">
                  <span
                    className="absolute bottom-0 left-1 origin-bottom-left -rotate-45 text-[9px] leading-none text-muted whitespace-nowrap"
                    title={tactic}
                  >
                    {SHORT_TACTIC[tactic] || tactic}
                  </span>
                </div>
                {techs.map((t) => (
                  <span
                    key={t.id}
                    data-testid={observed.has(t.id) ? 'matrix-cell-observed' : 'matrix-cell'}
                    title={`${t.id} · ${TECHNIQUE_NAMES[t.id] || t.name || ''} · ${tactic}`}
                    className={`w-full aspect-square rounded-[3px] border ${observed.has(t.id)
                      ? 'bg-[#16436b] border-[#16436b]'
                      : 'bg-[#f6f8fa] border-[#d0d7de]'}`}
                  />
                ))}
                {techs.length === 0 && (
                  <span className="w-full aspect-square rounded-[3px] border border-dashed border-[#e2e6ea] bg-white" />
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* the complete text equivalent */}
      <table className="sr-only">
        <caption>
          ATT&amp;CK Matrix{incidentId ? ` for ${incidentId}` : ''}: the corpus technique
          grid by tactic; highlighted cells are techniques observed in the
          current investigation.
        </caption>
        <thead>
          <tr><th>Tactic</th><th>Techniques</th><th>Observed</th></tr>
        </thead>
        <tbody>
          {ATTACK_TACTICS.map((tactic) => {
            const techs = byTactic.get(tactic) || [];
            const seen = techs.filter((t) => observed.has(t.id));
            return (
              <tr key={tactic}>
                <td>{tactic}</td>
                <td>{techs.map((t) => `${t.id} ${TECHNIQUE_NAMES[t.id] || ''}`.trim()).join(', ') || 'none'}</td>
                <td>{seen.map((t) => t.id).join(', ') || 'none'}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

export default AttackMatrix;
