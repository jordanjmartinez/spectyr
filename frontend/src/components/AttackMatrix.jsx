import React, { useState } from 'react';
import { Check, AlertTriangle } from 'lucide-react';
import { ATTACK_VERSION, ATTACK_TACTICS, techniquesByTactic } from './attackCatalog';
import { SegmentedToggle, Btn, SectionLabel, CARD_STYLE } from './ui';
import { NAV_STROKE } from './icons';

// ============================================================================
// Visual pass V6b: the ATT&CK Coverage Matrix.
//
// Two truthful views over two disjoint data sources (V11: every state
// names its source; nothing here is mastery language):
// - Catalog coverage: the static label-free corpus mirror
//   (attackCatalog.json, pinned to the loaded corpus by the backend gate)
//   -- which pinned v19.1 techniques Spectyr represents and how many
//   scenarios map to each.
// - This session: ONLY the learner's submitted incidents (each submitted
//   incident's disclosed triage-review technique + its frozen Incident
//   Grade, supplied by the Dashboard). Active incidents NEVER place a
//   cell (the temporal leak rule); they surface as a count note only.
//   Success is defined visibly in the legend: Incident Grade B or higher.
//
// Accessibility: state is never color-alone -- every cell carries its
// technique id as text, a per-state icon, an sr-only state sentence, and
// a native title; a real table List view renders the same data. The grid
// scrolls horizontally inside its own container.
// ============================================================================

const stateOf = (sessionMap, techId) => {
  const rec = sessionMap && sessionMap[techId];
  if (!rec) return 'none';
  return rec.accuracy >= 80 ? 'success' : 'weak';
};

const SESSION_STATE = {
  success: {
    cls: 'bg-emerald-50 border-emerald-200',
    word: 'submitted, Incident Grade B or higher',
    legend: 'Completed (Incident Grade B or higher)',
    Icon: Check, iconCls: 'text-emerald-700',
  },
  weak: {
    cls: 'bg-amber-50 border-amber-200',
    word: 'submitted, needs improvement (C or lower)',
    legend: 'Completed, needs improvement (C or lower)',
    Icon: AlertTriangle, iconCls: 'text-amber-700',
  },
  none: {
    cls: 'bg-[#f6f8fa] border-[#e2e6ea]',
    word: 'not attempted this session',
    legend: 'Represented, not attempted this session',
    Icon: null, iconCls: '',
  },
};

const LegendChip = ({ swatchCls, children }) => (
  <span className="inline-flex items-center gap-1.5 text-xs text-[#57606a]">
    <span aria-hidden="true" className={`w-3 h-3 rounded border ${swatchCls}`} />
    {children}
  </span>
);

const AttackMatrix = ({ sessionMap = {}, activeCount = 0, fpSubmittedCount = 0 }) => {
  const [view, setView] = useState('catalog');   // 'catalog' | 'session'
  const [asList, setAsList] = useState(false);
  const byTactic = techniquesByTactic();
  const isSession = view === 'session';

  const cellFor = (tech) => {
    const st = isSession ? stateOf(sessionMap, tech.id) : 'catalog';
    const spec = isSession ? SESSION_STATE[st] : null;
    const rec = sessionMap[tech.id];
    const srState = isSession
      ? SESSION_STATE[st].word + (rec ? ` (best this session: ${rec.grade}, ${rec.accuracy}%)` : '')
      : `${tech.scenarios} scenario${tech.scenarios === 1 ? '' : 's'} in the catalog`;
    const titleText = `${tech.id} ${tech.name}: ${srState}`;
    const Icon = spec?.Icon;
    return (
      <div
        key={tech.id}
        title={titleText}
        className={`rounded-md border px-2 py-1.5 text-left ${
          isSession ? spec.cls : 'bg-white border-[#d0d7de]'
        }`}
      >
        <div className="flex items-center justify-between gap-1">
          <span className="log-mono text-[11px] font-medium text-[#1a2332]">{tech.id}</span>
          {isSession
            ? (Icon && <Icon size={12} strokeWidth={NAV_STROKE} aria-hidden="true" className={spec.iconCls} />)
            : <span className="text-[10px] text-[#6e7781]">{tech.scenarios}</span>}
        </div>
        <p className="text-[10px] text-[#57606a] truncate" aria-hidden="true">{tech.name}</p>
        <span className="sr-only">{tech.name}, {srState}</span>
      </div>
    );
  };

  const listRows = ATTACK_TACTICS.flatMap((tactic) =>
    (byTactic.get(tactic) || []).map((tech) => ({ tactic, tech })));

  return (
    <div className="rounded-xl" style={CARD_STYLE} data-testid="attack-matrix">
      <div className="px-4 pt-4 pb-3 flex flex-wrap items-center gap-2">
        <SectionLabel>ATT&amp;CK Coverage</SectionLabel>
        <div className="ml-auto flex items-center gap-2">
          <SegmentedToggle
            ariaLabel="Coverage view"
            value={view}
            onChange={setView}
            options={[['catalog', 'Catalog coverage'], ['session', 'This session']]}
          />
          <Btn className="px-2 py-1 text-xs" onClick={() => setAsList(v => !v)}>
            {asList ? 'Grid view' : 'List view'}
          </Btn>
        </div>
      </div>

      {/* honest scope notes (observable counts only) */}
      {isSession && (
        <div className="px-4 pb-2 text-xs text-[#6e7781] space-y-0.5">
          <p>Session state reflects submitted incidents only; it is not long-term mastery.</p>
          {activeCount > 0 && (
            <p>{activeCount} active investigation{activeCount === 1 ? '' : 's'} will appear here after submission.</p>
          )}
          {fpSubmittedCount > 0 && (
            <p>Submitted false-positive scenarios carry no technique cell.</p>
          )}
        </div>
      )}

      {asList ? (
        <div className="px-4 pb-4 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="dark-thead">
              <tr className="text-xs uppercase tracking-wider">
                <th className="px-3 py-2 font-medium whitespace-nowrap">Technique</th>
                <th className="px-3 py-2 font-medium">Name</th>
                <th className="px-3 py-2 font-medium whitespace-nowrap">Tactic</th>
                <th className="px-3 py-2 font-medium whitespace-nowrap">Scenarios</th>
                {isSession && <th className="px-3 py-2 font-medium">This session</th>}
              </tr>
            </thead>
            <tbody>
              {listRows.map(({ tactic, tech }) => {
                const st = stateOf(sessionMap, tech.id);
                const rec = sessionMap[tech.id];
                return (
                  <tr key={tech.id} className="border-b border-[#eef1f4] last:border-b-0">
                    <td className="px-3 py-2 log-mono whitespace-nowrap">{tech.id}</td>
                    <td className="px-3 py-2 text-[#1a2332]">{tech.name}</td>
                    <td className="px-3 py-2 whitespace-nowrap text-[#57606a]">{tactic}</td>
                    <td className="px-3 py-2 text-[#57606a]">{tech.scenarios}</td>
                    {isSession && (
                      <td className="px-3 py-2 text-[#57606a]">
                        {SESSION_STATE[st].word}{rec ? ` (${rec.grade}, ${rec.accuracy}%)` : ''}
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="px-4 pb-3 overflow-x-auto">
          <div className="flex gap-2 min-w-max pb-1" role="list" aria-label="ATT&CK tactics">
            {ATTACK_TACTICS.map((tactic) => {
              const techs = byTactic.get(tactic) || [];
              return (
                <div key={tactic} role="listitem" className="w-[7.5rem] shrink-0">
                  <p className="text-[10px] uppercase tracking-wide text-[#6e7781] font-medium mb-1.5 leading-tight min-h-[2rem]">
                    {tactic}
                  </p>
                  {techs.length === 0 ? (
                    <div className="rounded-md border border-dashed border-[#d0d7de] px-2 py-3 text-center">
                      <span className="text-[10px] text-[#8b949e]">No coverage</span>
                    </div>
                  ) : (
                    <div className="space-y-1.5">{techs.map(cellFor)}</div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* legend: words beside every state swatch (never color alone) */}
      <div className="px-4 pb-3 flex flex-wrap gap-x-4 gap-y-1">
        {isSession ? (
          <>
            <LegendChip swatchCls="bg-emerald-50 border-emerald-200">{SESSION_STATE.success.legend}</LegendChip>
            <LegendChip swatchCls="bg-amber-50 border-amber-200">{SESSION_STATE.weak.legend}</LegendChip>
            <LegendChip swatchCls="bg-[#f6f8fa] border-[#e2e6ea]">{SESSION_STATE.none.legend}</LegendChip>
            <LegendChip swatchCls="border-dashed border-[#d0d7de] bg-white">No scenario coverage</LegendChip>
          </>
        ) : (
          <>
            <LegendChip swatchCls="bg-white border-[#d0d7de]">Represented (count = scenarios in the catalog)</LegendChip>
            <LegendChip swatchCls="border-dashed border-[#d0d7de] bg-white">No scenario coverage</LegendChip>
          </>
        )}
      </div>

      {/* data-source disclosure (V11) */}
      <div className="px-4 pb-3 text-[11px] text-[#8b949e]">
        {ATTACK_VERSION} &middot; {isSession
          ? 'Source: submitted incidents this session (disclosed technique + frozen Incident Grade).'
          : 'Source: the 20-scenario catalog answer keys (static mirror, corpus-pinned).'}
      </div>
    </div>
  );
};

export default AttackMatrix;
