/**
 * Stage 5 Phase 6 (contract A1-B.5, consolidated; scaffold Phase 6):
 * 6.1 - the help-model libraries: the HINT_MODES allow-list, the
 * structural hint-inputs neutrality rule, and the copy denylist over
 * every tooltip and hint string (answer-free by construction).
 * 6.2 adds the mounting assertions (tooltip presence on the nine
 * controls in every mode; hint flow Guided-only; Hardcore purity).
 */
import {
  TOOLTIPS, HINT_MODES, hintsAllowed, hintsFor,
} from '../components/helpContent';
import {
  TOOLTIP_EQ, TOOLTIP_NEQ, TOOLTIP_PIVOT, TOOLTIP_SURROUNDING,
} from '../components/uiCopy';

// --- 6.1: the allow-list -----------------------------------------------------

test('HINT_MODES is exactly the ruled Guided allow-list', () => {
  expect(HINT_MODES).toEqual(['guided']);
  expect(hintsAllowed('guided')).toBe(true);
  // Hardcore-never and SOC-Queue-never: excluded by default, plus any
  // future mode is locked out rather than accidentally permitted
  for (const mode of ['hardcore', 'analyst', 'soc_queue', 'training', '', undefined, 'future_mode']) {
    expect(hintsAllowed(mode)).toBe(false);
  }
});

// --- 6.1: structural neutrality ----------------------------------------------

test('hintsFor is a pure function of exactly (surface, level): the binding neutrality rule', () => {
  // structural inputs: surface id and level, nothing else
  expect(hintsFor.length).toBe(2);
  // identical output on every call: no hidden state, clock, or randomness
  for (const surface of ['incidents', 'siem', 'detections', 'endpoints', 'metrics', 'unknown']) {
    for (const level of [1, 2]) {
      const a = hintsFor(surface, level);
      const b = hintsFor(surface, level);
      expect(b).toEqual(a);
      expect(a.length).toBeGreaterThan(0);
    }
  }
  // level 1 mechanics are surface-independent (the same help everywhere)
  expect(hintsFor('siem', 1)).toEqual(hintsFor('detections', 1));
  // unknown surfaces fall back to the generic nudges, never nothing
  expect(hintsFor('unknown', 2)).toEqual(hintsFor('another_unknown', 2));
});

// --- 6.1: the copy denylist --------------------------------------------------

const CATEGORY_NAMES = [
  'Malware', 'Phishing', 'Defense Evasion', 'Lateral Movement',
  'Command & Control', 'Brute Force', 'Data Exfiltration', 'Insider Threat',
];
const SCENARIO_LABELS = /\b[a-z0-9]+(_[a-z0-9]+)+\b/;   // label-shaped tokens
const CORRECTNESS = /\b(correct|incorrect|wrong|answer|required action)\b/i;

const allHelpStrings = () => {
  const out = [...Object.values(TOOLTIPS)];
  for (const surface of ['incidents', 'siem', 'detections', 'endpoints', 'metrics', 'other']) {
    out.push(...hintsFor(surface, 1), ...hintsFor(surface, 2));
  }
  return out;
};

test('no tooltip or hint string carries category names, scenario labels, correctness phrasing, or em dashes', () => {
  for (const s of allHelpStrings()) {
    for (const cat of CATEGORY_NAMES) {
      expect(s).not.toMatch(new RegExp(`\\b${cat}\\b`, 'i'));
    }
    expect(s).not.toMatch(SCENARIO_LABELS);
    expect(s).not.toMatch(CORRECTNESS);
    expect(s).not.toContain('—');
  }
});

test('the four ruled query tooltips are the canonical finals, byte-identical', () => {
  expect(TOOLTIPS.eq).toBe(TOOLTIP_EQ);
  expect(TOOLTIPS.neq).toBe(TOOLTIP_NEQ);
  expect(TOOLTIPS.pivot).toBe(TOOLTIP_PIVOT);
  expect(TOOLTIPS.surrounding).toBe(TOOLTIP_SURROUNDING);
});

test('every one of the nine controls has a non-empty tooltip line', () => {
  const keys = ['promote', 'dismiss', 'reopen', 'feed_threats', 'eq', 'neq',
    'pivot', 'surrounding', 'expanded_search'];
  expect(Object.keys(TOOLTIPS).sort()).toEqual([...keys].sort());
  for (const k of keys) {
    expect(typeof TOOLTIPS[k]).toBe('string');
    expect(TOOLTIPS[k].length).toBeGreaterThan(10);
  }
});
