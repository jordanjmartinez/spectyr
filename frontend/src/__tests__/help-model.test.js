/**
 * Stage 5 Phase 6 (contract A1-B.5, consolidated; scaffold Phase 6):
 * 6.1 - the help-model libraries: the HINT_MODES allow-list, the
 * structural hint-inputs neutrality rule, and the copy denylist over
 * every tooltip and hint string (answer-free by construction).
 * 6.2 - the mounting assertions: tooltip presence on the nine controls
 * in every mode (mode-universal under the recorded invariant-7 reading),
 * the hint flow Guided-only (Hardcore-never and SOC-Queue-never), and
 * Hardcore purity (no hint affordance, no coaching prompt).
 */
import React from 'react';
import { render, screen, fireEvent, act, within } from '@testing-library/react';
import {
  TOOLTIPS, HINT_MODES, hintsAllowed, hintsFor,
} from '../components/helpContent';
import {
  TOOLTIP_EQ, TOOLTIP_NEQ, TOOLTIP_PIVOT,
  CONSIDER_PROMPT,
} from '../components/uiCopy';
import HintPanel from '../components/HintPanel';
import EventInspector from '../components/EventInspector';
import Detections from '../components/Detections';
import { PhaseStrip } from '../components/Incidents';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');
const ok = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

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

test('the three ruled query tooltips are the canonical finals, byte-identical', () => {
  expect(TOOLTIPS.eq).toBe(TOOLTIP_EQ);
  expect(TOOLTIPS.neq).toBe(TOOLTIP_NEQ);
  expect(TOOLTIPS.pivot).toBe(TOOLTIP_PIVOT);
});

test('every one of the seven controls has a non-empty tooltip line (feed_threats retired with the Final-pass triage-only Detections)', () => {
  const keys = ['promote', 'dismiss', 'reopen', 'eq', 'neq',
    'pivot', 'expanded_search'];
  expect(Object.keys(TOOLTIPS).sort()).toEqual([...keys].sort());
  for (const k of keys) {
    expect(typeof TOOLTIPS[k]).toBe('string');
    expect(TOOLTIPS[k].length).toBeGreaterThan(10);
  }
});

// --- 6.2: mounting ------------------------------------------------------------

const FEED = {
  detections: [
    { id: 'det-aaa', rule_name: 'Rule Open', rule_type: 'sigma_behavioral',
      severity: 'high', mitre: null, yara_rule_name: null, description: 'x',
      entity: { host: 'ACME-WS12', account: 'nkhan' },
      time: '2026-07-16T12:10:00+00:00', sha256: null, player_action: 'open' },
    { id: 'det-bbb', rule_name: 'Rule Done', rule_type: 'sigma_behavioral',
      severity: 'medium', mitre: null, yara_rule_name: null, description: 'x',
      entity: { host: 'ACME-WS12', account: 'nkhan' },
      time: '2026-07-16T12:05:00+00:00', sha256: null, player_action: 'dismissed' },
  ],
  counts: { open: 1, promoted: 0, dismissed: 1 },
};

const renderDetections = async () => {
  apiFetch.mockImplementation((path) => {
    if (path === '/api/detections') return ok(FEED);
    if (path === '/api/actions') return ok({ actions: [], count: 0 });
    return ok({});
  });
  await act(async () => {
    render(<Detections isVisible resetTrigger={0} activeIncidentId={null} />);
  });
};

test('6.2: Promote, Dismiss, and Reopen carry their tooltip lines (all modes: the surface has no mode gate)', async () => {
  await renderDetections();
  await screen.findByText('Rule Open');
  const byTitle = (t) => document.querySelectorAll(`[title="${t}"]`);
  expect(byTitle(TOOLTIPS.promote).length).toBeGreaterThanOrEqual(2);
  expect(byTitle(TOOLTIPS.dismiss).length).toBeGreaterThanOrEqual(2);
  expect(byTitle(TOOLTIPS.reopen).length).toBeGreaterThanOrEqual(1); // the triaged row
  // keyboard-reachable: the same line rides data-help on the help-tip class
  for (const el of byTitle(TOOLTIPS.promote)) {
    expect(el.getAttribute('data-help')).toBe(TOOLTIPS.promote);
    expect(el.className).toContain('help-tip');
  }
});

test('6.2: the three ruled query controls carry the ruled finals in the inspector (no surrounding control)', () => {
  const event = {
    id: 'e1', event_seq: 1, timestamp: '2026-03-17T04:00:01+00:00',
    event_type: 'ProcessCreate', source_type: 'Sysmon', severity: 'high',
    hostname: 'ACME-WS12', message: 'proc', key_value_pairs: {},
  };
  render(<EventInspector event={event} onFilter={() => {}} onPivot={() => {}}
    onHostPivot={() => {}} />);
  expect(document.querySelectorAll(`[title="${TOOLTIP_EQ}"]`).length).toBeGreaterThan(0);
  expect(document.querySelectorAll(`[title="${TOOLTIP_NEQ}"]`).length).toBeGreaterThan(0);
  const pivots = Array.from(document.querySelectorAll('[title]'))
    .filter(el => el.getAttribute('title').startsWith(TOOLTIP_PIVOT));
  expect(pivots.length).toBeGreaterThan(0);
  expect(screen.queryByText('Surrounding events')).toBeNull();
  for (const el of document.querySelectorAll('.help-tip')) {
    expect(el.getAttribute('data-help')).toBeTruthy();
  }
});

test('6.2: the hint flow is Guided-only; Hardcore and SOC Queue render nothing', () => {
  const g = render(<HintPanel gameMode="guided" surface="siem" />);
  expect(screen.getByText('Need a hint?')).toBeInTheDocument();
  g.unmount();
  for (const mode of ['hardcore', 'analyst', 'soc_queue', 'future_mode']) {
    const r = render(<HintPanel gameMode={mode} surface="siem" />);
    expect(screen.queryByText('Need a hint?')).toBeNull();
    expect(screen.queryByTestId('hint-panel')).toBeNull();
    r.unmount();
  }
});

test('6.2: opening hints shows L1 mechanics, and Nudges shows the active-surface library only', () => {
  render(<HintPanel gameMode="guided" surface="siem" />);
  fireEvent.click(screen.getByText('Need a hint?'));
  const panel = within(screen.getByTestId('hint-panel'));
  for (const line of hintsFor('siem', 1)) {
    expect(panel.getByText(line)).toBeInTheDocument();
  }
  fireEvent.click(panel.getByText('Nudges'));
  for (const line of hintsFor('siem', 2)) {
    expect(panel.getByText(line)).toBeInTheDocument();
  }
  // the level-2 list is the surface library, not another surface's
  for (const line of hintsFor('endpoints', 2)) {
    expect(panel.queryByText(line)).toBeNull();
  }
});

test('6.2: Hardcore purity: no hint affordance and no coaching prompt on the checklist', () => {
  render(<HintPanel gameMode="hardcore" surface="incidents" />);
  expect(screen.queryByText('Need a hint?')).toBeNull();
  // the ONE static prompt renders in Guided only (ruled B-OD-5)
  const strip = render(<PhaseStrip sealed triage={{ total: 2, triaged: 1 }}
    related={0} ready={false} classification={null} showPrompt={false} />);
  expect(screen.queryByText(CONSIDER_PROMPT)).toBeNull();
  strip.unmount();
});
