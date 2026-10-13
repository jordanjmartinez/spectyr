/**
 * Owner dashboard redesign (2026-10-12): the ATT&CK MATRIX card, replacing
 * the VA3/VD3 radar ("Incident ATT&CK Profile") AND its ruled
 * pre-submission lock -- the supersession is deliberate and owner-directed.
 *
 * The contract pinned here:
 * - The FULL corpus grid renders at all times (tactics as columns, one
 *   cell per corpus technique); the ruled empty state is the full grid
 *   with NOTHING highlighted.
 * - Highlights come ONLY from supplied observable mitre tags (roster
 *   detections' ids, each already visible on the Detections surface in
 *   every mode). The ANSWER KEY never feeds this card: structurally it
 *   imports only the label-free catalog mirror and issues no requests.
 * - The card is mode-independent (no mode input) and carries no
 *   session/performance or framework-coverage claims.
 * - The accessible table mirrors the grid (tactic, techniques, observed).
 *
 * The incidentProfile pure-function tests ride along from the radar suite:
 * the catalog function remains exported and its contract is unchanged.
 */
import React from 'react';
import fs from 'fs';
import path from 'path';
import { render, screen, within } from '@testing-library/react';
import AttackMatrix, { SHORT_TACTIC } from '../components/AttackMatrix';
import {
  incidentProfile, ATTACK_TACTICS, ATTACK_TECHNIQUES,
} from '../components/attackCatalog';

const EXAMPLE = [
  { id: 'T1685', tactic: 'Defense Impairment' },
  { id: 'T1685.005', tactic: 'Defense Impairment' },
  { id: 'T1046', tactic: 'Discovery' },
];

const rowFor = (rows, tactic) => rows.find((r) => r.tactic === tactic);

// ---- incidentProfile (catalog pure function, unchanged contract) ----------

test('normalization is incident-relative: strongest tactic is 100%, others proportional, absent 0%', () => {
  const { rows, max } = incidentProfile([
    ...EXAMPLE,
    { id: 'T1036.005', tactic: 'Defense Impairment' },
    { id: 'T1090', tactic: 'Command and Control' },
    { id: 'T1071.001', tactic: 'Command and Control' },
    { id: 'T1218.011', tactic: 'Stealth' },
  ]);
  expect(max).toBe(3);
  expect(rowFor(rows, 'Defense Impairment')).toMatchObject({ count: 3, pct: 100 });
  expect(rowFor(rows, 'Command and Control')).toMatchObject({ count: 2, pct: 67 });
  expect(rowFor(rows, 'Stealth')).toMatchObject({ count: 1, pct: 33 });
  expect(rows.map((r) => r.tactic)).toEqual(ATTACK_TACTICS);
});

test('duplicate technique ids within a tactic count once', () => {
  const { rows, max } = incidentProfile([
    { id: 'T1685', tactic: 'Defense Impairment' },
    { id: 'T1685', tactic: 'Defense Impairment' },
    { id: 'T1046', tactic: 'Discovery' },
  ]);
  expect(max).toBe(1);
  expect(rowFor(rows, 'Defense Impairment').count).toBe(1);
});

// ---- the matrix card -------------------------------------------------------

test('the full grid renders with nothing highlighted when no tags are supplied (the ruled empty state)', () => {
  const { container } = render(<AttackMatrix incidentId={null} mappings={[]} />);
  expect(screen.getByText('ATT&CK Matrix')).toBeInTheDocument();
  // one cell per corpus technique, all unhighlighted
  expect(screen.queryAllByTestId('matrix-cell')).toHaveLength(ATTACK_TECHNIQUES.length);
  expect(screen.queryAllByTestId('matrix-cell-observed')).toHaveLength(0);
  // every tactic is a column (vertical label present, short form)
  for (const t of ATTACK_TACTICS) {
    expect(container.querySelector(`[title="${t}"]`)).not.toBeNull();
  }
  expect(Object.keys(SHORT_TACTIC)).toEqual(expect.arrayContaining(ATTACK_TACTICS));
});

test('observed techniques highlight; everything else stays unhighlighted', () => {
  render(<AttackMatrix incidentId="INC-8340" mappings={EXAMPLE} />);
  const observed = screen.queryAllByTestId('matrix-cell-observed');
  // only ids that exist in the corpus grid can highlight
  const corpusIds = new Set(ATTACK_TECHNIQUES.map((t) => t.id));
  const expected = new Set(EXAMPLE.map((m) => m.id).filter((id) => corpusIds.has(id)));
  expect(observed).toHaveLength(expected.size);
  expect(screen.queryAllByTestId('matrix-cell'))
    .toHaveLength(ATTACK_TECHNIQUES.length - expected.size);
  // cell identity rides the title (id · name · tactic)
  for (const cell of observed) {
    expect(cell.getAttribute('title')).toMatch(/^T\d{4}/);
  }
});

test('the accessible table mirrors the grid with the observed column', () => {
  render(<AttackMatrix incidentId="INC-8340" mappings={EXAMPLE} />);
  const table = screen.getByRole('table');
  expect(table.querySelector('caption').textContent).toMatch(/INC-8340/);
  const di = within(table).getByText('Defense Impairment').closest('tr');
  expect(di.textContent).toContain('T1685');
  const rows = within(table).getAllByRole('row');
  expect(rows).toHaveLength(ATTACK_TACTICS.length + 1); // header + one per tactic
});

test('structural honesty: no answer-key path, no requests, no mode input, no coverage claims', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'components', 'AttackMatrix.jsx'), 'utf8');
  expect(src).not.toMatch(/apiFetch|fetch\(/);
  expect(src).not.toMatch(/gameMode|GUIDED|HARDCORE|MODE_LABEL/);
  expect(src).not.toMatch(/coverageByTactic|TACTIC_TOTALS|scenarios/);
  const { container } = render(<AttackMatrix incidentId="INC-1" mappings={EXAMPLE} />);
  expect(container.textContent).not.toMatch(/coverage of|Enterprise ATT&CK v|represented \/ total/i);
  expect(container.textContent).not.toMatch(/mastery|session performance|Incident Grade|submitted/i);
  // no controls at all: the matrix is a pure display
  expect(screen.queryAllByRole('button')).toHaveLength(0);
});
