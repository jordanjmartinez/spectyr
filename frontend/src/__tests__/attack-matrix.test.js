/**
 * Visual pass V6b: the ATT&CK Coverage Matrix component. Pure
 * presentation over the corpus-pinned catalog mirror + a
 * submitted-session map supplied by the Dashboard (this component
 * imports no api module -- it cannot fetch, so it cannot leak). Every
 * state carries text/icon equivalence (id text, sr-only sentence, native
 * title, legend words) and a real table List view renders the same data.
 */
import React from 'react';
import { render, screen, fireEvent, within } from '@testing-library/react';
import AttackMatrix from '../components/AttackMatrix';
import { ATTACK_TACTICS, ATTACK_TECHNIQUES } from '../components/attackCatalog';

const COVERED_TACTICS = new Set(ATTACK_TECHNIQUES.map(t => t.tactic));

test('catalog view: pinned v19.1 tactic columns, technique cells with counts, muted no-coverage slots', () => {
  render(<AttackMatrix />);
  // all 15 pinned tactic columns render, in the pinned order
  const list = screen.getByRole('list', { name: 'ATT&CK tactics' });
  const headers = within(list).getAllByRole('listitem').map(li => li.querySelector('p').textContent);
  expect(headers).toEqual(ATTACK_TACTICS);
  // v19.1 split tactics present; the pre-v19 name absent
  expect(headers).toContain('Stealth');
  expect(headers).toContain('Defense Impairment');
  expect(headers).not.toContain('Defense Evasion');
  // every represented technique renders a cell; empty tactics render the
  // muted outline slot
  for (const tech of ATTACK_TECHNIQUES) {
    expect(within(list).getByText(tech.id)).toBeInTheDocument();
  }
  const emptyCount = ATTACK_TACTICS.filter(t => !COVERED_TACTICS.has(t)).length;
  expect(within(list).getAllByText('No coverage')).toHaveLength(emptyCount);
  // the version + data-source disclosure line
  expect(screen.getByText(/Enterprise ATT&CK v19\.1 \(pinned\)/)).toBeInTheDocument();
  expect(screen.getByText(/catalog answer keys/)).toBeInTheDocument();
});

test('session view: submitted-only states with icon + sr-only + title equivalence, honest notes', () => {
  render(<AttackMatrix
    sessionMap={{ 'T1486': { grade: 'A', accuracy: 100 }, 'T1046': { grade: 'D', accuracy: 62 } }}
    activeCount={2}
    fpSubmittedCount={1}
  />);
  fireEvent.click(screen.getByRole('button', { name: 'This session' }));
  // success + weak carry native-title sentences (the text equivalence)
  expect(screen.getByTitle(/T1486 .*submitted, Incident Grade B or higher.*100%/)).toBeInTheDocument();
  expect(screen.getByTitle(/T1046 .*needs improvement.*62%/)).toBeInTheDocument();
  // a not-attempted technique states it too
  expect(screen.getByTitle(/T1091 .*not attempted this session/)).toBeInTheDocument();
  // honest scope notes: session-only framing, active count, FP note
  expect(screen.getByText(/not long-term mastery/)).toBeInTheDocument();
  expect(screen.getByText(/2 active investigations will appear here after submission/)).toBeInTheDocument();
  expect(screen.getByText(/false-positive scenarios carry no technique cell/i)).toBeInTheDocument();
  // the legend names every state in words
  expect(screen.getByText('Completed (Incident Grade B or higher)')).toBeInTheDocument();
  expect(screen.getByText('Completed, needs improvement (C or lower)')).toBeInTheDocument();
  expect(screen.getByText('Represented, not attempted this session')).toBeInTheDocument();
  expect(screen.getByText('No scenario coverage')).toBeInTheDocument();
});

test('the List view is a real table carrying the same data', () => {
  render(<AttackMatrix sessionMap={{ 'T1486': { grade: 'A', accuracy: 100 } }} />);
  fireEvent.click(screen.getByRole('button', { name: 'This session' }));
  fireEvent.click(screen.getByRole('button', { name: 'List view' }));
  const table = screen.getByRole('table');
  // one row per represented technique
  expect(within(table).getAllByRole('row')).toHaveLength(1 + ATTACK_TECHNIQUES.length);
  expect(within(table).getByText('Data Encrypted for Impact')).toBeInTheDocument();
  expect(within(table).getByText(/submitted, Incident Grade B or higher \(A, 100%\)/)).toBeInTheDocument();
  // and back to the grid
  fireEvent.click(screen.getByRole('button', { name: 'Grid view' }));
  expect(screen.getByRole('list', { name: 'ATT&CK tactics' })).toBeInTheDocument();
});

test('no mastery claims and no scenario labels anywhere', () => {
  const { container } = render(<AttackMatrix sessionMap={{ 'T1486': { grade: 'A', accuracy: 100 } }} />);
  fireEvent.click(screen.getByRole('button', { name: 'This session' }));
  // the only permitted "mastery" text is the explicit DISCLAIMER
  expect(container.textContent).not.toMatch(/mastered|lifetime|all[- ]time|proficien/i);
  expect(screen.getByText(/not long-term mastery/)).toBeInTheDocument();
  // the mirror is label-free; the rendered matrix must be too
  expect(container.textContent).not.toMatch(/malware_|phishing_|false_positive_|defense_evasion|c2_|insider_|lateral_movement_|password_spray|brute_force|data_exfil/);
});
