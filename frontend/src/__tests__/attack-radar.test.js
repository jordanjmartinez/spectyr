/**
 * V6-R (owner correction): the ATT&CK coverage radar. ONE restrained
 * polygon over the canonical pinned v19.1 tactics; axis value =
 * scenario-represented techniques / AUTHORITATIVE per-tactic technique
 * count (derived from the sha256-verified pinned STIX dataset, parent
 * technique counting on both sides, never normalized against Spectyr's
 * own largest category). No tabs, no list control, no matrix cards, no
 * player or adversary overlay, no buttons at all; percentage rings at
 * 0/25/50/75/100; a complete sr-only table is the text equivalent.
 */
import React from 'react';
import { render, screen, within } from '@testing-library/react';
import AttackRadar from '../components/AttackRadar';
import { coverageByTactic, ATTACK_TACTICS, TACTIC_TOTALS } from '../components/attackCatalog';

test('coverage rows: pinned order, authoritative denominators, parent-technique dedup, honest percentages', () => {
  const rows = coverageByTactic();
  expect(rows.map(r => r.tactic)).toEqual(ATTACK_TACTICS);
  expect(rows).toHaveLength(15);
  const by = Object.fromEntries(rows.map(r => [r.tactic, r]));
  // parent dedup: three Credential Access mirror entries (T1003.001,
  // T1110.001, T1110.003) are TWO parent techniques
  expect(by['Credential Access']).toEqual({ tactic: 'Credential Access', represented: 2, total: 17, pct: 12 });
  expect(by['Initial Access']).toEqual({ tactic: 'Initial Access', represented: 2, total: 11, pct: 18 });
  expect(by['Discovery']).toEqual({ tactic: 'Discovery', represented: 1, total: 34, pct: 3 });
  expect(by['Reconnaissance']).toEqual({ tactic: 'Reconnaissance', represented: 0, total: 12, pct: 0 });
  expect(by['Defense Impairment']).toEqual({ tactic: 'Defense Impairment', represented: 1, total: 18, pct: 6 });
  // every denominator is the authoritative dataset count, present and positive
  rows.forEach(r => {
    expect(r.total).toBe(TACTIC_TOTALS[r.tactic]);
    expect(r.total).toBeGreaterThan(0);
    expect(r.represented).toBeLessThanOrEqual(r.total);
  });
});

test('renders one polygon with percentage rings and the sr-only table equivalent', () => {
  const { container } = render(<AttackRadar />);
  // exactly one radar polygon; no animation classes in play
  expect(container.querySelectorAll('.recharts-radar')).toHaveLength(1);
  // percentage rings 0/25/50/75/100
  for (const ring of ['0%', '25%', '50%', '75%', '100%']) {
    expect(container.textContent).toContain(ring);
  }
  // the complete text equivalent
  const table = screen.getByRole('table');
  expect(within(table).getAllByRole('row')).toHaveLength(1 + 15);
  const caption = container.querySelector('caption');
  expect(caption.textContent).toMatch(/Enterprise ATT&CK v19\.1 \(pinned\)/);
  expect(caption.textContent).toMatch(/ATT&CK-v19\.1/);
  const discovery = within(table).getByText('Discovery').closest('tr');
  expect(discovery.textContent).toBe('Discovery1343%');
  // VL: concise footer + the full derivation on the accessible info tooltip
  expect(screen.getByText(/v19\.1 · represented \/ total techniques per tactic/)).toBeInTheDocument();
  const info = screen.getByRole('button', { name: 'Coverage data source' });
  expect(info.getAttribute('data-help')).toMatch(/parent-technique counting/);
  expect(info.getAttribute('data-help')).toMatch(/ATT&CK-v19\.1/);
  // VL: subtitle + concise visual labels, full names in the sr table
  expect(screen.getByText('Catalog technique coverage')).toBeInTheDocument();
  expect(within(table).getByText('Command and Control')).toBeInTheDocument();
});

test('no tabs, no list control, no matrix leftovers, no overlays, no view controls', () => {
  const { container } = render(<AttackRadar />);
  expect(screen.queryByText('Catalog coverage')).toBeNull();
  expect(screen.queryByText('This session')).toBeNull();
  expect(screen.queryByText('List view')).toBeNull();
  expect(screen.queryByText('No coverage')).toBeNull();
  // the ONLY button is the accessible data-source info tooltip (VL)
  const buttons = screen.queryAllByRole('button');
  expect(buttons).toHaveLength(1);
  expect(buttons[0]).toHaveAccessibleName('Coverage data source');
  expect(screen.queryAllByRole('tab')).toHaveLength(0);
  // no player-performance or adversary overlay vocabulary
  expect(container.textContent).not.toMatch(/submitted|Incident Grade|adversar/i);
  // one polygon only -- never multiple overlapping series
  expect(container.querySelectorAll('.recharts-radar')).toHaveLength(1);
});

test('hidden dashboards render the equivalent table but not the chart', () => {
  const { container } = render(<AttackRadar isVisible={false} />);
  expect(container.querySelector('.recharts-radar')).toBeNull();
  expect(screen.getByRole('table')).toBeInTheDocument();
});
