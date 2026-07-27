/**
 * VA2 (amendment section 4): "Choose your experience". Two experiences
 * only -- Guided and Hardcore. SOC Queue is gone from the player-facing
 * product, the analyst-name input is gone with the invented identity it
 * invited (the product supplies its own generic role label), and the
 * heavy illustrated three-column cards are replaced by two compact
 * radio rows with a single Continue. Guided still opens the
 * answer-neutral catalog picker and selects by opaque catalog_id.
 */
import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import DifficultySelector, { ANALYST_LABEL } from '../components/DifficultySelector';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

const CATALOG = {
  catalog: [
    { catalog_id: 'cat-aaaaaaaaaaaa', title: 'Event Logs Cleared on Workstation', severity: 'Critical', description: 'Logs emptied; no maintenance.', difficulty: null },
    { catalog_id: 'cat-bbbbbbbbbbbb', title: 'Unusual HTTPS Traffic', severity: 'High', description: 'Repeated outbound at an interval.', difficulty: null },
  ],
  random_available: true,
};

beforeEach(() => {
  apiFetch.mockReset();
  apiFetch.mockImplementation((path) =>
    Promise.resolve({ ok: true, json: () => Promise.resolve(path === '/api/guided-catalog' ? CATALOG : {}) }));
});

test('offers exactly two experiences with the ruled copy; no SOC Queue, no name field', () => {
  const { container } = render(<DifficultySelector onSelect={jest.fn()} onCancel={jest.fn()} />);
  expect(screen.getByText('Choose your experience')).toBeInTheDocument();
  expect(screen.getByText('Select how much guidance you want during the investigation.')).toBeInTheDocument();
  const options = screen.getAllByRole('radio');
  expect(options).toHaveLength(2);
  expect(options.map(o => o.textContent.startsWith('Guided') || o.textContent.startsWith('Hardcore')))
    .toEqual([true, true]);
  expect(screen.getByText('Learn with immediate feedback and optional hints.')).toBeInTheDocument();
  expect(screen.getByText('No timer.')).toBeInTheDocument();
  expect(screen.getByText('Investigate independently under time pressure.')).toBeInTheDocument();
  expect(screen.getByText('Feedback appears after submission.')).toBeInTheDocument();
  // removed furniture
  expect(screen.queryByText('SOC Queue')).toBeNull();
  expect(screen.queryByPlaceholderText('Your Name')).toBeNull();
  expect(container.querySelectorAll('input')).toHaveLength(0);
  expect(container.querySelectorAll('img')).toHaveLength(0);   // no oversized artwork
  expect(container.textContent).not.toMatch(/Jordan/);
  // one Continue
  expect(screen.getAllByRole('button', { name: 'Continue' })).toHaveLength(1);
});

test('the selected experience is visible and accessible (radio semantics)', () => {
  render(<DifficultySelector onSelect={jest.fn()} onCancel={jest.fn()} />);
  const [guided, hardcore] = screen.getAllByRole('radio');
  expect(guided).toHaveAttribute('aria-checked', 'true');    // Guided is the default
  expect(hardcore).toHaveAttribute('aria-checked', 'false');
  fireEvent.click(hardcore);
  expect(hardcore).toHaveAttribute('aria-checked', 'true');
  expect(guided).toHaveAttribute('aria-checked', 'false');
  expect(screen.getByRole('radiogroup', { name: 'Experience' })).toBeInTheDocument();
});

test('Hardcore starts immediately with the role label and no catalog fetch', () => {
  const onSelect = jest.fn();
  render(<DifficultySelector onSelect={onSelect} onCancel={jest.fn()} />);
  fireEvent.click(screen.getAllByRole('radio')[1]);
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  expect(onSelect).toHaveBeenCalledWith('hardcore', ANALYST_LABEL);
  expect(ANALYST_LABEL).toBe('Analyst');
  expect(apiFetch).not.toHaveBeenCalledWith('/api/guided-catalog');
});

test('Guided opens the catalog picker and selects a scenario by opaque id', async () => {
  const onSelect = jest.fn();
  render(<DifficultySelector onSelect={onSelect} onCancel={jest.fn()} />);
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));   // Guided is default
  expect(await screen.findByText('Event Logs Cleared on Workstation')).toBeInTheDocument();
  expect(screen.getByText('Random scenario')).toBeInTheDocument();
  fireEvent.click(screen.getByText('Unusual HTTPS Traffic'));
  expect(onSelect).toHaveBeenCalledWith('guided', ANALYST_LABEL, 'cat-bbbbbbbbbbbb');
});

test('Guided Random selects the random sentinel', async () => {
  const onSelect = jest.fn();
  render(<DifficultySelector onSelect={onSelect} onCancel={jest.fn()} />);
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  await screen.findByText('Random scenario');
  fireEvent.click(screen.getByText('Random scenario'));
  expect(onSelect).toHaveBeenCalledWith('guided', ANALYST_LABEL, 'random');
});

test('Practice Another opens straight at the Guided catalog', async () => {
  const onSelect = jest.fn();
  render(<DifficultySelector onSelect={onSelect} onCancel={jest.fn()} initialStep="catalog" initialName="Reviewer" />);
  expect(await screen.findByText('Event Logs Cleared on Workstation')).toBeInTheDocument();
  fireEvent.click(screen.getByText('Unusual HTTPS Traffic'));
  expect(onSelect).toHaveBeenCalledWith('guided', 'Reviewer', 'cat-bbbbbbbbbbbb');
});

test('SOC Queue is unreachable from the player-facing product', () => {
  const fs = require('fs');
  const path = require('path');
  // comments may RECORD the removal; only rendered code is scanned
  const code = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');
  // the picker cannot select it and the docs no longer describe it
  expect(code('components/DifficultySelector.jsx')).not.toMatch(/SOC Queue/);
  expect(code('pages/Docs.jsx')).not.toMatch(/SOC Queue/);
  // the DORMANT engine mapping is deliberately retained (the frozen
  // backend batteries exercise the "analyst" path); nothing routes to it
  expect(read('components/uiCopy.js')).toMatch(/analyst: 'SOC Queue'/);
});
