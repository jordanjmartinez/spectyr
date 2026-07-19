/**
 * Stage 3.9B Step 3: the three renamed modes and the Guided catalog picker.
 * Guided opens the answer-neutral picker (title / severity / neutral description;
 * difficulty is NOT presented) and selects one scenario (or Random) by opaque
 * catalog_id; SOC Queue and Hardcore start immediately with no catalog.
 */
import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import DifficultySelector from '../components/DifficultySelector';

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
  apiFetch.mockImplementation((path) =>
    Promise.resolve({ ok: true, json: () => Promise.resolve(path === '/api/guided-catalog' ? CATALOG : {}) }));
});

const nameIt = () => fireEvent.change(screen.getByPlaceholderText('Your Name'), { target: { value: 'A' } });

test('offers the three renamed modes', () => {
  render(<DifficultySelector onSelect={jest.fn()} onCancel={jest.fn()} />);
  expect(screen.getByText('Guided')).toBeInTheDocument();
  expect(screen.getByText('SOC Queue')).toBeInTheDocument();
  expect(screen.getByText('Hardcore')).toBeInTheDocument();
});

test('SOC Queue starts immediately with no catalog fetch', () => {
  const onSelect = jest.fn();
  render(<DifficultySelector onSelect={onSelect} onCancel={jest.fn()} />);
  nameIt();
  fireEvent.click(screen.getByText('SOC Queue'));
  expect(onSelect).toHaveBeenCalledWith('analyst', 'A');
  expect(apiFetch).not.toHaveBeenCalledWith('/api/guided-catalog');
});

test('Guided opens the catalog picker and selects a scenario by opaque id', async () => {
  const onSelect = jest.fn();
  render(<DifficultySelector onSelect={onSelect} onCancel={jest.fn()} />);
  nameIt();
  fireEvent.click(screen.getByText('Guided'));
  expect(await screen.findByText('Event Logs Cleared on Workstation')).toBeInTheDocument();
  expect(screen.getByText('Random scenario')).toBeInTheDocument();
  fireEvent.click(screen.getByText('Unusual HTTPS Traffic'));
  expect(onSelect).toHaveBeenCalledWith('guided', 'A', 'cat-bbbbbbbbbbbb');
});

test('Guided Random selects the random sentinel', async () => {
  const onSelect = jest.fn();
  render(<DifficultySelector onSelect={onSelect} onCancel={jest.fn()} />);
  nameIt();
  fireEvent.click(screen.getByText('Guided'));
  await screen.findByText('Random scenario');
  fireEvent.click(screen.getByText('Random scenario'));
  expect(onSelect).toHaveBeenCalledWith('guided', 'A', 'random');
});

test('Practice Another opens straight at the Guided catalog with the name preset', async () => {
  const onSelect = jest.fn();
  render(<DifficultySelector onSelect={onSelect} onCancel={jest.fn()} initialStep="catalog" initialName="Reviewer" />);
  expect(await screen.findByText('Event Logs Cleared on Workstation')).toBeInTheDocument();  // catalog, no mode step
  expect(screen.getByText('Random scenario')).toBeInTheDocument();
  fireEvent.click(screen.getByText('Unusual HTTPS Traffic'));   // name already valid
  expect(onSelect).toHaveBeenCalledWith('guided', 'Reviewer', 'cat-bbbbbbbbbbbb');
});

test('a name is required before any mode can be picked', () => {
  const onSelect = jest.fn();
  render(<DifficultySelector onSelect={onSelect} onCancel={jest.fn()} />);
  fireEvent.click(screen.getByText('Guided'));   // no name entered
  expect(onSelect).not.toHaveBeenCalled();
  expect(apiFetch).not.toHaveBeenCalledWith('/api/guided-catalog');
});
