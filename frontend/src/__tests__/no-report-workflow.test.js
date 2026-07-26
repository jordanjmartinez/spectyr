/**
 * Final pass III.0 item 7: Reports stay hidden and NOTHING implies a
 * report workflow exists. The Dashboard nav guard (hidden Reports tab)
 * lives in nav-badges.test.js (C1 F6); this battery covers the public
 * pages, where the retired workflow was still described.
 */
import React from 'react';
import { render, screen } from '@testing-library/react';

// react-router-dom v7 ships ESM that CRA's jest cannot resolve; these pages
// use only <Link>, so a factory mock stands in for it (the nav-badges
// pattern).
jest.mock('react-router-dom', () => ({
  Link: ({ to, children, ...rest }) => {
    const R = require('react');
    return R.createElement('a', { href: typeof to === 'string' ? to : '#', ...rest }, children);
  },
}), { virtual: true });

const Docs = require('../pages/Docs').default;
const Landing = require('../pages/Landing').default;

beforeAll(() => {
  // jsdom has no IntersectionObserver (the Docs scroll-spy uses one)
  global.IntersectionObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
});

test('the player Docs page has no Reports section and no report-workflow copy', () => {
  const { container } = render(<Docs />);
  expect(screen.queryByText('Reports')).toBeNull();
  expect(container.textContent.toLowerCase()).not.toContain('report');
  expect(container.querySelector('#reports')).toBeNull();
});

test('the landing page offers no Reports destination', () => {
  const { container } = render(<Landing />);
  expect(screen.queryByText('Reports')).toBeNull();
  expect(container.textContent.toLowerCase()).not.toContain('report');
});
