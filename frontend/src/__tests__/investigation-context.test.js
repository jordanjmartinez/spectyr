/**
 * Stage 5 Phase 1 commit 1.1 (contract Amendment 1 Delta A, A1-A.4),
 * simplified by the Final pass (III.0 item 2): the case-constant context is
 * ONE pinned case line. The expanded-search block, its clue line, and the
 * return action retired with the expanded-search state itself; this suite
 * now guards that nothing beyond the line ever renders. The uiCopy module
 * is the single copy source: rendered text is asserted byte-equal to its
 * templates.
 */
import React from 'react';
import { render, screen } from '@testing-library/react';
import InvestigationContext from '../components/InvestigationContext';
import { investigatingCase, ALL_ACTIVITY } from '../components/uiCopy';

const INC = 'INC-8541';

test('pinned line renders the canonical Investigating template for a selected case', () => {
  render(<InvestigationContext incidentId={INC} />);
  expect(screen.getByTestId('pinned-case-line').textContent)
    .toBe(investigatingCase(INC));
});

test('pinned line renders All activity when no case is selected', () => {
  render(<InvestigationContext incidentId={null} />);
  expect(screen.getByTestId('pinned-case-line').textContent)
    .toBe(ALL_ACTIVITY);
});

test('the context is the line alone: no expanded-search block, no return action, no button of any kind', () => {
  const { container } = render(<InvestigationContext incidentId={INC} />);
  expect(screen.queryByTestId('expanded-search-block')).toBeNull();
  expect(screen.queryByTestId('return-chip')).toBeNull();
  expect(container.querySelectorAll('button')).toHaveLength(0);
});
