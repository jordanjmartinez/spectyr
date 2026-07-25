/**
 * Stage 5 Phase 1 commit 1.1 (consolidated scaffold; contract Amendment 1
 * Delta A, A1-A.4 / translated acceptance 13): the case-constant context
 * presentation, rendered from mocked props only -- the component is pure
 * and is not mounted anywhere until commit 1.2. The uiCopy module is the
 * single copy source: rendered text is asserted byte-equal to its
 * templates.
 */
import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import InvestigationContext from '../components/InvestigationContext';
import {
  investigatingCase, ALL_ACTIVITY, EXPANDED_SEARCH_TITLE, followingClue,
  expandedSearchExplanation, returnToCaseEvidence, returnSubcopy,
} from '../components/uiCopy';

const INC = 'INC-8541';

test('pinned line renders the canonical Investigating template for a selected case', () => {
  render(<InvestigationContext incidentId={INC} expandedSearch={null} />);
  expect(screen.getByTestId('pinned-case-line').textContent)
    .toBe(investigatingCase(INC));
});

test('pinned line renders All activity when no case is selected', () => {
  render(<InvestigationContext incidentId={null} expandedSearch={null} />);
  expect(screen.getByTestId('pinned-case-line').textContent)
    .toBe(ALL_ACTIVITY);
});

test('no expanded-search block renders by default', () => {
  render(<InvestigationContext incidentId={INC} expandedSearch={null} />);
  expect(screen.queryByTestId('expanded-search-block')).toBeNull();
});

test('expanded-search block: title, clue line, explanation, and exactly ONE return action', () => {
  const onReturn = jest.fn();
  render(
    <InvestigationContext
      incidentId={INC}
      expandedSearch={{ clue: { field: 'user_account', value: 'ACME\\dpark' }, onReturn }}
    />,
  );
  const block = screen.getByTestId('expanded-search-block');
  expect(block.textContent).toContain(EXPANDED_SEARCH_TITLE);
  expect(block.textContent)
    .toContain(followingClue('user_account', 'ACME\\dpark'));
  expect(block.textContent).toContain(expandedSearchExplanation(INC));
  const buttons = block.querySelectorAll('button');
  expect(buttons).toHaveLength(1);
  expect(buttons[0].textContent).toBe(returnToCaseEvidence(INC));
  expect(block.textContent).toContain(returnSubcopy(INC));
  fireEvent.click(buttons[0]);
  expect(onReturn).toHaveBeenCalledTimes(1);
});

test('search-all entry: the block renders without a clue line', () => {
  render(
    <InvestigationContext
      incidentId={INC}
      expandedSearch={{ clue: null, onReturn: () => {} }}
    />,
  );
  const block = screen.getByTestId('expanded-search-block');
  expect(block.textContent).not.toContain('Following clue:');
  expect(block.textContent).toContain(expandedSearchExplanation(INC));
});

test('no block without a pinned case: the no-case SIEM is plain All activity', () => {
  render(
    <InvestigationContext
      incidentId={null}
      expandedSearch={{ clue: null, onReturn: () => {} }}
    />,
  );
  expect(screen.queryByTestId('expanded-search-block')).toBeNull();
  expect(screen.getByTestId('pinned-case-line').textContent)
    .toBe(ALL_ACTIVITY);
});
