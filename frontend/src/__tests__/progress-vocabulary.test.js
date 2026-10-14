/**
 * Phase 2 commit 2.1 (Stage 5 consolidated scaffold; locked contract 10.1):
 * the ONE canonical vocabulary. Every Section 10.1 string is a named
 * constant/template in uiCopy.js, pinned byte-exact here, and the forbidden
 * class (correctness phrasing, answer-key-derived totals) never appears in
 * any pre-submission string. Surfaces adopt the constants in 2.2+; this
 * suite is the copy source of truth (risk R7: constants land BEFORE any
 * consumer).
 */
import React from 'react';
import { render, screen } from '@testing-library/react';
import Incidents from '../components/Incidents';
import {
  investigatingCase, ALL_ACTIVITY,
  followingClue, resultsFor, ALL_EVENTS_LABEL, INITIAL_INCIDENT_EVIDENCE,
  INITIAL_EVIDENCE, SELECTED_EVENT_HIDDEN, newEventsAvailable,
  LOAD_NEW_EVENTS,
  STALE_RESULTS_NOTE, TELEMETRY_LOADING, detectionsReviewed,
  detectionsRemaining, PROMOTED_LABEL, DISMISSED_LABEL, REOPENED_LABEL,
  responseActionsTaken, READY_TO_SUBMIT, SUBMITTED_GRADE_LOCKED,
  completedStrip, toReview, filterAdded,
  excludedFilter, CLASSIFY_TO_SUBMIT,
  FILTERS_TOGGLE, MORE_FILTERS, SHOW_MORE_VALUES,
  SHOW_FEWER_VALUES, NO_GROUP_VALUES,
  TOO_MANY_FILTERS, SHOW_EVENTS, FILTERS_EMPTY_HINT, INCIDENT_WINDOW_LABEL,
  ALL_TIME_LABEL, FILTER_TO_THIS, FILTER_OUT_THIS, PIVOT_SEE_ALL,
  COPY_VALUE, OPEN_IN_ENDPOINTS, KEY_FACTS_LABEL, ALL_FIELDS_TOGGLE,
  SEARCH_PLACEHOLDER, SEARCH_BUTTON, searchUnknownField, SEARCH_IP_CONTAINS,
} from '../components/uiCopy';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

// --- byte-exact canonical strings (locked 10.1 + ratified A1-A.5 finals) ---

test('the Section 10.1 canonical vocabulary is byte-exact', () => {
  expect(TELEMETRY_LOADING).toBe('Incident telemetry is still loading.');
  expect(detectionsReviewed(4, 5)).toBe('Detections Reviewed: 4 of 5');
  expect(detectionsRemaining(1)).toBe('1 detection still need Promote or Dismiss');
  expect(detectionsRemaining(3)).toBe('3 detections still need Promote or Dismiss');
  expect(PROMOTED_LABEL).toBe('Promoted');
  expect(DISMISSED_LABEL).toBe('Dismissed');
  expect(REOPENED_LABEL).toBe('Reopened (needs review again)');
  expect(responseActionsTaken(6)).toBe('Response Actions Taken: 6');
  expect(READY_TO_SUBMIT).toBe('Ready to Submit');
  expect(SUBMITTED_GRADE_LOCKED).toBe('Submitted. Grade locked.');
  expect(completedStrip(5)).toBe('Reviewed 5 of 5 · Submitted');
  expect(toReview(2)).toBe('2 to Review');
  // owner UI pass (2026-10-12): the OD-9 Feed/Threats subcopy pair is
  // retired from the shared copy (the Feed line removed from Detections;
  // the Threats line had no remaining render site)
  const copy = require('fs').readFileSync(
    require('path').join(__dirname, '..', 'components', 'uiCopy.js'), 'utf8');
  expect(copy).not.toMatch(/FEED_SUBCOPY =|THREATS_SUBCOPY =/);
});

test('the case-constant terms are the ratified A-OD-1 finals, byte-exact (the expanded-search family retired, III.0 item 2)', () => {
  expect(investigatingCase('INC-8541')).toBe('Investigating INC-8541');
  expect(ALL_ACTIVITY).toBe('All activity');
});

test('the owner SIEM simplification finals are byte-exact; the retired copy is gone from the module', () => {
  expect(CLASSIFY_TO_SUBMIT).toBe('Select a classification to submit.');
  // owner SIEM simplification (2026-10-13): the F7 simple-search copy and
  // the Source / Event Type dropdown copy retired with the controls; the
  // same-day follow-up retired the Advanced LCQL bar and its error
  // apparatus (one simple search box remains)
  const copy = require('fs').readFileSync(
    require('path').join(__dirname, '..', 'components', 'uiCopy.js'), 'utf8');
  for (const retired of ['SIMPLE_HELP =', 'SIMPLE_PLACEHOLDER =', 'SIMPLE_TOGGLE =',
    'SOURCE_LABEL =', 'EVENT_TYPE_LABEL =', 'ALL_SOURCES =', 'ALL_EVENT_TYPES =',
    'ADVANCED_TOGGLE =', 'CUSTOM_QUERY_CHIP =', 'FACET_RESET_NOTICE =',
    'EDITED_NOTE =', 'NO_QUERY_ENTERED =', 'PRESERVED_RESULTS_LABEL =',
    'RESTORE_LAST_QUERY =', 'STRUCTURE_LINE =', 'QUERY_SECTION_NAMES =']) {
    expect(copy).not.toContain(retired);
  }
  expect(FILTERS_TOGGLE).toBe('Filters');
  expect(MORE_FILTERS).toBe('More Filters');
  expect(FILTER_TO_THIS).toBe('Filter to Just This');
  expect(FILTER_OUT_THIS).toBe('Filter This Out');
  expect(PIVOT_SEE_ALL).toBe('Pivot: See Everything About This');
  expect(COPY_VALUE).toBe('Copy');
  expect(KEY_FACTS_LABEL).toBe('Key Facts');
  expect(ALL_FIELDS_TOGGLE).toBe('All Fields');
  expect(INCIDENT_WINDOW_LABEL).toBe('Incident Window');
  expect(SEARCH_BUTTON).toBe('Search');
  expect(searchUnknownField('computr')).toContain('No filter field called "computr"');
  expect(searchUnknownField('x')).toContain('Computer, User Account, Source IP');
});

test('the Section 8.2 clue-naming forms are byte-exact', () => {
  expect(followingClue('user_account', 'ACME\\dpark'))
    .toBe('Following clue: user_account = "ACME\\dpark"');
  expect(filterAdded('hostname', 'ACME-WS10'))
    .toBe('Filter added: hostname == "ACME-WS10"');
  expect(excludedFilter('severity', 'low'))
    .toBe('Excluded: severity != "low"');
});

// --- the forbidden-phrase scan (10.1, binding): pre-submission copy may
// never state or imply correctness, nor carry an answer-key-derived total.
// Enumerated BY NAME (the ruling-B discipline), never an unenumerated
// "every": each pre-submission string in the module is listed here.

// Word-boundary anchored so canonical verbs are never false positives
// (e.g. "Dismissed" must not match "missed").
const FORBIDDEN =
  /\b(correct|incorrect|wrong|solved|missed|harmful|optimal)\b|right answer|required action/i;

const PRE_SUBMISSION_STRINGS = [
  ['investigatingCase', investigatingCase('INC-0001')],
  ['ALL_ACTIVITY', ALL_ACTIVITY],
  ['followingClue', followingClue('user_account', 'x')],
  // Final pass III.0 item 3: the search-state labels
  ['resultsFor', resultsFor('source_ip == "10.0.1.32"')],
  ['ALL_EVENTS_LABEL', ALL_EVENTS_LABEL],
  ['INITIAL_INCIDENT_EVIDENCE', INITIAL_INCIDENT_EVIDENCE],
  ['INITIAL_EVIDENCE', INITIAL_EVIDENCE],
  ['SELECTED_EVENT_HIDDEN', SELECTED_EVENT_HIDDEN],
  // Final pass III.0 item 4: the new-events action
  ['newEventsAvailable', newEventsAvailable(3)],
  ['LOAD_NEW_EVENTS', LOAD_NEW_EVENTS],
  ['STALE_RESULTS_NOTE', STALE_RESULTS_NOTE],
  ['TELEMETRY_LOADING', TELEMETRY_LOADING],
  ['detectionsReviewed', detectionsReviewed(1, 2)],
  ['detectionsRemaining', detectionsRemaining(2)],
  ['PROMOTED_LABEL', PROMOTED_LABEL],
  ['DISMISSED_LABEL', DISMISSED_LABEL],
  ['REOPENED_LABEL', REOPENED_LABEL],
  ['responseActionsTaken', responseActionsTaken(3)],
  ['READY_TO_SUBMIT', READY_TO_SUBMIT],
  ['SUBMITTED_GRADE_LOCKED', SUBMITTED_GRADE_LOCKED],
  ['completedStrip', completedStrip(4)],
  ['toReview', toReview(2)],
  ['filterAdded', filterAdded('a', 'b')],
  ['excludedFilter', excludedFilter('a', 'b')],
  // Amendment 3 (A3.1) pre-submission additions; RETURN_SUBCOPY retired
  // with the expanded-search state (Final pass III.0 item 2)
  ['CLASSIFY_TO_SUBMIT', CLASSIFY_TO_SUBMIT],
  // Owner SIEM simplification pass + follow-up (2026-10-13): the ONE
  // filter system's vocabulary (dropdowns, the F7 projection, Advanced
  // LCQL, and the Custom Query chip all retired)
  ['FILTERS_TOGGLE', FILTERS_TOGGLE],
  ['MORE_FILTERS', MORE_FILTERS],
  ['SHOW_MORE_VALUES', SHOW_MORE_VALUES],
  ['SHOW_FEWER_VALUES', SHOW_FEWER_VALUES],
  ['NO_GROUP_VALUES', NO_GROUP_VALUES],
  ['SEARCH_PLACEHOLDER', SEARCH_PLACEHOLDER],
  ['SEARCH_BUTTON', SEARCH_BUTTON],
  ['searchUnknownField', searchUnknownField('computr')],
  ['SEARCH_IP_CONTAINS', SEARCH_IP_CONTAINS],
  ['TOO_MANY_FILTERS', TOO_MANY_FILTERS],
  ['SHOW_EVENTS', SHOW_EVENTS],
  ['FILTERS_EMPTY_HINT', FILTERS_EMPTY_HINT],
  ['INCIDENT_WINDOW_LABEL', INCIDENT_WINDOW_LABEL],
  ['ALL_TIME_LABEL', ALL_TIME_LABEL],
  ['FILTER_TO_THIS', FILTER_TO_THIS],
  ['FILTER_OUT_THIS', FILTER_OUT_THIS],
  ['PIVOT_SEE_ALL', PIVOT_SEE_ALL],
  ['COPY_VALUE', COPY_VALUE],
  ['OPEN_IN_ENDPOINTS', OPEN_IN_ENDPOINTS],
  ['KEY_FACTS_LABEL', KEY_FACTS_LABEL],
  ['ALL_FIELDS_TOGGLE', ALL_FIELDS_TOGGLE],
];

test('no pre-submission canonical string carries the forbidden class', () => {
  for (const [name, value] of PRE_SUBMISSION_STRINGS) {
    expect({ name, forbidden: FORBIDDEN.test(value) })
      .toEqual({ name, forbidden: false });
  }
});

test('no canonical string contains an em dash', () => {
  for (const [name, value] of PRE_SUBMISSION_STRINGS) {
    expect({ name, emdash: /—/.test(value) })
      .toEqual({ name, emdash: false });
  }
});

// --- 2.2: surfaces render the constants (canonical-copy per surface) -------

test('the decluttered panel: the row chip speaks the vocabulary; the strip lines no longer render (owner 2026-10-12)', async () => {
  apiFetch.mockImplementation((path) => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(
      path === '/api/incidents'
        ? { active: [{ incident_id: 'INC-1', title: 'T', briefing: 'b',
                       severity: 'High', state: 'in_progress', sealed: true,
                       triage: { total: 5, triaged: 4 }, open_detections: 1,
                       ready: false, related_actions: 6 }],
            completed: [], queue_length: 1, resolved_count: 0 }
        : path.endsWith('/scope')
          ? { incident_id: 'INC-1', sealed: true, hosts: [], accounts: [],
              detection_ids: [] }
          : {}),
  }));
  render(
    <Incidents gameMode="soc_queue" activeIncidentId="INC-1"
      onSelectIncident={() => {}} />
  );
  // the list row chip still speaks the canonical vocabulary
  expect(await screen.findByText('1 to Review')).toBeInTheDocument();
  // owner declutter (2026-10-12): the checklist lines and the remaining-
  // count text no longer render in the panel
  expect(screen.queryByText('Detections Reviewed: 4 of 5')).toBeNull();
  expect(screen.queryByText('Response Actions Taken: 6')).toBeNull();
  expect(screen.queryByText(/1 detection still need Promote or Dismiss/)).toBeNull();
  // ruling A: the fuzzy related-activity LIST is gone; no such block renders
  expect(screen.queryByText(/Related response activity/)).toBeNull();
});

test('a completed incident renders the completed strip, never the active strip (0-of-0 structurally impossible)', async () => {
  apiFetch.mockImplementation((path) => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(
      path === '/api/incidents'
        ? { active: [],
            completed: [{ incident_id: 'INC-9', title: 'T', briefing: 'b',
                          severity: 'High', state: 'submitted',
                          submitted_at: 'x', assisted: false,
                          incident_grade: { grade: 'A', accuracy: 100 } }],
            queue_length: 1, resolved_count: 1 }
        : path.endsWith('/score')
          ? { state: 'submitted', assisted: false,
              grading: { detection: { total: 5 }, classification: {},
                         response: {}, composite: {} } }
          : path.endsWith('/scope')
            ? { incident_id: 'INC-9', sealed: true, hosts: [], accounts: [],
                detection_ids: [] }
            : {}),
  }));
  render(
    <Incidents gameMode="soc_queue" activeIncidentId="INC-9"
      onSelectIncident={() => {}} />
  );
  expect(await screen.findByText('Reviewed 5 of 5 · Submitted')).toBeInTheDocument();
  // the active strip's vocabulary never renders for a submitted incident
  expect(screen.queryByText(/Detections Reviewed: 0 of 0/)).toBeNull();
  expect(screen.queryByText('pending')).toBeNull();
  expect(screen.queryByText('Incident telemetry is still loading.')).toBeNull();
});
