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
  investigatingCase, ALL_ACTIVITY, caseEvidenceLabel, EXPANDED_SEARCH_TITLE,
  followingClue, expandedSearchExplanation, returnToCaseEvidence,
  SEARCH_ALL_EVIDENCE, RESULTS_FROM_LABEL, EDITED_NOTE,
  STALE_RESULTS_NOTE, TELEMETRY_LOADING, detectionsReviewed,
  detectionsRemaining, PROMOTED_LABEL, DISMISSED_LABEL, REOPENED_LABEL,
  responseActionsTaken, READY_TO_SUBMIT, SUBMITTED_GRADE_LOCKED,
  completedStrip, toReview, FEED_SUBCOPY, THREATS_SUBCOPY, filterAdded,
  excludedFilter, RETURN_SUBCOPY, CLASSIFY_TO_SUBMIT,
  SIMPLE_PLACEHOLDER, SIMPLE_HELP, SIMPLE_TOGGLE, ADVANCED_TOGGLE,
  SOURCE_LABEL, EVENT_TYPE_LABEL, ALL_SOURCES, ALL_EVENT_TYPES,
} from '../components/uiCopy';

jest.mock('../api', () => ({ apiFetch: jest.fn() }));
const { apiFetch } = require('../api');

// --- byte-exact canonical strings (locked 10.1 + ratified A1-A.5 finals) ---

test('the Section 10.1 canonical vocabulary is byte-exact', () => {
  expect(TELEMETRY_LOADING).toBe('Incident telemetry is still loading.');
  expect(detectionsReviewed(4, 5)).toBe('Detections reviewed: 4 of 5');
  expect(detectionsRemaining(1)).toBe('1 detection still need Promote or Dismiss');
  expect(detectionsRemaining(3)).toBe('3 detections still need Promote or Dismiss');
  expect(PROMOTED_LABEL).toBe('Promoted');
  expect(DISMISSED_LABEL).toBe('Dismissed');
  expect(REOPENED_LABEL).toBe('Reopened (needs review again)');
  expect(responseActionsTaken(6)).toBe('Response actions taken: 6');
  expect(READY_TO_SUBMIT).toBe('Ready to submit');
  expect(SUBMITTED_GRADE_LOCKED).toBe('Submitted. Grade locked.');
  expect(completedStrip(5)).toBe('Reviewed 5 of 5 · Submitted');
  expect(toReview(2)).toBe('2 to review');
  expect(FEED_SUBCOPY).toBe('Feed: every detection, including reviewed');
  expect(THREATS_SUBCOPY).toBe('Threats: detections you promoted');
});

test('the case-constant terms are the ratified A-OD-1 finals, byte-exact', () => {
  expect(investigatingCase('INC-8541')).toBe('Investigating INC-8541');
  expect(ALL_ACTIVITY).toBe('All activity');
  expect(caseEvidenceLabel('INC-8541')).toBe('INC-8541 evidence');
  expect(EXPANDED_SEARCH_TITLE).toBe('Expanded search');
  expect(expandedSearchExplanation('INC-8541'))
    .toBe('Searching all evidence. Your case INC-8541 stays open.');
  expect(returnToCaseEvidence('INC-8541')).toBe('Return to INC-8541 evidence');
  expect(SEARCH_ALL_EVIDENCE).toBe('Search all evidence');
});

test('the Amendment 3 ratified finals are byte-exact (A3-R.1 + standing drafted finals)', () => {
  expect(RETURN_SUBCOPY).toBe(
    'Return restores the incident evidence you were viewing before Expanded search. Changes made in Expanded search are not kept.');
  expect(CLASSIFY_TO_SUBMIT).toBe('Select a classification to submit.');
  expect(SIMPLE_PLACEHOLDER).toBe('Example: source_ip == "10.0.1.32"');
  expect(SIMPLE_HELP).toBe(
    'Enter a filter expression. Timeframe, source, and event type are controlled above.');
  expect(SIMPLE_TOGGLE).toBe('Simple search');
  expect(ADVANCED_TOGGLE).toBe('Advanced LCQL');
  expect(SOURCE_LABEL).toBe('Source');
  expect(EVENT_TYPE_LABEL).toBe('Event type');
  expect(ALL_SOURCES).toBe('All sources');
  expect(ALL_EVENT_TYPES).toBe('All event types');
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
  ['caseEvidenceLabel', caseEvidenceLabel('INC-0001')],
  ['EXPANDED_SEARCH_TITLE', EXPANDED_SEARCH_TITLE],
  ['followingClue', followingClue('user_account', 'x')],
  ['expandedSearchExplanation', expandedSearchExplanation('INC-0001')],
  ['returnToCaseEvidence', returnToCaseEvidence('INC-0001')],
  ['SEARCH_ALL_EVIDENCE', SEARCH_ALL_EVIDENCE],
  ['RESULTS_FROM_LABEL', RESULTS_FROM_LABEL],
  ['EDITED_NOTE', EDITED_NOTE],
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
  ['FEED_SUBCOPY', FEED_SUBCOPY],
  ['THREATS_SUBCOPY', THREATS_SUBCOPY],
  ['filterAdded', filterAdded('a', 'b')],
  ['excludedFilter', excludedFilter('a', 'b')],
  // Amendment 3 (A3.1): the pre-submission additions (the C1 guard string
  // and the model A subcopy retired with the F2 model B mechanics)
  ['RETURN_SUBCOPY', RETURN_SUBCOPY],
  ['CLASSIFY_TO_SUBMIT', CLASSIFY_TO_SUBMIT],
  ['SIMPLE_PLACEHOLDER', SIMPLE_PLACEHOLDER],
  ['SIMPLE_HELP', SIMPLE_HELP],
  ['SIMPLE_TOGGLE', SIMPLE_TOGGLE],
  ['ADVANCED_TOGGLE', ADVANCED_TOGGLE],
  ['SOURCE_LABEL', SOURCE_LABEL],
  ['EVENT_TYPE_LABEL', EVENT_TYPE_LABEL],
  ['ALL_SOURCES', ALL_SOURCES],
  ['ALL_EVENT_TYPES', ALL_EVENT_TYPES],
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

test('the phase strip renders the canonical vocabulary from card observables, D4 count included', async () => {
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
  expect(await screen.findByText('Detections reviewed: 4 of 5')).toBeInTheDocument();
  expect(screen.getByText('Response actions taken: 6')).toBeInTheDocument();
  expect(screen.getByText('1 to review')).toBeInTheDocument();
  expect(screen.getByText(/1 detection still need Promote or Dismiss/)).toBeInTheDocument();
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
  expect(screen.queryByText(/Detections reviewed: 0 of 0/)).toBeNull();
  expect(screen.queryByText('pending')).toBeNull();
  expect(screen.queryByText('Incident telemetry is still loading.')).toBeNull();
});
