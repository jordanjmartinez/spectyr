# Stage 4 — SIEM Investigation Workbench: Implementation Report

Closing evidence for Stage 4 (LCQL + the SIEM Investigation Workbench),
produced at the Phase 9 certification checkpoint. This report is the
single closing artifact required by the implementation scaffold's Phase 9.

**Status:** Phases 1–9 complete on branch `stage-4-siem-workbench`. NOT
merged to `main`; awaiting owner and reviewer approval.

---

## 1. Final branch tip

- Branch: `stage-4-siem-workbench`
- Tip before this artifact: **`9556636`** (`Stage 4 P8 closure: append-only Phase 8 milestone records`)
- This report lands as the Phase 9.2 docs-only commit on top of `9556636`.
- Stage 4 base (pre-lock `main` tip / hotfix): `37486b1`.

## 2. Phase 1–9 commit ledger (chronological, `37486b1..HEAD`)

| # | Commit | Summary |
|---|--------|---------|
| 1 | `eb49610` | Stage 4A: lock the SIEM Workbench contract (Revision 3) |
| 2 | `e0bdf16` | SIEM Workbench implementation scaffold (docs-only, for approval) |
| 3 | `ccdaeaa` | scaffold: fold in the owner review corrections (approved) |
| 4 | `df9990a` | **P1.1** deterministic simulation epoch + authored occurrence times (A1) |
| 5 | `b61dac7` | **P1.2** event_seq foundation + background occurrence times |
| 6 | `730891e` | **P1.3** OD-10 shape-parity amendment (user → user_account; protocol into kvp) |
| 7 | `8a11d11` | docs: record the exercised K2 background-spacing tuning measurement |
| 8 | `7d0e2c3` | **P2.1** LCQL structural core (tokenizer, parser, AST, canonicalizer) |
| 9 | `070c263` | **P2.2** LCQL field catalog and resolution (GD-2) |
| 10 | `4e983a8` | **P2.3** LCQL evaluator, quote-case semantics, pivot/descent + OR-scan corpora |
| 11 | `fb6cfad` | docs: Erratum E1 (41 data-derived event types) + GD-5a ratification |
| 12 | `f290919` | docs: complete the GD-5a Phase 8.4 annotation missed by fb6cfad |
| 13 | `29a715f` | **P3.1** GET /api/events/query (snapshot identity, token mint, observable hostname catalog) |
| 14 | `18d9938` | **P3.2** snapshot-token validation, secret rotation, refresh-now new-count |
| 15 | `a8f44cd` | **P3.3** transitional route audit (single event-query path) |
| 16 | `7650fe2` | **P3.4** (Amendment E2) freeze resolved_scope_hosts into the snapshot identity |
| 17 | `1694217` | **P4.1** SIEM workbench shell (query bar, Run Query, frozen snapshot rendering) |
| 18 | `0fd08b4` | **P4.2** scope control (revised error behavior) + TIMEFRAME segment editor |
| 19 | `8368f36` | **P4** closure: permanent default-scope guard test |
| 20 | `03295e6` | docs: record the accepted Phase 4 test-replacement deviation |
| 21 | `00a79dd` | **P5.1** explicit Refresh, atomic replacement, id-keyed selection persistence |
| 22 | `7ef6c0b` | **P5.2** new-events indicator, pool-growth readout, token-bound poll, sort proofs |
| 23 | `f9b2b3a` | ride-along: scope-change-without-Run de-emphasizes the indicator |
| 24 | `167d79f` | **P6.1** LCQL pivot generator (lcqlPivots.js), the single choke point |
| 25 | `eade21a` | **P6.2** snapshot-scoped field sidebar (fieldSummary.js, FieldSidebar.jsx) |
| 26 | `08bcee9` | **P6.3** event inspector (EventInspector.jsx), one lens over the sanitized event |
| 27 | `d354410` | **P6** fix: sidebar value click passes the '==' operator explicitly |
| 28 | `21b77bf` | **P6.3** completion: kvp catalog order pinned by a shared fixture |
| 29 | `8ee0a66` | **P7.1** entity pivots, Session-wide flip, return-to-incident chip |
| 30 | `3810591` | **P7.2** Open Evidence Timeline descent, origin banner, breadcrumb |
| 31 | `ebd98c3` | **P7.3** surrounding-event investigation + OR-fallback notice UX |
| 32 | `25ace9c` | **P7.4** identity-detection evidence descent (R17 uniform control) |
| 33 | `b4475e2` | **P7.5** identity descent = uniform two-field OR (account + UPN) |
| 34 | `ebd2e5f` | **P8.1** Dashboard session-existence check migrates to game-state |
| 35 | `bdb09f8` | **P8.2** severity stats relocate to /api/incidents; Dashboard migrates |
| 36 | `c263fb5` | **P8.3** route deletions — one event path (point of no return) |
| 37 | `3ddf1fe` | **P8.4** docs pass — the retirement is documented truthfully |
| 38 | `9556636` | **P8** closure: append-only Phase 8 milestone records (docs-only) |
| 39 | *(this report)* | **P9.2** Stage 4 closing evidence artifact (docs-only) |

Phase 9.1 (test gap-fills) produced **no commit**: the acceptance-matrix
audit (§4) found every criterion backed by an automated test — none was
prose-only.

## 3. Authoritative final gate output

Run before the Phase 9 workflow servers were started (dev-harness rule:
batteries never run against a live backend sharing `backend/logs`):

```
python backend/run_gates.py --all
...
[gate] ALL GREEN
Test Suites: 17 passed, 17 total
Tests:       164 passed, 164 total
```

- Backend battery: all suites PASS (373 backend test functions across 24 files, incl. `test_lcql` 46, `test_query_read` 21, `test_event_disclosure` 8, `test_submission_gate` 22, `test_sim_epoch` 8, `test_event_seq` 8).
- Frontend battery: 17 suites / 164 tests PASS (incl. workbench-pivots, workbench-sidebar, workbench-inspector, workbench-snapshot, workbench-states, workbench-cross-host, workbench-descent, workbench-surrounding, scope-no-mutation, incident-dashboard, copy-emdash).

## 4. Section 18 acceptance matrix

Every criterion maps to a named automated test (result: PASS) and, where
applicable, a live Chrome workflow (§5). Evidence labelled **Automated**,
**Observed**, or **Both**. No prose-only rows.

| Section 18 criterion | Automated test (file::test) | Chrome workflow | Evidence |
|---|---|---|---|
| Hierarchy / 3.9 battery green incl. detection indistinguishability | `test_detection_indistinguishability.py` (6); full 3.9 battery | W3, W8 | Both |
| Sanitized payloads (recursive planted-marker absence, structural whitelist) | `test_event_disclosure.py::test_query_rows_serialize_only_the_whitelist`, `::test_query_rows_unknown_future_field_does_not_pass_through`, `::test_no_planted_answer_marker_in_query_or_count_response` | W9 | Both |
| Shape parity (OD-10): no population-exclusive top-level field; no top-level protocol | `test_event_disclosure.py::test_shape_parity_no_population_exclusive_top_level_field`; `test_detections`/live-drip parity | W9 | Both |
| event_seq foundation (uniqueness, monotonicity, assign-once, append-only, read-no-mutation) | `test_event_seq.py` (8) | W1, W9 | Both |
| Stable snapshots (byte-stable rows/order under a growing pool; atomic replacement) | `workbench-snapshot.test.js` (rows byte-stable across poll cycles; atomic replacement) | W1 | Both |
| Deterministic replay (identical identity → byte-identical rows) | `test_query_read.py::test_identical_identity_replays_byte_identical`, `::test_token_reexecution_equals_identity_reexecution` | — | Automated |
| Explicit refresh (new cutoff+token; prior untouched; selection persists/absence notice) | `test_query_read.py::test_preseal_scope_growth_replay_and_refresh_semantics`; `workbench-snapshot.test.js` | W1 | Both |
| Canonical order and client sort (server order == canonical; client sort no request/token change) | `test_query_read.py::test_rows_in_canonical_order`; `workbench-snapshot.test.js` (client sort issues no request) | W1 | Both |
| Token security (altered/foreign/post-reset fail neutrally & indistinguishably) | `test_query_read.py::test_invalid_tokens_fail_neutrally_and_identically` | **W7** | Both |
| Shared epoch (`world["started_at"]` == epoch; frozen-time guard) | `test_sim_epoch.py::test_world_started_at_equals_epoch`; `test_snapshot_generator.py` frozen-time guard | — | Automated |
| New-count (OD-6 semantics, token-bound; pool_growth independent; zero-state hidden; edited text can't alter count) | `test_query_read.py::test_new_count_matches_refresh_now_semantics_and_pool_growth`, `::test_new_count_request_carries_token_only`, `::test_new_count_does_not_mutate` | W1, W8 | Both |
| Time semantics (A1): occurrence == recompute; sim-now == pool max; corrected docs | `test_sim_epoch.py::test_occurrence_times_recompute_from_epoch_spacing_offsets_gapstream`, `::test_no_wall_clock_in_occurrence_timestamps`; `test_event_seq.py::test_authored_background_gap_within_bound` | W9 | Both |
| Query parsing (valid examples parse; INVALID reject w/ position+reason; GD-3; quote-case; idempotence) | `test_lcql.py` (46) | W1, W5 | Both |
| Pivot and descent generation (every Section 13 form parses & equals documented shape; escaping; OR fallback; both descent forms) | `workbench-pivots.test.js`; `test_lcql.py::test_documented_pivot_and_descent_forms_parse` | W2, W3, W4, W5 | Both |
| Inspector completeness (every whitelisted field per family; recursive props check; event_seq displays) | `workbench-inspector.test.js` (8-family matrix + recursive leak guard) | W2 | Both |
| Incident scoping (scoped ⊆ session; constraint == participant hosts; structural guard) | `test_query_read.py::test_scoped_results_subset_and_constraint_equals_participant_hosts`; `test_incident_scope.py` | W4 | Both |
| Cross-host pivots (entity pivot from incident scope lands Session-wide; return chip restores; all reads) | `workbench-cross-host.test.js` (18) | **W4** | Both |
| Mode visibility (all modes through the query read; route audit finds no mode-specific endpoint; grouped-alerts trigger branch removed) | `test_query_read.py::test_no_mode_specific_event_endpoint`, `::test_route_audit_single_event_query_path` | **W8** | Both |
| States (per-pane states incl. revised scope-error: chip retained, Run disabled, no silent fallback) | `workbench-states.test.js` | **W6** (see §7) | Both* |
| No-mutation reads (query/refresh/new-count/pivot/descent/scope switch/inspector are GETs) | `scope-no-mutation.test.js`; `test_query_read.py::test_query_read_does_not_mutate`, `::test_new_count_does_not_mutate` | W2–W5, W8 | Both |
| Zero grading leaks (planted markers never in query/count; submission-gate battery green) | `test_event_disclosure.py`; `test_submission_gate.py` (22) | W8, W9 | Both |
| Zero row movement (no insert/remove/reorder while the mocked pool grows across poll cycles) | `workbench-snapshot.test.js` (rows stay byte-stable across multiple poll cycles) | **W1** | Both |

\* States row: the revised scope-error behavior is fully covered automated;
the live DevTools request-blocking reproduction of W6 was not achievable
with the browser-automation tooling (harness limitation, §7).

## 5. Nine Chrome workflow transcripts

All workflows run against a dedicated backend instance; console and network
captures cleared before each. Screenshots referenced are stable evidence IDs
from the certification session (not archived to disk).

**W1 — Session-wide investigation + frozen results.** SOC Queue run.
Executed `1h | Sysmon | ProcessCreate | command_line contains "powershell"`
(0 rows this seed; header correct: `seq #106`, sim time). Then
`all | * | * | *` → snapshot **124 events, seq #124, 06:14:12 sim**, top row
`4624 06:14:12 ACME-WS45`. Held open ~65s of live drip: header + all rows +
sidebar counts **byte-identical (zero row movement)**; indicator counted to
**`101 new`**, **`pool: +101`**. Deliberate **Refresh → atomic replacement**
124 → **241 events, seq #241, 06:20:03 sim**, indicator reset. *(ss_31226mdyx,
ss_45296svqi, ss_21109teq2 equivalents.)*

**W2 — Incident descent.** Incidents → INC-6345 (Mass File Encryption) → Open
Evidence Timeline → `GET /api/events/query?q=all | ACME-WS05 | * | *&scope=INC-6345`.
Scope "Focused on INC-6345", banner "Evidence timeline for ACME-WS05, from
INC-6345 — occurrence ascending", ransomware chain ascending (svchost →
vssadmin → `.locked` → DECRYPT_YOUR_FILES.txt). Inspector: identity incl.
**"arrived as event #6"**, sanitized RAW JSON (no forbidden fields). Breadcrumb
**"Back to Incidents"** returned with INC-6345 still focused. Zero console errors.

**W3 — Detection descent.** Scenario detection "Shadow Copy Deletion via
vssadmin" (ACME-WS05): trigger card is a **rule-evidence summary** (Rule text,
MITRE T1490, File/PID/SHA256), not a SIEM row; no correctness disclosure.
Ambient detection "Software Updater Outbound Connection" (ACME-WS05): identical
layout/control. Both descents fired the **byte-identical** query
`all | ACME-WS05 | * | *&scope=session` — indistinguishability through descent.

**W4 — Pivot chain + scope flip.** From the ACME-WS05 timeline: account →
`all | * | * | user_account == "ACME\\dpark"` (GD-5 escaped); IP →
`all | * | * | source_ip == "10.0.1.202" or destination_ip == "10.0.1.202"`
(130 events, many hosts); another host → `all | ACME-WS03 | * | *`. Each
visible/editable/parsed. Scope-flip shown explicitly: running
`all | ACME-WS05 | * | *` under INC-6345 then pivoting account flipped the
scope control **"Focused on INC-6345" → "Session-wide"** with the
**"Back to INC-6345" chip** appearing. Chip re-ran the current query under
`scope=INC-6345` → **0 events** (honest participant filter: WS03 ∉ INC-6345).

**W5 — OR-query protection.** `4h | DNS | QUERY | query contains "google" or
query contains "microsoft"` (17 events). Sidebar value click (ACME-WS18) →
**fresh standalone query** `4h | DNS | QUERY | hostname == "ACME-WS18"` (not an
append) with the exact notice **"Started a new query; the previous one mixed
or-conditions."**

**W6 — Scope failure.** DevTools request-blocking on
`/api/incidents/<id>/scope` was not achievable via the browser-automation
tooling (harness limitation). The behavior is fully covered by
`workbench-states.test.js` ("scope-error: chip retained, prior snapshot
preserved, Run disabled, no silent fallback; retry and explicit Session-wide
recover"), PASS.

**W7 — Token lifecycle (all six neutral failures, byte-identical).** Captured a
valid token (baseline 200). Every class returned **`{"error":"Unknown token"}`
[400]**, byte-identical:
1. altered token — 400 `{"error":"Unknown token"}`
2. garbage token — 400 `{"error":"Unknown token"}`
3. foreign-session token — 400 `{"error":"Unknown token"}`
4. Reset (secret rotates) — 400 `{"error":"Unknown token"}`
5. Practice Another (start-simulator rotates) — 400 `{"error":"Unknown token"}`
6. **backend restart** — 400 `{"error":"Unknown token"}`, with a **fresh
   X-Session-ID minted** (`35d08498…` ≠ stale `017caa9c…`), confirming the
   stale-session middleware re-creation path is traversed before token
   validation yet still returns the identical neutral body.
(One earlier run showed a 200 on the Practice-Another case; diagnosed as a
shell session-id parsing artifact in the test harness, not a product defect —
the correctly-parsed isolated re-run returned 400. §7.)

**W8 — All three modes.** In **Guided**, **SOC Queue** (W1–W5), and
**Hardcore** (15:00 timer live), the SIEM tab issued **only**
`/api/events/query` + `/api/events/query/new-count` for events; **zero**
fake-events / grouped-alerts in any mode. Pre-submission grading withheld:
`/api/analytics/report_card` returned
`{"state":"in_progress","progress":{...observable counts only...}}` (no grade,
no answer-key total). Workbench behavior identical modulo intake/timer.

**W9 — Console/network audit + time coherence.** Query payload (103 rows):
top-level keys are **exactly** the 12 whitelisted fields; **zero forbidden
top-level hits**; **no top-level `protocol`** (OD-10). Identity keys:
canonical_query/cutoff_seq/resolved_range/resolved_scope_hosts/scope. new-count
payload: only `new_count`+`pool_growth`. Time coherence: the cleanly
identifiable ransomware chain (04:30–04:33) had **47 background events within
its timespan** — interspersed, not a detached block; latest-authored vs
latest-background gap **243s (≤ 300s)** at the first measurement. All-tab sweep
(Dashboard, Incidents, SIEM, Detections, Endpoints, Metrics, Reports): **zero
fake-events, zero grouped-alerts, zero steady-state console errors.**

## 6. K8 latency

In-process measurement (Flask test client, session-scale pool of 400 events),
50 samples each, against the 250 ms sustained halt condition:

| Route | min | p50 | p95 | max | mean |
|---|---|---|---|---|---|
| `/api/events/query` | 4.4 ms | **4.5 ms** | 4.8 ms | 5.2 ms | 4.5 ms |
| `/api/events/query/new-count` | 3.3 ms | **3.3 ms** | 3.4 ms | 3.5 ms | 3.3 ms |

**Sustained behavior far below the 250 ms halt condition** (~55× headroom on
the query read). No architecture change or amendment indicated.

## 7. Time coherence — quantified bound (authoritative) + live corroboration

The authoritative quantified proof of the K2 authored/background coherence
bound is **`test_event_seq.py::test_authored_background_gap_within_bound`** — a
reference write model over the live catalog (10 positions, worst-case chain
length + hi-offsets + supplemental counts, background spacing) asserting the
latest-authored vs latest-background occurrence gap **≤ 300s**. It is **GREEN**
in the battery, and background spacing is the ruled first tuning knob if it
ever fails (already exercised 2s→3s at scaffold correction).

Live corroboration (W9) confirms the **interleave** (47 background events within
the identifiable chain's timespan) and a first-measurement gap of **243s**. A
naive content-marker classifier over sanitized payloads cannot reliably
identify *all* authored raw events (many authored events carry benign-looking
content), so a precise *live* gap number is not measurable from the client —
the reference-model test is the authority. A later live figure of 597s was an
**artifact** of (a) the classifier freezing on the one identifiable chain while
background advanced, and (b) detection materialization running ahead of raw-event
drip (detections at 04:55 while the pool was at 04:45) — the **documented,
deferred** detection-materialization-vs-raw-visibility timing (contract §13/§19),
not a pool coherence defect.

## 8. Final endpoint and serialized-field state

**Event path (the single source of event rows):**
- `GET /api/events/query` — LCQL query read; frozen snapshot `{token, identity, count, rows}`; HMAC session-bound token.
- `GET /api/events/query/new-count` — token-bound; serializes `{new_count, pool_growth}` only (never rows).

**Serialized event row (whitelist, exactly these top-level keys):** `id`,
`event_seq`, `timestamp`, `event_type`, `source_type`, `severity`, `hostname`,
`user_account`, `source_ip`, `destination_ip`, `message`, `key_value_pairs`.
No `protocol` top-level (OD-10: it lives inside `key_value_pairs`). No
answer-bearing field ever.

**Snapshot identity:** `canonical_query`, `cutoff_seq`, `resolved_range`,
`resolved_scope_hosts`, `scope`. The token carries identity + MAC, nothing hidden.

**Stage-4 serialized-field additions to existing endpoints:**
- `/api/incidents` gained `stats.severity_breakdown` (`{low,medium,high,critical}` ints; P8.2), computed uniformly over chain-complete incidents in every mode.

**Deleted routes (P8.3):** `/api/fake-events`, `/api/grouped-alerts`
(+`_sanitize_alert_group`, +the analyst trigger-only reveal branch).

## 9. Retired-route and retired-helper proof

**K9 repo-wide grep (post-deletion) — zero live consumers.** Every surviving
match is a retirement comment or an absence-asserting guard:
```
grep -rn "fake-events"    → 7 matches: 2 retirement comments, 4 test docstrings, 1 route-audit assertion
grep -rn "grouped-alerts" → 13 matches: retirement comments, test docstrings, 3 absence-asserting tests
grep -rn "parseEventQuery|FIELD_ALIASES|alertFieldValue|platformOf|withinPreset|poolAnchorMs|TIME_PRESETS"
                          → 0 matches (legacy client-side search/filter helpers entirely gone)
grep -rn "analyst_mode"   → 0 matches (analyst trigger-only branch gone)
```
Structural backstop: `test_query_read.py::test_route_audit_single_event_query_path`
pins event emitters to exactly `["/api/events/query","/api/events/query/new-count"]`
and asserts both retired rules absent from the URL map;
`test_no_mode_specific_event_endpoint` PASS.

Live (W8/W9): the full-session all-tab network sweep recorded **zero** calls to
either retired route in any mode.

## 10. All behavioral and serialized changes from the stage

- **New event path** `GET /api/events/query` + `/api/events/query/new-count`; frozen snapshots; HMAC session-bound tokens; token invalidation on Reset / Practice Another / restart.
- **A1 simulation epoch** unified with `world["started_at"]`; every occurrence timestamp derives from it (no wall clock). `event_seq` visibility-order identity added to the serialized row.
- **OD-10 shape amendment**: internal `user` → canonical `user_account`; `protocol` moved from top-level into `key_value_pairs` (population-shape parity).
- **LCQL** grammar, catalog, evaluator (P8: server-side only; the client never evaluates a predicate).
- **Workbench UI** (SIEM tab absorbed): query bar + Run/Refresh, frozen snapshot cards/table, TIMEFRAME segment editor, scope control (revised error behavior: chip retained, Run disabled, no silent Session-wide fallback), new-events indicator + pool-growth, field sidebar, event inspector (one lens; kvp catalog order fixture-pinned), entity pivots + Session-wide flip + return chip, Open Evidence Timeline descent (host-anchored; identity descent = uniform two-field OR `user_account == A or UserPrincipalName == A`), surrounding events (viewport centered on the source event), OR-fallback fresh-query notice.
- **Migration/retirement (P8)**: Dashboard existence check → `game-state`; severity stats → `/api/incidents.stats.severity_breakdown` (SOC Queue counts now full-chain, not trigger-only — the ruled OD-4 consequence); `/api/fake-events` + `/api/grouped-alerts` deleted with the analyst trigger branch; nav key `grouped` → `incidents`; docs pass (CLAUDE.md API table, grammar-notes frozen-clock now true, `log_writer` C7 docstring 20–40s, Docs-page SIEM section incl. GD-5a help).
- **Incidental disclosures**: P6 sidebar `==`-operator fix (live-caught seam); kvp catalog order moved from `localeCompare` to code-point order via the checked-in fixture; the "Simulation Active" modal no longer shows an event count; two commit-message test-count typos (7.2 said 152 vs gate 151; 7.4 said 162 vs gate 161) — gate logs authoritative.
- **No changes** to scoring functions, schema v2, scenario content/answer keys, world/detection generation, response actions, submission-boundary grading, or the Stage 3.9 batteries.

## 11. Anomalies and harness workarounds

- **W7 Practice-Another 200 (resolved):** a first curl run showed a 200 where 400 was expected; root cause was a shell session-id extraction bug (`awk` matched extra header lines, contaminating variables), not a product defect. The correctly-parsed isolated re-run and the automated `test_invalid_tokens_fail_neutrally_and_identically` both confirm 400. Diagnosed and disclosed rather than patched.
- **W9 live gap 597s (artifact, resolved):** classifier limitation + documented detection-materialization-ahead-of-pool timing; the authoritative bound is the reference-model test (§7).
- **Mode-dialog timing:** the Start dialog occasionally rendered after a scripted click; re-issued the click. Cosmetic automation timing, no product effect.
- **`find`-by-ref instability:** element refs from `find` sometimes went stale between calls; used `javascript_tool` clicks (by `aria-label`) as a stable fallback.
- **Screenshot CDP timeouts:** intermittent `Page.captureScreenshot` timeouts under load; retried with a short wait. No product effect.
- **Orphaned dev-server (earlier phases):** a prior dev server survived its wrapper on port 3000; killed by PID. Not present in the Phase 9 run.

## 12. Known limitations and deferred work (contract §19, unchanged)

Deferred and NOT implemented in Stage 4: A2 full same-seed replay (session
seed infrastructure); multi-host scenario authoring (so live multi-host
incident descent is test-pinned, not live-observed — §5 W2 is single-host);
exact-id descent (OD-9 alternative); detection-materialization vs
raw-event-visibility timing alignment (§7); live tail; investigation graph;
saved searches; snapshot/persistent history; advanced LCQL operators
(parentheses, numeric/range, field-existence, absolute TIMEFRAME, windowed
surrounding-events, projection, GROUP BY); cross-session deterministic event
identity; CampaignProgress micro-fix. Response-vocabulary-v2 backlog (from
Stage 3) also unbuilt.

Live content-frequency gaps (not defects): **Veeam and Defender** produced
zero live events in the certification session (rare low-frequency background
families under the in-flight drip cap); their inspector rendering is the
standing 8-family automated matrix (`workbench-inspector.test.js`).

## 13. Working-tree status

At certification, the only working-tree entries are the owner's own asset
edits, untouched by Stage 4:
```
 M frontend/public/videos/spectyrvideo.mp4
?? frontend/public/spectyr_svg.svg
```

---

*Stopped at the Phase 9 checkpoint. NOT merged to `main`; awaiting owner and
reviewer approval. Phase 9 changed no product behavior.*

---

# Phase 9 closure addendum (owner direction review, 2026-07-21)

Append-only. Closes the final certification items from the Phase 9
direction review. No product behavior changed; the only new commit
besides this addendum is one test-only guard (P9.1, below). Console and
network captures were cleared before each re-run workflow.

## A1. Workflow 1 — complete live Session-wide investigation transcript

Fresh runtime (backend restarted, captures cleared). SOC Queue run
started as "Jordan".

1. **Ordinary SIEM navigation opens Session-wide.** Clicking the SIEM
   nav tab landed on the workbench with the Scope control reading
   **"Session-wide"** (default), no query executed, the "Run a query to
   begin." empty state with the two example queries and the GD-5a
   quoting-rules line.
2. **Valid LCQL execution.** Typed and ran the scaffold query. Wire:
   `GET /api/events/query?q=1h | Sysmon | ProcessCreate | command_line contains "powershell"&scope=session` → 200.
   Header: `Snapshot: 0 events · as of seq #22 · 04:53:06 sim` with the
   canonical echo (honest empty result). Then ran `all | * | * | *` →
   **`Snapshot: 41 events · as of seq #41 · 04:55:23 sim`**, top row
   FileCreate 04:55:23 ACME-WS29; DOM fingerprint of the header, the
   full results pane, and the full field sidebar stored.
3. **65-second hold during live drip — zero row movement.** After 65 s
   (drip live; the Incidents badge climbed 2→3 behind the snapshot),
   the header, results pane, and sidebar compared **byte-identical** to
   the stored fingerprint:
   `{"header_identical":true,"results_identical":true,"sidebar_identical":true}`.
4. **new_count and pool_growth update.** The indicator read
   **`85 new`** with **`pool: +85`** at the 65-second mark (climbing
   from 0 across poll ticks — token-bound; no snapshot change).
5. **Deliberate Refresh — atomic replacement.** One click replaced the
   snapshot 41 → **`Snapshot: 142 events · as of seq #142 · 04:59:06
   sim`** (`replaced: true` vs the stored header), sidebar re-derived,
   indicator reset (the next poll tick minted a fresh `3 new · pool:
   +3`). Zero console errors.

## A2. Workflow 6 — live scope failure via request/fetch blocking

Method: the Phase 4 fetch-monkeypatch (reject every request whose URL
contains `/scope`), the request-blocking equivalent executable under
browser automation. Guided run, incident **INC-2403** (sealed);
active-incident context established through the Incidents workspace;
baseline snapshot present (`Snapshot: 6 events · seq #14 · all |
ACME-WS16 | * | *`, the surrounding-events timeline). Console cleared at
workflow start.

1. **Failure.** With the block installed, selecting "Focused on
   INC-2403" in the Scope control produced, verified by DOM inspection
   and screenshot:
   `{"select_shows":"Focused on INC-2403","chip_text":"INC-2403 scope
   unavailable ×","error_notice":true,"retry_present":true,
   "use_sessionwide_present":true,"run_disabled":true,
   "snapshot_unchanged":true}` — i.e. **chip retained** ("INC-2403
   scope unavailable"), the notice "Incident scope could not be
   loaded." with Retry and Use Session-wide, **previous snapshot
   preserved untouched** (all six ACME-WS16 rows + banner), **Run Query
   disabled**, and **no silent Session-wide fallback** (the select still
   showed the incident).
2. **Retry while still blocked** → `{"still_error":true,
   "run_still_disabled":true}` (fails again, state unchanged).
3. **Recovery through Retry.** Block removed; Retry →
   `{"recovered":true,"chip_text":"INC-2403 ×","run_enabled":true}`;
   Run Query then fired
   `GET /api/events/query?q=all | ACME-WS16 | * | *&scope=INC-2403` → 200.
4. **Recovery through explicit Use Session-wide.** Block re-installed;
   incident scope re-selected → error state again (`error_again:
   true`); clicking **Use Session-wide** →
   `{"scope_now":"Session-wide","error_gone":true,"run_enabled":true}`
   with the "Back to INC-2403" return chip appearing (explicit flip,
   not silent).
5. **Console.** The error-console read covering the ENTIRE workflow
   (cleared at start, read at end — including both blocked windows):
   **"No console errors or exceptions found for this tab."** Zero
   steady-state (and in fact zero transient) console errors.

## A3. The two missing workflow excerpts — run and recorded

Neither proof was present in the original §5 (the certification W3
spot-checked two host-anchored detections; surrounding events was
live-verified in Phase 7.3 but not re-run in Phase 9). Both were run
live for this addendum:

**W3 supplement — identity-detection descent (two-field OR, live).**
Guided run of the identity-telemetry scenario. The Detections feed
carried two identity detections whose entity is the **account with no
host** (`slopez@acme.com`, unlinked — the identity-entity rule live).
Opened "Entra Impossible-Travel Risk Detection" (`det-6c916a327126`):
same uniform detail layout and the same **Open Evidence Timeline**
control as host detections. Descent wire (decoded):

```
GET /api/events/query?q=all | * | * | user_account == "slopez@acme.com"
    or UserPrincipalName == "slopez@acme.com"&scope=session   → 200
```

Banner: "Evidence timeline for slopez@acme.com, from det-6c916a327126 —
occurrence ascending"; 3 Azure AD events rendered occurrence-ascending
(SigninLogs 04:50:45 → SigninLogs 04:52:47 → AADUserRiskEvents
04:53:00). The OR earned its keep on the wire: the rows serialize
`user_account` as `ACME\slopez` (sidebar: `user_account (1)
ACME\slopez ×3`), so the **UserPrincipalName disjunct** is what matched
all three events — the exact live failure P7.5 was ruled to fix.

**W5 supplement — Surrounding events (ascending + centered, live).**
From that timeline, selected the SigninLogs 04:52:47 event and clicked
the inspector's **Surrounding events**. Wire:
`GET /api/events/query?q=all | ACME-WS16 | * | *&scope=session` → 200
(the host form under the CURRENT scope). Banner: **"Surrounding events
for ACME-WS16, centered on the selected event — occurrence ascending"**.
Snapshot 6 events (seq #14), rendered strictly occurrence-ascending:
04:50:45 SigninLogs → 04:52:00 HTTP_GET → 04:52:06 HTTP_POST → 04:52:21
ALLOW → **04:52:47 SigninLogs (the source event — highlighted/selected,
scrolled to the viewport center via the P7.3 `scrollIntoView({block:
'center'})` path)** → 04:53:00 AADUserRiskEvents, with the source
event's inspector persisting beneath ("arrived as event #10").

## A4. Final closure record

**Phase 9 commits (complete enumeration):**

| Commit | Subject |
|---|---|
| `c4a0f2f` | Stage 4 P9.2: closing evidence report (docs/stage-4-implementation-report.md) |
| `6ca2105` | Stage 4 P9.1: per-mode planted-marker leak guard (test-only) |
| *(this addendum)* | Stage 4 P9 closure addendum (docs-only) |

The Section 18 matrix audit found **no prose-only criterion, so no 9.1
gap-fill commits were needed for the acceptance matrix**. One 9.1
test-only commit (`6ca2105`) was added at the closure direction review
to make the per-mode planted-marker result directly quotable (below);
it changes no product behavior and landed through the enforced gate
(`[gate] ALL GREEN`; `test_event_disclosure` 8 → 9 tests).

**`c4a0f2f` confirmation:** `git show --stat c4a0f2f` =
`Stage 4 P9.2: closing evidence report (docs/stage-4-implementation-report.md)`,
touching exactly `docs/stage-4-implementation-report.md | 332 insertions`.
It is the committed tip of the original report; the branch tip after
this addendum supersedes it as the review tip.

**K8 latency (fresh run, 400-event pool, 50 samples per route, pasted):**

```
query      : {"n": 50, "min_ms": 4.3, "p50_ms": 4.4, "p95_ms": 4.5, "max_ms": 4.9, "mean_ms": 4.5, "samples_above_250ms": 0}
new_count  : {"n": 50, "min_ms": 3.2, "p50_ms": 3.3, "p95_ms": 3.3, "max_ms": 3.4, "mean_ms": 3.3, "samples_above_250ms": 0}
halt_condition_250ms_sustained_breached: False
```

Per route over 50 samples: query p50 4.4 ms / p95 4.5 ms / max 4.9 ms /
**0 samples above 250 ms**; new-count p50 3.3 ms / p95 3.3 ms / max
3.4 ms / **0 samples above 250 ms**.

**Planted-marker result in Guided, SOC Queue, and Hardcore (pasted):**
the new guard `test_event_disclosure.py::
test_planted_marker_absent_in_query_and_count_in_every_mode` starts a
REAL session in each mode (`guided` / `analyst` [SOC Queue] /
`hardcore`), plants a marker-laden event through the live
append-and-stamp choke point, asserts the sanitized row is present
(non-vacuous), and recursively scans the full query + new-count
responses:

```
  ok  test_planted_marker_absent_in_query_and_count_in_every_mode
[test_event_disclosure] all 9 passed
```

**Named final no-mutation results (pasted):**

```
backend  (test_query_read.py):
  ok  test_new_count_does_not_mutate
  ok  test_query_read_does_not_mutate
[test_query_read] all 21 passed

frontend (scope-no-mutation.test.js):
PASS src/__tests__/scope-no-mutation.test.js
  √ select A, switch to B, clear to Session-wide across scoped tabs issues reads only
  √ P7 descent, pivot, scope switch, and return-to-incident issue reads only
  √ P7.4 identity descent issues reads only
Tests:       3 passed, 3 total
```

**Evidence references/screenshots — record correction (disclosed):**
the `ss_*` identifiers cited in §5 are Chrome-extension capture IDs,
**ephemeral to the capture session — they are NOT durable on-disk
artifacts and should not be treated as stable references**. The §5
phrase "stable evidence IDs" was inaccurate and is corrected here (the
original text is left in place per append-only discipline). The durable
evidence record is: (a) the certification-session transcripts (this
report's §5 and this addendum's A1–A3, which quote the wire URLs,
snapshot headers, DOM byte-comparisons, and banner/notice text
verbatim), and (b) the automated suites that pin each behavior. All
wire URLs and DOM-comparison results quoted in this addendum were
captured live in the closure session.

---

*Phase 9 closure complete. Stopped at the checkpoint. NOT merged to
`main`; no further stage begun. This report now goes to owner and
reviewers for the row-by-row acceptance walk against the locked
contract; the merge ruling follows that walk.*
