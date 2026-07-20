# Stage 4 SIEM Workbench — Implementation Scaffold

**Status: APPROVED WITH CORRECTIONS (owner review, 2026-07-19); this
revision folds in the eight review corrections plus the action-clock
re-anchoring rule. Implementation is authorized on branch
`stage-4-siem-workbench` from `main` after this correction commit, in the
phase order below, stopping at every phase stop condition.**

Governing document: `docs/stage-4a-siem-workbench-contract.md` — the
canonical LOCKED Stage 4A contract (Revision 3, final; R1-R18; lock
recorded 2026-07-19). This scaffold translates every locked requirement
into a buildable sequence with independently reviewable checkpoints. Where
the contract delegates a detail to the scaffold, the choice is made here,
marked **[Scaffold decision]**, and is part of what approval ratifies.
Nothing here amends the contract; Section 11 (amendment register) is the
place where an amendment would be requested, and it is empty of requests.

---

## 1. Baseline and scope (task 3.1)

### 1.1 Commit baseline

| Anchor | Commit |
|---|---|
| Current `main` tip (at scaffold authoring) | `eb49610` (the contract-lock commit) |
| Contract-lock commit | `eb49610` "Stage 4A: lock the SIEM Workbench contract (Revision 3)" |
| Event-disclosure hotfix baseline | `37486b1` (pre-lock tip; the serializer + leak-guard foundation) |
| Stage 4A inventory | `27a693c` (`docs/stage-4a-repository-inventory.md`) |
| Stage 3.9 closure docs / product merge | `decfb18` / `97e3292` |

### 1.2 Test baseline (counted at `eb49610`)

- **Backend: 290 test functions across 19 `backend/test_*.py` files**
  (largest: `test_scenario_loader_v2.py` 61, `test_action_scoring.py` 39,
  `test_submission_gate.py` 22, `test_snapshot_generator.py` 21,
  `test_persistence.py` 19, `test_persistence_response.py` 19,
  `test_action_overlay.py` 18, `test_guided_catalog.py` 13,
  `test_detections.py` 12, `test_event_disclosure.py` 8). Plus the
  non-pytest gate scripts `parity_check.py`, `parity_check_v2.py`,
  `fairness_check.py`, orchestrated by `backend/run_gates.py`.
- **Frontend: 43 tests across 9 `frontend/src/__tests__/*.test.js` files**
  (`incidents-workspace` 10, `difficulty-selector` 6, `endpoints` 6,
  `incident-dashboard` 6, `siem` 6, `detections` 5, `score-sections` 2,
  `copy-emdash` 1, `scope-no-mutation` 1).

### 1.3 Current SIEM surface affected by this implementation

| Piece | Fate (per locked contract) |
|---|---|
| `frontend/src/components/Siem.jsx` (2s poll, dropdowns, search box) | **Adapted**: becomes the workbench shell; live-feed poll, dropdown filters, `field=value` search, Splunk-style placeholder **retired** (R9, R14, C5) |
| `frontend/src/components/SiemTable.jsx` | **Adapted**: snapshot renderer with client-only column sort over frozen rows |
| `frontend/src/components/SiemCards.jsx` | **Adapted**: snapshot renderer (cards view) |
| `frontend/src/components/siemUtils.js` | **Split**: `sanitizeEvent` display helper + `sourceColor` retained; `parseEventQuery`, `FIELD_ALIASES`, `withinPreset`/`poolAnchorMs` client windowing, dropdown derivations **retired** (server resolves TIMEFRAME; catalog supersedes aliases) |
| `GET /api/fake-events` (`app.py:2625`) | **Retained during migration, then retired** in Phase 8 after its last consumers move (Section 3.3 lists every consumer) |
| `GET /api/grouped-alerts` (`app.py:4369`) | **Retired** in Phase 8 after `.stats` relocation; the internal analyst-mode trigger branch (`app.py:4419-4454`) is deleted with it (R11) |
| `frontend/src/__tests__/siem.test.js` | **Superseded progressively**: each retired behavior's test is replaced in the same concern commit that removes the code (contract Section 5) |
| `Dashboard.jsx:101` session-existence check on `fake-events` | **Migrated** to `GET /api/game-state` |
| `IncidentDashboard.jsx:39` grouped-alerts `.stats` consumer | **Migrated** to a `stats` field on `GET /api/incidents` (Section 3.3.4) |

### 1.4 Frozen boundaries inherited from Stage 3.9 (unchanged by this stage)

Scoring and grading functions, collateral pricing, the composite (40/30/30),
submission boundary and readiness (`submit_incident`,
`incident_submission_readiness`), detection-roster sealing
(`chain_complete_at`), the immutable submission-record schema, answer keys
and scenario content (YAML v1/v2 byte-parity, `test_corpus_matches_v1_content`),
response actions/overlay/traps, detection generation and
indistinguishability, the incident-scope structural guard, `GUIDED_MODES`,
and the mode intake rules. **One explicitly authorized crossing:** R8/A1
changes event **occurrence timestamps** and `world["started_at"]`
derivation (content byte-parity except timestamps preserved and re-proven
by the existing parity suite). Nothing else in event generation changes:
template choice, employee choice, interleave, drip scheduling, INC ids,
uuids all stay as they are.

### 1.5 Explicitly NOT in this implementation (restated from the locked contract)

A2 full same-seed replay (no session seed input is introduced); multi-host
scenario authoring; exact-ID detection descent (the OD-9 deferred
alternative); live tail / streaming; investigation graph; saved searches;
snapshot history; persistent history of any kind; advanced deferred LCQL
operators (parentheses, numeric/range comparison, field-existence
predicates, absolute TIMEFRAME windows, windowed surrounding-events,
projection, GROUP BY); detection-materialization vs raw-event-visibility
timing alignment; CampaignProgress mode-total correction (separate
micro-fix, R13); and any visual-polish phase (separately authorized only).

---

## 2. Architecture map (task 3.2)

Legend: **added** = new code; **adapted** = existing code modified in
place; **moved** = relocated unchanged responsibility; **retired** =
deleted with its tests replaced in the same commit.

### 2.1 Event generation

- **Current:** `backend/app.py` — `log_writer` (`:2541-2623`, 1s tick,
  drip 20-40s, interleave 2-3), `build_attack_chain_logs` (`:2382-2522`,
  `base_time = datetime.now(timezone.utc)` at `:2399`), `_raw_chain_yaml`
  (`:2225-2246`, gap draw from the global RNG at `:2238`),
  `generate_normal_event` (`:2140-2198`, wall-clock-minus-random-backdate
  at `:2177`).
- **Target:** **added** `backend/sim_epoch.py` (epoch derivation, authored
  base-time function, background occurrence-time function, the dedicated
  per-session gap RNG); **adapted** call sites in `app.py`
  (`build_attack_chain_logs` base time, `_raw_chain_yaml` gap source,
  `generate_normal_event` timestamp, `start_simulator`
  `world["started_at"]` at `:4697`). Drip orchestration
  (`next_drip_at`, `injected_at`, `chain_complete_at`, `timer_start`)
  **stays wall clock** — those are visibility/orchestration times, not
  occurrence times (contract Section 9's two-concept rule).
- **Constrained today by:** `parity_check_v2.py` + `test_scenario_loader_v2.py`
  (content parity, timestamps excluded), `test_snapshot_generator.py::test_frozen_time_and_system_block`,
  `test_actions.py::test_no_wall_clock_in_log_entries`.
- **Tests to add:** `backend/test_sim_epoch.py` — epoch determinism given
  session id; occurrence-time recomputation (epoch + spacing + authored
  offsets + seeded gap stream); no-wall-clock property on generated
  occurrence timestamps; `world["started_at"] == epoch`; action-clock
  alignment (the response log's logical base equals the epoch).

### 2.2 Event sanitization

- **Current:** `backend/detection_templates.py` — `EVENT_WHITELIST`
  (`:294-297`), `FEED_EVENT_WHITELIST = EVENT_WHITELIST + ("id","protocol")`
  (`:316`), `sanitize_feed_event` (`:319-327`), `sanitize_event`
  (`:300-302`, the detail/trigger whitelist).
- **Target:** **adapted** `sanitize_feed_event` per OD-10/R18 +
  `event_seq`: map internal `user` to `user_account` when no
  `user_account` exists; drop top-level `protocol` from the whitelist and
  inject a non-empty internal top-level `protocol` into a **copied**
  `key_value_pairs` (never mutating the stored log, never overwriting an
  existing kvp `protocol` key); serialize `event_seq` unconditionally
  alongside `id`. `EVENT_WHITELIST` (detection triggering events)
  **unchanged** — triggering events continue to serialize no `id` and gain
  no `event_seq` (preserves the enforced D11 invariant and R17's design).
  **Transitional protocol compatibility (review correction 5):** the one
  legacy consumer of top-level `protocol` is the SIEM search filter
  (`siemUtils.js:11` `protocol`/`proto` aliases, read via
  `alertFieldValue`, `siemUtils.js:33-34`; the display whitelist never
  included it). Chosen option: update that consumer **in the same Phase
  1.3 concern commit** — the `protocol` filter reads
  `key_value_pairs.protocol` (top-level fallback kept for robustness) —
  with its frontend test updated alongside, so the relocation never
  breaks the live legacy SIEM between Phases 1 and 4. Delaying the
  relocation to Phase 4 was rejected: it would carry a known population
  discriminator (a leak-class defect) through Phases 2-3. **Every
  serialized-payload change in Phase 1 runs the complete backend and
  frontend gate (`run_gates.py --all`).**
- **Constrained today by:** `test_event_disclosure.py` (8 tests),
  `test_detections.py::test_sanitized_triggering_events_are_whitelisted`,
  `::test_whole_corpus_detections_sanitize_clean`.
- **Tests to add/update:** update the feed-whitelist assertions in
  `test_event_disclosure.py` in the same commit; **added**
  `test_event_disclosure.py::test_shape_parity_no_population_exclusive_top_level_field`
  (live drip of both populations; asserts background events with account
  data serialize `user_account` and no event serializes top-level
  `protocol`).

### 2.3 `event_seq` assignment

- **Current:** none; array position is the implicit stand-in (inventory 11).
- **Target (review correction 4):** **added** allocator: **one actual
  append-and-stamp helper is the only way a generated event enters the
  pool.** Shape: `_append_pool_event_unlocked(session, log)` (stamp
  `event_seq = counter + 1`, write the NDJSON line, then advance the
  counter — so a failed append never advances it) plus a locking wrapper
  `append_pool_event(session, log)`. Both existing write paths route
  through it: the `log_writer` normal/attack writes (today
  `append_ndjson`, `app.py:2604,:2620`) use the wrapper; the supplemental
  append inside `build_attack_chain_logs` (`app.py:2471-2474`, already
  under `io_lock`) uses the unlocked variant. **Sequence assignment and
  the successful append occur inside one atomic `io_lock` boundary**;
  the stamped value persists in the NDJSON row. This is load-bearing
  for the API: `pool_growth = max_seq - cutoff_seq` is only a truthful
  event count if the sequence is contiguous. Detection instances hold
  references to the same dicts; their serialization path
  (`sanitize_event`) whitelists `event_seq` away, so no linkage leaks.
- **Constrained today by:** nothing (the identity gap is inventory finding
  D6/11).
- **Tests to add (permanent):** `backend/test_event_seq.py` — uniqueness
  across a full session pool; **strict increase**; **contiguity (1..N, no
  gaps)**; **assignment-once** (re-reads and re-serializations never
  re-stamp); **no counter advancement on a failed append** (patched write
  failure leaves the counter and the file consistent); pool append-only
  under polling; read-no-mutation on every event read route; `event_seq`
  present on every `/api/fake-events` (transitional) and query-read row;
  absent from detection triggering events.

### 2.4 Simulation epoch and `world["started_at"]`

- **Current:** `world["started_at"] = now.replace(microsecond=0).isoformat()`
  in `start_simulator` (`app.py:4697`); wall clock. The response-action
  clock already derives from it (`app.py:2804` passes
  `s["world"]["started_at"]` into `action_overlay.record_attempt`,
  `action_overlay.py:462-470`), so epoch unification aligns the action
  clock automatically (contract finalization item 3).
- **Target:** **adapted** `start_simulator` sets
  `world["started_at"] = sim_epoch.epoch_iso(session["id"])`. **[Scaffold
  decision — epoch derivation]** digest-derived: a fixed canonical base
  `SIM_BASE = 2026-03-16T08:00:00+00:00` (a Monday morning) plus a
  per-session offset of `_stable_int(0, 5759)` **minutes** derived from
  sha256 over `(session_id, "sim_epoch")` — the same stable-key practice
  as detection ids and world times (`detection_templates.py:103-136`).
  Result: wall-clock-free, deterministic given session identity, lands
  every session inside a plausible Mon-Fri work week, and keeps distinct
  sessions on distinct timelines (so nobody mistakes cross-session
  equality for a promise). The rejected alternative (one fixed constant
  epoch for all sessions) is simpler but makes every session's timestamps
  identical, which invites exactly the cross-session-replay assumption the
  contract refuses to promise.
- **Consequence, disclosed:** because `reset-simulator` keeps the session
  id, a reset or Practice Another re-derives the **same epoch** (and the
  same stable-key world times). This is consistent with the contract
  ("deterministic given session identity"); uuids, INC ids, employee
  picks, and drip interleave still differ per run.
- **Constrained today by:** `test_snapshot_generator.py::test_frozen_time_and_system_block`
  (must pass unchanged against the shared epoch), `test_actions.py`
  frozen-clock tests.
- **Tests to add:** in `test_sim_epoch.py` — same session id twice yields
  the same epoch; different ids yield different epochs; epoch is within
  the SIM_BASE window; `started_at == epoch`; snapshot-generator and
  action-clock guards re-run green against it.
- **Harness compatibility (verified):** `parity_check_v2.py:99-100` calls
  `build_attack_chain_logs` with a bare session dict (no `id`, no rng)
  and seeds the global RNG itself. The A1 call sites therefore fall back
  when session identity is absent: base time falls back to `SIM_BASE`
  with zero offset, and gap draws fall back to the global `random`
  module — both deterministic under the harness's own seeding, so the
  parity harness is untouched.

### 2.4b Response-action clock (review correction 6, with the re-anchoring rule)

- **Exact current formula (verified):** `action_overlay.record_attempt`
  (`action_overlay.py:469-471`): `overlay["seq"] += 1;
  ts = datetime.fromisoformat(started_at) + timedelta(seconds=overlay["seq"])`,
  microseconds zeroed. `started_at` is `world["started_at"]`, passed at
  the one call site (`app.py:2804`).
- **Monotonicity: proven.** `seq` strictly increments under the request
  path; timestamps are `started_at + seq` seconds, hence strictly
  increasing. Already guarded by
  `test_actions.py::test_log_records_every_attempt_with_frozen_clock_sequence`.
- **"Never timestamps before the visible evidence": disproven — today
  and under A1 alike.** The action clock is a logical clock anchored at
  session start: today actions stamp `wall_start + seq` seconds while
  evidence occurrence times are wall-at-drip (minutes later); under A1
  actions stamp `epoch + seq` seconds while evidence runs from
  `epoch - 80s` (negative supplemental offsets) up to `epoch + ~19min`.
  An action responding to late evidence has always carried an earlier
  logical timestamp than that evidence. This is a pre-existing Stage 3.9
  property, not an A1 regression; `seq` is the authoritative order.
- **Must actions re-anchor to sim-now? NO — ruled out by the
  determinism requirement.** Sim-now at action time is the maximum
  visible occurrence timestamp, which depends on how many events the
  nondeterministic drip interleave has written when the player acts. A1
  deliberately leaves ordering unseeded, so a sim-now-anchored timestamp
  cannot be a pure function of (session identity, action sequence), and
  the Stage 3.9A byte-identical action-log invariant
  (`test_actions.py::test_replay_determinism_byte_identical_logs`)
  cannot be re-proven in its ruled sense. Per the owner's rule ("if it
  cannot be, leave the action clock exactly as it is today"), **the
  action clock is left byte-for-byte unchanged**. It inherits the epoch
  base automatically through `started_at` — zero code change, all
  existing guards untouched and green.
- **Evidence added anyway (commit 1.1):**
  `test_sim_epoch.py::test_action_clock_base_equals_epoch` (the log's
  first timestamp derives from the epoch — the alignment the contract's
  finalization item 3 asks for) and
  `test_sim_epoch.py::test_action_score_is_timestamp_invariant`
  (`compute_action_score` output is unchanged under arbitrary mutation
  of log timestamps — scoring never reads the clock).
- **Recorded, not built:** a timeline-coherent action *display* (e.g.
  presenting the Response Log on the sim timeline) would require the
  deferred deterministic anchoring and comes back as an explicit
  amendment if ever wanted.

### 2.5 LCQL tokenizer / parser / AST / canonicalizer

- **Current:** none (D4). The pinned grammar exists only in
  `docs/stage4-query-grammar-notes.md`; the client search
  (`siemUtils.parseEventQuery`) is non-conforming and is retired.
- **Target:** **added** `backend/lcql.py`, pure module, no Flask imports:
  - Tokenizer: emits `PIPE`, `STAR`, `IDENT`, `OP_EQ`, `OP_NE`,
    `OP_CONTAINS`, `OP_NOT_CONTAINS`, `AND`, `OR`, `DQ_STRING`,
    `SQ_STRING`, `EOF`, each with a 0-based character position; backslash
    escapes `\"`, `\'`, `\\` inside quoted values (GD-5).
  - Parser: recursive descent over exactly four `|` segments (GD-4: all
    four always present; empty segment = parse error). FILTERS grammar:
    `expr := conj ( "or" conj )*`, `conj := pred ( "and" pred )*`,
    `pred := FIELD OP VALUE` (GD-3: `and` binds tighter).
  - AST: `Query(timeframe, sensor, event_type, filters)` where `filters`
    is `Star | Or([And([Pred(field, op, value, quote_kind)])])`.
  - Canonicalizer: AST -> string; single spaces around `|` and operators;
    operators lowercased; field names in catalog-canonical case; segment
    keywords in catalog case; quoted values byte-preserved; idempotent.
  - Errors: `LcqlError(position, reason, suggestions)` — unknown field /
    sensor / event type errors carry near-match suggestions (difflib
    against the catalog).
- **Tests to add:** `backend/test_lcql.py` — every contract Section 11
  valid example parses; every INVALID example rejects with position and
  reason; the GD-1/GD-2/GD-3/GD-4/GD-5 matrices;
  `canonical(canonical(q)) == canonical(q)` over a generated corpus of
  queries; tokenizer position accuracy.

### 2.6 Query execution (evaluator)

- **Current:** all filtering is client-side (`Siem.jsx:67-77`), retired.
- **Target:** **added** in `lcql.py`: `matches(sanitized_event, ast,
  resolved_range) -> bool`. Evaluation runs over the **sanitized feed
  shape** (the exact dict `sanitize_feed_event` returns), never the raw
  log — structurally, a predicate cannot see an unsanitized field.
  Semantics: TIMEFRAME bounds occurrence `timestamp` inclusive;
  SENSOR_SELECTOR matches `source_type` family or `hostname`
  case-insensitively; EVENT_TYPE matches `event_type` case-insensitively;
  FILTERS per GD-1/GD-5 (double-quoted and unquoted values casefold;
  single-quoted exact; `==`/`!=` whole-string over the stringified value;
  `contains`/`not contains` substring; missing field evaluates false for
  all four operators).
- **Tests to add:** in `test_lcql.py` — operator matrix per quote kind;
  missing-field falsity for all four operators; kvp resolution order
  (canonical top-level first, exact kvp name reaches a shadowed key);
  family vs hostname sensor selection; range bounds.

### 2.7 Snapshot identity

- **Current:** none.
- **Target:** **added** in `backend/app.py` (route layer): identity dict
  `{canonical_query, scope, resolved_scope_hosts (Amendment E2, P3.4:
  the participant-host set resolved at execution, sorted + deduplicated,
  [] for session-wide; frozen so replay and the new-count baseline never
  re-resolve a pre-seal incident's grown host set), resolved_range:
  {start, end}, cutoff_seq}`
  computed at execution: canonical query from the parser; scope validated
  (`session` or known incident id); TIMEFRAME resolved against sim-now
  (max visible occurrence timestamp). **`all` resolution (review
  correction 1):** `start` = the **minimum visible occurrence timestamp**
  and `end` = sim-now — never the epoch, because authored negative
  supplemental offsets place events before the epoch (e.g.
  `data_exfil_archive` supplemental events at -80s/-65s), and an
  epoch-anchored `all` would exclude them. Empty pool: `start == end ==`
  the epoch (permitted). A pinned fixture proves the rule
  (`test_query_read.py::test_all_range_includes_negative_offset_supplemental`:
  drip a negative-offset scenario, then `all | * | * | *` returns every
  visible event). `cutoff_seq` = current max `event_seq` (0 when the pool
  is empty).
  Sort is **not** identity: the response rows are always in canonical
  server order — occurrence `timestamp` descending, then `event_seq`
  descending, then `id`.
- **Tests to add:** `backend/test_query_read.py` — identity round-trip;
  canonical order property; within-session deterministic replay
  (byte-identical rows for an identical identity).

### 2.8 Snapshot-token signing and validation

- **Current:** none.
- **Target:** **added** in `app.py` + `sim_epoch`-adjacent helper (or a
  small `backend/snapshot_token.py`): token =
  `base64url(identity_json) + "." + base64url(hmac_sha256(secret, identity_json))`
  where `identity_json` is the compact, sorted-keys serialization of the
  identity dict. Secret: `session["snapshot_secret"] = os.urandom(32)`,
  minted in `create_session` (`app.py:110-165`) and **rotated** in both
  `reset_simulator` and `start_simulator`, so Reset, Practice Another, and
  restart all invalidate every outstanding token by construction.
  Validation: constant-time MAC compare; **[Scaffold decision — neutral
  failure shape]** every failure (malformed, altered, foreign-session,
  post-reset) returns the identical `400 {"error": "Unknown token"}`,
  matching the actions-API indistinguishability convention.
- **Tests to add:** in `test_query_read.py` — altered payload, altered
  MAC, foreign-session token, post-reset token, and garbage all yield the
  byte-identical neutral 400; a valid token re-executes to the identical
  snapshot; no server-side job state exists (no new session keys beyond
  the secret).

### 2.9 New-count calculation

- **Current:** none (D2).
- **Target:** **added** route logic (R16, refresh-now): from the token's
  identity, (a) re-execute the original identity (canonical query, scope,
  original resolved range, original `cutoff_seq`) to reconstruct the
  displayed row-id set — valid because within-session replay is
  deterministic; (b) execute the refresh-now definition (same canonical
  query and scope, TIMEFRAME re-resolved at count time, cutoff = current
  max `event_seq`); (c) `new_count` = rows in (b) whose `id` is not in
  (a); `pool_growth` = current max `event_seq` minus original
  `cutoff_seq`. The displayed snapshot is never touched; the route is a
  pure read.
- **Tests to add:** in `test_query_read.py` — count matches a hand-built
  drip scenario under the ratified semantics including the re-resolved
  window; zero-state; `pool_growth` independence; edited bar text provably
  cannot influence the count (the request carries only the token).

### 2.10 Incident scoping

- **Current:** `_incident_observable_scope` (`app.py:3545-3590`),
  served by `GET /api/incidents/<id>/scope`; structurally guarded
  (`test_incident_scope.py::test_scope_structural_no_grading_or_expected_actions`).
  The SIEM never intersects it (inventory 7).
- **Target:** **adapted** (reused, not modified): the query read with
  `scope=<INC id>` resolves participant hosts via
  `_incident_observable_scope` and applies one implicit constraint —
  `hostname in participant_hosts` — before LCQL evaluation. Accounts never
  constrain (contract Section 14). Unknown/foreign incident id: `404`
  neutral, indistinguishable.
- **Tests to add:** in `test_query_read.py` — scoped result set is a
  subset of the session set for the same query; the implicit constraint
  equals scope hosts exactly; the structural no-answer-key guard is
  extended to cover the query read's source (same `inspect.getsource`
  technique as `test_incident_scope.py`).

### 2.11 Field catalog and canonical normalization

- **Current:** client `FIELD_ALIASES` (retired); no server catalog.
- **Target:** **added** in `lcql.py`: `build_field_catalog(...)` executed
  once at boot from repository truth: canonical top-level names (contract
  10.1), kvp key union from `yaml_catalog` chains + supplemental events
  plus `NORMAL_TRAFFIC_TEMPLATES` kvp keys plus `protocol` (OD-10
  relocation), event types (30), source families (8), known hostnames
  (`EMPLOYEES` workstations + `SERVERS` hostnames). Case-insensitive
  resolution to catalog-canonical case (GD-2); resolution order canonical
  top-level first, then kvp (contract 10.2).
  **Two catalogs, separated (review correction 8):** the catalog exposes
  `SERIALIZED_FIELDS` (everything the payload/display/inspector may
  carry, including `event_seq`) and `FILTERABLE_FIELDS` (what a FILTERS
  predicate may name) as distinct sets, with
  `FILTERABLE_FIELDS = SERIALIZED_FIELDS - {event_seq}` in v1: `id` IS
  filterable (contract 10.1, exact-event queries), `event_seq` serializes
  and renders in the inspector but is **rejected by the parser as a
  FILTERS field** with a parse-time error naming it as not filterable.
- **Tests to add:** in `test_lcql.py` — catalog contains every serialized
  field observed on a live drip of both populations and nothing outside
  the sanitized shape; `RiskLevel`-style case resolution; shadowed-key
  addressing; unknown-name suggestions;
  `test_lcql.py::test_event_seq_rejected_as_filter_field` (the parser
  rejection, permanent).

### 2.12 SIEM frontend state

- **Current:** `Siem.jsx` poll/filter/dropdown state (retired).
- **Target:** **adapted** `Siem.jsx` as the workbench shell owning the
  client state model of Section 4 (query text vs executed snapshot, scope,
  return context, selection, new-count, client sort, view mode). Stays
  mounted across tab switches (Dashboard mounts views hidden/visible), so
  scope persistence for the session (R10) falls out of component state.
- **Tests to add:** `frontend/src/__tests__/workbench.test.js` +
  `workbench-states.test.js` — the Section 6 per-pane state enumeration,
  including the revised scope-error behavior (chip retained, prior
  snapshot preserved, Run disabled, no silent Session-wide fallback).

### 2.13 Results rendering

- **Current:** `SiemTable.jsx` / `SiemCards.jsx` render the live pool.
- **Target:** **adapted**: both receive the frozen `rows` array from the
  executed snapshot; pagination stays display-only; `SiemTable` column
  sort becomes client-only view state over the frozen set (no refetch, no
  token change); row expansion becomes inspector opening; selection keyed
  by `id`.
- **Tests to add:** `workbench-snapshot.test.js` — byte-stable row set and
  order under a mocked growing pool across poll cycles; atomic
  replacement; client sort issues no network request.

### 2.14 Inspector

- **Current:** expanded-row rendering (`renderCleanEventDetails`,
  `SiemCards` JSON view) — adapted as the base.
- **Target:** **adapted/added** inspector panel per contract Section 12:
  identity (timestamp, `id`, "arrived as event #<event_seq>"), family +
  event_type with family color, canonical commons, every sanitized kvp in
  catalog order (type-aware), raw message + sanitized raw JSON view,
  per-field actions routed through the pivot generator, malformed-event
  fallback rendering.
- **Tests to add:** `workbench.test.js` — inspector completeness per
  family (a representative event of each of the 8 families renders every
  whitelisted field); recursive props check that no non-whitelisted key
  ever renders; `event_seq` display.

### 2.15 Pivots

- **Current:** none (the old `pivotQuery` prefill is superseded).
- **Target:** **added** `frontend/src/components/lcqlPivots.js` — the
  single generation choke point: every Section 13 form (host, account,
  process image, process-name contains, file, IP, domain/proxy,
  domain/DNS, event type, sensor family, sidebar value append,
  surrounding events) plus descent forms; GD-5 escaping of injected
  values; the conjunction-only rule. **[Scaffold decision —
  conjunction detection]** the generator decides append-vs-fresh by a
  quote-aware lexical scan of the executed canonical query's FILTERS
  segment for a top-level ` or ` token (canonical text guarantees
  lowercase spaced operators; the scan honors GD-5 escapes). This is
  generation logic, not query execution, so P8 (no client-side execution)
  is preserved; the choke-point test pins its behavior.
  **Equivalence boundary (review requirement):** `lcqlPivots.js` carries
  a permanent comment stating that the lexical OR scan is equivalent to
  AST conjunction-detection **only while LCQL has no grouping or
  parentheses**; if grouping is ever introduced (a deferred grammar
  item), this mechanism must be replaced, not patched. The equivalence
  itself is pinned by a shared fixture corpus: a list of FILTERS strings
  with expected conjunction-only verdicts, asserted against the lexical
  scan in `workbench-pivots.test.js` and against the parser's AST in
  `test_lcql.py::test_or_scan_fixture_corpus_matches_ast_verdicts` — the
  same corpus, both engines, permanent.
- **Tests to add:** `workbench-pivots.test.js` — every documented form
  emits exactly the documented shape; escaping; the OR-case fresh-query
  fallback and notice; the shared OR-scan fixture corpus. Backend:
  `test_lcql.py::test_documented_pivot_and_descent_forms_parse` parses
  the same pinned fixture strings, closing the loop, plus the AST side
  of the OR-scan corpus.

### 2.16 Evidence-timeline descent

- **Current:** none; `DetectionDetail.jsx` shows triggering-event content
  (rule-evidence summaries per R17); `Incidents.jsx` shows related
  hosts/accounts.
- **Target:** **added** "Open Evidence Timeline" controls (R17): on a
  detection (any kind, uniform) and on an incident. Generated queries:
  single host `all | <hostname> | * | *` (sorted occurrence ascending,
  banner naming the origin, breadcrumb chip back); incident with several
  participant hosts: `all | * | * | *` under the incident's scope filter.
  Descent sets the incident scope for that entry (R10).
- **Tests to add:** `workbench-pivots.test.js` descent forms; navigation
  behavior in `workbench.test.js`; backend fixture parse (2.15).

### 2.17 Legacy endpoint and component retirement

- **Current:** `/api/fake-events` (consumers: `Siem.jsx:26`,
  `Dashboard.jsx:101`, `test_actions.py::test_api_immutable_evidence_after_kill`,
  four `test_event_disclosure.py` tests); `/api/grouped-alerts`
  (consumers: `IncidentDashboard.jsx:39` `.stats`,
  `test_submission_gate.py::test_grouped_alerts_surface_incident_scoped_readiness`,
  `test_event_disclosure.py::test_grouped_alerts_serializes_only_the_whitelist`,
  `::test_no_planted_answer_marker_in_either_response`); the internal
  `grouped` nav key (`Dashboard.jsx`).
- **Target:** **retired** in Phase 8, in dependency order (Section 7,
  Phase 8), with every consumer migrated first and every superseded test
  replaced in the same concern commit. A **route-audit test** (added in
  Phase 3, finalized in Phase 8) asserts the query read is the only event
  path and no mode-specific event endpoint exists.

---

## 3. Exact API plan (task 3.3)

Everything here is inside the locked contract's Section 17 shape; the two
pre-authorized serialized-field changes (event_seq; OD-10) and the P1
stats relocation are the only changes to existing payloads. No endpoint or
field outside the locked contract appears.

### 3.1 `GET /api/events/query`

**Request parameters:**

| Param | Type | Rules |
|---|---|---|
| `q` | string, required | the LCQL query; hard cap 300 characters (re-validated against measured descent needs, contract Section 13); over-cap returns the parse-error shape with `position: 300`, `reason: "query exceeds the 300 character cap"` |
| `scope` | string, optional | `session` (default when absent) or one opaque incident id (`INC-####`) |

Session binding: the standard session middleware (`X-Session-ID` header /
`spectyr_session` cookie), identical to every existing route.

**200 response — complete field enumeration (no ellipses):**

```
{
  "token":    <string, opaque snapshot token>,
  "identity": {
    "canonical_query":      <string>,
    "scope":                <string: "session" or the incident id>,
    "resolved_scope_hosts": [ <hostname string>, ... ],
                            // Amendment E2 (P3.4): the participant-host
                            // set resolved at execution, sorted and
                            // deduplicated; [] for session-wide (no
                            // implicit constraint). MAC-covered. Frozen:
                            // replay and the new-count baseline use THIS
                            // list, never the incident's current set.
    "resolved_range":  { "start": <ISO-8601 string>, "end": <ISO-8601 string> },
    "cutoff_seq":      <integer>
  },
  "count":    <integer>,
  "rows":     [ <sanitized event>, ... ]   // canonical server order
}
```

**Sanitized event row — complete field enumeration (no ellipses).** Fields
marked (always) are unconditionally present; every other field is omitted
when its value is null or empty (the existing serializer rule):

```
{
  "id":              <string uuid, always>,
  "event_seq":       <integer, always>,
  "timestamp":       <ISO-8601 string>,
  "event_type":      <string>,
  "source_type":     <string>,
  "severity":        <string>,
  "hostname":        <string>,
  "source_ip":       <string>,
  "destination_ip":  <string>,
  "user_account":    <string; canonical account field, both populations (OD-10)>,
  "message":         <string>,
  "key_value_pairs": <object; family fields; includes "protocol" when the
                      event has one (OD-10 uniform placement)>
}
```

There is **no** top-level `protocol`, no `label`, `category`,
`scenario_id`, `threat_pattern`, `storyline`, `level`, `level_name`,
`alert_id`, `flagged`, `status`, `detected_by`, `user`, `process_id`,
`parent_process_id`, `log_source`, or any other internal field, and no
population discriminator by presence (shape-parity test).

**Error responses:**

- **400 parse failure:** `{ "error": { "position": <integer, 0-based
  character index into q>, "reason": <string> } }` — optionally
  `"suggestions": [<string>, ...]` for unknown field/sensor/type near
  matches. Nothing executes; no token is minted.
- **404 unknown scope:** `{ "error": "Unknown incident" }` — identical for
  nonexistent and foreign-session incident ids (actions-API convention).
- **Empty result:** a normal `200` with `"count": 0, "rows": []` and a
  valid token (distinct from any error).

**Read-only guarantee:** GET; reads never mutate the pool, the session, or
the world; polling never generates (extended by direct test).

### 3.2 `GET /api/events/query/new-count`

**Request parameters:** `token` (string, required) — nothing else; the
count is bound to the executed definition and edited bar text structurally
cannot influence it.

**200 response — complete enumeration:**

```
{ "new_count": <integer>, "pool_growth": <integer> }
```

Semantics per R16 (refresh-now): `new_count` = rows a Refresh executed now
would add (same canonical query and scope, TIMEFRAME re-resolved at count
time, cutoff = current max `event_seq`, counted by `id` absence from the
original snapshot's rows); `pool_growth` = current max `event_seq` minus
the token's `cutoff_seq`.

**Invalid-token response:** `400 { "error": "Unknown token" }` —
byte-identical for malformed, altered, foreign-session, and
post-reset/post-restart tokens (neutral, indistinguishable).

### 3.3 Token lifecycle (API-visible behavior)

Minted only by a successful query execution. Valid only within the minting
session's lifetime: `snapshot_secret` rotates on `reset-simulator` and
`start-simulator` and dies with the process, so Reset, Practice Another,
and backend restart invalidate all tokens with the single neutral failure
above. No token enumeration, no expiry metadata, no job objects.

### 3.4 Changes to existing endpoints (each pre-authorized by the contract)

1. **`GET /api/fake-events` (transitional, Phases 1-7):** its serializer
   is the shared `sanitize_feed_event`, so it picks up `event_seq` and the
   OD-10 shape amendment the moment Phase 1 lands. Disclosed here as the
   contract requires ("serialized on every event"; Section 17 amendment
   list). Retired in Phase 8.
2. **`GET /api/incidents`:** gains one top-level field in Phase 8 —
   `"stats": { "severity_breakdown": { "low": n, "medium": n, "high": n,
   "critical": n } }` — the relocation target for the grouped-alerts
   `.stats` consumer. **[Scaffold decision]** fields-on-`/api/incidents`
   chosen over a new stats endpoint (P1 authorizes either; a new endpoint
   for one widget is surface without benefit).
   **Exact semantics comparison (review correction 7).** Current
   calculation, recorded from code: `get_grouped_alerts` builds one group
   per non-normal scenario with a per-group `severity_breakdown` counting
   **each written event's** severity (`app.py:4411-4414`); groups are
   filtered to chain-complete (`:4417`); analyst mode first reduces each
   group's logs to trigger events and recomputes the breakdown
   (`:4434-4444`); `stats.severity_breakdown` then sums the per-group
   per-event counts (`:4479-4486`). So the widget's current meaning is
   **per-event severity counts over chain-complete attack-scenario
   events, excluding normal traffic** — it has never been per-incident
   severity. The relocated computation is **byte-for-byte the same
   aggregation** (per-event, non-normal, chain-complete-scenarios-only)
   with exactly one ratified difference: the analyst-mode trigger
   reduction disappears with R11 uniform visibility. Nothing is
   redefined; the migration commit (8.2) asserts equality of the
   relocated and legacy computations over the same pool in a non-analyst
   session. The `source_breakdown`, `total/open/closed_alerts` stats die
   with the endpoint (no consumer; `IncidentDashboard` reads only
   `severity_breakdown` — verified `IncidentDashboard.jsx:31,39` and its
   test mock).
3. **`GET /api/detections/<id>` / `GET /api/threats`:** **unchanged.**
   Triggering events keep the `EVENT_WHITELIST` shape: no `id`, no
   `event_seq` (D11 invariant; R17 rule-evidence framing).

### 3.5 Route retirement and consumer migration map

| Legacy route | Consumer | Migration | Phase |
|---|---|---|---|
| `/api/fake-events` | `Siem.jsx:26` 2s poll | replaced by the query read when the shell lands | 4 |
| `/api/fake-events` | `Dashboard.jsx:101` session-existence check | `GET /api/game-state` | 8 |
| `/api/fake-events` | `test_actions.py::test_api_immutable_evidence_after_kill` | re-reads via `/api/events/query` (`all \| * \| * \| *`) | 8 |
| `/api/fake-events` | `test_event_disclosure.py` (4 fake-events tests) | retargeted to the query read, not weakened | 8 |
| `/api/grouped-alerts` | `IncidentDashboard.jsx:39` `.stats` | `GET /api/incidents` `stats` field | 8 |
| `/api/grouped-alerts` | `test_submission_gate.py::test_grouped_alerts_surface_incident_scoped_readiness` | readiness fields already live on `/api/incidents` cards; the test migrates there | 8 |
| `/api/grouped-alerts` | `test_event_disclosure.py::test_grouped_alerts_serializes_only_the_whitelist`, `::test_no_planted_answer_marker_in_either_response` | first retires with the route; second retargets to query + count reads | 8 |

Neither route is deleted until every row above is migrated and green; the
final route-audit assertion (no `/api/fake-events`, no
`/api/grouped-alerts`, no mode-specific event endpoint, query read as the
only event path) lands in the same Phase 8 commit that deletes them.

---

## 4. State model (task 3.4)

For every item: owner; init; Reset (`/api/reset-simulator`); Practice
Another (= reset + new Guided start); backend restart; serialization;
effect on scoring/readiness/sealing/submissions. **Rule stated up front:
no item below carries or derives from answer-key or grading state; the
structural guard extends to the query read (Section 2.10).**

| # | State item | Owner | Init | Reset | Practice Another | Restart | Serializes? | Scoring/readiness/sealing/submissions |
|---|---|---|---|---|---|---|---|---|
| S1 | Simulation epoch (derived; materialized as `world["started_at"]`) | server | at `start_simulator` from session-id digest | cleared with world; re-derived (same id -> same epoch) | same as reset | new session id -> new epoch | yes (started_at; every occurrence timestamp derives from it) | none: sealing keys on wall `chain_complete_at`; readiness on dispositions; scorers read no timestamps |
| S2 | `session["event_seq"]` counter | server | 0 at `create_session`/`start` | reset to 0 (pool truncated) | reset to 0 | fresh session | per-event stamped value serializes (`event_seq`) | none (never a scoring input; cutoff/visibility only) |
| S3 | Gap RNG (`random.Random(digest(session_id, "gaps"))`) | server | at `start_simulator` | re-seeded identically (same id) | same | fresh | no (its draws surface only as occurrence-time gaps) | none |
| S4 | `session["snapshot_secret"]` (32 random bytes) | server | `create_session` | **rotated** | **rotated** | gone (in-memory) | never (only MACs derived from it leave the server) | none |
| S5 | Snapshot token(s) | client-held, server-verified | minted per successful query | all invalid (S4 rotation) | all invalid | all invalid | is itself the serialized artifact; carries identity + MAC, nothing hidden | none |
| S6 | Editable query text | client (`Siem.jsx`) | empty (placeholder = one canonical example) | cleared on resetTrigger | cleared | n/a (client survives; next query hits new session) | no | none |
| S7 | Executed snapshot `{token, identity, rows, count}` | client | null until first Run | cleared | cleared | stale token fails neutrally on next count/refresh; UI clears on error | no (it IS a served payload, held client-side) | none |
| S8 | Active scope (`session` \| INC id) | client | `session` (R10 default) | reset to `session` | reset | n/a | as the `scope` request param only | none (participant filter only) |
| S9 | Remembered incident return context (return chip) | client | null; set by descent or scope selection | cleared | cleared | n/a | no | none |
| S10 | Selected row id + inspector open state | client | null/closed | cleared | cleared | n/a | no | none |
| S11 | New-events count + pool growth | client (poll of the token read) | hidden (zero state) | cleared | cleared | neutral token failure hides it | no | none |
| S12 | Client sort (field, dir) | client | null (canonical server order) | cleared | cleared | n/a | never (explicitly not identity) | none |
| S13 | View mode (cards/table) | client | cards (existing default) | kept (cosmetic) | kept | n/a | no | none |

---

## 5. LCQL implementation plan (task 3.5)

**Implementation units, in certification order** (each unit is
unit-certified in `test_lcql.py` before the next depends on it; all of
Phase 2 completes before any route or UI touches the module):

1. **Tokenizer** (positions, escapes, quote kinds).
2. **Four-segment parser** (GD-4 `*`/`all`; empty segment = error).
3. **AST** (dataclasses; `Star | Or[And[Pred]]`).
4. **Canonicalizer** (idempotence property test).
5. **Field catalog + resolution** (boot-derived; GD-2 case-insensitive;
   canonical-first-then-kvp order; near-match suggestions).
6. **Operator evaluation** (GD-1 unquoted case-insensitive; GD-5
   string-typed, missing-field-false, escaping; quote-case matrix;
   AND-before-OR precedence).
7. **Error positions and suggestions** (every error names position +
   reason; unknown identifiers add suggestions).
8. **Query executor** (route layer; evaluates over sanitized shapes only;
   canonical order; identity; token).
9. **Pivot generator** (frontend `lcqlPivots.js`; the single choke point;
   conjunction-only refinement restriction with the fresh-query fallback).
10. **Generated-query parse validation** (backend fixture test parses
    every documented pivot/descent form; frontend test asserts the
    generator emits exactly those fixtures; at runtime every generated
    query executes through the server parser, so drift fails loudly).

**Pinned test fixtures from the contract (all become named tests):**

Valid (Section 11): the five examples verbatim —
`1h | Sysmon | ProcessCreate | command_line contains "powershell"`;
`24h | Windows Security | 4625 | user_account == "spatel" and source_ip contains "10.0."`;
`all | ACME-WS10 | * | *`;
`15m | Proxy | HTTP_CONNECT | url contains 'Login.Microsoft'`;
`4h | * | QUERY | query contains "telemetry-sync" or query contains "cdn-edge"`.

Invalid (Section 11): `source_ip=10.0.1.24 event_type=4625` (Splunk-style,
no segments); `Sysmon | ProcessCreate` (two segments); `1h | Sysmon |
ProcessCreate |` (empty FILTERS); `1h | Sysmon | ProcessCreate | x = "y"`
(single `=`). Each asserts position + reason.

Plus: the twelve Section 13 pivot forms and both descent forms as parse
fixtures; the GD-3 precedence cases (`A and B or C` == `(A and B) or C`;
`A or B and C` == `A or (B and C)`); the quote-case matrix (double,
single, unquoted) for all four operators; normalization idempotence.

**Order rationale:** parser and evaluator are certified as a pure module
(Phase 2) before the query route exists (Phase 3), and the route is
certified before the frontend consumes it (Phase 4+), so each layer's
failures are attributable to that layer alone.

---

## 6. Time and event foundation — A1 (task 3.6)

**The A1 implementation, complete and wall-clock-free:**

1. **Simulation epoch:** Section 2.4's digest-derived epoch;
   `SIM_BASE + stable_minutes(session_id)`; no wall-clock input.
2. **`world["started_at"]` = the epoch** (replaces `app.py:4697`'s wall
   clock). Endpoints' world times (stable-key from started_at) and the
   response-action clock (already `started_at`-based via `app.py:2804`)
   align automatically; `test_snapshot_generator.py` and `test_actions.py`
   frozen-clock guards re-verified unchanged.
3. **Authored occurrence times:** for the incident at queue position `p`,
   `base_time = epoch + (p - 1) * 120s` **[Scaffold decision: 120s
   per-position spacing]**, plus authored per-step offsets exactly as
   today (scalar offsets, and supplemental offsets which may be negative).
4. **Authored `[lo, hi]` range offsets:** resolved by the dedicated gap
   RNG (S3), seeded from the epoch digest; consumption order is the
   deterministic queue order, so within a session the gap sequence is a
   pure function of session identity and queue composition.
5. **Background occurrence time:** `epoch + event_seq * 3s` **[Scaffold
   decision, revised at review per correction 3]**, replacing
   wall-clock-minus-random-backdate (`app.py:2177`). Strictly increasing,
   and lands in Phase 1 commit 1.2 (it is a function of `event_seq`,
   which does not exist before 1.2 — review correction 2).
   **Quantified coherence bound (correction 3):** at full-queue drain
   under the encoded reference write model (10 scenarios; writer 1
   write/tick; drip every 30 ticks; one attack write per ~3.5 ticks
   while a chain drains; supplemental events appended at drip; authored
   chain offsets at their `hi` values), the latest background occurrence
   must land within **300 s** of the latest authored occurrence. The
   originally proposed 2 s/step **fails** that bound by precomputation
   (~300 total seq -> background max ~ epoch+600s vs authored max ~
   epoch+1140s: gap ~540s), so the first permitted tuning knob —
   background spacing — was exercised at scaffold correction: **3 s/step**
   (~epoch+900s vs ~epoch+1140s: gap ~240s, inside the bound). The bound
   is enforced permanently by
   `test_event_seq.py::test_authored_background_gap_within_bound`
   (the reference model recomputed from the live catalog's chain lengths
   and offsets, so corpus drift moves the guard). If the constant fails
   again, background spacing is the first knob; any broader semantic
   change requires an owner amendment.
6. **Response-action clock:** unchanged code, now epoch-based via
   `started_at` (item 2).
7. **Sim-now:** the maximum **visible** occurrence timestamp (pool
   anchor), exactly the existing preset semantics, now over sim
   timestamps. TIMEFRAME resolves against it and freezes into identity.
8. **Reset / Practice Another:** same session id re-derives the same
   epoch, gap seed, and spacing; the new run's occurrence times are
   deterministic again (not identical run-to-run in content or
   interleave — see below).
9. **Drip orchestration stays wall clock** (`next_drip_at`,
   `injected_at`, `chain_complete_at`, `timer_start`): these are
   visibility/orchestration times, never occurrence times, and sealing
   and readiness continue to key on them untouched.

**Explicitly still nondeterministic (A1 claims nothing about these; A2
stays deferred and is not accidentally implemented):**

- **Content selection:** normal-event template choice (global RNG).
- **Entity selection:** employee choice per drip (global RNG), INC alert
  ids, queue sampling and shuffle.
- **UUID generation:** event `id`s, session ids (OS entropy).
- **Event ordering:** attack/normal interleave (global RNG gap 2-3), drip
  timing (wall clock, cap gating), thread scheduling; consequently
  `event_seq`-to-content assignment varies run to run.
- **Full cross-run replay:** not provided, not claimed; no session seed
  input exists anywhere in the product (inspection report D), and this
  scaffold introduces none.

**The A1 determinism test** (`test_sim_epoch.py`): recompute every
authored occurrence timestamp from (epoch, position spacing, authored
offsets, the seeded gap stream) and every background timestamp from
(epoch, event_seq) and compare to the written pool — byte-equal; plus a
no-wall-clock property (generate with a mocked frozen wall clock at two
different wall times; occurrence timestamps identical).

---

## 7. Build phases and checkpoints (task 3.7)

The task's proposed order is adopted with **one adjustment**: the pivot
**generator module** (frontend) and its choke-point fixtures land at the
start of Phase 6 rather than Phase 7, because the Phase 6 sidebar and
inspector per-field actions are contractually required to route through
that generator; Phase 7 then wires entity pivots, descent, and scope
movement. No phase depends on a later phase to become gate-green; the one
transitional artifact (the route-audit test) asserts the transitional
truth at Phase 3 and is tightened, not un-broken, at Phase 8.

Per phase: concern; prerequisites; files; endpoint/serialized-field
changes; tests before commit; Chrome evidence; stop condition; commits;
rollback boundary.

---

**Phase 0 — contract lock and baseline verification.** DONE upon this
scaffold's approval: lock commit `eb49610`; baseline facts in Section 1;
verification battery recorded in the session report. No product code.
Stop condition: owner + reviewer approve this scaffold. Rollback: n/a.

---

**Phase 1 — event foundation (backend only).**
- **Concern:** one coherent, deterministic event timeline and one
  canonical serialized event shape, before any query machinery.
- **Prerequisites:** Phase 0 approval.
- **Files:** added `backend/sim_epoch.py`, `backend/test_sim_epoch.py`,
  `backend/test_event_seq.py`; adapted `backend/app.py` (`:2140-2198`,
  `:2225-2246`, `:2382-2522`, `:2541-2623`, `:4697`, `create_session`,
  `reset_simulator`), `backend/detection_templates.py` (`:294-327`),
  `backend/test_event_disclosure.py`, `frontend/src/components/siemUtils.js`
  + `frontend/src/__tests__/siem.test.js` (the 1.3 transitional protocol
  consumer); `backend/run_gates.py` suite list extension.
- **Endpoint/field changes:** `/api/fake-events` rows gain `event_seq`;
  `user_account` appears on background events with account data;
  top-level `protocol` disappears into `key_value_pairs` (all
  pre-authorized; disclosed in the implementation report).
- **Commits (order per review correction 2 — background occurrence times
  cannot land before `event_seq` exists):**
  (1.1) simulation epoch + `started_at` unification + **authored**
  occurrence times + determinism tests + parity re-run + the action-clock
  alignment/scoring-invariance evidence (Section 2.4b; the action clock
  itself is unchanged);
  (1.2) `event_seq` allocator (atomic append-and-stamp helper) +
  serialization + **background** occurrence times (`epoch + 3s x seq`) +
  pool invariants (uniqueness, strict increase, contiguity, once-only,
  failed-append) + the authored/background coherence-bound test;
  (1.3) OD-10 shape amendment + shape-parity test + disclosure-suite
  updates + the `siemUtils` protocol-filter compatibility change and its
  test (same concern).
- **Tests before each commit:** the complete backend AND frontend gate
  (`run_gates.py --all`) for every Phase 1 commit (each changes the
  serialized payload; review correction 5).
- **Chrome evidence:** optional payload spot-check only (backend phase).
- **Stop condition:** battery green; parity green; a captured
  `/api/fake-events` payload of both populations shows the canonical
  shape.
- **Rollback boundary:** each commit reverts cleanly; 1.3 is independent
  of 1.1 (serializer vs clock) — failure diagnosis splits along commit
  lines.

---

**Phase 2 — LCQL core (pure module).**
- **Concern:** the certified grammar engine, no routes, no UI.
- **Prerequisites:** Phase 1 (evaluator runs over the canonical shape).
- **Files:** added `backend/lcql.py`, `backend/test_lcql.py`;
  `run_gates.py` list.
- **Endpoint/field changes:** none.
- **Commits:** (2.1) tokenizer + parser + AST + canonicalizer + error
  positions; (2.2) field catalog + resolution + suggestions; (2.3)
  evaluator + quote-case + precedence + missing-field semantics + the
  pinned valid/invalid fixture battery + documented pivot/descent parse
  fixtures.
- **Tests before commit:** backend battery.
- **Chrome evidence:** none (pure module).
- **Stop condition:** every pinned fixture green; idempotence property
  green.
- **Rollback boundary:** the module is unused by product routes until
  Phase 3; reverting it cannot affect the running game.

---

**Phase 3 — query and snapshot backend.**
- **Concern:** the single server-side event-query path with snapshot
  identity, token, new-count, scope, and leak guards.
- **Prerequisites:** Phases 1-2.
- **Files:** adapted `backend/app.py` (two new routes; secret mint +
  rotation); added `backend/test_query_read.py` (routes, canonical order,
  replay, token security, new-count, scope subset + structural guard,
  planted-marker leaks, read-no-mutation, transitional route audit);
  `run_gates.py` list.
- **Endpoint/field changes:** adds `GET /api/events/query` and
  `GET /api/events/query/new-count` exactly per Section 3 of this
  scaffold.
- **Commits:** (3.1) query route (parse -> scope -> execute -> canonical
  order -> identity -> token) + replay/order/leak/no-mutation tests;
  (3.2) token validation + neutral failures + secret rotation + new-count
  route + its semantics tests; (3.3) transitional route-audit test
  (asserts: the only event-row-serving routes are `fake-events` (flagged
  transitional) + the query read; no mode-specific event route).
- **Tests before commit:** backend battery.
- **Chrome evidence:** curl/DevTools payload capture of both routes.
- **Stop condition:** Section 18 backend-only criteria for snapshots,
  replay, token, new-count, scope all green.
- **Rollback boundary:** routes are additive; reverting restores the
  pre-Stage-4 API surface exactly.

---

**Phase 4 — SIEM workbench shell (frontend).**
- **Concern:** replace the live feed with the analyst-driven shell:
  query bar, scope control, TIMEFRAME editor, Run Query, snapshot status,
  and a minimal frozen result rendering (adapted table/cards) with
  loading/error/empty/no-results states. The 2s poll, dropdown filters,
  `parseEventQuery`, and the Splunk placeholder are deleted here.
- **Prerequisites:** Phase 3.
- **Files:** adapted `frontend/src/components/Siem.jsx`,
  `SiemTable.jsx`, `SiemCards.jsx`, `siemUtils.js` (retire dead halves);
  adapted `frontend/src/__tests__/siem.test.js` -> superseded cases
  replaced by added `workbench.test.js` + `workbench-states.test.js` in
  the same commits.
- **Endpoint/field changes:** none (consumes Phase 3 routes).
- **Commits:** (4.1) shell + Run Query + snapshot status + minimal frozen
  results + state tests -- the empty-state/hint query help MUST include
  the GD-5a unquoted-value rules (contract post-lock amendment, owner
  rider at Phase 2 acceptance); (4.2) scope control incl. the revised
  scope-error behavior (chip retained, prior snapshot preserved, Run
  disabled, no silent fallback) + TIMEFRAME segment editor (control and
  text can never disagree).
- **Accepted process deviation (recorded at Phase 4 closure, owner
  ruling):** the client TIMEFRAME helpers (`TIME_PRESETS`,
  `withinPreset`, `poolAnchorMs`) and their old `siem.test.js` cases were
  removed in commit 4.1 (`1694217`), while the replacement
  TIMEFRAME-control coverage landed in commit 4.2 (`0fd08b4`) -- a
  cross-commit replacement inside one phase, accepted without rewriting
  history because the replacement control itself was a 4.2 deliverable.
  **Same-concern replacement remains the rule going forward.**
- **Tests before commit:** frontend suite (`CI=true npx react-scripts
  test --watchAll=false`) via `run_gates.py --frontend`.
- **Chrome evidence:** run a valid query, see frozen results; parse error
  renders position + reason with prior snapshot intact.
- **Stop condition:** shell states enumerated and tested; zero console
  errors in a manual pass.
- **Rollback boundary:** frontend-only; the backend routes stand alone.

---

**Phase 5 — stable result experience.**
- **Concern:** the no-movement guarantees under live drip.
- **Prerequisites:** Phase 4.
- **Files:** adapted `Siem.jsx`, `SiemTable.jsx`, `SiemCards.jsx`; added
  `workbench-snapshot.test.js`.
- **Endpoint/field changes:** none.
- **Commits:** (5.1) atomic snapshot replacement + selection persistence
  (id survives -> selection + inspector persist; absent -> one-line
  notice) + explicit Refresh; (5.2) new-events indicator + pool-growth
  readout (token-read poll) + zero-state hiding + client-only column
  sorting over frozen rows.
- **Tests before commit:** frontend suite; the mocked-growing-pool
  byte-stability and no-row-movement assertions are the heart of this
  phase.
- **Chrome evidence:** watch telemetry arrive with a snapshot open; rows
  do not move; the indicator counts; Refresh replaces atomically.
- **Stop condition:** Section 18 "Stable snapshots", "Explicit refresh",
  "Canonical order and client sort", "Zero row movement" criteria green.
- **Rollback boundary:** commit-level.

---

**Phase 6 — field sidebar and inspector (+ the pivot generator module).**
- **Concern:** snapshot-derived field summaries and the full event lens.
- **Prerequisites:** Phase 5. **Adjustment (stated reasoning):** the
  generator module lands first in this phase because sidebar value clicks
  and inspector per-field actions must route through it (contract
  Sections 10.3, 12); building them against a stub would mean rework and
  an untested seam.
- **Files:** added `frontend/src/components/lcqlPivots.js`,
  `workbench-pivots.test.js`; adapted `Siem.jsx` (sidebar), inspector
  componentry (from `renderCleanEventDetails` base), `workbench.test.js`;
  backend `test_lcql.py` gains the generator fixture parity fixtures (if
  not already complete from 2.3).
- **Endpoint/field changes:** none.
- **Commits:** (6.1) `lcqlPivots.js` generator + choke-point tests
  (documented forms, escaping, conjunction-only append, OR fresh-query
  fallback); (6.2) field sidebar (snapshot-only top-5 values + counts,
  common-then-family, type-aware rendering, value click -> generator);
  (6.3) inspector completeness (identity + `event_seq` display + commons
  + kvp catalog order + raw views + per-field actions + malformed
  fallback) + recursive props leak check.
- **Tests before commit:** frontend suite (+ backend battery when
  `test_lcql.py` fixtures are touched).
- **Chrome evidence:** sidebar counts match a hand-count over the visible
  snapshot; inspector shows every field of one event per family.
- **Stop condition:** "Inspector completeness" + sidebar behavior green.
- **Rollback boundary:** commit-level; the generator module is pure and
  independently revertable.

---

**Phase 7 — pivots and evidence descent.**
- **Concern:** investigative movement: entity pivots, scope flip, return
  chip, Open Evidence Timeline.
- **Prerequisites:** Phase 6.
- **Files:** adapted `Siem.jsx`, `Dashboard.jsx` (descent navigation
  context), `DetectionDetail.jsx`, `Incidents.jsx`; adapted
  `workbench-pivots.test.js`, `workbench.test.js`,
  `scope-no-mutation.test.js` (extended to query/pivot/descent
  interactions).
- **Endpoint/field changes:** none.
- **Commits:** (7.1) entity pivots (host, account, IP, domain, process,
  file, event type, sensor) + Session-wide flip + return chip; (7.2)
  Open Evidence Timeline descent from detections and incidents
  (host-anchored ascending timeline, origin banner, breadcrumb; incident
  multi-host form under incident scope) + descent-sets-scope rule; (7.3)
  surrounding-events action + OR-fallback notice UX.
- **Tests before commit:** frontend suite; backend battery if fixtures
  extend.
- **Chrome evidence:** the full pivot chain and both descent workflows
  (Section 9's workflows 2-5 in draft form).
- **Stop condition:** "Pivot and descent generation", "Cross-host
  pivots" criteria green; detection-kind indistinguishability preserved
  through descent (identical control and query shape for every kind).
- **Rollback boundary:** commit-level.

---

**Phase 8 — migration and retirement.**
- **Concern:** one event path; legacy surface deleted; docs truthful.
- **Prerequisites:** Phases 4-7 (no remaining UI dependence on legacy
  routes except the two named migrations).
- **Files:** adapted `frontend/src/pages/Dashboard.jsx` (existence check;
  nav `grouped` key rename), `IncidentDashboard.jsx`,
  `incident-dashboard.test.js`, `backend/app.py` (delete
  `get_fake_events`, `get_grouped_alerts` + `_sanitize_alert_group` +
  the analyst trigger branch; add `stats` to `list_incidents`),
  `test_actions.py`, `test_event_disclosure.py`,
  `test_submission_gate.py`, `test_query_read.py` (final route audit),
  docs (`CLAUDE.md` API table, `docs/stage4-query-grammar-notes.md`
  frozen-clock note now true, `log_writer` docstring C7, Docs page SIEM
  description).
- **Endpoint/field changes:** `/api/incidents` gains `stats`
  (severity_breakdown); `/api/fake-events` and `/api/grouped-alerts`
  **deleted**.
- **Commits:** (8.1) Dashboard existence check -> `game-state`; (8.2)
  stats relocation + IncidentDashboard migration + its test; (8.3) route
  deletions + trigger-branch removal + every retargeted backend test +
  final route-audit assertion + nav key rename; (8.4) docs pass, incl.
  the GD-5a unquoted-value rules in the Docs-page query help (owner
  rider at Phase 2 acceptance).
- **Tests before commit:** full battery both sides (`run_gates.py --all`).
- **Chrome evidence:** Dashboard severity widget still renders; network
  tab shows zero calls to retired routes across all tabs.
- **Stop condition:** route audit final-form green; "Mode visibility"
  criterion green (single query path, no mode-specific endpoint,
  trigger branch gone).
- **Rollback boundary:** 8.3 is the point of no return for the legacy
  routes; it reverts as one commit if a hidden consumer surfaces (the
  audit test and consumer map above exist to make that impossible).

---

**Phase 9 — complete closing evidence.**
- **Concern:** the contract's Section 18 battery as a whole, plus the
  Chrome workflow evidence, across all three modes.
- **Prerequisites:** Phases 1-8.
- **Files:** added `docs/stage-4-implementation-report.md` (the closing
  evidence document: every serialized-field and endpoint change disclosed
  per the standing rule; the Section 18 criteria table with test names
  and results; Chrome workflow transcripts); test-only gap-fill commits
  if the matrix audit finds a criterion represented only by prose.
- **Endpoint/field changes:** none.
- **Commits:** (9.1) any test gap-fills; (9.2) the evidence report
  (docs-only).
- **Tests before commit:** full battery both sides; the nine Chrome
  workflows of Section 9 executed and recorded; leak verification
  (planted markers + payload inspection) in all three modes; the
  no-row-movement proof under live drip.
- **Stop condition:** every Section 18 criterion maps to a green named
  test or recorded Chrome step; zero steady-state console errors; owner
  review of the report.
- **Rollback boundary:** docs-only closure; product state is Phase 8's.

---

## 8. Test and evidence matrix (task 3.8)

Every contract Section 18 criterion, mapped. Status: **new** = new test,
**ext** = extension of a named existing test/file, **mig** = migrated/
retargeted existing test. Backend files: `test_sim_epoch.py` (T-SE),
`test_event_seq.py` (T-EQ), `test_lcql.py` (T-LC), `test_query_read.py`
(T-QR), `test_event_disclosure.py` (T-ED). Frontend: `workbench.test.js`
(W), `workbench-states.test.js` (W-ST), `workbench-snapshot.test.js`
(W-SN), `workbench-pivots.test.js` (W-PV).

| Section 18 criterion | Backend test (planned name) | Frontend test (planned name) | Chrome step (Section 9 ref) | Phase | Status |
|---|---|---|---|---|---|
| Hierarchy (3.9 battery untouched, incl. detection indistinguishability) | the full existing battery via `run_gates.py` (no renames) | existing suite | #8 modes | every phase | ext (unchanged, continuously green) |
| Sanitized payloads (retargeted hotfix suite; recursive planted markers; structural whitelist) | T-ED::test_query_read_serializes_only_the_whitelist (mig of fake-events form); T-QR::test_planted_marker_never_serializes_recursively; T-ED::test_fake_events_unknown_future_field_does_not_pass_through (mig to query read at P8) | W::renders only whitelisted keys (recursive props check) | #9 payload inspection | 3, 8 | mig + new |
| Shape parity (OD-10) | T-ED::test_shape_parity_no_population_exclusive_top_level_field | n/a | #9 payload inspection | 1 | new |
| event_seq foundation: uniqueness, strict increase, contiguity, assignment-once, failed-append safety | T-EQ::test_event_seq_unique_and_strictly_monotonic; T-EQ::test_event_seq_contiguous_no_gaps; T-EQ::test_event_seq_assigned_exactly_once; T-EQ::test_failed_append_does_not_advance_counter | W::inspector displays arrival position | #2 inspector | 1 | new |
| Append-only pool | T-EQ::test_pool_append_only_under_polls_and_reads | W-SN (mocked pool only grows) | #1 | 1 | new |
| Stable snapshots (byte-stable under growth; atomic replacement) | T-QR::test_snapshot_rows_stable_for_fixed_identity | W-SN::"snapshot rows byte-stable while mocked pool grows"; W-SN::"replacement is atomic" | #1 | 3, 5 | new |
| Deterministic within-session replay (identity and token) | T-QR::test_identical_identity_replays_byte_identical; T-QR::test_token_reexecution_equals_identity_reexecution | n/a | #1 refresh | 3 | new |
| Explicit refresh (new cutoff/token; prior snapshot untouched; selection persistence + absence notice) | T-QR::test_refresh_mints_new_cutoff_and_token | W-SN::"selection persists when id survives"; W-SN::"absence notice when it does not" | #1 | 3, 5 | new |
| Canonical order and client-only sort | T-QR::test_rows_in_canonical_order | W-SN::"column sort issues no request and keeps token" | #1 | 3, 5 | new |
| Token security (neutral, indistinguishable failures; invalid after Reset / Practice Another / restart) | T-QR::test_invalid_tokens_fail_neutrally_and_identically; T-QR::test_reset_and_start_rotate_secret | W-ST::"token failure clears indicator neutrally" | #7 token lifecycle | 3 | new |
| Shared epoch (started_at == epoch; frozen-time guard green; no wall clock) | T-SE::test_world_started_at_equals_epoch; T-SE::test_no_wall_clock_in_occurrence_timestamps; existing test_snapshot_generator + test_actions guards | n/a | #9 | 1 | new + ext |
| New-count (refresh-now semantics; token-bound; zero state; pool_growth; bar text cannot alter) | T-QR::test_new_count_matches_refresh_now_semantics; T-QR::test_new_count_request_carries_token_only | W-SN::"indicator hidden at zero; de-emphasized on edit" | #1 | 3, 5 | new |
| Time semantics A1 (recomputation equality; sim-now = pool max; coherence bound; action clock unchanged) | T-SE::test_occurrence_times_recompute_from_epoch_spacing_offsets_gapstream; T-SE::test_sim_now_is_pool_max_never_wall_clock; T-EQ::test_authored_background_gap_within_bound; T-SE::test_action_clock_base_equals_epoch; T-SE::test_action_score_is_timestamp_invariant | n/a | #9 (incl. sorted-window interleave) | 1 | new |
| `all`-range correctness (min visible occurrence; negative offsets included) | T-QR::test_all_range_includes_negative_offset_supplemental | n/a | #1 | 3 | new |
| Display vs FILTERS catalogs (event_seq serialized but not filterable) | T-LC::test_event_seq_rejected_as_filter_field | W::inspector shows event_seq; no filter action offered on it | #2 | 2, 6 | new |
| LCQL grammar (valid/invalid fixtures; errors w/ position; precedence; quote matrix; idempotence) | T-LC::test_contract_valid_examples_parse; T-LC::test_contract_invalid_examples_reject_with_position; T-LC::test_and_binds_tighter_than_or; T-LC::test_quote_case_matrix; T-LC::test_canonicalization_idempotent | W::query bar surfaces position + reason inline | #1, #5 | 2 | new |
| Pivot and descent generation (choke point; escaping; OR fallback; both descent forms) | T-LC::test_documented_pivot_and_descent_forms_parse | W-PV::"every documented form emitted exactly"; W-PV::"OR filters trigger fresh standalone query + notice"; W-PV::"escaping of injected values" | #4, #5 | 6, 7 | new |
| Evidence descent (host-anchored; uniform across detection kinds; origin banner; ascending) | T-LC (descent fixtures); existing test_detection_indistinguishability battery stays green | W-PV::"descent emits all-host timeline ascending with banner" | #2, #3 | 7 | new + ext |
| Inspector completeness (every whitelisted field per family; no non-whitelisted key; event_seq shown) | n/a (serializer side covered above) | W::"renders every whitelisted field for each family"; W::"recursive props check finds no forbidden key" | #2 | 6 | new |
| Incident scoping (subset property; constraint equals participant hosts; structural guard on query read) | T-QR::test_scoped_subset_of_session; T-QR::test_scope_constraint_equals_participant_hosts; T-QR::test_query_read_structural_no_answer_key_inputs | W-ST::"scope chip states" | #2, #6 | 3 | new |
| Cross-host pivots (visible Session-wide flip; return chip restores; reads only) | n/a | W-PV::"entity pivot flips scope visibly"; W-PV::"return chip re-runs under incident scope" | #4 | 7 | new |
| Mode visibility (single query path; route audit; trigger branch removed) | T-QR::test_route_audit_single_event_query_path (transitional P3, final P8); T-QR::test_no_mode_specific_event_endpoint | n/a | #8 all three modes | 3, 8 | new |
| Empty/loading/error/sealing states (incl. revised scope-error) | n/a | W-ST enumerates every Section 6 pane state incl. "scope load failure keeps chip, disables Run, no silent fallback"; pre-seal banner; submitted-incident scope | #6 scope failure | 4, 5 | new |
| No-mutation reads (query, refresh, new-count, pivot, descent, scope switch, inspector) | T-QR::test_query_and_count_reads_do_not_mutate | scope-no-mutation.test.js extended to workbench interactions | #9 network audit | 3, 7 | new + ext |
| Zero grading leaks (planted grading markers; submission-gate battery green) | T-QR::test_planted_grading_marker_never_in_query_or_count; full test_submission_gate battery | detections.test.js (existing) | #3, #9 | 3 | new + ext |
| Zero automatic row movement | n/a (server rows are a response value) | W-SN::"no insertion, removal, or reorder across mocked poll cycles" | #1 | 5 | new |

No criterion is represented only by prose: every row names at least one
automated test, and the review-level "Hierarchy" docs check rides on the
Phase 9 report.

---

## 9. Chrome workflow plan (task 3.9)

Executed in Phase 9 against the production-like runtime (built frontend
or CI-equivalent dev build with zero steady-state console errors), with
the dev-harness rule observed (never run the gate battery against the
live backend sharing `backend/logs`; the manual backend for these
workflows is started fresh and stopped before any battery run).

1. **Session-wide investigation.** Start a SOC Queue run; open SIEM; run
   `1h | Sysmon | ProcessCreate | command_line contains "powershell"`;
   verify the snapshot header (count, `seq #N`, sim time); let telemetry
   drip for 60+ seconds; verify zero row movement; watch the new-events
   indicator count up and the Refresh tooltip show pool growth; press
   Refresh deliberately; verify atomic replacement and indicator reset.
2. **Incident descent.** Open an active incident in the Incidents
   workspace; press Open Evidence Timeline; verify the workbench opens
   with incident scope set, the generated host-anchored LCQL visible in
   the bar, ascending order, and the origin banner; inspect one event
   (verify identity incl. "arrived as event #N"); return to the incident
   via the breadcrumb.
3. **Detection descent.** Open a scenario detection's detail; verify its
   trigger card reads as a rule-evidence summary (not a SIEM result row);
   press Open Evidence Timeline; verify the same uniform host-anchored
   query shape as an ambient detection produces (spot-check one of each
   kind); verify no correctness/disposition-correctness disclosure
   anywhere on the path.
4. **Pivot chain.** From a result row: pivot host -> account -> IP ->
   another host; at each step verify the generated LCQL is visible,
   editable, and parses (executes without error); verify the scope
   control visibly flips to Session-wide on the first entity pivot and
   the "Back to INC-…" chip appears and works.
5. **OR-query protection.** Run
   `4h | * | QUERY | query contains "telemetry-sync" or query contains "cdn-edge"`;
   click a sidebar/inspector field value; verify a fresh standalone query
   replaces the bar (not an append) with the explanatory one-line notice.
6. **Scope failure.** With an incident scope selected, simulate a scope
   read failure (DevTools request blocking on `/api/incidents/<id>/scope`);
   verify the chip is retained, the "Incident scope could not be loaded."
   notice shows, the previous snapshot is preserved untouched, Run Query
   is disabled, and there is no silent Session-wide fallback; unblock and
   verify recovery.
7. **Token lifecycle.** Capture a valid token; (a) alter one character
   and call new-count — neutral 400; (b) replay a token from a different
   session — identical neutral 400; (c) Reset — old token identical
   neutral 400; (d) Practice Another — same; (e) restart the backend —
   same, **explicitly confirming the stale-session middleware path: after
   restart the old session id no longer exists, so the request traverses
   session-middleware re-creation before token validation, and the
   response must still be the byte-identical neutral 400 (not a different
   middleware error body)**; verify all five failure bodies are
   byte-identical.
8. **All three modes.** In Guided, SOC Queue, and Hardcore: verify the
   SIEM issues only `/api/events/query` + `/api/events/query/new-count`
   for events (network tab); verify no pre-submission grading appears
   anywhere in the workbench; verify no mode-specific event endpoint is
   ever called; verify identical workbench behavior modulo intake/timer.
9. **Console and network audit, plus time-coherence evidence (review
   correction 3).** A full session (start -> investigate -> submit at
   least one incident) with the console open: zero steady-state errors;
   capture one `/api/events/query` and one new-count payload and inspect
   every field against Section 3's enumeration: no forbidden field, no
   population discriminator, no grading value. **Then the interleave
   proof:** run `all | * | * | *` sorted by occurrence time and verify
   authored and background events remain meaningfully interleaved in the
   sorted window — events of a known incident's chain (identified by the
   tester via known scenario content, invisible to players) appear
   interspersed with background events, not as a detached block beyond
   all background timestamps; record the observed latest-authored vs
   latest-background gap against the tested 300 s bound.

---

## 10. Risk register (task 3.10)

| # | Risk | Detection strategy | Retired in | Halt condition | Owner amendment needed? |
|---|---|---|---|---|---|
| K1 | Changing `world["started_at"]` breaks snapshot/world invariants (stable-key world times, action clock) | run `test_snapshot_generator.py` + `test_actions.py` + full battery in commit 1.1; the epoch is an ISO string exactly like today's value, so type surface is unchanged | 1 | any frozen-clock guard red at 1.1 | no (R8 authorizes; if a guard proves epoch-incompatible in a way requiring semantics change, halt and report) |
| K2 | Occurrence-timestamp changes upset scenario parity, UI time displays, or authored/background coherence | parity suite (ignores timestamps) + T-SE; the quantified 300 s gap bound (T-EQ, reference model); Chrome workflow 9's sorted-window interleave proof; manual sweep of every timestamp-rendering surface (SIEM, Detections `time`, Endpoints, Incidents) in Phase 4/9 | 1 (backend), 9 (UI sweep) | parity red, bound test red, or a UI surface renders nonsense sim times that the permitted knob cannot fix | **background spacing is the first permitted tuning knob** (already exercised once: 2s -> 3s at scaffold correction); any broader semantic change (e.g. re-anchoring authored times to drip seq): yes, amendment |
| K3 | `event_seq` not exactly-once/contiguous under concurrent writes (writer thread vs supplemental append), breaking `pool_growth = max_seq - cutoff_seq` | ONE append-and-stamp helper under a single atomic `io_lock` boundary; counter advances only on successful append; T-EQ uniqueness/strict-increase/contiguity/failed-append tests over a live multi-incident drip; code review of both write paths | 1 | duplicate, skipped, or non-contiguous seq observed in any test run | no |
| K4 | Token signing/validation flaw (forgeable, distinguishable failures, secret survives reset) | T-QR security battery incl. byte-identical failure assertion + rotation tests; constant-time compare | 3 | any distinguishable failure or accepted forgery | no |
| K5 | Query parser ambiguity (precedence, quotes, segment boundaries with spaces) | pinned fixture battery + idempotence property + fuzz-lite corpus in T-LC | 2 | any fixture ambiguous or canonicalization non-idempotent | no (grammar completions are ratified; a discovered grammar hole = amendment request, not silent fix) |
| K6 | Nested `key_value_pairs` normalization (OD-10 protocol injection) mutating stored logs or colliding with existing kvp keys | serializer copies kvp before injection; never overwrites an existing key; T-EQ read-no-mutation + T-ED shape tests | 1 | any mutation of a stored log dict or NDJSON row observed | no |
| K7 | Attack/background shape leakage returning through a future field | whitelist-only construction + unknown-future-field test + shape-parity test + recursive planted markers | 1, 3 | any parity or marker test red | no |
| K8 | Query performance: repeated full-pool scans (query + new-count re-execution) | volumes are ~150-300 events (inventory 10); measure request latency in Phase 9 Chrome audit; new-count is O(2 scans) | 9 | observed latency degrading the UI (>250ms server time sustained) | no (contract defers performance work absent measurement; if measurement demands architecture change, amendment) |
| K9 | Retiring legacy feeds breaks Dashboard/Incidents (hidden consumer) | the Section 3.5 consumer map; repo-wide grep gate in 8.3; final route audit; Chrome network sweep of every tab | 8 | any surface still calling a retired route | no |
| K10 | Stage 3.9 submission/readiness invariants disturbed (timestamps, seq, or scope wiring touching sealing) | sealing keys on wall-clock `chain_complete_at` (untouched); full submission-gate battery every phase | every phase (continuous) | any 3.9 battery test red | halt regardless; if the fix requires touching a frozen boundary, amendment |
| K11 | Frontend state complexity: editable text vs executed snapshot vs scope vs return context drifting apart | the state model table (Section 4) is the implementation checklist; W-ST enumerates every pane state; the indicator is token-bound by construction | 4-5 | states unrepresentable in the model table appear during build | no (model table update = scaffold-level, disclosed in the report) |
| K12 | Detection indistinguishability broken behaviorally by descent (kind-revealing query shape or empty-result tell) | uniform host-anchored form for every kind (R17); existing indistinguishability battery; Chrome workflow #3 compares kinds | 7 | any kind-distinguishing behavior observed | no (this is exactly what R17's design prevents; an id-descent revival would be an amendment) |
| K13 | Test harness vs live backend session dirs (gate boot sweep kills live drip) | BACKLOG rule enforced procedurally: batteries never run while the manual backend is up; Phase 9 workflows use a dedicated backend instance | every phase | a battery run while a live session is active | no |

---

## 11. Explicit amendment register (task 3.11)

**No amendment requests.** Everything this scaffold builds is inside the
locked contract's authority, including the three pre-authorized payload
changes (`event_seq`; the OD-10 shape amendment; the P1 stats
relocation). Specifically re-checked against the amendment triggers:

- **Not covered by the contract:** nothing found requiring coverage. The
  scaffold-level decisions the contract delegated are **RATIFIED at the
  owner review of 2026-07-19**: digest-derived epoch (Section 2.4);
  spacing constants (120s/position; background spacing revised 2s -> 3s
  under the quantified coherence check, Section 6) — **subject to the
  quantified coherence bound test**. **K2 tuning authority exercised
  (recorded per the Phase 2 rider):** the reference model over the live
  catalog (n_model = 309 seq steps = 270 drip-gap ticks + 21 drain ticks
  for the longest chain + 18 worst-case supplemental appends; authored
  max = 9 x 120s + 138s max hi-offset span = 1218s) measured 2 s/step at
  background max 618s -> gap **600s, failing** the 300s bound, and
  3 s/step at background max 927s -> gap **291s, passing**; the knob was
  exercised once, 2s -> 3s, at scaffold correction, and
  `test_event_seq.py::test_authored_background_gap_within_bound` now
  recomputes exactly this model from the live catalog permanently; HMAC snapshot token and neutral
  failure response (Section 2.8); corrected `all`-range semantics
  (minimum visible occurrence, Section 2.7); stats relocation venue
  (fields on `/api/incidents`, Section 3.4.2) — **subject to preserving
  the widget's recorded semantics** (the comparison in 3.4.2);
  quote-aware conjunction scan (Section 2.15, with the
  grouping-equivalence boundary comment and shared fixture corpus).
  The review also ruled: action clock left unchanged (Section 2.4b),
  Phase 1 commit order 1.1/1.2/1.3 as revised, and transitional protocol
  compatibility handled in 1.3.
- **More expensive than represented:** nothing found. The A1 cost
  matches the contract's re-costed estimate (one new module + localized
  call-site changes + one determinism suite); the action clock aligns for
  free because it already reads `started_at` (`app.py:2804`).
- **Incompatible with repository truth:** nothing found. Every cited
  line was re-verified this session (`app.py:2399/:2177/:4697/:2804`,
  `detection_templates.py:294-327`, `_incident_observable_scope`
  `app.py:3545`, `_sanitize_alert_group` `app.py:4351`, consumer map).
- **Alters a frozen 3.9 invariant:** only the one ratified crossing (A1
  occurrence timestamps + `started_at`), exactly as authorized by R8;
  sealing/readiness/scoring inputs remain wall-clock/disposition-based
  and untouched.
- **Undisclosed field/endpoint/state/behavior:** none — Sections 3 and 4
  enumerate every one, and the Phase 9 report re-discloses them per the
  standing rule.
- **Pulls deferred work forward:** none. A2 stays unimplemented (no seed
  input appears anywhere in this plan); exact-id descent, absolute
  TIMEFRAME, parentheses, saved searches, history, and the
  detection-materialization timing alignment all stay deferred.

One watch item, pre-registered (not an amendment): if Phase 9's Chrome
sweep shows the A1 constants producing player-visible time incoherence
that tuning cannot fix (risk K2), the fallback options touch contract
semantics and would come back as an explicit amendment request rather
than be absorbed silently.

---

## 12. Recommended implementation branch and relative sizing

**Branch:** `stage-4-siem-workbench` (from `main` at `eb49610`+, matching
the `stage-3.9b-workflow-clarity` convention). Concern-level gate-green
commits on the branch; merge to `main` after Phase 9 evidence review.

**Relative complexity by phase** (S < M < L; no time promises):

| Phase | Size | Dominant cost |
|---|---|---|
| 0 lock + baseline | done | — |
| 1 event foundation | **L** | touching generation under parity + freeze constraints; three suites |
| 2 LCQL core | **L** | parser/evaluator correctness + the pinned fixture battery |
| 3 query/snapshot backend | **M** | token + new-count semantics; leak/no-mutation guards |
| 4 workbench shell | **M** | Siem.jsx rewrite + state enumeration + superseded-test replacement |
| 5 stable results | **M** | stability/atomicity/no-movement test rigging |
| 6 sidebar + inspector (+ generator) | **M** | generator choke point + inspector completeness matrix |
| 7 pivots + descent | **M** | scope movement UX + uniform descent + fixtures |
| 8 migration + retirement | **S-M** | consumer migrations + deletions + route audit + docs |
| 9 closing evidence | **M** | nine Chrome workflows + report + gap fills |

---

*End of scaffold. Implementation is not authorized by this document;
it begins only after explicit owner and reviewer approval of this
scaffold, on the named branch, in the phase order above.*
