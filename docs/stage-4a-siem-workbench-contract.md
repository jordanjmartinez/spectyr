# Stage 4A Contract: SIEM Investigation Workbench (Revision 3, final)

**Status: LOCKED. Owner lock recorded 2026-07-19 at pre-lock `main` tip
`37486b1`; the lock applies to Revision 3 (this document). Changes after
the lock require an explicit owner-approved amendment. No code lands from
this contract until its implementation scaffold is approved
(scaffold -> approve -> implement).**

**Post-lock amendments (owner-approved 2026-07-19, recorded at Phase 2
acceptance):**

- **Erratum E1 (event-type counts):** Sections 10.1 and 11 say "30" event
  types. The binding definition is the data-derived, payload-bounded
  catalog measured at implementation Phase 2.2: **29 authored types** (the
  inventory's own Section 4.2/16.3 table in fact lists 29) **plus 12
  background-template-only types** (`4634, 4647, 4648, 4672, 4688, 4768,
  ALLOWED, DNSQuery, ImageLoaded, NXDOMAIN, ProcessTerminate,
  SESSION_END`) **= 41 queryable types**. The catalog is built from
  repository data at boot; the literal "30" is an erratum, not a cap.
- **GD-5a (unquoted-value lexical rules, retroactively ratified as a
  GD-5-adjacent grammar completion):** an unquoted FILTERS value may not
  be a bare reserved word (`and`, `or`, `not`, `contains` -- quote it to
  match it literally), and unquoted values end at whitespace or at any of
  `" ' = ! | *` -- values containing those characters must be quoted.
  These rules MUST surface in the player-facing query help: the Phase 4
  workbench empty-state/hint copy and the Phase 8 Docs-page pass.
- **Amendment E2 (pre-seal scope determinism; narrow, owner-authorized at
  the Phase 3 review):** the snapshot identity gains
  `resolved_scope_hosts: [<hostname strings>]` -- the incident
  participant-host set RESOLVED AT EXECUTION, sorted and deduplicated;
  `[]` for Session-wide (which carries no implicit hostname constraint).
  Rationale: a pre-seal incident's observable host set can grow, and
  identifying scope only by the opaque incident id made replay re-resolve
  the grown set, breaking byte-identical replay and corrupting the
  new-count baseline with sub-cutoff background events of newly joined
  hosts. The frozen list governs original-snapshot reconstruction and
  token replay; the prospective Refresh side of new-count and any actual
  Refresh resolve the incident's CURRENT observable set and freeze it
  into the new identity. The hostnames are observable at execution (no
  answer-key or grading disclosure); the token MAC covers the field.

Revision 2 incorporated: the owner/reviewer contract review (items 1-10),
seven ratified owner rulings, the completed event-disclosure hotfix
(reconciled), and the factual inspection report on event-shape parity,
triggering-event identity, trigger counts, and background-event determinism.

**Repository baseline:** `main` at Stage 3.9 merge `97e3292`, closure docs
`decfb18`, Stage 4A bookkeeping `5cce002`, repository inventory `27a693c`,
event-disclosure hotfix `37486b1`. Repository claims cite the inventory
(`docs/stage-4a-repository-inventory.md`) and the post-hotfix inspection
report by `path:line`.

Decision markers: **[Ratified]** (recorded owner ruling), **[Recommendation]**
(this contract's proposal), **[Owner Decision]** (open), **[Deferred]**.
No owner decisions remain open (Section 20.3). The contract is ready
for the owner's lock; after the lock, changes require an explicit
amendment.

**Changelog from Revision 1:** hotfix reconciled, all pending-reconciliation
language removed, old OD-6 (storyline) closed as removed-by-hotfix; detection
ownership terms corrected (Section 4.2); triggering-evidence descent
redesigned after the id-linkage premise failed on inspection (Sections 12-13,
OD-9); explicit `event_seq` introduced (Section 7, replacing implicit pool
position); new-count rebound to a snapshot token with semantics as open OD-6
(Section 8); OR-pivot composition restricted to conjunction-only append
(Sections 11, 13); silent scope fallback removed (Section 6); Option A
re-costed against the no-seed finding and split into A1/A2 (Section 9);
citations hardened with exact page titles (Section 3); field-presence
discriminators found in the post-hotfix shape, amendment proposed as OD-10
(Sections 10, 17).

**Changelog from Revision 2 (finalization):** sort removed from snapshot
identity with a canonical server order defined and client sorting made
view state; snapshot-token security specified (session-bound,
tamper-evident, dies with the session, neutral failure); the A1
simulation epoch unified with `world["started_at"]` so Endpoints, event
occurrence times, the action clock, and TIMEFRAME share one timeline,
with the executive wording adjusted accordingly; detection trigger cards
framed as rule-evidence summaries and the descent control renamed Open
Evidence Timeline; OD-6, OD-9, OD-10 ratified (R16-R18); zero owner
decisions remain open.

---

## 1. Executive product definition

The SIEM Investigation Workbench is the single raw-evidence surface of
Spectyr. It replaces the current SIEM tab's auto-scrolling feed with an
analyst-driven query tool: the player asks questions in LCQL, receives a
stable result snapshot that never moves while they read it, inspects
individual events, and pivots on what they find, with every pivot writing
visible, valid LCQL. It teaches the investigation habits of real SOC work
(query, freeze, inspect, pivot, correlate across hosts) on a coherent
simulated timeline with deterministic within-session snapshot behavior, without ever disclosing grading, answer keys, or
scenario internals.

The player problem, in the owner's words from the Stage 3.9 audit: the
current SIEM "presents a noisy firehose rather than an investigation
workspace"; rows insert and reorder while the analyst reads; alerts,
incidents, detections, and raw events do not form a clear hierarchy. The
workbench fixes all three: stable snapshots kill the firehose, the object
model fixes the hierarchy, and scoped descent connects incidents and
detections to their evidence.

**The intended investigation loop:**

```
Incident
  -> Open Evidence Timeline (descent opens the workbench with a generated LCQL query)
  -> run or edit LCQL
  -> inspect a stable result snapshot
  -> open an event in the inspector
  -> pivot on a field or entity
  -> generate a new valid LCQL query
  -> continue across hosts and evidence
  -> return to the incident decision (classify, disposition, respond, submit)
```

The workbench is an evidence surface, never a grading surface. Nothing in it
changes the submission boundary, readiness, sealing, or scoring, and nothing
in it may disclose correctness before submission.

---

## 2. Current defects and required foundations

Classes: **SP** immediate safety prerequisite, **AF** architectural
foundation, **WF** workbench feature, **DC** deferred capability.

| # | Defect / gap | Class / disposition |
|---|---|---|
| D1 | Legacy event APIs disclosed answer fields (`label`, `category`, `scenario_id`, `threat_pattern`, `storyline`, `level_name`, `alert_id`) with no server sanitization (inventory 3.1-3.2). | SP, **resolved** by hotfix `37486b1`: whitelist-only `sanitize_feed_event` (detection_templates.py:319-327) on `/api/fake-events`; `/api/grouped-alerts` reduced to readiness + stats. Guards: `test_event_disclosure.py` (five named tests, Section 17). |
| D2 | SIEM rows mutate under the analyst: 2s poll, pool re-reversed, no refresh, no indicator, no snapshot (inventory 8). | WF, replaced by Sections 6-8. |
| D3 | Event content timestamps are wall-clock-at-drip (app.py:2399); the "frozen scenario clock" claimed by `siemUtils.js:73` and the grammar notes does not exist for events (inventory 6). | AF, Section 9. **[Ratified]** Option A direction; A1 now, A2 deferred. |
| D4 | LCQL unimplemented; the live search and its placeholder are Splunk-style drift (inventory 9, Siem.jsx:140). | AF/WF, Sections 5 and 11. |
| D5 | SOC Queue's rendered SIEM shows the full stream; the trigger-only filter lives in the unrendered grouped-alerts payload (inventory 2.5). | AF. **[Ratified]** uniform visibility, Section 15. |
| D6 | Event identity: uuid4, stable within session, not across sessions; no identity or sequence field, no identity test (inventory 11; inspection report D). | AF: `event_seq` introduced (Section 7); cross-session identity DC. |
| D7 | Attack and normal events have divergent internal field shapes; the hotfix whitelist unifies the serializer but yields a union shape with population-dependent presence: `user_account` serializes only on authored events (background `user` is dropped), top-level `protocol` only on background events (inspection report A). Presence is therefore an attack/background discriminator. | AF, **new finding this revision**. Amendment ratified as **[R18, OD-10]**, Sections 10 and 17. |
| D8 | No incident-scoped raw-event read exists (inventory 7). | WF, Sections 14 and 17. |
| D9 | Full-pool poll every 2s, O(n) per call (inventory 10). | WF, removed by the snapshot model; volumes need no pagination in v1. |
| D10 | `CampaignProgress` renders un-adapted totals (inventory 2.4). | **[Ratified]** separate micro-fix outside this stage (OD-7 ruling). |
| D11 | Detections' triggering events serialize no event id, by an enforced test invariant; ambient detections' triggers are synthetic and never enter the pool (inspection report B). | AF constraint that shapes descent design (Sections 12-13, OD-9). |

---

## 3. Reference-pattern matrix

Constraint keys: **DET** deterministic simulation, **SW** session/world
model, **SG** submission-gated gameplay, **FT** frozen-time goals, **GR**
pinned LCQL grammar. Citations carry the exact official page title.

| # | Pattern (source) | Primary citation (title, URL) | Spectyr decision | Verdict, reason |
|---|---|---|---|---|
| 1 | Incidents are aggregations of alert evidence generated by analytics rules; incidents inherit the alerts' entities and properties (Microsoft Sentinel) | "Investigate Microsoft Sentinel incidents in depth in the Azure portal", learn.microsoft.com/en-us/azure/sentinel/investigate-incidents | Event -> Detection -> Incident three-tier hierarchy | **Adopt.** Maps onto existing engine objects; resolves the audit's hierarchy confusion. (SG) |
| 2 | Analysts add alerts to or remove them from incidents, refining scope during investigation (Sentinel) | "Relate alerts to incidents in Microsoft Sentinel in the Azure portal", learn.microsoft.com/en-us/azure/sentinel/relate-alerts-to-incidents | Sealed roster, fixed ownership, no membership editing | **Reject.** Grading requires a fixed roster (3.9A); divergence stated openly. (SG) |
| 3 | From an incident's Evidence, selecting Events opens a pre-scoped Logs panel without leaving the incident (Sentinel) | "Investigate Microsoft Sentinel incidents in depth in the Azure portal", learn.microsoft.com/en-us/azure/sentinel/investigate-incidents | Descent opens the workbench with a generated, visible LCQL query (host-anchored evidence timeline, Section 13) | **Adapt.** The loop's entry point; observable-only; the generated query honestly describes the result set. (SG, GR) |
| 4 | A search creates a job whose finished results are a fixed set, retrieved via count and offset (Splunk) | "Run searches and display results", dev.splunk.com/view/SP-CAAAEFA | Deterministic query snapshots with a precise identity tuple and an opaque session-local token; no job objects, TTLs, or job management | **Adapt.** Append-only pool plus non-mutating reads make within-session snapshots exactly reproducible; job lifecycle machinery is irrelevant single-player complexity. (DET, SW) |
| 5 | Streaming log views are a separate opt-in mode; the stream is not persisted and a new search clears it (Datadog) | "Live Tail", docs.datadoghq.com/logs/explorer/live_tail/ (supporting page: "Containers Explorer", docs.datadoghq.com/containers/monitoring/containers_explorer/, which carries the not-persisted, cleared-on-new-search language) | No live tail, no auto-inserting rows, anywhere in the workbench | **Reject.** Auto-insertion is the firehose defect this stage kills. (SW) |
| 6 | Queries execute when the analyst clicks refresh or presses Enter (Kibana Discover) | "Explore fields and data with Discover", elastic.co/docs/explore-analyze/discover/discover-get-started | Explicit Run Query and Refresh; each creates a new snapshot | **Adopt.** Analyst-initiated execution is the foundation of stable results. (DET) |
| 7 | The sidebar lists available fields; selecting one shows its top values with record counts (Kibana Discover) | "Explore fields and data with Discover", elastic.co/docs/explore-analyze/discover/discover-get-started | Field sidebar from the sanitized catalog, top values per current snapshot | **Adopt.** Sized to the 30-type schema; bounded by the sanitization contract. (SG) |
| 8 | Expanding a row shows every field with per-field filter actions, plus the documents before and after it (Kibana Discover) | "Explore fields and data with Discover", elastic.co/docs/explore-analyze/discover/discover-get-started | Inspector as a lens over the sanitized event; surrounding-events emits a generated LCQL query | **Adapt.** Surrounding-documents becomes a grammar-conformant query. (GR, SG) |
| 9 | Investigation proceeds by pivoting between related entities, a user to their asset to a domain (Google SecOps / Chronicle) | "Understand data availability for search", docs.cloud.google.com/chronicle/docs/investigation/expected-data-availability-for-search | Entity chips pivot across hosts via SENSOR_SELECTOR broadening plus FILTERS | **Adapt.** Entity movement without new endpoint families; observable-only scope. (SG) |
| 10 | Pivot refinement generates the query text itself, visible and reusable (Chronicle) | "Conduct a search for entity context data", docs.cloud.google.com/chronicle/docs/investigation/entity-context-in-search | Every pivot writes a visible, editable, parser-valid LCQL string | **Adopt, elevated to a teaching goal.** One generation choke point plus a parse-validity gate. (GR) |
| 11 | A graphical investigation tool diagrams entities connected to the alert and further resources (Sentinel) | "Investigate incidents with Microsoft Sentinel (legacy)", learn.microsoft.com/en-us/azure/sentinel/investigate-cases | No graph UI | **Reject at current scale** (6 hosts, single-digit entities; inventory 10). Revisit only if multi-host content changes the scale. (SW) |
| 12 | Historical search vs a distinct real-time mode; result sets retrieved when the search finishes (Splunk) | "Run searches and display results", dev.splunk.com/view/SP-CAAAEFA | Exactly one workbench mode: historical query over the visible pool | **Adopt.** One mode, one semantics. (DET) |

No other product's information architecture or query syntax is copied.

---

## 4. Object model

### 4.1 Event

- **Produced:** written by the per-session `log_writer`: authored
  attack-chain and supplemental events at drip, interleaved with
  `generate_normal_event()` background traffic, ~2-3 normals per attack
  event at a ~1s tick (inventory 5).
- **Identity:** `id` (uuid4), minted once at write; stable within the
  session across polling, sorting, and scoping; not stable across sessions
  (inventory 11). Revision 2 adds `event_seq` (Section 7): a server-assigned
  monotonic within-session visibility-order identity. Two fields, two jobs:
  `id` is row identity, `event_seq` is arrival order and the snapshot
  cutoff dimension. Neither is cross-session identity.
- **Lifecycle:** append-only; never edited or deleted; response actions
  never alter historical evidence
  (test_actions.py::test_api_immutable_evidence_after_kill).
- **Relationships:** an authored event's scenario linkage is server-side
  only and never serialized. Detections reference triggering events
  server-side; that linkage is stripped at serialization by enforced tests
  (inspection report B; test_detections.py:123).
- **Presented by:** the workbench, the endpoint timeline, and detection
  detail (whitelisted triggering-event content only, without ids).
- **Observable before submission:** every sanitized field of every visible
  event. **Never observable:** scenario linkage, any answer field, or any
  population discriminator (Sections 10, 17; OD-10 closes the two found).

### 4.2 Detection

Corrected terminology this revision. Four distinct concepts, used
consistently everywhere in this contract:

- **Ownership:** a scenario detection belongs to exactly one incident. An
  ambient-benign detection is session-level and belongs to no incident.
- **Roster inclusion (readiness-relevant):** an incident's sealed roster =
  its owned scenario detections **plus** ambient detections on the
  incident's observable hosts (repository truth: `_incident_observable_scope`,
  app.py:3538-3586; inventory 7). An ambient detection can therefore sit in
  multiple incidents' rosters simultaneously. **Ambient detections DO gate
  readiness**, exactly as Stage 3.9 built and tested it; one disposition of
  an ambient detection satisfies every roster containing it. Stage 4 changes
  none of this.
- **Scope visibility:** which detections render under an incident's scope
  toggle. Equals roster inclusion today; visibility never implies ownership.
- **Membership mutability:** none after sealing, for any kind (3.9A
  invariants, inventory 12).

Other properties: produced once at drip (app.py:2478-2500); opaque
stable-key identity distinct from event and incident identity; lifecycle
open -> promoted or dismissed; the field set is deliberately identical
across kinds (test_detection_indistinguishability.py), an invariant this
contract's descent design must and does preserve (Section 13, OD-9).
Observable before submission: existence, entity references, triggering-event
content, own dispositions; never disposition correctness.

### 4.3 Incident

Unchanged from Revision 1: opaque `INC-####` identity; lifecycle arrival ->
sealed -> ready -> submitted (immutable grade); owns a sealed roster per
4.2; observable scope from participant attribution only, structurally
guarded; presented by Dashboard, Incidents workspace, and the workbench only
as a scope filter and descent origin. Sentinel-style membership editing is
rejected **[Ratified]** and the divergence is stated on the Docs page as a
deliberate training constraint.

---

## 5. Fate of the old Events surface

**[Ratified, OD-2]:** absorb. The SIEM tab becomes the workbench; the
player-facing name remains **SIEM**.

Post-hotfix repository truth adjusts the migration picture: `/api/fake-events`
is already whitelist-sanitized (12 fields) and `/api/grouped-alerts` already
reduced to readiness fields plus stats (hotfix `37486b1`), so the retirement
path starts from clean payloads.

Migration implications:

- **Navigation:** tab count unchanged; the internal legacy `grouped` key for
  the Incidents tab is renamed in the same pass (C6 label hygiene).
- **APIs:** the workbench queries exclusively through the new query read
  (Section 17). The SIEM's 2s `/api/fake-events` poll disappears with the
  feed; the endpoint is retained only for any residual consumer, then
  retired. `Dashboard.jsx`'s session-existence check moves to
  `/api/game-state`. `grouped-alerts` retires once its stats consumer
  (IncidentDashboard) moves to a stats read or fields on `/api/incidents`.
- **Components:** `Siem.jsx` becomes the workbench shell; `parseEventQuery`,
  the Splunk-style placeholder, and the pool-derived dropdown filters are
  deleted **[Ratified, OD-8]**; `SiemTable` and `SiemCards` are adapted as
  snapshot renderers; `sanitizeEvent` remains a display helper over
  already-sanitized payloads.
- **Tests:** superseded `siem.test.js` cases are replaced in the same
  concern commit that removes the code they test; `test_event_disclosure.py`
  is retargeted, not weakened, when the query read becomes the primary
  event path (Section 18).
- **Docs:** the Docs page's SIEM description is rewritten; the two "frozen
  scenario clock" claims are corrected per Section 9; the log_writer
  docstring interval error (C7) is fixed in the same doc pass.

---

## 6. Workbench layout

Text wireframe (deliverable 2). The state definitions bind; the wireframe
illustrates.

```
+----------------------------------------------------------------------+
| [Scope: Session-wide v]  [TIMEFRAME v]  LCQL query bar    [Run Query]|
|  (or: Focused on INC-4056  [x])                                      |
+----------------------------------------------------------------------+
| Snapshot: 142 events - as of seq #311 - 14:32 sim   [8 new] [Refresh]|
+-------------------+--------------------------------------------------+
| FIELDS            |  RESULTS (stable snapshot table / cards toggle)  |
|  event_type (12)  |  time      type          host       account  ... |
|   ProcessCreate 9 |  14:31:58  ProcessCreate ACME-WS10  spatel       |
|   4625          7 |  14:31:44  QUERY         ACME-WS10  -            |
|  hostname (4)     |  ...                                             |
|  user_account (6) +--------------------------------------------------+
|  source (5)       |  INSPECTOR (expanded event)                      |
|  ...              |   field        value            [==] [!=] [pivot]|
|                   |   raw message view                               |
|                   |   [Surrounding events]  [Pivot: host] [account]  |
+-------------------+--------------------------------------------------+
```

Per-pane states (empty, loading, active, error, no-results,
telemetry-arriving, sealing boundary, submitted incident where relevant):

**Scope control.** Session-wide, or one active incident chip. Sealing
boundary: an unsealed scoped incident shows the standard "Incident telemetry
is still loading." line beside the snapshot status; scope covers the
participants known so far. Submitted incident: remains selectable
(evidence stays reviewable); no grading here ever. **Error (revised per
review item 8):** a failed incident-scope read keeps the selected chip,
shows "Incident scope could not be loaded.", preserves the prior snapshot
untouched, and disables Run Query until the scope read succeeds on retry or
the player explicitly selects Session-wide. Scope never broadens silently.

**Query bar.** Empty: placeholder is one canonical conforming LCQL example,
never a key=value form. Loading: read-only during execution. Active: the
current snapshot's canonical query. Error: parser errors render inline with
position and reason; the prior snapshot stays. No-results: query retained;
results pane shows its no-results state.

**TIMEFRAME control.** A dropdown of grammar TIMEFRAME tokens that edits the
query text's first segment in place; control and text can never disagree.
Default `1h`.

**Run Query / Refresh.** Run executes the bar's text as a new snapshot.
Refresh re-executes the displayed snapshot's definition now (token-bound,
Sections 7-8). Both disabled during execution; failures leave the prior
snapshot intact.

**Snapshot status.** Result count, cutoff (`seq #N` plus the latest visible
occurrence time), scope, and the new-events indicator. Empty: "Run a query
to begin." Telemetry-arriving: only the indicator changes.

**New-events indicator.** Section 8. Zero state hidden.

**Field sidebar.** Catalog fields present in the current snapshot, top 5
values with counts computed over the snapshot only. Empty until a snapshot
exists; no-results snapshot shows "No fields to summarize."; value clicks
route through the pivot generator under the conjunction-only rule
(Section 13).

**Results table/cards.** The stable snapshot; rows never insert, remove, or
reorder while displayed. Empty: a short hint with two valid example
queries. No-results: "0 events match" plus the echoed query. Loading: prior
snapshot visible until atomic replacement. Column sorting is client-side view
state over the frozen row set: it issues no request, changes no token,
and is the one deliberate movement the no-movement rule permits. Row
selection persists by `id` across column sorts within a snapshot.

**Inspector.** Section 12; closing preserves selection.

---

## 7. Stable query-result snapshots

**Foundation introduced this revision: `event_seq`.** A server-assigned
monotonic integer, assigned exactly once when an event enters the visible
pool, unique and strictly increasing within the session, stable across
reads, sorting, and scope, reset only with the session, and never a
cross-session identity. It is serialized on every event (an explicit,
documented extension of the hotfix whitelist under the disclosure rule;
Section 17) and shown in the inspector as "arrived as event #N". `id`
remains row identity; `event_seq` is visibility-order identity. Array
position is thereby retired as an implicit stand-in.

**Snapshot identity tuple:**

1. Canonical query text (Section 11 normalization).
2. Scope: `session` or one opaque incident id.
3. Resolved absolute occurrence-time range (TIMEFRAME resolved at
   execution; Section 9 defines occurrence time).
4. Visibility cutoff: the maximum `event_seq` at execution.
5. Paging: none in v1 (volumes per inventory 10); client display
   pagination does not enter identity.

**Sort is not part of identity (finalization item 1).** The query read
returns one canonical deterministic order: occurrence timestamp
descending, tie-broken by `event_seq` descending, then `id`. Column
sorting in the UI is client-side view state over the frozen row set; it
never refetches, never mints a token, and never alters identity. The
no-row-movement guarantee prohibits automatic movement; deliberate
analyst sorting of the frozen set is allowed.

Executing a query returns the identity, the rows, and an **opaque
session-local snapshot token** naming that immutable executed definition
(review item 5). The token is not a server-side job: it identifies, it does
not store; re-derivation from the identity is equivalent.

**Token security (finalization item 2):** the token is opaque,
session-bound, and tamper-evident: an HMAC over the identity under a
secret minted per session and held only in that session's memory. Reset,
Practice Another, and backend restart therefore invalidate every token
automatically, because the secret dies with the session. Altered,
expired, and foreign tokens all fail with the same neutral unknown-token
response, indistinguishable from one another, matching the actions-API
convention. No server-side search-job lifecycle exists.

**Guarantees:**

- A snapshot never inserts, removes, or reorders rows while displayed.
- **Within-session deterministic replay:** re-executing an identical
  identity in the same session returns byte-identical rows in the
  canonical order. Testable; Section 18.
- **Cross-session replay is explicitly not promised.** Ids and (until A2)
  occurrence times differ across sessions (inventory 11; inspection report
  D). **[Deferred]** with cross-session identity.
- Direct tests for the foundation replace indirect citations: event pool
  append-only, `event_seq` uniqueness and monotonicity, read-no-mutation on
  the query routes (Section 18).

**Behaviors:** Refresh creates a new snapshot from the token's definition
with TIMEFRAME re-resolved and a new cutoff; replacement is atomic; exactly
one live snapshot, no history in v1 (the query text is the recoverable
artifact). Selection persists across refresh when the inspected `id`
survives; otherwise the inspector closes with a one-line notice. Sealing
never alters an existing snapshot.

---

## 8. New-events indicator

**Binding (review item 5):** the count request references the executed
snapshot token, never the query bar's editable text. `GET
/api/events/query/new-count?token=...` evaluates against the immutable
executed definition.

**Semantics [Ratified, OD-6]: refresh-now.** Two meanings were
weighed; the record keeps both:

- **Strict snapshot-window count:** newly visible events inside the
  snapshot's original resolved absolute range. Honest to the executed
  window; goes quiet as sim time moves past a relative window's end, which
  reads as "nothing new" while relevant matching events arrive.
- **Refresh-now count (ratified):** the number of rows that pressing
  Refresh now would add: evaluate the token's canonical query and scope
  with TIMEFRAME re-resolved at count time, over events up to the current
  maximum `event_seq`, and count rows absent from the displayed snapshot
  (by `id`). This matches what "8 new matching events" means to an analyst,
  and it is exactly the Refresh contract, previewed.

Either way: the displayed snapshot never changes; `pool_growth` (current
max `event_seq` minus the snapshot cutoff) is reported alongside as the
all-events counter.

Behavior table (under the ratified semantics):

| Situation | Indicator |
|---|---|
| Telemetry drips | Count updates passively via the token read; snapshot untouched. |
| Scoped incident seals | No special behavior; the count settles once the chain and trailing normals finish. |
| Query text edited, not run | Indicator stays bound to the token, visually de-emphasized as describing the last run. |
| Scope or TIMEFRAME changed, not run | Same as above; a new run mints a new token. |
| Refresh pressed | New snapshot, new token, indicator resets. |
| No new matching rows | Hidden. |

---

## 9. Time model

**Repository truth, updated by inspection report D:** there is no seed
anywhere in product code. Template selection, employee choice, authored gap
ranges, interleave gaps, ids, and the INC id all draw from the unseeded
global RNG, OS entropy, or wall clock; `world["started_at"]` is frozen (it
does not advance) but is wall-clock-set and therefore not reproducible.
"Same-seed replay" is currently a category error: no seed input exists to
hold equal. Revision 1's Option A cost estimate was wrong accordingly.

The two concepts stand regardless of option: **occurrence time** (the
event's timestamp; what TIMEFRAME filters) and **visibility order**
(`event_seq`; the snapshot cutoff dimension; never filtered by TIMEFRAME).

**Option A [Ratified direction, OD-1], now two tiers:**

- **A1, deterministic simulation epoch and coherent occurrence times
  (ratified for this stage):** define a simulation epoch as a stable digest
  of the session id (the same stable-key practice already used for
  detection ids and world times, detection_templates.py:103-136). Authored
  events: occurrence time = epoch + deterministic per-queue-position
  spacing + authored offsets, with authored `[lo, hi]` gap ranges resolved
  by a dedicated per-session RNG stream seeded from the epoch digest (so
  times are a pure function of session identity, not of wall clock or the
  shared global RNG). Background events: occurrence time derived from the
  epoch and `event_seq` spacing, replacing wall-clock-minus-random-backdate.
  **The same epoch becomes `world["started_at"]` (finalization item 3):**
  Endpoints' frozen world, the response-action clock, event occurrence
  times, and TIMEFRAME thereby share one coherent timeline. The exact
  epoch derivation (a fixed canonical simulation datetime versus a
  digest-derived one) is a scaffold-level detail constrained to be
  wall-clock-free and deterministic given session identity;
  `snapshot_generator`'s frozen-time guard is re-verified against the
  shared epoch in the same change. Full runtime or cross-run determinism
  is not claimed at this tier; A2 remains deferred.
  Result: occurrence times are internally coherent, sim-anchored, aligned
  with the frozen world snapshot the player sees in Endpoints, and
  deterministic given the session. The two "frozen scenario clock" doc
  claims become true. Cross-run equality is NOT claimed at this tier.
- **A2, full same-seed replay (deferred):** introduce an explicit session
  seed input and route all product randomness (template and employee
  selection, gaps, interleave, INC id) through a per-session seeded RNG.
  Only then does "same seed, identical occurrence timestamps and content"
  become a truthful cross-run guarantee. Costed honestly: it touches the
  writer loop, both generators, intake, and needs its own replay test
  harness; it is pulled forward only if a future feature needs it.

Effects under A1: TIMEFRAME windows are reproducible within a session and
meaningful against the sim timeline; snapshot identity's resolved ranges
are session-deterministic; sim-now remains the pool anchor (maximum visible
occurrence timestamp), continuous with today's preset behavior; scenario
YAML untouched; parity unaffected (it ignores timestamps); one new
determinism test (recompute expected times from epoch, offsets, and the
seeded gap stream; compare) replaces the impossible same-seed cross-run
test.

**Option B** (wall-clock retained, docs corrected) remains documented for
the record and remains inferior: it codifies the mixed-clock seam and
falsifies the pinned TIMEFRAME semantics. The ratified direction is A.

Boundary note: A1 crosses the Stage 3.9 event-generation freeze; the
ratification above is the explicit owner authorization that the freeze
requires. Content byte-parity except timestamps is preserved by
construction and re-proven by the existing parity suite.

---

## 10. Searchable field catalog

Bounded by the server sanitization contract: **no field outside the
sanitized payload is searchable, listable, or inspectable.** The exact
serialized whitelist, from hotfix `37486b1` (inspection report A):

```
id, timestamp, event_type, source_type, severity, hostname, source_ip,
destination_ip, user_account, message, key_value_pairs, protocol
```

plus, per Section 7, `event_seq` as this contract's one explicit whitelist
extension. Null and empty values are omitted per field (`id` always
present; detection_templates.py:324-326). Construction is whitelist-only;
unknown internal fields are dropped by omission and tested
(test_event_disclosure.py::test_fake_events_unknown_future_field_does_not_pass_through).

**The presence-discriminator finding and its amendment [Ratified,
OD-10].** The hotfix applied one whitelist to two divergent internal
shapes, producing a union with population-dependent presence: background
events' internal `user` is dropped, so a serialized `user_account` marks an
event as authored; `protocol` serializes top-level only on background
events, marking the converse (inspection report A.3-A.4). Both are
structural attack/background discriminators, and telling attack from noise
is the game. Ratified amendment, an explicit revision of the hotfix
whitelist under the disclosure rule:

- The serializer maps internal `user` -> `user_account`, so both
  populations carry the canonical account field whenever account data
  exists.
- `protocol` is removed from the top-level whitelist; background events'
  protocol serializes inside `key_value_pairs`, where authored network
  events already carry it. One uniform placement.
- `test_event_disclosure.py` is updated in the same change; a new
  shape-parity test asserts no whitelist field's top-level presence is
  population-exclusive (Section 18).

**Scope rule, stated plainly:** the no-discriminator invariant covers field
shape and presence, which are serializer artifacts. Content-level
statistical patterns (severity distributions, event-type mixes) are
scenario realism, owned by scenario design, and are out of the serializer's
scope. Field presence that varies by event type identically for both
populations (destination_ip on network events) is type-driven and
acceptable.

### 10.1 Canonical common fields (top level)

`id` (opaque event id; searchable, enabling exact-event queries),
`event_seq` (arrival order; inspector display and cutoff; searchable is
unnecessary and it is excluded from FILTERS in v1), `timestamp` (occurrence
time), `event_type` (30 types; Erratum E1: 41 data-derived), `source_type`
(the 8 families), `severity`,
`hostname`, `source_ip`, `destination_ip` (event-type-dependent),
`user_account` (canonical account field per OD-10), `message`.

### 10.2 Family-specific fields (inside `key_value_pairs`)

Searchable by bare key name, resolved case-insensitively (GD-2). The
authorized key set is the sanitized union of inventory appendix 16.4,
which is raw-log payload content by design (inspection report A.3).
Representative: Sysmon `command_line`, `image`, `parent_image`,
`target_filename`, `target_object`; Windows Security `account_name`,
`logon_type`, `status`, `share_name`; Proxy `url`, `url_category`,
`http_method`; DNS `query`, `query_type`; Firewall `action`, `dest_port`,
`rule`; Azure AD `UserPrincipalName`, `RiskLevel`, `IPAddress`,
`Location`; Veeam `job_name`; Defender `old_value`, `new_value`; and
`protocol` (uniform kvp placement per OD-10).

Resolution order: canonical top-level name first, then kvp key. Missing-field
predicates evaluate false for all four operators (GD-5). Aliases: none; the
old client alias table is superseded. Inspector-only fields: none beyond
`event_seq` display; one lens, one truth. Never exposed: every internal
field outside the whitelist, and any population discriminator (OD-10).

### 10.3 Field sidebar

Fields present in the current snapshot, common-then-family, top 5 values
with counts computed over the snapshot only (never the full pool). Value
clicks route through the pivot generator under the conjunction-only rule.
Type-aware rendering: datetimes localized, byte counts humanized, all else
literal.

---

## 11. LCQL contract

**Pinned and unchanged [Ratified]:**

```
TIMEFRAME | SENSOR_SELECTOR | EVENT_TYPE | FILTERS
```

Operators `contains`, `not contains`, `==`, `!=`, `and`, `or`; double
quotes case-insensitive, single quotes case-sensitive; projection and
GROUP BY deferred; a real tokenizer and parser, deterministic, unit-tested
before any UI (grammar notes; inventory 9).

**Grammar completions [Ratified, OD-5], with one restriction from review
item 7:**

- **GD-1:** unquoted values match case-insensitively.
- **GD-2:** field names are bare identifiers `[A-Za-z0-9_]+`, resolved
  case-insensitively against the catalog; unknown field, sensor, or event
  type is a parse-time error with position and near-match suggestions,
  never a silent empty result.
- **GD-3:** `and` binds tighter than `or`; parentheses deferred.
- **GD-4:** `*` is the any token for SENSOR_SELECTOR, EVENT_TYPE, and
  FILTERS; `all` for TIMEFRAME; all four segments always present; an empty
  segment is a parse error.
- **GD-5:** string-typed comparison everywhere in v1; missing-field
  predicates evaluate false; escaping inside quotes is backslash (`\"`,
  `\'`, `\\`).
- **OR-composition restriction (ratified with OD-5):** programmatic
  refinement (sidebar clicks, per-field `==`/`!=` actions) appends
  `and <predicate>` only when the current FILTERS AST is conjunction-only.
  If the AST contains `or`, the generator emits a fresh standalone query
  for the clicked predicate and shows a one-line notice ("Started a new
  query; the previous one mixed or-conditions."). A UI click never emits a
  query whose precedence surprises (`A or B` + `and C` would mean
  `A or (B and C)`); the restriction guarantees it cannot.

**Defined v1 semantics:** TIMEFRAME tokens `15m | 1h | 4h | 12h | 24h |
all`, relative windows resolving against sim-now = the maximum visible
occurrence timestamp, then freezing into the snapshot identity;
SENSOR_SELECTOR = a source family (`Sysmon`, `Windows Security`, `Proxy`,
`DNS`, `Firewall`, `Azure AD`, `Veeam`, `Defender`), a known hostname, or
`*`, matched case-insensitively as one trimmed token, spaces permitted
unquoted; EVENT_TYPE = one of the catalog types (Erratum E1: the
data-derived union, 41 at measurement) or `*`; FILTERS = predicates
joined by `and`/`or` under GD-3, or `*`. `==`/`!=` whole-string,
`contains`/`not contains` substring. Canonical formatting: single spaces
around `|` and operators, operators lowercased, field names in catalog
case, quoted values byte-preserved, idempotent
(`canonical(canonical(q)) == canonical(q)`, tested). Parse errors report
position and reason and execute nothing.

**Valid examples:**

```
1h | Sysmon | ProcessCreate | command_line contains "powershell"
24h | Windows Security | 4625 | user_account == "spatel" and source_ip contains "10.0."
all | ACME-WS10 | * | *
15m | Proxy | HTTP_CONNECT | url contains 'Login.Microsoft'
4h | * | QUERY | query contains "telemetry-sync" or query contains "cdn-edge"
```

**INVALID examples (labeled):**

```
source_ip=10.0.1.24 event_type=4625     INVALID: Splunk-style key=value (the retired placeholder, Siem.jsx:140)
Sysmon | ProcessCreate                   INVALID: two segments; four required
1h | Sysmon | ProcessCreate |            INVALID: empty FILTERS; use *
1h | Sysmon | ProcessCreate | x = "y"    INVALID: single = is not an operator
```

**Non-expressible in v1, flagged, deferred:** parentheses, field-existence
predicates, numeric and range comparison, absolute time windows, windowed
surrounding-events.

---

## 12. Event inspector

Shows, in order: identity (occurrence timestamp, event `id`, "arrived as
event #<event_seq>"); family and event_type with the family color;
canonical commons (hostname, user_account, source_ip, destination_ip,
severity); every sanitized kvp for the event, type-aware, catalog order;
the raw message and the sanitized raw JSON view.

- **Detection linkage:** none on the event payload, by enforced invariant
  (inspection report B; test_detections.py:123). When the workbench was
  entered by descent, a breadcrumb chip ("from DET-...") is UI state only,
  for navigation back; it implies nothing about any row.
- **Incident relationship:** none per event, ever. Incident scope is a
  participant filter (Section 14), never a membership tag. A per-row
  attack/normal or scenario marker of any kind is prohibited; OD-10 exists
  because even field presence must honor this.

**Per-field actions**, each through the pivot generator under the
conjunction-only rule: add `==` filter; add `!=` filter; pivot to host,
user_account, process, file, IP, domain/url; Surrounding events.

**States:** brief loading skeleton (data is local); malformed events render
their sanitized raw JSON with a notice; no sealing or submission special
cases (the inspector is a pure lens over one visible sanitized object).

---

## 13. Field-driven pivots and descent

**Teaching goal:** clicks teach LCQL by showing the syntax they generate.
Every pivot writes a visible, editable, parser-valid query and executes it
as a new snapshot. `<tf>` is the current snapshot's TIMEFRAME token.

| Pivot | Generated query |
|---|---|
| Host `H` | `<tf> \| H \| * \| *` |
| Account `A` | `<tf> \| * \| * \| user_account == "A"` |
| Process image `P` | `<tf> \| * \| * \| image == "P"` |
| Process name (contains) | `<tf> \| * \| ProcessCreate \| image contains "P"` |
| File `F` | `<tf> \| * \| * \| target_filename == "F"` |
| IP `X` | `<tf> \| * \| * \| source_ip == "X" or destination_ip == "X"` |
| Domain/URL `D` (proxy) | `<tf> \| Proxy \| * \| url contains "D"` |
| Domain `D` (dns) | `<tf> \| DNS \| QUERY \| query contains "D"` |
| Event type `T` | `<tf> \| * \| T \| *` |
| Sensor family `S` | `<tf> \| S \| * \| *` |
| Sidebar value `field=V` | conjunction-only append of `and field == "V"`; fresh standalone query when the AST contains `or` (Section 11) |
| Surrounding events (host `H`, event `E`) | `all \| H \| * \| *`, sorted occurrence ascending, viewport centered on `E` |

**Triggering-evidence descent [Ratified, OD-9], redesigned on
repository truth.** Revision 1 assumed detections serialize their
triggering events' ids. Inspection report B falsifies that: ids are
stripped by the serializer, two tests enforce the absence, and ambient
detections' triggers are synthetic dicts that never enter the pool at all.
An id-based descent would therefore require a whitelist amendment, two test
rewrites, minted synthetic ids, and would still leave a permanent
kind-discriminator: post-seal, an ambient detection's id-query returns
empty forever while scenario detections return rows, breaking the
detection-indistinguishability invariant behaviorally.

- **Ratified v1 form (host-anchored, uniform):** descent from any
  detection or from an incident generates the host evidence timeline,
  `all | <entity hostname> | * | *`, sorted occurrence ascending, with a
  banner naming the origin ("Evidence timeline for ACME-WS10, from
  DET-...."). Identical shape for every detection kind, so
  indistinguishability is preserved; fully expressible in the pinned
  grammar; zero serializer or test changes; the query bar honestly
  describes the result set with no hidden dimension. The detection detail
  view already shows the exact triggering-event content inline, so
  precision lives there and context lives in the workbench, a clean
  division of labor. Incident descent uses the incident's participant
  hosts: one host, that host's timeline; several, the scoped session query
  `all | * | * | *` under the incident's scope filter.
  **Naming (finalization item 4):** the descent control is labeled
  **Open Evidence Timeline** (Investigate Host Evidence was the weighed
  alternative). It is never labeled "View Triggering Evidence", because
  the generated query honestly returns the full host timeline, not the
  trigger set.
  **Trigger cards (finalization item 4):** detection trigger cards are
  rule-evidence summaries rendered from the detection instance, not raw
  SIEM result rows; under the current drip model they may appear before
  the corresponding raw events are searchable in the pool (inspection
  report B.6). Aligning detection materialization with raw-event
  visibility is deferred unless separately authorized (Section 19).
- **Deferred alternative (exact-id descent):** enumerated above; pulled
  forward only if the owner accepts its serializer, test, and
  indistinguishability costs as a package.

Trigger-count facts recorded for the register (inspection report C): corpus
maximum 3 triggering events per detection, median 1; even an id-based form
would fit the existing 300-character query cap with ~2x headroom; the cap
stands unchanged.

**Guarantees:** all pivot and descent output flows through one generator; a
permanent test parses every documented form, asserts emitted text equals
the documented shape, covers value escaping, and includes the OR-case fresh-
query fallback (Section 18).

---

## 14. Cross-host investigation

- **Scope broadening:** entity pivots always execute Session-wide, and the
  scope control visibly flips as part of the pivot; a pivot is the player
  deliberately following an entity beyond one case, and constraining it
  silently to incident participants would return misleading zeros. The
  flip is on screen, never a side effect.
- **Returning:** the last focused incident stays as a one-click chip
  ("Back to INC-4056"), re-running the current query under that incident's
  participant scope.
- **Incident scope over events:** an implicit hostname-in-participant-hosts
  constraint from `_incident_observable_scope` (structurally guarded). A
  participant filter, never a membership filter; it cannot mark rows as
  attack rows. Account chips render for pivoting but do not further
  constrain the event filter in v1, since an account acting from an
  out-of-scope host is exactly the lateral movement the player should find.
- **Shared entities:** shared hosts and accounts appear under every
  incident scoping them; ambient detections follow Section 4.2's roster
  rules; ownership never changes.
- **Graph:** rejected at current scale (matrix row 11); entity pivots as
  readable generated queries achieve the investigative movement.

---

## 15. Per-mode evidence visibility

**[Ratified, OD-4]: uniform written-pool visibility in all three modes.**
The single query read enforces one visibility rule; a route-audit test
asserts no mode-specific event endpoint exists. The drip itself is the
evidence pacing, which is exactly the ratified definition of Triggered
Evidence Arrival (observable telemetry becoming available; never
correctness feedback). Consequences: the grouped-alerts trigger branch
retires with its endpoint (Section 5); the five-seed reachability and
fairness guarantees, proven against full visibility, remain valid
unchanged; Guided, SOC Queue, and Hardcore differ through intake, timer,
Check Answer, and failure rules, not through hidden SIEM evidence.
Correctness remains fully submission-gated in every mode.

---

## 16. Default workbench scope

**[Ratified, OD-3]:** default Session-wide; detection or incident descent
opens the relevant incident scope for that entry; thereafter the player's
explicit scope selection persists for the session. Every scope is
observable-only and uses opaque identifiers.

---

## 17. API and security contract

**Post-hotfix baseline (reconciled; hotfix `37486b1`):**

- `GET /api/fake-events`: whitelist-only serialization via
  `sanitize_feed_event` (detection_templates.py:319-327);
  `FEED_EVENT_WHITELIST` = `timestamp, event_type, source_type, severity,
  hostname, source_ip, destination_ip, user_account, message,
  key_value_pairs` + `id, protocol`; null/empty omitted; id forced; dedup
  by id. Guards: `test_event_disclosure.py::
  test_sanitize_feed_event_strips_all_but_whitelist`,
  `::test_generated_background_traffic_is_sanitized`,
  `::test_fake_events_serializes_only_the_whitelist`,
  `::test_fake_events_unknown_future_field_does_not_pass_through`,
  `::test_live_drip_feed_is_clean_across_modes`.
- `GET /api/grouped-alerts`: reduced to per-incident readiness fields
  (`incident_id, detections_sealed, open_detections, submission_ready`)
  plus `stats`; slated for retirement under Section 5.
- Recorded facts: `storyline` removed (no consumer required it); normal
  traffic's internal `scenario_id` exists server-side and never serializes;
  the event `id` is within-session identity only.

**Target workbench contract:**

- `GET /api/events/query` with `q` (LCQL, 300-char cap; the cap was
  re-validated against measured descent needs, inspection report C) and
  `scope` (`session` or opaque incident id).
  - 200: `{ token, identity: { canonical_query, scope,
    resolved_scope_hosts (Amendment E2), resolved_range: {start, end},
    cutoff_seq }, count, rows }` (rows in the Section 7 canonical order;
    sort is client view state).
  - 400 parse failure: `{ error: { position, reason } }`; nothing executes.
  - 404 unknown incident (indistinguishable from foreign, matching the
    actions-API convention).
- `GET /api/events/query/new-count?token=...`: `{ new_count, pool_growth }`
  per Section 8's OD-6 semantics. The token binds the count to the executed
  definition; edited bar text can never influence it.
- Both are reads; reads never mutate and polling never generates, extended
  by direct test to these routes.

**Security properties, all test-enforced:**

- Explicit whitelist construction; no passthrough-then-delete; unknown
  future fields absent by omission (existing hotfix test, retargeted to
  the query read).
- Serialized fields: the hotfix whitelist, amended by exactly two explicit,
  documented changes: `event_seq` added (Section 7) and the OD-10 shape
  amendment (`user` -> `user_account` mapping; `protocol` relocated to
  kvp). Every serialized-field change in Stage 4 is disclosed in the
  implementation report per the standing rule.
- No scenario ids, categories, labels, answer or grading fields, and **no
  population discriminator of any kind, including field presence** (OD-10;
  shape-parity test in Section 18).
- Recursive planted-marker leak guards over both event shapes at all
  nesting levels.
- Incident-scope consistency: the scoped constraint derives only from
  `_incident_observable_scope`; the structural no-answer-key guard extends
  to the query read.
- Authoritative visibility: the query read is the only event-query path;
  route-audit test.

---

## 18. Acceptance criteria for later implementation

| Area | Criterion |
|---|---|
| Hierarchy | Object-model docs match Section 4 (review-level); the full 3.9 battery stays green untouched, including detection indistinguishability. |
| Sanitized payloads | Hotfix suite green and retargeted to the query read; recursive planted-marker absence on both event shapes; structural whitelist (unknown injected field never serializes). |
| Shape parity (OD-10) | No whitelist field's top-level presence is population-exclusive: background events with account data serialize `user_account`; no event serializes top-level `protocol`; both asserted across a live drip of both populations. |
| event_seq foundation | Direct tests: uniqueness, strict monotonicity, assignment-once, pool append-only, read-no-mutation on query routes. |
| Stable snapshots | Under a mocked growing pool, a displayed snapshot's row set and order are byte-stable; replacement on Run/Refresh is atomic. |
| Deterministic replay | Executing an identical identity twice in one session returns byte-identical rows in the canonical order; token re-execution equals identity re-execution. |
| Explicit refresh | New cutoff and token; prior snapshot object untouched; selection persists when the inspected id survives; absence notice otherwise. |
| Canonical order and client sort | The query read's row order equals the canonical definition; client column sorting issues no request and leaves the token unchanged. |
| Token security | Altered, foreign, and post-reset tokens fail neutrally and indistinguishably; tokens are invalid after Reset, Practice Another, and backend restart. |
| Shared epoch | `world["started_at"]` equals the simulation epoch; the snapshot_generator frozen-time guard passes against the shared epoch; no wall clock in any occurrence timestamp. |
| New-count | Matches the ratified OD-6 semantics exactly, token-bound; pool_growth independent; zero state hides the indicator; edited bar text provably cannot alter the count. |
| Time semantics (A1) | Occurrence times equal the recomputation from epoch, spacing, authored offsets, and the seeded gap stream; sim-now anchors to the pool maximum, never wall clock; the corrected doc language ships. |
| Query parsing | Every Section 11 valid example parses; every INVALID rejects with position and reason; unknown field/sensor/type errors; GD-3 precedence cases; quote-case matrix; normalization idempotence. |
| Pivot and descent generation | Choke-point test: every Section 13 form parses and equals its documented shape, including escaping, the OR-case fresh-query fallback, and both descent forms (single-host, incident participant scope). |
| Inspector completeness | Renders every whitelisted field per family; recursive props check proves no non-whitelisted key renders; event_seq displays. |
| Incident scoping | Scoped results are a subset of session results for the same query; the constraint equals participant hosts; structural guard covers the query read. |
| Cross-host pivots | Entity pivot from incident scope visibly lands Session-wide; the return chip restores scope; all reads. |
| Mode visibility | All modes execute through the single query read; route audit finds no mode-specific event endpoint; grouped-alerts trigger branch removed. |
| States | Frontend tests enumerate Section 6's per-pane states, including the revised scope-error behavior (chip retained, Run disabled, no silent fallback). |
| No-mutation reads | scope-no-mutation extended: query, refresh, new-count, pivot, descent, scope switch, inspector are GETs only. |
| Zero grading leaks | Planted grading markers never in query or count responses; submission-gate battery green. |
| Zero row movement | Explicit assertion: no insertion, removal, or reorder of a displayed snapshot while the mocked pool grows across poll cycles. |

---

## 19. Deferred work

LCQL implementation and workbench implementation until this contract is
locked; multi-host scenario authoring; live tail; investigation graph;
saved searches; snapshot history; persistent history; performance work
absent measurement; parentheses, numeric/range operators, field-existence
predicates, absolute TIMEFRAME, windowed surrounding-events, projection,
GROUP BY; **A2 full same-seed replay** (session seed infrastructure);
detection-materialization vs raw-event-visibility timing alignment
(finalization item 4);
cross-session deterministic event identity; exact-id descent (the OD-9
alternative, with its enumerated costs); CampaignProgress micro-fix
(ratified venue: separate).

---

## 20. Decision register

### 20.1 Ratified decisions

| # | Decision |
|---|---|
| R1 | LCQL pipe grammar pinned; operators and quote-case per the notes. |
| R2 | Sealed roster; ownership per Section 4.2; no post-seal membership change. |
| R3 | Incident scope from observable attribution only; answer-key inputs structurally banned. |
| R4 | Three modes; sealing, drip, readiness identical; correctness submission-gated. |
| R5 | Triggered Evidence Arrival = observable telemetry arriving; never correctness. |
| R6 | Event-disclosure hotfix landed (`37486b1`); server-sanitized payloads are the Stage 4 foundation. |
| R7 | Scaffold -> approve -> implement cadence; disclosure rules; concern-level gate-green commits. |
| R8 | **OD-1:** Option A with a deterministic simulation epoch; tier A1 in this stage, A2 deferred (Section 9). |
| R9 | **OD-2:** absorb into the existing SIEM tab; player-facing name remains SIEM. |
| R10 | **OD-3:** Session-wide default; descent opens incident scope; explicit selection then persists. |
| R11 | **OD-4:** uniform written-pool visibility across all modes. |
| R12 | **OD-5:** GD-1 through GD-5 approved, subject to the OR-composition restriction (Section 11). |
| R13 | **OD-7:** CampaignProgress corrected as a separate micro-fix. |
| R14 | **OD-8:** legacy dropdown filters retired; sidebar and query-generating controls replace them. |
| R15 | Old OD-6 (storyline) closed: removed by the hotfix; no consumer required it. |
| R16 | **OD-6:** refresh-now semantics for the new-events indicator (Section 8). |
| R17 | **OD-9:** host-anchored uniform evidence-timeline descent, control labeled Open Evidence Timeline; exact-id descent deferred with its enumerated costs (Section 13). |
| R18 | **OD-10:** shape-parity amendment adopted: internal `user` maps to `user_account`; `protocol` serializes uniformly inside `key_value_pairs` (Section 10). |

### 20.2 Recommendations (P3, P5, P6 subsumed by R16-R18; the rest
stand approved with this finalization unless amended at lock)

| # | Recommendation | Section |
|---|---|---|
| P1 | Migration path per Section 5 from the post-hotfix baseline; grouped-alerts retirement after stats relocation. | 5 |
| P2 | Snapshot model per Section 7: event_seq foundation, identity tuple, token, no history in v1. | 7 |
| P3 | Refresh-now semantics for the new-count (the OD-6 recommendation). | 8 |
| P4 | A1 mechanics as specified (epoch digest, seeded gap stream, background times from event_seq spacing). | 9 |
| P5 | OD-10 amendment as specified (`user` -> `user_account`; `protocol` to kvp; shape-parity test). | 10 |
| P6 | Host-anchored uniform descent (the OD-9 recommendation); exact-id descent deferred with enumerated costs. | 13 |
| P7 | Entity pivots always Session-wide with visible flip and return chip. | 14 |
| P8 | Server-side single query read; no client-side query execution. | 17 |
| P9 | Reference-matrix verdicts rows 1-12 with hardened citations. | 3 |

### 20.3 Owner decisions required

None. Every owner decision is ratified (R8 through R18). The contract is
ready for the owner's lock.

### 20.4 Known repository conflicts, dispositions

| # | Conflict | Disposition |
|---|---|---|
| C1 | fake-events answer-field leak | Resolved: hotfix `37486b1` + test_event_disclosure suite. |
| C2 | grouped-alerts per-group leak | Resolved by hotfix reduction; endpoint retires per Section 5. |
| C3 | "Frozen scenario clock" claims vs wall-clock events | Resolved by R8/A1; docs corrected. |
| C4 | SOC Queue full stream vs described trigger-only | Resolved by R11. |
| C5 | Pinned grammar vs implemented Splunk-style search | Search retired (R9/R14); grammar implemented per Section 11. |
| C6 | CampaignProgress un-adapted totals | R13 micro-fix. |
| C7 | log_writer docstring 40-80s vs code 20-40s | Doc correction in the Section 5 doc pass. |
| C8 | Attack vs normal field shapes | Serializer unified by hotfix; residual presence discriminators closed by R18. |
| C9 | No incident-scoped raw-event read | Resolved by the scoped query read. |
| C10 | No refresh/indicator/snapshot; rows move | Resolved by Sections 6-8. |
| C11 | Triggering events carry no ids; ambient triggers are synthetic (new, inspection report B) | Resolved by R17; enforced-test invariant preserved. |
| C12 | No seed exists; "same-seed replay" was a category error (new, inspection report D) | Resolved by the A1/A2 split; A1 claims only what is true. |

### 20.5 Deferred work

As enumerated in Section 19.

### 20.6 Implementation prerequisites (in order)

1. The owner records the lock on this revision. After the lock, changes
   require an explicit amendment, never a new general review cycle.
2. Per the cadence: an implementation scaffold for the locked contract,
   reviewed and approved before any code; concern-level gate-green
   commits; Section 18 is the closing-evidence list; every serialized
   field and endpoint change is disclosed per the standing rule.

---

*Deliverables mapping: (1) this document; (2) wireframe, Section 6;
(3) reference matrix with exact titled citations, Section 3; (4) player
flow, Section 1; (5) decision register, Section 20; (6) acceptance
criteria, Section 18; (7) hotfix reconciliation, folded into Sections 2, 5,
10, and 17 (no pending items remain).*
