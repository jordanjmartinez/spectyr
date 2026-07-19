# Stage 4A Repository-Truth Inventory (SIEM Investigation Workbench)

**Status: factual inventory only.** This document records observed repository
truth to ground the future Stage 4A workbench contract. It makes **no** design
decisions, recommendations, or grammar revisions, and it does not draft the
contract. Where interpretation is unavoidable it is labelled. Baseline: `main`
tip `decfb18` (Stage 3.9 merge `97e3292`).

**Evidence labels used throughout:** **[Observed]** = read directly from a cited
file/line or measured; **[Inferred]** = derived reasoning, not directly measured;
**[Conflict]** = a disagreement between sources; **[Unprotected]** = behaviour
with no direct automated guard. File citations are `path:line`.

Measurements in this document were produced by (a) direct code reading, (b) a
throwaway inventory script over `app.yaml_catalog` (event-type/field/volume
counts), and (c) a throwaway Flask-test-client drip that captured a real
`/api/fake-events` payload. Both scratch scripts lived outside the repository and
were deleted; nothing was committed. No gate battery was run against a live dev
backend (per the BACKLOG note added in this task).

---

## 1. Executive factual summary

- **[Observed]** The player-facing event surface today is the **SIEM** tab
  (`Siem.jsx` + `SiemCards.jsx` + `SiemTable.jsx` + `siemUtils.js`). It polls
  `GET /api/fake-events` every 2s, reverses the pool to newest-first, and does
  **all** filtering/search/sort/paging client-side over the cached pool. It is
  **session-wide only** — it is never incident-scoped.
- **[Observed]** The legacy Events surfaces are **gone from the repository**:
  `GroupedAlerts.jsx` and `AlertTable.jsx` do not exist (`frontend/src/components/`
  listing). No player route renders grouped/notable events anymore.
- **[Observed][Unprotected]** `GET /api/fake-events` serves the **raw** event
  pool with no server-side sanitization. A served attack event carries answer-
  adjacent fields — `label` (the scenario_label), `category` (the attack
  category), `scenario_id`, `threat_pattern`, `storyline`, `level_name`,
  `alert_id`, `level`, `flagged`, `status`. The frontend hides these via a
  10-field display whitelist (`siemUtils.sanitizeEvent`), but they are present in
  the network payload. No backend test guards this.
- **[Observed][Conflict]** Event content timestamps are **wall-clock-at-drip**
  (`base_time = datetime.now(timezone.utc)` at `app.py:2399`), not a session-
  frozen clock. Only `world["started_at"]` and the response-action log use a
  frozen clock. This is in tension with the "frozen scenario clock" language in
  `siemUtils.js` and `docs/stage4-query-grammar-notes.md`.
- **[Observed]** LCQL is **entirely unimplemented**. The pinned grammar
  (`TIMEFRAME | SENSOR_SELECTOR | EVENT_TYPE | FILTERS`) exists only in
  `docs/stage4-query-grammar-notes.md`. The current SIEM search is a different,
  simpler `field=value` + free-text substring syntax (`siemUtils.parseEventQuery`)
  that does not conform to the pinned grammar. **[Conflict]**
- **[Observed]** Corpus authored volume: **20 scenarios**, mean **6.20** authored
  events/scenario (chain+supplemental; total 124), **3.0** detections/scenario
  (total 60), **2.65** environment hosts/scenario. **30 event types** across
  **8 source families**. Runtime totals additionally include normal traffic and
  are runtime-duration-dependent (Section 10).

---

## 2. Current surface map

### 2.1 Routes and navigation

**[Observed] React routes (`App.jsx:102-107`):**

| Path | Element | Notes |
|---|---|---|
| `/` | `Landing` | marketing landing |
| `/docs` | `Docs` | static "How Spectyr Works" |
| `/sim` | `BackendGate > Dashboard` | the app; health-gated (`App.jsx:23-91`) |
| `/analytics` | `BackendGate > Analytics` | standalone Metrics component (same component as the Metrics tab) |

**[Observed] Sim nav tabs (`Dashboard.jsx` `tabs` array):** Dashboard, Incidents,
SIEM, Detections, Endpoints, Metrics, Reports; plus a Docs link. Keyboard 1-7
switch tabs. Each tab's view mounts hidden/visible via a `view` state string
(`dashboard | grouped | siem | detections | endpoints | analytics | reports`).
The internal key for the Incidents tab is still `grouped` (legacy name).

### 2.2 SIEM surface (the event surface)

**[Observed] `Siem.jsx`:**
- Polls `GET /api/fake-events` every **2000ms** (`Siem.jsx:34`); on each poll
  `setAlerts([...data].reverse())` — **newest-first** ordering (`:28`).
- Fetches `GET /api/endpoints` once per `resetTrigger` only for `org.name`
  (`:38-43`).
- Owns all filter state: `searchTerm, sourceFilter, platformFilter, typeFilter,
  preset`, `view` (`cards | table`, default `cards`).
- **All filtering is client-side over the cached pool** (`:67-77`): source,
  platform, event-type dropdowns (values derived from the pool `:61-63`), a time
  preset (`withinPreset`), structured `field=value` filters (AND-ed), and a bare
  free-text term matched as `JSON.stringify(alert).includes(free)` (`:75`).
- **No incident scoping.** `Siem` takes no `activeIncidentId` prop and applies no
  incident filter. **[Observed]**
- `resetTrigger` clears all state and refetches (`:45-53`). `pivotQuery` prefills
  the search box (`:56-58`).

**[Observed] `SiemTable.jsx` (table view):**
- Sortable columns (`SORTABLE`, `:7-13`): `timestamp, event_type, source_type,
  source_ip, destination_ip`. Default `sort === null` = feed order (`:19`).
- Stable sort tie-break: chosen key, then `timestamp` desc, then `id` (`:34-42`).
- Pagination 10/20/50 per page, default **20** (`:17`); expandable rows keyed by
  `alert.id` (`:18,:53`).
- Row body renders `renderCleanEventDetails` which calls `sanitizeEvent` and
  excludes a further set of kvp keys from the inline view (`:65-71`).

**[Observed] `SiemCards.jsx` (card view, default):**
- **12** cards/page (`:8`), feed order (receives already-ordered pool), expandable
  to `JSON.stringify(sanitizeEvent(alert))` (`:118-120`), keyed by `alert.id`
  (`:70`). Source-family color dot (`sourceColor`). Host name pivots to Endpoints.

**[Observed] `siemUtils.js` (shared logic):**
- `FIELD_ALIASES` (`:6-15`): search aliases mapping to `event_type, source_type,
  source_ip, destination_ip, protocol, message, hostname, severity`.
- `parseEventQuery` (`:17-31`): splits on whitespace; `field=value` tokens (first
  `=`) become AND-ed lowercase substring filters; other tokens join into a free
  term. **No `==`, `contains`, quotes, pipes, or segments** — this is not LCQL.
- `sanitizeEvent` / `RAW_LOG_FIELDS` (`:60-70`): the display whitelist —
  `timestamp, event_type, source_type, severity, hostname, source_ip,
  destination_ip, user_account, message, key_value_pairs`. Empty/undefined
  dropped.
- `TIME_PRESETS` (`:74-81`): `15m,1h,4h,12h,24h,all`. `withinPreset`/`poolAnchorMs`
  (`:83-98`): the window is measured back from the **pool's own maximum event
  timestamp**, computed at render (not render wall-clock).
- `platformOf`/`PLATFORM_MAP` (`:50-56`): Sysmon/Windows Security/Defender ->
  Windows; Azure AD -> Cloud; Proxy/Firewall/DNS -> Network; Veeam -> Application.

### 2.3 Other player surfaces (summarized; not primary event surfaces)

**[Observed]**
- **Detections** (`Detections.jsx` + `DetectionDetail.jsx`): feed/Threats/Response-
  Log toggle; polls `GET /api/detections` and `GET /api/actions` every 2500ms;
  incident-scope toggle ("This incident / Session-wide") via `activeIncidentId` +
  `GET /api/incidents/<id>/scope`. Detection detail (`DetectionDetail`) shows
  triggering-event + parent-process lineage (event-derived).
- **Endpoints** (`Endpoints.jsx` + `EndpointDetail.jsx`): fixed snapshot, no
  polling; fetched on tab open / reset / pivot; incident-scope toggle. Endpoint
  detail has an **event-derived timeline** across Overview/Processes/Network/
  Services/Users/Autoruns tabs, materialized by `snapshot_generator` from the
  substituted event pool.
- **Incidents** (`Incidents.jsx`): the operational workspace; polls
  `GET /api/incidents` every 3000ms and `GET /api/incidents/<id>/scope` +
  `GET /api/actions` every 3000ms for Related hosts/accounts + Related response
  activity.
- **Dashboard** (`IncidentDashboard.jsx`): compact overview; polls `/api/incidents`,
  `/api/analytics/report_card`, `/api/grouped-alerts` (`.stats` only),
  `/api/analytics/attack_coverage`, `/api/endpoints`, `/api/detections` every 3s.
- **Metrics** (`Analytics.jsx`, also the standalone `/analytics` route): fetches
  `report_card`, `current-level`, `action_history`; **renders** `CampaignProgress`
  (`:73`), `AnalystReportCard` (`:94`), `ActionHistory` (`:114`).
- **Reports** (`Reports.jsx`): documentation-only incident reports; uses
  `IncidentReportForm`, `SeverityPill`.

### 2.4 Retired / possibly-orphaned components (repository truth)

**[Observed]** `GroupedAlerts.jsx`, `AlertTable.jsx`: **absent** from the repo
(deleted at Stage 3.9B). No route/import references them (`grep`).

**[Observed][Conflict]** `CampaignProgress.jsx` **is imported and rendered** by
`Analytics.jsx:5,:73`. This contradicts the Stage 3.9B commit-message claim that
"CampaignProgress.jsx ... is dead code (imported nowhere)". Repository truth:
it renders in the Metrics tab and `/analytics` route, and it still prints
`{resolved} of {total} resolved` (`CampaignProgress.jsx:37`) using
`current-level` data, un-adapted to the 3.9B mode-specific totals. Recorded here
as a fact for the reviewer; not resolved.

**[Observed]** `Navbar.jsx` (App-level, hidden on `/`,`/docs`,`/sim`),
`AnalystReportCard.jsx`, `ActionHistory.jsx` (Analytics), `IncidentReportForm.jsx`,
`SeverityPill.jsx` (Reports), `TriageFeedback.jsx` (no import found -> possibly
orphaned, **Inferred**), `GameTimer.jsx`, `FailureModal.jsx`, `ClassificationSelector.jsx`,
`CategorySelector.jsx`, `ConfirmDialog.jsx`, `DifficultySelector.jsx` are present
and referenced.

### 2.5 Duplicated responsibilities / reachability (facts)

- **[Observed]** SIEM (`fake-events`) and grouped-alerts (`grouped-alerts`) both
  read the same `generated_logs` pool but present it differently (flat stream vs.
  scenario groups). Only `.stats` of grouped-alerts is consumed today
  (`IncidentDashboard.jsx`); the per-group `logs`/`label`/`category` are computed
  but not rendered by any current surface.
- **[Observed][Conflict]** The analyst-mode "triggered evidence arrival" filtering
  lives in `grouped-alerts` (`app.py:4401-4432`, trigger-only + pivot_values), but
  the current UI does not render grouped-alerts logs, and `fake-events` (which the
  SIEM does render) is **not** mode-filtered. So in SOC Queue mode the SIEM shows
  the full event stream; the trigger-only display is not enforced by any rendered
  surface. Recorded as a fact; not resolved.

---

## 3. Event API inventory

Legend: **direct event endpoint** = serves event rows/pool; **event-referencing**
= embeds or summarizes events. All are `GET` unless noted. All read the session's
`generated_logs` and/or `world`/`detections` under `session["io_lock"]` where
noted. None accept query parameters unless listed.

### 3.1 `GET /api/fake-events` — direct event endpoint

- **[Observed] `app.py:2625-2634`.** No parameters. Returns a **bare JSON array**
  of the full session event pool, deduped by `log["id"]` (`seen_ids`).
- No pagination / limit / truncation. No incident scope. No session-wide/scoped
  distinction (always the full pool). **No server-side sanitization.**
- **Serialized top-level fields on a served attack event [Observed, measured]:**
  `alert_id, category, event_type, flagged, hostname, id, key_value_pairs, label,
  level, level_name, log_source, message, scenario_id, severity, source_ip,
  source_type, status, storyline, threat_pattern, timestamp, user_account`.
- **Serialized top-level fields on a served normal-traffic event [Observed,
  measured]:** `destination_ip, detected_by, event_type, flagged, hostname, id,
  key_value_pairs, label, message, parent_process_id, process_id, protocol,
  scenario_id, severity, source_ip, source_type, timestamp, user`.
- Identifier field: `id` (uuid4). Timestamp field: `timestamp` (ISO-8601).
- Sort/order: file order = drip write order (no server sort). Empty pool -> `[]`.
- No explicit loading/not-ready state; the array simply grows.
- Error: relies on the session middleware; a valid session always returns 200.
- **Consumers:** `Siem.jsx:26` (2s poll). Also read in `Dashboard.jsx`
  `handleSimulateEvents` to detect an existing session (`fake-events` length).
- **[Unprotected]** No backend test asserts field sanitization; `test_actions.py`
  reads `/api/fake-events` only to assert immutable evidence after a kill
  (`test_api_immutable_evidence_after_kill`).

### 3.2 `GET /api/grouped-alerts` — event-referencing (aggregation)

- **[Observed] `app.py:4347-4478`.** No parameters. Groups `generated_logs` by
  `scenario_id` (excludes `label == "normal_traffic"`); returns only groups where
  some log has `chain_complete` (`:4395`).
- **Per-group serialized fields:** `scenario_id, threat_pattern, label, status,
  severity, category, ticket_title, storyline, analyst_category, alert_id,
  incident_id (== alert_id), level, log_count, logs (full raw log dicts),
  severity_breakdown, total_log_count, hidden_count, group_severity,
  detections_sealed, open_detections, submission_ready`. Top-level: `alerts`
  (groups) + `stats {total_alerts, closed_alerts, open_alerts,
  severity_breakdown, source_breakdown}`.
- **[Observed]** Analyst-mode branch (`:4401-4432`): reduces each group's `logs` to
  trigger logs, recomputes `severity_breakdown`, and emits `pivot_values`
  (distinguishing entity values excluding infra IPs/hostnames). `hidden_count` =
  hidden chain size.
- **[Observed][Unprotected]** Serves `label`, `category`, `analyst_category`,
  `storyline`, and raw `logs` (which include `scenario_id`/`category`). Only
  `.stats` is consumed today (`IncidentDashboard.jsx`). No leak guard on the
  per-group answer-adjacent fields; `test_submission_gate.py:494`
  (`test_grouped_alerts_surface_incident_scoped_readiness`) only asserts the
  observable readiness fields.

### 3.3 `GET /api/detections` — event-referencing

- **[Observed] `app.py:2683-2697`.** Returns `{detections:[...], counts:{open,
  promoted,dismissed}}`. Each entry passes `detection_templates.sanitize_detection`
  (disposition + scenario linkage stripped) and `_attach_account_ref` (adds
  `entity.account_id`, `entity.account_state`). Ordered by
  `order_detections_for_client` (deterministic stable-key). No incident scope
  (the scope toggle is applied client-side via `/scope` roster ids).

### 3.4 `GET /api/detections/<det_id>` — event-referencing

- **[Observed] `app.py:2700-2711`.** Full detail with `include_events=True`
  (triggering events, whitelisted). 404 unknown. Sanitized.

### 3.5 `POST /api/detections/<det_id>/disposition`

- **[Observed] `app.py:2714-2729`.** Body `{action: promote|dismiss|open}`; 400
  otherwise. Sets `player_action`; returns the sanitized detection. 404 unknown.

### 3.6 `GET /api/threats` — event-referencing

- **[Observed] `app.py:2732-2742`.** Promoted detections only, `include_events=True`,
  sanitized, same deterministic order.

### 3.7 `GET /api/endpoints` and `GET /api/endpoints/<hostname>` — event-derived

- **[Observed] `app.py:2636-2664` / `2667-2680`.** List rows: `hostname, ip,
  external_ip, role, os, desc, platform, status, isolation, tags[], first_seen,
  last_seen, owner, entity_id`, sorted by hostname; base+overlay current state.
  Detail: full `snapshot_generator.public_view` + overlay + `annotate_view`
  (client entity ids); 404 unknown. The endpoint tabs (processes/network/services/
  users/autoruns) are the event-derived host timeline.

### 3.8 `GET /api/actions` — event-referencing (response log)

- **[Observed] `app.py:2806-2813`.** Returns `{actions:[...], count}`; each entry
  `action_overlay.sanitize_action_entry`; **oldest-first**. Entry fields (from
  `sanitize_action_entry`): `seq, action, target {id,kind,label}, outcome, reason`
  and a logical timestamp (frozen clock + monotonic sequence, no wall clock).

### 3.9 `GET /api/incidents` and `GET /api/incidents/<id>/scope` — incident-scoped, observable-only

- **[Observed] `app.py:3592-3644`.** `list_incidents` returns `active[]` /
  `completed[]` / `queue_length` / `resolved_count`. Active card:
  `{incident_id, title, briefing, severity, queue_position, state, sealed}` + when
  sealed `triage{total,triaged}, open_detections, ready`. Completed card adds
  `submitted_at, assisted, incident_grade{grade,accuracy}`.
- **[Observed] `app.py:3753-3775`.** `incident_scope_route` returns `{incident_id,
  sealed, hosts[], accounts[], detection_ids[]}` + `triage{total,triaged}` only
  when sealed. `detection_ids` are the opaque client-facing detection ids
  (Section 7 of the 3.9B work). No `scenario_id`/`category`/answer key.

### 3.10 Endpoints that expose the requested categories (classification)

| Category | Endpoint(s) | Direct or referencing |
|---|---|---|
| raw events | `GET /api/fake-events` | direct |
| notable events | (none — `GroupedAlerts` retired) | n/a |
| grouped events | `GET /api/grouped-alerts` | referencing (groups + raw logs) |
| detection-linked events | `GET /api/detections/<id>`, `GET /api/threats` | referencing (triggering events) |
| endpoint timelines | `GET /api/endpoints/<hostname>` | event-derived (snapshot) |
| response logs | `GET /api/actions` (GET) | referencing (action attempts) |
| incident-scoped evidence | `GET /api/incidents/<id>/scope` | referencing (roster ids, hosts, accounts) |

**Summarizing/grading endpoints that do NOT serve event rows [Observed]:**
`/api/analytics/report_card`, `/api/analytics/detection_score`,
`/api/analytics/action_score`, `/api/analytics/attack_coverage`,
`/api/analytics/action_history`, `/api/incidents/<id>/score`,
`/api/current-level`, `/api/game-state`, `/api/guided-catalog`,
`/api/triage-review/<label>`, `/api/incidents/<id>/triage-review`.

---

## 4. Event-schema catalog and shared-field matrix

**[Observed, measured]** 30 authored event types across 8 source families (from
`app.yaml_catalog` chain + supplemental steps). "n" = authored occurrences across
the corpus.

### 4.1 Fields added at drip (all attack events)

`build_attack_chain_logs` (`app.py:2413-2429`) sets on every attack log:
`id` (uuid4, **overwrites** the authored step-id tag), `timestamp` (ISO,
`base_time + cumulative offset`), `severity` (default "high"), `scenario_id`,
`status` ("active"), `level` (queue_position), `level_name` (ticket_title),
`storyline`, `category`, `flagged` (True), `alert_id` (INC-####), `source_type`
(from `detected_by` if absent). `threat_pattern` also appears on served attack
events (**Observed** in the captured payload; carried through from the scenario).

### 4.2 Event-type table

| event_type | source | kind | n | notable kvp keys |
|---|---|---|---|---|
| `AADUserRiskEvents` | Azure AD | identity risk | 2 | RiskLevel, RiskEventType, RiskState, UserPrincipalName, IPAddress, Location, MitreTechnique |
| `SigninLogs` | Azure AD | identity signin | 4 | ResultType, IPAddress, Location, ClientAppUsed, IsInteractive, ConditionalAccessStatus, UserPrincipalName, IncomingTokenType |
| `QUERY` | DNS | dns query | 13 | query, query_type, reply_code, src_ip, dst_ip, message_type, transport |
| `5007` | Defender | config change | 1 | old_value, new_value, product_name, product_version, event_id, channel |
| `ALLOW` | Firewall | fw allow | 8 | action, app, src_ip, dst_ip, dest_port, rule, transport |
| `DENY` | Firewall | fw deny | 2 | action, app, src_ip, dst_ip, dest_port, rule, transport |
| `FileSyncUploadedFull` | Proxy | cloud upload | 2 | bytes_uploaded, file_count, site_url, url, http_method, src_user |
| `HTTP_CONNECT` | Proxy | proxy connect | 6 | url, url_category, http_method, server_cert_subject, src_user |
| `HTTP_GET` | Proxy | proxy get | 5 | url, http_method, bytes_received, content_type, src_user |
| `HTTP_POST` | Proxy | proxy post | 4 | url, http_method, bytes_sent, grant_type, scope, interval_minutes, occurrence_count |
| `SSL_HANDSHAKE_FAILED` | Proxy | tls fail | 1 | failure_reason, tls_alert, tls_alert_code, expected/presented_cert_issuer, failure_count_last_hour, process |
| `SSL_INSPECT` | Proxy | tls inspect | 2 | ssl_action, ssl_policy, tls_version, original/presented/reissued/server_cert_issuer, category |
| `FileCreate` | Sysmon | 11 (evt 11) | 11 | target_filename, image, process_id, creation_utc_time, rule_name, user |
| `NetworkConnect` | Sysmon | 3 (evt 3) | 5 | destination_ip/port/hostname, source_ip/port, protocol, initiated, image, process_id |
| `ProcessAccess` | Sysmon | 10 (evt 10) | 1 | source/target_image, source/target_process_id, granted_access, call_trace, rule_name |
| `ProcessCreate` | Sysmon | 1 (evt 1) | 24 | command_line, image, parent_image, parent_command_line, process_id, parent_process_id, integrity_level, user, hashes(via kvp), current_directory |
| `SetValue` | Sysmon | 13 (evt 13) | 4 | target_object, details, image, process_id, event_type, rule_name |
| `WmiEventConsumer` | Sysmon | 20 (evt 20) | 1 | name, type, destination, operation, host |
| `WmiEventConsumerToFilter` | Sysmon | 21 (evt 21) | 1 | consumer, filter, operation, host |
| `WmiEventFilter` | Sysmon | 19 (evt 19) | 1 | name, query, event_namespace, operation, host |
| `110` | Veeam | backup start | 1 | job_name, scheduled_time, service, event_level, event_log |
| `190` | Veeam | backup done | 2 | job_name, bytes_backed_up, duration_seconds, repository, repository_ip, status |
| `1102` | Windows Security | log cleared | 1 | account_name, domain_name, logon_id, security_id, channel |
| `4624` | Windows Security | logon | 4 | account_name, logon_type, logon_process, authentication_package, workstation_name, src_ip, subject_* |
| `4625` | Windows Security | logon fail | 13 | account_name, logon_type, status, sub_status, failure_reason, src_ip, workstation_name, subject_* |
| `4663` | Windows Security | object access | 1 | object_name, object_type, accesses, access_mask, handle_id, process_name, subject_* |
| `4740` | Windows Security | account lockout | 2 | target_account_name, caller_computer_name, locked_out_security_id, subject_* |
| `5140` | Windows Security | share access | 1 | share_name, share_local_path, accesses, access_mask, src_ip, subject_* |
| `6416` | Windows Security | device add | 1 | device_name, device_id, class_name, class_id, vendor_ids, compatible_ids, location_information |

**[Observed]** Detection linkage: detections reference event ids via `triggers`
(step ids / supplemental ids), server-side only; not present on the event rows.
Incident linkage: attack events carry `scenario_id` + `alert_id`(= incident id);
supplemental/normal events carry no scenario linkage (supplemental logs are
appended with `category:"Benign"` and no `scenario_id`, `app.py:2453-2458`; the
captured normal event carried `scenario_id` present-but-null, **Observed**).

### 4.3 Shared-field matrix (top-level)

**[Observed]** Union of authored top-level keys across every event step:
`destination_ip, event_type, host, hostname, id, log_source, message, offset,
red_herring, severity, source_ip, source_type, trigger, user, user_account`
(where `id/host/user` are schema-v2 per-step **tags**, `trigger`/`red_herring` are
authoring flags, `offset` is the authored time offset).

| top-level field | attack events (served) | normal events (served) | notes |
|---|---|---|---|
| `id` | yes (uuid4) | yes (uuid4) | client-facing event id |
| `timestamp` | yes | yes | ISO; drip-anchored |
| `event_type` | yes | yes | |
| `source_type` | yes | yes | attack also carries `log_source` |
| `severity` | yes | yes | |
| `hostname` | yes | yes | |
| `source_ip` | yes | yes | |
| `destination_ip` | some | yes | network events only on attack side |
| `message` | yes | yes | |
| `key_value_pairs` | yes | yes | type-specific nest |
| `user_account` | yes | **no** | **[Conflict]** normal events use `user` |
| `user` | no | yes | field-shape divergence |
| `label` | yes (scenario_label) | yes ("normal_traffic") | **answer-adjacent on attack** |
| `category` | yes (attack category) | no | **answer field** |
| `scenario_id` | yes | present (null) | linkage |
| `level`,`level_name`,`storyline`,`alert_id`,`flagged`,`status`,`threat_pattern` | yes | (subset) | internal/answer-adjacent |
| `detected_by` | (from source) | yes | normal events |
| `process_id`,`parent_process_id`,`protocol` | (kvp) | yes (top-level) | normal events flatten some fields |

**[Conflict]** Attack and normal events have **different field shapes** for
user/process/protocol (`user_account`+kvp vs `user`/`process_id`/`protocol`
top-level). Any Stage 4A searchable-field model must reconcile this.

The complete kvp key union (all families) is in the Appendix (16).

---

## 5. Telemetry-drip lifecycle

**[Observed]** Single writer thread `log_writer(session, interval=1)`
(`app.py:2541-2623`), one per session, started by `start_simulator`. 1s tick.

Distinct events (do not conflate):

1. **Scenario scheduling / intake.** Queue built at start:
   `build_alert_queue(n=10, fp_min=1, fp_max=2)` for SOC Queue/Hardcore, or
   `build_guided_queue(catalog_id)` (queue_length 1) for Guided. First drip is due
   immediately (`next_drip_at = now` at start). **[Observed]**
2. **Incident arrival (drip).** When `now >= next_drip_at` AND
   `injected_count < len(alert_queue)` AND `in_flight < CONCURRENT_QUEUE_CAP (3)`
   (`app.py:2580-2583`): `build_attack_chain_logs` runs, `injected_at = now`,
   `injected_count++`, `next_drip_at = now + random(20,40)s` (`:2594`). If the cap
   is full, the drip is **skipped without advancing the timer**, so it fires
   immediately once a slot frees (`:2577-2583`). **[Observed]**
   - **[Conflict]** The docstring says "every 40-80 seconds" (`:2543`); the code
     uses 20-40s (`:2594`).
3. **Telemetry arrival (per-event writes).** Attack logs from the built chain are
   held in `attack_queue` and written interleaved with normal traffic: an attack
   log is emitted only when `logs_since_last_attack >= next_attack_gap`
   (`next_attack_gap = random(2,3)`, `:2549,:2606`); otherwise a
   `generate_normal_event()` normal log is written. So ~2-3 normal events per
   attack event, ~1 write/second. **[Observed]**
4. **Detection materialization.** Detections are built **at drip time**, inside
   `build_attack_chain_logs` under `io_lock` (`app.py:2478-2500`): scenario
   detections + ambient-benign detections for any host first seen. They exist in
   `session["detections"]` immediately at drip (before the chain finishes
   writing). **[Observed]**
5. **Incident card appearance (frontend).** `list_incidents` returns the active
   card as soon as the queue entry exists; `sealed` reflects
   `chain_complete_at`. Pre-seal the card shows "Loading". **[Observed]**
6. **Chain completion + roster sealing.** When the last log of a scenario's chain
   is written (`next_same_scenario` false, `:2610-2616`): `finalize_chain` marks
   all that scenario's logs `chain_complete = True`, and the queue entry's
   `chain_complete_at` is stamped (the **seal marker**). **[Observed]**
7. **Submission readiness.** `incident_submission_readiness` requires the roster
   sealed (chain_complete_at) + every scoped detection dispositioned. **[Observed]**

**What can grow before sealing vs fixed after [Observed]:** before seal, the
scenario's events and detection roster are still materializing; after
`chain_complete_at` the roster is fixed (`benign_hosts` blocks re-attach; polls
never regenerate). Detections materialize once at drip (they do not grow per
poll).

**Reads do not mutate / polling does not generate [Observed].** All generation is
in `log_writer`. The GET endpoints read under `io_lock` and do not write
(`fake-events`, `endpoints`, `detections`, `grouped-alerts`, `actions`,
`incidents`, `scope`). Guarded by `test_sealed_roster_finality_no_growth_on_poll_or_unrelated_activity`
and `scope-no-mutation.test.js`.

**Mode differences [Observed]:** sealing, drip mechanics, readiness are
**identical** across Guided / SOC Queue (`analyst`) / Hardcore. Differences:
Guided builds a 1-entry queue and drips one incident; the others build the sampled
10-queue. Guided allows Check Answer (`GUIDED_MODES = {"training","guided"}`);
Hardcore adds the timer + wrong-submit-ends-run. The analyst-mode trigger-only
filter is in `grouped-alerts` only (Section 2.5 conflict). Retained legacy key
`training` behaves like Guided for the Check-Answer allow-list.

**Distinctions (per the task):** incident arrival (`injected_at`) precedes
telemetry arrival (per-event writes) precedes chain completion
(`finalize_chain`) == roster sealing (`chain_complete_at`); detection arrival is
at drip (co-incident with incident arrival, before telemetry finishes);
submission readiness is later (sealed + all dispositioned).

---

## 6. Frozen-clock model

**[Observed]** There is **not** a single session-frozen clock for all timestamps.
Sources:

| timestamp | source | frozen? | citation |
|---|---|---|---|
| event content `timestamp` | `base_time = datetime.now(timezone.utc)` at drip + cumulative offsets | **NO — wall-clock-at-drip** | `app.py:2399,:2415,:2449` |
| endpoint world (`first_seen`, `last_heartbeat`, process times) | `world["started_at"]` (frozen at session start) | **YES** | `start_simulator` (`world["started_at"] = now.replace(microsecond=0).isoformat()`); `snapshot_generator` |
| response-action log entries | frozen session clock + monotonic sequence (no wall clock) | **YES** | `action_overlay`; `test_actions.py::test_no_wall_clock_in_log_entries`, `::test_log_records_every_attempt_with_frozen_clock_sequence` |
| drip orchestration (`injected_at`, `chain_complete_at`, `next_drip_at`, `timer_start`) | `datetime.now(timezone.utc)` | **NO — wall clock** | `log_writer` (`:2574,:2588,:2616`); `start_simulator` |
| SIEM time-preset anchor | pool's max event `timestamp` (`poolAnchorMs`) | render-independent, but derived from drip-time event timestamps | `siemUtils.js:91-98` |

**[Conflict]** `siemUtils.js:73` ("Time presets anchored to the pool's own latest
timestamp ... never wall time") and `docs/stage4-query-grammar-notes.md:14`
("TIMEFRAME ... anchored to the frozen scenario clock") both assert a frozen
scenario clock, but event content timestamps are wall-clock-at-drip. The SIEM
anchor is deterministic **relative to render** (it uses the pool max, not the
render-time wall clock), yet the underlying event times advance with real time as
scenarios drip.

**Reads do not affect the clock [Observed].** Clock state advances only in
`log_writer` / at session start.

**After reset (`reset-simulator`, `app.py:2816-2852`) [Observed]:** `world`
reset to `{hosts:{}, started_at:None}`; `timer_start=None`; `next_drip_at=None`;
log files truncated. Fresh `started_at` set at next `start_simulator`.

**Practice Another [Observed]:** calls `reset-simulator` then re-opens the picker;
so the clock is reset as above (verified in the Stage 3.9B checks: response log
empty, world empty after reset).

**Server restart [Observed/Inferred]:** sessions are in-memory; a restart drops
all sessions and their frozen clocks (`sessions` dict; boot sweep clears orphaned
log dirs). New requests create fresh sessions.

**Timezone [Observed]:** all clocks use `datetime.now(timezone.utc)` /
UTC-isoformat. Frontend renders `toLocaleTimeString('en-GB', {hour12:false})`.

**Ties [Observed]:** no server-side ordering guarantee when two events share a
timestamp; `fake-events` returns file/write order. `SiemTable` tie-breaks
client-side on `timestamp` desc then `id` (`SiemTable.jsx:40-41`).

**[Unprotected]** No test asserts event-content-timestamp determinism; parity
checks explicitly ignore timestamps (they compare chain content byte-for-byte
except timestamps). `snapshot_generator`'s frozen time is guarded
(`test_snapshot_generator.py::test_frozen_time_and_system_block`), but that is the
world snapshot, not the event stream.

---

## 7. Incident-scoping model

**[Observed] `_incident_observable_scope(s, incident_id)` (`app.py:3538-3586`),
served by `GET /api/incidents/<id>/scope`:**

- Resolves the opaque `incident_id` (`INC-####` == the drip alert_id) to
  `scenario_id` via `incident_index`.
- Observable participant **hosts** = written non-normal event participants
  (`hostname`) of that scenario ∪ tagged-detection entity hosts.
- Observable **accounts** = event `key_value_pairs.account_name` ∪ tagged-detection
  entity accounts.
- Detection **roster** = scenario-tagged detections + ambient-benign detections on
  the incident's observable hosts. `roster_ids = [d["id"] for d in roster]` — the
  opaque client-facing detection ids (identical to the `/api/detections` feed
  ids). `triaged` = count with `player_action != "open"`.
- `sealed` = `_incident_roster_sealed(s, scenario_id)` (chain_complete_at).
- **Never derived from `scenario_grading`, `expected_actions`, answer keys, or
  grading config.**

**Structural guard [Observed]:** `test_incident_scope.py::test_scope_structural_no_grading_or_expected_actions`
asserts (via `inspect.getsource`) the scope code references none of
`expected_actions / scenario_grading / _grading_record_for / grading_rec /
answer_key`. Field guard: `test_scope_serializes_observable_fields_only`. Total
withheld pre-seal: `test_scope_withholds_roster_total_before_seal`,
`test_list_withholds_roster_total_before_seal`. Roster == readiness roster:
`test_observable_roster_matches_readiness_roster`.

**Frontend scope state [Observed]:** `Dashboard.jsx` owns `activeIncidentId`
(opaque INC id, pure UI state). Detections/Endpoints show a "This incident /
Session-wide" toggle (fetch `/scope`, filter feed/list to `detection_ids` / hosts);
Incidents shows Related hosts/accounts + Related response activity. Switching is
reads-only (`scope-no-mutation.test.js`). Session-wide is always available.

**Exclusive attribution [Observed]:** a detection stays attributed to one incident
(scenario-tagged); ambient-benign on a shared host counts for every incident that
scopes that host. Pre-seal scope may grow as telemetry becomes visible; post-seal
it is fixed except for observable shared-world state.

**Intersection with event surfaces [Observed]:** **the SIEM does NOT intersect
incident scope at all** — it fetches `/api/fake-events` (session-wide) and never
filters by incident. Only Detections, Endpoints, and the Incidents workspace
consume `/scope`. There is no incident-scoped raw-event endpoint today; the only
incident-scoped event reference is `scope.detection_ids` (detection roster) +
`hosts`/`accounts` (participant summaries).

---

## 8. Sorting, insertion, polling, and refresh behavior

**[Observed]**

| Surface | default order | tie-break | new rows insert? | rows reorder while visible? | scroll/selection preserved? | poll | manual refresh | new-events indicator | snapshot or live |
|---|---|---|---|---|---|---|---|---|---|
| SIEM cards (`SiemCards`) | newest-first (pool reversed) | n/a (feed order) | yes (top) | yes (pool re-fetched, re-reversed) | no explicit preservation; expansion keyed by `id` persists | 2000ms (`Siem`) | no | no | **live mutable** |
| SIEM table (`SiemTable`) | feed order (newest-first) unless a column sort chosen | chosen key -> `timestamp` desc -> `id` | yes | yes; sort re-applies on every re-render | expansion keyed by `id`; page resets on reset only | 2000ms | no | no | **live mutable** |
| Detections feed (`Detections`) | `order_detections_for_client` stable-key server order | server-side deterministic | yes (materialize at drip) | order stable within a session (`test_order_is_deterministic_within_a_session`) | selection via detail view | 2500ms | no | no | live (roster fixed at seal) |
| Endpoints list/detail | hostname asc (server) | hostname | no (fixed set) | no | fetched on open/reset/pivot | **none (snapshot)** | implicit (pivot/reset) | no | **snapshot** |
| Incidents workspace | active/completed by state; rows stable | incident_id | on drip/submit | rows stable (keyed by id) | selection = `activeIncidentId` | 3000ms | no | no | live |
| Dashboard overview | Active list; Recent Completed `slice(-6).reverse()` | id | on drip/submit | yes | navigation-only | 3000ms | no | no | live |
| Response log (`/api/actions` via Detections) | oldest-first (server) | `seq` | on action | append-only | — | 2500ms (Detections) | no | no | live append |

**"What moves under the analyst today" [Observed]:** in the SIEM, the pool grows
~1 event/second (server writes) and is re-fetched every 2s and re-reversed, so
**new events appear at the top and push existing rows down**; on a paginated
page-1 the visible window shifts as new events arrive. No new-events indicator, no
manual refresh, no snapshot freeze. The Endpoints surface is the only event-
derived surface that is a stable snapshot (no polling).

---

## 9. LCQL grammar-note summary and conflicts

**[Observed] `docs/stage4-query-grammar-notes.md` (design record, "do not
implement yet"):**

- Pinned pipe structure: `TIMEFRAME | SENSOR_SELECTOR | EVENT_TYPE | FILTERS`
  (`:8-18`). TIMEFRAME anchored to the "frozen scenario clock"; SENSOR_SELECTOR =
  which sensor/source or host; EVENT_TYPE = event class; FILTERS = field
  predicates.
- Operators (`:20-25`): `contains`, `not contains`, `==`, `!=`, `and`, `or`.
- Quote semantics (`:27-29`): double quotes = case-insensitive; single quotes =
  case-sensitive.
- Deferred out of v1 (`:31-37`): projection, GROUP BY.
- Implementation reminders (`:39-45`): proper tokenizer/parser (not ad-hoc regex);
  runs over the scenario's full event pool (attack + noise), post-substitution;
  deterministic; unit-tested before UI.

**Grammar elements, faithfully summarized:**
- Token/separator: four `|`-separated segments; operators are words (`and`,`or`,
  `contains`,`not contains`) and symbols (`==`,`!=`).
- Quoting: `"..."` case-insensitive; `'...'` case-sensitive.
- Case: as governed by quoting; unquoted case behaviour is **not specified** in the
  notes (**Open question, Section 15**).
- Equality (`==`) vs contains (`contains`): notes list both but give no field-name
  or type rules, valid/invalid examples, or field-name syntax (**Open question**).
- Timeframe/sensor/event-type/filter-combination specifics beyond the above:
  **not enumerated** in the notes.

**Valid example authored here (conforms to the pinned grammar):**
`15m | Sysmon | ProcessCreate | command_line contains "powershell"` —
four pipe segments, `contains`, double-quote case-insensitive.

**Conflicts / drift flagged (not resolved):**
- **[Conflict]** LCQL is unimplemented; the current SIEM search
  (`siemUtils.parseEventQuery`) is a **different** syntax: `field=value` (single
  `=`, substring, case-insensitive) + bare free-text substring over
  `JSON.stringify`. It has no pipes, no `==`/`!=`/`contains`, no quote-case
  semantics, no TIMEFRAME/SENSOR/EVENT_TYPE segments. The example placeholder in
  the SIEM search box (`source_ip=10.0.1.24 event_type=4625`, `Siem.jsx:140`) is
  **Splunk-style `key=value`**, i.e. drift away from the pinned grammar. Labelled
  INVALID against the pinned grammar.
- **[Conflict]** The notes assume a "frozen scenario clock" for TIMEFRAME, but
  event content timestamps are wall-clock-at-drip (Section 6).
- **Grammar features with no implementation:** the entire grammar (all four
  segments, all operators, quote-case semantics). **[Observed]**
- **Implementation features absent from the grammar:** the current dropdown
  filters (Source/Platform/Event Type) and time presets, and the free-text
  `JSON.stringify` substring search, are present in the SIEM but are not part of
  the pinned grammar. **[Observed]**

**No grammar revision is proposed here.**

---

## 10. Event volume and performance measurements

**[Observed, measured from `app.yaml_catalog` — authored only]:**

| metric | min | max | mean | median | total (20 scen) |
|---|---|---|---|---|---|
| attack-chain events / scenario | 4 | 6 | 5.10 | 5 | 102 |
| supplemental events / scenario | 0 | 3 | 1.10 | 1 | 22 |
| authored events (chain+supp) / scenario | 4 | 8 | 6.20 | 6 | 124 |
| detections / scenario (authored) | 2 | 4 | 3.00 | 3 | 60 |
| environment hosts / scenario | 1 | 5 | 2.65 | 3 | 53 |

**[Observed, measured] event-family distribution over authored events:**
Sysmon 48, Windows Security 23, Proxy 20, DNS 13, Firewall 10, Azure AD 6,
Veeam 3, Defender 1.

**Runtime totals (with normal traffic) [Inferred]:** the runtime pool =
authored events + `generate_normal_event()` normals written at ~2/3 of a ~1/s tick
(2-3 normals per attack log). Therefore:
- **One Guided run**: ~6 authored events + normal traffic accruing for as long as
  the single incident is worked (unbounded until submit; normal writes stop once
  `injected_count >= queue_length` and `attack_queue` is empty). **[Inferred]**
- **Full 10-scenario queue**: ~60 authored events + normal traffic across the drip
  span (10 drips at 20-40s each, gated at 3 in-flight) plus chain drain.
  **[Inferred]** Order-of-magnitude ~150-300 total events by session end.
- **Observed data points (Stage 3.9B Chrome sweep, `SIEM` tab count):** a single
  Guided incident showed ~16-34; a SOC Queue session with 4 injected showed 184;
  Hardcore with 3 active showed ~90-136. These are **Observed** live counts;
  their authored/normal split is **Inferred**.

**Hard limits / pagination / rendering [Observed]:**
- `/api/fake-events`: **no** server limit/pagination (full pool each call).
- SIEM table pagination: 10/20/50 per page, default 20 (`SiemTable.jsx:17,:160`).
- SIEM cards: 12/page (`SiemCards.jsx:8`).
- Search input capped at 300 chars (`Siem.jsx:143`).
- Detection detail whitelists triggering events server-side.

**Known cost paths [Observed/Inferred]:**
- `/api/fake-events` reads the whole NDJSON and builds a `seen_ids` set + a full
  list every call (`app.py:2628-2634`) — O(n) per poll, every 2s
  (**[Observed]** repeated full-array scan).
- SIEM client filtering runs over the whole pool every render; the free-text term
  does `JSON.stringify(alert)` per event per keystroke/poll (`Siem.jsx:75`)
  (**[Observed]** repeated full serialization).
- `grouped-alerts` re-groups the whole pool and recomputes readiness per call
  (`app.py:4350-4451`) (**[Observed]**).
- `finalize_chain` rewrites the entire log file when a chain completes
  (`app.py:2529-2538`) (**[Observed]** full read+write).
- Event copying/duplicate materialization: supplemental logs are appended to the
  pool once; `fake-events` de-dups by `id` defensively (ids are unique uuids, so
  no real duplicates today — **Inferred**).

No optimization is proposed here.

---

## 11. Event identity and deduplication

**[Observed]**
- Client-facing event id: `log["id"] = str(uuid.uuid4())` set at drip
  (`app.py:2416` attack, `:2450` supplemental) and in `generate_normal_event`
  (normals also carry a uuid `id`, confirmed in the captured payload).
- **Not** derived from event fields; random uuid4 (not sequential, not hashed, not
  composite).
- Stable across polling and sorting **within a session** (written once to the
  NDJSON; reads never rewrite ids).
- Stable across incident scoping (the same id regardless of scope view).
- **Not** stable across reset / Practice Another (files truncated; a new run mints
  new uuids) and **not** stable across seeds/reruns (fresh uuids each drip).
  **[Observed]**
- Duplicate raw events: `fake-events` collapses by `id` (`seen_ids`,
  `app.py:2631`) — a defensive de-dup; because ids are unique uuids no genuine
  duplicates arise today (**Inferred**). Identical field+timestamp collisions are
  possible in principle (no field-based identity), but each still has a distinct
  uuid, so they are retained as distinct rows.
- Authoritative ordering field: none server-side beyond file write order;
  `timestamp` is the natural order; client tie-break `timestamp` desc then `id`
  (`SiemTable.jsx:40-41`).
- Event identity (uuid `id`) differs from detection identity (stable-key
  `detection_index` id, `app.py:2499`) and from incident identity
  (`INC-####` alert_id). **[Observed]**
- **Raw internal identifiers serialize:** `scenario_id` (internal
  `generate_scenario_id()`) is present on served attack events and normal events
  (Section 3.1). **[Observed][Unprotected]**

**[Unprotected]** No event family has an automated stable-identity guard; there is
no test asserting event-id stability, uniqueness, or the de-dup behaviour of
`/api/fake-events`.

---

## 12. Existing tests and protected invariants

Legend: **[Contract]** = named test directly guards it; **[Indirect]** =
guarded as a side effect; **[NoTest]** = implementation behaviour with no direct
guard; **[Unclear]**.

| Behaviour | Class | Test (file::name) |
|---|---|---|
| Detection serialization / disposition-strip | [Contract] | `test_detections.py::test_sanitize_strips_disposition_and_linkage`; `::test_whole_corpus_detections_sanitize_clean` |
| Detection triggering-events whitelisted | [Contract] | `test_detections.py::test_sanitized_triggering_events_are_whitelisted` |
| Supplemental events carry no answer fields | [Contract] | `test_detections.py::test_supplemental_events_never_carry_answer_fields` |
| Detection field-set indistinguishable across kinds | [Contract] | `test_detection_indistinguishability.py::test_exact_field_set_identical`, `::test_no_forbidden_or_kind_revealing_field`, `::test_id_format_uniform_across_kinds` |
| Detection order deterministic / not time-sorted / seed-varying | [Contract] | `test_detection_order.py::test_order_is_deterministic_within_a_session`, `::test_order_is_not_time_sorted`, `::test_order_differs_across_sessions`, `::test_not_authored_first_or_ambient_last`, `::test_order_is_independent_of_input_order` |
| Opaque detection ids resolve; internal key never serializes | [Contract] | `test_detections.py::test_scenario_detection_builds_and_carries_disposition`; `test_detection_indistinguishability.py::test_id_format_uniform_across_kinds` |
| Telemetry visibility / roster sealed before submit | [Contract] | `test_submission_gate.py::test_sealing_roster_blocks_submission`, `::test_completing_dispositions_enables_full_grade` |
| Roster finality (no growth on poll/unrelated activity) | [Contract] | `test_submission_gate.py::test_sealed_roster_finality_no_growth_on_poll_or_unrelated_activity`, `::test_no_detection_attaches_to_a_submitted_incident`, `::test_every_sealed_roster_detection_is_dispositionable_in_feed` |
| No grading disclosed before submission | [Contract] | `test_submission_gate.py::test_no_grading_surface_leaks_before_submission`, `::test_progress_shape_is_observable_activity_only`, `::test_incident_score_is_in_progress_before_submit` |
| Incident scope observable-only / structural guard | [Contract] | `test_incident_scope.py::test_scope_serializes_observable_fields_only`, `::test_scope_structural_no_grading_or_expected_actions`, `::test_observable_roster_matches_readiness_roster`, `::test_scope_withholds_roster_total_before_seal`, `::test_list_withholds_roster_total_before_seal` |
| Guided catalog leak-guard (no answer fields, opaque ids) | [Contract] | `test_guided_catalog.py::test_no_forbidden_keys_anywhere`, `::test_no_internal_label_or_category_in_values`, `::test_reviewed_language_denylist_clean`, `::test_field_whitelist_exact` |
| Frozen world time / snapshot | [Contract] | `test_snapshot_generator.py::test_frozen_time_and_system_block`, `::test_no_placeholders_leak`, `::test_public_view_strips_markers` |
| No wall clock in the response-action log | [Contract] | `test_actions.py::test_no_wall_clock_in_log_entries`, `::test_log_records_every_attempt_with_frozen_clock_sequence`, `::test_replay_determinism_byte_identical_logs` |
| Action-target rejection unlogged / foreign-session indistinguishable | [Contract] | `test_actions.py::test_api_rejects_invalid_targets_unlogged`, `::test_api_foreign_session_ids_indistinguishable_from_unknown` |
| Immutable evidence after kill (SIEM unchanged) | [Contract] | `test_actions.py::test_api_immutable_evidence_after_kill` |
| Parity / frozen scenario boundaries (chain content byte-identical, timestamps excluded) | [Contract] | `parity_check_v2.py`; `test_scenario_loader_v2.py::test_corpus_matches_v1_content`, `::test_no_static_values_in_v2_files`, `::test_load_is_deterministic` |
| Frontend SIEM: sanitize strips internal fields (display) | [Contract] | `siem.test.js::"sanitizeEvent strips every simulation-internal field"` |
| Frontend SIEM: presets anchor to pool clock | [Contract] | `siem.test.js::"time presets anchor to the pool clock, never wall time"` |
| Frontend SIEM: cards default / expand shows sanitized JSON / table toggle | [Contract] | `siem.test.js::"cards view renders by default..."`, `::"expanding a card shows sanitized JSON only"`, `::"table view toggle works and filters apply"` |
| Frontend no-mutation reads across scoped tabs | [Contract] | `scope-no-mutation.test.js::"select A, switch to B, clear to Session-wide..."` |
| Frontend client payloads carry no answer-key fields (detections) | [Contract] | `detections.test.js::"client payloads carry no answer-key fields"` |
| Frontend endpoint timeline tabs / isolate flow | [Contract] | `endpoints.test.js::"endpoint detail renders all tabs..."`, `::"isolate flow..."`, `::"remove persistence flow..."` |
| Submission-gated disclosure (event surfaces vs grading) | [Indirect] | `test_submission_gate.py` battery; SIEM/events are never grading surfaces |
| **`/api/fake-events` server-side field sanitization** | **[NoTest]** | none — raw payload carries `label/category/scenario_id/...` (Section 3.1) |
| **`/api/grouped-alerts` per-group answer-field non-leak** | **[NoTest]** | none — only readiness fields tested (`test_grouped_alerts_surface_incident_scoped_readiness`) |
| **Event content-timestamp determinism / ordering** | **[NoTest]** | none — parity ignores timestamps |
| **Event id stability / uniqueness / de-dup** | **[NoTest]** | none |
| **SIEM row/sort/refresh live-mutation behaviour** | **[NoTest]** | `siem.test.js` covers render/filter/sanitize, not insertion/re-order under polling |
| **SIEM incident-scope absence** | **[NoTest]** | not asserted either way |

---

## 13. Reuse-versus-retire observations (facts only; no decisions)

Labels are the only permitted verdicts: **likely reusable** / **reusable with
adaptation** / **appears superseded** / **unclear, requires contract decision**.

| Piece | Label | Factual basis |
|---|---|---|
| SIEM page shell (`Siem.jsx`) | reusable with adaptation | client-side filtering + polling + dropdowns; would need server-side query + snapshot semantics + scoping for Stage 4 |
| SIEM table (`SiemTable.jsx`) | likely reusable | generic sortable/paginated/expandable event table |
| SIEM cards (`SiemCards.jsx`) | likely reusable | generic event-card grid |
| `siemUtils.sanitizeEvent` (display whitelist) | reusable with adaptation | today a **client** whitelist; the leak (Section 3.1) implies a server whitelist is needed |
| `siemUtils.parseEventQuery` (search) | appears superseded | Splunk-style `field=value`; does not conform to the pinned LCQL grammar |
| dropdown filter controls (`Siem.jsx`) | unclear, requires contract decision | pool-derived Source/Platform/Type; not in the pinned grammar |
| time-preset controls (`siemUtils.TIME_PRESETS`) | reusable with adaptation | pool-anchored windows; TIMEFRAME segment overlaps |
| `/api/fake-events` (endpoint) | reusable with adaptation | serves the pool but unsanitized, unscoped, unpaginated |
| `/api/grouped-alerts` (endpoint) | appears superseded (for display) | per-group logs unrendered; only `.stats` consumed; still holds the analyst trigger logic |
| incident-scope API (`/scope`, `_incident_observable_scope`) | likely reusable | observable-only, structurally guarded |
| polling hooks (`Siem`/`Detections`/`Incidents` intervals) | reusable with adaptation | fixed intervals; Stage 4 wants explicit refresh + snapshots |
| endpoint timeline (`EndpointDetail` + `snapshot_generator`) | likely reusable | the only snapshot (non-polling) event-derived surface |
| event row component (`renderCleanEventDetails`) | likely reusable | field/kvp rendering with an exclusion list |
| raw-event JSON rendering (`SiemCards` `<pre>`) | likely reusable | renders `sanitizeEvent` output |
| current query input (`Siem.jsx` search box) | appears superseded | placeholder is Splunk-style `key=value`; not LCQL |
| sort controls (`SiemTable` `SORTABLE`) | likely reusable | column sort with stable tie-break |
| navigation structure (`Dashboard.jsx` tabs) | reusable with adaptation | internal Incidents key is still `grouped`; SIEM tab present |
| notable-evidence components | n/a (retired) | `GroupedAlerts`/`AlertTable` deleted |
| `CampaignProgress` (Metrics) | unclear, requires contract decision | still renders "N of total resolved" un-adapted to 3.9B modes (Section 2.4) |

---

## 14. Conflict and ambiguity register

1. **[Conflict/Unprotected]** `/api/fake-events` serves answer-adjacent fields
   (`label`, `category`, `scenario_id`, `threat_pattern`, `storyline`,
   `level_name`, `alert_id`) with no server sanitization and no test guard
   (Section 3.1, 11, 12). The frontend whitelist hides them from display only.
2. **[Conflict/Unprotected]** `/api/grouped-alerts` serves per-group `label`,
   `category`, `analyst_category`, `storyline`, and raw `logs`; only `.stats` is
   consumed; no leak guard (Section 3.2).
3. **[Conflict]** "Frozen scenario clock" (`siemUtils.js:73`,
   grammar-notes `:14`) vs event content timestamps = wall-clock-at-drip
   (`app.py:2399`) (Section 6). No event-timestamp determinism test.
4. **[Conflict]** The analyst-mode "triggered evidence arrival" trigger-only
   filter lives in `grouped-alerts` (`app.py:4401-4432`), but the rendered SIEM
   uses `fake-events` (full stream, no mode filter). In SOC Queue the full chain is
   visible in SIEM (Section 2.5, 5).
5. **[Conflict]** LCQL pinned grammar (`==`/`contains`/quotes/pipes) vs the
   implemented SIEM search (`field=value` substring). The search-box placeholder is
   Splunk-style (`Siem.jsx:140`) (Section 9).
6. **[Conflict]** Stage 3.9B commit claim "CampaignProgress is dead code (imported
   nowhere)" vs repository truth: `Analytics.jsx` imports and renders it
   (Section 2.4). Repository truth governs.
7. **[Conflict]** `log_writer` docstring "every 40-80 seconds" vs code 20-40s
   (`app.py:2543` vs `:2594`) (Section 5).
8. **[Conflict]** Attack vs normal event field shapes differ (`user_account`+kvp
   vs `user`/`process_id`/`protocol` top-level) (Section 4.3).
9. **[Ambiguity]** SIEM is session-wide with no incident scope; there is no
   incident-scoped raw-event endpoint (Section 7). Whether Stage 4 needs one is a
   contract decision (not decided here).
10. **[Ambiguity]** No new-events indicator / explicit refresh / snapshot freeze
    on the SIEM; rows move under the analyst (Section 8).

---

## 15. Open factual questions repository inspection could not answer

1. Runtime **total** event counts (authored + normal) for a full 10-queue at
   session end are duration-dependent and were not exhaustively measured; only
   authored counts (measured) and a few live SIEM counts (Observed in the 3.9B
   sweep) are recorded (Section 10). A deterministic total would require a fixed-
   duration live run.
2. The LCQL notes do not specify **unquoted** case behaviour, field-name syntax,
   whitespace/precedence rules for `and`/`or`, or valid/invalid example sets
   (Section 9). These are unspecified in the repository.
3. Whether any historical route besides `/analytics` mounts an event surface — no
   others found, but route discovery relied on `App.jsx` + `Dashboard.jsx`; there
   is no server-side route table for the SPA beyond these.
4. Whether normal events ever carry a non-null `scenario_id` — the captured sample
   showed the key present but null; a value could exist for some normal templates
   (not exhaustively verified across all `NORMAL_TRAFFIC_TEMPLATES`).
5. Exact `generate_normal_event` field set and volume rate per second were not
   directly read (inferred from the writer loop and the captured normal sample).

---

## 16. Appendix

### 16.1 Exact event endpoints (method, route, file:line)

- `GET /api/fake-events` — `app.py:2625`
- `GET /api/endpoints` — `app.py:2636`
- `GET /api/endpoints/<hostname>` — `app.py:2667`
- `GET /api/detections` — `app.py:2683`
- `GET /api/detections/<det_id>` — `app.py:2700`
- `POST /api/detections/<det_id>/disposition` — `app.py:2714`
- `GET /api/threats` — `app.py:2732`
- `GET /api/actions` — `app.py:2806`
- `POST /api/actions` — `app.py:2766`
- `GET /api/grouped-alerts` — `app.py:4347`
- `GET /api/incidents` — `app.py:3592`
- `GET /api/incidents/<id>/scope` — `app.py:3753`
- (non-event, for completeness) `submit`/`score`/`check-answer`/`triage-review`,
  `analytics/*`, `guided-catalog`, `game-state`, `reset-simulator`,
  `start-simulator`, `resume`, `reports*`, `current-level`, `health`.

### 16.2 `/api/fake-events` served top-level fields (measured)

- Attack: `alert_id, category, event_type, flagged, hostname, id, key_value_pairs,
  label, level, level_name, log_source, message, scenario_id, severity, source_ip,
  source_type, status, storyline, threat_pattern, timestamp, user_account`.
- Normal: `destination_ip, detected_by, event_type, flagged, hostname, id,
  key_value_pairs, label, message, parent_process_id, process_id, protocol,
  scenario_id, severity, source_ip, source_type, timestamp, user`.
- Display whitelist (`siemUtils.RAW_LOG_FIELDS`): `timestamp, event_type,
  source_type, severity, hostname, source_ip, destination_ip, user_account,
  message, key_value_pairs`.

### 16.3 All 30 event types (source :: type)

Azure AD :: `AADUserRiskEvents`, `SigninLogs`. DNS :: `QUERY`. Defender ::
`5007`. Firewall :: `ALLOW`, `DENY`. Proxy :: `FileSyncUploadedFull`,
`HTTP_CONNECT`, `HTTP_GET`, `HTTP_POST`, `SSL_HANDSHAKE_FAILED`, `SSL_INSPECT`.
Sysmon :: `FileCreate`(11), `NetworkConnect`(3), `ProcessAccess`(10),
`ProcessCreate`(1), `SetValue`(13), `WmiEventFilter`(19), `WmiEventConsumer`(20),
`WmiEventConsumerToFilter`(21). Veeam :: `110`, `190`. Windows Security ::
`1102`, `4624`, `4625`, `4663`, `4740`, `5140`, `6416`.

### 16.4 Complete authored kvp key union

`Activity, AppDisplayName, AuthenticationRequirement, ClientAppUsed,
ConditionalAccessStatus, DetectionTimingType, DeviceDetail, IPAddress,
IncomingTokenType, IsInteractive, Location, MitreTechnique, OperationName,
ResourceDisplayName, ResultType, RiskDetail, RiskEventType, RiskLevel,
RiskLevelDuringSignIn, RiskState, SignInCount, SignInEventType, TokenIssuerType,
UserPrincipalName, access_mask, accesses, account_domain, account_name, action,
app, authentication_package, bytes_backed_up, bytes_backed_up_human,
bytes_received, bytes_sent, bytes_uploaded, call_trace, caller_computer_name,
caller_process_id, caller_process_name, category, channel, class_id, class_name,
command_line, company, compatible_ids, computer, connection_result, consumer,
content_type, creation_utc_time, current_directory, description, dest_port,
destination, destination_hostname, destination_ip, destination_is_ipv6,
destination_port, destination_port_name, details, device_id, device_name,
domain_name, dst_ip, duration_seconds, dvc, event_id, event_level, event_log,
event_namespace, event_type, expected_cert_issuer, failure_count_last_hour,
failure_reason, file_count, file_version, filter, grant_type, granted_access,
handle_id, host, http_method, image, initiated, integrity_level, interval_minutes,
job_name, key_length, location_information, locked_out_security_id, logon_guid,
logon_id, logon_process, logon_type, message_type, name, new_logon_logon_id,
new_value, object_name, object_server, object_type, occurrence_count, old_value,
operation, original_cert_issuer, original_file_name, package_name,
parent_command_line, parent_image, parent_process_id, parent_user,
presented_cert_issuer, process, process_id, process_name, product, product_name,
product_version, protocol, query, query_type, reissued_cert_issuer, reply_code,
repository, repository_ip, resource_attributes, rule, rule_name, scheduled_time,
scope, security_id, server_cert_issuer, server_cert_subject, service,
share_local_path, share_name, site_url, source_hostname, source_image, source_ip,
source_is_ipv6, source_port_name, source_process_guid, source_process_id,
source_thread_id, source_user, src_ip, src_port, src_user, ssl_action,
ssl_inspected, ssl_policy, status, sub_status, subject_account_domain,
subject_account_name, subject_domain, subject_logon_id, subject_security_id,
subject_user_sid, target_account_name, target_domain_name, target_filename,
target_image, target_object, target_process_guid, target_process_id, target_user,
terminal_session_id, tls_alert, tls_alert_code, tls_version, transited_services,
transport, type, url, url_category, user, user_agent, vendor_ids,
workstation_name`.

### 16.5 Key test files cited (Section 12 has exact names)

Backend: `test_detections.py`, `test_detection_indistinguishability.py`,
`test_detection_order.py`, `test_submission_gate.py`, `test_incident_scope.py`,
`test_guided_catalog.py`, `test_snapshot_generator.py`, `test_actions.py`,
`test_scenario_loader_v2.py`, `parity_check_v2.py`. Frontend (`src/__tests__/`):
`siem.test.js`, `scope-no-mutation.test.js`, `detections.test.js`,
`endpoints.test.js`, `incidents-workspace.test.js`, `incident-dashboard.test.js`.

### 16.6 Relevant constants

`CONCURRENT_QUEUE_CAP = 3` (`app.py`). Guided queue length 1; SOC Queue / Hardcore
queue length 10. Drip interval: writer tick 1s; scenario drip 20-40s; ~2-3 normals
per attack log. SIEM poll 2s; Detections poll 2.5s; Incidents/Dashboard poll 3s;
Endpoints no poll.
