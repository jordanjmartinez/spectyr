# Pre-Stage-5 Hotfix Diagnosis: Submission-Readiness Roster Mismatch

**Status: DIAGNOSIS ONLY — no product code, tests, schemas, scenarios, readiness
logic, or UI behavior changed. Awaiting owner review and explicit fix
authorization.**

Date: 2026-07-22. Branch: `pre-stage-5-hotfix` (from `main` tip `b093483`).

---

## 0. Stage 4 merge-record closure

| Item | Value |
|------|-------|
| Stage 4 merge commit | `a8632648f57230d61b92ad6ce597dc4e349bfb2c` — "Stage 4 closure: merge SIEM Investigation Workbench + LCQL (eb49610..e7f6e9e)" (merge commit; parents `ccdaeaa7b56c350bb6c66fe0032f0417d4663dba` + `e7f6e9e737c3d566d80a1b7fd4ec177ede436bab`) |
| Current `main` tip | `b093483c3b29186e2e39a90dd3a5ae7ebac1d280` — "Stage 4 baseline record: a863264 is the reviewed product-merge baseline (docs-only)" |
| Current branch | `pre-stage-5-hotfix`, created from `main` tip `b093483` (see environment note below) |
| `git status` | `M frontend/public/videos/spectyrvideo.mp4` (modified, uncommitted); `?? frontend/public/spectyr_svg.svg` (untracked). Both unrelated working-tree items; carried, not committed. |
| Reviewed Stage 4 branch tip on main | CONFIRMED: `git merge-base --is-ancestor e7f6e9e main` → ancestor |
| Stage 4 closing artifact on main | CONFIRMED: `ba556c5` is an ancestor of `main`; `docs/stage-4-implementation-report.md` present at `main` (`git cat-file -e main:docs/stage-4-implementation-report.md`) |

**Environment blocker (disclosed):** at diagnosis time the primary repository
`C:\Users\Spectyr` — including `.git` — is read-only to the unelevated user
token (`.git` DACL grants BUILTIN\Users read/execute only; owner is
HERMES\Jordan; only SYSTEM/Administrators hold write). Every git write fails
with `Unable to create .git/index.lock: Permission denied`, and an ACL repair
was blocked by the tool-permission classifier. The `pre-stage-5-hotfix` branch
was therefore created in a full clone of the repository (clone of `main` at
`b093483`) in the session scratchpad; all reproduction ran there against
byte-identical code. To land this branch in the primary repo once write access
is restored (elevated shell, or owner-run
`icacls C:\Users\Spectyr\.git /grant "HERMES\Jordan:(OI)(CI)F" /T`):
`git switch -c pre-stage-5-hotfix main`, then copy this document in.

---

## 1. Summary and proven root cause

Two different functions compute "this incident's detections," and they join
ambient (untagged) detections over two different host sets:

- **Every player-visible surface** (incident card, Ready label, Submit button,
  "X of Y reviewed" phase strip, incident-scoped Detections view, Related
  hosts, Evidence-Timeline descent) reads
  `_incident_observable_scope` (`backend/app.py:3850`), whose host set is
  **observable participants**: hostnames on the incident's *written events*
  plus entity hosts of its *scenario-tagged detections*
  (`app.py:3870-3872`).
- **The submission gate and the grade** read `_incident_detections`
  (`backend/app.py:3358`), whose host set is
  `grading_rec["hostnames"]` — **every host declared in the scenario's
  `environment.hosts`** (`scenario_grading_record`, `app.py:4232`, recorded at
  drip, `app.py:2583-2584`).

Both apply the identical ambient-join predicate
(`d["scenario_id"] is None and d["entity"]["host"] in hosts`) — to different
`hosts`. The rosters coincide **only** when every environment-declared host is
observable. Scenarios that declare hosts which never appear as any event's
`hostname` break the premise: ambient benign detections materialized on those
hosts at drip (`app.py:2550-2559`) are **in the readiness/grading roster but
in no player-visible incident scope**. `password_spray` is the guaranteed
manifestation: its `ws_victim` (the resolved employee's workstation — the
reported ACME-WS27/owilson) and `backup` hosts are environment-declared, but
every authored event carries the DC hostname (ACME-SVR01); workstations always
draw ≥1 ambient detection (`detection_templates.benign_detections_for_host`,
lo=1 for role `workstation`, `detection_templates.py:239`), including
`chrome_updater` = **"Software Updater Outbound Connection"**
(`detection_templates.py:48`) — the exact detection reported on INC-1310.

Both computations, and the equality test that was supposed to pin them
together, landed in the same commit `7b9d8f7` ("Stage 3.9A/3.9B backend:
submission boundary + observable presentation reads"). The divergence has
existed since Stage 3.9 and survived Stage 4 unchanged; the invariant test
passed because its fixture hand-aligns the two host sets (Section 6).

The mismatch is **static from drip** — nothing grows after sealing (Section 4;
sealed-roster finality and submitted-record immutability both held).

---

## 2. Reproduction (real product path, deterministic)

Harness: `backend/repro_pre_stage5.py` (diagnosis artifact in the clone only,
never product code). It uses only product code paths, in the writer thread's
exact order, with no hand-rolled session state:

1. Real API session via `/api/health` (full session bootstrap).
2. Field-for-field replica of `start_simulator` state for
   `{game_mode: "guided", catalog_id: cat(password_spray)}` via
   `build_guided_queue` (no writer thread, so no races).
3. `build_attack_chain_logs(s, entry, employee=owilson)` — the real drip
   (`log_writer`'s call at `app.py:2650` with the employee forced to owilson →
   workstation **ACME-WS27**, the reported configuration; `app.py:1015`).
4. Chain written through `append_pool_event`, then `finalize_chain`, then
   `chain_complete_at` stamped — mirroring `app.py:2666-2681`.
5. Player triages **exactly the displayed roster** via
   `POST /api/detections/<id>/disposition`.
6. Submit; then disposition the hidden detections via the session-wide feed;
   submit again; inspect the stored record.

### Reproduced session (INC-7972; full JSON in scratchpad `repro_run.json`)

Session `e6a61dd7-76d1-4a29-8857-85269057343a`, scenario
`52dd81c1-e06d-4e20-9ca4-9ca2c4a3eef8` (password_spray), victim owilson /
ACME-WS27.

**Timeline:**

| T | Event |
|---|-------|
| `t_drip` = 2026-07-23T00:28:05.211Z | Drip. All 6 detections materialize synchronously inside `build_attack_chain_logs`'s locked block, **before any chain event is written**: 3 scenario-tagged (entity host ACME-SVR01) + 3 ambient (`scenario_id: null`): `det-08e98fc36411` "Software Updater Outbound Connection" on **ACME-WS27/owilson**, `det-1675b9827c0e` "Backup Agent Periodic Beacon" and `det-c292700478d1` "Backup Agent Bulk File Read via Shadow Copy" on ACME-VEEAM01/svc_backup. `benign_hosts` = {ACME-SVR01, ACME-VEEAM01, ACME-WS27}. Grading record hostnames = {ACME-SVR01, ACME-VEEAM01, ACME-WS27}. |
| pre-seal | `POST submit` → 409 `{"reason": "sealing"}` (correct). |
| `t_seal` = 2026-07-23T00:28:05.221Z | Chain fully written, `chain_complete_at` stamped. |

**The two rosters at seal (and unchanged at submit):**

| Roster | Hosts used for ambient join | Detection ids |
|--------|------------------------------|---------------|
| Displayed (`_incident_observable_scope`) | `["ACME-SVR01"]` | `det-0f80e3450b5d, det-1eea4cc04344, det-5ce2bf6e2043` (size 3) |
| Readiness/grading (`_incident_detections`) | `{ACME-SVR01, ACME-VEEAM01, ACME-WS27}` | those 3 **plus** `det-08e98fc36411, det-1675b9827c0e, det-c292700478d1` (size 6) |

**Player-visible sequence (API responses captured):**

- Card after triaging the 3 displayed detections:
  `{"sealed": true, "ready": true, "open_detections": 0, "triage": {"total": 3, "triaged": 3}}` → UI shows **Ready**, phase strip "3 of 3 reviewed", **Submit enabled**.
- Same instant, `GET /api/incidents/INC-7972/score` (in-progress progress, grading-side):
  `{"detections_triaged": 3, "detections_open": 3, "submission_ready": false}` — two live API surfaces disagree in the same poll cycle.
- `POST submit` while the card says Ready → **409**
  `{"error": "3 detections still need review.", "reason": "open_detections", "open_detections": 3}`.
  (Server template `app.py:3810` renders n=1 as "1 detection still need review." — byte-identical to the INC-1310 report.)
- All 3 hidden detections are present and dispositionable in the session-wide
  `/api/detections` feed (`hidden_in_session_wide_feed: true`) — exactly the
  player's workaround on INC-1310.
- After dispositioning them session-wide: `POST submit` → **200 submitted**.

**Stored immutable record:** `inputs.detection_dispositions` contains all 6
ids including the 3 hidden; `report_card.detection` = `{correct: 4, wrong: 2,
graded: 6, total: 6, accuracy: 66.7}` — the incident was **gated and graded
over 6 detections while every incident-scoped surface showed 3**.

**Finality checks:** observable roster and readiness roster both byte-identical
post-submit (`no growth`). The count difference vs the report (INC-1310 showed
"4 of 4" and one hidden detection; INC-7972 showed "3 of 3" and three hidden)
is stable-key draw variance only — DC/backup hosts draw 0–2 ambient per
session (`benign_detections_for_host`), and previously-dispositioned ambients
don't re-block; the mechanism is identical, and the WS27 workstation ambient is
guaranteed (lo=1).

---

## 3. Q1 — Observable participant scope

- **Was ACME-WS27 in INC-1310's observable participant-host scope at seal
  time?** No. For password_spray every authored event's `hostname` is
  `{infra.dc.hostname}` → ACME-SVR01 (chain and supplementals,
  `scenarios/v2/password_spray.yaml`), and the tagged detections' entities
  resolve to accounts/the DC — so observable hosts = `["ACME-SVR01"]`
  (reproduced: `observable_scope_at_seal.hosts`).
- **At submit time?** Still no — proven identical post-submit
  (`observable_roster_post_submit_identical: true`).
- **Mechanism that allowed scope to grow after sealing:** none — the scope
  never grew. ACME-WS27 was in the **readiness scope from drip onward**
  (`scenario_grading` hostnames = environment hosts, recorded at
  `app.py:2583-2584`), and its ambient detection materialized at INC-1310's own
  drip (`app.py:2550-2559`), before sealing. The defect is a **constant
  disagreement between two scope definitions**, not post-seal growth.
- **Distinctions:** *incident-owned* (scenario-tagged) detections are in both
  rosters; *ambient* detections (`scenario_id: null`) are host-joined, and the
  host set differs per consumer; *roster inclusion* for readiness/grading uses
  environment hosts; *scope visibility* (everything the player sees) uses
  observable hosts; *readiness gating* follows the readiness roster, not the
  visible one.

## 4. Q2 — Displayed roster versus submission gate

- **"4 of 4 reviewed" count:** `_incident_observable_scope` (`app.py:3850`) →
  `roster_ids`/`roster_size`/`triaged` → served by `GET /api/incidents`
  (`list_incidents`, `app.py:3965-3973`, `card["triage"]`) and
  `GET /api/incidents/<id>/scope` (`app.py:4104-4105`) → rendered by the phase
  strip `${t.triaged} of ${t.total} reviewed` (`Incidents.jsx:23`, used at
  `:240-241`). The incident-scoped Detections list filters the feed to
  `scope.detection_ids` (`Detections.jsx:127-129`).
- **Ready state + Submit enablement:** same observable scope →
  `card["ready"] = triaged == total` (`app.py:3973`) → `Incidents.jsx:212`
  (Ready label), `:291-293` (Submit button rendered only when
  `selected.sealed && selected.ready`), `:111` (pre-flight check).
- **Submit-time validation:** `POST /api/incidents/<id>/submit`
  (`submit_incident_route`, `app.py:3787`) → `submit_incident`
  (`app.py:3503`) → `_grading_record_for` (`app.py:3353`) →
  `incident_submission_readiness` (`app.py:3489`) →
  `_incident_open_detections` (`app.py:3469`) → `_incident_detections`
  (`app.py:3358`) joining ambient on `grading_rec["hostnames"]`
  (= environment hosts, `scenario_grading_record` `app.py:4225-4235`).
- **Same roster/scope snapshot?** No. The card/phase-strip/Submit-button chain
  and the gate consume different rosters. **First divergence point:** the host
  set fed to the ambient-join predicate — `app.py:3870-3871` (observable
  events + tagged entities) vs `app.py:3361` (`grading_rec["hostnames"]`). The
  predicate itself (`app.py:3366` vs `app.py:3885-3887`) is identical.
- Additional divergent pair: `_incident_progress` (`app.py:3615`, the /score
  in-progress view) sits on the grading side, so it contradicts the card in
  the same poll cycle (reproduced above).

## 5. Q3 — Detection timing

The ACME-WS27 ambient detection materialized **at INC-1310's own drip start**,
synchronously inside `build_attack_chain_logs`'s locked block
(`app.py:2542-2559`) — *before* the first chain event was written and
therefore **before** `chain_complete_at`. Reproduced: all 6 detections present
at `t_drip` 00:28:05.211Z; seal at 00:28:05.221Z. It was **present before
sealing and omitted from the displayed roster the entire time** — not late
materialization, not post-seal eligibility. Timestamps, host sets, roster
contents, and detection ids: Section 2 tables (`detections_at_drip`,
`benign_hosts_at_drip`, `observable_scope_at_seal`,
`readiness_roster_ids_at_seal`, `hidden_gate_only_detection_ids`).

## 6. Q4 — Ambient roster join semantics

- Readiness/grading inclusion uses **none of** "participant hosts visible at
  seal time", "current live observable scope", or "session-wide open list": it
  uses the **scenario's environment-declared host set frozen at drip** —
  `_incident_detections` `app.py:3366` over `grading_rec["hostnames"]`, filled
  by `scenario_grading_record` `app.py:4232`
  (`{h["hostname"] for h in concrete_env.get("hosts", [])}`) at
  `app.py:2583-2584`.
- The *display* join (`app.py:3885-3887`) uses observable participant hosts.
- **Can one ambient detection join several incident rosters?** Yes, on both
  sides: ambient instances are materialized once per host per session
  (`benign_hosts` gate, `app.py:2553-2555`) and joined by host membership, so
  any incident whose (env / observable) host set contains that host includes
  the same instance, and **one disposition satisfies every roster** (single
  `player_action` on the shared instance) — matching
  docs/submission-boundary.md:92-94 ("a shared host's ambient benign is
  dispositioned once and counts for every incident that scopes it").
- Per the instruction not to presume the fix: the proven mechanism is the
  **join-key divergence** (environment hosts vs observable hosts), not
  seal-time-vs-live filtering — no live/seal-time drift exists (Section 3).

## 7. Q5 — Test gap

- **The test that should have caught it:**
  `test_incident_scope.py::test_observable_roster_matches_readiness_roster`
  (line 115) — its docstring is the recorded invariant: "The observable roster
  equals the readiness roster (`_incident_detections`), so the Triage 'X of Y'
  is consistent with the submission gate."
- **Why its fixture missed it:** `_seed` (`test_incident_scope.py:37-64`)
  hand-builds `scenario_grading` with `"hostnames": {WS}` — **defined equal to
  the observable event host**. With the two host sets forced identical, the
  equality is true by construction. The fixture's "unrelated" ambient sits on
  ACME-WS99, outside *both* sets, so it exercises only the case where the two
  joins agree. The same aligned shape is used by every submission-gate fixture
  (`test_submission_gate.py::_add_incident`, lines 52-107: grading hostnames =
  {the single event host}; all detections' entities on that host) — so
  `test_remaining_count_and_readiness_are_incident_scoped` (:431),
  `test_incident_cards_surface_incident_scoped_readiness` (:494),
  `test_sealed_roster_finality_no_growth_on_poll_or_unrelated_activity`
  (:517), `test_no_detection_attaches_to_a_submitted_incident` (:555), and
  `test_every_sealed_roster_detection_is_dispositionable_in_feed` (:586) all
  pass and all genuinely hold — none constructs a grading-scope host without
  observable events. No fixture ever runs the real
  `scenario_grading_record(concrete_env)` against a real scenario environment.
- **The missing fixture is:** an ambient detection on a host that is
  **environment-declared (grading scope) but never observable** in the
  incident's written events or tagged-detection entities. Of the offered
  taxonomy it is the "mismatch between incident-scoped and Session-wide reads"
  arising from a **scope-source divergence present from seal** — NOT an
  unrelated host (the host is claimed by this scenario's own environment), NOT
  a host entering scope after seal, NOT late materialization.

## 8. Q6 — Recorded invariant violations

Violated:

1. **"Observable roster equals readiness roster"** —
   `test_incident_scope.py:115-118` docstring (quoted above) and
   `docs/stage-4a-repository-inventory.md:555` ("Roster == readiness roster:
   `test_observable_roster_matches_readiness_roster`"). **Falsified at
   runtime** (Section 2: 3 vs 6).
2. **Displayed count / Ready / Submit gate agreement** —
   `docs/submission-boundary.md:100-103`: "The grouped-alerts group carries
   observable readiness … so the frontend can block Submit before the
   round-trip; the backend enforces **the same rule** authoritatively, so a
   stale client count still 409s." The premise "the same rule" is false — the
   client blocks on the observable roster, the backend enforces the grading
   roster; the 409 here is not staleness but a different rule.
3. **"Unrelated detections do not gate the incident"** (player-facing
   semantics) — recorded as per-incident scoping in
   `docs/submission-boundary.md:92-93` ("Detections from other incidents never
   affect readiness") and CLAUDE.md §Submission Boundary ("readiness is
   per-incident (other incidents' open detections never gate this one)").
   *Technically* the WS27 ambient is not another incident's detection — it is
   claimed by INC-1310's own environment scope — so the letter of this rule
   held; but every player-visible definition of "this incident" excluded it,
   so the observable contract the rule describes is violated in effect.

Held (verified, no violation):

4. **Readiness uses the authoritative incident roster** —
   `docs/submission-boundary.md:90-92`: "The incident's roster is its
   authoritative server-side set (`_incident_detections` = its scenario-tagged
   detections plus ambient-benign detections on its hosts), NOT whatever the
   UI currently shows." The gate did exactly this; the defect is that "its
   hosts" means environment hosts server-side but observable hosts on every
   display surface.
5. **Sealed-roster finality** — `docs/submission-boundary.md:80-84`;
   `test_sealed_roster_finality_no_growth_on_poll_or_unrelated_activity`.
   Reproduction: both rosters byte-identical from seal through post-submit.
6. **Submitted-record immutability** —
   `test_no_detection_attaches_to_a_submitted_incident`;
   `docs/submission-boundary.md:82-84`. Held (Section 9).

## 9. Q7 — Submitted-record blast radius

Proven on the reproduced session's stored record (INC-7972) and the grading
call path (`submit_incident` `app.py:3536-3557` → `_incident_report_card`
`app.py:3399-3447` → `_incident_detections` → `compute_detection_score`):

- **Gated against a readiness set different from its displayed sealed
  roster:** YES — gate demanded 6, display showed 3 (Section 2).
- **Graded against a roster different from the one shown:** YES —
  `report_card.detection.graded = 6` vs displayed roster size 3;
  `inputs.detection_dispositions` contains all three hidden ids
  (`hidden_ids_in_graded_record`). The gate and the grade use the SAME roster
  (`_incident_detections` both times), so every submitted record is complete
  and internally consistent — readiness forces the hidden detections to be
  dispositioned before the record exists. But the player was graded on
  detections that no incident-scoped surface ever attributed to the incident
  (a player who *promoted* the invisible WS27 benign would lose detection
  accuracy on a detection "not in" their incident).
- **Immutable record affected by post-seal ambient join or scope change:**
  NO — no post-seal join exists: every grading-scope host's ambient set is
  materialized at the incident's own drip (all non-`NON_ENDPOINT_ROLES`
  environment hosts, `app.py:2550-2559`), `benign_hosts` blocks re-attach,
  `NON_ENDPOINT_ROLES` hosts ({firewall, proxy}, `snapshot_generator.py:90`)
  never materialize ambient at all, and both rosters were proven identical
  post-submit. The frozen record also snapshots dispositions at submit
  (`app.py:3551`), independently guarded by
  `test_no_detection_attaches_to_a_submitted_incident`.

Consequence for existing sessions: any previously submitted incident of an
affected scenario (Section 10 list) carries hidden-roster detections in its
immutable record. Records are in-memory-only and session-scoped (cleared on
reset, discarded on restart), so there is no persistent corrupted store.

## 10. Q8 — Other affected surfaces, and corpus scope

Surface-by-surface (which detection collection each reads):

| Surface | Reads | Affected? |
|---------|-------|-----------|
| Incident-scoped Detections view | `scope.detection_ids` (observable) — `Detections.jsx:127-129` | YES — hides gate-relevant detections |
| Feed / Threats counts | session-wide `s["detections"]` (`/api/detections`, `/api/threats`) | No — session-wide by design; hidden detections visible and dispositionable here (reproduced `hidden_in_session_wide_feed: true`) |
| Phase strip ("X of Y reviewed") | card `triage` (observable) — `Incidents.jsx:23,240` | YES — reads complete while the gate wants more |
| Ready label | card `ready` (observable) — `Incidents.jsx:212` | YES |
| Submit-button enablement | card `sealed && ready` (observable) — `Incidents.jsx:291`, pre-check `:111` | YES |
| Submit-time error message | server readiness (grading roster) — `app.py:3810` | Authoritative side; its count can exceed anything visible in incident scope (the confusing-but-accurate "N detections still need review") |
| Post-Incident Review | stored record grading (grading roster) — `openReview` → `/score` submitted | YES (presentation): detection section reports `graded: 6` vs the 3 the incident view showed |
| Submitted incident's immutable record | grading roster, frozen at submit | Internally consistent and immutable; basis differs from what was displayed (Section 9) |
| Session Performance / Incident Grade | `aggregate_submitted` over stored records (`app.py:3661`) | Inherits the grading-roster basis; consistent with records, inconsistent with pre-submit display |
| Per-incident `/score` in-progress progress | `_incident_progress` (grading roster, `app.py:3615-3634`) | YES — `detections_open: 3` / `submission_ready: false` while the card said 0 / Ready (same poll cycle, reproduced) |
| Endpoints "This incident" filter | `scope.hosts` (observable) — `Endpoints.jsx:95` | Same seam: ACME-WS27's endpoint never listed for the incident |
| Open Evidence Timeline descent | `scope.hosts` (observable) — `Incidents.jsx:256-266` | Same seam: descent queries exclude the grading-only host |

**Corpus sweep** (`backend/sweep_scope_gap.py` in the clone; real drip per
scenario, forced employee owilson): 13/20 scenarios have grading-only hosts,
but 9 of those involve only ACME-SVR06 (role `proxy` ∈ `NON_ENDPOINT_ROLES`)
which can never carry ambient detections — structurally divergent but cannot
manifest. The scenarios that CAN manifest the defect:

| Scenario | Grading-only ambient-capable hosts | Manifestation |
|----------|-------------------------------------|---------------|
| `password_spray` | ws_victim workstation (**guaranteed ≥1 ambient**), ACME-VEEAM01 (0–2) | **Always** (the INC-1310 case) |
| `brute_force_attack` | ACME-VEEAM01 (0–2, stable-key) | Seed-dependent (manifested in the sweep seed: 4 displayed vs 5 readiness) |
| `false_positive_veeam` | ACME-VEEAM01 (0–2) | Seed-dependent (manifested in sweep seed: 5 vs 6) |
| `false_positive_robocopy` | ACME-SVR02 file server (0–2) | Seed-dependent (0 in sweep seed) |

(Side observation, not this defect: `false_positive_robocopy`'s observable
hosts include the literal string `10.0.1.201` — an event carries an IP in its
`hostname` field. Worth a separate content flag.)

## 11. Proven root cause (one sentence)

Stage 3.9B's player-facing incident scope (`_incident_observable_scope`,
deliberately answer-key-free and structurally barred from reading
`scenario_grading`) and Stage 3.9A's readiness/grading roster
(`_incident_detections` joining ambient detections over environment-declared
hostnames) implement the incident's "own hosts" differently, so for scenarios
whose environment declares hosts that never appear in observable telemetry
(guaranteed: `password_spray`'s victim workstation), drip-time ambient benign
detections on those hosts are readiness- and grading-relevant while being
excluded from every displayed roster, count, Ready state, and Submit gate —
introduced together in commit `7b9d8f7` and never caught because the equality
test's fixture hand-aligns the two host sets.

## 12. Minimal proposed fix (NOT implemented — for review)

Change ONE join input, at one choke point: make `_incident_detections`
(`app.py:3358`) join ambient detections over the incident's **observable
participant hosts** — the identical derivation `_incident_observable_scope`
already uses (written scenario events' hostnames + tagged detections' entity
hosts) — instead of `grading_rec["hostnames"]`. Concretely, extract the
observable host-set/roster derivation into a single shared helper consumed by
BOTH `_incident_observable_scope` and `_incident_detections`, so display,
readiness, progress, and grading are equal **by construction** rather than by
parallel implementations. `scenario_grading` remains untouched for its actual
purpose (response-action collateral scoping and isolation end-state — NOT
part of this fix).

Direction justification: the alternative (displaying the grading roster)
would disclose environment scope the player has no evidence for — e.g., that
the victim's workstation participates before any visible telemetry says so —
violating the C1 observable-attribution principle and A2's "no roster-derived
total before every roster detection is player-visible" intent. Narrowing the
server join to observable hosts moves server knowledge toward player-visible
data, never the reverse; no leak surface is created.

**Permanent regression fixture (with the fix):**

1. Unit (exact escaped configuration): extend `test_incident_scope.py::_seed`
   with a grading record whose hostnames include an environment-only host
   (e.g., `{WS, "ACME-WS27"}`) plus an ambient detection on that host with no
   written event — `test_observable_roster_matches_readiness_roster` then
   fails on today's code and passes with the fix.
2. Corpus gate (mechanism, seed-independent): a new test that real-drips every
   catalog scenario (the `sweep_scope_gap.py` harness pattern: session
   bootstrap → `build_guided_queue` → `build_attack_chain_logs` → write →
   seal) and asserts `set(_incident_observable_scope(s, inc)["roster_ids"]) ==
   {d["id"] for d in _incident_detections(s, scen, grec)}` — `password_spray`
   reproduces the exact INC-1310 mechanism on every seed (workstation ambient
   guaranteed), the others cover the seed-dependent hosts. Add to
   `run_gates.py`.

**Risks of the proposed fix:**

- **The accepted gating rule is preserved, not broken:** "ambient detections
  on observable participant hosts may gate readiness" is exactly what the join
  becomes; shared-host semantics (one ambient in several rosters, one
  disposition satisfies all) continue via observable-host overlap. What
  changes is only that ambient on *never-observable* environment hosts stops
  gating and stops being graded — it remains in the session-wide feed as
  triage material.
- **Detection-score denominators shift** for the four affected scenarios
  (e.g., INC-7972: graded 6 → 3), so per-incident detection accuracies and any
  recorded illustrative numbers involving those scenarios change; Stage 3d
  response baselines (20×5) are response-only and unaffected, but the fix
  commit must re-verify the detection-score gates and disclose any recorded
  detection-distribution deltas.
- **Readiness becomes strictly easier** (never demands invisible work) — this
  is the intended behavior change; Hardcore/SOC Queue difficulty via
  detections is unchanged for all observable rosters.
- **Empty-observable-host edge:** a hypothetical future scenario with no
  hosted events would get a tagged-only roster — acceptable; note for
  authoring review.
- **No structural-guard conflict:** the observable side still never reads
  grading inputs (`test_scope_structural_no_grading_or_expected_actions`
  unaffected); the grading side reading the written pool adds negligible I/O
  already performed by every `/api/incidents` poll.
- **Submitted-record schema unchanged**; already-submitted in-memory records
  are not rewritten (session lifecycle moots them, as in 3.9A closure).

## 13. Deliverable inventory

- This document.
- Repro harness: clone `backend/repro_pre_stage5.py`; full captured run:
  scratchpad `repro_run.json` (session `e6a61dd7…`, INC-7972).
- Corpus sweep: clone `backend/sweep_scope_gap.py`; output: scratchpad
  `sweep_output.json`.
- No product file modified anywhere.

**STOP.** Per instruction, no fix is implemented. After diagnosis approval the
fix lands as one concern-level commit with regression fixtures (unit +
corpus gate), the full backend and frontend battery, and Chrome verification
of the exact INC-1310 configuration (Guided password_spray, triage
incident-scoped only, observe Ready+Submit, expect no 409). The hotfix merges
separately into `main` after review; Stage 5 branches only after the hotfix
is merged.
