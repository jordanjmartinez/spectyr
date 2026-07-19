# Stage 3.9B — Modes Mini-Spec (A4)

For owner approval BEFORE build step 3. Steps 1 and 2 (Dashboard + Submit/
Resume/Review boundary; Incident Grade vs Session Performance) are built against
the locked scaffold and do not depend on this document. This spec covers only
what build step 3 (modes) needs defined. Nothing here changes scoring, grading,
readiness, sealing, or the submission-record schema.

## 1. Modes (A5, ratified): three total

| Mode | From | Intake | Assistance | Pressure |
|---|---|---|---|---|
| **Guided** | `training` | player picks one scenario (or Random) | Check Answer (Guided allow-list) | none, unlimited time |
| **SOC Queue** | `analyst` | timed drip push of the sampled queue | none | none, unlimited time |
| **Hardcore** | `hardcore` | timed drip push | none | session timer + wrong-submit-ends-run |

`chain_complete_at` sealing, the per-incident telemetry drip
(`build_attack_chain_logs` -> `finalize_chain`), and the readiness gate
(`incident_submission_readiness`) are the SAME code for all three modes.
Confirmed: a mode never alters sealing or readiness — they are mode-independent.

## 2. Guided intake flow (B2)

1. Select Guided -> a **catalog picker** appears: the full 20-scenario catalog
   plus a **Random** option.
2. Player picks exactly one (or Random) -> `POST /api/start-simulator`
   `{game_mode: "guided", catalog_id: "<opaque>" | "random"}`.
3. The backend builds a queue of **exactly one** scenario (the chosen one, or a
   uniform-random pick), `queue_length = 1`. The opaque `INC-####` is assigned
   when that single incident is created at drip, never before.
4. The single incident drips its telemetry **immediately** (no drip timer, no
   concurrency cap needed for one), seals on `chain_complete_at`, and is gated by
   the unchanged readiness rule. No further incidents arrive during the run.
5. Player triages / investigates / responds -> Submit -> Review.

**Relationship to drip start:** SOC Queue / Hardcore schedule drips on the
20-40s timer under `CONCURRENT_QUEUE_CAP`; Guided has a single incident that
drips at once. Same per-incident drip mechanics; only the queue scheduling
differs.

## 3. Guided post-Review flow + Session Performance (OWNER RULED 2026-07-19)

Ruled (supersedes the earlier sequential-aggregation proposal):
- **One Guided incident is one independent run.**
- **Practice Another** returns to the answer-neutral picker THROUGH A FRESH
  SIMULATION RESET. Prior world mutations never carry into the next practice
  incident.
- Because reset clears session submissions, **Practice Another first WARNS**
  that the current Guided run -- its submitted incident record AND its
  Post-Incident Review -- will be cleared before it proceeds.
- **Guided Session Performance equals the current run's Incident Grade** (one
  submitted incident, so the aggregate is that incident).
- Cross-run history and aggregate Guided performance are DEFERRED until
  persistent history is deliberately designed (BACKLOG note 1).

Implementation note for step 3: Practice Another calls the existing
`reset-simulator` (clearing submissions/world) then re-opens the picker; no new
persistence is introduced.

## 4. Sanitized picker payload + permanent leak guard

`GET /api/guided-catalog` returns:

```jsonc
{ "catalog": [
    { "catalog_id": "cat-<opaque>",   // opaque; NOT scenario_id
      "title": "Event Logs Cleared on Workstation",
      "severity": "Critical",
      "description": "<short, symptom-oriented, answer-neutral>",
      "difficulty": "medium"          // optional; may be null
    }, ... ],
  "random_available": true }
```

Permanent leak-guard test (`test_guided_catalog.py`): for all 20 entries the
payload contains NONE of `category`, `scenario_id`, `label`, `answer_key`,
`disposition`, `classification`, `verdict`, or any tactic/technique id; every
`catalog_id` is opaque and resolves server-side only. Selection addresses the
opaque `catalog_id`; the internal scenario id and answer key never serialize.

## 5. C4 catalog-neutrality prose pass

Before step 3 ships, an explicit owner/reviewer read of all 20 catalog
**titles and short descriptions** confirms none reveals the classification the
player must make: no verdict words ("false positive", "benign", "malicious"), no
attack category, no technique name; descriptions are symptom-oriented (what was
observed), matching what a SOC analyst sees on a ticket. The payload leak test is
necessary but does not replace this prose review. Deliverable: a short neutrality
sign-off checklist alongside the authored descriptions.

## 6. Submission, the in-flight slot, and the Completed section

- **Submission frees an in-flight slot (SOC Queue / Hardcore).** The drip gate is
  `in_flight = injected_count - resolved_count < CONCURRENT_QUEUE_CAP`. Submit
  (`submit_incident`) increments `resolved_count`, so a submitted incident stops
  counting as in-flight and the next queued incident may drip. This is the
  existing, unchanged behavior; no scoring/queue change is introduced.
- **The Completed section does not interact with the queue cap.** Completed cards
  are a presentation of submitted (resolved) incidents; they are never in-flight,
  so they never consume a `CONCURRENT_QUEUE_CAP` slot. The Dashboard's Active
  section shows the in-flight set (<= 3 in SOC Queue/Hardcore, exactly 1 in
  Guided); Completed grows without bound and is purely presentational.
- Guided has `queue_length = 1` and no cap interaction (one incident at a time);
  under sequential practice each new selection is a fresh single incident after
  the prior one is submitted.

## 7. What step 3 will build (once this is approved)

- `DifficultySelector` renamed options: Guided / SOC Queue / Hardcore, with the
  Guided catalog picker (answer-neutral payload).
- Backend: `GET /api/guided-catalog` (sanitized) + Guided one-scenario intake in
  `start_simulator` (opaque `catalog_id` -> one incident); rename the
  `analyst`-mode trigger-only handling to "triggered evidence arrival"
  (framing/comments; logic unchanged, already non-grading and submission-gated).
- The mode-specific session total in the Dashboard band (`N submitted` for
  Guided vs `N of 10` for SOC Queue/Hardcore).
- `test_guided_catalog.py` (leak guard) + the C4 neutrality sign-off.

Nothing in step 3 touches scoring, grading, readiness, sealing, or the record
schema. Build step 3 stays held until this mini-spec is approved.
