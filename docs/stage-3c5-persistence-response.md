# Stage 3c.5: Persistence-Response Increment (SCAFFOLD for owner review)

A dedicated engineering increment that adds exactly one response verb,
`remove_persistence`, so a compromised host's persistence can be
neutralized as a first-class response action. It unblocks
`defense_evasion_log_clearing` (whose WMI subscription is active
persistence that no current verb can remove) and restores the path to the
20/20 review gate.

Design-only. Nothing here is implemented until this scaffold is approved.

## Scope boundary (on the record)

3c.5 adds **exactly one verb** because exactly one vocabulary gap blocks a
scenario and the all-20 review gate. The other response gaps stay in the
backlog "response-vocabulary-v2" review and are NOT unlocked here:
arbitrary-file deletion (FX2), OAuth application-grant revocation (FX3),
perimeter source-IP blocking (EX-BF), security-control re-enable
(EX-RECON). This increment does not establish a precedent for adding
verbs piecemeal outside a reviewed engineering increment.

## 1. Materialize WMI subscriptions as stable persistence entities

`snapshot_generator` currently ignores Sysmon WMI events (event_id 19
WmiEventFilter, 20 WmiEventConsumer, 21 WmiEventConsumerToFilter). It will
materialize a **persistence artifact** per WMI consumer binding, keyed by
the consumer Name (e.g. `WindowsUpdConsumer` from the s3 binding). Each
artifact carries: the consumer name, the command it runs (the
CommandLineEventConsumer template, from the s20 event), the trigger (the
filter query, from the s19 event), and a stable-key id. Materialization is
pure derivation over the event pool, stable-key (sha256 over
session/host/consumer-name), never draw-order - the same discipline as
every other world value.

## 2. Extend the Autoruns surface (not a new tab)

Real Sysinternals Autoruns enumerates WMI subscriptions alongside Run
keys, Services, and Scheduled Tasks, so the Autoruns surface is the honest
home for persistence artifacts. The proposal:

- Autoruns rows gain a `persist_type` field: `run_key` (existing rows) and
  `wmi_subscription` (new). Existing Run-key rows are unchanged except for
  the added, defaulted field.
- WMI subscriptions render as Autoruns rows: entry = consumer name,
  location = `WMI:__EventConsumer` (or similar), command = the consumer's
  command template, signer = null (WMI CommandLineEventConsumers are not
  signed artifacts).
- A separate tab is proposed ONLY if review finds Autoruns cannot
  represent WMI subscriptions honestly; the default is same-surface.

This unifies persistence on one surface and is what a real analyst sees.

## 3. The `remove_persistence` verb (first-class)

- **Grammar:** a new action verb `remove_persistence` with a composite
  target `{host, persistence}`, where `persistence` is the persistence
  identifier (the WMI consumer name, or a Run-key `location\name`).
  Schema, per-action target conditionals, loader referential +
  achievability validation - identical rigor to the existing six verbs. It
  is a real verb, never a stretched `delete_file`.
- **Overlay + cascade:** removal writes to a new overlay set
  `removed_persistence` (host, persistence-key). The live Autoruns view
  drops that persistence row (base+overlay). Historical WMI events
  (19/20/21) and Run-key SetValue events remain fully in the SIEM and in
  triggering-event evidence - response changes the present, never the
  record. Integrity: after any action sequence, no live Autoruns row
  references a removed persistence artifact.
- **Client entity ids:** persistence artifacts join the entity registry
  with `ent-`+12hex stable-key ids, shape-uniform with host/process/file/
  account ids. Raw composites never serialize.
- **UI reachability:** a Remove control on Autoruns persistence rows
  (both WMI subscriptions and Run keys), so `remove_persistence` is
  player-reachable exactly where the persistence is investigated - the
  same surface-based reachability the invariant already enforces.
- **Scoring + collateral:** `remove_persistence` grades like the other
  occurrence verbs - credit on a required/acceptable target, collateral on
  an off-list persistence artifact (e.g. removing the benign OneDrive Run
  key). Achievability: the target must be an authored persistence artifact
  (WMI consumer from 19/20/21, or a Run key from event_id 13), never
  seed-generated - so it validates identically under all five seeds.
- **Leak guards + tests:** the persistence answer-key linkage never
  serializes; the five-seed achievability, trap, and reachability harness
  all cover `remove_persistence`; deterministic overlay/cascade tests;
  replay determinism; the API leak-guard suite extends to the new target
  kind.
- **Run-key reuse by design:** because the target is a generic persistence
  artifact, `remove_persistence` works on Run-key persistence too, not
  only WMI - so the same verb neutralizes both mechanisms.

## 4. Two explicit decisions this scaffold must surface

### D1 - remove_persistence status in defense_evasion_log_clearing: propose REQUIRED

The scenario was blocked precisely because isolate + killing the wevtutil
processes is incomplete - the WMI subscription survives and can re-launch
the payload, and no verb could remove it. `remove_persistence` on the
`WindowsUpdConsumer` WMI subscription IS the completing containment step,
so it should be **REQUIRED**. Proposed authored answer key once 3c.5
lands:

- Required: isolate_host ws_victim; remove_persistence the WMI consumer.
- Acceptable: kill the two malicious wevtutil instances (22480, 22544).
- Traps: kill the benign maintenance wevtutil 8820; disable the victim
  account. (s5 1102 classification binding stays untouched.)

### D2 - defense_evasion retroactive acceptable remove_persistence: propose YES (acceptable)

defense_evasion's Run-key persistence (svchost32.exe) is already
neutralized by the REQUIRED `delete_file` of the payload (the delete
cascade clears the Run-key autorun row). But once `remove_persistence` can
target Run keys, a player could remove that Run key directly. If it is
left undeclared it would grade as COLLATERAL, which is wrong (removing
malicious persistence is not collateral). So defense_evasion should
retroactively gain an **ACCEPTABLE** `remove_persistence` on its
svchost32 Run key: the required delete_file stays the primary containment;
remove_persistence(Run key) is a defensible alternative path, surfaced
factually, never collateral. (Cascade note: if the player deletes the
payload first, the Run-key row is already gone, so a later
remove_persistence no_ops - handled by the standing no_op rule.)

## 5. Sequencing

1. Implement 3c.5 per the above; full gates; owner review.
2. After 3c.5 passes: author defense_evasion_log_clearing (D1), apply D2
   to defense_evasion, flip both to their final answer keys.
3. Restore and ENFORCE the 20/20 reviewed gate (the REVIEWED_SCENARIOS
   ledger test becomes all-20; the "blocked exception" is removed).
4. Then begin Stage 3d.
