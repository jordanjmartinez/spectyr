# Stage 3 Final Report (Response Actions) — close-out for owner review

Stage 3 added a response layer to the investigation platform: an immutable
base world, a session-local action overlay, eight response verbs, a
deterministic scoring model, and answer-key response content for all 20
scenarios. This report closes Stage 3d. **No engine capability, response
verb, or scenario content was changed in the close-out** — it is
verification, baselines, the composite decision, and documentation.

Status at close: reviewed-scenario ledger **20/20**; full gate battery green
(backend + frontend); the composite headline-grade decision is presented in
§5 for the owner to rule (Option A side-by-side stays in the UI until then).

---

## 1. Architecture summary

- **Immutable base world + session-local overlay** (`action_overlay.py`).
  Response actions never mutate the world or the event pool. Current-state
  surfaces (endpoint ENUMERATE tabs, isolation/identity badges, the
  persistence view) render base+overlay at serialization time; historical
  surfaces (SIEM, detections, triggering-event evidence, lineage) always
  render the immutable base. Response changes the present, never the record.
- **Eight verbs**: `isolate_host`, `release_host`, `kill_process`,
  `delete_file`, `disable_account`, `revoke_sessions`,
  `force_password_reset`, `remove_persistence` (the last added as the
  Stage 3c.5 engineering increment). `release_host` is deliberately absent
  from the answer-key grammar (a rollback control, globally score-neutral).
- **Client entity ids**: stable-key `ent-`+12hex, shape-uniform across kinds
  (host/process/file/account/persistence), derived from a length-prefixed
  digest so distinct composite keys can never collide. Raw composites and
  the persistence identity never serialize; the registry resolves ids
  server-side and is rebuilt from the base world after each drip.
- **Composite targets**: process=(host,pid), file=(host,normpath),
  account=(domain,username), persistence=the correlated artifact identity
  (WMI subscription = host+namespace+filter path+consumer path; Run key =
  host+reg key+value name).
- **Dual-flag persistence model** (Stage 3c.5): a persistence artifact
  carries a registration flag (cleared by `remove_persistence`) and, when
  file-backed, a file flag (cleared by `delete_file`); the Autoruns row
  survives until BOTH clear. GENERAL RULE, enforced by this model: no
  acceptable action may render a required action unreachable.
- **Deterministic scoring** (`compute_action_score`, `compute_detection_score`,
  classification `report_card`): pure functions of (successful actions,
  end-state isolation, per-scenario grading, dispositions, classifications).
  No clock, no rng, no LLM grading. Action accuracy = correct/(required +
  collateral); isolation graded on end-state, kill/delete/identity/persistence
  on occurrence; order only where an answer key declares `after`.
- **Tri-state grading marker** `answer_key.actions_reviewed` (server-side
  only): unreviewed = excluded from action scoring; reviewed+actions =
  graded; reviewed+[] = intentional correct inaction (one graded unit).
- **Achievability + reachability**, validator-enforced and seed-independent:
  every required and acceptable action must be executable from the initial
  world and UI-reachable, across the fixed five-seed set; targets resolve
  only to authored sources (chain / supplemental / canonical environment).
- **Report card (Option A)**: classification keeps the headline grade;
  Detections and Response render as independent scored sections.

## 2. All 20 answer-key summaries

Legend: REQ = required (credit/miss), ACC = acceptable (defensible, never
credit, never collateral), TRAP = declared collateral trap.

| Scenario | Category | Required | Acceptable | Traps |
|---|---|---|---|---|
| malware_usb | Malware | isolate ws; kill 7412; kill 8044; delete winupdate.exe | — | kill 7340 (EndpointCentral); disable victim |
| malware_ransomware | Malware | isolate ws; kill 18204 (encryptor) | kill 19301 | disable victim |
| phishing_1 | Phishing | revoke + reset victim | disable victim | isolate ws |
| phishing_link | Phishing | isolate ws; kill 11284; delete InvoiceService.exe | kill 13056 | disable victim; isolate dns |
| lateral_movement_1 | Lateral Movement | isolate ws; kill 8844; kill 2104 (file); revoke + reset victim | kill 3312; kill 6240; disable victim | isolate/kill scanner; isolate file |
| lateral_movement_2 | Lateral Movement | isolate ws; kill 19840; kill 21056; revoke + reset victim | disable victim | isolate file; kill 6180 (WerFault) |
| c2_http | Command & Control | isolate ws; kill 5912 | — | disable victim; isolate dns |
| c2_dns_tunnel | Command & Control | isolate ws; kill 17892 | — | disable victim; isolate dns |
| data_exfil_archive | Data Exfiltration | isolate ws | kill 15820 | disable victim; isolate dns; kill 6820 |
| insider_staging | Insider Threat | disable + revoke insider; isolate ws | kill 7832; reset insider | isolate file |
| insider_shadow_it | Insider Threat | isolate ws; revoke employee | disable + reset employee; kill 14320 | isolate dns |
| defense_evasion | Defense Evasion | isolate ws; kill 6104; delete svchost32.exe | kill 4812; remove_persistence run_key WindowsServices | disable victim |
| defense_evasion_log_clearing | Defense Evasion | isolate ws; remove_persistence wmi WindowsUpdConsumer | kill 22480; kill 22544 (wevtutil) | kill 8820 (benign wevtutil); disable victim |
| password_spray | Brute Force | isolate ws; revoke + reset lgreen | disable lgreen; reset dpark | isolate dc; disable dpark; disable svc_backup |
| brute_force_attack | Brute Force | none (correct inaction) | reset victim | isolate dc; disable victim; disable svc_backup |
| false_positive_pentest | False Positive | none (correct inaction) | — | disable victim; isolate ws |
| false_positive_robocopy | False Positive | none (correct inaction) | — | kill 4812; disable victim; isolate ws |
| false_positive_veeam | False Positive | none (correct inaction) | — | kill 2916; isolate ws |
| false_positive_oauth | False Positive | none (correct inaction) | — | disable victim; isolate ws |
| false_positive_ssl_inspection | False Positive | none (correct inaction) | — | kill 4492; disable victim; isolate ws |

14 scenarios carry required actions; 6 are correct-inaction (5 FP +
brute_force_attack, whose lockout contained the attack).

## 3. Chrome end-to-end verification

Fresh backend (current code) + frontend, Training mode, one live session
(queue of 10). Covered ≥3 complete workflows across the required types:

- **Host-malware (malware_usb)** — investigated the SIEM feed and the
  Endpoints/Autoruns persistence view; promoted the "Executable Launched
  from Removable Media" YARA TP; executed `remove_persistence` then
  `delete_file` on the malicious `WindowsUpdate → winupdate.exe` Run key and
  watched the **dual-flag lifecycle live** (Remove → "Registration removed"
  + "File present", row stays, only Delete File remains → Delete → row
  drops); classified True Positive / Malware; correct-classification triage
  review (T1091). Response Log recorded both actions **Success** with
  monotonic frozen-clock timestamps.
- **Identity (insider_shadow_it + Threats view)** — the Threats view
  RESPOND column exposes Disable / Revoke / Reset PW on account-bearing
  promoted detections; executed `revoke_sessions` (confirm dialog: "the
  detection record does not change"); classified insider Dropbox exfil as
  Insider Threat (T1567.002).
- **Correct-inaction (brute_force_attack)** — failed-logon burst (4625)
  ending in lockout (4740); classified Brute Force (T1110.001) and took no
  response actions (inaction credited).
- Also completed defense_evasion (Defense Evasion, T1685 in the live
  triage — the v19.1 mapping).

Checklist results:
- **Zero console errors** across the whole session.
- **All six nav links** work and render (Alerts, SIEM, Detections,
  Endpoints, Metrics, Reports).
- **Current-state changes render** (persistence state badges, isolation,
  identity); **historical evidence remains** (SIEM/detection counts keep
  growing; "event record unchanged" / "originating events stay in the log").
- **Detection triage**: promote + dismiss + Section 8 detail (RULE, MITRE
  chips, triggering-event lineage, SHA256 + copy); disposition scoring
  updated correctly.
- **Action outcome display**: Response section showed required / correct /
  missed / collateral; Response Log showed Success entries.
- **Report-card numbers match backend**: the rendered counts matched the
  exact actions taken — Classification **A** (1/1 correct), Detections
  **D / 66.7%** (2 correct, 1 wrong: the promoted critical benign
  VSS-read; 17 open), Response **F / 6.2%** (14 required, 1 correct
  [delete winupdate.exe], 13 missed, 2 collateral [the off-answer-key
  remove_persistence + revoke]). The frontend renders the server-computed
  grades directly (no client re-derivation), and all five `/api/analytics/*`
  endpoints returned 200.
- Note on the cross-check method: the Chrome extension blocks page scripts
  from reading the session token (a genuine leak-guard property), so the
  match was verified by behavioral consistency + the render-server-values
  architecture rather than a raw JSON diff. The session token being
  unreadable from JS is itself the desired guarantee.

## 4. Full-corpus response baselines (20 scenarios × 5 seeds)

Deterministic action-score baselines for three strategies:

| Strategy | micro | macro |
|---|---|---|
| Correct response | 100.0 | 100.0 |
| Act on nothing | 13.3 | 30.0 |
| Act on everything | 1.4 | 1.5 |

Both naive strategies score strictly below correct response on micro **and**
macro. Behavior:

- **Correct** = A/100 on every scenario (attack: required executed; FP:
  inaction unit credited).
- **Act-on-nothing** scores 100 only on the 6 no-required scenarios (5 FP +
  brute_force_attack) and 0 on all 14 attack scenarios; macro 30.0 = 6/20,
  micro 13.3 (attack scenarios carry more graded units, so pooling weights
  them). This is the **false-positive inaction behavior**: doing nothing is
  correct exactly on the correct-inaction scenarios and nowhere else.
- **Act-on-everything** ≈ 0 everywhere (1–4% on attacks from the couple of
  required hits drowned in ~50 collateral entities; 0 on FP scenarios
  because collateral forfeits the inaction unit).
- **Outliers**: no attack scenario lets a naive strategy tie or beat
  correct. The only ties are act-on-nothing == correct on the six
  correct-inaction scenarios, which is by design (there, inaction *is* the
  correct response).

## 5. Composite headline-grade decision (owner ruling required)

Three independent sub-scores exist, each on the shared 10-point band
(A≥90 B≥80 C≥70 D≥60 F<60) and each A/100 for a correct player across the
corpus:

- **Classification** = (correct threats + FPs caught) / classifications
- **Detection** = correct dispositions / graded dispositions
- **Response** = correct actions / (required + collateral)

**Treatment of no-required scenarios (all options):** response accuracy
uses the action-score denominator, in which a no-required scenario
contributes exactly one *inaction unit* (credited 100 on clean hands, 0 if
collateral lands in its scope). No dimension is ever dropped or
renormalized in practice: corpus density guarantees every scenario has
detections, a classification, and a response unit, so the composite is
always a clean weighted average of three defined sub-scores. (Renormalize
only if some dimension has zero graded units session-wide — which does not
occur.)

**Options** (C = classification, D = detection, R = response):

| Run (C / D / R) | B 50/25/25 | C 40/30/30 | D 60/20/20 |
|---|---|---|---|
| Clean expert (100/100/100) | 100.0 A | 100.0 A | 100.0 A |
| Right call, weak triage (100/60/70) | 82.5 B | 79.0 C | 86.0 B |
| Wrong class, good work (60/100/100) | 80.0 B | 84.0 B | 76.0 C |
| Solid, one FP promoted (100/80/100) | 95.0 A | 94.0 A | 96.0 A |
| Over-responder (100/100/55) | 88.8 B | 86.5 B | 91.0 A |
| FP-heavy session (100/90/100) | 97.5 A | 97.0 A | 98.0 A |

Band effects to weigh:
- **D 60/20/20** keeps classification dominant but **under-penalizes
  collateral**: the over-responder (100/100/55) still earns A/91.
- **B 50/25/25** penalizes collateral appropriately but **cushions a wrong
  classification** to B/80 (wrong-class/good-work).
- **C 40/30/30** keeps classification the single largest weight while
  making investigation quality genuinely matter: the over-responder drops
  to B (collateral costs the A) and weak triage drops to C, yet a correct
  classification is still the biggest single lever.

**Recommendation: Option C (40/30/30).** It is the only option where
neither failure mode hides — a wrong classification cannot ride good
investigation to an A (wrong-class/good-work = B/84, and a wrong call with
average investigation falls to C/D), and a correct classification cannot
excuse reckless collateral (over-responder = B/86.5). Classification stays
the largest single dimension, so it remains the de-facto headline driver
without being the only thing that matters. If the owner prefers
classification to anchor even harder, B is the fallback; D is not
recommended because it lets collateral slide.

Per instruction, the UI keeps the **Option A side-by-side** presentation
until the owner rules; no composite is wired.

## 6. Structural verification

All confirmed by the green gate battery (guards named):

- **20/20 reviewed** — `test_all_twenty_scenarios_reviewed_gate` (ledger ==
  corpus, none unreviewed).
- **Required + acceptable five-seed achievable + UI-reachable** —
  `test_reviewed_corpus_actions_achievable_across_seed_set`,
  `test_required_and_acceptable_actions_are_ui_reachable_across_seeds`.
- **Declared traps reachable + collateral** —
  `test_declared_traps_execute_reachable_and_grade_collateral_across_seeds`.
- **Answer keys + entity composites never serialize** —
  `test_score_endpoint_shape_surfacing_and_no_leak`, the `annotate_view`
  strip guard, `test_detections` sanitization; persistence identity/id_parts
  stripped and length-prefixed.
- **Deterministic replay → identical grades** —
  `test_replay_determinism_including_reversal_sequences`.
- **v1 YAML / legacy NDJSON / frozen boundaries untouched** — `parity_check`
  (CLEAN), `parity_check_v2` (CLEAN 20/20, 23 approved divergences),
  `test_scenario_loader` (v1).
- **No em dashes in rendered copy** — `copy-emdash.test.js` + the render
  scan (frontend 19/19).

Final gate counts: loader v2 61, loader v1 10, action-scoring 27, actions
14, action-overlay 18, persistence 19, persistence-response 19, snapshots
21, detections 12, detection-scoring 7, detection-order 5,
detection-indistinguishability 6, rank-uniformity pass, attack-coverage 6,
solver-gates PASS, parity CLEAN (both), fairness FAIR, frontend 19.
`run_gates.py --all` → ALL GREEN.

## 7. response-vocabulary-v2 backlog (unbuilt, on the record)

Deferred response gaps, each requiring its own reviewed schema+engineering
increment (never a stretched existing verb):
- **Arbitrary-file deletion** (FX2) — delete of non-autorun evidence files;
  needs UI+entity support and an evidence-preservation ruling.
- **OAuth application-grant revocation** (FX3) — revoking a malicious OAuth
  app's grant; not expressible as `disable_account`/`revoke_sessions`.
- **Perimeter source-IP blocking** (EX-BF) — firewall block of an attacking
  source IP (e.g. the brute_force/password_spray origin).
- **Security-control re-enable** (EX-RECON) — re-enabling a disabled
  Defender/EDR control.

Stage 3c.5 added exactly one verb (`remove_persistence`) because exactly one
gap blocked a scenario and the all-20 gate; it is not a precedent for
piecemeal additions.

## 8. Known-actor prior status

The detection layer carries a deliberately-learnable **known-actor prior**
(report-only, not gated): promoting detections tied to a recurring
malicious actor identity scores ~0.87 micro. This is intentional — a real
SOC does prioritize known-bad actors — and is surfaced, not penalized. Its
counter (a *trusted-actor-compromised* seed, where a normally-benign
recurring actor is the attacker, defeating the prior) is on the backlog and
was **not** built in Stage 3. Until then, a solver that always promotes
known-actor detections gains a measurable-but-bounded edge that does not
generalize to the compromised-trusted-actor case.

## 9. Explicit limits — what Stage 3 certifies (and does not)

**Certifies:**
- The response engine is deterministic, immutable-base, and leak-guarded;
  every answer-key action is achievable and UI-reachable across the fixed
  five-seed set; every declared trap grades collateral.
- The three sub-scores are pure, server-side, and replay-identical.
- Naive response strategies (do-nothing, do-everything) score strictly
  below correct on micro and macro.
- All 20 scenarios are reviewed and the corpus is internally consistent by
  its own guards.

**Does NOT certify:**
- **Seed-independence beyond the fixed five-seed set.** Achievability and
  reachability are proven across five seeds, not all seeds; the guarantee is
  "authored-source targets resolve identically under substitution," which is
  structural, but only five seeds are executed.
- **Correct-response uniqueness / pedagogical optimality.** The scoring
  certifies that the authored answer key is achievable and that naive play
  scores low; it does not certify that the authored required/acceptable
  split is the single pedagogically-best response, nor that no defensible
  alternative response exists outside the answer key (such alternatives
  grade as collateral or acceptable by design).
- **The composite grade.** No composite is certified — §5 presents options;
  the ruling is the owner's.
- **The known-actor prior counter** (compromised-trusted-actor seed) — not
  built.
- **The response-vocabulary-v2 gaps** — not built (§7).
- **Adversarial UI/CTF robustness.** Leak guards are tested at the API and
  render boundaries and in Chrome; they are not a formal proof against a
  determined reverse-engineer of the client bundle.
- **Load / concurrency.** Single-worker, in-process sessions; no multi-user
  or high-concurrency certification.

---

*Prepared at the Stage 3d checkpoint. Stage 3d is not closed and the
visual-polish phase has not begun; both await this report passing owner
review and the composite ruling.*
