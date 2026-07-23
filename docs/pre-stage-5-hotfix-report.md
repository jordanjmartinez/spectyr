# Pre-Stage-5 Hotfix Report: One Shared Incident Roster

**Status: IMPLEMENTED and verified.** Branch `pre-stage-5-hotfix`; stopped at the
hotfix checkpoint per instruction — NOT merged, Stage 5 NOT begun.

Date: 2026-07-22. Fix commit: `3b97a89dff4a803b5b9c21b4ceb4ea7e189304a4`
("Pre-Stage-5 hotfix: one shared incident roster (display == readiness ==
grading)") on top of the diagnosis commit
`57368f5c4ddfaec66594fe7e9401f9ecc5a2e099`, branched from `main` tip
`b093483c3b29186e2e39a90dd3a5ae7ebac1d280`.

---

## 1. Stage 4 merge record (quoted in full, closing the bookkeeping)

Quoted verbatim from docs/pre-stage-5-hotfix-diagnosis.md Section 0, verified
against live git output this session (`git log --oneline -3` at branch time:
`b093483`, `a863264`, `e7f6e9e`):

> | Item | Value |
> |------|-------|
> | Stage 4 merge commit | `a8632648f57230d61b92ad6ce597dc4e349bfb2c` — "Stage 4 closure: merge SIEM Investigation Workbench + LCQL (eb49610..e7f6e9e)" (merge commit; parents `ccdaeaa7b56c350bb6c66fe0032f0417d4663dba` + `e7f6e9e737c3d566d80a1b7fd4ec177ede436bab`) |
> | Current `main` tip | `b093483c3b29186e2e39a90dd3a5ae7ebac1d280` — "Stage 4 baseline record: a863264 is the reviewed product-merge baseline (docs-only)" |
> | `git status` | `M frontend/public/videos/spectyrvideo.mp4` (modified, uncommitted); `?? frontend/public/spectyr_svg.svg` (untracked). Both unrelated working-tree items; carried, not committed. |
> | Reviewed Stage 4 branch tip on main | CONFIRMED: `git merge-base --is-ancestor e7f6e9e main` → ancestor |
> | Stage 4 closing artifact on main | CONFIRMED: `ba556c5` is an ancestor of `main`; `docs/stage-4-implementation-report.md` present at `main` (`git cat-file -e main:docs/stage-4-implementation-report.md`) |

The environment blocker recorded in that section (repo ACL-read-only to the
unelevated token) is resolved operationally: this session runs elevated, and the
branch + diagnosis commit `57368f5` were fetched hash-identical from the
scratchpad clone into the real repository before implementation. The `.git`
DACL itself remains unrepaired (BUILTIN\Users = RX only); an unelevated future
session will hit the same wall until `icacls` is run.

## 2. Root cause (diagnosis evidence, verbatim)

From docs/pre-stage-5-hotfix-diagnosis.md Section 1 — the two derivations:

> - **Every player-visible surface** (incident card, Ready label, Submit button,
>   "X of Y reviewed" phase strip, incident-scoped Detections view, Related
>   hosts, Evidence-Timeline descent) reads
>   `_incident_observable_scope` (`backend/app.py:3850`), whose host set is
>   **observable participants**: hostnames on the incident's *written events*
>   plus entity hosts of its *scenario-tagged detections*
>   (`app.py:3870-3872`).
> - **The submission gate and the grade** read `_incident_detections`
>   (`backend/app.py:3358`), whose host set is
>   `grading_rec["hostnames"]` — **every host declared in the scenario's
>   `environment.hosts`** (`scenario_grading_record`, `app.py:4232`, recorded at
>   drip, `app.py:2583-2584`).
>
> Both apply the identical ambient-join predicate
> (`d["scenario_id"] is None and d["entity"]["host"] in hosts`) — to different
> `hosts`.

And Section 4's first-divergence-point finding:

> **First divergence point:** the host set fed to the ambient-join predicate —
> `app.py:3870-3871` (observable events + tagged entities) vs `app.py:3361`
> (`grading_rec["hostnames"]`). The predicate itself (`app.py:3366` vs
> `app.py:3885-3887`) is identical.

## 3. Why the equality test passed for two stages (diagnosis Q5, verbatim)

From diagnosis Section 7 ("Q5 — Test gap"):

> - **The test that should have caught it:**
>   `test_incident_scope.py::test_observable_roster_matches_readiness_roster`
>   (line 115) — its docstring is the recorded invariant: "The observable roster
>   equals the readiness roster (`_incident_detections`), so the Triage 'X of Y'
>   is consistent with the submission gate."
> - **Why its fixture missed it:** `_seed` (`test_incident_scope.py:37-64`)
>   hand-builds `scenario_grading` with `"hostnames": {WS}` — **defined equal to
>   the observable event host**. With the two host sets forced identical, the
>   equality is true by construction. The fixture's "unrelated" ambient sits on
>   ACME-WS99, outside *both* sets, so it exercises only the case where the two
>   joins agree. The same aligned shape is used by every submission-gate fixture
>   (`test_submission_gate.py::_add_incident`, lines 52-107: grading hostnames =
>   {the single event host}; all detections' entities on that host) … No fixture
>   ever runs the real `scenario_grading_record(concrete_env)` against a real
>   scenario environment.

### The Q5 lesson applied: the fixture CLASS, not just the instance

Standing fixtures sharing the environment==observed blind spot, and how the
class is now closed:

| Fixture | Blind spot | Closure |
|---------|-----------|---------|
| `test_incident_scope.py::_seed` | grading hostnames = `{WS}` = the only event host | Now seeds `{WS, ENV_ONLY}` with an OPEN ambient on the env-only host — the escaped configuration is IN the canonical fixture, so `test_observable_roster_matches_readiness_roster` is red on the pre-fix join (verified, Section 6) |
| `test_submission_gate.py::_add_incident` (used by every submission-gate test, incl. `test_remaining_count_and_readiness_are_incident_scoped`, `test_incident_cards_surface_incident_scoped_readiness`, `test_sealed_roster_finality_no_growth_on_poll_or_unrelated_activity`, `test_no_detection_attaches_to_a_submitted_incident`, `test_every_sealed_roster_detection_is_dispositionable_in_feed`) | grading hostnames = `{host}` = the single event host; every detection entity on that host | Fixture gains `extra_env_hosts` / `ambient_specs` parameters (documented in its docstring as the deliberate misalignment lever); four new tests exercise them (Section 5) |
| No corpus fixture at all | the real `scenario_grading_record(concrete_env)` never ran over a real environment in any test | New gate `test_incident_roster_corpus.py` real-drips ALL 20 scenarios through the actual drip path and asserts the three-way roster equality — the class can no longer hide behind hand-built grading records |
| `test_incident_scope.py::test_scope_structural_no_grading_or_expected_actions` | guarded only the display side | Guard extended over `_incident_roster`, `_incident_detections`, `_incident_open_detections`, `incident_submission_readiness` — the entire roster/readiness path is structurally barred from grading inputs, so a future grading-side join cannot silently reappear |

## 4. The fix

One shared derivation, consumed everywhere (commit `3b97a89`, backend/app.py):

- **`_incident_roster(s, scenario_id, written=None)`** (new): the incident's
  scenario-tagged detections + ambient benign detections on its OBSERVABLE
  participant hosts (hostnames on written non-normal events + tagged
  detections' entity hosts). Observable inputs only; never reads
  `scenario_grading`.
- **`_incident_detections`** now returns `_incident_roster(...)["roster"]` —
  the `grading_rec` parameter is GONE. Consumers updated:
  `_incident_report_card` (grading), `submit_incident` (record snapshot),
  `_incident_open_detections` + `incident_submission_readiness` (submit gate;
  parameter dropped), `_incident_progress` (/score progress).
- **`_incident_observable_scope`** (display: card ready, "X of Y", Submit
  enablement, incident-scoped Detections filter, Related hosts, descent) now
  consumes the SAME `_incident_roster` — equality by construction.
- Environment-declared hosts with no observable telemetry admit NO ambient
  detections into the roster (they remain session-wide triage material);
  ambient on genuinely observable participant hosts still joins, still gates,
  and one disposition still satisfies every roster it appears in.
- `scenario_grading` remains untouched for response-action collateral scoping
  and isolation end-state. NOT changed: scenario manifests, answer keys,
  detection generation, scoring functions/weights, submission-record schema.
- docs/submission-boundary.md updated where its premises were falsified
  (the "same rule" paragraph and the roster definition).

## 5. Permanent tests (all green at `3b97a89`; suites registered in run_gates.py)

1. **Exact escaped defect** —
   `test_incident_scope.py::test_observable_roster_matches_readiness_roster`
   (fixture now carries a real-drip-shaped grading record with env-only host
   `ACME-WS27` + open ambient `det-envonly`; asserts displayed == readiness,
   env-only ambient in neither, open-set empty) and
   `test_submission_gate.py::test_env_only_host_ambient_never_gates_grades_or_blocks_submit`
   (API level: card Ready, scope excludes it, /score progress agrees, feed still
   shows it, submit 200, record ids == displayed ids, ambient left open).
2. **Preserve ambient gating** —
   `test_submission_gate.py::test_ambient_on_observable_host_gates_and_one_disposition_satisfies_all`:
   observable-host ambient is in the displayed roster, raises the displayed
   total, 409s both sharing incidents with count 1, and ONE disposition (via
   the real triage API) unblocks both.
3. **Surface agreement** —
   `test_submission_gate.py::test_all_surfaces_consume_the_shared_roster_and_agree`:
   card triage ("X of Y" phase strip source), scope.detection_ids
   (incident-scoped Detections view), card.ready (Ready label + Submit
   enablement), /score progress, and submit-time validation agree in a mixed
   state (3-roster, 1 triaged, 409 count 2) and after full review (all ready,
   submit 200). Structural guard
   (`test_scope_structural_no_grading_or_expected_actions`) extended over the
   whole roster/readiness chain.
4. **Submitted-record protection** —
   `test_submission_gate.py::test_submitted_record_grades_exactly_the_displayed_roster_and_stays_frozen`:
   record's `detection_dispositions` ids == the scope ids displayed at submit,
   `detection.graded` == displayed size; late tagged/ambient/env-only attaches
   change neither the record nor the served grading bytes. (Existing 3.9A
   finality tests retained unchanged in behavior.)
5. **Corpus regression** —
   `test_incident_roster_corpus.py::test_corpus_every_scenario_has_one_roster`
   (new gate in run_gates.py): real-drips all 20 scenarios (session bootstrap →
   `build_guided_queue` → `build_attack_chain_logs` → `append_pool_event` →
   `finalize_chain` → seal → submit), asserts displayed == readiness ==
   grading roster per scenario, and prints the denominator delta vs the retired
   environment-host join.

## 6. Red/green proof (signature-agnostic harness, scratchpad `red_proof.py`)

Run against the PRE-FIX code (scratchpad clone at `57368f5`):

```
check 1 (unit, escaped config): displayed=['det-amb', 'det-tp'] readiness=['det-amb', 'det-envonly', 'det-tp'] -> DIVERGENT
check 2 (password_spray real drip): displayed=4 readiness=7 hidden=3 -> DIVERGENT
RESULT: RED (rosters diverge)          exit=1
```

Run against the FIXED code (this repo at `3b97a89`):

```
check 1 (unit, escaped config): displayed=['det-amb', 'det-tp'] readiness=['det-amb', 'det-tp'] -> EQUAL
check 2 (password_spray real drip): displayed=3 readiness=3 hidden=0 -> EQUAL
RESULT: GREEN (rosters equal)          exit=0
```

## 7. Detection-score denominator disclosure (corpus gate output, this run's seeds)

4/20 scenarios change denominator (exactly the diagnosis Section 10 set; the
other 16 are byte-identical, including the 9 whose only divergence was the
ambient-immune PAN-OS proxy):

```
brute_force_attack        env-join 6 -> observable 4   CHANGED
false_positive_robocopy   env-join 7 -> observable 5   CHANGED
false_positive_veeam      env-join 6 -> observable 4   CHANGED
password_spray            env-join 5 -> observable 4   CHANGED
(all 16 others unchanged)
```

Ambient counts are per-session stable-key draws, so the exact numbers vary by
session id; the equality assertion is seed-independent. Behavioral changes
disclosed: per-incident detection accuracies on these four scenarios are now
computed over the (smaller) displayed roster; submission readiness is strictly
easier (never demands invisible work); no serialized field, endpoint shape,
scoring function, weight, or record schema changed — only which detections
join an incident's roster. Already-submitted in-memory records are not
rewritten (session lifecycle moots them, as in the 3.9A closure).

## 8. Gate battery (authoritative counts)

- `python backend/run_gates.py` (backend battery, 27 suites including the new
  corpus gate): **ALL GREEN** — run standalone and again by the pre-commit hook
  at commit `3b97a89`.
- `python backend/run_gates.py --frontend`: **ALL GREEN** — 17 suites,
  164 tests (no frontend source changes; pre-existing act() console warnings
  only).
- Directly-affected suites: test_incident_scope 6/6,
  test_submission_gate 26/26 (22 prior + 4 new), test_incident_roster_corpus
  1/1 (20 scenarios inside).

## 9. Chrome end-to-end evidence (fixed backend pid 19552, frontend dev server, zero console errors)

**Original INC-1310 configuration (Guided password_spray, session
`c7f1afe4-8f77-42c3-acf3-ff2c65e6e295`, incident INC-6743, victim
rclark/ACME-WS45):**
- Roster sealed at 4; incident pane: Related hosts **ACME-SVR01 only**, phase
  strip "0 of 4 reviewed", "4 detections still need review". Session-wide feed:
  6 detections.
- Triaged exactly the 4 displayed → card **Ready**, "4 of 4 reviewed", Submit
  enabled — while 2 detections ("Backup Agent Periodic Beacon", "Microsoft
  Edge Update Service Beacon", both on env-declared never-observable
  ACME-WS45) remained OPEN and visible in the Session-wide view.
- **Submit → 200 submitted, no 409.** Incident Grade: Classification A·100%,
  Detections C·75%, Response F·0%, Composite D·62.5%.
- API record check: `detection.graded = 4 = total`, record disposition ids ==
  `scope.detection_ids` (4), `scope.hosts = ["ACME-SVR01"]`, the 2 open
  session-wide ambients on ACME-WS45 untouched (`assisted: false`). 75%
  accuracy is arithmetically impossible over the pre-fix 6-roster —
  independent confirmation the displayed roster was graded.
- Post-Incident Review re-served the identical immutable numbers.

**Opposite case (Practice Another → Guided malware_usb, INC-8541, victim
crodriguez/ACME-WS32 — the workstation IS observable):**
- Roster sealed at 5 INCLUDING ambient benigns on the observable host
  ("Microsoft Edge Update Service Beacon" — the same rule class correctly
  excluded in the password_spray run — and "Vulnerability Scanner
  Authenticated Sweep").
- Reviewed 4 of 5, left the Edge-updater ambient open → card NOT ready
  ("4 of 5 reviewed", "1 detections still need review", no Submit button);
  authoritative server check: `POST /submit` → **409
  `{"error":"1 detection still need review.","open_detections":1}`** — the
  count now MATCHES the display (1 == 1).
- Dismissed the ambient → "5 of 5 reviewed", Submit enabled → 200 submitted;
  record `detection.graded = 5 = total` == displayed roster.

Zero console errors across the entire verification session. (Pre-existing
cosmetic observation, unrelated to this fix and unchanged by it: a completed
incident's residual phase strip can transiently render "0 of 0 reviewed" while
the grade modal is open; the scope API returns the correct 4/4 post-submit.)

## 10. Submitted-record protection (diagnosis Q7 baseline, verbatim, and what changed)

The diagnosis proved the pre-fix records were internally consistent but based
on the hidden roster (Section 9):

> - **Gated against a readiness set different from its displayed sealed
>   roster:** YES — gate demanded 6, display showed 3 (Section 2).
> - **Graded against a roster different from the one shown:** YES —
>   `report_card.detection.graded = 6` vs displayed roster size 3;
>   `inputs.detection_dispositions` contains all three hidden ids
>   (`hidden_ids_in_graded_record`). The gate and the grade use the SAME roster
>   (`_incident_detections` both times), so every submitted record is complete
>   and internally consistent — readiness forces the hidden detections to be
>   dispositioned before the record exists. But the player was graded on
>   detections that no incident-scoped surface ever attributed to the incident …
> - **Immutable record affected by post-seal ambient join or scope change:**
>   NO — no post-seal join exists … `benign_hosts` blocks re-attach …
>   and both rosters were proven identical post-submit.

Post-fix, the first two answers become NO by construction (gate and grade
consume the displayed roster; permanent tests 1 and 4), and the third —
finality/immutability, which always held — is retained under the extended
late-attach tests.

## 11. Working tree at completion

`git status --short` on `pre-stage-5-hotfix`:

```
 M frontend/public/videos/spectyrvideo.mp4    (pre-existing, unrelated, uncommitted)
?? frontend/public/spectyr_svg.svg            (pre-existing, unrelated, untracked)
```

Branch tip: `3b97a89dff4a803b5b9c21b4ceb4ea7e189304a4` (fix) on
`57368f5c4ddfaec66594fe7e9401f9ecc5a2e099` (diagnosis) on `main` `b093483`.
This report lands as a docs-only commit on the same branch. **STOP: hotfix
checkpoint. Not merged to `main`; not pushed; Stage 5 not begun.**
