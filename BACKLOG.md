# Backlog

Items approved for later work. Each entry names its target window; nothing
here is in progress until a stage plan picks it up.

## Indexed multi-account placeholders

**Target: before end of Stage 2.**

Add indexed employee placeholders (`{username_1}` through `{username_n}`,
resolved as distinct roster picks per run) to the scenario placeholder
grammar, then migrate `password_spray` off its grandfathered literal
usernames (dpark, mjohnson, bwilliams, achen, jkim, lgreen).

Why: the literals are static values in chain content (placeholder-integrity
exemption), they pin the sprayed accounts to six specific roster employees,
and the runtime victim pick can collide with a sprayed account. Indexed
placeholders make every run's target set unique and remove the exemption.

Scope notes for the implementer:
- Grammar and resolution live in `scenario_loader.py` (v1, frozen) vs
  `scenario_loader_v2.py`: implement resolution for the v2 path only, and
  route it through `resolve_entities`-style per-run resolution so the same
  index always yields the same employee within a run.
- Requires an approved correction record (scenario_corrections.py) for the
  password_spray chain rewrite, with the parity divergences enumerated.
- The environment accounts and answer_key.scope.accounts for password_spray
  must switch from literal ids to the indexed placeholders' resolved ids.
- Remove the six username entries from the placeholder-integrity
  grandfather allowlist in `test_scenario_loader_v2.py` when done.

## Scenario seed: trusted recurring actor compromised

**Target: post-Phase-2.**

Author a scenario that weaponizes the known-benign-actor prior this corpus
deliberately builds. Across the density pass, recurring benign actors
(`svc_backup` / ACME-VEEAM01, the Endpoint Central agent, the Nessus scanner,
the sanctioned SharePoint tenant) appear as the dismissable FP in many
scenarios, training the analyst to wave them through. A late-game scenario
should make one of these actors the *real* compromise — e.g. `svc_backup` or
ACME-VEEAM01 genuinely abused for lateral movement / exfiltration — so that
"it's just the backup account again" is the wrong call. The whole point is to
punish the reflex the earlier scenarios instilled; disposition must turn on the
specific evidence (unusual target, off-schedule timing, new source host), not
on actor familiarity.

## Org-prefix theming substitution set

**Target: when the {org_prefix} theming feature lands.**

The SharePoint/OneDrive tenant literal `acme-my.sharepoint.com` is currently
duplicated as a single source of truth across four scenarios
(`false_positive_robocopy` entity `sharepoint`; and `data_exfil_archive`,
`insider_shadow_it`, `phishing_link` supplemental_entity `sup_sharepoint` — all
byte-identical, via the `_SHAREPOINT_TENANT` constant in `migrate_v1_to_v2.py`).
When org-prefix theming substitution lands, this tenant literal joins the
`{org_prefix}` set so the `acme` prefix is substituted consistently (e.g.
`{org_prefix}-my.sharepoint.com`) rather than hardcoded in four places.

## Offline-host wrinkle: exercise in the trusted-actor-compromised scenario

**Target: when the trusted-actor-compromised scenario is authored (backlog).**

The offline-host isolation wrinkle (isolating a declared-offline host fails
with an in-fiction agent-delivery error, surfaced factually and score-neutral)
is implemented and unit-tested (test_actions.py, test_action_scoring.py) but is
NOT used in any authored scenario (3c Batch 4 review ruling: do not alter a
host's status merely to exercise the mechanic). The trusted-actor-compromised
scenario is the natural place to exercise it in real content - e.g. a host the
actor has already taken offline, where a reflexive isolate fails and teaches the
offline-host lesson. Wire it there when that scenario is authored.
