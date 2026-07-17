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

## Org-prefix theming substitution set

**Target: when the {org_prefix} theming feature lands.**

The SharePoint/OneDrive tenant literal `acme-my.sharepoint.com` is currently
duplicated as a single source of truth across two scenarios
(`false_positive_robocopy` entity `sharepoint`, and `data_exfil_archive`
supplemental_entity `sup_sharepoint`, byte-identical). When org-prefix theming
substitution lands, this tenant literal joins the `{org_prefix}` set so the
`acme` prefix is substituted consistently (e.g. `{org_prefix}-my.sharepoint.com`)
rather than hardcoded in two places.
