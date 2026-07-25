# Tier 2 rationale batch scaffold (Stage 5 Phase 5, commits 5.6..5.N)

The D2 authoring scaffold (the 3c cadence, per the consolidated
implementation scaffold Section 6 Phase 5): every scenario's proposed
top-level `expected_response` paragraph, drafted in one batch, reviewed at
the 5.6 checkpoint, then landed ONE SCENARIO PER COMMIT, each commit adding
the YAML field and its `RATIONALE_SCENARIOS` ledger row together
(`test_scenario_loader_v2.py` enforces the ratchet in both directions).

Authoring rules (contract 7.3, ratified OD-1/OD-3; review correction 4):

- **Tier 2 owns scenario causality** and only Tier 2: what this incident
  was, why the required actions are required, why the acceptable ones are
  defensible-but-optional, and why the tempting wrong moves are collateral.
  The Tier 1 generic templates stay purpose-only.
- **Grounded in the ratified answer key, never contradicting it**: every
  required/acceptable/trap characterization below restates the scenario's
  frozen `answer_key` statuses; no paragraph invents an action outside the
  vocabulary or contradicts a status.
- **Role language only**: "the victim workstation", "the file server",
  "the breached account" — never concrete hostnames, usernames, or PIDs
  (those are session-resolved; the teaching entries carry the labels).
- **Post-boundary only**: the field freezes into a record as
  `scenario_rationale` at submit and renders solely in the Learning
  Review's Key takeaway (ruling H: records frozen before authoring stay
  null). No pre-submission surface reads it (planted-marker guarded).
- Player-visible copy: no em dashes; ASCII punctuation.

Checkpoint record (one-shot authorization, 2026-07-25): the batch below
was self-reviewed against every answer key dumped from the corpus (all 20
labels; required/acceptable/trap sets restated 1:1) in place of the
separate owner batch approval, as recorded in the Phase 7 report. Each
paragraph lands as its own revertable commit, and post-hoc rewording
reaches future submissions only (correction 6).

---

## Batch (20 paragraphs)

### malware_usb (Malware)
> A removable-media infection executed a dropped payload on the victim
> workstation and spawned follow-on malicious processes. The workstation is
> the infected asset, so the required response is host containment: isolate
> the workstation, terminate both malicious processes, and delete the
> dropped executable so it cannot be relaunched. No credential compromise is
> in evidence, so disabling the signed-in account punishes a bystander; the
> similarly named legitimate system process is a deliberate near-miss, and
> killing it disrupts a clean asset.

### phishing_1 (Phishing)
> This was a credential phish: the victim entered their password on an
> attacker page, and the evidence shows the account being abused, not the
> workstation being compromised. The response evicts the attacker from the
> identity: revoke the account's active sessions so stolen tokens die, and
> force a password reset so the stolen secret stops working. Disabling the
> account also works and is defensible, but eviction plus reset already
> closes the breach with less disruption. Isolating the workstation is the
> tempting wrong move: no malware ran there, so host containment addresses
> an asset the attacker never controlled.

### defense_evasion (Defense Evasion)
> Security tooling on the victim workstation was tampered with and a
> masquerading executable was dropped and set to persist. Required: isolate
> the workstation, terminate the malicious process, and delete the dropped
> binary, because the host is attacker-controlled and the payload would
> otherwise survive. Removing the Run-key persistence and terminating the
> secondary process are defensible additional steps; the graded core is the
> host plus the payload. The account itself shows no credential theft, so
> disabling it is collateral.

### false_positive_pentest (False Positive)
> The alerts trace to an authorized security exercise: the activity matches
> the announced testing window and tooling, not a live adversary. The
> correct response is investigation without action: classify the incident
> as a false positive and leave the environment alone. Isolating the
> workstation or disabling the account involved would disrupt sanctioned
> work; response actions against benign assets are collateral harm, not
> caution.

### lateral_movement_1 (Lateral Movement)
> An attacker moved from the victim workstation to the file server using the
> victim's credentials. The response must close both footholds and the
> identity: isolate the source workstation, terminate the malicious
> processes on the workstation and on the file server, revoke the account's
> sessions, and reset its password, resetting only after the workstation is
> contained so a live foothold cannot immediately recapture the new
> credential. Disabling the account outright is defensible. The
> vulnerability scanner's activity is a look-alike, and isolating the file
> server takes a shared service away from the whole company when
> terminating its malicious process suffices.

### c2_http (Command & Control)
> A process on the victim workstation is beaconing to attacker
> infrastructure over HTTP, which means the host is compromised and remotely
> controllable. Required: isolate the workstation to cut the channel, and
> terminate the beaconing process. The signed-in account is not shown to be
> stolen, so disabling it is collateral, and the DNS server merely resolved
> the lookups every client makes, so isolating shared infrastructure is the
> classic over-reach.

### brute_force_attack (Brute Force)
> This was a failed external brute force that the system already contained:
> the account lockout triggered and no logon succeeded, so there is no
> breach to evict. The correct response is investigation without action;
> blocking the source address sits outside the response vocabulary here,
> and nothing inside the environment is attacker-controlled. An optional
> hygiene password reset on the locked account is defensible. Isolating the
> domain controller or disabling accounts punishes healthy assets for an
> attack that already failed, which is why over-reaction grades as
> collateral, not caution.

### false_positive_robocopy (False Positive)
> The flagged transfer is a scheduled data migration: an administrative copy
> job moving files to the file server with a known tool, on schedule, under
> the expected account. Classify it as a false positive and take no response
> action. Killing the copy job, isolating the hosts, or disabling the
> account would break a sanctioned migration in progress: collateral harm
> against the company's own operations.

### phishing_link (Phishing)
> The phishing link delivered a payload: opening it dropped and executed a
> fake invoice service on the victim workstation. Because the compromise is
> on the host, the required response is containment there: isolate the
> workstation, terminate the malicious process, and delete the dropped
> executable. Terminating the secondary process is a defensible extra. The
> evidence shows no credential entry, so disabling the account is
> collateral, and the DNS server that resolved the malicious domain is
> shared infrastructure doing its job.

### data_exfil_archive (Data Exfiltration)
> Corporate data was staged, archived, and pushed out from the victim
> workstation. Isolating that workstation is the one required action: it
> stops the outbound transfer immediately and preserves the staging
> evidence. Terminating the archiver process is defensible but secondary
> once the host is off the network. The account shows no sign of takeover,
> so disabling it is collateral, as is action against shared infrastructure
> or the look-alike process.

### insider_staging (Insider Threat)
> A trusted insider used their own valid account to stage sensitive files
> from the file server onto their workstation. Because the actor is the
> account, identity comes first: disable the insider's account and revoke
> its sessions so no further access is possible, and isolate the
> workstation holding the staged data. Terminating the staging process and
> resetting the password are defensible additions. Isolating the file
> server is the tempting wrong move: it takes a shared service down when
> the access has already been cut at the account.

### malware_ransomware (Malware)
> An encryptor is running on the victim workstation. Speed matters: isolate
> the workstation so the encryption cannot reach network shares, and
> terminate the encrypting process to stop local damage. Terminating the
> dropper is a defensible extra. There is no credential compromise in
> evidence, so disabling the signed-in account adds harm without adding
> containment.

### lateral_movement_2 (Lateral Movement)
> The victim workstation shows remote-execution tooling and credential use
> against the file server. Contain the source first: isolate the
> workstation and terminate both attack processes, then evict the attacker
> from the identity by revoking sessions and resetting the password, the
> reset ordered after isolation so a live foothold cannot immediately
> recapture the new credential. Disabling the account is defensible.
> Isolating the file server, the target of the movement, would take a
> shared service offline when the compromise lives on the source host.

### defense_evasion_log_clearing (Defense Evasion)
> Security logs on the victim workstation were cleared and a WMI event
> subscription was planted: a fileless foothold that re-executes on its
> trigger even after reboots. Required: isolate the workstation, and remove
> the WMI subscription itself, because terminating processes does not
> unregister the subscription and the foothold would simply fire again.
> Terminating the involved processes is defensible but not sufficient. The
> look-alike process and the signed-in account are near-misses: neither is
> shown compromised.

### insider_shadow_it (Insider Threat)
> An employee installed unsanctioned remote-access tooling, exposing the
> workstation to outside control regardless of intent. Required: isolate the
> workstation to cut the remote channel, and revoke the account's sessions
> so any hijacked session dies with it. Disabling the account, terminating
> the tool, and a password reset are all defensible steps of increasing
> firmness. Shared infrastructure that carried the traffic is not the
> problem, so isolating it is collateral.

### password_spray (Brute Force)
> A password spray hammered the domain controller from one internal
> workstation, and one sprayed account then authenticated successfully:
> that account is breached, the rest only failed. Required: isolate the
> workstation named as the logon source, then evict the attacker from the
> breached account by revoking its sessions and resetting its password, the
> reset ordered after isolation so the live foothold cannot recapture it.
> Disabling the breached account and a hygiene reset on a heavily targeted
> account are defensible. The domain controller only processed the failed
> logons, and the merely targeted accounts were never breached, so acting
> against them is collateral.

### c2_dns_tunnel (Command & Control)
> The victim workstation is exchanging attacker traffic inside DNS queries:
> tunneling that rides the one protocol every network allows. Required:
> isolate the workstation to sever the covert channel, and terminate the
> tunneling process. The DNS server is the strongest temptation in this
> scenario, but it is shared infrastructure faithfully resolving what
> clients send; isolating it breaks name resolution for everyone while the
> compromise stays on the workstation. The account shows no credential
> theft, so disabling it is collateral.

### false_positive_veeam (False Positive)
> The beacon-like traffic is the backup agent checking in with its
> management server on its normal schedule: regular intervals and a known
> internal destination. Classify as a false positive and take no action.
> Killing the backup process or isolating the host would break the
> company's data-protection cycle: real harm in exchange for imaginary
> containment.

### false_positive_oauth (False Positive)
> The flagged sign-in anomalies come from a sanctioned application's
> modern-auth consent flow, not a compromise: the grants, client, and
> scopes match the rollout. The correct response is investigation without
> action. Disabling the account or isolating the workstation would lock a
> legitimate user out of tools the company just deployed: collateral harm
> with nothing contained.

### false_positive_ssl_inspection (False Positive)
> The certificate anomalies are the proxy's SSL inspection expanding to new
> categories: the issuer is the corporate inspection CA and the timing
> matches the policy change. Classify as a false positive and stand down.
> Killing the flagged process, isolating the workstation, or disabling the
> account would disrupt normal browsing that is already being inspected by
> design.

---

## Rollout ledger (mirror of `RATIONALE_SCENARIOS`)

Landed commits check off here as each scenario's field + ledger row lands:

- [x] malware_usb
- [x] phishing_1
- [ ] defense_evasion
- [ ] false_positive_pentest
- [ ] lateral_movement_1
- [ ] c2_http
- [ ] brute_force_attack
- [ ] false_positive_robocopy
- [ ] phishing_link
- [ ] data_exfil_archive
- [ ] insider_staging
- [ ] malware_ransomware
- [ ] lateral_movement_2
- [ ] defense_evasion_log_clearing
- [ ] insider_shadow_it
- [ ] password_spray
- [ ] c2_dns_tunnel
- [ ] false_positive_veeam
- [ ] false_positive_oauth
- [ ] false_positive_ssl_inspection
