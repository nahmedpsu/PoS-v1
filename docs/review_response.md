# Response to the external review of v3.4.0

*The follow-up review of v3.5.0 (G01 to G10) is answered in
[review_response_round2.md](review_response_round2.md); several figures below were
revised in 3.6.0.*

The review ("PoS GitHub Repository Review", Reviewer 2) examined release v3.4.0,
commit `bd39021`, and listed 25 items, R01 to R25. This page gives the status of each
in version 3.5.0. Results, before and after, are in
[recycling_results.md](recycling_results.md); the scope that remains is stated in
[recycling.md](recycling.md#scope-after-the-external-review-of-v340-version-350).

Status:

* **Fixed**: the defect is corrected, a regression test covers it, and every
  dependent result was rerun.
* **Partly addressed**: some of what the review asks for is done; the rest is
  stated as a limitation.
* **Limitation**: not changed in the model; stated in the scope section and in
  the limitations of the results.

Every experiment was rerun at 3.5.0: E1 to E6, E1x, E2x, E1r, both SUMO traces,
plus the new departed-vehicle return policies and five motorway traffic
realizations. The v2 results, the attack bench and the use cases were rerun too:
their security and privacy outcomes are unchanged (14 defended, 4 mitigated), and
only wall-clock timings differ.

## Errors that directly affect reported results

| Item | Status | What changed |
|---|---|---|
| R01 Honest revocation metric counts attackers | Fixed | `ITSSimulation.population_report()` exports `vehicles`, `honest`, `attackers`, `revoked_total`, `revoked_honest`, `revoked_attackers` per seed, with the two sums asserted in every run. Every table and figure uses `honest_revoked` with the honest population as denominator; attackers revoked are reported separately. S1 at 120 s: 31.8 of 91.5 honest vehicles (35 %), plus 1.4 of 5 attackers; at 600 s, 89.6 (98 %) plus 4.0. Test: `test_population_counts_are_disjoint_and_honest_excludes_attackers`. |
| R02 Fresh issuance suppresses eligible attempts | Fixed, with one endpoint left as a limitation | Opportunities (attacker key-seconds), attempts, messages accepted by at least one receiver, receiver checks accepted, RSU acceptance, reports and distinct vehicles reported are separate fields. A rate with no attempts is `null` and shown as "not applicable", and paired tests on it say so instead of returning p = 0.002. The number of retained credentials still valid is sampled every round in every mode: at the end of a 120 s run the five former holders hold 40 valid credentials under every mode, fresh included. Under fresh issuance none of them is held by another vehicle, so impersonation and framing have no target; reuse of one's own retired pseudonym (accepted by receivers until expiry, the E2 mechanism) is named as a separate endpoint and not counted as impersonation. Test: `test_no_attempt_is_not_applicable_not_zero`. |
| R03 Verification cache bypasses time-dependent checks | Fixed | `V2VLayer` caches only the signature check, keyed by public key, message digest and signature, plus the PM-certificate check. Pseudonym match, certificate expiry, holder window, freshness and plausibility are evaluated on every delivery. Tests: `test_cached_verification_rechecks_expiry`, `test_certificate_substitution_is_not_served_from_cache`. |
| R04 Retained credentials share mutable objects | Fixed; acquisition of renewed certificates is a limitation | A former holder keeps an immutable snapshot (`entities.snapshot`) taken when the pseudonym leaves it. Rerun: with 300 s certificates over 600 s, S1's forgeries are accepted by 81 % of receivers instead of 96 %, S2's and S3's by about half, and a revoked vehicle is believed for 240 s instead of 540 s. A former holder that copies the renewed public certificate off the air is not modelled (R07), so these figures are a lower bound on what the attacker keeps. Test: `test_retained_credentials_do_not_follow_renewals`. |

## Adversary and communication assumptions

| Item | Status | What changed |
|---|---|---|
| R05 Insider transmits from the victim's position | Limitation | Not changed. The insider forger is given a radio at the position it claims; stated in 3.5.0 as an upper bound on the attacker; from 3.6.0 a conditional model result, not a formal bound. |
| R06 Insider experiment does not isolate one entity | Limitation | Not changed. All four entities forge in the same run; stated. |
| R07 Attackers obtain oracle information | Limitation | Not changed. The former holder and insider act on simulator truth (current holder, its position, its silent period, its certificate); labelled in 3.5.0 as an upper bound; from 3.6.0 a conditional model result, not a formal bound. |
| R08 GPS error does not reach the plausibility detector | Partly addressed | The physical position, the measured position a vehicle signs (`gps_noise_m`, AR(1) with `gps_noise_corr`) and the observer's estimate (`position_noise_m`) are now separate. The default (no sensor error on signed positions) reproduces the runs in the results; benign false positives under sensor noise are not measured in this version. |
| R09 One idealized detector | Partly addressed | `V2VLayer` has three detectors (two-places-at-once, range, kinematic), tolerance parameters, per-reception loss, and counts honest messages received and rejected. The results use the default speed bound; no sensitivity is reported. |
| R10 RSUs do not supply independent observations | Partly addressed | A local clone-check history per RSU is available (`rsu_history="local"`); E1r still uses the shared ledger state, so its multi-RSU quorums are correlated witnesses, as stated. |
| R11 Revocation latency mixes policy with schedules | Partly addressed | Continuous report processing with a delivery delay (`report_processing="continuous"`, `report_delay_s`) and a matched per-second misbehaver (`malicious_replay="per_second"`) are available, and the simulator records the time of each vehicle's first report and first replay (`recycling_report()["revocation_timing"]`). E1r is run at the defaults, so its latencies still include round batching and the workload difference, as stated. |

## Privacy metrics and statistical inference

| Item | Status | What changed |
|---|---|---|
| R12 Non-significant difference presented as equality | Fixed | An equivalence margin of ±1 point of link rate (set in 3.5.0, after the earlier results; labelled exploratory) and two one-sided tests on the paired differences, with the paired-difference interval and the number of valid pairs in every cell. Attack-free, recycle is 0.2 to 0.4 points less linkable than fresh and equivalent within the margin on the ring and both traces; the direction is stated. Test: `test_equivalence_uses_valid_pairs_and_the_margin`. |
| R13 Paired seeds do not give the same denominator | Fixed | An attack-free comparison on the same traffic (`privacy_attack_free`: identical true-change counts across modes) is reported beside the joint security and privacy run. |
| R14 Tracker does not hear attack traffic | Fixed | Forged CAMs are added to the eavesdropper's beacon stream, with the true sender used only for scoring. With forgeries on the air recycle is 0.9 to 2.2 points less linkable than fresh, a side effect of the attack. Test: `test_tracker_hears_forged_cams`. |
| R15 Coverage rewards merging | Fixed | `cluster_metrics` reports pair recall, cluster purity, and each vehicle's observed beacon-seconds (called "driven seconds" in 3.5.0; renamed in 3.6.0, with a separate driven-time share) attributed to its own identity, to a wrong one, or to an ambiguous cluster. Tracker plus PM at 40 veh/km: purity 0.67, 38 % of seconds correctly attributed, 33 % ambiguous (3.4.0 reported 90 % coverage). Test: `test_all_merged_clusters_are_not_reported_as_attribution`. |
| R16 Different denominators hidden | Fixed | Per-seed numerators and denominators in every result file; exposure p95 is the pooled percentile over all exposure windows, with the window count; messages, receiver checks, reports and distinct vehicles are separate fields. Test: `test_pooled_percentile_is_not_a_mean_of_percentiles`. |

## Cost accounting and the proposed fix

| Item | Status | What changed |
|---|---|---|
| R17 CPU results are a partial coefficient model | Fixed as far as a simulation can | Sign, verify, key generation, encryption and decryption are measured on the machine that runs the study (`calibrate_op_costs`) and recorded with the hardware, Python and library versions. Signatures in RSU and PM transactions, package encryption at the PKI and decryption at the PM are now counted. Every load report gives a ×0.5 to ×2 range. Fresh issuance: 27 CPU-s per 1,000 vehicle-hours at the PKI plus 38 at the PMs (3.4.0: 54 from assumed costs). These remain software estimates; database, storage and network service costs are outside the model, as stated. Test: `test_rsu_block_transactions_are_counted`. |
| R18 Message size reflects the simulator's encoding | Fixed | `v2/sizes.py` gives a standards-based CAM size (typical COER sizes for IEEE 1609.2 / ETSI TS 103 097, not a byte-exact encoder) with a certificate-attachment parameter: rekey is 1.47 times recycle with the certificate in every message, 1.18 at one in five, 1.12 at one in ten. "Twice the bytes" is withdrawn as the expected cost. Test: `test_standard_size_model_ratios`. |
| R19 Fresh baseline is an ablation | Scoped | Labelled a matched ablation of the issuance mechanism; not an SCMS-style system. |
| R20 Re-keying not specified against an active issuer | Scoped | The trust assumption (an honest PM issues the holder-bound certificate) is stated, with what is absent: authenticated enrolment with proof of possession, a grace period, overlapping transfers, base-certificate expiry over a lifetime. |

## Scenario design and reproducibility

| Item | Status | What changed |
|---|---|---|
| R21 SUMO realism | Partly addressed | The sources of randomness are stated (the trace fixes the traffic; seeds vary keys, attacker choice and noise). Return of a departed vehicle's pseudonyms is a parameter (`departed_return_prob`, `departed_return_delay_rounds`): any policy short of immediate return leaves recycling 100 to 280 unserved requests per run, fresh_vgk none. Five motorway traffic realizations (SUMO `--seed` 1 to 5) are run. The road remains one-dimensional; no urban scenario. Test: `test_departed_pseudonyms_can_be_lost`. |
| R22 Full-trace statistics mixed with the window | Fixed | `trace_info` exports `full_*` and `window_*` statistics under distinct names; attackers are drawn from the vehicles inside the evaluated window (22 on LuST, 29 on the motorway, not 61 and 103), and the achieved, time-weighted attack share (attacker vehicle-seconds over all vehicle-seconds) is reported. Test: `test_attackers_are_drawn_from_the_evaluated_window`. |
| R23 Cloud leakage not invariant across modes | Fixed | The cloud channel is "uploads" or "absent" per mode, and its link rate is "not applicable" where absent (fresh, fresh_vgk); the text says the leak exists only where pseudonyms are uploaded. |
| R24 Incomplete audit trail | Fixed | `requirements.lock` with exact versions and a Dockerfile built from it; `scripts/make_sumo_traces.sh` regenerates the traces and checks them against `config/sumo/CONTENT_SHA256SUMS` (content hashes that ignore SUMO's timestamped header); `scripts/reproduce.sh` is the single entry point; every result file carries per-seed records, and the run records the commit, dirty flag, command line, calibration and whether deterministic signing was in effect; [figure_map.md](figure_map.md) maps every figure to its command and data. Analyses added after the pre-registered plan are labelled exploratory. |
| R25 Tests do not establish scientific validity | Partly addressed | `tests/test_review.py` adds 13 invariant tests at the interface between the simulator, the metrics and the reports (listed above). Realistic transmitter positions are not tested because they are not modelled (R05), and no golden per-seed output is archived beyond the per-seed records in `results/`. |

## What changed in the conclusions

* **Accountability failure: unchanged in kind, corrected in size.** 35 % of honest
  vehicles in two minutes (S1, 5 % former holders), not "33 of 97"; 98 % over
  600 s; 18 % of those seen on the SUMO motorways (3.4.0: about a fifth, against
  an inflated attacker set).
* **Certificate lifetime now matters over 600 s.** It bounds both a former holder's
  forgeries and a revoked vehicle's acceptance. 3.4.0's "it changes nothing" came
  from the R04 aliasing.
* **Privacy: equivalent, now tested as such.** Equivalent within ±1 point without
  attackers; with forgeries heard, recycle is less linkable, as a side effect of the
  attack.
* **Insider identity attribution is weaker than 3.4.0 implied.** A PM attributes
  half of a vehicle's driving to it; colluding with the tracker at high density
  makes a third of the driving ambiguous.
* **Costs: halved at the PKI, with load newly counted at the PMs.** Fresh issuance
  costs 27 CPU-s per 1,000 vehicle-hours at the PKI with measured costs, plus the
  PMs' decryption. Re-keying costs 12 to 47 % more bytes, not 100 %.
