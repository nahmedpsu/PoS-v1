# Response to the follow-up review of v3.5.0

The follow-up review ("PoS Repository Follow Up Review", round 2) examined the
v3.5.0 merge, commit `9f494ca`, and listed ten remaining defects, G01 to G10, plus
points that should not be overstated. This page gives the status of each in
version 3.6.0. The first review's items are in [review_response.md](review_response.md);
the results are in [recycling_results.md](recycling_results.md), and the scope of the
model in [recycling.md](recycling.md#scope-after-the-external-review-of-v340-version-350).

Every experiment that depends on a changed path was rerun at 3.6.0 (E1, E1x, E1r,
E2, E2x, E3, E3b, E4, E5, E6, both SUMO traces, the five motorway realizations and
the return policies). New regression tests are in `tests/test_review2.py`; the suite
is 112 tests.

**Provenance of the 3.6.0 results.** E4 was produced from commit `9e9396b`, which
captures provenance when the command starts. The other files were produced by runs
started from `f648ef3` and record the commit checked out when each file was written
(`57fa948` to `2cd710b`). No file under `src`, `config` or `scripts` changed between
those commits (`git diff f648ef3 2cd710b -- src` is empty), so every file records the
source it ran, and every file records `source_dirty: false`.

## Remaining defects

| Item | Status | What changed | Effect on the results |
|---|---|---|---|
| G01 Report counters neither all reports nor honest only | Fixed | Every misbehaviour report goes through one hook (`PrivacyManager.report_hook`) and is tagged, for evaluation only, with its route (forged message, own beacon, misbehaver replay, insider) and true sender. `report_summary()` counts reports and distinct vehicles per route and as a union, naming honest vehicles only; `victims_blamed` is gone. Test: `test_every_report_route_is_counted_and_classified` (the honest vehicles reported equal the honest vehicles revoked under the first-report rule). | S1, 120 s: forged messages name 19.7 honest vehicles (294 reports), own beacons 25.5 more (183 reports); 43.4 honest vehicles reported, all revoked. The review's instrumented rerun of 3.5.0 found 13.7 + 135.1 reports and 31.8 vehicles; the larger 3.6.0 figures also include G02. |
| G02 Attacker discards one credential every round | Fixed | `_drive_round` calls `Vehicle._keep` on the round's last credential too. The report exports `retention.held_distinct` and `retained_distinct`. Test: `test_attackers_retain_every_credential_they_held` (recycle and fresh_vgk: retained equals held, per vehicle). | Five S1 attackers now keep 55.5 credentials per run, not about 40; S1 revokes 43.4 honest vehicles in 120 s (48 %), not 31.8, and 90.5 in 600 s (99 %). Every former-holder result moved; the "forty credentials" statement is withdrawn. |
| G03 Exposure sums separated episodes | Fixed | `exposure_windows` keys on the holding (pseudonym, holder), emits one record per contiguous segment with start, end and right-censoring at the horizon, and reports contiguous-window and cumulative-per-holding endpoints separately, each with a mean, a pooled p95 and its count. Test: `test_separated_episodes_are_separate_windows` (the review's `[0, 1, 100, 101]` gives two 2 s windows). | S1's contiguous window is 7 s, the holder's active slot (3.5.0: 32.6 s, a sum of episodes); cumulative per holding 21 s. S3: 36.8 s, censored in 100 of 174 windows. |
| G04 Re-keying fails at the handoff boundary | Fixed | Holder windows are half-open, (t_start, t_end]. The outgoing holder's last message falls exactly on t_end and the incoming holder's first is at least a second later (checked in the simulation), so the end point belongs to the outgoing holder and no instant has two valid holders. Test: `test_no_handoff_instant_has_two_valid_holders` (old key with old certificate at the boundary and just after, old key with the new public certificate, new holder at the boundary and after). | At the boundary instant itself the old certificate verifies because that instant is the old holder's own; from the next instant only the new holder's certificate verifies, and the old key never verifies under the new certificate. Rekey still stops every strategy (E5). The guarantee is stated under two conditions: honest issuance and non-overlapping windows. |
| G05 S1 and S3 use simulator holder state | Scoped, not changed | The scope section and the results page now say that S1, S2 and S3 all read the ledger's holder (S2 also the holder's position), so every former-holder rate is a conditional model result, not a feasible attack rate and not a formal upper bound. The feasibility assertion is withdrawn. A blind or observation-limited schedule is not implemented in this version (the attacker-model extensions of the first review, R05 to R07, were left out by the author's decision). | Wording only. |
| G06 Equivalence test and estimand differ | Fixed | `paired_equivalence` estimates the mean paired difference and tests it by two one-sided paired t-tests, with the matching 90 % t interval (`ci90`, the exact dual of the TOST) and a 95 % interval for the same mean. The signed-rank test is kept only as a test of difference. Student-t functions are implemented in `v2/metrics.py` (no SciPy dependency). Test: `test_equivalence_tests_the_mean_it_reports` (the review's counterexample, mean 0.0105, is now not equivalent; the TOST verdict matches the 90 % interval). | Unchanged conclusions: attack-free, recycle against fresh, 0.34 points (90 % interval 0.20 to 0.48) at 10 veh/km and 0.29 (0.20 to 0.38) at 40, both equivalent within ±1 point; with forgeries heard, not equivalent. The margin stays labelled exploratory. |
| G07 Driven time is weighted by emitted beacons | Fixed | The attribution shares are renamed `*_identity_beacon_share` and described as shares of observed beacon-seconds, pooled over all vehicles. A second denominator, `correct_identity_driven_share`, divides by all vehicle-seconds on the road (silent and unserved seconds count as unattributed). | PM: 51 % of beacon-seconds, 36 % of driven time; tracker plus PM at 40 veh/km: 38 % and 27 %. |
| G08 Opportunities are raw checks | Fixed | `ForgeryStats` counts `key_checks` (every retained key, every second), `valid_key_seconds` (a key no longer held by the attacker whose retained certificate is unexpired) and `eligible` (valid, and the strategy's condition holds: another vehicle transmitting under the pseudonym for S1/S2, nobody holding it for S3, which therefore needs no victim). Attempts are `sent`. Test: `test_opportunity_tiers_are_nested_and_expiry_counts`. | E1x S3: valid-key seconds are 48 % of key checks at 300 s certificates and 97 % at 900 s, where 3.5.0 showed the same 59,717 at every lifetime. |
| G09 Reproducibility claims outrun the artifacts | Fixed, with one gap | Each result file carries `provenance` (commit, version, command line, `source_dirty` limited to source and configuration, SHA-256 of the source diff), captured when the command starts, and `calibration` (coefficients and environment). E3 and E3b have per-seed records; E4 has per-seed load counts. `requirements-sumo.lock` pins Eclipse SUMO 1.28.0; the Dockerfile copies `scripts` and installs SUMO and git with `--build-arg WITH_SUMO=1`. The figure map states that scientific values are deterministic for a given seed and source, while timings, calibration and metadata are not. The repository draws the two layouts the review compared, the strategy bars (first panel of `E1.png`) and the identity-attribution split (`E3_attribution.png`). | The gap: the manuscript's own figure build path and figure-number map belong with the manuscript source, which is not in this repository. |
| G10 PM cost is verification, not decryption | Fixed | The load report gives CPU by entity and operation (`cpu_by_operation_per_1000_veh_h`, aggregated in `E4.json`). ECIES has a per-byte term calibrated at 120 bytes and at a 64 KB payload, and the load counts encrypted and decrypted bytes. The explanation in the results is corrected. Test: `test_cpu_breakdown_names_the_operations`. | Fresh issuance, 10 veh/km: the PMs' 37.3 CPU-s per 1,000 vehicle-hours are 36.5 verification and 0.35 decryption (8 packages of 49 KB per run); encryption costs about 0.3 ns per byte. |

## Points that should not be overstated

| Point | Status |
|---|---|
| SUMO `honest_revoked_share` divided by the full-trace honest population | Fixed: `honest` and `revoked_honest_share` are over the honest vehicles seen in the evaluated window (417 on LuST, 555 on the motorway); the trace counts are `honest_in_trace` and `revoked_honest_share_of_trace`. Test: `test_sumo_share_is_over_the_window`. S1 revokes 24 % and 22 % of the honest vehicles seen. |
| Fresh-mode retired-credential reuse is inferred, not measured; E2 ran under recycle only | Fixed: E2 and E2x run under recycle, fresh, fresh_vgk and rekey. A revoked vehicle's retained credentials are accepted for the rest of the run under the first three (60 of 60 messages in 120 s; 240 or 540 s over 600 s by lifetime) and not at all under rekey. Impersonation of another holder under fresh issuance stays "no holder to impersonate", with retained credentials counted. |
| Former holders stop forging once revoked | Stated as a restriction in the scope section and the results page; a persistent attacker is not modelled, and "upper bound" is no longer used for the attacker. |
| Insider CAMs do not reach the tracker | Stated: the eavesdropper hears every honest CAM and every former-holder CAM, not the insiders'. |
| R06: four insiders forge concurrently | Stated in the scope section; per-entity isolated runs are not provided. |
| R08 to R11: detection options exist but are not swept | Unchanged and stated. |

## Changes to the conclusions

* **Accountability failure, larger.** With every report route counted and every
  credential retained, S1 at 5 % former holders gets 48 % of the honest vehicles
  revoked in two minutes on the ring (3.5.0: 35 %) and 22 to 24 % of those seen on
  the SUMO motorways (3.5.0: 18 %). The finding is now labelled conditional on the
  simulator-conditioned attack schedule.
* **Exposure is a slot, not half a minute.** A shadowed holder is exposed for its 7 s
  active slot at a time; the gap filler for up to the full gap between holders.
* **Revocation fails in fresh issuance too.** E2 now measures what 3.5.0 inferred: a
  revoked vehicle is believed until expiry under recycle, fresh and fresh_vgk.
* **Re-keying's guarantee is exact at the boundary** under half-open windows and
  honest issuance.
* **The PM cost of fresh issuance is verification.** The figures barely change; the
  explanation does.
* **Privacy: unchanged.** Equivalent within ±1 point without attackers, now by a
  test whose estimand matches the reported mean.
