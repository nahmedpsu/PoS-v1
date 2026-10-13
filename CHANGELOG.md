# Changelog

## 3.6.0 - response to the follow-up review of 3.5.0

Every item of the follow-up review (G01 to G10) is answered in
docs/review_response_round2.md; every dependent experiment was rerun.

Corrections that change reported numbers:

* G01: every misbehaviour report goes through one hook and is counted by route
  (forged message, own beacon, replay, insider), naming honest vehicles only.
  S1 at 120 s: forged messages name 19.7 honest vehicles, their own beacons
  25.5 more; 43.4 honest vehicles reported, all revoked.
* G02: attackers keep the last credential of each round too (55 to 60 per
  run, not about 40).  S1 revokes 48 % of honest vehicles in 120 s (3.5.0:
  35 %) and 99 % in 600 s; 22 to 24 % of those seen on the SUMO motorways.
* G03: exposure per contiguous window and per holding, with censoring.  S1's
  window is the holder's 7 s slot (3.5.0: 32.6 s, a sum of episodes).
* G04: holder windows are half-open (t_start, t_end]; no handoff instant has
  two valid holders.
* G06: equivalence is a paired t TOST on the mean difference with its 90 %
  interval; conclusions unchanged.
* G07: identity attribution is a share of observed beacon-seconds, with a
  driven-time share beside it.
* G08: opportunities are key checks, valid-key seconds and eligible seconds.
* G10: CPU by entity and operation; the PMs' cost under fresh issuance is
  certificate verification (98 %), not decryption.  ECIES has a per-byte term.
* E2 and E2x run under every issuance mode: a revoked vehicle is believed until
  expiry under recycle, fresh and fresh_vgk, and not at all under rekey.
* SUMO revocation shares are over the honest vehicles seen in the window.

Added:

* G09: provenance (commit, source-diff SHA-256, captured at start) and the
  cost calibration inside every result file; per-seed records in E3 and E3b,
  per-seed load counts in E4; requirements-sumo.lock; the Dockerfile copies
  scripts and can install SUMO; E1 strategy bars and the E3 attribution split.
* tests/test_review2.py, 9 tests; 112 tests.

Not changed, stated: every former-holder schedule reads simulator state
(G05), so its rates are conditional model results; former holders stop once
revoked; insider CAMs are not fed to the eavesdropper; the manuscript's own
figure build path lives with the manuscript.

## 3.5.0 - response to the external review of 3.4.0

Every item of the review (R01 to R25) is answered in docs/review_response.md;
every recycling experiment, both SUMO traces, the v2 results, the attack bench and
the use cases were rerun.

Corrections that change reported numbers:

* R01: honest, attacker and total populations and revocations are disjoint
  per-seed fields.  S1 revokes 31.8 of 91.5 honest vehicles in 120 s (35 %) and
  89.6 (98 %) in 600 s; 3.4.0's column included revoked attackers.
* R02: cells with no attempts are "not applicable" (null), not 0 % or 100 %, and
  paired tests on them say so.  Retained credentials still valid are sampled in
  every mode.
* R03: receivers cache only signature verification and recheck expiry, holder
  window, freshness and plausibility on every delivery.
* R04: a former holder keeps an immutable snapshot of each credential.  Over
  600 s a 300 s lifetime now cuts S1 receiver acceptance from 96 % to 81 % and a
  revoked vehicle's acceptance from 540 s to 240 s; 3.4.0's flat lifetime axis
  came from the aliasing.
* R14: the eavesdropper hears forged CAMs.  R13 and R12: an attack-free privacy
  comparison on the same traffic with a +-1 point equivalence test; recycle and
  fresh are equivalent (recycle 0.2 to 0.4 points less linkable).
* R15: pair recall, purity and identity attribution per driven second; tracker
  plus PM at 40 veh/km attributes 38 % of driving correctly, 33 % ambiguously.
* R17: CPU costs measured per run (sign, verify, keygen, encrypt, decrypt) with
  a x0.5 to x2 range; transaction signatures, package encryption and decryption
  counted.  Fresh issuance: 27 CPU-s per 1,000 vehicle-hours at the PKI plus 38
  at the PMs (3.4.0: 54).
* R18: standards-based CAM size model (v2/sizes.py): rekey costs 1.12 to 1.47
  times the bytes, not twice.
* R22: SUMO attackers are drawn from the vehicles in the evaluated window (22
  and 29, not 61 and 103); full-trace and window statistics are exported
  separately.  S1 revokes 18 % of the honest vehicles seen.
* R23: the cloud channel is "absent" in fresh modes.

Added:

* R21: departed-vehicle return policy (`departed_return_prob`,
  `departed_return_delay_rounds`, `recycling-sumo --returns`) and five motorway
  traffic realizations (comma-separated `--trace`).
* R08 to R11 (options, defaults unchanged, not swept in the results): sensor
  noise on signed positions, range and kinematic detectors, tolerance, message
  loss, per-RSU clone history, continuous report processing, per-second
  misbehaver.
* R24: requirements.lock, Dockerfile on python:3.11-slim, trace regeneration
  script with content checksums, scripts/reproduce.sh, provenance in result
  files, docs/figure_map.md, exploratory analyses labelled.
* R25: tests/test_review.py, 13 invariant tests; 103 tests.
* `recycling --only E1,E3b` runs selected experiments.
* Seed-grinding attack: VRF keys are derived from the attack's seed, so the
  bench gives the same result every run (the quick check failed about 3 % of
  CI runs by chance with random keys).  Block-hash seed share 0.11 to 0.44,
  chained VRF seed 0.10 (fair share 0.10).

Not changed, stated as limitations (docs/recycling.md): the adversary's
observations, transmitter placement and single-insider isolation (R05 to R07),
the fresh baseline as an ablation (R19), the re-keying trust assumption (R20),
the one-dimensional road (R21).

## 3.4.0 - scenarios on ten seeds, a stronger insider, corrected explanations

* Deployment scenarios (`pop-sim usecases`) run on seeds 1-10 and report the
  mean and a 95 % bootstrap interval of every metric; the verdict uses the
  mean linking rate.  Urban intersection 0.72 [0.70, 0.74]; with 9 s of
  silence in every 10 s period 0.51 [0.50, 0.53].  No scenario reaches the
  adequate privacy band.
* Corrected cause of the scenario and protocol figures that changed in 3.3.1:
  the old runs used the same Kalman tracker, whose same-pseudonym step before
  3.0.0 took a recycled pseudonym on another vehicle as a certain
  continuation; 3.0.0 gated that step.
* E3b: insider forgery strategies `offset` (40 m), `near` (10 m, inside the
  25 m one-second tolerance) and `silent` (holder's silent period), ten
  forgeries per entity per round, receiver / message / RSU / blame rates.
  At 40 m a third of receivers accept and the RSU blames the holder for 70 %;
  near or silent, every receiver and the RSU accept and nobody is blamed.
* Release workflow: `move_tag` repoints an existing tag.
* 90 tests.

## 3.3.1 - v2 results regenerated with the current code

* `results/v2` and `figures/v2` regenerated (`pop-sim run-v2`, `attacks`,
  `usecases`); they dated from 2.x.  They already used the Kalman tracker, but
  its same-pseudonym step then took a recycled pseudonym on another vehicle as
  a certain continuation of the earlier track, which corrupted tracks and
  pushed linking down; 3.0.0 gated that step (the 3.3.0 scoring fix moved the
  figures by under two points).  What moved: the tracker figures (end-to-end protocol 75 % ->
  96 % linked; demand-aware distribution 0.61-0.82 -> 0.97-1.00), the
  deployment scenarios (urban intersection 0.35 "adequate" -> 0.74
  "insufficient"; no scenario now reaches the adequate band), the cross-PM
  proof (33 of 42 verified, 1.6 KB, 27 us), the seed-grinding shares (block
  hash 0.09 -> 0.36, chained VRF 0.11), and timing measurements within run
  noise.  Stock-outs, forks, Sybil shares and the bench outcomes (14 defended,
  4 mitigated) are unchanged.  docs/v2_results.md, docs/attack_and_scenario_
  results.md and the README updated; the "10 s silence gives margin" claim is
  withdrawn (9 s of silence in every 10 s period still leaves 0.52).
* v1 results kept as the 1.0.0 reproduction: rerunning changes only timing
  noise and three messages of the protocol trace.
* Zenodo metadata removed; the release workflow keeps a generic republish.

## 3.3.0 - tracker scoring fix, insider forgery (E3b), the swapping papers read

* Trackers (`v2/tracker_kalman.py`, `v2/adversary.py`): a beacon assigned to
  a track that already carries its pseudonym is a continuation, not a change.
  Under recycling such re-links were counted as correctly linked changes and
  inflated the recycle link rate (1,061.7 counted against 1,058.5 true).
  `linking_success_true` (correct links over the ground-truth change count)
  is reported next to the existing rate; E3, E4 and the SUMO runs are rerun.
  Counts now equal ground truth in every mode.  A residual a third of a point
  *below* fresh remains under recycle: a recycled label reappearing on another
  vehicle near its former holder's coasting track is taken as a continuation
  (`relabel_captures`, reported per run; zero captures, zero difference).
  E3 is unchanged: the removed links joined a holding to itself.
* E3b (`exp_e3b_insider_forgery`, `ITSSimulation._insider_step`): the PKI,
  PMs, RSUs and cloud record every private key that passes through them
  (`key_custody`); once per round each signs one message with a key it holds
  on behalf of the current holder.  `PKI.certify` now takes public keys only,
  so fresh_vgk and rekey never route a vehicle's private key through the
  infrastructure.
* `pop-sim recycling --only E3,E3b,E4` reruns a subset.
* docs/recycling.md: threat model A2 and A3 updated; the two 2023 swapping
  designs (Mdee et al.; Salin) read in full: neither re-keys at transfer, both
  rely on trusted hardware and an authority's holder record.
* 89 tests.

## 3.2.0 - review follow-ups: the revocation rule, exact tests, real SUMO scenarios

* `revocation_reports` / `revocation_distinct_rsus` (ITSConfig): the PM asks
  the PKI to revoke a vehicle only after k clone reports from m distinct RSUs
  (defaults 1/1 reproduce 3.0.0).  `pop-sim recycling --sensitivity` runs E1r
  over seven rules and reports wrongful revocations, wrongful reports and the
  time a genuine misbehaver survives under each.
* `wilcoxon_signed_rank` returns the exact two-sided p-value up to 25 non-zero
  pairs (enumeration of the sign patterns, ties mid-ranked) instead of the
  normal approximation; E4's paired tests are re-reported (p = 0.002 for ten
  pairs all one way, where 3.0.0 printed 0.005).
* `pop-sim recycling-sumo --trace --corridor --name`: E1 and E4 on a SUMO
  floating-car trace (`experiments_sumo.py`).  Run on the LuST (Luxembourg)
  motorway corridor at the morning peak and on a netgenerate motorway;
  corridor files and the motorway demand are in `config/sumo/`.
* Trace roads provision every vehicle that ever enters the corridor (one that
  enters mid-run is allotted pseudonyms at the next round) and a straight
  corridor never wraps distances around (`ITSSimulation.wrap_m`).
* Results page: E2 revokes after round 2 (not "the first round") and is the
  one oracle-attribution experiment, said so; E6 explains why the bench's
  replay attack stays defended while E1's does not; one wording for the
  verdict (pre-registered case 2 with case 3 as the headline); the SUMO
  limitation replaced by the scenario results.
* Vehicles that leave a trace corridor return everything they hold through
  their last RSU (`ITSSimulation._return_departed`), so the recycled supply no
  longer drains out of the study area; SUMO E4 rerun with it.
* README and bench page: the 14/4/0 bench result is stated for oracle
  attribution, with the E6 change under ledger attribution.
* The two 2023 swapping papers (Mdee et al.; Salin) are recorded as an open
  go/no-go item in `docs/recycling.md`; neither full text is open access.
* 87 tests.

## 3.1.0 - longer horizons and SUMO traces

* `pop-sim recycling --long` / `--only-long`: E1x and E2x over a 600 s horizon,
  so certificate expiry and PKI renewal happen inside a run (the limitation
  the 3.0.0 results page stated).
* `v2/mobility_sumo.py`: SUMO FCD import mapped onto a corridor (lane
  position along an edge sequence, or an x-y axis projection); a
  `TraceRoad` drop-in for the synthetic ring, `ITSSimulation(cfg, road=...)`.
  Tested on synthetic traces only.
* 83 tests.

## 3.0.0 - pseudonym recycling study

* Research question: is pseudonym recycling ever worth it compared with fresh
  issuance?  `pop-sim recycling` runs E1-E6 (`experiments_recycling.py`).
* Vehicle-to-vehicle receivers (`v2/v2v.py`): certificate + signature checks
  without a ledger, optional local plausibility, cached cryptography.
* Former-holder adversary (`v2/recycling_attacks.py`): strategies S1 remote
  shadow, S2 co-located ghost, S3 gap filler; revoked-vehicle persistence.
* RSU attribution modes: `oracle` (v2.2.1) and `ledger` (a real RSU).
* Issuance modes: recycle, fresh, fresh_vgk (vehicle-generated keys), rekey
  (holder-bound PM-signed certificate with a fresh vehicle key) and its
  ablation window; load counters at PKI, PMs, RSUs and vehicles.
* Insider linker (`v2/insider.py`): union-find over holdings for RSU, PM,
  cloud, PKI and tracker evidence, alone and in collusion; cloud upload-order
  leak and its fix.
* Metrics module (`v2/metrics.py`) with bootstrap CIs and paired Wilcoxon.
* Trackers gate the same-pseudonym rule so a recycled pseudonym on another
  vehicle starts a new track.
* `docs/recycling.md` with the pre-registered outcome cases; v2.2.1 tagged and
  its results archived under `results/archive/v2.2.1/`.

## 2.2.1 - review fixes

* Security fix: the PoP v2 verifier read the sortition threshold and the
  miner count from the block, so a node above the threshold could get its
  block accepted by writing `threshold: 1.0` or `miners: 0`. The threshold is
  now a protocol constant and a no-miner round must carry every certified
  node's proof as evidence. Added to the attack bench ("sortition threshold
  tampering").
* New bench entry "multi-key seed choice": what an attacker with k certified
  keys gains by choosing which winning key publishes (measured, bounded).
* Docs now say what the code does: equivocation keeps the first block and
  rejects the second; sortition halves messages but does not change who wins
  (the O(n/2) claim); the chained seed covers single-key grinding; the ECVRF
  uses a private suite byte so no RFC test vectors apply.
* Seeded runs are byte-identical: P-256 and ECVRF keys derive from the seed,
  transactions and blocks are stamped from a virtual clock.
* `Blockchain.is_valid` re-checks every block's consensus proof.
* 64 tests.

## 2.2.0 - fast ECVRF and a stronger tracker

* `ecvrf.py`: ECVRF (RFC 9381 Section 5 construction, try-and-increment
  hash-to-curve, SHA-256) over secp256k1 on libsecp256k1 via `coincurve`.
  Proof 0.16 ms, verification 0.17 ms, against 7 ms / 0.2 ms for the pure
  Python RSA-FDH-VRF, which remains available (`vrf_scheme="rsa-fdh"`).
  `vrf.py` dispatches on the scheme; election-cost experiment measures both.
* `v2/tracker_kalman.py`: Kalman-filter (constant velocity) tracker with
  Mahalanobis gating and global assignment by the Hungarian algorithm. It is
  the default eavesdropper (`tracker="kalman"`); the nearest-neighbour
  baseline stays as `"nn"`. Linkability sweep, attack bench and scenarios
  report the stronger tracker, so the privacy numbers are conservative.
* Dockerfile for reproducible runs; README split into a short landing page
  with the results moved to `docs/`.
* 59 tests.

## 2.1.0 - attack bench and deployment scenarios

* `pop-sim attacks`: sixteen attacks executed against PoP v2 (value forgery,
  seed grinding, withholding, equivocation, proof replay, server DoS, Sybil
  keys, partition, pseudonym replay/cloning/forgery, fake-vehicle flood,
  revoked-vehicle persistence, RSU chain rewrite, curious RSU, tracking);
  exits non-zero if any is vulnerable, so CI runs it.
* `pop-sim usecases`: seven deployment scenarios (urban intersection, highway,
  rural night, cross-PM roaming, toll/service access, incident revocation,
  city scale).
* Protocol hardening found necessary by the bench: election seed is the
  previous winner's VRF output (grinding resistance), equivocation detection,
  certificate-checked allotment, pseudonym clone check in the ledger,
  immediate retirement of a revoked vehicle's pseudonyms.
* 53 tests.

## 2.0.0 - PoP v2

* Verifiable, serverless election (`consensus/popv2.py`) on an RFC 9381
  RSA-FDH-VRF (`vrf.py`), with PKI-certified election keys and a fork rule.
* Mobility model (ring road, Poisson density, CAM beacons with GPS noise) and a
  kinematic tracking adversary that measures linkability across pseudonym
  changes (`v2/mobility.py`, `v2/adversary.py`).
* Demand-aware distribution: RSU demand forecast with safety stock, stock-out
  accounting, cloud relocation by net demand.
* Blockchain of blockchains: Merkle transaction roots, RSU-chain anchors in
  every PM block, tamper detection from the PM level, compact cross-PM
  allotment proofs (`v2/anchoring.py`).
* Network model with latency and loss; fork probability of timer-based
  elections; block-latency and message-count models for PoW 2, PoET, PoP v1,
  PoP v2, PBFT and Raft (`v2/network.py`).
* Sybil and collusion analysis, analytic and simulated (`v2/sybil.py`).
* `pop-sim run-v2` (all v2 experiments and figures) and `pop-sim bench
  config.json` (protocol from a configuration file); `pop-sim demo --mobility`.
* 36 tests.

## 1.0.0

* Simulation of the manuscript as published: Algorithms 1 to 6, the
  pseudonym shuffling protocol over two blockchain levels, Figures 7 to 14,
  Table 2, and the Section VI threat scenarios. 23 tests.
