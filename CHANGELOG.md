# Changelog

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
