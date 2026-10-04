# PoP v2: what changed and why

PoP v1 is the manuscript's protocol as published. PoP v2 is the set of
extensions in this repository that address what the v1 simulation exposed.
Each item below names the weakness, the change, the code, and the experiment
that measures it. Numbers are in the README's "PoP v2 results" section.

## 1. Verifiable random election (`consensus/popv2.py`, `vrf.py`)

**Weakness.** Algorithm 6 has a cloud server choose the miners and trusts every
node's self-reported random short time. A node that always reports the smallest
value wins every round it is selected for, and the server is a single point of
trust in a protocol whose stated goal is to have none.

**Change.** Every node holds a VRF key whose public half PKI certifies at
registration: by default an ECVRF over secp256k1 (RFC 9381 Section 5
construction on libsecp256k1, 0.16 ms per proof), with the pure-Python
RSA-FDH-VRF of RFC 9381 Section 4 as a fallback. For block `i` the node
evaluates the VRF on the previous winner's output and `i` (the block hash
is used only for the first block after genesis). The output, read as a number in [0, 1), is
the node's "random short time": it is unique for that key and input, so it can
be neither chosen nor ground, and the proof travels in the block for everyone to
verify. Nodes with an output below 0.5 are this block's miners (the paper's
"not less than 50 percent"), the smallest output wins, and if two valid blocks
reach a node the smaller output wins (`fork_rule`). There is no server.

**Measured.** `exp_v2_election_cost`: what one node spends per block (its own
proof plus verifying the winner's), against PoET and the v1 server.

## 2. Measured unlinkability (`v2/mobility.py`, `v2/adversary.py`)

**Weakness.** The manuscript asserts unlinkability because pseudonyms change.
The v1 run measured only pseudonym reuse. An eavesdropper also sees position,
speed and heading in every CAM.

**Change.** Vehicles drive on a two-direction ring road with Poisson traffic
density, beacon once a second with GPS noise, and change pseudonym on a
schedule, optionally keeping silent for a few seconds after each change. Two
Global Passive Adversaries continue trajectories across pseudonym changes and
are scored against ground truth: a nearest-neighbour baseline (constant
velocity, fixed gate widening during silence) and, the default, a Kalman
filter per track with Mahalanobis gating and global assignment by the
Hungarian algorithm (the GNN tracker of the tracking literature). The Kalman
tracker links more, so its numbers are the conservative bound.

**Measured.** `exp_v2_linkability`: fraction of pseudonym changes the tracker
links correctly versus traffic density, for silent periods of 0, 3 and 10 s and
for synchronized (mix-zone) and unsynchronized changes.

## 3. Demand-aware distribution (`entities.RSU.update_forecast`, `shuffle`)

**Weakness.** The paper says shuffling targets zones of maximum traffic but the
pseudonym stock an RSU needs, and how often shuffling must run, are not
addressed.

**Change.** In mobility mode RSU membership follows vehicle positions. Each RSU
keeps an exponential moving average of the vehicles under coverage and requests
forecast times (1 + safety stock) sets; the cloud relocates to PMs by net
demand. Vehicles that arrive at a distribution and find fewer sets than they
need are counted as stock-outs.

**Measured.** `exp_v2_demand`: stock-outs and pseudonyms issued per vehicle
versus safety stock and shuffle period.

## 4. Blockchain of blockchains with anchors (`v2/anchoring.py`)

**Weakness.** The RSU-level and PM-level chains are not connected, so a tampered
RSU chain is invisible from above and a vehicle moving to another PM has no way
to prove its allotment.

**Change.** Every block now commits to its transactions through a Merkle root,
and every PM-level block carries, per PM, the Merkle root of the RSU-level block
hashes since the previous anchor. `detect_rsu_tamper` recomputes anchors from
the RSU chain; `build_allotment_proof` produces a proof of an `allot`
transaction (Merkle path to its block, RSU header, Merkle path to the anchor,
PM block hash) that a foreign PM verifies with nothing but the PM chain. The
transaction stays encrypted: the verifier learns inclusion, not the set.

**Measured.** `exp_v2_anchoring`: proof size and verification time versus the
number of RSU blocks an anchor covers, with tamper detection checked.

## 5. Network model and forks (`v2/network.py`)

**Weakness.** All nodes run in one process and propagation is a constant. A
timer-based election forks whenever a node's timer fires before the winner's
block reaches it, which the manuscript never considers.

**Change.** Per-link log-normal latency with loss. `simulate_timer_forks`
measures the fork probability of PoP v1/v2 and PoET as a function of latency
and time limit. Six consensus algorithms get latency models on the same
network with measured cryptographic costs: PoW 2, PoET, PoP v1, PoP v2, PBFT
and Raft, plus their message counts.

**Measured.** `exp_v2_forks`, `exp_v2_latency`.

## 6. Sybil and collusion analysis (`v2/sybil.py`)

**Weakness.** The manuscript states that random selection prevents Sybil
attacks.

**Change.** Analytic and simulated attacker share of blocks for PoP v1 with
honest timers, PoP v1 with an attacker that reports the minimum timer, PoP v2
with `k` VRF keys, and PoP v2 with PKI-bound keys where the attacker's
identities are limited to the certificates it holds.

**Measured.** `exp_v2_sybil`.

## 7. Benchmark packaging and repositioning

`pop-sim bench config/benchmark.json` runs the protocol from a configuration
file (any `ITSConfig` field, including the road), so other consensus
algorithms or parameters can be plugged in. The README states PoP's advantage
as independence from puzzle difficulty and hardware, not raw speed, because a
single difficulty-3 puzzle per block is cheaper than PoP's random wait.

## What v2 does not do

* Nodes still run in one process; the network model is sampled, not emulated.
  Running the PMs as separate processes or on devices is the next step.
* The ECVRF is on secp256k1 rather than P-256 because that is the curve the
  fast library exposes point operations for; the construction is otherwise
  that of ECVRF-P256-SHA256-TAI.
* The road is a ring with two directions and no intersections. Intersections
  and lane changes would weaken the tracker further; the ring is the harder
  case for privacy.
