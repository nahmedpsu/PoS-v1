# PoP v2 results

Back to the [README](../README.md). Design rationale in [pop_v2.md](pop_v2.md).


Numbers from `results/v2/` and `figures/v2/`, produced by `pop-sim run-v2` on the
same machine as the v1 run (88 s wall time). Each subsection names the item of
[docs/pop_v2.md](docs/pop_v2.md) it measures.

### 1. Verifiable election: what one node pays (`v2_election_cost.json`)

| Nodes | PoET, all nodes (us) | PoP v1, server total (us) | PoP v2, one node: own proof + verify winner (us) | PoP v2, race over received values (us) |
|---|---|---|---|---|
| 10 | 24 | 494 | 7,351 | 16 |
| 100 | 67 | 280 | 7,325 | 29 |
| 200 | 107 | 314 | 7,222 | 38 |

PoP v2's per-node cost is flat in the network size: one RSA-2048 FDH proof
(7.2 ms in pure Python with the CRT; about 1 ms with OpenSSL) and one 0.17 ms
verification. The race itself stays in the tens of microseconds. What v2 buys for
those 7 ms is that nobody can lie about or grind the value and no server exists to
spoof. Key generation is 46 ms per node, once.

![Election cost](../figures/v2/v2_election_cost.png)

### 5. Forks: the manuscript's timer range is unsafe on a real network (`v2_forks.json`)

Fork probability per block, 20 nodes, 50 % participation, log-normal link delay:

| Time limit | 5 ms links | 20 ms links | 100 ms links |
|---|---|---|---|
| 0.1 s | 0.41 | 0.90 | 1.00 |
| 0.25 s (manuscript's maximum) | 0.21 | 0.53 | 0.99 |
| 1 s | 0.06 | 0.19 | 0.69 |
| 2 s | 0.02 | 0.14 | 0.38 |

A node whose timer fires before the winner's block reaches it publishes too. With
the paper's 10 to 250 ms timers and ordinary 20 ms links, more than half of the
blocks fork. The time limit must be a large multiple of the propagation delay, which
makes PoP's block time a network property, not a free parameter. The v2 fork rule
(smaller VRF value wins) resolves forks deterministically, but the wasted blocks
remain.

![Forks](../figures/v2/v2_forks.png)

### 5 and 7. Block latency on the same network, six algorithms (`v2_latency.json`)

20 ms links with 1 % loss, measured costs (ECDSA verify 0.11 ms, VRF prove 7.8 ms,
one difficulty-3 puzzle 2.2 ms), 50 rounds per point:

| Nodes | PoW 2 | PoET | PoP v1 (server) | PoP v2 (VRF) | PBFT | Raft | PBFT messages |
|---|---|---|---|---|---|---|---|
| 10 | 58 ms | 77 ms | 259 ms | 100 ms | 93 ms | 107 ms | 189 |
| 20 | 73 ms | 89 ms | 297 ms | 100 ms | 138 ms | 110 ms | 779 |
| 100 | 165 ms | 167 ms | 599 ms | 190 ms | 221 ms | 204 ms | 19,899 |

PoP v1 is the slowest at every size because of its handshake and selection round
trips with the server. PoP v2 removes those and lands with PBFT and Raft while
sending O(n) messages per block instead of PBFT's O(n^2). PoW 2 at difficulty 3 is
the fastest here because the puzzle is trivial; its cost scales with difficulty and
hardware, the others' do not.

![Latency](../figures/v2/v2_latency.png)

### 2. Measured unlinkability (`v2_linkability.json`)

Fraction of pseudonym changes a kinematic tracker links correctly (pseudonym change
every 30 s, 3 m GPS noise, 300 s of traffic, dead reckoning up to 20 s):

| Vehicles / km / direction | Synchronized, no silence | Synchronized, 3 s silence | Synchronized, 10 s silence | Unsynchronized, 10 s silence |
|---|---|---|---|---|
| 2 | 0.92 | 0.88 | 0.82 | 0.91 |
| 10 | 0.90 | 0.84 | 0.75 | 0.84 |
| 80 | 0.59 | 0.51 | 0.30 | 0.41 |

Changing the pseudonym alone buys almost nothing: on a quiet road nine changes in
ten are linked by position and speed. The scheme protects only where the manuscript
says shuffling should happen, in dense traffic, and only if the changes are
synchronized across vehicles (a mix zone) and followed by a silent period. At 80
vehicles per km with synchronized changes and 10 s of silence the tracker links
30 % and mis-links another 25 %. This is the quantitative form of the paper's
unlinkability claim, and its limit.

![Linkability](../figures/v2/v2_linkability.png)

### 3. Demand-aware distribution (`v2_demand.json`)

8 vehicles per km (65 vehicles), 6 rounds, stock-outs are vehicles that arrive at a
distribution and find fewer than their 3 sets:

| Shuffle every | Safety stock 0 | 10 % | 25 % | 50 % |
|---|---|---|---|---|
| 20 s | 26 stock-outs | 6 | 0 | 0 |
| 40 s | 41 | 13 | 5 | 0 |
| 80 s | 39 | 17 | 10 | 2 |

Pseudonyms issued per vehicle: 3.0, 3.5, 3.9, 4.6 for the four stock levels. With
the forecast alone a sixth of the vehicles are left short every round; a 25 % safety
stock (about one extra pseudonym per vehicle in the domain) removes stock-outs at a
20 s shuffle period, and 50 % does so at 40 s. Longer shuffle periods need more stock,
and (previous table) give the tracker more time.

![Demand](../figures/v2/v2_demand.png)

### 4. Blockchain of blockchains (`v2_anchoring.json`)

| RSU blocks per anchor | Allotment proof size | Verification |
|---|---|---|
| 10 | 1,173 bytes | 11 us |
| 100 | 1,400 bytes | 12 us |
| 1,000 | 1,626 bytes | 16 us |

A vehicle entering another PM's area carries a 1.2 to 1.6 KB proof (logarithmic in
the anchor's span) that a foreign PM verifies in microseconds from the PM chain
alone. Editing one transaction on an RSU chain, even with the RSU re-hashing its
block, is detected from the PM level in every case.

![Anchoring](../figures/v2/v2_anchoring.png)

### 6. Sybil resistance (`v2_sybil.json`)

Attacker's share of published blocks, 20 honest nodes, 2,000 rounds:

| Sybil identities k | PoP v1, attacker reports the minimum timer | PoP v1 honest / PoP v2 with k VRF keys | PoP v2, PKI-bound (one certificate) |
|---|---|---|---|
| 1 | 0.50 | 0.05 | 0.05 |
| 5 | 0.97 | 0.20 | 0.05 |
| 20 | 1.00 | 0.50 | 0.05 |

Random selection does not prevent Sybil attacks: an attacker with k identities
wins k/(n+k) of the blocks, and in v1 a single lying identity wins half of them.
What bounds the attacker is binding the election key to a PKI certificate, which v2
does: then one compromised PM is one identity, at 5 % of the blocks whatever k is.

![Sybil](../figures/v2/v2_sybil.png)

### End-to-end PoP v2 protocol (`v2_protocol.json`)

2 PMs, 6 RSUs, 65 driving vehicles, 5 rounds of 30 s, 3 s silent period, 3 m GPS
noise, 25 % safety stock, one malicious vehicle; run under the v2 election and, for
reference, the v1 election:

| | PoP v2 (VRF) | PoP v1 (server) |
|---|---|---|
| PM-chain election per round | 7.2 ms | 150 ms (incl. the winner's wait) |
| RSU-chain elections per round, both PMs | 30 ms | 390 ms |
| Every PM block verifies against the certified VRF key | yes | n/a |
| Stock-outs over 5 rounds | 3 | 3 |
| Pseudonym changes linked by the tracker | 78 % | 77 % |
| Allotment proof | 2,150 bytes, 20 us | 1,233 bytes, 11 us |
| Malicious vehicle caught and revoked | yes | yes |

The election change does not alter privacy or distribution (same traffic, same
shuffle); it removes the server and makes every block verifiable at a cost of a few
milliseconds per node.

![Protocol](../figures/v2/v2_protocol.png)

### What v2 establishes

* The published PoP is not safe to deploy as described: its timer range forks on
  ordinary links, its server is a trusted party, its random time is unverifiable, and
  it is not Sybil-resistant. PoP v2 fixes the last three at about 7 ms per node per
  block and makes the first a measured design constraint.
* Pseudonym shuffling protects location privacy only in dense traffic with
  synchronized changes and silent periods. The simulation gives the curve.
* An RSU needs roughly 25 to 50 % more pseudonyms than its forecast to avoid
  stock-outs, depending on the shuffle period.
* Cross-PM proofs and tamper detection cost a few hundred bytes and microseconds.

