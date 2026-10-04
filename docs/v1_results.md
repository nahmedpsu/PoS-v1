# PoP v1 results: the manuscript reproduced

Back to the [README](../README.md).


Numbers below are from `results/` and `figures/`, produced by the full run on the
reference machine recorded in `results/run_info.json` (Python 3.11, x86_64, cloud
container). They are machine dependent; the shapes are what matters.

### Proof of Work 1 (Figures 7 and 8, `results/pow1.json`)

| Puzzle | Guesses | CPU time (s) | Note |
|---|---|---|---|
| 0a | 3,667 | 0.004 | measured |
| 0ab | 256,648 | 0.28 | measured |
| 0abc | 17,965,319 | 20.5 | measured |
| 0abcd | 1.3 x 10^9 | 1,376 | extrapolated |
| 00a | 258,467 | 0.28 | measured |
| 00ab | 18,092,648 | 20.3 | measured |
| 00abc | 1.3 x 10^9 | 1,380 | extrapolated |
| 00gf | 18,093,072 | 19.6 | measured |
| 00gfs | 1.3 x 10^9 | 1,415 | extrapolated |
| 00upha | 9.4 x 10^10 | 101,886 | extrapolated |

Every extra character multiplies the search by the size of the guessing set (70), so
the puzzle, not the hardware, decides the time. The paper reports 0.2 s to 2,018 s for
the same ten puzzles; the ordering is reproduced, the absolute values depend on the
enumeration order (see `docs/paper_mapping.md`).

![Fig. 7](../figures/fig07_pow1_cpu_time.png)

### Proof of Work 2 (Figures 9 and 10, `results/pow2.json`)

| Transactions | d = 3 (s) | d = 4 (s) |
|---|---|---|
| 100 | 0.34 | 5.1 |
| 500 | 1.31 | 22.4 |
| 1000 | 2.69 | 44.3 |

Linear in the number of transactions and 16x per extra leading zero, as in the paper
(1.6 to 19.5 s and 34 to 286 s on the authors' machine).

![Fig. 10](../figures/fig09_10_pow2_d4.png)

### PoET and Proof of Pseudonym elections (Figures 11 and 12, `results/poet.json`, `results/pop.json`)

Ten rounds each. PoET, 10 nodes: winners' random short times 0.01 to 0.07 s. PoP,
20 nodes with the server drawing the miner percentage in [50, 100] every round:
11 to 20 nodes mine, winners' times 0.01 to 0.06 s, the election itself takes
50 to 90 microseconds (2.8 ms in the first round, which includes key set-up). Every
election record verifies against the server's signature.

![Fig. 12](../figures/fig12_pop_winners.png)

### Comparison (Figure 13, `results/comparison.json`)

Ten runs of each: PoW 2 at difficulty 3 takes 0.34 to 2.7 s, PoW 1 0.004 to 10^5 s,
Proof of Pseudonym 0.01 to 0.06 s. PoP does not solve a puzzle, so its cost is the
winner's random short time plus a sub-millisecond election.

![Fig. 13](../figures/fig13_comparison.png)

### Block time (Figure 14, `results/block_time.json`)

`tB = nT*tV + 2*tP + tprep + tM*N` with measured `tV` = 0.115 ms per transaction
(ECDSA P-256 verification), `tP` = 1 ms, measured `tprep`, and 10 nodes (PoP: 5 miners).

| Transactions | PoW 2, puzzle per transaction (s) | PoW 2, one puzzle per block (s) | Proof of Pseudonym (s) | PoW reported by [31] (s) |
|---|---|---|---|---|
| 100 | 0.35 | 0.035 | 0.24 | 0.2 |
| 500 | 1.37 | 0.081 | 0.29 | 1.0 |
| 1000 | 2.81 | 0.138 | 0.35 | 2.0 |

With the paper's measurement model (every transaction hashed to the difficulty) PoP
is 1.4x cheaper than PoW at 100 transactions and 8x cheaper at 1000, which is the
Figure 14 result. If PoW solves a single difficulty-3 puzzle per block, PoW is cheaper
than PoP in this implementation, because PoP's `tM` (46 ms on average) is the random
short time the winner waits, while one difficulty-3 puzzle takes 2 ms here. The
advantage of PoP therefore lies in not scaling with the puzzle difficulty or hardware,
not in beating a trivial puzzle.

![Fig. 14](../figures/fig14_block_time.png)

### Election cost vs network size (Table 2, `results/scalability.json`)

| Nodes | PoET, all nodes (us) | PoP race, 50 % of nodes (us) | PoP total incl. selection and signed record (us) |
|---|---|---|---|
| 10 | 7 | 3 | 47 |
| 100 | 42 | 23 | 88 |
| 1000 | 407 | 211 | 559 |

The race among half the nodes costs about half of PoET's (the O(n/2) vs O(n) of
Table 2); the server's random selection and the ECDSA signature on the election
record add roughly 40 us plus a per-node shuffle, so the total stays above PoET.

![Scalability](../figures/fig_scalability.png)

### End-to-end protocol (`results/protocol.json`)

2 PMs, 6 RSUs, 30 vehicles, 3 pseudonyms per vehicle, 5 shuffle rounds, one malicious
vehicle, run once per consensus. In every run: all 90 pseudonyms come back and are
re-allotted each round, no pseudonym is ever handed back to a vehicle that used it,
both blockchain levels validate, the malicious vehicle is caught on its first replay
and revoked, and PKI is accessed 31 times (30 registrations, 1 revocation).

| Consensus | Mean PM-chain consensus per round (s) | Mean RSU-chain consensus per round, both PMs (s) |
|---|---|---|
| Proof of Pseudonym | 0.048 | 0.320 |
| PoET | 0.096 | 0.274 |
| PoW 2 (d = 3, one puzzle per node) | 0.004 | 0.030 |
| PoKW (d = 3, kernel of half the nodes) | 0.003 | 0.009 |

These times include the winner's random wait for PoP and PoET (simulated, not slept),
which is why the two puzzle-free algorithms look slower than a difficulty-3 puzzle on
a tiny network. The protocol itself (signing, encryption, shuffling, ledger checks) runs
in about 0.1 to 0.3 s for the five rounds.

![Protocol](../figures/fig_protocol.png)

## Security scenarios (Section VI)

`experiments.exp_security` runs each threat and checks the counter-measure
mechanically; `tests/test_protocol.py` asserts them all.

| Threat (manuscript) | What the simulation does | Outcome |
|---|---|---|
| Tampering with the ledger | Changes one byte of a published transaction | Chain validation fails |
| Forged PKI broadcast | Attacker signs a pseudonym package with their own key | PM rejects the package |
| Curious / compromised RSU (Section VI-C) | RSU tries to decrypt a transaction addressed to the PM | AES-GCM authentication fails; the PM can read it |
| Spoofed PM (Section VI-B-3) | A PM that was not elected publishes a block, with the real election record or a self-signed one | Both blocks rejected |
| Internal Tricking Adversary (Section VI-B-2) | A compromised OBU keeps a copy of a used pseudonym and replays it | Flagged by the RSU, reported to the PM, certificate revoked by the PKI; honest vehicles are never flagged |
| Global / Local Passive Adversary (Section VI-B-1) | Eavesdropper collects every safety message over 5 shuffle rounds and tries to link them by pseudonym | 0 of 450 messages link to an earlier message of the same vehicle; every pseudonym passed through several vehicles |
| Single point of failure | PKI access count | Equals the number of vehicles (registration only) plus revocations |

## Honest notes on what the simulation shows and does not show

* PoP's advantage over PoW in the paper comes from not solving a puzzle at all; the
  simulation reproduces that (Figures 13 and 14). Whether PoP is also cheaper than
  PoET depends on what is counted: the race among 50 % of the nodes is about half the
  cost of PoET's race among all nodes (Table 2's O(n/2) vs O(n)), but the server's
  random selection and the signature on the election record add a fixed cost, so the
  total election time of this implementation is above PoET's at every network size
  tested. Both are well under a millisecond for 1000 nodes; the winner's random short
  time (10 to 250 ms) dominates either.
* The random short time is simulated, not slept, except with `real_wait=True`.
* All nodes run in one process; network propagation is the constant `tP` of the formula.
* The PoW 1 numbers for puzzles longer than four characters are extrapolations, see
  `docs/paper_mapping.md`.
* The scheme is reproduced faithfully to the manuscript's algorithms; two additions
  that the manuscript implies but does not spell out (no-return-to-previous-holder
  allotment and the signed election record) are documented in `docs/paper_mapping.md`
  and can be switched off.

