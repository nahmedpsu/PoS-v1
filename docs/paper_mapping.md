# Mapping between the manuscript and the code

Reference: S. Johar, N. Ahmad, A. Durrani and G. Ali, "Proof of Pseudonym:
Blockchain-Based Privacy Preserving Protocol for Intelligent Transport System",
IEEE Access, vol. 9, pp. 163625-163639, Dec. 2021, doi:10.1109/ACCESS.2021.3133423.

| Manuscript | Code | Notes |
|---|---|---|
| Table 1 notations (`v_i`, `rsu_j`, `cert_i`, `PID_i`, `pk_i`, `sk_i`) | `entities.py`: `Vehicle`, `RSU`, `VehicleCredential`, `Pseudonym`, `crypto.KeyPair` | Keys are NIST P-256; certificates are PKI ECDSA signatures over `(id, pk[, expiry])`. |
| Section IV-D, transactions carry sender/receiver keys, a timestamp, data encrypted for the receiver and the sender's signature | `blockchain.Transaction.create` | ECIES-style encryption (ephemeral ECDH + HKDF + AES-256-GCM), ECDSA signature. |
| Section I feature 5, every block hashes the preceding block | `blockchain.Block`, `blockchain.Blockchain.is_valid` | Tampering with any transaction invalidates the chain. |
| Algorithm 1, Proof of Work 1 | `consensus/pow1.py: solve_pow1` | Linear walk through the enumeration of strings over the guessing set until the puzzle string is hit. Puzzles beyond the guess budget are extrapolated from the measured guess rate and are marked `extrapolated`. |
| Algorithm 2, Proof of Work 2 | `consensus/pow2.py: mine_pow2` | `sha256(h || timestamp || nonce)` with `d` leading zero hex digits. |
| Section III-B, Proof of Kernel Work | `consensus/pokw.py: pokw_mine` | A random kernel (half of the nodes by default) runs PoW 2; the member needing the fewest hashes wins. |
| Algorithm 3, Proof of Elapsed Time | `consensus/poet.py: poet_elect` | Every node draws a random time; the smallest wins; the comparison is the linear scan of Step 3. |
| Section IV-3 and Algorithm 6, Proof of Pseudonym | `consensus/pop.py: PoPServer.elect` | Clients handshake with the server; the server fixes the miner percentage (50 % by default, optionally random in [50, 100]) and the time limit, randomly grants access to that many nodes (formula (1)), only they draw random short times, the shortest wins. The election record is signed by the server so a node that was not elected cannot publish. |
| Algorithm 4, pseudonym shuffling | `shuffle.ITSSimulation` (`_build`, `run_round`) with `entities.PKI`, `PrivacyManager`, `PMCloud` | Steps 1-3 registration through the manufacturer; steps 4-6 PKI generates pseudonym credentials and broadcasts them encrypted for the PM and signed by PKI; steps 8-9 allotment PM -> RSU -> vehicles; lines 11-16 PMs collect used sets, upload to the cloud, the cloud shuffles and relocates by traffic need; lines 18-19 PMs mine the shuffle transactions with the consensus and the winner's block is published; line 21 PMs retrieve the new sets. |
| Algorithm 5, pseudonym distribution of RSUs via blockchain | `shuffle.ITSSimulation._allot_and_distribute`, `RSU.collect_used`, `PrivacyManager.rsu_chain` | RSUs record the allotment (`allot`) and the used sets (`used`) as transactions, mine the RSU-level chain of their PM, distribute to vehicles and return the used sets to the PM. |
| Section IV-2, used pseudonyms are tracked by the blockchain and a vehicle reusing them is reported to the PM and revoked by the CA | `entities.PseudonymLedger`, `RSU.receive_message`, `ITSSimulation._process_reports` | The ledger is the materialised view of the `allot`/`used` transactions. A message with a returned pseudonym, a pseudonym held by another vehicle or a bad signature is flagged; the PM reports it and the PKI puts the certificate on the CRL. |
| Section V, formula `tB = nT*tV + 2*tP + tprep + tM*N` | `block_time.py` | `tV` and `tprep` are measured; `tP` is a constant as in the paper; `tM` is the measured mining (PoW 2) or election (PoP) time. |
| Figures 7 and 8 | `experiments.exp_pow1` | CPU time and peak traced memory per puzzle. |
| Figures 9 and 10 | `experiments.exp_pow2` | Each transaction is mined to the difficulty; 100 to 1000 transactions. |
| Figure 11 | `experiments.exp_poet` | 10 nodes, 10 rounds. |
| Figure 12 | `experiments.exp_pop` | 20 nodes, 10 rounds, random miner percentage in [50, 100]. |
| Figure 13 | `experiments.exp_comparison` | The three series side by side. |
| Figure 14 | `experiments.exp_block_time` | PoP against PoW 2 (this run) and the PoW figures reported by Bao et al. [31]. |
| Table 2, O(n) vs O(n/2) | `experiments.exp_scalability` | Election cost of PoET and PoP as the network grows from 10 to 1000 nodes. |
| Section VI, security analysis | `experiments.exp_security`, `tests/test_protocol.py` | Tampering, forged PKI broadcast, curious RSU, spoofed PM, internal tricking adversary, global passive adversary, PKI accessed only at registration. |

## Deviations and additions

* **No-return-to-previous-holder allotment.** The manuscript shuffles the
  used sets at random. A purely random shuffle hands a pseudonym back to a
  vehicle that already used it with noticeable probability in small pools,
  which would let a passive adversary link two of that vehicle's messages.
  `RSU.distribute` therefore searches, over random orderings of the set, for an
  allotment in which no vehicle receives a pseudonym it has used before. The
  flag `ITSConfig.avoid_previous_holder=False` restores the plain random shuffle.
* **Signed election record.** Algorithm 6 says only that the elected nodes are
  informed. To make the "spoofing attack" counter-measure of Section VI-B-3
  checkable, the PoP server signs `(winner, mining list, threshold)` and every
  node validates that record before accepting a block.
* **Net demand.** The cloud relocates pseudonyms according to the traffic need
  each PM reports, net of the sets it already holds, so supply follows the
  vehicles (a vehicle whose certificate was revoked no longer counts).
* **PoW 1 extrapolation.** Enumerating every string of length 5 or 6 over a
  70-character guessing set is infeasible (10^9 to 10^11 guesses), so those
  puzzles are reported as extrapolations from the measured guess rate and the
  known position of the puzzle in the enumeration. The manuscript's absolute
  numbers for these puzzles come from a different enumeration order that the
  text does not specify.

## PoP v2

The extensions that go beyond the manuscript (verifiable election, measured
linkability, demand-aware distribution, anchoring, network model, Sybil
analysis, benchmark packaging) are documented in `pop_v2.md`.
