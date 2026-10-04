# PoS: Proof of Pseudonym simulation (v1 reproduction and v2 extensions)

*"PoS" here abbreviates Proof of pSeudonym, the manuscript's protocol; it is not
Proof of Stake.*

A simulation of the protocol proposed in

> S. Johar, N. Ahmad, A. Durrani and G. Ali, "Proof of Pseudonym: Blockchain-Based
> Privacy Preserving Protocol for Intelligent Transport System", *IEEE Access*,
> vol. 9, pp. 163625-163639, 2021. doi:[10.1109/ACCESS.2021.3133423](https://doi.org/10.1109/ACCESS.2021.3133423)

The manuscript proposes a pseudonym *shuffling* scheme for Intelligent Transport
Systems: instead of a central authority minting fresh pseudonyms all the time,
Privacy Managers (PMs) collect the pseudonyms vehicles have used, shuffle them in a
cloud and hand them back out through Road Side Units (RSUs), recording every step
on two levels of private blockchain. The blocks are published with a new consensus,
**Proof of Pseudonym (PoP)**, in which a server randomly selects at least half of the
nodes, only those nodes draw a random short time, and the shortest wins. The paper
compares PoP with Proof of Work (two variants), Proof of Kernel Work and Proof of
Elapsed Time.

This repository implements all of that in Python and re-runs the paper's
experiments (Figures 7 to 14, Table 2) and its security analysis (Section VI).
That is **PoP v1**, the manuscript as published. On top of it, **PoP v2** adds
what the v1 simulation showed was missing: a verifiable serverless election, a
measured (not asserted) unlinkability, demand-aware distribution, anchored
blockchains with cross-PM proofs, a network model with fork analysis and PBFT/Raft
baselines, a Sybil analysis, and a configurable benchmark. See
[docs/pop_v2.md](docs/pop_v2.md) for the design and the "PoP v2 results" section
below for the numbers.

## What is in the box

```
src/pop_sim/
  crypto.py          P-256 key pairs, ECDSA signatures, ECIES-style encryption, SHA-256
  blockchain.py      signed + encrypted transactions, hash-linked blocks, validation hook
  entities.py        PKI, Manufacturer, Vehicle, RSU, Privacy Manager, PM cloud, pseudonym ledger
  consensus/
    pow1.py          Algorithm 1  - Proof of Work 1 (puzzle-string search)
    pow2.py          Algorithm 2  - Proof of Work 2 (leading-zero hash puzzle)
    pokw.py          Proof of Kernel Work
    poet.py          Algorithm 3  - Proof of Elapsed Time
    pop.py           Algorithm 6  - Proof of Pseudonym (server, handshake, >= 50 % selection, signed election)
    popv2.py         PoP v2 - serverless election on a VRF, chained seed, PKI-bound keys, fork rule
  vrf.py             VRF front end: RSA-FDH-VRF of RFC 9381 (pure Python, CRT) or the ECVRF below
  ecvrf.py           ECVRF (RFC 9381 Section 5 construction) over secp256k1 on libsecp256k1, 0.16 ms per proof
  shuffle.py         Algorithm 4 (shuffling over the PM cloud) and Algorithm 5 (RSU distribution),
                     plus the v2 options: mobility, forecasting, anchoring, adversary
  block_time.py      tB = nT*tV + 2*tP + tprep + tM*N
  v2/
    network.py       latency/loss model, fork analysis, latency models for 6 consensus algorithms
    mobility.py      ring road, Poisson traffic, CAM beacons
    adversary.py     nearest-neighbour tracker across pseudonym changes (baseline)
    tracker_kalman.py Kalman-filter tracker with Hungarian assignment (default, conservative)
    anchoring.py     Merkle roots, RSU-chain anchors in PM blocks, allotment proofs
    sybil.py         Sybil / collusion analysis
    attacks.py       adversarial bench: 16 attacks executed against the implementation
    usecases.py      7 deployment scenarios with operator-facing metrics
  experiments.py     v1: Figures 7-14, scalability, end-to-end protocol runs, security scenarios
  experiments_v2.py  v2: the seven experiments of docs/pop_v2.md
  plots.py, plots_v2.py
  cli.py             `pop-sim run`, `run-v2`, `bench`, `demo`
tests/               59 tests: crypto, chain integrity, every consensus, protocol invariants, v2, attack bench, scenarios, ECVRF, tracker
results/, figures/   JSON and PNG of the full v1 run; results/v2 and figures/v2 of the full v2 run
config/benchmark.json  example configuration for `pop-sim bench`
Dockerfile           reproducible environment (python:3.12-slim + requirements)
docs/paper_mapping.md  section-by-section mapping from the manuscript to the code, and the deviations
docs/pop_v2.md         what v2 changes, why, and how each change is measured
docs/attacks_and_usecases.md  the attack table and the scenario table
```

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q                                   # 59 tests
PYTHONPATH=src python -m pop_sim demo       # trace three shuffle rounds (v1)
PYTHONPATH=src python -m pop_sim demo --mobility --consensus popv2   # v2: vehicles drive, VRF election
PYTHONPATH=src python -m pop_sim run --quick     # v1 experiments, small budgets (~15 s)
PYTHONPATH=src python -m pop_sim run             # v1 full budgets (~7 min), writes results/ and figures/
PYTHONPATH=src python -m pop_sim run-v2 --quick  # v2 experiments, small budgets (~20 s)
PYTHONPATH=src python -m pop_sim run-v2          # v2 full budgets (~10 min), writes results/v2 and figures/v2
PYTHONPATH=src python -m pop_sim bench config/benchmark.json   # the protocol from a JSON configuration
PYTHONPATH=src python -m pop_sim attacks  [--quick]  # 16 attacks executed against PoP v2 (exit 1 if any succeeds)
PYTHONPATH=src python -m pop_sim usecases [--quick]  # 7 deployment scenarios
```

`pip install -e .` installs the `pop-sim` command so the `PYTHONPATH=src` prefix is not needed.
`docker build -t pos-sim . && docker run --rm pos-sim pytest -q` does the same in a container.

### Demo output

```
ITS domain: 2 PMs, 6 RSUs, 30 vehicles, 90 pseudonyms, consensus=pop
round 1: 91 msgs (0 rejected), 90 pseudonyms shuffled, PM block by PM-1 (2/2 mining, 30.0 ms), 4 RSU blocks, 0 returned to a previous holder
round 2: 91 msgs (1 rejected), 90 pseudonyms shuffled, PM block by PM-2 (2/2 mining, 60.0 ms), 4 RSU blocks, 0 returned to a previous holder
round 3: 87 msgs (0 rejected), 87 pseudonyms shuffled, PM block by PM-1 (2/2 mining, 200.0 ms), 4 RSU blocks, 0 returned to a previous holder
PM chain: 4 blocks, valid = True
RSU chains: {'PM-1': 8, 'PM-2': 8} valid = True
linkability: {"messages_observed": 267, "pid_reused_by_same_vehicle": 0, "pids_issued": 90, ...}
revocations: [{"vehicle": "VEH-00009-...", "pid": "PID-843f...", "rsu": "RSU-1.2", "reason": "pseudonym-held-by-another-vehicle"}]
```

The one rejected message in round 2 is the configured malicious vehicle replaying a
pseudonym it had already returned; the RSU catches it against the ledger, the PM
reports it and the PKI revokes the vehicle's certificate (its three pseudonyms then
leave the pool, hence 87 messages in round 3).

## How the protocol is simulated

One `ITSSimulation` holds a PKI, `n_pm` Privacy Managers, `rsus_per_pm` RSUs each and
`vehicles_per_rsu` vehicles under every RSU. Set-up follows Algorithm 4 steps 1-9:
the manufacturer provisions each vehicle with a PKI-issued permanent identity, the
PKI generates `pid, cert, pk, sk` for every pseudonym and broadcasts the sets to the
PMs encrypted with the PM's public key and signed with the PKI's key, the PMs serve
their RSUs and the RSUs allot the sets to vehicles. From then on PKI is only touched
again to revoke a certificate (the simulation counts PKI accesses to check this).

Every shuffle round (`run_round`) then does:

1. Vehicles sign safety messages with their pseudonyms, rotating through the set.
   The RSU verifies each message against the **pseudonym ledger** (the state the
   `allot`/`used` transactions of the RSU chain describe): pseudonym must be
   currently allotted to that vehicle, not returned, and the signature must verify.
2. Algorithm 5 lines 7-9: RSUs collect the used pseudonyms together with the
   vehicles' status, record them as a transaction encrypted for the PM, and the
   RSUs of the PM mine the RSU-level chain.
3. Algorithm 4 lines 11-16: PMs collect the packages, upload them to the PM cloud,
   the cloud shuffles everything and relocates sets to PMs by traffic need.
4. Algorithm 4 lines 18-19: the relocations become `shuffle` transactions
   (signed by the origin PM, encrypted for the destination PM); the PMs run the
   consensus and the winner publishes the block on the PM chain. Under PoP, the
   block carries the server-signed election record and every node checks it.
5. Algorithm 4 line 21 and Algorithm 5 lines 1-6: PMs retrieve their new sets,
   RSUs record the allotment, mine, and distribute to vehicles.

The consensus is pluggable (`pop`, `poet`, `pow2`, `pokw`) so the same protocol run
can be compared across algorithms.

## Results at a glance

Full tables and figures: [v1 reproduction](docs/v1_results.md),
[v2 results](docs/v2_results.md), [attack bench and scenarios](docs/attack_and_scenario_results.md).
All numbers come from `results/` and `results/v2/` as produced by the commands above.

* **The manuscript reproduces.** PoW 2 grows linearly with transactions and 16x per
  leading zero; Proof of Pseudonym (PoP) costs no puzzle and its block time stays
  flat (0.24 to 0.35 s for 100 to 1000 transactions against 0.35 to 2.8 s for PoW).
* **The published PoP is not deployable as described.** Its timer range forks more
  than half the blocks on 20 ms links, the election server is a trusted party, the
  random time is self-reported, and k Sybil identities win k/(n+k) of the blocks (a
  lying one wins half).
* **PoP v2 fixes the election** with a verifiable random function: a serverless,
  ungrindable, PKI-bound election at 0.4 ms per node per block (ECVRF on
  libsecp256k1: 0.15 ms to prove, 0.23 ms to verify), plus equivocation detection, anchored RSU chains and
  certificate-checked allotment. Eighteen executed attacks: 14 defended, 4 bounded,
  0 successful.
* **Pseudonym shuffling alone does not give location privacy.** Against a
  Kalman-filter tracker a lone vehicle is followed through every change; only dense
  traffic with synchronized changes and a silent period brings linking down, and the
  curves say by how much.
* **Operators get numbers:** stock an RSU needs (about 25 % above forecast), proof a
  roaming vehicle carries (2.2 KB, 24 us to verify), time to revoke a misbehaving
  vehicle across PMs (2 rounds), one core keeps up with a 784-vehicle district.

## License

MIT, see `LICENSE`.
