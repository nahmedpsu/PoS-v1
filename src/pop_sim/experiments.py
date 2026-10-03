"""Experiments reproducing Section V (Figures 7-14) plus end-to-end protocol
and security runs.  Every experiment returns a JSON-serialisable dict."""

from __future__ import annotations

import platform
import random
import statistics
import time
import tracemalloc

from cryptography.exceptions import InvalidTag

from . import crypto
from .block_time import BlockTimeParams, block_time, measure_tprep, measure_tv
from .consensus.poet import poet_elect
from .consensus.pop import PoPServer, verify_election
from .consensus.pow1 import solve_pow1
from .consensus.pow2 import mine_pow2
from .entities import PKI, PMCloud, PrivacyManager
from .shuffle import ITSConfig, ITSSimulation

# Puzzles of Figure 7 / 8 in the manuscript.
PAPER_PUZZLES = ["0a", "0ab", "0abc", "0abcd", "00a", "00ab", "00abc", "00gf", "00gfs", "00upha"]


def machine_info() -> dict:
    return {"python": platform.python_version(), "machine": platform.machine(),
            "processor": platform.processor() or platform.machine(), "system": platform.system()}


# ---------------------------------------------------------------- Fig. 7 / 8
def exp_pow1(puzzles: list[str] = PAPER_PUZZLES, max_guesses: int = 5_000_000) -> dict:
    """Proof of Work 1: CPU time and peak memory per puzzle (Figures 7 and 8)."""
    rows = []
    for pz in puzzles:
        tracemalloc.start()
        r = solve_pow1(pz, max_guesses=max_guesses)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        rows.append({"puzzle": pz, "length": len(pz), "found": r.found, "guesses": r.guesses,
                     "measured_seconds": r.seconds, "cpu_seconds": r.cpu_seconds,
                     "extrapolated": not r.found, "search_space": r.search_space,
                     "peak_memory_kb": peak / 1024})
    return {"experiment": "pow1", "max_guesses": max_guesses, "rows": rows, "machine": machine_info()}


# --------------------------------------------------------------- Fig. 9 / 10
def exp_pow2(difficulties=(3, 4), tx_counts=tuple(range(100, 1001, 100)), seed: int = 1) -> dict:
    """Proof of Work 2: CPU time to mine ``nT`` transactions at each difficulty."""
    rng = random.Random(seed)
    series = {}
    for d in difficulties:
        rows = []
        for n in tx_counts:
            hashes = 0
            t0 = time.perf_counter()
            ts = time.time()
            for i in range(n):
                r = mine_pow2(crypto.sha256_hex(f"tx-{rng.getrandbits(64)}-{i}"), d, timestamp=ts)
                hashes += r.hashes
            rows.append({"transactions": n, "cpu_seconds": time.perf_counter() - t0, "hashes": hashes})
        series[str(d)] = rows
    return {"experiment": "pow2", "difficulties": list(difficulties), "series": series, "machine": machine_info()}


# ------------------------------------------------------------------- Fig. 11
def exp_poet(nodes: int = 10, rounds: int = 10, seed: int = 1) -> dict:
    rng = random.Random(seed)
    ids = [f"Node {i+1}" for i in range(nodes)]
    rows = []
    for r in range(rounds):
        res = poet_elect(ids, rng=rng)
        rows.append({"round": r + 1, "winner": res.winner, "winner_time": res.winner_time,
                     "cpu_seconds": res.cpu_seconds, "times": res.times})
    return {"experiment": "poet", "nodes": nodes, "rows": rows}


# ------------------------------------------------------------------- Fig. 12
def exp_pop(nodes: int = 20, rounds: int = 10, seed: int = 1, max_threshold: int = 100) -> dict:
    """Proof of Pseudonym with ``nodes`` connected clients; the server draws
    the miner percentage in [50, ``max_threshold``] each round."""
    rng = random.Random(seed)
    server = PoPServer(rng=rng, max_threshold=max_threshold)
    ids = [f"Node {i+1}" for i in range(nodes)]
    rows = []
    for r in range(rounds):
        server.disconnect_all()
        for nid in ids:
            server.connect(nid)
        res = server.elect()
        assert verify_election(res.proof(), server.keys.pk_hex)
        rows.append({"round": r + 1, "winner": res.winner, "winner_time": res.winner_time,
                     "threshold_percent": res.threshold_percent, "miners": res.miners,
                     "cpu_seconds": res.cpu_seconds, "times": res.times})
    return {"experiment": "pop", "nodes": nodes, "rows": rows}


# ------------------------------------------------------------------- Fig. 13
def exp_comparison(pow2_result: dict, pow1_result: dict, pop_result: dict, pow2_difficulty: int = 3) -> dict:
    """Side-by-side series: PoW 2 (per transaction count), PoW 1 (per puzzle),
    PoP (per round) - the three groups of Figure 13."""
    key = str(pow2_difficulty) if str(pow2_difficulty) in pow2_result["series"] else next(iter(pow2_result["series"]))
    return {
        "experiment": "comparison",
        "pow2": [r["cpu_seconds"] for r in pow2_result["series"][key]],
        "pow2_difficulty": int(key),
        "pow1": [r["cpu_seconds"] for r in pow1_result["rows"]],
        "pop": [r["winner_time"] + r["cpu_seconds"] for r in pop_result["rows"]],
    }


# ------------------------------------------------------------------- Fig. 14
def exp_block_time(pow2_result: dict | None = None, tx_counts=tuple(range(100, 1001, 100)),
                   pow2_difficulty: int = 3, miners: int = 10, rounds: int = 10, seed: int = 1) -> dict:
    """tB = nT*tV + 2*tP + tprep + tM*N for PoW 2 and PoP, measured on this
    machine, against the time cost reported by Bao et al. [31].

    Two PoW 2 variants are reported: ``tB_pow2_per_tx`` takes the mining time
    from the Figure 9/10 measurement (every transaction is hashed to the
    difficulty, as the manuscript does) and ``tB_pow2_per_block`` solves one
    puzzle per block.  Proof of Pseudonym mines nothing: ``tM`` is the
    election time plus the winner's random short time."""
    rng = random.Random(seed)
    tV = measure_tv()
    tP = 0.001                                  # constant network propagation, as in the paper
    ts = time.time()
    pow_times = [mine_pow2(crypto.sha256_hex(str(rng.random())), pow2_difficulty, timestamp=ts).seconds
                 for _ in range(rounds)]
    tM_pow = statistics.mean(pow_times)
    per_tx = {}
    if pow2_result is not None:
        key = str(pow2_difficulty)
        if key not in pow2_result["series"]:
            key = max(pow2_result["series"], key=int)
        per_tx = {r["transactions"]: r["cpu_seconds"] for r in pow2_result["series"][key]}
    server = PoPServer(rng=rng)
    pop_times = []
    for _ in range(rounds):
        server.disconnect_all()
        for i in range(miners):
            server.connect(f"N{i}")
        r = server.elect()
        pop_times.append(r.cpu_seconds + r.winner_time)
    tM_pop = statistics.mean(pop_times)
    rows = []
    for n in tx_counts:
        tprep = measure_tprep(n)
        p_pow = BlockTimeParams(tV, tP, tprep, tM_pow, miners)
        p_pop = BlockTimeParams(tV, tP, tprep, tM_pop, PoPServer.miners_for(miners, 50))
        base = n * tV + 2 * tP + tprep
        row = {"transactions": n, "tprep": tprep,
               "tB_pow2_per_block": block_time(n, p_pow), "tB_pop": block_time(n, p_pop),
               "ref_bao2019": 0.2 + (2.0 - 0.2) * (n - 100) / 900}
        if n in per_tx:
            row["tB_pow2_per_tx"] = base + per_tx[n]
        rows.append(row)
    return {"experiment": "block_time", "tV": tV, "tP": tP, "tM_pow2": tM_pow, "tM_pop": tM_pop,
            "miners": miners, "pow2_difficulty": pow2_difficulty, "rows": rows,
            "reference": "Bao et al. [31] report 0.2 s for 100 and 2 s for 1000 transactions (PoW); linear interpolation."}


# ------------------------------------------------------------- scalability
def exp_scalability(node_counts=(10, 20, 50, 100, 200, 500, 1000), rounds: int = 20, seed: int = 1) -> dict:
    """Election cost of PoET (all nodes) vs PoP (random >= 50 % subset) as the
    network grows - the O(n) vs O(n/2) claim of Table 2."""
    rng = random.Random(seed)
    rows = []
    for n in node_counts:
        ids = [f"N{i}" for i in range(n)]
        poet_cpu, pop_cpu, pop_race, pop_miners = [], [], [], []
        server = PoPServer(rng=rng)
        for _ in range(rounds):
            poet_cpu.append(poet_elect(ids, rng=rng).cpu_seconds)
            server.disconnect_all()
            for nid in ids:
                server.connect(nid)
            r = server.elect()
            pop_cpu.append(r.cpu_seconds)
            pop_race.append(r.race_seconds)
            pop_miners.append(r.miners)
        rows.append({"nodes": n, "poet_cpu_mean": statistics.mean(poet_cpu),
                     "pop_cpu_mean": statistics.mean(pop_cpu), "pop_race_mean": statistics.mean(pop_race),
                     "pop_miners_mean": statistics.mean(pop_miners)})
    return {"experiment": "scalability", "rounds": rounds, "rows": rows}


# ------------------------------------------------------ end-to-end protocol
def exp_protocol(rounds: int = 5, n_pm: int = 2, rsus_per_pm: int = 3, vehicles_per_rsu: int = 5,
                 pseudonyms_per_vehicle: int = 3, pow_difficulty: int = 3, seed: int = 1,
                 consensus_kinds=("pop", "poet", "pow2", "pokw")) -> dict:
    """Run Algorithms 4 and 5 for ``rounds`` shuffle rounds under each consensus."""
    out = {"experiment": "protocol", "rounds": rounds, "runs": {}}
    for kind in consensus_kinds:
        cfg = ITSConfig(n_pm=n_pm, rsus_per_pm=rsus_per_pm, vehicles_per_rsu=vehicles_per_rsu,
                        pseudonyms_per_vehicle=pseudonyms_per_vehicle, consensus=kind,
                        pow_difficulty=pow_difficulty, seed=seed, malicious_vehicles=1)
        sim = ITSSimulation(cfg)
        t0 = time.perf_counter()
        sim.run(rounds)
        s = sim.summary()
        s["total_wall_seconds"] = time.perf_counter() - t0
        s["mean_pm_consensus_cpu"] = statistics.mean(r["pm_consensus_cpu"] for r in s["rounds"])
        s["mean_rsu_consensus_cpu"] = statistics.mean(r["rsu_consensus_cpu"] for r in s["rounds"])
        out["runs"][kind] = s
    return out


# ---------------------------------------------------------------- security
def exp_security(seed: int = 7) -> dict:
    """Threat scenarios of Section VI, each checked mechanically."""
    rng = random.Random(seed)
    results = {}

    # 1. Tampering: changing one transaction in a published block breaks the chain.
    sim = ITSSimulation(ITSConfig(n_pm=2, rsus_per_pm=2, vehicles_per_rsu=3, seed=seed))
    sim.run(2)
    assert sim.pm_chain.is_valid()
    victim = sim.pm_chain.chain[1].transactions[0]
    victim.ciphertext = victim.ciphertext[:-2] + ("00" if victim.ciphertext[-2:] != "00" else "11")
    results["tampered_block_detected"] = not sim.pm_chain.is_valid()

    # 2. Forged PKI broadcast: a package signed by an attacker key is rejected by the PM.
    pki = PKI(rng)
    cloud = PMCloud(rng)
    pm = PrivacyManager("PM-X", cloud, rng)
    ps = pki.generate_pseudonyms(5)
    ct, _ = pki.package_for_pm(pm.keys.pk, ps)
    forged_sig = crypto.sign(crypto.generate_keypair().sk, ct)
    try:
        pm.receive_from_pki(ct, forged_sig, pki.keys.pk)
        results["forged_pki_package_rejected"] = False
    except ValueError:
        results["forged_pki_package_rejected"] = True

    # 3. Curious / compromised RSU: it holds the chain but cannot open PM-bound transactions.
    sim = ITSSimulation(ITSConfig(n_pm=1, rsus_per_pm=2, vehicles_per_rsu=3, seed=seed))
    sim.run(1)
    rsu = sim.rsus[0]
    blocks_with_tx = [b for b in sim.pms[0].rsu_chain.chain if b.transactions]
    tx = blocks_with_tx[-1].transactions[0]
    try:
        tx.open(rsu.keys)
        results["curious_rsu_cannot_read_transactions"] = False
    except InvalidTag:
        results["curious_rsu_cannot_read_transactions"] = True
    results["pm_can_read_its_transactions"] = "used" in tx.open(sim.pms[0].keys) or "pids" in tx.open(sim.pms[0].keys)

    # 4. Spoofed PM: a node that was not elected tries to publish a block.
    sim = ITSSimulation(ITSConfig(n_pm=3, rsus_per_pm=1, vehicles_per_rsu=2, seed=seed))
    sim.run(1)
    last = sim.pm_chain.last
    impostor = next(p for p in sim.pms if p.pm_id != last.miner)
    fake = sim.pm_chain.new_block([], miner=impostor.pm_id, consensus="pop", proof=dict(last.proof))
    try:
        sim.pm_chain.add_block(fake)
        results["spoofed_pm_block_rejected"] = False
    except ValueError:
        results["spoofed_pm_block_rejected"] = True
    # ... and a proof the impostor signs itself is rejected as well.
    fake2 = sim.pm_chain.new_block([], miner=impostor.pm_id, consensus="pop",
                                   proof={**last.proof, "winner": impostor.pm_id,
                                          "mining_list": [impostor.pm_id], "attestation": "00"})
    try:
        sim.pm_chain.add_block(fake2)
        results["self_signed_election_rejected"] = False
    except ValueError:
        results["self_signed_election_rejected"] = True

    # 5. Internal Tricking Adversary: reuse of a returned pseudonym is caught and revoked.
    sim = ITSSimulation(ITSConfig(n_pm=2, rsus_per_pm=2, vehicles_per_rsu=4, seed=seed, malicious_vehicles=2))
    sim.run(3)
    rep = sim.linkability_report()
    results["pseudonym_reuse_detected_and_revoked"] = rep["revoked_vehicles"] == 2 and rep["flagged_messages"] >= 2
    results["honest_vehicles_never_flagged"] = all(
        any(v.malicious for v in sim.vehicles if v.vehicle_id == r["vehicle"]) for r in sim.revocations)

    # 6. Global Passive Adversary: linking messages across shuffle rounds by pseudonym.
    sim = ITSSimulation(ITSConfig(n_pm=2, rsus_per_pm=3, vehicles_per_rsu=5, pseudonyms_per_vehicle=3, seed=seed))
    sim.run(5)
    rep = sim.linkability_report()
    results["unlinkability"] = {
        "messages_observed": rep["messages_observed"],
        "pid_reused_by_same_vehicle": rep["pid_reused_by_same_vehicle"],
        "pids_held_by_more_than_one_vehicle": rep["pids_held_by_more_than_one_vehicle"],
        "pids_issued": rep["pids_issued"],
        "linkable_fraction": rep["pid_reused_by_same_vehicle"] / max(1, rep["messages_observed"]),
    }
    results["pki_accessed_only_at_registration"] = sim.pki.accesses == len(sim.vehicles)
    return {"experiment": "security", "results": results}
