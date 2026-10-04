"""PoP v2 experiments: verifiable election, forks under latency, consensus
latency incl. PBFT/Raft, measured linkability, demand-aware distribution,
chain anchoring, Sybil analysis and the end-to-end v2 protocol."""

from __future__ import annotations

import random
import statistics
import time

from . import crypto, vrf
from .blockchain import Blockchain, Transaction
from .consensus.poet import poet_elect
from .consensus.pop import PoPServer
from .consensus.popv2 import V2Node, popv2_elect
from .consensus.pow2 import mine_pow2
from .shuffle import ITSConfig, ITSSimulation
from .v2 import network as nw
from .v2.anchoring import (
    anchors_to_proof,
    build_allotment_proof,
    detect_rsu_tamper,
    make_anchor,
    proof_size_bytes,
    time_verify,
)
from .v2.mobility import Beacon, Road, RoadConfig
from .v2.sybil import simulate_sybil
from .v2.tracker_kalman import make_tracker


# ------------------------------------------------------------ item 1
def exp_v2_election_cost(node_counts=(10, 20, 50, 100, 200), rounds: int = 10, bits: int = 2048, seed: int = 1,
                         schemes=("ecvrf", "rsa-fdh")) -> dict:
    """Per-block cost of PoET, PoP v1 and PoP v2 as the network grows.

    For PoP v2 the figure that matters is what *one node* spends: its own
    VRF proof plus verifying the winner's, independent of ``n``; the
    sequential total (every node proving in turn) is also reported for an
    honest comparison with the single-process v1 numbers.  Both VRF
    schemes are measured when available."""
    rng = random.Random(seed)
    schemes = [sc for sc in schemes if sc != "ecvrf" or vrf.ecvrf.AVAILABLE]
    keys = {}
    keygen = {}
    for sc in schemes:
        t0 = time.perf_counter()
        keys[sc] = [vrf.generate_vrf_keypair(bits, sc) for _ in range(max(node_counts))]
        keygen[sc] = (time.perf_counter() - t0) / len(keys[sc])
    rows = []
    for n in node_counts:
        ids = [f"N{i}" for i in range(n)]
        poet, v1, v1_race = [], [], []
        per_scheme = {sc: {"node": [], "total": [], "race": [], "verify": []} for sc in schemes}
        server = PoPServer(rng=rng)
        for r in range(rounds):
            poet.append(poet_elect(ids, rng=rng).cpu_seconds)
            server.disconnect_all()
            for i in ids:
                server.connect(i)
            res1 = server.elect()
            v1.append(res1.cpu_seconds)
            v1_race.append(res1.race_seconds)
            for sc in schemes:
                nodes = [V2Node(i, k) for i, k in zip(ids, keys[sc])]
                res2, _ = popv2_elect(nodes, crypto.sha256_hex(f"{sc}{r}"), r + 1)
                per_scheme[sc]["node"].append(res2.prove_seconds_mean + res2.verify_seconds)
                per_scheme[sc]["total"].append(res2.cpu_seconds)
                per_scheme[sc]["race"].append(res2.race_seconds)
                per_scheme[sc]["verify"].append(res2.verify_seconds)
        row = {"nodes": n, "poet_total": statistics.mean(poet), "pop_v1_total": statistics.mean(v1),
               "pop_v1_race": statistics.mean(v1_race)}
        primary = schemes[0]
        row.update({"pop_v2_per_node": statistics.mean(per_scheme[primary]["node"]),
                    "pop_v2_race": statistics.mean(per_scheme[primary]["race"]),
                    "pop_v2_sequential_total": statistics.mean(per_scheme[primary]["total"])})
        for sc in schemes:
            row[f"pop_v2_per_node_{sc}"] = statistics.mean(per_scheme[sc]["node"])
            row[f"pop_v2_verify_{sc}"] = statistics.mean(per_scheme[sc]["verify"])
        rows.append(row)
    return {"experiment": "v2_election_cost", "schemes": schemes, "vrf_bits": bits, "vrf_keygen_seconds": keygen, "rows": rows}


# ------------------------------------------------------------ item 5
def exp_v2_forks(latencies=(0.005, 0.01, 0.02, 0.05, 0.1), time_limits=(0.05, 0.1, 0.25, 0.5, 1.0, 2.0),
                 nodes: int = 20, rounds: int = 300, seed: int = 1) -> dict:
    rng = random.Random(seed)
    rows = []
    for lat in latencies:
        for tl in time_limits:
            net = nw.NetworkModel(lat, 0.5, 0.0, random.Random(rng.getrandbits(32)))
            r = nw.simulate_timer_forks(nodes, tl, net, rounds, rng, timer="uniform")
            rows.append(r)
    return {"experiment": "v2_forks", "nodes": nodes, "rounds": rounds, "rows": rows,
            "note": "A node whose timer fires before the winner's block reaches it also publishes."}


def measure_crypto_costs(pow2_difficulty: int = 3, vrf_bits: int = 2048, samples: int = 20) -> nw.CryptoCosts:
    k = crypto.generate_keypair()
    r = crypto.generate_keypair()
    tx = Transaction.create("b", k, r.pk, {"i": 1})
    t0 = time.perf_counter()
    for _ in range(samples):
        crypto.sign(k.sk, tx.signing_bytes())
    sign = (time.perf_counter() - t0) / samples
    t0 = time.perf_counter()
    for _ in range(samples):
        tx.verify_signature()
    verify = (time.perf_counter() - t0) / samples
    vk = vrf.generate_vrf_keypair(vrf_bits)
    t0 = time.perf_counter()
    for i in range(samples):
        pi = vrf.vrf_prove(vk, str(i).encode())
    prove = (time.perf_counter() - t0) / samples
    t0 = time.perf_counter()
    for i in range(samples):
        vrf.vrf_verify(vk.public, str(samples - 1).encode(), pi)
    vverify = (time.perf_counter() - t0) / samples
    ts = time.time()
    puzzles = [mine_pow2(crypto.sha256_hex(str(i)), pow2_difficulty, timestamp=ts).seconds for i in range(samples)]
    return nw.CryptoCosts(sign, verify, prove, vverify, statistics.mean(puzzles))


def exp_v2_latency(node_counts=(4, 7, 10, 20, 50, 100), mean_latency: float = 0.02, loss: float = 0.01,
                   time_limit: float = 0.25, rounds: int = 50, pow2_difficulty: int = 3, seed: int = 1) -> dict:
    """Block latency of six consensus algorithms on the same lossy network."""
    costs = measure_crypto_costs(pow2_difficulty)
    rng = random.Random(seed)
    rows = []
    for n in node_counts:
        row = {"nodes": n}
        for name, fn in nw.LATENCY_MODELS.items():
            net = nw.NetworkModel(mean_latency, 0.5, loss, random.Random(rng.getrandbits(32)))
            row[name] = statistics.mean(fn(n, net, costs, rng, time_limit) for _ in range(rounds))
        row["messages"] = nw.message_counts(n)
        rows.append(row)
    return {"experiment": "v2_latency", "mean_latency": mean_latency, "loss": loss, "time_limit": time_limit,
            "costs": costs.__dict__, "rows": rows}


# ------------------------------------------------------------ item 2
def _track_run(density: float, change_period: int, silent: float, noise_m: float, seconds: int,
               synchronized: bool, seed: int, gate_m: float = 8.0, tracker: str = "kalman") -> dict:
    cfg = RoadConfig(density_per_km=density, seed=seed)
    road = Road(cfg)
    rng = random.Random(seed + 1)
    adv = make_tracker(tracker, cfg.length_m, gate_m, 1.0)
    pid = {v.vid: f"P{v.vid}-0" for v in road.vehicles}
    offset = {v.vid: 0 if synchronized else rng.randrange(change_period) for v in road.vehicles}
    silent_until = {v.vid: 0.0 for v in road.vehicles}
    changes = 0
    for t in range(1, seconds + 1):
        road.step(1.0)
        beacons = []
        for v in road.vehicles:
            if (t + offset[v.vid]) % change_period == 0:
                pid[v.vid] = f"P{v.vid}-{t}"
                changes += 1
                silent_until[v.vid] = t + silent
            if t < silent_until[v.vid]:
                continue
            x = (v.x + rng.gauss(0, noise_m)) % cfg.length_m if noise_m else v.x
            beacons.append(Beacon(float(t), pid[v.vid], x, v.v, v.direction, v.rsu, v.vid))
        adv.observe(beacons)
    rep = adv.report(changes).to_dict()
    rep.update({"density_per_km": density, "change_period": change_period, "silent_period": silent,
                "position_noise_m": noise_m, "synchronized": synchronized, "vehicles": len(road.vehicles),
                "tracker": tracker})
    return rep


def exp_v2_linkability(densities=(2, 5, 10, 20, 40, 80), silent_periods=(0, 3, 10), change_period: int = 30,
                       noise_m: float = 3.0, seconds: int = 300, seed: int = 1, trackers=("kalman", "nn")) -> dict:
    """What a kinematic tracker achieves across pseudonym changes, as a
    function of traffic density and of a silent period after each change,
    for synchronized (mix-zone style) and unsynchronized changes, under the
    Kalman/GNN tracker (conservative) and the nearest-neighbour baseline."""
    rows = []
    for tracker in trackers:
        for sync in (True, False):
            for silent in silent_periods:
                for d in densities:
                    rows.append(_track_run(d, change_period, silent, noise_m, seconds, sync, seed, tracker=tracker))
    return {"experiment": "v2_linkability", "change_period": change_period, "position_noise_m": noise_m,
            "seconds": seconds, "trackers": list(trackers), "rows": rows}


# ------------------------------------------------------------ item 3
def exp_v2_demand(safety_stocks=(0.0, 0.1, 0.25, 0.5), round_seconds=(20, 40, 80), density: float = 8.0,
                  rounds: int = 6, seed: int = 1) -> dict:
    """Stock-outs and pseudonym stock of the demand-aware distribution as a
    function of the RSU safety stock and the shuffle period."""
    rows = []
    for rs in round_seconds:
        for ss in safety_stocks:
            cfg = ITSConfig(n_pm=2, rsus_per_pm=3, consensus="pop", mobility=True,
                            road=RoadConfig(density_per_km=density, seed=seed), round_seconds=rs,
                            pseudonyms_per_vehicle=3, safety_stock=ss, seed=seed, silent_period=0.0)
            sim = ITSSimulation(cfg)
            sim.run(rounds)
            s = sim.summary()
            rows.append({"round_seconds": rs, "safety_stock": ss, "vehicles": len(sim.vehicles),
                         "stockouts": s["stockouts"], "pids_issued": s["linkability"]["pids_issued"],
                         "stock_per_vehicle": s["linkability"]["pids_issued"] / len(sim.vehicles),
                         "linking_success": s["tracking"]["linking_success"],
                         "mean_pm_consensus": statistics.mean(r["pm_consensus_cpu"] for r in s["rounds"])})
    return {"experiment": "v2_demand", "density_per_km": density, "rounds": rounds, "rows": rows}


# ------------------------------------------------------------ item 4
def exp_v2_anchoring(rsu_blocks=(10, 50, 100, 500, 1000), txs_per_block: int = 5, seed: int = 1) -> dict:
    """Allotment-proof size and verification time versus the number of RSU
    blocks an anchor covers, plus tamper detection from the PM level."""
    rng = random.Random(seed)
    pm = crypto.generate_keypair()
    rsu = crypto.generate_keypair()
    rows = []
    for n in rsu_blocks:
        rsu_chain = Blockchain("rsu")
        target_pid = None
        for b in range(n):
            txs = []
            for t in range(txs_per_block):
                pids = [f"PID-{rng.getrandbits(48):012x}" for _ in range(3)]
                if b == n // 2 and t == 0:
                    target_pid = pids[1]
                txs.append(Transaction.create("allot", rsu, pm.pk, {"rsu": "RSU-1.1", "pids": pids}))
            rsu_chain.add_block(rsu_chain.new_block(txs, "RSU-1.1", "popv2"))
        pm_chain = Blockchain("pm")
        anchor = make_anchor(rsu_chain, "PM-1", 1)
        pm_chain.add_block(pm_chain.new_block([], "PM-1", "popv2", anchors_to_proof([anchor])))
        t0 = time.perf_counter()
        proof = build_allotment_proof(rsu_chain, pm_chain, "PM-1", target_pid, pm)
        build = time.perf_counter() - t0
        assert proof is not None
        ok = detect_rsu_tamper(rsu_chain, pm_chain, "PM-1") is False
        victim = rsu_chain.chain[n // 3].transactions[0]
        victim.timestamp += 1
        detected = detect_rsu_tamper(rsu_chain, pm_chain, "PM-1")
        rows.append({"rsu_blocks": n, "proof_bytes": proof_size_bytes(proof),
                     "verify_seconds": time_verify(proof, pm_chain), "build_seconds": build,
                     "tx_path_len": len(proof["tx_path"]), "anchor_path_len": len(proof["anchor_path"]),
                     "clean_chain_ok": ok, "tamper_detected": detected})
    return {"experiment": "v2_anchoring", "txs_per_block": txs_per_block, "rows": rows}


# ------------------------------------------------------------ item 6
def exp_v2_sybil(n_honest_values=(10, 20, 50), k_values=(0, 1, 2, 5, 10, 20, 50), rounds: int = 2000, seed: int = 1) -> dict:
    out = {}
    for n in n_honest_values:
        out[str(n)] = [r.__dict__ for r in simulate_sybil(n, k_values, rounds, seed=seed)]
    return {"experiment": "v2_sybil", "rounds": rounds, "series": out}


# ------------------------------------------------------------ item 7
def exp_v2_protocol(rounds: int = 5, density: float = 8.0, consensus_kinds=("popv2", "pop"), seed: int = 1,
                    silent_period: float = 3.0, noise_m: float = 3.0) -> dict:
    """End-to-end PoP v2: mobility, forecasting, anchoring, adversary, under
    the v2 election and, for reference, the v1 election."""
    out = {"experiment": "v2_protocol", "rounds": rounds, "runs": {}}
    for kind in consensus_kinds:
        cfg = ITSConfig(n_pm=2, rsus_per_pm=3, consensus=kind, mobility=True,
                        road=RoadConfig(density_per_km=density, seed=seed), round_seconds=30,
                        pseudonyms_per_vehicle=3, safety_stock=0.25, malicious_vehicles=1, seed=seed,
                        silent_period=silent_period, position_noise_m=noise_m)
        sim = ITSSimulation(cfg)
        t0 = time.perf_counter()
        sim.run(rounds)
        s = sim.summary()
        s["total_wall_seconds"] = time.perf_counter() - t0
        s["vehicles"] = len(sim.vehicles)
        s["mean_pm_consensus_cpu"] = statistics.mean(r["pm_consensus_cpu"] for r in s["rounds"])
        s["mean_rsu_consensus_cpu"] = statistics.mean(r["rsu_consensus_cpu"] for r in s["rounds"])
        s["all_pm_blocks_verify"] = all(sim.validate_block(b, sim.pm_chain) for b in sim.pm_chain.chain[1:])
        out["runs"][kind] = s
    return out
