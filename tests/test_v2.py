import random

import pytest

from pop_sim import crypto, vrf
from pop_sim.blockchain import Blockchain, Transaction
from pop_sim.consensus.popv2 import V2Node, fork_rule, popv2_elect, verify_popv2_proof
from pop_sim.shuffle import ITSConfig, ITSSimulation
from pop_sim.v2 import network as nw
from pop_sim.v2.adversary import TrackingAdversary
from pop_sim.v2.anchoring import (anchors_to_proof, build_allotment_proof, detect_rsu_tamper, make_anchor,
                                  merkle_path, merkle_root, merkle_verify, verify_allotment_proof)
from pop_sim.v2.mobility import Road, RoadConfig
from pop_sim.v2.sybil import analytic_win_probability, simulate_sybil


@pytest.fixture(scope="module")
def vrf_keys():
    return [vrf.generate_vrf_keypair(1024) for _ in range(6)]


def test_vrf_is_deterministic_unique_and_verifiable(vrf_keys):
    k = vrf_keys[0]
    pi = vrf.vrf_prove(k, b"seed")
    assert vrf.vrf_prove(k, b"seed") == pi                      # unique output per (key, input)
    beta = vrf.vrf_verify(k.public, b"seed", pi)
    assert beta == vrf.vrf_proof_to_hash(pi)
    assert vrf.vrf_verify(k.public, b"other", pi) is None
    assert vrf.vrf_verify(vrf_keys[1].public, b"seed", pi) is None
    tampered = bytes([pi[0] ^ 1]) + pi[1:]
    assert vrf.vrf_verify(k.public, b"seed", tampered) is None
    assert 0.0 <= vrf.beta_to_unit(beta) < 1.0


def test_popv2_election_and_proof(vrf_keys):
    nodes = [V2Node(f"N{i}", k) for i, k in enumerate(vrf_keys)]
    res, pi = popv2_elect(nodes, "ab" * 32, 3)
    assert res.winner in res.miners or not res.miners
    assert all(res.values[m] < 0.5 for m in res.miners)
    assert res.winner_value == min(res.values[m] for m in (res.miners or res.values))
    w = next(n for n in nodes if n.node_id == res.winner)
    proof = res.proof(w, pi)
    assert verify_popv2_proof(proof, "ab" * 32, 3, res.winner, certified_pk=w.pk.to_hex())
    assert not verify_popv2_proof(proof, "ab" * 32, 4, res.winner)          # wrong chain position
    assert not verify_popv2_proof(proof, "cd" * 32, 3, res.winner)          # wrong parent
    assert not verify_popv2_proof(proof, "ab" * 32, 3, "N-other")           # wrong miner
    other = nodes[(nodes.index(w) + 1) % len(nodes)]
    assert not verify_popv2_proof(proof, "ab" * 32, 3, res.winner, certified_pk=other.pk.to_hex())
    assert not verify_popv2_proof({**proof, "value": 0.0}, "ab" * 32, 3, res.winner)   # cannot claim a smaller value


def test_popv2_fork_rule_prefers_smaller_value():
    assert fork_rule([{"value": 0.3, "winner": "a"}, {"value": 0.1, "winner": "b"}])["winner"] == "b"


def test_protocol_under_popv2_validates_and_rejects_impostor():
    sim = ITSSimulation(ITSConfig(n_pm=3, rsus_per_pm=1, vehicles_per_rsu=2, consensus="popv2", vrf_bits=1024, seed=5))
    sim.run(2)
    s = sim.summary()
    assert s["pm_chain_valid"] and s["rsu_chains_valid"]
    assert all(sim.validate_block(b) for b in sim.pm_chain.chain[1:])
    last = sim.pm_chain.last
    impostor = next(p for p in sim.pms if p.pm_id != last.miner)
    fake = sim.pm_chain.new_block([], miner=impostor.pm_id, consensus="popv2", proof=dict(last.proof))
    with pytest.raises(ValueError):
        sim.pm_chain.add_block(fake)


def test_merkle_roundtrip():
    leaves = [crypto.sha256_hex(str(i)) for i in range(9)]
    root = merkle_root(leaves)
    for i in range(9):
        assert merkle_verify(leaves[i], merkle_path(leaves, i), root)
    assert not merkle_verify(leaves[0], merkle_path(leaves, 1), root)
    assert merkle_root([leaves[0]]) == leaves[0]


def test_anchoring_proof_and_tamper_detection():
    pm, rsu = crypto.generate_keypair(), crypto.generate_keypair()
    rsu_chain = Blockchain("rsu")
    pids = []
    for b in range(6):
        txs = []
        for t in range(3):
            p = [f"PID-{b}-{t}-{j}" for j in range(2)]
            pids.extend(p)
            txs.append(Transaction.create("allot", rsu, pm.pk, {"rsu": "R", "pids": p}))
        rsu_chain.add_block(rsu_chain.new_block(txs, "R", "popv2"))
    pm_chain = Blockchain("pm")
    pm_chain.add_block(pm_chain.new_block([], "PM-1", "popv2", anchors_to_proof([make_anchor(rsu_chain, "PM-1", 1)])))
    proof = build_allotment_proof(rsu_chain, pm_chain, "PM-1", "PID-4-1-1", pm)
    assert proof and verify_allotment_proof(proof, pm_chain)
    bad = dict(proof, pid="PID-0-0-0", tx_hash="00" * 32)
    assert not verify_allotment_proof(bad, pm_chain)
    assert not detect_rsu_tamper(rsu_chain, pm_chain, "PM-1")
    rsu_chain.chain[2].transactions[0].timestamp += 1
    rsu_chain.chain[2].seal()                       # RSU re-hashes to hide the edit ...
    assert detect_rsu_tamper(rsu_chain, pm_chain, "PM-1")   # ... but the anchor no longer matches


def test_protocol_anchors_every_round_and_builds_proof():
    sim = ITSSimulation(ITSConfig(n_pm=2, rsus_per_pm=2, vehicles_per_rsu=3, seed=2))
    sim.run(3)
    rep = sim.summary()["anchoring"]
    assert rep["enabled"] and not rep["tamper_detected_on_clean_chains"]
    assert rep["proof_bytes"] and rep["proof_verify_seconds"] > 0
    assert all("anchors" in b.proof for b in sim.pm_chain.chain[1:])


def test_fork_probability_falls_with_time_limit():
    net = nw.NetworkModel(0.02, 0.5, 0.0, random.Random(0))
    fast = nw.simulate_timer_forks(20, 0.05, net, 200, random.Random(1))["fork_probability"]
    slow = nw.simulate_timer_forks(20, 5.0, net, 200, random.Random(1))["fork_probability"]
    assert fast > 0.5 > slow


def test_latency_models_run_and_pbft_is_quadratic():
    c = nw.CryptoCosts(3e-4, 2e-4, 2e-2, 2e-4, 2e-3)
    net = nw.NetworkModel(0.02, 0.5, 0.01, random.Random(0))
    rng = random.Random(0)
    for fn in nw.LATENCY_MODELS.values():
        assert fn(10, net, c, rng, 0.25) > 0
    m = nw.message_counts(100)
    assert m["pbft"] > 50 * m["pop_v2"]


def _lonely_road_run(silent: tuple[int, int] | None, max_gap: float) -> float:
    road = Road(RoadConfig(density_per_km=0.4, seed=3))     # a couple of vehicles on 5 km
    adv = TrackingAdversary(road.cfg.length_m, 8.0, 1.0, max_gap=max_gap)
    pid = {v.vid: f"A{v.vid}" for v in road.vehicles}
    changes = 0
    for t in range(1, 61):
        road.step(1.0)
        if t == 30:
            pid = {k: f"B{k}" for k in pid}
            changes += len(pid)
        if silent and silent[0] <= t < silent[1]:
            adv.observe([])
            continue
        adv.observe(road.beacons(pid))
    return adv.report(changes).linking_success


def test_tracker_follows_isolated_vehicle_even_through_silence():
    assert _lonely_road_run(None, 20.0) == 1.0
    # dead reckoning carries an isolated vehicle across a 10 s silent period ...
    assert _lonely_road_run((30, 40), 20.0) == 1.0
    # ... unless the tracker gives up before the silence ends
    assert _lonely_road_run((30, 40), 5.0) == 0.0


def test_mobility_protocol_conserves_pseudonyms_and_reports():
    cfg = ITSConfig(n_pm=2, rsus_per_pm=2, consensus="pop", mobility=True, road=RoadConfig(density_per_km=3, seed=4),
                    round_seconds=12, pseudonyms_per_vehicle=3, safety_stock=0.25, seed=4)
    sim = ITSSimulation(cfg)
    sim.run(3)
    s = sim.summary()
    assert s["pm_chain_valid"] and s["rsu_chains_valid"]
    assert s["tracking"]["beacons"] > 0 and s["tracking"]["pseudonym_changes"] > 0
    assert all(r["rejected_messages"] == 0 for r in s["rounds"])
    # every used pseudonym comes back and is re-allotted
    held = sum(len(v.pseudonyms) for v in sim.vehicles)
    assert held + len(sim.cloud.store) + sum(len(p.pool) for p in sim.pms) + sum(len(r.shuffled_sets) for r in sim.rsus) \
        == len(sim.pki.issued_pids)


def test_sybil_numbers():
    assert analytic_win_probability(20, 5) == pytest.approx(0.2)
    rows = simulate_sybil(20, (1, 10), rounds=400, seed=2)
    r1, r10 = rows
    assert r10.v1_lying > 0.95                      # a lying attacker owns v1
    assert abs(r10.v2_vrf - r10.analytic) < 0.1     # v2 is bounded by k/(n+k)
    assert r10.v2_pki_bound < 0.15                  # and one certificate is one identity
